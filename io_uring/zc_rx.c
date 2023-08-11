// SPDX-License-Identifier: GPL-2.0
#if defined(CONFIG_PAGE_POOL)
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/io_uring.h>
#include <linux/netdevice.h>
#include <linux/nospec.h>
#include <net/tcp.h>
#include <net/af_unix.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "memmap.h"
#include "zc_rx.h"
#include "rsrc.h"

static int io_allocate_rbuf_ring(struct io_zc_rx_ifq *ifq,
				 struct io_uring_zc_rx_ifq_reg *reg)
{
	size_t off, size;
	void *ptr;

	off = sizeof(struct io_uring);
	size = off + sizeof(struct io_uring_rbuf_rqe) * reg->rq_entries;

	ptr = io_pages_map(&ifq->rqe_pages, &ifq->n_rqe_pages, size);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	ifq->rq_ring = (struct io_uring *)ptr;
	ifq->rqes = (struct io_uring_rbuf_rqe *)((char *)ptr + off);
	return 0;
}

static void io_free_rbuf_ring(struct io_zc_rx_ifq *ifq)
{
	io_pages_unmap(ifq->rq_ring, &ifq->rqe_pages, &ifq->n_rqe_pages, true);
	ifq->rq_ring = NULL;
	ifq->rqes = NULL;
}

static void io_zc_rx_free_pool(struct io_zc_rx_pool *pool)
{
	if (pool->freelist)
		kvfree(pool->freelist);
	if (pool->bufs)
		kvfree(pool->bufs);
	if (pool->pages) {
		unpin_user_pages(pool->pages, pool->nr_bufs);
		kvfree(pool->pages);
	}
	kfree(pool);
}

static int io_zc_rx_create_pool(struct io_ring_ctx *ctx,
				struct io_zc_rx_ifq *ifq,
				struct io_zc_rx_pool **res,
				struct io_uring_zc_rx_region_reg *region)
{
	struct io_zc_rx_pool *pool;
	int i, ret, nr_pages;
	struct iovec iov;

	if (region->flags || region->region_id)
		return -EINVAL;
	if (region->resv2[0] || region->resv2[1] || region->resv2[2])
		return -EINVAL;
	if (region->addr & ~PAGE_MASK || region->len & ~PAGE_MASK)
		return -EINVAL;

	iov.iov_base = u64_to_user_ptr(region->addr);
	iov.iov_len = region->len;
	ret = io_buffer_validate(&iov);
	if (ret)
		return ret;

	ret = -ENOMEM;
	pool = kmalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		goto err;

	pool->pages = io_pin_pages((unsigned long)region->addr, region->len,
				   &nr_pages);
	pool->nr_bufs = nr_pages;
	if (!pool->pages)
		goto err;

	pool->bufs = kvmalloc_array(nr_pages, sizeof(pool->bufs[0]), GFP_KERNEL);
	if (!pool->bufs)
		goto err;

	pool->freelist = kvmalloc_array(nr_pages, sizeof(pool->freelist[0]),
					GFP_KERNEL);
	if (!pool->freelist)
		goto err;

	for (i = 0; i < nr_pages; i++) {
		struct net_iov *niov = &pool->bufs[i].niov;

		memset(niov, 0, sizeof(*niov));
		atomic_long_set(&niov->pp_ref_count, 0);
		pool->freelist[i] = i;
	}

	pool->free_count = nr_pages;
	pool->ifq = ifq;
	/* we're only supporting one region per ifq for now */
	pool->pool_id = 0;
	region->region_id = pool->pool_id;
	spin_lock_init(&pool->freelist_lock);
	*res = pool;
	return 0;
err:
	if (pool)
		io_zc_rx_free_pool(pool);
	return ret;
}

static struct io_zc_rx_ifq *io_zc_rx_ifq_alloc(struct io_ring_ctx *ctx)
{
	struct io_zc_rx_ifq *ifq;

	ifq = kzalloc(sizeof(*ifq), GFP_KERNEL);
	if (!ifq)
		return NULL;

	ifq->if_rxq_id = -1;
	ifq->ctx = ctx;
	return ifq;
}

static void io_shutdown_ifq(struct io_zc_rx_ifq *ifq)
{
	int i;

	if (!ifq)
		return;

	for (i = 0; i < ifq->nr_sockets; i++) {
		if (ifq->sockets[i]) {
			fput(ifq->sockets[i]);
			ifq->sockets[i] = NULL;
		}
	}
	ifq->nr_sockets = 0;
}

static void io_zc_rx_ifq_free(struct io_zc_rx_ifq *ifq)
{
	io_shutdown_ifq(ifq);
	if (ifq->pool)
		io_zc_rx_free_pool(ifq->pool);
	io_free_rbuf_ring(ifq);
	kfree(ifq);
}

int io_register_zc_rx_ifq(struct io_ring_ctx *ctx,
			  struct io_uring_zc_rx_ifq_reg __user *arg)
{
	struct io_uring_zc_rx_region_reg region;
	struct io_uring_zc_rx_ifq_reg reg;
	struct io_zc_rx_ifq *ifq;
	size_t ring_sz, rqes_sz;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	/* mandatory io_uring features for zc rx */
	if (!(ctx->flags & IORING_SETUP_DEFER_TASKRUN &&
	      ctx->flags & IORING_SETUP_CQE32))
		return -EINVAL;
	if (ctx->ifq)
		return -EBUSY;
	if (reg.if_rxq_id == -1)
		return -EINVAL;
	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	if (copy_from_user(&region, u64_to_user_ptr(reg.region), sizeof(region)))
		return -EFAULT;

	ifq = io_zc_rx_ifq_alloc(ctx);
	if (!ifq)
		return -ENOMEM;

	ret = io_allocate_rbuf_ring(ifq, &reg);
	if (ret)
		goto err;

	ret = io_zc_rx_create_pool(ctx, ifq, &ifq->pool, &region);
	if (ret)
		goto err;

	ifq->rq_entries = reg.rq_entries;
	ifq->if_rxq_id = reg.if_rxq_id;

	ring_sz = sizeof(struct io_uring);
	rqes_sz = sizeof(struct io_uring_rbuf_rqe) * ifq->rq_entries;
	reg.mmap_sz = ring_sz + rqes_sz;
	reg.rq_off.rqes = ring_sz;
	reg.rq_off.head = offsetof(struct io_uring, head);
	reg.rq_off.tail = offsetof(struct io_uring, tail);

	if (copy_to_user(arg, &reg, sizeof(reg))) {
		ret = -EFAULT;
		goto err;
	}
	if (copy_to_user(u64_to_user_ptr(reg.region), &region,
			 sizeof(region))) {
		ret = -EFAULT;
		goto err;
	}
	ctx->ifq = ifq;
	return 0;
err:
	io_zc_rx_ifq_free(ifq);
	return ret;
}

void io_unregister_zc_rx_ifqs(struct io_ring_ctx *ctx)
{
	struct io_zc_rx_ifq *ifq = ctx->ifq;

	lockdep_assert_held(&ctx->uring_lock);

	if (!ifq)
		return;

	WARN_ON_ONCE(ifq->nr_sockets);

	ctx->ifq = NULL;
	io_zc_rx_ifq_free(ifq);
}

void io_shutdown_zc_rx_ifqs(struct io_ring_ctx *ctx)
{
	lockdep_assert_held(&ctx->uring_lock);

	io_shutdown_ifq(ctx->ifq);
}

int io_register_zc_rx_sock(struct io_ring_ctx *ctx,
			   struct io_uring_zc_rx_sock_reg __user *arg)
{
	struct io_uring_zc_rx_sock_reg sr;
	struct io_zc_rx_ifq *ifq;
	struct socket *sock;
	struct file *file;
	int ret = -EEXIST;
	int idx;

	if (copy_from_user(&sr, arg, sizeof(sr)))
		return -EFAULT;
	if (sr.__resv[0] || sr.__resv[1])
		return -EINVAL;
	if (sr.zc_rx_ifq_idx != 0 || !ctx->ifq)
		return -EINVAL;

	ifq = ctx->ifq;
	if (ifq->nr_sockets >= ARRAY_SIZE(ifq->sockets))
		return -EINVAL;

	BUILD_BUG_ON(ARRAY_SIZE(ifq->sockets) > IO_ZC_IFQ_IDX_MASK);

	file = fget(sr.sockfd);
	if (!file)
		return -EBADF;

	if (!!unix_get_socket(file)) {
		fput(file);
		return -EBADF;
	}

	sock = sock_from_file(file);
	if (unlikely(!sock || !sock->sk)) {
		fput(file);
		return -ENOTSOCK;
	}

	idx = ifq->nr_sockets;
	lock_sock(sock->sk);
	if (!sock->zc_rx_idx) {
		unsigned token;

		token = idx + (sr.zc_rx_ifq_idx << IO_ZC_IFQ_IDX_OFFSET);
		WRITE_ONCE(sock->zc_rx_idx, token);
		ret = 0;
	}
	release_sock(sock->sk);

	if (ret) {
		fput(file);
		return ret;
	}
	ifq->sockets[idx] = file;
	ifq->nr_sockets++;
	return 0;
}

#endif
