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
#include <net/page_pool/helpers.h>
#include <trace/events/page_pool.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "memmap.h"
#include "zcrx.h"
#include "rsrc.h"

static inline struct io_zcrx_area *io_zcrx_iov_to_area(const struct net_iov *niov)
{
	struct net_iov_area *owner = net_iov_owner(niov);

	return container_of(owner, struct io_zcrx_area, nia);
}

static int io_allocate_rbuf_ring(struct io_zcrx_ifq *ifq,
				 struct io_uring_zcrx_ifq_reg *reg)
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

static void io_free_rbuf_ring(struct io_zcrx_ifq *ifq)
{
	io_pages_unmap(ifq->rq_ring, &ifq->rqe_pages, &ifq->n_rqe_pages, true);
	ifq->rq_ring = NULL;
	ifq->rqes = NULL;
}

static void io_zcrx_free_area(struct io_zcrx_area *area)
{
	if (area->freelist)
		kvfree(area->freelist);
	if (area->nia.niovs)
		kvfree(area->nia.niovs);
	if (area->pages) {
		unpin_user_pages(area->pages, area->nia.num_niovs);
		kvfree(area->pages);
	}
	kfree(area);
}

static int io_zcrx_create_area(struct io_ring_ctx *ctx,
			       struct io_zcrx_ifq *ifq,
			       struct io_zcrx_area **res,
			       struct io_uring_zcrx_area_reg *area_reg)
{
	struct io_zcrx_area *area;
	int i, ret, nr_pages;
	struct iovec iov;

	if (area_reg->flags || area_reg->area_id)
		return -EINVAL;
	if (area_reg->__resv2[0] || area_reg->__resv2[1] || area_reg->__resv2[2])
		return -EINVAL;
	if (area_reg->addr & ~PAGE_MASK || area_reg->len & ~PAGE_MASK)
		return -EINVAL;

	iov.iov_base = u64_to_user_ptr(area_reg->addr);
	iov.iov_len = area_reg->len;
	ret = io_buffer_validate(&iov);
	if (ret)
		return ret;

	ret = -ENOMEM;
	area = kmalloc(sizeof(*area), GFP_KERNEL);
	if (!area)
		goto err;

	area->pages = io_pin_pages((unsigned long)area_reg->addr, area_reg->len,
				   &nr_pages);
	if (!area->pages)
		goto err;
	area->nia.num_niovs = nr_pages;

	area->nia.niovs = kvmalloc_array(nr_pages, sizeof(area->nia.niovs[0]),
					 GFP_KERNEL);
	if (!area->nia.niovs)
		goto err;

	area->freelist = kvmalloc_array(nr_pages, sizeof(area->freelist[0]),
					GFP_KERNEL);
	if (!area->freelist)
		goto err;

	for (i = 0; i < nr_pages; i++) {
		struct net_iov *niov = &area->nia.niovs[i];

		memset(niov, 0, sizeof(*niov));
		atomic_long_set(&niov->pp_ref_count, 0);
		niov->owner = &area->nia;
		area->freelist[i] = i;
	}

	area->free_count = nr_pages;
	area->ifq = ifq;
	/* we're only supporting one area per ifq for now */
	area_reg->area_id = area->area_id = 0;
	spin_lock_init(&area->freelist_lock);
	*res = area;
	return 0;
err:
	if (area)
		io_zcrx_free_area(area);
	return ret;
}

static struct io_zcrx_ifq *io_zcrx_ifq_alloc(struct io_ring_ctx *ctx)
{
	struct io_zcrx_ifq *ifq;

	ifq = kzalloc(sizeof(*ifq), GFP_KERNEL);
	if (!ifq)
		return NULL;

	ifq->if_rxq = -1;
	ifq->ctx = ctx;
	return ifq;
}

static void io_shutdown_ifq(struct io_zcrx_ifq *ifq)
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

static void io_zcrx_ifq_free(struct io_zcrx_ifq *ifq)
{
	io_shutdown_ifq(ifq);
	if (ifq->area)
		io_zcrx_free_area(ifq->area);
	io_free_rbuf_ring(ifq);
	kfree(ifq);
}

int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
			  struct io_uring_zcrx_ifq_reg __user *arg)
{
	struct io_uring_zcrx_area_reg area;
	struct io_uring_zcrx_ifq_reg reg;
	struct io_zcrx_ifq *ifq;
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
	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	if (copy_from_user(&area, u64_to_user_ptr(reg.area_ptr), sizeof(area)))
		return -EFAULT;
	if (reg.if_rxq == -1)
		return -EINVAL;

	ifq = io_zcrx_ifq_alloc(ctx);
	if (!ifq)
		return -ENOMEM;

	ret = io_allocate_rbuf_ring(ifq, &reg);
	if (ret)
		goto err;

	ret = io_zcrx_create_area(ctx, ifq, &ifq->area, &area);
	if (ret)
		goto err;

	ifq->rq_entries = reg.rq_entries;
	ifq->if_rxq = reg.if_rxq;

	ring_sz = sizeof(struct io_uring);
	rqes_sz = sizeof(struct io_uring_rbuf_rqe) * ifq->rq_entries;
	reg.offsets.mmap_sz = ring_sz + rqes_sz;
	reg.offsets.rqes = ring_sz;
	reg.offsets.head = offsetof(struct io_uring, head);
	reg.offsets.tail = offsetof(struct io_uring, tail);

	if (copy_to_user(arg, &reg, sizeof(reg))) {
		ret = -EFAULT;
		goto err;
	}
	if (copy_to_user(u64_to_user_ptr(reg.area_ptr), &area, sizeof(area))) {
		ret = -EFAULT;
		goto err;
	}
	ctx->ifq = ifq;
	return 0;
err:
	io_zcrx_ifq_free(ifq);
	return ret;
}

void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx)
{
	struct io_zcrx_ifq *ifq = ctx->ifq;

	lockdep_assert_held(&ctx->uring_lock);

	if (!ifq)
		return;

	WARN_ON_ONCE(ifq->nr_sockets);

	ctx->ifq = NULL;
	io_zcrx_ifq_free(ifq);
}

void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx)
{
	lockdep_assert_held(&ctx->uring_lock);

	io_shutdown_ifq(ctx->ifq);
}

int io_register_zcrx_sock(struct io_ring_ctx *ctx,
			  struct io_uring_zcrx_sock_reg __user *arg)
{
	struct io_uring_zcrx_sock_reg sr;
	struct io_zcrx_ifq *ifq;
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

static bool io_zcrx_niov_put(struct net_iov *niov, int nr)
{
	return atomic_long_sub_and_test(nr, &niov->pp_ref_count);
}

static bool io_zcrx_put_niov_uref(struct net_iov *niov)
{
	if (atomic_long_read(&niov->pp_ref_count) < IO_ZC_RX_UREF)
		return false;

	return io_zcrx_niov_put(niov, IO_ZC_RX_UREF);
}

static inline void io_zc_add_pp_cache(struct page_pool *pp,
				      struct net_iov *niov)
{
	netmem_ref netmem = net_iov_to_netmem(niov);

	page_pool_set_pp_info(pp, netmem);
	pp->alloc.cache[pp->alloc.count++] = netmem;
}

static inline u32 io_zcrx_rqring_entries(struct io_zcrx_ifq *ifq)
{
	u32 entries;

	entries = smp_load_acquire(&ifq->rq_ring->tail) - ifq->cached_rq_head;
	return min(entries, ifq->rq_entries);
}

static void io_zcrx_ring_refill(struct page_pool *pp,
				struct io_zcrx_ifq *ifq)
{
	unsigned int entries = io_zcrx_rqring_entries(ifq);
	unsigned int mask = ifq->rq_entries - 1;
	struct io_zcrx_area *area = ifq->area;

	if (unlikely(!entries))
		return;

	while (entries--) {
		unsigned int rq_idx = ifq->cached_rq_head++ & mask;
		struct io_uring_rbuf_rqe *rqe = &ifq->rqes[rq_idx];
		u32 pgid = rqe->off / PAGE_SIZE;
		struct net_iov *niov = &area->nia.niovs[pgid];

		if (!io_zcrx_put_niov_uref(niov))
			continue;
		io_zc_add_pp_cache(pp, niov);
		if (pp->alloc.count >= PP_ALLOC_CACHE_REFILL)
			break;
	}
	smp_store_release(&ifq->rq_ring->head, ifq->cached_rq_head);
}

static void io_zcrx_refill_slow(struct page_pool *pp, struct io_zcrx_ifq *ifq)
{
	struct io_zcrx_area *area = ifq->area;

	spin_lock_bh(&area->freelist_lock);
	while (area->free_count && pp->alloc.count < PP_ALLOC_CACHE_REFILL) {
		struct net_iov *niov;
		u32 pgid;

		pgid = area->freelist[--area->free_count];
		niov = &area->nia.niovs[pgid];

		io_zc_add_pp_cache(pp, niov);
		pp->pages_state_hold_cnt++;
		trace_page_pool_state_hold(pp, net_iov_to_netmem(niov),
					   pp->pages_state_hold_cnt);
	}
	spin_unlock_bh(&area->freelist_lock);
}

static void io_zcrx_recycle_niov(struct net_iov *niov)
{
	struct io_zcrx_area *area = io_zcrx_iov_to_area(niov);

	spin_lock_bh(&area->freelist_lock);
	area->freelist[area->free_count++] = net_iov_idx(niov);
	spin_unlock_bh(&area->freelist_lock);
}

static netmem_ref io_pp_zc_alloc_pages(struct page_pool *pp, gfp_t gfp)
{
	struct io_zcrx_ifq *ifq = pp->mp_priv;

	/* pp should already be ensuring that */
	if (unlikely(pp->alloc.count))
		goto out_return;

	io_zcrx_ring_refill(pp, ifq);
	if (likely(pp->alloc.count))
		goto out_return;

	io_zcrx_refill_slow(pp, ifq);
	if (!pp->alloc.count)
		return 0;
out_return:
	return pp->alloc.cache[--pp->alloc.count];
}

static bool io_pp_zc_release_page(struct page_pool *pp, netmem_ref netmem)
{
	struct net_iov *niov;

	if (WARN_ON_ONCE(!netmem_is_net_iov(netmem)))
		return false;

	niov = netmem_to_net_iov(netmem);

	if (io_zcrx_niov_put(niov, 1))
		io_zcrx_recycle_niov(niov);
	return false;
}

static void io_pp_zc_scrub(struct page_pool *pp)
{
	struct io_zcrx_ifq *ifq = pp->mp_priv;
	struct io_zcrx_area *area = ifq->area;
	int i;

	for (i = 0; i < area->nia.num_niovs; i++) {
		struct net_iov *niov = &area->nia.niovs[i];
		int count;

		if (!io_zcrx_put_niov_uref(niov))
			continue;
		io_zcrx_recycle_niov(niov);

		count = atomic_inc_return_relaxed(&pp->pages_state_release_cnt);
		trace_page_pool_state_release(pp, net_iov_to_netmem(niov), count);
	}
}

static int io_pp_zc_init(struct page_pool *pp)
{
	struct io_zcrx_ifq *ifq = pp->mp_priv;

	if (!ifq)
		return -EINVAL;
	if (pp->p.order != 0)
		return -EINVAL;
	if (!pp->p.napi)
		return -EINVAL;
	if (pp->p.flags & PP_FLAG_DMA_MAP)
		return -EOPNOTSUPP;
	if (pp->p.flags & PP_FLAG_DMA_SYNC_DEV)
		return -EOPNOTSUPP;

	percpu_ref_get(&ifq->ctx->refs);
	ifq->pp = pp;
	return 0;
}

static void io_pp_zc_destroy(struct page_pool *pp)
{
	struct io_zcrx_ifq *ifq = pp->mp_priv;
	struct io_zcrx_area *area = ifq->area;

	ifq->pp = NULL;

	if (WARN_ON_ONCE(area->free_count != area->nia.num_niovs))
		return;
	percpu_ref_put(&ifq->ctx->refs);
}

const struct memory_provider_ops io_uring_pp_zc_ops = {
	.alloc_pages		= io_pp_zc_alloc_pages,
	.release_page		= io_pp_zc_release_page,
	.init			= io_pp_zc_init,
	.destroy		= io_pp_zc_destroy,
	.scrub			= io_pp_zc_scrub,
};
EXPORT_SYMBOL(io_uring_pp_zc_ops);


#endif
