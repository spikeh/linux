// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "memmap.h"
#include "zcrx.h"
#include "rsrc.h"

#if defined(CONFIG_PAGE_POOL) && defined(CONFIG_INET)

static int io_allocate_rbuf_ring(struct io_zcrx_ifq *ifq,
				 struct io_uring_zcrx_ifq_reg *reg)
{
	size_t off, size;
	void *ptr;

	off = sizeof(struct io_uring);
	size = off + sizeof(struct io_uring_zcrx_rqe) * reg->rq_entries;

	ptr = io_pages_map(&ifq->rqe_pages, &ifq->n_rqe_pages, size);
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	ifq->rq_ring = (struct io_uring *)ptr;
	ifq->rqes = (struct io_uring_zcrx_rqe *)((char *)ptr + off);
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

	if (area_reg->flags || area_reg->area_token)
		return -EINVAL;
	if (area_reg->__resv1 || area_reg->__resv2[0] || area_reg->__resv2[1])
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
		area->freelist[i] = i;
	}

	area->free_count = nr_pages;
	area->ifq = ifq;
	/* we're only supporting one area per ifq for now */
	area->area_id = 0;
	area_reg->area_token = (u64)area->area_id << IORING_ZCRX_AREA_SHIFT;
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
	if (!ifq)
		return;
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

	/*
	 * 1. Interface queue allocation.
	 * 2. It can observe data destined for sockets of other tasks.
	 */
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/* mandatory io_uring features for zc rx */
	if (!(ctx->flags & IORING_SETUP_DEFER_TASKRUN &&
	      ctx->flags & IORING_SETUP_CQE32))
		return -EINVAL;
	if (ctx->ifq)
		return -EBUSY;
	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	if (reg.__resv[0] || reg.__resv[1] || reg.__resv[2])
		return -EINVAL;
	if (reg.if_rxq == -1 || !reg.rq_entries || reg.flags)
		return -EINVAL;
	if (copy_from_user(&area, u64_to_user_ptr(reg.area_ptr), sizeof(area)))
		return -EFAULT;

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
	rqes_sz = sizeof(struct io_uring_zcrx_rqe) * ifq->rq_entries;
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

	ctx->ifq = NULL;
	io_zcrx_ifq_free(ifq);
}

void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx)
{
	lockdep_assert_held(&ctx->uring_lock);

	io_shutdown_ifq(ctx->ifq);
}

#endif
