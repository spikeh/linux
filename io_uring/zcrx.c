// SPDX-License-Identifier: GPL-2.0
#if defined(CONFIG_PAGE_POOL)
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/io_uring.h>
#include <linux/netdevice.h>
#include <linux/nospec.h>

#include <net/busy_poll.h>
#include <net/tcp.h>
#include <net/af_unix.h>
#include <net/rps.h>
#include <net/page_pool/helpers.h>
#include <net/netdev_rx_queue.h>
#include <trace/events/page_pool.h>
#include <linux/skbuff_ref.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "memmap.h"
#include "zcrx.h"
#include "rsrc.h"

#define IO_SKBS_PER_CALL_LIMIT	20

struct io_zcrx_args {
	struct io_kiocb		*req;
	struct io_zcrx_ifq	*ifq;
	struct socket		*sock;
	unsigned		nr_skbs;
};

struct io_zc_refill_data {
	struct io_zcrx_ifq *ifq;
	struct net_iov *niov;
};

static inline struct io_zcrx_area *io_zcrx_iov_to_area(const struct net_iov *niov)
{
	struct net_iov_area *owner = net_iov_owner(niov);

	return container_of(owner, struct io_zcrx_area, nia);
}

static inline struct page *io_zcrx_iov_page(const struct net_iov *niov)
{
	struct io_zcrx_area *area = io_zcrx_iov_to_area(niov);

	return area->pages[net_iov_idx(niov)];
}

static int io_open_zc_rxq(struct io_zcrx_ifq *ifq)
{
	struct netdev_rx_queue *rxq;

	rxq = __netif_get_rx_queue(ifq->dev, ifq->if_rxq);
	if (rxq->mp_params.mp_priv)
		return -EEXIST;

	rxq->mp_params.mp_ops = &io_uring_pp_zc_ops;
	rxq->mp_params.mp_priv = ifq;

	return netdev_rx_queue_restart(ifq->dev, ifq->if_rxq);
}

static int io_close_zc_rxq(struct io_zcrx_ifq *ifq)
{
	struct netdev_rx_queue *rxq;
	int err;

	rtnl_lock();
	rxq = __netif_get_rx_queue(ifq->dev, ifq->if_rxq);
	rxq->mp_params.mp_ops = NULL;
	rxq->mp_params.mp_priv = NULL;

	err = netdev_rx_queue_restart(ifq->dev, ifq->if_rxq);
	rtnl_unlock();

	return err;
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
		page_pool_set_dma_addr_netmem(net_iov_to_netmem(niov), 0);
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

	if (ifq->if_rxq != -1) {
		io_close_zc_rxq(ifq);
		ifq->if_rxq = -1;
	}
}

static void io_zcrx_ifq_free(struct io_zcrx_ifq *ifq)
{
	io_shutdown_ifq(ifq);
	if (ifq->if_rxq != -1)
		io_close_zc_rxq(ifq);
	if (ifq->area)
		io_zcrx_free_area(ifq->area);
	if (ifq->dev)
		dev_put(ifq->dev);
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

	ret = -ENODEV;
	rtnl_lock();
	ifq->dev = dev_get_by_index(current->nsproxy->net_ns, reg.if_idx);
	if (!ifq->dev)
		goto err_rtnl_unlock;

	ret = io_open_zc_rxq(ifq);
	if (ret)
		goto err_rtnl_unlock;
	rtnl_unlock();

	ring_sz = sizeof(struct io_uring);
	rqes_sz = sizeof(struct io_uring_rbuf_rqe) * ifq->rq_entries;
	reg.offsets.mmap_sz = ring_sz + rqes_sz;
	reg.offsets.rqes = ring_sz;
	reg.offsets.head = offsetof(struct io_uring, head);
	reg.offsets.tail = offsetof(struct io_uring, tail);

	if (copy_to_user(arg, &reg, sizeof(reg))) {
		io_close_zc_rxq(ifq);
		ret = -EFAULT;
		goto err;
	}
	if (copy_to_user(u64_to_user_ptr(reg.area_ptr), &area, sizeof(area))) {
		io_close_zc_rxq(ifq);
		ret = -EFAULT;
		goto err;
	}
	ctx->ifq = ifq;
	return 0;

err_rtnl_unlock:
	rtnl_unlock();
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

static void io_zcrx_get_buf_uref(struct net_iov *niov)
{
	atomic_long_add(IO_ZC_RX_UREF, &niov->pp_ref_count);
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

static inline void io_zc_sync_for_device(struct page_pool *pp,
					 netmem_ref netmem)
{
	if (pp->p.flags & PP_FLAG_DMA_SYNC_DEV) {
		dma_addr_t dma_addr = page_pool_get_dma_addr_netmem(netmem);

		dma_sync_single_range_for_device(pp->p.dev, dma_addr,
						 pp->p.offset, pp->p.max_len,
						 pp->p.dma_dir);
	}
}

static inline void io_zc_add_pp_cache(struct page_pool *pp,
				      struct net_iov *niov)
{
	netmem_ref netmem = net_iov_to_netmem(niov);

	page_pool_set_pp_info(pp, netmem);
	io_zc_sync_for_device(pp, netmem);
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

#define IO_PP_DMA_ATTRS (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)

static void io_pp_unmap_buf(struct net_iov *niov, struct page_pool *pp)
{
	netmem_ref netmem = net_iov_to_netmem(niov);
	dma_addr_t dma = page_pool_get_dma_addr_netmem(netmem);

	dma_unmap_page_attrs(pp->p.dev, dma, PAGE_SIZE << pp->p.order,
			     pp->p.dma_dir, IO_PP_DMA_ATTRS);
	page_pool_set_dma_addr_netmem(netmem, 0);
}

static int io_pp_map_buf(struct io_zcrx_area *area, int idx,
			 struct page_pool *pp)
{
	struct net_iov *niov = &area->nia.niovs[idx];
	struct page *page = area->pages[idx];
	netmem_ref netmem = net_iov_to_netmem(niov);
	dma_addr_t dma_addr;
	int ret;

	dma_addr = dma_map_page_attrs(pp->p.dev, page, 0,
				      PAGE_SIZE << pp->p.order, pp->p.dma_dir,
				      IO_PP_DMA_ATTRS);
	ret = dma_mapping_error(pp->p.dev, dma_addr);
	if (ret)
		return ret;

	if (WARN_ON_ONCE(page_pool_set_dma_addr_netmem(netmem, dma_addr))) {
		dma_unmap_page_attrs(pp->p.dev, dma_addr,
				     PAGE_SIZE << pp->p.order, pp->p.dma_dir,
				     IO_PP_DMA_ATTRS);
		return -EFAULT;
	}

	io_zc_sync_for_device(pp, netmem);
	return 0;
}

static int io_pp_map_area(struct io_zcrx_area *area, struct page_pool *pp)
{
	int i, ret = 0;

	for (i = 0; i < area->nia.num_niovs; i++) {
		ret = io_pp_map_buf(area, i, pp);
		if (ret)
			break;
	}

	if (ret) {
		while (i--)
			io_pp_unmap_buf(&area->nia.niovs[i], pp);
	}
	return ret;
}

static void io_pp_unmap_area(struct io_zcrx_area *area, struct page_pool *pp)
{
	int i;

	for (i = 0; i < area->nia.num_niovs; i++)
		io_pp_unmap_buf(&area->nia.niovs[i], pp);
}

static int io_pp_zc_init(struct page_pool *pp)
{
	struct io_zcrx_ifq *ifq = pp->mp_priv;
	int ret;

	if (!ifq)
		return -EINVAL;
	if (pp->p.order != 0)
		return -EINVAL;
	if (!pp->p.napi)
		return -EINVAL;

	if (pp->p.flags & PP_FLAG_DMA_MAP) {
		ret = io_pp_map_area(ifq->area, pp);
		if (ret)
			return ret;
	}

	percpu_ref_get(&ifq->ctx->refs);
	ifq->pp = pp;
	return 0;
}

static void io_pp_zc_destroy(struct page_pool *pp)
{
	struct io_zcrx_ifq *ifq = pp->mp_priv;
	struct io_zcrx_area *area = ifq->area;

	if (pp->p.flags & PP_FLAG_DMA_MAP)
		io_pp_unmap_area(ifq->area, pp);

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

static void io_napi_refill(void *data)
{
	struct io_zc_refill_data *rd = data;
	struct io_zcrx_ifq *ifq = rd->ifq;
	netmem_ref netmem;

	if (WARN_ON_ONCE(!ifq->pp))
		return;

	netmem = page_pool_alloc_netmem(ifq->pp, GFP_ATOMIC | __GFP_NOWARN);
	if (!netmem)
		return;
	if (WARN_ON_ONCE(!netmem_is_net_iov(netmem)))
		return;

	rd->niov = netmem_to_net_iov(netmem);
}

static struct net_iov *io_zc_get_buf_task_safe(struct io_zcrx_ifq *ifq)
{
	struct io_zc_refill_data rd = {
		.ifq = ifq,
	};

	napi_execute(ifq->pp->p.napi, io_napi_refill, &rd);
	return rd.niov;
}

static bool io_zcrx_queue_cqe(struct io_kiocb *req, struct net_iov *niov,
			      struct io_zcrx_ifq *ifq, int off, int len)
{
	struct io_uring_rbuf_cqe *rcqe;
	struct io_zcrx_area *area;
	struct io_uring_cqe *cqe;
	u64 off2;

	if (!io_defer_get_uncommited_cqe(req->ctx, &cqe))
		return false;

	cqe->user_data = req->cqe.user_data;
	cqe->res = len;
	cqe->flags = IORING_CQE_F_MORE;

	area = container_of(niov->owner, struct io_zcrx_area, nia);

	rcqe = (struct io_uring_rbuf_cqe *)(cqe + 1);
	rcqe->off = net_iov_virtual_addr(niov) + off;

	area = io_zcrx_iov_to_area(niov);
	off2 = ((u64)area->area_id << IORING_RBUF_REGION_SHIFT) |
	       (net_iov_idx(niov) * PAGE_SIZE + off);
	WARN_ON(rcqe->off != off2);

	memset(rcqe->__pad, 0, sizeof(rcqe->__pad));
	return true;
}

static ssize_t io_zcrx_copy_chunk(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
				  void *data, unsigned int offset, size_t len)
{
	size_t copy_size, copied = 0;
	int ret = 0, off = 0;
	struct page *page;
	u8 *vaddr;

	do {
		struct net_iov *niov;

		niov = io_zc_get_buf_task_safe(ifq);
		if (!niov) {
			ret = -ENOMEM;
			break;
		}

		page = io_zcrx_iov_page(niov);
		vaddr = kmap_local_page(page);
		copy_size = min_t(size_t, PAGE_SIZE, len);
		memcpy(vaddr, data + offset, copy_size);
		kunmap_local(vaddr);

		if (!io_zcrx_queue_cqe(req, niov, ifq, off, copy_size)) {
			napi_pp_put_page(net_iov_to_netmem(niov));
			return -ENOSPC;
		}

		io_zcrx_get_buf_uref(niov);
		napi_pp_put_page(net_iov_to_netmem(niov));

		offset += copy_size;
		len -= copy_size;
		copied += copy_size;
	} while (offset < len);

	return copied ? copied : ret;
}

static int io_zcrx_recv_frag(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
			     const skb_frag_t *frag, int off, int len)
{
	off += skb_frag_off(frag);

	if (likely(skb_frag_is_net_iov(frag))) {
		struct net_iov *niov;

		niov = netmem_to_net_iov(frag->netmem);
		if (niov->pp->mp_ops != &io_uring_pp_zc_ops ||
		    niov->pp->mp_priv != ifq)
			return -EFAULT;

		if (!io_zcrx_queue_cqe(req, niov, ifq, off, len))
			return -ENOSPC;
		io_zcrx_get_buf_uref(niov);
	} else {
		struct page *page = skb_frag_page(frag);
		u32 p_off, p_len, t, copied = 0;
		u8 *vaddr;
		int ret = 0;

		skb_frag_foreach_page(frag, off, len,
				      page, p_off, p_len, t) {
			vaddr = kmap_local_page(page);
			ret = io_zcrx_copy_chunk(req, ifq, vaddr, p_off, p_len);
			kunmap_local(vaddr);

			if (ret < 0)
				return copied ? copied : ret;
			copied += ret;
		}
		len = copied;
	}

	return len;
}

static int
io_zcrx_recv_skb(read_descriptor_t *desc, struct sk_buff *skb,
		 unsigned int offset, size_t len)
{
	struct io_zcrx_args *args = desc->arg.data;
	struct io_zcrx_ifq *ifq = args->ifq;
	struct io_kiocb *req = args->req;
	struct sk_buff *frag_iter;
	unsigned start, start_off = offset;
	int i, copy, end, off;
	int ret = 0;

	if (unlikely(args->nr_skbs++) > IO_SKBS_PER_CALL_LIMIT)
		return -EAGAIN;

	if (unlikely(offset < skb_headlen(skb))) {
		ssize_t copied;
		size_t to_copy;

		to_copy = min_t(size_t, skb_headlen(skb) - offset, len);
		copied = io_zcrx_copy_chunk(req, ifq, skb->data, offset, to_copy);
		if (copied < 0) {
			ret = copied;
			goto out;
		}
		offset += copied;
		len -= copied;
		if (!len)
			goto out;
		if (offset != skb_headlen(skb))
			goto out;
	}

	start = skb_headlen(skb);

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		const skb_frag_t *frag;

		if (WARN_ON(start > offset + len))
			return -EFAULT;

		frag = &skb_shinfo(skb)->frags[i];
		end = start + skb_frag_size(frag);

		if (offset < end) {
			copy = end - offset;
			if (copy > len)
				copy = len;

			off = offset - start;
			ret = io_zcrx_recv_frag(req, ifq, frag, off, copy);
			if (ret < 0)
				goto out;

			offset += ret;
			len -= ret;
			if (len == 0 || ret != copy)
				goto out;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		if (WARN_ON(start > offset + len))
			return -EFAULT;

		end = start + frag_iter->len;
		if (offset < end) {
			copy = end - offset;
			if (copy > len)
				copy = len;

			off = offset - start;
			ret = io_zcrx_recv_skb(desc, frag_iter, off, copy);
			if (ret < 0)
				goto out;

			offset += ret;
			len -= ret;
			if (len == 0 || ret != copy)
				goto out;
		}
		start = end;
	}

out:
	if (offset == start_off)
		return ret;
	return offset - start_off;
}

static int io_zcrx_tcp_recvmsg(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
				struct sock *sk, int flags,
				unsigned int issue_flags)
{
	struct io_zcrx_args args = {
		.req = req,
		.ifq = ifq,
		.sock = sk->sk_socket,
	};
	read_descriptor_t rd_desc = {
		.count = 1,
		.arg.data = &args,
	};
	int ret;

	lock_sock(sk);
	ret = tcp_read_sock(sk, &rd_desc, io_zcrx_recv_skb);
	if (ret <= 0) {
		if (ret < 0 || sock_flag(sk, SOCK_DONE))
			goto out;
		if (sk->sk_err)
			ret = sock_error(sk);
		else if (sk->sk_shutdown & RCV_SHUTDOWN)
			goto out;
		else if (sk->sk_state == TCP_CLOSE)
			ret = -ENOTCONN;
		else
			ret = -EAGAIN;
	} else if (unlikely(args.nr_skbs > IO_SKBS_PER_CALL_LIMIT) &&
		   (issue_flags & IO_URING_F_MULTISHOT)) {
		ret = IOU_REQUEUE;
	} else if (sock_flag(sk, SOCK_DONE)) {
		/* Make it to retry until it finally gets 0. */
		ret = -EAGAIN;
	}
out:
	release_sock(sk);
	return ret;
}

int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
		 struct socket *sock, unsigned int flags,
		 unsigned int issue_flags)
{
	struct sock *sk = sock->sk;
	const struct proto *prot = READ_ONCE(sk->sk_prot);

	if (prot->recvmsg != tcp_recvmsg)
		return -EPROTONOSUPPORT;

	sock_rps_record_flow(sk);
	return io_zcrx_tcp_recvmsg(req, ifq, sk, flags, issue_flags);
}

struct page *io_iov_get_page(netmem_ref netmem)
{
	struct net_iov *niov;

	if (WARN_ON_ONCE(!netmem_is_net_iov(netmem)))
		return NULL;
	niov = netmem_to_net_iov(netmem);

	if (WARN_ON_ONCE(niov->pp->mp_ops != &io_uring_pp_zc_ops))
		return  NULL;
	return io_zcrx_iov_page(niov);
}
EXPORT_SYMBOL_GPL(io_iov_get_page);

#endif
