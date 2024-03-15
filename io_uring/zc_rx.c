// SPDX-License-Identifier: GPL-2.0
#if defined(CONFIG_PAGE_POOL)
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/io_uring.h>
#include <linux/netdevice.h>
#include <linux/nospec.h>

#include <net/page_pool/helpers.h>
#include <net/tcp.h>
#include <net/af_unix.h>
#include <net/rps.h>

#include <trace/events/page_pool.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "kbuf.h"
#include "zc_rx.h"
#include "rsrc.h"

struct io_zc_rx_args {
	struct io_kiocb		*req;
	struct io_zc_rx_ifq	*ifq;
	struct socket		*sock;
};

typedef int (*bpf_op_t)(struct net_device *dev, struct netdev_bpf *bpf);

static int __io_queue_mgmt(struct net_device *dev, struct io_zc_rx_ifq *ifq,
			   u16 queue_id)
{
	struct netdev_bpf cmd;
	bpf_op_t ndo_bpf;

	ndo_bpf = dev->netdev_ops->ndo_bpf;
	if (!ndo_bpf)
		return -EINVAL;

	cmd.command = XDP_SETUP_ZC_RX;
	cmd.zc_rx.ifq = ifq;
	cmd.zc_rx.queue_id = queue_id;
	return ndo_bpf(dev, &cmd);
}

static int io_open_zc_rxq(struct io_zc_rx_ifq *ifq)
{
	return __io_queue_mgmt(ifq->dev, ifq, ifq->if_rxq_id);
}

static int io_close_zc_rxq(struct io_zc_rx_ifq *ifq)
{
	return __io_queue_mgmt(ifq->dev, NULL, ifq->if_rxq_id);
}

static int io_allocate_rbuf_ring(struct io_zc_rx_ifq *ifq,
				 struct io_uring_zc_rx_ifq_reg *reg)
{
	gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO | __GFP_NOWARN | __GFP_COMP;
	size_t off, rq_size;
	void *ptr;

	off = sizeof(struct io_uring);
	rq_size = reg->rq_entries * sizeof(struct io_uring_rbuf_rqe);
	ptr = (void *) __get_free_pages(gfp, get_order(off + rq_size));
	if (!ptr)
		return -ENOMEM;
	ifq->rq_ring = (struct io_uring *)ptr;
	ifq->rqes = (struct io_uring_rbuf_rqe *)((char *)ptr + off);
	return 0;
}

static void io_free_rbuf_ring(struct io_zc_rx_ifq *ifq)
{
	if (ifq->rq_ring)
		folio_put(virt_to_folio(ifq->rq_ring));
}

static int io_zc_rx_init_buf(struct page *page, struct io_zc_rx_buf *buf)
{
	memset(&buf->niov, 0, sizeof(buf->niov));
	atomic_long_set(&buf->niov.pp_ref_count, 0);
	page_pool_set_dma_addr_netmem(net_iov_to_netmem(&buf->niov), 0);

	buf->page = page;
	get_page(page);
	return 0;
}

static void io_zc_rx_free_buf(struct io_zc_rx_buf *buf)
{
	struct page *page = buf->page;

	put_page(page);
}

static int io_zc_rx_init_pool(struct io_zc_rx_pool *pool,
			     struct io_mapped_ubuf *imu)
{
	struct io_zc_rx_buf *buf;
	struct page *page;
	int i, ret;

	for (i = 0; i < imu->nr_bvecs; i++) {
		page = imu->bvec[i].bv_page;
		buf = &pool->bufs[i];
		ret = io_zc_rx_init_buf(page, buf);
		if (ret)
			goto err;

		pool->freelist[i] = i;
	}

	pool->free_count = imu->nr_bvecs;
	return 0;
err:
	while (i--) {
		buf = &pool->bufs[i];
		io_zc_rx_free_buf(buf);
	}
	return ret;
}

static int io_zc_rx_create_pool(struct io_ring_ctx *ctx,
				struct io_zc_rx_ifq *ifq,
				u16 id)
{
	struct io_mapped_ubuf *imu;
	struct io_zc_rx_pool *pool;
	int nr_pages;
	int ret;

	if (ifq->pool)
		return -EFAULT;

	if (unlikely(id >= ctx->nr_user_bufs))
		return -EFAULT;
	id = array_index_nospec(id, ctx->nr_user_bufs);
	imu = ctx->user_bufs[id];
	if (imu->ubuf & ~PAGE_MASK || imu->ubuf_end & ~PAGE_MASK)
		return -EFAULT;

	ret = -ENOMEM;
	nr_pages = imu->nr_bvecs;
	pool = kvmalloc(struct_size(pool, freelist, nr_pages), GFP_KERNEL);
	if (!pool)
		goto err;

	pool->bufs = kvmalloc_array(nr_pages, sizeof(*pool->bufs), GFP_KERNEL);
	if (!pool->bufs)
		goto err_buf;

	ret = io_zc_rx_init_pool(pool, imu);
	if (ret)
		goto err_map;

	pool->ifq = ifq;
	pool->pool_id = id;
	pool->nr_bufs = nr_pages;
	spin_lock_init(&pool->freelist_lock);
	ifq->pool = pool;
	return 0;
err_map:
	kvfree(pool->bufs);
err_buf:
	kvfree(pool);
err:
	return ret;
}

static void io_zc_rx_free_pool(struct io_zc_rx_pool *pool)
{
	struct io_zc_rx_buf *buf;

	for (int i = 0; i < pool->nr_bufs; i++) {
		buf = &pool->bufs[i];
		io_zc_rx_free_buf(buf);
	}
	kvfree(pool->bufs);
	kvfree(pool);
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

	if (ifq->if_rxq_id != -1) {
		io_close_zc_rxq(ifq);
		ifq->if_rxq_id = -1;
	}
}

static void io_zc_rx_ifq_free(struct io_zc_rx_ifq *ifq)
{
	io_shutdown_ifq(ifq);

	if (ifq->pool)
		io_zc_rx_free_pool(ifq->pool);
	if (ifq->dev)
		dev_put(ifq->dev);
	io_free_rbuf_ring(ifq);
	kfree(ifq);
}

int io_register_zc_rx_ifq(struct io_ring_ctx *ctx,
			  struct io_uring_zc_rx_ifq_reg __user *arg)
{
	struct io_uring_zc_rx_ifq_reg reg;
	struct io_zc_rx_ifq *ifq;
	size_t ring_sz, rqes_sz;
	int ret;

	if (!(ctx->flags & IORING_SETUP_DEFER_TASKRUN &&
	      ctx->flags & IORING_SETUP_CQE32))
		return -EINVAL;
	if (copy_from_user(&reg, arg, sizeof(reg)))
		return -EFAULT;
	if (ctx->ifq)
		return -EBUSY;
	if (reg.if_rxq_id == -1)
		return -EINVAL;

	ifq = io_zc_rx_ifq_alloc(ctx);
	if (!ifq)
		return -ENOMEM;

	ret = io_allocate_rbuf_ring(ifq, &reg);
	if (ret)
		goto err;

	ret = -ENODEV;
	ifq->dev = dev_get_by_index(current->nsproxy->net_ns, reg.if_idx);
	if (!ifq->dev)
		goto err;

	ret = io_zc_rx_create_pool(ctx, ifq, reg.region_id);
	if (ret)
		goto err;

	ifq->rq_entries = reg.rq_entries;
	ifq->if_rxq_id = reg.if_rxq_id;

	ret = io_open_zc_rxq(ifq);
	if (ret)
		goto err;

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

static inline struct io_zc_rx_buf *io_niov_to_buf(struct net_iov *niov)
{
	return container_of(niov, struct io_zc_rx_buf, niov);
}

static inline unsigned io_buf_pgid(struct io_zc_rx_pool *pool,
				   struct io_zc_rx_buf *buf)
{
	return buf - pool->bufs;
}

static void io_zc_rx_get_buf_uref(struct io_zc_rx_buf *buf)
{
	atomic_long_add(IO_ZC_RX_UREF, &buf->niov.pp_ref_count);
}

static bool io_zc_rx_buf_put(struct io_zc_rx_buf *buf, int nr)
{
	return atomic_long_sub_and_test(nr, &buf->niov.pp_ref_count);
}

static bool io_zc_rx_put_buf_uref(struct io_zc_rx_buf *buf)
{
	if (atomic_long_read(&buf->niov.pp_ref_count) < IO_ZC_RX_UREF)
		return false;

	return io_zc_rx_buf_put(buf, IO_ZC_RX_UREF);
}

static inline netmem_ref io_zc_buf_to_netmem(struct io_zc_rx_buf *buf)
{
	return net_iov_to_netmem(&buf->niov);
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
				      struct io_zc_rx_buf *buf)
{
	netmem_ref netmem = io_zc_buf_to_netmem(buf);

	page_pool_set_pp_info(pp, netmem);
	io_zc_sync_for_device(pp, netmem);
	pp->alloc.cache[pp->alloc.count++] = netmem;
}

static inline u32 io_zc_rx_rqring_entries(struct io_zc_rx_ifq *ifq)
{
	u32 entries;

	entries = smp_load_acquire(&ifq->rq_ring->tail) - ifq->cached_rq_head;
	return min(entries, ifq->rq_entries);
}

static void io_zc_rx_ring_refill(struct page_pool *pp,
				 struct io_zc_rx_ifq *ifq)
{
	unsigned int entries = io_zc_rx_rqring_entries(ifq);
	unsigned int mask = ifq->rq_entries - 1;
	struct io_zc_rx_pool *pool = ifq->pool;

	if (unlikely(!entries))
		return;

	while (entries--) {
		unsigned int rq_idx = ifq->cached_rq_head++ & mask;
		struct io_uring_rbuf_rqe *rqe = &ifq->rqes[rq_idx];
		u32 pgid = rqe->off / PAGE_SIZE;
		struct io_zc_rx_buf *buf = &pool->bufs[pgid];

		if (!io_zc_rx_put_buf_uref(buf))
			continue;
		io_zc_add_pp_cache(pp, buf);
		if (pp->alloc.count >= PP_ALLOC_CACHE_REFILL)
			break;
	}
	smp_store_release(&ifq->rq_ring->head, ifq->cached_rq_head);
}

static void io_zc_rx_refill_slow(struct page_pool *pp, struct io_zc_rx_ifq *ifq)
{
	struct io_zc_rx_pool *pool = ifq->pool;

	spin_lock_bh(&pool->freelist_lock);
	while (pool->free_count && pp->alloc.count < PP_ALLOC_CACHE_REFILL) {
		struct io_zc_rx_buf *buf;
		u32 pgid;

		pgid = pool->freelist[--pool->free_count];
		buf = &pool->bufs[pgid];

		io_zc_add_pp_cache(pp, buf);
		pp->pages_state_hold_cnt++;
		trace_page_pool_state_hold(pp, io_zc_buf_to_netmem(buf),
					   pp->pages_state_hold_cnt);
	}
	spin_unlock_bh(&pool->freelist_lock);
}

static void io_zc_rx_recycle_buf(struct io_zc_rx_pool *pool,
				 struct io_zc_rx_buf *buf)
{
	spin_lock_bh(&pool->freelist_lock);
	pool->freelist[pool->free_count++] = io_buf_pgid(pool, buf);
	spin_unlock_bh(&pool->freelist_lock);
}

static netmem_ref io_pp_zc_alloc_pages(struct page_pool *pp, gfp_t gfp)
{
	struct io_zc_rx_ifq *ifq = pp->mp_priv;

	/* pp should already be ensuring that */
	if (unlikely(pp->alloc.count))
		goto out_return;

	io_zc_rx_ring_refill(pp, ifq);
	if (likely(pp->alloc.count))
		goto out_return;

	io_zc_rx_refill_slow(pp, ifq);
	if (!pp->alloc.count)
		return 0;
out_return:
	return pp->alloc.cache[--pp->alloc.count];
}

static bool io_pp_zc_release_page(struct page_pool *pp, netmem_ref netmem)
{
	struct io_zc_rx_ifq *ifq = pp->mp_priv;
	struct io_zc_rx_buf *buf;
	struct net_iov *niov;

	if (WARN_ON_ONCE(!netmem_is_net_iov(netmem)))
		return false;

	niov = netmem_to_net_iov(netmem);
	buf = io_niov_to_buf(niov);

	if (io_zc_rx_buf_put(buf, 1))
		io_zc_rx_recycle_buf(ifq->pool, buf);
	return false;
}

static void io_pp_zc_scrub(struct page_pool *pp)
{
	struct io_zc_rx_ifq *ifq = pp->mp_priv;
	struct io_zc_rx_pool *pool = ifq->pool;
	int i;

	for (i = 0; i < pool->nr_bufs; i++) {
		struct io_zc_rx_buf *buf = &pool->bufs[i];
		int count;

		if (!io_zc_rx_put_buf_uref(buf))
			continue;
		io_zc_rx_recycle_buf(pool, buf);

		count = atomic_inc_return_relaxed(&pp->pages_state_release_cnt);
		trace_page_pool_state_release(pp, io_zc_buf_to_netmem(buf), count);
	}
}

#define IO_PP_DMA_ATTRS (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_WEAK_ORDERING)

static void io_pp_unmap_buf(struct io_zc_rx_buf *buf, struct page_pool *pp)
{
	netmem_ref netmem = net_iov_to_netmem(&buf->niov);
	dma_addr_t dma = page_pool_get_dma_addr_netmem(netmem);

	dma_unmap_page_attrs(pp->p.dev, dma, PAGE_SIZE << pp->p.order,
			     pp->p.dma_dir, IO_PP_DMA_ATTRS);
	page_pool_set_dma_addr_netmem(netmem, 0);
}

static int io_pp_map_buf(struct io_zc_rx_buf *buf, struct page_pool *pp)
{
	netmem_ref netmem = net_iov_to_netmem(&buf->niov);
	dma_addr_t dma_addr;
	int ret;

	dma_addr = dma_map_page_attrs(pp->p.dev, buf->page, 0,
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

static int io_pp_map_pool(struct io_zc_rx_pool *pool, struct page_pool *pp)
{
	int i, ret = 0;

	for (i = 0; i < pool->nr_bufs; i++) {
		ret = io_pp_map_buf(&pool->bufs[i], pp);
		if (ret)
			break;
	}

	if (ret) {
		while (i--)
			io_pp_unmap_buf(&pool->bufs[i], pp);
	}
	return ret;
}

static void io_pp_unmap_pool(struct io_zc_rx_pool *pool, struct page_pool *pp)
{
	int i;

	for (i = 0; i < pool->nr_bufs; i++)
		io_pp_unmap_buf(&pool->bufs[i], pp);
}

static int io_pp_zc_init(struct page_pool *pp)
{
	struct io_zc_rx_ifq *ifq = pp->mp_priv;
	int ret;

	if (!ifq)
		return -EINVAL;
	if (pp->p.order != 0)
		return -EINVAL;
	if (!pp->p.napi)
		return -EINVAL;

	if (pp->p.flags & PP_FLAG_DMA_MAP) {
		ret = io_pp_map_pool(ifq->pool, pp);
		if (ret)
			return ret;
	}

	percpu_ref_get(&ifq->ctx->refs);
	ifq->pp = pp;
	return 0;
}

static void io_pp_zc_destroy(struct page_pool *pp)
{
	struct io_zc_rx_ifq *ifq = pp->mp_priv;
	struct io_zc_rx_pool *pool = ifq->pool;

	if (pp->p.flags & PP_FLAG_DMA_MAP)
		io_pp_unmap_pool(ifq->pool, pp);

	ifq->pp = NULL;

	if (WARN_ON_ONCE(pool->free_count != pool->nr_bufs))
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

static bool zc_rx_queue_cqe(struct io_kiocb *req, struct io_zc_rx_buf *buf,
			   struct io_zc_rx_ifq *ifq, int off, int len)
{
	struct io_uring_rbuf_cqe *rcqe;
	struct io_uring_cqe *cqe;

	if (!io_defer_get_uncommited_cqe(req->ctx, &cqe))
		return false;

	cqe->user_data = req->cqe.user_data;
	cqe->res = 0;
	cqe->flags = IORING_CQE_F_MORE;

	rcqe = (struct io_uring_rbuf_cqe *)(cqe + 1);
	rcqe->region = 0;
	rcqe->off = io_buf_pgid(ifq->pool, buf) * PAGE_SIZE + off;
	rcqe->len = len;
	memset(rcqe->__pad, 0, sizeof(rcqe->__pad));
	return true;
}

static int zc_rx_recv_frag(struct io_kiocb *req, struct io_zc_rx_ifq *ifq,
			   const skb_frag_t *frag, int off, int len)
{
	off += skb_frag_off(frag);

	if (likely(skb_frag_is_net_iov(frag))) {
		struct io_zc_rx_buf *buf;
		struct net_iov *niov;

		niov = netmem_to_net_iov(frag->netmem);
		if (niov->pp->mp_ops != &io_uring_pp_zc_ops ||
		    niov->pp->mp_priv != ifq)
			return -EFAULT;

		buf = io_niov_to_buf(niov);
		if (!zc_rx_queue_cqe(req, buf, ifq, off, len))
			return -ENOSPC;
		io_zc_rx_get_buf_uref(buf);
	} else {
		return -EOPNOTSUPP;
	}

	return len;
}

static int
zc_rx_recv_skb(read_descriptor_t *desc, struct sk_buff *skb,
	       unsigned int offset, size_t len)
{
	struct io_zc_rx_args *args = desc->arg.data;
	struct io_zc_rx_ifq *ifq = args->ifq;
	struct io_kiocb *req = args->req;
	struct sk_buff *frag_iter;
	unsigned start, start_off;
	int i, copy, end, off;
	int ret = 0;

	start = skb_headlen(skb);
	start_off = offset;

	if (offset < start)
		return -EOPNOTSUPP;

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
			ret = zc_rx_recv_frag(req, ifq, frag, off, copy);
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
			ret = zc_rx_recv_skb(desc, frag_iter, off, copy);
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

static int io_zc_rx_tcp_recvmsg(struct io_kiocb *req, struct io_zc_rx_ifq *ifq,
				struct sock *sk, int flags)
{
	struct io_zc_rx_args args = {
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
	ret = tcp_read_sock(sk, &rd_desc, zc_rx_recv_skb);
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
	}
out:
	release_sock(sk);
	return ret;
}

int io_zc_rx_recv(struct io_kiocb *req, struct io_zc_rx_ifq *ifq,
		  struct socket *sock, unsigned int flags)
{
	struct sock *sk = sock->sk;
	const struct proto *prot = READ_ONCE(sk->sk_prot);

	if (prot->recvmsg != tcp_recvmsg)
		return -EPROTONOSUPPORT;

	sock_rps_record_flow(sk);
	return io_zc_rx_tcp_recvmsg(req, ifq, sk, flags);
}

#endif
