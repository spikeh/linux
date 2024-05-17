// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *      Devmem TCP
 *
 *      Authors:	Mina Almasry <almasrymina@google.com>
 *			Willem de Bruijn <willemdebruijn.kernel@gmail.com>
 *			Kaiyuan Zhang <kaiyuanz@google.com
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/netdevice.h>
#include <trace/events/page_pool.h>
#include <net/netdev_rx_queue.h>
#include <net/page_pool/types.h>
#include <net/page_pool/helpers.h>
#include <linux/genalloc.h>
#include <linux/dma-buf.h>
#include <net/devmem.h>
#include <net/netdev_queues.h>

/* Device memory support */

#ifdef CONFIG_DMA_SHARED_BUFFER
static void net_devmem_dmabuf_free_chunk_owner(struct gen_pool *genpool,
					       struct gen_pool_chunk *chunk,
					       void *not_used)
{
	struct dmabuf_genpool_chunk_owner *owner = chunk->owner;

	kvfree(owner->niovs);
	kfree(owner);
}

void __net_devmem_dmabuf_binding_free(struct net_devmem_dmabuf_binding *binding)
{
	size_t size, avail;

	gen_pool_for_each_chunk(binding->chunk_pool,
				net_devmem_dmabuf_free_chunk_owner, NULL);

	size = gen_pool_size(binding->chunk_pool);
	avail = gen_pool_avail(binding->chunk_pool);

	if (!WARN(size != avail, "can't destroy genpool. size=%zu, avail=%zu",
		  size, avail))
		gen_pool_destroy(binding->chunk_pool);

	dma_buf_unmap_attachment(binding->attachment, binding->sgt,
				 DMA_FROM_DEVICE);
	dma_buf_detach(binding->dmabuf, binding->attachment);
	dma_buf_put(binding->dmabuf);
	xa_destroy(&binding->bound_rxq_list);
	kfree(binding);
}

/* Protected by rtnl_lock() */
static DEFINE_XARRAY_FLAGS(net_devmem_dmabuf_bindings, XA_FLAGS_ALLOC1);

void net_devmem_unbind_dmabuf(struct net_devmem_dmabuf_binding *binding)
{
	struct netdev_rx_queue *rxq;
	unsigned long xa_idx;
	unsigned int rxq_idx;

	if (!binding)
		return;

	if (binding->list.next)
		list_del(&binding->list);

	xa_for_each(&binding->bound_rxq_list, xa_idx, rxq) {
		if (rxq->mp_params.mp_priv == binding) {
			/* We hold the rtnl_lock while binding/unbinding
			 * dma-buf, so we can't race with another thread that
			 * is also modifying this value. However, the page_pool
			 * may read this config while it's creating its
			 * rx-queues. WRITE_ONCE() here to match the
			 * READ_ONCE() in the page_pool.
			 */
			WRITE_ONCE(rxq->mp_params.mp_ops, NULL);
			WRITE_ONCE(rxq->mp_params.mp_priv, NULL);

			rxq_idx = get_netdev_rx_queue_index(rxq);

			netdev_rx_queue_restart(binding->dev, rxq_idx);
		}
	}

	xa_erase(&net_devmem_dmabuf_bindings, binding->id);

	net_devmem_dmabuf_binding_put(binding);
}

int net_devmem_bind_dmabuf_to_queue(struct net_device *dev, u32 rxq_idx,
				    struct net_devmem_dmabuf_binding *binding)
{
	struct netdev_rx_queue *rxq;
	u32 xa_idx;
	int err;

	if (rxq_idx >= dev->num_rx_queues)
		return -ERANGE;

	rxq = __netif_get_rx_queue(dev, rxq_idx);
	if (rxq->mp_params.mp_priv)
		return -EEXIST;

	err = xa_alloc(&binding->bound_rxq_list, &xa_idx, rxq, xa_limit_32b,
		       GFP_KERNEL);
	if (err)
		return err;

	/* We hold the rtnl_lock while binding/unbinding dma-buf, so we can't
	 * race with another thread that is also modifying this value. However,
	 * the driver may read this config while it's creating its * rx-queues.
	 * WRITE_ONCE() here to match the READ_ONCE() in the driver.
	 */
	WRITE_ONCE(rxq->mp_params.mp_priv, binding);

	err = netdev_rx_queue_restart(dev, rxq_idx);
	if (err)
		goto err_xa_erase;

	return 0;

err_xa_erase:
	WRITE_ONCE(rxq->mp_params.mp_ops, NULL);
	WRITE_ONCE(rxq->mp_params.mp_priv, NULL);
	xa_erase(&binding->bound_rxq_list, xa_idx);

	return err;
}

int net_devmem_bind_dmabuf(struct net_device *dev, unsigned int dmabuf_fd,
			   struct net_devmem_dmabuf_binding **out)
{
	struct net_devmem_dmabuf_binding *binding;
	static u32 id_alloc_next;
	struct scatterlist *sg;
	struct dma_buf *dmabuf;
	unsigned int sg_idx, i;
	unsigned long virtual;
	int err;

	dmabuf = dma_buf_get(dmabuf_fd);
	if (IS_ERR(dmabuf))
		return -EBADFD;

	binding = kzalloc_node(sizeof(*binding), GFP_KERNEL,
			       dev_to_node(&dev->dev));
	if (!binding) {
		err = -ENOMEM;
		goto err_put_dmabuf;
	}

	binding->dev = dev;

	err = xa_alloc_cyclic(&net_devmem_dmabuf_bindings, &binding->id,
			      binding, xa_limit_32b, &id_alloc_next,
			      GFP_KERNEL);
	if (err < 0)
		goto err_free_binding;

	xa_init_flags(&binding->bound_rxq_list, XA_FLAGS_ALLOC);

	refcount_set(&binding->ref, 1);

	binding->dmabuf = dmabuf;

	binding->attachment = dma_buf_attach(binding->dmabuf, dev->dev.parent);
	if (IS_ERR(binding->attachment)) {
		err = PTR_ERR(binding->attachment);
		goto err_free_id;
	}

	binding->sgt =
		dma_buf_map_attachment(binding->attachment, DMA_BIDIRECTIONAL);
	if (IS_ERR(binding->sgt)) {
		err = PTR_ERR(binding->sgt);
		goto err_detach;
	}

	/* For simplicity we expect to make PAGE_SIZE allocations, but the
	 * binding can be much more flexible than that. We may be able to
	 * allocate MTU sized chunks here. Leave that for future work...
	 */
	binding->chunk_pool =
		gen_pool_create(PAGE_SHIFT, dev_to_node(&dev->dev));
	if (!binding->chunk_pool) {
		err = -ENOMEM;
		goto err_unmap;
	}

	virtual = 0;
	for_each_sgtable_dma_sg(binding->sgt, sg, sg_idx) {
		dma_addr_t dma_addr = sg_dma_address(sg);
		struct dmabuf_genpool_chunk_owner *owner;
		size_t len = sg_dma_len(sg);
		struct net_iov *niov;

		owner = kzalloc_node(sizeof(*owner), GFP_KERNEL,
				     dev_to_node(&dev->dev));
		owner->base_virtual = virtual;
		owner->base_dma_addr = dma_addr;
		owner->num_niovs = len / PAGE_SIZE;
		owner->binding = binding;

		err = gen_pool_add_owner(binding->chunk_pool, dma_addr,
					 dma_addr, len, dev_to_node(&dev->dev),
					 owner);
		if (err) {
			err = -EINVAL;
			goto err_free_chunks;
		}

		owner->niovs = kvmalloc_array(owner->num_niovs,
					      sizeof(*owner->niovs),
					      GFP_KERNEL);
		if (!owner->niovs) {
			err = -ENOMEM;
			goto err_free_chunks;
		}

		for (i = 0; i < owner->num_niovs; i++) {
			niov = &owner->niovs[i];
			niov->owner = owner;
		}

		virtual += len;
	}

	*out = binding;

	return 0;

err_free_chunks:
	gen_pool_for_each_chunk(binding->chunk_pool,
				net_devmem_dmabuf_free_chunk_owner, NULL);
	gen_pool_destroy(binding->chunk_pool);
err_unmap:
	dma_buf_unmap_attachment(binding->attachment, binding->sgt,
				 DMA_BIDIRECTIONAL);
err_detach:
	dma_buf_detach(dmabuf, binding->attachment);
err_free_id:
	xa_erase(&net_devmem_dmabuf_bindings, binding->id);
err_free_binding:
	kfree(binding);
err_put_dmabuf:
	dma_buf_put(dmabuf);
	return err;
}
#endif
