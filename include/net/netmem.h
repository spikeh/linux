/* SPDX-License-Identifier: GPL-2.0
 *
 *	Network memory
 *
 *	Author:	Mina Almasry <almasrymina@google.com>
 */

#ifndef _NET_NETMEM_H
#define _NET_NETMEM_H

#include <net/devmem.h>

/* net_iov */

struct net_iov {
	struct dmabuf_genpool_chunk_owner *owner;
	unsigned long dma_addr;
};

static inline struct dmabuf_genpool_chunk_owner *
net_iov_owner(const struct net_iov *niov)
{
	return niov->owner;
}

static inline unsigned int net_iov_idx(const struct net_iov *niov)
{
	return niov - net_iov_owner(niov)->niovs;
}

static inline dma_addr_t net_iov_dma_addr(const struct net_iov *niov)
{
	struct dmabuf_genpool_chunk_owner *owner = net_iov_owner(niov);

	return owner->base_dma_addr +
	       ((dma_addr_t)net_iov_idx(niov) << PAGE_SHIFT);
}

static inline struct netdev_dmabuf_binding *
net_iov_binding(const struct net_iov *niov)
{
	return net_iov_owner(niov)->binding;
}

/* netmem */

/**
 * typedef netmem_ref - a nonexistent type marking a reference to generic
 * network memory.
 *
 * A netmem_ref currently is always a reference to a struct page. This
 * abstraction is introduced so support for new memory types can be added.
 *
 * Use the supplied helpers to obtain the underlying memory pointer and fields.
 */
typedef unsigned long __bitwise netmem_ref;

/* This conversion fails (returns NULL) if the netmem_ref is not struct page
 * backed.
 *
 * Currently struct page is the only possible netmem, and this helper never
 * fails.
 */
static inline struct page *netmem_to_page(netmem_ref netmem)
{
	return (__force struct page *)netmem;
}

/* Converting from page to netmem is always safe, because a page can always be
 * a netmem.
 */
static inline netmem_ref page_to_netmem(struct page *page)
{
	return (__force netmem_ref)page;
}

#endif /* _NET_NETMEM_H */
