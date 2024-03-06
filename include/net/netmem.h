/* SPDX-License-Identifier: GPL-2.0
 *
 *	Network memory
 *
 *	Author:	Mina Almasry <almasrymina@google.com>
 */

#ifndef _NET_NETMEM_H
#define _NET_NETMEM_H

#include <net/devmem.h>
#include <net/net_debug.h>

/* net_iov */

DECLARE_STATIC_KEY_FALSE(page_pool_mem_providers);

/*  We overload the LSB of the struct page pointer to indicate whether it's
 *  a page or net_iov.
 */
#define NET_IOV 0x01UL

struct net_iov {
	unsigned long __unused_padding;
	unsigned long pp_magic;
	struct page_pool *pp;
	struct dmabuf_genpool_chunk_owner *owner;
	unsigned long dma_addr;
	atomic_long_t pp_ref_count;
};

/* These fields in struct page are used by the page_pool and net stack:
 *
 *	struct {
 *		unsigned long pp_magic;
 *		struct page_pool *pp;
 *		unsigned long _pp_mapping_pad;
 *		unsigned long dma_addr;
 *		atomic_long_t pp_ref_count;
 *	};
 *
 * We mirror the page_pool fields here so the page_pool can access these fields
 * without worrying whether the underlying fields belong to a page or net_iov.
 *
 * The non-net stack fields of struct page are private to the mm stack and must
 * never be mirrored to net_iov.
 */
#define NET_IOV_ASSERT_OFFSET(pg, iov)             \
	static_assert(offsetof(struct page, pg) == \
		      offsetof(struct net_iov, iov))
NET_IOV_ASSERT_OFFSET(pp_magic, pp_magic);
NET_IOV_ASSERT_OFFSET(pp, pp);
NET_IOV_ASSERT_OFFSET(dma_addr, dma_addr);
NET_IOV_ASSERT_OFFSET(pp_ref_count, pp_ref_count);
#undef NET_IOV_ASSERT_OFFSET

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

/* Converting from page to netmem is always safe, because a page can always be
 * a netmem.
 */
static inline bool netmem_is_net_iov(const netmem_ref netmem)
{
#ifdef CONFIG_PAGE_POOL
	return static_branch_unlikely(&page_pool_mem_providers) &&
	       (__force unsigned long)netmem & NET_IOV;
#else
	return false;
#endif
}

/* This conversion fails (returns NULL) if the netmem_ref is not struct page
 * backed.
 *
 * Currently struct page is the only possible netmem, and this helper never
 * fails.
 */
static inline struct page *netmem_to_page(netmem_ref netmem)
{
	if (WARN_ON_ONCE(netmem_is_net_iov(netmem)))
		return NULL;

	return (__force struct page *)netmem;
}

/* Converting from page to netmem is always safe and possible, because a page
 * can always be a netmem.
 */
static inline netmem_ref page_to_netmem(struct page *page)
{
	return (__force netmem_ref)page;
}

static inline int netmem_ref_count(netmem_ref netmem)
{
	/* The non-pp refcount of netmem is always 1. On netmem, we only support
	 * pp refcounting.
	 */
	if (netmem_is_net_iov(netmem))
		return 1;

	return page_ref_count(netmem_to_page(netmem));
}

static inline unsigned long netmem_to_pfn(netmem_ref netmem)
{
	if (netmem_is_net_iov(netmem))
		return 0;

	return page_to_pfn(netmem_to_page(netmem));
}

static inline struct net_iov *__netmem_clear_lsb(netmem_ref netmem)
{
	return (struct net_iov *)((__force unsigned long)netmem & ~NET_IOV);
}

static inline unsigned long netmem_get_pp_magic(netmem_ref netmem)
{
	return __netmem_clear_lsb(netmem)->pp_magic;
}

static inline void netmem_or_pp_magic(netmem_ref netmem, unsigned long pp_magic)
{
	__netmem_clear_lsb(netmem)->pp_magic |= pp_magic;
}

static inline void netmem_clear_pp_magic(netmem_ref netmem)
{
	__netmem_clear_lsb(netmem)->pp_magic = 0;
}

static inline struct page_pool *netmem_get_pp(netmem_ref netmem)
{
	return __netmem_clear_lsb(netmem)->pp;
}

static inline void netmem_set_pp(netmem_ref netmem, struct page_pool *pool)
{
	__netmem_clear_lsb(netmem)->pp = pool;
}

static inline unsigned long netmem_get_dma_addr(netmem_ref netmem)
{
	return __netmem_clear_lsb(netmem)->dma_addr;
}

static inline void netmem_set_dma_addr(netmem_ref netmem,
				       unsigned long dma_addr)
{
	__netmem_clear_lsb(netmem)->dma_addr = dma_addr;
}

static inline atomic_long_t *netmem_get_pp_ref_count_ref(netmem_ref netmem)
{
	return &__netmem_clear_lsb(netmem)->pp_ref_count;
}

static inline bool netmem_is_pref_nid(netmem_ref netmem, int pref_nid)
{
	/* Assume net_iov are on the preferred node without actually
	 * checking...
	 *
	 * This check is only used to check for recycling memory in the page
	 * pool's fast paths. Currently the only implementation of net_iov
	 * is dmabuf device memory. It's a deliberate decision by the user to
	 * bind a certain dmabuf to a certain netdev, and the netdev rx queue
	 * would not be able to reallocate memory from another dmabuf that
	 * exists on the preferred node, so, this check doesn't make much sense
	 * in this case. Assume all net_iovs can be recycled for now.
	 */
	if (netmem_is_net_iov(netmem))
		return true;

	return page_to_nid(netmem_to_page(netmem)) == pref_nid;
}

static inline netmem_ref netmem_compound_head(netmem_ref netmem)
{
	/* niov are never compounded */
	if (netmem_is_net_iov(netmem))
		return netmem;

	return page_to_netmem(compound_head(netmem_to_page(netmem)));
}

static inline void *netmem_address(netmem_ref netmem)
{
	if (netmem_is_net_iov(netmem))
		return NULL;

	return page_address(netmem_to_page(netmem));
}

#endif /* _NET_NETMEM_H */
