/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __PAGE_POOL_PRIV_H
#define __PAGE_POOL_PRIV_H

#include <net/page_pool/helpers.h>

#include "netmem_priv.h"

s32 page_pool_inflight(const struct page_pool *pool, bool strict);

int page_pool_list(struct page_pool *pool);
void page_pool_detached(struct page_pool *pool);
void page_pool_unlist(struct page_pool *pool);

#if defined(CONFIG_PAGE_POOL)
int page_pool_check_memory_provider(struct net_device *dev,
				    struct netdev_rx_queue *rxq);
#else
static inline int page_pool_check_memory_provider(struct net_device *dev,
						  struct netdev_rx_queue *rxq)
{
	return 0;
}
#endif

#endif
