/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NETDEV_CFG_H
#define _LINUX_NETDEV_CFG_H

#include <linux/ethtool.h>
#include <net/page_pool/types.h>

/**
 * struct netdev_cfg - datapath configuration for struct net_device
 */
struct netdev_cfg {
	/** @mtu: MTU of the interface */
	unsigned int mtu;

	/** @chan: ring counts */
	struct ethtool_channels chan;
};

struct netdev_txq_cfg {
	struct ethtool_ringparam ring;
	struct kernel_ethtool_ringparam kring;
};

/**
 * struct netdev_rxq_cfg - datapath configuration for an Rx queue
 */
struct netdev_rxq_cfg {
	/**
	 * @ring:  ring sizes
	 * @kring: additional ring descriptor/buffer config parameters
	 */
	struct ethtool_ringparam ring;
	struct kernel_ethtool_ringparam kring;
	struct page_pool_params pp;
};

/**
 * struct netdev_nic_cfg - NIC datapath config parameters
 * @rxq_cfg_size: size of the private struct holding queue mem alloc state (Rx)
 * @rxq_mem_size: size of the private struct holding queue memory (Rx)
 */
struct netdev_nic_cfg_info {
	unsigned int txq_mem_size;
	unsigned int rxq_mem_size;
};

/* Internals start here, all the stuff below should be hidden from drivers
 * once the code covers enough configuration.
 */

struct netdev_nic_cfg {
	struct netdev_cfg cfg;

	/* dynamic state */
	struct netdev_txq_cfg tqcfg;
	unsigned int txq_cnt;
	void *txqmem;

	struct netdev_rxq_cfg rqcfg;
	unsigned int rxq_cnt;
	void *rxqmem;

	/* global parameters */
	struct ethtool_ringparam ring;
	struct kernel_ethtool_ringparam kring;

	/* Clone when replacing */
	struct netdev_nic_cfg *other_cfg;
};

/* Prepopulate/free the current configuration, probe/remove */
int netdev_nic_cfg_init(struct net_device *netdev);
void netdev_nic_cfg_deinit(struct net_device *netdev);

/* Alloc mem for queues, ndo_open/ndo_stop */
int netdev_nic_cfg_start(struct net_device *netdev);
void netdev_nic_cfg_stop(struct net_device *netdev);

void *netdev_nic_cfg_txqmem(struct net_device *netdev, unsigned int qid);
void *netdev_nic_cfg_rxqmem(struct net_device *netdev, unsigned int qid);

/* Runtime config */
int netdev_nic_recfg_start(struct net_device *netdev);
/* .. after start() caller modifies the config .. */
int netdev_nic_recfg_prep(struct net_device *netdev);
void netdev_nic_recfg_swap(struct net_device *netdev);
void netdev_nic_recfg_end(struct net_device *netdev);

// TODO: need queue start + queue stop

#endif
