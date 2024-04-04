// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <net/pkt_sched.h>
#include <net/page_pool/helpers.h>

#include "fbnic.h"
#include "fbnic_fw.h"
#include "fbnic_netdev.h"
#include "fbnic_txrx.h"

#define DEFAULT_MSG_ENABLE \
	(NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)
#define MSG_ENABLE_MASK		(((u32)1 << NETIF_MSG_CLASS_COUNT) - 1)
#define FBNIC_PAGE_POOL_FLAGS \
	(PP_FLAG_DMA_MAP | PP_FLAG_DMA_SYNC_DEV)

static unsigned int debug_mask = DEFAULT_MSG_ENABLE;
module_param(debug_mask, int, 0);
MODULE_PARM_DESC(debug_mask, "Debug message level flags");

unsigned int mac_fallback;
module_param(mac_fallback, int, 0644);
MODULE_PARM_DESC(mac_fallback, "Generate new MAC address if DSN is invalid");

int __fbnic_open(struct fbnic_net *fbn)
{
	struct fbnic_dev *fbd = fbn->fbd;
	int err;

	err = netif_set_real_num_tx_queues(fbn->netdev,
					   fbn->num_tx_queues);
	if (err)
		return err;

	err = netif_set_real_num_rx_queues(fbn->netdev,
					   fbn->num_rx_queues);
	if (err)
		return err;

	printk("----- __fbnic_open: fbn->netdev=%px, fbn->netdev->dev=%px, fbn->netdev->dev.parent=%px\n", fbn->netdev, fbn->netdev->dev, fbn->netdev->dev.parent);
	netdev_nic_cfg_start(fbn->netdev);

	err = fbnic_alloc_napi_vectors(fbn);
	if (err)
		return err;

	err = fbnic_alloc_resources(fbn);
	if (err)
		goto free_napi_vectors;

	/* Send ownership message and flush to verify FW has seen it */
	err = fbnic_fw_xmit_ownership_msg(fbd, true);
	if (err) {
		dev_warn(fbd->dev,
			 "Error %d sending host ownership message to the firmware\n",
			 err);
		goto free_resources;
	}

	err = fbnic_time_start(fbn);
	if (err)
		goto release_ownership;

	err = fbnic_fw_init_heartbeat(fbd, false);
	if (err)
		goto time_stop;

	err = fbnic_mac_enable(fbd);
	if (err)
		goto time_stop;

	/* Pull the BMC config and initialize the RPC */
	fbnic_bmc_rpc_init(fbd);
	fbnic_rss_reinit(fbd, fbn);

	return 0;
time_stop:
	fbnic_time_stop(fbn);
release_ownership:
	fbnic_fw_xmit_ownership_msg(fbn->fbd, false);
free_resources:
	fbnic_free_resources(fbn);
free_napi_vectors:
	fbnic_free_napi_vectors(fbn);
	return err;
}

static int fbnic_open(struct net_device *netdev)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	int err;

	err = __fbnic_open(fbn);
	if (!err)
		fbnic_up(fbn);

	return err;
}

static int fbnic_stop(struct net_device *netdev)
{
	struct fbnic_net *fbn = netdev_priv(netdev);

	fbnic_down(fbn);
	fbnic_mac_disable(fbn->fbd);

	fbnic_time_stop(fbn);

	fbnic_free_resources(fbn);
	fbnic_free_napi_vectors(fbn);

	netdev_nic_cfg_stop(netdev);

	fbnic_fw_xmit_ownership_msg(fbn->fbd, false);

	return 0;
}

static int fbnic_change_mtu(struct net_device *dev, int new_mtu)
{
	/* TBD: Add code as needed to change FIFO thresholds */

	dev->mtu = new_mtu;

	return 0;
}

static int fbnic_uc_sync(struct net_device *netdev, const unsigned char *addr)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_mac_addr *avail_addr;

	if (WARN_ON(!is_valid_ether_addr(addr)))
		return -EADDRNOTAVAIL;

	avail_addr = __fbnic_uc_sync(fbn->fbd, addr);
	if (!avail_addr)
		return -ENOSPC;

	/* Add type flag indicating this address is in use by the host */
	set_bit(FBNIC_MAC_ADDR_T_UNICAST, avail_addr->act_tcam);

	return 0;
}

static int fbnic_uc_unsync(struct net_device *netdev, const unsigned char *addr)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;
	int i, ret;

	/* Scan from middle of list to bottom, filling bottom up.
	 * Skip the first entry which is reserved for dev_addr and
	 * leave the last entry to use for promiscuous filtering.
	 */
	for (i = fbd->mac_addr_boundary, ret = -ENOENT;
	     i < FBNIC_RPC_TCAM_MACDA_HOST_ADDR_IDX && ret; i++) {
		struct fbnic_mac_addr *mac_addr = &fbd->mac_addr[i];

		if (!ether_addr_equal(mac_addr->value.addr8, addr))
			continue;

		ret = __fbnic_uc_unsync(mac_addr);
	}

	return ret;
}

static int fbnic_mc_sync(struct net_device *netdev, const unsigned char *addr)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_mac_addr *avail_addr;

	if (WARN_ON(!is_multicast_ether_addr(addr)))
		return -EADDRNOTAVAIL;

	avail_addr = __fbnic_mc_sync(fbn->fbd, addr);
	if (!avail_addr)
		return -ENOSPC;

	/* Add type flag indicating this address is in use by the host */
	set_bit(FBNIC_MAC_ADDR_T_MULTICAST, avail_addr->act_tcam);

	return 0;
}

static int fbnic_mc_unsync(struct net_device *netdev, const unsigned char *addr)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;
	int i, ret;

	/* Scan from middle of list to top, filling top down.
	 * Skip over the address reserved for the BMC MAC and
	 * exclude index 0 as that belongs to the broadcast address
	 */
	for (i = fbd->mac_addr_boundary, ret = -ENOENT;
	     --i > FBNIC_RPC_TCAM_MACDA_BROADCAST_IDX && ret;) {
		struct fbnic_mac_addr *mac_addr = &fbd->mac_addr[i];

		if (!ether_addr_equal(mac_addr->value.addr8, addr))
			continue;

		ret = __fbnic_mc_unsync(mac_addr);
	}

	return ret;
}

void __fbnic_set_rx_mode(struct net_device *netdev)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	bool uc_promisc = false, mc_promisc = false;
	struct fbnic_dev *fbd = fbn->fbd;
	struct fbnic_mac_addr *mac_addr;
	int err;

	/* Populate host address from dev_addr */
	mac_addr = &fbd->mac_addr[FBNIC_RPC_TCAM_MACDA_HOST_ADDR_IDX];
	if (!ether_addr_equal(mac_addr->value.addr8, netdev->dev_addr) ||
	    mac_addr->state != FBNIC_TCAM_S_VALID) {
		ether_addr_copy(mac_addr->value.addr8, netdev->dev_addr);
		mac_addr->state = FBNIC_TCAM_S_UPDATE;
		set_bit(FBNIC_MAC_ADDR_T_UNICAST, mac_addr->act_tcam);
	}

	/* Populate broadcast address if broadcast is enabled */
	mac_addr = &fbd->mac_addr[FBNIC_RPC_TCAM_MACDA_BROADCAST_IDX];
	if (netdev->flags & IFF_BROADCAST) {
		if (!is_broadcast_ether_addr(mac_addr->value.addr8) ||
		    mac_addr->state != FBNIC_TCAM_S_VALID) {
			eth_broadcast_addr(mac_addr->value.addr8);
			mac_addr->state = FBNIC_TCAM_S_ADD;
		}
		set_bit(FBNIC_MAC_ADDR_T_BROADCAST, mac_addr->act_tcam);
	} else if (mac_addr->state == FBNIC_TCAM_S_VALID) {
		__fbnic_xc_unsync(mac_addr, FBNIC_MAC_ADDR_T_BROADCAST);
	}

	/* synchronize unicast and multicast address lists */
	err = __dev_uc_sync(netdev, fbnic_uc_sync, fbnic_uc_unsync);
	if (err == -ENOSPC)
		uc_promisc = true;
	err = __dev_mc_sync(netdev, fbnic_mc_sync, fbnic_mc_unsync);
	if (err == -ENOSPC)
		mc_promisc = true;

	uc_promisc |= !!(netdev->flags & IFF_PROMISC);
	mc_promisc |= !!(netdev->flags & IFF_ALLMULTI) | uc_promisc;

	/* Populate last TCAM entry with promiscuous entry and 0/1 bit mask */
	mac_addr = &fbd->mac_addr[FBNIC_RPC_TCAM_MACDA_PROMISC_IDX];
	if (uc_promisc) {
		if (!is_zero_ether_addr(mac_addr->value.addr8) ||
		    mac_addr->state != FBNIC_TCAM_S_VALID) {
			eth_zero_addr(mac_addr->value.addr8);
			eth_broadcast_addr(mac_addr->mask.addr8);
			clear_bit(FBNIC_MAC_ADDR_T_ALLMULTI,
				  mac_addr->act_tcam);
			set_bit(FBNIC_MAC_ADDR_T_PROMISC,
				mac_addr->act_tcam);
			mac_addr->state = FBNIC_TCAM_S_ADD;
		}
	} else if (mc_promisc &&
		   (!fbnic_bmc_present(fbd) || !fbd->fw_cap.all_multi)) {
		/* We have to add a special handler for multicast as the
		 * BMC may have an all-multi rule already in place. As such
		 * adding a rule ourselves won't do any good so we will have
		 * to modify the rules for the ALL MULTI below if the BMC
		 * already has the rule in place.
		 */
		if (!is_multicast_ether_addr(mac_addr->value.addr8) ||
		    mac_addr->state != FBNIC_TCAM_S_VALID) {
			eth_zero_addr(mac_addr->value.addr8);
			eth_broadcast_addr(mac_addr->mask.addr8);
			mac_addr->value.addr8[0] ^= 1;
			mac_addr->mask.addr8[0] ^= 1;
			set_bit(FBNIC_MAC_ADDR_T_ALLMULTI,
				mac_addr->act_tcam);
			clear_bit(FBNIC_MAC_ADDR_T_PROMISC,
				  mac_addr->act_tcam);
			mac_addr->state = FBNIC_TCAM_S_ADD;
		}
	} else if (mac_addr->state == FBNIC_TCAM_S_VALID) {
		if (test_bit(FBNIC_MAC_ADDR_T_BMC, mac_addr->act_tcam)) {
			clear_bit(FBNIC_MAC_ADDR_T_ALLMULTI,
				  mac_addr->act_tcam);
			clear_bit(FBNIC_MAC_ADDR_T_PROMISC,
				  mac_addr->act_tcam);
		} else {
			mac_addr->state = FBNIC_TCAM_S_DELETE;
		}
	}

	/* Add rules for BMC all multicast if it is enabled */
	fbnic_bmc_rpc_all_multi_config(fbd, mc_promisc);

	/* sift out any unshared BMC rules and place them in BMC only section */
	fbnic_sift_macda(fbd);

	/* Write updates to hardware */
	fbnic_write_rules(fbd);
	fbnic_write_macda(fbd);
	fbnic_write_tce_tcam(fbd);
}

static void fbnic_set_rx_mode(struct net_device *netdev)
{
	/* no need to update the hardware if we are not running */
	if (netif_running(netdev))
		__fbnic_set_rx_mode(netdev);
}

static int fbnic_set_mac(struct net_device *netdev, void *p)
{
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	eth_hw_addr_set(netdev, addr->sa_data);

	fbnic_set_rx_mode(netdev);

	return 0;
}

void fbnic_clear_rx_mode(struct net_device *netdev)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;
	int idx;

	for (idx = ARRAY_SIZE(fbd->mac_addr); idx--;) {
		struct fbnic_mac_addr *mac_addr = &fbd->mac_addr[idx];

		if (mac_addr->state != FBNIC_TCAM_S_VALID)
			continue;

		bitmap_clear(mac_addr->act_tcam,
			     FBNIC_MAC_ADDR_T_HOST_START,
			     FBNIC_MAC_ADDR_T_HOST_LEN);

		if (bitmap_empty(mac_addr->act_tcam,
				 FBNIC_RPC_TCAM_ACT_NUM_ENTRIES))
			mac_addr->state = FBNIC_TCAM_S_DELETE;
	}

	/* Write updates to hardware */
	fbnic_write_macda(fbd);

	__dev_uc_unsync(netdev, NULL);
	__dev_mc_unsync(netdev, NULL);
}

static int fbnic_hwtstamp_get(struct fbnic_net *fbn, struct ifreq *ifr)
{
	if (copy_to_user(ifr->ifr_data, &fbn->hwtstamp_config,
			 sizeof(fbn->hwtstamp_config)))
		return -EFAULT;

	return 0;
}

static int fbnic_hwtstamp_set(struct fbnic_net *fbn, struct ifreq *ifr)
{
	struct hwtstamp_config config;
	int old_rx_filter;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	/* Upscale the filters */
	switch (config.rx_filter) {
	case HWTSTAMP_FILTER_NONE:
	case HWTSTAMP_FILTER_ALL:
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
		break;
	case HWTSTAMP_FILTER_NTP_ALL:
		config.rx_filter = HWTSTAMP_FILTER_ALL;
		break;
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
		config.rx_filter = HWTSTAMP_FILTER_PTP_V1_L4_EVENT;
		break;
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_L4_EVENT;
		break;
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_L2_EVENT;
		break;
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		config.rx_filter = HWTSTAMP_FILTER_PTP_V2_EVENT;
		break;
	default:
		return -ERANGE;
	}

	/* Configure */
	old_rx_filter = fbn->hwtstamp_config.rx_filter;
	memcpy(&fbn->hwtstamp_config, &config, sizeof(config));

	if (old_rx_filter != config.rx_filter && netif_running(fbn->netdev)) {
		fbnic_rss_reinit(fbn->fbd, fbn);
		fbnic_write_rules(fbn->fbd);
	}

	/* Save / report back filter configuration
	 * Note that our filter configuration is inexact. Instead of
	 * filtering for a specific UDP port or L2 Ethertype we are
	 * filtering in all UDP or all non-IP packets for timestamping. So
	 * if anything other than FILTER_ALL is requested we report
	 * FILTER_SOME indicating that we will be timestamping a few
	 * additional packets.
	 */
	if (config.rx_filter > HWTSTAMP_FILTER_ALL)
		config.rx_filter = HWTSTAMP_FILTER_SOME;

	if (copy_to_user(ifr->ifr_data, &config, sizeof(config)))
		return -EFAULT;

	return 0;
}

static int fbnic_eth_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct fbnic_net *fbn = netdev_priv(dev);

	switch (cmd) {
	case SIOCGHWTSTAMP:
		return fbnic_hwtstamp_get(fbn, ifr);
	case SIOCSHWTSTAMP:
		return fbnic_hwtstamp_set(fbn, ifr);
	default:
		return -EOPNOTSUPP;
	}
}

static void fbnic_get_stats64(struct net_device *dev,
			      struct rtnl_link_stats64 *stats64)
{
	u64 tx_bytes, tx_packets, tx_dropped = 0, tx_errors = 0;
	u64 rx_bytes, rx_packets, rx_dropped = 0, rx_errors = 0;
	u64 rx_missed = 0, rx_over = 0, rx_length = 0;
	struct fbnic_net *fbn = netdev_priv(dev);
	struct fbnic_dev *fbd = fbn->fbd;
	struct fbnic_queue_stats *stats;
	unsigned int start, i;

	fbnic_get_hw_stats(fbd);

	/* Record drops from Tx HW Datapath */
	tx_dropped += fbd->hw_stats.tti.cm_drop.frames.value;
	tx_dropped += fbd->hw_stats.tti.frame_drop.frames.value;
	tx_dropped += fbd->hw_stats.tti.tbi_drop.frames.value;
	tx_dropped += fbd->hw_stats.tmi.drop.frames.value;

	for (i = 0; i < fbd->max_num_queues; i++) {
		tx_errors += fbd->hw_stats.hw_q[i].tde_pkt_err[0].value;
		tx_errors += fbd->hw_stats.hw_q[i].tde_pkt_err[1].value;
	}

	stats64->tx_errors = tx_errors;

	/* Record Tx software maintained statistics */
	stats = &fbn->tx_stats;

	tx_bytes = stats->bytes;
	tx_packets = stats->packets;
	tx_dropped = stats->dropped;

	stats64->tx_bytes = tx_bytes;
	stats64->tx_packets = tx_packets;
	stats64->tx_dropped = tx_dropped;

	for (i = 0; i < fbn->num_tx_queues; i++) {
		struct fbnic_ring *txr = fbn->tx[i];

		if (!txr)
			continue;

		stats = &txr->stats;
		do {
			start = u64_stats_fetch_begin(&stats->syncp);
			tx_bytes = stats->bytes;
			tx_packets = stats->packets;
			tx_dropped = stats->dropped;
		} while (u64_stats_fetch_retry(&stats->syncp, start));

		stats64->tx_bytes += tx_bytes;
		stats64->tx_packets += tx_packets;
		stats64->tx_dropped += tx_dropped;
	}

	/* Record any drops to the NIC FIFOs */
	for (i = 0; i < 8; i++)
		rx_missed += fbd->hw_stats.rxb.fifo[i].drop.frames.value;

	/* Report packets dropped due to CQ/BDQ being full */
	for (i = 0; i < fbd->max_num_queues; i++) {
		rx_over += fbd->hw_stats.hw_q[i].rde_pkt_cq_drop.value;
		rx_over += fbd->hw_stats.hw_q[i].rde_pkt_bdq_drop.value;
		rx_errors += fbd->hw_stats.hw_q[i].rde_pkt_err.value;
	}

	rx_length += fbd->hw_stats.rpc.ovr_size_err.value;

	stats64->rx_over_errors = rx_over;
	stats64->rx_missed_errors = rx_missed;
	stats64->rx_length_errors = rx_length;
	stats64->rx_errors = rx_errors + rx_length;

	/* Record Rx software maintained statistics */
	stats = &fbn->rx_stats;

	rx_bytes = stats->bytes;
	rx_packets = stats->packets;
	rx_dropped = stats->dropped;

	stats64->rx_bytes = rx_bytes;
	stats64->rx_packets = rx_packets;
	stats64->rx_dropped = rx_dropped;

	for (i = 0; i < fbn->num_rx_queues; i++) {
		struct fbnic_ring *xdpr = fbn->tx[FBNIC_MAX_TXQS + i];
		struct fbnic_ring *rxr = fbn->rx[i];

		if (!rxr)
			continue;

		stats = &rxr->stats;
		do {
			start = u64_stats_fetch_begin(&stats->syncp);
			rx_bytes = stats->bytes;
			rx_packets = stats->packets;
			rx_dropped = stats->dropped;
		} while (u64_stats_fetch_retry(&stats->syncp, start));

		stats64->rx_bytes += rx_bytes;
		stats64->rx_packets += rx_packets;
		stats64->rx_dropped += rx_dropped;

		/* We may have fewer XDP queues than Rx queues if multiple
		 * Rx queues are allocated per vector. In order to account
		 * for that we will bail if the XDP queue isn't assigned.
		 */
		if (!xdpr)
			continue;

		stats = &xdpr->stats;
		do {
			start = u64_stats_fetch_begin(&stats->syncp);
			tx_bytes = stats->bytes;
			tx_packets = stats->packets;
			tx_dropped = stats->dropped;
		} while (u64_stats_fetch_retry(&stats->syncp, start));

		stats64->rx_bytes += tx_bytes;
		stats64->rx_packets += tx_packets;
		stats64->rx_dropped += tx_dropped;

		stats64->tx_bytes += tx_bytes;
		stats64->tx_packets += tx_packets;
	}
}

static int fbnic_bpf(struct net_device *netdev, struct netdev_bpf *bpf)
{
	struct bpf_prog *prog = bpf->prog, *prev_prog;
	struct fbnic_net *fbn = netdev_priv(netdev);

	switch (bpf->command) {
	case XDP_SETUP_PROG:
		prev_prog = xchg(&fbn->xdp_prog, prog);

		if (prev_prog)
			bpf_prog_put(prev_prog);
		break;
#ifdef HAVE_XDP_QUERY_PROG
	case XDP_QUERY_PROG:
		prev_prog = READ_ONCE(fbn->xdp_prog);
		bpf->prog_id = prev_prog ? prev_prog->aux->id : 0;
		break;
#endif
	default:
		return -EINVAL;
	}

	return 0;
}

static int fbnic_setup_tc_etf(struct net_device *netdev, void *data)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct tc_etf_qopt_offload *qopt = data;
	int q_idx = qopt->queue;

	if (q_idx < 0 || q_idx >= fbn->num_tx_queues)
		return -EINVAL;

	/* Store the configuration in the fbnic_net structure */
	if (qopt->enable)
		set_bit(q_idx, fbn->edt);
	else
		clear_bit(q_idx, fbn->edt);

	/* If the interface is up then we also need to push the
	 * configuration change to the running queue.
	 */
	if (netif_running(netdev)) {
		if (qopt->enable)
			fbn->tx[q_idx]->flags |= FBNIC_RING_F_EDT;
		else
			fbn->tx[q_idx]->flags &= ~FBNIC_RING_F_EDT;
	}

	return 0;
}

static int fbnic_setup_tc(struct net_device *netdev,
			  enum tc_setup_type type, void *data)
{
	if (type != TC_SETUP_QDISC_ETF)
		return -EOPNOTSUPP;

	return fbnic_setup_tc_etf(netdev, data);
}

static bool __is_split(unsigned int napi, unsigned int tx, unsigned int rx)
{
	return napi < FBNIC_MAX_TXQS && napi == tx + rx;
}

static int __foo_tx(unsigned int napi, unsigned int tx, unsigned int rx, int i)
{
	if (__is_split(napi, tx, rx) || i >= rx)
		return FBNIC_NV_TYPE_TX_ONLY;

	// not split, and i < rx
	return FBNIC_NV_TYPE_COMBINED;
}

static int __foo_rx(unsigned int napi, unsigned int tx, unsigned int rx, int i)
{
	if (__is_split(napi, tx, rx) || i >= tx)
		return FBNIC_NV_TYPE_RX_ONLY;

	// not split, and i < tx
	return FBNIC_NV_TYPE_COMBINED;
}

static void *fbnic_tx_queue_mem_alloc(struct net_device *dev,
				      const struct netdev_cfg *dcfg,
				      const struct netdev_txq_cfg *qcfg,
				      void *qmem,
				      int idx)
{
	struct fbnic_net *fbn = netdev_priv(dev);
	struct fbnic_txq_mem *txq_mem = qmem;
	struct device *pdev = dev->dev.parent;
	struct fbnic_ring *txr;
	int type;

	type = __foo_tx(fbn->num_napi, fbn->num_tx_queues, fbn->num_rx_queues, idx);
	printk("----- txq_mem_alloc: i=%d, type=%d\n", idx, type);

	// NOTE: 1 - tx queue
	txr = &txq_mem->qt.sub0;
	fbnic_alloc_tx_ring_desc(txr, pdev, &qcfg->ring);
	fbnic_alloc_tx_ring_buffer(txr);

	// NOTE: 3- tx cmpl queue
	txr = &txq_mem->qt.cmpl;
	fbnic_alloc_tx_ring_desc(txr, pdev, &qcfg->ring);

	// NOTE: 2 - tx xdp queue
	if (type == FBNIC_NV_TYPE_COMBINED) {
		txr = &txq_mem->qt.sub1;
		fbnic_alloc_tx_ring_desc(txr, pdev, &qcfg->ring);
		fbnic_alloc_tx_ring_buffer(txr);
	}

	txq_mem->type = type;

	return NULL;
}

static void fbnic_tx_queue_mem_free(struct net_device *dev,
						const struct netdev_cfg *dcfg,
						const struct netdev_txq_cfg *qcfg,
						void *qmem) {
	struct fbnic_net *fbn = netdev_priv(dev);
	struct fbnic_txq_mem *txq_mem = qmem;

	fbnic_free_qt_resources(fbn, &txq_mem->qt);
}

static int fbnic_tx_queue_start(struct net_device *dev,
						int idx,
						void *queue_mem)
{
	return -EOPNOTSUPP;
}

static int fbnic_tx_queue_stop(struct net_device *dev,
						int idx,
						void **out_queue_mem)
{
	return -EOPNOTSUPP;
}

static void *fbnic_rx_queue_mem_alloc(struct net_device *dev,
					const struct netdev_cfg *dcfg,
					const struct netdev_rxq_cfg *qcfg,
					void *qmem,
					int idx)
{
	struct fbnic_net *fbn = netdev_priv(dev);
	struct device *pdev = dev->dev.parent;
	struct fbnic_rxq_mem *rxq_mem = qmem;
	struct fbnic_ring *rxr;
	const struct ethtool_ringparam *params = &qcfg->ring;
	int type;

	type = __foo_rx(fbn->num_napi, fbn->num_tx_queues, fbn->num_rx_queues, idx);
	printk("----- rxq_mem_alloc: i=%d, type=%d\n", idx, type);

	// ethtool_ringparam->tx_pending = fbn->txq_size = tx ring desc ring size
	// tx ring buf ring size = txr->size_mask = fbn->txq_size - 1

	rxr = &rxq_mem->qt.sub0;
	// needed for fbnic_alloc_rx_ring_buffer()
	rxr->flags = FBNIC_RING_F_CTX;
	fbnic_alloc_rx_ring_desc(rxr, pdev, params->rx_mini_pending);
	fbnic_alloc_rx_ring_buffer(rxr);

	rxr = &rxq_mem->qt.sub1;
	rxr->flags = FBNIC_RING_F_CTX;
	fbnic_alloc_rx_ring_desc(rxr, pdev, params->rx_jumbo_pending);
	fbnic_alloc_rx_ring_buffer(rxr);

	rxr = &rxq_mem->qt.cmpl;
	rxr->flags = FBNIC_RING_F_STATS;
	fbnic_alloc_rx_ring_desc(rxr, pdev, params->rx_pending);
	fbnic_alloc_rx_ring_buffer(rxr);

	// if there are rx only queue triads, set up xdp queue
	if (type == FBNIC_NV_TYPE_RX_ONLY) {
		rxr = &rxq_mem->xdp_qt.sub1;
		fbnic_alloc_tx_ring_desc(rxr, pdev, params);
		fbnic_alloc_tx_ring_buffer(rxr);

		rxr = &rxq_mem->xdp_qt.cmpl;
		fbnic_alloc_tx_ring_desc(rxr, pdev, params);
	}

	struct page_pool_params pp_params = {
		.order = 0,
		.flags = FBNIC_PAGE_POOL_FLAGS,
		.pool_size = params->rx_mini_pending + params->rx_jumbo_pending,
		.nid = NUMA_NO_NODE,
		.dev = pdev,
		.dma_dir = DMA_BIDIRECTIONAL,
#ifndef KCOMPAT_NEED_DMA_SYNC_DEV
		.offset = 0,
		.max_len = PAGE_SIZE
#endif
	};

	if (pp_params.pool_size > 32768)
		pp_params.pool_size = 32768;

	rxq_mem->page_pool = page_pool_create(&pp_params);
	rxq_mem->type = type;

	return NULL;
}

static void fbnic_rx_queue_mem_free(struct net_device *dev,
						const struct netdev_cfg *dcfg,
						const struct netdev_rxq_cfg *qcfg,
						void *qmem) {
	struct fbnic_net *fbn = netdev_priv(dev);
	struct fbnic_rxq_mem *rxq_mem = qmem;

	fbnic_free_qt_resources(fbn, &rxq_mem->qt);
	fbnic_free_qt_resources(fbn, &rxq_mem->xdp_qt);
	xdp_rxq_info_unreg_mem_model(&rxq_mem->qt.xdp_rxq);
#ifndef HAVE_XDP_UNREG_FIX
	memset(&rxq_mem->qt.xdp_rxq.mem, 0, sizeof(struct xdp_mem_info));
#endif
	page_pool_destroy(rxq_mem->page_pool);
}

static int fbnic_rx_queue_start(struct net_device *dev,
						int idx,
						void *queue_mem)
{
	return -EOPNOTSUPP;
}

static int fbnic_rx_queue_stop(struct net_device *dev,
						int idx,
						void **out_queue_mem)
{
	return -EOPNOTSUPP;
}

static const struct net_device_ops fbnic_netdev_ops = {
	.ndo_open		= fbnic_open,
	.ndo_stop		= fbnic_stop,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_start_xmit		= fbnic_xmit_frame,
	.ndo_features_check	= fbnic_features_check,
	.ndo_set_mac_address	= fbnic_set_mac,
	.ndo_change_mtu		= fbnic_change_mtu,
	.ndo_set_rx_mode	= fbnic_set_rx_mode,
	.ndo_eth_ioctl		= fbnic_eth_ioctl,
	.ndo_get_stats64	= fbnic_get_stats64,
	.ndo_bpf		= fbnic_bpf,
	.ndo_setup_tc		= fbnic_setup_tc,
	.ndo_tx_queue_mem_alloc	= fbnic_tx_queue_mem_alloc,
	.ndo_tx_queue_mem_free	= fbnic_tx_queue_mem_free,
	.ndo_tx_queue_start	= fbnic_tx_queue_start,
	.ndo_tx_queue_stop	= fbnic_tx_queue_stop,
	.ndo_rx_queue_mem_alloc	= fbnic_rx_queue_mem_alloc,
	.ndo_rx_queue_mem_free	= fbnic_rx_queue_mem_free,
	.ndo_rx_queue_start	= fbnic_rx_queue_start,
	.ndo_rx_queue_stop	= fbnic_rx_queue_stop,
};

void fbnic_reset_queues(struct fbnic_net *fbn,
			unsigned int tx, unsigned int rx)
{
	struct fbnic_dev *fbd = fbn->fbd;
	unsigned int max_napis;

	max_napis = fbd->num_irqs - FBNIC_NON_NAPI_VECTORS;

	tx = min(tx, max_napis);
	fbn->num_tx_queues = tx;

	rx = min(rx, max_napis);
	fbn->num_rx_queues = rx;

	fbn->num_napi = max(tx, rx);
}

/**
 * fbnic_netdev_alloc - Allocate a netdev and associate with fbnic
 * @fbd: Driver specific structure to associate netdev with
 *
 * Allocate and initialize the netdev and netdev private structure. Bind
 * together the hardware, netdev, and pci data structures.
 **/
struct net_device *fbnic_netdev_alloc(struct fbnic_dev *fbd)
{
	struct net_device *netdev;
	struct fbnic_net *fbn;
	int default_queues;

	netdev = alloc_etherdev_mq(sizeof(*fbn), FBNIC_MAX_RXQS);
	if (!netdev)
		return NULL;

	SET_NETDEV_DEV(netdev, fbd->dev);
	fbd->netdev = netdev;

	netdev->netdev_ops = &fbnic_netdev_ops;
	fbnic_set_ethtool_ops(netdev);

	fbn = netdev_priv(netdev);

	fbn->netdev = netdev;
	fbn->fbd = fbd;
	INIT_LIST_HEAD(&fbn->napis);

	fbn->msg_enable = debug_mask & MSG_ENABLE_MASK;

	/* TBD: Need to determine actual queue counts */
	fbn->txq_size = FBNIC_TXQ_SIZE_DEFAULT;
	fbn->hpq_size = FBNIC_HPQ_SIZE_DEFAULT;
	fbn->ppq_size = FBNIC_PPQ_SIZE_DEFAULT;
	fbn->rcq_size = FBNIC_RCQ_SIZE_DEFAULT;

	default_queues = netif_get_num_default_rss_queues();
	if (default_queues > fbd->max_num_queues)
		default_queues = fbd->max_num_queues;

	fbnic_reset_queues(fbn, default_queues, default_queues);
	fbn->rx_usecs = -1;
	fbn->tx_usecs = -1;

	/* Capture snapshot of hardware stats so netdev can compute delta */
	fbnic_reset_hw_stats(fbd);

	fbnic_reset_indir_tbl(fbn);
	fbnic_rss_key_fill(fbn->rss_key);
	fbnic_rss_init_en_mask(fbn);

	netdev->gso_partial_features =
		NETIF_F_GSO_GRE |
		NETIF_F_GSO_GRE_CSUM |
		NETIF_F_GSO_IPXIP4 |
		NETIF_F_GSO_UDP_TUNNEL |
		NETIF_F_GSO_UDP_TUNNEL_CSUM;

	netdev->features |=
		netdev->gso_partial_features |
		FBNIC_TUN_GSO_FEATURES |
		NETIF_F_RXHASH |
		NETIF_F_SG |
		NETIF_F_HW_CSUM |
		NETIF_F_RXCSUM |
		NETIF_F_TSO |
		NETIF_F_TSO_ECN |
		NETIF_F_TSO6 |
		NETIF_F_GSO_PARTIAL |
		NETIF_F_GSO_UDP_L4;

	netdev->hw_features |= netdev->features;
	netdev->vlan_features |= netdev->features;
	netdev->hw_enc_features |= netdev->features;

	netdev->min_mtu = IPV6_MIN_MTU;
	netdev->max_mtu = FBNIC_MAX_JUMBO_FRAME_SIZE - ETH_HLEN;

	/* Default to accept pause frames w/ attempt to autoneg the value */
	fbn->autoneg_pause = true;
	fbn->rx_pause = true;
	fbn->tx_pause = false;

	fbn->fec = FBNIC_FEC_AUTO | FBNIC_FEC_RS;
	fbn->link_mode = FBNIC_LINK_AUTO | FBNIC_LINK_50R2;
	netif_carrier_off(netdev);

	netif_tx_stop_all_queues(netdev);

	fbnic_dbg_fbn_init(fbn);

	return netdev;
}

/**
 * fbnic_netdev_free - Free the netdev associate with fbnic
 * @fbd: Driver specific structure to free netdev from
 *
 * Allocate and initialize the netdev and netdev private structure. Bind
 * together the hardware, netdev, and pci data structures.
 **/
void fbnic_netdev_free(struct fbnic_dev *fbd)
{
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);

	fbnic_dbg_fbn_exit(fbn);
	free_netdev(fbd->netdev);
	fbd->netdev = NULL;
}

static int fbnic_dsn_to_mac_addr(u64 dsn, char *addr)
{
	addr[0] = (dsn >> 56) & 0xFF;
	addr[1] = (dsn >> 48) & 0xFF;
	addr[2] = (dsn >> 40) & 0xFF;
	addr[3] = (dsn >> 16) & 0xFF;
	addr[4] = (dsn >> 8) & 0xFF;
	addr[5] = dsn & 0xFF;

	return is_valid_ether_addr(addr) ? 0 : -EINVAL;
}

/**
 * fbnic_netdev_register - Initialize general software structures
 * @netdev: Netdev containing structure to initialize and register
 *
 * Initialize the MAC address for the netdev and register it.
 **/
int fbnic_netdev_register(struct net_device *netdev)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;
	u64 dsn = fbd->dsn;
	u8 addr[ETH_ALEN];
	int err;

	err = fbnic_dsn_to_mac_addr(dsn, addr);
	if (!err) {
		ether_addr_copy(netdev->perm_addr, addr);
		eth_hw_addr_set(netdev, addr);
	} else if (mac_fallback) {
		eth_hw_addr_random(netdev);
		dev_warn(fbd->dev,
			 "Initial MAC addr %pM was invalid, New MAC %pM\n",
			 addr, netdev->dev_addr);
	} else {
		dev_err(fbd->dev, "MAC addr %pM invalid\n", addr);
		return err;
	}

	fbnic_time_init(fbn);

	/* Abort and do not register netdev if MMIO has failed.
	 * This should always be the last check before registration
	 * as the code for reading the registers will only be able to
	 * detach the device after it has already been registered.
	 */
	if (!fbd->uc_addr0)
		return -EIO;

	return register_netdev(netdev);
}

void fbnic_netdev_unregister(struct net_device *netdev)
{
	if (netdev->reg_state != NETREG_REGISTERED)
		return;
	unregister_netdev(netdev);
}
