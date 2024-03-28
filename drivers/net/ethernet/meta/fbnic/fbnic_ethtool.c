// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <linux/bitops.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <net/ipv6.h>
#include <net/page_pool/helpers.h>

#include "fbnic.h"
#include "fbnic_tlv.h"
#include "fbnic_netdev.h"

struct fbnic_stat {
	u8 string[ETH_GSTRING_LEN];
	unsigned int size;
	unsigned int offset;
};

#define FBNIC_STAT_FIELDS(type, name, stat) { \
	.string = name, \
	.size = sizeof_field(struct type, stat), \
	.offset = offsetof(struct type, stat) \
}

/* Hardware statistics not captured in rtnl_link_stats */
#define FBNIC_HW_STAT(name, stat) \
	FBNIC_STAT_FIELDS(fbnic_dev, name, hw_stats.stat.value)

/* FBD specific stats not tracked elsewhere */
#define FBNIC_FBD_STAT(name, stat) \
	FBNIC_STAT_FIELDS(fbnic_dev, name, stat)

static const struct fbnic_stat fbnic_gstrings_hw_stats[] = {
	/* tmi */
	FBNIC_HW_STAT("ptp_illegal_req", tmi.ptp_illegal_req),
	FBNIC_HW_STAT("ptp_good_ts", tmi.ptp_good_ts),
	FBNIC_HW_STAT("ptp_bad_ts", tmi.ptp_bad_ts),

	/* rpc */
	FBNIC_HW_STAT("rpc_unkn_etype", rpc.unkn_etype),
	FBNIC_HW_STAT("rpc_unkn_ext_hdr", rpc.unkn_ext_hdr),

	FBNIC_HW_STAT("rpc_ipv4_frag", rpc.ipv4_frag),
	FBNIC_HW_STAT("rpc_ipv6_frag", rpc.ipv6_frag),
	FBNIC_HW_STAT("rpc_ipv4_esp", rpc.ipv4_esp),
	FBNIC_HW_STAT("rpc_ipv6_esp", rpc.ipv6_esp),

	FBNIC_HW_STAT("rpc_tcp_opt_err", rpc.tcp_opt_err),
	FBNIC_HW_STAT("rpc_out_of_hdr_err", rpc.out_of_hdr_err),

	FBNIC_HW_STAT("rpc_macda_miss", rpc.macda_miss),
	FBNIC_HW_STAT("rpc_ipsrc_miss", rpc.ipsrc_miss),
	FBNIC_HW_STAT("rpc_ipdst_miss", rpc.ipdst_miss),
	FBNIC_HW_STAT("rpc_outer_ipsrc_miss", rpc.outer_ipsrc_miss),
	FBNIC_HW_STAT("rpc_outer_ipdst_miss", rpc.outer_ipdst_miss),
	FBNIC_HW_STAT("rpc_tcam_act_miss", rpc.tcam_act_miss),

	/* pcie */
	FBNIC_HW_STAT("pcie_ob_rd_tlp", pcie.ob_rd_tlp),
	FBNIC_HW_STAT("pcie_ob_rd_dword", pcie.ob_rd_dword),
	FBNIC_HW_STAT("pcie_ob_wr_tlp", pcie.ob_wr_tlp),
	FBNIC_HW_STAT("pcie_ob_wr_dword", pcie.ob_wr_dword),
	FBNIC_HW_STAT("pcie_ib_cpl_tlp", pcie.ib_cpl_tlp),
	FBNIC_HW_STAT("pcie_ib_cpl_dword", pcie.ib_cpl_dword),
	FBNIC_HW_STAT("pcie_ob_rd_no_tag", pcie.ob_rd_no_tag),
	FBNIC_HW_STAT("pcie_ob_rd_no_cpl_cred", pcie.ob_rd_no_cpl_cred),
	FBNIC_HW_STAT("pcie_ob_rd_no_np_cred", pcie.ob_rd_no_np_cred),

	/* Stats stored in FBD */
	FBNIC_FBD_STAT("fw_mbx_events", fw_mbx_events),
	FBNIC_FBD_STAT("fw_mbx_rx_alloc_failed", mbx[0].alloc_failed),
	FBNIC_FBD_STAT("fw_mbx_rx_mapping_error", mbx[0].mapping_error),
	FBNIC_FBD_STAT("fw_mbx_rx_parser_error", mbx[0].parser_error),
	FBNIC_FBD_STAT("fw_mbx_tx_mapping_error", mbx[1].mapping_error),
};

#define FBNIC_HW_FIXED_STATS_LEN ARRAY_SIZE(fbnic_gstrings_hw_stats)

#define FBNIC_RXB_ENQUEUE_STAT(name, stat) \
	FBNIC_STAT_FIELDS(fbnic_rxb_enqueue_stats, name, stat)

static const struct fbnic_stat fbnic_gstrings_rxb_enqueue_stats[] = {
	FBNIC_RXB_ENQUEUE_STAT("rxb_pause%u", pause),
	FBNIC_RXB_ENQUEUE_STAT("rxb_integrity_err%u", integrity_err),
	FBNIC_RXB_ENQUEUE_STAT("rxb_mac_err%u", mac_err),
	FBNIC_RXB_ENQUEUE_STAT("rxb_parser_err%u", parser_err),
	FBNIC_RXB_ENQUEUE_STAT("rxb_frm_err%u", frm_err),

	FBNIC_RXB_ENQUEUE_STAT("rxb_drbo%u_frames", drbo.frames),
	FBNIC_RXB_ENQUEUE_STAT("rxb_drbo%u_bytes", drbo.bytes),
};

#define FBNIC_HW_RXB_ENQUEUE_STATS_LEN \
	ARRAY_SIZE(fbnic_gstrings_rxb_enqueue_stats)

#define FBNIC_RXB_FIFO_STAT(name, stat) \
	FBNIC_STAT_FIELDS(fbnic_rxb_fifo_stats, name, stat)

static const struct fbnic_stat fbnic_gstrings_rxb_fifo_stats[] = {
	FBNIC_RXB_FIFO_STAT("rxb_fifo%u_pause", trans_pause),
	FBNIC_RXB_FIFO_STAT("rxb_fifo%u_drop", trans_drop),
	FBNIC_RXB_FIFO_STAT("rxb_fifo%u_dropped_frames", drop.frames),
	FBNIC_RXB_FIFO_STAT("rxb_fifo%u_ecn", trans_ecn),
	FBNIC_RXB_FIFO_STAT("rxb_fifo%u_level", level),
};

#define FBNIC_HW_RXB_FIFO_STATS_LEN ARRAY_SIZE(fbnic_gstrings_rxb_fifo_stats)

#define FBNIC_RXB_DEQUEUE_STAT(name, stat) \
	FBNIC_STAT_FIELDS(fbnic_rxb_dequeue_stats, name, stat)

static const struct fbnic_stat fbnic_gstrings_rxb_dequeue_stats[] = {
	FBNIC_RXB_DEQUEUE_STAT("rxb_intf%u_frames", intf.frames),
	FBNIC_RXB_DEQUEUE_STAT("rxb_intf%u_bytes", intf.bytes),
	FBNIC_RXB_DEQUEUE_STAT("rxb_pbuf%u_frames", pbuf.frames),
	FBNIC_RXB_DEQUEUE_STAT("rxb_pbuf%u_bytes", pbuf.bytes),
};

#define FBNIC_HW_RXB_DEQUEUE_STATS_LEN \
	ARRAY_SIZE(fbnic_gstrings_rxb_dequeue_stats)

#define FBNIC_HW_Q_STAT(name, stat) \
	FBNIC_STAT_FIELDS(fbnic_hw_q_stats, name, stat.value)

static const struct fbnic_stat fbnic_gstrings_hw_q_stats[] = {
	/* Tx */
	FBNIC_HW_Q_STAT("tde_%u_pkt_err0", tde_pkt_err[0]),
	FBNIC_HW_Q_STAT("tde_%u_pkt_err1", tde_pkt_err[1]),

	/* Rx */
	FBNIC_HW_Q_STAT("rde_%u_pkt_err", rde_pkt_err),
	FBNIC_HW_Q_STAT("rde_%u_pkt_cq_drop", rde_pkt_cq_drop),
	FBNIC_HW_Q_STAT("rde_%u_pkt_bdq_drop", rde_pkt_bdq_drop),
};

#define FBNIC_HW_Q_STATS_LEN ARRAY_SIZE(fbnic_gstrings_hw_q_stats)
#define FBNIC_HW_STATS_LEN \
	(FBNIC_HW_FIXED_STATS_LEN + \
	 FBNIC_HW_RXB_ENQUEUE_STATS_LEN * FBNIC_RXB_ENQUEUE_INDICES + \
	 FBNIC_HW_RXB_FIFO_STATS_LEN * FBNIC_RXB_FIFO_INDICES + \
	 FBNIC_HW_RXB_DEQUEUE_STATS_LEN * FBNIC_RXB_DEQUEUE_INDICES + \
	 FBNIC_HW_Q_STATS_LEN * FBNIC_MAX_QUEUES_ASIC)

/* per-queue netdev statistics */
#define FBNIC_NET_STAT(name, stat) \
	FBNIC_STAT_FIELDS(fbnic_net, name, stat)

static const struct fbnic_stat fbnic_gstrings_priv_stats[] = {
	FBNIC_NET_STAT("tx_noqueue_packets", tx_stats.packets),
	FBNIC_NET_STAT("tx_noqueue_bytes", tx_stats.bytes),
	FBNIC_NET_STAT("tx_noqueue_dropped", tx_stats.dropped),
	FBNIC_NET_STAT("tx_noqueue_wake", tx_stats.twq.wake),
	FBNIC_NET_STAT("tx_noqueue_restart", tx_stats.twq.restart),
	FBNIC_NET_STAT("tx_noqueue_busy", tx_stats.twq.busy),
	FBNIC_NET_STAT("tx_noqueue_csum_partial", tx_stats.twq.csum_partial),
	FBNIC_NET_STAT("tx_noqueue_lso", tx_stats.twq.lso),
	FBNIC_NET_STAT("rx_noqueue_packets", rx_stats.packets),
	FBNIC_NET_STAT("rx_noqueue_bytes", rx_stats.bytes),
	FBNIC_NET_STAT("rx_noqueue_dropped", rx_stats.dropped),
	FBNIC_NET_STAT("rx_noqueue_alloc_failed", rx_stats.rx.alloc_failed),
	FBNIC_NET_STAT("rx_noqueue_csum_complete", rx_stats.rx.csum_complete),
	FBNIC_NET_STAT("rx_noqueue_csum_none", rx_stats.rx.csum_none),
	FBNIC_NET_STAT("link_down_events", link_down_events),
};

#define FBNIC_NET_STATS_LEN ARRAY_SIZE(fbnic_gstrings_priv_stats)

/* per-queue ring statistics */
#define FBNIC_QUEUE_STAT(name, stat) \
	FBNIC_STAT_FIELDS(fbnic_ring, name, stat)

static const struct fbnic_stat fbnic_gstrings_tx_queue_stats[] = {
	FBNIC_QUEUE_STAT("tx_queue_%u_packets", stats.packets),
	FBNIC_QUEUE_STAT("tx_queue_%u_bytes", stats.bytes),
	FBNIC_QUEUE_STAT("tx_queue_%u_dropped", stats.dropped),
	FBNIC_QUEUE_STAT("tx_queue_%u_wake", stats.twq.wake),
	FBNIC_QUEUE_STAT("tx_queue_%u_restart", stats.twq.restart),
	FBNIC_QUEUE_STAT("tx_queue_%u_busy", stats.twq.busy),
	FBNIC_QUEUE_STAT("tx_queue_%u_csum_partial", stats.twq.csum_partial),
	FBNIC_QUEUE_STAT("tx_queue_%u_lso", stats.twq.lso),
};

#define FBNIC_TX_QUEUE_STATS_LEN ARRAY_SIZE(fbnic_gstrings_tx_queue_stats)

static const struct fbnic_stat fbnic_gstrings_rcq_stats[] = {
	FBNIC_QUEUE_STAT("rx_queue_%u_packets", stats.packets),
	FBNIC_QUEUE_STAT("rx_queue_%u_bytes", stats.bytes),
	FBNIC_QUEUE_STAT("rx_queue_%u_dropped", stats.dropped),
	FBNIC_QUEUE_STAT("rx_queue_%u_skb_alloc_failed", stats.rx.alloc_failed),
	FBNIC_QUEUE_STAT("rx_queue_%u_csum_complete", stats.rx.csum_complete),
	FBNIC_QUEUE_STAT("rx_queue_%u_csum_none", stats.rx.csum_none),
};

static const struct fbnic_stat fbnic_gstrings_xdp_stats[] = {
	FBNIC_QUEUE_STAT("xdp_tx_queue_%u_packets", stats.packets),
	FBNIC_QUEUE_STAT("xdp_tx_queue_%u_bytes", stats.bytes),
	FBNIC_QUEUE_STAT("xdp_tx_queue_%u_dropped", stats.dropped),
};

/* remember to add stats both to active and inactive queue sets */
static_assert(ARRAY_SIZE(fbnic_gstrings_priv_stats) ==
	      ARRAY_SIZE(fbnic_gstrings_tx_queue_stats) +
	      ARRAY_SIZE(fbnic_gstrings_rcq_stats) + 1);

/* All BDQ stats must be in pairs as we will pull from both the hdr and the
 * payload queues and present stats from both.
 */
static const struct fbnic_stat fbnic_gstrings_bdq_stats[] = {
	FBNIC_QUEUE_STAT("rx_queue_%u_hdr_alloc_failed", stats.rx.alloc_failed),
	FBNIC_QUEUE_STAT("rx_queue_%u_payld_alloc_failed",
			 stats.rx.alloc_failed),
};

#define FBNIC_RCQ_STATS_LEN ARRAY_SIZE(fbnic_gstrings_rcq_stats)
#define FBNIC_BDQ_STATS_LEN ARRAY_SIZE(fbnic_gstrings_bdq_stats)
#define FBNIC_XDP_STATS_LEN ARRAY_SIZE(fbnic_gstrings_xdp_stats)

#define FBNIC_RX_QUEUE_STATS_LEN \
	 (FBNIC_RCQ_STATS_LEN + FBNIC_BDQ_STATS_LEN + FBNIC_XDP_STATS_LEN)

#define FBNIC_STATS_LEN \
	(FBNIC_HW_STATS_LEN + FBNIC_NET_STATS_LEN + \
	 FBNIC_TX_QUEUE_STATS_LEN * FBNIC_MAX_TXQS + \
	 FBNIC_RX_QUEUE_STATS_LEN * FBNIC_MAX_RXQS)

enum fbnic_self_test_results {
	TEST_REG = 0,
	TEST_MSIX,
	TEST_LPBK,
	TEST_TLV,
	TEST_MBX,
	TEST_STOP,
};

static const char fbnic_gstrings_self_test[][ETH_GSTRING_LEN] = {
	[TEST_REG]	= "Register test (offline)",
	[TEST_MSIX]	= "MSI-X Interrupt test (offline)",
	[TEST_LPBK]	= "Loopback test (offline)",
	[TEST_TLV]	= "TLV message test (offline)",
	[TEST_MBX]	= "FW mailbox test (offline)",
	[TEST_STOP]	= "Idempotent stop test (offline)",
};

#define FBNIC_TEST_LEN ARRAY_SIZE(fbnic_gstrings_self_test)

static void fbnic_get_rxb_enqueue_strings(u8 **data, unsigned int idx)
{
	const struct fbnic_stat *stat;
	int i;

	stat = fbnic_gstrings_rxb_enqueue_stats;
	for (i = 0; i < FBNIC_HW_RXB_ENQUEUE_STATS_LEN; i++, stat++)
		ethtool_sprintf(data, stat->string, idx);
}

static void fbnic_get_rxb_fifo_strings(u8 **data, unsigned int idx)
{
	const struct fbnic_stat *stat;
	int i;

	stat = fbnic_gstrings_rxb_fifo_stats;
	for (i = 0; i < FBNIC_HW_RXB_FIFO_STATS_LEN; i++, stat++)
		ethtool_sprintf(data, stat->string, idx);
}

static void fbnic_get_rxb_dequeue_strings(u8 **data, unsigned int idx)
{
	const struct fbnic_stat *stat;
	int i;

	stat = fbnic_gstrings_rxb_dequeue_stats;
	for (i = 0; i < FBNIC_HW_RXB_DEQUEUE_STATS_LEN; i++, stat++)
		ethtool_sprintf(data, stat->string, idx);
}

static void fbnic_get_hardware_strings(u8 **data)
{
	const struct fbnic_stat *stat;
	int i, idx;

	stat = fbnic_gstrings_hw_stats;
	for (i = 0; i < FBNIC_HW_FIXED_STATS_LEN; i++, stat++)
		ethtool_sprintf(data, stat->string);

	for (i = 0; i < FBNIC_RXB_ENQUEUE_INDICES; i++)
		fbnic_get_rxb_enqueue_strings(data, i);

	for (i = 0; i < FBNIC_RXB_FIFO_INDICES; i++)
		fbnic_get_rxb_fifo_strings(data, i);

	for (i = 0; i < FBNIC_RXB_DEQUEUE_INDICES; i++)
		fbnic_get_rxb_dequeue_strings(data, i);

	for (idx = 0; idx < FBNIC_MAX_QUEUES_ASIC; idx++) {
		stat = fbnic_gstrings_hw_q_stats;

		for (i = 0; i < FBNIC_HW_Q_STATS_LEN; i++, stat++)
			ethtool_sprintf(data, stat->string, idx);
	}
}

static void fbnic_get_priv_strings(u8 **data)
{
	const struct fbnic_stat *stat;
	int i;

	stat = fbnic_gstrings_priv_stats;
	for (i = 0; i < FBNIC_NET_STATS_LEN; i++, stat++)
		ethtool_sprintf(data, stat->string);
}

static void fbnic_get_tx_queue_strings(u8 **data, unsigned int idx)
{
	const struct fbnic_stat *stat;
	int i;

	stat = fbnic_gstrings_tx_queue_stats;
	for (i = 0; i < FBNIC_TX_QUEUE_STATS_LEN; i++, stat++)
		ethtool_sprintf(data, stat->string, idx);
}

static void fbnic_get_rx_queue_strings(u8 **data, unsigned int idx)
{
	const struct fbnic_stat *stat;
	int i;

	stat = fbnic_gstrings_rcq_stats;
	for (i = 0; i < FBNIC_RCQ_STATS_LEN; i++, stat++)
		ethtool_sprintf(data, stat->string, idx);
	stat = fbnic_gstrings_bdq_stats;
	for (i = 0; i < FBNIC_BDQ_STATS_LEN; i++, stat++)
		ethtool_sprintf(data, stat->string, idx);
	stat = fbnic_gstrings_xdp_stats;
	for (i = 0; i < FBNIC_XDP_STATS_LEN; i++, stat++)
		ethtool_sprintf(data, stat->string, idx);
}

static void fbnic_get_strings(struct net_device *dev, u32 sset, u8 *data)
{
	int i;

	switch (sset) {
	case ETH_SS_STATS:
		fbnic_get_hardware_strings(&data);
		fbnic_get_priv_strings(&data);
		for (i = 0; i < FBNIC_MAX_TXQS; i++)
			fbnic_get_tx_queue_strings(&data, i);
		for (i = 0; i < FBNIC_MAX_RXQS; i++)
			fbnic_get_rx_queue_strings(&data, i);
		break;
	case ETH_SS_TEST:
		memcpy(data, fbnic_gstrings_self_test,
		       sizeof(fbnic_gstrings_self_test));
		break;
	}
}

static int fbnic_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return FBNIC_STATS_LEN;
	case ETH_SS_TEST:
		return FBNIC_TEST_LEN;
	default:
		return -EOPNOTSUPP;
	}
}

static void __fbnic_get_hardware_stats(const struct fbnic_stat *stat,
				       const void *base, int len, u64 **data)
{
	while (len--) {
		u8 *curr = (u8 *)base + stat->offset;

		/* Currently all hardware stats are 64b, if this changes
		 * we should update this to account for that.
		 */
		**data = *(u64 *)curr;

		stat++;
		(*data)++;
	}
}

static void fbnic_get_hardware_stats(struct fbnic_net *fbn, u64 **data)
{
	const struct fbnic_rxb_enqueue_stats *enq;
	const struct fbnic_rxb_dequeue_stats *deq;
	const struct fbnic_rxb_fifo_stats *fifo;
	const struct fbnic_hw_q_stats *hw_q;
	struct fbnic_dev *fbd = fbn->fbd;

	fbnic_get_hw_stats(fbd);

	__fbnic_get_hardware_stats(fbnic_gstrings_hw_stats, fbd,
				   FBNIC_HW_FIXED_STATS_LEN, data);

	for (enq = fbd->hw_stats.rxb.enq;
	     enq < &fbd->hw_stats.rxb.enq[FBNIC_RXB_ENQUEUE_INDICES]; enq++)
		__fbnic_get_hardware_stats(fbnic_gstrings_rxb_enqueue_stats,
					   enq, FBNIC_HW_RXB_ENQUEUE_STATS_LEN,
					   data);

	for (fifo = fbd->hw_stats.rxb.fifo;
	     fifo < &fbd->hw_stats.rxb.fifo[FBNIC_RXB_FIFO_INDICES];
	     fifo++)
		__fbnic_get_hardware_stats(fbnic_gstrings_rxb_fifo_stats,
					   fifo, FBNIC_HW_RXB_FIFO_STATS_LEN,
					   data);

	for (deq = fbd->hw_stats.rxb.deq;
	     deq < &fbd->hw_stats.rxb.deq[FBNIC_RXB_DEQUEUE_INDICES]; deq++)
		__fbnic_get_hardware_stats(fbnic_gstrings_rxb_dequeue_stats,
					   deq, FBNIC_HW_RXB_DEQUEUE_STATS_LEN,
					   data);

	for (hw_q = fbd->hw_stats.hw_q;
	     hw_q < &fbd->hw_stats.hw_q[FBNIC_MAX_QUEUES_ASIC]; hw_q++)
		__fbnic_get_hardware_stats(fbnic_gstrings_hw_q_stats, hw_q,
					   FBNIC_HW_Q_STATS_LEN, data);
}

static void fbnic_get_priv_stats(struct fbnic_net *fbn, u64 **data)
{
	const struct fbnic_stat *stat;
	int i;

	stat = fbnic_gstrings_priv_stats;
	for (i = 0; i < FBNIC_NET_STATS_LEN; i++, stat++, (*data)++) {
		u8 *p = (u8 *)fbn + stat->offset;

		**data = stat->size < sizeof(u64) ? *(u32 *)p : *(u64 *)p;
	}
}

static void fbnic_get_tx_queue_stats(struct fbnic_ring *ring, u64 **data)
{
	const struct fbnic_stat *stat;
	int i;

	if (!ring) {
		*data += FBNIC_TX_QUEUE_STATS_LEN;
		return;
	}

	stat = fbnic_gstrings_tx_queue_stats;
	for (i = 0; i < FBNIC_TX_QUEUE_STATS_LEN; i++, stat++, (*data)++) {
		u8 *p = (u8 *)ring + stat->offset;

		**data = *(u64 *)p;
	}
}

static void fbnic_get_rx_queue_stats(struct fbnic_ring *ring, u64 **data)
{
	const struct fbnic_stat *stat;
	int i;

	if (!ring) {
		*data += FBNIC_RCQ_STATS_LEN + FBNIC_BDQ_STATS_LEN;
		return;
	}

	/* Pull data from the RCQ */
	stat = fbnic_gstrings_rcq_stats;
	for (i = 0; i < FBNIC_RCQ_STATS_LEN; i++, stat++, (*data)++) {
		u8 *p = (u8 *)ring + stat->offset;

		**data = *(u64 *)p;
	}

	/* Pull data from the BDQs, even then odd for each stat */
	stat = fbnic_gstrings_bdq_stats;
	ring = &container_of(ring, struct fbnic_q_triad, cmpl)->sub0;
	for (i = 0; i < FBNIC_BDQ_STATS_LEN; i++, stat++, (*data)++) {
		u8 *p = (u8 *)&ring[i % 2] + stat->offset;

		**data = *(u64 *)p;
	}
}

static void fbnic_get_xdp_queue_stats(struct fbnic_ring *ring, u64 **data)
{
	const struct fbnic_stat *stat;
	int i;

	if (!ring) {
		*data += FBNIC_XDP_STATS_LEN;
		return;
	}

	stat = fbnic_gstrings_xdp_stats;
	for (i = 0; i < FBNIC_XDP_STATS_LEN; i++, stat++, (*data)++) {
		u8 *p = (u8 *)ring + stat->offset;

		**data = *(u64 *)p;
	}
}

static void fbnic_get_ethtool_stats(struct net_device *dev,
				    struct ethtool_stats *stats, u64 *data)
{
	struct fbnic_net *fbn = netdev_priv(dev);
	int i;

	fbnic_get_hardware_stats(fbn, &data);
	fbnic_get_priv_stats(fbn, &data);

	for (i = 0; i < FBNIC_MAX_TXQS; i++)
		fbnic_get_tx_queue_stats(fbn->tx[i], &data);
	for (i = 0; i < FBNIC_MAX_RXQS; i++) {
		fbnic_get_rx_queue_stats(fbn->rx[i], &data);
		fbnic_get_xdp_queue_stats(fbn->tx[i + FBNIC_MAX_TXQS], &data);
	}
}

static u32 fbnic_get_msglevel(struct net_device *dev)
{
	struct fbnic_net *fbn = netdev_priv(dev);

	return fbn->msg_enable;
}

static void fbnic_set_msglevel(struct net_device *dev, u32 msg_enable)
{
	struct fbnic_net *fbn = netdev_priv(dev);

	fbn->msg_enable = msg_enable;
}

static void fbnic_get_regs(struct net_device *netdev,
			   struct ethtool_regs *regs, void *p)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;
	u32 *data = p;

	/* Update version if we need to change out any registers.
	 * Otherwise we can always add more registers onto the end of this
	 * list.
	 */
	regs->version = 1u;

	fbnic_csr_get_regs(fbd, data);
}

static int fbnic_get_regs_len(struct net_device *netdev)
{
	return fbnic_csr_regs_len();
}

static void
fbnic_get_ringparam(struct net_device *netdev, struct ethtool_ringparam *ring,
		    struct kernel_ethtool_ringparam *kernel_ring,
		    struct netlink_ext_ack *extack)
{
	struct fbnic_net *fbn = netdev_priv(netdev);

	ring->rx_max_pending = FBNIC_QUEUE_SIZE_MAX;
	ring->rx_mini_max_pending = FBNIC_QUEUE_SIZE_MAX;
	ring->rx_jumbo_max_pending = FBNIC_QUEUE_SIZE_MAX;
	ring->tx_max_pending = FBNIC_QUEUE_SIZE_MAX;

	ring->rx_pending = fbn->rcq_size;
	ring->rx_mini_pending = fbn->hpq_size;
	ring->rx_jumbo_pending = fbn->ppq_size;
	ring->tx_pending = fbn->txq_size;
}

static struct fbnic_net *fbnic_clone_create(struct fbnic_net *orig)
{
	return kmemdup(orig, sizeof(*orig), GFP_KERNEL);
}

static void fbnic_clone_swap_cfg(struct fbnic_net *orig,
				 struct fbnic_net *clone)
{
	swap(clone->rcq_size, orig->rcq_size);
	swap(clone->hpq_size, orig->hpq_size);
	swap(clone->ppq_size, orig->ppq_size);
	swap(clone->txq_size, orig->txq_size);
	swap(clone->num_rx_queues, orig->num_rx_queues);
	swap(clone->num_tx_queues, orig->num_tx_queues);
	swap(clone->num_napi, orig->num_napi);
}

static void fbnic_aggregate_vector_counters(struct fbnic_net *fbn,
					    struct fbnic_napi_vector *nv)
{
	int i, j;

	for (i = 0; i < nv->txt_count; i++) {
		fbnic_aggregate_ring_tx_counters(fbn, &nv->qt[i].sub0);
		fbnic_aggregate_ring_tx_counters(fbn, &nv->qt[i].sub1);
		fbnic_aggregate_ring_tx_counters(fbn, &nv->qt[i].cmpl);
	}

	for (j = 0; j < nv->rxt_count; j++, i++) {
		fbnic_aggregate_ring_rx_counters(fbn, &nv->qt[i].sub0);
		fbnic_aggregate_ring_rx_counters(fbn, &nv->qt[i].sub1);
		fbnic_aggregate_ring_rx_counters(fbn, &nv->qt[i].cmpl);
	}
}

static void fbnic_clone_swap(struct fbnic_net *orig,
			     struct fbnic_net *clone)
{
	struct msix_entry *msix_entries = orig->fbd->msix_entries;
	struct fbnic_napi_vector *nv;
	unsigned int i;

	fbnic_clone_swap_cfg(orig, clone);

	list_for_each_entry(nv, &clone->napis, napis) {
		set_bit(NAPI_STATE_DRV0, &nv->napi.state);
		synchronize_irq(msix_entries[nv->v_idx].vector);
	}
	list_for_each_entry(nv, &orig->napis, napis) {
		clear_bit(NAPI_STATE_DRV0, &nv->napi.state);
		synchronize_irq(msix_entries[nv->v_idx].vector);
		fbnic_aggregate_vector_counters(orig, nv);
	}

	list_swap(&clone->napis, &orig->napis);
	for (i = 0; i < ARRAY_SIZE(orig->tx); i++)
		swap(clone->tx[i], orig->tx[i]);
	for (i = 0; i < ARRAY_SIZE(orig->rx); i++)
		swap(clone->rx[i], orig->rx[i]);
}

static void fbnic_clone_free(struct fbnic_net *clone)
{
	kfree(clone);
}

static void fbnic_set_rings(struct fbnic_net *fbn,
			    struct ethtool_ringparam *ring)
{
	fbn->rcq_size = ring->rx_pending;
	fbn->hpq_size = ring->rx_mini_pending;
	fbn->ppq_size = ring->rx_jumbo_pending;
	fbn->txq_size = ring->tx_pending;
}

static int
fbnic_set_ringparam(struct net_device *netdev, struct ethtool_ringparam *ring,
		    struct kernel_ethtool_ringparam *kernel_ring,
		    struct netlink_ext_ack *extack)

{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_net *clone;
	int err;

	ring->rx_pending	= roundup_pow_of_two(ring->rx_pending);
	ring->rx_mini_pending	= roundup_pow_of_two(ring->rx_mini_pending);
	ring->rx_jumbo_pending	= roundup_pow_of_two(ring->rx_jumbo_pending);
	ring->tx_pending	= roundup_pow_of_two(ring->tx_pending);

	/* These are absolute minimums allowing the device and driver to operate
	 * but not necessarily guarantee reasonable performance. Settings below
	 * Rx queue size of 128 and BDQs smaller than 64 are likely suboptimal
	 * at best.
	 */
	if (ring->rx_pending < max(FBNIC_QUEUE_SIZE_MIN, FBNIC_RX_DESC_MIN) ||
	    ring->rx_mini_pending < FBNIC_QUEUE_SIZE_MIN ||
	    ring->rx_jumbo_pending < FBNIC_QUEUE_SIZE_MIN ||
	    ring->tx_pending < max(FBNIC_QUEUE_SIZE_MIN, FBNIC_TX_DESC_MIN))
		return -EINVAL;

	if (ring->rx_pending == fbn->rcq_size &&
	    ring->rx_mini_pending == fbn->hpq_size &&
	    ring->rx_jumbo_pending == fbn->ppq_size &&
	    ring->tx_pending == fbn->txq_size)
		return 0;

	if (!netif_running(netdev)) {
		fbnic_set_rings(fbn, ring);
		return 0;
	}

	clone = fbnic_clone_create(fbn);
	if (!clone)
		return -ENOMEM;

	fbnic_set_rings(clone, ring);

	err = fbnic_rplc_alloc_rings(fbn, clone);
	if (err)
		goto err_free_clone;

	fbnic_down_noidle(fbn);
	err = fbnic_wait_all_queues_idle(fbn->fbd, true);
	if (err)
		goto err_start_stack;

	/* nothing can fail past this point */
	fbnic_flush(fbn);

	fbnic_rplc_swap_rings(fbn);
	fbnic_clone_swap_cfg(fbn, clone);

	fbnic_up(fbn);

	fbnic_rplc_free_rings(fbn);
	fbnic_clone_free(clone);

	return 0;

err_start_stack:
	/* TBD: enable does reset - can we just renable ?? asking @jhas */
	fbnic_flush(fbn);
	fbnic_up(fbn);
	fbnic_rplc_free_rings(fbn);
err_free_clone:
	fbnic_clone_free(clone);
	return err;
}

/**
 * fbnic_ethtool_regs_test - Verify behavior of NIC registers
 * @netdev: netdev device to test
 * @data: Pointer to results storage
 *
 * This function is meant to test the bit values ov various registers in
 * the NIC device. Specifically this test will verify which bits are
 * writable and which ones are not. It will write varying patterns of bits
 * to the registers testing for sticky bits, or bits that are writable but
 * should not be.
 *
 * Returns non-zero on failure.
 **/
static int fbnic_ethtool_regs_test(struct net_device *netdev, u64 *data)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;

	*data = fbnic_csr_regs_test(fbd);

	return !!*data;
}

static int fbnic_setup_loopback_net(struct fbnic_net *fbn)
{
	int ret_val;

	/* Set number of queues */
	fbn->num_rx_queues = 1;
	fbn->num_tx_queues = 1;
	fbn->num_napi = 1;
	fbnic_reset_indir_tbl(fbn);

	INIT_LIST_HEAD(&fbn->napis);
	memset(fbn->tx, 0, sizeof(fbn->tx));
	memset(fbn->rx, 0, sizeof(fbn->rx));

	/* Intentionally set the minimum size to something less than
	 * the wakeup threshold for the Tx queue to prevent the test
	 * from waking up any queues. This should default to 32 in all
	 * cases.
	 *
	 * We will set the RCQ to match as it will consume the same number
	 * of Rx descriptors as Tx descriptors when processing.
	 */
	fbn->txq_size = FBNIC_TX_DESC_MIN / 2;
	fbn->rcq_size = FBNIC_TX_DESC_MIN / 2;

	/* The Header and Payload queues can be set to minimum as we should
	 * only ever have at most 16 frames on the queue at any given point in
	 * time and the frames are only 512B in size so it shouldn't need full
	 * pages.
	 */
	fbn->hpq_size = FBNIC_RX_DESC_MIN;
	fbn->ppq_size = FBNIC_RX_DESC_MIN;

	/* Allocates one napi vector for both Rx and Tx */
	if (fbnic_alloc_napi_vectors(fbn)) {
		ret_val = 10;
		goto err;
	}

	/* Populate descriptors */
	if (fbnic_alloc_resources(fbn)) {
		ret_val = 11;
		goto err_free_napis;
	}

	/* Send ownership message and flush to verify FW has seen it */
	if (fbnic_fw_xmit_ownership_msg(fbn->fbd, true)) {
		ret_val = 12;
		goto err_free_resources;
	}

	/* Wait on ownership confirmation before starting test */
	if (fbnic_fw_init_heartbeat(fbn->fbd, false)) {
		ret_val = 13;
		goto err_release_ownership;
	}

	/* Enable MAC interface */
	if (fbnic_mac_enable(fbn->fbd)) {
		ret_val = 14;
		goto err_release_ownership;
	}

	/* Disable timestamp filters if present */
	fbn->hwtstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;

	/* Set up NIC for manually triggered/cleaned Rx and Tx */
	fbnic_rss_reinit(fbn->fbd, fbn);

	/* Load buffers into rings and Configure Rx Classifier */
	__fbnic_up(fbn);

	return 0;

err_release_ownership:
	fbnic_fw_xmit_ownership_msg(fbn->fbd, false);
err_free_resources:
	fbnic_free_resources(fbn);
err_free_napis:
	fbnic_free_napi_vectors(fbn);
err:
	return ret_val;
}

static int fbnic_cleanup_loopback_net(struct fbnic_net *fbn)
{
	/* Clear Rx rules and disable queues */
	__fbnic_down(fbn);

	/* Flush any non-completed buffers */
	fbnic_wait_all_queues_idle(fbn->fbd, false);
	fbnic_flush(fbn);

	/* Disable MAC and drop remaining resources */
	fbnic_mac_disable(fbn->fbd);
	fbnic_fw_xmit_ownership_msg(fbn->fbd, false);
	fbnic_free_resources(fbn);
	fbnic_free_napi_vectors(fbn);

	return 0;
}

static int fbnic_setup_mac_loopback(struct fbnic_net *fbn)
{
	struct fbnic_dev *fbd = fbn->fbd;
	const struct fbnic_mac *mac;

	mac = fbd->mac;
	if (mac->enable_loopback(fbd))
		return 20;

	/* give hardware time to process writes */
	wrfl();
	msleep(200);

	return 0;
}

static int fbnic_check_loopback_rcq(struct fbnic_napi_vector *nv,
				    struct fbnic_q_triad *qt,
				    int budget,
				    int pkt_size)
{
	unsigned int half_pkt_size = pkt_size / 2;
	struct net_device *netdev = nv->napi.dev;
	unsigned int packets = 0;
	struct fbnic_ring *rcq = &qt->cmpl;
	__le64 *raw_rcd, done;
	u32 head = rcq->head;
	s32 attempts = 10;
	int ret_val = 0;
	s32 head0 = -1;

	done = (head & (rcq->size_mask + 1)) ? cpu_to_le64(FBNIC_RCD_DONE) : 0;
	raw_rcd = &rcq->desc[head & rcq->size_mask];

	/* Attempt to receive each budgeted packet */
	while (packets < budget) {
		unsigned int hdr_pg_off;
		unsigned char *data;
		dma_addr_t dma_addr;
		struct page *page;
		u64 rcd;

		/* Poll for up to 200ms (10 * 20ms) on the RCD_DONE bit. */
		if ((*raw_rcd & cpu_to_le64(FBNIC_RCD_DONE)) == done) {
			if (attempts--) {
				msleep(20);
				continue;
			}
			ret_val = 40;
			break;
		}
		dma_rmb();
		rcd = le64_to_cpu(*raw_rcd);

		/* expect to see header first */
		if (FIELD_GET(FBNIC_RCD_TYPE_MASK, rcd) !=
		    FBNIC_RCD_TYPE_HDR_AL) {
			ret_val = 41;
			break;
		}

		/* process header */
		hdr_pg_off = FIELD_GET(FBNIC_RCD_AL_BUFF_OFF_MASK, rcd);
		head0 = FIELD_GET(FBNIC_RCD_AL_BUFF_ID_MASK, rcd);
		page = qt->sub0.rx_buf[head0].page;
		dma_addr = page_pool_get_dma_addr(page);
		dma_sync_single_range_for_cpu(nv->dev, dma_addr,
					      hdr_pg_off, pkt_size,
					      DMA_BIDIRECTIONAL);

		/* advance through RCQ */
		raw_rcd++;
		head++;
		if (!(head & rcq->size_mask)) {
			done ^= cpu_to_le64(FBNIC_RCD_DONE);
			raw_rcd = &rcq->desc[0];
		}

		if ((*raw_rcd & cpu_to_le64(FBNIC_RCD_DONE)) == done) {
			ret_val = 42;
			break;
		}
		dma_rmb();
		rcd = le64_to_cpu(*raw_rcd);

		/* expect to see payload (assuming no header splitting) */
		if (FIELD_GET(FBNIC_RCD_TYPE_MASK, rcd) !=
		    FBNIC_RCD_TYPE_META) {
			ret_val = 43;
			break;
		}

		data = page_address(page);

		/* check payload, probing arbitrary points of the contiguous
		 * constant-value regions
		 */
		if (!ether_addr_equal(&data[hdr_pg_off], netdev->dev_addr) ||
		    data[hdr_pg_off + half_pkt_size + 4] != 0xAA ||
		    data[hdr_pg_off + half_pkt_size + 10] != 0xBE ||
		    data[hdr_pg_off + half_pkt_size + 12] != 0xAF) {
			ret_val = 44;
			break;
		}

		raw_rcd++;
		head++;
		if (!(head & rcq->size_mask)) {
			done ^= cpu_to_le64(FBNIC_RCD_DONE);
			raw_rcd = &rcq->desc[0];
		}

		if (ret_val)
			break;

		packets++;
	}

	/* Unmap and free processed buffers */
	if (head0 >= 0)
		fbnic_clean_bdq(nv, 0, &qt->sub0, head0);
	fbnic_fill_bdq(nv, &qt->sub0);

	/* Record the current head/tail of the queue */
	if (rcq->head != head) {
		rcq->head = head;
		writel(head & rcq->size_mask, rcq->doorbell);
	}

	/* Check for done descriptor */
	if (!ret_val && (*raw_rcd & cpu_to_le64(FBNIC_RCD_DONE)) != done)
		ret_val = 45;

	return ret_val;
}

static int fbnic_run_loopback_test(struct fbnic_net *fbn)
{
	const int pkt_size = 512, half_pkt_size = pkt_size / 2;
	int max_twq_pkts, max_bdq_pkts, max_rcq_pkts;
	struct net_device *netdev = fbn->netdev;
	int pkts_per_iter, npackets, lc;
	struct fbnic_napi_vector *nv;
	struct sk_buff *skb;
	int ret_val = 0;
	u8 *pkt_data;
	int i, j;

	/* place packet on queue */
	skb = netdev_alloc_skb(netdev, pkt_size);
	pkt_data = skb_put(skb, pkt_size);

	/* Populate destination address */
	ether_addr_copy(pkt_data, netdev->dev_addr);

	/* populate packet data */
	memset(&pkt_data[ETH_ALEN], 0xFF, half_pkt_size - ETH_ALEN);
	memset(&pkt_data[half_pkt_size], 0xAA, half_pkt_size);
	pkt_data[half_pkt_size + 10] = 0xBE;
	pkt_data[half_pkt_size + 12] = 0xAF;

	/* napi vector with tx and rx queue triads */
	nv = list_entry((&fbn->napis)->next, struct fbnic_napi_vector, napis);

	/* upper bound on how many packets can be handled by TWQ, we
	 * ignore the TCQ as it is the same size as the TWQ but uses
	 * half as many descriptors per packet.
	 *
	 * We subtract 8 to keep tail from advancing into the same cacheline
	 * as head. This keeps us from triggering the NETDEV_TX_BUSY logic or
	 * slipping into unallocated buffers.
	 */
	max_twq_pkts = (nv->qt[0].sub0.size_mask - 8) / 2;
	/* upper bound for packets handled by RCQ */
	max_rcq_pkts = (nv->qt[1].cmpl.size_mask - 8) / 2;
	/* a rough upper bound on how many packets can be handled by BDQ */
	max_bdq_pkts = (4096 / (FBNIC_RX_HROOM + pkt_size + FBNIC_RX_TROOM)) *
		       nv->qt[1].sub0.size_mask;

	/* Compute packets per iteration and total number of packets we need
	 * to run for this test. The pkts_per_iter is based on finding the
	 * bottleneck between all the queues and establishing that as our
	 * limit.
	 *
	 * For the total number of packets to send we will use the TCQ and
	 * HPQ as the limits since those two queues should be capable of
	 * handling the most frames. Basically double that to guarantee we
	 * loop through all queues at least once.
	 */
	pkts_per_iter = min(min(max_twq_pkts, max_bdq_pkts), max_rcq_pkts - 3);
	npackets = max_t(u16,
			 nv->qt[0].cmpl.size_mask + 1,
			 max_bdq_pkts +
			 max_bdq_pkts / nv->qt[1].sub0.size_mask);
	lc = (2 * npackets + pkts_per_iter) / pkts_per_iter;

	for (j = 0; j < lc; j++) {
		struct fbnic_dev *fbd = fbn->fbd;

		for (i = 0; i < pkts_per_iter; i++) {
			/* keep reference since buffer is reused */
			skb_get(skb);
			/* transmit on twq0 */
			if (fbnic_xmit_frame_ring(skb, &nv->qt[0].sub0) !=
			    NETDEV_TX_OK) {
				ret_val = 30;
				goto err;
			}
		}

		/* give hardware time to process Tx descriptors */
		wrfl();
		usleep_range(100, 1000);

		/* check and clean recieval queue */
		ret_val = fbnic_check_loopback_rcq(nv, &nv->qt[1],
						   pkts_per_iter, pkt_size);
		if (ret_val)
			goto err;

		/* clean transmission queue */
		fbnic_clean_tcq(nv, &nv->qt[0], 0);
	}

err:
	/* free the skb */
	kfree_skb(skb);

	return ret_val;
}

/**
 * fbnic_loopback_test - Verify TX-RX data path with loopback enabled
 * @netdev: netdev device to test
 * @data: Pointer to results storage
 *
 * This test works by partially bringing up the NIC with one TX queue triad
 * and one RX queue triad. A number of bursts of packets are sent, and we
 * check that they are faithfully received. MAC and RSS are set up to
 * the extent necessary for RX to work, but NAPI interrupts are disabled and
 * the net device is not brought up.
 *
 * Returns non-zero on failure.
 **/
static int fbnic_loopback_test(struct net_device *netdev, u64 *data)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_net *clone;

	clone = fbnic_clone_create(fbn);
	if (!clone) {
		*data = 1;
		goto err;
	}

	*data = fbnic_setup_loopback_net(clone);
	if (*data)
		goto err_free_clone;

	*data = fbnic_setup_mac_loopback(clone);
	if (*data)
		goto err_cleanup_loopback;

	*data = fbnic_run_loopback_test(clone);
	if (*data)
		goto err_cleanup_loopback;

	*data = 0;
err_cleanup_loopback:
	fbnic_cleanup_loopback_net(clone);
err_free_clone:
	fbnic_clone_free(clone);
err:
	return *data;
}

/**
 * fbnic_ethtool_msix_test - Verify behavior of NIC interrupts
 * @netdev: netdev device to test
 * @data: Pointer to results storage
 *
 * This function is meant to test the global interrupt registers and the
 * PCIe IP MSI-X functionalty. It essentially goes through and tests
 * test various combinations of the set, clear, and mask bits in order to
 * verify the behavior is as we expect it to be from the driver.
 *
 * Returns non-zero on failure.
 **/
static int fbnic_ethtool_msix_test(struct net_device *netdev, u64 *data)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;

	*data = fbnic_msix_test(fbd);

	return !!*data;
}

static int fbnic_ethtool_tlv_self_test(struct net_device *netdev, u64 *data)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;

	*data = fbnic_tlv_self_test(fbd);

	return !!*data;
}

static int fbnic_ethtool_mbx_self_test(struct net_device *netdev, u64 *data)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;

	*data = fbnic_fw_mbx_self_test(fbd, false);

	return !!*data;
}

/**
 * fbnic_stop_test - Verify behavior of ndo_stop call
 * @netdev: netdev device to test
 * @data: Pointer to results storage
 *
 * This function is meant to test the driver ndo_stop call to verify that
 * it can be called multiple times without side effects. The test is really
 * split into two pieces. This first block just verifies that the kernel
 * doesn't panic when we call stop the second time. The real test is
 * calling ndo_open after the stop and verifying we are able to pass
 * traffic again.
 *
 * Returns non-zero on failure.
 **/
static int fbnic_stop_test(struct net_device *netdev, u64 *data)
{
	/* A gratuitous call to stop. Interface should either have already
	 * been down or brought down prior to starting this self test.
	 */
	netdev->netdev_ops->ndo_stop(netdev);

	/* If the kernel didn't panic there isn't much else we can test
	 * at this time. Essentially the next step after this will be to
	 * bring the interface back up, and if that fails we will flag the
	 * test as failed.
	 */

	return 0;
}

static void fbnic_self_test(struct net_device *netdev,
			    struct ethtool_test *eth_test, u64 *data)
{
	bool if_running = netif_running(netdev);

	if (fbnic_ethtool_tlv_self_test(netdev, &data[TEST_TLV]))
		eth_test->flags |= ETH_TEST_FL_FAILED;

	if (fbnic_ethtool_mbx_self_test(netdev, &data[TEST_MBX]))
		eth_test->flags |= ETH_TEST_FL_FAILED;

	if (!(eth_test->flags & ETH_TEST_FL_OFFLINE)) {
		data[TEST_REG] = 0;
		data[TEST_MSIX] = 0;
		data[TEST_LPBK] = 0;
		data[TEST_STOP] = 0;
		return;
	}

	if (if_running)
		netdev->netdev_ops->ndo_stop(netdev);

	if (fbnic_ethtool_regs_test(netdev, &data[TEST_REG]))
		eth_test->flags |= ETH_TEST_FL_FAILED;

	if (fbnic_ethtool_msix_test(netdev, &data[TEST_MSIX]))
		eth_test->flags |= ETH_TEST_FL_FAILED;

	if (fbnic_loopback_test(netdev, &data[TEST_LPBK]))
		eth_test->flags |= ETH_TEST_FL_FAILED;

	if (fbnic_stop_test(netdev, &data[TEST_STOP]))
		eth_test->flags |= ETH_TEST_FL_FAILED;

	if (if_running && netdev->netdev_ops->ndo_open(netdev)) {
		netdev_err(netdev,
			   "Failed to rei-initialize hardware following test\n");
		eth_test->flags |= ETH_TEST_FL_FAILED;
		dev_close(netdev);
	}
}

static void fbnic_get_channels(struct net_device *netdev,
			       struct ethtool_channels *ch)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;

	ch->max_rx = fbd->max_num_queues;
	ch->max_tx = fbd->max_num_queues;
	ch->max_combined = min(ch->max_rx, ch->max_tx);
	ch->max_other =	FBNIC_NON_NAPI_VECTORS;

	if (fbn->num_rx_queues > fbn->num_napi ||
	    fbn->num_tx_queues > fbn->num_napi)
		ch->combined_count = min(fbn->num_rx_queues,
					 fbn->num_tx_queues);
	else
		ch->combined_count =
			fbn->num_rx_queues + fbn->num_tx_queues - fbn->num_napi;
	ch->rx_count = fbn->num_rx_queues - ch->combined_count;
	ch->tx_count = fbn->num_tx_queues - ch->combined_count;
	ch->other_count = FBNIC_NON_NAPI_VECTORS;
}

static void fbnic_set_queues(struct fbnic_net *fbn, struct ethtool_channels *ch,
			     unsigned int max_napis)
{
	fbn->num_rx_queues = ch->rx_count + ch->combined_count;
	fbn->num_tx_queues = ch->tx_count + ch->combined_count;
	fbn->num_napi = min(ch->rx_count + ch->tx_count + ch->combined_count,
			    max_napis);
}

static int fbnic_set_channels(struct net_device *netdev,
			      struct ethtool_channels *ch)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	unsigned int max_napis, standalone;
	struct fbnic_dev *fbd = fbn->fbd;
	struct fbnic_net *clone;
	int err;

	max_napis = fbd->num_irqs - FBNIC_NON_NAPI_VECTORS;
	standalone = ch->rx_count + ch->tx_count;

	/* Limits for standalone queues:
	 *  - each queue has it's own NAPI (num_napi >= rx + tx + combined)
	 *  - combining queues (combined not 0, rx or tx must be 0)
	 */
	if ((ch->rx_count && ch->tx_count && ch->combined_count) ||
	    (standalone && standalone + ch->combined_count > max_napis) ||
	    ch->rx_count + ch->combined_count > fbd->max_num_queues ||
	    ch->tx_count + ch->combined_count > fbd->max_num_queues ||
	    ch->other_count != FBNIC_NON_NAPI_VECTORS)
		return -EINVAL;

	if (!netif_running(netdev)) {
		fbnic_set_queues(fbn, ch, max_napis);
		fbnic_reset_indir_tbl(fbn);
		return 0;
	}

	clone = fbnic_clone_create(fbn);
	if (!clone)
		return -ENOMEM;

	fbnic_set_queues(clone, ch, max_napis);
	INIT_LIST_HEAD(&clone->napis);
	memset(clone->tx, 0, sizeof(clone->tx));
	memset(clone->rx, 0, sizeof(clone->rx));

	err = fbnic_alloc_napi_vectors(clone);
	if (err)
		goto err_free_clone;

	err = fbnic_alloc_resources(clone);
	if (err)
		goto err_free_napis;

	fbnic_down_noidle(fbn);
	err = fbnic_wait_all_queues_idle(fbn->fbd, true);
	if (err)
		goto err_start_stack;

	err = netif_set_real_num_queues(netdev, clone->num_tx_queues,
					clone->num_rx_queues);
	if (err)
		goto err_start_stack;

	/* nothing can fail past this point */
	fbnic_flush(fbn);

	fbnic_clone_swap(fbn, clone);

	/* reset RSS indirection table */
	fbnic_reset_indir_tbl(fbn);

	fbnic_up(fbn);

	fbnic_free_resources(clone);
	fbnic_free_napi_vectors(clone);
	fbnic_clone_free(clone);

	return 0;

err_start_stack:
	/* TBD: enable does reset - can we just renable ?? asking @jhas */
	fbnic_flush(fbn);
	fbnic_up(fbn);
	fbnic_free_resources(clone);
err_free_napis:
	fbnic_free_napi_vectors(clone);
err_free_clone:
	fbnic_clone_free(clone);
	return err;
}

static int
fbnic_get_ts_info(struct net_device *netdev, struct ethtool_ts_info *tsinfo)
{
	struct fbnic_net *fbn = netdev_priv(netdev);

	tsinfo->phc_index = ptp_clock_index(fbn->fbd->ptp);

	tsinfo->so_timestamping =
		SOF_TIMESTAMPING_TX_SOFTWARE |
		SOF_TIMESTAMPING_RX_SOFTWARE |
		SOF_TIMESTAMPING_SOFTWARE |
		SOF_TIMESTAMPING_TX_HARDWARE |
		SOF_TIMESTAMPING_RX_HARDWARE |
		SOF_TIMESTAMPING_RAW_HARDWARE;

	tsinfo->tx_types =
		BIT(HWTSTAMP_TX_OFF) |
		BIT(HWTSTAMP_TX_ON);

	tsinfo->rx_filters =
		BIT(HWTSTAMP_FILTER_NONE) |
		BIT(HWTSTAMP_FILTER_PTP_V1_L4_EVENT) |
		BIT(HWTSTAMP_FILTER_PTP_V2_L4_EVENT) |
		BIT(HWTSTAMP_FILTER_PTP_V2_L2_EVENT) |
		BIT(HWTSTAMP_FILTER_PTP_V2_EVENT) |
		BIT(HWTSTAMP_FILTER_ALL);

	return 0;
}

static int fbnic_get_rss_hash_idx(u32 flow_type)
{
	switch (flow_type & ~(FLOW_EXT | FLOW_MAC_EXT | FLOW_RSS)) {
	case TCP_V4_FLOW:
		return FBNIC_TCP4_HASH_OPT;
	case TCP_V6_FLOW:
		return FBNIC_TCP6_HASH_OPT;
	case UDP_V4_FLOW:
		return FBNIC_UDP4_HASH_OPT;
	case UDP_V6_FLOW:
		return FBNIC_UDP6_HASH_OPT;
	case AH_V4_FLOW:
	case ESP_V4_FLOW:
	case AH_ESP_V4_FLOW:
	case SCTP_V4_FLOW:
	case IPV4_FLOW:
	case IPV4_USER_FLOW:
		return FBNIC_IPV4_HASH_OPT;
	case AH_V6_FLOW:
	case ESP_V6_FLOW:
	case AH_ESP_V6_FLOW:
	case SCTP_V6_FLOW:
	case IPV6_FLOW:
	case IPV6_USER_FLOW:
		return FBNIC_IPV6_HASH_OPT;
	case ETHER_FLOW:
		return FBNIC_ETHER_HASH_OPT;
	}

	return -1;
}

static int fbnic_get_rss_hash_opts(struct fbnic_net *fbn,
				   struct ethtool_rxnfc *cmd)
{
	int hash_opt_idx = fbnic_get_rss_hash_idx(cmd->flow_type);

	if (hash_opt_idx < 0)
		return -EINVAL;

	/* Report options from rss_en table in fbn */
	cmd->data = fbn->rss_flow_hash[hash_opt_idx];

	return 0;
}

static int fbnic_get_cls_rule(struct fbnic_net *fbn,
			      struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp;
	struct fbnic_dev *fbd = fbn->fbd;
	struct fbnic_act_tcam *act_tcam;
	int idx;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	if (fsp->location >= FBNIC_RPC_ACT_TBL_NFC_ENTRIES)
		return -EINVAL;

	idx = fsp->location + FBNIC_RPC_ACT_TBL_NFC_OFFSET;
	act_tcam = &fbd->act_tcam[idx];

	if (act_tcam->state != FBNIC_TCAM_S_VALID)
		return -EINVAL;

	/* report maximum rule count */
	cmd->data = FBNIC_RPC_ACT_TBL_NFC_ENTRIES;

	/* set flow type field */
	if (!(act_tcam->value.tcam[1] & FBNIC_RPC_TCAM_ACT1_IP_VALID)) {
		fsp->flow_type = ETHER_FLOW;
		if (!FIELD_GET(FBNIC_RPC_TCAM_ACT1_L2_MACDA_IDX,
			       act_tcam->mask.tcam[1])) {
			struct fbnic_mac_addr *mac_addr;

			idx = FIELD_GET(FBNIC_RPC_TCAM_ACT1_L2_MACDA_IDX,
					act_tcam->value.tcam[1]);
			mac_addr = &fbd->mac_addr[idx];

			ether_addr_copy(fsp->h_u.ether_spec.h_dest,
					mac_addr->value.addr8);
			eth_broadcast_addr(fsp->m_u.ether_spec.h_dest);
		}
	} else if (act_tcam->value.tcam[1] &
		   FBNIC_RPC_TCAM_ACT1_OUTER_IP_VALID) {
		fsp->flow_type = IPV6_USER_FLOW;
		fsp->h_u.usr_ip6_spec.l4_proto = IPPROTO_IPV6;
		fsp->m_u.usr_ip6_spec.l4_proto = 0xff;

		if (!FIELD_GET(FBNIC_RPC_TCAM_ACT0_OUTER_IPSRC_IDX,
			       act_tcam->mask.tcam[0])) {
			struct fbnic_ip_addr *ip_addr;
			int i;

			idx = FIELD_GET(FBNIC_RPC_TCAM_ACT0_OUTER_IPSRC_IDX,
					act_tcam->value.tcam[0]);
			ip_addr = &fbd->ipo_src[idx];

			for (i = 0; i < 4; i++) {
				fsp->h_u.usr_ip6_spec.ip6src[i] =
					ip_addr->value.s6_addr32[i];
				fsp->m_u.usr_ip6_spec.ip6src[i] =
					~ip_addr->mask.s6_addr32[i];
			}
		}

		if (!FIELD_GET(FBNIC_RPC_TCAM_ACT0_OUTER_IPDST_IDX,
			       act_tcam->mask.tcam[0])) {
			struct fbnic_ip_addr *ip_addr;
			int i;

			idx = FIELD_GET(FBNIC_RPC_TCAM_ACT0_OUTER_IPDST_IDX,
					act_tcam->value.tcam[0]);
			ip_addr = &fbd->ipo_dst[idx];

			for (i = 0; i < 4; i++) {
				fsp->h_u.usr_ip6_spec.ip6dst[i] =
					ip_addr->value.s6_addr32[i];
				fsp->m_u.usr_ip6_spec.ip6dst[i] =
					~ip_addr->mask.s6_addr32[i];
			}
		}
	} else if ((act_tcam->value.tcam[1] & FBNIC_RPC_TCAM_ACT1_IP_IS_V6)) {
		if (act_tcam->value.tcam[1] & FBNIC_RPC_TCAM_ACT1_L4_VALID) {
			if (act_tcam->value.tcam[1] &
			    FBNIC_RPC_TCAM_ACT1_L4_IS_UDP)
				fsp->flow_type = UDP_V6_FLOW;
			else
				fsp->flow_type = TCP_V6_FLOW;
			fsp->h_u.tcp_ip6_spec.psrc =
				cpu_to_be16(act_tcam->value.tcam[3]);
			fsp->m_u.tcp_ip6_spec.psrc =
				cpu_to_be16(~act_tcam->mask.tcam[3]);
			fsp->h_u.tcp_ip6_spec.pdst =
				cpu_to_be16(act_tcam->value.tcam[4]);
			fsp->m_u.tcp_ip6_spec.pdst =
				cpu_to_be16(~act_tcam->mask.tcam[4]);
		} else {
			fsp->flow_type = IPV6_USER_FLOW;
		}

		if (!FIELD_GET(FBNIC_RPC_TCAM_ACT0_IPSRC_IDX,
			       act_tcam->mask.tcam[0])) {
			struct fbnic_ip_addr *ip_addr;
			int i;

			idx = FIELD_GET(FBNIC_RPC_TCAM_ACT0_IPSRC_IDX,
					act_tcam->value.tcam[0]);
			ip_addr = &fbd->ip_src[idx];

			for (i = 0; i < 4; i++) {
				fsp->h_u.usr_ip6_spec.ip6src[i] =
					ip_addr->value.s6_addr32[i];
				fsp->m_u.usr_ip6_spec.ip6src[i] =
					~ip_addr->mask.s6_addr32[i];
			}
		}

		if (!FIELD_GET(FBNIC_RPC_TCAM_ACT0_IPDST_IDX,
			       act_tcam->mask.tcam[0])) {
			struct fbnic_ip_addr *ip_addr;
			int i;

			idx = FIELD_GET(FBNIC_RPC_TCAM_ACT0_IPDST_IDX,
					act_tcam->value.tcam[0]);
			ip_addr = &fbd->ip_dst[idx];

			for (i = 0; i < 4; i++) {
				fsp->h_u.usr_ip6_spec.ip6dst[i] =
					ip_addr->value.s6_addr32[i];
				fsp->m_u.usr_ip6_spec.ip6dst[i] =
					~ip_addr->mask.s6_addr32[i];
			}
		}
	} else {
		if (act_tcam->value.tcam[1] & FBNIC_RPC_TCAM_ACT1_L4_VALID) {
			if (act_tcam->value.tcam[1] &
			    FBNIC_RPC_TCAM_ACT1_L4_IS_UDP)
				fsp->flow_type = UDP_V4_FLOW;
			else
				fsp->flow_type = TCP_V4_FLOW;
			fsp->h_u.tcp_ip4_spec.psrc =
				cpu_to_be16(act_tcam->value.tcam[3]);
			fsp->m_u.tcp_ip4_spec.psrc =
				cpu_to_be16(~act_tcam->mask.tcam[3]);
			fsp->h_u.tcp_ip4_spec.pdst =
				cpu_to_be16(act_tcam->value.tcam[4]);
			fsp->m_u.tcp_ip4_spec.pdst =
				cpu_to_be16(~act_tcam->mask.tcam[4]);
		} else {
			fsp->flow_type = IPV4_USER_FLOW;
			fsp->h_u.usr_ip4_spec.ip_ver = ETH_RX_NFC_IP4;
		}

		if (!FIELD_GET(FBNIC_RPC_TCAM_ACT0_IPSRC_IDX,
			       act_tcam->mask.tcam[0])) {
			struct fbnic_ip_addr *ip_addr;

			idx = FIELD_GET(FBNIC_RPC_TCAM_ACT0_IPSRC_IDX,
					act_tcam->value.tcam[0]);
			ip_addr = &fbd->ip_src[idx];

			fsp->h_u.usr_ip4_spec.ip4src =
				ip_addr->value.s6_addr32[3];
			fsp->m_u.usr_ip4_spec.ip4src =
				~ip_addr->mask.s6_addr32[3];
		}

		if (!FIELD_GET(FBNIC_RPC_TCAM_ACT0_IPDST_IDX,
			       act_tcam->mask.tcam[0])) {
			struct fbnic_ip_addr *ip_addr;

			idx = FIELD_GET(FBNIC_RPC_TCAM_ACT0_IPDST_IDX,
					act_tcam->value.tcam[0]);
			ip_addr = &fbd->ip_dst[idx];

			fsp->h_u.usr_ip4_spec.ip4dst =
				ip_addr->value.s6_addr32[3];
			fsp->m_u.usr_ip4_spec.ip4dst =
				~ip_addr->mask.s6_addr32[3];
		}
	}

	/* record action */
	if (act_tcam->dest & FBNIC_RPC_ACT_TBL0_DROP)
		fsp->ring_cookie = RX_CLS_FLOW_DISC;
	else if (act_tcam->dest & FBNIC_RPC_ACT_TBL0_Q_SEL)
		fsp->ring_cookie = FIELD_GET(FBNIC_RPC_ACT_TBL0_Q_ID,
					     act_tcam->dest);
	else
		fsp->flow_type |= FLOW_RSS;

	cmd->rss_context = FIELD_GET(FBNIC_RPC_ACT_TBL0_RSS_CTXT_ID,
				     act_tcam->dest);

	return 0;
}

static int fbnic_get_cls_rule_all(struct fbnic_net *fbn,
				  struct ethtool_rxnfc *cmd,
				  u32 *rule_locs)
{
	struct fbnic_dev *fbd = fbn->fbd;
	int i, cnt = 0;

	/* report maximum rule count */
	cmd->data = FBNIC_RPC_ACT_TBL_NFC_ENTRIES;

	for (i = 0; i < FBNIC_RPC_ACT_TBL_NFC_ENTRIES; i++) {
		int idx = i + FBNIC_RPC_ACT_TBL_NFC_OFFSET;
		struct fbnic_act_tcam *act_tcam;

		act_tcam = &fbd->act_tcam[idx];
		if (act_tcam->state != FBNIC_TCAM_S_VALID)
			continue;

		if (rule_locs) {
			if (cnt == cmd->rule_cnt)
				return -EMSGSIZE;

			rule_locs[cnt] = i;
		}

		cnt++;
	}

	return cnt;
}

static int fbnic_get_rxnfc(struct net_device *netdev,
			   struct ethtool_rxnfc *cmd, u32 *rule_locs)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_GRXRINGS:
		cmd->data = fbn->num_rx_queues;
		ret = 0;
		break;
	case ETHTOOL_GRXFH:
		ret = fbnic_get_rss_hash_opts(fbn, cmd);
		break;
	case ETHTOOL_GRXCLSRULE:
		ret = fbnic_get_cls_rule(fbn, cmd);
		break;
	case ETHTOOL_GRXCLSRLCNT:
		rule_locs = NULL;
		fallthrough;
	case ETHTOOL_GRXCLSRLALL:
		ret = fbnic_get_cls_rule_all(fbn, cmd, rule_locs);
		if (ret < 0)
			break;

		cmd->rule_cnt = ret;
		ret = 0;
		break;
	}

	return ret;
}

#define FBNIC_L2_HASH_OPTIONS \
	(RXH_L2DA | RXH_DISCARD)
#define FBNIC_L3_HASH_OPTIONS \
	(FBNIC_L2_HASH_OPTIONS | RXH_IP_SRC | RXH_IP_DST)
#define FBNIC_L4_HASH_OPTIONS \
	(FBNIC_L3_HASH_OPTIONS | RXH_L4_B_0_1 | RXH_L4_B_2_3)

static int fbnic_set_rss_hash_opts(struct fbnic_net *fbn,
				   const struct ethtool_rxnfc *cmd)
{
	int hash_opt_idx;

	/* Verify the type requested is correct */
	hash_opt_idx = fbnic_get_rss_hash_idx(cmd->flow_type);
	if (hash_opt_idx < 0)
		return -EINVAL;

	/* verify the fields asked for can actually be assigned based on type */
	if (cmd->data & ~FBNIC_L4_HASH_OPTIONS ||
	    (hash_opt_idx > FBNIC_L4_HASH_OPT &&
	     cmd->data & ~FBNIC_L3_HASH_OPTIONS) ||
	    (hash_opt_idx > FBNIC_IP_HASH_OPT &&
	     cmd->data & ~FBNIC_L2_HASH_OPTIONS))
		return -EINVAL;

	fbn->rss_flow_hash[hash_opt_idx] = cmd->data;

	if (netif_running(fbn->netdev)) {
		fbnic_rss_reinit(fbn->fbd, fbn);
		fbnic_write_rules(fbn->fbd);
	}

	return 0;
}

static int fbnic_set_cls_rule_ins(struct fbnic_net *fbn,
				  const struct ethtool_rxnfc *cmd)
{
	u16 flow_value = 0, flow_mask = 0xffff, ip_value = 0, ip_mask = 0xffff;
	u16 sport = 0, sport_mask = ~0, dport = 0, dport_mask = ~0;
	u16 misc = 0, misc_mask = ~0;
	u32 dest = FIELD_PREP(FBNIC_RPC_ACT_TBL0_DEST_MASK,
			      FBNIC_RPC_ACT_TBL0_DEST_HOST);
	struct fbnic_ip_addr *ip_src = NULL, *ip_dst = NULL;
	struct fbnic_mac_addr *mac_addr = NULL;
	struct ethtool_rx_flow_spec *fsp;
	struct fbnic_dev *fbd = fbn->fbd;
	struct fbnic_act_tcam *act_tcam;
	struct in6_addr *addr6, *mask6;
	struct in_addr *addr4, *mask4;
	u32 flow_type;
	int hash_idx;
	int idx, j;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	if (fsp->location >= FBNIC_RPC_ACT_TBL_NFC_ENTRIES)
		return -EINVAL;

	if (fsp->ring_cookie == RX_CLS_FLOW_DISC) {
		dest = FBNIC_RPC_ACT_TBL0_DROP;
	} else if (fsp->flow_type & FLOW_RSS) {
		if (fsp->ring_cookie != 0 ||  cmd->rss_context > 1)
			return -EINVAL;
		if (cmd->rss_context == 1)
			dest |= FBNIC_RPC_ACT_TBL0_RSS_CTXT_ID;
	} else {
		u32 ring_idx = ethtool_get_flow_spec_ring(fsp->ring_cookie);

		if (ring_idx >= fbn->num_rx_queues)
			return -EINVAL;

		dest |= FBNIC_RPC_ACT_TBL0_Q_SEL |
			FIELD_PREP(FBNIC_RPC_ACT_TBL0_Q_ID, ring_idx);
	}

	idx = fsp->location + FBNIC_RPC_ACT_TBL_NFC_OFFSET;
	act_tcam = &fbd->act_tcam[idx];

	/* Do not allow overwriting for now.
	 * To support overwriting rules we will need to add logic to free
	 * any IP or MACDA TCAMs that may be associated with the old rule.
	 */
	if (act_tcam->state != FBNIC_TCAM_S_DISABLED)
		return -EBUSY;

	flow_type = fsp->flow_type & ~(FLOW_EXT | FLOW_RSS);
	hash_idx = fbnic_get_rss_hash_idx(flow_type);

	switch (flow_type) {
	case UDP_V4_FLOW:
udp4_flow:
		flow_value |= FBNIC_RPC_TCAM_ACT1_L4_IS_UDP;
		fallthrough;
	case TCP_V4_FLOW:
tcp4_flow:
		flow_value |= FBNIC_RPC_TCAM_ACT1_L4_VALID;
		flow_mask &= ~(FBNIC_RPC_TCAM_ACT1_L4_IS_UDP |
			       FBNIC_RPC_TCAM_ACT1_L4_VALID);

		sport = be16_to_cpu(fsp->h_u.tcp_ip4_spec.psrc);
		sport_mask = ~be16_to_cpu(fsp->m_u.tcp_ip4_spec.psrc);
		dport = be16_to_cpu(fsp->h_u.tcp_ip4_spec.pdst);
		dport_mask = ~be16_to_cpu(fsp->m_u.tcp_ip4_spec.pdst);
		goto ip4_flow;
	case IP_USER_FLOW:
		if (!fsp->m_u.usr_ip4_spec.proto)
			goto ip4_flow;
		if (fsp->m_u.usr_ip4_spec.proto != 0xff)
			return -EINVAL;
		if (fsp->h_u.usr_ip4_spec.proto == IPPROTO_UDP)
			goto udp4_flow;
		if (fsp->h_u.usr_ip4_spec.proto == IPPROTO_TCP)
			goto tcp4_flow;
		return -EINVAL;
ip4_flow:
		addr4 = (struct in_addr *)&fsp->h_u.usr_ip4_spec.ip4src;
		mask4 = (struct in_addr *)&fsp->m_u.usr_ip4_spec.ip4src;
		if (mask4->s_addr) {
			ip_src = __fbnic_ip4_sync(fbd, fbd->ip_src,
						  addr4, mask4);
			if (!ip_src)
				return -ENOSPC;

			set_bit(idx, ip_src->act_tcam);
			ip_value |= FBNIC_RPC_TCAM_ACT0_IPSRC_VALID |
				    FIELD_PREP(FBNIC_RPC_TCAM_ACT0_IPSRC_IDX,
					       ip_src - fbd->ip_src);
			ip_mask &= ~(FBNIC_RPC_TCAM_ACT0_IPSRC_VALID |
				     FBNIC_RPC_TCAM_ACT0_IPSRC_IDX);
		}

		addr4 = (struct in_addr *)&fsp->h_u.usr_ip4_spec.ip4dst;
		mask4 = (struct in_addr *)&fsp->m_u.usr_ip4_spec.ip4dst;
		if (mask4->s_addr) {
			ip_dst = __fbnic_ip4_sync(fbd, fbd->ip_dst,
						  addr4, mask4);
			if (!ip_dst) {
				if (ip_src && ip_src->state == FBNIC_TCAM_S_ADD)
					memset(ip_src, 0, sizeof(*ip_src));
				return -ENOSPC;
			}

			set_bit(idx, ip_dst->act_tcam);
			ip_value |= FBNIC_RPC_TCAM_ACT0_IPDST_VALID |
				    FIELD_PREP(FBNIC_RPC_TCAM_ACT0_IPDST_IDX,
					       ip_dst - fbd->ip_dst);
			ip_mask &= ~(FBNIC_RPC_TCAM_ACT0_IPDST_VALID |
				     FBNIC_RPC_TCAM_ACT0_IPDST_IDX);
		}
		flow_value |= FBNIC_RPC_TCAM_ACT1_IP_VALID |
			      FBNIC_RPC_TCAM_ACT1_L2_MACDA_VALID;
		flow_mask &= ~(FBNIC_RPC_TCAM_ACT1_IP_IS_V6 |
			       FBNIC_RPC_TCAM_ACT1_IP_VALID |
			       FBNIC_RPC_TCAM_ACT1_L2_MACDA_VALID);
		break;
	case UDP_V6_FLOW:
udp6_flow:
		flow_value |= FBNIC_RPC_TCAM_ACT1_L4_IS_UDP;
		fallthrough;
	case TCP_V6_FLOW:
tcp6_flow:
		flow_value |= FBNIC_RPC_TCAM_ACT1_L4_VALID;
		flow_mask &= ~(FBNIC_RPC_TCAM_ACT1_L4_IS_UDP |
			  FBNIC_RPC_TCAM_ACT1_L4_VALID);

		sport = be16_to_cpu(fsp->h_u.tcp_ip6_spec.psrc);
		sport_mask = ~be16_to_cpu(fsp->m_u.tcp_ip6_spec.psrc);
		dport = be16_to_cpu(fsp->h_u.tcp_ip6_spec.pdst);
		dport_mask = ~be16_to_cpu(fsp->m_u.tcp_ip6_spec.pdst);
		goto ipv6_flow;
	case IPV6_USER_FLOW:
		if (!fsp->m_u.usr_ip6_spec.l4_proto)
			goto ipv6_flow;

		if (fsp->m_u.usr_ip6_spec.l4_proto != 0xff)
			return -EINVAL;
		if (fsp->h_u.usr_ip6_spec.l4_proto == IPPROTO_UDP)
			goto udp6_flow;
		if (fsp->h_u.usr_ip6_spec.l4_proto == IPPROTO_TCP)
			goto tcp6_flow;
		if (fsp->h_u.usr_ip6_spec.l4_proto != IPPROTO_IPV6)
			return -EINVAL;

		addr6 = (struct in6_addr *)fsp->h_u.usr_ip6_spec.ip6src;
		mask6 = (struct in6_addr *)fsp->m_u.usr_ip6_spec.ip6src;
		if (!ipv6_addr_any(mask6)) {
			ip_src = __fbnic_ip6_sync(fbd, fbd->ipo_src,
						  addr6, mask6);
			if (!ip_src)
				return -ENOSPC;

			set_bit(idx, ip_src->act_tcam);
			ip_value |=
				FBNIC_RPC_TCAM_ACT0_OUTER_IPSRC_VALID |
				FIELD_PREP(FBNIC_RPC_TCAM_ACT0_OUTER_IPSRC_IDX,
					   ip_src - fbd->ipo_src);
			ip_mask &=
				~(FBNIC_RPC_TCAM_ACT0_OUTER_IPSRC_VALID |
				  FBNIC_RPC_TCAM_ACT0_OUTER_IPSRC_IDX);
		}

		addr6 = (struct in6_addr *)fsp->h_u.usr_ip6_spec.ip6dst;
		mask6 = (struct in6_addr *)fsp->m_u.usr_ip6_spec.ip6dst;
		if (!ipv6_addr_any(mask6)) {
			ip_dst = __fbnic_ip6_sync(fbd, fbd->ipo_dst,
						  addr6, mask6);
			if (!ip_dst) {
				if (ip_src && ip_src->state == FBNIC_TCAM_S_ADD)
					memset(ip_src, 0, sizeof(*ip_src));
				return -ENOSPC;
			}

			set_bit(idx, ip_dst->act_tcam);
			ip_value |=
				FBNIC_RPC_TCAM_ACT0_OUTER_IPDST_VALID |
				FIELD_PREP(FBNIC_RPC_TCAM_ACT0_OUTER_IPDST_IDX,
					   ip_dst - fbd->ipo_dst);
			ip_mask &= ~(FBNIC_RPC_TCAM_ACT0_OUTER_IPDST_VALID |
				     FBNIC_RPC_TCAM_ACT0_OUTER_IPDST_IDX);
		}

		flow_value |= FBNIC_RPC_TCAM_ACT1_OUTER_IP_VALID;
		flow_mask &= FBNIC_RPC_TCAM_ACT1_OUTER_IP_VALID;
ipv6_flow:
		addr6 = (struct in6_addr *)fsp->h_u.usr_ip6_spec.ip6src;
		mask6 = (struct in6_addr *)fsp->m_u.usr_ip6_spec.ip6src;
		if (!ip_src && !ipv6_addr_any(mask6)) {
			ip_src = __fbnic_ip6_sync(fbd, fbd->ip_src,
						  addr6, mask6);
			if (!ip_src)
				return -ENOSPC;

			set_bit(idx, ip_src->act_tcam);
			ip_value |= FBNIC_RPC_TCAM_ACT0_IPSRC_VALID |
				    FIELD_PREP(FBNIC_RPC_TCAM_ACT0_IPSRC_IDX,
					       ip_src - fbd->ip_src);
			ip_mask &= ~(FBNIC_RPC_TCAM_ACT0_IPSRC_VALID |
				       FBNIC_RPC_TCAM_ACT0_IPSRC_IDX);
		}

		addr6 = (struct in6_addr *)fsp->h_u.usr_ip6_spec.ip6dst;
		mask6 = (struct in6_addr *)fsp->m_u.usr_ip6_spec.ip6dst;
		if (!ip_dst && !ipv6_addr_any(mask6)) {
			ip_dst = __fbnic_ip6_sync(fbd, fbd->ip_dst,
						  addr6, mask6);
			if (!ip_dst) {
				if (ip_src && ip_src->state == FBNIC_TCAM_S_ADD)
					memset(ip_src, 0, sizeof(*ip_src));
				return -ENOSPC;
			}

			set_bit(idx, ip_dst->act_tcam);
			ip_value |= FBNIC_RPC_TCAM_ACT0_IPDST_VALID |
				    FIELD_PREP(FBNIC_RPC_TCAM_ACT0_IPDST_IDX,
					       ip_dst - fbd->ip_dst);
			ip_mask &= ~(FBNIC_RPC_TCAM_ACT0_IPDST_VALID |
				       FBNIC_RPC_TCAM_ACT0_IPDST_IDX);
		}

		flow_value |= FBNIC_RPC_TCAM_ACT1_IP_IS_V6 |
			      FBNIC_RPC_TCAM_ACT1_IP_VALID |
			      FBNIC_RPC_TCAM_ACT1_L2_MACDA_VALID;
		flow_mask &= ~(FBNIC_RPC_TCAM_ACT1_IP_IS_V6 |
			       FBNIC_RPC_TCAM_ACT1_IP_VALID |
			       FBNIC_RPC_TCAM_ACT1_L2_MACDA_VALID);
		break;
	case ETHER_FLOW:
		if (!is_zero_ether_addr(fsp->m_u.ether_spec.h_dest)) {
			u8 *addr = fsp->h_u.ether_spec.h_dest;
			u8 *mask = fsp->m_u.ether_spec.h_dest;

			/* Do not allow MAC addr of 0 */
			if (is_zero_ether_addr(addr))
				return -EINVAL;

			/* Only support full MAC address to avoid
			 * conflicts with other MAC addresses.
			 */
			if (!is_broadcast_ether_addr(mask))
				return -EINVAL;

			if (is_multicast_ether_addr(addr))
				mac_addr = __fbnic_mc_sync(fbd, addr);
			else
				mac_addr = __fbnic_uc_sync(fbd, addr);

			if (!mac_addr)
				return -ENOSPC;

			set_bit(idx, mac_addr->act_tcam);
			flow_value |=
				FIELD_PREP(FBNIC_RPC_TCAM_ACT1_L2_MACDA_IDX,
					   mac_addr - fbd->mac_addr);
			flow_mask &= ~FBNIC_RPC_TCAM_ACT1_L2_MACDA_IDX;
		}

		flow_value |= FBNIC_RPC_TCAM_ACT1_L2_MACDA_VALID;
		flow_mask &= ~FBNIC_RPC_TCAM_ACT1_L2_MACDA_VALID;
		break;
	default:
		return -EINVAL;
	}

	/* Write action table values */
	act_tcam->dest = dest;
	act_tcam->rss_en_mask = fbnic_flow_hash_2_rss_en_mask(fbn, hash_idx);

	/* Write IP Match value/mask to action_tcam[0] */
	act_tcam->value.tcam[0] = ip_value;
	act_tcam->mask.tcam[0] = ip_mask;

	/* Write flow type value/mask to action_tcam[1] */
	act_tcam->value.tcam[1] = flow_value;
	act_tcam->mask.tcam[1] = flow_mask;

	/* Write error, DSCP, extra L4 matches to action_tcam[2] */
	act_tcam->value.tcam[2] = misc;
	act_tcam->mask.tcam[2] = misc_mask;

	/* Write source/destination port values */
	act_tcam->value.tcam[3] = sport;
	act_tcam->mask.tcam[3] = sport_mask;
	act_tcam->value.tcam[4] = dport;
	act_tcam->mask.tcam[4] = dport_mask;

	for (j = 5; j < FBNIC_RPC_TCAM_ACT_WORD_LEN; j++)
		act_tcam->mask.tcam[j] = 0xffff;

	act_tcam->state = FBNIC_TCAM_S_UPDATE;

	if (netif_running(fbn->netdev)) {
		fbnic_write_rules(fbd);
		if (ip_src || ip_dst)
			fbnic_write_ip_addr(fbd);
		if (mac_addr)
			fbnic_write_macda(fbd);
	}

	return 0;
}

static void fbnic_clear_nfc_macda(struct fbnic_net *fbn,
				  unsigned int tcam_idx)
{
	struct fbnic_dev *fbd = fbn->fbd;
	int idx;

	for (idx = ARRAY_SIZE(fbd->mac_addr); idx--;)
		__fbnic_xc_unsync(&fbd->mac_addr[idx], tcam_idx);

	/* Write updates to hardware */
	if (netif_running(fbn->netdev))
		fbnic_write_macda(fbd);
}

static void fbnic_clear_nfc_ip_addr(struct fbnic_net *fbn,
				    unsigned int tcam_idx)
{
	struct fbnic_dev *fbd = fbn->fbd;
	int idx;

	for (idx = ARRAY_SIZE(fbd->ip_src); idx--;)
		__fbnic_ip_unsync(&fbd->ip_src[idx], tcam_idx);
	for (idx = ARRAY_SIZE(fbd->ip_dst); idx--;)
		__fbnic_ip_unsync(&fbd->ip_dst[idx], tcam_idx);
	for (idx = ARRAY_SIZE(fbd->ipo_src); idx--;)
		__fbnic_ip_unsync(&fbd->ipo_src[idx], tcam_idx);
	for (idx = ARRAY_SIZE(fbd->ipo_dst); idx--;)
		__fbnic_ip_unsync(&fbd->ipo_dst[idx], tcam_idx);

	/* Write updates to hardware */
	if (netif_running(fbn->netdev))
		fbnic_write_ip_addr(fbd);
}

static int fbnic_set_cls_rule_del(struct fbnic_net *fbn,
				  const struct ethtool_rxnfc *cmd)
{
	struct ethtool_rx_flow_spec *fsp;
	struct fbnic_dev *fbd = fbn->fbd;
	struct fbnic_act_tcam *act_tcam;
	int idx;

	fsp = (struct ethtool_rx_flow_spec *)&cmd->fs;

	if (fsp->location >= FBNIC_RPC_ACT_TBL_NFC_ENTRIES)
		return -EINVAL;

	idx = fsp->location + FBNIC_RPC_ACT_TBL_NFC_OFFSET;
	act_tcam = &fbd->act_tcam[idx];

	if (act_tcam->state != FBNIC_TCAM_S_VALID)
		return -EINVAL;

	act_tcam->state = FBNIC_TCAM_S_DELETE;

	if ((act_tcam->value.tcam[1] & FBNIC_RPC_TCAM_ACT1_L2_MACDA_VALID) &&
	    (~act_tcam->mask.tcam[1] & FBNIC_RPC_TCAM_ACT1_L2_MACDA_IDX))
		fbnic_clear_nfc_macda(fbn, idx);

	if ((act_tcam->value.tcam[0] &
	     (FBNIC_RPC_TCAM_ACT0_IPSRC_VALID |
	      FBNIC_RPC_TCAM_ACT0_IPDST_VALID |
	      FBNIC_RPC_TCAM_ACT0_OUTER_IPSRC_VALID |
	      FBNIC_RPC_TCAM_ACT0_OUTER_IPDST_VALID)) &&
	    (~act_tcam->mask.tcam[0] &
	     (FBNIC_RPC_TCAM_ACT0_IPSRC_IDX |
	      FBNIC_RPC_TCAM_ACT0_IPDST_IDX |
	      FBNIC_RPC_TCAM_ACT0_OUTER_IPSRC_IDX |
	      FBNIC_RPC_TCAM_ACT0_OUTER_IPDST_IDX)))
		fbnic_clear_nfc_ip_addr(fbn, idx);

	if (netif_running(fbn->netdev))
		fbnic_write_rules(fbd);

	return 0;
}

static int fbnic_set_rxnfc(struct net_device *netdev, struct ethtool_rxnfc *cmd)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	int ret = -EOPNOTSUPP;

	switch (cmd->cmd) {
	case ETHTOOL_SRXFH:
		ret = fbnic_set_rss_hash_opts(fbn, cmd);

		break;
	case ETHTOOL_SRXCLSRLINS:
		ret = fbnic_set_cls_rule_ins(fbn, cmd);
		break;
	case ETHTOOL_SRXCLSRLDEL:
		ret = fbnic_set_cls_rule_del(fbn, cmd);
		break;
	}

	return ret;
}

static u32 fbnic_get_rxfh_indir_size(struct net_device *netdev)
{
	return FBNIC_RPC_RSS_TBL_SIZE;
}

static u32 fbnic_get_rxfh_key_size(struct net_device *netdev)
{
	return FBNIC_RPC_RSS_KEY_BYTE_LEN;
}

static int fbnic_get_rxfh(struct net_device *netdev, u32 *indir, u8 *key,
			  u8 *hfunc)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	unsigned int i;

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;

	if (key) {
		for (i = 0; i < FBNIC_RPC_RSS_KEY_BYTE_LEN; i++) {
			u32 rss_key = fbn->rss_key[i / 4] << ((i % 4) * 8);

			key[i] = rss_key >> 24;
		}
	}

	if (indir) {
		for (i = 0; i < FBNIC_RPC_RSS_TBL_SIZE; i++)
			indir[i] = fbn->indir_tbl[0][i];
	}

	return 0;
}

static bool fbnic_indir_set(struct fbnic_net *fbn, int idx, const u32 *indir)
{
	unsigned int i, changes = 0;

	for (i = 0; i < FBNIC_RPC_RSS_TBL_SIZE; i++) {
		if (fbn->indir_tbl[idx][i] == indir[i])
			continue;

		fbn->indir_tbl[idx][i] = indir[i];
		changes++;
	}

	return !!changes;
}

static int fbnic_set_rxfh(struct net_device *netdev, const u32 *indir,
			  const u8 *key, const u8 hfunc)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	unsigned int i, changes = 0;

	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EINVAL;

	if (key) {
		u32 rss_key = 0;

		for (i = FBNIC_RPC_RSS_KEY_BYTE_LEN; i--;) {
			rss_key >>= 8;
			rss_key |= (u32)(key[i]) << 24;

			if (i % 4)
				continue;

			if ((i / 4) == FBNIC_RPC_RSS_KEY_LAST_IDX)
				rss_key &= FBNIC_RPC_RSS_KEY_LAST_MASK;

			if (fbn->rss_key[i / 4] == rss_key)
				continue;

			fbn->rss_key[i / 4] = rss_key;
			changes++;
		}
	}

	if (indir)
		changes += fbnic_indir_set(fbn, 0, indir);

	if (changes && netif_running(netdev))
		fbnic_rss_reinit_hw(fbn->fbd, fbn);

	return 0;
}

static int
fbnic_get_rxfh_context(struct net_device *netdev, u32 *indir, u8 *key,
		       u8 *hfunc, u32 rss_context)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	unsigned int i;

	if (rss_context >= FBNIC_RPC_RSS_TBL_COUNT)
		return -EINVAL;

	if (hfunc)
		*hfunc = ETH_RSS_HASH_TOP;

	if (key) {
		for (i = 0; i < FBNIC_RPC_RSS_KEY_BYTE_LEN; i++) {
			u32 rss_key = fbn->rss_key[i / 4] << ((i % 4) * 8);

			key[i] = rss_key >> 24;
		}
	}

	if (indir) {
		for (i = 0; i < FBNIC_RPC_RSS_TBL_SIZE; i++)
			indir[i] = fbn->indir_tbl[rss_context][i];
	}

	return 0;
}

static int
fbnic_set_rxfh_context(struct net_device *netdev, const u32 *indir,
		       const u8 *key, const u8 hfunc, u32 *rss_context,
		       bool delete)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	unsigned int idx = *rss_context;

	if (hfunc != ETH_RSS_HASH_NO_CHANGE && hfunc != ETH_RSS_HASH_TOP)
		return -EINVAL;

	if (idx >= FBNIC_RPC_RSS_TBL_COUNT)
		return -EINVAL;

	if (key || delete)
		return -EOPNOTSUPP;

	if (indir && fbnic_indir_set(fbn, idx, indir) && netif_running(netdev))
		fbnic_rss_reinit_hw(fbn->fbd, fbn);

	return 0;
}

static int fbnic_get_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *ec,
			      struct kernel_ethtool_coalesce *kernel_coal,
			      struct netlink_ext_ack *extack)
{
	struct fbnic_net *fbn = netdev_priv(netdev);

	ec->use_adaptive_tx_coalesce = fbn->tx_usecs < 0;
	ec->tx_coalesce_usecs = fbn->tx_usecs < 0 ? 0 : fbn->tx_usecs;

	ec->use_adaptive_rx_coalesce = fbn->rx_usecs < 0;
	ec->rx_coalesce_usecs = fbn->rx_usecs < 0 ? 0 : fbn->rx_usecs;

	return 0;
}

static int fbnic_set_coalesce(struct net_device *netdev,
			      struct ethtool_coalesce *ec,
			      struct kernel_ethtool_coalesce *kernel_coal,
			      struct netlink_ext_ack *extack)
{
	u8 mode = DIM_CQ_PERIOD_MODE_START_FROM_EQE;
	struct fbnic_net *fbn = netdev_priv(netdev);
	s16 tx_usec = -1, rx_usec = -1;
	struct fbnic_napi_vector *nv;
	struct dim_cq_moder moder;

	/* verify limits */
	if (ec->rx_coalesce_usecs >
	    FIELD_MAX(FBNIC_INTR_CQ_REARM_RCQ_TIMEOUT) ||
	    ec->tx_coalesce_usecs >
	    FIELD_MAX(FBNIC_INTR_CQ_REARM_TCQ_TIMEOUT))
		return -EINVAL;

	/* record settings */
	if (!ec->use_adaptive_tx_coalesce) {
		fbn->tx_usecs = ec->tx_coalesce_usecs;
		tx_usec = fbn->tx_usecs;
	} else if (fbn->tx_usecs >= 0) {
		moder = net_dim_get_def_tx_moderation(mode);
		tx_usec = moder.usec;
	}

	if (!ec->use_adaptive_rx_coalesce) {
		fbn->rx_usecs = ec->rx_coalesce_usecs;
		rx_usec = fbn->rx_usecs;
	} else if (fbn->rx_usecs >= 0) {
		moder = net_dim_get_def_rx_moderation(mode);
		rx_usec = moder.usec;
	}

	/* This should only occur when there was no change to the config */
	if (tx_usec < 0 && rx_usec < 0)
		return 0;

	/* If we are transitioning into, out of, or from one non-dynamic
	 * interrupt moderation configuration to another we need to update
	 * the moderation registers.
	 */
	if (netif_running(netdev)) {
		struct fbnic_dev *fbd = fbn->fbd;
		u32 val = 0;

		if (rx_usec >= 0)
			val |= FIELD_PREP(FBNIC_INTR_CQ_REARM_RCQ_TIMEOUT,
					  rx_usec) |
			       FBNIC_INTR_CQ_REARM_RCQ_TIMEOUT_UPD_EN;
		if (tx_usec >= 0)
			val |= FIELD_PREP(FBNIC_INTR_CQ_REARM_TCQ_TIMEOUT,
					  tx_usec) |
			       FBNIC_INTR_CQ_REARM_TCQ_TIMEOUT_UPD_EN;

		/* Loop through the napi vectors flushing out any dynamic
		 * interrupt moderation workers that may still be running
		 * and then update the register so that the non-dynamic
		 * bits will be updated.
		 */
		list_for_each_entry(nv, &fbn->napis, napis) {
			flush_work(&nv->tx_dim.work);
			flush_work(&nv->rx_dim.work);
			wr32(FBNIC_INTR_CQ_REARM(nv->v_idx), val);
		}
	}

	/* record adaptive moderation now that the registers are initialized */
	if (ec->use_adaptive_tx_coalesce)
		fbn->tx_usecs = -1;
	if (ec->use_adaptive_rx_coalesce)
		fbn->rx_usecs = -1;

	return 0;
}

static void fbnic_get_pauseparam(struct net_device *netdev,
				 struct ethtool_pauseparam *pause)
{
	struct fbnic_net *fbn = netdev_priv(netdev);

	pause->autoneg = fbn->autoneg_pause;

	pause->rx_pause = fbn->rx_pause;
	pause->tx_pause = fbn->tx_pause;
}

static int fbnic_set_pauseparam(struct net_device *netdev,
				struct ethtool_pauseparam *pause)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;
	const struct fbnic_mac *mac;
	bool rx, tx, autoneg;

	autoneg = !!pause->autoneg;
	rx = !!pause->rx_pause;
	tx = !!pause->tx_pause;

	if (fbn->autoneg_pause == autoneg &&
	    fbn->rx_pause == rx && fbn->tx_pause == tx)
		return 0;

	/* TBD: Record flow control to autoneg flags */

	/* Record values to flow control settings.
	 * If autoneg is enabled set initial values to
	 * enable receiving pause frames and do not transmit them.
	 */
	fbn->autoneg_pause = autoneg;
	fbn->rx_pause = rx | autoneg;
	fbn->tx_pause = tx & !autoneg;

	mac = fbd->mac;

	/* Force pause setting if autoneg is disabled */
	if (!fbn->autoneg_pause)
		mac->config_pause(fbd);
	/* TBD: Enable else case for autoneg reconfig */

	return 0;
}

static int fbnic_get_fecparam(struct net_device *netdev,
			      struct ethtool_fecparam *fecparam)
{
	struct fbnic_net *fbn = netdev_priv(netdev);

	if (fbn->fec & FBNIC_FEC_AUTO)
		fecparam->active_fec |= ETHTOOL_FEC_AUTO;
	if (!(fbn->fec & (FBNIC_FEC_BASER | FBNIC_FEC_RS)))
		fecparam->active_fec = ETHTOOL_FEC_OFF;
	if (fbn->fec & FBNIC_FEC_BASER)
		fecparam->active_fec |= ETHTOOL_FEC_BASER;
	if (fbn->fec & FBNIC_FEC_RS)
		fecparam->active_fec |= ETHTOOL_FEC_RS;

	if (fbn->link_mode & FBNIC_LINK_MODE_PAM4)
		fecparam->fec = ETHTOOL_FEC_AUTO |
				ETHTOOL_FEC_RS;
	else
		fecparam->fec = ETHTOOL_FEC_AUTO |
				ETHTOOL_FEC_OFF |
				ETHTOOL_FEC_RS |
				ETHTOOL_FEC_BASER;

	return 0;
}

static int fbnic_set_fecparam(struct net_device *netdev,
			      struct ethtool_fecparam *fecparam)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;
	const struct fbnic_mac *mac;
	int fec = FBNIC_FEC_OFF;

	/* The auto flag is meant to be used to indicate that the driver
	 * is allowed to select the best config automatically. Specifically
	 * this applies to the PAM4 modes as we must force RS in those modes.
	 */
	if (fecparam->fec & ETHTOOL_FEC_AUTO)
		fec |= FBNIC_FEC_AUTO;

	/* Allow the user to only specify one of the supported modes, so
	 * they can only specify Reed-Solomon, Base-R, or No FEC.
	 */
	switch (fecparam->fec &
		(ETHTOOL_FEC_RS | ETHTOOL_FEC_BASER | ETHTOOL_FEC_OFF)) {
	case ETHTOOL_FEC_RS:
		fec |= FBNIC_FEC_RS;
		break;
	case ETHTOOL_FEC_BASER:
		fec |= FBNIC_FEC_BASER;
		fallthrough;
	case ETHTOOL_FEC_OFF:
		/* Setting is sticky for non-PAM4 modes */
		if (!(fbn->link_mode & FBNIC_LINK_MODE_PAM4))
			break;

		/* PAM4 modes will auto override the value with RS if PAM4
		 * mode is enabled. As such we take no action if auto is
		 * populated since it will already be RS.
		 */
		if (fec & FBNIC_FEC_AUTO)
			break;

		netdev_warn(netdev,
			    "Unsupported FEC param for current link mode\n");
		return -EINVAL;
	default:
		netdev_warn(netdev, "Unsupported FEC mode\n");
		return -EINVAL;
	}

	if (fec == fbn->fec)
		return 0;

	fbn->fec = fec;
	mac = fbd->mac;

	return mac->config_fec(fbd);
}

static void fbnic_get_pause_stats(struct net_device *netdev,
				  struct ethtool_pause_stats *pause_stats)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_mac_stats *mac_stats;
	struct fbnic_dev *fbd = fbn->fbd;
	const struct fbnic_mac *mac;

	mac_stats = &fbd->hw_stats.mac;
	mac = fbd->mac;

	mac->get_pause_stats(fbd, false, &mac_stats->pause);

	pause_stats->tx_pause_frames = mac_stats->pause.tx_pause_frames.value;
	pause_stats->rx_pause_frames = mac_stats->pause.rx_pause_frames.value;
}

static void fbnic_get_fec_stats(struct net_device *netdev,
				struct ethtool_fec_stats *fec_stats)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_mac_stats *mac_stats;
	struct fbnic_dev *fbd = fbn->fbd;
	const struct fbnic_mac *mac;
	int i;

	mac_stats = &fbd->hw_stats.mac;
	mac = fbd->mac;

	mac->get_fec_stats(fbd, false, &mac_stats->fec);

	for (i = 0; i < FBNIC_RSFEC_MAX_LANES; i++) {
		fec_stats->corrected_blocks.lanes[i] =
			mac_stats->fec.corrected_blocks.lanes[i].value;
		fec_stats->uncorrectable_blocks.lanes[i] =
			mac_stats->fec.uncorrectable_blocks.lanes[i].value;
	}

	fec_stats->corrected_blocks.total =
		mac_stats->fec.corrected_blocks.total.value;
	fec_stats->uncorrectable_blocks.total =
		mac_stats->fec.uncorrectable_blocks.total.value;
}

static void fbnic_get_eth_phy_stats(struct net_device *netdev,
				    struct ethtool_eth_phy_stats *phy_stats)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_mac_stats *mac_stats;
	struct fbnic_dev *fbd = fbn->fbd;
	const struct fbnic_mac *mac;
	struct fbnic_fec_stats *fec;
	u64 total = 0;
	int i;

	mac_stats = &fbd->hw_stats.mac;
	mac = fbd->mac;
	fec = &mac_stats->fec;

	mac->get_fec_stats(fbd, false, fec);

	for (i = 0; i < FBNIC_RSFEC_MAX_LANES; i++)
		total += fec->SymbolErrorDuringCarrier.lanes[i].value;

	phy_stats->SymbolErrorDuringCarrier = total;
}

static void
fbnic_get_eth_mac_stats(struct net_device *netdev,
			struct ethtool_eth_mac_stats *eth_mac_stats)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_mac_stats *mac_stats;
	struct fbnic_dev *fbd = fbn->fbd;
	const struct fbnic_mac *mac;

	mac_stats = &fbd->hw_stats.mac;
	mac = fbd->mac;

	mac->get_eth_mac_stats(fbd, false, &mac_stats->eth_mac);

	eth_mac_stats->FramesTransmittedOK =
		mac_stats->eth_mac.FramesTransmittedOK.value;
	eth_mac_stats->FramesReceivedOK =
		mac_stats->eth_mac.FramesReceivedOK.value;
	eth_mac_stats->FrameCheckSequenceErrors =
		mac_stats->eth_mac.FrameCheckSequenceErrors.value;
	eth_mac_stats->AlignmentErrors =
		mac_stats->eth_mac.AlignmentErrors.value;
	eth_mac_stats->OctetsTransmittedOK =
		mac_stats->eth_mac.OctetsTransmittedOK.value;
	eth_mac_stats->FramesLostDueToIntMACXmitError =
		mac_stats->eth_mac.FramesLostDueToIntMACXmitError.value;
	eth_mac_stats->OctetsReceivedOK =
		mac_stats->eth_mac.OctetsReceivedOK.value;
	eth_mac_stats->FramesLostDueToIntMACRcvError =
		mac_stats->eth_mac.FramesLostDueToIntMACRcvError.value;
	eth_mac_stats->MulticastFramesXmittedOK =
		mac_stats->eth_mac.MulticastFramesXmittedOK.value;
	eth_mac_stats->BroadcastFramesXmittedOK =
		mac_stats->eth_mac.BroadcastFramesXmittedOK.value;
	eth_mac_stats->MulticastFramesReceivedOK =
		mac_stats->eth_mac.MulticastFramesReceivedOK.value;
	eth_mac_stats->BroadcastFramesReceivedOK =
		mac_stats->eth_mac.BroadcastFramesReceivedOK.value;
	eth_mac_stats->FrameTooLongErrors =
		mac_stats->eth_mac.FrameTooLongErrors.value;
}

static void
fbnic_get_eth_ctrl_stats(struct net_device *netdev,
			 struct ethtool_eth_ctrl_stats *eth_ctrl_stats)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_mac_stats *mac_stats;
	struct fbnic_dev *fbd = fbn->fbd;
	const struct fbnic_mac *mac;

	mac_stats = &fbd->hw_stats.mac;
	mac = fbd->mac;

	mac->get_eth_ctrl_stats(fbd, false, &mac_stats->eth_ctrl);

	eth_ctrl_stats->MACControlFramesReceived =
		mac_stats->eth_ctrl.MACControlFramesReceived.value;
	eth_ctrl_stats->MACControlFramesTransmitted =
		mac_stats->eth_ctrl.MACControlFramesTransmitted.value;
}

static const struct ethtool_rmon_hist_range fbnic_rmon_ranges[] = {
	{    0,   64 },
	{   65,  127 },
	{  128,  255 },
	{  256,  511 },
	{  512, 1023 },
	{ 1024, 1518 },
	{ 1519, 2047 },
	{ 2048, 4095 },
	{ 4096, 8191 },
	{ 8192, FBNIC_MAX_JUMBO_FRAME_SIZE },
	{}
};

static void
fbnic_get_rmon_stats(struct net_device *netdev,
		     struct ethtool_rmon_stats *rmon_stats,
		     const struct ethtool_rmon_hist_range **ranges)
{
	const struct fbnic_rmon_hist_range *mac_range;
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_mac_stats *mac_stats;
	struct fbnic_dev *fbd = fbn->fbd;
	const struct fbnic_mac *mac;
	int i, j;

	mac_stats = &fbd->hw_stats.mac;
	mac = fbd->mac;

	mac->get_rmon_stats(fbd, false, &mac_stats->rmon);

	rmon_stats->undersize_pkts =
		mac_stats->rmon.undersize_pkts.value;
	rmon_stats->oversize_pkts =
		mac_stats->rmon.oversize_pkts.value;
	rmon_stats->fragments =
		mac_stats->rmon.fragments.value;
	rmon_stats->jabbers =
		mac_stats->rmon.jabbers.value;

	mac_range = mac->rmon_ranges;

	/* The FPGA device hash a much broader set of RMON ranges then the
	 * kernel supports. For this reason what we end up doing is packing
	 * the FPGA ranges into the set of ranges matching the ASIC provided
	 * above since it fits in the ethtool ranges.
	 */
	for (i = 0, j = 0; fbnic_rmon_ranges[i].high; i++) {
		rmon_stats->hist[i] = 0;
		rmon_stats->hist_tx[i] = 0;

		for (; mac_range[j].high; j++) {
			if (mac_range[j].high > fbnic_rmon_ranges[i].high)
				break;

			rmon_stats->hist[i] +=
				mac_stats->rmon.hist[j].value;
			rmon_stats->hist_tx[i] +=
				mac_stats->rmon.hist_tx[j].value;
		}
	}

	*ranges = fbnic_rmon_ranges;
}

static int
fbnic_get_link_ksettings(struct net_device *netdev,
			 struct ethtool_link_ksettings *cmd)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;
	const struct fbnic_mac *mac;

	mac = fbd->mac;
	mac->get_link_settings(fbd, cmd);

	return 0;
}

static int
fbnic_set_link_ksettings(struct net_device *netdev,
			 const struct ethtool_link_ksettings *cmd)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;
	const struct fbnic_mac *mac;

	mac = fbd->mac;
	if (!mac->set_link_settings)
		return -EOPNOTSUPP;

	return mac->set_link_settings(fbd, cmd);
}

static void
fbnic_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *drvinfo)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;

	strscpy(drvinfo->bus_info, dev_name(netdev->dev.parent),
		sizeof(drvinfo->bus_info));
	strscpy(drvinfo->driver, netdev->dev.parent->driver->name,
		sizeof(drvinfo->driver));
	snprintf(drvinfo->version, sizeof(drvinfo->version), UTS_RELEASE);
	if (fbnic_is_asic(fbd)) {
		fbnic_mk_fw_ver_commit_str(fbd, drvinfo->fw_version);
	} else {
		u32 rev_id = rd32(FBNIC_TOP_FPGA_REVISION_ID);

		snprintf(drvinfo->fw_version, sizeof(drvinfo->fw_version),
			 "%02lu.%02lu",
			 FIELD_GET(FBNIC_TOP_FPGA_REVISION_ID_MAJOR, rev_id),
			 FIELD_GET(FBNIC_TOP_FPGA_REVISION_ID_MINOR, rev_id));
	}
}

/**
 * fbnic_set_phys_id - Used to strobe the MAC LEDs in a recognizable pattern
 * @netdev: Interface/port to strobe the LEDs for
 * @phys_id_state: State requested by the call
 *
 * This function can really be broken down into two parts. There are the
 * ACTIVE/INACTIVE states which really are meant to be defining the start
 * and stop of the LED strobing. There is also the ON/OFF states which are
 * used to provide us with a way of telling us that we should be turning
 * the LED on and/or off.
 *
 * We translate these calls and pass them off to the MAC layer. They will
 * be used to initialize a strobe, then on and off will be used to cycle
 * between the patterns, and finally we will restore the original LED state.
 *
 * We will return 2 when we are requested to go active. This will tell the
 * call that it will need to call back to turn on/off the LED twice every
 * second.
 */
static int fbnic_set_phys_id(struct net_device *netdev,
			     enum ethtool_phys_id_state phys_id_state)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;
	const struct fbnic_mac *mac;
	int cycle_interval = 0;
	int state;

	mac = fbd->mac;

	if (!mac || !mac->set_led_state)
		return -EOPNOTSUPP;

	switch (phys_id_state) {
	case ETHTOOL_ID_ACTIVE:
		state = FBNIC_LED_STROBE_INIT;
		cycle_interval = 2;
		break;
	case ETHTOOL_ID_INACTIVE:
		state = FBNIC_LED_RESTORE;
		break;
	case ETHTOOL_ID_ON:
		state = FBNIC_LED_ON;
		break;
	case ETHTOOL_ID_OFF:
		state = FBNIC_LED_OFF;
		break;
	default:
		return -EINVAL;
	}

	mac->set_led_state(fbd, state);

	return cycle_interval;
}

static int fbnic_get_eeprom_len(struct net_device *netdev)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_dev *fbd = fbn->fbd;

	return fbd->mac->eeprom_len;
}

static int fbnic_get_eeprom(struct net_device *netdev,
			    struct ethtool_eeprom *eeprom, u8 *data)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_fw_completion *fw_cmpl;
	struct fbnic_dev *fbd = fbn->fbd;
	int err = 0, retries = 5;
	u32 offset, length;

	if (eeprom->len == 0)
		return -EINVAL;

	offset = eeprom->offset;
	length = eeprom->len;

	fw_cmpl = kzalloc(sizeof(*fw_cmpl), GFP_KERNEL);
	if (!fw_cmpl)
		return -ENOMEM;

	/* Initialize completion and queue it for FW to process */
	fw_cmpl->msg_type = FBNIC_TLV_MSG_ID_EEPROM_READ_RESP;
	fw_cmpl->eeprom.data = data;
	fw_cmpl->eeprom.size = length;
	fw_cmpl->eeprom.offset = offset;
	init_completion(&fw_cmpl->done);

	err = fbnic_fw_xmit_eeprom_read_msg(fbd, fw_cmpl, offset, length);
	if (err) {
		dev_err(fbd->dev,
			"Failed to transmit EEPROM read msg, err %d\n",
			err);
		goto cmpl_free;
	}

	/* Allow 2 seconds for reply, resend and try up to 5 times */
	while (!wait_for_completion_timeout(&fw_cmpl->done, 2 * HZ)) {
		retries--;

		if (retries == 0) {
			dev_err(fbd->dev,
				"Timed out waiting on EEPROM read\n");
			err = -ETIMEDOUT;
			goto cmpl_cleanup;
		}

		err = fbnic_fw_xmit_eeprom_read_msg(fbd, NULL, offset, length);
		if (err) {
			dev_err(fbd->dev,
				"Failed to transmit EEPROM read msg, err %d\n",
				err);
			goto cmpl_cleanup;
		}
	}

	/* Handle error returned by firmware */
	if (fw_cmpl->result) {
		err = fw_cmpl->result;
		dev_err(fbd->dev, "%s: Firmware returned error %d\n",
			__func__, err);
		dev_err(fbd->dev, "%s: Length: %d Offset: %d\n",
			__func__, length, offset);
	}

cmpl_cleanup:
	fbd->cmpl_data = NULL;
cmpl_free:
	kfree(fw_cmpl);

	return err;
}

static int fbnic_set_eeprom(struct net_device *netdev,
			    struct ethtool_eeprom *eeprom, u8 *data)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_fw_completion *fw_cmpl;
	struct fbnic_dev *fbd = fbn->fbd;
	int err = 0, retries = 5;
	struct pci_dev *pdev;
	u32 offset, length;

	if (eeprom->len == 0)
		return -EINVAL;

	pdev = to_pci_dev(fbd->dev);
	if (eeprom->magic != (pdev->vendor | pdev->device << 16)) {
		netdev_err(netdev, "Bad magic value %#10X\n", eeprom->magic);
		return -EINVAL;
	}

	offset = eeprom->offset;
	length = eeprom->len;

	fw_cmpl = kzalloc(sizeof(*fw_cmpl), GFP_KERNEL);
	if (!fw_cmpl)
		return -ENOMEM;

	/* Initialize completion and queue it for FW to process */
	fw_cmpl->msg_type = FBNIC_TLV_MSG_ID_EEPROM_WRITE_RESP;
	fw_cmpl->eeprom.size = length;
	fw_cmpl->eeprom.offset = offset;
	init_completion(&fw_cmpl->done);

	err = fbnic_fw_xmit_eeprom_write_msg(fbd, fw_cmpl,
					     offset, length, data);
	if (err) {
		dev_err(fbd->dev,
			"Failed to transmit EEPROM read msg, err %d\n",
			err);
		goto cmpl_free;
	}

	/* Allow 2 seconds for reply, resend and try up to 5 times */
	while (!wait_for_completion_timeout(&fw_cmpl->done, 2 * HZ)) {
		retries--;

		if (retries == 0) {
			dev_err(fbd->dev,
				"Timed out waiting on EEPROM read\n");
			err = -ETIMEDOUT;
			goto cmpl_cleanup;
		}

		err = fbnic_fw_xmit_eeprom_write_msg(fbd, fw_cmpl,
						     offset, length, data);
		if (err) {
			dev_err(fbd->dev,
				"Failed to transmit EEPROM read msg, err %d\n",
				err);
			goto cmpl_cleanup;
		}
	}

	/* Handle error returned by firmware */
	if (fw_cmpl->result) {
		err = fw_cmpl->result;
		dev_err(fbd->dev, "%s: Firmware returned error %d\n",
			__func__, err);
		dev_err(fbd->dev, "%s: Length: %d Offset: %d\n",
			__func__, length, offset);
	}

cmpl_cleanup:
	fbd->cmpl_data = NULL;
cmpl_free:
	kfree(fw_cmpl);

	return err;
}

static int __fbnic_get_module_eeprom(struct net_device *netdev,
				     u32 size, u32 offset, u8 page, u8 bank,
				     u8 *data)
{
	struct fbnic_net *fbn = netdev_priv(netdev);
	struct fbnic_fw_completion *fw_cmpl;
	struct fbnic_dev *fbd = fbn->fbd;
	int err = 0, retries = 5;

	/* Nothing to do if read size is 0 */
	if (size == 0)
		return 0;

	/* Limit reads to current page only, truncate the size to fit
	 * current page only
	 */
	if (offset < 128 && (offset + size) > 128)
		size = 128 - offset;

	/* If page or bank are set we are in paged mode, only support
	 * offsets greater than 128
	 */
	if ((page || bank) && offset < 128)
		return -EINVAL;
	if (offset + size > 256)
		return -EINVAL;

	fw_cmpl = kzalloc(sizeof(*fw_cmpl), GFP_KERNEL);
	if (!fw_cmpl)
		return -ENOMEM;

	/* Initialize completion and queue it for FW to process */
	fw_cmpl->msg_type = FBNIC_TLV_MSG_ID_QSFP_READ_RESP;
	fw_cmpl->qsfp.data = data;
	fw_cmpl->qsfp.size = size;
	fw_cmpl->qsfp.offset = offset;
	fw_cmpl->qsfp.page = page;
	fw_cmpl->qsfp.bank = bank;
	init_completion(&fw_cmpl->done);

	err = fbnic_fw_xmit_qsfp_read_msg(fbd, fw_cmpl, page, bank,
					  offset, size);
	if (err) {
		dev_err(fbd->dev,
			"Failed to transmit EEPROM read msg, err %d\n",
			err);
		goto cmpl_free;
	}

	/* Allow 2 seconds for reply, resend and try up to 5 times */
	while (!wait_for_completion_timeout(&fw_cmpl->done, 2 * HZ)) {
		retries--;

		if (retries == 0) {
			dev_err(fbd->dev,
				"Timed out waiting on EEPROM read\n");
			err = -ETIMEDOUT;
			goto cmpl_cleanup;
		}

		err = fbnic_fw_xmit_qsfp_read_msg(fbd, NULL, page, bank,
						  offset, size);
		if (err) {
			dev_err(fbd->dev,
				"Failed to transmit EEPROM read msg, err %d\n",
				err);
			goto cmpl_cleanup;
		}
	}

	/* Handle error returned by firmware */
	if (fw_cmpl->result) {
		err = fw_cmpl->result;
		dev_err(fbd->dev, "%s: Firmware returned error %d\n",
			__func__, err);
		dev_err(fbd->dev, "%s: Page: %d Bank: %d Offset: %d Size: %d\n",
			__func__, page, bank, offset, size);
	}

cmpl_cleanup:
	fbd->cmpl_data = NULL;
cmpl_free:
	kfree(fw_cmpl);

	return err ? : size;
}

#define FBNIC_QSFP_TYPE_QSFP_PLUS	0x0D
#define FBNIC_QSFP_TYPE_QSFP28		0x11
#define FBNIC_QSFP_TYPE_QSFP_DD		0x18
#define FBNIC_QSFP_FLAG_FLAT_MEM	0x80
static int fbnic_get_module_info(struct net_device *netdev,
				 struct ethtool_modinfo *modinfo)
{
	u8 data[4] = { 0 };
	int err;

	err = __fbnic_get_module_eeprom(netdev, 4, 0, 0, 0, data);
	if (err < 4)
		return -EIO;

	if (data[0] != FBNIC_QSFP_TYPE_QSFP_PLUS &&
	    data[0] != FBNIC_QSFP_TYPE_QSFP28 &&
	    data[0] != FBNIC_QSFP_TYPE_QSFP_DD) {
		netdev_err(netdev, "%s: cable type not recognized:0x%x\n",
			   __func__, data[0]);
		return -EINVAL;
	}

	modinfo->type = ETH_MODULE_SFF_8636;
	modinfo->eeprom_len = (data[2] & FBNIC_QSFP_FLAG_FLAT_MEM) ?
			      ETH_MODULE_SFF_8636_LEN :
			      ETH_MODULE_SFF_8636_MAX_LEN;

	return 0;
}

static int fbnic_get_module_eeprom(struct net_device *netdev,
				   struct ethtool_eeprom *ee,
				   u8 *data)
{
	u32 offset = ee->offset, size = ee->len;

	while (size) {
		int read = __fbnic_get_module_eeprom(netdev, size, offset,
						     0, 0, data);

		if (read < 0)
			return read;

		size -= read;
		offset += read;
	}

	return 0;
}

static int
fbnic_get_module_eeprom_by_page(struct net_device *netdev,
				const struct ethtool_module_eeprom *page_data,
				struct netlink_ext_ack *extack)
{
	/* We only support i2c address of 0x50 for QSFP cages */
	if (page_data->i2c_address != 0x50)
		return -EINVAL;

	/* Since all reads  are a single page we should
	 * be able to complete this in a single read.
	 */
	return __fbnic_get_module_eeprom(netdev,
					 page_data->length,
					 page_data->offset,
					 page_data->page,
					 page_data->bank,
					 page_data->data);
}

static const struct ethtool_ops fbnic_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				     ETHTOOL_COALESCE_USE_ADAPTIVE,
	.get_ethtool_stats	= fbnic_get_ethtool_stats,
	.get_link		= ethtool_op_get_link,
	.get_msglevel		= fbnic_get_msglevel,
	.get_regs		= fbnic_get_regs,
	.get_regs_len		= fbnic_get_regs_len,
	.get_ringparam		= fbnic_get_ringparam,
	.set_ringparam		= fbnic_set_ringparam,
	.get_sset_count		= fbnic_get_sset_count,
	.get_strings		= fbnic_get_strings,
	.self_test		= fbnic_self_test,
	.set_msglevel		= fbnic_set_msglevel,
	.get_channels		= fbnic_get_channels,
	.set_channels		= fbnic_set_channels,
	.get_ts_info		= fbnic_get_ts_info,
	.get_rxnfc		= fbnic_get_rxnfc,
	.set_rxnfc		= fbnic_set_rxnfc,
	.get_rxfh_indir_size	= fbnic_get_rxfh_indir_size,
	.get_rxfh_key_size	= fbnic_get_rxfh_key_size,
	.get_rxfh		= fbnic_get_rxfh,
	.set_rxfh		= fbnic_set_rxfh,
	.get_rxfh_context	= fbnic_get_rxfh_context,
	.set_rxfh_context	= fbnic_set_rxfh_context,
	.get_coalesce		= fbnic_get_coalesce,
	.set_coalesce		= fbnic_set_coalesce,
	.get_pauseparam		= fbnic_get_pauseparam,
	.set_pauseparam		= fbnic_set_pauseparam,
	.get_fecparam		= fbnic_get_fecparam,
	.set_fecparam		= fbnic_set_fecparam,
	.get_pause_stats	= fbnic_get_pause_stats,
	.get_fec_stats		= fbnic_get_fec_stats,
	.get_eth_phy_stats	= fbnic_get_eth_phy_stats,
	.get_eth_mac_stats	= fbnic_get_eth_mac_stats,
	.get_eth_ctrl_stats	= fbnic_get_eth_ctrl_stats,
	.get_rmon_stats		= fbnic_get_rmon_stats,
	.get_link_ksettings	= fbnic_get_link_ksettings,
	.set_link_ksettings	= fbnic_set_link_ksettings,
	.get_drvinfo		= fbnic_get_drvinfo,
	.set_phys_id		= fbnic_set_phys_id,
	.get_eeprom_len		= fbnic_get_eeprom_len,
	.get_eeprom		= fbnic_get_eeprom,
	.set_eeprom		= fbnic_set_eeprom,
	.get_module_info	= fbnic_get_module_info,
	.get_module_eeprom	= fbnic_get_module_eeprom,
	.get_module_eeprom_by_page = fbnic_get_module_eeprom_by_page,
};

void fbnic_set_ethtool_ops(struct net_device *dev)
{
	dev->ethtool_ops = &fbnic_ethtool_ops;
}
