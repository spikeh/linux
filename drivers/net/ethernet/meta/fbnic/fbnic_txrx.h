/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#ifndef _FBNIC_TXRX_H_
#define _FBNIC_TXRX_H_

#include <linux/dim.h>
#include <linux/list.h>
#include <linux/log2.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/u64_stats_sync.h>

struct fbnic_net;

/* Guarantee we have space needed for storing the buffer
 * To store the buffer we need:
 *	1 descriptor per page
 *	+ 1 descriptor for skb head
 *	+ 2 descriptors for metadata and optional metadata
 *	+ 7 descriptors to keep tail out of the same cachline as head
 * If we cannot guarantee that then we should return TX_BUSY
 */
#define FBNIC_MAX_SKB_DESC	(MAX_SKB_FRAGS + 10)
#define FBNIC_TX_DESC_WAKEUP	(FBNIC_MAX_SKB_DESC * 2)
#define FBNIC_TX_DESC_MIN	roundup_pow_of_two(FBNIC_TX_DESC_WAKEUP)

#define FBNIC_MAX_RX_PKT_DESC	6
#define FBNIC_RX_DESC_MIN	roundup_pow_of_two(FBNIC_MAX_RX_PKT_DESC * 2)

#define FBNIC_MAX_TXQS			128u
#define FBNIC_MAX_XDPQS			128u
#define FBNIC_MAX_RXQS			128u
#define FBNIC_MAX_NAPI_VECTORS		128u

/* These apply to all queues, TWQs, TCQ, HPQ, PPQ, RCQ */
#define FBNIC_QUEUE_SIZE_MIN		16UL
#define FBNIC_QUEUE_SIZE_MAX		SZ_64K

#define FBNIC_TXQ_SIZE_DEFAULT		1024
#define FBNIC_HPQ_SIZE_DEFAULT		256
#define FBNIC_PPQ_SIZE_DEFAULT		256
#define FBNIC_RCQ_SIZE_DEFAULT		1024

#define FBNIC_RX_TROOM \
	SKB_DATA_ALIGN(sizeof(struct skb_shared_info))
#define FBNIC_RX_HROOM \
	(ALIGN(FBNIC_RX_TROOM + NET_SKB_PAD, 128) - FBNIC_RX_TROOM)
#define FBNIC_RX_PAD			0
#define FBNIC_RX_MAX_HDR		(1536 - FBNIC_RX_PAD)
#define FBNIC_RX_PAYLD_OFFSET		0
#define FBNIC_RX_PAYLD_PG_CL		0

#define FBNIC_RING_F_DISABLED		BIT(0)
#define FBNIC_RING_F_CTX		BIT(1)
#define FBNIC_RING_F_STATS		BIT(2)	/* ring's stats may be used */
#define FBNIC_RING_F_EDT		BIT(3)	/* Earliest Departure Time */

struct fbnic_xdp_buff {
	struct xdp_buff buff;
	ktime_t hwtstamp;
	u32 data_truesize;
	u16 data_len;
	u16 nr_frags;
};

struct fbnic_queue_stats {
	u64 packets;
	u64 bytes;
	union {
		struct {
			u64 csum_partial;
			u64 lso;
			u64 restart;
			u64 wake;
			u64 busy;
		} twq;
		struct {
			u64 alloc_failed;
			u64 csum_complete;
			u64 csum_none;
		} rx;
	};
	u64 dropped;
	struct u64_stats_sync syncp;
};

#define PAGECNT_BIAS_MAX	USHRT_MAX
struct fbnic_rx_buf {
	struct page *page;
	unsigned int pagecnt_bias;
};

struct fbnic_ring {
	/* Pointer to buffer specific info */
	union {
		struct fbnic_xdp_buff *xdp;	/* RCQ */
		struct fbnic_rx_buf *rx_buf;	/* BDQ */
		void **tx_buf;			/* TWQ */
		void *buffer;			/* Generic pointer */
	};

	u32 __iomem *doorbell;		/* pointer to CSR space for ring */
	__le64 *desc;			/* descriptor ring memory */
	u16 size_mask;			/* size of ring in descriptors - 1 */
	u8 q_idx;			/* logical netdev ring index */
	u8 flags;			/* ring flags (FBNIC_RING_F_*) */

	u32 head, tail;			/* head/tail of ring */

	struct fbnic_queue_stats stats;

	/* slow path fields follow */
	dma_addr_t dma;			/* phys addr of descriptor memory */
	size_t size;			/* size of descriptor ring in memory */
	struct fbnic_ring *rplc;	/* replacement ring used during recfg */
};

struct fbnic_q_triad {
	struct xdp_rxq_info xdp_rxq;
	struct fbnic_ring sub0, sub1, cmpl;
};

struct fbnic_napi_vector {
	struct napi_struct napi;
	struct device *dev;		/* Device for DMA unmapping */
	struct page_pool *page_pool;
	struct fbnic_dev *fbd;
	struct dentry *dbg_nv;
	char name[IFNAMSIZ + 9];

	u16 v_idx;
	u8 txt_count;
	u8 rxt_count;

	struct list_head napis;

	struct dim tx_dim;
	u16 dim_tx_sample_count;
	s16 dim_prev_tx_idx;

	struct dim rx_dim;
	u16 dim_rx_sample_count;
	s16 dim_prev_rx_idx;

	struct fbnic_q_triad qt[];
};

netdev_tx_t fbnic_xmit_frame_ring(struct sk_buff *skb, struct fbnic_ring *ring);
netdev_tx_t fbnic_xmit_frame(struct sk_buff *skb, struct net_device *dev);
netdev_features_t
fbnic_features_check(struct sk_buff *skb, struct net_device *dev,
		     netdev_features_t features);
int fbnic_alloc_napi_vectors(struct fbnic_net *fbn);
void fbnic_aggregate_ring_rx_counters(struct fbnic_net *fbn,
				      struct fbnic_ring *rxr);
void fbnic_aggregate_ring_tx_counters(struct fbnic_net *fbn,
				      struct fbnic_ring *txr);
void fbnic_free_napi_vectors(struct fbnic_net *fbn);
void fbnic_free_resources(struct fbnic_net *fbn);
int fbnic_alloc_resources(struct fbnic_net *fbn);
void fbnic_napi_disable(struct fbnic_net *fbn);
void fbnic_napi_enable(struct fbnic_net *fbn);
void fbnic_disable(struct fbnic_net *fbn);
void fbnic_config_drop_mode(struct fbnic_net *fbn);
void fbnic_enable(struct fbnic_net *fbn);
void fbnic_dbg_up(struct fbnic_net *fbn);
void fbnic_dbg_down(struct fbnic_net *fbn);
void fbnic_flush(struct fbnic_net *fbn);
void fbnic_fill(struct fbnic_net *fbn);
u32 __iomem *fbnic_ring_csr_base(const struct fbnic_ring *ring);
void fbnic_napi_depletion_check(struct net_device *netdev);
int fbnic_wait_all_queues_idle(struct fbnic_dev *fbd, bool may_fail);

int fbnic_rplc_alloc_rings(struct fbnic_net *orig, struct fbnic_net *clone);
void fbnic_rplc_free_rings(struct fbnic_net *orig);
void fbnic_rplc_swap_rings(struct fbnic_net *orig);

void fbnic_clean_tcq(struct fbnic_napi_vector *nv, struct fbnic_q_triad *qt,
		     int napi_budget);
void fbnic_clean_bdq(struct fbnic_napi_vector *nv, int napi_budget,
		     struct fbnic_ring *ring, unsigned int hw_head);
void fbnic_fill_bdq(struct fbnic_napi_vector *nv, struct fbnic_ring *bdq);

#endif /* _FBNIC_TXRX_H_ */
