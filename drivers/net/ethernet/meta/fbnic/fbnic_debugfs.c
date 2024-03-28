// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <linux/bitfield.h>
#include <linux/debugfs.h>
#include <linux/pci.h>
#include <linux/seq_file.h>

#include "fbnic.h"
#include "fbnic_fw.h"
#include "fbnic_csr.h"
#include "fbnic_netdev.h"
#include "fbnic_txrx.h"

static struct dentry *fbnic_dbg_root;

/* Descriptor Seq Functions */

static void fbnic_dbg_desc_break(struct seq_file *s, int i)
{
	while (i--)
		seq_putc(s, '-');

	seq_putc(s, '\n');
}

static void fbnic_dbg_ring_show(struct seq_file *s)
{
	struct fbnic_ring *ring = s->private;
	unsigned long doorbell_offset;
	u32 head = 0, tail = 0;
	u32 __iomem *csr_base;

	csr_base = fbnic_ring_csr_base(ring);
	doorbell_offset = ring->doorbell - csr_base;

	seq_printf(s, "doorbell CSR: %#05lx q_idx: %d\n",
		   doorbell_offset, ring->q_idx);
	seq_printf(s, "size_mask: %#06x size: %zu flags: 0x%02x\n",
		   ring->size_mask, ring->size, ring->flags);
	seq_printf(s, "SW: head: %#06x tail: %#06x\n",
		   ring->head, ring->tail);

	switch (doorbell_offset) {
	case FBNIC_QUEUE_TWQ0_TAIL:
		tail = readl(csr_base + FBNIC_QUEUE_TWQ0_PTRS);
		head = FIELD_GET(FBNIC_QUEUE_TWQ_PTRS_HEAD_MASK, tail);
		break;
	case FBNIC_QUEUE_TWQ1_TAIL:
		tail = readl(csr_base + FBNIC_QUEUE_TWQ1_PTRS);
		head = FIELD_GET(FBNIC_QUEUE_TWQ_PTRS_HEAD_MASK, tail);
		break;
	case FBNIC_QUEUE_TCQ_HEAD:
		head = readl(csr_base + FBNIC_QUEUE_TCQ_PTRS);
		tail = FIELD_GET(FBNIC_QUEUE_TCQ_PTRS_TAIL_MASK, head);
		break;
	case FBNIC_QUEUE_BDQ_HPQ_TAIL:
		tail = readl(csr_base + FBNIC_QUEUE_BDQ_HPQ_PTRS);
		head = FIELD_GET(FBNIC_QUEUE_BDQ_PTRS_HEAD_MASK, tail);
		break;
	case FBNIC_QUEUE_BDQ_PPQ_TAIL:
		tail = readl(csr_base + FBNIC_QUEUE_BDQ_PPQ_PTRS);
		head = FIELD_GET(FBNIC_QUEUE_BDQ_PTRS_HEAD_MASK, tail);
		break;
	case FBNIC_QUEUE_RCQ_HEAD:
		head = readl(csr_base + FBNIC_QUEUE_RCQ_PTRS);
		tail = FIELD_GET(FBNIC_QUEUE_RCQ_PTRS_TAIL_MASK, head);
		break;
	}

	tail &= FBNIC_QUEUE_BDQ_PTRS_TAIL_MASK;
	head &= FBNIC_QUEUE_RCQ_PTRS_HEAD_MASK;

	seq_printf(s, "HW: head: %#06x tail: %#06x\n", head, tail);

	seq_puts(s, "\n");
}

static void fbnic_dbg_twd_desc_seq_show(struct seq_file *s, int i)
{
	struct fbnic_ring *ring = s->private;
	u64 twd = le64_to_cpu(ring->desc[i]);

	switch (FIELD_GET(FBNIC_TWD_TYPE_MASK, twd)) {
	case FBNIC_TWD_TYPE_META:
		seq_printf(s, "%04x %#06llx  %llx %llx %llx %llx %llx %#llx %#llx %llx %#04llx %#04llx %llx %#04llx\n",
			   i, FIELD_GET(FBNIC_TWD_LEN_MASK, twd),
			   FIELD_GET(FBNIC_TWD_TYPE_MASK, twd),
			   FIELD_GET(FBNIC_TWD_FLAG_REQ_COMPLETION, twd),
			   FIELD_GET(FBNIC_TWD_FLAG_REQ_CSO, twd),
			   FIELD_GET(FBNIC_TWD_FLAG_REQ_LSO, twd),
			   FIELD_GET(FBNIC_TWD_FLAG_REQ_TS, twd),
			   FIELD_GET(FBNIC_TWD_L4_HLEN_MASK, twd),
			   FIELD_GET(FBNIC_TWD_CSUM_OFFSET_MASK, twd),
			   FIELD_GET(FBNIC_TWD_L4_TYPE_MASK, twd),
			   FIELD_GET(FBNIC_TWD_L3_IHLEN_MASK, twd),
			   FIELD_GET(FBNIC_TWD_L3_OHLEN_MASK, twd),
			   FIELD_GET(FBNIC_TWD_L3_TYPE_MASK, twd),
			   FIELD_GET(FBNIC_TWD_L2_HLEN_MASK, twd));
		break;
	default:
		seq_printf(s, "%04x %#06llx  %llx %#014llx\n", i,
			   FIELD_GET(FBNIC_TWD_LEN_MASK, twd),
			   FIELD_GET(FBNIC_TWD_TYPE_MASK, twd),
			   FIELD_GET(FBNIC_TWD_ADDR_MASK, twd));
		break;
	}
}

static int fbnic_dbg_twq_desc_seq_show(struct seq_file *s, void *v)
{
	/* TBD format header of display string */
	static const char desc_hdr[] =
		"DESC LEN/MSS T METADATA/TIMESTAMP/BUFFER_ADDR\n";
	struct fbnic_ring *ring = s->private;
	int i;

	/* Generate header on first entry */
	fbnic_dbg_ring_show(s);
	seq_printf(s, desc_hdr);
	fbnic_dbg_desc_break(s, sizeof(desc_hdr) - 1);

	/* Display descriptor */
	if (!ring->desc) {
		seq_puts(s, "Descriptor ring not allocated.\n");
		return 0;
	}

	for (i = 0; i <= ring->size_mask; i++)
		fbnic_dbg_twd_desc_seq_show(s, i);

	return 0;
}

static int fbnic_dbg_tcq_desc_seq_show(struct seq_file *s, void *v)
{
	/* TBD format header of display string */
	static const char desc_hdr[] =
		"DESC D T Q STATUS TIMESTAMP     HEAD1 HEAD0\n";
	struct fbnic_ring *ring = s->private;
	int i;

	/* Generate header on first entry */
	fbnic_dbg_ring_show(s);
	seq_puts(s, desc_hdr);
	fbnic_dbg_desc_break(s, sizeof(desc_hdr) - 1);

	/* Display descriptor */
	if (!ring->desc) {
		seq_puts(s, "Descriptor ring not allocated.\n");
		return 0;
	}

	for (i = 0; i <= ring->size_mask; i++) {
		u64 tcd = le64_to_cpu(ring->desc[i]);

		switch (FIELD_GET(FBNIC_TCD_TYPE_MASK, tcd)) {
		case FBNIC_TCD_TYPE_0:
			seq_printf(s, "%04x %llx %llx %llx %#05llx          %#06llx  %#06llx\n",
				   i, FIELD_GET(FBNIC_TCD_DONE, tcd),
				   FIELD_GET(FBNIC_TCD_TYPE_MASK, tcd),
				   FIELD_GET(FBNIC_TCD_TWQ1, tcd),
				   FIELD_GET(FBNIC_TCD_STATUS_MASK, tcd),
				   FIELD_GET(FBNIC_TCD_TYPE0_HEAD1_MASK, tcd),
				   FIELD_GET(FBNIC_TCD_TYPE0_HEAD0_MASK, tcd));
			break;
		case FBNIC_TCD_TYPE_1:
			seq_printf(s, "%04x %llx %llx %llx %#05llx  %#012llx\n",
				   i, FIELD_GET(FBNIC_TCD_DONE, tcd),
				   FIELD_GET(FBNIC_TCD_TYPE_MASK, tcd),
				   FIELD_GET(FBNIC_TCD_TWQ1, tcd),
				   FIELD_GET(FBNIC_TCD_STATUS_MASK, tcd),
				   FIELD_GET(FBNIC_TCD_TYPE1_TS_MASK, tcd));
			break;
		default:
			break;
		}
	}

	return 0;
}

static int fbnic_dbg_bdq_desc_seq_show(struct seq_file *s, void *v)
{
	/* TBD format header of display string */
	static const char desc_hdr[] = "DESC ID   BUFFER_ADDR\n";
	struct fbnic_ring *ring = s->private;
	int i;

	/* Generate header on first entry */
	fbnic_dbg_ring_show(s);
	seq_printf(s, desc_hdr);
	fbnic_dbg_desc_break(s, sizeof(desc_hdr) - 1);

	/* Display descriptor */
	if (!ring->desc) {
		seq_puts(s, "Descriptor ring not allocated.\n");
		return 0;
	}

	for (i = 0; i <= ring->size_mask; i++) {
		u64 bd = le64_to_cpu(ring->desc[i]);

		seq_printf(s, "%04x %#04llx %#014llx\n", i,
			   FIELD_GET(FBNIC_BD_PAGE_ID_MASK, bd),
			   FIELD_GET(FBNIC_BD_PAGE_ADDR_MASK, bd));
	}

	return 0;
}

static void fbnic_dbg_rcd_desc_seq_show(struct seq_file *s, int i)
{
	struct fbnic_ring *ring = s->private;
	u64 rcd = le64_to_cpu(ring->desc[i]);

	switch (FIELD_GET(FBNIC_RCD_TYPE_MASK, rcd)) {
	case FBNIC_RCD_TYPE_HDR_AL:
	case FBNIC_RCD_TYPE_PAY_AL:
		seq_printf(s, "%04x %llx %llx %llx %#06llx      %#06llx   %#06llx\n",
			   i, FIELD_GET(FBNIC_RCD_DONE, rcd),
			   FIELD_GET(FBNIC_RCD_TYPE_MASK, rcd),
			   FIELD_GET(FBNIC_RCD_AL_PAGE_FIN, rcd),
			   FIELD_GET(FBNIC_RCD_AL_BUFF_OFF_MASK, rcd),
			   FIELD_GET(FBNIC_RCD_AL_BUFF_LEN_MASK, rcd),
			   FIELD_GET(FBNIC_RCD_AL_BUFF_ID_MASK, rcd));
		break;
	case FBNIC_RCD_TYPE_OPT_META:
		seq_printf(s, "%04x %llx %llx %llx %llx %llx      %#06llx   %#012llx\n",
			   i, FIELD_GET(FBNIC_RCD_DONE, rcd),
			   FIELD_GET(FBNIC_RCD_TYPE_MASK, rcd),
			   FIELD_GET(FBNIC_RCD_OPT_META_TYPE_MASK, rcd),
			   FIELD_GET(FBNIC_RCD_OPT_META_TS, rcd),
			   FIELD_GET(FBNIC_RCD_OPT_META_ACTION, rcd),
			   FIELD_GET(FBNIC_RCD_OPT_META_ACTION_MASK, rcd),
			   FIELD_GET(FBNIC_RCD_OPT_META_TS_MASK, rcd));
		break;
	case FBNIC_RCD_TYPE_META:
		seq_printf(s, "%04x %llx %llx %llx %llx %llx %llx %llx %llx %llx %#06llx   %#010llx\n",
			   i, FIELD_GET(FBNIC_RCD_DONE, rcd),
			   FIELD_GET(FBNIC_RCD_TYPE_MASK, rcd),
			   FIELD_GET(FBNIC_RCD_META_ECN, rcd),
			   FIELD_GET(FBNIC_RCD_META_L4_CSUM_UNNECESSARY, rcd),
			   FIELD_GET(FBNIC_RCD_META_ERR_MAC_EOP, rcd),
			   FIELD_GET(FBNIC_RCD_META_ERR_TRUNCATED_FRAME, rcd),
			   FIELD_GET(FBNIC_RCD_META_ERR_PARSER, rcd),
			   FIELD_GET(FBNIC_RCD_META_L4_TYPE_MASK, rcd),
			   FIELD_GET(FBNIC_RCD_META_L3_TYPE_MASK, rcd),
			   FIELD_GET(FBNIC_RCD_META_L2_CSUM_MASK, rcd),
			   FIELD_GET(FBNIC_RCD_META_RSS_HASH_MASK, rcd));
		break;
	}
}

static int fbnic_dbg_rcq_desc_seq_show(struct seq_file *s, void *v)
{
	/* TBD format header of display string */
	static const char desc_hdr[] =
		"           OFFSET/ L L\n"
		"DESC D T F C M T P 4 3 LEN/CSUM ID/TS/RSS\n";
	struct fbnic_ring *ring = s->private;
	int i;

	/* Generate header on first entry */
	fbnic_dbg_ring_show(s);
	seq_puts(s, desc_hdr);
	fbnic_dbg_desc_break(s, sizeof(desc_hdr) - 1);

	/* Display descriptor */
	if (!ring->desc) {
		seq_puts(s, "Descriptor ring not allocated.\n");
		return 0;
	}

	for (i = 0; i <= ring->size_mask; i++)
		fbnic_dbg_rcd_desc_seq_show(s, i);

	return 0;
}

static int fbnic_dbg_desc_open(struct inode *inode, struct file *file)
{
	struct fbnic_ring *ring = inode->i_private;
	int (*show)(struct seq_file *s, void *v);

	switch (ring->doorbell - fbnic_ring_csr_base(ring)) {
	case FBNIC_QUEUE_TWQ0_TAIL:
	case FBNIC_QUEUE_TWQ1_TAIL:
		show = fbnic_dbg_twq_desc_seq_show;
		break;
	case FBNIC_QUEUE_TCQ_HEAD:
		show = fbnic_dbg_tcq_desc_seq_show;
		break;
	case FBNIC_QUEUE_BDQ_HPQ_TAIL:
	case FBNIC_QUEUE_BDQ_PPQ_TAIL:
		show = fbnic_dbg_bdq_desc_seq_show;
		break;
	case FBNIC_QUEUE_RCQ_HEAD:
		show = fbnic_dbg_rcq_desc_seq_show;
		break;
	default:
		return -EINVAL;
	}

	return single_open(file, show, ring);
}

static const struct file_operations fbnic_dbg_desc_fops = {
	.owner		= THIS_MODULE,
	.open		= fbnic_dbg_desc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

void fbnic_dbg_nv_init(struct fbnic_napi_vector *nv)
{
	struct fbnic_dev *fbd = nv->fbd;
	char name[16];
	int i, j;

	/* Generate a folder for each napi vector */
	snprintf(name, sizeof(name), "nv.%03d", nv->v_idx);

	nv->dbg_nv = debugfs_create_dir(name, fbd->dbg_fbd);

	/* Generate a file for each Tx ring in the napi vector */
	for (i = 0; i < nv->txt_count; i++) {
		struct fbnic_q_triad *qt = &nv->qt[i];
		unsigned int hw_idx;

		hw_idx = fbnic_ring_csr_base(&qt->cmpl) -
			  &fbd->uc_addr0[FBNIC_QUEUE(0)];
		hw_idx /= FBNIC_QUEUE_STRIDE;

		snprintf(name, sizeof(name), "twq0.%03d", hw_idx);
		debugfs_create_file(name, 0400, nv->dbg_nv, &qt->sub0,
				    &fbnic_dbg_desc_fops);

		snprintf(name, sizeof(name), "twq1.%03d", hw_idx);
		debugfs_create_file(name, 0400, nv->dbg_nv, &qt->sub1,
				    &fbnic_dbg_desc_fops);

		snprintf(name, sizeof(name), "tcq.%03d", hw_idx);
		debugfs_create_file(name, 0400, nv->dbg_nv, &qt->cmpl,
				    &fbnic_dbg_desc_fops);
	}

	/* Generate a file for each Rx ring in the napi vector */
	for (j = 0; j < nv->rxt_count; j++, i++) {
		struct fbnic_q_triad *qt = &nv->qt[i];
		unsigned int hw_idx;

		hw_idx = fbnic_ring_csr_base(&qt->cmpl) -
			  &fbd->uc_addr0[FBNIC_QUEUE(0)];
		hw_idx /= FBNIC_QUEUE_STRIDE;

		snprintf(name, sizeof(name), "hpq.%03d", hw_idx);
		debugfs_create_file(name, 0400, nv->dbg_nv, &qt->sub0,
				    &fbnic_dbg_desc_fops);

		snprintf(name, sizeof(name), "ppq.%03d", hw_idx);
		debugfs_create_file(name, 0400, nv->dbg_nv, &qt->sub1,
				    &fbnic_dbg_desc_fops);

		snprintf(name, sizeof(name), "rcq.%03d", hw_idx);
		debugfs_create_file(name, 0400, nv->dbg_nv, &qt->cmpl,
				    &fbnic_dbg_desc_fops);
	}
}

void fbnic_dbg_nv_exit(struct fbnic_napi_vector *nv)
{
	debugfs_remove_recursive(nv->dbg_nv);
	nv->dbg_nv = NULL;
}

static int fbnic_dbg_mac_addr_show(struct seq_file *s, void *v)
{
	/* TBD format header of display string */
	static const char mac_addr_hdr[] =
		"Idx S TCAM Bitmap       Addr/Mask\n";
	struct fbnic_dev *fbd = s->private;
	int i;

	/* Generate Header */
	seq_puts(s, mac_addr_hdr);
	fbnic_dbg_desc_break(s, sizeof(mac_addr_hdr) - 1);

	for (i = 0; i < FBNIC_RPC_TCAM_MACDA_NUM_ENTRIES; i++) {
		struct fbnic_mac_addr *mac_addr = &fbd->mac_addr[i];

		seq_printf(s, "%02d  %d %64pb %pm\n",
			   i, mac_addr->state, mac_addr->act_tcam,
			   mac_addr->value.addr8);
		seq_printf(s, "                        %pm\n",
			   mac_addr->mask.addr8);
	}

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(fbnic_dbg_mac_addr);

static int fbnic_dbg_tce_tcam_show(struct seq_file *s, void *v)
{
	/* TBD format header of display string */
	static const char tce_tcam_hdr[] =
		"Idx S TCAM Bitmap       Addr/Mask\n";
	struct fbnic_dev *fbd = s->private;
	int i, tcam_idx = 0;

	/* Generate Header */
	seq_puts(s, tce_tcam_hdr);
	fbnic_dbg_desc_break(s, sizeof(tce_tcam_hdr) - 1);

	for (i = 0; i < ARRAY_SIZE(fbd->mac_addr); i++) {
		struct fbnic_mac_addr *mac_addr = &fbd->mac_addr[i];

		/* Verify BMC bit is set */
		if (!test_bit(FBNIC_MAC_ADDR_T_BMC, mac_addr->act_tcam))
			continue;

		if (tcam_idx == FBNIC_TCE_TCAM_NUM_ENTRIES)
			break;

		seq_printf(s, "%02d  %d %64pb %pm\n",
			   tcam_idx, mac_addr->state, mac_addr->act_tcam,
			   mac_addr->value.addr8);
		seq_printf(s, "                        %pm\n",
			   mac_addr->mask.addr8);
		tcam_idx++;
	}

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(fbnic_dbg_tce_tcam);

#define fbnic_mac_stat_show(__member)					\
do {									\
	struct fbnic_stat_counter *__stat = &mac_stats->__member;	\
	seq_printf(s, "  %s: %llu\n", #__member, __stat->value);	\
} while (0)

static int fbnic_dbg_mac_stats_show(struct seq_file *s, void *v)
{
	/* TBD format header of display string */
	static const char mac_stats_hdr[] = "MAC Statistics:\n";
	u64 corrected_blocks, uncorrectable_blocks;
	const struct fbnic_rmon_hist_range *ranges;
	struct fbnic_eth_ctrl_stats *ctrl_stats;
	struct fbnic_pause_stats *pause_stats;
	struct fbnic_eth_mac_stats *mac_stats;
	struct fbnic_rmon_stats *rmon_stats;
	struct fbnic_dev *fbd = s->private;
	struct fbnic_fec_stats *fec_stats;
	int i;

	/* Generate Header */
	seq_puts(s, mac_stats_hdr);

	fbnic_get_mac_stats(fbd);

	pause_stats = &fbd->hw_stats.mac.pause;
	seq_printf(s, "  PAUSEMACCtrlFramesTransmitted: %llu\n",
		   pause_stats->tx_pause_frames.value);
	seq_printf(s, "  PAUSEMACCtrlFramesReceived: %llu\n",
		   pause_stats->rx_pause_frames.value);

	fec_stats = &fbd->hw_stats.mac.fec;
	corrected_blocks = fec_stats->corrected_blocks.total.value;
	for (i = 0; i < FBNIC_RSFEC_MAX_LANES; i++) {
		seq_printf(s, "  FECCorrectedBlocks[%d]: %llu\n",
			   i, fec_stats->corrected_blocks.lanes[i].value);
		corrected_blocks +=
			fec_stats->corrected_blocks.lanes[i].value;
	}
	seq_printf(s, "  FECCorrectedBlocks: %llu\n",
		   corrected_blocks);

	uncorrectable_blocks = fec_stats->uncorrectable_blocks.total.value;
	for (i = 0; i < FBNIC_RSFEC_MAX_LANES; i++) {
		seq_printf(s, "  FECUncorrectedBlocks[%d]: %llu\n",
			   i, fec_stats->uncorrectable_blocks.lanes[i].value);
		uncorrectable_blocks +=
			fec_stats->uncorrectable_blocks.lanes[i].value;
	}
	seq_printf(s, "  FECUncorrectableBlocks: %llu\n",
		   uncorrectable_blocks);

	mac_stats = &fbd->hw_stats.mac.eth_mac;
	fbnic_mac_stat_show(FramesTransmittedOK);
	fbnic_mac_stat_show(OctetsTransmittedOK);
	fbnic_mac_stat_show(MulticastFramesXmittedOK);
	fbnic_mac_stat_show(BroadcastFramesXmittedOK);
	fbnic_mac_stat_show(FramesLostDueToIntMACXmitError);
	fbnic_mac_stat_show(FramesReceivedOK);
	fbnic_mac_stat_show(OctetsReceivedOK);
	fbnic_mac_stat_show(MulticastFramesReceivedOK);
	fbnic_mac_stat_show(BroadcastFramesReceivedOK);
	fbnic_mac_stat_show(FrameCheckSequenceErrors);
	fbnic_mac_stat_show(FrameTooLongErrors);
	fbnic_mac_stat_show(FramesLostDueToIntMACRcvError);

	ctrl_stats = &fbd->hw_stats.mac.eth_ctrl;
	seq_printf(s, "  MACControlFramesTransmitted: %llu\n",
		   ctrl_stats->MACControlFramesTransmitted.value);
	seq_printf(s, "  MACControlFramesReceived: %llu\n",
		   ctrl_stats->MACControlFramesReceived.value);

	rmon_stats = &fbd->hw_stats.mac.rmon;
	seq_printf(s, "  etherStatsUndersizePkts: %llu\n",
		   rmon_stats->undersize_pkts.value);
	seq_printf(s, "  etherStatsOversizePkts: %llu\n",
		   rmon_stats->oversize_pkts.value);
	seq_printf(s, "  etherStatsFragments: %llu\n",
		   rmon_stats->fragments.value);
	seq_printf(s, "  etherStatsJabbers: %llu\n",
		   rmon_stats->jabbers.value);

	ranges = fbd->mac->rmon_ranges;
	for (i = 0; i < FBNIC_RMON_HIST_MAX && ranges[i].high; i++) {
		if (!ranges[i].low) {
			seq_printf(s, "  etherStatsPkts%dOctets: %llu\n",
				   ranges[i].high,
				   rmon_stats->hist[i].value);
			continue;
		}
		seq_printf(s, "  etherStatsPkts%dto%dOctets: %llu\n",
			   ranges[i].low, ranges[i].high,
			   rmon_stats->hist[i].value);
	}
	for (i = 0; i < FBNIC_RMON_HIST_MAX && ranges[i].high; i++) {
		if (!ranges[i].low) {
			seq_printf(s, "  etherStatsTxPkts%dOctets: %llu\n",
				   ranges[i].high,
				   rmon_stats->hist_tx[i].value);
			continue;
		}
		seq_printf(s, "  etherStatsTxPkts%dto%dOctets: %llu\n",
			   ranges[i].low, ranges[i].high,
			   rmon_stats->hist_tx[i].value);
	}

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(fbnic_dbg_mac_stats);

#define ACT_TCAM_HDR "Idx S Value/Mask                                              RSS  Dest\n"

static int fbnic_dbg_act_tcam_show(struct seq_file *s, void *v)
{
	const char act_tcam_hdr[] = ACT_TCAM_HDR;
	struct fbnic_dev *fbd = s->private;
	int i;

	/* Generate Header */
	seq_puts(s, act_tcam_hdr);
	fbnic_dbg_desc_break(s, sizeof(act_tcam_hdr) - 1);

	for (i = 0; i < FBNIC_RPC_TCAM_ACT_NUM_ENTRIES; i++) {
		struct fbnic_act_tcam *act_tcam = &fbd->act_tcam[i];

		seq_printf(s, "%02d  %d %04x %04x %04x %04x %04x %04x %04x %04x %04x %04x %04x  %04x %08x\n",
			   i, act_tcam->state,
			   act_tcam->value.tcam[10], act_tcam->value.tcam[9],
			   act_tcam->value.tcam[8], act_tcam->value.tcam[7],
			   act_tcam->value.tcam[6], act_tcam->value.tcam[5],
			   act_tcam->value.tcam[4], act_tcam->value.tcam[3],
			   act_tcam->value.tcam[2], act_tcam->value.tcam[1],
			   act_tcam->value.tcam[0], act_tcam->rss_en_mask,
			   act_tcam->dest);
		seq_printf(s, "      %04x %04x %04x %04x %04x %04x %04x %04x %04x %04x %04x\n",
			   act_tcam->mask.tcam[10], act_tcam->mask.tcam[9],
			   act_tcam->mask.tcam[8], act_tcam->mask.tcam[7],
			   act_tcam->mask.tcam[6], act_tcam->mask.tcam[5],
			   act_tcam->mask.tcam[4], act_tcam->mask.tcam[3],
			   act_tcam->mask.tcam[2], act_tcam->mask.tcam[1],
			   act_tcam->mask.tcam[0]);
	}

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(fbnic_dbg_act_tcam);

static int fbnic_dbg_ip_addr_show(struct seq_file *s,
				  struct fbnic_ip_addr *ip_addr)
{
	/* TBD format header of display string */
	static const char ip_addr_hdr[] =
		"Idx S TCAM Bitmap       V Addr/Mask\n";
	int i;

	/* Generate Header */
	seq_puts(s, ip_addr_hdr);
	fbnic_dbg_desc_break(s, sizeof(ip_addr_hdr) - 1);

	for (i = 0; i < FBNIC_RPC_TCAM_IP_ADDR_NUM_ENTRIES; i++, ip_addr++) {
		seq_printf(s, "%02d  %d %64pb %d %pi6\n",
			   i, ip_addr->state, ip_addr->act_tcam,
			   ip_addr->version, &ip_addr->value);
		seq_printf(s, "                          %pi6\n",
			   &ip_addr->mask);
	}

	return 0;
}

static int fbnic_dbg_ip_src_show(struct seq_file *s, void *v)
{
	struct fbnic_dev *fbd = s->private;

	return fbnic_dbg_ip_addr_show(s, fbd->ip_src);
}

DEFINE_SHOW_ATTRIBUTE(fbnic_dbg_ip_src);

static int fbnic_dbg_ip_dst_show(struct seq_file *s, void *v)
{
	struct fbnic_dev *fbd = s->private;

	return fbnic_dbg_ip_addr_show(s, fbd->ip_dst);
}

DEFINE_SHOW_ATTRIBUTE(fbnic_dbg_ip_dst);

static int fbnic_dbg_ipo_src_show(struct seq_file *s, void *v)
{
	struct fbnic_dev *fbd = s->private;

	return fbnic_dbg_ip_addr_show(s, fbd->ipo_src);
}

DEFINE_SHOW_ATTRIBUTE(fbnic_dbg_ipo_src);

static int fbnic_dbg_ipo_dst_show(struct seq_file *s, void *v)
{
	struct fbnic_dev *fbd = s->private;

	return fbnic_dbg_ip_addr_show(s, fbd->ipo_dst);
}

DEFINE_SHOW_ATTRIBUTE(fbnic_dbg_ipo_dst);

static int fbnic_dbg_bmc_present_show(struct seq_file *s, void *v)
{
	struct fbnic_dev *fbd = s->private;

	seq_printf(s, "%u\n", fbnic_bmc_present(fbd));

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(fbnic_dbg_bmc_present);

#define FW_MBX_HDR "Idx Len  E  Addr        F H   Raw\n"

static void fbnic_dbg_fw_mbx_display(struct seq_file *s,
				     struct fbnic_dev *fbd, int mbx_idx)
{
	static const char * const fw_mbx_names[] = { "Rx\n", "Tx\n" };
	struct fbnic_fw_mbx *mbx = &fbd->mbx[mbx_idx];
	const char fw_mbx_hdr[] = FW_MBX_HDR;
	int i;

	seq_puts(s, fw_mbx_names[mbx_idx]);

	seq_printf(s, "Rdy: %d Head: %d Tail: %d\n",
		   mbx->ready, mbx->head, mbx->tail);
	seq_printf(s, "alloc_failed: %lld mapping_error: %lld parser_error: %lld\n",
		   mbx->alloc_failed, mbx->mapping_error, mbx->parser_error);

	seq_puts(s, fw_mbx_hdr);
	fbnic_dbg_desc_break(s, sizeof(fw_mbx_hdr) - 1);

	for (i = 0; i < FBNIC_IPC_MBX_DESC_LEN; i++) {
		u64 desc = __fbnic_mbx_rd_desc(fbd, mbx_idx, i);

		seq_printf(s, "%02d  %04lld %d %012llx %d %d   %016llx\n",
			   i, FIELD_GET(FBNIC_IPC_MBX_DESC_LEN_MASK, desc),
			   !!(desc & FBNIC_IPC_MBX_DESC_EOM),
			   desc & FBNIC_IPC_MBX_DESC_ADDR_MASK,
			   !!(desc & FBNIC_IPC_MBX_DESC_FW_CMPL),
			   !!(desc & FBNIC_IPC_MBX_DESC_HOST_CMPL),
			   desc);
	}
}

static int fbnic_dbg_fw_mbx_show(struct seq_file *s, void *v)
{
	struct fbnic_dev *fbd = s->private;

	/* Generate Header */
	fbnic_dbg_fw_mbx_display(s, fbd, FBNIC_IPC_MBX_RX_IDX);

	/* Add blank line between Rx and Tx */
	seq_puts(s, "\n");

	/* Generate Header */
	fbnic_dbg_fw_mbx_display(s, fbd, FBNIC_IPC_MBX_TX_IDX);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(fbnic_dbg_fw_mbx);

static int fbnic_dbg_fw_log_show(struct seq_file *s, void *v)
{
	struct fbnic_dev *fbd = s->private;
	struct fbnic_fw_log *log = &fbd->fw_log;
	struct fbnic_fw_log_entry *entry;

	if (!log->data_start)
		return 0;

	list_for_each_entry_reverse(entry, &log->entries, list) {
		seq_printf(s, "[%lld] %s\n", entry->index, entry->msg);
	}

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(fbnic_dbg_fw_log);

void fbnic_dbg_fbd_init(struct fbnic_dev *fbd)
{
	struct pci_dev *pdev = to_pci_dev(fbd->dev);
	const char *name = pci_name(pdev);

	fbd->dbg_fbd = debugfs_create_dir(name, fbnic_dbg_root);
	debugfs_create_file("mac_addr", 0400, fbd->dbg_fbd, fbd,
			    &fbnic_dbg_mac_addr_fops);
	debugfs_create_file("tce_tcam", 0400, fbd->dbg_fbd, fbd,
			    &fbnic_dbg_tce_tcam_fops);
	debugfs_create_file("mac_stats", 0400, fbd->dbg_fbd, fbd,
			    &fbnic_dbg_mac_stats_fops);
	debugfs_create_file("act_tcam", 0400, fbd->dbg_fbd, fbd,
			    &fbnic_dbg_act_tcam_fops);
	debugfs_create_file("ip_src", 0400, fbd->dbg_fbd, fbd,
			    &fbnic_dbg_ip_src_fops);
	debugfs_create_file("ip_dst", 0400, fbd->dbg_fbd, fbd,
			    &fbnic_dbg_ip_dst_fops);
	debugfs_create_file("ipo_src", 0400, fbd->dbg_fbd, fbd,
			    &fbnic_dbg_ipo_src_fops);
	debugfs_create_file("ipo_dst", 0400, fbd->dbg_fbd, fbd,
			    &fbnic_dbg_ipo_dst_fops);
	debugfs_create_file("bmc_present", 0400, fbd->dbg_fbd, fbd,
			    &fbnic_dbg_bmc_present_fops);
	debugfs_create_file("fw_mbx", 0400, fbd->dbg_fbd, fbd,
			    &fbnic_dbg_fw_mbx_fops);
	debugfs_create_file("fw_log", 0400, fbd->dbg_fbd, fbd,
			    &fbnic_dbg_fw_log_fops);
}

void fbnic_dbg_fbd_exit(struct fbnic_dev *fbd)
{
	debugfs_remove_recursive(fbd->dbg_fbd);
	fbd->dbg_fbd = NULL;
}

void fbnic_dbg_fbn_init(struct fbnic_net *fbn)
{
	fbn->dbg_fbn = debugfs_create_dir("fbn", fbn->fbd->dbg_fbd);
}

void fbnic_dbg_fbn_exit(struct fbnic_net *fbn)
{
	debugfs_remove_recursive(fbn->dbg_fbn);
	fbn->dbg_fbn = NULL;
}

void fbnic_dbg_init(void)
{
	fbnic_dbg_root = debugfs_create_dir(fbnic_driver_name, NULL);
}

void fbnic_dbg_exit(void)
{
	debugfs_remove_recursive(fbnic_dbg_root);
	fbnic_dbg_root = NULL;
}
