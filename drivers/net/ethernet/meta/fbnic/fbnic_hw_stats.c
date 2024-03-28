// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include "fbnic.h"

u64 fbnic_stat_rd64(struct fbnic_dev *fbd, u32 reg, u32 offset)
{
	u32 prev_upper, upper, lower, diff;

	prev_upper = fbnic_rd32(fbd, reg + offset);
	lower = fbnic_rd32(fbd, reg);
	upper = fbnic_rd32(fbd, reg + offset);

	diff = upper - prev_upper;
	if (!diff)
		return ((u64)upper << 32) | lower;

	if (diff > 1)
		dev_warn_once(fbd->dev,
			      "Stats inconsistent, upper 32b of %#010x updating too quickly\n",
			      reg * 4);

	/* Return only the upper bits as we cannot guarantee
	 * the accuracy of the lower bits. We will add them in
	 * when the counter slows down enough that we can get
	 * a snapshot with both upper values being the same
	 * between reads.
	 */
	return ((u64)upper << 32);
}

static void fbnic_hw_stat_rst32(struct fbnic_dev *fbd, u32 reg,
				struct fbnic_stat_counter *stat)
{
	/* We do not touch the "value" field here.
	 * It gets zeroed out on fbd structure allocation.
	 * After that we want it to grow continuously
	 * through device resets and power state changes.
	 */
	stat->u.old_reg_value_32 = fbnic_rd32(fbd, reg);
}

static void fbnic_hw_stat_rst64(struct fbnic_dev *fbd, u32 reg, u32 offset,
				struct fbnic_stat_counter *stat)
{
	stat->u.old_reg_value_64 = fbnic_stat_rd64(fbd, reg, offset);
}

static void fbnic_reset_tti_stats(struct fbnic_dev *fbd,
				  struct fbnic_tti_stats *tti)
{
	fbnic_hw_stat_rst32(fbd,
			    FBNIC_TCE_TTI_CM_DROP_PKTS,
			    &tti->cm_drop.frames);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_TCE_TTI_CM_DROP_BYTE_L,
			    1,
			    &tti->cm_drop.bytes);

	fbnic_hw_stat_rst32(fbd,
			    FBNIC_TCE_TTI_FRAME_DROP_PKTS,
			    &tti->frame_drop.frames);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_TCE_TTI_FRAME_DROP_BYTE_L,
			    1,
			    &tti->frame_drop.bytes);

	fbnic_hw_stat_rst32(fbd,
			    FBNIC_TCE_TBI_DROP_PKTS,
			    &tti->tbi_drop.frames);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_TCE_TBI_DROP_BYTE_L,
			    1,
			    &tti->tbi_drop.bytes);
}

static void fbnic_hw_stat_rd32(struct fbnic_dev *fbd, u32 reg,
			       struct fbnic_stat_counter *stat)
{
	u32 new_reg_value;

	new_reg_value = fbnic_rd32(fbd, reg);
	stat->value += new_reg_value - stat->u.old_reg_value_32;
	stat->u.old_reg_value_32 = new_reg_value;
}

static void fbnic_get_tti_stats32(struct fbnic_dev *fbd,
				  struct fbnic_tti_stats *tti)
{
	fbnic_hw_stat_rd32(fbd,
			   FBNIC_TCE_TTI_CM_DROP_PKTS,
			   &tti->cm_drop.frames);

	fbnic_hw_stat_rd32(fbd,
			   FBNIC_TCE_TTI_FRAME_DROP_PKTS,
			   &tti->frame_drop.frames);

	fbnic_hw_stat_rd32(fbd,
			   FBNIC_TCE_TBI_DROP_PKTS,
			   &tti->tbi_drop.frames);
}

static void fbnic_hw_stat_rd64(struct fbnic_dev *fbd, u32 reg, u32 offset,
			       struct fbnic_stat_counter *stat)
{
	u64 new_reg_value;

	new_reg_value = fbnic_stat_rd64(fbd, reg, offset);
	stat->value += new_reg_value - stat->u.old_reg_value_64;
	stat->u.old_reg_value_64 = new_reg_value;
}

static void fbnic_get_tti_stats(struct fbnic_dev *fbd,
				struct fbnic_tti_stats *tti)
{
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_TCE_TTI_CM_DROP_BYTE_L,
			   1,
			   &tti->cm_drop.bytes);

	fbnic_hw_stat_rd64(fbd,
			   FBNIC_TCE_TTI_FRAME_DROP_BYTE_L,
			   1,
			   &tti->frame_drop.bytes);

	fbnic_hw_stat_rd64(fbd,
			   FBNIC_TCE_TBI_DROP_BYTE_L,
			   1,
			   &tti->tbi_drop.bytes);

	fbnic_get_tti_stats32(fbd, tti);
}

static void fbnic_reset_tmi_stats(struct fbnic_dev *fbd,
				  struct fbnic_tmi_stats *tmi)
{
	fbnic_hw_stat_rst32(fbd, FBNIC_TMI_DROP_PKTS, &tmi->drop.frames);
	fbnic_hw_stat_rst64(fbd, FBNIC_TMI_DROP_BYTE_L, 1, &tmi->drop.bytes);

	fbnic_hw_stat_rst32(fbd,
			    FBNIC_TMI_ILLEGAL_PTP_REQS,
			    &tmi->ptp_illegal_req);
	fbnic_hw_stat_rst32(fbd, FBNIC_TMI_GOOD_PTP_TS, &tmi->ptp_good_ts);
	fbnic_hw_stat_rst32(fbd, FBNIC_TMI_BAD_PTP_TS, &tmi->ptp_bad_ts);
}

static void fbnic_get_tmi_stats32(struct fbnic_dev *fbd,
				  struct fbnic_tmi_stats *tmi)
{
	fbnic_hw_stat_rd32(fbd, FBNIC_TMI_DROP_PKTS, &tmi->drop.frames);

	fbnic_hw_stat_rd32(fbd,
			   FBNIC_TMI_ILLEGAL_PTP_REQS,
			   &tmi->ptp_illegal_req);
	fbnic_hw_stat_rd32(fbd, FBNIC_TMI_GOOD_PTP_TS, &tmi->ptp_good_ts);
	fbnic_hw_stat_rd32(fbd, FBNIC_TMI_BAD_PTP_TS, &tmi->ptp_bad_ts);
}

static void fbnic_get_tmi_stats(struct fbnic_dev *fbd,
				struct fbnic_tmi_stats *tmi)
{
	fbnic_hw_stat_rd64(fbd, FBNIC_TMI_DROP_BYTE_L, 1, &tmi->drop.bytes);
	fbnic_get_tmi_stats32(fbd, tmi);
}

static void fbnic_reset_rxb_fifo_stats(struct fbnic_dev *fbd, int i,
				       struct fbnic_rxb_fifo_stats *fifo)
{
	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_DROP_FRMS_STS(i),
			    &fifo->drop.frames);
	fbnic_hw_stat_rst64(fbd, FBNIC_RXB_DROP_BYTES_STS_L(i), 1,
			    &fifo->drop.bytes);

	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_TRUN_FRMS_STS(i),
			    &fifo->trunc.frames);
	fbnic_hw_stat_rst64(fbd, FBNIC_RXB_TRUN_BYTES_STS_L(i), 1,
			    &fifo->trunc.bytes);

	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_TRANS_PAUSE_STS(i),
			    &fifo->trans_pause);
	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_TRANS_DROP_STS(i),
			    &fifo->trans_drop);
	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_TRANS_ECN_STS(i),
			    &fifo->trans_ecn);

	fifo->level.u.old_reg_value_32 = 0;
}

static void fbnic_reset_rxb_enq_stats(struct fbnic_dev *fbd, int i,
				      struct fbnic_rxb_enqueue_stats *enq)
{
	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_DRBO_FRM_CNT_SRC(i),
			    &enq->drbo.frames);
	fbnic_hw_stat_rst64(fbd, FBNIC_RXB_DRBO_BYTE_CNT_SRC_L(i), 4,
			    &enq->drbo.bytes);

	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_PAUSE_EVENT_CNT(i),
			    &enq->pause);

	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_INTEGRITY_ERR(i),
			    &enq->integrity_err);
	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_MAC_ERR(i),
			    &enq->mac_err);
	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_PARSER_ERR(i),
			    &enq->parser_err);
	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_FRM_ERR(i),
			    &enq->frm_err);
}

static void fbnic_reset_rxb_deq_stats(struct fbnic_dev *fbd, int i,
				      struct fbnic_rxb_dequeue_stats *deq)
{
	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_INTF_FRM_CNT_DST(i),
			    &deq->intf.frames);
	fbnic_hw_stat_rst64(fbd, FBNIC_RXB_INTF_BYTE_CNT_DST_L(i), 4,
			    &deq->intf.bytes);

	fbnic_hw_stat_rst32(fbd, FBNIC_RXB_PBUF_FRM_CNT_DST(i),
			    &deq->pbuf.frames);
	fbnic_hw_stat_rst64(fbd, FBNIC_RXB_PBUF_BYTE_CNT_DST_L(i), 4,
			    &deq->pbuf.bytes);
}

static void fbnic_reset_rxb_stats(struct fbnic_dev *fbd,
				  struct fbnic_rxb_stats *rxb)
{
	int i;

	for (i = 0; i < 8; i++)
		fbnic_reset_rxb_fifo_stats(fbd, i, &rxb->fifo[i]);

	for (i = 0; i < 4; i++) {
		fbnic_reset_rxb_enq_stats(fbd, i, &rxb->enq[i]);
		fbnic_reset_rxb_deq_stats(fbd, i, &rxb->deq[i]);
	}
}

static void fbnic_get_rxb_fifo_stats32(struct fbnic_dev *fbd, int i,
				       struct fbnic_rxb_fifo_stats *fifo)
{
	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_DROP_FRMS_STS(i),
			   &fifo->drop.frames);
	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_TRUN_FRMS_STS(i),
			   &fifo->trunc.frames);

	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_TRANS_PAUSE_STS(i),
			   &fifo->trans_pause);
	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_TRANS_DROP_STS(i),
			   &fifo->trans_drop);
	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_TRANS_ECN_STS(i),
			   &fifo->trans_ecn);

	fifo->level.value = fbnic_rd32(fbd, FBNIC_RXB_PBUF_FIFO_LEVEL(i));
}

static void fbnic_get_rxb_fifo_stats(struct fbnic_dev *fbd, int i,
				     struct fbnic_rxb_fifo_stats *fifo)
{
	fbnic_hw_stat_rd64(fbd, FBNIC_RXB_DROP_BYTES_STS_L(i), 1,
			   &fifo->drop.bytes);
	fbnic_hw_stat_rd64(fbd, FBNIC_RXB_TRUN_BYTES_STS_L(i), 1,
			   &fifo->trunc.bytes);

	fbnic_get_rxb_fifo_stats32(fbd, i, fifo);
}

static void fbnic_get_rxb_enq_stats32(struct fbnic_dev *fbd, int i,
				      struct fbnic_rxb_enqueue_stats *enq)
{
	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_DRBO_FRM_CNT_SRC(i),
			   &enq->drbo.frames);

	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_PAUSE_EVENT_CNT(i),
			   &enq->pause);

	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_INTEGRITY_ERR(i),
			   &enq->integrity_err);
	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_MAC_ERR(i),
			   &enq->mac_err);
	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_PARSER_ERR(i),
			   &enq->parser_err);
	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_FRM_ERR(i),
			   &enq->frm_err);
}

static void fbnic_get_rxb_enq_stats(struct fbnic_dev *fbd, int i,
				    struct fbnic_rxb_enqueue_stats *enq)
{
	fbnic_hw_stat_rd64(fbd, FBNIC_RXB_DRBO_BYTE_CNT_SRC_L(i), 4,
			   &enq->drbo.bytes);

	fbnic_get_rxb_enq_stats32(fbd, i, enq);
}

static void fbnic_get_rxb_deq_stats32(struct fbnic_dev *fbd, int i,
				      struct fbnic_rxb_dequeue_stats *deq)
{
	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_INTF_FRM_CNT_DST(i),
			   &deq->intf.frames);
	fbnic_hw_stat_rd32(fbd, FBNIC_RXB_PBUF_FRM_CNT_DST(i),
			   &deq->pbuf.frames);
}

static void fbnic_get_rxb_deq_stats(struct fbnic_dev *fbd, int i,
				    struct fbnic_rxb_dequeue_stats *deq)
{
	fbnic_hw_stat_rd64(fbd, FBNIC_RXB_INTF_BYTE_CNT_DST_L(i), 4,
			   &deq->intf.bytes);
	fbnic_hw_stat_rd64(fbd, FBNIC_RXB_PBUF_BYTE_CNT_DST_L(i), 4,
			   &deq->pbuf.bytes);

	fbnic_get_rxb_deq_stats32(fbd, i, deq);
}

static void fbnic_get_rxb_stats32(struct fbnic_dev *fbd,
				  struct fbnic_rxb_stats *rxb)
{
	int i;

	for (i = 0; i < 8; i++)
		fbnic_get_rxb_fifo_stats32(fbd, i, &rxb->fifo[i]);

	for (i = 0; i < 4; i++) {
		fbnic_get_rxb_enq_stats32(fbd, i, &rxb->enq[i]);
		fbnic_get_rxb_deq_stats32(fbd, i, &rxb->deq[i]);
	}
}

static void fbnic_get_rxb_stats(struct fbnic_dev *fbd,
				struct fbnic_rxb_stats *rxb)
{
	int i;

	for (i = 0; i < 8; i++)
		fbnic_get_rxb_fifo_stats(fbd, i, &rxb->fifo[i]);

	for (i = 0; i < 4; i++) {
		fbnic_get_rxb_enq_stats(fbd, i, &rxb->enq[i]);
		fbnic_get_rxb_deq_stats(fbd, i, &rxb->deq[i]);
	}
}

static void fbnic_reset_rpc_stats(struct fbnic_dev *fbd,
				  struct fbnic_rpc_stats *rpc)
{
	int i;

	fbnic_hw_stat_rst32(fbd,
			    FBNIC_RPC_CNTR_UNKN_ETYPE,
			    &rpc->unkn_etype);
	fbnic_hw_stat_rst32(fbd,
			    FBNIC_RPC_CNTR_UNKN_EXT_HDR,
			    &rpc->unkn_ext_hdr);

	fbnic_hw_stat_rst32(fbd, FBNIC_RPC_CNTR_IPV4_FRAG, &rpc->ipv4_frag);
	fbnic_hw_stat_rst32(fbd, FBNIC_RPC_CNTR_IPV6_FRAG, &rpc->ipv6_frag);

	fbnic_hw_stat_rst32(fbd, FBNIC_RPC_CNTR_IPV4_ESP, &rpc->ipv4_esp);
	fbnic_hw_stat_rst32(fbd, FBNIC_RPC_CNTR_IPV6_ESP, &rpc->ipv6_esp);

	fbnic_hw_stat_rst32(fbd, FBNIC_RPC_CNTR_TCP_OPT_ERR, &rpc->tcp_opt_err);
	fbnic_hw_stat_rst32(fbd,
			    FBNIC_RPC_CNTR_OUT_OF_HDR_ERR,
			    &rpc->out_of_hdr_err);
	fbnic_hw_stat_rst32(fbd,
			    FBNIC_RPC_CNTR_OVR_SIZE_ERR,
			    &rpc->ovr_size_err);

	for (i = 0; i < 32; i++)
		fbnic_hw_stat_rst32(fbd,
				    FBNIC_RPC_TCAM_MACDA_HIT_CNT(i),
				    &rpc->macda_hit[i]);
	fbnic_hw_stat_rst32(fbd,
			    FBNIC_RPC_TCAM_MACDA_MISS_CNT,
			    &rpc->macda_miss);

	for (i = 0; i < 8; i++) {
		fbnic_hw_stat_rst32(fbd,
				    FBNIC_RPC_TCAM_IPSRC_HIT_CNT(i),
				    &rpc->ipsrc_hit[i]);
		fbnic_hw_stat_rst32(fbd,
				    FBNIC_RPC_TCAM_IPDST_HIT_CNT(i),
				    &rpc->ipdst_hit[i]);
		fbnic_hw_stat_rst32(fbd,
				    FBNIC_RPC_TCAM_OUTER_IPSRC_HIT_CNT(i),
				    &rpc->outer_ipsrc_hit[i]);
		fbnic_hw_stat_rst32(fbd,
				    FBNIC_RPC_TCAM_OUTER_IPDST_HIT_CNT(i),
				    &rpc->outer_ipdst_hit[i]);
	}
	fbnic_hw_stat_rst32(fbd,
			    FBNIC_RPC_TCAM_IPSRC_MISS_CNT,
			    &rpc->ipsrc_miss);
	fbnic_hw_stat_rst32(fbd,
			    FBNIC_RPC_TCAM_IPDST_MISS_CNT,
			    &rpc->ipdst_miss);
	fbnic_hw_stat_rst32(fbd,
			    FBNIC_RPC_TCAM_OUTER_IPSRC_MISS_CNT,
			    &rpc->outer_ipsrc_miss);
	fbnic_hw_stat_rst32(fbd,
			    FBNIC_RPC_TCAM_OUTER_IPDST_MISS_CNT,
			    &rpc->outer_ipdst_miss);

	for (i = 0; i < 64; i++)
		fbnic_hw_stat_rst32(fbd,
				    FBNIC_RPC_TCAM_ACT_HIT_CNT(i),
				    &rpc->tcam_act_hit[i]);
	fbnic_hw_stat_rst32(fbd,
			    FBNIC_RPC_TCAM_ACT_MISS_CNT,
			    &rpc->tcam_act_miss);
}

static void fbnic_get_rpc_stats32(struct fbnic_dev *fbd,
				  struct fbnic_rpc_stats *rpc)
{
	int i;

	fbnic_hw_stat_rd32(fbd,
			   FBNIC_RPC_CNTR_UNKN_ETYPE,
			   &rpc->unkn_etype);
	fbnic_hw_stat_rd32(fbd,
			   FBNIC_RPC_CNTR_UNKN_EXT_HDR,
			   &rpc->unkn_ext_hdr);

	fbnic_hw_stat_rd32(fbd, FBNIC_RPC_CNTR_IPV4_FRAG, &rpc->ipv4_frag);
	fbnic_hw_stat_rd32(fbd, FBNIC_RPC_CNTR_IPV6_FRAG, &rpc->ipv6_frag);

	fbnic_hw_stat_rd32(fbd, FBNIC_RPC_CNTR_IPV4_ESP, &rpc->ipv4_esp);
	fbnic_hw_stat_rd32(fbd, FBNIC_RPC_CNTR_IPV6_ESP, &rpc->ipv6_esp);

	fbnic_hw_stat_rd32(fbd, FBNIC_RPC_CNTR_TCP_OPT_ERR, &rpc->tcp_opt_err);
	fbnic_hw_stat_rd32(fbd,
			   FBNIC_RPC_CNTR_OUT_OF_HDR_ERR,
			   &rpc->out_of_hdr_err);
	fbnic_hw_stat_rd32(fbd,
			   FBNIC_RPC_CNTR_OVR_SIZE_ERR,
			   &rpc->ovr_size_err);

	for (i = 0; i < 32; i++)
		fbnic_hw_stat_rd32(fbd,
				   FBNIC_RPC_TCAM_MACDA_HIT_CNT(i),
				   &rpc->macda_hit[i]);
	fbnic_hw_stat_rd32(fbd,
			   FBNIC_RPC_TCAM_MACDA_MISS_CNT,
			   &rpc->macda_miss);

	for (i = 0; i < 8; i++) {
		fbnic_hw_stat_rd32(fbd,
				   FBNIC_RPC_TCAM_IPSRC_HIT_CNT(i),
				   &rpc->ipsrc_hit[i]);
		fbnic_hw_stat_rd32(fbd,
				   FBNIC_RPC_TCAM_IPDST_HIT_CNT(i),
				   &rpc->ipdst_hit[i]);
		fbnic_hw_stat_rd32(fbd,
				   FBNIC_RPC_TCAM_OUTER_IPSRC_HIT_CNT(i),
				   &rpc->outer_ipsrc_hit[i]);
		fbnic_hw_stat_rd32(fbd,
				   FBNIC_RPC_TCAM_OUTER_IPDST_HIT_CNT(i),
				   &rpc->outer_ipdst_hit[i]);
	}
	fbnic_hw_stat_rd32(fbd,
			   FBNIC_RPC_TCAM_IPSRC_MISS_CNT,
			   &rpc->ipsrc_miss);
	fbnic_hw_stat_rd32(fbd,
			   FBNIC_RPC_TCAM_IPDST_MISS_CNT,
			   &rpc->ipdst_miss);
	fbnic_hw_stat_rd32(fbd,
			   FBNIC_RPC_TCAM_OUTER_IPSRC_MISS_CNT,
			   &rpc->outer_ipsrc_miss);
	fbnic_hw_stat_rd32(fbd,
			   FBNIC_RPC_TCAM_OUTER_IPDST_MISS_CNT,
			   &rpc->outer_ipdst_miss);

	for (i = 0; i < 64; i++)
		fbnic_hw_stat_rd32(fbd,
				   FBNIC_RPC_TCAM_ACT_HIT_CNT(i),
				   &rpc->tcam_act_hit[i]);
	fbnic_hw_stat_rd32(fbd,
			   FBNIC_RPC_TCAM_ACT_MISS_CNT,
			   &rpc->tcam_act_miss);
}

static void fbnic_get_rpc_stats(struct fbnic_dev *fbd,
				struct fbnic_rpc_stats *rpc)
{
	fbnic_get_rpc_stats32(fbd, rpc);
}

static void fbnic_reset_pcie_stats_fpga(struct fbnic_dev *fbd,
					struct fbnic_pcie_stats *pcie)
{
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PCIE_USER_OB_RD_TLP_CNT_31_0,
			    1,
			    &pcie->ob_rd_tlp);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PCIE_USER_OB_RD_DWORD_CNT_31_0,
			    1,
			    &pcie->ob_rd_dword);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PCIE_USER_OB_WR_TLP_CNT_31_0,
			    1,
			    &pcie->ob_wr_tlp);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PCIE_USER_OB_WR_DWORD_CNT_31_0,
			    1,
			    &pcie->ob_wr_dword);

	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PCIE_USER_IB_CPL_TLP_CNT_31_0,
			    1,
			    &pcie->ib_cpl_tlp);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PCIE_USER_IB_CPL_DWORD_CNT_31_0,
			    1,
			    &pcie->ib_cpl_dword);

	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PCIE_USER_OB_RD_DBG_CNT_TAG_31_0,
			    1,
			    &pcie->ob_rd_no_tag);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PCIE_USER_OB_RD_DBG_CNT_CPL_CRED_31_0,
			    1,
			    &pcie->ob_rd_no_cpl_cred);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PCIE_USER_OB_RD_DBG_CNT_NP_CRED_31_0,
			    1,
			    &pcie->ob_rd_no_np_cred);
}

static void fbnic_reset_pcie_stats_asic(struct fbnic_dev *fbd,
					struct fbnic_pcie_stats *pcie)
{
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PUL_USER_OB_RD_TLP_CNT_31_0,
			    1,
			    &pcie->ob_rd_tlp);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PUL_USER_OB_RD_DWORD_CNT_31_0,
			    1,
			    &pcie->ob_rd_dword);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PUL_USER_OB_WR_TLP_CNT_31_0,
			    1,
			    &pcie->ob_wr_tlp);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PUL_USER_OB_WR_DWORD_CNT_31_0,
			    1,
			    &pcie->ob_wr_dword);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PUL_USER_OB_RD_DBG_CNT_TAG_31_0,
			    1,
			    &pcie->ob_rd_no_tag);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PUL_USER_OB_RD_DBG_CNT_CPL_CRED_31_0,
			    1,
			    &pcie->ob_rd_no_cpl_cred);
	fbnic_hw_stat_rst64(fbd,
			    FBNIC_PUL_USER_OB_RD_DBG_CNT_NP_CRED_31_0,
			    1,
			    &pcie->ob_rd_no_np_cred);
}

static void fbnic_get_pcie_stats_fpga(struct fbnic_dev *fbd,
				      struct fbnic_pcie_stats *pcie)
{
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PCIE_USER_OB_RD_TLP_CNT_31_0,
			   1,
			   &pcie->ob_rd_tlp);
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PCIE_USER_OB_RD_DWORD_CNT_31_0,
			   1,
			   &pcie->ob_rd_dword);
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PCIE_USER_OB_WR_TLP_CNT_31_0,
			   1,
			   &pcie->ob_wr_tlp);
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PCIE_USER_OB_WR_DWORD_CNT_31_0,
			   1,
			   &pcie->ob_wr_dword);
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PCIE_USER_OB_RD_DBG_CNT_TAG_31_0,
			   1,
			   &pcie->ob_rd_no_tag);
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PCIE_USER_OB_RD_DBG_CNT_CPL_CRED_31_0,
			   1,
			   &pcie->ob_rd_no_cpl_cred);
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PCIE_USER_OB_RD_DBG_CNT_NP_CRED_31_0,
			   1,
			   &pcie->ob_rd_no_np_cred);
}

static void fbnic_get_pcie_stats_asic(struct fbnic_dev *fbd,
				      struct fbnic_pcie_stats *pcie)
{
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PUL_USER_OB_RD_TLP_CNT_31_0,
			   1,
			   &pcie->ob_rd_tlp);
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PUL_USER_OB_RD_DWORD_CNT_31_0,
			   1,
			   &pcie->ob_rd_dword);
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PUL_USER_OB_WR_TLP_CNT_31_0,
			   1,
			   &pcie->ob_wr_tlp);
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PUL_USER_OB_WR_DWORD_CNT_31_0,
			   1,
			   &pcie->ob_wr_dword);
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PUL_USER_OB_RD_DBG_CNT_TAG_31_0,
			   1,
			   &pcie->ob_rd_no_tag);
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PUL_USER_OB_RD_DBG_CNT_CPL_CRED_31_0,
			   1,
			   &pcie->ob_rd_no_cpl_cred);
	fbnic_hw_stat_rd64(fbd,
			   FBNIC_PUL_USER_OB_RD_DBG_CNT_NP_CRED_31_0,
			   1,
			   &pcie->ob_rd_no_np_cred);
}

static void fbnic_reset_hw_mac_stats(struct fbnic_dev *fbd,
				     struct fbnic_mac_stats *mac_stats)
{
	const struct fbnic_mac *mac = fbd->mac;

	mac->get_fec_stats(fbd, true, &mac_stats->fec);
	mac->get_pause_stats(fbd, true, &mac_stats->pause);
	mac->get_eth_mac_stats(fbd, true, &mac_stats->eth_mac);
	mac->get_eth_ctrl_stats(fbd, true, &mac_stats->eth_ctrl);
	mac->get_rmon_stats(fbd, true, &mac_stats->rmon);
}

static void fbnic_get_hw_mac_stats(struct fbnic_dev *fbd,
				   struct fbnic_mac_stats *mac_stats)
{
	const struct fbnic_mac *mac = fbd->mac;

	mac->get_fec_stats(fbd, false, &mac_stats->fec);
	mac->get_pause_stats(fbd, false, &mac_stats->pause);
	mac->get_eth_mac_stats(fbd, false, &mac_stats->eth_mac);
	mac->get_eth_ctrl_stats(fbd, false, &mac_stats->eth_ctrl);
	mac->get_rmon_stats(fbd, false, &mac_stats->rmon);
}

static void fbnic_reset_hw_q_stats(struct fbnic_dev *fbd,
				   struct fbnic_hw_q_stats *hw_q)
{
	int i;

	for (i = 0; i < fbd->max_num_queues; i++, hw_q++) {
		u32 base = FBNIC_QUEUE(i);

		fbnic_hw_stat_rst32(fbd,
				    base + FBNIC_QUEUE_TWQ0_PKT_CNT,
				    &hw_q->tde[0].frames);
		fbnic_hw_stat_rst32(fbd,
				    base + FBNIC_QUEUE_TWQ0_ERR_CNT,
				    &hw_q->tde_pkt_err[0]);
		fbnic_hw_stat_rst32(fbd,
				    base + FBNIC_QUEUE_TWQ1_PKT_CNT,
				    &hw_q->tde[1].frames);
		fbnic_hw_stat_rst32(fbd,
				    base + FBNIC_QUEUE_TWQ1_ERR_CNT,
				    &hw_q->tde_pkt_err[1]);
		fbnic_hw_stat_rst32(fbd,
				    base + FBNIC_QUEUE_RDE_PKT_CNT,
				    &hw_q->rde.frames);
		fbnic_hw_stat_rst32(fbd,
				    base + FBNIC_QUEUE_RDE_PKT_ERR_CNT,
				    &hw_q->rde_pkt_err);
		fbnic_hw_stat_rst32(fbd,
				    base + FBNIC_QUEUE_RDE_CQ_DROP_CNT,
				    &hw_q->rde_pkt_cq_drop);
		fbnic_hw_stat_rst32(fbd,
				    base + FBNIC_QUEUE_RDE_BDQ_DROP_CNT,
				    &hw_q->rde_pkt_bdq_drop);
	}
}

static void fbnic_get_hw_q_stats32(struct fbnic_dev *fbd,
				   struct fbnic_hw_q_stats *hw_q)
{
	int i;

	for (i = 0; i < fbd->max_num_queues; i++, hw_q++) {
		u32 base = FBNIC_QUEUE(i);

		fbnic_hw_stat_rd32(fbd,
				   base + FBNIC_QUEUE_TWQ0_PKT_CNT,
				   &hw_q->tde[0].frames);
		fbnic_hw_stat_rd32(fbd,
				   base + FBNIC_QUEUE_TWQ0_ERR_CNT,
				   &hw_q->tde_pkt_err[0]);
		fbnic_hw_stat_rd32(fbd,
				   base + FBNIC_QUEUE_TWQ1_PKT_CNT,
				   &hw_q->tde[1].frames);
		fbnic_hw_stat_rd32(fbd,
				   base + FBNIC_QUEUE_TWQ1_ERR_CNT,
				   &hw_q->tde_pkt_err[1]);
		fbnic_hw_stat_rd32(fbd,
				   base + FBNIC_QUEUE_RDE_PKT_CNT,
				   &hw_q->rde.frames);
		fbnic_hw_stat_rd32(fbd,
				   base + FBNIC_QUEUE_RDE_PKT_ERR_CNT,
				   &hw_q->rde_pkt_err);
		fbnic_hw_stat_rd32(fbd,
				   base + FBNIC_QUEUE_RDE_CQ_DROP_CNT,
				   &hw_q->rde_pkt_cq_drop);
		fbnic_hw_stat_rd32(fbd,
				   base + FBNIC_QUEUE_RDE_BDQ_DROP_CNT,
				   &hw_q->rde_pkt_bdq_drop);
	}
}

static void fbnic_get_hw_q_stats(struct fbnic_dev *fbd,
				 struct fbnic_hw_q_stats *hw_q)
{
	fbnic_get_hw_q_stats32(fbd, hw_q);
}

void fbnic_reset_hw_stats(struct fbnic_dev *fbd)
{
	fbnic_reset_tti_stats(fbd, &fbd->hw_stats.tti);
	fbnic_reset_tmi_stats(fbd, &fbd->hw_stats.tmi);
	fbnic_reset_rxb_stats(fbd, &fbd->hw_stats.rxb);
	fbnic_reset_rpc_stats(fbd, &fbd->hw_stats.rpc);
	if (fbnic_is_asic(fbd))
		fbnic_reset_pcie_stats_asic(fbd, &fbd->hw_stats.pcie);
	else
		fbnic_reset_pcie_stats_fpga(fbd, &fbd->hw_stats.pcie);

	fbnic_reset_hw_mac_stats(fbd, &fbd->hw_stats.mac);
	fbnic_reset_hw_q_stats(fbd, fbd->hw_stats.hw_q);
}

void fbnic_get_hw_stats(struct fbnic_dev *fbd)
{
	fbnic_get_tti_stats(fbd, &fbd->hw_stats.tti);
	fbnic_get_tmi_stats(fbd, &fbd->hw_stats.tmi);
	fbnic_get_rxb_stats(fbd, &fbd->hw_stats.rxb);
	fbnic_get_rpc_stats(fbd, &fbd->hw_stats.rpc);

	if (fbnic_is_asic(fbd))
		fbnic_get_pcie_stats_asic(fbd, &fbd->hw_stats.pcie);
	else
		fbnic_get_pcie_stats_fpga(fbd, &fbd->hw_stats.pcie);

	fbnic_get_hw_q_stats(fbd, fbd->hw_stats.hw_q);
}

void fbnic_update_hw_stats32(struct fbnic_dev *fbd)
{
	fbnic_get_tti_stats32(fbd, &fbd->hw_stats.tti);
	fbnic_get_tmi_stats32(fbd, &fbd->hw_stats.tmi);
	fbnic_get_rxb_stats32(fbd, &fbd->hw_stats.rxb);
	fbnic_get_rpc_stats32(fbd, &fbd->hw_stats.rpc);

	fbnic_get_hw_q_stats32(fbd, fbd->hw_stats.hw_q);
}

void fbnic_get_mac_stats(struct fbnic_dev *fbd)
{
	fbnic_get_hw_mac_stats(fbd, &fbd->hw_stats.mac);
}
