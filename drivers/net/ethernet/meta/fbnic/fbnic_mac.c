// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <linux/ethtool.h>
#include <linux/iopoll.h>
#include <linux/linkmode.h>
#include <net/tcp.h>

#include "fbnic.h"
#include "fbnic_hw_stats.h"
#include "fbnic_mac.h"
#include "fbnic_netdev.h"

static void fbnic_init_readrq(struct fbnic_dev *fbd, unsigned int offset,
			      unsigned int cls, unsigned int readrq)
{
	u32 val = rd32(offset);

	/* The TDF_CTL masks are a superset of the RNI_RBP ones. So we can
	 * use them when setting either the TDE_CTF or RNI_RBP registers.
	 */
	val &= FBNIC_QM_TNI_TDF_CTL_MAX_OT | FBNIC_QM_TNI_TDF_CTL_MAX_OB;

	val |= FIELD_PREP(FBNIC_QM_TNI_TDF_CTL_MRRS, readrq) |
	       FIELD_PREP(FBNIC_QM_TNI_TDF_CTL_CLS, cls);

	wr32(offset, val);
}

static void fbnic_init_mps(struct fbnic_dev *fbd, unsigned int offset,
			   unsigned int cls, unsigned int mps)
{
	u32 val = rd32(offset);

	/* Currently all MPS masks are identical so just use the first one */
	val &= ~(FBNIC_QM_TNI_TCM_CTL_MPS | FBNIC_QM_TNI_TCM_CTL_CLS);

	val |= FIELD_PREP(FBNIC_QM_TNI_TCM_CTL_MPS, mps) |
	       FIELD_PREP(FBNIC_QM_TNI_TCM_CTL_CLS, cls);

	wr32(offset, val);
}

static void fbnic_mac_init_axi(struct fbnic_dev *fbd)
{
	bool override_1k = false;
	int readrq, mps, cls;

	/* All of the values are based on being a power of 2 starting
	 * with 64 == 0. Therefore we can either divide by 64 in the
	 * case of constants, or just subtract 6 from the log2 of the value
	 * in order to get the value we will be programming into the
	 * registers.
	 */
	readrq = ilog2(fbd->readrq) - 6;
	if (readrq > 3)
		override_1k = true;
	readrq = clamp(readrq, 0, 3);

	mps = ilog2(fbd->mps) - 6;
	mps = clamp(mps, 0, 3);

	cls = ilog2(L1_CACHE_BYTES) - 6;
	cls = clamp(cls, 0, 3);

	/* Configure Tx/Rx AXI Paths w/ Read Request and Max Payload sizes */
	fbnic_init_readrq(fbd, FBNIC_QM_TNI_TDF_CTL, cls, readrq);
	fbnic_init_mps(fbd, FBNIC_QM_TNI_TCM_CTL, cls, mps);

	/* Configure QM TNI TDE:
	 * - Max outstanding AXI beats to 704(768 - 64) - guaranetees 8% of
	 *   buffer capacity to descriptors.
	 * - Max outstanding transactions to 128
	 */
	wr32(FBNIC_QM_TNI_TDE_CTL,
	     FIELD_PREP(FBNIC_QM_TNI_TDE_CTL_MRRS_1K, override_1k ? 1 : 0) |
	     FIELD_PREP(FBNIC_QM_TNI_TDE_CTL_MAX_OB, 704) |
	     FIELD_PREP(FBNIC_QM_TNI_TDE_CTL_MAX_OT, 128) |
	     FIELD_PREP(FBNIC_QM_TNI_TDE_CTL_MRRS, readrq) |
	     FIELD_PREP(FBNIC_QM_TNI_TDE_CTL_CLS, cls));

	fbnic_init_readrq(fbd, FBNIC_QM_RNI_RBP_CTL, cls, readrq);
	fbnic_init_mps(fbd, FBNIC_QM_RNI_RDE_CTL, cls, mps);
	fbnic_init_mps(fbd, FBNIC_QM_RNI_RCM_CTL, cls, mps);

	/* Enable XALI AR/AW outbound */
	if (fbnic_is_asic(fbd)) {
		wr32(FBNIC_PUL_OB_TLP_HDR_AW_CFG,
		     FBNIC_PUL_OB_TLP_HDR_AW_CFG_BME);
		wr32(FBNIC_PUL_OB_TLP_HDR_AR_CFG,
		     FBNIC_PUL_OB_TLP_HDR_AR_CFG_BME);
	}
}

static void fbnic_mac_init_qm(struct fbnic_dev *fbd)
{
	u64 default_meta = FIELD_PREP(FBNIC_TWD_L2_HLEN_MASK, ETH_HLEN) |
			   FBNIC_TWD_FLAG_REQ_COMPLETION;
	u32 clock_freq;

	/* Configure default TWQ Metadata descriptor */
	fbnic_wr32(fbd, FBNIC_QM_TWQ_DEFAULT_META_L,
		   lower_32_bits(default_meta));
	fbnic_wr32(fbd, FBNIC_QM_TWQ_DEFAULT_META_H,
		   upper_32_bits(default_meta));

	/* Configure TSO behavior */
	fbnic_wr32(fbd, FBNIC_QM_TQS_CTL0,
		   FIELD_PREP(FBNIC_QM_TQS_CTL0_LSO_TS_MASK,
			      FBNIC_QM_TQS_CTL0_LSO_TS_LAST) |
		   FIELD_PREP(FBNIC_QM_TQS_CTL0_PREFETCH_THRESH,
			      FBNIC_QM_TQS_CTL0_PREFETCH_THRESH_MIN));

	/* Limit EDT to INT_MAX as this is the limit of the EDT Qdisc */
	fbnic_wr32(fbd, FBNIC_QM_TQS_EDT_TS_RANGE, INT_MAX);

	/* Configure MTU
	 * Due to known HW issue we cannot set the MTU to within 16 octets
	 * of a 64 octet aligned boundary. So we will set the TQS_MTU(s) to
	 * MTU + 1.
	 */
	fbnic_wr32(fbd, FBNIC_QM_TQS_MTU_CTL0, FBNIC_MAX_JUMBO_FRAME_SIZE + 1);
	fbnic_wr32(fbd, FBNIC_QM_TQS_MTU_CTL1,
		   FIELD_PREP(FBNIC_QM_TQS_MTU_CTL1_BULK,
			      FBNIC_MAX_JUMBO_FRAME_SIZE + 1));

	clock_freq = fbnic_is_asic(fbd) ? FBNIC_ASIC_CLOCK_FREQ :
					  FBNIC_FPGA_CLOCK_FREQ;

	/* Be aggressive on the timings. We will have the interrupt
	 * threshold timer tick once every 1 usec and coalese writes for
	 * up to 80 usecs.
	 */
	fbnic_wr32(fbd, FBNIC_QM_TCQ_CTL0,
		   FIELD_PREP(FBNIC_QM_TCQ_CTL0_TICK_CYCLES,
			      clock_freq / 1000000) |
		   FIELD_PREP(FBNIC_QM_TCQ_CTL0_COAL_WAIT,
			      clock_freq / 12500));

	/* We will have the interrupt threshold timer tick once every
	 * 1 usec and coalese writes for up to 2 usecs.
	 */
	fbnic_wr32(fbd, FBNIC_QM_RCQ_CTL0,
		   FIELD_PREP(FBNIC_QM_RCQ_CTL0_TICK_CYCLES,
			      clock_freq / 1000000) |
		   FIELD_PREP(FBNIC_QM_RCQ_CTL0_COAL_WAIT,
			      clock_freq / 500000));

	/* Configure spacer control to 64 beats. */
	fbnic_wr32(fbd, FBNIC_FAB_AXI4_AR_SPACER_2_CFG,
		   FBNIC_FAB_AXI4_AR_SPACER_MASK |
		   FIELD_PREP(FBNIC_FAB_AXI4_AR_SPACER_THREADSHOLD, 2));
}

#define FBNIC_DROP_EN_MASK	0x7d
#define FBNIC_PAUSE_EN_MASK	0x14
#define FBNIC_ECN_EN_MASK	0x10

struct fbnic_fifo_config {
	unsigned int addr;
	unsigned int size;
};

/* Rx FIFO Configuration
 * The table consists of 8 entries, of which only 4 are currently used
 * The starting addr is in units of 64B and the size is in 2KB units
 * Below is the human readable version of the table defined below:
 * Function		Addr	Size
 * ----------------------------------
 * network to Host/BMC	384K	64K
 * Unused
 * Unused
 * network to BMC	448K	32K
 * network to Host	0	384K
 * Unused
 * BMC to Host		480K	32K
 * Unused
 */
static const struct fbnic_fifo_config fifo_config[] = {
	{ .addr = 0x1800, .size = 0x20 },	/* network to Host/BMC */
	{ },					/* not used */
	{ },					/* not used */
	{ .addr = 0x1c00, .size = 0x10 },	/* network to BMC */
	{ .addr = 0x0000, .size = 0xc0 },	/* network to Host */
	{ },					/* not used */
	{ .addr = 0x1e00, .size = 0x10 },	/* BMC to Host */
	{ }					/* not used */
};

static void fbnic_mac_init_rxb(struct fbnic_dev *fbd)
{
	bool rx_enable;
	int i;

	rx_enable = !!(fbnic_rd32(fbd, FBNIC_RPC_RMI_CONFIG) &
		       FBNIC_RPC_RMI_CONFIG_ENABLE);

	for (i = 0; i < 8; i++) {
		unsigned int size = fifo_config[i].size;

		/* If we are coming up on a system that already has the
		 * Rx data path enabled we don't need to reconfigure the
		 * FIFOs. Instead we can check to verify the values are
		 * large enough to meet our needs, and use the values to
		 * populate the flow control, ECN, and drop thresholds.
		 */
		if (rx_enable) {
			size = FIELD_GET(FBNIC_RXB_PBUF_SIZE,
					 fbnic_rd32(fbd,
						    FBNIC_RXB_PBUF_CFG(i)));
			if (size < fifo_config[i].size)
				dev_warn(fbd->dev,
					 "fifo%d size of %d smaller than expected value of %d\n",
					 i, size << 11,
					 fifo_config[i].size << 11);
		} else {
			/* Program RXB Cuthrough */
			fbnic_wr32(fbd, FBNIC_RXB_CT_SIZE(i),
				   FIELD_PREP(FBNIC_RXB_CT_SIZE_HEADER, 4) |
				   FIELD_PREP(FBNIC_RXB_CT_SIZE_PAYLOAD, 2));

			/* The granularity for the packet buffer size is 2KB
			 * granularity while the packet buffer base address is
			 * only 64B granularity
			 */
			fbnic_wr32(fbd, FBNIC_RXB_PBUF_CFG(i),
				   FIELD_PREP(FBNIC_RXB_PBUF_BASE_ADDR,
					      fifo_config[i].addr) |
				   FIELD_PREP(FBNIC_RXB_PBUF_SIZE, size));

			/* The granularity for the credits is 64B. This is
			 * based on RXB_PBUF_SIZE * 32 + 4.
			 */
			fbnic_wr32(fbd, FBNIC_RXB_PBUF_CREDIT(i),
				   FIELD_PREP(FBNIC_RXB_PBUF_CREDIT_MASK,
					      size ? size * 32 + 4 : 0));
		}

		if (!size)
			continue;

		/* Pause is size of FIFO with 56KB skid to start/stop */
		fbnic_wr32(fbd, FBNIC_RXB_PAUSE_THLD(i),
			   !(FBNIC_PAUSE_EN_MASK & (1u << i)) ? 0x1fff :
			   FIELD_PREP(FBNIC_RXB_PAUSE_THLD_ON,
				      size * 32 - 0x380) |
			   FIELD_PREP(FBNIC_RXB_PAUSE_THLD_OFF, 0x380));

		/* Enable Drop when only one packet is left in the FIFO */
		fbnic_wr32(fbd, FBNIC_RXB_DROP_THLD(i),
			   !(FBNIC_DROP_EN_MASK & (1u << i)) ? 0x1fff :
			   FIELD_PREP(FBNIC_RXB_DROP_THLD_ON,
				      size * 32 -
				      FBNIC_MAX_JUMBO_FRAME_SIZE / 64) |
			   FIELD_PREP(FBNIC_RXB_DROP_THLD_OFF,
				      size * 32 -
				      FBNIC_MAX_JUMBO_FRAME_SIZE / 64));

		/* Enable ECN bit when 1/4 of RXB is filled with at least
		 * 1 room for one full jumbo frame before setting ECN
		 */
		fbnic_wr32(fbd, FBNIC_RXB_ECN_THLD(i),
			   !(FBNIC_ECN_EN_MASK & (1u << i)) ? 0x1fff :
			   FIELD_PREP(FBNIC_RXB_ECN_THLD_ON,
				      max_t(unsigned int,
					    size * 32 / 4,
					    FBNIC_MAX_JUMBO_FRAME_SIZE / 64)) |
			   FIELD_PREP(FBNIC_RXB_ECN_THLD_OFF,
				      max_t(unsigned int,
					    size * 32 / 4,
					    FBNIC_MAX_JUMBO_FRAME_SIZE / 64)));
	}

	/* For now only enable drop and ECN. We need to add driver/kernel
	 * interfaces for configuring pause.
	 */
	fbnic_wr32(fbd, FBNIC_RXB_PAUSE_DROP_CTRL,
		   FIELD_PREP(FBNIC_RXB_PAUSE_DROP_CTRL_DROP_ENABLE,
			      FBNIC_DROP_EN_MASK) |
		   FIELD_PREP(FBNIC_RXB_PAUSE_DROP_CTRL_ECN_ENABLE,
			      FBNIC_ECN_EN_MASK));

	/* Program INTF credits */
	fbnic_wr32(fbd, FBNIC_RXB_INTF_CREDIT,
		   FBNIC_RXB_INTF_CREDIT_MASK0 |
		   FBNIC_RXB_INTF_CREDIT_MASK1 |
		   FBNIC_RXB_INTF_CREDIT_MASK2 |
		   FIELD_PREP(FBNIC_RXB_INTF_CREDIT_MASK3, 8));

	/* Configure calendar slots.
	 * Rx: 0 - 62	RDE 1st, BMC 2nd
	 *     63	BMC 1st, RDE 2nd
	 */
	for (i = 0; i < 16; i++) {
		u32 calendar_val = (i == 15) ? 0x1e1b1b1b : 0x1b1b1b1b;

		fbnic_wr32(fbd, FBNIC_RXB_CLDR_PRIO_CFG(i), calendar_val);
	}

	/* Split the credits for the DRR up as follows:
	 * Quantum0: 8000	Network to Host
	 * Quantum1: 0		Not used
	 * Quantum2: 80		BMC to Host
	 * Quantum3: 0		Not used
	 * Quantum4: 8000	Multicast to Host and BMC
	 */
	fbnic_wr32(fbd, FBNIC_RXB_DWRR_RDE_WEIGHT0,
		   FIELD_PREP(FBNIC_RXB_DWRR_RDE_WEIGHT0_QUANTUM0, 0x40) |
		   FIELD_PREP(FBNIC_RXB_DWRR_RDE_WEIGHT0_QUANTUM2, 0x50));
	fbnic_wr32(fbd, FBNIC_RXB_DWRR_RDE_WEIGHT0_EXT,
		   FIELD_PREP(FBNIC_RXB_DWRR_RDE_WEIGHT0_QUANTUM0, 0x1f));
	fbnic_wr32(fbd, FBNIC_RXB_DWRR_RDE_WEIGHT1,
		   FIELD_PREP(FBNIC_RXB_DWRR_RDE_WEIGHT1_QUANTUM4, 0x40));
	fbnic_wr32(fbd, FBNIC_RXB_DWRR_RDE_WEIGHT1_EXT,
		   FIELD_PREP(FBNIC_RXB_DWRR_RDE_WEIGHT1_QUANTUM4, 0x1f));

	/* Program RXB FCS Endian register */
	fbnic_wr32(fbd, FBNIC_RXB_ENDIAN_FCS, 0x0aaaaaa0);
}

static void fbnic_mac_init_txb(struct fbnic_dev *fbd)
{
	int i;

	fbnic_wr32(fbd, FBNIC_TCE_TXB_CTRL, 0);

	/* Configure Tx QM Credits */
	fbnic_wr32(fbd, FBNIC_QM_TQS_CTL1,
		   FIELD_PREP(FBNIC_QM_TQS_CTL1_MC_MAX_CREDITS, 0x40) |
		   FIELD_PREP(FBNIC_QM_TQS_CTL1_BULK_MAX_CREDITS, 0x20));

	/* Initialize internal Tx queues */
	fbnic_wr32(fbd, FBNIC_TCE_TXB_TEI_Q0_CTRL, 0);
	fbnic_wr32(fbd, FBNIC_TCE_TXB_TEI_Q1_CTRL, 0);
	fbnic_wr32(fbd, FBNIC_TCE_TXB_MC_Q_CTRL,
		   FIELD_PREP(FBNIC_TCE_TXB_Q_CTRL_SIZE, 0x400) |
		   FIELD_PREP(FBNIC_TCE_TXB_Q_CTRL_START, 0x000));
	fbnic_wr32(fbd, FBNIC_TCE_TXB_RX_TEI_Q_CTRL, 0);
	fbnic_wr32(fbd, FBNIC_TCE_TXB_TX_BMC_Q_CTRL,
		   FIELD_PREP(FBNIC_TCE_TXB_Q_CTRL_SIZE, 0x200) |
		   FIELD_PREP(FBNIC_TCE_TXB_Q_CTRL_START, 0x400));
	fbnic_wr32(fbd, FBNIC_TCE_TXB_RX_BMC_Q_CTRL,
		   FIELD_PREP(FBNIC_TCE_TXB_Q_CTRL_SIZE, 0x200) |
		   FIELD_PREP(FBNIC_TCE_TXB_Q_CTRL_START, 0x600));

	fbnic_wr32(fbd, FBNIC_TCE_LSO_CTRL,
		   FBNIC_TCE_LSO_CTRL_IPID_MODE_INC |
		   FIELD_PREP(FBNIC_TCE_LSO_CTRL_TCPF_CLR_1ST, TCPHDR_PSH |
							       TCPHDR_FIN) |
		   FIELD_PREP(FBNIC_TCE_LSO_CTRL_TCPF_CLR_MID, TCPHDR_PSH |
							       TCPHDR_CWR |
							       TCPHDR_FIN) |
		   FIELD_PREP(FBNIC_TCE_LSO_CTRL_TCPF_CLR_END, TCPHDR_CWR));
	fbnic_wr32(fbd, FBNIC_TCE_CSO_CTRL, 0);

	fbnic_wr32(fbd, FBNIC_TCE_BMC_MAX_PKTSZ,
		   FIELD_PREP(FBNIC_TCE_BMC_MAX_PKTSZ_TX,
			      FBNIC_MAX_JUMBO_FRAME_SIZE) |
		   FIELD_PREP(FBNIC_TCE_BMC_MAX_PKTSZ_RX,
			      FBNIC_MAX_JUMBO_FRAME_SIZE));
	fbnic_wr32(fbd, FBNIC_TCE_MC_MAX_PKTSZ,
		   FIELD_PREP(FBNIC_TCE_MC_MAX_PKTSZ_TMI,
			      FBNIC_MAX_JUMBO_FRAME_SIZE));

	/* Enable Drops in Tx path, needed for FPGA only */
	if (!fbnic_is_asic(fbd))
		fbnic_wr32(fbd, FBNIC_TCE_DROP_CTRL,
			   FBNIC_TCE_DROP_CTRL_TTI_CM_DROP_EN |
			   FBNIC_TCE_DROP_CTRL_TTI_FRM_DROP_EN |
			   FBNIC_TCE_DROP_CTRL_TTI_TBI_DROP_EN);

	/* Configure calendar slots.
	 * Tx: 0 - 62	TMI 1st, BMC 2nd
	 *     63	BMC 1st, TMI 2nd
	 */
	for (i = 0; i < 16; i++) {
		u32 calendar_val = (i == 15) ? 0x1e1b1b1b : 0x1b1b1b1b;

		fbnic_wr32(fbd, FBNIC_TCE_TXB_CLDR_SLOT_CFG(i), calendar_val);
	}

	/* Configure DWRR */
	fbnic_wr32(fbd, FBNIC_TCE_TXB_ENQ_WRR_CTRL,
		   FIELD_PREP(FBNIC_TCE_TXB_ENQ_WRR_CTRL_WEIGHT0, 0x64) |
		   FIELD_PREP(FBNIC_TCE_TXB_ENQ_WRR_CTRL_WEIGHT2, 0x04));
	fbnic_wr32(fbd, FBNIC_TCE_TXB_TEI_DWRR_CTRL, 0);
	fbnic_wr32(fbd, FBNIC_TCE_TXB_TEI_DWRR_CTRL_EXT, 0);
	fbnic_wr32(fbd, FBNIC_TCE_TXB_BMC_DWRR_CTRL,
		   FIELD_PREP(FBNIC_TCE_TXB_BMC_DWRR_CTRL_QUANTUM0, 0x50) |
		   FIELD_PREP(FBNIC_TCE_TXB_BMC_DWRR_CTRL_QUANTUM1, 0x82));
	fbnic_wr32(fbd, FBNIC_TCE_TXB_BMC_DWRR_CTRL_EXT, 0);
	fbnic_wr32(fbd, FBNIC_TCE_TXB_NTWRK_DWRR_CTRL,
		   FIELD_PREP(FBNIC_TCE_TXB_NTWRK_DWRR_CTRL_QUANTUM1, 0x50) |
		   FIELD_PREP(FBNIC_TCE_TXB_NTWRK_DWRR_CTRL_QUANTUM2, 0x20));
	fbnic_wr32(fbd, FBNIC_TCE_TXB_NTWRK_DWRR_CTRL_EXT,
		   FIELD_PREP(FBNIC_TCE_TXB_NTWRK_DWRR_CTRL_QUANTUM2, 0x03));

	/* Configure SOP protocol protection */
	fbnic_wr32(fbd, FBNIC_TCE_SOP_PROT_CTRL,
		   FIELD_PREP(FBNIC_TCE_SOP_PROT_CTRL_TBI, 0x78) |
		   FIELD_PREP(FBNIC_TCE_SOP_PROT_CTRL_TTI_FRM, 0x40) |
		   FIELD_PREP(FBNIC_TCE_SOP_PROT_CTRL_TTI_CM, 0x0c));

	/* Conservative configuration on MAC interface Start of Packet
	 * protection FIFO. This sets the minimum depth of the FIFO before
	 * we start sending packets to the MAC measured in 64B units and
	 * up to 160 entries deep.
	 *
	 * For the ASIC the clock is fast enough that we will likely fill
	 * the SOP FIFO before the MAC can drain it. So just use a minimum
	 * value of 8.
	 *
	 * For the FPGA we have a clock that is about 3/5 of the MAC clock.
	 * As such we will need to account for adding more runway before
	 * transmitting the frames.
	 * SOP = (9230 / 64) * 2/5 + 8
	 * SOP = 66
	 */
	fbnic_wr32(fbd, FBNIC_TMI_SOP_PROT_CTRL, fbnic_is_asic(fbd) ? 8 : 66);

	wrfl();
	fbnic_wr32(fbd, FBNIC_TCE_TXB_CTRL, FBNIC_TCE_TXB_CTRL_TCAM_ENABLE |
					    FBNIC_TCE_TXB_CTRL_LOAD);
}

static void fbnic_mac_init_regs(struct fbnic_dev *fbd)
{
	fbnic_mac_init_axi(fbd);
	fbnic_mac_init_qm(fbd);
	fbnic_mac_init_rxb(fbd);
	fbnic_mac_init_txb(fbd);
}

static int fbnic_mac_clear_reset(struct fbnic_dev *fbd)
{
	int err;
	u32 reg;

	if (rd32(FBNIC_TOP_FPGA_REVISION_ID) < FBNIC_FPGA_MIN_VERSION) {
		dev_err(fbd->dev, "Bitstream version out of date\n");
		return -ENOPKG;
	}

	/* Force the CMS into reset */
	wr32(FBNIC_CMS_QSPI_RESET, 0);
	wrfl();

	/* Bring the CMS/QSPI out of reset */
	wr32(FBNIC_CMS_QSPI_RESET, 1);

	/* Unfortunately the register indicating the CMS register
	 * map is ready returns a false 'true' in the case of the
	 * CMS being in reset. In order to account for that we have
	 * to watch for the ready bit to toggle from '1' to '0'
	 * before we can start polling to actually watch for the
	 * 'ready' indiciation.
	 */
	err = readx_poll_timeout(rd32, FBNIC_CMS_QSPI_HOST_STATUS2, reg,
				 !reg, 1000, 1000000);
	if (err == -ETIMEDOUT) {
		dev_err(fbd->dev, "Timeout bringing CMS out of reset\n");
		return err;
	}

	/* Verify device has come out of reset, can take up to 3s */
	err = readx_poll_timeout(rd32, FBNIC_CMS_QSPI_HOST_STATUS2, reg,
				 !!reg, 1000, 10000000);
	if (err == -ETIMEDOUT)
		dev_err(fbd->dev, "Timeout waiting on mailbox ready\n");

	return err;
}

static int fbnic_mac_set_addr_fpga(struct fbnic_dev *fbd)
{
	int len, i, err;
	u8 key, keylen;
	u32 reg;

	/* Verify MBX is not currently in reset */
	err = fbnic_mac_clear_reset(fbd);
	if (err)
		return err;

	/* Verify MBX isn't in use */
	reg = rd32(FBNIC_CMS_QSPI_CONTROL);
	if (reg & FBNIC_CMS_QSPI_CONTROL_MSG) {
		dev_err(fbd->dev, "Mailbox already in use\n");
		return -EBUSY;
	}

	/* Place card info request in mailbox */
	wr32(FBNIC_CMS_QSPI_MAILBOX(0),
	     FIELD_PREP(FBNIC_CMS_QSPI_MAILBOX_OPCODE,
			FBNIC_CMS_OP_CARD_INFO_REQ));

	/* Flush mailbox write prior to notifying CMS.
	 * Needed as workaround for FD-03 - FD-05, fixed in FD-06.
	 */
	wrfl();

	/* Notify CMS of message, enable HBM temperature monitoring */
	wr32(FBNIC_CMS_QSPI_CONTROL,
	     FBNIC_CMS_QSPI_CONTROL_MSG | FBNIC_CMS_QSPI_CONTROL_HBM);

	/* poll for completion, typically takes up to 90ms */
	err = readx_poll_timeout(rd32, FBNIC_CMS_QSPI_CONTROL, reg,
				 !(reg & FBNIC_CMS_QSPI_CONTROL_MSG),
				 1000, 150000);
	if (err == -ETIMEDOUT) {
		dev_err(fbd->dev, "Timeout waiting on message processing\n");
		return err;
	}

	/* Check for error */
	reg = rd32(FBNIC_CMS_QSPI_HOST_MSG_ERR);
	if (reg) {
		dev_err(fbd->dev, "CMS Error processing message: %d\n", reg);
		return -EIO;
	}

	/* Read start of message, add 4 to len to include the message hdr */
	reg = rd32(FBNIC_CMS_QSPI_MAILBOX(0));
	len = FIELD_GET(FBNIC_CMS_QSPI_MAILBOX_RESP_LEN, reg) + 4;

	/* Parse out message skipping over all but MAC addr info.
	 * Guarantee we always have at least enough bytes for key (i) and
	 * keylen (i + 1) so that we do not parse past the end of the message.
	 */
	for (i = 4; i + 1 < len; i += keylen + 1) {
		unsigned int reg_offset = FBNIC_CMS_QSPI_MAILBOX(i / 4);
		u64 mac_addr = 0;

		/* Read through the list of key and length pairs to
		 * find the MAC addr.
		 */
		reg = rd32(reg_offset);
		reg >>= ((8 * i) % 32);

		key = reg & 0xff;

		/* shift or read new if we have moved to next register */
		if (++i % 4)
			reg >>= 8;
		else
			reg = rd32(++reg_offset);

		keylen = reg & 0xff;

		/* We only care about the MAC ADDR message */
		if (key != FBNIC_SNSR_ID_MAC_ADDR)
			continue;

		/* The MAC Addr message should always have a size of 8 */
		if (keylen != 8 || len <= i + keylen) {
			dev_err(fbd->dev, "Malformed response\n");
			return -EINVAL;
		}

		/* Construct mac_addr based on byte offset of keylen.
		 * The format of the MAC address message is:
		 * 0x4b 0x8 ll rr aa bb cc dd ee ff
		 *
		 * In this example:
		 * 0x4b is the key
		 * 0x8 is the keylength
		 * ll is the number of sequential MAC addresses
		 * rr is reserved
		 * aa..ff is the MAC address
		 *
		 * When it is read from the device it will be a big endian
		 * value stored in a little endian register so it will come
		 * out split over 2 to 3 registers with the ordering
		 * reversed. We will pull in the value to a 64b memory
		 * and byte swap it.
		 */
		mac_addr = rd32(reg_offset + 2);
		mac_addr <<= 32;
		mac_addr |= rd32(reg_offset + 1);
		mac_addr <<= (8 * ~i) % 32;

		/* If i is divisible by 4 then the last byte of the keylen
		 * register contains the first byte of the MAC address.
		 */
		if (!(i % 4))
			mac_addr |= reg >> 8;

		/* Byteswap MAC Address to expected byte ordering for DSN */
		mac_addr = swab64(mac_addr);

		/* Use the mac_addr to fill in the 0 sections */
		fbd->dsn = (0x000000fffffffffful | (mac_addr << 16)) &
			   (0xffffffffff000000ul | mac_addr);

		return 0;
	}

	dev_err(fbd->dev, "MAC Address info not found in response\n");

	return -ENODEV;
}

static bool fbnic_mac_get_link_fpga(struct fbnic_dev *fbd)
{
	u32 mac_status;
	bool link;

	/* If disabled do not update link_state nor change settings */
	if (fbd->link_state == FBNIC_LINK_DISABLED)
		return false;

	/* Clear the interrupt status since we are now performing the check */
	wr32(FBNIC_CMAC_INTR_STS,
	     FBNIC_CMAC_INTR_RX_LINK_UP | FBNIC_CMAC_INTR_RX_LINK_DOWN);

	mac_status = rd32(FBNIC_CMAC_STATUS);

	link = (mac_status & FBNIC_CMAC_STATUS_RX_READY) &&
	       (mac_status & FBNIC_CMAC_STATUS_RX_ALIGNED);

	/* Depending on the event we will unmask the cause that will force a
	 * transition, and update the Tx to reflect our status to the remote
	 * link partner.
	 */
	if (link) {
		wr32(FBNIC_CMAC_CONFIG_TX, FBNIC_CMAC_CONFIG_TX_ENABLE);
		fbd->link_state = FBNIC_LINK_UP;
		wr32(FBNIC_CMAC_INTR_MASK, ~FBNIC_CMAC_INTR_RX_LINK_DOWN);
	} else if (fbd->link_state != FBNIC_LINK_DOWN) {
		wr32(FBNIC_CMAC_CONFIG_TX, FBNIC_CMAC_CONFIG_TX_SEND_RFI);
		fbd->link_state = FBNIC_LINK_DOWN;
		wr32(FBNIC_CMAC_INTR_MASK, ~FBNIC_CMAC_INTR_RX_LINK_UP);
	}

	return link;
}

static void fbnic_mac_config_pause_fpga(struct fbnic_dev *fbd)
{
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);
	u32 rxb_pause_ctrl;

	/* TBD: Determine if we even want to support flow control refresh */
	wr32(FBNIC_CMAC_CONFIG_TXFC_QUANTA, 0xffff);
	wr32(FBNIC_CMAC_CONFIG_TXFC_REFRESH, 0x7fff);

	/* Disable Pause at the RXB */
	rxb_pause_ctrl = rd32(FBNIC_RXB_PAUSE_DROP_CTRL);
	if (!fbn->tx_pause) {
		rxb_pause_ctrl &= ~FBNIC_RXB_PAUSE_DROP_CTRL_PAUSE_ENABLE;
		wr32(FBNIC_RXB_PAUSE_DROP_CTRL, rxb_pause_ctrl);
	}

	/* Enable generation of pause frames if enabled */
	wr32(FBNIC_CMAC_CONFIG_TXFC_CTRL,
	     fbn->tx_pause ? FBNIC_CMAC_CONFIG_TXFC_CTRL_PAUSE_GPP : 0);

	/* Enable Pause at the RXB */
	if (fbn->tx_pause) {
		rxb_pause_ctrl |=
			FIELD_PREP(FBNIC_RXB_PAUSE_DROP_CTRL_PAUSE_ENABLE,
				   FBNIC_PAUSE_EN_MASK);
		wr32(FBNIC_RXB_PAUSE_DROP_CTRL, rxb_pause_ctrl);
	}

	/* Enable processing of all general pause types if enabled*/
	wr32(FBNIC_CMAC_CONFIG_RXFC_CTRL1,
	     fbn->rx_pause ? (FBNIC_CMAC_CONFIG_RXFC_CTRL1_PAUSE_GPP |
			      FBNIC_CMAC_CONFIG_RXFC_CTRL1_EN_GCP |
			      FBNIC_CMAC_CONFIG_RXFC_CTRL1_EN_GPP) : 0);
	wr32(FBNIC_CMAC_CONFIG_RXFC_CTRL2,
	     fbn->rx_pause ? (FBNIC_CMAC_CONFIG_RXFC_CTRL2_CHK_MC_GCP |
			      FBNIC_CMAC_CONFIG_RXFC_CTRL2_CHK_ET_GCP |
			      FBNIC_CMAC_CONFIG_RXFC_CTRL2_CHK_OP_GCP |
			      FBNIC_CMAC_CONFIG_RXFC_CTRL2_CHK_MC_GPP |
			      FBNIC_CMAC_CONFIG_RXFC_CTRL2_CHK_ET_GPP |
			      FBNIC_CMAC_CONFIG_RXFC_CTRL2_CHK_OP_GPP) : 0);
}

static int fbnic_mac_config_fec_fpga(struct fbnic_dev *fbd)
{
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);

	/* Enable RS-FEC */
	wr32(FBNIC_CMAC_CONFIG_RSFEC_CTRL,
	     fbn->fec ? (FBNIC_CMAC_CONFIG_RSFEC_CTRL_CORR_EN |
			 FBNIC_CMAC_CONFIG_RSFEC_CTRL_IND_EN |
			 FBNIC_CMAC_CONFIG_RSFEC_CTRL_IND_MODE) : 0);
	wr32(FBNIC_CMAC_CONFIG_RSFEC_ENABLE,
	     fbn->fec ? (FBNIC_CMAC_CONFIG_RSFEC_ENABLE_RX |
			 FBNIC_CMAC_CONFIG_RSFEC_ENABLE_TX) : 0);

	return 0;
}

static int fbnic_mac_get_link_event_fpga(struct fbnic_dev *fbd)
{
	u32 cmac_int_sts;

	cmac_int_sts = rd32(FBNIC_CMAC_INTR_STS);

	if (cmac_int_sts & FBNIC_CMAC_INTR_RX_LINK_DOWN)
		return -1;

	return (cmac_int_sts & FBNIC_CMAC_INTR_RX_LINK_UP) ? 1 : 0;
}

static int fbnic_mac_enable_fpga(struct fbnic_dev *fbd)
{
	/* Mask and clear the CMAC interrupt, will be enabled by link handler */
	wr32(FBNIC_CMAC_INTR_MASK, ~0);
	wr32(FBNIC_CMAC_INTR_STS, ~0);

	/* Configure flow control */
	fbnic_mac_config_pause_fpga(fbd);

	/* Configure Forward Error Correction */
	fbnic_mac_config_fec_fpga(fbd);

	/* Enable Tx/Rx link */
	wr32(FBNIC_CMAC_CONFIG_TX, FBNIC_CMAC_CONFIG_TX_SEND_RFI);
	wr32(FBNIC_CMAC_CONFIG_RX, FBNIC_CMAC_CONFIG_RX_ENABLE);

	/* Report starting state as "Link Event" to force detection of link */
	fbd->link_state = FBNIC_LINK_EVENT;

	return 0;
}

static void fbnic_mac_disable_fpga(struct fbnic_dev *fbd)
{
	/* Clear link state to disable any further transitions */
	fbd->link_state = FBNIC_LINK_DISABLED;

	wr32(FBNIC_CMAC_CONFIG_TX, 0);
	wr32(FBNIC_CMAC_CONFIG_RX, 0);

	/* This may already be 0, but make sure we clear it */
	wr32(FBNIC_CMAC_GT_LOOPBACK_REG, 0);
}

static void fbnic_mac_stat_rd64(struct fbnic_dev *fbd, u32 reg, bool reset,
				struct fbnic_stat_counter *stat)
{
	u64 new_reg_value;

	new_reg_value = fbnic_stat_rd64(fbd, reg, 1);
	if (!reset)
		stat->value += new_reg_value - stat->u.old_reg_value_64;
	stat->u.old_reg_value_64 = new_reg_value;
}

#define mac_stat_rd64(__stat, __CSR) \
	fbnic_mac_stat_rd64(fbd, FBNIC_##__CSR##_L, reset, &(__stat))

static void
fbnic_mac_get_pause_stats_fpga(struct fbnic_dev *fbd, bool reset,
			       struct fbnic_pause_stats *pause_stats)
{
	mac_stat_rd64(pause_stats->tx_pause_frames, CMAC_STAT_TX_PAUSE);
	mac_stat_rd64(pause_stats->rx_pause_frames, CMAC_STAT_RX_PAUSE);
}

static void
fbnic_mac_get_fec_stats_fpga(struct fbnic_dev *fbd, bool reset,
			     struct fbnic_fec_stats *fec_stats)
{
	mac_stat_rd64(fec_stats->corrected_blocks.total,
		      CMAC_STAT_RX_RSFEC_CORRECTED);
	mac_stat_rd64(fec_stats->uncorrectable_blocks.total,
		      CMAC_STAT_RX_RSFEC_UNCORRECTED);
}

static void
fbnic_mac_get_eth_mac_stats_fpga(struct fbnic_dev *fbd, bool reset,
				 struct fbnic_eth_mac_stats *mac_stats)
{
	mac_stat_rd64(mac_stats->FramesTransmittedOK,
		      CMAC_STAT_TX_TOTAL_GOOD_PACKETS);
	mac_stat_rd64(mac_stats->OctetsTransmittedOK,
		      CMAC_STAT_TX_TOTAL_GOOD_BYTES);
	mac_stat_rd64(mac_stats->MulticastFramesXmittedOK,
		      CMAC_STAT_TX_MULTICAST);
	mac_stat_rd64(mac_stats->BroadcastFramesXmittedOK,
		      CMAC_STAT_TX_BROADCAST);
	mac_stat_rd64(mac_stats->FramesLostDueToIntMACXmitError,
		      CMAC_STAT_TX_FRAME_ERROR);

	mac_stat_rd64(mac_stats->FramesReceivedOK,
		      CMAC_STAT_RX_TOTAL_GOOD_PACKETS);
	mac_stat_rd64(mac_stats->OctetsReceivedOK,
		      CMAC_STAT_RX_TOTAL_GOOD_BYTES);
	mac_stat_rd64(mac_stats->MulticastFramesReceivedOK,
		      CMAC_STAT_RX_MULTICAST);
	mac_stat_rd64(mac_stats->BroadcastFramesReceivedOK,
		      CMAC_STAT_RX_BROADCAST);
	mac_stat_rd64(mac_stats->FrameCheckSequenceErrors,
		      CMAC_STAT_RX_PACKET_BAD_FCS);
	mac_stat_rd64(mac_stats->FrameTooLongErrors,
		      CMAC_STAT_RX_TOOLONG);
	mac_stat_rd64(mac_stats->FramesLostDueToIntMACRcvError,
		      CMAC_STAT_RX_BAD_CODE);
}

static void
fbnic_mac_get_eth_ctrl_stats_fpga(struct fbnic_dev *fbd, bool reset,
				  struct fbnic_eth_ctrl_stats *ctrl_stats)
{
}

static const struct fbnic_rmon_hist_range fbnic_mac_rmon_ranges_fpga[] = {
	{    0,   64 },
	{   65,  127 },
	{  128,  255 },
	{  256,  511 },
	{  512, 1023 },
	{ 1024, 1518 },
	{ 1519, 1522 },
	{ 1523, 1548 },
	{ 1549, 2047 },
	{ 2048, 4095 },
	{ 4096, 8191 },
	{ 8192, 9215 },
	{ 9216, FBNIC_MAX_JUMBO_FRAME_SIZE },
	{}
};

static void
fbnic_mac_get_rmon_stats_fpga(struct fbnic_dev *fbd, bool reset,
			      struct fbnic_rmon_stats *rmon_stats)
{
	mac_stat_rd64(rmon_stats->undersize_pkts,
		      CMAC_STAT_RX_UNDERSIZE);
	mac_stat_rd64(rmon_stats->oversize_pkts,
		      CMAC_STAT_RX_OVERSIZE);
	mac_stat_rd64(rmon_stats->fragments,
		      CMAC_STAT_RX_FRAGMENT);
	mac_stat_rd64(rmon_stats->jabbers,
		      CMAC_STAT_RX_JABBER);

	mac_stat_rd64(rmon_stats->hist[0],
		      CMAC_STAT_RX_PACKET_64_BYTES);
	mac_stat_rd64(rmon_stats->hist[1],
		      CMAC_STAT_RX_PACKET_65_127_BYTES);
	mac_stat_rd64(rmon_stats->hist[2],
		      CMAC_STAT_RX_PACKET_128_255_BYTES);
	mac_stat_rd64(rmon_stats->hist[3],
		      CMAC_STAT_RX_PACKET_256_511_BYTES);
	mac_stat_rd64(rmon_stats->hist[4],
		      CMAC_STAT_RX_PACKET_512_1023_BYTES);
	mac_stat_rd64(rmon_stats->hist[5],
		      CMAC_STAT_RX_PACKET_1024_1518_BYTES);
	mac_stat_rd64(rmon_stats->hist[6],
		      CMAC_STAT_RX_PACKET_1519_1522_BYTES);
	mac_stat_rd64(rmon_stats->hist[7],
		      CMAC_STAT_RX_PACKET_1523_1548_BYTES);
	mac_stat_rd64(rmon_stats->hist[8],
		      CMAC_STAT_RX_PACKET_1549_2047_BYTES);
	mac_stat_rd64(rmon_stats->hist[9],
		      CMAC_STAT_RX_PACKET_2048_4095_BYTES);
	mac_stat_rd64(rmon_stats->hist[10],
		      CMAC_STAT_RX_PACKET_4096_8191_BYTES);
	mac_stat_rd64(rmon_stats->hist[11],
		      CMAC_STAT_RX_PACKET_8192_9215_BYTES);
	mac_stat_rd64(rmon_stats->hist[12],
		      CMAC_STAT_RX_PACKET_9216_MAX_BYTES);

	mac_stat_rd64(rmon_stats->hist_tx[0],
		      CMAC_STAT_TX_PACKET_64_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[1],
		      CMAC_STAT_TX_PACKET_65_127_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[2],
		      CMAC_STAT_TX_PACKET_128_255_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[3],
		      CMAC_STAT_TX_PACKET_256_511_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[4],
		      CMAC_STAT_TX_PACKET_512_1023_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[5],
		      CMAC_STAT_TX_PACKET_1024_1518_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[6],
		      CMAC_STAT_TX_PACKET_1519_1522_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[7],
		      CMAC_STAT_TX_PACKET_1523_1548_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[8],
		      CMAC_STAT_TX_PACKET_1549_2047_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[9],
		      CMAC_STAT_TX_PACKET_2048_4095_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[10],
		      CMAC_STAT_TX_PACKET_4096_8191_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[11],
		      CMAC_STAT_TX_PACKET_8192_9215_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[12],
		      CMAC_STAT_TX_PACKET_9216_MAX_BYTES);
}

static void fbnic_mac_get_link_settings_fpga(struct fbnic_dev *fbd,
					     struct ethtool_link_ksettings *cmd)
{
	__ETHTOOL_DECLARE_LINK_MODE_MASK(supp) = { 0 };

	cmd->base.port = PORT_DA;
	cmd->base.autoneg = AUTONEG_DISABLE;
	if (netif_carrier_ok(fbd->netdev)) {
		cmd->base.duplex = DUPLEX_FULL;
		cmd->base.speed = SPEED_100000;
	} else {
		cmd->base.duplex = DUPLEX_UNKNOWN;
		cmd->base.speed = SPEED_UNKNOWN;
	}

	linkmode_set_bit(ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT, supp);

	linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_NONE_BIT, supp);
	linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_RS_BIT, supp);

	linkmode_set_bit(ETHTOOL_LINK_MODE_Pause_BIT, supp);
	linkmode_set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, supp);

	linkmode_set_bit(ETHTOOL_LINK_MODE_FIBRE_BIT, supp);

	linkmode_copy(cmd->link_modes.supported, supp);
}

static int fbnic_mac_get_temp_fpga(struct fbnic_dev *fbd, long *val)
{
	unsigned int degrees = rd32(FBNIC_CMS_QSPI_FPGA_TEMP_INS);

	/* Capture obvious range errors and read failures */
	if (degrees > INT_MAX)
		return -EIO;

	/* multiply by 1000 to convert degrees to millidegrees */
	*val = degrees * 1000;

	return 0;
}

static int fbnic_mac_get_voltage_fpga(struct fbnic_dev *fbd, long *val)
{
	unsigned int millivolts = rd32(FBNIC_CMS_QSPI_PEX_12V_INS);

	/* Capture obvious range errors and read failures */
	if (millivolts > INT_MAX)
		return -EIO;

	/* divide by 16 to fake this being a 750mv input which is what
	 * the final ASIC will have.
	 */
	*val = millivolts / 16;

	return 0;
}

static int fbnic_mac_get_sensor_fpga(struct fbnic_dev *fbd, int id, long *val)
{
	switch (id) {
	case FBNIC_SENSOR_TEMP:
		return fbnic_mac_get_temp_fpga(fbd, val);
	case FBNIC_SENSOR_VOLTAGE:
		return fbnic_mac_get_voltage_fpga(fbd, val);
	default:
		break;
	}

	return -EINVAL;
}

static int fbnic_enable_loopback_fpga(struct fbnic_dev *fbd)
{
	/* enable near-end PMA loopback */
	wr32(FBNIC_CMAC_GT_LOOPBACK_REG, 2);
	wr32(FBNIC_CMAC_CONFIG_TX, FBNIC_CMAC_CONFIG_TX_ENABLE);

	return 0;
}

static const struct fbnic_mac fbnic_mac_fpga = {
	.enable = fbnic_mac_enable_fpga,
	.disable = fbnic_mac_disable_fpga,
	.init_regs = fbnic_mac_init_regs,
	.set_addr = fbnic_mac_set_addr_fpga,
	.get_link = fbnic_mac_get_link_fpga,
	.get_link_event = fbnic_mac_get_link_event_fpga,
	.config_fec = fbnic_mac_config_fec_fpga,
	.config_pause = fbnic_mac_config_pause_fpga,
	.get_fec_stats = fbnic_mac_get_fec_stats_fpga,
	.get_eth_mac_stats = fbnic_mac_get_eth_mac_stats_fpga,
	.get_eth_ctrl_stats = fbnic_mac_get_eth_ctrl_stats_fpga,
	.get_rmon_stats = fbnic_mac_get_rmon_stats_fpga,
	.get_pause_stats = fbnic_mac_get_pause_stats_fpga,
	.get_link_settings = fbnic_mac_get_link_settings_fpga,
	.get_sensor = fbnic_mac_get_sensor_fpga,
	.enable_loopback = fbnic_enable_loopback_fpga,
	.rmon_ranges = fbnic_mac_rmon_ranges_fpga,
};

static int fbnic_mac_get_link_event_asic(struct fbnic_dev *fbd)
{
	u32 pcs_intr_mask = rd32(FBNIC_MAC_PCS_INTR_STS);

	if (pcs_intr_mask & FBNIC_MAC_PCS_INTR_LINK_DOWN)
		return -1;

	return (pcs_intr_mask & FBNIC_MAC_PCS_INTR_LINK_UP) ? 1 : 0;
}

static u32 __fbnic_mac_config_asic(struct fbnic_dev *fbd)
{
	/* Enable MAC Promiscuous mode and Tx padding */
	u32 command_config = FBNIC_MAC_COMMAND_CONFIG_TX_PAD_EN |
			     FBNIC_MAC_COMMAND_CONFIG_PROMISC_EN;
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);
	u32 rxb_pause_ctrl;

	/* Set class 0 Quanta and refresh */
	wr32(FBNIC_MAC_CL01_PAUSE_QUANTA, 0xffff);
	wr32(FBNIC_MAC_CL01_QUANTA_THRESH, 0x7fff);

	/* Enable generation of pause frames if enabled */
	rxb_pause_ctrl = rd32(FBNIC_RXB_PAUSE_DROP_CTRL);
	rxb_pause_ctrl &= ~FBNIC_RXB_PAUSE_DROP_CTRL_PAUSE_ENABLE;
	if (!fbn->tx_pause)
		command_config |= FBNIC_MAC_COMMAND_CONFIG_TX_PAUSE_DIS;
	else
		rxb_pause_ctrl |=
			FIELD_PREP(FBNIC_RXB_PAUSE_DROP_CTRL_PAUSE_ENABLE,
				   FBNIC_PAUSE_EN_MASK);
	wr32(FBNIC_RXB_PAUSE_DROP_CTRL, rxb_pause_ctrl);

	if (!fbn->rx_pause)
		command_config |= FBNIC_MAC_COMMAND_CONFIG_RX_PAUSE_DIS;

	/* Disable fault handling if no FEC is requested */
	if ((fbn->fec & FBNIC_FEC_MODE_MASK) == FBNIC_FEC_OFF)
		command_config |= FBNIC_MAC_COMMAND_CONFIG_FLT_HDL_DIS;

	return command_config;
}

static bool fbnic_mac_get_pcs_link_status(struct fbnic_dev *fbd)
{
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);
	u32 pcs_status, lane_mask = ~0;

#ifndef REMOVE_WORKAROUND
	/* The Palladium emulation environment doesn't have a PCS block in
	 * it. As a result it returns 0 on all reads. The PCS control1
	 * register should have the "Speed Always" and "Speed Select Always"
	 * bits set. If there are no bits set, assume we are on Palladium and
	 * force the link up.
	 */
	if (!rd32(FBNIC_PCS_CONTROL1_0))
		return true;
#endif
	pcs_status = rd32(FBNIC_MAC_PCS_STS0);
	if (!(pcs_status & FBNIC_MAC_PCS_STS0_LINK))
		return false;

	/* Define the expected lane mask for the status bits we need to check */
	switch (fbn->link_mode & FBNIC_LINK_MODE_MASK) {
	case FBNIC_LINK_100R2:
		lane_mask = 0xf;
		break;
	case FBNIC_LINK_50R1:
		lane_mask = 3;
		break;
	case FBNIC_LINK_50R2:
		switch (fbn->fec & FBNIC_FEC_MODE_MASK) {
		case FBNIC_FEC_OFF:
			lane_mask = 0x63;
			break;
		case FBNIC_FEC_RS:
			lane_mask = 5;
			break;
		case FBNIC_FEC_BASER:
			lane_mask = 0xf;
			break;
		}
		break;
	case FBNIC_LINK_25R1:
		lane_mask = 1;
		break;
	}

	/* Use an XOR to remove the bits we expect to see set */
	switch (fbn->fec & FBNIC_FEC_MODE_MASK) {
	case FBNIC_FEC_OFF:
		lane_mask ^= FIELD_GET(FBNIC_MAC_PCS_STS0_BLOCK_LOCK,
				       pcs_status);
		break;
	case FBNIC_FEC_RS:
		lane_mask ^= FIELD_GET(FBNIC_MAC_PCS_STS0_AMPS_LOCK,
				       pcs_status);
		break;
	case FBNIC_FEC_BASER:
		lane_mask ^= FIELD_GET(FBNIC_MAC_PCS_STS1_FCFEC_LOCK,
				       rd32(FBNIC_MAC_PCS_STS1));
		break;
	}

	/* If all lanes cancelled then we have a lock on all lanes */
	return !lane_mask;
}

#define FBNIC_MAC_ENET_LED_DEFAULT				\
	(FIELD_PREP(FBNIC_MAC_ENET_LED_AMBER_MASK,		\
		    FBNIC_MAC_ENET_LED_AMBER_50G |		\
		    FBNIC_MAC_ENET_LED_AMBER_25G) |		\
	 FIELD_PREP(FBNIC_MAC_ENET_LED_BLUE_MASK,		\
		    FBNIC_MAC_ENET_LED_BLUE_100G |		\
		    FBNIC_MAC_ENET_LED_BLUE_50G))
#define FBNIC_MAC_ENET_LED_ACTIVITY_DEFAULT			\
	FIELD_PREP(FBNIC_MAC_ENET_LED_BLINK_RATE_MASK,		\
		   FBNIC_MAC_ENET_LED_BLINK_RATE_5HZ)
#define FBNIC_MAC_ENET_LED_ACTIVITY_ON				\
	FIELD_PREP(FBNIC_MAC_ENET_LED_OVERRIDE_EN,		\
		   FBNIC_MAC_ENET_LED_OVERRIDE_ACTIVITY)
#define FBNIC_MAC_ENET_LED_AMBER				\
	(FIELD_PREP(FBNIC_MAC_ENET_LED_OVERRIDE_EN,		\
		    FBNIC_MAC_ENET_LED_OVERRIDE_BLUE |		\
		    FBNIC_MAC_ENET_LED_OVERRIDE_AMBER) |	\
	 FIELD_PREP(FBNIC_MAC_ENET_LED_OVERRIDE_VAL,		\
		    FBNIC_MAC_ENET_LED_OVERRIDE_AMBER))
#define FBNIC_MAC_ENET_LED_BLUE					\
	(FIELD_PREP(FBNIC_MAC_ENET_LED_OVERRIDE_EN,		\
		    FBNIC_MAC_ENET_LED_OVERRIDE_BLUE |		\
		    FBNIC_MAC_ENET_LED_OVERRIDE_AMBER) |	\
	 FIELD_PREP(FBNIC_MAC_ENET_LED_OVERRIDE_VAL,		\
		    FBNIC_MAC_ENET_LED_OVERRIDE_BLUE))

static void fbnic_set_led_state_asic(struct fbnic_dev *fbd, int state)
{
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);
	u32 led_csr = FBNIC_MAC_ENET_LED_DEFAULT;

	switch (state) {
	case FBNIC_LED_OFF:
		led_csr |= FBNIC_MAC_ENET_LED_AMBER |
			   FBNIC_MAC_ENET_LED_ACTIVITY_ON;
		break;
	case FBNIC_LED_ON:
		led_csr |= FBNIC_MAC_ENET_LED_BLUE |
			   FBNIC_MAC_ENET_LED_ACTIVITY_ON;
		break;
	case FBNIC_LED_RESTORE:
		led_csr |= FBNIC_MAC_ENET_LED_ACTIVITY_DEFAULT;

		/* Don't set LEDs on if link isn't up */
		if (fbd->link_state != FBNIC_LINK_UP)
			break;
		/* Don't set LEDs for supported autoneg modes */
		if ((fbn->link_mode & FBNIC_LINK_AUTO) &&
		    (fbn->link_mode & FBNIC_LINK_MODE_MASK) != FBNIC_LINK_50R2)
			break;

		/* Set LEDs based on link speed
		 * 100G	Blue,
		 * 50G	Blue & Amber
		 * 25G	Amber
		 */
		switch (fbn->link_mode & FBNIC_LINK_MODE_MASK) {
		case FBNIC_LINK_100R2:
			led_csr |= FBNIC_MAC_ENET_LED_BLUE;
			break;
		case FBNIC_LINK_50R1:
		case FBNIC_LINK_50R2:
			led_csr |= FBNIC_MAC_ENET_LED_BLUE;
			fallthrough;
		case FBNIC_LINK_25R1:
			led_csr |= FBNIC_MAC_ENET_LED_AMBER;
			break;
		}
		break;
	default:
		return;
	}

	wr32(FBNIC_MAC_ENET_LED, led_csr);
}

static bool fbnic_mac_get_link_asic(struct fbnic_dev *fbd)
{
	u32 cmd_cfg, mac_ctrl;
	int link_direction;
	bool link;

	/* If disabled do not update link_state nor change settings */
	if (fbd->link_state == FBNIC_LINK_DISABLED)
		return false;

	link_direction = fbnic_mac_get_link_event_asic(fbd);

	/* Clear interrupt state due to recent changes. */
	wr32(FBNIC_MAC_PCS_INTR_STS,
	     FBNIC_MAC_PCS_INTR_LINK_DOWN | FBNIC_MAC_PCS_INTR_LINK_UP);

	/* If link bounced down clear the PCS_STS bit related to link */
	if (link_direction < 0) {
		wr32(FBNIC_MAC_PCS_STS0, FBNIC_MAC_PCS_STS0_LINK |
					 FBNIC_MAC_PCS_STS0_BLOCK_LOCK |
					 FBNIC_MAC_PCS_STS0_AMPS_LOCK);
		wr32(FBNIC_MAC_PCS_STS1, FBNIC_MAC_PCS_STS1_FCFEC_LOCK);
	}

	link = fbnic_mac_get_pcs_link_status(fbd);
	cmd_cfg = __fbnic_mac_config_asic(fbd);
	mac_ctrl = rd32(FBNIC_MAC_CTRL);

	/* Depending on the event we will unmask the cause that will force a
	 * transition, and update the Tx to reflect our status to the remote
	 * link partner.
	 */
	if (link) {
		mac_ctrl &= ~(FBNIC_MAC_CTRL_RESET_FF_TX_CLK |
			      FBNIC_MAC_CTRL_RESET_TX_CLK |
			      FBNIC_MAC_CTRL_RESET_FF_RX_CLK |
			      FBNIC_MAC_CTRL_RESET_RX_CLK);
		cmd_cfg |= FBNIC_MAC_COMMAND_CONFIG_RX_ENA |
			   FBNIC_MAC_COMMAND_CONFIG_TX_ENA;
		fbd->link_state = FBNIC_LINK_UP;
	} else {
		mac_ctrl |= FBNIC_MAC_CTRL_RESET_FF_TX_CLK |
			    FBNIC_MAC_CTRL_RESET_TX_CLK |
			    FBNIC_MAC_CTRL_RESET_FF_RX_CLK |
			    FBNIC_MAC_CTRL_RESET_RX_CLK;
		fbd->link_state = FBNIC_LINK_DOWN;
	}

	wr32(FBNIC_MAC_CTRL, mac_ctrl);
	wr32(FBNIC_MAC_COMMAND_CONFIG, cmd_cfg);

	/* Toggle LED settings to enable LEDs manually if necessary */
	fbnic_set_led_state_asic(fbd, FBNIC_LED_RESTORE);

	if (link_direction)
		wr32(FBNIC_MAC_PCS_INTR_MASK,
		     link ?  ~FBNIC_MAC_PCS_INTR_LINK_DOWN :
			     ~FBNIC_MAC_PCS_INTR_LINK_UP);

	return link;
}

static void fbnic_mac_config_pause_asic(struct fbnic_dev *fbd)
{
	/* Force link check to reconfigure pause and FEC settings */
	fbnic_mac_get_link_asic(fbd);
}

static void fbnic_mac_pre_config(struct fbnic_dev *fbd)
{
	u32 serdes_ctrl, mac_ctrl, xif_mode, enet_fec_ctrl = 0;
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);

	/* set reset bits and enable appending of Tx CRC */
	mac_ctrl = FBNIC_MAC_CTRL_RESET_FF_TX_CLK |
		   FBNIC_MAC_CTRL_RESET_FF_RX_CLK |
		   FBNIC_MAC_CTRL_RESET_TX_CLK |
		   FBNIC_MAC_CTRL_RESET_RX_CLK |
		   FBNIC_MAC_CTRL_TX_CRC;
	serdes_ctrl = FBNIC_MAC_SERDES_CTRL_RESET_PCS_REF_CLK |
		      FBNIC_MAC_SERDES_CTRL_RESET_F91_REF_CLK |
		      FBNIC_MAC_SERDES_CTRL_RESET_SD_TX_CLK |
		      FBNIC_MAC_SERDES_CTRL_RESET_SD_RX_CLK;
	xif_mode = FBNIC_MAC_XIF_MODE_TX_MAC_RS_ERR;

	switch (fbn->link_mode & FBNIC_LINK_MODE_MASK) {
	case FBNIC_LINK_25R1:
		/* Enable XGMII to run w/ 10G pacer */
		xif_mode |= FBNIC_MAC_XIF_MODE_XGMII;
		serdes_ctrl |= FBNIC_MAC_SERDES_CTRL_PACER_10G_MASK;
		if (fbn->fec & FBNIC_FEC_RS)
			serdes_ctrl |= FBNIC_MAC_SERDES_CTRL_F91_1LANE_IN0;
		break;
	case FBNIC_LINK_50R2:
		if (!(fbn->fec & FBNIC_FEC_RS))
			serdes_ctrl |= FBNIC_MAC_SERDES_CTRL_RXLAUI_ENA_IN0;
		break;
	case FBNIC_LINK_100R2:
		mac_ctrl |= FBNIC_MAC_CTRL_CFG_MODE128;
		serdes_ctrl |= FBNIC_MAC_SERDES_CTRL_PCS100_ENA_IN0;
		enet_fec_ctrl |= FBNIC_MAC_ENET_FEC_CTRL_KP_MODE_ENA;
		fallthrough;
	case FBNIC_LINK_50R1:
		serdes_ctrl |= FBNIC_MAC_SERDES_CTRL_SD_8X;
		if (fbn->fec & FBNIC_FEC_AUTO)
			fbn->fec = FBNIC_FEC_AUTO | FBNIC_FEC_RS;
		break;
	}

	switch (fbn->fec & FBNIC_FEC_MODE_MASK) {
	case FBNIC_FEC_RS:
		enet_fec_ctrl |= FBNIC_MAC_ENET_FEC_CTRL_F91_ENA;
		break;
	case FBNIC_FEC_BASER:
		enet_fec_ctrl |= FBNIC_MAC_ENET_FEC_CTRL_FEC_ENA;
		break;
	case FBNIC_FEC_OFF:
		break;
	default:
		dev_err(fbd->dev, "Unsupported FEC mode detected");
	}

	/* Store updated config to MAC */
	wr32(FBNIC_MAC_CTRL, mac_ctrl);
	wr32(FBNIC_MAC_SERDES_CTRL, serdes_ctrl);
	wr32(FBNIC_MAC_XIF_MODE, xif_mode);
	wr32(FBNIC_MAC_ENET_FEC_CTRL, enet_fec_ctrl);

	/* flush writes to allow time for MAC to go into resets */
	wrfl();

	/* Set signal detect for all lanes */
	wr32(FBNIC_MAC_ENET_SIG_DETECT, FBNIC_MAC_ENET_SIG_DETECT_PCS_MASK);
}

static void fbnic_mac_pcs_config(struct fbnic_dev *fbd)
{
	u32 pcs_mode = 0, rsfec_ctrl = 0, vl_intvl = 0;
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);
	int i;

	/* Set link mode specific lane and FEC values */
	switch (fbn->link_mode & FBNIC_LINK_MODE_MASK) {
	case FBNIC_LINK_25R1:
		if (fbn->fec & FBNIC_FEC_RS)
			vl_intvl = 20479;
		else
			pcs_mode |= FBNIC_PCS_MODE_DISABLE_MLD;
		pcs_mode |= FBNIC_PCS_MODE_HI_BER25 |
			    FBNIC_PCS_MODE_ENA_CLAUSE49;
		break;
	case FBNIC_LINK_50R1:
		rsfec_ctrl |= FBNIC_RSFEC_CONTROL_KP_ENABLE;
		fallthrough;
	case FBNIC_LINK_50R2:
		rsfec_ctrl |= FBNIC_RSFEC_CONTROL_TC_PAD_ALTER;
		vl_intvl = 20479;
		break;
	case FBNIC_LINK_100R2:
		rsfec_ctrl |= FBNIC_RSFEC_CONTROL_AM16_COPY_DIS |
			      FBNIC_RSFEC_CONTROL_KP_ENABLE;
		pcs_mode |= FBNIC_PCS_MODE_DISABLE_MLD;
		/* TBD: Spreadsheet was disabling MLD and enabling Clause 49.
		 * skip that for now as I am not sure that is correct.
		 */
		vl_intvl = 16383;
		break;
	}

	for (i = 0; i < 4; i++)
		wr32(FBNIC_RSFEC_CONTROL(i), rsfec_ctrl);

	wr32(FBNIC_PCS_MODE_VL_CHAN_0, pcs_mode);
	wr32(FBNIC_PCS_MODE_VL_CHAN_1, pcs_mode);

	wr32(FBNIC_PCS_VENDOR_VL_INTVL_0, vl_intvl);
	wr32(FBNIC_PCS_VENDOR_VL_INTVL_1, vl_intvl);

	/* Update IPG to account for vl_intvl */
	wr32(FBNIC_MAC_TX_IPG_LENGTH,
	     FIELD_PREP(FBNIC_MAC_TX_IPG_LENGTH_COMP, vl_intvl) | 0xc);

	/* Program lane markers indicating which lanes are in use
	 * and what speeds we are transmitting at.
	 */
	switch (fbn->link_mode & FBNIC_LINK_MODE_MASK) {
	case FBNIC_LINK_100R2:
		wr32(FBNIC_PCS_VL0_0_CHAN_0, 0x68c1);
		wr32(FBNIC_PCS_VL0_1_CHAN_0, 0x21);
		wr32(FBNIC_PCS_VL1_0_CHAN_0, 0x719d);
		wr32(FBNIC_PCS_VL1_1_CHAN_0, 0x8e);
		wr32(FBNIC_PCS_VL2_0_CHAN_0, 0x4b59);
		wr32(FBNIC_PCS_VL2_1_CHAN_0, 0xe8);
		wr32(FBNIC_PCS_VL3_0_CHAN_0, 0x954d);
		wr32(FBNIC_PCS_VL3_1_CHAN_0, 0x7b);
		wr32(FBNIC_PCS_VL0_0_CHAN_1, 0x68c1);
		wr32(FBNIC_PCS_VL0_1_CHAN_1, 0x21);
		wr32(FBNIC_PCS_VL1_0_CHAN_1, 0x719d);
		wr32(FBNIC_PCS_VL1_1_CHAN_1, 0x8e);
		wr32(FBNIC_PCS_VL2_0_CHAN_1, 0x4b59);
		wr32(FBNIC_PCS_VL2_1_CHAN_1, 0xe8);
		wr32(FBNIC_PCS_VL3_0_CHAN_1, 0x954d);
		wr32(FBNIC_PCS_VL3_1_CHAN_1, 0x7b);
		break;
	case FBNIC_LINK_50R2:
		wr32(FBNIC_PCS_VL0_0_CHAN_1, 0x7690);
		wr32(FBNIC_PCS_VL0_1_CHAN_1, 0x47);
		wr32(FBNIC_PCS_VL1_0_CHAN_1, 0xc4f0);
		wr32(FBNIC_PCS_VL1_1_CHAN_1, 0xe6);
		wr32(FBNIC_PCS_VL2_0_CHAN_1, 0x65c5);
		wr32(FBNIC_PCS_VL2_1_CHAN_1, 0x9b);
		wr32(FBNIC_PCS_VL3_0_CHAN_1, 0x79a2);
		wr32(FBNIC_PCS_VL3_1_CHAN_1, 0x3d);
		fallthrough;
	case FBNIC_LINK_50R1:
		wr32(FBNIC_PCS_VL0_0_CHAN_0, 0x7690);
		wr32(FBNIC_PCS_VL0_1_CHAN_0, 0x47);
		wr32(FBNIC_PCS_VL1_0_CHAN_0, 0xc4f0);
		wr32(FBNIC_PCS_VL1_1_CHAN_0, 0xe6);
		wr32(FBNIC_PCS_VL2_0_CHAN_0, 0x65c5);
		wr32(FBNIC_PCS_VL2_1_CHAN_0, 0x9b);
		wr32(FBNIC_PCS_VL3_0_CHAN_0, 0x79a2);
		wr32(FBNIC_PCS_VL3_1_CHAN_0, 0x3d);
		break;
	case FBNIC_LINK_25R1:
		wr32(FBNIC_PCS_VL0_0_CHAN_0, 0x68c1);
		wr32(FBNIC_PCS_VL0_1_CHAN_0, 0x21);
		wr32(FBNIC_PCS_VL1_0_CHAN_0, 0xc4f0);
		wr32(FBNIC_PCS_VL1_1_CHAN_0, 0xe6);
		wr32(FBNIC_PCS_VL2_0_CHAN_0, 0x65c5);
		wr32(FBNIC_PCS_VL2_1_CHAN_0, 0x9b);
		wr32(FBNIC_PCS_VL3_0_CHAN_0, 0x79a2);
		wr32(FBNIC_PCS_VL3_1_CHAN_0, 0x3d);
		break;
	}
}

static bool fbnic_mac_pcs_reset_complete(struct fbnic_dev *fbd)
{
	return !(rd32(FBNIC_PCS_CONTROL1_0) & FBNIC_PCS_CONTROL1_RESET) &&
	       !(rd32(FBNIC_PCS_CONTROL1_1) & FBNIC_PCS_CONTROL1_RESET);
}

static int fbnic_mac_post_config(struct fbnic_dev *fbd)
{
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);
	u32 serdes_ctrl, reset_complete, lane_mask;
	int err;

	/* Clear resets for XPCS and F91 reference clocks */
	serdes_ctrl = rd32(FBNIC_MAC_SERDES_CTRL);
	serdes_ctrl &= ~FBNIC_MAC_SERDES_CTRL_RESET_PCS_REF_CLK;
	if (fbn->fec & FBNIC_FEC_RS)
		serdes_ctrl &= ~FBNIC_MAC_SERDES_CTRL_RESET_F91_REF_CLK;
	wr32(FBNIC_MAC_SERDES_CTRL, serdes_ctrl);

	/* Reset PCS and flush reset value */
	wr32(FBNIC_PCS_CONTROL1_0,
	     FBNIC_PCS_CONTROL1_RESET |
	     FBNIC_PCS_CONTROL1_SPEED_SELECT_ALWAYS |
	     FBNIC_PCS_CONTROL1_SPEED_ALWAYS);
	wr32(FBNIC_PCS_CONTROL1_1,
	     FBNIC_PCS_CONTROL1_RESET |
	     FBNIC_PCS_CONTROL1_SPEED_SELECT_ALWAYS |
	     FBNIC_PCS_CONTROL1_SPEED_ALWAYS);

	/* poll for completion of reset */
	err = readx_poll_timeout(fbnic_mac_pcs_reset_complete, fbd,
				 reset_complete, reset_complete,
				 1000, 150000);
	if (err)
		return err;

	/* Flush any stale link status info */
	wr32(FBNIC_MAC_PCS_STS0, FBNIC_MAC_PCS_STS0_LINK |
				 FBNIC_MAC_PCS_STS0_BLOCK_LOCK |
				 FBNIC_MAC_PCS_STS0_AMPS_LOCK);

	/* Report starting state as "Link Event" to force detection of link */
	fbd->link_state = FBNIC_LINK_EVENT;

	/* Force link down to allow for link detection */
	netif_carrier_off(fbn->netdev);

	/* create simple bitmask for 2 or 1 lane setups */
	lane_mask = (fbn->link_mode & FBNIC_LINK_MODE_R2) ? 3 : 1;

	/* release the brakes and allow Tx/Rx to come out of reset */
	serdes_ctrl &=
	     ~(FIELD_PREP(FBNIC_MAC_SERDES_CTRL_RESET_SD_TX_CLK, lane_mask) |
	       FIELD_PREP(FBNIC_MAC_SERDES_CTRL_RESET_SD_RX_CLK, lane_mask));
	wr32(FBNIC_MAC_SERDES_CTRL, serdes_ctrl);

	/* TBD: Clear the autoneg mask for now. Will need to leave this flag
	 * set at some point in the future when we start doing actual autoneg.
	 */
	fbn->link_mode &= ~FBNIC_LINK_AUTO;

	/* Ask firmware to configure the PHY for the correct encoding mode */
	return fbnic_fw_xmit_comphy_set_msg(fbd,
					    fbn->link_mode &
					    FBNIC_LINK_MODE_MASK);
}

static void fbnic_mac_get_fw_settings(struct fbnic_dev *fbd)
{
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);
	u8 fec = fbn->fec;
	u8 link_mode;

	/* Update FEC first to reflect FW current mode */
	if (fbn->fec & FBNIC_FEC_AUTO) {
		switch (fbd->fw_cap.link_fec) {
		case FBNIC_FW_LINK_FEC_NONE:
			fec = FBNIC_FEC_OFF;
			break;
		case FBNIC_FW_LINK_FEC_RS:
			fec = FBNIC_FEC_RS;
			break;
		case FBNIC_FW_LINK_FEC_BASER:
			fec = FBNIC_FEC_BASER;
			break;
		default:
			return;
		}
	}

	/* Do nothing if AUTO mode is not engaged */
	if (fbn->link_mode & FBNIC_LINK_AUTO) {
		switch (fbd->fw_cap.link_speed) {
		case FBNIC_FW_LINK_SPEED_25R1:
			link_mode = FBNIC_LINK_25R1;
			break;
		case FBNIC_FW_LINK_SPEED_50R2:
			link_mode = FBNIC_LINK_50R2;
			break;
		case FBNIC_FW_LINK_SPEED_50R1:
			link_mode = FBNIC_LINK_50R1;
			fec = FBNIC_FEC_RS;
			break;
		case FBNIC_FW_LINK_SPEED_100R2:
			link_mode = FBNIC_LINK_100R2;
			fec = FBNIC_FEC_RS;
			break;
		default:
			return;
		}

		fbn->link_mode = link_mode;
		fbn->fec = fec;
	}
}

static int fbnic_mac_enable_asic(struct fbnic_dev *fbd)
{
	/* Mask and clear the PCS interrupt, will be enabled by link handler */
	wr32(FBNIC_MAC_PCS_INTR_MASK, ~0);
	wr32(FBNIC_MAC_PCS_INTR_STS, ~0);

	/* Pull in settings from FW */
	fbnic_mac_get_fw_settings(fbd);

	/* Configure MAC registers */
	fbnic_mac_pre_config(fbd);

	/* Configure PCS block */
	fbnic_mac_pcs_config(fbd);

	/* Configure flow control and error correction */
	wr32(FBNIC_MAC_COMMAND_CONFIG, __fbnic_mac_config_asic(fbd));

	/* Configure maximum frame size */
	wr32(FBNIC_MAC_FRM_LENGTH, FBNIC_MAX_JUMBO_FRAME_SIZE);

	/* Configure LED defaults */
	fbnic_set_led_state_asic(fbd, FBNIC_LED_RESTORE);

	return fbnic_mac_post_config(fbd);
}

static void fbnic_mac_disable_asic(struct fbnic_dev *fbd)
{
	u32 mask = FBNIC_MAC_COMMAND_CONFIG_LOOPBACK_EN;
	u32 cmd_cfg = rd32(FBNIC_MAC_COMMAND_CONFIG);
	u32 mac_ctrl = rd32(FBNIC_MAC_CTRL);

	/* Clear link state to disable any further transitions */
	fbd->link_state = FBNIC_LINK_DISABLED;

	/* Clear Tx and Rx enable bits to disable MAC, ignore other values */
	if (!fbnic_bmc_present(fbd)) {
		mask |= FBNIC_MAC_COMMAND_CONFIG_RX_ENA |
			FBNIC_MAC_COMMAND_CONFIG_TX_ENA;
		mac_ctrl |= FBNIC_MAC_CTRL_RESET_FF_TX_CLK |
			    FBNIC_MAC_CTRL_RESET_TX_CLK |
			    FBNIC_MAC_CTRL_RESET_FF_RX_CLK |
			    FBNIC_MAC_CTRL_RESET_RX_CLK;

		/* Restore LED defaults */
		fbnic_set_led_state_asic(fbd, FBNIC_LED_RESTORE);
	}

	/* Check mask for enabled bits, if any set clear and write back */
	if (mask & cmd_cfg) {
		wr32(FBNIC_MAC_COMMAND_CONFIG, cmd_cfg & ~mask);
		wr32(FBNIC_MAC_CTRL, mac_ctrl);
	}

	/* Disable loopback, and flush write */
	wr32(FBNIC_PCS_CONTROL1_0,
	     FBNIC_PCS_CONTROL1_RESET |
	     FBNIC_PCS_CONTROL1_SPEED_SELECT_ALWAYS |
	     FBNIC_PCS_CONTROL1_SPEED_ALWAYS);
	wr32(FBNIC_PCS_CONTROL1_1,
	     FBNIC_PCS_CONTROL1_RESET |
	     FBNIC_PCS_CONTROL1_SPEED_SELECT_ALWAYS |
	     FBNIC_PCS_CONTROL1_SPEED_ALWAYS);
}

static void
fbnic_mac_get_pause_stats_asic(struct fbnic_dev *fbd, bool reset,
			       struct fbnic_pause_stats *pause_stats)
{
	mac_stat_rd64(pause_stats->tx_pause_frames, MAC_STAT_TX_PAUSE);
	mac_stat_rd64(pause_stats->rx_pause_frames, MAC_STAT_RX_PAUSE);
}

static void fbnic_rsfec_stat_rd64(struct fbnic_dev *fbd, u32 reg, bool reset,
				  struct fbnic_stat_counter *stat)
{
	u32 rsfec_stat;

	/* The RFSEC registers are only 16b wide each. So what we will have
	 * after the 64b read is 0x0000xxxx0000xxxx. To make it usable as
	 * a full stat we will shift the upper bits into the lower set of
	 * 0s and then mask off the math at 32b.
	 *
	 * Read ordering must be lower reg followed by upper reg.
	 */
	rsfec_stat = fbnic_rd32(fbd, reg) & 0xffff;
	rsfec_stat |= fbnic_rd32(fbd, reg + 1) << 16;

	/* RFSEC registers clear themselves upon being read we there is no
	 * need to store the old_reg_value.
	 */
	if (!reset)
		stat->value += rsfec_stat;
}

static void
fbnic_mac_get_fec_stats_asic(struct fbnic_dev *fbd, bool reset,
			     struct fbnic_fec_stats *s)
{
	int i;

	for (i = 0; i < FBNIC_RSFEC_MAX_LANES; i++) {
		fbnic_rsfec_stat_rd64(fbd, FBNIC_RSFEC_CCW_LO(i), reset,
				      &s->corrected_blocks.lanes[i]);
		fbnic_rsfec_stat_rd64(fbd, FBNIC_RSFEC_NCCW_LO(i), reset,
				      &s->uncorrectable_blocks.lanes[i]);
		fbnic_rsfec_stat_rd64(fbd, FBNIC_RSFEC_SYMBLERR_LO(i),
				      reset | !netif_carrier_ok(fbd->netdev),
				      &s->SymbolErrorDuringCarrier.lanes[i]);
	}
}

static void
fbnic_mac_get_eth_mac_stats_asic(struct fbnic_dev *fbd, bool reset,
				 struct fbnic_eth_mac_stats *mac_stats)
{
	mac_stat_rd64(mac_stats->OctetsReceivedOK,
		      MAC_STAT_RX_BYTE_COUNT);
	mac_stat_rd64(mac_stats->AlignmentErrors,
		      MAC_STAT_RX_ALIGN_ERROR);
	mac_stat_rd64(mac_stats->FrameTooLongErrors,
		      MAC_STAT_RX_TOOLONG);
	mac_stat_rd64(mac_stats->FramesReceivedOK,
		      MAC_STAT_RX_RECEIVED_OK);
	mac_stat_rd64(mac_stats->FrameCheckSequenceErrors,
		      MAC_STAT_RX_PACKET_BAD_FCS);
	mac_stat_rd64(mac_stats->FramesLostDueToIntMACRcvError,
		      MAC_STAT_RX_IFINERRORS);
	mac_stat_rd64(mac_stats->MulticastFramesReceivedOK,
		      MAC_STAT_RX_MULTICAST);
	mac_stat_rd64(mac_stats->BroadcastFramesReceivedOK,
		      MAC_STAT_RX_BROADCAST);

	mac_stat_rd64(mac_stats->OctetsTransmittedOK,
		      MAC_STAT_TX_BYTE_COUNT);
	mac_stat_rd64(mac_stats->FramesTransmittedOK,
		      MAC_STAT_TX_TRANSMITTED_OK);
	mac_stat_rd64(mac_stats->FramesLostDueToIntMACXmitError,
		      MAC_STAT_TX_IFOUTERRORS);
	mac_stat_rd64(mac_stats->MulticastFramesXmittedOK,
		      MAC_STAT_TX_MULTICAST);
	mac_stat_rd64(mac_stats->BroadcastFramesXmittedOK,
		      MAC_STAT_TX_BROADCAST);
}

static void
fbnic_mac_get_eth_ctrl_stats_asic(struct fbnic_dev *fbd, bool reset,
				  struct fbnic_eth_ctrl_stats *ctrl_stats)
{
	mac_stat_rd64(ctrl_stats->MACControlFramesReceived,
		      MAC_STAT_RX_CONTROL_FRAMES);
	mac_stat_rd64(ctrl_stats->MACControlFramesTransmitted,
		      MAC_STAT_TX_CONTROL_FRAMES);
}

static const struct fbnic_rmon_hist_range fbnic_mac_rmon_ranges_asic[] = {
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
fbnic_mac_get_rmon_stats_asic(struct fbnic_dev *fbd, bool reset,
			      struct fbnic_rmon_stats *rmon_stats)
{
	mac_stat_rd64(rmon_stats->undersize_pkts,
		      MAC_STAT_RX_UNDERSIZE);
	mac_stat_rd64(rmon_stats->oversize_pkts,
		      MAC_STAT_RX_OVERSIZE);
	mac_stat_rd64(rmon_stats->fragments,
		      MAC_STAT_RX_FRAGMENT);
	mac_stat_rd64(rmon_stats->jabbers,
		      MAC_STAT_RX_JABBER);

	mac_stat_rd64(rmon_stats->hist[0],
		      MAC_STAT_RX_PACKET_64_BYTES);
	mac_stat_rd64(rmon_stats->hist[1],
		      MAC_STAT_RX_PACKET_65_127_BYTES);
	mac_stat_rd64(rmon_stats->hist[2],
		      MAC_STAT_RX_PACKET_128_255_BYTES);
	mac_stat_rd64(rmon_stats->hist[3],
		      MAC_STAT_RX_PACKET_256_511_BYTES);
	mac_stat_rd64(rmon_stats->hist[4],
		      MAC_STAT_RX_PACKET_512_1023_BYTES);
	mac_stat_rd64(rmon_stats->hist[5],
		      MAC_STAT_RX_PACKET_1024_1518_BYTES);
	mac_stat_rd64(rmon_stats->hist[6],
		      RPC_STAT_RX_PACKET_1519_2047_BYTES);
	mac_stat_rd64(rmon_stats->hist[7],
		      RPC_STAT_RX_PACKET_2048_4095_BYTES);
	mac_stat_rd64(rmon_stats->hist[8],
		      RPC_STAT_RX_PACKET_4096_8191_BYTES);
	mac_stat_rd64(rmon_stats->hist[9],
		      RPC_STAT_RX_PACKET_8192_9216_BYTES);

	mac_stat_rd64(rmon_stats->hist_tx[0],
		      MAC_STAT_TX_PACKET_64_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[1],
		      MAC_STAT_TX_PACKET_65_127_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[2],
		      MAC_STAT_TX_PACKET_128_255_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[3],
		      MAC_STAT_TX_PACKET_256_511_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[4],
		      MAC_STAT_TX_PACKET_512_1023_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[5],
		      MAC_STAT_TX_PACKET_1024_1518_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[6],
		      TMI_STAT_TX_PACKET_1519_2047_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[7],
		      TMI_STAT_TX_PACKET_2048_4095_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[8],
		      TMI_STAT_TX_PACKET_4096_8191_BYTES);
	mac_stat_rd64(rmon_stats->hist_tx[9],
		      TMI_STAT_TX_PACKET_8192_9216_BYTES);
}

static void fbnic_mac_get_link_settings_asic(struct fbnic_dev *fbd,
					     struct ethtool_link_ksettings *cmd)
{
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);
	__ETHTOOL_DECLARE_LINK_MODE_MASK(supp) = { 0 };

	cmd->base.port = PORT_DA;
	cmd->base.autoneg = (fbn->link_mode & FBNIC_LINK_AUTO) ?
			    AUTONEG_ENABLE : AUTONEG_DISABLE;
	if (netif_carrier_ok(fbd->netdev) ||
	    !(fbn->link_mode & FBNIC_LINK_AUTO)) {
		cmd->base.duplex = DUPLEX_FULL;
		switch (fbn->link_mode & FBNIC_LINK_MODE_MASK) {
		case FBNIC_LINK_100R2:
			cmd->base.speed = SPEED_100000;
			break;
		case FBNIC_LINK_50R1:
		case FBNIC_LINK_50R2:
			cmd->base.speed = SPEED_50000;
			break;
		case FBNIC_LINK_25R1:
			cmd->base.speed = SPEED_25000;
			break;
		}
	} else {
		cmd->base.duplex = DUPLEX_UNKNOWN;
		cmd->base.speed = SPEED_UNKNOWN;
	}

	/* The NIC can support up to 8 possible combinations.
	 * Either 50G-CR, or 100G-CR2
	 *   This is with RS FEC mode only
	 * Either 25G-CR, or 50G-CR2
	 *   This is with No FEC, RS, or Base-R
	 */
	linkmode_set_bit(ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT, supp);
	linkmode_set_bit(ETHTOOL_LINK_MODE_50000baseCR_Full_BIT, supp);
	linkmode_set_bit(ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT, supp);
	linkmode_set_bit(ETHTOOL_LINK_MODE_25000baseCR_Full_BIT, supp);

	linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_NONE_BIT, supp);
	linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_RS_BIT, supp);
	linkmode_set_bit(ETHTOOL_LINK_MODE_FEC_BASER_BIT, supp);

	linkmode_set_bit(ETHTOOL_LINK_MODE_Pause_BIT, supp);
	linkmode_set_bit(ETHTOOL_LINK_MODE_Asym_Pause_BIT, supp);

	linkmode_set_bit(ETHTOOL_LINK_MODE_FIBRE_BIT, supp);

	linkmode_copy(cmd->link_modes.supported, supp);
}

static int
fbnic_mac_config_fec_asic(struct fbnic_dev *fbd)
{
	/* Tear down the current config and restart w/ new settings */
	fbnic_mac_disable_asic(fbd);

	return fbnic_mac_enable_asic(fbd);
}

static int
fbnic_mac_set_link_settings_asic(struct fbnic_dev *fbd,
				 const struct ethtool_link_ksettings *cmd)
{
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);

	fbn->link_mode = 0;

	/* For now we do not support autoneg */
	if (cmd->base.autoneg == AUTONEG_ENABLE)
		return -EINVAL;

	/* Convert base speed to a FBNIC link mode.
	 * As we don't have a way of getting the number of lanes
	 * they want us to use we default to 50R2 for a 50G link.
	 */
	switch (cmd->base.speed) {
	case SPEED_25000:
		fbn->link_mode = FBNIC_LINK_25R1;
		break;
	case SPEED_50000:
		fbn->link_mode = FBNIC_LINK_50R2;
		break;
	case SPEED_100000:
		if (!(fbn->fec & (FBNIC_FEC_AUTO | FBNIC_FEC_RS)))
			return -EINVAL;
		fbn->link_mode = FBNIC_LINK_100R2;
		fbn->fec &= FBNIC_FEC_AUTO;
		fbn->fec |= FBNIC_FEC_RS;
		break;
	default:
		return -EINVAL;
	}

	if (!netif_running(fbn->netdev))
		return 0;

	return fbnic_mac_config_fec_asic(fbd);
}

static int fbnic_mac_get_sensor_asic(struct fbnic_dev *fbd, int id, long *val)
{
	struct fbnic_fw_completion fw_cmpl;
	int err = 0, retries = 5;
	s32 *sensor;

	switch (id) {
	case FBNIC_SENSOR_TEMP:
		sensor = &fw_cmpl.tsene.millidegrees;
		break;
	case FBNIC_SENSOR_VOLTAGE:
		sensor = &fw_cmpl.tsene.millivolts;
		break;
	default:
		return -EINVAL;
	}

	memset(&fw_cmpl, 0, sizeof(fw_cmpl));

	/* Initialize completion and queue it for FW to process */
	fw_cmpl.msg_type = FBNIC_TLV_MSG_ID_TSENE_READ_RESP;
	init_completion(&fw_cmpl.done);

	err = fbnic_fw_xmit_tsene_read_msg(fbd, &fw_cmpl);
	if (err) {
		dev_err(fbd->dev,
			"Failed to transmit TSENE read msg, err %d\n",
			err);
		return err;
	}

	/* Allow 2 seconds for reply, resend and try up to 5 times */
	while (!wait_for_completion_timeout(&fw_cmpl.done, 2 * HZ)) {
		retries--;

		if (retries == 0) {
			dev_err(fbd->dev,
				"Timed out waiting on TSENE read\n");
			err = -ETIMEDOUT;
			goto cmpl_cleanup;
		}

		err = fbnic_fw_xmit_tsene_read_msg(fbd, NULL);
		if (err) {
			dev_err(fbd->dev,
				"Failed to transmit TSENE read msg, err %d\n",
				err);
			goto cmpl_cleanup;
		}
	}

	/* Handle error returned by firmware */
	if (fw_cmpl.result) {
		err = fw_cmpl.result;
		dev_err(fbd->dev, "%s: Firmware returned error %d\n",
			__func__, err);
		goto cmpl_cleanup;
	}

	*val = *sensor;
cmpl_cleanup:
	fbd->cmpl_data = NULL;

	return err;
}

static int fbnic_enable_loopback_asic(struct fbnic_dev *fbd)
{
	u32 cmd_cfg = __fbnic_mac_config_asic(fbd);
	u32 mac_ctrl = rd32(FBNIC_MAC_CTRL);
	u32 reset_complete;
	int err;

	mac_ctrl &= ~(FBNIC_MAC_CTRL_RESET_FF_TX_CLK |
		      FBNIC_MAC_CTRL_RESET_TX_CLK |
		      FBNIC_MAC_CTRL_RESET_FF_RX_CLK |
		      FBNIC_MAC_CTRL_RESET_RX_CLK);
	cmd_cfg |= FBNIC_MAC_COMMAND_CONFIG_RX_ENA |
		   FBNIC_MAC_COMMAND_CONFIG_TX_ENA |
		   FBNIC_MAC_COMMAND_CONFIG_LOOPBACK_EN;

	/* Enable loopback, and flush writes */
	wr32(FBNIC_PCS_CONTROL1_0,
	     FBNIC_PCS_CONTROL1_RESET |
	     FBNIC_PCS_CONTROL1_LOOPBACK |
	     FBNIC_PCS_CONTROL1_SPEED_SELECT_ALWAYS |
	     FBNIC_PCS_CONTROL1_SPEED_ALWAYS);
	wr32(FBNIC_PCS_CONTROL1_1,
	     FBNIC_PCS_CONTROL1_RESET |
	     FBNIC_PCS_CONTROL1_LOOPBACK |
	     FBNIC_PCS_CONTROL1_SPEED_SELECT_ALWAYS |
	     FBNIC_PCS_CONTROL1_SPEED_ALWAYS);

	/* poll for completion of reset */
	err = readx_poll_timeout(fbnic_mac_pcs_reset_complete, fbd,
				 reset_complete, reset_complete,
				 1000, 150000);
	if (err)
		return err;

	wr32(FBNIC_MAC_CTRL, mac_ctrl);
	wr32(FBNIC_MAC_COMMAND_CONFIG, cmd_cfg);

	return 0;
}

static const struct fbnic_mac fbnic_mac_asic = {
	.enable = fbnic_mac_enable_asic,
	.disable = fbnic_mac_disable_asic,
	.init_regs = fbnic_mac_init_regs,
	.get_link = fbnic_mac_get_link_asic,
	.get_link_event = fbnic_mac_get_link_event_asic,
	.config_fec = fbnic_mac_config_fec_asic,
	.config_pause = fbnic_mac_config_pause_asic,
	.get_fec_stats = fbnic_mac_get_fec_stats_asic,
	.get_eth_mac_stats = fbnic_mac_get_eth_mac_stats_asic,
	.get_eth_ctrl_stats = fbnic_mac_get_eth_ctrl_stats_asic,
	.get_rmon_stats = fbnic_mac_get_rmon_stats_asic,
	.get_pause_stats = fbnic_mac_get_pause_stats_asic,
	.get_link_settings = fbnic_mac_get_link_settings_asic,
	.set_link_settings = fbnic_mac_set_link_settings_asic,
	.get_sensor = fbnic_mac_get_sensor_asic,
	.enable_loopback = fbnic_enable_loopback_asic,
	.set_led_state = fbnic_set_led_state_asic,
	.rmon_ranges = fbnic_mac_rmon_ranges_asic,
	.eeprom_len = FBNIC_FRU_EEPROM_SIZE,
};

bool fbnic_is_asic(struct fbnic_dev *fbd)
{
	return fbd->max_num_queues == FBNIC_MAX_QUEUES_ASIC;
}

/**
 * fbnic_mac_init - Assign a MAC type and initialize the fbnic device
 * @fbd: Device pointer to device to initialize
 *
 * Returns 0 on success, negative on failure
 *
 * Initialize the MAC function pointers and initializes the MAC of
 * the device.
 **/
int fbnic_mac_init(struct fbnic_dev *fbd)
{
	fbd->mac = fbnic_is_asic(fbd) ? &fbnic_mac_asic : &fbnic_mac_fpga;

	/* Clear link state to disable any further transitions */
	fbd->link_state = FBNIC_LINK_DISABLED;

	if (!fbd->dsn && fbd->mac->set_addr)
		return fbd->mac->set_addr(fbd);

	fbd->mac->init_regs(fbd);

	return 0;
}
