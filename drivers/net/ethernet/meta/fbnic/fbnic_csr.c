// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include "fbnic.h"

/* Regarding FBNIC_CSR_LEN,
 * +1 because end is an actual register offset so need to go one past that
 * +2 to add start and end to the dump itself
 */
#define FBNIC_CSR_LEN(section) \
	(FBNIC_CSR_END_##section - FBNIC_CSR_START_##section + 1 + 2)

#define FBNIC_CSR_REGS_LEN \
	(FBNIC_CSR_LEN(INTR) + \
	 FBNIC_CSR_LEN(INTR_CQ) + \
	 FBNIC_CSR_LEN(QM_TX) + \
	 FBNIC_CSR_LEN(QM_RX) + \
	 FBNIC_CSR_LEN(TCE) + \
	 FBNIC_CSR_LEN(TCE_RAM) + \
	 FBNIC_CSR_LEN(TMI) + \
	 FBNIC_CSR_LEN(PTP)  + \
	 FBNIC_CSR_LEN(RXB) + \
	 FBNIC_CSR_LEN(RPC) + \
	 FBNIC_CSR_LEN(RPC_RAM) + \
	 FBNIC_CSR_LEN(FAB) + \
	 FBNIC_CSR_LEN(MASTER) +  \
	 FBNIC_CSR_LEN(CMS_QSPI) + \
	 FBNIC_CSR_LEN(TOP) + \
	 FBNIC_CSR_LEN(PCIE_USER_RAM) + \
	 FBNIC_CSR_LEN(PCIE_USER) + \
	 FBNIC_CSR_LEN(PCIE_AXI) + \
	 FBNIC_CSR_LEN(CMAC) + \
	 FBNIC_CSR_LEN(QUEUE))

#define FBNIC_BOUNDS(section) { \
	.start = FBNIC_CSR_START_##section,\
	.end = FBNIC_CSR_END_##section \
}

struct fbnic_csr_bounds {
	u32	start;
	u32	end;
};

static const struct fbnic_csr_bounds fbnic_csr_sects[] = {
	FBNIC_BOUNDS(INTR),
	FBNIC_BOUNDS(INTR_CQ),
	FBNIC_BOUNDS(QM_TX),
	FBNIC_BOUNDS(QM_RX),
	FBNIC_BOUNDS(TCE),
	FBNIC_BOUNDS(TCE_RAM),
	FBNIC_BOUNDS(TMI),
	FBNIC_BOUNDS(PTP),
	FBNIC_BOUNDS(RXB),
	FBNIC_BOUNDS(RPC),
	FBNIC_BOUNDS(FAB),
	FBNIC_BOUNDS(MASTER),
	FBNIC_BOUNDS(CMAC),
	FBNIC_BOUNDS(CMS_QSPI),
	FBNIC_BOUNDS(TOP),
	FBNIC_BOUNDS(PCIE_USER_RAM),
	FBNIC_BOUNDS(PCIE_USER),
	FBNIC_BOUNDS(PCIE_AXI),
	FBNIC_BOUNDS(QUEUE),
	{~0U}
};

#define FBNIC_RPC_TCAM_ACT_DW_PER_ENTRY			14
#define FBNIC_RPC_TCAM_ACT_NUM_ENTRIES			64

#define FBNIC_RPC_TCAM_MACDA_DW_PER_ENTRY		4
#define FBNIC_RPC_TCAM_MACDA_NUM_ENTRIES		32

#define FBNIC_RPC_TCAM_OUTER_IPSRC_DW_PER_ENTRY		9
#define FBNIC_RPC_TCAM_OUTER_IPSRC_NUM_ENTRIES		8

#define FBNIC_RPC_TCAM_OUTER_IPDST_DW_PER_ENTRY		9
#define FBNIC_RPC_TCAM_OUTER_IPDST_NUM_ENTRIES		8

#define FBNIC_RPC_TCAM_IPSRC_DW_PER_ENTRY		9
#define FBNIC_RPC_TCAM_IPSRC_NUM_ENTRIES		8

#define FBNIC_RPC_TCAM_IPDST_DW_PER_ENTRY		9
#define FBNIC_RPC_TCAM_IPDST_NUM_ENTRIES		8

#define FBNIC_RPC_RSS_TBL_DW_PER_ENTRY			2
#define FBNIC_RPC_RSS_TBL_NUM_ENTRIES			256

static void fbnic_csr_get_regs_rpc_ram(struct fbnic_dev *fbd, u32 **data_p)
{
	u32 start = FBNIC_CSR_START_RPC_RAM;
	u32 end = FBNIC_CSR_END_RPC_RAM;
	u32 *data = *data_p;
	u32 i, j;

	/* we can't linearly dump the RPC_RAM section
	 * so it gets a special handler to dump the registers in interleaved
	 * fashion.
	 */

	*(data++) = start;
	*(data++) = end;

	/* FBNIC_RPC_TCAM_ACT */
	for (i = 0; i < FBNIC_RPC_TCAM_ACT_NUM_ENTRIES; i++) {
		for (j = 0; j < FBNIC_RPC_TCAM_ACT_DW_PER_ENTRY; j++)
			*(data++) = rd32(FBNIC_RPC_TCAM_ACT(i, j));
	}
	/* FBNIC_RPC_TCAM_MACDA */
	for (i = 0; i < FBNIC_RPC_TCAM_MACDA_NUM_ENTRIES; i++) {
		for (j = 0; j < FBNIC_RPC_TCAM_MACDA_DW_PER_ENTRY; j++)
			*(data++) = rd32(FBNIC_RPC_TCAM_MACDA(i, j));
	}
	/* FBNIC_RPC_TCAM_OUTER_IPSRC */
	for (i = 0; i < FBNIC_RPC_TCAM_OUTER_IPSRC_NUM_ENTRIES; i++) {
		for (j = 0; j < FBNIC_RPC_TCAM_OUTER_IPSRC_DW_PER_ENTRY; j++)
			*(data++) = rd32(FBNIC_RPC_TCAM_OUTER_IPSRC(i, j));
	}

	/* FBNIC_RPC_TCAM_OUTER_IPDST */
	for (i = 0; i < FBNIC_RPC_TCAM_OUTER_IPDST_NUM_ENTRIES; i++) {
		for (j = 0; j < FBNIC_RPC_TCAM_OUTER_IPDST_DW_PER_ENTRY; j++)
			*(data++) = rd32(FBNIC_RPC_TCAM_OUTER_IPDST(i, j));
	}

	/* FBNIC_RPC_TCAM_IPSRC */
	for (i = 0; i < FBNIC_RPC_TCAM_IPSRC_NUM_ENTRIES; i++) {
		for (j = 0; j < FBNIC_RPC_TCAM_IPSRC_DW_PER_ENTRY; j++)
			*(data++) = rd32(FBNIC_RPC_TCAM_IPSRC(i, j));
	}

	/* FBNIC_RPC_TCAM_IPDST */
	for (i = 0; i < FBNIC_RPC_TCAM_IPDST_NUM_ENTRIES; i++) {
		for (j = 0; j < FBNIC_RPC_TCAM_IPDST_DW_PER_ENTRY; j++)
			*(data++) = rd32(FBNIC_RPC_TCAM_IPDST(i, j));
	}

	/* FBNIC_RPC_RSS_TBL */
	for (i = 0; i < FBNIC_RPC_RSS_TBL_NUM_ENTRIES; i++) {
		for (j = 0; j < FBNIC_RPC_RSS_TBL_DW_PER_ENTRY; j++)
			*(data++) = rd32(FBNIC_RPC_RSS_TBL(i, j));
	}

	*data_p = data;
}

void fbnic_csr_get_regs(struct fbnic_dev *fbd, u32 *data)
{
	const struct fbnic_csr_bounds *bound;
	u32 *start = data;
	int i;

	for (bound = fbnic_csr_sects ; bound->start != ~0U ; ++bound) {
		/* bound->start and bound->end output as consistency checks */
		*(data++) = bound->start;
		*(data++) = bound->end;
		for (i = bound->start; i <= bound->end; i++)
			*(data++) = rd32(FBNIC_INTR_STATUS(i));
		dev_info(fbd->dev, "get_regs: 0x%05X to 0x%05X, total %4d\n",
			 bound->start, bound->end,
			 bound->end - bound->start + 1);
	}

	/* special cases register sections that can't be dumped linearly */
	fbnic_csr_get_regs_rpc_ram(fbd, &data);

	dev_info(fbd->dev, "FBNIC_REGS_LEN %4d\n", FBNIC_CSR_REGS_LEN);
	dev_info(fbd->dev, "actual %4ld\n", (data - start));

	/* Generate driver warning if FBNIC_CSR_REGS_LEN is out of date */
	WARN_ON((data - start) != FBNIC_CSR_REGS_LEN);
}

int fbnic_csr_regs_len(void)
{
	return FBNIC_CSR_REGS_LEN * sizeof(u32);
}

/* CSR register test data
 *
 * The register test will be used to verify hardware is behaving as expected.
 *
 * The test itself will have us writing to registers that should have no
 * side effects due to us resetting after the test has been completed.
 * While the test is being run the interface should be offline.
 */
struct fbnic_csr_reg_test_data {
	int	reg;
	u16	reg_offset;
	u8	array_len;
	u32	read;
	u32	write;
};

#define FBNIC_QUEUE_REG_TEST(_name, _read, _write) { \
	.reg = FBNIC_QUEUE(0) + FBNIC_QUEUE_##_name, \
	.reg_offset = FBNIC_QUEUE_STRIDE, \
	.array_len = 64, \
	.read = _read, \
	.write = _write \
}

static struct fbnic_csr_reg_test_data pattern_test[] = {
	FBNIC_QUEUE_REG_TEST(TWQ0_CTL, FBNIC_QUEUE_TWQ_CTL_RESET,
			     FBNIC_QUEUE_TWQ_CTL_RESET),
	FBNIC_QUEUE_REG_TEST(TWQ0_PTRS, 0, ~0),
	FBNIC_QUEUE_REG_TEST(TWQ0_SIZE, FBNIC_QUEUE_TWQ_SIZE_MASK, ~0),
	FBNIC_QUEUE_REG_TEST(TWQ0_BAL, FBNIC_QUEUE_BAL_MASK, ~0),
	FBNIC_QUEUE_REG_TEST(TWQ0_BAH, ~0, ~0),
	FBNIC_QUEUE_REG_TEST(TWQ1_CTL, FBNIC_QUEUE_TWQ_CTL_RESET,
			     FBNIC_QUEUE_TWQ_CTL_RESET),
	FBNIC_QUEUE_REG_TEST(TWQ1_PTRS, 0, ~0),
	FBNIC_QUEUE_REG_TEST(TWQ1_SIZE, FBNIC_QUEUE_TWQ_SIZE_MASK, ~0),
	FBNIC_QUEUE_REG_TEST(TWQ1_BAL, FBNIC_QUEUE_BAL_MASK, ~0),
	FBNIC_QUEUE_REG_TEST(TWQ1_BAH, ~0, ~0),
	FBNIC_QUEUE_REG_TEST(TCQ_CTL, FBNIC_QUEUE_TCQ_CTL_RESET,
			     FBNIC_QUEUE_TCQ_CTL_RESET),
	FBNIC_QUEUE_REG_TEST(TCQ_PTRS, 0, ~0),
	FBNIC_QUEUE_REG_TEST(TCQ_SIZE, FBNIC_QUEUE_TCQ_SIZE_MASK, ~0),
	FBNIC_QUEUE_REG_TEST(TCQ_BAL, FBNIC_QUEUE_BAL_MASK, ~0),
	FBNIC_QUEUE_REG_TEST(TCQ_BAH, ~0, ~0),
	FBNIC_QUEUE_REG_TEST(RCQ_CTL, FBNIC_QUEUE_RCQ_CTL_RESET,
			     FBNIC_QUEUE_RCQ_CTL_RESET),
	FBNIC_QUEUE_REG_TEST(RCQ_PTRS, 0, ~0),
	FBNIC_QUEUE_REG_TEST(RCQ_SIZE, FBNIC_QUEUE_RCQ_SIZE_MASK, ~0),
	FBNIC_QUEUE_REG_TEST(RCQ_BAL, FBNIC_QUEUE_BAL_MASK, ~0),
	FBNIC_QUEUE_REG_TEST(RCQ_BAH, ~0, ~0),
	FBNIC_QUEUE_REG_TEST(BDQ_CTL, FBNIC_QUEUE_BDQ_CTL_RESET,
			     FBNIC_QUEUE_BDQ_CTL_RESET),
	FBNIC_QUEUE_REG_TEST(BDQ_HPQ_PTRS, 0, ~0),
	FBNIC_QUEUE_REG_TEST(BDQ_HPQ_SIZE, FBNIC_QUEUE_BDQ_SIZE_MASK, ~0),
	FBNIC_QUEUE_REG_TEST(BDQ_HPQ_BAL, FBNIC_QUEUE_BAL_MASK, ~0),
	FBNIC_QUEUE_REG_TEST(BDQ_HPQ_BAH, ~0, ~0),
	FBNIC_QUEUE_REG_TEST(BDQ_PPQ_PTRS, 0, ~0),
	FBNIC_QUEUE_REG_TEST(BDQ_PPQ_SIZE, FBNIC_QUEUE_BDQ_SIZE_MASK, ~0),
	FBNIC_QUEUE_REG_TEST(BDQ_PPQ_BAL, FBNIC_QUEUE_BAL_MASK, ~0),
	FBNIC_QUEUE_REG_TEST(BDQ_PPQ_BAH, ~0, ~0),
	{ -1 }
};

static int fbnic_csr_reg_pattern_test(struct fbnic_dev *fbd, int index,
				      struct fbnic_csr_reg_test_data *test_data)
{
	static const u32 pattern[] = { ~0, 0x5A5A5A5A, 0xA5A5A5A5, 0};
	u32 reg = test_data->reg + test_data->reg_offset * index;
	int i;

	for (i = 0; i < ARRAY_SIZE(pattern); i++) {
		u32 val = pattern[i] & test_data->write;
		u32 result;

		wr32(reg, val);
		result = rd32(reg);
		val &= test_data->read;

		if (result == val)
			continue;

		dev_err(fbd->dev,
			"%s: reg 0x%06X failed, expected 0x%08X received 0x%08X\n",
			__func__, reg, val, result);

		/* Note that FBNIC_INTR_STATUS(0) could be tested and fail
		 * and the result would not be reported since the register
		 * offset is 0. However as that register isn't included in
		 * the register test that isn't an issue.
		 */
		return reg;
	}

	return 0;
}

/**
 * fbnic_csr_regs_test() - Verify behavior of NIC registers
 * @fbd: device to test
 *
 * This function is meant to test the bit values ov various registers in
 * the NIC device. Specifically this test will verify which bits are
 * writable and which ones are not. It will write varying patterns of bits
 * to the registers testing for sticky bits, or bits that are writable but
 * should not be.
 *
 * Returns non-zero on failure.
 **/
int fbnic_csr_regs_test(struct fbnic_dev *fbd)
{
	struct fbnic_csr_reg_test_data *test_data;

	for (test_data = pattern_test; test_data->reg >= 0; test_data++) {
		u32 i;

		for (i = 0; i < test_data->array_len; i++) {
			int reg = fbnic_csr_reg_pattern_test(fbd, i, test_data);

			if (reg)
				return reg;
		}
	}

	return 0;
}

