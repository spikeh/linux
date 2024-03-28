// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <linux/pci.h>
#include <linux/types.h>

#include "fbnic.h"

static irqreturn_t fbnic_fw_msix_intr(int __always_unused irq, void *data)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)data;

	fbnic_mbx_poll(fbd);

	wr32(FBNIC_INTR_MASK_CLEAR(0), 1u << FBNIC_FW_MSIX_ENTRY);

	return IRQ_HANDLED;
}

/**
 * fbnic_fw_enable_mbx - Configure and initialize Firmware Mailbox
 * @fbd: Pointer to device to initialize
 *
 * This function will initialize the firmware mailbox rings, enable the IRQ
 * and initialize the communication between the Firmware and the host. The
 * firmware is expected to respond to the initialization by sending an
 * interrupt essentially notifying the host that it has seen the
 * initialization and is now synced up.
 **/
int fbnic_fw_enable_mbx(struct fbnic_dev *fbd)
{
	u32 vector;
	int err;

	vector = fbd->fw_msix_vector;

	/* Request the IRQ for MAC link vector.
	 * Map MAC cause to it, and unmask it
	 */
	err = request_threaded_irq(vector, NULL, &fbnic_fw_msix_intr, 0,
				   dev_name(fbd->dev), fbd);
	if (err)
		return err;

	/* Initialize mailbox and attempt to poll it into ready state */
	fbnic_mbx_init(fbd);
	err = fbnic_mbx_poll_tx_ready(fbd);
	if (err)
		dev_warn(fbd->dev, "FW mailbox did not enter ready state\n");

	/* Enable interrupts */
	wr32(FBNIC_INTR_SW_AC_MODE(0), ~(1u << FBNIC_FW_MSIX_ENTRY));
	wr32(FBNIC_INTR_MASK_CLEAR(0), 1u << FBNIC_FW_MSIX_ENTRY);

	return 0;
}

/**
 * fbnic_fw_disable_mbx - Disable mailbox and place it in standby state
 * @fbd: Pointer to device to disable
 *
 * This function will disable the mailbox interrupt, free any messages still
 * in the mailbox and place it into a standby state. The firmware is
 * expected to see the update and assume that the host is in the reset state.
 **/
void fbnic_fw_disable_mbx(struct fbnic_dev *fbd)
{
	/* Make sure the firmware knows to stop sending logs */
	fbnic_fw_xmit_send_logs(fbd, false);

	/* Disable interrupt and free vector */
	wr32(FBNIC_INTR_MASK_SET(0), 1u << FBNIC_FW_MSIX_ENTRY);

	/* Re-enable auto-clear for the mailbox register */
	wr32(FBNIC_INTR_SW_AC_MODE(0), ~0);

	/* Free the vector */
	free_irq(fbd->fw_msix_vector, fbd);

	/* Make sure disabling logs message is sent, must be done here to
	 * avoid risk of completing without a running interrupt.
	 */
	fbnic_mbx_flush_tx(fbd);

	/* Flush any remaining entries */
	fbnic_mbx_clean(fbd);
}

static irqreturn_t fbnic_mac_msix_intr(int __always_unused irq, void *data)
{
	struct fbnic_dev *fbd = data;

	if (fbd->mac->get_link_event(fbd))
		fbd->link_state = FBNIC_LINK_EVENT;
	else
		wr32(FBNIC_INTR_MASK_CLEAR(0), 1u << FBNIC_MAC_MSIX_ENTRY);

	return IRQ_HANDLED;
}

/**
 * fbnic_mac_get_link - Retrieve the current link state of the MAC
 * @fbd: Device to retrieve the link state of
 * @link: pointer to boolean value that will store link state
 *
 * This function will query the hardware to determine the state of the
 * hardware to determine the link status of the device. If it is unable to
 * communicate with the device it will return ENODEV and return false
 * indicating the link is down.
 **/
int fbnic_mac_get_link(struct fbnic_dev *fbd, bool *link)
{
	const struct fbnic_mac *mac = fbd->mac;

	*link = true;

	/* In an interrupt driven setup we can just skip the check if
	 * the link is up as the interrupt should toggle it to the EVENT
	 * state if the link has changed state at any time since the last
	 * check.
	 */
	if (fbd->link_state == FBNIC_LINK_UP)
		goto skip_check;

	*link = mac->get_link(fbd);

	wr32(FBNIC_INTR_MASK_CLEAR(0), 1u << FBNIC_MAC_MSIX_ENTRY);
skip_check:
	if (!fbnic_present(fbd)) {
		*link = false;
		return -ENODEV;
	}

	return 0;
}

/**
 * fbnic_mac_enable - Configure the MAC to enable it to advertise link
 * @fbd: Pointer to device to initialize
 *
 * This function provides basic bringup for the CMAC and sets the link
 * state to FBNIC_LINK_EVENT which tells the link state check that the
 * current state is unknown and that interrupts must be enabled after the
 * check is completed.
 **/
int fbnic_mac_enable(struct fbnic_dev *fbd)
{
	const struct fbnic_mac *mac = fbd->mac;
	u32 vector = fbd->mac_msix_vector;
	int err;

	/* Request the IRQ for MAC link vector.
	 * Map MAC cause to it, and unmask it
	 */
	err = request_irq(vector, &fbnic_mac_msix_intr, 0,
			  fbd->netdev->name, fbd);
	if (err)
		return err;

	wr32(FBNIC_INTR_MSIX_CTRL(FBNIC_INTR_MSIX_CTRL_PCS_IDX),
	     FBNIC_MAC_MSIX_ENTRY | FBNIC_INTR_MSIX_CTRL_ENABLE);

	err = mac->enable(fbd);
	if (err) {
		/* Disable interrupt */
		wr32(FBNIC_INTR_MSIX_CTRL(FBNIC_INTR_MSIX_CTRL_PCS_IDX),
		     FBNIC_MAC_MSIX_ENTRY);
		wr32(FBNIC_INTR_MASK_SET(0), 1u << FBNIC_MAC_MSIX_ENTRY);

		/* Free the vector */
		free_irq(fbd->mac_msix_vector, fbd);
	}

	return err;
}

/**
 * fbnic_mac_disable - Teardown the MAC to prepare for stopping
 * @fbd: Pointer to device that is stopping
 *
 * This function undoes the work done in fbnic_mac_enable and prepares the
 * device to no longer receive traffic on the host interface.
 **/
void fbnic_mac_disable(struct fbnic_dev *fbd)
{
	const struct fbnic_mac *mac = fbd->mac;

	/* Nothing to do if link is already disabled */
	if (fbd->link_state == FBNIC_LINK_DISABLED)
		return;

	mac->disable(fbd);

	/* Disable interrupt */
	wr32(FBNIC_INTR_MSIX_CTRL(FBNIC_INTR_MSIX_CTRL_PCS_IDX),
	     FBNIC_MAC_MSIX_ENTRY);
	wr32(FBNIC_INTR_MASK_SET(0), 1u << FBNIC_MAC_MSIX_ENTRY);

	/* Free the vector */
	free_irq(fbd->mac_msix_vector, fbd);
}

struct fbnic_msix_test_data {
	struct fbnic_dev *fbd;
	unsigned long test_msix_status[BITS_TO_LONGS(FBNIC_MAX_MSIX_VECS)];
};

static irqreturn_t fbnic_irq_test(int irq, void *data)
{
	struct fbnic_msix_test_data *test_data = data;
	struct fbnic_dev *fbd = test_data->fbd;
	int i;

	for (i = fbd->num_irqs; i--;) {
		if (fbd->msix_entries[i].vector == irq) {
			set_bit(i, test_data->test_msix_status);
			break;
		}
	}

	return IRQ_HANDLED;
}

/**
 * fbnic_msix_test - Verify behavior of NIC interrupts
 * @fbd: device to test
 *
 * This function is meant to test the global interrupt registers and the
 * PCIe IP MSI-X functionalty. It essentially goes through and tests
 * test various combinations of the set, clear, and mask bits in order to
 * verify the behavior is as we expect it to be from the driver.
 *
 * Returns non-zero on failure.
 **/
int fbnic_msix_test(struct fbnic_dev *fbd)
{
	struct fbnic_msix_test_data test_data;
	int result = 0;
	u32 mask = 0;
	int i;

	/* Initialize test data */
	test_data.fbd = fbd;
	memset(test_data.test_msix_status, 0,
	       sizeof(test_data.test_msix_status));

	for (i = FBNIC_NON_NAPI_VECTORS; i < fbd->num_irqs; i++) {
		if (!request_irq(fbd->msix_entries[i].vector,
				 fbnic_irq_test, 0, fbd->netdev->name,
				 &test_data))
			continue;

		while (i--)
			free_irq(fbd->msix_entries[i].vector, &test_data);

		/* Result = 10 for IRQ request failure */
		return 10;
	}

	/* Test each bit individually */
	for (i = FBNIC_NON_NAPI_VECTORS; i < fbd->num_irqs; i++) {
		mask = 1U << (i % 32);

		/* Start with mask set and interrupt cleared */
		wr32(FBNIC_INTR_MASK_SET(i / 32), mask);
		wrfl();
		wr32(FBNIC_INTR_CLEAR(i / 32), mask);
		wrfl();

		/* Result = 20 for masking failure to prevent interrupt */
		result = 20;

		wr32(FBNIC_INTR_SET(i / 32), mask);
		wrfl();
		usleep_range(10000, 11000);

		if (test_bit(i, test_data.test_msix_status))
			break;

		/* Result = 30 for unmasking failure w/ sw status set */
		result = 30;

		wr32(FBNIC_INTR_MASK_CLEAR(i / 32), mask);
		wrfl();
		usleep_range(10000, 11000);

		if (!test_bit(i, test_data.test_msix_status))
			break;

		/* Result = 40 for interrupt when clearing mask */
		result = 40;

		clear_bit(i, test_data.test_msix_status);
		wr32(FBNIC_INTR_MASK_CLEAR(i / 32), mask);
		wrfl();
		usleep_range(10000, 11000);

		if (test_bit(i, test_data.test_msix_status))
			break;

		/* Result = 50 for interrupt not triggering when not masked */
		result = 50;

		wr32(FBNIC_INTR_SET(i / 32), mask);
		wrfl();
		usleep_range(10000, 11000);

		if (!test_bit(i, test_data.test_msix_status))
			break;

		/* Result = 60 for status not cleared, or mask not set */
		result = 60;
		if (mask & rd32(FBNIC_INTR_STATUS(i / 32)))
			break;
		if (!(mask & rd32(FBNIC_INTR_MASK(i / 32))))
			break;

		/* Result = 0 - Success */
		result = 0;

		clear_bit(i, test_data.test_msix_status);
	}

	if (i < fbd->num_irqs) {
		wr32(FBNIC_INTR_MASK_SET(i / 32), mask);
		wrfl();
		wr32(FBNIC_INTR_CLEAR(i / 32), mask);
		wrfl();
		clear_bit(i, test_data.test_msix_status);
	}

	for (i = FBNIC_NON_NAPI_VECTORS; i < fbd->num_irqs; i++) {
		/* Test for bits set after testing */
		if (test_bit(i, test_data.test_msix_status))
			result = 70;

		/* Free IRQ */
		free_irq(fbd->msix_entries[i].vector, &test_data);
	}

	return result;
}
