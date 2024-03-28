// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <linux/etherdevice.h>
#include <linux/types.h>
#include <net/devlink.h>

#include "fbnic.h"
#include "fbnic_tlv.h"

static void __fbnic_mbx_wr_desc(struct fbnic_dev *fbd, int mbx_idx,
				int desc_idx, u64 desc)
{
	fw_wr32(FBNIC_IPC_MBX(mbx_idx, desc_idx) + 1, upper_32_bits(desc));
	fw_wrfl();
	fw_wr32(FBNIC_IPC_MBX(mbx_idx, desc_idx), lower_32_bits(desc));
}

u64 __fbnic_mbx_rd_desc(struct fbnic_dev *fbd, int mbx_idx, int desc_idx)
{
	u64 ret_val;

	ret_val = fw_rd32(FBNIC_IPC_MBX(mbx_idx, desc_idx));
	ret_val += (u64)fw_rd32(FBNIC_IPC_MBX(mbx_idx, desc_idx) + 1) << 32;

	return ret_val;
}

static void fbnic_mbx_init_desc_ring(struct fbnic_dev *fbd, int mbx_idx)
{
	int desc_idx;

	/* Initialize first descriptor to all 0s. Doing this gives us a
	 * solid stop for the firmware to hit when it is done looping
	 * through the ring.
	 */
	__fbnic_mbx_wr_desc(fbd, mbx_idx, 0, 0);

	fw_wrfl();

	/* We then fill the rest of the ring starting at the end and moving
	 * back toward descriptor 0 with skip descriptors that have no
	 * length nor address, and tell the firmware that they can skip
	 * them and just move past them to the one we initialized to 0.
	 */
	for (desc_idx = FBNIC_IPC_MBX_DESC_LEN; --desc_idx;) {
		__fbnic_mbx_wr_desc(fbd, mbx_idx, desc_idx,
				    FBNIC_IPC_MBX_DESC_FW_CMPL |
				    FBNIC_IPC_MBX_DESC_HOST_CMPL);
		fw_wrfl();
	}
}

void fbnic_mbx_init(struct fbnic_dev *fbd)
{
	int i;

	/* Initialize lock to protect Tx ring */
	spin_lock_init(&fbd->fw_tx_lock);

	/* reinitialize mailbox memory */
	for (i = 0; i < FBNIC_IPC_MBX_INDICES; i++)
		memset(&fbd->mbx[i], 0, sizeof(struct fbnic_fw_mbx));

	/* Clear any stale causes in vector 0 as that is used for doorbell */
	wr32(FBNIC_INTR_CLEAR(0), 1u << FBNIC_FW_MSIX_ENTRY);

	for (i = 0; i < FBNIC_IPC_MBX_INDICES; i++)
		fbnic_mbx_init_desc_ring(fbd, i);
}

static int fbnic_mbx_map_msg(struct fbnic_dev *fbd, int mbx_idx,
			     struct fbnic_tlv_msg *msg, u16 length, u8 eom)
{
	struct fbnic_fw_mbx *mbx = &fbd->mbx[mbx_idx];
	u8 tail = mbx->tail;
	dma_addr_t addr;
	int direction;

	if (!mbx->ready || !fbnic_fw_present(fbd))
		return -ENODEV;

	direction = (mbx_idx == FBNIC_IPC_MBX_RX_IDX) ? DMA_FROM_DEVICE :
							DMA_TO_DEVICE;

	if (mbx->head == ((tail + 1) % FBNIC_IPC_MBX_DESC_LEN))
		return -EBUSY;

	addr = fbnic_dma_map(fbd, msg, PAGE_SIZE, direction);
	if (fbnic_dma_mapping_error(fbd, addr)) {
		fbnic_free_page(fbd, msg);
		mbx->mapping_error++;

		return -ENOSPC;
	}

	mbx->buf_info[tail].msg = msg;
	mbx->buf_info[tail].addr = addr;

	mbx->tail = (tail + 1) % FBNIC_IPC_MBX_DESC_LEN;

	fw_wr32(FBNIC_IPC_MBX(mbx_idx, mbx->tail), 0);

	__fbnic_mbx_wr_desc(fbd, mbx_idx, tail,
			    FIELD_PREP(FBNIC_IPC_MBX_DESC_LEN_MASK, length) |
			    (addr & FBNIC_IPC_MBX_DESC_ADDR_MASK) |
			    (eom ? FBNIC_IPC_MBX_DESC_EOM : 0) |
			    FBNIC_IPC_MBX_DESC_HOST_CMPL);

	return 0;
}

static void fbnic_mbx_unmap_and_free_msg(struct fbnic_dev *fbd, int mbx_idx,
					 int desc_idx)
{
	struct fbnic_fw_mbx *mbx = &fbd->mbx[mbx_idx];
	int direction;

	if (!mbx->buf_info[desc_idx].msg)
		return;

	direction = (mbx_idx == FBNIC_IPC_MBX_RX_IDX) ? DMA_FROM_DEVICE :
							DMA_TO_DEVICE;
	fbnic_dma_unmap(fbd, mbx->buf_info[desc_idx].msg,
			PAGE_SIZE, direction,
			mbx->buf_info[desc_idx].addr);

	fbnic_free_page(fbd, mbx->buf_info[desc_idx].msg);
	mbx->buf_info[desc_idx].msg = NULL;
}

static void fbnic_mbx_clean_desc_ring(struct fbnic_dev *fbd, int mbx_idx)
{
	int i;

	fbnic_mbx_init_desc_ring(fbd, mbx_idx);

	for (i = FBNIC_IPC_MBX_DESC_LEN; i--;)
		fbnic_mbx_unmap_and_free_msg(fbd, mbx_idx, i);
}

void fbnic_mbx_clean(struct fbnic_dev *fbd)
{
	int i;

	for (i = 0; i < FBNIC_IPC_MBX_INDICES; i++)
		fbnic_mbx_clean_desc_ring(fbd, i);
}

#define FBNIC_MBX_MAX_PAGE_SIZE	FIELD_MAX(FBNIC_IPC_MBX_DESC_LEN_MASK)
#define FBNIC_RX_PAGE_SIZE	min_t(int, PAGE_SIZE, FBNIC_MBX_MAX_PAGE_SIZE)

static int fbnic_mbx_alloc_rx_msgs(struct fbnic_dev *fbd)
{
	struct fbnic_fw_mbx *rx_mbx = &fbd->mbx[FBNIC_IPC_MBX_RX_IDX];
	u8 tail = rx_mbx->tail, head = rx_mbx->head, count;
	int err = 0;

	/* Do nothing if mailbox is not ready, or we already have pages on
	 * the ring that can be used by the firmware
	 */
	if (!rx_mbx->ready)
		return -ENODEV;

	/* Fill all but 1 unused descriptors in the Rx queue. */
	count = (head - tail - 1) % FBNIC_IPC_MBX_DESC_LEN;
	while (!err && count--) {
		struct fbnic_tlv_msg *msg;

		msg = (struct fbnic_tlv_msg *)fbnic_alloc_page(fbd,
							       GFP_ATOMIC |
							       __GFP_NOWARN);
		if (!msg) {
			rx_mbx->alloc_failed++;
			err = -ENOMEM;
			break;
		}

		err = fbnic_mbx_map_msg(fbd, FBNIC_IPC_MBX_RX_IDX, msg,
					FBNIC_RX_PAGE_SIZE, 0);
		if (err)
			fbnic_free_page(fbd, msg);
	}

	return err;
}

static int fbnic_mbx_map_tlv_msg(struct fbnic_dev *fbd,
				 struct fbnic_tlv_msg *msg)
{
	unsigned long flags;
	int err;

	spin_lock_irqsave(&fbd->fw_tx_lock, flags);

	err = fbnic_mbx_map_msg(fbd, FBNIC_IPC_MBX_TX_IDX, msg,
				le16_to_cpu(msg->hdr.len) * sizeof(u32), 1);

	spin_unlock_irqrestore(&fbd->fw_tx_lock, flags);

	return err;
}

static int fbnic_mbx_map_req_w_cmpl(struct fbnic_dev *fbd,
				    struct fbnic_tlv_msg *msg,
				    struct fbnic_fw_completion *cmpl_data)
{
	unsigned long flags;
	int err;

	spin_lock_irqsave(&fbd->fw_tx_lock, flags);

	/* If we are already waiting on a completion then abort */
	if (cmpl_data && fbd->cmpl_data) {
		err = -EBUSY;
		goto unlock_mbx;
	}

	/* Record completion location and submit request */
	if (cmpl_data)
		fbd->cmpl_data = cmpl_data;

	err = fbnic_mbx_map_msg(fbd, FBNIC_IPC_MBX_TX_IDX, msg,
				le16_to_cpu(msg->hdr.len) * sizeof(u32), 1);

	/* If msg failed then clear completion data for next caller */
	if (err && cmpl_data)
		fbd->cmpl_data = NULL;

unlock_mbx:
	spin_unlock_irqrestore(&fbd->fw_tx_lock, flags);

	return err;
}

static void fbnic_mbx_process_tx_msgs(struct fbnic_dev *fbd)
{
	struct fbnic_fw_mbx *tx_mbx = &fbd->mbx[FBNIC_IPC_MBX_TX_IDX];
	u8 head = tx_mbx->head;
	u64 desc;

	while (head != tx_mbx->tail) {
		desc = __fbnic_mbx_rd_desc(fbd, FBNIC_IPC_MBX_TX_IDX, head);
		if (!(desc & FBNIC_IPC_MBX_DESC_FW_CMPL))
			break;

		fbnic_mbx_unmap_and_free_msg(fbd, FBNIC_IPC_MBX_TX_IDX, head);

		head++;
		head %= FBNIC_IPC_MBX_DESC_LEN;
	}

	/* record head for next interrupt */
	tx_mbx->head = head;
}

/**
 * fbnic_fw_xmit_test_msg - Create and transmit a test message to FW mailbox
 * @fbd: FBNIC device structure
 *
 * Returns 0 on success, negative value on failure
 *
 * Generates a single page mailbox test message and places it in the Tx
 * mailbox queue. Expectation is that the FW will validate that the nested
 * value matches the external values, and then will echo them back to us.
 */
int fbnic_fw_xmit_test_msg(struct fbnic_dev *fbd)
{
	struct fbnic_tlv_msg *test_msg;
	int err;

	if (!fbnic_is_asic(fbd))
		return 0;

	if (!fbnic_fw_present(fbd))
		return -ENODEV;

	test_msg = fbnic_tlv_test_create(fbd);
	if (!test_msg)
		return -ENOMEM;

	err = fbnic_mbx_map_tlv_msg(fbd, test_msg);
	if (err)
		fbnic_free_page(fbd, test_msg);
	else
		dev_info(fbd->dev, "Sent test message\n");

	return err;
}

/**
 * fbnic_fw_xmit_simple_msg - Transmit a simple single TLV message w/o data
 * @fbd: FBNIC device structure
 * @msg_type: ENUM value indicating message type to send
 *
 * Returns the following values:
 * -EOPNOTSUPP: Is not ASIC so mailbox is not supported
 * -ENODEV: Device I/O error
 * -ENOMEM: Failed to allocate message
 * -EBUSY: No space in mailbox
 * -ENOSPC: DMA mapping failed
 *
 * This function sends a single TLV header indicating the host wants to take
 * some action. However there are no other side effects which means that any
 * response will need to be caught via a completion if this action is
 * expected to kick off a resultant action.
 */
static int fbnic_fw_xmit_simple_msg(struct fbnic_dev *fbd, u32 msg_type)
{
	struct fbnic_tlv_msg *msg;
	int err = 0;

	if (!fbnic_is_asic(fbd))
		return -EOPNOTSUPP;

	if (!fbnic_fw_present(fbd))
		return -ENODEV;

	msg = fbnic_tlv_msg_alloc(fbd, msg_type);
	if (!msg)
		return -ENOMEM;

	err = fbnic_mbx_map_tlv_msg(fbd, msg);
	if (err)
		fbnic_free_page(fbd, msg);

	return err;
}

/**
 * fbnic_fw_xmit_cap_msg - Allocate and populate a FW capabilities message
 * @fbd: FBNIC device structure
 *
 * Returns NULL on failure to allocate, error pointer on error, or pointer
 * to new TLV test message.
 *
 * Sends a single TLV header indicating the host wants the firmware to
 * confirm the capabilities and version.
 **/
static int fbnic_fw_xmit_cap_msg(struct fbnic_dev *fbd)
{
	int err = fbnic_fw_xmit_simple_msg(fbd, FBNIC_TLV_MSG_ID_HOST_CAP_REQ);

	/* return 0 if we are not calling this on ASIC */
	return (err == -EOPNOTSUPP) ? 0 : err;
}

static void fbnic_mbx_postinit_desc_ring(struct fbnic_dev *fbd, int mbx_idx)
{
	struct fbnic_fw_mbx *mbx = &fbd->mbx[mbx_idx];

	/* This is a one time init, so just exit if it is completed */
	if (mbx->ready)
		return;

	mbx->ready = true;

	switch (mbx_idx) {
	case FBNIC_IPC_MBX_RX_IDX:
		/* Make sure we have a page for the FW to write to */
		fbnic_mbx_alloc_rx_msgs(fbd);
		break;
	case FBNIC_IPC_MBX_TX_IDX:
		/* Force version to 1 if we successfully requested an update
		 * from the firmware. This should be overwritten once we get
		 * the actual version from the firmware in the capabilities
		 * request message.
		 */
		if (!fbnic_fw_xmit_cap_msg(fbd) &&
		    !fbd->fw_cap.running.mgmt.version)
			fbd->fw_cap.running.mgmt.version = 1;
		break;
	}
}

static void fbnic_mbx_postinit(struct fbnic_dev *fbd)
{
	int i;

	/* We only need to do this on the first interrupt following init.
	 * this primes the mailbox so that we will have cleared all the
	 * skip descriptors.
	 */
	if (!(rd32(FBNIC_INTR_STATUS(0)) & (1u << FBNIC_FW_MSIX_ENTRY)))
		return;

	wr32(FBNIC_INTR_CLEAR(0), 1u << FBNIC_FW_MSIX_ENTRY);

	for (i = 0; i < FBNIC_IPC_MBX_INDICES; i++)
		fbnic_mbx_postinit_desc_ring(fbd, i);

	fbd->fw_mbx_events++;
}

/**
 * fbnic_fw_xmit_ownership_msg - Create and transmit a host ownership message
 * to FW mailbox
 *
 * @fbd: FBNIC device structure
 * @take_ownership: take/release the ownership
 *
 * Returns 0 on success, negative value on failure
 *
 * Notifies the firmware that the driver either takes ownership of the NIC
 * (when @take_ownership is true) or releases it.
 */
int fbnic_fw_xmit_ownership_msg(struct fbnic_dev *fbd, bool take_ownership)
{
	unsigned long req_time = jiffies;
	struct fbnic_tlv_msg *msg;
	int err = 0;

	if (!fbnic_is_asic(fbd)) {
		fbd->last_heartbeat_response = req_time;
		goto schedule_next_request;
	}

	if (!fbnic_fw_present(fbd))
		return -ENODEV;

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_OWNERSHIP_REQ);
	if (!msg)
		return -ENOMEM;

	if (take_ownership) {
		err = fbnic_tlv_attr_put_flag(msg, FBNIC_FW_OWNERSHIP_FLAG);
		if (err)
			goto free_message;
	}

	err = fbnic_mbx_map_tlv_msg(fbd, msg);
	if (err)
		goto free_message;

	/* Initialize heartbeat, set last response to 1 second in the past
	 * so that we will trigger a timeout if the firmware doesn't respond
	 */
	fbd->last_heartbeat_response = req_time - HZ;

schedule_next_request:
	fbd->last_heartbeat_request = req_time;

	/* Set prev_firmware_time to 0 to avoid triggering firmware crash
	 * detection now that we received a response from firmware.
	 */
	fbd->prev_firmware_time = 0;

	/* set heartbeat detection based on if we are taking ownership */
	fbd->fw_heartbeat_enabled = take_ownership;

	return err;

free_message:
	fbnic_free_page(fbd, msg);
	return err;
}

static const struct fbnic_tlv_index fbnic_fw_cap_resp_index[] = {
	FBNIC_TLV_ATTR_U32(FBNIC_FW_CAP_RESP_VERSION),
	FBNIC_TLV_ATTR_FLAG(FBNIC_FW_CAP_RESP_BMC_PRESENT),
	FBNIC_TLV_ATTR_MAC_ADDR(FBNIC_FW_CAP_RESP_BMC_MAC_ADDR),
	FBNIC_TLV_ATTR_ARRAY(FBNIC_FW_CAP_RESP_BMC_MAC_ARRAY),
	FBNIC_TLV_ATTR_U32(FBNIC_FW_CAP_RESP_STORED_VERSION),
	FBNIC_TLV_ATTR_U32(FBNIC_FW_CAP_RESP_ACTIVE_FW_SLOT),
	FBNIC_TLV_ATTR_STRING(FBNIC_FW_CAP_RESP_VERSION_COMMIT_STR,
			      FBNIC_FW_CAP_RESP_COMMIT_MAX_SIZE),
	FBNIC_TLV_ATTR_U32(FBNIC_FW_CAP_RESP_BMC_ALL_MULTI),
	FBNIC_TLV_ATTR_U32(FBNIC_FW_CAP_RESP_FW_LINK_SPEED),
	FBNIC_TLV_ATTR_U32(FBNIC_FW_CAP_RESP_FW_LINK_FEC),
	FBNIC_TLV_ATTR_STRING(FBNIC_FW_CAP_RESP_STORED_COMMIT_STR,
			      FBNIC_FW_CAP_RESP_COMMIT_MAX_SIZE),
	FBNIC_TLV_ATTR_U32(FBNIC_FW_CAP_RESP_CMRT_VERSION),
	FBNIC_TLV_ATTR_U32(FBNIC_FW_CAP_RESP_STORED_CMRT_VERSION),
	FBNIC_TLV_ATTR_STRING(FBNIC_FW_CAP_RESP_CMRT_COMMIT_STR,
			      FBNIC_FW_CAP_RESP_COMMIT_MAX_SIZE),
	FBNIC_TLV_ATTR_STRING(FBNIC_FW_CAP_RESP_STORED_CMRT_COMMIT_STR,
			      FBNIC_FW_CAP_RESP_COMMIT_MAX_SIZE),
	FBNIC_TLV_ATTR_U32(FBNIC_FW_CAP_RESP_UEFI_VERSION),
	FBNIC_TLV_ATTR_STRING(FBNIC_FW_CAP_RESP_UEFI_COMMIT_STR,
			      FBNIC_FW_CAP_RESP_COMMIT_MAX_SIZE),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_bmc_addrs(u8 bmc_mac_addr[][ETH_ALEN],
				    struct fbnic_tlv_msg *attr, int len)
{
	int attr_len = le16_to_cpu(attr->hdr.len) / sizeof(u32) - 1;
	struct fbnic_tlv_msg *mac_results[8];
	int err, i = 0;

	/* make sure we have enough room to process all the MAC addresses */
	if (len > 8)
		return -ENOSPC;

	/* Parse the array */
	err = fbnic_tlv_attr_parse_array(&attr[1], attr_len, mac_results,
					 fbnic_fw_cap_resp_index,
					 FBNIC_FW_CAP_RESP_BMC_MAC_ADDR, len);
	if (err)
		return err;

	/* Copy results into MAC addr array */
	for (i = 0; i < len && mac_results[i]; i++)
		fbnic_tlv_attr_addr_copy(bmc_mac_addr[i], mac_results[i]);

	/* Zero remaining unused addresses */
	while (i < len)
		eth_zero_addr(bmc_mac_addr[i++]);

	return 0;
}

/**
 *  fbnic_enable_versioned_features - Enable features which have a version req
 *  @fbd: FBNIC device struct
 *
 * Called after version information is received in fbnic_fw_parse_cap_resp.
 * These are features that have strict firmware version requirements. If
 * enabled on older versions of firmware may cause crashes.
 **/
static void fbnic_enable_versioned_features(struct fbnic_dev *fbd)
{
	int err = 0;

	err = fbnic_fw_xmit_send_logs(fbd, fbnic_fw_log_enabled(fbd));
	if (err) {
		dev_err(fbd->dev,
			"Error %d, unable to send firmware log request\n",
			err);
	}
}

static int fbnic_fw_parse_cap_resp(void *opaque, struct fbnic_tlv_msg **results)
{
	u32 active_slot = 0, all_multi = 0;
	struct fbnic_dev *fbd = opaque;
	u32 speed = 0, fec = 0;
	size_t commit_size = 0;
	bool bmc_present;
	int err;

	get_unsigned_result(FBNIC_FW_CAP_RESP_VERSION,
			    fbd->fw_cap.running.mgmt.version);

	if (!fbd->fw_cap.running.mgmt.version)
		return -EINVAL;

	if (fbd->fw_cap.running.mgmt.version < MIN_FW_VERSION_CODE) {
		char running_ver[FBNIC_FW_VER_MAX_SIZE];

		fbnic_mk_fw_ver_str(fbd->fw_cap.running.mgmt.version,
				    running_ver);
		dev_err(fbd->dev, "Device firmware version(%s) is older than minimum required version(%02d.%02d.%02d)\n",
			running_ver,
			MIN_FW_MAJOR_VERSION,
			MIN_FW_MINOR_VERSION,
			MIN_FW_BUILD_VERSION);
		/* Disable TX mailbox to prevent card use until firmware is
		 * updated.
		 */
		fbd->mbx[FBNIC_IPC_MBX_TX_IDX].ready = false;
		return -EINVAL;
	}

	get_string_result(FBNIC_FW_CAP_RESP_VERSION_COMMIT_STR, commit_size,
			  fbd->fw_cap.running.mgmt.commit,
			  FBNIC_FW_CAP_RESP_COMMIT_MAX_SIZE);
	if (!commit_size)
		dev_warn(fbd->dev, "Firmware did not send mgmt commit!\n");

	get_unsigned_result(FBNIC_FW_CAP_RESP_STORED_VERSION,
			    fbd->fw_cap.stored.mgmt.version);
	get_string_result(FBNIC_FW_CAP_RESP_STORED_COMMIT_STR, commit_size,
			  fbd->fw_cap.stored.mgmt.commit,
			  FBNIC_FW_CAP_RESP_COMMIT_MAX_SIZE);

	get_unsigned_result(FBNIC_FW_CAP_RESP_CMRT_VERSION,
			    fbd->fw_cap.running.bootloader.version);
	get_string_result(FBNIC_FW_CAP_RESP_CMRT_COMMIT_STR, commit_size,
			  fbd->fw_cap.running.bootloader.commit,
			  FBNIC_FW_CAP_RESP_COMMIT_MAX_SIZE);

	get_unsigned_result(FBNIC_FW_CAP_RESP_STORED_CMRT_VERSION,
			    fbd->fw_cap.stored.bootloader.version);
	get_string_result(FBNIC_FW_CAP_RESP_STORED_CMRT_COMMIT_STR, commit_size,
			  fbd->fw_cap.stored.bootloader.commit,
			  FBNIC_FW_CAP_RESP_COMMIT_MAX_SIZE);

	get_unsigned_result(FBNIC_FW_CAP_RESP_UEFI_VERSION,
			    fbd->fw_cap.stored.undi.version);
	get_string_result(FBNIC_FW_CAP_RESP_UEFI_COMMIT_STR, commit_size,
			  fbd->fw_cap.stored.undi.commit,
			  FBNIC_FW_CAP_RESP_COMMIT_MAX_SIZE);

	get_unsigned_result(FBNIC_FW_CAP_RESP_ACTIVE_FW_SLOT, active_slot);
	fbd->fw_cap.active_slot = active_slot;

	get_unsigned_result(FBNIC_FW_CAP_RESP_FW_LINK_SPEED, speed);
	get_unsigned_result(FBNIC_FW_CAP_RESP_FW_LINK_FEC, fec);
	fbd->fw_cap.link_speed = speed;
	fbd->fw_cap.link_fec = fec;

	bmc_present = !!results[FBNIC_FW_CAP_RESP_BMC_PRESENT];
	if (bmc_present) {
		struct fbnic_tlv_msg *attr;

		attr = results[FBNIC_FW_CAP_RESP_BMC_MAC_ARRAY];
		if (!attr)
			return -EINVAL;

		err = fbnic_fw_parse_bmc_addrs(fbd->fw_cap.bmc_mac_addr,
					       attr, 4);
		if (err)
			return err;

		get_unsigned_result(FBNIC_FW_CAP_RESP_BMC_ALL_MULTI, all_multi);
	} else {
		memset(fbd->fw_cap.bmc_mac_addr, 0,
		       sizeof(fbd->fw_cap.bmc_mac_addr));
	}

	fbd->fw_cap.bmc_present = bmc_present;

	if (results[FBNIC_FW_CAP_RESP_BMC_ALL_MULTI] || !bmc_present)
		fbd->fw_cap.all_multi = all_multi;

	fbnic_enable_versioned_features(fbd);

	return 0;
}

static const struct fbnic_tlv_index fbnic_ownership_resp_index[] = {
	FBNIC_TLV_ATTR_U64(FBNIC_FW_OWNERSHIP_TIME),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_ownership_resp(void *opaque,
					 struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	u64 firmware_time = 0;

	/* Count the ownership response as a heartbeat reply */
	fbd->last_heartbeat_response = jiffies;

	get_unsigned_result(FBNIC_FW_OWNERSHIP_TIME, firmware_time);

	/* Capture firmware time for logging and firmware crash check */
	fbd->firmware_time = firmware_time;

	return 0;
}

static const struct fbnic_tlv_index fbnic_heartbeat_resp_index[] = {
	FBNIC_TLV_ATTR_U64(FBNIC_FW_HEARTBEAT_UPTIME),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_heartbeat_resp(void *opaque,
					 struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	u64 firmware_time = 0;

	get_unsigned_result(FBNIC_FW_HEARTBEAT_UPTIME, firmware_time);

	fbd->last_heartbeat_response = jiffies;

	/* Capture firmware time for logging and firmware crash check */
	fbd->firmware_time = firmware_time;

	return 0;
}

static int fbnic_fw_xmit_heartbeat_message(struct fbnic_dev *fbd)
{
	unsigned long req_time = jiffies;
	struct fbnic_tlv_msg *msg;
	int err = 0;

	if (!fbnic_is_asic(fbd)) {
		fbd->last_heartbeat_response = req_time;
		goto schedule_next_request;
	}

	if (!fbnic_fw_present(fbd))
		return -ENODEV;

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_HEARTBEAT_REQ);
	if (!msg)
		return -ENOMEM;

	err = fbnic_mbx_map_tlv_msg(fbd, msg);
	if (err)
		goto free_message;

schedule_next_request:
	fbd->last_heartbeat_request = req_time;
	fbd->prev_firmware_time = fbd->firmware_time;

	return err;

free_message:
	fbnic_free_page(fbd, msg);
	return err;
}

static bool fbnic_fw_heartbeat_current(struct fbnic_dev *fbd)
{
	unsigned long last_response = fbd->last_heartbeat_response;
	unsigned long last_request = fbd->last_heartbeat_request;

	return !time_before(last_response, last_request);
}

int fbnic_fw_init_heartbeat(struct fbnic_dev *fbd, bool poll)
{
	int err = -ETIMEDOUT;
	int attempts = 50;

	/* Nothing to do if there is no mailbox */
	if (!fbnic_is_asic(fbd) || !fbnic_fw_present(fbd))
		return 0;

	while (attempts--) {
		msleep(200);
		if (poll)
			fbnic_mbx_poll(fbd);

		if (!fbnic_fw_heartbeat_current(fbd))
			continue;

		/* Place new message on mailbox to elicit a response */
		err = fbnic_fw_xmit_heartbeat_message(fbd);
		if (err)
			dev_warn(fbd->dev,
				 "Failed to send heartbeat message\n");
		break;
	}

	return err;
}

void fbnic_fw_check_heartbeat(struct fbnic_dev *fbd)
{
	unsigned long last_request = fbd->last_heartbeat_request;
	int err;

	/* Do not check heartbeat or send another request until current
	 * period has expired. Otherwise we might start spamming requests.
	 */
	if (time_is_after_jiffies(last_request + FW_HEARTBEAT_PERIOD))
		return;

	/* We already reported no mailbox. Wait for it to come back */
	if (!fbd->fw_heartbeat_enabled)
		return;

	/* Was the last heartbeat response long time ago?
	 * Did firmware time go back?
	 */
	if (!fbnic_fw_heartbeat_current(fbd) ||
	    fbd->firmware_time < fbd->prev_firmware_time) {
		dev_warn(fbd->dev,
			 "Firmware did not respond to heartbeat message\n");
		fbd->fw_heartbeat_enabled = false;
	}

	/* Place new message on mailbox to elicit a response */
	err = fbnic_fw_xmit_heartbeat_message(fbd);
	if (err)
		dev_warn(fbd->dev, "Failed to send heartbeat message\n");
}

static const struct fbnic_tlv_index fbnic_eeprom_lock_resp_index[] = {
	FBNIC_TLV_ATTR_FLAG(FBNIC_EEPROM_LOCK),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_eeprom_lock_resp(void *opaque,
					   struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	int err = 0;

	get_signed_result(FBNIC_EEPROM_LOCK, err);
	if (!err)
		fbd->eeprom_state = fbd->eeprom_desired_state;

	return err;
}

/**
 * fbnic_fw_xmit_eeprom_lock_msg - Create and transmit a EEPROM lock message
 * to FW mailbox
 *
 * @fbd: FBNIC device structure
 * @lock_eeprom: lock/unlock
 *
 * Returns 0 on success, negative value on failure
 *
 * Asks the firmware to lock or unlock the EEPROM via GPIO line. Sets the
 * eeprom state to unknown (until the reply from the firmware arrives).
 */
int fbnic_fw_xmit_eeprom_lock_msg(struct fbnic_dev *fbd, bool lock_eeprom)
{
	struct fbnic_tlv_msg *msg;
	int err = 0;

	if (!fbnic_is_asic(fbd) || !fbnic_fw_present(fbd))
		return -ENODEV;

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_EEPROM_LOCK_REQ);
	if (!msg)
		return -ENOMEM;

	fbd->eeprom_state = FBNIC_EEPROM_STATE_UNKNOWN;

	if (lock_eeprom) {
		err = fbnic_tlv_attr_put_flag(msg, FBNIC_EEPROM_LOCK);
		if (err)
			goto free_message;
	}

	fbd->eeprom_desired_state = lock_eeprom ?
		FBNIC_EEPROM_STATE_LOCKED : FBNIC_EEPROM_STATE_UNLOCKED;

	err = fbnic_mbx_map_tlv_msg(fbd, msg);
	if (err)
		goto free_message;

	return err;

free_message:
	fbnic_free_page(fbd, msg);
	return err;
}

/**
 * fbnic_fw_xmit_coredump_info_msg - Create and transmit a coredump info message
 * to FW mailbox
 *
 * @fbd: FBNIC device structure
 * @cmpl_data: Structure to store info in
 * @force: Force coredump event if one hasn't already occurred
 *
 * Returns 0 on success, negative value on failure
 *
 * Asks the FW for info related to coredump. If a coredump doesn't exist it
 * can optionally force one if force is true.
 */
int fbnic_fw_xmit_coredump_info_msg(struct fbnic_dev *fbd,
				    struct fbnic_fw_completion *cmpl_data,
				    bool force)
{
	struct fbnic_tlv_msg *msg;
	int err = 0;

	if (!fbnic_is_asic(fbd) || !fbnic_fw_present(fbd))
		return -ENODEV;

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_COREDUMP_GET_INFO_REQ);
	if (!msg)
		return -ENOMEM;

	if (!force)
		goto send_msg;

	err = fbnic_tlv_attr_put_flag(msg, FBNIC_FW_COREDUMP_REQ_INFO_CREATE);
	if (err)
		goto free_msg;

send_msg:
	err = fbnic_mbx_map_req_w_cmpl(fbd, msg, cmpl_data);
	if (err)
		goto free_msg;

	return err;

free_msg:
	fbnic_free_page(fbd, msg);
	return err;
}

static const struct fbnic_tlv_index fbnic_coredump_info_resp_index[] = {
	FBNIC_TLV_ATTR_FLAG(FBNIC_FW_COREDUMP_INFO_AVAILABLE),
	FBNIC_TLV_ATTR_U32(FBNIC_FW_COREDUMP_INFO_SIZE),
	FBNIC_TLV_ATTR_S32(FBNIC_FW_COREDUMP_INFO_ERROR),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_coredump_info_resp(void *opaque,
					     struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	struct fbnic_fw_completion *cmpl_data;
	u32 size = 0;
	int err = 0;

	/* Verify we have a completion pointer to provide with data */
	cmpl_data = READ_ONCE(fbd->cmpl_data);
	if (!cmpl_data ||
	    cmpl_data->msg_type != FBNIC_TLV_MSG_ID_COREDUMP_GET_INFO_RESP)
		return -ENOSPC;

	get_signed_result(FBNIC_FW_COREDUMP_INFO_ERROR, err);
	if (err)
		goto msg_err;

	if (!get_bool(FBNIC_FW_COREDUMP_INFO_AVAILABLE)) {
		err = -ENOENT;
		goto msg_err;
	}

	get_unsigned_result(FBNIC_FW_COREDUMP_INFO_SIZE, size);
	cmpl_data->coredump_info.size = size;

msg_err:
	cmpl_data->result = err;
	complete(&cmpl_data->done);

	return err;
}

/**
 * fbnic_fw_xmit_coredump_read_msg - Create and transmit a coredump read request
 *
 * @fbd: FBNIC device structure
 * @cmpl_data: Completion struct to store coredump
 * @offset: Offset into coredump requested
 * @length: Length of section of cordeump to fetch
 *
 * Returns 0 on success, negative value on failure
 *
 * Asks the firmware to provide a section of the cordeump back in a message.
 * The response will have an offset and size matching the values provided.
 */
int fbnic_fw_xmit_coredump_read_msg(struct fbnic_dev *fbd,
				    struct fbnic_fw_completion *cmpl_data,
				    u32 offset, u32 length)
{
	struct fbnic_tlv_msg *msg;
	int err = 0;

	if (!fbnic_is_asic(fbd) || !fbnic_fw_present(fbd))
		return -ENODEV;

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_COREDUMP_READ_REQ);
	if (!msg)
		return -ENOMEM;

	if (offset) {
		err = fbnic_tlv_attr_put_int(msg, FBNIC_FW_COREDUMP_READ_OFFSET,
					     offset);
		if (err)
			goto free_message;
	}

	if (length) {
		err = fbnic_tlv_attr_put_int(msg, FBNIC_FW_COREDUMP_READ_LENGTH,
					     length);
		if (err)
			goto free_message;
	}

	err = fbnic_mbx_map_req_w_cmpl(fbd, msg, cmpl_data);
	if (err)
		goto free_message;

	return 0;

free_message:
	fbnic_free_page(fbd, msg);
	return err;
}

static const struct fbnic_tlv_index fbnic_coredump_resp_index[] = {
	FBNIC_TLV_ATTR_U32(FBNIC_FW_COREDUMP_READ_OFFSET),
	FBNIC_TLV_ATTR_U32(FBNIC_FW_COREDUMP_READ_LENGTH),
	FBNIC_TLV_ATTR_RAW_DATA(FBNIC_FW_COREDUMP_READ_DATA),
	FBNIC_TLV_ATTR_S32(FBNIC_FW_COREDUMP_READ_ERROR),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_coredump_resp(void *opaque,
					struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	struct fbnic_fw_completion *cmpl_data;
	u32 index, last_offset, last_length;
	struct fbnic_tlv_msg *data_hdr;
	u32 length = 0, offset = 0;
	int err = 0;
	void *data;

	/* Verify we have a completion pointer to provide with data */
	cmpl_data = READ_ONCE(fbd->cmpl_data);
	if (!cmpl_data ||
	    cmpl_data->msg_type != FBNIC_TLV_MSG_ID_COREDUMP_READ_RESP)
		return -ENOSPC;

	get_signed_result(FBNIC_FW_COREDUMP_READ_ERROR, err);
	if (err)
		goto msg_err;

	data_hdr = results[FBNIC_FW_COREDUMP_READ_DATA];
	if (!data_hdr) {
		err = -ENODATA;
		goto msg_err;
	}

	get_unsigned_result(FBNIC_FW_COREDUMP_READ_OFFSET, offset);
	get_unsigned_result(FBNIC_FW_COREDUMP_READ_LENGTH, length);

	if (length > (le16_to_cpu(data_hdr->hdr.len) - sizeof(u32))) {
		dev_err(fbd->dev, "length greater than size of data\n");
		err = -EINVAL;
		goto msg_err;
	}

	/* Only the last offset can have a length != stride */
	last_length =
		(cmpl_data->coredump.size % cmpl_data->coredump.stride) ? :
		cmpl_data->coredump.stride;
	last_offset = cmpl_data->coredump.size - last_length;

	/* Verify offset and length */
	if (offset % cmpl_data->coredump.stride || offset > last_offset) {
		dev_err(fbd->dev, "offset %d out of range\n", offset);
		err = -EINVAL;
	} else if (length != ((offset == last_offset) ?
			      last_length : cmpl_data->coredump.stride)) {
		dev_err(fbd->dev, "length %d out of range for offset %d\n",
			length, offset);
		err = -EINVAL;
	}

	if (err)
		goto msg_err;

	/* If data pointer is NULL it is already filled, just skip the copy */
	index = offset / cmpl_data->coredump.stride;
	if (!cmpl_data->coredump.data[index])
		goto msg_err;

	data = fbnic_tlv_attr_get_value_ptr(data_hdr);

	/* Copy data and mark index filled by setting pointer to NULL */
	if (!err) {
		memcpy(cmpl_data->coredump.data[index], data, length);
		cmpl_data->coredump.data[index] = NULL;
	}

msg_err:
	cmpl_data->result = err;
	complete(&cmpl_data->done);

	return err;
}

/**
 * fbnic_fw_xmit_fw_start_upgrade - Create and transmit a start update message
 * @fbd: FBNIC device structure
 * @cmpl_data: Completion data for upgrade process
 * @id: Component ID
 * @len: Length of FW update package data
 *
 * Returns 0 on success, negative value on failure
 *
 * Asks the FW to prepare for starting a firmware upgrade
 */
int fbnic_fw_xmit_fw_start_upgrade(struct fbnic_dev *fbd,
				   struct fbnic_fw_completion *cmpl_data,
				   unsigned int id, unsigned int len)
{
	struct fbnic_tlv_msg *msg;
	int err = 0;

	if (!fbnic_is_asic(fbd))
		return -EOPNOTSUPP;
	if (!fbnic_fw_present(fbd))
		return -ENODEV;

	if (!len)
		return -EINVAL;

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_FW_START_UPGRADE_REQ);
	if (!msg)
		return -ENOMEM;

	err = fbnic_tlv_attr_put_int(msg, FBNIC_FW_START_UPGRADE_SECTION, id);
	if (err)
		goto free_message;

	err = fbnic_tlv_attr_put_int(msg, FBNIC_FW_START_UPGRADE_IMAGE_LENGTH,
				     len);
	if (err)
		goto free_message;

	err = fbnic_mbx_map_req_w_cmpl(fbd, msg, cmpl_data);
	if (err)
		goto free_message;

	return 0;

free_message:
	fbnic_free_page(fbd, msg);
	return err;
}

static const struct fbnic_tlv_index fbnic_fw_start_upgrade_resp_index[] = {
	FBNIC_TLV_ATTR_S32(FBNIC_FW_START_UPGRADE_ERROR),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_fw_start_upgrade_resp(void *opaque,
						struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	struct fbnic_fw_completion *cmpl_data;
	int err = 0;

	/* Verify we have a completion pointer */
	cmpl_data = READ_ONCE(fbd->cmpl_data);
	if (!cmpl_data ||
	    cmpl_data->msg_type != FBNIC_TLV_MSG_ID_FW_WRITE_CHUNK_REQ)
		return -ENOSPC;

	/* Check for errors */
	get_signed_result(FBNIC_FW_START_UPGRADE_ERROR, err);

	cmpl_data->result = err;
	complete(&cmpl_data->done);

	return 0;
}

static const struct fbnic_tlv_index fbnic_fw_write_chunk_req_index[] = {
	FBNIC_TLV_ATTR_U32(FBNIC_FW_WRITE_CHUNK_OFFSET),
	FBNIC_TLV_ATTR_U32(FBNIC_FW_WRITE_CHUNK_LENGTH),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_fw_write_chunk_req(void *opaque,
					     struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	struct fbnic_fw_completion *cmpl_data;
	u32 length = 0, offset = 0;
	struct fbnic_tlv_msg *msg;
	int err = 0;

	/* Start by attempting to allocate a response to the message */
	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_FW_WRITE_CHUNK_RESP);
	if (!msg)
		return -ENOMEM;

	/* Verify we have a completion pointer */
	cmpl_data = READ_ONCE(fbd->cmpl_data);
	if (!cmpl_data ||
	    cmpl_data->msg_type != FBNIC_TLV_MSG_ID_FW_WRITE_CHUNK_REQ) {
		err = -ENOSPC;
		goto msg_err;
	}

	/* Notify FW if the data link has been severed */
	if (!cmpl_data->fw_update.data) {
		err = -ECANCELED;
		goto msg_err;
	}

	/* pull length/offset pair and mark it as complete */
	get_unsigned_result(FBNIC_FW_WRITE_CHUNK_OFFSET, offset);
	get_unsigned_result(FBNIC_FW_WRITE_CHUNK_LENGTH, length);

	/* Record offset and length for the response */
	if (offset) {
		err = fbnic_tlv_attr_put_int(msg, FBNIC_FW_WRITE_CHUNK_OFFSET,
					     offset);
		if (err)
			goto msg_err;
	}

	err = fbnic_tlv_attr_put_int(msg, FBNIC_FW_WRITE_CHUNK_LENGTH,
				     length);
	if (err)
		goto msg_err;

	/* Verify length */
	if (!length || length > TLV_MAX_DATA) {
		err = -EINVAL;
		goto msg_err;
	}

	/* Verify offset and length are within bounds */
	if (offset >= cmpl_data->fw_update.size ||
	    (offset + length) > cmpl_data->fw_update.size) {
		err = -EFAULT;
		goto msg_err;
	}

	/* Add outbound data to message */
	err = fbnic_tlv_attr_put_value(msg, FBNIC_FW_WRITE_CHUNK_DATA,
				       cmpl_data->fw_update.data + offset,
				       length);

	/* Notify the waiting thread that we processed a message */
	if (!err)
		cmpl_data->fw_update.last_offset = offset;

	cmpl_data->result = err;
	complete(&cmpl_data->done);

msg_err:
	/* Report error to FW if one occurred */
	if (err)
		fbnic_tlv_attr_put_int(msg, FBNIC_FW_WRITE_CHUNK_ERROR, err);

	/* Map and send the response */
	err = fbnic_mbx_map_tlv_msg(fbd, msg);
	if (err)
		fbnic_free_page(fbd, msg);

	return err;
}

/**
 * fbnic_fw_xmit_fw_verify_image - Create and transmit a verify FW image message
 * @fbd: FBNIC device structure
 *
 * Returns 0 on success, negative value on failure
 *
 * Asks the FW to validate the firmware image
 */
int fbnic_fw_xmit_fw_verify_image(struct fbnic_dev *fbd)
{
	u32 msg_type = FBNIC_TLV_MSG_ID_FW_VERIFY_IMAGE_REQ;

	return fbnic_fw_xmit_simple_msg(fbd, msg_type);
}

static const struct fbnic_tlv_index fbnic_fw_verify_image_resp_index[] = {
	FBNIC_TLV_ATTR_S32(FBNIC_FW_VERIFY_IMAGE_ERROR),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_fw_verify_image_resp(void *opaque,
					       struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	struct fbnic_fw_completion *cmpl_data;
	int err = 0;

	/* Verify we have a completion pointer */
	cmpl_data = READ_ONCE(fbd->cmpl_data);
	if (!cmpl_data ||
	    cmpl_data->msg_type != FBNIC_TLV_MSG_ID_FW_VERIFY_IMAGE_RESP)
		return -ENOSPC;

	/* Check for errors */
	get_signed_result(FBNIC_FW_VERIFY_IMAGE_ERROR, err);

	cmpl_data->result = err;
	complete(&cmpl_data->done);

	return err;
}

static const struct fbnic_tlv_index fbnic_fw_finish_upgrade_req_index[] = {
	FBNIC_TLV_ATTR_S32(FBNIC_FW_FINISH_UPGRADE_ERROR),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_fw_finish_upgrade_req(void *opaque,
						struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	struct fbnic_fw_completion *cmpl_data;
	int err = 0;

	/* Verify we have a completion pointer */
	cmpl_data = READ_ONCE(fbd->cmpl_data);
	if (!cmpl_data ||
	    cmpl_data->msg_type != FBNIC_TLV_MSG_ID_FW_WRITE_CHUNK_REQ)
		return -ENOSPC;

	/* Check for errors */
	get_signed_result(FBNIC_FW_FINISH_UPGRADE_ERROR, err);

	/* Close out update by clearing data pointer */
	cmpl_data->fw_update.last_offset = cmpl_data->fw_update.size;
	cmpl_data->fw_update.data = NULL;

	cmpl_data->result = err;
	complete(&cmpl_data->done);

	return 0;
}

/**
 * fbnic_fw_xmit_eeprom_read_msg - Create and transmit a eeprom read request
 *
 * @fbd: FBNIC device structure
 * @cmpl_data: Completion data to store response in
 * @offset: Offset into eeprom requested
 * @length: Length of section of eeprom to fetch
 *
 * Returns 0 on success, negative value on failure
 *
 * Asks the firmware to provide a section of the eeprom back in a message.
 * The response will have an offset and size matching the values provided.
 */
int fbnic_fw_xmit_eeprom_read_msg(struct fbnic_dev *fbd,
				  struct fbnic_fw_completion *cmpl_data,
				  u32 offset, u32 length)
{
	struct fbnic_tlv_msg *msg;
	int err = 0;

	if (!fbnic_is_asic(fbd) || !fbnic_fw_present(fbd))
		return -ENODEV;

	if (!length || length > TLV_MAX_DATA)
		return -EINVAL;

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_EEPROM_READ_REQ);
	if (!msg)
		return -ENOMEM;

	if (offset) {
		err = fbnic_tlv_attr_put_int(msg, FBNIC_EEPROM_READ_OFFSET,
					     offset);
		if (err)
			goto free_message;
	}

	err = fbnic_tlv_attr_put_int(msg, FBNIC_EEPROM_READ_LENGTH, length);
	if (err)
		goto free_message;

	err = fbnic_mbx_map_req_w_cmpl(fbd, msg, cmpl_data);
	if (err)
		goto free_message;

	return 0;

free_message:
	fbnic_free_page(fbd, msg);
	return err;
}

static const struct fbnic_tlv_index fbnic_eeprom_read_resp_index[] = {
	FBNIC_TLV_ATTR_U32(FBNIC_EEPROM_READ_OFFSET),
	FBNIC_TLV_ATTR_U32(FBNIC_EEPROM_READ_LENGTH),
	FBNIC_TLV_ATTR_RAW_DATA(FBNIC_EEPROM_READ_DATA),
	FBNIC_TLV_ATTR_S32(FBNIC_EEPROM_READ_ERROR),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_eeprom_read_resp(void *opaque,
					   struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	struct fbnic_fw_completion *cmpl_data;
	struct fbnic_tlv_msg *data_hdr;
	u32 length = 0, offset = 0;
	int err = 0, err_resp = 0;
	u8 *data;

	/* Verify we have a completion pointer to provide with data */
	cmpl_data = READ_ONCE(fbd->cmpl_data);
	if (!cmpl_data ||
	    cmpl_data->msg_type != FBNIC_TLV_MSG_ID_EEPROM_READ_RESP)
		return -ENOSPC;

	get_signed_result(FBNIC_EEPROM_READ_ERROR, err_resp);
	if (err_resp)
		goto msg_err;

	data_hdr = results[FBNIC_EEPROM_READ_DATA];
	if (!data_hdr) {
		err = -ENODATA;
		goto msg_err;
	}

	get_unsigned_result(FBNIC_EEPROM_READ_OFFSET, offset);
	get_unsigned_result(FBNIC_EEPROM_READ_LENGTH, length);

	if (length != cmpl_data->eeprom.size ||
	    offset != cmpl_data->eeprom.offset) {
		dev_err(fbd->dev,
			"offset/length not equal to size requested: %d/%d vs %d/%d\n",
			 offset, length,
			 cmpl_data->eeprom.offset, cmpl_data->eeprom.size);
		err = -EINVAL;
		goto msg_err;
	}

	/* Copy data */
	data = fbnic_tlv_attr_get_value_ptr(data_hdr);
	memcpy(cmpl_data->eeprom.data, data, length);
msg_err:
	cmpl_data->result = err_resp ? : err;
	complete(&cmpl_data->done);

	return err;
}

/**
 * fbnic_fw_xmit_eeprom_write_msg - Create and transmit a eeprom write request
 *
 * @fbd: FBNIC device structure
 * @cmpl_data: Pointer to completion data for processing write
 * @offset: Offset into eeprom requested
 * @length: Length of section of EEPROM to write
 * @data: Data to be written
 *
 * Returns 0 on success, negative value on failure
 *
 * Asks the firmware to write a section of the eeprom with data in a message.
 * The response will have an offset and size matching the values provided.
 */
int fbnic_fw_xmit_eeprom_write_msg(struct fbnic_dev *fbd,
				   struct fbnic_fw_completion *cmpl_data,
				   u32 offset, u32 length, const u8 *data)
{
	struct fbnic_tlv_msg *msg;
	int err = 0;

	if (!fbnic_is_asic(fbd) || !fbnic_fw_present(fbd))
		return -ENODEV;

	if (!length || length > TLV_MAX_DATA || !data)
		return -EINVAL;

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_EEPROM_WRITE_REQ);
	if (!msg)
		return -ENOMEM;

	if (offset) {
		err = fbnic_tlv_attr_put_int(msg, FBNIC_EEPROM_WRITE_OFFSET,
					     offset);
		if (err)
			goto free_message;
	}

	err = fbnic_tlv_attr_put_int(msg, FBNIC_EEPROM_WRITE_LENGTH,
				     length);
	if (err)
		goto free_message;

	/* Add outbound data to message */
	err = fbnic_tlv_attr_put_value(msg, FBNIC_EEPROM_WRITE_DATA,
				       data, length);
	if (err)
		goto free_message;

	err = fbnic_mbx_map_req_w_cmpl(fbd, msg, cmpl_data);
	if (err)
		goto free_message;

	return 0;

free_message:
	fbnic_free_page(fbd, msg);
	return err;
}

static const struct fbnic_tlv_index fbnic_eeprom_write_resp_index[] = {
	FBNIC_TLV_ATTR_U32(FBNIC_EEPROM_WRITE_OFFSET),
	FBNIC_TLV_ATTR_U32(FBNIC_EEPROM_WRITE_LENGTH),
	FBNIC_TLV_ATTR_S32(FBNIC_EEPROM_WRITE_ERROR),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_eeprom_write_resp(void *opaque,
					    struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	struct fbnic_fw_completion *cmpl_data;
	u32 length = 0, offset = 0;
	int err = 0, err_resp = 0;

	/* Verify we have a completion pointer to provide with data */
	cmpl_data = READ_ONCE(fbd->cmpl_data);
	if (!cmpl_data ||
	    cmpl_data->msg_type != FBNIC_TLV_MSG_ID_EEPROM_WRITE_RESP)
		return -ENOSPC;

	get_signed_result(FBNIC_EEPROM_WRITE_ERROR, err_resp);
	if (err_resp)
		goto msg_err;

	get_unsigned_result(FBNIC_EEPROM_WRITE_OFFSET, offset);
	get_unsigned_result(FBNIC_EEPROM_WRITE_LENGTH, length);

	if (length != cmpl_data->eeprom.size ||
	    offset != cmpl_data->eeprom.offset) {
		dev_err(fbd->dev,
			"offset/length not equal to size requested: %d/%d vs %d/%d\n",
			 offset, length,
			 cmpl_data->eeprom.offset, cmpl_data->eeprom.size);
		err = -EINVAL;
		goto msg_err;
	}
msg_err:
	cmpl_data->result = err_resp ? : err;
	complete(&cmpl_data->done);

	return err;
}

/**
 * fbnic_fw_xmit_qsfp_read_msg - Transmit a QSFP read request
 *
 * @fbd: FBNIC device structure
 * @cmpl_data: Structure to store EEPROM response in
 * @page: Refers to page number on page enabled QSFP modules
 * @bank: Refers to a collection of pages
 * @offset: Offset into qsfp eeprom requested
 * @length: Length of section of qsfp eeprom to fetch
 *
 * Returns 0 on success, negative value on failure
 *
 * Asks the firmware to provide a section of the qsfp eeprom back in a
 * message. The response will have an offset and size matching the values
 * provided.
 */
int fbnic_fw_xmit_qsfp_read_msg(struct fbnic_dev *fbd,
				struct fbnic_fw_completion *cmpl_data,
				u32 page, u32 bank, u32 offset, u32 length)
{
	struct fbnic_tlv_msg *msg;
	int err = 0;

	if (!fbnic_is_asic(fbd) || !fbnic_fw_present(fbd))
		return -ENODEV;

	if (!length || length > TLV_MAX_DATA)
		return -EINVAL;

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_QSFP_READ_REQ);
	if (!msg)
		return -ENOMEM;

	if (bank) {
		err = fbnic_tlv_attr_put_int(msg, FBNIC_QSFP_BANK, bank);
		if (err)
			goto free_message;
	}
	if (page) {
		err = fbnic_tlv_attr_put_int(msg, FBNIC_QSFP_PAGE, page);
		if (err)
			goto free_message;
	}
	if (offset) {
		err = fbnic_tlv_attr_put_int(msg, FBNIC_QSFP_OFFSET, offset);
		if (err)
			goto free_message;
	}

	err = fbnic_tlv_attr_put_int(msg, FBNIC_QSFP_LENGTH, length);
	if (err)
		goto free_message;

	err = fbnic_mbx_map_req_w_cmpl(fbd, msg, cmpl_data);
	if (err)
		goto free_message;

	return 0;

free_message:
	fbnic_free_page(fbd, msg);
	return err;
}

static const struct fbnic_tlv_index fbnic_qsfp_read_resp_index[] = {
	FBNIC_TLV_ATTR_U32(FBNIC_QSFP_BANK),
	FBNIC_TLV_ATTR_U32(FBNIC_QSFP_PAGE),
	FBNIC_TLV_ATTR_U32(FBNIC_QSFP_OFFSET),
	FBNIC_TLV_ATTR_U32(FBNIC_QSFP_LENGTH),
	FBNIC_TLV_ATTR_RAW_DATA(FBNIC_QSFP_DATA),
	FBNIC_TLV_ATTR_S32(FBNIC_QSFP_ERROR),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_qsfp_read_resp(void *opaque,
					 struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	u32 length = 0, offset = 0, page = 0, bank = 0;
	struct fbnic_fw_completion *cmpl_data;
	struct fbnic_tlv_msg *data_hdr;
	int err = 0, err_resp = 0;
	u8 *data;

	/* Verify we have a completion pointer to provide with data */
	cmpl_data = READ_ONCE(fbd->cmpl_data);
	if (!cmpl_data ||
	    cmpl_data->msg_type != FBNIC_TLV_MSG_ID_QSFP_READ_RESP)
		return -ENOSPC;

	get_signed_result(FBNIC_QSFP_ERROR, err_resp);
	if (err_resp)
		goto msg_err;

	data_hdr = results[FBNIC_QSFP_DATA];
	if (!data_hdr) {
		err = -ENODATA;
		goto msg_err;
	}

	get_unsigned_result(FBNIC_QSFP_BANK, bank);
	if (bank != cmpl_data->qsfp.bank) {
		dev_err(fbd->dev, "bank not equal to bank requested: %d vs %d\n",
			bank, cmpl_data->qsfp.bank);
		err = -EINVAL;
		goto msg_err;
	}
	get_unsigned_result(FBNIC_QSFP_PAGE, page);
	if (page != cmpl_data->qsfp.page) {
		dev_err(fbd->dev, "page not equal to page requested: %d vs %d\n",
			page, cmpl_data->qsfp.page);
		err = -EINVAL;
		goto msg_err;
	}
	get_unsigned_result(FBNIC_QSFP_OFFSET, offset);
	get_unsigned_result(FBNIC_QSFP_LENGTH, length);

	if (length != cmpl_data->qsfp.size ||
	    offset != cmpl_data->qsfp.offset) {
		dev_err(fbd->dev,
			"offset/length not equal to size requested: %d/%d vs %d/%d\n",
			 offset, length,
			 cmpl_data->qsfp.offset, cmpl_data->qsfp.size);
		err = -EINVAL;
		goto msg_err;
	}

	/* Copy data */
	data = fbnic_tlv_attr_get_value_ptr(data_hdr);
	memcpy(cmpl_data->qsfp.data, data, length);
msg_err:
	cmpl_data->result = err_resp ? : err;
	complete(&cmpl_data->done);

	return err;
}

/**
 * fbnic_fw_xmit_tsene_read_msg - Create and transmit a sensor read request
 *
 * @fbd: FBNIC device structure
 * @cmpl_data: Completion data to store response in
 *
 * Returns 0 on success, negative value on failure
 *
 * Asks the firmware to provide an update w/ the latest sensor data
 */
int fbnic_fw_xmit_tsene_read_msg(struct fbnic_dev *fbd,
				 struct fbnic_fw_completion *cmpl_data)
{
	struct fbnic_tlv_msg *msg;
	int err = 0;

	if (!fbnic_is_asic(fbd) || !fbnic_fw_present(fbd))
		return -ENODEV;

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_TSENE_READ_REQ);
	if (!msg)
		return -ENOMEM;

	err = fbnic_mbx_map_req_w_cmpl(fbd, msg, cmpl_data);
	if (err)
		goto free_message;

	return 0;

free_message:
	fbnic_free_page(fbd, msg);
	return err;
}

static const struct fbnic_tlv_index fbnic_tsene_read_resp_index[] = {
	FBNIC_TLV_ATTR_S32(FBNIC_TSENE_THERM),
	FBNIC_TLV_ATTR_S32(FBNIC_TSENE_VOLT),
	FBNIC_TLV_ATTR_S32(FBNIC_TSENE_ERROR),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_tsene_read_resp(void *opaque,
					  struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	struct fbnic_fw_completion *cmpl_data;
	s32 millidegrees = 0, millivolts = 0;
	int err = 0, err_resp = 0;

	/* Verify we have a completion pointer to provide with data */
	cmpl_data = READ_ONCE(fbd->cmpl_data);
	if (!cmpl_data ||
	    cmpl_data->msg_type != FBNIC_TLV_MSG_ID_TSENE_READ_RESP)
		return -ENOSPC;

	get_signed_result(FBNIC_TSENE_ERROR, err_resp);
	if (err_resp)
		goto msg_err;

	if (!results[FBNIC_TSENE_THERM] || !results[FBNIC_TSENE_VOLT]) {
		err = -EINVAL;
		goto msg_err;
	}

	get_signed_result(FBNIC_TSENE_THERM, millidegrees);
	get_signed_result(FBNIC_TSENE_VOLT, millivolts);

	cmpl_data->tsene.millidegrees = millidegrees;
	cmpl_data->tsene.millivolts = millivolts;

msg_err:
	cmpl_data->result = err_resp ? : err;
	complete(&cmpl_data->done);

	return err;
}

/**
 * fbnic_fw_xmit_comphy_set_msg - Create and transmit a comphy set request
 *
 * @fbd: FBNIC device structure
 * @speed: Indicates link speed, composed of modulation and number of lanes
 *
 * Returns 0 on success, negative value on failure
 *
 * Asks the firmware to reconfigure the comphy for this slice to the target
 * speed.
 */
int fbnic_fw_xmit_comphy_set_msg(struct fbnic_dev *fbd, u32 speed)
{
	struct fbnic_tlv_msg *msg;
	int err = 0;

	/* Only neeeded for ASIC, for FPGA we can skip this */
	if (!fbnic_is_asic(fbd))
		return 0;

	if (!fbnic_fw_present(fbd))
		return -ENODEV;

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_COMPHY_SET_REQ);
	if (!msg)
		return -ENOMEM;

	err = fbnic_tlv_attr_put_int(msg, FBNIC_COMPHY_SET_PAM4,
				     !!(speed & FBNIC_LINK_MODE_PAM4));
	if (err)
		goto free_message;

	err = fbnic_mbx_map_tlv_msg(fbd, msg);
	if (err)
		goto free_message;

	return 0;

free_message:
	fbnic_free_page(fbd, msg);
	return err;
}

static const struct fbnic_tlv_index fbnic_comphy_set_resp_index[] = {
	FBNIC_TLV_ATTR_S32(FBNIC_COMPHY_SET_ERROR),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_comphy_set_resp(void *opaque,
					  struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	int err_resp = 0;

	get_signed_result(FBNIC_COMPHY_SET_ERROR, err_resp);
	if (err_resp)
		dev_err(fbd->dev, "COMPHY_SET returned %d\n", err_resp);

	return 0;
}

static const struct fbnic_tlv_index fbnic_threshold_exceeded_resp_index[] = {
	FBNIC_TLV_ATTR_S32(FBNIC_TSENE_THERM_EXCEEDED_FLAG),
	FBNIC_TLV_ATTR_S32(FBNIC_TSENE_VOLT_EXCEEDED_FLAG),
	FBNIC_TLV_ATTR_S32(FBNIC_TSENE_THERMAL),
	FBNIC_TLV_ATTR_S32(FBNIC_TSENE_VOLTAGE),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_threshold_exceeded_resp(void *opaque,
						  struct fbnic_tlv_msg
						  **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	bool rec_flag = false;
	s32 exceeded, value;

	exceeded = 0;
	value = 0;
	get_signed_result(FBNIC_TSENE_THERM_EXCEEDED_FLAG, exceeded);

	if (exceeded) {
		if (results[FBNIC_TSENE_THERMAL]) {
			get_signed_result(FBNIC_TSENE_THERMAL, value);
			dev_err(fbd->dev, "Thermal level exceeded, it is currently %d°C!\n",
				value);
		} else {
			dev_err(fbd->dev, "Thermal level exceeded but no value received!\n");
		}
		rec_flag = true;
	}

	exceeded = 0;
	value = 0;
	get_signed_result(FBNIC_TSENE_VOLT_EXCEEDED_FLAG, exceeded);

	if (exceeded) {
		if (results[FBNIC_TSENE_VOLTAGE]) {
			get_signed_result(FBNIC_TSENE_VOLTAGE, value);
			dev_err(fbd->dev, "Voltage level exceeded, it is currently %dV!\n",
				value);
		} else {
			dev_err(fbd->dev, "Voltage level exceeded but no value received!\n");
		}
		rec_flag = true;
	}

	if (!rec_flag) {
		dev_warn(fbd->dev,
			 "Threshold exceeded message received but no recognized flag found!\n");
		return -EINVAL;
	}

	return 0;
}

static const struct fbnic_tlv_index fbnic_fw_log_req_index[] = {
	FBNIC_TLV_ATTR_U32(FBNIC_FW_LOG_MSEC),
	FBNIC_TLV_ATTR_U64(FBNIC_FW_LOG_INDEX),
	FBNIC_TLV_ATTR_STRING(FBNIC_FW_LOG_MSG, FBNIC_FW_LOG_MAX_SIZE),
	FBNIC_TLV_ATTR_LAST
};

static int fbnic_fw_parse_log_req(void *opaque,
				  struct fbnic_tlv_msg **results)
{
	struct fbnic_dev *fbd = (struct fbnic_dev *)opaque;
	char log[FBNIC_FW_LOG_MAX_SIZE];
	size_t log_size = 0;
	u32 timestamp = 0;
	u64 index = 0;
	int err = 0;

	get_string_result(FBNIC_FW_LOG_MSG, log_size, log,
			  FBNIC_FW_LOG_MAX_SIZE);

	if (log_size == 0) {
		dev_warn(fbd->dev, "Empty firmware log message received!\n");
		return -EINVAL;
	}

	get_unsigned_result(FBNIC_FW_LOG_MSEC, timestamp);
	get_unsigned_result(FBNIC_FW_LOG_INDEX, index);

	err = fbnic_fw_log_write(fbd, index, timestamp, log);
	if (err)
		return err;

	/* TBD: ACK successful receipt of the log resp. */

	return 0;
}

static const struct fbnic_tlv_parser fbnic_fw_tlv_parser[] = {
	FBNIC_TLV_MSG_TEST,
	FBNIC_TLV_PARSER(FW_CAP_RESP, fbnic_fw_cap_resp_index,
			 fbnic_fw_parse_cap_resp),
	FBNIC_TLV_PARSER(OWNERSHIP_RESP, fbnic_ownership_resp_index,
			 fbnic_fw_parse_ownership_resp),
	FBNIC_TLV_PARSER(HEARTBEAT_RESP, fbnic_heartbeat_resp_index,
			 fbnic_fw_parse_heartbeat_resp),
	FBNIC_TLV_PARSER(EEPROM_LOCK_RESP, fbnic_eeprom_lock_resp_index,
			 fbnic_fw_parse_eeprom_lock_resp),
	FBNIC_TLV_PARSER(COREDUMP_GET_INFO_RESP,
			 fbnic_coredump_info_resp_index,
			 fbnic_fw_parse_coredump_info_resp),
	FBNIC_TLV_PARSER(COREDUMP_READ_RESP, fbnic_coredump_resp_index,
			 fbnic_fw_parse_coredump_resp),
	FBNIC_TLV_PARSER(FW_START_UPGRADE_RESP,
			 fbnic_fw_start_upgrade_resp_index,
			 fbnic_fw_parse_fw_start_upgrade_resp),
	FBNIC_TLV_PARSER(FW_WRITE_CHUNK_REQ,
			 fbnic_fw_write_chunk_req_index,
			 fbnic_fw_parse_fw_write_chunk_req),
	FBNIC_TLV_PARSER(FW_VERIFY_IMAGE_RESP,
			 fbnic_fw_verify_image_resp_index,
			 fbnic_fw_parse_fw_verify_image_resp),
	FBNIC_TLV_PARSER(FW_FINISH_UPGRADE_REQ,
			 fbnic_fw_finish_upgrade_req_index,
			 fbnic_fw_parse_fw_finish_upgrade_req),
	FBNIC_TLV_PARSER(EEPROM_READ_RESP,
			 fbnic_eeprom_read_resp_index,
			 fbnic_fw_parse_eeprom_read_resp),
	FBNIC_TLV_PARSER(EEPROM_WRITE_RESP,
			 fbnic_eeprom_write_resp_index,
			 fbnic_fw_parse_eeprom_write_resp),
	FBNIC_TLV_PARSER(QSFP_READ_RESP,
			 fbnic_qsfp_read_resp_index,
			 fbnic_fw_parse_qsfp_read_resp),
	FBNIC_TLV_PARSER(TSENE_READ_RESP,
			 fbnic_tsene_read_resp_index,
			 fbnic_fw_parse_tsene_read_resp),
	FBNIC_TLV_PARSER(COMPHY_SET_RESP,
			 fbnic_comphy_set_resp_index,
			 fbnic_fw_parse_comphy_set_resp),
	FBNIC_TLV_PARSER(SENSOR_THRESHOLD_EXCEEDED_RESP,
			 fbnic_threshold_exceeded_resp_index,
			 fbnic_fw_parse_threshold_exceeded_resp),
	FBNIC_TLV_PARSER(LOG_MSG_REQ,
			 fbnic_fw_log_req_index,
			 fbnic_fw_parse_log_req),
	FBNIC_TLV_MSG_ERROR
};

static void fbnic_mbx_process_rx_msgs(struct fbnic_dev *fbd)
{
	struct fbnic_fw_mbx *rx_mbx = &fbd->mbx[FBNIC_IPC_MBX_RX_IDX];
	u8 head = rx_mbx->head;
	u64 desc, length;

	while (head != rx_mbx->tail) {
		struct fbnic_tlv_msg *msg;
		int err;

		desc = __fbnic_mbx_rd_desc(fbd, FBNIC_IPC_MBX_RX_IDX, head);
		if (!(desc & FBNIC_IPC_MBX_DESC_FW_CMPL))
			break;

		fbnic_dma_unmap(fbd, rx_mbx->buf_info[head].msg,
				PAGE_SIZE, DMA_FROM_DEVICE,
				rx_mbx->buf_info[head].addr);

		msg = rx_mbx->buf_info[head].msg;

		length = FIELD_GET(FBNIC_IPC_MBX_DESC_LEN_MASK, desc);

		if (!length || length > PAGE_SIZE) {
			dev_warn(fbd->dev,
				 "Invalid mailbox descriptor length: %lld\n",
				 length);
			goto next_page;
		}

		if (le16_to_cpu(msg->hdr.len) * sizeof(u32) > length)
			dev_warn(fbd->dev, "Mailbox message length mismatch\n");

		/* If parsing fails dump conents of message to dmesg */
		err = fbnic_tlv_msg_parse(fbd, msg, fbnic_fw_tlv_parser);
		if (err) {
			rx_mbx->parser_error++;
			dev_warn(fbd->dev, "Unable to process message: %d\n",
				 err);
			print_hex_dump(KERN_WARNING, "fbnic:",
				       DUMP_PREFIX_OFFSET, 16, 2,
				       msg, length, true);
		}

		dev_dbg(fbd->dev, "Parsed msg type %d\n", msg->hdr.type);
next_page:
		fbnic_free_page(fbd, rx_mbx->buf_info[head].msg);
		rx_mbx->buf_info[head].msg = NULL;

		head++;
		head %= FBNIC_IPC_MBX_DESC_LEN;
	}

	/* record head for next interrupt */
	rx_mbx->head = head;

	/* Make sure we have at least one page for the FW to write to */
	fbnic_mbx_alloc_rx_msgs(fbd);
}

void fbnic_mbx_poll(struct fbnic_dev *fbd)
{
	fbnic_mbx_postinit(fbd);

	fbnic_mbx_process_tx_msgs(fbd);
	fbnic_mbx_process_rx_msgs(fbd);
}

int fbnic_mbx_poll_tx_ready(struct fbnic_dev *fbd)
{
	struct fbnic_fw_mbx *tx_mbx;
	int attempts = 50;

	/* Nothing to do if there is no mailbox */
	if (!fbnic_is_asic(fbd) || !fbnic_fw_present(fbd))
		return 0;

	tx_mbx = &fbd->mbx[FBNIC_IPC_MBX_TX_IDX];
	while (!tx_mbx->ready && --attempts) {
		msleep(200);
		fbnic_mbx_poll(fbd);
	}

	return attempts ? 0 : -ETIMEDOUT;
}

void fbnic_mbx_flush_tx(struct fbnic_dev *fbd)
{
	struct fbnic_fw_mbx *tx_mbx;
	int attempts = 50;
	u8 count = 0;

	/* Nothing to do if there is no mailbox */
	if (!fbnic_is_asic(fbd) || !fbnic_fw_present(fbd))
		return;

	/* Record current Rx stats */
	tx_mbx = &fbd->mbx[FBNIC_IPC_MBX_TX_IDX];

	/* Nothing to do if mailbox never got to ready */
	if (!tx_mbx->ready)
		return;

	/* give firmware time to process packet,
	 * we will wait up to 10 seconds which is 50 waits of 200ms.
	 */
	do {
		u8 head = tx_mbx->head;

		if (head == tx_mbx->tail)
			break;

		msleep(200);
		fbnic_mbx_process_tx_msgs(fbd);

		count += (tx_mbx->head - head) % FBNIC_IPC_MBX_DESC_LEN;
	} while (count < FBNIC_IPC_MBX_DESC_LEN && --attempts);
}

int fbnic_fw_mbx_self_test(struct fbnic_dev *fbd, bool poll)
{
	struct fbnic_fw_mbx *rx_mbx;
	int err, attempts = 50;
	u64 parser_error;
	u8 head;

	/* Skip test if we are on the FPGA since there is no mailbox */
	if (!fbnic_is_asic(fbd))
		return 0;

	/* Skip test if FW interface is not present */
	if (!fbnic_fw_present(fbd))
		return 10;

	/* Record current Rx stats */
	rx_mbx = &fbd->mbx[FBNIC_IPC_MBX_RX_IDX];
	parser_error = rx_mbx->parser_error;
	head = rx_mbx->head;

	/* Load a test message onto the FW mailbox interface */
	err = fbnic_fw_xmit_test_msg(fbd);
	if (err)
		return 20;

	/* give firmware time to process packet,
	 * we will wait up to 10 seconds which is 50 waits of 200ms.
	 *
	 * TBD: Will need to roll this back later once we have actual silicon
	 */
	do {
		msleep(200);
		if (poll)
			fbnic_mbx_poll(fbd);
	} while (head == rx_mbx->head && --attempts);

	/* Verify we received a message back */
	if (!attempts)
		return 30;

	/* Verify there were no parsing errors */
	if (parser_error != rx_mbx->parser_error)
		return 40;

	return 0;
}

int fbnic_fw_xmit_send_logs(struct fbnic_dev *fbd, bool enabled)
{
	struct fbnic_tlv_msg *msg;
	int err = 0;

	if (!fbnic_fw_present(fbd))
		return -ENODEV;

	if (enabled &&
	    fbd->fw_cap.running.mgmt.version < MIN_FW_LOG_VERSION_CODE) {
		dev_warn(fbd->dev, "Firmware version is too old to support firmware logs!\n");
		return -EOPNOTSUPP;
	}

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_LOG_SEND_LOGS_REQ);
	if (!msg)
		return -ENOMEM;

	if (enabled) {
		err = fbnic_tlv_attr_put_flag(msg, FBNIC_SEND_LOGS);
		if (err)
			goto free_message;

		/* Report request for version 1 of logs */
		err = fbnic_tlv_attr_put_int(msg, FBNIC_SEND_LOGS_VERSION, 1);
		if (err)
			goto free_message;
	}

	err = fbnic_mbx_map_tlv_msg(fbd, msg);
	if (err)
		goto free_message;

	return 0;

free_message:
	fbnic_free_page(fbd, msg);
	return err;
}

int fbnic_fw_xmit_rpc_macda_sync(struct fbnic_dev *fbd)
{
	struct fbnic_tlv_msg *mac_array;
	int i, addr_count = 0, err = 0;
	struct fbnic_tlv_msg *msg;
	u32 rx_flags = 0;

	if (!fbnic_fw_present(fbd))
		return -ENODEV;

	msg = fbnic_tlv_msg_alloc(fbd, FBNIC_TLV_MSG_ID_RPC_MAC_SYNC_REQ);
	if (!msg)
		return -ENOMEM;

	mac_array = fbnic_tlv_attr_nest_start(msg,
					      FBNIC_FW_RPC_MAC_SYNC_UC_ARRAY);
	if (!mac_array)
		return -ENOSPC;

	/* Populate the unicast MAC addrs and capture PROMISC/ALLMULTI flags */
	for (addr_count = 0, i = FBNIC_RPC_TCAM_MACDA_PROMISC_IDX;
	     i >= fbd->mac_addr_boundary; i--) {
		struct fbnic_mac_addr *mac_addr = &fbd->mac_addr[i];

		if (mac_addr->state != FBNIC_TCAM_S_VALID)
			continue;
		if (test_bit(FBNIC_MAC_ADDR_T_ALLMULTI, mac_addr->act_tcam))
			rx_flags |= FW_RPC_MAC_SYNC_RX_FLAGS_ALLMULTI;
		if (test_bit(FBNIC_MAC_ADDR_T_PROMISC, mac_addr->act_tcam))
			rx_flags |= FW_RPC_MAC_SYNC_RX_FLAGS_PROMISC;
		if (!test_bit(FBNIC_MAC_ADDR_T_UNICAST, mac_addr->act_tcam))
			continue;
		if (addr_count == FW_RPC_MAC_SYNC_UC_ARRAY_SIZE) {
			rx_flags |= FW_RPC_MAC_SYNC_RX_FLAGS_PROMISC;
			continue;
		}

		err = fbnic_tlv_attr_put_value(mac_array,
					       FBNIC_FW_RPC_MAC_SYNC_MAC_ADDR,
					       mac_addr->value.addr8,
					       ETH_ALEN);
		if (err)
			goto free_message;
		addr_count++;
	}

	/* Close array */
	fbnic_tlv_attr_nest_stop(msg);

	mac_array = fbnic_tlv_attr_nest_start(msg,
					      FBNIC_FW_RPC_MAC_SYNC_MC_ARRAY);
	if (!mac_array)
		return -ENOSPC;

	/* Repeat for multicast addrs, record BROADCAST/ALLMULTI flags */
	for (addr_count = 0, i = FBNIC_RPC_TCAM_MACDA_BROADCAST_IDX;
	     i < fbd->mac_addr_boundary; i++) {
		struct fbnic_mac_addr *mac_addr = &fbd->mac_addr[i];

		if (mac_addr->state != FBNIC_TCAM_S_VALID)
			continue;
		if (test_bit(FBNIC_MAC_ADDR_T_BROADCAST, mac_addr->act_tcam))
			rx_flags |= FW_RPC_MAC_SYNC_RX_FLAGS_BROADCAST;
		if (test_bit(FBNIC_MAC_ADDR_T_ALLMULTI, mac_addr->act_tcam))
			rx_flags |= FW_RPC_MAC_SYNC_RX_FLAGS_ALLMULTI;
		if (!test_bit(FBNIC_MAC_ADDR_T_MULTICAST, mac_addr->act_tcam))
			continue;
		if (addr_count == FW_RPC_MAC_SYNC_MC_ARRAY_SIZE) {
			rx_flags |= FW_RPC_MAC_SYNC_RX_FLAGS_ALLMULTI;
			continue;
		}

		err = fbnic_tlv_attr_put_value(mac_array,
					       FBNIC_FW_RPC_MAC_SYNC_MAC_ADDR,
					       mac_addr->value.addr8,
					       ETH_ALEN);
		if (err)
			goto free_message;
		addr_count++;
	}

	/* Close array */
	fbnic_tlv_attr_nest_stop(msg);

	/* Report flags at end of list */
	err = fbnic_tlv_attr_put_int(msg, FBNIC_FW_RPC_MAC_SYNC_RX_FLAGS,
				     rx_flags);
	if (err)
		goto free_message;

	/* Send message of to FW notifying it of current RPC config */
	err = fbnic_mbx_map_tlv_msg(fbd, msg);
	if (err)
		goto free_message;
	return 0;
free_message:
	fbnic_free_page(fbd, msg);
	return err;
}
