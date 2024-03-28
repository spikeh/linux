// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <asm/unaligned.h>
#include <linux/pci.h>
#include <linux/pldmfw.h>
#include <linux/types.h>
#include <net/devlink.h>

#include "fbnic.h"
#include "fbnic_tlv.h"
#include "fbnic_fw.h"

#define FBNIC_SN_STR_LEN	24

static int fbnic_version_running_put(struct devlink_info_req *req,
				     struct fbnic_fw_ver *fw_ver,
				     char *ver_name, char *commit_name)
{
	char running_ver[FBNIC_FW_VER_MAX_SIZE];
	int err;

	fbnic_mk_fw_ver_str(fw_ver->version, running_ver);
	err = devlink_info_version_running_put(req, ver_name, running_ver);
	if (err)
		return err;

	if (strlen(fw_ver->commit) > 0) {
		err = devlink_info_version_running_put(req, commit_name,
						       fw_ver->commit);
		if (err)
			return err;
	}

	return 0;
}

static int fbnic_version_stored_put(struct devlink_info_req *req,
				    struct fbnic_fw_ver *fw_ver,
				    char *ver_name, char *commit_name)
{
	char stored_ver[FBNIC_FW_VER_MAX_SIZE];
	int err;

	fbnic_mk_fw_ver_str(fw_ver->version, stored_ver);
	err = devlink_info_version_stored_put(req, ver_name, stored_ver);
	if (err)
		return err;

	if (strlen(fw_ver->commit) > 0) {
		err = devlink_info_version_stored_put(req, commit_name,
						      fw_ver->commit);
		if (err)
			return err;
	}

	return 0;
}

#define FBNIC_VERSION_PUT(_section, _type) \
	fbnic_version_ ## _section ## _put(req, &fbd->fw_cap._section._type, \
					   "fw." #_type, \
					   "fw." #_type ".commit")

static int fbnic_devlink_info_get(struct devlink *devlink,
				  struct devlink_info_req *req,
				  struct netlink_ext_ack *extack)
{
	struct fbnic_dev *fbd = devlink_priv(devlink);
	int err;

	if (fbnic_is_asic(fbd)) {
		/* Version names should conform with devlink standard names
		 * found in include/net/devlink.h.
		 */
		err = FBNIC_VERSION_PUT(running, mgmt);
		if (err)
			return err;

		err = FBNIC_VERSION_PUT(running, bootloader);
		if (err)
			return err;

		err = FBNIC_VERSION_PUT(stored, mgmt);
		if (err)
			return err;

		err = FBNIC_VERSION_PUT(stored, bootloader);
		if (err)
			return err;

		err = FBNIC_VERSION_PUT(stored, undi);
		if (err)
			return err;
	}

	if (fbd->dsn) {
		unsigned char serial[FBNIC_SN_STR_LEN];
		u8 dsn[8];

		put_unaligned_be64(fbd->dsn, dsn);
		err = snprintf(serial, FBNIC_SN_STR_LEN, "%8phD", dsn);
		if (err < 0)
			return err;

		err = devlink_info_serial_number_put(req, serial);
		if (err)
			return err;
	}

	return 0;
}

/**
 * fbnic_send_package_data - Send record package data to firmware
 * @context: PLDM FW update structure
 * @data: pointer to the package data
 * @length: length of the package data
 *
 * Send a copy of the package data associated with the PLDM record matching
 * this device to the firmware.
 *
 * Returns: zero on success
 *	    negative error code on failure
 */
static int
fbnic_send_package_data(struct pldmfw *context, const u8 *data, u16 length)
{
	struct device *dev = context->dev;

	/* Temp placeholder */
	dev_info(dev,
		 "Sending %u bytes of PLDM record package data to firmware\n",
		 length);

	return 0;
}

/**
 * fbnic_send_component_table - Send PLDM component table to the firmware
 * @context: PLDM FW update structure
 * @component: The component to send
 * @transfer_flag: Flag indication location in component tables
 *
 * Read relevant data from component table and forward it to the firmware.
 * Check response to verify if the firmware indicates that it wishes to
 * proceed with the update.
 *
 * Returns: zero on success
 *	    negative error code on failure
 */
static int
fbnic_send_component_table(struct pldmfw *context,
			   struct pldmfw_component *component,
			   u8 transfer_flag)
{
	struct device *dev = context->dev;
	u16 id = component->identifier;
	u8 test_string[80];

	switch (id) {
	case QSPI_SECTION_CMRT:
	case QSPI_SECTION_CONTROL_FW:
	case QSPI_SECTION_OPTION_ROM:
		break;
	default:
		dev_err(dev, "Unknown component ID %u\n", id);
		return -EINVAL;
	}

	dev_dbg(dev, "Sending PLDM component table to firmware\n");

	/* Temp placeholder */
	memcpy(test_string, component->version_string,
	       min_t(u8, component->version_len, 79));
	test_string[min_t(u8, component->version_len, 79)] = 0;
	dev_info(dev, "PLDMFW: Component ID: %u version %s\n",
		 id, test_string);

	return 0;
}

/**
 * fbnic_flash_component - Flash a component of the QSPI
 * @context: PLDM FW update structure
 * @component: The component table to send to FW
 *
 * Map contents of component and make it available for FW to download
 * so that it can update the contents of the QSPI Flash.
 *
 * Returns: zero on success
 *	    negative error code on failure
 */
static int
fbnic_flash_component(struct pldmfw *context,
		      struct pldmfw_component *component)
{
	const u8 *data = component->component_data;
	u32 size = component->component_size;
	struct fbnic_fw_completion *fw_cmpl;
	struct device *dev = context->dev;
	struct pci_dev *pdev = to_pci_dev(dev);
	u16 id = component->identifier;
	const char *component_name;
	int err = 0, retries = 2;

	struct devlink *devlink;
	struct fbnic_dev *fbd;

	switch (id) {
	case QSPI_SECTION_CMRT:
		component_name = "boot1";
		break;
	case QSPI_SECTION_CONTROL_FW:
		component_name = "boot2";
		break;
	case QSPI_SECTION_OPTION_ROM:
		component_name = "option-rom";
		break;
	default:
		dev_err(dev, "Unknown component ID %u\n", id);
		return -EINVAL;
	}

	fw_cmpl = kzalloc(sizeof(*fw_cmpl), GFP_KERNEL);
	if (!fw_cmpl)
		return -ENOMEM;

	pdev = to_pci_dev(dev);
	fbd = pci_get_drvdata(pdev);
	devlink = priv_to_devlink(fbd);

	/* Initialize completion and queue it for FW to process */
	fw_cmpl->msg_type = FBNIC_TLV_MSG_ID_FW_WRITE_CHUNK_REQ;
	init_completion(&fw_cmpl->done);

	fw_cmpl->fw_update.last_offset = 0;
	fw_cmpl->fw_update.data = data;
	fw_cmpl->fw_update.size = size;

	err = fbnic_fw_xmit_fw_start_upgrade(fbd, fw_cmpl, id, size);
	if (err)
		goto cmpl_free;

	/* Monitor completions and report status of update */
	while (fw_cmpl->fw_update.data) {
		u32 offset = fw_cmpl->fw_update.last_offset;

		devlink_flash_update_status_notify(devlink, "Flashing",
						   component_name, offset,
						   size);

		/* Allow 5 seconds for reply, resend and try up to 2 times */
		if (wait_for_completion_timeout(&fw_cmpl->done, 5 * HZ)) {
			reinit_completion(&fw_cmpl->done);
			/* If we receive a reply, reinit our retry counter */
			retries = 2;
		} else if (--retries == 0) {
			dev_err(fbd->dev, "Timed out waiting on update\n");
			err = -ETIMEDOUT;
			goto cmpl_cleanup;
		}
	}

	err = fw_cmpl->result;
	if (err)
		goto cmpl_cleanup;

	devlink_flash_update_status_notify(devlink, "Flashing",
					   component_name, size, size);

cmpl_cleanup:
	fbd->cmpl_data = NULL;
cmpl_free:
	kfree(fw_cmpl);

	return err;
}

/**
 * fbnic_finalize_update - Perform last steps to complete device update
 * @context: PLDM FW update structure
 *
 * Notify FW that update is complete and that it can take any actions
 * needed to finalize the FW update.
 *
 * Returns: zero on success
 *	    negative error code on failure
 */
static int
fbnic_finalize_update(struct pldmfw *context)
{
	struct device *dev = context->dev;

	/* Temp placeholder */
	dev_info(dev, "PLDMFW: Finalize update\n");

	return 0;
}

static const struct pldmfw_ops fbnic_pldmfw_ops = {
	.match_record = pldmfw_op_pci_match_record,
	.send_package_data = fbnic_send_package_data,
	.send_component_table = fbnic_send_component_table,
	.flash_component = fbnic_flash_component,
	.finalize_update = fbnic_finalize_update,
};

void
fbnic_devlink_flash_update_report_err(struct fbnic_dev *fbd,
				      struct devlink *devlink,
				      const char *err_msg,
				      int err)
{
	char err_str[128];

	snprintf(err_str, sizeof(err_str),
		 "Failed to flash PLDM Image: %s (error: %d)",
		 err_msg, err);
	devlink_flash_update_status_notify(devlink, err_str, NULL, 0, 0);
	dev_err(fbd->dev, "%s\n", err_str);
}

static int
fbnic_devlink_flash_update(struct devlink *devlink,
			   struct devlink_flash_update_params *params,
			   struct netlink_ext_ack *extack)
{
	struct fbnic_dev *fbd = devlink_priv(devlink);
	const struct firmware *fw = params->fw;
	struct device *dev = fbd->dev;
	struct pldmfw context;
	char *err_msg;
	int err;

	if (!fw || !fw->data || !fw->size)
		return -EINVAL;

	devlink_flash_update_status_notify(devlink, "Preparing to flash",
					   NULL, 0, 0);

	context.ops = &fbnic_pldmfw_ops;
	context.dev = dev;

	err = pldmfw_flash_image(&context, fw);
	if (err) {
		switch (err) {
		case -EINVAL:
			err_msg = "Invalid image";
			break;
		case -EOPNOTSUPP:
			err_msg = "Unsupported image";
			break;
		case -ENOMEM:
			err_msg = "Out of memory";
			break;
		case -EFAULT:
			err_msg = "Invalid header";
			break;
		case -ENOENT:
			err_msg = "No matching record";
			break;
		case -ENODEV:
			err_msg = "No matching device";
			break;
		case -ETIMEDOUT:
			err_msg = "Timed out waiting for reply";
			break;
		default:
			err_msg = "Unknown error";
			break;
		}
		fbnic_devlink_flash_update_report_err(fbd, devlink,
						      err_msg, err);
	} else {
		devlink_flash_update_status_notify(devlink, "Flashing done",
						   NULL, 0, 0);
	}

	return err;
}

static const struct devlink_ops fbnic_devlink_ops = {
	.info_get = fbnic_devlink_info_get,
	.flash_update = fbnic_devlink_flash_update,
};

static int fbnic_fw_reporter_dump(struct devlink_health_reporter *reporter,
				  struct devlink_fmsg *fmsg, void *priv_ctx,
				  struct netlink_ext_ack *extack)
{
	u32 offset, index, index_count, length, size;
	struct fbnic_fw_completion *fw_cmpl;
	int err = 0, retries = 5;
	u8 *dump_data, **data;
	struct fbnic_dev *fbd;
	int incomplete = 0;

	fbd = (struct fbnic_dev *)devlink_health_reporter_priv(reporter);

	fw_cmpl = kzalloc(sizeof(*fw_cmpl), GFP_KERNEL);
	if (!fw_cmpl)
		return -ENOMEM;

	/* Initialize completion and queue it for FW to process */
	fw_cmpl->msg_type = FBNIC_TLV_MSG_ID_COREDUMP_GET_INFO_RESP;
	init_completion(&fw_cmpl->done);

	err = fbnic_fw_xmit_coredump_info_msg(fbd, fw_cmpl, true);
	if (err) {
		dev_err(fbd->dev,
			"Failed to transmit coredump info msg, err %d\n",
			err);
		goto cmpl_free;
	}

	/* Allow 2 seconds for reply, resend and try up to 5 times */
	while (!wait_for_completion_timeout(&fw_cmpl->done, 2 * HZ)) {
		retries--;

		if (retries == 0) {
			dev_err(fbd->dev,
				"Timed out waiting on coredump_info\n");
			err = -ETIMEDOUT;
			goto cmpl_cleanup;
		}

		err = fbnic_fw_xmit_coredump_info_msg(fbd, NULL, true);
		if (err) {
			dev_err(fbd->dev,
				"Failed to transmit coredump info msg, err %d\n",
				err);
			goto cmpl_cleanup;
		}
	}

	/* Handle error returned by firmware */
	if (fw_cmpl->result) {
		err = fw_cmpl->result;
		dev_err(fbd->dev, "%s: Firmware returned error %d\n",
			__func__, err);
		goto cmpl_cleanup;
	}

	/* Verify Size */
	size = fw_cmpl->coredump_info.size;
	if (!size) {
		err = -EIO;
		dev_err(fbd->dev, "Firmware returned size 0\n");
	}

	fbd->cmpl_data = NULL;
	kfree(fw_cmpl);

	index_count = DIV_ROUND_UP(size, TLV_MAX_DATA);

	fw_cmpl = kzalloc(sizeof(*fw_cmpl) +
			  sizeof(void *) * index_count +
			  size,
			  GFP_KERNEL);
	if (!fw_cmpl)
		return -ENOMEM;

	/* Populate pointer table w/ pointer offsets */
	dump_data = (void *)&fw_cmpl->coredump.data[index_count];
	data = fw_cmpl->coredump.data;

	/* Initialize completion and queue it for FW to process */
	fw_cmpl->msg_type = FBNIC_TLV_MSG_ID_COREDUMP_READ_RESP;
	init_completion(&fw_cmpl->done);
	fw_cmpl->coredump.size = size;
	fw_cmpl->coredump.stride = TLV_MAX_DATA;

	/* Make two passes through the data verifying all of the
	 * slots have been filled. The first pass is meant to get
	 * the indices filled, and the second pass will be to fill
	 * in any gaps that may have been added due to a missed
	 * message and verify all slots are filled.
	 *
	 * With the first pass we will fill the slots and notify the
	 * firmware of each slot allowing it time to complete the slot
	 * before proceeding to the next one. We will have from 2 to 5
	 * slots active at the same time depending on the FW response
	 * time.
	 */

	/* start at index of last offset in the array */
	index = (size - 1) / TLV_MAX_DATA;

	/* Send one message to kick off requesting of buffers */
	offset = index * TLV_MAX_DATA;
	length = size - offset;
	data[index] = dump_data + offset;
	err = fbnic_fw_xmit_coredump_read_msg(fbd, fw_cmpl, offset, length);
	if (err) {
		dev_err(fbd->dev,
			"Failed to transmit coredump msg, err %d\n",
			err);
		goto cmpl_free;
	}

	/* reset length as all remaining sections should be TLV sized */
	length = TLV_MAX_DATA;

	while (index--) {
		/* Send a second request so that we have one outstanding while
		 * one is being processed.
		 */
		offset = index * TLV_MAX_DATA;
		data[index] = dump_data + offset;
		err = fbnic_fw_xmit_coredump_read_msg(fbd, NULL,
						      offset, length);
		if (err) {
			dev_err(fbd->dev,
				"Failed to transmit coredump msg, err %d\n",
				err);
			goto cmpl_cleanup;
		}

		/* Allow 2 seconds for reply, resend and try up to 5 times */
		if (wait_for_completion_timeout(&fw_cmpl->done, 2 * HZ)) {
			reinit_completion(&fw_cmpl->done);
		} else if (--retries == 0) {
			dev_err(fbd->dev,
				"Timed out waiting on coredump\n");
			err = -ETIMEDOUT;
			goto cmpl_cleanup;
		}

		/* If we didn't see the reply record as incomplete */
		if (fw_cmpl->coredump.data[index + 1])
			incomplete++;
	}

	/* Add one additional wait to catch any remaining completions */
	if (wait_for_completion_timeout(&fw_cmpl->done, 2 * HZ))
		reinit_completion(&fw_cmpl->done);

	/* Skip retry if it looks like we filled all slots */
	if (!incomplete && !fw_cmpl->coredump.data[0])
		goto coredump_complete;

	/* For the second pass we need to go through and identify any
	 * slots which didn't receive the expected completion. To address
	 * these we will need to go through and search for populated slots
	 * that have yet to be filled and resend a message for them.
	 */

	/* Round up to get the size of the array instead of the last index*/
	index = DIV_ROUND_UP(size, TLV_MAX_DATA);
	incomplete = 0;

	for (;;) {
		/* Reset counts and restart at end of data array. We
		 * will reset the number of incomplete slots when wrapping
		 * as we can only exit when we reach the start of the array
		 * and have encountered no incomplete slots.
		 */
		if (!index--) {
			if (!incomplete)
				break;

			index = (size - 1) / TLV_MAX_DATA;
			incomplete = 0;
		}

		/* If slot is already cleared move to the next slot */
		if (!fw_cmpl->coredump.data[index])
			continue;

		/* We are about to issue a retry. So we will test and
		 * decrement the value here. The general idea is that we will
		 * retry this one, but if we are asked to exhaust our retries
		 * we will stop before we send any more requests.
		 */
		if (retries-- == 0) {
			dev_err(fbd->dev,
				"Timed out waiting on coredump\n");
			err = -ETIMEDOUT;
			goto cmpl_cleanup;
		}

		/* Follow up on our original request with a retry */
		offset = index * TLV_MAX_DATA;
		length = min_t(u32, size - offset, TLV_MAX_DATA);
		err = fbnic_fw_xmit_coredump_read_msg(fbd, NULL,
						      offset, length);
		if (err) {
			dev_err(fbd->dev,
				"Failed to transmit coredump msg, err %d\n",
				err);
			goto cmpl_cleanup;
		}

		/* Allow 2 seconds for reply */
		if (wait_for_completion_timeout(&fw_cmpl->done, 2 * HZ))
			reinit_completion(&fw_cmpl->done);

		/* If we still don't see the reply record as incomplete */
		if (fw_cmpl->coredump.data[index])
			incomplete++;
	}

coredump_complete:
	/* Create wrapper for binary data */
	err = devlink_fmsg_binary_pair_nest_start(fmsg, "FW coredump");
	if (err)
		goto cmpl_cleanup;

	/* Copy dump data in page size chunks */
	for (offset = 0; offset < size; offset += length) {
		length = min_t(u32, size - offset, TLV_MAX_DATA);

		err = devlink_fmsg_binary_put(fmsg, dump_data + offset, length);
		if (err)
			break;
	}

	/* Close binary data */
	err = devlink_fmsg_binary_pair_nest_end(fmsg);

cmpl_cleanup:
	fbd->cmpl_data = NULL;
cmpl_free:
	kfree(fw_cmpl);

	return err;
}

static const struct devlink_health_reporter_ops fbnic_fw_fault_reporter_ops = {
	.name = "fw",
	.dump = fbnic_fw_reporter_dump,
};

static void
fbnic_health_reporter_destroy(struct devlink_health_reporter **reporter)
{
	if (*reporter) {
		devlink_health_reporter_destroy(*reporter);
		*reporter = NULL;
	}
}

static void fbnic_health_reporters_destroy(struct fbnic_dev *fbd)
{
	fbnic_health_reporter_destroy(&fbd->fw_fault_reporter);
}

static int
fbnic_health_reporter_create(struct fbnic_dev *fbd,
			     struct devlink_health_reporter **reporter,
			     const struct devlink_health_reporter_ops *ops)
{
	struct devlink_health_reporter *fault_reporter;
	struct devlink *devlink = priv_to_devlink(fbd);

	fault_reporter = devlink_health_reporter_create(devlink, ops, 0, fbd);
	if (IS_ERR(fault_reporter))
		return PTR_ERR(fault_reporter);

	*reporter = fault_reporter;

	return 0;
}

static int fbnic_health_reporters_create(struct fbnic_dev *fbd)
{
	int err;

	err = fbnic_health_reporter_create(fbd, &fbd->fw_fault_reporter,
					   &fbnic_fw_fault_reporter_ops);
	if (err) {
		dev_warn(fbd->dev,
			 "Failed to create FW fault reporter, err: %d\n",
			 err);
		return err;
	}

	return 0;
}

void fbnic_devlink_free(struct fbnic_dev *fbd)
{
	struct devlink *devlink = priv_to_devlink(fbd);

	fbnic_dbg_fbd_exit(fbd);

	fbnic_health_reporters_destroy(fbd);

	fbnic_fw_log_free_buf(fbd);

	devlink_free(devlink);
}

struct fbnic_dev *fbnic_devlink_alloc(struct pci_dev *pdev)
{
	void __iomem * const *iomap_table;
	struct devlink *devlink;
	struct fbnic_dev *fbd;

	devlink = devlink_alloc(&fbnic_devlink_ops, sizeof(struct fbnic_dev),
				&pdev->dev);
	if (!devlink)
		return NULL;

	fbd = devlink_priv(devlink);
	pci_set_drvdata(pdev, fbd);
	fbd->dev = &pdev->dev;

	iomap_table = pcim_iomap_table(pdev);
	fbd->uc_addr0 = iomap_table[0];
	fbd->uc_addr4 = iomap_table[4];

	fbd->dsn = pci_get_dsn(pdev);
	fbd->mps = pcie_get_mps(pdev);
	fbd->readrq = pcie_get_readrq(pdev);

	/* TBD: Add logic for configuring this via a devlink operation */
	fbd->mac_addr_boundary = FBNIC_RPC_TCAM_MACDA_DEFAULT_BOUNDARY;

	/* Attempt to add health reporters.
	 * We will ignore the errors for now as this doesn't prevent the NIC
	 * itself from functioning, however there will be warnings reported
	 * in the log.
	 */
	fbnic_health_reporters_create(fbd);

	if (fbnic_fw_log_alloc_buf(fbd)) {
		dev_err(fbd->dev, "Unable to enable firmware logging!\n");
		return NULL;
	}

	fbnic_dbg_fbd_init(fbd);

	return fbd;
}

void fbnic_devlink_register(struct fbnic_dev *fbd)
{
	struct devlink *devlink = priv_to_devlink(fbd);

	devlink_register(devlink);
}

void fbnic_devlink_unregister(struct fbnic_dev *fbd)
{
	struct devlink *devlink = priv_to_devlink(fbd);

	devlink_unregister(devlink);
}

void fbnic_devlink_fw_fault_report(struct fbnic_dev *fbd, const char *format,
				   ...)
{
	char msg[FBNIC_FW_LOG_MAX_SIZE];
	va_list args;

	va_start(args, format);
	vsnprintf(msg, FBNIC_FW_LOG_MAX_SIZE, format, args);
	va_end(args);

	devlink_health_report(fbd->fw_fault_reporter, msg, fbd);
	if (fbnic_fw_log_enabled(fbd))
		fbnic_fw_log_write(fbd, 0, fbd->firmware_time, msg);
}
