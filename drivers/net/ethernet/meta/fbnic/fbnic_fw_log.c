// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include "fbnic.h"
#include "fbnic_fw_log.h"

int fbnic_fw_log_alloc_buf(struct fbnic_dev *fbd)
{
	struct fbnic_fw_log *log = &fbd->fw_log;
	void *data;

	if (log->data_start)
		return -EINVAL;

	data = vmalloc(FBNIC_FW_LOG_SIZE);

	if (!data)
		return -ENOMEM;

	log->data_end = data + FBNIC_FW_LOG_SIZE;
	log->size = FBNIC_FW_LOG_SIZE;
	INIT_LIST_HEAD(&log->entries);
	log->data_start = data;

	return 0;
}

void fbnic_fw_log_free_buf(struct fbnic_dev *fbd)
{
	struct fbnic_fw_log *log = &fbd->fw_log;
	void *data = log->data_start;

	if (!data)
		return;

	log->data_start = NULL;
	INIT_LIST_HEAD(&log->entries);
	log->size = 0;
	vfree(data);
	log->data_end = NULL;
}

int fbnic_fw_log_write(struct fbnic_dev *fbd, u64 index, u32 timestamp,
		       char *msg)
{
	struct fbnic_fw_log_entry *entry, *head, *tail, *next;
	struct fbnic_fw_log *log = &fbd->fw_log;
	size_t msg_len = strlen(msg) + 1;
	void *entry_end;

	if (!log->data_start) {
		dev_err(fbd->dev, "Firmware sent log entry without being requested!\n");
		return -ENOSPC;
	}

	dev_dbg(fbd->dev, "[%lld] %s\n", index, msg);

	if (list_empty(&log->entries)) {
		entry = log->data_start;
	} else {
		head = list_first_entry(&log->entries, typeof(*head), list);
		entry = (struct fbnic_fw_log_entry *)
			((void *)(head + 1) + (sizeof(char) * head->len));
	}

	entry_end = (void *)(entry + 1) + (sizeof(char) * msg_len);

	/* We've reached the end of the buffer, wrap around */
	if (entry_end > log->data_end) {
		entry = log->data_start;
		entry_end = (void *)(entry + 1) + (sizeof(char) * msg_len);
	}

	/* Make room for entry by removing from tail. */
	list_for_each_entry_safe_reverse(tail, next,  &log->entries, list) {
		if (entry <= tail && entry_end > (void *)(tail))
			list_del(&tail->list);
		else
			break;
	}

	entry->index = index;
	entry->timestamp = timestamp;
	entry->msg = (char *)(entry + 1);
	strcpy(entry->msg, msg);
	entry->len = msg_len;
	list_add(&entry->list, &log->entries);

	return 0;
}
