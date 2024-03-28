/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#ifndef _FBNIC_FW_LOG_H_
#define _FBNIC_FW_LOG_H_

#include <linux/types.h>

#include "fbnic.h"

/* A 512K log buffer was chosen fairly arbitrarily */
#define FBNIC_FW_LOG_SIZE         (512 * 1024)

struct fbnic_fw_log_entry {
	struct list_head          list;
	u64			  index;
	u32			  timestamp;
	char			  *msg;
	size_t                    len;
};

struct fbnic_fw_log {
	void                      *data_start;
	void                      *data_end;
	size_t                    size;
	struct list_head          entries;
};

#define fbnic_fw_log_enabled(_fbd) (!!(_fbd)->fw_log.data_start)

int fbnic_fw_log_alloc_buf(struct fbnic_dev *fbd);
void fbnic_fw_log_free_buf(struct fbnic_dev *fbd);
int fbnic_fw_log_write(struct fbnic_dev *fbd, u64 index, u32 timestamp,
		       char *msg);
#endif /* _FBNIC_FW_LOG_H_ */
