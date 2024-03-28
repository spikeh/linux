/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#ifndef _FBNIC_FW_H_
#define _FBNIC_FW_H_

#include <asm/param.h>
#include <linux/completion.h>
#include <linux/types.h>
#include <linux/if_ether.h>

struct fbnic_dev;
struct fbnic_tlv_msg;

struct fbnic_fw_mbx {
	u8 ready, head, tail;
	u64 alloc_failed, mapping_error, parser_error;
	struct {
		struct fbnic_tlv_msg	*msg;
		dma_addr_t		addr;
	} buf_info[FBNIC_IPC_MBX_DESC_LEN];
};

// FW_VER_MAX_SIZE must match ETHTOOL_FWVERS_LEN
#define FBNIC_FW_VER_MAX_SIZE	                32
// Formatted version is in the format XX.YY.ZZ_RRR_COMMIT
#define FBNIC_FW_CAP_RESP_COMMIT_MAX_SIZE	(FBNIC_FW_VER_MAX_SIZE - 13)
#define FBNIC_FW_LOG_MAX_SIZE	                256

struct fbnic_fw_ver {
	u32 version;
	char commit[FBNIC_FW_CAP_RESP_COMMIT_MAX_SIZE];
};

struct fbnic_fw_cap {
	struct {
		struct fbnic_fw_ver mgmt, bootloader;
	} running;
	struct {
		struct fbnic_fw_ver mgmt, bootloader, undi;
	} stored;
	u8	active_slot;
	u8	bmc_mac_addr[4][ETH_ALEN];
	u8	bmc_present	: 1;
	u8	all_multi	: 1;
	u8	link_speed;
	u8	link_fec;
};

struct fbnic_fw_completion {
	u32 msg_type;
	struct completion done;
	int result;
	union {
		struct {
			u32 size;
		} coredump_info;
		struct {
			u32 size;
			u16 stride;
			u8 *data[];
		} coredump;
		struct {
			u32 size;
			u32 last_offset;
			const u8 *data;
		} fw_update;
		struct {
			u32 size;
			u32 offset;
			u8 *data;
		} eeprom;
		struct {
			u16 size;
			u8 offset;
			u8 page;
			u8 bank;
			u8 *data;
		} qsfp;
		struct {
			s32 millivolts;
			s32 millidegrees;
		} tsene;
	};
};

u64 __fbnic_mbx_rd_desc(struct fbnic_dev *fbd, int mbx_idx, int desc_idx);
void fbnic_mbx_init(struct fbnic_dev *fbd);
void fbnic_mbx_clean(struct fbnic_dev *fbd);
void fbnic_mbx_poll(struct fbnic_dev *fbd);
int fbnic_mbx_poll_tx_ready(struct fbnic_dev *fbd);
void fbnic_mbx_flush_tx(struct fbnic_dev *fbd);
int fbnic_fw_mbx_self_test(struct fbnic_dev *fbd, bool poll);
int fbnic_fw_xmit_test_msg(struct fbnic_dev *fbd);
int fbnic_fw_xmit_ownership_msg(struct fbnic_dev *fbd, bool take_ownership);
int fbnic_fw_init_heartbeat(struct fbnic_dev *fbd, bool poll);
void fbnic_fw_check_heartbeat(struct fbnic_dev *fbd);
int fbnic_fw_xmit_eeprom_lock_msg(struct fbnic_dev *fbd, bool lock_eeprom);
int fbnic_fw_xmit_coredump_info_msg(struct fbnic_dev *fbd,
				    struct fbnic_fw_completion *cmpl_data,
				    bool force);
int fbnic_fw_xmit_coredump_read_msg(struct fbnic_dev *fbd,
				    struct fbnic_fw_completion *cmpl_data,
				    u32 offset, u32 length);
int fbnic_fw_xmit_fw_start_upgrade(struct fbnic_dev *fbd,
				   struct fbnic_fw_completion *cmpl_data,
				   unsigned int id, unsigned int len);
int fbnic_fw_xmit_fw_write_chunk(struct fbnic_dev *fbd, void *data,
				 u32 offset, u32 len);
int fbnic_fw_xmit_fw_verify_image(struct fbnic_dev *fbd);
int fbnic_fw_xmit_eeprom_read_msg(struct fbnic_dev *fbd,
				  struct fbnic_fw_completion *cmpl_data,
				  u32 offset, u32 length);
int fbnic_fw_xmit_eeprom_write_msg(struct fbnic_dev *fbd,
				   struct fbnic_fw_completion *cmpl_data,
				   u32 offset, u32 length, const u8 *data);
int fbnic_fw_xmit_qsfp_read_msg(struct fbnic_dev *fbd,
				struct fbnic_fw_completion *cmpl_data,
				u32 page, u32 bank, u32 offset, u32 length);
int fbnic_fw_xmit_tsene_read_msg(struct fbnic_dev *fbd,
				 struct fbnic_fw_completion *cmpl_data);
int fbnic_fw_xmit_comphy_set_msg(struct fbnic_dev *fbd, u32 speed);
int fbnic_fw_xmit_send_logs(struct fbnic_dev *fbd, bool enabled);
int fbnic_fw_xmit_rpc_macda_sync(struct fbnic_dev *fbd);

#define fbnic_mk_full_fw_ver_str(_rev_id, _delim, _commit, _str)      \
	snprintf(_str, sizeof(_str), "%02lu.%02lu.%02lu-%03lu%s%s",   \
		 FIELD_GET(FBNIC_FW_CAP_RESP_VERSION_MAJOR, _rev_id), \
		 FIELD_GET(FBNIC_FW_CAP_RESP_VERSION_MINOR, _rev_id), \
		 FIELD_GET(FBNIC_FW_CAP_RESP_VERSION_PATCH, _rev_id), \
		 FIELD_GET(FBNIC_FW_CAP_RESP_VERSION_BUILD, _rev_id), \
		 _delim, _commit)

#define fbnic_mk_fw_ver_str(_rev_id, _str) \
	fbnic_mk_full_fw_ver_str(_rev_id, "", "", _str)

#define fbnic_mk_fw_ver_commit_str(_fbd, _str) \
do { \
	if (strlen((_fbd)->fw_cap.running.mgmt.commit) > 0) \
		fbnic_mk_full_fw_ver_str((_fbd)->fw_cap.running.mgmt.version, \
					 "_", \
					 (_fbd)->fw_cap.running.mgmt.commit, \
					 _str); \
	else \
		fbnic_mk_fw_ver_str((_fbd)->fw_cap.running.mgmt.version, \
				    _str); \
} while (0)

enum {
	QSPI_SECTION_CMRT			= 0,
	QSPI_SECTION_CONTROL_FW			= 1,
	QSPI_SECTION_UCODE			= 2,
	QSPI_SECTION_OPTION_ROM			= 3,
	QSPI_SECTION_USER			= 4,
	QSPI_SECTION_INVALID,
};

#define FW_HEARTBEAT_PERIOD (10 * HZ)

enum {
	FBNIC_TLV_MSG_ID_HOST_CAP_REQ			= 0x10,
	FBNIC_TLV_MSG_ID_FW_CAP_RESP			= 0x11,
	FBNIC_TLV_MSG_ID_OWNERSHIP_REQ			= 0x12,
	FBNIC_TLV_MSG_ID_OWNERSHIP_RESP			= 0x13,
	FBNIC_TLV_MSG_ID_HEARTBEAT_REQ			= 0x14,
	FBNIC_TLV_MSG_ID_HEARTBEAT_RESP			= 0x15,
	FBNIC_TLV_MSG_ID_EEPROM_LOCK_REQ		= 0x16,
	FBNIC_TLV_MSG_ID_EEPROM_LOCK_RESP		= 0x17,
	FBNIC_TLV_MSG_ID_COREDUMP_GET_INFO_REQ		= 0x18,
	FBNIC_TLV_MSG_ID_COREDUMP_GET_INFO_RESP		= 0x19,
	FBNIC_TLV_MSG_ID_COREDUMP_READ_REQ		= 0x20,
	FBNIC_TLV_MSG_ID_COREDUMP_READ_RESP		= 0x21,
	FBNIC_TLV_MSG_ID_FW_START_UPGRADE_REQ		= 0x22,
	FBNIC_TLV_MSG_ID_FW_START_UPGRADE_RESP		= 0x23,
	FBNIC_TLV_MSG_ID_FW_WRITE_CHUNK_REQ		= 0x24,
	FBNIC_TLV_MSG_ID_FW_WRITE_CHUNK_RESP		= 0x25,
	FBNIC_TLV_MSG_ID_FW_VERIFY_IMAGE_REQ		= 0x26,
	FBNIC_TLV_MSG_ID_FW_VERIFY_IMAGE_RESP		= 0x27,
	FBNIC_TLV_MSG_ID_FW_FINISH_UPGRADE_REQ		= 0x28,
	FBNIC_TLV_MSG_ID_FW_FINISH_UPGRADE_RESP		= 0x29,
	FBNIC_TLV_MSG_ID_EEPROM_READ_REQ		= 0x2A,
	FBNIC_TLV_MSG_ID_EEPROM_READ_RESP		= 0x2B,
	FBNIC_TLV_MSG_ID_EEPROM_WRITE_REQ		= 0x2C,
	FBNIC_TLV_MSG_ID_EEPROM_WRITE_RESP		= 0x2D,
	FBNIC_TLV_MSG_ID_FW_CANCEL_UPGRADE_REQ		= 0x2E,
	FBNIC_TLV_MSG_ID_FW_CANCEL_UPGRADE_RESP		= 0x2F,
	FBNIC_TLV_MSG_ID_FW_ACTIVATE_UPGRADE_REQ	= 0x30,
	FBNIC_TLV_MSG_ID_FW_ACTIVATE_UPGRADE_RESP	= 0x31,
	/* 0x32 - 0x35 GPIO */
	/* 0x36 - 0x37 PCIe handoff testing */
	FBNIC_TLV_MSG_ID_QSFP_READ_REQ			= 0x38,
	FBNIC_TLV_MSG_ID_QSFP_READ_RESP			= 0x39,
	FBNIC_TLV_MSG_ID_QSFP_WRITE_REQ			= 0x3A,
	FBNIC_TLV_MSG_ID_QSPF_WRITE_RESP		= 0x3B,
	FBNIC_TLV_MSG_ID_TSENE_READ_REQ			= 0x3C,
	FBNIC_TLV_MSG_ID_TSENE_READ_RESP		= 0x3D,
	FBNIC_TLV_MSG_ID_COMPHY_SET_REQ			= 0x3E,
	FBNIC_TLV_MSG_ID_COMPHY_SET_RESP		= 0x3F,
	FBNIC_TLV_MSG_ID_SENSOR_THRESHOLD_EXCEEDED_RESP = 0x40,
	/* 0x41 and 0x42 are no longer used */
	FBNIC_TLV_MSG_ID_LOG_SEND_LOGS_REQ		= 0x43,
	FBNIC_TLV_MSG_ID_LOG_MSG_REQ			= 0x44,
	FBNIC_TLV_MSG_ID_LOG_MSG_RESP			= 0x45,
	FBNIC_TLV_MSG_ID_RPC_MAC_SYNC_REQ		= 0x46,
	/* 0x47 reserved for UNICAST_SYNC_RESP */
};

#define FBNIC_FW_CAP_RESP_VERSION_MAJOR		CSR_GENMASK(31, 24)
#define FBNIC_FW_CAP_RESP_VERSION_MINOR		CSR_GENMASK(23, 16)
#define FBNIC_FW_CAP_RESP_VERSION_PATCH		CSR_GENMASK(15, 8)
#define FBNIC_FW_CAP_RESP_VERSION_BUILD		CSR_GENMASK(7, 0)
enum {
	FBNIC_FW_CAP_RESP_VERSION		    = 0x0,
	FBNIC_FW_CAP_RESP_BMC_PRESENT		    = 0x1,
	FBNIC_FW_CAP_RESP_BMC_MAC_ADDR		    = 0x2,
	FBNIC_FW_CAP_RESP_BMC_MAC_ARRAY		    = 0x3,
	FBNIC_FW_CAP_RESP_STORED_VERSION	    = 0x4,
	FBNIC_FW_CAP_RESP_ACTIVE_FW_SLOT	    = 0x5,
	FBNIC_FW_CAP_RESP_VERSION_COMMIT_STR	    = 0x6,
	FBNIC_FW_CAP_RESP_BMC_ALL_MULTI		    = 0x8,
	FBNIC_FW_CAP_RESP_FW_STATE		    = 0x9,
	FBNIC_FW_CAP_RESP_FW_LINK_SPEED		    = 0xa,
	FBNIC_FW_CAP_RESP_FW_LINK_FEC		    = 0xb,
	FBNIC_FW_CAP_RESP_STORED_COMMIT_STR	    = 0xc,
	FBNIC_FW_CAP_RESP_CMRT_VERSION		    = 0xd,
	FBNIC_FW_CAP_RESP_STORED_CMRT_VERSION	    = 0xe,
	FBNIC_FW_CAP_RESP_CMRT_COMMIT_STR	    = 0xf,
	FBNIC_FW_CAP_RESP_STORED_CMRT_COMMIT_STR    = 0x10,
	FBNIC_FW_CAP_RESP_UEFI_VERSION		    = 0x11,
	FBNIC_FW_CAP_RESP_UEFI_COMMIT_STR	    = 0x12,
	FBNIC_FW_CAP_RESP_MSG_MAX
};

enum {
	FBNIC_FW_STATE_UNKNOWN			 = 0x0,
	FBNIC_FW_STATE_BLANK			 = 0x1,
	FBNIC_FW_STATE_TESTED			 = 0x2,
	FBNIC_FW_STATE_PROVISIONED		 = 0x3,
	FBNIC_FW_STATE_MISSION			 = 0x4,
	FBNIC_FW_STATE_FRA			 = 0x5,
	FBNIC_FW_STATE_DECOM			 = 0x6,
	FBNIC_FW_STATE_MAX
};

enum {
	FBNIC_FW_LINK_SPEED_25R1		= 1,
	FBNIC_FW_LINK_SPEED_50R2		= 2,
	FBNIC_FW_LINK_SPEED_50R1		= 3,
	FBNIC_FW_LINK_SPEED_100R2		= 4,
};

enum {
	FBNIC_FW_LINK_FEC_NONE			= 1,
	FBNIC_FW_LINK_FEC_RS			= 2,
	FBNIC_FW_LINK_FEC_BASER			= 3,
};

enum {
	FBNIC_FW_OWNERSHIP_FLAG			= 0x0,
	FBNIC_FW_OWNERSHIP_TIME			= 0x1,
	FBNIC_FW_OWNERSHIP_MSG_MAX
};

enum {
	FBNIC_FW_HEARTBEAT_UPTIME               = 0x0,
	FBNIC_FW_HEARTBEAT_NUMBER_OF_MESSAGES   = 0x1,
	FBNIC_FW_HEARTBEAT_MSG_MAX
};

enum {
	FBNIC_EEPROM_LOCK			= 0x0,
	FBNIC_EEPROM_LOCK_MSG_MAX
};

enum {
	FBNIC_EEPROM_STATE_UNKNOWN		= 0x0,
	FBNIC_EEPROM_STATE_LOCKED		= 0x1,
	FBNIC_EEPROM_STATE_UNLOCKED		= 0x2
};

enum {
	FBNIC_FW_COREDUMP_REQ_INFO_CREATE	= 0x0,
	FBNIC_FW_COREDUMP_REQ_INFO_MSG_MAX
};

enum {
	FBNIC_FW_COREDUMP_INFO_AVAILABLE	= 0x0,
	FBNIC_FW_COREDUMP_INFO_SIZE		= 0x1,
	FBNIC_FW_COREDUMP_INFO_ERROR		= 0x2,
	FBNIC_FW_COREDUMP_INFO_MSG_MAX
};

enum {
	FBNIC_FW_COREDUMP_READ_OFFSET		= 0x0,
	FBNIC_FW_COREDUMP_READ_LENGTH		= 0x1,
	FBNIC_FW_COREDUMP_READ_DATA		= 0x2,
	FBNIC_FW_COREDUMP_READ_ERROR		= 0x3,
	FBNIC_FW_COREDUMP_READ_MSG_MAX
};

enum {
	FBNIC_FW_START_UPGRADE_ERROR		= 0x0,
	FBNIC_FW_START_UPGRADE_SECTION		= 0x1,
	FBNIC_FW_START_UPGRADE_IMAGE_LENGTH	= 0x2,
	FBNIC_FW_START_UPGRADE_MSG_MAX
};

enum {
	FBNIC_FW_WRITE_CHUNK_OFFSET		= 0x0,
	FBNIC_FW_WRITE_CHUNK_LENGTH		= 0x1,
	FBNIC_FW_WRITE_CHUNK_DATA		= 0x2,
	FBNIC_FW_WRITE_CHUNK_ERROR		= 0x3,
	FBNIC_FW_WRITE_CHUNK_MSG_MAX
};

enum {
	FBNIC_FW_VERIFY_IMAGE_ERROR		= 0x0,
	FBNIC_FW_VERIFY_IMAGE_MSG_MAX
};

/* Time needed to finalize flash and prepare it to boot */
#define FBNIC_FLASH_SELECT_TIMEOUT	60

enum {
	FBNIC_FW_FINISH_UPGRADE_ERROR		= 0x0,
	FBNIC_FW_FINISH_UPGRADE_MSG_MAX
};

enum {
	FBNIC_FW_CANCEL_UPGRADE_ERROR		= 0x0,
	FBNIC_FW_CANCEL_UPGRADE_MSG_MAX
};

enum {
	FBNIC_EEPROM_READ_OFFSET		= 0x0,
	FBNIC_EEPROM_READ_LENGTH		= 0x1,
	FBNIC_EEPROM_READ_CRC			= 0x2,
	FBNIC_EEPROM_READ_ERROR			= 0x3,
	FBNIC_EEPROM_READ_DATA			= 0x4,
	FBNIC_EEPROM_READ_MSG_MAX
};

enum {
	FBNIC_EEPROM_WRITE_OFFSET		= 0x0,
	FBNIC_EEPROM_WRITE_LENGTH		= 0x1,
	FBNIC_EEPROM_WRITE_CRC			= 0x2,
	FBNIC_EEPROM_WRITE_ERROR		= 0x3,
	FBNIC_EEPROM_WRITE_DATA			= 0x4,
	FBNIC_EEPROM_WRITE_MSG_MAX
};

enum {
	FBNIC_QSFP_BANK				= 0x0,
	FBNIC_QSFP_PAGE				= 0x1,
	FBNIC_QSFP_OFFSET			= 0x2,
	FBNIC_QSFP_LENGTH			= 0x3,
	FBNIC_QSFP_ERROR			= 0x4,
	FBNIC_QSFP_DATA				= 0x5,
	FBNIC_QSFP_MSG_MAX
};

enum {
	FBNIC_TSENE_THERM			= 0x0,
	FBNIC_TSENE_VOLT			= 0x1,
	FBNIC_TSENE_ERROR			= 0x2,
	FBNIC_TSENE_MSG_MAX
};

enum {
	FBNIC_COMPHY_SET_PAM4			= 0x0,
	FBNIC_COMPHY_SET_ERROR			= 0x1,
	FBNIC_COMPHY_SET_MSG_MAX
};

enum {
	FBNIC_TSENE_THERM_EXCEEDED_FLAG		= 0x0,
	FBNIC_TSENE_VOLT_EXCEEDED_FLAG		= 0x1,
	FBNIC_TSENE_THERMAL			= 0x2,
	FBNIC_TSENE_VOLTAGE			= 0x3,
	FBNIC_TSENE_EXCEEDED_MSG_MAX,
};

enum {
	FBNIC_SEND_LOGS				= 0x0,
	FBNIC_SEND_LOGS_VERSION			= 0x1,
	FBNIC_SEND_LOGS_MSG_MAX
};

enum {
	FBNIC_FW_LOG_MSEC			= 0x0,
	FBNIC_FW_LOG_INDEX			= 0x1,
	FBNIC_FW_LOG_MSG			= 0x2,
	FBNIC_FW_LOG_MSG_MAX
};

enum {
	FBNIC_FW_RPC_MAC_SYNC_RX_FLAGS		= 0x0,
	FBNIC_FW_RPC_MAC_SYNC_UC_ARRAY		= 0x1,
	FBNIC_FW_RPC_MAC_SYNC_MC_ARRAY		= 0x2,
	FBNIC_FW_RPC_MAC_SYNC_MAC_ADDR		= 0x3,
	FBNIC_FW_RPC_MAC_SYNC_MSG_MAX
};

#define FW_RPC_MAC_SYNC_RX_FLAGS_PROMISC	1
#define FW_RPC_MAC_SYNC_RX_FLAGS_ALLMULTI	2
#define FW_RPC_MAC_SYNC_RX_FLAGS_BROADCAST	4

#define FW_RPC_MAC_SYNC_UC_ARRAY_SIZE		8
#define FW_RPC_MAC_SYNC_MC_ARRAY_SIZE		8

#endif /* _FBNIC_FW_H_ */
