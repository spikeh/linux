/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#ifndef _FBNIC_H_
#define _FBNIC_H_

#include <generated/utsrelease.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <net/xdp.h>

#include "fbnic_csr.h"
#include "fbnic_fw.h"
#include "fbnic_fw_log.h"
#include "fbnic_mac.h"
#include "fbnic_rpc.h"
#include "fbnic_txrx.h"
#include "fbnic_hw_stats.h"

struct fbnic_dev {
	struct device *dev;
	struct net_device *netdev;
	struct dentry *dbg_fbd;
	struct device *hwmon;
	struct devlink_health_reporter *fw_fault_reporter;

	u32 __iomem *uc_addr0;
	u32 __iomem *uc_addr4;
	const struct fbnic_mac *mac;
	struct msix_entry *msix_entries;
	unsigned int fw_msix_vector;
	unsigned int mac_msix_vector;
	unsigned short num_irqs;

	struct delayed_work service_task;

	struct fbnic_fw_mbx mbx[FBNIC_IPC_MBX_INDICES];
	struct fbnic_fw_cap fw_cap;
	struct fbnic_fw_completion *cmpl_data;
	/* Lock protecting Tx Mailbox queue to9 prevent possible races */
	spinlock_t fw_tx_lock;

	unsigned long last_heartbeat_request;
	unsigned long last_heartbeat_response;
	u8 fw_heartbeat_enabled;
	u8 eeprom_desired_state, eeprom_state;

	u64 dsn;
	u32 mps;
	u32 readrq;

	/* Local copy of the devices TCAM */
	struct fbnic_act_tcam act_tcam[FBNIC_RPC_TCAM_ACT_NUM_ENTRIES];
	struct fbnic_mac_addr mac_addr[FBNIC_RPC_TCAM_MACDA_NUM_ENTRIES];
	u8 mac_addr_boundary;
	u8 tce_tcam_last;

	/* IP TCAM */
	struct fbnic_ip_addr ip_src[FBNIC_RPC_TCAM_IP_ADDR_NUM_ENTRIES];
	struct fbnic_ip_addr ip_dst[FBNIC_RPC_TCAM_IP_ADDR_NUM_ENTRIES];
	struct fbnic_ip_addr ipo_src[FBNIC_RPC_TCAM_IP_ADDR_NUM_ENTRIES];
	struct fbnic_ip_addr ipo_dst[FBNIC_RPC_TCAM_IP_ADDR_NUM_ENTRIES];

	/* Tri-state value indicating state of link.
	 *  0 - Up
	 *  1 - Down
	 *  2 - Event - Requires checking as link state may have changed
	 */
	s8 link_state;

	/* Number of TCQs/RCQs available on hardware */
	u16 max_num_queues;

	/* Lock protecting writes to @time_high, @time_offset of fbnic_netdev,
	 * and the HW time CSR machinery.
	 */
	spinlock_t time_lock;
	/* Externally accessible PTP clock, may be NULL */
	struct ptp_clock *ptp;
	struct ptp_clock_info ptp_info;
	/* Last @time_high refresh time in jiffies (to catch stalls) */
	unsigned long last_read;

	/* Local copy of hardware statistics */
	struct fbnic_hw_stats hw_stats;
	u64 fw_mbx_events;

	/* Firmware time since boot in milliseconds */
	u64 firmware_time;
	u64 prev_firmware_time;

	struct fbnic_fw_log fw_log;
};

/* Reserve entry 0 in the MSI-X "others" array until we have filled all
 * 32 of the possible interrupt slots. By doing this we can avoid any
 * potential conflicts should we need to enable one of the debug interrupt
 * causes later.
 */
enum {
	FBNIC_FW_MSIX_ENTRY,
	FBNIC_MAC_MSIX_ENTRY,
	FBNIC_DBG_MSIX_ENTRY,
	FBNIC_NON_NAPI_VECTORS
};

static inline bool fbnic_present(struct fbnic_dev *fbd)
{
	return !!READ_ONCE(fbd->uc_addr0);
}

static inline void fbnic_wr32(struct fbnic_dev *fbd, u32 reg, u32 val)
{
	u32 __iomem *csr = READ_ONCE(fbd->uc_addr0);

	if (csr)
		writel(val, csr + reg);
}

u32 fbnic_rd32(struct fbnic_dev *fbd, u32 reg);

static inline void
fbnic_rmw32(struct fbnic_dev *fbd, u32 reg, u32 mask, u32 val)
{
	u32 v;

	v = fbnic_rd32(fbd, reg);
	v &= ~mask;
	v |= val;
	fbnic_wr32(fbd, reg, v);
}

#define wr32(reg, val)	fbnic_wr32(fbd, reg, val)
#define rd32(reg)	fbnic_rd32(fbd, reg)
#define wrfl()		fbnic_rd32(fbd, FBNIC_MASTER_SPARE_0)

bool fbnic_fw_present(struct fbnic_dev *fbd);
u32 fbnic_fw_rd32(struct fbnic_dev *fbd, u32 reg);
void fbnic_fw_wr32(struct fbnic_dev *fbd, u32 reg, u32 val);

#define fw_rd32(reg)		fbnic_fw_rd32(fbd, reg)
#define fw_wr32(reg, val)	fbnic_fw_wr32(fbd, reg, val)
#define fw_wrfl()		fbnic_fw_rd32(fbd, FBNIC_FW_ZERO_REG)

static inline void *
fbnic_alloc_page(struct fbnic_dev *fbd, gfp_t gfp)
{
	return (void *)__get_free_page(gfp);
}

static inline void
fbnic_free_page(struct fbnic_dev *fbd, void *addr)
{
	free_page((unsigned long)addr);
}

static inline dma_addr_t
fbnic_dma_map(struct fbnic_dev *fbd, void *ptr, size_t size,
	      enum dma_data_direction dir)
{
	return dma_map_single(fbd->dev, ptr, size, dir);
}

static inline int
fbnic_dma_mapping_error(struct fbnic_dev *fbd, dma_addr_t addr)
{
	return dma_mapping_error(fbd->dev, addr);
}

static inline void
fbnic_dma_unmap(struct fbnic_dev *fbd, void *ptr, size_t size,
		enum dma_data_direction dir, dma_addr_t addr)
{
	return dma_unmap_single(fbd->dev, addr, size, dir);
}

static inline bool fbnic_bmc_present(struct fbnic_dev *fbd)
{
	return fbd->fw_cap.bmc_present;
}

static inline void fbnic_bmc_set_present(struct fbnic_dev *fbd, bool present)
{
	fbd->fw_cap.bmc_present = present;
}

static inline bool fbnic_init_failure(struct fbnic_dev *fbd)
{
	return !fbd->netdev;
}

extern char fbnic_driver_name[];

void fbnic_devlink_free(struct fbnic_dev *fbd);
struct fbnic_dev *fbnic_devlink_alloc(struct pci_dev *pdev);
void fbnic_devlink_register(struct fbnic_dev *fbd);
void fbnic_devlink_unregister(struct fbnic_dev *fbd);
void fbnic_devlink_fw_fault_report(struct fbnic_dev *fbd, const char *format,
				   ...);

int fbnic_fw_enable_mbx(struct fbnic_dev *fbd);
void fbnic_fw_disable_mbx(struct fbnic_dev *fbd);

void fbnic_hwmon_register(struct fbnic_dev *fbd);
void fbnic_hwmon_unregister(struct fbnic_dev *fbd);

int fbnic_mac_get_link(struct fbnic_dev *fbd, bool *link);
int fbnic_mac_enable(struct fbnic_dev *fbd);
void fbnic_mac_disable(struct fbnic_dev *fbd);

int fbnic_msix_test(struct fbnic_dev *fbd);

void fbnic_dbg_nv_init(struct fbnic_napi_vector *nv);
void fbnic_dbg_nv_exit(struct fbnic_napi_vector *nv);
void fbnic_dbg_fbd_init(struct fbnic_dev *fbd);
void fbnic_dbg_fbd_exit(struct fbnic_dev *fbd);
void fbnic_dbg_init(void);
void fbnic_dbg_exit(void);

enum fbnic_boards {
	fbnic_board_fpga,
	fbnic_board_asic
};

struct fbnic_info {
	int max_num_queues;
	int bar_mask;
};

#endif /* _FBNIC_H_ */
