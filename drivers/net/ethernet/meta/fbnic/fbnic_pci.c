// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */

#include <linux/aer.h>
#include <linux/bitfield.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/rtnetlink.h>
#include <linux/types.h>

#include "fbnic.h"
#include "fbnic_drvinfo.h"
#include "fbnic_netdev.h"
#include "fbnic_txrx.h"

char fbnic_driver_name[] = "fbnic";

MODULE_DESCRIPTION(DRV_SUMMARY);
MODULE_LICENSE("GPL");

static const struct fbnic_info fbnic_fpga_info = {
	.max_num_queues = FBNIC_MAX_QUEUES_FPGA,
	.bar_mask = BIT(0)
};

static const struct fbnic_info fbnic_asic_info = {
	.max_num_queues = FBNIC_MAX_QUEUES_ASIC,
	.bar_mask = BIT(0) | BIT(4)
};

static const struct fbnic_info *fbnic_info_tbl[] = {
	[fbnic_board_fpga] = &fbnic_fpga_info,
	[fbnic_board_asic] = &fbnic_asic_info,
};

static const struct pci_device_id fbnic_pci_tbl[] = {
	{ PCI_DEVICE_DATA(META, FBNIC_FPGA, fbnic_board_fpga) },
	{ PCI_DEVICE_DATA(META, FBNIC_ASIC, fbnic_board_asic) },
	/* required last entry */
	{0, }
};

MODULE_DEVICE_TABLE(pci, fbnic_pci_tbl);

u32 fbnic_rd32(struct fbnic_dev *fbd, u32 reg)
{
	u32 __iomem *csr = READ_ONCE(fbd->uc_addr0);
	u32 value;

	if (!csr)
		return ~0U;

	value = readl(csr + reg);

	/* If any bits are 0 value should be valid */
	if (~value)
		return value;

	/* All 1's may be valid if ZEROs register still works */
	if (reg != FBNIC_MASTER_SPARE_0 && ~readl(csr + FBNIC_MASTER_SPARE_0))
		return value;

	/* Hardware is giving us all 1's reads, assume it is gone */
	WRITE_ONCE(fbd->uc_addr0, NULL);
	WRITE_ONCE(fbd->uc_addr4, NULL);

	dev_err(fbd->dev,
		"Failed read (idx 0x%x AKA addr 0x%x), disabled CSR access, awaiting reset\n",
		reg, reg << 2);

	/* Notify stack that device has lost (PCIe) link */
	if (!fbnic_init_failure(fbd))
		netif_device_detach(fbd->netdev);

	return ~0U;
}

bool fbnic_fw_present(struct fbnic_dev *fbd)
{
	return !!READ_ONCE(fbd->uc_addr4);
}

void fbnic_fw_wr32(struct fbnic_dev *fbd, u32 reg, u32 val)
{
	u32 __iomem *csr = READ_ONCE(fbd->uc_addr4);

	if (csr)
		writel(val, csr + reg);
}

u32 fbnic_fw_rd32(struct fbnic_dev *fbd, u32 reg)
{
	u32 __iomem *csr = READ_ONCE(fbd->uc_addr4);
	u32 value;

	if (!csr)
		return ~0U;

	value = readl(csr + reg);

	/* If any bits are 0 value should be valid */
	if (~value)
		return value;

	/* All 1's may be valid if ZEROs register still works
	 * TBD: Set correct ZEROs register for BAR4.
	 */
	if (reg != FBNIC_FW_ZERO_REG && ~readl(csr + FBNIC_FW_ZERO_REG))
		return value;

	/* Hardware is giving us all 1's reads, assume it is gone */
	WRITE_ONCE(fbd->uc_addr0, NULL);
	WRITE_ONCE(fbd->uc_addr4, NULL);

	dev_err(fbd->dev,
		"Failed read (idx 0x%x AKA addr 0x%x), disabled CSR access, awaiting reset\n",
		reg, reg << 2);

	/* Notify stack that device has lost (PCIe) link */
	if (fbd->netdev)
		netif_device_detach(fbd->netdev);

	return ~0U;
}

static void fbnic_service_task_start(struct fbnic_net *fbn)
{
	struct fbnic_dev *fbd = fbn->fbd;

	schedule_delayed_work(&fbd->service_task, HZ);
}

static void fbnic_service_task_stop(struct fbnic_net *fbn)
{
	struct net_device *netdev = fbn->netdev;
	struct fbnic_dev *fbd = fbn->fbd;

	cancel_delayed_work(&fbd->service_task);
	netif_carrier_off(netdev);
}

void __fbnic_up(struct fbnic_net *fbn)
{
	fbnic_enable(fbn);

	/* TBD: Verify if Rings have been enabled? */

	fbnic_fill(fbn);

	fbnic_rss_reinit_hw(fbn->fbd, fbn);

	__fbnic_set_rx_mode(fbn->netdev);
}

void fbnic_up(struct fbnic_net *fbn)
{
	__fbnic_up(fbn);

	/* Enable Tx/Rx processing */
	fbnic_napi_enable(fbn);
	netif_tx_start_all_queues(fbn->netdev);

	fbnic_service_task_start(fbn);

	fbnic_dbg_up(fbn);
}

void __fbnic_down(struct fbnic_net *fbn)
{
	fbnic_clear_rx_mode(fbn->netdev);
	fbnic_clear_rules(fbn->fbd);
	fbnic_rss_disable_hw(fbn->fbd);
	fbnic_disable(fbn);
}

void fbnic_down_noidle(struct fbnic_net *fbn)
{
	fbnic_dbg_down(fbn);

	fbnic_service_task_stop(fbn);

	/* Enable Tx/Rx Processing */
	fbnic_napi_disable(fbn);
	netif_tx_disable(fbn->netdev);

	__fbnic_down(fbn);
}

void fbnic_down(struct fbnic_net *fbn)
{
	fbnic_down_noidle(fbn);

	fbnic_wait_all_queues_idle(fbn->fbd, false);

	fbnic_flush(fbn);
}

static void fbnic_free_irqs(struct fbnic_dev *fbd)
{
	struct pci_dev *pdev = to_pci_dev(fbd->dev);

	fbd->mac_msix_vector = 0;
	fbd->fw_msix_vector = 0;

	fbd->num_irqs = 0;

	pci_disable_msix(pdev);

	kfree(fbd->msix_entries);
	fbd->msix_entries = NULL;
}

static int fbnic_alloc_irqs(struct fbnic_dev *fbd)
{
	unsigned int wanted_irqs = FBNIC_NON_NAPI_VECTORS;
	struct pci_dev *pdev = to_pci_dev(fbd->dev);
	struct msix_entry *msix_entries;
	int i, num_irqs;

	wanted_irqs += min_t(unsigned int, num_online_cpus(), FBNIC_MAX_RXQS);
	msix_entries = kcalloc(wanted_irqs, sizeof(*msix_entries), GFP_KERNEL);
	if (!msix_entries)
		return -ENOMEM;

	for (i = 0; i < wanted_irqs; i++)
		msix_entries[i].entry = i;

	num_irqs = pci_enable_msix_range(pdev, msix_entries,
					 FBNIC_NON_NAPI_VECTORS + 1,
					 wanted_irqs);
	if (num_irqs < 0) {
		dev_err(fbd->dev, "Failed to allocate MSI-X entries\n");
		kfree(msix_entries);
		return num_irqs;
	}

	if (num_irqs < wanted_irqs)
		dev_warn(fbd->dev, "Allocated %d IRQs, expected %d\n",
			 num_irqs, wanted_irqs);

	fbd->msix_entries = msix_entries;
	fbd->num_irqs = num_irqs;

	fbd->mac_msix_vector = msix_entries[FBNIC_MAC_MSIX_ENTRY].vector;
	fbd->fw_msix_vector = msix_entries[FBNIC_FW_MSIX_ENTRY].vector;

	return 0;
}

static char *fbnic_report_fec(struct fbnic_dev *fbd)
{
	struct fbnic_net *fbn = netdev_priv(fbd->netdev);

	if (fbn->link_mode & FBNIC_LINK_MODE_PAM4)
		return "Clause 91 RS(544,514)";

	switch (fbn->fec & FBNIC_FEC_MODE_MASK) {
	case FBNIC_FEC_OFF:
		return "Off";
	case FBNIC_FEC_BASER:
		return "Clause 74 BaseR";
	case FBNIC_FEC_RS:
		return "Clause 91 RS(528,514)";
	}

	return "Unknown";
}

static void fbnic_link_check(struct fbnic_dev *fbd)
{
	struct net_device *netdev = fbd->netdev;
	bool link_found = false;
	int err;

	err = fbnic_mac_get_link(fbd, &link_found);
	if (err) {
		/* TBD: For now we do nothing. In the future we should have
		 * the link_check function request a reset.
		 *
		 * We would do this here as the reset will likely involve
		 * us having to tear down the interface which will require
		 * us taking the RTNL lock in order to coordinate the
		 * teardown and bringup before and after the reset.
		 */
		return;
	}

	if (!link_found) {
		if (netif_carrier_ok(netdev)) {
			struct fbnic_net *fbn = netdev_priv(netdev);

			netdev_err(netdev, "NIC Link is Down\n");
			fbn->link_down_events++;
		}
		netif_carrier_off(netdev);
		return;
	}

	if (!netif_carrier_ok(netdev)) {
		struct fbnic_net *fbn = netdev_priv(netdev);

		netdev_info(netdev,
			    "NIC Link is Up, %d Mbps (%s), Flow control: %s\n",
			    ((fbn->link_mode & FBNIC_LINK_MODE_PAM4) ?
			     50000 : 25000) *
			    ((fbn->link_mode & FBNIC_LINK_MODE_R2) ?
			     2 : 1),
			    (fbn->link_mode & FBNIC_LINK_MODE_PAM4) ?
			    "PAM4" : "NRZ",
			    (fbn->rx_pause ?
			     (fbn->tx_pause ? "ON - Tx/Rx" : "ON - Rx") :
			     (fbn->tx_pause ? "ON - Tx" : "OFF")));
		netdev_info(netdev, "FEC autoselect %s encoding: %s\n",
			    (fbn->fec & FBNIC_FEC_AUTO) ?
			    "enabled" : "disabled",
			    fbnic_report_fec(fbd));
		fbnic_config_drop_mode(fbn);
	}
	netif_carrier_on(netdev);
}

static void fbnic_health_check(struct fbnic_dev *fbd)
{
	struct fbnic_fw_mbx *tx_mbx = &fbd->mbx[FBNIC_IPC_MBX_TX_IDX];

	/* As long as the heart is beating the FW is healty */
	if (fbd->fw_heartbeat_enabled)
		return;

	/* If the Tx mailbox still has messages sitting in it then there likely
	 * isn't anything we can do. We will wait until the mailbox is empty to
	 * report the fault so we can collect the crashlog.
	 */
	if (tx_mbx->head != tx_mbx->tail)
		return;

	fbnic_devlink_fw_fault_report(fbd, "Firmware crashed detected!\n");

	/* TBD: Need to add a more thorough recovery here.
	 *	Specifically I need to verify what all the firmware will have
	 *	changed since we had setup and it rebooted. May just need to
	 *	perform a down/up. For now we will just reclaim ownership so
	 *	the heartbeat can catch the next fault.
	 */
	fbnic_fw_xmit_ownership_msg(fbd, true);
}

static void fbnic_service_task(struct work_struct *work)
{
	struct fbnic_dev *fbd = container_of(to_delayed_work(work),
					     struct fbnic_dev, service_task);

	fbnic_update_hw_stats32(fbd);

	rtnl_lock();

	fbnic_fw_check_heartbeat(fbd);
	fbnic_link_check(fbd);

	fbnic_health_check(fbd);

	if (netif_carrier_ok(fbd->netdev))
		fbnic_napi_depletion_check(fbd->netdev);

	if (netif_running(fbd->netdev))
		schedule_delayed_work(&fbd->service_task, HZ);

	rtnl_unlock();
}

/**
 *  fbnic_probe - Device Initialization Routine
 *  @pdev: PCI device information struct
 *  @ent: entry in fbnic_pci_tbl
 *
 *  Returns 0 on success, negative on failure
 *
 *  Initializes a PCI device identified by a pci_dev structure.
 *  The OS initialization, configuring of the adapter private structure,
 *  and a hardware reset occur.
 **/
static int fbnic_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	const struct fbnic_info *info = fbnic_info_tbl[ent->driver_data];
	struct net_device *netdev;
	struct fbnic_dev *fbd;
	int err;

	if (pdev->error_state != pci_channel_io_normal) {
		dev_err(&pdev->dev,
			"PCI device still in an error state. Unable to load...\n");
		return -EIO;
	}

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev,
			"PCI enable device failed: %d\n", err);
		return err;
	}

	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(46));
	if (err)
		err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	if (err) {
		dev_err(&pdev->dev,
			"DMA configuration failed: %d\n", err);
		return err;
	}

	err = pcim_iomap_regions(pdev, info->bar_mask, fbnic_driver_name);
	if (err) {
		dev_err(&pdev->dev,
			"pci_request_selected_regions failed: %d\n", err);
		return err;
	}

	fbd = fbnic_devlink_alloc(pdev);
	if (!fbd) {
		dev_err(&pdev->dev, "Devlink allocation failed\n");
		return -ENOMEM;
	}

	/* populate driver with hardware-specific info and handlers */
	fbd->max_num_queues = info->max_num_queues;

	fbnic_devlink_register(fbd);

	pci_set_master(pdev);
	pci_save_state(pdev);

	INIT_DELAYED_WORK(&fbd->service_task, fbnic_service_task);

	err = fbnic_alloc_irqs(fbd);
	if (err)
		goto init_failure_mode;

	err = fbnic_mac_init(fbd);
	if (err) {
		dev_err(&pdev->dev, "Failed to assign CMAC: %d\n", err);
		goto init_failure_mode;
	}

	err = fbnic_fw_enable_mbx(fbd);
	if (err) {
		dev_err(&pdev->dev, "Firmware mailbox initialization failure\n");
		goto init_failure_mode;
	}

	fbnic_hwmon_register(fbd);

	if (!fbd->dsn) {
		dev_warn(&pdev->dev, "Reading serial number failed\n");
		if (!mac_fallback)
			goto init_failure_mode;
	}

	netdev = fbnic_netdev_alloc(fbd);
	if (!netdev) {
		dev_err(&pdev->dev, "Netdev allocation failed\n");
		goto ifm_hwmon_unregister;
	}

	netdev->nic_cfg_info.txq_mem_size = sizeof(struct fbnic_txq_mem);
	netdev->nic_cfg_info.rxq_mem_size = sizeof(struct fbnic_rxq_mem);

	err = netdev_nic_cfg_init(netdev);
	if (err)
		goto ifm_free_netdev;

	err = fbnic_ptp_setup(fbd);
	if (err)
		goto ifm_free_netdev;

	err = fbnic_netdev_register(netdev);
	if (err) {
		dev_err(&pdev->dev, "Netdev registration failed: %d\n", err);
		goto ifm_destroy_ptp;
	}

	return 0;

ifm_destroy_ptp:
	fbnic_ptp_destroy(fbd);
ifm_free_netdev:
	fbnic_netdev_free(fbd);
ifm_hwmon_unregister:
	fbnic_hwmon_unregister(fbd);
init_failure_mode:
	dev_warn(&pdev->dev, "Probe error encountered, entering init failure mode. Normal networking functionality will not be available.\n");
	 /* Always return 0 even on error so devlink is registered to allow
	  * firmware updates for fixes.
	  */
	return 0;
}

/**
 * fbnic_remove - Device Removal Routine
 * @pdev: PCI device information struct
 *
 * Called by the PCI subsystem to alert the driver that it should release
 * a PCI device.  The could be caused by a Hot-Plug event, or because the
 * driver is going to be removed from memory.
 **/
static void fbnic_remove(struct pci_dev *pdev)
{
	struct fbnic_dev *fbd = pci_get_drvdata(pdev);

	if (!fbnic_init_failure(fbd)) {
		struct net_device *netdev = fbd->netdev;

		fbnic_netdev_unregister(netdev);
		cancel_delayed_work_sync(&fbd->service_task);
		fbnic_ptp_destroy(fbd);
		fbnic_netdev_free(fbd);
	}

	netdev_nic_cfg_deinit(fbd->netdev);
	fbnic_hwmon_unregister(fbd);
	fbnic_fw_disable_mbx(fbd);
	fbnic_free_irqs(fbd);

	pci_disable_device(pdev);

	fbnic_devlink_unregister(fbd);
	fbnic_devlink_free(fbd);
}

static int fbnic_pm_suspend(struct device *dev)
{
	struct fbnic_dev *fbd = dev_get_drvdata(dev);
	struct net_device *netdev = fbd->netdev;

	if (fbnic_init_failure(fbd))
		goto null_uc_addr;

	rtnl_lock();

	netif_device_detach(netdev);

	if (netif_running(netdev))
		netdev->netdev_ops->ndo_stop(netdev);

	rtnl_unlock();

null_uc_addr:
	fbnic_fw_disable_mbx(fbd);

	/* Free the IRQs so they aren't trying to occupy sleeping CPUs */
	fbnic_free_irqs(fbd);

	/* Hardware is about ot go away, so switch off MMIO access internally */
	WRITE_ONCE(fbd->uc_addr0, NULL);
	WRITE_ONCE(fbd->uc_addr4, NULL);

	return 0;
}

static int __fbnic_pm_resume(struct device *dev)
{
	struct fbnic_dev *fbd = dev_get_drvdata(dev);
	struct net_device *netdev = fbd->netdev;
	void __iomem * const *iomap_table;
	struct fbnic_net *fbn;
	int err;

	/* restore MMIO access */
	iomap_table = pcim_iomap_table(to_pci_dev(dev));
	fbd->uc_addr0 = iomap_table[0];
	fbd->uc_addr4 = iomap_table[4];

	/* rerequest the IRQs */
	err = fbnic_alloc_irqs(fbd);
	if (err)
		goto err_invalidate_uc_addr;

	fbd->mac->init_regs(fbd);

	/* Reenable mailbox */
	err = fbnic_fw_enable_mbx(fbd);
	if (err)
		goto err_free_irqs;

	/* no netdev means there isn't a network interface to bring up */
	if (fbnic_init_failure(fbd))
		return 0;

	fbn = netdev_priv(netdev);

	/* reset the queues if needed */
	fbnic_reset_queues(fbn, fbn->num_tx_queues, fbn->num_rx_queues);

	rtnl_lock();

	if (netif_running(netdev)) {
		err = __fbnic_open(fbn);
		if (err)
			goto err_disable_mbx;
	}

	rtnl_unlock();

	return 0;
err_disable_mbx:
	rtnl_unlock();
	fbnic_fw_disable_mbx(fbd);
err_free_irqs:
	fbnic_free_irqs(fbd);
err_invalidate_uc_addr:
	WRITE_ONCE(fbd->uc_addr0, NULL);
	WRITE_ONCE(fbd->uc_addr4, NULL);
	return err;
}

static void __fbnic_pm_attach(struct device *dev)
{
	struct fbnic_dev *fbd = dev_get_drvdata(dev);
	struct net_device *netdev = fbd->netdev;
	struct fbnic_net *fbn;

	fbnic_reset_hw_stats(fbd);

	if (fbnic_init_failure(fbd))
		return;

	fbn = netdev_priv(netdev);

	if (netif_running(netdev))
		fbnic_up(fbn);

	netif_device_attach(netdev);
}

static int __maybe_unused fbnic_pm_resume(struct device *dev)
{
	int err;

	err = __fbnic_pm_resume(dev);
	if (!err)
		__fbnic_pm_attach(dev);

	return err;
}

static const struct dev_pm_ops fbnic_pm_ops = {
	SET_SYSTEM_SLEEP_PM_OPS(fbnic_pm_suspend, fbnic_pm_resume)
};

static void fbnic_shutdown(struct pci_dev *pdev)
{
	fbnic_pm_suspend(&pdev->dev);
}

static pci_ers_result_t fbnic_err_error_detected(struct pci_dev *pdev,
						 pci_channel_state_t state)
{
	/* disconnect device if failure is not recoverable via reset */
	if (state == pci_channel_io_perm_failure)
		return PCI_ERS_RESULT_DISCONNECT;

	fbnic_pm_suspend(&pdev->dev);

	/* Request a slot reset */
	return PCI_ERS_RESULT_NEED_RESET;
}

static pci_ers_result_t fbnic_err_slot_reset(struct pci_dev *pdev)
{
	int err;

	pci_set_power_state(pdev, PCI_D0);
	pci_restore_state(pdev);
	pci_save_state(pdev);

	if (pci_enable_device_mem(pdev)) {
		dev_err(&pdev->dev,
			"Cannot re-enable PCI device after reset.\n");
		return PCI_ERS_RESULT_DISCONNECT;
	}

	/* restore device to previous state */
	err = __fbnic_pm_resume(&pdev->dev);

	return err ? PCI_ERS_RESULT_DISCONNECT : PCI_ERS_RESULT_RECOVERED;
}

static void fbnic_err_resume(struct pci_dev *pdev)
{
	__fbnic_pm_attach(&pdev->dev);
}

static const struct pci_error_handlers fbnic_err_handler = {
	.error_detected	= fbnic_err_error_detected,
	.slot_reset	= fbnic_err_slot_reset,
	.resume		= fbnic_err_resume,
};

static struct pci_driver fbnic_driver = {
	.name		= fbnic_driver_name,
	.id_table	= fbnic_pci_tbl,
	.probe		= fbnic_probe,
	.remove		= fbnic_remove,
	.driver.pm	= &fbnic_pm_ops,
	.shutdown	= fbnic_shutdown,
	.err_handler	= &fbnic_err_handler,
};

/**
 * fbnic_init_module - Driver Registration Routine
 *
 * The first routine called when the driver is loaded.  All it does is
 * register with the PCI subsystem.
 **/
static int __init fbnic_init_module(void)
{
	int err;

	pr_info(DRV_SUMMARY " (%s)", fbnic_driver.name);

	fbnic_dbg_init();

	err = pci_register_driver(&fbnic_driver);
	if (err)
		fbnic_dbg_exit();

	return err;
}
module_init(fbnic_init_module);

/**
 * fbnic_exit_module - Driver Exit Cleanup Routine
 *
 * Called just before the driver is removed from memory.
 **/
static void __exit fbnic_exit_module(void)
{
	pci_unregister_driver(&fbnic_driver);

	fbnic_dbg_exit();
}
module_exit(fbnic_exit_module);
