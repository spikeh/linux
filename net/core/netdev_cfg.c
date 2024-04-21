/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/netdevice.h>
#include <net/netdev_cfg.h>

static int
netdev_nic_cfg_txqmem_alloc(struct net_device *dev, struct netdev_nic_cfg *nic)
{
	const struct netdev_nic_cfg_info *info = &dev->nic_cfg_info;
	struct netdev_nic_cfg *old_nic = dev->nic_cfg;
	struct netdev_cfg *dcfg = &nic->cfg;
	unsigned int i;
	void *qmem;
	int err;

	if (WARN_ON(!nic->txq_cnt))
		return -EINVAL;

	nic->txqmem = kvcalloc(nic->txq_cnt, info->txq_mem_size, GFP_KERNEL);
	if (!nic->txqmem)
		return -ENOMEM;

	nic->txq_cfg.ring = nic->ring;
	nic->txq_cfg.kring = nic->kring;

	if (old_nic->recfg) {
		unsigned int min_qcnt;
		size_t len;

		min_qcnt = min(old_nic->txq_cnt, nic->txq_cnt);
		if (unlikely(check_mul_overflow(min_qcnt, info->txq_mem_size, &len))) {
			err = -ENOMEM;
			goto err_txqmem_free;
		}
		memcpy(nic->txqmem, old_nic->txqmem, len);
	}

	for (i = 0; i < nic->txq_cnt; i++) {
		qmem = netdev_nic_cfg_txqmem(dev, nic, i);

		err = dev->netdev_ops->ndo_tx_queue_mem_alloc(dev, dcfg, &nic->txq_cfg, qmem, i);
		if (err)
			goto err_qmem_free_prev;
	}

	return 0;

err_qmem_free_prev:
	while (i--) {
		qmem = netdev_nic_cfg_txqmem(dev, nic, i);

		dev->netdev_ops->ndo_tx_queue_mem_free(dev, dcfg, &nic->txq_cfg, qmem, i);
	}
err_txqmem_free:
	kvfree(nic->txqmem);
	nic->txqmem = NULL;
	return err;
}

static int
netdev_nic_cfg_rxqmem_alloc(struct net_device *dev, struct netdev_nic_cfg *nic)
{
	const struct netdev_nic_cfg_info *info = &dev->nic_cfg_info;
	struct netdev_nic_cfg *old_nic = dev->nic_cfg;
	struct netdev_cfg *dcfg = &nic->cfg;
	unsigned int i;
	void *qmem;
	int err;

	if (WARN_ON(!nic->rxq_cnt))
		return -EINVAL;

	nic->rxqmem = kvcalloc(nic->rxq_cnt, info->rxq_mem_size, GFP_KERNEL);
	if (!nic->rxqmem)
		return -ENOMEM;

	nic->rxq_cfg.ring = nic->ring;
	nic->rxq_cfg.kring = nic->kring;

	if (old_nic->recfg) {
		unsigned int min_qcnt;
		size_t len;

		min_qcnt = min(old_nic->rxq_cnt, nic->rxq_cnt);
		if (unlikely(check_mul_overflow(min_qcnt, info->rxq_mem_size, &len))) {
			err = -ENOMEM;
			goto err_rxqmem_free;
		}
		memcpy(nic->rxqmem, old_nic->rxqmem, len);
	}

	for (i = 0; i < nic->rxq_cnt; i++) {
		qmem = netdev_nic_cfg_rxqmem(dev, nic, i);

		err = dev->netdev_ops->ndo_rx_queue_mem_alloc(dev, dcfg, &nic->rxq_cfg, qmem, i);
		if (err)
			goto err_qmem_free_prev;
	}

	return 0;

err_qmem_free_prev:
	while (i--) {
		qmem = netdev_nic_cfg_rxqmem(dev, nic, i);

		dev->netdev_ops->ndo_rx_queue_mem_free(dev, dcfg, &nic->rxq_cfg, qmem, i);
	}
err_rxqmem_free:
	kvfree(nic->rxqmem);
	nic->rxqmem = NULL;
	return err;
}

static void
netdev_nic_cfg_txqmem_free(struct net_device *dev, struct netdev_nic_cfg *nic)
{
	unsigned int i;
	void *qmem;

	if (!nic->txqmem)
		return;

	for (i = 0; i < nic->txq_cnt; i++) {
		qmem = netdev_nic_cfg_txqmem(dev, nic, i);

		dev->netdev_ops->ndo_tx_queue_mem_free(dev, &nic->cfg, &nic->txq_cfg, qmem, i);
	}
	kvfree(nic->txqmem);
	nic->txqmem = NULL;
}

static void
netdev_nic_cfg_rxqmem_free(struct net_device *dev, struct netdev_nic_cfg *nic)
{
	unsigned int i;
	void *qmem;

	if (!nic->rxqmem)
		return;

	for (i = 0; i < nic->rxq_cnt; i++) {
		qmem = netdev_nic_cfg_rxqmem(dev, nic, i);

		dev->netdev_ops->ndo_rx_queue_mem_free(dev, &nic->cfg, &nic->rxq_cfg, qmem, i);
	}
	kvfree(nic->rxqmem);
	nic->rxqmem = NULL;
}

int netdev_nic_cfg_init(struct net_device *dev)
{
	struct netdev_nic_cfg *nic;

	if (WARN_ON(!dev->nic_cfg_info.txq_mem_size))
		return -EINVAL;
	if (WARN_ON(!dev->nic_cfg_info.rxq_mem_size))
		return -EINVAL;

	nic = kzalloc(sizeof(*nic), GFP_KERNEL);
	if (!nic)
		return -ENOMEM;

	nic->cfg.mtu = dev->mtu;
	dev->ethtool_ops->get_channels(dev, &nic->cfg.chan);
	dev->ethtool_ops->get_ringparam(dev, &nic->ring, &nic->kring, NULL);

	dev->nic_cfg = nic;

	return 0;
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_init);

void netdev_nic_cfg_deinit(struct net_device *dev)
{
	WARN_ON(dev->nic_cfg->txqmem || dev->nic_cfg->txq_cnt);
	WARN_ON(dev->nic_cfg->rxqmem || dev->nic_cfg->rxq_cnt);
	WARN_ON(dev->nic_cfg->other_cfg);
	kfree(dev->nic_cfg);
	dev->nic_cfg = NULL;
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_deinit);

int netdev_nic_cfg_start(struct net_device *dev)
{
	struct ethtool_channels *chan = &dev->nic_cfg->cfg.chan;
	struct netdev_nic_cfg *nic = dev->nic_cfg;
	int err;

	/* Make sure driver already set the real_num_rx_queues */
	if (dev->real_num_rx_queues != chan->combined_count + chan->rx_count &&
	    dev->real_num_rx_queues != max(chan->combined_count,
					   chan->rx_count)) {
		WARN_ON(1);
		return -EINVAL;
	}

	nic->txq_cnt = dev->real_num_tx_queues;
	nic->rxq_cnt = dev->real_num_rx_queues;
	printk("----- netdev_nic_cfg_start: txq=%d, rxq=%d\n", nic->txq_cnt, nic->rxq_cnt);

	err = netdev_nic_cfg_txqmem_alloc(dev, nic);
	if (err)
		goto err_clear_qcnt;

	err = netdev_nic_cfg_rxqmem_alloc(dev, nic);
	if (err)
		goto err_free_txqmem;

	return 0;

err_free_txqmem:
	netdev_nic_cfg_txqmem_free(dev, nic);
err_clear_qcnt:
	nic->rxq_cnt = 0;
	nic->txq_cnt = 0;
	return err;
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_start);

void netdev_nic_cfg_stop(struct net_device *dev)
{
	netdev_nic_cfg_txqmem_free(dev, dev->nic_cfg);
	netdev_nic_cfg_rxqmem_free(dev, dev->nic_cfg);
	dev->nic_cfg->txq_cnt = 0;
	dev->nic_cfg->rxq_cnt = 0;
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_stop);

void netdev_nic_cfg_restart_txq(struct net_device *dev, unsigned int qid)
{
	struct netdev_nic_cfg *nic = dev->nic_cfg;
	void *qmem;

	WARN_ON(!nic->recfg);
	printk("----- restart_txq: id=%d\n", qid);

	if (qid < nic->txq_cnt) {
		qmem = netdev_nic_cfg_txqmem(dev, nic, qid);
		printk("----- restart_txq: stopping old queue=%d\n", qid);
		dev->netdev_ops->ndo_tx_queue_stop(dev, qmem, qid);
	}

	nic = nic->other_cfg;
	if (qid < nic->txq_cnt) {
		qmem = netdev_nic_cfg_txqmem(dev, nic, qid);
		printk("----- restart_txq: starting new queue=%d\n", qid);
		dev->netdev_ops->ndo_tx_queue_start(dev, qmem, qid);
	}
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_restart_txq);

void netdev_nic_cfg_restart_rxq(struct net_device *dev, unsigned int qid)
{
	struct netdev_nic_cfg *nic = dev->nic_cfg;
	void *qmem;

	WARN_ON(!nic->recfg);
	printk("----- restart_rxq: id=%d\n", qid);

	if (qid < nic->rxq_cnt) {
		qmem = netdev_nic_cfg_rxqmem(dev, nic, qid);
		printk("----- restart_rxq: stopping old queue=%d\n", qid);
		dev->netdev_ops->ndo_rx_queue_stop(dev, qmem, qid);
	}

	nic = nic->other_cfg;
	if (qid < nic->rxq_cnt) {
		qmem = netdev_nic_cfg_rxqmem(dev, nic, qid);
		printk("----- restart_rxq: starting new queue=%d\n", qid);
		dev->netdev_ops->ndo_rx_queue_start(dev, qmem, qid);
	}
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_restart_rxq);

void *netdev_nic_cfg_rxqmem(struct net_device *dev, struct netdev_nic_cfg *nic, unsigned int qid)
{
	if (WARN_ON_ONCE(qid >= nic->rxq_cnt))
		return NULL;
	return nic->rxqmem + qid * dev->nic_cfg_info.rxq_mem_size;
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_rxqmem);

void *netdev_nic_cfg_txqmem(struct net_device *dev, struct netdev_nic_cfg *nic, unsigned int qid)
{
	if (WARN_ON_ONCE(qid >= nic->txq_cnt))
		return NULL;
	return nic->txqmem + qid * dev->nic_cfg_info.txq_mem_size;
}
EXPORT_SYMBOL_GPL(netdev_nic_cfg_txqmem);

int netdev_nic_recfg_start(struct net_device *dev)
{
	struct netdev_nic_cfg *new_cfg;

	if (WARN_ON(dev->nic_cfg->other_cfg))
		return -EBUSY;

	new_cfg = kmemdup(dev->nic_cfg, sizeof(*dev->nic_cfg), GFP_KERNEL);
	if (!new_cfg)
		return -ENOMEM;

	memset(&new_cfg->txq_cfg, 0, sizeof(new_cfg->txq_cfg));
	memset(&new_cfg->rxq_cfg, 0, sizeof(new_cfg->rxq_cfg));
	new_cfg->txq_cnt = 0;
	new_cfg->rxq_cnt = 0;
	new_cfg->txqmem = NULL;
	new_cfg->rxqmem = NULL;
	new_cfg->txq_idx = 0;
	new_cfg->rxq_idx = 0;

	dev->nic_cfg->other_cfg = new_cfg;
	dev->nic_cfg->recfg = true;

	return 0;
}
EXPORT_SYMBOL_GPL(netdev_nic_recfg_start);

int netdev_nic_recfg_prep(struct net_device *dev)
{
	struct netdev_nic_cfg *nic = dev->nic_cfg->other_cfg;
	int err;

	if (!nic->txq_cnt)
		nic->txq_cnt = dev->real_num_tx_queues;
	if (!nic->rxq_cnt)
		nic->rxq_cnt = dev->real_num_rx_queues;

	printk("----- netdev_nic_recfg_prep: txq=%d, rxq=%d\n", nic->txq_cnt, nic->rxq_cnt);

	err = netdev_nic_cfg_txqmem_alloc(dev, nic);
	if (err)
		goto err_clear_qcnt;

	err = netdev_nic_cfg_rxqmem_alloc(dev, nic);
	if (err)
		goto err_free_txqmem;

	return 0;

err_free_txqmem:
	netdev_nic_cfg_txqmem_free(dev, nic);
err_clear_qcnt:
	nic->rxq_cnt = 0;
	nic->txq_cnt = 0;
	return err;
}
EXPORT_SYMBOL_GPL(netdev_nic_recfg_prep);

void netdev_nic_recfg_swap(struct net_device *dev)
{
	struct netdev_nic_cfg *new, *old;

	old = dev->nic_cfg;
	new = old->other_cfg;

	dev->nic_cfg = new;
	new->other_cfg = old;
	old->other_cfg = NULL;
}
EXPORT_SYMBOL_GPL(netdev_nic_recfg_swap);

void netdev_nic_recfg_end(struct net_device *dev)
{
	dev->nic_cfg->recfg = false;
	netdev_nic_cfg_txqmem_free(dev, dev->nic_cfg->other_cfg);
	netdev_nic_cfg_rxqmem_free(dev, dev->nic_cfg->other_cfg);
	kfree(dev->nic_cfg->other_cfg);
	dev->nic_cfg->other_cfg = NULL;
}
EXPORT_SYMBOL_GPL(netdev_nic_recfg_end);
