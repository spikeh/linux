#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

from os import path
from lib.py import ksft_run, ksft_exit
from lib.py import NetDrvEpEnv
from lib.py import bkg, cmd, wait_port_listen


def _get_rx_ring_entries(cfg):
    eth_cmd = "ethtool -g {} | awk '/RX:/ {{count++}} count == 2 {{print $2; exit}}'"
    res = cmd(eth_cmd.format(cfg.ifname), host=cfg.remote)
    return int(res.stdout)


def _get_combined_channels(cfg):
    eth_cmd = "ethtool -l {} | awk '/Combined:/ {{count++}} count == 2 {{print $2; exit}}'"
    res = cmd(eth_cmd.format(cfg.ifname), host=cfg.remote)
    return int(res.stdout)


def _set_flow_rule(cfg, chan):
    eth_cmd = "ethtool -N {} flow-type tcp6 dst-port 9999 action {} | awk '{{print $NF}}'"
    res = cmd(eth_cmd.format(cfg.ifname, chan), host=cfg.remote)
    return int(res.stdout)


def test_zcrx(cfg) -> None:
    cfg.require_v6()
    cfg.require_cmd("awk", remote=True)

    combined_chans = _get_combined_channels(cfg)
    if combined_chans < 2:
        raise KsftSkipEx('at least 2 combined channels required')
    rx_ring = _get_rx_ring_entries(cfg)

    rx_cmd = f"{cfg.bin_remote} -6 -s -p 9999 -i {cfg.ifname} -q {combined_chans - 1}"
    tx_cmd = f"{cfg.bin_local} -6 -c -h {cfg.remote_v6} -p 9999 -l 12840"

    try:
        cmd(f"ethtool -G {cfg.ifname} rx 64", host=cfg.remote)
        cmd(f"ethtool -X {cfg.ifname} equal {combined_chans - 1}", host=cfg.remote)
        flow_rule_id = _set_flow_rule(cfg, combined_chans - 1)

        with bkg(rx_cmd, host=cfg.remote, exit_wait=True):
            wait_port_listen(9999, proto="tcp", host=cfg.remote)
            cmd(tx_cmd)
    finally:
        cmd(f"ethtool -N {cfg.ifname} delete {flow_rule_id}", host=cfg.remote)
        cmd(f"ethtool -X {cfg.ifname} default", host=cfg.remote)
        cmd(f"ethtool -G {cfg.ifname} rx {rx_ring}", host=cfg.remote)


def main() -> None:
    with NetDrvEpEnv(__file__) as cfg:
        cfg.bin_local = path.abspath(path.dirname(__file__) + "/../../../drivers/net/hw/iou-zcrx")
        cfg.bin_remote = cfg.remote.deploy(cfg.bin_local)

        ksft_run(globs=globals(), case_pfx={"test_"}, args=(cfg, ))
    ksft_exit()


if __name__ == "__main__":
    main()
