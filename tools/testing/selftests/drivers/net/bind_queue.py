#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

from lib.py import ksft_run, ksft_exit
from lib.py import ksft_eq
from lib.py import NetDrvEnv
from lib.py import NetdevFamily, ip, ethtool
from lib.py import NlError, CmdExitFailure


def bind(cfg, nl) -> None:
    ip(f"link add nk1 type netkit mode l2 forward peer forward nk2 numrxqueues 2")

    channels = ethtool(f"-l {cfg.ifname}", json=True)[0]
    src_qid = channels["combined"] - 1

    netkit = ip(f"-d link show dev nk2", json=True)[0]
    nk_qid = nl.bind_queue(
        {
            "src-ifindex": cfg.ifindex,
            "src-queue-id": src_qid,
            "dst-ifindex": netkit["ifindex"],
            "queue-type": "rx",
        }
    )
    nk_qid = nk_qid["dst-queue-id"]

    queue = nl.queue_get({"ifindex": cfg.ifindex, "id": src_qid, "type": "rx"})

    ksft_eq(nk_qid, queue["peer"]["id"])
    ksft_eq(netkit["ifindex"], queue["peer"]["ifindex"])

    ip(f"link del nk1")


def bind_no_queues(cfg, nl) -> None:
    ip(f"link add nk1 type netkit mode l2 forward peer forward nk2")

    channels = ethtool(f"-l {cfg.ifname}", json=True)[0]
    src_qid = channels["combined"] - 1

    netkit = ip(f"-d link show dev nk2", json=True)[0]
    try:
        nl.bind_queue(
            {
                "src-ifindex": cfg.ifindex,
                "src-queue-id": src_qid,
                "dst-ifindex": netkit["ifindex"],
                "queue-type": "rx",
            }
        )
    except NlError as ex:
        ksft_eq(ex.error, 22)

    ip(f"link del nk1")


def resize(cfg, nl) -> None:
    ip(f"link add nk1 type netkit mode l2 forward peer forward nk2 numrxqueues 2")

    channels = ethtool(f"-l {cfg.ifname}", json=True)[0]
    src_qid = channels["combined"] - 1

    netkit = ip(f"-d link show dev nk2", json=True)[0]
    nl.bind_queue(
        {
            "src-ifindex": cfg.ifindex,
            "src-queue-id": src_qid,
            "dst-ifindex": netkit["ifindex"],
            "queue-type": "rx",
        }
    )

    fail = False
    try:
        ethtool(f"-L {cfg.ifname} combined {src_qid}")
    except CmdExitFailure as ex:
        fail = True

    ksft_eq(fail, True)

    ip(f"link del nk1")


def main() -> None:
    with NetDrvEnv(__file__) as cfg:
        ksft_run([bind, bind_no_queues, resize], args=(cfg, NetdevFamily()))
    ksft_exit()


if __name__ == "__main__":
    main()
