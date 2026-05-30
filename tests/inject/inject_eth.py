#!/usr/bin/env python3
"""
inject_eth.py — send one well-formed Ethernet frame on the named iface.

Usage:
    sudo python3 inject_eth.py <iface> <src_mac> <dst_mac> [ethertype]

Builds a 60-byte Ethernet frame with a 46-byte zero payload to satisfy
minimum Ethernet length without invoking any kernel L3 path. The optional
4th positional `ethertype` (hex/int) defaults to 0x88B5 (locally
experimental, no L3 stack interpretation) — so existing 3-arg callers stay
byte-equivalent (§5.51 D-mvp-4.11-INJECT-DEFAULT). The MVP-4.11/S1 negation
control passes 0x86DD to traverse the new ETH_P_IPV6 dispatch arm.
"""
import sys

from scapy.all import Ether, Raw, sendp  # type: ignore


def main() -> int:
    if len(sys.argv) not in (4, 5):
        print(
            "usage: inject_eth.py <iface> <src_mac> <dst_mac> [ethertype]",
            file=sys.stderr,
        )
        return 1
    iface, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    # base 0 lets the optional arg accept 0x86DD / 0x88B5 / decimal alike.
    ethertype = int(sys.argv[4], 0) if len(sys.argv) == 5 else 0x88B5
    pkt = Ether(src=src, dst=dst, type=ethertype) / Raw(load=b"\x00" * 46)
    # count=1: exactly one packet so counter assertions are exact.
    sendp(pkt, iface=iface, count=1, verbose=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
