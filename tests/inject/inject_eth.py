#!/usr/bin/env python3
"""
inject_eth.py — send one well-formed Ethernet frame on the named iface.

Usage:
    sudo python3 inject_eth.py <iface> <src_mac> <dst_mac>

Builds a 60-byte Ethernet frame with EtherType 0x88B5 (locally
experimental, no L3 stack interpretation) and a 46-byte zero payload to
satisfy minimum Ethernet length without invoking any kernel L3 path.
"""
import sys

from scapy.all import Ether, Raw, sendp  # type: ignore


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: inject_eth.py <iface> <src_mac> <dst_mac>", file=sys.stderr)
        return 1
    iface, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    pkt = Ether(src=src, dst=dst, type=0x88B5) / Raw(load=b"\x00" * 46)
    # count=1: exactly one packet so counter assertions are exact.
    sendp(pkt, iface=iface, count=1, verbose=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
