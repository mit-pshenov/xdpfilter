#!/usr/bin/env python3
"""
inject_l6.py — MVP-4.12 §5.52 IPv6 frame injector (L2/L3 gate-rework S2).

Builds ONE Eth + [VLAN]* + 40-byte IPv6 base header + {TCP|UDP|ICMPv6 echo}
frame and sends it at L2 via scapy ``sendp`` (count=1). This is the testability
prerequisite the HLD's testability lens surfaced: ``inject_l4.py`` can only emit
IPv4 (EtherType 0x0800), so without this tool every future IPv6/cidr6 oracle
test (S4) would be vacuously green — there was no way to put a real IPv6 frame
on the wire. S2 ships the injector NOW so S4 can drop in cidr6 rules and
actually assert matches against the 128-bit src/dst the cidr6 axes will read.

Usage (CLI mirrors inject_l4.py):
    sudo python3 inject_l6.py <iface> \
        --dst-ip A --src-ip B --proto {tcp,udp,icmp6} [--dport N] \
        [--src-mac M] [--dst-mac M] [--vlan VID]...

LOAD-BEARING (PI-mvp-4.12-INJECTOR / D-mvp-4.12-L2-SENDP): the frame is sent at
LAYER 2 via ``sendp``, NEVER scapy's L3 ``send``. L3 send invokes the kernel
IPv6 routing/neighbour stack (and the veth has disable_ipv6=1), which would
rewrite the source address and L2 headers; the gate tests assert on exact
bytes, so the frame must leave the host verbatim. Mirrors inject_eth.py's sendp.

Q1=A1 (scapy): correct-by-construction — scapy computes the IPv6 payload_len,
the next-header (nh) field from the stacked L4 layer (6=TCP / 17=UDP /
58=ICMPv6), all L4 checksums (mandatory over the 128-bit IPv6 pseudo-header),
and the EtherType chain (0x86DD, or 0x8100->...->0x86DD when VLAN tags are
present). We deliberately do NOT hardcode Ether.type so the VLAN/QinQ case
lands 0x86DD in the innermost tag.

Scope: base 40-byte IPv6 header ONLY — NO IPv6 extension headers (ext-header
walking is S6). S6 SEAM: when ext-headers land, insert the chain (e.g.
IPv6ExtHdrHopByHop()/IPv6ExtHdrDestOpt()/...) between the IPv6() layer and the
L4 layer at the marked point in build_frame(), and add an ``--ext`` CLI option.

The MAC axis is irrelevant to the IPv6/cidr6 classification under test;
--src-mac/--dst-mac default to fixed non-meaningful constants (mirroring
inject_l4.py) and exist only so the frame is well-formed.
"""
import argparse
import sys

from scapy.all import (  # type: ignore
    Ether,
    Dot1Q,
    IPv6,
    TCP,
    UDP,
    ICMPv6EchoRequest,
    sendp,
)

# Fixed, deliberately non-meaningful MACs — there is no MAC axis under test
# here. Mirrors inject_l4.py's DEFAULT_SRC_MAC/DST_MAC values.
DEFAULT_SRC_MAC = "02:00:00:00:00:01"
DEFAULT_DST_MAC = "02:00:00:00:00:02"


def build_frame(src_mac, dst_mac, src_ip, dst_ip, proto, dport, vlans=None):
    """Return a scapy packet: Eth + [Dot1Q]* + IPv6 + L4.

    We stack layers and let scapy derive every type/length/next-header/checksum
    field rather than hardcoding them — that is the whole point of the scapy
    choice (Q1=A1) and is what keeps the VLAN/QinQ EtherType chain correct.
    """
    pkt = Ether(src=src_mac, dst=dst_mac)
    # First --vlan is the OUTERMOST tag (closest to the MAC headers); stacking
    # two yields QinQ. Matches inject_l4.py's --vlan ordering convention.
    for vid in (vlans or []):
        pkt /= Dot1Q(vlan=vid)
    pkt /= IPv6(src=src_ip, dst=dst_ip)
    # --- S6 SEAM: IPv6 extension headers would be inserted here (between the
    # IPv6 base header and the L4 layer). NOT in scope for S2 (base header only).
    if proto == "tcp":
        pkt /= TCP(dport=dport)
    elif proto == "udp":
        pkt /= UDP(dport=dport)
    else:  # icmp6: a basic echo request; --dport is unused (ICMPv6 has no port)
        pkt /= ICMPv6EchoRequest()
    return pkt


def _vlan_vid(s):
    vid = int(s, 0)
    if not 0 <= vid <= 4095:
        raise argparse.ArgumentTypeError(f"VLAN VID must be 0..4095, got {vid}")
    return vid


def _port(s):
    p = int(s, 0)
    if not 0 <= p <= 65535:
        raise argparse.ArgumentTypeError(f"dport must be 0..65535, got {p}")
    return p


def main():
    parser = argparse.ArgumentParser(
        prog="inject_l6.py",
        description="send one Eth+[VLAN]*+IPv6+L4 frame on an iface")
    parser.add_argument("iface")
    parser.add_argument("--dst-ip", required=True, help="IPv6 destination literal")
    parser.add_argument("--src-ip", required=True, help="IPv6 source literal")
    parser.add_argument("--proto", required=True,
                        choices=("tcp", "udp", "icmp6"))
    parser.add_argument("--dport", type=_port, default=0)
    parser.add_argument("--src-mac", default=DEFAULT_SRC_MAC)
    parser.add_argument("--dst-mac", default=DEFAULT_DST_MAC)
    parser.add_argument("--vlan", type=_vlan_vid, action="append", metavar="VID",
                        help="insert an 802.1Q tag; repeat for QinQ; "
                             "first --vlan is outermost")
    args = parser.parse_args()

    pkt = build_frame(args.src_mac, args.dst_mac,
                      args.src_ip, args.dst_ip,
                      args.proto, args.dport, args.vlan)
    # count=1: exactly one packet so counter-delta assertions are exact.
    sendp(pkt, iface=args.iface, count=1, verbose=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
