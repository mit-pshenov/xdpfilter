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

MVP-4.15 / S6 (§5.55): the S6 SEAM is now FILLED. ``--ext TYPE`` (repeatable;
hbh/dstopt/rt/frag) inserts an IPv6 extension-header chain between the IPv6()
base header and the L4 layer — exactly at the documented seam. scapy auto-chains
the per-header ``nh`` fields (correct-by-construction, Q1=A1 / D-mvp-4.15-INJECTOR),
so a frame built with ``--ext hbh --ext dstopt --proto tcp --dport N`` carries a
HopByHop→DestOpt→TCP chain whose true upper-layer protocol is TCP — visible ONLY
to a datapath that WALKS the chain (the VA-5 detectability headline). ``--truncate
N`` drops the trailing N bytes of the fully-built frame and sends the raw L2
bytes verbatim — used to exercise the mid-walk bounds-miss MALFORMED path without
asking scapy to build an intentionally-corrupt packet.

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
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrRouting,
    IPv6ExtHdrFragment,
    TCP,
    UDP,
    ICMPv6EchoRequest,
    Raw,
    sendp,
)

# §5.55 S6: --ext TYPE → scapy extension-header layer. scapy fills the per-layer
# `nh` (next-header) field automatically so the chain terminates at the stacked
# L4 layer's protocol number — the walk's whole job is to follow this chain.
EXT_HDR = {
    "hbh": IPv6ExtHdrHopByHop,    # nexthdr=0  (IPPROTO_HOPOPTS)
    "dstopt": IPv6ExtHdrDestOpt,  # nexthdr=60 (IPPROTO_DSTOPTS)
    "rt": IPv6ExtHdrRouting,      # nexthdr=43 (IPPROTO_ROUTING)
    "frag": IPv6ExtHdrFragment,   # nexthdr=44 (IPPROTO_FRAGMENT)
}

# Fixed, deliberately non-meaningful MACs — there is no MAC axis under test
# here. Mirrors inject_l4.py's DEFAULT_SRC_MAC/DST_MAC values.
DEFAULT_SRC_MAC = "02:00:00:00:00:01"
DEFAULT_DST_MAC = "02:00:00:00:00:02"


def build_frame(src_mac, dst_mac, src_ip, dst_ip, proto, dport, vlans=None,
                exts=None):
    """Return a scapy packet: Eth + [Dot1Q]* + IPv6 + [ext-hdr]* + L4.

    We stack layers and let scapy derive every type/length/next-header/checksum
    field rather than hardcoding them — that is the whole point of the scapy
    choice (Q1=A1) and is what keeps the VLAN/QinQ EtherType chain AND the
    extension-header `nh` chain correct.
    """
    pkt = Ether(src=src_mac, dst=dst_mac)
    # First --vlan is the OUTERMOST tag (closest to the MAC headers); stacking
    # two yields QinQ. Matches inject_l4.py's --vlan ordering convention.
    for vid in (vlans or []):
        pkt /= Dot1Q(vlan=vid)
    pkt /= IPv6(src=src_ip, dst=dst_ip)
    # --- S6 SEAM (§5.55, now FILLED): extension headers go between the IPv6
    # base header and the L4 layer. First --ext is CLOSEST to the base header
    # (CLI order = wire order). scapy chains the nh fields automatically.
    for kind in (exts or []):
        pkt /= EXT_HDR[kind]()
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
    parser.add_argument("--ext", action="append", metavar="TYPE",
                        choices=("hbh", "dstopt", "rt", "frag"),
                        help="insert an IPv6 extension header between the base "
                             "header and L4; repeat to build a chain; first "
                             "--ext is closest to the base header (§5.55 S6)")
    parser.add_argument("--truncate", type=int, default=0, metavar="N",
                        help="drop the trailing N bytes of the fully-built frame "
                             "and send the raw L2 bytes verbatim (exercises the "
                             "mid-walk bounds-miss MALFORMED path; default 0)")
    args = parser.parse_args()

    pkt = build_frame(args.src_mac, args.dst_mac,
                      args.src_ip, args.dst_ip,
                      args.proto, args.dport, args.vlan, args.ext)

    if args.truncate > 0:
        # Serialize then trim the trailing N bytes; send the raw frame verbatim
        # so the on-wire bytes are exactly the truncated chain (NEVER let scapy
        # re-derive lengths/checksums from the trimmed buffer). Raw(load=...) is
        # the full Ethernet frame already, so sendp puts these exact bytes out.
        raw = bytes(pkt)[: -args.truncate]
        sendp(Raw(load=raw), iface=args.iface, count=1, verbose=False)
        return 0

    # count=1: exactly one packet so counter-delta assertions are exact.
    sendp(pkt, iface=args.iface, count=1, verbose=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
