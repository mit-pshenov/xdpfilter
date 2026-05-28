#!/usr/bin/env python3
"""
inject_l4.py — MVP-4.2 §5.42 raw L4 frame injector for the bit-vector spike.

Builds ONE Eth + [VLAN]* + IPv4 + {TCP|UDP|ICMP} frame and sends it via a raw
AF_PACKET socket (count=1) so the prototype XDP datapath receives EXACTLY the
bytes built — the kernel does not rewrite the IPv4/L4 headers on AF_PACKET
egress. Mirrors the §5.41 inject_ipv4.py socket setup + VLAN tag insertion;
inject_ipv4.py is NOT edited (separate file per the §5.42 FileList).

Usage:
    sudo python3 inject_l4.py <iface> \
        --dst-ip A --src-ip B --proto {tcp,udp,icmp} --dport N \
        [--src-mac M] [--dst-mac M] [--vlan VID]...

The prototype has NO MAC axis (MAC is irrelevant to the bit-vector
classification under test); --src-mac/--dst-mac default to fixed
non-allowlisted constants and exist only so the frame is well-formed.

--vlan is repeatable; the FIRST --vlan is the OUTERMOST tag (closest to the
MAC headers), stacking two yields a QinQ frame (TPID 0x8100, matching
inject_ipv4.py's C-TAG convention).

For --proto icmp the IPv4 protocol is 1 and an 8-byte ICMP echo header is
emitted; --dport is ignored at the wire level (ICMP has no L4 port), which is
exactly the spike's "ICMP → only port-wildcard rules survive" case.
"""
import argparse
import socket
import struct
import sys

VLAN_TPID = 0x8100

PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}

# Fixed, deliberately non-meaningful MACs — the prototype has no MAC axis.
DEFAULT_SRC_MAC = "02:00:00:00:00:01"
DEFAULT_DST_MAC = "02:00:00:00:00:02"


def mac_to_bytes(s: str) -> bytes:
    return bytes(int(b, 16) for b in s.split(":"))


def ipv4_to_bytes(s: str) -> bytes:
    return socket.inet_aton(s)


def checksum16(data: bytes) -> int:
    """RFC 1071 16-bit ones-complement of ones-complement sum."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_l4(proto: str, dport: int) -> tuple[int, bytes]:
    """Return (ip_proto_number, l4_bytes) for the requested L4 protocol."""
    if proto == "tcp":
        # Minimal 20-byte TCP header; data offset = 5 (<<4 in the offset byte).
        # Only the dest port is load-bearing for the bit-vector port axis.
        sport = 12345
        seq = 0
        ack = 0
        off_flags = (5 << 12) | 0x002  # data offset 5, SYN
        window = 1024
        csum = 0
        urg = 0
        l4 = struct.pack("!HHLLHHHH",
                         sport, dport, seq, ack, off_flags, window, csum, urg)
        return 6, l4
    if proto == "udp":
        sport = 12345
        length = 8  # header only, no payload
        csum = 0
        l4 = struct.pack("!HHHH", sport, dport, length, csum)
        return 17, l4
    # icmp: 8-byte echo-request header; no L4 port (dport unused on the wire).
    icmp_type = 8
    icmp_code = 0
    csum = 0
    ident = 0
    seq = 0
    hdr = struct.pack("!BBHHH", icmp_type, icmp_code, csum, ident, seq)
    csum = checksum16(hdr)
    l4 = struct.pack("!BBHHH", icmp_type, icmp_code, csum, ident, seq)
    return 1, l4


def build_frame(src_mac: bytes, dst_mac: bytes,
                src_ip: bytes, dst_ip: bytes,
                proto: str, dport: int, vlans=None) -> bytes:
    ip_proto, l4 = build_l4(proto, dport)

    total_len = 20 + len(l4)
    ver_ihl = (4 << 4) | 5   # IHL=5 → no IPv4 options (datapath assumes this)
    tos = 0
    ident = 0
    flags_frag = 0x4000      # DF
    ttl = 64
    csum = 0
    iphdr = struct.pack("!BBHHHBBH4s4s",
                        ver_ihl, tos, total_len, ident, flags_frag,
                        ttl, ip_proto, csum, src_ip, dst_ip)
    csum = checksum16(iphdr)
    iphdr = struct.pack("!BBHHHBBH4s4s",
                        ver_ihl, tos, total_len, ident, flags_frag,
                        ttl, ip_proto, csum, src_ip, dst_ip)

    ethertype = (0x0800).to_bytes(2, "big")  # IPv4
    tags = b"".join(struct.pack("!HH", VLAN_TPID, vid) for vid in (vlans or []))
    frame = dst_mac + src_mac + tags + ethertype + iphdr + l4
    # Pad to the 60-byte Ethernet minimum if needed.
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def _vlan_vid(s: str) -> int:
    vid = int(s, 0)
    if not 0 <= vid <= 4095:
        raise argparse.ArgumentTypeError(f"VLAN VID must be 0..4095, got {vid}")
    return vid


def _port(s: str) -> int:
    p = int(s, 0)
    if not 0 <= p <= 65535:
        raise argparse.ArgumentTypeError(f"dport must be 0..65535, got {p}")
    return p


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="inject_l4.py",
        description="send one Eth+[VLAN]*+IPv4+L4 frame on an iface")
    parser.add_argument("iface")
    parser.add_argument("--dst-ip", required=True)
    parser.add_argument("--src-ip", required=True)
    parser.add_argument("--proto", required=True, choices=("tcp", "udp", "icmp"))
    parser.add_argument("--dport", type=_port, default=0)
    parser.add_argument("--src-mac", default=DEFAULT_SRC_MAC)
    parser.add_argument("--dst-mac", default=DEFAULT_DST_MAC)
    parser.add_argument("--vlan", type=_vlan_vid, action="append", metavar="VID",
                        help="insert an 802.1Q tag; repeat for QinQ; "
                             "first --vlan is outermost")
    args = parser.parse_args()

    frame = build_frame(
        mac_to_bytes(args.src_mac), mac_to_bytes(args.dst_mac),
        ipv4_to_bytes(args.src_ip), ipv4_to_bytes(args.dst_ip),
        args.proto, args.dport, args.vlan)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    try:
        sock.bind((args.iface, 0))
        sock.send(frame)
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
