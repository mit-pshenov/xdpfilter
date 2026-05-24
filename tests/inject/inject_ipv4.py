#!/usr/bin/env python3
"""
inject_ipv4.py — send one well-formed IPv4 Ethernet frame on the named iface.

Usage:
    sudo python3 inject_ipv4.py <iface> <src_mac> <dst_mac> <src_ip> [dst_ip]

Builds a 60-byte Ethernet frame with EtherType 0x0800 (IPv4) carrying a
20-byte IPv4 header (proto=17 / UDP, payload size 0 — purely a parseable
IP header for the BPF datapath's CIDR-axis lookup). The IPv4 src_ip is
the load-bearing field — BPF's LPM_TRIE lookup matches on src_ip in
network byte order.

If dst_ip is omitted, defaults to 192.0.2.1 (TEST-NET-1; RFC 5737; safe
benign destination for arbitrary-egress contracts).

The frame is sent via a raw AF_PACKET socket (no scapy IP-stack
manipulation) so the BPF program receives EXACTLY the bytes we built —
the kernel does not rewrite the IPv4 header on AF_PACKET egress.
"""
import socket
import struct
import sys


def mac_to_bytes(s: str) -> bytes:
    return bytes(int(b, 16) for b in s.split(":"))


def ipv4_to_bytes(s: str) -> bytes:
    return socket.inet_aton(s)


def ip_checksum(header: bytes) -> int:
    """RFC 1071 16-bit ones-complement of ones-complement sum."""
    if len(header) % 2:
        header += b"\x00"
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) | header[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_ipv4_frame(src_mac: bytes, dst_mac: bytes,
                     src_ip: bytes, dst_ip: bytes) -> bytes:
    # IPv4 header (20 bytes, no options): version=4, IHL=5, TOS=0,
    # total_length=20+26=46 (so frame = 14+46 = 60, min Ethernet),
    # id=0, flags=DF, frag_off=0, TTL=64, proto=17 (UDP, but we have
    # zero payload — irrelevant for the XDP CIDR-axis test), checksum=0,
    # src_ip, dst_ip.
    payload_len = 26
    total_len = 20 + payload_len
    ver_ihl = (4 << 4) | 5
    tos = 0
    ident = 0
    flags_frag = 0x4000  # DF
    ttl = 64
    proto = 17           # UDP — doesn't matter; LPM_TRIE only reads src_ip
    csum = 0
    iphdr = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ident, flags_frag,
        ttl, proto, csum, src_ip, dst_ip,
    )
    csum = ip_checksum(iphdr)
    iphdr = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, tos, total_len, ident, flags_frag,
        ttl, proto, csum, src_ip, dst_ip,
    )
    ethertype = (0x0800).to_bytes(2, "big")  # IPv4
    payload = b"\x00" * payload_len
    return dst_mac + src_mac + ethertype + iphdr + payload


def main() -> int:
    if len(sys.argv) not in (5, 6):
        print("usage: inject_ipv4.py <iface> <src_mac> <dst_mac> "
              "<src_ip> [dst_ip]", file=sys.stderr)
        return 1
    iface, src_mac_s, dst_mac_s, src_ip_s = sys.argv[1:5]
    dst_ip_s = sys.argv[5] if len(sys.argv) == 6 else "192.0.2.1"

    src_mac = mac_to_bytes(src_mac_s)
    dst_mac = mac_to_bytes(dst_mac_s)
    src_ip = ipv4_to_bytes(src_ip_s)
    dst_ip = ipv4_to_bytes(dst_ip_s)
    frame = build_ipv4_frame(src_mac, dst_mac, src_ip, dst_ip)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(0x0800))
    try:
        sock.bind((iface, 0))
        sock.send(frame)
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
