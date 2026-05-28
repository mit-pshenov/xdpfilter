#!/usr/bin/env python3
"""
bitvec_oracle.py — independent reference classifier for the MVP-4.2
bit-vector AND-classification spike (design §5.42).

THIS FILE IS THE TESTER-OWNED ORACLE. It is deliberately a *naive O(N)
first-match scan* — there is NO bitmask, NO prefix-closure, NO ffsll, NO
range table. Its whole reason to exist is to be algorithmically DIFFERENT
from the structure-under-test (`tests/bitvec/bitvec_proto.bpf.c` +
`bitvec_harness`), so that any disagreement localises a closure / wildcard
/ range bug in the datapath.

The 12-rule canonical set below is transcribed by hand from the §5.42
"Canonical rule-set (the exact 12 rules — SOURCE OF TRUTH)" table. It is
NOT read from impl's `canonical_ruleset.inc` — independence of DATA
transcription is intentional (per D-mvp-4.2-CANONICAL: divergent
transcriptions make the agreement test fail loudly, which is the point).

Semantics (§5.42 "Oracle semantics"):
  input = (dst_ip, src_ip, proto, dport)
  for each rule in ASCENDING id:
      rule matches iff for EVERY axis the rule CONSTRAINS, the packet
      field satisfies it:
        - dst / src : IP ∈ CIDR
        - proto     : proto == rule.proto
        - dport     : rule.lo <= dport <= rule.hi  (inclusive)
      a wildcard (`*`) axis is satisfied unconditionally.
      An ICMP packet has NO L4 port ⇒ a rule that CONSTRAINS the port
      axis can NEVER match an ICMP packet (only port-wildcard rules can).
  return the FIRST (lowest id) matching rule, else NOMATCH.

Output: prints a single integer to stdout — the matched rule id, or
NOMATCH (= XDPMF_ALLOWLIST_MAX = 64) if nothing matches.

Usage:
    bitvec_oracle.py --dst-ip A --src-ip B --proto {tcp,udp,icmp} --dport N

(`--vlan` is accepted-and-ignored: VLAN tags do not affect L3/L4
classification, they are only an injector-side framing concern.)
"""
import argparse
import socket
import struct
import sys

# §5.42 DataStructures: BITVEC_NOMATCH = XDPMF_ALLOWLIST_MAX = 64.
NOMATCH = 64

# proto name → IP protocol number (§5.42 canonical-set legend:
# TCP=6, UDP=17, ICMP=1).
PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1}
ICMP = 1

# Wildcard sentinel for an axis the rule does not constrain.
W = None


def _cidr(s):
    """Parse 'a.b.c.d/len' → (network_int, prefixlen)."""
    addr, length = s.split("/")
    length = int(length)
    net = struct.unpack("!I", socket.inet_aton(addr))[0]
    return (net, length)


# ── The 12-rule canonical set (SOURCE OF TRUTH, §5.42 table) ──────────────
# Each rule: (id, dst_cidr|W, src_cidr|W, proto|W, port(lo,hi)|W, action).
# action is documentation-only here (the observable is the matched id;
# the action falls out of bv_action — see D-mvp-4.2-OBSERVABLE).
RULES = [
    # id  dst-IP              src-IP                proto port          action
    (0,  _cidr("10.1.2.0/24"),    W,                       6,    (1000, 2000), "DROP"),
    (1,  _cidr("10.1.0.0/16"),    W,                       6,    W,            "PASS"),
    (2,  _cidr("10.0.0.0/8"),     W,                       W,    W,            "PASS"),
    (3,  _cidr("192.168.1.0/24"), W,                       17,   (53, 53),     "DROP"),
    (4,  _cidr("192.168.0.0/16"), _cidr("172.16.0.0/12"),  17,   (53, 53),     "PASS"),
    (5,  W,                       _cidr("10.5.0.0/16"),    6,    (443, 443),   "DROP"),
    (6,  _cidr("203.0.113.0/24"), W,                       W,    (8080, 8090), "PASS"),
    (7,  W,                       W,                       1,    W,            "PASS"),
    (8,  _cidr("10.1.2.128/25"),  W,                       6,    (1000, 2000), "PASS"),
    (9,  _cidr("198.51.100.0/24"),_cidr("198.51.100.0/24"),6,    (22, 22),     "PASS"),
    (10, _cidr("10.2.0.0/16"),    W,                       17,   (5000, 6000), "DROP"),
    (11, W,                       W,                       W,    (9999, 9999), "PASS"),
]


def _ip_to_int(s):
    return struct.unpack("!I", socket.inet_aton(s))[0]


def _ip_in_cidr(ip_int, cidr):
    net, length = cidr
    if length == 0:
        return True
    mask = (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF
    return (ip_int & mask) == (net & mask)


def classify(dst_ip, src_ip, proto, dport):
    """Return the lowest matching rule id, or NOMATCH.

    proto is an IP protocol number. dport is the L4 dest port, or None
    when the packet has no L4 port (ICMP).
    """
    dst_i = _ip_to_int(dst_ip)
    src_i = _ip_to_int(src_ip)
    has_port = dport is not None and proto != ICMP

    for (rid, dst_c, src_c, p, port, _action) in RULES:
        # dst axis
        if dst_c is not W and not _ip_in_cidr(dst_i, dst_c):
            continue
        # src axis
        if src_c is not W and not _ip_in_cidr(src_i, src_c):
            continue
        # proto axis (exact)
        if p is not W and proto != p:
            continue
        # port axis (inclusive range). A constrained-port rule cannot
        # match a packet that has no L4 port (ICMP).
        if port is not W:
            if not has_port:
                continue
            lo, hi = port
            if not (lo <= dport <= hi):
                continue
        # all constrained axes satisfied → first match wins (ascending id)
        return rid
    return NOMATCH


def _proto_arg(s):
    s = s.lower()
    if s in PROTO_NUM:
        return PROTO_NUM[s]
    try:
        return int(s, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"proto must be one of tcp/udp/icmp or a number, got {s!r}")


def main():
    ap = argparse.ArgumentParser(
        prog="bitvec_oracle.py",
        description="independent first-match reference classifier (§5.42)")
    ap.add_argument("--dst-ip", required=True)
    ap.add_argument("--src-ip", required=True)
    ap.add_argument("--proto", required=True, type=_proto_arg)
    ap.add_argument("--dport", type=int, default=0)
    # accepted-and-ignored: VLAN framing does not change L3/L4 match.
    ap.add_argument("--vlan", action="append", metavar="VID")
    args = ap.parse_args()

    dport = None if args.proto == ICMP else args.dport
    print(classify(args.dst_ip, args.src_ip, args.proto, dport))
    return 0


if __name__ == "__main__":
    sys.exit(main())
