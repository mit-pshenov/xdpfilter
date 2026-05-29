#!/usr/bin/env python3
"""
bitvec_oracle_prod.py — independent reference classifier for the PRODUCTION
bit-vector AND classifier. Originally the MVP-4.3 2-axis oracle (design §5.43,
dst_cidr + src_cidr); EXTENDED in MVP-4.4 (§5.44) to a 4-axis oracle
(dst_cidr + src_cidr + protocol + dst_port); EXTENDED in MVP-4.5 (§5.45) to a
5-axis oracle (+ vlan, exact-membership).

THIS FILE IS THE TESTER-OWNED ORACLE. It is deliberately a *naive O(N)
first-match scan* — there is NO bitmask, NO prefix-closure, NO ffsll, NO
wildcard map, NO range table. Its whole reason to exist is to be
algorithmically DIFFERENT from the production datapath under test
(`src/bpf/mac_filter.bpf.c`'s bit-vector AND compose + `port_scan` + proto
HASH + vlan HASH + `loader.cpp`'s `close_prefixes()`), so that any disagreement
localises a closure / wildcard / range / vlan-capture / first-match bug in the
datapath rather than masking it (§5.43 §6.61, §5.44 §6.66, §5.45 §6.69).

THREE independent rule tables (multi-table — all transcribed BY HAND from their
respective fixtures; NOT parsed from YAML, per the §5.42 D-mvp-4.2-CANONICAL
independence precedent):

  * RULES       (2-axis) — transcribed from tests/fixtures/config_valid_and.yaml.
                Consumed by §6.61 (T_AND_ORACLE_AGREEMENT), invoked with
                --dst-ip/--src-ip only (default --ruleset and). UNCHANGED from
                MVP-4.3 so §6.61 stays byte-behaviour-identical (§5.44
                additive-within-v2: existing v2 corpus GREEN, zero conversions).
  * RULES_AND4  (4-axis) — transcribed from tests/fixtures/config_valid_and4.yaml.
                Consumed by §6.66 (T_AND4_ORACLE_AGREEMENT), invoked with
                --ruleset and4 --proto P --dport N. UNCHANGED from MVP-4.4 so
                §6.66 stays byte-behaviour-identical.
  * RULES_AND5  (5-axis) — transcribed from tests/fixtures/config_valid_and5.yaml.
                Consumed by §6.69 (T_AND5_ORACLE_AGREEMENT), invoked with
                --ruleset and5 --proto P --dport N [--vlan V].
  * RULES_AND6  (6-axis) — transcribed from tests/fixtures/config_valid_and6.yaml.
                Consumed by §6.70 (T_AND6_ORACLE_AGREEMENT), invoked with
                --ruleset and6 --proto P --dport N [--vlan V] --src-mac M.
                Adds the §5.47 MAC axis (src-MAC exact membership; NO closure).

If you edit any fixture you MUST edit the matching table here.

Semantics (§5.43 §6.61 / §5.44 §6.66 / §5.45 §6.69 / DataStructures):
  input = (dst_ip, src_ip[, proto, dport, vlan])
  for each rule in ASCENDING id:
      rule matches iff for EVERY axis the rule CONSTRAINS, the packet
      field satisfies it:
        - dst_cidr  : dst_ip ∈ CIDR
        - src_cidr  : src_ip ∈ CIDR
        - protocol  : proto == rule.proto                 (exact)
        - dst_port  : rule.lo <= dport <= rule.hi         (inclusive)
        - vlan      : vlan == rule.vlan                   (exact membership)
        - mac       : src_mac == rule.mac                 (exact membership)
      a wildcard (unconstrained) axis is satisfied unconditionally.
      An ICMP packet has NO L4 port (has_port=0) ⇒ a rule that CONSTRAINS
      the port axis can NEVER match it (only port-wildcard rules can).
      An UNTAGGED frame has NO vlan (has_vlan=0) ⇒ a rule that CONSTRAINS
      the vlan axis can NEVER match it (only vlan-wildcard rules can).
  return the FIRST (lowest id) matching rule, else NOMATCH.

This is the OR→AND contract: a rule constraining N axes matches ONLY when
ALL N are satisfied (under the retired OR model a single-axis match would
have hit — see §6.60/§6.64).

Output: prints a single integer to stdout — the matched rule id, or
NOMATCH (= XDPMF_ALLOWLIST_MAX = 64) if nothing matches.

Usage:
    bitvec_oracle_prod.py --dst-ip A --src-ip B                       # 2-axis (§6.61)
    bitvec_oracle_prod.py --ruleset and4 --dst-ip A --src-ip B \\
                          --proto {tcp,udp,icmp,N} --dport N          # 4-axis (§6.66)
    bitvec_oracle_prod.py --ruleset and5 --dst-ip A --src-ip B \\
                          --proto {tcp,udp,icmp,N} --dport N [--vlan V]  # 5-axis (§6.69)
"""
import argparse
import socket
import struct
import sys

# §5.43 DataStructures: id ∈ [0, XDPMF_ALLOWLIST_MAX-1=63]; NOMATCH = 64.
NOMATCH = 64

# proto name → IP protocol number (§5.44 D-mvp-4.4-PROTO-GRAMMAR: tcp=6,
# udp=17, icmp=1).
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


# ── 2-axis table: transcribed by hand from config_valid_and.yaml (§5.43) ──
# Each rule: (id, dst_cidr|W, src_cidr|W, action).
# `action` is documentation-only — the observable is the matched id.
RULES = [
    # id  dst_cidr                  src_cidr                  action
    (0,  _cidr("10.1.0.0/16"),     _cidr("192.168.5.0/24"),  "pass"),  # full AND
    (1,  _cidr("10.3.0.0/16"),     W,                        "pass"),  # dst-only
    (2,  W,                        _cidr("10.9.0.0/16"),     "drop"),  # src-only
    (4,  _cidr("10.3.5.0/24"),     W,                        "drop"),  # overlaps id1
]

# ── 4-axis table: transcribed by hand from config_valid_and4.yaml (§5.44) ──
# Each rule: (id, dst_cidr|W, src_cidr|W, proto|W, port(lo,hi)|W, action).
RULES_AND4 = [
    # id  dst_cidr                  src_cidr                  proto port           action
    (0,  _cidr("10.1.0.0/16"),     _cidr("192.168.5.0/24"),  6,    (1000, 2000),  "pass"),  # FULL 4-axis
    (1,  _cidr("10.3.0.0/16"),     W,                        17,   W,             "pass"),  # dst + proto
    (2,  W,                        _cidr("10.9.0.0/16"),     W,    W,             "drop"),  # src-only
    (3,  _cidr("10.7.0.0/16"),     W,                        W,    W,             "pass"),  # dst-only (port-wildcard)
    (4,  W,                        W,                        W,    (443, 443),    "pass"),  # port-only single
    (5,  W,                        W,                        W,    (1000, 2000),  "pass"),  # port-only range
]

# ── 5-axis table: transcribed by hand from config_valid_and5.yaml (§5.45) ──
# Each rule: (id, dst_cidr|W, src_cidr|W, proto|W, port(lo,hi)|W, vlan|W, action).
# `vlan` is an exact VID (membership); W = vlan-wildcard (unconstrained).
RULES_AND5 = [
    # id  dst_cidr                  src_cidr                  proto port           vlan  action
    (0,  _cidr("10.1.0.0/16"),     _cidr("192.168.5.0/24"),  6,    (1000, 2000),  100,  "pass"),  # FULL 5-axis
    (1,  W,                        W,                        17,   W,             200,  "pass"),  # vlan + proto
    (2,  W,                        W,                        W,    W,             300,  "pass"),  # vlan-only
    (3,  _cidr("10.5.0.0/16"),     W,                        W,    W,             100,  "pass"),  # dst + vlan
    (4,  _cidr("10.5.0.0/16"),     W,                        W,    W,             W,    "pass"),  # dst-only (vlan-wildcard)
    (5,  W,                        W,                        W,    (443, 443),    W,    "pass"),  # port-only (vlan-wildcard)
]


# ── 6-axis table: transcribed by hand from config_valid_and6.yaml (§5.47) ──
# Each rule: (id, dst_cidr|W, src_cidr|W, proto|W, port(lo,hi)|W, vlan|W,
#            mac|W, action). `mac` is the canonical lowercase 17-char src-MAC
# (exact membership); W = mac-wildcard (unconstrained).
RULES_AND6 = [
    # id  dst_cidr                  src_cidr                  proto port           vlan  mac                  action
    (0,  _cidr("10.1.0.0/16"),     _cidr("192.168.5.0/24"),  6,    (1000, 2000),  100,  "aa:bb:cc:dd:ee:01", "pass"),  # FULL 6-axis
    (1,  W,                        W,                        17,   W,             200,  "aa:bb:cc:dd:ee:02", "pass"),  # mac + vlan + proto
    (2,  W,                        W,                        W,    W,             300,  W,                   "pass"),  # vlan-only (mac-wild)
    (3,  _cidr("10.5.0.0/16"),     W,                        W,    W,             100,  W,                   "pass"),  # dst + vlan (mac-wild)
    (4,  _cidr("10.5.0.0/16"),     W,                        W,    W,             W,    W,                   "pass"),  # dst-only (mac/vlan-wild)
    (5,  W,                        W,                        W,    (443, 443),    W,    W,                   "pass"),  # port-only (mac-wild)
    (6,  W,                        W,                        W,    W,             W,    "aa:bb:cc:dd:ee:06", "pass"),  # mac-only (5 axes wild)
]


def _norm_mac(s):
    """Normalize a MAC to lowercase canonical for exact comparison."""
    return s.lower() if s is not None else None


def _ip_to_int(s):
    return struct.unpack("!I", socket.inet_aton(s))[0]


def _ip_in_cidr(ip_int, cidr):
    net, length = cidr
    if length == 0:
        return True
    mask = (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF
    return (ip_int & mask) == (net & mask)


def classify(dst_ip, src_ip):
    """2-axis (dst+src) first-match — UNCHANGED from MVP-4.3 (§6.61)."""
    dst_i = _ip_to_int(dst_ip)
    src_i = _ip_to_int(src_ip)
    for (rid, dst_c, src_c, _action) in RULES:
        # dst axis
        if dst_c is not W and not _ip_in_cidr(dst_i, dst_c):
            continue
        # src axis
        if src_c is not W and not _ip_in_cidr(src_i, src_c):
            continue
        # all constrained axes satisfied → first match wins (ascending id)
        return rid
    return NOMATCH


def classify4(dst_ip, src_ip, proto, dport):
    """4-axis (dst+src+proto+port) first-match (§5.44 §6.66).

    proto is an IP protocol number. dport is the L4 dest port, or None when
    the packet has no L4 port (ICMP → has_port=0).
    """
    dst_i = _ip_to_int(dst_ip)
    src_i = _ip_to_int(src_ip)
    has_port = dport is not None and proto != ICMP

    for (rid, dst_c, src_c, p, port, _action) in RULES_AND4:
        # dst axis
        if dst_c is not W and not _ip_in_cidr(dst_i, dst_c):
            continue
        # src axis
        if src_c is not W and not _ip_in_cidr(src_i, src_c):
            continue
        # proto axis (exact)
        if p is not W and proto != p:
            continue
        # port axis (inclusive range). A constrained-port rule cannot match a
        # packet that has no L4 port (ICMP → has_port=0).
        if port is not W:
            if not has_port:
                continue
            lo, hi = port
            if not (lo <= dport <= hi):
                continue
        # all constrained axes satisfied → first match wins (ascending id)
        return rid
    return NOMATCH


def classify5(dst_ip, src_ip, proto, dport, vlan):
    """5-axis (dst+src+proto+port+vlan) first-match (§5.45 §6.69).

    proto is an IP protocol number. dport is the L4 dest port, or None when
    the packet has no L4 port (ICMP → has_port=0). vlan is the outer 802.1Q
    VID, or None when the frame is untagged (has_vlan=0).
    """
    dst_i = _ip_to_int(dst_ip)
    src_i = _ip_to_int(src_ip)
    has_port = dport is not None and proto != ICMP
    has_vlan = vlan is not None

    for (rid, dst_c, src_c, p, port, vl, _action) in RULES_AND5:
        # dst axis
        if dst_c is not W and not _ip_in_cidr(dst_i, dst_c):
            continue
        # src axis
        if src_c is not W and not _ip_in_cidr(src_i, src_c):
            continue
        # proto axis (exact)
        if p is not W and proto != p:
            continue
        # port axis (inclusive range). A constrained-port rule cannot match a
        # packet that has no L4 port (ICMP → has_port=0).
        if port is not W:
            if not has_port:
                continue
            lo, hi = port
            if not (lo <= dport <= hi):
                continue
        # vlan axis (exact membership). A constrained-vlan rule cannot match an
        # UNTAGGED frame (has_vlan=0) — only vlan-wildcard rules survive.
        if vl is not W:
            if not has_vlan:
                continue
            if vlan != vl:
                continue
        # all constrained axes satisfied → first match wins (ascending id)
        return rid
    return NOMATCH


def classify6(dst_ip, src_ip, proto, dport, vlan, src_mac):
    """6-axis (dst+src+proto+port+vlan+mac) first-match (§5.47 §6.70).

    proto is an IP protocol number. dport is the L4 dest port, or None when the
    packet has no L4 port (ICMP → has_port=0). vlan is the outer 802.1Q VID, or
    None when untagged (has_vlan=0). src_mac is the source MAC (every frame has
    one → no "absent" sentinel); a mac-constrained rule matches iff the src_mac
    equals it EXACTLY (no closure). MAC is composed inside the IPv4 gate, so this
    classifier is only meaningful for IPv4 frames (D-mvp-4.7-Q2-GATE).
    """
    dst_i = _ip_to_int(dst_ip)
    src_i = _ip_to_int(src_ip)
    has_port = dport is not None and proto != ICMP
    has_vlan = vlan is not None
    mac_n = _norm_mac(src_mac)

    for (rid, dst_c, src_c, p, port, vl, mac, _action) in RULES_AND6:
        # dst axis
        if dst_c is not W and not _ip_in_cidr(dst_i, dst_c):
            continue
        # src axis
        if src_c is not W and not _ip_in_cidr(src_i, src_c):
            continue
        # proto axis (exact)
        if p is not W and proto != p:
            continue
        # port axis (inclusive range; ICMP has no L4 port)
        if port is not W:
            if not has_port:
                continue
            lo, hi = port
            if not (lo <= dport <= hi):
                continue
        # vlan axis (exact membership; untagged cannot match a vlan rule)
        if vl is not W:
            if not has_vlan:
                continue
            if vlan != vl:
                continue
        # mac axis (exact membership; src-MAC h_source)
        if mac is not W and mac_n != _norm_mac(mac):
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
        prog="bitvec_oracle_prod.py",
        description="independent production AND first-match classifier "
                    "(§5.43 2-axis / §5.44 4-axis / §5.45 5-axis)")
    ap.add_argument("--ruleset", choices=("and", "and4", "and5", "and6"),
                    default="and",
                    help="and = 2-axis (config_valid_and.yaml, §6.61); "
                         "and4 = 4-axis (config_valid_and4.yaml, §6.66); "
                         "and5 = 5-axis (config_valid_and5.yaml, §6.69); "
                         "and6 = 6-axis (config_valid_and6.yaml, §6.70)")
    ap.add_argument("--dst-ip", required=True)
    ap.add_argument("--src-ip", required=True)
    ap.add_argument("--proto", type=_proto_arg,
                    help="IP protocol (tcp/udp/icmp or number); and4/and5/and6 only")
    ap.add_argument("--dport", type=int, default=0,
                    help="L4 dest port; and4/and5/and6 only (ignored for icmp)")
    ap.add_argument("--vlan", type=int, default=None,
                    help="outer 802.1Q VID; and5/and6 only (omit ⇒ untagged frame, "
                         "has_vlan=0)")
    ap.add_argument("--src-mac", default=None,
                    help="source MAC (eth->h_source); and6 only (exact match)")
    args = ap.parse_args()

    if args.ruleset == "and6":
        if args.proto is None:
            ap.error("--ruleset and6 requires --proto")
        if args.src_mac is None:
            ap.error("--ruleset and6 requires --src-mac")
        dport = None if args.proto == ICMP else args.dport
        print(classify6(args.dst_ip, args.src_ip, args.proto, dport, args.vlan,
                        args.src_mac))
    elif args.ruleset == "and5":
        if args.proto is None:
            ap.error("--ruleset and5 requires --proto")
        dport = None if args.proto == ICMP else args.dport
        print(classify5(args.dst_ip, args.src_ip, args.proto, dport, args.vlan))
    elif args.ruleset == "and4":
        if args.proto is None:
            ap.error("--ruleset and4 requires --proto")
        dport = None if args.proto == ICMP else args.dport
        print(classify4(args.dst_ip, args.src_ip, args.proto, dport))
    else:
        # 2-axis default — §6.61 invokes with --dst-ip/--src-ip only.
        print(classify(args.dst_ip, args.src_ip))
    return 0


if __name__ == "__main__":
    sys.exit(main())
