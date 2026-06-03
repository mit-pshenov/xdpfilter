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
(`src/bpf/xdpfilter.bpf.c`'s bit-vector AND compose + `port_scan` + proto
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
# udp=17, icmp=1). §5.53 (MVP-4.13): icmp6=58 (IPv6 ICMP nexthdr) — like
# icmp(v4) it carries NO L4 port (has_port=0).
PROTO_NUM = {"tcp": 6, "udp": 17, "icmp": 1, "icmp6": 58}
ICMP = 1
ICMP6 = 58

# Wildcard sentinel for an axis the rule does not constrain.
W = None


def _cidr(s):
    """Parse 'a.b.c.d/len' → (network_int, prefixlen)."""
    addr, length = s.split("/")
    length = int(length)
    net = struct.unpack("!I", socket.inet_aton(addr))[0]
    return (net, length)


# ── §5.53 (MVP-4.13) IPv6 128-bit helpers (defined here so the RULES_ANDV6
# table below can call _cidr6 at module-load, mirroring _cidr) ─────────────
# GUARD #23 masking discipline: the oracle masks in the **128-bit Python
# arbitrary-precision integer domain** (NOT per-byte / per-limb) so that
# non-byte-aligned prefixes (/40, /68, /127) are exercised BY CONSTRUCTION and
# the oracle is algorithmically DIFFERENT from the kernel LPM_TRIE (which walks
# the network-order addr6[16] byte array MSB-first). A datapath byte-order or
# limb-boundary bug surfaces as an oracle disagreement.
_V6_FULL = (1 << 128) - 1


def _ip6_to_int(s):
    """Parse an IPv6 literal → 128-bit big-endian (network-order) integer."""
    return int.from_bytes(socket.inet_pton(socket.AF_INET6, s), "big")


def _cidr6(s):
    """Parse '2001:db8::/len' → (network_int_128, prefixlen)."""
    addr, length = s.rsplit("/", 1)
    length = int(length)
    if not 0 <= length <= 128:
        raise ValueError(f"IPv6 prefixlen out of range [0,128]: {length}")
    return (_ip6_to_int(addr), length)


def _ip6_in_cidr6(ip_int, cidr6):
    """128-bit-domain membership test (guard #23 — NOT per-byte)."""
    net, length = cidr6
    if length == 0:
        return True
    mask = (_V6_FULL << (128 - length)) & _V6_FULL
    return (ip_int & mask) == (net & mask)


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


# ── mac-MERGE canary table: by hand from config_valid_macmerge.yaml (§5.50) ──
# Same 7-tuple shape as RULES_AND6. ids 0 & 1 SHARE src-MAC ee:01 (different
# proto) → the datapath's mac-axis lowering must MERGE them into one inner-HASH
# entry with both bits; this naive first-match oracle models NO merge (it just
# scans ascending id), so it is the independent reference. id2 has a DISTINCT
# mac (must NOT collide). Consumed by T_MAC_MERGE_ORACLE_AGREEMENT
# (--ruleset macmerge --proto P --src-mac M).
RULES_MACMERGE = [
    # id  dst_cidr  src_cidr  proto port  vlan  mac                  action
    (0,  W,        W,        6,    W,    W,    "aa:bb:cc:dd:ee:01", "pass"),  # mac ee:01 + tcp
    (1,  W,        W,        17,   W,    W,    "aa:bb:cc:dd:ee:01", "pass"),  # mac ee:01 + udp (SHARES mac → merge)
    (2,  W,        W,        W,    W,    W,    "aa:bb:cc:dd:ee:02", "pass"),  # mac ee:02 (distinct)
]


# ── 8-axis v6 table: by hand from config_valid_andv6.yaml (§5.53 §6.71) ────
# Each rule: (id, dst_cidr|W, src_cidr|W, proto|W, port(lo,hi)|W, vlan|W,
#            mac|W, dst_cidr6|W, src_cidr6|W, action). The two NEW axes are the
# v6 sibling LPM axes dst_cidr6 (BV_AXIS_DST6=6, matches ip6->daddr) and
# src_cidr6 (BV_AXIS_SRC6=7, matches ip6->saddr). SYMMETRIC 8-term AND
# (D-mvp-4.13-Q2): a v4 frame carries NO v6 address (the dst6/src6 axes are
# unsatisfiable for any rule that CONSTRAINS them) and vice-versa — this models
# the cross-family exclusion exactly (a v4-only rule cannot match a v6 frame and
# a v6-only rule cannot match a v4 frame).
#
# Consumed by §6.71 (T_ANDV6_ORACLE_AGREEMENT), invoked
#   --ruleset andv6 --dst-ip6 D --src-ip6 S --proto P [--dport N] [--vlan V]
# for v6 frames (and --dst-ip/--src-ip for the v4-frame cross-family probe).
#
# IMPORTANT: tests/fixtures/config_valid_andv6.yaml transcribes the SAME rules.
# Any edit here MUST be mirrored there — data-independence is intentional.
RULES_ANDV6 = [
    # id dst_cidr            src_cidr proto port          vlan mac dst_cidr6                  src_cidr6                  action
    (0, W,                   W,       6,    (1000, 2000), 100, W,  _cidr6("2001:db8:1::/48"), _cidr6("2001:db8:5::/48"), "pass"),  # FULL v6 AND
    (1, W,                   W,       W,    W,            W,   W,  _cidr6("2001:db8:2::/48"), W,                         "pass"),  # dst6-only
    (2, _cidr("10.1.0.0/16"), W,      W,    W,            W,   W,  W,                         W,                         "drop"),  # v4-only (cross-family; §6.73 DROP)
    (3, W,                   W,       17,   W,            W,   W,  W,                         W,                         "pass"),  # proto-only (addr-wildcard)
]


# ── 9-axis ethertype table: by hand from config_valid_andeth.yaml (§5.54 §6.74)
# Each rule: (id, dst_cidr|W, src_cidr|W, proto|W, port(lo,hi)|W, vlan|W, mac|W,
#            dst_cidr6|W, src_cidr6|W, ethertype|W, action). The NEW 9th axis is
# `ethertype` (BV_AXIS_ETHERTYPE=8): the host-order post-VLAN inner EtherType,
# EXACT match, NO closure (like proto/vlan/mac).
#
# ethertype is BOTH a normal exact-match axis AND the FAMILY SELECTOR
# (D-mvp-4.14-Q1): a frame's ethertype decides which IP-family axes are even
# evaluable. A non-IP frame (ethertype ∉ {0x0800, 0x86dd}) carries NO L3/L4, so
# the dst/src/proto/port/dst6/src6 axes are UNSATISFIABLE for any rule that
# CONSTRAINS them — exactly mirroring the datapath's wildcard-only IP-family
# halves in the NEW non-IP `else` arm. mac/vlan/ethertype are FAMILY-AGNOSTIC
# (composed in ALL THREE arms — v4, v6, and the new non-IP arm), so a mac/vlan/
# ethertype rule fires on a non-IP frame too (the family-blind property, the
# natural completion of S4's family-blind mac-fires-on-v6).
#
# Consumed by §6.74 (T_ANDETH_ORACLE_AGREEMENT), invoked
#   --ruleset andeth --ethertype E [--dst-ip/--src-ip | --dst-ip6/--src-ip6]
#   [--proto P --dport N] [--vlan V] [--src-mac M]
# The --ethertype value (named ipv4/ipv6/arp, hex, or numeric base-0) is the
# load-bearing discriminator: ipv4→0x0800 = v4 frame (reads --dst-ip/--src-ip/
# --proto), ipv6→0x86dd = v6 frame (reads --dst-ip6/--src-ip6/--proto), anything
# else = non-IP frame (no L3/L4 at all).
#
# IMPORTANT: tests/fixtures/config_valid_andeth.yaml transcribes the SAME rules.
# Any edit here MUST be mirrored there — data-independence is intentional.
ETH_ARP = 0x0806
ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD

RULES_ANDETH = [
    # id dst_cidr             src_cidr proto port vlan mac                  dst6 src6 ethertype action
    (0, W,                    W,       W,    W,   W,   "02:00:00:00:00:11", W,   W,   0x88B5,   "drop"),  # 0x88b5 + mac (combined; non-IP)
    (1, W,                    W,       W,    W,   W,   W,                   W,   W,   0x88B5,   "drop"),  # pure 0x88b5 (non-IP)
    (2, W,                    W,       W,    W,   W,   W,                   W,   W,   0x0806,   "drop"),  # pure arp (non-IP headline)
    (3, _cidr("10.1.0.0/16"), W,       W,    W,   W,   W,                   W,   W,   0x0800,   "pass"),  # ethertype ipv4 + dst_cidr (v4-arm compose)
    (4, W,                    W,       17,   W,   W,   W,                   W,   W,   W,        "pass"),  # proto udp (ethertype-WILDCARD)
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


def classify6(dst_ip, src_ip, proto, dport, vlan, src_mac, rules=RULES_AND6):
    """6-axis (dst+src+proto+port+vlan+mac) first-match (§5.47 §6.70).

    proto is an IP protocol number. dport is the L4 dest port, or None when the
    packet has no L4 port (ICMP → has_port=0). vlan is the outer 802.1Q VID, or
    None when untagged (has_vlan=0). src_mac is the source MAC (every frame has
    one → no "absent" sentinel); a mac-constrained rule matches iff the src_mac
    equals it EXACTLY (no closure). MAC is composed inside the IPv4 gate, so this
    classifier is only meaningful for IPv4 frames (D-mvp-4.7-Q2-GATE).

    `rules` defaults to RULES_AND6; the mac-MERGE canary (§5.50) reuses this same
    naive first-match scan over RULES_MACMERGE (the scan models NO inner-HASH
    merge, so it is the independent reference for the dedup branch).
    """
    dst_i = _ip_to_int(dst_ip)
    src_i = _ip_to_int(src_ip)
    has_port = dport is not None and proto != ICMP
    has_vlan = vlan is not None
    mac_n = _norm_mac(src_mac)

    for (rid, dst_c, src_c, p, port, vl, mac, _action) in rules:
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


def classify_andv6(dst_ip, src_ip, dst_ip6, src_ip6, proto, dport, vlan,
                   src_mac, rules=RULES_ANDV6):
    """8-axis (dst+src+proto+port+vlan+mac+dst6+src6) first-match (§5.53 §6.71).

    SYMMETRIC cross-family model (D-mvp-4.13-Q2): the frame is EITHER IPv4
    (dst_ip/src_ip set, dst_ip6/src_ip6 None) OR IPv6 (the reverse) — exactly
    one family. A rule that CONSTRAINS a v4 address axis can NEVER match a v6
    frame (the frame has no v4 address — the v6 arm's `& wc_dst` term zeroes it);
    symmetrically a v6-constrained rule can never match a v4 frame. This is the
    naive, algorithm-independent reference for the datapath's 8-term AND + the
    cross-family wildcard halves.

    The v6 masking is 128-bit-domain (guard #23) via _ip6_in_cidr6.
    """
    has_v4 = dst_ip is not None and src_ip is not None
    has_v6 = dst_ip6 is not None and src_ip6 is not None
    dst_i = _ip_to_int(dst_ip) if has_v4 else None
    src_i = _ip_to_int(src_ip) if has_v4 else None
    dst6_i = _ip6_to_int(dst_ip6) if has_v6 else None
    src6_i = _ip6_to_int(src_ip6) if has_v6 else None
    has_port = dport is not None and proto not in (ICMP, ICMP6)
    has_vlan = vlan is not None
    mac_n = _norm_mac(src_mac)

    for (rid, dst_c, src_c, p, port, vl, mac, dst_c6, src_c6, _action) in rules:
        # dst axis (IPv4) — a constrained v4 rule cannot match a v6 frame.
        if dst_c is not W:
            if not has_v4 or not _ip_in_cidr(dst_i, dst_c):
                continue
        # src axis (IPv4)
        if src_c is not W:
            if not has_v4 or not _ip_in_cidr(src_i, src_c):
                continue
        # proto axis (exact); for v6 frames proto == ip6->nexthdr
        if p is not W and proto != p:
            continue
        # port axis (inclusive range; icmp/icmp6 have no L4 port)
        if port is not W:
            if not has_port:
                continue
            lo, hi = port
            if not (lo <= dport <= hi):
                continue
        # vlan axis (exact membership; untagged cannot match a vlan rule)
        if vl is not W:
            if not has_vlan or vlan != vl:
                continue
        # mac axis (exact membership; src-MAC h_source)
        if mac is not W and mac_n != _norm_mac(mac):
            continue
        # dst6 axis (IPv6) — a constrained v6 rule cannot match a v4 frame.
        if dst_c6 is not W:
            if not has_v6 or not _ip6_in_cidr6(dst6_i, dst_c6):
                continue
        # src6 axis (IPv6)
        if src_c6 is not W:
            if not has_v6 or not _ip6_in_cidr6(src6_i, src_c6):
                continue
        # all constrained axes satisfied → first match wins (ascending id)
        return rid
    return NOMATCH


def classify_andeth(ethertype, dst_ip, src_ip, dst_ip6, src_ip6, proto, dport,
                    vlan, src_mac, rules=RULES_ANDETH):
    """9-axis (dst+src+proto+port+vlan+mac+dst6+src6+ethertype) first-match
    (§5.54 §6.74).

    ethertype is the host-order EtherType value of the frame AND the family
    selector. From it we derive the frame family:
      * ethertype == 0x0800 → IPv4 frame (reads dst_ip/src_ip/proto/dport).
      * ethertype == 0x86dd → IPv6 frame (reads dst_ip6/src_ip6/proto/dport).
      * anything else        → non-IP frame: NO L3/L4 (proto/port/all addr
                               axes are wildcard-only — a rule constraining any
                               of them can never match, exactly mirroring the
                               datapath's wildcard-only halves in the non-IP arm).

    mac/vlan/ethertype are family-agnostic (evaluated for every frame). This is
    the naive O(N) algorithm-independent reference for the datapath's 9-term AND
    composed across all three dispatch arms.
    """
    has_v4 = ethertype == ETH_IPV4
    has_v6 = ethertype == ETH_IPV6
    dst_i = _ip_to_int(dst_ip) if (has_v4 and dst_ip is not None) else None
    src_i = _ip_to_int(src_ip) if (has_v4 and src_ip is not None) else None
    dst6_i = _ip6_to_int(dst_ip6) if (has_v6 and dst_ip6 is not None) else None
    src6_i = _ip6_to_int(src_ip6) if (has_v6 and src_ip6 is not None) else None
    # proto/port exist ONLY for an IP frame; a non-IP frame has neither.
    eff_proto = proto if (has_v4 or has_v6) else None
    has_port = (eff_proto is not None and dport is not None
                and eff_proto not in (ICMP, ICMP6))
    has_vlan = vlan is not None
    mac_n = _norm_mac(src_mac)

    for (rid, dst_c, src_c, p, port, vl, mac, dst_c6, src_c6, eth, _action) \
            in rules:
        # ethertype axis (exact; the family selector). Wildcard matches any.
        if eth is not W and ethertype != eth:
            continue
        # dst axis (IPv4) — a v4-constrained rule cannot match a non-v4 frame.
        if dst_c is not W:
            if not has_v4 or not _ip_in_cidr(dst_i, dst_c):
                continue
        # src axis (IPv4)
        if src_c is not W:
            if not has_v4 or not _ip_in_cidr(src_i, src_c):
                continue
        # proto axis (exact); a non-IP frame has no proto.
        if p is not W:
            if eff_proto is None or eff_proto != p:
                continue
        # port axis (inclusive range; icmp/icmp6/non-IP have no L4 port)
        if port is not W:
            if not has_port:
                continue
            lo, hi = port
            if not (lo <= dport <= hi):
                continue
        # vlan axis (exact membership; untagged cannot match a vlan rule)
        if vl is not W:
            if not has_vlan or vlan != vl:
                continue
        # mac axis (exact membership; src-MAC h_source; family-agnostic)
        if mac is not W and mac_n != _norm_mac(mac):
            continue
        # dst6 axis (IPv6) — a v6-constrained rule cannot match a non-v6 frame.
        if dst_c6 is not W:
            if not has_v6 or not _ip6_in_cidr6(dst6_i, dst_c6):
                continue
        # src6 axis (IPv6)
        if src_c6 is not W:
            if not has_v6 or not _ip6_in_cidr6(src6_i, src_c6):
                continue
        # all constrained axes satisfied → first match wins (ascending id)
        return rid
    return NOMATCH


# ── andext ruleset: by hand from tests/fixtures/andext.yaml (§5.55 / S6) ──────
# Each rule: same 9-tuple shape as RULES_ANDV6 (dst_cidr|W, src_cidr|W, proto|W,
# port(lo,hi)|W, vlan|W, mac|W, dst_cidr6|W, src_cidr6|W, action) — andext reuses
# the v6 classifier (classify_andv6) because the slice changes NOTHING about the
# match model: it only changes how the datapath READS proto/port off a v6 frame
# carrying an extension-header chain.
#
# THE ORACLE IS WALK-TRANSPARENT (the load-bearing detectability property,
# §5.55 / VA-5): ext-headers are INVISIBLE to this oracle. It keys on the TRUE
# upper-layer protocol + L4 port the test injects via --proto/--dport — i.e. the
# value the datapath must reach by WALKING the chain. The oracle NEVER parses an
# ext chain; it asserts the OUTCOME the walk must produce. So for an ext-bearing
# frame the oracle predicts the true-L4 verdict (id0=drop for tcp/443) while a
# datapath that did NOT walk computes proto=HOPOPTS(0) and predicts NOMATCH —
# the disagreement is exactly the VA-5 trap that makes T_ANDEXT_WALK_STEER RED on
# a non-walking / short-walking datapath.
#
# Rule layout (mirrors andext.yaml; default_action: pass ⇒ NOMATCH means PASS):
#   id 0 : protocol tcp AND dst_port 443    DROP   (proto+port; addr/mac/vlan wild)
#
# IMPORTANT: tests/fixtures/andext.yaml transcribes the SAME rule. Any edit here
# MUST be mirrored there — data-independence is intentional.
RULES_ANDEXT = [
    # id dst_cidr src_cidr proto port        vlan mac dst_cidr6 src_cidr6 action
    (0, W,       W,       6,    (443, 443), W,   W,  W,        W,        "drop"),  # tcp + dport 443
]


# ethertype name → host-order value (§5.54 D-mvp-4.14-ETH-GRAMMAR).
ETHERTYPE_NUM = {"ipv4": ETH_IPV4, "ipv6": ETH_IPV6, "arp": ETH_ARP}


def _ethertype_arg(s):
    """Parse --ethertype: named (ipv4/ipv6/arp), hex (0x86dd), or decimal."""
    lowered = s.lower()
    if lowered in ETHERTYPE_NUM:
        return ETHERTYPE_NUM[lowered]
    try:
        v = int(s, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"ethertype must be ipv4/ipv6/arp or a number, got {s!r}")
    if not 0 <= v <= 0xFFFF:
        raise argparse.ArgumentTypeError(
            f"ethertype out of range [0,65535]: {v}")
    return v


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
    ap.add_argument("--ruleset",
                    choices=("and", "and4", "and5", "and6", "andv6", "andeth",
                             "andext", "macmerge"),
                    default="and",
                    help="and = 2-axis (config_valid_and.yaml, §6.61); "
                         "and4 = 4-axis (config_valid_and4.yaml, §6.66); "
                         "and5 = 5-axis (config_valid_and5.yaml, §6.69); "
                         "and6 = 6-axis (config_valid_and6.yaml, §6.70); "
                         "andv6 = 8-axis +dst6/src6 (config_valid_andv6.yaml, §6.71); "
                         "andeth = 9-axis +ethertype (config_valid_andeth.yaml, §6.74); "
                         "macmerge = mac-dedup MERGE canary "
                         "(config_valid_macmerge.yaml, §5.50)")
    # §5.53: --dst-ip/--src-ip are now OPTIONAL (a v6 frame carries no v4
    # address); the v4-only rulesets re-require them below.
    ap.add_argument("--dst-ip", default=None)
    ap.add_argument("--src-ip", default=None)
    ap.add_argument("--dst-ip6", default=None,
                    help="IPv6 destination literal; andv6 only (ip6->daddr)")
    ap.add_argument("--src-ip6", default=None,
                    help="IPv6 source literal; andv6 only (ip6->saddr)")
    ap.add_argument("--proto", type=_proto_arg,
                    help="IP protocol (tcp/udp/icmp/icmp6 or number); "
                         "and4/and5/and6/andv6 only")
    ap.add_argument("--dport", type=int, default=0,
                    help="L4 dest port; and4/and5/and6/andv6 only (ignored for icmp)")
    ap.add_argument("--vlan", type=int, default=None,
                    help="outer 802.1Q VID; and5/and6/andv6 only (omit ⇒ untagged "
                         "frame, has_vlan=0)")
    ap.add_argument("--src-mac", default=None,
                    help="source MAC (eth->h_source); and6/andv6/andeth only (exact match)")
    ap.add_argument("--ethertype", type=_ethertype_arg, default=None,
                    help="EtherType (ipv4/ipv6/arp or hex/decimal); andeth only "
                         "(the family selector + exact axis)")
    args = ap.parse_args()

    # The v4-only rulesets require an IPv4 dst+src (the v6 axes don't exist).
    if args.ruleset in ("and", "and4", "and5", "and6", "macmerge"):
        if args.dst_ip is None or args.src_ip is None:
            ap.error(f"--ruleset {args.ruleset} requires --dst-ip and --src-ip")

    if args.ruleset == "andv6":
        if args.proto is None:
            ap.error("--ruleset andv6 requires --proto")
        v4 = args.dst_ip is not None and args.src_ip is not None
        v6 = args.dst_ip6 is not None and args.src_ip6 is not None
        if v4 == v6:
            ap.error("--ruleset andv6 requires EXACTLY ONE family: either "
                     "--dst-ip+--src-ip (v4 frame) OR --dst-ip6+--src-ip6 (v6 frame)")
        dport = None if args.proto in (ICMP, ICMP6) else args.dport
        print(classify_andv6(args.dst_ip, args.src_ip,
                             args.dst_ip6, args.src_ip6,
                             args.proto, dport, args.vlan, args.src_mac))
    elif args.ruleset == "andext":
        # §5.55 / S6: a v6 frame carrying an ext-header chain. The oracle is
        # walk-TRANSPARENT — it keys on the TRUE L4 (--proto/--dport), exactly the
        # value the datapath must reach by walking the chain. Requires the v6
        # family (the frame is always IPv6).
        if args.proto is None:
            ap.error("--ruleset andext requires --proto")
        if args.dst_ip6 is None or args.src_ip6 is None:
            ap.error("--ruleset andext requires --dst-ip6 and --src-ip6 (v6 frame)")
        dport = None if args.proto in (ICMP, ICMP6) else args.dport
        print(classify_andv6(None, None, args.dst_ip6, args.src_ip6,
                             args.proto, dport, args.vlan, args.src_mac,
                             rules=RULES_ANDEXT))
    elif args.ruleset == "andeth":
        if args.ethertype is None:
            ap.error("--ruleset andeth requires --ethertype")
        # proto/dport apply only to an IP frame; for a non-IP ethertype the
        # classifier ignores them (eff_proto=None). icmp/icmp6 carry no port.
        dport = None if args.proto in (ICMP, ICMP6) else args.dport
        print(classify_andeth(args.ethertype, args.dst_ip, args.src_ip,
                              args.dst_ip6, args.src_ip6,
                              args.proto, dport, args.vlan, args.src_mac))
    elif args.ruleset == "macmerge":
        if args.proto is None:
            ap.error("--ruleset macmerge requires --proto")
        if args.src_mac is None:
            ap.error("--ruleset macmerge requires --src-mac")
        dport = None if args.proto == ICMP else args.dport
        print(classify6(args.dst_ip, args.src_ip, args.proto, dport, args.vlan,
                        args.src_mac, rules=RULES_MACMERGE))
    elif args.ruleset == "and6":
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
