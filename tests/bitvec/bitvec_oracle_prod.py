#!/usr/bin/env python3
"""
bitvec_oracle_prod.py — independent reference classifier for the MVP-4.3
PRODUCTION OR→AND bit-vector pivot (design §5.43, axis-1: dst_cidr + src_cidr).

THIS FILE IS THE TESTER-OWNED ORACLE. It is deliberately a *naive O(N)
first-match scan* — there is NO bitmask, NO prefix-closure, NO ffsll, NO
wildcard map. Its whole reason to exist is to be algorithmically DIFFERENT
from the production datapath under test (`src/bpf/mac_filter.bpf.c`'s
bit-vector AND compose + `loader.cpp`'s `close_prefixes()`), so that any
disagreement localises a closure / wildcard / first-match bug in the
datapath rather than masking it (§5.43 TestStrategy §6.61).

The rule set below is transcribed BY HAND from tests/fixtures/config_valid_and.yaml
(the v2 AND-compose fixture). It is NOT parsed from the YAML — independence
of DATA transcription is intentional (per the §5.42 D-mvp-4.2-CANONICAL
precedent: divergent transcriptions make the agreement test fail loudly,
which is the point). If you edit config_valid_and.yaml you MUST edit this
table to match.

Semantics (§5.43 §6.61 / DataStructures):
  input = (dst_ip, src_ip)
  for each rule in ASCENDING id:
      rule matches iff for EVERY axis the rule CONSTRAINS, the packet
      field satisfies it:
        - dst_cidr : dst_ip ∈ CIDR
        - src_cidr : src_ip ∈ CIDR
      a wildcard (unconstrained) axis is satisfied unconditionally.
  return the FIRST (lowest id) matching rule, else NOMATCH.

This is the OR→AND contract: a rule constraining BOTH axes matches ONLY
when BOTH are satisfied (under the retired OR model a single-axis match
would have hit — see §6.60).

Output: prints a single integer to stdout — the matched rule id, or
NOMATCH (= XDPMF_ALLOWLIST_MAX = 64) if nothing matches.

Usage:
    bitvec_oracle_prod.py --dst-ip A --src-ip B
"""
import argparse
import socket
import struct
import sys

# §5.43 DataStructures: id ∈ [0, XDPMF_ALLOWLIST_MAX-1=63]; NOMATCH = 64.
NOMATCH = 64

# Wildcard sentinel for an axis the rule does not constrain.
W = None


def _cidr(s):
    """Parse 'a.b.c.d/len' → (network_int, prefixlen)."""
    addr, length = s.split("/")
    length = int(length)
    net = struct.unpack("!I", socket.inet_aton(addr))[0]
    return (net, length)


# ── Rule set transcribed by hand from config_valid_and.yaml ───────────────
# Each rule: (id, dst_cidr|W, src_cidr|W, action).
# `action` is documentation-only — the observable is the matched id; the
# action is verified separately by §6.60 (compose) and §6.62 (overlap).
RULES = [
    # id  dst_cidr                  src_cidr                  action
    (0,  _cidr("10.1.0.0/16"),     _cidr("192.168.5.0/24"),  "pass"),  # full AND
    (1,  _cidr("10.3.0.0/16"),     W,                        "pass"),  # dst-only
    (2,  W,                        _cidr("10.9.0.0/16"),     "drop"),  # src-only
    (4,  _cidr("10.3.5.0/24"),     W,                        "drop"),  # overlaps id1
]


def _ip_to_int(s):
    return struct.unpack("!I", socket.inet_aton(s))[0]


def _ip_in_cidr(ip_int, cidr):
    net, length = cidr
    if length == 0:
        return True
    mask = (0xFFFFFFFF << (32 - length)) & 0xFFFFFFFF
    return (ip_int & mask) == (net & mask)


def classify(dst_ip, src_ip):
    """Return the lowest matching rule id, or NOMATCH."""
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


def main():
    ap = argparse.ArgumentParser(
        prog="bitvec_oracle_prod.py",
        description="independent dst+src AND first-match classifier (§5.43)")
    ap.add_argument("--dst-ip", required=True)
    ap.add_argument("--src-ip", required=True)
    args = ap.parse_args()
    print(classify(args.dst_ip, args.src_ip))
    return 0


if __name__ == "__main__":
    sys.exit(main())
