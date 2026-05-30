#!/bin/bash
# T_IPV6_GATE_DEFAULT — design §5.51 / §6.70 TestStrategy (MVP-4.11 / S1), the
# EtherType gate-scaffold negation control. S1 reshapes the terminal
# `if (inner_proto == ETH_P_IP)` datapath gate into an
# `if (ETH_P_IP) {…} else if (ETH_P_IPV6) {/* empty seam */}` dispatch. The new
# `ETH_P_IPV6` arm is a recognized-but-not-classified seam that falls through to
# defaults[active] — a provably-no-op reshape (S4 cidr6 lands in this arm later).
#
# This is the OPS canary for the NEW datapath control-flow path: only a 0x86DD
# frame traverses the new arm (T_MAC_NON_IP's 0x88B5 frame matches NEITHER arm
# and only re-proves the pre-existing generic fallthrough). Without this test
# the new seam ships untested.
#
# The fixture config_mac_drop_default_pass.yaml (REUSED) inverts the usual
# polarity:  default_action: pass; id0 mac=02:00:00:00:00:01 action DROP.
#
#   (1) IPv4 frame, src_mac=MAC_RULE (inject_ipv4.py) → the MAC rule fires →
#       STAT_DROP_DENY delta == 1. (Positive/negation control: proves the rule +
#       drop machinery are LIVE — a "must-drop" case that MUST register, so
#       step (2)'s "not dropped" is meaningful, not a silently-broken
#       pass-everything.)
#   (2) 0x86DD frame, src_mac=MAC_RULE (inject_eth.py called DIRECTLY with the
#       4th ethertype arg 0x86DD, per D-mvp-4.11-INJECT-DEFAULT) → the frame
#       ENTERS the new ETH_P_IPV6 arm → falls to defaults[active] (= pass) →
#       STAT_DROP_DENY delta == 0 AND STAT_DROP_MALFORMED delta == 0. THE
#       boundary assertion: an IPv6 arm that (wrongly) early-returned DROP would
#       fail the deny-delta; one that dereferenced the zero-payload "v6 header"
#       and dropped on a bounds-miss would fail the malformed-delta.
#
# Sanity floor: smoke = apply exit 0. Positive/negation control = step (1) (a
# frame that MUST drop and does). Boundary/negation = step (2) (the new arm).
#
# Maps to: PI-mvp-4.11-IPV6-DEFAULTS, D-mvp-4.11-DISPATCH, D-mvp-4.11-IPV6-EMPTY,
#          D-mvp-4.11-NEGATION, D-mvp-4.11-INJECT-DEFAULT.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_mac_drop_default_pass.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

MAC_RULE="02:00:00:00:00:01"   # the drop-rule MAC in the fixture
SRC_IP="10.0.0.7"

stderr_file=$(mktemp /tmp/xdpmf-ipv6gate-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
cat "${stderr_file}" >&2 || true
echo "rc=${rc}"
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[smoke]: apply exit ${rc} (expected 0)" >&2
    exit 1
fi

fail=0

# ── (1) IPv4 frame from MAC_RULE → DROP (rule fires; positive control) ────
echo "=== (1) inject IPv4 frame src_mac=${MAC_RULE} → expect DROP (rule fires)"
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${MAC_RULE}" "${MAC_DST}" "${SRC_IP}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true
read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
echo "  after IPv4: PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1} PASS_CIDR=${c1}"
if (( d1 - d0 != 1 )); then
    echo "FAIL[1.deny]: STAT_DROP_DENY delta=$(( d1 - d0 )) (expected 1 — IPv4 MAC rule must drop)" >&2
    fail=1
fi

# ── (2) 0x86DD frame from MAC_RULE → NOT dropped (new ETH_P_IPV6 seam) ─────
# Call inject_eth.py DIRECTLY with the 4th ethertype arg 0x86DD so the frame
# traverses the NEW ETH_P_IPV6 arm (the common.sh inject_eth 3-arg wrapper emits
# the default 0x88B5, which matches NEITHER arm — D-mvp-4.11-INJECT-DEFAULT).
echo "=== (2) inject 0x86DD frame src_mac=${MAC_RULE} → expect NOT dropped (new arm → defaults=pass)"
read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_eth.py" \
    "${IFACE_B}" "${MAC_RULE}" "${MAC_DST}" 0x86DD
# The frame is counted somewhere (default pass) — wait for the total to advance.
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + c2 + 1 )) || true
read -r p3 d3 m3 c3 < <(read_stats_with_cidr)
echo "  after 0x86DD: PASS=${p3} DROP_DENY=${d3} DROP_MALFORMED=${m3} PASS_CIDR=${c3}"
if (( d3 - d2 != 0 )); then
    echo "FAIL[2.deny]: STAT_DROP_DENY delta=$(( d3 - d2 )) (expected 0)" >&2
    echo "             the new ETH_P_IPV6 arm must NOT early-return DROP — it falls to defaults[active]" >&2
    echo "             (PI-mvp-4.11-IPV6-DEFAULTS; D-mvp-4.11-IPV6-EMPTY)" >&2
    fail=1
fi
if (( m3 - m2 != 0 )); then
    echo "FAIL[2.mal]: STAT_DROP_MALFORMED delta=$(( m3 - m2 )) (expected 0)" >&2
    echo "             the IPv6 arm must NOT deref the frame or reclassify it MALFORMED — no deref this slice" >&2
    echo "             (PI-mvp-4.11-IPV6-DEFAULTS; Q1=A1 empty seam)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_IPV6_GATE_DEFAULT (the new ETH_P_IPV6 arm routes to defaults)"
exit "${fail}"
