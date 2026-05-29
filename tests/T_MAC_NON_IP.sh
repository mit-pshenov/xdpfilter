#!/bin/bash
# T_MAC_NON_IP — design §5.47 TestStrategy (MVP-4.7 / §5.47), the
# D-mvp-4.7-Q2-GATE boundary. The whole 6-axis rule-model composes INSIDE the
# `if (inner_proto == ETH_P_IP)` block, so a MAC-constrained rule matches IPv4
# frames ONLY; a NON-IPv4 frame from the same src-MAC falls through to
# defaults[active] (Phase A FINDING-1, §7 OOS fence).
#
# This test pins that boundary so it is deliberate, not accidental. The fixture
# config_mac_drop_default_pass.yaml inverts the usual polarity:
#   default_action: pass; id0 mac=02:00:00:00:00:01 action DROP.
#
#   (1) IPv4 frame, src_mac=MAC_RULE (inject_ipv4.py) → the MAC rule fires →
#       STAT_DROP_DENY delta == 1. (Proves the rule + drop machinery are live —
#       this is the negation control: a "must-drop" case that MUST register.)
#   (2) NON-IPv4 frame, src_mac=MAC_RULE (inject_eth.py emits EtherType 0x88B5)
#       → falls to defaults (= pass), NOT dropped → STAT_DROP_DENY delta == 0,
#       STAT_DROP_MALFORMED delta == 0. THE boundary assertion: a datapath that
#       (wrongly) applied the MAC drop rule to non-IPv4 frames would drop it.
#
# Sanity floor: smoke = apply exit 0. Negation control = step (1) (a frame that
# MUST drop and does).
#
# Maps to: PI-mvp-4.7-MAC, D-mvp-4.7-Q2-GATE, §7 OOS "MAC on non-IPv4 frames".
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_mac_drop_default_pass.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

MAC_RULE="02:00:00:00:00:01"   # the drop-rule MAC in the fixture
SRC_IP="10.0.0.7"

stderr_file=$(mktemp /tmp/xdpmf-macnonip-stderr.XXXXXX)
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

# ── (1) IPv4 frame from MAC_RULE → DROP (rule fires; negation control) ────
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

# ── (2) NON-IPv4 (0x88B5) frame from MAC_RULE → NOT dropped (gate boundary) ─
echo "=== (2) inject NON-IPv4 (0x88B5) frame src_mac=${MAC_RULE} → expect NOT dropped (defaults=pass)"
read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
inject_eth "${IFACE_B}" "${MAC_RULE}" "${MAC_DST}"
# The frame is counted somewhere (default pass) — wait for the total to advance.
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + c2 + 1 )) || true
read -r p3 d3 m3 c3 < <(read_stats_with_cidr)
echo "  after non-IPv4: PASS=${p3} DROP_DENY=${d3} DROP_MALFORMED=${m3} PASS_CIDR=${c3}"
if (( d3 - d2 != 0 )); then
    echo "FAIL[2.deny]: STAT_DROP_DENY delta=$(( d3 - d2 )) (expected 0)" >&2
    echo "             the MAC rule is IPv4-gated — a non-IPv4 frame must NOT be dropped by it" >&2
    echo "             (D-mvp-4.7-Q2-GATE; §7 OOS 'MAC on non-IPv4 frames')" >&2
    fail=1
fi
if (( m3 - m2 != 0 )); then
    echo "FAIL[2.mal]: STAT_DROP_MALFORMED delta=$(( m3 - m2 )) (expected 0 — the 60B frame is well-formed)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_MAC_NON_IP (MAC axis is IPv4-gated)"
exit "${fail}"
