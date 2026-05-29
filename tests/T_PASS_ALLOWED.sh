#!/bin/bash
# T_PASS_ALLOWED → T_MAC_PASS — design §5.47 TestStrategy (MVP-4.7 / §5.47).
#
# MAC is a LIVE 6th exact-HASH axis again (un-SKIP'd from §5.43 deferral;
# PI-mvp-4.3-MAC-DEFERRED RETIRED per D-mvp-4.7-MAC-RETURN-SHIFT). This test
# asserts the v2 live MAC verdict under the AND-model:
#
#   Setup   : apply config_valid_mac.yaml (id0 mac=MAC_ALLOW pass; default drop).
#   Trigger : inject ONE IPv4 frame with src_mac == MAC_ALLOW.
#   Outcome : the frame PASSES (STAT_PASS + STAT_PASS_CIDR delta == 1),
#             STAT_DROP_DENY delta == 0, STAT_DROP_MALFORMED delta == 0.
#   Negation: inject ONE IPv4 frame with src_mac != MAC_ALLOW → defaults
#             (STAT_DROP_DENY delta == 1; both PASS counters unchanged).
#
# MAC is IPv4-gated (D-mvp-4.7-Q2-GATE) so frames are injected as IPv4
# (inject_ipv4.py) — a non-IPv4 frame would fall to defaults regardless of MAC.
# The PASS counter assertion uses the (pass + pass_cidr) SUM because the design
# states "STAT_PASS/PASS_CIDR (matched)" — robust to whichever bucket fires.
#
# Sanity floor: smoke = apply exit 0. Negation control = the unmatched-MAC
# injection MUST drop (proves the verdict machinery can register a miss).
#
# Maps to: PI-mvp-4.7-MAC, PI-mvp-4.3-AND (→6 axes), PI-mvp-4.7-GRAMMAR.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_mac.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

MAC_ALLOW="02:00:00:00:00:01"   # in config_valid_mac.yaml id0
MAC_DENY="02:00:00:00:00:fe"    # in no rule — negation control
SRC_IP="10.0.0.7"               # irrelevant to a mac-only rule; just well-formed

stderr_file=$(mktemp /tmp/xdpmf-macpass-stderr.XXXXXX)
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
    echo "FAIL[smoke]: apply exit ${rc} (expected 0 — mac key must be accepted under v2)" >&2
    exit 1
fi

fail=0

# ── matched MAC → PASS ────────────────────────────────────────────────────
echo "=== inject IPv4 frame src_mac=${MAC_ALLOW} (allowed) → expect PASS"
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "  baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${MAC_ALLOW}" "${MAC_DST}" "${SRC_IP}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true

read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
echo "  after allow: PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1} PASS_CIDR=${c1}"

pass_delta=$(( (p1 - p0) + (c1 - c0) ))
if (( pass_delta != 1 )); then
    echo "FAIL[allow.pass]: (STAT_PASS + STAT_PASS_CIDR) delta=${pass_delta} (expected 1)" >&2
    echo "                  the src-MAC matched id0 — the frame must PASS" >&2
    fail=1
fi
if (( d1 - d0 != 0 )); then
    echo "FAIL[allow.deny]: STAT_DROP_DENY delta=$(( d1 - d0 )) (expected 0 on a MAC match)" >&2
    fail=1
fi
if (( m1 - m0 != 0 )); then
    echo "FAIL[allow.mal]: STAT_DROP_MALFORMED delta=$(( m1 - m0 )) (expected 0)" >&2
    fail=1
fi

# ── unmatched MAC → DROP (NEGATION CONTROL) ───────────────────────────────
echo "=== NEGATION: inject IPv4 frame src_mac=${MAC_DENY} (not in any rule) → expect DROP"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${MAC_DENY}" "${MAC_DST}" "${SRC_IP}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true

read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
echo "  after deny: PASS=${p2} DROP_DENY=${d2} DROP_MALFORMED=${m2} PASS_CIDR=${c2}"

if (( d2 - d1 != 1 )); then
    echo "FAIL[deny.deny]: STAT_DROP_DENY delta=$(( d2 - d1 )) (expected 1 — NEGATION FAILED)" >&2
    echo "                 a non-matching src-MAC must fall to defaults (drop)" >&2
    fail=1
fi
if (( (p2 - p1) + (c2 - c1) != 0 )); then
    echo "FAIL[deny.pass]: PASS counters moved on a non-matching MAC (delta $(( (p2-p1)+(c2-c1) )))" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_PASS_ALLOWED (live MAC verdict, AND-model)"
exit "${fail}"
