#!/bin/bash
# T_AND_PREFIX_CLOSURE_OVERLAP — design §6.62 (MVP-4.3 / §5.43) — guard #23.
#
# THE #1-bug-class canary for the bit-vector pivot: prefix-closure
# cover-direction + first-match-by-id. The load-bearing test of the slice.
#
# Fixture config_overlap_lowid.yaml (schema_version: 2, default_action: pass):
#   id 0 : dst 10.1.2.0/24    DROP  (less-specific COVER, LOWER id)
#   id 1 : dst 10.1.0.0/16    PASS  (broader cover)
#   id 3 : dst 10.1.2.128/25  PASS  (MORE-specific, HIGHER id)
#
# A packet to 10.1.2.130 is in ALL THREE prefixes. The correct verdict is
# DROP via id0 — the LOWEST matching id wins, NOT the most-specific id3.
# This is producible ONLY if:
#   (a) prefix-closure stored the covering /24's bit (id0) into the /25 LPM
#       entry — cover-direction CORRECT, and
#   (b) ffsll(acc) picks the lowest set bit.
# A backwards closure (storing covered-into-covering) OR a most-specific-wins
# bug FLIPS the verdict to PASS via id3 → this test FAILS loudly.
#
# Steps / observable outcome (ALL must hold):
#   (a) SMOKE: apply exit 0; rule_counters pin exists.
#   (b) LOAD-BEARING: inject dst=10.1.2.130 → DROP via id0:
#       rule_counters[0] == 1; STAT_DROP_DENY delta == 1;
#       rule_counters[3] == 0 (id3 must NOT win); rule_counters[1] == 0.
#   (c) broader-cover-only: inject dst=10.1.5.5 (∈ /16 only) → PASS via id1:
#       rule_counters[1] == 1; STAT_PASS_CIDR delta == 1; rule_counters[0] STAYS 1.
#   (d) NEGATION CONTROL: inject dst=8.8.8.8 (matches NO rule) → defaults
#       PASS: NO rule_counters slot bumps; STAT_PASS delta == 1. Proves the
#       machinery registers a clean miss (not an always-match closure).
#
# Sanity-floor smoke: step (a). Negation control: step (d).
#
# Maps to: PI-mvp-4.3-CLOSURE, PI-mvp-4.3-AND (first-match-by-id).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_overlap_lowid.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

SRC_MAC="02:00:00:00:00:aa"
SRC_IP="203.0.113.9"           # src is wildcard for all rules — value irrelevant
INJECT="${TEST_DIR}/inject/inject_ipv4.py"

stderr_file=$(mktemp /tmp/xdpmf-overlap-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}
rule_counters_active_pin() {
    case "$(read_active_idx)" in
        1) echo "${PIN_DIR}/rule_counters_b" ;;
        *) echo "${PIN_DIR}/rule_counters_a" ;;
    esac
}
read_rc_slot() {
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" \
        "$(rule_counters_active_pin)" "$1"
}
inject() { ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "${SRC_IP}" "$1"; }

# ── (a) apply + smoke ────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
cat "${stderr_file}" >&2 || true
if [[ "${rc}" -ne 0 ]]; then echo "FAIL[a]: apply exit ${rc} (expected 0)" >&2; exit 1; fi
sudo -n test -e "${PIN_DIR}/rule_counters_a" \
    || { echo "FAIL[a]: ${PIN_DIR}/rule_counters_a pin missing" >&2; exit 1; }
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "stats baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"

fail=0

# ── (b) LOAD-BEARING: 10.1.2.130 → DROP via id0 (lowest), NOT id3 ────────
echo "=== (b) inject dst=10.1.2.130 (∈ /24 id0, /16 id1, /25 id3) → expect DROP via id0"
inject 10.1.2.130
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true
read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
rc0=$(read_rc_slot 0); rc1=$(read_rc_slot 1); rc3=$(read_rc_slot 3)
echo "rule_counters: [0]=${rc0} [1]=${rc1} [3]=${rc3}; DROP_DENY delta=$((d1-d0)) PASS_CIDR delta=$((c1-c0))"
if [[ "${rc0}" != "1" ]]; then
    echo "FAIL[b1]: rule_counters[0]='${rc0}' (expected 1 — lowest-id covering rule must win)" >&2
    echo "          bug shape: backwards prefix-closure OR most-specific-wins" >&2
    fail=1
fi
if [[ "${rc3}" != "0" ]]; then
    echo "FAIL[b2]: rule_counters[3]='${rc3}' (expected 0 — more-specific HIGHER id must NOT win)" >&2
    echo "          bug shape: most-specific-wins instead of first-match-by-id" >&2
    fail=1
fi
if [[ "${rc1}" != "0" ]]; then
    echo "FAIL[b3]: rule_counters[1]='${rc1}' (expected 0 — id0 lower than id1)" >&2; fail=1
fi
if (( d1 - d0 != 1 )); then
    echo "FAIL[b4]: STAT_DROP_DENY delta=$((d1-d0)) (expected 1 — id0 is DROP)" >&2
    echo "          a PASS here means id3 won (closure/first-match bug)" >&2
    fail=1
fi

# ── (c) broader-cover-only: 10.1.5.5 ∈ /16 only → PASS via id1 ──────────
echo "=== (c) inject dst=10.1.5.5 (∈ /16 id1 only) → expect PASS via id1"
inject 10.1.5.5
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true
read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
rc1=$(read_rc_slot 1); rc0=$(read_rc_slot 0)
if [[ "${rc1}" != "1" ]]; then
    echo "FAIL[c1]: rule_counters[1]='${rc1}' (expected 1 — broader cover id1)" >&2; fail=1
fi
if (( c2 - c1 != 1 )); then
    echo "FAIL[c2]: STAT_PASS_CIDR delta=$((c2-c1)) (expected 1 — id1 is PASS)" >&2; fail=1
fi
if [[ "${rc0}" != "1" ]]; then
    echo "FAIL[c3]: rule_counters[0]='${rc0}' drifted (expected STILL 1)" >&2; fail=1
fi

# ── (d) NEGATION CONTROL: 8.8.8.8 matches nothing → defaults PASS ────────
echo "=== (d) NEGATION: inject dst=8.8.8.8 (matches NO rule) → expect defaults PASS, no rule bump"
inject 8.8.8.8
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + c2 + 1 )) || true
read -r p3 d3 m3 c3 < <(read_stats_with_cidr)
rc0=$(read_rc_slot 0); rc1=$(read_rc_slot 1); rc3=$(read_rc_slot 3)
if [[ "${rc0}" != "1" || "${rc1}" != "1" || "${rc3}" != "0" ]]; then
    echo "FAIL[d1]: a rule_counters slot moved on a no-match frame ([0]=${rc0} [1]=${rc1} [3]=${rc3})" >&2
    echo "          expected [0]=1 [1]=1 [3]=0 (unchanged) — closure must not always-match" >&2
    fail=1
fi
if (( p3 - p2 != 1 )); then
    echo "FAIL[d2]: STAT_PASS delta=$((p3-p2)) (expected 1 — defaults PASS fallthrough)" >&2; fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_AND_PREFIX_CLOSURE_OVERLAP"
exit "${fail}"
