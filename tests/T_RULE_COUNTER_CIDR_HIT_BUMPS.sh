#!/bin/bash
# T_RULE_COUNTER_CIDR_HIT_BUMPS — design §6.48 (MVP-3.4b cycle 1 / §5.31).
#
# CIDR LPM_TRIE-hit increments rule_counters[rule_id] per Q1 B3 unified
# per-match semantic — symmetric MAC/CIDR (PI-3.4b-3 + PI-3.4b-4 +
# PI-13-3.4b T.5 OQ #3).
#
# Fixture has rule_id=42 as CIDR-only PASS (src_cidr: 10.0.0.0/24).
#
# Trigger:
#   1. setup_veth + apply config_per_rule_counters.yaml.
#   2. Inject N=4 IPv4 frames with src_ip IN 10.0.0.0/24 (e.g., 10.0.0.5)
#      from a MAC NOT in any MAC rule (proves it's the CIDR axis bumping,
#      NOT MAC-axis short-circuit).
#   3. Negation: inject 1 IPv4 frame with src_ip OUTSIDE 10.0.0.0/24
#      (e.g., 192.168.1.1) from same MAC — STAT_DROP_DENY bumps;
#      rule_counters[42] STAYS 4.
#   4. MAC/CIDR axis isolation: inject 1 MAC-id-5 frame; rule_counters[5]
#      bumps; rule_counters[42] STAYS 4 (CIDR branch not entered when
#      MAC-axis short-circuits per §5.27 OR1 ordering).
#
# Observable outcome (ALL must hold):
#   (a) apply exit 0; rule_counters pin exists.
#   (b) After step 2: rule_counters[42] == 4; STAT_PASS_CIDR delta == 4;
#       STAT_PASS delta == 0; STAT_DROP_DENY delta == 0.
#   (c) After step 3 (negation): rule_counters[42] STILL == 4;
#       STAT_DROP_DENY delta == 1 (the out-of-range frame);
#       STAT_PASS_CIDR delta == 0 (no CIDR hit).
#   (d) After step 4: rule_counters[5] == 1; rule_counters[42] STILL == 4;
#       STAT_PASS delta == 1.
#
# Sanity-floor smoke: step (a) — apply succeeds + rule_counters pin
# materializes.
# Negation control: step 3 (src_ip OUTSIDE the CIDR — counter STAYS).
# This catches a bug where bump_rule fires on any IPv4 frame regardless
# of LPM_TRIE match status, or where the wrong rule_id is bumped.
#
# Maps to: PI-3.4b-3 (CIDR symmetric inner-value), PI-3.4b-4 (bump_rule
# on CIDR-hit), Q1 B3 (unified semantic).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for rule_counters dump parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_per_rule_counters.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

# §5.43 MVP-4.3: MAC axis deferred to mvp-4.5; fixture id42 now src_cidr
# 10.42.0.0/16. The former step (d) MAC-axis-isolation sub-case is dropped
# (MAC-is-the-point → covered by the SKIP'd MAC suite per PI-mvp-4.3-MAC-DEFERRED).
SRC_MAC="02:00:00:00:00:aa"        # MAC axis deferred — value irrelevant
SRC_IP_IN="10.42.0.5"              # ∈ 10.42.0.0/16 (rule_id=42 PASS)
SRC_IP_OUT="8.8.8.8"               # ∉ any rule → defaults drop

stderr_file=$(mktemp /tmp/xdpmf-rulecidr-stderr.XXXXXX)
# §5.33 HK-B: explicit signal trap-set covers SIGINT/SIGTERM/SIGHUP in
# addition to normal EXIT so ctest's kill-escalation under -j4 still
# fires cleanup_veth (bash's implicit-EXIT-on-signal is racy under some
# kill scenarios; named-signal handlers fire immediately on receipt).
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP

# §5.33 HK-B pre-test residue wipe — idempotent belt-and-suspenders defense
# against PID-recycled prior aborted runs leaving residue at the same
# PID-scoped ${PIN_DIR}=${PIN_ROOT}/xdpmf_a_$$ path. setup_veth's internal
# rm-rf already handles the in-test case; this catches the cross-run case.
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

# §5.35 (MVP-3.4d) fixture-ripple: single `rule_counters` PERCPU_ARRAY pin
# RETIRED; replaced by `rule_counters_<a|b>` inners under
# `rule_counters_outer` ARRAY_OF_MAPS. Reads must follow active_idx.
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
    local active; active=$(read_active_idx)
    case "${active}" in
        0) echo "${PIN_DIR}/rule_counters_a" ;;
        1) echo "${PIN_DIR}/rule_counters_b" ;;
        *) echo "${PIN_DIR}/rule_counters_a" ;;
    esac
}
read_rc_slot() {
    local id="$1" pin
    pin=$(rule_counters_active_pin)
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" "${pin}" "${id}"
}

# ── (a) apply + smoke ────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
cat "${stderr_file}" >&2 || true

fail=0
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[a1]: apply exit ${rc} (expected 0)" >&2
    fail=1
fi
if ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[a2]: ${PIN_DIR}/rule_counters_a pin missing (§5.35 PI-3.4d-2)" >&2
    exit 1
fi

# Baseline stats (4-column for CIDR axis).
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "stats baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"

# Baseline rule_counters — slot 42 must be 0.
c42_before=$(read_rc_slot 42)
if [[ "${c42_before}" != "0" ]]; then
    echo "FAIL[a3]: rule_counters[42]='${c42_before}' baseline (expected 0)" >&2
    fail=1
fi

# ── (b) Inject N=4 IPv4 frames IN-range → rule_counters[42] == 4 ────────
echo "=== step (b): inject 4 IPv4 frames src_ip=${SRC_IP_IN} mac=${SRC_MAC}"
for i in 1 2 3 4; do
    ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
        "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "${SRC_IP_IN}"
done
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 4 )) || true

c42_after_b=$(read_rc_slot 42)
read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
echo "rule_counters[42]=${c42_after_b} (expected 4)"
echo "stats: PASS=${p1} DROP_DENY=${d1} PASS_CIDR=${c1} (PASS_CIDR delta=$((c1-c0)))"

if [[ "${c42_after_b}" != "4" ]]; then
    echo "FAIL[b1]: rule_counters[42]='${c42_after_b}' (expected 4)" >&2
    fail=1
fi
if (( c1 - c0 != 4 )); then
    echo "FAIL[b2]: STAT_PASS_CIDR delta=$((c1-c0)) (expected 4)" >&2
    fail=1
fi
if (( p1 - p0 != 0 )); then
    echo "FAIL[b3]: STAT_PASS moved on CIDR-axis hits (delta=$((p1-p0)); expected 0)" >&2
    fail=1
fi
if (( d1 - d0 != 0 )); then
    echo "FAIL[b4]: STAT_DROP_DENY moved on IN-range frames (delta=$((d1-d0)))" >&2
    fail=1
fi

# Other slots STILL 0 — slots 0/5/17 should be untouched.
for slot in 0 5 17; do
    v=$(read_rc_slot "${slot}")
    if [[ "${v}" != "0" ]]; then
        echo "FAIL[b5.${slot}]: rule_counters[${slot}]='${v}' (expected 0; should NOT bump on CIDR hit)" >&2
        fail=1
    fi
done

# ── (c) NEGATION CONTROL: out-of-range src_ip → rule_counters[42] STAYS ─
echo "=== step (c): NEGATION — inject 1 IPv4 frame src_ip=${SRC_IP_OUT} (OUTSIDE 10.0.0.0/24)"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "${SRC_IP_OUT}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true

c42_after_c=$(read_rc_slot 42)
read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
echo "rule_counters[42]=${c42_after_c} (expected STILL 4)"
echo "stats: DROP_DENY delta=$((d2-d1)) PASS_CIDR delta=$((c2-c1))"

if [[ "${c42_after_c}" != "4" ]]; then
    echo "FAIL[c1]: rule_counters[42]='${c42_after_c}' bumped on OUT-of-range (expected STILL 4)" >&2
    echo "          bug shape: LPM_TRIE matched a wrong prefix OR bump_rule fires unconditionally" >&2
    fail=1
fi
if (( d2 - d1 != 1 )); then
    echo "FAIL[c2]: STAT_DROP_DENY delta=$((d2-d1)) (expected 1 from out-of-range frame)" >&2
    fail=1
fi
if (( c2 - c1 != 0 )); then
    echo "FAIL[c3]: STAT_PASS_CIDR moved on out-of-range frame (delta=$((c2-c1)))" >&2
    fail=1
fi

# ── (d) RULE isolation (§5.43): a DIFFERENT rule's range (id5) bumps only
#       counters[5]; counters[42] unchanged. (Replaces the retired MAC-axis
#       sub-case — MAC deferred to mvp-4.5. Same isolation intent, CIDR-only.)
echo "=== step (d): inject 1 frame src_ip=10.5.0.5 (rule_id=5 PASS)"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "10.5.0.5"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + c2 + 1 )) || true

c5_after_d=$(read_rc_slot 5)
c42_after_d=$(read_rc_slot 42)
read -r p3 d3 m3 c3 < <(read_stats_with_cidr)
echo "rule_counters[5]=${c5_after_d} (expected 1); rule_counters[42]=${c42_after_d} (expected STILL 4)"
echo "stats: PASS_CIDR delta=$((c3-c2))"

if [[ "${c5_after_d}" != "1" ]]; then
    echo "FAIL[d1]: rule_counters[5]='${c5_after_d}' (expected 1 from id5 CIDR hit)" >&2
    fail=1
fi
if [[ "${c42_after_d}" != "4" ]]; then
    echo "FAIL[d2]: rule_counters[42]='${c42_after_d}' bumped on id5 hit (expected STILL 4)" >&2
    echo "          rule isolation broken: id5 hit must not touch id42's slot" >&2
    fail=1
fi
if (( c3 - c2 != 1 )); then
    echo "FAIL[d3]: STAT_PASS_CIDR delta=$((c3-c2)) (expected 1 from id5 PASS hit)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_RULE_COUNTER_CIDR_HIT_BUMPS"
exit "${fail}"
