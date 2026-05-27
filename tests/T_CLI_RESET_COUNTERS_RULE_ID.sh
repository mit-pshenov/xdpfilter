#!/bin/bash
# T_CLI_RESET_COUNTERS_RULE_ID — design §6.NN+1 (MVP-3.4d / §5.35).
#
# `xdpmacfilter reset-counters --iface X --rule-id N` zeros ONLY slot N;
# out-of-range / non-integer values are rejected at parse-time (Q1.A) with
# exit 1 + stderr ERE. Maps to PI-3.4d-1, HG-3.4d-2 (--rule-id semantics +
# range validation), Q1.A (parse-time validation).
#
# Trigger:
#   1. setup_veth + apply config_per_rule_counters.yaml.
#   2. Bump rule_counters[0]=2, [5]=5, [17]=3.
#   3. Sub-case (a) — selectivity: reset-counters --rule-id 17 → exits 0;
#      stderr audit-line contains rule_id=17; [17]=0, [0]=2 UNCHANGED,
#      [5]=5 UNCHANGED.
#   4. Sub-case (b) — NEGATION (out-of-range): reset-counters --rule-id 64
#      → exits 1 + stderr ERE 'out of range \[0,63\]'; NO audit-log
#      (parse-time rejection); rule_counters state byte-equivalent.
#   5. Sub-case (c) — NEGATION (non-integer): reset-counters --rule-id foo
#      → exits 1 + stderr ERE 'requires an unsigned integer'; NO audit-log.
#
# Sanity-floor smoke: sub-case (a) — selective reset zeroes ONE slot and
# emits audit-log. Cannot proceed otherwise.
# Negation controls: (b) + (c) — out-of-range AND non-integer parses both
# rejected at parse-time. Without negation, "reset --rule-id 17 actually
# zeros all 64" or "out-of-range silently accepted" bugs hide.
#
# Anti-theatricality: the 3-rule baseline + selective-reset differential
# rules out "reset --rule-id N actually zeros ALL slots" via the
# UNCHANGED-others assertion.
#
# RESOURCE_LOCK xdp_fixture (guard #12).
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

MAC_ID0="02:00:00:00:00:01"
MAC_ID5="02:00:00:00:00:05"
MAC_ID17="02:00:00:00:00:11"

stderr_apply=$(mktemp /tmp/xdpmf-resetid-apply.XXXXXX)
stderr_a=$(mktemp /tmp/xdpmf-resetid-a.XXXXXX)
stderr_b=$(mktemp /tmp/xdpmf-resetid-b.XXXXXX)
stderr_c=$(mktemp /tmp/xdpmf-resetid-c.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_apply}" "${stderr_a}" "${stderr_b}" "${stderr_c}"' EXIT INT TERM HUP

sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true
setup_veth

# ── helpers (mirror T_CLI_RESET_COUNTERS) ────────────────────────────────
read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}

rule_counters_pin() {
    if sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
        local active; active=$(read_active_idx)
        case "${active}" in
            0) echo "${PIN_DIR}/rule_counters_a" ;;
            1) echo "${PIN_DIR}/rule_counters_b" ;;
            *) echo "${PIN_DIR}/rule_counters_a" ;;
        esac
    else
        echo "${PIN_DIR}/rule_counters"
    fi
}

read_rc_slot() {
    local id="$1" pin
    pin=$(rule_counters_pin)
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" "${pin}" "${id}"
}

# ── apply + bump baseline ────────────────────────────────────────────────
echo "=== apply ${FIXTURE}"
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_apply}"

if ! sudo -n test -e "${PIN_DIR}/rule_counters" \
     && ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[apply.pin]: no rule_counters pin after apply" >&2
    exit 1
fi

echo "=== inject baseline: 2 x id=0 + 5 x id=5 + 3 x id=17"
read -r p0 d0 m0 < <(read_stats)
for i in 1 2;         do inject_eth "${IFACE_B}" "${MAC_ID0}"  "${MAC_DST}"; done
for i in 1 2 3 4 5;   do inject_eth "${IFACE_B}" "${MAC_ID5}"  "${MAC_DST}"; done
for i in 1 2 3;       do inject_eth "${IFACE_B}" "${MAC_ID17}" "${MAC_DST}"; done
wait_for_stats_sum "${IFACE_A}" $(( p0 + d0 + m0 + 10 )) || true

c0_pre=$(read_rc_slot 0)
c5_pre=$(read_rc_slot 5)
c17_pre=$(read_rc_slot 17)
echo "baseline: [0]=${c0_pre} [5]=${c5_pre} [17]=${c17_pre}"
if [[ "${c0_pre}" != "2" || "${c5_pre}" != "5" || "${c17_pre}" != "3" ]]; then
    echo "FAIL[baseline]: expected [0]=2 [5]=5 [17]=3" >&2
    exit 1
fi

fail=0

# ── (a) sub-case: selective reset --rule-id 17 ───────────────────────────
echo "=== sub-case (a): reset-counters --iface ${IFACE_A} --rule-id 17"
set +e
sudo -n "${LOADER_BIN}" reset-counters --iface "${IFACE_A}" --rule-id 17 2>"${stderr_a}"
rc_a=$?
set -e
echo "rc_a=${rc_a}"
cat "${stderr_a}" >&2 || true

if [[ "${rc_a}" -ne 0 ]]; then
    echo "FAIL[a1]: --rule-id 17 expected exit 0, got ${rc_a}" >&2
    fail=1
fi

audit_ere_17="^xdpmacfilter: RESET-COUNTERS on ${IFACE_A} by uid=[0-9]+ .*rule_id=17\$"
if ! grep -qE -- "${audit_ere_17}" "${stderr_a}"; then
    echo "FAIL[a2]: stderr missing audit-log ERE for rule_id=17:" >&2
    echo "         ${audit_ere_17}" >&2
    fail=1
fi

# Selectivity: only slot 17 zeroed; slots 0 and 5 UNCHANGED.
c17_after_a=$(read_rc_slot 17)
c0_after_a=$(read_rc_slot 0)
c5_after_a=$(read_rc_slot 5)
echo "post-(a): [0]=${c0_after_a} [5]=${c5_after_a} [17]=${c17_after_a}"
if [[ "${c17_after_a}" != "0" ]]; then
    echo "FAIL[a3]: rule_counters[17]='${c17_after_a}' (expected 0 after selective reset)" >&2
    fail=1
fi
if [[ "${c0_after_a}" != "2" ]]; then
    echo "FAIL[a4]: rule_counters[0]='${c0_after_a}' (expected STILL 2 — selectivity broken)" >&2
    fail=1
fi
if [[ "${c5_after_a}" != "5" ]]; then
    echo "FAIL[a5]: rule_counters[5]='${c5_after_a}' (expected STILL 5 — selectivity broken)" >&2
    fail=1
fi

# ── (b) NEGATION: --rule-id 64 (out of range) ───────────────────────────
echo "=== sub-case (b) NEGATION: --rule-id 64 (out of range)"
set +e
sudo -n "${LOADER_BIN}" reset-counters --iface "${IFACE_A}" --rule-id 64 2>"${stderr_b}"
rc_b=$?
set -e
echo "rc_b=${rc_b}"
cat "${stderr_b}" >&2 || true

if [[ "${rc_b}" -ne 1 ]]; then
    echo "FAIL[b1]: --rule-id 64 expected exit 1 (CliError), got ${rc_b}" >&2
    fail=1
fi
if ! grep -qE -- 'out of range \[0,63\]' "${stderr_b}"; then
    echo "FAIL[b2]: stderr missing 'out of range [0,63]' ERE" >&2
    fail=1
fi
# Parse-time rejection: NO audit-log line must appear (per Q1.A).
if grep -qE -- 'RESET-COUNTERS on' "${stderr_b}"; then
    echo "FAIL[b3]: audit-log emitted for out-of-range --rule-id (parse-time rejection violated)" >&2
    fail=1
fi
# Counters state UNCHANGED from after sub-case (a).
c0_after_b=$(read_rc_slot 0)
c5_after_b=$(read_rc_slot 5)
c17_after_b=$(read_rc_slot 17)
if [[ "${c0_after_b}" != "${c0_after_a}" \
     || "${c5_after_b}" != "${c5_after_a}" \
     || "${c17_after_b}" != "${c17_after_a}" ]]; then
    echo "FAIL[b4]: rule_counters state changed across rejected --rule-id 64" >&2
    fail=1
fi

# ── (c) NEGATION: --rule-id foo (non-integer) ───────────────────────────
echo "=== sub-case (c) NEGATION: --rule-id foo (non-integer)"
set +e
sudo -n "${LOADER_BIN}" reset-counters --iface "${IFACE_A}" --rule-id foo 2>"${stderr_c}"
rc_c=$?
set -e
echo "rc_c=${rc_c}"
cat "${stderr_c}" >&2 || true

if [[ "${rc_c}" -ne 1 ]]; then
    echo "FAIL[c1]: --rule-id foo expected exit 1 (CliError), got ${rc_c}" >&2
    fail=1
fi
if ! grep -qE -- 'requires an unsigned integer' "${stderr_c}"; then
    echo "FAIL[c2]: stderr missing 'requires an unsigned integer' ERE" >&2
    fail=1
fi
if grep -qE -- 'RESET-COUNTERS on' "${stderr_c}"; then
    echo "FAIL[c3]: audit-log emitted for non-integer --rule-id (parse-time rejection violated)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_CLI_RESET_COUNTERS_RULE_ID"
exit "${fail}"
