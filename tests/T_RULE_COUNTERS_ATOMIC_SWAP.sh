#!/bin/bash
# T_RULE_COUNTERS_ATOMIC_SWAP — design §6.NN+3 (MVP-3.4d / §5.35).
#
# **LOAD-BEARING canary** for PI-3.4b-2 PRESERVE-across-apply +
# D-3.4d-3 apply-step copy-forward (5-axis active_idx mechanism per
# D-3.4d-7). The atomic-swap promotion of rule_counters to parallel
# ARRAY_OF_MAPS is STRUCTURAL-ONLY (HG-3.4d-5); per-CPU counter state
# MUST survive `apply -f` via the userspace copy-forward step that runs
# BEFORE the active_idx flip.
#
# CONDITIONAL: SKIP-77 if D-3.4d-FALLBACK active (atomic-swap deferred).
# Probe rule_counters_outer pin at test start; if missing, skip.
#
# Trigger:
#   1. setup_veth + apply config A (config_per_rule_counters.yaml).
#   2. SKIP-77 probe: rule_counters_outer pin must exist; otherwise
#      D-3.4d-FALLBACK is active and atomic-swap path is deferred.
#   3. Inject 5 frames id=5 + 3 frames id=17 → bump rule_counters in
#      active_A inner.
#   4. Read active_idx → active_A; verify rule_counters_<active_A>[5]=5,
#      [17]=3 (baseline pre-flip).
#   5. apply config B (re-apply same fixture forces active_idx flip).
#   6. Read active_idx → active_B; assert active_B != active_A.
#   7. LOAD-BEARING ASSERT: read rule_counters_<active_B> →
#      [5] STILL =5; [17] STILL =3 (D-3.4d-3 copy-forward preserved
#      per-CPU state across the flip).
#   8. Inject 2 more frames id=5; assert rule_counters_<active_B>[5]=7
#      (monotonic continuation from preserved 5).
#   9. Inject 1 more frame id=17; assert rule_counters_<active_B>[17]=4.
#
# Observable outcome (ALL):
#   (a) apply A + apply B exit 0.
#   (b) active_B != active_A (single u32 flip observed).
#   (c) Pre-flip rule_counters_<active_A>[5]=5, [17]=3.
#   (d) Post-flip rule_counters_<active_B>[5]=5, [17]=3 (PI-3.4b-2 PRESERVE
#       held; D-3.4d-3 copy-forward worked).
#   (e) Post-flip bumps continue monotonically: [5]=7, [17]=4 after
#       additional injections (active inner is being bumped).
#
# Sanity-floor smoke: step (a) — apply A succeeds + rule_counters_outer
# pin materializes. Cannot reach later assertions otherwise.
# Negation control: step (b) — active_idx ACTUALLY flipped (without this,
# "values preserved" could be theatre — we'd just be re-reading the same
# inner. The flip-then-read-different-inner pattern is the load-bearing
# anti-theatricality. Bug mode caught: bump_rule writes to wrong inner
# OR copy-forward never runs.
#
# Maps to: PI-3.4b-2 (counter-monotonicity-across-apply LOAD-BEARING
# PRESERVATION), HG-3.4d-5 (structural-only semantic), D-3.4d-3
# (apply-step copy-forward), D-3.4d-7 (5-axis active_idx mechanism).
#
# RESOURCE_LOCK xdp_fixture (guard #12).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_per_rule_counters.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

MAC_ID5="02:00:00:00:00:05"
SRC_MAC="02:00:00:00:00:aa"  # 5.43: MAC deferred; src_mac irrelevant
MAC_ID17="02:00:00:00:00:11"

stderr_apply_a=$(mktemp /tmp/xdpmf-rcswap-apply-a.XXXXXX)
stderr_apply_b=$(mktemp /tmp/xdpmf-rcswap-apply-b.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_apply_a}" "${stderr_apply_b}"' EXIT INT TERM HUP

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

# Map active_idx (0|1) → inner pin name (a|b).
rule_counters_inner_for() {
    case "$1" in
        0) echo "${PIN_DIR}/rule_counters_a" ;;
        1) echo "${PIN_DIR}/rule_counters_b" ;;
        *) return 1 ;;
    esac
}

read_rc_slot_at() {
    local pin="$1" id="$2"
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" "${pin}" "${id}"
}

# ── (1) apply A ──────────────────────────────────────────────────────────
echo "=== step 1: apply A (${FIXTURE})"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_apply_a}"
rc_a=$?
set -e
echo "rc_a=${rc_a}"
cat "${stderr_apply_a}" >&2 || true

if [[ "${rc_a}" -ne 0 ]]; then
    echo "FAIL[1]: apply A exit ${rc_a} (expected 0)" >&2
    exit 1
fi

# ── (2) SKIP-77 probe: D-3.4d-FALLBACK detection ─────────────────────────
if ! sudo -n test -e "${PIN_DIR}/rule_counters_outer"; then
    echo "T_RULE_COUNTERS_ATOMIC_SWAP: D-3.4d-FALLBACK active; atomic-swap deferred — skipping" >&2
    exit 77
fi
echo "=== rule_counters_outer pin present — HG-3.4d-4 default ship is active"

fail=0

# ── (3) bump rule_counters[5]=5, [17]=3 in active_A inner ───────────────
echo "=== step 3: inject 5 x id=5 + 3 x id=17"
read -r p0 d0 m0 p0_c < <(read_stats_with_cidr)
for i in 1 2 3 4 5; do ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "10.5.0.1"; done
for i in 1 2 3;     do ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "10.17.0.1"; done
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + p0_c + 8 )) || true

# ── (4) read active_A + verify baseline ──────────────────────────────────
active_A=$(read_active_idx)
echo "active_A = '${active_A}'"
if [[ -z "${active_A}" ]]; then
    echo "FAIL[4]: cannot read active_idx" >&2
    exit 1
fi
rc_inner_A=$(rule_counters_inner_for "${active_A}") || {
    echo "FAIL[4]: cannot map active_A='${active_A}' to rule_counters_<a|b>" >&2
    exit 1
}
echo "rule_counters inner (active_A) = ${rc_inner_A}"

c5_A=$(read_rc_slot_at "${rc_inner_A}" 5)
c17_A=$(read_rc_slot_at "${rc_inner_A}" 17)
echo "pre-flip: rule_counters_<active_A>[5]=${c5_A} [17]=${c17_A}"
if [[ "${c5_A}" != "5" || "${c17_A}" != "3" ]]; then
    echo "FAIL[c]: expected pre-flip [5]=5 [17]=3, got [5]=${c5_A} [17]=${c17_A}" >&2
    echo "        test premise invalid — bump_rule not writing to active inner" >&2
    fail=1
fi

# ── (5) apply B (re-apply forces flip) ──────────────────────────────────
echo "=== step 5: RE-apply ${FIXTURE} to force active_idx flip"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_apply_b}"
rc_b=$?
set -e
echo "rc_b=${rc_b}"
cat "${stderr_apply_b}" >&2 || true

if [[ "${rc_b}" -ne 0 ]]; then
    echo "FAIL[a.B]: apply B exit ${rc_b} (expected 0)" >&2
    fail=1
fi

# ── (6) read active_B + assert flip ─────────────────────────────────────
active_B=$(read_active_idx)
echo "active_B = '${active_B}' (was '${active_A}')"
if [[ -z "${active_B}" ]]; then
    echo "FAIL[6]: cannot read active_idx after apply B" >&2
    exit 1
fi
if [[ "${active_A}" == "${active_B}" ]]; then
    echo "FAIL[b]: active_idx did NOT flip across re-apply (still ${active_B})" >&2
    echo "         test premise invalid — no atomic swap happened" >&2
    exit 1
fi
rc_inner_B=$(rule_counters_inner_for "${active_B}") || {
    echo "FAIL[6]: cannot map active_B='${active_B}' to rule_counters_<a|b>" >&2
    exit 1
}
echo "rule_counters inner (active_B) = ${rc_inner_B}"

# ── (7) LOAD-BEARING ASSERT: per-CPU state PRESERVED in new-active ──────
c5_B=$(read_rc_slot_at "${rc_inner_B}" 5)
c17_B=$(read_rc_slot_at "${rc_inner_B}" 17)
echo "post-flip (LOAD-BEARING): rule_counters_<active_B>[5]=${c5_B} [17]=${c17_B}"
if [[ "${c5_B}" != "5" ]]; then
    echo "FAIL[d1]: rule_counters_<active_B>[5]='${c5_B}' (expected STILL 5)" >&2
    echo "         PI-3.4b-2 PRESERVE-across-apply VIOLATED" >&2
    echo "         Likely root cause: D-3.4d-3 copy_rule_counters_forward not called" >&2
    echo "         OR called AFTER the active_idx flip (race)" >&2
    fail=1
fi
if [[ "${c17_B}" != "3" ]]; then
    echo "FAIL[d2]: rule_counters_<active_B>[17]='${c17_B}' (expected STILL 3)" >&2
    echo "         PI-3.4b-2 PRESERVE-across-apply VIOLATED" >&2
    fail=1
fi

# ── (8) post-flip bumps continue monotonically: [5] → 7 ─────────────────
echo "=== step 8: inject 2 more frames id=5 → expect [5]=7"
read -r p1 d1 m1 p1_c < <(read_stats_with_cidr)
for i in 1 2; do ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "10.5.0.1"; done
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + p1_c + 2 )) || true

c5_final=$(read_rc_slot_at "${rc_inner_B}" 5)
echo "post-flip+rebump: rule_counters_<active_B>[5]=${c5_final}"
if [[ "${c5_final}" != "7" ]]; then
    echo "FAIL[e1]: rule_counters_<active_B>[5]='${c5_final}' (expected 7 = 5 + 2)" >&2
    if [[ "${c5_final}" == "2" ]]; then
        echo "          got 2 — counter reset on flip + only new bumps counted" >&2
        echo "          (copy-forward broken AND bump-to-active works)" >&2
    fi
    fail=1
fi

# ── (9) post-flip bump on id=17: [17] → 4 ───────────────────────────────
echo "=== step 9: inject 1 more frame id=17 → expect [17]=4"
read -r p2 d2 m2 p2_c < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "10.17.0.1"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + p2_c + 1 )) || true

c17_final=$(read_rc_slot_at "${rc_inner_B}" 17)
echo "post-flip+rebump: rule_counters_<active_B>[17]=${c17_final}"
if [[ "${c17_final}" != "4" ]]; then
    echo "FAIL[e2]: rule_counters_<active_B>[17]='${c17_final}' (expected 4 = 3 + 1)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_RULE_COUNTERS_ATOMIC_SWAP"
exit "${fail}"
