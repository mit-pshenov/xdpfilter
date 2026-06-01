#!/bin/bash
# T_RULE_COUNTER_SURVIVES_APPLY — design §6.49 (MVP-3.4b cycle 1 / §5.31).
#
# **LOAD-BEARING canary** for HG-3.4b-2 + PI-3.4b-2 — counter survival
# across `apply -f` via PIN_BY_NAME + reuse_fd discipline (D-3.4b-2).
# Prometheus counter-monotonicity semantic: if operator-visible counter
# resets on every apply, alerting + rate() queries break.
#
# Trigger:
#   1. setup_veth + apply config_per_rule_counters.yaml.
#   2. Inject 7 frames from MAC of rule_id=5 → rule_counters[5] == 7.
#   3. RE-apply the SAME config_per_rule_counters.yaml (forces an
#      active_idx swap_count++; same rules, same ids).
#   4. Assert rule_counters[5] STILL == 7 (NOT 0) — the survival contract.
#   5. Inject 3 more frames → rule_counters[5] == 10 (continuation from 7).
#
# Observable outcome (ALL must hold):
#   (a) After step 2: rule_counters[5] == 7.
#   (b) active_idx flips between step 1 and step 3 (proves a real apply
#       was performed, not a no-op).
#   (c) After step 3: rule_counters[5] STILL == 7 (LOAD-BEARING — if
#       counter reset to 0 here, HG-3.4b-2 is violated; impl peer-DM
#       architect; likely root cause is missing kManagedMaps[] 13th
#       entry in the reuse_fd loop).
#   (d) After step 5: rule_counters[5] == 10 (continued counting from 7,
#       NOT 3).
#
# Sanity-floor smoke: step (a) — apply + first bump-and-read works.
# Negation control: this entire test IS the negation against the
# "counter-resets-on-apply" failure mode. The differential assertion
# (rule_counters[5] before vs. after the second apply) catches the
# regression. If reuse_fd discipline is broken, this fails LOUDLY.
#
# Maps to: PI-3.4b-2 (counter survival), HG-3.4b-2, D-3.4b-2, D-3.4b-13
# (kManagedMaps[] HK-9 dividend — 13th entry walks all 3 loops).
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

MAC_ID5="02:00:00:00:00:05"   # rule_id=5 PASS
SRC_MAC="02:00:00:00:00:aa"  # 5.43: MAC deferred; src_mac irrelevant

stderr_file=$(mktemp /tmp/xdpmf-rulesurv-stderr.XXXXXX)
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

# §5.35 (MVP-3.4d) fixture-ripple: single `rule_counters` PERCPU_ARRAY
# pin RETIRED; replaced by `rule_counters_<a|b>` inners under
# `rule_counters_outer` ARRAY_OF_MAPS. Reads must follow active_idx.
# This test specifically validates PI-3.4b-2 PRESERVE-across-apply held
# via D-3.4d-3 apply-step copy-forward — so reading the CURRENT active
# inner after each apply observes the preserved values.
rule_counters_active_pin() {
    local active; active=$(read_active_idx)
    case "${active}" in
        0) echo "${PIN_DIR}/rule_counters_a" ;;
        1) echo "${PIN_DIR}/rule_counters_b" ;;
        *) echo "${PIN_DIR}/rule_counters_a" ;;
    esac
}
read_rc_slot() {
    # §5.61 (B30): rule_counters is slot-keyed; remap operator id -> slot
    # via slot_rule_id (D-mvp-4.21-RAWMAP-REMAP). Assertion values unchanged.
    read_rule_counter_by_id "${IFACE_A}" "$(rule_counters_active_pin)" "$1"
}

read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}

# ── (1) initial apply ────────────────────────────────────────────────────
echo "=== step 1: initial apply ${FIXTURE}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
cat "${stderr_file}" >&2 || true

fail=0
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[1]: initial apply exit ${rc} (expected 0)" >&2
    fail=1
fi
if ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[1.pin]: ${PIN_DIR}/rule_counters_a pin missing — cannot proceed" >&2
    exit 1
fi

active_1=$(read_active_idx)
echo "active_idx after step 1 = '${active_1}'"

# ── (2) inject 7 frames → rule_counters[5] == 7 ──────────────────────────
echo "=== step 2: inject 7 frames src=${MAC_ID5}"
read -r p0 d0 m0 p0_c < <(read_stats_with_cidr)
for i in 1 2 3 4 5 6 7; do
    ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "10.5.0.1"
done
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + p0_c + 7 )) || true

c5_after_step2=$(read_rc_slot 5)
echo "rule_counters[5] after step 2 = ${c5_after_step2} (expected 7)"
if [[ "${c5_after_step2}" != "7" ]]; then
    echo "FAIL[2]: rule_counters[5]='${c5_after_step2}' (expected 7) — bump-on-MAC-hit broken" >&2
    fail=1
fi

# ── (3) RE-apply the SAME config → forces active_idx swap ───────────────
echo "=== step 3: RE-apply ${FIXTURE} (force swap_count++)"
: >"${stderr_file}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc2=$?
set -e
echo "rc2=${rc2}"
cat "${stderr_file}" >&2 || true

if [[ "${rc2}" -ne 0 ]]; then
    echo "FAIL[3]: re-apply exit ${rc2} (expected 0)" >&2
    fail=1
fi

active_2=$(read_active_idx)
echo "active_idx after step 3 = '${active_2}'"
# (b) The active_idx should have flipped (proves a real apply happened).
if [[ -n "${active_1}" && -n "${active_2}" && "${active_2}" == "${active_1}" ]]; then
    echo "FAIL[3.idx]: active_idx did NOT flip across re-apply (still '${active_2}')" >&2
    echo "             a non-flip means the swap mechanism is broken — test premise invalid" >&2
    fail=1
fi

# ── (4) LOAD-BEARING ASSERTION: rule_counters[5] STILL == 7 ─────────────
c5_after_step3=$(read_rc_slot 5)
echo "rule_counters[5] after re-apply = ${c5_after_step3} (LOAD-BEARING: expected STILL 7)"
if [[ "${c5_after_step3}" != "7" ]]; then
    echo "FAIL[4]: rule_counters[5]='${c5_after_step3}' after re-apply (expected STILL 7)" >&2
    echo "         HG-3.4b-2 PRESERVE-counter-across-apply contract VIOLATED" >&2
    echo "         Likely root cause: kManagedMaps[] missing rule_counters entry in reuse_fd loop" >&2
    echo "         (HK-9 13th-entry table-walk dividend not collected)" >&2
    fail=1
fi

# ── (5) inject 3 more → rule_counters[5] == 10 (continuation) ────────────
echo "=== step 5: inject 3 more frames src=${MAC_ID5} (continuation from 7)"
read -r p_pre5 d_pre5 m_pre5 p_pre5_c < <(read_stats_with_cidr)
for i in 1 2 3; do
    ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "10.5.0.1"
done
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p_pre5 + d_pre5 + m_pre5 + p_pre5_c + 3 )) || true

c5_after_step5=$(read_rc_slot 5)
echo "rule_counters[5] after step 5 = ${c5_after_step5} (expected 10)"
if [[ "${c5_after_step5}" != "10" ]]; then
    echo "FAIL[5]: rule_counters[5]='${c5_after_step5}' (expected 10 = 7 + 3)" >&2
    if [[ "${c5_after_step5}" == "3" ]]; then
        echo "         got 3 — counter reset on re-apply + new bumps counted only ⇒ "
        echo "         survival contract still broken (delayed reset?)"
    fi
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_RULE_COUNTER_SURVIVES_APPLY"
exit "${fail}"
