#!/bin/bash
# T_CLI_RESET_COUNTERS — design §6.NN (MVP-3.4d / §5.35).
#
# `xdpmacfilter reset-counters --iface X` (no --rule-id) zeros ALL 64
# rule_counters slots; subsequent bumps work normally from a zero baseline.
# Maps to PI-3.4d-1 (CLI behavioural contract), HG-3.4d-1 (zero-write
# mechanism), HG-3.4d-2 (no-flag = batch), HG-3.4d-6 (audit-stderr format).
#
# Trigger:
#   1. setup_veth.
#   2. apply config_per_rule_counters.yaml (3 PASS+1 DROP rules, ids 0/5/17/42).
#   3. Inject 5 frames id=5, 3 frames id=17 (drop-but-still-bumps per §5.34),
#      2 frames id=0 (PASS).
#   4. Read baseline rule_counters → assert [0]=2, [5]=5, [17]=3, others=0.
#   5. Run `xdpmacfilter reset-counters --iface ${IFACE_A}`.
#   6. Read post-reset → assert ALL 64 slots = 0.
#   7. Re-inject 1 frame id=5.
#   8. Read final → assert [5]=1; all others (incl. [0], [17]) = 0.
#
# Observable outcome (ALL):
#   (a) reset-counters exits 0.
#   (b) stderr matches ERE
#       `^xdpmacfilter: RESET-COUNTERS on ${IFACE_A} by uid=[0-9]+ .*rule_id=ALL$`
#       (HG-3.4d-6 audit-line shape; permissive middle for uid/euid/sudo_user).
#   (c) All 64 PERCPU rule_counters slots read 0 post-reset (sum across CPUs).
#   (d) Post-reset bump works: rule_counters[5]=1 after re-inject.
#
# Sanity-floor smoke: step (a) — reset-counters exits 0 + audit-log present.
# Negation control: dual-bump-then-reset-then-rebump verifies reset
# ACTUALLY zeros (not just appears zero) AND post-reset BPF map writes
# don't clobber pin state. Step (d) catches the "reset destroyed the map"
# regression mode.
#
# RESOURCE_LOCK xdp_fixture (guard #12 — touches veth + bpffs pins).
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

# MACs in fixture (must match config_per_rule_counters.yaml exactly).
MAC_ID0="02:00:00:00:00:01"   # rule_id=0 PASS
SRC_MAC="02:00:00:00:00:aa"  # 5.43: MAC deferred; src_mac irrelevant
MAC_ID5="02:00:00:00:00:05"   # rule_id=5 PASS
MAC_ID17="02:00:00:00:00:11"  # rule_id=17 DROP — post-§5.34 cycle 2 STILL bumps counter

stderr_apply=$(mktemp /tmp/xdpmf-reset-apply.XXXXXX)
stderr_reset=$(mktemp /tmp/xdpmf-reset-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_apply}" "${stderr_reset}"' EXIT INT TERM HUP

sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

# ── helpers ──────────────────────────────────────────────────────────────
# Read active_idx (returns 0 or 1, empty on failure).
read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}

# Compute the per-cycle rule_counters pin path. Default ship = use
# rule_counters_<active>; D-3.4d-FALLBACK = single rule_counters pin.
# Both shapes are PERCPU_ARRAY<u64>[64] so read_rule_counters.py works
# against either path identically.
rule_counters_pin() {
    if sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
        local active; active=$(read_active_idx)
        case "${active}" in
            0) echo "${PIN_DIR}/rule_counters_a" ;;
            1) echo "${PIN_DIR}/rule_counters_b" ;;
            *) echo "${PIN_DIR}/rule_counters_a" ;;  # defensive default
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

read_rc_all() {
    local pin
    pin=$(rule_counters_pin)
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" "${pin}"
}

# ── apply + smoke ────────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_apply}"
rc=$?
set -e
echo "rc=${rc}"
cat "${stderr_apply}" >&2 || true

fail=0
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[apply]: apply exit ${rc} (expected 0)" >&2
    exit 1
fi
# At least one of the two rule_counters pin shapes must exist (default OR
# fallback). If neither, attach didn't ship counter pins — abort.
if ! sudo -n test -e "${PIN_DIR}/rule_counters" \
     && ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[apply.pin]: neither rule_counters NOR rule_counters_a pin exists" >&2
    exit 1
fi

# ── inject baseline bumps: 5xid5 + 3xid17 + 2xid0 ────────────────────────
echo "=== inject baseline: 5 x ${MAC_ID5} + 3 x ${MAC_ID17} + 2 x ${MAC_ID0}"
read -r p0 d0 m0 p0_c < <(read_stats_with_cidr)
for i in 1 2 3 4 5; do ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "10.5.0.1"; done
for i in 1 2 3;       do ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "10.17.0.1"; done
for i in 1 2;         do ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "10.0.0.1"; done
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + p0_c + 10 )) || true

# Read baseline rule_counters.
c0_pre=$(read_rc_slot 0)
c5_pre=$(read_rc_slot 5)
c17_pre=$(read_rc_slot 17)
echo "baseline rule_counters: [0]=${c0_pre} [5]=${c5_pre} [17]=${c17_pre}"
if [[ "${c5_pre}" != "5" || "${c17_pre}" != "3" || "${c0_pre}" != "2" ]]; then
    echo "FAIL[baseline]: expected [0]=2 [5]=5 [17]=3, got [0]=${c0_pre} [5]=${c5_pre} [17]=${c17_pre}" >&2
    echo "         test premise invalid — cannot exercise reset" >&2
    exit 1
fi

# ── reset-counters --iface (batch) ───────────────────────────────────────
echo "=== reset-counters --iface ${IFACE_A} (batch, no --rule-id)"
set +e
sudo -n "${LOADER_BIN}" reset-counters --iface "${IFACE_A}" 2>"${stderr_reset}"
rc_reset=$?
set -e
echo "reset rc=${rc_reset}"
echo "--- stderr ---"
cat "${stderr_reset}" >&2 || true
echo "--- end stderr ---"

# (a) exit 0
if [[ "${rc_reset}" -ne 0 ]]; then
    echo "FAIL[a]: reset-counters exit ${rc_reset} (expected 0)" >&2
    fail=1
fi

# (b) audit-log ERE — permissive middle for uid=/euid=/sudo_user= per §5.30 HK-4
# precedent (the bypass tests use the same `.*` middle-fill pattern).
audit_ere="^xdpmacfilter: RESET-COUNTERS on ${IFACE_A} by uid=[0-9]+ .*rule_id=ALL\$"
if ! grep -qE -- "${audit_ere}" "${stderr_reset}"; then
    echo "FAIL[b]: stderr missing audit-log line matching ERE:" >&2
    echo "        ${audit_ere}" >&2
    fail=1
fi

# (c) all 64 slots = 0 post-reset
echo "=== post-reset rule_counters dump"
all_post=$(read_rc_all)
echo "all 64 slots: ${all_post}"
nonzero_post=$(echo "${all_post}" | tr ' ' '\n' | grep -cvE '^0$' || true)
nonzero_post=${nonzero_post:-0}
if [[ "${nonzero_post}" != "0" ]]; then
    echo "FAIL[c]: post-reset rule_counters has ${nonzero_post} non-zero slot(s) (expected 0)" >&2
    fail=1
fi

# ── (d) re-inject 1 frame id=5 → rule_counters[5]=1 (post-reset bump works) ─
echo "=== re-inject 1 frame ${MAC_ID5} (rule_id=5) — post-reset baseline"
read -r p1 d1 m1 p1_c < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "10.5.0.1"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + p1_c + 1 )) || true

c5_final=$(read_rc_slot 5)
c0_final=$(read_rc_slot 0)
c17_final=$(read_rc_slot 17)
echo "post-reset+rebump rule_counters: [0]=${c0_final} [5]=${c5_final} [17]=${c17_final}"
if [[ "${c5_final}" != "1" ]]; then
    echo "FAIL[d1]: rule_counters[5]='${c5_final}' (expected 1) — reset broke bump path" >&2
    fail=1
fi
if [[ "${c0_final}" != "0" || "${c17_final}" != "0" ]]; then
    echo "FAIL[d2]: rule_counters[0]='${c0_final}' [17]='${c17_final}' (expected 0,0)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_CLI_RESET_COUNTERS"
exit "${fail}"
