#!/bin/bash
# T_LINK_PERSIST_ACROSS_LOADER_EXIT — design §6.25 (MVP-3.1 / §5.26).
#
# LOAD-BEARING for P0a per HG2. Reviewer's 5th framework point asserts
# this test actually verifies enforcement on FRESH traffic after the
# loader process has exited — not just "pin file exists on bpffs".
#
# Sequence (per §6.25):
#   1. setup_veth; apply config_apply_swap_a.yaml (pass MAC_X only).
#      Foreground apply exits 0 — this IS the loader-exit event.
#   2. Confirm pin exists: ${PIN_DIR}/link.
#   3. Confirm XDP slot occupied: xdp_prog_id returns non-empty.
#   4. (apply already exited — no loader process to kill.)
#   5. Wait 1 s (defensive — give kernel any async settle).
#      Belt-and-suspenders: pkill -9 -f xdpmacfilter to assert NO zombie.
#   6. Inject 1 packet from MAC_X → STAT_PASS += 1 (filter alive).
#   7. Inject 1 packet from MAC_Y → STAT_DROP_DENY += 1 (default drop alive).
#   8. Re-invoke apply config_apply_swap_b.yaml (exercises
#      bpf_link__update_program — idempotent reattach over the pinned link).
#   9. Inject 1 packet from MAC_Y → STAT_PASS += 1 (new ruleset took effect).
#
# Sanity-floor smoke: step 1 (apply succeeds + pins created) IS the
# smoke test. Negation control: step 7 (denied MAC → drop counter
# moves) proves the filter is genuinely enforcing, not just "rubber
# stamping". Step 9 (denied MAC becomes allowed after re-apply) is
# the bidirectional control.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE_DIR="${TEST_DIR}/fixtures"
FIX_A="${FIXTURE_DIR}/config_apply_swap_a.yaml"
FIX_B="${FIXTURE_DIR}/config_apply_swap_b.yaml"

[[ -f "${FIX_A}" ]] || { echo "FAIL: missing fixture ${FIX_A}" >&2; exit 1; }
[[ -f "${FIX_B}" ]] || { echo "FAIL: missing fixture ${FIX_B}" >&2; exit 1; }

stderr_apply_a=$(mktemp /tmp/xdpmf-persist-apply-a-stderr.XXXXXX)
stderr_apply_b=$(mktemp /tmp/xdpmf-persist-apply-b-stderr.XXXXXX)

cleanup_persist() {
    set +e
    # Per §6.25 cleanup + HK-10 §5.30 fix: pkill any zombie that matches
    # OUR iface's argv (NOT a broad `-f xdpmacfilter` which would clobber
    # any concurrent xdpmacfilter invocation belonging to a parallel test
    # session). Iface-scoped match: the loader's argv always carries
    # `--iface ${IFACE_A}`, so the regex `xdpmacfilter.*${IFACE_A}` matches
    # only our own loader processes. Unlink the link pin (last reference
    # drop should trigger kernel-side XDP detach).
    sudo -n pkill -9 -f "xdpmacfilter.*${IFACE_A}" 2>/dev/null
    sudo -n rm -f "${PIN_DIR}/link" 2>/dev/null
    cleanup_veth
    rm -f "${stderr_apply_a}" "${stderr_apply_b}"
    set -e
}
trap cleanup_persist EXIT

MAC_X="02:00:00:00:00:01"   # in A (and B)
MAC_Y="02:00:00:00:00:02"   # in B only; denied under A

setup_veth

fail=0

# ── Step 1: apply A (loader exits after) ─────────────────────────────────
echo "=== step 1: apply ${FIX_A} (foreground; loader exits on success)"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIX_A}" 2> "${stderr_apply_a}"
rc_a=$?
set -e
echo "rc_a=${rc_a}"
echo "--- stderr (apply A) ---"
cat "${stderr_apply_a}" >&2 || true
echo "--- end stderr ---"

# Per §5.26 trust_model stderr sub-decision: apply ALWAYS logs `trust_model=<mode>` at attach entry.
# §6.25 asserts the format here per design.md:4370-4371. [POST-REVIEW SWEEP round 1]
if ! grep -qE 'xdpmacfilter: trust_model=strict' "${stderr_apply_a}"; then
    echo "FAIL[1b]: stderr missing 'xdpmacfilter: trust_model=strict' log line" >&2
    fail=1
fi

if [[ "${rc_a}" -ne 0 ]]; then
    echo "FAIL[1]: apply A exit ${rc_a} (expected 0)" >&2
    fail=1
fi

# Step-3.5 SKIP probe: if bpf_link__pin is unsupported, stderr will say so.
# Per §6.25: if 'bpf_link__pin unsupported' in stderr → exit 77.
if grep -qE -- 'bpf_link__pin .* unsupported|ENOSYS' "${stderr_apply_a}"; then
    echo "SKIP: bpf_link__pin unsupported on this kernel" >&2
    exit 77
fi

# ── Step 2: link pin must exist ──────────────────────────────────────────
if ! sudo -n test -e "${PIN_DIR}/link"; then
    echo "FAIL[2]: ${PIN_DIR}/link does NOT exist after apply — P0a pin missing" >&2
    fail=1
fi

# ── Step 3: XDP slot must be occupied ───────────────────────────────────
prog_after_apply=$(xdp_prog_id "${IFACE_A}")
if [[ -z "${prog_after_apply}" ]]; then
    echo "FAIL[3]: no XDP attached to ${IFACE_A} after apply" >&2
    fail=1
fi
echo "prog_id after apply = '${prog_after_apply}'"

# ── Step 4: loader process — assert none left running ────────────────────
# Apply exited foreground; nothing to kill. But assert no zombie tied to
# OUR iface (HK-10 §5.30: iface-scoped pgrep/pkill to avoid clobbering a
# parallel session's loader processes).
if pgrep -f "xdpmacfilter.*${IFACE_A}" >/dev/null 2>&1; then
    echo "WARN: found a running xdpmacfilter process targeting ${IFACE_A} — apply should have exited" >&2
    # Belt-and-suspenders kill per §6.25 step 10 (optional), iface-scoped.
    sudo -n pkill -9 -f "xdpmacfilter.*${IFACE_A}" 2>/dev/null || true
    sleep 0.2
fi

# ── Step 5: defensive settle ─────────────────────────────────────────────
sleep 1.0

# Confirm pin + XDP STILL there after the 1 s wait.
if ! sudo -n test -e "${PIN_DIR}/link"; then
    echo "FAIL[5a]: ${PIN_DIR}/link disappeared during 1s wait" >&2
    fail=1
fi
prog_after_wait=$(xdp_prog_id "${IFACE_A}")
if [[ -z "${prog_after_wait}" ]]; then
    echo "FAIL[5b]: XDP detached during 1s wait (loader-exit broke persistence)" >&2
    fail=1
fi

# ── Step 6: inject MAC_X → STAT_PASS += 1 (filter alive!) ───────────────
echo "=== step 6: inject MAC_X (allowed under A) — filter MUST still enforce"
read -r p0 d0 m0 < <(read_stats)
inject_eth "${IFACE_B}" "${MAC_X}" "${MAC_DST}"
wait_for_stats_sum "${IFACE_A}" $(( p0 + d0 + m0 + 1 )) || true
read -r p1 d1 m1 < <(read_stats)
echo "  stats: PASS=${p1} DROP_DENY=${d1} (delta P=$(( p1-p0 )) D=$(( d1-d0 )))"
if (( p1 - p0 != 1 )); then
    echo "FAIL[6]: expected STAT_PASS delta=1 (MAC_X passes post-loader-exit), got $(( p1-p0 ))" >&2
    echo "        P0a load-bearing assertion: filter must still allow MAC_X after apply exits." >&2
    fail=1
fi

# ── Step 7: inject MAC_Y → STAT_DROP_DENY += 1 (default drop alive!) ────
echo "=== step 7: inject MAC_Y (denied under A) — default-drop MUST still enforce"
read -r p2 d2 m2 < <(read_stats)
inject_eth "${IFACE_B}" "${MAC_Y}" "${MAC_DST}"
wait_for_stats_sum "${IFACE_A}" $(( p2 + d2 + m2 + 1 )) || true
read -r p3 d3 m3 < <(read_stats)
echo "  stats: PASS=${p3} DROP_DENY=${d3} (delta P=$(( p3-p2 )) D=$(( d3-d2 )))"
if (( d3 - d2 != 1 )); then
    echo "FAIL[7]: expected STAT_DROP_DENY delta=1 (MAC_Y dropped post-loader-exit), got $(( d3-d2 ))" >&2
    echo "        P0a load-bearing: default-drop policy must still enforce after loader exit." >&2
    fail=1
fi

# ── Step 8: re-apply B (idempotent reattach via bpf_link__update_program) ─
echo "=== step 8: re-apply ${FIX_B} (exercises bpf_link__update_program)"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIX_B}" 2> "${stderr_apply_b}"
rc_b=$?
set -e
echo "rc_b=${rc_b}"
echo "--- stderr (apply B) ---"
cat "${stderr_apply_b}" >&2 || true
echo "--- end stderr ---"

if [[ "${rc_b}" -ne 0 ]]; then
    echo "FAIL[8]: re-apply B exit ${rc_b} (expected 0 — idempotent reattach)" >&2
    fail=1
fi

# ── Step 9: inject MAC_Y → STAT_PASS += 1 (new ruleset took effect) ─────
echo "=== step 9: inject MAC_Y (now allowed under B)"
read -r p4 d4 m4 < <(read_stats)
inject_eth "${IFACE_B}" "${MAC_Y}" "${MAC_DST}"
wait_for_stats_sum "${IFACE_A}" $(( p4 + d4 + m4 + 1 )) || true
read -r p5 d5 m5 < <(read_stats)
echo "  stats: PASS=${p5} DROP_DENY=${d5} (delta P=$(( p5-p4 )) D=$(( d5-d4 )))"
if (( p5 - p4 != 1 )); then
    echo "FAIL[9]: expected STAT_PASS delta=1 (MAC_Y now allowed under B), got $(( p5-p4 ))" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_LINK_PERSIST_ACROSS_LOADER_EXIT"
exit "${fail}"
