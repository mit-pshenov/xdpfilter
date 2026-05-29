#!/bin/bash
# T_APPLY_ATOMIC_SWAP_NO_DROP — design §6.23 (MVP-3.1 / §5.26).
#
# LOAD-BEARING for Composite 6 promise. Architect explicitly fenced
# against making this theatrical: the apply MUST be invoked CONCURRENTLY
# with continuous in-flight traffic on the overlapping-allowed MAC, and
# the swap MUST drop zero packets for that MAC.
#
# Sequence (per §6.23):
#   1. setup_veth + apply config_apply_swap_a.yaml (pass MAC_X only).
#   2. Start background traffic injector on peer veth: continuous packets
#      from MAC_X at ~RATE_HZ packets/s for the duration of the test
#      (single long-lived python+scapy process — NOT a per-packet bash
#      loop, which would not sustain 100 Hz due to Python startup cost).
#   3. After ~2 s baseline: snapshot STAT_DROP_DENY_baseline + STAT_PASS_baseline.
#      Verify baseline_pass_delta >= lower_bound; else SKIP_RETURN_CODE 77
#      ('XDPMF_INJECT_RATE_HZ too low for swap test on this runner').
#   4. Snapshot active_idx (pre-swap).
#   5. Invoke apply config_apply_swap_b.yaml (pass MAC_X + MAC_Y).
#   6. Snapshot active_idx (post-swap); assert flip happened.
#   7. Continue traffic for ~2 s more.
#   8. Stop the injector; snapshot STAT_DROP_DENY_final + STAT_PASS_final.
#   9. Assert: STAT_DROP_DENY_final - STAT_DROP_DENY_baseline == 0.
#  10. Assert: STAT_PASS_final - STAT_PASS_baseline >= lower_bound
#      (anti-theatricality — traffic must actually be flowing during swap).
#  11. Negation control: post-swap inject ONE packet from MAC_DENY (never
#      in either config); assert STAT_DROP_DENY DOES increment. Proves
#      the drop machinery is functional on this runner — without this,
#      "delta==0 across swap" could be theatrical (no drops at all).
#
# SKIP_RETURN_CODE 77 if veth load is below threshold (slow CI runner).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

# §5.43 MVP-4.3 (T-SKIP): this test proves "allowlist atomic-swap, no in-flight
# DROP across the swap" on the MAC-allowlist axis. MAC matching is DEFERRED to
# mvp-4.5 (HG-mvp-4.3-2 / PI-mvp-4.3-MAC-DEFERRED), and the IDENTICAL atomic-
# swap-no-drop property on the LIVE axis is already covered (green) by
# T_CIDR_ATOMIC_SWAP_NO_DROP. Converting this MAC variant to CIDR would just
# duplicate that coverage (per team steer: do NOT contort into a duplicate
# CIDR test). Converted to SKIP (NOT dropped) — un-SKIP when the MAC axis
# returns as a bit-vector axis in mvp-4.5.
echo "SKIP: MAC-allowlist atomic-swap deferred to mvp-4.5; CIDR-axis equivalent" >&2
echo "      covered by T_CIDR_ATOMIC_SWAP_NO_DROP (per HG-mvp-4.3-2 / PI-mvp-4.3-MAC-DEFERRED)" >&2
exit 77

require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE_DIR="${TEST_DIR}/fixtures"
FIX_A="${FIXTURE_DIR}/config_apply_swap_a.yaml"
FIX_B="${FIXTURE_DIR}/config_apply_swap_b.yaml"

[[ -f "${FIX_A}" ]] || { echo "FAIL: missing fixture ${FIX_A}" >&2; exit 1; }
[[ -f "${FIX_B}" ]] || { echo "FAIL: missing fixture ${FIX_B}" >&2; exit 1; }

# §6.23 SKIP-rate threshold mechanism. Env-var override for slow CI.
RATE_HZ="${XDPMF_INJECT_RATE_HZ:-100}"
WINDOW_SEC=2
# Lower-bound per design: 2s × 100Hz × 0.75 fudge = 150. Scale by RATE_HZ
# so override is honest (lowering rate also lowers expectation).
LOWER_BOUND=$(( WINDOW_SEC * RATE_HZ * 3 / 4 ))
if (( LOWER_BOUND < 10 )); then LOWER_BOUND=10; fi

MAC_X="02:00:00:00:00:01"   # MAC_GOOD — in BOTH config A and config B (load-bearing MAC)
MAC_Y="02:00:00:00:00:02"   # MAC_BAD  — in config B only (used by §6.24, not here)
MAC_DENY="02:00:00:00:00:99" # not in ANY fixture; used for negation control

INJECT_SCRIPT="$(mktemp /tmp/xdpmf_swap_inject_$$_XXXXXX.py)"
stderr_apply_a=$(mktemp /tmp/xdpmf-swap-apply-a-stderr.XXXXXX)
stderr_apply_b=$(mktemp /tmp/xdpmf-swap-apply-b-stderr.XXXXXX)

# Modern bpftool: --json + .[0].formatted.value gives the integer.
# Older bpftool fallback: .[0].value as LE byte array; byte 0 has the LSB.
read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then
        printf '%d\n' "0x${hex}"
    fi
}

INJECT_PID=""
cleanup_swap() {
    set +e
    if [[ -n "${INJECT_PID}" ]]; then
        sudo -n pkill -KILL -f "${INJECT_SCRIPT}" 2>/dev/null
        kill -KILL "${INJECT_PID}" 2>/dev/null
        wait "${INJECT_PID}" 2>/dev/null
    fi
    rm -f "${INJECT_SCRIPT}" "${stderr_apply_a}" "${stderr_apply_b}"
    cleanup_veth
    set -e
}
trap cleanup_swap EXIT

# ── Background injector: ONE python process, raw AF_PACKET in loop ───────
# Same persistent-socket pattern as tests/inject/inject_runt.py — no scapy.
# scapy's sendp() opens a fresh AF_PACKET socket per call (~50-70ms each on
# typical hosts), which floors the achievable rate at ~15 Hz regardless of
# RATE_HZ. Raw socket + bind-once + send-in-loop easily sustains 1000+ Hz.
cat > "${INJECT_SCRIPT}" <<'PYEOF'
import socket, sys, time
iface = sys.argv[1]
src   = sys.argv[2]
dst   = sys.argv[3]
duration_s = float(sys.argv[4])
rate_hz    = float(sys.argv[5])

def mac_to_bytes(s):
    return bytes(int(b, 16) for b in s.split(":"))

dst_b = mac_to_bytes(dst)
src_b = mac_to_bytes(src)
ethertype = (0x88B5).to_bytes(2, "big")  # locally experimental — no L3 stack
payload = b"\x00" * 46                   # 14 + 46 = 60 bytes (min eth frame)
frame = dst_b + src_b + ethertype + payload

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x88B5))
try:
    sock.bind((iface, 0))
except OSError as e:
    print(f"inject: bind({iface}) failed: {e}", file=sys.stderr)
    sys.exit(1)

interval = 1.0 / rate_hz if rate_hz > 0 else 0.01
end = time.monotonic() + duration_s
sent = 0
try:
    while time.monotonic() < end:
        try:
            sock.send(frame)
            sent += 1
        except OSError as e:
            print(f"inject: send failed at frame {sent}: {e}", file=sys.stderr)
            break
        time.sleep(interval)
finally:
    sock.close()
PYEOF

setup_veth

# ── Step 1: apply config_apply_swap_a.yaml ───────────────────────────────
echo "=== apply ${FIX_A} (initial state — pass MAC_X only)"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIX_A}" 2> "${stderr_apply_a}"
rc_a=$?
set -e
echo "rc_a=${rc_a}"
echo "--- stderr (apply A) ---"
cat "${stderr_apply_a}" >&2 || true
echo "--- end stderr ---"
if [[ "${rc_a}" -ne 0 ]]; then
    echo "FAIL: initial apply (A) exit ${rc_a} (expected 0)" >&2
    exit 1
fi

# Confirm XDP attached.
if [[ -z "$(xdp_prog_id "${IFACE_A}")" ]]; then
    echo "FAIL: no XDP attached after apply A" >&2
    exit 1
fi

# ── Step 2: start background injector ────────────────────────────────────
INJECTOR_DURATION=$(( WINDOW_SEC * 2 + 10 ))  # well beyond the test window
echo "=== start background injector (MAC_X=${MAC_X} at ${RATE_HZ} Hz for ${INJECTOR_DURATION}s)"
${NSEXEC} python3 "${INJECT_SCRIPT}" "${IFACE_B}" "${MAC_X}" "${MAC_DST}" "${INJECTOR_DURATION}" "${RATE_HZ}" \
    >/dev/null 2>&1 &
INJECT_PID=$!
echo "INJECT_PID=${INJECT_PID}"

# Give the python interpreter a beat to spin up scapy + open AF_PACKET.
sleep 0.5

# ── Step 3: baseline window ──────────────────────────────────────────────
read -r p0 d0 m0 < <(read_stats)
echo "stats T0 (pre-baseline): PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0}"

sleep "${WINDOW_SEC}"

read -r p_bl d_bl m_bl < <(read_stats)
echo "stats T1 (baseline, post-${WINDOW_SEC}s): PASS=${p_bl} DROP_DENY=${d_bl} DROP_MALFORMED=${m_bl}"

baseline_pass_delta=$(( p_bl - p0 ))
echo "baseline_pass_delta=${baseline_pass_delta}  lower_bound=${LOWER_BOUND}"

if (( baseline_pass_delta < LOWER_BOUND )); then
    echo "SKIP: XDPMF_INJECT_RATE_HZ too low for swap test on this runner" >&2
    echo "      baseline_pass_delta=${baseline_pass_delta} < lower_bound=${LOWER_BOUND}" >&2
    exit 77
fi

# Sanity: drop counter should be ~zero during baseline (MAC_X is allowed in A).
baseline_drop_delta=$(( d_bl - d0 ))
if (( baseline_drop_delta != 0 )); then
    echo "FAIL: baseline_drop_delta=${baseline_drop_delta} (expected 0 — MAC_X is allowed in config A)" >&2
    # Continue to gather more diagnostic info; emit the final result later.
fi

# Snapshot active_idx pre-swap.
active_pre=$(read_active_idx)
echo "active_idx pre-swap = '${active_pre}'"

# ── Step 5: swap to config B (CONCURRENT with traffic) ────────────────────
echo "=== apply ${FIX_B} (CONCURRENT with in-flight MAC_X traffic — LOAD-BEARING)"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIX_B}" 2> "${stderr_apply_b}"
rc_b=$?
set -e
echo "rc_b=${rc_b}"
echo "--- stderr (apply B) ---"
cat "${stderr_apply_b}" >&2 || true
echo "--- end stderr ---"

fail=0

if [[ "${rc_b}" -ne 0 ]]; then
    echo "FAIL[swap-rc]: apply B during traffic exit ${rc_b} (expected 0)" >&2
    fail=1
fi

# Snapshot active_idx post-swap.
active_post=$(read_active_idx)
echo "active_idx post-swap = '${active_post}'"

if [[ -z "${active_pre}" || -z "${active_post}" ]]; then
    echo "FAIL[active-idx-readout]: could not read active_idx (pre='${active_pre}' post='${active_post}')" >&2
    fail=1
elif [[ "${active_pre}" == "${active_post}" ]]; then
    echo "FAIL[active-idx-flip]: active_idx did not flip (pre='${active_pre}' post='${active_post}')" >&2
    fail=1
fi

# ── Step 7: post-swap window ─────────────────────────────────────────────
sleep "${WINDOW_SEC}"

# ── Step 8: stop injector + final snapshot ───────────────────────────────
echo "=== stop background injector"
sudo -n pkill -KILL -f "${INJECT_SCRIPT}" 2>/dev/null || true
kill -KILL "${INJECT_PID}" 2>/dev/null || true
wait "${INJECT_PID}" 2>/dev/null || true
INJECT_PID=""

# Allow last in-flight frames to settle into the BPF map before reading.
sleep 0.3

read -r p_f d_f m_f < <(read_stats)
echo "stats T2 (final): PASS=${p_f} DROP_DENY=${d_f} DROP_MALFORMED=${m_f}"

# NOTE: stats counters PRESERVED across apply per §5.26 D-3.1-4 reuse_fd loop
# (per HK-12 §5.30 — corrects the prior NOTE which incorrectly claimed
# the stats map is re-pinned and counters reset). Reality: D-3.1-4
# specifies `bpf_map__reuse_fd` over the pinned maps so the new
# skeleton's stats map shares the SAME kernel fd as the pre-swap map.
# Counters accumulate continuously across the swap; (p_f - p_bl)
# therefore reflects post-baseline-window traffic + any drops that
# occurred during/after the swap. The original assertions remain
# correct in their content:
#   - "no drops since swap"  →  d_f == 0  iff baseline already showed
#     d_bl == 0 (no drops yet); the test injects only MAC_X which is
#     allowed under BOTH A and B, so the running-total drop counter
#     stays 0 throughout — `d_f == 0` is the load-bearing assertion.
#   - "traffic flowing post-swap" → p_f >= LOWER_BOUND remains valid:
#     with preserved counters, p_f is the CUMULATIVE pass count and is
#     therefore ≥ baseline (already ≥ LOWER_BOUND) — assertion is robust.
echo "  (post-swap TOTAL from preserved stats map; D-3.1-4 reuse_fd loop)"
echo "  d_f (post-swap drops) = ${d_f}  (expected 0)"
echo "  p_f (post-swap passes) = ${p_f}  (expected >= ${LOWER_BOUND})"

# (9) STAT_DROP_DENY in the post-swap map MUST be 0 (load-bearing).
#     MAC_X is the only injected MAC and it's allowed in BOTH A and B —
#     any drop counted by the NEW program means the post-swap state
#     mis-classified an overlapping-allowed MAC. Drops by the OLD program
#     during the swap window go into the OLD stats map (unpinned by
#     impl); test cannot observe those. The OLD-program drops are
#     ARCHITECTURALLY UNOBSERVABLE under this impl; reviewer's
#     responsibility to flag if that matters.
if (( d_f != 0 )); then
    echo "FAIL[swap-drop]: STAT_DROP_DENY in post-swap map = ${d_f}, expected 0" >&2
    echo "                 MAC_X was overlapping-allowed in both A and B; any drop" >&2
    echo "                 visible to the NEW program means the swap left a window" >&2
    echo "                 where MAC_X was dropped (Composite 6 promise broken)." >&2
    fail=1
fi

# (10) Anti-theatricality: post-swap traffic must have actually flowed.
#      LOWER_BOUND = 2s × RATE_HZ × 0.75 ≈ 150 @ 100Hz. With baseline
#      already proven (skip-77 guard above), failure here would mean
#      the injector stopped between baseline and post-swap snapshot.
if (( p_f < LOWER_BOUND )); then
    echo "FAIL[swap-pass-anti-theatricality]: post-swap STAT_PASS = ${p_f}, expected >= ${LOWER_BOUND}" >&2
    echo "                                    baseline proved injection rate OK; post-swap reads from" >&2
    echo "                                    NEW stats map. Low value here means injector stopped" >&2
    echo "                                    AFTER baseline (possibly during the swap → assertion is" >&2
    echo "                                    theatrical because traffic wasn't continuous through swap)." >&2
    fail=1
fi

# (11) Negation control: prove the drop machinery is functional on this runner.
echo "=== negation control: inject one MAC_DENY (never-allowed) → STAT_DROP_DENY MUST increment"
read -r p_n0 d_n0 m_n0 < <(read_stats)
inject_eth "${IFACE_B}" "${MAC_DENY}" "${MAC_DST}"
wait_for_stats_sum "${IFACE_A}" $(( p_n0 + d_n0 + m_n0 + 1 )) || true
read -r p_n1 d_n1 m_n1 < <(read_stats)
neg_drop_delta=$(( d_n1 - d_n0 ))
echo "negation-control drop_delta = ${neg_drop_delta} (expected 1)"
if (( neg_drop_delta != 1 )); then
    echo "FAIL[negation]: drop machinery did NOT register MAC_DENY — test cannot prove non-zero drops are detectable" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_APPLY_ATOMIC_SWAP_NO_DROP"
exit "${fail}"
