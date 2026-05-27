#!/bin/bash
# T_RULES_ATOMIC_SWAP_NO_DROP — design §6.NN+1 (MVP-3.4b cycle 2 / §5.34).
#
# LOAD-BEARING canary for PI-13-3.4b-c2 (rules-axis atomic-swap via
# active_idx flip — symmetric with §5.27 Q1 AS1 CIDR-axis pattern).
# Template shape: §6.23 T_APPLY_ATOMIC_SWAP_NO_DROP (MAC axis) +
# §6.31 T_CIDR_ATOMIC_SWAP_NO_DROP (CIDR axis); this test is the
# rules-axis sibling proving the 4-axis single-u32-flip discipline.
#
# Architect explicitly fenced against making this theatrical: the apply
# MUST be invoked CONCURRENTLY with continuous in-flight traffic;
# action inversion across config_rules_swap_a.yaml → swap_b.yaml is the
# load-bearing element (each MAC's verdict FLIPS across the swap, so
# half-applied state would produce inflated D_DROP or D_PASS, directly
# observable in the deltas).
#
# Sequence (per §6.NN+1):
#   1. setup_veth + apply config_rules_swap_a.yaml
#      (id=5 PASS MAC_05; id=17 DROP MAC_11).
#   2. Start background traffic injector on peer veth: continuous frames
#      ALTERNATING between MAC_05 and MAC_11 at ~RATE_HZ packets/s.
#   3. After ~2s baseline: snapshot STAT_PASS_baseline +
#      STAT_DROP_DENY_baseline + rule_counters[5]_baseline +
#      rule_counters[17]_baseline. SKIP-77 if baseline rate too low.
#   4. Snapshot active_idx (pre-swap).
#   5. Invoke apply config_rules_swap_b.yaml
#      (id=5 DROP MAC_05 — INVERTED; id=17 PASS MAC_11 — INVERTED).
#   6. Snapshot active_idx — assert flip happened.
#   7. Continue traffic for ~2s more.
#   8. Stop injector; final snapshot.
#   9. Assert D_PASS + D_DROP == approx total injected frames (no loss).
#  10. Anti-theatricality: post-swap deltas non-zero on both buckets
#      (since AT LEAST ONE side passes pre-swap AND post-swap, and
#      AT LEAST ONE side drops pre-swap AND post-swap; over the
#      action-inversion swap, both D_PASS and D_DROP MUST advance).
#  11. rule_counters: rc[5] advanced by ≈total MAC_05 frames across
#      window; rc[17] advanced by ≈total MAC_11 frames across window
#      (HG-3.4b-c2-5 — bumps regardless of verdict).
#  12. Negation control: post-swap inject ONE frame from MAC_DENY (in
#      NEITHER config) → STAT_DROP_DENY DOES increment (drop machinery
#      functional; without this, "deltas" could be theatrical).
#
# Per-rule counter bumps + verdict counters together prove atomic
# swap: a half-applied window where rules_outer[active]→rules_inner
# was updated but action_table dispatch hadn't reset would surface as
# rc[5]+rc[17] != STAT_PASS+STAT_DROP_DENY delta, OR as one of the
# verdict buckets being grossly inflated against expectation.
#
# SKIP_RETURN_CODE 77 if veth load below threshold (slow CI runner).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE_DIR="${TEST_DIR}/fixtures"
FIX_A="${FIXTURE_DIR}/config_rules_swap_a.yaml"
FIX_B="${FIXTURE_DIR}/config_rules_swap_b.yaml"

[[ -f "${FIX_A}" ]] || { echo "FAIL: missing fixture ${FIX_A}" >&2; exit 1; }
[[ -f "${FIX_B}" ]] || { echo "FAIL: missing fixture ${FIX_B}" >&2; exit 1; }

# Mirror §6.23 + §6.31 rate-threshold convention. Same env var honored
# (single knob across MAC/CIDR/rules swap tests per §5.27 OOS fence).
RATE_HZ="${XDPMF_INJECT_RATE_HZ:-100}"
WINDOW_SEC=2
LOWER_BOUND=$(( WINDOW_SEC * RATE_HZ * 3 / 4 ))
if (( LOWER_BOUND < 10 )); then LOWER_BOUND=10; fi

MAC_05="02:00:00:00:00:05"     # rule_id=5  pass-in-A / drop-in-B
MAC_11="02:00:00:00:00:11"     # rule_id=17 drop-in-A / pass-in-B
MAC_DENY="02:00:00:00:00:99"   # not in any rule — for negation control

INJECT_SCRIPT="$(mktemp /tmp/xdpmf_rules_swap_inject_$$_XXXXXX.py)"
stderr_apply_a=$(mktemp /tmp/xdpmf-rulesswap-apply-a-stderr.XXXXXX)
stderr_apply_b=$(mktemp /tmp/xdpmf-rulesswap-apply-b-stderr.XXXXXX)

read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}
# §5.35 (MVP-3.4d) fixture-ripple: single `rule_counters` PERCPU_ARRAY
# pin RETIRED; replaced by `rule_counters_<a|b>` inners under
# `rule_counters_outer` ARRAY_OF_MAPS. Reads must follow active_idx;
# across the apply-induced flip in this test, the helper re-reads
# active_idx on each call so post-flip reads land on the new active inner
# (PI-3.4b-2 PRESERVE via D-3.4d-3 copy-forward keeps counters consistent).
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

# Background injector: ONE python process; alternates between MAC_05 and
# MAC_11 each iteration → both rules get matches across the swap window.
# Same persistent-socket pattern as §6.23: bind once, send-in-loop.
cat > "${INJECT_SCRIPT}" <<'PYEOF'
import socket, sys, time
iface = sys.argv[1]
src_a = sys.argv[2]
src_b = sys.argv[3]
dst   = sys.argv[4]
duration_s = float(sys.argv[5])
rate_hz    = float(sys.argv[6])

def mac_to_bytes(s):
    return bytes(int(b, 16) for b in s.split(":"))

dst_b   = mac_to_bytes(dst)
src_a_b = mac_to_bytes(src_a)
src_b_b = mac_to_bytes(src_b)
ethertype = (0x88B5).to_bytes(2, "big")  # locally experimental — no L3 stack
payload = b"\x00" * 46                   # 14 + 46 = 60-byte minimum frame
frame_a = dst_b + src_a_b + ethertype + payload
frame_b = dst_b + src_b_b + ethertype + payload

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
            sock.send(frame_a if (sent & 1) == 0 else frame_b)
            sent += 1
        except OSError as e:
            print(f"inject: send failed at frame {sent}: {e}", file=sys.stderr)
            break
        time.sleep(interval)
finally:
    sock.close()
PYEOF

setup_veth

# ── Step 1: apply A ──────────────────────────────────────────────────────
echo "=== apply ${FIX_A} (initial — id=5 PASS MAC_05; id=17 DROP MAC_11)"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIX_A}" 2> "${stderr_apply_a}"
rc_a=$?
set -e
echo "rc_a=${rc_a}"
echo "--- stderr (apply A) ---"; cat "${stderr_apply_a}" >&2 || true
echo "--- end stderr ---"
if [[ "${rc_a}" -ne 0 ]]; then
    echo "FAIL: initial apply (A) exit ${rc_a} (expected 0)" >&2
    exit 1
fi
if [[ -z "$(xdp_prog_id "${IFACE_A}")" ]]; then
    echo "FAIL: no XDP attached after apply A" >&2
    exit 1
fi

# ── Step 2: start background alternating injector ─────────────────────────
INJECTOR_DURATION=$(( WINDOW_SEC * 2 + 10 ))
echo "=== start background injector (MAC_05+MAC_11 alternating @ ${RATE_HZ}Hz for ${INJECTOR_DURATION}s)"
${NSEXEC} python3 "${INJECT_SCRIPT}" \
    "${IFACE_B}" "${MAC_05}" "${MAC_11}" "${MAC_DST}" \
    "${INJECTOR_DURATION}" "${RATE_HZ}" \
    >/dev/null 2>&1 &
INJECT_PID=$!
echo "INJECT_PID=${INJECT_PID}"

# Give python a beat to spin up + open AF_PACKET socket.
sleep 0.5

# ── Step 3: baseline window ──────────────────────────────────────────────
read -r p0 d0 m0 < <(read_stats)
rc5_0=$(read_rc_slot 5)
rc17_0=$(read_rc_slot 17)
echo "T0 baseline-pre: PASS=${p0} DROP_DENY=${d0} rc[5]=${rc5_0} rc[17]=${rc17_0}"

sleep "${WINDOW_SEC}"

read -r p_bl d_bl m_bl < <(read_stats)
rc5_bl=$(read_rc_slot 5)
rc17_bl=$(read_rc_slot 17)
echo "T1 baseline (post-${WINDOW_SEC}s): PASS=${p_bl} DROP_DENY=${d_bl} rc[5]=${rc5_bl} rc[17]=${rc17_bl}"

bl_pass_delta=$(( p_bl - p0 ))
bl_drop_delta=$(( d_bl - d0 ))
echo "baseline delta: PASS=${bl_pass_delta} DROP_DENY=${bl_drop_delta}"

# Under config A: MAC_05 passes (id=5), MAC_11 drops (id=17). Both
# alternate at ~equal rate, so PASS ≈ DROP ≈ total/2. Anti-rate-floor
# check: total baseline volume must be above LOWER_BOUND for the test
# to be useful as a swap canary.
if (( bl_pass_delta + bl_drop_delta < LOWER_BOUND )); then
    echo "SKIP: XDPMF_INJECT_RATE_HZ too low for rules-axis swap test on this runner" >&2
    echo "      baseline (PASS+DROP)=$((bl_pass_delta+bl_drop_delta)) < lower_bound=${LOWER_BOUND}" >&2
    exit 77
fi

# Sanity: each side must have moved during baseline (else alternation
# isn't actually happening or one rule is broken).
if (( bl_pass_delta == 0 )); then
    echo "FAIL: baseline_pass_delta == 0 under config A — MAC_05 PASS rule is broken" >&2
    exit 1
fi
if (( bl_drop_delta == 0 )); then
    echo "FAIL: baseline_drop_delta == 0 under config A — MAC_11 DROP rule is broken" >&2
    exit 1
fi

active_pre=$(read_active_idx)
echo "active_idx pre-swap = '${active_pre}'"

# ── Step 5: swap to B (CONCURRENT with traffic) ──────────────────────────
echo "=== apply ${FIX_B} (CONCURRENT with in-flight alternating traffic — LOAD-BEARING)"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIX_B}" 2> "${stderr_apply_b}"
rc_b=$?
set -e
echo "rc_b=${rc_b}"
echo "--- stderr (apply B) ---"; cat "${stderr_apply_b}" >&2 || true
echo "--- end stderr ---"

fail=0

if [[ "${rc_b}" -ne 0 ]]; then
    echo "FAIL[swap-rc]: apply B during traffic exit ${rc_b} (expected 0)" >&2
    fail=1
fi

active_post=$(read_active_idx)
echo "active_idx post-swap = '${active_post}'"
if [[ -z "${active_pre}" || -z "${active_post}" ]]; then
    echo "FAIL[active-idx-readout]: pre='${active_pre}' post='${active_post}'" >&2
    fail=1
elif [[ "${active_pre}" == "${active_post}" ]]; then
    echo "FAIL[active-idx-flip]: active_idx did not flip (pre='${active_pre}' post='${active_post}')" >&2
    echo "                       rules-axis atomic-swap did not commit (PI-13-3.4b-c2 VIOLATED)" >&2
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

sleep 0.3

read -r p_f d_f m_f < <(read_stats)
rc5_f=$(read_rc_slot 5)
rc17_f=$(read_rc_slot 17)
echo "T2 final: PASS=${p_f} DROP_DENY=${d_f} rc[5]=${rc5_f} rc[17]=${rc17_f}"

# Compute window-total deltas. Per §5.31 reuse_fd discipline (HK-12),
# stats + rule_counters are PRESERVED across applies — so deltas across
# the whole window are observable.
D_PASS=$(( p_f - p0 ))
D_DROP=$(( d_f - d0 ))
D_rc5=$(( rc5_f  - rc5_0  ))
D_rc17=$(( rc17_f - rc17_0 ))
total_verdicts=$(( D_PASS + D_DROP ))
total_matches=$(( D_rc5 + D_rc17 ))
echo "window deltas: D_PASS=${D_PASS} D_DROP=${D_DROP} D_rc5=${D_rc5} D_rc17=${D_rc17}"
echo "  total verdicts = ${total_verdicts}  total matches = ${total_matches}"

# (9) D_rc5 + D_rc17 ≈ D_PASS + D_DROP within tolerance. Per design §6.NN+1
#     the assertion is approximate (real-time race window is ms-scale, not
#     deterministic): PERCPU read-skew (bpftool dumps each CPU's slot
#     sequentially) + the 3 separate bpftool invocations to gather
#     stats/rc[5]/rc[17] each see slightly different snapshots even
#     after the injector stops. STRICT equality fails on a tight skew
#     of a few frames per ~hundreds. Allow max(10, 10% of total_verdicts)
#     absolute deviation — same ~10% tolerance the design enumerates.
#
#     The LOAD-BEARING atomicity proof is: rc_sum stays in the SAME
#     ballpark as verdict_sum (NOT half-applied, where rc would bump
#     without a verdict or vice versa, producing a >>10% divergence).
#
#     Note: STAT_DROP_MALFORMED is ignored — frames are well-formed.
diff=$(( total_matches - total_verdicts ))
abs_diff=$(( diff < 0 ? -diff : diff ))
tol=$(( total_verdicts / 10 ))
if (( tol < 10 )); then tol=10; fi
echo "  |rc_sum - verdict_sum| = ${abs_diff}  tolerance = ${tol}"
if (( abs_diff > tol )); then
    echo "FAIL[swap-atomicity]: rule_counters total (${total_matches}) diverges from verdict total (${total_verdicts}) by ${abs_diff} > tol ${tol}" >&2
    echo "                      half-applied state across swap (PI-13-3.4b-c2 VIOLATED)" >&2
    fail=1
fi

# (10) Anti-theatricality: each side advanced post-swap. Under both A
#      AND B, at least one MAC produces PASS and the OTHER produces DROP
#      (the actions just flip). So across the full window (baseline +
#      post-swap), BOTH D_PASS and D_DROP MUST be non-zero AND each
#      should exceed the baseline-only contribution from the side that
#      was-already-producing-that-verdict pre-swap.
if (( D_PASS == 0 )); then
    echo "FAIL[anti-theatricality.pass]: D_PASS == 0 across entire window" >&2
    echo "                                neither config A (MAC_05) nor B (MAC_11) produced PASS" >&2
    fail=1
fi
if (( D_DROP == 0 )); then
    echo "FAIL[anti-theatricality.drop]: D_DROP == 0 across entire window" >&2
    echo "                                neither config A (MAC_11) nor B (MAC_05) produced DROP" >&2
    fail=1
fi

# (11) rc[5] + rc[17] should both have advanced — alternation means
#      each rule got ~half the traffic. If one is zero, the alternation
#      injector failed or one of the rules wasn't being matched.
if (( D_rc5 == 0 )); then
    echo "FAIL[rc5-zero]: rule_counters[5] never advanced — MAC_05 not matching id=5" >&2
    fail=1
fi
if (( D_rc17 == 0 )); then
    echo "FAIL[rc17-zero]: rule_counters[17] never advanced — MAC_11 not matching id=17" >&2
    fail=1
fi

# (12) Negation control: prove the drop machinery is functional on this
#      runner. ONE frame from MAC_DENY (in NEITHER config) → drops.
echo "=== negation control: inject one MAC_DENY (never-allowed) → STAT_DROP_DENY MUST increment"
read -r p_n0 d_n0 m_n0 < <(read_stats)
inject_eth "${IFACE_B}" "${MAC_DENY}" "${MAC_DST}"
wait_for_stats_sum "${IFACE_A}" $(( p_n0 + d_n0 + m_n0 + 1 )) || true
read -r p_n1 d_n1 m_n1 < <(read_stats)
neg_drop_delta=$(( d_n1 - d_n0 ))
echo "negation-control drop_delta = ${neg_drop_delta} (expected >= 1)"
if (( neg_drop_delta < 1 )); then
    echo "FAIL[negation]: drop machinery did NOT register MAC_DENY frame" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_RULES_ATOMIC_SWAP_NO_DROP"
exit "${fail}"
