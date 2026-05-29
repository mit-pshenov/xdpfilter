#!/bin/bash
# T_APPLY_ATOMIC_SWAP_NO_DROP — design §5.47 TestStrategy (MVP-4.7 / §5.47).
#
# MAC-rule apply atomic-swap: re-applying a MAC-rule config under sustained
# in-flight traffic drops ZERO packets for an overlapping-allowed MAC (atomic
# active_idx flip; the reshaped MAC inner + wildcard are written to the INACTIVE
# half BEFORE the flip — RESET-on-apply, guard #15). MAC is the LIVE 6th
# exact-HASH axis (un-SKIP'd; PI-mvp-4.3-MAC-DEFERRED RETIRED).
#
# This is the MAC-axis sibling of T_CIDR_ATOMIC_SWAP_NO_DROP. Frames are IPv4
# (MAC is IPv4-gated, D-mvp-4.7-Q2-GATE): the background injector emits a raw
# Eth(0x0800)+IPv4 frame with src_mac == MAC_X at ~RATE_HZ via a single
# persistent AF_PACKET socket.
#
# Sequence:
#   1. apply config_mac_swap_a.yaml (pass MAC_X only).
#   2. background injector: continuous IPv4 frames src_mac=MAC_X.
#   3. baseline window; SKIP 77 if rate too low for this runner.
#   4. snapshot active_idx pre-swap.
#   5. apply config_mac_swap_b.yaml (pass MAC_X + MAC_Y) CONCURRENT with traffic.
#   6. assert active_idx flipped.
#   7. post-swap window; stop injector.
#   8. assert post-swap STAT_DROP_DENY == 0 (MAC_X overlapping-allowed → 0 drops).
#   9. anti-theatricality: post-swap STAT_PASS >= LOWER_BOUND (traffic flowed).
#  10. NEGATION: inject ONE IPv4 frame src_mac=MAC_DENY (never-allowed) →
#      STAT_DROP_DENY increments (proves the drop machinery is live).
#
# SKIP_RETURN_CODE 77 if veth load is below threshold (slow CI runner).
#
# Maps to: PI-mvp-4.7-MAC, PI-mvp-4.3-WILDCARD (atomic 6-axis commit), guard #15.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE_DIR="${TEST_DIR}/fixtures"
FIX_A="${FIXTURE_DIR}/config_mac_swap_a.yaml"
FIX_B="${FIXTURE_DIR}/config_mac_swap_b.yaml"

[[ -f "${FIX_A}" ]] || { echo "FAIL: missing fixture ${FIX_A}" >&2; exit 1; }
[[ -f "${FIX_B}" ]] || { echo "FAIL: missing fixture ${FIX_B}" >&2; exit 1; }

RATE_HZ="${XDPMF_INJECT_RATE_HZ:-100}"
WINDOW_SEC=2
LOWER_BOUND=$(( WINDOW_SEC * RATE_HZ * 3 / 4 ))
if (( LOWER_BOUND < 10 )); then LOWER_BOUND=10; fi

MAC_X="02:00:00:00:00:01"    # in BOTH config A and B (overlapping-allowed)
MAC_Y="02:00:00:00:00:02"    # in config B only
MAC_DENY="02:00:00:00:00:99" # not in ANY fixture; negation control
SRC_IP="10.0.0.7"            # well-formed IPv4 so the frame clears the IPv4 gate

INJECT_SCRIPT="$(mktemp /tmp/xdpmf_macswap_inject_$$_XXXXXX.py)"
stderr_apply_a=$(mktemp /tmp/xdpmf-macswap-apply-a-stderr.XXXXXX)
stderr_apply_b=$(mktemp /tmp/xdpmf-macswap-apply-b-stderr.XXXXXX)

read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
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
trap cleanup_swap EXIT INT TERM HUP

# ── Background injector: ONE python process, raw AF_PACKET IPv4 frame loop ──
# MAC is IPv4-gated, so the injected frame is Eth(0x0800)+IPv4 (NOT 0x88B5);
# the src_mac is the load-bearing field the MAC axis keys on.
cat > "${INJECT_SCRIPT}" <<'PYEOF'
import socket, struct, sys, time
iface      = sys.argv[1]
src_mac    = sys.argv[2]
dst_mac    = sys.argv[3]
src_ip     = sys.argv[4]
duration_s = float(sys.argv[5])
rate_hz    = float(sys.argv[6])

def mac_to_bytes(s):
    return bytes(int(b, 16) for b in s.split(":"))

def ip_checksum(header):
    if len(header) % 2:
        header += b"\x00"
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) | header[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

dst_b = mac_to_bytes(dst_mac)
src_b = mac_to_bytes(src_mac)
src_ip_b = socket.inet_aton(src_ip)
dst_ip_b = socket.inet_aton("192.0.2.1")

payload_len = 26
total_len = 20 + payload_len
ver_ihl = (4 << 4) | 5
iphdr = struct.pack("!BBHHHBBH4s4s",
                    ver_ihl, 0, total_len, 0, 0x4000, 64, 17, 0, src_ip_b, dst_ip_b)
csum = ip_checksum(iphdr)
iphdr = struct.pack("!BBHHHBBH4s4s",
                    ver_ihl, 0, total_len, 0, 0x4000, 64, 17, csum, src_ip_b, dst_ip_b)
ethertype = (0x0800).to_bytes(2, "big")
frame = dst_b + src_b + ethertype + iphdr + (b"\x00" * payload_len)

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
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

# ── Step 1: apply config_mac_swap_a.yaml ──────────────────────────────────
echo "=== apply ${FIX_A} (initial — pass MAC_X only)"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIX_A}" 2> "${stderr_apply_a}"
rc_a=$?
set -e
echo "rc_a=${rc_a}"
cat "${stderr_apply_a}" >&2 || true
if [[ "${rc_a}" -ne 0 ]]; then
    echo "FAIL: initial apply (A) exit ${rc_a} (expected 0)" >&2
    exit 1
fi
if [[ -z "$(xdp_prog_id "${IFACE_A}")" ]]; then
    echo "FAIL: no XDP attached after apply A" >&2
    exit 1
fi

# ── Step 2: start background injector ──────────────────────────────────────
INJECTOR_DURATION=$(( WINDOW_SEC * 2 + 10 ))
echo "=== start background injector (IPv4 src_mac=${MAC_X} at ${RATE_HZ} Hz for ${INJECTOR_DURATION}s)"
${NSEXEC} python3 "${INJECT_SCRIPT}" "${IFACE_B}" "${MAC_X}" "${MAC_DST}" "${SRC_IP}" "${INJECTOR_DURATION}" "${RATE_HZ}" \
    >/dev/null 2>&1 &
INJECT_PID=$!
echo "INJECT_PID=${INJECT_PID}"
sleep 0.5

# ── Step 3: baseline window ────────────────────────────────────────────────
# A MAC-axis pass may land in STAT_PASS or STAT_PASS_CIDR (design notes
# "STAT_PASS/PASS_CIDR"); count the SUM so the assertion is bucket-robust.
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "stats T0: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"
sleep "${WINDOW_SEC}"
read -r p_bl d_bl m_bl c_bl < <(read_stats_with_cidr)
echo "stats T1 (baseline): PASS=${p_bl} DROP_DENY=${d_bl} DROP_MALFORMED=${m_bl} PASS_CIDR=${c_bl}"

baseline_pass_delta=$(( (p_bl + c_bl) - (p0 + c0) ))
echo "baseline_pass_delta=${baseline_pass_delta}  lower_bound=${LOWER_BOUND}"
if (( baseline_pass_delta < LOWER_BOUND )); then
    echo "SKIP: XDPMF_INJECT_RATE_HZ too low for swap test on this runner" >&2
    echo "      baseline_pass_delta=${baseline_pass_delta} < lower_bound=${LOWER_BOUND}" >&2
    exit 77
fi

baseline_drop_delta=$(( d_bl - d0 ))
if (( baseline_drop_delta != 0 )); then
    echo "FAIL: baseline_drop_delta=${baseline_drop_delta} (expected 0 — MAC_X allowed in config A)" >&2
fi

active_pre=$(read_active_idx)
echo "active_idx pre-swap = '${active_pre}'"

# ── Step 5: swap to config B (CONCURRENT with traffic) ─────────────────────
echo "=== apply ${FIX_B} (CONCURRENT with in-flight MAC_X traffic — LOAD-BEARING)"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIX_B}" 2> "${stderr_apply_b}"
rc_b=$?
set -e
echo "rc_b=${rc_b}"
cat "${stderr_apply_b}" >&2 || true

fail=0
if [[ "${rc_b}" -ne 0 ]]; then
    echo "FAIL[swap-rc]: apply B during traffic exit ${rc_b} (expected 0)" >&2
    fail=1
fi

active_post=$(read_active_idx)
echo "active_idx post-swap = '${active_post}'"
if [[ -z "${active_pre}" || -z "${active_post}" ]]; then
    echo "FAIL[active-idx-readout]: could not read active_idx (pre='${active_pre}' post='${active_post}')" >&2
    fail=1
elif [[ "${active_pre}" == "${active_post}" ]]; then
    echo "FAIL[active-idx-flip]: active_idx did not flip (pre='${active_pre}' post='${active_post}')" >&2
    fail=1
fi

# ── Step 7: post-swap window + stop injector ───────────────────────────────
sleep "${WINDOW_SEC}"
echo "=== stop background injector"
sudo -n pkill -KILL -f "${INJECT_SCRIPT}" 2>/dev/null || true
kill -KILL "${INJECT_PID}" 2>/dev/null || true
wait "${INJECT_PID}" 2>/dev/null || true
INJECT_PID=""
sleep 0.3

read -r p_f d_f m_f c_f < <(read_stats_with_cidr)
pass_total_f=$(( p_f + c_f ))
echo "stats T2 (final): PASS=${p_f} DROP_DENY=${d_f} DROP_MALFORMED=${m_f} PASS_CIDR=${c_f}"

# (8) STAT_DROP_DENY in the post-swap map MUST be 0 — MAC_X is overlapping-allowed
#     in BOTH A and B; any drop visible to the NEW program means the swap left a
#     window where MAC_X was dropped (atomic-flip promise broken). Counters are
#     PRESERVED across apply (reuse_fd), so d_f is the cumulative drop count.
echo "  d_f (post-swap drops) = ${d_f}  (expected 0)"
echo "  pass_total_f (post-swap passes, STAT_PASS+STAT_PASS_CIDR) = ${pass_total_f}  (expected >= ${LOWER_BOUND})"
if (( d_f != 0 )); then
    echo "FAIL[swap-drop]: STAT_DROP_DENY = ${d_f}, expected 0 — MAC_X dropped across the swap" >&2
    fail=1
fi

# (9) Anti-theatricality: post-swap traffic must have actually flowed.
if (( pass_total_f < LOWER_BOUND )); then
    echo "FAIL[swap-pass-anti-theatricality]: post-swap passes = ${pass_total_f}, expected >= ${LOWER_BOUND}" >&2
    fail=1
fi

# (10) Negation control: a never-allowed MAC MUST drop (IPv4 frame so it clears
#      the gate and is actually classified by the MAC axis).
echo "=== negation control: inject one IPv4 src_mac=${MAC_DENY} (never-allowed) → STAT_DROP_DENY++"
read -r p_n0 d_n0 m_n0 c_n0 < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${MAC_DENY}" "${MAC_DST}" "${SRC_IP}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p_n0 + d_n0 + m_n0 + c_n0 + 1 )) || true
read -r p_n1 d_n1 m_n1 c_n1 < <(read_stats_with_cidr)
neg_drop_delta=$(( d_n1 - d_n0 ))
echo "negation-control drop_delta = ${neg_drop_delta} (expected 1)"
if (( neg_drop_delta != 1 )); then
    echo "FAIL[negation]: drop machinery did NOT register MAC_DENY (delta=${neg_drop_delta})" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_APPLY_ATOMIC_SWAP_NO_DROP (MAC-rule atomic swap, no in-flight drop)"
exit "${fail}"
