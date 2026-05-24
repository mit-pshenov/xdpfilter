#!/bin/bash
# T_CIDR_ATOMIC_SWAP_NO_DROP — design §6.31 (MVP-3.2 / §5.27).
#
# LOAD-BEARING for risk-register MVP-3.2 row 1 mitigation specifically
# for the CIDR axis. Per Q1 AS1 the swap mechanism is byte-identical to
# §6.23 (single `active_idx` u32 flip), but the CIDR-axis lookup path
# is a different BPF code path (LPM_TRIE chained-deref vs HASH chained-
# deref). This test proves no-drop-under-load on the CIDR path.
#
# Sequence (mirrors §6.23 T_APPLY_ATOMIC_SWAP_NO_DROP for CIDR axis):
#   1. setup_veth + apply config_valid_cidr_swap_a.yaml (CIDR 10.0.0.0/8 only).
#   2. Start background traffic injector on peer veth: continuous IPv4
#      packets with src_ip = 10.5.6.7 (in 10.0.0.0/8 — overlaps with
#      both A and B) at ~RATE_HZ packets/s. Single long-lived python
#      process with raw AF_PACKET socket (NOT per-packet bash).
#   3. After ~2s baseline: snapshot STAT_DROP_DENY_baseline +
#      STAT_PASS_CIDR_baseline. SKIP 77 if baseline rate too low for
#      this runner (XDPMF_INJECT_RATE_HZ honestly downscales the bound).
#   4. Snapshot active_idx.
#   5. Invoke apply config_valid_cidr_swap_b.yaml (10.0.0.0/8 + 192.168.0.0/16);
#      10.0.0.0/8 OVERLAPS — the in-flight traffic must NOT drop across
#      the swap.
#   6. Snapshot active_idx — assert flip happened.
#   7. Continue traffic for ~2s more.
#   8. Stop injector; final snapshot.
#   9. Assert STAT_DROP_DENY (post-swap map total) == 0.
#  10. Anti-theatricality: post-swap STAT_PASS_CIDR >= LOWER_BOUND
#      (continuous traffic actually flowed through the swap window).
#  11. Negation control: inject ONE packet with src_ip OUT of any CIDR
#      → STAT_DROP_DENY MUST increment. Proves drop machinery is
#      functional on this runner (without it, "drops == 0" could be
#      theatrical because no drops are detectable at all).
#
# SKIP_RETURN_CODE 77 if veth load below threshold (slow CI).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE_DIR="${TEST_DIR}/fixtures"
FIX_A="${FIXTURE_DIR}/config_valid_cidr_swap_a.yaml"
FIX_B="${FIXTURE_DIR}/config_valid_cidr_swap_b.yaml"

[[ -f "${FIX_A}" ]] || { echo "FAIL: missing fixture ${FIX_A}" >&2; exit 1; }
[[ -f "${FIX_B}" ]] || { echo "FAIL: missing fixture ${FIX_B}" >&2; exit 1; }

# §6.31 reuses §6.23's XDPMF_INJECT_RATE_HZ env var (one knob across
# MAC + CIDR swap tests, per §5.27 OOS fence).
RATE_HZ="${XDPMF_INJECT_RATE_HZ:-100}"
WINDOW_SEC=2
LOWER_BOUND=$(( WINDOW_SEC * RATE_HZ * 3 / 4 ))
if (( LOWER_BOUND < 10 )); then LOWER_BOUND=10; fi

SRC_MAC_NONALLOW="55:55:55:55:55:55"        # not in any MAC allowlist
SRC_IP_OVERLAP="10.5.6.7"                   # in 10.0.0.0/8 (in BOTH A and B)
SRC_IP_NEGATION="172.16.0.99"               # in NEITHER A nor B
DST_IP_BENIGN="192.0.2.1"                   # TEST-NET-1 (RFC 5737)

INJECT_SCRIPT="$(mktemp /tmp/xdpmf_cidr_swap_inject_$$_XXXXXX.py)"
stderr_apply_a=$(mktemp /tmp/xdpmf-cidrswap-apply-a-stderr.XXXXXX)
stderr_apply_b=$(mktemp /tmp/xdpmf-cidrswap-apply-b-stderr.XXXXXX)

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
cleanup_cidr_swap() {
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
trap cleanup_cidr_swap EXIT

# ── Background injector: persistent AF_PACKET, IPv4 frames with the ──
# overlap src_ip at RATE_HZ packets/sec. Mirrors T_APPLY_ATOMIC_SWAP's
# pattern but with ethertype 0x0800 + a parseable 20-byte IPv4 header.
cat > "${INJECT_SCRIPT}" <<'PYEOF'
import socket, struct, sys, time

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

iface       = sys.argv[1]
src_mac_s   = sys.argv[2]
dst_mac_s   = sys.argv[3]
src_ip_s    = sys.argv[4]
dst_ip_s    = sys.argv[5]
duration_s  = float(sys.argv[6])
rate_hz     = float(sys.argv[7])

src_mac = mac_to_bytes(src_mac_s)
dst_mac = mac_to_bytes(dst_mac_s)
src_ip  = socket.inet_aton(src_ip_s)
dst_ip  = socket.inet_aton(dst_ip_s)

payload_len = 26
total_len   = 20 + payload_len
ver_ihl     = (4 << 4) | 5
tos         = 0
ident       = 0
flags_frag  = 0x4000
ttl         = 64
proto       = 17  # UDP — irrelevant; LPM_TRIE only reads src_ip
csum        = 0
iphdr = struct.pack("!BBHHHBBH4s4s",
                    ver_ihl, tos, total_len, ident, flags_frag,
                    ttl, proto, csum, src_ip, dst_ip)
csum = ip_checksum(iphdr)
iphdr = struct.pack("!BBHHHBBH4s4s",
                    ver_ihl, tos, total_len, ident, flags_frag,
                    ttl, proto, csum, src_ip, dst_ip)
ethertype = (0x0800).to_bytes(2, "big")
payload = b"\x00" * payload_len
frame = dst_mac + src_mac + ethertype + iphdr + payload

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

# ── Step 1: apply A ─────────────────────────────────────────────────────
echo "=== apply ${FIX_A} (initial — CIDR 10.0.0.0/8 only)"
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
if [[ -z "$(xdp_prog_id "${IFACE_A}")" ]]; then
    echo "FAIL: no XDP attached after apply A" >&2
    exit 1
fi

# ── Step 2: start background injector ──────────────────────────────────
INJECTOR_DURATION=$(( WINDOW_SEC * 2 + 10 ))
echo "=== start background IPv4 injector"
echo "    src_mac=${SRC_MAC_NONALLOW} src_ip=${SRC_IP_OVERLAP} (overlap) rate=${RATE_HZ}Hz duration=${INJECTOR_DURATION}s"
${NSEXEC} python3 "${INJECT_SCRIPT}" \
    "${IFACE_B}" "${SRC_MAC_NONALLOW}" "${MAC_DST}" \
    "${SRC_IP_OVERLAP}" "${DST_IP_BENIGN}" \
    "${INJECTOR_DURATION}" "${RATE_HZ}" \
    >/dev/null 2>&1 &
INJECT_PID=$!
echo "INJECT_PID=${INJECT_PID}"

sleep 0.5

# ── Step 3: baseline window ────────────────────────────────────────────
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "stats T0 (pre-baseline): PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"

sleep "${WINDOW_SEC}"

read -r p_bl d_bl m_bl c_bl < <(read_stats_with_cidr)
echo "stats T1 (baseline @ ${WINDOW_SEC}s): PASS=${p_bl} DROP_DENY=${d_bl} DROP_MALFORMED=${m_bl} PASS_CIDR=${c_bl}"

baseline_pass_cidr_delta=$(( c_bl - c0 ))
echo "baseline_pass_cidr_delta=${baseline_pass_cidr_delta}  lower_bound=${LOWER_BOUND}"

if (( baseline_pass_cidr_delta < LOWER_BOUND )); then
    echo "SKIP: XDPMF_INJECT_RATE_HZ too low — runner too slow for CIDR-axis swap test" >&2
    echo "      baseline_pass_cidr_delta=${baseline_pass_cidr_delta} < lower_bound=${LOWER_BOUND}" >&2
    exit 77
fi

# Sanity: baseline drop counter should be ~zero (overlap IP is allowed in A).
baseline_drop_delta=$(( d_bl - d0 ))
if (( baseline_drop_delta != 0 )); then
    echo "FAIL: baseline_drop_delta=${baseline_drop_delta} (expected 0 — overlap IP must be allowed in A)" >&2
fi

active_pre=$(read_active_idx)
echo "active_idx pre-swap = '${active_pre}'"

# ── Step 5: swap to B (CONCURRENT with traffic) ────────────────────────
echo "=== apply ${FIX_B} (CONCURRENT with in-flight 10.5.6.7 — LOAD-BEARING)"
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

active_post=$(read_active_idx)
echo "active_idx post-swap = '${active_post}'"

if [[ -z "${active_pre}" || -z "${active_post}" ]]; then
    echo "FAIL[active-idx-readout]: could not read active_idx (pre='${active_pre}' post='${active_post}')" >&2
    fail=1
elif [[ "${active_pre}" == "${active_post}" ]]; then
    echo "FAIL[active-idx-flip]: active_idx did not flip (pre='${active_pre}' post='${active_post}')" >&2
    fail=1
fi

# ── Step 7: post-swap window ───────────────────────────────────────────
sleep "${WINDOW_SEC}"

# ── Step 8: stop injector + final snapshot ─────────────────────────────
echo "=== stop background injector"
sudo -n pkill -KILL -f "${INJECT_SCRIPT}" 2>/dev/null || true
kill -KILL "${INJECT_PID}" 2>/dev/null || true
wait "${INJECT_PID}" 2>/dev/null || true
INJECT_PID=""

sleep 0.3

read -r p_f d_f m_f c_f < <(read_stats_with_cidr)
echo "stats T2 (final): PASS=${p_f} DROP_DENY=${d_f} DROP_MALFORMED=${m_f} PASS_CIDR=${c_f}"
echo "  (post-swap TOTAL from new stats map; impl re-pins on every reattach per D-3.1-4)"
echo "  d_f (post-swap drops) = ${d_f}  (expected 0)"
echo "  c_f (post-swap CIDR passes) = ${c_f}  (expected >= ${LOWER_BOUND})"

# (9) STAT_DROP_DENY in the post-swap map MUST be 0 (load-bearing).
#     SRC_IP_OVERLAP (10.5.6.7) is allowed in BOTH A and B via the
#     overlapping 10.0.0.0/8 CIDR — any drop in the NEW program means
#     the swap mis-classified an overlapping-allowed src_ip (a half-
#     applied window in the LPM_TRIE swap).
if (( d_f != 0 )); then
    echo "FAIL[swap-drop]: STAT_DROP_DENY in post-swap map = ${d_f}, expected 0" >&2
    echo "                 src_ip ${SRC_IP_OVERLAP} was in 10.0.0.0/8 across BOTH A and B." >&2
    echo "                 Any drop visible to the NEW program means the CIDR-axis swap" >&2
    echo "                 left a window where 10.x traffic was dropped (Q1 AS1 atomic-" >&2
    echo "                 swap promise broken for the LPM_TRIE path)." >&2
    fail=1
fi

# (10) Anti-theatricality: post-swap CIDR traffic must have actually flowed.
if (( c_f < LOWER_BOUND )); then
    echo "FAIL[swap-pass-anti-theatricality]: post-swap STAT_PASS_CIDR = ${c_f}, expected >= ${LOWER_BOUND}" >&2
    echo "                                    baseline proved CIDR-axis injection rate OK; low value" >&2
    echo "                                    post-swap means injector stopped after baseline (the" >&2
    echo "                                    no-drop assertion would be theatrical because traffic" >&2
    echo "                                    wasn't continuous through the swap window)." >&2
    fail=1
fi

# (11) Negation control: prove the drop machinery is functional on this
#      runner. Single IPv4 packet with src_ip OUTSIDE every CIDR — must
#      drop.
echo "=== negation control: inject one OUT-of-range src_ip=${SRC_IP_NEGATION} → STAT_DROP_DENY MUST increment"
read -r p_n0 d_n0 m_n0 c_n0 < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${SRC_MAC_NONALLOW}" "${MAC_DST}" "${SRC_IP_NEGATION}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p_n0 + d_n0 + m_n0 + c_n0 + 1 )) || true
read -r p_n1 d_n1 m_n1 c_n1 < <(read_stats_with_cidr)
neg_drop_delta=$(( d_n1 - d_n0 ))
echo "negation-control drop_delta = ${neg_drop_delta} (expected 1)"
if (( neg_drop_delta != 1 )); then
    echo "FAIL[negation]: drop machinery did NOT register OUT-of-range src_ip" >&2
    echo "                — test cannot prove non-zero drops are detectable on this runner." >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_CIDR_ATOMIC_SWAP_NO_DROP"
exit "${fail}"
