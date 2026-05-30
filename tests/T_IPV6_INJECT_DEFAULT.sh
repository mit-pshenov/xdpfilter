#!/bin/bash
# T_IPV6_INJECT_DEFAULT — design §5.52 TestStrategy (MVP-4.12 / S2), the
# inject_l6.py injector smoke + S4 harness scaffold. The real-IPv6 analog of
# S1's §6.70 T_IPV6_GATE_DEFAULT.
#
# S1 (§5.51) already proved 0x86DD → defaults, but with a ZERO-PAYLOAD Ether
# frame (46 bytes of zeros after the EtherType; NOT a valid IPv6 packet). S2
# proves the SAME → defaults outcome with a REAL, well-formed IPv6 base-header
# frame (version=6, payload_len, next-header, hop-limit, 128-bit src/dst + an L4
# header), emitted by the NEW tests/inject/inject_l6.py. Per D-mvp-4.12-HONEST-
# SMOKE this is an INJECTOR SMOKE + HARNESS SCAFFOLD, NOT a new-datapath-behavior
# proof: the S1 ETH_P_IPV6 arm doesn't deref, so the real v6 frame routes
# IDENTICALLY to S1's zero-payload frame. Its value is (a) inject_l6.py emits a
# frame the veth → XDP datapath ingests without choking (the NEW tool works
# end-to-end), and (b) it establishes the inject → counter-delta harness S4
# reuses to assert cidr6 matching.
#
# The fixture config_mac_drop_default_pass.yaml (REUSED) inverts the usual
# polarity:  default_action: pass; id0 mac=02:00:00:00:00:01 action DROP.
#
#   (1) IPv4 frame, src_mac=MAC_RULE (inject_ipv4.py) → the MAC rule fires →
#       STAT_DROP_DENY delta == 1. (Positive/negation control: proves the rule +
#       drop machinery are LIVE — a "must-drop" case that MUST register, so
#       step (2)'s "not dropped" is meaningful, not a silently-broken
#       pass-everything.)
#   (2) a REAL well-formed IPv6 base-header frame, src_mac=MAC_RULE
#       (inject_l6.py) → the frame ENTERS the S1 ETH_P_IPV6 arm → falls to
#       defaults[active] (= pass) → STAT_DROP_DENY delta == 0 AND
#       STAT_DROP_MALFORMED delta == 0. THE injector smoke: an injector that
#       failed to emit an ingestible frame, or an arm that (wrongly) dropped or
#       dereffed it, would fail one of these deltas. Documentation IPv6 range
#       2001:db8::/32 (RFC 3849) used for the addrs.
#
# Sanity floor: smoke = apply exit 0. Positive control = step (1) (a frame that
# MUST drop and does). Injector-smoke/negation = step (2) (real v6 → defaults).
#
# Maps to: PI-mvp-4.12-INJECTOR, PI-mvp-4.12-REGRESSION-GREEN,
#          D-mvp-4.12-HONEST-SMOKE, D-mvp-4.12-NO-SRC, Q2=A1.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_mac_drop_default_pass.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

MAC_RULE="02:00:00:00:00:01"   # the drop-rule MAC in the fixture
SRC_IP="10.0.0.7"              # IPv4 positive-control src
V6_SRC="2001:db8::7"           # real IPv6 src (RFC 3849 documentation range)
V6_DST="2001:db8::1"           # real IPv6 dst (RFC 3849 documentation range)
V6_DPORT=443

stderr_file=$(mktemp /tmp/xdpmf-ipv6inject-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
cat "${stderr_file}" >&2 || true
echo "rc=${rc}"
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[smoke]: apply exit ${rc} (expected 0)" >&2
    exit 1
fi

fail=0

# ── (1) IPv4 frame from MAC_RULE → DROP (rule fires; positive control) ────
echo "=== (1) inject IPv4 frame src_mac=${MAC_RULE} → expect DROP (rule fires)"
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${MAC_RULE}" "${MAC_DST}" "${SRC_IP}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true
read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
echo "  after IPv4: PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1} PASS_CIDR=${c1}"
if (( d1 - d0 != 1 )); then
    echo "FAIL[1.deny]: STAT_DROP_DENY delta=$(( d1 - d0 )) (expected 1 — IPv4 MAC rule must drop)" >&2
    fail=1
fi

# ── (2) REAL IPv6 frame from MAC_RULE → NOT dropped (S1 ETH_P_IPV6 seam) ───
# inject_l6.py emits a well-formed base-header IPv6 frame (EtherType 0x86DD,
# 40-byte base header, 128-bit src/dst + an L4 header) sent at LAYER 2. The
# frame enters the S1 ETH_P_IPV6 arm → falls to defaults[active] (= pass). The
# S1 arm doesn't deref, so this routes identically to S1's zero-payload frame —
# this is the injector smoke (does the NEW tool emit an ingestible real v6
# frame?), not a new-datapath-behavior proof (D-mvp-4.12-HONEST-SMOKE).
echo "=== (2) inject REAL IPv6 frame src_mac=${MAC_RULE} → expect NOT dropped (S1 arm → defaults=pass)"
read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_l6.py" \
    "${IFACE_B}" \
    --src-mac "${MAC_RULE}" --dst-mac "${MAC_DST}" \
    --src-ip "${V6_SRC}" --dst-ip "${V6_DST}" \
    --proto tcp --dport "${V6_DPORT}"
# The frame is counted somewhere (default pass) — wait for the total to advance.
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + c2 + 1 )) || true
read -r p3 d3 m3 c3 < <(read_stats_with_cidr)
echo "  after IPv6: PASS=${p3} DROP_DENY=${d3} DROP_MALFORMED=${m3} PASS_CIDR=${c3}"
if (( d3 - d2 != 0 )); then
    echo "FAIL[2.deny]: STAT_DROP_DENY delta=$(( d3 - d2 )) (expected 0)" >&2
    echo "             the S1 ETH_P_IPV6 arm must NOT early-return DROP — it falls to defaults[active]" >&2
    echo "             (PI-mvp-4.12-INJECTOR; D-mvp-4.12-HONEST-SMOKE)" >&2
    fail=1
fi
if (( m3 - m2 != 0 )); then
    echo "FAIL[2.mal]: STAT_DROP_MALFORMED delta=$(( m3 - m2 )) (expected 0)" >&2
    echo "             the S1 IPv6 arm must NOT deref the frame or reclassify it MALFORMED — no deref this slice" >&2
    echo "             (PI-mvp-4.12-INJECTOR; non-IP-never-MALFORMED extended to v6)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_IPV6_INJECT_DEFAULT (real IPv6 frame from inject_l6.py routes to defaults)"
exit "${fail}"
