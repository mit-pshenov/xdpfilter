#!/bin/bash
# T_IPV6_INJECT_DEFAULT — design §5.52 (MVP-4.12 / S2) + §5.53 ⚠ S4-SUPERSEDED
# (MVP-4.13 / S4): inject_l6.py injector smoke + the family-blind-MAC proof.
#
# S2 (§5.52) shipped this as an INJECTOR SMOKE that proved a REAL well-formed
# IPv6 base-header frame (emitted by tests/inject/inject_l6.py) routes through
# the THEN-empty ETH_P_IPV6 seam to defaults. S4 (§5.53) fills that seam with a
# LIVE 8-term v6 AND classifier, and the MAC axis is FAMILY-AGNOSTIC (one of the
# 8 axes composed in BOTH arms — D-mvp-4.13-Q2). So a v6 frame whose src-MAC
# matches the fixture's mac-only DROP rule is now CORRECTLY DROPPED — the
# S2-era "v6 → defaults" step (2) is SUPERSEDED (see §5.53 ⚠ S4-SUPERSEDED).
# This test now positively proves the family-blind MAC drop on a v6 frame, while
# STILL exercising the inject_l6.py end-to-end harness (the smoke half survives).
#
# The fixture config_mac_drop_default_pass.yaml (REUSED) inverts the usual
# polarity:  default_action: pass; id0 mac=02:00:00:00:00:01 action DROP.
#
#   (1) IPv4 frame, src_mac=MAC_RULE (inject_ipv4.py) → the MAC rule fires →
#       STAT_DROP_DENY delta == 1. (Positive control: proves the rule + drop
#       machinery are LIVE on IPv4.)
#   (2) a REAL well-formed IPv6 base-header frame, src_mac=MAC_RULE
#       (inject_l6.py) → the now-LIVE v6 arm composes the FAMILY-BLIND MAC axis →
#       the mac-only DROP rule (id0) MATCHES → STAT_DROP_DENY delta == 1 AND
#       STAT_DROP_MALFORMED delta == 0 (the frame is well-formed — no bounds
#       miss). THE S4 proof: a v6 arm that ignored the MAC axis (or wrongly
#       IPv4-gated it) would leave deny-delta==0; an arm that mis-derefed the
#       well-formed frame would bump malformed. Documentation IPv6 range
#       2001:db8::/32 (RFC 3849) used for the addrs.
#
# Sanity floor: smoke = apply exit 0 + inject_l6.py emits an ingestible frame.
# Positive control = step (1) (IPv4 must-drop). NEGATION control = step (2)'s
# mal-delta==0 (a well-formed v6 frame must NOT be reclassified malformed) AND
# step (1)'s baseline (the drop machinery registers exactly the expected deltas,
# not an always-drop).
#
# Maps to: PI-mvp-4.12-INJECTOR, PI-mvp-4.13-CROSS-FAMILY (family-blind MAC),
#          D-mvp-4.13-Q2, §5.53 ⚠ S4-SUPERSEDED.
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

# ── (2) REAL IPv6 frame from MAC_RULE → DROPPED by the family-blind MAC axis ─
# inject_l6.py emits a well-formed base-header IPv6 frame (EtherType 0x86DD,
# 40-byte base header, 128-bit src/dst + an L4 header) sent at LAYER 2. The
# frame enters the now-LIVE ETH_P_IPV6 arm; under the Q2 symmetric 8-term AND
# the MAC axis is family-blind, so the mac-only DROP rule (id0) matches its
# src-MAC ⇒ STAT_DROP_DENY (§5.53 ⚠ S4-SUPERSEDED — was "→defaults" pre-S4).
# The frame is well-formed (40B base header present) ⇒ NOT malformed.
echo "=== (2) inject REAL IPv6 frame src_mac=${MAC_RULE} → expect DROP (family-blind MAC rule fires)"
read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_l6.py" \
    "${IFACE_B}" \
    --src-mac "${MAC_RULE}" --dst-mac "${MAC_DST}" \
    --src-ip "${V6_SRC}" --dst-ip "${V6_DST}" \
    --proto tcp --dport "${V6_DPORT}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + c2 + 1 )) || true
read -r p3 d3 m3 c3 < <(read_stats_with_cidr)
echo "  after IPv6: PASS=${p3} DROP_DENY=${d3} DROP_MALFORMED=${m3} PASS_CIDR=${c3}"
if (( d3 - d2 != 1 )); then
    echo "FAIL[2.deny]: STAT_DROP_DENY delta=$(( d3 - d2 )) (expected 1)" >&2
    echo "             the family-blind MAC axis must DROP a v6 frame whose src-MAC matches the rule" >&2
    echo "             (D-mvp-4.13-Q2 symmetric 8-term AND; PI-mvp-4.13-CROSS-FAMILY)" >&2
    fail=1
fi
if (( m3 - m2 != 0 )); then
    echo "FAIL[2.mal]: STAT_DROP_MALFORMED delta=$(( m3 - m2 )) (expected 0)" >&2
    echo "             a WELL-FORMED v6 base-header frame must NOT be reclassified MALFORMED" >&2
    echo "             (D-mvp-4.13-NO-MALFORMED-NONV6 fires only on a truncated base header)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_IPV6_INJECT_DEFAULT (family-blind MAC rule drops the matching v6 frame)"
exit "${fail}"
