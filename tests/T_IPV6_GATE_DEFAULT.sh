#!/bin/bash
# T_IPV6_GATE_DEFAULT — design §5.51 / §6.70 (MVP-4.11 / S1) + §5.53 ⚠
# S4-SUPERSEDED (MVP-4.13 / S4): the ETH_P_IPV6 arm fallthrough proof.
#
# S1 (§5.51) reshaped the terminal `if (ETH_P_IP)` gate into
# `if (ETH_P_IP) {…} else if (ETH_P_IPV6) {/* empty seam */}` and proved a
# 0x86DD frame fell through the EMPTY seam to defaults[active]. S4 (§5.53) fills
# that seam with a LIVE 8-term v6 classifier. The S1-era step (2) (a bare
# zero-payload 0x86DD ether frame asserting mal-delta==0) is SUPERSEDED: the
# now-live v6 arm bounds-checks the 40B base header, so a malformed probe no
# longer cleanly tests the fallthrough (see §5.53 ⚠ S4-SUPERSEDED, option b).
#
# The PROPERTY this test guards — a recognized v6 frame that matches NO rule
# falls through to defaults[active] (the v6 arm's `acc==0` path) — is PRESERVED
# under S4, but it must now be tested with a WELL-FORMED v6 frame whose src-MAC
# matches NO rule (a matching MAC would fire the family-blind MAC axis — that
# case is T_IPV6_INJECT_DEFAULT). Generic non-IP→defaults coverage stays in
# T_MAC_NON_IP (0x88B5).
#
# The fixture config_mac_drop_default_pass.yaml (REUSED) inverts the usual
# polarity:  default_action: pass; id0 mac=02:00:00:00:00:01 action DROP.
#
#   (1) IPv4 frame, src_mac=MAC_RULE (inject_ipv4.py) → the MAC rule fires →
#       STAT_DROP_DENY delta == 1. (Positive control: proves the rule + drop
#       machinery are LIVE, so step (2)'s "not dropped" is meaningful.)
#   (2) a WELL-FORMED IPv6 base-header frame, src_mac=MAC_NOMATCH (inject_l6.py)
#       → enters the LIVE ETH_P_IPV6 arm → the mac-only rule does NOT match
#       (different MAC) and no other axis is constrained ⇒ acc==0 ⇒ falls to
#       defaults[active] (= pass) → STAT_DROP_DENY delta == 0 AND
#       STAT_DROP_MALFORMED delta == 0. THE fallthrough assertion: a v6 arm that
#       (wrongly) dropped an unmatched frame fails the deny-delta; one that
#       mis-derefed a well-formed frame fails the malformed-delta.
#
# Sanity floor: smoke = apply exit 0. Positive control = step (1) (IPv4
# must-drop). NEGATION/boundary = step (2) (well-formed v6, no match → defaults;
# no rule may fire, nothing may be reclassified malformed).
#
# Maps to: PI-mvp-4.11-IPV6-DEFAULTS (preserved for well-formed v6),
#          PI-mvp-4.13-CROSS-FAMILY (no-match v6 → defaults), §5.53 ⚠ S4-SUPERSEDED.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_mac_drop_default_pass.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

MAC_RULE="02:00:00:00:00:01"   # the drop-rule MAC in the fixture
MAC_NOMATCH="02:00:00:00:00:99" # a MAC matching NO rule (for the v6 fallthrough)
SRC_IP="10.0.0.7"
V6_SRC="2001:db8::7"           # RFC 3849 documentation range; matches no cidr6 rule
V6_DST="2001:db8::1"

stderr_file=$(mktemp /tmp/xdpmf-ipv6gate-stderr.XXXXXX)
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

# ── (2) well-formed v6 frame, NON-matching MAC → defaults (acc==0 fallthrough) ─
# A real well-formed base-header IPv6 frame (inject_l6.py) with a src-MAC that
# matches NO rule. It enters the LIVE ETH_P_IPV6 arm; the mac-only rule's MAC
# axis does not match and no other axis is constrained ⇒ acc==0 ⇒ defaults
# (= pass). (A MATCHING MAC would fire the family-blind MAC drop — see
# T_IPV6_INJECT_DEFAULT.)
echo "=== (2) inject well-formed IPv6 frame src_mac=${MAC_NOMATCH} (no rule) → expect defaults=pass (acc==0)"
read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_l6.py" \
    "${IFACE_B}" \
    --src-mac "${MAC_NOMATCH}" --dst-mac "${MAC_DST}" \
    --src-ip "${V6_SRC}" --dst-ip "${V6_DST}" \
    --proto tcp --dport 443
# The frame is counted somewhere (default pass) — wait for the total to advance.
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + c2 + 1 )) || true
read -r p3 d3 m3 c3 < <(read_stats_with_cidr)
echo "  after IPv6: PASS=${p3} DROP_DENY=${d3} DROP_MALFORMED=${m3} PASS_CIDR=${c3}"
if (( d3 - d2 != 0 )); then
    echo "FAIL[2.deny]: STAT_DROP_DENY delta=$(( d3 - d2 )) (expected 0)" >&2
    echo "             a well-formed v6 frame matching NO rule must fall to defaults[active], not DROP" >&2
    echo "             (PI-mvp-4.11-IPV6-DEFAULTS preserved for well-formed v6; PI-mvp-4.13-CROSS-FAMILY)" >&2
    fail=1
fi
if (( m3 - m2 != 0 )); then
    echo "FAIL[2.mal]: STAT_DROP_MALFORMED delta=$(( m3 - m2 )) (expected 0)" >&2
    echo "             a WELL-FORMED v6 base-header frame must NOT be reclassified MALFORMED" >&2
    echo "             (D-mvp-4.13-NO-MALFORMED-NONV6 fires only on a truncated base header)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_IPV6_GATE_DEFAULT (well-formed unmatched v6 frame → defaults[active])"
exit "${fail}"
