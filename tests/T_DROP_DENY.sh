#!/bin/bash
# T_DROP_DENY → T_MAC_DROP — design §5.47 TestStrategy (MVP-4.7 / §5.47).
#
# A frame whose src-MAC is covered by NO rule hits defaults[active] (drop)
# under default_action: drop. MAC is the LIVE 6th exact-HASH axis (un-SKIP'd;
# PI-mvp-4.3-MAC-DEFERRED RETIRED per D-mvp-4.7-MAC-RETURN-SHIFT).
#
#   Setup   : apply config_valid_mac.yaml (id0 mac=MAC_ALLOW pass; default drop).
#   Trigger : inject ONE IPv4 frame with src_mac NOT in the allowlist.
#   Outcome : STAT_DROP_DENY delta == 1; STAT_PASS + STAT_PASS_CIDR delta == 0;
#             STAT_DROP_MALFORMED delta == 0.
#
# Frames are IPv4 (inject_ipv4.py) — MAC is IPv4-gated (D-mvp-4.7-Q2-GATE).
#
# Sanity floor: smoke = apply exit 0. This test IS itself the drop assertion;
# the paired positive (allowed MAC passes) lives in T_PASS_ALLOWED.
#
# Maps to: PI-mvp-4.7-MAC, PI-mvp-4.3-AND (→6 axes).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_mac.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

MAC_DENY="02:00:00:00:00:02"   # NOT in config_valid_mac.yaml (only ...:01 is)
SRC_IP="10.0.0.7"

stderr_file=$(mktemp /tmp/xdpmf-macdrop-stderr.XXXXXX)
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

echo "=== inject IPv4 frame src_mac=${MAC_DENY} (disallowed) → expect DROP_DENY"
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "  baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${MAC_DENY}" "${MAC_DST}" "${SRC_IP}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true

read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
echo "  after: PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1} PASS_CIDR=${c1}"

fail=0
if (( d1 - d0 != 1 )); then
    echo "FAIL: STAT_DROP_DENY delta=$(( d1 - d0 )) (expected 1)" >&2
    fail=1
fi
if (( (p1 - p0) + (c1 - c0) != 0 )); then
    echo "FAIL: PASS counters moved on a disallowed MAC (delta $(( (p1-p0)+(c1-c0) )))" >&2
    fail=1
fi
if (( m1 - m0 != 0 )); then
    echo "FAIL: STAT_DROP_MALFORMED delta=$(( m1 - m0 )) (expected 0)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_DROP_DENY (live MAC verdict, AND-model)"
exit "${fail}"
