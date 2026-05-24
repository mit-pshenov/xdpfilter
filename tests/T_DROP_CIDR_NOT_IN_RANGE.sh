#!/bin/bash
# T_DROP_CIDR_NOT_IN_RANGE — design §6.29 (MVP-3.2 / §5.27).
#
# Focused negation: with a single CIDR rule (10.0.0.0/8) applied, an
# IPv4 packet whose src_ip is NOT in any rule's CIDR range AND whose
# src_mac is NOT in any MAC allowlist must increment ONLY STAT_DROP_DENY
# (counter SPLIT — neither STAT_PASS nor STAT_PASS_CIDR may move).
#
# Second injection with a DIFFERENT out-of-range src_ip proves the
# denial is idempotent (every out-of-range packet drops; not a sticky
# one-shot first-packet anomaly).
#
# Sanity-floor smoke: the apply exit-0 is the smoke test.
# Negation control: THIS WHOLE TEST IS THE NEGATION — focused
# "no-rule-matches → DROP" assertion separate from §6.28's combined
# in-range/out-of-range pair. Operator-audit grep "did the drop happen
# because CIDR missed" is unambiguous via §6.29 alone.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_cidr.yaml"

[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-dropcidr-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT

SRC_MAC_NONALLOW="aa:aa:aa:aa:aa:aa"     # never in any allowlist
SRC_IP_1="8.8.8.8"                       # OUT of 10.0.0.0/8
SRC_IP_2="100.64.0.1"                    # OUT of 10.0.0.0/8 (CGN range)

setup_veth

echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2> "${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
echo "--- stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

fail=0
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[1]: apply exit ${rc} (expected 0)" >&2
    fail=1
fi

# ── Injection 1: 8.8.8.8 → DROP_DENY ────────────────────────────────────
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"

echo "=== inject 1: src_ip=${SRC_IP_1} src_mac=${SRC_MAC_NONALLOW}"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${SRC_MAC_NONALLOW}" "${MAC_DST}" "${SRC_IP_1}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true

read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
echo "  after inject 1: PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1} PASS_CIDR=${c1}"

if (( d1 - d0 != 1 )); then
    echo "FAIL[2.d]: STAT_DROP_DENY delta != 1 (got $(( d1 - d0 )))" >&2
    fail=1
fi
if (( p1 - p0 != 0 )); then
    echo "FAIL[2.p]: STAT_PASS unexpectedly moved (got delta $(( p1 - p0 )))" >&2
    fail=1
fi
if (( c1 - c0 != 0 )); then
    echo "FAIL[2.c]: STAT_PASS_CIDR unexpectedly moved (got delta $(( c1 - c0 )))" >&2
    echo "          src_ip ${SRC_IP_1} is OUT of 10.0.0.0/8 — LPM_TRIE must NOT match." >&2
    fail=1
fi

# ── Injection 2: 100.64.0.1 → same outcome (idempotent denial) ─────────
echo "=== inject 2: src_ip=${SRC_IP_2} (different OUT-of-range src_ip)"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${SRC_MAC_NONALLOW}" "${MAC_DST}" "${SRC_IP_2}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true

read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
echo "  after inject 2: PASS=${p2} DROP_DENY=${d2} DROP_MALFORMED=${m2} PASS_CIDR=${c2}"

if (( d2 - d1 != 1 )); then
    echo "FAIL[3.d]: STAT_DROP_DENY delta != 1 on second OUT-of-range packet (got $(( d2 - d1 )))" >&2
    fail=1
fi
if (( p2 - p1 != 0 )); then
    echo "FAIL[3.p]: STAT_PASS unexpectedly moved on inject 2 (got delta $(( p2 - p1 )))" >&2
    fail=1
fi
if (( c2 - c1 != 0 )); then
    echo "FAIL[3.c]: STAT_PASS_CIDR unexpectedly moved on inject 2 (got delta $(( c2 - c1 )))" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_DROP_CIDR_NOT_IN_RANGE"
exit "${fail}"
