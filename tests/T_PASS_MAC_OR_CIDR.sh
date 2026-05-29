#!/bin/bash
# T_PASS_MAC_OR_CIDR — design §6.30 (MVP-3.2 / §5.27).
#
# LOAD-BEARING for the OR-compose architectural correctness per
# `architecture-v2.md` line 334 risk register MVP-3.2 row 2 mitigation.
# Architect explicitly fences against making this theatrical: the test
# asserts the COUNTER SPLIT across 3 sub-cases, not just "all pass".
#
# Single fixture: one rule with BOTH mac AND src_cidr set (OR-compose
# within the rule). Three injections:
#   (a) src_mac MATCHES the rule's MAC; src_ip OUT of CIDR → expect
#       STAT_PASS += 1 (MAC short-circuit per Q2 OR1); STAT_PASS_CIDR
#       delta == 0.
#   (b) src_mac DOES NOT match the rule's MAC; src_ip IN CIDR → expect
#       STAT_PASS_CIDR += 1; STAT_PASS delta == 0 (CIDR axis fired).
#   (c) src_mac DOES NOT match; src_ip OUT of CIDR (NEGATION CONTROL)
#       → expect STAT_DROP_DENY += 1; both PASS counters unchanged.
#
# Sub-case ordering: a → b → c. Stats deltas are checked after EACH
# injection (cumulative reads with explicit per-step deltas), not at the
# end. The counter SPLIT (STAT_PASS vs STAT_PASS_CIDR vs STAT_DROP_DENY)
# is the anti-theatricality fence: an OR-compose impl that always fired
# STAT_PASS would FAIL sub-case (b); an impl that always passed would
# FAIL sub-case (c).
#
# Sanity-floor smoke: the apply exit-0 + pin-existence check is the
# smoke test.
# Negation control: sub-case (c) — neither axis matches → DROP_DENY.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

# §5.43 MVP-4.3 (T-SKIP): MAC-axis matching is DEFERRED to mvp-4.5
# (HG-mvp-4.3-2 / PI-mvp-4.3-MAC-DEFERRED). The v2 config grammar rejects
# the `mac` match-key and the production datapath no longer consults the
# MAC HASH maps, so this MAC-verdict test cannot pass until the MAC-axis
# slice lands. Converted to SKIP (NOT silently dropped) — un-SKIP when the
# MAC-axis returns as a bit-vector axis in mvp-4.5.
echo "SKIP: MAC-axis deferred to mvp-4.5 per HG-mvp-4.3-2 / PI-mvp-4.3-MAC-DEFERRED" >&2
exit 77
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_mac_or_cidr.yaml"

[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-macorcidr-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT

# Rule from fixture: mac=AA:BB:CC:DD:EE:FF, src_cidr=10.0.0.0/8.
MAC_IN_RULE="AA:BB:CC:DD:EE:FF"
MAC_NOT_IN_RULE="11:22:33:44:55:66"
IP_IN_CIDR="10.5.6.7"
IP_OUT_CIDR="192.168.99.1"

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

# Confirm BOTH MAC inner AND CIDR inner pins were populated from the
# single OR-compose rule (load-bearing assertion: a buggy validator
# that populated only one axis would fail downstream sub-cases).
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

active=$(read_active_idx)
echo "active_idx = '${active}'"

if [[ "${active}" == "0" ]]; then
    mac_inner_pin="${PIN_DIR}/allowlist_a"
    cidr_inner_pin="${PIN_DIR}/cidr_allowlist_a"
elif [[ "${active}" == "1" ]]; then
    mac_inner_pin="${PIN_DIR}/allowlist_b"
    cidr_inner_pin="${PIN_DIR}/cidr_allowlist_b"
else
    mac_inner_pin=""
    cidr_inner_pin=""
fi

# Both inners must be non-empty: single rule contributes to BOTH.
for pin in "${mac_inner_pin}" "${cidr_inner_pin}"; do
    [[ -z "${pin}" ]] && continue
    if ! sudo -n test -e "${pin}"; then
        echo "FAIL[2]: expected inner pin ${pin} missing" >&2
        fail=1
        continue
    fi
    n=$(sudo -n bpftool map dump pinned "${pin}" --json 2>/dev/null | jq 'length' 2>/dev/null || echo 0)
    echo "  ${pin}: ${n} entries"
    if (( n < 1 )); then
        echo "FAIL[2]: inner pin ${pin} empty — OR-compose rule must populate BOTH axes" >&2
        sudo -n bpftool map dump pinned "${pin}" >&2 || true
        fail=1
    fi
done

# ── Sub-case (a): MAC-only match ───────────────────────────────────────
echo
echo "=== sub-case (a): MAC=${MAC_IN_RULE} (match) + src_ip=${IP_OUT_CIDR} (miss CIDR) → expect STAT_PASS"
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "  baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"

${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${MAC_IN_RULE}" "${MAC_DST}" "${IP_OUT_CIDR}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true

read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
echo "  after (a):    PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1} PASS_CIDR=${c1}"

# Q2 OR1: MAC hit short-circuits → STAT_PASS (NOT STAT_PASS_CIDR).
if (( p1 - p0 != 1 )); then
    echo "FAIL[a.p]: STAT_PASS delta != 1 (got $(( p1 - p0 )))" >&2
    echo "          OR1: MAC match must fire STAT_PASS via the cheap short-circuit." >&2
    fail=1
fi
if (( c1 - c0 != 0 )); then
    echo "FAIL[a.c]: STAT_PASS_CIDR moved on MAC-axis match (got delta $(( c1 - c0 )))" >&2
    echo "          OR1 short-circuit requires MAC hit to NOT also fire STAT_PASS_CIDR." >&2
    fail=1
fi
if (( d1 - d0 != 0 )); then
    echo "FAIL[a.d]: STAT_DROP_DENY moved on MAC-axis match (got delta $(( d1 - d0 )))" >&2
    fail=1
fi

# ── Sub-case (b): CIDR-only match ──────────────────────────────────────
echo
echo "=== sub-case (b): MAC=${MAC_NOT_IN_RULE} (miss) + src_ip=${IP_IN_CIDR} (match CIDR) → expect STAT_PASS_CIDR"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${MAC_NOT_IN_RULE}" "${MAC_DST}" "${IP_IN_CIDR}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true

read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
echo "  after (b):    PASS=${p2} DROP_DENY=${d2} DROP_MALFORMED=${m2} PASS_CIDR=${c2}"

if (( c2 - c1 != 1 )); then
    echo "FAIL[b.c]: STAT_PASS_CIDR delta != 1 (got $(( c2 - c1 )))" >&2
    echo "          MAC miss + CIDR hit must fire STAT_PASS_CIDR (not STAT_PASS)." >&2
    fail=1
fi
if (( p2 - p1 != 0 )); then
    echo "FAIL[b.p]: STAT_PASS moved on CIDR-axis match (got delta $(( p2 - p1 )))" >&2
    echo "          Counter SPLIT broken: CIDR hit must fire STAT_PASS_CIDR, NOT STAT_PASS." >&2
    fail=1
fi
if (( d2 - d1 != 0 )); then
    echo "FAIL[b.d]: STAT_DROP_DENY moved on CIDR-axis match (got delta $(( d2 - d1 )))" >&2
    fail=1
fi

# ── Sub-case (c): NEITHER match (NEGATION CONTROL) ─────────────────────
echo
echo "=== sub-case (c): MAC=${MAC_NOT_IN_RULE} (miss) + src_ip=${IP_OUT_CIDR} (miss) → expect STAT_DROP_DENY (NEGATION)"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${MAC_NOT_IN_RULE}" "${MAC_DST}" "${IP_OUT_CIDR}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + c2 + 1 )) || true

read -r p3 d3 m3 c3 < <(read_stats_with_cidr)
echo "  after (c):    PASS=${p3} DROP_DENY=${d3} DROP_MALFORMED=${m3} PASS_CIDR=${c3}"

if (( d3 - d2 != 1 )); then
    echo "FAIL[c.d]: STAT_DROP_DENY delta != 1 — NEGATION CONTROL FAILED (got $(( d3 - d2 )))" >&2
    echo "          neither axis matches → DROP. A PASS here means OR-compose is broken to always-PASS." >&2
    fail=1
fi
if (( p3 - p2 != 0 )); then
    echo "FAIL[c.p]: STAT_PASS moved on no-match packet (got delta $(( p3 - p2 )))" >&2
    fail=1
fi
if (( c3 - c2 != 0 )); then
    echo "FAIL[c.c]: STAT_PASS_CIDR moved on no-match packet (got delta $(( c3 - c2 )))" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_PASS_MAC_OR_CIDR"
exit "${fail}"
