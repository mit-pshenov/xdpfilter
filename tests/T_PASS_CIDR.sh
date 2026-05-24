#!/bin/bash
# T_PASS_CIDR — design §6.28 (MVP-3.2 / §5.27).
#
# Verifies the CIDR-axis datapath end-to-end:
#   1. apply config_valid_cidr.yaml (single rule: pass {src_cidr: 10.0.0.0/8}).
#   2. Pin ${PIN_DIR}/cidr_rulesets exists.
#   3. Active inner LPM_TRIE (${PIN_DIR}/cidr_allowlist_a|b) is non-empty.
#   4. Inject IPv4 packet with src_ip = 10.5.6.7 (IN range), arbitrary
#      src_mac (NOT in any MAC allowlist) → STAT_PASS_CIDR += 1; STAT_PASS
#      delta == 0; STAT_DROP_DENY delta == 0.
#   5. Inject IPv4 packet with src_ip = 192.168.1.1 (OUT of range), same
#      arbitrary src_mac → STAT_DROP_DENY += 1; STAT_PASS_CIDR delta == 0.
#
# Sanity-floor smoke: the apply exit-0 + pin-existence checks before any
# packet injection ARE the smoke test (we cannot reach the counter
# assertions without them).
# Negation control: step 5 (out-of-range src_ip → DROP_DENY) is the
# differential — if CIDR axis were broken to always-PASS, step 5 would
# increment STAT_PASS_CIDR instead of STAT_DROP_DENY. The counter SPLIT
# is the anti-theatricality fence.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_cidr.yaml"

[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-passcidr-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT

# A MAC not in any allowlist anywhere — proves the PASS is genuinely
# CIDR-axis driven, NOT MAC-axis short-circuit.
SRC_MAC_NONALLOW="99:99:99:99:99:99"
SRC_IP_IN_RANGE="10.5.6.7"
SRC_IP_OUT_RANGE="192.168.1.1"

setup_veth

# ── Step 1: apply CIDR fixture ──────────────────────────────────────────
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

# ── Step 2: CIDR-outer pin exists ──────────────────────────────────────
if ! sudo -n test -e "${PIN_DIR}/cidr_rulesets"; then
    echo "FAIL[2]: expected pin ${PIN_DIR}/cidr_rulesets missing" >&2
    fail=1
fi

# ── Step 3: active CIDR inner non-empty ─────────────────────────────────
# Read active_idx to pick the correct inner pin (a or b).
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
    cidr_inner_pin="${PIN_DIR}/cidr_allowlist_a"
elif [[ "${active}" == "1" ]]; then
    cidr_inner_pin="${PIN_DIR}/cidr_allowlist_b"
else
    cidr_inner_pin=""
fi

if [[ -n "${cidr_inner_pin}" ]]; then
    if ! sudo -n test -e "${cidr_inner_pin}"; then
        echo "FAIL[3a]: active CIDR inner pin ${cidr_inner_pin} missing" >&2
        fail=1
    else
        # Count entries — must be >= 1 (the 10.0.0.0/8 we just applied).
        n_entries=$(sudo -n bpftool map dump pinned "${cidr_inner_pin}" --json 2>/dev/null \
                    | jq 'length' 2>/dev/null || echo 0)
        echo "  active CIDR inner has ${n_entries} entr(y/ies)"
        if (( n_entries < 1 )); then
            echo "FAIL[3b]: active CIDR inner pin ${cidr_inner_pin} empty (expected >= 1)" >&2
            sudo -n bpftool map dump pinned "${cidr_inner_pin}" >&2 || true
            fail=1
        fi
    fi
fi

# ── Step 4: inject IN-range IPv4 packet → STAT_PASS_CIDR += 1 ──────────
echo "=== step 4: inject src_ip=${SRC_IP_IN_RANGE} (IN 10.0.0.0/8) src_mac=${SRC_MAC_NONALLOW}"
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "  baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"

${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${SRC_MAC_NONALLOW}" "${MAC_DST}" "${SRC_IP_IN_RANGE}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true

read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
echo "  after IN-range:  PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1} PASS_CIDR=${c1}"

if (( c1 - c0 != 1 )); then
    echo "FAIL[4.c]: STAT_PASS_CIDR delta != 1 (got $(( c1 - c0 )))" >&2
    fail=1
fi
if (( p1 - p0 != 0 )); then
    echo "FAIL[4.p]: STAT_PASS moved on CIDR-axis hit (got delta $(( p1 - p0 )))" >&2
    echo "          MAC ${SRC_MAC_NONALLOW} is NOT in any MAC allowlist; the PASS must come from the CIDR axis (STAT_PASS_CIDR)." >&2
    fail=1
fi
if (( d1 - d0 != 0 )); then
    echo "FAIL[4.d]: STAT_DROP_DENY moved on IN-range packet (got delta $(( d1 - d0 )))" >&2
    fail=1
fi

# ── Step 5: inject OUT-of-range IPv4 packet → STAT_DROP_DENY += 1 ──────
echo "=== step 5: inject src_ip=${SRC_IP_OUT_RANGE} (OUT 10.0.0.0/8) src_mac=${SRC_MAC_NONALLOW}"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${SRC_MAC_NONALLOW}" "${MAC_DST}" "${SRC_IP_OUT_RANGE}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true

read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
echo "  after OUT-range: PASS=${p2} DROP_DENY=${d2} DROP_MALFORMED=${m2} PASS_CIDR=${c2}"

if (( d2 - d1 != 1 )); then
    echo "FAIL[5.d]: STAT_DROP_DENY delta != 1 on OUT-range packet (got $(( d2 - d1 )))" >&2
    fail=1
fi
if (( c2 - c1 != 0 )); then
    echo "FAIL[5.c]: STAT_PASS_CIDR moved on OUT-range packet (got delta $(( c2 - c1 )))" >&2
    echo "          src_ip ${SRC_IP_OUT_RANGE} must miss 10.0.0.0/8 — a CIDR-axis hit here means LPM_TRIE matched a wrong prefix." >&2
    fail=1
fi
if (( p2 - p1 != 0 )); then
    echo "FAIL[5.p]: STAT_PASS moved on OUT-range packet (got delta $(( p2 - p1 )))" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_PASS_CIDR"
exit "${fail}"
