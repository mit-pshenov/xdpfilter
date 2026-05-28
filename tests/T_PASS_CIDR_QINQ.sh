#!/bin/bash
# T_PASS_CIDR_QINQ — design §6.44 (MVP-4.1 / §5.41).
#
# Verifies (a) the depth-2 QinQ tag-walk reaches the src-CIDR branch, and
# (b) the LOAD-BEARING depth-3-overflow anti-vacuity fence: a 3rd stacked
# tag is NOT parsed (XDPMF_VLAN_MAX_DEPTH = 2), so the frame falls through
# to defaults (DROP_DENY) — a verdict producible ONLY if XDP saw all 3 raw
# tags AND the depth cap holds.
#
#   1. apply config_valid_cidr.yaml (pass {src_cidr: 10.0.0.0/8}, default drop).
#   2. Pin ${PIN_DIR}/cidr_rulesets exists.
#   3. Active inner LPM_TRIE (${PIN_DIR}/cidr_allowlist_a|b) is non-empty.
#   4. Inject a DEPTH-2 (vid 100,200) IPv4 packet, src_ip = 10.5.6.7 (IN range),
#      src_mac = 99:99:99:99:99:99 (NOT in any MAC allowlist) →
#      STAT_PASS_CIDR += 1; STAT_PASS delta == 0; STAT_DROP_DENY delta == 0.
#      Verifies the depth-2 walk reaches L3.
#   5. Inject a DEPTH-3 (vid 100,200,300) IPv4 packet, src_ip = 10.5.6.7
#      (IN range inner IPv4), same src_mac → STAT_DROP_DENY += 1;
#      STAT_PASS_CIDR delta == 0.
#      LOAD-BEARING ANTI-VACUITY (D-mvp-4.1-TEST-VACUITY): the <=2 walk stops
#      at the 3rd tag's TPID (non-IPv4) → defaults → DROP_DENY. This verdict
#      is producible ONLY if XDP saw all 3 raw tags AND stopped at the
#      depth-2 cap. A stripped-tag environment would present <=2 tags and
#      emit STAT_PASS_CIDR here, FAILING the assertion. This is the test the
#      existing untagged-only suite structurally cannot provide.
#
# Sanity-floor smoke: the apply exit-0 + pin-existence checks (steps 1-3)
# ARE the smoke test. Step 5 (depth-3 → DROP) IS the negation control /
# anti-vacuity fence.
#
# NIC VLAN offload is disabled best-effort in setup so the kernel does not
# strip/rewrite the tags between AF_PACKET TX and XDP RX (guard #22).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_cidr.yaml"

[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-passcidrqinq-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT

SRC_MAC_NONALLOW="99:99:99:99:99:99"
SRC_IP_IN_RANGE="10.5.6.7"
VID_OUTER=100
VID_MIDDLE=200
VID_INNER=300

setup_veth

# ── Disable NIC VLAN offload (best-effort) — guard #22 ─────────────────
${NSEXEC} ethtool -K "${IFACE_A}" rxvlan off txvlan off 2>/dev/null || true
${NSEXEC} ethtool -K "${IFACE_B}" rxvlan off txvlan off 2>/dev/null || true

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

# ── Step 4: inject DEPTH-2 in-range IPv4 → STAT_PASS_CIDR += 1 ─────────
echo "=== step 4: inject --vlan ${VID_OUTER} --vlan ${VID_MIDDLE} src_ip=${SRC_IP_IN_RANGE} (IN range) src_mac=${SRC_MAC_NONALLOW}"
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "  baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"

${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${SRC_MAC_NONALLOW}" "${MAC_DST}" "${SRC_IP_IN_RANGE}" \
    --vlan "${VID_OUTER}" --vlan "${VID_MIDDLE}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true

read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
echo "  after depth-2:   PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1} PASS_CIDR=${c1}"

if (( c1 - c0 != 1 )); then
    echo "FAIL[4.c]: STAT_PASS_CIDR delta != 1 on depth-2 tagged in-range packet (got $(( c1 - c0 )))" >&2
    echo "          The depth-2 QinQ walk must reach the CIDR branch." >&2
    fail=1
fi
if (( p1 - p0 != 0 )); then
    echo "FAIL[4.p]: STAT_PASS moved on CIDR-axis hit (got delta $(( p1 - p0 )))" >&2
    fail=1
fi
if (( d1 - d0 != 0 )); then
    echo "FAIL[4.d]: STAT_DROP_DENY moved on depth-2 in-range packet (got delta $(( d1 - d0 )))" >&2
    fail=1
fi

# ── Step 5: inject DEPTH-3 in-range inner IPv4 → STAT_DROP_DENY += 1 ───
# LOAD-BEARING ANTI-VACUITY FENCE (D-mvp-4.1-TEST-VACUITY / guard #22).
echo "=== step 5: inject --vlan ${VID_OUTER} --vlan ${VID_MIDDLE} --vlan ${VID_INNER} src_ip=${SRC_IP_IN_RANGE} (3 tags, in-range inner) src_mac=${SRC_MAC_NONALLOW}"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${SRC_MAC_NONALLOW}" "${MAC_DST}" "${SRC_IP_IN_RANGE}" \
    --vlan "${VID_OUTER}" --vlan "${VID_MIDDLE}" --vlan "${VID_INNER}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true

read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
echo "  after depth-3:   PASS=${p2} DROP_DENY=${d2} DROP_MALFORMED=${m2} PASS_CIDR=${c2}"

if (( d2 - d1 != 1 )); then
    echo "FAIL[5.d]: STAT_DROP_DENY delta != 1 on depth-3 (overflow) packet (got $(( d2 - d1 )))" >&2
    echo "          The <=2 tag-walk must stop at the 3rd tag's TPID (non-IPv4) → defaults → DROP_DENY." >&2
    fail=1
fi
if (( c2 - c1 != 0 )); then
    echo "FAIL[5.c]: STAT_PASS_CIDR moved on depth-3 (overflow) packet (got delta $(( c2 - c1 )))" >&2
    echo "          ANTI-VACUITY VIOLATION: PASS_CIDR here means either (a) the depth cap > 2 (3rd tag parsed)," >&2
    echo "          or (b) a NIC offload STRIPPED tags before XDP (frame presented <=2 tags). Check ethtool -K" >&2
    echo "          rxvlan/txvlan off on ${IFACE_A}/${IFACE_B} and XDPMF_VLAN_MAX_DEPTH == 2." >&2
    fail=1
fi
if (( p2 - p1 != 0 )); then
    echo "FAIL[5.p]: STAT_PASS moved on depth-3 (overflow) packet (got delta $(( p2 - p1 )))" >&2
    fail=1
fi
if (( m2 - m1 != 0 )); then
    echo "FAIL[5.m]: STAT_DROP_MALFORMED moved on depth-3 packet (got delta $(( m2 - m1 )))" >&2
    echo "          A depth-overflow tag must fall to defaults (DROP_DENY), NOT be reclassified MALFORMED" >&2
    echo "          (HG-mvp-4.1-2 / D-mvp-4.1-MALFORMED)." >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_PASS_CIDR_QINQ"
exit "${fail}"
