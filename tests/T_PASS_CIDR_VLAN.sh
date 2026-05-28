#!/bin/bash
# T_PASS_CIDR_VLAN — design §6.43 (MVP-4.1 / §5.41).
#
# Verifies that a SINGLE 802.1Q-tagged IPv4 frame reaches the src-CIDR
# match branch — THE regression this slice closes. Pre-fix, a tagged
# frame's outer EtherType is 0x8100, so it never reaches the L3 gate and
# falls through to defaults[active] (= DROP_DENY for config_valid_cidr).
# Post-fix, the VLAN tag-walk derives the inner IPv4 EtherType + L3 offset
# and the existing CIDR branch fires.
#
#   1. apply config_valid_cidr.yaml (single rule: pass {src_cidr: 10.0.0.0/8},
#      default_action: drop).
#   2. Pin ${PIN_DIR}/cidr_rulesets exists.
#   3. Active inner LPM_TRIE (${PIN_DIR}/cidr_allowlist_a|b) is non-empty.
#   4. Inject a 1-tag (vid 100) IPv4 packet with src_ip = 10.5.6.7 (IN range),
#      src_mac = 99:99:99:99:99:99 (NOT in any MAC allowlist) →
#      STAT_PASS_CIDR += 1; STAT_PASS delta == 0; STAT_DROP_DENY delta == 0.
#      THIS IS THE REGRESSION DIFFERENTIAL (D-mvp-4.1-TEST-DIFF) — it FAILS
#      on a pre-fix binary (which would show STAT_DROP_DENY += 1).
#   5. Inject a 1-tag (vid 100) IPv4 packet with src_ip = 192.168.1.1 (OUT of
#      range), same src_mac → STAT_DROP_DENY += 1; STAT_PASS_CIDR delta == 0;
#      STAT_PASS delta == 0 (negation control — proves the fix did not break
#      to always-PASS).
#
# Sanity-floor smoke: the apply exit-0 + pin-existence checks (steps 1-3)
# ARE the smoke test — the counter assertions are unreachable without them.
# The pre-fix-DROP vs post-fix-PASS differential at step 4 IS the regression
# smoke; step 5 (out-of-range → DROP_DENY) is the negation control.
#
# NIC VLAN offload is disabled best-effort in setup so the kernel does not
# strip/rewrite the tag between AF_PACKET TX and XDP RX (guard #22 /
# D-mvp-4.1-TEST-VACUITY).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_cidr.yaml"

[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-passcidrvlan-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT

# A MAC not in any allowlist anywhere — proves the PASS is genuinely
# CIDR-axis driven, NOT MAC-axis short-circuit.
SRC_MAC_NONALLOW="99:99:99:99:99:99"
SRC_IP_IN_RANGE="10.5.6.7"
SRC_IP_OUT_RANGE="192.168.1.1"
VID=100

setup_veth

# ── Disable NIC VLAN offload (best-effort) — guard #22 ─────────────────
# Interfaces live inside the netns, so ethtool runs via ${NSEXEC}.
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

# ── Step 4: inject IN-range single-tag IPv4 → STAT_PASS_CIDR += 1 ──────
# REGRESSION DIFFERENTIAL: pre-fix → DROP_DENY (tag skips L3 gate);
# post-fix → PASS_CIDR (tag-walk reaches CIDR branch).
echo "=== step 4: inject --vlan ${VID} src_ip=${SRC_IP_IN_RANGE} (IN 10.0.0.0/8) src_mac=${SRC_MAC_NONALLOW}"
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "  baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"

${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${SRC_MAC_NONALLOW}" "${MAC_DST}" "${SRC_IP_IN_RANGE}" --vlan "${VID}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true

read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
echo "  after IN-range:  PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1} PASS_CIDR=${c1}"

if (( c1 - c0 != 1 )); then
    echo "FAIL[4.c]: STAT_PASS_CIDR delta != 1 (got $(( c1 - c0 )))" >&2
    echo "          REGRESSION: a single 802.1Q-tagged in-range IPv4 frame must reach the CIDR branch." >&2
    echo "          A pre-fix binary (or stripped tag) would show DROP_DENY += 1 here." >&2
    fail=1
fi
if (( p1 - p0 != 0 )); then
    echo "FAIL[4.p]: STAT_PASS moved on CIDR-axis hit (got delta $(( p1 - p0 )))" >&2
    echo "          MAC ${SRC_MAC_NONALLOW} is NOT in any MAC allowlist; the PASS must come from the CIDR axis." >&2
    fail=1
fi
if (( d1 - d0 != 0 )); then
    echo "FAIL[4.d]: STAT_DROP_DENY moved on IN-range tagged packet (got delta $(( d1 - d0 )))" >&2
    echo "          This is the pre-fix symptom: tag skipped the L3 gate and fell to defaults (drop)." >&2
    fail=1
fi

# ── Step 5: inject OUT-of-range single-tag IPv4 → STAT_DROP_DENY += 1 ──
# NEGATION CONTROL: proves the fix did not break to always-PASS.
echo "=== step 5: inject --vlan ${VID} src_ip=${SRC_IP_OUT_RANGE} (OUT 10.0.0.0/8) src_mac=${SRC_MAC_NONALLOW}"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${SRC_MAC_NONALLOW}" "${MAC_DST}" "${SRC_IP_OUT_RANGE}" --vlan "${VID}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true

read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
echo "  after OUT-range: PASS=${p2} DROP_DENY=${d2} DROP_MALFORMED=${m2} PASS_CIDR=${c2}"

if (( d2 - d1 != 1 )); then
    echo "FAIL[5.d]: STAT_DROP_DENY delta != 1 on OUT-range tagged packet (got $(( d2 - d1 )))" >&2
    fail=1
fi
if (( c2 - c1 != 0 )); then
    echo "FAIL[5.c]: STAT_PASS_CIDR moved on OUT-range tagged packet (got delta $(( c2 - c1 )))" >&2
    echo "          src_ip ${SRC_IP_OUT_RANGE} must miss 10.0.0.0/8 — a CIDR-axis hit means the fix broke to always-PASS." >&2
    fail=1
fi
if (( p2 - p1 != 0 )); then
    echo "FAIL[5.p]: STAT_PASS moved on OUT-range tagged packet (got delta $(( p2 - p1 )))" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_PASS_CIDR_VLAN"
exit "${fail}"
