#!/bin/bash
# T_PASS_MAC_OR_CIDR → T_MAC_AND_CIDR — design §5.47 TestStrategy (MVP-4.7).
#
# RE-AUTHORED OR→AND. The §6.30 OR short-circuit (a MAC hit short-circuits the
# CIDR axis) is GONE under the v2 bit-vector AND-model (D-mvp-4.7-MAC-RETURN-SHIFT).
# A single rule constraining BOTH `mac` AND `src_cidr` now matches a frame ONLY
# when BOTH axes hold.
#
# Fixture config_valid_mac_or_cidr.yaml: one rule, mac=AA:BB:CC:DD:EE:FF AND
# src_cidr=10.0.0.0/8, action pass, default drop.
#
# Four sub-cases (the AND truth table) — frames are IPv4 (MAC is IPv4-gated):
#   (a) M-hit + C-hit  → MATCH  → PASS (pass+pass_cidr delta == 1, deny 0)
#   (b) M-hit + C-miss → NO MATCH → DROP (deny delta == 1) — OR short-circuit GONE
#   (c) M-miss + C-hit → NO MATCH → DROP (deny delta == 1)
#   (d) M-miss + C-miss → NO MATCH → DROP (deny delta == 1) [NEGATION CONTROL]
#
# The load-bearing fences are (b) and (c): under the retired OR model EITHER of
# them would have PASSED (single-axis hit). Under AND they MUST drop.
#
# Sanity floor: smoke = apply exit 0 + BOTH inner axes populated from the single
# rule. Negation control = (d): neither axis matches → DROP.
#
# Maps to: PI-mvp-4.7-MAC, PI-mvp-4.3-AND (→6 axes), PI-mvp-4.3-WILDCARD.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_mac_or_cidr.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-macandcidr-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

# Rule from fixture.
MAC_IN_RULE="AA:BB:CC:DD:EE:FF"
MAC_NOT_IN_RULE="11:22:33:44:55:66"
IP_IN_CIDR="10.5.6.7"
IP_OUT_CIDR="192.168.99.1"

setup_veth

echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
cat "${stderr_file}" >&2 || true
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[smoke]: apply exit ${rc} (expected 0)" >&2
    exit 1
fi

fail=0

# Smoke: BOTH the MAC inner AND the CIDR inner must be populated by the single
# AND-rule (a validator that dropped one axis would fail the sub-cases below).
read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}
if command -v jq >/dev/null 2>&1; then
    active=$(read_active_idx)
    echo "active_idx = '${active}'"
    case "${active}" in
        0) mac_pin="${PIN_DIR}/allowlist_a"; cidr_pin="${PIN_DIR}/cidr_allowlist_a" ;;
        1) mac_pin="${PIN_DIR}/allowlist_b"; cidr_pin="${PIN_DIR}/cidr_allowlist_b" ;;
        *) mac_pin=""; cidr_pin="" ;;
    esac
    for pin in "${mac_pin}" "${cidr_pin}"; do
        [[ -z "${pin}" ]] && continue
        if ! sudo -n test -e "${pin}"; then
            echo "FAIL[smoke.pin]: expected inner pin ${pin} missing" >&2; fail=1; continue
        fi
        n=$(sudo -n bpftool map dump pinned "${pin}" --json 2>/dev/null | jq 'length' 2>/dev/null || echo 0)
        echo "  ${pin}: ${n} entries"
        if (( n < 1 )); then
            echo "FAIL[smoke.pin]: ${pin} empty — the AND-rule must populate BOTH axes" >&2; fail=1
        fi
    done
fi

# inject_and_classify <label> <src_mac> <src_ip> <expect: pass|drop>
inject_and_classify() {
    local label="$1" mac="$2" ip="$3" expect="$4"
    local p0 d0 m0 c0 p1 d1 m1 c1 passd dropd
    read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
    ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
        "${IFACE_B}" "${mac}" "${MAC_DST}" "${ip}"
    wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true
    read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
    passd=$(( (p1 - p0) + (c1 - c0) ))
    dropd=$(( d1 - d0 ))
    echo "  [${label}] mac=${mac} ip=${ip} → pass_delta=${passd} deny_delta=${dropd} (expect ${expect})"
    if [[ "${expect}" == "pass" ]]; then
        (( passd == 1 )) || { echo "FAIL[${label}]: pass_delta=${passd} (expected 1)" >&2; fail=1; }
        (( dropd == 0 )) || { echo "FAIL[${label}]: deny_delta=${dropd} (expected 0)" >&2; fail=1; }
    else
        (( dropd == 1 )) || { echo "FAIL[${label}]: deny_delta=${dropd} (expected 1 — AND requires BOTH axes)" >&2; fail=1; }
        (( passd == 0 )) || { echo "FAIL[${label}]: pass_delta=${passd} (expected 0 — OR short-circuit is GONE)" >&2; fail=1; }
    fi
}

echo "=== (a) M-hit + C-hit → MATCH (pass)"
inject_and_classify "a" "${MAC_IN_RULE}"     "${IP_IN_CIDR}"  pass
echo "=== (b) M-hit + C-miss → NO MATCH (drop) — OR short-circuit GONE"
inject_and_classify "b" "${MAC_IN_RULE}"     "${IP_OUT_CIDR}" drop
echo "=== (c) M-miss + C-hit → NO MATCH (drop)"
inject_and_classify "c" "${MAC_NOT_IN_RULE}" "${IP_IN_CIDR}"  drop
echo "=== (d) M-miss + C-miss → NO MATCH (drop) [NEGATION CONTROL]"
inject_and_classify "d" "${MAC_NOT_IN_RULE}" "${IP_OUT_CIDR}" drop

[[ "${fail}" == 0 ]] && echo "PASS: T_PASS_MAC_OR_CIDR (AND-compose: mac ∧ src_cidr)"
exit "${fail}"
