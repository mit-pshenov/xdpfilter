#!/bin/bash
# T_PROTO_AND_COMPOSE — design §6.64 (MVP-4.4 / §5.44).
#
# Proves the NEW proto axis is an exact-HASH bit-vector axis intersected (AND)
# with the other axes — NOT unioned (PI-mvp-4.4-PROTO, PI-mvp-4.4-AND4).
#
# Fixture config_valid_and4.yaml (schema_version: 2):
#   id 0 : dst 10.1.0.0/16 AND src 192.168.5.0/24 AND tcp AND port 1000-2000  pass
#   id 1 : dst 10.3.0.0/16 AND udp                                            pass
#   id 5 : dst_port 1000-2000 (port-only; proto wildcard)                     pass
#   ... (see fixture)
#
# Steps / observable outcome (ALL must hold):
#   (a) SMOKE: apply exit 0; proto_rulesets + port_rulesets + wildcard pins
#       exist; the active proto inner is non-empty (2 proto keys: 6, 17).
#   (b) TCP packet on id0's OTHER axes (dst=10.1.2.3 src=192.168.5.50
#       dport=1500 proto=tcp) → id0 hit: rule_counters[0] == 1.
#   (c) NEGATION CONTROL — the SAME 4-tuple sent as UDP (proto flipped only)
#       must NOT hit id0: rule_counters[0] STAYS 1. The proto bit is cleared
#       from the accumulator → the packet routes to the port-only rule id5
#       (proto wildcard): rule_counters[5] == 1. A datapath that UNIONS proto
#       (or ignores it) would re-hit id0 here → this step FAILS it.
#
# Sanity floor: smoke = step (a). Negation control = step (c) — a proto
# mismatch of an all-axes rule MUST NOT fire that rule.
#
# Maps to: PI-mvp-4.4-PROTO, PI-mvp-4.4-AND4, PI-mvp-4.4-WILDCARD.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_and4.yaml"
INJECT="${TEST_DIR}/inject/inject_l4.py"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }
[[ -f "${INJECT}"  ]] || { echo "FAIL: missing injector ${INJECT}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-protoand-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

# ── active_idx-aware rule_counters reader (§5.34/§5.35 topology) ──────────
read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}
rule_counters_active_pin() {
    case "$(read_active_idx)" in
        1) echo "${PIN_DIR}/rule_counters_b" ;;
        *) echo "${PIN_DIR}/rule_counters_a" ;;
    esac
}
proto_inner_active_pin() {
    case "$(read_active_idx)" in
        1) echo "${PIN_DIR}/proto_bitmask_b" ;;
        *) echo "${PIN_DIR}/proto_bitmask_a" ;;
    esac
}
read_rc_slot() {
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" \
        "$(rule_counters_active_pin)" "$1"
}
# inject <dst> <src> <proto> <dport>
inject() {
    ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" \
        --dst-ip "$1" --src-ip "$2" --proto "$3" --dport "$4" \
        --dst-mac "${MAC_DST}"
}

# ── (a) apply + smoke ────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
cat "${stderr_file}" >&2 || true
echo "rc=${rc}"

fail=0
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[a1]: apply exit ${rc} (expected 0)" >&2
    exit 1
fi
for pin in proto_rulesets port_rulesets ruleset_state; do
    if ! sudo -n test -e "${PIN_DIR}/${pin}"; then
        echo "FAIL[a2]: expected pin ${PIN_DIR}/${pin} missing (§5.44 DataStructures)" >&2
        fail=1
    fi
done
# Active proto inner must hold the two constrained protos (tcp=6, udp=17).
proto_entries=$(sudo -n bpftool map dump pinned "$(proto_inner_active_pin)" --json 2>/dev/null \
                | jq 'length' 2>/dev/null || echo 0)
if [[ -z "${proto_entries}" || "${proto_entries}" -lt 1 ]]; then
    echo "FAIL[a3]: active proto inner empty (expected >=1 proto key after apply)" >&2
    fail=1
else
    echo "smoke OK: proto inner has ${proto_entries} key(s)"
fi
for slot in 0 5; do
    v=$(read_rc_slot "${slot}")
    [[ "${v}" == "0" ]] || { echo "FAIL[a4]: rule_counters[${slot}]='${v}' baseline (expected 0)" >&2; fail=1; }
done

# ── (b) TCP on id0's other axes → id0 hit ────────────────────────────────
echo "=== (b) inject dst=10.1.2.3 src=192.168.5.50 proto=tcp dport=1500 (id0 full-4-axis)"
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
inject 10.1.2.3 192.168.5.50 tcp 1500
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true
rc0=$(read_rc_slot 0)
if [[ "${rc0}" != "1" ]]; then
    echo "FAIL[b1]: rule_counters[0]='${rc0}' (expected 1 — TCP matches the proto:tcp rule id0)" >&2
    fail=1
fi

# ── (c) NEGATION: same 4-tuple as UDP → must NOT hit id0 ──────────────────
echo "=== (c) NEGATION: inject dst=10.1.2.3 src=192.168.5.50 proto=udp dport=1500 (proto flipped)"
read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
inject 10.1.2.3 192.168.5.50 udp 1500
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true
rc0=$(read_rc_slot 0)
rc5=$(read_rc_slot 5)
if [[ "${rc0}" != "1" ]]; then
    echo "FAIL[c1]: rule_counters[0]='${rc0}' bumped on a UDP packet (expected STILL 1)" >&2
    echo "          bug shape: datapath UNIONS / ignores the proto axis instead of ANDing it" >&2
    fail=1
fi
if [[ "${rc5}" != "1" ]]; then
    echo "FAIL[c2]: rule_counters[5]='${rc5}' (expected 1 — UDP routes to the port-only rule id5)" >&2
    echo "          bug shape: proto bit not cleared from acc, or port-wildcard rule not surviving" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_PROTO_AND_COMPOSE (proto axis intersects, not unions)"
exit "${fail}"
