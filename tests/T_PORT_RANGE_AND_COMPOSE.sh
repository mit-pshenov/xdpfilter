#!/bin/bash
# T_PORT_RANGE_AND_COMPOSE — design §6.65 (MVP-4.4 / §5.44).
#
# Proves the NEW dst_port axis is a bounded range-scan: a packet matches a
# dst_port rule iff dport ∈ [lo,hi] (inclusive); single-port rules (lo==hi)
# match only their exact port; and a packet with no L4 port (ICMP, has_port=0)
# can match ONLY port-wildcard rules (PI-mvp-4.4-PORT, PI-mvp-4.4-L4PARSE).
#
# Fixture config_valid_and4.yaml (schema_version: 2):
#   id 3 : dst 10.7.0.0/16 (dst-only; port wildcard)   pass
#   id 4 : dst_port 443 (single; lo==hi)               pass
#   id 5 : dst_port 1000-2000 (inclusive range)        pass
#   default_action: drop
#
# All probe packets use dst=203.0.113.5 / src=8.8.8.8 (matched by NO dst/src
# rule) so routing is decided purely by the port axis — EXCEPT the ICMP
# survival case (e2) which targets the dst-only rule id3.
#
# Steps / observable outcome (ALL must hold):
#   (a) SMOKE: apply exit 0; port_rulesets pin exists; active port inner holds
#       the used range slots.
#   (a') dport=1500 (∈ [1000,2000])              → id5 hit  (rc[5] -> 1)
#   (b)  NEGATION: dport=999 and dport=2001 (just outside [1000,2000])
#                                                → NO port rule (rc[5] STAYS 1)
#   (c)  dport=1000 and dport=2000 (inclusive edges)
#                                                → id5 hit  (rc[5] -> 2, 3)
#   (d)  dport=443 → id4 (single-port);  dport=444 → NO hit (rc[4]: 1, STAYS 1)
#   (e1) NEGATION: ICMP dst=203.0.113.5 (has_port=0) → NO port rule fires
#                  (rc[4]/rc[5] unchanged; falls to defaults drop)
#   (e2) ICMP dst=10.7.1.1 → survives the port-wildcard dst-only rule id3
#                                                → id3 hit  (rc[3] -> 1)
#
# Sanity floor: smoke = (a). Negation controls = (b) out-of-range +
# (e1) ICMP has_port=0 — both MUST NOT fire any port-constrained rule.
#
# Maps to: PI-mvp-4.4-PORT, PI-mvp-4.4-L4PARSE, PI-mvp-4.4-WILDCARD.
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

stderr_file=$(mktemp /tmp/xdpmf-portand-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

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
port_inner_active_pin() {
    case "$(read_active_idx)" in
        1) echo "${PIN_DIR}/port_ranges_b" ;;
        *) echo "${PIN_DIR}/port_ranges_a" ;;
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

DST=203.0.113.5   # matched by NO dst rule → routing decided purely by port
SRC=8.8.8.8       # matched by NO src rule

fail=0
# Send one frame + sync, then assert rule_counters[3/4/5] == running expected.
exp3=0 exp4=0 exp5=0
step() {                      # step <label> <dst> <src> <proto> <dport>
    local label="$1" dst="$2" src="$3" proto="$4" dport="$5"
    local p d m c
    read -r p d m c < <(read_stats_with_cidr)
    inject "${dst}" "${src}" "${proto}" "${dport}"
    wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p + d + m + c + 1 )) || true
    local r3 r4 r5
    r3=$(read_rc_slot 3); r4=$(read_rc_slot 4); r5=$(read_rc_slot 5)
    if [[ "${r3}" != "${exp3}" || "${r4}" != "${exp4}" || "${r5}" != "${exp5}" ]]; then
        echo "FAIL[${label}]: rule_counters {id3=${r3} id4=${r4} id5=${r5}}" \
             "expected {id3=${exp3} id4=${exp4} id5=${exp5}}" \
             "(dst=${dst} proto=${proto} dport=${dport})" >&2
        fail=1
    else
        echo "  [${label}] dst=${dst} proto=${proto} dport=${dport} -> {id3=${r3} id4=${r4} id5=${r5}} OK"
    fi
}

# ── (a) apply + smoke ────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
cat "${stderr_file}" >&2 || true
echo "rc=${rc}"
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[a1]: apply exit ${rc} (expected 0)" >&2
    exit 1
fi
if ! sudo -n test -e "${PIN_DIR}/port_rulesets"; then
    echo "FAIL[a2]: ${PIN_DIR}/port_rulesets pin missing (§5.44 DataStructures)" >&2
    fail=1
fi
# The active port inner must hold the used range slots (id4 single + id5 range).
port_used=$(sudo -n bpftool map dump pinned "$(port_inner_active_pin)" --json 2>/dev/null \
            | jq '[.[] | (.formatted.value // .value) | tostring] | length' 2>/dev/null || echo 0)
if [[ -z "${port_used}" || "${port_used}" -lt 1 ]]; then
    echo "FAIL[a3]: active port inner unreadable/empty after apply" >&2
    fail=1
else
    echo "smoke OK: port inner readable (${port_used} slot rows)"
fi
for slot in 3 4 5; do
    v=$(read_rc_slot "${slot}")
    [[ "${v}" == "0" ]] || { echo "FAIL[a4]: rule_counters[${slot}]='${v}' baseline (expected 0)" >&2; fail=1; }
done

# ── (a') in-range middle → id5 ───────────────────────────────────────────
exp5=1; step "a'-in-range-1500" "${DST}" "${SRC}" tcp 1500

# ── (b) NEGATION: just outside the range → NO port rule ──────────────────
# exp unchanged: out-of-range must not bump any port rule.
step "b-below-999"  "${DST}" "${SRC}" tcp 999
step "b-above-2001" "${DST}" "${SRC}" tcp 2001

# ── (c) inclusive edges → id5 ────────────────────────────────────────────
exp5=2; step "c-edge-lo-1000" "${DST}" "${SRC}" tcp 1000
exp5=3; step "c-edge-hi-2000" "${DST}" "${SRC}" tcp 2000

# ── (d) single-port rule id4 ─────────────────────────────────────────────
exp4=1; step "d-single-443" "${DST}" "${SRC}" tcp 443
# 444 must NOT hit the single-port rule.
step "d-single-miss-444" "${DST}" "${SRC}" tcp 444

# ── (e1) NEGATION: ICMP (has_port=0) on a no-rule dst → NO port rule ──────
step "e1-icmp-no-port" "${DST}" "${SRC}" icmp 1500

# ── (e2) ICMP survives the port-wildcard dst-only rule id3 ───────────────
exp3=1; step "e2-icmp-dst-wildcard-port" 10.7.1.1 "${SRC}" icmp 1500

[[ "${fail}" == 0 ]] && echo "PASS: T_PORT_RANGE_AND_COMPOSE (range inclusivity + has_port)"
exit "${fail}"
