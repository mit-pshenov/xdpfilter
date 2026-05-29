#!/bin/bash
# T_RULE_COUNTER_MAC_HIT_BUMPS — design §5.47 TestStrategy (MVP-4.7 / §5.47).
#
# A MAC-axis match bumps the per-rule counter rule_match_total{rule_id} for the
# matched rule's id (first-match-by-id). MAC is the LIVE 6th exact-HASH axis
# (un-SKIP'd; PI-mvp-4.3-MAC-DEFERRED RETIRED). Sparse-id fixture proves the
# operator's YAML `id:` IS the BPF ARRAY index.
#
# Fixture config_mac_counters.yaml (mac-only rules; sparse ids 0/5/17/42):
#   id=0  mac 02:00:00:00:00:01 PASS    id=5  mac 02:00:00:00:00:05 PASS
#   id=17 mac 02:00:00:00:00:11 DROP    id=42 mac 02:00:00:00:00:2a PASS
#
# Trigger (frames are IPv4 — MAC is IPv4-gated, D-mvp-4.7-Q2-GATE):
#   (b) inject 5 frames src_mac=02:00:00:00:00:05 → rule_counters[5] == 5.
#   (c) inject 3 frames src_mac=02:00:00:00:00:01 → rule_counters[0] == 3;
#       slot 5 STILL 5.
#   (d) NEGATION — inject 2 frames src_mac=02:00:00:00:00:fe (no rule) →
#       rule_counters[0]/[5] UNCHANGED; STAT_DROP_DENY += 2.
#
# Sanity floor: smoke = apply exit 0 + rule_counters pin shape. Negation = (d).
#
# Maps to: PI-mvp-4.7-MAC, PI-mvp-4.6-COUNTER-CONTRACT, PI-mvp-4.3-COUNTER-PRESERVE.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for rule_counters dump parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_mac_counters.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

# MACs in fixture (must match config_mac_counters.yaml exactly).
MAC_ID0="02:00:00:00:00:01"   # rule_id=0 PASS
MAC_ID5="02:00:00:00:00:05"   # rule_id=5 PASS
MAC_OUTSIDE="02:00:00:00:00:fe"   # NOT in fixture — negation control
SRC_IP="10.0.0.9"             # irrelevant to mac-only rules; just well-formed IPv4

stderr_file=$(mktemp /tmp/xdpmf-rulemac-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

# active_idx-aware rule_counters inner reader.
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
read_rc_slot() {
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" "$(rule_counters_active_pin)" "$1"
}
inject_mac() {
    ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "$1" "${MAC_DST}" "${SRC_IP}"
}

# ── (a) apply + smoke ────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
cat "${stderr_file}" >&2 || true

fail=0
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[a1]: apply exit ${rc} (expected 0)" >&2
    exit 1
fi
if ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[a2]: ${PIN_DIR}/rule_counters_a pin missing" >&2
    exit 1
fi
shape_json=$(sudo -n bpftool map show pinned "$(rule_counters_active_pin)" --json 2>&1)
echo "rule_counters shape JSON: ${shape_json}"
shape_type=$(echo "${shape_json}" | jq -r '.type // empty' 2>/dev/null)
shape_max=$( echo "${shape_json}" | jq -r '.max_entries // empty' 2>/dev/null)
shape_vsz=$(echo "${shape_json}" | jq -r '.bytes_value // .value_size // empty' 2>/dev/null)
echo "  type=${shape_type} max_entries=${shape_max} value_size=${shape_vsz}"
[[ "${shape_type}" == "percpu_array" ]] || { echo "FAIL[a3]: type='${shape_type}' (expected percpu_array)" >&2; fail=1; }
[[ "${shape_max}"  == "64" ]]          || { echo "FAIL[a4]: max_entries='${shape_max}' (expected 64)" >&2; fail=1; }
[[ "${shape_vsz}"  == "8" ]]           || { echo "FAIL[a5]: value_size='${shape_vsz}' (expected 8)" >&2; fail=1; }

# Baseline: all 64 slots zero.
all_baseline=$(sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" "$(rule_counters_active_pin)")
nonzero_baseline=$(echo "${all_baseline}" | tr ' ' '\n' | grep -cvE '^0$' || true)
nonzero_baseline=${nonzero_baseline:-0}
[[ "${nonzero_baseline}" == "0" ]] || { echo "FAIL[a6]: baseline has ${nonzero_baseline} non-zero slot(s)" >&2; fail=1; }

# A MAC-axis pass may land in STAT_PASS or STAT_PASS_CIDR — count the 4-col SUM
# so the post-inject sync barrier is reliable regardless of the pass bucket.
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "stats baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"

# ── (b) 5 frames from MAC_ID5 → rule_counters[5] == 5 ────────────────────
echo "=== (b) inject 5 IPv4 frames src_mac=${MAC_ID5} (rule_id=5 PASS)"
for i in 1 2 3 4 5; do inject_mac "${MAC_ID5}"; done
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 5 )) || true

c5=$(read_rc_slot 5)
echo "rule_counters[5]=${c5} (expected 5)"
[[ "${c5}" == "5" ]] || { echo "FAIL[b1]: rule_counters[5]='${c5}' (expected 5)" >&2; fail=1; }
# All other slots STAY 0.
all_after_b=$(sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" "$(rule_counters_active_pin)")
idx=0
for v in ${all_after_b}; do
    if [[ "${idx}" != "5" && "${v}" != "0" ]]; then
        echo "FAIL[b2]: rule_counters[${idx}]='${v}' (expected 0; only slot 5 should move)" >&2; fail=1
    fi
    idx=$(( idx + 1 ))
done

# ── (c) 3 frames from MAC_ID0 → rule_counters[0] == 3; slot 5 STILL 5 ────
echo "=== (c) inject 3 IPv4 frames src_mac=${MAC_ID0} (rule_id=0 PASS)"
read -r p_b d_b m_b c_b < <(read_stats_with_cidr)
for i in 1 2 3; do inject_mac "${MAC_ID0}"; done
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p_b + d_b + m_b + c_b + 3 )) || true

c0=$(read_rc_slot 0); c5=$(read_rc_slot 5)
echo "rule_counters[0]=${c0} (expected 3); rule_counters[5]=${c5} (expected 5)"
[[ "${c0}" == "3" ]] || { echo "FAIL[c1]: rule_counters[0]='${c0}' (expected 3)" >&2; fail=1; }
[[ "${c5}" == "5" ]] || { echo "FAIL[c2]: rule_counters[5]='${c5}' (expected STILL 5)" >&2; fail=1; }

# ── (d) NEGATION: 2 non-matching frames → no counter move; deny += 2 ─────
echo "=== (d) NEGATION — inject 2 IPv4 frames src_mac=${MAC_OUTSIDE} (no rule)"
read -r p_c d_c m_c c_c < <(read_stats_with_cidr)
for i in 1 2; do inject_mac "${MAC_OUTSIDE}"; done
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p_c + d_c + m_c + c_c + 2 )) || true

c0=$(read_rc_slot 0); c5=$(read_rc_slot 5)
echo "rule_counters[0]=${c0} (expected STILL 3); rule_counters[5]=${c5} (expected STILL 5)"
[[ "${c0}" == "3" ]] || { echo "FAIL[d1]: rule_counters[0]='${c0}' bumped on negation (expected STILL 3)" >&2; fail=1; }
[[ "${c5}" == "5" ]] || { echo "FAIL[d2]: rule_counters[5]='${c5}' bumped on negation (expected STILL 5)" >&2; fail=1; }
read -r p_d d_d m_d c_d < <(read_stats_with_cidr)
if (( d_d - d_c != 2 )); then
    echo "FAIL[d3]: STAT_DROP_DENY delta=$((d_d - d_c)) (expected 2 from non-matching frames)" >&2; fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_RULE_COUNTER_MAC_HIT_BUMPS (MAC-axis match bumps per-rule counter)"
exit "${fail}"
