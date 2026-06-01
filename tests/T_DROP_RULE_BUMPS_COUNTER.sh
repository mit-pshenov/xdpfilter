#!/bin/bash
# T_DROP_RULE_BUMPS_COUNTER — design §6.52-revised (MVP-3.4b cycle 2 / §5.34).
#
# REWRITTEN per Q3.A + HG-3.4b-c2-2 (PI-6-3.4b-c2 carve-out). The
# pre-§5.34 body asserted the §5.26 schema cycle 2 contract ("drop rules
# don't populate inner-allowlist; rule_counters stay 0"). §5.34 RETIRES
# that contract: drop rules NOW populate the inner-allowlist with their
# rule_id, the per-rule counter NOW bumps on match (HG-3.4b-c2-5), and
# the verdict XDP_DROP is dispatched via the rules→action_table chain
# (PI-29-3.4b-c2), NOT via the defaults[active]=drop fallthrough.
#
# Test name kept (now matches semantic — pre-§5.34 the name was ironic).
#
# Per §5.34 Q3.A concrete shape:
#   - Apply config_per_rule_counters.yaml (id=17 DROP MAC_11; id=5 PASS).
#   - Inject 5 frames from drop-MAC.
#   - Assert STAT_DROP_DENY delta == 5 (value unchanged from pre-§5.34;
#     mechanism flipped from defaults-fallthrough to action_table dispatch).
#   - NEW: assert rule_counters[17] delta == 5 (was 0 pre-§5.34).
#   - NEW: assert drop-rule MAC IS in active inner-allowlist (was ABSENT).
#   - Sidecar rule_index.json for id=17 STILL shows action="drop"
#     (sidecar shape UNCHANGED — only the inner-allowlist population
#     filter changed in loader.cpp; sidecar emit is downstream).
#   - Negation: inject 2 frames from id=5 PASS MAC → rc[5] == 2,
#     rc[17] still == 5 (no cross-bump). STAT_PASS delta == 2.
#
# Observable outcome (ALL must hold):
#   (a) apply exit 0.
#   (b) STAT_DROP_DENY delta == 5 (the drop-MAC frames).
#   (c) rule_counters[17] delta == 5 (was 0 pre-§5.34 — INVERTED).
#   (d) rules_<active>[17] has present=1, action_id=1 (DROP).
#   (e) Sidecar rule_index.json shows rule_id=17 with action="drop".
#   (f) drop-rule MAC IS in active inner-allowlist (was ABSENT — INVERTED).
#   (g) After negation: rule_counters[5] == 2; rule_counters[17] still
#       advanced exactly 5 (no cross-bump on pass-MAC traffic).
#
# Sanity-floor smoke: step (a) — apply succeeds.
# Negation control: step (g) — pass-rule MAC bumps rc[5] while drop-rule
# counter rc[17] does NOT advance on pass-MAC frames. This is the
# differential proving rc[N] keys on rule_id (i.e., on inner-allowlist
# match), not on traffic volume.
#
# Maps to: HG-3.4b-c2-2 (schema cycle 3 shift — load-bearing for this
# rewrite), HG-3.4b-c2-5 (counter bumps regardless of verdict),
# §5.34 D-3.4b-c2-2 (filter-line removal mechanism),
# PI-29-3.4b-c2 (datapath consults rules+action_table),
# PI-30-3.4b-c2-schema, Q3.A disposition.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for rules + rule_counters dump parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_per_rule_counters.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

SRC_MAC="02:00:00:00:00:aa"  # 5.43: MAC deferred
SRC_IP_DROP="10.17.0.1"   # id17 DROP (10.17.0.0/16)
SRC_IP_PASS="10.5.0.1"    # id5 PASS (10.5.0.0/16)

# §5.31 EDIT-1: sidecar path = /run/xdpmacfilter/<iface>/rule_index.json
SIDECAR_ROOT="/run/xdpmacfilter"
SIDECAR_DIR="${SIDECAR_ROOT}/${IFACE_A}"
SIDECAR_PATH="${SIDECAR_DIR}/rule_index.json"

stderr_file=$(mktemp /tmp/xdpmf-droprule-stderr.XXXXXX)
trap 'cleanup_veth; sudo -n rm -rf "${SIDECAR_DIR}" 2>/dev/null; rm -f "${stderr_file}"' EXIT

# §5.35 (MVP-3.4d) fixture-ripple: single `rule_counters` PERCPU_ARRAY
# pin RETIRED; replaced by `rule_counters_<a|b>` inners under
# `rule_counters_outer` ARRAY_OF_MAPS. Reads must follow active_idx.
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
    local active; active=$(read_active_idx)
    case "${active}" in
        0) echo "${PIN_DIR}/rule_counters_a" ;;
        1) echo "${PIN_DIR}/rule_counters_b" ;;
        *) echo "${PIN_DIR}/rule_counters_a" ;;
    esac
}
read_rc_slot() {
    # §5.61 (B30): rule_counters is slot-keyed; remap operator id -> slot
    # via slot_rule_id (D-mvp-4.21-RAWMAP-REMAP). Assertion values unchanged.
    read_rule_counter_by_id "${IFACE_A}" "$(rule_counters_active_pin)" "$1"
}

# MAC → JSON octet array (for inner-allowlist queries).
mac_to_oct_json() {
    local mac="$1" oct_arr="[" first=1 hex
    local IFS=':'
    for hex in ${mac}; do
        if [[ ${first} -eq 1 ]]; then first=0; else oct_arr+=","; fi
        oct_arr+=$(printf '%d' "0x${hex}")
    done
    oct_arr+="]"
    printf '%s' "${oct_arr}"
}
mac_in_inner_pin() {
    local pin="$1" mac="$2" oct_arr
    oct_arr=$(mac_to_oct_json "${mac}")
    sudo -n bpftool map dump pinned "${pin}" 2>/dev/null \
        | jq -e --argjson tgt "${oct_arr}" '
            [.[] | (.key.octets // .formatted.key.octets // null)]
            | map(select(. != null))
            | any(. == $tgt)
        ' >/dev/null 2>&1
}

# rules_<active>[key].action_id reader (parallel-outer post-§5.34).
_jq_decode_key='
  (.formatted.key //
    (if (.key | type) == "array"
       then ((.key[0] // 0) | if type == "string" then sub("^0x";"") | tonumber else . end)
     elif (.key | type) == "number" then .key
     else null end))
'
rule_present_at() {
    # §5.61 (B30): rules_inner is slot-keyed; remap operator id -> slot.
    local pin="$1" id="$2" k half
    half=$(half_of_pin "${pin}") || half=$(active_idx_of "${IFACE_A}")
    k=$(id_to_slot "${IFACE_A}" "${id}" "${half}")
    [[ -z "${k}" ]] && { echo 0; return; }   # id not loaded in this half → absent
    sudo -n bpftool map dump pinned "${pin}" --json 2>/dev/null \
        | jq -r --argjson k "${k}" "
            .[]
            | select(${_jq_decode_key} == \$k)
            | (.formatted.value.present //
               ((.value[0] // 0) | if type == \"string\" then sub(\"^0x\";\"\") | tonumber else . end))
        " 2>/dev/null | head -n1
}
rule_action_id_at() {
    # §5.61 (B30): rules_inner is slot-keyed; remap operator id -> slot.
    local pin="$1" id="$2" k half
    half=$(half_of_pin "${pin}") || half=$(active_idx_of "${IFACE_A}")
    k=$(id_to_slot "${IFACE_A}" "${id}" "${half}")
    [[ -z "${k}" ]] && { echo 0; return; }
    sudo -n bpftool map dump pinned "${pin}" --json 2>/dev/null \
        | jq -r --argjson k "${k}" "
            .[]
            | select(${_jq_decode_key} == \$k)
            | (.formatted.value.action_id //
               ((.value[1] // 0) | if type == \"string\" then sub(\"^0x\";\"\") | tonumber else . end))
        " 2>/dev/null | head -n1
}

read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}

setup_veth

# ── (a) apply ────────────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
cat "${stderr_file}" >&2 || true

fail=0
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[a]: apply exit ${rc} (expected 0)" >&2
    fail=1
fi
if ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[a.pin]: rule_counters_a pin missing — cannot proceed" >&2
    exit 1
fi

# Determine active inner slot + active rules slot.
active=$(read_active_idx)
echo "active_idx='${active}'"
case "${active}" in
    0) inner_pin="${PIN_DIR}/allowlist_a"; rules_pin="${PIN_DIR}/rules_a" ;;
    1) inner_pin="${PIN_DIR}/allowlist_b"; rules_pin="${PIN_DIR}/rules_b" ;;
    *)
        echo "FAIL[a.idx]: cannot determine active inner slot (active_idx='${active}')" >&2
        exit 1
        ;;
esac

# ── (b/c) inject 5 drop-MAC frames → STAT_DROP_DENY += 5; rc[17] += 5 ──
echo "=== step (b/c): inject 5 frames src=${SRC_IP_DROP} (rule_id=17 DROP via action_table)"
read -r p0 d0 m0 p0_c < <(read_stats_with_cidr)
rc17_0=$(read_rc_slot 17)
echo "baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} rc[17]=${rc17_0}"

for i in 1 2 3 4 5; do
    ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "${SRC_IP_DROP}"
done
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + p0_c + 5 )) || true

read -r p1 d1 m1 p1_c < <(read_stats_with_cidr)
rc17_1=$(read_rc_slot 17)
echo "after drop-MAC: PASS=${p1} DROP_DENY=${d1} rc[17]=${rc17_1}"
echo "  delta PASS=$((p1-p0)) DROP_DENY=$((d1-d0)) rc[17]=$((rc17_1-rc17_0))"

# (b) STAT_DROP_DENY delta == 5 — same value pre/post §5.34, different
#     mechanism (was defaults-fallthrough; now action_table dispatch).
if (( d1 - d0 != 5 )); then
    echo "FAIL[b]: STAT_DROP_DENY delta=$((d1-d0)) (expected 5)" >&2
    fail=1
fi
if (( p1 - p0 != 0 )); then
    echo "FAIL[b.p]: STAT_PASS moved on drop-MAC frames (delta=$((p1-p0)))" >&2
    fail=1
fi

# (c) rule_counters[17] delta == 5 — INVERTED from pre-§5.34 (was STAY-0).
#     The drop-rule's MAC IS in inner-allowlist (HG-3.4b-c2-2); each
#     match invokes bump_rule(17) (HG-3.4b-c2-5) regardless of verdict.
if (( rc17_1 - rc17_0 != 5 )); then
    echo "FAIL[c]: rule_counters[17] delta=$((rc17_1-rc17_0)) (expected 5 — HG-3.4b-c2-5 contract)" >&2
    echo "         per-rule counter must bump on match regardless of verdict;" >&2
    echo "         drop-rule MAC must be in inner-allowlist per HG-3.4b-c2-2" >&2
    fail=1
fi

# ── (d) rules_<active>[17] has action_id=1 (DROP) — PI-29-3.4b-c2 ──────
p17=$(rule_present_at   "${rules_pin}" 17)
a17=$(rule_action_id_at "${rules_pin}" 17)
echo "rules_<active>[17] present='${p17}' action_id='${a17}' (expected 1, 1=DROP)"
if [[ "${p17}" != "1" ]]; then
    echo "FAIL[d.p]: rules_<active>[17].present='${p17}' (expected 1)" >&2
    fail=1
fi
if [[ "${a17}" != "1" ]]; then
    echo "FAIL[d.a]: rules_<active>[17].action_id='${a17}' (expected 1=DROP)" >&2
    fail=1
fi

# ── (e) Sidecar shows rule_id=17 with action="drop" ────────────────────
if ! sudo -n test -e "${SIDECAR_PATH}"; then
    echo "FAIL[e.pin]: sidecar ${SIDECAR_PATH} missing" >&2
    fail=1
else
    sc_action_17=$(sudo -n jq -r '.rules[] | select(.rule_id == 17) | .action' \
                   "${SIDECAR_PATH}" 2>/dev/null | head -n1)
    echo "sidecar rule_id=17 action='${sc_action_17}' (expected 'drop')"
    if [[ "${sc_action_17}" != "drop" ]]; then
        echo "FAIL[e]: sidecar rule_id=17 action='${sc_action_17}' (expected 'drop')" >&2
        fail=1
    fi
fi

# ── (f) drop-rule's prefix IS in the active CIDR inner (§5.43 bit-vector) ─
# Under the OR→AND pivot a DROP rule is a constrained src_cidr entry in the
# cidr_allowlist bitmask (its action comes from action_table). So the active
# cidr inner must hold all 4 rules' prefixes (drop rule id17 included).
if [[ "${active}" == "0" ]]; then cidr_inner_pin="${PIN_DIR}/cidr_allowlist_a"; else cidr_inner_pin="${PIN_DIR}/cidr_allowlist_b"; fi
if ! sudo -n test -e "${cidr_inner_pin}"; then
    echo "FAIL[f.pin]: active CIDR inner pin ${cidr_inner_pin} missing" >&2
    fail=1
else
    n_cidr=$(sudo -n bpftool map dump pinned "${cidr_inner_pin}" --json 2>/dev/null | jq 'length' 2>/dev/null || echo 0)
    if [[ -n "${n_cidr}" && "${n_cidr}" -ge 4 ]]; then
        echo "active CIDR inner ${cidr_inner_pin} has ${n_cidr} prefixes (drop rule id17 included) OK"
    else
        echo "FAIL[f]: active CIDR inner ${cidr_inner_pin} has ${n_cidr} prefixes (expected ≥4; drop rule must populate)" >&2
        sudo -n bpftool map dump pinned "${cidr_inner_pin}" >&2 || true
        fail=1
    fi
fi

# ── (g) NEGATION CONTROL: PASS rule bumps rc[5]; drop rc[17] stays at 5 ─
echo
echo "=== step (g): NEGATION — inject 2 frames src=${SRC_IP_PASS} (rule_id=5 PASS)"
read -r p2 d2 m2 p2_c < <(read_stats_with_cidr)
rc5_0=$(read_rc_slot 5)
for i in 1 2; do
    ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "${SRC_IP_PASS}"
done
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + p2_c + 2 )) || true

read -r p3 d3 m3 p3_c < <(read_stats_with_cidr)
c5=$(read_rc_slot 5)
c17_final=$(read_rc_slot 17)
echo "after pass-MAC: PASS_delta=$((p3-p2)) DROP_delta=$((d3-d2))  rc[5]=${c5} (delta $((c5-rc5_0)))  rc[17]=${c17_final}"

# (g.PASS) STAT_PASS delta == 2.
if (( p3_c - p2_c != 2 )); then
    echo "FAIL[g.pass]: STAT_PASS_CIDR delta=$((p3_c-p2_c)) (expected 2)" >&2
    fail=1
fi
# (g.rc5) rule_counters[5] delta == 2.
if (( c5 - rc5_0 != 2 )); then
    echo "FAIL[g.5]: rule_counters[5] delta=$((c5-rc5_0)) (expected 2)" >&2
    fail=1
fi
# (g.rc17-no-cross) rc[17] did NOT bump on pass-MAC frames.
if (( c17_final != rc17_1 )); then
    echo "FAIL[g.17]: rule_counters[17]='${c17_final}' moved on pass-MAC frames (was ${rc17_1})" >&2
    echo "           cross-bump leak — rule_id isolation broken" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_DROP_RULE_BUMPS_COUNTER"
exit "${fail}"
