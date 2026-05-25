#!/bin/bash
# T_DROP_RULE_BUMPS_COUNTER — design §6.52 (MVP-3.4b cycle 1 / §5.31).
#
# Operational signature of PI-29-3.4b carve-out + the §5.26/§5.29
# "drop rules don't populate inner-allowlist" contract.
#
# Per §5.26 schema cycle 2: drop rules are POPULATED into the `rules`
# map (with action_id=1=DROP) but their MAC is NOT added to the inner
# allowlist. Frames from drop-rule MAC therefore MISS the inner-HASH
# lookup → fall through to defaults[active]=drop → STAT_DROP_DENY bumps,
# but rule_counters[drop_rule_id] STAYS 0 (bump_rule is only called on
# MATCH per Q1 B3 — and the drop-rule MAC produces no match).
#
# This is the operationally-observable signature that PI-29-3.4b's
# carve-out is intact: action dispatch via existing PASS-branch
# (defaults[active]=drop fallthrough), NOT via rules+action_table lookup.
#
# Fixture has rule_id=17 as `action: drop` with MAC "02:00:00:00:00:11".
#
# Trigger:
#   1. setup_veth + apply config_per_rule_counters.yaml.
#   2. Inject 5 frames from the drop-rule's MAC (rule_id=17).
#   3. Verify STAT_DROP_DENY advances by 5 AND rule_counters[17] STAYS 0.
#   4. Verify `rules` map IS populated for id=17 with action_id=1=DROP
#      (proves PI-29-3.4b: `rules` map populated NOT consulted).
#   5. Verify sidecar rule_index.json shows action="drop" for rule_id=17.
#   6. Negation: inject 2 frames from rule_id=5 MAC (PASS); confirm
#      rule_counters[5] advances; rule_counters[17] STILL 0.
#
# Observable outcome (ALL must hold):
#   (a) apply exit 0.
#   (b) STAT_DROP_DENY delta == 5 (the drop-MAC frames).
#   (c) rule_counters[17] == 0 (the drop-rule's per-rule counter STAYS).
#   (d) `rules` map at key=17 has action_id=1 (DROP).
#   (e) Sidecar rule_index.json at /run/xdpmacfilter/<iface>/ shows
#       rule_id=17 with action="drop" (path per §5.31 EDIT-1 D-3.4b-21).
#   (f) Drop-rule MAC is ABSENT from the active inner allowlist (
#       §5.26 schema cycle 2 contract — preserved across §5.31).
#   (g) After step 6: rule_counters[5] == 2; rule_counters[17] STILL == 0.
#
# Sanity-floor smoke: step (a) — apply succeeds.
# Negation control: step (g) — PASS rule bumps counter; DROP rule does
# NOT. This is the differential proving "bump_rule only fires on MATCH"
# rather than "bump_rule fires on every traffic frame".
#
# Maps to: PI-29-3.4b (carve-out: rules map populated NOT consulted;
# inner-VALUE's rule_id IS read on MATCH only), HG-3.4b-4, Q5 R1.
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

MAC_DROP="02:00:00:00:00:11"   # rule_id=17 DROP
MAC_ID5="02:00:00:00:00:05"    # rule_id=5 PASS (negation control)

# §5.31 EDIT-1: sidecar path = /run/xdpmacfilter/<iface>/rule_index.json
SIDECAR_ROOT="/run/xdpmacfilter"
SIDECAR_DIR="${SIDECAR_ROOT}/${IFACE_A}"
SIDECAR_PATH="${SIDECAR_DIR}/rule_index.json"

stderr_file=$(mktemp /tmp/xdpmf-droprule-stderr.XXXXXX)
trap 'cleanup_veth; sudo -n rm -rf "${SIDECAR_DIR}" 2>/dev/null; rm -f "${stderr_file}"' EXIT

read_rc_slot() {
    local id="$1"
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" \
        "${PIN_DIR}/rule_counters" "${id}"
}

# Helper: MAC → JSON octet array (for inner-allowlist queries).
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

# Helper: read rules[key].action_id (BTF-formatted shape from T_RULES_SKELETON_NOT_WIRED).
_jq_decode_key='
  (.formatted.key //
    (if (.key | type) == "array"
       then ((.key[0] // 0) | if type == "string" then sub("^0x";"") | tonumber else . end)
     elif (.key | type) == "number" then .key
     else null end))
'
rule_action_id_at() {
    local pin="$1" key="$2"
    sudo -n bpftool map dump pinned "${pin}" --json 2>/dev/null \
        | jq -r --argjson k "${key}" "
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
if ! sudo -n test -e "${PIN_DIR}/rule_counters"; then
    echo "FAIL[a.pin]: rule_counters pin missing — cannot proceed" >&2
    exit 1
fi

# ── (b/c) inject 5 drop-MAC frames → STAT_DROP_DENY += 5; rc[17] stays 0 ─
echo "=== step (b/c): inject 5 frames src=${MAC_DROP} (rule_id=17 DROP)"
read -r p0 d0 m0 < <(read_stats)
echo "stats baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0}"

for i in 1 2 3 4 5; do
    inject_eth "${IFACE_B}" "${MAC_DROP}" "${MAC_DST}"
done
wait_for_stats_sum "${IFACE_A}" $(( p0 + d0 + m0 + 5 )) || true

read -r p1 d1 m1 < <(read_stats)
echo "stats after drop-MAC: PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1}"
echo "  delta PASS=$((p1-p0)) DROP_DENY=$((d1-d0)) DROP_MALFORMED=$((m1-m0))"

# (b) STAT_DROP_DENY delta == 5
if (( d1 - d0 != 5 )); then
    echo "FAIL[b]: STAT_DROP_DENY delta=$((d1-d0)) (expected 5)" >&2
    fail=1
fi
if (( p1 - p0 != 0 )); then
    echo "FAIL[b.p]: STAT_PASS moved on drop-MAC frames (delta=$((p1-p0)))" >&2
    fail=1
fi

# (c) rule_counters[17] STAYS 0 — the drop-rule did NOT match (MAC absent
#     from inner-allowlist; no bump_rule invocation per PI-29-3.4b).
c17=$(read_rc_slot 17)
echo "rule_counters[17]=${c17} (expected 0 — drop-rule MAC absent from inner; bump_rule never fires)"
if [[ "${c17}" != "0" ]]; then
    echo "FAIL[c]: rule_counters[17]='${c17}' (expected 0)" >&2
    echo "         PI-29-3.4b VIOLATED: bump_rule fired despite no inner-allowlist match" >&2
    echo "         OR: drop-rule MAC was incorrectly added to inner allowlist" >&2
    fail=1
fi

# ── (d) `rules` map at key=17 has action_id=1 (DROP) — PI-29-3.4b populate ─
if ! sudo -n test -e "${PIN_DIR}/rules"; then
    echo "FAIL[d.pin]: ${PIN_DIR}/rules pin missing" >&2
    fail=1
else
    action_17=$(rule_action_id_at "${PIN_DIR}/rules" 17)
    echo "rules[17].action_id='${action_17}' (expected 1 = DROP)"
    if [[ "${action_17}" != "1" ]]; then
        echo "FAIL[d]: rules[17].action_id='${action_17}' (expected 1 = DROP)" >&2
        echo "         drop-rule must be POPULATED into the rules map per HG-3.4b-4 / D-3.4b-18" >&2
        fail=1
    fi
fi

# ── (e) Sidecar shows rule_id=17 with action="drop" (path per §5.31 EDIT-1) ─
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

# ── (f) drop-rule MAC ABSENT from active inner allowlist (§5.26 contract) ─
active=$(read_active_idx)
echo "active_idx='${active}'"
inner_pin=""
case "${active}" in
    0) inner_pin="${PIN_DIR}/allowlist_a" ;;
    1) inner_pin="${PIN_DIR}/allowlist_b" ;;
esac

if [[ -z "${inner_pin}" ]]; then
    echo "FAIL[f.idx]: could not determine active inner pin (active_idx='${active}')" >&2
    fail=1
elif ! sudo -n test -e "${inner_pin}"; then
    echo "FAIL[f.pin]: active inner pin ${inner_pin} missing" >&2
    fail=1
else
    if mac_in_inner_pin "${inner_pin}" "${MAC_DROP}"; then
        echo "FAIL[f]: drop-rule MAC ${MAC_DROP} (id=17) found in active inner allowlist" >&2
        echo "         §5.26 schema cycle 2 contract VIOLATED: drop rules must NOT populate inner" >&2
        fail=1
    fi
fi

# ── (g) NEGATION CONTROL: PASS rule bumps; DROP rule still 0 ──────────────
echo
echo "=== step (g): NEGATION — inject 2 frames src=${MAC_ID5} (rule_id=5 PASS)"
read -r p2 d2 m2 < <(read_stats)
for i in 1 2; do
    inject_eth "${IFACE_B}" "${MAC_ID5}" "${MAC_DST}"
done
wait_for_stats_sum "${IFACE_A}" $(( p2 + d2 + m2 + 2 )) || true

c5=$(read_rc_slot 5)
c17_final=$(read_rc_slot 17)
echo "rule_counters[5]=${c5} (expected 2); rule_counters[17]=${c17_final} (expected STILL 0)"

if [[ "${c5}" != "2" ]]; then
    echo "FAIL[g.5]: rule_counters[5]='${c5}' (expected 2)" >&2
    fail=1
fi
if [[ "${c17_final}" != "0" ]]; then
    echo "FAIL[g.17]: rule_counters[17]='${c17_final}' (expected STILL 0)" >&2
    echo "           drop-rule counter must NOT bump even with subsequent PASS traffic" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_DROP_RULE_BUMPS_COUNTER"
exit "${fail}"
