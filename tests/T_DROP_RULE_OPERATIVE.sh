#!/bin/bash
# T_DROP_RULE_OPERATIVE — design §6.NN (MVP-3.4b cycle 2 / §5.34).
#
# LOAD-BEARING canary for the rules→action_table dispatch chain
# (PI-29-3.4b-c2) AND for the schema cycle 3 semantic shift
# (PI-30-3.4b-c2-schema): explicit `action: drop` rules now populate the
# inner-allowlist with their `rule_id` and the datapath dispatches
# XDP_DROP via `rules_outer[active] → rules_inner[rule_id] →
# action_table[action_id].action_type == DROP`.
#
# Fixture: tests/fixtures/config_per_rule_counters.yaml — has
# id=17 action=drop MAC 02:00:00:00:00:11 (the load-bearing drop rule)
# AND id=5 action=pass MAC 02:00:00:00:00:05 (the negation control —
# different rule, different action, same machinery).
#
# Trigger (per §6.NN):
#   1. setup_veth + apply config_per_rule_counters.yaml.
#   2. (smoke) verify pin existence: rules_outer + rules_a + rules_b +
#      action_table + allowlist_a/b + active_idx.
#   3. Read active_idx → pick rules_<active> + allowlist_<active>.
#   4. Verify rules_<active>[17].present==1, action_id==1 (DROP).
#      Verify rules_<active>[5].present==1, action_id==0 (PASS).
#   5. Verify drop-rule MAC 02:00:00:00:00:11 IS present in
#      allowlist_<active>  (schema cycle 3 shift per HG-3.4b-c2-2; was
#      ABSENT pre-§5.34 — the cycle-2 contract).
#   6. Verify action_table[0].action_type==0 (PASS) + [1].action_type==1
#      (DROP) — proves dispatch source is the static action_table.
#   7. Inject 5 frames with src MAC 02:00:00:00:00:11 → STAT_DROP_DENY
#      delta == 5 (explicit dispatch, NOT default-fallthrough);
#      STAT_PASS delta == 0; rule_counters[17] delta == 5 (per
#      HG-3.4b-c2-5 — bumps on match regardless of verdict).
#   8. Inject 5 frames with src MAC 02:00:00:00:00:05 (NEGATION
#      CONTROL — different rule, action=PASS, same machinery) →
#      STAT_PASS delta == 5; STAT_DROP_DENY delta == 0 from this batch;
#      rule_counters[5] delta == 5; rule_counters[17] unchanged.
#
# Observable outcome (ALL must hold):
#   (a) apply exit 0.
#   (b) rules_outer / rules_a / rules_b pins all exist (per §5.34 D-1).
#   (c) rules_<active>[17] has present=1, action_id=1 (DROP).
#   (d) rules_<active>[5]  has present=1, action_id=0 (PASS).
#   (e) drop-rule MAC IS in allowlist_<active> (PI-30-3.4b-c2-schema).
#   (f) action_table[0]=PASS + action_table[1]=DROP (HG-3.4b-c2-3 SHARED).
#   (g) 5 drop-MAC frames: STAT_DROP_DENY += 5, STAT_PASS += 0,
#       rule_counters[17] += 5.
#   (h) 5 pass-MAC frames: STAT_PASS += 5, STAT_DROP_DENY += 0,
#       rule_counters[5] += 5, rule_counters[17] unchanged.
#
# Sanity-floor smoke: step (a)+(b) — apply succeeds AND new pins
# materialize. Without these the test cannot proceed.
# Negation control: step (h) — pass-rule MAC produces STAT_PASS bump
# while drop-rule MAC produced STAT_DROP_DENY (g). If the action_table
# dispatch were always-PASS or always-DROP, this differential breaks.
# AND: step (h)'s rule_counters[17] non-bump on pass-MAC frames proves
# the per-rule counter actually keys on rule_id, not on traffic volume.
#
# Maps to: PI-29-3.4b-c2 (datapath consults rules+action_table),
# PI-30-3.4b-c2-schema (drop rules in inner-allowlist),
# HG-3.4b-c2-2 (schema shift), HG-3.4b-c2-4 (dispatch order),
# HG-3.4b-c2-5 (counter bumps regardless of verdict), Q1.B (STAT bucket).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for bpftool --json + map content parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_per_rule_counters.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

# MACs per fixture (config_per_rule_counters.yaml).
MAC_DROP="02:00:00:00:00:11"   # rule_id=17 action=drop  (load-bearing)
MAC_PASS="02:00:00:00:00:05"   # rule_id=5  action=pass  (negation control)

stderr_file=$(mktemp /tmp/xdpmf-droprule-op-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT

# ── bpftool jq decoders (per existing convention) ─────────────────────────
_jq_decode_key='
  (.formatted.key //
    (if (.key | type) == "array"
       then ((.key[0] // 0) | if type == "string" then sub("^0x";"") | tonumber else . end)
     elif (.key | type) == "number" then .key
     else null end))
'
rule_present_at() {
    local pin="$1" key="$2"
    sudo -n bpftool map dump pinned "${pin}" --json 2>/dev/null \
        | jq -r --argjson k "${key}" "
            .[]
            | select(${_jq_decode_key} == \$k)
            | (.formatted.value.present //
               ((.value[0] // 0) | if type == \"string\" then sub(\"^0x\";\"\") | tonumber else . end))
        " 2>/dev/null | head -n1
}
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
action_type_at() {
    local pin="$1" key="$2"
    sudo -n bpftool map dump pinned "${pin}" --json 2>/dev/null \
        | jq -r --argjson k "${key}" "
            .[]
            | select(${_jq_decode_key} == \$k)
            | (.formatted.value.action_type //
               ((.value[0] // 0) | if type == \"string\" then sub(\"^0x\";\"\") | tonumber else . end))
        " 2>/dev/null | head -n1
}

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

read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}

# §5.35 (MVP-3.4d) fixture-ripple: single `rule_counters` PERCPU_ARRAY
# pin RETIRED; replaced by `rule_counters_<a|b>` inners under
# `rule_counters_outer` ARRAY_OF_MAPS. Reads must follow active_idx.
rule_counters_active_pin() {
    local active; active=$(read_active_idx)
    case "${active}" in
        0) echo "${PIN_DIR}/rule_counters_a" ;;
        1) echo "${PIN_DIR}/rule_counters_b" ;;
        *) echo "${PIN_DIR}/rule_counters_a" ;;
    esac
}
read_rc_slot() {
    local id="$1" pin
    pin=$(rule_counters_active_pin)
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" "${pin}" "${id}"
}

setup_veth

# ── (a) apply ────────────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
echo "--- stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

fail=0
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[a]: apply exit ${rc} (expected 0)" >&2
    fail=1
fi

# ── (b) sanity-floor smoke: new pins exist ───────────────────────────────
for pin in rules_outer rules_a rules_b action_table allowlist_a allowlist_b \
           active_idx rule_counters_outer rule_counters_a rule_counters_b stats; do
    if ! sudo -n test -e "${PIN_DIR}/${pin}"; then
        echo "FAIL[b.${pin}]: ${PIN_DIR}/${pin} pin missing — §5.34 D-1 violated" >&2
        fail=1
    fi
done
# If smoke fails, no point continuing — assertions below all assume pins.
if (( fail != 0 )); then
    echo "FAIL: smoke floor failed; aborting before content assertions" >&2
    exit 1
fi

# ── pick rules_<active> + allowlist_<active> ─────────────────────────────
active=$(read_active_idx)
echo "active_idx='${active}'"
case "${active}" in
    0) rules_pin="${PIN_DIR}/rules_a"; inner_pin="${PIN_DIR}/allowlist_a" ;;
    1) rules_pin="${PIN_DIR}/rules_b"; inner_pin="${PIN_DIR}/allowlist_b" ;;
    *)
        echo "FAIL[active-idx]: cannot determine active inner slot (active_idx='${active}')" >&2
        exit 1
        ;;
esac
echo "rules_<active>=${rules_pin}  allowlist_<active>=${inner_pin}"

# Dump for diagnostic.
echo "=== rules_<active> dump"
sudo -n bpftool map dump pinned "${rules_pin}" 2>/dev/null | head -40 || true
echo "=== action_table dump"
sudo -n bpftool map dump pinned "${PIN_DIR}/action_table" 2>/dev/null || true

# ── (c) rules_<active>[17].present=1, action_id=1 (DROP) ─────────────────
p17=$(rule_present_at   "${rules_pin}" 17)
a17=$(rule_action_id_at "${rules_pin}" 17)
echo "rules[17] present='${p17}' action_id='${a17}' (expected 1, 1=DROP)"
if [[ "${p17}" != "1" ]]; then
    echo "FAIL[c.p17]: rules[17].present='${p17}' (expected 1)" >&2
    fail=1
fi
if [[ "${a17}" != "1" ]]; then
    echo "FAIL[c.a17]: rules[17].action_id='${a17}' (expected 1=DROP)" >&2
    fail=1
fi

# ── (d) rules_<active>[5].present=1, action_id=0 (PASS) ──────────────────
p5=$(rule_present_at   "${rules_pin}" 5)
a5=$(rule_action_id_at "${rules_pin}" 5)
echo "rules[5]  present='${p5}'  action_id='${a5}'  (expected 1, 0=PASS)"
if [[ "${p5}" != "1" ]]; then
    echo "FAIL[d.p5]: rules[5].present='${p5}' (expected 1)" >&2
    fail=1
fi
if [[ "${a5}" != "0" ]]; then
    echo "FAIL[d.a5]: rules[5].action_id='${a5}' (expected 0=PASS)" >&2
    fail=1
fi

# ── (e) drop-rule MAC IS in allowlist_<active> (schema cycle 3 shift) ────
if mac_in_inner_pin "${inner_pin}" "${MAC_DROP}"; then
    echo "drop-MAC ${MAC_DROP} present in ${inner_pin} (PI-30-3.4b-c2-schema OK)"
else
    echo "FAIL[e]: drop-rule MAC ${MAC_DROP} NOT in ${inner_pin}" >&2
    echo "         PI-30-3.4b-c2-schema VIOLATED: drop rules must populate inner-allowlist" >&2
    echo "         per HG-3.4b-c2-2 schema cycle 3 contract" >&2
    fail=1
fi

# ── (f) action_table is the static dispatch source ───────────────────────
at0=$(action_type_at "${PIN_DIR}/action_table" 0)
at1=$(action_type_at "${PIN_DIR}/action_table" 1)
echo "action_table[0].action_type='${at0}' (expected 0=PASS); [1]='${at1}' (expected 1=DROP)"
if [[ "${at0}" != "0" ]]; then
    echo "FAIL[f.0]: action_table[0].action_type='${at0}' (expected 0=PASS)" >&2
    fail=1
fi
if [[ "${at1}" != "1" ]]; then
    echo "FAIL[f.1]: action_table[1].action_type='${at1}' (expected 1=DROP)" >&2
    fail=1
fi

# ── (g) 5 drop-MAC frames → STAT_DROP_DENY+=5; rule_counters[17]+=5 ──────
echo
echo "=== step (g): inject 5 frames src=${MAC_DROP} (rule_id=17 DROP via action_table)"
read -r p0 d0 m0 < <(read_stats)
rc17_0=$(read_rc_slot 17)
rc5_0=$(read_rc_slot 5)
echo "baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} rc[17]=${rc17_0} rc[5]=${rc5_0}"

for i in 1 2 3 4 5; do
    inject_eth "${IFACE_B}" "${MAC_DROP}" "${MAC_DST}"
done
wait_for_stats_sum "${IFACE_A}" $(( p0 + d0 + m0 + 5 )) || true

read -r p1 d1 m1 < <(read_stats)
rc17_1=$(read_rc_slot 17)
rc5_1=$(read_rc_slot 5)
echo "after drop-MAC: PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1}"
echo "  delta PASS=$((p1-p0)) DROP_DENY=$((d1-d0)) DROP_MALFORMED=$((m1-m0))"
echo "  rc[17]=${rc17_1} (delta $((rc17_1-rc17_0)))  rc[5]=${rc5_1} (delta $((rc5_1-rc5_0)))"

if (( d1 - d0 != 5 )); then
    echo "FAIL[g.drop]: STAT_DROP_DENY delta=$((d1-d0)) (expected 5)" >&2
    echo "             explicit drop-rule did NOT dispatch via action_table" >&2
    fail=1
fi
if (( p1 - p0 != 0 )); then
    echo "FAIL[g.pass]: STAT_PASS moved on drop-MAC frames (delta=$((p1-p0)))" >&2
    fail=1
fi
if (( rc17_1 - rc17_0 != 5 )); then
    echo "FAIL[g.rc17]: rule_counters[17] delta=$((rc17_1-rc17_0)) (expected 5 per HG-3.4b-c2-5)" >&2
    echo "             per-rule counter must bump on match regardless of verdict" >&2
    fail=1
fi
if (( rc5_1 - rc5_0 != 0 )); then
    echo "FAIL[g.rc5]: rule_counters[5] moved on drop-MAC frames (delta=$((rc5_1-rc5_0)))" >&2
    fail=1
fi

# ── (h) NEGATION CONTROL: 5 pass-MAC frames → STAT_PASS+=5 ───────────────
echo
echo "=== step (h): NEGATION — inject 5 frames src=${MAC_PASS} (rule_id=5 PASS)"
read -r p2 d2 m2 < <(read_stats)
rc17_2=$(read_rc_slot 17)
rc5_2=$(read_rc_slot 5)
echo "baseline-h: PASS=${p2} DROP_DENY=${d2} rc[17]=${rc17_2} rc[5]=${rc5_2}"

for i in 1 2 3 4 5; do
    inject_eth "${IFACE_B}" "${MAC_PASS}" "${MAC_DST}"
done
wait_for_stats_sum "${IFACE_A}" $(( p2 + d2 + m2 + 5 )) || true

read -r p3 d3 m3 < <(read_stats)
rc17_3=$(read_rc_slot 17)
rc5_3=$(read_rc_slot 5)
echo "after pass-MAC: PASS=${p3} DROP_DENY=${d3} DROP_MALFORMED=${m3}"
echo "  delta PASS=$((p3-p2)) DROP_DENY=$((d3-d2)) DROP_MALFORMED=$((m3-m2))"
echo "  rc[17]=${rc17_3} (delta $((rc17_3-rc17_2)))  rc[5]=${rc5_3} (delta $((rc5_3-rc5_2)))"

if (( p3 - p2 != 5 )); then
    echo "FAIL[h.pass]: STAT_PASS delta=$((p3-p2)) (expected 5)" >&2
    echo "             pass-rule did not produce XDP_PASS via action_table" >&2
    fail=1
fi
if (( d3 - d2 != 0 )); then
    echo "FAIL[h.drop]: STAT_DROP_DENY moved on pass-MAC frames (delta=$((d3-d2)))" >&2
    echo "             pass-rule dispatched DROP — action_table machinery broken" >&2
    fail=1
fi
if (( rc5_3 - rc5_2 != 5 )); then
    echo "FAIL[h.rc5]: rule_counters[5] delta=$((rc5_3-rc5_2)) (expected 5)" >&2
    fail=1
fi
if (( rc17_3 - rc17_2 != 0 )); then
    echo "FAIL[h.rc17]: rule_counters[17] moved on pass-MAC frames (delta=$((rc17_3-rc17_2)))" >&2
    echo "             rule_id isolation broken — counters cross-bumping" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_DROP_RULE_OPERATIVE"
exit "${fail}"
