#!/bin/bash
# T_RULES_SKELETON_NOT_WIRED — design §6.42 (MVP-3.4 / §5.29).
#
# **The LOAD-BEARING defer-posture test.** Apply a config with mixed
# `pass`/`drop` rules; verify (i) schema accepted, (ii) WARN emitted with
# entry count, (iii) `rules` + `action_table` maps populated correctly,
# (iv) inner allowlist contains ONLY pass-rule MACs (drop-rule MAC ABSENT).
#
# The architect-preferred direct-map-dump approach (§6.42 tester note):
# observe map contents directly via bpftool — robust, no traffic-flake risk.
#
# PI bindings:
#   - PI-27 / PI-13-3.4: inner-allowlist-value byte-equivalent to MVP-3.2
#     (the bpftool dump of the active allowlist returns 1-byte values).
#   - PI-28: mac_filter_prog body byte-equivalent (indirect — datapath
#     does NOT consult `rules` map, verified by drop-MAC ABSENCE from inner).
#   - PI-29: rules+action_table populated but NOT consulted; WARN emitted.
#   - HG-3.4-1 + D-3.4-4 + D-3.4-8.
#
# Trigger:
#   1. setup_veth.
#   2. apply tests/fixtures/config_rules_skeleton.yaml (3 rules: ids 0+1
#      pass MAC_A/MAC_B; id 2 drop MAC_C).
#   3. Capture stderr.
#
# Observable outcome (ALL must hold):
#   (a) apply exit 0.
#   (b) stderr contains WARN line matching ERE
#       '^xdpmacfilter: rules: section parsed \([0-9]+ entries\) but per-rule action dispatch deferred to MVP-3.4b — datapath uses MAC/CIDR-only matching this cycle$'
#       AND the <N> in the line equals 3.
#   (c) `${PIN_DIR}/rules` pinned + `${PIN_DIR}/action_table` pinned.
#   (d) `bpftool map dump pinned ${PIN_DIR}/action_table` reports two
#       entries with value byte[0] = 0 (ACTION_PASS) for index 0 and
#       value byte[0] = 1 (ACTION_DROP) for index 1.
#   (e) `bpftool map dump pinned ${PIN_DIR}/rules` at key=0 has byte[0]=1
#       (present) byte[1]=0 (action_id=PASS); at key=1 has [1,0]; at key=2
#       has [1,1] (drop-rule); at all other keys byte[0]=0 (empty).
#   (f) Active inner allowlist (allowlist_a OR allowlist_b) contains the
#       pass-rule MACs (id=0 MAC_A and id=1 MAC_B) but DOES NOT contain
#       the drop-rule MAC (id=2 MAC_C). This is the OBSERVABLE
#       SKELETON-NOT-WIRED SIGNATURE.
#
# Sanity-floor smoke: step (a)+(c) — apply succeeds AND both new pins
# materialize.
# **Negation control**: step (f) IS the failure-path probe — if the impl
# accidentally populated MAC_C into the inner allowlist (or, equivalently,
# extended the inner-value shape to embed rule_id), this test catches
# the regression. The WARN regex (b) is the secondary failure-path probe.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required by §6.42 direct-map-dump approach)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_rules_skeleton.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

# MACs declared in the fixture.
MAC_A="02:00:00:00:00:01"   # id=0 pass
MAC_B="02:00:00:00:00:02"   # id=1 pass
MAC_C="02:00:00:00:00:03"   # id=2 drop  ← MUST NOT appear in inner

stderr_file=$(mktemp /tmp/xdpmf-rules-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT

setup_veth

# ── (a) apply the rules-skeleton fixture ────────────────────────────────
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
    echo "FAIL[a]: apply exit ${rc} (expected 0 — schema must accept rules+action)" >&2
    fail=1
fi

# ── (b) WARN line with the correct entry count ──────────────────────────
warn_ere='^xdpmacfilter: rules: section parsed \(([0-9]+) entries\) but per-rule action dispatch deferred to MVP-3.4b — datapath uses MAC/CIDR-only matching this cycle$'
# `grep -c` always prints to stdout — use `|| true` to swallow rc=1
# without emitting a second "0" (would yield multi-line "0\n0").
warn_count=$(grep -cE -- "${warn_ere}" "${stderr_file}" 2>/dev/null || true)
warn_count=${warn_count:-0}
echo "WARN line count: ${warn_count}"
if [[ "${warn_count}" != "1" ]]; then
    echo "FAIL[b1]: expected exactly 1 WARN line matching:" >&2
    echo "         ${warn_ere}" >&2
    echo "         got: ${warn_count}" >&2
    fail=1
fi
# Extract the entries-count from the WARN line.
warn_n=$(grep -oE -- 'rules: section parsed \([0-9]+ entries\)' "${stderr_file}" \
         | grep -oE '[0-9]+' | head -n1)
echo "WARN reports N=${warn_n} entries (expected 3)"
if [[ "${warn_n}" != "3" ]]; then
    echo "FAIL[b2]: WARN N=${warn_n} != 3 (fixture has 3 rules)" >&2
    fail=1
fi

# ── (c) skeleton map pins exist ─────────────────────────────────────────
if ! sudo -n test -e "${PIN_DIR}/rules"; then
    echo "FAIL[c1]: ${PIN_DIR}/rules pin missing" >&2
    fail=1
fi
if ! sudo -n test -e "${PIN_DIR}/action_table"; then
    echo "FAIL[c2]: ${PIN_DIR}/action_table pin missing" >&2
    fail=1
fi

# Field-read helpers for the rules + action_table ARRAY maps.
#
# bpftool --json emits a DUAL shape for BTF-annotated maps:
#   {
#     "key":   ["0x00","0x00","0x00","0x00"],     ← raw LE bytes
#     "value": ["0x01","0x00","0x00","0x00"],     ← raw LE bytes
#     "formatted": {
#       "key":   0,                                ← BTF-decoded integer
#       "value": {"present": 1, "action_id": 0, "_pad": [0,0]}  ← BTF struct
#     }
#   }
# (Phase-B observation: bpftool 7.x always emits BOTH; the `.formatted`
# sub-object exists iff BTF is loaded for the map's value type. For our
# `rules` + `action_table` maps, BTF is always present because the skeleton
# is built with BTF metadata.)
#
# Helpers below QUERY `.formatted.value.<field>` FIRST (the named-field
# shape, robust regardless of byte ordering) AND FALL BACK to decoding
# raw LE byte at the expected struct offset if `.formatted` is missing
# (defensive — never observed in practice).
#
# Key match: try .formatted.key (BTF integer) first; fall back to decoding
# .key as a LE byte array (byte 0 is LSB; for keys 0..63 byte 0 carries
# the entire value).

# Decode the key of an entry to an integer, robustly handling both shapes.
_jq_decode_key='
  (.formatted.key //
    (if (.key | type) == "array"
       then ((.key[0] // 0) | if type == "string" then sub("^0x";"") | tonumber else . end)
     elif (.key | type) == "number" then .key
     else null end))
'

# rule_present_at <pin> <key> → integer 0/1; "" if entry absent.
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

# rule_action_id_at <pin> <key> → integer 0/1; "" if entry absent.
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

# action_type_at <pin> <key> → integer action_type; "" if entry absent.
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

# ── (d) action_table: index 0 → PASS=0, index 1 → DROP=1 ────────────────
if sudo -n test -e "${PIN_DIR}/action_table"; then
    echo "=== action_table dump"
    sudo -n bpftool map dump pinned "${PIN_DIR}/action_table" 2>/dev/null || true
    at0=$(action_type_at "${PIN_DIR}/action_table" 0)
    at1=$(action_type_at "${PIN_DIR}/action_table" 1)
    echo "action_table[0].action_type='${at0}'  action_table[1].action_type='${at1}'"
    if [[ "${at0}" != "0" ]]; then
        echo "FAIL[d1]: action_table[0].action_type='${at0}' (expected 0 = ACTION_PASS)" >&2
        fail=1
    fi
    if [[ "${at1}" != "1" ]]; then
        echo "FAIL[d2]: action_table[1].action_type='${at1}' (expected 1 = ACTION_DROP)" >&2
        fail=1
    fi
fi

# ── (e) rules map: ids 0,1 present action_id=0; id 2 present action_id=1; others empty ─
if sudo -n test -e "${PIN_DIR}/rules"; then
    echo "=== rules map dump"
    sudo -n bpftool map dump pinned "${PIN_DIR}/rules" 2>/dev/null || true

    r0_present=$(rule_present_at   "${PIN_DIR}/rules" 0)
    r0_action=$( rule_action_id_at "${PIN_DIR}/rules" 0)
    r1_present=$(rule_present_at   "${PIN_DIR}/rules" 1)
    r1_action=$( rule_action_id_at "${PIN_DIR}/rules" 1)
    r2_present=$(rule_present_at   "${PIN_DIR}/rules" 2)
    r2_action=$( rule_action_id_at "${PIN_DIR}/rules" 2)
    r3_present=$(rule_present_at   "${PIN_DIR}/rules" 3)
    echo "rules[0]={present=${r0_present},action_id=${r0_action}}  rules[1]={present=${r1_present},action_id=${r1_action}}  rules[2]={present=${r2_present},action_id=${r2_action}}  rules[3].present=${r3_present}"

    [[ "${r0_present}" == "1" ]] || { echo "FAIL[e0p]: rules[0].present='${r0_present}' (expected 1)" >&2; fail=1; }
    [[ "${r0_action}"  == "0" ]] || { echo "FAIL[e0a]: rules[0].action_id='${r0_action}' (expected 0 = PASS)" >&2; fail=1; }
    [[ "${r1_present}" == "1" ]] || { echo "FAIL[e1p]: rules[1].present='${r1_present}' (expected 1)" >&2; fail=1; }
    [[ "${r1_action}"  == "0" ]] || { echo "FAIL[e1a]: rules[1].action_id='${r1_action}' (expected 0 = PASS)" >&2; fail=1; }
    [[ "${r2_present}" == "1" ]] || { echo "FAIL[e2p]: rules[2].present='${r2_present}' (expected 1)" >&2; fail=1; }
    [[ "${r2_action}"  == "1" ]] || { echo "FAIL[e2a]: rules[2].action_id='${r2_action}' (expected 1 = DROP)" >&2; fail=1; }
    [[ "${r3_present}" == "0" ]] || { echo "FAIL[e3p]: rules[3].present='${r3_present}' (expected 0 = empty slot)" >&2; fail=1; }
fi

# ── (f) inner allowlist contains MAC_A + MAC_B but NOT MAC_C ───────────
# Read active_idx to pick the right inner pin.
read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
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

active=$(read_active_idx)
echo "active_idx='${active}'"

inner_pin=""
case "${active}" in
    0) inner_pin="${PIN_DIR}/allowlist_a" ;;
    1) inner_pin="${PIN_DIR}/allowlist_b" ;;
esac

if [[ -z "${inner_pin}" ]]; then
    echo "FAIL[f0]: could not determine active inner pin (active_idx='${active}')" >&2
    fail=1
elif ! sudo -n test -e "${inner_pin}"; then
    echo "FAIL[f1]: active inner pin ${inner_pin} missing" >&2
    fail=1
else
    echo "=== active inner allowlist dump (${inner_pin})"
    sudo -n bpftool map dump pinned "${inner_pin}" 2>/dev/null || true

    # MAC_A present?
    if ! mac_in_inner_pin "${inner_pin}" "${MAC_A}"; then
        echo "FAIL[fA]: pass-rule MAC ${MAC_A} (id=0) NOT in active inner — apply step 8 broken" >&2
        fail=1
    fi
    # MAC_B present?
    if ! mac_in_inner_pin "${inner_pin}" "${MAC_B}"; then
        echo "FAIL[fB]: pass-rule MAC ${MAC_B} (id=1) NOT in active inner — apply step 8 broken" >&2
        fail=1
    fi
    # MAC_C ABSENT (load-bearing).
    if mac_in_inner_pin "${inner_pin}" "${MAC_C}"; then
        echo "FAIL[fC]: drop-rule MAC ${MAC_C} (id=2) FOUND in active inner —" >&2
        echo "         either (i) the apply path treats drop-rules as pass (PI-29 violation), OR" >&2
        echo "         (ii) the inner-value shape was extended to embed rule_id (PI-27/PI-13-3.4 violation, defer broken)." >&2
        fail=1
    fi
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_RULES_SKELETON_NOT_WIRED"
exit "${fail}"
