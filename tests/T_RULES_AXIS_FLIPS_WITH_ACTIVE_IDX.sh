#!/bin/bash
# T_RULES_AXIS_FLIPS_WITH_ACTIVE_IDX — design §6.NN+2 (MVP-3.4b cycle 2 / §5.34).
#
# Verifies that the rules axis flips IN LOCKSTEP with active_idx (per
# HG-3.4b-c2-1 + D-3.4b-c2-1 parallel-outer pattern, mirroring §5.27
# CIDR-axis). One-deep rollback history: the inactive slot still holds
# the previous config's rules (per §5.26 atomic-swap contract).
#
# NO traffic injection — purely bpftool map dump assertions on the
# parallel-outer indexing.
#
# Trigger (per §6.NN+2):
#   1. setup_veth + apply config_per_rule_counters.yaml
#      (config A: 4 rules — id=0/5/17/42).
#   2. Read active_idx → active_A.
#   3. Read rules_<active_A>: assert ids 0, 5, 17, 42 occupied
#      (.present == 1); other slots empty.
#   4. apply <heredoc config B: 2 rules — id=10 drop, id=20 pass>.
#   5. Read active_idx → active_B. Assert active_B != active_A.
#   6. Read rules_<active_B>: assert ids 10, 20 occupied; ids 0/5/17/42
#      now EMPTY in the new slot.
#   7. Read rules_<active_A> (the NOW-INACTIVE slot): assert STILL
#      contains config A's rules (one-deep rollback history).
#
# Observable outcome (ALL):
#   (a) apply A exit 0.
#   (b) all 3 rules_outer/rules_a/rules_b pins exist; both inner pins
#       are dumpable.
#   (c) rules_<active_A>: present[{0,5,17,42}]==1; present[other]==0.
#   (d) apply B exit 0.
#   (e) active_B != active_A (single u32 flip across the apply).
#   (f) rules_<active_B>: present[{10,20}]==1; present[{0,5,17,42}]==0.
#   (g) rules_<active_A> (inactive): STILL contains {0,5,17,42};
#       proves one-deep rollback history.
#
# Sanity-floor smoke: step (a)+(b) — apply succeeds AND parallel-outer
# triple of pins materialize.
# Negation control: step (g) is the load-bearing differential — without
# this assertion, "active slot has new content" could be theatrical
# (both slots overwritten on every apply). The non-active slot retaining
# OLD content is the parallel-swap-correctness signature.
# Secondary negation: step (f) — that the NEW active slot does NOT
# contain config A's ids proves the active_idx is actually steering the
# datapath toward a DIFFERENT inner slot, not toward a re-written single
# slot.
#
# Maps to: PI-13-3.4b-c2 (rules-axis active_idx-driven swap),
# §5.26 Q2 A1 + §5.27 Q1 AS1 (parallel-outer indexing precedent extends
# to rules axis), §5.34 D-3.4b-c2-1 + D-3.4b-c2-8.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIX_A="${TEST_DIR}/fixtures/config_per_rule_counters.yaml"
[[ -f "${FIX_A}" ]] || { echo "FAIL: missing fixture ${FIX_A}" >&2; exit 1; }

# Config B as heredoc — different rule_ids than config A.
FIX_B=$(mktemp /tmp/xdpmf_rules_flip_B_XXXXXX.yaml)
cat > "${FIX_B}" <<'YEOF'
# §6.NN+2 config B — different rule_ids (10, 20) than config A (0, 5, 17, 42).
# §5.43 MVP-4.3: MAC deferred → src_cidr grammar; schema_version: 2.
# id=10 DROPS src 10.10.0.0/16; id=20 PASSES src 10.20.0.0/16.
schema_version: 2
default_action: drop
rules:
  - id: 10
    action: drop
    match:
      src_cidr: "10.10.0.0/16"
  - id: 20
    action: pass
    match:
      src_cidr: "10.20.0.0/16"
YEOF

stderr_apply_a=$(mktemp /tmp/xdpmf-rulesflip-apply-a.XXXXXX)
stderr_apply_b=$(mktemp /tmp/xdpmf-rulesflip-apply-b.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_apply_a}" "${stderr_apply_b}" "${FIX_B}"' EXIT

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

read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}

# Pin name selector for a given active_idx value.
rules_pin_for() {
    case "$1" in
        0) echo "${PIN_DIR}/rules_a" ;;
        1) echo "${PIN_DIR}/rules_b" ;;
        *) return 1 ;;
    esac
}

# assert_rule_present <pin> <expected_present 0|1> <ids...>
assert_rules_present() {
    local pin="$1" expected="$2"; shift 2
    local id p
    for id in "$@"; do
        p=$(rule_present_at "${pin}" "${id}")
        if [[ "${p}" != "${expected}" ]]; then
            echo "FAIL: ${pin}[${id}].present='${p}' (expected ${expected})" >&2
            return 1
        fi
    done
    return 0
}

setup_veth

# ── (a) apply config A ───────────────────────────────────────────────────
echo "=== apply ${FIX_A} (config A — ids 0, 5, 17, 42)"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIX_A}" 2>"${stderr_apply_a}"
rc_a=$?
set -e
echo "rc_a=${rc_a}"
cat "${stderr_apply_a}" >&2 || true
fail=0
if [[ "${rc_a}" -ne 0 ]]; then
    echo "FAIL[a]: apply A exit ${rc_a} (expected 0)" >&2
    fail=1
fi

# ── (b) sanity-floor smoke: 3 rules_* pins exist ─────────────────────────
for pin in rules_outer rules_a rules_b active_idx; do
    if ! sudo -n test -e "${PIN_DIR}/${pin}"; then
        echo "FAIL[b.${pin}]: ${PIN_DIR}/${pin} pin missing — §5.34 D-1 violated" >&2
        fail=1
    fi
done
if (( fail != 0 )); then
    echo "FAIL: smoke floor failed; aborting before content assertions" >&2
    exit 1
fi

# ── pick rules_<active_A> ────────────────────────────────────────────────
active_A=$(read_active_idx)
echo "active_idx (after A) = '${active_A}'"
rules_A_pin=$(rules_pin_for "${active_A}") || {
    echo "FAIL[a.idx]: cannot map active_idx='${active_A}' to rules_<a|b>" >&2
    exit 1
}
echo "rules_<active_A> = ${rules_A_pin}"
echo "=== rules_<active_A> dump"
sudo -n bpftool map dump pinned "${rules_A_pin}" 2>/dev/null | head -20 || true

# ── (c) rules_<active_A>: ids 0,5,17,42 occupied; others empty ───────────
if ! assert_rules_present "${rules_A_pin}" 1 0 5 17 42; then
    echo "FAIL[c.occupied]: expected rules_<active_A> ids {0,5,17,42} all present=1" >&2
    fail=1
fi
# Spot-check a few empty slots.
if ! assert_rules_present "${rules_A_pin}" 0 1 2 3 4 6 7 8 18 41 43 60 63; then
    echo "FAIL[c.empty]: rules_<active_A> non-config-A slot is unexpectedly present" >&2
    fail=1
fi

# ── (d) apply config B ───────────────────────────────────────────────────
echo "=== apply ${FIX_B} (config B — ids 10, 20)"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIX_B}" 2>"${stderr_apply_b}"
rc_b=$?
set -e
echo "rc_b=${rc_b}"
cat "${stderr_apply_b}" >&2 || true
if [[ "${rc_b}" -ne 0 ]]; then
    echo "FAIL[d]: apply B exit ${rc_b} (expected 0)" >&2
    fail=1
fi

# ── (e) active_idx flipped ──────────────────────────────────────────────
active_B=$(read_active_idx)
echo "active_idx (after B) = '${active_B}'"
if [[ -z "${active_A}" || -z "${active_B}" ]]; then
    echo "FAIL[e.readout]: could not read active_idx" >&2
    fail=1
elif [[ "${active_A}" == "${active_B}" ]]; then
    echo "FAIL[e.flip]: active_idx did NOT flip (A=${active_A} B=${active_B})" >&2
    fail=1
fi
rules_B_pin=$(rules_pin_for "${active_B}") || {
    echo "FAIL[e.idx]: cannot map active_idx='${active_B}' to rules_<a|b>" >&2
    exit 1
}
echo "rules_<active_B> = ${rules_B_pin}"

# ── (f) rules_<active_B>: ids 10, 20 occupied; ids 0,5,17,42 EMPTY ───────
echo "=== rules_<active_B> dump"
sudo -n bpftool map dump pinned "${rules_B_pin}" 2>/dev/null | head -20 || true
if ! assert_rules_present "${rules_B_pin}" 1 10 20; then
    echo "FAIL[f.occupied]: expected rules_<active_B> ids {10,20} both present=1" >&2
    fail=1
fi
if ! assert_rules_present "${rules_B_pin}" 0 0 5 17 42; then
    echo "FAIL[f.cleared]: rules_<active_B> still has config-A ids — slots not cleared" >&2
    fail=1
fi

# ── (g) rules_<active_A> (inactive) STILL holds config A — rollback hist ─
echo "=== rules_<active_A> dump (now INACTIVE — one-deep rollback)"
sudo -n bpftool map dump pinned "${rules_A_pin}" 2>/dev/null | head -20 || true
if ! assert_rules_present "${rules_A_pin}" 1 0 5 17 42; then
    echo "FAIL[g.rollback]: rules_<active_A> (now inactive) lost config-A rules" >&2
    echo "                  one-deep rollback history broken (§5.26 atomic-swap contract)" >&2
    fail=1
fi
# Spot-check that the inactive slot was NOT also overwritten with B's content.
if ! assert_rules_present "${rules_A_pin}" 0 10 20; then
    echo "FAIL[g.no-overlap]: rules_<active_A> (inactive) also contains config-B ids" >&2
    echo "                    impl is writing both inners — atomic-swap discipline broken" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_RULES_AXIS_FLIPS_WITH_ACTIVE_IDX"
exit "${fail}"
