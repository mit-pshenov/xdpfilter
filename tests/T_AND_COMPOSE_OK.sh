#!/bin/bash
# T_AND_COMPOSE_OK — design §6.60 (MVP-4.3 / §5.43).
#
# THE OR→AND proof. Under the production bit-vector AND classifier, a rule
# constraining BOTH dst_cidr AND src_cidr matches ONLY when BOTH axes are
# satisfied. Under the retired OR model a single-axis match would have hit.
#
# Fixture config_valid_and.yaml (schema_version: 2):
#   id 0 : dst 10.1.0.0/16 AND src 192.168.5.0/24  pass  (full-AND rule)
#   id 1 : dst 10.3.0.0/16                          pass  (dst-only; src wildcard)
#   id 2 : src 10.9.0.0/16                          drop  (src-only; dst wildcard)
#   id 4 : dst 10.3.5.0/24                          drop  (overlaps id1)
#   default_action: drop
#
# Steps / observable outcome (ALL must hold):
#   (a) SMOKE: apply exit 0; dst_rulesets + cidr_rulesets + wildcard pins
#       exist; rule_counters baseline slot 0/1 == 0.
#   (b) BOTH axes of id0 (dst=10.1.2.3 src=192.168.5.50) → id0 hit:
#       rule_counters[0] == 1; STAT_PASS_CIDR delta == 1.
#   (c) NEGATION CONTROL — dst-only of id0 (dst=10.1.2.3 src=8.8.8.8) →
#       does NOT hit id0: rule_counters[0] STAYS 1; falls to defaults DROP
#       (STAT_DROP_DENY delta == 1). Under OR this would have PASSed via id0.
#   (d) src-only of id0 (dst=8.8.8.8 src=192.168.5.50) → does NOT hit id0:
#       rule_counters[0] STAYS 1; defaults DROP (STAT_DROP_DENY delta == 1).
#   (e) dst-only RULE id1 (dst=10.3.1.1 src=8.8.8.8) → matches on dst alone
#       (src wildcard): rule_counters[1] == 1; STAT_PASS_CIDR delta == 1.
#
# Sanity-floor smoke: step (a). Negation control: steps (c)+(d) — a
# single-axis match of an all-axes rule MUST NOT fire that rule. A datapath
# that still ORs the axes FAILS here.
#
# Maps to: PI-mvp-4.3-AND, PI-mvp-4.3-WILDCARD (single-axis rule id1).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_and.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

SRC_MAC="02:00:00:00:00:aa"   # MAC axis is deferred — value is irrelevant
INJECT="${TEST_DIR}/inject/inject_ipv4.py"

stderr_file=$(mktemp /tmp/xdpmf-andcompose-stderr.XXXXXX)
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
read_rc_slot() {
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" \
        "$(rule_counters_active_pin)" "$1"
}
inject() { ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "$1" "$2"; }

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
for pin in dst_rulesets cidr_rulesets wildcard; do
    if ! sudo -n test -e "${PIN_DIR}/${pin}"; then
        echo "FAIL[a2]: expected pin ${PIN_DIR}/${pin} missing (§5.43 DataStructures)" >&2
        fail=1
    fi
done
for slot in 0 1; do
    v=$(read_rc_slot "${slot}")
    [[ "${v}" == "0" ]] || { echo "FAIL[a3]: rule_counters[${slot}]='${v}' baseline (expected 0)" >&2; fail=1; }
done
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "stats baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"

# ── (b) BOTH axes of id0 → id0 hit ───────────────────────────────────────
echo "=== (b) inject dst=10.1.2.3 src=192.168.5.50 (BOTH axes of id0)"
inject 192.168.5.50 10.1.2.3
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true
read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
rc0=$(read_rc_slot 0)
if [[ "${rc0}" != "1" ]]; then
    echo "FAIL[b1]: rule_counters[0]='${rc0}' (expected 1 — both-axes match of id0)" >&2; fail=1
fi
if (( c1 - c0 != 1 )); then
    echo "FAIL[b2]: STAT_PASS_CIDR delta=$((c1-c0)) (expected 1)" >&2; fail=1
fi

# ── (c) NEGATION: dst-only of id0 → must NOT hit id0 ─────────────────────
echo "=== (c) NEGATION: inject dst=10.1.2.3 src=8.8.8.8 (dst-only of id0)"
inject 8.8.8.8 10.1.2.3
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true
read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
rc0=$(read_rc_slot 0)
if [[ "${rc0}" != "1" ]]; then
    echo "FAIL[c1]: rule_counters[0]='${rc0}' bumped on dst-only match (expected STILL 1)" >&2
    echo "          bug shape: datapath ORs the axes instead of ANDing them" >&2
    fail=1
fi
if (( d2 - d1 != 1 )); then
    echo "FAIL[c2]: STAT_DROP_DENY delta=$((d2-d1)) (expected 1 — falls to defaults drop)" >&2; fail=1
fi

# ── (d) NEGATION: src-only of id0 → must NOT hit id0 ─────────────────────
echo "=== (d) NEGATION: inject dst=8.8.8.8 src=192.168.5.50 (src-only of id0)"
inject 192.168.5.50 8.8.8.8
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + c2 + 1 )) || true
read -r p3 d3 m3 c3 < <(read_stats_with_cidr)
rc0=$(read_rc_slot 0)
if [[ "${rc0}" != "1" ]]; then
    echo "FAIL[d1]: rule_counters[0]='${rc0}' bumped on src-only match (expected STILL 1)" >&2; fail=1
fi
if (( d3 - d2 != 1 )); then
    echo "FAIL[d2]: STAT_DROP_DENY delta=$((d3-d2)) (expected 1 — falls to defaults drop)" >&2; fail=1
fi

# ── (e) dst-only RULE id1 matches on dst alone (src wildcard) ────────────
echo "=== (e) inject dst=10.3.1.1 src=8.8.8.8 (dst-only rule id1; src wildcard)"
inject 8.8.8.8 10.3.1.1
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p3 + d3 + m3 + c3 + 1 )) || true
read -r p4 d4 m4 c4 < <(read_stats_with_cidr)
rc1=$(read_rc_slot 1)
if [[ "${rc1}" != "1" ]]; then
    echo "FAIL[e1]: rule_counters[1]='${rc1}' (expected 1 — dst-only rule via src wildcard)" >&2
    echo "          bug shape: wildcard[src] not OR'd in, so id1 cannot survive the src axis" >&2
    fail=1
fi
if (( c4 - c3 != 1 )); then
    echo "FAIL[e2]: STAT_PASS_CIDR delta=$((c4-c3)) (expected 1)" >&2; fail=1
fi
# id0 must STILL be 1 (never re-hit across c/d/e).
rc0=$(read_rc_slot 0)
[[ "${rc0}" == "1" ]] || { echo "FAIL[e3]: rule_counters[0]='${rc0}' drifted (expected STILL 1)" >&2; fail=1; }

[[ "${fail}" == 0 ]] && echo "PASS: T_AND_COMPOSE_OK"
exit "${fail}"
