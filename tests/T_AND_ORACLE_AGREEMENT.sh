#!/bin/bash
# T_AND_ORACLE_AGREEMENT — design §6.61 (MVP-4.3 / §5.43).
#
# THE correctness test for the production OR→AND bit-vector pivot.
#
# For each test vector (dst_ip, src_ip):
#   1. snapshot all 64 rule_counters slots (active_idx-aware),
#   2. inject exactly one IPv4 frame via inject_ipv4.py,
#   3. wait for the packet to be classified (4-col stats sum +1),
#   4. re-snapshot; find the single rule-id slot that rose by exactly 1
#      (NONE rising == datapath matched NOTHING == defaults fallthrough),
#   5. assert that id == the INDEPENDENT oracle's prediction
#      (bitvec_oracle_prod.py) for the same tuple (NOMATCH == 64).
#
# The oracle is a naive O(N) first-match scan (NO bitmask / closure /
# ffsll / wildcard map) — algorithmically independent of the datapath, so a
# disagreement localises a closure / wildcard / first-match bug.
#
# Sanity floor:
#   * SMOKE    — apply exit 0 + rule_counters pin existence (V1 is a clean
#                both-axes hit on id0).
#   * NEGATION — V2/V3/V7 predict NOMATCH (no rule slot may bump). Proves the
#                machinery can register a "miss": an always-match datapath
#                FAILS here. (V2/V3 are the AND-miss single-axis controls.)
#   * OVERLAP / FIRST-MATCH — V6 (id1 covers more-specific id4), V8 (cross-axis tie).
#   * WILDCARD — V4 (dst-only rule via src wildcard), V5 (src-only rule).
#
# The expected-id column is documentation; the LOAD-BEARING expected is
# computed live by bitvec_oracle_prod.py so the fixture and oracle
# transcriptions of the rule set must agree (data-independence).
#
# Maps to: PI-mvp-4.3-AND, PI-mvp-4.3-CLOSURE, PI-mvp-4.3-WILDCARD.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_and.yaml"
ORACLE="${AND_ORACLE_PROD:-${TEST_DIR}/bitvec/bitvec_oracle_prod.py}"
INJECT="${TEST_DIR}/inject/inject_ipv4.py"
SRC_MAC="02:00:00:00:00:aa"
NOMATCH=64

[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }
[[ -f "${ORACLE}"  ]] || { echo "FAIL: oracle missing at ${ORACLE}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-andoracle-stderr.XXXXXX)
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
# Echo all 64 rule_counters slots, space-separated.
read_rc_all() {
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" "$(rule_counters_active_pin)"
}

# ── apply + smoke ────────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
cat "${stderr_file}" >&2 || true
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[smoke]: apply exit ${rc} (expected 0)" >&2; exit 1
fi
if ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[smoke]: ${PIN_DIR}/rule_counters_a pin missing after apply" >&2; exit 1
fi
echo "smoke OK: apply exit 0, rule_counters reachable"

# ── Vector battery (dst src → expected id computed live) ─────────────────
VECTORS=(
  "V1  10.1.2.3     192.168.5.50"   # both axes of id0          -> 0
  "V2  10.1.2.3     8.8.8.8"        # dst-only of id0 (AND miss) -> NOMATCH
  "V3  8.8.8.8      192.168.5.50"   # src-only of id0 (AND miss) -> NOMATCH
  "V4  10.3.1.1     8.8.8.8"        # dst-only rule id1 (src wc) -> 1
  "V5  8.8.8.8      10.9.4.4"       # src-only rule id2 (dst wc) -> 2
  "V6  10.3.5.9     8.8.8.8"        # overlap id1/id4 first-match-> 1
  "V7  203.0.113.5  8.8.8.8"        # matches nothing            -> NOMATCH
  "V8  10.3.1.1     10.9.4.4"       # cross-axis tie id1 vs id2  -> 1
  "V9  10.1.5.5     192.168.5.50"   # both axes of id0 (alt)     -> 0
  "V10 10.1.0.0     192.168.5.255"  # id0 prefix boundary        -> 0
)

fail=0
saw_negation=0
for spec in "${VECTORS[@]}"; do
    read -r name dst src <<<"${spec}"

    expected=$(python3 "${ORACLE}" --dst-ip "${dst}" --src-ip "${src}")
    [[ "${expected}" == "${NOMATCH}" ]] && saw_negation=1

    read -ra before < <(read_rc_all)
    read -r bp bd bm bc < <(read_stats_with_cidr)

    ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "${src}" "${dst}"
    wait_for_stats_sum_with_cidr "${IFACE_A}" $(( bp + bd + bm + bc + 1 )) || true

    read -ra after < <(read_rc_all)

    # Find every slot whose count rose by exactly 1; flag any other drift.
    bumped=""
    drift=0
    for id in $(seq 0 63); do
        delta=$(( ${after[$id]:-0} - ${before[$id]:-0} ))
        if (( delta == 1 )); then
            bumped="${bumped} ${id}"
        elif (( delta != 0 )); then
            echo "  [${name}] WARN: rule_counters[${id}] delta=${delta} (expected 0 or 1)" >&2
            drift=1
        fi
    done
    bumped="${bumped# }"

    # No slot bumped == datapath matched nothing == NOMATCH.
    [[ -z "${bumped}" ]] && bumped="${NOMATCH}"

    if (( drift )); then
        echo "FAIL[${name}]: a non-target rule_counters slot also changed" >&2
        fail=1; continue
    fi
    if [[ "${bumped}" == *" "* ]]; then
        echo "FAIL[${name}]: expected exactly ONE slot to bump; got '{${bumped}}' (oracle=${expected})" >&2
        fail=1; continue
    fi

    if [[ "${bumped}" == "${expected}" ]]; then
        tag="OK"; [[ "${expected}" == "${NOMATCH}" ]] && tag="OK(NOMATCH)"
        echo "  [${name}] dst=${dst} src=${src} -> id=${bumped} (oracle=${expected}) ${tag}"
    else
        echo "FAIL[${name}]: datapath matched id=${bumped} but oracle predicted ${expected}" >&2
        echo "          tuple dst=${dst} src=${src}" >&2
        echo "          (disagreement localises a closure/wildcard/first-match/AND bug)" >&2
        fail=1
    fi
done

if (( ! saw_negation )); then
    echo "FAIL[sanity]: no NOMATCH (negation-control) vector present in battery" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_AND_ORACLE_AGREEMENT (oracle ↔ datapath agree across V-battery)"
exit "${fail}"
