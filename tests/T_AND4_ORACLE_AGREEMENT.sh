#!/bin/bash
# T_AND4_ORACLE_AGREEMENT — design §6.66 (MVP-4.4 / §5.44).
#
# THE 4-axis compose proof. For each test vector (dst, src, proto, dport):
#   1. snapshot all 64 rule_counters slots (active_idx-aware),
#   2. inject exactly one Eth+IPv4+L4 frame via inject_l4.py,
#   3. wait for the packet to be classified (4-col stats sum +1),
#   4. re-snapshot; find the single rule-id slot that rose by exactly 1
#      (NONE rising == datapath matched NOTHING == defaults fallthrough),
#   5. assert that id == the INDEPENDENT oracle's prediction
#      (bitvec_oracle_prod.py --ruleset and4) for the same tuple (NOMATCH=64).
#
# The oracle is a naive O(N) first-match scan (NO bitmask / closure / ffsll /
# range-table / wildcard map) — algorithmically independent of the datapath,
# so a disagreement localises a proto / port / wildcard / acc bug.
#
# Vector battery spans: full-4-axis hit, single-axis-miss for each axis,
# proto-miss, port edges (lo, hi, lo-1, hi+1), single-port, wildcard survival,
# first-match-tie (lower id wins), ICMP has_port=0 survival, and FOUR negation
# controls (predict NOMATCH).
#
# Sanity floor:
#   * SMOKE    — apply exit 0 + rule_counters pin existence (V1 is a clean
#                full-4-axis hit on id0).
#   * NEGATION — V5/V8/V9/V15 predict NOMATCH (no rule slot may bump). Proves
#                the machinery can register a "miss": an always-match datapath
#                FAILS here.
#
# The expected-id comments are documentation; the LOAD-BEARING expected is
# computed live by the oracle so the fixture and the oracle's hand-transcribed
# RULES_AND4 table must agree (data-independence).
#
# Maps to: PI-mvp-4.4-AND4, PI-mvp-4.4-PROTO, PI-mvp-4.4-PORT,
#          PI-mvp-4.4-L4PARSE, PI-mvp-4.4-WILDCARD.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_and4.yaml"
ORACLE="${AND_ORACLE_PROD:-${TEST_DIR}/bitvec/bitvec_oracle_prod.py}"
INJECT="${TEST_DIR}/inject/inject_l4.py"
NOMATCH=64

[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }
[[ -f "${ORACLE}"  ]] || { echo "FAIL: oracle missing at ${ORACLE}" >&2; exit 1; }
[[ -f "${INJECT}"  ]] || { echo "FAIL: missing injector ${INJECT}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-and4oracle-stderr.XXXXXX)
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

# ── Vector battery (dst src proto dport → expected id computed live) ──────
VECTORS=(
  "V1  10.1.2.3     192.168.5.50  tcp  1500"   # full-4-axis hit id0       -> 0
  "V2  10.1.2.3     192.168.5.50  udp  1500"   # proto-miss of id0         -> 5 (port-only)
  "V3  8.8.8.8      192.168.5.50  tcp  1500"   # dst-miss of id0           -> 5
  "V4  10.1.2.3     8.8.8.8       tcp  1500"   # src-miss of id0           -> 5
  "V5  10.1.2.3     192.168.5.50  tcp  2001"   # port-miss of id0 (hi+1)   -> NOMATCH
  "V6  203.0.113.5  8.8.8.8       tcp  1000"   # port edge lo (inclusive)  -> 5
  "V7  203.0.113.5  8.8.8.8       tcp  2000"   # port edge hi (inclusive)  -> 5
  "V8  203.0.113.5  8.8.8.8       tcp  999"    # port lo-1                  -> NOMATCH
  "V9  203.0.113.5  8.8.8.8       tcp  2001"   # port hi+1                  -> NOMATCH
  "V10 203.0.113.5  8.8.8.8       tcp  443"    # single-port rule id4      -> 4
  "V11 10.3.1.1     8.8.8.8       udp  7777"   # dst+proto rule id1        -> 1
  "V12 8.8.8.8      10.9.4.4      tcp  7777"   # src-only rule id2         -> 2
  "V13 10.7.1.1     8.8.8.8       icmp 0"      # icmp survives dst rule id3-> 3
  "V14 10.7.1.1     8.8.8.8       tcp  1500"   # first-match tie id3<id5   -> 3
  "V15 203.0.113.5  8.8.8.8       icmp 0"      # icmp has_port=0, no rule  -> NOMATCH
)

fail=0
saw_negation=0
for spec in "${VECTORS[@]}"; do
    read -r name dst src proto dport <<<"${spec}"

    expected=$(python3 "${ORACLE}" --ruleset and4 \
                 --dst-ip "${dst}" --src-ip "${src}" --proto "${proto}" --dport "${dport}")
    [[ "${expected}" == "${NOMATCH}" ]] && saw_negation=1

    read -ra before < <(read_rc_all)
    read -r bp bd bm bc < <(read_stats_with_cidr)

    ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" \
        --dst-ip "${dst}" --src-ip "${src}" --proto "${proto}" --dport "${dport}" \
        --dst-mac "${MAC_DST}"
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
        echo "  [${name}] dst=${dst} src=${src} ${proto}/${dport} -> id=${bumped} (oracle=${expected}) ${tag}"
    else
        echo "FAIL[${name}]: datapath matched id=${bumped} but oracle predicted ${expected}" >&2
        echo "          tuple dst=${dst} src=${src} proto=${proto} dport=${dport}" >&2
        echo "          (disagreement localises a proto/port/wildcard/acc bug)" >&2
        fail=1
    fi
done

if (( ! saw_negation )); then
    echo "FAIL[sanity]: no NOMATCH (negation-control) vector present in battery" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_AND4_ORACLE_AGREEMENT (oracle ↔ 4-axis datapath agree)"
exit "${fail}"
