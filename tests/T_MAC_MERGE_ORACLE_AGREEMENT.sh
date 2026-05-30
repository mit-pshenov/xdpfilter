#!/bin/bash
# T_MAC_MERGE_ORACLE_AGREEMENT — design §5.50 (MVP-4.10 / B28) targeted canary.
#
# Closes the ONE mac-axis branch the §6.70 (T_AND6) corpus leaves uncovered:
# the memcmp-dedup MERGE of TWO rules SHARING ONE src-MAC. T_AND6 has three
# DISTINCT macs and no shared-MAC pair, so an always-false / too-strict mac
# comparator (one that fails to MERGE same-MAC rules) passes the entire AND6
# net while silently dropping a rule bit (the 2nd update_elem(BPF_ANY)
# overwrites the 1st in the inner HASH). This test makes that branch observable.
#
# config_valid_macmerge.yaml:
#   id 0 : mac ee:01 + tcp   id 1 : mac ee:01 + udp   id 2 : mac ee:02
# The mac-axis inner HASH MUST map key ee:01 -> (1<<0)|(1<<1); the proto axis
# then intersects (AND): a tcp frame from ee:01 -> id0, a udp frame -> id1.
# A FAILED merge holds only ONE of the two bits (whichever wrote last) -> one
# of M1/M2 flips to NOMATCH (or the wrong id) -> the independent naive O(N)
# first-match oracle (which models NO HASH/merge) disagrees and we FAIL loudly.
#
# Mechanism mirrors §6.70: snapshot rule_counters, inject one Eth+IPv4+L4 frame
# with the chosen --src-mac, wait for classification, find the slot that rose by
# exactly 1, assert it == bitvec_oracle_prod.py --ruleset macmerge.
#
# Sanity floor:
#   * SMOKE    — apply exit 0 + rule_counters pin existence (M1 is a clean hit).
#   * NEGATION — M4 predicts NOMATCH (unknown src-MAC ee:99; no slot may bump).
#                Proves the machinery registers a "miss"; an always-match
#                datapath FAILS here.
#
# Maps to: PI-mvp-4.10-LOWER-EQUIV, PI-mvp-4.10-POPULATE-EQUIV, PI-mvp-4.10-MAC-EQ.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_macmerge.yaml"
ORACLE="${AND_ORACLE_PROD:-${TEST_DIR}/bitvec/bitvec_oracle_prod.py}"
INJECT="${INJECT_L4:-${TEST_DIR}/inject/inject_l4.py}"
NOMATCH=64

[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }
[[ -f "${ORACLE}"  ]] || { echo "FAIL: oracle missing at ${ORACLE}" >&2; exit 1; }
[[ -f "${INJECT}"  ]] || { echo "FAIL: missing injector ${INJECT}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-macmerge-stderr.XXXXXX)
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
    echo "FAIL[smoke]: apply exit ${rc} (expected 0 — shared-MAC config must apply)" >&2; exit 1
fi
if ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[smoke]: ${PIN_DIR}/rule_counters_a pin missing after apply" >&2; exit 1
fi
echo "smoke OK: apply exit 0, rule_counters reachable"

# ── Vector battery (dst src proto dport mac → expected id computed live) ────
# All untagged IPv4 (mac axis is IPv4-gated; dst/src/port/vlan are wildcard).
#   M1  ee:01 tcp -> id0  (merge: if 2nd write wins, HASH[ee:01]=bit1 -> NOMATCH)
#   M2  ee:01 udp -> id1  (merge: if 1st write wins, HASH[ee:01]=bit0 -> NOMATCH)
#   M3  ee:02 tcp -> id2  (DISTINCT mac must NOT collide)
#   M4  ee:99 tcp -> NOMATCH (negation control — unknown src-MAC)
VECTORS=(
  "M1 1.2.3.4 5.6.7.8 tcp 80 aa:bb:cc:dd:ee:01"  # shared-mac tcp -> 0
  "M2 1.2.3.4 5.6.7.8 udp 80 aa:bb:cc:dd:ee:01"  # shared-mac udp -> 1
  "M3 1.2.3.4 5.6.7.8 tcp 80 aa:bb:cc:dd:ee:02"  # distinct mac   -> 2
  "M4 1.2.3.4 5.6.7.8 tcp 80 aa:bb:cc:dd:ee:99"  # unknown mac    -> NOMATCH
)

fail=0
saw_negation=0
for spec in "${VECTORS[@]}"; do
    read -r name dst src proto dport mac <<<"${spec}"

    expected=$(python3 "${ORACLE}" --ruleset macmerge \
                 --dst-ip "${dst}" --src-ip "${src}" --proto "${proto}" --dport "${dport}" \
                 --src-mac "${mac}")
    [[ "${expected}" == "${NOMATCH}" ]] && saw_negation=1

    read -ra before < <(read_rc_all)
    read -r bp bd bm bc < <(read_stats_with_cidr)

    ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" \
        --dst-ip "${dst}" --src-ip "${src}" --proto "${proto}" --dport "${dport}" \
        --src-mac "${mac}" --dst-mac "${MAC_DST}"
    wait_for_stats_sum_with_cidr "${IFACE_A}" $(( bp + bd + bm + bc + 1 )) || true

    read -ra after < <(read_rc_all)

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
        echo "  [${name}] dst=${dst} src=${src} ${proto}/${dport} mac=${mac} -> id=${bumped} (oracle=${expected}) ${tag}"
    else
        echo "FAIL[${name}]: datapath matched id=${bumped} but oracle predicted ${expected}" >&2
        echo "          tuple dst=${dst} src=${src} proto=${proto} dport=${dport} mac=${mac}" >&2
        echo "          (disagreement localises a mac dedup-MERGE / comparator bug)" >&2
        fail=1
    fi
done

if (( ! saw_negation )); then
    echo "FAIL[sanity]: no NOMATCH (negation-control) vector present in battery" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_MAC_MERGE_ORACLE_AGREEMENT (shared-MAC dedup merges correctly)"
exit "${fail}"
