#!/bin/bash
# T_AND5_ORACLE_AGREEMENT — design §6.69 (MVP-4.5 / §5.45).
#
# THE 5-axis compose proof. For each test vector (dst, src, proto, dport, vlan):
#   1. snapshot all 64 rule_counters slots (active_idx-aware),
#   2. inject exactly one Eth+[VLAN]+IPv4+L4 frame via inject_l4.py,
#   3. wait for the packet to be classified (4-col stats sum +1),
#   4. re-snapshot; find the single rule-id slot that rose by exactly 1
#      (NONE rising == datapath matched NOTHING == defaults fallthrough),
#   5. assert that id == the INDEPENDENT oracle's prediction
#      (bitvec_oracle_prod.py --ruleset and5 [--vlan V]) for the same tuple
#      (NOMATCH=64).
#
# The oracle is a naive O(N) first-match scan (NO bitmask / closure / ffsll /
# range-table / wildcard map / vlan HASH) — algorithmically independent of the
# datapath, so a disagreement localises a vlan / capture / wildcard / acc bug.
#
# Vector battery (config_valid_and5.yaml) spans: full-5-axis hit, single-axis
# miss for EACH of the 5 axes (incl. vlan-miss + dst/src/proto/port miss),
# UNTAGGED (has_vlan=0), port edges (lo, hi, hi+1), vlan+proto rule, vlan-only
# (ICMP) rule, first-match-tie (lower id wins), untagged→vlan-wildcard,
# vlan-miss→vlan-wildcard, port-only vlan-wildcard, and THREE negation
# controls (predict NOMATCH).
#
# Guard #22: NIC VLAN offload disabled in setup so tagged vectors are not
# silently stripped before XDP (D-mvp-4.5-OFFLOAD; §5.41 precedent). The
# tagged-hit vs untagged/vlan-miss vectors form the anti-vacuity differential:
# a stripped tag would change a tagged-hit vector's outcome → loud disagreement.
#
# Sanity floor:
#   * SMOKE    — apply exit 0 + rule_counters pin existence (V1 is a clean
#                full-5-axis hit on id0).
#   * NEGATION — V2/V3/V4/V5/V9/V15/V16/V17 predict NOMATCH (no rule slot may
#                bump). Proves the machinery can register a "miss": an
#                always-match datapath FAILS here.
#
# The expected-id comments are documentation; the LOAD-BEARING expected is
# computed live by the oracle so the fixture and the oracle's hand-transcribed
# RULES_AND5 table must agree (data-independence).
#
# Maps to: PI-mvp-4.5-AND5, PI-mvp-4.5-VLAN, PI-mvp-4.5-VLAN-CAPTURE,
#          PI-mvp-4.5-UNTAGGED, PI-mvp-4.5-WILDCARD, PI-mvp-4.5-OFFLOAD.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_and5.yaml"
ORACLE="${AND_ORACLE_PROD:-${TEST_DIR}/bitvec/bitvec_oracle_prod.py}"
INJECT="${INJECT_L4:-${TEST_DIR}/inject/inject_l4.py}"
NOMATCH=64

[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }
[[ -f "${ORACLE}"  ]] || { echo "FAIL: oracle missing at ${ORACLE}" >&2; exit 1; }
[[ -f "${INJECT}"  ]] || { echo "FAIL: missing injector ${INJECT}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-and5oracle-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

# ── Guard #22: disable NIC VLAN offload (best-effort) ─────────────────────
${NSEXEC} ethtool -K "${IFACE_A}" rxvlan off txvlan off 2>/dev/null || true
${NSEXEC} ethtool -K "${IFACE_B}" rxvlan off txvlan off 2>/dev/null || true

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

# ── Vector battery (dst src proto dport vlan → expected id computed live) ──
# vlan = "-" means UNTAGGED (no --vlan; has_vlan=0).
VECTORS=(
  "V1  10.1.2.3     192.168.5.50  tcp  1500  100"   # full-5-axis hit id0       -> 0
  "V2  10.1.2.3     192.168.5.50  tcp  1500  999"   # vlan-miss of id0          -> NOMATCH
  "V3  10.1.2.3     192.168.5.50  tcp  1500  -"     # untagged-miss of id0      -> NOMATCH
  "V4  10.1.2.3     192.168.5.50  udp  1500  100"   # proto-miss of id0         -> NOMATCH
  "V5  10.1.2.3     192.168.5.50  tcp  2001  100"   # port-miss of id0 (hi+1)   -> NOMATCH
  "V6  10.1.2.3     192.168.5.50  tcp  1000  100"   # port edge lo (inclusive)  -> 0
  "V7  10.1.2.3     192.168.5.50  tcp  2000  100"   # port edge hi (inclusive)  -> 0
  "V8  8.8.8.8      8.8.8.8       udp  1234  200"   # vlan+proto rule id1       -> 1
  "V9  8.8.8.8      8.8.8.8       tcp  1234  200"   # proto-miss of id1         -> NOMATCH
  "V10 8.8.8.8      8.8.8.8       icmp 0     300"   # vlan-only id2 (icmp ok)   -> 2
  "V11 10.5.1.1     8.8.8.8       tcp  8080  100"   # dst+vlan id3 < id4 (tie)  -> 3
  "V12 10.5.1.1     8.8.8.8       tcp  8080  -"     # untagged -> vlan-wild id4 -> 4
  "V13 10.5.1.1     8.8.8.8       tcp  8080  999"   # vlan-miss -> vlan-wild id4-> 4
  "V14 9.9.9.9      9.9.9.9       tcp  443   -"     # port-only vlan-wild id5   -> 5
  "V15 1.2.3.4      5.6.7.8       tcp  12345 777"   # matches nothing           -> NOMATCH
  "V16 8.8.8.8      192.168.5.50  tcp  1500  100"   # dst-miss of id0           -> NOMATCH
  "V17 10.1.2.3     8.8.8.8       tcp  1500  100"   # src-miss of id0           -> NOMATCH
)

fail=0
saw_negation=0
for spec in "${VECTORS[@]}"; do
    read -r name dst src proto dport vlan <<<"${spec}"

    vlan_args=()
    [[ "${vlan}" != "-" ]] && vlan_args=(--vlan "${vlan}")

    expected=$(python3 "${ORACLE}" --ruleset and5 \
                 --dst-ip "${dst}" --src-ip "${src}" --proto "${proto}" --dport "${dport}" \
                 "${vlan_args[@]}")
    [[ "${expected}" == "${NOMATCH}" ]] && saw_negation=1

    read -ra before < <(read_rc_all)
    read -r bp bd bm bc < <(read_stats_with_cidr)

    ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" \
        --dst-ip "${dst}" --src-ip "${src}" --proto "${proto}" --dport "${dport}" \
        --dst-mac "${MAC_DST}" "${vlan_args[@]}"
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
        echo "  [${name}] dst=${dst} src=${src} ${proto}/${dport} vlan=${vlan} -> id=${bumped} (oracle=${expected}) ${tag}"
    else
        echo "FAIL[${name}]: datapath matched id=${bumped} but oracle predicted ${expected}" >&2
        echo "          tuple dst=${dst} src=${src} proto=${proto} dport=${dport} vlan=${vlan}" >&2
        echo "          (disagreement localises a vlan/capture/wildcard/acc bug)" >&2
        fail=1
    fi
done

if (( ! saw_negation )); then
    echo "FAIL[sanity]: no NOMATCH (negation-control) vector present in battery" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_AND5_ORACLE_AGREEMENT (oracle ↔ 5-axis datapath agree)"
exit "${fail}"
