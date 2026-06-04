#!/bin/bash
# T_ANDV6_ORACLE_AGREEMENT — design §5.53 TestStrategy / §6.71 (MVP-4.13 / S4).
#
# THE OPS canary for the now-LIVE ETH_P_IPV6 datapath arm. S1 (§6.70) proved the
# empty seam routes 0x86DD frames to defaults; S2 (§5.52) proved a REAL IPv6
# frame still routes to defaults. S4 fills the seam with the 8-term v6 AND +
# dst6/src6 LPM axes — and ONLY a real v6 frame against a real v6 rule exercises
# it. Without this test the v6 classification ships untested.
#
# For each vector (dst6, src6, proto, dport, vlan):
#   1. snapshot all 64 rule_counters slots (active_idx-aware),
#   2. inject exactly one Eth+[VLAN]+IPv6+L4 frame via inject_l6.py,
#   3. wait for classification (4-col stats sum +1),
#   4. re-snapshot; find the single rule-id slot that rose by exactly 1
#      (NONE rising == datapath matched NOTHING == defaults fallthrough),
#   5. assert that id == the INDEPENDENT oracle's prediction
#      (bitvec_oracle_prod.py --ruleset andv6 --dst-ip6 D --src-ip6 S …).
#
# The oracle is a naive O(N) first-match scan that masks v6 prefixes in the
# 128-bit Python-int domain (NO LPM_TRIE, NO bitmask, NO closure, NO ffsll) —
# algorithmically independent of the datapath, so a disagreement localises a
# v6-key byte-order / cross-family-wildcard / acc / first-match bug (PI-V6KEY).
#
# Vector battery (config_valid_andv6.yaml) covers: FULL-8-axis-v6 hit (id0),
# dst6-only hit (id1), single-axis miss of id0 on vlan (AND not OR), a src6-axis
# miss of id0 (AND not OR — the v6-SOURCE-axis negation), the proto-only
# address-wildcard rule (id3), a first-match TIE (a udp frame to 2001:db8:2::/48
# matches BOTH dst6-rule id1 and proto-rule id3 → LOWER id 1 wins), and a
# matches-nothing control.
#
# Sanity floor:
#   * SMOKE    — apply exit 0 + rule_counters/dst6_rulesets/src6_rulesets/wildcard
#                pins exist (W1 is a clean full-8-axis-v6 hit on id0).
#   * NEGATION — W3/W6/W7 predict NOMATCH (no rule slot may bump). Proves the
#                machinery registers a "miss"; an always-match v6 arm FAILS here.
#                W7 is a v6-SRC-axis negation specifically (only delta from the
#                matching vector is src6) — it fails a datapath that ignores src6.
#
# Maps to: PI-mvp-4.13-V6KEY, PI-mvp-4.13-CROSS-FAMILY (v6 side),
#          PI-mvp-4.13-AXES8, PI-mvp-4.13-FIRST-MATCH.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_andv6.yaml"
ORACLE="${AND_ORACLE_PROD:-${TEST_DIR}/bitvec/bitvec_oracle_prod.py}"
INJECT="${INJECT_L6:-${TEST_DIR}/inject/inject_l6.py}"
NOMATCH=64

[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }
[[ -f "${ORACLE}"  ]] || { echo "FAIL: oracle missing at ${ORACLE}" >&2; exit 1; }
[[ -f "${INJECT}"  ]] || { echo "FAIL: missing injector ${INJECT}" >&2; exit 1; }

# inject_l6.py needs scapy; skip (not fail) if absent — matches S2's idiom.
if ! ${NSEXEC:-sudo -n} python3 -c 'import scapy' 2>/dev/null \
     && ! python3 -c 'import scapy' 2>/dev/null; then
    echo "SKIP: scapy not importable (inject_l6.py prerequisite)" >&2
    exit 77
fi

stderr_file=$(mktemp /tmp/xdpmf-andv6oracle-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

# Guard #22 N/A (untagged v6 frames in most vectors) but disabling offload is
# harmless and protects the one tagged vector (vlan 100).
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
    echo "FAIL[smoke]: apply exit ${rc} (expected 0 — dst_cidr6/src_cidr6 keys must be accepted under v2)" >&2; exit 1
fi
if ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[smoke]: ${PIN_DIR}/rule_counters_a pin missing after apply" >&2; exit 1
fi
for pin in dst6_rulesets src6_rulesets ruleset_state; do
    if ! sudo -n test -e "${PIN_DIR}/${pin}"; then
        echo "FAIL[smoke]: ${PIN_DIR}/${pin} pin missing after apply (S4 v6 axes not wired)" >&2; exit 1
    fi
done
echo "smoke OK: apply exit 0; rule_counters + dst6_rulesets + src6_rulesets + ruleset_state reachable"

# ── Vector battery (dst6 src6 proto dport vlan → expected id computed live) ──
# vlan = "-" means UNTAGGED (no --vlan; has_vlan=0).
VECTORS=(
  "W1 2001:db8:1::1234 2001:db8:5::9    tcp 1500 100  0"        # FULL-8-axis-v6 id0 -> 0
  "W2 2001:db8:2::5    2001:db8:9::9    tcp 80   -    1"        # dst6-only id1      -> 1
  "W3 2001:db8:1::1234 2001:db8:5::9    tcp 1500 999  64"       # id0 vlan-miss      -> NOMATCH
  "W4 2001:db8:dead::1 2001:db8:beef::2 udp 53   -    3"        # proto-only id3     -> 3
  "W5 2001:db8:2::5    2001:db8:9::9    udp 53   -    1"        # TIE id1+id3        -> 1
  "W6 2001:db8:dead::1 2001:db8:5::9    tcp 22   -    64"       # matches nothing    -> NOMATCH
  "W7 2001:db8:1::1234 2001:db8:9::9    tcp 1500 100  64"       # id0 src6-miss      -> NOMATCH
)

fail=0
saw_negation=0
for spec in "${VECTORS[@]}"; do
    read -r name dst src proto dport vlan annotated <<<"${spec}"

    vlan_args=()
    [[ "${vlan}" != "-" ]] && vlan_args=(--vlan "${vlan}")

    expected=$(python3 "${ORACLE}" --ruleset andv6 \
                 --dst-ip6 "${dst}" --src-ip6 "${src}" --proto "${proto}" --dport "${dport}" \
                 "${vlan_args[@]}")
    # Cross-check the live oracle prediction against the table-author's intent.
    if [[ "${expected}" != "${annotated}" ]]; then
        echo "FAIL[${name}]: oracle predicted ${expected} but vector annotation says ${annotated}" >&2
        echo "          (fixture/oracle transcription drift — fix RULES_ANDV6 or the fixture)" >&2
        fail=1; continue
    fi
    [[ "${expected}" == "${NOMATCH}" ]] && saw_negation=1

    read -ra before < <(read_rc_all)
    read -r bp bd bm bc < <(read_stats_with_cidr)

    ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" \
        --dst-ip "${dst}" --src-ip "${src}" --proto "${proto}" --dport "${dport}" \
        --dst-mac "${MAC_DST}" "${vlan_args[@]}"
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
        echo "  [${name}] dst6=${dst} src6=${src} ${proto}/${dport} vlan=${vlan} -> id=${bumped} (oracle=${expected}) ${tag}"
    else
        echo "FAIL[${name}]: datapath matched id=${bumped} but oracle predicted ${expected}" >&2
        echo "          tuple dst6=${dst} src6=${src} proto=${proto} dport=${dport} vlan=${vlan}" >&2
        echo "          (disagreement localises a v6-key/cross-family/acc/first-match bug)" >&2
        fail=1
    fi
done

if (( ! saw_negation )); then
    echo "FAIL[sanity]: no NOMATCH (negation-control) vector present in battery" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_ANDV6_ORACLE_AGREEMENT (oracle ↔ 8-axis v6 datapath agree)"
exit "${fail}"
