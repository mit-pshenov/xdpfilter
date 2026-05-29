#!/bin/bash
# T_AND6_ORACLE_AGREEMENT — design §5.47 TestStrategy / §6.70 (MVP-4.7 / §5.47).
#
# THE 6-axis compose proof (adds the LIVE MAC axis to the §6.69 5-axis proof).
# For each vector (dst, src, proto, dport, vlan, src_mac):
#   1. snapshot all 64 rule_counters slots (active_idx-aware),
#   2. inject exactly one Eth+[VLAN]+IPv4+L4 frame via inject_l4.py with the
#      chosen --src-mac,
#   3. wait for classification (4-col stats sum +1),
#   4. re-snapshot; find the single rule-id slot that rose by exactly 1
#      (NONE rising == datapath matched NOTHING == defaults fallthrough),
#   5. assert that id == the INDEPENDENT oracle's prediction
#      (bitvec_oracle_prod.py --ruleset and6 --src-mac M) for the same tuple.
#
# The oracle is a naive O(N) first-match scan (NO bitmask / closure / ffsll /
# range-table / wildcard map / HASH) — algorithmically independent of the
# datapath, so a disagreement localises a mac/capture/wildcard/acc bug.
#
# Vector battery (config_valid_and6.yaml) spans: full-6-axis hit, MAC-miss of
# the full rule (negation), mac+vlan+proto rule hit + its mac-miss + proto-miss,
# vlan-only / dst+vlan / dst-only / port-only MAC-WILDCARD rules (each matched by
# an ARBITRARY src-MAC — proves a rule omitting `mac` survives via the wildcard),
# a mac-only rule hit + its mac-miss, and a matches-nothing control. MAC is
# EXACT (no closure) and composed inside the IPv4 gate (D-mvp-4.7-Q2-GATE).
#
# Sanity floor:
#   * SMOKE    — apply exit 0 + rule_counters pin existence (W1 is a clean
#                full-6-axis hit on id0).
#   * NEGATION — W2/W4/W5/W11/W12 predict NOMATCH (no rule slot may bump).
#                Proves the machinery can register a "miss"; an always-match
#                datapath FAILS here. W2/W4/W11 are MAC-axis negations
#                specifically (the only delta from the matching vector is the
#                src-MAC) — they fail a datapath that UNIONS or ignores MAC.
#
# Maps to: PI-mvp-4.7-MAC, PI-mvp-4.3-AND (→6 axes), PI-mvp-4.3-WILDCARD,
#          PI-mvp-4.7-AXES6.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_and6.yaml"
ORACLE="${AND_ORACLE_PROD:-${TEST_DIR}/bitvec/bitvec_oracle_prod.py}"
INJECT="${INJECT_L4:-${TEST_DIR}/inject/inject_l4.py}"
NOMATCH=64

[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }
[[ -f "${ORACLE}"  ]] || { echo "FAIL: oracle missing at ${ORACLE}" >&2; exit 1; }
[[ -f "${INJECT}"  ]] || { echo "FAIL: missing injector ${INJECT}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-and6oracle-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

# Guard #22: disable NIC VLAN offload so tagged vectors are not stripped.
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
    echo "FAIL[smoke]: apply exit ${rc} (expected 0 — mac key must be accepted under v2)" >&2; exit 1
fi
if ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[smoke]: ${PIN_DIR}/rule_counters_a pin missing after apply" >&2; exit 1
fi
echo "smoke OK: apply exit 0, rule_counters reachable"

# ── Vector battery (dst src proto dport vlan mac → expected id computed live) ─
# vlan = "-" means UNTAGGED (no --vlan; has_vlan=0).
VECTORS=(
  "W1  10.1.2.3 192.168.5.50 tcp  1500  100 aa:bb:cc:dd:ee:01"  # full-6-axis hit id0      -> 0
  "W2  10.1.2.3 192.168.5.50 tcp  1500  100 aa:bb:cc:dd:ee:99"  # MAC-miss of id0          -> NOMATCH
  "W3  8.8.8.8  8.8.8.8       udp  1234  200 aa:bb:cc:dd:ee:02"  # mac+vlan+proto id1       -> 1
  "W4  8.8.8.8  8.8.8.8       udp  1234  200 aa:bb:cc:dd:ee:99"  # MAC-miss of id1          -> NOMATCH
  "W5  8.8.8.8  8.8.8.8       tcp  1234  200 aa:bb:cc:dd:ee:02"  # proto-miss of id1        -> NOMATCH
  "W6  8.8.8.8  8.8.8.8       icmp 0     300 aa:bb:cc:dd:ee:99"  # vlan-only id2 (mac-wild) -> 2
  "W7  10.5.1.1 8.8.8.8       tcp  8080  100 aa:bb:cc:dd:ee:99"  # dst+vlan id3 (mac-wild)  -> 3
  "W8  10.5.1.1 8.8.8.8       tcp  8080  -   aa:bb:cc:dd:ee:99"  # untagged -> dst-only id4 -> 4
  "W9  9.9.9.9  9.9.9.9       tcp  443   -   aa:bb:cc:dd:ee:99"  # port-only id5 (mac-wild) -> 5
  "W10 9.9.9.9  9.9.9.9       udp  1234  -   aa:bb:cc:dd:ee:06"  # mac-only id6             -> 6
  "W11 9.9.9.9  9.9.9.9       udp  1234  -   aa:bb:cc:dd:ee:99"  # MAC-miss of id6          -> NOMATCH
  "W12 1.2.3.4  5.6.7.8       tcp  12345 777 aa:bb:cc:dd:ee:99"  # matches nothing          -> NOMATCH
)

fail=0
saw_negation=0
for spec in "${VECTORS[@]}"; do
    read -r name dst src proto dport vlan mac <<<"${spec}"

    vlan_args=()
    [[ "${vlan}" != "-" ]] && vlan_args=(--vlan "${vlan}")

    expected=$(python3 "${ORACLE}" --ruleset and6 \
                 --dst-ip "${dst}" --src-ip "${src}" --proto "${proto}" --dport "${dport}" \
                 --src-mac "${mac}" "${vlan_args[@]}")
    [[ "${expected}" == "${NOMATCH}" ]] && saw_negation=1

    read -ra before < <(read_rc_all)
    read -r bp bd bm bc < <(read_stats_with_cidr)

    ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" \
        --dst-ip "${dst}" --src-ip "${src}" --proto "${proto}" --dport "${dport}" \
        --src-mac "${mac}" --dst-mac "${MAC_DST}" "${vlan_args[@]}"
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
        echo "  [${name}] dst=${dst} src=${src} ${proto}/${dport} vlan=${vlan} mac=${mac} -> id=${bumped} (oracle=${expected}) ${tag}"
    else
        echo "FAIL[${name}]: datapath matched id=${bumped} but oracle predicted ${expected}" >&2
        echo "          tuple dst=${dst} src=${src} proto=${proto} dport=${dport} vlan=${vlan} mac=${mac}" >&2
        echo "          (disagreement localises a mac/capture/wildcard/acc bug)" >&2
        fail=1
    fi
done

if (( ! saw_negation )); then
    echo "FAIL[sanity]: no NOMATCH (negation-control) vector present in battery" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_AND6_ORACLE_AGREEMENT (oracle ↔ 6-axis datapath agree)"
exit "${fail}"
