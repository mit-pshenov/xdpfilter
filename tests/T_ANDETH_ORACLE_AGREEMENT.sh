#!/bin/bash
# T_ANDETH_ORACLE_AGREEMENT — design §5.54 TestStrategy / §6.74 (MVP-4.14 / S5).
#
# THE OPS canary for the NEW non-IP classification `else` arm + the hoisted
# ethertype axis composed into all THREE dispatch arms. Pre-S5 a non-IP frame
# fell straight to defaults[active] with ZERO classification; S5 adds a full
# symmetric 9-term AND in the non-IP arm (mac/vlan/ethertype real, IP-family
# axes wildcard-only) + an `& (eth_mask|wc_eth)` term in the v4/v6 arms. ONLY a
# real frame against an ethertype/mac rule exercises this — without §6.74 the
# new control-flow ships untested.
#
# For each vector inject ONE real frame and read the matched rule_id via the
# per-rule rule_counters delta (active_idx-aware); assert it equals the
# INDEPENDENT oracle's prediction
#   bitvec_oracle_prod.py --ruleset andeth --ethertype E …
# The oracle is a naive O(N) first-match scan in which the ethertype is the
# family selector (NO bitmask, NO ffsll, NO hoist) — algorithmically independent
# of the datapath, so a disagreement localises an ethertype key/byte-order,
# non-IP-arm, cross-arm-exclusion, or first-match bug.
#
# Vector battery (config_valid_andeth.yaml):
#   E1 arp 0x0806            -> id2 (pure arp in the NEW non-IP arm; headline)
#   E2 0x88b5 from mac ...:11 -> id0 (combined mac+ethertype; first-match TIE id0<id1)
#   E3 0x88b5 from mac ...:99 -> id1 (pure 0x88b5; mac axis excludes id0)
#   E4 ipv4 udp -> 10.1.2.3  -> id3 (ethertype ipv4 AND dst_cidr; v4-arm compose)
#   E5 ipv4 udp -> 10.9.9.9  -> id4 (ethertype-wildcard proto rule on a v4 frame)
#   E6 ipv6 udp              -> id4 (ethertype-wildcard rule still matches v6 —
#                              verdict-identity; the ipv4-ethertype rule id3 is
#                              EXCLUDED from the v6 arm, the cross-arm exclusion)
#   E7 0x9999 non-IP         -> NOMATCH (ethertype-miss -> defaults; negation)
#   E8 ipv6 tcp              -> NOMATCH (proto-miss -> defaults; negation)
#
# Sanity floor:
#   * SMOKE    — apply exit 0 + ethertype_rulesets / ethertype_bitmask_a /
#                wildcard pins exist (E1 is a clean non-IP arp hit).
#   * NEGATION — E7/E8 predict NOMATCH (no rule slot may bump). Proves the
#                machinery registers a "miss"; an always-match arm FAILS here.
#                E6's id4 (NOT id3) also proves cross-arm exclusion.
#
# Maps to: PI-mvp-4.14-NONIP-ARM, PI-mvp-4.14-CROSS-ARM-EXCL, PI-mvp-4.14-ETHKEY,
#          PI-mvp-4.14-AXES9, PI-mvp-4.14-FIRST-MATCH.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_andeth.yaml"
ORACLE="${AND_ORACLE_PROD:-${TEST_DIR}/bitvec/bitvec_oracle_prod.py}"
INJECT_ETH_PY="${INJECT_ETH:-${TEST_DIR}/inject/inject_eth.py}"
INJECT4="${INJECT_IPV4:-${TEST_DIR}/inject/inject_ipv4.py}"
INJECT6="${INJECT_L6:-${TEST_DIR}/inject/inject_l6.py}"
NOMATCH=64

for f in "${FIXTURE}" "${ORACLE}" "${INJECT_ETH_PY}" "${INJECT4}" "${INJECT6}"; do
    [[ -f "${f}" ]] || { echo "FAIL: missing ${f}" >&2; exit 1; }
done

# inject_eth.py + inject_l6.py need scapy; skip (not fail) if absent.
if ! python3 -c 'import scapy' 2>/dev/null; then
    echo "SKIP: scapy not importable (inject_eth.py / inject_l6.py prerequisite)" >&2
    exit 77
fi

# Drop-rule MAC for the combined rule id0, and a NON-matching MAC for id1.
MAC_COMBINED="02:00:00:00:00:11"
MAC_OTHER="02:00:00:00:00:99"
MAC_ARP="02:00:00:00:00:aa"

stderr_file=$(mktemp /tmp/xdpmf-andeth-stderr.XXXXXX)
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
    echo "FAIL[smoke]: apply exit ${rc} (expected 0 — ethertype key must be accepted under v2)" >&2; exit 1
fi
if ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[smoke]: ${PIN_DIR}/rule_counters_a pin missing after apply" >&2; exit 1
fi
for pin in ethertype_rulesets ethertype_bitmask_a wildcard; do
    if ! sudo -n test -e "${PIN_DIR}/${pin}"; then
        echo "FAIL[smoke]: ${PIN_DIR}/${pin} pin missing after apply (S5 ethertype axis not wired)" >&2; exit 1
    fi
done
echo "smoke OK: apply exit 0; rule_counters + ethertype_rulesets + ethertype_bitmask_a + wildcard reachable"

fail=0
saw_negation=0

# probe <name> <expected_id> -- <inject argv (run under NSEXEC)>
# Snapshots rule_counters, injects exactly ONE frame, finds the single rule slot
# that rose by 1 (NONE rising == NOMATCH == defaults fallthrough), asserts it
# equals <expected_id>.
probe() {
    local name="$1" expected="$2"; shift 2  # remaining args = inject argv
    local before after bumped drift=0 id delta bp bd bm bc

    read -ra before < <(read_rc_all)
    read -r bp bd bm bc < <(read_stats_with_cidr)

    ${NSEXEC} "$@"
    wait_for_stats_sum_with_cidr "${IFACE_A}" $(( bp + bd + bm + bc + 1 )) || true

    read -ra after < <(read_rc_all)

    bumped=""
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
        fail=1; return
    fi
    if [[ "${bumped}" == *" "* ]]; then
        echo "FAIL[${name}]: expected exactly ONE slot to bump; got '{${bumped}}' (oracle=${expected})" >&2
        fail=1; return
    fi
    if [[ "${bumped}" == "${expected}" ]]; then
        local tag="OK"; [[ "${expected}" == "${NOMATCH}" ]] && tag="OK(NOMATCH)"
        echo "  [${name}] -> id=${bumped} (oracle=${expected}) ${tag}"
    else
        echo "FAIL[${name}]: datapath matched id=${bumped} but oracle predicted ${expected}" >&2
        echo "          (disagreement localises an ethertype-key / non-IP-arm / cross-arm / first-match bug)" >&2
        fail=1
    fi
}

# Cross-check the oracle's live prediction against the test author's annotation,
# THEN probe the datapath against the oracle.
check() {
    local name="$1" annotated="$2"; shift 2  # remaining = oracle args (no python3/path)
    local predicted
    predicted=$(python3 "${ORACLE}" "$@")
    if [[ "${predicted}" != "${annotated}" ]]; then
        echo "FAIL[${name}]: oracle predicted ${predicted} but annotation says ${annotated}" >&2
        echo "          (fixture/oracle transcription drift — fix RULES_ANDETH or the fixture)" >&2
        fail=1; return 1
    fi
    [[ "${annotated}" == "${NOMATCH}" ]] && saw_negation=1
    return 0
}

# ── E1: arp 0x0806 -> id2 (pure arp in the NEW non-IP classification arm) ───
echo "=== E1 inject arp (0x0806) -> expect id2 (non-IP arm, headline)"
if check E1 2 --ruleset andeth --ethertype arp --src-mac "${MAC_ARP}"; then
    probe E1 2 python3 "${INJECT_ETH_PY}" "${IFACE_B}" "${MAC_ARP}" "${MAC_DST}" 0x0806
fi

# ── E2: 0x88b5 from the combined-rule MAC -> id0 (TIE id0<id1) ──────────────
echo "=== E2 inject 0x88b5 from mac ${MAC_COMBINED} -> expect id0 (combined mac+ethertype; first-match tie)"
if check E2 0 --ruleset andeth --ethertype 0x88b5 --src-mac "${MAC_COMBINED}"; then
    probe E2 0 python3 "${INJECT_ETH_PY}" "${IFACE_B}" "${MAC_COMBINED}" "${MAC_DST}" 0x88b5
fi

# ── E3: 0x88b5 from a NON-matching MAC -> id1 (pure 0x88b5; id0 excluded) ────
echo "=== E3 inject 0x88b5 from mac ${MAC_OTHER} -> expect id1 (pure 0x88b5; mac axis excludes id0)"
if check E3 1 --ruleset andeth --ethertype 0x88b5 --src-mac "${MAC_OTHER}"; then
    probe E3 1 python3 "${INJECT_ETH_PY}" "${IFACE_B}" "${MAC_OTHER}" "${MAC_DST}" 0x88b5
fi

# ── E4: ipv4 udp -> 10.1.2.3 -> id3 (ethertype ipv4 AND dst_cidr; v4 arm) ────
echo "=== E4 inject ipv4 udp dst=10.1.2.3 -> expect id3 (ethertype ipv4 + dst_cidr compose, v4 arm)"
if check E4 3 --ruleset andeth --ethertype ipv4 --dst-ip 10.1.2.3 --src-ip 203.0.113.9 --proto udp --dport 53; then
    probe E4 3 python3 "${INJECT4}" "${IFACE_B}" "${MAC_OTHER}" "${MAC_DST}" 203.0.113.9 10.1.2.3
fi

# ── E5: ipv4 udp -> 10.9.9.9 -> id4 (ethertype-wildcard proto rule on v4) ────
echo "=== E5 inject ipv4 udp dst=10.9.9.9 -> expect id4 (ethertype-wildcard proto rule, v4)"
if check E5 4 --ruleset andeth --ethertype ipv4 --dst-ip 10.9.9.9 --src-ip 203.0.113.9 --proto udp --dport 53; then
    probe E5 4 python3 "${INJECT4}" "${IFACE_B}" "${MAC_OTHER}" "${MAC_DST}" 203.0.113.9 10.9.9.9
fi

# ── E6: ipv6 udp -> id4 (ethertype-wildcard rule matches v6; id3 excluded) ──
echo "=== E6 inject ipv6 udp -> expect id4 (verdict-identity; ipv4-ethertype rule id3 excluded from v6 arm)"
if check E6 4 --ruleset andeth --ethertype ipv6 --dst-ip6 2001:db8::1 --src-ip6 2001:db8:5::9 --proto udp --dport 53; then
    probe E6 4 python3 "${INJECT6}" "${IFACE_B}" \
        --dst-ip 2001:db8::1 --src-ip 2001:db8:5::9 --proto udp --dport 53 \
        --dst-mac "${MAC_DST}" --src-mac "${MAC_OTHER}"
fi

# ── E7: 0x9999 non-IP -> NOMATCH (ethertype-miss -> defaults; NEGATION) ─────
echo "=== E7 inject 0x9999 non-IP -> expect NOMATCH (ethertype-miss -> defaults; negation control)"
if check E7 "${NOMATCH}" --ruleset andeth --ethertype 0x9999 --src-mac "${MAC_OTHER}"; then
    probe E7 "${NOMATCH}" python3 "${INJECT_ETH_PY}" "${IFACE_B}" "${MAC_OTHER}" "${MAC_DST}" 0x9999
fi

# ── E8: ipv6 tcp -> NOMATCH (proto-miss -> defaults; NEGATION) ──────────────
echo "=== E8 inject ipv6 tcp -> expect NOMATCH (proto-miss -> defaults; negation control)"
if check E8 "${NOMATCH}" --ruleset andeth --ethertype ipv6 --dst-ip6 2001:db8::1 --src-ip6 2001:db8:5::9 --proto tcp --dport 80; then
    probe E8 "${NOMATCH}" python3 "${INJECT6}" "${IFACE_B}" \
        --dst-ip 2001:db8::1 --src-ip 2001:db8:5::9 --proto tcp --dport 80 \
        --dst-mac "${MAC_DST}" --src-mac "${MAC_OTHER}"
fi

if (( ! saw_negation )); then
    echo "FAIL[sanity]: no NOMATCH (negation-control) vector present in battery" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_ANDETH_ORACLE_AGREEMENT (oracle ↔ 9-axis ethertype datapath agree across all 3 arms)"
exit "${fail}"
