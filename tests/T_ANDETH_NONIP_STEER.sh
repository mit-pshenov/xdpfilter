#!/bin/bash
# T_ANDETH_NONIP_STEER — design §5.54 TestStrategy / §6.75 (MVP-4.14 / S5).
#
# THE headline coarse non-IP steering proof + the cross-arm exclusion negation.
# This is the highest-value semantic in the slice: a pure `ethertype: arp` DROP
# rule must DROP a non-IP ARP frame (the previously-defaults non-IP arm now
# classifies + drops) WHILE that same rule must NOT drop an IPv4 frame (its bit
# is excluded from the v4 arm — absent from both eth_mask[0x0800] and wc_eth).
#
# Fixture config_steer_arp_drop.yaml (default_action: pass):
#   id 0 : ethertype arp (0x0806)   DROP
#   id 1 : ethertype 0x88b5         DROP
#
# Steps / observable outcome (ALL must hold):
#   (a) SMOKE: apply exit 0; rule_counters + ethertype_rulesets pins exist.
#   (b) non-IP DROP (headline): inject an ARP frame -> id0 fires:
#       rule_counters[0] delta == 1; STAT_DROP_DENY delta == 1.
#   (c) second non-IP DROP: inject a 0x88b5 frame -> id1 fires:
#       rule_counters[1] delta == 1; STAT_DROP_DENY delta == 1.
#   (d) cross-arm exclusion (NEGATION): inject an IPv4 frame -> NOT dropped by
#       the ethertype rules: STAT_DROP_DENY delta == 0; a PASS-class stat rises
#       by 1 (default pass); rule_counters[0] and [1] unchanged.
#
# Sanity floor:
#   * SMOKE    — step (a).
#   * NEGATION — step (d): an IPv4 frame MUST NOT be dropped by the arp/0x88b5
#                rules. A datapath that (wrongly) let an ethertype rule leak into
#                the v4 arm would bump slot 0/1 and DROP — this test catches it.
#                Steps (b)/(c) are the positive "must-drop" controls.
#
# Maps to: PI-mvp-4.14-NONIP-ARM, PI-mvp-4.14-CROSS-ARM-EXCL.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_steer_arp_drop.yaml"
INJECT_ETH_PY="${INJECT_ETH:-${TEST_DIR}/inject/inject_eth.py}"
INJECT4="${INJECT_IPV4:-${TEST_DIR}/inject/inject_ipv4.py}"

for f in "${FIXTURE}" "${INJECT_ETH_PY}" "${INJECT4}"; do
    [[ -f "${f}" ]] || { echo "FAIL: missing ${f}" >&2; exit 1; }
done

# inject_eth.py needs scapy; skip (not fail) if absent.
if ! python3 -c 'import scapy' 2>/dev/null; then
    echo "SKIP: scapy not importable (inject_eth.py prerequisite)" >&2
    exit 77
fi

SRC_MAC="02:00:00:00:00:aa"

stderr_file=$(mktemp /tmp/xdpmf-andethsteer-stderr.XXXXXX)
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
read_rc_slot() {
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" \
        "$(rule_counters_active_pin)" "$1"
}

# ── (a) apply + smoke ────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
cat "${stderr_file}" >&2 || true
if [[ "${rc}" -ne 0 ]]; then echo "FAIL[a]: apply exit ${rc} (expected 0)" >&2; exit 1; fi
sudo -n test -e "${PIN_DIR}/rule_counters_a" \
    || { echo "FAIL[a]: ${PIN_DIR}/rule_counters_a pin missing" >&2; exit 1; }
sudo -n test -e "${PIN_DIR}/ethertype_rulesets" \
    || { echo "FAIL[a]: ${PIN_DIR}/ethertype_rulesets pin missing (S5 axis not wired)" >&2; exit 1; }
echo "smoke OK: apply exit 0; rule_counters + ethertype_rulesets reachable"

fail=0

# ── (b) ARP frame -> id0 DROP (headline: non-IP arm classifies + drops) ─────
echo "=== (b) inject ARP (0x0806) src_mac=${SRC_MAC} -> expect DROP via id0"
b0=$(read_rc_slot 0)
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
${NSEXEC} python3 "${INJECT_ETH_PY}" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" 0x0806
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true
b1=$(read_rc_slot 0)
read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
echo "  rule_counters[0] delta=$(( b1 - b0 )); DROP_DENY delta=$(( d1 - d0 ))"
if (( b1 - b0 != 1 )); then
    echo "FAIL[b1]: rule_counters[0] delta=$(( b1 - b0 )) (expected 1 — arp rule must fire in the NEW non-IP arm)" >&2
    fail=1
fi
if (( d1 - d0 != 1 )); then
    echo "FAIL[b2]: STAT_DROP_DENY delta=$(( d1 - d0 )) (expected 1 — id0 is DROP)" >&2
    echo "          a non-DROP means the non-IP classification arm did not drop the ARP frame" >&2
    fail=1
fi

# ── (c) 0x88b5 frame -> id1 DROP (second non-IP drop vector) ────────────────
echo "=== (c) inject 0x88b5 src_mac=${SRC_MAC} -> expect DROP via id1"
e0=$(read_rc_slot 1)
read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
${NSEXEC} python3 "${INJECT_ETH_PY}" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" 0x88b5
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + c2 + 1 )) || true
e1=$(read_rc_slot 1)
read -r p3 d3 m3 c3 < <(read_stats_with_cidr)
echo "  rule_counters[1] delta=$(( e1 - e0 )); DROP_DENY delta=$(( d3 - d2 ))"
if (( e1 - e0 != 1 )); then
    echo "FAIL[c1]: rule_counters[1] delta=$(( e1 - e0 )) (expected 1 — 0x88b5 rule must fire)" >&2; fail=1
fi
if (( d3 - d2 != 1 )); then
    echo "FAIL[c2]: STAT_DROP_DENY delta=$(( d3 - d2 )) (expected 1 — id1 is DROP)" >&2; fail=1
fi

# ── (d) IPv4 frame -> NOT dropped by the ethertype rules (cross-arm excl.) ──
echo "=== (d) inject IPv4 udp -> expect NOT dropped (defaults=pass; cross-arm exclusion; negation)"
f0_0=$(read_rc_slot 0); f0_1=$(read_rc_slot 1)
read -r p4 d4 m4 c4 < <(read_stats_with_cidr)
${NSEXEC} python3 "${INJECT4}" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" 203.0.113.9 198.51.100.7
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p4 + d4 + m4 + c4 + 1 )) || true
f1_0=$(read_rc_slot 0); f1_1=$(read_rc_slot 1)
read -r p5 d5 m5 c5 < <(read_stats_with_cidr)
echo "  rule_counters[0] delta=$(( f1_0 - f0_0 )) [1] delta=$(( f1_1 - f0_1 )); DROP_DENY delta=$(( d5 - d4 )); PASS-class delta=$(( (p5-p4)+(c5-c4) ))"
if (( d5 - d4 != 0 )); then
    echo "FAIL[d1]: STAT_DROP_DENY delta=$(( d5 - d4 )) (expected 0 — the ethertype rules must NOT drop a v4 frame)" >&2
    echo "          bug shape: an ethertype DROP rule leaked into the v4 arm (cross-arm exclusion violated)" >&2
    echo "          (PI-mvp-4.14-CROSS-ARM-EXCL / D-mvp-4.14-Q1)" >&2
    fail=1
fi
if (( f1_0 - f0_0 != 0 )) || (( f1_1 - f0_1 != 0 )); then
    echo "FAIL[d2]: an ethertype rule_counters slot bumped on a v4 frame ([0] d=$(( f1_0 - f0_0 )) [1] d=$(( f1_1 - f0_1 )); expected 0/0)" >&2
    fail=1
fi
if (( (p5 - p4) + (c5 - c4) != 1 )); then
    echo "FAIL[d3]: PASS-class delta=$(( (p5-p4)+(c5-c4) )) (expected 1 — the v4 frame falls to default pass)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_ANDETH_NONIP_STEER (ethertype:arp drops a non-IP frame; excluded from the v4 arm)"
exit "${fail}"
