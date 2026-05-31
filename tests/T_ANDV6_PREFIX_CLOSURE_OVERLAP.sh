#!/bin/bash
# T_ANDV6_PREFIX_CLOSURE_OVERLAP — design §5.53 TestStrategy / §6.72 — guard #23.
#
# THE #1-bug-class canary at 128 bits: v6 prefix-closure cover-direction +
# first-match-by-id across NON-byte-aligned and 64-bit-LIMB-crossing prefix
# lengths. The load-bearing correctness test of the slice (PI-mvp-4.13-CLOSURE6).
#
# Fixture config_overlap_lowid6.yaml (schema_version: 2, default_action: pass):
#   id 0 : dst_cidr6 2001:db8:0:100::/68   DROP  (covering /68, LOWER id — wins)
#   id 1 : dst_cidr6 2001:db8::/40         PASS  (BROADEST cover, mid id)
#   id 3 : dst_cidr6 2001:db8:0:100::/127  PASS  (MOST-specific, HIGHER id)
#
# A packet to 2001:db8:0:100::1 is in ALL THREE prefixes (/40, /68, /127). The
# correct verdict is DROP via id0 — the LOWEST matching id wins, NOT the
# most-specific id3. This is producible ONLY if:
#   (a) close_prefixes6 stored the covering bits (id0 /68, id1 /40) INTO the
#       /127 LPM entry — cover-direction CORRECT at 128 bits incl. the mid-limb
#       /68 boundary, AND
#   (b) ffsll(acc) picks the lowest set bit.
# A backwards closure, a most-specific-wins bug, OR a byte-order/limb-boundary
# mask error FLIPS the verdict to PASS via id3 → this test FAILS loudly.
#
# Steps / observable outcome (ALL must hold):
#   (a) SMOKE: apply exit 0; rule_counters + dst6_rulesets pins exist.
#   (b) LOAD-BEARING: inject v6 dst=2001:db8:0:100::1 → DROP via id0:
#       rule_counters[0] == 1; STAT_DROP_DENY delta == 1;
#       rule_counters[3] == 0 (id3 must NOT win); rule_counters[1] == 0.
#   (c) broader-cover-only: inject v6 dst=2001:db8:5::1 (∈ /40 only — byte 5
#       differs from /68) → PASS via id1: rule_counters[1] == 1; a PASS-class
#       stat (STAT_PASS or STAT_PASS_CIDR) rises by 1; NO DROP_DENY; id0 STAYS 1.
#       Proves the closure does NOT over-propagate more-specific bits backwards.
#   (d) NEGATION CONTROL: inject v6 dst=2001:dead::1 (matches NO rule) →
#       defaults PASS: NO rule_counters slot bumps; a PASS-class stat rises by 1.
#       Proves the machinery registers a clean miss (not an always-match closure).
#
# Sanity-floor smoke: step (a). Negation control: step (d).
#
# Maps to: PI-mvp-4.13-CLOSURE6, PI-mvp-4.13-FIRST-MATCH, PI-mvp-4.13-V6KEY.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_overlap_lowid6.yaml"
INJECT="${INJECT_L6:-${TEST_DIR}/inject/inject_l6.py}"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }
[[ -f "${INJECT}"  ]] || { echo "FAIL: missing injector ${INJECT}" >&2; exit 1; }

if ! python3 -c 'import scapy' 2>/dev/null; then
    echo "SKIP: scapy not importable (inject_l6.py prerequisite)" >&2
    exit 77
fi

stderr_file=$(mktemp /tmp/xdpmf-overlap6-stderr.XXXXXX)
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
# Inject one v6 frame to the given dst6; src6/proto irrelevant (all rules are
# dst6-only). tcp avoids any incidental proto-axis interaction.
inject6() {
    ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" \
        --dst-ip "$1" --src-ip "2001:db8:aaaa::9" --proto tcp --dport 80 \
        --dst-mac "${MAC_DST}"
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
sudo -n test -e "${PIN_DIR}/dst6_rulesets" \
    || { echo "FAIL[a]: ${PIN_DIR}/dst6_rulesets pin missing (S4 v6 axis not wired)" >&2; exit 1; }
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "stats baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"

fail=0

# ── (b) LOAD-BEARING: 2001:db8:0:100::1 → DROP via id0 (lowest), NOT id3 ──
echo "=== (b) inject dst6=2001:db8:0:100::1 (∈ /68 id0, /40 id1, /127 id3) → expect DROP via id0"
inject6 2001:db8:0:100::1
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true
read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
rc0=$(read_rc_slot 0); rc1=$(read_rc_slot 1); rc3=$(read_rc_slot 3)
echo "rule_counters: [0]=${rc0} [1]=${rc1} [3]=${rc3}; DROP_DENY delta=$((d1-d0)) PASS_CIDR delta=$((c1-c0))"
if [[ "${rc0}" != "1" ]]; then
    echo "FAIL[b1]: rule_counters[0]='${rc0}' (expected 1 — lowest-id covering rule must win)" >&2
    echo "          bug shape: backwards v6 prefix-closure OR most-specific-wins OR limb-boundary mask error" >&2
    fail=1
fi
if [[ "${rc3}" != "0" ]]; then
    echo "FAIL[b2]: rule_counters[3]='${rc3}' (expected 0 — more-specific HIGHER id must NOT win)" >&2
    echo "          bug shape: most-specific-wins instead of first-match-by-id" >&2
    fail=1
fi
if [[ "${rc1}" != "0" ]]; then
    echo "FAIL[b3]: rule_counters[1]='${rc1}' (expected 0 — id0 lower than id1)" >&2; fail=1
fi
if (( d1 - d0 != 1 )); then
    echo "FAIL[b4]: STAT_DROP_DENY delta=$((d1-d0)) (expected 1 — id0 is DROP)" >&2
    echo "          a PASS here means id3 won (v6 closure / first-match bug)" >&2
    fail=1
fi

# ── (c) broader-cover-only: 2001:db8:5::1 ∈ /40 only → PASS via id1 ─────────
echo "=== (c) inject dst6=2001:db8:5::1 (∈ /40 id1 only; byte 5 differs from /68) → expect PASS via id1"
inject6 2001:db8:5::1
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true
read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
rc1=$(read_rc_slot 1); rc0=$(read_rc_slot 0)
if [[ "${rc1}" != "1" ]]; then
    echo "FAIL[c1]: rule_counters[1]='${rc1}' (expected 1 — broader cover id1)" >&2; fail=1
fi
if (( (p2 - p1) + (c2 - c1) != 1 )); then
    echo "FAIL[c2]: PASS-class delta=$(( (p2-p1)+(c2-c1) )) (expected 1 — id1 is PASS)" >&2; fail=1
fi
if (( d2 - d1 != 0 )); then
    echo "FAIL[c3]: STAT_DROP_DENY delta=$((d2-d1)) (expected 0 — id1 PASS, closure over-propagated?)" >&2; fail=1
fi
if [[ "${rc0}" != "1" ]]; then
    echo "FAIL[c4]: rule_counters[0]='${rc0}' drifted (expected STILL 1)" >&2; fail=1
fi

# ── (d) NEGATION CONTROL: 2001:dead::1 matches nothing → defaults PASS ──────
echo "=== (d) NEGATION: inject dst6=2001:dead::1 (matches NO rule) → expect defaults PASS, no rule bump"
inject6 2001:dead::1
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + c2 + 1 )) || true
read -r p3 d3 m3 c3 < <(read_stats_with_cidr)
rc0=$(read_rc_slot 0); rc1=$(read_rc_slot 1); rc3=$(read_rc_slot 3)
if [[ "${rc0}" != "1" || "${rc1}" != "1" || "${rc3}" != "0" ]]; then
    echo "FAIL[d1]: a rule_counters slot moved on a no-match frame ([0]=${rc0} [1]=${rc1} [3]=${rc3})" >&2
    echo "          expected [0]=1 [1]=1 [3]=0 (unchanged) — v6 closure must not always-match" >&2
    fail=1
fi
if (( (p3 - p2) + (c3 - c2) != 1 )); then
    echo "FAIL[d2]: PASS-class delta=$(( (p3-p2)+(c3-c2) )) (expected 1 — defaults PASS fallthrough)" >&2; fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_ANDV6_PREFIX_CLOSURE_OVERLAP"
exit "${fail}"
