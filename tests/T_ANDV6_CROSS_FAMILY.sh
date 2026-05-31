#!/bin/bash
# T_ANDV6_CROSS_FAMILY — design §5.53 TestStrategy / §6.73 — the Q2 proof.
#
# THE direct test of D-mvp-4.13-Q2 (the single highest-risk semantic in S4):
# the SYMMETRIC 8-term AND must exclude cross-family rules in BOTH directions.
#   * a v4-only rule must FIRE on a v4 frame (NOT spuriously zeroed by the v4
#     arm's NEW `& wc_dst6 & wc_src6` terms — PI-mvp-4.13-IPV4-VERDICT), AND
#   * a v4-only rule must NOT FIRE on a v6 frame (excluded by the v6 arm's
#     `& wc_dst` term, since a v4-constrained rule is absent from wc_dst —
#     PI-mvp-4.13-CROSS-FAMILY), while the v6-only rule DOES fire.
#
# Fixture config_valid_andv6.yaml (DUAL-USE; default_action: drop):
#   id 1 : dst_cidr6 2001:db8:2::/48   PASS  (v6-only — fires on v6, never on v4)
#   id 2 : dst_cidr  10.1.0.0/16       DROP  (v4-only — fires on v4, never on v6)
# (ids 0/3 are unrelated to the families probed here.)
#
# Steps / observable outcome (ALL must hold):
#   (a) SMOKE: apply exit 0; rule_counters pin exists.
#   (b) v4-only rule NOT spuriously dropped: inject an IPv4 frame to 10.1.2.3
#       (∈ id2 10.1.0.0/16) → id2 fires DROP: rule_counters[2] == 1; STAT_DROP_DENY
#       delta == 1; rule_counters[1] == 0. If the v4 arm's new dst6/src6 terms had
#       zeroed id2, the verdict would flip (id2 stops matching its OWN v4 traffic).
#   (c) cross-family exclusion: inject an IPv6 frame to 2001:db8:2::1 (∈ id1
#       2001:db8:2::/48) over TCP → id1 fires PASS: rule_counters[1] == 1; a
#       PASS-class stat rises by 1; **rule_counters[2] == 0** (the v4-only DROP
#       rule did NOT fire on the v6 frame — the cross-family exclusion); NO new
#       DROP_DENY.
#
# Sanity floor:
#   * SMOKE    — step (a).
#   * NEGATION — step (c)'s rule_counters[2]==0 IS a strong negation control: a
#                v4-only DROP rule that WRONGLY matched the v6 frame would bump
#                slot 2 and DROP — proving the v6 arm's `& wc_dst` term excludes
#                the wrong-family rule. (A naive arm that ignored cross-family
#                wildcards would FAIL here.)
#
# Maps to: PI-mvp-4.13-CROSS-FAMILY, PI-mvp-4.13-IPV4-VERDICT.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_andv6.yaml"
INJECT4="${INJECT_IPV4:-${TEST_DIR}/inject/inject_ipv4.py}"
INJECT6="${INJECT_L6:-${TEST_DIR}/inject/inject_l6.py}"
[[ -f "${FIXTURE}"  ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }
[[ -f "${INJECT4}"  ]] || { echo "FAIL: missing injector ${INJECT4}" >&2; exit 1; }
[[ -f "${INJECT6}"  ]] || { echo "FAIL: missing injector ${INJECT6}" >&2; exit 1; }

if ! python3 -c 'import scapy' 2>/dev/null; then
    echo "SKIP: scapy not importable (inject_l6.py prerequisite)" >&2
    exit 77
fi

SRC_MAC="02:00:00:00:00:aa"

stderr_file=$(mktemp /tmp/xdpmf-crossfam6-stderr.XXXXXX)
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
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
echo "stats baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0}"

fail=0

# ── (b) v4-only DROP rule id2 fires on a v4 frame (NOT zeroed by v6 terms) ──
echo "=== (b) inject IPv4 dst=10.1.2.3 (∈ id2 10.1.0.0/16 DROP) → expect DROP via id2"
${NSEXEC} python3 "${INJECT4}" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" 203.0.113.9 10.1.2.3
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true
read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
rc1=$(read_rc_slot 1); rc2=$(read_rc_slot 2)
echo "rule_counters: [1]=${rc1} [2]=${rc2}; DROP_DENY delta=$((d1-d0))"
if [[ "${rc2}" != "1" ]]; then
    echo "FAIL[b1]: rule_counters[2]='${rc2}' (expected 1 — v4-only rule must fire on v4)" >&2
    echo "          bug shape: the v4 arm's new & wc_dst6 & wc_src6 terms ZEROED the v4-only rule" >&2
    fail=1
fi
if (( d1 - d0 != 1 )); then
    echo "FAIL[b2]: STAT_DROP_DENY delta=$((d1-d0)) (expected 1 — id2 is DROP)" >&2
    echo "          a non-DROP here means id2 stopped matching its own v4 traffic (PI-IPV4-VERDICT)" >&2
    fail=1
fi
if [[ "${rc1}" != "0" ]]; then
    echo "FAIL[b3]: rule_counters[1]='${rc1}' (expected 0 — v6-only rule must NOT fire on v4)" >&2; fail=1
fi

# ── (c) cross-family: v6 frame hits id1 PASS; v4-only id2 must NOT fire ─────
echo "=== (c) inject IPv6 dst=2001:db8:2::1 (∈ id1 2001:db8:2::/48 PASS) over TCP → expect PASS via id1, id2 silent"
${NSEXEC} python3 "${INJECT6}" "${IFACE_B}" \
    --dst-ip 2001:db8:2::1 --src-ip 2001:db8:aaaa::9 --proto tcp --dport 80 \
    --dst-mac "${MAC_DST}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true
read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
rc1=$(read_rc_slot 1); rc2=$(read_rc_slot 2)
echo "rule_counters: [1]=${rc1} [2]=${rc2}; PASS delta=$((p2-p1)) PASS_CIDR delta=$((c2-c1)) DROP_DENY delta=$((d2-d1))"
if [[ "${rc1}" != "1" ]]; then
    echo "FAIL[c1]: rule_counters[1]='${rc1}' (expected 1 — v6-only PASS rule must fire on v6)" >&2; fail=1
fi
if [[ "${rc2}" != "1" ]]; then
    echo "FAIL[c2]: rule_counters[2]='${rc2}' (expected STILL 1 — v4-only DROP rule MUST NOT fire on the v6 frame)" >&2
    echo "          bug shape: the v6 arm's & wc_dst term failed to exclude the v4-constrained rule" >&2
    echo "          (cross-family exclusion violated — D-mvp-4.13-Q2 / PI-CROSS-FAMILY)" >&2
    fail=1
fi
if (( (p2 - p1) + (c2 - c1) != 1 )); then
    echo "FAIL[c3]: PASS-class delta=$(( (p2-p1)+(c2-c1) )) (expected 1 — id1 is PASS)" >&2; fail=1
fi
if (( d2 - d1 != 0 )); then
    echo "FAIL[c4]: STAT_DROP_DENY delta=$((d2-d1)) (expected 0 — a v6 frame must NOT hit the v4-only DROP)" >&2
    echo "          a DROP here means the v4-only rule spuriously matched the v6 frame" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_ANDV6_CROSS_FAMILY (symmetric 8-term AND excludes cross-family both ways)"
exit "${fail}"
