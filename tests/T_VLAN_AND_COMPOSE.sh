#!/bin/bash
# T_VLAN_AND_COMPOSE — design §6.67 (MVP-4.5 / §5.45).
#
# Proves the NEW vlan axis is an exact-HASH bit-vector axis intersected (AND)
# with the other axes — NOT unioned (PI-mvp-4.5-VLAN, PI-mvp-4.5-AND5) — AND
# that the 802.1Q tag actually reached XDP (guard #22 anti-vacuity).
#
# Fixture config_valid_and5.yaml (schema_version: 2):
#   id 0 : dst 10.1.0.0/16 AND src 192.168.5.0/24 AND tcp AND port 1000-2000
#          AND vlan 100                                               pass  (FULL 5-axis)
#   id 3 : dst 10.5.0.0/16 AND vlan 100                               pass  (dst + vlan)
#   id 4 : dst 10.5.0.0/16                                            pass  (dst-only; vlan-wildcard)
#   ... (see fixture)
#
# Steps / observable outcome (ALL must hold):
#   (a) SMOKE: apply exit 0; vlan_rulesets + wildcard pins exist; the active
#       vlan inner is non-empty (≥1 vlan key after apply).
#   (b) POSITIVE + ANTI-VACUITY: a frame TAGGED vlan 100 on id0's other axes
#       (dst=10.1.2.3 src=192.168.5.50 tcp dport=1500) → id0 hit:
#       rule_counters[0] == 1. This step is ALSO the guard-#22 anti-vacuity
#       control: id0 fires ONLY if the tag reached XDP — a kernel that stripped
#       the tag (offload) would present an untagged frame ⇒ vlan_mask=0 ⇒ id0
#       cleared ⇒ NO bump here (the step FAILS, loudly, instead of passing
#       vacuously).
#   (c) STRIP DIFFERENTIAL: the SAME 5-tuple sent UNTAGGED must NOT hit id0
#       (has_vlan=0 ⇒ vlan_mask=0): rule_counters[0] STAYS 1. Confirms the (b)
#       hit was the captured tag, not an always-match.
#   (d) VLAN-MISS NEGATION: the SAME 5-tuple TAGGED with a DIFFERENT vlan 999
#       must NOT hit id0 (vlan bit cleared from acc); no other rule covers this
#       tuple → matches NOTHING (NOMATCH/defaults): rule_counters[0] STAYS 1.
#       A datapath that UNIONS / ignores vlan would re-hit id0 → this FAILS it.
#   (e) FALLS-TO-VLAN-WILDCARD: on the id3/id4 shared dst (10.5.1.1, tcp 8080),
#       TAGGED vlan 100 → id3 hit (dst+vlan, lower id wins the tie); the SAME
#       frame TAGGED vlan 999 → id3's vlan bit cleared → routes to the
#       vlan-wildcard rule id4: rule_counters[4] == 1. Proves the vlan axis
#       intersects and the wildcard survival path works.
#
# Sanity floor: smoke = step (a). Negation control = step (d) — a vlan
# mismatch of an all-axes rule MUST NOT fire that rule. Anti-vacuity (guard
# #22) = step (b)+(c) differential (tag captured vs stripped).
#
# Guard #22: NIC VLAN offload disabled best-effort in setup so the kernel does
# not strip the 802.1Q tag before XDP runs (D-mvp-4.5-OFFLOAD; §5.41 precedent).
#
# Maps to: PI-mvp-4.5-VLAN, PI-mvp-4.5-VLAN-CAPTURE, PI-mvp-4.5-AND5,
#          PI-mvp-4.5-WILDCARD, PI-mvp-4.5-OFFLOAD.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid_and5.yaml"
INJECT="${INJECT_L4:-${TEST_DIR}/inject/inject_l4.py}"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }
[[ -f "${INJECT}"  ]] || { echo "FAIL: missing injector ${INJECT}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-vlanand-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

# ── Guard #22: disable NIC VLAN offload (best-effort) ─────────────────────
# Interfaces live inside the netns, so ethtool runs via ${NSEXEC}. If the
# kernel strips/inserts the tag in the driver before XDP, the vlan assertion
# would be VACUOUS (D-mvp-4.5-OFFLOAD).
${NSEXEC} ethtool -K "${IFACE_A}" rxvlan off txvlan off 2>/dev/null || true
${NSEXEC} ethtool -K "${IFACE_B}" rxvlan off txvlan off 2>/dev/null || true

# ── active_idx-aware readers (§5.34/§5.35 topology) ──────────────────────
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
vlan_inner_active_pin() {
    case "$(read_active_idx)" in
        1) echo "${PIN_DIR}/vlan_bitmask_b" ;;
        *) echo "${PIN_DIR}/vlan_bitmask_a" ;;
    esac
}
read_rc_slot() {
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" \
        "$(rule_counters_active_pin)" "$1"
}
# inject <dst> <src> <proto> <dport> [vlan]
inject() {
    local dst="$1" src="$2" proto="$3" dport="$4" vlan="${5:-}"
    if [[ -n "${vlan}" ]]; then
        ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" \
            --dst-ip "${dst}" --src-ip "${src}" --proto "${proto}" --dport "${dport}" \
            --dst-mac "${MAC_DST}" --vlan "${vlan}"
    else
        ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" \
            --dst-ip "${dst}" --src-ip "${src}" --proto "${proto}" --dport "${dport}" \
            --dst-mac "${MAC_DST}"
    fi
}
# pump one frame through and wait for the 4-col stats sum to advance by 1
pump() {
    local p d m c
    read -r p d m c < <(read_stats_with_cidr)
    inject "$@"
    wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p + d + m + c + 1 )) || true
}

# ── (a) apply + smoke ────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
cat "${stderr_file}" >&2 || true
echo "rc=${rc}"

fail=0
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[a1]: apply exit ${rc} (expected 0)" >&2
    exit 1
fi
for pin in vlan_rulesets ruleset_state; do
    if ! sudo -n test -e "${PIN_DIR}/${pin}"; then
        echo "FAIL[a2]: expected pin ${PIN_DIR}/${pin} missing (§5.45 DataStructures)" >&2
        fail=1
    fi
done
vlan_entries=$(sudo -n bpftool map dump pinned "$(vlan_inner_active_pin)" --json 2>/dev/null \
               | jq 'length' 2>/dev/null || echo 0)
if [[ -z "${vlan_entries}" || "${vlan_entries}" -lt 1 ]]; then
    echo "FAIL[a3]: active vlan inner empty (expected >=1 vlan key after apply)" >&2
    fail=1
else
    echo "smoke OK: vlan inner has ${vlan_entries} key(s)"
fi
for slot in 0 3 4; do
    v=$(read_rc_slot "${slot}")
    [[ "${v}" == "0" ]] || { echo "FAIL[a4]: rule_counters[${slot}]='${v}' baseline (expected 0)" >&2; fail=1; }
done

# ── (b) TAGGED vlan 100 on id0's other axes → id0 hit (+ anti-vacuity) ────
echo "=== (b) inject TAGGED vlan100 dst=10.1.2.3 src=192.168.5.50 tcp/1500 (id0 full-5-axis)"
pump 10.1.2.3 192.168.5.50 tcp 1500 100
rc0=$(read_rc_slot 0)
if [[ "${rc0}" != "1" ]]; then
    echo "FAIL[b1]: rule_counters[0]='${rc0}' (expected 1 — vlan100 frame matches the vlan:100 rule id0)" >&2
    echo "          guard #22: if this is 0, the tag may have been STRIPPED before XDP (offload on?)" >&2
    fail=1
fi

# ── (c) STRIP DIFFERENTIAL: same 5-tuple UNTAGGED → must NOT hit id0 ──────
echo "=== (c) inject UNTAGGED dst=10.1.2.3 src=192.168.5.50 tcp/1500 (has_vlan=0)"
pump 10.1.2.3 192.168.5.50 tcp 1500
rc0=$(read_rc_slot 0)
if [[ "${rc0}" != "1" ]]; then
    echo "FAIL[c1]: rule_counters[0]='${rc0}' bumped on an UNTAGGED frame (expected STILL 1)" >&2
    echo "          bug shape: vlan-constrained id0 fired on has_vlan=0 (vlan axis not ANDed)" >&2
    fail=1
fi

# ── (d) VLAN-MISS NEGATION: same 5-tuple TAGGED vlan 999 → must NOT hit id0 ─
echo "=== (d) NEGATION: inject TAGGED vlan999 dst=10.1.2.3 src=192.168.5.50 tcp/1500 (wrong vid)"
pump 10.1.2.3 192.168.5.50 tcp 1500 999
rc0=$(read_rc_slot 0)
if [[ "${rc0}" != "1" ]]; then
    echo "FAIL[d1]: rule_counters[0]='${rc0}' bumped on a vlan999 frame (expected STILL 1)" >&2
    echo "          bug shape: datapath UNIONS / ignores the vlan axis instead of ANDing it" >&2
    fail=1
fi

# ── (e) FALLS-TO-VLAN-WILDCARD: id3 (dst+vlan) vs id4 (dst-only) ──────────
echo "=== (e) inject TAGGED vlan100 dst=10.5.1.1 tcp/8080 (id3 dst+vlan; id4 also matches → tie id3)"
pump 10.5.1.1 8.8.8.8 tcp 8080 100
rc3=$(read_rc_slot 3)
if [[ "${rc3}" != "1" ]]; then
    echo "FAIL[e1]: rule_counters[3]='${rc3}' (expected 1 — vlan100 dst-10.5 hits id3, lower id wins the tie)" >&2
    fail=1
fi
echo "=== (e) inject TAGGED vlan999 dst=10.5.1.1 tcp/8080 (id3 vlan cleared → vlan-wildcard id4)"
pump 10.5.1.1 8.8.8.8 tcp 8080 999
rc3=$(read_rc_slot 3)
rc4=$(read_rc_slot 4)
if [[ "${rc3}" != "1" ]]; then
    echo "FAIL[e2]: rule_counters[3]='${rc3}' bumped on vlan999 (expected STILL 1 — id3 requires vlan100)" >&2
    fail=1
fi
if [[ "${rc4}" != "1" ]]; then
    echo "FAIL[e3]: rule_counters[4]='${rc4}' (expected 1 — vlan999 routes to vlan-wildcard rule id4)" >&2
    echo "          bug shape: vlan bit not cleared from acc, or vlan-wildcard rule not surviving" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_VLAN_AND_COMPOSE (vlan axis intersects, not unions; tag reached XDP)"
exit "${fail}"
