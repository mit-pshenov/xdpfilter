#!/bin/bash
# T_VLAN_UNTAGGED_WILDCARD — design §6.68 (MVP-4.5 / §5.45).
#
# Proves untagged-frame semantics (HG-mvp-4.5-4 / PI-mvp-4.5-UNTAGGED): an
# UNTAGGED IPv4 frame has has_vlan=0 ⇒ vlan_mask=0 ⇒ EVERY vlan-constrained
# rule's bit is cleared from the accumulator, so only vlan-WILDCARD rules can
# survive the vlan axis. A vlan-constrained rule MUST NOT match an untagged
# frame.
#
# Fixture config_valid_and5.yaml (schema_version: 2) — the id3/id4 pair shares
# dst 10.5.0.0/16:
#   id 3 : dst 10.5.0.0/16 AND vlan 100        pass   (dst + vlan; vlan-constrained)
#   id 4 : dst 10.5.0.0/16                      pass   (dst-only; vlan-WILDCARD)
#
# Steps / observable outcome (ALL must hold):
#   (a) SMOKE: apply exit 0; rule_counters pin reachable; id3/id4 baseline 0.
#   (b) UNTAGGED → only the vlan-WILDCARD rule survives: an UNTAGGED frame on
#       dst=10.5.1.1 (tcp/8080) hits id4 (rule_counters[4]==1) and does NOT
#       hit the vlan-constrained id3 (rule_counters[3] STAYS 0). This is the
#       core proof: has_vlan=0 ⇒ id3's vlan bit cleared.
#   (c) ANTI-VACUITY companion: the SAME tuple TAGGED vlan 100 DOES hit the
#       vlan-constrained id3 (rule_counters[3]==1, lower id wins the tie over
#       id4). Proves the (b) untagged-miss is the capture path (has_vlan=0),
#       NOT a broken/never-matching id3 rule — without this companion, a rule
#       that simply never matches would pass (b) vacuously (guard #22 /
#       D-mvp-4.5-OFFLOAD).
#
# Sanity floor: smoke = step (a). The untagged-miss in (b) IS the negation
# (a vlan-constrained rule firing on has_vlan=0 would FAIL it). (c) is the
# anti-vacuity differential.
#
# Guard #22: NIC VLAN offload disabled best-effort in setup — defensive (this
# test injects untagged in (b)), keeping setup uniform with §6.67/§6.69 and
# load-bearing for the (c) tagged companion.
#
# Maps to: PI-mvp-4.5-UNTAGGED, PI-mvp-4.5-WILDCARD, PI-mvp-4.5-AND5,
#          PI-mvp-4.5-OFFLOAD.
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

stderr_file=$(mktemp /tmp/xdpmf-vlanuntagged-stderr.XXXXXX)
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
if ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[a2]: ${PIN_DIR}/rule_counters_a pin missing after apply" >&2
    exit 1
fi
for slot in 3 4; do
    v=$(read_rc_slot "${slot}")
    [[ "${v}" == "0" ]] || { echo "FAIL[a3]: rule_counters[${slot}]='${v}' baseline (expected 0)" >&2; fail=1; }
done
echo "smoke OK: apply exit 0, rule_counters reachable, id3/id4 baseline 0"

# ── (b) UNTAGGED → only vlan-WILDCARD id4 survives (id3 cleared) ──────────
echo "=== (b) inject UNTAGGED dst=10.5.1.1 tcp/8080 (has_vlan=0)"
pump 10.5.1.1 8.8.8.8 tcp 8080
rc3=$(read_rc_slot 3)
rc4=$(read_rc_slot 4)
if [[ "${rc3}" != "0" ]]; then
    echo "FAIL[b1]: rule_counters[3]='${rc3}' bumped on an UNTAGGED frame (expected STILL 0)" >&2
    echo "          bug shape: vlan-constrained id3 fired with has_vlan=0 (vlan_mask not forced to 0)" >&2
    fail=1
fi
if [[ "${rc4}" != "1" ]]; then
    echo "FAIL[b2]: rule_counters[4]='${rc4}' (expected 1 — untagged frame survives only on vlan-wildcard id4)" >&2
    fail=1
fi

# ── (c) ANTI-VACUITY: SAME tuple TAGGED vlan 100 → id3 hits ──────────────
echo "=== (c) anti-vacuity: inject TAGGED vlan100 dst=10.5.1.1 tcp/8080 (id3 dst+vlan)"
pump 10.5.1.1 8.8.8.8 tcp 8080 100
rc3=$(read_rc_slot 3)
rc4=$(read_rc_slot 4)
if [[ "${rc3}" != "1" ]]; then
    echo "FAIL[c1]: rule_counters[3]='${rc3}' (expected 1 — vlan100 tag makes id3 the winner)" >&2
    echo "          this proves the (b) untagged-miss was the capture path, NOT a never-matching id3" >&2
    echo "          guard #22: if 0, the tag may have been STRIPPED before XDP (offload on?)" >&2
    fail=1
fi
if [[ "${rc4}" != "1" ]]; then
    echo "FAIL[c2]: rule_counters[4]='${rc4}' moved on the vlan100 frame (expected STILL 1)" >&2
    echo "          id3 (lower id) wins the tie over id4 for the tagged frame" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_VLAN_UNTAGGED_WILDCARD (untagged ⇒ only vlan-wildcard survives)"
exit "${fail}"
