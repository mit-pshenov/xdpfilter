#!/bin/bash
# T_APPLY_REPLACES_RULESET — design §6.24 (MVP-3.1 / §5.26).
#
# Bidirectional A → B → A swap verification:
#   1. apply config_apply_swap_a.yaml (pass MAC_X only).
#   2. inject MAC_Y → STAT_DROP_DENY += 1 (Y denied under A).
#   3. apply config_apply_swap_b.yaml (pass MAC_X + MAC_Y).
#   4. inject MAC_Y → STAT_PASS += 1 (Y now allowed under B).
#   5. apply config_apply_swap_a.yaml AGAIN (back to MAC_X-only).
#   6. inject MAC_Y → STAT_DROP_DENY += 1 (Y denied again under A).
#
# Each apply must exit 0; active_idx flipped between successive applies;
# inner-map contents reflect the new ruleset on the now-active slot.
#
# Sanity-floor smoke: each apply that returns 0 verifies the path is
# functional. Negation control: step 6's "MAC_Y denied AGAIN after
# returning to A" is the differential — proves the swap is genuinely
# replacing (not merging) state. If the second A apply leaked MAC_Y
# from B into the active inner, step 6 would PASS instead of drop.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE_DIR="${TEST_DIR}/fixtures"
FIX_A="${FIXTURE_DIR}/config_apply_swap_a.yaml"
FIX_B="${FIXTURE_DIR}/config_apply_swap_b.yaml"

[[ -f "${FIX_A}" ]] || { echo "FAIL: missing fixture ${FIX_A}" >&2; exit 1; }
[[ -f "${FIX_B}" ]] || { echo "FAIL: missing fixture ${FIX_B}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-replaces-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT

MAC_X="02:00:00:00:00:01"   # in both A and B
SRC_MAC="02:00:00:00:00:aa"  # 5.43: MAC deferred; src_mac irrelevant
MAC_Y="02:00:00:00:00:02"   # in B only

# Helper: invoke apply, capturing rc + stderr.
do_apply() {
    local fixture="$1"
    : >"${stderr_file}"
    set +e
    ${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${fixture}" 2> "${stderr_file}"
    local rc=$?
    set -e
    echo "  rc=${rc}"
    echo "  --- stderr ---"
    cat "${stderr_file}" >&2 || true
    echo "  --- end stderr ---"
    return "${rc}"
}

read_active_idx() {
    # Modern bpftool: `--json` gives `.[0].formatted.value` as integer.
    # Older bpftool fallback: parse the LE byte array's byte 0.
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then
        printf '%d\n' "0x${hex}"
    fi
}

setup_veth

fail=0

# ── Step 1: apply A ──────────────────────────────────────────────────────
echo "=== step 1: apply A (pass MAC_X only)"
if ! do_apply "${FIX_A}"; then
    echo "FAIL[1]: apply A exit non-zero" >&2
    fail=1
fi
active_1=$(read_active_idx)
echo "active_idx after step 1 = '${active_1}'"
if [[ -z "${active_1}" ]]; then
    echo "FAIL[1.idx]: could not read active_idx after step 1" >&2
    fail=1
fi

# ── Step 2: inject MAC_Y → STAT_DROP_DENY += 1 ───────────────────────────
echo "=== step 2: inject MAC_Y (expected DENY under A)"
read -r p0 d0 m0 p0_c < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "192.168.0.1"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + p0_c + 1 )) || true
read -r p1 d1 m1 p1_c < <(read_stats_with_cidr)
echo "  stats: PASS=${p1} DROP_DENY=${d1} (delta P=$(( p1-p0 )) D=$(( d1-d0 )))"
if (( d1 - d0 != 1 )); then
    echo "FAIL[2.d]: expected STAT_DROP_DENY delta=1 under A for MAC_Y, got $(( d1-d0 ))" >&2
    fail=1
fi
if (( p1 - p0 != 0 )); then
    echo "FAIL[2.p]: expected STAT_PASS delta=0 under A for MAC_Y, got $(( p1-p0 ))" >&2
    fail=1
fi

# ── Step 3: apply B ──────────────────────────────────────────────────────
echo "=== step 3: apply B (pass MAC_X + MAC_Y)"
if ! do_apply "${FIX_B}"; then
    echo "FAIL[3]: apply B exit non-zero" >&2
    fail=1
fi
active_2=$(read_active_idx)
echo "active_idx after step 3 = '${active_2}'"
if [[ -n "${active_1}" && -n "${active_2}" && "${active_2}" == "${active_1}" ]]; then
    echo "FAIL[3.idx]: active_idx did NOT flip A→B (still '${active_2}')" >&2
    fail=1
fi

# §5.43: src_cidr axis → check the active cidr_allowlist inner pin grew to
# the expected ruleset (B has 2 prefixes). The verdict in step 4 is the
# load-bearing membership proof; here we assert the inner has ≥2 entries.
if [[ "${active_2}" == "0" ]]; then
    inner_pin="${PIN_DIR}/cidr_allowlist_a"
elif [[ "${active_2}" == "1" ]]; then
    inner_pin="${PIN_DIR}/cidr_allowlist_b"
else
    inner_pin=""
fi
if [[ -n "${inner_pin}" ]]; then
    n_entries=$(sudo -n bpftool map dump pinned "${inner_pin}" --json 2>/dev/null | jq 'length' 2>/dev/null || echo 0)
    if [[ -z "${n_entries}" || "${n_entries}" -lt 2 ]]; then
        echo "FAIL[3.inner]: active CIDR inner ${inner_pin} has ${n_entries} prefixes (expected ≥2 under B)" >&2
        sudo -n bpftool map dump pinned "${inner_pin}" >&2 || true
        fail=1
    fi
fi

# ── Step 4: inject MAC_Y → STAT_PASS += 1 ────────────────────────────────
echo "=== step 4: inject MAC_Y (expected PASS under B)"
read -r p2 d2 m2 p2_c < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "192.168.0.1"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + p2_c + 1 )) || true
read -r p3 d3 m3 p3_c < <(read_stats_with_cidr)
echo "  stats: PASS=${p3} DROP_DENY=${d3} (delta P=$(( p3-p2 )) D=$(( d3-d2 )))"
# §5.43: matched-rule PASS → STAT_PASS_CIDR.
if (( p3_c - p2_c != 1 )); then
    echo "FAIL[4.p]: expected STAT_PASS_CIDR delta=1 under B for src∈id1, got $(( p3_c-p2_c ))" >&2
    fail=1
fi
if (( d3 - d2 != 0 )); then
    echo "FAIL[4.d]: expected STAT_DROP_DENY delta=0 under B for MAC_Y, got $(( d3-d2 ))" >&2
    fail=1
fi

# ── Step 5: apply A again (bidirectional verification) ───────────────────
echo "=== step 5: apply A again (back to MAC_X-only)"
if ! do_apply "${FIX_A}"; then
    echo "FAIL[5]: second apply A exit non-zero" >&2
    fail=1
fi
active_3=$(read_active_idx)
echo "active_idx after step 5 = '${active_3}'"
if [[ -n "${active_2}" && -n "${active_3}" && "${active_3}" == "${active_2}" ]]; then
    echo "FAIL[5.idx]: active_idx did NOT flip B→A (still '${active_3}')" >&2
    fail=1
fi

# ── Step 6: inject MAC_Y → STAT_DROP_DENY += 1 (negation differential) ──
echo "=== step 6: inject MAC_Y (expected DENY again under A — NEGATION DIFFERENTIAL)"
read -r p4 d4 m4 p4_c < <(read_stats_with_cidr)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "192.168.0.1"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p4 + d4 + m4 + p4_c + 1 )) || true
read -r p5 d5 m5 p5_c < <(read_stats_with_cidr)
echo "  stats: PASS=${p5} DROP_DENY=${d5} (delta P=$(( p5-p4 )) D=$(( d5-d4 )))"
if (( d5 - d4 != 1 )); then
    echo "FAIL[6.d]: expected STAT_DROP_DENY delta=1 (MAC_Y denied AGAIN under A), got $(( d5-d4 ))" >&2
    echo "          a non-drop here means the swap A→B leaked into the active slot — replacement is not happening" >&2
    fail=1
fi
if (( p5 - p4 != 0 )); then
    echo "FAIL[6.p]: expected STAT_PASS delta=0, got $(( p5-p4 ))" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_APPLY_REPLACES_RULESET"
exit "${fail}"
