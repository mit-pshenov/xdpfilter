#!/bin/bash
# T_REATTACH_TWICE_SLOT_CANARY — design §5.48 TestStrategy (MVP-4.8 / B20).
#
# WHY THIS TEST EXISTS (corpus-justified, NOT symmetry):
#   The HK-9 bug class B20 guards against is an `_a`/`_b` slot swap inside
#   `inactive_axis_fd` (the single `slot==0→_a` / `slot==1→_b` select site).
#   That bug ONLY manifests when the REATTACH path runs with BOTH inactive=1
#   (→_b) AND inactive=0 (→_a). Every existing apply/atomic-swap test does at
#   most ONE reattach on a given attachment (fresh apply A + one re-apply B),
#   which flips active_idx 0→1 and exercises ONLY inactive=1→_b. The
#   inactive=0→_a reattach selection (a SECOND re-apply, flipping 1→0) is
#   exercised by NO existing test (verified against the corpus: the max
#   successful re-applies on one attachment across all atomic-swap, oracle,
#   and counter tests is one; T_SCHEMA_V2_CUTOVER's 3 applies are 2 rejects
#   that never attach + 1 fresh + 1 reattach). §5.48 therefore justifies this
#   single targeted reattach-twice canary.
#
# CONTRACT (from §5.48): apply config A → apply config B (reattach, inactive=1→_b)
#   → apply config C (reattach, inactive=0→_a), asserting per-axis verdicts
#   track the LIVE config at each step. A/B/C each allow a DIFFERENT exclusive
#   MAC, so "verdict tracks live config" is directly observable as PASS/DROP.
#
# Sequence:
#   1. setup_veth + apply A (pass MAC_A only).
#   2. assert MAC_A PASSES, MAC_B DROPS (state A live). Snapshot active_idx.
#   3. apply B (REATTACH #1, inactive=1→_b). Assert active_idx FLIPPED.
#   4. assert MAC_B PASSES, MAC_A DROPS (state B live).
#   5. apply C (REATTACH #2, inactive=0→_a — LOAD-BEARING). Assert active_idx
#      FLIPPED AGAIN and ping-ponged back to its post-A value (proves the
#      second reattach selected the OTHER slot = _a).
#   6. assert MAC_C PASSES, MAC_B DROPS (state C live). This is the assertion
#      the HK-9 _a/_b-swap bug would fail.
#   7. NEGATION CONTROL: inject MAC_DENY (in NO config) → MUST DROP. Proves the
#      drop machinery is live and the test can register a failure verdict.
#
# Deterministic: fixed-count injection + wait_for_stats_sum_with_cidr per step
# (no rate-dependent SKIP-77). Counters PRESERVE across apply (reuse_fd), so
# every check is a before/after DELTA around its own injection batch.
#
# Maps to: PI-mvp-4.8-FD-SELECT (load-bearing), PI-mvp-4.8-SWAP-SEMANTICS,
#          PI-mvp-4.8-BEHAVIOR-EQUIV; B20 / HK-9 _a/_b-swap guard.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE_DIR="${TEST_DIR}/fixtures"
FIX_A="${FIXTURE_DIR}/config_reattach_canary_a.yaml"
FIX_B="${FIXTURE_DIR}/config_reattach_canary_b.yaml"
FIX_C="${FIXTURE_DIR}/config_reattach_canary_c.yaml"

for f in "${FIX_A}" "${FIX_B}" "${FIX_C}"; do
    [[ -f "${f}" ]] || { echo "FAIL: missing fixture ${f}" >&2; exit 1; }
done

MAC_A="02:00:00:00:00:0a"    # allowed ONLY by config A
MAC_B="02:00:00:00:00:0b"    # allowed ONLY by config B
MAC_C="02:00:00:00:00:0c"    # allowed ONLY by config C
MAC_DENY="02:00:00:00:00:dd" # allowed by NO config — negation control
SRC_IP="10.0.0.7"            # well-formed IPv4 so the frame clears the IPv4 gate
N=5                          # frames per injection batch

stderr_file=$(mktemp /tmp/xdpmf-reattach2-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP

read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}

fail=0

# apply_or_die <fixture> <label>
apply_or_die() {
    local fixture="$1" label="$2"
    : >"${stderr_file}"
    echo "=== ${label}: apply ${fixture}"
    set +e
    ${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${fixture}" 2>"${stderr_file}"
    local rc=$?
    set -e
    cat "${stderr_file}" >&2 || true
    if [[ "${rc}" -ne 0 ]]; then
        echo "FAIL[${label}.rc]: apply exit ${rc} (expected 0)" >&2
        exit 1
    fi
    if [[ -z "$(xdp_prog_id "${IFACE_A}")" ]]; then
        echo "FAIL[${label}.attach]: no XDP attached after ${label}" >&2
        exit 1
    fi
}

# expect_verdict <label> <src_mac> <pass|drop>
#   Injects N IPv4 frames with the given src_mac, then asserts the stats DELTA:
#   a PASS lands in STAT_PASS or STAT_PASS_CIDR (sum is bucket-robust); a DROP
#   lands in STAT_DROP_DENY. Well-formed frame ⇒ STAT_DROP_MALFORMED unchanged.
expect_verdict() {
    local label="$1" mac="$2" expected="$3"
    local p0 d0 m0 c0 p1 d1 m1 c1 pass_delta drop_delta i
    read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
    for ((i = 0; i < N; i++)); do
        ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
            "${IFACE_B}" "${mac}" "${MAC_DST}" "${SRC_IP}" >/dev/null 2>&1
    done
    wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + N )) || true
    read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
    pass_delta=$(( (p1 + c1) - (p0 + c0) ))
    drop_delta=$(( d1 - d0 ))
    echo "  [${label}] mac=${mac} expect=${expected}: pass_delta=${pass_delta} drop_delta=${drop_delta} (n=${N})"
    if [[ "${expected}" == "pass" ]]; then
        if (( pass_delta != N || drop_delta != 0 )); then
            echo "  FAIL[${label}]: expected ${N} pass / 0 drop; got pass=${pass_delta} drop=${drop_delta}" >&2
            fail=1
        fi
    else
        if (( drop_delta != N || pass_delta != 0 )); then
            echo "  FAIL[${label}]: expected ${N} drop / 0 pass; got pass=${pass_delta} drop=${drop_delta}" >&2
            fail=1
        fi
    fi
}

setup_veth

# ── Step 1-2: fresh attach A; state A live ────────────────────────────────
apply_or_die "${FIX_A}" "A (fresh attach)"
active_a=$(read_active_idx)
echo "active_idx after A = '${active_a}'"
expect_verdict "A.live.MAC_A" "${MAC_A}" pass
expect_verdict "A.live.MAC_B" "${MAC_B}" drop

# ── Step 3-4: reattach #1 (inactive=1→_b); state B live ───────────────────
apply_or_die "${FIX_B}" "B (reattach #1, inactive=1→_b)"
active_b=$(read_active_idx)
echo "active_idx after B = '${active_b}'"
if [[ -z "${active_a}" || -z "${active_b}" ]]; then
    echo "FAIL[B.idx-readout]: could not read active_idx (a='${active_a}' b='${active_b}')" >&2
    fail=1
elif [[ "${active_a}" == "${active_b}" ]]; then
    echo "FAIL[B.flip]: active_idx did NOT flip on reattach #1 (still '${active_b}')" >&2
    fail=1
fi
expect_verdict "B.live.MAC_B" "${MAC_B}" pass
expect_verdict "B.live.MAC_A" "${MAC_A}" drop

# ── Step 5-6: reattach #2 (inactive=0→_a) — LOAD-BEARING; state C live ─────
apply_or_die "${FIX_C}" "C (reattach #2, inactive=0→_a — LOAD-BEARING)"
active_c=$(read_active_idx)
echo "active_idx after C = '${active_c}'"
if [[ -z "${active_c}" ]]; then
    echo "FAIL[C.idx-readout]: could not read active_idx after C" >&2
    fail=1
else
    if [[ "${active_b}" == "${active_c}" ]]; then
        echo "FAIL[C.flip]: active_idx did NOT flip on reattach #2 (still '${active_c}')" >&2
        fail=1
    fi
    # Ping-pong: the second reattach must select the OTHER slot, i.e. return to
    # the post-A value. This is what proves the inactive=0→_a reattach selection
    # was exercised (the corpus gap B20 cares about).
    if [[ -n "${active_a}" && "${active_c}" != "${active_a}" ]]; then
        echo "FAIL[C.pingpong]: active_idx did not ping-pong back to post-A value" >&2
        echo "                  (a='${active_a}' b='${active_b}' c='${active_c}') — two-slot swap broken" >&2
        fail=1
    fi
fi
# THE load-bearing assertion: state C must be live (written through inactive=0→_a).
# Under the HK-9 _a/_b-swap bug, the _a slot holds stale state B and these fail.
expect_verdict "C.live.MAC_C" "${MAC_C}" pass
expect_verdict "C.live.MAC_B" "${MAC_B}" drop

# ── Step 7: negation control ──────────────────────────────────────────────
# A MAC allowed by NO config MUST drop — proves the drop machinery is live and
# the test is capable of registering a failure verdict (not vacuously passing).
echo "=== negation control: MAC_DENY (in no config) must DROP"
expect_verdict "NEG.MAC_DENY" "${MAC_DENY}" drop

[[ "${fail}" == 0 ]] && echo "PASS: T_REATTACH_TWICE_SLOT_CANARY (both reattach slot cases _b AND _a exercised)"
exit "${fail}"
