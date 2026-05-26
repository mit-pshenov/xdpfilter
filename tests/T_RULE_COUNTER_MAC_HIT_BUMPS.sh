#!/bin/bash
# T_RULE_COUNTER_MAC_HIT_BUMPS — design §6.47 (MVP-3.4b cycle 1 / §5.31).
#
# MAC HASH-hit increments rule_counters[rule_id] (per Q1 B3 bump_rule
# wiring + PI-3.4b-4). Sparse-id fixture proves the operator's YAML `id:`
# IS the BPF ARRAY index (Q5 R1 / PI-3.4b-7).
#
# Trigger:
#   1. setup_veth + apply config_per_rule_counters.yaml.
#   2. Inject N=5 frames from MAC of rule_id=5 (PASS rule).
#   3. Inject K=3 frames from MAC of rule_id=0 (different PASS rule).
#   4. Negation-control: inject 2 frames from a MAC NOT in any rule.
#
# Observable outcome (ALL must hold):
#   (a) apply exit 0; rule_counters pin exists with shape PERCPU_ARRAY[64]
#       of u64 (PI-3.4b-1).
#   (b) After step 2: rule_counters[5] == 5; all OTHER slots (0..4, 6..63) == 0.
#   (c) After step 3: rule_counters[0] == 3; rule_counters[5] STILL == 5.
#   (d) After negation step 4: rule_counters[0] STILL == 3;
#       rule_counters[5] STILL == 5; STAT_DROP_DENY advances by 2.
#   (e) Global STAT_PASS advances by 8 across steps 2+3 (existing global
#       counter byte-equivalent to MVP-3.4.5 / PI-31-3.4b read-only).
#
# Sanity-floor smoke: step (a) — apply exits 0 + rule_counters pin
# materializes (cannot reach later assertions otherwise).
# Negation control: step (d) — inject a non-matching MAC; rule_counters[5]
# and rule_counters[0] STAY unchanged (no spurious bump on miss). This
# also catches a bug where bump_rule() fired on EVERY frame regardless
# of match status (would inflate counter[0] or counter[5]).
#
# Maps to: PI-3.4b-1, PI-3.4b-4, HG-3.4b-1, Q1 B3, Q5 R1.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for rule_counters dump parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_per_rule_counters.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

# MACs in fixture (must match config_per_rule_counters.yaml exactly).
MAC_ID0="02:00:00:00:00:01"   # rule_id=0 PASS
MAC_ID5="02:00:00:00:00:05"   # rule_id=5 PASS
MAC_OUTSIDE="02:00:00:00:00:fe"   # NOT in fixture — negation control

stderr_file=$(mktemp /tmp/xdpmf-rulemac-stderr.XXXXXX)
# §5.33 HK-B: explicit signal trap-set covers SIGINT/SIGTERM/SIGHUP in
# addition to normal EXIT so ctest's kill-escalation under -j4 still
# fires cleanup_veth (bash's implicit-EXIT-on-signal is racy under some
# kill scenarios; named-signal handlers fire immediately on receipt).
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP

# §5.33 HK-B pre-test residue wipe — idempotent belt-and-suspenders defense
# against PID-recycled prior aborted runs leaving residue at the same
# PID-scoped ${PIN_DIR}=${PIN_ROOT}/xdpmf_a_$$ path. setup_veth's internal
# rm-rf already handles the in-test case; this catches the cross-run case.
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

# Helper to read one rule_counters slot via the new lib helper.
read_rc_slot() {
    local id="$1"
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" \
        "${PIN_DIR}/rule_counters" "${id}"
}

# ── (a) apply + smoke ────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
echo "--- stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

fail=0
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[a1]: apply exit ${rc} (expected 0)" >&2
    fail=1
fi
if ! sudo -n test -e "${PIN_DIR}/rule_counters"; then
    echo "FAIL[a2]: ${PIN_DIR}/rule_counters pin missing (PI-3.4b-1)" >&2
    exit 1   # cannot proceed without the pin
fi

# Verify map shape via bpftool map show --json (robust to text-format drift —
# libbpf 1.x emits 'value 8B' in text mode, NOT 'value_size 8'; JSON is stable).
# libbpf 1.x JSON keys: bytes_key, bytes_value (NOT key_size/value_size).
shape_json=$(sudo -n bpftool map show pinned "${PIN_DIR}/rule_counters" --json 2>&1)
echo "rule_counters shape JSON: ${shape_json}"
shape_type=$(echo "${shape_json}" | jq -r '.type // empty' 2>/dev/null)
shape_max=$( echo "${shape_json}" | jq -r '.max_entries // empty' 2>/dev/null)
# Support both newer (bytes_value/bytes_key) and older (value_size/key_size) JSON
# key names defensively; libbpf 1.x emits bytes_*; older bpftool emitted *_size.
shape_vsz=$(echo "${shape_json}" | jq -r '.bytes_value // .value_size // empty' 2>/dev/null)
shape_ksz=$(echo "${shape_json}" | jq -r '.bytes_key   // .key_size   // empty' 2>/dev/null)
echo "  type=${shape_type} max_entries=${shape_max} value_size=${shape_vsz} key_size=${shape_ksz}"
if [[ "${shape_type}" != "percpu_array" ]]; then
    echo "FAIL[a3]: rule_counters type='${shape_type}' (expected percpu_array)" >&2
    fail=1
fi
if [[ "${shape_max}" != "64" ]]; then
    echo "FAIL[a4]: rule_counters max_entries='${shape_max}' (expected 64)" >&2
    fail=1
fi
if [[ "${shape_vsz}" != "8" ]]; then
    echo "FAIL[a5]: rule_counters value_size='${shape_vsz}' (expected 8 = u64)" >&2
    fail=1
fi

# Baseline: all 64 slots should be 0 (fresh apply, no traffic yet).
echo "=== baseline rule_counters dump"
all_baseline=$(sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" \
               "${PIN_DIR}/rule_counters")
echo "all 64 slots: ${all_baseline}"
nonzero_baseline=$(echo "${all_baseline}" | tr ' ' '\n' | grep -cvE '^0$' || true)
nonzero_baseline=${nonzero_baseline:-0}
if [[ "${nonzero_baseline}" != "0" ]]; then
    echo "FAIL[a6]: baseline rule_counters has ${nonzero_baseline} non-zero slot(s) (expected 0)" >&2
    fail=1
fi

# Baseline global stats (for later delta).
read -r p0 d0 m0 < <(read_stats)
echo "stats baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0}"

# ── (b) Inject N=5 frames from MAC_ID5 → rule_counters[5] == 5 ────────────
echo "=== step (b): inject 5 frames src=${MAC_ID5} (rule_id=5 PASS)"
for i in 1 2 3 4 5; do
    inject_eth "${IFACE_B}" "${MAC_ID5}" "${MAC_DST}"
done
wait_for_stats_sum "${IFACE_A}" $(( p0 + d0 + m0 + 5 )) || true

c5_after_b=$(read_rc_slot 5)
echo "rule_counters[5]=${c5_after_b} (expected 5)"
if [[ "${c5_after_b}" != "5" ]]; then
    echo "FAIL[b1]: rule_counters[5]='${c5_after_b}' (expected 5)" >&2
    fail=1
fi

# Other slots must STAY 0 (only slot 5 should have moved).
all_after_b=$(sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" \
              "${PIN_DIR}/rule_counters")
echo "all 64 slots after step (b): ${all_after_b}"
# Check slots 0..4 and 6..63 are all zero.
idx=0
for v in ${all_after_b}; do
    if [[ "${idx}" != "5" && "${v}" != "0" ]]; then
        echo "FAIL[b2]: rule_counters[${idx}]='${v}' (expected 0; only slot 5 should move)" >&2
        fail=1
    fi
    idx=$(( idx + 1 ))
done

# ── (c) Inject K=3 frames from MAC_ID0 → rule_counters[0] == 3; slot 5 == 5 ─
echo "=== step (c): inject 3 frames src=${MAC_ID0} (rule_id=0 PASS)"
read -r p_b d_b m_b < <(read_stats)
for i in 1 2 3; do
    inject_eth "${IFACE_B}" "${MAC_ID0}" "${MAC_DST}"
done
wait_for_stats_sum "${IFACE_A}" $(( p_b + d_b + m_b + 3 )) || true

c0_after_c=$(read_rc_slot 0)
c5_after_c=$(read_rc_slot 5)
echo "rule_counters[0]=${c0_after_c} (expected 3); rule_counters[5]=${c5_after_c} (expected 5)"
if [[ "${c0_after_c}" != "3" ]]; then
    echo "FAIL[c1]: rule_counters[0]='${c0_after_c}' (expected 3)" >&2
    fail=1
fi
if [[ "${c5_after_c}" != "5" ]]; then
    echo "FAIL[c2]: rule_counters[5]='${c5_after_c}' (expected STILL 5; bumped on wrong slot?)" >&2
    fail=1
fi

# ── (d) NEGATION CONTROL: inject 2 non-matching → no rule_counters move ──
echo "=== step (d): NEGATION — inject 2 frames src=${MAC_OUTSIDE} (no rule)"
read -r p_c d_c m_c < <(read_stats)
for i in 1 2; do
    inject_eth "${IFACE_B}" "${MAC_OUTSIDE}" "${MAC_DST}"
done
wait_for_stats_sum "${IFACE_A}" $(( p_c + d_c + m_c + 2 )) || true

c0_after_d=$(read_rc_slot 0)
c5_after_d=$(read_rc_slot 5)
echo "rule_counters[0]=${c0_after_d} (expected STILL 3); rule_counters[5]=${c5_after_d} (expected STILL 5)"
if [[ "${c0_after_d}" != "3" ]]; then
    echo "FAIL[d1]: rule_counters[0]='${c0_after_d}' bumped on negation (expected STILL 3)" >&2
    echo "          a bump here means bump_rule fires even on no-match — datapath bug" >&2
    fail=1
fi
if [[ "${c5_after_d}" != "5" ]]; then
    echo "FAIL[d2]: rule_counters[5]='${c5_after_d}' bumped on negation (expected STILL 5)" >&2
    fail=1
fi

# Negation: STAT_DROP_DENY must advance by exactly 2 (the non-matching frames).
read -r p_d d_d m_d < <(read_stats)
if (( d_d - d_c != 2 )); then
    echo "FAIL[d3]: STAT_DROP_DENY delta=$((d_d - d_c)) (expected 2 from non-matching frames)" >&2
    fail=1
fi

# ── (e) Global STAT_PASS delta == 8 (5 from step b + 3 from step c) ─────
delta_pass=$(( p_d - p0 ))
# d_d - d0 should be 2 (the negation drops); m_d - m0 should be 0
echo "STAT_PASS delta from start: ${delta_pass} (expected 8)"
if (( delta_pass != 8 )); then
    echo "FAIL[e]: STAT_PASS delta=${delta_pass} (expected 8 = 5 + 3)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_RULE_COUNTER_MAC_HIT_BUMPS"
exit "${fail}"
