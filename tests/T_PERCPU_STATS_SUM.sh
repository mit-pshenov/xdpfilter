#!/bin/bash
# T_PERCPU_STATS_SUM — design §6.18 (MVP-2 Perf / §5.23 Q3 Option F).
#
# Deterministic verification that the new read_stats.py correctly sums
# across CPU slots in the PERCPU `stats` map. NO traffic injection;
# seeds known per-CPU values directly via `bpftool map update`, asserts
# read_stats.py's sum matches the seeded total.
#
# Diagnostic value (per §6.18): if this test FAILS but §6.3 PASSES, the
# bug is in read_stats.py sum logic OR a bpftool JSON schema mismatch.
# If this PASSES but §6.3 fails, the bug is in BPF program's PERCPU
# lookup-and-bump, NOT the sum logic — diagnostic separation is the point.
#
# ── PHASE-B DIVERGENCE FROM DESIGN §6.18 SEED MECHANISM ─────────────────
# Design §6.18 specified seeding "value = c + 1 for CPU c" with expected
# sum = nr_cpus*(nr_cpus+1)/2. Empirical Phase B investigation of bpftool
# v7.1.0 source (src/map.c:fill_per_cpu_value()) revealed: `bpftool map
# update` on a PERCPU map reads exactly value_size bytes (8 for u64) and
# then BROADCASTS that single value to all CPU slots via memcpy. There is
# NO CLI syntax for setting DIFFERENT per-CPU values via bpftool — only a
# broadcast is supported. Passing more than value_size bytes triggers the
# "expected key or value, got: 02" parse error.
#
# Tester's resolution (preserves §6.18 diagnostic intent): seed a single
# known value V across all CPUs via the broadcast; expected_sum = V *
# nr_cpus. On the host's 2+ CPU configuration (typical CI), this still
# discriminates "sum across all CPUs" (returns V * nr_cpus) from "read
# CPU 0 only" (returns V). On a single-CPU host the cases degenerate,
# but the §6.18 spec already accepts that ("Even on single-CPU runners
# (nr_cpus == 1), test is deterministic").  V is chosen as a recognizable
# magic number (0x2a == 42) for log-readability; the actual value is
# arbitrary as long as it's non-zero (so STAT_DROP_DENY/MALFORMED slots
# at 0 are visibly distinct).
#
# Trigger (sequential):
#   1. setup_veth + attach default mode (so ${PIN_DIR}/stats exists).
#   2. nr_cpus=$(nproc --all)
#   3. V=42  ;  expected_sum = nr_cpus * V
#   4. bpftool map update pinned ${PIN_DIR}/stats key hex 00 00 00 00
#      value hex 2a 00 00 00 00 00 00 00     (LE u64 = 42, broadcast to all CPUs)
#   5. Read STAT_PASS via read_stats; assert pass == expected_sum.
#
# Outcome (ALL must hold):
#   (a) Step 4 exits 0 (bpftool accepts the single-CPU-worth byte stream).
#   (b) Step 5 exits 0 and pass == nr_cpus * V.
#
# Cleanup (trap EXIT): xdpmacfilter detach + cleanup_veth + aggressive
# pin-path cleanup to prevent stale bpffs entries tripping subsequent
# tests (per Phase B note from team-lead on T_ATTACH_TAG_MISMATCH).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
echo "loader=${LOADER_BIN}"

cleanup_test() {
    set +e
    # Detach via loader (best-effort — may fail if we corrupted state).
    ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" >/dev/null 2>&1
    # Aggressive bpffs cleanup — strip any per-iface dir AND any
    # accidentally-rooted map pins (defensive vs Phase B "stale-pin
    # tripping T_ATTACH_TAG_MISMATCH" report).
    sudo -n rm -rf "${PIN_DIR}"                   2>/dev/null
    sudo -n rm -f  /sys/fs/bpf/stats              2>/dev/null
    sudo -n rm -f  /sys/fs/bpf/allowlist          2>/dev/null
    cleanup_veth
    set -e
}
trap cleanup_test EXIT

setup_veth

echo "=== attach (default mode = generic) on ${IFACE_A}"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

# Sanity floor: the stats pin must exist (else attach silently failed).
if ! sudo -n test -e "${PIN_DIR}/stats"; then
    echo "FAIL: ${PIN_DIR}/stats not present after attach — cannot run sum test" >&2
    exit 1
fi

# ── Compute broadcast value + expected sum ──────────────────────────────
nr_cpus=$(nproc --all)
if (( nr_cpus < 1 )); then
    echo "ERROR: nproc --all returned '${nr_cpus}' (<1)" >&2
    exit 1
fi
V=42
expected_sum=$(( nr_cpus * V ))
echo "nr_cpus=${nr_cpus}  V=${V}  expected_sum=${expected_sum}  (broadcast semantic)"

# ── Seed STAT_PASS slot via bpftool map update (broadcasts to all CPUs) ─
# Key is u32 index = 0 (STAT_PASS) in LE bytes: "00 00 00 00".
# Value is the LE u64 representation of V = 42 → 2a 00 00 00 00 00 00 00.
# bpftool's fill_per_cpu_value() replicates this 8-byte payload across
# all per-CPU slots of the PERCPU_ARRAY (per bpftool/src/map.c, v7.1.0).
echo "=== bpftool map update pinned ${PIN_DIR}/stats key 0 value V=${V} (broadcast)"
set +e
sudo -n bpftool map update pinned "${PIN_DIR}/stats" \
    key hex 00 00 00 00 \
    value hex 2a 00 00 00 00 00 00 00
update_rc=$?
set -e

fail=0

# (a) bpftool exit 0.
if [[ "${update_rc}" -ne 0 ]]; then
    echo "FAIL: bpftool map update failed (rc=${update_rc})" >&2
    echo "      this means bpftool refused the single-CPU-worth value bytes —" >&2
    echo "      check bpftool version (need v7.x+) and PERCPU broadcast support" >&2
    fail=1
fi

# Sanity diagnostic: dump the map to confirm the broadcast actually
# populated all CPU slots with V (load-bearing for diagnostic separation
# — if dump shows CPU 0 == V but CPU 1 == 0, bpftool didn't broadcast
# and the expected_sum will mismatch).
echo "=== bpftool dump (diagnostic — confirms broadcast worked)"
sudo -n bpftool map dump pinned "${PIN_DIR}/stats" --json 2>/dev/null \
    | jq -r '.[] | select(.key[0] == "0x00") | .values[]?
              | "    cpu \(.cpu): value=\(.value | join(" "))"' \
    || echo "    (jq decode failed; bpftool output may be in fallback format)"

# (b) read_stats returns pass == expected_sum.
echo "=== read stats (expect pass=${expected_sum}, others=0)"
stats_out=$(read_stats "${PIN_DIR}/stats")
echo "read_stats output: '${stats_out}'"
read -r pass deny malformed <<<"${stats_out}"

if [[ "${pass}" != "${expected_sum}" ]]; then
    echo "FAIL: STAT_PASS sum mismatch" >&2
    echo "      expected ${expected_sum} (= nr_cpus(${nr_cpus}) * V(${V})), got ${pass}" >&2
    if [[ "${pass}" == "${V}" ]]; then
        echo "      diagnostic: pass==V suggests read_stats reads only CPU 0 — sum-across-CPUs broken" >&2
    elif [[ "${pass}" == "0" ]]; then
        echo "      diagnostic: pass==0 suggests bpftool update didn't land OR read_stats can't find the key" >&2
    else
        echo "      diagnostic: pass is some other value — partial CPU read or schema mismatch" >&2
    fi
    fail=1
fi

# Diagnostic-only: report deny/malformed values (NOT asserted per §6.18 —
# they should be 0 in the no-traffic test but we don't fail if they're not).
echo "diagnostic: STAT_DROP_DENY=${deny}  STAT_DROP_MALFORMED=${malformed}"

[[ "${fail}" == 0 ]] && echo "PASS: T_PERCPU_STATS_SUM (pass=${pass}, expected=${expected_sum})"
exit "${fail}"
