#!/bin/bash
# T_SANITIZER_BUILD — design §6.8 / MVP-1.1A (per §5.18 sanitizer build),
#                      enriched per §5.59 (MVP-4.19 — 9-axis andv6 exercise).
#
# Setup    : fresh, isolated /tmp build dir configured with -DXDPMF_SANITIZERS=ON
#            so the default ${BUILD_DIR} is untouched (refactor-mode: existing
#            tests still consume ${BUILD_DIR}).
# Trigger  :
#   1. cmake -S "${SOURCE_DIR}" -B "${ASAN_BUILD_DIR}" -DXDPMF_SANITIZERS=ON
#   2. cmake --build "${ASAN_BUILD_DIR}" --parallel   (must exit 0, no warnings)
#   3. setup_veth
#   4. <sanitized_xdpmacfilter> apply --iface veth_a -f config_valid_andv6.yaml
#      (stderr → file).  §5.59: this richer apply is the genuine ASAN/UBSAN
#      payload — it drives the net-new userspace lowering (close_prefixes6's
#      __int128 prefix-closure + host_mask6 shift, the dst_port 1000-2000 RANGE
#      expansion, the v6 LPM populate, aggregate_axis/populate_hash_inner_slot
#      templates, and write_wildcard_slots) that the old single-src_cidr apply
#      never touched.
#   5. inject a 3-vector matrix on veth_b via inject_l6.py (andv6, default-drop):
#        V1 full-9-axis-v6 hit  (id0: dst6 2001:db8:1::/48, src6 2001:db8:5::/48,
#           tcp, dport 1500∈1000-2000, vlan 100) + --ext hbh --ext dstopt
#           → STAT_PASS_CIDR  (the --ext chain is a FUNCTIONAL S6 ext-walk
#             regression — in-kernel, NOT ASAN-instrumented; it proves the
#             datapath still derives true-L4 TCP through hbh→dstopt for id0)
#        V2 dst6-only wildcard hit (id1: dst6 2001:db8:2::/48, 7 axes wildcard)
#           → STAT_PASS_CIDR  (drives the write_wildcard_slots accumulator path)
#        V3 NOMATCH frame (dst6 ∉ any prefix, tcp ≠ id3's udp, id2 is v4-only)
#           → STAT_DROP_DENY  (andv6 default_action: drop → defaults fall-through)
#   6. read stats (4-col read_stats_with_cidr helper)
#   7. <sanitized_xdpmacfilter> detach --iface veth_a                    (stderr → same file)
#   8. cleanup_veth (via trap)
# Outcome  : ALL must hold
#   - build exits 0 with no compiler warnings (§5.12 policy)
#   - apply + detach exit 0
#   - cumulative stats == "pass=0 deny=1 mal=0 pass_cidr=2" (positive
#     correctness — V1+V2 → 2× STAT_PASS_CIDR, V3 → 1× STAT_DROP_DENY;
#     confirms the sanitized apply produced a working 9-axis datapath)
#   - captured stderr from steps 4+7 has ZERO lines matching ERE
#     'AddressSanitizer|UndefinedBehavior' (a clean sanitizer run prints
#     nothing from its runtime; ANY match is a real finding)
#
# Negation control: NOT required for this test per design §6.8 — the
# suite-level sanity floor is already satisfied by T_NEGATION_CONTROL
# (§6.7). This pass is purely additive.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

: "${SOURCE_DIR:?SOURCE_DIR must be set by ctest}"

ASAN_BUILD_DIR=$(mktemp -d /tmp/xdpmf-asan-XXXXXX)
LOG="${ASAN_BUILD_DIR}/buildlog.txt"
STDERR_FILE="${ASAN_BUILD_DIR}/sanitized.stderr"
: > "${STDERR_FILE}"

cleanup() {
    set +e
    # Tear down veth + bpffs pin (idempotent, safe if setup never ran).
    cleanup_veth 2>/dev/null
    # Remove the temp build tree (the whole point of using /tmp).
    rm -rf "${ASAN_BUILD_DIR}"
    set -e
}
trap cleanup EXIT

# ── Step 1: configure with -DXDPMF_SANITIZERS=ON ─────────────────────────
echo "=== T_SANITIZER_BUILD: configure in ${ASAN_BUILD_DIR} (XDPMF_SANITIZERS=ON)"
cmake -S "${SOURCE_DIR}" -B "${ASAN_BUILD_DIR}" \
        -DXDPMF_SANITIZERS=ON \
        2>&1 | tee -a "${LOG}"

# ── Step 2: build, assert exit 0 + no warnings ───────────────────────────
echo "=== T_SANITIZER_BUILD: build"
cmake --build "${ASAN_BUILD_DIR}" --parallel 2>&1 | tee -a "${LOG}"

echo "=== T_SANITIZER_BUILD: scanning build log for compiler warnings"
if grep -E '(^|[: ])warning:' "${LOG}" >/dev/null; then
    echo "FAIL: sanitizer build emitted compiler warnings:" >&2
    grep -nE '(^|[: ])warning:' "${LOG}" >&2 || true
    exit 1
fi

# Resolve the sanitized binary under the temp build dir.  Per §6.8 the
# binary lives at the same relative path the default build produces; we
# search rather than hard-code to stay layout-agnostic.
SANITIZED_LOADER=$(find "${ASAN_BUILD_DIR}" -maxdepth 5 -type f -executable \
                        -name xdpmacfilter 2>/dev/null | head -1 || true)
if [[ -z "${SANITIZED_LOADER}" || ! -x "${SANITIZED_LOADER}" ]]; then
    echo "FAIL: sanitized xdpmacfilter binary not produced under ${ASAN_BUILD_DIR}" >&2
    exit 1
fi
echo "sanitized loader = ${SANITIZED_LOADER}"

# ── Step 3: standard veth fixture (cleanup wired via trap) ───────────────
setup_veth

# ── Step 4: apply via sanitized binary, capture stderr ───────────────────
# §5.59 MVP-4.19: exercise the sanitized datapath via the richer 9-axis
# andv6 fixture (default_action: drop) instead of the single-src_cidr config.
# This apply is the genuine ASAN/UBSAN payload — it drives close_prefixes6
# (__int128 prefix-closure + host_mask6 shift), the dst_port 1000-2000 RANGE
# expansion, the v6 LPM populate, and write_wildcard_slots, none of which the
# old src_cidr apply touched. A matched bit-vector AND rule with a `pass`
# action lands on STAT_PASS_CIDR; a v6 NOMATCH falls through to the fixture's
# default_action: drop → STAT_DROP_DENY (per §5.59 verdict-slot mapping).
ANDV6_FIXTURE="${TEST_DIR}/fixtures/config_valid_andv6.yaml"
echo "=== T_SANITIZER_BUILD: apply (sanitized) iface=${IFACE_A} -f ${ANDV6_FIXTURE}"
set +e
${NSEXEC} "${SANITIZED_LOADER}" apply --iface "${IFACE_A}" -f "${ANDV6_FIXTURE}" \
    2>>"${STDERR_FILE}"
attach_rc=$?
set -e
sleep 0.3

# ── Step 5: inject the §5.59 3-vector matrix on veth_b (inject_l6.py) ─────
# Vectors are the W1/W2/W6 oracle analogs of T_ANDV6_ORACLE_AGREEMENT. After
# each inject, poll the cumulative classified-frame sum (§5.21 C1).
INJECT_L6="${TEST_DIR}/inject/inject_l6.py"

# V1: full-9-axis-v6 hit (id0) + an ext-header chain (hbh→dstopt). The walk is
# in-kernel/verifier-checked (NOT ASAN), a functional S6 regression that id0
# still classifies as true-L4 TCP through the chain.  → STAT_PASS_CIDR.
${NSEXEC} python3 "${INJECT_L6}" "${IFACE_B}" \
    --dst-ip "2001:db8:1::1234" --src-ip "2001:db8:5::9" \
    --proto tcp --dport 1500 --vlan 100 --ext hbh --ext dstopt \
    --dst-mac "${MAC_DST}"
wait_for_stats_sum_with_cidr "${IFACE_A}" 1 || true

# V2: dst6-only wildcard hit (id1, 7 axes wildcard) — drives the
# write_wildcard_slots accumulator path.  → STAT_PASS_CIDR.
${NSEXEC} python3 "${INJECT_L6}" "${IFACE_B}" \
    --dst-ip "2001:db8:2::5" --src-ip "2001:db8:9::9" \
    --proto tcp --dport 80 \
    --dst-mac "${MAC_DST}"
wait_for_stats_sum_with_cidr "${IFACE_A}" 2 || true

# V3: NOMATCH (dst6 ∉ id0/id1 prefixes, tcp ≠ id3's udp, id2 is v4-only) →
# acc==0 → defaults[active]=drop (andv6 default_action: drop).  → STAT_DROP_DENY.
${NSEXEC} python3 "${INJECT_L6}" "${IFACE_B}" \
    --dst-ip "2001:db8:dead::1" --src-ip "2001:db8:5::9" \
    --proto tcp --dport 22 \
    --dst-mac "${MAC_DST}"
wait_for_stats_sum_with_cidr "${IFACE_A}" 3 || true

# ── Step 6: read stats (4-col for the CIDR axis) ────────────────────────
read -r pass deny mal pass_cidr < <(read_stats_with_cidr)
echo "stats: PASS=${pass} DROP_DENY=${deny} DROP_MALFORMED=${mal} PASS_CIDR=${pass_cidr}"

# ── Step 7: detach via sanitized binary, capture stderr ─────────────────
echo "=== T_SANITIZER_BUILD: detach (sanitized)"
set +e
${NSEXEC} "${SANITIZED_LOADER}" detach --iface "${IFACE_A}" 2>>"${STDERR_FILE}"
detach_rc=$?
set -e

# Dump captured stderr for diagnostic before we grep it.
if [[ -s "${STDERR_FILE}" ]]; then
    echo "=== captured sanitized-binary stderr (steps 4+7) ==="
    cat "${STDERR_FILE}" >&2 || true
    echo "=== end stderr ==="
fi

# ── Assertions ──────────────────────────────────────────────────────────
fail=0

# Exit codes of the sanitized invocations.
[[ "${attach_rc}" == "0" ]] \
    || { echo "FAIL: sanitized apply exit=${attach_rc} (expected 0)" >&2; fail=1; }
[[ "${detach_rc}" == "0" ]] \
    || { echo "FAIL: sanitized detach exit=${detach_rc} (expected 0)" >&2; fail=1; }

# Positive correctness check: the sanitized apply produced a working 9-axis
# datapath (not just exited cleanly without doing work). §5.59: V1 (id0 full
# AND-v6 hit) + V2 (id1 dst6-only wildcard hit) → 2× STAT_PASS_CIDR; V3
# (NOMATCH, andv6 default-drop) → 1× STAT_DROP_DENY. Cumulative == "0 1 0 2".
[[ "${pass}" == "0" && "${deny}" == "1" && "${mal}" == "0" && "${pass_cidr}" == "2" ]] \
    || { echo "FAIL: expected stats '0 1 0 2' (pass deny mal pass_cidr), got '${pass} ${deny} ${mal} ${pass_cidr}'" >&2; fail=1; }

# THE key assertion: no sanitizer report in stderr.  Match is the failure
# condition (§6.8 "Negation form": a regex match means the test fails).
if grep -q -E 'AddressSanitizer|UndefinedBehavior' "${STDERR_FILE}" 2>/dev/null; then
    echo "FAIL: sanitizer report detected in captured stderr:" >&2
    grep -nE 'AddressSanitizer|UndefinedBehavior' "${STDERR_FILE}" >&2 || true
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_SANITIZER_BUILD"
exit "${fail}"
