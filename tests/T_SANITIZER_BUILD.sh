#!/bin/bash
# T_SANITIZER_BUILD — design §6.8 / MVP-1.1A (per §5.18 sanitizer build).
#
# Setup    : fresh, isolated /tmp build dir configured with -DXDPMF_SANITIZERS=ON
#            so the default ${BUILD_DIR} is untouched (refactor-mode: 7 existing
#            tests still consume ${BUILD_DIR}).
# Trigger  :
#   1. cmake -S "${SOURCE_DIR}" -B "${ASAN_BUILD_DIR}" -DXDPMF_SANITIZERS=ON
#   2. cmake --build "${ASAN_BUILD_DIR}" --parallel   (must exit 0, no warnings)
#   3. setup_veth
#   4. <sanitized_xdpmacfilter> attach --iface veth_a --allow MAC_GOOD   (stderr → file)
#   5. inject MAC_GOOD on veth_b (reuse existing inject_eth helper)
#   6. read stats (reuse read_stats helper)
#   7. <sanitized_xdpmacfilter> detach --iface veth_a                    (stderr → same file)
#   8. cleanup_veth (via trap)
# Outcome  : ALL must hold
#   - build exits 0 with no compiler warnings (§5.12 policy)
#   - attach + detach exit 0
#   - stats[STAT_PASS] == 1  (positive correctness check — confirms the
#     sanitized binary actually executed the BPF userspace hot path)
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

# ── Step 4: attach via sanitized binary, capture stderr ──────────────────
echo "=== T_SANITIZER_BUILD: attach (sanitized) iface=${IFACE_A} allow=${MAC_GOOD}"
set +e
sudo -n "${SANITIZED_LOADER}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" \
    2>>"${STDERR_FILE}"
attach_rc=$?
set -e
sleep 0.3

# ── Step 5: inject one well-formed allowed frame ────────────────────────
inject_eth "${IFACE_B}" "${MAC_GOOD}" "${MAC_DST}"
# Per §5.21 C1: replace post-inject sleep with stats-sum poll.
wait_for_stats_sum "${IFACE_A}" 1 || true

# ── Step 6: read stats ──────────────────────────────────────────────────
read -r pass deny mal < <(read_stats)
echo "stats: PASS=${pass} DROP_DENY=${deny} DROP_MALFORMED=${mal}"

# ── Step 7: detach via sanitized binary, capture stderr ─────────────────
echo "=== T_SANITIZER_BUILD: detach (sanitized)"
set +e
sudo -n "${SANITIZED_LOADER}" detach --iface "${IFACE_A}" 2>>"${STDERR_FILE}"
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
    || { echo "FAIL: sanitized attach exit=${attach_rc} (expected 0)" >&2; fail=1; }
[[ "${detach_rc}" == "0" ]] \
    || { echo "FAIL: sanitized detach exit=${detach_rc} (expected 0)" >&2; fail=1; }

# Positive correctness check: the sanitized binary actually drove the
# BPF userspace hot path (not just exited cleanly without doing work).
# Per §6.8 only STAT_PASS is asserted in this test; the other slots are
# covered by §6.3–6.5.
[[ "${pass}" == "1" ]] \
    || { echo "FAIL: expected STAT_PASS=1, got ${pass}" >&2; fail=1; }

# THE key assertion: no sanitizer report in stderr.  Match is the failure
# condition (§6.8 "Negation form": a regex match means the test fails).
if grep -q -E 'AddressSanitizer|UndefinedBehavior' "${STDERR_FILE}" 2>/dev/null; then
    echo "FAIL: sanitizer report detected in captured stderr:" >&2
    grep -nE 'AddressSanitizer|UndefinedBehavior' "${STDERR_FILE}" >&2 || true
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_SANITIZER_BUILD"
exit "${fail}"
