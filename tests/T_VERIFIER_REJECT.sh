#!/bin/bash
# T_VERIFIER_REJECT — design §6.20 (MVP-2 Robust / §5.24 Q4 Option (c)).
#
# Asserts that handing the loader a verifier-rejected BPF object produces
# a clean LoaderError::LoadFailed (exit 2) with a recognizable
# verifier-shaped stderr substring, AND that no XDP-attach side-effects
# leak (no XDP attached to ${IFACE_A}, no orphan pin dir left behind).
#
# Bad fixture: tests/fixtures/mac_filter_bad.bpf.c (unbounded-shape loop
# bounded by `ctx->data_end - ctx->data`, NO `#pragma unroll`) —
# clang-compiles cleanly; only the kernel verifier rejects it at
# bpf()-syscall BPF_PROG_LOAD time. Path: ${BUILD_DIR}/mac_filter_bad.bpf.o
# (per existing `add_bpf_object` convention — outputs at
# ${CMAKE_BINARY_DIR}/<name>.bpf.o; see cmake/BpfBuild.cmake).
#
# Hybrid Q4 Option (c) per §5.24:
#   - SKIP probe FIRST: standalone `bpftool prog load` on the bad
#     fixture. If the kernel verifier UNEXPECTEDLY accepts → exit 77
#     (ctest SKIP) so a future kernel that silently verifies our
#     deliberate violation does not produce a confusing red failure.
#     §5.24 Q4 fallback is a manual fixture swap (OOB-deref backup
#     pattern), NOT a runtime auto-switch — preserves reproducibility.
#   - Active branch (verifier rejects, as expected on 5.15+): invoke our
#     loader with `XDPMF_BPF_OBJECT_PATH` env-var override pointing at
#     the bad fixture, assert exit 2 + recognizable stderr + no XDP
#     leak. `sudo -n -E` is load-bearing: -E preserves env-var across
#     the privilege boundary; without it the override is silently
#     discarded and the loader would attempt to load the real bpf.o
#     (which DOES verify — false PASS).
#
# Outcome assertions (ALL must hold on the active branch):
#   (A1) rc == 2 — LoadFailed (§4.1 exit-code table).
#   (A2) Stderr non-empty (a LoadFailed with empty stderr is undebuggable).
#   (A3) Stderr contains ≥1 of: `verifier` | `BPF_PROG_LOAD` |
#        `Invalid argument` (impl-shape flexibility per §5.24 stderr
#        discipline contract).
#   (A4) No XDP attached to ${IFACE_A} — load-fail happens before attach,
#        so the XDP slot must remain empty.
#   (A5) No orphan pin dir at /sys/fs/bpf/xdpmacfilter/${IFACE_A} —
#        either ensure_bpffs_dir wasn't reached or RAII rollback unwound
#        it (per §4.3 partially-created pins MUST be cleaned up).
#
# Cleanup (trap EXIT/INT/TERM/HUP, idempotent): SKIP-probe scratch pin
# removed, any residual xdpgeneric forced off, any orphan pin dir wiped,
# cleanup_veth, stderr tempfile removed.
#
# Coupling notes:
#   - Depends on the §5.24 kernel-version probe NOT firing on the test
#     host (modern kernel ≥ 5.15). If the probe false-positives and
#     this test exits 7 instead of 2, that surfaces a §5.24 impl bug,
#     not a §6.20 design flaw (per design §6.20 "Sanity coupling").
#   - Depends on impl honouring `XDPMF_BPF_OBJECT_PATH` env-var override
#     symmetrically in attach(). If the override is ignored, the loader
#     loads the real (verifier-clean) program and rc=0 — surfaces as a
#     FAIL[A1] with `case 0`.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
BAD_OBJ="${BUILD_DIR}/mac_filter_bad.bpf.o"
# Per design §6.20: literal pin path `/sys/fs/bpf/xdpmf_verifier_probe`.
# RESOURCE_LOCK xdp_fixture in tests/CMakeLists.txt serializes this test,
# so no PID-suffix collision risk; trap-driven cleanup wipes on EXIT.
PROBE_PIN="/sys/fs/bpf/xdpmf_verifier_probe"
stderr_file=$(mktemp /tmp/xdpmf-verifier-reject-stderr.XXXXXX)

cleanup_verifier_reject() {
    set +e
    # SKIP-probe scratch pin (may not exist; -f swallows ENOENT).
    sudo -n rm -f "${PROBE_PIN}" 2>/dev/null
    # Defensive: if active branch somehow attached, force xdpgeneric off.
    sudo -n ip link set "${IFACE_A}" xdpgeneric off 2>/dev/null
    # Defensive: remove any orphan pin dir for ${IFACE_A}.
    sudo -n rm -rf "${PIN_DIR}" 2>/dev/null
    cleanup_veth
    rm -f "${stderr_file}"
    set -e
}
trap cleanup_verifier_reject EXIT INT TERM HUP

# ── Fixture build-artifact sanity ────────────────────────────────────────
# Hard failure if the .bpf.o is missing — that means add_bpf_object
# wiring (mac_filter_bad in tests/CMakeLists.txt) is broken; surface
# loudly rather than letting bpftool error message lead the diagnosis.
[[ -f "${BAD_OBJ}" ]] \
    || { echo "FAIL: bad fixture missing at ${BAD_OBJ}" >&2
         echo "       (expected build artifact from add_bpf_object mac_filter_bad" >&2
         echo "        in tests/CMakeLists.txt; cmake/BpfBuild.cmake places" >&2
         echo "        outputs at \${CMAKE_BINARY_DIR}/<name>.bpf.o)" >&2
         exit 1; }

setup_veth

# ─────────────────────────────────────────────────────────────────────────
# SKIP PROBE — standalone `bpftool prog load` on the bad fixture.
# If exit 0 → verifier on this kernel UNEXPECTEDLY accepts our deliberate
#   violation (future-kernel surprise) → SKIP this test with exit 77,
#   per §5.24 Q4 Option (c) "degrades gracefully" contract.
# If non-zero → verifier rejected as expected; proceed to active branch.
# ─────────────────────────────────────────────────────────────────────────
echo "=== SKIP probe: bpftool prog load ${BAD_OBJ} ${PROBE_PIN} type xdp"
sudo -n rm -f "${PROBE_PIN}" 2>/dev/null || true
set +e
sudo -n bpftool prog load "${BAD_OBJ}" "${PROBE_PIN}" type xdp 2>/dev/null
skip_rc=$?
set -e
echo "SKIP-probe rc=${skip_rc}"

if [[ "${skip_rc}" -eq 0 ]]; then
    echo "SKIP: verifier on this kernel ACCEPTED the bad fixture — test inapplicable" >&2
    echo "      (the unbounded-loop violation may have been accepted by a newer" >&2
    echo "       verifier; swap mac_filter_bad.bpf.c to OOB-deref backup pattern" >&2
    echo "       per §5.24 Q4 documented fallback — manual update, no auto-switch.)" >&2
    # Probe pin was created by the load; remove so it doesn't survive SKIP.
    sudo -n rm -f "${PROBE_PIN}" 2>/dev/null || true
    exit 77
fi
# Defensive: SKIP probe may have left a partial pin even on failure
# (unlikely but cheap insurance). Wipe before the active branch.
sudo -n rm -f "${PROBE_PIN}" 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────
# ACTIVE BRANCH — invoke our loader with XDPMF_BPF_OBJECT_PATH override.
# Expected: rc=2 (LoadFailed) + recognizable verifier-shape stderr +
# zero XDP / pin-dir side-effects.
# ─────────────────────────────────────────────────────────────────────────
echo "=== ACTIVE: XDPMF_BPF_OBJECT_PATH=${BAD_OBJ} loader attach --iface ${IFACE_A}"
set +e
XDPMF_BPF_OBJECT_PATH="${BAD_OBJ}" \
    sudo -n -E "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" \
    2> "${stderr_file}"
rc=$?
set -e
echo "loader rc=${rc}"
# libbpf dumps the FULL verifier register-state log to stderr on
# LoadFailed — often 100+ MB. Echoing the whole capture into ctest
# output blows up test-run.log AND eats the test TIMEOUT budget. Show
# head + tail only (each enough to capture the canonical libbpf-side
# wrappers + the trailing impl-side error wrap); full capture stays
# in ${stderr_file} until the trap removes it.
stderr_bytes=$(stat -c '%s' "${stderr_file}" 2>/dev/null || echo "?")
echo "--- captured stderr (size=${stderr_bytes} bytes; HEAD 4KB) ---"
head -c 4096 "${stderr_file}" >&2 || true
echo "--- (… verifier log trimmed for log brevity …) TAIL 4KB ---" >&2
tail -c 4096 "${stderr_file}" >&2 || true
echo "--- end stderr ---"

fail=0

# (A1) Exit code MUST be 2 — LoaderError::LoadFailed (§4.1).
if [[ "${rc}" != 2 ]]; then
    echo "FAIL[A1]: expected rc=2 (LoadFailed), got rc=${rc}" >&2
    case "${rc}" in
        0) echo "          rc=0 — loader silently accepted a verifier-rejected program," >&2
           echo "                 OR XDPMF_BPF_OBJECT_PATH override was ignored (real .bpf.o loaded)" >&2 ;;
        3) echo "          rc=3 (AttachFailed) — verifier reject leaked as attach error;" >&2
           echo "                 classify() bug in §5.24 impl path" >&2 ;;
        6) echo "          rc=6 (Permission) — sudo/CAP issue, not verifier reject" >&2 ;;
        7) echo "          rc=7 (KernelUnsupported) — §5.24 kernel-version probe false-positive" >&2
           echo "                 on a kernel new enough to be testing the verifier-reject path;" >&2
           echo "                 that is a §5.24 impl bug, not a §6.20 design flaw" >&2 ;;
        8) echo "          rc=8 (PathRefused) — wrong axis; the .bpf.o path is fine, the program is bad" >&2 ;;
    esac
    fail=1
fi

# (A2) Stderr MUST be non-empty (a LoadFailed with no diagnostic is undebuggable).
if [[ ! -s "${stderr_file}" ]]; then
    echo "FAIL[A2]: stderr empty — loader produced no diagnostic on LoadFailed" >&2
    fail=1
fi

# (A3) Stderr MUST contain at least one of the canonical verifier-reject
# substrings. Impl-shape flexibility: the loader may emit any of the
# listed shapes depending on whether it wraps libbpf's message or emits
# its own. Per §5.24 stderr discipline + EDIT-11 (broadened to match
# libbpf 1.x wording — `BPF program load failed` / `PROG LOAD LOG`
# (spaces, not underscores) / `BPF object load failed` are the actual
# strings emitted; original `BPF_PROG_LOAD` was the syscall-name guess
# that does not appear in libbpf 1.x output).
if ! grep -q -E -- 'BPF program load failed|BPF object load failed|PROG LOAD LOG|verifier|Invalid argument' "${stderr_file}"; then
    echo "FAIL[A3]: stderr contains none of: 'BPF program load failed', 'BPF object load failed', 'PROG LOAD LOG', 'verifier', 'Invalid argument'" >&2
    fail=1
fi

# (A4) No XDP attached on ${IFACE_A}. Load-fail must happen before attach.
attached_id=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
if [[ -n "${attached_id}" ]]; then
    echo "FAIL[A4]: XDP unexpectedly attached after LoadFailed (prog_id=${attached_id})" >&2
    fail=1
fi

# (A5) No orphan pin dir at ${PIN_DIR}.
# Per §4.3: "On exception during attach(), partially-created bpffs pins
# MUST be cleaned up (RAII rollback)." Sudo for the test so /sys/fs/bpf
# mode-1700 doesn't false-negative as "doesn't exist".
if sudo -n test -e "${PIN_DIR}"; then
    echo "FAIL[A5]: orphan pin dir ${PIN_DIR} remained after LoadFailed" >&2
    sudo -n ls -la "${PIN_DIR}" >&2 || true
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_VERIFIER_REJECT"
exit "${fail}"
