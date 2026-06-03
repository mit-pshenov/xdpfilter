#!/bin/bash
# T_PROD_VERIFIER_LOAD — design §6.80 (MVP-4.23 / §5.63, TEST-H3 / C-1).
#
# Standalone verifier-load of the PRODUCTION xdpfilter.bpf.o (the SHIPPED
# 9-axis program), closing TEST-H3: the only pre-existing standalone
# "verifier" test (T_BITVEC_VERIFIER_LOAD) loads the 4-axis PROTOTYPE, so a
# verifier-complexity / stack-budget regression in the real datapath was
# invisible short of the heavyweight full-attach path.
#
# This test clones the T_BITVEC_VERIFIER_LOAD standalone-load MECHANISM but:
#   - points at ${BUILD_DIR}/xdpfilter.bpf.o (the production object), and
#   - drops the harness/attach/netns/veth path ENTIRELY (D-mvp-4.23-H3-NOLOCK):
#     it is a pure `bpftool prog load <prod_obj> <PID-unique pin> type xdp`
#     to a bpffs-root pin that is a SIBLING of — never inside — the project's
#     pin dir, so it cannot race any veth-touching or bpffs-dir test. Hence
#     NO RESOURCE_LOCK and no ${NSEXEC}.
#
# Assertion: the production object loads with rc=0 (the in-kernel BPF
# verifier accepts the shipped 9-axis program). This is reviewer special-
# attention item (a) (datapath-identity / complexity-regression canary).
#
# Sanity floor:
#   * SMOKE    — the load itself IS the smoke (object initialises / verifies).
#   * NEGATION — the assertion is rc==0; a verifier REJECT (rc!=0 — a future
#                complexity/stack-budget regression in xdpfilter.bpf.c) makes
#                this gate FAIL LOUDLY with the verifier log surfaced (head-
#                truncated to stderr), so the test machinery demonstrably
#                distinguishes a verifying object from a rejected one.
#
# Informational (NON-fatal, SHOULD-level per D-mvp-4.23-H3-PRODOBJ): the xdp
# program section is 3658 insns at the MVP-4.22/4.23 baseline. We report the
# loaded insn count for a complexity-regression note; rc==0 is the contract,
# the count is NOT a hard assertion (avoids literal brittleness).
#
# SKIP 77 paths (tooling/precondition absent, not a failure): `bpftool`
# absent, xdpfilter.bpf.o not built, or passwordless sudo unavailable
# (CAP_BPF is needed to load).

set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v bpftool >/dev/null 2>&1 && ! sudo -n bpftool version >/dev/null 2>&1; then
    echo "SKIP: bpftool not available (needed for standalone prog load)" >&2
    exit 77
fi

PROBE_PIN="/sys/fs/bpf/xdpmf_prod_verifier_probe_$$"

# ── Locate the PRODUCTION object (add_bpf_object → <binary-dir>/<name>.bpf.o) ─
# Resolution order per §5.63 Interfaces: PROD_BPF_OBJ env → ${BUILD_DIR}/
# xdpfilter.bpf.o → recursive find under ${BUILD_DIR}.
find_prod_obj() {
    if [[ -n "${PROD_BPF_OBJ:-}" && -f "${PROD_BPF_OBJ}" ]]; then
        printf '%s\n' "${PROD_BPF_OBJ}"; return 0
    fi
    if [[ -f "${BUILD_DIR}/xdpfilter.bpf.o" ]]; then
        printf '%s\n' "${BUILD_DIR}/xdpfilter.bpf.o"; return 0
    fi
    local found
    found=$(find "${BUILD_DIR}" -maxdepth 5 -type f -name 'xdpfilter.bpf.o' 2>/dev/null | head -1 || true)
    [[ -n "${found}" ]] && { printf '%s\n' "${found}"; return 0; }
    return 1
}

PROD_OBJ=$(find_prod_obj || true)

if [[ -z "${PROD_OBJ}" ]]; then
    echo "SKIP: production xdpfilter.bpf.o not found under ${BUILD_DIR}" >&2
    echo "      (build first: cmake --build build)" >&2
    exit 77
fi

cleanup() {
    set +e
    sudo -n rm -f "${PROBE_PIN}" 2>/dev/null
    set -e
}
trap cleanup EXIT INT TERM HUP

fail=0

echo "=== bpftool prog load ${PROD_OBJ} ${PROBE_PIN} type xdp"
sudo -n rm -f "${PROBE_PIN}" 2>/dev/null || true
set +e
sudo -n bpftool prog load "${PROD_OBJ}" "${PROBE_PIN}" type xdp 2> >(head -c 8192 >&2)
rc=$?
set -e
echo "bpftool prog load rc=${rc}"

if [[ "${rc}" -eq 0 ]]; then
    echo "  verifier ACCEPTED the PRODUCTION 9-axis object (standalone load)"

    # Informational (SHOULD, NON-fatal): report the loaded xdp insn count.
    # Baseline is 3658 at MVP-4.22/4.23; a drift feeds a complexity-regression
    # note but is NOT a hard gate (D-mvp-4.23-H3-PRODOBJ).
    insns=$(sudo -n bpftool prog show pinned "${PROBE_PIN}" 2>/dev/null \
            | grep -oE 'xlated [0-9]+B' | grep -oE '[0-9]+' | head -1 || true)
    if [[ -n "${insns:-}" ]]; then
        echo "  NOTE: loaded xlated size ${insns}B (informational complexity signal)"
    fi
else
    echo "FAIL: verifier REJECTED the production xdpfilter.bpf.o (rc=${rc})" >&2
    echo "      the shipped 9-axis datapath did not verify on this kernel —" >&2
    echo "      a complexity / stack-budget regression has landed in" >&2
    echo "      src/bpf/xdpfilter.bpf.c. See verifier log above." >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_PROD_VERIFIER_LOAD (production xdpfilter.bpf.o loads+verifies on $(uname -r))"
exit "${fail}"
