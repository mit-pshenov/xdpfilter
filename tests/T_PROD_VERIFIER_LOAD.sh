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
# FATAL insn-count gate (design §5.67 / §6.83, B37-1 — promoted from the prior
# SHOULD-level informational read; this CONSCIOUSLY REVERSES D-mvp-4.23-H3-PRODOBJ
# "the 3658-insn count is an OPTIONAL informational assert … NOT a hard gate"
# and §5.63 verifiable-invariant item 8, both marked SUPERSEDED/RETIRED inline,
# per [[impl-role-discipline]] — a sanctioned reversal, NOT silent drift):
#   On the rc==0 path we measure the xdp-section INSTRUCTION-LINE count of the
#   shipped object via llvm-objdump (the project-canonical 3658 source per
#   D-mvp-4.27-INSN-SOURCE — NOT the post-verifier xlated-BYTE value the script
#   used to print, which is ~30-40 KB and kernel/verifier-version dependent),
#   and FATAL-assert it equals ${XDPMF_PROD_INSN_BASELINE:-3658}. This is the
#   byte-identity guard every "xdp 3658" claim (incl. the upcoming B34 split)
#   leans on. An INTENTIONAL codegen change re-baselines in one line via the
#   XDPMF_PROD_INSN_BASELINE escape hatch (named in the failure message), so the
#   gate is a tripwire, not a roadblock (guard #35; neutralises the original
#   "literal brittleness" concern).
#
# SKIP-SAFE (HG-3 / D-mvp-4.27-SKIP-SAFE): the insn assert fires ONLY on the
# rc==0 path AND only when the count was actually measured; if no llvm-objdump
# is present, or the count cannot be parsed, we print a NOTE and CONTINUE — a
# tooling-absence path NEVER becomes a hard FAIL. The whole-test SKIP-77 paths
# below (no bpftool / object not built / no passwordless sudo) are UNCHANGED.
# The post-verifier xlated-BYTE size MAY still be printed as a secondary
# informational NOTE (clearly labelled — it is NOT the 3658 baseline).
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

    # ── B37-1 FATAL insn-count gate (design §5.67 / §6.83) ────────────────
    # Measure the xdp-section INSTRUCTION-LINE count of the shipped object
    # (D-mvp-4.27-INSN-SOURCE: the project-canonical insn-count source — static
    # llvm-objdump of the .o, codegen/toolchain-pinned, NOT the running
    # kernel's post-verifier xlated bytes). FATAL-assert it == the baseline,
    # naming the XDPMF_PROD_INSN_BASELINE escape hatch on mismatch. SKIP-SAFE:
    # absent objdump / unparseable count → NOTE + continue (never FAIL).
    # §5.70 (MVP-4.30) B35 D-mvp-4.30-REBASELINE: re-baselined 3658 → 3437 (the
    # MEASURED post-pack count) — the SANCTIONED escape-hatch use for the
    # intentional ruleset_state map-schema VALUE-pack (NOT a silent weakening;
    # the gate stays FATAL at the NEW count). Correctness now held by
    # verdict-identity (T_*_ORACLE_AGREEMENT), not byte-identity.
    expected="${XDPMF_PROD_INSN_BASELINE:-3437}"
    objdump_bin=""
    for cand in llvm-objdump-19 llvm-objdump; do
        if command -v "${cand}" >/dev/null 2>&1; then objdump_bin="${cand}"; break; fi
    done
    if [[ -z "${objdump_bin}" ]]; then
        echo "  NOTE: no llvm-objdump available — insn-count sub-gate skipped" >&2
        echo "        for tooling absence (NOT a failure; D-mvp-4.27-SKIP-SAFE)" >&2
    else
        actual=$("${objdump_bin}" -d --section=xdp "${PROD_OBJ}" 2>/dev/null \
                 | grep -cE '^\s+[0-9a-f]+:' || true)
        if ! [[ "${actual}" =~ ^[0-9]+$ ]]; then
            echo "  NOTE: ${objdump_bin} produced an unparseable xdp-section count" >&2
            echo "        ('${actual}') — insn sub-gate skipped (NOT a failure)" >&2
        elif [[ "${actual}" -ne "${expected}" ]]; then
            echo "FAIL: xdp-section instruction-count ${actual} != baseline ${expected}" >&2
            echo "      this is an xdp-section instruction-count regression OR an" >&2
            echo "      intentional codegen change. The 3658 byte-identity guard" >&2
            echo "      (every 'xdp 3658' claim, incl. the B34 split) just tripped." >&2
            echo "      If this change is INTENTIONAL, re-baseline via" >&2
            echo "      XDPMF_PROD_INSN_BASELINE=${actual}" >&2
            fail=1
        else
            echo "  insn-count gate: xdp section == ${expected} instructions (datapath identity holds)"
        fi
    fi

    # Secondary informational NOTE (NOT the gate): the post-verifier xlated
    # BYTE size (~30-40 KB, kernel/verifier-version dependent) — explicitly
    # NOT the 3658 baseline (which is the objdump instruction-line count above).
    xlated_bytes=$(sudo -n bpftool prog show pinned "${PROBE_PIN}" 2>/dev/null \
            | grep -oE 'xlated [0-9]+B' | grep -oE '[0-9]+' | head -1 || true)
    if [[ -n "${xlated_bytes:-}" ]]; then
        echo "  NOTE: post-verifier xlated bytes ${xlated_bytes}B (NOT the 3658 baseline)"
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
