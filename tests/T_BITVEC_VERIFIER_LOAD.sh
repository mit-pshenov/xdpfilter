#!/bin/bash
# T_BITVEC_VERIFIER_LOAD — design §6.46 (MVP-4.2 / §5.42).
#
# The empirical FEASIBILITY GATE (D-mvp-4.2-FFS-FEAS): does the bit-vector
# prototype datapath — four map lookups, OR-with-wildcard, AND-compose,
# a bounded #pragma-unroll port scan, and the `ffsll`-based first-match
# lowering — VERIFY on the 5.15 floor?
#
# Assertion: the prototype BPF object loads with rc=0 (verifier accepted).
#   - PASS path: `__builtin_ffsll(acc)-1` lowered cleanly OR the documented
#     bounded-scan fallback (D-mvp-4.2-FFS-FALLBACK) is in place. Either way
#     the SHIPPED prototype MUST make this green (PI-mvp-4.2-VERIFIER).
#   - This is reviewer special-attention item (a).
#
# Two acceptable load mechanisms per §6.46 — we try them in order:
#   (1) standalone `bpftool prog load bitvec_proto.bpf.o … type xdp` — the
#       purest verifier exercise, independent of the harness populate logic;
#   (2) `bitvec_harness populate <iface>` — the full load+populate+attach
#       path (also drives the program through BPF_PROG_LOAD).
# If NEITHER artifact is present → SKIP 77 (tooling absent, not a failure).
#
# Sanity floor:
#   * SMOKE    — the load itself IS the smoke (object initialises / verifies).
#   * NEGATION — the assertion is rc==0 and a non-empty/parseable load; a
#                verifier REJECT (rc!=0, the failure path) is exactly what
#                this gate is built to catch, so the test machinery
#                demonstrably distinguishes accept from reject (a rejected
#                object fails here loudly with the verifier log surfaced).
#
# Informational (feeds §5.42 complexity verdict, NON-fatal): scan the
# object for an unresolved `__ffsdi2`/`__ctzdi2` libcall. Its ABSENCE on a
# clean rc=0 = "FEAS held (ffsll lowered)"; its presence would have made
# the load FAIL anyway (so rc=0 already implies no unresolved libcall) —
# we report which lowering shipped, we do NOT fail on it.

set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

PROBE_PIN="/sys/fs/bpf/xdpmf_bitvec_verifier_probe"
PROTO_PIN_ROOT="/sys/fs/bpf/xdpmf-bitvec-proto"

# ── Locate the prototype object (add_bpf_object → <binary-dir>/<name>.bpf.o) ─
find_proto_obj() {
    if [[ -n "${BITVEC_BPF_OBJ:-}" && -f "${BITVEC_BPF_OBJ}" ]]; then
        printf '%s\n' "${BITVEC_BPF_OBJ}"; return 0
    fi
    local cand
    for cand in \
        "${BUILD_DIR}/bitvec_proto.bpf.o" \
        "${BUILD_DIR}/tests/bitvec/bitvec_proto.bpf.o" \
        "${BUILD_DIR}/bitvec/bitvec_proto.bpf.o" \
        "${BUILD_DIR}/tests/bitvec_proto.bpf.o"; do
        [[ -f "$cand" ]] && { printf '%s\n' "$cand"; return 0; }
    done
    local found
    found=$(find "${BUILD_DIR}" -maxdepth 5 -type f -name 'bitvec_proto.bpf.o' 2>/dev/null | head -1 || true)
    [[ -n "${found}" ]] && { printf '%s\n' "${found}"; return 0; }
    return 1
}

find_harness() {
    if [[ -n "${BITVEC_HARNESS:-}" && -x "${BITVEC_HARNESS}" ]]; then
        printf '%s\n' "${BITVEC_HARNESS}"; return 0
    fi
    local cand
    for cand in \
        "${BUILD_DIR}/tests/bitvec/bitvec_harness" \
        "${BUILD_DIR}/bitvec/bitvec_harness" \
        "${BUILD_DIR}/tests/bitvec_harness" \
        "${BUILD_DIR}/bitvec_harness"; do
        [[ -x "$cand" ]] && { printf '%s\n' "$cand"; return 0; }
    done
    local found
    found=$(find "${BUILD_DIR}" -maxdepth 5 -type f -executable -name bitvec_harness 2>/dev/null | head -1 || true)
    [[ -n "${found}" ]] && { printf '%s\n' "${found}"; return 0; }
    return 1
}

PROTO_OBJ=$(find_proto_obj || true)
HARNESS=$(find_harness || true)

if [[ -z "${PROTO_OBJ}" && -z "${HARNESS}" ]]; then
    echo "SKIP: neither bitvec_proto.bpf.o nor bitvec_harness found under ${BUILD_DIR}" >&2
    echo "      (impl deliverables not yet built; reconfigure + build first)" >&2
    exit 77
fi

cleanup() {
    set +e
    sudo -n rm -f "${PROBE_PIN}" 2>/dev/null
    if [[ -n "${HARNESS}" ]]; then ${NSEXEC} "${HARNESS}" detach "${IFACE_A}" 2>/dev/null; fi
    sudo -n rm -rf "${PROTO_PIN_ROOT}" 2>/dev/null
    cleanup_veth
    set -e
}
trap cleanup EXIT INT TERM HUP

setup_veth

fail=0
loaded=0

# ── Mechanism (1): standalone bpftool prog load ──────────────────────────
if [[ -n "${PROTO_OBJ}" ]]; then
    echo "=== bpftool prog load ${PROTO_OBJ} ${PROBE_PIN} type xdp"
    sudo -n rm -f "${PROBE_PIN}" 2>/dev/null || true
    set +e
    sudo -n bpftool prog load "${PROTO_OBJ}" "${PROBE_PIN}" type xdp 2> >(head -c 8192 >&2)
    rc=$?
    set -e
    echo "bpftool prog load rc=${rc}"
    if [[ "${rc}" -eq 0 ]]; then
        loaded=1
        echo "  verifier ACCEPTED the prototype object (standalone load)"
    else
        echo "FAIL: verifier REJECTED bitvec_proto.bpf.o (rc=${rc})" >&2
        echo "      the ffsll/AND/bounded-scan datapath did not verify on this kernel;" >&2
        echo "      per D-mvp-4.2-FFS-FALLBACK impl must activate the bounded-scan" >&2
        echo "      first-set-bit lowering so this gate goes green." >&2
        fail=1
    fi
    sudo -n rm -f "${PROBE_PIN}" 2>/dev/null || true

    # Informational libcall scan (NON-fatal; feeds the complexity verdict).
    if command -v llvm-objdump >/dev/null 2>&1; then
        if llvm-objdump -r "${PROTO_OBJ}" 2>/dev/null | grep -qE '__ffsdi2|__ctzdi2'; then
            echo "  NOTE: object references __ffsdi2/__ctzdi2 (ffsll did NOT inline) — FALLBACK territory"
        else
            echo "  NOTE: no unresolved __ffsdi2/__ctzdi2 libcall — FEAS held (ffsll lowered/inlined or scan fallback)"
        fi
    fi
fi

# ── Mechanism (2): harness populate (full load+populate+attach path) ─────
# Run as a corroborating check when the harness exists; if the standalone
# object was unavailable, this is the PRIMARY verifier gate.
if [[ -n "${HARNESS}" ]]; then
    echo "=== bitvec_harness populate ${IFACE_A}"
    set +e
    ${NSEXEC} "${HARNESS}" populate "${IFACE_A}" 2> >(head -c 8192 >&2)
    prc=$?
    set -e
    echo "harness populate rc=${prc}"
    if [[ "${prc}" -eq 0 ]]; then
        loaded=1
        echo "  verifier ACCEPTED the prototype object (harness populate path)"
    else
        echo "FAIL: bitvec_harness populate exit ${prc} — load/verify/attach failed" >&2
        fail=1
    fi
fi

if (( ! loaded )); then
    echo "FAIL: no load mechanism succeeded — prototype did not verify" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_BITVEC_VERIFIER_LOAD (prototype verifies on the 5.15 floor)"
exit "${fail}"
