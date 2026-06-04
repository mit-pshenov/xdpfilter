#!/bin/bash
# T_INSN_BASELINE_GATE — tester verification for design §6.83 / §5.67 B37-1.
#
# Written against the SPECIFICATION (design.md §5.67 Interfaces +
# DataStructures + TestStrategy item 1), NOT against impl's edited
# T_PROD_VERIFIER_LOAD.sh. This is the tester's independent proof that the
# promoted BPF instruction-stream gate is REAL (fail-loud + escape-hatch),
# plus a standalone always-on datapath-identity fence.
#
# Two responsibilities:
#
#  (A) STANDALONE REGRESSION FENCE  (smoke / no privilege)
#      The shipped xdp-section objdump instruction-LINE count equals the
#      baseline (default 3658) — this is PI-mvp-4.27-DATAPATH-IDENTICAL,
#      the byte-identity guard every "xdp 3658" claim leans on, measured
#      with the project-canonical command
#        llvm-objdump -d --section=xdp <obj> | grep -cE '^\s+[0-9a-f]+:'
#      It is fully tester-controlled and independent of impl. The same
#      XDPMF_PROD_INSN_BASELINE escape hatch (design §5.67 DataStructures)
#      is honoured so an INTENTIONAL re-baseline never false-fails here.
#
#  (B) GATE-HAS-TEETH  (negation control + escape-hatch proof)
#      Drive impl's promoted gate (tests/T_PROD_VERIFIER_LOAD.sh, which per
#      §5.67 consumes XDPMF_PROD_INSN_BASELINE) with a DELIBERATELY WRONG
#      baseline and confirm it FAILS LOUD (exit != 0 and != 77); then with
#      the CORRECT (measured) baseline and confirm it PASSES. This proves
#      the gate is a tripwire, not decorative, AND that the escape hatch
#      governs the verdict.
#
# SKIP discipline (HG-3 / PI-mvp-4.27-SKIP-PRESERVED): tooling/precondition
# absence is NEVER a hard FAIL.
#   - prod object not built          -> SKIP 77 (whole test)
#   - llvm-objdump absent            -> nothing to measure -> SKIP 77
#   - impl gate's privileged bpftool path unavailable (inner exits 77)
#                                    -> teeth sub-checks INCONCLUSIVE, NOT FAIL
#   - impl gate not present yet      -> teeth sub-checks INCONCLUSIVE, NOT FAIL
#                                       (Part A fence still runs)
#
# NO RESOURCE_LOCK (D-mvp-4.23-H3-NOLOCK): the inner gate pins a PID-unique
# bpffs sibling path, touches no iface / no shared fixture.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

fail=0

# ── Resolve the production object (mirror T_PROD_VERIFIER_LOAD's wiring) ──
PROD_OBJ="${PROD_BPF_OBJ:-${BUILD_DIR}/xdpfilter.bpf.o}"
if [[ ! -f "${PROD_OBJ}" ]]; then
    echo "SKIP: production object not built at ${PROD_OBJ}" >&2
    echo "      (build the xdpfilter.bpf.o target, then re-run)" >&2
    exit 77
fi

# ── Locate llvm-objdump (canonical insn-source per D-mvp-4.27-INSN-SOURCE) ─
OBJDUMP=""
for c in llvm-objdump-19 llvm-objdump; do
    if command -v "$c" >/dev/null 2>&1; then OBJDUMP="$c"; break; fi
done
if [[ -z "${OBJDUMP}" ]]; then
    echo "SKIP: no llvm-objdump available — insn-count cannot be measured" >&2
    echo "      (skip-safe per HG-3: tooling absence is not a regression)" >&2
    exit 77
fi

# The expected baseline honours the SAME escape hatch the gate exposes, so an
# intentional re-baseline (XDPMF_PROD_INSN_BASELINE=<N>) governs uniformly.
# §5.70 (MVP-4.30) B35 D-mvp-4.30-REBASELINE: re-baselined 3658 → 3437 (the
# MEASURED post-pack count) for the intentional ruleset_state map-schema
# VALUE-pack — the sanctioned escape-hatch use; Part-B (wrong-baseline → FAIL)
# still proves the gate keeps its teeth at the NEW count.
EXPECTED="${XDPMF_PROD_INSN_BASELINE:-3437}"

# ── Part A: STANDALONE datapath-identity fence ───────────────────────────
echo "=== Part A: objdump xdp-section instruction-line count vs baseline ${EXPECTED}"
ACTUAL=$("${OBJDUMP}" -d --section=xdp "${PROD_OBJ}" | grep -cE '^\s+[0-9a-f]+:')
echo "measured actual=${ACTUAL}  expected=${EXPECTED}  (obj=${PROD_OBJ})"
if ! [[ "${ACTUAL}" =~ ^[0-9]+$ ]]; then
    echo "SKIP: objdump produced an unparseable count ('${ACTUAL}')" >&2
    echo "      (skip-safe: cannot assert an unmeasured quantity)" >&2
    exit 77
fi
if [[ "${ACTUAL}" -ne "${EXPECTED}" ]]; then
    echo "FAIL[A]: xdp-section instruction-line count ${ACTUAL} != baseline ${EXPECTED}" >&2
    echo "         this is an xdp-section instruction-count regression OR an" >&2
    echo "         intentional codegen change (PI-mvp-4.27-DATAPATH-IDENTICAL)." >&2
    echo "         if intentional, re-baseline via XDPMF_PROD_INSN_BASELINE=${ACTUAL}" >&2
    fail=1
else
    echo "OK[A]: datapath-identity fence holds (count == ${EXPECTED})"
fi

# ── Part B: prove impl's gate has TEETH + the escape hatch governs ────────
GATE="${TEST_DIR}/T_PROD_VERIFIER_LOAD.sh"
if [[ ! -f "${GATE}" ]]; then
    echo "NOTE[B]: impl gate ${GATE} not present — teeth sub-check INCONCLUSIVE" >&2
    echo "         (Part A fence still ran; not a FAIL)" >&2
    [[ "${fail}" == 0 ]] && echo "PASS: T_INSN_BASELINE_GATE (Part A only)"
    exit "${fail}"
fi

gate_out=$(mktemp /tmp/xdpmf-insngate-out.XXXXXX)
trap 'rm -f "${gate_out}"' EXIT

# Choose a baseline GUARANTEED to differ from the real count.
WRONG=$(( ACTUAL + 1 ))

echo
echo "=== Part B negation: run gate with WRONG baseline ${WRONG} (expect FAIL-loud)"
set +e
XDPMF_PROD_INSN_BASELINE="${WRONG}" bash "${GATE}" >"${gate_out}" 2>&1
rc_wrong=$?
set -e
echo "gate rc(wrong)=${rc_wrong}"
sed 's/^/  gate| /' "${gate_out}" >&2 || true
case "${rc_wrong}" in
    0)  echo "FAIL[B-teeth]: gate PASSED with a deliberately-WRONG baseline (${WRONG})" >&2
        echo "              -> the insn gate is DECORATIVE (no teeth); a codegen drift" >&2
        echo "              would pass silently. (guard #35)" >&2
        fail=1 ;;
    77) echo "NOTE[B-teeth]: gate SKIPPED (rc=77; privileged bpftool/object/sudo path" >&2
        echo "              unavailable) -> teeth INCONCLUSIVE in this env, NOT a FAIL" >&2 ;;
    *)  echo "OK[B-teeth]: gate FAILED LOUD (rc=${rc_wrong}) on the wrong baseline -> teeth confirmed" ;;
esac

echo
echo "=== Part B hatch: run gate with CORRECT baseline ${ACTUAL} (expect PASS or SKIP)"
set +e
XDPMF_PROD_INSN_BASELINE="${ACTUAL}" bash "${GATE}" >"${gate_out}" 2>&1
rc_right=$?
set -e
echo "gate rc(right)=${rc_right}"
sed 's/^/  gate| /' "${gate_out}" >&2 || true
case "${rc_right}" in
    0)  echo "OK[B-hatch]: gate PASSED with the measured count as baseline -> escape hatch governs" ;;
    77) echo "NOTE[B-hatch]: gate SKIPPED (rc=77) -> hatch proof INCONCLUSIVE in this env, NOT a FAIL" >&2 ;;
    *)  echo "FAIL[B-hatch]: gate FAILED (rc=${rc_right}) when the baseline EQUALS the measured" >&2
        echo "              count (${ACTUAL}) -> escape hatch broken or gate over-strict" >&2
        fail=1 ;;
esac

# Cross-consistency: when BOTH runs were conclusive, wrong must fail-loud AND
# right must pass — i.e. the verdict actually tracks the hatch value.
if [[ "${rc_wrong}" != 77 && "${rc_right}" != 77 ]]; then
    if [[ "${rc_wrong}" -eq 0 || "${rc_right}" -ne 0 ]]; then
        echo "FAIL[B-track]: gate verdict does not track the baseline (wrong rc=${rc_wrong}," >&2
        echo "              right rc=${rc_right}); a real gate FAILS wrong & PASSES right." >&2
        fail=1
    else
        echo "OK[B-track]: gate verdict tracks the escape-hatch baseline (wrong FAILS, right PASSES)"
    fi
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_INSN_BASELINE_GATE"
exit "${fail}"
