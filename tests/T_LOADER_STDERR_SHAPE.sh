#!/bin/bash
# T_LOADER_STDERR_SHAPE — tester verification for design §6.84 / §5.67 B37-2.
#
# Written against the SPECIFICATION (design.md §5.67 Interfaces MUST corpus +
# Decisions D-mvp-4.27-Q1-A2 / -EXACTMATCH), NOT against impl's new
# T_LOADER_STDERR_GOLDEN.sh or its checked-in goldens. This is the tester's
# independent proof that the operator-facing loader stderr SHAPE (the
# greppable `xdpfilter:` / `error:` audit-ABI prefix, docs/FLEET_DEPLOYMENT.md)
# is pinned AND that the golden-diff MECHANISM has teeth.
#
# MUST corpus (no privilege, deterministic — §5.67 Interfaces):
#   1. bad trust_model  -> exit 9, first line `^xdpfilter: config error:`
#                          (exercises the ConfigError sentinel-suppression
#                           branch: NO bare `error:` prefix)
#   2. missing config   -> exit 1, first line `^xdpfilter: config error:`
#   3. usage error      -> exit 1, an `^error:` line (the CliError parse arm)
#
# NEGATION CONTROL (golden-diff teeth): capture a clean shape, exact-match it
# against itself (must be empty), then against a one-line-mutated copy (must be
# non-empty). A deliberately-wrong golden MUST fail the diff — this is the core
# property §6.84's gate must have.
#
# SMOKE: the loader binary launches and emits non-empty stderr on each error.
#
# SKIP discipline: SKIP 77 if the loader binary is not built. NO RESOURCE_LOCK
# (D-mvp-4.27-Q1-NOLOCK): every MUST-corpus path throws at CLI/env/config parse
# BEFORE `--iface lo` is resolved or any bpffs/kernel op runs.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader 2>/dev/null) || {
    echo "SKIP: xdpfilter loader binary not built under ${BUILD_DIR}" >&2
    exit 77
}
echo "loader=${LOADER_BIN}"

cap1=$(mktemp /tmp/xdpmf-stderrshape-1.XXXXXX)
cap2=$(mktemp /tmp/xdpmf-stderrshape-2.XXXXXX)
cap3=$(mktemp /tmp/xdpmf-stderrshape-3.XXXXXX)
gold_ok=$(mktemp /tmp/xdpmf-stderrshape-gok.XXXXXX)
gold_bad=$(mktemp /tmp/xdpmf-stderrshape-gbad.XXXXXX)
trap 'rm -f "${cap1}" "${cap2}" "${cap3}" "${gold_ok}" "${gold_bad}"' EXIT

fail=0

dump() { echo "--- stderr ---"; cat "$1" >&2 || true; echo "--- end stderr ---"; }

# ── Shape 1: bad trust_model -> exit 9, ConfigError prefix (sentinel-suppress)
echo "=== Shape 1: XDPMF_TRUST_MODEL=garbage_value attach --iface lo --allow <mac>"
set +e
XDPMF_TRUST_MODEL=garbage_value \
    "${LOADER_BIN}" attach --iface lo --allow 02:00:00:00:00:01 2>"${cap1}"
rc1=$?
set -e
echo "rc1=${rc1}"; dump "${cap1}"
if [[ "${rc1}" -ne 9 ]]; then
    echo "FAIL[1a]: expected exit 9 (ConfigError), got ${rc1}" >&2; fail=1
fi
if [[ ! -s "${cap1}" ]]; then
    echo "FAIL[1-smoke]: shape 1 produced empty stderr" >&2; fail=1
fi
if ! head -n1 "${cap1}" | grep -qE -- '^xdpfilter: config error:'; then
    echo "FAIL[1b]: shape 1 first stderr line is not '^xdpfilter: config error:'" >&2; fail=1
fi
# sentinel-suppression branch active: ConfigError must NOT render the bare
# `error:` prefix (that branch is the most refactor-fragile per §5.26).
if head -n1 "${cap1}" | grep -qE -- '^error:'; then
    echo "FAIL[1c]: shape 1 rendered a bare '^error:' prefix — ConfigError" >&2
    echo "          sentinel-suppression branch is NOT active (regression)" >&2
    fail=1
fi

# ── Shape 2: missing config -> exit 1, ConfigError prefix ────────────────
MISSING_CFG="/nonexistent/xdpmf-stderrshape-$$-$(date +%s).yaml"
[[ ! -e "${MISSING_CFG}" ]] || { echo "FAIL: chosen MISSING_CFG ${MISSING_CFG} exists" >&2; exit 1; }
echo "=== Shape 2: apply -f ${MISSING_CFG} --iface lo"
set +e
"${LOADER_BIN}" apply -f "${MISSING_CFG}" --iface lo 2>"${cap2}"
rc2=$?
set -e
echo "rc2=${rc2}"; dump "${cap2}"
if [[ "${rc2}" -ne 1 ]]; then
    echo "FAIL[2a]: expected exit 1 (missing config / kExitUsageErr), got ${rc2}" >&2; fail=1
fi
if [[ ! -s "${cap2}" ]]; then
    echo "FAIL[2-smoke]: shape 2 produced empty stderr" >&2; fail=1
fi
if ! head -n1 "${cap2}" | grep -qE -- '^xdpfilter: config error:'; then
    echo "FAIL[2b]: shape 2 first stderr line is not '^xdpfilter: config error:'" >&2; fail=1
fi

# ── Shape 3: usage / CLI parse error -> exit 1, `^error:` prefix ─────────
# A malformed MAC is a deterministic CliError parse error (guaranteed exit 1,
# cf. T_CLI_BAD_MAC) routed through main.cpp's `error: <what>` arm.
echo "=== Shape 3: attach --iface lo --allow not-a-mac (CLI parse error)"
set +e
"${LOADER_BIN}" attach --iface lo --allow not-a-mac 2>"${cap3}"
rc3=$?
set -e
echo "rc3=${rc3}"; dump "${cap3}"
if [[ "${rc3}" -ne 1 ]]; then
    echo "FAIL[3a]: expected exit 1 (CLI usage error), got ${rc3}" >&2; fail=1
fi
if [[ ! -s "${cap3}" ]]; then
    echo "FAIL[3-smoke]: shape 3 produced empty stderr" >&2; fail=1
fi
if ! grep -qE -- '^error:' "${cap3}"; then
    echo "FAIL[3b]: shape 3 stderr lacks an '^error:' line (CliError parse arm)" >&2; fail=1
fi

# ── NEGATION CONTROL: the golden-diff mechanism must discriminate ────────
# Use the clean, usage-dump-free shape 1 capture as a deterministic golden.
echo
echo "=== NEGATION CONTROL: golden-diff teeth"
cp "${cap1}" "${gold_ok}"
cp "${cap1}" "${gold_bad}"
printf 'DELIBERATE-DRIFT-LINE\n' >>"${gold_bad}"

if ! diff -u "${gold_ok}" "${cap1}" >/dev/null 2>&1; then
    echo "FAIL[neg-smoke]: an EXACT golden failed to match its own capture" >&2
    echo "                 (diff mechanism broken)" >&2
    fail=1
else
    echo "OK[neg-smoke]: exact golden matches capture (diff empty)"
fi
if diff -u "${gold_bad}" "${cap1}" >/dev/null 2>&1; then
    echo "FAIL[neg]: a DELIBERATELY-WRONG golden MATCHED the capture -> the" >&2
    echo "           golden-diff gate has NO teeth (a drifted message would pass)" >&2
    fail=1
else
    echo "OK[neg]: wrong golden fails the diff -> golden gate has teeth (guard #35)"
fi

# ── Best-effort cross-check of impl's checked-in goldens (non-fatal) ─────
# If impl shipped tests/fixtures/loader_stderr_*.golden, confirm each is
# non-empty and report whether it exact-matches one of the captured shapes.
# This is advisory (filename->shape mapping is impl's finalize choice per
# §5.67 verifiable-invariant 5); a mismatch is a NOTE, not a FAIL, but a
# present-yet-empty golden is flagged.
shopt -s nullglob
goldens=( "${TEST_DIR}"/fixtures/loader_stderr_*.golden )
shopt -u nullglob
if [[ ${#goldens[@]} -eq 0 ]]; then
    echo "NOTE: no impl goldens (tests/fixtures/loader_stderr_*.golden) found yet" >&2
else
    for g in "${goldens[@]}"; do
        if [[ ! -s "${g}" ]]; then
            echo "FAIL[golden-empty]: impl golden $(basename "${g}") is present but EMPTY" >&2
            fail=1
            continue
        fi
        if   diff -u "${g}" "${cap1}" >/dev/null 2>&1; then echo "NOTE: $(basename "${g}") exact-matches shape 1"
        elif diff -u "${g}" "${cap2}" >/dev/null 2>&1; then echo "NOTE: $(basename "${g}") exact-matches shape 2"
        elif diff -u "${g}" "${cap3}" >/dev/null 2>&1; then echo "NOTE: $(basename "${g}") exact-matches shape 3"
        else echo "NOTE: $(basename "${g}") matches none of the 3 captures verbatim (may be normalized/combined)"; fi
    done
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_LOADER_STDERR_SHAPE"
exit "${fail}"
