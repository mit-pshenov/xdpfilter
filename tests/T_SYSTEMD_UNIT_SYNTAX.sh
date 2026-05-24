#!/bin/bash
# T_SYSTEMD_UNIT_SYNTAX — design §6.32 (MVP-3.3 / §5.28).
#
# `systemd-analyze verify systemd/xdpmacfilter@.service` accepts the unit
# (positive case) AND rejects a deliberately-broken copy (negation control).
#
# Per §6.32 Observable outcome:
#   - Exit code 0 on the canonical unit.
#   - Stderr EMPTY of warnings (info-only lines via grep -v filter).
#
# Anti-theatricality NEGATION control (REQUIRED per spec): also run the
# verifier against a copy with `Type=oneshot` substituted to `Type=invalid`
# and assert exit-nonzero. Proves the verifier is actually verifying,
# not just rubber-stamping.
#
# Sanity-floor smoke: the canonical unit file MUST exist before any
# check (file-existence baseline).
#
# NO sudo, NO veth — read-only systemd-analyze.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

# SKIP-77 if systemd-analyze missing (extremely rare; design §6.32 SKIP cond).
if ! command -v systemd-analyze >/dev/null 2>&1; then
    echo "SKIP: systemd-analyze not in PATH" >&2
    exit 77
fi

# §5.28 tests/CMakeLists.txt amendment: SYSTEMD_UNIT_SRC carries the source
# path. Fallback for ad-hoc invocation.
SYSTEMD_UNIT_SRC="${SYSTEMD_UNIT_SRC:-${SOURCE_DIR}/systemd/xdpmacfilter@.service}"

# Sanity / smoke: the unit file must exist.
if [[ ! -f "${SYSTEMD_UNIT_SRC}" ]]; then
    echo "FAIL: canonical unit file not found at ${SYSTEMD_UNIT_SRC}" >&2
    exit 1
fi

TMPDIR=$(mktemp -d /tmp/xdpmf-systemd-syntax.XXXXXX)
trap 'rm -rf "${TMPDIR}"' EXIT

# Per §6.32 trigger: stage the unit into TMPDIR preserving the canonical
# template name; verify via instance form (arbitrary iface name).
stage_unit="${TMPDIR}/xdpmacfilter@.service"
cp "${SYSTEMD_UNIT_SRC}" "${stage_unit}"

fail=0

# ── POSITIVE case ────────────────────────────────────────────────────────
echo "=== POSITIVE: systemd-analyze verify on canonical unit"
stdout_pos="${TMPDIR}/stdout.pos"
stderr_pos="${TMPDIR}/stderr.pos"
set +e
systemd-analyze verify "${TMPDIR}/xdpmacfilter@verifycheck.service" \
    >"${stdout_pos}" 2>"${stderr_pos}"
rc_pos=$?
set -e
echo "rc_pos=${rc_pos}"
echo "--- stdout (pos) ---"
cat "${stdout_pos}" || true
echo "--- stderr (pos) ---"
cat "${stderr_pos}" >&2 || true
echo "--- end (pos) ---"

if [[ "${rc_pos}" -ne 0 ]]; then
    echo "FAIL[P1]: systemd-analyze verify (positive) exit ${rc_pos} (expected 0)" >&2
    fail=1
fi

# Stderr SHOULD be free of warnings/errors. Some systemd versions emit
# informational/progress lines like "Loading …" or "Created slice …" on
# stderr; we filter those out and assert nothing else remains.
#
# WARNINGS we MUST surface: "Unknown key", "Unknown lvalue", "Failed to",
# "Cannot add dependency", "is not absolute", any line beginning with
# "Warning:" / "Error:" / containing "[!!]".
warn_lines=$(grep -E -v \
    -e '^(Loading|Created|Started|Stopped|Reloading)' \
    -e '^$' \
    "${stderr_pos}" || true)
if [[ -n "${warn_lines}" ]]; then
    echo "FAIL[P2]: systemd-analyze verify (positive) emitted warnings/errors:" >&2
    printf '  > %s\n' "${warn_lines}" >&2
    fail=1
fi

# ── NEGATION control ────────────────────────────────────────────────────
# REMOVE the entire [Service] section. A .service unit without [Service]
# is structurally invalid (no ExecStart, no service type) — systemd-analyze
# MUST reject. Earlier attempt was `Type=invalid` substitution but Debian's
# systemd-analyze treats unknown Type= as a soft stderr warning + rc=0
# (per impl Phase 2.5 ctest report). Removing the section gives a hard
# rejection across systemd versions.
#
# Failure criterion is broadened to "rc!=0 OR stderr contains an explicit
# rejection token" — captures the negation's INTENT ("verifier checks")
# robustly across systemd-version-specific rc behaviour.
echo
echo "=== NEGATION: systemd-analyze verify on deliberately-broken copy ([Service] removed)"
broken_dir=$(mktemp -d /tmp/xdpmf-systemd-broken.XXXXXX)
trap 'rm -rf "${TMPDIR}" "${broken_dir}"' EXIT
broken_unit="${broken_dir}/xdpmacfilter@.service"
# awk state-machine: skip lines starting at "[Service]" up to (but
# excluding) the next "[..." section header.
awk '
    /^\[Service\]/   { skip = 1; next }
    /^\[/ && skip    { skip = 0 }
    !skip            { print }
' "${SYSTEMD_UNIT_SRC}" > "${broken_unit}"

# Confirm the awk actually mutated something (anti-bug-in-the-test):
# the broken unit must NOT contain the [Service] header any more.
if grep -qE '^\[Service\]' "${broken_unit}"; then
    echo "FAIL[N0]: broken-unit transform did NOT remove [Service] header; check unit format" >&2
    echo "Original [..]-section headers:" >&2
    grep -nE '^\[' "${SYSTEMD_UNIT_SRC}" >&2 || true
    fail=1
fi
# Also confirm ExecStart= was removed (it lives under [Service]).
if grep -qE '^ExecStart=' "${broken_unit}"; then
    echo "FAIL[N0b]: broken-unit transform left ExecStart= behind" >&2
    fail=1
fi

stdout_neg="${broken_dir}/stdout.neg"
stderr_neg="${broken_dir}/stderr.neg"
set +e
systemd-analyze verify "${broken_dir}/xdpmacfilter@verifycheck.service" \
    >"${stdout_neg}" 2>"${stderr_neg}"
rc_neg=$?
set -e
echo "rc_neg=${rc_neg}"
echo "--- stdout (neg) ---"
cat "${stdout_neg}" || true
echo "--- stderr (neg) ---"
cat "${stderr_neg}" >&2 || true
echo "--- end (neg) ---"

# Accept rc!=0 OR stderr-token as a rejection signal. The systemd-analyze
# verdict-routing varies across distros (Debian routes soft rejects to
# stderr+rc=0; Fedora hard-fails with rc!=0). Either path = verifier
# actually-checking ≡ negation-control passes.
neg_rejected=0
if [[ "${rc_neg}" -ne 0 ]]; then
    neg_rejected=1
    echo "  neg signal: rc=${rc_neg} (nonzero)"
fi
if grep -qiE 'Failed to|is missing|not found|Invalid|no \[?Service|Cannot add|misses .* Service|service has no|nothing to start' \
       "${stderr_neg}"; then
    neg_rejected=1
    echo "  neg signal: stderr matched a known rejection token"
fi

if [[ "${neg_rejected}" -eq 0 ]]; then
    echo "FAIL[N1]: NEGATION control — systemd-analyze verify on a unit with" \
         "no [Service] section exited 0 AND emitted no rejection-token stderr;" \
         "verifier is rubber-stamping (test machinery broken)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_SYSTEMD_UNIT_SYNTAX"
exit "${fail}"
