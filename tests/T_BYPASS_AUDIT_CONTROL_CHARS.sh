#!/bin/bash
# T_BYPASS_AUDIT_CONTROL_CHARS — design §5.37 T-1 (MVP-3.4f, sec M1 closure).
#
# Operational evidence of the extended `escape_audit` policy: bytes in
# {[0x01,0x08] ∪ {0x0B,0x0C} ∪ [0x0E,0x1F] ∪ {0x7F}} emit as `\xHH`
# lowercase in the text-mode audit-line emitted by `xdpmacfilter bypass`
# — AND the named escapes (`\\`, `\"`, `\n`, `\r`) continue to use the
# named form (PI-3.4f-3 backward-compat fence; PI-3.4f-2 extended policy).
# Closes Theme B / sec M1 from /mint-review 2026-05-27.
#
# Sub-case (a) — extended-policy bytes get \xHH:
#   Trigger:  bypass --reason $'\x01\x07\x0b\x0e\x1f\x7f tail'
#   Assert:   audit-line contains literal `\x01\x07\x0b\x0e\x1f\x7f`
#   Assert:   audit-line contains literal `tail` (anti-truncation)
#   Negation: stderr contains NO raw 0x01 byte (escape branch active)
#
# Sub-case (b) — named escapes use named form (NOT \xHH):
#   Trigger:  bypass --reason $'has\\backslash and \"quote and\nnewline and\rCR tail'
#   Assert:   audit-line contains `\\backslash`, `\"quote`, `\nnewline`, `\rCR`
#   Negation: audit-line does NOT contain `\x0a` or `\x0d` (named-escape
#             precedence over extended-policy default branch)
#   (`\0NUL` assertion DROPPED per §5.37 EDIT-1 — see NOTE below.)
#
# Sub-case (c) — printable ASCII unchanged (NEGATION CONTROL):
#   Trigger:  bypass --reason 'simple_safe-reason.42'
#   Assert:   audit-line contains literal `simple_safe-reason.42`
#   Negation: audit-line contains NO `\x` substring (printable branch quiet)
#
# NOTE on `\0NUL` omission (per design §5.37 EDIT-1):
#   Sub-case (b) covers 4 of 5 named escapes (`\\`, `\"`, `\n`, `\r`)
#   through integration. The 5th named escape (`\0` → `\0`) is UNREACHABLE
#   via execve(2) argv-passed --reason (kernel truncates argv at NUL).
#   PI-3.4f-3 coverage of the `\0` byte is via CODE-REVIEW of
#   src/common/escape_util.cpp body per §5.37 EDIT-1 verifiable
#   invariant #15 (`grep -nE "case '\\0':" src/common/escape_util.cpp`
#   returns exactly 1 hit), NOT through this integration test.
#   See design.md §5.37 D-3.4f-EDIT-1-NUL-INTEGRATION-OOS.
#
# Sanity-floor smoke: pre-attach succeeded → bypass has something to detach.
# Negation control: sub-case (c) — printable ASCII must NOT trigger any
#   `\x` escape (proves the policy doesn't over-escape benign input).
#
# SKIP: passwordless sudo (project convention).
#
# Cleanup: trap-driven cleanup_veth + rm tmp captures.
#
# Maps to: §5.37 T-1; D-3.4f-3 (policy details); D-3.4f-T1 (integration
# shape); PI-3.4f-2 (extended-policy contract); PI-3.4f-3 (named-escape
# backward-compat); HG-3.4f-1; HG-3.4f-3.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
echo "loader=${LOADER_BIN}"

cap_a=$(mktemp /tmp/xdpmf-bypctl-a.XXXXXX)
cap_b=$(mktemp /tmp/xdpmf-bypctl-b.XXXXXX)
cap_c=$(mktemp /tmp/xdpmf-bypctl-c.XXXXXX)
trap 'cleanup_veth; rm -f "${cap_a}" "${cap_b}" "${cap_c}"' EXIT

setup_veth

fail=0

# ─── Sub-case (a) — extended-policy bytes get \xHH ─────────────────────
echo
echo "=== (a) attach + bypass with control-char reason"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

# Smoke (sanity-floor): attach succeeded → bypass has something to detach.
pre_id_a=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
if [[ -z "${pre_id_a}" ]]; then
    echo "FAIL: smoke — ${IFACE_A} has no XDP attached after attach call" >&2
    exit 1
fi
echo "(a) smoke OK: XDP prog id=${pre_id_a} attached on ${IFACE_A}"

set +e
${NSEXEC} env XDPMF_LOG_FORMAT=text setsid -- "${LOADER_BIN}" \
    bypass --iface "${IFACE_A}" --unsafe --reason $'\x01\x07\x0b\x0e\x1f\x7f tail' \
    </dev/null 2>"${cap_a}"
rc_a=$?
set -e
echo "(a) bypass rc=${rc_a}"
echo "--- stderr (a) ---"
cat "${cap_a}"
echo "--- end ---"

if [[ "${rc_a}" -ne 0 ]]; then
    echo "FAIL[a-rc]: (a) bypass rc=${rc_a}, expected 0 (bypass succeeds; reason is just a label)" >&2
    fail=1
fi

audit_a=$(grep "BYPASS activated" "${cap_a}" | tail -1 || true)
echo "(a) audit-line: ${audit_a}"
if [[ -z "${audit_a}" ]]; then
    echo "FAIL[a-line]: (a) no BYPASS-activated audit-line in stderr" >&2
    fail=1
fi

# Positive — literal `\x01\x07\x0b\x0e\x1f\x7f` (24 visible chars).
# grep -F treats pattern as literal substring (no regex interp); '\x01' here
# is the 4-char sequence backslash-x-0-1, NOT byte 0x01.
if ! printf '%s' "${audit_a}" | grep -qF -- '\x01\x07\x0b\x0e\x1f\x7f'; then
    echo "FAIL[a]: audit-line missing literal '\\x01\\x07\\x0b\\x0e\\x1f\\x7f'" >&2
    echo "        extended-policy branch broken OR escaped to wrong form" >&2
    echo "        (\\u00xx mistake, uppercase hex, etc. — see §5.37 failure-mode notes)" >&2
    fail=1
else
    echo "[a] OK: audit-line contains \\x01\\x07\\x0b\\x0e\\x1f\\x7f"
fi

# Anti-truncation: 'tail' must appear AFTER the escaped sequence (proves
# escape_audit emits the full escaped reason, not just the first byte).
if ! printf '%s' "${audit_a}" | grep -qF -- 'tail'; then
    echo "FAIL[a-tail]: audit-line missing 'tail' literal — escape_audit truncated early" >&2
    fail=1
else
    echo "[a-tail] OK: 'tail' appears in audit-line (no early truncation)"
fi

# Negation — stderr file must NOT contain a raw 0x01 byte anywhere. If the
# default branch fell through (raw passthrough), 0x01 would appear in the
# captured stderr. bash $'\x01' = literal byte 0x01; LC_ALL=C for byte mode.
if LC_ALL=C grep -q $'\x01' "${cap_a}"; then
    echo "FAIL[a-neg]: raw 0x01 byte found in stderr — extended-policy branch inactive" >&2
    fail=1
else
    echo "[a-neg] OK: no raw 0x01 byte in stderr (escape branch active)"
fi

# ─── Sub-case (b) — named escapes use named form (NOT \xHH) ────────────
echo
echo "=== (b) attach + bypass with named-escape reason"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

# bash $'...' interprets: `\\` → \ (one backslash); `\"` → " (one dquote,
# since bash 4.4); `\n` → LF (0x0A); `\r` → CR (0x0D).
# argv reason bytes: `has\backslash and "quote and<LF>newline and<CR>CR tail`.
# Trailing ` tail` token mirrors sub-case (a) anti-truncation marker
# (escape_audit must process past the last escape into trailing printable).
# (NUL omitted per §5.37 EDIT-1 — see header NOTE on argv truncation.)
set +e
${NSEXEC} env XDPMF_LOG_FORMAT=text setsid -- "${LOADER_BIN}" \
    bypass --iface "${IFACE_A}" --unsafe --reason $'has\\backslash and \"quote and\nnewline and\rCR tail' \
    </dev/null 2>"${cap_b}"
rc_b=$?
set -e
echo "(b) bypass rc=${rc_b}"
echo "--- stderr (b) ---"
cat "${cap_b}"
echo "--- end ---"

if [[ "${rc_b}" -ne 0 ]]; then
    echo "FAIL[b-rc]: (b) bypass rc=${rc_b}, expected 0" >&2
    fail=1
fi

audit_b=$(grep "BYPASS activated" "${cap_b}" | tail -1 || true)
echo "(b) audit-line: ${audit_b}"
if [[ -z "${audit_b}" ]]; then
    echo "FAIL[b-line]: (b) no BYPASS-activated audit-line in stderr" >&2
    fail=1
fi

# Positive — named escapes preserved.
# Patterns are single-quoted in bash, so backslashes are literal.
# Each grep pattern matches the rendered escape-pair in the audit-line.
for tok in '\\backslash' '\"quote' '\nnewline' '\rCR'; do
    if ! printf '%s' "${audit_b}" | grep -qF -- "${tok}"; then
        echo "FAIL[b]: audit-line missing literal '${tok}' — named-escape broken" >&2
        fail=1
    else
        echo "[b] OK: audit-line contains '${tok}'"
    fi
done

# Anti-theatricality — named escapes win over extended-policy default. If
# `\x0a` or `\x0d` appears, the switch-order in escape_audit is broken
# (extended check fires BEFORE the named cases).
for tok in '\x0a' '\x0d'; do
    if printf '%s' "${audit_b}" | grep -qF -- "${tok}"; then
        echo "FAIL[b-anti]: audit-line contains '${tok}' — switch-order broken" >&2
        echo "             (named-escape precedence lost; extended branch fires first)" >&2
        fail=1
    else
        echo "[b-anti] OK: audit-line lacks '${tok}' (named precedence preserved)"
    fi
done

# ─── Sub-case (c) — printable ASCII unchanged (NEGATION CONTROL) ───────
echo
echo "=== (c) attach + bypass with printable-ASCII reason"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

set +e
${NSEXEC} env XDPMF_LOG_FORMAT=text setsid -- "${LOADER_BIN}" \
    bypass --iface "${IFACE_A}" --unsafe --reason 'simple_safe-reason.42' \
    </dev/null 2>"${cap_c}"
rc_c=$?
set -e
echo "(c) bypass rc=${rc_c}"
echo "--- stderr (c) ---"
cat "${cap_c}"
echo "--- end ---"

if [[ "${rc_c}" -ne 0 ]]; then
    echo "FAIL[c-rc]: (c) bypass rc=${rc_c}, expected 0" >&2
    fail=1
fi

audit_c=$(grep "BYPASS activated" "${cap_c}" | tail -1 || true)
echo "(c) audit-line: ${audit_c}"
if [[ -z "${audit_c}" ]]; then
    echo "FAIL[c-line]: (c) no BYPASS-activated audit-line in stderr" >&2
    fail=1
fi

# Positive — printable ASCII passes through verbatim.
if ! printf '%s' "${audit_c}" | grep -qF -- 'simple_safe-reason.42'; then
    echo "FAIL[c]: audit-line missing literal 'simple_safe-reason.42'" >&2
    fail=1
else
    echo "[c] OK: audit-line contains 'simple_safe-reason.42'"
fi

# NEGATION CONTROL — audit-line must NOT contain ANY `\x` substring (the
# printable-ASCII branch is quiet; extended-policy fires ONLY on control
# bytes + 0x7F). If `\x` appears, the default branch is over-escaping.
if printf '%s' "${audit_c}" | grep -qF -- '\x'; then
    echo "FAIL[c-neg]: audit-line contains '\\x' — printable-ASCII branch over-escaping" >&2
    fail=1
else
    echo "[c-neg] OK: audit-line has no '\\x' substring (printable branch quiet)"
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_BYPASS_AUDIT_CONTROL_CHARS"
exit "${fail}"
