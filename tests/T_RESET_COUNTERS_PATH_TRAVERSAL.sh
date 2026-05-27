#!/bin/bash
# T_RESET_COUNTERS_PATH_TRAVERSAL — design §5.36 T-1 (MVP-3.4e).
#
# `xdpmacfilter reset-counters --iface <bad-shape>` rejected at the
# §5.22 invariant layer (now extended to reset-counters per HG-3.4e-1)
# with:
#   - exit code 8 (LoaderError::PathRefused, per HG-3.4e-3)
#   - stderr containing literal substring 'refusing to operate'
#   - stderr containing the offending iface token (raw or escaped echo)
#
# Closes KC-3 reset-counters limb: a path-traversal-shaped iface name
# MUST NOT reach `pin_path_for` + `bpf_obj_get` and clobber a sibling
# PERCPU pin under /sys/fs/bpf/. Before §5.36, `reset-counters --iface
# ../foo` would zero-write any matching pin under any sibling subsystem.
#
# Maps to:
#   - PI-3.4e-1 (reset-counters path-refused via §5.22 invariant)
#   - HG-3.4e-1 (route through internal::reset_counters_request)
#   - HG-3.4e-3 (exit 8 = PathRefused)
#   - Q2.A2 (validate_iface_name shape-check helper)
#
# Sub-cases:
#   (a) `--iface ../foo` → exit 8 + 'refusing to operate' + '../foo'.
#   (b) `--iface 'invalid name with spaces'` → exit 8 + 'refusing to
#       operate' + token (dev_valid_name reject — whitespace illegal).
#   (c) NEGATION CONTROL: attach (via apply) a real IFACE_A, then
#       `--iface ${IFACE_A}` → exit 0 + audit-log line.
#       Proves the helper-routing did not break the legitimate operator
#       path AND that validate_iface_name doesn't reject every input.
#
# Sanity-floor smoke: sub-case (c) — exit 0 + audit-log present proves
# the test harness can even invoke a successful reset-counters call.
# Negation control: sub-case (c) IS the negation against an "always-
# refused" failure mode. A passing (a)+(b) without (c) would mean the
# validation rules are too aggressive (over-broad reject).
#
# Failure-mode signaling (per §5.36 T-1 design):
#   - (a) yields exit 2/1 → Q3 not honored / PathRefused not wired.
#   - (a) yields exit 0  → KC-3 reset-counters limb is OPEN.
#   - (b) yields exit 0  → validation too permissive (whitespace passed).
#   - (c) yields exit != 0 → routing through internal-helper broke
#                            legitimate operation.
# All four are [INVARIANT-VIOLATED] per §6.5 PI-3.4e-1.
#
# RESOURCE_LOCK xdp_fixture (per design §5.36 — guard #12; touches veth
# + bpffs pins via the sub-case (c) attach precondition).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

stderr_a=$(mktemp /tmp/xdpmf-resetpt-a.XXXXXX)
stderr_b=$(mktemp /tmp/xdpmf-resetpt-b.XXXXXX)
stderr_c=$(mktemp /tmp/xdpmf-resetpt-c.XXXXXX)

cleanup() {
    set +e
    # Detach if sub-case (c) attached.
    ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" >/dev/null 2>&1
    cleanup_veth
    rm -f "${stderr_a}" "${stderr_b}" "${stderr_c}"
    set -e
}
trap cleanup EXIT INT TERM HUP

# Defensive: wipe any stale per-iface pin dir from a crashed prior run.
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

fail=0

# ─────────────────────────────────────────────────────────────────────────
# Sub-case (a): path-traversal-shaped iface → exit 8.
# Validate_iface_name (Q2.A2) MUST reject `../foo` (contains chars outside
# [A-Za-z0-9._-] — the `/` — AND/OR matches the `..` prefix discipline).
# Rejection fires BEFORE pin-path construction → no bpffs touch on
# sibling subsystems.
# ─────────────────────────────────────────────────────────────────────────
BAD_A="../foo"
echo "=== sub-case (a): reset-counters --iface '${BAD_A}'"
set +e
${NSEXEC} "${LOADER_BIN}" reset-counters --iface "${BAD_A}" 2>"${stderr_a}"
rc_a=$?
set -e
echo "rc_a=${rc_a}"
echo "--- stderr (a) ---"
cat "${stderr_a}" >&2 || true
echo "--- end stderr (a) ---"

# (a1) Exit 8 — PathRefused per HG-3.4e-3.
if [[ "${rc_a}" -ne 8 ]]; then
    echo "FAIL[a1]: expected rc=8 (PathRefused), got rc=${rc_a}" >&2
    case "${rc_a}" in
        0) echo "          rc=0 means reset-counters followed the path — KC-3 limb OPEN" >&2 ;;
        1) echo "          rc=1 means impl reused CliUsageError — Q3/HG-3.4e-3 not honored" >&2 ;;
        2) echo "          rc=2 means impl reused LoadFailed — PathRefused enum not wired" >&2 ;;
    esac
    fail=1
fi

# (a2) Stderr literal 'refusing to operate' (§5.22 phrasing precedent).
if ! grep -q -F -- 'refusing to operate' "${stderr_a}"; then
    echo "FAIL[a2]: stderr (a) does not contain literal 'refusing to operate'" >&2
    fail=1
fi

# (a3) Stderr contains the offending iface token (raw or safely-escaped echo).
# Per design "impl-flexible — the literal AS-INVOKED OR a safely-escaped echo".
# We accept raw '../foo' OR the bytes 'foo' on its own (in case the escape
# strips '..'); we assert at minimum the 'foo' substring is echoed back so
# the operator can correlate the rejection with their argv.
if ! grep -q -F -- "${BAD_A}" "${stderr_a}" \
   && ! grep -q -F -- 'foo' "${stderr_a}"; then
    echo "FAIL[a3]: stderr (a) does not echo the offending iface (raw '${BAD_A}' or escaped 'foo')" >&2
    fail=1
fi

# ─────────────────────────────────────────────────────────────────────────
# Sub-case (b): shape-invalid iface (whitespace) → exit 8.
# dev_valid_name-style check rejects whitespace + control chars.
# ─────────────────────────────────────────────────────────────────────────
BAD_B="invalid name with spaces"
echo
echo "=== sub-case (b): reset-counters --iface '${BAD_B}'"
set +e
${NSEXEC} "${LOADER_BIN}" reset-counters --iface "${BAD_B}" 2>"${stderr_b}"
rc_b=$?
set -e
echo "rc_b=${rc_b}"
echo "--- stderr (b) ---"
cat "${stderr_b}" >&2 || true
echo "--- end stderr (b) ---"

# (b1) Exit 8.
if [[ "${rc_b}" -ne 8 ]]; then
    echo "FAIL[b1]: expected rc=8 (PathRefused) for shape-invalid iface, got rc=${rc_b}" >&2
    if [[ "${rc_b}" -eq 0 ]]; then
        echo "          rc=0 means validation accepts whitespace — too permissive" >&2
    fi
    fail=1
fi

# (b2) Stderr literal 'refusing to operate'.
if ! grep -q -F -- 'refusing to operate' "${stderr_b}"; then
    echo "FAIL[b2]: stderr (b) does not contain literal 'refusing to operate'" >&2
    fail=1
fi

# (b3) Stderr contains the iface token (raw or a substring; the whole
# string contains a space which echoers may quote or escape — accept
# either a substring 'invalid' OR the full token).
if ! grep -q -F -- "${BAD_B}" "${stderr_b}" \
   && ! grep -q -F -- 'invalid' "${stderr_b}"; then
    echo "FAIL[b3]: stderr (b) does not echo the offending iface token" >&2
    fail=1
fi

# ─────────────────────────────────────────────────────────────────────────
# Sub-case (c) — NEGATION CONTROL: legitimate iface still works.
# Apply config_valid.yaml first (HG-3.4d-3 precondition: rule_counters
# pin exists), then reset-counters on the real iface → exit 0 +
# audit-log line per HG-3.4d-6.
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== sub-case (c) NEGATION: apply on ${IFACE_A} then reset-counters --iface ${IFACE_A}"
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" >/dev/null

# Confirm at least one rule_counters pin shape exists post-apply (either
# the default §5.35 atomic-swap shape OR the D-3.4d-FALLBACK shape).
if ! sudo -n test -e "${PIN_DIR}/rule_counters" \
     && ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[c.pin]: neither rule_counters NOR rule_counters_a pin exists after apply" >&2
    echo "             — test premise invalid, cannot exercise sub-case (c) negation" >&2
    exit 1
fi

set +e
${NSEXEC} "${LOADER_BIN}" reset-counters --iface "${IFACE_A}" 2>"${stderr_c}"
rc_c=$?
set -e
echo "rc_c=${rc_c}"
echo "--- stderr (c) ---"
cat "${stderr_c}" >&2 || true
echo "--- end stderr (c) ---"

# (c1) Exit 0 — legitimate iface accepted.
if [[ "${rc_c}" -ne 0 ]]; then
    echo "FAIL[c1]: NEGATION expected rc=0 for real iface, got ${rc_c}" >&2
    echo "          (helper-routing broke legitimate operator path OR validation over-broad)" >&2
    fail=1
fi

# (c2) Audit-log line present per HG-3.4d-6 (carry-forward from §5.35).
# ERE matches: "xdpmacfilter: RESET-COUNTERS on <iface> by uid=NN .* rule_id=ALL".
audit_ere="^xdpmacfilter: RESET-COUNTERS on ${IFACE_A} by uid=[0-9]+ .*rule_id=ALL\$"
if ! grep -qE -- "${audit_ere}" "${stderr_c}"; then
    echo "FAIL[c2]: NEGATION stderr missing audit-log line matching ERE:" >&2
    echo "          ${audit_ere}" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_RESET_COUNTERS_PATH_TRAVERSAL"
exit "${fail}"
