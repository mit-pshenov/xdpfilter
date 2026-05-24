#!/bin/bash
# T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE — design §6.41 (MVP-3.4 / §5.29).
#
# Bypass invoked without `--unsafe` in a non-tty context refuses with
# exit 1 + stderr audit-instructive message; XDP STAYS ATTACHED.
#
# **NEGATION CONTROL** (sanity-floor mandatory failure-path probe):
# This test is the load-bearing failure-path probe for the bypass-audit
# story. If bypass silently detached without `--unsafe` in non-tty (e.g.,
# ansible/cron/systemd context), an operator could fail-open by accident
# (risk-register MVP-3.4 row 4). This test catches that regression class.
#
# Trigger:
#   1. setup_veth + attach.
#   2. Confirm XDP attached + link pin present.
#   3. Run bypass via `setsid sh -c ... < /dev/null > stdout 2> stderr` —
#      forces non-tty for stdin (and the loader checks isatty(STDIN_FILENO)
#      OR isatty(STDERR_FILENO) per §5.29 CLI grammar).
#   4. No `--unsafe`.
#
# Observable outcome (ALL must hold):
#   (a) bypass exit code 1 (audit-safety refusal).
#   (b) stderr contains substring 'refusing to bypass'.
#   (c) stderr contains '--unsafe' (so the operator sees the remediation).
#   (d) XDP STILL attached on IFACE_A (xdp_prog_id non-empty == pre-state).
#   (e) ${PIN_DIR}/link STILL exists.
#
# Cleanup: bypass refused → no detach happened → we manually detach via
# the existing `detach` subcommand (which already works) before cleanup_veth.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
echo "loader=${LOADER_BIN}"

stderr_file=$(mktemp /tmp/xdpmf-bypassneg-stderr.XXXXXX)
stdout_file=$(mktemp /tmp/xdpmf-bypassneg-stdout.XXXXXX)

cleanup_test() {
    set +e
    # Bypass refused → loader still has XDP attached. Manually detach.
    ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>/dev/null
    cleanup_veth
    rm -f "${stderr_file}" "${stdout_file}"
    set -e
}
trap cleanup_test EXIT

setup_veth

echo "=== attach on ${IFACE_A}"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

pre_id=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
echo "pre-bypass xdp_prog_id=${pre_id}"
if [[ -z "${pre_id}" ]]; then
    echo "FAIL: smoke — ${IFACE_A} has no XDP attached after attach call" >&2
    exit 1
fi
if ! sudo -n test -e "${PIN_DIR}/link"; then
    echo "FAIL: smoke — link pin missing after attach" >&2
    exit 1
fi

# ── trigger: bypass without --unsafe in non-tty ─────────────────────────
echo "=== bypass --iface ${IFACE_A}  (NO --unsafe, NON-INTERACTIVE)"
# setsid drops the controlling tty; redirected stdin/stderr both fail
# isatty() inside the loader's bypass codepath → audit-safety branch.
set +e
${NSEXEC} setsid -- "${LOADER_BIN}" bypass --iface "${IFACE_A}" \
    </dev/null >"${stdout_file}" 2>"${stderr_file}"
rc=$?
set -e
echo "bypass rc=${rc}"
echo "--- stdout ---"
cat "${stdout_file}"
echo "--- stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end ---"

fail=0

# (a) exit code 1
if [[ "${rc}" -ne 1 ]]; then
    echo "FAIL[a]: expected bypass exit 1 (audit-safety refusal), got ${rc}" >&2
    if [[ "${rc}" == "0" ]]; then
        echo "        rc=0 means bypass SILENTLY succeeded without --unsafe in non-tty —" >&2
        echo "        this is the fail-open regression class (risk-register MVP-3.4 row 4)" >&2
    fi
    fail=1
fi

# (b) refusal substring
if ! grep -q -F -- 'refusing to bypass' "${stderr_file}"; then
    echo "FAIL[b]: stderr missing 'refusing to bypass' substring" >&2
    fail=1
fi

# (c) --unsafe mentioned in remediation
if ! grep -q -F -- '--unsafe' "${stderr_file}"; then
    echo "FAIL[c]: stderr missing '--unsafe' hint (operator can't remediate)" >&2
    fail=1
fi

# (d) XDP STILL attached
post_id=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
echo "post-refused-bypass xdp_prog_id=${post_id}"
if [[ -z "${post_id}" ]]; then
    echo "FAIL[d]: XDP was detached despite refusal — fail-open regression" >&2
    fail=1
fi
if [[ "${post_id}" != "${pre_id}" ]]; then
    echo "WARN: prog_id changed across refused-bypass (${pre_id} → ${post_id}) — non-fatal" >&2
fi

# (e) link pin still present
if ! sudo -n test -e "${PIN_DIR}/link"; then
    echo "FAIL[e]: ${PIN_DIR}/link gone after refused bypass — partial detach happened" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE"
exit "${fail}"
