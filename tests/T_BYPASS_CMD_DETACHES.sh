#!/bin/bash
# T_BYPASS_CMD_DETACHES — design §6.40 (MVP-3.4 / §5.29).
#
# `xdpfilter bypass --iface X --unsafe --reason Y` detaches XDP + emits
# audit-log line. PI-30: bypass = detach-alias + audit + --unsafe gate.
#
# Trigger:
#   1. setup_veth + attach (default mode) on IFACE_A allow=MAC_GOOD.
#   2. Confirm XDP attached (xdp_prog_id non-empty) + link pin exists.
#   3. Run `xdpfilter bypass --iface IFACE_A --unsafe --reason "T_BYPASS_test"`
#      under NSEXEC. Capture stderr.
#   4. Sub-case: re-attach + bypass WITHOUT --reason → audit line ends UNSPECIFIED.
#
# Observable outcome (PRIMARY):
#   (a) bypass exit code 0.
#   (b) stderr line matches ERE
#       '^xdpfilter: BYPASS activated on <IFACE_A> by uid=[0-9]+ reason="T_BYPASS_test"$'
#   (c) XDP NOT attached on IFACE_A after bypass (xdp_prog_id is empty).
#   (d) ${PIN_DIR}/link does NOT exist (detach cleaned up the link pin).
#
# Observable outcome (SUB-CASE):
#   (e) bypass without --reason exits 0; audit line ends `reason="UNSPECIFIED"`.
#
# Sanity-floor smoke: step 2 (attach succeeded) IS the smoke; without it
# we can't tell whether the subsequent detach is a no-op or real.
# Negation control: the audit-log REGEX (b) IS the failure-mode-catching
# assertion — if bypass silently detached without the audit line, this
# test would fail and surface the absent audit trail (D-3.4-5).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
echo "loader=${LOADER_BIN}"

stderr_file=$(mktemp /tmp/xdpmf-bypass-stderr.XXXXXX)
stderr2_file=$(mktemp /tmp/xdpmf-bypass-stderr2.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}" "${stderr2_file}"' EXIT

setup_veth

# ── PRIMARY: attach + bypass --unsafe --reason X ────────────────────────
echo "=== attach on ${IFACE_A} allow=${MAC_GOOD}"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

# Smoke: confirm XDP is up (so subsequent detach is meaningful).
pre_id=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
echo "pre-bypass xdp_prog_id=${pre_id}"
if [[ -z "${pre_id}" ]]; then
    echo "FAIL: smoke — ${IFACE_A} has no XDP attached after attach call" >&2
    exit 1
fi
if ! sudo -n test -e "${PIN_DIR}/link"; then
    echo "FAIL: smoke — link pin ${PIN_DIR}/link missing after attach" >&2
    exit 1
fi

echo "=== bypass --iface ${IFACE_A} --unsafe --reason 'T_BYPASS_test'"
# `setsid` + redirected stdin → non-tty; --unsafe satisfies the audit gate.
set +e
${NSEXEC} setsid -- "${LOADER_BIN}" bypass --iface "${IFACE_A}" \
    --unsafe --reason "T_BYPASS_test" \
    </dev/null 2>"${stderr_file}"
rc=$?
set -e
echo "bypass rc=${rc}"
echo "--- stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

fail=0

# (a) exit code 0
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[a]: expected bypass exit 0, got ${rc}" >&2
    fail=1
fi

# (b) audit-log ERE — permissive middle-fill per §5.30 D-3.4.5-8 / HK-4.
# HK-4 inserts `euid=<N> sudo_user="<X>"` between `uid=<N>` and `reason=...`.
# The `.*` between `uid=[0-9]+ ` and `reason="..."` matches BOTH the pre-
# HK-4 shape (empty middle) AND the post-HK-4 shape (` euid=N sudo_user=...`).
# Detailed HK-4 field-shape assertions live in T_BYPASS_INTERACTIVE_PROMPT
# per option (b); §6.40 keeps only the high-level structural assertion.
audit_ere="^xdpfilter: BYPASS activated on ${IFACE_A} by uid=[0-9]+ .*reason=\"T_BYPASS_test\"\$"
if ! grep -qE -- "${audit_ere}" "${stderr_file}"; then
    echo "FAIL[b]: stderr missing audit-log line matching ERE:" >&2
    echo "        ${audit_ere}" >&2
    fail=1
fi

# (c) XDP detached
post_id=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
echo "post-bypass xdp_prog_id='${post_id}'"
if [[ -n "${post_id}" ]]; then
    echo "FAIL[c]: ${IFACE_A} still has XDP attached (prog_id=${post_id}) after bypass" >&2
    fail=1
fi

# (d) link pin cleaned up
if sudo -n test -e "${PIN_DIR}/link"; then
    echo "FAIL[d]: ${PIN_DIR}/link still exists after bypass" >&2
    fail=1
fi

# ── SUB-CASE: bypass WITHOUT --reason → UNSPECIFIED audit text ──────────
echo
echo "=== sub-case: re-attach + bypass --unsafe (no --reason)"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

pre_id2=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
echo "pre-bypass(sub) xdp_prog_id=${pre_id2}"
if [[ -z "${pre_id2}" ]]; then
    echo "FAIL: sub-case smoke — re-attach did not put XDP back" >&2
    exit 1
fi

set +e
${NSEXEC} setsid -- "${LOADER_BIN}" bypass --iface "${IFACE_A}" --unsafe \
    </dev/null 2>"${stderr2_file}"
rc2=$?
set -e
echo "bypass(sub) rc=${rc2}"
echo "--- stderr ---"
cat "${stderr2_file}" >&2 || true
echo "--- end stderr ---"

if [[ "${rc2}" -ne 0 ]]; then
    echo "FAIL[e1]: sub-case expected bypass exit 0, got ${rc2}" >&2
    fail=1
fi
audit_ere_unspec="^xdpfilter: BYPASS activated on ${IFACE_A} by uid=[0-9]+ .*reason=\"UNSPECIFIED\"\$"
if ! grep -qE -- "${audit_ere_unspec}" "${stderr2_file}"; then
    echo "FAIL[e2]: sub-case stderr missing audit-log line matching ERE:" >&2
    echo "         ${audit_ere_unspec}" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_BYPASS_CMD_DETACHES"
exit "${fail}"
