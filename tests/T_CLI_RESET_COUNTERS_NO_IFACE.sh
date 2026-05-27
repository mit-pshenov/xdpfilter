#!/bin/bash
# T_CLI_RESET_COUNTERS_NO_IFACE — design §6.NN+2 (MVP-3.4d / §5.35).
#
# `xdpmacfilter reset-counters --iface X` on a NOT-attached iface fails
# with exit 1 + stderr 'no rule_counters pin' substring (HG-3.4d-3
# precondition). Negation control: same call on an attached iface
# succeeds (proves the precondition probe doesn't always fail).
#
# Maps to PI-3.4d-1 (CLI behavioural), HG-3.4d-3 (iface-attached precondition).
#
# Trigger:
#   1. Sub-case (a) PRECONDITION FAIL: setup_veth but DO NOT apply/attach;
#      reset-counters --iface ${IFACE_A} → exit 1 + stderr substring
#      'no rule_counters pin at' + 'iface '${IFACE_A}' not attached?'.
#   2. Sub-case (b) NEGATION CONTROL: apply config_per_rule_counters.yaml;
#      reset-counters --iface ${IFACE_A} → exit 0 + audit-log present.
#
# Sanity-floor smoke: sub-case (b) succeeds (proves test fixture works).
# Negation control: sub-case (a) IS the negation against
# "precondition probe never fires" failure mode. Without it, the
# stderr substring check is theatre — it could match even if the impl
# ALWAYS emits the message regardless of pin state.
#
# RESOURCE_LOCK xdp_fixture (guard #12).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_per_rule_counters.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

stderr_a=$(mktemp /tmp/xdpmf-resetnoif-a.XXXXXX)
stderr_b=$(mktemp /tmp/xdpmf-resetnoif-b.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_a}" "${stderr_b}"' EXIT INT TERM HUP

sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true
setup_veth

fail=0

# Defensively ensure no rule_counters pin exists at the iface dir (we did
# NOT call apply/attach for sub-case (a)).
if sudo -n test -e "${PIN_DIR}/rule_counters" \
   || sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[setup]: rule_counters pin exists before attach — test premise invalid" >&2
    exit 1
fi

# ── (a) PRECONDITION FAIL: not-attached iface → exit 1 ──────────────────
echo "=== sub-case (a): reset-counters on NOT-attached ${IFACE_A}"
set +e
sudo -n "${LOADER_BIN}" reset-counters --iface "${IFACE_A}" 2>"${stderr_a}"
rc_a=$?
set -e
echo "rc_a=${rc_a}"
echo "--- stderr ---"
cat "${stderr_a}" >&2 || true
echo "--- end stderr ---"

if [[ "${rc_a}" -ne 1 ]]; then
    echo "FAIL[a1]: expected exit 1 (precondition fail), got ${rc_a}" >&2
    fail=1
fi
if ! grep -q -F -- "no rule_counters pin at" "${stderr_a}"; then
    echo "FAIL[a2]: stderr missing 'no rule_counters pin at' substring" >&2
    fail=1
fi
if ! grep -q -F -- "iface '${IFACE_A}' not attached?" "${stderr_a}"; then
    echo "FAIL[a3]: stderr missing \"iface '${IFACE_A}' not attached?\" substring" >&2
    fail=1
fi

# ── (b) NEGATION CONTROL: apply + reset → exit 0 ────────────────────────
echo "=== sub-case (b) NEGATION CONTROL: apply then reset-counters"
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" >/dev/null

if ! sudo -n test -e "${PIN_DIR}/rule_counters" \
     && ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[b.pin]: no rule_counters pin after apply — cannot validate negation" >&2
    exit 1
fi

set +e
sudo -n "${LOADER_BIN}" reset-counters --iface "${IFACE_A}" 2>"${stderr_b}"
rc_b=$?
set -e
echo "rc_b=${rc_b}"
echo "--- stderr ---"
cat "${stderr_b}" >&2 || true
echo "--- end stderr ---"

if [[ "${rc_b}" -ne 0 ]]; then
    echo "FAIL[b1]: NEGATION expected exit 0, got ${rc_b}" >&2
    fail=1
fi
# Audit-log must be present (HG-3.4d-6).
audit_ere="^xdpmacfilter: RESET-COUNTERS on ${IFACE_A} by uid=[0-9]+ .*rule_id=ALL\$"
if ! grep -qE -- "${audit_ere}" "${stderr_b}"; then
    echo "FAIL[b2]: NEGATION stderr missing audit-log line" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_CLI_RESET_COUNTERS_NO_IFACE"
exit "${fail}"
