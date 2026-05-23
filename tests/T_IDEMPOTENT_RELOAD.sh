#!/bin/bash
# T_IDEMPOTENT_RELOAD — design §6.6: no leaked kernel objects (acceptance #6).
#
# Trigger (post-§5.21 C4 — baseline/final prog-count steps DROPPED, per-iface
# XDP-presence check substituted):
#   1. attach (exit 0)
#   2. attach again — must succeed (detect-and-detach "ours", §5.4)
#   3. detach (exit 0)
# Outcome : post-detach `xdp_prog_id ${IFACE_A}` returns empty
#           AND ${PIN_DIR} does NOT exist
#           AND `ip -j link show ${IFACE_A}` shows no XDP attached.
#
# (Sub-variant §6.6 — alien-program refusal — is OPTIONAL per design and
# is NOT exercised here; promoted to standalone T_ATTACH_ALIEN_REFUSAL.)
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)

trap cleanup_veth EXIT
setup_veth

echo "=== attach #1"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.2

echo "=== attach #2 (must replace ours, not refuse)"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.2

echo "=== detach"
${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}"
sleep 0.2

fail=0

# Pin dir must be gone — gate via sudo so /sys/fs/bpf mode 1700 doesn't
# cause a false-negative absence assertion.
if sudo -n test -e "${PIN_DIR}"; then
    echo "FAIL: ${PIN_DIR} still exists after detach" >&2
    sudo -n ls -la "${PIN_DIR}" >&2 || true
    fail=1
fi

# No XDP on ${IFACE_A} — per-iface presence check (§5.21 C4 replaces the
# global `bpftool prog show | wc -l` delta).
left=$(xdp_prog_id "${IFACE_A}")
if [[ -n "${left}" ]]; then
    echo "FAIL: XDP still attached to ${IFACE_A} (prog_id=${left})" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_IDEMPOTENT_RELOAD"
exit "${fail}"
