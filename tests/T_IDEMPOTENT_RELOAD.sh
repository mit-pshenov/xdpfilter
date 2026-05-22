#!/bin/bash
# T_IDEMPOTENT_RELOAD — design §6.6: no leaked kernel objects (acceptance #6).
#
# Trigger :
#   1. baseline = count of bpftool prog show entries
#   2. attach (exit 0)
#   3. attach again — must succeed (detect-and-detach "ours", §5.4)
#   4. detach (exit 0)
#   5. final = count of bpftool prog show entries
# Outcome : final == baseline AND ${PIN_DIR} does NOT exist
#           AND no XDP attached to veth_a.
#
# (Sub-variant §6.6 — alien-program refusal — is OPTIONAL per design and
# is NOT exercised here.)
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)

trap cleanup_veth EXIT
setup_veth

baseline=$(prog_count)
echo "baseline prog count = ${baseline}"

echo "=== attach #1"
sudo "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.2
mid=$(prog_count)
echo "after attach #1: prog count = ${mid}"

echo "=== attach #2 (must replace ours, not refuse)"
sudo "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.2

echo "=== detach"
sudo "${LOADER_BIN}" detach --iface "${IFACE_A}"
sleep 0.2

fail=0

# Pin dir must be gone.
if [[ -e "${PIN_DIR}" ]]; then
    echo "FAIL: ${PIN_DIR} still exists after detach" >&2
    sudo ls -la "${PIN_DIR}" >&2 || true
    fail=1
fi

# No XDP on veth_a.
left=$(xdp_prog_id "${IFACE_A}")
if [[ -n "${left}" ]]; then
    echo "FAIL: XDP still attached to ${IFACE_A} (prog_id=${left})" >&2
    fail=1
fi

# Prog count must be back to baseline.
final=$(prog_count)
echo "final prog count = ${final}"
if [[ "${baseline}" != "${final}" ]]; then
    echo "FAIL: prog count leaked (baseline=${baseline} final=${final})" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_IDEMPOTENT_RELOAD"
exit "${fail}"
