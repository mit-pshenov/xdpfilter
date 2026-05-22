#!/bin/bash
# T_PASS_ALLOWED — design §6.3: allowed src MAC passes (acceptance #3).
#
# Setup   : attach with allow-list = {MAC_GOOD}.
# Trigger : inject 1 Ethernet frame on veth_b with src=MAC_GOOD.
# Outcome : stats[PASS]==1 AND stats[DROP_DENY]==0 AND stats[DROP_MAL]==0.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)

trap cleanup_veth EXIT
setup_veth

sudo "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

# Inject exactly one well-formed frame with the allowed src MAC.
inject_eth "${IFACE_B}" "${MAC_GOOD}" "${MAC_DST}"

# Wait for the BPF program to finish (single sender + single packet ⇒
# very short window, but be generous).
sleep 0.3

read -r pass deny mal < <(read_stats)
echo "stats: PASS=${pass} DROP_DENY=${deny} DROP_MALFORMED=${mal}"

fail=0
[[ "${pass}" == "1" ]] || { echo "FAIL: expected STAT_PASS=1, got ${pass}" >&2; fail=1; }
[[ "${deny}" == "0" ]] || { echo "FAIL: expected STAT_DROP_DENY=0, got ${deny}" >&2; fail=1; }
[[ "${mal}"  == "0" ]] || { echo "FAIL: expected STAT_DROP_MALFORMED=0, got ${mal}" >&2; fail=1; }
exit "${fail}"
