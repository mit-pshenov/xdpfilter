#!/bin/bash
# T_DROP_DENY — design §6.4: disallowed src MAC dropped (acceptance #4).
#
# Setup   : attach with allow-list = {MAC_GOOD}.
# Trigger : inject 1 frame on veth_b with src=MAC_BAD (NOT in allow-list).
# Outcome : stats[DROP_DENY]==1 AND stats[PASS]==0 AND stats[DROP_MAL]==0.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

# §5.43 MVP-4.3 (T-SKIP): MAC-axis matching is DEFERRED to mvp-4.5
# (HG-mvp-4.3-2 / PI-mvp-4.3-MAC-DEFERRED). The v2 config grammar rejects
# the `mac` match-key and the production datapath no longer consults the
# MAC HASH maps, so this MAC-verdict test cannot pass until the MAC-axis
# slice lands. Converted to SKIP (NOT silently dropped) — un-SKIP when the
# MAC-axis returns as a bit-vector axis in mvp-4.5.
echo "SKIP: MAC-axis deferred to mvp-4.5 per HG-mvp-4.3-2 / PI-mvp-4.3-MAC-DEFERRED" >&2
exit 77
require_passwordless_sudo

LOADER_BIN=$(find_loader)

trap cleanup_veth EXIT
setup_veth

${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

inject_eth "${IFACE_B}" "${MAC_BAD}" "${MAC_DST}"
# Per §5.21 C1: replace post-inject sleep with stats-sum poll.
wait_for_stats_sum "${IFACE_A}" 1 || true

read -r pass deny mal < <(read_stats)
echo "stats: PASS=${pass} DROP_DENY=${deny} DROP_MALFORMED=${mal}"

fail=0
[[ "${deny}" == "1" ]] || { echo "FAIL: expected STAT_DROP_DENY=1, got ${deny}" >&2; fail=1; }
[[ "${pass}" == "0" ]] || { echo "FAIL: expected STAT_PASS=0, got ${pass}" >&2; fail=1; }
[[ "${mal}"  == "0" ]] || { echo "FAIL: expected STAT_DROP_MALFORMED=0, got ${mal}" >&2; fail=1; }
exit "${fail}"
