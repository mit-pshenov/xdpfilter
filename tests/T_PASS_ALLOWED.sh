#!/bin/bash
# T_PASS_ALLOWED — design §6.3: allowed src MAC passes (acceptance #3).
#
# Setup   : attach with allow-list = {MAC_GOOD}.
# Trigger : inject 1 Ethernet frame on veth_b with src=MAC_GOOD.
# Outcome : stats[PASS]==1 AND stats[DROP_DENY]==0 AND stats[DROP_MAL]==0.
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

# Inject exactly one well-formed frame with the allowed src MAC.
inject_eth "${IFACE_B}" "${MAC_GOOD}" "${MAC_DST}"

# Per §5.21 C1: replace post-inject sleep with deterministic poll until
# the BPF program has accounted for our single frame in any stats slot.
# Timeout means failure (no frame was ever counted) — let the assertion
# below name the specific slot that didn't move.
wait_for_stats_sum "${IFACE_A}" 1 || true

read -r pass deny mal < <(read_stats)
echo "stats: PASS=${pass} DROP_DENY=${deny} DROP_MALFORMED=${mal}"

fail=0
[[ "${pass}" == "1" ]] || { echo "FAIL: expected STAT_PASS=1, got ${pass}" >&2; fail=1; }
[[ "${deny}" == "0" ]] || { echo "FAIL: expected STAT_DROP_DENY=0, got ${deny}" >&2; fail=1; }
[[ "${mal}"  == "0" ]] || { echo "FAIL: expected STAT_DROP_MALFORMED=0, got ${mal}" >&2; fail=1; }
exit "${fail}"
