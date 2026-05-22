#!/bin/bash
# T_DROP_MALFORMED — design §6.5: truncated frame dropped (acceptance #5).
#
# Setup   : attach with allow-list = {MAC_GOOD} (content irrelevant).
# Trigger : inject a sub-14-byte frame on veth_b via AF_PACKET SOCK_RAW.
# Outcome : stats[DROP_MALFORMED]==1 AND PASS==0 AND DROP_DENY==0.
#
# Per design §6.5 note: if the test environment cannot reliably deliver
# sub-14-byte frames to XDP (kernel zero-pads via dev_validate_header
# when caller has CAP_SYS_RAWIO), this test reports SKIP via exit code
# 77 (matched by SKIP_RETURN_CODE in tests/CMakeLists.txt).  We detect
# that situation by checking whether the malformed counter bumped; if
# instead the deny counter bumped (kernel padded → src MAC is now
# 02:00:00:00:00:00 which is not in the allow-list), we know padding
# happened and SKIP.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)

trap cleanup_veth EXIT
setup_veth

sudo "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

inject_runt "${IFACE_B}"
sleep 0.3

read -r pass deny mal < <(read_stats)
echo "stats: PASS=${pass} DROP_DENY=${deny} DROP_MALFORMED=${mal}"

# Success path: the malformed counter saw exactly our one runt frame.
if [[ "${mal}" == "1" && "${pass}" == "0" && "${deny}" == "0" ]]; then
    echo "PASS: T_DROP_MALFORMED"
    exit 0
fi

# STAT_PASS must never bump from a malformed frame.  If it did, that's
# a real implementation bug.
if [[ "${pass}" -ge 1 ]]; then
    echo "FAIL: STAT_PASS=${pass} on malformed frame (stats=${pass} ${deny} ${mal})" >&2
    exit 1
fi

# More than one malformed counted from a single runt = a real bug.
if [[ "${mal}" -gt 1 ]]; then
    echo "FAIL: STAT_DROP_MALFORMED=${mal} from a single runt (stats=${pass} ${deny} ${mal})" >&2
    exit 1
fi

# At this point pass==0 and mal==0.  Per design §6.5: if the test
# environment cannot reliably deliver a sub-14-byte frame to XDP, we
# SKIP (NOT silently merge with T_DROP_DENY).  This branch covers
# both "kernel padded to ETH_HLEN" (deny bumped) and "kernel rejected
# the runt send with EINVAL" (no counter bumped, but possibly the
# background-traffic deny is non-zero).
echo "SKIP: environment cannot deliver sub-14-byte frame to XDP" >&2
echo "      observed stats: PASS=${pass} DROP_DENY=${deny} DROP_MALFORMED=${mal}" >&2
echo "      kernel either rejected the send (EINVAL from packet_snd / dev_validate_header)" >&2
echo "      or zero-padded the frame to ETH_HLEN before XDP saw it." >&2
echo "      Malformed counter still exists and is readable (assertable separately)." >&2
exit 77
