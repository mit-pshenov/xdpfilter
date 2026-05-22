#!/bin/bash
# T_NEGATION_CONTROL — design §6.7 / acceptance #7.
#
# Sanity floor: proves the test suite is NOT a no-op.
#
# Construction: identical to T_DROP_DENY (inject MAC_BAD, which the
# spec says MUST be dropped), but the assertion is INVERTED — we
# assert STAT_PASS==1.  Per spec MAC_BAD is dropped ⇒ STAT_PASS==0,
# so the assertion will fail and the script exits non-zero.
#
# ctest's WILL_FAIL property (set in tests/CMakeLists.txt) inverts the
# meaning: non-zero exit = test pass, zero exit = test fail.
# If anyone ever breaks the BPF filter and lets all frames pass, this
# script will exit 0 → ctest will report T_NEGATION_CONTROL as FAILED,
# surfacing the regression.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)

trap cleanup_veth EXIT
setup_veth

sudo "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

# Inject a DISALLOWED MAC — spec says this MUST be dropped.
inject_eth "${IFACE_B}" "${MAC_BAD}" "${MAC_DST}"
sleep 0.3

read -r pass deny mal < <(read_stats)
echo "stats: PASS=${pass} DROP_DENY=${deny} DROP_MALFORMED=${mal}"

# INVERTED assertion: we (deliberately wrongly) assert MAC_BAD was passed.
# This MUST exit non-zero on a correct implementation.  If it exits zero,
# the spec is being violated and ctest will surface that as a failure.
if [[ "${pass}" == "1" ]]; then
    echo "UNEXPECTED PASS: STAT_PASS=1 — MAC_BAD was NOT dropped!" >&2
    echo "                 This means XDP filter is broken." >&2
    exit 0
fi

echo "EXPECTED FAIL: STAT_PASS=${pass} (≠1), confirming the suite catches failures" >&2
exit 1
