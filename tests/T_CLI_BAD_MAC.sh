#!/bin/bash
# T_CLI_BAD_MAC — design §6.12 (MVP-1.1C / §5.21 D3).
#
# Malformed MAC rejected: 4 sub-cases exercising the realistic
# malformed-MAC variety (non-hex chars, short, long, totally non-MAC).
# All four MUST produce exit 1 (CLI usage error per §4.1) and a
# recognizable stderr token containing 'mac' (case-insensitive — the
# exact wording is impl-shape).
#
# Pure CLI-parser test; no veth, no root, no SKIP_RETURN_CODE.
#
# Sub-cases:
#   1. 'not-a-mac'                — totally malformed (no colons)
#   2. 'gg:gg:gg:gg:gg:gg'        — right shape, non-hex octets
#   3. '01:02:03:04:05'           — too few octets (5)
#   4. '01:02:03:04:05:06:07'     — too many octets (7)
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)
stderr_file=$(mktemp /tmp/xdpmf-clibadmac-stderr.XXXXXX)
trap 'rm -f "${stderr_file}"' EXIT

bad_macs=(
    'not-a-mac'
    'gg:gg:gg:gg:gg:gg'
    '01:02:03:04:05'
    '01:02:03:04:05:06:07'
)

fail=0
for bad in "${bad_macs[@]}"; do
    echo "=== sub-case: --allow '${bad}'"
    : >"${stderr_file}"
    set +e
    "${LOADER_BIN}" attach --iface lo --allow "${bad}" 2> "${stderr_file}"
    rc=$?
    set -e
    echo "rc=${rc}"
    echo "--- stderr ---"
    cat "${stderr_file}" >&2 || true
    echo "--- end stderr ---"

    if [[ "${rc}" -ne 1 ]]; then
        echo "FAIL[${bad}]: expected rc=1 (CLI usage error), got ${rc}" >&2
        fail=1
    fi
    # Recognizable token — exact wording is impl-shape, so we accept any
    # case-insensitive 'mac' substring anywhere in stderr.
    if ! grep -qi -- 'mac' "${stderr_file}"; then
        echo "FAIL[${bad}]: stderr lacks recognizable 'mac' token" >&2
        fail=1
    fi
done

[[ "${fail}" == 0 ]] && echo "PASS: T_CLI_BAD_MAC"
exit "${fail}"
