#!/bin/bash
# T_CLI_CAPACITY — design §6.11 (MVP-1.1C / §5.21 D2).
#
# Allow-list overflow rejected: invoke `attach` with 65 distinct MACs
# (one more than XDPMF_ALLOWLIST_MAX = 64 per §3.3).  The CLI parser
# MUST reject before any libbpf call, returning exit 1 with a
# recognizable stderr substring.
#
# Pure CLI-parser test; no veth, no root, no SKIP_RETURN_CODE.
# Trigger uses --iface lo only so the parser has a syntactically valid
# iface to chew on before the capacity check; even if the parser
# happened to validate iface before counting MACs, lo is the only iface
# guaranteed to exist on every Linux host.
#
# Outcome:
#   - rc == 1 (CLI usage error, §4.1)
#   - stderr contains literal substring 'too many --allow entries'
#     (the `(max 64)` tail is impl-shape and NOT asserted)
#   - sanity floor: no XDP on lo after invocation (parser error happens
#     before attach — we should never have reached the kernel path)
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)
stderr_file=$(mktemp /tmp/xdpmf-clicap-stderr.XXXXXX)
trap 'rm -f "${stderr_file}"' EXIT

# Build a 65-MAC comma-separated list: 02:00:00:00:00:00 .. 02:00:00:00:00:40
# (65 distinct MACs — one more than XDPMF_ALLOWLIST_MAX).
list=""
for i in $(seq 0 64); do
    list+=$(printf '02:00:00:00:%02x:%02x,' $(( i / 256 )) $(( i % 256 )))
done
list="${list%,}"  # strip trailing comma

echo "=== invoke loader with 65 MACs (one over capacity)"
set +e
"${LOADER_BIN}" attach --iface lo --allow "${list}" 2> "${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
echo "--- stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

fail=0

if [[ "${rc}" -ne 1 ]]; then
    echo "FAIL: expected rc=1 (CLI usage error), got ${rc}" >&2
    fail=1
fi

if ! grep -q -F -- 'too many --allow entries' "${stderr_file}"; then
    echo "FAIL: stderr missing literal 'too many --allow entries'" >&2
    fail=1
fi

# Sanity floor: parser-only error means no attach happened on lo.
# If any XDP id appears on lo, either we reached the attach path
# (capacity check didn't actually short-circuit) or pre-existing
# state was present (a separate environmental concern; either way
# the contract is violated for this run).
left=$(xdp_prog_id lo 2>/dev/null || true)
if [[ -n "${left}" ]]; then
    echo "FAIL: XDP attached to lo (prog_id=${left}) after rejected parse" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_CLI_CAPACITY"
exit "${fail}"
