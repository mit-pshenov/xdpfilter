#!/bin/bash
# T_CLI_HELP_VERSION — design §6.10 (MVP-1.1C / §5.21 D1).
#
# CLI surface lock: --help and --version exit cleanly and emit recognizable
# content without touching the kernel. Pure binary-invocation test; no veth,
# no root, no SKIP_RETURN_CODE (no sudo needed per design §6.10).
#
# Sub-cases (both must pass — fail aggregator pattern from §6.9):
#   1. ${LOADER_BIN} --help     → exit 0; stdout contains 'Usage:' AND 'attach' AND 'detach'.
#   2. ${LOADER_BIN} --version  → exit 0; single line; contains 'xdpmacfilter'
#                                 AND matches ERE [0-9]+\.[0-9]+\.[0-9]+
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)
stdout_file=$(mktemp /tmp/xdpmf-clihelp-stdout.XXXXXX)
trap 'rm -f "${stdout_file}"' EXIT

fail=0

# ── Sub-case 1: --help ───────────────────────────────────────────────────
echo "=== sub-case 1: --help"
set +e
"${LOADER_BIN}" --help >"${stdout_file}" 2>&1
rc=$?
set -e
echo "rc=${rc}"
echo "--- stdout ---"
cat "${stdout_file}"
echo "--- end stdout ---"

if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[--help]: expected rc=0, got ${rc}" >&2
    fail=1
fi
if ! grep -q -F -- 'Usage:' "${stdout_file}"; then
    echo "FAIL[--help]: stdout missing 'Usage:' literal" >&2
    fail=1
fi
if ! grep -q -F -- 'attach' "${stdout_file}"; then
    echo "FAIL[--help]: stdout missing 'attach' subcommand name" >&2
    fail=1
fi
if ! grep -q -F -- 'detach' "${stdout_file}"; then
    echo "FAIL[--help]: stdout missing 'detach' subcommand name" >&2
    fail=1
fi
# §5.23 Item 3 / §6.10 amendment (MVP-2 Perf): --mode flag MUST appear in
# the help text so the new attach option is operator-discoverable.
if ! grep -q -F -- '--mode' "${stdout_file}"; then
    echo "FAIL[--help]: stdout missing '--mode' substring (§5.23 Item 3 amendment)" >&2
    fail=1
fi

# ── Sub-case 2: --version ────────────────────────────────────────────────
echo "=== sub-case 2: --version"
: >"${stdout_file}"
set +e
"${LOADER_BIN}" --version >"${stdout_file}" 2>&1
rc=$?
set -e
echo "rc=${rc}"
echo "--- stdout ---"
cat "${stdout_file}"
echo "--- end stdout ---"

if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[--version]: expected rc=0, got ${rc}" >&2
    fail=1
fi
# Single line tolerance: 0 newlines (no trailing \n) OR exactly 1 newline.
lines=$(wc -l < "${stdout_file}")
if [[ "${lines}" -gt 1 ]]; then
    echo "FAIL[--version]: expected ≤1 newline (single line), got ${lines}" >&2
    fail=1
fi
if ! grep -q -F -- 'xdpmacfilter' "${stdout_file}"; then
    echo "FAIL[--version]: stdout missing 'xdpmacfilter' literal" >&2
    fail=1
fi
if ! grep -qE '[0-9]+\.[0-9]+\.[0-9]+' "${stdout_file}"; then
    echo "FAIL[--version]: stdout missing semver-shaped version token" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_CLI_HELP_VERSION"
exit "${fail}"
