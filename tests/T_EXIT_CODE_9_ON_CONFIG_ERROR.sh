#!/bin/bash
# T_EXIT_CODE_9_ON_CONFIG_ERROR — design §6.27 (MVP-3.1 / §5.26).
#
# Bare-bones exit-code-9 audit-grep. Smoke-tests the wiring from
# main() → loader_error_category() → ConfigError exit 9 with ZERO fixture
# dependencies (no veth, no root needed, no alien fixture, no apply-file).
#
# Trigger: bad XDPMF_TRUST_MODEL=garbage invocation. Per §5.26 attach()
# flow update step 2, env parse happens BEFORE ifindex resolution, so:
#   - any iface arg is fine (rejected before resolved)
#   - no root needed (parse is pure userspace)
#   - no veth needed
#
# Observable outcome (per §6.27):
#   - exit code EXACTLY 9
#   - stderr starts with 'xdpmacfilter: config error:'
#   - stderr contains 'unknown trust model' (specific message)
#   - No XDP touched, no bpffs dir created (not asserted here — pure
#     binary-invocation test; the §6.26 sub-case 4 covers that with veth.)
#
# Ops-script writers grep for "exit 9" — this test is the canonical
# reference. If §6.26 fails for fixture-infrastructure reasons, §6.27
# still proves the exit-code path.
#
# Sanity-floor smoke: loader binary exists and runs. Negation control:
# this test asserts a non-zero exit code (specifically 9) — the opposite
# of T_CLI_HELP_VERSION's "exit 0" path. Together they bracket the
# success/failure exit-code surface.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)
stderr_file=$(mktemp /tmp/xdpmf-exit9-stderr.XXXXXX)
trap 'rm -f "${stderr_file}"' EXIT

fail=0

echo "=== invoke loader with XDPMF_TRUST_MODEL=garbage_value"
set +e
XDPMF_TRUST_MODEL=garbage_value \
    "${LOADER_BIN}" attach --iface lo --allow 02:00:00:00:00:01 2> "${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
echo "--- stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

# (a) Exit code EXACTLY 9.
if [[ "${rc}" -ne 9 ]]; then
    echo "FAIL[a]: expected rc=9 (LoaderError::ConfigError per §4.1), got ${rc}" >&2
    case "${rc}" in
        0) echo "         rc=0 means the garbage trust_model was IGNORED — env parse not wired" >&2 ;;
        1) echo "         rc=1 means CLI usage error — wrong axis; this is a config error" >&2 ;;
        3) echo "         rc=3 means AttachFailed (e.g., 'lo' resolved) — env parse happened TOO LATE" >&2 ;;
    esac
    fail=1
fi

# (b) Stderr STARTS with the expected prefix. The §5.26 stderr-discipline
#     guarantees a single-line 'xdpmacfilter: config error:' opener.
if ! grep -qE -- '^xdpmacfilter: config error:' "${stderr_file}"; then
    echo "FAIL[b]: stderr does not start with 'xdpmacfilter: config error:'" >&2
    fail=1
fi

# (c) Stderr contains the specific message naming the failure.
if ! grep -qE -- 'unknown trust model' "${stderr_file}"; then
    echo "FAIL[c]: stderr missing 'unknown trust model' substring" >&2
    fail=1
fi

# (d) Stderr names the rejected value (for operator debuggability).
if ! grep -q -F -- 'garbage_value' "${stderr_file}"; then
    echo "FAIL[d]: stderr does not echo the rejected value 'garbage_value'" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_EXIT_CODE_9_ON_CONFIG_ERROR"
exit "${fail}"
