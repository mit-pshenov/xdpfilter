#!/bin/bash
# T_MODE_DETACH_REJECTS — design §6.19 (MVP-2 Perf / §5.23 Q1 Option A).
#
# Closes Q1 Option A: `detach` does NOT accept --mode. CLI parser rejects
# with exit 1 + stderr substring `attach-only` (recommended literal
# `--mode is attach-only`; tester accepts the shorter `attach-only`
# token per §6.19 impl-shape flexibility).
#
# Setup: minimal — no veth, no attach, no root. Parser rejects BEFORE
# any privileged syscall (no kernel call needed).  NO RESOURCE_LOCK
# (pure CLI surface, no shared kernel state).
#
# Trigger (two sub-cases, both must produce rc=1 + 'attach-only'):
#   1. detach --iface xdpmf_test --mode native
#   2. detach --iface xdpmf_test --mode generic
#      (proves rule is flag-presence-driven, not mode-value-driven —
#      §6.19 optional sub-variant.  Listed as recommended here for the
#      sanity-floor pair-test value.)
#
# Negation control (implicit): an `attach --mode native` invocation does
# NOT exit 1 with this same stderr — §6.17 covers the attach side.
# Within this test, the two sub-cases (native vs generic) also serve as
# pair-test diagnostic: if only one fails, the rule is mistakenly
# mode-value-driven.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)
stderr_file=$(mktemp /tmp/xdpmf-detrej-stderr.XXXXXX)
trap 'rm -f "${stderr_file}"' EXIT

# Use a literal placeholder iface name; CLI parser is expected to reject
# BEFORE if_nametoindex is called (--mode presence check fires first per
# §5.23 Q1 Option A wording).  Using a name that doesn't exist on the
# host is the conservative choice — if a future impl regression made
# if_nametoindex run before the --mode check, we'd get exit 1 anyway
# (iface unresolved) but the stderr substring would differ; the
# 'attach-only' grep is the load-bearing assertion that distinguishes
# the right rejection path from the wrong one.
PROBE_IFACE="${IFACE_A:-xdpmf_test}"

modes_to_test=(native generic)
fail=0

for mode in "${modes_to_test[@]}"; do
    echo "=== sub-case: detach --iface ${PROBE_IFACE} --mode ${mode}"
    : >"${stderr_file}"
    set +e
    "${LOADER_BIN}" detach --iface "${PROBE_IFACE}" --mode "${mode}" 2> "${stderr_file}"
    rc=$?
    set -e
    echo "rc=${rc}"
    echo "--- stderr ---"
    cat "${stderr_file}" >&2 || true
    echo "--- end stderr ---"

    # (a) Exit 1 — CLI usage error per §4.1.
    if [[ "${rc}" -ne 1 ]]; then
        echo "FAIL[${mode}]: expected rc=1 (CLI usage error), got ${rc}" >&2
        case "${rc}" in
            0) echo "        rc=0 means --mode was silently accepted on detach — Option W antipattern (regression)" >&2 ;;
            5) echo "        rc=5 means parser passed --mode through to detach() and the syscall failed — parser-level rejection broken" >&2 ;;
        esac
        fail=1
    fi

    # (b) Stderr contains the load-bearing 'attach-only' token (substring
    # of the recommended literal '--mode is attach-only' per §5.23 Q1 +
    # Item 2 stderr-discipline).
    if ! grep -q -F -- 'attach-only' "${stderr_file}"; then
        echo "FAIL[${mode}]: stderr lacks load-bearing 'attach-only' substring" >&2
        echo "        (per §5.23 Q1 stderr-discipline contract)" >&2
        fail=1
    fi
done

[[ "${fail}" == 0 ]] && echo "PASS: T_MODE_DETACH_REJECTS"
exit "${fail}"
