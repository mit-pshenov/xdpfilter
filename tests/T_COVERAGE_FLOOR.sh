#!/bin/bash
# T_COVERAGE_FLOOR — design §6.81 (MVP-4.23 / §5.63, TEST-H2 / C-2).
#
# The non-skipping coverage-floor gate (guard #31). Closes TEST-H2: most
# datapath tests SKIP_RETURN_CODE 77 when passwordless sudo is absent AND the
# T_NEGATION_CONTROL sanity canary (whose whole job is to prove the suite
# isn't a no-op) is ITSELF among the skippable tests — so a coverage-zero CI
# run is indistinguishable from a healthy one (near-all-green while exercising
# nothing).
#
# This gate is DELIBERATELY:
#   - registered WITHOUT SKIP_RETURN_CODE 77 (it must never skip — see
#     PI-mvp-4.23-NO-SKIP-FLOOR), and
#   - does NOT source/call require_passwordless_sudo (calling the skip helper
#     would let it skip → theatre).
#
# Mechanism (D-mvp-4.23-Q1-A2): reads the XDPMF_REQUIRE_FULL_COVERAGE env var
# (the SOLE coupling with ci.yml, which sets it to "1"):
#   - "1"  → coverage-expected context (CI): the full datapath suite incl. the
#            T_NEGATION_CONTROL canary MUST be reachable, i.e. passwordless
#            sudo MUST be present. If `sudo -n true` fails here → RED (exit 1):
#            refusing to report a coverage-zero run as green.
#   - unset / "0" / anything ≠ "1" → gate INACTIVE, a green no-op (the
#     local-developer default: a userspace-only ctest run is legitimately
#     allowed to SKIP the sudo-gated datapath tests).
#
# Non-vacuity (D-mvp-4.23-Q1-SELFTEST): the RED branch only fires in a
# sudo-less context that the (sudo-present) dev/CI box can't reproduce LIVE.
# So the decision is factored into the pure helper floor_verdict(require,
# sudo_ok) and an intrinsic deterministic self-test asserts the full verdict
# truth-table on EVERY run — PROVING the RED path is reachable regardless of
# the live sudo state. This is the simulated coverage-zero condition the brief
# mandates be shown to go RED.
#
# This test MUST NOT exit 77 under any path.

set -euo pipefail

# ── Pure verdict helper (no environment access) ──────────────────────────
# floor_verdict <require_flag> <sudo_ok 0|1> → returns 0 = PASS, 1 = RED.
# RED iff coverage is REQUIRED (require_flag == "1") but sudo is unreachable
# (sudo_ok == 0). Every other combination is PASS.
floor_verdict() {
    local require="$1" sudo_ok="$2"
    if [[ "${require}" == "1" && "${sudo_ok}" -eq 0 ]]; then
        return 1
    fi
    return 0
}

# ── (a) Intrinsic self-test — the deterministic non-vacuity proof ─────────
# Asserts the verdict truth-table independent of the live environment, so the
# RED branch is provably reachable on every run (NOT just in a sudo-less CI).
selftest_floor_verdict() {
    local rc

    # verdict(require=1, sudo_ok=0) == RED(1)  ← the load-bearing row
    floor_verdict 1 0; rc=$?
    if [[ "${rc}" -ne 1 ]]; then
        echo "SELFTEST FAIL: floor_verdict(1,0) expected RED(1), got ${rc}" >&2
        return 1
    fi

    # verdict(1,1) == PASS(0)
    floor_verdict 1 1; rc=$?
    if [[ "${rc}" -ne 0 ]]; then
        echo "SELFTEST FAIL: floor_verdict(1,1) expected PASS(0), got ${rc}" >&2
        return 1
    fi

    # verdict(0,0) == PASS(0)
    floor_verdict 0 0; rc=$?
    if [[ "${rc}" -ne 0 ]]; then
        echo "SELFTEST FAIL: floor_verdict(0,0) expected PASS(0), got ${rc}" >&2
        return 1
    fi

    # verdict(0,1) == PASS(0)
    floor_verdict 0 1; rc=$?
    if [[ "${rc}" -ne 0 ]]; then
        echo "SELFTEST FAIL: floor_verdict(0,1) expected PASS(0), got ${rc}" >&2
        return 1
    fi

    echo "selftest: verdict truth-table OK (RED branch proven reachable: verdict(1,0)==RED)"
    return 0
}

if ! selftest_floor_verdict; then
    echo "FAIL: T_COVERAGE_FLOOR self-test failed — the gate is vacuous/broken" >&2
    exit 1
fi

# ── (b) Live gate — compute the real verdict from the environment ─────────
require="${XDPMF_REQUIRE_FULL_COVERAGE:-}"
sudo_ok=0
if sudo -n true 2>/dev/null; then
    sudo_ok=1
fi

if floor_verdict "${require}" "${sudo_ok}"; then
    if [[ "${require}" == "1" ]]; then
        echo "PASS: T_COVERAGE_FLOOR (coverage-expected; passwordless sudo present → datapath suite reachable)"
    else
        echo "PASS: T_COVERAGE_FLOOR (gate inactive; XDPMF_REQUIRE_FULL_COVERAGE='${require}' ≠ '1' → local no-op)"
    fi
    exit 0
fi

echo "FAIL: coverage-expected (XDPMF_REQUIRE_FULL_COVERAGE=1) but passwordless sudo absent →" >&2
echo "      the datapath suite + the T_NEGATION_CONTROL canary would all SKIP-77," >&2
echo "      so this run would report near-all-green while exercising NOTHING." >&2
echo "      Refusing to report a coverage-zero run as green (guard #31)." >&2
exit 1
