#!/bin/bash
# T_EXPORTER_BIND_NON_LOOPBACK_WARN — design §5.39 (MVP-3.4h) TestStrategy T-1.
#
# Exporter emits a startup WARN (event `exporter.warn.bind_non_loopback`)
# when `--bind <addr>` resolves to a non-loopback IPv4 address — i.e., NOT
# in `127.0.0.0/8` (HG-3.4h-2 numerical bitmask check on parsed in_addr).
# Default `--bind=127.0.0.1` and any 127.0.0.0/8 address stays silent
# (no operator-observable behavior change on the default path; PI-3.5-1).
# WARN-only posture per HG-3.4h-4 (no refusal). Closes /mint-review sec M2
# (KC-2 observability half).
#
# Sub-cases (per §5.39 TestStrategy T-1 table + D-3.4h-7 LOAD-BEARING prose):
#   (a) PRIMARY positive (text):   --bind 0.0.0.0
#       → stderr contains literal substring `WARN --bind 0.0.0.0 is not loopback`
#         AND `(127.0.0.0/8)` AND `/metrics will be exposed on a routable
#         interface`; exporter starts (listening healthz responsive).
#   (b) UPPER-EDGE negation (text): --bind 127.255.255.255
#       → stderr does NOT contain `bind_non_loopback` token nor `WARN --bind`
#         prose. Proves HG-3.4h-2 full /8 coverage at the upper boundary.
#         Defensive: 127.255.255.255 may or may not bind on a given host;
#         per D-3.4h-1 the WARN check fires BEFORE ::socket(), so the
#         absence assertion is well-defined regardless of subsequent bind
#         success.
#   (c) DEFAULT negation (text):   no --bind flag (default 127.0.0.1)
#       → stderr does NOT contain bind_non_loopback substring / token.
#   (d) IN-RANGE non-default negation (text): --bind 127.0.0.2
#       → stderr does NOT contain bind_non_loopback substring / token.
#         Proves the check is NOT a degenerate exact-match on 127.0.0.1.
#   (e) JSON-mode positive: --bind 0.0.0.0 + XDPMF_LOG_FORMAT=json
#       → exactly 1 NDJSON object with .event=="exporter.warn.bind_non_loopback"
#         AND .level=="warn" AND .fields.bind_addr=="0.0.0.0".
#         Validates the structured-logging surface for the new event token
#         (HG-3.4h-3 + D-3.4h-3 catalog placement).
#
# Sanity-floor smoke: each positive sub-case polls /healthz BEFORE
#   asserting on stderr — the exporter is proven up and serving requests
#   before the WARN-content check runs.
# Negation control: sub-cases (b), (c), (d) — KNOWN-GOOD inputs that MUST
#   NOT trigger the WARN. Without them sub-case (a) is unfalsifiable
#   (a sloppy impl that emits the WARN unconditionally would still pass).
#
# SKIP-77: curl absent (positive sub-cases need readiness probe);
#          xdpmf-exporter binary missing (build dependency); jq absent
#          downgrades sub-case (e) to NOTE-only (sub-cases a-d still run).
#
# Cleanup: trap-driven kill of EXPORTER_PID; tmpfile rm; non-existent
#   bpffs root scrubbed (will not exist anyway).
#
# RESOURCE_LOCK (per D-3.4h-T1-LOCK + Q4): `exporter_port_9417` ONLY.
#   No xdp_fixture — this test does NOT touch the veth pair or attach any
#   XDP program; minimizing lock surface per architect spec guard #12.
#
# Maps to: PI-3.4h-1 (positive sub-case (a) + negation (c) + (d)),
#          PI-3.4h-K (kEventNames catalog presence proven by sub-case (e)
#                     succeeding under JSON mode — event-name resolves),
#          HG-3.4h-2, HG-3.4h-3, HG-3.4h-4,
#          D-3.4h-7 LOAD-BEARING text prose contract.

set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not in PATH (required by §5.39 T-1 for /healthz readiness probe)" >&2
    exit 77
fi

find_exporter() {
    if [[ -n "${XDPMF_EXPORTER_BIN:-}" && -x "${XDPMF_EXPORTER_BIN}" ]]; then
        printf '%s\n' "${XDPMF_EXPORTER_BIN}"; return 0
    fi
    local cand
    for cand in \
        "${BUILD_DIR}/xdpmf-exporter" \
        "${BUILD_DIR}/src/exporter/xdpmf-exporter" \
        "${BUILD_DIR}/bin/xdpmf-exporter"; do
        if [[ -x "$cand" ]]; then printf '%s\n' "$cand"; return 0; fi
    done
    local found
    found=$(find "${BUILD_DIR}" -maxdepth 5 -type f -executable -name xdpmf-exporter 2>/dev/null | head -1 || true)
    if [[ -n "${found}" ]]; then printf '%s\n' "${found}"; return 0; fi
    return 1
}

EXPORTER_BIN=$(find_exporter) || {
    echo "FAIL: xdpmf-exporter binary not found under ${BUILD_DIR}" >&2
    exit 1
}
echo "exporter=${EXPORTER_BIN}"

# Per-PID port; RESOURCE_LOCK exporter_port_9417 serializes against the
# sibling exporter ctests, the PID modulus distributes across rerun
# instances. We reuse the same port across sub-cases (each sub-case kills
# the prior exporter before launching the next).
PORT=$(( 9417 + ($$ % 1000) ))
echo "PORT=${PORT}"

# Non-existent bpffs root → exporter prints HK-16 WARN ("bpffs root ...
# does not exist") and then serves empty metrics (PI-32 graceful-empty).
# The HK-16 substring (`WARN bpffs root`) is DISJOINT from the substring
# we look for (`WARN --bind`), so an extra HK-16 line never confounds
# our assertions. Saves us a mkdir + chmod dance for fixture setup.
MISSING_ROOT="/tmp/xdpmf-bindwarn-noexist-${$}-$(date +%s)"
echo "bpffs root (non-existent on purpose): ${MISSING_ROOT}"

exp_log_base=$(mktemp /tmp/xdpmf-bindwarn-explog.XXXXXX)
EXPORTER_PID=""
fail=0

cleanup_test() {
    set +e
    if [[ -n "${EXPORTER_PID}" ]]; then
        sudo -n kill "${EXPORTER_PID}" 2>/dev/null
        sleep 0.2
        sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null
        wait "${EXPORTER_PID}" 2>/dev/null
        EXPORTER_PID=""
    fi
    rm -rf "${MISSING_ROOT}" 2>/dev/null
    rm -f "${exp_log_base}" "${exp_log_base}".[a-z] 2>/dev/null
    set -e
}
trap cleanup_test EXIT

# ── kill_exporter — best-effort termination of EXPORTER_PID (no-op if dead) ─
kill_exporter() {
    set +e
    if [[ -n "${EXPORTER_PID}" ]]; then
        sudo -n kill "${EXPORTER_PID}" 2>/dev/null
        sleep 0.2
        sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null
        wait "${EXPORTER_PID}" 2>/dev/null
        EXPORTER_PID=""
    fi
    set -e
}

# ── spawn_and_wait_ready <port> <log_path> <fmt> <poll_host> [extra-args...] ─
# Spawns the exporter with the given args; sets EXPORTER_PID; polls
# /healthz on <poll_host>:<port> for up to 5s. <poll_host> MUST match
# the address the exporter is actually listening on — a socket bound to
# `--bind 127.0.0.2` does NOT accept connections destined to 127.0.0.1
# (TCP listening sockets are address-specific even when the destination
# is within the same /8 loopback range); for `--bind 0.0.0.0` any local
# address works, so callers pass "127.0.0.1".
# fmt="" → no env prefix; fmt="text" / fmt="json" → XDPMF_LOG_FORMAT.
# Returns 0 on ready; 1 on early-death OR readiness timeout. On the
# failure return paths the exporter is KILLED before returning so its
# port does not leak into subsequent sub-cases (EADDRINUSE cascade).
spawn_and_wait_ready() {
    local sub_port="$1"; shift
    local sub_log="$1"; shift
    local fmt="$1"; shift
    local poll_host="$1"; shift
    : > "${sub_log}"
    if [[ -n "${fmt}" ]]; then
        sudo -n env XDPMF_LOG_FORMAT="${fmt}" "${EXPORTER_BIN}" \
            --port "${sub_port}" \
            --bpffs-root "${MISSING_ROOT}" \
            "$@" \
            >"${sub_log}" 2>&1 &
    else
        sudo -n "${EXPORTER_BIN}" \
            --port "${sub_port}" \
            --bpffs-root "${MISSING_ROOT}" \
            "$@" \
            >"${sub_log}" 2>&1 &
    fi
    EXPORTER_PID=$!
    local i
    for i in $(seq 1 50); do
        if curl -sf -m 1 "http://${poll_host}:${sub_port}/healthz" -o /dev/null 2>/dev/null; then
            echo "  ready after ${i} polls (~$((i*100))ms) on ${poll_host}:${sub_port}"
            return 0
        fi
        if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
            echo "  exporter PID ${EXPORTER_PID} died during startup" >&2
            EXPORTER_PID=""
            return 1
        fi
        sleep 0.1
    done
    echo "  exporter not ready within 5s on ${poll_host}:${sub_port}" >&2
    # Don't leak the running exporter — kill before returning failure so
    # the next sub-case doesn't hit EADDRINUSE on the same port.
    sudo -n kill "${EXPORTER_PID}" 2>/dev/null
    sleep 0.2
    sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null
    wait "${EXPORTER_PID}" 2>/dev/null
    EXPORTER_PID=""
    return 1
}

# ── spawn_blind <port> <log_path> [extra-args...] ────────────────────────
# Spawns the exporter, sleeps 1.5s, kills it (no readiness probe). Used
# for sub-case (b) where the target bind address may not be locally
# reachable via curl (127.255.255.255). The WARN under test fires BEFORE
# ::socket() per D-3.4h-1, so 1.5s is ample for the (potential) emission
# AND the bind() failure to surface in stderr before we kill.
spawn_blind() {
    local sub_port="$1"; shift
    local sub_log="$1"; shift
    : > "${sub_log}"
    sudo -n "${EXPORTER_BIN}" \
        --port "${sub_port}" \
        --bpffs-root "${MISSING_ROOT}" \
        "$@" \
        >"${sub_log}" 2>&1 &
    EXPORTER_PID=$!
    sleep 1.5
}

# ════════════════════════════════════════════════════════════════════════
# Sub-case (a) — PRIMARY positive: --bind 0.0.0.0 → WARN expected (text)
# ════════════════════════════════════════════════════════════════════════
echo
echo "=== (a) PRIMARY positive: --bind 0.0.0.0 → WARN expected (text mode)"
log_a="${exp_log_base}.a"
if ! spawn_and_wait_ready "${PORT}" "${log_a}" "" "127.0.0.1" --bind 0.0.0.0; then
    echo "FAIL[a0]: exporter could not be brought up with --bind 0.0.0.0" >&2
    cat "${log_a}" >&2
    fail=1
else
    kill_exporter
    echo "--- (a) exporter log ---"
    cat "${log_a}"
    echo "--- end ---"

    # Per D-3.4h-7 LOAD-BEARING text-mode prose: exact substrings.
    if ! grep -qE 'WARN --bind 0\.0\.0\.0 is not loopback' "${log_a}"; then
        echo "FAIL[a1]: substring 'WARN --bind 0.0.0.0 is not loopback' missing" >&2
        fail=1
    fi
    if ! grep -qF '(127.0.0.0/8)' "${log_a}"; then
        echo "FAIL[a2]: substring '(127.0.0.0/8)' missing" >&2
        fail=1
    fi
    if ! grep -qF '/metrics will be exposed on a routable interface' "${log_a}"; then
        echo "FAIL[a3]: substring '/metrics will be exposed on a routable interface' missing" >&2
        fail=1
    fi
    # Per guard #19: text-mode prose convention is `xdpmf-exporter: WARN ...`
    # (no colon after WARN). Verify the prefix is present at least once on
    # the WARN line.
    if ! grep -qE '^xdpmf-exporter: WARN --bind 0\.0\.0\.0 is not loopback' "${log_a}"; then
        echo "FAIL[a4]: WARN line missing 'xdpmf-exporter: WARN' prefix per guard #19 convention" >&2
        fail=1
    fi
fi

# ════════════════════════════════════════════════════════════════════════
# Sub-case (b) — UPPER-EDGE negation: --bind 127.255.255.255 → no WARN
# ════════════════════════════════════════════════════════════════════════
# Architect (T-1 sub-case (b)) calls 127.255.255.255 "Operative-semantic;
# impl-flex on whether (b) is realized". On most hosts the kernel rejects
# bind() to 127.255.255.255 (broadcast); per D-3.4h-1 the WARN check
# happens BEFORE ::socket()/bind(), so the absence assertion is sound
# regardless of bind() outcome.
echo
echo "=== (b) UPPER-EDGE negation: --bind 127.255.255.255 (top of 127.0.0.0/8) → no WARN"
log_b="${exp_log_base}.b"
spawn_blind "${PORT}" "${log_b}" --bind 127.255.255.255
kill_exporter
echo "--- (b) exporter log ---"
cat "${log_b}"
echo "--- end ---"

if grep -qE 'WARN --bind .* is not loopback' "${log_b}"; then
    echo "FAIL[b1]: bind_non_loopback WARN fired on 127.255.255.255 (in-range upper edge of /8)" >&2
    fail=1
fi
if grep -qF 'bind_non_loopback' "${log_b}"; then
    echo "FAIL[b2]: 'bind_non_loopback' event token leaked into 127.255.255.255 log" >&2
    fail=1
fi

# ════════════════════════════════════════════════════════════════════════
# Sub-case (c) — DEFAULT negation: no --bind (default 127.0.0.1) → no WARN
# ════════════════════════════════════════════════════════════════════════
echo
echo "=== (c) DEFAULT negation: no --bind (HttpConfig default 127.0.0.1) → no WARN"
log_c="${exp_log_base}.c"
if ! spawn_and_wait_ready "${PORT}" "${log_c}" "" "127.0.0.1"; then
    echo "FAIL[c0]: exporter could not be brought up with default --bind=127.0.0.1" >&2
    cat "${log_c}" >&2
    fail=1
else
    kill_exporter
    echo "--- (c) exporter log ---"
    cat "${log_c}"
    echo "--- end ---"

    if grep -qE 'WARN --bind .* is not loopback' "${log_c}"; then
        echo "FAIL[c1]: bind_non_loopback WARN fired on default --bind=127.0.0.1 (regression)" >&2
        fail=1
    fi
    if grep -qF 'bind_non_loopback' "${log_c}"; then
        echo "FAIL[c2]: 'bind_non_loopback' event token leaked into default-bind log" >&2
        fail=1
    fi
fi

# ════════════════════════════════════════════════════════════════════════
# Sub-case (d) — IN-RANGE non-default negation: --bind 127.0.0.2 → no WARN
# ════════════════════════════════════════════════════════════════════════
echo
echo "=== (d) IN-RANGE non-default negation: --bind 127.0.0.2 → no WARN"
log_d="${exp_log_base}.d"
if ! spawn_and_wait_ready "${PORT}" "${log_d}" "" "127.0.0.2" --bind 127.0.0.2; then
    echo "FAIL[d0]: exporter could not be brought up with --bind 127.0.0.2" >&2
    cat "${log_d}" >&2
    fail=1
else
    kill_exporter
    echo "--- (d) exporter log ---"
    cat "${log_d}"
    echo "--- end ---"

    if grep -qE 'WARN --bind .* is not loopback' "${log_d}"; then
        echo "FAIL[d1]: bind_non_loopback WARN fired on 127.0.0.2 (in-range non-default) — HG-3.4h-2 violation" >&2
        echo "          impl appears to be doing degenerate exact-match on 127.0.0.1 instead of /8 bitmask check" >&2
        fail=1
    fi
    if grep -qF 'bind_non_loopback' "${log_d}"; then
        echo "FAIL[d2]: 'bind_non_loopback' event token leaked into 127.0.0.2 log" >&2
        fail=1
    fi
fi

# ════════════════════════════════════════════════════════════════════════
# Sub-case (e) — JSON-mode positive: --bind 0.0.0.0 → structured event
# ════════════════════════════════════════════════════════════════════════
echo
echo "=== (e) JSON-mode positive: --bind 0.0.0.0 + XDPMF_LOG_FORMAT=json"
if ! command -v jq >/dev/null 2>&1; then
    echo "[e] NOTE: jq not in PATH — JSON-mode sub-case (e) skipped (sub-cases a-d still ran)"
else
    log_e="${exp_log_base}.e"
    if ! spawn_and_wait_ready "${PORT}" "${log_e}" "json" "127.0.0.1" --bind 0.0.0.0; then
        echo "FAIL[e0]: exporter could not be brought up under JSON mode + --bind 0.0.0.0" >&2
        cat "${log_e}" >&2
        fail=1
    else
        # Settle a moment so startup events are flushed before we kill.
        sleep 0.2
        kill_exporter
        echo "--- (e) exporter log (json) ---"
        cat "${log_e}"
        echo "--- end ---"

        # Exactly one event with the new token.
        warn_count=$(jq -s '[.[] | select(.event == "exporter.warn.bind_non_loopback")] | length' "${log_e}" 2>/dev/null || echo 0)
        echo "[e] exporter.warn.bind_non_loopback event count = ${warn_count}"
        if [[ "${warn_count}" != "1" ]]; then
            echo "FAIL[e1]: expected exactly 1 exporter.warn.bind_non_loopback event, got ${warn_count}" >&2
            fail=1
        fi

        # .level must be "warn".
        lvl=$(jq -s -r '.[] | select(.event == "exporter.warn.bind_non_loopback") | .level' "${log_e}" 2>/dev/null | head -1)
        echo "[e] .level = '${lvl}'"
        if [[ "${lvl}" != "warn" ]]; then
            echo "FAIL[e2]: expected .level='warn', got '${lvl}'" >&2
            fail=1
        fi

        # .fields.bind_addr must carry the operator's --bind argument verbatim.
        bind_field=$(jq -s -r '.[] | select(.event == "exporter.warn.bind_non_loopback") | .fields.bind_addr' "${log_e}" 2>/dev/null | head -1)
        echo "[e] .fields.bind_addr = '${bind_field}'"
        if [[ "${bind_field}" != "0.0.0.0" ]]; then
            echo "FAIL[e3]: expected .fields.bind_addr='0.0.0.0', got '${bind_field}'" >&2
            fail=1
        fi
    fi
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_EXPORTER_BIND_NON_LOOPBACK_WARN"
exit "${fail}"
