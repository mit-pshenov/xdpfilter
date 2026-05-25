#!/bin/bash
# T_EXPORTER_NO_ATTACHED_IFACE — design §6.39 (MVP-3.4 / §5.29).
#
# Exporter serves cleanly on a system with zero attached XDP. PI-32:
# graceful-empty-bpffs handling; PI-31: exporter does not try to attach
# anything; HG-3.4-3 format compliance for the empty case.
#
# Trigger:
#   1. Point exporter at a FRESH empty bpffs root path (--bpffs-root
#      /tmp/xdpmf-empty-$$/, which we do NOT create). NO veth setup.
#   2. Start exporter in background on per-PID port.
#   3. curl /metrics → /tmp/metrics.out.
#
# Observable outcome (ALL must hold):
#   (a) curl exits 0; HTTP 200; body contains HELP+TYPE lines.
#   (b) Body has ZERO sample lines (no `^xdpfilter_packets_total\{...\}` lines).
#   (c) Exporter still alive after the request (kill -0 succeeds).
#   (d) Smoke: a second curl /healthz returns 200 — confirms exporter
#       didn't crash after the empty /metrics response (anti-crash on
#       repeated empty scrapes).
#
# Sanity-floor smoke: (a) AND (d) together — process up, two requests
# succeed.
# Negation control: this IS the "no-crash on absent fixture" failure-path
# probe — if the exporter raised on missing/empty bpffs (e.g., uncaught
# bpf_obj_get(non-existent) exception), (a) or (c) would fail.
#
# SKIP: curl absent → exit 77.
#
# Cleanup: kill exporter.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

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

if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not in PATH (required by §6.39)" >&2
    exit 77
fi

EXPORTER_BIN=$(find_exporter) || {
    echo "FAIL: xdpmf-exporter binary not found under ${BUILD_DIR}" >&2
    exit 1
}
echo "exporter=${EXPORTER_BIN}"

PORT=$(( 9417 + ($$ % 1000) ))
echo "EXPORTER_PORT=${PORT}"

# Fresh, non-existent bpffs root. Per PI-32: "if ${XDPMF_BPFFS_ROOT} does
# not exist, exporter logs ONE warning line at startup but continues."
EMPTY_ROOT="/tmp/xdpmf-empty-${$}-$(date +%s)"
echo "empty bpffs root: ${EMPTY_ROOT}"

metrics_body=$(mktemp /tmp/xdpmf-noattach-metrics.XXXXXX)
exp_log=$(mktemp /tmp/xdpmf-noattach-explog.XXXXXX)
EXPORTER_PID=""

cleanup_test() {
    set +e
    if [[ -n "${EXPORTER_PID}" ]]; then
        sudo -n kill "${EXPORTER_PID}" 2>/dev/null
        sleep 0.2
        sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null
        wait "${EXPORTER_PID}" 2>/dev/null
    fi
    rm -rf "${EMPTY_ROOT}" 2>/dev/null
    rm -f "${metrics_body}" "${exp_log}"
    set -e
}
trap cleanup_test EXIT

# ── start exporter against non-existent bpffs root ──────────────────────
echo "=== starting xdpmf-exporter on 127.0.0.1:${PORT} (root=${EMPTY_ROOT})"
sudo -n "${EXPORTER_BIN}" \
    --port "${PORT}" \
    --bind 127.0.0.1 \
    --bpffs-root "${EMPTY_ROOT}" \
    >"${exp_log}" 2>&1 &
EXPORTER_PID=$!

ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT}/healthz" -o /dev/null 2>/dev/null; then
        ready=1; echo "exporter ready after ${i} polls (~$((i*100))ms)"; break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        echo "FAIL: exporter PID ${EXPORTER_PID} died during startup against empty bpffs" >&2
        echo "--- exporter log ---" >&2
        cat "${exp_log}" >&2
        exit 1
    fi
    sleep 0.1
done

fail=0
if [[ "${ready}" != "1" ]]; then
    echo "FAIL: exporter not ready within 5s on empty bpffs" >&2
    cat "${exp_log}" >&2
    exit 1
fi

# ── (a) curl /metrics → 200 + HELP+TYPE present ─────────────────────────
echo "=== curl /metrics"
set +e
http_code=$(curl -s -o "${metrics_body}" -w '%{http_code}' \
    -m 5 "http://127.0.0.1:${PORT}/metrics")
curl_rc=$?
set -e
echo "curl rc=${curl_rc} http_code=${http_code}"
echo "--- body ---"
cat "${metrics_body}"
echo "--- end ---"

if [[ "${curl_rc}" -ne 0 ]]; then
    echo "FAIL[a1]: curl rc=${curl_rc}" >&2; fail=1
fi
if [[ "${http_code}" != "200" ]]; then
    echo "FAIL[a2]: HTTP status ${http_code} (expected 200)" >&2; fail=1
fi
if ! grep -qE '^# HELP xdpfilter_packets_total ' "${metrics_body}"; then
    echo "FAIL[a3]: body missing HELP line" >&2; fail=1
fi
if ! grep -qE '^# TYPE xdpfilter_packets_total counter$' "${metrics_body}"; then
    echo "FAIL[a4]: body missing TYPE line" >&2; fail=1
fi

# ── (b) ZERO sample lines ───────────────────────────────────────────────
# `grep -c` always prints the count to stdout, even when no match found
# (only the exit code differs). Use `|| true` to swallow rc=1 without
# emitting a second "0" — `|| echo 0` would yield a multi-line "0\n0".
sample_count=$(grep -cE '^xdpfilter_packets_total\{' "${metrics_body}" 2>/dev/null || true)
sample_count=${sample_count:-0}
echo "sample line count: ${sample_count}"
if [[ "${sample_count}" != "0" ]]; then
    echo "FAIL[b]: expected 0 sample lines on empty bpffs, got ${sample_count}" >&2
    fail=1
fi

# ── (c) exporter still alive ────────────────────────────────────────────
if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
    echo "FAIL[c]: exporter PID ${EXPORTER_PID} dead after first /metrics request" >&2
    fail=1
fi

# ── (d) second healthz (anti-crash on repeated empty scrapes) ───────────
echo "=== second curl /healthz (anti-crash check)"
set +e
http2=$(curl -s -o /dev/null -w '%{http_code}' -m 5 "http://127.0.0.1:${PORT}/healthz")
curl2_rc=$?
set -e
echo "second healthz: rc=${curl2_rc} http=${http2}"
if [[ "${curl2_rc}" -ne 0 ]] || [[ "${http2}" != "200" ]]; then
    echo "FAIL[d]: second /healthz failed (rc=${curl2_rc} status=${http2}) — exporter unstable on empty bpffs" >&2
    fail=1
fi
if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
    echo "FAIL[d2]: exporter died between the two requests" >&2
    fail=1
fi

# ── HK-16 (§5.30): startup WARN MUST be present on nonexistent bpffs root ─
# Per PI-32 (strengthened in §5.30): exporter logs ONE warning line at
# startup when --bpffs-root does not exist. Exact wording per HK-16 spec:
#   xdpmf-exporter: WARN bpffs root <path> does not exist; will serve empty metrics
# The W1 semantic also dictates: the WARN MUST NOT fire when the path
# EXISTS but is empty (graceful-empty contract). Sub-case 2 below
# verifies the negation.
echo
echo "=== HK-16: WARN substring on stderr when --bpffs-root path does not exist"
warn_ere='xdpmf-exporter: WARN bpffs root .* does not exist; will serve empty metrics'
if ! grep -qE -- "${warn_ere}" "${exp_log}"; then
    echo "FAIL[hk16-a]: exporter log missing HK-16 WARN line matching ERE:" >&2
    echo "              ${warn_ere}" >&2
    fail=1
fi

# ── HK-16 SUB-CASE 2: WARN MUST NOT fire when bpffs root EXISTS but empty ─
echo
echo "=== HK-16 sub-case 2: existing-but-empty bpffs root → WARN MUST NOT fire"

# Kill the primary exporter first to free the port.
if [[ -n "${EXPORTER_PID}" ]]; then
    sudo -n kill "${EXPORTER_PID}" 2>/dev/null || true
    sleep 0.2
    sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null || true
    wait "${EXPORTER_PID}" 2>/dev/null || true
    EXPORTER_PID=""
fi

EXIST_ROOT=$(sudo -n mktemp -d /sys/fs/bpf/xdpmf-empty-existing-XXXXXX 2>/dev/null) || {
    # Fallback: bpffs may not support mktemp; use a deterministic name.
    EXIST_ROOT="/sys/fs/bpf/xdpmf-empty-existing-$$"
    sudo -n mkdir -p "${EXIST_ROOT}" 2>/dev/null
}
echo "existing-empty bpffs root: ${EXIST_ROOT}"

# Re-use the same port — primary exporter is gone.
exp_log2=$(mktemp /tmp/xdpmf-noattach-explog2.XXXXXX)
sudo -n "${EXPORTER_BIN}" \
    --port "${PORT}" \
    --bind 127.0.0.1 \
    --bpffs-root "${EXIST_ROOT}" \
    >"${exp_log2}" 2>&1 &
EXPORTER_PID=$!

# Wait for ready (or quick die).
ready2=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT}/healthz" -o /dev/null 2>/dev/null; then
        ready2=1; break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

# Force one scrape so the exporter has done its work.
if [[ "${ready2}" == "1" ]]; then
    curl -s -m 2 "http://127.0.0.1:${PORT}/metrics" -o /dev/null 2>/dev/null || true
fi

echo "--- exporter log (existing-empty) ---"
cat "${exp_log2}" || true
echo "--- end ---"

# WARN MUST NOT appear (the directory exists; W1 contract is "exists
# check, not contents check").
if grep -qE -- "${warn_ere}" "${exp_log2}"; then
    echo "FAIL[hk16-b]: WARN line FIRED on existing-but-empty bpffs root — over-WARN regression" >&2
    echo "              W1 contract: PI-32 startup WARN is ONLY for nonexistent paths" >&2
    fail=1
fi

# Cleanup sub-case 2 exporter + tmpdir.
sudo -n kill "${EXPORTER_PID}" 2>/dev/null || true
sleep 0.2
sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null || true
wait "${EXPORTER_PID}" 2>/dev/null || true
EXPORTER_PID=""
sudo -n rmdir "${EXIST_ROOT}" 2>/dev/null || true
rm -f "${exp_log2}"

[[ "${fail}" == 0 ]] && echo "PASS: T_EXPORTER_NO_ATTACHED_IFACE"
exit "${fail}"
