#!/bin/bash
# T_EXPORTER_METRICS_FORMAT — design §6.37 (MVP-3.4 / §5.29).
#
# `/metrics` endpoint returns Prometheus text-format compliant output
# after attach + inject. Asserts the format contract from HG-3.4-3.
#
# Trigger:
#   1. setup_veth + attach (default action drop, allow MAC_GOOD).
#   2. Inject one allowed frame so STAT_PASS advances (no silent zeroes).
#   3. Start xdpmf-exporter in background on per-PID-derived port.
#   4. Poll until exporter accepts a /healthz request OR timeout.
#   5. curl /metrics, capture body + headers.
#
# Observable outcome (ALL must hold):
#   (a) curl exits 0; HTTP status 200.
#   (b) Response header contains 'text/plain; version=0.0.4' (per §5.29).
#   (c) Body contains '# HELP xdpfilter_packets_total ...' substring.
#   (d) Body contains '^# TYPE xdpfilter_packets_total counter$' line.
#   (e) Body contains ≥1 line matching the sample-line ERE
#       '^xdpfilter_packets_total\{iface="[^"]+",verdict="(pass|drop_deny|drop_malformed|pass_cidr)"\} [0-9]+$'.
#   (f) PI-33 smoke: `xdpmf-exporter --version` reports `xdpmf-exporter 0.6.0`.
#
# Sanity-floor smoke: step (a) + (f) — exporter starts AND --version works.
# Negation control: none in this test by itself — the failure-path control
# lives in T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE.
#
# SKIP conditions: `curl` absent → exit 77 (per §6.37 SKIP carve-out).
#
# Cleanup: kill exporter PID; cleanup_veth.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

# ── locate xdpmf-exporter binary ─────────────────────────────────────────
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

# ── SKIP if curl absent ──────────────────────────────────────────────────
if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not in PATH (required by §6.37)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
EXPORTER_BIN=$(find_exporter) || {
    echo "FAIL: xdpmf-exporter binary not found under ${BUILD_DIR}" >&2
    exit 1
}
echo "loader=${LOADER_BIN}"
echo "exporter=${EXPORTER_BIN}"

# Port derived from PID to avoid clash with parallel runners; xdp_fixture
# RESOURCE_LOCK also serializes us against the other 5 new MVP-3.4 tests.
PORT=$(( 9417 + ($$ % 1000) ))
echo "EXPORTER_PORT=${PORT}"

stdout_file=$(mktemp /tmp/xdpmf-expfmt-stdout.XXXXXX)
stderr_file=$(mktemp /tmp/xdpmf-expfmt-stderr.XXXXXX)
metrics_body=$(mktemp /tmp/xdpmf-expfmt-body.XXXXXX)
metrics_hdrs=$(mktemp /tmp/xdpmf-expfmt-hdrs.XXXXXX)
exp_log=$(mktemp /tmp/xdpmf-expfmt-explog.XXXXXX)

EXPORTER_PID=""
cleanup_test() {
    set +e
    if [[ -n "${EXPORTER_PID}" ]]; then
        sudo -n kill "${EXPORTER_PID}" 2>/dev/null
        sleep 0.2
        sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null
        wait "${EXPORTER_PID}" 2>/dev/null
    fi
    cleanup_veth
    rm -f "${stdout_file}" "${stderr_file}" "${metrics_body}" "${metrics_hdrs}" "${exp_log}"
    set -e
}
trap cleanup_test EXIT

# (f) PI-33 smoke — --version reports the expected string. Do this BEFORE
# touching the veth fixture so a binary-build failure flagged here is
# disentangled from any fixture/attach issue.
echo "=== xdpmf-exporter --version (PI-33 smoke)"
ver=$(${EXPORTER_BIN} --version 2>&1 | head -n1 || true)
echo "version line: '${ver}'"
fail=0
if [[ "${ver}" != "xdpmf-exporter 0.6.0" ]]; then
    echo "FAIL[f]: expected --version output 'xdpmf-exporter 0.6.0', got '${ver}'" >&2
    fail=1
fi

# ── setup veth + attach + inject one PASS frame so STAT_PASS > 0 ────────
setup_veth

echo "=== attach (default mode) on ${IFACE_A} allow=${MAC_GOOD}"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

if ! sudo -n test -e "${PIN_DIR}/stats"; then
    echo "FAIL: stats pin missing after attach (cannot proceed)" >&2
    exit 1
fi

echo "=== inject 1 frame (src=${MAC_GOOD}) to advance STAT_PASS"
inject_eth "${IFACE_B}" "${MAC_GOOD}" "${MAC_DST}"
wait_for_stats_sum "${IFACE_A}" 1 || true

# ── start exporter in background ────────────────────────────────────────
# Use the host-global PIN_ROOT so the exporter sees our pinned per-iface
# stats map (PIN_DIR is ${PIN_ROOT}/${IFACE_A}).
echo "=== starting xdpmf-exporter on 127.0.0.1:${PORT}"
sudo -n "${EXPORTER_BIN}" \
    --port "${PORT}" \
    --bind 127.0.0.1 \
    --bpffs-root "${PIN_ROOT}" \
    >"${exp_log}" 2>&1 &
EXPORTER_PID=$!
echo "EXPORTER_PID=${EXPORTER_PID}"

# Poll for readiness (≤5s).
ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT}/healthz" -o /dev/null 2>/dev/null; then
        ready=1
        echo "exporter ready after ${i} polls (~$((i*100))ms)"
        break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        echo "FAIL: exporter PID ${EXPORTER_PID} died during startup" >&2
        echo "--- exporter log ---" >&2
        cat "${exp_log}" >&2
        echo "--- end exporter log ---" >&2
        exit 1
    fi
    sleep 0.1
done

if [[ "${ready}" != "1" ]]; then
    echo "FAIL: exporter did not become ready within 5s" >&2
    echo "--- exporter log ---" >&2
    cat "${exp_log}" >&2
    echo "--- end exporter log ---" >&2
    exit 1
fi

# ── (a) curl /metrics → 200 OK ──────────────────────────────────────────
echo "=== curl /metrics"
set +e
http_code=$(curl -s -o "${metrics_body}" -D "${metrics_hdrs}" -w '%{http_code}' \
    -m 5 "http://127.0.0.1:${PORT}/metrics")
curl_rc=$?
set -e
echo "curl rc=${curl_rc} http_code=${http_code}"
echo "--- response headers ---"
cat "${metrics_hdrs}"
echo "--- response body (first 30 lines) ---"
head -n30 "${metrics_body}"
echo "--- end ---"

if [[ "${curl_rc}" -ne 0 ]]; then
    echo "FAIL[a1]: curl exit ${curl_rc} (expected 0)" >&2
    fail=1
fi
if [[ "${http_code}" != "200" ]]; then
    echo "FAIL[a2]: HTTP status ${http_code} (expected 200)" >&2
    fail=1
fi

# ── (b) Content-Type ─────────────────────────────────────────────────────
if ! grep -qiE '^content-type:.*text/plain.*version=0\.0\.4' "${metrics_hdrs}"; then
    echo "FAIL[b]: response missing Content-Type 'text/plain; version=0.0.4'" >&2
    fail=1
fi

# ── (c) HELP line ────────────────────────────────────────────────────────
if ! grep -qE '^# HELP xdpfilter_packets_total ' "${metrics_body}"; then
    echo "FAIL[c]: body missing '# HELP xdpfilter_packets_total ...' line" >&2
    fail=1
fi

# ── (d) TYPE line (exact ERE per §6.37) ─────────────────────────────────
if ! grep -qE '^# TYPE xdpfilter_packets_total counter$' "${metrics_body}"; then
    echo "FAIL[d]: body missing '# TYPE xdpfilter_packets_total counter' line" >&2
    fail=1
fi

# ── (e) ≥1 sample line ──────────────────────────────────────────────────
# `grep -c` always prints to stdout (only the exit code differs on zero
# matches); `|| true` swallows the rc=1 without emitting a spurious second
# "0" the way `|| echo 0` would. `:-0` handles the empty-file edge case.
sample_lines=$(grep -cE '^xdpfilter_packets_total\{iface="[^"]+",verdict="(pass|drop_deny|drop_malformed|pass_cidr)"\} [0-9]+$' "${metrics_body}" 2>/dev/null || true)
sample_lines=${sample_lines:-0}
echo "sample lines matching sample ERE: ${sample_lines}"
if (( sample_lines < 1 )); then
    echo "FAIL[e]: body has 0 sample lines matching the Prometheus sample ERE" >&2
    fail=1
fi

# Helpful diagnostic — number of HELP + TYPE lines.
help_count=$(grep -cE '^# HELP xdpfilter_packets_total ' "${metrics_body}" 2>/dev/null || true)
help_count=${help_count:-0}
type_count=$(grep -cE '^# TYPE xdpfilter_packets_total counter$' "${metrics_body}" 2>/dev/null || true)
type_count=${type_count:-0}
echo "diagnostic: HELP=${help_count} TYPE=${type_count} sample=${sample_lines}"
if [[ "${help_count}" != "1" ]]; then
    echo "FAIL[c2]: expected exactly 1 HELP line, got ${help_count}" >&2
    fail=1
fi
if [[ "${type_count}" != "1" ]]; then
    echo "FAIL[d2]: expected exactly 1 TYPE line, got ${type_count}" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_EXPORTER_METRICS_FORMAT"
exit "${fail}"
