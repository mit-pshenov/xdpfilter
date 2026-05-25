#!/bin/bash
# T_EXPORTER_RULE_LABELS — design §6.51 (MVP-3.4b cycle 1 / §5.31).
#
# Exporter emits xdpfilter_rule_match_total{iface, rule_id, action}
# Prometheus series per Q4 A3 + D-3.4b-8 + PI-3.4b-6. Sidecar-orphan
# tolerance per PI-32-3.4b — deleting rule_index.json mid-scrape leaves
# exporter alive + emits action="unknown" labels.
#
# Trigger:
#   1. setup_veth + apply config_per_rule_counters.yaml.
#   2. Inject mixed traffic to advance multiple rule_ids
#      (rule_id=0 + rule_id=5 + rule_id=42 via CIDR).
#   3. Start xdpmf-exporter; curl /metrics.
#   4. Delete sidecar; re-scrape; verify action="unknown" labels appear
#      for rule_ids that have counter > 0 but no sidecar entry.
#
# Observable outcome (ALL must hold):
#   (a) HTTP 200; Content-Type contains 'text/plain; version=0.0.4'.
#   (b) Body contains exactly one '# HELP xdpfilter_rule_match_total ...' line.
#   (c) Body contains exactly one '# TYPE xdpfilter_rule_match_total counter' line.
#   (d) Body contains ≥1 line matching the sample ERE
#       '^xdpfilter_rule_match_total\{iface="[^"]+",rule_id="[0-9]+",action="(pass|drop|unknown)"\} [0-9]+$'.
#   (e) For each rule_id with non-zero traffic (we injected for 0, 5, 42),
#       the emitted sample line shows action matching the fixture
#       (id=0 → pass; id=5 → pass; id=42 → pass).
#   (f) Existing xdpfilter_packets_total series UNCHANGED (PI-31-3.4b).
#   (g) SIDECAR-ORPHAN sub-test: delete rule_index.json; re-scrape;
#       rule_ids in BPF map with counter > 0 emit with action="unknown".
#       Exporter MUST NOT crash; kill -0 confirms it's still alive.
#
# Sanity-floor smoke: step (a) — curl returns 200 + exporter alive.
# Negation control: step (g) — delete sidecar mid-scrape; if exporter
# crashed OR series disappeared entirely, the negation triggers.
# action="unknown" must appear for previously-tracked rule_ids.
#
# SKIP conditions: curl absent → exit 77.
#
# Note: per §5.31 EDIT-1 (Phase B platform-constraint correction), the
# sidecar lives at /run/xdpmacfilter/<iface>/rule_index.json (NOT under
# bpffs ${PIN_DIR}). The orphan-tolerance sub-test deletes the file at
# the corrected path; the BPF map `rule_counters` still lives under
# bpffs at ${PIN_DIR}/<iface>/rule_counters.
#
# Maps to: PI-3.4b-6, PI-31-3.4b, PI-32-3.4b, Q4 A3, D-3.4b-8, D-3.4b-21.
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
    echo "SKIP: curl not in PATH (required by §6.51)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
EXPORTER_BIN=$(find_exporter) || {
    echo "FAIL: xdpmf-exporter binary not found under ${BUILD_DIR}" >&2
    exit 1
}
FIXTURE="${TEST_DIR}/fixtures/config_per_rule_counters.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

# Port derived from PID; exporter_port_9417 RESOURCE_LOCK serializes
# against the other exporter-spawning tests.
PORT=$(( 9417 + ($$ % 1000) ))
echo "EXPORTER_PORT=${PORT}"

metrics_body=$(mktemp /tmp/xdpmf-rulelabel-body.XXXXXX)
metrics_hdrs=$(mktemp /tmp/xdpmf-rulelabel-hdrs.XXXXXX)
exp_log=$(mktemp /tmp/xdpmf-rulelabel-explog.XXXXXX)
stderr_file=$(mktemp /tmp/xdpmf-rulelabel-stderr.XXXXXX)
metrics_body2=$(mktemp /tmp/xdpmf-rulelabel-body2.XXXXXX)
EXPORTER_PID=""

# §5.31 EDIT-1: sidecar path = /run/xdpmacfilter/<iface>/rule_index.json
SIDECAR_ROOT="/run/xdpmacfilter"
SIDECAR_DIR="${SIDECAR_ROOT}/${IFACE_A}"
SIDECAR_PATH="${SIDECAR_DIR}/rule_index.json"

cleanup_test() {
    set +e
    if [[ -n "${EXPORTER_PID}" ]]; then
        sudo -n kill "${EXPORTER_PID}" 2>/dev/null
        sleep 0.2
        sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null
        wait "${EXPORTER_PID}" 2>/dev/null
    fi
    cleanup_veth
    sudo -n rm -rf "${SIDECAR_DIR}" 2>/dev/null
    rm -f "${metrics_body}" "${metrics_hdrs}" "${metrics_body2}" \
          "${exp_log}" "${stderr_file}"
    set -e
}
trap cleanup_test EXIT

# MACs / IPs in fixture.
MAC_ID0="02:00:00:00:00:01"
MAC_ID5="02:00:00:00:00:05"
MAC_CIDR_HIT="99:99:99:99:99:99"   # NOT in any MAC rule, but src_ip in 10.0.0.0/24
SRC_IP_IN="10.0.0.5"

setup_veth

# ── apply + traffic ──────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
cat "${stderr_file}" >&2 || true
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL: apply exit ${rc}" >&2
    exit 1
fi

# Inject mixed: 2× id=0 MAC, 3× id=5 MAC, 1× id=42 CIDR.
echo "=== inject 2× rule_id=0 MAC"
for i in 1 2; do inject_eth "${IFACE_B}" "${MAC_ID0}" "${MAC_DST}"; done
echo "=== inject 3× rule_id=5 MAC"
for i in 1 2 3; do inject_eth "${IFACE_B}" "${MAC_ID5}" "${MAC_DST}"; done
echo "=== inject 1× rule_id=42 via CIDR"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${MAC_CIDR_HIT}" "${MAC_DST}" "${SRC_IP_IN}"

# Wait for the BPF stats counters to catch up before scraping.
sleep 0.3

# ── start exporter ───────────────────────────────────────────────────────
echo "=== starting xdpmf-exporter on 127.0.0.1:${PORT}"
sudo -n "${EXPORTER_BIN}" \
    --port "${PORT}" \
    --bind 127.0.0.1 \
    --bpffs-root "${PIN_ROOT}" \
    >"${exp_log}" 2>&1 &
EXPORTER_PID=$!
echo "EXPORTER_PID=${EXPORTER_PID}"

ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT}/healthz" -o /dev/null 2>/dev/null; then
        ready=1
        echo "exporter ready after ${i} polls"
        break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        echo "FAIL: exporter died during startup" >&2
        cat "${exp_log}" >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "${ready}" != "1" ]]; then
    echo "FAIL: exporter not ready within 5s" >&2
    cat "${exp_log}" >&2
    exit 1
fi

# ── scrape /metrics ──────────────────────────────────────────────────────
echo "=== curl /metrics"
set +e
http_code=$(curl -s -o "${metrics_body}" -D "${metrics_hdrs}" -w '%{http_code}' \
    -m 5 "http://127.0.0.1:${PORT}/metrics")
curl_rc=$?
set -e
echo "curl rc=${curl_rc} http_code=${http_code}"
echo "--- response headers ---"
cat "${metrics_hdrs}"
echo "--- response body ---"
cat "${metrics_body}"
echo "--- end ---"

fail=0

# (a) HTTP 200 + Content-Type
if [[ "${curl_rc}" -ne 0 ]] || [[ "${http_code}" != "200" ]]; then
    echo "FAIL[a]: curl rc=${curl_rc} http=${http_code} (expected 0 + 200)" >&2
    fail=1
fi
if ! grep -qiE '^content-type:.*text/plain.*version=0\.0\.4' "${metrics_hdrs}"; then
    echo "FAIL[a.ct]: Content-Type missing 'text/plain; version=0.0.4'" >&2
    fail=1
fi

# (b) Exactly one HELP line for the NEW series.
help_count=$(grep -cE '^# HELP xdpfilter_rule_match_total ' "${metrics_body}" 2>/dev/null || true)
help_count=${help_count:-0}
echo "HELP xdpfilter_rule_match_total count: ${help_count}"
if [[ "${help_count}" != "1" ]]; then
    echo "FAIL[b]: expected exactly 1 HELP line for xdpfilter_rule_match_total, got ${help_count}" >&2
    fail=1
fi

# (c) Exactly one TYPE line for the NEW series, with 'counter' type.
type_count=$(grep -cE '^# TYPE xdpfilter_rule_match_total counter$' "${metrics_body}" 2>/dev/null || true)
type_count=${type_count:-0}
echo "TYPE xdpfilter_rule_match_total counter count: ${type_count}"
if [[ "${type_count}" != "1" ]]; then
    echo "FAIL[c]: expected exactly 1 TYPE line for xdpfilter_rule_match_total counter, got ${type_count}" >&2
    fail=1
fi

# (d) ≥1 sample line matching the labelled ERE.
sample_ere='^xdpfilter_rule_match_total\{iface="[^"]+",rule_id="[0-9]+",action="(pass|drop|unknown)"\} [0-9]+$'
sample_count=$(grep -cE "${sample_ere}" "${metrics_body}" 2>/dev/null || true)
sample_count=${sample_count:-0}
echo "rule_match_total sample line count: ${sample_count}"
if (( sample_count < 1 )); then
    echo "FAIL[d]: expected ≥1 sample line matching ERE:" >&2
    echo "         ${sample_ere}" >&2
    fail=1
fi

# (e) Specific rule_ids 0, 5, 42 should show action=pass (per fixture).
# Note: label order is iface,rule_id,action per design §5.31.
for id in 0 5 42; do
    line=$(grep -E "^xdpfilter_rule_match_total\{iface=\"${IFACE_A}\",rule_id=\"${id}\",action=\"[^\"]+\"\} [0-9]+$" "${metrics_body}" 2>/dev/null | head -n1 || true)
    echo "  rule_id=${id}: line='${line}'"
    if [[ -z "${line}" ]]; then
        echo "FAIL[e.${id}]: no series for rule_id=${id} found" >&2
        fail=1
        continue
    fi
    # Extract action label.
    got_action=$(echo "${line}" | sed -nE 's/.*action="([^"]+)".*/\1/p')
    if [[ "${got_action}" != "pass" ]]; then
        echo "FAIL[e.${id}.action]: rule_id=${id} action='${got_action}' (expected pass)" >&2
        fail=1
    fi
done

# (f) Existing xdpfilter_packets_total series PRESERVED (PI-31-3.4b).
if ! grep -qE '^# HELP xdpfilter_packets_total ' "${metrics_body}"; then
    echo "FAIL[f1]: xdpfilter_packets_total HELP line missing (PI-31-3.4b regression)" >&2
    fail=1
fi
if ! grep -qE '^# TYPE xdpfilter_packets_total counter$' "${metrics_body}"; then
    echo "FAIL[f2]: xdpfilter_packets_total TYPE line missing (PI-31-3.4b regression)" >&2
    fail=1
fi
packets_sample=$(grep -cE '^xdpfilter_packets_total\{iface="[^"]+",verdict="(pass|drop_deny|drop_malformed|pass_cidr)"\} [0-9]+$' "${metrics_body}" 2>/dev/null || true)
packets_sample=${packets_sample:-0}
if (( packets_sample < 1 )); then
    echo "FAIL[f3]: no xdpfilter_packets_total sample lines (PI-31-3.4b regression)" >&2
    fail=1
fi

# ── (g) SIDECAR-ORPHAN TOLERANCE sub-test ────────────────────────────────
echo
echo "=== step (g): SIDECAR-ORPHAN tolerance — delete sidecar; expect action=unknown"
sudo -n rm -f "${SIDECAR_PATH}"
if sudo -n test -e "${SIDECAR_PATH}"; then
    echo "FAIL[g.setup]: could not delete sidecar (still present)" >&2
    fail=1
fi

# Re-scrape /metrics.
set +e
http_code2=$(curl -s -o "${metrics_body2}" -w '%{http_code}' \
    -m 5 "http://127.0.0.1:${PORT}/metrics")
curl2_rc=$?
set -e
echo "second scrape: rc=${curl2_rc} http=${http_code2}"
echo "--- body (post-sidecar-delete) ---"
cat "${metrics_body2}"
echo "--- end ---"

# Exporter must NOT have crashed.
if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
    echo "FAIL[g.alive]: exporter PID ${EXPORTER_PID} died after sidecar delete" >&2
    echo "              PI-32-3.4b sidecar-orphan tolerance VIOLATED" >&2
    fail=1
fi

if [[ "${http_code2}" != "200" ]]; then
    echo "FAIL[g.http]: post-sidecar-delete scrape http=${http_code2} (expected 200)" >&2
    fail=1
fi

# For previously-tracked rule_ids (0, 5, 42), the action label MUST be
# "unknown" now (sidecar absent → exporter cannot resolve action).
for id in 0 5 42; do
    line=$(grep -E "^xdpfilter_rule_match_total\{iface=\"${IFACE_A}\",rule_id=\"${id}\",action=\"[^\"]+\"\} [0-9]+$" "${metrics_body2}" 2>/dev/null | head -n1 || true)
    echo "  post-delete rule_id=${id}: line='${line}'"
    if [[ -z "${line}" ]]; then
        echo "FAIL[g.${id}.absent]: rule_id=${id} series MISSING post-sidecar-delete" >&2
        echo "                     PI-32-3.4b: exporter must STILL emit the data point with action=unknown" >&2
        fail=1
        continue
    fi
    got_action=$(echo "${line}" | sed -nE 's/.*action="([^"]+)".*/\1/p')
    if [[ "${got_action}" != "unknown" ]]; then
        echo "FAIL[g.${id}.action]: rule_id=${id} action='${got_action}' (expected 'unknown' per PI-32-3.4b)" >&2
        fail=1
    fi
done

[[ "${fail}" == 0 ]] && echo "PASS: T_EXPORTER_RULE_LABELS"
exit "${fail}"
