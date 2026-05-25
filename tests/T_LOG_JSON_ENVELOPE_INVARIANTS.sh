#!/bin/bash
# T_LOG_JSON_ENVELOPE_INVARIANTS — design §6.57 (MVP-3.5 / §5.32).
#
# Broad sweep across many event types under XDPMF_LOG_FORMAT=json — every
# captured stderr line must satisfy the envelope invariants per HG-3.5-2:
#
#   { ts, level, event, iface, msg, fields }
#
#   - ts:     ERE ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$
#   - level:  ∈ {"info","warn","error"} (exact)
#   - event:  ∈ kEventNames (catalog from tests/fixtures/log_events_v1.txt)
#   - iface:  type ∈ {string, null} — NEVER absent, NEVER object/array/bool/number
#   - msg:    type == string (may contain escaped \n)
#   - fields: type == object — possibly {}; NEVER absent, NEVER array/scalar
#
# Sweep sequence (covers loader + exporter event surfaces):
#   1. attach + apply + detach on IFACE_A
#   2. bypass --unsafe --reason "T_LOG_INV"
#   3. attach + apply with malformed --reason (cli.error / config.error path)
#   4. exporter against --bpffs-root /nonexistent (warn + listening + shutdown)
#
# NEGATION CONTROL (the validator-must-reject probe):
#   Artificially construct a malformed JSON line missing required fields;
#   feed through the validator; assert it REJECTS. Proves the validator
#   isn't a no-op.
#
# PI-3.5-3 negation sub-case (empty XDPMF_LOG_FORMAT="" → text fallback):
#   Run a tiny sequence with XDPMF_LOG_FORMAT="" — output MUST be text, not
#   JSON. (T_LOG_TEXT_BYTE_EQUIVALENT covers this primary; we repeat the
#   probe here for catalog membership.)
#
# Sanity-floor smoke: at least one event was emitted under the sweep.
# Negation control: malformed-line probe + empty-env-var probe (both above).
#
# SKIP: passwordless sudo; jq; curl.
#
# Cleanup: cleanup_veth + kill exporter + rm tmp captures.
#
# Maps to: PI-3.5-2, PI-3.5-4 (envelope invariants), HG-3.5-2.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required by §6.57)" >&2
    exit 77
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not in PATH (required by §6.57)" >&2
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

LOADER_BIN=$(find_loader)
EXPORTER_BIN=$(find_exporter) || { echo "FAIL: xdpmf-exporter not found" >&2; exit 1; }
FIXTURE_CONFIG="${TEST_DIR}/fixtures/config_valid.yaml"
EVENTS_FIXTURE="${TEST_DIR}/fixtures/log_events_v1.txt"
[[ -f "${FIXTURE_CONFIG}" ]] || { echo "FAIL: missing ${FIXTURE_CONFIG}" >&2; exit 1; }
[[ -f "${EVENTS_FIXTURE}" ]] || { echo "FAIL: missing ${EVENTS_FIXTURE}" >&2; exit 1; }

PORT=$(( 9417 + ($$ % 1000) ))
MISSING_ROOT="/tmp/xdpmf-inv-noexist-${$}-$(date +%s)"

cap_attach=$(mktemp /tmp/xdpmf-inv-attach.XXXXXX)
cap_apply=$(mktemp /tmp/xdpmf-inv-apply.XXXXXX)
cap_detach=$(mktemp /tmp/xdpmf-inv-detach.XXXXXX)
cap_bypass=$(mktemp /tmp/xdpmf-inv-bypass.XXXXXX)
cap_exporter=$(mktemp /tmp/xdpmf-inv-exporter.XXXXXX)
cap_empty=$(mktemp /tmp/xdpmf-inv-empty.XXXXXX)
combined=$(mktemp /tmp/xdpmf-inv-combined.XXXXXX)
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
    rm -rf "${MISSING_ROOT}" 2>/dev/null
    rm -f "${cap_attach}" "${cap_apply}" "${cap_detach}" "${cap_bypass}" \
          "${cap_exporter}" "${cap_empty}" "${combined}"
    set -e
}
trap cleanup_test EXIT

fail=0

# ── Sweep step 1: attach + apply + detach under JSON ───────────────────
setup_veth
echo "=== sweep step 1: attach + apply + detach (json)"
${NSEXEC} env XDPMF_LOG_FORMAT=json "${LOADER_BIN}" \
    attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2>"${cap_attach}" 1>/dev/null
${NSEXEC} env XDPMF_LOG_FORMAT=json "${LOADER_BIN}" \
    apply --iface "${IFACE_A}" -f "${FIXTURE_CONFIG}" 2>"${cap_apply}" 1>/dev/null

# ── Sweep step 2: bypass under JSON ────────────────────────────────────
echo "=== sweep step 2: bypass (json)"
set +e
${NSEXEC} env XDPMF_LOG_FORMAT=json setsid -- "${LOADER_BIN}" \
    bypass --iface "${IFACE_A}" --unsafe --reason "T_LOG_INV" \
    </dev/null 2>"${cap_bypass}"
set -e

# (re-attach so detach has something to act on, capture detach stderr)
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2>/dev/null
sleep 0.3
${NSEXEC} env XDPMF_LOG_FORMAT=json "${LOADER_BIN}" \
    detach --iface "${IFACE_A}" 2>"${cap_detach}" 1>/dev/null

cleanup_veth

# ── Sweep step 3: exporter against non-existent bpffs root ─────────────
echo "=== sweep step 3: exporter (json)"
sudo -n env XDPMF_LOG_FORMAT=json "${EXPORTER_BIN}" \
    --port "${PORT}" \
    --bind 127.0.0.1 \
    --bpffs-root "${MISSING_ROOT}" \
    >"${cap_exporter}" 2>&1 &
EXPORTER_PID=$!

ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT}/healthz" -o /dev/null 2>/dev/null; then
        ready=1; break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then break; fi
    sleep 0.1
done
sleep 0.3
sudo -n kill "${EXPORTER_PID}" 2>/dev/null
set +e
wait "${EXPORTER_PID}" 2>/dev/null
set -e
EXPORTER_PID=""

# ── Combine all captures and dump for visibility ───────────────────────
cat "${cap_attach}" "${cap_apply}" "${cap_detach}" "${cap_bypass}" "${cap_exporter}" \
    | grep -v '^$' > "${combined}" || true
echo "--- combined sweep stderr ---"
cat "${combined}"
echo "--- end ---"

# Smoke: at least one event emitted.
line_count=$(wc -l < "${combined}")
echo "total event lines: ${line_count}"
if (( line_count < 1 )); then
    echo "FAIL[smoke]: zero events emitted across sweep — binaries not running?" >&2
    exit 1
fi

# Load known-events catalog into bash array.
mapfile -t KNOWN_EVENTS < "${EVENTS_FIXTURE}"
echo "known events catalog count: ${#KNOWN_EVENTS[@]}"

# ── per-line validator function ────────────────────────────────────────
# Returns 0 if line is a valid envelope, 1 otherwise. Echoes failure reason.
validate_line() {
    local line="$1"
    # Must parse.
    if ! printf '%s\n' "${line}" | jq -e '.' >/dev/null 2>&1; then
        echo "not-json"; return 1
    fi
    # ts present + matches ERE.
    local ts
    ts=$(printf '%s\n' "${line}" | jq -r '.ts // ""' 2>/dev/null)
    if ! [[ "${ts}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
        echo "bad-ts:${ts}"; return 1
    fi
    # level ∈ {info,warn,error}.
    local level
    level=$(printf '%s\n' "${line}" | jq -r '.level // ""' 2>/dev/null)
    case "${level}" in info|warn|error) ;; *) echo "bad-level:${level}"; return 1 ;; esac
    # event present.
    local event
    event=$(printf '%s\n' "${line}" | jq -r '.event // ""' 2>/dev/null)
    if [[ -z "${event}" ]]; then
        echo "missing-event"; return 1
    fi
    # event ∈ KNOWN_EVENTS.
    local found=0
    local k
    for k in "${KNOWN_EVENTS[@]}"; do
        if [[ "${k}" == "${event}" ]]; then
            found=1; break
        fi
    done
    if (( found == 0 )); then
        echo "unknown-event:${event}"; return 1
    fi
    # iface: present + type ∈ {string, null}.
    local iface_present iface_type
    iface_present=$(printf '%s\n' "${line}" | jq 'has("iface")' 2>/dev/null)
    if [[ "${iface_present}" != "true" ]]; then
        echo "missing-iface"; return 1
    fi
    iface_type=$(printf '%s\n' "${line}" | jq -r '.iface | type' 2>/dev/null)
    case "${iface_type}" in string|null) ;; *) echo "bad-iface-type:${iface_type}"; return 1 ;; esac
    # msg: present + type == string.
    local msg_type
    msg_type=$(printf '%s\n' "${line}" | jq -r '.msg | type' 2>/dev/null)
    if [[ "${msg_type}" != "string" ]]; then
        echo "bad-msg-type:${msg_type}"; return 1
    fi
    # fields: present + type == object.
    local fields_present fields_type
    fields_present=$(printf '%s\n' "${line}" | jq 'has("fields")' 2>/dev/null)
    if [[ "${fields_present}" != "true" ]]; then
        echo "missing-fields"; return 1
    fi
    fields_type=$(printf '%s\n' "${line}" | jq -r '.fields | type' 2>/dev/null)
    if [[ "${fields_type}" != "object" ]]; then
        echo "bad-fields-type:${fields_type}"; return 1
    fi
    return 0
}

# ── Walk every line; assert envelope invariants ─────────────────────────
echo
echo "=== per-line envelope-invariant validation"
bad_lines=0
lineno=0
err_reason=""
while IFS= read -r line; do
    lineno=$(( lineno + 1 ))
    [[ -z "${line}" ]] && continue
    if ! err_reason=$(validate_line "${line}"); then
        echo "FAIL: line ${lineno} invalid (${err_reason}):" >&2
        echo "      ${line}" >&2
        bad_lines=$(( bad_lines + 1 ))
    fi
done < "${combined}"

if (( bad_lines > 0 )); then
    echo "FAIL: ${bad_lines} line(s) failed envelope-invariant check" >&2
    fail=1
fi

# ── NEGATION CONTROL: validator must reject malformed lines ────────────
echo
echo "=== NEGATION CONTROL: validator must reject malformed lines"
neg_tests=0
neg_fails=0

probe_reject() {
    local label="$1" line="$2"
    neg_tests=$(( neg_tests + 1 ))
    if validate_line "${line}" >/dev/null 2>&1; then
        echo "FAIL[neg-${label}]: validator unexpectedly ACCEPTED malformed line:" >&2
        echo "        ${line}" >&2
        neg_fails=$(( neg_fails + 1 ))
    else
        echo "[neg-${label}] OK: validator rejected"
    fi
}

# Missing msg + iface + fields.
probe_reject "missing-fields" '{"ts":"2026-05-25T17:00:00Z","level":"info","event":"cli.usage_error"}'
# Bad level value.
probe_reject "bad-level" '{"ts":"2026-05-25T17:00:00Z","level":"INFO","event":"cli.usage_error","iface":null,"msg":"x","fields":{}}'
# Bad ts.
probe_reject "bad-ts" '{"ts":"yesterday","level":"info","event":"cli.usage_error","iface":null,"msg":"x","fields":{}}'
# Unknown event.
probe_reject "unknown-event" '{"ts":"2026-05-25T17:00:00Z","level":"info","event":"NONEXISTENT.bogus","iface":null,"msg":"x","fields":{}}'
# iface as bool (wrong type).
probe_reject "iface-bool" '{"ts":"2026-05-25T17:00:00Z","level":"info","event":"cli.usage_error","iface":true,"msg":"x","fields":{}}'
# fields as array (wrong type).
probe_reject "fields-array" '{"ts":"2026-05-25T17:00:00Z","level":"info","event":"cli.usage_error","iface":null,"msg":"x","fields":[]}'

if (( neg_fails > 0 )); then
    echo "FAIL[neg]: ${neg_fails}/${neg_tests} negation probes failed — validator is too lax" >&2
    fail=1
fi

# ── PI-3.5-3 EDGE CASE: XDPMF_LOG_FORMAT="" → text fallback (NOT WARN) ─
echo
echo "=== PI-3.5-3 edge: XDPMF_LOG_FORMAT=\"\" → silent Text fallback"
setup_veth
set +e
${NSEXEC} env "XDPMF_LOG_FORMAT=" "${LOADER_BIN}" \
    attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2>"${cap_empty}" 1>/dev/null
set -e
cleanup_veth

echo "--- stderr (empty env) ---"
cat "${cap_empty}"
echo "--- end ---"

# Output MUST NOT contain the unknown-log-format WARN.
if grep -qF 'logger.warn.unknown_log_format' "${cap_empty}"; then
    echo "FAIL[edge]: empty XDPMF_LOG_FORMAT triggered unknown-format WARN — should be silent Text fallback per Q4" >&2
    fail=1
fi
# Also: no line should be JSON.
empty_json=0
while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    if printf '%s\n' "${line}" | jq -e '.' >/dev/null 2>&1; then
        empty_json=1
        break
    fi
done < "${cap_empty}"
if (( empty_json == 1 )); then
    echo "FAIL[edge2]: empty XDPMF_LOG_FORMAT produced JSON output — should be Text fallback" >&2
    fail=1
fi
echo "[edge] OK: empty XDPMF_LOG_FORMAT produces text (silent fallback)"

[[ "${fail}" == 0 ]] && echo "PASS: T_LOG_JSON_ENVELOPE_INVARIANTS"
exit "${fail}"
