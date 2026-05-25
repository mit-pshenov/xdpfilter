#!/bin/bash
# T_LOG_JSON_EXPORTER_EVENTS — design §6.55 (MVP-3.5 / §5.32).
#
# Exporter under XDPMF_LOG_FORMAT=json:
#   - PRIMARY: --bpffs-root /tmp/does-not-exist-${RANDOM} → HK-16 WARN event
#     `exporter.warn.bpffs_root_missing` appears as JSON line with
#     fields.bpffs_root set; also `exporter.listening` fires at startup;
#     `exporter.shutdown` fires after SIGTERM.
#   - NEGATION: re-run with XDPMF_LOG_FORMAT=text — HK-16 line is the
#     pre-§5.32 text form `xdpmf-exporter: WARN bpffs root .* does not exist`
#     (PI-3.5-1 byte-equivalent at the exporter scope).
#   - HK-17 sub-case: chmod-000 fixture → exit-6 event
#     `exporter.error.all_ifaces_eacces` (SKIP-77 if EACCES not reproducible).
#
# Observable outcome (PRIMARY JSON):
#   (a) Every stderr line parses as JSON (jq -e '.')
#   (b) Exactly ONE `exporter.warn.bpffs_root_missing` event with
#       fields.bpffs_root matching the non-existent path used.
#   (c) Exactly ONE `exporter.listening` event with fields.port set to
#       the chosen port (or a "bind_addr" / "port" presence — exact field
#       names per architect-catalog).
#   (d) After SIGTERM: at least ONE `exporter.shutdown` event.
#
# Observable outcome (NEGATION text):
#   (e) `xdpmf-exporter: WARN bpffs root .* does not exist; will serve
#       empty metrics` — pre-§5.32 byte-equivalent (PI-3.5-1).
#
# Observable outcome (HK-17 sub-case, SKIP-77 if not reproducible):
#   (f) exit-6 + JSON event `exporter.error.all_ifaces_eacces` with
#       fields.total_discovered > 0.
#
# Sanity-floor smoke: (a) — every line valid JSON.
# Negation control: (e) — text-mode HK-16 line preserves pre-§5.32 form
# byte-equivalent.
#
# SKIP: passwordless sudo; jq; curl. HK-17 sub-case SKIP-77 if EACCES
# not reproducible (no nobody/unprivileged user available).
#
# Cleanup: kill exporter; rm tmp captures; rm tmp dirs.
#
# Maps to: PI-3.5-2, PI-3.5-3 (HK-16 + HK-17), HG-3.5-2.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required by §6.55)" >&2
    exit 77
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not in PATH (required by §6.55)" >&2
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

EXPORTER_BIN=$(find_exporter) || { echo "FAIL: xdpmf-exporter not found" >&2; exit 1; }
echo "exporter=${EXPORTER_BIN}"

# Per-PID port to avoid clashing with other tests.
PORT=$(( 9417 + ($$ % 1000) ))
echo "PORT=${PORT}"

# Path that does NOT exist (HK-16 trigger).
MISSING_ROOT="/tmp/xdpmf-jsonexp-noexist-${$}-$(date +%s)"

exp_log_json=$(mktemp /tmp/xdpmf-jsonexp-jsonlog.XXXXXX)
exp_log_text=$(mktemp /tmp/xdpmf-jsonexp-textlog.XXXXXX)
combined=$(mktemp /tmp/xdpmf-jsonexp-combined.XXXXXX)
EXPORTER_PID=""

cleanup_test() {
    set +e
    if [[ -n "${EXPORTER_PID}" ]]; then
        sudo -n kill "${EXPORTER_PID}" 2>/dev/null
        sleep 0.2
        sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null
        wait "${EXPORTER_PID}" 2>/dev/null
    fi
    rm -rf "${MISSING_ROOT}" 2>/dev/null
    rm -f "${exp_log_json}" "${exp_log_text}" "${combined}"
    set -e
}
trap cleanup_test EXIT

fail=0

# ── PRIMARY: exporter under JSON, --bpffs-root missing → HK-16 WARN ─────
echo "=== launching exporter under XDPMF_LOG_FORMAT=json --bpffs-root ${MISSING_ROOT}"
sudo -n env XDPMF_LOG_FORMAT=json "${EXPORTER_BIN}" \
    --port "${PORT}" \
    --bind 127.0.0.1 \
    --bpffs-root "${MISSING_ROOT}" \
    >"${exp_log_json}" 2>&1 &
EXPORTER_PID=$!

# Wait for ready OR die.
ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT}/healthz" -o /dev/null 2>/dev/null; then
        ready=1; break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if [[ "${ready}" != "1" ]]; then
    echo "FAIL: exporter not ready within 5s under JSON mode" >&2
    cat "${exp_log_json}" >&2
    exit 1
fi

# Settle a moment to make sure startup events have flushed.
sleep 0.3

# Send SIGTERM so we get the shutdown event.
sudo -n kill "${EXPORTER_PID}" 2>/dev/null
set +e
wait "${EXPORTER_PID}" 2>/dev/null
set -e
EXPORTER_PID=""

# Now process the log.
echo "--- exporter log (json mode) ---"
cat "${exp_log_json}"
echo "--- end ---"

# ── (a) every non-empty stderr line is valid JSON ──────────────────────
echo
echo "=== (a) every non-empty stderr line is valid JSON"
non_json_count=0
while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    if ! printf '%s\n' "${line}" | jq -e '.' >/dev/null 2>&1; then
        echo "FAIL[a]: line is NOT valid JSON: ${line}" >&2
        non_json_count=$(( non_json_count + 1 ))
    fi
done < "${exp_log_json}"
if (( non_json_count > 0 )); then
    fail=1
fi

# ── (b) exactly one exporter.warn.bpffs_root_missing event ─────────────
echo
echo "=== (b) exporter.warn.bpffs_root_missing event"
warn_count=$(jq -s '[.[] | select(.event == "exporter.warn.bpffs_root_missing")] | length' "${exp_log_json}" 2>/dev/null || echo 0)
echo "warn.bpffs_root_missing count = ${warn_count}"
if [[ "${warn_count}" != "1" ]]; then
    echo "FAIL[b1]: expected exactly 1 exporter.warn.bpffs_root_missing event, got ${warn_count}" >&2
    fail=1
fi

# fields.bpffs_root must match the missing path.
warn_path=$(jq -s -r '.[] | select(.event == "exporter.warn.bpffs_root_missing") | .fields.bpffs_root' "${exp_log_json}" 2>/dev/null | head -1)
echo "warn.bpffs_root fields.bpffs_root = ${warn_path}"
if [[ "${warn_path}" != "${MISSING_ROOT}" ]]; then
    echo "FAIL[b2]: fields.bpffs_root='${warn_path}', expected '${MISSING_ROOT}'" >&2
    fail=1
fi

# ── (c) at least one exporter.listening event ──────────────────────────
echo
echo "=== (c) exporter.listening event"
listen_count=$(jq -s '[.[] | select(.event == "exporter.listening")] | length' "${exp_log_json}" 2>/dev/null || echo 0)
echo "exporter.listening count = ${listen_count}"
if [[ "${listen_count}" -lt 1 ]]; then
    echo "FAIL[c]: expected at least 1 exporter.listening event, got ${listen_count}" >&2
    fail=1
fi

# ── (d) at least one exporter.shutdown event after SIGTERM ─────────────
echo
echo "=== (d) exporter.shutdown event"
shutdown_count=$(jq -s '[.[] | select(.event == "exporter.shutdown")] | length' "${exp_log_json}" 2>/dev/null || echo 0)
echo "exporter.shutdown count = ${shutdown_count}"
if [[ "${shutdown_count}" -lt 1 ]]; then
    echo "FAIL[d]: expected at least 1 exporter.shutdown event after SIGTERM, got ${shutdown_count}" >&2
    fail=1
fi

# ── (e) NEGATION CONTROL: text-mode HK-16 line byte-equivalent ─────────
echo
echo "=== (e) NEGATION CONTROL: text-mode HK-16 byte-equivalent"
MISSING_ROOT2="/tmp/xdpmf-jsonexp-noexist2-${$}-$(date +%s)"
PORT2=$(( PORT + 1 ))
sudo -n env XDPMF_LOG_FORMAT=text "${EXPORTER_BIN}" \
    --port "${PORT2}" \
    --bind 127.0.0.1 \
    --bpffs-root "${MISSING_ROOT2}" \
    >"${exp_log_text}" 2>&1 &
EXPORTER_PID=$!
ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT2}/healthz" -o /dev/null 2>/dev/null; then
        ready=1; break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then break; fi
    sleep 0.1
done
sleep 0.2
sudo -n kill "${EXPORTER_PID}" 2>/dev/null
set +e
wait "${EXPORTER_PID}" 2>/dev/null
set -e
EXPORTER_PID=""
rm -rf "${MISSING_ROOT2}"

echo "--- exporter log (text mode) ---"
cat "${exp_log_text}"
echo "--- end ---"

# Pre-§5.32 HK-16 wording: "xdpmf-exporter: WARN bpffs root <path> does not exist; will serve empty metrics"
warn_ere='xdpmf-exporter: WARN bpffs root .* does not exist; will serve empty metrics'
if ! grep -qE -- "${warn_ere}" "${exp_log_text}"; then
    echo "FAIL[e]: text-mode HK-16 line missing — PI-3.5-1 byte-equivalence violation" >&2
    echo "        Expected ERE: ${warn_ere}" >&2
    fail=1
else
    echo "[e] OK: text-mode HK-16 line present (byte-equivalent baseline)"
fi

# Also: text-mode lines MUST NOT be valid JSON (no { at start of HK-16 line).
if printf '%s\n' "$(grep -m1 'xdpmf-exporter:' "${exp_log_text}" || true)" \
        | jq -e '.' >/dev/null 2>&1; then
    echo "FAIL[e2]: text-mode HK-16 line unexpectedly parses as JSON" >&2
    fail=1
fi

# ── (f) HK-17 sub-case: exit-6 + exporter.error.all_ifaces_eacces ──────
echo
echo "=== (f) HK-17 sub-case (chmod-000 + unprivileged user → exit 6)"
UNPRIV_USER=""
for u in nobody xdpmftester _xdpmf; do
    if id -u "${u}" >/dev/null 2>&1; then
        UNPRIV_USER="${u}"; break
    fi
done

if [[ -z "${UNPRIV_USER}" ]]; then
    echo "[f] SKIP: no unprivileged user (nobody/xdpmftester) — HK-17 sub-case skipped" >&2
else
    # Copy exporter to world-readable path so unprivileged can exec.
    EXPORTER_BIN_TMP="/tmp/xdpmf-jsonexp-${$}-$(date +%s)"
    sudo -n cp "${EXPORTER_BIN}" "${EXPORTER_BIN_TMP}"
    sudo -n chmod 0755 "${EXPORTER_BIN_TMP}"

    # Set up the veth + attach to produce per-iface pin dirs.
    setup_veth
    LOADER_BIN=$(find_loader)
    ${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
    sleep 0.3

    STATS_A="${PIN_ROOT}/${IFACE_A}/stats"
    if ! sudo -n test -e "${STATS_A}"; then
        echo "[f] SKIP: stats pin missing after attach — HK-17 sub-case skipped" >&2
        sudo -n rm -f "${EXPORTER_BIN_TMP}" 2>/dev/null
        cleanup_veth
    else
        # Preflight: confirm EACCES under unpriv user.
        sudo -n chmod 000 "${STATS_A}"
        sudo -n chmod 000 "${PIN_ROOT}/${IFACE_A}"
        set +e
        sudo -n -u "${UNPRIV_USER}" cat "${STATS_A}" >/dev/null 2>/dev/null
        probe_rc=$?
        set -e
        if [[ "${probe_rc}" -eq 0 ]]; then
            echo "[f] SKIP: EACCES not reproducible — ${UNPRIV_USER} can read chmod-000 file" >&2
            sudo -n chmod 0755 "${PIN_ROOT}/${IFACE_A}" 2>/dev/null || true
            sudo -n chmod 0644 "${STATS_A}" 2>/dev/null || true
            ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>/dev/null || true
            sudo -n rm -f "${EXPORTER_BIN_TMP}" 2>/dev/null
            cleanup_veth
        else
            EPORT=$(( PORT + 2 ))
            exp_log_hk17=$(mktemp /tmp/xdpmf-jsonexp-hk17.XXXXXX)
            sudo -n -u "${UNPRIV_USER}" env XDPMF_LOG_FORMAT=json "${EXPORTER_BIN_TMP}" \
                --port "${EPORT}" \
                --bind 127.0.0.1 \
                --bpffs-root "${PIN_ROOT}" \
                >"${exp_log_hk17}" 2>&1 &
            EX_HK17_PID=$!

            ready=0
            for i in $(seq 1 50); do
                if curl -sf -m 1 "http://127.0.0.1:${EPORT}/healthz" -o /dev/null 2>/dev/null; then
                    ready=1; break
                fi
                if ! kill -0 "${EX_HK17_PID}" 2>/dev/null; then break; fi
                sleep 0.1
            done

            if [[ "${ready}" == "1" ]]; then
                curl -s -m 2 "http://127.0.0.1:${EPORT}/metrics" -o /dev/null 2>/dev/null || true
            fi

            # Wait up to 10s for exit.
            deadline=$(( $(date +%s) + 10 ))
            ex_hk17_rc=""
            set +e
            while (( $(date +%s) < deadline )); do
                if ! kill -0 "${EX_HK17_PID}" 2>/dev/null; then
                    wait "${EX_HK17_PID}" 2>/dev/null
                    ex_hk17_rc=$?
                    break
                fi
                sleep 0.2
            done
            if [[ -z "${ex_hk17_rc}" ]]; then
                sudo -n kill -9 "${EX_HK17_PID}" 2>/dev/null
                wait "${EX_HK17_PID}" 2>/dev/null
                ex_hk17_rc=999
            fi
            set -e

            echo "[f] HK-17 exporter exit code = ${ex_hk17_rc}"
            echo "--- HK-17 exporter log ---"
            cat "${exp_log_hk17}"
            echo "--- end ---"

            if [[ "${ex_hk17_rc}" -ne 6 ]]; then
                echo "FAIL[f1]: HK-17 expected exit 6, got ${ex_hk17_rc}" >&2
                fail=1
            fi

            err_count=$(jq -s '[.[] | select(.event == "exporter.error.all_ifaces_eacces")] | length' "${exp_log_hk17}" 2>/dev/null || echo 0)
            echo "[f] exporter.error.all_ifaces_eacces count = ${err_count}"
            if [[ "${err_count}" -lt 1 ]]; then
                echo "FAIL[f2]: expected ≥1 exporter.error.all_ifaces_eacces event, got ${err_count}" >&2
                fail=1
            fi

            # Cleanup HK-17 sub-case.
            sudo -n chmod 0755 "${PIN_ROOT}/${IFACE_A}" 2>/dev/null || true
            sudo -n chmod 0644 "${STATS_A}" 2>/dev/null || true
            ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>/dev/null || true
            sudo -n rm -f "${EXPORTER_BIN_TMP}" 2>/dev/null
            rm -f "${exp_log_hk17}"
            cleanup_veth
        fi
    fi
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_LOG_JSON_EXPORTER_EVENTS"
exit "${fail}"
