#!/bin/bash
# T_SIDECAR_READ_EXCEPTION_DIAGNOSTIC — design §6.79 (MVP-4.22 / §5.62, R-5).
#
# §5.62 R-5 stops the exporter's sidecar-reader from SILENTLY swallowing a
# read-path exception. The outer never-throw catch (sidecar_reader.cpp) becomes
# a TWO-ARM catch:
#   - catch(const std::exception& e) → emit NEW event
#       `exporter.scrape.warn.sidecar_read_exception` (+ e.what())
#   - trailing catch(...)            → emit the SAME event (unknown/non-std marker)
# The trailing catch(...) is RETAINED (guard #30 / PI-mvp-4.22-NEVER-THROW) so the
# exporter STILL never throws — graceful degradation is now OBSERVABLE, not silent.
#
# Contract (§5.62 TestStrategy #3 + PI-mvp-4.22-NEVER-THROW):
#   (a) on a sidecar-read failure the exporter emits the NEW event on stderr;
#   (b) the exporter does NOT crash and /metrics STILL serves 200 (never-throw).
#
# §5.32 logger convention: the event-NAME token appears in stderr ONLY under
# XDPMF_LOG_FORMAT=json (text mode emits prose). So — exactly like
# T_LOG_JSON_EXPORTER_EVENTS — we run the exporter under JSON and select the
# event via jq `.event == "exporter.scrape.warn.sidecar_read_exception"`.
#
# Triggering the OUTER :101 catch with a CATCHABLE std::exception is not
# inducible on this stdlib (verified): the inner :78 stoul catch swallows
# malformed numeric lines; the exporter runs as root so chmod can't EACCES;
# getline on a dir/garbage sets failbit (no throw). §6.79 EDIT-2 proposed a
# multi-MB single line to trip a std::regex_error from the per-line regex_search,
# but EMPIRICALLY (clang++-19 libstdc++) a ~7.7 MB line against the exact
# rule_line_re() pattern → SIGSEGV (recursive-NFA stack overflow), NOT a
# catchable throw — an UNCATCHABLE crash + a PRE-EXISTING out-of-scope DoS
# (external-review B27, "HELD by PO"; design §5.62 OOS fence). So that lever is
# DROPPED. The never-throw resilience (exporter alive + /metrics 200 under a
# corrupt/missing/dir sidecar) IS asserted deterministically and is the load-
# bearing R-5 contract; the new event's EXISTENCE is pinned by test #5.
#
# Outcome matrix (§6.79 EDIT-2 pre-negotiated — event-fire is best-effort):
#   - exporter died OR /metrics != 200            → FAIL (never-throw VIOLATED).
#   - clean baseline scrape emitted the event     → FAIL (negation: unconditional).
#   - (a) never-throw held + event FIRED          → PASS (diagnostic observable too).
#   - (a) never-throw held + event NOT fired      → PASS (ACCEPTING — throw not
#                                                    inducible in this libc++;
#                                                    §6.58 test #5 pins existence).
# The WHOLE test never exits 77 on (b)-absence; (a)+negation are the gate.
#
# Negation control: the BASELINE clean scrape (intact sidecar) MUST NOT emit the
# event — proving the diagnostic is CONDITIONAL on the read failure, not emitted
# unconditionally on every scrape. (An unconditional emit would make the
# post-corruption grep pass even with no real failure = theatre.)
#
# Sanity-floor smoke: the baseline clean scrape returns 200 + exporter ready.
#
# SKIP conditions (whole-test): passwordless sudo absent; curl/jq absent. (The
# best-effort (b) throw-induction does NOT skip the test — it degrades to a
# logged note while (a) carries the PASS.)
#
# RESOURCE_LOCK "xdp_fixture;exporter_port_9417" — touches veth (setup_veth) +
# spawns the exporter on the shared 9417-base port (guard #12).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not in PATH (required by §6.79)" >&2
    exit 77
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required by §6.79)" >&2
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
EXPORTER_BIN=$(find_exporter) || { echo "FAIL: xdpmf-exporter not found under ${BUILD_DIR}" >&2; exit 1; }
FIXTURE="${TEST_DIR}/fixtures/config_per_rule_counters.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

# §5.31 EDIT-1: sidecar path = /run/xdpmacfilter/<iface>/rule_index.json
SIDECAR_ROOT="/run/xdpmacfilter"
SIDECAR_DIR="${SIDECAR_ROOT}/${IFACE_A}"
SIDECAR_PATH="${SIDECAR_DIR}/rule_index.json"

PORT=$(( 9417 + ($$ % 1000) ))
echo "EXPORTER_PORT=${PORT}"

EVENT="exporter.scrape.warn.sidecar_read_exception"

exp_log=$(mktemp /tmp/xdpmf-sidecarread-explog.XXXXXX)
metrics_body=$(mktemp /tmp/xdpmf-sidecarread-body.XXXXXX)
stderr_file=$(mktemp /tmp/xdpmf-sidecarread-stderr.XXXXXX)
EXPORTER_PID=""

cleanup_test() {
    set +e
    if [[ -n "${EXPORTER_PID}" ]]; then
        sudo -n kill "${EXPORTER_PID}" 2>/dev/null
        sleep 0.2
        sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null
        wait "${EXPORTER_PID}" 2>/dev/null
    fi
    ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" >/dev/null 2>&1
    sudo -n rm -rf "${SIDECAR_DIR}" 2>/dev/null
    cleanup_veth
    rm -f "${exp_log}" "${metrics_body}" "${stderr_file}"
    set -e
}
trap cleanup_test EXIT INT TERM HUP

# Count occurrences of the NEW event in the JSON exporter log.
event_count() {
    jq -s --arg ev "${EVENT}" '[.[] | select(.event == $ev)] | length' "${exp_log}" 2>/dev/null || echo 0
}

# Scrape /metrics; echoes the HTTP code (000 on transport failure).
scrape_code() {
    curl -s -o "${metrics_body}" -w '%{http_code}' -m 5 "http://127.0.0.1:${PORT}/metrics" 2>/dev/null || echo 000
}

setup_veth

echo "=== apply ${FIXTURE} on ${IFACE_A} (materializes the sidecar)"
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
if ! sudo -n test -e "${SIDECAR_PATH}"; then
    echo "FAIL: sidecar ${SIDECAR_PATH} missing after apply — cannot exercise R-5" >&2
    cat "${stderr_file}" >&2 || true
    exit 1
fi

# ── start exporter under JSON so the event-name token is greppable ──────────
echo "=== starting xdpmf-exporter on 127.0.0.1:${PORT} (XDPMF_LOG_FORMAT=json)"
sudo -n env XDPMF_LOG_FORMAT=json "${EXPORTER_BIN}" \
    --port "${PORT}" \
    --bind 127.0.0.1 \
    --bpffs-root "${PIN_ROOT}" \
    >"${exp_log}" 2>&1 &
EXPORTER_PID=$!
ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT}/healthz" -o /dev/null 2>/dev/null; then
        ready=1; echo "exporter ready after ${i} polls"; break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        echo "FAIL: exporter died during startup" >&2; cat "${exp_log}" >&2; exit 1
    fi
    sleep 0.1
done
[[ "${ready}" == "1" ]] || { echo "FAIL: exporter not ready within 5s" >&2; cat "${exp_log}" >&2; exit 1; }

fail=0

# assert_resilient <desc> — the DETERMINISTIC never-throw core (§6.79 EDIT-2 (a)):
#   after a corruption, the exporter must NOT crash and /metrics must STILL serve
#   200. A crash / non-200 is the exact regression guard #30 protects against (a
#   narrowed catch that dropped the trailing catch(...)). This is load-bearing.
assert_resilient() {
    local desc="$1"
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        echo "FAIL[alive:${desc}]: exporter PID ${EXPORTER_PID} DIED — PI-mvp-4.22-NEVER-THROW VIOLATED" >&2
        cat "${exp_log}" >&2 || true
        fail=1
        return
    fi
    local code; code=$(scrape_code)
    echo "  [${desc}] /metrics http=${code}"
    if [[ "${code}" != "200" ]]; then
        echo "FAIL[serve:${desc}]: /metrics http=${code} (expected 200 — degradation must still serve)" >&2
        fail=1
    fi
}

# ── BASELINE clean scrape — smoke + negation control ───────────────────────
echo "=== baseline scrape (intact sidecar)"
base_code=$(scrape_code)
echo "baseline /metrics http=${base_code}"
if [[ "${base_code}" != "200" ]]; then
    echo "FAIL[base]: baseline /metrics http=${base_code} (expected 200 — smoke floor)" >&2
    fail=1
fi
sleep 0.2
base_event=$(event_count)
echo "baseline ${EVENT} count=${base_event}"
# NEGATION CONTROL: a clean read must NOT emit the read-exception event.
if [[ "${base_event}" != "0" ]]; then
    echo "FAIL[neg]: ${EVENT} emitted on a CLEAN scrape (count=${base_event}) — diagnostic is unconditional, not failure-gated" >&2
    fail=1
fi

# ── (a) DETERMINISTIC never-throw core across corruption forms ─────────────
# The exporter must survive + keep serving under each of these — independent of
# whether any of them actually trips the OUTER catch (b).
echo "=== (a) corrupt content (binary/truncated non-JSON)"
printf '\x00\x01\x02 NOT-json {{{ "schema_version": "xx" \xff\xfe garbage' \
    | sudo -n tee "${SIDECAR_PATH}" >/dev/null
sudo -n chmod 0644 "${SIDECAR_PATH}" 2>/dev/null || true
assert_resilient "corrupt-content"

echo "=== (a) missing file (sidecar removed mid-serve)"
sudo -n rm -f "${SIDECAR_PATH}" 2>/dev/null || true
assert_resilient "missing-file"

echo "=== (a) directory in place of the file"
sudo -n rm -f "${SIDECAR_PATH}" 2>/dev/null || true
sudo -n mkdir -p "${SIDECAR_PATH}" 2>/dev/null || true
assert_resilient "dir-in-place"
sudo -n rm -rf "${SIDECAR_PATH}" 2>/dev/null || true

# ── (b) BEST-EFFORT event-fire: NO safe deterministic lever on this stdlib ──
# §6.79 EDIT-2 proposed a pathologically-long single line to trip a
# std::regex_error from the per-line std::regex_search (the OUTER :101 catch).
# EMPIRICALLY FALSIFIED on this platform's libstdc++ (clang++-19): a ~7.7 MB
# single line against the exact rule_line_re() pattern → SIGSEGV (exit 139,
# recursive-NFA stack overflow), NOT a catchable std::regex_error. A SIGSEGV is
# outside the C++ exception model — the two-arm catch CANNOT intercept it, so it
# (i) can NEVER fire `exporter.scrape.warn.sidecar_read_exception`, and (ii) would
# CRASH the exporter → fail assert_resilient on a PRE-EXISTING, OUT-OF-SCOPE DoS
# (external-review B27, "HELD by PO", on untouched getline+regex code; design
# §5.62 OOS fence). So the long-line lever is DROPPED (it tests neither R-5 nor a
# catchable path). No other inducement produces a CATCHABLE std::exception in
# parse_rule_index on this stdlib (the inner :78 stoul catch swallows numeric
# junk; non-matching lines `continue`; getline on a dir/garbage sets failbit, no
# throw) — exactly the architect's prediction that (b) is "not inducible in this
# libc++". Per the pre-negotiated fallback, (a)+test#5 carry the contract.
#
# We still OPPORTUNISTICALLY record whether ANY of the SAFE (a) corruption forms
# happened to emit the event (base_event==0 by the negation control, so any
# positive count is a real catchable induction); if so we note it as a bonus.
echo "--- exporter JSON log ---"
cat "${exp_log}"
echo "--- end ---"

final_event=$(event_count)
echo "final ${EVENT} count=${final_event}"
event_fired=0
if (( final_event > 0 )); then
    event_fired=1
fi

# ── outcome (§6.79 EDIT-2 pre-negotiated): (a)+negation green = ACCEPTING PASS ─
# A never-throw / negation regression is a hard FAIL. (b) firing is a bonus:
# its ABSENCE neither fails nor skips the whole test (test #5 pins existence).
if [[ "${fail}" != 0 ]]; then
    echo "FAIL: T_SIDECAR_READ_EXCEPTION_DIAGNOSTIC (never-throw resilience or negation control failed)" >&2
    exit 1
fi

if (( event_fired == 1 )); then
    echo "PASS: T_SIDECAR_READ_EXCEPTION_DIAGNOSTIC (a: never-throw held; b: event '${EVENT}' observed)"
else
    echo "PASS: T_SIDECAR_READ_EXCEPTION_DIAGNOSTIC (a: never-throw held under corrupt/missing/dir sidecar)"
    echo "      NOTE: no CATCHABLE std::exception is inducible in parse_rule_index on this libstdc++" >&2
    echo "      (the regex_error long-line lever is a SIGSEGV/OOS-DoS, dropped) — so the event's" >&2
    echo "      EXISTENCE is pinned by T_LOG_EVENT_CATALOG_STABILITY (§6.58, test #5); the never-throw" >&2
    echo "      contract (the load-bearing R-5 invariant) IS verified above." >&2
fi
exit 0
