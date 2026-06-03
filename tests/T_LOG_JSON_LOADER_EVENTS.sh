#!/bin/bash
# T_LOG_JSON_LOADER_EVENTS — design §6.54 (MVP-3.5 / §5.32).
#
# attach + apply + detach under XDPMF_LOG_FORMAT=json. Capture stderr from
# each invocation. Each line must be valid JSON envelope per HG-3.5-2.
#
# Observable outcome:
#   (a) Each stderr line is a valid JSON object (per-line `jq -e '.'`).
#   (b) `loader.trust_model` event fires exactly TWICE across attach+apply
#       captures (once per invocation per §5.26 audit-log; detach does NOT
#       emit it — pre-§5.32 behavior preserved).
#   (c) Each event's `level` value is in {"info","warn","error"}.
#   (d) `loader.trust_model` event has `fields.trust_model == "strict"`
#       (default env, no XDPMF_TRUST_MODEL override).
#   (e) `loader.trust_model` event's `iface` is null (process-scoped per catalog).
#
# Sanity-floor smoke: (a) — each line parses as JSON. If JSON renderer is
# broken (e.g., trailing comma, unquoted strings), no line parses → fail.
# Negation control: re-run sequence under XDPMF_LOG_FORMAT=text; assert
# the stderr lines are NOT JSON (per-line `jq -e '.'` returns non-zero for
# at least one non-trivial line). Proves the env-var is doing real work.
#
# SKIP: passwordless sudo (require_passwordless_sudo); jq (assumed present).
#
# Cleanup: cleanup_veth + rm tmp captures.
#
# Maps to: PI-3.5-2 (JSON envelope), PI-3.5-4 (event-name catalog),
# HG-3.5-2, Q3 E1, Q4 R1.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required by §6.54)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE_CONFIG="${TEST_DIR}/fixtures/config_valid.yaml"
[[ -f "${FIXTURE_CONFIG}" ]] || { echo "FAIL: missing fixture ${FIXTURE_CONFIG}" >&2; exit 1; }

cap_attach=$(mktemp /tmp/xdpmf-jsonldr-attach.XXXXXX)
cap_apply=$(mktemp /tmp/xdpmf-jsonldr-apply.XXXXXX)
cap_detach=$(mktemp /tmp/xdpmf-jsonldr-detach.XXXXXX)
cap_text=$(mktemp /tmp/xdpmf-jsonldr-text.XXXXXX)
trap 'cleanup_veth; rm -f "${cap_attach}" "${cap_apply}" "${cap_detach}" "${cap_text}"' EXIT

setup_veth

echo "=== attach under XDPMF_LOG_FORMAT=json"
set +e
${NSEXEC} env XDPMF_LOG_FORMAT=json "${LOADER_BIN}" \
    attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" \
    2>"${cap_attach}" 1>/dev/null
rc_attach=$?
set -e
echo "attach rc=${rc_attach}"
echo "--- stderr (attach) ---"
cat "${cap_attach}"
echo "--- end ---"

echo "=== apply under XDPMF_LOG_FORMAT=json"
set +e
${NSEXEC} env XDPMF_LOG_FORMAT=json "${LOADER_BIN}" \
    apply --iface "${IFACE_A}" -f "${FIXTURE_CONFIG}" \
    2>"${cap_apply}" 1>/dev/null
rc_apply=$?
set -e
echo "apply rc=${rc_apply}"
echo "--- stderr (apply) ---"
cat "${cap_apply}"
echo "--- end ---"

echo "=== detach under XDPMF_LOG_FORMAT=json"
set +e
${NSEXEC} env XDPMF_LOG_FORMAT=json "${LOADER_BIN}" \
    detach --iface "${IFACE_A}" \
    2>"${cap_detach}" 1>/dev/null
rc_detach=$?
set -e
echo "detach rc=${rc_detach}"
echo "--- stderr (detach) ---"
cat "${cap_detach}"
echo "--- end ---"

fail=0

# Smoke: attach + apply succeeded (rc=0). detach may emit nothing.
if [[ "${rc_attach}" -ne 0 ]]; then
    echo "FAIL[smoke-attach]: attach rc=${rc_attach}, expected 0" >&2
    fail=1
fi
if [[ "${rc_apply}" -ne 0 ]]; then
    echo "FAIL[smoke-apply]: apply rc=${rc_apply}, expected 0" >&2
    fail=1
fi

# ── (a) every non-empty stderr line is valid JSON ──────────────────────
echo
echo "=== (a) every non-empty stderr line is valid JSON"
check_lines_json() {
    local file="$1" tag="$2"
    local lineno=0 failed=0
    while IFS= read -r line; do
        lineno=$(( lineno + 1 ))
        [[ -z "${line}" ]] && continue
        if ! printf '%s\n' "${line}" | jq -e '.' >/dev/null 2>&1; then
            echo "FAIL[a/${tag}]: line ${lineno} is NOT valid JSON:" >&2
            echo "  ${line}" >&2
            failed=1
        fi
    done < "${file}"
    return ${failed}
}
if ! check_lines_json "${cap_attach}" attach; then fail=1; fi
if ! check_lines_json "${cap_apply}"  apply;  then fail=1; fi
# detach may be empty (no events emitted); only check if non-empty.
if [[ -s "${cap_detach}" ]]; then
    if ! check_lines_json "${cap_detach}" detach; then fail=1; fi
fi

# ── (b) loader.trust_model fires exactly TWICE across attach+apply ─────
echo
echo "=== (b) loader.trust_model event count across attach+apply"
combined=$(mktemp /tmp/xdpmf-jsonldr-combined.XXXXXX)
cat "${cap_attach}" "${cap_apply}" "${cap_detach}" > "${combined}"
# Use jq -s '[ select ] | length'. Per-line slurp then filter.
tm_count=$(jq -s '[.[] | select(.event == "loader.trust_model")] | length' "${combined}" 2>/dev/null || echo "PARSE_ERROR")
echo "loader.trust_model event count = ${tm_count}"
if [[ "${tm_count}" != "2" ]]; then
    echo "FAIL[b]: expected exactly 2 loader.trust_model events (attach + apply), got ${tm_count}" >&2
    fail=1
fi

# ── (c) every event's level ∈ {info,warn,error} ────────────────────────
echo
echo "=== (c) level values are valid"
bad_levels=$(jq -s -r '
    .[]
    | select((.level | IN("info","warn","error")) | not)
    | .level
' "${combined}" 2>/dev/null || true)
if [[ -n "${bad_levels}" ]]; then
    echo "FAIL[c]: events with off-spec level values:" >&2
    echo "${bad_levels}" >&2
    fail=1
fi

# ── (d) loader.trust_model has fields.trust_model == "strict" ──────────
echo
echo "=== (d) loader.trust_model fields.trust_model == \"strict\""
tm_values=$(jq -s -r '
    .[]
    | select(.event == "loader.trust_model")
    | .fields.trust_model
' "${combined}" 2>/dev/null || true)
echo "trust_model field values: ${tm_values}"
# Each value must be "strict"; expect 2 lines.
nonstrict_count=$(printf '%s\n' "${tm_values}" | grep -cvE '^strict$' || true)
nonstrict_count=${nonstrict_count:-0}
if [[ "${nonstrict_count}" -gt 0 ]]; then
    echo "FAIL[d]: loader.trust_model event(s) with fields.trust_model != \"strict\"" >&2
    fail=1
fi

# ── (e) loader.trust_model.iface is null (process-scoped) ──────────────
echo
echo "=== (e) loader.trust_model.iface == null"
nonnull_iface=$(jq -s -r '
    .[]
    | select(.event == "loader.trust_model")
    | select(.iface != null)
    | .iface
' "${combined}" 2>/dev/null || true)
if [[ -n "${nonnull_iface}" ]]; then
    echo "FAIL[e]: loader.trust_model.iface is not null for at least one event:" >&2
    echo "${nonnull_iface}" >&2
    fail=1
fi

# ── NEGATION CONTROL: text-mode lines are NOT JSON ─────────────────────
echo
echo "=== NEGATION CONTROL: re-run attach under XDPMF_LOG_FORMAT=text"
setup_veth
set +e
${NSEXEC} env XDPMF_LOG_FORMAT=text "${LOADER_BIN}" \
    attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" \
    2>"${cap_text}" 1>/dev/null
cleanup_veth
set -e

echo "--- stderr (text) ---"
cat "${cap_text}"
echo "--- end ---"

# At least one non-empty text-mode line must FAIL to parse as JSON
# (text lines like `xdpfilter: trust_model=strict` are not JSON).
any_non_json=0
while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    if ! printf '%s\n' "${line}" | jq -e '.' >/dev/null 2>&1; then
        any_non_json=1
        break
    fi
done < "${cap_text}"
if [[ "${any_non_json}" -ne 1 ]]; then
    echo "FAIL[neg]: every text-mode line parsed as JSON — env-var not honored" >&2
    fail=1
else
    echo "[neg] OK: at least one text-mode line fails JSON parse"
fi

rm -f "${combined}"

[[ "${fail}" == 0 ]] && echo "PASS: T_LOG_JSON_LOADER_EVENTS"
exit "${fail}"
