#!/bin/bash
# T_LOG_JSON_BYPASS_AUDIT — design §6.56 (MVP-3.5 / §5.32).
#
# bypass.activated event under XDPMF_LOG_FORMAT=json carries HK-4
# structural fields (uid, euid, sudo_user, reason) in fields:{}.
#
# Trigger (PRIMARY):
#   - setup_veth + attach (default mode) on IFACE_A allow=MAC_GOOD.
#   - `xdpmacfilter bypass --iface IFACE_A --unsafe --reason T_LOG_JSON_test`
#     under XDPMF_LOG_FORMAT=json (non-tty via setsid).
#   - Capture stderr.
#
# Observable outcome (PRIMARY):
#   (a) Exactly ONE JSON line with .event == "bypass.activated".
#   (b) .level == "info".
#   (c) .iface == "<IFACE_A>".
#   (d) .fields.uid is an integer (matches `id -u` of invoking process).
#   (e) .fields.euid is an integer.
#   (f) .fields.sudo_user is a string (real SUDO_USER OR "<none>" sentinel).
#   (g) .fields.reason == "T_LOG_JSON_test".
#
# NEGATION CONTROL (PI-3.5-1 byte-equivalence under text mode):
#   (h) Re-run under XDPMF_LOG_FORMAT=text — stderr contains the pre-§5.32
#       HK-4 audit-line ERE byte-equivalent.
#
# Second negation (JSON escape):
#   (i) `--reason 'has"quote'` under JSON mode — .fields.reason decoded by
#       jq returns `has"quote` (escape handled correctly).
#
# D-3.5-7 / PI-3.5-6 cross-check (out of audit scope but related):
#   The interactive prompt at bypass.cpp:96 is EXEMPT (not converted to logger).
#   This test does NOT cover that prompt path — T_BYPASS_INTERACTIVE_PROMPT
#   does (using a pty). Here we use --unsafe → prompt is suppressed entirely.
#
# Sanity-floor smoke: step "attach succeeded" is the smoke (bypass needs
# something to detach).
# Negation control: (h) — text-mode byte-equivalence at the HK-4 scope.
#
# SKIP: passwordless sudo; jq.
#
# Cleanup: cleanup_veth + rm tmp captures.
#
# Maps to: PI-3.5-2, PI-3.5-5 (HK-4 fields), HG-3.5-3.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required by §6.56)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
echo "loader=${LOADER_BIN}"

cap_json=$(mktemp /tmp/xdpmf-jsonbyp-json.XXXXXX)
cap_text=$(mktemp /tmp/xdpmf-jsonbyp-text.XXXXXX)
cap_escape=$(mktemp /tmp/xdpmf-jsonbyp-escape.XXXXXX)
trap 'cleanup_veth; rm -f "${cap_json}" "${cap_text}" "${cap_escape}"' EXIT

setup_veth

# ── PRIMARY: bypass under XDPMF_LOG_FORMAT=json ─────────────────────────
echo "=== attach on ${IFACE_A}"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

pre_id=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
if [[ -z "${pre_id}" ]]; then
    echo "FAIL: smoke — ${IFACE_A} has no XDP attached after attach call" >&2
    exit 1
fi

echo "=== bypass --unsafe --reason T_LOG_JSON_test under XDPMF_LOG_FORMAT=json"
set +e
${NSEXEC} env XDPMF_LOG_FORMAT=json setsid -- "${LOADER_BIN}" \
    bypass --iface "${IFACE_A}" --unsafe --reason "T_LOG_JSON_test" \
    </dev/null 2>"${cap_json}"
rc=$?
set -e
echo "bypass rc=${rc}"
echo "--- stderr (json) ---"
cat "${cap_json}"
echo "--- end ---"

fail=0

if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[smoke-rc]: bypass rc=${rc}, expected 0" >&2
    fail=1
fi

# Extract the bypass.activated line.
bypass_line=$(jq -s -c '.[] | select(.event == "bypass.activated")' "${cap_json}" 2>/dev/null || true)
echo "bypass.activated line: ${bypass_line}"

# (a) exactly ONE bypass.activated event
ba_count=$(jq -s '[.[] | select(.event == "bypass.activated")] | length' "${cap_json}" 2>/dev/null || echo 0)
if [[ "${ba_count}" != "1" ]]; then
    echo "FAIL[a]: expected exactly 1 bypass.activated event, got ${ba_count}" >&2
    fail=1
fi

# Helper to extract a single field from the bypass.activated event.
ba_field() {
    local path="$1"
    jq -s -r ".[] | select(.event == \"bypass.activated\") | ${path}" "${cap_json}" 2>/dev/null | head -1
}

# (b) .level == "info"
ba_level=$(ba_field '.level')
echo "level=${ba_level}"
if [[ "${ba_level}" != "info" ]]; then
    echo "FAIL[b]: expected .level==info, got '${ba_level}'" >&2
    fail=1
fi

# (c) .iface == "${IFACE_A}"
ba_iface=$(ba_field '.iface')
echo "iface=${ba_iface}"
if [[ "${ba_iface}" != "${IFACE_A}" ]]; then
    echo "FAIL[c]: expected .iface==${IFACE_A}, got '${ba_iface}'" >&2
    fail=1
fi

# (d) .fields.uid is an integer
uid_type=$(ba_field '.fields.uid | type')
uid_val=$(ba_field '.fields.uid')
echo "fields.uid=${uid_val} (type=${uid_type})"
if [[ "${uid_type}" != "number" ]]; then
    echo "FAIL[d]: .fields.uid type='${uid_type}', expected number" >&2
    fail=1
fi

# (e) .fields.euid is an integer
euid_type=$(ba_field '.fields.euid | type')
euid_val=$(ba_field '.fields.euid')
echo "fields.euid=${euid_val} (type=${euid_type})"
if [[ "${euid_type}" != "number" ]]; then
    echo "FAIL[e]: .fields.euid type='${euid_type}', expected number" >&2
    fail=1
fi

# (f) .fields.sudo_user is a string
su_type=$(ba_field '.fields.sudo_user | type')
su_val=$(ba_field '.fields.sudo_user')
echo "fields.sudo_user='${su_val}' (type=${su_type})"
if [[ "${su_type}" != "string" ]]; then
    echo "FAIL[f]: .fields.sudo_user type='${su_type}', expected string" >&2
    fail=1
fi

# (g) .fields.reason == "T_LOG_JSON_test"
reason_val=$(ba_field '.fields.reason')
echo "fields.reason='${reason_val}'"
if [[ "${reason_val}" != "T_LOG_JSON_test" ]]; then
    echo "FAIL[g]: .fields.reason='${reason_val}', expected 'T_LOG_JSON_test'" >&2
    fail=1
fi

# ── NEGATION CONTROL: text-mode HK-4 byte-equivalence ──────────────────
echo
echo "=== NEGATION CONTROL: bypass under XDPMF_LOG_FORMAT=text"
# Re-attach (previous bypass detached).
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

set +e
${NSEXEC} env XDPMF_LOG_FORMAT=text setsid -- "${LOADER_BIN}" \
    bypass --iface "${IFACE_A}" --unsafe --reason "T_LOG_JSON_text" \
    </dev/null 2>"${cap_text}"
rc_text=$?
set -e
echo "text bypass rc=${rc_text}"
echo "--- stderr (text) ---"
cat "${cap_text}"
echo "--- end ---"

if [[ "${rc_text}" -ne 0 ]]; then
    echo "FAIL[h-rc]: text-mode bypass rc=${rc_text}, expected 0" >&2
    fail=1
fi

# Pre-§5.32 HK-4 audit-line ERE (mirrors T_BYPASS_INTERACTIVE_PROMPT line 309).
audit_ere="xdpmacfilter: BYPASS activated on ${IFACE_A} by uid=[0-9]+ euid=[0-9]+ sudo_user=\"[^\"]*\" reason=\"T_LOG_JSON_text\"\$"
if ! grep -qE -- "${audit_ere}" "${cap_text}"; then
    echo "FAIL[h]: text-mode HK-4 audit-line missing — PI-3.5-1 byte-equivalence violation" >&2
    echo "        expected ERE: ${audit_ere}" >&2
    fail=1
else
    echo "[h] OK: text-mode HK-4 audit-line present (byte-equivalent baseline)"
fi

# Text-mode line is NOT JSON.
if grep -m1 'xdpmacfilter:' "${cap_text}" | jq -e '.' >/dev/null 2>&1; then
    echo "FAIL[h2]: text-mode HK-4 line unexpectedly parses as JSON" >&2
    fail=1
fi

# ── Second NEGATION: JSON escape inside --reason ────────────────────────
echo
echo "=== escape sub-case: --reason 'has\"quote' under JSON"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3

set +e
${NSEXEC} env XDPMF_LOG_FORMAT=json setsid -- "${LOADER_BIN}" \
    bypass --iface "${IFACE_A}" --unsafe --reason 'has"quote' \
    </dev/null 2>"${cap_escape}"
rc_esc=$?
set -e
echo "escape bypass rc=${rc_esc}"
echo "--- stderr (escape json) ---"
cat "${cap_escape}"
echo "--- end ---"

if [[ "${rc_esc}" -ne 0 ]]; then
    echo "FAIL[i-rc]: escape bypass rc=${rc_esc}, expected 0" >&2
    fail=1
fi

# Each line of stderr must still parse as JSON despite the embedded quote
# (proves escape correctness — a broken escape would produce malformed JSON).
esc_non_json=0
while IFS= read -r line; do
    [[ -z "${line}" ]] && continue
    if ! printf '%s\n' "${line}" | jq -e '.' >/dev/null 2>&1; then
        echo "FAIL[i-parse]: line is NOT valid JSON despite escape: ${line}" >&2
        esc_non_json=$(( esc_non_json + 1 ))
    fi
done < "${cap_escape}"
if (( esc_non_json > 0 )); then
    fail=1
fi

# jq-decoded value must equal the raw input (has"quote).
escaped_reason=$(jq -s -r '.[] | select(.event == "bypass.activated") | .fields.reason' "${cap_escape}" 2>/dev/null | head -1)
echo "decoded reason: '${escaped_reason}'"
if [[ "${escaped_reason}" != 'has"quote' ]]; then
    echo "FAIL[i]: decoded reason='${escaped_reason}', expected 'has\"quote'" >&2
    fail=1
else
    echo "[i] OK: jq-decoded reason matches raw input (escape round-trip correct)"
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_LOG_JSON_BYPASS_AUDIT"
exit "${fail}"
