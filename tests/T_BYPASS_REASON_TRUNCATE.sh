#!/bin/bash
# T_BYPASS_REASON_TRUNCATE — design §6.45 (MVP-3.4.5 / §5.30 HK-4).
#
# Verifies the HK-4 truncation contract on the bypass `--reason` field:
#   - 253 bytes (boundary): NO truncation — full 253 bytes preserved.
#   - 254 bytes (first truncation): truncated to 253 bytes + `…` (3-byte
#     UTF-8 ellipsis) = 256 bytes total inside the quotes.
#   - 300 bytes ending mid 4-byte UTF-8 codepoint: truncation REWINDS to
#     the codepoint boundary BEFORE byte 253 (NEVER cuts mid-codepoint);
#     appends `…`. Resulting bytes form valid UTF-8.
#
# Per architect's amendment in §6.45 (correcting the brief's 256/257
# headline): 253 is the no-truncation boundary, 254 is the first
# truncation byte-count. The brief said 256/257 — that contradicts the
# HK-4 byte budget (253 bytes payload + 3 bytes `…` = 256 max). Architect
# locked the test at 253/254/300.
#
# Sanity-floor smoke: each sub-case begins with a successful attach
# (smoke for the fixture). The audit-log line itself IS the assertion
# vehicle — its presence proves the bypass primitive ran.
#
# Negation control: the 254-byte sub-case is the load-bearing failure-mode
# probe: if HK-4 truncation were broken (e.g. byte-counted off-by-one),
# either no `…` or wrong-length output would surface. The 300-byte
# mid-UTF-8 case is the deeper failure probe — if rewind-safety were
# broken, the resulting bytes would not decode as valid UTF-8 (the
# Python decode check raises and we fail).
#
# SKIP-77: needs `python3` (preferred) or `iconv` for UTF-8 validity
# check on the rewind-safety sub-case. Both are POSIX-common; SKIP if
# neither present.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

# String construction for sub-case 3 (300B mid-UTF-8) requires python3
# to emit a precisely-byte-counted blob ending mid 4-byte codepoint;
# bash printf alone cannot reliably construct that. The UTF-8 validity
# check on the output can be python3 OR iconv; if neither is present,
# SKIP-77. python3 is therefore the harder requirement.
if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: T_BYPASS_REASON_TRUNCATE needs python3 for byte-precise UTF-8 fixture construction" >&2
    exit 77
fi
UTF8_CHECK_TOOL=python3
if ! command -v iconv >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: T_BYPASS_REASON_TRUNCATE needs python3 or iconv for UTF-8 validity check" >&2
    exit 77
fi
echo "UTF8_CHECK_TOOL=${UTF8_CHECK_TOOL}"

LOADER_BIN=$(find_loader)
echo "loader=${LOADER_BIN}"

stderr_253=$(mktemp /tmp/xdpmf-trunc-253.XXXXXX)
stderr_254=$(mktemp /tmp/xdpmf-trunc-254.XXXXXX)
stderr_300=$(mktemp /tmp/xdpmf-trunc-300.XXXXXX)

cleanup_test() {
    set +e
    ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>/dev/null
    cleanup_veth
    rm -f "${stderr_253}" "${stderr_254}" "${stderr_300}"
    set -e
}
trap cleanup_test EXIT

setup_veth

attach_smoke() {
    ${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
    sleep 0.3
    local pre_id
    pre_id=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
    if [[ -z "${pre_id}" ]]; then
        echo "FAIL: smoke — attach did not produce XDP prog id" >&2
        return 1
    fi
}

# Extract the value inside `reason="..."` from a stderr file. Greedy
# match against the LAST `reason="..."` token (the audit-log line is the
# only one in our test invocations).
extract_reason_value() {
    local file="$1"
    # `grep -oE 'reason="[^"]*"'` extracts the whole token; trim outer
    # `reason="` and trailing `"`.
    grep -oE 'reason="[^"]*"' "${file}" | tail -n1 | sed -E 's/^reason="//; s/"$//'
}

# Byte length (NOT codepoint count) of stdin.
byte_len() {
    wc -c
}

# Check that the input is valid UTF-8. Returns 0 if valid, 1 if invalid.
check_utf8_valid() {
    local file="$1"
    if [[ "${UTF8_CHECK_TOOL}" == "python3" ]]; then
        python3 -c '
import sys
data = open(sys.argv[1], "rb").read()
try:
    data.decode("utf-8")
except UnicodeDecodeError as e:
    sys.stderr.write("UTF-8 decode error: %s\n" % e)
    sys.exit(1)
' "${file}"
    else
        # iconv emits an error to stderr (and exits non-zero) on invalid UTF-8.
        iconv -f UTF-8 -t UTF-8 "${file}" >/dev/null 2>&1
    fi
}

fail=0

# ─────────────────────────────────────────────────────────────────────────
# SUB-CASE 1: 253 bytes (boundary — NO truncation).
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== SUB-CASE 1: --reason of 253 ASCII bytes (boundary, no truncation expected)"
attach_smoke || { fail=1; }
REASON_253=$(python3 -c 'import sys; sys.stdout.write("a"*253)')
[[ ${#REASON_253} -eq 253 ]] || { echo "FAIL: REASON_253 setup wrong length: ${#REASON_253}" >&2; fail=1; }

set +e
${NSEXEC} setsid -- "${LOADER_BIN}" bypass --iface "${IFACE_A}" \
    --unsafe --reason "${REASON_253}" \
    </dev/null 2>"${stderr_253}"
rc_253=$?
set -e
echo "253-byte rc=${rc_253}"

if [[ "${rc_253}" -ne 0 ]]; then
    echo "FAIL[1a]: 253-byte case: expected rc=0, got ${rc_253}" >&2
    fail=1
fi

reason_out_253=$(extract_reason_value "${stderr_253}")
reason_len_253=$(printf '%s' "${reason_out_253}" | byte_len | tr -d ' ')
echo "reason_out_253 byte-length = ${reason_len_253} (expected 253)"

# (1b) Output reason MUST be 253 bytes (no truncation, no `…`).
if [[ "${reason_len_253}" != "253" ]]; then
    echo "FAIL[1b]: 253-byte case: expected reason value 253 bytes, got ${reason_len_253}" >&2
    fail=1
fi
# (1c) MUST NOT contain `…` (U+2026, 3 bytes 0xE2 0x80 0xA6).
if printf '%s' "${reason_out_253}" | grep -q $'\xe2\x80\xa6'; then
    echo "FAIL[1c]: 253-byte case: ellipsis `…` present — truncation fired prematurely" >&2
    fail=1
fi

# Re-attach for sub-case 2 (bypass detached).
${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>/dev/null || true
sleep 0.2

# ─────────────────────────────────────────────────────────────────────────
# SUB-CASE 2: 254 bytes (FIRST truncation — 253 bytes + `…`).
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== SUB-CASE 2: --reason of 254 ASCII bytes (first truncation: 253B + ellipsis)"
attach_smoke || { fail=1; }
REASON_254=$(python3 -c 'import sys; sys.stdout.write("b"*254)')
[[ ${#REASON_254} -eq 254 ]] || { echo "FAIL: REASON_254 setup wrong length: ${#REASON_254}" >&2; fail=1; }

set +e
${NSEXEC} setsid -- "${LOADER_BIN}" bypass --iface "${IFACE_A}" \
    --unsafe --reason "${REASON_254}" \
    </dev/null 2>"${stderr_254}"
rc_254=$?
set -e
echo "254-byte rc=${rc_254}"

if [[ "${rc_254}" -ne 0 ]]; then
    echo "FAIL[2a]: 254-byte case: expected rc=0, got ${rc_254}" >&2
    fail=1
fi

reason_out_254=$(extract_reason_value "${stderr_254}")
reason_len_254=$(printf '%s' "${reason_out_254}" | byte_len | tr -d ' ')
echo "reason_out_254 byte-length = ${reason_len_254} (expected 256: 253 + 3-byte ellipsis)"

# (2b) Truncated output MUST be 256 bytes (253 + `…` 3 bytes).
if [[ "${reason_len_254}" != "256" ]]; then
    echo "FAIL[2b]: 254-byte case: expected truncated reason 256 bytes (253 + ellipsis), got ${reason_len_254}" >&2
    fail=1
fi
# (2c) MUST end with `…` (U+2026, 3 bytes 0xE2 0x80 0xA6).
if ! printf '%s' "${reason_out_254}" | tail -c 3 | grep -q $'\xe2\x80\xa6'; then
    echo "FAIL[2c]: 254-byte case: reason value does not end with `…` (U+2026) — truncation marker missing" >&2
    fail=1
fi
# (2d) First 253 bytes MUST be all 'b' (no corruption).
prefix_253_bytes=$(printf '%s' "${reason_out_254}" | head -c 253)
if [[ "${prefix_253_bytes}" != $(python3 -c 'import sys; sys.stdout.write("b"*253)') ]]; then
    echo "FAIL[2d]: 254-byte case: first 253 bytes of truncated output not the original 'b'*253" >&2
    fail=1
fi

# Re-attach for sub-case 3.
${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>/dev/null || true
sleep 0.2

# ─────────────────────────────────────────────────────────────────────────
# SUB-CASE 3: 300 bytes ending mid 4-byte UTF-8 codepoint (rewind-safety).
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== SUB-CASE 3: --reason 300B with byte-253 mid 4-byte UTF-8 codepoint"
attach_smoke || { fail=1; }

# Build the string: 251 ASCII 'c' + 4-byte 😀 (U+1F600) ≈ 255 bytes prefix.
# Pad with more 4-byte emojis until total ≥ 300 bytes. The 4-byte emoji
# straddling byte 253: 251 bytes ASCII + emoji starts at byte 252 → emoji
# bytes occupy 252,253,254,255 → byte-253-cut would split it.
#
# Per HK-4: impl MUST rewind to the codepoint boundary BEFORE byte 253
# (i.e., truncate to 251 bytes of payload + `…`), NOT cut mid-codepoint.
REASON_300=$(python3 -c '
import sys
# 251 ASCII + 4-byte emoji × N → ≥300 bytes.
# 251 + 13*4 = 251 + 52 = 303 bytes; trim to exactly 300.
s = "c" * 251 + ("\U0001F600" * 13)
out = s.encode("utf-8")
# Trim to exactly 300 bytes (cut may happen mid-codepoint; that mirrors
# the OPERATOR-PROVIDED input which is itself bytes-only). The loader is
# what has to rewind on truncation — NOT our test input.
out = out[:300]
sys.stdout.buffer.write(out)
')
reason_300_len=$(printf '%s' "${REASON_300}" | byte_len | tr -d ' ')
echo "REASON_300 byte length = ${reason_300_len} (expected 300)"
if [[ "${reason_300_len}" != "300" ]]; then
    echo "FAIL: REASON_300 setup wrong length: ${reason_300_len}" >&2
    fail=1
fi

set +e
${NSEXEC} setsid -- "${LOADER_BIN}" bypass --iface "${IFACE_A}" \
    --unsafe --reason "${REASON_300}" \
    </dev/null 2>"${stderr_300}"
rc_300=$?
set -e
echo "300-byte rc=${rc_300}"
echo "--- stderr (300B) ---"
cat "${stderr_300}" >&2 || true
echo "--- end ---"

if [[ "${rc_300}" -ne 0 ]]; then
    echo "FAIL[3a]: 300-byte case: expected rc=0, got ${rc_300}" >&2
    fail=1
fi

# (3b) The extracted reason value MUST be valid UTF-8.
# Strip the trailing newline that grep/sed always appends — otherwise
# the byte count is off-by-one and the head/tail math below drifts.
# Tested via a regular text file (no NUL bytes), so `tr -d '\n'` is safe.
extract_reason_value "${stderr_300}" | tr -d '\n' > "${stderr_300}.reason"
if ! check_utf8_valid "${stderr_300}.reason"; then
    echo "FAIL[3b]: 300-byte case: truncated reason is NOT valid UTF-8 — rewind-safety broken" >&2
    head -c 300 "${stderr_300}.reason" | od -An -c | head -3 >&2 || true
    fail=1
fi

# (3c) Truncated value MUST end with `…` (U+2026, 3 bytes).
if ! tail -c 3 "${stderr_300}.reason" | grep -q $'\xe2\x80\xa6'; then
    echo "FAIL[3c]: 300-byte case: truncated reason does not end with `…` — truncation marker missing" >&2
    fail=1
fi

# (3d) Truncated payload (everything before `…`) MUST be ≤ 253 bytes
# (the HK-4 budget) AND must be a whole-codepoint prefix of the input.
# With the newline stripped above, total file bytes = payload + 3
# (ellipsis); payload = (total - 3).
total_bytes_300=$(wc -c < "${stderr_300}.reason" | tr -d ' ')
payload_len_300=$(( total_bytes_300 - 3 ))
echo "300-byte case: total bytes in stripped reason = ${total_bytes_300}; payload (minus ellipsis) = ${payload_len_300} (expected 251)"
if (( payload_len_300 > 253 )); then
    echo "FAIL[3d]: 300-byte case: truncated payload ${payload_len_300} > 253-byte budget" >&2
    fail=1
fi
# For the specific input we built (251 ASCII + 4-byte emoji starting at
# byte 252), the rewind MUST land at byte 251 — i.e. payload is exactly
# 251 bytes of 'c'. Verify.
if (( payload_len_300 != 251 )); then
    echo "FAIL[3d-precise]: 300-byte case: expected rewind to byte 251 (start of straddling emoji); got payload length ${payload_len_300}" >&2
    echo "                  if 252-byte payload → rewind landed INSIDE the emoji (1 byte too late)" >&2
    echo "                  if <251 bytes → rewind retreated too far" >&2
    fail=1
fi

rm -f "${stderr_300}.reason"

[[ "${fail}" == 0 ]] && echo "PASS: T_BYPASS_REASON_TRUNCATE"
exit "${fail}"
