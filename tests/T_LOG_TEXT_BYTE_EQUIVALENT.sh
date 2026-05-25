#!/bin/bash
# T_LOG_TEXT_BYTE_EQUIVALENT — design §6.53 (MVP-3.5 / §5.32).
#
# LOAD-BEARING CANARY for PI-3.5-1 (text-mode byte-equivalence).
#
# Trigger: run a deterministic stderr-producing sequence under THREE env
# conditions:
#   1. `XDPMF_LOG_FORMAT` UNSET (no env var present)
#   2. `XDPMF_LOG_FORMAT=""`   (empty string)
#   3. `XDPMF_LOG_FORMAT=text` (explicit literal)
#
# Sequence: attach + apply + detach on IFACE_A under default trust_model.
# Capture stderr from each invocation in each env condition.
#
# Observable outcome:
#   (a) All 3 env conditions produce BYTE-IDENTICAL stderr (after the
#       iface-name normalization).
#   (b) Stderr matches the captured-at-test-write-time reference fixture
#       (tests/fixtures/log_text_reference.txt) after normalization.
#   (c) NEGATION: re-run sequence under XDPMF_LOG_FORMAT=json — stderr is
#       DIFFERENT (cmp returns NON-ZERO). Proves env var is doing real
#       work; proves test isn't a no-op.
#
# Normalization (per §6.53 spec):
#   - process-specific ints: `s/uid=[0-9]+/uid=N/g`, `s/euid=[0-9]+/euid=N/g`,
#     `s/prog id [0-9]+/prog id N/g`
#   - iface name placeholder: `s/${IFACE_A}/IFACE_A_PLACEHOLDER/g` (test
#     uses PID-suffixed iface name; reference fixture uses literal placeholder)
#
# Sanity-floor smoke: the first attach that completes is the smoke (no
# functional packet assertion — just that the binary runs and writes stderr).
# Negation control: sub-case (c) — JSON mode MUST produce non-byte-identical
# output. If text-mode and json-mode collide, the env var isn't honored or
# JSON wrapping isn't real.
#
# SKIP conditions: passwordless sudo (require_passwordless_sudo).
#
# Cleanup: cleanup_veth + rm tmp captures.
#
# Maps to: PI-3.5-1, PI-3.5-3 (env-var contract — unset/empty/text equivalence),
# HG-3.5-1, D-3.5-6.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE_DIR="${TEST_DIR}/fixtures"
FIXTURE_CONFIG="${FIXTURE_DIR}/config_valid.yaml"
REF_FILE="${FIXTURE_DIR}/log_text_reference.txt"

[[ -f "${FIXTURE_CONFIG}" ]] || { echo "FAIL: missing fixture ${FIXTURE_CONFIG}" >&2; exit 1; }
[[ -f "${REF_FILE}" ]]       || { echo "FAIL: missing reference ${REF_FILE}" >&2; exit 1; }

# Tmp captures (one per env condition + JSON for negation).
cap_unset=$(mktemp /tmp/xdpmf-textcap-unset.XXXXXX)
cap_empty=$(mktemp /tmp/xdpmf-textcap-empty.XXXXXX)
cap_text=$(mktemp /tmp/xdpmf-textcap-text.XXXXXX)
cap_json=$(mktemp /tmp/xdpmf-textcap-json.XXXXXX)
norm_unset=$(mktemp /tmp/xdpmf-textnorm-unset.XXXXXX)
norm_empty=$(mktemp /tmp/xdpmf-textnorm-empty.XXXXXX)
norm_text=$(mktemp /tmp/xdpmf-textnorm-text.XXXXXX)
norm_json=$(mktemp /tmp/xdpmf-textnorm-json.XXXXXX)
norm_ref=$(mktemp /tmp/xdpmf-textnorm-ref.XXXXXX)

trap 'cleanup_veth; rm -f "${cap_unset}" "${cap_empty}" "${cap_text}" "${cap_json}" "${norm_unset}" "${norm_empty}" "${norm_text}" "${norm_json}" "${norm_ref}"' EXIT

# ── normalization helper ────────────────────────────────────────────────
# Replaces process-specific ints + per-PID iface name with stable tokens.
# Reads stdin, writes stdout.
normalize() {
    sed -E \
        -e 's/uid=[0-9]+/uid=N/g' \
        -e 's/euid=[0-9]+/euid=N/g' \
        -e 's/prog id [0-9]+/prog id N/g' \
        -e "s/${IFACE_A}/IFACE_A_PLACEHOLDER/g" \
        -e "s/${IFACE_B}/IFACE_B_PLACEHOLDER/g"
}

# ── run_seq: attach + apply + detach under chosen env mode ──────────────
# $1: env-var spec — "unset", "empty", "text", "json"
# $2: stderr capture file
run_seq() {
    local mode="$1" capfile="$2"
    : > "${capfile}"

    # Construct env prefix per mode.
    # NB: bash `XDPMF_LOG_FORMAT= cmd` (= empty value) is "explicitly set
    # to empty" which is exactly the "" condition.
    local env_pfx=()
    case "${mode}" in
        unset)  env_pfx=(env -u XDPMF_LOG_FORMAT) ;;
        empty)  env_pfx=(env "XDPMF_LOG_FORMAT=") ;;
        text)   env_pfx=(env "XDPMF_LOG_FORMAT=text") ;;
        json)   env_pfx=(env "XDPMF_LOG_FORMAT=json") ;;
        *) echo "internal: bad mode '${mode}'" >&2; return 2 ;;
    esac

    setup_veth

    set +e
    # attach
    ${NSEXEC} "${env_pfx[@]}" "${LOADER_BIN}" \
        attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" \
        2>>"${capfile}" 1>/dev/null
    # apply
    ${NSEXEC} "${env_pfx[@]}" "${LOADER_BIN}" \
        apply --iface "${IFACE_A}" -f "${FIXTURE_CONFIG}" \
        2>>"${capfile}" 1>/dev/null
    # detach
    ${NSEXEC} "${env_pfx[@]}" "${LOADER_BIN}" \
        detach --iface "${IFACE_A}" \
        2>>"${capfile}" 1>/dev/null
    set -e

    cleanup_veth
}

fail=0

# ── (smoke) sub-case 1: unset XDPMF_LOG_FORMAT ──────────────────────────
echo "=== run sequence: XDPMF_LOG_FORMAT unset"
run_seq unset "${cap_unset}"
echo "--- raw stderr (unset) ---"
cat "${cap_unset}"
echo "--- end ---"
if [[ ! -s "${cap_unset}" ]]; then
    echo "FAIL[smoke]: stderr capture is empty — sequence did not produce any output (binary not running?)" >&2
    fail=1
fi
normalize < "${cap_unset}" > "${norm_unset}"

# ── sub-case 2: XDPMF_LOG_FORMAT="" (empty) ─────────────────────────────
echo "=== run sequence: XDPMF_LOG_FORMAT=\"\" (empty)"
run_seq empty "${cap_empty}"
normalize < "${cap_empty}" > "${norm_empty}"

# ── sub-case 3: XDPMF_LOG_FORMAT=text (explicit) ────────────────────────
echo "=== run sequence: XDPMF_LOG_FORMAT=text"
run_seq text "${cap_text}"
normalize < "${cap_text}" > "${norm_text}"

# ── (a) 3-way byte-equivalence across env conditions ───────────────────
echo
echo "=== (a) 3-way byte-equivalence: unset ≡ empty ≡ text"
if ! cmp -s "${norm_unset}" "${norm_empty}"; then
    echo "FAIL[a1]: stderr DIFFERS between XDPMF_LOG_FORMAT unset and =\"\" (empty)" >&2
    diff -u "${norm_unset}" "${norm_empty}" || true
    fail=1
fi
if ! cmp -s "${norm_empty}" "${norm_text}"; then
    echo "FAIL[a2]: stderr DIFFERS between XDPMF_LOG_FORMAT=\"\" and =text" >&2
    diff -u "${norm_empty}" "${norm_text}" || true
    fail=1
fi

# ── (b) byte-equivalence against committed reference fixture ───────────
echo
echo "=== (b) byte-equivalence against ${REF_FILE}"
# Normalize the reference too (cheap; mostly no-op except line endings).
normalize < "${REF_FILE}" > "${norm_ref}"
if ! cmp -s "${norm_text}" "${norm_ref}"; then
    echo "FAIL[b]: text-mode stderr DIFFERS from committed reference fixture" >&2
    echo "        This is a PI-3.5-1 violation: text mode is not byte-equivalent" >&2
    echo "        to the pre-§5.32 baseline." >&2
    echo "--- actual (normalized) ---" >&2
    cat "${norm_text}" >&2
    echo "--- expected (reference, normalized) ---" >&2
    cat "${norm_ref}" >&2
    echo "--- diff (actual vs expected) ---" >&2
    diff -u "${norm_ref}" "${norm_text}" >&2 || true
    fail=1
fi

# ── (c) NEGATION CONTROL: JSON mode must produce DIFFERENT stderr ──────
echo
echo "=== run sequence: XDPMF_LOG_FORMAT=json (negation control)"
run_seq json "${cap_json}"
echo "--- raw stderr (json mode) ---"
cat "${cap_json}"
echo "--- end ---"
normalize < "${cap_json}" > "${norm_json}"
if cmp -s "${norm_text}" "${norm_json}"; then
    echo "FAIL[c]: JSON-mode stderr is BYTE-IDENTICAL to text-mode — env var not honored" >&2
    echo "        This means the test machinery itself is broken: cannot detect drift" >&2
    fail=1
else
    echo "[c] OK: JSON mode produces distinct stderr (negation control passes)"
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_LOG_TEXT_BYTE_EQUIVALENT"
exit "${fail}"
