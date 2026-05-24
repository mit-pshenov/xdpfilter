#!/bin/bash
# T_APPLY_REJECTS_MALFORMED — design §6.22 (MVP-3.1 / §5.26).
#
# 5 sub-cases, all should exit 9 (LoaderError::ConfigError) with
# recognizable stderr:
#   1. config_malformed_yaml.yaml          (flow-form top-level rejected by parser)
#   2. config_malformed_schema.yaml        (default_action: maybe — schema rejection)
#   3. config_malformed_dup_id.yaml        (two rules same id — schema rejection)
#   4. config_malformed_iface_mismatch.yaml (file `interface:` != --iface — orchestrator rejection)
#   5. config_malformed_unsupported_match.yaml (flow-form + unsupported match — either rejection path)
#
# Common assertions per sub-case (per §6.22 Observable outcome):
#   - rc == 9 (LoaderError::ConfigError; exit-code-9 audit-grep target)
#   - stderr contains 'xdpmacfilter: config error:' prefix
#   - For sub-cases 1, 2, 3, 5: stderr contains the fixture path AND a
#     <line>:<col> position (line:col regex)
#   - For sub-case 4: stderr contains BOTH the file's declared interface
#     name AND the runtime --iface arg value (case-sensitive substrings)
#   - No XDP attached afterwards (xdp_prog_id returns empty)
#   - No bpffs per-iface dir created (PIN_DIR absent)
#
# Sanity-floor smoke: each sub-case's loader invocation actually runs.
# Negation control: §6.21 T_APPLY_VALID_CONFIG is the symmetric "valid →
# exit 0"; this test is the "invalid → exit 9" half of the pair. The
# differential is the negation control across the two tests.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE_DIR="${TEST_DIR}/fixtures"

stderr_file=$(mktemp /tmp/xdpmf-applymalformed-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT

# Sub-case fixture paths.
FIX_1="${FIXTURE_DIR}/config_malformed_yaml.yaml"
FIX_2="${FIXTURE_DIR}/config_malformed_schema.yaml"
FIX_3="${FIXTURE_DIR}/config_malformed_dup_id.yaml"
FIX_4="${FIXTURE_DIR}/config_malformed_iface_mismatch.yaml"
FIX_5="${FIXTURE_DIR}/config_malformed_unsupported_match.yaml"

for f in "${FIX_1}" "${FIX_2}" "${FIX_3}" "${FIX_4}" "${FIX_5}"; do
    [[ -f "${f}" ]] || { echo "FAIL: missing fixture ${f}" >&2; exit 1; }
done

# Hardcoded mismatch-iface name baked into FIX_4 (must NOT equal IFACE_A).
DECLARED_IFACE_IN_FIX_4="notthisiface"

setup_veth

fail=0
run_subcase() {
    local label="$1" fixture="$2"
    local require_path_linecol="$3"  # "yes" or "no"
    local sc_fail=0

    echo
    echo "=== sub-case ${label}: ${fixture}"
    : >"${stderr_file}"

    # Pre-condition: no XDP, no pin dir.
    if [[ -n "$(xdp_prog_id "${IFACE_A}")" ]]; then
        echo "  precondition FAIL: XDP already attached before sub-case" >&2
        sc_fail=1
    fi
    if sudo -n test -e "${PIN_DIR}"; then
        echo "  precondition FAIL: ${PIN_DIR} exists before sub-case" >&2
        sc_fail=1
    fi

    set +e
    ${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${fixture}" 2> "${stderr_file}"
    local rc=$?
    set -e
    echo "  rc=${rc}"
    echo "  --- stderr ---"
    cat "${stderr_file}" >&2 || true
    echo "  --- end stderr ---"

    # (a) Exit code EXACTLY 9.
    if [[ "${rc}" -ne 9 ]]; then
        echo "  FAIL[${label}.a]: expected rc=9 (ConfigError), got ${rc}" >&2
        sc_fail=1
    fi

    # (b) stderr matches 'xdpmacfilter: config error:'.
    if ! grep -qE -- 'xdpmacfilter: config error:' "${stderr_file}"; then
        echo "  FAIL[${label}.b]: stderr missing 'xdpmacfilter: config error:' prefix" >&2
        sc_fail=1
    fi

    if [[ "${require_path_linecol}" == "yes" ]]; then
        # (c1) stderr contains the fixture path (substring; allow basename-only).
        local basename
        basename=$(basename "${fixture}")
        if ! grep -q -F -- "${basename}" "${stderr_file}"; then
            echo "  FAIL[${label}.c1]: stderr does not name fixture path (basename: ${basename})" >&2
            sc_fail=1
        fi
        # (c2) stderr contains a <line>:<col> position (1-based decimal:decimal).
        if ! grep -qE -- '[0-9]+:[0-9]+' "${stderr_file}"; then
            echo "  FAIL[${label}.c2]: stderr missing <line>:<col> position" >&2
            sc_fail=1
        fi
    else
        # Sub-case 4: stderr contains BOTH the declared iface AND the --iface value.
        if ! grep -q -F -- "${DECLARED_IFACE_IN_FIX_4}" "${stderr_file}"; then
            echo "  FAIL[${label}.c1]: stderr does not name declared interface '${DECLARED_IFACE_IN_FIX_4}'" >&2
            sc_fail=1
        fi
        if ! grep -q -F -- "${IFACE_A}" "${stderr_file}"; then
            echo "  FAIL[${label}.c2]: stderr does not name --iface value '${IFACE_A}'" >&2
            sc_fail=1
        fi
    fi

    # (d) No XDP attached afterwards.
    local prog
    prog=$(xdp_prog_id "${IFACE_A}")
    if [[ -n "${prog}" ]]; then
        echo "  FAIL[${label}.d]: XDP attached after rejection (prog_id=${prog})" >&2
        sc_fail=1
    fi

    # (e) No bpffs per-iface dir.
    if sudo -n test -e "${PIN_DIR}"; then
        echo "  FAIL[${label}.e]: orphan ${PIN_DIR} after rejection" >&2
        sudo -n ls -la "${PIN_DIR}" >&2 || true
        sc_fail=1
    fi

    if [[ "${sc_fail}" -ne 0 ]]; then
        fail=1
    fi
}

run_subcase 1 "${FIX_1}" yes
run_subcase 2 "${FIX_2}" yes
run_subcase 3 "${FIX_3}" yes
run_subcase 4 "${FIX_4}" no
run_subcase 5 "${FIX_5}" yes

[[ "${fail}" == 0 ]] && echo "PASS: T_APPLY_REJECTS_MALFORMED"
exit "${fail}"
