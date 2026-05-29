#!/bin/bash
# T_SCHEMA_V2_CUTOVER — design §6.63 (MVP-4.3 / §5.43).
#
# OPS canary for the M.1 hard cutover: the load-time config grammar changes
# materially. supported schema_version set {1} -> {2}.
#
#   (a) schema_version: 1            -> exit 9 + re-author diagnostic
#   (b) absent schema_version        -> exit 9 (default-to-1 path is gone)
#   (c) schema_version: 2 + match.mac -> exit 9 + MAC-deferred diagnostic
#                                        (HG-mvp-4.3-2 / PI-mvp-4.3-MAC-DEFERRED)
#   (d) valid schema_version: 2      -> exit 0
#
# (c) is the load-bearing distinction: the schema_version IS valid (2), so
# the rejection must come from the match-GRAMMAR gate (mac deferred), NOT
# the schema-version gate. Asserting the MAC-specific diagnostic proves the
# config reached the grammar gate rather than tripping the schema gate.
#
# Sanity-floor smoke: (d) — a valid v2 config applies cleanly (exit 0).
# Negation control: (a)/(b)/(c) — known-bad grammars MUST hard-reject
# (exit 9). Together they bracket the accept/reject grammar surface; a
# loader that still accepts v1/absent (no cutover) FAILS (a)/(b).
#
# Maps to: PI-mvp-4.3-SCHEMA-V2, PI-mvp-4.3-DSTCIDR, PI-mvp-4.3-MAC-DEFERRED.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIX_DIR="${TEST_DIR}/fixtures"
FIX_V1="${FIX_DIR}/config_schema_v1.yaml"
FIX_ABSENT="${FIX_DIR}/config_schema_absent.yaml"
FIX_MAC="${FIX_DIR}/config_v2_mac.yaml"
FIX_VALID="${FIX_DIR}/config_valid_and.yaml"

for f in "${FIX_V1}" "${FIX_ABSENT}" "${FIX_MAC}" "${FIX_VALID}"; do
    [[ -f "${f}" ]] || { echo "FAIL: missing fixture ${f}" >&2; exit 1; }
done

stderr_file=$(mktemp /tmp/xdpmf-schemav2-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

fail=0

# ── reject sub-cases: exit 9 + 'config error:' prefix + axis-specific grep ─
# require_substr_regex: an ERE that MUST match the stderr (spec-anchored).
run_reject() {
    local label="$1" fixture="$2" require_substr_regex="$3" forbid_attach="yes"
    : >"${stderr_file}"
    echo
    echo "=== ${label}: ${fixture} (expect exit 9)"
    set +e
    ${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${fixture}" 2>"${stderr_file}"
    local rc=$?
    set -e
    echo "  rc=${rc}"
    echo "  --- stderr ---"; cat "${stderr_file}" >&2 || true; echo "  --- end ---"

    if [[ "${rc}" -ne 9 ]]; then
        echo "  FAIL[${label}.rc]: expected rc=9 (ConfigError), got ${rc}" >&2
        [[ "${rc}" == 0 ]] && echo "         rc=0 means the cutover did NOT reject — grammar gate missing" >&2
        fail=1
    fi
    if ! grep -qE -- 'xdpmacfilter: config error:' "${stderr_file}"; then
        echo "  FAIL[${label}.prefix]: stderr missing 'xdpmacfilter: config error:'" >&2
        fail=1
    fi
    if ! grep -qiE -- "${require_substr_regex}" "${stderr_file}"; then
        echo "  FAIL[${label}.diag]: stderr missing expected diagnostic /${require_substr_regex}/i" >&2
        fail=1
    fi
    # No XDP attached after a rejected apply.
    if [[ "${forbid_attach}" == "yes" && -n "$(xdp_prog_id "${IFACE_A}")" ]]; then
        echo "  FAIL[${label}.attach]: XDP attached after a rejected config" >&2
        fail=1
    fi
}

# (a) explicit v1 → reject, diagnostic mentions schema_version (+ re-author to 2).
run_reject "(a) v1"      "${FIX_V1}"     'schema_version'
# (b) absent → reject (the default-1 path is gone), diagnostic mentions schema_version.
run_reject "(b) absent"  "${FIX_ABSENT}" 'schema_version'
# (c) v2 + mac → reject at the GRAMMAR gate; diagnostic is MAC-specific, NOT
#     a bare schema-version complaint. Spec quote: "MAC matching deferred;
#     schema_version 2 supports dst_cidr + src_cidr".
run_reject "(c) v2+mac"  "${FIX_MAC}"    'mac'
# Extra (c): the MAC reject must be distinguishable from the schema reject.
if grep -qiE -- 'mac' "${stderr_file}" && grep -qiE -- 'defer|dst_cidr|src_cidr|mvp-4\.5' "${stderr_file}"; then
    echo "  (c) MAC-deferred diagnostic distinguishable from schema reject: OK"
else
    echo "  FAIL[(c).deferred]: v2+mac stderr does not carry a MAC-deferred diagnostic" >&2
    echo "          (must reach the match-grammar gate, not the schema-version gate)" >&2
    fail=1
fi

# ── (d) valid v2 → exit 0 + attach ───────────────────────────────────────
: >"${stderr_file}"
echo
echo "=== (d) valid v2: ${FIX_VALID} (expect exit 0)"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIX_VALID}" 2>"${stderr_file}"
rc=$?
set -e
echo "  rc=${rc}"
cat "${stderr_file}" >&2 || true
if [[ "${rc}" -ne 0 ]]; then
    echo "  FAIL[(d).rc]: valid schema_version: 2 config rejected (rc=${rc}, expected 0)" >&2
    fail=1
fi
if ! sudo -n test -e "${PIN_DIR}/active_idx"; then
    echo "  FAIL[(d).pin]: ${PIN_DIR}/active_idx missing after valid apply" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_SCHEMA_V2_CUTOVER"
exit "${fail}"
