#!/bin/bash
# T_SIDECAR_JSON_SHAPE — design §6.50 (MVP-3.4b cycle 1 / §5.31).
#
# rule_index.json sidecar correctness per Q2 S1 (defaults-only schema)
# + Q3 P4 (sidecar lives at /run/xdpmacfilter/<iface>/rule_index.json
# per §5.31 EDIT-1 — bpffs rejects regular-file creation EPERM, hence
# the P1→P4 path correction; D-3.4b-21 supersedes D-3.4b-7) +
# D-3.4b-10 (roll-your-own writer) + D-3.4b-20 (one-rule-per-line) +
# PI-3.4b-5.
#
# Trigger:
#   1. setup_veth + apply config_per_rule_counters.yaml.
#   2. Read /run/xdpmacfilter/<iface>/rule_index.json and validate via jq.
#   3. Negation: apply malformed config; verify sidecar is NOT corrupted
#      (still describes the previously-applied valid config).
#
# Observable outcome (ALL must hold):
#   (a) File /run/xdpmacfilter/<iface>/rule_index.json exists, non-empty.
#   (b) File mode 0644 (operator + exporter readable per D-3.4b-21).
#   (c) jq -e '.iface == "<iface>"' succeeds (iface matches --iface arg).
#   (d) jq -e '.schema_version == 1' succeeds (literal 1 per Q2 S1).
#   (e) jq -e '.applied_at | test("^[0-9]{4}-...Z$")' succeeds (ISO-8601 UTC).
#   (f) jq -e '.rules | length == 4' succeeds (fixture has 4 rules).
#   (g) Per-rule shape: for each id in {0, 5, 17, 42}, the entry contains
#       rule_id == id AND action ∈ {"pass","drop"} matching the fixture.
#   (h) Match-kind: id 0/5/17 have .match.mac present (MAC rules);
#       id 42 has .match.cidr present (CIDR rule).
#   (i) Negation: applying a malformed config DOES NOT corrupt the sidecar
#       (file still parses + still describes the valid config).
#
# Sanity-floor smoke: step (a) — file exists + non-empty (cannot assert
# shape otherwise).
# Negation control: step (i) — apply malformed config; sidecar persists
# describing prior valid config (the failed apply did NOT clobber the
# good file). This catches a bug where the sidecar write happens before
# config validation or where the writer writes a partial file on error.
#
# Maps to: PI-3.4b-5, Q2 S1, Q3 P4 (§5.31 EDIT-1), D-3.4b-10, D-3.4b-20,
# D-3.4b-21 (supersedes D-3.4b-7).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for sidecar shape validation)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_per_rule_counters.yaml"
FIXTURE_BAD="${TEST_DIR}/fixtures/config_malformed_yaml.yaml"
[[ -f "${FIXTURE}" ]]     || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }
[[ -f "${FIXTURE_BAD}" ]] || { echo "FAIL: missing fixture ${FIXTURE_BAD}" >&2; exit 1; }

# §5.31 EDIT-1 (Phase B platform-constraint correction): sidecar lives at
# /run/xdpmacfilter/<iface>/rule_index.json (tmpfs under systemd convention),
# NOT under bpffs ${PIN_DIR}. bpffs rejects regular-file creation EPERM.
SIDECAR_ROOT="/run/xdpmacfilter"
SIDECAR_DIR="${SIDECAR_ROOT}/${IFACE_A}"
SIDECAR_PATH="${SIDECAR_DIR}/rule_index.json"
stderr_file=$(mktemp /tmp/xdpmf-sidecar-stderr.XXXXXX)
sidecar_local=$(mktemp /tmp/xdpmf-sidecar-body.XXXXXX)
cleanup_sidecar() {
    set +e
    sudo -n rm -rf "${SIDECAR_DIR}" 2>/dev/null
    set -e
}
trap 'cleanup_veth; cleanup_sidecar; rm -f "${stderr_file}" "${sidecar_local}"' EXIT

# Helper: read sidecar via sudo (root-owned in bpffs).
read_sidecar() {
    sudo -n cat "${SIDECAR_PATH}" 2>/dev/null
}

setup_veth

# ── (a) apply + sidecar materializes ─────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
cat "${stderr_file}" >&2 || true

fail=0
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[a1]: apply exit ${rc} (expected 0)" >&2
    fail=1
fi
if ! sudo -n test -e "${SIDECAR_PATH}"; then
    echo "FAIL[a2]: ${SIDECAR_PATH} sidecar missing after apply (PI-3.4b-5)" >&2
    exit 1
fi
sidecar_size=$(sudo -n stat -c %s "${SIDECAR_PATH}" 2>/dev/null || echo 0)
echo "sidecar size: ${sidecar_size} bytes"
if (( sidecar_size == 0 )); then
    echo "FAIL[a3]: sidecar file is empty" >&2
    fail=1
fi

read_sidecar > "${sidecar_local}"
echo "--- sidecar contents ---"
cat "${sidecar_local}"
echo "--- end sidecar ---"

# ── (b) File mode 0644 ───────────────────────────────────────────────────
mode=$(sudo -n stat -c '%a' "${SIDECAR_PATH}" 2>/dev/null || echo "")
echo "sidecar mode: ${mode}"
if [[ "${mode}" != "644" ]]; then
    echo "FAIL[b]: sidecar mode '${mode}' (expected 644 per D-3.4b-21)" >&2
    fail=1
fi

# ── (c) .iface == IFACE_A ────────────────────────────────────────────────
if ! jq -e --arg iface "${IFACE_A}" '.iface == $iface' "${sidecar_local}" >/dev/null 2>&1; then
    echo "FAIL[c]: .iface != '${IFACE_A}'" >&2
    sudo -n jq '.iface' "${SIDECAR_PATH}" >&2 || true
    fail=1
fi

# ── (d) .schema_version == 2 (§5.43 C1 / PI-mvp-4.3-SIDECAR) ─────────────
if ! jq -e '.schema_version == 2' "${sidecar_local}" >/dev/null 2>&1; then
    echo "FAIL[d]: .schema_version != 2 (M.1 cutover; sidecar must emit 2)" >&2
    fail=1
fi

# ── (e) .applied_at is ISO-8601 UTC ──────────────────────────────────────
# Pattern: YYYY-MM-DDTHH:MM:SSZ
if ! jq -e '.applied_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")' "${sidecar_local}" >/dev/null 2>&1; then
    echo "FAIL[e]: .applied_at not ISO-8601 UTC format (YYYY-MM-DDTHH:MM:SSZ)" >&2
    sudo -n jq '.applied_at' "${SIDECAR_PATH}" >&2 || true
    fail=1
fi

# ── (f) rules array length == 4 ──────────────────────────────────────────
n_rules=$(jq '.rules | length' "${sidecar_local}" 2>/dev/null || echo 0)
echo "rules array length: ${n_rules}"
if [[ "${n_rules}" != "4" ]]; then
    echo "FAIL[f]: .rules length=${n_rules} (expected 4 from fixture)" >&2
    fail=1
fi

# ── (g) Per-rule rule_id + action ────────────────────────────────────────
# Expected (matching fixture):
#   id=0  action=pass
#   id=5  action=pass
#   id=17 action=drop
#   id=42 action=pass
declare -A EXPECTED_ACTIONS=(
    [0]="pass"
    [5]="pass"
    [17]="drop"
    [42]="pass"
)
for id in 0 5 17 42; do
    exp_action="${EXPECTED_ACTIONS[$id]}"
    got_action=$(jq -r --argjson id "${id}" '.rules[] | select(.rule_id == $id) | .action' "${sidecar_local}" 2>/dev/null | head -n1)
    echo "  rule_id=${id}: action='${got_action}' (expected '${exp_action}')"
    if [[ "${got_action}" != "${exp_action}" ]]; then
        echo "FAIL[g.${id}]: rule_id=${id} action='${got_action}' (expected '${exp_action}')" >&2
        fail=1
    fi
done

# ── (h) match-kind per rule (§5.43: MAC deferred → all rules src_cidr) ────
# Per converted fixture: ids 0/5/17/42 are all src_cidr (MAC deferred to
# mvp-4.5 per PI-mvp-4.3-MAC-DEFERRED; sidecar emits the explicit src_cidr/
# dst_cidr match-kinds per PI-mvp-4.3-SIDECAR).
for id in 0 5 17 42; do
    has_src_cidr=$(jq --argjson id "${id}" '[.rules[] | select(.rule_id == $id) | .match | has("src_cidr")] | first // false' "${sidecar_local}" 2>/dev/null)
    if [[ "${has_src_cidr}" != "true" ]]; then
        echo "FAIL[h.src_cidr.${id}]: rule_id=${id} sidecar match missing 'src_cidr' key" >&2
        sudo -n jq --argjson id "${id}" '.rules[] | select(.rule_id == $id)' "${SIDECAR_PATH}" >&2 || true
        fail=1
    fi
done

# ── (i) NEGATION CONTROL: apply malformed → sidecar UNCHANGED ───────────
echo
echo "=== step (i): NEGATION — apply malformed config; sidecar must NOT be corrupted"
# Capture pre-state checksum.
pre_sum=$(sudo -n md5sum "${SIDECAR_PATH}" 2>/dev/null | awk '{print $1}')
echo "pre-malformed sidecar md5: ${pre_sum}"

: >"${stderr_file}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE_BAD}" 2>"${stderr_file}"
rc_bad=$?
set -e
echo "rc_bad=${rc_bad}"
cat "${stderr_file}" >&2 || true

# Malformed apply MUST exit non-zero (ConfigError = 9 per §6.22 baseline).
if [[ "${rc_bad}" == "0" ]]; then
    echo "FAIL[i1]: malformed apply exited 0 (expected non-zero)" >&2
    fail=1
fi

# Sidecar must STILL exist + STILL be valid JSON + STILL describe the
# prior good config (md5 unchanged).
if ! sudo -n test -e "${SIDECAR_PATH}"; then
    echo "FAIL[i2]: sidecar disappeared after malformed apply" >&2
    fail=1
else
    post_sum=$(sudo -n md5sum "${SIDECAR_PATH}" 2>/dev/null | awk '{print $1}')
    echo "post-malformed sidecar md5: ${post_sum}"
    if [[ "${pre_sum}" != "${post_sum}" ]]; then
        echo "FAIL[i3]: sidecar md5 changed after failed apply" >&2
        echo "         a failed apply must NOT clobber the prior good sidecar" >&2
        fail=1
    fi
    # Still valid JSON?
    if ! sudo -n jq -e '.schema_version == 2' "${SIDECAR_PATH}" >/dev/null 2>&1; then
        echo "FAIL[i4]: sidecar no longer parses as expected after failed apply" >&2
        fail=1
    fi
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_SIDECAR_JSON_SHAPE"
exit "${fail}"
