#!/bin/bash
# T_APPLY_EXITS_1_ON_MISSING_CONFIG — design §6.43 (MVP-3.4.5 / §5.30 HK-1).
#
# HK-1 exit-code triple drift fix:
#   `xdpfilter apply -f /nonexistent/path --iface lo` MUST exit with
#   kExitUsageErr (= 1, per §4.1). Stderr MUST still carry the existing
#   `xdpfilter: config error:` prefix (the §5.26 stderr-discipline is
#   preserved — HK-1 only fixes the exit code, not the message format).
#   The loader MUST exit BEFORE touching the kernel (no `bpf_prog_load`,
#   no orphan pin dir).
#
# Sanity-floor smoke: loader binary runs + prints SOMETHING on stderr.
# Negation control: re-run with a VALID minimal config (existing fixture
# config_valid.yaml) — assert rc != 1, proving the test doesn't false-pass
# on every apply invocation.
#
# This test uses `--iface lo` so it does NOT need veth setup and does NOT
# take RESOURCE_LOCK xdp_fixture. Per design §5.30 §6.43, the failure
# happens BEFORE iface resolution (config_open() throws first) — `lo`
# would only be used had we reached that point.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)
echo "loader=${LOADER_BIN}"

stderr_file=$(mktemp /tmp/xdpmf-apply-missing-stderr.XXXXXX)
stderr_neg_file=$(mktemp /tmp/xdpmf-apply-missing-neg-stderr.XXXXXX)
trap 'rm -f "${stderr_file}" "${stderr_neg_file}"' EXIT

fail=0

# A path that ENOENT-guarantees: /nonexistent + a timestamped suffix so
# a parallel run can never create a real file there between our check
# and the loader's open(). Defensive.
MISSING_CFG="/nonexistent/xdpmf-test-missing-cfg-$$-$(date +%s).yaml"
[[ ! -e "${MISSING_CFG}" ]] || { echo "FAIL: chosen MISSING_CFG path ${MISSING_CFG} unexpectedly exists" >&2; exit 1; }

# ── PRIMARY: missing config → exit 1 + stderr prefix preserved ──────────
echo "=== PRIMARY: apply -f ${MISSING_CFG} --iface lo (expect rc=1)"
set +e
"${LOADER_BIN}" apply -f "${MISSING_CFG}" --iface lo 2> "${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
echo "--- stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

# (a) Exit code EXACTLY 1 (kExitUsageErr per §4.1 + HK-1 fix).
if [[ "${rc}" -ne 1 ]]; then
    echo "FAIL[a]: expected rc=1 (kExitUsageErr per §4.1, HK-1 fix), got rc=${rc}" >&2
    case "${rc}" in
        0) echo "         rc=0 means missing-file was IGNORED — apply silently succeeded against a phantom config" >&2 ;;
        9) echo "         rc=9 is the pre-HK-1 behavior (ConfigError). HK-1 explicitly relocates this to exit 1." >&2 ;;
        3) echo "         rc=3 (AttachFailed) means open() was attempted AFTER attach — wrong order" >&2 ;;
        *) echo "         rc=${rc} — unexpected exit code; consult §4.1 table" >&2 ;;
    esac
    fail=1
fi

# (b) Stderr STILL carries the existing 'xdpfilter: config error:' prefix.
#     Per HK-1 Interfaces (§5.30 D-3.4.5-5): the message format is preserved
#     verbatim; ONLY the exit code is relocated (9 → 1).
if ! grep -qE -- '^xdpfilter: config error:' "${stderr_file}"; then
    echo "FAIL[b]: stderr does not start with 'xdpfilter: config error:' (HK-1 preserves §5.26 message)" >&2
    fail=1
fi

# ── NEGATION CONTROL: valid config → rc != 1 (would normally rc=0 or
# something else specific to lo, but explicitly NOT 1) ───────────────────
# This proves the test's exit-1 assertion is real-vs-spec, not "all apply
# invocations exit 1". If impl ever broke apply by returning 1 universally,
# this branch would catch it.
echo
echo "=== NEGATION CONTROL: apply -f ${TEST_DIR}/fixtures/config_valid.yaml --iface lo (expect rc != 1)"
VALID_CFG="${TEST_DIR}/fixtures/config_valid.yaml"
if [[ ! -f "${VALID_CFG}" ]]; then
    echo "FAIL: negation control prerequisite — ${VALID_CFG} missing (existing fixture)" >&2
    fail=1
else
    set +e
    # `lo` may or may not accept XDP on this kernel — but EITHER way the
    # loader must NOT return rc=1 (CliError). On success rc=0; on attach
    # failure rc=3 (AttachFailed); rc=1 would mean CliError on a known-good
    # arg-shape, which is precisely what we're checking can't happen.
    "${LOADER_BIN}" apply -f "${VALID_CFG}" --iface lo 2> "${stderr_neg_file}"
    rc_neg=$?
    set -e
    echo "negation rc=${rc_neg}"
    echo "--- negation stderr ---"
    cat "${stderr_neg_file}" >&2 || true
    echo "--- end ---"

    # Cleanup any XDP that the valid-apply may have attached to lo.
    sudo -n "${LOADER_BIN}" detach --iface lo 2>/dev/null || true

    if [[ "${rc_neg}" -eq 1 ]]; then
        echo "FAIL[neg]: negation control got rc=1 on VALID config — apply now exits 1 universally" >&2
        echo "           the primary assertion's exit-1 signal is therefore not specific to missing-file" >&2
        fail=1
    fi
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_APPLY_EXITS_1_ON_MISSING_CONFIG"
exit "${fail}"
