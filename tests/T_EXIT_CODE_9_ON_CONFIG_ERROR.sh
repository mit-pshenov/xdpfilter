#!/bin/bash
# T_EXIT_CODE_9_ON_CONFIG_ERROR — design §6.27 (MVP-3.1 / §5.26).
#
# Bare-bones exit-code-9 audit-grep. Smoke-tests the wiring from
# main() → loader_error_category() → ConfigError exit 9 with ZERO fixture
# dependencies (no veth, no root needed, no alien fixture, no apply-file).
#
# Trigger: bad XDPMF_TRUST_MODEL=garbage invocation. Per §5.26 attach()
# flow update step 2, env parse happens BEFORE ifindex resolution, so:
#   - any iface arg is fine (rejected before resolved)
#   - no root needed (parse is pure userspace)
#   - no veth needed
#
# Observable outcome (per §6.27):
#   - exit code EXACTLY 9
#   - stderr starts with 'xdpfilter: config error:'
#   - stderr contains 'unknown trust model' (specific message)
#   - No XDP touched, no bpffs dir created (not asserted here — pure
#     binary-invocation test; the §6.26 sub-case 4 covers that with veth.)
#
# Ops-script writers grep for "exit 9" — this test is the canonical
# reference. If §6.26 fails for fixture-infrastructure reasons, §6.27
# still proves the exit-code path.
#
# §5.75 (MVP-4.35 / B42) EXTENSION — the two NEGATIVE redirect-config
# validation paths from the §5.75.6 TestStrategy (config validation):
#   (e) schema_version:3 config with `action: redirect` but NO `steering:`
#       block → exit 9 (cross-validation: a redirect rule REQUIRES a
#       steering.redirect_to). This is the soundness precondition the
#       datapath leans on — no steering ⇒ no redirect rule ⇒ devmap unused.
#       A silent regression would let a redirect rule reach the datapath
#       with an empty devmap → PASS-on-miss → DPI feed silently dark.
#   (f) a `steering:` block carrying an UNKNOWN sub-key (e.g. `target_id:`)
#       → exit 9 (forward-compat fence; per-rule targets are Option-2 OOS).
# Both are pure validate() path (config parse happens before iface
# resolution / any BPF work, per §5.26 apply flow) → NO root / netns / BPF
# needed; they ride this binary-invocation test, not the veth corpus.
#
# Sanity-floor smoke: loader binary exists and runs. Negation control:
# this test asserts a non-zero exit code (specifically 9) — the opposite
# of T_CLI_HELP_VERSION's "exit 0" path. Together they bracket the
# success/failure exit-code surface. The §5.75 sub-cases each pin a
# DISTINCT redirect-config defect to the SAME exit 9, anchored on a
# steering/redirect reason-substring so an exit-9 for an unrelated schema
# defect cannot pass vacuously.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)
stderr_file=$(mktemp /tmp/xdpmf-exit9-stderr.XXXXXX)
cfg_noredir=$(mktemp /tmp/xdpmf-exit9-noredir.XXXXXX.yaml)
cfg_badsteer=$(mktemp /tmp/xdpmf-exit9-badsteer.XXXXXX.yaml)
trap 'rm -f "${stderr_file}" "${cfg_noredir}" "${cfg_badsteer}"' EXIT

fail=0

echo "=== invoke loader with XDPMF_TRUST_MODEL=garbage_value"
set +e
XDPMF_TRUST_MODEL=garbage_value \
    "${LOADER_BIN}" attach --iface lo --allow 02:00:00:00:00:01 2> "${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
echo "--- stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

# (a) Exit code EXACTLY 9.
if [[ "${rc}" -ne 9 ]]; then
    echo "FAIL[a]: expected rc=9 (LoaderError::ConfigError per §4.1), got ${rc}" >&2
    case "${rc}" in
        0) echo "         rc=0 means the garbage trust_model was IGNORED — env parse not wired" >&2 ;;
        1) echo "         rc=1 means CLI usage error — wrong axis; this is a config error" >&2 ;;
        3) echo "         rc=3 means AttachFailed (e.g., 'lo' resolved) — env parse happened TOO LATE" >&2 ;;
    esac
    fail=1
fi

# (b) Stderr STARTS with the expected prefix. The §5.26 stderr-discipline
#     guarantees a single-line 'xdpfilter: config error:' opener.
if ! grep -qE -- '^xdpfilter: config error:' "${stderr_file}"; then
    echo "FAIL[b]: stderr does not start with 'xdpfilter: config error:'" >&2
    fail=1
fi

# (c) Stderr contains the specific message naming the failure.
if ! grep -qE -- 'unknown trust model' "${stderr_file}"; then
    echo "FAIL[c]: stderr missing 'unknown trust model' substring" >&2
    fail=1
fi

# (d) Stderr names the rejected value (for operator debuggability).
if ! grep -q -F -- 'garbage_value' "${stderr_file}"; then
    echo "FAIL[d]: stderr does not echo the rejected value 'garbage_value'" >&2
    fail=1
fi

# ── §5.75 redirect-config validation sub-cases (apply -f, pure validate) ──
# Runs the loader DIRECTLY (no NSEXEC/sudo): config parse + cross-validation
# happen in userspace before iface resolution, so exit 9 is reached without
# root. `lo` always exists; we never reach attach because validation throws
# first. No `interface:` key in the configs (avoids the §6.22 mismatch axis).
run_redirect_cfg_subcase() {
    local label="$1" cfg="$2"
    local sc_fail=0
    echo
    echo "=== sub-case ${label}: apply -f ${cfg}"
    : >"${stderr_file}"
    set +e
    "${LOADER_BIN}" apply --iface lo -f "${cfg}" 2>"${stderr_file}"
    local rc=$?
    set -e
    echo "  rc=${rc}"
    echo "  --- stderr ---"; cat "${stderr_file}" >&2 || true; echo "  --- end stderr ---"

    # (1) Exit code EXACTLY 9 (LoaderError::ConfigError).
    if [[ "${rc}" -ne 9 ]]; then
        echo "  FAIL[${label}.1]: expected rc=9 (ConfigError), got ${rc}" >&2
        case "${rc}" in
            0) echo "         rc=0 means the malformed redirect config was ACCEPTED — a redirect" >&2
               echo "         rule could reach the datapath with an unconfigured devmap (DPI dark)." >&2 ;;
            3) echo "         rc=3 means it reached attach on 'lo' — validation ran TOO LATE" >&2 ;;
        esac
        sc_fail=1
    fi
    # (2) stderr carries the canonical config-error prefix.
    if ! grep -qE -- '^xdpfilter: config error:' "${stderr_file}"; then
        echo "  FAIL[${label}.2]: stderr missing 'xdpfilter: config error:' prefix" >&2
        sc_fail=1
    fi
    # (3) Reason-anchor: the failure is about steering/redirect, NOT some
    #     incidental schema defect (guards against a vacuous exit-9 pass).
    if ! grep -qiE -- 'steering|redirect' "${stderr_file}"; then
        echo "  FAIL[${label}.3]: stderr does not name the steering/redirect reason" >&2
        sc_fail=1
    fi
    # NB: a trailing `[[ … ]] && fail=1` would return non-zero when sc_fail==0
    # and trip `set -e` (aborting before the next sub-case) — use an explicit
    # if + return 0, matching the run_subcase idiom in T_APPLY_REJECTS_MALFORMED.
    if [[ "${sc_fail}" -ne 0 ]]; then fail=1; fi
    return 0
}

# (e) redirect rule with NO steering block → cross-validation exit 9.
cat > "${cfg_noredir}" <<'EOF'
schema_version: 3
default_action: drop
rules:
  - id: 0
    action: redirect
    match:
      mac: "02:00:00:00:00:01"
EOF
run_redirect_cfg_subcase e "${cfg_noredir}"

# (f) steering block with an UNKNOWN sub-key (target_id) → fence exit 9.
#     redirect_to is present + valid so the ONLY defect is the unknown key.
cat > "${cfg_badsteer}" <<'EOF'
schema_version: 3
default_action: drop
steering:
  redirect_to: dummy0
  target_id: 7
rules:
  - id: 0
    action: redirect
    match:
      mac: "02:00:00:00:00:01"
EOF
run_redirect_cfg_subcase f "${cfg_badsteer}"

[[ "${fail}" == 0 ]] && echo "PASS: T_EXIT_CODE_9_ON_CONFIG_ERROR"
exit "${fail}"
