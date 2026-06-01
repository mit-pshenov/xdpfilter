#!/bin/bash
# T_IFACE_SHAPE_REJECT_APPLY_DETACH — design §6.77 (MVP-4.22 / §5.62, R-1 / SEC-H1).
#
# OPS canary for the NEW apply/detach iface shape-fence. §5.62 R-1 retrofits
# `validate_iface_name(..., LoaderError::PathRefused)` as the FIRST statement of
# BOTH `apply_request` and `detach` (it already guarded `reset_counters_request`
# per §5.36). A shape-invalid iface name (disallowed char / path-traversal token
# / whitespace) MUST now be refused at BOTH entry points with:
#   - exit code 8 (LoaderError::PathRefused, per HG-mvp-4.22-1)
#   - stderr containing the literal substring 'refusing to operate' (§5.22/§5.36
#     phrasing precedent — same token validate_iface_name throws today).
#
# The rejection fires BEFORE any bpffs / iface mutation (validate is the first
# statement, ahead of compute_id_to_slot for apply and ahead of
# kernel_version_probe for detach) → this is a PRE-privileged-op refusal:
# NO veth, NO root, NO bpffs pin is created. Hence NO RESOURCE_LOCK (guard #12
# N/A) and NO require_passwordless_sudo (pure userspace CLI test, like
# T_EXIT_CODE_9_ON_CONFIG_ERROR / T_CLI_BAD_MAC).
#
# Sub-cases:
#   (a) apply -f <valid-config> --iface '../foo'   → exit 8 + 'refusing to operate'
#   (b) apply -f <valid-config> --iface 'eth0;x'   → exit 8 + 'refusing to operate'
#   (c) detach --iface 'a/b'                        → exit 8 + 'refusing to operate'
#   (d) detach --iface 'bad name with spaces'      → exit 8 + 'refusing to operate'
#   (e) NEGATION / PARITY CONTROL: detach --iface <valid-but-nonexistent name>
#       → does NOT trip the shape gate (rc != 8 AND stderr lacks 'refusing to
#       operate'); it proceeds to the normal path and fails LATER for an
#       unrelated reason (resolve_ifindex on a nonexistent iface).
#
# OPS-canary rationale (§5.62 TestStrategy #1): the existing suite drives
# apply/detach ONLY with VALID iface names (inheriting the runner's env). NO
# existing test exercises the stripped-down "shape-invalid name reaches the new
# first-statement gate" path on BOTH apply and detach — this canary catches the
# class where the retrofit is wired to only ONE entry point (e.g. apply gated
# but detach left open, or vice-versa).
#
# Sanity-floor smoke: every loader invocation actually launches + exits.
# Negation control: sub-case (e) — a VALID iface name MUST NOT be refused by the
# shape gate. A passing (a)-(d) WITHOUT (e) would mean validate_iface_name is
# over-broad (rejects everything) — i.e. the gate is theatre. (e) proves the gate
# discriminates shape-invalid from shape-valid.
#
# Failure-mode signaling (per §5.62 R-1 design):
#   - any of (a)-(d) yields exit 0 → shape gate NOT wired at that entry point
#     (SEC-H1 still open on that path).
#   - any of (a)-(d) yields a non-8 non-0 exit → rejection fires but with the
#     wrong code (HG-mvp-4.22-1 PathRefused=8 not honored).
#   - (e) yields exit 8 OR 'refusing to operate' → shape gate over-rejects a
#     VALID name (false positive — the retrofit is too aggressive).
# All are [INVARIANT-VIOLATED] per §6.5 PI (R-1 shape-fence uniformity).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

stderr_file=$(mktemp /tmp/xdpmf-ifaceshape-stderr.XXXXXX)
trap 'rm -f "${stderr_file}"' EXIT INT TERM HUP

fail=0

# A VALID but (vanishingly-likely-to-exist) iface name for the negation case.
# Valid chars [A-Za-z0-9._-], <= IFNAMSIZ-1 (15) bytes, no '/', no '..', no
# whitespace → passes the shape gate. PID-derived so it does not collide with a
# real host iface. We deliberately do NOT use a real iface (e.g. `lo`) so the
# test never touches host XDP state → stays lock-free + root-free.
VALID_NONEXISTENT="xmfno$(( $$ % 100000 ))"

# ─────────────────────────────────────────────────────────────────────────
# assert_shape_refused <label> <expect_refuse:yes|no> <argv...>
#   Runs the loader with the given argv (capturing stderr + rc) and asserts
#   the shape-gate signature (exit 8 + 'refusing to operate') is present
#   (expect_refuse=yes) or absent (expect_refuse=no).
# ─────────────────────────────────────────────────────────────────────────
assert_shape_refused() {
    local label="$1" expect="$2"; shift 2
    : >"${stderr_file}"
    echo
    echo "=== sub-case ${label}: ${LOADER_BIN} $*"
    set +e
    "${LOADER_BIN}" "$@" 2>"${stderr_file}"
    local rc=$?
    set -e
    echo "rc=${rc}"
    echo "--- stderr (${label}) ---"
    cat "${stderr_file}" >&2 || true
    echo "--- end stderr (${label}) ---"

    local has_token=0
    if grep -q -F -- 'refusing to operate' "${stderr_file}"; then
        has_token=1
    fi

    if [[ "${expect}" == "yes" ]]; then
        # (1) exit 8 — PathRefused per HG-mvp-4.22-1.
        if [[ "${rc}" -ne 8 ]]; then
            echo "FAIL[${label}.rc]: expected rc=8 (PathRefused), got rc=${rc}" >&2
            case "${rc}" in
                0) echo "          rc=0 means the shape gate is NOT wired at this entry point — SEC-H1 still OPEN" >&2 ;;
                *) echo "          rc=${rc} means a refusal fired but with the WRONG code (HG-mvp-4.22-1 PathRefused=8 not honored)" >&2 ;;
            esac
            fail=1
        fi
        # (2) stderr literal 'refusing to operate'.
        if [[ "${has_token}" -ne 1 ]]; then
            echo "FAIL[${label}.token]: stderr does not contain literal 'refusing to operate'" >&2
            fail=1
        fi
    else
        # NEGATION: a VALID name must NOT trip the shape gate.
        if [[ "${rc}" -eq 8 ]]; then
            echo "FAIL[${label}.rc]: VALID iface refused with rc=8 — shape gate over-rejects (false positive)" >&2
            fail=1
        fi
        if [[ "${has_token}" -eq 1 ]]; then
            echo "FAIL[${label}.token]: VALID iface produced 'refusing to operate' — shape gate fires on a good name" >&2
            fail=1
        fi
    fi
}

# (a)+(b) — apply entry point with shape-invalid iface.
# config_valid.yaml declares NO `interface:` key, so there is no iface-mismatch
# check to short-circuit; the --iface arg flows straight to apply_request's
# first-statement validate.
assert_shape_refused a yes apply -f "${FIXTURE}" --iface '../foo'
assert_shape_refused b yes apply -f "${FIXTURE}" --iface 'eth0;x'

# (c)+(d) — detach entry point with shape-invalid iface.
assert_shape_refused c yes detach --iface 'a/b'
assert_shape_refused d yes detach --iface 'bad name with spaces'

# (e) — NEGATION / PARITY: a VALID iface name passes the shape gate.
assert_shape_refused e no detach --iface "${VALID_NONEXISTENT}"

[[ "${fail}" == 0 ]] && echo "PASS: T_IFACE_SHAPE_REJECT_APPLY_DETACH"
exit "${fail}"
