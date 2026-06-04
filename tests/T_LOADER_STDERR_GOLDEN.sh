#!/bin/bash
# T_LOADER_STDERR_GOLDEN — design §6.84 (MVP-4.27 / §5.67 B37-2).
#
# Pins the OPERATOR-FACING loader/CLI error-stderr SHAPE — the greppable
# `xdpfilter:` / `error:` audit-ABI prefix (docs/FLEET_DEPLOYMENT.md:34-52) —
# by driving operator-REACHABLE error paths through the REAL xdpfilter CLI and
# EXACT-matching the rendered stderr against checked-in goldens
# (D-mvp-4.27-Q1-A2 / -EXACTMATCH). Closes the gap that ~20 existing tests grep
# stderr SUBSTRINGS incidentally but NONE pin the rendered SHAPE, so a
# behaviour-preserving refactor of LoaderCategory::message / the main.cpp catch
# arms / the logger render could silently mutate the operator/audit ABI.
#
# This test ASSERTS the CURRENT message text — it does NOT modify it
# (PI-mvp-4.27-ZERO-SRC). A future message change rippling to a golden is the
# gate working as designed (guard #13 INVERTED), NOT this slice editing src/.
#
# MUST corpus (no privilege, deterministic — variable parts FIXED so the
# golden is byte-deterministic):
#   1. bad trust_model  -> exit 9, `^xdpfilter: config error: …`
#                          (the ConfigError sentinel-suppression branch — the
#                           most refactor-fragile logic per §5.26: NO bare
#                           `error:` prefix). EXACT full-line match.
#   2. missing config   -> exit 1, `^xdpfilter: config error: …`. EXACT match.
#   3. usage error      -> exit 1, an `^error:` line (CliError parse arm). The
#                          golden pins the `error:` line; the usage-text dump
#                          that follows is trimmed (D-mvp-4.27-Q1-A2).
#
# SHOULD / best-effort OPS-canary (SKIP-clean): Permission via an UNPRIVILEGED
# `attach --iface lo` -> exit 6, `^error: …: permission denied (need CAP_BPF /
# CAP_NET_ADMIN)`. Prefix-anchored (errno/strerror tail is locale/kernel-
# variable). SKIPPED if the test runs privileged (cannot trigger EPERM as root).
#
# SKIP 77 if the loader binary is not built. NO RESOURCE_LOCK
# (D-mvp-4.27-Q1-NOLOCK): every MUST-corpus path throws at CLI/env/config parse
# BEFORE `--iface lo` is resolved or any bpffs/kernel op runs; the best-effort
# Permission arm fails at bpf_object__load (EPERM) before pinning. No shared
# host state is touched.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader 2>/dev/null) || {
    echo "SKIP: xdpfilter loader binary not built under ${BUILD_DIR}" >&2
    exit 77
}
echo "loader=${LOADER_BIN}"

GOLDEN_DIR="${TEST_DIR}/fixtures"

# ── FIXED variable inputs (must match the checked-in goldens verbatim) ────
TRUST_GARBAGE="garbage_value"
ALLOW_MAC="02:00:00:00:00:01"
MISSING_CFG="/nonexistent/xdpmf_golden_missing.yaml"
BAD_MAC="not-a-mac"

cap=$(mktemp /tmp/xdpmf-stderrgolden.XXXXXX)
line=$(mktemp /tmp/xdpmf-stderrgolden-line.XXXXXX)
trap 'rm -f "${cap}" "${line}"' EXIT INT TERM HUP

fail=0

dump() { echo "--- stderr ---" >&2; cat "$1" >&2 || true; echo "--- end ---" >&2; }

# exact_match <golden-basename> <captured-file> <label>
exact_match() {
    local golden="${GOLDEN_DIR}/$1" capf="$2" label="$3"
    if [[ ! -f "${golden}" ]]; then
        echo "FAIL[${label}]: golden ${golden} missing" >&2; fail=1; return
    fi
    if diff -u "${golden}" "${capf}" >&2; then
        echo "OK[${label}]: rendered stderr EXACT-matches $(basename "${golden}")"
    else
        echo "FAIL[${label}]: rendered stderr does NOT match $(basename "${golden}")" >&2
        echo "               (operator/audit stderr ABI drifted — see diff above)" >&2
        fail=1
    fi
}

# ── Shape 1: bad trust_model -> exit 9, ConfigError sentinel-suppression ──
echo "=== Shape 1: XDPMF_TRUST_MODEL=${TRUST_GARBAGE} attach --iface lo --allow ${ALLOW_MAC}"
set +e
XDPMF_TRUST_MODEL="${TRUST_GARBAGE}" \
    "${LOADER_BIN}" attach --iface lo --allow "${ALLOW_MAC}" 2>"${cap}"
rc=$?
set -e
echo "rc=${rc}"; dump "${cap}"
[[ "${rc}" -eq 9 ]] || { echo "FAIL[1-exit]: expected exit 9 (ConfigError), got ${rc}" >&2; fail=1; }
exact_match loader_stderr_bad_trust_model.golden "${cap}" "1-shape"

# ── Shape 2: missing config -> exit 1, ConfigError prefix ────────────────
echo "=== Shape 2: apply -f ${MISSING_CFG} --iface lo"
[[ ! -e "${MISSING_CFG}" ]] || { echo "FAIL: fixed MISSING_CFG ${MISSING_CFG} exists on host" >&2; exit 1; }
set +e
"${LOADER_BIN}" apply -f "${MISSING_CFG}" --iface lo 2>"${cap}"
rc=$?
set -e
echo "rc=${rc}"; dump "${cap}"
[[ "${rc}" -eq 1 ]] || { echo "FAIL[2-exit]: expected exit 1 (missing config), got ${rc}" >&2; fail=1; }
exact_match loader_stderr_missing_config.golden "${cap}" "2-shape"

# ── Shape 3: usage / CLI parse error -> exit 1, `^error:` line ───────────
# A malformed MAC is a deterministic CliError parse error routed through
# main.cpp's `error: <what>` arm; the usage-text dump that follows is trimmed
# (golden pins only the `error:` line per D-mvp-4.27-Q1-A2).
echo "=== Shape 3: attach --iface lo --allow ${BAD_MAC} (CLI parse error)"
set +e
"${LOADER_BIN}" attach --iface lo --allow "${BAD_MAC}" 2>"${cap}"
rc=$?
set -e
echo "rc=${rc}"; dump "${cap}"
[[ "${rc}" -eq 1 ]] || { echo "FAIL[3-exit]: expected exit 1 (CLI usage error), got ${rc}" >&2; fail=1; }
# Extract the single rendered `error:` line (the pinned shape); the usage dump
# below it is intentionally NOT pinned.
grep -m1 -E '^error:' "${cap}" >"${line}" || true
exact_match loader_stderr_usage_error.golden "${line}" "3-shape"

# ── Best-effort OPS-canary: Permission via UNPRIVILEGED attach (SKIP-clean) ─
# Drives the loader through a capability-stripped invocation the sudo-run suite
# never exercises. SKIP if privileged (cannot trigger EPERM as root).
echo "=== Best-effort: unprivileged attach --iface lo (Permission shape)"
if [[ "$(id -u)" -eq 0 ]]; then
    echo "SKIP-arm: running privileged (euid 0) — cannot trigger EPERM; Permission arm skipped" >&2
else
    set +e
    "${LOADER_BIN}" attach --iface lo --allow "${ALLOW_MAC}" 2>"${cap}"
    rc=$?
    set -e
    echo "rc=${rc}"; dump "${cap}"
    if [[ "${rc}" -ne 6 ]]; then
        echo "NOTE-arm: unprivileged attach exited ${rc} (expected 6) — env may grant" >&2
        echo "          CAP_BPF/CAP_NET_ADMIN ambiently; Permission arm inconclusive" >&2
    else
        # Prefix-anchored / normalized: anchor on `^error:` + the fixed
        # permission-denied message; the errno/strerror tail is locale-variable.
        if grep -qE -- '^error:.*permission denied \(need CAP_BPF / CAP_NET_ADMIN\)' "${cap}"; then
            echo "OK[perm]: unprivileged attach renders the pinned Permission shape (exit 6)"
        else
            echo "FAIL[perm]: exit 6 but stderr lacks the pinned Permission shape" >&2
            fail=1
        fi
    fi
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_LOADER_STDERR_GOLDEN"
exit "${fail}"
