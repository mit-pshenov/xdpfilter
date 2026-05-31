#!/bin/bash
# T_BPFFS_ROOT_SYMLINK — design §6.15 (MVP-2 Sec / §5.22 Item 2).
#
# Closes the symlink-vortex vector: a symlink placed at
#   /sys/fs/bpf/xdpmacfilter            (bpffs root)         OR
#   /sys/fs/bpf/xdpmacfilter/<iface>    (per-iface dir)
# MUST cause the loader to refuse with:
#   - exit code 8 (LoaderError::PathRefused, per §4.1 + §5.22 Q3)
#   - stderr containing literal substring 'symlink'
#   - stderr containing the relevant path token (root path or iface name)
#   - no write into the attacker-controlled target dir
#   - no XDP attached
#
# Negation control: after cleanup restores the real bpffs root, a fresh
# attach MUST succeed (rc==0) and detach succeeds (rc==0) — proves the
# refusal is symlink-specific, not a permanent break.
#
# DESTRUCTIVE — corrupts /sys/fs/bpf/xdpmacfilter for the test's
# duration. Cleanup is mandatory and trap-driven (EXIT/INT/TERM/HUP).
# CMake registers this test with RESOURCE_LOCK xdp_fixture; §6.13
# T_DETACH_NOTHING was amended (per §5.22) to take the SAME lock so it
# can't race the destructive setup window.
#
# Per design §6.15 Setup pre-check: if /sys/fs/bpf/xdpmacfilter is a
# real directory AND non-empty, abort early (exit 1 — NOT 77) — we
# refuse to corrupt an in-use bpffs path. Empty real dir: snapshot
# (record so cleanup re-creates) then rmdir before placing the symlink.
# Non-existent: no snapshot needed.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
BPFFS_ROOT="/sys/fs/bpf/xdpmacfilter"
FAKE_ROOT="/tmp/xdpmf-fake-bpffs"
FAKE_IFACE_DIR="/tmp/xdpmf-fake-iface"
stderr_file=$(mktemp /tmp/xdpmf-symlink-stderr.XXXXXX)

# Snapshot: whether the real bpffs root pre-existed. Set in pre-check
# below. Used by cleanup to decide whether to restore (mkdir) or leave
# the path absent (matches pre-test host state).
ROOT_PREEXISTED=0

cleanup_symlink() {
    set +e
    # 1) Detach if any negation-control attach succeeded but script died
    #    before reaching its detach.
    ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>/dev/null

    # 2) Remove per-iface symlink (may or may not exist; -f swallows ENOENT).
    sudo -n rm -f "${BPFFS_ROOT}/${IFACE_A}" 2>/dev/null

    # 3) If BPFFS_ROOT exists right now as a symlink (primary scenario
    #    state), unlink it. `rm -f` on a symlink unlinks the symlink
    #    itself (does NOT follow it).
    if sudo -n test -L "${BPFFS_ROOT}"; then
        sudo -n rm -f "${BPFFS_ROOT}"
    fi

    # 4) If BPFFS_ROOT exists as a real dir, leave it (or clean its
    #    contents from the sub-variant transient mkdir). If it does NOT
    #    exist and snapshot says it should: restore. If it does NOT
    #    exist and snapshot says it shouldn't: leave it absent.
    if ! sudo -n test -e "${BPFFS_ROOT}"; then
        if [[ "${ROOT_PREEXISTED}" == 1 ]]; then
            sudo -n mkdir -p "${BPFFS_ROOT}" 2>/dev/null
        fi
    else
        # Real dir exists — if we created an empty per-iface entry by
        # accident (e.g. negation control left state), let cleanup_veth
        # mop it via PIN_DIR removal.
        :
    fi

    # 5) Remove attacker-controlled fake dirs.
    sudo -n rm -rf "${FAKE_ROOT}" "${FAKE_IFACE_DIR}" 2>/dev/null

    # 6) Veth fixture (idempotent).
    cleanup_veth

    # 7) Temp stderr capture.
    rm -f "${stderr_file}"
    set -e
}
trap cleanup_symlink EXIT INT TERM HUP

# ── Pre-check: refuse to corrupt an in-use bpffs path ────────────────────
# Order matters: lstat (-L) before stat (-d) — a symlink at BPFFS_ROOT
# pre-existing on a sane host would be VERY suspicious, but bail anyway.
if sudo -n test -L "${BPFFS_ROOT}"; then
    echo "ERROR: ${BPFFS_ROOT} pre-exists as a symlink — host state is dirty" >&2
    echo "       (something already corrupted the bpffs root before the test)" >&2
    exit 1
fi
if sudo -n test -e "${BPFFS_ROOT}"; then
    if ! sudo -n test -d "${BPFFS_ROOT}"; then
        echo "ERROR: ${BPFFS_ROOT} exists but is not a directory" >&2
        exit 1
    fi
    # Real dir exists — check if non-empty (use sudo because /sys/fs/bpf
    # is mode 0700 on many distros).
    if [[ -n "$(sudo -n ls -A "${BPFFS_ROOT}" 2>/dev/null)" ]]; then
        echo "ERROR: real bpffs path ${BPFFS_ROOT} is non-empty — refusing to corrupt" >&2
        sudo -n ls -la "${BPFFS_ROOT}" >&2 || true
        exit 1
    fi
    # Empty real dir: snapshot it (cleanup will re-mkdir), then rmdir
    # so we can place the symlink in its slot.
    ROOT_PREEXISTED=1
    sudo -n rmdir "${BPFFS_ROOT}" \
        || { echo "ERROR: failed to rmdir empty ${BPFFS_ROOT}" >&2; exit 1; }
else
    ROOT_PREEXISTED=0
fi

# Prepare attacker-controlled target dir.
sudo -n mkdir -p "${FAKE_ROOT}"
[[ -z "$(sudo -n ls -A "${FAKE_ROOT}" 2>/dev/null)" ]] \
    || { echo "ERROR: ${FAKE_ROOT} unexpectedly non-empty pre-test" >&2; exit 1; }

# veth setup MUST happen BEFORE the symlink installation so the veth
# itself is real (the --iface arg of the loader resolves via
# if_nametoindex; the iface must exist regardless of bpffs state).
setup_veth

fail=0

# ─────────────────────────────────────────────────────────────────────────
# PRIMARY SCENARIO — root-level symlink.
# Expected: exit 8 + 'symlink' + root-path token in stderr; no writes
# into fake dir; no XDP attached.
# ─────────────────────────────────────────────────────────────────────────
echo "=== PRIMARY: install root symlink ${BPFFS_ROOT} -> ${FAKE_ROOT}"
sudo -n ln -sfn "${FAKE_ROOT}" "${BPFFS_ROOT}"
if ! sudo -n test -L "${BPFFS_ROOT}"; then
    echo "FAIL[P0]: post-install lstat of ${BPFFS_ROOT} did NOT report a symlink" >&2
    exit 1
fi
echo "   readlink -> $(sudo -n readlink "${BPFFS_ROOT}")"

: > "${stderr_file}"
echo "=== invoke our loader (expect exit 8 — PathRefused)"
set +e
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"
rc=$?
set -e
echo "loader rc=${rc}"
echo "--- captured stderr (primary) ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

# (P1) Exit 8 — PathRefused.
if [[ "${rc}" -ne 8 ]]; then
    echo "FAIL[P1]: expected rc=8 (PathRefused), got rc=${rc}" >&2
    case "${rc}" in
        0) echo "          rc=0 means loader FOLLOWED the symlink — vortex is open" >&2 ;;
        4) echo "          rc=4 means impl reused AttachRefusedAlien for path refusal — Q3 not honored" >&2 ;;
        6) echo "          rc=6 means impl picked Permission semantic — Q3 not honored" >&2 ;;
    esac
    fail=1
fi

# (P2) Stderr contains literal 'symlink' (per §5.22 Item 2 discipline).
if ! grep -q -F -- 'symlink' "${stderr_file}"; then
    echo "FAIL[P2]: stderr does not contain literal 'symlink'" >&2
    fail=1
fi

# (P3) Stderr contains the bpffs root path token.
if ! grep -q -F -- "${BPFFS_ROOT}" "${stderr_file}"; then
    echo "FAIL[P3]: stderr does not contain root path token '${BPFFS_ROOT}'" >&2
    fail=1
fi

# (P4) Fake dir MUST be empty — loader did not follow the symlink before
# refusing. Non-empty here means partial-write data leak.
if [[ -n "$(sudo -n ls -A "${FAKE_ROOT}" 2>/dev/null)" ]]; then
    echo "FAIL[P4]: loader wrote into attacker dir ${FAKE_ROOT} before refusing" >&2
    sudo -n ls -la "${FAKE_ROOT}" >&2 || true
    fail=1
fi

# (P5) No XDP attached on IFACE_A (refusal happened before bpf_xdp_attach).
xdp_now=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
if [[ -n "${xdp_now}" ]]; then
    echo "FAIL[P5]: XDP unexpectedly attached on ${IFACE_A} after refusal (prog_id=${xdp_now})" >&2
    fail=1
fi

# Tear down the root symlink and restore the real (empty) root for the
# next scenario.
echo "=== teardown root symlink, restore real root for sub-variant"
sudo -n rm -f "${BPFFS_ROOT}"
sudo -n mkdir "${BPFFS_ROOT}"
# Wipe any leftover fake content (defensive — should still be empty).
sudo -n rm -rf "${FAKE_ROOT}"
sudo -n mkdir -p "${FAKE_ROOT}"

# ─────────────────────────────────────────────────────────────────────────
# SUB-VARIANT — per-iface symlink (Q2 Standard scope).
# Same exit 8, same 'symlink' discipline, iface name token instead of
# root path token.
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== SUB-VARIANT: install per-iface symlink ${BPFFS_ROOT}/${IFACE_A} -> ${FAKE_IFACE_DIR}"
sudo -n mkdir -p "${FAKE_IFACE_DIR}"
sudo -n ln -sfn "${FAKE_IFACE_DIR}" "${BPFFS_ROOT}/${IFACE_A}"
if ! sudo -n test -L "${BPFFS_ROOT}/${IFACE_A}"; then
    echo "FAIL[S0]: post-install lstat of ${BPFFS_ROOT}/${IFACE_A} did NOT report a symlink" >&2
    fail=1
fi
echo "   readlink -> $(sudo -n readlink "${BPFFS_ROOT}/${IFACE_A}")"

: > "${stderr_file}"
echo "=== invoke our loader (expect exit 8 — PathRefused, per-iface)"
set +e
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"
rc_sub=$?
set -e
echo "loader rc=${rc_sub}"
echo "--- captured stderr (sub-variant) ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

# (S1) Exit 8.
if [[ "${rc_sub}" -ne 8 ]]; then
    echo "FAIL[S1]: sub-variant: expected rc=8 (PathRefused), got rc=${rc_sub}" >&2
    fail=1
fi

# (S2) Stderr contains 'symlink'.
if ! grep -q -F -- 'symlink' "${stderr_file}"; then
    echo "FAIL[S2]: sub-variant: stderr does not contain literal 'symlink'" >&2
    fail=1
fi

# (S3) Stderr contains the iface name token (per §5.22 Item 2: per-iface
# message includes the iface name).
if ! grep -q -F -- "${IFACE_A}" "${stderr_file}"; then
    echo "FAIL[S3]: sub-variant: stderr does not contain iface name token '${IFACE_A}'" >&2
    fail=1
fi

# (S4) Fake iface dir empty.
if [[ -n "$(sudo -n ls -A "${FAKE_IFACE_DIR}" 2>/dev/null)" ]]; then
    echo "FAIL[S4]: loader wrote into attacker dir ${FAKE_IFACE_DIR} before refusing" >&2
    sudo -n ls -la "${FAKE_IFACE_DIR}" >&2 || true
    fail=1
fi

# (S5) No XDP attached.
xdp_now=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
if [[ -n "${xdp_now}" ]]; then
    echo "FAIL[S5]: XDP unexpectedly attached on ${IFACE_A} after sub-variant refusal" >&2
    fail=1
fi

# Teardown sub-variant symlink, restore real iface-less root.
echo "=== teardown per-iface symlink"
sudo -n rm -f "${BPFFS_ROOT}/${IFACE_A}"
sudo -n rm -rf "${FAKE_IFACE_DIR}"

# ─────────────────────────────────────────────────────────────────────────
# NEGATION CONTROL — clean bpffs root (real dir, no per-iface entry).
# Expected: attach succeeds (rc==0), detach succeeds (rc==0).
# Proves refusal in primary/sub-variant was symlink-specific, not a
# permanent break of the loader.
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== NEGATION CONTROL: real bpffs root, no symlinks anywhere"
# Defensive: ensure no per-iface entry from sub-variant teardown lingers.
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true
if sudo -n test -L "${BPFFS_ROOT}"; then
    echo "FAIL[N0]: precondition: BPFFS_ROOT is still a symlink before negation" >&2
    exit 1
fi
if ! sudo -n test -d "${BPFFS_ROOT}"; then
    echo "FAIL[N0]: precondition: BPFFS_ROOT is not a real directory before negation" >&2
    exit 1
fi

: > "${stderr_file}"
echo "=== invoke our loader (expect exit 0 — attach succeeds)"
set +e
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"
rc_neg_attach=$?
set -e
echo "loader attach rc=${rc_neg_attach}"
echo "--- captured stderr (negation attach) ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

# (N1) Attach exit 0.
if [[ "${rc_neg_attach}" -ne 0 ]]; then
    echo "FAIL[N1]: negation attach: expected rc=0, got ${rc_neg_attach}" >&2
    fail=1
fi

# (N2) Pin dir populated (proves attach actually completed pinning).
if ! sudo -n test -e "${PIN_DIR}/allowlist_a"; then
    echo "FAIL[N2]: negation: expected ${PIN_DIR}/allowlist_a after successful attach" >&2
    fail=1
fi

# (N3) XDP attached.
xdp_now=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
if [[ -z "${xdp_now}" ]]; then
    echo "FAIL[N3]: negation: no XDP attached after successful attach" >&2
    fail=1
fi

: > "${stderr_file}"
echo "=== invoke our loader (detach, expect exit 0)"
set +e
${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2> "${stderr_file}"
rc_neg_detach=$?
set -e
echo "loader detach rc=${rc_neg_detach}"

# (N4) Detach exit 0.
if [[ "${rc_neg_detach}" -ne 0 ]]; then
    echo "FAIL[N4]: negation detach: expected rc=0, got ${rc_neg_detach}" >&2
    fail=1
fi

# (N5) Post-detach: pin dir gone, no XDP attached.
if sudo -n test -e "${PIN_DIR}"; then
    echo "FAIL[N5]: negation: pin dir ${PIN_DIR} remained after detach" >&2
    fail=1
fi
xdp_now=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
if [[ -n "${xdp_now}" ]]; then
    echo "FAIL[N5]: negation: XDP still attached after detach (prog_id=${xdp_now})" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_BPFFS_ROOT_SYMLINK"
exit "${fail}"
