#!/bin/bash
# T_SIDECAR_IFACE_SYMLINK_REFUSAL — design §5.36 T-2 (MVP-3.4e).
#
# Per-iface symlink planted at `/run/xdpmacfilter/<iface>` (pointing to
# an attacker-controlled directory) MUST be:
#   - DETECTED by the post-§5.36 fd-relative discipline
#     (`SidecarRootFd` + `fstatat(AT_SYMLINK_NOFOLLOW)` /
#     `openat(O_NOFOLLOW)`)
#   - LOGGED via NEW event `sidecar.warn.iface_dir_symlink` (HG-3.4e-4)
#   - SKIPPED — the sidecar must not write into the symlink target
#   - NOT FATAL — `apply` MUST still exit 0 (PI-32-3.4b PRESERVED:
#     sidecar never throws; exporter degrades to action="unknown").
#
# Closes KC-3 sidecar limb: attacker with write under `/run/xdpmacfilter/`
# pre-creates `<iface>` as symlink → loader follows + writes
# attacker-controlled JSON to chosen target (e.g. cron-executed path).
#
# Maps to:
#   - PI-3.4e-2 (sidecar iface-subdir symlink refusal)
#   - PI-32-3.4b PRESERVED (sidecar never throws; apply continues)
#   - HG-3.4e-4 (WARN + skip response; new `sidecar.warn.iface_dir_symlink`)
#   - §5.31 EDIT-1 SIDECAR_ROOT discipline event-name preservation
#
# Sub-cases:
#   (a) Plant symlink `/run/xdpmacfilter/<iface>` → `/tmp/<attacker>`;
#       attach + apply → apply exit 0 + stderr contains the literal
#       prose token `symlink` (impl emits `... is a symlink` in the
#       per-iface-symlink branch msg) + iface name token + attacker
#       target dir has NO `rule_index.json` AND no `rule_index.json.tmp`
#       file.
#   (b) NEGATION CONTROL: clean `/run/xdpmacfilter/<iface>` (no symlink,
#       let sidecar create the iface subdir as a real dir);
#       re-apply → exit 0 + `rule_index.json` materializes + stderr
#       does NOT contain the `symlink` prose token (warn must be
#       conditional, not unconditional).
#
# §5.36 EDIT-2 (architect peer-DM 2026-05-27): the original assertion
# list included a literal `sidecar.warn.iface_dir_symlink` event-name
# grep, but per §5.32 logger convention (logger.cpp:231-242 emit_text =
# write_stderr(msg)) event-name tokens appear ONLY in JSON-envelope
# mode — text-mode prose carries the semantic phrasing instead. The
# event-name observability is covered at build-time via guard #13
# (logger.hpp kEventNames inclusion + log_events_v1.txt fixture +1).
# Our text-mode assertion uses the prose `symlink` token + iface name.
#
# Sanity-floor smoke: sub-case (b) — apply succeeds + rule_index.json
# materializes proves the upgrade didn't break the happy-path write.
# Negation control: sub-case (b) IS the negation against an
# "always-emit-warn" failure mode. A passing (a) without (b) would
# mean the warn event is unconditional (broken trigger).
#
# Failure-mode signaling (per §5.36 T-2 design + EDIT-2):
#   - (a) exit != 0 → sidecar threw (PI-32-3.4b violated).
#   - (a) /tmp/.../rule_index.json created → fd-relative discipline
#     broken (symlink followed).
#   - (a) no `symlink` prose token in stderr → WARN didn't fire at the
#     iface-dir-symlink branch (impl mis-wired or msg drift).
#   - (b) exit != 0 OR no rule_index.json → upgrade broke happy-path.
#   - (b) `symlink` token in stderr → WARN fires unconditionally.
# All five are [INVARIANT-VIOLATED] per §6.5 PI-3.4e-2.
#
# RESOURCE_LOCK xdp_fixture (per D-3.4e-T2-LOCK; no separate
# `sidecar_root` lock domain because IFACE_A is PID-unique so the
# per-iface subdir cannot clash with concurrent tests).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/config_valid.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

# §5.31 EDIT-1: sidecar lives at /run/xdpmacfilter/<iface>/rule_index.json.
SIDECAR_ROOT="/run/xdpmacfilter"
SIDECAR_DIR="${SIDECAR_ROOT}/${IFACE_A}"
SIDECAR_PATH="${SIDECAR_DIR}/rule_index.json"
SIDECAR_TMP="${SIDECAR_DIR}/rule_index.json.tmp"

# Attacker-controlled target dir for the symlink (sub-case (a)).
# PID-suffixed so concurrent tests on different IFACE_A values don't
# fight over the attacker dir.
ATTACKER_DIR="/tmp/xdpmf-fake-iface-attacker-$$"
ATTACKER_FILE="${ATTACKER_DIR}/rule_index.json"
ATTACKER_TMPFILE="${ATTACKER_DIR}/rule_index.json.tmp"

stderr_a=$(mktemp /tmp/xdpmf-sidesym-a.XXXXXX)
stderr_b=$(mktemp /tmp/xdpmf-sidesym-b.XXXXXX)

cleanup_sidesym() {
    set +e
    # Detach iface if (a)'s attach succeeded.
    ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" >/dev/null 2>&1

    # Remove planted symlink (rm -f on a symlink unlinks the link, NOT
    # the target — confirmed by GNU coreutils manual / POSIX rm(1)).
    sudo -n rm -f "${SIDECAR_DIR}" 2>/dev/null

    # If sub-case (b) left a real iface subdir, remove it (and any
    # contents) — only the per-PID iface subdir, NOT all of /run/xdpmacfilter
    # (other concurrent tests may use it).
    if sudo -n test -d "${SIDECAR_DIR}"; then
        sudo -n rm -rf "${SIDECAR_DIR}"
    fi

    # Remove attacker dir (and any leaked content — its emptiness is
    # the assertion in sub-case (a), but cleanup is unconditional).
    sudo -n rm -rf "${ATTACKER_DIR}" 2>/dev/null

    cleanup_veth
    rm -f "${stderr_a}" "${stderr_b}"
    set -e
}
trap cleanup_sidesym EXIT INT TERM HUP

# Defensive: clean any leftover state from a crashed prior run.
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true
# /run/xdpmacfilter/<iface> entry from a prior cycle — kill it whether
# symlink, dir, or regular file.
if sudo -n test -e "${SIDECAR_DIR}" || sudo -n test -L "${SIDECAR_DIR}"; then
    sudo -n rm -rf "${SIDECAR_DIR}" 2>/dev/null || true
    sudo -n rm -f  "${SIDECAR_DIR}" 2>/dev/null || true
fi
sudo -n rm -rf "${ATTACKER_DIR}" 2>/dev/null || true

# Ensure SIDECAR_ROOT exists as a real dir (mirrors §5.31 EDIT-1 expectation;
# the sidecar code creates it via mkdir if missing, but we want to plant
# a symlink one level deeper).
sudo -n mkdir -p "${SIDECAR_ROOT}"
if ! sudo -n test -d "${SIDECAR_ROOT}"; then
    echo "ERROR: ${SIDECAR_ROOT} is not a real directory (host state dirty)" >&2
    exit 1
fi

setup_veth

fail=0

# ─────────────────────────────────────────────────────────────────────────
# Sub-case (a) — plant per-iface symlink, attach + apply.
# Expected: apply exit 0 + sidecar.warn.iface_dir_symlink event in
# stderr + NO rule_index.json (or .tmp) in attacker dir.
# ─────────────────────────────────────────────────────────────────────────
echo "=== sub-case (a): plant ${SIDECAR_DIR} -> ${ATTACKER_DIR}"
sudo -n mkdir -p "${ATTACKER_DIR}"
# Defensive: attacker dir must be empty pre-test so non-emptiness post-
# apply unambiguously means "loader wrote here".
if [[ -n "$(sudo -n ls -A "${ATTACKER_DIR}" 2>/dev/null)" ]]; then
    echo "ERROR: ${ATTACKER_DIR} unexpectedly non-empty pre-test" >&2
    sudo -n ls -la "${ATTACKER_DIR}" >&2 || true
    exit 1
fi

sudo -n ln -sfn "${ATTACKER_DIR}" "${SIDECAR_DIR}"
if ! sudo -n test -L "${SIDECAR_DIR}"; then
    echo "FAIL[a0]: planted symlink ${SIDECAR_DIR} did NOT register as a symlink" >&2
    exit 1
fi
echo "   readlink ${SIDECAR_DIR} -> $(sudo -n readlink "${SIDECAR_DIR}")"

# Trigger 1 — attach (per design "attach unaffected by sidecar state;
# sidecar fires from apply, not attach"). attach must succeed regardless
# of the planted symlink.
echo "=== trigger 1: attach --iface ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2>"${stderr_a}"
rc_attach=$?
set -e
echo "attach rc=${rc_attach}"
echo "--- stderr (attach) ---"
cat "${stderr_a}" >&2 || true
echo "--- end stderr (attach) ---"

if [[ "${rc_attach}" -ne 0 ]]; then
    echo "FAIL[a.attach]: attach exit ${rc_attach} (expected 0 — sidecar state must not affect attach)" >&2
    fail=1
fi

# Trigger 2 — apply (this is where sidecar runs). Even with the
# symlinked iface subdir, apply MUST exit 0 (PI-32-3.4b — sidecar never
# throws; degrades to action="unknown" via missing rule_index.json).
echo "=== trigger 2: apply -f ${FIXTURE} --iface ${IFACE_A}"
: >"${stderr_a}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_a}"
rc_apply=$?
set -e
echo "apply rc=${rc_apply}"
echo "--- stderr (apply) ---"
cat "${stderr_a}" >&2 || true
echo "--- end stderr (apply) ---"

# (a1) apply exit 0 (PI-32-3.4b PRESERVED).
if [[ "${rc_apply}" -ne 0 ]]; then
    echo "FAIL[a1]: apply exit ${rc_apply} (expected 0 — PI-32-3.4b sidecar-never-throws VIOLATED)" >&2
    fail=1
fi

# (a2) stderr contains literal prose token `symlink` per §5.36 EDIT-2
# (architect peer-DM 2026-05-27). §5.32 logger convention: event-name
# tokens appear ONLY in JSON-envelope mode; text-mode emits prose like
# `... is a symlink`. All 6 existing sidecar.warn.* events follow this
# convention. Catalog inclusion / fixture lockstep covers event-name
# observability at build-time (guard #13).
if ! grep -q -F -- 'symlink' "${stderr_a}"; then
    echo "FAIL[a2]: stderr does not contain prose token 'symlink'" >&2
    echo "          (per-iface-symlink branch msg did not fire OR drift in wording)" >&2
    fail=1
fi

# (a2b) stderr contains the iface name token — the impl's std::format
# msg shape includes the iface being refused. Confirms the refusal is
# scoped to the planted iface (not a global "something is wrong" msg).
if ! grep -q -F -- "${IFACE_A}" "${stderr_a}"; then
    echo "FAIL[a2b]: stderr does not contain iface name token '${IFACE_A}'" >&2
    echo "           (per-iface refusal msg missing the iface — may be over-general)" >&2
    fail=1
fi

# (a3) Attacker target MUST NOT contain rule_index.json — confirms the
# sidecar did NOT follow the symlink. Use `test ! -e` on the attacker-
# side path (NOT via SIDECAR_DIR which is the symlink).
if sudo -n test -e "${ATTACKER_FILE}"; then
    echo "FAIL[a3]: ${ATTACKER_FILE} EXISTS — sidecar followed the symlink (fd-relative discipline broken)" >&2
    sudo -n ls -la "${ATTACKER_DIR}" >&2 || true
    fail=1
fi

# (a4) Same for the .tmp staging file — sidecar might create+rename, so
# .tmp existence (even if cleaned up) means partial-write data leak.
if sudo -n test -e "${ATTACKER_TMPFILE}"; then
    echo "FAIL[a4]: ${ATTACKER_TMPFILE} EXISTS — sidecar started writing through the symlink" >&2
    fail=1
fi

# (a5) Defensive: attacker dir empty (catches any other write through
# the symlink — e.g. a future file shape the test doesn't enumerate).
attacker_contents=$(sudo -n ls -A "${ATTACKER_DIR}" 2>/dev/null || true)
if [[ -n "${attacker_contents}" ]]; then
    echo "FAIL[a5]: ${ATTACKER_DIR} non-empty post-apply — sidecar wrote SOMETHING through the symlink" >&2
    sudo -n ls -la "${ATTACKER_DIR}" >&2 || true
    fail=1
fi

# ─────────────────────────────────────────────────────────────────────────
# Sub-case (b) — NEGATION CONTROL: clean iface subdir, re-apply.
# Expected: apply exit 0 + rule_index.json materializes + stderr does
# NOT contain `sidecar.warn.iface_dir_symlink`.
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== sub-case (b) NEGATION: clean ${SIDECAR_DIR}, re-apply"
# Unlink the symlink (rm on a symlink removes the link only).
sudo -n rm -f "${SIDECAR_DIR}"
# Wipe the attacker dir to keep the test environment hygenic.
sudo -n rm -rf "${ATTACKER_DIR}"
# Let the sidecar create the iface subdir as a real dir via mkdirat —
# do NOT pre-create it here, so we exercise the happy-path mkdir.

# Verify pre-state: SIDECAR_DIR does NOT exist (neither symlink nor real).
if sudo -n test -e "${SIDECAR_DIR}" || sudo -n test -L "${SIDECAR_DIR}"; then
    echo "FAIL[b0]: ${SIDECAR_DIR} still exists pre-negation" >&2
    fail=1
fi

: >"${stderr_b}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_b}"
rc_b=$?
set -e
echo "apply (neg) rc=${rc_b}"
echo "--- stderr (b) ---"
cat "${stderr_b}" >&2 || true
echo "--- end stderr (b) ---"

# (b1) apply exit 0.
if [[ "${rc_b}" -ne 0 ]]; then
    echo "FAIL[b1]: NEGATION apply exit ${rc_b} (expected 0 — upgrade broke happy-path write)" >&2
    fail=1
fi

# (b2) Real rule_index.json materializes at the iface subdir.
if ! sudo -n test -e "${SIDECAR_PATH}"; then
    echo "FAIL[b2]: NEGATION ${SIDECAR_PATH} missing — sidecar happy-path broken" >&2
    fail=1
fi

# (b3) Stderr does NOT contain the `symlink` prose token — the per-iface
# WARN msg must be conditional on the symlink being present. §5.36
# EDIT-2: text-mode signature of the warn is the prose phrasing
# (`... is a symlink`), not the event-name token (JSON-only). A clean
# happy-path apply must not mention symlinks at all.
if grep -q -F -- 'symlink' "${stderr_b}"; then
    echo "FAIL[b3]: NEGATION stderr unexpectedly contains 'symlink' prose token" >&2
    echo "          — per-iface-symlink branch is firing unconditionally" >&2
    echo "          (sub-case (a) prose-grep would pass even without the symlink — theatre)" >&2
    fail=1
fi

# (b4) Defensive: attacker dir still absent (we wiped it; sub-case (b)
# must not recreate or write to it).
if sudo -n test -e "${ATTACKER_DIR}"; then
    echo "FAIL[b4]: NEGATION ${ATTACKER_DIR} unexpectedly exists (leak from prior sub-case?)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_SIDECAR_IFACE_SYMLINK_REFUSAL"
exit "${fail}"
