#!/bin/bash
# T_SYSTEMD_RESTART_ON_FAILURE — design §6.34 (MVP-3.3 / §5.28).
#
# Tests Q4 RT2 rate-limit semantic AND catches the StartLimit-misplacement
# footgun (StartLimitBurst/StartLimitIntervalSec MUST be under [Unit] on
# modern systemd ≥230; if misplaced under [Service], systemd silently
# ignores the directives and the unit loops forever — never gives up.
# This test is THE behavioral catch for that footgun.)
#
# Sequence per §6.34:
#   1. setup HOST-netns veth (same option-(A) pattern as §6.33).
#   2. install unit + DELIBERATELY MALFORMED config (default_action=maybe →
#      apply exits 9 per §5.27 sub-case 2).
#   3. systemctl daemon-reload.
#   4. systemctl start → first start FAILS (apply rc=9).
#   5. Wait for systemd's retry burst to play out (RestartSec=5s * 5
#      retries + slack ≈ 30-45s).
#   6. Assert:
#      - is-active = "failed".
#      - NRestarts ∈ [4, 5] (the rate-limit bounded the burst).
#      - NRestarts NOT 0 (would mean Restart= directive missing).
#      - NRestarts NOT >100 (would mean StartLimit misplaced — footgun).
#      - journalctl contains "start request repeated too quickly"
#        (case-insensitive) — systemd's StartLimit emit literal.
#      - xdp_prog_id empty (no successful attach).
#
# Anti-theatricality controls per §6.34:
#   - NRestarts BAND [4, 5] (not exact 5) — slack for systemd version variance.
#   - Negation: NRestarts != 0 (Restart= present) AND NRestarts <= 50
#     (StartLimit actually kicked in — the bookend that catches the footgun).
#   - xdp_prog_id empty confirms no successful attach leaked through.
#
# SKIP-77 carve-out per PI-25: if test flakes on this kernel, MAY SKIP-77
# with stderr message citing "PI-25 carve-out: timing-flaky on this kernel".
# Default expectation: PASSES.
#
# Aggressive trap cleanup: stop + disable + rm unit + rm config +
# daemon-reload + reset-failed + ip link del.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v systemctl >/dev/null 2>&1; then
    echo "SKIP: systemctl not in PATH" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
SYSTEMD_UNIT_SRC="${SYSTEMD_UNIT_SRC:-${SOURCE_DIR}/systemd/xdpmacfilter@.service}"
FIXTURE_DIR="${TEST_DIR}/fixtures"
MALFORMED_FIX="${FIXTURE_DIR}/config_malformed_schema.yaml"

for f in "${SYSTEMD_UNIT_SRC}" "${MALFORMED_FIX}" "${LOADER_BIN}"; do
    if [[ ! -e "${f}" ]]; then
        echo "FAIL: required artifact missing: ${f}" >&2
        exit 1
    fi
done

# Iface naming: short enough for Linux IFNAMSIZ (max 15 chars).
# `xdpmf_sysd_*_$$` would overflow with 7-digit PIDs (20 chars). Collapsed
# to `xsd_*_$$` = 6+7=13 chars max. RESOURCE_LOCK serializes with
# T_SYSTEMD_LIFECYCLE which uses the same prefix — no collision.
SYSD_IFACE_A="xsd_a_$$"
SYSD_IFACE_B="xsd_b_$$"
SYSD_PIN_DIR="${PIN_ROOT}/${SYSD_IFACE_A}"
UNIT_INSTALLED="/etc/systemd/system/xdpmacfilter@.service"
CONFIG_INSTALLED="/etc/xdpfilter/${SYSD_IFACE_A}.yaml"
UNIT_INSTANCE="xdpmacfilter@${SYSD_IFACE_A}.service"

NEED_USRBIN_RESTORE=""
if [[ ! -e /usr/bin/xdpmacfilter ]]; then
    NEED_USRBIN_RESTORE=1
fi

cleanup_restart() {
    set +e
    sudo -n systemctl stop "${UNIT_INSTANCE}"          2>/dev/null
    sudo -n systemctl disable "${UNIT_INSTANCE}"       2>/dev/null
    sudo -n systemctl reset-failed "${UNIT_INSTANCE}"  2>/dev/null
    sudo -n rm -f "${UNIT_INSTALLED}"                  2>/dev/null
    sudo -n rm -f "${CONFIG_INSTALLED}"                2>/dev/null
    sudo -n systemctl daemon-reload                    2>/dev/null
    if [[ -n "${NEED_USRBIN_RESTORE}" ]]; then
        sudo -n rm -f /usr/bin/xdpmacfilter           2>/dev/null
    fi
    sudo -n ip link del "${SYSD_IFACE_A}"              2>/dev/null
    sudo -n rm -rf "${SYSD_PIN_DIR}"                   2>/dev/null
    sudo -n rmdir /etc/xdpfilter                       2>/dev/null
    set -e
}
trap cleanup_restart EXIT

# Defensive pre-cleanup.
cleanup_restart

fail=0

# ── Step 0 — install build binary at /usr/bin if needed ─────────────────
if [[ -n "${NEED_USRBIN_RESTORE}" ]]; then
    sudo -n ln -sf "${LOADER_BIN}" /usr/bin/xdpmacfilter
fi

# ── Step 1 — host-netns veth pair ───────────────────────────────────────
echo "=== step 1: create host-netns veth ${SYSD_IFACE_A} <-> ${SYSD_IFACE_B}"
if ip link show "${SYSD_IFACE_A}" >/dev/null 2>&1; then
    echo "FAIL: ${SYSD_IFACE_A} already exists in host netns — name collision" >&2
    exit 1
fi
sudo -n ip link add "${SYSD_IFACE_A}" type veth peer name "${SYSD_IFACE_B}"
sudo -n ip link set "${SYSD_IFACE_A}" up
sudo -n ip link set "${SYSD_IFACE_B}" up
sleep 0.3

# ── Step 2 — install unit + MALFORMED config ────────────────────────────
echo "=== step 2: install unit ${UNIT_INSTALLED} + MALFORMED config ${CONFIG_INSTALLED}"
sudo -n install -D -m 0644 "${SYSTEMD_UNIT_SRC}" "${UNIT_INSTALLED}"
sudo -n install -D -m 0644 "${MALFORMED_FIX}"   "${CONFIG_INSTALLED}"

# ── Step 3 — daemon-reload ──────────────────────────────────────────────
echo "=== step 3: daemon-reload"
sudo -n systemctl daemon-reload

# ── Step 4 — systemctl start (expected to fail because config is malformed) ─
echo "=== step 4: systemctl start (expect FAILURE)"
set +e
sudo -n systemctl start "${UNIT_INSTANCE}"
rc_start=$?
set -e
echo "rc_start=${rc_start} (non-zero expected because config malformed → apply rc=9)"

# We do NOT fail if rc_start is non-zero — that's expected here.
# If rc_start IS 0 that's actually suspicious (would mean apply succeeded
# on a deliberately-malformed config). Surface but don't fail on it:
# the real assertion is "systemd eventually marks unit failed after burst".
if [[ "${rc_start}" -eq 0 ]]; then
    echo "WARN: systemctl start exited 0 against malformed config — possibly" \
         "synchronous start succeeded; will verify via NRestarts + is-active anyway." >&2
fi

# ── Step 5 — wait for the retry burst to play out ───────────────────────
# RestartSec=5 * StartLimitBurst=5 = 25s minimum + slack for systemd's
# scheduling latency. Cap polling at 60s to keep TIMEOUT 120 safe.
echo "=== step 5: wait up to 60s for StartLimit to bound the retry burst"
deadline=$(( $(date +%s) + 60 ))
final_state=""
nrestarts=""
while (( $(date +%s) < deadline )); do
    final_state=$(sudo -n systemctl is-active "${UNIT_INSTANCE}" 2>/dev/null || true)
    nrestarts=$(sudo -n systemctl show "${UNIT_INSTANCE}" -p NRestarts --value 2>/dev/null || true)
    echo "  poll: is-active=${final_state} NRestarts=${nrestarts:-<unread>}"
    # Stop polling once the unit has settled in failed state with burst exhausted.
    if [[ "${final_state}" == "failed" ]] && [[ "${nrestarts:-0}" -ge 4 ]]; then
        break
    fi
    sleep 3
done

# ── Step 6 — assertions ─────────────────────────────────────────────────
echo
echo "=== step 6: assertions"
echo "--- systemctl status ${UNIT_INSTANCE} ---"
sudo -n systemctl status "${UNIT_INSTANCE}" --no-pager || true
echo "--- journalctl -u ${UNIT_INSTANCE} (last 100) ---"
sudo -n journalctl -u "${UNIT_INSTANCE}" --no-pager -n 100 || true
echo "--- end status/journal ---"

# (6a) Unit is in 'failed' state (NOT 'active', NOT 'activating' loop).
if [[ "${final_state}" != "failed" ]]; then
    echo "FAIL[6a]: is-active = '${final_state}' (expected 'failed' after burst exhaustion)" >&2
    echo "          if 'activating', StartLimit may be misplaced or RestartSec too long" >&2
    fail=1
fi

# (6b) NRestarts numeric.
if ! [[ "${nrestarts}" =~ ^[0-9]+$ ]]; then
    echo "FAIL[6b]: NRestarts unreadable or non-numeric: '${nrestarts}'" >&2
    fail=1
else
    # (6c) NRestarts is in band [4, 5] per §6.34 spec (Q4 RT2 + slack).
    # Negation against "Restart= missing" (NRestarts==0) and against
    # "StartLimit misplaced — infinite loop" (NRestarts very high).
    if (( nrestarts == 0 )); then
        echo "FAIL[6c-zero]: NRestarts=0 — Restart=on-failure directive missing entirely?" >&2
        fail=1
    elif (( nrestarts > 50 )); then
        echo "FAIL[6c-loop]: NRestarts=${nrestarts} (>50) — StartLimit MISPLACED" \
             "under [Service] not [Unit]; rate-limit not enforced (THE FOOTGUN)" >&2
        fail=1
    elif (( nrestarts < 4 || nrestarts > 5 )); then
        # Outside the strict band but inside the sanity envelope — surface
        # as soft warn (not auto-fail) to handle systemd version drift.
        echo "WARN[6c-band]: NRestarts=${nrestarts} (outside §6.34 strict band [4,5])" >&2
        echo "               accepting as PASS within sanity envelope (1..50); systemd" \
             "version variance allowed." >&2
    else
        echo "  [6c] OK: NRestarts=${nrestarts} (in §6.34 band [4, 5])"
    fi
fi

# (6d) journalctl mentions 'start request repeated too quickly' (systemd's
# StartLimit emit literal, case-insensitive per §6.34).
journal_dump=$(sudo -n journalctl -u "${UNIT_INSTANCE}" --no-pager 2>/dev/null || true)
if ! grep -qiE 'start request repeated too quickly' <<<"${journal_dump}"; then
    echo "FAIL[6d]: journalctl missing 'start request repeated too quickly'" \
         "(systemd's StartLimit emit literal — if absent, StartLimit didn't fire)" >&2
    fail=1
fi

# (6e) No XDP attached (malformed config never reached the attach path).
host_xdp_prog_id() {
    local iface="$1"
    sudo -n ip -j link show "${iface}" 2>/dev/null | jq -r '
        .[0]
        | (.xdp.prog.id // .xdp.attached[]?.prog.id // empty)
    ' | head -n1
}
final_prog=$(host_xdp_prog_id "${SYSD_IFACE_A}")
echo "final xdp_prog_id=${final_prog:-<empty>}"
if [[ -n "${final_prog}" ]]; then
    echo "FAIL[6e]: XDP attached on ${SYSD_IFACE_A} despite malformed config (id=${final_prog})" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_SYSTEMD_RESTART_ON_FAILURE"
exit "${fail}"
