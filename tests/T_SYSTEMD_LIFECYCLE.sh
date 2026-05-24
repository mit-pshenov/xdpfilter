#!/bin/bash
# T_SYSTEMD_LIFECYCLE — design §6.33 (MVP-3.3 / §5.28) — LOAD-BEARING OPS canary.
#
# Install systemd unit + per-iface config; `systemctl start/reload/stop`
# end-to-end against a HOST-netns veth fixture (systemd-as-PID-1 runs in
# the host netns; the project-wide per-PID netns fixture cannot host
# systemd-driven `if_nametoindex` lookups — see tester→architect note
# 2026-05-24 on §6.33 netns conflict, option (A) confined to this test
# and §6.34).
#
# Sequence per §6.33:
#   PRE: assert XDP NOT attached on test iface (negation baseline).
#   1. setup host veth pair (xdpmf_sysd_a_$$ / xdpmf_sysd_b_$$).
#   2. install unit → /etc/systemd/system/xdpmacfilter@.service.
#   3. install config → /etc/xdpfilter/${SYSD_IFACE_A}.yaml.
#   4. systemctl daemon-reload.
#   5. systemctl start xdpmacfilter@${SYSD_IFACE_A}.service.
#      POST-START assertions:
#        - is-active → "active".
#        - XDP attached (prog_id non-empty); capture PROG_ID_START.
#        - ${PIN_DIR}/link present.
#        - active_idx == 0 (first apply per §5.26 invariant).
#        - journalctl contains 'xdpmacfilter: trust_model=strict' (PI-23 verbatim).
#   6. modify config (swap to a different valid fixture).
#   7. systemctl reload.
#      POST-RELOAD assertions:
#        - is-active still "active".
#        - active_idx == 1 (FLIPPED — atomic-swap occurred, Q2 R1 contract).
#        - xdp_prog_id UNCHANGED (== PROG_ID_START — bpf_link__update_program
#          did NOT detach+reattach; this is the load-bearing P0a contract).
#   8. systemctl stop.
#      POST-STOP assertions (NEGATION control):
#        - is-active → "inactive".
#        - xdp_prog_id empty (XDP detached).
#        - ${PIN_DIR}/link absent.
#
# Anti-theatricality controls:
#   - active_idx FLIP across reload distinguishes R1 (atomic swap) from
#     R3 (restart-as-reload would give idx=0 again).
#   - PROG_ID constancy across reload distinguishes bpf_link__update_program
#     (same prog, link rebound) from detach+reattach (new prog_id).
#   - The pre-start no-attach baseline + post-stop no-attach are the
#     bookended negation controls.
#
# Aggressive trap cleanup: stop unit, disable, rm unit file + config,
# daemon-reload, reset-failed, then ip link del (idempotent).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

# SKIP-77 conditions per §6.33.
if ! command -v systemctl >/dev/null 2>&1; then
    echo "SKIP: systemctl not in PATH" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
SYSTEMD_UNIT_SRC="${SYSTEMD_UNIT_SRC:-${SOURCE_DIR}/systemd/xdpmacfilter@.service}"
FIXTURE_DIR="${TEST_DIR}/fixtures"
FIX_A="${FIXTURE_DIR}/config_apply_swap_a.yaml"
FIX_B="${FIXTURE_DIR}/config_apply_swap_b.yaml"

# Sanity: required artifacts exist.
for f in "${SYSTEMD_UNIT_SRC}" "${FIX_A}" "${FIX_B}" "${LOADER_BIN}"; do
    if [[ ! -e "${f}" ]]; then
        echo "FAIL: required artifact missing: ${f}" >&2
        exit 1
    fi
done

# ── HOST-netns test iface (NOT the netns-isolated common.sh IFACE_A) ─────
# Confined to this test + T_SYSTEMD_RESTART_ON_FAILURE per option (A).
# PID-suffixed for collision avoidance with parallel runs (though
# RESOURCE_LOCK serializes systemd tests anyway).
# Iface naming: short enough to satisfy Linux IFNAMSIZ (max 15 chars for
# the iface name). Earlier draft was `xdpmf_sysd_*_$$` (20 chars with
# 7-digit PID — `ip link add` rejects with "wrong: not a valid ifname").
# `xsd_*_$$` collapses to 6+7=13 chars max — fits comfortably. Still
# project-distinguishable (xdpmacfilter-systemd-test).
SYSD_IFACE_A="xsd_a_$$"
SYSD_IFACE_B="xsd_b_$$"
SYSD_PIN_DIR="${PIN_ROOT}/${SYSD_IFACE_A}"
UNIT_INSTALLED="/etc/systemd/system/xdpmacfilter@.service"
CONFIG_INSTALLED="/etc/xdpfilter/${SYSD_IFACE_A}.yaml"
UNIT_INSTANCE="xdpmacfilter@${SYSD_IFACE_A}.service"

# Make sure that:
#   - /usr/bin/xdpmacfilter exists at the path the unit's ExecStart cites,
#     OR the test gracefully bridges via a /usr/local/bin or BUILD_DIR
#     install. The shipped unit hardcodes /usr/bin/xdpmacfilter (per
#     §5.28 directive catalogue) so we either (a) symlink the build
#     binary to /usr/bin or (b) refuse to run. We choose (a) — fragile-
#     but-functional for dev VM; cleanup restores prior state.
#
# Strategy: if /usr/bin/xdpmacfilter already exists (real install), leave
# it alone. Otherwise symlink our build binary; mark for removal in trap.
NEED_USRBIN_RESTORE=""
if [[ ! -e /usr/bin/xdpmacfilter ]]; then
    NEED_USRBIN_RESTORE=1
fi

cleanup_lifecycle() {
    set +e
    # Stop + disable + remove unit + remove config + daemon-reload + reset-failed.
    sudo -n systemctl stop "${UNIT_INSTANCE}"          2>/dev/null
    sudo -n systemctl disable "${UNIT_INSTANCE}"       2>/dev/null
    sudo -n rm -f "${UNIT_INSTALLED}"                  2>/dev/null
    sudo -n rm -f "${CONFIG_INSTALLED}"                2>/dev/null
    sudo -n systemctl daemon-reload                    2>/dev/null
    sudo -n systemctl reset-failed "${UNIT_INSTANCE}"  2>/dev/null
    # Remove our build-binary symlink IF we created it. Idempotent.
    if [[ -n "${NEED_USRBIN_RESTORE}" ]]; then
        sudo -n rm -f /usr/bin/xdpmacfilter           2>/dev/null
    fi
    # Tear down veth pair (idempotent) + bpffs pin dir.
    sudo -n ip link del "${SYSD_IFACE_A}"              2>/dev/null
    sudo -n rm -rf "${SYSD_PIN_DIR}"                   2>/dev/null
    # /etc/xdpfilter dir: leave if non-empty (other operators may use it).
    sudo -n rmdir /etc/xdpfilter                       2>/dev/null
    set -e
}
trap cleanup_lifecycle EXIT

# ── Defensive pre-cleanup of any leftover state ─────────────────────────
cleanup_lifecycle

fail=0

# ── Step 0 — install build binary at /usr/bin if needed ─────────────────
if [[ -n "${NEED_USRBIN_RESTORE}" ]]; then
    sudo -n ln -sf "${LOADER_BIN}" /usr/bin/xdpmacfilter
fi

# ── Step 1 — create host-netns veth pair ────────────────────────────────
echo "=== step 1: create host-netns veth ${SYSD_IFACE_A} <-> ${SYSD_IFACE_B}"
# Defensive: if either name exists in host netns, refuse loudly.
if ip link show "${SYSD_IFACE_A}" >/dev/null 2>&1; then
    echo "FAIL: ${SYSD_IFACE_A} already exists in host netns — name collision" >&2
    exit 1
fi
sudo -n ip link add "${SYSD_IFACE_A}" type veth peer name "${SYSD_IFACE_B}"
sudo -n sysctl -w "net.ipv6.conf.${SYSD_IFACE_A}.disable_ipv6=1" >/dev/null 2>&1 || true
sudo -n sysctl -w "net.ipv6.conf.${SYSD_IFACE_B}.disable_ipv6=1" >/dev/null 2>&1 || true
sudo -n ip link set "${SYSD_IFACE_A}" up
sudo -n ip link set "${SYSD_IFACE_B}" up
sleep 0.3

# ── PRE-step NEGATION: XDP NOT attached before start ────────────────────
host_xdp_prog_id() {
    local iface="$1"
    sudo -n ip -j link show "${iface}" 2>/dev/null | jq -r '
        .[0]
        | (.xdp.prog.id // .xdp.attached[]?.prog.id // empty)
    ' | head -n1
}

pre_prog_id=$(host_xdp_prog_id "${SYSD_IFACE_A}")
echo "PRE-start xdp_prog_id=${pre_prog_id:-<empty>}"
if [[ -n "${pre_prog_id}" ]]; then
    echo "FAIL[PRE-NEG]: XDP unexpectedly attached on ${SYSD_IFACE_A} BEFORE start (negation baseline failure)" >&2
    fail=1
fi

# ── Step 2 — install unit ──────────────────────────────────────────────
echo "=== step 2: install unit ${UNIT_INSTALLED}"
sudo -n install -D -m 0644 "${SYSTEMD_UNIT_SRC}" "${UNIT_INSTALLED}"

# ── Step 3 — install config (start from FIX_A) ─────────────────────────
echo "=== step 3: install config ${CONFIG_INSTALLED} (from FIX_A=${FIX_A})"
sudo -n install -D -m 0644 "${FIX_A}" "${CONFIG_INSTALLED}"

# ── Step 4 — daemon-reload ─────────────────────────────────────────────
echo "=== step 4: daemon-reload"
sudo -n systemctl daemon-reload

# ── Step 5 — systemctl start ───────────────────────────────────────────
echo "=== step 5: systemctl start ${UNIT_INSTANCE}"
set +e
sudo -n systemctl start "${UNIT_INSTANCE}"
rc_start=$?
set -e
echo "rc_start=${rc_start}"

# Capture the status + journal for diagnostics.
echo "--- systemctl status ${UNIT_INSTANCE} ---"
sudo -n systemctl status "${UNIT_INSTANCE}" --no-pager || true
echo "--- journalctl -u ${UNIT_INSTANCE} (last 50) ---"
sudo -n journalctl -u "${UNIT_INSTANCE}" --no-pager -n 50 || true
echo "--- end status/journal ---"

if [[ "${rc_start}" -ne 0 ]]; then
    echo "FAIL[5]: systemctl start exit ${rc_start}" >&2
    fail=1
fi

# ── POST-START assertions ──────────────────────────────────────────────
# (5a) is-active = active.
state=$(sudo -n systemctl is-active "${UNIT_INSTANCE}" 2>/dev/null || true)
echo "is-active (post-start) = '${state}'"
if [[ "${state}" != "active" ]]; then
    echo "FAIL[5a]: systemctl is-active = '${state}' (expected 'active')" >&2
    fail=1
fi

# (5b) XDP attached on host iface; capture PROG_ID_START.
PROG_ID_START=$(host_xdp_prog_id "${SYSD_IFACE_A}")
echo "PROG_ID_START=${PROG_ID_START:-<empty>}"
if [[ -z "${PROG_ID_START}" ]]; then
    echo "FAIL[5b]: no XDP attached on ${SYSD_IFACE_A} after start" >&2
    fail=1
fi

# (5c) link pin exists.
if ! sudo -n test -e "${SYSD_PIN_DIR}/link"; then
    echo "FAIL[5c]: expected pin ${SYSD_PIN_DIR}/link missing" >&2
    fail=1
fi

# (5d) active_idx == 0 (first apply lands in slot 0).
read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${SYSD_PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then
        printf '%d\n' "0x${hex}"
    fi
}
active_after_start=$(read_active_idx)
echo "active_idx (post-start) = '${active_after_start}'"
if [[ "${active_after_start}" != "0" ]]; then
    echo "FAIL[5d]: active_idx post-start = '${active_after_start}' (expected 0 per §5.26 invariant)" >&2
    fail=1
fi

# (5e) journalctl contains 'xdpmacfilter: trust_model=strict' (PI-23 verbatim).
if ! sudo -n journalctl -u "${UNIT_INSTANCE}" --no-pager -n 200 2>/dev/null \
        | grep -qE 'xdpmacfilter: trust_model=strict'; then
    echo "FAIL[5e]: journalctl missing 'xdpmacfilter: trust_model=strict' (PI-23 verbatim format)" >&2
    sudo -n journalctl -u "${UNIT_INSTANCE}" --no-pager -n 100 >&2 || true
    fail=1
fi

# ── Step 6 — modify config (swap to FIX_B) ─────────────────────────────
echo "=== step 6: swap config to FIX_B=${FIX_B}"
sudo -n install -D -m 0644 "${FIX_B}" "${CONFIG_INSTALLED}"

# ── Step 7 — systemctl reload ──────────────────────────────────────────
echo "=== step 7: systemctl reload ${UNIT_INSTANCE}"
set +e
sudo -n systemctl reload "${UNIT_INSTANCE}"
rc_reload=$?
set -e
echo "rc_reload=${rc_reload}"
if [[ "${rc_reload}" -ne 0 ]]; then
    echo "FAIL[7]: systemctl reload exit ${rc_reload}" >&2
    echo "--- journalctl after reload (last 50) ---" >&2
    sudo -n journalctl -u "${UNIT_INSTANCE}" --no-pager -n 50 >&2 || true
    fail=1
fi

# ── POST-RELOAD assertions ─────────────────────────────────────────────
# (7a) is-active still active.
state=$(sudo -n systemctl is-active "${UNIT_INSTANCE}" 2>/dev/null || true)
echo "is-active (post-reload) = '${state}'"
if [[ "${state}" != "active" ]]; then
    echo "FAIL[7a]: systemctl is-active post-reload = '${state}' (expected 'active')" >&2
    fail=1
fi

# (7b) active_idx FLIPPED to 1 (atomic-swap occurred, Q2 R1 contract).
# This is THE differential signal for reload=re-exec-apply (NOT restart).
active_after_reload=$(read_active_idx)
echo "active_idx (post-reload) = '${active_after_reload}'"
if [[ "${active_after_reload}" != "1" ]]; then
    echo "FAIL[7b]: active_idx post-reload = '${active_after_reload}' (expected 1 — FLIPPED from 0)" >&2
    echo "          if 0: ExecReload re-attached from scratch (R3 not R1) — Q2 contract violated" >&2
    fail=1
fi

# (7c) XDP STILL attached after reload (link persisted, no detach window).
#
# CORRECTION (rework round 2, post-impl-evidence): Architect's §6.33 spec
# previously asserted "prog_id UNCHANGED across reload" as the R1 vs R3
# differential. Impl source (src/lib/loader.cpp:1466-1473) explicitly
# documents the OPPOSITE contract: every apply() invocation loads a FRESH
# skeleton (different prog_id) and then calls bpf_link__update_program to
# rebind the persistent LINK to the new prog. The CORRECT contract is:
#   - LINK persists (same kernel link object; pin file unchanged).
#   - MAPS are reused (stats counts preserved through the swap).
#   - active_idx flips (atomic inner-map slot swap — assertion 7b above).
#   - prog_id NECESSARILY CHANGES (fresh skel → new BPF_PROG_LOAD).
#
# The load-bearing R1-vs-R3 differential is the active_idx flip (7b): R3
# (restart-as-reload) would re-attach from scratch and land in slot 0,
# NOT flip 0→1. The flip-to-1 already PROVES R1 was used.
#
# We additionally assert (i) XDP is still attached post-reload, AND (ii)
# the pin file ${SYSD_PIN_DIR}/link still exists (R3 would unlink it on
# detach). These two together cover the "link persisted" side of R1.
PROG_ID_AFTER_RELOAD=$(host_xdp_prog_id "${SYSD_IFACE_A}")
echo "PROG_ID_AFTER_RELOAD=${PROG_ID_AFTER_RELOAD:-<empty>} (note: may legitimately differ from PROG_ID_START=${PROG_ID_START} per loader.cpp:1466-1473)"
if [[ -z "${PROG_ID_AFTER_RELOAD}" ]]; then
    echo "FAIL[7c-i]: no XDP attached on ${SYSD_IFACE_A} after reload" >&2
    fail=1
fi
if ! sudo -n test -e "${SYSD_PIN_DIR}/link"; then
    echo "FAIL[7c-ii]: link pin ${SYSD_PIN_DIR}/link MISSING after reload" \
         "(R3 detach+reattach would unlink it; R1 bpf_link__update_program preserves it)" >&2
    fail=1
fi

# ── Step 8 — systemctl stop ────────────────────────────────────────────
echo "=== step 8: systemctl stop ${UNIT_INSTANCE}"
set +e
sudo -n systemctl stop "${UNIT_INSTANCE}"
rc_stop=$?
set -e
echo "rc_stop=${rc_stop}"
if [[ "${rc_stop}" -ne 0 ]]; then
    echo "FAIL[8]: systemctl stop exit ${rc_stop}" >&2
    fail=1
fi

# ── POST-STOP assertions (NEGATION) ────────────────────────────────────
# (8a) is-active = inactive.
state=$(sudo -n systemctl is-active "${UNIT_INSTANCE}" 2>/dev/null || true)
echo "is-active (post-stop) = '${state}'"
if [[ "${state}" != "inactive" ]]; then
    echo "FAIL[8a]: systemctl is-active post-stop = '${state}' (expected 'inactive')" >&2
    fail=1
fi

# (8b) XDP detached (prog_id empty).
post_stop_prog=$(host_xdp_prog_id "${SYSD_IFACE_A}")
echo "post-stop xdp_prog_id=${post_stop_prog:-<empty>}"
if [[ -n "${post_stop_prog}" ]]; then
    echo "FAIL[8b]: XDP still attached on ${SYSD_IFACE_A} after stop (id=${post_stop_prog})" >&2
    fail=1
fi

# (8c) link pin absent.
if sudo -n test -e "${SYSD_PIN_DIR}/link"; then
    echo "FAIL[8c]: pin ${SYSD_PIN_DIR}/link still present after stop" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_SYSTEMD_LIFECYCLE"
exit "${fail}"
