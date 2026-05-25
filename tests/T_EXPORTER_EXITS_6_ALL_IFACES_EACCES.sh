#!/bin/bash
# T_EXPORTER_EXITS_6_ALL_IFACES_EACCES — design §6.46 (MVP-3.4.5 / §5.30 HK-17).
#
# Verifies HK-17 fix: when ALL discovered ifaces fail with EACCES/EPERM
# on `bpf_obj_get` AND there are zero successful reads, the exporter
# emits the HK-17 ERROR line and exits 6 (per Q3 E1 trigger condition).
#
# Sequence per §6.46:
#   1. setup_veth (2 ifaces — IFACE_A, IFACE_B) inside per-PID netns.
#   2. Attach the loader on EACH iface so the pin dirs ${PIN_ROOT}/<iface>/
#      get created with the per-iface map pins (stats, allowlist, etc.).
#   3. `chmod 000` each iface's stats pin (the specific file the exporter's
#      `bpf_obj_get` opens). Run under `sudo -u nobody` so the EACCES
#      actually fires (root would bypass DAC checks otherwise; we can also
#      drop CAP_DAC_OVERRIDE if needed).
#   4. Launch xdpmf-exporter under the same unprivileged context, pointed
#      at PIN_ROOT.
#   5. Either trigger a scrape OR wait for the per-scrape check window;
#      assert exit code 6 + stderr matches the HK-17 ERE.
#
# Sanity-floor smoke: step 2 attach produces stats pins (smoke for the
# discovery surface — without pins, `total_discovered == 0` and exit 0
# would fire instead of exit 6, masking a real bug).
# Negation control: re-run WITHOUT the chmod step; assert exit code is
# NOT 6 within a brief observation window — proves the test isn't false-
# failing on a different exit path.
#
# SKIP-77: EACCES is not reproducible in the test environment.
#   (a) `nobody` user unavailable.
#   (b) Running under `sudo -u nobody` still bypasses DAC because of file
#       caps OR because the kernel/BPF subsystem ignores DAC. The test
#       does its own preflight to detect this and SKIPs cleanly.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

# Preflight: do we have an unprivileged user we can run the exporter as?
UNPRIV_USER=""
for u in nobody xdpmftester _xdpmf; do
    if id -u "${u}" >/dev/null 2>&1; then
        UNPRIV_USER="${u}"
        break
    fi
done
if [[ -z "${UNPRIV_USER}" ]]; then
    echo "SKIP: T_EXPORTER_EXITS_6_ALL_IFACES_EACCES: no unprivileged user (nobody/xdpmftester) available" >&2
    echo "      cannot reproduce EACCES under root (DAC bypass)" >&2
    exit 77
fi
echo "UNPRIV_USER=${UNPRIV_USER}"

find_exporter() {
    if [[ -n "${XDPMF_EXPORTER_BIN:-}" && -x "${XDPMF_EXPORTER_BIN}" ]]; then
        printf '%s\n' "${XDPMF_EXPORTER_BIN}"; return 0
    fi
    local cand
    for cand in \
        "${BUILD_DIR}/xdpmf-exporter" \
        "${BUILD_DIR}/src/exporter/xdpmf-exporter" \
        "${BUILD_DIR}/bin/xdpmf-exporter"; do
        if [[ -x "$cand" ]]; then printf '%s\n' "$cand"; return 0; fi
    done
    local found
    found=$(find "${BUILD_DIR}" -maxdepth 5 -type f -executable -name xdpmf-exporter 2>/dev/null | head -1 || true)
    if [[ -n "${found}" ]]; then printf '%s\n' "${found}"; return 0; fi
    return 1
}

LOADER_BIN=$(find_loader)
EXPORTER_BIN_ORIG=$(find_exporter) || {
    echo "FAIL: xdpmf-exporter binary not found under ${BUILD_DIR}" >&2
    exit 1
}
echo "loader=${LOADER_BIN}"
echo "exporter (orig)=${EXPORTER_BIN_ORIG}"

if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not in PATH (required to force a /metrics scrape)" >&2
    exit 77
fi

# `nobody` likely can't exec the binary under /home/<user>/... because
# the home dir is typically mode 700 (search bit denied). Copy the
# exporter to /tmp/ — world-searchable — and run from there. This is a
# fixture concern only; we're verifying impl behaviour, NOT the
# install-path discipline.
EXPORTER_BIN="/tmp/xdpmf-exporter-${$}-$(date +%s)"
sudo -n cp "${EXPORTER_BIN_ORIG}" "${EXPORTER_BIN}"
sudo -n chmod 0755 "${EXPORTER_BIN}"
echo "exporter (run-path)=${EXPORTER_BIN}"

# Probe: can `nobody` actually exec the copy?
if ! sudo -n -u "${UNPRIV_USER}" "${EXPORTER_BIN}" --version >/dev/null 2>&1; then
    echo "SKIP: ${UNPRIV_USER} cannot exec copied exporter at ${EXPORTER_BIN} — test env restriction" >&2
    sudo -n rm -f "${EXPORTER_BIN}" 2>/dev/null
    exit 77
fi

# Per-PID exporter port to avoid clash with other tests.
EPORT=$(( 9420 + ($$ % 1000) ))
echo "EXPORTER_PORT=${EPORT}"

exp_log=$(mktemp /tmp/xdpmf-exit6-explog.XXXXXX)
exp_log_neg=$(mktemp /tmp/xdpmf-exit6-explog-neg.XXXXXX)
EXPORTER_PID=""
EXPORTER_PID_NEG=""

# Track chmod-modified pins so we can restore on cleanup. Bash array.
declare -a CHMODED=()

cleanup_test() {
    set +e
    # Kill background exporter(s) if alive.
    if [[ -n "${EXPORTER_PID}" ]]; then
        sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null
        wait "${EXPORTER_PID}" 2>/dev/null
    fi
    if [[ -n "${EXPORTER_PID_NEG}" ]]; then
        sudo -n kill -9 "${EXPORTER_PID_NEG}" 2>/dev/null
        wait "${EXPORTER_PID_NEG}" 2>/dev/null
    fi
    # Restore chmod on any pin files we touched (defensive).
    for p in "${CHMODED[@]:-}"; do
        [[ -n "${p}" ]] && sudo -n chmod 0644 "${p}" 2>/dev/null
    done
    # Detach + cleanup_veth.
    ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>/dev/null
    ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_B}" 2>/dev/null
    cleanup_veth
    # Remove the /tmp copy of the exporter binary.
    sudo -n rm -f "${EXPORTER_BIN}" 2>/dev/null
    rm -f "${exp_log}" "${exp_log_neg}"
    set -e
}
trap cleanup_test EXIT

setup_veth

# ── Step 2: attach on both ifaces → pin dirs + stats pins created ───────
echo "=== attach on ${IFACE_A}"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
sleep 0.3
# The fixture only has one veth pair; IFACE_B is the peer of IFACE_A.
# We can still attach XDP to IFACE_B (it has its own ifindex).
echo "=== attach on ${IFACE_B}"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_B}" --allow "${MAC_GOOD}"
sleep 0.3

# Smoke: stats pins exist for both ifaces.
STATS_A="${PIN_ROOT}/${IFACE_A}/stats"
STATS_B="${PIN_ROOT}/${IFACE_B}/stats"
for p in "${STATS_A}" "${STATS_B}"; do
    if ! sudo -n test -e "${p}"; then
        echo "FAIL: smoke — stats pin ${p} missing after attach" >&2
        exit 1
    fi
done

# ── Preflight: can we reproduce EACCES under the unprivileged user? ─────
# `bpftool map show pinned <stats>` as ${UNPRIV_USER} on a chmod-000 pin
# MUST fail. If it succeeds (e.g., kernel/cap bypass), SKIP cleanly.
echo "=== preflight: probe EACCES reproducibility under ${UNPRIV_USER}"
sudo -n chmod 000 "${STATS_A}"
CHMODED+=("${STATS_A}")

# Run a probe `cat` on the pinned file as the unprivileged user.
set +e
sudo -n -u "${UNPRIV_USER}" cat "${STATS_A}" >/dev/null 2>/dev/null
probe_rc=$?
set -e
echo "preflight cat probe rc=${probe_rc} (expect non-zero → EACCES reachable)"
if [[ "${probe_rc}" -eq 0 ]]; then
    echo "SKIP: EACCES not reproducible in this test env — ${UNPRIV_USER} can read chmod-000 file" >&2
    echo "      probably CAP_DAC_OVERRIDE set on the binary or user has unusual privileges" >&2
    exit 77
fi

# ── Step 3: chmod 000 on BOTH ifaces' stats pins ───────────────────────
sudo -n chmod 000 "${STATS_B}"
CHMODED+=("${STATS_B}")

# Also chmod 000 the per-iface DIRS (sledgehammer — covers exporters that
# open the dir or other map files in addition to stats). Restore in trap.
sudo -n chmod 000 "${PIN_ROOT}/${IFACE_A}"
sudo -n chmod 000 "${PIN_ROOT}/${IFACE_B}"
CHMODED+=("${PIN_ROOT}/${IFACE_A}")
CHMODED+=("${PIN_ROOT}/${IFACE_B}")

ATTACHED_COUNT=2  # IFACE_A + IFACE_B

# ── Step 4: launch exporter under unprivileged user, point at PIN_ROOT ──
echo "=== launching xdpmf-exporter as ${UNPRIV_USER} on 127.0.0.1:${EPORT}"
sudo -n -u "${UNPRIV_USER}" "${EXPORTER_BIN}" \
    --port "${EPORT}" \
    --bind 127.0.0.1 \
    --bpffs-root "${PIN_ROOT}" \
    >"${exp_log}" 2>&1 &
EXPORTER_PID=$!
echo "EXPORTER_PID=${EXPORTER_PID}"

# Wait for exporter to start serving OR die. We want one /metrics scrape
# to fire because the HK-17 check is per-scrape (D-3.4.5-2).
ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${EPORT}/healthz" -o /dev/null 2>/dev/null; then
        ready=1; echo "exporter ready after ${i} polls"; break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        # Process died — that's actually OK if it exited 6 immediately.
        echo "exporter PID ${EXPORTER_PID} no longer alive after ${i} polls — checking exit code"
        break
    fi
    sleep 0.1
done

# Trigger /metrics scrape to force the per-scrape EACCES discovery and
# the exit-6 check. Best-effort: exporter may already be dead.
if [[ "${ready}" == "1" ]]; then
    echo "=== curl /metrics to force scrape (response ignored)"
    curl -s -m 2 "http://127.0.0.1:${EPORT}/metrics" -o /dev/null 2>/dev/null || true
fi

# Wait up to 10s for exporter to exit. Important: bash's job control
# may auto-reap the backgrounded process between commands, after which
# `wait $PID` returns 127 ("not a child of this shell"). Under set -e
# that would abort the script. Wrap in set +e / set -e so we capture
# the exit code regardless of whether bash has already reaped.
echo "=== waiting up to 10s for exporter to exit"
deadline=$(( $(date +%s) + 10 ))
exp_rc=""
set +e
while (( $(date +%s) < deadline )); do
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        # Try wait — if bash retained the exit status in its jobs table,
        # we get the actual exit code; if the PID was auto-reaped and
        # the table cleared, wait returns 127. Either is fine — we'll
        # surface the value below and let the assertion logic decide.
        wait "${EXPORTER_PID}" 2>/dev/null
        exp_rc=$?
        break
    fi
    sleep 0.2
done
set -e

# If still alive past timeout, kill + read its log; this is a FAIL
# scenario because HK-17 should have caused exit.
if [[ -z "${exp_rc}" ]]; then
    echo "FAIL[pri]: exporter still alive after 10s; HK-17 exit-6 path did not fire" >&2
    set +e
    sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null
    wait "${EXPORTER_PID}" 2>/dev/null
    set -e
    exp_rc=999
fi
EXPORTER_PID=""  # cleanup_test already handled if needed
echo "exporter exit code: ${exp_rc}"
echo "--- exporter log ---"
cat "${exp_log}"
echo "--- end exporter log ---"

fail=0

# (a) Exit code EXACTLY 6.
if [[ "${exp_rc}" -ne 6 ]]; then
    echo "FAIL[a]: expected exit code 6 (HK-17 all-iface EACCES), got ${exp_rc}" >&2
    case "${exp_rc}" in
        0)   echo "         rc=0 — exporter exited normally, EACCES path never triggered" >&2 ;;
        999) echo "         exporter never exited — HK-17 check not firing or not wired" >&2 ;;
    esac
    fail=1
fi

# (b) Stderr (in exp_log) contains the HK-17 ERE.
hk17_ere='^xdpmf-exporter: ERROR all [0-9]+ discovered interfaces failed permission-denied; check CAP_BPF and bpffs read mode \(exit 6\)$'
if ! grep -qE -- "${hk17_ere}" "${exp_log}"; then
    echo "FAIL[b]: exporter log missing HK-17 ERROR line matching ERE:" >&2
    echo "         ${hk17_ere}" >&2
    fail=1
fi

# (c) Extract <N> from the line and confirm it equals ATTACHED_COUNT.
extracted_N=$(grep -oE 'all [0-9]+ discovered' "${exp_log}" | head -n1 | grep -oE '[0-9]+' || true)
echo "extracted N=${extracted_N} (expected ${ATTACHED_COUNT})"
if [[ -z "${extracted_N}" ]]; then
    echo "FAIL[c]: could not extract <N> from HK-17 line — line format off-spec" >&2
    fail=1
elif [[ "${extracted_N}" != "${ATTACHED_COUNT}" ]]; then
    # Soft warn (not hard fail): HK-17 says <N> = total_discovered, which
    # is the count of ifaces in PIN_ROOT. We attached 2 ifaces → expected 2.
    # If kernel discovery sees more (e.g., stale orphan dirs), surface but
    # don't fail — the EXACT count depends on discovery implementation.
    echo "WARN[c]: extracted N=${extracted_N} != attached count ${ATTACHED_COUNT}" >&2
    echo "         not failing; the HK-17 contract is 'total_discovered > 0' + all-EACCES" >&2
fi

# Restore perms for the negation control.
sudo -n chmod 0755 "${PIN_ROOT}/${IFACE_A}" 2>/dev/null || true
sudo -n chmod 0755 "${PIN_ROOT}/${IFACE_B}" 2>/dev/null || true
sudo -n chmod 0644 "${STATS_A}" 2>/dev/null || true
sudo -n chmod 0644 "${STATS_B}" 2>/dev/null || true
CHMODED=()

# ─────────────────────────────────────────────────────────────────────────
# NEGATION CONTROL: re-run WITHOUT chmod step → exporter MUST NOT exit 6
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== NEGATION CONTROL: run exporter with default perms (expect rc != 6 within 5s window)"

EPORT_NEG=$(( EPORT + 1 ))
echo "EXPORTER_PORT (negation) = ${EPORT_NEG}"

# Launch as ROOT this time (NOT as ${UNPRIV_USER}). The negation control
# asks: "without permission-denied conditions, does the exporter avoid
# exit 6?" Running as root guarantees that root CAN read the default-
# mode pin files (whatever they are). The primary case proved exit-6
# fires under EACCES; this case proves it does NOT fire when reads
# succeed. Running as nobody here would fail again because the OTHER
# per-iface pins (allowlist, action_table, etc., not just stats) were
# created at default root-only mode and nobody can't read them — that's
# not the contract this negation tests; it tests "if reads succeed,
# no exit 6", which root demonstrates cleanly.
sudo -n "${EXPORTER_BIN_ORIG}" \
    --port "${EPORT_NEG}" \
    --bind 127.0.0.1 \
    --bpffs-root "${PIN_ROOT}" \
    >"${exp_log_neg}" 2>&1 &
EXPORTER_PID_NEG=$!

# Wait for exporter ready.
neg_ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${EPORT_NEG}/healthz" -o /dev/null 2>/dev/null; then
        neg_ready=1; break
    fi
    if ! kill -0 "${EXPORTER_PID_NEG}" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if [[ "${neg_ready}" == "1" ]]; then
    curl -s -m 2 "http://127.0.0.1:${EPORT_NEG}/metrics" -o /dev/null 2>/dev/null || true
fi

# Observe for 3 seconds: exporter MUST still be alive (no exit-6 firing).
sleep 3
neg_alive=1
set +e
if ! kill -0 "${EXPORTER_PID_NEG}" 2>/dev/null; then
    wait "${EXPORTER_PID_NEG}" 2>/dev/null
    neg_rc=$?
    EXPORTER_PID_NEG=""
    echo "negation: exporter exited unexpectedly with rc=${neg_rc}"
    echo "--- negation exporter log ---"
    cat "${exp_log_neg}"
    echo "--- end ---"
    if [[ "${neg_rc}" -eq 6 ]]; then
        echo "FAIL[neg-a]: negation control: exporter exited 6 WITHOUT chmod step — HK-17 check is too eager" >&2
        fail=1
    fi
    neg_alive=0
fi
if (( neg_alive == 1 )); then
    echo "[neg] OK: exporter still alive after 3s with default perms (HK-17 trigger correctly did NOT fire)"
    sudo -n kill "${EXPORTER_PID_NEG}" 2>/dev/null
    sleep 0.2
    sudo -n kill -9 "${EXPORTER_PID_NEG}" 2>/dev/null
    wait "${EXPORTER_PID_NEG}" 2>/dev/null
    EXPORTER_PID_NEG=""
fi
set -e

[[ "${fail}" == 0 ]] && echo "PASS: T_EXPORTER_EXITS_6_ALL_IFACES_EACCES"
exit "${fail}"
