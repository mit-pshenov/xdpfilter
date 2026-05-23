#!/bin/bash
# T_MODE_GENERIC_DEFAULT — design §6.16 (MVP-2 Perf / §5.23 Q1).
#
# Closes the implicit-default-mode question: `--mode` flag, when omitted,
# MUST default to XdpMode::Generic (SKB mode) to preserve the MVP-1
# baseline behaviour that §6.3-§6.8 depend on. End-to-end assertion that
# `attach` without --mode lands the program in generic (SKB) mode.
#
# Trigger (sequential):
#   1. setup_veth — standard fresh ${IFACE_A}/${IFACE_B} pair.
#   2. xdpmacfilter attach --iface ${IFACE_A} --allow ${MAC_GOOD}
#      (NO --mode flag — exercises the default).
#   3. Probe attached mode via `ip -j link show ${IFACE_A}` + jq.
#
# Outcome (ALL must hold):
#   (a) Step 2 exits 0.
#   (b) Attached XDP mode is generic OR xdpgeneric (kernel-version variance).
#   (c) ${PIN_DIR}/{allowlist,stats} both exist.
#
# Cleanup (trap EXIT, idempotent): detach (NO --mode per Q1 Option A) +
# cleanup_veth.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
echo "loader=${LOADER_BIN}"

cleanup_test() {
    set +e
    ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" >/dev/null 2>&1
    cleanup_veth
    set -e
}
trap cleanup_test EXIT

setup_veth

echo "=== attach without --mode (expect default = generic/SKB)"
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"

# Let the attach settle (verifier+JIT, netlink ack).
sleep 0.3

fail=0

# (a) Exit 0 already confirmed (set -e would have aborted on rc!=0). No
# explicit check needed beyond this point — we got past the attach call.

# (b) Mode probe via ip -j link show.  Three kernel/iproute2 schemas
# observed (per Phase B investigation, libbpf 1.1.2 / kernel 6.x hosts):
#   * Newer schema:  .xdp.attached[*].mode   (with .xdp.mode mirror)
#   * Older schema:  .xdp.mode               (no .attached array)
#   * Numeric form:  mode = 2  (= XDP_ATTACHED_SKB enum value from
#                   uapi/linux/if_link.h: NONE=0, DRV=1, SKB=2, HW=3,
#                   MULTI=4).  This host emits the numeric form
#                   (kernel/iproute2 combo dependent).
# Per §6.16: "accept both generic and xdpgeneric for kernel-version
# variance" — extended here to ALSO accept numeric 2 (the same enum
# value the string form names), since iproute2's JSON output diverges
# from its text output.  All three forms denote XDP_ATTACHED_SKB, which
# is what §5.23 Q1 + §5.6 default = Generic must produce.
mode=$(${NSEXEC} ip -j link show "${IFACE_A}" 2>/dev/null \
    | jq -r '.[0].xdp.attached[]?.mode // .[0].xdp.mode // empty' \
    | head -n1)
echo "probed mode='${mode}'"
case "${mode}" in
    generic|xdpgeneric|2)
        echo "OK: mode='${mode}' matches generic/SKB expectation (XDP_ATTACHED_SKB)"
        ;;
    "")
        echo "FAIL: ip -j link show ${IFACE_A} reported no XDP mode" >&2
        ${NSEXEC} ip -j link show "${IFACE_A}" >&2 || true
        fail=1
        ;;
    1|native|xdpdrv)
        echo "FAIL: mode='${mode}' is NATIVE/DRV — regression: default should be SKB/generic" >&2
        ${NSEXEC} ip -j link show "${IFACE_A}" >&2 || true
        fail=1
        ;;
    3|offload|xdpoffload)
        echo "FAIL: mode='${mode}' is HW/offload — regression: default should be SKB/generic" >&2
        ${NSEXEC} ip -j link show "${IFACE_A}" >&2 || true
        fail=1
        ;;
    *)
        echo "FAIL: expected generic|xdpgeneric|2, got '${mode}'" >&2
        echo "      regression: default mode is no longer SKB-class" >&2
        ${NSEXEC} ip -j link show "${IFACE_A}" >&2 || true
        fail=1
        ;;
esac

# (c) Both pinned maps must exist (gate via sudo for bpffs mode 1700).
if ! sudo -n test -e "${PIN_DIR}/allowlist"; then
    echo "FAIL: ${PIN_DIR}/allowlist pin missing after default-mode attach" >&2
    fail=1
fi
if ! sudo -n test -e "${PIN_DIR}/stats"; then
    echo "FAIL: ${PIN_DIR}/stats pin missing after default-mode attach" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_MODE_GENERIC_DEFAULT (mode=${mode})"
exit "${fail}"
