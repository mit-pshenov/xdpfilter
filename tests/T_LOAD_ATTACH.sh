#!/bin/bash
# T_LOAD_ATTACH — design §6.2: load+attach succeeds (acceptance #2).
#
# Trigger : set up veth pair; run `xdpfilter attach --iface veth_a
#           --allow MAC_GOOD`.
# Outcome : exit 0; xdp.prog.id is set on veth_a; both pinned maps exist.
#
# This test doubles as the smoke test of the sanity floor — if the
# loader binary cannot even attach a program, none of the functional
# tests below mean anything.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
echo "loader=${LOADER_BIN}"

trap cleanup_veth EXIT
setup_veth

${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"

# Allow the attach to settle (verifier+JIT, link netlink ack).
sleep 0.3

# /sys/fs/bpf may be mode 1700 (root-only traversal) on some hosts —
# gate the existence check via `sudo -n test` so it works regardless of
# bpffs perms.
sudo -n test -e "${PIN_DIR}/allowlist_a" \
    || { echo "FAIL: ${PIN_DIR}/allowlist_a pin missing" >&2; exit 1; }
# Negation control (MVP-4.18): the legacy single-pin alias must be GONE.
! sudo -n test -e "${PIN_DIR}/allowlist" \
    || { echo "FAIL: legacy ${PIN_DIR}/allowlist pin must NOT exist after MVP-4.18 removal" >&2; exit 1; }
sudo -n test -e "${PIN_DIR}/stats" \
    || { echo "FAIL: ${PIN_DIR}/stats pin missing"     >&2; exit 1; }

prog_id=$(xdp_prog_id "${IFACE_A}")
[[ -n "${prog_id}" ]] \
    || { echo "FAIL: no XDP prog id reported by ip -j on ${IFACE_A}" >&2
         ${NSEXEC} ip -j link show "${IFACE_A}" >&2
         exit 1; }

echo "PASS: T_LOAD_ATTACH (prog_id=${prog_id})"
