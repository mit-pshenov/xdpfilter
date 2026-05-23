#!/bin/bash
# T_ATTACH_ALIEN_REFUSAL — design §6.9 (MVP-1.1B).
#
# Closes hybrid-review.md testing MEDIUM M1: prove the §5.4 state-(c)
# alien-refusal path (LoaderError::AttachRefusedAlien, exit 4) is
# reachable end-to-end from a real fixture, AND that the §5.19 identity
# verification correctly rejects a foreign program even when that
# program is attached in our same SKB-mode family.
#
# Trigger (sequential):
#   1. setup_veth — fresh veth_a/veth_b pair (helper from tests/lib/common.sh).
#   2. Pre-attach foreign XDP (xdp_pass.bpf.o, function name `xdp_pass_prog`)
#      to veth_a in generic (SKB) mode via `ip link set … xdpgeneric obj …`.
#   3. Capture the foreign prog id (xdp_prog_id helper).
#   4. Run our loader: `xdpmacfilter attach --iface veth_a --allow MAC_GOOD`,
#      capturing exit code (rc) and stderr.
#
# Outcome (ALL four must hold — fail aggregator pattern from
# T_IDEMPOTENT_RELOAD):
#   (a) rc == 4 — LoaderError::AttachRefusedAlien (§4.1 exit table).
#   (b) stderr contains the foreign prog id as a substring (§5.19 message
#       contract names the foreign prog id; only the id is asserted —
#       mode/name strings are impl-shape, not contract-shape).
#   (c) Foreign program STILL attached, prog id unchanged — the
#       safety-floor assertion (KC-A spoofed-ours blackhole did NOT fire;
#       loader did not clobber the alien program).
#   (d) No orphan pin dir at /sys/fs/bpf/xdpmacfilter/veth_a/ — refusal
#       happens before ensure_bpffs_dir OR the RAII rollback unwinds it.
#
# Cleanup (trap EXIT, idempotent): detach foreign xdpgeneric, then
# standard cleanup_veth (also wipes any pin dir + the veth pair).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)
FOREIGN_OBJ="${BUILD_DIR}/xdp_pass.bpf.o"
stderr_file=$(mktemp /tmp/xdpmf-alien-stderr.XXXXXX)

cleanup_alien() {
    set +e
    # Detach the foreign XDP before veth deletion (defensive; cleanup_veth
    # also kills the iface, which implicitly detaches XDP, but be explicit
    # so a future cleanup_veth refactor can't silently change behaviour).
    sudo ip link set "${IFACE_A}" xdpgeneric off 2>/dev/null
    cleanup_veth
    rm -f "${stderr_file}"
    set -e
}
trap cleanup_alien EXIT

# Sanity: the fixture must exist as a build artifact (per
# tests/CMakeLists.txt:add_bpf_object(xdp_pass …)). Hard failure if
# missing — design §6.9 explicitly forbids SKIP semantics here.
[[ -f "${FOREIGN_OBJ}" ]] \
    || { echo "FAIL: foreign-XDP fixture missing at ${FOREIGN_OBJ}" >&2
         echo "       (expected build artifact from add_bpf_object xdp_pass)" >&2
         exit 1; }

setup_veth

echo "=== pre-attach foreign XDP (xdp_pass_prog) on ${IFACE_A} via xdpgeneric"
sudo ip link set "${IFACE_A}" xdpgeneric obj "${FOREIGN_OBJ}" sec xdp
# Let the attach settle (verifier+JIT, netlink ack).
sleep 0.2

foreign_id=$(xdp_prog_id "${IFACE_A}")
if [[ -z "${foreign_id}" || "${foreign_id}" == "0" ]]; then
    echo "FAIL: foreign-attach step left no XDP prog id on ${IFACE_A}" >&2
    echo "      (the fixture failed before our loader was invoked — not our bug)" >&2
    ip -j link show "${IFACE_A}" >&2
    exit 1
fi
echo "foreign prog id = ${foreign_id}"

echo "=== invoke our loader (expect exit 4 — AttachRefusedAlien)"
set +e
sudo "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"
rc=$?
set -e
echo "loader rc=${rc}"
echo "--- captured stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

fail=0

# (a) Exit code must be 4.
if [[ "${rc}" != 4 ]]; then
    echo "FAIL: expected rc=4 (AttachRefusedAlien), got rc=${rc}" >&2
    case "${rc}" in
        0) echo "       rc=0 means KC-A regression: loader CLOBBERED the foreign program" >&2 ;;
        3) echo "       rc=3 means KC-B regression: SKB-mode foreign prog mis-classified as AttachFailed" >&2 ;;
    esac
    fail=1
fi

# (b) stderr must name the foreign prog id (literal substring; -F end-of-options safe).
if ! grep -q -F -- "${foreign_id}" "${stderr_file}"; then
    echo "FAIL: stderr does not mention foreign prog id ${foreign_id}" >&2
    fail=1
fi

# (c) Foreign program must STILL be attached, byte-identical id.
now_id=$(xdp_prog_id "${IFACE_A}")
if [[ "${now_id}" != "${foreign_id}" ]]; then
    echo "FAIL: foreign XDP clobbered (was ${foreign_id}, now '${now_id}')" >&2
    fail=1
fi

# (d) No orphan pin dir.
if [[ -e "${PIN_DIR}" ]]; then
    echo "FAIL: orphan pin dir ${PIN_DIR} remained after refusal" >&2
    sudo ls -la "${PIN_DIR}" >&2 || true
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_ATTACH_ALIEN_REFUSAL"
exit "${fail}"
