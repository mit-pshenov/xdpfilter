#!/bin/bash
# tests/lib/common.sh — shared fixture helpers, sourced by test scripts.
#
# Provides:
#   IFACE_A / IFACE_B / MAC_GOOD / MAC_BAD / MAC_DST   (design §6 constants)
#   PIN_ROOT / PIN_DIR
#   find_loader               → echoes path of xdpmacfilter binary
#   setup_veth                → fresh veth_a/veth_b pair, both UP
#   cleanup_veth              → wipe veth + pin dir (idempotent, suitable for trap)
#   read_stats <pin>          → echoes "<pass> <drop_deny> <drop_malformed>"
#   inject_eth <iface> <src> <dst>            → scapy-based Ethernet frame
#   inject_runt <iface>                       → sub-14-byte raw frame
#
# Env consumed (set by ctest):
#   BUILD_DIR / SOURCE_DIR / TEST_DIR

set -euo pipefail

# ── Constants per design §6 TestStrategy ──────────────────────────────────
IFACE_A=veth_a
IFACE_B=veth_b
MAC_GOOD="02:00:00:00:00:01"
MAC_BAD="02:00:00:00:00:02"
MAC_DST="ff:ff:ff:ff:ff:ff"
PIN_ROOT=/sys/fs/bpf/xdpmacfilter
PIN_DIR=${PIN_ROOT}/${IFACE_A}

# ── Locate the loader binary in BUILD_DIR ─────────────────────────────────
find_loader() {
    if [[ -n "${LOADER:-}" && -x "${LOADER}" ]]; then
        printf '%s\n' "${LOADER}"; return 0
    fi
    local cand
    for cand in \
        "${BUILD_DIR}/xdpmacfilter" \
        "${BUILD_DIR}/src/loader/xdpmacfilter" \
        "${BUILD_DIR}/loader/xdpmacfilter" \
        "${BUILD_DIR}/bin/xdpmacfilter" \
        "${BUILD_DIR}/src/xdpmacfilter"; do
        if [[ -x "$cand" ]]; then printf '%s\n' "$cand"; return 0; fi
    done
    local found
    found=$(find "${BUILD_DIR}" -maxdepth 5 -type f -executable -name xdpmacfilter 2>/dev/null | head -1 || true)
    if [[ -n "${found}" ]]; then printf '%s\n' "${found}"; return 0; fi
    echo "ERROR: xdpmacfilter binary not found under ${BUILD_DIR}" >&2
    return 1
}

# ── Fixture lifecycle ─────────────────────────────────────────────────────
setup_veth() {
    # Idempotent: wipe any prior state first.
    sudo ip link del "${IFACE_A}" 2>/dev/null || true
    sudo rm -rf "${PIN_DIR}"     2>/dev/null || true

    sudo ip link add "${IFACE_A}" type veth peer name "${IFACE_B}"

    # Suppress kernel-emitted background traffic on the veth pair so
    # that exact-equality stat assertions are not polluted.  Diagnosis
    # of an earlier failing run: a fresh veth up emits ≈12 IPv6
    # MLDv2/RS/NS/LLMNR frames within the first second.  We:
    #   1) disable IPv6 autoconf BEFORE the iface goes up (so no
    #      link-local address is generated → no DAD, no MLD, no RS),
    #   2) set addrgen mode = none,
    #   3) turn ARP off (raw L2 frames don't need it).
    sudo sysctl -w "net.ipv6.conf.${IFACE_A}.disable_ipv6=1" >/dev/null 2>&1 || true
    sudo sysctl -w "net.ipv6.conf.${IFACE_B}.disable_ipv6=1" >/dev/null 2>&1 || true
    sudo ip link set "${IFACE_A}" addrgenmode none 2>/dev/null || true
    sudo ip link set "${IFACE_B}" addrgenmode none 2>/dev/null || true
    sudo ip link set "${IFACE_A}" arp off          2>/dev/null || true
    sudo ip link set "${IFACE_B}" arp off          2>/dev/null || true

    sudo ip link set "${IFACE_A}" up
    sudo ip link set "${IFACE_B}" up

    # Per pack idiom: rp_filter can drop frames before XDP runs.
    sudo sysctl -w "net.ipv4.conf.${IFACE_A}.rp_filter=0" >/dev/null 2>&1 || true
    sudo sysctl -w "net.ipv4.conf.${IFACE_B}.rp_filter=0" >/dev/null 2>&1 || true
    sudo sysctl -w "net.ipv4.conf.all.rp_filter=0"        >/dev/null 2>&1 || true

    # Let any residual chatter quiesce BEFORE XDP attaches; anything
    # that fires now is invisible to the BPF program (not attached yet).
    sleep 0.5
}

cleanup_veth() {
    set +e
    # Deleting one veth end removes the peer too, and implicitly detaches XDP.
    sudo ip link del "${IFACE_A}" 2>/dev/null
    sudo rm -rf "${PIN_DIR}"     2>/dev/null
    set -e
}

# ── Stats reader (delegates to read_stats.py) ─────────────────────────────
# Echoes 3 space-separated u64 counters: pass drop_deny drop_malformed
read_stats() {
    local pin="${1:-${PIN_DIR}/stats}"
    sudo python3 "${TEST_DIR}/lib/read_stats.py" "${pin}"
}

# ── Frame injection (scapy / raw AF_PACKET) ──────────────────────────────
# inject_eth <iface> <src_mac> <dst_mac>
inject_eth() {
    local iface="$1" src="$2" dst="$3"
    sudo python3 "${TEST_DIR}/inject/inject_eth.py" "${iface}" "${src}" "${dst}"
}

# inject_runt <iface> — sub-14-byte frame for malformed-frame test.
inject_runt() {
    local iface="$1"
    sudo python3 "${TEST_DIR}/inject/inject_runt.py" "${iface}"
}

# ── XDP-on-iface query ────────────────────────────────────────────────────
# Echoes the attached XDP prog id, or empty string if none.
xdp_prog_id() {
    local iface="$1"
    ip -j link show "${iface}" 2>/dev/null | jq -r '
        .[0]
        | (.xdp.prog.id // .xdp.attached[]?.prog.id // empty)
    ' | head -n1
}

# ── BPF prog count snapshot (for idempotency assertion) ──────────────────
prog_count() {
    sudo bpftool prog show --json 2>/dev/null | jq 'length'
}
