#!/bin/bash
# T_ANDEXT_TRUNCATED_MALFORMED — design §5.55 TestStrategy test 2 (MVP-4.15 / S6).
#
# The mid-walk bounds-miss MALFORMED path. The S6 ext-header walk bounds-checks
# every hop (verifier-mandated, no OOB). A v6 frame whose extension-header chain
# declares a `nexthdr` pointing at a header that was truncated away triggers a
# per-hop bounds-check miss -> STAT_DROP_MALFORMED + XDP_DROP (D-mvp-4.15-Q2-
# MALFORMED, extending the v6 base-header bounds-miss semantic to the chain).
#
# Construction (deterministic, scapy-default sizes):
#   full frame = Ether(14) + IPv6(40) + HopByHop(8) + DestOpt(8) + TCP(20) = 90B.
#   --truncate 28 drops the trailing 28 bytes (= TCP 20 + DestOpt 8), leaving
#   Ether + IPv6 + HopByHop = 62 bytes on the wire (62 > ETH_ZLEN 60, so the
#   kernel does NOT zero-pad it back). The HopByHop header's nexthdr says
#   "DestOpt follows", but DestOpt's bytes are gone — so when the walk advances
#   past HopByHop and bounds-checks the DestOpt header, `cursor + sizeof(opt) >
#   data_end` fires -> DROP_MALFORMED. The 2-hop chain guarantees a true mid-walk
#   EXT bounds-miss (not a mere L4 cutoff, which would be has_port=0, not
#   malformed).
#
# Observable: STAT_DROP_MALFORMED delta == 1; PASS-class delta == 0; DROP_DENY
#   delta == 0. NO OOB (the prod .bpf.o already loaded clean — the verifier
#   guarantees it; this test asserts the SEMANTIC, the verifier asserts safety).
#
# Sanity floor:
#   * SMOKE         — apply exit 0; stats pin reachable.
#   * FAILURE-PATH  — the malformed-delta==1 assertion IS the failure-path
#                     control: a walk that did NOT detect the truncated chain
#                     would route the frame to default pass (pass-delta==1) and
#                     this test goes RED. Proves the bounds-check actually fires.
#
# Environment caveat (mirrors T_DROP_MALFORMED): if NO counter bumps the frame
# never reached XDP (raw send rejected) -> SKIP (77), NOT a silent pass.
#
# Maps to: PI-mvp-4.15-MALFORMED.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/andext.yaml"
INJECT="${INJECT_L6:-${TEST_DIR}/inject/inject_l6.py}"
DST6="2001:db8:aaaa::1"
SRC6="2001:db8:bbbb::2"
TRUNCATE=28   # = TCP(20) + DestOpt(8); leaves Ether+IPv6+HopByHop = 62B (>60)

for f in "${FIXTURE}" "${INJECT}"; do
    [[ -f "${f}" ]] || { echo "FAIL: missing ${f}" >&2; exit 1; }
done

if ! ${NSEXEC:-sudo -n} python3 -c 'import scapy' 2>/dev/null \
     && ! python3 -c 'import scapy' 2>/dev/null; then
    echo "SKIP: scapy not importable (inject_l6.py prerequisite)" >&2
    exit 77
fi

stderr_file=$(mktemp /tmp/xdpmf-andextmal-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

${NSEXEC} ethtool -K "${IFACE_A}" rxvlan off txvlan off 2>/dev/null || true
${NSEXEC} ethtool -K "${IFACE_B}" rxvlan off txvlan off 2>/dev/null || true

# ── apply + smoke ────────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
cat "${stderr_file}" >&2 || true
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[smoke]: apply exit ${rc} (expected 0)" >&2; exit 1
fi
sudo -n test -e "${PIN_DIR}/stats" \
    || { echo "FAIL[smoke]: ${PIN_DIR}/stats pin missing after apply" >&2; exit 1; }
echo "smoke OK: apply exit 0; stats reachable"

# ── inject the truncated ext-bearing frame ─────────────────────────────────
echo "=== inject ext hbh+dstopt tcp/443 --truncate ${TRUNCATE} (chain declares DestOpt, bytes truncated away)"
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
${NSEXEC} python3 "${INJECT}" "${IFACE_B}" \
    --dst-ip "${DST6}" --src-ip "${SRC6}" --proto tcp --dport 443 \
    --dst-mac "${MAC_DST}" --ext hbh --ext dstopt --truncate "${TRUNCATE}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true
read -r p1 d1 m1 c1 < <(read_stats_with_cidr)

mal_delta=$(( m1 - m0 ))
deny_delta=$(( d1 - d0 ))
pass_delta=$(( (p1 - p0) + (c1 - c0) ))
echo "stats delta: MALFORMED=${mal_delta} DROP_DENY=${deny_delta} PASS-class=${pass_delta}"

# Success: exactly one malformed drop, nothing else.
if (( mal_delta == 1 && deny_delta == 0 && pass_delta == 0 )); then
    echo "PASS: T_ANDEXT_TRUNCATED_MALFORMED (mid-walk bounds-miss -> DROP_MALFORMED)"
    exit 0
fi

# A PASS- or DENY-class bump means the truncated chain was NOT caught as
# malformed — the walk failed to bounds-check the absent DestOpt header. That is
# a real PI-mvp-4.15-MALFORMED violation (or an OOB the verifier would have
# rejected — but the prod object loaded, so it must be the missing semantic).
if (( pass_delta >= 1 || deny_delta >= 1 )); then
    echo "FAIL: truncated ext chain was NOT dropped as malformed" >&2
    echo "      MALFORMED=${mal_delta} DROP_DENY=${deny_delta} PASS-class=${pass_delta}" >&2
    echo "      expected MALFORMED=1; a PASS/DENY bump means the per-hop bounds-check did not fire" >&2
    echo "      (PI-mvp-4.15-MALFORMED / D-mvp-4.15-Q2-MALFORMED)" >&2
    exit 1
fi

if (( mal_delta > 1 )); then
    echo "FAIL: STAT_DROP_MALFORMED=${mal_delta} from a single frame (expected 1)" >&2
    exit 1
fi

# Nothing bumped: the raw truncated frame never reached XDP (kernel rejected the
# send). Per the §6.5 environment-skip discipline, SKIP rather than silently pass.
echo "SKIP: environment did not deliver the truncated frame to XDP" >&2
echo "      observed delta: MALFORMED=${mal_delta} DROP_DENY=${deny_delta} PASS-class=${pass_delta}" >&2
echo "      (raw L2 send likely rejected before XDP ingest; malformed path is assertable in a delivering env)" >&2
exit 77
