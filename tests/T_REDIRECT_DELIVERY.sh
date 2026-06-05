#!/bin/bash
# T_REDIRECT_DELIVERY — design §5.75.6 SELECT-B (THE headline delivery oracle).
#
# Written against the SPECIFICATION (design.md §5.75.4 Interfaces + §5.75.6
# TestStrategy), NOT against impl's classifier/loader edits. This is the
# irreducible proof that the new `redirect` verb PHYSICALLY DIVERTS a matched
# frame out the configured steering target — not merely that the classifier
# decided to redirect (STAT_REDIRECT alone would prove only the decision).
#
# Topology (§5.75.4): xdpfilter on IFACE_A (frames injected on IFACE_B → RX
# on IFACE_A); steering.redirect_to = IFACE_C (devmap[0]=ifindex(IFACE_C));
# the counting sink (sink_xdp.bpf.o) attached on IFACE_D, the peer of IFACE_C.
# A frame the datapath redirects out IFACE_C egresses there and arrives RX on
# IFACE_D → the sink bumps its counter. read_sink reading non-zero is the
# delivery proof; STAT_REDIRECT proves the verdict; the unchanged PASS/DROP
# columns prove the redirect verdict was TERMINAL (original not also passed).
#
# Trigger (§5.75.6 SELECT-B):
#   1. setup_veth + setup_redirect_sink (both veth pairs; sink on IFACE_D).
#   2. apply a config with a `redirect`-action MAC rule + steering target
#      IFACE_C (config generated at runtime — the target iface name is
#      PID-suffixed).
#   3. Inject ONE redirect-matching frame (src_mac == the rule's MAC) on
#      IFACE_B.
#
# Observable outcome (ALL must hold):
#   (a) apply exit 0  (smoke).
#   (b) redirect_devmap pin exists + sink prog attached on IFACE_D (smoke).
#   (c) sink counter delta == 1   — the divert PHYSICALLY LANDED on IFACE_D.
#   (d) STAT_REDIRECT delta == 1  — the redirect verdict fired once.
#   (e) STAT_PASS / STAT_PASS_CIDR / STAT_DROP_DENY deltas == 0 — the redirect
#       was terminal; the original frame did NOT also take a pass/drop verdict.
#
# Sanity-floor smoke: (a)+(b) — apply succeeds AND the redirect map + sink
# materialize. Without them the delivery assertions are unreachable.
# Negation control: a frame with a NON-matching src MAC (default_action drop)
# must NOT bump the sink (delta 0) and must NOT bump STAT_REDIRECT (delta 0) —
# it lands in STAT_DROP_DENY instead. If the datapath redirected unconditionally
# (always-redirect bug), the sink would bump here too; the differential is the
# anti-theatricality fence (a sink that can only ever increment proves nothing).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v bpftool >/dev/null 2>&1; then
    echo "SKIP: bpftool not in PATH (required to load the sink + dump maps)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
SINK_OBJ="${BUILD_DIR}/sink_xdp.bpf.o"
[[ -f "${SINK_OBJ}" ]] \
    || { echo "FAIL: sink fixture missing at ${SINK_OBJ}" >&2
         echo "      (expected build artifact from add_bpf_object sink_xdp)" >&2
         exit 1; }

cfg_file=$(mktemp /tmp/xdpmf-redir-deliv-cfg.XXXXXX.yaml)
stderr_file=$(mktemp /tmp/xdpmf-redir-deliv-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${cfg_file}" "${stderr_file}"' EXIT

REDIR_MAC="02:00:00:00:00:01"   # matches the redirect rule
NONMATCH_MAC="02:00:00:00:00:02" # negation — falls to default_action: drop
SRC_IP="10.0.0.5"

setup_veth
setup_redirect_sink

# ── Generate the redirect config (steering target = PID-suffixed IFACE_C) ──
cat > "${cfg_file}" <<EOF
# Runtime-generated redirect fixture for T_REDIRECT_DELIVERY (§5.75.6).
schema_version: 3
default_action: drop
steering:
  redirect_to: ${IFACE_C}
rules:
  - id: 0
    action: redirect
    match:
      mac: "${REDIR_MAC}"
EOF

echo "=== apply redirect config on ${IFACE_A} (redirect_to=${IFACE_C})"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${cfg_file}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
echo "--- stderr ---"; cat "${stderr_file}" >&2 || true; echo "--- end stderr ---"

fail=0

# ── (a) apply exit 0 ─────────────────────────────────────────────────────
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[a]: apply exit ${rc} (expected 0)" >&2
    fail=1
fi

# ── (b) smoke: redirect_devmap pin + sink attached ───────────────────────
if ! sudo -n test -e "${PIN_DIR}/redirect_devmap"; then
    echo "FAIL[b.map]: expected pin ${PIN_DIR}/redirect_devmap missing" >&2
    fail=1
fi
sink_id=$(xdp_prog_id "${IFACE_D}")
if [[ -z "${sink_id}" || "${sink_id}" == "0" ]]; then
    echo "FAIL[b.sink]: no XDP sink prog attached on ${IFACE_D}" >&2
    fail=1
fi
# If the smoke floor failed the delivery assertions are meaningless.
if (( fail != 0 )); then
    echo "FAIL: smoke floor failed; aborting before delivery assertions" >&2
    exit 1
fi

# ── Baselines ────────────────────────────────────────────────────────────
read -r p0 d0 m0 c0 r0 < <(read_stats_with_redirect)
s0=$(read_sink)
echo "baseline: PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0} PASS_CIDR=${c0} REDIRECT=${r0} SINK=${s0}"

# ── Inject ONE redirect-matching frame ───────────────────────────────────
echo "=== inject matching frame src_mac=${REDIR_MAC} on ${IFACE_B}"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${REDIR_MAC}" "${MAC_DST}" "${SRC_IP}"

# Redirect is a terminal verdict counted in STAT_REDIRECT → the 5-column sum
# advances by exactly 1; poll for that, then poll the sink for delivery.
wait_for_stats_sum_with_redirect "${IFACE_A}" $(( p0 + d0 + m0 + c0 + r0 + 1 )) || true
wait_for_sink $(( s0 + 1 )) || true

read -r p1 d1 m1 c1 r1 < <(read_stats_with_redirect)
s1=$(read_sink)
echo "after match: PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1} PASS_CIDR=${c1} REDIRECT=${r1} SINK=${s1}"

# ── (c) sink delivery — THE headline proof ───────────────────────────────
if (( s1 - s0 != 1 )); then
    echo "FAIL[c.sink]: sink counter delta=$(( s1 - s0 )) (expected 1)" >&2
    echo "             the redirected frame did NOT physically land on ${IFACE_D};" >&2
    echo "             the verb may DECIDE to redirect without actually diverting." >&2
    fail=1
fi
# ── (d) STAT_REDIRECT verdict ────────────────────────────────────────────
if (( r1 - r0 != 1 )); then
    echo "FAIL[d.redirect]: STAT_REDIRECT delta=$(( r1 - r0 )) (expected 1)" >&2
    fail=1
fi
# ── (e) redirect was terminal — original PASS/DROP slots unmoved ─────────
if (( p1 - p0 != 0 )); then
    echo "FAIL[e.pass]: STAT_PASS moved on a redirect (delta $(( p1 - p0 )))" >&2
    fail=1
fi
if (( c1 - c0 != 0 )); then
    echo "FAIL[e.pass_cidr]: STAT_PASS_CIDR moved on a redirect (delta $(( c1 - c0 )))" >&2
    fail=1
fi
if (( d1 - d0 != 0 )); then
    echo "FAIL[e.drop]: STAT_DROP_DENY moved on a redirect (delta $(( d1 - d0 )))" >&2
    fail=1
fi

# ── NEGATION CONTROL: non-matching MAC → drop, NOT redirect, sink unmoved ─
echo
echo "=== NEGATION: inject non-matching frame src_mac=${NONMATCH_MAC} (default drop)"
read -r p2 d2 m2 c2 r2 < <(read_stats_with_redirect)
s2=$(read_sink)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${NONMATCH_MAC}" "${MAC_DST}" "${SRC_IP}"
wait_for_stats_sum_with_redirect "${IFACE_A}" $(( p2 + d2 + m2 + c2 + r2 + 1 )) || true
# Give any (erroneous) delivery a chance to register before asserting absence.
sleep 0.3

read -r p3 d3 m3 c3 r3 < <(read_stats_with_redirect)
s3=$(read_sink)
echo "after non-match: PASS=${p3} DROP_DENY=${d3} DROP_MALFORMED=${m3} PASS_CIDR=${c3} REDIRECT=${r3} SINK=${s3}"

if (( s3 - s2 != 0 )); then
    echo "FAIL[neg.sink]: sink bumped on a NON-matching frame (delta $(( s3 - s2 )))" >&2
    echo "               the datapath is redirecting unconditionally (always-redirect bug)." >&2
    fail=1
fi
if (( r3 - r2 != 0 )); then
    echo "FAIL[neg.redirect]: STAT_REDIRECT bumped on a NON-matching frame (delta $(( r3 - r2 )))" >&2
    fail=1
fi
if (( d3 - d2 != 1 )); then
    echo "FAIL[neg.drop]: non-matching frame did NOT land in STAT_DROP_DENY (delta $(( d3 - d2 )))" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_REDIRECT_DELIVERY"
exit "${fail}"
