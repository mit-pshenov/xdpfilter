#!/bin/bash
# T_REDIRECT_TARGET_DOWN — design §5.75.6 (OPTIONAL, gated by the
# D-mvp-4.35-FALLBACK spike). Written against the SPECIFICATION (design.md
# §5.75.4 classifier branch + §5.75.5 D-mvp-4.35-FEAS/FALLBACK), NOT impl src.
#
# The redirect helper is `bpf_redirect_map(&redirect_devmap, 0, XDP_PASS)`:
# the low flag bits select XDP_PASS as the MISS fallback, so a matched frame
# whose devmap[0] target is absent/down degrades to the original flow
# (XDP_PASS) rather than blackholing (HG-2). This test proves that
# PASS-on-miss contract on the target kernel.
#
# Shipped only because the Phase-2.5 fallback smoke CONFIRMED the kernel
# honours the miss-fallback (spike PASS → PI-mvp-4.35-MISS-DEFERRED is NOT
# triggered). If a future kernel silently dropped on miss, this test would
# fail loud — which is the correct signal, not a reason to delete it.
#
# IMPORTANT classifier ordering (per §5.75.4): STAT_REDIRECT is bumped BEFORE
# the bpf_redirect_map call, so a MISS STILL bumps STAT_REDIRECT — the verb
# DECIDED to redirect; only the physical delivery degraded. The target-down
# observable is therefore: STAT_REDIRECT bumps, sink does NOT, and no
# PASS/DROP slot bumps for that frame.
#
# Trigger (two phases, same apply):
#   Phase 1 (CONTROL / known-good delivery): devmap[0] populated with
#     ifindex(IFACE_C); inject a matching frame → sink delta == 1
#     (delivery machinery provably works — this is the negation control;
#     a sink that can only ever read 0 would prove nothing).
#   Phase 2 (TARGET-DOWN): clear devmap[0] (`bpftool map delete … key 0`);
#     inject a matching frame → sink delta == 0 (PASS-on-miss, NOT delivered),
#     STAT_REDIRECT delta == 1 (decision still counted), PASS/PASS_CIDR/
#     DROP_DENY deltas == 0 (degrade is to the ORIGINAL flow, not a new
#     verdict bucket).
#
# Sanity-floor smoke: apply exit 0 + redirect_devmap pin + sink attached.
# Negation control: Phase 1's sink delta == 1 is the known-good that MUST
# fire; the Phase-1↔Phase-2 sink differential (1 vs 0 across the devmap
# clear) is the anti-theatricality fence.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v bpftool >/dev/null 2>&1; then
    echo "SKIP: bpftool not in PATH (required to clear the devmap + load sink)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
SINK_OBJ="${BUILD_DIR}/sink_xdp.bpf.o"
[[ -f "${SINK_OBJ}" ]] \
    || { echo "FAIL: sink fixture missing at ${SINK_OBJ}" >&2; exit 1; }

cfg_file=$(mktemp /tmp/xdpmf-redir-down-cfg.XXXXXX.yaml)
stderr_file=$(mktemp /tmp/xdpmf-redir-down-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${cfg_file}" "${stderr_file}"' EXIT

REDIR_MAC="02:00:00:00:00:01"
SRC_IP="10.0.0.5"

setup_veth
setup_redirect_sink

cat > "${cfg_file}" <<EOF
# Runtime-generated redirect fixture for T_REDIRECT_TARGET_DOWN (§5.75.6).
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
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[smoke.apply]: apply exit ${rc} (expected 0)" >&2
    fail=1
fi
if ! sudo -n test -e "${PIN_DIR}/redirect_devmap"; then
    echo "FAIL[smoke.map]: pin ${PIN_DIR}/redirect_devmap missing" >&2
    fail=1
fi
sink_id=$(xdp_prog_id "${IFACE_D}")
if [[ -z "${sink_id}" || "${sink_id}" == "0" ]]; then
    echo "FAIL[smoke.sink]: no XDP sink prog on ${IFACE_D}" >&2
    fail=1
fi
if (( fail != 0 )); then
    echo "FAIL: smoke floor failed; aborting" >&2
    exit 1
fi

# ── Phase 1: CONTROL — populated devmap delivers (sink MUST bump) ─────────
echo
echo "=== Phase 1 (control): devmap populated → inject match → expect delivery"
read -r p0 d0 m0 c0 r0 < <(read_stats_with_redirect)
s0=$(read_sink)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${REDIR_MAC}" "${MAC_DST}" "${SRC_IP}"
wait_for_stats_sum_with_redirect "${IFACE_A}" $(( p0 + d0 + m0 + c0 + r0 + 1 )) || true
wait_for_sink $(( s0 + 1 )) || true
read -r p1 d1 m1 c1 r1 < <(read_stats_with_redirect)
s1=$(read_sink)
echo "after control: REDIRECT delta=$(( r1 - r0 )) SINK delta=$(( s1 - s0 ))"
if (( s1 - s0 != 1 )); then
    echo "FAIL[ctl.sink]: control delivery did NOT land (sink delta $(( s1 - s0 )), expected 1)" >&2
    echo "              the delivery machinery is broken — Phase-2 differential is meaningless" >&2
    fail=1
fi
if (( r1 - r0 != 1 )); then
    echo "FAIL[ctl.redirect]: STAT_REDIRECT delta=$(( r1 - r0 )) (expected 1)" >&2
    fail=1
fi

# ── Phase 2: TARGET-DOWN — clear devmap[0]; PASS-on-miss, NO delivery ─────
echo
echo "=== Phase 2 (target-down): clear redirect_devmap[0], inject match"
set +e
sudo -n bpftool map delete pinned "${PIN_DIR}/redirect_devmap" key 0 0 0 0 2>"${stderr_file}"
del_rc=$?
set -e
echo "bpftool map delete rc=${del_rc}"
cat "${stderr_file}" >&2 || true
if [[ "${del_rc}" -ne 0 ]]; then
    echo "SKIP: could not clear redirect_devmap[0] (bpftool delete rc=${del_rc}) — cannot stage target-down" >&2
    exit 77
fi

read -r p2 d2 m2 c2 r2 < <(read_stats_with_redirect)
s2=$(read_sink)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${REDIR_MAC}" "${MAC_DST}" "${SRC_IP}"
# STAT_REDIRECT still bumps on a miss (the bump precedes the helper) → the
# 5-col sum advances by 1; poll for that, then give any (erroneous) delivery
# a chance to register before asserting sink absence.
wait_for_stats_sum_with_redirect "${IFACE_A}" $(( p2 + d2 + m2 + c2 + r2 + 1 )) || true
sleep 0.3
read -r p3 d3 m3 c3 r3 < <(read_stats_with_redirect)
s3=$(read_sink)
echo "after target-down: REDIRECT delta=$(( r3 - r2 )) SINK delta=$(( s3 - s2 )) DROP delta=$(( d3 - d2 )) PASS delta=$(( p3 - p2 ))"

# sink must NOT bump — the frame degraded to XDP_PASS on miss, not delivered.
if (( s3 - s2 != 0 )); then
    echo "FAIL[down.sink]: sink bumped on a CLEARED devmap (delta $(( s3 - s2 )))" >&2
    echo "               a miss must NOT deliver (PASS-on-miss degrade, HG-2)" >&2
    fail=1
fi
# STAT_REDIRECT STILL bumps (decision counted before the helper call).
if (( r3 - r2 != 1 )); then
    echo "FAIL[down.redirect]: STAT_REDIRECT delta=$(( r3 - r2 )) (expected 1 — the bump precedes the helper)" >&2
    fail=1
fi
# Degrade is to the ORIGINAL flow (XDP_PASS), not a PASS/DROP verdict bucket.
if (( d3 - d2 != 0 )); then
    echo "FAIL[down.drop]: STAT_DROP_DENY moved on a target-down miss (delta $(( d3 - d2 )))" >&2
    fail=1
fi
if (( p3 - p2 != 0 )); then
    echo "FAIL[down.pass]: STAT_PASS moved on a target-down miss (delta $(( p3 - p2 )))" >&2
    fail=1
fi
if (( c3 - c2 != 0 )); then
    echo "FAIL[down.pass_cidr]: STAT_PASS_CIDR moved on a target-down miss (delta $(( c3 - c2 )))" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_REDIRECT_TARGET_DOWN"
exit "${fail}"
