#!/bin/bash
# T_REDIRECT_COUNTER_AND_MAP — design §5.75.6 SELECT-A (counter + devmap dump).
#
# Written against the SPECIFICATION (design.md §5.75.4 Interfaces + §5.75.6
# TestStrategy), NOT against impl's loader/classifier edits. Complements the
# SELECT-B delivery oracle (T_REDIRECT_DELIVERY) with the two host-observable
# halves of the redirect verb:
#   (A) the STAT_REDIRECT counter bumps on a redirect match (the classifier
#       decided to redirect), and
#   (B) the loader programmed the steering target into redirect_devmap[0] —
#       `bpftool map dump pinned ${PIN_DIR}/redirect_devmap` shows key 0 ==
#       ifindex(IFACE_C) (Q2/A1: loader resolves steering.redirect_to → ifindex
#       and fills the single-entry DEVMAP at apply).
#
# Unlike SELECT-B this does NOT depend on live cross-iface delivery — the
# STAT_REDIRECT bump fires in the classifier independent of whether the
# generic-mode redirect physically lands, so this test isolates the
# decision + map-programming contract. IFACE_C must still exist so the
# loader's apply-time ifindex resolution succeeds (fail-closed otherwise,
# §5.75.4 populate_redirect_devmap).
#
# Trigger:
#   1. setup_veth + bring up the IFACE_C/IFACE_D target pair (no sink needed).
#   2. apply a redirect-action MAC rule + steering target IFACE_C (config
#      generated at runtime — the target name is PID-suffixed).
#   3. Inject ONE redirect-matching frame.
#
# Observable outcome (ALL must hold):
#   (a) apply exit 0 (smoke).
#   (b) redirect_devmap pin exists (smoke).
#   (c) STAT_REDIRECT delta == 1 on the matching frame.
#   (d) redirect_devmap[0] == ifindex(IFACE_C)  (the resolved steering target).
#
# Sanity-floor smoke: (a)+(b).
# Negation control: a frame with a NON-matching src MAC must NOT bump
# STAT_REDIRECT (delta 0) — proves the counter tracks the redirect verdict,
# not raw traffic. The exact ifindex equality in (d) is a second differential:
# a devmap left empty / programmed with a wrong ifindex fails (d).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v bpftool >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: bpftool + jq required (devmap dump + JSON parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)

cfg_file=$(mktemp /tmp/xdpmf-redir-map-cfg.XXXXXX.yaml)
stderr_file=$(mktemp /tmp/xdpmf-redir-map-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${cfg_file}" "${stderr_file}"' EXIT

REDIR_MAC="02:00:00:00:00:01"
NONMATCH_MAC="02:00:00:00:00:02"
SRC_IP="10.0.0.5"

setup_veth

# ── Bring up the steering target pair (IFACE_C/IFACE_D); no sink here ─────
${NSEXEC} ip link add "${IFACE_C}" type veth peer name "${IFACE_D}"
${NSEXEC} ip link set "${IFACE_C}" addrgenmode none 2>/dev/null || true
${NSEXEC} ip link set "${IFACE_D}" addrgenmode none 2>/dev/null || true
${NSEXEC} ip link set "${IFACE_C}" up
${NSEXEC} ip link set "${IFACE_D}" up

target_ifindex=$(ifindex_of "${IFACE_C}")
echo "steering target ${IFACE_C} ifindex=${target_ifindex}"
if [[ -z "${target_ifindex}" ]]; then
    echo "FAIL: could not resolve ifindex of ${IFACE_C} (fixture setup error)" >&2
    exit 1
fi

# ── Generate the redirect config ─────────────────────────────────────────
cat > "${cfg_file}" <<EOF
# Runtime-generated redirect fixture for T_REDIRECT_COUNTER_AND_MAP (§5.75.6).
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

# ── (b) smoke: redirect_devmap pin exists ────────────────────────────────
if ! sudo -n test -e "${PIN_DIR}/redirect_devmap"; then
    echo "FAIL[b]: expected pin ${PIN_DIR}/redirect_devmap missing" >&2
    fail=1
fi
if (( fail != 0 )); then
    echo "FAIL: smoke floor failed; aborting before content assertions" >&2
    exit 1
fi

# ── (c) STAT_REDIRECT bumps on a matching frame ──────────────────────────
read -r p0 d0 m0 c0 r0 < <(read_stats_with_redirect)
echo "baseline: REDIRECT=${r0} (PASS=${p0} DROP_DENY=${d0})"
echo "=== inject matching frame src_mac=${REDIR_MAC}"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${REDIR_MAC}" "${MAC_DST}" "${SRC_IP}"
wait_for_stats_sum_with_redirect "${IFACE_A}" $(( p0 + d0 + m0 + c0 + r0 + 1 )) || true

read -r p1 d1 m1 c1 r1 < <(read_stats_with_redirect)
echo "after match: REDIRECT=${r1} (delta $(( r1 - r0 )))"
if (( r1 - r0 != 1 )); then
    echo "FAIL[c]: STAT_REDIRECT delta=$(( r1 - r0 )) (expected 1)" >&2
    fail=1
fi

# ── (d) redirect_devmap[0] == ifindex(IFACE_C) ───────────────────────────
echo "=== redirect_devmap dump"
dump=$(sudo -n bpftool map dump pinned "${PIN_DIR}/redirect_devmap" --json 2>/dev/null || echo '[]')
printf '%s\n' "${dump}" | sed 's/^/  devmap| /' >&2 || true
# bpftool renders a DEVMAP value as either {"ifindex":N,"ifname":"..."} (newer)
# or a raw little-endian u32 byte array (older). Extract the key-0 entry's
# ifindex via either shape; also surface ifname for the ifname-equality path.
mapped_ifindex=$(printf '%s' "${dump}" | jq -r '
    [ .[]
      | { k: ( .formatted.key? //
               ( if (.key|type)=="array"
                 then ([ .key[] | if type=="string" then sub("^0x";"")|tonumber else . end ]
                        | (.[0] + (.[1]*256) + (.[2]*65536) + (.[3]*16777216)))
                 else .key end ) ),
          ifx: ( .formatted.value.ifindex? // .value.ifindex? //
                 ( if (.value|type)=="array"
                   then ([ .value[] | if type=="string" then sub("^0x";"")|tonumber else . end ]
                          | (.[0] + (.[1]*256) + (.[2]*65536) + (.[3]*16777216)))
                   else null end ) ) }
      | select(.k == 0) | .ifx ] | (.[0] // "")
' 2>/dev/null)
mapped_ifname=$(printf '%s' "${dump}" | jq -r '
    [ .[] | (.formatted.value.ifname? // .value.ifname? // empty) ] | (.[0] // "")
' 2>/dev/null)
echo "redirect_devmap[0]: ifindex='${mapped_ifindex}' ifname='${mapped_ifname}' (expected ifindex=${target_ifindex} / ${IFACE_C})"

if [[ "${mapped_ifindex}" == "${target_ifindex}" ]]; then
    echo "OK[d]: devmap[0] ifindex matches ${IFACE_C}"
elif [[ -n "${mapped_ifname}" && "${mapped_ifname}" == "${IFACE_C}" ]]; then
    echo "OK[d]: devmap[0] ifname matches ${IFACE_C}"
else
    echo "FAIL[d]: redirect_devmap[0] does NOT name ${IFACE_C}" >&2
    echo "        got ifindex='${mapped_ifindex}' ifname='${mapped_ifname}'," >&2
    echo "        expected ifindex=${target_ifindex} (ifname ${IFACE_C})" >&2
    fail=1
fi

# ── NEGATION CONTROL: non-matching MAC → STAT_REDIRECT unmoved ────────────
echo
echo "=== NEGATION: inject non-matching frame src_mac=${NONMATCH_MAC}"
read -r p2 d2 m2 c2 r2 < <(read_stats_with_redirect)
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${NONMATCH_MAC}" "${MAC_DST}" "${SRC_IP}"
wait_for_stats_sum_with_redirect "${IFACE_A}" $(( p2 + d2 + m2 + c2 + r2 + 1 )) || true
read -r p3 d3 m3 c3 r3 < <(read_stats_with_redirect)
echo "after non-match: REDIRECT=${r3} (delta $(( r3 - r2 ))) DROP_DENY delta=$(( d3 - d2 ))"
if (( r3 - r2 != 0 )); then
    echo "FAIL[neg]: STAT_REDIRECT bumped on a NON-matching frame (delta $(( r3 - r2 )))" >&2
    echo "          the counter is not gated on the redirect verdict." >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_REDIRECT_COUNTER_AND_MAP"
exit "${fail}"
