#!/bin/bash
# T_ANDEXT_WALK_STEER — design §5.55 TestStrategy test 1 (MVP-4.15 / S6).
#
# THE VA-5 detectability headline + the OPS-canary for the NEW ext-bearing v6
# frame-shape. S4 (§5.53) classifies v6 frames on the BASE-header nexthdr only;
# a v6 frame carrying a HopByHop/DestOpt chain has proto=ip6->nexthdr=0 (HOPOPTS)
# — an ext-header number, NOT the real L4 — so a `proto:tcp`/`dst_port:N` rule
# silently never matches it. S6 walks the chain so proto/dst_port see the TRUE
# upper-layer L4. This test proves the walk actually reaches L4.
#
# Fixture andext.yaml (default_action: pass):
#   id 0 : protocol tcp AND dst_port 443    DROP   (addr/mac/vlan wildcard)
#
# Vector battery (frame shape → expected verdict, cross-checked vs the oracle):
#   W1 HEADLINE   : ext hbh+dstopt, tcp/443  -> id0 DROP. A NON-walking datapath
#                   computes proto=HOPOPTS(0), the proto:tcp rule MISSES, the
#                   frame is NOT dropped -> RED. A walk that stops short (reaches
#                   dstopt but not L4) mis-reads dport -> RED. This is the only
#                   vector that exercises the walk's reach.
#   W2 WALK-NO-OP : NON-ext tcp/443         -> id0 DROP. The walk breaks at hop 0
#                   when the first nexthdr is already L4 -> verdict IDENTICAL to
#                   pre-slice (PI-mvp-4.15-NONEXT-V6 / walk-transparency). Its
#                   drop-delta MUST equal W1's (ext-bearing == non-ext).
#   W3 NEGATION   : ext hbh+dstopt, tcp/8080 -> NOMATCH -> default PASS. The SAME
#                   ext-bearing frame-shape with a DIFFERENT dport must NOT drop
#                   (drop-delta==0) — proves the match is the PORT axis reaching
#                   true L4, NOT a blanket "drop any ext-bearing frame".
#
# Each vector's expected id is computed LIVE by the independent oracle
# (bitvec_oracle_prod.py --ruleset andext) and cross-checked against the table
# annotation (transcription-drift guard). The oracle is WALK-TRANSPARENT: it keys
# on the TRUE L4 (--proto/--dport) the test injects, exactly the value the walk
# must reach — so an ext-bearing tcp/443 frame predicts id0 (drop) while a
# non-walking datapath predicts NOMATCH. That divergence IS the VA-5 trap.
#
# Sanity floor:
#   * SMOKE    — apply exit 0; rule_counters + wildcard pins exist (W1/W2 are
#                clean DROP hits on id0).
#   * NEGATION — W3: an ext-bearing tcp/8080 frame MUST NOT be dropped by the
#                tcp/443 rule. An always-drop-ext-frames datapath FAILS here.
#
# Maps to: PI-mvp-4.15-EXT-WALK, PI-mvp-4.15-NONEXT-V6.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx / rule_counters parse)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
FIXTURE="${TEST_DIR}/fixtures/andext.yaml"
ORACLE="${AND_ORACLE_PROD:-${TEST_DIR}/bitvec/bitvec_oracle_prod.py}"
INJECT="${INJECT_L6:-${TEST_DIR}/inject/inject_l6.py}"
NOMATCH=64
DST6="2001:db8:aaaa::1"
SRC6="2001:db8:bbbb::2"

for f in "${FIXTURE}" "${ORACLE}" "${INJECT}"; do
    [[ -f "${f}" ]] || { echo "FAIL: missing ${f}" >&2; exit 1; }
done

# inject_l6.py needs scapy; skip (not fail) if absent — matches the v6 idiom.
if ! ${NSEXEC:-sudo -n} python3 -c 'import scapy' 2>/dev/null \
     && ! python3 -c 'import scapy' 2>/dev/null; then
    echo "SKIP: scapy not importable (inject_l6.py prerequisite)" >&2
    exit 77
fi

stderr_file=$(mktemp /tmp/xdpmf-andextsteer-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT INT TERM HUP
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

setup_veth

# Untagged v6 frames in every vector; disabling offload is harmless.
${NSEXEC} ethtool -K "${IFACE_A}" rxvlan off txvlan off 2>/dev/null || true
${NSEXEC} ethtool -K "${IFACE_B}" rxvlan off txvlan off 2>/dev/null || true

read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}
rule_counters_active_pin() {
    case "$(read_active_idx)" in
        1) echo "${PIN_DIR}/rule_counters_b" ;;
        *) echo "${PIN_DIR}/rule_counters_a" ;;
    esac
}
read_rc_slot() {
    sudo -n python3 "${TEST_DIR}/lib/read_rule_counters.py" \
        "$(rule_counters_active_pin)" "$1"
}

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
sudo -n test -e "${PIN_DIR}/rule_counters_a" \
    || { echo "FAIL[smoke]: ${PIN_DIR}/rule_counters_a pin missing after apply" >&2; exit 1; }
sudo -n test -e "${PIN_DIR}/wildcard" \
    || { echo "FAIL[smoke]: ${PIN_DIR}/wildcard pin missing after apply" >&2; exit 1; }
echo "smoke OK: apply exit 0; rule_counters + wildcard reachable"

# Vector: name | ext-args | dport | expected-id (annotation, cross-checked live)
# ext field uses '+' as a separator that we split into repeated --ext flags;
# '-' means NO extension headers (the non-ext walk-no-op vector).
VECTORS=(
  "W1 hbh+dstopt 443  0"    # HEADLINE: ext-bearing tcp/443 -> id0 DROP
  "W2 -         443  0"    # WALK-NO-OP: non-ext tcp/443     -> id0 DROP (identical)
  "W3 hbh+dstopt 8080 64"  # NEGATION: ext-bearing tcp/8080  -> NOMATCH (default pass)
)

fail=0
saw_negation=0
saw_drop=0
for spec in "${VECTORS[@]}"; do
    read -r name extspec dport annotated <<<"${spec}"

    ext_args=()
    if [[ "${extspec}" != "-" ]]; then
        IFS='+' read -ra exts <<<"${extspec}"
        for e in "${exts[@]}"; do ext_args+=(--ext "${e}"); done
    fi

    # Independent oracle prediction (walk-transparent: keys on the TRUE L4).
    expected=$(python3 "${ORACLE}" --ruleset andext \
                 --dst-ip6 "${DST6}" --src-ip6 "${SRC6}" --proto tcp --dport "${dport}")
    if [[ "${expected}" != "${annotated}" ]]; then
        echo "FAIL[${name}]: oracle predicted ${expected} but annotation says ${annotated}" >&2
        echo "          (fixture/oracle transcription drift — fix RULES_ANDEXT or andext.yaml)" >&2
        fail=1; continue
    fi
    [[ "${expected}" == "${NOMATCH}" ]] && saw_negation=1
    [[ "${expected}" != "${NOMATCH}" ]] && saw_drop=1

    b0=$(read_rc_slot 0)
    read -r p0 d0 m0 c0 < <(read_stats_with_cidr)

    ${NSEXEC} python3 "${INJECT}" "${IFACE_B}" \
        --dst-ip "${DST6}" --src-ip "${SRC6}" --proto tcp --dport "${dport}" \
        --dst-mac "${MAC_DST}" "${ext_args[@]}"
    wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + 1 )) || true

    b1=$(read_rc_slot 0)
    read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
    rc_delta=$(( b1 - b0 ))
    deny_delta=$(( d1 - d0 ))
    pass_delta=$(( (p1 - p0) + (c1 - c0) ))
    mal_delta=$(( m1 - m0 ))
    echo "  [${name}] ext='${extspec}' tcp/${dport} -> rule_counters[0] d=${rc_delta} DENY d=${deny_delta} PASS d=${pass_delta} MAL d=${mal_delta} (oracle=${expected})"

    if (( mal_delta != 0 )); then
        echo "FAIL[${name}]: STAT_DROP_MALFORMED delta=${mal_delta} (expected 0 — a well-formed ext-bearing frame must NOT be malformed)" >&2
        fail=1; continue
    fi

    if [[ "${expected}" == "${NOMATCH}" ]]; then
        # NEGATION: must NOT drop; falls to default pass.
        if (( deny_delta != 0 )); then
            echo "FAIL[${name}]: DROP_DENY delta=${deny_delta} (expected 0 — tcp/${dport} must NOT match the tcp/443 rule)" >&2
            echo "          bug shape: a blanket ext-frame drop, OR a port axis ignored (PI-mvp-4.15-EXT-WALK)" >&2
            fail=1
        fi
        if (( rc_delta != 0 )); then
            echo "FAIL[${name}]: rule_counters[0] delta=${rc_delta} (expected 0 — id0 must not fire on tcp/${dport})" >&2
            fail=1
        fi
        if (( pass_delta != 1 )); then
            echo "FAIL[${name}]: PASS-class delta=${pass_delta} (expected 1 — frame falls to default pass)" >&2
            fail=1
        fi
    else
        # DROP via id0: the walk reached true L4 and the proto+port rule fired.
        if (( rc_delta != 1 )); then
            echo "FAIL[${name}]: rule_counters[0] delta=${rc_delta} (expected 1 — the tcp/443 rule must fire on the WALKED L4)" >&2
            echo "          bug shape: the v6 arm did NOT walk the ext chain (proto stuck at HOPOPTS), or stopped short of L4 (VA-5)" >&2
            echo "          (PI-mvp-4.15-EXT-WALK; W2 non-ext baseline proves the rule itself works)" >&2
            fail=1
        fi
        if (( deny_delta != 1 )); then
            echo "FAIL[${name}]: DROP_DENY delta=${deny_delta} (expected 1 — id0 is a DROP rule)" >&2
            fail=1
        fi
    fi
done

# Walk-transparency cross-check: W1 (ext) and W2 (non-ext) must produce the SAME
# verdict (both DROP via id0). Both are asserted above; this is the explicit
# PI-mvp-4.15-NONEXT-V6 statement for the reviewer/log.
if (( ! saw_drop )); then
    echo "FAIL[sanity]: no DROP vector exercised (the walk-reach proof is missing)" >&2
    fail=1
fi
if (( ! saw_negation )); then
    echo "FAIL[sanity]: no NEGATION (NOMATCH) vector present in battery" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_ANDEXT_WALK_STEER (ext-bearing v6 frame matched by proto:tcp/dst_port via the walk; non-ext identical; wrong-port negation)"
exit "${fail}"
