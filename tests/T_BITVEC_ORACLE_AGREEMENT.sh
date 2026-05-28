#!/bin/bash
# T_BITVEC_ORACLE_AGREEMENT — design §6.45 (MVP-4.2 / §5.42).
#
# THE correctness test for the bit-vector AND-classification spike.
#
# For each test vector (dst_ip, src_ip, proto, dport[, vlan]):
#   1. snapshot the prototype's bv_result (per-rule-id hit counters,
#      summed across CPUs) via `bitvec_harness dump`,
#   2. inject exactly one matching L4 frame via inject_l4.py,
#   3. re-snapshot bv_result,
#   4. find the single rule-id slot that incremented by exactly 1,
#   5. assert that id == the INDEPENDENT oracle's prediction
#      (bitvec_oracle.py) for the same tuple.
#
# The oracle is a naive O(N) first-match scan (NO bitmask / closure /
# ffsll / range table) — algorithmically independent of the datapath
# under test, so a disagreement localises a closure / wildcard / range
# bug rather than masking it.
#
# Sanity floor (design §5.42 + spawn brief):
#   * SMOKE       — `populate` exit-0 + bv_result pin existence (we cannot
#                   reach a single assertion without them); V7 is a clear
#                   single-axis hit.
#   * NEGATION    — V9 (8.8.8.8/8.8.8.8 tcp:7) matches NO rule → the
#                   NOMATCH slot (id 64) must bump and NO real-rule slot may.
#                   This proves the machinery can register "miss", i.e. a
#                   broken always-match datapath FAILS here.
#   * OVERLAP     — V1/V2/V11 (prefix-closure cover-direction, guard #23).
#   * RANGE-EDGE  — V3/V4/V5/V6 (8079/8080/8090/8091 around r6 [8080,8090]).
#   * FIRST-MATCH — V1 (r0 DROP wins over more-specific r8 PASS) + V11.
#   * SRC-LPM     — V10a/V10b (src ∈ 10.5/16 flips the verdict).
#
# The expected-id column below is documentation; the LOAD-BEARING expected
# is computed live by bitvec_oracle.py so the two transcriptions of the
# canonical set must agree (D-mvp-4.2-CANONICAL).

set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

BITVEC_DIR="${TEST_DIR}/bitvec"
# Prefer the env vars impl exports in the test ENVIRONMENT; fall back to
# the canonical source paths so the test is robust to build-layout drift.
ORACLE="${BITVEC_ORACLE:-${BITVEC_DIR}/bitvec_oracle.py}"
INJECTOR="${INJECT_L4:-${TEST_DIR}/inject/inject_l4.py}"
PROTO_PIN_ROOT="/sys/fs/bpf/xdpmf-bitvec-proto"
NOMATCH=64

# ── Locate the bitvec_harness binary (mirrors find_loader idiom) ──────────
find_harness() {
    if [[ -n "${BITVEC_HARNESS:-}" && -x "${BITVEC_HARNESS}" ]]; then
        printf '%s\n' "${BITVEC_HARNESS}"; return 0
    fi
    local cand
    for cand in \
        "${BUILD_DIR}/tests/bitvec/bitvec_harness" \
        "${BUILD_DIR}/bitvec/bitvec_harness" \
        "${BUILD_DIR}/tests/bitvec_harness" \
        "${BUILD_DIR}/bitvec_harness"; do
        [[ -x "$cand" ]] && { printf '%s\n' "$cand"; return 0; }
    done
    local found
    found=$(find "${BUILD_DIR}" -maxdepth 5 -type f -executable -name bitvec_harness 2>/dev/null | head -1 || true)
    [[ -n "${found}" ]] && { printf '%s\n' "${found}"; return 0; }
    return 1
}

# ── Preconditions → SKIP (77) on missing tooling, never silent green ──────
[[ -f "${ORACLE}"   ]] || { echo "FAIL: oracle missing at ${ORACLE}" >&2; exit 1; }
if [[ ! -f "${INJECTOR}" ]]; then
    echo "SKIP: inject_l4.py not present at ${INJECTOR} (impl deliverable)" >&2
    exit 77
fi
HARNESS=$(find_harness) || {
    echo "SKIP: bitvec_harness binary not built under ${BUILD_DIR}" >&2
    exit 77
}
echo "harness  = ${HARNESS}"
echo "injector = ${INJECTOR}"
echo "oracle   = ${ORACLE}"

# ── Harness wrappers (NSEXEC for iface-scoped ops; dump reads the pin) ────
harness_populate() { ${NSEXEC} "${HARNESS}" populate "${IFACE_A}"; }
harness_detach()   { ${NSEXEC} "${HARNESS}" detach   "${IFACE_A}" 2>/dev/null || true; }
# `dump` reads the host-global bv_result pin (bpffs is not netns-isolated,
# per common.sh pin-path host-globalness invariant) — no netns needed, but
# run under sudo for map-read perms.
harness_dump()     { sudo -n "${HARNESS}" dump; }

# Parse `dump` output → emit "<id> <count>" lines, tolerating decoration.
# Defensive: keep only lines whose first two whitespace-or-=-separated
# fields are integers (handles "<id> <count>", "id=N count=M", etc.).
dump_pairs() {
    harness_dump 2>/dev/null \
      | sed -E 's/[=,]+/ /g' \
      | awk '{ for(i=1;i<=NF;i++){ if($i ~ /^[0-9]+$/){ a=$i; for(j=i+1;j<=NF;j++){ if($j ~ /^[0-9]+$/){ print a, $j; break } } break } } }'
}

# Echo the count for a given id from a captured dump snapshot (default 0).
count_for() {  # <id> <snapshot-text>
    local id="$1"; local snap="$2"
    awk -v want="$id" '$1==want{print $2; found=1} END{if(!found) print 0}' <<<"${snap}"
}

cleanup() {
    harness_detach
    sudo -n rm -rf "${PROTO_PIN_ROOT}" 2>/dev/null || true
    cleanup_veth
}
trap cleanup EXIT

setup_veth
# guard #22: disable HW VLAN offload in case any vector injects a tag.
${NSEXEC} ethtool -K "${IFACE_A}" rxvlan off txvlan off 2>/dev/null || true
${NSEXEC} ethtool -K "${IFACE_B}" rxvlan off txvlan off 2>/dev/null || true

# ── SMOKE: populate must succeed and pin bv_result ───────────────────────
echo "=== populate ${IFACE_A}"
set +e
harness_populate
prc=$?
set -e
if [[ "${prc}" -ne 0 ]]; then
    echo "FAIL[smoke]: bitvec_harness populate exit ${prc} (expected 0)" >&2
    exit 1
fi
if ! sudo -n test -e "${PROTO_PIN_ROOT}/bv_result"; then
    # tolerate impl pinning under a slightly different leaf — assert the
    # root subtree exists and dump produces parseable output instead.
    if ! sudo -n test -e "${PROTO_PIN_ROOT}"; then
        echo "FAIL[smoke]: prototype bpffs root ${PROTO_PIN_ROOT} missing after populate" >&2
        exit 1
    fi
fi
if [[ -z "$(dump_pairs)" ]]; then
    echo "FAIL[smoke]: bitvec_harness dump produced no parseable <id> <count> lines" >&2
    echo "--- raw dump ---" >&2; harness_dump >&2 || true
    exit 1
fi
echo "smoke OK: populate exit 0, bv_result reachable, dump parseable"

# ── Vector battery (design §6.45 mandatory table) ────────────────────────
# columns: name dst_ip src_ip proto dport   (expected id is computed live)
VECTORS=(
  "V1   10.1.2.130    8.8.8.8        tcp  1500"
  "V2   10.9.9.9      8.8.8.8        tcp  1234"
  "V3   203.0.113.5   8.8.8.8        tcp  8079"
  "V4   203.0.113.5   8.8.8.8        tcp  8080"
  "V5   203.0.113.5   8.8.8.8        tcp  8090"
  "V6   203.0.113.5   8.8.8.8        tcp  8091"
  "V7   8.8.8.8       8.8.8.8        icmp 0"
  "V8   198.51.100.10 198.51.100.20  tcp  22"
  "V9   8.8.8.8       8.8.8.8        tcp  7"
  "V10a 8.8.8.8       10.5.1.1       tcp  443"
  "V10b 8.8.8.8       8.8.8.8        tcp  443"
  "V11  192.168.1.50  172.16.5.5     udp  53"
)

fail=0
saw_negation=0
for spec in "${VECTORS[@]}"; do
    read -r name dst src proto dport <<<"${spec}"

    # Independent oracle prediction (LOAD-BEARING expected).
    expected=$(python3 "${ORACLE}" --dst-ip "${dst}" --src-ip "${src}" \
                       --proto "${proto}" --dport "${dport}")
    [[ "${expected}" == "${NOMATCH}" ]] && saw_negation=1

    # Snapshot → inject one frame → re-snapshot.
    before=$(dump_pairs)
    ${NSEXEC} python3 "${INJECTOR}" "${IFACE_B}" \
        --dst-ip "${dst}" --src-ip "${src}" --proto "${proto}" --dport "${dport}"

    # Poll for the per-vector single-packet bump to land (total over all
    # slots must rise by exactly 1). Deterministic, no fixed sleep race.
    target_total=0
    while read -r _id c; do target_total=$(( target_total + c )); done <<<"${before}"
    target_total=$(( target_total + 1 ))
    after=""
    for _ in $(seq 1 100); do
        after=$(dump_pairs)
        cur_total=0
        while read -r _id c; do cur_total=$(( cur_total + c )); done <<<"${after}"
        (( cur_total == target_total )) && break
        sleep 0.02
    done

    # Find every id whose count rose by exactly 1, and flag any other drift.
    bumped=""
    drift=0
    all_ids=$(printf '%s\n%s\n' "${before}" "${after}" | awk '{print $1}' | sort -un)
    for id in ${all_ids}; do
        cb=$(count_for "${id}" "${before}")
        ca=$(count_for "${id}" "${after}")
        delta=$(( ca - cb ))
        if (( delta == 1 )); then
            bumped="${bumped} ${id}"
        elif (( delta != 0 )); then
            echo "  [${name}] WARN: id ${id} delta=${delta} (expected 0 or 1)" >&2
            drift=1
        fi
    done
    bumped="${bumped# }"

    got="${bumped:-<none>}"
    # exactly one slot must have bumped, by exactly 1
    if [[ -z "${bumped}" || "${bumped}" == *" "* ]]; then
        echo "FAIL[${name}]: expected exactly ONE rule-id slot to bump by 1; got '{${got}}' (oracle=${expected})" >&2
        echo "  before: $(echo ${before} | tr '\n' ' ')" >&2
        echo "  after : $(echo ${after}  | tr '\n' ' ')" >&2
        fail=1
        continue
    fi
    if (( drift )); then
        echo "FAIL[${name}]: a non-target slot also changed (see WARN above)" >&2
        fail=1
    fi

    if [[ "${bumped}" == "${expected}" ]]; then
        tag="OK"; [[ "${expected}" == "${NOMATCH}" ]] && tag="OK(NOMATCH)"
        echo "  [${name}] ${dst} ${src} ${proto}:${dport} -> id=${bumped} (oracle=${expected}) ${tag}"
    else
        echo "FAIL[${name}]: datapath matched id=${bumped} but oracle predicted ${expected}" >&2
        echo "          tuple dst=${dst} src=${src} proto=${proto} dport=${dport}" >&2
        echo "          (disagreement localises a closure/wildcard/range/first-match bug)" >&2
        fail=1
    fi
done

# ── Sanity-floor guarantee: a negation-control vector was actually run ────
if (( ! saw_negation )); then
    echo "FAIL[sanity]: no NOMATCH (negation-control) vector present in battery" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_BITVEC_ORACLE_AGREEMENT (oracle ↔ prototype agree across V-battery)"
exit "${fail}"
