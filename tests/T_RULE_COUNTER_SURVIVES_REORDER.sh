#!/bin/bash
# T_RULE_COUNTER_SURVIVES_REORDER — design §6.76 (MVP-4.21 / B30, §5.61).
#
# THE headline executable spec for the slot/id decouple: a per-rule
# Prometheus counter must follow its STABLE operator id across an internal
# bit-vector SLOT move (caused by inserting a lower/middle id under
# id-sorted-rank slot assignment). This is the PI-3.4b-2-across-slot-move
# proof + the OPS canary for the new slot↔id contract (D-mvp-4.21-Q1 /
# COPYFWD-BY-ID). It also folds in: Q2 sparse-id (>63) acceptance,
# first-match-by-lowest-id priority parity with sparse ids (Q3), and the
# Q2 sentinel + count-cap rejections.
#
# Assertion mechanism: the exporter /metrics scrape, parsed for the
# `xdpfilter_rule_match_total{...,rule_id="N",...}` labels — the id
# labelling is ITSELF under test (the exporter remaps slot→id via the new
# slot_rule_id map; we never read the raw slot index for the asserts).
#
# ── Slot bookkeeping (id-sorted rank, D-mvp-4.21-Q3) ─────────────────────
#   base   ids {5,100}     → slot: id5=0, id100=1
#   insert ids {5,50,100}  → slot: id5=0, id50=1, id100=2   (id100 1→2)
#
# A BLANKET index-by-index counter copy (the pre-§5.61 bug class, correct
# only while slot==id) would copy old-slot-1 (= id100's N100) into new
# slot-1 (= id50) and leave new-slot-2 (= id100) at 0 — surfacing as
# rule_id=50 == N100 and rule_id=100 == 0. The id-keyed copy-forward
# instead leaves rule_id=100 == N100 (its counter followed its id across
# the move) and rule_id=50 == 0 (a genuinely new id).
#
# Steps / observable outcomes (ALL must hold):
#   (a) SMOKE: apply base (sparse ids 5,100; 100>63 ⟹ Q2 accepted) exit 0;
#       exporter starts; /metrics HTTP 200.
#   (b) inject N5=3 frames → id5, N100=4 frames → id100; scrape →
#       rule_match_total{rule_id=5}==3, {rule_id=100}==4.
#   (c) apply insert (id 50 inserted ⟹ id100 slot 1→2); scrape →
#       LOAD-BEARING: {rule_id=100}==4 (survived the slot move),
#       {rule_id=5}==3, and NEGATION CONTROL {rule_id=50} is 0/absent
#       (NOT 4 — proves remap is per-id, not slot blanket-copy).
#   (d) inject 1 more frame → id100-only (10.100.0.x ∉ id50's /24); scrape →
#       {rule_id=100}==5 (monotonic continuation post-move).
#   (e) PRIORITY PARITY (Q3, sparse ids): inject 1 frame to 10.100.50.x
#       (∈ BOTH id50 /24 AND id100 /16) → lowest id (50) wins; scrape →
#       {rule_id=50}==1, {rule_id=100} STAYS 5.
#   (f) Q2 sentinel reject: apply id==0xFFFFFFFF → exit 9 (ConfigError).
#   (g) Q2 count-cap reject: apply 65 rules → exit 9 (ConfigError).
#   (h) Q2 sparse accept: apply ids {100, 4000000000} → exit 0 (large u32
#       id accepted; the dense [0,63] cap is gone).
#
# Sanity-floor smoke: step (a). Negation control: step (c) {rule_id=50}
# stays 0 (would be N100 under a slot-keyed copy). Priority negation:
# step (e) id100 must NOT bump on the overlapping frame.
#
# Maps to: PI-3.4b-2 (counter-survives-slot-move), PI-mvp-4.21-PRIORITY,
# D-mvp-4.21-Q1/Q2/Q3/COPYFWD-BY-ID/SENTINEL.
#
# SKIP conditions: curl/jq absent → exit 77.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not in PATH (required to scrape /metrics for §6.76)" >&2
    exit 77
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for active_idx diagnostics)" >&2
    exit 77
fi

find_exporter() {
    if [[ -n "${XDPMF_EXPORTER_BIN:-}" && -x "${XDPMF_EXPORTER_BIN}" ]]; then
        printf '%s\n' "${XDPMF_EXPORTER_BIN}"; return 0
    fi
    local cand
    for cand in \
        "${BUILD_DIR}/xdpmf-exporter" \
        "${BUILD_DIR}/src/exporter/xdpmf-exporter" \
        "${BUILD_DIR}/bin/xdpmf-exporter"; do
        if [[ -x "$cand" ]]; then printf '%s\n' "$cand"; return 0; fi
    done
    local found
    found=$(find "${BUILD_DIR}" -maxdepth 5 -type f -executable -name xdpmf-exporter 2>/dev/null | head -1 || true)
    if [[ -n "${found}" ]]; then printf '%s\n' "${found}"; return 0; fi
    return 1
}

LOADER_BIN=$(find_loader)
EXPORTER_BIN=$(find_exporter) || {
    echo "FAIL: xdpmf-exporter binary not found under ${BUILD_DIR}" >&2
    exit 1
}
BASE_FIXTURE="${TEST_DIR}/fixtures/config_reorder_base.yaml"
INSERT_FIXTURE="${TEST_DIR}/fixtures/config_reorder_insert.yaml"
for f in "${BASE_FIXTURE}" "${INSERT_FIXTURE}"; do
    [[ -f "$f" ]] || { echo "FAIL: missing fixture ${f}" >&2; exit 1; }
done

# Per-id match counts (distinct, to catch cross-id contamination).
N5=3
N100=4

# All rules are dst-only (src wildcard) → src_ip/src_mac irrelevant.
SRC_MAC="02:00:00:00:00:aa"
DST_ID5="10.5.0.1"          # ∈ id5 /16 only
DST_ID100="10.100.0.1"      # ∈ id100 /16 only (NOT in id50 /24)
DST_OVERLAP="10.100.50.5"   # ∈ BOTH id50 /24 AND id100 /16 → lowest id (50) wins

PORT=$(( 9417 + ($$ % 1000) ))
echo "EXPORTER_PORT=${PORT}"

body1=$(mktemp /tmp/xdpmf-reorder-body1.XXXXXX)
body2=$(mktemp /tmp/xdpmf-reorder-body2.XXXXXX)
body3=$(mktemp /tmp/xdpmf-reorder-body3.XXXXXX)
body4=$(mktemp /tmp/xdpmf-reorder-body4.XXXXXX)
exp_log=$(mktemp /tmp/xdpmf-reorder-explog.XXXXXX)
stderr_file=$(mktemp /tmp/xdpmf-reorder-stderr.XXXXXX)
sentinel_cfg=$(mktemp /tmp/xdpmf-reorder-sentinel.XXXXXX.yaml)
countcap_cfg=$(mktemp /tmp/xdpmf-reorder-countcap.XXXXXX.yaml)
bigid_cfg=$(mktemp /tmp/xdpmf-reorder-bigid.XXXXXX.yaml)
EXPORTER_PID=""

SIDECAR_ROOT="/run/xdpfilter"
SIDECAR_DIR="${SIDECAR_ROOT}/${IFACE_A}"

cleanup_test() {
    set +e
    if [[ -n "${EXPORTER_PID}" ]]; then
        sudo -n kill "${EXPORTER_PID}" 2>/dev/null
        sleep 0.2
        sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null
        wait "${EXPORTER_PID}" 2>/dev/null
    fi
    cleanup_veth
    sudo -n rm -rf "${SIDECAR_DIR}" 2>/dev/null
    rm -f "${body1}" "${body2}" "${body3}" "${body4}" "${exp_log}" \
          "${stderr_file}" "${sentinel_cfg}" "${countcap_cfg}" "${bigid_cfg}"
    set -e
}
trap cleanup_test EXIT INT TERM HUP

# §5.33 HK-B pre-test residue wipe.
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

fail=0

# Extract the integer value of rule_match_total for a rule_id from a body
# file; prints the value, or empty string if no such series line exists.
match_total_for_id() {
    local id="$1" body="$2"
    grep -E "^xdpfilter_rule_match_total\{iface=\"${IFACE_A}\",rule_id=\"${id}\",action=\"[^\"]+\"\} [0-9]+$" \
        "${body}" 2>/dev/null | head -n1 | sed -nE 's/.*\} ([0-9]+)$/\1/p'
}

# Scrape /metrics into the given body file; echoes the HTTP status code.
scrape() {
    local body="$1" code
    set +e
    code=$(curl -s -o "${body}" -w '%{http_code}' -m 5 "http://127.0.0.1:${PORT}/metrics")
    set -e
    echo "${code}"
}

read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then printf '%d\n' "0x${hex}"; fi
}

apply_cfg() {  # apply_cfg <fixture> ; echoes loader exit code
    local cfg="$1" rc
    : >"${stderr_file}"
    set +e
    ${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${cfg}" 2>"${stderr_file}"
    rc=$?
    set -e
    cat "${stderr_file}" >&2 || true
    echo "${rc}"
}

inject_n() {  # inject_n <count> <dst_ip>
    local n="$1" dst="$2" i
    for (( i = 0; i < n; i++ )); do
        ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
            "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "192.0.2.9" "${dst}"
    done
}

setup_veth

# ── (a) SMOKE: apply base + start exporter + first scrape ────────────────
echo "=== (a) apply base ${BASE_FIXTURE} (sparse ids 5,100; 100>63 ⟹ Q2 accept)"
rc=$(apply_cfg "${BASE_FIXTURE}")
echo "apply base rc=${rc}"
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[a.apply]: base apply exit ${rc} (expected 0; sparse id>63 must be accepted)" >&2
    exit 1
fi
if ! sudo -n test -e "${PIN_DIR}/rule_counters_a"; then
    echo "FAIL[a.pin]: ${PIN_DIR}/rule_counters_a pin missing — cannot proceed" >&2
    exit 1
fi
echo "active_idx (post-base) = $(read_active_idx)"

echo "=== starting xdpmf-exporter on 127.0.0.1:${PORT}"
sudo -n "${EXPORTER_BIN}" \
    --port "${PORT}" --bind 127.0.0.1 --bpffs-root "${PIN_ROOT}" \
    >"${exp_log}" 2>&1 &
EXPORTER_PID=$!
echo "EXPORTER_PID=${EXPORTER_PID}"
ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT}/healthz" -o /dev/null 2>/dev/null; then
        ready=1; echo "exporter ready after ${i} polls"; break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        echo "FAIL[a.exp]: exporter died during startup" >&2; cat "${exp_log}" >&2; exit 1
    fi
    sleep 0.1
done
[[ "${ready}" == "1" ]] || { echo "FAIL[a.ready]: exporter not ready within 5s" >&2; cat "${exp_log}" >&2; exit 1; }

# ── (b) inject per-id traffic, scrape, assert id5==N5, id100==N100 ───────
echo "=== (b) inject ${N5}× id5 (dst ${DST_ID5}) + ${N100}× id100 (dst ${DST_ID100})"
read -r p0 d0 m0 c0 < <(read_stats_with_cidr)
inject_n "${N5}"   "${DST_ID5}"
inject_n "${N100}" "${DST_ID100}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p0 + d0 + m0 + c0 + N5 + N100 )) || true

code=$(scrape "${body1}")
echo "scrape1 http=${code}"
echo "--- body1 (rule_match_total lines) ---"
grep -E '^xdpfilter_rule_match_total\{' "${body1}" || true
echo "--- end ---"
if [[ "${code}" != "200" ]]; then
    echo "FAIL[b.http]: /metrics http=${code} (expected 200)" >&2; fail=1
fi
v5_b=$(match_total_for_id 5 "${body1}")
v100_b=$(match_total_for_id 100 "${body1}")
echo "post-base: rule_id=5 → '${v5_b}' (expect ${N5}); rule_id=100 → '${v100_b}' (expect ${N100})"
if [[ "${v5_b}" != "${N5}" ]]; then
    echo "FAIL[b.5]: rule_match_total{rule_id=5}='${v5_b}' (expected ${N5})" >&2; fail=1
fi
if [[ "${v100_b}" != "${N100}" ]]; then
    echo "FAIL[b.100]: rule_match_total{rule_id=100}='${v100_b}' (expected ${N100})" >&2
    echo "             (sparse id>63 must label + count under its stable id)" >&2; fail=1
fi

# ── (c) apply insert (slot move) → LOAD-BEARING survival + NEGATION ──────
echo "=== (c) apply insert ${INSERT_FIXTURE} (id 50 inserted ⟹ id100 slot 1→2)"
active_before=$(read_active_idx)
rc=$(apply_cfg "${INSERT_FIXTURE}")
echo "apply insert rc=${rc}"
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[c.apply]: insert apply exit ${rc} (expected 0)" >&2; exit 1
fi
active_after=$(read_active_idx)
echo "active_idx ${active_before} → ${active_after} (should flip — proves a real apply)"
if [[ -n "${active_before}" && "${active_before}" == "${active_after}" ]]; then
    echo "FAIL[c.idx]: active_idx did NOT flip across insert apply (still '${active_after}')" >&2; fail=1
fi

code=$(scrape "${body2}")
echo "scrape2 http=${code}"
echo "--- body2 (rule_match_total lines) ---"
grep -E '^xdpfilter_rule_match_total\{' "${body2}" || true
echo "--- end ---"
if [[ "${code}" != "200" ]]; then
    echo "FAIL[c.http]: /metrics http=${code} (expected 200)" >&2; fail=1
fi
v100_c=$(match_total_for_id 100 "${body2}")
v5_c=$(match_total_for_id 5 "${body2}")
v50_c=$(match_total_for_id 50 "${body2}")
echo "post-insert: rule_id=100 → '${v100_c}' (LOAD-BEARING expect ${N100});" \
     "rule_id=5 → '${v5_c}' (expect ${N5}); rule_id=50 → '${v50_c}' (NEGATION expect 0/absent)"

# LOAD-BEARING: id100's counter followed its id across the slot move.
if [[ "${v100_c}" != "${N100}" ]]; then
    echo "FAIL[c.100]: rule_match_total{rule_id=100}='${v100_c}' after slot move (expected STILL ${N100})" >&2
    echo "             PI-3.4b-2-across-slot-move VIOLATED — counter did NOT follow its id" >&2
    echo "             likely cause: copy_rule_counters_forward still keyed by index, not id" >&2
    fail=1
fi
# id5 did not move (slot 0) — must be unchanged.
if [[ "${v5_c}" != "${N5}" ]]; then
    echo "FAIL[c.5]: rule_match_total{rule_id=5}='${v5_c}' after insert (expected STILL ${N5})" >&2; fail=1
fi
# NEGATION CONTROL: id50 is a brand-new id → must read 0 (or be absent).
# Under a slot-keyed BLANKET copy, new-slot-1 (= id50) would inherit
# old-slot-1's value (= id100's ${N100}) — this assert catches exactly
# that failure mode.
if [[ -n "${v50_c}" && "${v50_c}" != "0" ]]; then
    echo "FAIL[c.50.neg]: rule_match_total{rule_id=50}='${v50_c}' (expected 0/absent for a NEW id)" >&2
    echo "                NEGATION TRIPPED: counters appear keyed by SLOT, not id —" >&2
    echo "                id100's old count leaked into id50's series via a blanket index copy" >&2
    fail=1
fi

# ── (d) monotonic continuation: 1 more frame → id100 ─────────────────────
echo "=== (d) inject 1× id100-only (dst ${DST_ID100}) → expect rule_id=100 == $((N100+1))"
read -r p1 d1 m1 c1 < <(read_stats_with_cidr)
inject_n 1 "${DST_ID100}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p1 + d1 + m1 + c1 + 1 )) || true
code=$(scrape "${body3}")
echo "scrape3 http=${code}"
v100_d=$(match_total_for_id 100 "${body3}")
echo "post-continue: rule_id=100 → '${v100_d}' (expect $((N100+1)))"
if [[ "${v100_d}" != "$((N100+1))" ]]; then
    echo "FAIL[d.100]: rule_match_total{rule_id=100}='${v100_d}' (expected $((N100+1)) — monotonic continuation post-move)" >&2
    fail=1
fi

# ── (e) PRIORITY PARITY (Q3, sparse ids): overlap frame → lowest id wins ─
echo "=== (e) inject 1× overlap (dst ${DST_OVERLAP} ∈ id50 /24 ∩ id100 /16) → lowest id (50) wins"
read -r p2 d2 m2 c2 < <(read_stats_with_cidr)
inject_n 1 "${DST_OVERLAP}"
wait_for_stats_sum_with_cidr "${IFACE_A}" $(( p2 + d2 + m2 + c2 + 1 )) || true
code=$(scrape "${body4}")
echo "scrape4 http=${code}"
echo "--- body4 (rule_match_total lines) ---"
grep -E '^xdpfilter_rule_match_total\{' "${body4}" || true
echo "--- end ---"
v50_e=$(match_total_for_id 50 "${body4}")
v100_e=$(match_total_for_id 100 "${body4}")
echo "post-overlap: rule_id=50 → '${v50_e}' (expect 1 — lower id won);" \
     "rule_id=100 → '${v100_e}' (expect STILL $((N100+1)))"
if [[ "${v50_e}" != "1" ]]; then
    echo "FAIL[e.50]: rule_match_total{rule_id=50}='${v50_e}' (expected 1 — first-match-by-lowest-id)" >&2
    echo "            id50 (more-specific, LOWER id) must win the overlap; priority parity broken" >&2
    fail=1
fi
# NEGATION for priority: id100 must NOT have bumped on the overlapping frame.
if [[ "${v100_e}" != "$((N100+1))" ]]; then
    echo "FAIL[e.100.neg]: rule_match_total{rule_id=100}='${v100_e}' bumped on overlap frame (expected STILL $((N100+1)))" >&2
    echo "                 most-specific-wins or wrong-winner bug: id100 must lose to lower id50" >&2
    fail=1
fi

# ── (f)+(g)+(h) Q2 config-validation: sentinel reject / count-cap reject /
#               large-u32-id accept ───────────────────────────────────────
echo "=== (f) Q2 sentinel reject: id == 0xFFFFFFFF (4294967295)"
cat > "${sentinel_cfg}" <<'EOF'
schema_version: 2
default_action: drop
rules:
  - id: 4294967295
    action: pass
    match:
      dst_cidr: "10.7.0.0/16"
EOF
rc=$(apply_cfg "${sentinel_cfg}")
echo "sentinel apply rc=${rc} (expect 9 ConfigError)"
if [[ "${rc}" -ne 9 ]]; then
    echo "FAIL[f]: apply of id==0xFFFFFFFF sentinel exit ${rc} (expected 9 — D-mvp-4.21-SENTINEL)" >&2
    fail=1
fi

echo "=== (g) Q2 count-cap reject: 65 rules > XDPMF_ALLOWLIST_MAX(64)"
{
    echo "schema_version: 2"
    echo "default_action: drop"
    echo "rules:"
    for n in $(seq 1 65); do
        printf '  - id: %d\n    action: pass\n    match:\n      dst_cidr: "10.200.%d.0/24"\n' "$n" "$n"
    done
} > "${countcap_cfg}"
rc=$(apply_cfg "${countcap_cfg}")
echo "count-cap apply rc=${rc} (expect 9 ConfigError)"
if [[ "${rc}" -ne 9 ]]; then
    echo "FAIL[g]: apply of 65 rules exit ${rc} (expected 9 — slot-space count cap)" >&2
    fail=1
fi

echo "=== (h) Q2 sparse accept: ids {100, 4000000000} (both > 63, neither sentinel)"
cat > "${bigid_cfg}" <<'EOF'
schema_version: 2
default_action: drop
rules:
  - id: 100
    action: pass
    match:
      dst_cidr: "10.5.0.0/16"
  - id: 4000000000
    action: pass
    match:
      dst_cidr: "10.100.0.0/16"
EOF
rc=$(apply_cfg "${bigid_cfg}")
echo "big-id apply rc=${rc} (expect 0 — large u32 ids accepted)"
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[h]: apply of ids {100, 4000000000} exit ${rc} (expected 0 — Q2 dense cap removed)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_RULE_COUNTER_SURVIVES_REORDER"
exit "${fail}"
