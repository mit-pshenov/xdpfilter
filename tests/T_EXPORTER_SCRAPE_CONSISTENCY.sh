#!/bin/bash
# T_EXPORTER_SCRAPE_CONSISTENCY — design §6.82 (MVP-4.24 / §5.64).
#
# Verifies the exporter's per-iface rule_counters scrape is a SINGLE
# consistent generation under a concurrent loader atomic-swap (`apply -f`),
# closing the active_idx-selector TOCTOU read-skew (P1 from
# external-review-2026-06.md). The fix under test is an active_idx-as-seqlock
# retry loop in src/exporter/rule_counters_reader.cpp (D-mvp-4.24-SEQNUM);
# this test is written against the §6.82 CONTRACT, not impl's code.
#
# ── Generation fingerprint (the discriminator) ────────────────────────────
# Two single-rule configs produce distinguishable generations:
#   config_gen_a.yaml → id RA=11 @ slot 0  (src 10.11.0.0/16)
#   config_gen_b.yaml → id RB=22 @ slot 0  (src 10.22.0.0/16)
# The exporter emits one `xdpfilter_rule_match_total{iface,rule_id,action}`
# series per NON-SENTINEL slot, with rule_id = slot_to_id[slot] read from the
# `slot_rule_id` BPF map's ACTIVE half (prom_format.cpp:135-144). So the SET
# of rule_ids in a scrape is the generation fingerprint — {11} for gen A,
# {22} for gen B — and it is observable even at counter 0 (the series is
# emitted per occupied slot regardless of count). A consistent scrape reports
# EXACTLY {11} or EXACTLY {22}; never {11,22} (cross-generation mix) and never
# {} (torn/partial) while the iface is attached.
#
# ── Honesty note (§5.60 discipline) ───────────────────────────────────────
# The pre-fix code reads active_idx ONCE then reads both buffers from that
# snapshot, so it returns CONSISTENT-BUT-STALE (never torn) — a pure
# consistency assertion is therefore near-vacuous on this codebase (guard
# #32). That is WHY this test carries (1) a deterministic generation-
# sensitivity control that catches a frozen/ignored-selector regression and
# (3) a generation-change observability guard that FAILS "could not stage the
# race" rather than passing vacuously. Per-overlap FRESHNESS (a scrape whose
# read window overlaps a flip preferring the NEW gen) is BEST-EFFORT after
# bounded retry (D-mvp-4.24-Q1, N=3 fallback may legitimately serve the old
# consistent gen) — so part 2 does NOT hard-assert "overlapping scrape ==
# newest gen". The deterministic freshness contract is part 1 (settled scrape
# == current gen); the hard race assertion is CONSISTENCY. The X→Y→X two-
# applies-in-one-scrape tear is OOS-impossible (D-mvp-4.24-TEAR-HONESTY) and
# is NOT asserted.
#
# ── Sanity floor ──────────────────────────────────────────────────────────
#   Smoke           : exporter loads + /healthz + /metrics return 200 (part 1).
#   Negation control: part 3 — if the apply/scrape loops never interleave
#                     (only one generation ever observed, or active_idx never
#                     transitions) the test FAILS "could not stage the race".
#                     Part 1 additionally catches a reader frozen on a stale
#                     generation. A test that cannot fail proves nothing.
#
# SKIP conditions: passwordless sudo absent → 77; curl absent → 77.
#
# Maps to: §6.82 (parts 1/2/3), D-mvp-4.24-SEQNUM/WINDOW/Q1, PI-31-mvp-4.24,
#          PI-32-mvp-4.24, guard #32.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not in PATH (required by §6.82)" >&2
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
EXPORTER_BIN=$(find_exporter) || { echo "FAIL: xdpmf-exporter binary not found under ${BUILD_DIR}" >&2; exit 1; }

GEN_A="${TEST_DIR}/fixtures/config_gen_a.yaml"
GEN_B="${TEST_DIR}/fixtures/config_gen_b.yaml"
for f in "${GEN_A}" "${GEN_B}"; do
    [[ -f "$f" ]] || { echo "FAIL: missing fixture $f" >&2; exit 1; }
done

# Generation fingerprints (operator ids).
RA=11
RB=22
SRC_MAC="02:00:00:00:00:aa"   # MAC axis wildcard in both gens — value irrelevant
SRC_IP_A="10.11.0.7"          # ∈ 10.11.0.0/16 → matches gen-A rule id 11
SRC_IP_B="10.22.0.7"          # ∈ 10.22.0.0/16 → matches gen-B rule id 22

# Port derived from PID; exporter_port_9417 RESOURCE_LOCK serialises against
# the other exporter-spawning tests.
PORT=$(( 9417 + ($$ % 1000) ))
echo "EXPORTER_PORT=${PORT}"

body=$(mktemp /tmp/xdpmf-scrapecons-body.XXXXXX)
exp_log=$(mktemp /tmp/xdpmf-scrapecons-explog.XXXXXX)
stderr_file=$(mktemp /tmp/xdpmf-scrapecons-stderr.XXXXXX)
apply_log=$(mktemp /tmp/xdpmf-scrapecons-applylog.XXXXXX)
EXPORTER_PID=""
APPLY_LOOP_PID=""

cleanup_test() {
    set +e
    if [[ -n "${APPLY_LOOP_PID}" ]]; then
        kill "${APPLY_LOOP_PID}" 2>/dev/null
        wait "${APPLY_LOOP_PID}" 2>/dev/null
    fi
    # belt-and-suspenders: kill any straggler loader still mid-apply
    kill_loader_keep_link "${IFACE_A}"
    if [[ -n "${EXPORTER_PID}" ]]; then
        sudo -n kill "${EXPORTER_PID}" 2>/dev/null
        sleep 0.2
        sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null
        wait "${EXPORTER_PID}" 2>/dev/null
    fi
    cleanup_veth
    sudo -n rm -rf "/run/xdpfilter/${IFACE_A}" 2>/dev/null
    rm -f "${body}" "${exp_log}" "${stderr_file}" "${apply_log}"
    set -e
}
trap cleanup_test EXIT

fail=0

apply_gen() {  # apply_gen <fixture>
    local fixture="$1"
    ${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${fixture}" >>"${apply_log}" 2>&1
}

scrape() {  # scrape -> writes body file, echoes http_code (or 000 on curl err)
    local code
    set +e
    code=$(curl -s -o "${body}" -w '%{http_code}' -m 5 "http://127.0.0.1:${PORT}/metrics" 2>/dev/null)
    [[ $? -ne 0 ]] && code="000"
    set -e
    printf '%s\n' "${code}"
}

# fingerprint_of <body-file> -> sorted-unique comma-joined rule_id set for IFACE_A
# e.g. "11", "22", "11,22", or "" (no series).
fingerprint_of() {
    grep -E "^xdpfilter_rule_match_total\{iface=\"${IFACE_A}\",rule_id=\"[0-9]+\"," "$1" 2>/dev/null \
        | sed -nE 's/.*rule_id="([0-9]+)".*/\1/p' | sort -un | paste -sd, -
}

# counter_of <body-file> <rule_id> -> echoes counter value, or empty if absent
counter_of() {
    grep -E "^xdpfilter_rule_match_total\{iface=\"${IFACE_A}\",rule_id=\"$2\",action=\"[^\"]+\"\} [0-9]+$" "$1" 2>/dev/null \
        | head -n1 | sed -nE 's/.*\} ([0-9]+)$/\1/p'
}

setup_veth

# ── Start the exporter ONCE (re-reads the maps on every scrape) ───────────
# §6.82 runs the exporter under JSON log format so the rare
# rule_counters_generation_unstable diagnostic (retry exhaustion) is
# machine-parseable if it ever fires; we do not hard-assert it (single applies
# converge within N=3 retries — D-mvp-4.24-Q1).
echo "=== starting xdpmf-exporter on 127.0.0.1:${PORT}"
sudo -n env XDPMF_LOG_FORMAT=json "${EXPORTER_BIN}" \
    --port "${PORT}" --bind 127.0.0.1 --bpffs-root "${PIN_ROOT}" \
    >"${exp_log}" 2>&1 &
EXPORTER_PID=$!

# Apply gen A FIRST so the iface is attached before the readiness probe scrapes.
echo "=== apply gen A (id ${RA}) for initial attach"
apply_gen "${GEN_A}"

ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT}/healthz" -o /dev/null 2>/dev/null; then
        ready=1; echo "exporter ready after ${i} polls"; break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        echo "FAIL: exporter died during startup" >&2; cat "${exp_log}" >&2; exit 1
    fi
    sleep 0.1
done
[[ "${ready}" == 1 ]] || { echo "FAIL: exporter not ready within 5s" >&2; cat "${exp_log}" >&2; exit 1; }

# ════════════════════════════════════════════════════════════════════════════
# PART 1 — Generation-sensitivity control (non-vacuity backbone; serial).
#   Proves (i) the observable distinguishes generations and (ii) a reader
#   frozen on a stale generation (or ignoring active_idx entirely) is caught
#   deterministically. apply A → scrape == {RA}; apply B → scrape == {RB}.
# ════════════════════════════════════════════════════════════════════════════
echo
echo "═══ PART 1: deterministic generation-sensitivity control ═══"

# --- 1a: gen A settled -> scrape reports id RA (and NOT RB), counter bumped ---
N_A=4
echo "--- inject ${N_A}× gen-A traffic (src ${SRC_IP_A} → id ${RA})"
for _ in $(seq 1 ${N_A}); do
    ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "${SRC_IP_A}"
done
wait_for_stats_sum_with_cidr "${IFACE_A}" "${N_A}" 3000 20 \
    || { echo "FAIL[1a.stats]: gen-A pass counter never reached ${N_A}" >&2; fail=1; }

code=$(scrape)
echo "scrape http=${code}"
[[ "${code}" == "200" ]] || { echo "FAIL[1a.http]: scrape http=${code} (expected 200)" >&2; fail=1; }
fp=$(fingerprint_of "${body}")
echo "fingerprint after gen A = '${fp}'"
if [[ "${fp}" != "${RA}" ]]; then
    echo "FAIL[1a.fp]: expected fingerprint '${RA}', got '${fp}' — exporter did not reflect gen A" >&2
    echo "--- body ---" >&2; cat "${body}" >&2
    fail=1
fi
cval=$(counter_of "${body}" "${RA}")
echo "rule_id=${RA} counter=${cval:-<absent>}"
if [[ -z "${cval}" ]] || (( cval < N_A )); then
    echo "FAIL[1a.ctr]: rule_id=${RA} counter='${cval:-absent}' (expected ≥ ${N_A})" >&2
    fail=1
fi

# --- 1b: gen B settled -> scrape now reports id RB (and NOT RA) ---
echo "--- apply gen B (id ${RB}); inject ${N_A}× gen-B traffic (src ${SRC_IP_B})"
apply_gen "${GEN_B}"
# active_idx flips on the swap; the new gen-B counter starts at 0 (copy-forward
# carries no id-22 from gen A). Inject to make it non-zero.
for _ in $(seq 1 ${N_A}); do
    ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "${SRC_IP_B}"
done
# Poll the EXPORTER until it observes id RB with counter ≥ N_A (the settled
# new generation). This is the load-bearing "not frozen on stale gen" check.
got_b=0
for _ in $(seq 1 50); do
    code=$(scrape)
    [[ "${code}" == "200" ]] || { sleep 0.1; continue; }
    cval=$(counter_of "${body}" "${RB}")
    if [[ -n "${cval}" ]] && (( cval >= N_A )); then got_b=1; break; fi
    sleep 0.1
done
fp=$(fingerprint_of "${body}")
echo "fingerprint after gen B = '${fp}'   rule_id=${RB} counter=$(counter_of "${body}" "${RB}")"
if [[ "${got_b}" != 1 ]]; then
    echo "FAIL[1b.frozen]: exporter never reported gen B (id ${RB}) with counter ≥ ${N_A}" >&2
    echo "                 a reader frozen on the stale generation is caught HERE" >&2
    echo "--- body ---" >&2; cat "${body}" >&2
    fail=1
fi
if [[ "${fp}" != "${RB}" ]]; then
    echo "FAIL[1b.fp]: expected fingerprint '${RB}' after gen B, got '${fp}'" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PART 1: PASS (observable distinguishes generations; not frozen)"

# ════════════════════════════════════════════════════════════════════════════
# PART 2 — Concurrency consistency (the race).
#   Background: alternate apply gen A / gen B as fast as possible.
#   Foreground: scrape as fast as possible, collect every fingerprint.
#   HARD assert (every 200-scrape): fingerprint is a SINGLE consistent
#   generation ∈ {RA, RB}; never a cross-mix {RA,RB}; never empty {} (torn).
# ════════════════════════════════════════════════════════════════════════════
echo
echo "═══ PART 2: concurrency consistency under apply-flip race ═══"

RACE_SECS=5

# Background flip loop: alternate gen A / gen B until the deadline.
(
    set +e
    deadline=$(( $(date +%s) + RACE_SECS ))
    while (( $(date +%s) < deadline )); do
        ${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${GEN_A}" >>"${apply_log}" 2>&1
        ${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${GEN_B}" >>"${apply_log}" 2>&1
    done
) &
APPLY_LOOP_PID=$!

declare -A SEEN_FP=()
declare -A SEEN_AIDX=()
scrapes=0
bad_mix=0
bad_empty=0
race_deadline=$(( $(date +%s) + RACE_SECS ))
while (( $(date +%s) < race_deadline )); do
    code=$(scrape)
    [[ "${code}" == "200" ]] || continue
    scrapes=$(( scrapes + 1 ))
    fp=$(fingerprint_of "${body}")
    SEEN_FP["${fp}"]=1
    # sample the shared active_idx selector to evidence the transition
    aidx=$(active_idx_of "${IFACE_A}")
    [[ -n "${aidx}" ]] && SEEN_AIDX["${aidx}"]=1
    case "${fp}" in
        "${RA}"|"${RB}") : ;;                         # single consistent gen — OK
        "${RA},${RB}"|"${RB},${RA}")                  # cross-generation mix — FAIL
            echo "FAIL[2.mix]: scrape reported BOTH generations: fp='${fp}' (cross-gen tear)" >&2
            bad_mix=$(( bad_mix + 1 )); fail=1 ;;
        "")                                           # empty while attached — torn/partial
            echo "FAIL[2.empty]: scrape reported NO rule_match_total series while iface attached (torn/partial)" >&2
            bad_empty=$(( bad_empty + 1 )); fail=1 ;;
        *)
            echo "FAIL[2.unknown]: unexpected fingerprint '${fp}' (∉ {${RA},${RB}})" >&2
            fail=1 ;;
    esac
done

wait "${APPLY_LOOP_PID}" 2>/dev/null || true
APPLY_LOOP_PID=""

echo "race summary: scrapes(200)=${scrapes} cross-mix=${bad_mix} empty=${bad_empty}"
echo "distinct fingerprints seen: ${!SEEN_FP[*]}"
echo "distinct active_idx values seen: ${!SEEN_AIDX[*]}"

if (( scrapes < 5 )); then
    echo "FAIL[2.scrapes]: only ${scrapes} successful scrapes during the race (harness too slow / exporter wedged)" >&2
    fail=1
fi
[[ "${fail}" == 0 ]] && echo "PART 2: PASS (every scrape was a single consistent generation)"

# ════════════════════════════════════════════════════════════════════════════
# PART 3 — Generation-change observability guard (NON-VACUITY / negation control).
#   The race in part 2 must have ACTUALLY interleaved flip-with-scrape:
#     (a) BOTH generations {RA} and {RB} appeared across the scrapes, AND
#     (b) the shared active_idx selector was observed to transition (≥2 values).
#   If only one generation ever appears OR active_idx never moves, the loops
#   never interleaved → the consistency assertion in part 2 is meaningless →
#   FAIL "could not stage the race" (NOT a vacuous pass).
# ════════════════════════════════════════════════════════════════════════════
echo
echo "═══ PART 3: generation-change observability guard (non-vacuity) ═══"

saw_a=${SEEN_FP[${RA}]:-0}
saw_b=${SEEN_FP[${RB}]:-0}
n_aidx=${#SEEN_AIDX[@]}
echo "saw gen A({${RA}})=${saw_a}  saw gen B({${RB}})=${saw_b}  distinct active_idx=${n_aidx}"

if [[ "${saw_a}" != 1 || "${saw_b}" != 1 ]]; then
    echo "FAIL[3.stage]: could not stage the race — only one generation observed" >&2
    echo "              (saw A=${saw_a}, saw B=${saw_b}); the apply/scrape loops never" >&2
    echo "              interleaved, so part 2's consistency assertion is VACUOUS." >&2
    fail=1
fi
if (( n_aidx < 2 )); then
    echo "FAIL[3.aidx]: active_idx never observed to transition (distinct values=${n_aidx})" >&2
    echo "              the atomic-swap flip did not interleave with scraping → race not staged." >&2
    fail=1
fi
[[ "${fail}" == 0 ]] && echo "PART 3: PASS (race demonstrably staged: both generations + active_idx transition observed)"

echo
if [[ "${fail}" == 0 ]]; then
    echo "PASS: T_EXPORTER_SCRAPE_CONSISTENCY"
else
    echo "FAIL: T_EXPORTER_SCRAPE_CONSISTENCY (see FAIL[...] lines above)" >&2
fi
exit "${fail}"
