#!/bin/bash
# T_EXPORTER_BOUNDED_SCAN_INVARIANT — design §5.81.6 TS-1 (MVP-4.41 / PERF-M1).
#
# The exporter's bounded id-scan (dense-prefix early-break, D-mvp-4.41-Q1-A1)
# must be OBSERVATIONALLY INVISIBLE: a scrape with a small live rule count
# emits exactly the config's per-rule series — nothing fewer (bound too tight),
# nothing more (sentinel leak / stale-tail read), no new WARN
# (PI-mvp-4.41-OUTPUT-IDENTITY).
#
# Fixture ids are sparse and non-contiguous on purpose:
#   7, 1000, 4294967294 (= XDPMF_SLOT_ID_EMPTY - 1, the max legal id) —
# exercises guard #29 (slot ≠ operator id; the bound is over SLOTS) and the
# sentinel boundary edge (an off-by-one / >= comparison against
# 0xFFFFFFFF would either drop the 4294967294 series or leak "4294967295").
#
# Trigger:
#   1. setup_veth + apply generated config (N=3, ids 7/1000/4294967294).
#   2. Start xdpmf-exporter; curl /metrics.
#   3. Shrink re-apply (N=1, id 7 only); re-scrape.
#   4. MAY sub-case (§5.81.6 TS-1): apply count=0 config (rules absent);
#      if the loader accepts it, re-scrape and expect ZERO per-rule series
#      (early-break at slot 0). If the loader rejects it, the sub-case is
#      reported as skipped — legality was unverified at design time.
#
# Observable outcome (ALL must hold):
#   (a) scrape-1 emits EXACTLY 3 xdpfilter_rule_match_total series for the
#       iface; the rule_id label set == {7, 1000, 4294967294}.
#   (b) NO series anywhere in the body carries rule_id="4294967295"
#       (XDPMF_SLOT_ID_EMPTY must never leak into a label).
#   (c) NO 'WARN ... rule_counters' line on the exporter's log
#       (covers rule_counters_open_failed AND generation_unstable).
#   (d) other metric families present — xdpfilter_packets_total HELP/TYPE +
#       exactly one HELP/TYPE pair for rule_match_total (scrape not truncated).
#   (e) scrape-2 (after shrink to N=1) emits EXACTLY 1 series (id 7);
#       ids 1000 and 4294967294 are GONE.
#   (f) exporter still alive at the end (kill -0).
#
# Sanity-floor smoke: exporter starts, /healthz polls ready, /metrics → 200.
# Negation controls (2):
#   NC-1 (machinery self-test): a synthetic body line with
#        rule_id="4294967295" MUST be detected by the leak-grep — proves the
#        sentinel-leak assertion can actually fire.
#   NC-2 (live): the shrink re-apply makes previously-present series vanish;
#        if the assertions could not distinguish presence from absence (or the
#        exporter served stale/full-walk data), step (e) trips.
#
# SKIP conditions (guard #31 green-on-SKIP floor): no passwordless sudo or
# XDPMF_CI_BUILD_ONLY=1 → require_passwordless_sudo exits 77 (deterministic,
# never a silent pass); curl absent → 77.
#
# Maps to: §5.81.6 TS-1, PI-mvp-4.41-OUTPUT-IDENTITY, PI-32, guard #26/#29/#31,
#          D-mvp-4.41-Q1-A1, D-mvp-4.41-HG2-ORACLE.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not in PATH (required for /metrics scrape)" >&2
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

# ── generated fixtures (self-contained; sparse non-contiguous ids) ───────
WORK=$(mktemp -d /tmp/xdpmf-boundedscan.XXXXXX)
CFG3="${WORK}/config_sparse3.yaml"
CFG1="${WORK}/config_sparse1.yaml"
CFG0="${WORK}/config_empty.yaml"

cat > "${CFG3}" <<'EOF'
# §5.81.6 TS-1 generated fixture: N=3, sparse non-contiguous ids.
# 4294967294 = XDPMF_SLOT_ID_EMPTY - 1 — the max LEGAL operator id
# (config.cpp rejects only the 4294967295 sentinel itself).
schema_version: 2
default_action: drop
rules:
  - id: 7
    action: pass
    match:
      src_cidr: "10.7.0.0/16"
  - id: 1000
    action: pass
    match:
      src_cidr: "10.100.0.0/16"
  - id: 4294967294
    action: pass
    match:
      src_cidr: "10.200.0.0/16"
EOF

cat > "${CFG1}" <<'EOF'
# §5.81.6 TS-1 shrink fixture: N=1 (negation control NC-2).
schema_version: 2
default_action: drop
rules:
  - id: 7
    action: pass
    match:
      src_cidr: "10.7.0.0/16"
EOF

cat > "${CFG0}" <<'EOF'
# §5.81.6 TS-1 MAY sub-case: count=0 ("rules" absent → empty per config.cpp).
schema_version: 2
default_action: drop
EOF

PORT=$(( 9417 + (($$ + 547) % 1000) ))
echo "EXPORTER_PORT=${PORT}"

body1="${WORK}/body1.txt"
body2="${WORK}/body2.txt"
body3="${WORK}/body3.txt"
exp_log="${WORK}/exporter.log"
stderr_file="${WORK}/apply.stderr"
EXPORTER_PID=""

SIDECAR_DIR="/run/xdpfilter/${IFACE_A}"

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
    rm -rf "${WORK}"
    set -e
}
trap cleanup_test EXIT

fail=0

# Count rule_match_total SAMPLE lines for our iface in a body file.
series_count() {
    local c
    c=$(grep -cE "^xdpfilter_rule_match_total\{iface=\"${IFACE_A}\"," "$1" 2>/dev/null || true)
    echo "${c:-0}"
}

# Count sentinel-leak lines (ANY family) in a body file.
leak_count() {
    local c
    c=$(grep -cE 'rule_id="4294967295"' "$1" 2>/dev/null || true)
    echo "${c:-0}"
}

# Sorted rule_id set of the rule_match_total samples for our iface.
id_set() {
    grep -oE "^xdpfilter_rule_match_total\{iface=\"${IFACE_A}\",rule_id=\"[0-9]+\"" "$1" 2>/dev/null \
        | sed -E 's/.*rule_id="([0-9]+)"$/\1/' | sort -n | tr '\n' ' ' | sed 's/ $//'
}

scrape() {  # scrape <out_body_file>  → echoes http code
    local out="$1" code rc
    set +e
    code=$(curl -s -o "${out}" -w '%{http_code}' -m 5 "http://127.0.0.1:${PORT}/metrics")
    rc=$?
    set -e
    if [[ "${rc}" -ne 0 ]]; then echo "curl_rc_${rc}"; else echo "${code}"; fi
}

# ── NC-1: negation control — leak-grep machinery self-test ───────────────
echo "=== NC-1: sentinel-leak grep self-test"
printf 'xdpfilter_rule_match_total{iface="negctl0",rule_id="4294967295",action="pass"} 0\n' \
    > "${WORK}/negctl.txt"
if [[ "$(leak_count "${WORK}/negctl.txt")" -lt 1 ]]; then
    echo "FAIL[NC-1]: leak-grep failed to detect a synthetic sentinel rule_id — test machinery broken" >&2
    exit 1
fi
echo "NC-1 ok: synthetic sentinel detected"

# ── setup + apply N=3 ─────────────────────────────────────────────────────
setup_veth

echo "=== apply ${CFG3} (N=3, ids 7/1000/4294967294) on ${IFACE_A}"
set +e
apply_config "${CFG3}" "${IFACE_A}" 2>"${stderr_file}"
rc=$?
set -e
cat "${stderr_file}" >&2 || true
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL: apply (N=3) exit ${rc}" >&2
    exit 1
fi

# ── start exporter (smoke) ────────────────────────────────────────────────
echo "=== starting xdpmf-exporter on 127.0.0.1:${PORT}"
sudo -n "${EXPORTER_BIN}" \
    --port "${PORT}" \
    --bind 127.0.0.1 \
    --bpffs-root "${PIN_ROOT}" \
    >"${exp_log}" 2>&1 &
EXPORTER_PID=$!
echo "EXPORTER_PID=${EXPORTER_PID}"

ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT}/healthz" -o /dev/null 2>/dev/null; then
        ready=1
        echo "exporter ready after ${i} polls"
        break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        echo "FAIL: exporter died during startup" >&2
        cat "${exp_log}" >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "${ready}" != "1" ]]; then
    echo "FAIL: exporter not ready within 5s" >&2
    cat "${exp_log}" >&2
    exit 1
fi

# ── scrape 1: N=3 ─────────────────────────────────────────────────────────
echo "=== scrape 1 (N=3)"
code=$(scrape "${body1}")
echo "http=${code}"
echo "--- body 1 ---"; cat "${body1}"; echo "--- end ---"
if [[ "${code}" != "200" ]]; then
    echo "FAIL[smoke]: scrape-1 http='${code}' (expected 200)" >&2
    fail=1
fi

# (a) exactly 3 series, id set == {7, 1000, 4294967294}
n1=$(series_count "${body1}")
ids1=$(id_set "${body1}")
echo "scrape-1: series=${n1} id_set='${ids1}'"
if [[ "${n1}" != "3" ]]; then
    echo "FAIL[a.count]: expected EXACTLY 3 rule_match_total series for ${IFACE_A}, got ${n1}" >&2
    fail=1
fi
if [[ "${ids1}" != "7 1000 4294967294" ]]; then
    echo "FAIL[a.set]: rule_id set '${ids1}' != '7 1000 4294967294'" >&2
    fail=1
fi

# (b) sentinel never leaks
if [[ "$(leak_count "${body1}")" != "0" ]]; then
    echo "FAIL[b]: rule_id=\"4294967295\" (XDPMF_SLOT_ID_EMPTY) leaked into scrape-1" >&2
    fail=1
fi

# (d) families present / scrape not truncated; HELP/TYPE exactly once
for pat in '^# HELP xdpfilter_packets_total ' \
           '^# TYPE xdpfilter_packets_total counter$'; do
    if ! grep -qE "${pat}" "${body1}"; then
        echo "FAIL[d]: missing '${pat}' in scrape-1 (truncated scrape?)" >&2
        fail=1
    fi
done
for pat in '^# HELP xdpfilter_rule_match_total ' \
           '^# TYPE xdpfilter_rule_match_total counter$'; do
    cnt=$(grep -cE "${pat}" "${body1}" 2>/dev/null || true)
    if [[ "${cnt:-0}" != "1" ]]; then
        echo "FAIL[d.once]: expected exactly 1 line matching '${pat}', got ${cnt:-0}" >&2
        fail=1
    fi
done

# ── shrink re-apply N=1 + scrape 2 (NC-2) ────────────────────────────────
echo "=== apply ${CFG1} (shrink to N=1, id 7) on ${IFACE_A}"
set +e
apply_config "${CFG1}" "${IFACE_A}" 2>"${stderr_file}"
rc=$?
set -e
cat "${stderr_file}" >&2 || true
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL: shrink apply (N=1) exit ${rc}" >&2
    exit 1
fi

echo "=== scrape 2 (N=1 after shrink)"
code=$(scrape "${body2}")
echo "http=${code}"
echo "--- body 2 ---"; cat "${body2}"; echo "--- end ---"
if [[ "${code}" != "200" ]]; then
    echo "FAIL[e.http]: scrape-2 http='${code}' (expected 200)" >&2
    fail=1
fi

n2=$(series_count "${body2}")
ids2=$(id_set "${body2}")
echo "scrape-2: series=${n2} id_set='${ids2}'"
if [[ "${n2}" != "1" ]]; then
    echo "FAIL[e.count]: expected EXACTLY 1 series after shrink, got ${n2} (stale tail / bound not tracking live count?)" >&2
    fail=1
fi
if [[ "${ids2}" != "7" ]]; then
    echo "FAIL[e.set]: post-shrink rule_id set '${ids2}' != '7'" >&2
    fail=1
fi
for gone in 1000 4294967294; do
    if grep -qE "^xdpfilter_rule_match_total\{iface=\"${IFACE_A}\",rule_id=\"${gone}\"," "${body2}"; then
        echo "FAIL[e.gone.${gone}]: rule_id=${gone} still emitted after shrink (NC-2 negation trip)" >&2
        fail=1
    fi
done
if [[ "$(leak_count "${body2}")" != "0" ]]; then
    echo "FAIL[e.leak]: sentinel rule_id leaked into scrape-2" >&2
    fail=1
fi

# ── MAY sub-case: count=0 (§5.81.6 TS-1 — NOT a required assertion) ──────
echo "=== MAY sub-case: apply ${CFG0} (count=0)"
set +e
apply_config "${CFG0}" "${IFACE_A}" 2>"${stderr_file}"
rc0=$?
set -e
cat "${stderr_file}" >&2 || true
if [[ "${rc0}" -ne 0 ]]; then
    echo "NOTE: count=0 config rejected by loader (rc=${rc0}) — MAY sub-case skipped per §5.81.6"
else
    echo "=== scrape 3 (count=0)"
    code=$(scrape "${body3}")
    echo "http=${code}"
    echo "--- body 3 ---"; cat "${body3}"; echo "--- end ---"
    if [[ "${code}" != "200" ]]; then
        echo "FAIL[z.http]: scrape-3 http='${code}' (expected 200)" >&2
        fail=1
    fi
    n3=$(series_count "${body3}")
    echo "scrape-3: series=${n3}"
    if [[ "${n3}" != "0" ]]; then
        echo "FAIL[z.count]: count=0 config but ${n3} per-rule series emitted (break-at-slot-0 edge)" >&2
        fail=1
    fi
    if ! grep -qE '^# HELP xdpfilter_packets_total ' "${body3}"; then
        echo "FAIL[z.pkts]: packets_total family missing at count=0 (graceful-empty regression)" >&2
        fail=1
    fi
    if [[ "$(leak_count "${body3}")" != "0" ]]; then
        echo "FAIL[z.leak]: sentinel rule_id leaked into scrape-3" >&2
        fail=1
    fi
fi

# ── (c) no rule_counters WARN across the whole run ───────────────────────
if grep -E 'WARN.*rule_counters' "${exp_log}"; then
    echo "FAIL[c]: rule_counters WARN on exporter log (output-identity / PI-32 violation)" >&2
    fail=1
fi

# ── (f) exporter survived ─────────────────────────────────────────────────
if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
    echo "FAIL[f]: exporter PID ${EXPORTER_PID} died during the run" >&2
    cat "${exp_log}" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_EXPORTER_BOUNDED_SCAN_INVARIANT"
exit "${fail}"
