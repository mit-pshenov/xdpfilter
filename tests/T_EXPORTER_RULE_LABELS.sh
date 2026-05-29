#!/bin/bash
# T_EXPORTER_RULE_LABELS — design §6.51 (MVP-3.4b cycle 1 / §5.31).
#
# Exporter emits xdpfilter_rule_match_total{iface, rule_id, action}
# Prometheus series per Q4 A3 + D-3.4b-8 + PI-3.4b-6. Sidecar-orphan
# tolerance per PI-32-3.4b — deleting rule_index.json mid-scrape leaves
# exporter alive + emits action="unknown" labels.
#
# Trigger:
#   1. setup_veth + apply config_per_rule_counters.yaml.
#   2. Inject mixed traffic to advance multiple rule_ids
#      (rule_id=0 + rule_id=5 + rule_id=42 via CIDR).
#   3. Start xdpmf-exporter; curl /metrics.
#   4. Delete sidecar; re-scrape; verify action="unknown" labels appear
#      for rule_ids that have counter > 0 but no sidecar entry.
#
# Observable outcome (ALL must hold):
#   (a) HTTP 200; Content-Type contains 'text/plain; version=0.0.4'.
#   (b) Body contains exactly one '# HELP xdpfilter_rule_match_total ...' line.
#   (c) Body contains exactly one '# TYPE xdpfilter_rule_match_total counter' line.
#   (d) Body contains ≥1 line matching the sample ERE
#       '^xdpfilter_rule_match_total\{iface="[^"]+",rule_id="[0-9]+",action="(pass|drop|unknown)"\} [0-9]+$'.
#   (e) For each rule_id with non-zero traffic (we injected for 0, 5, 42),
#       the emitted sample line shows action matching the fixture
#       (id=0 → pass; id=5 → pass; id=42 → pass).
#   (f) Existing xdpfilter_packets_total series UNCHANGED (PI-31-3.4b).
#   (g) SIDECAR-ORPHAN sub-test: delete rule_index.json; re-scrape;
#       rule_ids in BPF map with counter > 0 emit with action="unknown".
#       Exporter MUST NOT crash; kill -0 confirms it's still alive.
#
# Sanity-floor smoke: step (a) — curl returns 200 + exporter alive.
# Negation control: step (g) — delete sidecar mid-scrape; if exporter
# crashed OR series disappeared entirely, the negation triggers.
# action="unknown" must appear for previously-tracked rule_ids.
#
# SKIP conditions: curl absent → exit 77.
#
# Note: per §5.31 EDIT-1 (Phase B platform-constraint correction), the
# sidecar lives at /run/xdpmacfilter/<iface>/rule_index.json (NOT under
# bpffs ${PIN_DIR}). The orphan-tolerance sub-test deletes the file at
# the corrected path; the BPF map `rule_counters` still lives under
# bpffs at ${PIN_DIR}/<iface>/rule_counters.
#
# Maps to: PI-3.4b-6, PI-31-3.4b, PI-32-3.4b, Q4 A3, D-3.4b-8, D-3.4b-21.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

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

if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not in PATH (required by §6.51)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
EXPORTER_BIN=$(find_exporter) || {
    echo "FAIL: xdpmf-exporter binary not found under ${BUILD_DIR}" >&2
    exit 1
}
FIXTURE="${TEST_DIR}/fixtures/config_per_rule_counters.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }
# §6.51-EXT (MVP-4.6 / §5.46; EXTENDED §5.47 MVP-4.7): the 6-axis fixture drives
# the rule_info family per-axis label assertions (config-derived; no traffic
# injection needed). MVP-4.7 adds the `mac` label (8th key, LAST).
AND6_FIXTURE="${TEST_DIR}/fixtures/config_valid_and6.yaml"
[[ -f "${AND6_FIXTURE}" ]] || { echo "FAIL: missing fixture ${AND6_FIXTURE}" >&2; exit 1; }

# Port derived from PID; exporter_port_9417 RESOURCE_LOCK serializes
# against the other exporter-spawning tests.
PORT=$(( 9417 + ($$ % 1000) ))
echo "EXPORTER_PORT=${PORT}"

metrics_body=$(mktemp /tmp/xdpmf-rulelabel-body.XXXXXX)
metrics_hdrs=$(mktemp /tmp/xdpmf-rulelabel-hdrs.XXXXXX)
exp_log=$(mktemp /tmp/xdpmf-rulelabel-explog.XXXXXX)
stderr_file=$(mktemp /tmp/xdpmf-rulelabel-stderr.XXXXXX)
metrics_body2=$(mktemp /tmp/xdpmf-rulelabel-body2.XXXXXX)
metrics_body3=$(mktemp /tmp/xdpmf-rulelabel-body3.XXXXXX)
EXPORTER_PID=""

# §5.31 EDIT-1: sidecar path = /run/xdpmacfilter/<iface>/rule_index.json
SIDECAR_ROOT="/run/xdpmacfilter"
SIDECAR_DIR="${SIDECAR_ROOT}/${IFACE_A}"
SIDECAR_PATH="${SIDECAR_DIR}/rule_index.json"

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
    rm -f "${metrics_body}" "${metrics_hdrs}" "${metrics_body2}" \
          "${metrics_body3}" "${exp_log}" "${stderr_file}"
    set -e
}
trap cleanup_test EXIT

# §5.43 MVP-4.3: MAC deferred → all rules src_cidr. Per-id src_ip:
#   id0 → 10.0.0.1 (10.0.0.0/16), id5 → 10.5.0.1 (10.5.0.0/16),
#   id42 → 10.42.0.5 (10.42.0.0/16).
SRC_MAC="02:00:00:00:00:aa"         # MAC axis deferred — value irrelevant
SRC_IP_ID0="10.0.0.1"
SRC_IP_ID5="10.5.0.1"
SRC_IP_ID42="10.42.0.5"

setup_veth

# ── apply + traffic ──────────────────────────────────────────────────────
echo "=== apply ${FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
cat "${stderr_file}" >&2 || true
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL: apply exit ${rc}" >&2
    exit 1
fi

# Inject mixed: 2× id=0, 3× id=5, 1× id=42 — all via src_cidr (§5.43).
echo "=== inject 2× rule_id=0 (src ${SRC_IP_ID0})"
for i in 1 2; do ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "${SRC_IP_ID0}"; done
echo "=== inject 3× rule_id=5 (src ${SRC_IP_ID5})"
for i in 1 2 3; do ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "${SRC_IP_ID5}"; done
echo "=== inject 1× rule_id=42 (src ${SRC_IP_ID42})"
${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
    "${IFACE_B}" "${SRC_MAC}" "${MAC_DST}" "${SRC_IP_ID42}"

# Wait for the BPF stats counters to catch up before scraping.
sleep 0.3

# ── start exporter ───────────────────────────────────────────────────────
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

# ── scrape /metrics ──────────────────────────────────────────────────────
echo "=== curl /metrics"
set +e
http_code=$(curl -s -o "${metrics_body}" -D "${metrics_hdrs}" -w '%{http_code}' \
    -m 5 "http://127.0.0.1:${PORT}/metrics")
curl_rc=$?
set -e
echo "curl rc=${curl_rc} http_code=${http_code}"
echo "--- response headers ---"
cat "${metrics_hdrs}"
echo "--- response body ---"
cat "${metrics_body}"
echo "--- end ---"

fail=0

# (a) HTTP 200 + Content-Type
if [[ "${curl_rc}" -ne 0 ]] || [[ "${http_code}" != "200" ]]; then
    echo "FAIL[a]: curl rc=${curl_rc} http=${http_code} (expected 0 + 200)" >&2
    fail=1
fi
if ! grep -qiE '^content-type:.*text/plain.*version=0\.0\.4' "${metrics_hdrs}"; then
    echo "FAIL[a.ct]: Content-Type missing 'text/plain; version=0.0.4'" >&2
    fail=1
fi

# (b) Exactly one HELP line for the NEW series.
help_count=$(grep -cE '^# HELP xdpfilter_rule_match_total ' "${metrics_body}" 2>/dev/null || true)
help_count=${help_count:-0}
echo "HELP xdpfilter_rule_match_total count: ${help_count}"
if [[ "${help_count}" != "1" ]]; then
    echo "FAIL[b]: expected exactly 1 HELP line for xdpfilter_rule_match_total, got ${help_count}" >&2
    fail=1
fi

# (c) Exactly one TYPE line for the NEW series, with 'counter' type.
type_count=$(grep -cE '^# TYPE xdpfilter_rule_match_total counter$' "${metrics_body}" 2>/dev/null || true)
type_count=${type_count:-0}
echo "TYPE xdpfilter_rule_match_total counter count: ${type_count}"
if [[ "${type_count}" != "1" ]]; then
    echo "FAIL[c]: expected exactly 1 TYPE line for xdpfilter_rule_match_total counter, got ${type_count}" >&2
    fail=1
fi

# (d) ≥1 sample line matching the labelled ERE.
sample_ere='^xdpfilter_rule_match_total\{iface="[^"]+",rule_id="[0-9]+",action="(pass|drop|unknown)"\} [0-9]+$'
sample_count=$(grep -cE "${sample_ere}" "${metrics_body}" 2>/dev/null || true)
sample_count=${sample_count:-0}
echo "rule_match_total sample line count: ${sample_count}"
if (( sample_count < 1 )); then
    echo "FAIL[d]: expected ≥1 sample line matching ERE:" >&2
    echo "         ${sample_ere}" >&2
    fail=1
fi

# (e) Specific rule_ids 0, 5, 42 should show action=pass (per fixture).
# Note: label order is iface,rule_id,action per design §5.31.
for id in 0 5 42; do
    line=$(grep -E "^xdpfilter_rule_match_total\{iface=\"${IFACE_A}\",rule_id=\"${id}\",action=\"[^\"]+\"\} [0-9]+$" "${metrics_body}" 2>/dev/null | head -n1 || true)
    echo "  rule_id=${id}: line='${line}'"
    if [[ -z "${line}" ]]; then
        echo "FAIL[e.${id}]: no series for rule_id=${id} found" >&2
        fail=1
        continue
    fi
    # Extract action label.
    got_action=$(echo "${line}" | sed -nE 's/.*action="([^"]+)".*/\1/p')
    if [[ "${got_action}" != "pass" ]]; then
        echo "FAIL[e.${id}.action]: rule_id=${id} action='${got_action}' (expected pass)" >&2
        fail=1
    fi
done

# (f) Existing xdpfilter_packets_total series PRESERVED (PI-31-3.4b).
if ! grep -qE '^# HELP xdpfilter_packets_total ' "${metrics_body}"; then
    echo "FAIL[f1]: xdpfilter_packets_total HELP line missing (PI-31-3.4b regression)" >&2
    fail=1
fi
if ! grep -qE '^# TYPE xdpfilter_packets_total counter$' "${metrics_body}"; then
    echo "FAIL[f2]: xdpfilter_packets_total TYPE line missing (PI-31-3.4b regression)" >&2
    fail=1
fi
packets_sample=$(grep -cE '^xdpfilter_packets_total\{iface="[^"]+",verdict="(pass|drop_deny|drop_malformed|pass_cidr)"\} [0-9]+$' "${metrics_body}" 2>/dev/null || true)
packets_sample=${packets_sample:-0}
if (( packets_sample < 1 )); then
    echo "FAIL[f3]: no xdpfilter_packets_total sample lines (PI-31-3.4b regression)" >&2
    fail=1
fi

# ── (g) SIDECAR-ORPHAN TOLERANCE sub-test ────────────────────────────────
echo
echo "=== step (g): SIDECAR-ORPHAN tolerance — delete sidecar; expect action=unknown"
sudo -n rm -f "${SIDECAR_PATH}"
if sudo -n test -e "${SIDECAR_PATH}"; then
    echo "FAIL[g.setup]: could not delete sidecar (still present)" >&2
    fail=1
fi

# Re-scrape /metrics.
set +e
http_code2=$(curl -s -o "${metrics_body2}" -w '%{http_code}' \
    -m 5 "http://127.0.0.1:${PORT}/metrics")
curl2_rc=$?
set -e
echo "second scrape: rc=${curl2_rc} http=${http_code2}"
echo "--- body (post-sidecar-delete) ---"
cat "${metrics_body2}"
echo "--- end ---"

# Exporter must NOT have crashed.
if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
    echo "FAIL[g.alive]: exporter PID ${EXPORTER_PID} died after sidecar delete" >&2
    echo "              PI-32-3.4b sidecar-orphan tolerance VIOLATED" >&2
    fail=1
fi

if [[ "${http_code2}" != "200" ]]; then
    echo "FAIL[g.http]: post-sidecar-delete scrape http=${http_code2} (expected 200)" >&2
    fail=1
fi

# For previously-tracked rule_ids (0, 5, 42), the action label MUST be
# "unknown" now (sidecar absent → exporter cannot resolve action).
for id in 0 5 42; do
    line=$(grep -E "^xdpfilter_rule_match_total\{iface=\"${IFACE_A}\",rule_id=\"${id}\",action=\"[^\"]+\"\} [0-9]+$" "${metrics_body2}" 2>/dev/null | head -n1 || true)
    echo "  post-delete rule_id=${id}: line='${line}'"
    if [[ -z "${line}" ]]; then
        echo "FAIL[g.${id}.absent]: rule_id=${id} series MISSING post-sidecar-delete" >&2
        echo "                     PI-32-3.4b: exporter must STILL emit the data point with action=unknown" >&2
        fail=1
        continue
    fi
    got_action=$(echo "${line}" | sed -nE 's/.*action="([^"]+)".*/\1/p')
    if [[ "${got_action}" != "unknown" ]]; then
        echo "FAIL[g.${id}.action]: rule_id=${id} action='${got_action}' (expected 'unknown' per PI-32-3.4b)" >&2
        fail=1
    fi
done

# ══════════════════════════════════════════════════════════════════════════
# §6.51-EXT (MVP-4.6 / §5.46; EXTENDED §5.47 MVP-4.7): xdpfilter_rule_info
# per-axis label family — now 6 axes.
#
# The info-metric surfaces each sidecar-known rule's 6-axis match constraints as
# Prometheus labels (mac is the 8th key, appended LAST per D-mvp-4.7-Q3):
#   xdpfilter_rule_info{iface,rule_id,dst_cidr,src_cidr,protocol,dst_port,vlan,mac} 1
# Stable 8-key set in fixed order; unconstrained axis → empty sentinel "";
# value always literal 1; emitted AFTER both counter families (block order).
#
# rule_info is CONFIG-derived (from rule_index.json), NOT packet-derived — no
# traffic injection is needed. We re-setup the fixture on the SAME iface with
# the rich 6-axis config_valid_and6.yaml so every axis is exercised:
#   id 0 : FULL 6-axis  dst 10.1.0.0/16 + src 192.168.5.0/24 + tcp + 1000-2000
#          + vlan 100 + mac aa:bb:cc:dd:ee:01
#   id 1 : vlan 200 + udp + mac aa:bb:cc:dd:ee:02
#   id 2 : vlan 300 only                 (5 axes unconstrained — incl. mac="")
#   id 3 : dst 10.5.0.0/16 + vlan 100    (mac unconstrained)
#   id 4 : dst 10.5.0.0/16 only          (vlan + mac unconstrained)
#   id 5 : dst_port 443 only             (5 axes unconstrained — incl. mac="")
#   id 6 : mac aa:bb:cc:dd:ee:06 only    (5 axes unconstrained)
#
# Assertions: (a) HELP/TYPE-once; (b) stable 8-key sample ERE, value=1;
# (c) POSITIVE per-axis (id0 carries all SIX fixture values verbatim incl. mac);
# (d) SENTINEL (id5 unconstrained axes incl. mac show ="" );
# (e) NEGATION (an unconstrained axis is NEVER a bogus value — only ""; a
#     non-configured rule_id emits NO rule_info series);
# (f) STABLE KEY SET (every series matches the 8-key ERE);
# (g) COUNTER-CONTRACT — verified above (existing counter-family steps remain
#     byte-equivalent; the rule_info label-set growth is purely additive).
echo
echo "═══ §6.51-EXT: xdpfilter_rule_info per-axis labels (config_valid_and6.yaml) ═══"

# Tear down scenario-1 exporter + veth; re-setup with the 5-axis fixture.
if [[ -n "${EXPORTER_PID}" ]]; then
    sudo -n kill "${EXPORTER_PID}" 2>/dev/null || true
    sleep 0.2
    sudo -n kill -9 "${EXPORTER_PID}" 2>/dev/null || true
    wait "${EXPORTER_PID}" 2>/dev/null || true
    EXPORTER_PID=""
fi
cleanup_veth
sudo -n rm -rf "${SIDECAR_DIR}" 2>/dev/null || true

setup_veth

echo "=== apply ${AND6_FIXTURE} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${AND6_FIXTURE}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
cat "${stderr_file}" >&2 || true
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[ri.apply]: apply exit ${rc} for 6-axis fixture" >&2
    exit 1
fi

# Distinct port from scenario-1 to dodge TIME_WAIT on the just-killed listener.
PORT2=$(( 9417 + (($$ + 137) % 1000) ))
echo "=== starting xdpmf-exporter on 127.0.0.1:${PORT2} (rule_info scenario)"
sudo -n "${EXPORTER_BIN}" \
    --port "${PORT2}" \
    --bind 127.0.0.1 \
    --bpffs-root "${PIN_ROOT}" \
    >"${exp_log}" 2>&1 &
EXPORTER_PID=$!
echo "EXPORTER_PID=${EXPORTER_PID}"

ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT2}/healthz" -o /dev/null 2>/dev/null; then
        ready=1
        echo "exporter ready after ${i} polls"
        break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        echo "FAIL[ri.startup]: exporter died during startup" >&2
        cat "${exp_log}" >&2
        exit 1
    fi
    sleep 0.1
done
if [[ "${ready}" != "1" ]]; then
    echo "FAIL[ri.ready]: exporter not ready within 5s" >&2
    cat "${exp_log}" >&2
    exit 1
fi

echo "=== curl /metrics (rule_info scenario)"
set +e
http_code3=$(curl -s -o "${metrics_body3}" -w '%{http_code}' \
    -m 5 "http://127.0.0.1:${PORT2}/metrics")
curl3_rc=$?
set -e
echo "curl rc=${curl3_rc} http_code=${http_code3}"
echo "--- response body (rule_info scenario) ---"
cat "${metrics_body3}"
echo "--- end ---"

if [[ "${curl3_rc}" -ne 0 ]] || [[ "${http_code3}" != "200" ]]; then
    echo "FAIL[ri.http]: curl rc=${curl3_rc} http=${http_code3} (expected 0 + 200)" >&2
    fail=1
fi

# Helper: extract a single axis value from the rule_info line for a rule_id.
#   axis_of <rule_id> <axis_key>  →  prints the captured value (may be empty).
axis_of() {
    local rid="$1" key="$2"
    grep -E "^xdpfilter_rule_info\{iface=\"${IFACE_A}\",rule_id=\"${rid}\"," "${metrics_body3}" 2>/dev/null \
        | head -n1 \
        | sed -nE "s/.*[,{]${key}=\"([^\"]*)\".*/\1/p"
}

# (a) EXACTLY ONE HELP + ONE TYPE (gauge) for the rule_info family.
ri_help=$(grep -cE '^# HELP xdpfilter_rule_info ' "${metrics_body3}" 2>/dev/null || true)
ri_help=${ri_help:-0}
ri_type=$(grep -cE '^# TYPE xdpfilter_rule_info gauge$' "${metrics_body3}" 2>/dev/null || true)
ri_type=${ri_type:-0}
echo "rule_info HELP=${ri_help} TYPE=${ri_type}"
if [[ "${ri_help}" != "1" ]]; then
    echo "FAIL[ri.a.help]: expected exactly 1 '# HELP xdpfilter_rule_info', got ${ri_help}" >&2
    fail=1
fi
if [[ "${ri_type}" != "1" ]]; then
    echo "FAIL[ri.a.type]: expected exactly 1 '# TYPE xdpfilter_rule_info gauge', got ${ri_type}" >&2
    fail=1
fi

# (b)+(f) ≥1 sample matches the stable 8-key ERE in fixed order, value EXACTLY 1.
# §5.47 D-mvp-4.7-Q3: `mac` is the 8th key, appended LAST after `vlan`.
ri_ere='^xdpfilter_rule_info\{iface="[^"]+",rule_id="[0-9]+",dst_cidr="[^"]*",src_cidr="[^"]*",protocol="[^"]*",dst_port="[^"]*",vlan="[^"]*",mac="[^"]*"\} 1$'
ri_stable=$(grep -cE "${ri_ere}" "${metrics_body3}" 2>/dev/null || true)
ri_stable=${ri_stable:-0}
# Total rule_info SAMPLE lines (exclude HELP/TYPE comment lines).
ri_total=$(grep -cE '^xdpfilter_rule_info\{' "${metrics_body3}" 2>/dev/null || true)
ri_total=${ri_total:-0}
echo "rule_info sample lines: stable-key-matching=${ri_stable} total=${ri_total}"
if (( ri_stable < 1 )); then
    echo "FAIL[ri.b]: no rule_info sample line matches the stable 8-key ERE:" >&2
    echo "            ${ri_ere}" >&2
    fail=1
fi
# (f) EVERY sample line must carry the same 8 keys in the same order + value 1.
if [[ "${ri_stable}" != "${ri_total}" ]]; then
    echo "FAIL[ri.f]: key set unstable — ${ri_total} rule_info lines but only ${ri_stable} match the 8-key ERE" >&2
    fail=1
fi
# We applied 7 rules (ids 0..6); expect a series per configured rule.
if (( ri_total < 7 )); then
    echo "FAIL[ri.count]: expected ≥7 rule_info series (ids 0..6), got ${ri_total}" >&2
    fail=1
fi

# (c) POSITIVE per-axis — id0 is the FULL 5-axis rule; all five axis labels
#     carry the fixture values verbatim (exporter passes the sidecar string
#     through; no normalization per §7 OOS fence).
declare -A ID0_EXPECT=(
    [dst_cidr]="10.1.0.0/16"
    [src_cidr]="192.168.5.0/24"
    [protocol]="tcp"
    [dst_port]="1000-2000"
    [vlan]="100"
    [mac]="aa:bb:cc:dd:ee:01"
)
for key in dst_cidr src_cidr protocol dst_port vlan mac; do
    got=$(axis_of 0 "${key}")
    exp="${ID0_EXPECT[$key]}"
    echo "  id0 ${key}='${got}' (expect '${exp}')"
    if [[ "${got}" != "${exp}" ]]; then
        echo "FAIL[ri.c.${key}]: id0 ${key}='${got}' (expected '${exp}')" >&2
        fail=1
    fi
done

# (d) SENTINEL — id5 constrains ONLY dst_port=443; the other four axes MUST be
#     the empty sentinel "".
got=$(axis_of 5 dst_port)
echo "  id5 dst_port='${got}' (expect '443')"
if [[ "${got}" != "443" ]]; then
    echo "FAIL[ri.d.port]: id5 dst_port='${got}' (expected '443')" >&2
    fail=1
fi
# id5 is port-only → every other axis, INCLUDING the new mac axis, is the
# empty sentinel "" (PI-mvp-4.7-RULEINFO-MAC: mac="" for a MAC-wildcard rule).
for key in dst_cidr src_cidr protocol vlan mac; do
    got=$(axis_of 5 "${key}")
    echo "  id5 ${key}='${got}' (expect empty sentinel)"
    if [[ -n "${got}" ]]; then
        echo "FAIL[ri.d.${key}]: id5 ${key}='${got}' (expected empty sentinel \"\")" >&2
        fail=1
    fi
done

# (e) NEGATION — id2 constrains ONLY vlan=300; the other four axes MUST be ""
#     and NEVER a bogus/garbage value. (If impl fabricates a value for an
#     unconstrained axis, this trips — the negation control for rule_info.)
got=$(axis_of 2 vlan)
echo "  id2 vlan='${got}' (expect '300')"
if [[ "${got}" != "300" ]]; then
    echo "FAIL[ri.e.vlan]: id2 vlan='${got}' (expected '300')" >&2
    fail=1
fi
# id2 is vlan-only → every other axis incl. mac MUST be "" and NEVER a bogus
# value (the negation control for the new mac axis too).
for key in dst_cidr src_cidr protocol dst_port mac; do
    got=$(axis_of 2 "${key}")
    echo "  id2 ${key}='${got}' (expect empty — never bogus)"
    if [[ -n "${got}" ]]; then
        echo "FAIL[ri.e.${key}]: id2 unconstrained ${key}='${got}' — bogus value (expected \"\")" >&2
        fail=1
    fi
done

# (e.3) POSITIVE mac on a mac-only rule — id6 constrains ONLY mac; the mac label
#       carries the fixture value verbatim and the other five axes are "".
got=$(axis_of 6 mac)
echo "  id6 mac='${got}' (expect 'aa:bb:cc:dd:ee:06')"
if [[ "${got}" != "aa:bb:cc:dd:ee:06" ]]; then
    echo "FAIL[ri.e.macpos]: id6 mac='${got}' (expected 'aa:bb:cc:dd:ee:06')" >&2
    fail=1
fi
for key in dst_cidr src_cidr protocol dst_port vlan; do
    got=$(axis_of 6 "${key}")
    if [[ -n "${got}" ]]; then
        echo "FAIL[ri.e.mac.${key}]: id6 (mac-only) ${key}='${got}' (expected empty sentinel)" >&2
        fail=1
    fi
done

# (e.2) NEGATION — a NON-configured rule_id (99 is absent from the fixture)
#       MUST emit NO rule_info series (D-mvp-4.6-METRIC-SOURCE: no fabrication).
bogus=$(grep -cE "^xdpfilter_rule_info\{iface=\"${IFACE_A}\",rule_id=\"99\"," "${metrics_body3}" 2>/dev/null || true)
bogus=${bogus:-0}
echo "  rule_id=99 (non-configured) rule_info series count=${bogus} (expect 0)"
if (( bogus != 0 )); then
    echo "FAIL[ri.e.orphan]: rule_id=99 not in config but emitted ${bogus} rule_info series" >&2
    fail=1
fi

# (g) COUNTER-CONTRACT — the rule_info family is appended LAST; the existing
#     counter families must still be present and precede it. Re-confirm here on
#     the second scrape that both counter families are intact (block order).
if ! grep -qE '^# HELP xdpfilter_packets_total ' "${metrics_body3}"; then
    echo "FAIL[ri.g.pkts]: xdpfilter_packets_total family missing (COUNTER-CONTRACT)" >&2
    fail=1
fi
if ! grep -qE '^# HELP xdpfilter_rule_match_total ' "${metrics_body3}"; then
    echo "FAIL[ri.g.rmt]: xdpfilter_rule_match_total family missing (COUNTER-CONTRACT)" >&2
    fail=1
fi
# Block order: the first rule_info line must come AFTER the last
# rule_match_total line (rule_info appended LAST per D-mvp-4.6-BLOCK-ORDER).
ri_first=$(grep -nE '^(# (HELP|TYPE) )?xdpfilter_rule_info' "${metrics_body3}" | head -n1 | cut -d: -f1)
rmt_last=$(grep -nE '^xdpfilter_rule_match_total\{' "${metrics_body3}" | tail -n1 | cut -d: -f1)
echo "  block order: first rule_info line=${ri_first:-none}, last rule_match_total line=${rmt_last:-none}"
if [[ -n "${ri_first}" && -n "${rmt_last}" ]] && (( ri_first < rmt_last )); then
    echo "FAIL[ri.g.order]: rule_info block (line ${ri_first}) precedes rule_match_total (line ${rmt_last}) — must be appended LAST" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_EXPORTER_RULE_LABELS"
exit "${fail}"
