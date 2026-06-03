#!/bin/bash
# T_SIDECAR_V6_ETH_KINDS — design §6.76 (MVP-4.16 / §5.56 — C3 fast-follow).
#
# Closes the C3 sidecar match-kinds gap: the IPv6-CIDR axes (dst_cidr6/src_cidr6,
# mvp-4.13/S4) and the EtherType axis (ethertype, mvp-4.14/S5) were written to
# the BPF maps but OMITTED from BOTH observability surfaces —
#   (1) the status JSON `rule_index.json` (producer src/lib/sidecar.cpp), and
#   (2) the Prometheus info-metric xdpfilter_rule_info (consumer
#       src/exporter/{sidecar_reader,prom_format}.cpp).
# A v6/ethertype rule therefore surfaced as all-empty (indistinguishable from a
# match-all rule) on both. This test asserts the 3 axes are now present + carry
# their verbatim values on BOTH surfaces (PI-mvp-4.16-SIDECAR + -LABEL-CONTRACT).
#
# Trigger:
#   1. setup_veth.
#   2. PART V6: apply config_valid_andv6.yaml; jq-assert the sidecar emits
#      dst_cidr6/src_cidr6; scrape the exporter; assert rule_info carries the
#      same v6 labels.
#   3. PART ETH: apply config_valid_andeth.yaml (overwrites the sidecar);
#      jq-assert the sidecar emits ethertype (named arp/ipv4 + hex 0x88b5);
#      re-scrape; assert rule_info carries the ethertype label.
#
# Observable outcome (ALL must hold):
#   V6.json (a): .match.dst_cidr6 == "2001:db8:1::/48" for rule_id 0;
#                .match.src_cidr6 == "2001:db8:5::/48" for rule_id 0;
#                .match.dst_cidr6 == "2001:db8:2::/48" for rule_id 1.
#   V6.metric(b): xdpfilter_rule_info for id0 carries dst_cidr6/src_cidr6 labels
#                with the same values; a v4-only rule (id2) has v6 labels "".
#   ETH.json (c): .match.ethertype == "0x88b5" (id0/id1), "arp" (id2),
#                "ipv4" (id3) — the producer mirrors the config grammar spelling.
#   ETH.metric(d): xdpfilter_rule_info for id2 carries ethertype="arp"; id3
#                carries ethertype="ipv4"; a non-ethertype rule (id4) has "".
#
# Sanity-floor smoke: PART V6 apply exits 0 + sidecar materializes.
# Negation control: V6.metric(b) id2 (a v4-only rule) MUST show v6 labels "" —
#   if the impl fabricated v6 values for a v4 rule, this trips. ETH.metric(d)
#   id4 (proto-only) MUST show ethertype="" likewise.
#
# SKIP conditions: jq or curl absent → exit 77.
#
# Maps to: §5.56, PI-mvp-4.16-SIDECAR, PI-mvp-4.16-LABEL-CONTRACT,
#          PI-mvp-4.16-EXPORTER-AXIS-AWARE. Fixtures: config_valid_andv6.yaml
#          (S4), config_valid_andeth.yaml (S5).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required for sidecar shape validation)" >&2
    exit 77
fi
if ! command -v curl >/dev/null 2>&1; then
    echo "SKIP: curl not in PATH (required for exporter scrape)" >&2
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
EXPORTER_BIN=$(find_exporter) || { echo "FAIL: xdpmf-exporter not found" >&2; exit 1; }
V6_FIXTURE="${TEST_DIR}/fixtures/config_valid_andv6.yaml"
ETH_FIXTURE="${TEST_DIR}/fixtures/config_valid_andeth.yaml"
[[ -f "${V6_FIXTURE}" ]]  || { echo "FAIL: missing fixture ${V6_FIXTURE}" >&2; exit 1; }
[[ -f "${ETH_FIXTURE}" ]] || { echo "FAIL: missing fixture ${ETH_FIXTURE}" >&2; exit 1; }

PORT=$(( 9417 + ($$ % 1000) ))
echo "EXPORTER_PORT=${PORT}"

SIDECAR_ROOT="/run/xdpfilter"
SIDECAR_DIR="${SIDECAR_ROOT}/${IFACE_A}"
SIDECAR_PATH="${SIDECAR_DIR}/rule_index.json"

sidecar_local=$(mktemp /tmp/xdpmf-v6eth-body.XXXXXX)
metrics_body=$(mktemp /tmp/xdpmf-v6eth-metrics.XXXXXX)
exp_log=$(mktemp /tmp/xdpmf-v6eth-explog.XXXXXX)
stderr_file=$(mktemp /tmp/xdpmf-v6eth-stderr.XXXXXX)
EXPORTER_PID=""

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
    rm -f "${sidecar_local}" "${metrics_body}" "${exp_log}" "${stderr_file}"
    set -e
}
trap cleanup_test EXIT

read_sidecar() { sudo -n cat "${SIDECAR_PATH}" 2>/dev/null; }

# axis_of <rule_id> <axis_key>  →  prints the rule_info label value (may be empty).
axis_of() {
    local rid="$1" key="$2"
    grep -E "^xdpfilter_rule_info\{iface=\"${IFACE_A}\",rule_id=\"${rid}\"," "${metrics_body}" 2>/dev/null \
        | head -n1 \
        | sed -nE "s/.*[,{]${key}=\"([^\"]*)\".*/\1/p"
}

fail=0

apply_fixture() {
    local fx="$1"
    : >"${stderr_file}"
    set +e
    ${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${fx}" 2>"${stderr_file}"
    local rc=$?
    set -e
    cat "${stderr_file}" >&2 || true
    return "${rc}"
}

scrape_metrics() {
    : >"${metrics_body}"
    local code
    set +e
    code=$(curl -s -o "${metrics_body}" -w '%{http_code}' -m 5 \
        "http://127.0.0.1:${PORT}/metrics")
    set -e
    echo "${code}"
}

setup_veth

# ════════════════════════ PART V6 (S4 axes) ══════════════════════════════
echo "═══ PART V6: apply ${V6_FIXTURE}"
if ! apply_fixture "${V6_FIXTURE}"; then
    echo "FAIL: v6 apply exited non-zero" >&2
    exit 1
fi
if ! sudo -n test -e "${SIDECAR_PATH}"; then
    echo "FAIL[smoke]: sidecar missing after v6 apply" >&2
    exit 1
fi
read_sidecar > "${sidecar_local}"
echo "--- v6 sidecar ---"; cat "${sidecar_local}"; echo "--- end ---"

# V6.json (a): the producer emits dst_cidr6/src_cidr6 with verbatim values.
check_json_kind() {
    local rid="$1" key="$2" exp="$3"
    local got
    got=$(jq -r --argjson id "${rid}" \
        ".rules[] | select(.rule_id == \$id) | .match.${key} // \"\"" \
        "${sidecar_local}" 2>/dev/null | head -n1)
    echo "  json id${rid} .match.${key}='${got}' (expect '${exp}')"
    if [[ "${got}" != "${exp}" ]]; then
        echo "FAIL[json.${rid}.${key}]: got '${got}' expected '${exp}'" >&2
        fail=1
    fi
}
check_json_kind 0 dst_cidr6 "2001:db8:1::/48"
check_json_kind 0 src_cidr6 "2001:db8:5::/48"
check_json_kind 1 dst_cidr6 "2001:db8:2::/48"

# Start the exporter once (re-reads the sidecar on each scrape).
echo "=== starting xdpmf-exporter on 127.0.0.1:${PORT}"
sudo -n "${EXPORTER_BIN}" --port "${PORT}" --bind 127.0.0.1 \
    --bpffs-root "${PIN_ROOT}" >"${exp_log}" 2>&1 &
EXPORTER_PID=$!
ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT}/healthz" -o /dev/null 2>/dev/null; then
        ready=1; break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        echo "FAIL: exporter died during startup" >&2; cat "${exp_log}" >&2; exit 1
    fi
    sleep 0.1
done
[[ "${ready}" == "1" ]] || { echo "FAIL: exporter not ready" >&2; cat "${exp_log}" >&2; exit 1; }

code=$(scrape_metrics)
echo "v6 scrape http=${code}"
[[ "${code}" == "200" ]] || { echo "FAIL[v6.metric.http]: ${code}" >&2; fail=1; }
grep -E '^xdpfilter_rule_info\{' "${metrics_body}" >&2 || true

# V6.metric (b): id0 carries the v6 labels verbatim.
check_label() {
    local rid="$1" key="$2" exp="$3"
    local got; got=$(axis_of "${rid}" "${key}")
    echo "  metric id${rid} ${key}='${got}' (expect '${exp}')"
    if [[ "${got}" != "${exp}" ]]; then
        echo "FAIL[metric.${rid}.${key}]: got '${got}' expected '${exp}'" >&2
        fail=1
    fi
}
check_label 0 dst_cidr6 "2001:db8:1::/48"
check_label 0 src_cidr6 "2001:db8:5::/48"
# NEGATION: id2 is a v4-only rule (dst_cidr 10.1.0.0/16) → v6 labels MUST be "".
check_label 2 dst_cidr6 ""
check_label 2 src_cidr6 ""

# ════════════════════════ PART ETH (S5 axis) ═════════════════════════════
echo "═══ PART ETH: apply ${ETH_FIXTURE}"
if ! apply_fixture "${ETH_FIXTURE}"; then
    echo "FAIL: eth apply exited non-zero" >&2
    exit 1
fi
read_sidecar > "${sidecar_local}"
echo "--- eth sidecar ---"; cat "${sidecar_local}"; echo "--- end ---"

# ETH.json (c): the producer mirrors the config grammar — hex 0x88b5 stays hex,
# the named ethertypes (arp/ipv4) round-trip to their names.
check_json_kind 0 ethertype "0x88b5"
check_json_kind 1 ethertype "0x88b5"
check_json_kind 2 ethertype "arp"
check_json_kind 3 ethertype "ipv4"

# Re-scrape (same exporter, fresh sidecar).
sleep 0.2
code=$(scrape_metrics)
echo "eth scrape http=${code}"
[[ "${code}" == "200" ]] || { echo "FAIL[eth.metric.http]: ${code}" >&2; fail=1; }
grep -E '^xdpfilter_rule_info\{' "${metrics_body}" >&2 || true

# ETH.metric (d): id2 → ethertype="arp", id3 → "ipv4"; id4 (proto-only) → "".
check_label 2 ethertype "arp"
check_label 3 ethertype "ipv4"
# NEGATION: id4 constrains only protocol=udp → ethertype MUST be "".
check_label 4 ethertype ""

[[ "${fail}" == 0 ]] && echo "PASS: T_SIDECAR_V6_ETH_KINDS"
exit "${fail}"
