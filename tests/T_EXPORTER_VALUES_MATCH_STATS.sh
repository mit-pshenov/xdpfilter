#!/bin/bash
# T_EXPORTER_VALUES_MATCH_STATS — design §6.38 (MVP-3.4 / §5.29).
#
# Exporter PERCPU sum matches bpftool sum, byte-for-byte. The load-bearing
# correctness test for `prom_format::emit_metrics` + PI-31 (read-only).
#
# Trigger:
#   1. setup_veth + apply config_valid_mac_or_cidr.yaml (mixed mac+cidr).
#   2. Inject known counts of frames per verdict:
#        N_pass    = inject 2× eth frames with src=AA:BB:CC:DD:EE:FF (MAC pass)
#        N_drop    = inject 3× eth frames with src=99:99:99:99:99:99 (no rule match → drop_deny)
#        N_malf    = inject 1× runt frame                            (drop_malformed)
#        N_pcidr   = inject 2× ipv4 frames src=10.5.6.7              (src_cidr 10.0.0.0/8 → pass_cidr)
#   3. wait_for_stats_sum_with_cidr — quiesce.
#   4. Start exporter in background on per-PID-derived port.
#   5. curl /metrics → /tmp/metrics.out
#   6. Compare per-verdict integer to read_stats.py output (strict ==).
#
# Observable outcome: for each of {pass, drop_deny, drop_malformed,
# pass_cidr}, exporter's number == read_stats.py's number.
#
# Sanity-floor smoke: step 5 (curl 200 OK + parseable lines) is the smoke.
# Negation control: implicit — strict equality. If the exporter were
# (a) mutating values, (b) reading wrong CPU slot, (c) reading wrong key,
# or (d) returning cached/stale values, equality breaks.
#
# SKIP: `curl` or `jq` not in PATH → exit 77.
#
# Cleanup: kill exporter; cleanup_veth.
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
    echo "SKIP: curl not in PATH (required by §6.38)" >&2
    exit 77
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq not in PATH (required by §6.38)" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
EXPORTER_BIN=$(find_exporter) || {
    echo "FAIL: xdpmf-exporter binary not found under ${BUILD_DIR}" >&2
    exit 1
}
# §5.43 MVP-4.3: config_valid_mac_or_cidr.yaml carries a `mac` key which v2
# rejects (MAC deferred). Repoint to the v2 src_cidr fixture (10.0.0.0/8).
# The exporter-vs-stats assertions below are dynamic (compare exporter to a
# live read_stats snapshot), so they hold regardless of the per-verdict mix.
FIXTURE="${TEST_DIR}/fixtures/config_valid_cidr.yaml"
[[ -f "${FIXTURE}" ]] || { echo "FAIL: missing fixture ${FIXTURE}" >&2; exit 1; }

PORT=$(( 9417 + ($$ % 1000) ))
echo "EXPORTER_PORT=${PORT}"

MAC_RULE="AA:BB:CC:DD:EE:FF"   # MAC in fixture → PASS
MAC_NORULE="99:99:99:99:99:99" # not in fixture → DROP_DENY
IP_IN="10.5.6.7"               # in 10.0.0.0/8 → PASS_CIDR
N_PASS=2
N_DROP=3
N_MALF=1
N_PCIDR=2

metrics_body=$(mktemp /tmp/xdpmf-expval-metrics.XXXXXX)
exp_log=$(mktemp /tmp/xdpmf-expval-explog.XXXXXX)
stderr_file=$(mktemp /tmp/xdpmf-expval-stderr.XXXXXX)
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
    rm -f "${metrics_body}" "${exp_log}" "${stderr_file}"
    set -e
}
trap cleanup_test EXIT

setup_veth

echo "=== apply ${FIXTURE} on ${IFACE_A}"
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE}" 2>"${stderr_file}"

fail=0
if ! sudo -n test -e "${PIN_DIR}/stats"; then
    echo "FAIL: stats pin missing after apply" >&2
    exit 1
fi

# ── inject known counts ───────────────────────────────────────────────────
echo "=== inject ${N_PASS}× pass (mac=${MAC_RULE})"
for _ in $(seq 1 "${N_PASS}"); do
    inject_eth "${IFACE_B}" "${MAC_RULE}" "${MAC_DST}"
done

echo "=== inject ${N_DROP}× drop_deny (mac=${MAC_NORULE})"
for _ in $(seq 1 "${N_DROP}"); do
    inject_eth "${IFACE_B}" "${MAC_NORULE}" "${MAC_DST}"
done

echo "=== inject ${N_MALF}× drop_malformed (runt)"
for _ in $(seq 1 "${N_MALF}"); do
    inject_runt "${IFACE_B}"
done

echo "=== inject ${N_PCIDR}× pass_cidr (src=${MAC_NORULE} ip=${IP_IN})"
for _ in $(seq 1 "${N_PCIDR}"); do
    ${NSEXEC} python3 "${TEST_DIR}/inject/inject_ipv4.py" \
        "${IFACE_B}" "${MAC_NORULE}" "${MAC_DST}" "${IP_IN}"
done

total_expected=$(( N_PASS + N_DROP + N_MALF + N_PCIDR ))
wait_for_stats_sum_with_cidr "${IFACE_A}" "${total_expected}" || {
    echo "WARN: stats sum did not reach ${total_expected} within timeout" >&2
    echo "      proceeding — we compare exporter vs read_stats.py snapshot anyway." >&2
}

# Bpftool / read_stats.py snapshot — taken BEFORE the exporter scrape so
# both see the same kernel-side state. (Even if BPF still bumps counters
# in flight, both should converge on the same view because the exporter
# uses the same PERCPU lookup that read_stats.py uses.)
echo "=== bpftool/read_stats.py snapshot"
read -r expected_pass expected_drop expected_malf expected_pcidr < <(read_stats_with_cidr)
echo "expected: pass=${expected_pass} drop=${expected_drop} malf=${expected_malf} pcidr=${expected_pcidr}"

# ── start exporter ──────────────────────────────────────────────────────
echo "=== starting xdpmf-exporter on 127.0.0.1:${PORT}"
sudo -n "${EXPORTER_BIN}" \
    --port "${PORT}" \
    --bind 127.0.0.1 \
    --bpffs-root "${PIN_ROOT}" \
    >"${exp_log}" 2>&1 &
EXPORTER_PID=$!
ready=0
for i in $(seq 1 50); do
    if curl -sf -m 1 "http://127.0.0.1:${PORT}/healthz" -o /dev/null 2>/dev/null; then
        ready=1; echo "exporter ready after ${i} polls"; break
    fi
    if ! kill -0 "${EXPORTER_PID}" 2>/dev/null; then
        echo "FAIL: exporter PID died during startup" >&2
        cat "${exp_log}" >&2
        exit 1
    fi
    sleep 0.1
done
[[ "${ready}" == "1" ]] || { echo "FAIL: exporter not ready within 5s" >&2; cat "${exp_log}" >&2; exit 1; }

echo "=== curl /metrics > ${metrics_body}"
curl -sf -m 5 "http://127.0.0.1:${PORT}/metrics" -o "${metrics_body}"
echo "--- /metrics body ---"
cat "${metrics_body}"
echo "--- end ---"

# ── parse per-verdict numbers from the exporter output ──────────────────
# Pattern: xdpfilter_packets_total{iface="<X>",verdict="<v>"} <N>
exporter_val() {
    local verdict="$1"
    grep -E "^xdpfilter_packets_total\{iface=\"${IFACE_A}\",verdict=\"${verdict}\"\} [0-9]+\$" "${metrics_body}" \
        | awk '{print $NF}' | head -n1
}

ex_pass=$(exporter_val pass)
ex_drop=$(exporter_val drop_deny)
ex_malf=$(exporter_val drop_malformed)
ex_pcidr=$(exporter_val pass_cidr)
echo "exporter:  pass='${ex_pass}' drop='${ex_drop}' malf='${ex_malf}' pcidr='${ex_pcidr}'"
echo "read_stats: pass=${expected_pass} drop=${expected_drop} malf=${expected_malf} pcidr=${expected_pcidr}"

# Empty exporter value (line missing for our iface) → FAIL with diagnostic.
for var_name in ex_pass ex_drop ex_malf ex_pcidr; do
    eval "v=\${${var_name}}"
    if [[ -z "${v}" ]]; then
        echo "FAIL: exporter output missing line for ${var_name} on iface=${IFACE_A}" >&2
        fail=1
    fi
done

if [[ "${fail}" == 0 ]]; then
    [[ "${ex_pass}"  == "${expected_pass}"  ]] || { echo "FAIL: pass mismatch (exporter=${ex_pass} read_stats=${expected_pass})"   >&2; fail=1; }
    [[ "${ex_drop}"  == "${expected_drop}"  ]] || { echo "FAIL: drop_deny mismatch (exporter=${ex_drop} read_stats=${expected_drop})" >&2; fail=1; }
    [[ "${ex_malf}"  == "${expected_malf}"  ]] || { echo "FAIL: drop_malformed mismatch (exporter=${ex_malf} read_stats=${expected_malf})" >&2; fail=1; }
    [[ "${ex_pcidr}" == "${expected_pcidr}" ]] || { echo "FAIL: pass_cidr mismatch (exporter=${ex_pcidr} read_stats=${expected_pcidr})" >&2; fail=1; }
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_EXPORTER_VALUES_MATCH_STATS"
exit "${fail}"
