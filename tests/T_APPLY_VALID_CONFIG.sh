#!/bin/bash
# T_APPLY_VALID_CONFIG — design §6.21 (MVP-3.1 / §5.26).
#
# Minimal valid YAML config is parsed, validated, and applied:
#   - apply exit 0
#   - stderr contains 'xdpmacfilter: trust_model=strict' (audit log, §5.26)
#   - stderr does NOT contain 'config error:' or 'unsupported'
#   - ${PIN_DIR}/link exists (P0a per HG2)
#   - ${PIN_DIR}/active_idx exists; value ∈ {0,1}
#   - active inner allowlist (allowlist_a OR allowlist_b) contains the
#     MACs from the fixture
#   - inject from a MAC in the fixture → STAT_PASS += 1
#   - inject from a MAC NOT in the fixture → STAT_DROP_DENY += 1
#   - sanity sub-case: apply config_valid_blanket_pass.yaml; inject a
#     fresh MAC → STAT_PASS increments (blanket-pass works).
#
# Sanity-floor smoke: the very first apply that exits 0 + populates pins
# is the smoke test (we cannot reach later assertions without it).
# Negation control: the MAC_BAD-drops sub-step IS the negation; if a
# never-in-allowlist MAC was passed instead of dropped, fail aggregator
# reports it.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FIXTURE_DIR="${TEST_DIR}/fixtures"
FIXTURE_VALID="${FIXTURE_DIR}/config_valid.yaml"
FIXTURE_BLANKET="${FIXTURE_DIR}/config_valid_blanket_pass.yaml"

stderr_file=$(mktemp /tmp/xdpmf-applyvalid-stderr.XXXXXX)
trap 'cleanup_veth; rm -f "${stderr_file}"' EXIT

# Sanity: fixtures present.
[[ -f "${FIXTURE_VALID}" ]]   || { echo "FAIL: missing fixture ${FIXTURE_VALID}"   >&2; exit 1; }
[[ -f "${FIXTURE_BLANKET}" ]] || { echo "FAIL: missing fixture ${FIXTURE_BLANKET}" >&2; exit 1; }

# MACs declared in config_valid.yaml.
MAC_IN_FIXTURE="02:00:00:00:00:01"     # also MAC_GOOD
MAC_NOT_IN_FIXTURE="02:00:00:00:00:99" # never appears in any fixture

setup_veth

# ── PRIMARY: apply config_valid.yaml ─────────────────────────────────────
echo "=== apply ${FIXTURE_VALID} on ${IFACE_A}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE_VALID}" 2> "${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
echo "--- stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

fail=0

# (1) rc == 0.
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[1]: expected rc=0 (apply succeeded), got ${rc}" >&2
    fail=1
fi

# (2) stderr contains trust_model=strict (mandatory audit log).
if ! grep -qE -- 'xdpmacfilter: trust_model=strict' "${stderr_file}"; then
    echo "FAIL[2]: stderr missing 'xdpmacfilter: trust_model=strict' audit line" >&2
    fail=1
fi

# (3) stderr does NOT contain 'config error:' or 'unsupported'.
if grep -q -F -- 'config error:' "${stderr_file}"; then
    echo "FAIL[3a]: stderr unexpectedly contains 'config error:'" >&2
    fail=1
fi
if grep -q -F -- 'unsupported' "${stderr_file}"; then
    echo "FAIL[3b]: stderr unexpectedly contains 'unsupported'" >&2
    fail=1
fi

# (4) link pin exists.
if ! sudo -n test -e "${PIN_DIR}/link"; then
    echo "FAIL[4]: expected pin ${PIN_DIR}/link missing" >&2
    fail=1
fi

# (5) active_idx pin exists; value ∈ {0,1}.
#
# Modern bpftool (libbpf 1.x) emits JSON-pretty-printed output even
# without --json. With --json, .[0].value is a 4-byte LE hex array
# AND .[0].formatted.value is the decoded integer. Without --json,
# .[0].value is already the integer.  Use --json + .formatted.value
# (always integer); fall back to byte-array decode for older bpftool.
read_active_idx() {
    local raw v hex
    raw=$(sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" --json 2>/dev/null)
    [[ -z "${raw}" ]] && return
    # Preferred: .[0].formatted.value (modern bpftool, guaranteed integer).
    v=$(printf '%s' "${raw}" | jq -r '.[0].formatted.value // empty' 2>/dev/null)
    if [[ -n "${v}" && "${v}" != "null" ]]; then echo "${v}"; return; fi
    # Older bpftool: .[0].value is a LE byte array; byte 0 has the LSB.
    hex=$(printf '%s' "${raw}" | jq -r '.[0].value[0] // empty' 2>/dev/null | sed 's/^0x//')
    if [[ -n "${hex}" && "${hex}" != "null" ]]; then
        printf '%d\n' "0x${hex}"
    fi
}

if ! sudo -n test -e "${PIN_DIR}/active_idx"; then
    echo "FAIL[5a]: expected pin ${PIN_DIR}/active_idx missing" >&2
    fail=1
else
    active=$(read_active_idx)
    echo "active_idx = '${active}'"
    if [[ "${active}" != "0" && "${active}" != "1" ]]; then
        echo "FAIL[5b]: active_idx is not 0 or 1, got '${active}'" >&2
        echo "  raw bpftool output:" >&2
        sudo -n bpftool map dump pinned "${PIN_DIR}/active_idx" >&2 || true
        fail=1
    fi
fi

# (6) Active inner allowlist contains the MAC from the fixture.
#     bpftool emits the key as a BTF-formatted struct ({"octets": [...]})
#     with decimal byte values when called WITHOUT --json on modern
#     libbpf builds. Use jq to query for the target MAC's octet array.
#     Helper: convert "AA:BB:CC:DD:EE:FF" → JSON "[170,187,...]".
mac_to_oct_json() {
    # Bash-native hex → decimal CSV (mawk has no strtonum()).
    local mac="$1" oct_arr="[" first=1 hex
    local IFS=':'
    for hex in ${mac}; do
        if [[ ${first} -eq 1 ]]; then first=0; else oct_arr+=","; fi
        oct_arr+=$(printf '%d' "0x${hex}")
    done
    oct_arr+="]"
    printf '%s' "${oct_arr}"
}
mac_in_inner_pin() {
    local pin="$1" mac="$2" oct_arr
    oct_arr=$(mac_to_oct_json "${mac}")
    sudo -n bpftool map dump pinned "${pin}" 2>/dev/null \
        | jq -e --argjson tgt "${oct_arr}" '
            [.[] | (.key.octets // .formatted.key.octets // null)]
            | map(select(. != null))
            | any(. == $tgt)
        ' >/dev/null 2>&1
}

if [[ "${active:-}" == "0" ]]; then
    inner_pin="${PIN_DIR}/allowlist_a"
elif [[ "${active:-}" == "1" ]]; then
    inner_pin="${PIN_DIR}/allowlist_b"
else
    inner_pin=""
fi
if [[ -n "${inner_pin}" ]]; then
    if ! sudo -n test -e "${inner_pin}"; then
        echo "FAIL[6a]: active inner pin ${inner_pin} missing" >&2
        fail=1
    else
        if ! mac_in_inner_pin "${inner_pin}" "${MAC_IN_FIXTURE}"; then
            echo "FAIL[6b]: active inner pin ${inner_pin} missing fixture MAC ${MAC_IN_FIXTURE}" >&2
            sudo -n bpftool map dump pinned "${inner_pin}" >&2 || true
            fail=1
        fi
    fi
fi

# (7) Inject from MAC in the fixture → STAT_PASS += 1.
read -r p0 d0 m0 < <(read_stats)
echo "stats baseline (after apply): PASS=${p0} DROP_DENY=${d0} DROP_MALFORMED=${m0}"
inject_eth "${IFACE_B}" "${MAC_IN_FIXTURE}" "${MAC_DST}"
wait_for_stats_sum "${IFACE_A}" $(( p0 + d0 + m0 + 1 )) || true
read -r p1 d1 m1 < <(read_stats)
echo "stats after MAC_IN_FIXTURE: PASS=${p1} DROP_DENY=${d1} DROP_MALFORMED=${m1}"
if (( p1 - p0 != 1 )); then
    echo "FAIL[7a]: STAT_PASS delta != 1 (got $(( p1 - p0 )))" >&2
    fail=1
fi
if (( d1 - d0 != 0 )); then
    echo "FAIL[7b]: STAT_DROP_DENY moved on MAC-in-fixture (got delta $(( d1 - d0 )))" >&2
    fail=1
fi

# (8) Inject from MAC NOT in fixture → STAT_DROP_DENY += 1 (negation control).
inject_eth "${IFACE_B}" "${MAC_NOT_IN_FIXTURE}" "${MAC_DST}"
wait_for_stats_sum "${IFACE_A}" $(( p1 + d1 + m1 + 1 )) || true
read -r p2 d2 m2 < <(read_stats)
echo "stats after MAC_NOT_IN_FIXTURE: PASS=${p2} DROP_DENY=${d2} DROP_MALFORMED=${m2}"
if (( d2 - d1 != 1 )); then
    echo "FAIL[8a]: STAT_DROP_DENY delta != 1 (got $(( d2 - d1 )))" >&2
    fail=1
fi
if (( p2 - p1 != 0 )); then
    echo "FAIL[8b]: STAT_PASS moved on MAC-not-in-fixture (got delta $(( p2 - p1 )))" >&2
    fail=1
fi

# ── SANITY SUB-CASE: blanket-pass mode ───────────────────────────────────
echo
echo "=== sanity sub-case: apply ${FIXTURE_BLANKET} (blanket pass)"
: >"${stderr_file}"
set +e
${NSEXEC} "${LOADER_BIN}" apply --iface "${IFACE_A}" -f "${FIXTURE_BLANKET}" 2> "${stderr_file}"
rc_b=$?
set -e
echo "rc_b=${rc_b}"
echo "--- stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

if [[ "${rc_b}" -ne 0 ]]; then
    echo "FAIL[B1]: blanket-pass apply: expected rc=0, got ${rc_b}" >&2
    fail=1
fi

# Inject a fresh random MAC (definitely not in any list — blanket-pass
# should accept it).
MAC_RANDOM="02:00:00:00:de:ad"
read -r pb0 db0 mb0 < <(read_stats)
inject_eth "${IFACE_B}" "${MAC_RANDOM}" "${MAC_DST}"
wait_for_stats_sum "${IFACE_A}" $(( pb0 + db0 + mb0 + 1 )) || true
read -r pb1 db1 mb1 < <(read_stats)
echo "stats after blanket-pass + MAC_RANDOM: PASS=${pb1} DROP_DENY=${db1} DROP_MALFORMED=${mb1}"
if (( pb1 - pb0 != 1 )); then
    echo "FAIL[B2]: blanket-pass: STAT_PASS delta != 1 (got $(( pb1 - pb0 )))" >&2
    fail=1
fi
if (( db1 - db0 != 0 )); then
    echo "FAIL[B3]: blanket-pass: STAT_DROP_DENY moved (got delta $(( db1 - db0 )))" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_APPLY_VALID_CONFIG"
exit "${fail}"
