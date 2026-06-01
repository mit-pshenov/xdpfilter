#!/bin/bash
# T_CONFIG_INT_OVERFLOW_REJECT — design §6.78 (MVP-4.22 / §5.62, R-3).
#
# §5.62 R-3 adds a pre-multiplication overflow guard to the base-10 integer
# accumulators (parse_u32_or_throw + parse_bounded_uint) so an oversized digit
# string is rejected at the multiply with ConfigError (exit 9). R-3 is
# defense-in-depth / local-explicitness (the code was already wrap-safe via a
# uint64 accumulator + per-digit post-check) — so the LOAD-BEARING contract is:
#   the guard MUST NOT reject the exact in-range MAXIMUM (no behaviour change on
#   in-range inputs).  The parity control below pins exactly that.
#
# Trigger (oversized → exit 9): `apply -f` configs with oversized digit strings
# in each integer grammar — rule `id` (30-digit, overflows u32 via
# parse_u32_or_throw) + `protocol` / `dst_port` / `vlan` (99999, over each
# parse_bounded_uint bound: 255 / 65535 / 4095).
# Observable: exit 9 (ConfigError) with the 'config error:' prefix + a
# field-naming diagnostic.
#
# Parity / negation control (LOAD-BEARING): the EXACT in-range maxima still parse
# (NOT rejected at the integer-parse layer) — protocol 255, dst_port 65535,
# vlan 4095, and the max usable rule id. This proves R-3 did not over-reject the
# boundary.
#
# Invocation discipline (root-free, lock-free — §5.62 FileList: §6.78 needs NO
# RESOURCE_LOCK, no attach/pin):
#   We drive `apply -f <cfg> --iface <VALID-but-NONEXISTENT name>`.  The config is
#   PARSED before any iface attach, so:
#     - an oversized integer is rejected at config-parse → exit 9 (the attach is
#       never reached; no bpffs/iface touch; no root needed).
#     - an in-range config PARSES, then the attach fails later at ifindex
#       resolution (the iface does not exist) → some NON-9 exit (e.g. 5).
#   So the parity assertion is rc != 9 ("the boundary value was accepted by the
#   parser"), which is root-free and touches no host state.
#   ANTI-VACUITY: the oversized cases asserting exit 9 with the SAME nonexistent
#   iface PROVE config-parse runs before ifindex resolution; if an oversized case
#   ever yields exit 5 instead of 9, the parse-before-resolve premise is broken
#   and the parity (rc!=9) would be vacuous — that failure surfaces loudly here.
#
# Sanity-floor smoke: every loader invocation launches + exits.
# Negation control: the parity cases (in-range maxima → rc != 9) ARE the negation
# against an "over-reject everything numeric" failure mode. Oversized→9 WITHOUT
# parity→(!=9) would mean the guard rejects valid boundary values (R-3 broke
# in-range parsing — a regression, not a fix).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)

# Valid-but-(vanishingly-likely-to-exist) iface — passes the §5.62 R-1 shape
# gate (valid chars, <=15 bytes, no '/', no '..', no whitespace) so it does NOT
# get exit-8'd; it is NONEXISTENT so a parsed-OK config fails at ifindex resolve
# (NOT exit 9) instead of attaching → keeps the test root-free + lock-free.
NIFACE="xmfno$(( $$ % 100000 ))"

# ── Architect-pending value (Q-B): the in-range MAXIMUM rule id used as the
# parity control. §6.78 TestStrategy literally says 4294967295, but B30's
# slot_rule_id map plausibly reserves UINT32_MAX (0xFFFFFFFF) as the empty-slot
# sentinel — which would make id=4294967295 a RESERVED→rejected value (exit 9 for
# a NON-R-3 reason), breaking the parity. Defaulting to 4294967294 (one below the
# sentinel) = "a large in-range id the R-3 overflow guard must accept". Flip to
# 4294967295 if the architect confirms it is NOT reserved.
ID_PARITY_MAX=4294967294

workdir=$(mktemp -d /tmp/xdpmf-intovf.XXXXXX)
stderr_file=$(mktemp /tmp/xdpmf-intovf-stderr.XXXXXX)
trap 'rm -rf "${workdir}"; rm -f "${stderr_file}"' EXIT INT TERM HUP

fail=0

# write_cfg <path> <id> <extra-match-lines...>
#   Emits a minimal valid schema_version:2 config with ONE pass rule. The rule
#   always carries a valid src_cidr axis so the ONLY thing under test is the
#   integer field injected via <id> / the extra match line(s).
write_cfg() {
    local path="$1" id="$2"; shift 2
    {
        echo "schema_version: 2"
        echo "default_action: drop"
        echo "rules:"
        echo "  - id: ${id}"
        echo "    action: pass"
        echo "    match:"
        echo "      src_cidr: \"10.0.0.0/8\""
        local line
        for line in "$@"; do
            echo "      ${line}"
        done
    } > "${path}"
}

# run_apply <cfg> → sets global RC + fills stderr_file.
run_apply() {
    local cfg="$1"
    : >"${stderr_file}"
    set +e
    "${LOADER_BIN}" apply -f "${cfg}" --iface "${NIFACE}" 2>"${stderr_file}"
    RC=$?
    set -e
}

# assert_overflow_rejected <label> <field-token> <overflow-msg-ERE> <cfg>
#   The oversized case: MUST exit 9 (ConfigError) at config-parse WITH the
#   integer-overflow diagnostic (per §6.78 EDIT-3 contrast-pair: the overflow
#   MESSAGE — not just exit 9 — proves it was the INTEGER that was rejected, not
#   some unrelated config error). Exit-9 here ALSO proves parse-runs-before-
#   resolve (anti-vacuity for the parity cases on the same nonexistent iface).
assert_overflow_rejected() {
    local label="$1" field="$2" msg_ere="$3" cfg="$4"
    echo
    echo "=== ${label} (oversized ${field}) — expect exit 9 + overflow message"
    run_apply "${cfg}"
    echo "rc=${RC}"
    echo "--- stderr ---"; cat "${stderr_file}" >&2 || true; echo "--- end ---"

    if [[ "${RC}" -ne 9 ]]; then
        echo "FAIL[${label}.rc]: expected rc=9 (ConfigError), got ${RC}" >&2
        case "${RC}" in
            0) echo "          rc=0 — oversized ${field} ACCEPTED (overflow guard absent/broken)" >&2 ;;
            5) echo "          rc=5 — ifindex resolve fired BEFORE config-parse: parse-before-resolve premise broken;" >&2
               echo "                 the parity (rc!=9) assertions would be vacuous → escalate to architect" >&2 ;;
            *) echo "          rc=${RC} — rejected but not via ConfigError(9)" >&2 ;;
        esac
        fail=1
    fi
    if ! grep -qE -- 'config error:' "${stderr_file}"; then
        echo "FAIL[${label}.prefix]: stderr missing 'config error:' prefix" >&2
        fail=1
    fi
    # Overflow-specific diagnostic (§6.78 EDIT-3): 'exceeds u32 max' (id) /
    # 'must be in [0,N]' (bounded). This is the discriminator that distinguishes
    # an INTEGER-overflow rejection from any other ConfigError.
    if ! grep -qiE -- "${msg_ere}" "${stderr_file}"; then
        echo "FAIL[${label}.msg]: stderr missing the integer-overflow diagnostic (ERE: ${msg_ere})" >&2
        fail=1
    fi
}

# assert_parity_parses <label> <field> <cfg>
#   The in-range MAXIMUM case: MUST NOT be rejected at the integer-parse layer
#   → rc != 9. (It then fails at ifindex resolve on the nonexistent iface, which
#   is fine — we only assert the parser accepted the boundary value.)
assert_parity_parses() {
    local label="$1" field="$2" cfg="$3"
    echo
    echo "=== ${label} (in-range max ${field}) — expect rc != 9 (parser accepted the boundary)"
    run_apply "${cfg}"
    echo "rc=${RC}"
    echo "--- stderr ---"; cat "${stderr_file}" >&2 || true; echo "--- end ---"

    if [[ "${RC}" -eq 9 ]]; then
        echo "FAIL[${label}]: in-range maximum ${field} REJECTED with ConfigError(9) — R-3 over-rejects the boundary" >&2
        echo "                (this is the load-bearing parity regression: R-3 broke in-range parsing)" >&2
        fail=1
    fi
}

# ── oversized → exit 9 + overflow message ───────────────────────────────────
# id overflows u32 via parse_u32_or_throw → 'exceeds u32 max' (config.cpp:88).
# protocol/dst_port/vlan overflow their parse_bounded_uint bound → 'must be in
# [0,N]'. EREs are loose to absorb minor wording variants (operative-semantic
# discipline — exact strings are SHOULD-level orientation).
CFG_ID_BIG="${workdir}/id_overflow.yaml"
write_cfg "${CFG_ID_BIG}" "999999999999999999999999999999"
assert_overflow_rejected id_overflow id 'exceeds|u32' "${CFG_ID_BIG}"

CFG_PROTO_BIG="${workdir}/proto_overflow.yaml"
write_cfg "${CFG_PROTO_BIG}" 0 "protocol: 99999"
assert_overflow_rejected proto_overflow protocol 'must be in|\[0,|range' "${CFG_PROTO_BIG}"

CFG_PORT_BIG="${workdir}/port_overflow.yaml"
write_cfg "${CFG_PORT_BIG}" 0 "dst_port: 99999"
assert_overflow_rejected port_overflow dst_port 'must be in|\[0,|range' "${CFG_PORT_BIG}"

CFG_VLAN_BIG="${workdir}/vlan_overflow.yaml"
write_cfg "${CFG_VLAN_BIG}" 0 "vlan: 99999"
assert_overflow_rejected vlan_overflow vlan 'must be in|\[0,|range' "${CFG_VLAN_BIG}"

# ── parity: in-range maxima still parse (rc != 9) ───────────────────────────
CFG_ID_MAX="${workdir}/id_max.yaml"
write_cfg "${CFG_ID_MAX}" "${ID_PARITY_MAX}"
assert_parity_parses id_max id "${CFG_ID_MAX}"

CFG_PROTO_MAX="${workdir}/proto_max.yaml"
write_cfg "${CFG_PROTO_MAX}" 0 "protocol: 255"
assert_parity_parses proto_max protocol "${CFG_PROTO_MAX}"

CFG_PORT_MAX="${workdir}/port_max.yaml"
write_cfg "${CFG_PORT_MAX}" 0 "dst_port: 65535"
assert_parity_parses port_max dst_port "${CFG_PORT_MAX}"

CFG_VLAN_MAX="${workdir}/vlan_max.yaml"
write_cfg "${CFG_VLAN_MAX}" 0 "vlan: 4095"
assert_parity_parses vlan_max vlan "${CFG_VLAN_MAX}"

# ── separate B30-sentinel check (§5.61, NOT R-3) — id 0xFFFFFFFF reserved ────
# Per §6.78 EDIT-1: id 4294967295 (= XDPMF_SLOT_ID_EMPTY) is rejected at
# config.cpp:420 ("rule id reserved") INDEPENDENTLY of R-3. This pins the
# boundary between "largest usable id" (0xFFFFFFFE, parity above) and the
# reserved sentinel — so a future R-3/B30 change that lets the sentinel through
# (or that pushes the overflow guard down to reject 0xFFFFFFFE) is caught.
echo
echo "=== id_sentinel (id 4294967295 = B30 XDPMF_SLOT_ID_EMPTY) — expect exit 9 (reserved, NOT R-3)"
CFG_ID_SENTINEL="${workdir}/id_sentinel.yaml"
write_cfg "${CFG_ID_SENTINEL}" "4294967295"
run_apply "${CFG_ID_SENTINEL}"
echo "rc=${RC}"
echo "--- stderr ---"; cat "${stderr_file}" >&2 || true; echo "--- end ---"
if [[ "${RC}" -ne 9 ]]; then
    echo "FAIL[id_sentinel.rc]: id 4294967295 expected rc=9 (B30 reserved sentinel), got ${RC}" >&2
    echo "          0xFFFFFFFF is XDPMF_SLOT_ID_EMPTY — accepting it would corrupt the slot_rule_id map" >&2
    fail=1
fi
if ! grep -qiE -- 'reserv|sentinel' "${stderr_file}"; then
    echo "FAIL[id_sentinel.msg]: stderr does not name the id as reserved (expected a 'reserved' diagnostic, NOT an overflow message)" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_CONFIG_INT_OVERFLOW_REJECT"
exit "${fail}"
