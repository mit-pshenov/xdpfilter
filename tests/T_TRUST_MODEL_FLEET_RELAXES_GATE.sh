#!/bin/bash
# T_TRUST_MODEL_FLEET_RELAXES_GATE — design §6.26 (MVP-3.1 / §5.26).
#
# Differential test of XDPMF_TRUST_MODEL. Uses the REAL alien fixture
# tests/fixtures/xdp_pass.bpf.o (same one §6.9 T_ATTACH_ALIEN_REFUSAL
# uses — built per add_bpf_object).
#
# 4 sub-cases:
#   1. strict-default (no env var): pre-attach alien → loader exit 4
#      + stderr 'trust_model=strict' + alien still attached.
#   2. strict-explicit (XDPMF_TRUST_MODEL=strict): same outcome as 1.
#   3. fleet (XDPMF_TRUST_MODEL=fleet): bypass alien-program check;
#      detach alien, attach ours → exit 0 + stderr 'trust_model=fleet'
#      + 'bypassing alien-program check' + our prog now attached.
#   4. garbage (XDPMF_TRUST_MODEL=garbage_value): config-error fail-closed
#      → exit 9 + 'config error: unknown trust model' in stderr + no XDP
#      attached + no bpffs dir.
#
# Sanity-floor smoke: each sub-case's loader invocation actually runs.
# Negation control: sub-cases 1+2 ARE the negation of sub-case 3 —
# same scenario, different env, opposite outcome. Differential proves
# the env var is functionally wired (not a no-op flag).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
FOREIGN_OBJ="${BUILD_DIR}/xdp_pass.bpf.o"
stderr_file=$(mktemp /tmp/xdpmf-trustmodel-stderr.XXXXXX)

cleanup_trustmodel() {
    set +e
    # Per §6.26 cleanup contract.
    ${NSEXEC} ip link set "${IFACE_A}" xdpgeneric off 2>/dev/null
    sudo -n rm -rf "${PIN_DIR}" 2>/dev/null
    cleanup_veth
    rm -f "${stderr_file}"
    set -e
}
trap cleanup_trustmodel EXIT

[[ -f "${FOREIGN_OBJ}" ]] \
    || { echo "FAIL: foreign-XDP fixture missing at ${FOREIGN_OBJ}" >&2
         echo "       (expected from add_bpf_object(xdp_pass …))" >&2
         exit 1; }

# Pre-attach the alien (xdp_pass.bpf.o) on IFACE_A; capture its prog id.
pre_attach_alien() {
    ${NSEXEC} ip link set "${IFACE_A}" xdpgeneric obj "${FOREIGN_OBJ}" sec xdp
    sleep 0.2
    local id
    id=$(xdp_prog_id "${IFACE_A}")
    if [[ -z "${id}" || "${id}" == "0" ]]; then
        echo "FAIL: alien-attach left no XDP prog id on ${IFACE_A}" >&2
        return 1
    fi
    echo "${id}"
}

# Wipe state between sub-cases.
reset_state() {
    ${NSEXEC} ip link set "${IFACE_A}" xdpgeneric off 2>/dev/null || true
    sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true
    sleep 0.2
}

setup_veth

fail=0

# ── Sub-case 1: strict-default (NO env var) → exit 4 ──────────────────────
echo
echo "=== sub-case 1: strict-default (no env) — alien refusal expected"
reset_state
alien_id_1=$(pre_attach_alien) || { fail=1; }
echo "alien_id_1=${alien_id_1}"
: >"${stderr_file}"
set +e
# Unset for paranoia (the caller's environment is the only source).
${NSEXEC} env -u XDPMF_TRUST_MODEL "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"
rc_1=$?
set -e
echo "rc_1=${rc_1}"
echo "--- stderr (1) ---"; cat "${stderr_file}" >&2 || true; echo "--- end stderr ---"

if [[ "${rc_1}" -ne 4 ]]; then
    echo "FAIL[1.a]: expected rc=4 (AttachRefusedAlien), got ${rc_1}" >&2
    fail=1
fi
if ! grep -qE -- 'xdpfilter: trust_model=strict' "${stderr_file}"; then
    echo "FAIL[1.b]: stderr missing 'trust_model=strict' audit line" >&2
    fail=1
fi
now_id_1=$(xdp_prog_id "${IFACE_A}")
if [[ "${now_id_1}" != "${alien_id_1}" ]]; then
    echo "FAIL[1.c]: alien clobbered in strict mode (was '${alien_id_1}', now '${now_id_1}')" >&2
    fail=1
fi

# ── Sub-case 2: strict-explicit → exit 4 ─────────────────────────────────
echo
echo "=== sub-case 2: strict-explicit (XDPMF_TRUST_MODEL=strict)"
reset_state
alien_id_2=$(pre_attach_alien) || { fail=1; }
echo "alien_id_2=${alien_id_2}"
: >"${stderr_file}"
set +e
${NSEXEC} env XDPMF_TRUST_MODEL=strict "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"
rc_2=$?
set -e
echo "rc_2=${rc_2}"
echo "--- stderr (2) ---"; cat "${stderr_file}" >&2 || true; echo "--- end stderr ---"

if [[ "${rc_2}" -ne 4 ]]; then
    echo "FAIL[2.a]: expected rc=4 (AttachRefusedAlien), got ${rc_2}" >&2
    fail=1
fi
if ! grep -qE -- 'xdpfilter: trust_model=strict' "${stderr_file}"; then
    echo "FAIL[2.b]: stderr missing 'trust_model=strict' audit line" >&2
    fail=1
fi
now_id_2=$(xdp_prog_id "${IFACE_A}")
if [[ "${now_id_2}" != "${alien_id_2}" ]]; then
    echo "FAIL[2.c]: alien clobbered in strict-explicit mode (was '${alien_id_2}', now '${now_id_2}')" >&2
    fail=1
fi

# ── Sub-case 3: fleet → exit 0 (alien detached, ours attached) ───────────
echo
echo "=== sub-case 3: fleet (XDPMF_TRUST_MODEL=fleet) — LOAD-BEARING differential"
reset_state
alien_id_3=$(pre_attach_alien) || { fail=1; }
echo "alien_id_3=${alien_id_3}"
: >"${stderr_file}"
set +e
${NSEXEC} env XDPMF_TRUST_MODEL=fleet "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"
rc_3=$?
set -e
echo "rc_3=${rc_3}"
echo "--- stderr (3) ---"; cat "${stderr_file}" >&2 || true; echo "--- end stderr ---"

if [[ "${rc_3}" -ne 0 ]]; then
    echo "FAIL[3.a]: expected rc=0 (fleet bypasses alien), got ${rc_3}" >&2
    fail=1
fi
if ! grep -qE -- 'xdpfilter: trust_model=fleet' "${stderr_file}"; then
    echo "FAIL[3.b]: stderr missing 'trust_model=fleet' audit line" >&2
    fail=1
fi
if ! grep -qE -- 'bypassing alien-program check' "${stderr_file}"; then
    echo "FAIL[3.c]: stderr missing 'bypassing alien-program check' signal" >&2
    fail=1
fi
now_id_3=$(xdp_prog_id "${IFACE_A}")
if [[ -z "${now_id_3}" ]]; then
    echo "FAIL[3.d]: no XDP attached after fleet apply (expected OUR prog)" >&2
    fail=1
elif [[ "${now_id_3}" == "${alien_id_3}" ]]; then
    echo "FAIL[3.e]: XDP prog id unchanged from alien (alien NOT replaced)" >&2
    fail=1
fi

# ── Sub-case 4: garbage value → exit 9 (config error fail-closed) ────────
echo
echo "=== sub-case 4: garbage XDPMF_TRUST_MODEL → fail-closed exit 9"
reset_state
# Clean iface — no pre-attached alien. Confirm.
pre_id=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
if [[ -n "${pre_id}" ]]; then
    echo "FAIL[4.pre]: ${IFACE_A} not clean before sub-case 4 (prog_id=${pre_id})" >&2
    fail=1
fi
: >"${stderr_file}"
set +e
${NSEXEC} env XDPMF_TRUST_MODEL=garbage_value "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"
rc_4=$?
set -e
echo "rc_4=${rc_4}"
echo "--- stderr (4) ---"; cat "${stderr_file}" >&2 || true; echo "--- end stderr ---"

if [[ "${rc_4}" -ne 9 ]]; then
    echo "FAIL[4.a]: expected rc=9 (ConfigError), got ${rc_4}" >&2
    fail=1
fi
if ! grep -qE -- 'xdpfilter: config error:' "${stderr_file}"; then
    echo "FAIL[4.b]: stderr missing 'xdpfilter: config error:' prefix" >&2
    fail=1
fi
if ! grep -qE -- 'unknown trust model' "${stderr_file}"; then
    echo "FAIL[4.c]: stderr missing 'unknown trust model' message" >&2
    fail=1
fi
if ! grep -q -F -- 'garbage_value' "${stderr_file}"; then
    echo "FAIL[4.d]: stderr does not name the rejected value 'garbage_value'" >&2
    fail=1
fi
post_id_4=$(xdp_prog_id "${IFACE_A}")
if [[ -n "${post_id_4}" ]]; then
    echo "FAIL[4.e]: XDP attached after rejected env (prog_id=${post_id_4})" >&2
    fail=1
fi
if sudo -n test -e "${PIN_DIR}"; then
    echo "FAIL[4.f]: orphan ${PIN_DIR} after rejected env" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_TRUST_MODEL_FLEET_RELAXES_GATE"
exit "${fail}"
