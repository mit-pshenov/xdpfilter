#!/bin/bash
# T_ANSIBLE_PLAYBOOK_SYNTAX — design §6.35 (MVP-3.3 / §5.28).
#
# `ansible-playbook --syntax-check ansible/xdpmacfilter-deploy.yml` exits 0.
# SKIP-77 if `ansible-playbook` not in PATH (per brief — ansible-core is
# OPTIONAL test-time dep; PI-25 carve-out cited verbatim).
#
# Per §6.35 Observable outcome:
#   - Exit code 0.
#   - Stdout contains `playbook: <path>` (ansible-version-dependent
#     confirmation line).
#   - Stderr free of WARNINGS (deprecation noise filtered via grep -v).
#
# Anti-theatricality NEGATION control: also run --syntax-check against a
# deliberately-broken copy with the top-level `hosts:` key removed; assert
# exit-nonzero. Same pattern as §6.32 negation.
#
# NO veth, NO root, NO RESOURCE_LOCK.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

# SKIP-77 per design §6.35 SKIP condition + PI-25 carve-out citation.
if ! command -v ansible-playbook >/dev/null 2>&1; then
    echo "SKIP: ansible-playbook not in PATH — PI-25 carve-out" >&2
    exit 77
fi

ANSIBLE_PLAYBOOK="${ANSIBLE_PLAYBOOK:-${SOURCE_DIR}/ansible/xdpmacfilter-deploy.yml}"

# Sanity / smoke: the playbook file must exist.
if [[ ! -f "${ANSIBLE_PLAYBOOK}" ]]; then
    echo "FAIL: playbook not found at ${ANSIBLE_PLAYBOOK}" >&2
    exit 1
fi

TMPDIR=$(mktemp -d /tmp/xdpmf-ansible-syntax.XXXXXX)
trap 'rm -rf "${TMPDIR}"' EXIT

fail=0

# ── POSITIVE case ────────────────────────────────────────────────────────
echo "=== POSITIVE: ansible-playbook --syntax-check on ${ANSIBLE_PLAYBOOK}"
stdout_pos="${TMPDIR}/stdout.pos"
stderr_pos="${TMPDIR}/stderr.pos"
set +e
ansible-playbook --syntax-check "${ANSIBLE_PLAYBOOK}" \
    >"${stdout_pos}" 2>"${stderr_pos}"
rc_pos=$?
set -e
echo "rc_pos=${rc_pos}"
echo "--- stdout (pos) ---"
cat "${stdout_pos}" || true
echo "--- stderr (pos) ---"
cat "${stderr_pos}" >&2 || true
echo "--- end (pos) ---"

if [[ "${rc_pos}" -ne 0 ]]; then
    echo "FAIL[P1]: ansible-playbook --syntax-check exit ${rc_pos} (expected 0)" >&2
    fail=1
fi

# Stdout SHOULD contain `playbook:` per ansible's syntax-check
# confirmation line. Some ansible versions print the absolute path; we
# accept either the literal substring "playbook:" (case-sensitive) OR
# the playbook filename as a heuristic.
if ! grep -qE 'playbook:' "${stdout_pos}" && \
   ! grep -qF 'xdpmacfilter-deploy.yml' "${stdout_pos}"; then
    echo "FAIL[P2]: stdout missing 'playbook:' confirmation line or filename" >&2
    fail=1
fi

# Stderr SHOULD be free of ERRORS. Some ansible versions emit
# [WARNING] / [DEPRECATION] lines; we filter those, but anything else
# is a real error.
err_lines=$(grep -E -v \
    -e '^\[WARNING\]' \
    -e '^\[DEPRECATION WARNING\]' \
    -e '^$' \
    "${stderr_pos}" || true)
if [[ -n "${err_lines}" ]]; then
    echo "FAIL[P3]: ansible-playbook --syntax-check emitted non-warning stderr:" >&2
    printf '  > %s\n' "${err_lines}" >&2
    fail=1
fi

# ── NEGATION control ────────────────────────────────────────────────────
# Remove the top-level `hosts:` key — ansible-playbook --syntax-check
# MUST reject (a playbook with no hosts target is structurally invalid).
echo
echo "=== NEGATION: ansible-playbook --syntax-check on broken copy (no hosts:)"
broken="${TMPDIR}/broken.yml"
# sed strips any line that BEGINS with `hosts:` (with optional leading
# whitespace, allowing for either top-level or nested forms in this
# minimal playbook).
sed -E '/^[[:space:]]*hosts:[[:space:]]/d' "${ANSIBLE_PLAYBOOK}" > "${broken}"

# Confirm sed actually removed something.
if ! diff -q "${ANSIBLE_PLAYBOOK}" "${broken}" >/dev/null 2>&1; then
    : # Differences exist, sed worked.
else
    echo "FAIL[N0]: broken-playbook sed did NOT remove any 'hosts:' line" >&2
    fail=1
fi

stdout_neg="${TMPDIR}/stdout.neg"
stderr_neg="${TMPDIR}/stderr.neg"
set +e
ansible-playbook --syntax-check "${broken}" \
    >"${stdout_neg}" 2>"${stderr_neg}"
rc_neg=$?
set -e
echo "rc_neg=${rc_neg}"
echo "--- stdout (neg) ---"
cat "${stdout_neg}" || true
echo "--- stderr (neg) ---"
cat "${stderr_neg}" >&2 || true
echo "--- end (neg) ---"

if [[ "${rc_neg}" -eq 0 ]]; then
    echo "FAIL[N1]: NEGATION control — ansible-playbook --syntax-check on" \
         "hostless playbook exited 0; verifier is rubber-stamping" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_ANSIBLE_PLAYBOOK_SYNTAX"
exit "${fail}"
