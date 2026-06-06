#!/bin/bash
# T_CLI_APPLY_DRYRUN — §5.78 (MVP-4.38 / B45) TestStrategy.
#
# `apply --dry-run` now has TWO output formats, OFFLINE and UNPRIVILEGED:
#   - DEFAULT  → the HUMAN-DECODED operator view (§5.78.4(a)) — readable,
#                operator-vocabulary, per-rule decode (id/slot/action/target +
#                match axes), header summary, redirect note, blackhole warning.
#   - --format=golden (or =image) → the frozen `# xdpfilter-image v1` machine
#                map-image (the B44 default), now BEHIND THE FLAG.
# Both formats render with ZERO kernel side effects (no map create, no bpffs
# pin, no XDP attach) — the operator-facing dual of the libbpf-free harness
# (T_DRYRUN_IMAGE_IDENTITY, #112).
#
# Realization of the zero-touch assertion (§5.78.6 ZERO-TOUCH): point --iface at
# a GUARANTEED-NONEXISTENT device AND run with NO sudo/root. A real apply in this
# environment cannot resolve/attach the iface, so a clean exit-0 PROVES the
# kernel was never touched. The MANDATORY zero-touch NEGATION runs the SAME
# `-f`/`--iface` WITHOUT `--dry-run` and asserts it exits NON-ZERO.
#
# The MANDATORY FEATURE NEGATION (§5.78.6 #5) is the empty-ruleset blackhole:
# dryrun_empty.yaml (default_action: drop, ZERO rules) → the human view MUST
# print ONE line carrying WARNING + 'no rules' + the default-verdict word
# ('drop'). The comparator-can-fail control (#6) asserts the 10-rule fixture
# does NOT print that warning line.
#
# Sanity-floor SMOKE: the loader binary exists + runs (find_loader).
#
# NO root / NO veth / NO RESOURCE_LOCK (guard #12: touches no shared host
# state) — runs in the CI build-only subset (§5.72).
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)        # SMOKE: binary located + executable, or aborts here.

CLI_YAML="${TEST_DIR}/dryrun/dryrun_cli.yaml"
EMPTY_YAML="${TEST_DIR}/dryrun/dryrun_empty.yaml"
GOLDEN="${TEST_DIR}/dryrun/dryrun_image.golden"

gold_file=$(mktemp /tmp/xdpmf-dryrun-gold.XXXXXX)
human_file=$(mktemp /tmp/xdpmf-dryrun-human.XXXXXX)
empty_file=$(mktemp /tmp/xdpmf-dryrun-empty.XXXXXX)
err_file=$(mktemp /tmp/xdpmf-dryrun-stderr.XXXXXX)
neg_out=$(mktemp /tmp/xdpmf-dryrun-negout.XXXXXX)
corrupt=$(mktemp /tmp/xdpmf-dryrun-corrupt.XXXXXX)
trap 'rm -f "${gold_file}" "${human_file}" "${empty_file}" "${err_file}" "${neg_out}" "${corrupt}"' EXIT

# A device name that CANNOT exist (project prefix + PID).
NODEV="xdpmf_nodev_$$"

fail=0

# Sanity: fixtures present.
[[ -f "${CLI_YAML}" ]]   || { echo "FAIL: missing CLI corpus ${CLI_YAML}"   >&2; exit 1; }
[[ -f "${EMPTY_YAML}" ]] || { echo "FAIL: missing empty fixture ${EMPTY_YAML}" >&2; exit 1; }
[[ -f "${GOLDEN}" ]]     || { echo "FAIL: missing golden ${GOLDEN}"         >&2; exit 1; }

# Precondition: NODEV really does not exist (the zero-touch realization needs it).
if ip link show "${NODEV}" >/dev/null 2>&1; then
    echo "FAIL: precondition — sentinel iface ${NODEV} unexpectedly EXISTS" >&2
    exit 1
fi
PIN_NODEV="${PIN_ROOT}/${NODEV}"
if [[ -e "${PIN_NODEV}" ]]; then
    echo "FAIL: precondition — pin dir ${PIN_NODEV} already exists before run" >&2
    exit 1
fi

# ════════════════════════════════════════════════════════════════════════════
# (1) GOLDEN behind --format=golden — PI-mvp-4.38-GOLDEN-UNCHANGED end-to-end.
#     The B44 assertions, now triggered with the explicit flag. §5.78.6 #1.
# ════════════════════════════════════════════════════════════════════════════
echo "=== [golden] apply --dry-run --format=golden -f ${CLI_YAML} --iface ${NODEV}"
set +e
"${LOADER_BIN}" apply --iface "${NODEV}" -f "${CLI_YAML}" --dry-run --format=golden \
    > "${gold_file}" 2> "${err_file}"
rc=$?
set -e
echo "rc=${rc}"
echo "--- stderr ---"; cat "${err_file}" >&2 || true; echo "--- end stderr ---"

# (1a) exit 0.
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[1a]: --format=golden dry-run expected rc=0, got ${rc}" >&2
    fail=1
fi
# (1b) first line is the canonical MACHINE header.
gold_first=$(head -n1 "${gold_file}" 2>/dev/null || true)
if [[ "${gold_first}" != "# xdpfilter-image v1" ]]; then
    echo "FAIL[1b]: --format=golden first line is not '# xdpfilter-image v1' (got '${gold_first}')" >&2
    fail=1
fi
# (1c) the symbolic redirect_devmap block + 'dpi0 RESOLVED-AT-APPLY' row.
if ! grep -qE '^map=redirect_devmap ' "${gold_file}"; then
    echo "FAIL[1c]: golden missing the 'map=redirect_devmap' block" >&2
    fail=1
fi
if ! grep -qE 'dpi0 RESOLVED-AT-APPLY' "${gold_file}"; then
    echo "FAIL[1d]: golden missing the symbolic 'dpi0 RESOLVED-AT-APPLY' devmap row" >&2
    fail=1
fi
# (1e) at least one occupied non-devmap map block.
if ! grep -qE '^map=allowlist_a ' "${gold_file}"; then
    echo "FAIL[1e]: golden missing an occupied non-devmap map (map=allowlist_a)" >&2
    fail=1
fi
# (1f) the apply --iface must NOT leak into the image.
if grep -qE -- "${NODEV}" "${gold_file}"; then
    echo "FAIL[1f]: golden leaked the apply --iface '${NODEV}' into the image" >&2
    fail=1
fi
# (1g) LOAD-BEARING: golden stdout BYTE-EQUALS the frozen golden.
if ! diff -u "${GOLDEN}" "${gold_file}" >/dev/null 2>&1; then
    echo "FAIL[1g]: --format=golden stdout != frozen golden (${GOLDEN})" >&2
    diff -u "${GOLDEN}" "${gold_file}" 2>&1 | head -30 >&2 || true
    fail=1
fi
# (1h) ZERO kernel side-effects after the golden run.
if [[ -e "${PIN_NODEV}" ]]; then
    echo "FAIL[1h]: golden dry-run created a bpffs pin dir ${PIN_NODEV} (kernel touched!)" >&2
    fail=1
fi
if ip link show "${NODEV}" >/dev/null 2>&1; then
    echo "FAIL[1i]: iface ${NODEV} now exists after golden dry-run (kernel touched!)" >&2
    fail=1
fi

# ════════════════════════════════════════════════════════════════════════════
# (2) DEFAULT output is the HUMAN view — §5.78.6 #2 (PI-FORMAT-DEFAULT).
#     Same command WITHOUT --format. Header summary + observable default-switch.
# ════════════════════════════════════════════════════════════════════════════
echo
echo "=== [human] apply --dry-run -f ${CLI_YAML} --iface ${NODEV} (DEFAULT format)"
set +e
"${LOADER_BIN}" apply --iface "${NODEV}" -f "${CLI_YAML}" --dry-run \
    > "${human_file}" 2> "${err_file}"
hrc=$?
set -e
echo "hrc=${hrc}"
echo "--- stderr ---"; cat "${err_file}" >&2 || true; echo "--- end stderr ---"
echo "--- human stdout ---"; cat "${human_file}" || true; echo "--- end human stdout ---"

# (2a) exit 0.
if [[ "${hrc}" -ne 0 ]]; then
    echo "FAIL[2a]: default (human) dry-run expected rc=0, got ${hrc}" >&2
    fail=1
fi
# (2b) first line is the HUMAN header — DISTINCT from the golden header
#      (the default-format switch is OBSERVABLE).
human_first=$(head -n1 "${human_file}" 2>/dev/null || true)
if [[ "${human_first}" != "# xdpfilter dry-run" ]]; then
    echo "FAIL[2b]: human first line is not '# xdpfilter dry-run' (got '${human_first}')" >&2
    fail=1
fi
if [[ "${human_first}" == "# xdpfilter-image v1" ]]; then
    echo "FAIL[2c]: human first line EQUALS the golden header — default-switch not observable" >&2
    fail=1
fi
# (2d) header summary: default_action, rule count, steering tap.
if ! grep -qE 'default_action: drop' "${human_file}"; then
    echo "FAIL[2d]: human view missing 'default_action: drop'" >&2
    fail=1
fi
if ! grep -qE 'rules: 10' "${human_file}"; then
    echo "FAIL[2e]: human view missing 'rules: 10'" >&2
    fail=1
fi
if ! grep -qE 'steering: redirect_to=dpi0' "${human_file}"; then
    echo "FAIL[2f]: human view missing 'steering: redirect_to=dpi0'" >&2
    fail=1
fi

# ════════════════════════════════════════════════════════════════════════════
# (3) PER-RULE DECODE + operator vocabulary — §5.78.6 #3.
#     Each rule line carries id=/slot=/action=; match: line lists axes in the
#     PINNED value forms (§5.78.4(a) table). Pin on value forms, NEVER on the
#     optional parenthesized name annotation.
# ════════════════════════════════════════════════════════════════════════════
echo
echo "=== [human] per-rule decode assertions"

# (3a) every rule line carries a slot= token. Count rule lines (id=<N> slot=).
rule_lines=$(grep -cE 'id=[0-9]+ slot=[0-9]+ action=' "${human_file}" || true)
if [[ "${rule_lines}" -ne 10 ]]; then
    echo "FAIL[3a]: expected 10 'id=N slot=N action=' rule lines, got ${rule_lines}" >&2
    fail=1
fi

# (3b) id=1 → slot=0, action=pass, with dst_cidr=10.0.0.0/8 on the contiguous
#      match: line (grep -A1 captures it because the two lines are CONTIGUOUS).
if ! grep -qE 'id=1 slot=0 action=pass' "${human_file}"; then
    echo "FAIL[3b]: human view missing 'id=1 slot=0 action=pass'" >&2
    fail=1
fi
if ! grep -A1 -E 'id=1 slot=0 action=pass' "${human_file}" | grep -qE 'match:.*dst_cidr=10\.0\.0\.0/8'; then
    echo "FAIL[3c]: id=1 match line missing 'dst_cidr=10.0.0.0/8'" >&2
    fail=1
fi

# (3d) id=2 → dst_cidr=10.1.2.0/24.
if ! grep -A1 -E 'id=2 slot=1 action=drop' "${human_file}" | grep -qE 'match:.*dst_cidr=10\.1\.2\.0/24'; then
    echo "FAIL[3d]: id=2 match line missing 'dst_cidr=10.1.2.0/24'" >&2
    fail=1
fi

# (3e) id=3 → protocol=6 (decimal; name annotation optional, pin on value).
if ! grep -A1 -E 'id=3 slot=2 action=pass' "${human_file}" | grep -qE 'match:.*protocol=6'; then
    echo "FAIL[3e]: id=3 match line missing 'protocol=6'" >&2
    fail=1
fi

# (3f) id=4 → protocol=6 AND dst_port=80-443 (inclusive range).
if ! grep -A1 -E 'id=4 slot=3 action=drop' "${human_file}" | grep -qE 'match:.*protocol=6'; then
    echo "FAIL[3f]: id=4 match line missing 'protocol=6'" >&2
    fail=1
fi
if ! grep -A1 -E 'id=4 slot=3 action=drop' "${human_file}" | grep -qE 'match:.*dst_port=80-443'; then
    echo "FAIL[3g]: id=4 match line missing 'dst_port=80-443'" >&2
    fail=1
fi

# (3h) id=5 → mac=aa:bb:cc:dd:ee:ff (lowercase colon-hex).
if ! grep -A1 -E 'id=5 slot=4 action=pass' "${human_file}" | grep -qE 'match:.*mac=aa:bb:cc:dd:ee:ff'; then
    echo "FAIL[3h]: id=5 match line missing 'mac=aa:bb:cc:dd:ee:ff'" >&2
    fail=1
fi

# (3i) id=6 → vlan=100 (decimal).
if ! grep -A1 -E 'id=6 slot=5 action=pass' "${human_file}" | grep -qE 'match:.*vlan=100'; then
    echo "FAIL[3i]: id=6 match line missing 'vlan=100'" >&2
    fail=1
fi

# (3j) id=7 → ethertype=0x806 (hex, lowercase, no fixed width).
if ! grep -A1 -E 'id=7 slot=6 action=drop' "${human_file}" | grep -qE 'match:.*ethertype=0x806'; then
    echo "FAIL[3j]: id=7 match line missing 'ethertype=0x806'" >&2
    fail=1
fi

# (3k) id=8 → dst_cidr6=2001:db8::/32 (canonical-compressed lowercase v6).
if ! grep -A1 -E 'id=8 slot=7 action=pass' "${human_file}" | grep -qE 'match:.*dst_cidr6=2001:db8::/32'; then
    echo "FAIL[3k]: id=8 match line missing 'dst_cidr6=2001:db8::/32'" >&2
    fail=1
fi

# (3l) id=9 → src_cidr6=fe80::/10.
if ! grep -A1 -E 'id=9 slot=8 action=drop' "${human_file}" | grep -qE 'match:.*src_cidr6=fe80::/10'; then
    echo "FAIL[3l]: id=9 match line missing 'src_cidr6=fe80::/10'" >&2
    fail=1
fi

# (3m) id=10 → redirect, with target=dpi0, mac=11:22:33:44:55:66.
if ! grep -qE 'id=10 slot=9 action=redirect target=dpi0' "${human_file}"; then
    echo "FAIL[3m]: human view missing 'id=10 slot=9 action=redirect target=dpi0'" >&2
    fail=1
fi
if ! grep -A1 -E 'id=10 slot=9 action=redirect target=dpi0' "${human_file}" | grep -qE 'match:.*mac=11:22:33:44:55:66'; then
    echo "FAIL[3n]: id=10 match line missing 'mac=11:22:33:44:55:66'" >&2
    fail=1
fi

# ════════════════════════════════════════════════════════════════════════════
# (4) REDIRECT RESOLUTION NOTE — §5.78.6 #4. The human view, having a redirect
#     rule, must carry a 'RESOLVED-AT-APPLY' line naming the target dpi0.
# ════════════════════════════════════════════════════════════════════════════
echo
echo "=== [human] redirect-resolution note assertion"
if ! grep -qE 'RESOLVED-AT-APPLY' "${human_file}"; then
    echo "FAIL[4a]: human view missing the 'RESOLVED-AT-APPLY' redirect note" >&2
    fail=1
fi
if ! grep -E 'RESOLVED-AT-APPLY' "${human_file}" | grep -qE 'dpi0'; then
    echo "FAIL[4b]: the 'RESOLVED-AT-APPLY' note does not name target 'dpi0'" >&2
    fail=1
fi

# ════════════════════════════════════════════════════════════════════════════
# (5) MANDATORY NEGATION — empty-ruleset blackhole WARNING — §5.78.6 #5.
#     dryrun_empty.yaml: default_action drop, ZERO rules → VALID, compiles,
#     exit 0. The human view MUST flag the blackhole.
# ════════════════════════════════════════════════════════════════════════════
echo
echo "=== [human] empty-ruleset blackhole NEGATION (dryrun_empty.yaml)"
set +e
"${LOADER_BIN}" apply --iface "${NODEV}" -f "${EMPTY_YAML}" --dry-run \
    > "${empty_file}" 2> "${err_file}"
erc=$?
set -e
echo "erc=${erc}"
echo "--- stderr ---"; cat "${err_file}" >&2 || true; echo "--- end stderr ---"
echo "--- empty stdout ---"; cat "${empty_file}" || true; echo "--- end empty stdout ---"

# (5a) the empty config is VALID and compiles → exit 0.
if [[ "${erc}" -ne 0 ]]; then
    echo "FAIL[5a]: empty-ruleset dry-run expected rc=0 (valid config), got ${erc}" >&2
    fail=1
fi
# (5b) header reports zero rules.
if ! grep -qE 'rules: 0' "${empty_file}"; then
    echo "FAIL[5b]: empty-ruleset human view missing 'rules: 0'" >&2
    fail=1
fi
# (5c) CONTRACT (§5.78.4(a)): ONE line carries ALL THREE substrings — 'WARNING'
#      (literal, case-sensitive) AND 'no rules' AND the default-verdict word
#      ('drop', matching this fixture's default_action). Non-vacuous (3 tokens)
#      without coupling to exact prose. ('all traffic dropped' was an
#      illustrative gloss only — NOT a pinned token; do not grep it.)
if ! grep -E 'WARNING' "${empty_file}" | grep -E 'no rules' | grep -qE 'drop'; then
    echo "FAIL[5c]: empty-ruleset view has no single line carrying 'WARNING' + 'no rules' + 'drop'" >&2
    fail=1
fi

# ════════════════════════════════════════════════════════════════════════════
# (6) COMPARATOR-CAN-FAIL CONTROL — §5.78.6 #6. The 10-rule fixture's human
#     view must NOT carry the empty-ruleset warning — proving the warning is
#     CONDITIONAL on zero rules, not always-printed (the negation is not vacuous).
# ════════════════════════════════════════════════════════════════════════════
echo
echo "=== [human] comparator-can-fail control (10-rule view must NOT warn 'no rules')"
if grep -E 'WARNING' "${human_file}" | grep -qE 'no rules'; then
    echo "FAIL[6]: 10-rule human view UNEXPECTEDLY printed the empty-ruleset 'no rules' WARNING" >&2
    echo "         — the warning is not conditional on zero rules ⇒ the negation is vacuous." >&2
    fail=1
fi

# ════════════════════════════════════════════════════════════════════════════
# (7) --format REQUIRES --dry-run — §5.78.6 #7 (D-mvp-4.38-FMT-REQUIRES-DRYRUN).
#     --format without --dry-run → non-zero CliError. (Realization: even on a
#     live path this MUST be rejected at parse time, before any kernel touch.)
# ════════════════════════════════════════════════════════════════════════════
echo
echo "=== --format WITHOUT --dry-run must be rejected (expect NON-ZERO)"
set +e
"${LOADER_BIN}" apply --iface "${NODEV}" -f "${CLI_YAML}" --format=golden \
    > "${neg_out}" 2>&1
fmt_rc=$?
set -e
echo "fmt_rc=${fmt_rc}"
echo "--- output ---"; cat "${neg_out}" >&2 || true; echo "--- end output ---"
if [[ "${fmt_rc}" -eq 0 ]]; then
    echo "FAIL[7]: 'apply --format=golden' WITHOUT --dry-run UNEXPECTEDLY exited 0" >&2
    fail=1
fi

# ════════════════════════════════════════════════════════════════════════════
# (8) UNKNOWN --format VALUE rejected — §5.78.6 #8.
# ════════════════════════════════════════════════════════════════════════════
echo
echo "=== unknown --format=bogus must be rejected (expect NON-ZERO)"
set +e
"${LOADER_BIN}" apply --iface "${NODEV}" -f "${CLI_YAML}" --dry-run --format=bogus \
    > "${neg_out}" 2>&1
bogus_rc=$?
set -e
echo "bogus_rc=${bogus_rc}"
if [[ "${bogus_rc}" -eq 0 ]]; then
    echo "FAIL[8]: '--format=bogus' UNEXPECTEDLY exited 0 (unknown format must be a CliError)" >&2
    fail=1
fi

# ════════════════════════════════════════════════════════════════════════════
# (9) ZERO-TOUCH NEGATION — same args WITHOUT --dry-run must exit NON-ZERO.
#     Proves the offline/unprivileged/nonexistent-iface env makes a real kernel
#     touch OBSERVABLY fail ⇒ the dry-run exit-0s above are genuine zero-touch.
# ════════════════════════════════════════════════════════════════════════════
echo
echo "=== ZERO-TOUCH NEGATION: live apply WITHOUT --dry-run (expect NON-ZERO)"
set +e
"${LOADER_BIN}" apply --iface "${NODEV}" -f "${CLI_YAML}" \
    > "${neg_out}" 2>&1
neg_rc=$?
set -e
echo "neg_rc=${neg_rc}"
echo "--- neg output ---"; cat "${neg_out}" >&2 || true; echo "--- end neg output ---"
if [[ "${neg_rc}" -eq 0 ]]; then
    echo "FAIL[9]: live apply (no --dry-run) UNEXPECTEDLY exited 0 in an offline," >&2
    echo "         unprivileged, nonexistent-iface context — the dry-run exit-0s would" >&2
    echo "         then be vacuous (the env does NOT make a kernel-touch fail)." >&2
    fail=1
fi
# defense in depth: no pin/iface left behind by any invocation.
if [[ -e "${PIN_NODEV}" ]] || ip link show "${NODEV}" >/dev/null 2>&1; then
    echo "FAIL[9b]: an invocation left a pin dir / iface for ${NODEV}" >&2
    fail=1
fi

# ════════════════════════════════════════════════════════════════════════════
# (10) GOLDEN BYTE-COMPARATOR CAN FAIL — corrupt one byte of the golden and
#      assert --format=golden stdout no longer matches (assertion 1g is real).
# ════════════════════════════════════════════════════════════════════════════
echo
echo "=== golden byte-comparator can FAIL (corrupt control)"
cp "${GOLDEN}" "${corrupt}"
python3 - "${corrupt}" <<'PY'
import sys
p = sys.argv[1]
data = open(p, 'rb').read().split(b'\n')
for i, line in enumerate(data):
    if line.startswith(b'  '):
        b = bytearray(line)
        for j in range(2, len(b)):
            c = chr(b[j])
            if c in '0123456789abcdef':
                b[j] = ord('1') if c == '0' else ord('0') if c in '123456789' else \
                       ord('b') if c == 'a' else ord('a')
                data[i] = bytes(b)
                open(p, 'wb').write(b'\n'.join(data))
                sys.exit(0)
sys.exit(2)  # could not find a byte to corrupt
PY
if diff -q "${corrupt}" "${gold_file}" >/dev/null 2>&1; then
    echo "FAIL[10]: corrupted golden still matched --format=golden stdout — comparator vacuous" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_CLI_APPLY_DRYRUN"
exit "${fail}"
