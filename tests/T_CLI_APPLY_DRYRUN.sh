#!/bin/bash
# T_CLI_APPLY_DRYRUN — §5.77 (MVP-4.37 / B44) TestStrategy #2.
#
# The `apply --dry-run` CLI verb, OFFLINE and UNPRIVILEGED. It renders the
# frozen `# xdpfilter-image v1` map-image to stdout with ZERO kernel side
# effects (no map create, no bpffs pin, no XDP attach) — the operator-facing
# dual of the libbpf-free harness (T_DRYRUN_IMAGE_IDENTITY).
#
# Realization of the zero-touch assertion (§5.77.6 #2): point --iface at a
# GUARANTEED-NONEXISTENT device AND run with NO sudo/root. A real apply in this
# environment cannot resolve/attach the iface, so a clean exit-0-with-image
# PROVES the kernel was never touched. The MANDATORY NEGATION runs the SAME
# `-f`/`--iface` WITHOUT `--dry-run` and asserts it exits NON-ZERO — proving the
# environment makes a kernel-touch OBSERVABLY fail, so dry-run's exit-0 is a
# genuine zero-touch and not a masked/silent pass.
#
# Sanity-floor SMOKE: the loader binary exists + runs (find_loader). Without it
# no assertion below is reachable.
#
# NO root / NO veth / NO RESOURCE_LOCK (guard #12: touches no shared host
# state) — runs in the CI build-only subset (§5.72), so it deliberately does
# NOT call require_passwordless_sudo.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"

LOADER_BIN=$(find_loader)        # SMOKE: binary located + executable, or aborts here.

CLI_YAML="${TEST_DIR}/dryrun/dryrun_cli.yaml"
GOLDEN="${TEST_DIR}/dryrun/dryrun_image.golden"

out_file=$(mktemp /tmp/xdpmf-dryrun-stdout.XXXXXX)
err_file=$(mktemp /tmp/xdpmf-dryrun-stderr.XXXXXX)
neg_out=$(mktemp /tmp/xdpmf-dryrun-negout.XXXXXX)
corrupt=$(mktemp /tmp/xdpmf-dryrun-corrupt.XXXXXX)
trap 'rm -f "${out_file}" "${err_file}" "${neg_out}" "${corrupt}"' EXIT

# A device name that CANNOT exist (project prefix + PID). Pre-assert absence so
# the zero-touch logic rests on a real precondition, not an assumption.
NODEV="xdpmf_nodev_$$"

fail=0

# Sanity: fixtures present.
[[ -f "${CLI_YAML}" ]] || { echo "FAIL: missing CLI corpus ${CLI_YAML}" >&2; exit 1; }
[[ -f "${GOLDEN}" ]]   || { echo "FAIL: missing golden ${GOLDEN}"       >&2; exit 1; }

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

# ── PRIMARY: apply --dry-run, unprivileged, nonexistent iface ────────────────
echo "=== apply --dry-run -f ${CLI_YAML} --iface ${NODEV} (UNPRIVILEGED, OFFLINE)"
set +e
"${LOADER_BIN}" apply --iface "${NODEV}" -f "${CLI_YAML}" --dry-run \
    > "${out_file}" 2> "${err_file}"
rc=$?
set -e
echo "rc=${rc}"
echo "--- stderr ---"; cat "${err_file}" >&2 || true; echo "--- end stderr ---"

# (1) exit 0.
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL[1]: dry-run expected rc=0, got ${rc}" >&2
    fail=1
fi

# (2) stdout is the image: first line is the canonical header.
first_line=$(head -n1 "${out_file}" 2>/dev/null || true)
if [[ "${first_line}" != "# xdpfilter-image v1" ]]; then
    echo "FAIL[2]: stdout first line is not '# xdpfilter-image v1' (got '${first_line}')" >&2
    fail=1
fi

# (3) the redirect_devmap block carries the symbolic '<target> RESOLVED-AT-APPLY'
#     row — proving the devmap target was rendered symbolically (never a numeric
#     ifindex; no resolve happened) and that it names the steering target (dpi0),
#     NOT the apply --iface.
if ! grep -qE '^map=redirect_devmap ' "${out_file}"; then
    echo "FAIL[3a]: stdout missing the 'map=redirect_devmap' block" >&2
    fail=1
fi
if ! grep -qE 'dpi0 RESOLVED-AT-APPLY' "${out_file}"; then
    echo "FAIL[3b]: stdout missing the symbolic 'dpi0 RESOLVED-AT-APPLY' devmap row" >&2
    fail=1
fi
# the apply --iface must NOT leak into the image (would mean a wrong target).
if grep -qE -- "${NODEV}" "${out_file}"; then
    echo "FAIL[3c]: stdout leaked the apply --iface '${NODEV}' into the image" >&2
    fail=1
fi

# (4) at least one occupied NON-devmap map block (a real inner write-set,
#     not just an empty/devmap-only image).
if ! grep -qE '^map=allowlist_a ' "${out_file}"; then
    echo "FAIL[4]: stdout missing an occupied non-devmap map (map=allowlist_a)" >&2
    fail=1
fi

# (5) LOAD-BEARING: stdout BYTE-EQUALS the frozen golden. dryrun_cli.yaml is
#     authored to compile to build_corpus() ⇒ CLI render == harness render ==
#     golden. A diff is a REAL discrepancy (do NOT rebless the golden).
if ! diff -u "${GOLDEN}" "${out_file}" >/dev/null 2>&1; then
    echo "FAIL[5]: dry-run stdout != golden (${GOLDEN})" >&2
    echo "  first diffs:" >&2
    diff -u "${GOLDEN}" "${out_file}" 2>&1 | head -30 >&2 || true
    fail=1
fi

# (6) ZERO kernel side-effects (the load-bearing zero-touch assertion): after
#     the run, NO bpffs pin dir was created for the iface, and the iface still
#     does not exist (no veth was conjured). Unprivileged + nonexistent iface:
#     a live apply would have failed to resolve/pin/attach.
if [[ -e "${PIN_NODEV}" ]]; then
    echo "FAIL[6a]: dry-run created a bpffs pin dir ${PIN_NODEV} (kernel was touched!)" >&2
    fail=1
fi
if ip link show "${NODEV}" >/dev/null 2>&1; then
    echo "FAIL[6b]: iface ${NODEV} now exists after dry-run (kernel was touched!)" >&2
    fail=1
fi

# ── MANDATORY NEGATION: same args WITHOUT --dry-run must exit NON-ZERO ────────
# Proves the offline/unprivileged/nonexistent-iface environment makes a real
# kernel-touch OBSERVABLY fail ⇒ the dry-run's exit-0 above is a genuine
# zero-touch, not a vacuous pass.
echo
echo "=== NEGATION: same apply WITHOUT --dry-run (expect NON-ZERO exit)"
set +e
"${LOADER_BIN}" apply --iface "${NODEV}" -f "${CLI_YAML}" \
    > "${neg_out}" 2>&1
neg_rc=$?
set -e
echo "neg_rc=${neg_rc}"
echo "--- neg output ---"; cat "${neg_out}" >&2 || true; echo "--- end neg output ---"
if [[ "${neg_rc}" -eq 0 ]]; then
    echo "FAIL[7]: live apply (no --dry-run) UNEXPECTEDLY exited 0 in an offline," >&2
    echo "         unprivileged, nonexistent-iface context — dry-run's exit-0 would" >&2
    echo "         then be a vacuous pass (the env does NOT make a kernel-touch fail)." >&2
    fail=1
fi
# And the live path must not have left a pin/iface either (defense in depth).
if [[ -e "${PIN_NODEV}" ]] || ip link show "${NODEV}" >/dev/null 2>&1; then
    echo "FAIL[7b]: live apply left a pin dir / iface for ${NODEV}" >&2
    fail=1
fi

# ── SECONDARY NEGATION: the byte-comparator can FAIL ─────────────────────────
# Corrupt one byte of the golden and assert the dry-run stdout no longer
# matches — proves assertion (5) is a real comparator, not a tautology.
cp "${GOLDEN}" "${corrupt}"
# flip the first hex nibble on the first occupied data row (a line starting "  ").
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
if diff -q "${corrupt}" "${out_file}" >/dev/null 2>&1; then
    echo "FAIL[8]: corrupted golden still matched dry-run stdout — comparator is vacuous" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_CLI_APPLY_DRYRUN"
exit "${fail}"
