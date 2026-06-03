#!/bin/bash
# T_MODE_NATIVE_UNSUPPORTED — design §6.17 (MVP-2 Perf / §5.23 Q2 Option K).
#
# Closes Q2: when the kernel rejects a non-generic mode (EOPNOTSUPP /
# EINVAL), the loader maps to exit 3 (LoaderError::AttachFailed) and
# stderr names the rejected mode. Uses `lo` — universally does NOT
# support native XDP — as the unsupported target.
#
# NOTE: this test targets `lo` directly (NO veth fixture) and so does
# NOT take RESOURCE_LOCK xdp_fixture (it does not touch the shared
# veth pair).  However, `lo` is shared host state — we pre-check it is
# clean before our invocation and refuse to run if not (dirty fixture is
# NOT the loader's bug).
#
# Trigger (sequential):
#   1. Pre-check: xdp_prog_id lo is empty (else exit 1 — dirty env).
#   2. set +e; sudo -n LOADER attach --iface lo --allow MAC_GOOD --mode native 2> stderr; rc=$?; set -e
#
# Outcome (ALL must hold):
#   (a) rc == 3 — exit code matches LoaderError::AttachFailed (§4.1 + Q2 Option K).
#   (b) Stderr is non-empty AND contains substring 'native' or 'mode=native'
#       (impl-shape — the stderr should at least mention the rejected mode).
#   (c) Post-test: xdp_prog_id lo still empty (loader did not leave a partial
#       attach on lo).
#   (d) No orphan pin dir: /sys/fs/bpf/xdpfilter/lo does NOT exist.
#
# Cleanup (trap EXIT): belt-and-suspenders `ip link set lo xdpgeneric off`
# in case some future kernel surprises us by accepting `xdpgeneric` on lo
# even though we asked for native; remove temp stderr file.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
stderr_file=$(mktemp /tmp/xdpmf-native-stderr.XXXXXX)

cleanup_native() {
    set +e
    # Belt-and-suspenders: nuke any XDP that somehow got attached to lo
    # during the test.  Should be a no-op in the happy path (kernel
    # rejected the attach before any state change).
    sudo -n ip link set lo xdpgeneric off 2>/dev/null
    sudo -n ip link set lo xdp off       2>/dev/null
    sudo -n rm -rf /sys/fs/bpf/xdpfilter/lo 2>/dev/null
    rm -f "${stderr_file}"
    set -e
}
trap cleanup_native EXIT

# ── Preconditions: lo must be clean BEFORE our invocation ───────────────
pre_id=$(xdp_prog_id lo 2>/dev/null || true)
if [[ -n "${pre_id}" ]]; then
    echo "ERROR: lo already has XDP attached (prog_id=${pre_id})" >&2
    echo "       test environment is dirty; not the loader's fault." >&2
    exit 1
fi
if sudo -n test -e /sys/fs/bpf/xdpfilter/lo; then
    echo "ERROR: /sys/fs/bpf/xdpfilter/lo already exists pre-test" >&2
    echo "       test environment is dirty; cleanup expected." >&2
    exit 1
fi

# ── Trigger: attach --mode native --iface lo ─────────────────────────────
echo "=== attach --iface lo --mode native --allow ${MAC_GOOD} (expect rc=3)"
set +e
sudo -n "${LOADER_BIN}" attach --iface lo --allow "${MAC_GOOD}" --mode native \
    2> "${stderr_file}"
rc=$?
set -e
echo "loader rc=${rc}"
echo "--- captured stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

fail=0

# (a) rc == 3 (AttachFailed per §4.1 + Q2 Option K).
if [[ "${rc}" -ne 3 ]]; then
    echo "FAIL: expected rc=3 (AttachFailed), got rc=${rc}" >&2
    case "${rc}" in
        0) echo "       rc=0 means lo unexpectedly accepted native XDP — kernel surprise" >&2 ;;
        1) echo "       rc=1 means CLI parser rejected the invocation — --mode arg shape wrong?" >&2 ;;
        2) echo "       rc=2 means BPF load failed before attach — unexpected" >&2 ;;
        4) echo "       rc=4 means alien refusal — but lo was pre-checked clean (regression?)" >&2 ;;
    esac
    fail=1
fi

# (b) stderr non-empty AND mentions 'native' (or 'mode=native').
if [[ ! -s "${stderr_file}" ]]; then
    echo "FAIL: stderr is empty — Q2 Option K stderr-discipline contract broken" >&2
    fail=1
elif ! grep -q -E -- 'native|mode=native' "${stderr_file}"; then
    echo "FAIL: stderr lacks 'native' or 'mode=native' substring" >&2
    fail=1
fi

# (c) lo's XDP slot still empty.
post_id=$(xdp_prog_id lo 2>/dev/null || true)
if [[ -n "${post_id}" ]]; then
    echo "FAIL: lo has XDP attached after our (expected-failure) invocation (prog_id=${post_id})" >&2
    fail=1
fi

# (d) No orphan pin dir at /sys/fs/bpf/xdpfilter/lo.
if sudo -n test -e /sys/fs/bpf/xdpfilter/lo; then
    echo "FAIL: orphan pin dir /sys/fs/bpf/xdpfilter/lo remained after attach refusal" >&2
    sudo -n ls -la /sys/fs/bpf/xdpfilter/lo >&2 || true
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_MODE_NATIVE_UNSUPPORTED"
exit "${fail}"
