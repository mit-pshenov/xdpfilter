#!/bin/bash
# T_DETACH_NOTHING — design §6.13 (MVP-1.1C / §5.21 D4 + §5.4 amendment).
#
# Locks the contract that `detach --iface <clean iface>` is fully idempotent
# — no prog AND no pin_dir is the no-op success path (exit 0), not an error.
#
# Uses 'lo' instead of a veth fixture (per design §6.13 — no fixture cost,
# no veth needed; we make NO state changes on lo, just probe + idempotent
# detach).  Requires CAP_BPF/CAP_NET_ADMIN for bpf_xdp_query — skip 77 if
# no passwordless sudo.
#
# Outcome (ALL must hold):
#   - rc == 0  (per §5.21 D4 amendment to §5.4 state (a))
#   - stderr does NOT contain literal substring 'error:' (matches the
#     'error: ' prefix used by main.cpp for thrown errors)
#   - post-state clean: xdp_prog_id lo empty AND /sys/fs/bpf/xdpfilter/lo
#     does not exist
#
# Depends on impl: src/loader/loader.cpp:401 throw drop (D4 impl scope).
# If that throw is still in place, this test surfaces it as a real bug
# (rc != 0 + stderr 'error:').
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
stdout_file=$(mktemp /tmp/xdpmf-detachnothing-stdout.XXXXXX)
stderr_file=$(mktemp /tmp/xdpmf-detachnothing-stderr.XXXXXX)
trap 'rm -f "${stdout_file}" "${stderr_file}"' EXIT

# ── Preconditions: fixture must be clean BEFORE we call detach ───────────
# If lo somehow has XDP attached or our pin dir, abort early — this is a
# dirty fixture, not a loader bug.  Use 'lo' per §6.13 (always exists, we
# do not modify it).
pre_id=$(xdp_prog_id lo 2>/dev/null || true)
if [[ -n "${pre_id}" ]]; then
    echo "ERROR: lo has pre-existing XDP attached (prog_id=${pre_id})" >&2
    echo "       this fixture precondition is dirty; not the loader's fault." >&2
    exit 1
fi
if sudo -n test -e /sys/fs/bpf/xdpfilter/lo; then
    echo "ERROR: /sys/fs/bpf/xdpfilter/lo already exists" >&2
    echo "       this fixture precondition is dirty; cleanup expected." >&2
    exit 1
fi

# ── Trigger ──────────────────────────────────────────────────────────────
echo "=== detach --iface lo (expect rc=0, no-op cleanup per §5.21 D4)"
set +e
sudo -n "${LOADER_BIN}" detach --iface lo >"${stdout_file}" 2>"${stderr_file}"
rc=$?
set -e
echo "rc=${rc}"
echo "--- stdout ---"
cat "${stdout_file}"
echo "--- end stdout ---"
echo "--- stderr ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

fail=0

# (a) Exit code 0 — the §5.21 D4 idempotency guarantee.
if [[ "${rc}" -ne 0 ]]; then
    echo "FAIL: expected rc=0 (idempotent no-op), got ${rc}" >&2
    if [[ "${rc}" == "5" ]]; then
        echo "      rc=5 means loader.cpp:401 throw drop (D4) did NOT land" >&2
    fi
    fail=1
fi

# (b) No 'error:' prefix in stderr (matches main.cpp's error: prefix per
# §6.13).  Informational lines without that prefix are fine.
if grep -q -F -- 'error:' "${stderr_file}"; then
    echo "FAIL: stderr contains 'error:' prefix (per §6.13 contract)" >&2
    fail=1
fi

# (c) Post-state: lo still clean.
post_id=$(xdp_prog_id lo 2>/dev/null || true)
if [[ -n "${post_id}" ]]; then
    echo "FAIL: detach somehow attached/left XDP on lo (prog_id=${post_id})" >&2
    fail=1
fi
if sudo -n test -e /sys/fs/bpf/xdpfilter/lo; then
    echo "FAIL: /sys/fs/bpf/xdpfilter/lo exists after no-op detach" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_DETACH_NOTHING"
exit "${fail}"
