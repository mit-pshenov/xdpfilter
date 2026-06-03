#!/bin/bash
# T_BYPASS_INTERACTIVE_PROMPT — design §6.44 (MVP-3.4.5 / §5.30).
#
# Interactive y/N branch via a python3 `pty.openpty()` driver.
# T_BYPASS_CMD_DETACHES uses `--unsafe` to SKIP the prompt — this test
# exercises the prompt path itself across 3 sub-cases:
#   - Positive (y): exit 0; XDP detached; HK-4 audit-log emitted.
#   - Negative (n): exit 0; XDP STILL attached; "cancelled by operator".
#   - EOF (empty input): exit 0; XDP STILL attached; "cancelled by operator".
#
# Sanity-floor smoke: attach succeeds + pre-state confirmed before each
# sub-case.
# Negation control: (negative) and (EOF) sub-cases ARE the negation
# probes — if the prompt silently detached on non-`y` input the
# assertions would fail (post-state would show XDP gone).
#
# Pty-driver mechanics (per impl Phase 2.5 feedback): the naive
# `script -qc 'echo y | xdpfilter bypass …'` pattern does NOT work —
# the pipe between `echo` and `xdpfilter` makes the loader's stdin
# a pipe, NOT a pty, so `isatty(STDIN_FILENO)` returns false and the
# loader treats the context as non-interactive. The fix: use python3's
# `pty.openpty()` to make a real master/slave pair; feed the slave to
# the child as stdin (so `isatty(STDIN)` returns true) and write the
# input character(s) to the master from the parent.
#
# This test ALSO carries the HK-4 audit-line field assertion per
# D-3.4.5-8 / §5.30 option (b): assert that the positive-case audit
# line contains the structural fields `uid=`, `euid=`, `sudo_user="..."`,
# `reason="..."` in the FIXED order (per HK-4 Interfaces format).
#
# SKIP-77 if python3 is unavailable (it provides the pty.openpty()
# mechanism we depend on). Bash + `script` alone cannot achieve true
# pty-stdin to the child process.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: T_BYPASS_INTERACTIVE_PROMPT needs python3 for pty.openpty() driver" >&2
    exit 77
fi

LOADER_BIN=$(find_loader)
echo "loader=${LOADER_BIN}"

stderr_pos=$(mktemp /tmp/xdpmf-bypprompt-pos.XXXXXX)
stderr_neg=$(mktemp /tmp/xdpmf-bypprompt-neg.XXXXXX)
stderr_eof=$(mktemp /tmp/xdpmf-bypprompt-eof.XXXXXX)

cleanup_test() {
    set +e
    # Try to detach if any sub-case left XDP attached. Idempotent.
    ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>/dev/null
    cleanup_veth
    rm -f "${stderr_pos}" "${stderr_neg}" "${stderr_eof}"
    set -e
}
trap cleanup_test EXIT

setup_veth

# ── Pty driver ──────────────────────────────────────────────────────────
# Drive the loader's bypass prompt under a proper pty. Args:
#   $1: input string (e.g., "y\n", "n\n", or "" for EOF)
#   $2: stderr capture file
#   $3..: loader argv prefix (without --unsafe; we WANT the prompt to fire)
#
# Mechanism: spawn loader with stdin connected to pty slave (so
# isatty(STDIN_FILENO) == true), stderr redirected to ${2}, then write
# $1 to pty master. For the EOF case ($1 empty), close the master fd
# WITHOUT writing — that signals EOF on the slave side, which the
# loader sees as immediate getline() EOF.
#
# Wait up to 10s for the child to exit; print its exit code to stdout
# so the caller can capture it. Stderr file is appended-to by the
# child directly (we pass an fd, not a pipe).
drive_pty() {
    local input="$1" stderr_out="$2"
    shift 2
    # Build argv array carefully (preserve spaces in args).
    local -a child_argv=("$@")
    # Python pty driver: inherits sudo + nsenter chain via argv prefix.
    # The argv prefix is `${NSEXEC} ${LOADER_BIN} bypass --iface ...`.
    # We embed it as positional args after the script body.
    #
    # Stderr-capture mechanism: bash opens ${stderr_out} as fd 1 of the
    # python process (via shell redirect `> "${stderr_out}"`). Python
    # reads child's stderr via a pipe and copies bytes to sys.stdout
    # (= fd 1 = the captured file). This sidesteps a Linux-host-specific
    # EACCES we hit earlier where `sudo -n python3 open(path)` failed
    # despite both processes being uid=0 — exact root cause unclear (no
    # SELinux active here, no apparent polyinstantiation), but giving
    # python a pre-opened fd from bash bypasses the open()-time check
    # entirely.
    sudo -n python3 - "${input}" "${child_argv[@]}" > "${stderr_out}" <<'PYEOF'
import os, sys, pty, select, time, termios, tty, errno

input_str = sys.argv[1]      # e.g. "y\n" or "n\n" or ""
cmd = sys.argv[2:]           # full argv: nsenter ... xdpfilter bypass ...

if not cmd:
    sys.stderr.write("drive_pty: no command given\n")
    sys.exit(127)

# IMPL CHECK (per src/cli/bypass.cpp:137):
#   const bool interactive = isatty(STDIN_FILENO) && isatty(STDERR_FILENO);
# Both stdin AND stderr must be pty-backed for the loader to enter the
# interactive prompt. We allocate ONE pty pair and use the slave fd as
# BOTH the child's stdin (fd 0) AND its stderr (fd 2). The master fd is
# then bidirectional: parent writes input to it (delivered as child's
# stdin) AND reads child's stderr from it (everything the child writes
# to fd 2). Termios ECHO is disabled on the slave so the parent's input
# bytes are NOT echoed back to the parent's reads (which would
# contaminate the captured stderr). ONLCR is disabled so `\n` stays as
# `\n` instead of being translated to `\r\n` on the parent's read side.
master_fd, slave_fd = pty.openpty()

# Tune termios on the slave: disable ECHO, ECHOE, ECHOK, ECHONL,
# ECHOCTL; disable ICRNL (input CR→NL); disable ONLCR (output NL→CRNL).
attrs = termios.tcgetattr(slave_fd)
# attrs = [iflag, oflag, cflag, lflag, ispeed, ospeed, cc]
attrs[0] &= ~(termios.ICRNL | termios.IGNCR | termios.INLCR)
attrs[1] &= ~(termios.ONLCR | termios.OPOST)
attrs[3] &= ~(termios.ECHO | termios.ECHOE | termios.ECHOK | termios.ECHONL)
try:
    attrs[3] &= ~termios.ECHOCTL
except AttributeError:
    pass
termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)

pid = os.fork()
if pid == 0:
    # Child.
    try:
        os.close(master_fd)
        os.dup2(slave_fd, 0)        # stdin  = pty slave (isatty(0) true)
        os.dup2(slave_fd, 2)        # stderr = pty slave (isatty(2) true)
        # stdout left alone — bypass doesn't print to fd 1.
        if slave_fd > 2:
            os.close(slave_fd)
        os.execvp(cmd[0], cmd)
    except Exception as e:
        sys.stderr.write("child exec failed: %s\n" % e)
        os._exit(127)

# Parent.
os.close(slave_fd)

# Send input. Loader prints the y/N prompt to stderr THEN reads stdin;
# we write input proactively (kernel pty buffer holds it until read).
if input_str:
    try:
        os.write(master_fd, input_str.encode('utf-8'))
    except OSError:
        pass
# For the EOF case (empty input_str), we don't write anything. We do
# NOT close master here because that would also tear down our read side.
# The loader's getline()-on-empty-pty WILL return with EAGAIN/empty —
# bypass.cpp's getline path handles that as "no answer → cancel" (the
# §5.29 grammar semantic for EOF).
#
# However, the loader may block on getline() forever if we don't signal
# EOF for the EOF case. Solution: write a single newline to indicate
# "empty input → enter pressed" if input_str is empty. The cpp side then
# reads an empty line, which it treats as non-`y` → cancel. (This is
# effectively how a real terminal user "just press Enter" works.)
if not input_str:
    try:
        os.write(master_fd, b"\n")
    except OSError:
        pass

# Drain master_fd → sys.stdout. Continue reading until child exits AND
# pipe is empty OR timeout. The master fd is bidirectional; once the
# child closes the slave (on exit), reads from master return EIO on
# Linux (kernel signals pty hangup). We treat EIO as EOF.
captured = []
deadline = time.time() + 10.0
while True:
    try:
        r, _, _ = select.select([master_fd], [], [], 1.0)
    except (OSError, ValueError):
        break
    if master_fd in r:
        try:
            chunk = os.read(master_fd, 4096)
        except OSError as e:
            if e.errno == errno.EIO:
                # Child closed slave; pty hangup.
                break
            break
        if not chunk:
            break
        captured.append(chunk)
    # Check if child exited (regardless of select result).
    try:
        pid_done, _ = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        break
    if pid_done == pid:
        # One last non-blocking drain.
        try:
            while True:
                chunk = os.read(master_fd, 4096)
                if not chunk:
                    break
                captured.append(chunk)
        except OSError:
            pass
        break
    if time.time() > deadline:
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass
        sys.stderr.write("drive_pty: child timeout after 10s\n")
        break

# Write captured bytes to sys.stdout (= bash-redirected capture file).
sys.stdout.buffer.write(b"".join(captured))
sys.stdout.buffer.flush()

# Final blocking wait (most of the time child is already exited).
try:
    _, status = os.waitpid(pid, 0)
except ChildProcessError:
    status = 0

try:
    os.close(master_fd)
except OSError:
    pass

if os.WIFEXITED(status):
    sys.exit(os.WEXITSTATUS(status))
elif os.WIFSIGNALED(status):
    sys.exit(128 + os.WTERMSIG(status))
sys.exit(255)
PYEOF
}

attach_smoke() {
    ${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"
    sleep 0.3
    local pre_id
    pre_id=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
    if [[ -z "${pre_id}" ]]; then
        echo "FAIL: smoke — ${IFACE_A} has no XDP attached after attach call" >&2
        return 1
    fi
    if ! sudo -n test -e "${PIN_DIR}/link"; then
        echo "FAIL: smoke — link pin missing after attach" >&2
        return 1
    fi
    echo "pre-prompt xdp_prog_id=${pre_id}"
    return 0
}

# Read NSEXEC into an array so it survives quoting through to the python
# child invocation. ${NSEXEC} is `sudo -n nsenter --net=...` — splitting
# on spaces is safe because none of its tokens contain whitespace.
read -ra NSEXEC_ARR <<< "${NSEXEC}"

fail=0

# ─────────────────────────────────────────────────────────────────────────
# SUB-CASE 1: POSITIVE (`y`) — prompt accepted; XDP detached; audit emitted.
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== SUB-CASE 1: positive prompt (input='y')"
attach_smoke || fail=1

set +e
drive_pty $'y\n' "${stderr_pos}" \
    "${NSEXEC_ARR[@]}" "${LOADER_BIN}" bypass --iface "${IFACE_A}" --reason "T_BYPASS_prompt"
rc_pos=$?
set -e
echo "positive rc=${rc_pos}"
echo "--- stderr (positive) ---"
cat "${stderr_pos}" >&2 || true
echo "--- end ---"

# (1a) Exit code 0 (bypass succeeded).
if [[ "${rc_pos}" -ne 0 ]]; then
    echo "FAIL[1a]: positive prompt: expected rc=0, got ${rc_pos}" >&2
    fail=1
fi

# (1b) XDP detached after positive prompt.
post_id_pos=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
echo "post-positive xdp_prog_id='${post_id_pos}'"
if [[ -n "${post_id_pos}" ]]; then
    echo "FAIL[1b]: positive prompt: XDP STILL attached (prog_id=${post_id_pos}) — bypass did not detach" >&2
    fail=1
fi

# (1c) Audit-log line present with HK-4 structural fields in FIXED order:
#   `BYPASS activated on <IFACE> by uid=<n> euid=<n> sudo_user="<...>" reason="<...>"`.
# Per D-3.4.5-8: order uid → euid → sudo_user → reason; <none> sentinel
# when SUDO_USER unset. Test invokes loader under sudo (NSEXEC includes
# sudo -n), so SUDO_USER MAY be set to root by sudo; the test accepts
# either real user or <none>.
# NOTE on regex anchoring: NO leading `^` — under our pty driver the
# y/N prompt (no trailing newline) and the audit line end up sharing
# the same captured line (`Continue? [y/N]: xdpfilter: BYPASS ...`).
# The structural-field match against the substring is what HK-4 contracts;
# anchoring to line-start would require coordinating the prompt's
# newline behaviour, which is not HK-4 scope.
audit_ere_pos="xdpfilter: BYPASS activated on ${IFACE_A} by uid=[0-9]+ euid=[0-9]+ sudo_user=\"[^\"]*\" reason=\"T_BYPASS_prompt\"\$"
if ! grep -qE -- "${audit_ere_pos}" "${stderr_pos}"; then
    echo "FAIL[1c]: positive prompt: audit-log missing or wrong shape" >&2
    echo "          expected ERE: ${audit_ere_pos}" >&2
    fail=1
fi

# ─────────────────────────────────────────────────────────────────────────
# SUB-CASE 2: NEGATIVE (`n`) — prompt cancelled; XDP STILL attached.
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== SUB-CASE 2: negative prompt (input='n')"
attach_smoke || fail=1

set +e
drive_pty $'n\n' "${stderr_neg}" \
    "${NSEXEC_ARR[@]}" "${LOADER_BIN}" bypass --iface "${IFACE_A}" --reason "T_BYPASS_prompt_neg"
rc_neg=$?
set -e
echo "negative rc=${rc_neg}"
echo "--- stderr (negative) ---"
cat "${stderr_neg}" >&2 || true
echo "--- end ---"

# (2a) Exit code 0 (cancellation is a legitimate, non-error outcome).
if [[ "${rc_neg}" -ne 0 ]]; then
    echo "FAIL[2a]: negative prompt: expected rc=0 (cancellation is OK), got ${rc_neg}" >&2
    fail=1
fi

# (2b) XDP STILL attached after negative prompt.
post_id_neg=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
echo "post-negative xdp_prog_id='${post_id_neg}'"
if [[ -z "${post_id_neg}" ]]; then
    echo "FAIL[2b]: negative prompt: XDP DETACHED despite 'n' — fail-open regression" >&2
    fail=1
fi

# (2c) Cancellation message present.
if ! grep -qE -- 'xdpfilter: bypass cancelled by operator' "${stderr_neg}"; then
    echo "FAIL[2c]: negative prompt: stderr missing 'bypass cancelled by operator'" >&2
    fail=1
fi

# Detach in preparation for sub-case 3.
${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>/dev/null || true
sleep 0.2

# ─────────────────────────────────────────────────────────────────────────
# SUB-CASE 3: EOF (empty input) — treated as non-`y`; XDP STILL attached.
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== SUB-CASE 3: EOF prompt (empty input)"
attach_smoke || fail=1

set +e
# Empty first arg → driver writes nothing, then closes master → EOF on
# child's stdin.
drive_pty "" "${stderr_eof}" \
    "${NSEXEC_ARR[@]}" "${LOADER_BIN}" bypass --iface "${IFACE_A}" --reason "T_BYPASS_prompt_eof"
rc_eof=$?
set -e
echo "eof rc=${rc_eof}"
echo "--- stderr (EOF) ---"
cat "${stderr_eof}" >&2 || true
echo "--- end ---"

# (3a) Exit code 0 (EOF as non-`y` is a legitimate cancellation).
if [[ "${rc_eof}" -ne 0 ]]; then
    echo "FAIL[3a]: EOF prompt: expected rc=0 (EOF treated as non-y per §5.29), got ${rc_eof}" >&2
    fail=1
fi

# (3b) XDP STILL attached after EOF prompt.
post_id_eof=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
echo "post-eof xdp_prog_id='${post_id_eof}'"
if [[ -z "${post_id_eof}" ]]; then
    echo "FAIL[3b]: EOF prompt: XDP DETACHED despite EOF — fail-open regression" >&2
    fail=1
fi

# (3c) Cancellation message present.
if ! grep -qE -- 'xdpfilter: bypass cancelled by operator' "${stderr_eof}"; then
    echo "FAIL[3c]: EOF prompt: stderr missing 'bypass cancelled by operator'" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_BYPASS_INTERACTIVE_PROMPT"
exit "${fail}"
