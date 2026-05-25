#!/bin/bash
# T_ATTACH_TAG_MISMATCH — design §6.14 (MVP-2 Sec / §5.22 Item 1).
#
# Closes the attacker-recompile vector: a BPF prog whose compile-time
# SEC() function name is `mac_filter_prog` (so the §5.19 name-check
# PASSES) but whose bytecode differs from our build (so the §5.22
# tag-check FAILS) MUST be classified as alien and refused with
#   - exit code 4 (LoaderError::AttachRefusedAlien, per §4.1)
#   - stderr containing the foreign tag as 16-char lowercase hex
#   - stderr containing the literal substring 'tag mismatch'
#   - stderr containing the foreign prog id (legacy §6.9 contract)
#   - foreign prog STILL attached (safety floor)
#   - no orphan pin dir
#
# Symmetric to §6.9 (which exercises name-mismatch); together they prove
# both gates of the §5.22 Q1 identity predicate (mode && name && tag).
#
# Trigger (sequential):
#   1. setup_veth.
#   2. Tag-distinctness preflight (HYBRID per §5.31 EDIT-2 + D-3.4b-22):
#      - real-fixture tag via real loader `xdpmacfilter attach` + bpftool
#        prog show id + `xdpmacfilter detach` (bpftool standalone `prog load`
#        cannot parse the post-§5.31 ARRAY_OF_MAPS inner-template value_size=8
#        because the BTF propagation isn't applied on its no-skeleton path);
#      - alt-fixture tag via bpftool standalone `prog load` (alt fixture body
#        is `return XDP_PASS;` — no inner-VALUE offset-4 load, still works);
#      - compare tags; abort with explicit error if they match (silent
#        fixture-regression catcher; defensive only).
#   3. Pre-attach mac_filter_alt.bpf.o (same `mac_filter_prog` name,
#      different bytecode → different tag) on ${IFACE_A} via xdpgeneric.
#   4. Capture foreign prog id + foreign tag.
#   5. Run our loader (`attach --iface ${IFACE_A} --allow ${MAC_GOOD}`),
#      capture rc + stderr.
#
# Outcome — primary (ALL 6 must hold): see top-of-file list.
#
# Outcome — negation control (triangulation; same script, second pass):
#   Same flow, but pre-attach the REAL mac_filter.bpf.o instead.
#   Loader should detect "ours" (state b per §5.4) and idempotently
#   reload — exit 0, no 'tag mismatch' in stderr, our prog attached,
#   pin dir populated. This control proves the identity gate ACCEPTS
#   our own program identity — not just rejects arbitrary aliens.
#
# Cleanup (trap EXIT/INT/TERM/HUP, idempotent): detach our prog if
# attached, detach foreign xdpgeneric, cleanup_veth, rm temp files.
set -euo pipefail
source "${TEST_DIR}/lib/common.sh"
require_passwordless_sudo

LOADER_BIN=$(find_loader)
ALT_OBJ="${BUILD_DIR}/mac_filter_alt.bpf.o"
REAL_OBJ="${BUILD_DIR}/mac_filter.bpf.o"
stderr_file=$(mktemp /tmp/xdpmf-tagmismatch-stderr.XXXXXX)

# Bpftool scratch pins used by the tag-distinctness preflight (loaded,
# tag-read, then unpinned). Names suffixed with $$ for uniqueness so
# concurrent runs of the suite (defensive — RESOURCE_LOCK serializes
# but cleanup-on-crash idioms benefit from unique names) don't collide.
ALT_PIN_TAG="/sys/fs/bpf/xdpmf_alt_tagprobe_$$"
REAL_PIN_TAG="/sys/fs/bpf/xdpmf_real_tagprobe_$$"

cleanup_tagmismatch() {
    set +e
    # Detach our prog if any negation-control left it attached.
    # §5.25 P1: loader runs inside ${NETNS}; cleanup_veth deletes the
    # whole netns so the detach attempt is racing the teardown — but
    # we still try it for tests that died mid-run before cleanup_veth.
    ${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>/dev/null
    # Detach any foreign xdpgeneric still attached (iface in netns).
    ${NSEXEC} ip link set "${IFACE_A}" xdpgeneric off 2>/dev/null
    # Remove preflight scratch prog pins (may not exist; -f swallows ENOENT).
    # Bpffs is host-global; no NSEXEC needed.
    sudo -n rm -f "${ALT_PIN_TAG}" "${REAL_PIN_TAG}" 2>/dev/null
    # HK-13 §5.30: the preflight `bpftool prog load` (above) was invoked
    # WITHOUT `pinmaps <dir>`, so libbpf auto-pinned any LIBBPF_PIN_BY_NAME
    # maps in mac_filter.bpf.o at /sys/fs/bpf/<map_name>. Remove those
    # orphans before the test exits. We use the pre-test snapshot
    # diff captured at script start (BPFFS_PRE_SNAPSHOT) — anything in
    # /sys/fs/bpf root that was NOT there before the preflight is a
    # candidate for removal. Restricted to depth 1 so we never touch
    # per-iface subdirs (those are cleaned by cleanup_veth → rm -rf
    # ${PIN_DIR}).
    if [[ -n "${BPFFS_PRE_SNAPSHOT:-}" && -f "${BPFFS_PRE_SNAPSHOT}" ]]; then
        local post_snap
        post_snap=$(sudo -n find /sys/fs/bpf -maxdepth 1 -mindepth 1 \
            ! -type d 2>/dev/null | sort)
        local pre_snap
        pre_snap=$(cat "${BPFFS_PRE_SNAPSHOT}")
        local orphan
        # Files present POST-test that were NOT in PRE snapshot.
        while IFS= read -r orphan; do
            [[ -z "${orphan}" ]] && continue
            sudo -n rm -f "${orphan}" 2>/dev/null
        done < <(comm -23 <(printf '%s\n' "${post_snap}") <(printf '%s\n' "${pre_snap}"))
        rm -f "${BPFFS_PRE_SNAPSHOT}"
    fi
    cleanup_veth
    rm -f "${stderr_file}"
    set -e
}
trap cleanup_tagmismatch EXIT INT TERM HUP

# ── Fixture build-artifact sanity ────────────────────────────────────────
[[ -f "${ALT_OBJ}" ]] \
    || { echo "FAIL: tag-mismatch fixture missing at ${ALT_OBJ}" >&2
         echo "       (expected build artifact from add_bpf_object mac_filter_alt)" >&2
         exit 1; }
[[ -f "${REAL_OBJ}" ]] \
    || { echo "FAIL: real BPF object missing at ${REAL_OBJ}" >&2
         echo "       (expected build artifact from add_bpf_object mac_filter)" >&2
         exit 1; }

# ── setup_veth FIRST (real-fixture preflight needs a live iface) ────────
# Per §5.31 EDIT-2 + D-3.4b-22 hybrid preflight: the real-fixture tag is
# read via the real loader's `attach` path (since standalone bpftool
# `prog load` mis-parses the new ARRAY_OF_MAPS inner-template value_size=8
# post-§5.31 PI-13-3.4b — verifier rejects with vs=1). Real loader needs
# an iface to attach to, so setup_veth must run BEFORE the preflight (was
# AFTER pre-§5.31 — ordering change is purely scope-internal to the
# preflight rewrite; PRIMARY scenario sequence below is byte-equivalent).
setup_veth

# ── Defensive tag-distinctness preflight (HYBRID per §5.31 EDIT-2) ──────
# Per design §6.14: paranoia check that the two .bpf.o files actually
# produce distinct kernel-reported tags. clang's instruction selection
# on `return XDP_PASS;` vs the real allowlist-lookup body always differs
# in practice, but a silent fixture regression (e.g. someone copy-pastes
# the real body into the alt fixture) MUST surface loudly here, not as
# a confusing exit-0-instead-of-4 in the primary scenario.
#
# Hybrid post-§5.31 (D-3.4b-22, Option B): the REAL fixture's tag comes
# from the actual loader path (bpftool standalone can't parse the new
# inner-template value_size=8 on ARRAY_OF_MAPS lookups — see verifier
# trace in Phase B test-run.log lines 8-80 of the pre-fix run). The ALT
# fixture's body is `return XDP_PASS;` with NO inner-VALUE loads, so
# the standalone `bpftool prog load` path STILL works for it (verified:
# `vs=1`-rejection only fires on programs that dereference offset 4 of
# the inner-allowlist-value, which alt fixture doesn't do). Belt + suspenders.
#
# HK-13 §5.30: capture a snapshot of /sys/fs/bpf/ top-level entries
# BEFORE the preflight loads — the cleanup trap will diff against this
# to remove any orphan map pins that bpftool's libbpf auto-creates from
# LIBBPF_PIN_BY_NAME maps. The alt fixture has NO maps (verified at
# /tests/fixtures/mac_filter_alt.bpf.c), so this snapshot is defensive
# / no-op for the alt-only bpftool path; the real-fixture path uses the
# real loader which pins under PIN_DIR (cleaned by cleanup_veth).
BPFFS_PRE_SNAPSHOT=$(mktemp /tmp/xdpmf-tagmismatch-bpffs-pre.XXXXXX)
sudo -n find /sys/fs/bpf -maxdepth 1 -mindepth 1 ! -type d 2>/dev/null \
    | sort > "${BPFFS_PRE_SNAPSHOT}"

echo "=== preflight: real-fixture tag via real loader (§5.31 EDIT-2 hybrid)"
# Real-fixture: xdpmacfilter attach → read prog id → bpftool prog show id → detach.
set +e
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" >/dev/null 2>&1
attach_rc=$?
set -e
if [[ "${attach_rc}" -ne 0 ]]; then
    echo "FAIL: preflight real-fixture attach failed (rc=${attach_rc})" >&2
    echo "      cannot proceed — real-fixture tag cannot be computed via loader path" >&2
    exit 1
fi
real_prog_id=$(xdp_prog_id "${IFACE_A}")
if [[ -z "${real_prog_id}" || "${real_prog_id}" == "0" ]]; then
    echo "FAIL: preflight real-fixture attach left no XDP prog id on ${IFACE_A}" >&2
    exit 1
fi
real_tag_pre=$(sudo -n bpftool -j prog show id "${real_prog_id}" | jq -r '.tag')
# Detach IMMEDIATELY — leave veth in clean state for PRIMARY scenario.
${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" >/dev/null 2>&1 || true
# Defensive: verify XDP is detached before continuing.
if [[ -n "$(xdp_prog_id "${IFACE_A}")" ]]; then
    echo "FAIL: preflight real-fixture detach did not clean XDP from ${IFACE_A}" >&2
    exit 1
fi

echo "=== preflight: alt-fixture tag via bpftool standalone (trivial body — still works)"
sudo -n rm -f "${ALT_PIN_TAG}" 2>/dev/null || true
sudo -n bpftool prog load "${ALT_OBJ}" "${ALT_PIN_TAG}" type xdp \
    || { echo "FAIL: preflight bpftool prog load (${ALT_OBJ}) failed" >&2; exit 1; }
alt_tag_pre=$(sudo -n bpftool -j prog show pinned "${ALT_PIN_TAG}" | jq -r '.tag')
sudo -n rm -f "${ALT_PIN_TAG}"

echo "   alt  tag = ${alt_tag_pre}"
echo "   real tag = ${real_tag_pre}"
if [[ -z "${alt_tag_pre}" || -z "${real_tag_pre}" ]]; then
    echo "FAIL: bpftool did not report tag for one of the fixtures" >&2
    exit 1
fi
if [[ "${alt_tag_pre}" == "${real_tag_pre}" ]]; then
    echo "FAIL: fixture regression — alt and real .bpf.o have IDENTICAL tags" >&2
    echo "      (the alt fixture body MUST differ from the real body;" >&2
    echo "       this fixture as built cannot exercise the tag-axis check)" >&2
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────
# PRIMARY SCENARIO — pre-attach alt fixture (same name, different tag).
# Expected: loader refuses with exit 4 + tag-mismatch stderr discipline.
# ─────────────────────────────────────────────────────────────────────────
fail=0

echo "=== PRIMARY: pre-attach mac_filter_alt.bpf.o on ${IFACE_A} via xdpgeneric"
${NSEXEC} ip link set "${IFACE_A}" xdpgeneric obj "${ALT_OBJ}" sec xdp
sleep 0.2

foreign_id=$(xdp_prog_id "${IFACE_A}")
if [[ -z "${foreign_id}" || "${foreign_id}" == "0" ]]; then
    echo "FAIL: foreign-attach step left no XDP prog id on ${IFACE_A}" >&2
    echo "      (the fixture failed before our loader was invoked — not our bug)" >&2
    ${NSEXEC} ip -j link show "${IFACE_A}" >&2
    exit 1
fi
foreign_tag_raw=$(sudo -n bpftool -j prog show id "${foreign_id}" | jq -r '.tag')
foreign_tag=$(printf '%s' "${foreign_tag_raw}" | tr 'A-F' 'a-f')
echo "foreign prog id  = ${foreign_id}"
echo "foreign tag      = ${foreign_tag}  (raw=${foreign_tag_raw})"
if [[ -z "${foreign_tag}" ]] || ! [[ "${foreign_tag}" =~ ^[0-9a-f]{16}$ ]]; then
    echo "FAIL: bpftool did not yield a 16-char hex tag for foreign prog" >&2
    exit 1
fi

echo "=== invoke our loader (expect exit 4 — AttachRefusedAlien, tag mismatch)"
set +e
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"
rc=$?
set -e
echo "loader rc=${rc}"
echo "--- captured stderr (primary) ---"
cat "${stderr_file}" >&2 || true
echo "--- end stderr ---"

# (P1) Exit code MUST be 4. exit 8 here is wrong (path is fine — it's
# the prog that's alien); exit 0 means the §5.22 tag-check did NOT land
# (loader accepted a bytecode-different alien as ours — attacker-recompile
# vector is open).
if [[ "${rc}" != 4 ]]; then
    echo "FAIL[P1]: expected rc=4 (AttachRefusedAlien tag-mismatch), got rc=${rc}" >&2
    case "${rc}" in
        0) echo "          rc=0 means §5.22 tag-check did NOT land (attacker-recompile vector open)" >&2 ;;
        8) echo "          rc=8 is PathRefused — wrong axis; the program is alien, the path is fine" >&2 ;;
    esac
    fail=1
fi

# (P2) Stderr MUST contain the foreign tag as 16-char lowercase hex.
if ! grep -qE -- "${foreign_tag}" "${stderr_file}"; then
    echo "FAIL[P2]: stderr does not contain foreign tag '${foreign_tag}' (16-char lowercase hex)" >&2
    fail=1
fi

# (P3) Stderr MUST contain literal 'tag mismatch' (per §5.22 Item 1).
if ! grep -q -F -- 'tag mismatch' "${stderr_file}"; then
    echo "FAIL[P3]: stderr does not contain literal 'tag mismatch'" >&2
    fail=1
fi

# (P4) Stderr MUST contain the foreign prog id (legacy §6.9 contract).
if ! grep -q -F -- "${foreign_id}" "${stderr_file}"; then
    echo "FAIL[P4]: stderr does not contain foreign prog id ${foreign_id}" >&2
    fail=1
fi

# (P5) Foreign program MUST STILL be attached — safety floor.
now_id=$(xdp_prog_id "${IFACE_A}")
if [[ "${now_id}" != "${foreign_id}" ]]; then
    echo "FAIL[P5]: foreign XDP clobbered (was ${foreign_id}, now '${now_id}')" >&2
    fail=1
fi

# (P6) No orphan pin dir. Use sudo so /sys/fs/bpf mode 1700 doesn't false-negative.
if sudo -n test -e "${PIN_DIR}"; then
    echo "FAIL[P6]: orphan pin dir ${PIN_DIR} remained after refusal" >&2
    sudo -n ls -la "${PIN_DIR}" >&2 || true
    fail=1
fi

# ─────────────────────────────────────────────────────────────────────────
# NEGATION CONTROL — loader-twice idempotent-reload pattern.
# (Reshaped per design-phase-b.md Section C, 2026-05-23.)
#
# Why not "pre-attach REAL mac_filter.bpf.o via ip link" as originally
# specified in §6.14: two independent problems make that path unable to
# reach §5.4 state (b) — (1) `ip link set xdpgeneric obj` does NOT create
# our pin_dir (state-b condition 2 fails regardless of identity), and
# (2) the kernel-computed bpf_prog_info.tag for the same .bpf.o differs
# between an ip-link load and our libbpf-skeleton load (libbpf-side
# preprocessing — CO-RE relocs, subprog inlining, etc. — happens before
# BPF_PROG_LOAD and is hashed into the tag). Mirrors §6.6
# T_IDEMPOTENT_RELOAD: both loader invocations go through OUR libbpf in
# OUR process → tag stability → state (b) reachable.
#
# Sequence:
#   1. Verify primary cleanup left the iface clean.
#   2. First loader attach (state a, fresh) → rc=0, capture our_id_1.
#   3. Second loader attach (state b, idempotent reload, load-bearing):
#      → rc=0, no 'tag mismatch' stderr, no 'error:' stderr,
#        xdp_prog_id non-empty, our_id_2 != our_id_1
#        (the id-change assertion is the trick that proves state-b was
#         actually traversed — if the loader had no-op'd the second
#         attach, ids would be identical).
#   4. Loader detach (validates the symmetric detach() identity gate
#      per design-phase-b.md Section A) → rc=0, xdp empty, pin dir gone.
#
# In-file pairing of "primary: reject on tag-mismatch" + "control:
# accept on tag-match" gives strongest LOCAL triangulation of the
# §5.22 identity-gate contract for a reviewer reading §6.14 alone.
# ─────────────────────────────────────────────────────────────────────────
echo
echo "=== NEGATION CONTROL (loader-twice idempotent-reload pattern)"

# Step 1: verify primary-scenario cleanup left the iface clean. If not
# clean, primary cleanup is broken — fail loud with explicit error, do
# NOT proceed (that's a separate bug, not a negation-control failure).
${NSEXEC} ip link set "${IFACE_A}" xdpgeneric off 2>/dev/null || true
sleep 0.2
sudo -n rm -rf "${PIN_DIR}" 2>/dev/null || true

precheck_id=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
if [[ -n "${precheck_id}" ]]; then
    echo "FAIL[N0]: negation precondition: ${IFACE_A} still has XDP attached" \
         "(prog_id=${precheck_id}) after primary cleanup" >&2
    fail=1
fi
if sudo -n test -e "${PIN_DIR}"; then
    echo "FAIL[N0]: negation precondition: ${PIN_DIR} still exists after primary cleanup" >&2
    fail=1
fi

# Step 2: first loader attach — state (a) fresh attach.
stderr1_file=$(mktemp /tmp/xdpmf-tagmismatch-neg1-stderr.XXXXXX)
stderr2_file=$(mktemp /tmp/xdpmf-tagmismatch-neg2-stderr.XXXXXX)
stderr_d_file=$(mktemp /tmp/xdpmf-tagmismatch-negd-stderr.XXXXXX)
# Extend cleanup to also wipe these (defensive — main trap already wipes
# stderr_file; trap is fixed-string so we rm extras here on script exit).
trap 'cleanup_tagmismatch; rm -f "${stderr1_file}" "${stderr2_file}" "${stderr_d_file}"' EXIT INT TERM HUP

echo "=== first loader attach (expect rc=0 — state (a) fresh attach)"
set +e
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr1_file}"
rc1=$?
set -e
echo "loader rc1=${rc1}"
echo "--- captured stderr (first attach) ---"
cat "${stderr1_file}" >&2 || true
echo "--- end stderr ---"

if [[ "${rc1}" -ne 0 ]]; then
    echo "FAIL[N1a]: first attach: expected rc=0 (fresh attach), got ${rc1}" >&2
    fail=1
fi
our_id_1=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
if [[ -z "${our_id_1}" ]]; then
    echo "FAIL[N1b]: first attach: no XDP attached after rc=${rc1}" >&2
    fail=1
fi
if ! sudo -n test -e "${PIN_DIR}/allowlist"; then
    echo "FAIL[N1c]: first attach: expected ${PIN_DIR}/allowlist" >&2
    fail=1
fi
if ! sudo -n test -e "${PIN_DIR}/stats"; then
    echo "FAIL[N1c]: first attach: expected ${PIN_DIR}/stats" >&2
    fail=1
fi
echo "our_id_1 = ${our_id_1}"

# Step 3: second loader attach — the load-bearing negation-control
# assertion. State (b) idempotent reload: detach-ours + bpffs_remove_iface
# + fresh attach. ALL three §5.4 state-(b) conditions hold because both
# loads go through OUR libbpf in OUR process: prog attached SKB, pin_dir
# present (from step 2), identity verifies (same name, same tag).
echo "=== second loader attach (expect rc=0 — state (b) idempotent reload — LOAD-BEARING)"
set +e
${NSEXEC} "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr2_file}"
rc2=$?
set -e
echo "loader rc2=${rc2}"
echo "--- captured stderr (second attach) ---"
cat "${stderr2_file}" >&2 || true
echo "--- end stderr ---"

# (N2a) Exit code 0 — state (b) idempotent reload succeeded.
if [[ "${rc2}" -ne 0 ]]; then
    echo "FAIL[N2a]: second attach: expected rc=0 (state-b reload), got ${rc2}" >&2
    case "${rc2}" in
        4) echo "          rc=4 means identity gate REJECTED our OWN program — tag/name check bug" >&2 ;;
    esac
    fail=1
fi

# (N2b) Stderr MUST NOT contain 'tag mismatch' (tags equal, both libbpf-side
# loads in our process).
if grep -q -F -- 'tag mismatch' "${stderr2_file}"; then
    echo "FAIL[N2b]: second attach: stderr unexpectedly contains 'tag mismatch'" >&2
    fail=1
fi

# (N2c) Stderr MUST NOT contain 'error:' prefix.
if grep -q -F -- 'error:' "${stderr2_file}"; then
    echo "FAIL[N2c]: second attach: stderr unexpectedly contains 'error:'" >&2
    fail=1
fi

# (N2d) Some XDP prog attached after the reload.
our_id_2=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
if [[ -z "${our_id_2}" ]]; then
    echo "FAIL[N2d]: second attach: no XDP attached after rc=${rc2}" >&2
    fail=1
fi

# (N2e) The trick — prog id MUST have changed. State (b) detaches the
# old kernel object and attaches a fresh skeleton load → kernel assigns
# a new prog id. If our_id_2 == our_id_1, the loader skipped the
# re-attach (no-op'd) and we didn't actually exercise the gate.
if [[ -n "${our_id_1}" && -n "${our_id_2}" && "${our_id_2}" == "${our_id_1}" ]]; then
    echo "FAIL[N2e]: second attach: prog id UNCHANGED (${our_id_2}) — gate was skipped, state-b not traversed" >&2
    fail=1
fi
echo "our_id_2 = ${our_id_2}  (different from our_id_1 = ${our_id_1} as expected)"

# Step 4: loader detach. Per design-phase-b.md Section A, detach() also
# load-captures self_tag and identity-checks symmetrically with attach();
# this exercises the detach() identity gate's acceptance path.
echo "=== loader detach (expect rc=0 — clean teardown, validates detach() identity gate)"
set +e
${NSEXEC} "${LOADER_BIN}" detach --iface "${IFACE_A}" 2> "${stderr_d_file}"
rc_d=$?
set -e
echo "loader detach rc_d=${rc_d}"
echo "--- captured stderr (detach) ---"
cat "${stderr_d_file}" >&2 || true
echo "--- end stderr ---"

if [[ "${rc_d}" -ne 0 ]]; then
    echo "FAIL[N3a]: detach: expected rc=0, got ${rc_d}" >&2
    case "${rc_d}" in
        5) echo "          rc=5 (DetachFailed) — detach() identity gate may have rejected our own program" >&2 ;;
    esac
    fail=1
fi
post_id=$(xdp_prog_id "${IFACE_A}" 2>/dev/null || true)
if [[ -n "${post_id}" ]]; then
    echo "FAIL[N3b]: detach: XDP still attached (prog_id=${post_id})" >&2
    fail=1
fi
if sudo -n test -e "${PIN_DIR}"; then
    echo "FAIL[N3c]: detach: ${PIN_DIR} remained" >&2
    fail=1
fi

[[ "${fail}" == 0 ]] && echo "PASS: T_ATTACH_TAG_MISMATCH"
exit "${fail}"
