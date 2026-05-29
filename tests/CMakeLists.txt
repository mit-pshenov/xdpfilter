# tests/CMakeLists.txt — populated by mint-tester per design §6.
#
# Tests are shell scripts driving a veth fixture; serialized via
# RESOURCE_LOCK xdp_fixture (they all touch fixed veth_a/veth_b names).
# Top-level CMakeLists.txt is expected to have called enable_testing()
# already (per design §2 FileList); we do NOT call it here to avoid
# double-init.

# §5.30 HK-3: T_VERIFIER_REJECT.sh requires the loader to honor the
# XDPMF_BPF_OBJECT_PATH env var. The top-level option defaults OFF
# (release-clean nm); when this subdir is included (in-tree dev/test
# build), we force the cache var ON so the generator expression in the
# top-level target_compile_definitions(xdpmf_internal) evaluates true
# at generate time. The genexp is evaluated AFTER all CMakeLists are
# parsed, so this FORCE wins.
set(XDPMF_ENABLE_BPF_OBJECT_OVERRIDE ON CACHE BOOL
    "Allow loader to honor XDPMF_BPF_OBJECT_PATH env var (testing-only)" FORCE)

set(TEST_DIR  ${CMAKE_CURRENT_SOURCE_DIR})
# §5.25 P2: PINS_SH is the path to the CMake-generated tests/pins.sh
# (configure_file output from tests/lib/pins.sh.in). common.sh sources
# it to pick up PIN_ROOT (extracted from src/common/mac_filter.h's
# XDPMF_BPFFS_ROOT). Runtime `:?` guard in common.sh exits if unset.
set(TEST_ENV
    "BUILD_DIR=${CMAKE_BINARY_DIR}"
    "SOURCE_DIR=${CMAKE_SOURCE_DIR}"
    "TEST_DIR=${TEST_DIR}"
    "PINS_SH=${CMAKE_BINARY_DIR}/tests/pins.sh"
    # §5.28 / MVP-3.3 — paths for the systemd / Ansible / fleet-docs tests
    # to locate the shipped artefacts in the source tree.
    "SYSTEMD_UNIT_SRC=${CMAKE_SOURCE_DIR}/systemd/xdpmacfilter@.service"
    "ANSIBLE_PLAYBOOK=${CMAKE_SOURCE_DIR}/ansible/xdpmacfilter-deploy.yml"
    "FLEET_DOCS=${CMAKE_SOURCE_DIR}/docs/FLEET_DEPLOYMENT.md"
    # §5.29 / MVP-3.4 — paths for the exporter / bypass / skeleton tests
    # to locate the shipped artefacts in the build / source trees.
    "XDPMF_EXPORTER_BIN=${CMAKE_BINARY_DIR}/xdpmf-exporter"
    "EXPORTER_UNIT_SRC=${CMAKE_SOURCE_DIR}/systemd/xdpmf-exporter.service"
)

# Foreign-XDP fixture for T_ATTACH_ALIEN_REFUSAL (design §6.9, MVP-1.1B).
# add_bpf_object() respects the sanitizer-isolation invariant
# (cmake/BpfBuild.cmake) — XDPMF_SANITIZERS does NOT propagate into the
# BPF compile. Tester loads the resulting ${CMAKE_BINARY_DIR}/xdp_pass.bpf.o
# via `ip link set ... xdpgeneric`; no skeleton header is generated (no C++
# code opens this object).
add_bpf_object(xdp_pass ${CMAKE_SOURCE_DIR}/tests/fixtures/xdp_pass.bpf.c)

# Tag-mismatch fixture for T_ATTACH_TAG_MISMATCH (design §6.14, MVP-2 Sec).
# Same SEC function name `mac_filter_prog` as the real prog (so the §5.19
# name-check passes) but minimal body (`return XDP_PASS;`) so the
# bytecode — and therefore bpf_prog_info.tag (SHA1 over bytecode) —
# differs. Same sanitizer-isolation invariant; loaded via `ip link set
# ... xdpgeneric obj …` from the test script.
add_bpf_object(mac_filter_alt ${CMAKE_SOURCE_DIR}/tests/fixtures/mac_filter_alt.bpf.c)

# Verifier-reject fixture for T_VERIFIER_REJECT (design §6.20, MVP-2 Robust).
# Deliberate verifier violation: unbounded-shape loop bounded by a
# runtime value derived from packet data (`ctx->data_end - ctx->data`)
# with NO `#pragma unroll`. clang -target bpf accepts at compile time;
# kernel BPF verifier rejects at bpf()-syscall BPF_PROG_LOAD time —
# exactly the LoadFailed (exit 2) path T_VERIFIER_REJECT exercises in
# the loader (via XDPMF_BPF_OBJECT_PATH env-var override per §5.24 Q4).
# Same sanitizer-isolation invariant; output at
# ${CMAKE_BINARY_DIR}/mac_filter_bad.bpf.o (consumed by both the
# SKIP-probe `bpftool prog load` and the active-branch loader invocation).
add_bpf_object(mac_filter_bad ${CMAKE_SOURCE_DIR}/tests/fixtures/mac_filter_bad.bpf.c)

# T_BUILD performs an isolated clean rebuild in /tmp and greps for warnings;
# it does NOT need the veth fixture and does NOT take the resource lock.
add_test(
    NAME T_BUILD
    COMMAND bash ${TEST_DIR}/T_BUILD.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_BUILD PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    TIMEOUT 300
)

# All other tests use the same veth (${IFACE_A}/${IFACE_B}, PID-suffixed
# per §5.21 C3) fixture → must be serialized via RESOURCE_LOCK.
# Per §5.21 C2: every root-using test gets SKIP_RETURN_CODE 77 so
# require_passwordless_sudo can SKIP cleanly when sudo would prompt.
foreach(T IN ITEMS
    T_LOAD_ATTACH
    T_PASS_ALLOWED
    T_DROP_DENY
    T_DROP_MALFORMED
    T_IDEMPOTENT_RELOAD
    T_NEGATION_CONTROL
    T_ATTACH_ALIEN_REFUSAL
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV}"
        RESOURCE_LOCK xdp_fixture
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
endforeach()

# Per design §6.5: this test may also exit 77 on kernels that pad short
# Ethernet frames before XDP sees them.  Same SKIP_RETURN_CODE 77
# already set above by the foreach loop (both the pad-skip and the
# require_passwordless_sudo skip use the same convention).

# Per design §6.7: negation control deliberately asserts a value that is
# wrong-by-spec.  The script exits NON-ZERO on the (expected) failure;
# ctest's WILL_FAIL flips that to a green test.  If the script ever exits
# zero (meaning MAC_BAD was let through, i.e. XDP is broken), ctest
# reports T_NEGATION_CONTROL as FAILED — surfacing the regression.
set_tests_properties(T_NEGATION_CONTROL PROPERTIES WILL_FAIL TRUE)

# Per design §6.8 (MVP-1.1A): sanitizer-build smoke. Configures a fresh
# /tmp build dir with -DXDPMF_SANITIZERS=ON, builds it, runs one
# end-to-end attach+inject+stats+detach via the asan-instrumented binary
# against the veth fixture, and greps captured stderr for sanitizer
# reports.  Takes the same xdp_fixture RESOURCE_LOCK as §6.3-§6.6 because
# it touches veth_a/veth_b.  TIMEOUT 240: the embedded cmake configure +
# sanitizer build dominates the runtime; observed 171-181s under -j4
# contention with T_BUILD (margin-flake under prior 180s ceiling across
# MVP-3.4.5 + MVP-3.4b cycles). 240s gives ~33% headroom against the
# observed-peak run.
add_test(
    NAME T_SANITIZER_BUILD
    COMMAND bash ${TEST_DIR}/T_SANITIZER_BUILD.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_SANITIZER_BUILD PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 240
    SKIP_RETURN_CODE 77
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-1.1C additions (§5.21 D1-D4 / §6.10-§6.13).
# D1/D2/D3 are pure CLI-parser tests — no root, no veth.
#   - T_CLI_HELP_VERSION: pure binary invocation, no iface — no lock.
#   - T_CLI_BAD_MAC: 4 sub-cases all fail at parse_mac() BEFORE iface
#     resolution — pure parser path, no `lo` interaction — no lock.
#   - T_CLI_CAPACITY: parser-rejects-65 path, BUT the test's defensive
#     "sanity floor" post-check reads `lo`'s XDP slot and FAILs if non-
#     empty (§6.11). Under -j4 contention a concurrent attach-test on
#     `lo` (T_DETACH_NOTHING / T_MODE_NATIVE_UNSUPPORTED /
#     T_APPLY_EXITS_1_ON_MISSING_CONFIG negation branch) would race this
#     read and produce false-positive FAILs. §5.33 HK-A classifier
#     (D-3.5.5-1) flags this for `lo_iface` lock even though the loader
#     never touches `lo` from this invocation — reads are AT RISK under
#     contention (guard #12).
# All use TIMEOUT 10 (binary launch + parse + exit only).
foreach(T IN ITEMS
    T_CLI_HELP_VERSION
    T_CLI_BAD_MAC
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV}"
        TIMEOUT 10
    )
endforeach()

# T_CLI_CAPACITY: separated from the no-lock foreach above per §5.33 HK-A
# (D-3.5.5-1 classifier). Defensive `lo`-state read at post-check → must
# serialize against other `lo`-touching tests under -j4 to avoid a
# concurrent-attach race producing false-positive FAILs.
add_test(
    NAME T_CLI_CAPACITY
    COMMAND bash ${TEST_DIR}/T_CLI_CAPACITY.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_CLI_CAPACITY PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK lo_iface
    TIMEOUT 10
)

# T_DETACH_NOTHING needs passwordless sudo (calls bpf_xdp_query under root).
# Per §5.22 amendment to §6.13: this entry takes RESOURCE_LOCK xdp_fixture
# so it cannot race the destructive setup window of T_BPFFS_ROOT_SYMLINK
# (§6.15) — that test transiently rmdir's /sys/fs/bpf/xdpmacfilter and a
# concurrent T_DETACH_NOTHING would either trip the new PathRefused exit 8
# (failure) or observe a wrong post-state. Test logic itself unchanged.
#
# §5.33 HK-A (D-3.5.5-1 classifier): extended to multi-lock
# "xdp_fixture;lo_iface" — loader's detach state-machine probes `lo` via
# bpf_xdp_query AND the post-check asserts on `lo`'s XDP slot. Follows
# the multi-lock precedent from §5.30 T_EXPORTER_EXITS_6
# ("xdp_fixture;exporter_port_9417").
add_test(
    NAME T_DETACH_NOTHING
    COMMAND bash ${TEST_DIR}/T_DETACH_NOTHING.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_DETACH_NOTHING PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK "xdp_fixture;lo_iface"
    TIMEOUT 10
    SKIP_RETURN_CODE 77
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-2 Sec additions (§5.22 / §6.14 + §6.15).
#
# T_ATTACH_TAG_MISMATCH (§6.14): same-name-different-bytecode alien
# rejected with exit 4 + 'tag mismatch' + 16-char hex tag in stderr;
# negation control re-runs with real mac_filter.bpf.o (rc==0, ours
# reload).  Same RESOURCE_LOCK as the rest of the veth-fixture tests.
#
# T_BPFFS_ROOT_SYMLINK (§6.15): symlink at bpffs root and per-iface dir
# refused with exit 8 + 'symlink' + path-token stderr discipline;
# negation control with real bpffs root proves refusal is
# symlink-specific.  DESTRUCTIVE to /sys/fs/bpf/xdpmacfilter for the
# test's duration; trap-driven cleanup mandatory; RESOURCE_LOCK
# xdp_fixture serializes against ALL other tests that touch the bpffs
# path (the §6.13 amendment above extends this lock to T_DETACH_NOTHING).
add_test(
    NAME T_ATTACH_TAG_MISMATCH
    COMMAND bash ${TEST_DIR}/T_ATTACH_TAG_MISMATCH.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_ATTACH_TAG_MISMATCH PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 60
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_BPFFS_ROOT_SYMLINK
    COMMAND bash ${TEST_DIR}/T_BPFFS_ROOT_SYMLINK.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_BPFFS_ROOT_SYMLINK PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 60
    SKIP_RETURN_CODE 77
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-2 Perf additions (§5.23 / §6.16-§6.19).
#
# T_MODE_GENERIC_DEFAULT (§6.16): attach without --mode defaults to
# generic (SKB); RESOURCE_LOCK xdp_fixture (uses standard veth pair).
#
# T_MODE_NATIVE_UNSUPPORTED (§6.17): attach --mode native --iface lo →
# exit 3.  RESOURCE_LOCK lo_iface (§5.33 HK-A / D-3.5.5-1: loader's
# attach state-machine reaches the kernel on `lo`; cleanup_native
# unconditionally runs `ip link set lo xdp{,generic} off` — touches `lo`
# state regardless of test outcome). SKIP 77 for require_passwordless_sudo
# path.
#
# T_PERCPU_STATS_SUM (§6.18): seeds known per-CPU values via bpftool map
# update, asserts read_stats sum matches; RESOURCE_LOCK xdp_fixture.
#
# T_MODE_DETACH_REJECTS (§6.19): detach --mode <X> → exit 1 + stderr
# 'attach-only'.  Pure CLI parser test — NO root, NO RESOURCE_LOCK,
# NO SKIP_RETURN_CODE.
add_test(
    NAME T_MODE_GENERIC_DEFAULT
    COMMAND bash ${TEST_DIR}/T_MODE_GENERIC_DEFAULT.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_MODE_GENERIC_DEFAULT PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 60
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_MODE_NATIVE_UNSUPPORTED
    COMMAND bash ${TEST_DIR}/T_MODE_NATIVE_UNSUPPORTED.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_MODE_NATIVE_UNSUPPORTED PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK lo_iface
    TIMEOUT 30
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_PERCPU_STATS_SUM
    COMMAND bash ${TEST_DIR}/T_PERCPU_STATS_SUM.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_PERCPU_STATS_SUM PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 30
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_MODE_DETACH_REJECTS
    COMMAND bash ${TEST_DIR}/T_MODE_DETACH_REJECTS.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_MODE_DETACH_REJECTS PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    TIMEOUT 10
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-2 Robust addition (§5.24 / §6.20).
#
# T_VERIFIER_REJECT (§6.20): hand the loader a verifier-rejected .bpf.o
# via XDPMF_BPF_OBJECT_PATH env-var override (per §5.24 Q4 Option (c));
# assert exit 2 (LoadFailed) + recognizable stderr (verifier|BPF_PROG_LOAD|
# Invalid argument) + no XDP attached + no orphan pin dir.
#
# SKIP probe FIRST: standalone `bpftool prog load` on the bad fixture;
# if a future kernel verifier silently accepts our deliberate violation,
# the test exits 77 (ctest SKIP) rather than producing a false red — Q4
# Option (c) "degrades gracefully" contract. SKIP_RETURN_CODE 77 honours
# that path.
#
# Takes RESOURCE_LOCK xdp_fixture because the test uses ${IFACE_A} (the
# active branch attempts an attach that will fail at load time, but the
# veth is touched). TIMEOUT 60: bpftool probe + loader invocation + a
# few cleanup sudo calls; no traffic injection. Spec §6.20 originally
# said 30; bumped to 60 per EDIT-12 (libbpf-stderr volume safety margin).
add_test(
    NAME T_VERIFIER_REJECT
    COMMAND bash ${TEST_DIR}/T_VERIFIER_REJECT.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_VERIFIER_REJECT PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 60
    SKIP_RETURN_CODE 77
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-3.1 additions (§5.26 / §6.21-§6.27 — Composite 6 config-first foundation).
#
# T_APPLY_VALID_CONFIG (§6.21): valid YAML → applied; MAC filtering matches.
# T_APPLY_REJECTS_MALFORMED (§6.22): 5 malformed sub-cases → exit 9.
# T_APPLY_ATOMIC_SWAP_NO_DROP (§6.23): LOAD-BEARING — concurrent traffic +
#   apply; zero drops for overlapping-allowed MAC across the swap window.
# T_APPLY_REPLACES_RULESET (§6.24): bidirectional A↔B↔A swap verification.
# T_LINK_PERSIST_ACROSS_LOADER_EXIT (§6.25): LOAD-BEARING P0a — bpf_link
#   pin persists across loader exit; filter still enforces on fresh
#   traffic; idempotent reattach via bpf_link__update_program.
# T_TRUST_MODEL_FLEET_RELAXES_GATE (§6.26): XDPMF_TRUST_MODEL=fleet
#   bypasses §5.4 alien refusal; strict re-confirms refusal; garbage value
#   fails closed exit 9. Uses xdp_pass.bpf.o alien fixture (already built).
# T_EXIT_CODE_9_ON_CONFIG_ERROR (§6.27): bare-bones exit-9 audit-grep via
#   garbage XDPMF_TRUST_MODEL — NO veth, NO root, NO fixture deps.
foreach(T IN ITEMS
    T_APPLY_VALID_CONFIG
    T_APPLY_REJECTS_MALFORMED
    T_APPLY_REPLACES_RULESET
    T_LINK_PERSIST_ACROSS_LOADER_EXIT
    T_TRUST_MODEL_FLEET_RELAXES_GATE
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV}"
        RESOURCE_LOCK xdp_fixture
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
endforeach()

# §6.23 LOAD-BEARING concurrent-traffic test — longer TIMEOUT because the
# test runs ≥4s of background injection (2s baseline + 2s post-swap). The
# SKIP_RETURN_CODE 77 path triggers when XDPMF_INJECT_RATE_HZ is too low
# for the runner's sustained packet-per-second capacity (slow CI).
add_test(
    NAME T_APPLY_ATOMIC_SWAP_NO_DROP
    COMMAND bash ${TEST_DIR}/T_APPLY_ATOMIC_SWAP_NO_DROP.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_APPLY_ATOMIC_SWAP_NO_DROP PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 120
    SKIP_RETURN_CODE 77
)

# §6.27 bare-bones exit-code-9 audit-grep — NO veth, NO root, NO
# RESOURCE_LOCK; pure binary invocation test (env-parse rejection
# happens before iface resolution per §5.26 attach() flow step 2).
add_test(
    NAME T_EXIT_CODE_9_ON_CONFIG_ERROR
    COMMAND bash ${TEST_DIR}/T_EXIT_CODE_9_ON_CONFIG_ERROR.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_EXIT_CODE_9_ON_CONFIG_ERROR PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    TIMEOUT 10
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-3.2 additions (§5.27 / §6.28–§6.31 — L3 src-CIDR rule type).
#
# T_PASS_CIDR (§6.28): CIDR-axis rule applied; in-range IPv4 src_ip
#   passes via STAT_PASS_CIDR; out-of-range drops via STAT_DROP_DENY.
# T_DROP_CIDR_NOT_IN_RANGE (§6.29): focused negation — no-rule-matches
#   drops are counter-SPLIT clean (only STAT_DROP_DENY moves).
# T_PASS_MAC_OR_CIDR (§6.30): LOAD-BEARING OR-compose verification —
#   single rule with both mac+src_cidr; 3 sub-cases assert counter
#   SPLIT (STAT_PASS vs STAT_PASS_CIDR vs STAT_DROP_DENY).
#   §6.43 T_PASS_CIDR_VLAN: single 802.1Q-tagged IPv4 reaches the CIDR axis
#     (THE regression closed by §5.41 MVP-4.1); in-range → STAT_PASS_CIDR,
#     out-of-range → STAT_DROP_DENY.
#   §6.44 T_PASS_CIDR_QINQ: depth-2 QinQ-tagged IPv4 in-range → STAT_PASS_CIDR,
#     plus the load-bearing depth-3-overflow anti-vacuity sub-case (guard #22).
foreach(T IN ITEMS
    T_PASS_CIDR
    T_DROP_CIDR_NOT_IN_RANGE
    T_PASS_MAC_OR_CIDR
    T_PASS_CIDR_VLAN
    T_PASS_CIDR_QINQ
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV}"
        RESOURCE_LOCK xdp_fixture
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
endforeach()

# §6.31 LOAD-BEARING CIDR-axis atomic-swap test — runs ≥4s of background
# IPv4 injection (2s baseline + 2s post-swap) at AF_PACKET rate.
# SKIP_RETURN_CODE 77 triggers when XDPMF_INJECT_RATE_HZ is too low for
# the runner's sustained packet-per-second capacity (slow CI), mirroring
# §6.23's pattern (same env-var knob per §5.27 OOS fence).
add_test(
    NAME T_CIDR_ATOMIC_SWAP_NO_DROP
    COMMAND bash ${TEST_DIR}/T_CIDR_ATOMIC_SWAP_NO_DROP.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_CIDR_ATOMIC_SWAP_NO_DROP PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 120
    SKIP_RETURN_CODE 77
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-3.3 additions (§5.28 / §6.32–§6.36 — systemd + Ansible + fleet docs).
#
# T_SYSTEMD_UNIT_SYNTAX (§6.32): `systemd-analyze verify` accepts the
#   unit template (positive case) + a deliberately-broken copy is rejected
#   (NEGATION sub-case). Read-only check — no sudo, no RESOURCE_LOCK.
#
# T_SYSTEMD_LIFECYCLE (§6.33): LOAD-BEARING OPS canary. Install unit
#   + config, daemon-reload, start, assert XDP attached + active_idx=0 +
#   `trust_model=` in journal; modify config + reload, assert active_idx
#   flipped + prog id UNCHANGED (atomic swap, NOT re-attach); stop,
#   assert XDP detached + link pin gone. Aggressive trap-cleanup.
#   Uses passwordless sudo; RESOURCE_LOCK xdp_fixture (touches veth)
#   AND systemd_unit_install (touches /etc/systemd/system/<unit>).
#
# T_SYSTEMD_RESTART_ON_FAILURE (§6.34): malformed config → systemd retries
#   per Restart=on-failure → eventually hits StartLimitBurst=5 within
#   StartLimitIntervalSec=300 (Q4 RT2). Assert NRestarts ∈ [4,5] and
#   journalctl shows `start request repeated too quickly`. Same locks
#   as §6.33 + same SKIP_RETURN_CODE 77 (PI-25 carve-out for timing flake).
#
# T_ANSIBLE_PLAYBOOK_SYNTAX (§6.35): `ansible-playbook --syntax-check`
#   on the playbook → exit 0; SKIP-77 if ansible-playbook not in PATH.
#   No locks (read-only syntax check).
#
# T_FLEET_DOCS_SUBSTRING (§6.36): 6-substring grep over FLEET_DEPLOYMENT.md
#   (PI-23 verbatim stderr citation + PI-1..PI-5 fence references).
#   Pure file-content check — no locks, no SKIP.
add_test(
    NAME T_SYSTEMD_UNIT_SYNTAX
    COMMAND bash ${TEST_DIR}/T_SYSTEMD_UNIT_SYNTAX.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_SYSTEMD_UNIT_SYNTAX PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    TIMEOUT 30
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_SYSTEMD_LIFECYCLE
    COMMAND bash ${TEST_DIR}/T_SYSTEMD_LIFECYCLE.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_SYSTEMD_LIFECYCLE PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK "xdp_fixture;systemd_unit_install"
    TIMEOUT 120
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_SYSTEMD_RESTART_ON_FAILURE
    COMMAND bash ${TEST_DIR}/T_SYSTEMD_RESTART_ON_FAILURE.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_SYSTEMD_RESTART_ON_FAILURE PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK "xdp_fixture;systemd_unit_install"
    TIMEOUT 120
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_ANSIBLE_PLAYBOOK_SYNTAX
    COMMAND bash ${TEST_DIR}/T_ANSIBLE_PLAYBOOK_SYNTAX.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_ANSIBLE_PLAYBOOK_SYNTAX PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    TIMEOUT 30
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_FLEET_DOCS_SUBSTRING
    COMMAND bash ${TEST_DIR}/T_FLEET_DOCS_SUBSTRING.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_FLEET_DOCS_SUBSTRING PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    TIMEOUT 10
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-3.4 additions (§5.29 / §6.37–§6.42 — observability exporter + bypass +
# rules/action_table skeleton).
#
# T_EXPORTER_METRICS_FORMAT  (§6.37): attach + inject; spawn exporter on
#   per-PID-derived port; assert /metrics returns Prometheus text-format
#   compliant output (HELP+TYPE+sample-line regex) + PI-33 --version smoke.
#   SKIP-77 if curl absent.
# T_EXPORTER_VALUES_MATCH_STATS (§6.38): LOAD-BEARING — inject known
#   per-verdict counts; compare exporter PERCPU sum vs read_stats.py
#   PERCPU sum strict-equal. SKIP-77 if curl OR jq absent.
# T_EXPORTER_NO_ATTACHED_IFACE (§6.39): exporter against empty/missing
#   bpffs root (PI-32 graceful-empty). 2 requests succeed; process stays
#   alive. SKIP-77 if curl absent.
# T_BYPASS_CMD_DETACHES (§6.40): `xdpmacfilter bypass --unsafe --reason X`
#   detaches XDP + emits audit line (regex ERE); sub-case verifies the
#   `reason="UNSPECIFIED"` default path. PI-30.
# T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE (§6.41): NEGATION CONTROL —
#   bypass under setsid (non-tty) without --unsafe refuses (exit 1, stderr
#   audit-safety message, XDP STILL attached). Fail-open regression guard.
# T_RULES_SKELETON_NOT_WIRED (§6.42): DELETED in §5.34 per Q2.A — the
#   defer-posture contract (rules+action_table NOT consulted) is RETIRED
#   by MVP-3.4b cycle 2; the new T_DROP_RULE_OPERATIVE / T_RULES_ATOMIC_
#   SWAP_NO_DROP / T_RULES_AXIS_FLIPS_WITH_ACTIVE_IDX cover the wired
#   contract. Foreach below shrunk from 6 to 5 entries.
#
# All 5 tests share RESOURCE_LOCK xdp_fixture — they touch the veth pair
# AND/OR spawn the exporter against the host-global PIN_ROOT bpffs.
# Serialized against the 30 other veth-touching tests.
foreach(T IN ITEMS
    T_EXPORTER_METRICS_FORMAT
    T_EXPORTER_VALUES_MATCH_STATS
    T_EXPORTER_NO_ATTACHED_IFACE
    T_BYPASS_CMD_DETACHES
    T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV}"
        RESOURCE_LOCK xdp_fixture
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
endforeach()

# ─────────────────────────────────────────────────────────────────────────
# MVP-3.4.5 additions (§5.30 / §6.43–§6.46 — housekeeping cycle).
#
# T_APPLY_EXITS_1_ON_MISSING_CONFIG (§6.43): HK-1 exit-code triple drift
#   fix — `apply -f /nonexistent --iface lo` exits 1 (kExitUsageErr); the
#   `xdpmacfilter: config error:` stderr prefix is preserved verbatim.
#   Negation control: valid config does NOT exit 1. Primary case is
#   pure-parser (config_open throws first), BUT the negation branch
#   invokes `apply -f config_valid.yaml --iface lo` which reaches the
#   loader's attach state-machine on `lo` AND the post-cleanup line
#   calls `detach --iface lo` → §5.33 HK-A (D-3.5.5-1 classifier) flags
#   for `lo_iface` lock. SKIP_RETURN_CODE 77 still present so
#   require_passwordless_sudo can SKIP cleanly in unprivileged contexts.
# T_BYPASS_INTERACTIVE_PROMPT (§6.44): pseudo-tty driven y/N/EOF prompt
#   coverage via `script -qc` (SKIP-77 if neither script nor expect
#   available). Also embeds the HK-4 audit-line uid=/euid=/sudo_user=
#   structural-field assertion (per D-3.4.5-8 option (b)).
# T_BYPASS_REASON_TRUNCATE (§6.45): HK-4 truncation contract — 253B
#   boundary (no trunc), 254B first trunc (253 + `…`), 300B mid-UTF-8
#   rewind-safety. SKIP-77 if neither python3 nor iconv present.
# T_EXPORTER_EXITS_6_ALL_IFACES_EACCES (§6.46): HK-17 exit-6 verification.
#   chmod 000 per-iface stats files; run exporter as unprivileged user;
#   assert exit 6 + HK-17 ERROR line. Negation control: default perms →
#   exporter does NOT exit 6 within 3s. SKIP-77 if EACCES not reproducible
#   OR curl absent OR no unprivileged user available.
#
# Resource locks:
#   - T_APPLY_EXITS_1_ON_MISSING_CONFIG: `lo_iface` (§5.33 HK-A — negation
#     branch reaches loader's attach/detach state-machine on `lo`).
#   - T_BYPASS_*: share `xdp_fixture` (touch veth via setup_veth).
#   - T_EXPORTER_EXITS_6: shares `xdp_fixture` (touches veth) AND
#     `exporter_port_9417` (new lock per §5.30 — prevents port clash with
#     concurrent exporter-running tests in §6.37/§6.38/§6.39).
add_test(
    NAME T_APPLY_EXITS_1_ON_MISSING_CONFIG
    COMMAND bash ${TEST_DIR}/T_APPLY_EXITS_1_ON_MISSING_CONFIG.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_APPLY_EXITS_1_ON_MISSING_CONFIG PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK lo_iface
    TIMEOUT 30
    SKIP_RETURN_CODE 77
)

foreach(T IN ITEMS
    T_BYPASS_INTERACTIVE_PROMPT
    T_BYPASS_REASON_TRUNCATE
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV}"
        RESOURCE_LOCK xdp_fixture
        TIMEOUT 90
        SKIP_RETURN_CODE 77
    )
endforeach()

add_test(
    NAME T_EXPORTER_EXITS_6_ALL_IFACES_EACCES
    COMMAND bash ${TEST_DIR}/T_EXPORTER_EXITS_6_ALL_IFACES_EACCES.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_EXPORTER_EXITS_6_ALL_IFACES_EACCES PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK "xdp_fixture;exporter_port_9417"
    TIMEOUT 90
    SKIP_RETURN_CODE 77
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-3.4b cycle 1 additions (§5.31 / §6.47–§6.52 — per-rule counters +
# inner-allowlist-value extension + datapath wiring + exporter rule labels).
#
# T_RULE_COUNTER_MAC_HIT_BUMPS  (§6.47): MAC HASH-hit increments
#   rule_counters[rule_id]; sparse-id verification (id=0, id=5); negation
#   on non-matching MAC. Uses config_per_rule_counters.yaml fixture.
# T_RULE_COUNTER_CIDR_HIT_BUMPS (§6.48): CIDR LPM_TRIE-hit symmetric;
#   negation on out-of-range src_ip; MAC/CIDR axis isolation sub-case.
# T_RULE_COUNTER_SURVIVES_APPLY (§6.49): LOAD-BEARING canary for
#   HG-3.4b-2 — counter survival across apply via PIN_BY_NAME + reuse_fd.
# T_SIDECAR_JSON_SHAPE          (§6.50): rule_index.json shape per Q2 S1;
#   negation on malformed config (sidecar NOT corrupted).
# T_EXPORTER_RULE_LABELS        (§6.51): xdpfilter_rule_match_total
#   Prometheus series + sidecar-orphan tolerance (action="unknown").
#   Takes BOTH xdp_fixture AND exporter_port_9417 RESOURCE_LOCKs.
# T_DROP_RULE_BUMPS_COUNTER     (§6.52-revised, §5.34 Q3.A): drop rule
#   MAC NOW enters inner-allowlist, per-rule counter NOW bumps on match,
#   verdict XDP_DROP via rules→action_table chain (PI-29-3.4b-c2 +
#   PI-30-3.4b-c2-schema — assertions INVERTED from pre-§5.34 body).
#
# All 6 tests touch the veth fixture → share xdp_fixture RESOURCE_LOCK.
# §6.51 additionally takes exporter_port_9417 (port-clash serialization).
foreach(T IN ITEMS
    T_RULE_COUNTER_MAC_HIT_BUMPS
    T_RULE_COUNTER_CIDR_HIT_BUMPS
    T_RULE_COUNTER_SURVIVES_APPLY
    T_SIDECAR_JSON_SHAPE
    T_DROP_RULE_BUMPS_COUNTER
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV}"
        RESOURCE_LOCK xdp_fixture
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
endforeach()

add_test(
    NAME T_EXPORTER_RULE_LABELS
    COMMAND bash ${TEST_DIR}/T_EXPORTER_RULE_LABELS.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_EXPORTER_RULE_LABELS PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK "xdp_fixture;exporter_port_9417"
    TIMEOUT 90
    SKIP_RETURN_CODE 77
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-3.4b cycle 2 additions (§5.34 / §6.NN–§6.NN+2 — rules atomic-swap
# promotion + datapath dispatch via rules→action_table + schema cycle
# 2→3 semantic shift).
#
# T_DROP_RULE_OPERATIVE          (§6.NN):   explicit drop rule dispatches
#   XDP_DROP via the rules→action_table chain (PI-29-3.4b-c2 + schema
#   shift per PI-30-3.4b-c2-schema). Dual-MAC fixture verifies that a
#   pass rule (id=5) and drop rule (id=17) produce different verdict
#   buckets via the SAME inner-allowlist machinery.
# T_RULES_ATOMIC_SWAP_NO_DROP    (§6.NN+1): LOAD-BEARING canary for
#   PI-13-3.4b-c2 (rules-axis atomic-swap via active_idx flip,
#   symmetric with §5.27 Q1 AS1 CIDR-axis pattern). Concurrent
#   alternating traffic across an action-inverting apply; rule_counters
#   sum equals verdict sum across the swap window (atomicity proof).
# T_RULES_AXIS_FLIPS_WITH_ACTIVE_IDX (§6.NN+2): bpftool-only verification
#   that rules_<active_A> ↔ rules_<active_B> indexing tracks active_idx
#   flip, and the inactive slot retains prior content (one-deep rollback
#   history per §5.26 atomic-swap contract).
#
# All 3 tests touch the veth fixture → share RESOURCE_LOCK xdp_fixture
# per anti-misdiagnosis guard #12. T_RULES_ATOMIC_SWAP_NO_DROP runs a
# 14s background injector + 2× WINDOW_SEC waits → TIMEOUT 120 matching
# §6.23 T_APPLY_ATOMIC_SWAP_NO_DROP + §6.31 T_CIDR_ATOMIC_SWAP_NO_DROP
# precedent. The other two are bpftool-only / single-batch tests → 60s.
foreach(T IN ITEMS
    T_DROP_RULE_OPERATIVE
    T_RULES_AXIS_FLIPS_WITH_ACTIVE_IDX
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV}"
        RESOURCE_LOCK xdp_fixture
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
endforeach()

add_test(
    NAME T_RULES_ATOMIC_SWAP_NO_DROP
    COMMAND bash ${TEST_DIR}/T_RULES_ATOMIC_SWAP_NO_DROP.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_RULES_ATOMIC_SWAP_NO_DROP PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 120
    SKIP_RETURN_CODE 77
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-3.5 additions (§5.32 / §6.53–§6.58 — JSON structured logs).
#
# T_LOG_TEXT_BYTE_EQUIVALENT (§6.53): LOAD-BEARING canary for PI-3.5-1.
#   3-way byte-equivalence (unset / "" / text) + cmp against committed
#   reference fixture; negation = JSON mode produces different stderr.
#   Takes xdp_fixture (touches veth via attach/apply/detach).
# T_LOG_JSON_LOADER_EVENTS (§6.54): attach + apply + detach under JSON;
#   per-line jq parse + loader.trust_model event count==2 + level ∈
#   {info,warn,error} + fields.trust_model == "strict" + iface==null;
#   negation = text mode does not parse as JSON.
#   Takes xdp_fixture.
# T_LOG_JSON_EXPORTER_EVENTS (§6.55): exporter under JSON;
#   exporter.warn.bpffs_root_missing (HK-16), exporter.listening,
#   exporter.shutdown events validated; negation = text-mode HK-16
#   wording byte-equivalent; HK-17 sub-case (chmod 000 + unpriv user)
#   SKIP-77 if EACCES not reproducible. Takes xdp_fixture +
#   exporter_port_9417 (touches both veth AND exporter port range).
# T_LOG_JSON_BYPASS_AUDIT (§6.56): bypass.activated event under JSON
#   carries HK-4 structural fields (uid, euid, sudo_user, reason);
#   negation = text-mode HK-4 audit-line byte-equivalent; escape sub-case
#   verifies JSON escape correctness for embedded quote. Takes xdp_fixture.
# T_LOG_JSON_ENVELOPE_INVARIANTS (§6.57): broad sweep across loader +
#   exporter; per-line envelope validation (ts, level, event, iface, msg,
#   fields all present + correctly typed); negation = malformed-line
#   probe must be REJECTED by the validator; PI-3.5-3 edge case (empty
#   XDPMF_LOG_FORMAT="" → silent Text fallback) sub-case. Takes
#   xdp_fixture + exporter_port_9417.
# T_LOG_EVENT_CATALOG_STABILITY (§6.58): static-analysis test on
#   src/common/logger.hpp's kEventNames constexpr table; sort + cmp
#   against committed reference; negation = inject extra event into a
#   COPY of the header, assert comparator catches the drift.
#   NO ROOT NEEDED, NO RESOURCE_LOCK — can run in parallel with anything.
add_test(
    NAME T_LOG_TEXT_BYTE_EQUIVALENT
    COMMAND bash ${TEST_DIR}/T_LOG_TEXT_BYTE_EQUIVALENT.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_LOG_TEXT_BYTE_EQUIVALENT PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 90
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_LOG_JSON_LOADER_EVENTS
    COMMAND bash ${TEST_DIR}/T_LOG_JSON_LOADER_EVENTS.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_LOG_JSON_LOADER_EVENTS PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 60
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_LOG_JSON_EXPORTER_EVENTS
    COMMAND bash ${TEST_DIR}/T_LOG_JSON_EXPORTER_EVENTS.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_LOG_JSON_EXPORTER_EVENTS PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK "xdp_fixture;exporter_port_9417"
    TIMEOUT 90
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_LOG_JSON_BYPASS_AUDIT
    COMMAND bash ${TEST_DIR}/T_LOG_JSON_BYPASS_AUDIT.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_LOG_JSON_BYPASS_AUDIT PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 60
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_LOG_JSON_ENVELOPE_INVARIANTS
    COMMAND bash ${TEST_DIR}/T_LOG_JSON_ENVELOPE_INVARIANTS.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_LOG_JSON_ENVELOPE_INVARIANTS PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK "xdp_fixture;exporter_port_9417"
    TIMEOUT 90
    SKIP_RETURN_CODE 77
)

add_test(
    NAME T_LOG_EVENT_CATALOG_STABILITY
    COMMAND bash ${TEST_DIR}/T_LOG_EVENT_CATALOG_STABILITY.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_LOG_EVENT_CATALOG_STABILITY PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    TIMEOUT 30
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-3.4d additions (§5.35 / §6.NN–§6.NN+3 — reset-counters CLI
# subcommand + rule_counters axis atomic-swap promotion).
#
# T_CLI_RESET_COUNTERS          (§6.NN):   `xdpmacfilter reset-counters
#   --iface X` (no --rule-id) zeros ALL 64 rule_counters slots; subsequent
#   bumps work from a zero baseline. HG-3.4d-1/HG-3.4d-2/HG-3.4d-6.
# T_CLI_RESET_COUNTERS_RULE_ID  (§6.NN+1): selective `--rule-id N` zeros
#   only slot N; out-of-range (64) + non-integer (foo) parse-time
#   rejections per Q1.A. PI-3.4d-1.
# T_CLI_RESET_COUNTERS_NO_IFACE (§6.NN+2): iface-not-attached precondition
#   yields exit 1 + 'no rule_counters pin' stderr substring (HG-3.4d-3);
#   negation control with attached iface returns exit 0.
# T_RULE_COUNTERS_ATOMIC_SWAP   (§6.NN+3): LOAD-BEARING canary for
#   PI-3.4b-2 PRESERVE-across-apply via D-3.4d-3 apply-step copy-forward.
#   CONDITIONAL — SKIP-77 if D-3.4d-FALLBACK active (atomic-swap deferred;
#   rule_counters_outer pin absent).
#
# All 4 tests touch veth + bpffs pins → RESOURCE_LOCK xdp_fixture per
# guard #12. Sit alongside the 6 §5.31 + 3 §5.34 rule_counters/rules-axis
# tests for serialization.
foreach(T IN ITEMS
    T_CLI_RESET_COUNTERS
    T_CLI_RESET_COUNTERS_RULE_ID
    T_CLI_RESET_COUNTERS_NO_IFACE
    T_RULE_COUNTERS_ATOMIC_SWAP
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV}"
        RESOURCE_LOCK xdp_fixture
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
endforeach()

# ─────────────────────────────────────────────────────────────────────────
# MVP-3.4f addition (§5.37 / T-1 — Theme B / sec M1 closure: extended
# escape_audit policy escapes control chars + 0x7F via `\xHH` while
# preserving the 4 argv-passable named escapes `\\` / `\"` / `\n` / `\r`).
#
# T_BYPASS_AUDIT_CONTROL_CHARS (§5.37 T-1): integration test via real
#   `xdpmacfilter bypass --iface IFACE_A --unsafe --reason <bytes>` with
#   3 sub-cases (a) control-char bytes → `\xHH`; (b) named escapes use
#   named form (NOT `\xHH`); (c) NEGATION — printable ASCII produces no
#   `\x` substring. PI-3.4f-2 + PI-3.4f-3 operational evidence.
#
# Takes RESOURCE_LOCK xdp_fixture per anti-misdiagnosis guard #12 —
# uses setup_veth + per-iface attach (touches veth pair + bpffs pin).
# TIMEOUT 60 matches sibling bypass-shape tests (T_BYPASS_CMD_DETACHES /
# T_LOG_JSON_BYPASS_AUDIT). SKIP_RETURN_CODE 77 for require_passwordless_sudo.
add_test(
    NAME T_BYPASS_AUDIT_CONTROL_CHARS
    COMMAND bash ${TEST_DIR}/T_BYPASS_AUDIT_CONTROL_CHARS.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_BYPASS_AUDIT_CONTROL_CHARS PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 60
    SKIP_RETURN_CODE 77
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-3.4e additions (§5.36 / T-1 + T-2 — KC-3 closure: reset-counters
# path-hardening + sidecar iface-subdir symlink defense).
#
# T_RESET_COUNTERS_PATH_TRAVERSAL (§5.36 T-1): `reset-counters --iface
#   <bad-shape>` rejected at the §5.22 invariant layer with exit 8
#   (PathRefused) + stderr substring 'refusing to operate'. Sub-cases
#   (a) `../foo` (path traversal), (b) 'invalid name with spaces' (shape
#   reject), (c) NEGATION real iface → exit 0 + audit-log. PI-3.4e-1.
# T_SIDECAR_IFACE_SYMLINK_REFUSAL (§5.36 T-2): per-iface symlink at
#   `/run/xdpmacfilter/<iface>` detected by SidecarRootFd discipline;
#   apply exit 0 (PI-32-3.4b PRESERVED) + `sidecar.warn.iface_dir_symlink`
#   event in stderr + NO write to attacker target dir. PI-3.4e-2.
#
# Both share RESOURCE_LOCK xdp_fixture per D-3.4e-T2-LOCK (no separate
# `sidecar_root` lock domain — IFACE_A is PID-unique so per-iface state
# under /run/xdpmacfilter cannot clash with concurrent tests).
foreach(T IN ITEMS
    T_RESET_COUNTERS_PATH_TRAVERSAL
    T_SIDECAR_IFACE_SYMLINK_REFUSAL
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV}"
        RESOURCE_LOCK xdp_fixture
        TIMEOUT 60
        SKIP_RETURN_CODE 77
    )
endforeach()

# ─────────────────────────────────────────────────────────────────────────
# MVP-3.4h additions (§5.39 — exporter --bind non-loopback startup WARN).
#
# T_EXPORTER_BIND_NON_LOOPBACK_WARN (§5.39 T-1): spawn exporter with
#   --bind <addr> across 5 sub-cases (a) 0.0.0.0 positive, (b) 127.255.255.255
#   upper-edge negation, (c) default-127.0.0.1 negation, (d) 127.0.0.2
#   in-range non-default negation, (e) JSON-mode positive structured-event
#   shape. Asserts the new `exporter.warn.bind_non_loopback` event token +
#   D-3.4h-7 LOAD-BEARING text prose substring on positive cases; verifies
#   silence on the entire 127.0.0.0/8 range (HG-3.4h-2 bitmask coverage).
#   Closes /mint-review sec M2 + KC-2 observability half.
#
# Resource lock per D-3.4h-T1-LOCK + Q4: `exporter_port_9417` ONLY (port-
# clash serialization with sibling exporter tests). NO xdp_fixture — this
# test does NOT touch the veth pair / attach XDP / read pinned maps.
# Minimizing lock surface per architect spec guard #12.
add_test(
    NAME T_EXPORTER_BIND_NON_LOOPBACK_WARN
    COMMAND bash ${TEST_DIR}/T_EXPORTER_BIND_NON_LOOPBACK_WARN.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_EXPORTER_BIND_NON_LOOPBACK_WARN PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK exporter_port_9417
    TIMEOUT 60
    SKIP_RETURN_CODE 77
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-4.2 additions (§5.42 — ISOLATED bit-vector AND-classification SPIKE).
#
# This block is ADDITIVE and fully isolated (D-mvp-4.2-ISOLATION): a separate
# prototype BPF object + skeleton + a test-only populate/dump harness, plus the
# two §6.45/§6.46 ctests. The prototype maps are NOT in the production
# kManagedMaps[] and pin under the SEPARATE bpffs root /sys/fs/bpf/
# xdpmf-bitvec-proto; the production datapath + its 70 ctests are untouched.
#
# (a) Prototype BPF object + skeleton (mirrors the mac_filter wiring). The
#     add_bpf_object/add_bpf_skeleton helpers (cmake/BpfBuild.cmake) are reused
#     verbatim — the sanitizer-isolation invariant holds (no flag splicing).
add_bpf_object(bitvec_proto ${CMAKE_SOURCE_DIR}/tests/bitvec/bitvec_proto.bpf.c)
add_bpf_skeleton(bitvec_proto)

# (b) Test-only harness executable. Links libbpf (skeleton consumer) the same
#     way xdpmf_internal does; depends on the generated skeleton header.
add_executable(bitvec_harness ${CMAKE_SOURCE_DIR}/tests/bitvec/bitvec_harness.cpp)
# Land the harness in the build root (not build/tests/) so its path matches the
# BITVEC_HARNESS env var below and mirrors the top-level binary layout the
# other tests assume via ${BUILD_DIR}.
set_target_properties(bitvec_harness PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
target_include_directories(bitvec_harness PRIVATE
    ${CMAKE_SOURCE_DIR}/tests/bitvec
)
# bpftool-generated skel.h uses C-style casts; treat the build dir as SYSTEM
# include so its diagnostics do not trip the -Werror floor (same convention as
# the top-level xdpmf_internal target).
target_include_directories(bitvec_harness SYSTEM PRIVATE
    ${CMAKE_BINARY_DIR}
)
target_link_libraries(bitvec_harness PRIVATE PkgConfig::LIBBPF)
add_dependencies(bitvec_harness bitvec_proto_skel)

# (c) The two spike ctests. The bitvec env extends the shared TEST_ENV with
#     explicit paths to the harness binary, the prototype BPF object, and the
#     L4 injector so the test bodies need not hard-code build-layout knowledge.
set(TEST_ENV_BITVEC
    ${TEST_ENV}
    "BITVEC_HARNESS=${CMAKE_BINARY_DIR}/bitvec_harness"
    "BITVEC_BPF_OBJ=${CMAKE_BINARY_DIR}/bitvec_proto.bpf.o"
    "INJECT_L4=${CMAKE_SOURCE_DIR}/tests/inject/inject_l4.py"
    "BITVEC_ORACLE=${CMAKE_SOURCE_DIR}/tests/bitvec/bitvec_oracle.py"
)

# T_BITVEC_ORACLE_AGREEMENT (§6.45): table-driven datapath-vs-oracle agreement
#   across hit/miss/overlap/range-edge/wildcard/first-match-tie + a negation
#   control. Touches the veth pair → RESOURCE_LOCK xdp_fixture.
# T_BITVEC_VERIFIER_LOAD (§6.46): the D-mvp-4.2-FFS-FEAS empirical gate —
#   load the prototype object through the verifier (rc=0). Touches the veth
#   pair (harness populate attaches) → RESOURCE_LOCK xdp_fixture.
foreach(T IN ITEMS
    T_BITVEC_ORACLE_AGREEMENT
    T_BITVEC_VERIFIER_LOAD
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV_BITVEC}"
        RESOURCE_LOCK xdp_fixture
        TIMEOUT 90
        SKIP_RETURN_CODE 77
    )
endforeach()

# ── §5.43 MVP-4.3 production OR→AND bit-vector pivot (axis-1) ─────────────
# Four NEW ctests (§6.60..§6.63) for the dst_cidr + src_cidr AND-compose
# datapath. The independent O(N) reference classifier lives at
# tests/bitvec/bitvec_oracle_prod.py (naive scan, NO bitmask/closure — guard
# #23 / §6.61); exported via AND_ORACLE_PROD so the test body needn't hardcode
# build-layout knowledge. All four touch the veth fixture (apply attaches +
# §6.63(d) attaches) → RESOURCE_LOCK xdp_fixture (guard #12). SKIP_RETURN_CODE
# 77 for the passwordless-sudo / jq preconditions.
#
# T_AND_COMPOSE_OK            (§6.60): dst AND src compose; OR→AND proof.
# T_AND_ORACLE_AGREEMENT      (§6.61): table-driven datapath-vs-oracle agreement.
# T_AND_PREFIX_CLOSURE_OVERLAP(§6.62): guard #23 cover-direction + first-match.
# T_SCHEMA_V2_CUTOVER         (§6.63): M.1 hard cutover (v1/absent reject, v2 ok).
set(TEST_ENV_AND
    ${TEST_ENV}
    "AND_ORACLE_PROD=${CMAKE_SOURCE_DIR}/tests/bitvec/bitvec_oracle_prod.py"
)
foreach(T IN ITEMS
    T_AND_COMPOSE_OK
    T_AND_ORACLE_AGREEMENT
    T_AND_PREFIX_CLOSURE_OVERLAP
    T_SCHEMA_V2_CUTOVER
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV_AND}"
        RESOURCE_LOCK xdp_fixture
        TIMEOUT 90
        SKIP_RETURN_CODE 77
    )
endforeach()

# ── §5.44 MVP-4.4 bit-vector axes 3-4: proto (exact HASH) + dst_port (range) ─
# Three NEW ctests (§6.64..§6.66) for the 4-axis AND-compose datapath. They
# reuse the production O(N) reference classifier tests/bitvec/bitvec_oracle_prod.py
# (now dual-table: --ruleset and4 selects the 4-axis table transcribed from
# config_valid_and4.yaml; the default 2-axis behaviour for §6.61 is unchanged)
# and the existing L4 injector tests/inject/inject_l4.py (--proto/--dport). All
# three touch the veth fixture (apply attaches + per-vector inject) →
# RESOURCE_LOCK xdp_fixture (guard #12). SKIP_RETURN_CODE 77 for the
# passwordless-sudo / jq preconditions.
#
# T_PROTO_AND_COMPOSE      (§6.64): proto exact-HASH AND-intersection (TCP hits,
#                                   UDP does not → routes to port-only rule).
# T_PORT_RANGE_AND_COMPOSE (§6.65): port range-membership (edges, out-of-range)
#                                   + has_port (ICMP survives only port-wildcard).
# T_AND4_ORACLE_AGREEMENT  (§6.66): table-driven 4-axis datapath-vs-oracle.
set(TEST_ENV_AND4
    ${TEST_ENV}
    "AND_ORACLE_PROD=${CMAKE_SOURCE_DIR}/tests/bitvec/bitvec_oracle_prod.py"
    "INJECT_L4=${CMAKE_SOURCE_DIR}/tests/inject/inject_l4.py"
)
foreach(T IN ITEMS
    T_PROTO_AND_COMPOSE
    T_PORT_RANGE_AND_COMPOSE
    T_AND4_ORACLE_AGREEMENT
)
    add_test(
        NAME ${T}
        COMMAND bash ${TEST_DIR}/${T}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    set_tests_properties(${T} PROPERTIES
        ENVIRONMENT "${TEST_ENV_AND4}"
        RESOURCE_LOCK xdp_fixture
        TIMEOUT 120
        SKIP_RETURN_CODE 77
    )
endforeach()
