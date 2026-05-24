# tests/CMakeLists.txt — populated by mint-tester per design §6.
#
# Tests are shell scripts driving a veth fixture; serialized via
# RESOURCE_LOCK xdp_fixture (they all touch fixed veth_a/veth_b names).
# Top-level CMakeLists.txt is expected to have called enable_testing()
# already (per design §2 FileList); we do NOT call it here to avoid
# double-init.

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
# it touches veth_a/veth_b.  TIMEOUT 180 because the embedded cmake
# configure + sanitizer build dominates the runtime.
add_test(
    NAME T_SANITIZER_BUILD
    COMMAND bash ${TEST_DIR}/T_SANITIZER_BUILD.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_SANITIZER_BUILD PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
    TIMEOUT 180
    SKIP_RETURN_CODE 77
)

# ─────────────────────────────────────────────────────────────────────────
# MVP-1.1C additions (§5.21 D1-D4 / §6.10-§6.13).
# D1/D2/D3 are pure CLI-parser tests — no root, no veth, no RESOURCE_LOCK.
# D4 needs CAP_BPF for bpf_xdp_query — uses `lo` instead of veth, so no
# RESOURCE_LOCK either (lo is shared but we make no state changes).
# All four use TIMEOUT 10 (binary launch + parse + exit only).
foreach(T IN ITEMS
    T_CLI_HELP_VERSION
    T_CLI_CAPACITY
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

# T_DETACH_NOTHING needs passwordless sudo (calls bpf_xdp_query under root).
# Per §5.22 amendment to §6.13: this entry takes RESOURCE_LOCK xdp_fixture
# so it cannot race the destructive setup window of T_BPFFS_ROOT_SYMLINK
# (§6.15) — that test transiently rmdir's /sys/fs/bpf/xdpmacfilter and a
# concurrent T_DETACH_NOTHING would either trip the new PathRefused exit 8
# (failure) or observe a wrong post-state. Test logic itself unchanged.
add_test(
    NAME T_DETACH_NOTHING
    COMMAND bash ${TEST_DIR}/T_DETACH_NOTHING.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
set_tests_properties(T_DETACH_NOTHING PROPERTIES
    ENVIRONMENT "${TEST_ENV}"
    RESOURCE_LOCK xdp_fixture
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
# exit 3.  NO RESOURCE_LOCK (does not touch the veth pair); SKIP 77 for
# require_passwordless_sudo path.
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
foreach(T IN ITEMS
    T_PASS_CIDR
    T_DROP_CIDR_NOT_IN_RANGE
    T_PASS_MAC_OR_CIDR
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
