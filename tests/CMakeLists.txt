# tests/CMakeLists.txt — populated by mint-tester per design §6.
#
# Tests are shell scripts driving a veth fixture; serialized via
# RESOURCE_LOCK xdp_fixture (they all touch fixed veth_a/veth_b names).
# Top-level CMakeLists.txt is expected to have called enable_testing()
# already (per design §2 FileList); we do NOT call it here to avoid
# double-init.

set(TEST_DIR  ${CMAKE_CURRENT_SOURCE_DIR})
set(TEST_ENV
    "BUILD_DIR=${CMAKE_BINARY_DIR}"
    "SOURCE_DIR=${CMAKE_SOURCE_DIR}"
    "TEST_DIR=${TEST_DIR}"
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
