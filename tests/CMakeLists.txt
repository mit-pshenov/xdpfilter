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

# All other tests use the same veth_a/veth_b fixture → must be serialized.
foreach(T IN ITEMS
    T_LOAD_ATTACH
    T_PASS_ALLOWED
    T_DROP_DENY
    T_DROP_MALFORMED
    T_IDEMPOTENT_RELOAD
    T_NEGATION_CONTROL
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
    )
endforeach()

# Per design §6.5: this test may legitimately not be assertable on kernels
# that pad short Ethernet frames before XDP sees them.  Exit code 77 →
# ctest reports the test as Skipped (with the reason printed to stdout).
set_tests_properties(T_DROP_MALFORMED PROPERTIES SKIP_RETURN_CODE 77)

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
)
