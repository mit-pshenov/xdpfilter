#!/bin/bash
# T_BUILD — design §6.1: build cleanliness (acceptance #1).
#
# Trigger : clean configure+build of SOURCE_DIR into a fresh temp dir.
# Outcome : exit 0, zero `warning:` matches in the combined cmake/build log.
#
# We use a separate /tmp build dir so this test does NOT clobber the
# build artifacts that the other tests depend on (those tests are run
# from ${BUILD_DIR}).
set -euo pipefail

: "${SOURCE_DIR:?SOURCE_DIR must be set by ctest}"

TMP_BUILD=$(mktemp -d -t xdpmf-build-XXXXXX)
LOG="${TMP_BUILD}/buildlog.txt"
trap 'rm -rf "${TMP_BUILD}"' EXIT

echo "=== T_BUILD: configure in ${TMP_BUILD}"
cmake -S "${SOURCE_DIR}" -B "${TMP_BUILD}" -DCMAKE_BUILD_TYPE=Release \
        2>&1 | tee -a "${LOG}"

echo "=== T_BUILD: build"
cmake --build "${TMP_BUILD}" -j"$(nproc)" 2>&1 | tee -a "${LOG}"

echo "=== T_BUILD: scanning for warnings"
# Match canonical clang/gcc warning lines: "<file>:<line>:<col>: warning:"
# or generic "warning:" lines. Exclude empty results.
if grep -E '(^|[: ])warning:' "${LOG}" >/dev/null; then
    echo "FAIL: build emitted compiler warnings:" >&2
    grep -nE '(^|[: ])warning:' "${LOG}" >&2 || true
    exit 1
fi

# Sanity floor: the loader binary must actually exist after build (proves
# the build did real work and produced the artefact under test).
if ! find "${TMP_BUILD}" -maxdepth 5 -type f -executable -name xdpfilter \
        | grep -q .; then
    echo "FAIL: xdpfilter binary not produced by build" >&2
    exit 1
fi

echo "PASS: T_BUILD (no warnings, loader binary produced)"
