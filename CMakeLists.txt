cmake_minimum_required(VERSION 3.20)

# Force clang-19 toolchain BEFORE project() so it sticks for all languages.
if(NOT CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER clang-19 CACHE STRING "C compiler" FORCE)
endif()
if(NOT CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER clang++-19 CACHE STRING "C++ compiler" FORCE)
endif()

project(xdpmacfilter
    LANGUAGES C CXX
    VERSION   0.6.0
    DESCRIPTION "MVP-3.4 L2 MAC + L3 src-CIDR allow-list XDP filter (OR-compose) + Prometheus exporter"
)

# §5.25 P3: version-string sync — generate include/version.h from the
# project(VERSION ...) tuple above so the loader's --version output and
# the CMake project version are guaranteed to agree. The template lives
# in include/version.h.in (committed); the rendered version.h lives in
# ${CMAKE_BINARY_DIR}/include/ (NOT committed).
configure_file(
    ${CMAKE_SOURCE_DIR}/include/version.h.in
    ${CMAKE_BINARY_DIR}/include/version.h
    @ONLY
)

set(CMAKE_C_STANDARD            17)
set(CMAKE_C_STANDARD_REQUIRED   ON)
set(CMAKE_CXX_STANDARD          23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

# Zero-tolerance warning floor (lang/cpp.md pack). Warning == build failure.
add_compile_options(
    -Wall -Wextra -Wpedantic -Wconversion -Wshadow
    -fno-strict-aliasing
    -Werror
)
add_compile_options(
    $<$<COMPILE_LANGUAGE:CXX>:-Wnon-virtual-dtor>
    $<$<COMPILE_LANGUAGE:CXX>:-Woverloaded-virtual>
    $<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>
    $<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes>
    $<$<COMPILE_LANGUAGE:C>:-Wmissing-prototypes>
)

# libstdc++-12 on this host lacks <format>; libc++-19 provides it.
# Applied to C++ only — pkg-config libbpf is plain C and stays on libstdc++.
add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-stdlib=libc++>)
add_link_options(-stdlib=libc++)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf>=1.1)

# §5.25 P2: extract XDPMF_BPFFS_ROOT from src/common/mac_filter.h so the
# test fixture (tests/lib/common.sh) inherits the SAME pin root the loader
# compiles in — no silent drift if the macro value is ever changed. The
# extracted value MUST be exactly "/sys/fs/bpf/xdpmacfilter" today; future
# renames here flow automatically into tests/pins.sh.
execute_process(
    COMMAND sed -nE "s@^[ \\t]*#define[ \\t]+XDPMF_BPFFS_ROOT[ \\t]+\"([^\"]+)\".*@\\1@p"
            ${CMAKE_SOURCE_DIR}/src/common/mac_filter.h
    OUTPUT_VARIABLE XDPMF_BPFFS_ROOT
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT XDPMF_BPFFS_ROOT)
    message(FATAL_ERROR
        "§5.25 P2: failed to extract XDPMF_BPFFS_ROOT from "
        "src/common/mac_filter.h — macro renamed or removed?")
endif()
configure_file(
    ${CMAKE_SOURCE_DIR}/tests/lib/pins.sh.in
    ${CMAKE_BINARY_DIR}/tests/pins.sh
    @ONLY
)

# XDPMF_SANITIZERS (design §5.18): test-only ASAN+UBSAN build mode for the
# C++ loader. Default OFF — when OFF, the build is byte-identical to the
# pre-amendment build (no flag injection, no extra link deps). When ON, the
# flags are applied via target_compile_options/target_link_options scoped
# to the xdpmacfilter binary ONLY (see below) — they MUST NOT propagate to
# the BPF object (clang -target bpf has no userspace sanitizer runtime).
option(XDPMF_SANITIZERS "Build C++ loader with ASAN+UBSAN (test-only)" OFF)

include(${CMAKE_SOURCE_DIR}/cmake/BpfBuild.cmake)

add_bpf_object(mac_filter ${CMAKE_SOURCE_DIR}/src/bpf/mac_filter.bpf.c)
add_bpf_skeleton(mac_filter)

# §5.26 Q1 R1: internal STATIC library aggregates src/lib/*.cpp (loader +
# config + yaml_subset). No installed headers; no SONAME; no public ABI
# surface (library promotion is MVP-3.6+ optional branch).
add_library(xdpmf_internal STATIC
    src/lib/loader.cpp
    src/lib/config.cpp
    src/lib/cidr.cpp          # §5.27 (MVP-3.2) — IPv4 CIDR parser
    src/lib/yaml_subset.cpp
)
target_include_directories(xdpmf_internal PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}/include
)
# bpftool-generated skel.h uses C-style casts and other C-isms; treat the
# build dir as SYSTEM include so its diagnostics are suppressed by default.
target_include_directories(xdpmf_internal SYSTEM PRIVATE
    ${CMAKE_BINARY_DIR}
)
target_link_libraries(xdpmf_internal PUBLIC PkgConfig::LIBBPF)
add_dependencies(xdpmf_internal mac_filter_skel)

add_subdirectory(src/cli)

# §5.29 (MVP-3.4) D-3.4-1 + D-3.4-2: xdpmf-exporter is a SEPARATE binary
# living under src/exporter/, linking the same xdpmf_internal STATIC lib as
# xdpmacfilter — no third-party HTTP library dep (D-3.4-3). Read-only by
# construction (PI-31): no map mutation / attach / detach. install() goes
# alongside the loader under ${CMAKE_INSTALL_BINDIR}.
add_executable(xdpmf-exporter
    src/exporter/main.cpp
    src/exporter/http.cpp
    src/exporter/prom_format.cpp
    src/exporter/stats_reader.cpp
)
target_include_directories(xdpmf-exporter PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}/include
)
target_include_directories(xdpmf-exporter SYSTEM PRIVATE
    ${CMAKE_BINARY_DIR}
)
target_link_libraries(xdpmf-exporter PRIVATE xdpmf_internal)
add_dependencies(xdpmf-exporter mac_filter_skel)

include(GNUInstallDirs)
install(TARGETS xdpmacfilter xdpmf-exporter
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Sanitizer injection (design §5.18; §5.26 Q1 R1 update; §5.29 extension):
# apply ASAN+UBSAN flags to xdpmf_internal AND BOTH binaries so a sanitizer-
# enabled build doesn't mix instrumented and non-instrumented TUs (ASAN
# refuses mixed objects at link/runtime). target_*_options is scoped; flag
# never reaches the BPF object.
if(XDPMF_SANITIZERS)
    target_compile_options(xdpmf_internal PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    target_compile_options(xdpmacfilter PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(xdpmacfilter PRIVATE
        -fsanitize=address,undefined
    )
    target_compile_options(xdpmf-exporter PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(xdpmf-exporter PRIVATE
        -fsanitize=address,undefined
    )
endif()

# §5.28 D-3.3-9: install the systemd template unit at `cmake --install`
# time. Default ON so the conventional packaging path "just works";
# operators who handle the unit out-of-band (distro packagers) can set
# -DXDPMF_INSTALL_SYSTEMD_UNIT=OFF. System install of the unit into
# /etc/systemd/system or daemon-reload is operator's call (not the build).
#
# §5.29 (MVP-3.4) extension: also install the exporter unit (single-instance,
# Q5 N3) under the same option — same operator deploy story for both units.
option(XDPMF_INSTALL_SYSTEMD_UNIT "Install systemd unit template" ON)
if(XDPMF_INSTALL_SYSTEMD_UNIT)
    install(FILES
            ${CMAKE_SOURCE_DIR}/systemd/xdpmacfilter@.service
            ${CMAKE_SOURCE_DIR}/systemd/xdpmf-exporter.service
        DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system/)
endif()

enable_testing()
if(EXISTS ${CMAKE_SOURCE_DIR}/tests/CMakeLists.txt)
    add_subdirectory(tests)
endif()
