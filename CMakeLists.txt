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
    VERSION   0.1.0
    DESCRIPTION "MVP-1 L2 MAC allow-list XDP filter"
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
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

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

add_executable(xdpmacfilter
    src/loader/main.cpp
    src/loader/cli.cpp
    src/loader/loader.cpp
)
target_include_directories(xdpmacfilter PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)
# bpftool-generated skel.h uses C-style casts and other C-isms that fail
# our zero-warning C++23 build. Treat the build dir as a SYSTEM include so
# diagnostics in skel.h are suppressed by default (matching how libbpf
# headers in /usr/include are already treated).
target_include_directories(xdpmacfilter SYSTEM PRIVATE
    ${CMAKE_BINARY_DIR}
)
target_link_libraries(xdpmacfilter PRIVATE PkgConfig::LIBBPF)
add_dependencies(xdpmacfilter mac_filter_skel)

# Sanitizer injection (design §5.18): apply ASAN+UBSAN flags to the C++
# loader target ONLY, on both compile and link. target_*_options is scoped
# (unlike add_compile_options), so the flag never reaches the BPF object
# nor any other target. -fno-omit-frame-pointer keeps ASAN traces readable.
if(XDPMF_SANITIZERS)
    target_compile_options(xdpmacfilter PRIVATE
        -fsanitize=address,undefined
        -fno-omit-frame-pointer
    )
    target_link_options(xdpmacfilter PRIVATE
        -fsanitize=address,undefined
    )
endif()

enable_testing()
if(EXISTS ${CMAKE_SOURCE_DIR}/tests/CMakeLists.txt)
    add_subdirectory(tests)
endif()
