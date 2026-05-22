# cmake/BpfBuild.cmake — helpers for compiling BPF objects and generating
# libbpf skeleton headers. Single-purpose: keep top-level CMakeLists.txt
# free of clang/bpftool invocation noise.

find_program(CLANG_BPF_EXE NAMES clang-19 clang REQUIRED)
find_program(BPFTOOL_EXE   NAMES bpftool          REQUIRED)

# Architecture define for vmlinux.h CO-RE — kernel headers gate per-arch
# fields on __TARGET_ARCH_* macros (x86 only for MVP-1).
set(_XDPMF_BPF_ARCH_DEFINE "-D__TARGET_ARCH_x86")

# add_bpf_object(<name> <source.bpf.c>)
#   Produces ${CMAKE_BINARY_DIR}/<name>.bpf.o via `clang -target bpf`.
#   Re-runs when the source or any shared header changes.
function(add_bpf_object name source)
    set(obj ${CMAKE_BINARY_DIR}/${name}.bpf.o)

    file(GLOB _shared_headers
        ${CMAKE_SOURCE_DIR}/src/common/*.h
        ${CMAKE_SOURCE_DIR}/include/*.h
    )

    add_custom_command(
        OUTPUT  ${obj}
        COMMAND ${CLANG_BPF_EXE}
                -target bpf
                -O2 -g
                -Wall -Wextra
                ${_XDPMF_BPF_ARCH_DEFINE}
                -I${CMAKE_SOURCE_DIR}/include
                -I${CMAKE_SOURCE_DIR}/src
                -c ${source}
                -o ${obj}
        DEPENDS ${source} ${_shared_headers}
        COMMENT "BPF compile ${name}.bpf.o"
        VERBATIM
    )

    add_custom_target(${name}_bpf ALL DEPENDS ${obj})
    set_target_properties(${name}_bpf PROPERTIES
        BPF_OBJECT_PATH ${obj}
    )
endfunction()

# add_bpf_skeleton(<name>)
#   Generates ${CMAKE_BINARY_DIR}/<name>.skel.h via `bpftool gen skeleton`,
#   depending on <name>.bpf.o produced by add_bpf_object().
function(add_bpf_skeleton name)
    set(obj  ${CMAKE_BINARY_DIR}/${name}.bpf.o)
    set(skel ${CMAKE_BINARY_DIR}/${name}.skel.h)

    add_custom_command(
        OUTPUT  ${skel}
        COMMAND ${BPFTOOL_EXE} gen skeleton ${obj} > ${skel}
        DEPENDS ${obj}
        COMMENT "BPF skeleton ${name}.skel.h"
        VERBATIM
    )

    add_custom_target(${name}_skel ALL DEPENDS ${skel})
    add_dependencies(${name}_skel ${name}_bpf)
endfunction()
