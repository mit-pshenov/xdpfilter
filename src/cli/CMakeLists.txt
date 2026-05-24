# src/cli/CMakeLists.txt — §5.26 Q1 R1: xdpmacfilter binary lives here
# alongside main.cpp / cli.cpp / apply.cpp. Links xdpmf_internal (STATIC)
# from the parent scope for the loader / config / yaml machinery.

add_executable(xdpmacfilter
    main.cpp
    cli.cpp
    apply.cpp
)
target_include_directories(xdpmacfilter PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}/include
)
target_include_directories(xdpmacfilter SYSTEM PRIVATE
    ${CMAKE_BINARY_DIR}
)
target_link_libraries(xdpmacfilter PRIVATE xdpmf_internal)
add_dependencies(xdpmacfilter mac_filter_skel)
