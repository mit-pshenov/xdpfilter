/*
 * loader_error.hpp — PRIVATE header (not exported, not installed).
 *
 * §5.76 (MVP-4.36) B43 D-mvp-4.36-Q1-A1: the host-only std::error_category
 * machinery (LoaderError translation + throw helper), extracted verbatim from
 * loader.cpp's anon-namespace so the libbpf-free render subset (materialize.cpp)
 * + the dryrun_harness can link the error path WITHOUT dragging loader.cpp /
 * libbpf. `loader_error_category()` + `LoaderError` + `make_error_code` already
 * live public in loader.hpp (PI-7 byte-identical); this header only adds the two
 * previously-anon helpers as external symbols.
 *
 * NOT in loader.hpp (PI-7 zero-diff streak); namespace `xdpmf`.
 */
#pragma once

#include <string>

#include "loader.hpp"  // LoaderError, loader_error_category(), make_error_code

namespace xdpmf {

/* Translate libbpf -errno into a LoaderError suitable for the given step.
 * EPERM/EACCES always map to LoaderError::Permission so users see the
 * "run as root" diagnostic regardless of which step rejected them. */
[[nodiscard]] LoaderError classify(int neg_errno, LoaderError fallback) noexcept;

[[noreturn]] void throw_loader(LoaderError code, std::string what);

}  // namespace xdpmf
