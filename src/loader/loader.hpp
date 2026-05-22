/*
 * loader.hpp — userspace control-plane API. Two operations:
 *   attach():  load BPF, pin maps under /sys/fs/bpf/xdpmacfilter/<iface>/,
 *              populate allow-list, attach XDP in SKB (generic) mode.
 *   detach():  detach XDP from <iface> if attached, unpin maps, remove the
 *              per-iface bpffs dir.
 *
 * Errors are reported by throwing std::system_error with a code from
 * `loader_error_category()`; main() maps category+value to exit code.
 */
#pragma once

#include <cstdint>
#include <string>
#include <system_error>

#include "cli.hpp"  // AttachConfig

namespace xdpmf {

enum class LoaderError : int {
    LoadFailed         = 2,
    AttachFailed       = 3,
    AttachRefusedAlien = 4,
    DetachFailed       = 5,
    Permission         = 6,
};

/* Singleton category whose error_code values are LoaderError integers.
 * main() inspects category()==loader_error_category() and uses value()
 * directly as exit code. */
const std::error_category& loader_error_category() noexcept;

inline std::error_code make_error_code(LoaderError e) noexcept
{
    return {static_cast<int>(e), loader_error_category()};
}

/* Attach XDP program to cfg.iface, populating allow-list with cfg.allow.
 * Returns kernel-assigned BPF prog id on success.
 * Throws std::system_error on failure (see LoaderError). */
[[nodiscard]] std::uint32_t attach(const AttachConfig& cfg);

/* Detach XDP from iface and tear down per-iface bpffs dir.
 * Returns prog id of the detached program.
 * Throws std::system_error on failure (LoaderError::DetachFailed, etc.). */
[[nodiscard]] std::uint32_t detach(const std::string& iface);

}  // namespace xdpmf

namespace std {
template <>
struct is_error_code_enum<xdpmf::LoaderError> : true_type {};
}  // namespace std
