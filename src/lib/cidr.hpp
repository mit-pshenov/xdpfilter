/*
 * cidr.hpp — IPv4 CIDR string parser (§5.27 MVP-3.2).
 *
 * Accepts ONLY IPv4 dotted-decimal CIDR notation "A.B.C.D/N" where
 * 0 ≤ N ≤ 32 and the host bits below the prefix are zero. v6 strings
 * (anything containing ':') are rejected per HG-3.2-1.
 *
 * All failures throw std::system_error{LoaderError::ConfigError, ...} with
 * stderr starting "xdpmacfilter: config error: ..." per §5.27 §4.1
 * message catalogue. Pure parser — no I/O, no kernel touch.
 */
#pragma once

#include <cstdint>
#include <string_view>

#include "common/mac_filter.h"  // struct xdpmf_cidr_v4

namespace xdpmf::cidr {

/* Parse `s` into an xdpmf_cidr_v4{prefixlen, addr_be}.
 *
 * `addr` is returned in NETWORK BYTE ORDER (matches iphdr.saddr on the
 * wire — no swap needed on the BPF side). The validator enforces that
 * all bits below `prefixlen` are zero (host-bits-set → ConfigError).
 *
 * `file_path_for_diagnostics`, `line`, `col` are woven into the thrown
 * what() so ops scripts can correlate validation errors with the
 * offending YAML location (per §5.26 throw_cfg() pattern).
 *
 * Throws std::system_error{LoaderError::ConfigError, ...} on any
 * malformed input per the §5.27 §4.1 stderr message catalogue. */
[[nodiscard]] xdpmf_cidr_v4 parse_cidr_v4(std::string_view s,
                                          std::string_view file_path_for_diagnostics,
                                          std::uint32_t    line,
                                          std::uint32_t    col);

}  // namespace xdpmf::cidr
