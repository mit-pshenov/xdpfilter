/*
 * config.hpp — typed schema for the §5.26/§5.27 YAML config.
 *
 * The schema (schema_version 2; v1 retired §5.43) is a top-level block mapping with:
 *   schema_version: 2     (REQUIRED; MUST be 2; supported set {2} — §5.43
 *                          HG-mvp-4.3-3 hard cutover from {1})
 *   interface: <name>     (optional; redundant with CLI --iface)
 *   default_action: drop|pass    (REQUIRED)
 *   rules:                (optional; list of rule mappings)
 *     - id: <u32>         (REQUIRED; range [0, XDPMF_ALLOWLIST_MAX-1])
 *       action: pass|drop (REQUIRED)
 *       match:            (REQUIRED mapping; rule 7: at-least-one of the 9
 *                          match axes required — see config.cpp error string)
 *         mac: "AA:BB:..."         (§5.47 — src-MAC exact-match axis; re-accepted in v2)
 *         src_cidr: "10.0.0.0/8"   (§5.27 — IPv4 dotted-decimal CIDR; v6 rejected)
 *
 * All validation failures throw std::system_error{LoaderError::ConfigError, ...}
 * with stderr starting "xdpfilter: config error: ..." per §5.26/§5.27.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "common/xdpfilter.h"  // struct xdpmf_mac, struct xdpmf_cidr_v4, XDPMF_ALLOWLIST_MAX
#include "yaml_subset.hpp"

namespace xdpmf {

enum class DefaultAction : std::uint8_t { Drop = 0, Pass = 1 };
enum class RuleAction    : std::uint8_t { Drop = 0, Pass = 1 };

// §5.44 (MVP-4.4) D-mvp-4.4-PORT-GRAMMAR: an inclusive dst_port range
// [lo,hi] (a single port is lo==hi). Both endpoints ∈ [0,65535], lo ≤ hi
// (enforced at parse). One range per rule (multi = multiple rules — OOS).
struct PortRange {
    std::uint16_t lo = 0;
    std::uint16_t hi = 0;
};

struct RuleMatch {
    std::optional<xdpmf_mac>     mac;       // §5.47 (MVP-4.7) — src-MAC exact-match axis (re-accepted in v2)
    std::optional<xdpmf_cidr_v4> dst_cidr;  // §5.43 NEW (MVP-4.3) — IPv4 dst-CIDR axis (#1 selection gap)
    std::optional<xdpmf_cidr_v4> src_cidr;  // §5.27 (Q3 K2) — IPv4 src-CIDR axis
    std::optional<std::uint8_t>  protocol;  // §5.44 NEW (MVP-4.4) — L4 proto axis (exact-match; tcp/udp/icmp/numeric)
    std::optional<PortRange>     dst_port;  // §5.44 NEW (MVP-4.4) — L4 dst-port axis (inclusive range)
    std::optional<std::uint16_t> vlan;      // §5.45 NEW (MVP-4.5) — outer 802.1Q VID axis (exact-match; [0,4095])
    std::optional<xdpmf_cidr_v6> dst_cidr6; // §5.53 NEW (MVP-4.13) — IPv6 dst-CIDR axis (LPM)
    std::optional<xdpmf_cidr_v6> src_cidr6; // §5.53 NEW (MVP-4.13) — IPv6 src-CIDR axis (LPM)
    std::optional<std::uint16_t> ethertype; // §5.54 NEW (MVP-4.14) — post-VLAN inner EtherType axis (exact-match HASH; named/hex/numeric, host order)
};

struct Rule {
    std::uint32_t id     = 0;
    RuleAction    action = RuleAction::Drop;
    RuleMatch     match;
};

struct Config {
    std::uint32_t              schema_version = 2;
    std::optional<std::string> iface;
    DefaultAction              default_action = DefaultAction::Drop;
    std::vector<Rule>          rules;
};

/* Validates `root` against the §5.26 cycle-1 schema and produces a Config.
 * `file_path_for_diagnostics` is woven into thrown ConfigError messages so
 * ops scripts can correlate errors with the offending YAML file.
 *
 * Throws std::system_error{LoaderError::ConfigError, ...} on any rule violation. */
[[nodiscard]] Config validate(const yaml::Node& root,
                              std::string_view  file_path_for_diagnostics);

}  // namespace xdpmf
