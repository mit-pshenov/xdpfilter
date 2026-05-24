/*
 * config.hpp — typed schema for the §5.26 MVP-3.1 YAML config.
 *
 * The schema (cycle 1) is a top-level block mapping with:
 *   schema_version: 1     (optional; default 1; supported set {1})
 *   interface: <name>     (optional; redundant with CLI --iface)
 *   default_action: drop|pass    (REQUIRED)
 *   rules:                (optional; list of rule mappings)
 *     - id: <u32>         (REQUIRED; range [0, XDPMF_ALLOWLIST_MAX-1])
 *       action: pass|drop (REQUIRED)
 *       match:            (REQUIRED mapping)
 *         mac: "AA:BB:..." (REQUIRED in cycle 1; only match type allowed)
 *
 * All validation failures throw std::system_error{LoaderError::ConfigError, ...}
 * with stderr starting "xdpmacfilter: config error: ..." per §5.26.
 */
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "common/mac_filter.h"  // struct xdpmf_mac, XDPMF_ALLOWLIST_MAX
#include "yaml_subset.hpp"

namespace xdpmf {

enum class DefaultAction : std::uint8_t { Drop = 0, Pass = 1 };
enum class RuleAction    : std::uint8_t { Drop = 0, Pass = 1 };

struct RuleMatch {
    std::optional<xdpmf_mac> mac;  // cycle 1: MAC-only
};

struct Rule {
    std::uint32_t id     = 0;
    RuleAction    action = RuleAction::Drop;
    RuleMatch     match;
};

struct Config {
    std::uint32_t              schema_version = 1;
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
