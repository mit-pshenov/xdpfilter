/*
 * cli.hpp — argv → {Subcommand + AttachConfig|DetachConfig} parser.
 *
 * Errors are reported via `CliError` thrown by parse(); main() catches
 * and maps to exit codes per design §4.1.
 */
#pragma once

#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include "common/mac_filter.h"

namespace xdpmf {

struct AttachConfig {
    std::string             iface;
    std::vector<xdpmf_mac>   allow;   // size ≤ XDPMF_ALLOWLIST_MAX, deduplicated
};

struct DetachConfig {
    std::string iface;
};

struct HelpRequest    {};
struct VersionRequest {};

using ParsedCommand = std::variant<AttachConfig, DetachConfig, HelpRequest, VersionRequest>;

class CliError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/* Parse argv[1..argc-1]. argv[0] is the program name (ignored).
 * Throws CliError on any usage error. */
ParsedCommand parse(int argc, char* const argv[]);

/* Validate and decode a single "XX:XX:XX:XX:XX:XX" token (upper or lower).
 * Returns true on success and writes 6 octets to `out`. */
[[nodiscard]] bool parse_mac(std::string_view tok, xdpmf_mac& out) noexcept;

/* Multi-line usage text; printed by HelpRequest dispatch and on CliError. */
std::string usage_text();

/* Single-line "<prog> <version>" string for --version. */
std::string version_text();

}  // namespace xdpmf
