/*
 * config.cpp — schema validator: yaml::Node → xdpmf::Config (cycle 1 schema).
 *
 * Per §5.26 schema rules (1-6): default_action REQUIRED & ∈ {drop,pass};
 * rules' id ∈ [0,63] unique; action ∈ {pass,drop}; match.mac REQUIRED with
 * canonical 17-char MAC format; only `mac` match type allowed in schema_version 1.
 *
 * Errors: std::system_error{LoaderError::ConfigError, ...}, stderr shape
 *   "xdpmacfilter: config error: <feature>: <file>:<line>:<col>[: <message>]".
 */
#include "config.hpp"
#include "loader.hpp"

#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_set>
#include <utility>

namespace xdpmf {

namespace {

[[noreturn]] void throw_cfg(std::string_view feature,
                            std::string_view file,
                            std::uint32_t    line,
                            std::uint32_t    col,
                            std::string_view message = {})
{
    std::string what =
        message.empty()
            ? std::format("xdpmacfilter: config error: {}: {}:{}:{}",
                          feature, file, line, col)
            : std::format("xdpmacfilter: config error: {}: {}:{}:{}: {}",
                          feature, file, line, col, message);
    throw std::system_error(make_error_code(LoaderError::ConfigError), std::move(what));
}

[[nodiscard]] const yaml::Node* find_key(const yaml::Node& m, std::string_view key) noexcept
{
    for (const std::pair<std::string, yaml::Node>& kv : m.mapping) {
        if (kv.first == key) return &kv.second;
    }
    return nullptr;
}

/* Parse "XX:XX:XX:XX:XX:XX" (case-insensitive) into xdpmf_mac. Returns true
 * iff valid. Same shape as cli.cpp's parse_mac but isolated here to avoid
 * cli.hpp ↔ config.hpp circular include. */
[[nodiscard]] constexpr int hex_nibble(char c) noexcept
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

[[nodiscard]] bool parse_mac_canonical(std::string_view tok, xdpmf_mac& out) noexcept
{
    constexpr std::size_t kExpectedLen = 17;
    if (tok.size() != kExpectedLen) return false;
    for (std::size_t i = 0; i < 6; ++i) {
        const std::size_t pos = i * 3;
        const int hi = hex_nibble(tok[pos]);
        const int lo = hex_nibble(tok[pos + 1]);
        if (hi < 0 || lo < 0) return false;
        if (i < 5 && tok[pos + 2] != ':') return false;
        out.octets[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

[[nodiscard]] std::uint32_t parse_u32_or_throw(const yaml::Node& scalar_node,
                                                std::string_view  file,
                                                std::string_view  field)
{
    if (scalar_node.kind != yaml::Node::Kind::Scalar) {
        throw_cfg("invalid integer", file, scalar_node.line, scalar_node.col,
                  std::format("{} requires a non-negative integer", field));
    }
    const std::string& s = scalar_node.scalar;
    if (s.empty()) {
        throw_cfg("invalid integer", file, scalar_node.line, scalar_node.col,
                  std::format("{} is empty", field));
    }
    // Q-HG1 grammar accepts signed decimal; we additionally require >= 0 here.
    std::uint64_t v = 0;
    std::size_t i = 0;
    if (s[0] == '-') {
        throw_cfg("integer out of range", file, scalar_node.line, scalar_node.col,
                  std::format("{} must be non-negative", field));
    }
    for (; i < s.size(); ++i) {
        const char ch = s[i];
        if (ch < '0' || ch > '9') {
            throw_cfg("invalid integer", file, scalar_node.line, scalar_node.col,
                      std::format("{} contains non-digit '{}'", field, ch));
        }
        v = v * 10u + static_cast<std::uint64_t>(ch - '0');
        if (v > 0xFFFFFFFFu) {
            throw_cfg("integer out of range", file, scalar_node.line, scalar_node.col,
                      std::format("{} exceeds u32 max", field));
        }
    }
    return static_cast<std::uint32_t>(v);
}

[[nodiscard]] DefaultAction parse_default_action(const yaml::Node& v, std::string_view file)
{
    if (v.kind != yaml::Node::Kind::Scalar) {
        throw_cfg("default_action", file, v.line, v.col,
                  "default_action must be 'drop' or 'pass'");
    }
    if (v.scalar == "drop") return DefaultAction::Drop;
    if (v.scalar == "pass") return DefaultAction::Pass;
    throw_cfg("default_action", file, v.line, v.col,
              "default_action must be 'drop' or 'pass'");
}

[[nodiscard]] RuleAction parse_rule_action(const yaml::Node& v, std::string_view file)
{
    if (v.kind != yaml::Node::Kind::Scalar) {
        throw_cfg("rule action", file, v.line, v.col,
                  "rule action must be 'pass' or 'drop'");
    }
    if (v.scalar == "drop") return RuleAction::Drop;
    if (v.scalar == "pass") return RuleAction::Pass;
    throw_cfg("rule action", file, v.line, v.col,
              "rule action must be 'pass' or 'drop'");
}

}  // namespace

Config validate(const yaml::Node& root, std::string_view file)
{
    if (root.kind != yaml::Node::Kind::Mapping) {
        throw_cfg("schema", file, root.line, root.col,
                  "top-level must be a mapping");
    }

    Config out;

    // schema_version (optional; default 1; supported {1}).
    if (const yaml::Node* sv = find_key(root, "schema_version")) {
        const std::uint32_t v = parse_u32_or_throw(*sv, file, "schema_version");
        if (v != 1u) {
            throw_cfg("schema_version", file, sv->line, sv->col,
                      std::format("unsupported schema_version: {} (supported: 1)", v));
        }
        out.schema_version = v;
    } else {
        out.schema_version = 1;
    }

    // interface (optional).
    if (const yaml::Node* iface = find_key(root, "interface")) {
        if (iface->kind != yaml::Node::Kind::Scalar || iface->scalar.empty()) {
            throw_cfg("interface", file, iface->line, iface->col,
                      "interface must be a non-empty string");
        }
        out.iface = iface->scalar;
    }

    // default_action (REQUIRED).
    const yaml::Node* da = find_key(root, "default_action");
    if (da == nullptr) {
        throw_cfg("default_action", file, root.line, root.col,
                  "default_action is required");
    }
    out.default_action = parse_default_action(*da, file);

    // rules (optional; absent or null → empty).
    if (const yaml::Node* rs = find_key(root, "rules")) {
        if (rs->kind == yaml::Node::Kind::Null) {
            // empty rules
        } else if (rs->kind != yaml::Node::Kind::Sequence) {
            throw_cfg("rules", file, rs->line, rs->col,
                      "rules must be a block sequence");
        } else {
            std::unordered_set<std::uint32_t> seen_ids;
            seen_ids.reserve(rs->sequence.size());
            for (const yaml::Node& entry : rs->sequence) {
                if (entry.kind != yaml::Node::Kind::Mapping) {
                    throw_cfg("rule", file, entry.line, entry.col,
                              "rule entry must be a mapping");
                }
                Rule r{};

                const yaml::Node* id_node = find_key(entry, "id");
                if (id_node == nullptr) {
                    throw_cfg("rule id", file, entry.line, entry.col,
                              "rule.id is required");
                }
                const std::uint32_t id = parse_u32_or_throw(*id_node, file, "rule.id");
                if (id >= static_cast<std::uint32_t>(XDPMF_ALLOWLIST_MAX)) {
                    throw_cfg("rule id out of range", file, id_node->line, id_node->col,
                              std::format("rule.id {} >= XDPMF_ALLOWLIST_MAX={}",
                                          id, XDPMF_ALLOWLIST_MAX));
                }
                if (!seen_ids.insert(id).second) {
                    throw_cfg("duplicate rule id", file, id_node->line, id_node->col,
                              std::format("duplicate rule id: {}", id));
                }
                r.id = id;

                const yaml::Node* act = find_key(entry, "action");
                if (act == nullptr) {
                    throw_cfg("rule action", file, entry.line, entry.col,
                              "rule.action is required");
                }
                r.action = parse_rule_action(*act, file);

                const yaml::Node* match = find_key(entry, "match");
                if (match == nullptr) {
                    throw_cfg("rule match", file, entry.line, entry.col,
                              "rule.match is required");
                }
                if (match->kind != yaml::Node::Kind::Mapping) {
                    throw_cfg("rule match", file, match->line, match->col,
                              "rule.match must be a mapping");
                }
                // Schema_version 1: exactly one match type — `mac`.
                for (const std::pair<std::string, yaml::Node>& kv : match->mapping) {
                    if (kv.first != "mac") {
                        throw_cfg("unsupported match type", file,
                                  kv.second.line, kv.second.col,
                                  std::format("match type '{}' not supported in schema_version 1",
                                              kv.first));
                    }
                }
                const yaml::Node* mac_node = find_key(*match, "mac");
                if (mac_node == nullptr) {
                    throw_cfg("rule match mac", file, match->line, match->col,
                              "rule.match.mac is required");
                }
                if (mac_node->kind != yaml::Node::Kind::Scalar) {
                    throw_cfg("rule match mac", file, mac_node->line, mac_node->col,
                              "rule.match.mac must be a string");
                }
                xdpmf_mac mac{};
                if (!parse_mac_canonical(mac_node->scalar, mac)) {
                    throw_cfg("invalid MAC", file, mac_node->line, mac_node->col,
                              std::format("'{}' is not a valid MAC (expected XX:XX:XX:XX:XX:XX)",
                                          mac_node->scalar));
                }
                r.match.mac = mac;

                // Reject unknown sibling keys in the rule (forward-compat hinge).
                for (const std::pair<std::string, yaml::Node>& kv : entry.mapping) {
                    if (kv.first != "id" && kv.first != "action" && kv.first != "match") {
                        throw_cfg("unknown rule field", file, kv.second.line, kv.second.col,
                                  std::format("unknown rule field '{}'", kv.first));
                    }
                }

                out.rules.push_back(std::move(r));
            }
        }
    }

    // Reject unknown top-level keys (forward-compat hinge; new top-level fields
    // require schema_version bump per §5.26 Q5 migration policy).
    for (const std::pair<std::string, yaml::Node>& kv : root.mapping) {
        if (kv.first != "schema_version" && kv.first != "interface"
            && kv.first != "default_action" && kv.first != "rules") {
            throw_cfg("unknown top-level field", file, kv.second.line, kv.second.col,
                      std::format("unknown top-level field '{}'", kv.first));
        }
    }

    return out;
}

}  // namespace xdpmf
