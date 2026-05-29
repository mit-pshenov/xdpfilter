/*
 * config.cpp — schema validator: yaml::Node → xdpmf::Config (cycles 1+2 schema).
 *
 * Per §5.26 schema rules (1-6) + §5.27 rules (7-11): default_action REQUIRED &
 * ∈ {drop,pass}; rules' id ∈ [0,63] unique; action ∈ {pass,drop}; each rule's
 * match.* mapping MUST contain at-least-one-of {mac, src_cidr} (§5.27 rule 7,
 * superseding §5.26 rule 5's mac-REQUIRED). `mac` parses canonical 17-char
 * XX:XX:..., `src_cidr` parses IPv4 A.B.C.D/N with host-bits-zero (§5.27 rule 8);
 * IPv6 strings rejected at the validator (§5.27 rule 9 / HG-3.2-1).
 *
 * Errors: std::system_error{LoaderError::ConfigError, ...}, stderr shape
 *   "xdpmacfilter: config error: <feature>: <file>:<line>:<col>[: <message>]"
 * EXCEPT CIDR-validation failures, which use cidr::parse_cidr_v4()'s
 * §5.27-catalogue stderr shape (one of {malformed CIDR: ..., IPv6 CIDR not
 * supported until MVP-3.2.5: ...}).
 */
#include "config.hpp"
#include "cidr.hpp"
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

/* §5.43 (MVP-4.3) HG-mvp-4.3-2: MAC matching is DEFERRED in schema_version 2
 * — the `mac` match-key is rejected at parse (D-mvp-4.3-MAC-GRAMMAR), so the
 * prior canonical-MAC parser (hex_nibble / parse_mac_canonical) is no longer
 * reachable from this validator and was removed. It returns with the MAC-axis
 * slice (mvp-4.5). */

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

    // §5.43 (MVP-4.3) HG-mvp-4.3-3 M.1 hard cutover: supported set {1}→{2}.
    // schema_version is now REQUIRED and MUST be 2 — both absent AND v1
    // (and any other value) hard-reject with a re-author diagnostic
    // (ConfigError exit 9). PO-confirmed safe (0 deployments).
    if (const yaml::Node* sv = find_key(root, "schema_version")) {
        const std::uint32_t v = parse_u32_or_throw(*sv, file, "schema_version");
        if (v != 2u) {
            throw_cfg("schema_version", file, sv->line, sv->col,
                      std::format("unsupported schema_version: {} (supported: 2); "
                                  "re-author config to schema_version 2", v));
        }
        out.schema_version = v;
    } else {
        throw_cfg("schema_version", file, root.line, root.col,
                  "schema_version is required and must be 2; "
                  "re-author config to schema_version 2");
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
                // §5.43 (MVP-4.3) D-mvp-4.3-MAC-GRAMMAR: the v2 accepted
                // match-key set is {dst_cidr, src_cidr}. `mac` is REJECTED
                // (not silently ignored) with a MAC-deferred diagnostic — a
                // hard cutover should fail loud, not enforce a no-op MAC rule
                // the operator believes is live (HG-mvp-4.3-2). Any other key
                // (cidr, port, vlan, ...) → ConfigError exit 9.
                for (const std::pair<std::string, yaml::Node>& kv : match->mapping) {
                    if (kv.first == "mac") {
                        throw_cfg("unsupported match type", file,
                                  kv.second.line, kv.second.col,
                                  "MAC matching deferred; schema_version 2 supports "
                                  "dst_cidr + src_cidr");
                    }
                    if (kv.first != "dst_cidr" && kv.first != "src_cidr") {
                        throw_cfg("unsupported match type", file,
                                  kv.second.line, kv.second.col,
                                  std::format("match type '{}' not supported in schema_version 2",
                                              kv.first));
                    }
                }
                // §5.43 v2 match grammar: each rule's match MUST contain AT
                // LEAST ONE of {dst_cidr, src_cidr}. Empty match: {} → exit 9.
                const yaml::Node* dst_cidr_node = find_key(*match, "dst_cidr");
                const yaml::Node* src_cidr_node = find_key(*match, "src_cidr");
                if (dst_cidr_node == nullptr && src_cidr_node == nullptr) {
                    throw_cfg("rule match", file, match->line, match->col,
                              "rule must specify 'dst_cidr' or 'src_cidr' (or both)");
                }
                if (dst_cidr_node != nullptr) {
                    if (dst_cidr_node->kind != yaml::Node::Kind::Scalar) {
                        throw_cfg("rule match dst_cidr", file,
                                  dst_cidr_node->line, dst_cidr_node->col,
                                  "rule.match.dst_cidr must be a string");
                    }
                    // §5.43 PI-mvp-4.3-DSTCIDR: parse via the SAME
                    // cidr::parse_cidr_v4 as src_cidr (IPv4 dotted-CIDR;
                    // IPv6 rejected; host-bits-zero enforced).
                    r.match.dst_cidr = cidr::parse_cidr_v4(
                        dst_cidr_node->scalar, file,
                        dst_cidr_node->line, dst_cidr_node->col);
                }
                if (src_cidr_node != nullptr) {
                    if (src_cidr_node->kind != yaml::Node::Kind::Scalar) {
                        throw_cfg("rule match src_cidr", file,
                                  src_cidr_node->line, src_cidr_node->col,
                                  "rule.match.src_cidr must be a string");
                    }
                    // §5.27 §4.1 stderr message catalogue: cidr::parse_cidr_v4
                    // throws ConfigError with one of {malformed CIDR: ...,
                    // IPv6 CIDR not supported until MVP-3.2.5: ...} —
                    // bypassing throw_cfg's feature/file prefix so the
                    // catalogue text drives the operator-facing diagnostic.
                    r.match.src_cidr = cidr::parse_cidr_v4(
                        src_cidr_node->scalar, file,
                        src_cidr_node->line, src_cidr_node->col);
                }

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
