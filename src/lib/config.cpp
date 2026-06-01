/*
 * config.cpp — schema validator: yaml::Node → xdpmf::Config (cycles 1+2 schema).
 *
 * Per §5.26 schema rules (1-6) + §5.27 rules (7-11): default_action REQUIRED &
 * ∈ {drop,pass}; rules' id ∈ [0,63] unique; action ∈ {pass,drop}; each rule's
 * match.* mapping MUST contain at-least-one of the 9 match axes (rule 7,
 * superseding §5.26 rule 5's mac-REQUIRED; see the config.cpp error string for
 * the full enumeration). `mac` parses canonical 17-char
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
#include <limits>
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

/* §5.47 (MVP-4.7): MAC matching is ACCEPTED in schema_version 2 — the `mac`
 * match-key parses to a src-MAC exact-match axis via the canonical-MAC parser
 * (hex_nibble / parse_mac_canonical) restored for the MAC-axis slice. */

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
        // §5.62 (MVP-4.22) R-3 / D-mvp-4.22-INT-OVERFLOW-DEFENSE: pre-multiply
        // overflow guard — reject explicitly AT the multiply, robust to a future
        // wider bound / accumulator-type change. Cannot reject the in-range
        // maximum (4294967295 ≪ this ceiling). Defense-in-depth, NOT a live-bug
        // fix; the post-check below still enforces the exact u32 bound.
        if (v > (std::numeric_limits<std::uint64_t>::max() - 9u) / 10u) {
            throw_cfg("integer out of range", file, scalar_node.line, scalar_node.col,
                      std::format("{} exceeds u32 max", field));
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

/* §5.44 (MVP-4.4) shared bounded base-10 parse of a non-negative integer
 * scalar with an explicit inclusive upper bound. Used by the protocol +
 * dst_port grammars (both reject signs, empty, non-digits, and overflow with
 * a field-named ConfigError exit 9). Returns the parsed value. */
[[nodiscard]] std::uint32_t parse_bounded_uint(std::string_view s,
                                               std::uint32_t    max_inclusive,
                                               std::string_view file,
                                               std::uint32_t    line,
                                               std::uint32_t    col,
                                               std::string_view field)
{
    if (s.empty()) {
        throw_cfg("invalid integer", file, line, col,
                  std::format("{} is empty", field));
    }
    std::uint64_t v = 0;
    for (const char ch : s) {
        if (ch < '0' || ch > '9') {
            throw_cfg("invalid integer", file, line, col,
                      std::format("{} contains non-digit '{}'", field, ch));
        }
        // §5.62 (MVP-4.22) R-3 / D-mvp-4.22-INT-OVERFLOW-DEFENSE: pre-multiply
        // overflow guard (see parse_u32_or_throw). Robust to a future wider
        // bound / accumulator-type change; cannot reject an in-range maximum.
        // The post-check below still enforces the exact inclusive bound.
        if (v > (std::numeric_limits<std::uint64_t>::max() - 9u) / 10u) {
            throw_cfg("integer out of range", file, line, col,
                      std::format("{} must be in [0,{}]", field, max_inclusive));
        }
        v = v * 10u + static_cast<std::uint64_t>(ch - '0');
        if (v > max_inclusive) {
            throw_cfg("integer out of range", file, line, col,
                      std::format("{} must be in [0,{}]", field, max_inclusive));
        }
    }
    return static_cast<std::uint32_t>(v);
}

/* §5.44 (MVP-4.4) D-mvp-4.4-PROTO-GRAMMAR: parse a `protocol` scalar — a name
 * {tcp→6, udp→17, icmp→1} OR a numeric IP-protocol number ∈ [0,255]. Unknown
 * name / out-of-range → ConfigError exit 9. */
[[nodiscard]] std::uint8_t parse_protocol(const yaml::Node& v, std::string_view file)
{
    if (v.kind != yaml::Node::Kind::Scalar || v.scalar.empty()) {
        throw_cfg("rule match protocol", file, v.line, v.col,
                  "protocol must be a name (tcp/udp/icmp) or a number in [0,255]");
    }
    if (v.scalar == "tcp")  return 6u;
    if (v.scalar == "udp")  return 17u;
    if (v.scalar == "icmp") return 1u;
    // Numeric fallback. A leading non-digit (e.g. an unknown name) is reported
    // as the proto-grammar error, not a bare integer diagnostic.
    if (v.scalar[0] < '0' || v.scalar[0] > '9') {
        throw_cfg("rule match protocol", file, v.line, v.col,
                  std::format("unknown protocol '{}' (expected tcp/udp/icmp "
                              "or a number in [0,255])", v.scalar));
    }
    const std::uint32_t n = parse_bounded_uint(v.scalar, 255u, file,
                                               v.line, v.col, "protocol");
    return static_cast<std::uint8_t>(n);
}

/* §5.54 (MVP-4.14) D-mvp-4.14-ETH-GRAMMAR: parse an `ethertype` scalar — a name
 * {ipv4→0x0800, ipv6→0x86dd, arp→0x0806}, a hex literal `0x…` (base-16; the
 * shared parse_bounded_uint is base-10 only and would reject `0x86dd`), OR a
 * decimal in [0,65535]. The result is the HOST-order EtherType value (the axis
 * keys on the post-VLAN inner ethertype, D-mvp-4.14-ETHKEY). Unknown name /
 * out-of-range / malformed hex → ConfigError exit 9. */
[[nodiscard]] std::uint16_t parse_ethertype(const yaml::Node& v, std::string_view file)
{
    if (v.kind != yaml::Node::Kind::Scalar || v.scalar.empty()) {
        throw_cfg("rule match ethertype", file, v.line, v.col,
                  "ethertype must be a name (ipv4/ipv6/arp), a hex literal "
                  "(0x86dd), or a number in [0,65535]");
    }
    if (v.scalar == "ipv4") return 0x0800u;
    if (v.scalar == "ipv6") return 0x86DDu;
    if (v.scalar == "arp")  return 0x0806u;

    // Hex path: `0x…` / `0X…` — base-16, [0,0xFFFF]. parse_bounded_uint cannot
    // handle hex (base-10 only), so do an explicit base-16 scan here.
    if (v.scalar.size() > 2 && v.scalar[0] == '0' &&
        (v.scalar[1] == 'x' || v.scalar[1] == 'X')) {
        const std::string_view hex = std::string_view{v.scalar}.substr(2);
        std::uint32_t value = 0;
        for (const char ch : hex) {
            std::uint32_t digit = 0;
            if (ch >= '0' && ch <= '9')      digit = static_cast<std::uint32_t>(ch - '0');
            else if (ch >= 'a' && ch <= 'f') digit = static_cast<std::uint32_t>(ch - 'a' + 10);
            else if (ch >= 'A' && ch <= 'F') digit = static_cast<std::uint32_t>(ch - 'A' + 10);
            else {
                throw_cfg("rule match ethertype", file, v.line, v.col,
                          std::format("ethertype hex literal '{}' contains "
                                      "non-hex digit '{}'", v.scalar, ch));
            }
            value = value * 16u + digit;
            if (value > 0xFFFFu) {
                throw_cfg("integer out of range", file, v.line, v.col,
                          "ethertype must be in [0,65535]");
            }
        }
        return static_cast<std::uint16_t>(value);
    }

    // A leading non-digit (e.g. an unknown name) is reported as the
    // ethertype-grammar error, not a bare integer diagnostic.
    if (v.scalar[0] < '0' || v.scalar[0] > '9') {
        throw_cfg("rule match ethertype", file, v.line, v.col,
                  std::format("unknown ethertype '{}' (expected ipv4/ipv6/arp, "
                              "a hex literal like 0x86dd, or a number in "
                              "[0,65535])", v.scalar));
    }
    // Decimal path.
    const std::uint32_t n = parse_bounded_uint(v.scalar, 65535u, file,
                                               v.line, v.col, "ethertype");
    return static_cast<std::uint16_t>(n);
}

/* §5.44 (MVP-4.4) D-mvp-4.4-PORT-GRAMMAR: parse a `dst_port` scalar — an
 * integer [0,65535] (→ {p,p}) OR a "lo-hi" string (inclusive range, both
 * endpoints ∈ [0,65535], lo ≤ hi). Malformed / out-of-range / lo>hi → exit 9. */
[[nodiscard]] PortRange parse_dst_port(const yaml::Node& v, std::string_view file)
{
    if (v.kind != yaml::Node::Kind::Scalar || v.scalar.empty()) {
        throw_cfg("rule match dst_port", file, v.line, v.col,
                  "dst_port must be an integer [0,65535] or a \"lo-hi\" range");
    }
    const std::string& s = v.scalar;
    // A '-' anywhere but position 0 marks the lo-hi separator (negative
    // endpoints are disallowed; parse_bounded_uint rejects the empty halves).
    const std::size_t dash = s.find('-', 1);
    PortRange out;
    if (dash == std::string::npos) {
        const std::uint32_t p = parse_bounded_uint(s, 65535u, file,
                                                   v.line, v.col, "dst_port");
        out.lo = static_cast<std::uint16_t>(p);
        out.hi = static_cast<std::uint16_t>(p);
    } else {
        const std::string_view lo_s{s.data(), dash};
        const std::string_view hi_s{s.data() + dash + 1, s.size() - dash - 1};
        const std::uint32_t lo = parse_bounded_uint(lo_s, 65535u, file,
                                                    v.line, v.col, "dst_port lo");
        const std::uint32_t hi = parse_bounded_uint(hi_s, 65535u, file,
                                                    v.line, v.col, "dst_port hi");
        if (lo > hi) {
            throw_cfg("rule match dst_port", file, v.line, v.col,
                      std::format("dst_port range lo {} > hi {}", lo, hi));
        }
        out.lo = static_cast<std::uint16_t>(lo);
        out.hi = static_cast<std::uint16_t>(hi);
    }
    return out;
}

/* §5.45 (MVP-4.5) D-mvp-4.5-VLAN-GRAMMAR: parse a `vlan` scalar — a single
 * integer outer VID ∈ [0,4095]. Lists/ranges are OOS this slice (multi-VID =
 * multiple rules). Non-integer / out-of-range → ConfigError exit 9. */
[[nodiscard]] std::uint16_t parse_vlan(const yaml::Node& v, std::string_view file)
{
    if (v.kind != yaml::Node::Kind::Scalar || v.scalar.empty()) {
        throw_cfg("rule match vlan", file, v.line, v.col,
                  "vlan must be an integer VID in [0,4095]");
    }
    const std::uint32_t n = parse_bounded_uint(v.scalar, 4095u, file,
                                               v.line, v.col, "vlan");
    return static_cast<std::uint16_t>(n);
}

// §5.47 (MVP-4.7) D-mvp-4.7-MAC-PARSER: a single hex nibble [0-9a-fA-F] → 0..15;
// returns -1 for any non-hex char (caller rejects → exit 9). RE-ADDED this slice
// (the §5.43 cutover DELETED the prior hex_nibble/parse_mac_canonical helpers —
// Phase A FINDING-2; this is NOT a mere "remove the reject").
[[nodiscard]] int hex_nibble(char c) noexcept
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// §5.47 D-mvp-4.7-Q1/HG-mvp-4.7-1: canonical 17-char src-MAC parser
// (AA:BB:CC:DD:EE:FF; lower/upper hex; ':'-separated) → xdpmf_mac{octets[6]}.
// EXACT match (v1 semantic, src-MAC). Malformed → ConfigError exit 9 with the
// §5.27 stderr-catalogue prefix.
[[nodiscard]] xdpmf_mac parse_mac(const yaml::Node& v, std::string_view file)
{
    if (v.kind != yaml::Node::Kind::Scalar) {
        throw_cfg("rule match mac", file, v.line, v.col,
                  "mac must be a canonical MAC string 'AA:BB:CC:DD:EE:FF'");
    }
    const std::string& s = v.scalar;
    // 6 octets * 2 hex + 5 ':' separators = 17 chars exactly.
    if (s.size() != 17) {
        throw_cfg("rule match mac", file, v.line, v.col,
                  "mac must be a canonical 17-char MAC 'AA:BB:CC:DD:EE:FF'");
    }
    xdpmf_mac out{};
    for (std::size_t oct = 0; oct < 6; ++oct) {
        const std::size_t base = oct * 3;
        const int hi = hex_nibble(s[base]);
        const int lo = hex_nibble(s[base + 1]);
        if (hi < 0 || lo < 0) {
            throw_cfg("rule match mac", file, v.line, v.col,
                      "mac contains a non-hex digit");
        }
        if (oct < 5 && s[base + 2] != ':') {
            throw_cfg("rule match mac", file, v.line, v.col,
                      "mac octets must be ':'-separated");
        }
        out.octets[oct] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return out;
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
                /* §5.61 (MVP-4.21) B30 D-mvp-4.21-Q2: the operator `id` is now a
                 * sparse stable identity decoupled from the internal `slot`
                 * (id-sorted rank). The old `id < XDPMF_ALLOWLIST_MAX` value cap
                 * is REMOVED — every u32 id is legal EXCEPT the reserved
                 * slot_rule_id EMPTY sentinel (D-mvp-4.21-SENTINEL), so that
                 * marker stays unambiguous. The ≤64 limit migrates to the slot
                 * count cap below. */
                if (id == XDPMF_SLOT_ID_EMPTY) {
                    throw_cfg("rule id reserved", file, id_node->line, id_node->col,
                              std::format("rule.id {} is reserved (XDPMF_SLOT_ID_EMPTY sentinel)",
                                          id));
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
                // §5.54 (MVP-4.14) v2 match grammar: the accepted match-key set
                // is the 9 axes {mac, dst_cidr, src_cidr, protocol, dst_port,
                // vlan, dst_cidr6, src_cidr6, ethertype}. Any other key →
                // ConfigError exit 9 (fail loud, not a silent no-op the operator
                // believes is live). (Per-axis grammar lineage §5.43–§5.54 lives
                // in git/RETROSPECTIVES.)
                for (const std::pair<std::string, yaml::Node>& kv : match->mapping) {
                    if (kv.first != "mac" && kv.first != "dst_cidr"
                        && kv.first != "src_cidr" && kv.first != "protocol"
                        && kv.first != "dst_port" && kv.first != "vlan"
                        && kv.first != "dst_cidr6" && kv.first != "src_cidr6"
                        && kv.first != "ethertype") {
                        throw_cfg("unsupported match type", file,
                                  kv.second.line, kv.second.col,
                                  std::format("match type '{}' not supported in schema_version 2",
                                              kv.first));
                    }
                }
                // §5.54 v2 match grammar: each rule's match MUST contain AT
                // LEAST ONE of {mac, dst_cidr, src_cidr, protocol, dst_port,
                // vlan, dst_cidr6, src_cidr6, ethertype}. Empty match: {} → exit 9.
                const yaml::Node* mac_node       = find_key(*match, "mac");
                const yaml::Node* dst_cidr_node  = find_key(*match, "dst_cidr");
                const yaml::Node* src_cidr_node  = find_key(*match, "src_cidr");
                const yaml::Node* protocol_node  = find_key(*match, "protocol");
                const yaml::Node* dst_port_node  = find_key(*match, "dst_port");
                const yaml::Node* vlan_node      = find_key(*match, "vlan");
                const yaml::Node* dst_cidr6_node = find_key(*match, "dst_cidr6");
                const yaml::Node* src_cidr6_node = find_key(*match, "src_cidr6");
                const yaml::Node* ethertype_node = find_key(*match, "ethertype");
                if (mac_node == nullptr && dst_cidr_node == nullptr
                    && src_cidr_node == nullptr && protocol_node == nullptr
                    && dst_port_node == nullptr && vlan_node == nullptr
                    && dst_cidr6_node == nullptr && src_cidr6_node == nullptr
                    && ethertype_node == nullptr) {
                    throw_cfg("rule match", file, match->line, match->col,
                              "rule must specify at least one of "
                              "'mac', 'dst_cidr', 'src_cidr', 'protocol', 'dst_port', "
                              "'vlan', 'dst_cidr6', 'src_cidr6', 'ethertype'");
                }
                // §5.47 D-mvp-4.7-MAC-PARSER: canonical 17-char src-MAC → exact axis.
                if (mac_node != nullptr) {
                    r.match.mac = parse_mac(*mac_node, file);
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
                // §5.44 (MVP-4.4) D-mvp-4.4-PROTO-GRAMMAR: `protocol` accepts a
                // name {tcp→6, udp→17, icmp→1} OR a numeric IP-protocol number
                // ∈ [0,255]; exact-match. Unknown name / out-of-range → exit 9.
                if (protocol_node != nullptr) {
                    r.match.protocol = parse_protocol(*protocol_node, file);
                }
                // §5.44 D-mvp-4.4-PORT-GRAMMAR: `dst_port` accepts an integer
                // [0,65535] (→ {p,p}) OR a "lo-hi" string (inclusive range);
                // both endpoints ∈ [0,65535], lo ≤ hi. → exit 9 otherwise.
                if (dst_port_node != nullptr) {
                    r.match.dst_port = parse_dst_port(*dst_port_node, file);
                }
                // §5.45 D-mvp-4.5-VLAN-GRAMMAR: `vlan` accepts a single integer
                // outer VID ∈ [0,4095]; exact-match. Out-of-range → exit 9.
                if (vlan_node != nullptr) {
                    r.match.vlan = parse_vlan(*vlan_node, file);
                }
                // §5.53 (MVP-4.13) D-mvp-4.13-Q1: `dst_cidr6`/`src_cidr6` parse
                // via cidr::parse_cidr_v6 (IPv6 CIDR; prefix [0,128]; host-bits-
                // zero enforced). Mirrors the v4 dst_cidr/src_cidr blocks.
                if (dst_cidr6_node != nullptr) {
                    if (dst_cidr6_node->kind != yaml::Node::Kind::Scalar) {
                        throw_cfg("rule match dst_cidr6", file,
                                  dst_cidr6_node->line, dst_cidr6_node->col,
                                  "rule.match.dst_cidr6 must be a string");
                    }
                    r.match.dst_cidr6 = cidr::parse_cidr_v6(
                        dst_cidr6_node->scalar, file,
                        dst_cidr6_node->line, dst_cidr6_node->col);
                }
                if (src_cidr6_node != nullptr) {
                    if (src_cidr6_node->kind != yaml::Node::Kind::Scalar) {
                        throw_cfg("rule match src_cidr6", file,
                                  src_cidr6_node->line, src_cidr6_node->col,
                                  "rule.match.src_cidr6 must be a string");
                    }
                    r.match.src_cidr6 = cidr::parse_cidr_v6(
                        src_cidr6_node->scalar, file,
                        src_cidr6_node->line, src_cidr6_node->col);
                }
                // §5.54 (MVP-4.14) D-mvp-4.14-ETH-GRAMMAR: `ethertype` accepts a
                // name {ipv4→0x0800, ipv6→0x86dd, arp→0x0806}, a hex literal
                // (0x86dd), or a decimal in [0,65535]; exact-match (post-VLAN
                // inner ethertype, host order). Unknown name / malformed hex /
                // out-of-range → exit 9.
                if (ethertype_node != nullptr) {
                    r.match.ethertype = parse_ethertype(*ethertype_node, file);
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
            /* §5.61 (MVP-4.21) B30 D-mvp-4.21-Q2: the ≤64 limit migrates from
             * the id VALUE to the slot COUNT — the loader assigns each rule a
             * dense slot ∈ [0, count) and shifts `1ULL << slot`, so the rule
             * count (not the id value) is what must stay ≤ XDPMF_ALLOWLIST_MAX
             * to keep the bit-vector shift safe. */
            if (out.rules.size() > static_cast<std::size_t>(XDPMF_ALLOWLIST_MAX)) {
                throw_cfg("too many rules", file, rs->line, rs->col,
                          std::format("rule count {} exceeds slot space "
                                      "XDPMF_ALLOWLIST_MAX={}",
                                      out.rules.size(), XDPMF_ALLOWLIST_MAX));
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
