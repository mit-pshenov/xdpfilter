/*
 * sidecar_reader.hpp — exporter-side parser for `rule_index.json` written
 * by the loader (§5.31 MVP-3.4b, sidecar::write_rule_index).
 *
 * D-3.4b-14: line-oriented regex extraction, NOT full JSON parse. The
 * writer's output shape is stable + controlled (D-3.4b-20 one-rule-per-line);
 * a simple ERE captures `(rule_id, action)` per rule with high reliability.
 * ~80 LOC vs ~300+ LOC for a full JSON parser. Future cycles can co-evolve
 * or adopt nlohmann/json if richer extraction is needed.
 *
 * PI-31-3.4b: READ-ONLY by construction — no writes to rule_index.json.
 *
 * PI-32-3.4b orphan tolerance: missing file → empty vector (exporter
 * degrades to `action="unknown"` labels for any rule_id seen in the
 * counter map). NEVER throws.
 */
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace xdpmf::exporter {

struct RuleMeta {
    std::uint32_t rule_id;
    std::string   action;     /* "pass" | "drop" */
    std::string   match_kind; /* "mac" | "cidr" | "both" — informational only */
};

/* Reads rule_index.json at `path`; returns empty vector if file missing,
 * unreadable, or no rules are extracted. NEVER throws. */
[[nodiscard]] std::vector<RuleMeta> parse_rule_index(std::string_view path) noexcept;

}  // namespace xdpmf::exporter
