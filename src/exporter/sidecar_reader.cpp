/*
 * sidecar_reader.cpp — line-oriented regex extraction of `rule_index.json`.
 *
 * D-3.4b-14: cycle-1 budget discipline avoids a full JSON parser. The
 * writer (src/lib/sidecar.cpp) emits one rule object per line of the form:
 *   {"rule_id": <N>, "match": {<KIND>: "<VAL>"[, <KIND2>: "..."]}, "action": "<ACT>"}
 * Our ERE captures `(rule_id, action)` per such line; `match_kind` is
 * derived by substring scan (informational only — exporter does not emit
 * the match value in metric labels per Q4 A3).
 *
 * PI-31-3.4b: READ-ONLY. Only file-reads here.
 */
#include "sidecar_reader.hpp"

#include <fstream>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace xdpmf::exporter {

namespace {

/* Per-rule ERE. Anchored against a single line of the writer's output
 * (D-3.4b-20). Captures:
 *   - group 1: rule_id (decimal integer)
 *   - group 2: match object body (between `{` and `}` — used for kind detection)
 *   - group 3: action ("pass" | "drop")
 * The trailing optional comma + whitespace tolerates inter-rule commas. */
const std::regex& rule_line_re()
{
    static const std::regex r{
        R"RE(\{"rule_id":\s*([0-9]+),\s*"match":\s*\{([^}]*)\},\s*"action":\s*"(pass|drop)"\s*\}\s*,?\s*$)RE",
        std::regex::ECMAScript | std::regex::optimize};
    return r;
}

[[nodiscard]] std::string classify_match_kind(std::string_view body)
{
    const bool has_mac  = body.find("\"mac\"")  != std::string_view::npos;
    const bool has_cidr = body.find("\"cidr\"") != std::string_view::npos;
    if (has_mac && has_cidr) return "both";
    if (has_mac)             return "mac";
    if (has_cidr)            return "cidr";
    return "";
}

/* §5.46 (MVP-4.6) D-mvp-4.6-Q2: key-anchored extraction of a single axis
 * value from the already-captured match-object body (regex group 2). The
 * leading `"` + exact key + `"` anchor disambiguates overlapping keys —
 * `dst_cidr` vs `src_cidr` (both contain "cidr") and
 * `dst_port`/`protocol`/`vlan` resolve exactly. Returns the verbatim value
 * the sidecar emitted, or "" when the axis is absent (D-3.4b-10: no JSON
 * parser; the writer's `"<key>": "<value>"` shape is stable). */
[[nodiscard]] std::string extract_axis(std::string_view body, std::string_view key)
{
    const std::regex re{
        "\"" + std::string{key} + "\"\\s*:\\s*\"([^\"]*)\"",
        std::regex::ECMAScript};
    const std::string body_s{body};
    std::smatch m;
    if (std::regex_search(body_s, m, re)) {
        return m[1].str();
    }
    return "";
}

}  // namespace

std::vector<RuleMeta> parse_rule_index(std::string_view path) noexcept
{
    std::vector<RuleMeta> out;
    try {
        std::ifstream in{std::string{path}};
        if (!in.is_open()) {
            return out;
        }
        std::string line;
        while (std::getline(in, line)) {
            std::smatch m;
            if (!std::regex_search(line, m, rule_line_re())) {
                continue;
            }
            RuleMeta rm;
            try {
                rm.rule_id = static_cast<std::uint32_t>(std::stoul(m[1].str()));
            } catch (...) {
                continue;  // malformed integer; skip the line, keep going
            }
            rm.action     = m[3].str();
            const std::string body = m[2].str();
            rm.match_kind = classify_match_kind(body);
            /* §5.46/§5.47: populate the 6 live axes verbatim (empty when
             * absent). `mac` un-frozen this slice (the producer's
             * append_kind("mac",…) branch fires once a rule sets it). */
            rm.mac      = extract_axis(body, "mac");
            rm.dst_cidr = extract_axis(body, "dst_cidr");
            rm.src_cidr = extract_axis(body, "src_cidr");
            rm.protocol = extract_axis(body, "protocol");
            rm.dst_port = extract_axis(body, "dst_port");
            rm.vlan     = extract_axis(body, "vlan");
            out.push_back(std::move(rm));
        }
    } catch (...) {
        /* Never-throw contract: any I/O or regex exception is swallowed;
         * caller observes empty-or-partial vector and degrades labels to
         * action="unknown" for affected rule_ids (PI-32-3.4b). */
    }
    return out;
}

}  // namespace xdpmf::exporter
