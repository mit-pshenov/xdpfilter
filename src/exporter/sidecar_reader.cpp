/*
 * sidecar_reader.cpp — line-oriented regex extraction of `rule_index.json`.
 *
 * D-3.4b-14: cycle-1 budget discipline avoids a full JSON parser. The
 * writer (src/lib/sidecar.cpp) emits one rule object per line of the form:
 *   {"rule_id": <N>, "match": {<KIND>: "<VAL>"[, <KIND2>: "..."]}, "action": "<ACT>"}
 * Our ERE captures `(rule_id, action)` per such line; the per-axis values
 * are extracted by key-anchored sub-scan (exporter does not emit the match
 * value in metric labels per Q4 A3).
 *
 * PI-31-3.4b: READ-ONLY. Only file-reads here.
 */
#include "sidecar_reader.hpp"

#include "common/logger.hpp"  // §5.62 (MVP-4.22) R-5 — observable graceful-degradation

#include <exception>
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
            /* §5.46/§5.47: populate the 9 live axes verbatim (empty when
             * absent). `mac` un-frozen this slice (the producer's
             * append_kind("mac",…) branch fires once a rule sets it). */
            rm.mac      = extract_axis(body, "mac");
            rm.dst_cidr = extract_axis(body, "dst_cidr");
            rm.src_cidr = extract_axis(body, "src_cidr");
            rm.protocol = extract_axis(body, "protocol");
            rm.dst_port = extract_axis(body, "dst_port");
            rm.vlan     = extract_axis(body, "vlan");
            /* §5.56 (MVP-4.16 C3): v6-CIDR + EtherType axes. The `"dst_cidr"`
             * key anchor in extract_axis ends with a quote, so it does NOT
             * alias `"dst_cidr6"` (the byte after `dst_cidr` is `6`, not `"`);
             * the v4 and v6 extractions are independent. */
            rm.dst_cidr6 = extract_axis(body, "dst_cidr6");
            rm.src_cidr6 = extract_axis(body, "src_cidr6");
            rm.ethertype = extract_axis(body, "ethertype");
            out.push_back(std::move(rm));
        }
    } catch (const std::exception& e) {
        /* §5.62 (MVP-4.22) R-5 / Q1-A2 + Q2-A2: make the graceful-degradation
         * OBSERVABLE — emit a structured diagnostic instead of swallowing
         * silently. Never-throw PRESERVED: emit() is noexcept and the trailing
         * catch(...) below backstops any non-std throw (guard #30 /
         * PI-mvp-4.22-NEVER-THROW). Caller still observes empty-or-partial
         * vector and degrades labels to action="unknown" (PI-32-3.4b). */
        const std::string what{e.what()};
        const std::string path_s{path};
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"path",      std::string_view{path_s}},
            xdpmf::logger::Field{"exception", std::string_view{what}},
        };
        xdpmf::logger::emit(
            xdpmf::logger::Level::Warn,
            "exporter.scrape.warn.sidecar_read_exception",
            "xdpmacfilter: WARN: rule_index.json read failed; serving "
            "degraded labels\n",
            fs);
    } catch (...) {
        /* Never-throw contract: any non-std exception is swallowed; caller
         * observes empty-or-partial vector and degrades labels to
         * action="unknown" for affected rule_ids (PI-32-3.4b). The diagnostic
         * event is emitted with an unknown/non-std marker. */
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"exception", std::string_view{"unknown (non-std)"}},
        };
        xdpmf::logger::emit(
            xdpmf::logger::Level::Warn,
            "exporter.scrape.warn.sidecar_read_exception",
            "xdpmacfilter: WARN: rule_index.json read failed; serving "
            "degraded labels\n",
            fs);
    }
    return out;
}

}  // namespace xdpmf::exporter
