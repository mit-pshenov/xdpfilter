/*
 * prom_format.cpp — Prometheus text-format (version 0.0.4) emitter.
 * See design §5.29 + §5.31 DataStructures for the expected output shape.
 */
#include "prom_format.hpp"

#include <algorithm>
#include <cstdint>
#include <format>
#include <iterator>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/mac_filter.h"  // STAT_PASS / STAT_DROP_DENY / STAT_DROP_MALFORMED / STAT_PASS_CIDR / STAT_MAX / XDPMF_RULE_COUNTERS_MAX

namespace xdpmf::exporter {

namespace {

/* Slot ordinal → verdict label. STAT_PASS_CIDR = 3 is the §5.27 NEW slot.
 * Order mirrors enum mac_filter_stat so the emit loop walks 0..STAT_MAX-1. */
[[nodiscard]] constexpr std::string_view verdict_label(std::uint32_t idx) noexcept
{
    switch (idx) {
        case STAT_PASS:           return "pass";
        case STAT_DROP_DENY:      return "drop_deny";
        case STAT_DROP_MALFORMED: return "drop_malformed";
        case STAT_PASS_CIDR:      return "pass_cidr";
        default:                  return "unknown";
    }
}

/* Prometheus label-value escaping per the exposition format: backslash, double
 * quote, and newline get backslash-escaped; other bytes pass through. iface
 * names from the kernel are constrained to [A-Za-z0-9._-] so this is mostly
 * defensive against a stale pin dir with an unusual name. */
[[nodiscard]] std::string escape_label_value(std::string_view raw)
{
    std::string out;
    out.reserve(raw.size());
    for (char c : raw) {
        switch (c) {
            case '\\': out.append("\\\\"); break;
            case '"':  out.append("\\\""); break;
            case '\n': out.append("\\n");  break;
            default:   out.push_back(c);   break;
        }
    }
    return out;
}

}  // namespace

std::string emit_metrics(
    const std::vector<StatsSample>&                       samples,
    const std::vector<RuleCountersSample>&                rule_counters,
    const std::map<std::string, std::vector<RuleMeta>>&   rule_meta_by_iface)
{
    std::string out;
    out.reserve(512 + samples.size() * 256 + rule_counters.size() * 512);

    /* HELP + TYPE lines fire EXACTLY ONCE per metric family even when the
     * sample set is empty (PI-32 — "0 timeseries" is a valid scrape). */
    out.append("# HELP xdpfilter_packets_total Total packets processed by xdpfilter, per iface and verdict.\n");
    out.append("# TYPE xdpfilter_packets_total counter\n");

    for (const StatsSample& s : samples) {
        const std::string iface_escaped = escape_label_value(s.iface);
        for (std::uint32_t k = 0; k < STAT_MAX; ++k) {
            /* §5.40 (MVP-3.4i) P-2 + D-3.4i-2: format directly into `out`'s
             * (already-reserved) storage instead of materializing a temporary
             * std::string per line. FMT literal byte-identical → PI-3.4i-A. */
            std::format_to(std::back_inserter(out),
                "xdpfilter_packets_total{{iface=\"{}\",verdict=\"{}\"}} {}\n",
                iface_escaped,
                verdict_label(k),
                s.stats[k]);
        }
    }

    /* §5.31 (MVP-3.4b) PI-3.4b-6 + Q4 A3: per-rule counter series with
     * `action` label sourced from the sidecar (PI-32-3.4b orphan tolerance
     * → `action="unknown"` for rule_id in counters but absent from sidecar).
     * HELP+TYPE emitted unconditionally so an empty fleet still produces
     * a complete-shape scrape. */
    out.append("# HELP xdpfilter_rule_match_total Total per-rule packet matches by iface and rule_id, labelled with action.\n");
    out.append("# TYPE xdpfilter_rule_match_total counter\n");

    for (const RuleCountersSample& s : rule_counters) {
        const std::string iface_escaped = escape_label_value(s.iface);

        /* Per-iface rule_id → action lookup table from sidecar. Missing
         * iface or missing rule_id => "unknown" action. Built per-iface
         * rather than globally so a sidecar-orphan in iface A doesn't
         * contaminate iface B's labels.
         *
         * §5.40 (MVP-3.4i) P-4 + D-3.4i-4: a `rule_id`-sorted vector replaces
         * the prior hash map (cache-friendly linear scan at ≤64 entries;
         * ~500 fewer small allocs/scrape). FIRST-WINS dedup on duplicate
         * rule_id is LOAD-BEARING — the prior hash-map emplace kept the first
         * insert, so we skip a rule_id already present (NOT overwrite) to keep
         * the emitted line-SET identical (PI-3.4i-B). The sort makes the
         * known-rule emission order deterministic ascending-rule_id (was
         * hash-order); Prometheus is order-insensitive so the oracle greps
         * stay green. */
        std::vector<std::pair<std::uint32_t, std::string_view>> action_for_rule;
        const auto it = rule_meta_by_iface.find(s.iface);
        if (it != rule_meta_by_iface.end()) {
            for (const RuleMeta& rm : it->second) {
                const bool already_present = std::any_of(
                    action_for_rule.begin(), action_for_rule.end(),
                    [&](const auto& e) { return e.first == rm.rule_id; });
                if (already_present) continue;  // first-wins dedup (D-3.4i-4)
                action_for_rule.emplace_back(rm.rule_id,
                                             std::string_view{rm.action});
            }
        }
        std::sort(action_for_rule.begin(), action_for_rule.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });

        /* Emit ALL sidecar-known rules even at count 0 (Prometheus
         * convention: emit zeroes for known series). Then emit any
         * orphan counter slots (non-zero counter for a rule_id absent
         * from sidecar) with action="unknown". */
        for (const auto& [rule_id, action] : action_for_rule) {
            const std::uint64_t v = (rule_id < XDPMF_RULE_COUNTERS_MAX)
                                        ? s.counters[rule_id]
                                        : 0u;
            std::format_to(std::back_inserter(out),
                "xdpfilter_rule_match_total{{iface=\"{}\",rule_id=\"{}\",action=\"{}\"}} {}\n",
                iface_escaped, rule_id, action, v);
        }
        for (std::uint32_t k = 0; k < XDPMF_RULE_COUNTERS_MAX; ++k) {
            if (s.counters[k] == 0) continue;
            /* Linear scan over the ≤64-entry sorted vector (D-3.4i-4 / Q3):
             * replaces the prior hash-map `.contains` membership test. */
            const bool known = std::any_of(
                action_for_rule.begin(), action_for_rule.end(),
                [&](const auto& e) { return e.first == k; });
            if (known) continue;
            std::format_to(std::back_inserter(out),
                "xdpfilter_rule_match_total{{iface=\"{}\",rule_id=\"{}\",action=\"unknown\"}} {}\n",
                iface_escaped, k, s.counters[k]);
        }
    }

    /* §5.46 (MVP-4.6) PI-mvp-4.6-EXPORTER-AXIS-AWARE: a THIRD family carrying
     * each sidecar-known rule's 5 match-axis values as labels (info-metric:
     * constant gauge value 1, joined to the counter on (iface,rule_id) in
     * PromQL). D-mvp-4.6-BLOCK-ORDER: appended LAST so the two counter blocks
     * above stay byte-identical (PI-mvp-4.6-COUNTER-CONTRACT). The 7-label key
     * set is STABLE and ordered; an unconstrained axis emits an empty value
     * (D-mvp-4.6-Q3). Sourced from `rule_meta_by_iface` (config-known rules),
     * NOT rule_counters — a counter-orphan rule_id has unknown axes and gets
     * NO series (D-mvp-4.6-METRIC-SOURCE). HELP+TYPE fire once unconditionally
     * (PI-32 empty-scrape). */
    out.append("# HELP xdpfilter_rule_info Per-rule match constraints (6-axis) by iface and rule_id; constant gauge value 1.\n");
    out.append("# TYPE xdpfilter_rule_info gauge\n");

    for (const auto& [iface, metas] : rule_meta_by_iface) {
        const std::string iface_escaped = escape_label_value(iface);

        /* First-wins dedup on duplicate rule_id + ascending rule_id sort,
         * mirroring the counter block (D-3.4i-4). Prometheus is
         * order-insensitive; the sort makes emission deterministic. */
        std::vector<const RuleMeta*> rules;
        for (const RuleMeta& rm : metas) {
            const bool already_present = std::any_of(
                rules.begin(), rules.end(),
                [&](const RuleMeta* e) { return e->rule_id == rm.rule_id; });
            if (already_present) continue;  // first-wins dedup
            rules.push_back(&rm);
        }
        std::sort(rules.begin(), rules.end(),
                  [](const RuleMeta* a, const RuleMeta* b) {
                      return a->rule_id < b->rule_id;
                  });

        for (const RuleMeta* rm : rules) {
            /* §5.47 (MVP-4.7) D-mvp-4.7-Q3: `mac` is the 8th (LAST) label key,
             * appended after `vlan` so the existing 7 keys' order stays byte-
             * stable; `""` for a MAC-unconstrained rule. */
            std::format_to(std::back_inserter(out),
                "xdpfilter_rule_info{{iface=\"{}\",rule_id=\"{}\",dst_cidr=\"{}\",src_cidr=\"{}\",protocol=\"{}\",dst_port=\"{}\",vlan=\"{}\",mac=\"{}\"}} 1\n",
                iface_escaped,
                rm->rule_id,
                escape_label_value(rm->dst_cidr),
                escape_label_value(rm->src_cidr),
                escape_label_value(rm->protocol),
                escape_label_value(rm->dst_port),
                escape_label_value(rm->vlan),
                escape_label_value(rm->mac));
        }
    }

    return out;
}

}  // namespace xdpmf::exporter
