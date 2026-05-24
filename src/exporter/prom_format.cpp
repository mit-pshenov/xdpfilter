/*
 * prom_format.cpp — Prometheus text-format (version 0.0.4) emitter.
 * See design §5.29 DataStructures additions for the expected output shape.
 */
#include "prom_format.hpp"

#include <format>
#include <string>
#include <string_view>

#include "common/mac_filter.h"  // STAT_PASS / STAT_DROP_DENY / STAT_DROP_MALFORMED / STAT_PASS_CIDR / STAT_MAX

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

std::string emit_metrics(const std::vector<StatsSample>& samples)
{
    std::string out;
    out.reserve(256 + samples.size() * 256);

    /* HELP + TYPE lines fire EXACTLY ONCE per metric family even when the
     * sample set is empty (PI-32 — "0 timeseries" is a valid scrape). */
    out.append("# HELP xdpfilter_packets_total Total packets processed by xdpfilter, per iface and verdict.\n");
    out.append("# TYPE xdpfilter_packets_total counter\n");

    for (const StatsSample& s : samples) {
        const std::string iface_escaped = escape_label_value(s.iface);
        for (std::uint32_t k = 0; k < STAT_MAX; ++k) {
            out.append(std::format(
                "xdpfilter_packets_total{{iface=\"{}\",verdict=\"{}\"}} {}\n",
                iface_escaped,
                verdict_label(k),
                s.stats[k]));
        }
    }
    return out;
}

}  // namespace xdpmf::exporter
