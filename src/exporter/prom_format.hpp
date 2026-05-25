/*
 * prom_format.hpp — Prometheus text-format emitter (v0.0.4) for the
 * exporter's `/metrics` endpoint. See design §5.29 (MVP-3.4) +
 * §5.31 (MVP-3.4b) DataStructures.
 *
 * Output shape (two metric families post-§5.31):
 *   # HELP xdpfilter_packets_total Total packets processed by xdpfilter, per iface and verdict.
 *   # TYPE xdpfilter_packets_total counter
 *   xdpfilter_packets_total{iface="<I>",verdict="pass"} <N>
 *   xdpfilter_packets_total{iface="<I>",verdict="drop_deny"} <N>
 *   xdpfilter_packets_total{iface="<I>",verdict="drop_malformed"} <N>
 *   xdpfilter_packets_total{iface="<I>",verdict="pass_cidr"} <N>
 *   # HELP xdpfilter_rule_match_total Total per-rule packet matches by iface and rule_id, labelled with action.
 *   # TYPE xdpfilter_rule_match_total counter
 *   xdpfilter_rule_match_total{iface="<I>",rule_id="<N>",action="(pass|drop|unknown)"} <N>
 *
 * Block ordering: existing `xdpfilter_packets_total` HELP+TYPE+samples
 * FIRST, then `xdpfilter_rule_match_total` HELP+TYPE+samples — preserves
 * byte-equivalence of the existing prefix for any operator scrapers that
 * pin head-of-output substring matches.
 *
 * Empty case (no samples): output is just HELP+TYPE lines, no sample lines.
 * Prometheus tolerates this (scrapes "0 timeseries" cleanly) per PI-32.
 */
#pragma once

#include <map>
#include <string>
#include <vector>

#include "rule_counters_reader.hpp"
#include "sidecar_reader.hpp"
#include "stats_reader.hpp"

namespace xdpmf::exporter {

/* Format the Prometheus text body. Caller wraps in HTTP response.
 *
 * `rule_meta_by_iface` maps each iface name → its parsed rule_index.json
 * RuleMeta vector. Ifaces absent from the map (or with empty vectors) are
 * sidecar-orphan candidates: any non-zero `rule_counters` slot for such
 * an iface emits `action="unknown"` per Q4 A3 + PI-32-3.4b. */
[[nodiscard]] std::string emit_metrics(
    const std::vector<StatsSample>&                       samples,
    const std::vector<RuleCountersSample>&                rule_counters,
    const std::map<std::string, std::vector<RuleMeta>>&   rule_meta_by_iface);

}  // namespace xdpmf::exporter
