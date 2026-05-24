/*
 * prom_format.hpp — Prometheus text-format emitter (v0.0.4) for the
 * exporter's `/metrics` endpoint. See design §5.29 DataStructures additions.
 *
 * Output shape (single metric family this slice):
 *   # HELP xdpfilter_packets_total Total packets processed by xdpfilter, per iface and verdict.
 *   # TYPE xdpfilter_packets_total counter
 *   xdpfilter_packets_total{iface="<I>",verdict="pass"} <N>
 *   xdpfilter_packets_total{iface="<I>",verdict="drop_deny"} <N>
 *   xdpfilter_packets_total{iface="<I>",verdict="drop_malformed"} <N>
 *   xdpfilter_packets_total{iface="<I>",verdict="pass_cidr"} <N>
 *
 * Empty case (no samples): output is just HELP+TYPE lines, no sample lines.
 * Prometheus tolerates this (scrapes "0 timeseries" cleanly) per PI-32.
 */
#pragma once

#include <string>
#include <vector>

#include "stats_reader.hpp"

namespace xdpmf::exporter {

/* Format the Prometheus text body. Caller wraps in HTTP response. */
[[nodiscard]] std::string emit_metrics(const std::vector<StatsSample>& samples);

}  // namespace xdpmf::exporter
