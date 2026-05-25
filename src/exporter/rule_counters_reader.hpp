/*
 * rule_counters_reader.hpp — PERCPU sum reader for the §5.31 (MVP-3.4b)
 * `rule_counters` map. Sister to `stats_reader.hpp`; same overall shape
 * (scan ${bpffs_root}/<iface>/rule_counters pins; PERCPU sum each slot).
 *
 * PI-31-3.4b: READ-ONLY by construction — only bpf_obj_get + the PERCPU
 * lookup; NO map mutations / attach / detach. Reviewer's grep over
 * src/exporter/ enforces the no-mutation fence on the new TU.
 *
 * Failure mode: per-iface errors are logged + skipped — the daemon must
 * survive a transient pin disappearance (PI-32 — graceful empty/partial).
 */
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "common/mac_filter.h"  // XDPMF_RULE_COUNTERS_MAX

namespace xdpmf::exporter {

/* Per-iface PERCPU-summed counter snapshot. `counters[k]` is the summed
 * count for rule_id == k across all CPUs at scrape time. Slots for
 * non-applied rules stay 0 (PERCPU init). */
struct RuleCountersSample {
    std::string   iface;
    std::uint64_t counters[XDPMF_RULE_COUNTERS_MAX] = {};
};

/* Scan ${bpffs_root}/<iface>/rule_counters for every attached iface; libbpf
 * PERCPU-sum each one. Returns an empty vector on empty / nonexistent
 * bpffs root (PI-32 — graceful). May emit per-iface WARN lines to stderr
 * on transient open / lookup errors but never throws. */
[[nodiscard]] std::vector<RuleCountersSample>
read_rule_counters(std::string_view bpffs_root) noexcept;

}  // namespace xdpmf::exporter
