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

#include "common/xdpfilter.h"  // XDPMF_RULE_COUNTERS_MAX

namespace xdpmf::exporter {

/* Per-iface PERCPU-summed counter snapshot. `counters[k]` is the summed
 * count for the rule occupying SLOT k across all CPUs at scrape time. Slots
 * for non-applied rules stay 0 (value-init; §5.81 the bounded scan does not
 * read the unoccupied tail's PERCPU zeros).
 *
 * §5.61 (MVP-4.21) B30: the counter index is the internal `slot` (id-sorted
 * rank), NOT the operator id. `slot_to_id[k]` carries the stable operator id
 * occupying slot k (or XDPMF_SLOT_ID_EMPTY if unoccupied), read from the
 * `slot_rule_id` BPF map's active half, so the exporter can label each counter
 * under its stable id (counters survive reorder/insert/renumber). A pre-§5.61
 * iface (no slot_rule_id pin) leaves slot_to_id all-sentinel → graceful-empty
 * (PI-32). */
struct RuleCountersSample {
    std::string   iface;
    std::uint64_t counters[XDPMF_RULE_COUNTERS_MAX]   = {};
    /* Every entry is sentinel-or-real on return: the occupied prefix carries
     * real ids/sums; the tail is well-defined by value-init + the explicit
     * sentinel-fill (§5.81 — no longer by per-slot reads of dead slots). */
    std::uint32_t slot_to_id[XDPMF_RULE_COUNTERS_MAX] = {};
};

/* Scan ${bpffs_root}/<iface>/rule_counters for every attached iface; libbpf
 * PERCPU-sum each one. Returns an empty vector on empty / nonexistent
 * bpffs root (PI-32 — graceful). May emit per-iface WARN lines to stderr
 * on transient open / lookup errors but never throws. */
[[nodiscard]] std::vector<RuleCountersSample>
read_rule_counters(std::string_view bpffs_root) noexcept;

}  // namespace xdpmf::exporter
