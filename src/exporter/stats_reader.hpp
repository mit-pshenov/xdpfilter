/*
 * stats_reader.hpp — read the pinned `stats` PERCPU_ARRAY per attached iface
 * via libbpf, sum across CPUs. Read-only by construction (PI-31, §5.29).
 *
 * Scans ${bpffs_root}/<iface>/stats for every per-iface directory; opens
 * each pinned map RO via bpf_obj_get(); reads PERCPU_ARRAY[STAT_MAX=4]
 * with bpf_map_lookup_elem(); sums the per-CPU u64 slots.
 *
 * NO map mutations — PI-31. NO program load. NO attach/detach.
 */
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "common/mac_filter.h"  // STAT_MAX, XDPMF_BPFFS_ROOT

namespace xdpmf::exporter {

struct StatsSample {
    std::string   iface;
    std::uint64_t stats[STAT_MAX] = {0, 0, 0, 0};   // index ≡ enum mac_filter_stat
};

/* Scan ${bpffs_root}/<iface>/stats for every attached iface; libbpf
 * PERCPU-sum each one. Returns an empty vector on empty / nonexistent
 * bpffs root (PI-32 — graceful). May emit per-iface WARN lines to stderr
 * on transient open / lookup errors but never throws. */
[[nodiscard]] std::vector<StatsSample> read_all_attached(std::string_view bpffs_root);

}  // namespace xdpmf::exporter
