/*
 * stats_reader.hpp — read the pinned `stats` PERCPU_ARRAY per attached iface
 * via libbpf, sum across CPUs. Read-only by construction (PI-31, §5.29).
 *
 * Scans ${bpffs_root}/<iface>/stats for every per-iface directory; opens
 * each pinned map RO via bpf_obj_get(); reads PERCPU_ARRAY[STAT_MAX=4]
 * with bpf_map_lookup_elem(); sums the per-CPU u64 slots.
 *
 * NO map mutations — PI-31. NO program load. NO attach/detach.
 *
 * §5.30 HK-16 + HK-17 (MVP-3.4.5):
 *   - validate_bpffs_root_or_warn() emits the PI-32 startup WARN line if
 *     bpffs_root does not exist (called ONCE from main() before the first
 *     http::run() invocation).
 *   - read_all_attached_with_acc() also populates a DiscoveryAccounting struct
 *     so the caller (main.cpp) can detect "ALL discovered ifaces failed
 *     EACCES/EPERM" and exit(6) per D-3.4.5-2. Per-iface partial-EACCES
 *     continues to WARN-and-continue (preserves PI-31/PI-32).
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "common/xdpfilter.h"  // STAT_MAX, XDPMF_BPFFS_ROOT

namespace xdpmf::exporter {

struct StatsSample {
    std::string   iface;
    std::uint64_t stats[STAT_MAX] = {0, 0, 0, 0, 0}; // index ≡ enum xdpfilter_stat (§5.75 +STAT_REDIRECT)
};

/* §5.30 HK-17 (MVP-3.4.5) — per-scrape discovery accounting populated by
 * read_all_attached_with_acc(). main.cpp consumes this AFTER every scrape: if
 * `total_discovered > 0 && eacces_failures == total_discovered &&
 *  successes == 0` then exit(6) per D-3.4.5-2. Empty bpffs root
 * (`total_discovered == 0`) is a normal state (HK-16 startup WARN flow).
 *
 * Field semantics:
 *   total_discovered = per-iface subdir found under bpffs_root
 *   eacces_failures  = bpf_obj_get failed with EACCES or EPERM
 *   other_failures   = bpf_obj_get failed with anything else (ENOENT, ...)
 *   successes        = bpf_obj_get + lookup succeeded
 * Invariant: eacces_failures + other_failures + successes == total_discovered. */
struct DiscoveryAccounting {
    std::size_t total_discovered = 0;
    std::size_t eacces_failures  = 0;
    std::size_t other_failures   = 0;
    std::size_t successes        = 0;
};

/* §5.30 HK-16: one-shot startup check. If `bpffs_root` does not exist on
 * the filesystem, emit ONE line to stderr:
 *     xdpmf-exporter: WARN bpffs root <path> does not exist; will serve empty metrics
 * and return. If the path exists, returns silently (no positive log).
 * Called by main() exactly once BEFORE the first http::run() invocation.
 * NEVER throws. PI-32: graceful continue, exporter still serves /metrics
 * (returns the HELP+TYPE header only). */
void validate_bpffs_root_or_warn(std::string_view bpffs_root) noexcept;

/* §5.30 HK-17 (MVP-3.4.5) — scan ${bpffs_root}/<iface>/stats for every
 * attached iface; libbpf PERCPU-sum each one. Returns an empty vector on
 * empty / nonexistent bpffs root (PI-32 — graceful). May emit per-iface WARN
 * lines to stderr on transient open / lookup errors but never throws.
 * Additionally populates `acc` with per-iface accounting (see
 * DiscoveryAccounting); the caller examines `acc` to detect the all-EACCES
 * condition and exit(6) per D-3.4.5-2. (§5.71/B38: the dead single-arg
 * read_all_attached trampoline was removed — this is the sole entry-point.) */
[[nodiscard]] std::vector<StatsSample> read_all_attached_with_acc(
    std::string_view      bpffs_root,
    DiscoveryAccounting&  acc) noexcept;

}  // namespace xdpmf::exporter
