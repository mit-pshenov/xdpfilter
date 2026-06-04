/*
 * stats_reader.cpp — exporter PERCPU stats reader.
 *
 * Walks ${bpffs_root}/, treats every entry that is a directory AND contains
 * a `stats` pin as an attached iface, opens it via bpf_obj_get() (RO fd),
 * and uses libbpf_num_possible_cpus() + bpf_map_lookup_elem() to sum each
 * STAT_PASS / STAT_DROP_DENY / STAT_DROP_MALFORMED / STAT_PASS_CIDR slot.
 *
 * PI-31 (READ-ONLY): the only BPF syscalls touched are bpf_obj_get + the
 * PERCPU lookup; NO bpf_map_update_elem / bpf_map_delete_elem / bpf_obj_pin
 * / bpf_link_create / xdp_attach / xdp_detach / prog_load. Reviewer's grep
 * over src/exporter/ enforces this fence.
 *
 * Failure mode: per-iface errors are logged + skipped — the daemon must
 * survive a transient pin disappearance (PI-32 — graceful empty/partial).
 */
#include "stats_reader.hpp"

#include "percpu_read.hpp"     // §5.71 B2: shared round_up_8/percpu_sum_u64/list_iface_dirs
#include "common/logger.hpp"   // §5.32 (MVP-3.5) structured-logging surface

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace xdpmf::exporter {

using detail::list_iface_dirs;
using detail::percpu_sum_u64;
using detail::round_up_8;

void validate_bpffs_root_or_warn(std::string_view bpffs_root) noexcept
{
    /* §5.30 HK-16 (W1): one-shot existence check at exporter startup.
     * fs::exists() returns false for both "does not exist" and "I can't
     * stat() because the parent denies search"; either flavour suffices
     * for the operator-facing WARN (the metrics path will be empty/erroring
     * either way). Suppress filesystem_error → noexcept contract. */
    std::error_code ec;
    const bool exists = std::filesystem::exists(
        std::filesystem::path{bpffs_root}, ec);
    if (ec || !exists) {
        /* §5.32 (MVP-3.5) HK-16 W1: byte-equivalent text-mode (PI-3.5-1) +
         * bpffs_root field in JSON. Process-scoped (no iface). */
        const std::string msg = std::format(
            "xdpmf-exporter: WARN bpffs root {} does not exist; "
            "will serve empty metrics\n", bpffs_root);
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"bpffs_root", bpffs_root},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                            "exporter.warn.bpffs_root_missing", msg, fs);
    }
}

std::vector<StatsSample> read_all_attached_with_acc(std::string_view     bpffs_root,
                                                     DiscoveryAccounting& acc) noexcept
{
    /* §5.30 HK-17: zero the accounting struct at every scrape. Caller
     * polls the snapshot after this call returns; "all-EACCES" detection
     * lives in main.cpp per D-3.4.5-2 (no exit() from library). */
    acc = DiscoveryAccounting{};

    std::vector<StatsSample> out;

    const std::vector<std::string> ifaces = list_iface_dirs(bpffs_root);
    acc.total_discovered = ifaces.size();
    if (ifaces.empty()) {
        return out;
    }

    const int num_cpus = ::libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        /* §5.32 (MVP-3.5): byte-equivalent text-mode + num_cpus in JSON.
         * Process-scoped (no iface). Shared event-name with
         * rule_counters_reader.cpp's identical site. */
        const std::string msg = std::format(
            "xdpmf-exporter: WARN libbpf_num_possible_cpus returned {}\n",
            num_cpus);
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"num_cpus", static_cast<std::int64_t>(num_cpus)},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                            "exporter.warn.cpu_count_invalid", msg, fs);
        /* §5.30 HK-17: cannot bpf_obj_get without a cpu count; count every
         * iface as other_failure so exit-6 (which requires all == EACCES)
         * does NOT fire on this distinct error path. */
        acc.other_failures = ifaces.size();
        return out;
    }

    /* §5.40 P-1: hoist + reuse the PERCPU read scratch buffer across the
     * per-iface loop. Sized once for the PERCPU map ABI (round_up_8(8) *
     * num_cpus bytes); see percpu_sum_u64 for the no-zero-init rationale. */
    std::vector<std::uint8_t> percpu_buf;
    percpu_buf.resize(round_up_8(sizeof(std::uint64_t))
                      * static_cast<std::size_t>(num_cpus));

    out.reserve(ifaces.size());
    for (const std::string& iface : ifaces) {
        std::string pin = std::string{bpffs_root};
        if (!pin.empty() && pin.back() != '/') {
            pin.push_back('/');
        }
        pin += iface;
        pin += "/";
        pin += XDPMF_MAP_STATS_NAME;

        const int fd = ::bpf_obj_get(pin.c_str());
        if (fd < 0) {
            const int e = errno;
            /* §5.30 HK-17: classify failure for the exit-6 accounting.
             * EACCES/EPERM are the operator-action-required errors (cap
             * mis-grant, bpffs mode change); any other errno (typically
             * ENOENT for a half-attached iface) does NOT count toward the
             * exit-6 trigger so a single permission glitch doesn't kill
             * the daemon if other ifaces are healthy. */
            if (e == EACCES || e == EPERM) {
                ++acc.eacces_failures;
            } else {
                ++acc.other_failures;
            }
            /* ENOENT is the common case for half-attached ifaces; squelch
             * to a single line per scrape (no flood). Other errors are
             * surfaced verbatim so operators can correlate via journalctl.
             *
             * §5.32 (MVP-3.5): byte-equivalent text-mode + iface/errno
             * surfaced as JSON fields for per-iface correlation. */
            const std::string errno_str = std::strerror(e);
            const std::string msg = std::format(
                "xdpmf-exporter: WARN failed to open stats pin for {}: {}\n",
                iface, errno_str);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
                xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(e)},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                                "exporter.scrape.warn.stats_open_failed",
                                std::string_view{iface}, msg, fs);
            continue;
        }

        StatsSample sample;
        sample.iface = iface;
        for (std::uint32_t k = 0; k < STAT_MAX; ++k) {
            sample.stats[k] = percpu_sum_u64(fd, k, num_cpus,
                                             std::span{percpu_buf});
        }
        (void)::close(fd);
        out.push_back(std::move(sample));
        ++acc.successes;
    }

    return out;
}

}  // namespace xdpmf::exporter
