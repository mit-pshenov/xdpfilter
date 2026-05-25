/*
 * rule_counters_reader.cpp — PERCPU sum reader for `rule_counters` map.
 *
 * Walks ${bpffs_root}/, for each per-iface directory that contains a
 * `rule_counters` pin: opens it via bpf_obj_get() (RO fd), uses
 * libbpf_num_possible_cpus() + bpf_map_lookup_elem() to sum each of the
 * XDPMF_RULE_COUNTERS_MAX (= 64) slots across CPUs.
 *
 * PI-31-3.4b: the only BPF syscalls touched are bpf_obj_get + PERCPU
 * lookup — NO bpf_map_update_elem / delete / pin / link / prog_load.
 *
 * Failure mode: per-iface errors WARN-and-continue; the daemon survives
 * a transient pin disappearance (PI-32 — graceful empty/partial).
 */
#include "rule_counters_reader.hpp"

#include "common/logger.hpp"   // §5.32 (MVP-3.5) structured-logging surface

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace xdpmf::exporter {

namespace {

/* PERCPU map ABI rounds per-CPU value-size up to 8 bytes. We read exactly
 * num_possible_cpus * round-up-8 bytes per slot. */
[[nodiscard]] constexpr std::size_t round_up_8(std::size_t n) noexcept
{
    return (n + 7u) & ~static_cast<std::size_t>(7u);
}

/* List subdirectories under `root` (one level deep). Returns iface names
 * sorted lexicographically so the exporter output ordering is stable
 * across scrapes. Sister to stats_reader.cpp::list_iface_dirs — kept
 * duplicated rather than factored out per design's "default: keep
 * stats_reader.cpp byte-equivalent" guidance (§5.31 EDITED table). */
[[nodiscard]] std::vector<std::string> list_iface_dirs(std::string_view bpffs_root)
{
    std::vector<std::string> out;
    std::error_code          ec;
    std::filesystem::directory_iterator it{
        std::filesystem::path{bpffs_root}, ec};
    if (ec) {
        return out;
    }
    for (; it != std::filesystem::directory_iterator{}; it.increment(ec)) {
        if (ec) {
            break;
        }
        const auto& path = it->path();
        const auto  name = path.filename().string();
        if (name.empty() || name[0] == '.') {
            continue;
        }
        std::error_code ec2;
        if (!std::filesystem::is_directory(path, ec2) || ec2) {
            continue;
        }
        out.push_back(name);
    }
    std::sort(out.begin(), out.end());
    return out;
}

/* PERCPU sum of `rule_counters` map's value at `key`. Returns 0 on lookup
 * error (caller logs once per iface, not once per key, to avoid flooding
 * stderr on a transient bpffs unmount). */
[[nodiscard]] std::uint64_t percpu_sum_u64(int map_fd,
                                            std::uint32_t key,
                                            int num_cpus)
{
    const std::size_t per_slot_bytes = round_up_8(sizeof(std::uint64_t));
    std::vector<std::uint8_t> buf(per_slot_bytes
                                     * static_cast<std::size_t>(num_cpus),
                                  std::uint8_t{0});
    const int rc = ::bpf_map_lookup_elem(map_fd, &key, buf.data());
    if (rc < 0) {
        return 0;
    }
    std::uint64_t total = 0;
    for (int cpu = 0; cpu < num_cpus; ++cpu) {
        std::uint64_t v = 0;
        std::memcpy(&v,
                    buf.data() + static_cast<std::size_t>(cpu) * per_slot_bytes,
                    sizeof(std::uint64_t));
        total += v;
    }
    return total;
}

}  // namespace

std::vector<RuleCountersSample>
read_rule_counters(std::string_view bpffs_root) noexcept
{
    std::vector<RuleCountersSample> out;

    const std::vector<std::string> ifaces = list_iface_dirs(bpffs_root);
    if (ifaces.empty()) {
        return out;
    }

    const int num_cpus = ::libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        /* §5.32 (MVP-3.5): byte-equivalent text-mode + num_cpus in JSON.
         * Shared event-name with stats_reader.cpp's identical site. */
        const std::string msg = std::format(
            "xdpmf-exporter: WARN libbpf_num_possible_cpus returned {}\n",
            num_cpus);
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"num_cpus", static_cast<std::int64_t>(num_cpus)},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                            "exporter.warn.cpu_count_invalid", msg, fs);
        return out;
    }

    out.reserve(ifaces.size());
    for (const std::string& iface : ifaces) {
        std::string pin = std::string{bpffs_root};
        if (!pin.empty() && pin.back() != '/') {
            pin.push_back('/');
        }
        pin += iface;
        pin += "/";
        pin += XDPMF_MAP_RULE_COUNTERS_NAME;

        const int fd = ::bpf_obj_get(pin.c_str());
        if (fd < 0) {
            /* ENOENT is the common case for half-attached ifaces or
             * pre-§5.31 ifaces attached by an older loader; squelch
             * to a single line per scrape (no flood).
             *
             * §5.32 (MVP-3.5): byte-equivalent text-mode + iface/errno
             * surfaced as JSON fields for per-iface correlation. */
            const int saved_errno = errno;
            const std::string errno_str = std::strerror(saved_errno);
            const std::string msg = std::format(
                "xdpmf-exporter: WARN failed to open rule_counters pin for {}: {}\n",
                iface, errno_str);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
                xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(saved_errno)},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                                "exporter.scrape.warn.rule_counters_open_failed",
                                std::string_view{iface}, msg, fs);
            continue;
        }

        RuleCountersSample sample;
        sample.iface = iface;
        for (std::uint32_t k = 0; k < XDPMF_RULE_COUNTERS_MAX; ++k) {
            sample.counters[k] = percpu_sum_u64(fd, k, num_cpus);
        }
        (void)::close(fd);
        out.push_back(std::move(sample));
    }

    return out;
}

}  // namespace xdpmf::exporter
