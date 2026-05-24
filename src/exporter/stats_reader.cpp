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

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace xdpmf::exporter {

namespace {

/* Round a PERCPU value-size up to 8 bytes per the kernel's PERCPU map ABI.
 * bpf_map_lookup_elem() on a PERCPU map fills num_possible_cpus * round-up-8
 * bytes into the caller buffer; we read exactly that. */
[[nodiscard]] constexpr std::size_t round_up_8(std::size_t n) noexcept
{
    return (n + 7u) & ~static_cast<std::size_t>(7u);
}

/* List subdirectories under `root` (one level deep). Returns iface names
 * sorted lexicographically so the exporter output ordering is stable across
 * scrapes. Skips dotfiles, regular files, broken symlinks. Silent on root
 * not existing (PI-32 — caller treats absent root as zero ifaces). */
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

/* PERCPU sum of the `stats` map's value at `key`. Returns 0 on lookup error
 * (caller logs once per iface, not once per key, to avoid flooding stderr
 * on a transient bpffs unmount). */
[[nodiscard]] std::uint64_t percpu_sum_u64(int stats_fd,
                                            std::uint32_t key,
                                            int num_cpus)
{
    /* Each per-CPU slot is u64 (rounded up to 8 — same as natural alignment).
     * We allocate sized buffer; libbpf writes num_cpus * 8 bytes. */
    const std::size_t per_slot_bytes = round_up_8(sizeof(std::uint64_t));
    std::vector<std::uint8_t> buf(per_slot_bytes
                                     * static_cast<std::size_t>(num_cpus),
                                  std::uint8_t{0});
    const int rc = ::bpf_map_lookup_elem(stats_fd, &key, buf.data());
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

std::vector<StatsSample> read_all_attached(std::string_view bpffs_root)
{
    std::vector<StatsSample> out;

    const std::vector<std::string> ifaces = list_iface_dirs(bpffs_root);
    if (ifaces.empty()) {
        return out;
    }

    const int num_cpus = ::libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        std::fprintf(stderr,
                     "xdpmf-exporter: WARN libbpf_num_possible_cpus returned %d\n",
                     num_cpus);
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
        pin += XDPMF_MAP_STATS_NAME;

        const int fd = ::bpf_obj_get(pin.c_str());
        if (fd < 0) {
            const int e = errno;
            /* ENOENT is the common case for half-attached ifaces; squelch
             * to a single line per scrape (no flood). Other errors are
             * surfaced verbatim so operators can correlate via journalctl. */
            std::fprintf(stderr,
                         "xdpmf-exporter: WARN failed to open stats pin for %s: %s\n",
                         iface.c_str(), std::strerror(e));
            continue;
        }

        StatsSample sample;
        sample.iface = iface;
        for (std::uint32_t k = 0; k < STAT_MAX; ++k) {
            sample.stats[k] = percpu_sum_u64(fd, k, num_cpus);
        }
        (void)::close(fd);
        out.push_back(std::move(sample));
    }

    return out;
}

}  // namespace xdpmf::exporter
