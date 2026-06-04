/*
 * percpu_read.hpp — shared inline home for the exporter's PERCPU-read helpers.
 *
 * §5.71 (MVP-4.31 / B38 — B2 + C1): the two exporter readers (stats_reader.cpp,
 * rule_counters_reader.cpp) each carried a byte-identical copy of round_up_8 /
 * percpu_sum_u64 / list_iface_dirs in their anon-namespaces. They now share ONE
 * definition here (namespace xdpmf::exporter::detail, all `inline`/`constexpr` →
 * ODR-safe across the two TUs). Equivalence is now by construction — one
 * definition cannot drift — which serves the §5.31 byte-equivalence goal
 * strictly better than two manually-kept-in-sync copies (D-mvp-4.31-HG2; C1
 * reverses §5.31's deliberate-duplication of list_iface_dirs).
 *
 * PI-31 (READ-ONLY): the only BPF syscall touched here is bpf_map_lookup_elem;
 * NO bpf_map_update_elem / delete / pin / link / prog_load. The reviewer's grep
 * over src/exporter/ covers this header.
 */
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <bpf/bpf.h>

namespace xdpmf::exporter::detail {

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
[[nodiscard]] inline std::vector<std::string> list_iface_dirs(std::string_view bpffs_root)
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

/* PERCPU sum of a map's value at `key`. Returns 0 on lookup error (caller logs
 * once per iface, not once per key, to avoid flooding stderr on a transient
 * bpffs unmount).
 *
 * §5.40 P-1: the caller hoists `buf` above the per-iface loop and reuses it for
 * every (iface, key) read, so the scratch allocation is O(1) per scrape. No
 * per-call zero-init is needed: on rc==0 the kernel overwrites the FULL span (so
 * every byte summed is freshly written by THIS lookup); on rc<0 the buffer is
 * never read (PI-3.4i-A: output value-identical). */
[[nodiscard]] inline std::uint64_t percpu_sum_u64(int map_fd,
                                                  std::uint32_t key,
                                                  int num_cpus,
                                                  std::span<std::uint8_t> buf)
{
    /* Each per-CPU slot is u64 (rounded up to 8 — same as natural alignment).
     * The kernel writes num_cpus * 8 bytes into the caller-provided span. */
    const std::size_t per_slot_bytes = round_up_8(sizeof(std::uint64_t));
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

}  // namespace xdpmf::exporter::detail
