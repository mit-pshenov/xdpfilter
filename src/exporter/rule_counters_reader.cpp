/*
 * rule_counters_reader.cpp — PERCPU sum reader for `rule_counters_<active>` map.
 *
 * Walks ${bpffs_root}/, for each per-iface directory that contains the new
 * §5.35 atomic-swap rule_counters pins: reads `active_idx[0]` to pick which
 * inner is live ({0,1} → suffix `_a`/`_b`), opens that inner via
 * bpf_obj_get() (RO fd), uses libbpf_num_possible_cpus() +
 * bpf_map_lookup_elem() to sum each of the XDPMF_RULE_COUNTERS_MAX (= 64)
 * slots across CPUs.
 *
 * §5.35 PI-3.4d-EXPORTER carve-out: the single `${PIN_DIR}/<iface>/rule_counters`
 * pin no longer exists (replaced by `rule_counters_a`/`_b`/`_outer`). Exporter
 * adapts to the active_idx-indirection here; existing per-CPU read + per-rule-id
 * loop UNCHANGED.
 *
 * PI-31-3.4b PRESERVED: the only BPF syscalls touched are bpf_obj_get + PERCPU
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
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace xdpmf::exporter {

namespace {

/* §5.64 (MVP-4.24) D-mvp-4.24-Q1: number of active_idx RE-READS after the
 * initial attempt before the seqlock stops retrying and commits the last
 * consistently-read generation. A single concurrent apply needs exactly one
 * retry to converge; 3 is generous for a rare multi-apply burst. Max total
 * buffer reads per iface ≤ 4 (1 initial + 3 retries) — bounded, NOT the B27
 * unbounded-retry DoS surface. */
inline constexpr std::size_t kRuleCountersGenRetryMax = 3;

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
 * stderr on a transient bpffs unmount).
 *
 * §5.40 (MVP-3.4i) P-1 + D-3.4i-1: the caller hoists `buf` above the per-iface
 * loop and reuses it for every (iface, key) read, so the scratch allocation is
 * O(1) per scrape instead of O(ifaces × XDPMF_RULE_COUNTERS_MAX). No per-call
 * zero-init is needed: on rc==0 the kernel overwrites the FULL span, so every
 * byte summed is freshly written by THIS lookup; on rc<0 the buffer is never
 * read. PI-3.4i-A holds (output value-identical). Kept independently per-TU
 * (the two readers stay duplicated per §5.31 guidance — NO factor-out). */
[[nodiscard]] std::uint64_t percpu_sum_u64(int map_fd,
                                            std::uint32_t key,
                                            int num_cpus,
                                            std::span<std::uint8_t> buf)
{
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

/* §5.64 (MVP-4.24) D-mvp-4.24-FD-REUSE: read the live ruleset index from an
 * already-open `active_idx` fd (reused across the seqlock's pre/post reads, so
 * one fd observes every loader flip). Out-of-range or lookup-failure → 0,
 * matching the pre-§5.64 clamp (a transient ENOENT falls through to slot 0,
 * which is also a valid inner pin). */
[[nodiscard]] std::uint32_t lookup_active(int active_fd)
{
    const std::uint32_t zero_key = 0;
    std::uint32_t       cur      = 0;
    const int lk = ::bpf_map_lookup_elem(active_fd, &zero_key, &cur);
    if (lk == 0 && cur < XDPMF_RULESET_COUNT) {
        return cur;
    }
    return 0;
}

/* §5.64 (MVP-4.24) D-mvp-4.24-WINDOW: read ONE full generation for `active` —
 * open `rule_counters_<active>`, PERCPU-sum all 64 slots into sample.counters,
 * then read `slot_rule_id`'s active half into sample.slot_to_id. BOTH buffers
 * are keyed by the SAME `active` so the committed sample pairs counters + ids
 * from one generation.
 *
 * Returns false (and emits the pre-existing `rule_counters_open_failed` WARN)
 * when the inner pin open fails — the seqlock does NOT suppress that fall-
 * through; the caller skips the iface exactly as today (PI-32 graceful-empty).
 * PI-31 PRESERVED: only bpf_obj_get + PERCPU lookup, no map mutation. */
[[nodiscard]] bool read_generation(std::string_view        iface,
                                   const std::string&      iface_dir,
                                   std::uint32_t           active,
                                   int                     num_cpus,
                                   std::span<std::uint8_t> percpu_buf,
                                   RuleCountersSample&     sample)
{
    std::string pin = iface_dir;
    pin += (active == 0)
            ? XDPMF_MAP_RULE_COUNTERS_INNER_A_NAME
            : XDPMF_MAP_RULE_COUNTERS_INNER_B_NAME;

    const int fd = ::bpf_obj_get(pin.c_str());
    if (fd < 0) {
        /* ENOENT is the common case for half-attached ifaces or pre-§5.31
         * ifaces attached by an older loader; squelch to a single line per
         * scrape (no flood).
         *
         * §5.32 (MVP-3.5): byte-equivalent text-mode + iface/errno surfaced as
         * JSON fields for per-iface correlation. The WARN-text token
         * "rule_counters" stays as the operator-grep-friendly substring. */
        const int         saved_errno = errno;
        const std::string errno_str   = std::strerror(saved_errno);
        const std::string msg         = std::format(
            "xdpmf-exporter: WARN failed to open rule_counters pin for {}: {}\n",
            iface, errno_str);
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
            xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(saved_errno)},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                            "exporter.scrape.warn.rule_counters_open_failed",
                            iface, msg, fs);
        return false;
    }

    sample.iface = std::string{iface};
    for (std::uint32_t k = 0; k < XDPMF_RULE_COUNTERS_MAX; ++k) {
        sample.counters[k] = percpu_sum_u64(fd, k, num_cpus, percpu_buf);
    }
    (void)::close(fd);

    /* §5.61 (MVP-4.21) B30: counters above are SLOT-keyed; recover each slot's
     * stable operator id from `slot_rule_id`'s active half so prom_format can
     * label `rule_match_total` by stable id. PI-32 graceful-empty: a pre-§5.61
     * iface has no slot_rule_id pin → leave slot_to_id all-sentinel. */
    for (std::uint32_t k = 0; k < XDPMF_RULE_COUNTERS_MAX; ++k) {
        sample.slot_to_id[k] = XDPMF_SLOT_ID_EMPTY;
    }
    const std::string sri_pin = iface_dir + XDPMF_MAP_SLOT_RULE_ID_NAME;
    const int         sri_fd  = ::bpf_obj_get(sri_pin.c_str());
    if (sri_fd >= 0) {
        const std::uint32_t base =
            active * static_cast<std::uint32_t>(XDPMF_ALLOWLIST_MAX);
        for (std::uint32_t slot = 0; slot < XDPMF_RULE_COUNTERS_MAX; ++slot) {
            const std::uint32_t key = base + slot;
            std::uint32_t       id  = XDPMF_SLOT_ID_EMPTY;
            if (::bpf_map_lookup_elem(sri_fd, &key, &id) == 0) {
                sample.slot_to_id[slot] = id;
            }
        }
        (void)::close(sri_fd);
    }
    return true;
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

    /* §5.40 (MVP-3.4i) P-1 + D-3.4i-1: hoist the PERCPU read scratch buffer
     * above the per-iface loop and reuse it for every (iface, key) lookup.
     * Sized once for the PERCPU map ABI (round_up_8(8) * num_cpus bytes); the
     * kernel overwrites the full span on each successful lookup. */
    std::vector<std::uint8_t> percpu_buf;
    percpu_buf.resize(round_up_8(sizeof(std::uint64_t))
                      * static_cast<std::size_t>(num_cpus));

    out.reserve(ifaces.size());
    for (const std::string& iface : ifaces) {
        /* §5.35 (MVP-3.4d) PI-3.4d-EXPORTER: the live inner is selected by
         * `active_idx`. §5.64 (MVP-4.24) wraps the active_idx→buffers read in a
         * bounded seqlock so a concurrent loader atomic-swap (`apply -f`) that
         * flips active_idx mid-read is detected and retried for freshness. */
        std::string iface_dir = std::string{bpffs_root};
        if (!iface_dir.empty() && iface_dir.back() != '/') {
            iface_dir.push_back('/');
        }
        iface_dir += iface;
        iface_dir += "/";

        const std::string active_idx_pin = iface_dir + XDPMF_MAP_ACTIVE_IDX_NAME;
        const int         active_fd      = ::bpf_obj_get(active_idx_pin.c_str());

        if (active_fd < 0) {
            /* §5.64 D-mvp-4.24-NOPIN-LEGACY: a half-attached / pre-§5.35 iface
             * has no active_idx seqnum to compare → single-shot read with
             * active=0 (exactly today's behavior, no seqlock). read_generation
             * emits the rule_counters_open_failed WARN + we skip on failure. */
            RuleCountersSample sample;
            if (read_generation(iface, iface_dir, 0, num_cpus,
                                std::span{percpu_buf}, sample)) {
                out.push_back(std::move(sample));
            }
            continue;
        }

        /* §5.64 D-mvp-4.24-SEQNUM seqlock: snapshot active_idx → read BOTH
         * buffers from that snapshot → re-read active_idx; if it flipped, the
         * sample is a consistent-but-now-stale generation → retry for freshness
         * (bounded by kRuleCountersGenRetryMax). The loader never mutates the
         * active buffer in place (it populates the inactive inner then atomic-
         * flips active_idx), so EVERY sample is a single consistent generation;
         * the after-N fallback is consistent-but-possibly-stale, NEVER torn
         * (D-mvp-4.24-TEAR-HONESTY). */
        RuleCountersSample candidate;
        bool               have_candidate = false;
        bool               open_failed    = false;
        bool               committed      = false;
        for (std::size_t attempt = 0; attempt <= kRuleCountersGenRetryMax;
             ++attempt) {
            const std::uint32_t active_pre = lookup_active(active_fd);
            RuleCountersSample  sample;
            if (!read_generation(iface, iface_dir, active_pre, num_cpus,
                                std::span{percpu_buf}, sample)) {
                open_failed = true;  // WARN already emitted by read_generation
                break;
            }
            const std::uint32_t active_post = lookup_active(active_fd);
            candidate      = std::move(sample);
            have_candidate = true;
            if (active_pre == active_post) {
                committed = true;  // no flip during the read → fresh + consistent
                break;
            }
            /* else: a flip landed mid-read; `candidate` is a consistent (older)
             * generation → loop again to try to capture the fresh one. */
        }
        (void)::close(active_fd);

        if (open_failed) {
            continue;  // PI-32: skip iface, exactly as the pre-§5.64 path did
        }

        if (!committed && have_candidate) {
            /* §5.64 D-mvp-4.24-Q1: retries exhausted without a stable snapshot
             * (a rare multi-apply burst) → serve the LAST consistently-read
             * generation (one full gen, never torn/zero) and make the rare
             * event observable. Emitted at most once per iface per scrape. */
            const std::string msg = std::format(
                "xdpmf-exporter: WARN rule_counters generation unstable for {} "
                "after {} attempts\n",
                iface, kRuleCountersGenRetryMax + 1);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{
                    "attempts",
                    static_cast<std::int64_t>(kRuleCountersGenRetryMax + 1)},
            };
            xdpmf::logger::emit(
                xdpmf::logger::Level::Warn,
                "exporter.scrape.warn.rule_counters_generation_unstable",
                std::string_view{iface}, msg, fs);
        }

        if (have_candidate) {
            out.push_back(std::move(candidate));
        }
    }

    return out;
}

}  // namespace xdpmf::exporter
