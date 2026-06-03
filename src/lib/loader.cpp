/*
 * loader.cpp — XDP attach/detach control plane built on libbpf.
 *
 * Attach sequence (design §5.4 4-state probe, hardened per
 *   §5.19 (identity-name verification),
 *   §5.20 (all-modes XDP query),
 *   §5.22 (Item 1: tag-check identity gate via Option E early-load;
 *          Item 2: O_PATH bpffs root + fd-relative `*at()` hardening)):
 *   1. Resolve <iface> → ifindex.
 *   2. Open bpffs root with O_PATH|O_DIRECTORY|O_NOFOLLOW (BpffsRootFd RAII).
 *      Symlink at root → PathRefused (exit 8).
 *   3. Open + load skeleton (no pin_root_path — pinning happens manually
 *      after the state-machine branch so state-(c) refusal can unwind via
 *      the BpfSkeleton dtor without leaving pinned maps behind).
 *   4. Capture self_tag from bpf_obj_get_info_by_fd(skel->progs.mac_filter_prog->fd).tag.
 *   5. Probe the iface's XDP slot across ALL modes (HW > NATIVE > SKB) via
 *      bpf_xdp_query(), and — if a program is attached — verify its
 *      compile-time identity (name == "mac_filter_prog" AND tag == self_tag).
 *   6. 4-state disposition (fd-relative for per-iface entry):
 *      (a) no prog, no pin_dir            → fresh attach
 *      (b) prog ours (SKB + name + tag)   → detach + clean + fresh attach
 *      (c) prog alien (any other shape)   → throw AttachRefusedAlien (4)
 *      (d) no prog, pin_dir present       → cleanup orphan + fresh attach
 *      Symlink at per-iface entry on any state → PathRefused (exit 8).
 *   7. mkdirat per-iface bpffs dir, manually pin LIBBPF_PIN_BY_NAME maps,
 *      populate allow-list, attach XDP in SKB mode (Decision §5.6).
 *
 * Rollback on any throw: IfaceDirGuard tears down the per-iface bpffs dir
 * via the same fd-relative walk used by bpffs_remove_iface; BpfSkeleton
 * tears down libbpf state (and the kernel garbage-collects unpinned
 * programs/maps). On success the guards release().
 */
#include "loader.hpp"
#include "apply_internal.hpp"
#include "common/logger.hpp"  // §5.32 (MVP-3.5) structured-logging surface
#include "config.hpp"
#include "sidecar.hpp"     // §5.31 (MVP-3.4b) rule_index.json writer

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>           // §5.24: std::getenv for XDPMF_BPF_OBJECT_PATH
#include <cstring>
#include <format>
#include <fstream>           // §5.24: read override BPF object from path
#include <functional>        // §5.50 (MVP-4.10 B28-2): std::equal_to for aggregate_axis
#include <optional>          // §5.50 (MVP-4.10 B28-2): std::optional projector return
#include <span>              // §5.61 (MVP-4.21): copy_rule_counters_forward slot↔id spans
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>     // §5.61 (MVP-4.21): id→slot rank map (D-mvp-4.21-SLOT-PLUMB)
#include <utility>
#include <vector>

#include <arpa/inet.h>       // §5.43 (MVP-4.3): ntohl for prefix-closure masking
#include <dirent.h>
#include <fcntl.h>           // O_PATH, O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, openat
#include <linux/bpf.h>       // BPF_XDP, BPF_LINK_TYPE_XDP
#include <linux/if_link.h>   // XDP_FLAGS_SKB_MODE
#include <net/if.h>
#include <sys/stat.h>        // fstatat, mkdirat, S_IS*
#include <sys/types.h>
#include <sys/utsname.h>     // §5.24 Q1: uname() for kernel-version probe
#include <unistd.h>          // close, faccessat, unlinkat

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common/mac_filter.h"
#include "raii.hpp"

namespace xdpmf {

namespace {

/* §5.19 identity gate: the BPF program's SEC()-exported function name as
 * kernel-reported via bpf_prog_info.name. MUST match
 * src/bpf/mac_filter.bpf.c's `int mac_filter_prog(...)` symbol; renaming
 * that symbol without updating this constant silently breaks "ours"
 * classification. */
constexpr std::string_view kOwnedProgName{"mac_filter_prog"};

/* §5.22 Item 1: BPF program tag is the kernel-computed SHA1-truncated
 * hash of the loaded bytecode (UAPI: linux/bpf.h BPF_TAG_SIZE). Used as
 * the second identity factor on top of the name check. */
constexpr std::size_t kBpfTagSize = 8;  // BPF_TAG_SIZE
using TagArray = std::array<std::uint8_t, kBpfTagSize>;

/* §5.24 Q2: minimum supported kernel version floor. Below this, libbpf
 * deeper in BPF_PROG_LOAD would surface a cryptic "Invalid argument"; the
 * probe replaces that with a clear KernelUnsupported (exit 7). LTS reality
 * (Debian Bookworm, Ubuntu 22.04, AlmaLinux/Rocky 9) — matches README. */
constexpr int kKernelFloorMajor = 5;
constexpr int kKernelFloorMinor = 15;

/* §5.24 Q1 Option U: env-var name for the BPF object path override (Q4
 * fixture-path mechanism for T_VERIFIER_REJECT). Testing-only — not
 * documented in --help per §7 Robust OOS. When unset or empty, the
 * compiled-in embedded ELF bytes from the skeleton are used (byte-identical
 * to pre-§5.24 behaviour).
 *
 * §5.30 HK-3 (MVP-3.4.5): the constant + its consumer paths + their error
 * messages are now compile-gated behind XDPMF_ENABLE_BPF_OBJECT_OVERRIDE.
 * In a default release build the env var has zero effect AND the literal
 * string "XDPMF_BPF_OBJECT_PATH" is absent from the binary (reviewer asserts
 * `nm $(which xdpmacfilter) | grep -c XDPMF_BPF_OBJECT_PATH` == 0). The
 * in-tree test build forces this define ON via tests/CMakeLists.txt's
 * cache-FORCE, so T_VERIFIER_REJECT.sh continues to pass. */
#ifdef XDPMF_ENABLE_BPF_OBJECT_OVERRIDE
constexpr std::string_view kBpfObjectPathEnv{"XDPMF_BPF_OBJECT_PATH"};
#endif

/* §5.30 HK-9: consolidated `LIBBPF_PIN_BY_NAME` map table — the SINGLE source
 * of truth walked by all three call-site loops (clear / pin / reuse). Before
 * HK-9 each site carried its own literal pair-array, and a new pin-by-name map
 * had to be lockstep-added to all three (a missed lockstep caused the MVP-3.4
 * "libbpf: map already has pin path" failure). The member-pointer representation
 * (D-3.4.5-3) catches a libbpf-skel rename at BUILD time (compiler error) rather
 * than at runtime. Adding an axis = adding rows here; no per-site churn. */
using SkelMapsT = std::remove_reference_t<decltype(std::declval<mac_filter_bpf&>().maps)>;

struct ManagedMapEntry {
    /* Pointer-to-member into the libbpf-skel `maps` struct. Compile-time-
     * checked: any rename in mac_filter.bpf.c → mac_filter.skel.h auto-
     * fails the build at this initializer. */
    ::bpf_map* SkelMapsT::* member_ptr;
    const char* name;       // pin file name under ${PIN_DIR}/<iface>/
};

/* Order matches the existing pre-HK-9 `pin_specs[]` literal for line-diff
 * readability across the refactor commit. All three call-site loops (clear,
 * pin, reuse) walk every row uniformly (§5.58: no legacy-alias skip). */
constexpr ManagedMapEntry kManagedMaps[] = {
    { &SkelMapsT::allowlist_a,      XDPMF_MAP_INNER_A_NAME },
    { &SkelMapsT::allowlist_b,      XDPMF_MAP_INNER_B_NAME },
    { &SkelMapsT::rulesets,         XDPMF_MAP_RULESETS_OUTER_NAME },
    { &SkelMapsT::cidr_allowlist_a, XDPMF_MAP_CIDR_INNER_A_NAME },
    { &SkelMapsT::cidr_allowlist_b, XDPMF_MAP_CIDR_INNER_B_NAME },
    { &SkelMapsT::cidr_rulesets,    XDPMF_MAP_CIDR_RULESETS_OUTER_NAME },
    /* §5.43 dst-CIDR ARRAY_OF_MAPS trio + the single combined `wildcard` ARRAY
     * (D-mvp-4.3-Q2 — ONE indexed map). The src-CIDR axis reuses the existing
     * cidr_allowlist_a/_b/cidr_rulesets entries (value-only reshape, pin names
     * unchanged — guard #16). */
    { &SkelMapsT::dst_bitmask_a,    XDPMF_MAP_DST_INNER_A_NAME },
    { &SkelMapsT::dst_bitmask_b,    XDPMF_MAP_DST_INNER_B_NAME },
    { &SkelMapsT::dst_rulesets,     XDPMF_MAP_DST_RULESETS_OUTER_NAME },
    { &SkelMapsT::wildcard,         XDPMF_MAP_WILDCARD_NAME },
    /* §5.44 proto axis trio (proto_bitmask_a/_b + proto_rulesets, HASH) + port
     * axis trio (port_ranges_a/_b + port_rulesets, ARRAY). `wildcard` unchanged
     * (its max_entries grows via the BITVEC_NUM_AXES macro, not a new row). */
    { &SkelMapsT::proto_bitmask_a,  XDPMF_MAP_PROTO_INNER_A_NAME },
    { &SkelMapsT::proto_bitmask_b,  XDPMF_MAP_PROTO_INNER_B_NAME },
    { &SkelMapsT::proto_rulesets,   XDPMF_MAP_PROTO_RULESETS_OUTER_NAME },
    { &SkelMapsT::port_ranges_a,    XDPMF_MAP_PORT_INNER_A_NAME },
    { &SkelMapsT::port_ranges_b,    XDPMF_MAP_PORT_INNER_B_NAME },
    { &SkelMapsT::port_rulesets,    XDPMF_MAP_PORT_RULESETS_OUTER_NAME },
    /* §5.45 vlan axis trio (vlan_bitmask_a/_b + vlan_rulesets, HASH). */
    { &SkelMapsT::vlan_bitmask_a,   XDPMF_MAP_VLAN_INNER_A_NAME },
    { &SkelMapsT::vlan_bitmask_b,   XDPMF_MAP_VLAN_INNER_B_NAME },
    { &SkelMapsT::vlan_rulesets,    XDPMF_MAP_VLAN_RULESETS_OUTER_NAME },
    /* §5.53 IPv6 dst6 + src6 axis trios (LPM_TRIE inners keyed by xdpmf_cidr_v6),
     * forked from the §5.43 dst-CIDR trio. */
    { &SkelMapsT::dst6_bitmask_a,   XDPMF_MAP_DST6_INNER_A_NAME },
    { &SkelMapsT::dst6_bitmask_b,   XDPMF_MAP_DST6_INNER_B_NAME },
    { &SkelMapsT::dst6_rulesets,    XDPMF_MAP_DST6_RULESETS_OUTER_NAME },
    { &SkelMapsT::src6_bitmask_a,   XDPMF_MAP_SRC6_INNER_A_NAME },
    { &SkelMapsT::src6_bitmask_b,   XDPMF_MAP_SRC6_INNER_B_NAME },
    { &SkelMapsT::src6_rulesets,    XDPMF_MAP_SRC6_RULESETS_OUTER_NAME },
    /* §5.54 ethertype axis trio (ethertype_bitmask_a/_b + ethertype_rulesets,
     * HASH keyed by host-order u32 ethertype). */
    { &SkelMapsT::ethertype_bitmask_a, XDPMF_MAP_ETHERTYPE_INNER_A_NAME },
    { &SkelMapsT::ethertype_bitmask_b, XDPMF_MAP_ETHERTYPE_INNER_B_NAME },
    { &SkelMapsT::ethertype_rulesets,  XDPMF_MAP_ETHERTYPE_RULESETS_OUTER_NAME },
    { &SkelMapsT::active_idx,       XDPMF_MAP_ACTIVE_IDX_NAME },
    { &SkelMapsT::defaults,         XDPMF_MAP_DEFAULTS_NAME },
    /* §5.61 B30: the userspace-only `slot_rule_id` ARRAY (slot→id per ruleset
     * half), single-indexed like defaults/wildcard. Never referenced by
     * mac_filter_prog (HG-mvp-4.21-1). */
    { &SkelMapsT::slot_rule_id,     XDPMF_MAP_SLOT_RULE_ID_NAME },
    { &SkelMapsT::stats,            XDPMF_MAP_STATS_NAME },
    /* §5.34 rules axis trio (rules_a/_b + rules_outer), mirroring the §5.27
     * CIDR-axis triple. */
    { &SkelMapsT::rules_a,          XDPMF_MAP_RULES_INNER_A_NAME },
    { &SkelMapsT::rules_b,          XDPMF_MAP_RULES_INNER_B_NAME },
    { &SkelMapsT::rules_outer,      XDPMF_MAP_RULES_OUTER_NAME },
    { &SkelMapsT::action_table,     XDPMF_MAP_ACTION_TABLE_NAME },
    /* §5.35 rule_counters axis trio (rule_counters_a/_b + rule_counters_outer,
     * PERCPU_ARRAY inners). The LIBBPF_PIN_BY_NAME + bpf_map__reuse_fd discipline
     * preserves per-CPU counter values across apply (Prometheus counter-
     * monotonicity); combined with copy_rule_counters_forward (D-3.4d-3),
     * PI-3.4b-2 PRESERVE-across-apply holds. */
    { &SkelMapsT::rule_counters_a,     XDPMF_MAP_RULE_COUNTERS_INNER_A_NAME },
    { &SkelMapsT::rule_counters_b,     XDPMF_MAP_RULE_COUNTERS_INNER_B_NAME },
    { &SkelMapsT::rule_counters_outer, XDPMF_MAP_RULE_COUNTERS_OUTER_NAME },
};

/* §5.4 + §5.20: per-iface XDP slot classification as observed by the §5.20
 * all-modes probe. Distinct from the public-API ::xdpmf::XdpMode (which
 * carries the operator's --mode choice for attach); this enum is the
 * kernel-side ground-truth read back from the netdev. Anon-namespace only. */
enum class ProbedMode : std::uint8_t { None, Skb, Native, Hw };

[[nodiscard]] constexpr std::string_view to_string(ProbedMode m) noexcept
{
    switch (m) {
        case ProbedMode::None:   return "NONE";
        case ProbedMode::Skb:    return "SKB";
        case ProbedMode::Native: return "NATIVE";
        case ProbedMode::Hw:     return "HW";
    }
    return "?";
}

/* §5.23 Item 2: map the public-API XdpMode (cli.cpp → AttachConfig.mode) to
 * the kernel XDP_FLAGS_*_MODE bit used by bpf_xdp_attach.
 * Kernel-ABI coupling stays in this TU (loader.hpp exposes the enum but
 * no flag values — design.md §5.23 "do NOT map them directly to XDP_FLAGS_*"). */
[[nodiscard]] constexpr std::uint32_t mode_to_flags(XdpMode m) noexcept
{
    switch (m) {
        case XdpMode::Generic: return XDP_FLAGS_SKB_MODE;
        case XdpMode::Native:  return XDP_FLAGS_DRV_MODE;
        case XdpMode::Offload: return XDP_FLAGS_HW_MODE;
    }
    return XDP_FLAGS_SKB_MODE;  // unreachable; switch is exhaustive
}

/* Human label for the operator-selected mode. Used in attach()'s stderr
 * format so §6.17 tester grep for "native" / "mode=native" matches. */
[[nodiscard]] constexpr std::string_view to_string(XdpMode m) noexcept
{
    switch (m) {
        case XdpMode::Generic: return "generic";
        case XdpMode::Native:  return "native";
        case XdpMode::Offload: return "offload";
    }
    return "?";
}

/* §5.23 Q1 detach() symmetry: the §5.20-probed XDP mode is what detach
 * passes to bpf_xdp_detach (instead of hardcoded SKB). Probe mode None
 * never reaches the detach call (state (b) precondition is prog_id != 0). */
[[nodiscard]] constexpr std::uint32_t probed_mode_to_flags(ProbedMode m) noexcept
{
    switch (m) {
        case ProbedMode::Skb:    return XDP_FLAGS_SKB_MODE;
        case ProbedMode::Native: return XDP_FLAGS_DRV_MODE;
        case ProbedMode::Hw:     return XDP_FLAGS_HW_MODE;
        case ProbedMode::None:   return XDP_FLAGS_SKB_MODE;  // unreachable on detach state (b)
    }
    return XDP_FLAGS_SKB_MODE;
}

/* Single-syscall probe result (§5.19/§5.20/§5.22). `is_ours` is the
 * conjunction of (mode == SKB) AND name == kOwnedProgName AND tag ==
 * self_tag — all three necessary post-§5.22. The `tag` field is populated
 * whenever `prog_id != 0`; zeroed otherwise (and zeroed on identity-fetch
 * failure, in which case `is_ours == false` via the name branch). */
struct XdpProbe {
    std::uint32_t prog_id = 0;
    ProbedMode    mode    = ProbedMode::None;
    bool          is_ours = false;
    std::string   name;
    TagArray      tag{};
};

/* Deterministic fd close. Single-callsite-pattern helper kept out of
 * raii.hpp per §5.19 — used for transient prog fds (§5.19) and for the
 * fd-relative bpffs walk (§5.22 Item 2). */
class UniqueFd {
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int fd) noexcept : fd_(fd) {}
    UniqueFd(const UniqueFd&)            = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    UniqueFd(UniqueFd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }
    ~UniqueFd() noexcept { reset(); }

    void reset() noexcept {
        if (fd_ >= 0) {
            (void)::close(fd_);
            fd_ = -1;
        }
    }
    /* Relinquish ownership to a callee that will close on its own
     * (e.g. fdopendir consumes the fd it is given). */
    [[nodiscard]] int release() noexcept {
        const int f = fd_;
        fd_ = -1;
        return f;
    }
    [[nodiscard]] int  get()   const noexcept { return fd_; }
    [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }

private:
    int fd_ = -1;
};

/* Single category instance — see loader.hpp. */
class LoaderCategory final : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override { return "xdpmf.loader"; }
    [[nodiscard]] std::string message(int ev) const override
    {
        switch (static_cast<LoaderError>(ev)) {
            case LoaderError::LoadFailed:         return "BPF object load failed";
            case LoaderError::AttachFailed:       return "XDP attach failed";
            case LoaderError::AttachRefusedAlien: return "alien XDP program already attached";
            case LoaderError::DetachFailed:       return "detach failed";
            case LoaderError::Permission:         return "permission denied (need CAP_BPF / CAP_NET_ADMIN)";
            case LoaderError::KernelUnsupported:  return "kernel version too old for xdpmacfilter";
            case LoaderError::PathRefused:        return "bpffs path refused (symlink or non-directory at the bpffs root or per-iface entry)";
            case LoaderError::ConfigError:        return "config error (YAML parse / schema / trust_model violation)";
        }
        return "unknown loader error";
    }
};

/* Translate libbpf -errno into a LoaderError suitable for the given step.
 * EPERM/EACCES always map to LoaderError::Permission so users see the
 * "run as root" diagnostic regardless of which step rejected them. */
[[nodiscard]] LoaderError classify(int neg_errno, LoaderError fallback) noexcept
{
    const int e = neg_errno < 0 ? -neg_errno : neg_errno;
    if (e == EPERM || e == EACCES) {
        return LoaderError::Permission;
    }
    return fallback;
}

[[noreturn]] void throw_loader(LoaderError code, std::string what)
{
    throw std::system_error(make_error_code(code), std::move(what));
}

/* §5.24 Q1: parse the leading "<major>.<minor>" of utsname.release. Accepts
 * canonical forms like "5.15.0", "5.15.0-100-generic", "6.1.0-rc4+", and
 * partial "5.15" (no patch). Rejects null, non-digit lead, missing dot,
 * empty minor field, and integer overflow. Returns true iff *out_major and
 * *out_minor are filled. Defensive: on any malformed input the caller
 * treats this as "fail closed" → throw KernelUnsupported. */
[[nodiscard]] bool parse_major_minor(const char* release,
                                     int* out_major,
                                     int* out_minor) noexcept
{
    if (release == nullptr || out_major == nullptr || out_minor == nullptr) {
        return false;
    }
    constexpr int kMaxComponent = 1'000'000;  // overflow guard far below INT_MAX
    auto parse_digits = [](const char*& p, int& value) noexcept -> bool {
        if (*p < '0' || *p > '9') {
            return false;  // require at least one digit
        }
        int v = 0;
        while (*p >= '0' && *p <= '9') {
            v = v * 10 + (*p - '0');
            if (v > kMaxComponent) {
                return false;  // overflow guard
            }
            ++p;
        }
        value = v;
        return true;
    };

    const char* p = release;
    int maj = 0;
    int min = 0;
    if (!parse_digits(p, maj)) return false;
    if (*p != '.')             return false;  // missing dot
    ++p;
    if (!parse_digits(p, min)) return false;  // empty minor field
    *out_major = maj;
    *out_minor = min;
    return true;
}

/* §5.24 Q3 Option B: kernel-version fast-fail at the head of attach() AND
 * detach(). One uname(2) syscall + a tiny parse — below the noise floor
 * (~microseconds). Replaces the cryptic libbpf `Invalid argument` from
 * deep inside bpf_object__load that operators on too-old kernels would
 * otherwise see (audit-clarity, not a security mechanism).
 *
 * Stderr discipline (load-bearing for §6.20 T_VERIFIER_REJECT siblings and
 * §5.24 stderr contract): on too-old kernel the thrown what() includes the
 * literals `kernel`, `too old`, the running `<maj>.<min>`, the floor `5.15`,
 * and the program name `xdpmacfilter`. */
void kernel_version_probe()
{
    struct utsname u{};
    if (::uname(&u) != 0) {
        const int e = errno;
        throw_loader(LoaderError::KernelUnsupported,
                     std::format("xdpmacfilter: uname() failed: {} "
                                 "(need kernel ≥ {}.{})",
                                 std::strerror(e),
                                 kKernelFloorMajor, kKernelFloorMinor));
    }
    int maj = 0;
    int min = 0;
    if (!parse_major_minor(u.release, &maj, &min)) {
        throw_loader(LoaderError::KernelUnsupported,
                     std::format("xdpmacfilter: unable to parse kernel release '{}' "
                                 "(need kernel ≥ {}.{})",
                                 u.release,
                                 kKernelFloorMajor, kKernelFloorMinor));
    }
    // Lexicographic compare via std::pair: maj first, then min on tie.
    if (std::pair{maj, min} < std::pair{kKernelFloorMajor, kKernelFloorMinor}) {
        throw_loader(LoaderError::KernelUnsupported,
                     std::format("xdpmacfilter: kernel {}.{} too old, "
                                 "need ≥ {}.{}",
                                 maj, min,
                                 kKernelFloorMajor, kKernelFloorMinor));
    }
}

[[nodiscard]] std::string bpffs_dir_for(const std::string& iface)
{
    return std::string{XDPMF_BPFFS_ROOT} + "/" + iface;
}

/* §5.22 Item 2 stderr discipline: load-bearing literal `symlink` token +
 * iface name token; tester §6.15 greps for both. */
[[noreturn]] void throw_iface_symlink(const std::string& iface)
{
    throw_loader(LoaderError::PathRefused,
                 std::format("bpffs entry for iface '{}' is a symlink — refusing to operate",
                             iface));
}

[[noreturn]] void throw_iface_not_dir(const std::string& iface)
{
    throw_loader(LoaderError::PathRefused,
                 std::format("bpffs entry for iface '{}' is not a directory — refusing to operate",
                             iface));
}

/* §5.36 (MVP-3.4e) D-3.4e-3 Q2.A2: dev_valid_name-style shape check for
 * the operator-controlled `iface` token BEFORE it is composed into any
 * filesystem path. Rejects:
 *   - empty (defense-in-depth — cli.cpp parser also rejects)
 *   - length > IFNAMSIZ - 1 (= 15) per kernel `dev_valid_name`
 *   - any char outside [A-Za-z0-9._-] (rejects '/', whitespace, NUL,
 *     control chars; mirrors POSIX portable filename character set)
 *   - exact "." or ".." (kernel reserves; canonical path-traversal tokens)
 * Throws std::system_error{on_fail, ...} with stderr containing the
 * literal `refusing to operate` token (load-bearing for §6 T-1 grep).
 *
 * Anon-namespace fence (D-3.4e-2). §5.62 (MVP-4.22) R-1 / SEC-H1: now also
 * the FIRST statement of apply_request() and detach() so the iface shape-fence
 * (exit 8) is uniform across all three entry points (reset/apply/detach). */
void validate_iface_name(const std::string& iface, LoaderError on_fail)
{
    auto reject = [&](std::string_view why) {
        throw_loader(on_fail,
                     std::format("iface name '{}' is invalid or unsafe — "
                                 "refusing to operate ({})",
                                 iface, why));
    };

    if (iface.empty()) {
        reject("empty");
    }
    // IFNAMSIZ - 1 = 15 — leave room for the NUL terminator the kernel
    // expects on ifname-shaped strings.
    if (iface.size() > 15) {
        reject("length > 15");
    }
    if (iface == "." || iface == "..") {
        reject("reserved name");
    }
    for (const char c : iface) {
        const bool ok = (c >= 'A' && c <= 'Z')
                     || (c >= 'a' && c <= 'z')
                     || (c >= '0' && c <= '9')
                     || c == '.' || c == '_' || c == '-';
        if (!ok) {
            reject("disallowed character");
        }
    }
}

/* §5.22 Item 2: O_PATH | O_DIRECTORY | O_NOFOLLOW fd on the bpffs root.
 * Single-callsite RAII per the §5.19 anon-namespace rule (not exported
 * to raii.hpp). All per-iface `*at()` syscalls in this TU resolve relative
 * to this fd, so the root path token is unforgeable from this point on.
 *
 * Ctor: open root; on ENOENT mkdir-once + retry; ELOOP/ENOTDIR throw
 * PathRefused (exit 8) with stderr containing literal `symlink` + root
 * path (load-bearing for §6.15 root-variant); EACCES/EPERM throw
 * Permission; anything else throws LoadFailed. */
class BpffsRootFd {
public:
    BpffsRootFd()
    {
        const char* root = XDPMF_BPFFS_ROOT;
        // O_PATH + O_NOFOLLOW on a symlink returns a fd to the symlink
        // itself (NOT ELOOP — per `man 2 open`). Combined with O_DIRECTORY,
        // the kernel then surfaces the "target isn't a dir" mismatch as
        // ENOTDIR. We disambiguate symlink-vs-other-non-dir below via
        // lstat so the stderr message carries the literal `symlink` token
        // (load-bearing for §6.15 root-variant tester grep).
        int fd = ::open(root, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            const int e = errno;
            if (e == ENOENT) {
                // Bpffs root is missing — try to create it once (idempotent
                // mkdir; race-safe under EEXIST).
                if (::mkdir(root, 0755) != 0 && errno != EEXIST) {
                    const int e2 = errno;
                    throw_loader(classify(-e2, LoaderError::LoadFailed),
                                 std::format("mkdir bpffs root '{}': {}",
                                             root, std::strerror(e2)));
                }
                fd = ::open(root, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                if (fd < 0) {
                    const int e2 = errno;
                    throw_loader(classify(-e2, LoaderError::LoadFailed),
                                 std::format("open bpffs root '{}' after mkdir: {}",
                                             root, std::strerror(e2)));
                }
            } else if (e == ELOOP) {
                // Some kernels surface symlink-at-trailing-component as
                // ELOOP under O_PATH+O_NOFOLLOW+O_DIRECTORY; keep the
                // literal-symlink message for them too.
                throw_loader(LoaderError::PathRefused,
                             std::format("bpffs root '{}' is a symlink — refusing to operate",
                                         root));
            } else if (e == ENOTDIR) {
                // Disambiguate: symlink (test-fixture case) vs regular
                // file / other non-dir.
                struct stat st{};
                const bool is_link = (::lstat(root, &st) == 0)
                                     && S_ISLNK(st.st_mode);
                if (is_link) {
                    throw_loader(LoaderError::PathRefused,
                                 std::format("bpffs root '{}' is a symlink — refusing to operate",
                                             root));
                }
                throw_loader(LoaderError::PathRefused,
                             std::format("bpffs root '{}' is not a directory — refusing to operate",
                                         root));
            } else if (e == EACCES || e == EPERM) {
                throw_loader(LoaderError::Permission,
                             std::format("open bpffs root '{}': {}",
                                         root, std::strerror(e)));
            } else {
                throw_loader(LoaderError::LoadFailed,
                             std::format("open bpffs root '{}': {}",
                                         root, std::strerror(e)));
            }
        }
        fd_ = fd;
    }

    ~BpffsRootFd() noexcept {
        if (fd_ >= 0) {
            (void)::close(fd_);
        }
    }

    BpffsRootFd(const BpffsRootFd&)            = delete;
    BpffsRootFd& operator=(const BpffsRootFd&) = delete;

    BpffsRootFd(BpffsRootFd&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }
    BpffsRootFd& operator=(BpffsRootFd&& other) noexcept {
        if (this != &other) {
            if (fd_ >= 0) (void)::close(fd_);
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }

    [[nodiscard]] int fd() const noexcept { return fd_; }

private:
    int fd_ = -1;
};

/* §5.22 Item 2: classify the per-iface entry inside the bpffs root via
 * fd-relative faccessat + fstatat (AT_SYMLINK_NOFOLLOW). Returns true on
 * "real directory exists"; false on ENOENT; throws PathRefused on
 * symlink or non-directory. */
[[nodiscard]] bool iface_entry_is_real_dir(const BpffsRootFd& root, const std::string& iface)
{
    if (::faccessat(root.fd(), iface.c_str(), F_OK, AT_SYMLINK_NOFOLLOW) != 0) {
        const int e = errno;
        if (e == ENOENT) return false;
        // ELOOP can surface from faccessat on a dangling symlink chain on
        // intermediate components — treat as symlink-refused (defensive).
        if (e == ELOOP) throw_iface_symlink(iface);
        throw_loader(classify(-e, LoaderError::LoadFailed),
                     std::format("faccessat bpffs/{}: {}", iface, std::strerror(e)));
    }
    struct stat st{};
    if (::fstatat(root.fd(), iface.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
        const int e = errno;
        throw_loader(classify(-e, LoaderError::LoadFailed),
                     std::format("fstatat bpffs/{}: {}", iface, std::strerror(e)));
    }
    if (S_ISLNK(st.st_mode)) throw_iface_symlink(iface);
    if (!S_ISDIR(st.st_mode)) throw_iface_not_dir(iface);
    return true;
}

/* §5.22 Item 2: fd-relative `mkdirat` of the per-iface dir. On EEXIST
 * verify it's a real dir via fstatat (symlink TOCTOU defense). */
void ensure_iface_dir(const BpffsRootFd& root, const std::string& iface)
{
    if (::mkdirat(root.fd(), iface.c_str(), 0755) == 0) {
        return;
    }
    const int e = errno;
    if (e == EEXIST) {
        struct stat st{};
        if (::fstatat(root.fd(), iface.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
            const int e2 = errno;
            throw_loader(classify(-e2, LoaderError::LoadFailed),
                         std::format("fstatat after EEXIST bpffs/{}: {}",
                                     iface, std::strerror(e2)));
        }
        if (S_ISLNK(st.st_mode)) throw_iface_symlink(iface);
        if (!S_ISDIR(st.st_mode)) throw_iface_not_dir(iface);
        return;
    }
    throw_loader(classify(-e, LoaderError::LoadFailed),
                 std::format("mkdirat bpffs/{}: {}", iface, std::strerror(e)));
}

/* §5.22 Item 2: fd-relative removal of the per-iface dir. Open with
 * O_PATH|O_NOFOLLOW for the AT_REMOVEDIR endpoint AND O_RDONLY|O_NOFOLLOW
 * (a second, disjoint fd) for fdopendir — `fdopendir` consumes its fd, so
 * sharing a single fd between the two ops is a use-after-close foot-gun.
 *
 * ENOENT at any step → silent no-op (preserves §5.4 state-(d) and
 * §5.21 D4 idempotency).
 * ELOOP at the initial openat → PathRefused (symlink attack rejected
 * even on the removal path).
 */
void bpffs_remove_iface(const BpffsRootFd& root, const std::string& iface)
{
    // (1) O_PATH handle: only used as the `dirfd` for unlinkat() entries
    // and as the rmdir target via root + iface name.
    int path_raw = ::openat(root.fd(), iface.c_str(),
                            O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (path_raw < 0) {
        const int e = errno;
        if (e == ENOENT) return;
        if (e == ELOOP)  throw_iface_symlink(iface);
        if (e == ENOTDIR) throw_iface_not_dir(iface);
        throw_loader(classify(-e, LoaderError::LoadFailed),
                     std::format("openat bpffs/{}: {}", iface, std::strerror(e)));
    }
    UniqueFd path_fd{path_raw};

    // (2) Readable handle for fdopendir. fdopendir takes ownership of the
    // fd, so we keep this in a separate UniqueFd and release() it at the
    // moment of fdopendir success. On any throw before that release, the
    // UniqueFd dtor closes it; on success, closedir owns lifetime.
    int read_raw = ::openat(root.fd(), iface.c_str(),
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (read_raw < 0) {
        const int e = errno;
        if (e == ENOENT) return;
        if (e == ELOOP)  throw_iface_symlink(iface);
        throw_loader(classify(-e, LoaderError::LoadFailed),
                     std::format("openat (readdir) bpffs/{}: {}",
                                 iface, std::strerror(e)));
    }
    UniqueFd read_fd{read_raw};

    DIR* dirp = ::fdopendir(read_fd.get());
    if (dirp == nullptr) {
        const int e = errno;
        throw_loader(classify(-e, LoaderError::LoadFailed),
                     std::format("fdopendir bpffs/{}: {}",
                                 iface, std::strerror(e)));
    }
    // fdopendir succeeded — relinquish read_fd ownership to closedir to
    // avoid a double-close in the UniqueFd dtor (the "foot-gun" called
    // out in §5.22 Q2 detail block).
    (void)read_fd.release();

    // (3) Iterate, unlink each entry via the O_PATH dirfd. The pinned
    // files (allowlist, stats) are regular-file-ish; AT_REMOVEDIR is not
    // needed for them.
    errno = 0;
    for (struct dirent* ent = ::readdir(dirp); ent != nullptr;
         ent = (errno = 0, ::readdir(dirp))) {
        const std::string_view name{ent->d_name};
        if (name == "." || name == "..") continue;
        if (::unlinkat(path_fd.get(), ent->d_name, 0) != 0) {
            const int e = errno;
            if (e == ENOENT) continue;  // raced (concurrent cleanup) — fine
            (void)::closedir(dirp);
            throw_loader(classify(-e, LoaderError::LoadFailed),
                         std::format("unlinkat bpffs/{}/{}: {}",
                                     iface, ent->d_name, std::strerror(e)));
        }
    }
    if (errno != 0) {
        const int e = errno;
        (void)::closedir(dirp);
        throw_loader(classify(-e, LoaderError::LoadFailed),
                     std::format("readdir bpffs/{}: {}",
                                 iface, std::strerror(e)));
    }
    (void)::closedir(dirp);  // also closes the underlying read fd

    // (4) Final: rmdir the now-empty iface entry. Idempotent on ENOENT.
    if (::unlinkat(root.fd(), iface.c_str(), AT_REMOVEDIR) != 0) {
        const int e = errno;
        if (e == ENOENT) return;
        throw_loader(classify(-e, LoaderError::LoadFailed),
                     std::format("unlinkat AT_REMOVEDIR bpffs/{}: {}",
                                 iface, std::strerror(e)));
    }
}

class IfaceDirGuard {
public:
    IfaceDirGuard() noexcept = default;
    IfaceDirGuard(const BpffsRootFd& root, std::string iface) noexcept
        : root_(&root), iface_(std::move(iface)) {}

    IfaceDirGuard(const IfaceDirGuard&)            = delete;
    IfaceDirGuard& operator=(const IfaceDirGuard&) = delete;

    IfaceDirGuard(IfaceDirGuard&& other) noexcept
        : root_(other.root_), iface_(std::move(other.iface_)), armed_(other.armed_) {
        other.armed_ = false;
        other.root_  = nullptr;
    }
    IfaceDirGuard& operator=(IfaceDirGuard&& other) noexcept {
        if (this != &other) {
            reset();
            root_  = other.root_;
            iface_ = std::move(other.iface_);
            armed_ = other.armed_;
            other.armed_ = false;
            other.root_  = nullptr;
        }
        return *this;
    }

    ~IfaceDirGuard() noexcept { reset(); }

    void arm()     noexcept { armed_ = true; }
    void release() noexcept { armed_ = false; }

    void reset() noexcept {
        if (armed_ && root_ != nullptr) {
            try {
                bpffs_remove_iface(*root_, iface_);
            } catch (...) {
                // Dtor path — we are unwinding; do not propagate.
            }
            armed_ = false;
        }
    }

private:
    const BpffsRootFd* root_ = nullptr;
    std::string        iface_;
    bool               armed_ = false;
};

/* §5.19 + §5.22 Item 1 identity verification: fetch bpf_prog_info for
 * prog_id, populate `name` and `tag`, return true iff name matches
 * kOwnedProgName. Fails closed: any errno on fd-get or info-get returns
 * false (the caller treats the prog as alien). `name` is filled with
 * whatever the kernel reported (possibly empty on failure) so the
 * §5.4-(c) stderr message can name the foreign program — even if its
 * name is the empty string. `tag` is populated on the same info call;
 * left zero on failure. */
[[nodiscard]] bool fetch_prog_identity(std::uint32_t prog_id,
                                       std::string& name,
                                       TagArray& tag) noexcept
{
    name.clear();
    tag.fill(0);

    const int raw_fd = bpf_prog_get_fd_by_id(prog_id);
    if (raw_fd < 0) {
        return false;  // TOCTOU or EPERM — fail closed
    }
    UniqueFd fd{raw_fd};

    struct bpf_prog_info info{};
    std::uint32_t info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd.get(), &info, &info_len) != 0) {
        return false;
    }

    const std::size_t n = ::strnlen(info.name, BPF_OBJ_NAME_LEN);
    name.assign(info.name, n);
    static_assert(sizeof(info.tag) == kBpfTagSize,
                  "kernel BPF_TAG_SIZE expected to be 8 — UAPI invariant");
    std::memcpy(tag.data(), info.tag, kBpfTagSize);
    return std::string_view{name} == kOwnedProgName;
}

/* §5.4 + §5.19 + §5.20 + §5.22: single-syscall XDP probe across all modes,
 * with name+tag identity verification when a program is found. The
 * `self_tag` parameter is the tag of OUR just-loaded skeleton (§5.22 Q1
 * Option E early-load); `is_ours` requires all three of mode==SKB, name
 * match, and tag match. Return-by-value POD. NEVER throws on the success
 * path; any kernel/libbpf failure during identity fetch downgrades the
 * result to `is_ours = false` (fail-closed). */
[[nodiscard]] XdpProbe probe_attached_xdp(int ifindex, const TagArray& self_tag)
{
    XdpProbe out;

    bpf_xdp_query_opts opts{};
    opts.sz = sizeof(opts);

    const int rc = bpf_xdp_query(ifindex, 0, &opts);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::AttachFailed),
                     std::format("bpf_xdp_query: {}", std::strerror(-rc)));
    }

    // Mode priority HW > NATIVE > SKB per §5.20.
    if (opts.hw_prog_id != 0) {
        out.prog_id = opts.hw_prog_id;
        out.mode    = ProbedMode::Hw;
    } else if (opts.drv_prog_id != 0) {
        out.prog_id = opts.drv_prog_id;
        out.mode    = ProbedMode::Native;
    } else if (opts.skb_prog_id != 0) {
        out.prog_id = opts.skb_prog_id;
        out.mode    = ProbedMode::Skb;
    } else {
        return out;  // (a)/(d): nothing attached.
    }

    // §5.22 Item 1 + §5.23 Q1: identity evaluation order — mode (cheapest;
    // ANY of SKB/NATIVE/HW since §5.23 relaxes the SKB-only restriction),
    // then name (compile-time literal compare), then tag (byte-array equality).
    // Short-circuit on first failure.
    const bool name_matches = fetch_prog_identity(out.prog_id, out.name, out.tag);
    out.is_ours = (out.mode != ProbedMode::None)
                  && name_matches
                  && (out.tag == self_tag);
    return out;
}

/* Resolve interface name → ifindex, or throw AttachFailed (no separate
 * usage-error code: kernel/iface state is a runtime not a parse problem). */
[[nodiscard]] int resolve_ifindex(const std::string& iface, LoaderError on_fail)
{
    const unsigned int idx = if_nametoindex(iface.c_str());
    if (idx == 0) {
        const int e = errno;
        throw_loader(classify(-e, on_fail),
                     std::format("if_nametoindex({}): {}", iface, std::strerror(e)));
    }
    return static_cast<int>(idx);
}

/* §5.22 Q1 Option E: open + load the skeleton WITHOUT auto-pinning to
 * disk. LIBBPF_PIN_BY_NAME normally drives libbpf to auto-pin each map
 * at `<pin_root_path>/<mapname>` (or its built-in default
 * `/sys/fs/bpf/<mapname>` if pin_root_path isn't set) during load.
 * We need pinning suppressed at this stage because the §5.4 state machine
 * has not yet decided whether the per-iface dir needs cleanup, and on a
 * state-(c) refusal we want the BpfSkeleton dtor to unwind the kernel
 * program+maps with nothing on disk to clean up.
 *
 * Mechanism: bpf_map__set_pin_path(map, NULL) clears the pin_path libbpf
 * computed from LIBBPF_PIN_BY_NAME during open; load() then skips the
 * auto-pin step. Manual pinning happens in attach() after the state
 * machine, once the per-iface dir is known-good. */
#ifdef XDPMF_ENABLE_BPF_OBJECT_OVERRIDE
/* §5.24 Q4 fixture-path override: read the BPF object ELF from `path` into
 * an in-memory buffer, allocate the typed skeleton struct manually (mirrors
 * mac_filter_bpf__open_opts), substitute s->data/s->data_sz with the file
 * bytes (instead of the embedded mac_filter_bpf__elf_bytes), then open via
 * bpf_object__open_skeleton. libbpf's bpf_object__open_mem (under the hood)
 * completes ELF parsing before returning, so the local buffer's lifetime
 * only needs to cover this call. Returns an owning BpfSkeleton.
 *
 * Testing-only path — undocumented in --help per §7 Robust OOS.
 *
 * §5.30 HK-3 (MVP-3.4.5): the entire function and its sole caller branch
 * are #ifdef'd behind XDPMF_ENABLE_BPF_OBJECT_OVERRIDE — release builds
 * lose the function body, the env var read, and the error-message string
 * literals that mention "XDPMF_BPF_OBJECT_PATH". */
[[nodiscard]] BpfSkeleton open_skeleton_from_path(const char* path)
{
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        throw_loader(LoaderError::LoadFailed,
                     std::format("XDPMF_BPF_OBJECT_PATH '{}': cannot open for reading",
                                 path));
    }
    const std::streamsize sz = ifs.tellg();
    if (sz <= 0) {
        throw_loader(LoaderError::LoadFailed,
                     std::format("XDPMF_BPF_OBJECT_PATH '{}': empty or unreadable",
                                 path));
    }
    ifs.seekg(0, std::ios::beg);
    std::vector<char> buf(static_cast<std::size_t>(sz));
    if (!ifs.read(buf.data(), sz)) {
        throw_loader(LoaderError::LoadFailed,
                     std::format("XDPMF_BPF_OBJECT_PATH '{}': short read", path));
    }

    auto* obj = static_cast<mac_filter_bpf*>(std::calloc(1, sizeof(mac_filter_bpf)));
    if (obj == nullptr) {
        throw_loader(LoaderError::LoadFailed,
                     "calloc(mac_filter_bpf) failed (out of memory?)");
    }
    // Adopt ownership immediately so any throw below routes through dtor.
    BpfSkeleton holder{obj};

    const int crc = mac_filter_bpf__create_skeleton(obj);
    if (crc != 0) {
        throw_loader(classify(crc, LoaderError::LoadFailed),
                     std::format("mac_filter_bpf__create_skeleton: {}",
                                 std::strerror(-crc)));
    }

    // Substitute the embedded ELF bytes with the file-loaded buffer. libbpf
    // copies/parses synchronously inside bpf_object__open_skeleton, so the
    // local std::vector remains live for the duration of the call.
    obj->skeleton->data    = buf.data();
    obj->skeleton->data_sz = static_cast<std::size_t>(sz);

    const int orc = bpf_object__open_skeleton(obj->skeleton, nullptr);
    if (orc < 0) {
        throw_loader(classify(orc, LoaderError::LoadFailed),
                     std::format("bpf_object__open_skeleton('{}'): {}",
                                 path, std::strerror(-orc)));
    }
    return holder;
}
#endif  // XDPMF_ENABLE_BPF_OBJECT_OVERRIDE

/* Open (no load) — used by both the direct-load path and the reuse_fd path.
 * Clears LIBBPF_PIN_BY_NAME pin paths for all managed maps so libbpf's load()
 * does NOT auto-pin (we pin/reuse manually after the §5.4 state machine). */
[[nodiscard]] BpfSkeleton open_skeleton_only()
{
    BpfSkeleton skel;
#ifdef XDPMF_ENABLE_BPF_OBJECT_OVERRIDE
    /* §5.30 HK-3 (MVP-3.4.5): env-var override only available in test builds.
     * Release builds skip the getenv() call entirely — the function literal
     * "XDPMF_BPF_OBJECT_PATH" is absent from the binary. */
    const char* env_path = std::getenv(kBpfObjectPathEnv.data());
    const char* obj_path = (env_path != nullptr && *env_path != '\0') ? env_path : nullptr;
    if (obj_path != nullptr) {
        skel = open_skeleton_from_path(obj_path);
    } else
#endif
    {
        skel = BpfSkeleton{mac_filter_bpf__open()};
        if (!skel) {
            const int e = errno;
            throw_loader(classify(-e, LoaderError::LoadFailed),
                         std::format("mac_filter_bpf__open: {}", std::strerror(e)));
        }
    }
    /* §5.30 HK-9: clear LIBBPF_PIN_BY_NAME auto-pin for ALL managed maps.
     * Manual pinning happens in `internal::apply_request` after the §5.4 state
     * machine. Walks kManagedMaps[]; if a future cycle adds a new
     * LIBBPF_PIN_BY_NAME map, adding ONE row to the table propagates to
     * all three callsites (this clear-list, pin_specs, reuse_specs). */
    for (const ManagedMapEntry& entry : kManagedMaps) {
        ::bpf_map* m = skel->maps.*entry.member_ptr;
        if (bpf_map__set_pin_path(m, nullptr) != 0) {
            const int e = errno;
            throw_loader(classify(-e, LoaderError::LoadFailed),
                         std::format("bpf_map__set_pin_path(clear, {}): {}",
                                     entry.name, std::strerror(e)));
        }
    }
    return skel;
}

/* Finish-load: invokes mac_filter_bpf__load. Separate from open_skeleton_only
 * so the caller can interject bpf_map__reuse_fd between open and load (the
 * state-b idempotent-reattach path uses this hook to swap in the pinned
 * kernel maps). */
void finish_load_skeleton(BpfSkeleton& skel)
{
    const int rc = mac_filter_bpf__load(skel.get());
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::LoadFailed),
                     std::format("mac_filter_bpf__load: {}", std::strerror(-rc)));
    }
}

[[nodiscard]] BpfSkeleton load_skeleton()
{
    BpfSkeleton skel = open_skeleton_only();
    finish_load_skeleton(skel);
    return skel;
}

/* §5.22 Q1: capture our own bytecode tag (kernel-computed SHA1-truncated)
 * from the just-loaded program fd. Failure modes (per §5.22 self-tag
 * failure modes block):
 *   - EPERM/EACCES → Permission (exit 6)   [classify() handles]
 *   - other errno → LoadFailed (exit 2)
 *   - all-zero tag (defensive — kernel bug) → LoadFailed (exit 2)
 * Load-bearing invariant: on the success path, returned tag is non-zero. */
[[nodiscard]] TagArray capture_self_tag(const BpfSkeleton& skel)
{
    const int prog_fd = bpf_program__fd(skel->progs.mac_filter_prog);
    if (prog_fd < 0) {
        throw_loader(LoaderError::LoadFailed,
                     "self_tag capture: mac_filter_prog fd unavailable");
    }
    struct bpf_prog_info info{};
    std::uint32_t info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len) != 0) {
        const int e = errno;
        throw_loader(classify(-e, LoaderError::LoadFailed),
                     std::format("bpf_obj_get_info_by_fd (self_tag): {}",
                                 std::strerror(e)));
    }
    TagArray tag{};
    static_assert(sizeof(info.tag) == kBpfTagSize,
                  "kernel BPF_TAG_SIZE expected to be 8 — UAPI invariant");
    std::memcpy(tag.data(), info.tag, kBpfTagSize);
    if (std::all_of(tag.begin(), tag.end(), [](std::uint8_t b) { return b == 0; })) {
        throw_loader(LoaderError::LoadFailed,
                     "kernel returned zero tag for our own program");
    }
    return tag;
}

/* §5.22 Item 1: render the 8-byte tag as 16-char lowercase hex.
 * Load-bearing for §6.14 tester assertion: grep -E '[0-9a-f]{16}' on
 * stderr MUST match. */
[[nodiscard]] std::string format_tag_hex(const TagArray& t)
{
    return std::format(
        "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7]);
}

/* §5.4 state-(c) refusal message. Splits by which check failed:
 *  - name-mismatch (or mode==None — defensive; unreachable when prog_id != 0)
 *    keeps the pre-§5.22 message format (preserves §6.9 assertion surface).
 *  - tag-mismatch adds hex tag and the literal substring `tag mismatch`
 *    (load-bearing for §6.14).
 * §5.23 Q1 relaxes the mode axis (any of SKB/NATIVE/HW is "ours-eligible"),
 * so mode is no longer a refusal sub-case — it falls into the name branch
 * via fetch_prog_identity's name comparison if the kernel rejects the
 * identity fetch for any reason. */
/* §5.26 HG3: trust-model env-var name. Single switch — strict | fleet. */
constexpr std::string_view kTrustModelEnv{"XDPMF_TRUST_MODEL"};

enum class TrustModel : std::uint8_t { Strict, Fleet };

[[nodiscard]] constexpr std::string_view to_string(TrustModel m) noexcept
{
    return (m == TrustModel::Strict) ? "strict" : "fleet";
}

/* §5.26 HG3: parse XDPMF_TRUST_MODEL. Unset/empty → Strict (default).
 * "strict" → Strict. "fleet" → Fleet. Anything else → ConfigError (exit 9)
 * with the canonical "xdpmacfilter: config error: unknown trust model: '<v>'"
 * stderr shape. Caller MUST log the resolved mode at attach() entry. */
[[nodiscard]] TrustModel parse_trust_model_env()
{
    const char* raw = std::getenv(kTrustModelEnv.data());
    if (raw == nullptr || *raw == '\0' || std::string_view{raw} == "strict") {
        return TrustModel::Strict;
    }
    if (std::string_view{raw} == "fleet") {
        return TrustModel::Fleet;
    }
    throw_loader(LoaderError::ConfigError,
                 std::format("xdpmacfilter: config error: unknown trust model: '{}' "
                             "(expected: strict|fleet)", raw));
}

/* §5.26 sub-decision: stderr-log the resolved trust_model at attach() entry.
 * Single-line, fixed format, audit-grep-friendly.
 *
 * §5.32 (MVP-3.5): routed through logger as `loader.trust_model` (process-
 * scoped — iface=nullopt). Text mode byte-equivalent to pre-§5.32 prose
 * (PI-3.5-1); JSON mode surfaces the model token in `fields.trust_model`. */
void log_trust_model(TrustModel m) noexcept
{
    const std::string model_str{to_string(m)};
    const std::string msg = std::format("xdpmacfilter: trust_model={}\n",
                                        model_str);
    const xdpmf::logger::Field fs[] = {
        xdpmf::logger::Field{"trust_model", std::string_view{model_str}},
    };
    xdpmf::logger::emit(xdpmf::logger::Level::Info,
                        "loader.trust_model",
                        msg,
                        fs);
}

[[nodiscard]] std::string link_pin_path_for(const std::string& iface)
{
    return std::string{XDPMF_BPFFS_ROOT} + "/" + iface + "/" XDPMF_LINK_PIN_BASENAME;
}

/* §5.26 HG2 P0a: pin the bpf_link via the raw fd returned by bpf_link_create
 * (the libbpf 1.1 API doesn't expose attach-with-mode-flags via
 * bpf_program__attach_xdp; we drive bpf_link_create directly so the
 * operator-selected XDP mode survives the link create). Returns the link
 * fd (caller closes after pinning) or throws AttachFailed. */
[[nodiscard]] int create_xdp_link(int prog_fd, int ifindex, XdpMode mode)
{
    // Cannot use LIBBPF_OPTS() macro under C++23 — it expands to a GNU
    // statement expression + compound literal that fail under -Werror.
    // Zero-init manually, then set the two load-bearing fields (sz +
    // flags). bpf_link_create_opts is forward/backward-compat via the
    // explicit sz field.
    bpf_link_create_opts opts{};
    opts.sz    = sizeof(opts);
    opts.flags = mode_to_flags(mode);
    const int link_fd = bpf_link_create(prog_fd, ifindex, BPF_XDP, &opts);
    if (link_fd < 0) {
        throw_loader(classify(link_fd, LoaderError::AttachFailed),
                     std::format("bpf_link_create (xdp mode={}): {}",
                                 to_string(mode), std::strerror(-link_fd)));
    }
    return link_fd;
}

/* §5.26 HG2 P0a: pin a bpf-object fd at <path>. Equivalent to bpf_link__pin
 * but works for the raw fd returned by bpf_link_create. */
void pin_fd(int fd, const std::string& path)
{
    if (bpf_obj_pin(fd, path.c_str()) < 0) {
        const int e = errno;
        throw_loader(classify(-e, LoaderError::AttachFailed),
                     std::format("bpf_obj_pin('{}'): {}", path, std::strerror(e)));
    }
}


/* §5.43 (MVP-4.3) D-mvp-4.3-Q3: a constrained prefix on one LPM axis carrying
 * the rule's bit (= 1ULL << rule_id). `cidr.addr` is network byte order (the
 * LPM_TRIE key shape); `host_addr` is the host-order copy used for prefix
 * masking in close_prefixes. */
struct BitPrefix {
    xdpmf_cidr_v4 cidr;
    std::uint32_t host_addr;
    std::uint64_t bit;
};

/* Host-order mask for a prefix length ([0,32]); len==0 → all-zero mask.
 * Transcribed from the §5.42 spike (guard #9 — production-owned, NOT
 * #include'd from tests/bitvec). */
[[nodiscard]] std::uint32_t host_mask(std::uint32_t prefixlen) noexcept
{
    if (prefixlen == 0) {
        return 0u;
    }
    return 0xFFFFFFFFu << (32u - prefixlen);
}

/* §5.43 FI-1 prefix-closure (the #1 bit-vector trap — guard #23). For each
 * prefix P_i in `entries`, OR in bit_j of every P_j that COVERS P_i
 * (P_j.prefixlen <= P_i.prefixlen AND P_j == P_i truncated to P_j.prefixlen),
 * INCLUDING P_i itself. The cover direction is the trap: the LESS-specific
 * (shorter) prefix's bit flows INTO the MORE-specific (longer) prefix's
 * stored mask, so a longest-prefix LPM hit carries every covering rule — and
 * first-match-by-id (ffsll) then picks the lowest covering id. Returns the
 * closed mask aligned 1:1 with `entries`. Transcribed from the §5.42 spike's
 * close_prefixes() into production types (guard #9 — Q3 A1). */
[[nodiscard]] std::vector<std::uint64_t>
close_prefixes(const std::vector<BitPrefix>& entries)
{
    std::vector<std::uint64_t> closed(entries.size(), 0u);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const BitPrefix& pi = entries[i];
        for (const BitPrefix& pj : entries) {
            if (pj.cidr.prefixlen > pi.cidr.prefixlen) {
                continue;  // pj more specific than pi → cannot cover it
            }
            const std::uint32_t m = host_mask(pj.cidr.prefixlen);
            if ((pi.host_addr & m) == (pj.host_addr & m)) {
                closed[i] |= pj.bit;  // pj covers pi (incl. pi == pj)
            }
        }
    }
    return closed;
}

/* §5.61 (MVP-4.21) B30 D-mvp-4.21-Q3 / SLOT-PLUMB: the loader-internal `slot`
 * carrier. `slot` = the rank of a rule's `id` in ascending-unique-id order,
 * ∈ [0, count-1]. Because slots are assigned in id-sorted order, `1ULL << slot`
 * preserves first-match-by-lowest-id (ffsll(acc)-1 still yields the lowest-id
 * survivor — HG-mvp-4.3-4, PI-mvp-4.21-PRIORITY) while decoupling the bit
 * position / counter index from the (now sparse) operator id. The SAME slot
 * value MUST be used at every populate site (the 4 lowering bit-shifts,
 * rules_inner[slot], rule_counters[slot], slot_rule_id[active*64+slot]) —
 * D-mvp-4.21-SLOT-COHERENCE. ids are unique (config seen_ids dedup). */
[[nodiscard]] std::unordered_map<std::uint32_t, std::uint32_t>
compute_id_to_slot(const std::vector<Rule>& rules)
{
    std::vector<std::uint32_t> ids;
    ids.reserve(rules.size());
    for (const Rule& r : rules) {
        ids.push_back(r.id);
    }
    std::sort(ids.begin(), ids.end());
    std::unordered_map<std::uint32_t, std::uint32_t> id_to_slot;
    id_to_slot.reserve(ids.size());
    for (std::uint32_t rank = 0; rank < ids.size(); ++rank) {
        id_to_slot.emplace(ids[rank], rank);
    }
    return id_to_slot;
}

/* §5.61 B30: the slot→id inverse over the full [0,64) slot space — slot_to_id
 * [slot] = the id occupying `slot`, or XDPMF_SLOT_ID_EMPTY for the unoccupied
 * tail [count,64). Drives both the `slot_rule_id` map write (occupied prefix)
 * and the copy-forward-by-id remap (new-side mapping). */
[[nodiscard]] std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX>
compute_slot_to_id(const std::vector<Rule>& rules,
                   const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX> slot_to_id;
    slot_to_id.fill(XDPMF_SLOT_ID_EMPTY);
    for (const Rule& r : rules) {
        slot_to_id[id_to_slot.at(r.id)] = r.id;
    }
    return slot_to_id;
}

/* §5.43 per-LPM-axis lowering result: the constrained prefixes (rules that
 * set this axis) + the wildcard mask (OR of bits for rules that do NOT
 * constrain this axis — they survive the axis unconditionally via
 * wildcard[active*2+axis], FI-2 mutual exclusion). */
struct AxisLowering {
    std::vector<BitPrefix> prefixes;
    std::uint64_t          wildcard = 0u;
};

/* Lower one LPM axis (dst or src) from the validated Config: a rule that sets
 * the axis contributes a BitPrefix at its bit position; a rule that does NOT
 * set the axis contributes its bit to the wildcard mask. §5.61 (MVP-4.21) B30:
 * the bit is `1ULL << slot` (id-sorted rank, D-mvp-4.21-Q3) — slot ∈ [0,count)
 * is shift-safe (config caps the rule COUNT at XDPMF_ALLOWLIST_MAX). */
[[nodiscard]] AxisLowering lower_axis(const Config& c, bool dst_axis,
    const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    AxisLowering out;
    out.prefixes.reserve(c.rules.size());
    for (const Rule& r : c.rules) {
        const std::optional<xdpmf_cidr_v4>& axis =
            dst_axis ? r.match.dst_cidr : r.match.src_cidr;
        const std::uint64_t bit = std::uint64_t{1} << id_to_slot.at(r.id);
        if (axis.has_value()) {
            BitPrefix bp{};
            bp.cidr      = *axis;
            bp.host_addr = ::ntohl(axis->addr);
            bp.bit       = bit;
            out.prefixes.push_back(bp);
        } else {
            out.wildcard |= bit;  // unconstrained on this axis → wildcard survivor
        }
    }
    return out;
}

/* §5.53 (MVP-4.13) D-mvp-4.13-FORK: the IPv6 sibling of BitPrefix — a v6
 * constrained prefix carrying the rule's bit. `cidr.addr6` is network byte
 * order (the LPM_TRIE key shape); `host_addr6` is the host-order `unsigned
 * __int128` copy used for 128-bit prefix masking in close_prefixes6 (Q1=A1 —
 * mirrors the v4 cover-direction body so the #1-bug-class invariant is
 * eyeball-auditable). */
struct BitPrefix6 {
    xdpmf_cidr_v6     cidr;
    unsigned __int128 host_addr6;
    std::uint64_t     bit;
};

/* Load the 16 network-order bytes (addr6[0]=MSB) into a host-order __int128. */
[[nodiscard]] unsigned __int128 host_addr6_of(const xdpmf_cidr_v6& c) noexcept
{
    unsigned __int128 v = 0;
    for (int i = 0; i < 16; ++i) {
        v = (v << 8) | static_cast<unsigned __int128>(c.addr6[i]);
    }
    return v;
}

/* Host-order 128-bit mask for a v6 prefix length ([0,128]); len==0 → all-zero.
 * The `/0` shift-by-128 UB site is special-cased (len==0 returns 0); for
 * len ∈ [1,128] the shift amount (128-len) ∈ [0,127], never 128 (Q1). */
[[nodiscard]] unsigned __int128 host_mask6(unsigned int prefixlen) noexcept
{
    if (prefixlen == 0) {
        return 0;
    }
    return (~static_cast<unsigned __int128>(0)) << (128u - prefixlen);
}

/* §5.53 FI-1 prefix-closure at 128 bits (guard #23 — the #1 bit-vector trap).
 * FORKED from close_prefixes: for each P_i, OR in bit_j of every P_j that
 * COVERS P_i (P_j.prefixlen <= P_i.prefixlen AND P_j == P_i truncated to
 * P_j.prefixlen), INCLUDING P_i. The LESS-specific (lower-id) covering prefix's
 * bit flows INTO the MORE-specific entry's stored mask, so a longest-prefix LPM
 * hit carries every covering rule and ffsll picks the lowest covering id. */
[[nodiscard]] std::vector<std::uint64_t>
close_prefixes6(const std::vector<BitPrefix6>& entries)
{
    std::vector<std::uint64_t> closed(entries.size(), 0u);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const BitPrefix6& pi = entries[i];
        for (const BitPrefix6& pj : entries) {
            if (pj.cidr.prefixlen > pi.cidr.prefixlen) {
                continue;  // pj more specific than pi → cannot cover it
            }
            const unsigned __int128 m = host_mask6(pj.cidr.prefixlen);
            if ((pi.host_addr6 & m) == (pj.host_addr6 & m)) {
                closed[i] |= pj.bit;  // pj covers pi (incl. pi == pj)
            }
        }
    }
    return closed;
}

/* §5.53 per-v6-LPM-axis lowering result — FORK of AxisLowering. */
struct AxisLowering6 {
    std::vector<BitPrefix6> prefixes;
    std::uint64_t           wildcard = 0u;
};

/* Lower one v6 LPM axis (dst6 or src6). FORK of lower_axis: a rule that sets
 * the axis contributes a BitPrefix6 at its bit; a rule that does NOT set the
 * axis contributes its bit to the wildcard mask (family-blind lowering — a
 * v4-only rule lands in wc_dst6/wc_src6 by this SAME mechanism, the load-
 * bearing Q2 cross-family fill). §5.61 (MVP-4.21) B30: bit = `1ULL << slot`. */
[[nodiscard]] AxisLowering6 lower_axis6(const Config& c, bool dst6_axis,
    const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    AxisLowering6 out;
    out.prefixes.reserve(c.rules.size());
    for (const Rule& r : c.rules) {
        const std::optional<xdpmf_cidr_v6>& axis =
            dst6_axis ? r.match.dst_cidr6 : r.match.src_cidr6;
        const std::uint64_t bit = std::uint64_t{1} << id_to_slot.at(r.id);
        if (axis.has_value()) {
            BitPrefix6 bp{};
            bp.cidr       = *axis;
            bp.host_addr6 = host_addr6_of(*axis);
            bp.bit        = bit;
            out.prefixes.push_back(bp);
        } else {
            out.wildcard |= bit;  // unconstrained on this axis → wildcard survivor
        }
    }
    return out;
}

/* §5.50 (MVP-4.10 B28-2) generic per-exact-HASH-axis lowering result — replaces
 * the byte-identical ProtoLowering/VlanLowering structs and the key-only-
 * different MacLowering (D-mvp-4.10-STRUCT). entries[k] = {key, OR of bits of
 * every rule constraining that exact key}; wildcard = OR of bits of rules NOT
 * constraining this axis. NO prefix-closure (exact-match HASH). PortLowering +
 * the dst/src AxisLowering are NOT folded (different shape — D-mvp-4.10-
 * BOUNDARY). */
template<class Key>
struct AxisAggregate {
    std::vector<std::pair<Key, std::uint64_t>> entries;
    std::uint64_t                              wildcard = 0u;
};
// Name-preserving aliases — Proto/Vlan are the SAME instantiation (legal); keep
// populate_all_axes' signature + the apply_request locals textually stable.
using ProtoLowering = AxisAggregate<std::uint32_t>;
using VlanLowering  = AxisAggregate<std::uint32_t>;
using MacLowering   = AxisAggregate<xdpmf_mac>;
// §5.54 (MVP-4.14): ethertype is an exact-HASH axis identical in shape to
// proto/vlan (only the projected source member differs: r.match.ethertype,
// widened u16→u32). Same instantiation; CLONE not fork (D-mvp-4.14-CLONE).
using EthertypeLowering = AxisAggregate<std::uint32_t>;

/* §5.50 (MVP-4.10 B28-2) unify lower_proto_axis / lower_vlan_axis /
 * lower_mac_axis into ONE monomorphized template (rule-of-three OVERRIDES guard
 * #9 per §5.37 / D-3.4f-1). They differed by THREE axes — key type, the
 * projected source member (proto/vlan/mac are distinct std::optional<> types),
 * and the dedup equality (== for proto/vlan, memcmp for the 6-octet mac). Per
 * rule: bit = 1<<slot; key_of(r) projects the axis key (std::nullopt => the rule
 * does NOT constrain this axis, so its bit goes to `wildcard`, FI-2 mutual
 * exclusion); on a key, a linear dedup-scan via key_eq (D-mvp-4.10-MAC-EQ keeps
 * the mac memcmp, NOT ==) ORs the bit into the matching entry, else emplace_back
 * a new entry. Insertion order preserved EXACTLY (D-mvp-4.10-ORDER) =>
 * bit-identical entries/wildcard to the three originals. §5.61 (MVP-4.21) B30:
 * bit = `1ULL << slot` (id-sorted rank, D-mvp-4.21-Q3) — slot ∈ [0,count) is
 * shift-safe (config caps the rule COUNT). Each lambda inlines per
 * instantiation => zero indirect-call cost (Q1 -> A1). */
template<class Key, class Project, class Eq>
[[nodiscard]] AxisAggregate<Key> aggregate_axis(const std::vector<Rule>& rules,
                                                Project key_of, Eq key_eq,
    const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    AxisAggregate<Key> out;
    for (const Rule& r : rules) {
        const std::uint64_t      bit = std::uint64_t{1} << id_to_slot.at(r.id);
        const std::optional<Key> key = key_of(r);
        if (key.has_value()) {
            // Aggregate rules sharing the same exact key into one entry.
            bool merged = false;
            for (std::pair<Key, std::uint64_t>& e : out.entries) {
                if (key_eq(e.first, *key)) {
                    e.second |= bit;
                    merged = true;
                    break;
                }
            }
            if (!merged) {
                out.entries.emplace_back(*key, bit);
            }
        } else {
            out.wildcard |= bit;
        }
    }
    return out;
}

/* §5.44 (MVP-4.4) per-port-axis lowering result: one xdpmf_port_range slot per
 * port-constrained rule (single port ⇒ lo==hi) + the wildcard mask (rules NOT
 * constraining dst_port). NO prefix-closure (explicit ranges — D-mvp-4.4-
 * NO-CLOSURE). */
struct PortLowering {
    std::vector<xdpmf_port_range> ranges;
    std::uint64_t                 wildcard = 0u;
};

/* Lower the dst_port axis: a rule with `dst_port` set contributes one
 * {lo,hi,bit} slot; a rule WITHOUT `dst_port` contributes its bit to the port
 * wildcard (FI-2). §5.61 (MVP-4.21) B30: bit = `1ULL << slot` (id-sorted rank). */
[[nodiscard]] PortLowering lower_port_axis(const Config& c,
    const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    PortLowering out;
    out.ranges.reserve(c.rules.size());
    for (const Rule& r : c.rules) {
        const std::uint64_t bit = std::uint64_t{1} << id_to_slot.at(r.id);
        if (r.match.dst_port.has_value()) {
            xdpmf_port_range slot{};
            slot.lo  = r.match.dst_port->lo;
            slot.hi  = r.match.dst_port->hi;
            slot.bit = bit;
            out.ranges.push_back(slot);
        } else {
            out.wildcard |= bit;
        }
    }
    return out;
}

/* §5.50 (MVP-4.10 B28-1) unify populate_inner_slot (mac, §5.47 D-mvp-4.7-Q1) /
 * populate_proto_inner_slot (§5.44) / populate_vlan_inner_slot (§5.45) into ONE
 * monomorphized template (rule-of-three OVERRIDES guard #9 per §5.37 /
 * D-3.4f-1). The three were byte-shape-identical (the old populate_vlan comment
 * already asserted "IDENTICAL shape to populate_proto_inner_slot") — differing
 * ONLY by the inner-map HASH key type (xdpmf_mac / __u32) + a diagnostic label.
 * Each inner value is a per-key aggregated rule-bitmask (bit k set iff rule k
 * constrains this exact key). EXACT match, NO prefix-closure. Bulk-clear (get_
 * next_key -> delete_elem, ENOENT-terminated) THEN insert (update_elem BPF_ANY);
 * the map is small (<= XDPMF_ALLOWLIST_MAX entries) so the clear cost is
 * bounded. `Key{}` value-init covers xdpmf_mac{} (zeroed) and __u32{} (=0),
 * matching the originals' prev{}/cur{} vs prev=0/cur=0. `what` is the diagnostic
 * label ("mac"/"proto"/"vlan"); error strings are key-agnostic — the old
 * proto/vlan key-in-message embed is dropped (D-mvp-4.10-DIAG; error path only,
 * not test-pinned). RESET-on-apply: caller passes the INACTIVE inner fd and
 * writes BEFORE the active_idx flip. */
template<class Key>
void populate_hash_inner_slot(int inner_fd,
                              const std::vector<std::pair<Key, std::uint64_t>>& entries,
                              const char* what)
{
    // Bulk-clear: iterate keys via bpf_map_get_next_key and delete each.
    Key  prev{};
    Key  cur{};
    bool have_prev = false;
    while (true) {
        const int rc = bpf_map_get_next_key(inner_fd,
                                            have_prev ? &prev : nullptr,
                                            &cur);
        if (rc != 0) {
            if (-rc == ENOENT) break;
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_get_next_key({}_inner): {}",
                                     what, std::strerror(-rc)));
        }
        const int drc = bpf_map_delete_elem(inner_fd, &cur);
        if (drc != 0 && -drc != ENOENT) {
            throw_loader(classify(drc, LoaderError::LoadFailed),
                         std::format("bpf_map_delete_elem({}_inner): {}",
                                     what, std::strerror(-drc)));
        }
        prev      = cur;
        have_prev = true;
    }
    for (const std::pair<Key, std::uint64_t>& e : entries) {
        const Key           key  = e.first;
        const std::uint64_t mask = e.second;
        const int rc = bpf_map_update_elem(inner_fd, &key, &mask, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem({}_inner): {}",
                                     what, std::strerror(-rc)));
        }
    }
}

/* §5.43 (MVP-4.3) D-mvp-4.3-Q1/Q3: populate one LPM bit-vector axis inner
 * (dst_bitmask_<a|b> OR cidr_allowlist_<a|b>) — value-reshaped to a __u64
 * prefix-closed bitmask. Used for BOTH LPM axes (the src axis replaces the
 * §5.31 allow_entry write; the dst axis is the new mirror). Bulk-clear-then-
 * insert preserved. RESET-on-apply: the caller passes the INACTIVE inner fd
 * and writes BEFORE the active_idx flip (D-mvp-4.3-RESET-VS-PRESERVE — match
 * maps reflect only the current config; NO copy-forward). */
void populate_bitvec_inner_slot(int inner_fd, const std::vector<BitPrefix>& prefixes)
{
    xdpmf_cidr_v4 prev{};
    xdpmf_cidr_v4 cur{};
    bool          have_prev = false;
    while (true) {
        const int rc = bpf_map_get_next_key(inner_fd,
                                            have_prev ? &prev : nullptr,
                                            &cur);
        if (rc != 0) {
            if (-rc == ENOENT) break;
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_get_next_key(bitvec_inner): {}",
                                     std::strerror(-rc)));
        }
        const int drc = bpf_map_delete_elem(inner_fd, &cur);
        if (drc != 0 && -drc != ENOENT) {
            throw_loader(classify(drc, LoaderError::LoadFailed),
                         std::format("bpf_map_delete_elem(bitvec_inner): {}",
                                     std::strerror(-drc)));
        }
        prev      = cur;
        have_prev = true;
    }
    // FI-1 cover-closure: each entry's stored __u64 = OR of every covering
    // rule's bit (close_prefixes). Duplicate prefixes (two rules sharing an
    // exact prefix) get IDENTICAL closed masks and collapse to one map entry.
    const std::vector<std::uint64_t> closed = close_prefixes(prefixes);
    for (std::size_t i = 0; i < prefixes.size(); ++i) {
        const xdpmf_cidr_v4 key  = prefixes[i].cidr;  // addr already network order
        const std::uint64_t mask = closed[i];
        const int rc = bpf_map_update_elem(inner_fd, &key, &mask, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(bitvec_inner): {}",
                                     std::strerror(-rc)));
        }
    }
}

/* §5.53 (MVP-4.13) D-mvp-4.13-FORK: populate one v6 LPM bit-vector axis inner
 * (dst6_bitmask_<a|b> OR src6_bitmask_<a|b>) — value = __u64 prefix-closed
 * bitmask (close_prefixes6). FORK of populate_bitvec_inner_slot with the
 * xdpmf_cidr_v6 key. Bulk-clear-then-insert; RESET-on-apply (caller passes the
 * INACTIVE inner fd, writes BEFORE the active_idx flip — NO copy-forward). */
void populate_bitvec6_inner_slot(int inner_fd, const std::vector<BitPrefix6>& prefixes)
{
    xdpmf_cidr_v6 prev{};
    xdpmf_cidr_v6 cur{};
    bool          have_prev = false;
    while (true) {
        const int rc = bpf_map_get_next_key(inner_fd,
                                            have_prev ? &prev : nullptr,
                                            &cur);
        if (rc != 0) {
            if (-rc == ENOENT) break;
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_get_next_key(bitvec6_inner): {}",
                                     std::strerror(-rc)));
        }
        const int drc = bpf_map_delete_elem(inner_fd, &cur);
        if (drc != 0 && -drc != ENOENT) {
            throw_loader(classify(drc, LoaderError::LoadFailed),
                         std::format("bpf_map_delete_elem(bitvec6_inner): {}",
                                     std::strerror(-drc)));
        }
        prev      = cur;
        have_prev = true;
    }
    const std::vector<std::uint64_t> closed = close_prefixes6(prefixes);
    for (std::size_t i = 0; i < prefixes.size(); ++i) {
        const xdpmf_cidr_v6 key  = prefixes[i].cidr;  // addr6 already network order
        const std::uint64_t mask = closed[i];
        const int rc = bpf_map_update_elem(inner_fd, &key, &mask, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(bitvec6_inner): {}",
                                     std::strerror(-rc)));
        }
    }
}

/* §5.44 (MVP-4.4) D-mvp-4.4-Q2 + D-mvp-4.4-PORT-ARRAY-CLEAR: populate one
 * dst_port-axis ARRAY inner (port_ranges_<a|b>). BPF ARRAY maps have no
 * delete, so clear by overwriting ALL XDPMF_ALLOWLIST_MAX slots with the
 * UNUSED sentinel {lo=1, hi=0, bit=0} (lo>hi → datapath port_scan skips it),
 * then write the used range slots (mirrors populate_rules_inner_slot's
 * clear-all-slots-then-write precedent). RESET-on-apply: caller passes the
 * INACTIVE inner fd and writes BEFORE the active_idx flip.
 *
 * B18 (§5.49) PRODUCER end of a NON-LOCAL coupling: the datapath port_scan
 * early-`break`s on the first lo>hi sentinel. That break is correct ONLY
 * because this function packs used slots DENSE-AT-FRONT (ranges[0..N-1]
 * contiguous after the bulk-clear) AND config.cpp parse_dst_port guarantees
 * every real range has lo<=hi (so no real slot can masquerade as a sentinel).
 * Do NOT introduce gaps/holes in the used-slot range or the break would skip
 * legit slots. Consumer note: port_scan in mac_filter.bpf.c — guard #26. */
void populate_port_inner_slot(int inner_fd, const std::vector<xdpmf_port_range>& ranges)
{
    /* Clear all slots to the unused sentinel (lo>hi). */
    xdpmf_port_range unused{};
    unused.lo  = 1;
    unused.hi  = 0;
    unused.bit = 0;
    for (std::uint32_t k = 0; k < static_cast<std::uint32_t>(XDPMF_ALLOWLIST_MAX); ++k) {
        const int rc = bpf_map_update_elem(inner_fd, &k, &unused, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(port_inner[{}] clear): {}",
                                     k, std::strerror(-rc)));
        }
    }
    /* Then write the used range slots. range count ≤ rule count ≤
     * XDPMF_ALLOWLIST_MAX (bounded by apply_request's pre-check). */
    for (std::uint32_t i = 0; i < ranges.size(); ++i) {
        const xdpmf_port_range slot = ranges[i];
        const int rc = bpf_map_update_elem(inner_fd, &i, &slot, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(port_inner[{}]): {}",
                                     i, std::strerror(-rc)));
        }
    }
}

/* §5.43 (MVP-4.3) D-mvp-4.3-Q2 + §5.44 (MVP-4.4) D-mvp-4.4-Q4 + §5.45 (MVP-4.5)
 * D-mvp-4.5-Q3 + §5.47 (MVP-4.7) D-mvp-4.7-Q4 + §5.53 (MVP-4.13) D-mvp-4.13-Q2:
 * write the INACTIVE half of the single combined `wildcard` ARRAY before the
 * active_idx flip — all EIGHT axis slots [inactive*BITVEC_NUM_AXES +
 * {DST,SRC,PROTO,PORT,VLAN,MAC,DST6,SRC6}]. The RESET-write (no copy-forward)
 * parallels populate_bitvec_inner_slot; the single active_idx u32 store commits
 * the wildcard swap together with the dst/src/proto/port/vlan/mac/dst6/src6/
 * defaults/rules/rule_counters swap. */
void write_wildcard_slots(int wildcard_fd, std::uint32_t inactive,
                          std::uint64_t wc_dst, std::uint64_t wc_src,
                          std::uint64_t wc_proto, std::uint64_t wc_port,
                          std::uint64_t wc_vlan, std::uint64_t wc_mac,
                          std::uint64_t wc_dst6, std::uint64_t wc_src6,
                          std::uint64_t wc_eth)
{
    const struct {
        std::uint32_t axis;
        std::uint64_t value;
        const char*   name;
    } slots[] = {
        { BV_AXIS_DST,       wc_dst,   "dst"       },
        { BV_AXIS_SRC,       wc_src,   "src"       },
        { BV_AXIS_PROTO,     wc_proto, "proto"     },
        { BV_AXIS_PORT,      wc_port,  "port"      },
        { BV_AXIS_VLAN,      wc_vlan,  "vlan"      },
        { BV_AXIS_MAC,       wc_mac,   "mac"       },
        { BV_AXIS_DST6,      wc_dst6,  "dst6"      },
        { BV_AXIS_SRC6,      wc_src6,  "src6"      },
        /* §5.54 (MVP-4.14): NET-NEW wildcard slot for the ethertype axis. */
        { BV_AXIS_ETHERTYPE, wc_eth,   "ethertype" },
    };
    for (const auto& s : slots) {
        const std::uint32_t key = inactive * BITVEC_NUM_AXES + s.axis;
        const int rc = bpf_map_update_elem(wildcard_fd, &key, &s.value, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(wildcard[{}] {}): {}",
                                     key, s.name, std::strerror(-rc)));
        }
    }
}

/* Write defaults_map[slot] = (default_action == Pass ? 1 : 0). */
void write_default_slot(int defaults_fd, std::uint32_t slot, DefaultAction da)
{
    const std::uint32_t value = (da == DefaultAction::Pass) ? 1u : 0u;
    const int rc = bpf_map_update_elem(defaults_fd, &slot, &value, BPF_ANY);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::LoadFailed),
                     std::format("bpf_map_update_elem(defaults[{}]): {}",
                                 slot, std::strerror(-rc)));
    }
}

/* Write active_idx[0] = idx. Single u32 store — kernel-atomic on aligned
 * word writes. THIS IS THE ATOMIC SWAP COMMIT POINT. */
void write_active_idx(int active_idx_fd, std::uint32_t idx)
{
    const std::uint32_t zero = 0;
    const int rc = bpf_map_update_elem(active_idx_fd, &zero, &idx, BPF_ANY);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::LoadFailed),
                     std::format("bpf_map_update_elem(active_idx): {}",
                                 std::strerror(-rc)));
    }
}

/* §5.34 populate the INACTIVE `rules` inner ARRAY slot from the validated
 * Config (per-axis inactive-slot pattern). The caller writes BEFORE the
 * active_idx flip so the single u32 store commits rules with the other axes.
 *
 * Encoding: a Config.rules entry with action=Pass becomes {present=1,
 * action_id=ACTION_PASS}; Drop becomes {present=1, action_id=ACTION_DROP}.
 * Empty slots written as {present=0, action_id=0} so a removed rule doesn't
 * leave stale state. BOTH pass and drop rules are written faithfully; the
 * action discrimination happens downstream at the rules→action_table chain. */
void populate_rules_inner_slot(int rules_inner_fd, const std::vector<Rule>& rules,
    const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    /* Clear all 64 slots first — operator may have removed rules across
     * applies; the prior occupant must not survive. */
    const struct rule_entry empty{};
    for (std::uint32_t k = 0; k < static_cast<std::uint32_t>(XDPMF_ALLOWLIST_MAX); ++k) {
        const int rc = bpf_map_update_elem(rules_inner_fd, &k, &empty, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(rules_inner[{}] clear): {}",
                                     k, std::strerror(-rc)));
        }
    }
    /* Then write occupied slots. §5.61 (MVP-4.21) B30: keyed by the rule's
     * internal `slot` (id-sorted rank), NOT its operator id — the datapath
     * winner `rid = ffsll(acc)-1` is a slot index into rules_inner, so this
     * MUST use the SAME slot the lowering bit-shifts used (D-mvp-4.21-SLOT-
     * COHERENCE). slot ∈ [0,count) is in range (config caps the count). */
    for (const Rule& r : rules) {
        struct rule_entry entry{};
        entry.present   = 1;
        entry.action_id = (r.action == RuleAction::Pass)
            ? static_cast<unsigned char>(ACTION_PASS)
            : static_cast<unsigned char>(ACTION_DROP);
        const std::uint32_t slot = id_to_slot.at(r.id);
        const int rc = bpf_map_update_elem(rules_inner_fd, &slot, &entry, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(rules_inner[{}]): {}",
                                     slot, std::strerror(-rc)));
        }
    }
}

/* §5.61 (MVP-4.21) B30 D-mvp-4.21-Q1: write the INACTIVE half of the single
 * combined `slot_rule_id` ARRAY before the active_idx flip — slot_rule_id
 * [inactive*XDPMF_ALLOWLIST_MAX + slot] = the operator id occupying that slot,
 * or XDPMF_SLOT_ID_EMPTY for the unoccupied tail [count,64). RESET-on-apply
 * (mirrors write_wildcard_slots / populate_rules_inner_slot): the whole half
 * is rewritten so no stale id survives. The single active_idx u32 store commits
 * this swap together with all 9 axes + defaults + rules + rule_counters +
 * wildcard. NEVER read by mac_filter_prog — userspace-only (HG-mvp-4.21-1). */
void write_slot_rule_id(int slot_rule_id_fd, std::uint32_t inactive,
    const std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX>& slot_to_id)
{
    const std::uint32_t base = inactive * static_cast<std::uint32_t>(XDPMF_ALLOWLIST_MAX);
    for (std::uint32_t slot = 0;
         slot < static_cast<std::uint32_t>(XDPMF_ALLOWLIST_MAX); ++slot) {
        const std::uint32_t key = base + slot;
        const std::uint32_t val = slot_to_id[slot];  // id or XDPMF_SLOT_ID_EMPTY
        const int rc = bpf_map_update_elem(slot_rule_id_fd, &key, &val, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(slot_rule_id[{}]): {}",
                                     key, std::strerror(-rc)));
        }
    }
}

/* §5.61 (MVP-4.21) B30: read one half (`active`) of the persisted slot_rule_id
 * map into a slot→id array. Used by the copy-forward to recover the OLD-active
 * slot assignment so a surviving id's counter follows its id across a slot move
 * (D-mvp-4.21-COPYFWD-BY-ID). Lookup-fail on any slot leaves the EMPTY sentinel
 * (defensive — a missing/half-written slot is treated as unoccupied). */
[[nodiscard]] std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX>
read_slot_rule_id_half(int slot_rule_id_fd, std::uint32_t active)
{
    std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX> out;
    out.fill(XDPMF_SLOT_ID_EMPTY);
    const std::uint32_t base = active * static_cast<std::uint32_t>(XDPMF_ALLOWLIST_MAX);
    for (std::uint32_t slot = 0;
         slot < static_cast<std::uint32_t>(XDPMF_RULE_COUNTERS_MAX); ++slot) {
        const std::uint32_t key = base + slot;
        std::uint32_t       val = XDPMF_SLOT_ID_EMPTY;
        if (bpf_map_lookup_elem(slot_rule_id_fd, &key, &val) == 0) {
            out[slot] = val;
        }
    }
    return out;
}

/* §5.35 (MVP-3.4d) D-3.4d-3 + §5.61 (MVP-4.21) B30 D-mvp-4.21-COPYFWD-BY-ID:
 * per-rule per-CPU copy-forward from old-active rule_counters inner to inactive
 * rule_counters inner, REMAPPED BY OPERATOR ID. Called from apply_request BEFORE
 * the single-u32 active_idx flip; ensures the new-active inner (post-flip)
 * carries each surviving id's accumulated per-CPU counter state — even when
 * that id's `slot` MOVED (reorder/insert/renumber). PI-3.4b-2 PRESERVE-across-
 * apply held across slot reassignment (this is THE load-bearing B30 change).
 *
 * Semantics (D-mvp-4.21-COPYFWD-BY-ID): for each NEW slot k ∈ [0,64):
 *   - new_slot_to_id[k] == EMPTY  → write zeros (unoccupied slot, no leak);
 *   - new id is a SURVIVOR (present in old_slot_to_id) → copy old-active
 *     [old_slot] → inactive[k] (the counter follows its id across the move);
 *   - new id is NEW (absent from old) → write zeros (starts at 0);
 * removed ids simply drop (their old slot is never a copy SOURCE). Every
 * [0,64) inactive slot is written, so no stale value leaks forward.
 *
 * old_slot_to_id is read from the OLD-active half of slot_rule_id (BEFORE the
 * flip; populate writes only the INACTIVE half, so the old half is intact).
 * new_slot_to_id is the freshly-computed slot→id for this apply.
 *
 * Loop bounded by XDPMF_RULE_COUNTERS_MAX (= 64), NOT by NCPUS — the PERCPU map
 * ABI ships NCPUS values per lookup/update syscall. Buffer sized via
 * libbpf_num_possible_cpus().
 *
 * On lookup-fail (never-bumped slot returns -ENOENT on some kernels): treat as
 * zero (re-zero the buffer so prior-iteration values cannot leak forward).
 * On update-fail: propagate as std::system_error (LoaderError::LoadFailed) —
 * apply fails, caller's rollback runs (no active_idx flip).
 *
 * On FIRST apply (fresh attach): caller passes self-fd + an all-EMPTY
 * old_slot_to_id, so nothing matches and every slot is zeroed — harmless since
 * the fresh inner is already zero (D-mvp-4.21-FIRSTAPPLY). Uniform code path. */
void copy_rule_counters_forward(int old_active_inner_fd, int inactive_inner_fd,
    std::span<const std::uint32_t> old_slot_to_id,
    std::span<const std::uint32_t> new_slot_to_id)
{
    const int num_cpus = ::libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        throw_loader(LoaderError::LoadFailed,
                     std::format("libbpf_num_possible_cpus returned {} "
                                 "(copy_rule_counters_forward)", num_cpus));
    }
    std::vector<std::uint64_t> buf(static_cast<std::size_t>(num_cpus), 0u);
    for (std::uint32_t k = 0;
         k < static_cast<std::uint32_t>(XDPMF_RULE_COUNTERS_MAX);
         ++k) {
        std::fill(buf.begin(), buf.end(), 0u);
        const std::uint32_t new_id = new_slot_to_id[k];
        if (new_id != XDPMF_SLOT_ID_EMPTY) {
            /* Find the OLD slot this surviving id occupied; copy its counter. */
            for (std::uint32_t old_slot = 0;
                 old_slot < static_cast<std::uint32_t>(XDPMF_RULE_COUNTERS_MAX);
                 ++old_slot) {
                if (old_slot_to_id[old_slot] == new_id) {
                    const int lk = bpf_map_lookup_elem(old_active_inner_fd,
                                                       &old_slot, buf.data());
                    if (lk < 0) {
                        std::fill(buf.begin(), buf.end(), 0u);
                    }
                    break;  // ids are unique → at most one old slot
                }
            }
            /* new id absent from old → buf stays all-zero (starts at 0). */
        }
        const int up = bpf_map_update_elem(inactive_inner_fd, &k,
                                             buf.data(), BPF_ANY);
        if (up < 0) {
            throw_loader(classify(up, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(rule_counters_inactive[{}]"
                                     " copy-forward): {}",
                                     k, std::strerror(-up)));
        }
    }
}

/* §5.29 (MVP-3.4): pre-populate action_table with the two reserved actions
 * (PASS=0, DROP=1) per §5.29 apply step 8.5. Idempotent (write-same-value).
 * The action_id field stored in `rules` is an index into THIS array. */
void populate_action_table(int action_table_fd)
{
    struct action_entry pass_entry{};
    pass_entry.action_type = static_cast<unsigned char>(ACTION_PASS);
    struct action_entry drop_entry{};
    drop_entry.action_type = static_cast<unsigned char>(ACTION_DROP);
    const std::uint32_t k_pass = static_cast<std::uint32_t>(ACTION_PASS);
    const std::uint32_t k_drop = static_cast<std::uint32_t>(ACTION_DROP);
    int rc = bpf_map_update_elem(action_table_fd, &k_pass, &pass_entry, BPF_ANY);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::LoadFailed),
                     std::format("bpf_map_update_elem(action_table[PASS]): {}",
                                 std::strerror(-rc)));
    }
    rc = bpf_map_update_elem(action_table_fd, &k_drop, &drop_entry, BPF_ANY);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::LoadFailed),
                     std::format("bpf_map_update_elem(action_table[DROP]): {}",
                                 std::strerror(-rc)));
    }
}

/* §5.48 (MVP-4.8) D-mvp-4.8-Q1 + D-mvp-4.8-FD-HELPER-SCOPE: fd-selector for the
 * 7 PAIRED axis inners (allowlist / dst_bitmask / cidr_allowlist /
 * proto_bitmask / port_ranges / vlan_bitmask / rules). Picks slot==0?a:b,
 * fetches the inner-map fd, throws LoadFailed(what) on <0. This is the SINGLE
 * home for the `_a`/`_b`<->slot decision — the HK-9 lockstep hazard B20 closes
 * (a wrong pair/slot in any one of the former 14 hand-rolled sites silently
 * corrupted the atomic swap and was compiler-invisible). Named `inactive_axis_fd`
 * (not the brief's `inactive_inner_fd`) to avoid shadowing the same-named
 * parameter in copy_rule_counters_forward — D-mvp-4.8-NAME-SHADOW. */
int inactive_axis_fd(bpf_map* a, bpf_map* b, std::uint32_t slot, const char* what)
{
    bpf_map*  inner = (slot == 0) ? a : b;
    const int fd    = bpf_map__fd(inner);
    if (fd < 0) {
        throw_loader(LoaderError::LoadFailed, what);
    }
    return fd;
}

/* §5.48 (MVP-4.8) D-mvp-4.8-BOUNDARY/ORDER: populate ALL RESET-on-apply
 * destinations into `slot` (fresh=0, reattach=inactive), in the EXACT current
 * order — mac, dst, src, proto, port, vlan, wildcard, defaults, rules. BOTH
 * apply_request branches call this; it replaces the per-branch hand-rolled
 * (slot==0?_a:_b)->fd->throw->populate blocks (the HK-9 14x idiom). EXCLUDES
 * populate_action_table (shared static {PASS,DROP}, no slot dimension) and
 * copy_rule_counters_forward (PRESERVE, branch-divergent args — guard #15);
 * those stay EXPLICIT per branch. Behavior-preserving: same maps, same slots,
 * same populate_* callees, same order as before the refactor. wildcard +
 * defaults are SINGLE maps indexed BY slot (direct bpf_map__fd, not pair-select
 * — D-mvp-4.8-FD-HELPER-SCOPE). */
void populate_all_axes(mac_filter_bpf* skel, std::uint32_t slot,
                       const MacLowering&        mac_low,
                       const AxisLowering&       dst_low,
                       const AxisLowering&       src_low,
                       const ProtoLowering&      proto_low,
                       const PortLowering&       port_low,
                       const VlanLowering&       vlan_low,
                       const AxisLowering6&      dst6_low,
                       const AxisLowering6&      src6_low,
                       const EthertypeLowering&  eth_low,
                       const std::vector<Rule>&  rules,
                       const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot,
                       const std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX>& slot_to_id,
                       DefaultAction             default_action)
{
    // 1 mac — paired allowlist_a/_b -> __u64 aggregated rule-bitmask
    populate_hash_inner_slot(
        inactive_axis_fd(skel->maps.allowlist_a, skel->maps.allowlist_b, slot,
                         "inactive mac inner fd unavailable"),
        mac_low.entries, "mac");
    // 2 dst — paired dst_bitmask_a/_b LPM bit-vector
    populate_bitvec_inner_slot(
        inactive_axis_fd(skel->maps.dst_bitmask_a, skel->maps.dst_bitmask_b, slot,
                         "inactive dst inner fd unavailable"),
        dst_low.prefixes);
    // 3 src — paired cidr_allowlist_a/_b LPM bit-vector
    populate_bitvec_inner_slot(
        inactive_axis_fd(skel->maps.cidr_allowlist_a, skel->maps.cidr_allowlist_b, slot,
                         "inactive src inner fd unavailable"),
        src_low.prefixes);
    // 4 proto — paired proto_bitmask_a/_b exact-HASH
    populate_hash_inner_slot(
        inactive_axis_fd(skel->maps.proto_bitmask_a, skel->maps.proto_bitmask_b, slot,
                         "inactive proto inner fd unavailable"),
        proto_low.entries, "proto");
    // 5 port — paired port_ranges_a/_b range ARRAY
    populate_port_inner_slot(
        inactive_axis_fd(skel->maps.port_ranges_a, skel->maps.port_ranges_b, slot,
                         "inactive port inner fd unavailable"),
        port_low.ranges);
    // 6 vlan — paired vlan_bitmask_a/_b exact-HASH
    populate_hash_inner_slot(
        inactive_axis_fd(skel->maps.vlan_bitmask_a, skel->maps.vlan_bitmask_b, slot,
                         "inactive vlan inner fd unavailable"),
        vlan_low.entries, "vlan");
    // §5.53 dst6 — paired dst6_bitmask_a/_b LPM bit-vector (v6 key)
    populate_bitvec6_inner_slot(
        inactive_axis_fd(skel->maps.dst6_bitmask_a, skel->maps.dst6_bitmask_b, slot,
                         "inactive dst6 inner fd unavailable"),
        dst6_low.prefixes);
    // §5.53 src6 — paired src6_bitmask_a/_b LPM bit-vector (v6 key)
    populate_bitvec6_inner_slot(
        inactive_axis_fd(skel->maps.src6_bitmask_a, skel->maps.src6_bitmask_b, slot,
                         "inactive src6 inner fd unavailable"),
        src6_low.prefixes);
    // §5.54 ethertype — paired ethertype_bitmask_a/_b exact-HASH (host-order u32 key)
    populate_hash_inner_slot(
        inactive_axis_fd(skel->maps.ethertype_bitmask_a, skel->maps.ethertype_bitmask_b, slot,
                         "inactive ethertype inner fd unavailable"),
        eth_low.entries, "ethertype");
    // 7 wildcard — SINGLE map indexed by slot (D-mvp-4.8-FD-HELPER-SCOPE)
    {
        const int wildcard_fd = bpf_map__fd(skel->maps.wildcard);
        if (wildcard_fd < 0) {
            throw_loader(LoaderError::LoadFailed, "wildcard fd unavailable");
        }
        write_wildcard_slots(wildcard_fd, slot,
                             dst_low.wildcard, src_low.wildcard,
                             proto_low.wildcard, port_low.wildcard,
                             vlan_low.wildcard, mac_low.wildcard,
                             dst6_low.wildcard, src6_low.wildcard,
                             eth_low.wildcard);
    }
    // 8 defaults — SINGLE map indexed by slot
    {
        const int defaults_fd = bpf_map__fd(skel->maps.defaults);
        if (defaults_fd < 0) {
            throw_loader(LoaderError::LoadFailed, "defaults fd unavailable");
        }
        write_default_slot(defaults_fd, slot, default_action);
    }
    // 9 rules — paired rules_a/_b inner ARRAY (keyed by internal slot)
    populate_rules_inner_slot(
        inactive_axis_fd(skel->maps.rules_a, skel->maps.rules_b, slot,
                         "inactive rules inner fd unavailable"),
        rules, id_to_slot);
    // 10 slot_rule_id — SINGLE map indexed by slot (§5.61 B30 D-mvp-4.21-Q1);
    // RESET-on-apply, mirrors wildcard/defaults. Userspace-only.
    {
        const int sri_fd = bpf_map__fd(skel->maps.slot_rule_id);
        if (sri_fd < 0) {
            throw_loader(LoaderError::LoadFailed, "slot_rule_id fd unavailable");
        }
        write_slot_rule_id(sri_fd, slot, slot_to_id);
    }
}

/* Read active_idx[0]. Returns 0 if unset; throws on real lookup error. */
[[nodiscard]] std::uint32_t read_active_idx(int active_idx_fd)
{
    const std::uint32_t zero = 0;
    std::uint32_t       cur  = 0;
    const int rc = bpf_map_lookup_elem(active_idx_fd, &zero, &cur);
    if (rc < 0) {
        // Map slot uninitialized → kernel returns ENOENT which userspace
        // surfaces as -ENOENT. Treat as "first time, defaults to 0".
        if (-rc == ENOENT) return 0;
        throw_loader(classify(rc, LoaderError::LoadFailed),
                     std::format("bpf_map_lookup_elem(active_idx): {}",
                                 std::strerror(-rc)));
    }
    return cur;
}

/* Check existence of a per-iface file under root, fd-relative + NOFOLLOW. */
[[nodiscard]] bool iface_file_exists(const BpffsRootFd& root,
                                      const std::string& iface,
                                      const char*        basename)
{
    const std::string rel = iface + "/" + basename;
    if (::faccessat(root.fd(), rel.c_str(), F_OK, AT_SYMLINK_NOFOLLOW) == 0) {
        return true;
    }
    const int e = errno;
    if (e == ENOENT) return false;
    if (e == ELOOP)  throw_iface_symlink(iface);
    throw_loader(classify(-e, LoaderError::LoadFailed),
                 std::format("faccessat bpffs/{}: {}", rel, std::strerror(e)));
}

[[noreturn]] void throw_alien_refused(const XdpProbe& probe, const std::string& iface)
{
    if (std::string_view{probe.name} != kOwnedProgName) {
        throw_loader(
            LoaderError::AttachRefusedAlien,
            std::format("XDP prog id {} (mode {}, name '{}') already attached to {} "
                        "(not ours — refusing to clobber)",
                        probe.prog_id, to_string(probe.mode),
                        probe.name, iface));
    }
    // Name matches but is_ours is false → tag check failed.
    throw_loader(
        LoaderError::AttachRefusedAlien,
        std::format("XDP prog id {} (mode {}, name '{}', tag {}) already attached to {} "
                    "(not ours — tag mismatch)",
                    probe.prog_id, to_string(probe.mode), probe.name,
                    format_tag_hex(probe.tag), iface));
}

}  // namespace

const std::error_category& loader_error_category() noexcept
{
    static const LoaderCategory cat;
    return cat;
}

std::uint32_t attach(const AttachConfig& cfg)
{
    /* §5.26 BC1 + EDIT-1: synthesize Config{default_action=Drop, rules=
     * [{id: i, action: Pass, match.mac: cfg.allow[i]}, ...]} then route
     * through internal::apply_request. AttachConfig stays unchanged per
     * PI-7. Sequential rule ids per architect's EDIT-1 prescription. */
    Config synth;
    synth.default_action = DefaultAction::Drop;
    synth.rules.reserve(cfg.allow.size());
    std::uint32_t next_id = 0;
    for (const xdpmf_mac& m : cfg.allow) {
        Rule r{};
        r.id        = next_id++;
        r.action    = RuleAction::Pass;
        r.match.mac = m;
        synth.rules.push_back(r);
    }
    return internal::apply_request(internal::ApplyRequest{cfg.iface, cfg.mode, std::move(synth)});
}

std::uint32_t detach(const std::string& iface)
{
    // §5.62 (MVP-4.22) R-1 / SEC-H1: iface shape-fence as the FIRST statement —
    // reject shape-invalid names (exit 8) before kernel_version_probe / any
    // kernel touch; removes the implicit reliance on if_nametoindex as the
    // sole shape gate.
    validate_iface_name(iface, LoaderError::PathRefused);

    // §5.24 Q3 Option B: symmetric with attach() — detach() also early-loads
    // the skeleton (§5.22 Q1), so kernel-version gating must precede that.
    kernel_version_probe();

    // §5.26 HG3: parse trust_model env even on detach so unknown values
    // fail-closed before any kernel touch. The stderr-log policy is
    // attach-only per §5.26 sub-decision; detach is silent on success
    // (preserves MVP-2 surface).
    (void)parse_trust_model_env();

    const int ifindex = resolve_ifindex(iface, LoaderError::DetachFailed);

    // §5.22 Item 2: BpffsRootFd guards the root for the duration of detach.
    BpffsRootFd root{};

    // §5.22 Q1 detach() symmetry: load the skeleton in detach() too so we
    // can compute self_tag and apply the same name+tag identity gate the
    // attach() path uses. Without this, an attacker-recompile (same name,
    // different bytecode) would pass detach()'s identity check and let
    // us "clean up" their evidence — restoring the very threat §5.22
    // closes for attach(). Cost: ~ms of verifier work per detach call
    // (detach is a rare path; acceptable). The skel goes out of scope at
    // function exit (BpfSkeleton dtor unwinds the kernel-side program);
    // we never call skel.attach() here — only query identity via
    // bpf_obj_get_info_by_fd on the just-loaded program fd. State-(c)
    // refusal on this path returns LoaderError::DetachFailed (exit 5),
    // NOT AttachRefusedAlien (4) — preserves the §5.4 semantic that
    // "operator asked to detach; we refused to touch a non-ours thing".
    // Authoritative spec for this flow lives in design.md §5.22 Q1
    // (post-architect-ack inline patch).
    BpfSkeleton skel = load_skeleton();
    const TagArray self_tag = capture_self_tag(skel);

    const XdpProbe probe = probe_attached_xdp(ifindex, self_tag);
    const bool pin_dir_exists = iface_entry_is_real_dir(root, iface);

    if (probe.prog_id == 0) {
        // §5.21 D4: detach is idempotent — both (a) "truly nothing" and
        // (d) "orphan pin dir only" return 0 from this layer. main.cpp
        // gates "detached prog id N" stdout on prog_id != 0, so the
        // caller-facing message comes from here for both branches.
        if (pin_dir_exists) {
            bpffs_remove_iface(root, iface);
            std::puts(std::format("removed orphan pin dir for {} (no XDP was attached)",
                                  iface).c_str());
            return 0;
        }
        std::puts(std::format("no XDP attached to {} (no-op)", iface).c_str());
        return 0;
    }

    if (!probe.is_ours || !pin_dir_exists) {
        // State (c) on detach path → DetachFailed (exit 5) per existing
        // §5.4 semantics. Identity-check sub-case (name vs tag) is exposed
        // via stderr but the exit code stays 5 (not 4) — detach never
        // returns AttachRefusedAlien. §5.23 Q1: mode is no longer a
        // refusal cause (any mode our name+tag match is "ours").
        if (std::string_view{probe.name} != kOwnedProgName) {
            throw_loader(LoaderError::DetachFailed,
                         std::format("XDP prog id {} (mode {}, name '{}') on {} is not ours — "
                                     "refusing to detach",
                                     probe.prog_id, to_string(probe.mode),
                                     probe.name, iface));
        }
        throw_loader(LoaderError::DetachFailed,
                     std::format("XDP prog id {} (mode {}, name '{}', tag {}) on {} is not ours — "
                                 "refusing to detach (tag mismatch)",
                                 probe.prog_id, to_string(probe.mode),
                                 probe.name, format_tag_hex(probe.tag), iface));
    }

    // §5.26 HG2 P0a: unpin the link BEFORE bpf_xdp_detach so the kernel
    // ref-count drops to zero in the expected order. unlinkat on the link
    // pin path; ENOENT is fine (link was never pinned — pre-§5.26 install
    // or already cleaned up). After unpin, bpf_xdp_detach drops the slot
    // proper (or returns idempotent-success if the kernel already collapsed
    // the slot under the link removal).
    if (::unlinkat(root.fd(), (iface + "/" XDPMF_LINK_PIN_BASENAME).c_str(), 0) != 0) {
        const int e = errno;
        if (e != ENOENT) {
            throw_loader(classify(-e, LoaderError::DetachFailed),
                         std::format("unlinkat bpffs/{}/{}: {}",
                                     iface, XDPMF_LINK_PIN_BASENAME, std::strerror(e)));
        }
    }

    // State (b): our prior instance. §5.23 Q1 Option A: detach in the
    // §5.20-probed mode (not hardcoded SKB) — operator did not supply
    // --mode on detach; the kernel told us which slot to detach.
    // ENOENT here means the link pin removal already triggered kernel-side
    // cleanup — treat as idempotent success.
    const int rc = bpf_xdp_detach(ifindex, probed_mode_to_flags(probe.mode), nullptr);
    if (rc < 0 && -rc != ENOENT) {
        throw_loader(classify(rc, LoaderError::DetachFailed),
                     std::format("bpf_xdp_detach: {}", std::strerror(-rc)));
    }
    bpffs_remove_iface(root, iface);
    return probe.prog_id;
}

namespace internal {

/* §5.26 + EDIT-1 atomic apply (single source of truth for the swap flow):
 * see design §5.26 attach() flow update + Phase B EDIT-1 internal-helper
 * contract. Both loader::attach() and apply::apply_config_inmemory() route
 * through here so the active_idx-flip + ruleset/defaults population logic
 * lives in exactly ONE place. */
std::uint32_t apply_request(const ApplyRequest& req)
{
    // §5.62 (MVP-4.22) R-1 / SEC-H1: iface shape-fence as the FIRST statement —
    // reject shape-invalid names (exit 8) before any lowering/kernel touch.
    validate_iface_name(req.iface, LoaderError::PathRefused);

    // §5.47 (MVP-4.7): the MAC axis is UN-FROZEN — lowered to a per-MAC
    // aggregated rule-bitmask list (constrained) + a wildcard mask
    // (unconstrained), exactly like the proto/vlan exact-HASH axes. NO closure
    // (D-mvp-4.7-NO-CLOSURE). The two LPM axes are lowered to prefix+bit lists
    // (constrained) + wildcard masks (unconstrained).
    // §5.61 (MVP-4.21) B30 D-mvp-4.21-Q3 / SLOT-PLUMB: assign each rule a dense
    // internal `slot` = its rank in ascending-unique-id order, computed ONCE and
    // threaded into EVERY populate site (the 4 lowering bit-shifts, rules_inner,
    // rule_counters, slot_rule_id) so a single coherent slot per rule is used
    // everywhere (D-mvp-4.21-SLOT-COHERENCE). slot_to_id is the [0,64) inverse
    // (id or EMPTY) feeding the slot_rule_id map write + the copy-forward remap.
    const std::unordered_map<std::uint32_t, std::uint32_t> id_to_slot =
        compute_id_to_slot(req.config.rules);
    const std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX> slot_to_id =
        compute_slot_to_id(req.config.rules, id_to_slot);
    // §5.50 (MVP-4.10 B28-2): mac/proto/vlan exact-HASH lowering folded into the
    // generic aggregate_axis template; per-axis projector + equality functors
    // here. mac uses a 6-octet memcmp equality (NOT ==, D-mvp-4.10-MAC-EQ).
    const MacLowering          mac_low     = aggregate_axis<xdpmf_mac>(
        req.config.rules,
        [](const Rule& r) { return r.match.mac; },
        [](const xdpmf_mac& a, const xdpmf_mac& b) {
            return std::memcmp(a.octets, b.octets, sizeof(a.octets)) == 0;
        },
        id_to_slot);
    const AxisLowering         dst_low     = lower_axis(req.config, /*dst_axis=*/true, id_to_slot);
    const AxisLowering         src_low     = lower_axis(req.config, /*dst_axis=*/false, id_to_slot);
    // §5.53 (MVP-4.13): lower the two NEW IPv6 LPM axes (dst6/src6). FORKED
    // siblings of the v4 dst/src lowering; family-blind (a v4-only rule lands
    // in wc_dst6/wc_src6, the load-bearing Q2 cross-family fill).
    const AxisLowering6        dst6_low    = lower_axis6(req.config, /*dst6_axis=*/true, id_to_slot);
    const AxisLowering6        src6_low    = lower_axis6(req.config, /*dst6_axis=*/false, id_to_slot);
    // §5.44 (MVP-4.4): lower the two NEW axes (proto exact-HASH, dst_port
    // range) alongside the §5.43 LPM axes. NO closure (D-mvp-4.4-NO-CLOSURE).
    const ProtoLowering        proto_low   = aggregate_axis<std::uint32_t>(
        req.config.rules,
        [](const Rule& r) -> std::optional<std::uint32_t> { return r.match.protocol; },
        std::equal_to<std::uint32_t>{},
        id_to_slot);
    const PortLowering         port_low    = lower_port_axis(req.config, id_to_slot);
    // §5.45 (MVP-4.5): lower the NEW vlan axis (exact-HASH outer VID) alongside
    // the §5.43/§5.44 axes. NO closure (D-mvp-4.5-NO-CLOSURE). The vlan projector
    // widens the config u16 VID -> the BPF __u32 HASH key (D-mvp-4.5-VLAN-VALUE-WIDTH).
    const VlanLowering         vlan_low    = aggregate_axis<std::uint32_t>(
        req.config.rules,
        [](const Rule& r) -> std::optional<std::uint32_t> {
            if (r.match.vlan) return std::uint32_t{*r.match.vlan};
            return std::nullopt;
        },
        std::equal_to<std::uint32_t>{},
        id_to_slot);
    // §5.54 (MVP-4.14): lower the NEW ethertype axis (exact-HASH, host-order u16
    // widened to the BPF __u32 HASH key). CLONE of the vlan lowering above; NO
    // closure (D-mvp-4.14-CLONE / D-mvp-4.14-HASH-MAX). Family-blind: the axis
    // is composed into all three datapath arms by the hoisted lookup.
    const EthertypeLowering    eth_low     = aggregate_axis<std::uint32_t>(
        req.config.rules,
        [](const Rule& r) -> std::optional<std::uint32_t> {
            if (r.match.ethertype) return std::uint32_t{*r.match.ethertype};
            return std::nullopt;
        },
        std::equal_to<std::uint32_t>{},
        id_to_slot);
    const DefaultAction default_action     = req.config.default_action;

    if (mac_low.entries.size() > XDPMF_ALLOWLIST_MAX) {
        throw_loader(LoaderError::LoadFailed,
                     std::format("apply: mac-rule count {} exceeds XDPMF_ALLOWLIST_MAX={}",
                                 mac_low.entries.size(), XDPMF_ALLOWLIST_MAX));
    }
    if (dst_low.prefixes.size() > XDPMF_ALLOWLIST_MAX) {
        throw_loader(LoaderError::LoadFailed,
                     std::format("apply: dst-cidr-rule count {} exceeds XDPMF_ALLOWLIST_MAX={}",
                                 dst_low.prefixes.size(), XDPMF_ALLOWLIST_MAX));
    }
    if (src_low.prefixes.size() > XDPMF_ALLOWLIST_MAX) {
        throw_loader(LoaderError::LoadFailed,
                     std::format("apply: src-cidr-rule count {} exceeds XDPMF_ALLOWLIST_MAX={}",
                                 src_low.prefixes.size(), XDPMF_ALLOWLIST_MAX));
    }
    if (dst6_low.prefixes.size() > XDPMF_ALLOWLIST_MAX) {
        throw_loader(LoaderError::LoadFailed,
                     std::format("apply: dst-cidr6-rule count {} exceeds XDPMF_ALLOWLIST_MAX={}",
                                 dst6_low.prefixes.size(), XDPMF_ALLOWLIST_MAX));
    }
    if (src6_low.prefixes.size() > XDPMF_ALLOWLIST_MAX) {
        throw_loader(LoaderError::LoadFailed,
                     std::format("apply: src-cidr6-rule count {} exceeds XDPMF_ALLOWLIST_MAX={}",
                                 src6_low.prefixes.size(), XDPMF_ALLOWLIST_MAX));
    }
    // §5.44 (MVP-4.4): the port axis stores one ARRAY slot per port-constrained
    // rule (bounded by XDPMF_ALLOWLIST_MAX inner slots). The proto axis
    // aggregates per proto, so its entry count ≤ 256 (XDPMF_PROTO_HASH_MAX) by
    // construction — no separate bound check needed beyond the per-rule id cap.
    if (port_low.ranges.size() > XDPMF_ALLOWLIST_MAX) {
        throw_loader(LoaderError::LoadFailed,
                     std::format("apply: dst-port-rule count {} exceeds XDPMF_ALLOWLIST_MAX={}",
                                 port_low.ranges.size(), XDPMF_ALLOWLIST_MAX));
    }

    // §5.24 Q3 Option B: kernel-version probe BEFORE any libbpf API call.
    kernel_version_probe();

    // §5.26 HG3: trust_model env parse — fail-closed on unknown values; log
    // the resolved mode at attach entry per the §5.26 sub-decision (audit
    // story for ops greps). The log line is the load-bearing signal for
    // §6.21 / §6.26 stderr assertions.
    const TrustModel trust_model = parse_trust_model_env();
    log_trust_model(trust_model);

    const int ifindex = resolve_ifindex(req.iface, LoaderError::AttachFailed);

    // §5.22 Item 2: BpffsRootFd guards the bpffs root via O_PATH|O_NOFOLLOW.
    BpffsRootFd root{};

    // §5.22 Q1 Option E: load skeleton FIRST so self_tag is available for
    // the §5.4 probe BEFORE we make any kernel-mutating decisions.
    BpfSkeleton skel = load_skeleton();
    const TagArray self_tag = capture_self_tag(skel);

    const XdpProbe probe          = probe_attached_xdp(ifindex, self_tag);
    const bool     pin_dir_exists = iface_entry_is_real_dir(root, req.iface);

    // §5.26 HG2 P0a: classify the link pin's presence — separate from the
    // dir-presence check because the dir may exist without a link (state-d
    // half-init). Only relevant for the idempotent-reattach branch.
    const bool link_pin_exists = pin_dir_exists
        && iface_file_exists(root, req.iface, XDPMF_LINK_PIN_BASENAME);

    bool reattach_via_link = false;

    if (probe.prog_id != 0) {
        if (probe.is_ours && pin_dir_exists) {
            // State (b): our prior instance. HG2 idempotent-reattach if a
            // link pin survives; else fall through to fresh attach with the
            // existing pin dir cleaned out (preserves pre-§5.26 cleanup-
            // and-reattach pattern for first-time-upgrades from MVP-2).
            if (link_pin_exists) {
                reattach_via_link = true;
                // Don't detach: bpf_link__update_program hot-swaps under
                // the existing kernel link. Maps stay in place. Defaults
                // and inner-map population happens below into the INACTIVE
                // slot; active_idx flip is the atomic commit.
            } else {
                // No link pin — pre-§5.26 instance; fall back to MVP-2
                // detach-then-reattach (one short packet window).
                const int rc = bpf_xdp_detach(ifindex,
                                              probed_mode_to_flags(probe.mode), nullptr);
                if (rc < 0) {
                    throw_loader(classify(rc, LoaderError::AttachFailed),
                                 std::format("bpf_xdp_detach (idempotent cleanup): {}",
                                             std::strerror(-rc)));
                }
                bpffs_remove_iface(root, req.iface);
            }
        } else {
            // State (c): alien. §5.26 HG3: trust_model gates disposition.
            if (trust_model == TrustModel::Strict) {
                throw_alien_refused(probe, req.iface);
            }
            // Fleet: bypass alien refusal — detach the alien, clean the dir,
            // proceed with a fresh attach. §5.19 + §5.22 hardening already
            // ran BEFORE this branch (we read name/tag to compute is_ours);
            // only §5.4 disposition is relaxed.
            /* §5.32 (MVP-3.5): byte-equivalent text-mode + structural fields
             * for JSON. Iface-scoped event. */
            const std::string mode_str{to_string(probe.mode)};
            const std::string fleet_msg = std::format(
                "xdpmacfilter: trust_model=fleet — bypassing alien-program check; "
                "replacing prog id {} (mode={}, name='{}')\n",
                probe.prog_id, mode_str, probe.name);
            const xdpmf::logger::Field fleet_fields[] = {
                xdpmf::logger::Field{"prog_id",
                                     static_cast<std::int64_t>(probe.prog_id)},
                xdpmf::logger::Field{"mode",      std::string_view{mode_str}},
                xdpmf::logger::Field{"alien_name", std::string_view{probe.name}},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Info,
                                "loader.attach.fleet_replace",
                                std::string_view{req.iface},
                                fleet_msg,
                                fleet_fields);
            const int rc = bpf_xdp_detach(ifindex,
                                          probed_mode_to_flags(probe.mode), nullptr);
            if (rc < 0) {
                throw_loader(classify(rc, LoaderError::AttachFailed),
                             std::format("bpf_xdp_detach (fleet bypass): {}",
                                         std::strerror(-rc)));
            }
            if (pin_dir_exists) bpffs_remove_iface(root, req.iface);
        }
    } else if (pin_dir_exists) {
        // State (d): no XDP attached, stale pin dir survives. Clean and
        // fresh-attach.
        bpffs_remove_iface(root, req.iface);
    }
    // State (a): nothing → fresh attach.

    // Ensure per-iface dir + arm rollback guard before any throw-risky op.
    // On reattach we MUST NOT remove the dir on rollback — the existing
    // link pin lives there and removing the dir would orphan the kernel link.
    ensure_iface_dir(root, req.iface);
    IfaceDirGuard dir_guard{root, req.iface};
    if (!reattach_via_link) {
        dir_guard.arm();
    }

    const std::string pin_dir = bpffs_dir_for(req.iface);

    if (reattach_via_link) {
        // §5.26 HG2 idempotent reattach per design step 10 +
        // §5.26 EDIT-1 single-implementation contract:
        //   bpf_link__open(link_pin) + bpf_link__update_program(link, new_prog).
        //
        // Strategy:
        //   1. Discard the just-loaded skel; reopen + bpf_map__reuse_fd
        //      against the SIX pinned kernel maps so the SECOND load's
        //      maps ARE the existing pinned maps (same kernel objects,
        //      same accumulated state — stats counts in particular are
        //      preserved across the swap per T_APPLY_ATOMIC_SWAP_NO_DROP).
        //   2. Read CURRENT active_idx (now visible via the reused map fd
        //      on the new skel) to determine the inactive slot.
        //   3. Populate the inactive inner slot + defaults via the (reused)
        //      map fds; the OLD prog still reads from these maps but the
        //      INACTIVE slot is unobserved until the flip.
        //   4. bpf_link__update_program — atomically swap to the NEW prog
        //      (different prog_id; same maps).
        //   5. Atomic commit: write active_idx = inactive (one u32 store).
        //
        // No re-pinning needed (pins already point at the maps we use).
        // No stats loss (stats map fd is reused; counts continue accumulating
        // through the new prog). T_ATTACH_TAG_MISMATCH's
        // our_id_2 != our_id_1 invariant holds (second load → different prog_id).
        skel.reset();
        skel = open_skeleton_only();

        // §5.30 HK-9: reuse-fd loop walks every kManagedMaps[] entry. Same
        // reuse semantic per slot — single active_idx shared. PI-7-3.4.5-cpp
        // scope: this loop body replaces the prior pre-HK-9 11-entry literal
        // at this site.
        for (const ManagedMapEntry& entry : kManagedMaps) {
            const std::string p = pin_dir + "/" + entry.name;
            const int fd = bpf_obj_get(p.c_str());
            if (fd < 0) {
                const int e = errno;
                throw_loader(classify(-e, LoaderError::LoadFailed),
                             std::format("bpf_obj_get (reuse '{}'): {}",
                                         p, std::strerror(e)));
            }
            UniqueFd dup_holder{fd};
            if (bpf_map__reuse_fd(skel->maps.*entry.member_ptr, dup_holder.get()) != 0) {
                const int e = errno;
                throw_loader(classify(-e, LoaderError::LoadFailed),
                             std::format("bpf_map__reuse_fd({}): {}",
                                         entry.name, std::strerror(e)));
            }
            // bpf_map__reuse_fd dup()'s the fd internally; safe to close ours.
        }
        finish_load_skeleton(skel);

        const int active_idx_reused_fd = bpf_map__fd(skel->maps.active_idx);
        if (active_idx_reused_fd < 0) {
            throw_loader(LoaderError::LoadFailed,
                         "active_idx fd unavailable (reattach reuse)");
        }
        const std::uint32_t cur      = read_active_idx(active_idx_reused_fd);
        const std::uint32_t inactive = (cur == 0) ? 1u : 0u;

        // §5.48 (MVP-4.8) D-mvp-4.8-BOUNDARY: populate ALL RESET-on-apply axes
        // (mac/dst/src/proto/port/vlan/wildcard/defaults/rules) into the
        // INACTIVE slot via the table-driven helper BEFORE the active_idx flip,
        // so the single u32 store commits the whole 9-axis+rules+wildcard+
        // defaults swap atomically (D-mvp-4.3-RESET-VS-PRESERVE — match/wildcard
        // maps RESET-on-apply). The HK-9 `_a`/`_b`<->slot hazard now lives in
        // exactly ONE place (inactive_axis_fd). populate_action_table (shared
        // static) + copy_rule_counters_forward (PRESERVE) stay EXPLICIT below
        // (guard #15 / D-mvp-4.8-BOUNDARY).
        populate_all_axes(skel.get(), inactive, mac_low, dst_low, src_low,
                          proto_low, port_low, vlan_low, dst6_low, src6_low,
                          eth_low, req.config.rules, id_to_slot, slot_to_id,
                          default_action);
        // §5.29 (MVP-3.4) step 8.5: `action_table` STAYS SHARED per
        // §5.34 HG-3.4b-c2-3 / D-3.4b-c2-6 — values are static
        // {PASS=0, DROP=1}, never mutate at runtime; atomic-swap meaningless.
        {
            const int at_fd = bpf_map__fd(skel->maps.action_table);
            if (at_fd < 0) {
                throw_loader(LoaderError::LoadFailed,
                             "action_table fd unavailable (reattach)");
            }
            populate_action_table(at_fd);
        }

        // §5.35 (MVP-3.4d) D-3.4d-3: copy-forward per-CPU rule_counters
        // values from the OLD-active inner to the INACTIVE inner BEFORE
        // the active_idx flip. PI-3.4b-2 PRESERVE-across-apply held: the
        // post-flip new-active inner carries the operator-observable
        // counter state from the pre-apply state. Combined with
        // D-3.4d-RESET-BOTH (reset-counters zeros BOTH inners), the reset-
        // counters → apply sequence keeps the post-apply inner at 0.
        {
            bpf_map* old_active_rc_inner = (cur == 0)
                                                ? skel->maps.rule_counters_a
                                                : skel->maps.rule_counters_b;
            bpf_map* inactive_rc_inner   = (inactive == 0)
                                                ? skel->maps.rule_counters_a
                                                : skel->maps.rule_counters_b;
            const int old_rc_fd = bpf_map__fd(old_active_rc_inner);
            const int inactive_rc_fd = bpf_map__fd(inactive_rc_inner);
            if (old_rc_fd < 0 || inactive_rc_fd < 0) {
                throw_loader(LoaderError::LoadFailed,
                             "rule_counters inner fd unavailable (reattach)");
            }
            // §5.61 B30 D-mvp-4.21-COPYFWD-BY-ID: recover the OLD-active slot→id
            // (from the intact OLD half of slot_rule_id — populate touched only
            // the INACTIVE half) so a surviving id's counter follows its id even
            // if its slot moved. new mapping = this apply's slot_to_id.
            const int sri_fd = bpf_map__fd(skel->maps.slot_rule_id);
            if (sri_fd < 0) {
                throw_loader(LoaderError::LoadFailed,
                             "slot_rule_id fd unavailable (reattach)");
            }
            const std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX> old_slot_to_id =
                read_slot_rule_id_half(sri_fd, cur);
            copy_rule_counters_forward(old_rc_fd, inactive_rc_fd,
                                       old_slot_to_id, slot_to_id);
        }

        // Atomic prog swap. The OLD prog has been reading from these same
        // (reused) maps; after update_program, the NEW prog reads from them.
        bpf_link* link = bpf_link__open(link_pin_path_for(req.iface).c_str());
        const long open_err = libbpf_get_error(link);
        if (open_err) {
            throw_loader(classify(static_cast<int>(open_err), LoaderError::AttachFailed),
                         std::format("bpf_link__open('{}'): {}",
                                     link_pin_path_for(req.iface),
                                     std::strerror(-static_cast<int>(open_err))));
        }
        const int upd_rc = bpf_link__update_program(link, skel->progs.mac_filter_prog);
        if (upd_rc < 0) {
            bpf_link__disconnect(link);
            bpf_link__destroy(link);
            throw_loader(classify(upd_rc, LoaderError::AttachFailed),
                         std::format("bpf_link__update_program: {}",
                                     std::strerror(-upd_rc)));
        }
        bpf_link__disconnect(link);  // keep kernel link alive past loader exit
        bpf_link__destroy(link);

        // ATOMIC SWAP COMMIT — single u32 store on the reused active_idx.
        // (Map dentries unchanged; userspace bpftool dumps see the new value.)
        write_active_idx(active_idx_reused_fd, inactive);

        /* §5.32 (MVP-3.5): byte-equivalent text-mode + iface field for JSON. */
        const std::string replace_msg = std::format(
            "xdpmacfilter: replacing existing program on {}\n", req.iface);
        xdpmf::logger::emit(xdpmf::logger::Level::Info,
                            "loader.attach.replace",
                            std::string_view{req.iface},
                            replace_msg);

        // §5.31 (MVP-3.4b) PI-3.4b-5 + D-3.4b-16: write rule_index.json
        // POST-flip so the sidecar describes the LIVE config (matches the
        // bpftool dump for inner-allowlist values' rule_id field). NEVER
        // throws — failures degrade to exporter's action="unknown" labels
        // per D-3.4b-17.
        sidecar::write_rule_index(req.iface, XDPMF_SIDECAR_ROOT, req.config);

        const XdpProbe after_probe = probe_attached_xdp(ifindex, self_tag);
        return after_probe.prog_id;
    }

    // FRESH ATTACH path (state a / state d / state c-fleet).
    // §5.30 HK-9: per-iface pin loop walks every kManagedMaps[] entry.
    for (const ManagedMapEntry& entry : kManagedMaps) {
        const std::string p = pin_dir + "/" + entry.name;
        const int rc = bpf_map__pin(skel->maps.*entry.member_ptr, p.c_str());
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map__pin({}): {}", p, std::strerror(-rc)));
        }
    }

    // Fresh attach: populate slot 0 (the initial active slot).
    const int active_idx_fd = bpf_map__fd(skel->maps.active_idx);
    if (active_idx_fd < 0) {
        throw_loader(LoaderError::LoadFailed, "active_idx map fd unavailable");
    }
    // §5.48 (MVP-4.8) D-mvp-4.8-BOUNDARY: fresh-attach populates slot 0 of ALL
    // RESET-on-apply axes (mac/dst/src/proto/port/vlan/wildcard/defaults/rules)
    // via the SAME table-driven helper the reattach branch uses; the active_idx
    // u32 store below (= 0) is the atomic commit for all of them. slot==0 ->
    // the `_a` inners (inactive_axis_fd). populate_action_table + the self-copy
    // copy_rule_counters_forward stay EXPLICIT below (guard #15).
    populate_all_axes(skel.get(), 0u, mac_low, dst_low, src_low, proto_low,
                      port_low, vlan_low, dst6_low, src6_low, eth_low,
                      req.config.rules, id_to_slot, slot_to_id, default_action);
    // §5.29 (MVP-3.4) step 8.5: `action_table` STAYS SHARED per §5.34
    // HG-3.4b-c2-3 / D-3.4b-c2-6 — static {PASS=0, DROP=1} mapping.
    {
        const int at_fd = bpf_map__fd(skel->maps.action_table);
        if (at_fd < 0) {
            throw_loader(LoaderError::LoadFailed, "action_table map fd unavailable");
        }
        populate_action_table(at_fd);
    }

    // §5.35 (MVP-3.4d) D-3.4d-3: fresh-attach uniform code path — copy-
    // forward from rule_counters_a to itself (self-copy, semantically no-op
    // since both inners are freshly zero-initialized at this point). Calling
    // the helper here keeps the apply-step structure parallel between the
    // reattach branch and fresh-attach branch (architect choice: uniform
    // code path; defense-in-depth — D-3.4d-3 ALWAYS-run discipline).
    {
        const int rc_a_fd = bpf_map__fd(skel->maps.rule_counters_a);
        if (rc_a_fd < 0) {
            throw_loader(LoaderError::LoadFailed,
                         "rule_counters_a fd unavailable (fresh attach)");
        }
        // §5.61 B30 D-mvp-4.21-FIRSTAPPLY: fresh attach has no prior slot→id;
        // pass an all-EMPTY old mapping so nothing matches and every slot is
        // zeroed (harmless — the fresh inner is already zero). Uniform path.
        std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX> empty_old;
        empty_old.fill(XDPMF_SLOT_ID_EMPTY);
        copy_rule_counters_forward(rc_a_fd, rc_a_fd, empty_old, slot_to_id);
    }

    // First attach: create+pin the XDP link with the operator-selected mode.
    {
        const int prog_fd = bpf_program__fd(skel->progs.mac_filter_prog);
        if (prog_fd < 0) {
            throw_loader(LoaderError::AttachFailed, "mac_filter_prog fd unavailable");
        }
        const int link_fd = create_xdp_link(prog_fd, ifindex, req.mode);
        try {
            pin_fd(link_fd, link_pin_path_for(req.iface));
        } catch (...) {
            (void)::close(link_fd);
            throw;
        }
        (void)::close(link_fd);
    }

    // ATOMIC SWAP COMMIT: active_idx[0] = 0 (slot 0 with our just-written rules).
    write_active_idx(active_idx_fd, 0u);

    // §5.31 (MVP-3.4b) PI-3.4b-5 + D-3.4b-16: write rule_index.json POST-flip.
    // See reattach branch above for rationale (non-fatal degrade, exporter
    // falls back to action="unknown" labels per D-3.4b-17 if this fails).
    sidecar::write_rule_index(req.iface, XDPMF_SIDECAR_ROOT, req.config);

    const XdpProbe after = probe_attached_xdp(ifindex, self_tag);
    dir_guard.release();
    return after.prog_id;
}

/* §5.36 (MVP-3.4e) HG-3.4e-1 + EDIT-1: `reset-counters` routed through
 * this helper instead of the CLI translation unit, so the §5.22
 * BpffsRootFd / iface_entry_is_real_dir primitives are composed BEFORE
 * any pin path is constructed. KC-3 reset-counters limb closure (closes
 * the regression noted by the 2026-05-27 /mint-review security-reviewer
 * H1).
 *
 * Flow (post §5.36 EDIT-1 — resolve_ifindex DROPPED per netns-vs-host
 * asymmetry + pin-as-authority semantic):
 *   1. validate_iface_name(req.iface, PathRefused)         — shape gate (exit 8)
 *   2. BpffsRootFd root{}                                  — root symlink gate (exit 8)
 *   3. iface_entry_is_real_dir(root, req.iface)
 *        → true               → proceed
 *        → false              → emit reset_counters.refused.no_pin + return false
 *                              (CLI maps false → exit 1, matches §5.35
 *                               T_CLI_RESET_COUNTERS_NO_IFACE expectation)
 *        → symlink / non-dir  → throws PathRefused (exit 8)
 *   4. bpf_obj_get(<iface>/rule_counters_a) + (..._b)
 *   5. per-CPU zero buffer (libbpf_num_possible_cpus())
 *   6. bpf_map_update_elem zero-write loop or single-slot (D-3.4d-RESET-BOTH)
 *   7. close fds; return true
 *
 * Return: true on success; false on iface-not-attached (event already
 * emitted). Throws std::system_error on PathRefused class + hard BPF
 * errors. CLI translation unit (src/cli/reset_counters.cpp) post-§5.36
 * EDIT-1: argv → audit-log `reset_counters.activated` → invoke this
 * helper → `return ok ? 0 : 1;`. NO path-construction, NO bpf_obj_get,
 * NO direct map writes survive in the CLI TU. */
[[nodiscard]] bool reset_counters_request(const ResetCountersRequest& req)
{
    // 1. Shape gate (Q2.A2): rejects path-traversal / whitespace / control
    // chars BEFORE the path is composed. Throws PathRefused (exit 8).
    validate_iface_name(req.iface, LoaderError::PathRefused);

    // 2. Bpffs root hardening (§5.22): O_PATH|O_DIRECTORY|O_NOFOLLOW on
    // XDPMF_BPFFS_ROOT — root symlink → PathRefused (exit 8); non-dir →
    // PathRefused; permission errors → Permission.
    //
    // §5.36 EDIT-1: resolve_ifindex step is INTENTIONALLY OMITTED. Reset-
    // counters is a host-global BPF MAP operation per §5.25 P1; the iface
    // is a pin-folder key, not a netdev attach target. Pin presence is the
    // authoritative attached?-signal (step 3 below). Apply/detach still
    // call resolve_ifindex because XDP attach genuinely needs ifindex.
    BpffsRootFd root{};

    // 3. Per-iface depth hardening (§5.22): faccessat + fstatat
    // (AT_SYMLINK_NOFOLLOW). Returns false on ENOENT; throws PathRefused
    // on symlink/non-dir. §5.36 EDIT-1: on ENOENT (iface not attached),
    // emit reset_counters.refused.no_pin event and return false — caller
    // maps to exit 1 (operator-observable "not attached" — preserves
    // §5.35 HG-3.4d-3 behavioural contract verbatim).
    if (!iface_entry_is_real_dir(root, req.iface)) {
        const std::string inner_a_path =
            std::string{XDPMF_BPFFS_ROOT} + "/" + req.iface + "/"
            + XDPMF_MAP_RULE_COUNTERS_INNER_A_NAME;
        const std::string msg = std::format(
            "reset-counters: no rule_counters pin at {}; iface '{}' not attached?\n",
            inner_a_path, req.iface);
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"pin_path", std::string_view{inner_a_path}},
            xdpmf::logger::Field{"errno",    static_cast<std::int64_t>(ENOENT)},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Error,
                            "reset_counters.refused.no_pin",
                            std::string_view{req.iface}, msg, fs);
        return false;
    }

    // 5. Construct pin paths post-validation. iface has passed validate_iface_name
    // and iface_entry_is_real_dir — the name is fence-clean; the path string
    // cannot escape XDPMF_BPFFS_ROOT.
    const std::string iface_dir   = bpffs_dir_for(req.iface);
    const std::string inner_a_pin = iface_dir + "/" + XDPMF_MAP_RULE_COUNTERS_INNER_A_NAME;
    const std::string inner_b_pin = iface_dir + "/" + XDPMF_MAP_RULE_COUNTERS_INNER_B_NAME;

    // §5.36 note: libbpf has no fd-relative bpf_obj_get_at (§5.22 Q2
    // Maximum carries forward as OOS). The path-based bpf_obj_get is
    // safe HERE because iface has been fence-validated above — no
    // attacker-controlled component remains.
    auto open_pin = [](const std::string& path) -> int {
        const int fd = ::bpf_obj_get(path.c_str());
        if (fd < 0) {
            const int e = errno;
            // ENOENT here is a partial-attach inconsistency: the iface dir
            // exists but the inner pin is missing. Emit the same no_pin
            // event so operator log-shipping pipelines treat it uniformly.
            if (e == ENOENT) {
                const std::string msg = std::format(
                    "reset-counters: no rule_counters pin at {}\n", path);
                const xdpmf::logger::Field fs[] = {
                    xdpmf::logger::Field{"pin_path", std::string_view{path}},
                    xdpmf::logger::Field{"errno",    static_cast<std::int64_t>(e)},
                };
                xdpmf::logger::emit(xdpmf::logger::Level::Error,
                                    "reset_counters.refused.no_pin",
                                    std::nullopt, msg, fs);
                throw_loader(LoaderError::LoadFailed,
                             std::format("rule_counters pin '{}' absent — partial attach?",
                                         path));
            }
            throw std::system_error(
                e, std::generic_category(),
                std::format("bpf_obj_get('{}')", path));
        }
        return fd;
    };

    const int inner_a_fd = open_pin(inner_a_pin);
    int inner_b_fd = -1;
    try {
        inner_b_fd = open_pin(inner_b_pin);
    } catch (...) {
        (void)::close(inner_a_fd);
        throw;
    }

    // 6. Per-CPU zero buffer sized by libbpf_num_possible_cpus(). std::vector
    // default-initializes to zero so the buffer is N×u64 zeros.
    const int num_cpus = ::libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        (void)::close(inner_a_fd);
        (void)::close(inner_b_fd);
        throw std::system_error(
            EINVAL, std::generic_category(),
            std::format("libbpf_num_possible_cpus returned {}", num_cpus));
    }
    std::vector<std::uint64_t> zero_per_cpu(static_cast<std::size_t>(num_cpus), 0u);

    // 7. D-3.4d-RESET-BOTH: zero the chosen slot(s) on BOTH inner_a AND
    // inner_b so subsequent active_idx flips are idempotent. Single-slot
    // when req.rule_id has a value; full sweep 0..XDPMF_RULE_COUNTERS_MAX-1
    // otherwise (HG-3.4d-1).
    auto zero_slot = [&](int fd, std::uint32_t rid, std::string_view inner_name) {
        const int rc = ::bpf_map_update_elem(fd, &rid, zero_per_cpu.data(), BPF_ANY);
        if (rc < 0) {
            const int e = -rc;
            throw std::system_error(
                e, std::generic_category(),
                std::format("bpf_map_update_elem({}[{}])", inner_name, rid));
        }
    };

    try {
        if (req.rule_id.has_value()) {
            const std::uint32_t rid = *req.rule_id;
            zero_slot(inner_a_fd, rid, XDPMF_MAP_RULE_COUNTERS_INNER_A_NAME);
            zero_slot(inner_b_fd, rid, XDPMF_MAP_RULE_COUNTERS_INNER_B_NAME);
        } else {
            for (std::uint32_t rid = 0;
                 rid < static_cast<std::uint32_t>(XDPMF_RULE_COUNTERS_MAX);
                 ++rid) {
                zero_slot(inner_a_fd, rid, XDPMF_MAP_RULE_COUNTERS_INNER_A_NAME);
                zero_slot(inner_b_fd, rid, XDPMF_MAP_RULE_COUNTERS_INNER_B_NAME);
            }
        }
    } catch (...) {
        (void)::close(inner_a_fd);
        (void)::close(inner_b_fd);
        throw;
    }

    (void)::close(inner_a_fd);
    (void)::close(inner_b_fd);
    return true;
}

}  // namespace internal

}  // namespace xdpmf
