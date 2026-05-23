/*
 * loader.cpp — XDP attach/detach control plane built on libbpf.
 *
 * Attach sequence (design §5.4 4-state probe, MVP-1.1B hardened per
 * §5.19 identity verification + §5.20 all-modes query):
 *   1. Resolve <iface> → ifindex.
 *   2. Probe the iface's XDP slot across ALL modes (HW > NATIVE > SKB)
 *      via bpf_xdp_query(), and — if a program is attached — verify its
 *      compile-time identity (bpf_prog_info.name == "mac_filter_prog")
 *      to classify it as ours-vs-alien.
 *   3. 4-state disposition:
 *      (a) no prog, no pin_dir            → fresh attach
 *      (b) prog ours (SKB + name match)   → detach + clean + fresh attach
 *      (c) prog alien (any other shape)   → throw AttachRefusedAlien (4)
 *      (d) no prog, pin_dir present       → cleanup orphan + fresh attach
 *   4. Create per-iface bpffs dir, open+load skeleton with
 *      pin_root_path = <dir> (LIBBPF_PIN_BY_NAME maps auto-pin), populate
 *      allow-list, attach XDP in SKB mode (Decision §5.6).
 *
 * Rollback on any throw: XdpAttachment unwinds, BpffsDir removes the
 * pinned dir, BpfSkeleton tears down libbpf state. On success all three
 * are release()'d — the kernel keeps the XDP slot via its netif ref.
 */
#include "loader.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <format>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <unistd.h>          // close()
#include <linux/if_link.h>   // XDP_FLAGS_SKB_MODE
#include <net/if.h>
#include <sys/stat.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common/mac_filter.h"
#include "raii.hpp"

namespace xdpmf {

namespace {

constexpr std::uint32_t kXdpFlags = XDP_FLAGS_SKB_MODE;

/* §5.19 identity gate: the BPF program's SEC()-exported function name as
 * kernel-reported via bpf_prog_info.name. MUST match
 * src/bpf/mac_filter.bpf.c's `int mac_filter_prog(...)` symbol; renaming
 * that symbol without updating this constant silently breaks "ours"
 * classification. */
constexpr std::string_view kOwnedProgName{"mac_filter_prog"};

/* §5.4 + §5.20: per-iface XDP slot classification. Stays anon-namespace
 * — no consumer outside loader.cpp (loader.hpp §4.3 unchanged). */
enum class XdpMode : std::uint8_t { None, Skb, Native, Hw };

[[nodiscard]] constexpr std::string_view to_string(XdpMode m) noexcept
{
    switch (m) {
        case XdpMode::None:   return "NONE";
        case XdpMode::Skb:    return "SKB";
        case XdpMode::Native: return "NATIVE";
        case XdpMode::Hw:     return "HW";
    }
    return "?";
}

/* Single-syscall probe result (§5.19/§5.20). is_ours is the conjunction
 * of (mode == SKB) AND name == kOwnedProgName — both necessary. */
struct XdpProbe {
    std::uint32_t prog_id  = 0;
    XdpMode       mode     = XdpMode::None;
    bool          is_ours  = false;
    std::string   name;
};

/* Deterministic fd close for the prog fd opened by bpf_prog_get_fd_by_id.
 * Single-callsite helper kept out of raii.hpp per §5.19. */
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

std::string bpffs_dir_for(const std::string& iface)
{
    return std::string{XDPMF_BPFFS_ROOT} + "/" + iface;
}

/* Best-effort: remove maps and dir for a given iface. Errors are silenced
 * because callers use this both during rollback and during detach where
 * a partially-missing layout is acceptable. */
void bpffs_remove_iface(const std::string& iface) noexcept
{
    std::error_code ec;
    std::filesystem::remove_all(bpffs_dir_for(iface), ec);
}

/* §5.19 identity verification: fetch bpf_prog_info for prog_id, populate
 * `name`, return true iff the kernel-reported program name matches
 * kOwnedProgName. Fails closed: any errno on fd-get or info-get returns
 * false (the caller treats the prog as alien). `name` is filled with
 * whatever the kernel reported (possibly empty on failure) so the
 * §5.4-(c) stderr message can name the foreign program — even if its
 * name is the empty string. */
[[nodiscard]] bool fetch_prog_identity(std::uint32_t prog_id, std::string& name) noexcept
{
    name.clear();

    const int raw_fd = bpf_prog_get_fd_by_id(prog_id);
    if (raw_fd < 0) {
        // TOCTOU racing the kernel (prog detached between probe and fd-get),
        // or EPERM — fail closed: caller treats as alien.
        return false;
    }
    UniqueFd fd{raw_fd};

    // libbpf 1.1 ships `bpf_obj_get_info_by_fd` (the generic form);
    // `bpf_prog_get_info_by_fd` is a libbpf 1.2+ wrapper around the same
    // BPF_OBJ_GET_INFO_BY_FD command. Use the generic form for portability.
    struct bpf_prog_info info{};
    std::uint32_t info_len = sizeof(info);
    if (bpf_obj_get_info_by_fd(fd.get(), &info, &info_len) != 0) {
        return false;
    }

    // kernel-populated char[16], NUL-padded; compare bytes up to the first
    // NUL (not the full 16) per §5.19.
    const std::size_t n = ::strnlen(info.name, BPF_OBJ_NAME_LEN);
    name.assign(info.name, n);
    return std::string_view{name} == kOwnedProgName;
}

/* §5.4 + §5.19 + §5.20: single-syscall XDP probe across all modes, with
 * identity verification when a program is found. Return-by-value (POD-ish
 * — sizeof ~32B + small-string name). NEVER throws on the success path;
 * any kernel/libbpf failure during identity check downgrades the result
 * to `is_ours = false` (fail-closed). The only throw path is when
 * bpf_xdp_query() itself errors out — that's a real kernel failure, not
 * a "no program" signal, and must surface to the caller. */
[[nodiscard]] XdpProbe probe_attached_xdp(int ifindex)
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
        out.mode    = XdpMode::Hw;
    } else if (opts.drv_prog_id != 0) {
        out.prog_id = opts.drv_prog_id;
        out.mode    = XdpMode::Native;
    } else if (opts.skb_prog_id != 0) {
        out.prog_id = opts.skb_prog_id;
        out.mode    = XdpMode::Skb;
    } else {
        return out;  // (a)/(d): nothing attached.
    }

    // §5.19: a program in non-SKB mode cannot be ours (we only attach in
    // SKB per §5.6). Skip the identity probe — but still populate `name`
    // for the alien-refusal stderr message.
    const bool name_match = fetch_prog_identity(out.prog_id, out.name);
    out.is_ours = name_match && (out.mode == XdpMode::Skb);
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

/* mkdir -p semantics restricted to under XDPMF_BPFFS_ROOT. Throws on
 * actual permission failure (translated to LoaderError::Permission). */
void ensure_bpffs_dir(const std::string& path)
{
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    if (ec) {
        const auto code = (ec.value() == EPERM || ec.value() == EACCES)
                              ? LoaderError::Permission
                              : LoaderError::LoadFailed;
        throw_loader(code, std::format("mkdir {}: {}", path, ec.message()));
    }
}

}  // namespace

const std::error_category& loader_error_category() noexcept
{
    static const LoaderCategory cat;
    return cat;
}

std::uint32_t attach(const AttachConfig& cfg)
{
    const int ifindex = resolve_ifindex(cfg.iface, LoaderError::AttachFailed);

    // §5.4 4-state probe.
    const XdpProbe probe = probe_attached_xdp(ifindex);
    const std::string pin_dir = bpffs_dir_for(cfg.iface);
    const bool pin_dir_exists = std::filesystem::exists(pin_dir);

    if (probe.prog_id != 0) {
        if (probe.is_ours && pin_dir_exists) {
            // State (b): our prior instance — clean detach then proceed.
            const int rc = bpf_xdp_detach(ifindex, static_cast<int>(kXdpFlags), nullptr);
            if (rc < 0) {
                throw_loader(classify(rc, LoaderError::AttachFailed),
                             std::format("bpf_xdp_detach (idempotent cleanup): {}",
                                         std::strerror(-rc)));
            }
            bpffs_remove_iface(cfg.iface);
        } else {
            // State (c): alien program — refuse to clobber. Stderr message
            // MUST include the foreign prog_id (load-bearing assertion
            // target for T_ATTACH_ALIEN_REFUSAL, §6.9).
            throw_loader(
                LoaderError::AttachRefusedAlien,
                std::format("XDP prog id {} (mode {}, name '{}') already attached to {} "
                            "(not ours — refusing to clobber)",
                            probe.prog_id, to_string(probe.mode),
                            probe.name, cfg.iface));
        }
    } else if (pin_dir_exists) {
        // State (d): no XDP attached, but a stale pin dir survives from a
        // crash/SIGKILL between ensure_bpffs_dir and bpf_xdp_attach on a
        // previous run. Clean the orphan and fall through to fresh attach
        // (no new exit code per §4.1 MVP-1.1B note).
        bpffs_remove_iface(cfg.iface);
    }
    // State (a): nothing attached, no pin dir — straight to fresh attach.

    // Fresh bpffs layout. armed BpffsDir will rm -rf on any rollback path.
    ensure_bpffs_dir(pin_dir);
    BpffsDir dir_guard{pin_dir};
    dir_guard.arm();

    // Open + load skeleton with pin_root_path so LIBBPF_PIN_BY_NAME maps
    // resolve to /sys/fs/bpf/xdpmacfilter/<iface>/<mapname>.
    // Hand-init the opts struct (avoid LIBBPF_OPTS macro which expands to
    // C99 compound literals and GCC statement-expressions — both warn-on
    // under our -Wpedantic C++23 floor).
    bpf_object_open_opts open_opts{};
    open_opts.sz = sizeof(open_opts);
    open_opts.pin_root_path = pin_dir.c_str();

    BpfSkeleton skel{mac_filter_bpf__open_opts(&open_opts)};
    if (!skel) {
        const int e = errno;
        throw_loader(classify(-e, LoaderError::LoadFailed),
                     std::format("mac_filter_bpf__open_opts: {}", std::strerror(e)));
    }

    {
        const int rc = mac_filter_bpf__load(skel.get());
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("mac_filter_bpf__load: {}", std::strerror(-rc)));
        }
    }

    // Populate allow-list.
    const int allow_fd = bpf_map__fd(skel->maps.allowlist);
    if (allow_fd < 0) {
        throw_loader(LoaderError::LoadFailed, "allowlist map fd unavailable");
    }
    for (const xdpmf_mac& m : cfg.allow) {
        const std::uint8_t present = 1;
        const int rc = bpf_map_update_elem(allow_fd, &m, &present, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(allowlist): {}",
                                     std::strerror(-rc)));
        }
    }

    // Attach XDP in SKB (generic) mode.
    const int prog_fd = bpf_program__fd(skel->progs.mac_filter_prog);
    if (prog_fd < 0) {
        throw_loader(LoaderError::AttachFailed, "mac_filter_prog fd unavailable");
    }
    {
        const int rc = bpf_xdp_attach(ifindex, prog_fd,
                                      static_cast<int>(kXdpFlags), nullptr);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::AttachFailed),
                         std::format("bpf_xdp_attach: {}", std::strerror(-rc)));
        }
    }
    XdpAttachment xdp_guard{ifindex, kXdpFlags};

    // Query the just-assigned prog id for stdout reporting. After our own
    // attach the slot is definitively populated in SKB mode by ourselves.
    const XdpProbe after = probe_attached_xdp(ifindex);

    // Commit: kernel keeps the XDP slot (Decision §5.9); maps stay pinned.
    xdp_guard.release();
    dir_guard.release();
    return after.prog_id;
}

std::uint32_t detach(const std::string& iface)
{
    const int ifindex = resolve_ifindex(iface, LoaderError::DetachFailed);

    const XdpProbe probe = probe_attached_xdp(ifindex);
    const std::string pin_dir = bpffs_dir_for(iface);
    const bool pin_dir_exists = std::filesystem::exists(pin_dir);

    if (probe.prog_id == 0) {
        // Symmetric idempotency per MVP-1.1C §5.21 D4: detach is a no-op
        // when there's nothing to detach. Both (a) "truly nothing" and
        // (d) "orphan pin dir only" return 0 from this layer. main.cpp
        // gates its "detached prog id N" stdout on prog_id != 0, so the
        // caller-facing message comes from here for both branches.
        if (pin_dir_exists) {
            // (d) — orphan pin dir from a crash mid-attach. Clean it up.
            bpffs_remove_iface(iface);
            std::puts(std::format("removed orphan pin dir for {} (no XDP was attached)",
                                  iface).c_str());
            return 0;
        }
        // (a) — nothing attached and no pin dir. Loudly confirm the no-op
        // so an operator scripting against `xdpmacfilter detach` can tell
        // the difference between "we cleaned something" and "nothing was
        // there to clean".
        std::puts(std::format("no XDP attached to {} (no-op)", iface).c_str());
        return 0;
    }

    if (!probe.is_ours || !pin_dir_exists) {
        // State (c): refuse to detach an alien program. Pre-MVP-1.1B this
        // was triggered by `!pin_dir_exists` alone; now identity gate adds
        // the name-mismatch case.
        throw_loader(LoaderError::DetachFailed,
                     std::format("XDP prog id {} (mode {}, name '{}') on {} is not ours — "
                                 "refusing to detach",
                                 probe.prog_id, to_string(probe.mode),
                                 probe.name, iface));
    }

    // State (b): our prior instance.
    const int rc = bpf_xdp_detach(ifindex, static_cast<int>(kXdpFlags), nullptr);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::DetachFailed),
                     std::format("bpf_xdp_detach: {}", std::strerror(-rc)));
    }
    bpffs_remove_iface(iface);
    return probe.prog_id;
}

}  // namespace xdpmf
