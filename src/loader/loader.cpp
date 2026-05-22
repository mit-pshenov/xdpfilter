/*
 * loader.cpp — XDP attach/detach control plane built on libbpf.
 *
 * Attach sequence (design §5.4 hybrid idempotent reload):
 *   1. Resolve <iface> → ifindex.
 *   2. Query existing XDP prog id on iface.
 *      - If none: fresh attach.
 *      - If present and bpffs dir /sys/fs/bpf/xdpmacfilter/<iface>/ exists:
 *        "ours" — detach, unpin, remove dir, then fresh attach.
 *      - If present and bpffs dir absent: "alien" — refuse with error 4.
 *   3. Create per-iface bpffs dir (and parent if missing).
 *   4. Open skeleton with pin_root_path = per-iface dir; load auto-pins
 *      maps tagged LIBBPF_PIN_BY_NAME.
 *   5. Populate allow-list map from cfg.allow.
 *   6. Attach XDP in SKB (generic) mode (Decision §5.6).
 *
 * Rollback on any throw: XdpAttachment unwinds, BpffsDir removes the
 * pinned dir, BpfSkeleton tears down libbpf state. On success all three
 * are release()'d — the kernel keeps the XDP slot via its netif ref.
 */
#include "loader.hpp"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <format>
#include <string>
#include <system_error>

#include <linux/if_link.h>  // XDP_FLAGS_SKB_MODE
#include <net/if.h>
#include <sys/stat.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common/mac_filter.h"
#include "raii.hpp"

namespace xdpmf {

namespace {

constexpr std::uint32_t kXdpFlags = XDP_FLAGS_SKB_MODE;

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

/* libbpf default log handler is noisy on stderr; we keep it (operators
 * benefit from verifier output). */
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

/* Query the prog id currently attached to ifindex in SKB mode.
 * Returns 0 if nothing is attached. Throws system_error on real error. */
[[nodiscard]] std::uint32_t query_attached_prog_id(int ifindex)
{
    std::uint32_t prog_id = 0;
    const int rc = bpf_xdp_query_id(ifindex, static_cast<int>(kXdpFlags), &prog_id);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::AttachFailed),
                     std::format("bpf_xdp_query_id: {}", std::strerror(-rc)));
    }
    return prog_id;
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

    // §5.4 ownership probe.
    const std::uint32_t existing = query_attached_prog_id(ifindex);
    const std::string pin_dir = bpffs_dir_for(cfg.iface);
    const bool pin_dir_exists = std::filesystem::exists(pin_dir);

    if (existing != 0) {
        if (!pin_dir_exists) {
            throw_loader(LoaderError::AttachRefusedAlien,
                         std::format("XDP prog id {} already attached to {} "
                                     "(not ours — refusing to clobber)",
                                     existing, cfg.iface));
        }
        // "Ours" — clean detach then proceed.
        const int rc = bpf_xdp_detach(ifindex, static_cast<int>(kXdpFlags), nullptr);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::AttachFailed),
                         std::format("bpf_xdp_detach (idempotent cleanup): {}",
                                     std::strerror(-rc)));
        }
        bpffs_remove_iface(cfg.iface);
    }

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

    // Query the just-assigned prog id for stdout reporting.
    const std::uint32_t new_prog_id = query_attached_prog_id(ifindex);

    // Commit: kernel keeps the XDP slot (Decision §5.9); maps stay pinned.
    xdp_guard.release();
    dir_guard.release();
    return new_prog_id;
}

std::uint32_t detach(const std::string& iface)
{
    const int ifindex = resolve_ifindex(iface, LoaderError::DetachFailed);

    const std::uint32_t prog_id = query_attached_prog_id(ifindex);
    if (prog_id == 0) {
        throw_loader(LoaderError::DetachFailed,
                     std::format("nothing attached to {}", iface));
    }

    const std::string pin_dir = bpffs_dir_for(iface);
    if (!std::filesystem::exists(pin_dir)) {
        throw_loader(LoaderError::DetachFailed,
                     std::format("no bpffs dir at {} — not ours, refusing detach",
                                 pin_dir));
    }

    const int rc = bpf_xdp_detach(ifindex, static_cast<int>(kXdpFlags), nullptr);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::DetachFailed),
                     std::format("bpf_xdp_detach: {}", std::strerror(-rc)));
    }
    bpffs_remove_iface(iface);
    return prog_id;
}

}  // namespace xdpmf
