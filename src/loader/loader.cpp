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
 * via the same fd-relative walk used by bpffs_remove_iface; XdpAttachment
 * unwinds; BpfSkeleton tears down libbpf state (and the kernel garbage-
 * collects unpinned programs/maps). On success the guards release().
 */
#include "loader.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <dirent.h>
#include <fcntl.h>           // O_PATH, O_DIRECTORY, O_NOFOLLOW, O_CLOEXEC, openat
#include <linux/if_link.h>   // XDP_FLAGS_SKB_MODE
#include <net/if.h>
#include <sys/stat.h>        // fstatat, mkdirat, S_IS*
#include <sys/types.h>
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
            case LoaderError::PathRefused:        return "bpffs path refused (symlink or non-directory at the bpffs root or per-iface entry)";
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

/* §5.22 Item 2 rollback RAII: removes the per-iface dir via the same
 * fd-relative walk used by bpffs_remove_iface(). Replaces the §5.17
 * BpffsDir wrapper for new code paths so rollback inherits the symlink
 * defense (raii.hpp BpffsDir stays as-is per §5.22 impl-surface table —
 * single-callsite-rule, BpffsRootFd is not exported). */
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
[[nodiscard]] BpfSkeleton load_skeleton()
{
    BpfSkeleton skel{mac_filter_bpf__open()};
    if (!skel) {
        const int e = errno;
        throw_loader(classify(-e, LoaderError::LoadFailed),
                     std::format("mac_filter_bpf__open: {}", std::strerror(e)));
    }
    if (bpf_map__set_pin_path(skel->maps.allowlist, nullptr) != 0
        || bpf_map__set_pin_path(skel->maps.stats,    nullptr) != 0) {
        const int e = errno;
        throw_loader(classify(-e, LoaderError::LoadFailed),
                     std::format("bpf_map__set_pin_path(clear): {}",
                                 std::strerror(e)));
    }
    const int rc = mac_filter_bpf__load(skel.get());
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::LoadFailed),
                     std::format("mac_filter_bpf__load: {}", std::strerror(-rc)));
    }
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
    const int ifindex = resolve_ifindex(cfg.iface, LoaderError::AttachFailed);

    // §5.22 Item 2: open bpffs root with O_PATH|O_NOFOLLOW. All subsequent
    // bpffs ops are fd-relative against root.fd() — symlink at the root
    // can't be substituted post-open.
    BpffsRootFd root{};

    // §5.22 Q1 Option E: load skeleton FIRST so we can compute self_tag
    // before the probe needs it. On a state-(c) refusal below, the
    // BpfSkeleton dtor unwinds the kernel-side program+maps (nothing is
    // pinned to disk yet — pinning happens after the state machine).
    BpfSkeleton skel = load_skeleton();
    const TagArray self_tag = capture_self_tag(skel);

    // §5.4 + §5.19 + §5.20 + §5.22 4-state probe with name+tag identity.
    const XdpProbe probe = probe_attached_xdp(ifindex, self_tag);
    const bool pin_dir_exists = iface_entry_is_real_dir(root, cfg.iface);

    if (probe.prog_id != 0) {
        if (probe.is_ours && pin_dir_exists) {
            // State (b): our prior instance — clean detach then proceed.
            // §5.23 Q1: detach in the probed mode (not hardcoded SKB), so we
            // can reload an attach made in any mode (native/offload too).
            const int rc = bpf_xdp_detach(ifindex,
                                          probed_mode_to_flags(probe.mode), nullptr);
            if (rc < 0) {
                throw_loader(classify(rc, LoaderError::AttachFailed),
                             std::format("bpf_xdp_detach (idempotent cleanup): {}",
                                         std::strerror(-rc)));
            }
            bpffs_remove_iface(root, cfg.iface);
        } else {
            // State (c): alien — refuse. Sub-case dispatch (name vs tag)
            // happens inside throw_alien_refused.
            throw_alien_refused(probe, cfg.iface);
        }
    } else if (pin_dir_exists) {
        // State (d): no XDP attached, but a stale pin dir survives from a
        // crash/SIGKILL between mkdirat and bpf_xdp_attach on a previous
        // run. Clean the orphan and fall through to fresh attach.
        bpffs_remove_iface(root, cfg.iface);
    }
    // State (a): nothing attached, no pin dir — straight to fresh attach.

    // Fresh bpffs layout (fd-relative). Arm the rollback guard before any
    // operation that might throw (libbpf pin, allowlist populate, attach).
    ensure_iface_dir(root, cfg.iface);
    IfaceDirGuard dir_guard{root, cfg.iface};
    dir_guard.arm();

    // §5.22 Q1 Option E: maps still need pinning (LIBBPF_PIN_BY_NAME) but
    // since we loaded without pin_root_path, do it manually now that the
    // dir exists. The TOCTOU window between our mkdirat and libbpf's
    // path-based bpf_obj_pin is explicit OOS per §5.22 Q2 Maximum.
    const std::string pin_dir = bpffs_dir_for(cfg.iface);
    {
        const std::string p = pin_dir + "/" XDPMF_MAP_ALLOWLIST_NAME;
        const int rc = bpf_map__pin(skel->maps.allowlist, p.c_str());
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map__pin({}): {}", p, std::strerror(-rc)));
        }
    }
    {
        const std::string p = pin_dir + "/" XDPMF_MAP_STATS_NAME;
        const int rc = bpf_map__pin(skel->maps.stats, p.c_str());
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map__pin({}): {}", p, std::strerror(-rc)));
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

    // §5.23 Item 2: attach in the operator-selected XDP mode (default
    // generic per AttachConfig.mode initializer; preserves MVP-1 baseline).
    const int prog_fd = bpf_program__fd(skel->progs.mac_filter_prog);
    if (prog_fd < 0) {
        throw_loader(LoaderError::AttachFailed, "mac_filter_prog fd unavailable");
    }
    const std::uint32_t attach_flags = mode_to_flags(cfg.mode);
    {
        const int rc = bpf_xdp_attach(ifindex, prog_fd, attach_flags, nullptr);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::AttachFailed),
                         std::format("bpf_xdp_attach (mode={}): {}",
                                     to_string(cfg.mode), std::strerror(-rc)));
        }
    }
    XdpAttachment xdp_guard{ifindex, attach_flags};

    // Query the just-assigned prog id for stdout reporting. We re-use the
    // probe helper (passing self_tag for the is_ours predicate, though we
    // ignore its result here — we only want the prog id).
    const XdpProbe after = probe_attached_xdp(ifindex, self_tag);

    // Commit: kernel keeps the XDP slot (Decision §5.9); maps stay pinned.
    xdp_guard.release();
    dir_guard.release();
    return after.prog_id;
}

std::uint32_t detach(const std::string& iface)
{
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

    // State (b): our prior instance. §5.23 Q1 Option A: detach in the
    // §5.20-probed mode (not hardcoded SKB) — operator did not supply
    // --mode on detach; the kernel told us which slot to detach.
    const int rc = bpf_xdp_detach(ifindex, probed_mode_to_flags(probe.mode), nullptr);
    if (rc < 0) {
        throw_loader(classify(rc, LoaderError::DetachFailed),
                     std::format("bpf_xdp_detach: {}", std::strerror(-rc)));
    }
    bpffs_remove_iface(root, iface);
    return probe.prog_id;
}

}  // namespace xdpmf
