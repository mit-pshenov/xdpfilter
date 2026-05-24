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
#include "apply_internal.hpp"
#include "config.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>           // §5.24: std::getenv for XDPMF_BPF_OBJECT_PATH
#include <cstring>
#include <format>
#include <fstream>           // §5.24: read override BPF object from path
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

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
 * to pre-§5.24 behaviour). */
constexpr std::string_view kBpfObjectPathEnv{"XDPMF_BPF_OBJECT_PATH"};

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
/* §5.24 Q4 fixture-path override: read the BPF object ELF from `path` into
 * an in-memory buffer, allocate the typed skeleton struct manually (mirrors
 * mac_filter_bpf__open_opts), substitute s->data/s->data_sz with the file
 * bytes (instead of the embedded mac_filter_bpf__elf_bytes), then open via
 * bpf_object__open_skeleton. libbpf's bpf_object__open_mem (under the hood)
 * completes ELF parsing before returning, so the local buffer's lifetime
 * only needs to cover this call. Returns an owning BpfSkeleton.
 *
 * Testing-only path — undocumented in --help per §7 Robust OOS. */
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

/* Open (no load) — used by both the direct-load path and the reuse_fd
 * path. Clears LIBBPF_PIN_BY_NAME pin paths for all 7 maps so libbpf's
 * load() does NOT auto-pin (we pin/reuse manually after the §5.4 state
 * machine). */
[[nodiscard]] BpfSkeleton open_skeleton_only()
{
    const char* env_path = std::getenv(kBpfObjectPathEnv.data());
    const char* obj_path = (env_path != nullptr && *env_path != '\0') ? env_path : nullptr;

    BpfSkeleton skel;
    if (obj_path != nullptr) {
        skel = open_skeleton_from_path(obj_path);
    } else {
        skel = BpfSkeleton{mac_filter_bpf__open()};
        if (!skel) {
            const int e = errno;
            throw_loader(classify(-e, LoaderError::LoadFailed),
                         std::format("mac_filter_bpf__open: {}", std::strerror(e)));
        }
    }
    bpf_map* const pinned_maps[] = {
        skel->maps.allowlist,      // legacy template — never pinned at runtime
        skel->maps.allowlist_a,    // §5.26 Q6 inner slot 0
        skel->maps.allowlist_b,    // §5.26 Q6 inner slot 1
        skel->maps.rulesets,       // §5.26 Q6 outer MAP_OF_MAPS
        skel->maps.active_idx,     // §5.26 Q6 active index
        skel->maps.defaults,       // §5.26 Q6 per-slot default action
        skel->maps.stats,
    };
    for (bpf_map* m : pinned_maps) {
        if (bpf_map__set_pin_path(m, nullptr) != 0) {
            const int e = errno;
            throw_loader(classify(-e, LoaderError::LoadFailed),
                         std::format("bpf_map__set_pin_path(clear): {}",
                                     std::strerror(e)));
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
 * Single-line, fixed format, audit-grep-friendly. */
void log_trust_model(TrustModel m) noexcept
{
    std::fprintf(stderr, "xdpmacfilter: trust_model=%s\n",
                 std::string{to_string(m)}.c_str());
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

/* §5.26 Q2 inner-slot population: bulk-clear the inactive inner map then
 * insert the new pass_macs presence markers. Caller passes the FD of the
 * inactive inner allowlist (allowlist_a or allowlist_b). */
void populate_inner_slot(int inner_fd, const std::vector<xdpmf_mac>& pass_macs)
{
    // Bulk-clear: iterate keys via bpf_map_get_next_key and delete each.
    // The map is small (≤ 64 entries) so cost is bounded.
    xdpmf_mac prev{};
    xdpmf_mac cur{};
    bool      have_prev = false;
    while (true) {
        const int rc = bpf_map_get_next_key(inner_fd,
                                            have_prev ? &prev : nullptr,
                                            &cur);
        if (rc != 0) {
            if (-rc == ENOENT) break;
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_get_next_key(inner): {}",
                                     std::strerror(-rc)));
        }
        const int drc = bpf_map_delete_elem(inner_fd, &cur);
        if (drc != 0 && -drc != ENOENT) {
            throw_loader(classify(drc, LoaderError::LoadFailed),
                         std::format("bpf_map_delete_elem(inner): {}",
                                     std::strerror(-drc)));
        }
        prev      = cur;
        have_prev = true;
    }
    for (const xdpmf_mac& m : pass_macs) {
        const std::uint8_t present = 1;
        const int rc = bpf_map_update_elem(inner_fd, &m, &present, BPF_ANY);
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map_update_elem(inner): {}",
                                     std::strerror(-rc)));
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

/* Extract the inner-allowlist contents from the validated Config: only
 * rules with action==Pass + a present mac contribute. Drop-action rules
 * are accepted-but-no-op in cycle 1 (the global default_action carries
 * them) per design §5.26 schema rule 4. Dedup preserved by insertion-order. */
[[nodiscard]] std::vector<xdpmf_mac> extract_pass_macs(const Config& c)
{
    std::vector<xdpmf_mac> out;
    out.reserve(c.rules.size());
    for (const Rule& r : c.rules) {
        if (r.action != RuleAction::Pass) continue;
        if (!r.match.mac.has_value())    continue;
        const xdpmf_mac& m = *r.match.mac;
        const bool already = std::any_of(
            out.begin(), out.end(),
            [&](const xdpmf_mac& e) {
                return std::memcmp(e.octets, m.octets, sizeof(m.octets)) == 0;
            });
        if (!already) out.push_back(m);
    }
    return out;
}

/* §5.26 + EDIT-1 atomic apply (single source of truth for the swap flow):
 * see design §5.26 attach() flow update + Phase B EDIT-1 internal-helper
 * contract. Both loader::attach() and apply::apply_config_inmemory() route
 * through here so the active_idx-flip + ruleset/defaults population logic
 * lives in exactly ONE place. */
std::uint32_t apply_request(const ApplyRequest& req)
{
    const std::vector<xdpmf_mac> deduped       = extract_pass_macs(req.config);
    const DefaultAction          default_action = req.config.default_action;

    if (deduped.size() > XDPMF_ALLOWLIST_MAX) {
        throw_loader(LoaderError::LoadFailed,
                     std::format("apply: pass-rule count {} exceeds XDPMF_ALLOWLIST_MAX={}",
                                 deduped.size(), XDPMF_ALLOWLIST_MAX));
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
            std::fprintf(stderr,
                         "xdpmacfilter: trust_model=fleet — bypassing alien-program check; "
                         "replacing prog id %u (mode=%s, name='%s')\n",
                         probe.prog_id,
                         std::string{to_string(probe.mode)}.c_str(),
                         probe.name.c_str());
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

        struct ReuseSpec { bpf_map* map; const char* name; };
        const ReuseSpec reuse_specs[] = {
            { skel->maps.allowlist_a, XDPMF_MAP_INNER_A_NAME        },
            { skel->maps.allowlist_b, XDPMF_MAP_INNER_B_NAME        },
            { skel->maps.rulesets,    XDPMF_MAP_RULESETS_OUTER_NAME },
            { skel->maps.active_idx,  XDPMF_MAP_ACTIVE_IDX_NAME     },
            { skel->maps.defaults,    XDPMF_MAP_DEFAULTS_NAME       },
            { skel->maps.stats,       XDPMF_MAP_STATS_NAME          },
        };
        for (const ReuseSpec& r : reuse_specs) {
            const std::string p = pin_dir + "/" + r.name;
            const int fd = bpf_obj_get(p.c_str());
            if (fd < 0) {
                const int e = errno;
                throw_loader(classify(-e, LoaderError::LoadFailed),
                             std::format("bpf_obj_get (reuse '{}'): {}",
                                         p, std::strerror(e)));
            }
            UniqueFd dup_holder{fd};
            if (bpf_map__reuse_fd(r.map, dup_holder.get()) != 0) {
                const int e = errno;
                throw_loader(classify(-e, LoaderError::LoadFailed),
                             std::format("bpf_map__reuse_fd({}): {}",
                                         r.name, std::strerror(e)));
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

        // Populate the INACTIVE slot via the (reused) inner-map fds.
        {
            bpf_map* inactive_inner = (inactive == 0)
                                          ? skel->maps.allowlist_a
                                          : skel->maps.allowlist_b;
            const int inactive_inner_fd = bpf_map__fd(inactive_inner);
            if (inactive_inner_fd < 0) {
                throw_loader(LoaderError::LoadFailed,
                             "inactive inner fd unavailable (reattach)");
            }
            populate_inner_slot(inactive_inner_fd, deduped);
        }
        {
            const int defaults_fd = bpf_map__fd(skel->maps.defaults);
            if (defaults_fd < 0) {
                throw_loader(LoaderError::LoadFailed,
                             "defaults fd unavailable (reattach)");
            }
            write_default_slot(defaults_fd, inactive, default_action);
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

        std::fprintf(stderr,
                     "xdpmacfilter: replacing existing program on %s\n",
                     req.iface.c_str());

        const XdpProbe after_probe = probe_attached_xdp(ifindex, self_tag);
        return after_probe.prog_id;
    }

    // FRESH ATTACH path (state a / state d / state c-fleet).
    struct PinSpec { bpf_map* map; const char* name; };
    const PinSpec pin_specs[] = {
        { skel->maps.allowlist_a, XDPMF_MAP_INNER_A_NAME        },
        { skel->maps.allowlist_b, XDPMF_MAP_INNER_B_NAME        },
        { skel->maps.rulesets,    XDPMF_MAP_RULESETS_OUTER_NAME },
        { skel->maps.active_idx,  XDPMF_MAP_ACTIVE_IDX_NAME     },
        { skel->maps.defaults,    XDPMF_MAP_DEFAULTS_NAME       },
        { skel->maps.stats,       XDPMF_MAP_STATS_NAME          },
    };
    for (const PinSpec& s : pin_specs) {
        const std::string p = pin_dir + "/" + s.name;
        const int rc = bpf_map__pin(s.map, p.c_str());
        if (rc < 0) {
            throw_loader(classify(rc, LoaderError::LoadFailed),
                         std::format("bpf_map__pin({}): {}", p, std::strerror(-rc)));
        }
    }

    // §5.26 backward-compat: pin allowlist_a ALSO at the legacy
    // ${PIN_DIR}/allowlist path so MVP-2-era ctests that grep for pin
    // existence (T_LOAD_ATTACH, T_ATTACH_TAG_MISMATCH, T_MODE_GENERIC_DEFAULT,
    // T_BPFFS_ROOT_SYMLINK) pass byte-equivalent (PI-6 invariant). The
    // legacy alias is a separate bpffs dentry wrapping the same kernel-side
    // inner-map; tests only check existence, not contents.
    {
        const int inner_a_fd = bpf_map__fd(skel->maps.allowlist_a);
        if (inner_a_fd < 0) {
            throw_loader(LoaderError::LoadFailed, "allowlist_a fd unavailable (legacy alias)");
        }
        const std::string legacy = pin_dir + "/" XDPMF_MAP_ALLOWLIST_NAME;
        if (bpf_obj_pin(inner_a_fd, legacy.c_str()) < 0) {
            const int e = errno;
            throw_loader(classify(-e, LoaderError::LoadFailed),
                         std::format("bpf_obj_pin (legacy {}): {}", legacy, std::strerror(e)));
        }
    }

    // Fresh attach: populate slot 0 (the initial active slot).
    const int active_idx_fd = bpf_map__fd(skel->maps.active_idx);
    if (active_idx_fd < 0) {
        throw_loader(LoaderError::LoadFailed, "active_idx map fd unavailable");
    }
    {
        bpf_map* inner_map = skel->maps.allowlist_a;
        const int inner_fd = bpf_map__fd(inner_map);
        if (inner_fd < 0) {
            throw_loader(LoaderError::LoadFailed, "inner-map fd unavailable");
        }
        populate_inner_slot(inner_fd, deduped);
    }
    {
        const int defaults_fd = bpf_map__fd(skel->maps.defaults);
        if (defaults_fd < 0) {
            throw_loader(LoaderError::LoadFailed, "defaults map fd unavailable");
        }
        write_default_slot(defaults_fd, 0u, default_action);
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

    const XdpProbe after = probe_attached_xdp(ifindex, self_tag);
    dir_guard.release();
    return after.prog_id;
}

}  // namespace internal

}  // namespace xdpmf
