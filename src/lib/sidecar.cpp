/*
 * sidecar.cpp — `rule_index.json` writer impl (§5.31 MVP-3.4b;
 * §5.36 MVP-3.4e KC-3 sidecar limb).
 *
 * Roll-your-own JSON emitter per D-3.4b-10 (no nlohmann/json build dep).
 * The schema (Q2 S1 defaults-only + D-3.4b-20 one-rule-per-line shape) has
 * exactly 3 top-level fields + a homogeneous `rules` array of 3-field
 * objects — well-bounded; a serializer is a few-dozen LOC. Output is
 * valid JSON (jq accepts it) AND line-oriented (the exporter regex
 * matches per-rule lines independently).
 *
 * Atomic write: write-to-<path>.tmp → fsync(fd) → close → rename(tmp, path).
 * Failures are NEVER fatal — log a single stderr WARN and return silently
 * (PI-32-3.4b PRESERVED — sidecar never throws).
 *
 * §5.36 (MVP-3.4e) hardening: ALL filesystem ops route through the
 * `SidecarRootFd` (O_PATH|O_DIRECTORY|O_NOFOLLOW fd to XDPMF_SIDECAR_ROOT)
 * via fd-relative mkdirat / fstatat / openat / renameat. Mirrors the
 * §5.22 BpffsRootFd discipline. Per-iface symlink at /run/xdpmacfilter/<iface>
 * triggers NEW `sidecar.warn.iface_dir_symlink` event + return (HG-3.4e-4 —
 * WARN + skip; PI-32-3.4b PRESERVED).
 */
#include "sidecar.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <format>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/escape_util.hpp"  // §5.37 (MVP-3.4f) escape_json + format_timestamp_utc
#include "common/logger.hpp"       // §5.32 (MVP-3.5) structured-logging surface
#include "common/mac_filter.h"     // xdpmf_mac, xdpmf_cidr_v4

namespace xdpmf::sidecar {

namespace {

/* Format an xdpmf_mac as the standard six-octet lowercase hex with `:`
 * separators (`aa:bb:cc:dd:ee:ff`). Matches §5.26 / §5.27 / §5.28 fleet
 * docs convention (Ansible Jinja emits the same shape) so operators see
 * the SAME bytes here as in their source YAML / inventory. */
[[nodiscard]] std::string format_mac(const xdpmf_mac& m)
{
    return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                       m.octets[0], m.octets[1], m.octets[2],
                       m.octets[3], m.octets[4], m.octets[5]);
}

/* Format an xdpmf_cidr_v4 (addr is network byte order) as dotted-quad
 * `A.B.C.D/N`. PI-15 / PI-17: byte-equivalent to the operator's source
 * YAML schema since cidr.cpp validates and stores in canonical form. */
[[nodiscard]] std::string format_cidr(const xdpmf_cidr_v4& c)
{
    const unsigned int a = (c.addr >>  0) & 0xFFu;
    const unsigned int b = (c.addr >>  8) & 0xFFu;
    const unsigned int d = (c.addr >> 16) & 0xFFu;
    const unsigned int e = (c.addr >> 24) & 0xFFu;
    // §5.43: copy the PACKED `prefixlen` field to an aligned local before
    // formatting — std::format binds a `const unsigned int&`, which is UB
    // (misaligned reference bind, UBSan) when bound directly to a packed
    // member. a/b/d/e are already such aligned local copies.
    const unsigned int plen = c.prefixlen;
    return std::format("{}.{}.{}.{}/{}", a, b, d, e, plen);
}

/* §5.37 (MVP-3.4f) D-3.4f-1: `format_timestamp_utc` + `json_escape`
 * extracted to src/common/escape_util.{hpp,cpp}. D-3.5-2's "duplicate"
 * directive SUPERSEDED by the rule-of-three escape valve. Call-sites
 * below use `xdpmf::escape_util::format_timestamp_utc` /
 * `xdpmf::escape_util::escape_json`. */

/* Build the rule_index.json body for `cfg` under `iface`. Stable
 * source-order (matches Config::rules vector order). Per D-3.4b-20:
 * one rule object per line so the exporter's line-oriented regex can
 * extract each independently without a full JSON parser. */
[[nodiscard]] std::string build_body(std::string_view iface, const Config& cfg)
{
    std::string body;
    body.reserve(256 + cfg.rules.size() * 96);

    body.append("{\n");
    body.append(std::format("  \"iface\": \"{}\",\n",
                            xdpmf::escape_util::escape_json(iface)));
    /* §5.43 (MVP-4.3) C1 + PI-mvp-4.3-SIDECAR: emit schema_version 2 (M.1
     * cutover); the loader only ever applies v2 configs (config.cpp rejects
     * v1/absent), so cfg.schema_version is always 2 here. */
    body.append("  \"schema_version\": 2,\n");
    body.append(std::format("  \"applied_at\": \"{}\",\n",
                            xdpmf::escape_util::format_timestamp_utc()));
    body.append("  \"rules\": [");

    bool first = true;
    for (const Rule& r : cfg.rules) {
        body.append(first ? "\n" : ",\n");
        first = false;

        const char* action_str = (r.action == RuleAction::Pass) ? "pass" : "drop";

        /* Build the `match` sub-object inline so the rule lives on one line
         * (one-rule-per-line per D-3.4b-20). §5.43 (MVP-4.3) C1: the v2
         * match grammar is at-least-one-of {dst_cidr, src_cidr} (guaranteed
         * by config.cpp validation); emit the explicit `dst_cidr` / `src_cidr`
         * match-kinds (PI-mvp-4.3-SIDECAR). The `mac` branch is dead-but-
         * harmless under v2 (config.cpp rejects `mac` at parse — HG-mvp-4.3-2),
         * retained so the MAC-axis slice (mvp-4.5) re-activates it cleanly. */
        std::string parts;
        bool match_first = true;
        const auto append_kind = [&](const char* key, const std::string& value) {
            if (!match_first) parts.append(", ");
            parts.append(std::format("\"{}\": \"{}\"", key, value));
            match_first = false;
        };
        if (r.match.mac.has_value()) {        // dead under v2; live again mvp-4.5
            append_kind("mac", format_mac(*r.match.mac));
        }
        if (r.match.dst_cidr.has_value()) {
            append_kind("dst_cidr", format_cidr(*r.match.dst_cidr));
        }
        if (r.match.src_cidr.has_value()) {
            append_kind("src_cidr", format_cidr(*r.match.src_cidr));
        }
        /* §5.44 (MVP-4.4) PI-mvp-4.4-SIDECAR: emit the proto axis as a name
         * for the well-known protocols {tcp,udp,icmp} (matching the config
         * grammar), else the numeric string. */
        if (r.match.protocol.has_value()) {
            const std::uint8_t p = *r.match.protocol;
            const char* name = (p == 6)  ? "tcp"
                             : (p == 17) ? "udp"
                             : (p == 1)  ? "icmp"
                             : nullptr;
            append_kind("protocol",
                        name ? std::string{name} : std::to_string(p));
        }
        /* §5.44 dst_port: a single port (lo==hi) emits "p"; a range emits
         * "lo-hi" (matching the config grammar). */
        if (r.match.dst_port.has_value()) {
            const PortRange& pr = *r.match.dst_port;
            append_kind("dst_port",
                        (pr.lo == pr.hi)
                            ? std::to_string(pr.lo)
                            : std::format("{}-{}", pr.lo, pr.hi));
        }
        const std::string match = std::format("{{{}}}", parts);

        body.append(std::format(
            "    {{\"rule_id\": {}, \"match\": {}, \"action\": \"{}\"}}",
            r.id, match, action_str));
    }
    body.append(first ? "]\n" : "\n  ]\n");
    body.append("}\n");
    return body;
}

/* §5.36 (MVP-3.4e) D-3.4e-4 / Q4.A2 — RAII for an O_PATH|O_DIRECTORY|
 * O_NOFOLLOW fd to XDPMF_SIDECAR_ROOT. Mirrors loader.cpp::BpffsRootFd's
 * shape (§5.22 single-callsite anon-namespace discipline — NOT exported
 * to a header). DOES NOT throw — sidecar-never-throws contract (PI-32-3.4b);
 * caller inspects `state()` and emits the appropriate sidecar.warn.*
 * event. ENOENT triggers an idempotent mkdir + reopen retry (matches
 * BpffsRootFd ctor).
 *
 * State enum maps 1:1 to sidecar.warn.* event names (D-3.4e-5 — event
 * names PRESERVED from §5.31 EDIT-1 for log-shipping pipeline stability):
 *   Ok          → caller proceeds
 *   RootSymlink → emit sidecar.warn.root_symlink (errno ELOOP)
 *   RootNotDir  → emit sidecar.warn.root_not_dir (errno ENOTDIR after
 *                 mkdir didn't succeed; fstatat confirms not-symlink)
 *   OpenFailed  → emit sidecar.warn.lstat_failed (catch-all for permission/
 *                 other errno — event NAME preserved per D-3.4e-5 even
 *                 though the trigger is no longer lstat itself)
 */
class SidecarRootFd {
public:
    enum class State : std::uint8_t {
        Ok,
        RootSymlink,
        RootNotDir,
        OpenFailed,
    };

    explicit SidecarRootFd(const char* root_path) noexcept
    {
        auto try_open = [&]() -> int {
            return ::open(root_path,
                          O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        };

        int fd = try_open();
        if (fd < 0 && errno == ENOENT) {
            // Idempotent root mkdir then retry — mirrors BpffsRootFd.
            if (::mkdir(root_path, 0755) != 0 && errno != EEXIST) {
                error_errno_ = errno;
                state_       = State::OpenFailed;
                return;
            }
            fd = try_open();
        }
        if (fd < 0) {
            const int e = errno;
            error_errno_ = e;
            if (e == ELOOP) {
                state_ = State::RootSymlink;
            } else if (e == ENOTDIR) {
                // Disambiguate symlink-to-non-dir vs regular-file-at-root via
                // lstat; in either case sidecar's contract is "refuse + WARN".
                // Symlink targets are treated as root_symlink for operator
                // clarity (the literal symlink IS what we refuse to follow).
                struct stat st{};
                const bool is_link = (::lstat(root_path, &st) == 0)
                                     && S_ISLNK(st.st_mode);
                state_ = is_link ? State::RootSymlink : State::RootNotDir;
            } else {
                state_ = State::OpenFailed;
            }
            return;
        }
        fd_    = fd;
        state_ = State::Ok;
    }

    ~SidecarRootFd() noexcept
    {
        if (fd_ >= 0) {
            (void)::close(fd_);
        }
    }

    SidecarRootFd(const SidecarRootFd&)            = delete;
    SidecarRootFd& operator=(const SidecarRootFd&) = delete;

    [[nodiscard]] int   fd()           const noexcept { return fd_; }
    [[nodiscard]] State state()        const noexcept { return state_; }
    [[nodiscard]] int   error_errno()  const noexcept { return error_errno_; }

private:
    int   fd_           = -1;
    State state_        = State::OpenFailed;
    int   error_errno_  = 0;
};

/* §5.36 (MVP-3.4e) fd-relative atomic write: openat(root, "<iface>/...",
 * O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC) → write → fsync → close →
 * renameat(root, ".tmp", root, ".json"). The path components passed to
 * openat / renameat are bound to root.fd() — symlinks at any depth along
 * the path are NOT followed (O_NOFOLLOW is per-component? No — it applies
 * to the trailing component only, but root_fd is already O_PATH on the
 * real-dir root, so the only attacker-controlled component left is the
 * iface name itself, which the caller has already verified via fstatat).
 *
 * Returns 0 on success; positive errno on failure (caller emits
 * sidecar.warn.write_failed). The tmp path is unlinkat'd on any failure
 * after the open so a future apply doesn't trip on a stale .tmp. */
[[nodiscard]] int atomic_write_file_at(int                root_fd,
                                        const std::string& iface_str,
                                        std::string_view   body)
{
    const std::string tmp_rel   = iface_str + "/rule_index.json.tmp";
    const std::string final_rel = iface_str + "/rule_index.json";

    /* O_NOFOLLOW: if rule_index.json.tmp happens to exist as a symlink at
     * the per-iface dir, the open refuses (ELOOP). 0644: world-readable
     * (CAP_BPF-only exporter reads it). */
    const int fd = ::openat(root_fd, tmp_rel.c_str(),
                             O_WRONLY | O_CREAT | O_TRUNC
                             | O_NOFOLLOW | O_CLOEXEC,
                             0644);
    if (fd < 0) {
        return errno;
    }

    /* Bounded write loop (defense against EINTR). The body is small
     * (~few KiB worst-case for 64 rules) so a single ::write usually
     * suffices, but EINTR-tolerance is cheap and correct. */
    const char* p   = body.data();
    std::size_t rem = body.size();
    while (rem > 0) {
        const ssize_t n = ::write(fd, p, rem);
        if (n < 0) {
            if (errno == EINTR) continue;
            const int e = errno;
            (void)::close(fd);
            (void)::unlinkat(root_fd, tmp_rel.c_str(), 0);
            return e;
        }
        p   += n;
        rem -= static_cast<std::size_t>(n);
    }

    if (::fsync(fd) != 0) {
        const int e = errno;
        (void)::close(fd);
        (void)::unlinkat(root_fd, tmp_rel.c_str(), 0);
        return e;
    }
    if (::close(fd) != 0) {
        const int e = errno;
        (void)::unlinkat(root_fd, tmp_rel.c_str(), 0);
        return e;
    }
    if (::renameat(root_fd, tmp_rel.c_str(), root_fd, final_rel.c_str()) != 0) {
        const int e = errno;
        (void)::unlinkat(root_fd, tmp_rel.c_str(), 0);
        return e;
    }
    return 0;
}

}  // namespace

void write_rule_index(std::string_view iface,
                      std::string_view sidecar_root,
                      const Config&    cfg) noexcept
{
    try {
        std::string root{sidecar_root};
        if (!root.empty() && root.back() == '/') {
            root.pop_back();
        }

        /* §5.36 D-3.4e-4: open SIDECAR_ROOT with O_PATH|O_DIRECTORY|
         * O_NOFOLLOW. Upgrades §5.31 EDIT-1's path-based lstat to the
         * §5.22-symmetric fd-relative discipline. Event names PRESERVED
         * per D-3.4e-5 (operator log-shipping pipeline stability). */
        SidecarRootFd root_fd{root.c_str()};
        switch (root_fd.state()) {
            case SidecarRootFd::State::Ok:
                break;
            case SidecarRootFd::State::RootSymlink: {
                /* §5.32 (MVP-3.5): byte-equivalent text-mode (PI-3.5-1) +
                 * JSON field `path`. Wording from §5.31 EDIT-1 PRESERVED. */
                const std::string msg = std::format(
                    "xdpmacfilter: WARN: rule_index.json refusing "
                    "to write — sidecar root '{}' is a symlink\n",
                    root);
                const xdpmf::logger::Field fs[] = {
                    xdpmf::logger::Field{"path", std::string_view{root}},
                };
                xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                                    "sidecar.warn.root_symlink",
                                    std::string_view{iface}, msg, fs);
                return;
            }
            case SidecarRootFd::State::RootNotDir: {
                const std::string msg = std::format(
                    "xdpmacfilter: WARN: rule_index.json refusing "
                    "to write — sidecar root '{}' is not a directory\n",
                    root);
                const xdpmf::logger::Field fs[] = {
                    xdpmf::logger::Field{"path", std::string_view{root}},
                };
                xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                                    "sidecar.warn.root_not_dir",
                                    std::string_view{iface}, msg, fs);
                return;
            }
            case SidecarRootFd::State::OpenFailed: {
                const int         e         = root_fd.error_errno();
                const std::string errno_str = std::strerror(e);
                const std::string msg       = std::format(
                    "xdpmacfilter: WARN: rule_index.json open of "
                    "sidecar root '{}' failed: {}\n",
                    root, errno_str);
                const xdpmf::logger::Field fs[] = {
                    xdpmf::logger::Field{"path",      std::string_view{root}},
                    xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
                    xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(e)},
                };
                xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                                    "sidecar.warn.lstat_failed",
                                    std::string_view{iface}, msg, fs);
                return;
            }
        }

        const std::string iface_str{iface};

        /* §5.36 HG-3.4e-2 + D-3.4e-4: fd-relative mkdirat of the per-iface
         * sidecar dir under XDPMF_SIDECAR_ROOT/<iface>. On EEXIST verify
         * the existing entry is a real directory (NOT a symlink — KC-3
         * sidecar limb) via fstatat(AT_SYMLINK_NOFOLLOW). On S_ISLNK:
         * emit NEW sidecar.warn.iface_dir_symlink + return (HG-3.4e-4 —
         * WARN + skip; PI-32-3.4b PRESERVED). */
        if (::mkdirat(root_fd.fd(), iface_str.c_str(), 0755) != 0
            && errno != EEXIST)
        {
            const int         e         = errno;
            const std::string errno_str = std::strerror(e);
            const std::string msg       = std::format(
                "xdpmacfilter: WARN: rule_index.json mkdirat "
                "of '{}/{}' failed: {}\n",
                root, iface_str, errno_str);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{"path",      std::string_view{iface_str}},
                xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
                xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(e)},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                                "sidecar.warn.mkdir_failed",
                                std::string_view{iface}, msg, fs);
            return;
        }

        /* §5.36 HG-3.4e-4: per-iface symlink defense. fstatat with
         * AT_SYMLINK_NOFOLLOW reports the link itself (NOT its target);
         * S_ISLNK then catches the attack regardless of whether the
         * mkdirat above returned 0 (race-free creation) or EEXIST
         * (pre-planted entry). On S_ISDIR proceed; on S_ISLNK or other
         * non-dir → WARN + skip. */
        struct stat st_iface{};
        if (::fstatat(root_fd.fd(), iface_str.c_str(), &st_iface,
                       AT_SYMLINK_NOFOLLOW) != 0)
        {
            const int         e         = errno;
            const std::string errno_str = std::strerror(e);
            const std::string msg       = std::format(
                "xdpmacfilter: WARN: rule_index.json fstatat "
                "'{}/{}' failed: {}\n",
                root, iface_str, errno_str);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{"path",      std::string_view{iface_str}},
                xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
                xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(e)},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                                "sidecar.warn.lstat_failed",
                                std::string_view{iface}, msg, fs);
            return;
        }
        if (S_ISLNK(st_iface.st_mode)) {
            /* §5.36 NEW event — HG-3.4e-4. Per-iface symlink under
             * XDPMF_SIDECAR_ROOT/<iface>. KC-3 sidecar limb closed.
             * WARN + skip; apply continues; PI-32-3.4b PRESERVED. */
            const std::string msg = std::format(
                "xdpmacfilter: WARN: rule_index.json refusing "
                "to write — sidecar per-iface entry '{}/{}' is a symlink\n",
                root, iface_str);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{"path", std::string_view{iface_str}},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                                "sidecar.warn.iface_dir_symlink",
                                std::string_view{iface}, msg, fs);
            return;
        }
        if (!S_ISDIR(st_iface.st_mode)) {
            /* Other non-dir (e.g. a regular file pre-planted) — treat
             * uniformly via mkdir_failed (closest existing event) so
             * downstream pipelines don't need a brand-new entry for an
             * edge case that is effectively the same operator action
             * "something blocked the iface dir creation". */
            const std::string errno_str = "not a directory";
            const std::string msg       = std::format(
                "xdpmacfilter: WARN: rule_index.json refusing "
                "to write — sidecar per-iface entry '{}/{}' is not a directory\n",
                root, iface_str);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{"path",      std::string_view{iface_str}},
                xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
                xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(ENOTDIR)},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                                "sidecar.warn.mkdir_failed",
                                std::string_view{iface}, msg, fs);
            return;
        }

        const std::string body = build_body(iface, cfg);
        const int rc = atomic_write_file_at(root_fd.fd(), iface_str, body);
        if (rc != 0) {
            /* D-3.4b-17: non-fatal degrade — single WARN line, no throw,
             * no exit. Exporter will degrade to action="unknown" labels
             * for this iface until the next successful apply.
             *
             * §5.32 (MVP-3.5): byte-equivalent text-mode (PI-3.5-1) + JSON
             * surfaces errno + path. */
            const std::string errno_str = std::strerror(rc);
            const std::string final_path = root + "/" + iface_str
                                         + "/rule_index.json";
            const std::string msg = std::format(
                "xdpmacfilter: WARN: rule_index.json write failed: {}\n",
                errno_str);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{"path",      std::string_view{final_path}},
                xdpmf::logger::Field{"errno_str", std::string_view{errno_str}},
                xdpmf::logger::Field{"errno",     static_cast<std::int64_t>(rc)},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Warn,
                                "sidecar.warn.write_failed",
                                std::string_view{iface}, msg, fs);
        }
    } catch (...) {
        /* PI-32-3.4b never-throw contract: any exception (std::bad_alloc,
         * std::format argument-formatting issue, etc.) degrades to silent
         * WARN. */
        xdpmf::logger::emit(
            xdpmf::logger::Level::Warn,
            "sidecar.warn.write_exception",
            std::string_view{iface},
            "xdpmacfilter: WARN: rule_index.json write failed: "
            "exception during body construction\n");
    }
}

}  // namespace xdpmf::sidecar
