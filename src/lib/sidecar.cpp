/*
 * sidecar.cpp — `rule_index.json` writer impl (§5.31 MVP-3.4b).
 *
 * Roll-your-own JSON emitter per D-3.4b-10 (no nlohmann/json build dep).
 * The schema (Q2 S1 defaults-only + D-3.4b-20 one-rule-per-line shape) has
 * exactly 3 top-level fields + a homogeneous `rules` array of 3-field
 * objects — well-bounded; a serializer is a few-dozen LOC. Output is
 * valid JSON (jq accepts it) AND line-oriented (the exporter regex
 * matches per-rule lines independently).
 *
 * Atomic write: write-to-<path>.tmp → fsync(fd) → close → rename(tmp, path).
 * Failures are NEVER fatal — log a single stderr WARN and return silently.
 */
#include "sidecar.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <format>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/mac_filter.h"   // xdpmf_mac, xdpmf_cidr_v4

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
    return std::format("{}.{}.{}.{}/{}", a, b, d, e, c.prefixlen);
}

/* ISO-8601 UTC `YYYY-MM-DDTHH:MM:SSZ` (single trailing `Z`; no fractional
 * seconds — per D-3.4b-20 grep-friendliness). CLOCK_REALTIME via std::time. */
[[nodiscard]] std::string format_timestamp_utc()
{
    const std::time_t now = std::time(nullptr);
    std::tm           tm_buf{};
    if (::gmtime_r(&now, &tm_buf) == nullptr) {
        /* gmtime_r failure is unprecedented but never-throw contract: emit
         * a clearly-broken timestamp that still matches the ERE shape so
         * the exporter's regex-based parser doesn't choke. */
        return "1970-01-01T00:00:00Z";
    }
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                       tm_buf.tm_year + 1900,
                       tm_buf.tm_mon  + 1,
                       tm_buf.tm_mday,
                       tm_buf.tm_hour,
                       tm_buf.tm_min,
                       tm_buf.tm_sec);
}

/* JSON string escape per RFC 8259: backslash, double-quote, and control
 * characters get backslash-escaped; non-ASCII bytes pass through verbatim
 * (sidecar consumers we care about — jq + our own line-regex parser — are
 * UTF-8 safe; iface names in practice are constrained to [A-Za-z0-9._-]). */
[[nodiscard]] std::string json_escape(std::string_view raw)
{
    std::string out;
    out.reserve(raw.size() + 2);
    for (char c : raw) {
        switch (c) {
            case '\\': out.append("\\\\"); break;
            case '"':  out.append("\\\""); break;
            case '\n': out.append("\\n");  break;
            case '\r': out.append("\\r");  break;
            case '\t': out.append("\\t");  break;
            case '\b': out.append("\\b");  break;
            case '\f': out.append("\\f");  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out.append(std::format("\\u{:04x}",
                                            static_cast<unsigned char>(c)));
                } else {
                    out.push_back(c);
                }
                break;
        }
    }
    return out;
}

/* Build the rule_index.json body for `cfg` under `iface`. Stable
 * source-order (matches Config::rules vector order). Per D-3.4b-20:
 * one rule object per line so the exporter's line-oriented regex can
 * extract each independently without a full JSON parser. */
[[nodiscard]] std::string build_body(std::string_view iface, const Config& cfg)
{
    std::string body;
    body.reserve(256 + cfg.rules.size() * 96);

    body.append("{\n");
    body.append(std::format("  \"iface\": \"{}\",\n", json_escape(iface)));
    body.append("  \"schema_version\": 1,\n");
    body.append(std::format("  \"applied_at\": \"{}\",\n", format_timestamp_utc()));
    body.append("  \"rules\": [");

    bool first = true;
    for (const Rule& r : cfg.rules) {
        body.append(first ? "\n" : ",\n");
        first = false;

        const char* action_str = (r.action == RuleAction::Pass) ? "pass" : "drop";

        /* Build the `match` sub-object inline so the rule lives on one line
         * (one-rule-per-line per D-3.4b-20). At-least-one-of mac/src_cidr
         * is guaranteed by config.cpp validation; both keys can appear if
         * the rule had both per §5.27 schema. */
        std::string match;
        if (r.match.mac.has_value() && r.match.src_cidr.has_value()) {
            match = std::format(
                "{{\"mac\": \"{}\", \"cidr\": \"{}\"}}",
                format_mac(*r.match.mac), format_cidr(*r.match.src_cidr));
        } else if (r.match.mac.has_value()) {
            match = std::format("{{\"mac\": \"{}\"}}",
                                 format_mac(*r.match.mac));
        } else if (r.match.src_cidr.has_value()) {
            match = std::format("{{\"cidr\": \"{}\"}}",
                                 format_cidr(*r.match.src_cidr));
        } else {
            /* Shouldn't happen — config validation rejects (mac=null && cidr=null);
             * defensive empty object preserves valid JSON shape. */
            match = "{}";
        }

        body.append(std::format(
            "    {{\"rule_id\": {}, \"match\": {}, \"action\": \"{}\"}}",
            r.id, match, action_str));
    }
    body.append(first ? "]\n" : "\n  ]\n");
    body.append("}\n");
    return body;
}

/* mkdir-p: ensure `dir` exists (creating each component as needed) with mode
 * 0755. Returns 0 on success (already-exists is OK), errno-positive on real
 * failure. Single-shot helper; no per-component error suppression needed
 * for our usage because /run is universally writable as root on systemd
 * hosts (FHS §3.15) and the per-iface child is the only new component. */
[[nodiscard]] int mkdir_p(const std::string& dir)
{
    /* Walk component-by-component; mkdir each; ignore EEXIST. */
    std::string acc;
    acc.reserve(dir.size());
    for (std::size_t i = 0; i <= dir.size(); ++i) {
        if (i == dir.size() || dir[i] == '/') {
            if (!acc.empty() && acc != "/") {
                if (::mkdir(acc.c_str(), 0755) != 0 && errno != EEXIST) {
                    return errno;
                }
            }
        }
        if (i < dir.size()) acc.push_back(dir[i]);
    }
    return 0;
}

/* Atomic write: write→fsync→rename. Returns 0 on success, errno-positive
 * on any failure (caller logs single WARN, never throws). The tmp file is
 * unlinked on failure so a future apply doesn't trip on a stale .tmp. */
[[nodiscard]] int atomic_write_file(const std::string& final_path,
                                     std::string_view  body)
{
    const std::string tmp_path = final_path + ".tmp";

    /* mode 0644: world-readable (CAP_BPF-only exporter reads it). */
    const int fd = ::open(tmp_path.c_str(),
                           O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
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
            (void)::unlink(tmp_path.c_str());
            return e;
        }
        p   += n;
        rem -= static_cast<std::size_t>(n);
    }

    if (::fsync(fd) != 0) {
        const int e = errno;
        (void)::close(fd);
        (void)::unlink(tmp_path.c_str());
        return e;
    }
    if (::close(fd) != 0) {
        const int e = errno;
        (void)::unlink(tmp_path.c_str());
        return e;
    }
    if (::rename(tmp_path.c_str(), final_path.c_str()) != 0) {
        const int e = errno;
        (void)::unlink(tmp_path.c_str());
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

        /* §5.31 EDIT-1 architect Phase B addendum (symlink-refuse): if
         * XDPMF_SIDECAR_ROOT itself is a symlink (or absent + the parent
         * has one in its way), refuse-and-warn. Mirrors §5.22 O_PATH
         * discipline used for the bpffs root. lstat() returns the
         * symlink's own type — NOT what it points to — so S_ISLNK directly
         * catches the attack. Missing-root is OK (mkdir_p creates it);
         * existing-non-dir-non-symlink (e.g. regular file at /run/xdpmacfilter)
         * also gets refused. */
        struct stat st_root{};
        if (::lstat(root.c_str(), &st_root) == 0) {
            if (S_ISLNK(st_root.st_mode)) {
                std::fprintf(stderr,
                             "xdpmacfilter: WARN: rule_index.json refusing "
                             "to write — sidecar root '%s' is a symlink\n",
                             root.c_str());
                return;
            }
            if (!S_ISDIR(st_root.st_mode)) {
                std::fprintf(stderr,
                             "xdpmacfilter: WARN: rule_index.json refusing "
                             "to write — sidecar root '%s' is not a directory\n",
                             root.c_str());
                return;
            }
        } else if (errno != ENOENT) {
            std::fprintf(stderr,
                         "xdpmacfilter: WARN: rule_index.json lstat('%s') "
                         "failed: %s\n",
                         root.c_str(), std::strerror(errno));
            return;
        }

        std::string dir = root;
        dir.push_back('/');
        dir.append(iface);

        /* §5.31 EDIT-1 + D-3.4b-21: mkdir-p the per-iface sidecar dir under
         * /run/xdpmacfilter/ (universally writable as root on systemd hosts).
         * Failure is non-fatal — degrades to exporter's action="unknown"
         * labels per D-3.4b-17. */
        if (const int mrc = mkdir_p(dir); mrc != 0) {
            std::fprintf(stderr,
                         "xdpmacfilter: WARN: rule_index.json mkdir-p "
                         "of '%s' failed: %s\n",
                         dir.c_str(), std::strerror(mrc));
            return;
        }

        std::string final_path = dir;
        final_path.append("/rule_index.json");

        const std::string body = build_body(iface, cfg);
        const int         rc   = atomic_write_file(final_path, body);
        if (rc != 0) {
            /* D-3.4b-17: non-fatal degrade — single WARN line, no throw,
             * no exit. Exporter will degrade to action="unknown" labels
             * for this iface until the next successful apply. */
            std::fprintf(stderr,
                         "xdpmacfilter: WARN: rule_index.json write failed: %s\n",
                         std::strerror(rc));
        }
    } catch (...) {
        /* Never-throw contract: any exception (std::bad_alloc, std::format
         * argument-formatting issue, etc.) degrades to silent WARN. */
        std::fprintf(stderr,
                     "xdpmacfilter: WARN: rule_index.json write failed: "
                     "exception during body construction\n");
    }
}

}  // namespace xdpmf::sidecar
