/*
 * main.cpp — `xdpmf-exporter` entry-point (§5.29, MVP-3.4).
 *
 * Parse argv, install SIGINT/SIGTERM handlers, dispatch into http::run().
 * Returns 0 on clean shutdown; 1 on CLI usage error; non-zero on bind/listen
 * failure (see http.cpp).
 *
 * Flags (per §5.29 CLI grammar):
 *   --port <N>          uint16; default 9417
 *   --bind <addr>       IPv4 dotted-quad; default 127.0.0.1
 *   --bpffs-root <path> default XDPMF_BPFFS_ROOT
 *   --help              prints usage + exit 0
 *   --version           prints "xdpmf-exporter <V>" + exit 0
 */
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <format>
#include <span>
#include <string>
#include <string_view>

#include "common/logger.hpp"    // §5.32 (MVP-3.5) structured-logging surface
#include "common/mac_filter.h"  // XDPMF_BPFFS_ROOT
#include "http.hpp"
#include "stats_reader.hpp"     // §5.30 HK-16: validate_bpffs_root_or_warn
#include "version.h"            // XDPMF_VERSION_STRING

namespace {

constexpr std::string_view kProgName = "xdpmf-exporter";
constexpr int              kExitOk        = 0;
constexpr int              kExitUsageErr  = 1;

void print_usage(std::FILE* out)
{
    std::fprintf(out,
        "Usage:\n"
        "  %s [--port <N>] [--bind <addr>] [--bpffs-root <path>]\n"
        "  %s --help | --version\n"
        "\n"
        "Options:\n"
        "  --port <N>             TCP port (uint16, default 9417).\n"
        "  --bind <addr>          IPv4 dotted-quad bind address (default 127.0.0.1).\n"
        "  --bpffs-root <path>    bpffs root scanned for per-iface stats pins\n"
        "                         (default %s).\n"
        "\n"
        "HTTP routes:\n"
        "  GET /metrics   Prometheus text-format counter family.\n"
        "  GET /healthz   liveness probe (200 OK \"ok\\n\").\n"
        "\n"
        "Environment variables:\n"
        "  XDPMF_BPFFS_ROOT      Compile-time default bpffs root; overridden by\n"
        "                        --bpffs-root if both given. Current default: %s.\n"
        "  XDPMF_TRUST_MODEL     NOT consumed by xdpmf-exporter (loader-only env\n"
        "                        var; documented here for fleet-ops cross-reference).\n"
        "\n"
        "The exporter is read-only -- no map mutations, no attach/detach.\n",
        std::string{kProgName}.c_str(),
        std::string{kProgName}.c_str(),
        XDPMF_BPFFS_ROOT,
        XDPMF_BPFFS_ROOT);
}

[[nodiscard]] bool parse_uint16(std::string_view s, std::uint16_t& out)
{
    unsigned long v = 0;
    auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || p != s.data() + s.size()) {
        return false;
    }
    if (v == 0 || v > 0xFFFFu) {
        return false;
    }
    out = static_cast<std::uint16_t>(v);
    return true;
}

/* Consume `--<expected>` with its value from `args` at `idx`. Supports
 * `--flag value` and `--flag=value`. Mirrors the loader's CLI idiom but
 * inlined to keep the exporter binary independent of cli.cpp helpers. */
[[nodiscard]] std::string_view consume_flag_value(
    std::span<char* const> args, std::size_t& idx, std::string_view expected)
{
    const std::string_view tok{args[idx]};
    const std::string with_eq = std::string{"--"} + std::string{expected} + "=";
    if (tok.starts_with(with_eq)) {
        std::string_view v = tok.substr(with_eq.size());
        ++idx;
        if (v.empty()) {
            /* §5.32 (MVP-3.5): byte-equivalent text-mode + flag field for JSON. */
            const std::string msg = std::format(
                "xdpmf-exporter: --{} requires a value\n", expected);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{"flag", expected},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Error,
                                "exporter.usage_error", msg, fs);
            std::exit(kExitUsageErr);
        }
        return v;
    }
    const std::string plain = std::string{"--"} + std::string{expected};
    if (tok == plain) {
        if (idx + 1 >= args.size()) {
            const std::string msg = std::format(
                "xdpmf-exporter: --{} requires a value\n", expected);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{"flag", expected},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Error,
                                "exporter.usage_error", msg, fs);
            std::exit(kExitUsageErr);
        }
        ++idx;
        const std::string_view v{args[idx]};
        ++idx;
        return v;
    }
    /* Unreachable if the caller checked the flag prefix; defensive only.
     * §5.32 (MVP-3.5): byte-equivalent text-mode + tok in JSON fields. */
    const std::string msg = std::format(
        "xdpmf-exporter: unexpected argument: '{}'\n", tok);
    const xdpmf::logger::Field fs[] = {
        xdpmf::logger::Field{"arg", tok},
    };
    xdpmf::logger::emit(xdpmf::logger::Level::Error,
                        "exporter.usage_error", msg, fs);
    std::exit(kExitUsageErr);
}

}  // namespace

int main(int argc, char* argv[])
{
    xdpmf::exporter::HttpConfig cfg;
    cfg.bind_addr  = "127.0.0.1";
    cfg.port       = 9417;
    cfg.bpffs_root = XDPMF_BPFFS_ROOT;

    if (argc > 1) {
        const std::span<char* const> args{argv + 1, static_cast<std::size_t>(argc - 1)};
        std::size_t i = 0;
        while (i < args.size()) {
            std::string_view tok{args[i]};
            if (tok == "--help" || tok == "-h") {
                print_usage(stdout);
                return kExitOk;
            }
            if (tok == "--version") {
                std::printf("%s %s\n",
                            std::string{kProgName}.c_str(),
                            XDPMF_VERSION_STRING);
                return kExitOk;
            }
            if (tok == "--port" || tok.starts_with("--port=")) {
                const std::string_view v = consume_flag_value(args, i, "port");
                std::uint16_t port = 0;
                if (!parse_uint16(v, port)) {
                    /* §5.32 (MVP-3.5): byte-equivalent text-mode + value
                     * in JSON fields. */
                    const std::string msg = std::format(
                        "xdpmf-exporter: invalid --port: '{}' "
                        "(expected uint16, 1..65535)\n", v);
                    const xdpmf::logger::Field fs[] = {
                        xdpmf::logger::Field{"flag",  std::string_view{"port"}},
                        xdpmf::logger::Field{"value", v},
                    };
                    xdpmf::logger::emit(xdpmf::logger::Level::Error,
                                        "exporter.usage_error", msg, fs);
                    return kExitUsageErr;
                }
                cfg.port = port;
            } else if (tok == "--bind" || tok.starts_with("--bind=")) {
                cfg.bind_addr = std::string{consume_flag_value(args, i, "bind")};
            } else if (tok == "--bpffs-root" || tok.starts_with("--bpffs-root=")) {
                cfg.bpffs_root = std::string{consume_flag_value(args, i, "bpffs-root")};
            } else {
                /* §5.32 (MVP-3.5): byte-equivalent text-mode + tok in JSON. */
                const std::string msg = std::format(
                    "xdpmf-exporter: unknown argument: '{}'\n", tok);
                const xdpmf::logger::Field fs[] = {
                    xdpmf::logger::Field{"arg", tok},
                };
                xdpmf::logger::emit(xdpmf::logger::Level::Error,
                                    "exporter.usage_error", msg, fs);
                print_usage(stderr);
                return kExitUsageErr;
            }
        }
    }

    xdpmf::exporter::install_signal_handlers();

    /* §5.30 HK-16 (W1, MVP-3.4.5): one-shot bpffs-root existence check. Fires
     * a single WARN line on stderr if `cfg.bpffs_root` does not exist (e.g.
     * operator pointed --bpffs-root at a typo path). Continues regardless;
     * the daemon serves empty metrics on a nonexistent root per PI-32. The
     * helper is implemented in stats_reader.cpp so future bpffs-path checks
     * cohere in one place. */
    xdpmf::exporter::validate_bpffs_root_or_warn(cfg.bpffs_root);

    int rc = kExitUsageErr;
    try {
        rc = xdpmf::exporter::run(cfg);
    } catch (const std::exception& e) {
        /* §5.32 (MVP-3.5): byte-equivalent text-mode (PI-3.5-1) + JSON
         * surfaces .what() in fields. Process-scoped (no iface). */
        const std::string what_str = e.what();
        const std::string msg = std::format(
            "xdpmf-exporter: fatal: {}\n", what_str);
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"what", std::string_view{what_str}},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Error,
                            "exporter.fatal", msg, fs);
        return kExitUsageErr;
    }

    /* §5.30 HK-17 (E1, MVP-3.4.5): run() returns 6 when the /metrics
     * handler detected the all-iface EACCES condition. Emit the canonical
     * stderr line "immediately before exit(6) from main()" per D-3.4.5-2
     * — the <N> field is the total_discovered count from the scrape that
     * fired the trigger (always >= 1; the trigger requires it). */
    if (rc == 6) {
        const std::size_t n = xdpmf::exporter::last_exit_six_total();
        /* §5.32 (MVP-3.5) HK-17 stderr line: byte-equivalent text-mode +
         * total_discovered surfaced as `fields.total_discovered` for JSON. */
        const std::string msg = std::format(
            "xdpmf-exporter: ERROR all {} discovered interfaces failed "
            "permission-denied; check CAP_BPF and bpffs read mode (exit 6)\n",
            n);
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"total_discovered",
                                 static_cast<std::int64_t>(n)},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Error,
                            "exporter.error.all_ifaces_eacces", msg, fs);
    }
    return rc;
}
