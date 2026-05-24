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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <span>
#include <string>
#include <string_view>

#include "common/mac_filter.h"  // XDPMF_BPFFS_ROOT
#include "http.hpp"
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
        "The exporter is read-only — no map mutations, no attach/detach.\n",
        std::string{kProgName}.c_str(),
        std::string{kProgName}.c_str(),
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
            std::fprintf(stderr, "xdpmf-exporter: --%.*s requires a value\n",
                         static_cast<int>(expected.size()), expected.data());
            std::exit(kExitUsageErr);
        }
        return v;
    }
    const std::string plain = std::string{"--"} + std::string{expected};
    if (tok == plain) {
        if (idx + 1 >= args.size()) {
            std::fprintf(stderr, "xdpmf-exporter: --%.*s requires a value\n",
                         static_cast<int>(expected.size()), expected.data());
            std::exit(kExitUsageErr);
        }
        ++idx;
        const std::string_view v{args[idx]};
        ++idx;
        return v;
    }
    /* Unreachable if the caller checked the flag prefix; defensive only. */
    std::fprintf(stderr, "xdpmf-exporter: unexpected argument: '%.*s'\n",
                 static_cast<int>(tok.size()), tok.data());
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
                    std::fprintf(stderr, "xdpmf-exporter: invalid --port: '%.*s' "
                                         "(expected uint16, 1..65535)\n",
                                 static_cast<int>(v.size()), v.data());
                    return kExitUsageErr;
                }
                cfg.port = port;
            } else if (tok == "--bind" || tok.starts_with("--bind=")) {
                cfg.bind_addr = std::string{consume_flag_value(args, i, "bind")};
            } else if (tok == "--bpffs-root" || tok.starts_with("--bpffs-root=")) {
                cfg.bpffs_root = std::string{consume_flag_value(args, i, "bpffs-root")};
            } else {
                std::fprintf(stderr, "xdpmf-exporter: unknown argument: '%.*s'\n",
                             static_cast<int>(tok.size()), tok.data());
                print_usage(stderr);
                return kExitUsageErr;
            }
        }
    }

    xdpmf::exporter::install_signal_handlers();
    try {
        return xdpmf::exporter::run(cfg);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "xdpmf-exporter: fatal: %s\n", e.what());
        return kExitUsageErr;
    }
}
