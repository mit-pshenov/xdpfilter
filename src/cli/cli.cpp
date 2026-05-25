/*
 * cli.cpp — hand-rolled argv parser. Hand-rolled (not getopt) because the
 * grammar is small (two subcommands × two flags), error messages need to
 * be readable, and we want zero non-standard dependencies. C++23.
 */
#include "cli.hpp"
#include "version.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <ranges>
#include <span>
#include <string_view>

namespace xdpmf {

namespace {

constexpr std::string_view kProgName = "xdpmacfilter";

/* Hex nibble → 0..15 or -1 on invalid. */
[[nodiscard]] constexpr int hex_nibble(char c) noexcept
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return 10 + (c - 'a'); }
    if (c >= 'A' && c <= 'F') { return 10 + (c - 'A'); }
    return -1;
}

/* Split `s` on every occurrence of `sep`. Empty fields are preserved
 * (parser surfaces them as MAC parse errors). */
[[nodiscard]] std::vector<std::string_view> split(std::string_view s, char sep)
{
    std::vector<std::string_view> out;
    std::size_t start = 0;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == sep) {
            out.emplace_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    out.emplace_back(s.substr(start));
    return out;
}

[[nodiscard]] bool macs_equal(const xdpmf_mac& a, const xdpmf_mac& b) noexcept
{
    return std::memcmp(a.octets, b.octets, sizeof(a.octets)) == 0;
}

}  // namespace

bool parse_mac(std::string_view tok, xdpmf_mac& out) noexcept
{
    // Exact form: XX:XX:XX:XX:XX:XX — 17 chars, ':' at positions 2,5,8,11,14.
    constexpr std::size_t kExpectedLen = 17;
    if (tok.size() != kExpectedLen) {
        return false;
    }
    for (std::size_t i = 0; i < 6; ++i) {
        const std::size_t pos = i * 3;
        const int hi = hex_nibble(tok[pos]);
        const int lo = hex_nibble(tok[pos + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        if (i < 5 && tok[pos + 2] != ':') {
            return false;
        }
        out.octets[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

std::string usage_text()
{
    return std::format(
        "Usage:\n"
        "  {0} attach --iface <IFNAME> [--allow <MAC>[,<MAC>...] ...] [--mode <M>]\n"
        "  {0} detach --iface <IFNAME>\n"
        "  {0} apply  --iface <IFNAME> -f <PATH> [--mode <M>]\n"
        "  {0} bypass --iface <IFNAME> [--unsafe] [--reason \"<text>\"]\n"
        "  {0} --help | --version\n"
        "\n"
        "Options:\n"
        "  --iface <IFNAME>            Network interface name (required).\n"
        "  --allow <MAC>[,<MAC>...]    Source MAC(s) to admit. May repeat or\n"
        "                              be a comma-separated list. Max {1} unique.\n"
        "                              Format: XX:XX:XX:XX:XX:XX (hex).\n"
        "                              Empty allow-list drops all frames.\n"
        "  -f <PATH>                   YAML config file (apply only). Schema\n"
        "                              version 1. Max 1 MiB.\n"
        "  --mode {{generic|native|offload}}\n"
        "                              XDP attach mode (attach / apply only;\n"
        "                              default generic). detach auto-detects\n"
        "                              from the attached program.\n"
        "  --unsafe                    bypass: required in non-interactive context;\n"
        "                              ALSO suppresses interactive y/N prompt when\n"
        "                              passed at a tty.\n"
        "  --reason \"<text>\"           bypass: audit-log reason (free-form; default\n"
        "                              UNSPECIFIED; capped at 256 bytes).\n"
        "\n"
        "Exit codes: 0 ok, 1 usage, 2 load-fail, 3 attach-fail,\n"
        "            4 attach-refused-alien, 5 detach-fail, 6 permission,\n"
        "            7 kernel-unsupported, 8 path-refused, 9 config-error.\n"
        "\n"
        "Environment variables:\n"
        "  XDPMF_TRUST_MODEL={{strict|fleet}}   Default: strict. fleet relaxes only\n"
        "                                      \xC2\xA7 5.4 alien-program refusal -- see\n"
        "                                      docs/FLEET_DEPLOYMENT.md for the full\n"
        "                                      gate diff between modes.\n",
        kProgName, XDPMF_ALLOWLIST_MAX);
}

std::string version_text()
{
    return std::format("{} {}\n", kProgName, XDPMF_VERSION_STRING);
}

namespace {

/*
 * Append all MACs parsed from `value` (a single MAC or a comma-list) into
 * `out`, de-duplicating against existing entries. Throws CliError on bad
 * token or if capacity is exceeded.
 */
void parse_allow_token(std::string_view value, std::vector<xdpmf_mac>& out)
{
    for (std::string_view piece : split(value, ',')) {
        xdpmf_mac m{};
        if (!parse_mac(piece, m)) {
            throw CliError(std::format("invalid MAC: '{}'", piece));
        }
        const auto already = std::ranges::any_of(
            out, [&](const xdpmf_mac& e) { return macs_equal(e, m); });
        if (already) {
            continue;
        }
        if (out.size() >= XDPMF_ALLOWLIST_MAX) {
            throw CliError(std::format(
                "too many --allow entries (max {})", XDPMF_ALLOWLIST_MAX));
        }
        out.push_back(m);
    }
}

/*
 * Consume `--<expected>` plus its value from `args` starting at `idx`.
 * On success advances `idx` past both and returns the value. Supports
 * both `--flag value` and `--flag=value` forms.
 */
[[nodiscard]] std::string_view consume_flag_value(
    std::span<char* const> args, std::size_t& idx, std::string_view expected)
{
    std::string_view tok{args[idx]};
    const std::string with_eq = std::string{"--"} + std::string{expected} + "=";
    if (tok.starts_with(with_eq)) {
        std::string_view v = tok.substr(with_eq.size());
        ++idx;
        if (v.empty()) {
            throw CliError(std::format("--{} requires a value", expected));
        }
        return v;
    }
    const std::string plain = std::string{"--"} + std::string{expected};
    if (tok == plain) {
        if (idx + 1 >= args.size()) {
            throw CliError(std::format("--{} requires a value", expected));
        }
        ++idx;
        std::string_view v{args[idx]};
        ++idx;
        return v;
    }
    throw CliError(std::format("unexpected argument: '{}'", tok));
}

/* §5.23 Item 2: map literal mode token → enum. Case-sensitive per design.
 * Throws CliError with the §5.23-specified message on any unknown value
 * (load-bearing for tester diagnostic). */
[[nodiscard]] XdpMode parse_mode_token(std::string_view tok)
{
    if (tok == "generic") return XdpMode::Generic;
    if (tok == "native")  return XdpMode::Native;
    if (tok == "offload") return XdpMode::Offload;
    throw CliError(std::format(
        "--mode: expected one of {{generic, native, offload}}, got '{}'", tok));
}

ParsedCommand parse_attach(std::span<char* const> args)
{
    AttachConfig cfg;
    std::size_t i = 0;
    while (i < args.size()) {
        std::string_view tok{args[i]};
        if (tok == "--iface" || tok.starts_with("--iface=")) {
            cfg.iface = std::string{consume_flag_value(args, i, "iface")};
        } else if (tok == "--allow" || tok.starts_with("--allow=")) {
            std::string_view v = consume_flag_value(args, i, "allow");
            parse_allow_token(v, cfg.allow);
        } else if (tok == "--mode" || tok.starts_with("--mode=")) {
            std::string_view v = consume_flag_value(args, i, "mode");
            cfg.mode = parse_mode_token(v);
        } else {
            throw CliError(std::format("unknown attach flag: '{}'", tok));
        }
    }
    if (cfg.iface.empty()) {
        throw CliError("attach requires --iface <IFNAME>");
    }
    return cfg;
}

/* §5.26 Q4 G1: `apply -f <path> --iface <iface> [--mode <m>]`. Both
 * --iface and -f are REQUIRED; --mode is optional (forwarded to first attach
 * only; ignored when an existing link pin is reused). */
ParsedCommand parse_apply(std::span<char* const> args)
{
    ApplyConfig cfg;
    std::size_t i = 0;
    while (i < args.size()) {
        std::string_view tok{args[i]};
        if (tok == "--iface" || tok.starts_with("--iface=")) {
            cfg.iface = std::string{consume_flag_value(args, i, "iface")};
        } else if (tok == "-f") {
            if (i + 1 >= args.size()) {
                throw CliError("apply: -f requires a value");
            }
            ++i;
            cfg.config_path = std::string{args[i]};
            if (cfg.config_path.empty()) {
                throw CliError("apply: -f requires a non-empty path");
            }
            ++i;
        } else if (tok == "--mode" || tok.starts_with("--mode=")) {
            std::string_view v = consume_flag_value(args, i, "mode");
            cfg.mode = parse_mode_token(v);
        } else {
            throw CliError(std::format("unknown apply flag: '{}'", tok));
        }
    }
    if (cfg.iface.empty()) {
        throw CliError("apply requires --iface <IFNAME>");
    }
    if (cfg.config_path.empty()) {
        throw CliError("apply requires -f <PATH>");
    }
    return cfg;
}

ParsedCommand parse_detach(std::span<char* const> args)
{
    DetachConfig cfg;
    std::size_t i = 0;
    while (i < args.size()) {
        std::string_view tok{args[i]};
        if (tok == "--iface" || tok.starts_with("--iface=")) {
            cfg.iface = std::string{consume_flag_value(args, i, "iface")};
        } else if (tok == "--mode" || tok.starts_with("--mode=")) {
            // §5.23 Q1 Option A: --mode is attach-only. The substring
            // "attach-only" is load-bearing for §6.19 tester grep.
            throw CliError(
                "detach: --mode is attach-only; mode is auto-detected from "
                "the attached program");
        } else {
            throw CliError(std::format("unknown detach flag: '{}'", tok));
        }
    }
    if (cfg.iface.empty()) {
        throw CliError("detach requires --iface <IFNAME>");
    }
    return cfg;
}

/* §5.29 HG-3.4-2: `bypass --iface <X> [--unsafe] [--reason "<text>"]`.
 * --iface is REQUIRED; --unsafe is a boolean flag; --reason takes a value
 * (free-form, may contain spaces — consumed as a single string). */
ParsedCommand parse_bypass(std::span<char* const> args)
{
    BypassConfig cfg;
    std::size_t i = 0;
    while (i < args.size()) {
        std::string_view tok{args[i]};
        if (tok == "--iface" || tok.starts_with("--iface=")) {
            cfg.iface = std::string{consume_flag_value(args, i, "iface")};
        } else if (tok == "--unsafe") {
            cfg.unsafe = true;
            ++i;
        } else if (tok == "--reason" || tok.starts_with("--reason=")) {
            cfg.reason = std::string{consume_flag_value(args, i, "reason")};
        } else {
            throw CliError(std::format("unknown bypass flag: '{}'", tok));
        }
    }
    if (cfg.iface.empty()) {
        throw CliError("bypass requires --iface <IFNAME>");
    }
    return cfg;
}

}  // namespace

ParsedCommand parse(int argc, char* const argv[])
{
    if (argc < 2) {
        throw CliError("missing subcommand");
    }
    std::string_view sub{argv[1]};
    if (sub == "--help" || sub == "-h") {
        return HelpRequest{};
    }
    if (sub == "--version") {
        return VersionRequest{};
    }
    std::span<char* const> rest{argv + 2, static_cast<std::size_t>(argc - 2)};
    if (sub == "attach") {
        return parse_attach(rest);
    }
    if (sub == "detach") {
        return parse_detach(rest);
    }
    if (sub == "apply") {
        return parse_apply(rest);
    }
    if (sub == "bypass") {
        return parse_bypass(rest);
    }
    throw CliError(std::format("unknown subcommand: '{}'", sub));
}

}  // namespace xdpmf
