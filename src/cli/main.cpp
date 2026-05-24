/*
 * main.cpp — entry point: parse argv, dispatch subcommand, map exceptions
 * to exit codes per design §4.1.
 */
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <format>
#include <string>
#include <system_error>
#include <variant>

#include "apply.hpp"  // §5.26 Q4 G1: apply subcommand dispatcher
#include "cli.hpp"
#include "lib/loader.hpp"

namespace {

constexpr int kExitOk        = 0;
constexpr int kExitUsageErr  = 1;

int run_attach(const xdpmf::AttachConfig& cfg)
{
    const auto prog_id = xdpmf::attach(cfg);
    const std::string line = std::format("attached prog id {} to {}\n",
                                         prog_id, cfg.iface);
    std::fputs(line.c_str(), stdout);
    return kExitOk;
}

int run_detach(const xdpmf::DetachConfig& cfg)
{
    // detach() returns 0 for the idempotent no-op paths (§5.21 D4) and
    // prints its own stdout message in those cases. Only emit the "real
    // detach" success line when a non-zero prog id was actually removed
    // — otherwise we'd double-print over loader.cpp's message.
    const auto prog_id = xdpmf::detach(cfg.iface);
    if (prog_id != 0) {
        const std::string line = std::format("detached prog id {} from {}\n",
                                             prog_id, cfg.iface);
        std::fputs(line.c_str(), stdout);
    }
    return kExitOk;
}

/* §5.26 Q4 G1: `apply -f <path> --iface <iface>` dispatcher. Mirrors
 * run_attach()'s stdout shape but routes through apply_config(), which
 * parses YAML, validates, and feeds internal::apply() (same atomic-swap
 * implementation backing the legacy attach path). */
int run_apply(const xdpmf::ApplyConfig& cfg)
{
    const auto prog_id = xdpmf::apply_config(cfg);
    const std::string line = std::format("applied config '{}' to {} (prog id {})\n",
                                         cfg.config_path, cfg.iface, prog_id);
    std::fputs(line.c_str(), stdout);
    return kExitOk;
}

/* Map an xdpmf LoaderError carried inside std::system_error directly to
 * its integer exit code. Non-loader system_errors fall back to LoadFailed
 * (2) — they are unexpected enough to warrant the "load problem" bucket. */
int exit_code_from(const std::system_error& e) noexcept
{
    const auto& code = e.code();
    if (code.category() == xdpmf::loader_error_category()) {
        return code.value();
    }
    return static_cast<int>(xdpmf::LoaderError::LoadFailed);
}

/* §5.26 stderr-shape contract: ConfigError messages MUST start with the
 * literal sentinel `xdpmacfilter: config error:` (Q-HG1 + Q5 + HG3 shape).
 * Our what() already embeds that sentinel; suppress the generic "error: "
 * prefix so the prefix matches the sentinel exactly. Other LoaderError
 * values keep the legacy "error: " prefix (unchanged stderr for MVP-2 tests). */
[[nodiscard]] bool is_config_error(const std::system_error& e) noexcept
{
    const auto& code = e.code();
    return code.category() == xdpmf::loader_error_category()
        && code.value() == static_cast<int>(xdpmf::LoaderError::ConfigError);
}

}  // namespace

int main(int argc, char* argv[])
{
    xdpmf::ParsedCommand cmd;
    try {
        cmd = xdpmf::parse(argc, argv);
    } catch (const xdpmf::CliError& e) {
        std::fprintf(stderr, "error: %s\n\n", e.what());
        std::fputs(xdpmf::usage_text().c_str(), stderr);
        return kExitUsageErr;
    }

    try {
        return std::visit(
            [](auto&& arg) -> int {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, xdpmf::HelpRequest>) {
                    std::fputs(xdpmf::usage_text().c_str(), stdout);
                    return kExitOk;
                } else if constexpr (std::is_same_v<T, xdpmf::VersionRequest>) {
                    std::fputs(xdpmf::version_text().c_str(), stdout);
                    return kExitOk;
                } else if constexpr (std::is_same_v<T, xdpmf::AttachConfig>) {
                    return run_attach(arg);
                } else if constexpr (std::is_same_v<T, xdpmf::DetachConfig>) {
                    return run_detach(arg);
                } else if constexpr (std::is_same_v<T, xdpmf::ApplyConfig>) {
                    return run_apply(arg);
                } else {
                    static_assert(sizeof(T) == 0, "unhandled ParsedCommand alternative");
                }
            },
            cmd);
    } catch (const std::system_error& e) {
        if (is_config_error(e)) {
            std::fprintf(stderr, "%s\n", e.what());
        } else {
            std::fprintf(stderr, "error: %s\n", e.what());
        }
        return exit_code_from(e);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return static_cast<int>(xdpmf::LoaderError::LoadFailed);
    }
}
