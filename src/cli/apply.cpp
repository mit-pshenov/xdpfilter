/*
 * apply.cpp — apply orchestrator implementation (design §5.26 Q4 G1).
 *
 * Drives:
 *   apply_config(ApplyConfig)             → read YAML file → parse → validate → apply
 *   apply_config_inmemory(iface, Config)  → (already-parsed Config) → apply
 *
 * Both funnel through internal::apply() in src/lib/apply_internal.hpp so
 * the atomic-swap semantics (active_idx flip + ruleset/defaults population)
 * are defined exactly once across the codebase.
 *
 * File-IO failures on the config path → exit 1 (CLI usage error) thrown as
 *   std::system_error{LoaderError::LoadFailed} (main.cpp's catch-arm renders
 *   exit-code from LoaderError::value); reading the YAML body is OK to
 *   surface as LoadFailed because the caller's CLI-error catch already
 *   ran above (parse() in cli.cpp does NOT raise CliError on missing file
 *   — only on bad arg shape).
 *
 * Per §5.26 Q4: file-IO failure is a CLI usage error (exit 1) whereas
 * parse/schema failure is ConfigError (exit 9). To keep the cli.cpp
 * surface small, we surface file-IO failure here with a dedicated stderr
 * message and a thrown system_error mapped to a fresh error_code value
 * outside the LoaderError category — main.cpp's catch falls back to
 * LoadFailed (exit 2) for anything not in loader_error_category. That's
 * the wrong exit code per §5.26 Q4.
 *
 * Resolution: use a thin custom exception `ApplyFileIoError` whose what()
 * carries the operator-facing message; main.cpp's existing CliError-style
 * catch arm needs a matching arm. We add it in main.cpp.
 */
#include "apply.hpp"
#include "cli.hpp"   // CliError — usage-error exit (exit 1) for file-IO failure

#include "lib/apply_internal.hpp"
#include "lib/config.hpp"
#include "lib/loader.hpp"
#include "lib/yaml_subset.hpp"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <format>
#include <string>
#include <system_error>
#include <vector>

namespace xdpmf {

namespace {

/* §5.26 Q4: read the YAML file. File-IO failure (missing, unreadable, too
 * big) → throw with a "usage-error" shape; the caller in cli.cpp / main.cpp
 * maps it to exit 1. The 1 MiB cap (Q-HG1 DoS guard) is enforced HERE
 * BEFORE invoking the parser so we can use a CLI-usage-friendly message;
 * yaml::parse() also enforces it (defense in depth). */
[[nodiscard]] std::string read_file_or_throw(const std::string& path)
{
    // §5.26 Q4: file-IO failure = CLI usage error (exit 1) via CliError.
    // Parse / schema failure = ConfigError (exit 9) thrown by yaml::parse
    // and config::validate respectively. Operators tell the two apart by
    // exit code AND by stderr shape ("apply:" prefix vs "config error:" prefix).
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        throw CliError(std::format("apply: config file '{}' does not exist or is unreadable", path));
    }
    const std::streamsize sz = ifs.tellg();
    if (sz < 0) {
        throw CliError(std::format("apply: config file '{}' tellg failed", path));
    }
    constexpr std::streamsize kMax = 1 * 1024 * 1024;  // 1 MiB
    if (sz > kMax) {
        // Q-HG1 size cap. File exists but is too big → ConfigError 9 per
        // Q-HG1 sentinel "config file exceeds 1 MiB limit" stderr.
        throw std::system_error(
            make_error_code(LoaderError::ConfigError),
            std::format("xdpmacfilter: config error: config file exceeds 1 MiB limit: {}", path));
    }
    ifs.seekg(0, std::ios::beg);
    std::string buf;
    buf.resize(static_cast<std::size_t>(sz));
    if (sz > 0 && !ifs.read(buf.data(), sz)) {
        throw CliError(std::format("apply: short read on config file '{}'", path));
    }
    return buf;
}

}  // namespace

std::uint32_t apply_config_inmemory(const std::string& iface,
                                    const Config&      parsed,
                                    XdpMode            mode)
{
    /* Per §5.26 EDIT-1: pass the validated Config straight through to
     * internal::apply_request — pass-MAC extraction + default_action
     * unpacking are impl-side concerns of the internal helper. */
    return internal::apply_request(internal::ApplyRequest{iface, mode, parsed});
}

std::uint32_t apply_config(const ApplyConfig& cfg)
{
    const std::string yaml_src = read_file_or_throw(cfg.config_path);
    const yaml::Node  root     = yaml::parse(yaml_src, cfg.config_path);
    const Config      parsed   = validate(root, cfg.config_path);

    // §5.26 Q4: interface reconciliation. If the file declares
    // `interface: <Y>` and CLI --iface is <X> with Y != X → ConfigError 9.
    if (parsed.iface.has_value() && *parsed.iface != cfg.iface) {
        throw std::system_error(
            make_error_code(LoaderError::ConfigError),
            std::format("xdpmacfilter: config error: interface mismatch "
                        "(file declares '{}', --iface is '{}'): {}",
                        *parsed.iface, cfg.iface, cfg.config_path));
    }
    return apply_config_inmemory(cfg.iface, parsed, cfg.mode);
}

}  // namespace xdpmf
