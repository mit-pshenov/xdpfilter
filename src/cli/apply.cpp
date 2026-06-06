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
 * Exit-code split (§5.26 Q4 + §5.30 D-3.4.5-5 / HK-1):
 *   - File-IO failure on `-f <path>` (missing, unreadable, short read) →
 *     throw `xdpmf::CliError` ("usage" exit 1). main.cpp's SECOND try
 *     block carries a `catch (CliError)` arm that renders the message and
 *     returns kExitUsageErr — this is the HK-1 fix; prior to it the
 *     missing-file path leaked out of the visit body and tripped the
 *     std::exception arm (exit 2 LoadFailed, wrong per §4.1).
 *   - YAML parse / schema-validation failure of a file that DOES exist →
 *     throw `std::system_error{LoaderError::ConfigError}` (exit 9). Caught
 *     by main.cpp's existing system_error arm; the §5.26 sentinel prefix
 *     `xdpfilter: config error:` is preserved verbatim for the
 *     T_EXIT_CODE_9_ON_CONFIG_ERROR ERE match.
 */
#include "apply.hpp"
#include "cli.hpp"   // CliError — usage-error exit (exit 1) for file-IO failure

#include "lib/apply_internal.hpp"
#include "lib/config.hpp"
#include "lib/loader.hpp"
#include "lib/map_image.hpp"  // §5.77 (MVP-4.37) B44: render_dryrun_image (offline)
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
    // §5.26 Q4 + §5.30 HK-1 (D-3.4.5-5): file-IO failure = CLI usage error
    // (exit 1) via CliError. Parse / schema failure = ConfigError (exit 9)
    // thrown by yaml::parse and config::validate respectively. Both flavours
    // emit the unified `xdpfilter: config error:` stderr prefix so
    // operators / log scrapers grep on a single sentinel; the exit code is
    // the discriminator (1 = file-IO upstream of YAML; 9 = YAML/schema).
    // T_APPLY_EXITS_1_ON_MISSING_CONFIG asserts on the prefix + exit 1.
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        throw CliError(std::format(
            "xdpfilter: config error: open {}: No such file or directory", path));
    }
    const std::streamsize sz = ifs.tellg();
    if (sz < 0) {
        throw CliError(std::format(
            "xdpfilter: config error: tellg failed on {}", path));
    }
    constexpr std::streamsize kMax = 1 * 1024 * 1024;  // 1 MiB
    if (sz > kMax) {
        // Q-HG1 size cap. File exists but is too big → ConfigError 9 per
        // Q-HG1 sentinel "config file exceeds 1 MiB limit" stderr.
        throw std::system_error(
            make_error_code(LoaderError::ConfigError),
            std::format("xdpfilter: config error: config file exceeds 1 MiB limit: {}", path));
    }
    ifs.seekg(0, std::ios::beg);
    std::string buf;
    buf.resize(static_cast<std::size_t>(sz));
    if (sz > 0 && !ifs.read(buf.data(), sz)) {
        throw CliError(std::format(
            "xdpfilter: config error: short read on {}", path));
    }
    return buf;
}

/* §5.26 Q4 + §5.77 (MVP-4.37) B44: read+parse+validate the YAML at
 * cfg.config_path and reconcile its `interface:` field with cfg.iface. The
 * SINGLE load/validate/reconcile path shared by live `apply_config` AND the
 * offline `dryrun_image_for_file` — so a dry-run of an invalid config errors
 * EXACTLY as the live apply would (same exit codes 1/9). */
[[nodiscard]] Config load_and_reconcile(const ApplyConfig& cfg)
{
    const std::string yaml_src = read_file_or_throw(cfg.config_path);
    const yaml::Node  root     = yaml::parse(yaml_src, cfg.config_path);
    const Config      parsed   = validate(root, cfg.config_path);

    // §5.26 Q4: interface reconciliation. If the file declares
    // `interface: <Y>` and CLI --iface is <X> with Y != X → ConfigError 9.
    if (parsed.iface.has_value() && *parsed.iface != cfg.iface) {
        throw std::system_error(
            make_error_code(LoaderError::ConfigError),
            std::format("xdpfilter: config error: interface mismatch "
                        "(file declares '{}', --iface is '{}'): {}",
                        *parsed.iface, cfg.iface, cfg.config_path));
    }
    return parsed;
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
    const Config parsed = load_and_reconcile(cfg);
    return apply_config_inmemory(cfg.iface, parsed, cfg.mode);
}

/* §5.77 (MVP-4.37) B44 D-mvp-4.37-BRANCH-SITE: the offline dry-run render. Same
 * load/validate/reconcile path as live apply (so a bad file/schema/iface errors
 * identically — exit 1/9), then render the frozen map-image with ZERO kernel
 * calls. Never reaches apply_config/apply_request. */
std::string dryrun_image_for_file(const ApplyConfig& cfg)
{
    const Config parsed = load_and_reconcile(cfg);
    return render_dryrun_image(parsed);
}

}  // namespace xdpmf
