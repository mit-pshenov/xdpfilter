/*
 * reset_counters.cpp — `xdpfilter reset-counters` subcommand impl
 * (§5.35 HG-3.4d-1..6 MVP-3.4d; §5.36 MVP-3.4e KC-3 reset-counters limb).
 *
 * Post-§5.36 (D-3.4e-PROBE-PLACEMENT FINAL A.2) the CLI translation unit
 * shrinks to:
 *   1. defense-in-depth empty-iface check (cli.usage_error; parser already
 *      enforces this — kept for symmetry with bypass.cpp:129-138);
 *   2. audit-log `reset_counters.activated` emission BEFORE the loader
 *      call (HG-3.4d-6 mirrors bypass.activated shape; D-3.4-5 guarantees
 *      the operator INTENT is recorded even if the loader throws);
 *   3. invoke `xdpmf::internal::reset_counters_request(req)` — this
 *      composes the §5.22 BpffsRootFd / iface_entry_is_real_dir primitives
 *      BEFORE any pin path is built (KC-3 closure);
 *   4. return 0 on success; std::system_error propagates to main.cpp's
 *      existing catch arm which maps LoaderError to exit codes (PathRefused
 *      → 8; LoadFailed → 2; etc.).
 *
 * Helpers removed from this TU per §5.36 D-3.4e-PROBE-PLACEMENT:
 *   - pin_path_for       (path-construction now lives in loader.cpp
 *                          AFTER validate_iface_name + iface_entry_is_real_dir)
 *   - open_pin_strict    (bpf_obj_get call-sites moved to loader.cpp)
 *   - zero_one_slot      (bpf_map_update_elem moved to loader.cpp)
 *
 * §5.37 (MVP-3.4f) — D-3.4d-6 DUP-INTENT escape helper PARTIALLY SUPERSEDED:
 * the local `escape_audit_value` body is gone (rule-of-three extraction to
 * src/common/escape_util.cpp). The `sudo_user` env-lookup half stays
 * duplicated at 2 call-sites (here + bypass.cpp) under guard #9 — below
 * rule-of-three threshold for now (NEW §7 OOS fence).
 *
 * The reset_counters.refused.no_pin event NOW emits from loader.cpp's
 * reset_counters_request body at the iface_entry_is_real_dir-returns-false
 * branch (D-3.4e-PROBE-PLACEMENT FINAL A.2). The event NAME is preserved
 * for log-shipping pipeline stability.
 */
#include "reset_counters.hpp"

#include "common/escape_util.hpp" // §5.37 (MVP-3.4f) — escape_audit
#include "common/logger.hpp"      // §5.32 (MVP-3.5) — structured-logging emit
#include "lib/apply_internal.hpp" // §5.36 — internal::reset_counters_request

#include <cstdint>
#include <cstdlib>
#include <format>
#include <string>
#include <string_view>

#include <unistd.h>     // getuid, geteuid

namespace xdpmf {

int reset_counters_main(const ResetCountersConfig& cfg)
{
    /* Defense-in-depth — parser already enforces non-empty iface. Following
     * bypass.cpp:129-138 precedent, route through cli.usage_error rather
     * than adding a reset_counters.usage_error to keep kEventNames lean
     * (§5.35 reset_counters.cpp body §3 + Phase 4.4 minimal-surface bias).
     *
     * The internal::reset_counters_request helper ALSO rejects empty iface
     * via validate_iface_name (with PathRefused → exit 8). Keeping the CLI
     * empty-check separate produces the operator-friendly cli.usage_error
     * + exit 1 for the trivial mistake, distinct from the security-hardened
     * exit 8 for path-traversal-shaped inputs. */
    if (cfg.iface.empty()) {
        xdpmf::logger::emit(xdpmf::logger::Level::Error,
                            "cli.usage_error",
                            std::nullopt,
                            "xdpfilter: reset-counters: --iface is required\n");
        return 1;
    }

    /* §5.35 HG-3.4d-6: audit-log fires BEFORE the loader call so the
     * operator's INTENT is recorded even if the helper throws (D-3.4-5
     * precedent from bypass). Mirrors bypass.cpp:174 verbatim shape +
     * substitutes `reason="..."` with `rule_id=<N|ALL>` per HG-3.4d-6 ERE.
     *
     * §5.36 note: emission UNCHANGED — the audit-log shape is operator-
     * facing stable; only the post-emit code path now routes through
     * internal::reset_counters_request instead of bpf_obj_get-in-CLI. */
    const auto uid  = ::getuid();
    const auto euid = ::geteuid();
    const char* sudo_user_env = std::getenv("SUDO_USER");
    const bool        have_sudo_user = sudo_user_env != nullptr
                                     && *sudo_user_env != '\0';
    const std::string sudo_user_raw = have_sudo_user
        ? std::string{sudo_user_env}
        : std::string{"<none>"};
    const std::string sudo_user_audit = have_sudo_user
        ? xdpmf::escape_util::escape_audit(sudo_user_raw)
        : std::string{"<none>"};
    const std::string rule_id_str = cfg.rule_id.has_value()
        ? std::to_string(*cfg.rule_id)
        : std::string{"ALL"};
    const std::string audit_msg = std::format(
        "xdpfilter: RESET-COUNTERS on {} by uid={} euid={} "
        "sudo_user=\"{}\" rule_id={}\n",
        cfg.iface,
        static_cast<unsigned int>(uid),
        static_cast<unsigned int>(euid),
        sudo_user_audit,
        rule_id_str);
    const xdpmf::logger::Field activated_fields[] = {
        xdpmf::logger::Field{"uid",       static_cast<std::int64_t>(uid)},
        xdpmf::logger::Field{"euid",      static_cast<std::int64_t>(euid)},
        xdpmf::logger::Field{"sudo_user", std::string_view{sudo_user_raw}},
        xdpmf::logger::Field{"rule_id",   std::string_view{rule_id_str}},
    };
    xdpmf::logger::emit(xdpmf::logger::Level::Info,
                        "reset_counters.activated",
                        std::string_view{cfg.iface},
                        audit_msg,
                        activated_fields);

    /* §5.36 HG-3.4e-1 + EDIT-1: route through the internal helper.
     * ALL hardening + map-write logic lives there:
     *   - return true  → success; CLI returns 0.
     *   - return false → iface NOT attached (event already emitted by
     *                    the helper); CLI returns 1 (preserves §5.35
     *                    T_CLI_RESET_COUNTERS_NO_IFACE expectation).
     *   - throws std::system_error → main.cpp's catch arm maps to exit:
     *       PathRefused (shape-bad iface or symlink at root/iface) → 8
     *       LoadFailed (partial-attach BPF state)                  → 2
     *       other                                                  → 2
     */
    xdpmf::internal::ResetCountersRequest req{};
    req.iface   = cfg.iface;
    req.rule_id = cfg.rule_id;
    const bool ok = xdpmf::internal::reset_counters_request(req);
    return ok ? 0 : 1;
}

}  // namespace xdpmf
