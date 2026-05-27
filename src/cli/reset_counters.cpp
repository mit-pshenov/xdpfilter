/*
 * reset_counters.cpp — `xdpmacfilter reset-counters` subcommand impl
 * (§5.35 HG-3.4d-1..6, MVP-3.4d).
 *
 * Flow:
 *   1. iface-empty defense-in-depth check (parser already enforces).
 *   2. Build pin paths ${PIN_DIR}/<iface>/rule_counters_{a,b}; check
 *      inner_a pin existence (HG-3.4d-3 precondition canary).
 *   3. Emit audit-log line on stderr BEFORE the BPF map writes (HG-3.4d-6
 *      mirrors bypass shape; D-3.4-5 — log even if subsequent writes fail).
 *   4. Open inner_a + inner_b fds.
 *   5. Construct per-CPU zero buffer sized via libbpf_num_possible_cpus().
 *   6. Branch on rule_id: single-slot OR loop 0..63; writes zero into BOTH
 *      inner_a AND inner_b at each chosen slot (D-3.4d-RESET-BOTH —
 *      semantically idempotent vs subsequent active_idx flips).
 *   7. Return 0.
 *
 * BPF errors propagate as std::system_error → main.cpp catch arm → cli.error
 * → exit 2 (LoaderError::LoadFailed bucket).
 *
 * Per anti-misdiagnosis guard #9 (D-3.4d-6), helpers (`escape_audit_value`)
 * are DUPLICATED from bypass.cpp rather than extracted to a shared header.
 */
#include "reset_counters.hpp"

#include "common/logger.hpp"      // §5.32 (MVP-3.5) — structured-logging emit
#include "common/mac_filter.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <format>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <unistd.h>     // getuid, geteuid, close

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

namespace xdpmf {

namespace {

/* §5.35 D-3.4d-6 (guard #9): DUPLICATED from bypass.cpp's escape_audit_value.
 * Operator log-injection mitigation: backslash, double-quote, newline, CR,
 * NUL are escaped so the audit-line stays single-line + safe to embed in
 * double-quoted stderr fields. */
[[nodiscard]] std::string escape_audit_value(std::string_view raw)
{
    std::string out;
    out.reserve(raw.size());
    for (char raw_c : raw) {
        const auto c = static_cast<unsigned char>(raw_c);
        switch (c) {
            case '\\': out.append("\\\\"); break;
            case '"':  out.append("\\\""); break;
            case '\n': out.append("\\n");  break;
            case '\r': out.append("\\r");  break;
            case '\0': out.append("\\0");  break;
            default:   out.push_back(static_cast<char>(c)); break;
        }
    }
    return out;
}

/* Construct ${PIN_DIR}/<iface>/<basename>. */
[[nodiscard]] std::string pin_path_for(std::string_view iface,
                                        std::string_view basename)
{
    std::string out;
    out.reserve(std::string_view{XDPMF_BPFFS_ROOT}.size() + iface.size()
                + basename.size() + 2);
    out.append(XDPMF_BPFFS_ROOT);
    out.push_back('/');
    out.append(iface);
    out.push_back('/');
    out.append(basename);
    return out;
}

/* Open a pin via bpf_obj_get. Returns fd >= 0 on success; on failure throws
 * std::system_error so main.cpp's catch arm produces cli.error + exit 2. */
[[nodiscard]] int open_pin_strict(const std::string& path)
{
    const int fd = ::bpf_obj_get(path.c_str());
    if (fd < 0) {
        const int e = errno;
        throw std::system_error(
            e, std::generic_category(),
            std::format("bpf_obj_get('{}')", path));
    }
    return fd;
}

/* Apply a per-CPU zero write to one slot of one inner PERCPU_ARRAY.
 * Throws std::system_error on failure (rare; main.cpp maps to exit 2). */
void zero_one_slot(int inner_fd,
                    std::uint32_t rule_id,
                    const std::uint64_t* zero_buf,
                    std::string_view inner_name)
{
    const int rc = ::bpf_map_update_elem(inner_fd, &rule_id, zero_buf, BPF_ANY);
    if (rc < 0) {
        const int e = -rc;
        throw std::system_error(
            e, std::generic_category(),
            std::format("bpf_map_update_elem({}[{}])", inner_name, rule_id));
    }
}

}  // namespace

int reset_counters_main(const ResetCountersConfig& cfg)
{
    /* Defense-in-depth — parser already enforces non-empty iface. Following
     * bypass.cpp:129-138 precedent, route through cli.usage_error rather
     * than adding a reset_counters.usage_error to keep kEventNames lean
     * (§5.35 reset_counters.cpp body §3 + Phase 4.4 minimal-surface bias). */
    if (cfg.iface.empty()) {
        xdpmf::logger::emit(xdpmf::logger::Level::Error,
                            "cli.usage_error",
                            std::nullopt,
                            "xdpmacfilter: reset-counters: --iface is required\n");
        return 1;
    }

    /* §5.35 HG-3.4d-3 + §5.35 reset_counters body §3: open inner_a as the
     * precondition canary. If absent → iface is not attached → exit 1 with
     * the operator-grep-friendly stderr substring "no rule_counters pin". */
    const std::string inner_a_path = pin_path_for(cfg.iface,
                                                   XDPMF_MAP_RULE_COUNTERS_INNER_A_NAME);
    const int probe_fd = ::bpf_obj_get(inner_a_path.c_str());
    if (probe_fd < 0) {
        const int probe_errno = errno;
        if (probe_errno == ENOENT) {
            const std::string msg = std::format(
                "reset-counters: no rule_counters pin at {}; iface '{}' not attached?\n",
                inner_a_path, cfg.iface);
            const xdpmf::logger::Field fs[] = {
                xdpmf::logger::Field{"pin_path", std::string_view{inner_a_path}},
                xdpmf::logger::Field{"errno",    static_cast<std::int64_t>(probe_errno)},
            };
            xdpmf::logger::emit(xdpmf::logger::Level::Error,
                                "reset_counters.refused.no_pin",
                                std::string_view{cfg.iface}, msg, fs);
            return 1;
        }
        /* Any other open errno (EACCES, permission, transient fs) → bubble
         * up to main.cpp's system_error arm → cli.error → exit 2. */
        throw std::system_error(
            probe_errno, std::generic_category(),
            std::format("bpf_obj_get('{}')", inner_a_path));
    }
    /* probe_fd opened OK; we'll re-open below for clarity but could reuse.
     * Reusing is fine — keep impl simple and reopen once we have inner_b. */
    (void)::close(probe_fd);

    /* §5.35 HG-3.4d-6: audit-log fires BEFORE the BPF map writes so the
     * operator's INTENT is recorded even if the writes fail (D-3.4-5
     * precedent from bypass). Mirrors bypass.cpp:174 verbatim shape +
     * substitutes `reason="..."` with `rule_id=<N|ALL>` per HG-3.4d-6 ERE. */
    const auto uid  = ::getuid();
    const auto euid = ::geteuid();
    const char* sudo_user_env = std::getenv("SUDO_USER");
    const bool        have_sudo_user = sudo_user_env != nullptr
                                     && *sudo_user_env != '\0';
    const std::string sudo_user_raw = have_sudo_user
        ? std::string{sudo_user_env}
        : std::string{"<none>"};
    const std::string sudo_user_audit = have_sudo_user
        ? escape_audit_value(sudo_user_raw)
        : std::string{"<none>"};
    const std::string rule_id_str = cfg.rule_id.has_value()
        ? std::to_string(*cfg.rule_id)
        : std::string{"ALL"};
    const std::string audit_msg = std::format(
        "xdpmacfilter: RESET-COUNTERS on {} by uid={} euid={} "
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

    /* Open BOTH inner fds (D-3.4d-RESET-BOTH). inner_a's existence was
     * already confirmed; inner_b's absence here would mean a partial
     * attach (broken state) — surface as system_error → exit 2. */
    const int inner_a_fd = open_pin_strict(inner_a_path);
    int inner_b_fd = -1;
    try {
        const std::string inner_b_path = pin_path_for(cfg.iface,
                                                       XDPMF_MAP_RULE_COUNTERS_INNER_B_NAME);
        inner_b_fd = open_pin_strict(inner_b_path);
    } catch (...) {
        (void)::close(inner_a_fd);
        throw;
    }

    /* §5.35 HG-3.4d-1: per-CPU zero buffer sized to libbpf_num_possible_cpus().
     * std::vector zero-initializes by default — buffer is N×u64 of zeros. */
    const int num_cpus = ::libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        (void)::close(inner_a_fd);
        (void)::close(inner_b_fd);
        throw std::system_error(
            EINVAL, std::generic_category(),
            std::format("libbpf_num_possible_cpus returned {}", num_cpus));
    }
    std::vector<std::uint64_t> zero_per_cpu(static_cast<std::size_t>(num_cpus), 0u);

    try {
        /* §5.35 Q2.A + D-3.4d-RESET-BOTH: branch on rule_id selection; in
         * both branches we zero BOTH inner_a AND inner_b at each chosen
         * slot. Per-slot failure → throw; caller's catch closes fds. */
        if (cfg.rule_id.has_value()) {
            const std::uint32_t rid = *cfg.rule_id;
            zero_one_slot(inner_a_fd, rid, zero_per_cpu.data(),
                          XDPMF_MAP_RULE_COUNTERS_INNER_A_NAME);
            zero_one_slot(inner_b_fd, rid, zero_per_cpu.data(),
                          XDPMF_MAP_RULE_COUNTERS_INNER_B_NAME);
        } else {
            for (std::uint32_t rid = 0;
                 rid < static_cast<std::uint32_t>(XDPMF_RULE_COUNTERS_MAX);
                 ++rid) {
                zero_one_slot(inner_a_fd, rid, zero_per_cpu.data(),
                              XDPMF_MAP_RULE_COUNTERS_INNER_A_NAME);
                zero_one_slot(inner_b_fd, rid, zero_per_cpu.data(),
                              XDPMF_MAP_RULE_COUNTERS_INNER_B_NAME);
            }
        }
    } catch (...) {
        (void)::close(inner_a_fd);
        (void)::close(inner_b_fd);
        throw;
    }

    (void)::close(inner_a_fd);
    (void)::close(inner_b_fd);
    return 0;
}

}  // namespace xdpmf
