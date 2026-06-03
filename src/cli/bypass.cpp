/*
 * bypass.cpp — `xdpfilter bypass` subcommand impl (§5.29 HG-3.4-2).
 *
 * Flow:
 *   1. tty-check (isatty on stdin AND stderr); if either is non-tty AND
 *      cfg.unsafe == false → emit refusal + exit 1 (audit safety gate).
 *   2. Interactive path: prompt y/N on stderr; anything other than y/Y/yes
 *      cancels (exit 0, no detach). Per §5.29 CLI grammar rules.
 *   3. Emit audit-log line on stderr BEFORE calling loader::detach() (D-3.4-5
 *      — log even if detach fails, so the operator's intent is recorded).
 *   4. Invoke loader::detach(iface); propagate std::system_error to main.cpp's
 *      catch arm for exit-code mapping (typically exit 5 on failure).
 *
 * Reason length cap: 256 bytes; longer truncated with U+2026 ("…") per the
 * §5.29 grammar — audit-log MUST succeed (no exit on long reason).
 */
#include "bypass.hpp"

#include "common/escape_util.hpp"  // §5.37 (MVP-3.4f) — escape_audit
#include "common/logger.hpp"       // §5.32 (MVP-3.5) — structured-logging emit
#include "lib/loader.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <string>
#include <string_view>

#include <unistd.h>   // isatty, getuid, STDIN_FILENO, STDERR_FILENO

namespace xdpmf {

namespace {

/* §5.29 CLI grammar: 256-byte reason cap. Truncate with the U+2026 ellipsis
 * sigil (3 UTF-8 bytes: 0xE2 0x80 0xA6) so the audit-log is visibly truncated
 * but never fails. Empty input → empty output (caller substitutes UNSPECIFIED).
 *
 * §5.30 HK-4 (MVP-3.4.5): truncation budget is 253 bytes (leaving 3 for the
 * ellipsis); inputs ≤253 pass through untruncated, >253 get rewind-safe UTF-8
 * truncation + ellipsis. After truncation we ALSO escape control bytes per
 * `prom_format::escape_label_value`-style discipline (\ -> \\, " -> \", \n
 * -> \\n, \r -> \\r, \0 -> \\0) — §5.37 (MVP-3.4f) D-3.4f-3 extends this
 * policy to escape ALL bytes in {[0x01,0x08] ∪ {0x0B,0x0C} ∪ [0x0E,0x1F] ∪
 * {0x7F}} as `\xHH` (operator log-injection mitigation; sec M1 closure).
 * The escape helper now lives in src/common/escape_util.cpp; this TU just
 * delegates via `xdpmf::escape_util::escape_audit`. */
constexpr std::size_t kReasonMaxBytes        = 256;
constexpr std::size_t kReasonTruncationBudget = 253;  // 256 - 3 for "…"

/* Truncate raw operator reason to the 253+3-byte budget WITHOUT applying
 * the audit-escape. Returns the truncated-only form — caller applies
 * xdpmf::escape_util::escape_audit separately to build the audit-line msg,
 * OR passes the raw-truncated form to logger's JSON fields where logger's
 * own escape_json handles quoting (avoids double-escape — §5.32 PI-3.5-5
 * contract). */
[[nodiscard]] std::string truncate_reason_raw(std::string_view raw)
{
    std::string truncated;
    if (raw.size() > kReasonTruncationBudget) {
        std::size_t cut = kReasonTruncationBudget;
        /* UTF-8 rewind-safety: if `cut` falls on a continuation byte
         * (0b10xxxxxx), step back to the leading byte boundary so we never
         * emit a half-codepoint. Worst-case rewind is 3 bytes (4-byte
         * codepoint started at cut-3). */
        while (cut > 0 && (static_cast<unsigned char>(raw[cut]) & 0xC0u) == 0x80u) {
            --cut;
        }
        truncated.assign(raw.substr(0, cut));
        truncated.append("\xE2\x80\xA6");  // U+2026 ELLIPSIS (3 UTF-8 bytes)
    } else {
        truncated.assign(raw);
    }
    /* Sanity guard — defensive cap; kReasonMaxBytes is the hard ceiling. */
    if (truncated.size() > kReasonMaxBytes) {
        truncated.resize(kReasonMaxBytes);
    }
    return truncated;
}

/* Interactive y/N prompt — reads ONE line from stdin. Accept exactly 'y',
 * 'Y', "yes", "YES" (case-insensitive single-word forms). Anything else
 * (including EOF) → caller exits 0 with cancellation notice. */
[[nodiscard]] bool prompt_confirm_y_n(std::string_view iface)
{
    std::fprintf(stderr, "BYPASS will detach XDP filter on %s. Continue? [y/N]: ",
                 std::string{iface}.c_str());
    std::fflush(stderr);

    std::string line;
    int ch;
    while ((ch = std::getchar()) != EOF && ch != '\n') {
        line.push_back(static_cast<char>(ch));
    }
    /* trim trailing whitespace */
    while (!line.empty()
           && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r')) {
        line.pop_back();
    }
    if (line.size() == 1) {
        return line[0] == 'y' || line[0] == 'Y';
    }
    if (line.size() == 3) {
        return (line[0] == 'y' || line[0] == 'Y')
            && (line[1] == 'e' || line[1] == 'E')
            && (line[2] == 's' || line[2] == 'S');
    }
    return false;
}

}  // namespace

int bypass_main(const BypassConfig& cfg)
{
    /* §5.29 CLI grammar: --iface is REQUIRED + non-empty. Parser already
     * enforces; this is a defense-in-depth check (also documents the
     * function's preconditions for any non-CLI caller). */
    if (cfg.iface.empty()) {
        /* §5.32 (MVP-3.5) PI-3.5-1 byte-equivalent text-mode emission. */
        xdpmf::logger::emit(xdpmf::logger::Level::Error,
                            "bypass.usage_error",
                            std::nullopt,
                            "xdpfilter: bypass: --iface is required\n");
        return 1;
    }

    /* §5.29 HG-3.4-2: tty check. Both stdin AND stderr must be ttys for
     * the interactive flow; if either is non-tty (e.g. piped, redirected
     * to a file, run under systemd / cron / ansible), the operator MUST
     * pass --unsafe — the audit-safety gate. */
    const bool interactive = ::isatty(STDIN_FILENO) && ::isatty(STDERR_FILENO);
    if (!interactive && !cfg.unsafe) {
        const xdpmf::logger::Field fs[] = {
            xdpmf::logger::Field{"interactive", false},
            xdpmf::logger::Field{"unsafe",      cfg.unsafe},
        };
        xdpmf::logger::emit(xdpmf::logger::Level::Error,
                            "bypass.refused.requires_unsafe",
                            std::string_view{cfg.iface},
                            "xdpfilter: refusing to bypass in non-interactive context "
                            "without --unsafe flag (audit safety)\n",
                            fs);
        return 1;
    }

    /* Interactive: y/N prompt is the safety gate. Non-y → no-op exit 0
     * (operator-cancelled; matches §5.29 grammar rule). The prompt itself
     * at prompt_confirm_y_n (line 96) is EXEMPT from logger conversion per
     * §5.32 D-3.5-7 / PI-3.5-6 — UI primitive, not a log event. */
    if (interactive && !cfg.unsafe) {
        if (!prompt_confirm_y_n(cfg.iface)) {
            xdpmf::logger::emit(xdpmf::logger::Level::Info,
                                "bypass.cancelled",
                                std::string_view{cfg.iface},
                                "xdpfilter: bypass cancelled by operator\n");
            return 0;
        }
    }

    /* §5.29 D-3.4-5: audit-log fires BEFORE the detach call so the
     * operator's INTENT is recorded even if the detach fails. The line
     * shape is fixed per §5.29 ERE and PI-30.
     *
     * §5.30 HK-4 (MVP-3.4.5, D-3.4.5-8): the line gains TWO new structural
     * fields after uid=, in fixed order: euid=<EUID> and
     * sudo_user="<SUDO_USER or <none>>". `<none>` is the explicit sentinel
     * for null/empty SUDO_USER (NOT empty quotes, NOT the literal "null") —
     * mirrors UNSPECIFIED for reason. Both euid AND sudo_user are emitted
     * ALWAYS so operators grep on stable field positions. reason="..."
     * remains the last structural field for backward-compat regex matchers. */
    /* §5.32 (MVP-3.5) PI-3.5-5: keep TWO views of reason + sudo_user — the
     * audit-escaped form goes into the text-mode msg (preserving HK-4
     * byte-equivalence); the RAW-truncated form goes into the JSON
     * `fields.reason` so logger's escape_json (§5.37) handles quoting on
     * its own (avoids double-escape: jq-decoded `.fields.reason` matches
     * the operator's input verbatim per design §6.56). */
    const std::string reason_raw = cfg.reason.empty()
        ? std::string{"UNSPECIFIED"}
        : truncate_reason_raw(cfg.reason);
    const std::string reason_audit = cfg.reason.empty()
        ? std::string{"UNSPECIFIED"}
        : xdpmf::escape_util::escape_audit(reason_raw);
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
    /* §5.32 (MVP-3.5) HG-3.5-3 + PI-3.5-5: text-mode emits the audit-line
     * byte-equivalent to MVP-3.4.5 HK-4 (PI-3.5-1); JSON-mode also exposes
     * the HK-4 structural fields (uid, euid, sudo_user, reason) inside the
     * envelope's fields:{} so operators can query
     *   jq 'select(.event=="bypass.activated" and .fields.sudo_user=="alice")'
     * without prose-grepping. */
    const std::string audit_msg = std::format(
        "xdpfilter: BYPASS activated on {} by uid={} euid={} "
        "sudo_user=\"{}\" reason=\"{}\"\n",
        cfg.iface,
        static_cast<unsigned int>(uid),
        static_cast<unsigned int>(euid),
        sudo_user_audit,
        reason_audit);
    const xdpmf::logger::Field activated_fields[] = {
        xdpmf::logger::Field{"uid",       static_cast<std::int64_t>(uid)},
        xdpmf::logger::Field{"euid",      static_cast<std::int64_t>(euid)},
        xdpmf::logger::Field{"sudo_user", std::string_view{sudo_user_raw}},
        xdpmf::logger::Field{"reason",    std::string_view{reason_raw}},
    };
    xdpmf::logger::emit(xdpmf::logger::Level::Info,
                        "bypass.activated",
                        std::string_view{cfg.iface},
                        audit_msg,
                        activated_fields);

    /* Invoke the existing detach codepath. Throws std::system_error{
     * LoaderError::DetachFailed, ...} on real failure; main.cpp's catch
     * arm maps that to exit 5. Idempotent no-op (§5.21 D4) returns 0. */
    const std::uint32_t prog_id = ::xdpmf::detach(cfg.iface);
    if (prog_id != 0) {
        const std::string line = std::format("detached prog id {} from {}\n",
                                             prog_id, cfg.iface);
        std::fputs(line.c_str(), stdout);
    }
    return 0;
}

}  // namespace xdpmf
