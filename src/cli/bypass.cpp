/*
 * bypass.cpp — `xdpmacfilter bypass` subcommand impl (§5.29 HG-3.4-2).
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

#include "lib/loader.hpp"

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
 * but never fails. Empty input → empty output (caller substitutes UNSPECIFIED). */
constexpr std::size_t kReasonMaxBytes = 256;

[[nodiscard]] std::string truncate_reason(std::string_view raw)
{
    if (raw.size() <= kReasonMaxBytes) {
        return std::string{raw};
    }
    /* Truncate to (cap - 3) bytes then append the ellipsis. The 3-byte
     * budget for "…" is fixed because we don't want the audit-log to grow
     * past the cap. Be careful not to cut inside a multi-byte UTF-8 sequence. */
    std::size_t cut = kReasonMaxBytes - 3;
    while (cut > 0 && (static_cast<unsigned char>(raw[cut]) & 0xC0u) == 0x80u) {
        --cut;
    }
    std::string out{raw.substr(0, cut)};
    out.append("\xE2\x80\xA6");  // U+2026
    return out;
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
        std::fprintf(stderr, "xdpmacfilter: bypass: --iface is required\n");
        return 1;
    }

    /* §5.29 HG-3.4-2: tty check. Both stdin AND stderr must be ttys for
     * the interactive flow; if either is non-tty (e.g. piped, redirected
     * to a file, run under systemd / cron / ansible), the operator MUST
     * pass --unsafe — the audit-safety gate. */
    const bool interactive = ::isatty(STDIN_FILENO) && ::isatty(STDERR_FILENO);
    if (!interactive && !cfg.unsafe) {
        std::fprintf(stderr,
                     "xdpmacfilter: refusing to bypass in non-interactive context "
                     "without --unsafe flag (audit safety)\n");
        return 1;
    }

    /* Interactive: y/N prompt is the safety gate. Non-y → no-op exit 0
     * (operator-cancelled; matches §5.29 grammar rule). */
    if (interactive && !cfg.unsafe) {
        if (!prompt_confirm_y_n(cfg.iface)) {
            std::fprintf(stderr, "xdpmacfilter: bypass cancelled by operator\n");
            return 0;
        }
    }

    /* §5.29 D-3.4-5: audit-log fires BEFORE the detach call so the
     * operator's INTENT is recorded even if the detach fails. The line
     * shape is fixed per §5.29 ERE and PI-30. */
    const std::string reason = cfg.reason.empty()
        ? std::string{"UNSPECIFIED"}
        : truncate_reason(cfg.reason);
    const auto uid = ::getuid();
    std::fprintf(stderr,
                 "xdpmacfilter: BYPASS activated on %s by uid=%u reason=\"%s\"\n",
                 cfg.iface.c_str(),
                 static_cast<unsigned int>(uid),
                 reason.c_str());

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
