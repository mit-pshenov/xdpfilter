/*
 * logger.cpp — structured-logging implementation (§5.32 MVP-3.5).
 *
 * Lazy-initialized format selector reads XDPMF_LOG_FORMAT once at the first
 * emit() call (Q4 R1, std::once_flag). Text mode is byte-equivalent to the
 * pre-§5.32 emission (PI-3.5-1 load-bearing canary). JSON mode emits one
 * NDJSON object per event with a fixed-order envelope per HG-3.5-2.
 *
 * §5.37 (MVP-3.4f): Theme B rule-of-three extraction — `json_escape` +
 * `format_timestamp_utc` MOVED to src/common/escape_util.{hpp,cpp} (D-3.4f-1
 * supersedes D-3.5-2's duplication directive). Call-sites use the
 * `xdpmf::escape_util::escape_json` / `::format_timestamp_utc` FQNs.
 *
 * NO external build dependency (PI-3.5-7): stdlib only.
 */
#include "common/logger.hpp"

#include "common/escape_util.hpp"  // §5.37 (MVP-3.4f) — escape_json + format_timestamp_utc

#include <cstdio>
#include <cstdlib>
#include <format>
#include <mutex>
#include <string>
#include <string_view>

namespace xdpmf::logger {

namespace {

/* §5.32 env-var constant. Mirrors §5.26's kTrustModelEnv at loader.cpp:1000. */
constexpr std::string_view kLogFormatEnv{"XDPMF_LOG_FORMAT"};
constexpr std::string_view kLogFormatTextValue{"text"};
constexpr std::string_view kLogFormatJsonValue{"json"};

/* Module-static cached format. Initialized lazily on the first emit() under
 * `g_init_once`; subsequent emits read without acquiring the once_flag's
 * lock (the call_once "already done" fast path is a single relaxed load). */
Format         g_format = Format::Text;
std::once_flag g_init_once;
/* When the env-var carries an unknown value, the lazy init queues a one-shot
 * WARN to fire AFTER the format is set to Text — emitting it from inside
 * call_once would recurse into emit() before initialization completes. */
bool        g_emit_unknown_warn = false;
std::string g_unknown_warn_value;

/* §5.37 (MVP-3.4f) D-3.4f-1: `json_escape` + `format_timestamp_utc`
 * extracted to src/common/escape_util.{hpp,cpp} under namespace
 * `xdpmf::escape_util`. D-3.5-2's "duplicate-don't-extract" directive
 * SUPERSEDED by the rule-of-three escape valve (3rd JSON emitter surfaced;
 * /mint-review Theme B 3-dim cross-validation). Call-sites use the
 * fully-qualified `xdpmf::escape_util::escape_json` / `::format_timestamp_utc`
 * — see render_field_value + build_json_line below. */

[[nodiscard]] constexpr std::string_view level_str(Level lvl) noexcept
{
    switch (lvl) {
        case Level::Info:  return "info";
        case Level::Warn:  return "warn";
        case Level::Error: return "error";
    }
    return "info";  // unreachable — enum is closed
}

/* Q4 R1 + D-3.5-8: read XDPMF_LOG_FORMAT exactly once. Unset OR empty OR
 * exact literal "text" → Text. Exact literal "json" → Json. Any other value
 * → queue a one-shot WARN to fire post-init + default Text. Per PI-3.5-3,
 * empty-string is silent-Text (treated as absent), not WARN. */
void init_format()
{
    const char* raw = std::getenv(kLogFormatEnv.data());
    if (raw == nullptr || raw[0] == '\0') {
        g_format = Format::Text;
        return;
    }
    const std::string_view value{raw};
    if (value == kLogFormatJsonValue) {
        g_format = Format::Json;
        return;
    }
    if (value == kLogFormatTextValue) {
        g_format = Format::Text;
        return;
    }
    /* Unknown value: queue WARN to fire AFTER call_once returns so the
     * recursive emit() observes g_format already set to Text and does NOT
     * re-enter init_format. */
    g_format             = Format::Text;
    g_unknown_warn_value = value;
    g_emit_unknown_warn  = true;
}

/* Write a string to stderr via fprintf — never throws. Failure (e.g. closed
 * stderr, EIO) is silently dropped per D-3.5-4: there is no recovery path
 * for a stderr write failure (logging the log failure would loop). */
void write_stderr(std::string_view s) noexcept
{
    /* %.*s avoids requiring s to be NUL-terminated. fprintf returns negative
     * on error; we ignore it. */
    (void)std::fprintf(stderr, "%.*s", static_cast<int>(s.size()), s.data());
}

/* Render a Field's value as a JSON scalar. string_view gets quoted + escaped;
 * int64_t prints as decimal; bool prints `true`/`false`; nullptr prints
 * `null`. */
void render_field_value(std::string& out, const FieldValue& fv)
{
    if (const auto* sv = std::get_if<std::string_view>(&fv)) {
        out.push_back('"');
        out.append(xdpmf::escape_util::escape_json(*sv));
        out.push_back('"');
    } else if (const auto* iv = std::get_if<std::int64_t>(&fv)) {
        out.append(std::format("{}", *iv));
    } else if (const auto* bv = std::get_if<bool>(&fv)) {
        out.append(*bv ? "true" : "false");
    } else {
        out.append("null");
    }
}

/* HG-3.5-2 + D-3.5-9 envelope: fixed field order
 *   ts → level → event → iface → msg → fields
 * One line terminated by '\n'. A trailing '\n' on the caller's msg is
 * stripped before embedding (D-3.5-6); embedded '\n's between content lines
 * are JSON-escaped via escape_json (surface as `\n` in the rendered JSON). */
[[nodiscard]] std::string build_json_line(Level                              level,
                                          std::string_view                   event,
                                          std::optional<std::string_view>    iface,
                                          std::string_view                   msg,
                                          std::span<const Field>             fields)
{
    /* Strip a single trailing '\n' so .msg doesn't carry a stray "\n" at
     * end (D-3.5-6 JSON-mode policy). Multi-line content between newlines
     * is preserved — only the terminator is dropped. */
    if (!msg.empty() && msg.back() == '\n') {
        msg.remove_suffix(1);
    }

    std::string out;
    out.reserve(256 + msg.size());
    out.push_back('{');

    out.append("\"ts\":\"");
    out.append(xdpmf::escape_util::format_timestamp_utc());
    out.append("\",");

    out.append("\"level\":\"");
    out.append(level_str(level));
    out.append("\",");

    out.append("\"event\":\"");
    out.append(xdpmf::escape_util::escape_json(event));
    out.append("\",");

    out.append("\"iface\":");
    if (iface.has_value()) {
        out.push_back('"');
        out.append(xdpmf::escape_util::escape_json(*iface));
        out.push_back('"');
    } else {
        out.append("null");
    }
    out.push_back(',');

    out.append("\"msg\":\"");
    out.append(xdpmf::escape_util::escape_json(msg));
    out.append("\",");

    out.append("\"fields\":{");
    bool first = true;
    for (const Field& f : fields) {
        if (!first) {
            out.push_back(',');
        }
        first = false;
        out.push_back('"');
        out.append(xdpmf::escape_util::escape_json(f.key));
        out.append("\":");
        render_field_value(out, f.value);
    }
    out.push_back('}');

    out.push_back('}');
    out.push_back('\n');
    return out;
}

/* D-3.5-6 text-mode policy: append '\n' ONLY if msg does not already end in
 * '\n'. Concrete pre-§5.32 sites are mixed — most fprintf format strings
 * end with "\n", but cli.usage_text dumps usage_text() which already
 * terminates with '\n'. */
void emit_text(std::string_view msg) noexcept
{
    if (msg.empty()) {
        /* Empty msg: emit nothing — matches a hypothetical fprintf(stderr, "")
         * which produces no output. Defensive guard. */
        return;
    }
    write_stderr(msg);
    if (msg.back() != '\n') {
        write_stderr("\n");
    }
}

void emit_json(Level                              level,
               std::string_view                   event,
               std::optional<std::string_view>    iface,
               std::string_view                   msg,
               std::span<const Field>             fields) noexcept
{
    /* D-3.5-4: catch any std::bad_alloc / std::format formatting exception
     * from std::string building inside build_json_line so emit() honors its
     * noexcept contract. Silent-on-failure mirrors fprintf's semantic — no
     * recovery path for a stderr write failure (logging the failure would
     * loop). */
    try {
        const std::string line = build_json_line(level, event, iface, msg, fields);
        write_stderr(line);
    } catch (...) {
        /* swallow */
    }
}

}  // namespace

void emit(Level                              level,
          std::string_view                   event,
          std::optional<std::string_view>    iface,
          std::string_view                   msg,
          std::span<const Field>             fields) noexcept
{
    /* call_once is thread-safe + reentrant-safe; init_format() does NOT call
     * emit() during init so the unknown-value WARN is queued + fired AFTER
     * the format is settled. */
    try {
        std::call_once(g_init_once, init_format);
    } catch (...) {
        /* call_once can theoretically throw on system_error (mutex failure);
         * silent-fallback to default Text. */
        g_format = Format::Text;
    }

    /* If lazy init flagged an unknown env value, fire the one-shot WARN now
     * via the regular code path. We clear the flag BEFORE the re-entrant
     * emit() so recursion is bounded to exactly one extra call. */
    if (g_emit_unknown_warn) {
        g_emit_unknown_warn = false;
        const std::string warn_msg = std::format(
            "xdpmacfilter: WARN: unknown XDPMF_LOG_FORMAT value '{}', "
            "defaulting to 'text'",
            g_unknown_warn_value);
        const Field warn_fields[] = {
            Field{"value", std::string_view{g_unknown_warn_value}},
        };
        /* iface=nullopt (process-scoped). Use the normal emit path so the
         * WARN itself respects the (now Text) format. */
        emit(Level::Warn,
             "logger.warn.unknown_log_format",
             std::nullopt,
             warn_msg,
             warn_fields);
    }

    if (g_format == Format::Json) {
        emit_json(level, event, iface, msg, fields);
    } else {
        emit_text(msg);
    }
}

void emit(Level                  level,
          std::string_view       event,
          std::string_view       msg,
          std::span<const Field> fields) noexcept
{
    emit(level, event, std::nullopt, msg, fields);
}

}  // namespace xdpmf::logger
