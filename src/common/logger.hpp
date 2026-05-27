/*
 * logger.hpp — structured-logging surface (§5.32 MVP-3.5).
 *
 * Operator-facing env var XDPMF_LOG_FORMAT={text,json} (default text) selects
 * the rendering for every diagnostic stderr line in BOTH binaries. text mode
 * is byte-equivalent to pre-§5.32 emissions (PI-3.5-1 load-bearing canary);
 * json mode emits one NDJSON object per emission with the flat envelope
 *   {ts, level, event, iface, msg, fields:{}}
 * per HG-3.5-2.
 *
 * Module ownership: this header lives under src/common/ (Q1=M3); logger.cpp
 * is dup-TU-compiled into BOTH xdpmf_internal AND xdpmf-exporter targets
 * (Q6=B1). Header has NO public dependency on loader.hpp / config.hpp —
 * PI-7-3.5-hpp ZERO-diff streak preserved.
 *
 * NO new external build dep (PI-3.5-7): stdlib only.
 */
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <variant>

namespace xdpmf::logger {

/* Severity. Renders to JSON "level" as the lowercase string of the enumerator
 * (info|warn|error). Text mode does NOT prefix the rendered line — the
 * pre-§5.32 prose lines already embed level tokens inline where appropriate
 * (e.g. "xdpmf-exporter: WARN ...") and PI-3.5-1 byte-equivalence requires
 * preserving them verbatim. */
enum class Level : std::uint8_t {
    Info  = 0,
    Warn  = 1,
    Error = 2,
};

/* Output format. Cached in module-static once_flag-protected state after the
 * first emit() per Q4 R1 read-once contract. */
enum class Format : std::uint8_t {
    Text = 0,   // default; byte-equivalent to pre-§5.32 emissions
    Json = 1,   // NDJSON envelope per HG-3.5-2
};

/* Field value variant (Q5 F1 flat-scalars-only). int64_t covers all natural
 * emitter cases (uid, euid, prog_id, port, errno, counters) per D-3.5-3;
 * unsigned values up to INT64_MAX round-trip safely via static_cast. */
using FieldValue = std::variant<
    std::string_view,    // string scalar (JSON-escaped at render time)
    std::int64_t,        // signed 64-bit integer
    bool,
    std::nullptr_t       // explicit null
>;

/* Caller-owned key/value pair. Both `key` and any string_view inside `value`
 * MUST remain valid for the duration of the emit() call; logger reads-then-
 * writes synchronously with no async copy. */
struct Field {
    std::string_view key;
    FieldValue       value;
};

/* Event-name catalog (HG-3.5-4). The constexpr array IS the locked set
 * asserted by T_LOG_EVENT_CATALOG_STABILITY; emission sites pass string_view
 * literals that MUST appear here. Adding a new event = one-line table
 * extension + bump size + tester reference update.
 *
 * §5.32 EDIT-1 (2026-05-25): catalog invariant — "every event emitted via
 * logger::emit() — including logger-internal self-emits — is in kEventNames".
 *
 * §5.34 (MVP-3.4b cycle 2) D-3.4b-c2-4: count 34 → 33. The
 * `loader.warn.rules_skeleton_not_wired` event entry is REMOVED in lockstep
 * with the §5.29 WARN-emission removal at loader.cpp:1557-1574 (the contract
 * it announced — "rules+action_table populated NOT consulted by datapath" —
 * is the operative thing §5.34 retires). Size = 32 emission-site-derived
 * events + 1 logger self-emit (`logger.warn.unknown_log_format`) = 33. */
inline constexpr std::array<std::string_view, 33> kEventNames = {
    /* loader (xdpmacfilter) — 18 events (was 19 pre-§5.34) */
    "cli.usage_error",                       /* src/cli/main.cpp:100 */
    "cli.usage_text",                        /* src/cli/main.cpp:101 (multi-line usage dump) */
    "cli.error",                             /* src/cli/main.cpp:136, 142, 146 (CliError + system_error + std::exception fallback) */
    "config.error",                          /* src/cli/main.cpp:140 (ConfigError variant) */
    "loader.trust_model",                    /* src/lib/loader.cpp:1031 (audit log — PI-23) */
    "loader.attach.fleet_replace",           /* src/lib/loader.cpp:1606 (trust_model=fleet replace) */
    "loader.attach.replace",                 /* src/lib/loader.cpp:1784 (existing program replace) */
    "logger.warn.unknown_log_format",        /* src/common/logger.cpp self-emit (Q4 edge case) */
    "bypass.usage_error",                    /* src/cli/bypass.cpp:129 (--iface missing) */
    "bypass.refused.requires_unsafe",        /* src/cli/bypass.cpp:139 (non-tty without --unsafe) */
    "bypass.cancelled",                      /* src/cli/bypass.cpp:149 (operator typed 'n') */
    "bypass.activated",                      /* src/cli/bypass.cpp:174 — HK-4 audit log */
    "sidecar.warn.root_symlink",             /* src/lib/sidecar.cpp:259 */
    "sidecar.warn.root_not_dir",             /* src/lib/sidecar.cpp:266 */
    "sidecar.warn.lstat_failed",             /* src/lib/sidecar.cpp:273 */
    "sidecar.warn.mkdir_failed",             /* src/lib/sidecar.cpp:289 */
    "sidecar.warn.write_failed",             /* src/lib/sidecar.cpp:305 */
    "sidecar.warn.write_exception",          /* src/lib/sidecar.cpp:312 */

    /* exporter (xdpmf-exporter) — 15 events */
    "exporter.usage_error",                  /* src/exporter/main.cpp:91, 100, 110, 143, 154 (5 sites share) */
    "exporter.fatal",                        /* src/exporter/main.cpp:176 */
    "exporter.error.all_ifaces_eacces",      /* src/exporter/main.cpp:187 — HK-17 */
    "exporter.bind.invalid_addr",            /* src/exporter/http.cpp:288 */
    "exporter.bind.socket_failed",           /* src/exporter/http.cpp:295 */
    "exporter.bind.failed",                  /* src/exporter/http.cpp:310 */
    "exporter.bind.listen_failed",           /* src/exporter/http.cpp:317 */
    "exporter.listening",                    /* src/exporter/http.cpp:323 — startup signal */
    "exporter.accept.poll_failed",           /* src/exporter/http.cpp:336 */
    "exporter.accept.failed",                /* src/exporter/http.cpp:353 */
    "exporter.shutdown",                     /* src/exporter/http.cpp:362 */
    "exporter.warn.bpffs_root_missing",      /* src/exporter/stats_reader.cpp:119 — HK-16 */
    "exporter.warn.cpu_count_invalid",       /* src/exporter/stats_reader.cpp:157 + rule_counters_reader.cpp:116 (2 sites share) */
    "exporter.scrape.warn.stats_open_failed",         /* src/exporter/stats_reader.cpp:194 */
    "exporter.scrape.warn.rule_counters_open_failed", /* src/exporter/rule_counters_reader.cpp:137 */
};

inline constexpr std::size_t kEventCount = kEventNames.size();   // = 33 (§5.34 D-3.4b-c2-4: 34 → 33; rules_skeleton_not_wired retired)

/*
 * emit() — write ONE log event to stderr.
 *
 * Format selected by XDPMF_LOG_FORMAT env var, read ONCE at first call (Q4
 * R1, lazy init under std::once_flag); cached for process lifetime.
 *
 *   text mode (default) — writes `<msg>` byte-equivalent to the pre-§5.32
 *                         emission. A trailing '\n' is appended ONLY IF msg
 *                         does not already end in '\n' (D-3.5-6 — handles
 *                         the cli.usage_text case where the multi-line dump
 *                         already terminates with '\n').
 *   json mode           — writes one NDJSON line per HG-3.5-2:
 *                         {"ts":"...","level":"...","event":"...",
 *                          "iface":<"str"|null>,"msg":"...","fields":{...}}
 *                         followed by a single '\n'.
 *
 * iface: pass std::nullopt for process-scoped events (cli usage, exporter
 * startup); pass the iface name otherwise. JSON mode renders nullopt as
 * "iface": null and a present value as "iface": "<value>".
 *
 * Logger NEVER throws (noexcept). bad_alloc during JSON envelope build is
 * caught and silently dropped per D-3.5-4 — there is no recovery path for a
 * stderr write failure.
 *
 * THREAD SAFETY: emit() is async-signal-UNSAFE (uses fprintf + std::string).
 * No current call site emits from a signal handler.
 *
 * MULTI-LINE msg: in text mode embedded '\n' surfaces as separate lines
 * (matches pre-§5.32 multi-line dumps such as cli.usage_text). In JSON mode
 * embedded '\n' is JSON-escaped to "\\n" inside the "msg" string field; a
 * single trailing '\n' on msg is stripped before embedding (operators
 * reading .msg via jq don't want a stray "\n" at end).
 *
 * UNSIGNED INTEGER VALUES: callers pass static_cast<std::int64_t>(unsigned_v).
 * Lossless for values up to INT64_MAX (~9.2 x 10^18). uint64_t > INT64_MAX
 * is OUT OF SCOPE per D-3.5-3.
 */
void emit(Level                              level,
          std::string_view                   event,
          std::optional<std::string_view>    iface,
          std::string_view                   msg,
          std::span<const Field>             fields = {}) noexcept;

/* Convenience overload for events without iface — equivalent to
 * emit(level, event, std::nullopt, msg, fields). JSON mode renders
 * "iface": null. */
void emit(Level                  level,
          std::string_view       event,
          std::string_view       msg,
          std::span<const Field> fields = {}) noexcept;

}  // namespace xdpmf::logger
