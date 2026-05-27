/*
 * escape_util.hpp — §5.37 (MVP-3.4f) Theme B rule-of-three extraction.
 *
 * Consolidates the 3 helpers previously duplicated across
 * src/common/logger.cpp + src/lib/sidecar.cpp + src/cli/bypass.cpp +
 * src/cli/reset_counters.cpp per D-3.5-2 + D-3.4d-6. Guard #9 EXPLICIT
 * OVERRIDE per D-3.4f-1 (rule-of-three: 6 duplicate bodies × 4 modules;
 * /mint-review 2026-05-27 Theme B 3-dim cross-validation triggered the
 * escape-valve activation).
 *
 * NO new external build dependency (PI-3.5-7 carry): stdlib only
 * (<string>, <string_view>, <format>, <ctime> in the .cpp).
 *
 * All functions return std::string by value. They are NOT noexcept —
 * std::string ops can throw std::bad_alloc. Throw semantic is byte-
 * equivalent to the pre-§5.37 duplicates; existing caller-side catch
 * envelopes (sidecar.cpp top-level try/catch, logger.cpp emit() internal
 * catch-all, main.cpp's terminal catch arm) swallow bad_alloc identically
 * to the duplicated-helper world. PI-32-3.4b PRESERVED by construction.
 */
#pragma once

#include <string>
#include <string_view>

namespace xdpmf::escape_util {

/* RFC 8259 JSON string escape. Backslash / double-quote / control chars get
 * backslash-escaped (7 named: `\\`, `\"`, `\n`, `\r`, `\t`, `\b`, `\f`;
 * other <0x20 → `\u00xx` lowercase); non-ASCII bytes pass through verbatim.
 * Used for JSON envelope construction in logger.cpp + sidecar.cpp.
 *
 * Body byte-equivalent to pre-§5.37 `json_escape` at logger.cpp:68-92 /
 * sidecar.cpp:93-117 (PI-3.4f-1). */
[[nodiscard]] std::string escape_json(std::string_view raw);

/* Text-mode audit-line escape (NOT JSON). Policy per HG-3.4f-1:
 *   5 named escapes: `\\`, `\"`, `\n`, `\r`, `\0` (byte-equivalent to
 *                    pre-§5.37 `escape_audit_value` at bypass.cpp:48-64 /
 *                    reset_counters.cpp:55-71 — PI-3.4f-3 backward-compat).
 *   EXTENDED (Q2.A1 / D-3.4f-3): bytes in [0x01,0x08] ∪ {0x0B,0x0C} ∪
 *                     [0x0E,0x1F] ∪ {0x7F} → `\xHH` (lowercase hex).
 *                     Closes sec M1 control-char gap from /mint-review
 *                     2026-05-27 (PI-3.4f-2).
 *   Printable ASCII (0x20..0x7E except `\`,`"`) + non-ASCII (>=0x80)
 *   pass through verbatim.
 *
 * Switch-order contract: the 5 named cases hit FIRST, so 0x0A emits `\n`
 * (NOT `\x0a`), 0x0D emits `\r`, 0x00 emits `\0`. Tab (0x09) is NOT in the
 * named-5 list and therefore hits the extended branch (emits `\x09`).
 *
 * Operator-readable convention: `\xHH` C-style escape (NOT JSON `\u00HH`).
 * Lowercase hex matches the existing `\u00xx` lowercase precedent in
 * escape_json. */
[[nodiscard]] std::string escape_audit(std::string_view raw);

/* ISO-8601 UTC `YYYY-MM-DDTHH:MM:SSZ`. Single trailing 'Z'; no fractional
 * seconds. gmtime_r failure yields the broken-but-shape-valid
 * "1970-01-01T00:00:00Z" so the exporter's regex-based parser doesn't choke.
 * CLOCK_REALTIME via std::time (no clock injection — caller cannot mock;
 * matches pre-§5.37 behavior of both logger.cpp and sidecar.cpp).
 *
 * Body byte-equivalent to pre-§5.37 `format_timestamp_utc` at
 * logger.cpp:49-63 / sidecar.cpp:70-87 (PI-3.4f-1). */
[[nodiscard]] std::string format_timestamp_utc();

}  // namespace xdpmf::escape_util
