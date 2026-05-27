/*
 * escape_util.cpp — §5.37 (MVP-3.4f) Theme B rule-of-three extraction
 * definitions. Bodies for `escape_json` + `format_timestamp_utc` are
 * byte-equivalent to the pre-§5.37 duplicates at logger.cpp:49-92 /
 * sidecar.cpp:70-117 (PI-3.4f-1). `escape_audit` body extends the prior
 * bypass.cpp:48-64 / reset_counters.cpp:55-71 policy with the additional
 * `\xHH` branch for control chars + 0x7F per HG-3.4f-1 / D-3.4f-3 / PI-3.4f-2.
 *
 * NOT noexcept: std::string append/push_back/std::format can throw
 * std::bad_alloc. PI-32-3.4b preserved by caller envelopes; see header.
 *
 * Q6=B1 dup-TU: compiled once inside xdpmf_internal STATIC lib + once
 * inside xdpmf-exporter executable (mirrors §5.32 D-3.5-1 logger.cpp
 * pattern). ODR-safe because the two binaries are linked from independent
 * source lists and each ends up with exactly one copy of the symbols.
 */
#include "common/escape_util.hpp"

#include <ctime>
#include <format>
#include <string>
#include <string_view>

namespace xdpmf::escape_util {

std::string escape_json(std::string_view raw)
{
    std::string out;
    out.reserve(raw.size() + 2);
    for (char c : raw) {
        switch (c) {
            case '\\': out.append("\\\\"); break;
            case '"':  out.append("\\\""); break;
            case '\n': out.append("\\n");  break;
            case '\r': out.append("\\r");  break;
            case '\t': out.append("\\t");  break;
            case '\b': out.append("\\b");  break;
            case '\f': out.append("\\f");  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    out.append(std::format("\\u{:04x}",
                                            static_cast<unsigned char>(c)));
                } else {
                    out.push_back(c);
                }
                break;
        }
    }
    return out;
}

std::string escape_audit(std::string_view raw)
{
    std::string out;
    out.reserve(raw.size());
    for (char raw_c : raw) {
        const auto c = static_cast<unsigned char>(raw_c);
        /* §5.37 D-3.4f-3 + PI-3.4f-3: the 5 named escapes hit FIRST so
         * 0x0A → "\\n" (NOT "\\x0a"); 0x0D → "\\r"; 0x00 → "\\0". The
         * extended branch only fires for bytes outside the named set. */
        switch (c) {
            case '\\': out.append("\\\\"); break;
            case '"':  out.append("\\\""); break;
            case '\n': out.append("\\n");  break;
            case '\r': out.append("\\r");  break;
            case '\0': out.append("\\0");  break;
            default:
                /* §5.37 PI-3.4f-2: control chars + DEL get `\xHH` lowercase.
                 * Set: [0x01,0x08] ∪ {0x0B,0x0C} ∪ [0x0E,0x1F] ∪ {0x7F}.
                 * Tab (0x09) IS in this set — named-5 does NOT include `\t`. */
                if (c < 0x20 || c == 0x7F) {
                    out.append(std::format("\\x{:02x}", c));
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return out;
}

std::string format_timestamp_utc()
{
    const std::time_t now = std::time(nullptr);
    std::tm           tm_buf{};
    if (::gmtime_r(&now, &tm_buf) == nullptr) {
        /* gmtime_r failure is unprecedented but never-throw contract: emit
         * a clearly-broken timestamp that still matches the ERE shape so
         * the exporter's regex-based parser doesn't choke. */
        return "1970-01-01T00:00:00Z";
    }
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                       tm_buf.tm_year + 1900,
                       tm_buf.tm_mon  + 1,
                       tm_buf.tm_mday,
                       tm_buf.tm_hour,
                       tm_buf.tm_min,
                       tm_buf.tm_sec);
}

}  // namespace xdpmf::escape_util
