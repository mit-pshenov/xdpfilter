/*
 * sidecar_reader.hpp — exporter-side parser for `rule_index.json` written
 * by the loader (§5.31 MVP-3.4b, sidecar::write_rule_index).
 *
 * D-3.4b-14 / D-3.4b-10 (CONTINUES per §5.46): line-oriented regex
 * extraction, NOT full JSON parse. The writer's output shape is stable +
 * controlled (D-3.4b-20 one-rule-per-line); a simple ERE captures
 * `(rule_id, action)` per rule, and §5.46 adds a key-anchored per-axis scan
 * over the same match-object body to fill the 5 axis fields below — still no
 * parser dependency.
 *
 * PI-31-3.4b: READ-ONLY by construction — no writes to rule_index.json.
 *
 * PI-32-3.4b orphan tolerance: missing file → empty vector (exporter
 * degrades to `action="unknown"` labels for any rule_id seen in the
 * counter map). NEVER throws.
 */
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace xdpmf::exporter {

struct RuleMeta {
    std::uint32_t rule_id;
    std::string   action;     /* "pass" | "drop" */
    std::string   match_kind; /* "mac" | "cidr" | "both" — informational only */
    /* §5.46 (MVP-4.6): per-axis match values, extracted verbatim from the
     * sidecar's match-object body via a key-anchored scan (D-3.4b-10 — NO
     * JSON parser). Empty string ⇒ the rule does not constrain that axis. */
    std::string   mac;        /* §5.47 (MVP-4.7) "aa:bb:cc:dd:ee:ff" or "" */
    std::string   dst_cidr;   /* "A.B.C.D/N" or "" */
    std::string   src_cidr;   /* "A.B.C.D/N" or "" */
    std::string   protocol;   /* "tcp" | "udp" | "icmp" | numeric | "" */
    std::string   dst_port;   /* "443" | "1000-2000" | "" */
    std::string   vlan;       /* "100" | "" */
};

/* Reads rule_index.json at `path`; returns empty vector if file missing,
 * unreadable, or no rules are extracted. NEVER throws. */
[[nodiscard]] std::vector<RuleMeta> parse_rule_index(std::string_view path) noexcept;

}  // namespace xdpmf::exporter
