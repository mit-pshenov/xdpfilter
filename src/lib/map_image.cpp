/*
 * map_image.cpp — §5.77 (MVP-4.37 / B44) the production offline map-image render.
 *
 * libbpf-FREE (PI-mvp-4.37-LIBBPF-FREE): no `bpf_*` call; #includes
 * xdpfilter.skel.h for the `xdpfilter_bpf` TYPE only (to reach skel->maps.* for
 * map_fd). Holds:
 *   • format_dryrun_image — the SINGLE producer of the `# xdpfilter-image v1`
 *     text (§5.76.4(6) / guard #36 capture-vs-format split), relocated from the
 *     B43 harness. Now the SSoT formatter for BOTH the CLI verb AND the harness
 *     oracle (guard #9 / PI-mvp-4.37-SSOT).
 *   • render_dryrun_image — the offline orchestration: compile → sentinel skel →
 *     RecordingScope → the SAME 3-call apply sequence the live fresh-apply issues
 *     → format. ZERO kernel calls by construction (PI-mvp-4.37-ZERO-TOUCH).
 */
#include "map_image.hpp"

#include <arpa/inet.h>  // §5.78: inet_ntop for canonical IPv6 CIDR rendering

#include <cstdint>
#include <cstring>
#include <format>
#include <map>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include "xdpfilter.skel.h"  // struct xdpfilter_bpf (full type; compile-path only)
}

#include "compiled_ruleset.hpp"  // compile(), CompiledRuleset
#include "map_writer.hpp"        // RecordedWrite, kMapCatalog, RecordingMapWriter, RecordingScope, make_dryrun_skel, map_fd
#include "materialize.hpp"       // materialize / populate_action_table / populate_redirect_devmap

namespace xdpmf {

namespace {

// fixed-width lowercase hex of stored bytes in memory order.
std::string hex_of(const std::vector<std::uint8_t>& bytes)
{
    static const char* k = "0123456789abcdef";
    std::string s;
    s.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes) { s.push_back(k[b >> 4]); s.push_back(k[b & 0xF]); }
    return s;
}

// §5.78 operator-vocabulary axis renderers — mirror sidecar.cpp's spellings so an
// operator sees the SAME tokens as in their source YAML / rule_index.json. Faithful
// echoes of the validated, already-stored values (NO re-lowering — guard #9).
std::string fmt_mac(const xdpmf_mac& m)
{
    return std::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                       m.octets[0], m.octets[1], m.octets[2],
                       m.octets[3], m.octets[4], m.octets[5]);
}

// addr is network byte order; aligned local copies avoid packed-member UB.
std::string fmt_cidr(const xdpmf_cidr_v4& c)
{
    const unsigned int a = (c.addr >>  0) & 0xFFu;
    const unsigned int b = (c.addr >>  8) & 0xFFu;
    const unsigned int d = (c.addr >> 16) & 0xFFu;
    const unsigned int e = (c.addr >> 24) & 0xFFu;
    const unsigned int plen = c.prefixlen;
    return std::format("{}.{}.{}.{}/{}", a, b, d, e, plen);
}

std::string fmt_cidr6(const xdpmf_cidr_v6& c)
{
    char buf[INET6_ADDRSTRLEN] = {};
    if (::inet_ntop(AF_INET6, c.addr6, buf, sizeof(buf)) == nullptr) { buf[0] = '\0'; }
    const unsigned int plen = c.prefixlen;
    // const char* overload stops at the NUL (a char[N] arg would leak trailing NULs).
    return std::format("{}/{}", static_cast<const char*>(buf), plen);
}

// §5.78.4(a): "protocol as the number" is the CONTRACT base; a trailing name
// annotation is a MAY nicety. VALUE-FIRST (`6(tcp)`) so the bare-number value is a
// substring (the operator/test pins on the value, the name is decoration).
std::string fmt_protocol(std::uint8_t p)
{
    const char* name = (p == 6) ? "tcp" : (p == 17) ? "udp" : (p == 1) ? "icmp" : nullptr;
    return name ? std::format("{}({})", p, name) : std::to_string(p);
}

// §5.78.4(a): ethertype "as the number" — lowercase hex, NO fixed-width leading
// zeros (`0x806`, not `0x0806`), value-first with an optional well-known name suffix.
std::string fmt_ethertype(std::uint16_t et)
{
    const char* name = (et == 0x0800u) ? "ipv4"
                     : (et == 0x86DDu) ? "ipv6"
                     : (et == 0x0806u) ? "arp"
                     : nullptr;
    return name ? std::format("0x{:x}({})", et, name) : std::format("0x{:x}", et);
}

// single port (lo==hi) → "p"; a range → "lo-hi" (the config grammar's spelling).
std::string fmt_port(const PortRange& pr)
{
    return (pr.lo == pr.hi) ? std::to_string(pr.lo)
                            : std::format("{}-{}", pr.lo, pr.hi);
}

// §5.78.4(a) per-rule `match:` line — the constrained axes as space-separated
// `<axis>=<value>` using the EXACT operator axis names. A valid rule always
// constrains ≥1 axis (config.cpp rule 7), so the list is never empty.
std::string fmt_match(const RuleMatch& mm)
{
    std::string s;
    const auto add = [&](const char* axis, const std::string& v) {
        if (!s.empty()) { s.push_back(' '); }
        s.append(axis).push_back('=');
        s.append(v);
    };
    if (mm.mac.has_value())       { add("mac", fmt_mac(*mm.mac)); }
    if (mm.dst_cidr.has_value())  { add("dst_cidr", fmt_cidr(*mm.dst_cidr)); }
    if (mm.src_cidr.has_value())  { add("src_cidr", fmt_cidr(*mm.src_cidr)); }
    if (mm.dst_cidr6.has_value()) { add("dst_cidr6", fmt_cidr6(*mm.dst_cidr6)); }
    if (mm.src_cidr6.has_value()) { add("src_cidr6", fmt_cidr6(*mm.src_cidr6)); }
    if (mm.protocol.has_value())  { add("protocol", fmt_protocol(*mm.protocol)); }
    if (mm.dst_port.has_value())  { add("dst_port", fmt_port(*mm.dst_port)); }
    if (mm.vlan.has_value())      { add("vlan", std::to_string(*mm.vlan)); }
    if (mm.ethertype.has_value()) { add("ethertype", fmt_ethertype(*mm.ethertype)); }
    return s;
}

const char* action_word(RuleAction a)
{
    switch (a) {
        case RuleAction::Pass:     return "pass";
        case RuleAction::Redirect: return "redirect";
        case RuleAction::Drop:     break;
    }
    return "drop";
}

}  // namespace

// The SINGLE producer of the image text (§5.76.4(6) / D-mvp-4.36-HG1-CONFIRM).
// Policy: canonical map order = kMapCatalog order; within-map rows sorted by raw
// stored-key bytes (memcmp); fixed-width lowercase hex of stored bytes in memory
// order; redirect_devmap value rendered SYMBOLICALLY (never a numeric ifindex);
// a map that received NO writes is omitted (slot-agnostic frozen shape).
std::string format_dryrun_image(const std::vector<RecordedWrite>& recs,
                                const std::string& devmap_target)
{
    std::ostringstream out;
    out << "# xdpfilter-image v1\n";

    for (std::size_t mi = 0; mi < kMapCatalogCount; ++mi) {
        const MapDesc& d = kMapCatalog[mi];

        // FAITHFUL FINAL MAP-IMAGE (D-mvp-4.36-IMAGE-FINAL-STATE): last-write-wins
        // per (map,key) over the dumb raw trace, then render EVERY resident key.
        // The std::map keyed by stored key bytes ALSO imposes the within-map sort
        // (memcmp == lexicographic for the fixed key_sz this map records). The
        // collapse dedups the ARRAY clear-then-set double-write; the cleared-tail
        // sentinels are REAL resident cells and ARE rendered ⇒ ARRAY maps come out
        // DENSE, HASH/LPM come out SPARSE (only inserted keys; their clear loop
        // no-ops on the empty recording inner).
        std::map<std::vector<std::uint8_t>, std::vector<std::uint8_t>> image;
        for (const RecordedWrite& r : recs) {
            if (r.map_tag == d.tag) { image[r.key] = r.value; }
        }

        // Omit a map that received NO writes (a wildcard-only HASH/LPM axis, or
        // redirect_devmap absent steering) — §5.76.4(6). ARRAY maps always wrote
        // all 64 slots ⇒ never empty here.
        if (image.empty()) { continue; }

        out << "map=" << d.name << " key_sz=" << d.key_sz
            << " val_sz=" << d.val_sz << " rows=" << image.size() << "\n";

        const bool is_devmap = (std::strcmp(d.name, "redirect_devmap") == 0);
        for (const auto& [key, value] : image) {
            out << "  " << hex_of(key) << " ";
            if (is_devmap) {
                // symbolic: the operator-chosen target name, resolved AT APPLY
                // (the sentinel ifindex is NEVER printed) — D-mvp-4.36-RESOLVE-SEAM.
                out << devmap_target << " RESOLVED-AT-APPLY";
            } else {
                out << hex_of(value);
            }
            out << "\n";
        }
    }
    return out.str();
}

std::string render_dryrun_image(const Config& cfg)
{
    const CompiledRuleset cr   = compile(cfg);  // pure / libbpf-free (§5.77.9 #8)
    xdpfilter_bpf*        skel = make_dryrun_skel();

    // Record every render primitive — ZERO kernel calls by construction.
    RecordingMapWriter rec_writer;
    RecordingScope     rec(rec_writer);

    // The SAME order + calls the fresh-apply site issues (D-mvp-4.36-SLOT0).
    materialize(skel, 0u, cr);
    populate_action_table(map_fd(skel->maps.action_table));
    if (cfg.steering.has_value()) {
        populate_redirect_devmap(map_fd(skel->maps.redirect_devmap), cfg);
    }

    std::string img = format_dryrun_image(rec_writer.writes(),
                                          rec_writer.resolved_ifindex_name());
    free_dryrun_skel(skel);
    return img;
}

// §5.78 (MVP-4.38 / B45) the human-decoded operator view (A1). Renders ONLY from
// the TESTED compile() output (`cr`) + `cfg` — id→slot, default_action, per-rule
// match axes, the steering target. NO trace, NO materialize, NO re-lowering
// (guard #9 / PI-mvp-4.38-SSOT). Pure / libbpf-free / side-effect-free.
std::string format_dryrun_human(const Config& cfg, const CompiledRuleset& cr)
{
    std::ostringstream out;

    // The redirect tap (resolved AT APPLY; validate() guarantees steering is
    // present whenever any rule redirects — D-mvp-4.38-EMPTYMATCH-NA).
    const std::string target = cfg.steering.has_value() ? cfg.steering->redirect_to
                                                        : std::string{};
    const bool default_drop = (cr.default_action == DefaultAction::Drop);

    // Header block — first line DISTINCT from the golden header so the
    // default-format switch is observable (§5.78.4(a)).
    out << "# xdpfilter dry-run\n";
    out << "default_action: " << (default_drop ? "drop" : "pass") << "\n";
    out << "rules: " << cr.rules.size() << "\n";
    if (cfg.steering.has_value()) {
        out << "steering: redirect_to=" << target << "\n";
    }
    out << "schema_version: " << cfg.schema_version << "\n";

    // Per-rule block — one entry per rule, in cr.rules (config) order. slot is
    // the dense rank compile() assigned (cr.id_to_slot).
    bool any_redirect = false;
    for (const Rule& r : cr.rules) {
        const std::uint32_t slot = cr.id_to_slot.at(r.id);
        out << "rule id=" << r.id << " slot=" << slot
            << " action=" << action_word(r.action);
        if (r.action == RuleAction::Redirect) {
            any_redirect = true;
            out << " target=" << target;
        }
        out << "\n";
        out << "  match: " << fmt_match(r.match) << "\n";
    }

    // Diagnostics block (HG-2 bounded — D-mvp-4.38-DIAG).
    if (any_redirect) {
        // Redirect resolution note — reuses the golden's RESOLVED-AT-APPLY
        // vocabulary; conveys "verify the tap is up".
        out << "redirect target '" << target
            << "' RESOLVED-AT-APPLY — verify the tap interface is up\n";
    }
    if (cr.rules.empty()) {
        // Empty-ruleset blackhole footgun — the MANDATORY negation. Fires when
        // and ONLY when there are zero rules: every frame gets default_action.
        out << "WARNING: no rules — every frame gets default_action: "
            << (default_drop ? "drop" : "pass") << " ("
            << (default_drop ? "all traffic dropped" : "all traffic passed")
            << ")\n";
    }

    return out.str();
}

}  // namespace xdpmf
