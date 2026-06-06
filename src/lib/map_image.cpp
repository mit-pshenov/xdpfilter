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

#include <cstdint>
#include <cstring>
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

}  // namespace xdpmf
