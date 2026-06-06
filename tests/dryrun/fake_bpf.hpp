/*
 * fake_bpf.hpp — §5.76 (MVP-4.36 / B43) the recording fake's public surface.
 *
 * This is the LINK-SEAM test-double for the dryrun_harness (§5.76 OPS-canary):
 * it lets the production `materialize` / `populate_action_table` /
 * `populate_redirect_devmap` object code run with NO libbpf, NO loader.cpp and
 * NO real BPF skeleton — every `bpf_map__fd` / `bpf_map_update_elem` /
 * `bpf_map_get_next_key` / `bpf_map_delete_elem` / `xdpmf::resolve_ifindex` the
 * render subset references is satisfied by a definition in fake_bpf.cpp.
 *
 * The fake records, IN CALL ORDER, one RecordedWrite per `bpf_map_update_elem`
 * (guard #36 — capture is DUMB; the golden's within-map sort + hex formatting is
 * a SEPARATE policy applied at format time in dryrun_harness.cpp). The fd-tag
 * descriptor table (D-mvp-4.36-Q3-FDTAG) decodes a recorded fake-fd back to a
 * map identity + key/value byte widths.
 *
 * Tester-owned per the §5.76 FileList role split (settled peer-to-peer with
 * mint-dev-impl): all of tests/dryrun/ is test infra; the link seam is coded
 * against the §5.76.4 design-pinned signatures, NOT impl's materialize.cpp body.
 */
#ifndef XDPMF_TESTS_DRYRUN_FAKE_BPF_HPP
#define XDPMF_TESTS_DRYRUN_FAKE_BPF_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// The REAL generated skeleton type (defined in xdpfilter.skel.h). Forward-
// declared here so this header pulls in NO build artifact; fake_bpf.cpp +
// dryrun_harness.cpp include xdpfilter.skel.h for the full definition.
struct xdpfilter_bpf;

namespace dryrun {

// ── Recorded write-set entry (§5.76.3 — dumb value-aggregate, guard #36) ──────
// One record per fake bpf_map_update_elem, appended in CALL (issue) order.
struct RecordedWrite {
    std::uint32_t             map_tag;  // fd-tag → kFakeMaps {name,key_sz,val_sz}
    std::vector<std::uint8_t> key;      // key_sz raw stored bytes
    std::vector<std::uint8_t> value;    // val_sz raw stored bytes
};

// ── fd-tag descriptor table (§5.76.3 / D-mvp-4.36-Q3-FDTAG) ────────────────────
// One entry per map whose fd the slot-0 write-set fetches. `map_tag` doubles as
// the fake fd AND the sentinel pointer value the fake skel stores in maps.X.
// key_sz / val_sz are pinned from the real struct sizes (zero magic numbers —
// see fake_bpf.cpp).
struct MapDesc {
    std::uint32_t map_tag;
    const char*   name;
    std::uint32_t key_sz;
    std::uint32_t val_sz;
};

// The 14 slot-0 write-set maps, in canonical golden (apply-issue) order
// (§5.76.4(6)): mac, dst, src, proto, port, vlan, dst6, src6, ethertype,
// ruleset_state, rules, slot_rule_id, action_table, redirect_devmap.
extern const MapDesc      kFakeMaps[];
extern const std::size_t  kFakeMapsCount;

// Decode a recorded fake-fd/tag → its descriptor, or nullptr if the tag is not
// one of the 14 expected write targets (a write to an unexpected map ⇒ spec
// violation; surfaced by the harness via unexpected_write()).
const MapDesc* desc_for_tag(std::uint32_t tag);

// ── recording sink ────────────────────────────────────────────────────────────
std::vector<RecordedWrite>& recorded_writes();
void                        reset_recording();
bool                        unexpected_write();  // true iff a write hit an unknown tag

// The iface name handed to the most recent fake xdpmf::resolve_ifindex — the
// symbol the golden renders for redirect_devmap (`<name> RESOLVED-AT-APPLY`);
// the numeric sentinel ifindex is NEVER printed (D-mvp-4.36-RESOLVE-SEAM).
const std::string& resolved_ifindex_name();

// ── fake skeleton ─────────────────────────────────────────────────────────────
// Build a zeroed xdpfilter_bpf whose 24 structurally-dereferenced maps.X members
// are each set to a distinct sentinel `bpf_map*` tag. NO libbpf open/load is
// called (SPIKE-1: the skel's libbpf-calling fns are inline + unreferenced ⇒
// zero libbpf link symbols). Caller frees with free_fake_skel.
xdpfilter_bpf* make_fake_skel();
void           free_fake_skel(xdpfilter_bpf* skel);

}  // namespace dryrun

#endif  // XDPMF_TESTS_DRYRUN_FAKE_BPF_HPP
