/*
 * fake_bpf.cpp — §5.76 (MVP-4.36 / B43) the recording fake + fd-tag table.
 *
 * Provides the libbpf-free LINK SEAM the dryrun_harness drives the production
 * render subset (materialize / populate_action_table / populate_redirect_devmap)
 * against. Defines:
 *   • the fd-tag descriptor table (D-mvp-4.36-Q3-FDTAG), key/val widths pinned
 *     from the REAL struct sizes (zero magic numbers);
 *   • the fake `bpf_map__fd` / `bpf_map_update_elem` / `bpf_map_get_next_key` /
 *     `bpf_map_delete_elem` (§5.76.4(5)) — update RECORDS, get_next_key returns
 *     ENOENT (empty fake inners ⇒ occupied-writes-only, D-mvp-4.36-CLEAR-EMPTY),
 *     delete is a no-op;
 *   • the fake `xdpmf::resolve_ifindex` (D-mvp-4.36-RESOLVE-SEAM) — records the
 *     requested name + returns a sentinel ifindex; ZERO kernel calls;
 *   • make_fake_skel — a zeroed real `xdpfilter_bpf` whose 24 structurally-
 *     dereferenced maps.X members are distinct sentinel tags, WITHOUT any
 *     libbpf open/load (SPIKE-1).
 *
 * The clean libbpf-free link of the harness IS the §5.76 OPS-canary contract.
 */
#include "fake_bpf.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <bpf/libbpf.h>        // bpf_map__fd / bpf_map_update_elem / ... decls (compile-path only)
#include "xdpfilter.skel.h"    // the REAL generated struct xdpfilter_bpf

#include "common/xdpfilter.h"  // struct sizes: xdpmf_mac/_cidr_v4/_cidr_v6/_port_range/_ruleset_state, rule_entry, action_entry
#include "loader.hpp"          // xdpmf::LoaderError (resolve_ifindex's 2nd param)

// The production render subset declares `xdpmf::resolve_ifindex` (external, per
// D-mvp-4.36-RESOLVE-SEAM) in the off-limits private header materialize.hpp. We
// re-declare the §5.76.4(3) signature here (NOT #include the in-flight header)
// and supply a FAKE definition; the mangled name matches materialize.cpp's call,
// so the harness links WITHOUT loader.cpp's live def.
namespace xdpmf {
[[nodiscard]] int resolve_ifindex(const std::string& iface, LoaderError on_fail);
}

namespace dryrun {

// ── module state (namespace-scope so the fake C functions below can mutate it) ─
namespace state {
std::vector<RecordedWrite> writes;
bool                       unexpected     = false;
std::string                resolved_name;
}  // namespace state

namespace {

// Sentinel/fake-fd tag spaces: written maps in [kWrittenBase, …); the _b siblings
// + rules_b (dereferenced but never fd-fetched at slot 0) in [kShadowBase, …).
constexpr std::uint32_t kWrittenBase = 1000;
constexpr std::uint32_t kShadowBase  = 2000;

}  // namespace

// The 14 slot-0 write-set maps in canonical golden (apply-issue) order. Widths
// are sizeof() of the real key/value types — NOT literals (guard #10 catalog
// arithmetic; the ABI static_asserts in common/xdpfilter.h pin these sizes).
const MapDesc kFakeMaps[] = {
    {kWrittenBase + 0,  "allowlist_a",         sizeof(struct xdpmf_mac),     sizeof(std::uint64_t)},
    {kWrittenBase + 1,  "dst_bitmask_a",       sizeof(struct xdpmf_cidr_v4), sizeof(std::uint64_t)},
    {kWrittenBase + 2,  "cidr_allowlist_a",    sizeof(struct xdpmf_cidr_v4), sizeof(std::uint64_t)},
    {kWrittenBase + 3,  "proto_bitmask_a",     sizeof(std::uint32_t),        sizeof(std::uint64_t)},
    {kWrittenBase + 4,  "port_ranges_a",       sizeof(std::uint32_t),        sizeof(struct xdpmf_port_range)},
    {kWrittenBase + 5,  "vlan_bitmask_a",      sizeof(std::uint32_t),        sizeof(std::uint64_t)},
    {kWrittenBase + 6,  "dst6_bitmask_a",      sizeof(struct xdpmf_cidr_v6), sizeof(std::uint64_t)},
    {kWrittenBase + 7,  "src6_bitmask_a",      sizeof(struct xdpmf_cidr_v6), sizeof(std::uint64_t)},
    {kWrittenBase + 8,  "ethertype_bitmask_a", sizeof(std::uint32_t),        sizeof(std::uint64_t)},
    {kWrittenBase + 9,  "ruleset_state",       sizeof(std::uint32_t),        sizeof(struct xdpmf_ruleset_state)},
    {kWrittenBase + 10, "rules_a",             sizeof(std::uint32_t),        sizeof(struct rule_entry)},
    {kWrittenBase + 11, "slot_rule_id",        sizeof(std::uint32_t),        sizeof(std::uint32_t)},
    {kWrittenBase + 12, "action_table",        sizeof(std::uint32_t),        sizeof(struct action_entry)},
    {kWrittenBase + 13, "redirect_devmap",     sizeof(std::uint32_t),        sizeof(std::uint32_t)},
};
const std::size_t kFakeMapsCount = sizeof(kFakeMaps) / sizeof(kFakeMaps[0]);

const MapDesc* desc_for_tag(std::uint32_t tag)
{
    for (std::size_t i = 0; i < kFakeMapsCount; ++i) {
        if (kFakeMaps[i].map_tag == tag) {
            return &kFakeMaps[i];
        }
    }
    return nullptr;
}

namespace {

std::uint32_t tag_by_name(const char* name)
{
    for (std::size_t i = 0; i < kFakeMapsCount; ++i) {
        if (std::strcmp(kFakeMaps[i].name, name) == 0) {
            return kFakeMaps[i].map_tag;
        }
    }
    std::fprintf(stderr, "fake_bpf: tag_by_name: unknown map '%s'\n", name);
    std::abort();
}

}  // namespace

std::vector<RecordedWrite>& recorded_writes() { return state::writes; }

void reset_recording()
{
    state::writes.clear();
    state::unexpected = false;
    state::resolved_name.clear();
}

bool unexpected_write() { return state::unexpected; }

const std::string& resolved_ifindex_name() { return state::resolved_name; }

// ── fake skeleton ─────────────────────────────────────────────────────────────
xdpfilter_bpf* make_fake_skel()
{
    auto* skel = new xdpfilter_bpf{};  // value-init: all pointers null

    auto W = [](std::uint32_t tag) {   // sentinel pointer == tag value
        return reinterpret_cast<struct bpf_map*>(static_cast<std::uintptr_t>(tag));
    };

    // 14 fd-fetched maps: sentinel == the kFakeMaps tag (so bpf_map__fd → tag → desc).
    skel->maps.allowlist_a         = W(tag_by_name("allowlist_a"));
    skel->maps.dst_bitmask_a       = W(tag_by_name("dst_bitmask_a"));
    skel->maps.cidr_allowlist_a    = W(tag_by_name("cidr_allowlist_a"));
    skel->maps.proto_bitmask_a     = W(tag_by_name("proto_bitmask_a"));
    skel->maps.port_ranges_a       = W(tag_by_name("port_ranges_a"));
    skel->maps.vlan_bitmask_a      = W(tag_by_name("vlan_bitmask_a"));
    skel->maps.dst6_bitmask_a      = W(tag_by_name("dst6_bitmask_a"));
    skel->maps.src6_bitmask_a      = W(tag_by_name("src6_bitmask_a"));
    skel->maps.ethertype_bitmask_a = W(tag_by_name("ethertype_bitmask_a"));
    skel->maps.rules_a             = W(tag_by_name("rules_a"));
    skel->maps.ruleset_state       = W(tag_by_name("ruleset_state"));
    skel->maps.slot_rule_id        = W(tag_by_name("slot_rule_id"));
    skel->maps.action_table        = W(tag_by_name("action_table"));
    skel->maps.redirect_devmap     = W(tag_by_name("redirect_devmap"));

    // 10 _b/shadow siblings: distinct non-null sentinels with NO descriptor —
    // they are inactive_axis_fd args at slot 0 but never fd-fetched/written; a
    // write landing on one decodes to nullptr ⇒ flagged as unexpected.
    skel->maps.allowlist_b         = W(kShadowBase + 0);
    skel->maps.dst_bitmask_b       = W(kShadowBase + 1);
    skel->maps.cidr_allowlist_b    = W(kShadowBase + 2);
    skel->maps.proto_bitmask_b     = W(kShadowBase + 3);
    skel->maps.port_ranges_b       = W(kShadowBase + 4);
    skel->maps.vlan_bitmask_b      = W(kShadowBase + 5);
    skel->maps.dst6_bitmask_b      = W(kShadowBase + 6);
    skel->maps.src6_bitmask_b      = W(kShadowBase + 7);
    skel->maps.ethertype_bitmask_b = W(kShadowBase + 8);
    skel->maps.rules_b             = W(kShadowBase + 9);

    return skel;
}

void free_fake_skel(xdpfilter_bpf* skel) { delete skel; }

}  // namespace dryrun

// ─────────────────────────────────────────────────────────────────────────────
// Fake libbpf surface (§5.76.4(5)). These DEFINITIONS satisfy the C-linkage
// declarations pulled in from <bpf/libbpf.h>; no real libbpf is linked.
// ─────────────────────────────────────────────────────────────────────────────

extern "C" int bpf_map__fd(const struct bpf_map* map)
{
    // The sentinel pointer value IS the tag / fake fd (make_fake_skel).
    return static_cast<int>(reinterpret_cast<std::uintptr_t>(map));
}

extern "C" int bpf_map_update_elem(int fd, const void* key, const void* value,
                                   std::uint64_t /*flags*/)
{
    const auto tag = static_cast<std::uint32_t>(fd);
    const dryrun::MapDesc* d = dryrun::desc_for_tag(tag);
    if (d == nullptr) {
        std::fprintf(stderr,
                     "fake_bpf: bpf_map_update_elem to UNEXPECTED map tag %u "
                     "(not one of the 14 slot-0 write targets)\n", tag);
        dryrun::state::unexpected = true;
        return 0;
    }
    dryrun::RecordedWrite rec;
    rec.map_tag = tag;
    rec.key.assign(static_cast<const std::uint8_t*>(key),
                   static_cast<const std::uint8_t*>(key) + d->key_sz);
    rec.value.assign(static_cast<const std::uint8_t*>(value),
                     static_cast<const std::uint8_t*>(value) + d->val_sz);
    dryrun::state::writes.push_back(std::move(rec));
    return 0;
}

extern "C" int bpf_map_get_next_key(int /*fd*/, const void* /*key*/, void* /*next_key*/)
{
    // Empty fake inners: no next key. ENOENT signals end-of-iteration so the
    // populate bulk-clear loop is a no-op (D-mvp-4.36-CLEAR-EMPTY) →
    // occupied-writes-only by construction. The production render reads the
    // RETURN value as -errno (libbpf 1.0 strict convention), so we return
    // -ENOENT (NOT plain -1, which would decode as -EPERM and make the clear
    // loop throw); errno is also set for any legacy errno-checking caller.
    errno = ENOENT;
    return -ENOENT;
}

extern "C" int bpf_map_delete_elem(int /*fd*/, const void* /*key*/)
{
    return 0;  // no-op (the steering corpus never reaches the delete branch)
}

// ── fake resolve_ifindex (D-mvp-4.36-RESOLVE-SEAM) ────────────────────────────
namespace xdpmf {
int resolve_ifindex(const std::string& iface, LoaderError /*on_fail*/)
{
    dryrun::state::resolved_name = iface;
    return 0x00ABCDEF;  // sentinel ifindex; the golden renders the NAME, never this
}
}  // namespace xdpmf
