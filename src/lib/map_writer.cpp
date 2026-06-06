/*
 * map_writer.cpp — §5.77 (MVP-4.37 / B44) the object-seam dispatch + the
 * recording writer + the production map CATALOG + the dry-run sentinel skel.
 *
 * libbpf-FREE (PI-mvp-4.37-LIBBPF-FREE): this TU calls NO `bpf_*` symbol. It
 * #includes xdpfilter.skel.h for the `xdpfilter_bpf` TYPE only (to construct the
 * sentinel skel) — the skel's libbpf-calling fns are inline + unreferenced ⇒ zero
 * libbpf link symbols (SPIKE-1, B43 precedent). The live writer (the ONLY TU that
 * references libbpf) lives in live_map_writer.cpp and is never linked here.
 *
 * Dispatch (D-mvp-4.37-Q1-OBJSEAM): the free-fn wrappers forward to the single
 * installed active MapWriter. FAIL-CLOSED (PI-mvp-4.37-FAILCLOSED): a wrapper
 * reached with NO writer installed aborts loudly — never null-derefs, silently
 * no-ops, or falls back to libbpf.
 */
#include "map_writer.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
#include "xdpfilter.skel.h"  // struct xdpfilter_bpf (full type; compile-path only)
}

#include "common/xdpfilter.h"  // value-struct sizes: xdpmf_mac/_cidr_v4/_cidr_v6/_port_range/_ruleset_state, rule_entry, action_entry

namespace xdpmf {

// ── object-seam dispatch ──────────────────────────────────────────────────────
namespace {

// The single installed active writer. nullptr until install_live_map_writer()
// (live) or a RecordingScope (dry-run / harness) sets it — a wrapper reached with
// it null is a programming error (FAIL-CLOSED).
MapWriter* g_active_writer = nullptr;

// FAIL-CLOSED guard — the FIRST action of every wrapper. The literal diagnostic
// "map writer not installed" is contract (PI-mvp-4.37-FAILCLOSED).
[[noreturn]] void no_writer_installed()
{
    std::fputs("xdpfilter: map writer not installed\n", stderr);
    std::abort();
}

}  // namespace

MapWriter* set_active_writer(MapWriter* w)
{
    MapWriter* prev = g_active_writer;
    g_active_writer = w;
    return prev;
}

MapWriter* active_writer() { return g_active_writer; }

int map_fd(bpf_map* m)
{
    if (g_active_writer == nullptr) { no_writer_installed(); }
    return g_active_writer->fd(m);
}

int map_update(int fd, const void* key, const void* value, std::uint64_t flags)
{
    if (g_active_writer == nullptr) { no_writer_installed(); }
    return g_active_writer->update(fd, key, value, flags);
}

int map_next_key(int fd, const void* prev, void* next)
{
    if (g_active_writer == nullptr) { no_writer_installed(); }
    return g_active_writer->next_key(fd, prev, next);
}

int map_delete(int fd, const void* key)
{
    if (g_active_writer == nullptr) { no_writer_installed(); }
    return g_active_writer->del(fd, key);
}

int map_resolve_ifindex(const std::string& iface, LoaderError on_fail)
{
    if (g_active_writer == nullptr) { no_writer_installed(); }
    return g_active_writer->resolve_ifindex(iface, on_fail);
}

// ── the production CATALOG (§5.77.3(5) / guard #10) ───────────────────────────
// EXACTLY the 14 slot-0 written maps, in canonical golden (apply-issue) order
// (§5.76.4(6)): mac, dst, src, proto, port, vlan, dst6, src6, ethertype,
// ruleset_state, rules, slot_rule_id, action_table, redirect_devmap. Widths are
// sizeof() the real key/value types — NOT literals (the ABI static_asserts in
// common/xdpfilter.h pin these). Relocated verbatim from the B43 kFakeMaps.
namespace {
constexpr std::uint32_t kWrittenBase = 1000;  // sentinel/tag space for written maps
constexpr std::uint32_t kShadowBase  = 2000;  // _b siblings: dereferenced, never fd-fetched at slot 0
}  // namespace

const MapDesc kMapCatalog[] = {
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
const std::size_t kMapCatalogCount = sizeof(kMapCatalog) / sizeof(kMapCatalog[0]);

const MapDesc* desc_for_tag(std::uint32_t tag)
{
    for (std::size_t i = 0; i < kMapCatalogCount; ++i) {
        if (kMapCatalog[i].tag == tag) { return &kMapCatalog[i]; }
    }
    return nullptr;
}

namespace {

std::uint32_t tag_by_name(const char* name)
{
    for (std::size_t i = 0; i < kMapCatalogCount; ++i) {
        if (std::strcmp(kMapCatalog[i].name, name) == 0) { return kMapCatalog[i].tag; }
    }
    std::fprintf(stderr, "map_writer: tag_by_name: unknown map '%s'\n", name);
    std::abort();
}

}  // namespace

// ── RecordingMapWriter (§5.77.3(3) — the dumb capture, guard #36) ─────────────
int RecordingMapWriter::fd(bpf_map* m)
{
    // The sentinel pointer value IS the tag (make_dryrun_skel). Decode WITHOUT
    // any libbpf call. An unknown sentinel (e.g. a _b shadow that should never be
    // fd-fetched at slot 0) flags a spec violation.
    const auto tag = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(m));
    if (desc_for_tag(tag) == nullptr) {
        std::fprintf(stderr,
                     "map_writer: fd() on UNEXPECTED sentinel tag %u "
                     "(not one of the 14 slot-0 write targets)\n", tag);
        unexpected_ = true;
    }
    return static_cast<int>(tag);
}

int RecordingMapWriter::update(int fd, const void* key, const void* value,
                               std::uint64_t /*flags*/)
{
    const auto     tag = static_cast<std::uint32_t>(fd);
    const MapDesc* d   = desc_for_tag(tag);
    if (d == nullptr) {
        std::fprintf(stderr,
                     "map_writer: update to UNEXPECTED map tag %u "
                     "(not one of the 14 slot-0 write targets)\n", tag);
        unexpected_ = true;
        return 0;
    }
    RecordedWrite rec;
    rec.map_tag = tag;
    rec.key.assign(static_cast<const std::uint8_t*>(key),
                   static_cast<const std::uint8_t*>(key) + d->key_sz);
    rec.value.assign(static_cast<const std::uint8_t*>(value),
                     static_cast<const std::uint8_t*>(value) + d->val_sz);
    writes_.push_back(std::move(rec));
    return 0;
}

int RecordingMapWriter::next_key(int /*fd*/, const void* /*prev*/, void* /*next*/)
{
    // Empty sentinel inners: no next key. ENOENT terminates the populate bulk-
    // clear loop (D-mvp-4.36-CLEAR-EMPTY) ⇒ occupied-writes-only by construction.
    // The render reads the RETURN value as -errno (libbpf 1.0 strict convention),
    // so return -ENOENT (NOT plain -1, which would decode as -EPERM and make the
    // clear loop throw); errno is also set for any legacy errno-checking caller.
    errno = ENOENT;
    return -ENOENT;
}

int RecordingMapWriter::del(int /*fd*/, const void* /*key*/)
{
    return 0;  // no-op (the recording inners are empty; nothing to delete)
}

int RecordingMapWriter::resolve_ifindex(const std::string& iface, LoaderError /*on_fail*/)
{
    // Record the requested name (the formatter renders it SYMBOLICALLY for
    // redirect_devmap[0]); return a sentinel index never used numerically.
    resolved_name_ = iface;
    return 0x00ABCDEF;
}

// ── dry-run sentinel skel (§5.77.3(7)) ────────────────────────────────────────
xdpfilter_bpf* make_dryrun_skel()
{
    auto* skel = new xdpfilter_bpf{};  // value-init: all pointers null

    auto W = [](std::uint32_t tag) {   // sentinel pointer == tag value
        return reinterpret_cast<struct bpf_map*>(static_cast<std::uintptr_t>(tag));
    };

    // 14 fd-fetched maps: sentinel == the kMapCatalog tag (so fd() → tag → desc).
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
    // inactive_axis_fd args at slot 0 but never fd-fetched/written; a write
    // landing on one decodes to nullptr ⇒ flagged unexpected.
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

void free_dryrun_skel(xdpfilter_bpf* skel) { delete skel; }

}  // namespace xdpmf
