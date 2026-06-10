/*
 * compiled_ruleset.cpp — §5.73 (MVP-4.33 / B40): `compile(const Config&)` +
 * the pure lowering machinery MOVED whole-cloth from loader.cpp (guard #9 —
 * relocation, NOT re-implementation; byte-identical). PURE / libbpf-free /
 * no-throw: this TU links WITHOUT libbpf and WITHOUT loader.cpp — that clean
 * link is the testability contract (D-mvp-4.2-ISOLATION closure / §5.73
 * OPS-canary). The bound-checks stay in apply_request (D-mvp-4.33-Q2), so no
 * throw_loader / loader_error_category dependency reaches here.
 */
#include "compiled_ruleset.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

#include <arpa/inet.h>  // §5.43 (MVP-4.3): ntohl for prefix-closure masking

namespace xdpmf {

namespace {

/* Host-order mask for a prefix length ([0,32]); len==0 → all-zero mask.
 * Transcribed from the §5.42 spike (guard #9 — production-owned, NOT
 * #include'd from tests/bitvec). */
[[nodiscard]] std::uint32_t host_mask(std::uint32_t prefixlen) noexcept
{
    if (prefixlen == 0) {
        return 0u;
    }
    return 0xFFFFFFFFu << (32u - prefixlen);
}

/* Load the 16 network-order bytes (addr6[0]=MSB) into a host-order __int128. */
[[nodiscard]] unsigned __int128 host_addr6_of(const xdpmf_cidr_v6& c) noexcept
{
    unsigned __int128 v = 0;
    for (int i = 0; i < 16; ++i) {
        v = (v << 8) | static_cast<unsigned __int128>(c.addr6[i]);
    }
    return v;
}

/* Host-order 128-bit mask for a v6 prefix length ([0,128]); len==0 → all-zero.
 * The `/0` shift-by-128 UB site is special-cased (len==0 returns 0); for
 * len ∈ [1,128] the shift amount (128-len) ∈ [0,127], never 128 (Q1). */
[[nodiscard]] unsigned __int128 host_mask6(unsigned int prefixlen) noexcept
{
    if (prefixlen == 0) {
        return 0;
    }
    return (~static_cast<unsigned __int128>(0)) << (128u - prefixlen);
}

/* §5.61 (MVP-4.21) B30 D-mvp-4.21-Q3 / SLOT-PLUMB: the loader-internal `slot`
 * carrier. `slot` = the rank of a rule's `id` in ascending-unique-id order,
 * ∈ [0, count-1]. Because slots are assigned in id-sorted order, `1ULL << slot`
 * preserves first-match-by-lowest-id (ffsll(acc)-1 still yields the lowest-id
 * survivor — HG-mvp-4.3-4, PI-mvp-4.21-PRIORITY) while decoupling the bit
 * position / counter index from the (now sparse) operator id. The SAME slot
 * value MUST be used at every populate site (the 4 lowering bit-shifts,
 * rules_inner[slot], rule_counters[slot], slot_rule_id[active*64+slot]) —
 * D-mvp-4.21-SLOT-COHERENCE. ids are unique (config seen_ids dedup). */
[[nodiscard]] std::unordered_map<std::uint32_t, std::uint32_t>
compute_id_to_slot(const std::vector<Rule>& rules)
{
    std::vector<std::uint32_t> ids;
    ids.reserve(rules.size());
    for (const Rule& r : rules) {
        ids.push_back(r.id);
    }
    std::sort(ids.begin(), ids.end());
    std::unordered_map<std::uint32_t, std::uint32_t> id_to_slot;
    id_to_slot.reserve(ids.size());
    for (std::uint32_t rank = 0; rank < ids.size(); ++rank) {
        id_to_slot.emplace(ids[rank], rank);
    }
    return id_to_slot;
}

/* §5.61 B30: the slot→id inverse over the full [0,64) slot space — slot_to_id
 * [slot] = the id occupying `slot`, or XDPMF_SLOT_ID_EMPTY for the unoccupied
 * tail [count,64). Drives both the `slot_rule_id` map write (occupied prefix)
 * and the copy-forward-by-id remap (new-side mapping).
 *
 * §5.81 (MVP-4.41) guard #26 PRODUCER (leg a): the exporter's bounded scan
 * (rule_counters_reader.cpp read_generation) early-`break`s at the FIRST
 * sentinel it reads — it load-bears on this dense-prefix shape (occupied =
 * exactly [0,count), sentinel tail). Do not make the occupied slots sparse. */
[[nodiscard]] std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX>
compute_slot_to_id(const std::vector<Rule>& rules,
                   const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX> slot_to_id;
    slot_to_id.fill(XDPMF_SLOT_ID_EMPTY);
    for (const Rule& r : rules) {
        slot_to_id[id_to_slot.at(r.id)] = r.id;
    }
    return slot_to_id;
}

/* Lower one LPM axis (dst or src) from the validated Config: a rule that sets
 * the axis contributes a BitPrefix at its bit position; a rule that does NOT
 * set the axis contributes its bit to the wildcard mask. §5.61 (MVP-4.21) B30:
 * the bit is `1ULL << slot` (id-sorted rank, D-mvp-4.21-Q3) — slot ∈ [0,count)
 * is shift-safe (config caps the rule COUNT at XDPMF_ALLOWLIST_MAX). */
[[nodiscard]] AxisLowering lower_axis(const Config& c, bool dst_axis,
    const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    AxisLowering out;
    out.prefixes.reserve(c.rules.size());
    for (const Rule& r : c.rules) {
        const std::optional<xdpmf_cidr_v4>& axis =
            dst_axis ? r.match.dst_cidr : r.match.src_cidr;
        const std::uint64_t bit = std::uint64_t{1} << id_to_slot.at(r.id);
        if (axis.has_value()) {
            BitPrefix bp{};
            bp.cidr      = *axis;
            bp.host_addr = ::ntohl(axis->addr);
            bp.bit       = bit;
            out.prefixes.push_back(bp);
        } else {
            out.wildcard |= bit;  // unconstrained on this axis → wildcard survivor
        }
    }
    return out;
}

/* Lower one v6 LPM axis (dst6 or src6). FORK of lower_axis: a rule that sets
 * the axis contributes a BitPrefix6 at its bit; a rule that does NOT set the
 * axis contributes its bit to the wildcard mask (family-blind lowering — a
 * v4-only rule lands in wc_dst6/wc_src6 by this SAME mechanism, the load-
 * bearing Q2 cross-family fill). §5.61 (MVP-4.21) B30: bit = `1ULL << slot`. */
[[nodiscard]] AxisLowering6 lower_axis6(const Config& c, bool dst6_axis,
    const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    AxisLowering6 out;
    out.prefixes.reserve(c.rules.size());
    for (const Rule& r : c.rules) {
        const std::optional<xdpmf_cidr_v6>& axis =
            dst6_axis ? r.match.dst_cidr6 : r.match.src_cidr6;
        const std::uint64_t bit = std::uint64_t{1} << id_to_slot.at(r.id);
        if (axis.has_value()) {
            BitPrefix6 bp{};
            bp.cidr       = *axis;
            bp.host_addr6 = host_addr6_of(*axis);
            bp.bit        = bit;
            out.prefixes.push_back(bp);
        } else {
            out.wildcard |= bit;  // unconstrained on this axis → wildcard survivor
        }
    }
    return out;
}

/* §5.50 (MVP-4.10 B28-2) unify lower_proto_axis / lower_vlan_axis /
 * lower_mac_axis into ONE monomorphized template (rule-of-three OVERRIDES guard
 * #9 per §5.37 / D-3.4f-1). They differed by THREE axes — key type, the
 * projected source member (proto/vlan/mac are distinct std::optional<> types),
 * and the dedup equality (== for proto/vlan, memcmp for the 6-octet mac). Per
 * rule: bit = 1<<slot; key_of(r) projects the axis key (std::nullopt => the rule
 * does NOT constrain this axis, so its bit goes to `wildcard`, FI-2 mutual
 * exclusion); on a key, a linear dedup-scan via key_eq (D-mvp-4.10-MAC-EQ keeps
 * the mac memcmp, NOT ==) ORs the bit into the matching entry, else emplace_back
 * a new entry. Insertion order preserved EXACTLY (D-mvp-4.10-ORDER) =>
 * bit-identical entries/wildcard to the three originals. §5.61 (MVP-4.21) B30:
 * bit = `1ULL << slot` (id-sorted rank, D-mvp-4.21-Q3) — slot ∈ [0,count) is
 * shift-safe (config caps the rule COUNT). Each lambda inlines per
 * instantiation => zero indirect-call cost (Q1 -> A1). */
template<class Key, class Project, class Eq>
[[nodiscard]] AxisAggregate<Key> aggregate_axis(const std::vector<Rule>& rules,
                                                Project key_of, Eq key_eq,
    const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    AxisAggregate<Key> out;
    for (const Rule& r : rules) {
        const std::uint64_t      bit = std::uint64_t{1} << id_to_slot.at(r.id);
        const std::optional<Key> key = key_of(r);
        if (key.has_value()) {
            // Aggregate rules sharing the same exact key into one entry.
            bool merged = false;
            for (std::pair<Key, std::uint64_t>& e : out.entries) {
                if (key_eq(e.first, *key)) {
                    e.second |= bit;
                    merged = true;
                    break;
                }
            }
            if (!merged) {
                out.entries.emplace_back(*key, bit);
            }
        } else {
            out.wildcard |= bit;
        }
    }
    return out;
}

/* Lower the dst_port axis: a rule with `dst_port` set contributes one
 * {lo,hi,bit} slot; a rule WITHOUT `dst_port` contributes its bit to the port
 * wildcard (FI-2). §5.61 (MVP-4.21) B30: bit = `1ULL << slot` (id-sorted rank). */
[[nodiscard]] PortLowering lower_port_axis(const Config& c,
    const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    PortLowering out;
    out.ranges.reserve(c.rules.size());
    for (const Rule& r : c.rules) {
        const std::uint64_t bit = std::uint64_t{1} << id_to_slot.at(r.id);
        if (r.match.dst_port.has_value()) {
            xdpmf_port_range slot{};
            slot.lo  = r.match.dst_port->lo;
            slot.hi  = r.match.dst_port->hi;
            slot.bit = bit;
            out.ranges.push_back(slot);
        } else {
            out.wildcard |= bit;
        }
    }
    return out;
}

}  // namespace

/* §5.43 FI-1 prefix-closure (the #1 bit-vector trap — guard #23). For each
 * prefix P_i in `entries`, OR in bit_j of every P_j that COVERS P_i
 * (P_j.prefixlen <= P_i.prefixlen AND P_j == P_i truncated to P_j.prefixlen),
 * INCLUDING P_i itself. The cover direction is the trap: the LESS-specific
 * (shorter) prefix's bit flows INTO the MORE-specific (longer) prefix's
 * stored mask, so a longest-prefix LPM hit carries every covering rule — and
 * first-match-by-id (ffsll) then picks the lowest covering id. Returns the
 * closed mask aligned 1:1 with `entries`. Transcribed from the §5.42 spike's
 * close_prefixes() into production types (guard #9 — Q3 A1). */
[[nodiscard]] std::vector<std::uint64_t>
close_prefixes(const std::vector<BitPrefix>& entries)
{
    std::vector<std::uint64_t> closed(entries.size(), 0u);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const BitPrefix& pi = entries[i];
        for (const BitPrefix& pj : entries) {
            if (pj.cidr.prefixlen > pi.cidr.prefixlen) {
                continue;  // pj more specific than pi → cannot cover it
            }
            const std::uint32_t m = host_mask(pj.cidr.prefixlen);
            if ((pi.host_addr & m) == (pj.host_addr & m)) {
                closed[i] |= pj.bit;  // pj covers pi (incl. pi == pj)
            }
        }
    }
    return closed;
}

/* §5.53 FI-1 prefix-closure at 128 bits (guard #23 — the #1 bit-vector trap).
 * FORKED from close_prefixes: for each P_i, OR in bit_j of every P_j that
 * COVERS P_i (P_j.prefixlen <= P_i.prefixlen AND P_j == P_i truncated to
 * P_j.prefixlen), INCLUDING P_i. The LESS-specific (lower-id) covering prefix's
 * bit flows INTO the MORE-specific entry's stored mask, so a longest-prefix LPM
 * hit carries every covering rule and ffsll picks the lowest covering id. */
[[nodiscard]] std::vector<std::uint64_t>
close_prefixes6(const std::vector<BitPrefix6>& entries)
{
    std::vector<std::uint64_t> closed(entries.size(), 0u);
    for (std::size_t i = 0; i < entries.size(); ++i) {
        const BitPrefix6& pi = entries[i];
        for (const BitPrefix6& pj : entries) {
            if (pj.cidr.prefixlen > pi.cidr.prefixlen) {
                continue;  // pj more specific than pi → cannot cover it
            }
            const unsigned __int128 m = host_mask6(pj.cidr.prefixlen);
            if ((pi.host_addr6 & m) == (pj.host_addr6 & m)) {
                closed[i] |= pj.bit;  // pj covers pi (incl. pi == pj)
            }
        }
    }
    return closed;
}

/* §5.73 (MVP-4.33) B40: lower a validated Config into the named CompiledRuleset.
 * VERBATIM lift of apply_request's former 12-local lowering block (guard #9):
 * the 11 lower_axis/aggregate_axis/lower_port_axis calls + compute_id_to_slot +
 * compute_slot_to_id, assembled into the aggregate. PURE / no-throw / libbpf-
 * free: the overflow bound-checks stay in apply_request (D-mvp-4.33-Q2). */
CompiledRuleset compile(const Config& c)
{
    CompiledRuleset cr;
    // §5.61 (MVP-4.21) B30 D-mvp-4.21-Q3 / SLOT-PLUMB: assign each rule a dense
    // internal `slot` = its rank in ascending-unique-id order; slot_to_id is the
    // [0,64) inverse (id or EMPTY).
    cr.id_to_slot = compute_id_to_slot(c.rules);
    cr.slot_to_id = compute_slot_to_id(c.rules, cr.id_to_slot);
    // §5.50 (MVP-4.10 B28-2): mac/proto/vlan exact-HASH lowering via the generic
    // aggregate_axis template; mac uses a 6-octet memcmp equality (NOT ==,
    // D-mvp-4.10-MAC-EQ).
    cr.mac_low = aggregate_axis<xdpmf_mac>(
        c.rules,
        [](const Rule& r) { return r.match.mac; },
        [](const xdpmf_mac& a, const xdpmf_mac& b) {
            return std::memcmp(a.octets, b.octets, sizeof(a.octets)) == 0;
        },
        cr.id_to_slot);
    cr.dst_low  = lower_axis(c, /*dst_axis=*/true, cr.id_to_slot);
    cr.src_low  = lower_axis(c, /*dst_axis=*/false, cr.id_to_slot);
    // §5.53 (MVP-4.13): the two IPv6 LPM axes (dst6/src6). Family-blind (a
    // v4-only rule lands in wc_dst6/wc_src6, the load-bearing Q2 cross-family fill).
    cr.dst6_low = lower_axis6(c, /*dst6_axis=*/true, cr.id_to_slot);
    cr.src6_low = lower_axis6(c, /*dst6_axis=*/false, cr.id_to_slot);
    // §5.44 (MVP-4.4): proto exact-HASH + dst_port range. NO closure.
    cr.proto_low = aggregate_axis<std::uint32_t>(
        c.rules,
        [](const Rule& r) -> std::optional<std::uint32_t> { return r.match.protocol; },
        std::equal_to<std::uint32_t>{},
        cr.id_to_slot);
    cr.port_low  = lower_port_axis(c, cr.id_to_slot);
    // §5.45 (MVP-4.5): vlan exact-HASH (outer VID, u16 widened to the BPF __u32
    // HASH key — D-mvp-4.5-VLAN-VALUE-WIDTH). NO closure.
    cr.vlan_low = aggregate_axis<std::uint32_t>(
        c.rules,
        [](const Rule& r) -> std::optional<std::uint32_t> {
            if (r.match.vlan) return std::uint32_t{*r.match.vlan};
            return std::nullopt;
        },
        std::equal_to<std::uint32_t>{},
        cr.id_to_slot);
    // §5.54 (MVP-4.14): ethertype exact-HASH (host-order u16 widened to __u32).
    // CLONE of the vlan lowering; NO closure (D-mvp-4.14-CLONE).
    cr.eth_low = aggregate_axis<std::uint32_t>(
        c.rules,
        [](const Rule& r) -> std::optional<std::uint32_t> {
            if (r.match.ethertype) return std::uint32_t{*r.match.ethertype};
            return std::nullopt;
        },
        std::equal_to<std::uint32_t>{},
        cr.id_to_slot);
    cr.default_action = c.default_action;
    // D-mvp-4.33-Q1: non-owning span into the caller's Config.rules (which
    // outlives cr); the action axis stays raw for the mirror/redirect path.
    cr.rules = std::span<const Rule>{c.rules};
    return cr;
}

}  // namespace xdpmf
