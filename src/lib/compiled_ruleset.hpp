/*
 * compiled_ruleset.hpp — §5.73 (MVP-4.33 / B40): the named, libbpf-free output
 * of lowering a validated Config into the per-axis bit-vector form the datapath
 * populate consumes. PURE HOST-SIDE: this header (and compiled_ruleset.cpp)
 * touch NO libbpf / skeleton / .bpf.c — `compile()` is a pure, side-effect-free,
 * non-throwing transform (D-mvp-4.33-Q2). The per-axis `*Lowering` types are
 * MOVED whole-cloth from loader.cpp (guard #9 — share/move, never duplicate);
 * `struct CompiledRuleset` is a dumb value-aggregate (guard #36) bundling the
 * 12 branch-INVARIANT compile locals + a non-owning span over Config.rules
 * (D-mvp-4.33-Q1). Private header (src/lib/, like apply_internal.hpp) — names no
 * loader.hpp public symbol (PI-7).
 */
#ifndef XDPMF_COMPILED_RULESET_HPP
#define XDPMF_COMPILED_RULESET_HPP

#include "config.hpp"          // Rule, Config, DefaultAction, RuleAction
#include "common/xdpfilter.h"  // xdpmf_mac/_cidr_v4/_cidr_v6/_port_range, XDPMF_*

#include <array>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>

namespace xdpmf {

/* §5.43 (MVP-4.3) D-mvp-4.3-Q3: a constrained prefix on one LPM axis carrying
 * the rule's bit (= 1ULL << slot). `cidr.addr` is network byte order (the
 * LPM_TRIE key shape); `host_addr` is the host-order copy used for prefix
 * masking in close_prefixes. */
struct BitPrefix {
    xdpmf_cidr_v4 cidr;
    std::uint32_t host_addr;
    std::uint64_t bit;
};

/* §5.43 per-LPM-axis lowering result: the constrained prefixes (rules that
 * set this axis) + the wildcard mask (OR of bits for rules that do NOT
 * constrain this axis — they survive the axis unconditionally via
 * wildcard[active*2+axis], FI-2 mutual exclusion). */
struct AxisLowering {
    std::vector<BitPrefix> prefixes;
    std::uint64_t          wildcard = 0u;
};

/* §5.53 (MVP-4.13) D-mvp-4.13-FORK: the IPv6 sibling of BitPrefix — a v6
 * constrained prefix carrying the rule's bit. `cidr.addr6` is network byte
 * order (the LPM_TRIE key shape); `host_addr6` is the host-order `unsigned
 * __int128` copy used for 128-bit prefix masking in close_prefixes6 (Q1=A1 —
 * mirrors the v4 cover-direction body so the #1-bug-class invariant is
 * eyeball-auditable). */
struct BitPrefix6 {
    xdpmf_cidr_v6     cidr;
    unsigned __int128 host_addr6;
    std::uint64_t     bit;
};

/* §5.53 per-v6-LPM-axis lowering result — FORK of AxisLowering. */
struct AxisLowering6 {
    std::vector<BitPrefix6> prefixes;
    std::uint64_t           wildcard = 0u;
};

/* §5.50 (MVP-4.10 B28-2) generic per-exact-HASH-axis lowering result — replaces
 * the byte-identical ProtoLowering/VlanLowering structs and the key-only-
 * different MacLowering (D-mvp-4.10-STRUCT). entries[k] = {key, OR of bits of
 * every rule constraining that exact key}; wildcard = OR of bits of rules NOT
 * constraining this axis. NO prefix-closure (exact-match HASH). PortLowering +
 * the dst/src AxisLowering are NOT folded (different shape — D-mvp-4.10-
 * BOUNDARY). */
template<class Key>
struct AxisAggregate {
    std::vector<std::pair<Key, std::uint64_t>> entries;
    std::uint64_t                              wildcard = 0u;
};
// Name-preserving aliases — Proto/Vlan are the SAME instantiation (legal); keep
// materialize's signature + the apply_request locals textually stable.
using ProtoLowering = AxisAggregate<std::uint32_t>;
using VlanLowering  = AxisAggregate<std::uint32_t>;
using MacLowering   = AxisAggregate<xdpmf_mac>;
// §5.54 (MVP-4.14): ethertype is an exact-HASH axis identical in shape to
// proto/vlan (only the projected source member differs: r.match.ethertype,
// widened u16→u32). Same instantiation; CLONE not fork (D-mvp-4.14-CLONE).
using EthertypeLowering = AxisAggregate<std::uint32_t>;

/* §5.44 (MVP-4.4) per-port-axis lowering result: one xdpmf_port_range slot per
 * port-constrained rule (single port ⇒ lo==hi) + the wildcard mask (rules NOT
 * constraining dst_port). NO prefix-closure (explicit ranges — D-mvp-4.4-
 * NO-CLOSURE). */
struct PortLowering {
    std::vector<xdpmf_port_range> ranges;
    std::uint64_t                 wildcard = 0u;
};

/* §5.73 (MVP-4.33) B40: the named compile output (guard #36 — dumb value
 * aggregate, no methods/logic). Exactly the 12 branch-INVARIANT compile locals
 * that apply_request used to thread through populate_all_axes' 16-arg signature,
 * plus a NON-OWNING span over Config.rules (D-mvp-4.33-Q1 — the action axis
 * stays raw for the mirror/redirect forward path; lifetime: `cr.rules` spans the
 * caller's `req.config.rules`, which outlives `cr`). */
struct CompiledRuleset {
    std::unordered_map<std::uint32_t, std::uint32_t>     id_to_slot;     // id → dense slot rank
    std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX>   slot_to_id;     // [0,64) inverse, EMPTY tail
    MacLowering                                          mac_low;        // AxisAggregate<xdpmf_mac>
    AxisLowering                                         dst_low;        // v4 LPM prefixes + wildcard
    AxisLowering                                         src_low;
    AxisLowering6                                        dst6_low;       // v6 LPM
    AxisLowering6                                        src6_low;
    ProtoLowering                                        proto_low;      // AxisAggregate<u32>
    PortLowering                                         port_low;       // ranges + wildcard
    VlanLowering                                         vlan_low;       // AxisAggregate<u32>
    EthertypeLowering                                    eth_low;        // AxisAggregate<u32>
    DefaultAction                                        default_action;
    std::span<const Rule>                                rules;          // NON-OWNING (Q1=A1)
};

/* §5.73 the pure lowering transform: validated Config → CompiledRuleset.
 * Side-effect-free, libbpf-free, NON-THROWING (D-mvp-4.33-Q2 keeps the
 * overflow bound-checks in apply_request, not here). */
[[nodiscard]] CompiledRuleset compile(const Config& c);

/* §5.43 FI-1 prefix-closure (the #1 bit-vector trap — guard #23). External
 * linkage so materialize() (loader.cpp) can still pass them by name to
 * populate_bitvec_inner_slot; defined in compiled_ruleset.cpp. */
[[nodiscard]] std::vector<std::uint64_t>
close_prefixes(const std::vector<BitPrefix>& entries);

[[nodiscard]] std::vector<std::uint64_t>
close_prefixes6(const std::vector<BitPrefix6>& entries);

}  // namespace xdpmf

#endif  // XDPMF_COMPILED_RULESET_HPP
