/*
 * compile_harness.cpp — §5.73 (MVP-4.33 / B40) offline unit test of the
 * production lowering `xdpmf::compile(const Config&) -> CompiledRuleset`.
 *
 * D-mvp-4.2-ISOLATION closure: this is the FIRST direct assertion of the
 * production `lower_*`/`aggregate_axis`/`compute_*_slot` path (until now only
 * the bitvec_harness PARALLEL reimplementation was tested). The test:
 *
 *   1. builds an in-memory Config corpus exercising representative axes
 *      (v4 dst/src LPM incl. a covering/covered pair, v6 dst/src LPM, mac/
 *      proto/vlan/ethertype exact-match HASH incl. a same-key aggregation
 *      pair, a dst_port range, and rules that leave axes unconstrained →
 *      wildcard bits), with >=1 RuleAction::Pass and >=1 RuleAction::Drop
 *      (recheck #4), and non-contiguous ids so slot != id (exercises the
 *      ascending-unique-id rank map + the XDPMF_SLOT_ID_EMPTY tail);
 *   2. runs the production compile();
 *   3. INDEPENDENTLY derives the expected lowering from the §5.73 slot model
 *      (slot = rank of a rule's id in ascending-unique-id order; bit =
 *      1ULL << slot; HASH entries aggregate by exact key in first-appearance
 *      order; LPM prefixes carry the raw per-rule bit — closure is applied
 *      later in materialize(), NOT in compile()) and asserts field-equality.
 *
 * Bare-main, NO gtest, NO libbpf (bitvec_harness precedent). The clean
 * libbpf-free link is itself the OPS-canary contract (§5.73 TestStrategy):
 * if compile() ever acquires a libbpf / error-category dependency this binary
 * fails to LINK. The CMake target links compiled_ruleset.cpp ONLY.
 *
 * Assertion mechanism: plain `if (mismatch) { fprintf(stderr, ...); ++fails; }`
 * accumulation; non-zero exit on any mismatch. A trailing NEGATION CONTROL
 * proves the comparison machinery can actually fail, and a SMOKE test proves
 * compile() returns a sane shape on a minimal Config.
 */
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "common/xdpfilter.h"   // xdpmf_mac, xdpmf_cidr_v4/v6, xdpmf_port_range, XDPMF_*
#include "config.hpp"           // Config, Rule, RuleMatch, RuleAction, DefaultAction, PortRange
#include "compiled_ruleset.hpp" // xdpmf::CompiledRuleset, xdpmf::compile()

using namespace xdpmf;

namespace {

int g_fails = 0;

void fail(const std::string& what)
{
    std::fprintf(stderr, "FAIL: %s\n", what.c_str());
    ++g_fails;
}

#define CHECK(cond, msg)                 \
    do {                                 \
        if (!(cond)) { fail(msg); }      \
    } while (false)

// ───────────────────────── helpers: CIDR builders ──────────────────────────

// Build an xdpmf_cidr_v4 from dotted octets + prefixlen. addr is NETWORK byte
// order (big-endian on the wire); host_addr (for prefix masking) is host order.
xdpmf_cidr_v4 cidr4(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                    std::uint8_t d, std::uint32_t prefixlen)
{
    xdpmf_cidr_v4 k{};
    k.prefixlen = prefixlen;
    // host-order value a.b.c.d; stored network order (big-endian) => bytes a,b,c,d.
    k.addr = (static_cast<std::uint32_t>(a) << 24) |
             (static_cast<std::uint32_t>(b) << 16) |
             (static_cast<std::uint32_t>(c) << 8)  |
             (static_cast<std::uint32_t>(d));
    // On a little-endian host the on-wire (network) byte order of a.b.c.d is the
    // byte sequence {a,b,c,d}; htonl of the host value yields exactly that. We
    // store the network-order u32 (matches xdpmf_cidr_v4.addr contract).
    std::uint32_t host = k.addr;
    k.addr = __builtin_bswap32(host); // network order on LE host
    return k;
}

std::uint32_t host_order_v4(const xdpmf_cidr_v4& c)
{
    // inverse of cidr4's network-order storage → host order for masking
    return __builtin_bswap32(c.addr);
}

xdpmf_cidr_v6 cidr6(std::initializer_list<std::uint8_t> bytes, std::uint32_t prefixlen)
{
    xdpmf_cidr_v6 k{};
    k.prefixlen = prefixlen;
    std::size_t i = 0;
    for (std::uint8_t byte : bytes) {
        if (i < 16) { k.addr6[i] = byte; }
        ++i;
    }
    return k;
}

xdpmf_mac mac(std::uint8_t a, std::uint8_t b, std::uint8_t c,
              std::uint8_t d, std::uint8_t e, std::uint8_t f)
{
    return xdpmf_mac{{a, b, c, d, e, f}};
}

// ───────────────── independent oracle: the §5.73 slot model ─────────────────

// slot = rank of a rule's id in ascending-unique-id order.
std::unordered_map<std::uint32_t, std::uint32_t>
oracle_id_to_slot(const Config& cfg)
{
    std::vector<std::uint32_t> ids;
    ids.reserve(cfg.rules.size());
    for (const Rule& r : cfg.rules) { ids.push_back(r.id); }
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    std::unordered_map<std::uint32_t, std::uint32_t> m;
    for (std::uint32_t slot = 0; slot < ids.size(); ++slot) {
        m[ids[slot]] = slot;
    }
    return m;
}

std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX>
oracle_slot_to_id(const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot)
{
    std::array<std::uint32_t, XDPMF_RULE_COUNTERS_MAX> s{};
    s.fill(XDPMF_SLOT_ID_EMPTY);
    for (const auto& [id, slot] : id_to_slot) {
        if (slot < XDPMF_RULE_COUNTERS_MAX) { s[slot] = id; }
    }
    return s;
}

std::uint64_t bit_of(const std::unordered_map<std::uint32_t, std::uint32_t>& id_to_slot,
                     std::uint32_t id)
{
    return 1ULL << id_to_slot.at(id);
}

// host-order mask for a v4 prefixlen ([0,32]); len 0 => all-zero.
std::uint32_t host_mask4(std::uint32_t len)
{
    return len == 0 ? 0u : (0xFFFFFFFFu << (32u - len));
}

// OOT-1 (§5.74 RD-5): independent v6 host-order derivations (do NOT call into
// production). host_addr6_oracle loads the 16 network-order bytes (addr6[0]=MSB)
// into a host-order __int128; host_mask6 builds the host-order prefix mask.
unsigned __int128 host_addr6_oracle(const xdpmf_cidr_v6& c)
{
    unsigned __int128 v = 0;
    for (int i = 0; i < 16; ++i) {
        v = (v << 8) | static_cast<unsigned __int128>(c.addr6[i]);
    }
    return v;
}

unsigned __int128 host_mask6(std::uint32_t len)
{
    if (len == 0) { return 0; }
    const unsigned __int128 all_ones = ~static_cast<unsigned __int128>(0);
    return all_ones << (128u - len);
}

// ───────────────────────────── the corpus ──────────────────────────────────
//
// Non-contiguous ids => slot != id. Sorted unique ids:
//   {0,1,2,3,4,5,6,7,8,9,11,40} -> slots 0..11.
// Covering/covered v4 dst pair (10.0.0.0/8 covers 10.1.2.0/24); v6 dst pair
// (2001:db8::/32 covers 2001:db8:1::/48); proto=6 shared by 2 rules
// (aggregation); mac AA:..:FF shared by 2 rules (aggregation). Pass + Drop
// both present (recheck #4). Several rules leave most axes unconstrained =>
// wildcard bits on those axes.

Config build_corpus()
{
    Config cfg;
    cfg.schema_version = 2;
    cfg.default_action = DefaultAction::Drop;

    auto add = [&](std::uint32_t id, RuleAction action, RuleMatch m) {
        Rule r;
        r.id = id;
        r.action = action;
        r.match = std::move(m);
        cfg.rules.push_back(std::move(r));
    };

    { RuleMatch m; m.dst_cidr = cidr4(10, 0, 0, 0, 8);   add(5,  RuleAction::Pass, m); } // v4 dst covering
    { RuleMatch m; m.dst_cidr = cidr4(10, 1, 2, 0, 24);  add(2,  RuleAction::Drop, m); } // v4 dst covered
    { RuleMatch m; m.src_cidr = cidr4(192,168,0, 0, 16); add(9,  RuleAction::Pass, m); } // v4 src
    { RuleMatch m; m.mac = mac(0xAA,0xBB,0xCC,0xDD,0xEE,0xFF); add(1, RuleAction::Drop, m); } // mac key X
    { RuleMatch m; m.mac = mac(0xAA,0xBB,0xCC,0xDD,0xEE,0xFF); add(11,RuleAction::Pass, m); } // mac key X (aggregate)
    { RuleMatch m; m.protocol = 6; m.dst_port = PortRange{80, 443}; add(7, RuleAction::Pass, m); } // proto 6 + port
    { RuleMatch m; m.protocol = 6;                       add(40, RuleAction::Drop, m); } // proto 6 (aggregate)
    { RuleMatch m; m.vlan = 100;                         add(3,  RuleAction::Drop, m); } // vlan
    { RuleMatch m; m.ethertype = 0x0806;                 add(8,  RuleAction::Pass, m); } // ethertype ARP
    { RuleMatch m; m.dst_cidr6 = cidr6({0x20,0x01,0x0d,0xb8}, 32);            add(4, RuleAction::Drop, m); } // v6 dst covering
    { RuleMatch m; m.dst_cidr6 = cidr6({0x20,0x01,0x0d,0xb8,0x00,0x01}, 48);  add(6, RuleAction::Pass, m); } // v6 dst covered
    { RuleMatch m; m.src_cidr6 = cidr6({0xfe,0x80}, 10);                      add(0, RuleAction::Drop, m); } // v6 src

    return cfg;
}

// ───────────── per-axis independent expected derivations ────────────────────

struct ExpPrefix4 { xdpmf_cidr_v4 cidr; std::uint32_t host_addr; std::uint64_t bit; };
// OOT-1 (§5.74 RD-5): ExpPrefix6 now carries host_addr6, the v6 analog of
// ExpPrefix4::host_addr — derived below and asserted in cmp_v6.
struct ExpPrefix6 { xdpmf_cidr_v6 cidr; unsigned __int128 host_addr6; std::uint64_t bit; };
struct ExpEntryU32 { std::uint32_t key; std::uint64_t mask; };
struct ExpEntryMac { xdpmf_mac key; std::uint64_t mask; };
struct ExpPort     { std::uint32_t lo; std::uint32_t hi; std::uint64_t bit; };

// LPM v4 axis: per constraining rule a {cidr, host_addr, own-bit}; others -> wc.
template <typename Sel>
void expect_v4(const Config& cfg,
               const std::unordered_map<std::uint32_t, std::uint32_t>& i2s,
               Sel sel, std::vector<ExpPrefix4>& out, std::uint64_t& wc)
{
    wc = 0;
    for (const Rule& r : cfg.rules) {
        const std::optional<xdpmf_cidr_v4>& c = sel(r.match);
        if (c) {
            // OOT-3 (§5.74 RD-5): the `& host_mask4(prefixlen)` here is
            // TEST-DERIVATION-ONLY — production stores host_addr UNMASKED; the
            // two agree only because the corpus CIDRs are host-bits-zero (the
            // config invariant). Same note applies to the v6 host_addr6 oracle.
            out.push_back(ExpPrefix4{*c, host_order_v4(*c) & host_mask4(c->prefixlen),
                                     bit_of(i2s, r.id)});
        } else {
            wc |= bit_of(i2s, r.id);
        }
    }
}

template <typename Sel>
void expect_v6(const Config& cfg,
               const std::unordered_map<std::uint32_t, std::uint32_t>& i2s,
               Sel sel, std::vector<ExpPrefix6>& out, std::uint64_t& wc)
{
    wc = 0;
    for (const Rule& r : cfg.rules) {
        const std::optional<xdpmf_cidr_v6>& c = sel(r.match);
        if (c) {
            // OOT-1: derive host_addr6 like the v4 host_addr — masked to the
            // prefix. Equivalent to production's UNMASKED store under the same
            // host-bits-zero corpus invariant noted at the v4 oracle (OOT-3).
            out.push_back(ExpPrefix6{*c,
                host_addr6_oracle(*c) & host_mask6(c->prefixlen),
                bit_of(i2s, r.id)});
        } else {
            wc |= bit_of(i2s, r.id);
        }
    }
}

// HASH u32 axis: aggregate bits by exact key, first-appearance order; others->wc.
template <typename Sel>
void expect_u32(const Config& cfg,
                const std::unordered_map<std::uint32_t, std::uint32_t>& i2s,
                Sel sel, std::vector<ExpEntryU32>& out, std::uint64_t& wc)
{
    wc = 0;
    for (const Rule& r : cfg.rules) {
        std::optional<std::uint32_t> key = sel(r.match);
        if (key) {
            auto it = std::find_if(out.begin(), out.end(),
                                   [&](const ExpEntryU32& e) { return e.key == *key; });
            if (it == out.end()) { out.push_back(ExpEntryU32{*key, bit_of(i2s, r.id)}); }
            else                 { it->mask |= bit_of(i2s, r.id); }
        } else {
            wc |= bit_of(i2s, r.id);
        }
    }
}

void expect_mac(const Config& cfg,
                const std::unordered_map<std::uint32_t, std::uint32_t>& i2s,
                std::vector<ExpEntryMac>& out, std::uint64_t& wc)
{
    wc = 0;
    for (const Rule& r : cfg.rules) {
        if (r.match.mac) {
            const xdpmf_mac& k = *r.match.mac;
            auto it = std::find_if(out.begin(), out.end(), [&](const ExpEntryMac& e) {
                return std::memcmp(e.key.octets, k.octets, 6) == 0;
            });
            if (it == out.end()) { out.push_back(ExpEntryMac{k, bit_of(i2s, r.id)}); }
            else                 { it->mask |= bit_of(i2s, r.id); }
        } else {
            wc |= bit_of(i2s, r.id);
        }
    }
}

void expect_port(const Config& cfg,
                 const std::unordered_map<std::uint32_t, std::uint32_t>& i2s,
                 std::vector<ExpPort>& out, std::uint64_t& wc)
{
    wc = 0;
    for (const Rule& r : cfg.rules) {
        if (r.match.dst_port) {
            out.push_back(ExpPort{r.match.dst_port->lo, r.match.dst_port->hi, bit_of(i2s, r.id)});
        } else {
            wc |= bit_of(i2s, r.id);
        }
    }
}

// ───────────────────── comparators (cr field reads) ─────────────────────────
//
// The cr.<axis>.<member> accessors below follow the §5.73 DataStructures
// layout: BitPrefix{.cidr,.host_addr,.bit}, BitPrefix6{.cidr,.host_addr6,.bit},
// AxisLowering/6{.prefixes,.wildcard}, AxisAggregate<K>{.entries (vector of
// std::pair<K,uint64_t>),.wildcard}, PortLowering{.ranges (xdpmf_port_range),
// .wildcard}.

void cmp_v4(const char* name, const AxisLowering& got,
            const std::vector<ExpPrefix4>& exp, std::uint64_t exp_wc)
{
    CHECK(got.wildcard == exp_wc, std::string(name) + ".wildcard");
    CHECK(got.prefixes.size() == exp.size(), std::string(name) + ".prefixes.size");
    const std::size_t n = std::min(got.prefixes.size(), exp.size());
    for (std::size_t i = 0; i < n; ++i) {
        const auto& g = got.prefixes[i]; // [CR-FIELD] BitPrefix
        CHECK(g.cidr.prefixlen == exp[i].cidr.prefixlen, std::string(name) + " prefixlen@" + std::to_string(i));
        CHECK(g.cidr.addr == exp[i].cidr.addr,           std::string(name) + " addr@" + std::to_string(i));
        CHECK(g.host_addr == exp[i].host_addr,           std::string(name) + " host_addr@" + std::to_string(i));
        CHECK(g.bit == exp[i].bit,                       std::string(name) + " bit@" + std::to_string(i));
    }
}

void cmp_v6(const char* name, const AxisLowering6& got,
            const std::vector<ExpPrefix6>& exp, std::uint64_t exp_wc)
{
    CHECK(got.wildcard == exp_wc, std::string(name) + ".wildcard");
    CHECK(got.prefixes.size() == exp.size(), std::string(name) + ".prefixes.size");
    const std::size_t n = std::min(got.prefixes.size(), exp.size());
    for (std::size_t i = 0; i < n; ++i) {
        const auto& g = got.prefixes[i]; // [CR-FIELD] BitPrefix6
        CHECK(g.cidr.prefixlen == exp[i].cidr.prefixlen, std::string(name) + " prefixlen@" + std::to_string(i));
        CHECK(std::memcmp(g.cidr.addr6, exp[i].cidr.addr6, 16) == 0, std::string(name) + " addr6@" + std::to_string(i));
        CHECK(g.host_addr6 == exp[i].host_addr6,         std::string(name) + " host_addr6@" + std::to_string(i)); // OOT-1
        CHECK(g.bit == exp[i].bit,                       std::string(name) + " bit@" + std::to_string(i));
    }
}

template <typename Agg>
void cmp_u32(const char* name, const Agg& got,
             const std::vector<ExpEntryU32>& exp, std::uint64_t exp_wc)
{
    CHECK(got.wildcard == exp_wc, std::string(name) + ".wildcard");
    CHECK(got.entries.size() == exp.size(), std::string(name) + ".entries.size");
    const std::size_t n = std::min(got.entries.size(), exp.size());
    for (std::size_t i = 0; i < n; ++i) {
        // AxisAggregate<Key>::entries is std::vector<std::pair<Key,uint64_t>>
        // (§5.73 DataStructures) → .first = key, .second = aggregated bitmask.
        const auto& g = got.entries[i];
        CHECK(g.first == exp[i].key,   std::string(name) + " key@" + std::to_string(i));
        CHECK(g.second == exp[i].mask, std::string(name) + " mask@" + std::to_string(i));
    }
}

void cmp_mac(const char* name, const MacLowering& got,
             const std::vector<ExpEntryMac>& exp, std::uint64_t exp_wc)
{
    CHECK(got.wildcard == exp_wc, std::string(name) + ".wildcard");
    CHECK(got.entries.size() == exp.size(), std::string(name) + ".entries.size");
    const std::size_t n = std::min(got.entries.size(), exp.size());
    for (std::size_t i = 0; i < n; ++i) {
        // AxisAggregate<xdpmf_mac>::entries element = std::pair<xdpmf_mac,uint64_t>.
        const auto& g = got.entries[i];
        CHECK(std::memcmp(g.first.octets, exp[i].key.octets, 6) == 0, std::string(name) + " key@" + std::to_string(i));
        CHECK(g.second == exp[i].mask, std::string(name) + " mask@" + std::to_string(i));
    }
}

void cmp_port(const char* name, const PortLowering& got,
              const std::vector<ExpPort>& exp, std::uint64_t exp_wc)
{
    CHECK(got.wildcard == exp_wc, std::string(name) + ".wildcard");
    CHECK(got.ranges.size() == exp.size(), std::string(name) + ".ranges.size");
    const std::size_t n = std::min(got.ranges.size(), exp.size());
    for (std::size_t i = 0; i < n; ++i) {
        const auto& g = got.ranges[i]; // [CR-FIELD] PortLowering::range
        CHECK(g.lo == exp[i].lo,   std::string(name) + " lo@" + std::to_string(i));
        CHECK(g.hi == exp[i].hi,   std::string(name) + " hi@" + std::to_string(i));
        CHECK(g.bit == exp[i].bit, std::string(name) + " bit@" + std::to_string(i));
    }
}

// ────────────────────────────── the tests ──────────────────────────────────

void test_lowering_identity()
{
    const Config cfg = build_corpus();
    const CompiledRuleset cr = compile(cfg);

    const auto i2s = oracle_id_to_slot(cfg);
    const auto s2i = oracle_slot_to_id(i2s);

    // slot maps
    CHECK(cr.id_to_slot == i2s, "id_to_slot (unordered_map operator==)");
    CHECK(cr.slot_to_id == s2i, "slot_to_id array");
    CHECK(cr.default_action == cfg.default_action, "default_action");

    // rules span carried through (recheck #4: Pass + Drop reach their slots)
    CHECK(cr.rules.size() == cfg.rules.size(), "rules span size");
    bool saw_pass = false, saw_drop = false;
    for (const Rule& r : cr.rules) {
        if (r.action == RuleAction::Pass) { saw_pass = true; }
        if (r.action == RuleAction::Drop) { saw_drop = true; }
    }
    CHECK(saw_pass, "corpus carries >=1 Pass rule");
    CHECK(saw_drop, "corpus carries >=1 Drop rule");

    // v4 LPM axes
    std::vector<ExpPrefix4> e_dst, e_src; std::uint64_t w;
    expect_v4(cfg, i2s, [](const RuleMatch& m) -> const std::optional<xdpmf_cidr_v4>& { return m.dst_cidr; }, e_dst, w);
    cmp_v4("dst_low", cr.dst_low, e_dst, w);
    expect_v4(cfg, i2s, [](const RuleMatch& m) -> const std::optional<xdpmf_cidr_v4>& { return m.src_cidr; }, e_src, w);
    cmp_v4("src_low", cr.src_low, e_src, w);

    // v6 LPM axes
    std::vector<ExpPrefix6> e6d, e6s;
    expect_v6(cfg, i2s, [](const RuleMatch& m) -> const std::optional<xdpmf_cidr_v6>& { return m.dst_cidr6; }, e6d, w);
    cmp_v6("dst6_low", cr.dst6_low, e6d, w);
    expect_v6(cfg, i2s, [](const RuleMatch& m) -> const std::optional<xdpmf_cidr_v6>& { return m.src_cidr6; }, e6s, w);
    cmp_v6("src6_low", cr.src6_low, e6s, w);

    // HASH u32 axes (proto / vlan / ethertype)
    std::vector<ExpEntryU32> ep, ev, ee;
    expect_u32(cfg, i2s, [](const RuleMatch& m) -> std::optional<std::uint32_t> {
        return m.protocol ? std::optional<std::uint32_t>(*m.protocol) : std::nullopt; }, ep, w);
    cmp_u32("proto_low", cr.proto_low, ep, w);
    expect_u32(cfg, i2s, [](const RuleMatch& m) -> std::optional<std::uint32_t> {
        return m.vlan ? std::optional<std::uint32_t>(*m.vlan) : std::nullopt; }, ev, w);
    cmp_u32("vlan_low", cr.vlan_low, ev, w);
    expect_u32(cfg, i2s, [](const RuleMatch& m) -> std::optional<std::uint32_t> {
        return m.ethertype ? std::optional<std::uint32_t>(*m.ethertype) : std::nullopt; }, ee, w);
    cmp_u32("eth_low", cr.eth_low, ee, w);

    // mac HASH axis
    std::vector<ExpEntryMac> em;
    expect_mac(cfg, i2s, em, w);
    cmp_mac("mac_low", cr.mac_low, em, w);

    // port axis
    std::vector<ExpPort> eport;
    expect_port(cfg, i2s, eport, w);
    cmp_port("port_low", cr.port_low, eport, w);
}

// SMOKE: compile() on a minimal one-rule Config returns a sane shape.
void test_smoke_minimal()
{
    Config cfg;
    cfg.schema_version = 2;
    cfg.default_action = DefaultAction::Pass;
    { Rule r; r.id = 42; r.action = RuleAction::Drop;
      r.match.dst_cidr = cidr4(203, 0, 113, 0, 24);
      cfg.rules.push_back(r); }

    const CompiledRuleset cr = compile(cfg);
    CHECK(cr.id_to_slot.size() == 1, "smoke: id_to_slot size==1");
    CHECK(cr.id_to_slot.count(42) == 1 && cr.id_to_slot.at(42) == 0, "smoke: id 42 -> slot 0");
    CHECK(cr.slot_to_id[0] == 42, "smoke: slot_to_id[0]==42");
    CHECK(cr.slot_to_id[1] == XDPMF_SLOT_ID_EMPTY, "smoke: slot_to_id[1]==EMPTY");
    CHECK(cr.default_action == DefaultAction::Pass, "smoke: default_action==Pass");
    CHECK(cr.dst_low.prefixes.size() == 1, "smoke: one dst prefix");
}

// NEGATION CONTROL: a deliberately-wrong expectation MUST be detected by the
// comparison machinery. We corrupt one expected wildcard bit and assert the
// equality test reports a mismatch — proving the assertions can actually fail.
void test_negation_control()
{
    const Config cfg = build_corpus();
    const CompiledRuleset cr = compile(cfg);
    const auto i2s = oracle_id_to_slot(cfg);

    std::vector<ExpPrefix4> e_dst; std::uint64_t w = 0;
    expect_v4(cfg, i2s, [](const RuleMatch& m) -> const std::optional<xdpmf_cidr_v4>& { return m.dst_cidr; }, e_dst, w);

    const std::uint64_t corrupt_wc = w ^ 0x1ULL;     // flip one bit
    const bool wc_mismatch_detected = (cr.dst_low.wildcard != corrupt_wc);
    CHECK(wc_mismatch_detected, "negation: corrupted wildcard golden must mismatch");

    bool prefix_mismatch_detected = false;
    if (!e_dst.empty()) {
        const std::uint64_t corrupt_bit = e_dst[0].bit ^ 0x1ULL;
        prefix_mismatch_detected = (cr.dst_low.prefixes.at(0).bit != corrupt_bit);
    }
    CHECK(prefix_mismatch_detected, "negation: corrupted prefix-bit golden must mismatch");
}

} // namespace

int main()
{
    test_smoke_minimal();
    test_lowering_identity();
    test_negation_control();

    if (g_fails != 0) {
        std::fprintf(stderr, "compile_harness: %d assertion(s) FAILED\n", g_fails);
        return 1;
    }
    std::printf("compile_harness: all assertions passed\n");
    return 0;
}
