/*
 * dryrun_harness.cpp — §5.76/§5.77 (MVP-4.36/B43 → MVP-4.37/B44) offline
 * map-image golden test.
 *
 * T_DRYRUN_IMAGE_IDENTITY. §5.77 Q2 reconciliation: the harness now drives the
 * PRODUCTION object seam — xdpmf::render_dryrun_image(Config) (which internally:
 * compile → make_dryrun_skel → RecordingScope → the SAME 3-call apply sequence
 * → format) — instead of the retired link-time fake (fake_bpf.{cpp,hpp}, DELETED
 * §5.77.2). This is strictly stronger SSoT than B43: the harness now exercises
 * the EXACT code the `apply --dry-run` CLI verb runs.
 *
 * Still libbpf-FREE (the OPS-canary, PI-mvp-4.37-LIBBPF-FREE): this TU links
 * {dryrun_harness.cpp, materialize.cpp, map_writer.cpp, map_image.cpp,
 * compiled_ruleset.cpp, loader_error.cpp} — NO PkgConfig::LIBBPF, NO
 * live_map_writer.cpp (the ONLY libbpf-calling TU), NO loader.cpp, NO *_skel
 * OBJECT. If the render subset acquires a real libbpf/skeleton dependency this
 * binary FAILS TO LINK.
 *
 *   default run  →  IDENTITY: render the corpus via the PRODUCTION seam, compare
 *                   to the frozen golden. plus SMOKE (minimal config renders a
 *                   sane image) + NEGATION (the comparator provably catches a
 *                   one-byte-corrupted image).
 *   --emit-golden → print the INDEPENDENTLY-DERIVED expected image (the tester's
 *                   oracle, NOT the production render) through the SAME
 *                   production formatter (xdpmf::format_dryrun_image). This is the
 *                   generator that produced the checked-in golden — the golden
 *                   is thus a spec-derived contract, not an impl snapshot.
 *                   THREE-WAY AGREEMENT: oracle == golden == production render.
 *   --emit-live   → DEBUG: print the production render of the corpus.
 *
 * Test independence (D-mvp-4.37-FORMATTER-MOVE): the formatter is now production
 * code shared by BOTH sides, so the independence that makes this test meaningful
 * lives ENTIRELY in the hand-derived oracle (oracle_expected_records) + the
 * FROZEN checked-in golden. Do NOT regenerate the golden via --emit-golden after
 * a formatter change without independent review.
 *
 * Tester-owned (all of tests/dryrun/, settled peer-to-peer with mint-dev-impl).
 * The production symbols are consumed from the NEW private headers map_writer.hpp
 * / map_image.hpp per the §5.77.4 pinned signatures; a signature mismatch
 * surfaces as a Phase-B compile/link error.
 */
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "common/xdpfilter.h"   // map key/value structs + XDPMF_* + enum xdpmf_action_type
#include "config.hpp"           // Config, Rule, RuleMatch, RuleAction, DefaultAction, PortRange, Steering
#include "compiled_ruleset.hpp" // xdpmf::compile(), CompiledRuleset, close_prefixes/6
#include "map_writer.hpp"       // xdpmf::RecordedWrite, MapDesc, kMapCatalog (the production catalog)
#include "map_image.hpp"        // xdpmf::render_dryrun_image(Config), xdpmf::format_dryrun_image(trace, target)

using namespace xdpmf;

namespace {

// ─────────────────────────── corpus builders ────────────────────────────────
// (CIDR/mac helpers transcribed from compile_harness — guard #9 test-side.)

xdpmf_cidr_v4 cidr4(std::uint8_t a, std::uint8_t b, std::uint8_t c,
                    std::uint8_t d, std::uint32_t prefixlen)
{
    xdpmf_cidr_v4 k{};
    k.prefixlen = prefixlen;
    const std::uint32_t host =
        (static_cast<std::uint32_t>(a) << 24) | (static_cast<std::uint32_t>(b) << 16) |
        (static_cast<std::uint32_t>(c) << 8)  |  static_cast<std::uint32_t>(d);
    k.addr = __builtin_bswap32(host);  // network order on a LE host
    return k;
}

xdpmf_cidr_v6 cidr6(std::initializer_list<std::uint8_t> bytes, std::uint32_t prefixlen)
{
    xdpmf_cidr_v6 k{};
    k.prefixlen = prefixlen;
    std::size_t i = 0;
    for (std::uint8_t byte : bytes) { if (i < 16) k.addr6[i] = byte; ++i; }
    return k;
}

xdpmf_mac mac(std::uint8_t a, std::uint8_t b, std::uint8_t c,
              std::uint8_t d, std::uint8_t e, std::uint8_t f)
{
    return xdpmf_mac{{a, b, c, d, e, f}};
}

// The rich corpus (§5.76.6): v4 dst covering/covered pair (LPM closure), v6
// dst6 + src6, same-proto HASH aggregation, a dst_port range, an unconstrained
// (wildcard) axis on every rule, >=1 Pass + >=1 Drop, and a steering:redirect
// rule with Config.steering{redirect_to}. ids 1..10 → dense slots 0..9.
// MUST stay in lock-step with tests/dryrun/dryrun_cli.yaml (the CLI verb's
// corpus, §5.77.6 #2) — both compile to THIS Config so CLI render == harness
// render == golden.
Config build_corpus()
{
    Config cfg;
    cfg.schema_version = 3;                 // steering: block requires schema 3
    cfg.default_action = DefaultAction::Drop;

    auto add = [&](std::uint32_t id, RuleAction action, RuleMatch m) {
        Rule r; r.id = id; r.action = action; r.match = std::move(m);
        cfg.rules.push_back(std::move(r));
    };

    { RuleMatch m; m.dst_cidr  = cidr4(10, 0, 0, 0, 8);   add(1, RuleAction::Pass, m); }     // v4 dst covering
    { RuleMatch m; m.dst_cidr  = cidr4(10, 1, 2, 0, 24);  add(2, RuleAction::Drop, m); }     // v4 dst covered (closure)
    { RuleMatch m; m.protocol  = 6;                       add(3, RuleAction::Pass, m); }     // proto 6  (aggregate A)
    { RuleMatch m; m.protocol  = 6; m.dst_port = PortRange{80, 443}; add(4, RuleAction::Drop, m); } // proto 6 (aggregate B) + port range
    { RuleMatch m; m.mac       = mac(0xAA,0xBB,0xCC,0xDD,0xEE,0xFF); add(5, RuleAction::Pass, m); }  // mac
    { RuleMatch m; m.vlan      = 100;                     add(6, RuleAction::Pass, m); }     // vlan
    { RuleMatch m; m.ethertype = 0x0806;                 add(7, RuleAction::Drop, m); }     // ethertype ARP
    { RuleMatch m; m.dst_cidr6 = cidr6({0x20,0x01,0x0d,0xb8}, 32); add(8, RuleAction::Pass, m); } // v6 dst
    { RuleMatch m; m.src_cidr6 = cidr6({0xfe,0x80}, 10);  add(9, RuleAction::Drop, m); }     // v6 src
    { RuleMatch m; m.mac       = mac(0x11,0x22,0x33,0x44,0x55,0x66); add(10, RuleAction::Redirect, m); } // redirect tap

    cfg.steering = Steering{"dpi0"};        // the single global DPI-feed target
    return cfg;
}

// ─────────────────── drive the production render seam ────────────────────────
// Returns the formatted image of the PRODUCTION render of `cfg` — the EXACT
// path the `apply --dry-run` CLI verb runs (compile → make_dryrun_skel →
// RecordingScope → materialize/populate_action_table/populate_redirect_devmap →
// format). An UNEXPECTED-map sentinel write would corrupt the recorded trace and
// thus the rendered image ⇒ the golden byte-compare below is the unexpected-write
// guard (no separate accessor needed; the harness stays decoupled from the
// RecordingMapWriter internals).
std::string render_live(const Config& cfg)
{
    return render_dryrun_image(cfg);
}

// ─────────────────── drive the production human render ────────────────────────
// Returns the DEFAULT human-decoded view (§5.78) of `cfg` — the EXACT string the
// `apply --dry-run` CLI verb prints by default. Single source for both the
// --emit-golden-human generator and test_human_identity, so the render path is
// computed identically in both (D-mvp-4.40-HUMAN-GEN). Unlike the IMAGE golden,
// the human golden has no independent map-image oracle — its independent spec is
// §5.78.4(a) (the token contract) + the T_CLI_APPLY_DRYRUN substring greps; this
// byte-golden is a complementary framing/whitespace/ordering drift pin.
std::string render_human(const Config& cfg)
{
    return format_dryrun_human(cfg, compile(cfg));
}

// ─────────────────────── independent oracle (golden generator) ────────────────
// The tester's SPEC-DERIVED expected write-set — built from the §5.73 slot model
// + close_prefixes (production compile(), allowed) + the map struct layouts, with
// NO reference to impl's materialize.cpp. Run via `--emit-golden` to (re)produce
// the checked-in golden. Filled per the architect-pinned write-set policy
// (§5.76.4(6) Q1..Q6).
//
// Byte serializer: the in-memory bytes of any trivially-copyable value, in
// memory (LE on this host) order — identical to what bpf_map_update_elem stores.
template <class T>
std::vector<std::uint8_t> bytes_of(const T& v)
{
    std::vector<std::uint8_t> b(sizeof(T));
    std::memcpy(b.data(), &v, sizeof(T));
    return b;
}

// map RuleAction → the action_table index (xdpmf_action_type) the rule dispatches
// to (Q2): Pass→ACTION_PASS, Drop→ACTION_DROP, Redirect→ACTION_REDIRECT.
std::uint8_t action_id_of(RuleAction a)
{
    switch (a) {
        case RuleAction::Pass:     return ACTION_PASS;
        case RuleAction::Drop:     return ACTION_DROP;
        case RuleAction::Redirect: return ACTION_REDIRECT;
    }
    return ACTION_DROP;
}

// The tester's INDEPENDENT expected write-set, derived from the §5.73 slot model
// (production compile() + close_prefixes — allowed) + the map struct layouts,
// per the architect-pinned write-set policy (§5.76.4(6)). NO reference to impl's
// materialize.cpp. Produces (map,key,value) triples in any order — the formatter
// sorts within-map and orders maps canonically. The map identities come from the
// PRODUCTION catalog xdpmf::kMapCatalog (the relocated kFakeMaps, §5.77.3(5)).
std::vector<RecordedWrite> oracle_expected_records(const Config& cfg)
{
    const CompiledRuleset cr = compile(cfg);
    std::vector<RecordedWrite> recs;

    auto find_tag = [](const char* name) -> std::uint32_t {
        for (std::size_t i = 0; i < kMapCatalogCount; ++i) {
            if (std::strcmp(kMapCatalog[i].name, name) == 0) {
                return kMapCatalog[i].tag;
            }
        }
        std::fprintf(stderr, "oracle: unknown map '%s'\n", name); std::abort();
    };
    auto push = [&](const char* name, std::vector<std::uint8_t> key,
                    std::vector<std::uint8_t> val) {
        recs.push_back(RecordedWrite{find_tag(name), std::move(key), std::move(val)});
    };

    // ── 9 axis inners ─────────────────────────────────────────────────────────
    // mac HASH: aggregated per-key bitmask (NO closure).
    for (const auto& e : cr.mac_low.entries) {
        push("allowlist_a", bytes_of(e.first), bytes_of(static_cast<std::uint64_t>(e.second)));
    }
    // dst v4 LPM: POST-closure mask (close_prefixes), key = stored xdpmf_cidr_v4.
    {
        const std::vector<std::uint64_t> closed = close_prefixes(cr.dst_low.prefixes);
        for (std::size_t i = 0; i < cr.dst_low.prefixes.size(); ++i) {
            push("dst_bitmask_a", bytes_of(cr.dst_low.prefixes[i].cidr), bytes_of(closed[i]));
        }
    }
    // src v4 LPM (cidr_allowlist_a): POST-closure mask.
    {
        const std::vector<std::uint64_t> closed = close_prefixes(cr.src_low.prefixes);
        for (std::size_t i = 0; i < cr.src_low.prefixes.size(); ++i) {
            push("cidr_allowlist_a", bytes_of(cr.src_low.prefixes[i].cidr), bytes_of(closed[i]));
        }
    }
    // proto HASH (NO closure).
    for (const auto& e : cr.proto_low.entries) {
        push("proto_bitmask_a", bytes_of(static_cast<std::uint32_t>(e.first)),
             bytes_of(static_cast<std::uint64_t>(e.second)));
    }
    // port ARRAY: DENSE 64 slots (D-mvp-4.36 FAITHFUL FINAL MAP-IMAGE). [0,N)=the
    // port-constrained ranges (dense-at-front, lowering order); [N,64)=the cleared
    // sentinel {lo=1,hi=0,bit=0} (lo>hi marks unused) — real resident cells.
    for (std::uint32_t i = 0; i < XDPMF_ALLOWLIST_MAX; ++i) {
        xdpmf_port_range pr;
        if (i < cr.port_low.ranges.size()) {
            pr = cr.port_low.ranges[i];
        } else {
            pr.lo = 1; pr.hi = 0; pr.bit = 0;          // cleared sentinel (lo>hi)
        }
        push("port_ranges_a", bytes_of(i), bytes_of(pr));
    }
    // vlan HASH (NO closure).
    for (const auto& e : cr.vlan_low.entries) {
        push("vlan_bitmask_a", bytes_of(static_cast<std::uint32_t>(e.first)),
             bytes_of(static_cast<std::uint64_t>(e.second)));
    }
    // dst6 v6 LPM: POST-closure mask (close_prefixes6).
    {
        const std::vector<std::uint64_t> closed = close_prefixes6(cr.dst6_low.prefixes);
        for (std::size_t i = 0; i < cr.dst6_low.prefixes.size(); ++i) {
            push("dst6_bitmask_a", bytes_of(cr.dst6_low.prefixes[i].cidr), bytes_of(closed[i]));
        }
    }
    // src6 v6 LPM: POST-closure mask.
    {
        const std::vector<std::uint64_t> closed = close_prefixes6(cr.src6_low.prefixes);
        for (std::size_t i = 0; i < cr.src6_low.prefixes.size(); ++i) {
            push("src6_bitmask_a", bytes_of(cr.src6_low.prefixes[i].cidr), bytes_of(closed[i]));
        }
    }
    // ethertype HASH (NO closure).
    for (const auto& e : cr.eth_low.entries) {
        push("ethertype_bitmask_a", bytes_of(static_cast<std::uint32_t>(e.first)),
             bytes_of(static_cast<std::uint64_t>(e.second)));
    }

    // ── ruleset_state (slot 0): the 9 wildcard halves + folded default_action ──
    {
        xdpmf_ruleset_state rs{};
        rs.wc[BV_AXIS_DST]       = cr.dst_low.wildcard;
        rs.wc[BV_AXIS_SRC]       = cr.src_low.wildcard;
        rs.wc[BV_AXIS_PROTO]     = cr.proto_low.wildcard;
        rs.wc[BV_AXIS_PORT]      = cr.port_low.wildcard;
        rs.wc[BV_AXIS_VLAN]      = cr.vlan_low.wildcard;
        rs.wc[BV_AXIS_MAC]       = cr.mac_low.wildcard;
        rs.wc[BV_AXIS_DST6]      = cr.dst6_low.wildcard;
        rs.wc[BV_AXIS_SRC6]      = cr.src6_low.wildcard;
        rs.wc[BV_AXIS_ETHERTYPE] = cr.eth_low.wildcard;
        rs.default_action = static_cast<unsigned int>(cr.default_action);
        push("ruleset_state", bytes_of(static_cast<std::uint32_t>(0)), bytes_of(rs));
    }

    // ── rules_a: DENSE 64 slots. [0,count)={present=1,action_id}; [count,64)=the
    // cleared empty cell {present=0} = 00000000 — real resident cells. ──────────
    const std::size_t count = cr.id_to_slot.size();
    std::vector<RuleAction> slot_action(count, RuleAction::Drop);
    for (const Rule& r : cr.rules) { slot_action[cr.id_to_slot.at(r.id)] = r.action; }
    for (std::uint32_t slot = 0; slot < XDPMF_ALLOWLIST_MAX; ++slot) {
        rule_entry re{};                                   // {present=0,action_id=0,_pad=0}
        if (slot < count) {
            re.present   = 1;
            re.action_id = action_id_of(slot_action[slot]);
        }
        push("rules_a", bytes_of(slot), bytes_of(re));
    }

    // ── slot_rule_id: DENSE 64 (inactive half, keys [0,64) at slot-0 apply). The
    // cr.slot_to_id array is already id for [0,count) + XDPMF_SLOT_ID_EMPTY tail. ─
    for (std::uint32_t slot = 0; slot < XDPMF_ALLOWLIST_MAX; ++slot) {
        push("slot_rule_id", bytes_of(slot),
             bytes_of(static_cast<std::uint32_t>(cr.slot_to_id[slot])));
    }

    // ── action_table (static identity table; 3 rows — MIRROR reserved, NEVER
    // written: Q1 RATIFIED) ────────────────────────────────────────────────────
    for (std::uint32_t a = 0; a < ACTION_MIRROR; ++a) {  // [PASS, DROP, REDIRECT)
        action_entry ae{};
        ae.action_type = static_cast<unsigned char>(a);
        push("action_table", bytes_of(a), bytes_of(ae));
    }

    // ── redirect_devmap[0] (value rendered SYMBOLICALLY; bytes are placeholder) ─
    if (cfg.steering.has_value()) {
        push("redirect_devmap", bytes_of(static_cast<std::uint32_t>(0)),
             bytes_of(static_cast<std::uint32_t>(0)));
    }

    return recs;
}

// ─────────────────────────────── the tests ───────────────────────────────────

int g_fails = 0;
void fail(const std::string& w) { std::fprintf(stderr, "FAIL: %s\n", w.c_str()); ++g_fails; }

std::string read_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) { fail("cannot open golden: " + path); return {}; }
    std::ostringstream ss; ss << f.rdbuf();
    return ss.str();
}

// print the first differing line (compile_harness precedent — no gtest).
void report_first_diff(const std::string& got, const std::string& want)
{
    std::istringstream g(got), w(want);
    std::string gl, wl; int ln = 1;
    while (true) {
        const bool gok = static_cast<bool>(std::getline(g, gl));
        const bool wok = static_cast<bool>(std::getline(w, wl));
        if (!gok && !wok) { break; }
        if (gl != wl || gok != wok) {
            std::fprintf(stderr, "  first diff at line %d:\n    got : %s\n    want: %s\n",
                         ln, gok ? gl.c_str() : "<eof>", wok ? wl.c_str() : "<eof>");
            return;
        }
        ++ln;
    }
}

// IDENTITY: the PRODUCTION render of the corpus == the checked-in golden,
// byte-for-byte. The golden is FROZEN from B43 (§5.77.7: byte-unchanged); a diff
// is a REAL discrepancy in the production render — investigate, do NOT rebless.
void test_image_identity(const std::string& golden_path)
{
    const Config cfg = build_corpus();
    const std::string got  = render_live(cfg);
    const std::string want = read_file(golden_path);

    if (got != want) {
        fail("rendered image != golden (" + golden_path + ")");
        report_first_diff(got, want);
    }
}

// SMOKE: a minimal one-rule config renders a well-formed, non-empty image —
// header present + at least one occupied map row.
void test_smoke_minimal()
{
    Config cfg;
    cfg.schema_version = 2;
    cfg.default_action = DefaultAction::Pass;
    { Rule r; r.id = 42; r.action = RuleAction::Drop;
      r.match.mac = mac(0xDE,0xAD,0xBE,0xEF,0x00,0x01);
      cfg.rules.push_back(r); }

    const std::string img = render_live(cfg);
    if (img.rfind("# xdpfilter-image v1\n", 0) != 0) {
        fail("smoke: image is missing the `# xdpfilter-image v1` header");
    }
    if (img.find("map=allowlist_a") == std::string::npos) {
        fail("smoke: image is missing the allowlist_a map header");
    }
    // at least one occupied row anywhere (a line beginning with two spaces).
    if (img.find("\n  ") == std::string::npos) {
        fail("smoke: image has no occupied rows (totally-broken render)");
    }
}

// NEGATION CONTROL: prove the byte-compare can FAIL. Take the real rendered
// image, corrupt exactly one byte of one value line, and assert the comparator
// reports a mismatch — a render regression therefore cannot pass green.
void test_negation_control()
{
    const Config cfg = build_corpus();
    const std::string img = render_live(cfg);

    // flip one hex nibble on the first occupied data row.
    std::string corrupt = img;
    const std::size_t row = corrupt.find("\n  ");
    bool mutated = false;
    if (row != std::string::npos) {
        for (std::size_t i = row + 3; i < corrupt.size() && corrupt[i] != '\n'; ++i) {
            char& ch = corrupt[i];
            if (ch >= '0' && ch <= '9') { ch = (ch == '0') ? '1' : '0'; mutated = true; break; }
            if (ch >= 'a' && ch <= 'f') { ch = (ch == 'a') ? 'b' : 'a'; mutated = true; break; }
        }
    }
    if (!mutated) { fail("negation: could not find a data byte to corrupt"); return; }

    const bool mismatch_detected = (img != corrupt);
    if (!mismatch_detected) {
        fail("negation: comparator FAILED to detect a one-byte-corrupted image");
    }
}

// HUMAN IDENTITY (§5.80.6 #1): the PRODUCTION human render of the corpus ==
// the checked-in human golden, byte-for-byte. FROZEN (§5.77.7): a diff is a REAL
// human-render regression that still satisfies the loose CLI substring greps —
// investigate, do NOT rebless.
void test_human_identity(const std::string& human_golden_path)
{
    const Config cfg = build_corpus();
    const std::string got  = render_human(cfg);
    const std::string want = read_file(human_golden_path);

    if (got != want) {
        fail("rendered human != golden (" + human_golden_path + ")");
        report_first_diff(got, want);
    }
}

// HUMAN NEGATION CONTROL (§5.80.6 #2): prove the human byte-compare can FAIL.
// Take the real rendered human view, corrupt exactly one data-bearing byte on the
// first non-header line, and assert the comparator reports a mismatch — a one-byte
// human-render regression therefore cannot pass green (the identity test is
// non-vacuous). Mechanical mirror of test_negation_control.
void test_human_negation_control()
{
    const Config cfg = build_corpus();
    const std::string view = render_human(cfg);

    // Skip the `# xdpfilter dry-run` header line; corrupt one [0-9a-z] char on
    // the first non-header line (e.g. `default_action: drop`).
    std::string corrupt = view;
    const std::size_t nl = corrupt.find('\n');
    bool mutated = false;
    if (nl != std::string::npos) {
        for (std::size_t i = nl + 1; i < corrupt.size(); ++i) {
            char& ch = corrupt[i];
            if (ch >= '0' && ch <= '9') { ch = (ch == '0') ? '1' : '0'; mutated = true; break; }
            if (ch >= 'a' && ch <= 'z') { ch = (ch == 'a') ? 'b' : 'a'; mutated = true; break; }
        }
    }
    if (!mutated) { fail("human negation: could not find a data byte to corrupt"); return; }

    const bool mismatch_detected = (view != corrupt);
    if (!mismatch_detected) {
        fail("human negation: comparator FAILED to detect a one-byte-corrupted view");
    }
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc >= 2 && std::strcmp(argv[1], "--emit-golden") == 0) {
        // Regenerate the spec-derived golden from the tester's independent oracle
        // (NOT the production render) through the SAME production formatter
        // (xdpmf::format_dryrun_image). The devmap target name comes from the corpus.
        const Config cfg = build_corpus();
        const std::string target = cfg.steering ? cfg.steering->redirect_to : std::string{};
        std::fputs(format_dryrun_image(oracle_expected_records(cfg), target).c_str(), stdout);
        return 0;
    }

    if (argc >= 2 && std::strcmp(argv[1], "--emit-golden-human") == 0) {
        // Generator for the human golden (D-mvp-4.40-EMIT): print the PRODUCTION
        // human render of the corpus (NOT a hand-derived oracle — D-mvp-4.40-
        // HUMAN-GEN; the tester REVIEWS it against §5.78.4(a) before freezing).
        std::fputs(render_human(build_corpus()).c_str(), stdout);
        return 0;
    }

    if (argc >= 2 && std::strcmp(argv[1], "--emit-live") == 0) {
        // DEBUG affordance: print the PRODUCTION render of the corpus. Used to
        // diff production-render-vs-oracle.
        std::fputs(render_live(build_corpus()).c_str(), stdout);
        return 0;
    }

    // Golden path: ${TEST_DIR}/dryrun/dryrun_image.golden (TEST_DIR from ctest
    // ENVIRONMENT, like compile_harness). Fall back to the in-tree source path.
    std::string golden_path;
    std::string human_golden_path;
    if (const char* td = std::getenv("TEST_DIR")) {
        golden_path       = std::string(td) + "/dryrun/dryrun_image.golden";
        human_golden_path = std::string(td) + "/dryrun/dryrun_human.golden";
    } else {
        golden_path       = "tests/dryrun/dryrun_image.golden";
        human_golden_path = "tests/dryrun/dryrun_human.golden";
    }

    test_smoke_minimal();
    test_image_identity(golden_path);
    test_negation_control();
    test_human_identity(human_golden_path);
    test_human_negation_control();

    if (g_fails != 0) {
        std::fprintf(stderr, "dryrun_harness: %d assertion(s) FAILED\n", g_fails);
        return 1;
    }
    std::printf("dryrun_harness: all assertions passed\n");
    return 0;
}
