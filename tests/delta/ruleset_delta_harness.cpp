/*
 * ruleset_delta_harness.cpp — §5.74 (MVP-4.34 / B41) offline truth-table for the
 * production id-reconciliation `xdpmf::diff(old_slot_to_id, new_slot_to_id)`.
 *
 * This is the FIRST direct offline assertion of the apply's only stateful
 * "two versions meet" seam (the survived/moved/new/dropped set-diff over
 * operator-id space, formerly an anonymous nested scan inlined inside
 * copy_rule_counters_forward at loader.cpp:1505-1515, tested only indirectly
 * via the counter-preservation datapath ctests).
 *
 * Model under test (§5.74 DataStructures / Interfaces) — for each NEW slot
 * k ∈ [0, XDPMF_RULE_COUNTERS_MAX):
 *   - source[k] == old_slot (∈[0,64)) when new_slot_to_id[k] is a valid id that
 *     also occupies some old_slot (a SURVIVOR; old_slot==k ⇒ survived-in-place,
 *     old_slot!=k ⇒ MOVED — the B30 moved-keeps-counter case: the counter source
 *     follows the id across its slot move, NOT the slot index).
 *   - source[k] == XDPMF_SLOT_ID_EMPTY (0xFFFFFFFF, the NONE sentinel) when
 *     new_slot_to_id[k] == EMPTY (unoccupied) OR the new id is absent from old
 *     (a NEW id). Both ⇒ zeros forwarded.
 *   - a DROPPED id (in old, absent from new) is never named by any source[k].
 *
 * Bare-main, NO gtest, NO libbpf (compile_harness precedent MINUS the libbpf
 * link). The clean libbpf-free link is itself the OPS-canary purity contract
 * (§5.74 TestStrategy): the CMake target compiles src/lib/ruleset_delta.cpp
 * DIRECTLY and links NEITHER PkgConfig::LIBBPF NOR xdpmf_internal NOR any
 * *_skel target. If diff() ever acquires a libbpf/fd/throw dependency this
 * binary fails to LINK — a signal the libbpf-linked datapath tests cannot give.
 *
 * Assertion mechanism: plain `if (got != want) { fprintf(stderr, ...); ++fails }`
 * accumulation; non-zero exit on any mismatch. A SMOKE test (all-EMPTY → all-NONE)
 * catches a totally broken diff() cheaply; a NEGATION CONTROL proves the
 * comparison machinery can actually fail (it would catch the exact B30
 * "source follows slot, not id" regression).
 */
#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>

#include "common/xdpfilter.h"   // XDPMF_RULE_COUNTERS_MAX, XDPMF_SLOT_ID_EMPTY
#include "ruleset_delta.hpp"    // xdpmf::RulesetDelta, xdpmf::diff()

using namespace xdpmf;

namespace {

constexpr std::uint32_t kMax   = XDPMF_RULE_COUNTERS_MAX;   // 64
constexpr std::uint32_t kEmpty = XDPMF_SLOT_ID_EMPTY;       // 0xFFFFFFFF

int g_fails = 0;

void check_u32(const std::string& what, std::uint32_t got, std::uint32_t want)
{
    if (got != want) {
        std::fprintf(stderr,
            "T_RULESET_DELTA_TRUTHTABLE: %s got=%#x want=%#x\n",
            what.c_str(), got, want);
        ++g_fails;
    }
}

void check_true(const std::string& what, bool cond)
{
    if (!cond) {
        std::fprintf(stderr, "T_RULESET_DELTA_TRUTHTABLE: %s (expected true)\n",
                     what.c_str());
        ++g_fails;
    }
}

using SlotMap = std::array<std::uint32_t, kMax>;

SlotMap all_empty()
{
    SlotMap s{};
    s.fill(kEmpty);
    return s;
}

// ─────────────────── INDEPENDENT oracle of the §5.74 model ───────────────────
//
// Derived directly from the §5.74 DataStructures contract, NOT from impl: for
// each new slot k, the source is the old slot holding the same (non-EMPTY) id,
// else NONE. (ids are unique across occupied slots in a ruleset half, so the
// first match is THE match.)
SlotMap oracle_source(const SlotMap& old_s, const SlotMap& new_s)
{
    SlotMap out = all_empty();
    for (std::uint32_t k = 0; k < kMax; ++k) {
        const std::uint32_t new_id = new_s[k];
        if (new_id == kEmpty) { continue; }            // unoccupied new slot → NONE
        for (std::uint32_t j = 0; j < kMax; ++j) {
            if (old_s[j] == new_id) { out[k] = j; break; }  // survivor → old slot
        }
        // no match → stays kEmpty (new id)
    }
    return out;
}

// Assert diff() == the independently-derived oracle, slot by slot.
void assert_matches_oracle(const std::string& corpus, const SlotMap& old_s,
                           const SlotMap& new_s)
{
    const RulesetDelta d = diff(old_s, new_s);
    const SlotMap want = oracle_source(old_s, new_s);
    for (std::uint32_t k = 0; k < kMax; ++k) {
        check_u32(corpus + " source[" + std::to_string(k) + "]", d.source[k], want[k]);
    }
}

// ────────────────────────── the truth-table tests ───────────────────────────

// ONE corpus covering every class + targeted hand-computed literal asserts that
// do NOT route through the oracle (the truly-independent ground truth).
//
//   old: slot1=id9 (will move), slot2=id99 (dropped), slot3=id7 (survives)
//   new: slot3=id7 (survived-in-place), slot4=id9 (moved from old slot1),
//        slot5=id42 (new), slot0 EMPTY in both, rest EMPTY.
void test_truthtable_all_classes()
{
    SlotMap old_s = all_empty();
    SlotMap new_s = all_empty();

    old_s[1] = 9;    // moves to new slot 4
    old_s[2] = 99;   // dropped (absent from new)
    old_s[3] = 7;    // survives in place

    new_s[3] = 7;    // survived-in-place
    new_s[4] = 9;    // moved (B30): id 9 was old slot 1
    new_s[5] = 42;   // new (absent from old)

    const RulesetDelta d = diff(old_s, new_s);

    // survived-in-place: id 7 at slot 3 in both → source[3] == 3.
    check_u32("survived-in-place id7", d.source[3], 3);

    // moved (B30 moved-keeps-counter — THE load-bearing case no test makes today):
    // id 9 old slot 1, new slot 4 → counter source FOLLOWS THE ID, == 1 (not 4).
    check_u32("moved id9 (counter follows id)", d.source[4], 1);

    // new: id 42 at new slot 5, nowhere in old → NONE.
    check_u32("new id42", d.source[5], kEmpty);

    // EMPTY new slot (slot 0, EMPTY in both) → NONE (must NOT match an EMPTY old
    // slot — guards the new_id==EMPTY skip).
    check_u32("empty new slot 0", d.source[0], kEmpty);

    // every other new slot is unoccupied → NONE.
    for (std::uint32_t k = 0; k < kMax; ++k) {
        if (k == 3 || k == 4 || k == 5) { continue; }
        check_u32("unoccupied new slot " + std::to_string(k), d.source[k], kEmpty);
    }

    // dropped: old slot 2 (id 99) is NEVER named as a copy source by any k.
    bool slot2_is_a_source = false;
    for (std::uint32_t k = 0; k < kMax; ++k) {
        if (d.source[k] == 2) { slot2_is_a_source = true; }
    }
    check_true("dropped old slot 2 is never a source", !slot2_is_a_source);

    // and the same corpus must agree with the independent oracle wholesale.
    assert_matches_oracle("all_classes", old_s, new_s);
}

// fresh-apply degenerate: old all-EMPTY (the empty_old call site) ⇒ every
// new id is NEW ⇒ ALL source[k] == NONE (nothing survives; matches
// D-mvp-4.21-FIRSTAPPLY — every slot zeroed).
void test_fresh_apply_degenerate()
{
    SlotMap old_s = all_empty();
    SlotMap new_s = all_empty();
    new_s[0] = 5;
    new_s[1] = 2;
    new_s[2] = 9;
    new_s[3] = 40;

    const RulesetDelta d = diff(old_s, new_s);
    for (std::uint32_t k = 0; k < kMax; ++k) {
        check_u32("fresh source[" + std::to_string(k) + "]", d.source[k], kEmpty);
    }
}

// full reorder (mirrors T_RULE_COUNTER_SURVIVES_REORDER): a permutation where
// EVERY id moves slot ⇒ each source[new_slot] equals that id's OLD slot.
//   old: slot j holds id (j+1)                 → ids {1..n}
//   new: slot k holds the id from old slot (k+1)%n  (cyclic-shift DERANGEMENT —
//        no fixed point for any n≥2, so every id genuinely moves).
//   ⇒ source[k] == (k+1)%n.
void test_full_reorder()
{
    SlotMap old_s = all_empty();
    SlotMap new_s = all_empty();
    const std::uint32_t n = 5;
    for (std::uint32_t j = 0; j < n; ++j) {
        old_s[j] = j + 1;                       // id (j+1) at old slot j
    }
    for (std::uint32_t k = 0; k < n; ++k) {
        const std::uint32_t src_slot = (k + 1) % n;
        new_s[k] = old_s[src_slot];             // new slot k = id from old slot (k+1)%n
    }

    const RulesetDelta d = diff(old_s, new_s);

    for (std::uint32_t k = 0; k < n; ++k) {
        const std::uint32_t old_slot = (k + 1) % n;
        check_u32("reorder source[" + std::to_string(k) + "]", d.source[k], old_slot);
        // derangement: every id genuinely moved (no fixed point for any k).
        check_true("reorder slot " + std::to_string(k) + " genuinely moved",
                   d.source[k] != k);
    }
    assert_matches_oracle("full_reorder", old_s, new_s);
}

// SMOKE: all-EMPTY → all-EMPTY ⇒ all source NONE. A totally broken diff() trips
// here cheaply.
void test_smoke_empty()
{
    const SlotMap old_s = all_empty();
    const SlotMap new_s = all_empty();
    const RulesetDelta d = diff(old_s, new_s);
    for (std::uint32_t k = 0; k < kMax; ++k) {
        check_u32("smoke source[" + std::to_string(k) + "]", d.source[k], kEmpty);
    }
}

// NEGATION CONTROL (MANDATORY): a deliberately-wrong expectation MUST be
// detected by the comparison machinery — proving the test can actually fail and
// would catch the exact B30 "source follows slot, not id" regression class.
//
// id 9 moves old slot 1 → new slot 4. A buggy "source follows slot" diff() would
// set source[4]==4. We assert the REAL diff() does NOT equal that wrong golden
// (mismatch detected) — if this CHECK ever flips, either the bug is back or the
// machinery is dead.
void test_negation_control()
{
    SlotMap old_s = all_empty();
    SlotMap new_s = all_empty();
    old_s[1] = 9;
    new_s[4] = 9;

    const RulesetDelta d = diff(old_s, new_s);

    const std::uint32_t wrong_source_follows_slot = 4;   // the B30 bug's output
    const bool mismatch_detected = (d.source[4] != wrong_source_follows_slot);
    check_true("negation: source-follows-slot wrong golden must mismatch",
               mismatch_detected);

    // sanity: and the correct source is the id's old slot.
    check_u32("negation: correct moved source", d.source[4], 1);
}

} // namespace

int main()
{
    test_smoke_empty();
    test_truthtable_all_classes();
    test_fresh_apply_degenerate();
    test_full_reorder();
    test_negation_control();

    if (g_fails != 0) {
        std::fprintf(stderr, "ruleset_delta_harness: %d assertion(s) FAILED\n", g_fails);
        return 1;
    }
    std::printf("ruleset_delta_harness: all assertions passed\n");
    return 0;
}
