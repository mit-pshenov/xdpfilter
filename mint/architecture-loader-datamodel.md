# Architecture — loader data-model cleanup (pre-mirror/redirect tidy)

> mint-hld synthesis, committed at human gate. Reviewer: **pass** (round 1). Grounder discharge: **clean-with-gates**. Roster: parallel [structure, testability, forward-compat] + sequential [contrarian].
>
> **PO ruling at gate (Dmitry):** Option 1 (CompiledRuleset bundle) is the *entire* pre-TC mandate — it sits on the mirror/redirect path (the 16-arg signature TC would extend). Slice 2 (RulesetDelta) is orthogonal to TC (id/counter reconciliation, not action/target), so it is **test-hygiene, not a pre-TC obligation**: run the spike first; **hard gate** — verbatim code-motion or defer entirely. The surviving §5.35 risk question collapses to the hard gate (no reason to trade an operator invariant for non-critical-path test-debt).

# Synthesis (round 1)

## Convergence (where architects agree)

- **(structure, testability, forward-compat, contrarian): `CompiledRuleset` bundle earns its keep — as a dumb value-aggregate of the existing 12 locals, killing the 16-arg `populate_all_axes` signature.** All four land on the same shape: no fds, no `skel*`, value-comparable. This is a textbook *introduce-parameter-object*, B35 struct-pack precedent applies → low byte-identity risk. [needs-grep]

- **(structure, forward-compat, contrarian): the action axis must stay RAW — `rules` carried as `std::span<const Rule>`, action NOT lowered into any mask/variant/field.** Forward-compat owns it; structure agrees (action is the one axis with no `*Lowering`); contrarian hardens it to a cross-lens invariant. A future redirect touches the same 3 sites (enum + `populate_rules_inner_slot` + `populate_action_table`) regardless of this cleanup. [needs-grep]

- **(structure, testability, forward-compat, contrarian): `RuntimeImage` / full staged pipeline is DROPPED, unanimously.** No second reader (`--dry-run` is out of scope), freezes an action encoding prematurely, textbook guard-#36 thin-wrapper. Do not scaffold "for later." [genuine-PO-value: `--dry-run` explicitly out-of-scope per brief]

- **(structure, testability, contrarian): the cutover oracle is already built — reuse, invent nothing.** `T_INSN_BASELINE_GATE.sh` must stay **3437** (pure host-side refactor recompiles no BPF → decisive cheap gate) + `T_*_ORACLE_AGREEMENT` corpus for verdict-identity + `T_RULE_COUNTER_SURVIVES_REORDER.sh` unchanged. [needs-grep]

- **(testability, contrarian): the `compile()`/`materialize()` split's REAL payoff is offline-testability of the production lowering, not "naming a seam."** Today only `bitvec_harness`'s parallel reimpl is tested (`D-mvp-4.2-ISOLATION`); the production lowering is unassertable. The split is worth it only if it ships WITH the unit test. [needs-grep]

- **(testability, contrarian): `diff()` extraction is the single highest provable-correctness-per-effort gain** — the delta is the worst-tested concept (4 implicit cases, O(n²), provable only via privileged round-trip), and a pure function with a finite case-space yields an exhaustive truth-table. [needs-grep]

## Divergence (where architects substantively disagree)

- **(structure vs contrarian, on `CompiledRuleset` naming): structure argues mint `CompiledRuleset` (documenting `≡ Rule IR` in a comment is a "refinement," A6); contrarian argues reusing the arch-doc's already-committed "Rule IR" vocabulary (architecture-rule-model.md C.4, line 47: "the in-map table *is* the portable IR") is a STANDING OBLIGATION, not optional — minting a parallel name silently is the exact renaming churn the brief warns against.** Implication: this is a naming-policy fork for the human, not a structural one. The byte-identity and shape are identical either way; only the documented vocabulary differs. [needs-grep — verify C.4 names the *compile-output* form, not the in-map table specifically]

- **(structure vs contrarian, on `RulesetDelta` slice scope): structure recommends `RulesetDelta` as a high-value carving and floats the O(n²)→O(n) optimization as a "bonus" (separate slice); contrarian rules HARDER — `diff()` extraction must be byte-identical *code-motion only* (lift the nested loop verbatim, consumer keeps its full-64-slot write loop), the O(n) flip NEVER rides this slice, and if pure code-motion isn't achievable without restructuring the write loop, `diff()` DEFERS ENTIRELY.** Implication: the contrarian's stricter gate is the load-bearing one — §5.35 counter-monotonicity + the full-64-slot write-set + the `lk<0` re-zero edge (`loader.cpp:1829-1831`) are the real risk surface. The synthesis adopts the contrarian's gate. [needs-grep]

- **(brief vs structure/contrarian, factual): the brief claims `BitPrefix` is "already `#include`d from tests/bitvec"; structure and contrarian both verified it is production-owned local (`loader.cpp:1165`, guard #9 note at `:1173`), NOT included from tests.** Implication: the brief's implicit premise that "lowerings already live partly out-of-module" is FALSE. Externalizing the compile half is a *new* move, not a continuation — raises the (still-low) bar slightly for the header-extraction decision. [grounded — two independent architects verified on code]

## Composite directions (cross-lens combinations)

### Option 1 — Tidy Bundle (minimal, single-slice)
- **Composition:** structure.A2 (compile/materialize split) + testability.T2-core (`compile()` exposed via `xdpmf::internal`) + forward-compat.A1 (action raw `std::span<const Rule>`) + contrarian's "ship-with-test" gate.
- **First slice scope:** Introduce `CompiledRuleset` (12 locals, dumb value-type, `rules` raw) in a new private `src/lib/compiled_ruleset.hpp`; extract `compile(const Config&) → CompiledRuleset` (= `loader.cpp:2206-2293` incl. bound-checks); collapse `populate_all_axes` 16→3 args → `materialize(skel, slot, cr)`; ship `T_COMPILE_*` offline unit test. Delta untouched.
- **Risk profile:** LOW — pure host-side struct-pack (B35 precedent), no BPF recompile, insn-count 3437 is the decisive gate. [needs-grep]
- **User value cycle 1:** mirror/redirect extends a named 3-arg `materialize` + a value-typed bundle, not a 17th positional arg; first-ever offline assertion of the *production* lowering closes the `D-mvp-4.2-ISOLATION` coverage gap.
- **Costs:** ~1 TTFW cycle [needs-grep]; LOC roughly net-neutral-to-slightly-positive (new header + test offsets collapsed args) [needs-grep]; new dep = one bare-`main` C++ unit binary + 1 `add_executable`/`add_test` (no gtest) [needs-grep]; sacrifice = delta test-debt stays unpaid this cycle.
- **Preserves:** datapath byte-identity (3437 ×3 arms), PI-7 (`loader.hpp` zero-diff), action-axis non-foreclosure, guard #36 (dumb aggregate, no methods).
- **Open Qs:** mint `CompiledRuleset` vs reuse "Rule IR"; in-`loader.cpp` vs new header (testability needs the header for linkage).

### Option 2 — Bundle + Delta (two-slice, full-value)
- **Composition:** Option 1 + testability.T4/T5 (`diff()` exposed) + structure.A3 + contrarian's *code-motion-only* gate on slice 2.
- **First slice scope:** identical to Option 1 (bundle + compile + test). **Slice 2** (only if pure code-motion achievable): extract `RulesetDelta diff(old_slot_to_id, new_slot_to_id)` by lifting `loader.cpp:1816-1834` verbatim; `copy_rule_counters_forward` keeps its full-64-slot write loop as thin consumer; ship `T_RULESET_DELTA_TRUTHTABLE` (survived/moved/new/dropped incl. B30 moved-keeps-counter). O(n²)→O(n) flip explicitly deferred/optional.
- **Risk profile:** slice 1 LOW; slice 2 MED — touches §5.35 counter-monotonicity + the full-64-slot write-set; mitigated by the contrarian's verbatim-lift gate + the truth-table proof. [needs-grep]
- **User value cycle 1:** same as Option 1 (slice 1 ships first); slice 2 adds the first-ever direct test of the id-reconciliation logic.
- **Costs:** ~2 TTFW cycles [needs-grep]; LOC modest positive (second test + struct) [needs-grep]; deps same as Option 1; sacrifice = O(n) perf win deferred (irrelevant at 64-rule scale).
- **Preserves:** everything in Option 1 + behavioral identity of `copy_rule_counters_forward` (§5.35).
- **Open Qs:** is verbatim code-motion of `:1816-1834` achievable without touching the write loop? (the gate that decides whether slice 2 happens at all).

### Option 3 — Delta-First Isolate (contrarian's "do only the under-tested thing")
- **Composition:** testability.T4 (`diff()` only) + contrarian's worth-it-on-own-merits framing; bundle DEFERRED.
- **First slice scope:** extract `RulesetDelta diff()` + truth-table ONLY; leave the 12 locals + 16-arg signature as-is.
- **Risk profile:** MED — same §5.35 surface as Option 2 slice 2, but without the low-risk bundle win banked first. [needs-grep]
- **User value cycle 1:** closes the single worst test-gap with zero TC dependency (worth doing even if mirror/redirect never happens).
- **Costs:** ~1 TTFW cycle [needs-grep]; smallest LOC; sacrifice = the 16-arg signature (the sharpest *structural* smell, and the one mirror/redirect will have to read) stays unfixed before TC.
- **Preserves:** datapath byte-identity, §5.35, action non-foreclosure.
- **Open Qs:** does fixing test-debt first but leaving the maintenance-hazard signature for the TC workstream invert the brief's "tidy before mirror/redirect" intent?

## Recommendation (with caveat)

**Lean: Option 2 (Bundle + Delta, two-slice)** — slice 1 (bundle + `compile()` + test) is unanimously worth-it, low-risk, and directly serves the brief's "tidy before mirror/redirect" intent (the 16-arg signature is the present maintenance hazard the TC work will have to extend). Slice 2 (`diff()`) pays the highest test-debt in the round on its own merits, gated behind the contrarian's verbatim-code-motion discipline.

**Single biggest caveat:** the lenses *look* convergent on `RulesetDelta` but are agreeing on three different things — testability (test-debt = strong yes), structure (conceptual elegance = soft yes), contrarian (yes-to-naming, **no-to-optimization-this-slice**, defer-entirely-if-not-pure-code-motion). The load-bearing constraint is byte-identity of the full-64-slot write-set + §5.35 counter-monotonicity. If a quick spike shows `:1816-1834` cannot be lifted verbatim without restructuring the write loop, slice 2 collapses to Option 1 and `diff()` waits. **Do not let slice 1 block on slice 2's uncertainty — ship slice 1 regardless.** [needs-spike — the verbatim-liftability of `loader.cpp:1816-1844`]

## Open questions (need human input)

1. **Naming policy:** mint `CompiledRuleset` in code (documenting `≡ Rule IR`) or adopt the arch-doc's already-committed "Rule IR" vocabulary directly? Structure says refine-via-comment; contrarian says reuse-is-an-obligation. [genuine-PO-value: documentation-coherence with committed architecture vocabulary]

2. **Slice-2 go/no-go criterion:** accept the contrarian's hard gate (defer `diff()` entirely if not pure code-motion), or allow a controlled write-loop restructure if the truth-table + `T_RULE_COUNTER_SURVIVES_REORDER` both pass? [genuine-PO-value: risk tolerance on §5.35 monotonicity]

3. **Test scaffold:** bare-`main` C++ unit binary (like `bitvec_harness`) vs the shell+golden `dump-compiled` idiom (testability.T8) — does the band accept a new `add_executable` unit target at all? [needs-grep — confirm no in-tree assertion framework]

4. **Header placement:** does `compile()`/`diff()` live in a new `compiled_ruleset.hpp` linked as a separate TU (cleaner test linkage, avoids dragging libbpf into the unit binary) or in-place in `loader.cpp`? Testability flags this as a BLOCKING linkage dependency. [needs-grep]

## Hidden assumptions

- **A pure host-side C++ refactor recompiles NO BPF, so insn-count stays exactly 3437.** If any lowering helper is somehow `constexpr`-fed into a BPF-side path or the struct-pack changes map *write order*, the gate moves and the "decisive cheap oracle" premise collapses. [needs-grep — confirm `compile`/`materialize` callees touch no BPF-side code]

- **`compile()` callees (the `lower_*`/`aggregate_*` helpers) are pure and side-effect-free**, so moving the block `2206-2293` into a function is behavior-preserving. If any reads global/static state or has ordering coupling with the runtime half, the split is not free. [needs-grep]

- **`:1816-1834` (the diff core) is separable from `:1837-1844` (the write loop) along a clean boundary.** The contrarian's entire slice-2 gate hinges on this; if the loops are interleaved, `diff()` defers. [needs-spike]

- **The `xdpmf::internal` private-header pattern (`apply_internal.hpp:24`) supports a second consumer without breaking PI-7** (`loader.hpp` zero-diff). All three lenses lean on this as "already blessed"; if PI-7 is more fragile than assumed, the header-extraction cost rises. [needs-grep]

- **`CompiledRuleset` field-comparability is achievable** (lowerings are insertion-ordered vectors per `D-mvp-4.10-ORDER`); if any field is an `unordered_map` with no deterministic compare, the testability payoff is half-realized and the test scaffold grows. [needs-grep]

- **The 64-rule ceiling makes O(n²) perf irrelevant**, so deferring the O(n)→flip costs nothing real. If a future requirement lifts `XDPMF_ALLOWLIST_MAX`, the deferred optimization re-enters scope — but that is out-of-scope here (fixed architectural limit). [genuine-PO-value: 64-rule limit is a fixed PO constraint]

---

## Discharge ledger (Phase 5.5 grounder)

**Verdict:** clean-with-gates  
**Summary:** 0 sizing/sequencing claims refuted — the synthesis's small, additive plan is well-grounded against the code. But 1 required pre-slice spike survives (verbatim-liftability of copy_rule_counters_forward's diff-core from its 64-slot write loop — the gate that decides whether slice 2 exists), so the verdict is clean-with-gates, NOT clean. Notably 2 of 4 "human-input" Open Qs were reclassified OFF the PO plate (naming + scaffold fall out of code facts), a near-po-leak; only 1 genuine PO question (slice-2 risk tolerance on §5.35 monotonicity) survives.

### Required spike (gates slice 2 existence)
- **Must prove:** Lifting loader.cpp:1820-1835 (surviving-id classification) into a pure RulesetDelta diff(old_slot_to_id, new_slot_to_id) leaves the consumer's full-64-slot write-set (incl. zeros for empty/dropped AND the lk<0 → re-zero edge at :1829-1831) byte-identical in map state.
  - **Pass/Fail:** PASS: verbatim code-motion achievable AND T_RULESET_DELTA_TRUTHTABLE (survived/moved/new/dropped incl. B30 moved-keeps-counter) + T_RULE_COUNTER_SURVIVES_REORDER.sh both green with the write loop unchanged. FAIL: extraction forces restructuring the write loop → diff() defers entirely this round, ship slice 1 only.
  - **Gates:** Option 2 slice 2 (RulesetDelta diff() extraction + truth-table) — its very existence this round

### Surviving PO plate (1 — ruled hard-gate at this gate)
- **Q:** Slice-2 go/no-go: accept the hard gate (defer diff() entirely if not pure code-motion) OR allow a controlled write-loop restructure if the truth-table + T_RULE_COUNTER_SURVIVES_REORDER both pass? (May be mooted if the spike shows pure code-motion IS achievable.)
  - **External value:** Risk appetite on §5.35 Prometheus counter-monotonicity — an operator-facing correctness guarantee. Proving byte-identity of the verbatim-lift is engineering; choosing to permit a riskier restructure on a live operator invariant is a risk-tolerance judgment external to code.

### Reclassified OFF the PO plate (decidable — not human questions)
- ~~Naming: mint CompiledRuleset (document ≡ Rule IR) vs reuse the arch-doc's committed 'Rule IR' vocabulary~~ — Decidable from the arch-doc: C.4 'Rule IR' is the config.cpp-emitted NormalizedRule ABOVE the lowering boundary (architecture-rule-model.md:52,75); :47 'in-map table is the IR' is the materialized rules map. NEITHER names the compile-output bit-structures, so no naming collision and no documentation-coherence value is actually at stake. [grounded]
- ~~Test scaffold: bare-main C++ unit binary vs a new gtest dependency~~ — Pure code fact: zero test framework in-tree (grep gtest/catch2/doctest empty); bitvec_harness (tests/CMakeLists.txt:1092) is the existing bare-main precedent. No product/priority value. [needs-grep]
- ~~Header placement / unit-binary linkage (separate TU vs in-place, avoid dragging libbpf into the test)~~ — An engineering decision fully decidable from the xdpmf::internal precedent (apply_internal.hpp:24); separate-TU is the cleaner linkage. No external value — an architect/dev call, not the PO's. [needs-grep]
- ~~RuntimeImage / full staged pipeline DROP (tagged genuine-PO-value: --dry-run out of scope)~~ — DROP is already decided by code (no consumer exists) + brief scope (--dry-run explicitly out). All four lenses independently reject it; no external value to weigh. [grounded]
- ~~64-rule ceiling makes O(n²) perf irrelevant (tagged genuine-PO-value)~~ — XDPMF_ALLOWLIST_MAX=64 is a fixed architectural limit (already PO-settled, not a work item). O(64²) host-side at apply-time is negligible. Nothing external left to decide. [grounded]

### Slice-time rechecks (next /mint-briefer MUST re-run)
- [ ] Re-read tests/T_INSN_BASELINE_GATE.sh:71 and T_PROD_VERIFIER_LOAD.sh:125 — confirm baseline is still 3437 (it was 3658 pre-B35); if any BPF-side slice landed since, compare against the new value.  _(for: Hidden-assumption #1 / cutover oracle — pure host-side refactor leaves insn-count unchanged)_
- [ ] Re-confirm CompiledRuleset's intended fields match the live AxisLowering/AxisLowering6/*Lowering shapes at loader.cpp:1256+ (one unordered_map id_to_slot, rest deterministic) for field-comparability in the unit test.  _(for: Hidden-assumption #5 — CompiledRuleset field-comparability)_
- [ ] Re-scope the cycle count + LOC delta from the actual diff at slice-time; the ~1-cycle (Opt 1) / ~2-cycle (Opt 2) and net-neutral-LOC figures are planning hypotheses, not grounded facts.  _(for: Costs: TTFW cycles + LOC delta (Options 1/2))_
- [ ] Confirm the corpus oracle covers BOTH action_id values — ≥1 Pass and ≥1 Drop rule through the bundled rules span — so the ?: at loader.cpp:1713 is exercised post-carving.  _(for: Convergence #2 — action stays raw, non-foreclosure (fwd-compat named dependency))_
