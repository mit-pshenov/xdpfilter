# Task brief — MVP-4.34 / B41: RulesetDelta — name the id-reconciliation + offline truth-table (brownfield)

## Goal

Slice 2 ("Bundle + Delta", second slice) of `mint/architecture-loader-datamodel.md` (mint-hld
synthesis `f37b63d`). Give the loader's **id-reconciliation a name and a boundary**: extract the
anonymous nested-scan classification inside `copy_rule_counters_forward` (the
survived/moved/new/dropped set-diff over operator-id space — the apply's only stateful "two
versions meet" seam) into a **pure `RulesetDelta diff(old_slot_to_id, new_slot_to_id)`**, leaving
`copy_rule_counters_forward` as a thin consumer whose full-64-slot write-set stays **byte-identical**.
Ship the **first direct offline test of the id-reconciliation** — `T_RULESET_DELTA_TRUTHTABLE`
(bare-`main`, libbpf-free) asserting survived/moved/new/dropped incl. the B30 moved-keeps-counter
case.

**The slice-2 spike (the HLD's hard gate) has PASSED** (run 2026-06-05, throwaway lift then
reverted): verbatim code-motion IS achievable — the classification (`loader.cpp:1505–1515`) lifts
into a pure function reading only the two slot→id spans; the consumer's write-set (lookup at the
precomputed source + the `lk<0 → re-zero` edge + every-slot update) stays unchanged. Empirical
proof: throwaway built clean, counter-preservation ctests green in isolation (REORDER ×3,
SURVIVES_APPLY, ATOMIC_SWAP, all bump). **The §5.35 risk question is therefore MOOTED** — no
write-loop restructure is needed; this slice is byte-identity code-motion only.

## Context: prior work

- mint-hld synthesis + discharge ledger: `mint/architecture-loader-datamodel.md` (`f37b63d`).
  Slice 1 (CompiledRuleset bundle, B40/§5.73) SHIPPED `b874e3a`. This is slice 2, **spike-discharged**.
- Spike result (this session): verbatim-liftability PROVEN; the §5.35 PRESERVE counter-monotonicity
  surface holds under the lift. The O(n²)→O(n) optimization is explicitly DEFERRED (64-rule scale).
- Phase-2 brief-author grep verification: see evidence footer (def/call-sites/classification-block
  line-anchored; new header + new test confirmed absent; no name collision).
- PI continuity: **PI-7** (`loader.hpp` zero-diff) CONTINUES (new header is private; loader.hpp
  untouched). **PI-3.4b-2 / §5.35 PRESERVE-across-apply** (Prometheus counter-monotonicity) is the
  load-bearing invariant this slice must hold byte-identically. **PI-mvp-4.27-DATAPATH-IDENTICAL**
  is untouched — this slice changes NO BPF datapath and NO compile path (insn 3437 stays by
  construction; the change is purely the host-side counter copy-forward).
- 3 deferred OOT test-polish items from B40's review (review.md) ride along in the tester scope.

## Workflow rules (brownfield)

- **Architect**: read `copy_rule_counters_forward` (`loader.cpp:1488`, the doc-comment §5.35/B30
  semantics at `:1456–1487`, the classification scan `:1505–1515`, both call sites `:2135` reattach
  / `:2233` fresh), the spike result (this brief + handoff), and `architecture-loader-datamodel.md`.
  EDIT `mint/design.md` in place; append **§5.74**.
- **Impl**: FileList per brownfield DIFF (NEW delta header/TU, EDIT loader.cpp consumer + CMake).
- **Tester**: NEW `T_RULESET_DELTA_TRUTHTABLE` (bare-`main`, no libbpf, no gtest — precedent
  `compile_harness`, `tests/CMakeLists.txt:1627`) + the existing counter-preservation ctests
  (T_RULE_COUNTER_SURVIVES_REORDER/APPLY, T_RULE_COUNTERS_ATOMIC_SWAP) are the REUSED byte-identity
  gate. Plus the 3 ride-along OOT polish items in `compile_harness.cpp`.
- **Reviewer**: 5-point brownfield. Special attention: (a) **behaviour preserved** — the consumer's
  64-slot map write-set is byte-identical (diff the new `copy_rule_counters_forward` body against
  `git show HEAD~1`); (b) guard #15 boundary (copy-forward stays EXPLICIT at both call sites,
  branch-divergent args — NOT folded); (c) guard #9 (classification lifted verbatim, not altered);
  (d) §5.35 counter-monotonicity holds (counter ctests green).

## Human-gate decisions (defaults applied — architect overrides at Phase A with evidence)

### HG-mvp-4.34-1: `RulesetDelta` + `diff()` placement → **NEW libbpf-free TU `src/lib/ruleset_delta.{hpp,cpp}`**
A SEPARATE model from `CompiledRuleset` (counter-reconciliation across two applies, NOT compile
output) → its own header reads cleaner and matches the "name the models" thesis. Architect MAY
instead co-locate in `compiled_ruleset.{hpp,cpp}` if it prefers one libbpf-free TU — either way
`diff()` MUST be libbpf-free/no-throw so `T_RULESET_DELTA_TRUTHTABLE` links it without libbpf
(the compile_harness linkage pattern).

### HG-mvp-4.34-2: `copy_rule_counters_forward` stays the consumer; write-set byte-identical
`diff()` is called inside (or just before) `copy_rule_counters_forward`; the precomputed delta
drives the SAME 64-slot loop — per-slot zero, lookup-at-source (only when the delta names a source),
`lk<0 → re-zero`, every-slot `bpf_map_update_elem`. The two call sites `:2135`/`:2233` (PRESERVE,
branch-divergent args) stay EXPLICIT and UNCHANGED (guard #15 / D-mvp-4.8-BOUNDARY).

### HG-mvp-4.34-3: O(n²)→O(n) optimization → **DEFERRED (not this slice)**
The classification scan is lifted VERBATIM (the spike's byte-identity rests on identical results).
An O(n) hash-map rewrite is a separate optional follow-up; at 64-rule scale it buys nothing real
and would trade byte-identity-by-construction for byte-identity-by-argument. Keep the O(n²) scan.

### HG-mvp-4.34-4: VERSION → **no bump** (0.16.0 held; internal refactor, no operator-visible surface)

## Open mechanism questions (architect decides; document in §5.74)

### Q1: `RulesetDelta` shape
- **A1**: minimal — a per-new-slot `source[64]` precompute (old-slot to copy from, or a NONE
  sentinel). Directly byte-identity-preserving (the spike's proven form).
- **A2**: richer — explicit `{survived/moved, added, dropped}` sets/spans, with `source[]` derived.
- **Recommendation**: architect's call, bounded by TWO hard constraints: (i) the consumer's map
  write-set stays byte-identical; (ii) the shape lets `T_RULESET_DELTA_TRUTHTABLE` assert
  survived/moved/new/dropped + the B30 moved-keeps-counter case directly. A1 is the safest for (i);
  a richer (A2) form is fine if it drives the identical writes and is a dumb aggregate (guard #36).

### Q2: NONE-sentinel for "no source" (if A1)
- The spike reused `XDPMF_SLOT_ID_EMPTY` (0xFFFF_FFFF); valid old_slot ∈ [0,64) never collides.
- Architect confirms the sentinel choice + that EMPTY/new/dropped all map to NONE → zeros written.

## Scope (cycle 1 — concrete items; estimates are UPPER BOUNDS)

### Item RD-1 — NEW `src/lib/ruleset_delta.{hpp,cpp}` (or co-located per HG-1)
**Where**: `src/lib/ruleset_delta.hpp` + `.cpp` (verified absent).
`struct RulesetDelta` (dumb aggregate, no methods — guard #36) + pure
`RulesetDelta diff(std::span<const std::uint32_t> old_slot_to_id, std::span<const std::uint32_t> new_slot_to_id)`.
**Libbpf-free, no-throw.** The classification logic is lifted VERBATIM from `loader.cpp:1505–1515`
(the `old_slot_to_id[old_slot] == new_id` scan, unique-id break) — guard #9 (move, not alter).

### Item RD-2 — EDIT `src/lib/loader.cpp`
**Where**: `copy_rule_counters_forward` body (`:1488`).
Replace the inline nested classification with `const RulesetDelta d = diff(old_slot_to_id, new_slot_to_id);`
then the SAME 64-slot write loop consuming `d` (lookup at the named source, `lk<0 → re-zero`,
every-slot update — byte-identical map I/O sequence). `#include "ruleset_delta.hpp"`. The 2 call
sites `:2135`/`:2233` UNCHANGED (guard #15). NO other loader.cpp change.

### Item RD-3 — NEW offline truth-table test
**Where**: `tests/<dir>/ruleset_delta_harness.cpp` (architect/tester names the dir) + ctest
registration. Bare-`main`, NO gtest, NO libbpf (links the `diff()` TU only). `T_RULESET_DELTA_TRUTHTABLE`
asserts `diff()` over a corpus covering all four classes: **survived** (id in both, same slot),
**moved** (id in both, slot changed — B30 moved-keeps-counter: source follows the id), **new** (id
only in new → NONE), **dropped** (id only in old → never a source), plus EMPTY slots → NONE. Include
a smoke + a negation control (mandatory).

### Item RD-4 — CMake wiring
**Where**: `src/` lib target (add `ruleset_delta.cpp` to `xdpmf_internal`) + `tests/CMakeLists.txt`
(`add_executable` + `add_test`, mirroring the `compile_harness` block `:1627` — libbpf-free).

### Item RD-5 — ride-along: 3 deferred OOT test-polish (from B40 review.md)
**Where**: `tests/compile/compile_harness.cpp`.
- **OOT-1**: add an offline assertion on the derived v6 `host_addr6` sub-field (v4 path asserts
  `host_addr` at `:211`; v6 `ExpPrefix6` `:196` omits it).
- **OOT-2** (optional): a direct unit exercise of `close_prefixes`/`close_prefixes6` if cheap.
- **OOT-3**: a one-line comment near the v4-oracle masking (`host_order_v4 & host_mask4`, `:211`)
  noting it is test-derivation-only (production stores unmasked; equivalent under the host-bits-zero
  config invariant). These are LOW-priority; do NOT let them expand the slice.

## Out of scope (explicit)

- **O(n²)→O(n) optimization** of `diff()` — deferred (HG-3; 64-rule scale).
- **`CompiledRuleset` changes** — shipped in B40, untouched here.
- **Any BPF datapath / compile-path change** — none; insn 3437 stays by construction.
- **`copy_rule_counters_forward` call-site / args change** — the 2 sites stay byte-identical (guard #15).
- **`apply --dry-run` / preview**, **mirror/redirect / TC**, **the 64-rule ceiling** — all OOS.

## Definition of done

- §5.74 amendment in `mint/design.md`.
- PI-7 (`loader.hpp` zero-diff) CONTINUES; §5.35 PRESERVE counter-monotonicity holds byte-identically.
- Behaviour preserved: `copy_rule_counters_forward` map write-set byte-identical (diff vs HEAD~1);
  existing counter ctests (T_RULE_COUNTER_SURVIVES_REORDER/APPLY, T_RULE_COUNTERS_ATOMIC_SWAP, bump
  tests) green; datapath insn 3437 untouched.
- NEW `T_RULESET_DELTA_TRUTHTABLE` green (survived/moved/new/dropped + B30 moved-keeps-counter).
- 3 ride-along OOT polish items applied (OOT-1/OOT-3 mandatory, OOT-2 optional).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies

- Build: C++23 (existing), libbpf (existing — but the new `diff()` TU + the truth-table test do NOT
  link it). No new third-party deps.
- Runtime/kernel: none new (host-side refactor). Counter ctests need root (BPF) — local gate.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       []
  tester:     []
  reviewer:   []
```

---

## Pre-brief sanity check (per mint-hld-scope-discipline)

**MECHANICAL** — single-architect `/mint-dev`. The design-space was resolved by the mint-hld round
(`f37b63d`), and the slice's one gating uncertainty (verbatim-liftability) was **discharged by the
spike (PASS)** this session. Multi-axis? No. Expensive-to-undo? Low — byte-identity code-motion with
the counter-ctest gate. PRESERVE-vs-RESET sub-check: `copy_rule_counters_forward` is the EXISTING
PRESERVE helper (PI-3.4b-2 / §5.35); this slice does NOT promote any map — it refactors the helper's
internals as pure code-motion, semantic stays **PRESERVE-UNCHANGED**. Rolling-wave: discharge ledger
present; the required spike is DISCHARGED (no undischarged gate remains).

## Notes for architect Phase A code-grep discipline

Brief author ran these; architect re-verifies + extends:
- `grep -nE 'copy_rule_counters_forward' src/lib/loader.cpp` — def `:1488`, calls `:2135`/`:2233`, guard-#15 boundary `:1581/:2089/:2204`.
- the classification scan to lift: `loader.cpp:1505–1515` (`old_slot_to_id[old_slot] == new_id` + unique-id break).
- `test -f src/lib/ruleset_delta.hpp` — absent (NEW); `ls tests/ | grep -i ruleset_delta` — absent (NEW test).
- `grep -nE 'add_executable\(compile_harness' tests/CMakeLists.txt` — `:1627` (libbpf-free test precedent).
- **Architect MUST** diff the proposed new `copy_rule_counters_forward` body against `git show HEAD~1:src/lib/loader.cpp` to confirm the write-set is byte-identical, and confirm `diff()` touches no fd/BPF/throw (the spike's pure-function property).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #15 (PRESERVE branch-boundary / D-mvp-4.8-BOUNDARY)**: `copy_rule_counters_forward` stays
  EXPLICIT at both call sites with branch-divergent args; `diff()` lives INSIDE it, NOT hoisted to
  the call sites. Reviewer special-attention.
- **Guard #9 (move byte-identical, not alter)**: the classification scan is lifted VERBATIM into
  `diff()`; any logic change = [INVARIANT-VIOLATED]. The O(n²) scan is preserved (HG-3).
- **Guard #36 (dumb aggregate)**: `RulesetDelta` carries data only — no methods, no logic.

### Evidence footer — spike discharge (slice-2 gate)

The HLD's required pre-slice spike ("prove verbatim-lift of the classification leaves the 64-slot
write-set byte-identical") **PASSED** this session: analytical (classification is pure, separable
from the write-set) + empirical (throwaway lift built clean; REORDER ×3 / SURVIVES_APPLY /
ATOMIC_SWAP / bump ctests green in isolation; host-side only → insn 3437 untouched). The throwaway
was reverted; this slice ships the proper named form + the truth-table the spike did not write.
