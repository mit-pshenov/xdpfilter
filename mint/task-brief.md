# Task brief — MVP-4.33 / B40: CompiledRuleset bundle — name the compile output + offline test (brownfield)

## Goal

Slice 1 ("Tidy Bundle") of `mint/architecture-loader-datamodel.md` (mint-hld synthesis,
committed `f37b63d`; reviewer pass, grounder `clean-with-gates`). Give the loader's
**compile output a name and a boundary**: bundle the 12 anonymous compile locals in
`apply_request` into a dumb value-type `CompiledRuleset`, extract a pure
`CompiledRuleset compile(const Config&)`, and collapse the 16-argument `populate_all_axes`
into a 3-argument `materialize(skel, slot, const CompiledRuleset&)`. Ship the **first-ever
offline unit test of the production lowering** (`Config → CompiledRuleset` bit-identity),
closing the `D-mvp-4.2-ISOLATION` coverage gap (today only `bitvec_harness`'s parallel
reimplementation is tested, never the production path).

This is the **entire pre-mirror/redirect tidy mandate**: the 16-arg signature is the present
maintenance hazard the TC workstream would otherwise extend to 17. It is a **pure host-side
refactor — zero datapath change**. `RulesetDelta`/`diff()` is the spike-gated **slice 2** and
is OUT of this brief.

## Context: prior work

- mint-hld synthesis + discharge ledger: `mint/architecture-loader-datamodel.md` (`f37b63d`).
- PO ruling at the gate: slice 1 is the whole pre-TC mandate; slice 2 (delta) is
  TC-orthogonal test-hygiene, spike-gated, hard gate (defer-if-not-pure-code-motion).
- Architecture vocabulary: `mint/architecture-rule-model.md` (Wave B). Grounder discharged
  the naming question: arch-doc "Rule IR" names a DIFFERENT form (the config.cpp-emitted
  NormalizedRule above the lowering boundary, and the in-map table), NOT the compile-output
  bit-structures → **no collision; mint `CompiledRuleset`**.
- Brief-author Phase 2 grep verification (this brief): see evidence footer. 3 of 4
  discharge-ledger slice-time rechecks DISCHARGED at brief-time (below); the 4th (cycle/LOC)
  is an impl-time measurement.
- PI continuity: **PI-7** (`loader.hpp` zero-diff) CONTINUES — the new header is private
  (`src/lib/`, like `apply_internal.hpp`), `loader.hpp` is untouched (verified: it names no
  `populate_*`/`materialize`/`Compiled` symbol). **PI-mvp-4.27-DATAPATH-IDENTICAL** (insn
  baseline 3437 ×3 arms) CONTINUES and is the decisive cheap oracle.

## Workflow rules (brownfield)

- **Architect**: read `apply_request` (`loader.cpp:2189+`), the lowering block
  (`:1165–1474`), both `populate_all_axes` call sites (`:2472` reattach / `:2589` fresh),
  and `architecture-loader-datamodel.md`. EDIT `mint/design.md` in place; append **§5.73**.
- **Impl**: FileList per brownfield mode (NEW headers + EDIT loader.cpp + NEW test + CMake).
- **Tester**: NEW offline unit test (bare-`main`, no gtest — precedent `bitvec_harness`,
  `tests/CMakeLists.txt:1092`); the datapath byte-identity gate (`T_INSN_BASELINE_GATE.sh`,
  `T_*_ORACLE_AGREEMENT`) is REUSED unchanged, not re-authored.
- **Reviewer**: 5-point brownfield framework. Special attention: (a) datapath byte-identity
  (insn 3437 ×3 + oracle-agreement); (b) guard #15 boundary intact (counter copy-forward
  NOT folded into `materialize`); (c) guard #36 (CompiledRuleset is a dumb aggregate).

## Human-gate decisions (defaults applied — architect overrides at Phase A with evidence)

### HG-mvp-4.33-1: `materialize()` scope → **wraps `populate_all_axes` ONLY**
`copy_rule_counters_forward` (PRESERVE, branch-divergent args — guard #15 / D-mvp-4.8-BOUNDARY)
and `populate_action_table` (shared static table) **STAY EXPLICIT at each call site**, NOT
folded into `materialize`. Verified separation: counter copy-forward is called at `:2519`
(reattach) and `:2619` (fresh self-copy), distinct from the `populate_all_axes` calls.
`materialize(skel, slot, cr)` is exactly the branch-INVARIANT 12-local consumer.

### HG-mvp-4.33-2: file placement → **NEW `src/lib/compiled_ruleset.{hpp,cpp}`; `compile()` libbpf-free**
`compile()` (pure, no `skel`/fd/libbpf) lives in the new TU so the unit test links it WITHOUT
dragging libbpf into the test binary (testability lens's clean-linkage point). `materialize()`
needs `xdpfilter_bpf*` → its definition MAY stay in `loader.cpp` (architect's call); only its
signature changes. `struct CompiledRuleset` is header-only in `compiled_ruleset.hpp`.

### HG-mvp-4.33-3: naming → **mint `CompiledRuleset`** (grounder-discharged; no "Rule IR" collision)

### HG-mvp-4.33-4: VERSION → **no bump** (0.16.0 held across B37/B38/B39; internal refactor, no operator-visible surface)

### HG-mvp-4.33-5: `CompiledRuleset` value-equality for the test → **compare the deterministic lowering fields**
`id_to_slot` is a `std::unordered_map` (non-deterministic iteration); the 11 other fields are
insertion-ordered vectors/arrays/scalars (deterministic per D-mvp-4.10-ORDER). The offline
bit-identity assertion compares the **lowering outputs** (entries/wildcard/prefixes — the
datapath-bearing bits); `id_to_slot` is an intermediate compared by key-set if at all.
Architect designs the exact assertion shape.

## Open mechanism questions (architect decides; document in §5.73)

### Q1: `CompiledRuleset.rules` member type
- **A1**: `std::span<const Rule>` (non-owning — points into the caller's `Config.rules`).
- **A2**: own a copy / hold `const Config&`.
- **Recommendation**: **A1 `std::span<const Rule>`** per the action-axis-stays-RAW
  non-foreclosure invariant (forward-compat lens). NB lifetime: the span must outlive the
  `CompiledRuleset` — in `apply_request`, `compile()`'s result is consumed within the same
  scope as `req.config`, so the span is valid; architect confirms no escape.

### Q2: does `compile()` keep the bound-checks (`:2260–2293`, count > XDPMF_ALLOWLIST_MAX)?
- **A1**: yes — bound-checks are part of "is this Config compilable", belong in `compile()`.
- **A2**: leave them in `apply_request` after `compile()`.
- **Recommendation**: **A1** — they throw `LoaderError::LoadFailed` on the lowering outputs;
  keeping them in `compile()` makes the offline test able to assert the throw-on-overflow
  contract too. Architect confirms the throw-site error strings are unchanged (byte-identity
  of operator-visible stderr).

## Scope (cycle 1 — concrete items; estimates are UPPER BOUNDS)

### Item CR-1 — NEW `src/lib/compiled_ruleset.hpp`
**Where**: `src/lib/compiled_ruleset.hpp` (verified absent).
`struct CompiledRuleset` — a **dumb value-aggregate** (no methods, guard #36) of the 12
compile locals: `id_to_slot`, `slot_to_id`, `mac_low`, `dst_low`, `src_low`, `dst6_low`,
`src6_low`, `proto_low`, `port_low`, `vlan_low`, `eth_low`, `default_action`, plus `rules`
(`std::span<const Rule>` per Q1). Declares `CompiledRuleset compile(const Config&)`.
The per-axis `*Lowering` types (`AxisLowering` `:1256`, `AxisLowering6` `:1347`,
`AxisAggregate<>` `:1387`, `PortLowering` `:1448`) are REUSED — this slice does NOT redefine
them. (Architect decides whether they move to the header or stay in loader.cpp with a fwd
include; moving risks needless churn — default: leave in loader.cpp, the header includes what
it needs.)

### Item CR-2 — NEW `src/lib/compiled_ruleset.cpp`
**Where**: `src/lib/compiled_ruleset.cpp`.
`CompiledRuleset compile(const Config&)` = verbatim lift of the compile block
`loader.cpp:2206–2293` (the 11 `lower_*`/`aggregate_axis` calls + `compute_id_to_slot`/
`compute_slot_to_id` + bound-checks per Q2). **Pure, no libbpf.** The lowering helper
functions it calls must be reachable (architect: keep them in loader.cpp and declare, or
co-locate — whichever preserves byte-identity with least churn).

### Item CR-3 — EDIT `src/lib/loader.cpp`
**Where**: `apply_request` body + `populate_all_axes` definition `:1903` + both call sites
`:2472` / `:2589`.
- `populate_all_axes(16 args)` → `materialize(xdpfilter_bpf* skel, std::uint32_t slot, const CompiledRuleset& cr)`; body reads `cr.mac_low` etc. (mechanical positional→member rename).
- `apply_request`: replace the 12-local block with `const CompiledRuleset cr = compile(req.config);`
  then `materialize(skel.get(), inactive|0u, cr)` at each branch.
- `copy_rule_counters_forward` + `populate_action_table` call sites **UNCHANGED** (guard #15).

### Item CR-4 — NEW offline unit test
**Where**: `tests/<dir>/compile_harness.cpp` (architect/tester names the dir) + ctest
registration. Bare-`main`, no gtest (precedent `bitvec_harness`). Builds a `Config` corpus
including **≥1 Pass and ≥1 Drop rule** (exercises the `action_id` ternary `loader.cpp:1713` —
recheck #4) across representative axes, runs `compile()`, asserts the lowering-bit outputs
match a golden expectation. Links `compiled_ruleset.cpp` + `config` (NOT libbpf).

### Item CR-5 — CMake wiring
**Where**: `src/` lib target (add `compiled_ruleset.cpp` to the lib sources) +
`tests/CMakeLists.txt` (`add_executable` + `add_test` for the compile harness, mirroring the
`bitvec_harness` block `:1092`). Guard #11 N/A (no VERSION bump).

## Out of scope (explicit)

- **`RulesetDelta` / `diff()` extraction** — spike-gated **slice 2**. The required spike
  (verbatim-liftability of `loader.cpp:1820–1835` leaving the 64-slot write-set byte-identical)
  must PASS first; hard gate (defer entirely if not pure code-motion).
- **`copy_rule_counters_forward`** — untouched this slice (guard #15 boundary).
- **Any BPF-side / map-shape change** — none; insn-count must stay 3437.
- **O(n²)→O(n) optimization** of anything — deferred (64-rule scale makes it irrelevant).
- **`apply --dry-run` / preview**, **mirror/redirect / TC**, **the 64-rule ceiling** — all OOS.

## Definition of done

- §5.73 amendment in `mint/design.md`.
- PI-7 (`loader.hpp` zero-diff) CONTINUES; PI-mvp-4.27-DATAPATH-IDENTICAL CONTINUES.
- Datapath byte-identity: `T_INSN_BASELINE_GATE.sh` stays **3437** ×3 arms;
  `T_*_ORACLE_AGREEMENT` corpus holds (verdict-identity).
- NEW `T_COMPILE_*` offline unit ctest green (Config→CompiledRuleset bit-identity, both action_ids).
- Full ctest baseline unchanged + the one new test (count: current baseline + 1).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies

- Build: C++23 (existing), libbpf (existing — but the new `compile()` TU + the unit test do
  NOT link it). No new third-party deps (no gtest).
- Runtime/kernel: none new (host-side refactor).

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

**MECHANICAL** — single-architect `/mint-dev` is correct. The design-space was resolved by
the mint-hld round (`f37b63d`); this slice carries a **discharged** decision (reviewer pass +
grounder clean-with-gates). Multi-axis? No — the carving, naming, placement, and test scaffold
are all decided/discharged. Expensive-to-undo? Low — pure struct-pack with the insn-3437 gate.
No `/mint-hld` re-run needed. PRESERVE-vs-RESET sub-check: **N/A** — no stateful map is promoted
to atomic-swap; `copy_rule_counters_forward` (PRESERVE) is explicitly untouched.

**Rolling-wave re-discharge of the inherited hld plan**: discharge ledger present in
`architecture-loader-datamodel.md`. The required spike gates **slice 2 only** — slice 1 has no
undischarged spike. Slice-time rechecks discharged at brief-time: see footer.

## Notes for architect Phase A code-grep discipline

Brief author ran these; architect re-verifies + extends:
- `grep -nE 'populate_all_axes' src/lib/loader.cpp` — def `:1903`, calls `:2472`/`:2589` (16 args each, confirmed).
- `grep -nE 'copy_rule_counters_forward' src/lib/loader.cpp` — calls `:2519`/`:2619`, SEPARATE from populate (guard #15).
- `test -f src/lib/compiled_ruleset.hpp` — absent (NEW).
- `grep -nE 'struct (AxisLowering|AxisLowering6|AxisAggregate|PortLowering)' src/lib/loader.cpp` — the lowering types to REUSE (`:1256/:1347/:1387/:1448`).
- `grep -nE 'XDPMF_PROD_INSN_BASELINE' tests/T_INSN_BASELINE_GATE.sh` — baseline `3437` (`:71`).
- `grep -niE 'gtest|catch2|doctest' tests/CMakeLists.txt` — empty (bare-main is the only path).
- **Architect MUST re-run** the discharge-ledger rechecks #2 (CompiledRuleset fields ↔ live
  `*Lowering` shapes — one `unordered_map`, rest deterministic) and #4 (corpus covers both
  action_ids) at design time, and confirm the `compile()` callees are pure/side-effect-free
  (hidden-assumption #2) and touch no BPF-side code (hidden-assumption #1).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #15 (PRESERVE branch-boundary / D-mvp-4.8-BOUNDARY)**: `copy_rule_counters_forward`
  has branch-divergent args (reattach reads old slot_rule_id; fresh passes empty) and stays
  EXPLICIT at the call site — do NOT fold it into `materialize`. Reviewer special-attention.
- **Guard #36 (macros-over-helpers for BPF byte-identity)**: `CompiledRuleset` is a dumb data
  aggregate — no methods, no logic; the lowering stays where it is. Earn-its-keep test:
  it kills a 16-arg signature + names a real seam (passes), it is not a thin wrapper.
- **Guard #9 (helper-location: duplication-over-extraction)**: if `compile()` needs a lowering
  helper currently file-local in loader.cpp, prefer declaring/sharing over re-implementing;
  do NOT duplicate logic (byte-identity risk).
- **Guard #37 (module-split precedent, B34b 3-header split)**: the private-header pattern is
  blessed; `compiled_ruleset.hpp` follows it. PI-7 (`loader.hpp` zero-diff) must hold.

### Evidence footer — discharge-ledger slice-time rechecks (brief-time status)

1. **insn baseline still 3437?** — DISCHARGED ✓ (`T_INSN_BASELINE_GATE.sh:71`
   `${XDPMF_PROD_INSN_BASELINE:-3437}`; rebaselined 3658→3437 in B35).
2. **CompiledRuleset fields ↔ live `*Lowering` shapes?** — VERIFIED ✓ with caveat: 5
   deterministic structs + 1 `unordered_map` (`id_to_slot`) → drives HG-mvp-4.33-5 test design.
3. **cycle/LOC from real diff** — DEFERRED to impl-time (planning hypothesis: ~1 TTFW cycle,
   LOC net-neutral-to-slightly-positive; new header+test offsets the collapsed args).
4. **corpus covers both action_ids?** — site VERIFIED ✓ (`loader.cpp:1713` Pass/Drop ternary);
   tester MUST include ≥1 Pass + ≥1 Drop in the compile corpus.
