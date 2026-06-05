# Review — MVP-4.34/B41 §5.74 RulesetDelta (mint triangulation, brownfield)

## Verdict
`pass` (round 1)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

No findings. Clean pass.

## Point 1 — Spec ↔ Code
- `struct RulesetDelta` = `std::array<uint32_t, XDPMF_RULE_COUNTERS_MAX> source;` — dumb aggregate, NO methods (`ruleset_delta.hpp:34-36`). Guard #36 ✔.
- `[[nodiscard]] RulesetDelta diff(span<const u32> old, span<const u32> new) noexcept` — exact per §5.74 Interfaces (`ruleset_delta.hpp:46-47`); defn `ruleset_delta.cpp:17-40`. Pure, libbpf-free, noexcept, no fd/bpf_map_*/throw ✔.
- D-Q1-A1 (`source[64]` precompute) ✔; D-Q2-SENTINEL (NONE = `XDPMF_SLOT_ID_EMPTY` 0xFFFFFFFF) ✔; D-HG1-PLACEMENT (new private TU) ✔.

## Point 5 (LOAD-BEARING) — Behaviour preserved
- **PI-mvp-4.34-WRITESET (hard gate, byte-identity)**: `git diff HEAD~1 -- src/lib/loader.cpp` consumer hunk (`loader.cpp:1500-1517`) shows ONLY inline-scan→`diff()` substitution. New loop: `fill(buf,0)` → `src=d.source[k]` → `if(src!=EMPTY){ lookup(&src); if(lk<0) re-zero; }` → `update(inactive,&k)`. Key `&src` carries the identical old_slot value the inline scan's first-match `&old_slot` carried; same `lk<0→re-zero` edge; every-slot update. Map I/O sequence byte-identical for every input. ✔ — corroborated by counter ctests green.
- **Guard #9 (verbatim move)**: `ruleset_delta.cpp:21-38` scan = deleted `loader.cpp:1505-1515` block; ONLY change = records matched `old_slot` into `source[k]` instead of inline lookup. O(n²) outer-k × inner-old_slot, unique-id `break` preserved (HG-3) ✔.
- **Guard #15 (branch-boundary PRESERVED)**: both call sites EXPLICIT, branch-divergent args — reattach `(old_rc_fd, inactive_rc_fd, old_slot_to_id, cr.slot_to_id)` (`loader.cpp:2133`), fresh `(rc_a_fd, rc_a_fd, empty_old, cr.slot_to_id)` (`loader.cpp:2231`). `diff()` lives INSIDE the consumer, NOT hoisted; both sites byte-identical ✔.
- **PI-7**: `git diff -- src/lib/loader.hpp` = ∅ ✔.
- **PI-DATAPATH**: `git diff -- src/bpf` = ∅; `T_INSN_BASELINE_GATE` PASS (xdp **3437**) ✔.
- **CompiledRuleset untouched**: `git diff -- src/lib/compiled_ruleset.{hpp,cpp}` = ∅ ✔.
- **No UNRELATED-EDIT**: `git diff --stat HEAD~1` = exactly the 7 FileList files ✔. **No REGRESSION**: counter ctests green.

## Point 2/3 — Tests
- `T_RULESET_DELTA_TRUTHTABLE` (`ruleset_delta_harness.cpp`): survived-in-place (`source[3]==3`), **moved/B30** (`source[4]==1` — counter follows id, NOT slot; line 140 — the assertion no test made before), new (`source[5]==EMPTY`), dropped (old slot 2 never a source), empty-new-slot, fresh-apply-degenerate, full-reorder. All §5.74 TestStrategy classes ✔.
- **NOT circular**: independent `oracle_source()` (lines 87-99) from the §5.74 contract + hand-computed literals; does NOT read diff()'s output as truth ✔.
- **Negation control** (line 235-251): a moved id's `source[k] != k` (the B30 "source-follows-slot" bug class would set `source[4]==4`) + smoke all-EMPTY→all-NONE ✔.
- **Moved-class genuinely asserts** (not a fixed-point tautology): `test_full_reorder` uses a cyclic-shift **derangement** (no fixed point) asserting `source[k] != k` (line 209) — the over-assertion the tester fixed ✔.
- **OPS-canary / purity link**: `ldd build/ruleset_delta_harness` = no libbpf; CMake target links NEITHER PkgConfig::LIBBPF NOR xdpmf_internal NOR *_skel (tests/CMakeLists.txt:1659-1676) — compiles `src/lib/ruleset_delta.cpp` directly ✔.
- **RD-5 OOT polish** (test-only): OOT-1 (`host_addr6` v6 golden, `compile_harness.cpp:355`) ✔, OOT-3 (test-derivation-only comment at v4 masking, `:232`) ✔; OOT-2 skipped (design-permitted).

## Point 4 — Out-of-scope drift
None. No O(n²)→O(n) rewrite (O(n²) held), no A2 richer shape, no compile-path/datapath touch, no call-site/signature change, no VERSION bump (0.16.0 held).

## Test execution (`/tmp/mint-review-tests-1780666967.log`)
```
ruleset_delta_harness: all assertions passed        (offline, rc=0)
compile_harness: all assertions passed              (offline, rc=0)
ldd ruleset_delta_harness → OK: no libbpf in link
#51  T_RULE_COUNTER_SURVIVES_APPLY ... Passed  3.90s
#55  T_RULE_COUNTER_SURVIVES_REORDER  Passed  4.02s
#70  T_RULE_COUNTERS_ATOMIC_SWAP .... Passed  3.96s
#105 T_INSN_BASELINE_GATE (xdp 3437)  Passed  0.44s
#108 T_RULESET_DELTA_TRUTHTABLE ..... Passed  0.00s
100% tests passed, 0 failed out of 5
```

## Out-of-triangulation findings
None.

Clean byte-identity code-motion; §5.35 counter-monotonicity hard gate held; first direct offline test of the id-reconciliation landed with a real negation control.

---

### Cross-cycle note — B40 deferred OOT items resolved here
The 3 OOT test-polish items deferred from B40's review (§5.73) were carried as RD-5 ride-along: OOT-1 (v6 `host_addr6` offline assertion) DONE, OOT-3 (v4-oracle masking comment) DONE, OOT-2 (direct `close_prefixes` unit) SKIPPED (file-static, would need an src/ change — design-permitted). No deferred items remain from the loader-datamodel cleanup arc.
