# Task brief — MVP-4.10: B28 template the 3 near-dup HASH-populate + 3 axis-merge fns (brownfield)

## Goal

Pure code-quality refactor (behavior-preserving). Collapse two rule-of-three near-duplications in `src/lib/loader.cpp` into generic helpers:
1. The three near-identical HASH inner-slot populate fns — `populate_inner_slot` (`:1424`), `populate_proto_inner_slot` (`:1516`), `populate_vlan_inner_slot` (`:1559`) — into one `template<class Key> populate_hash_inner_slot`. (proto+vlan are byte-identical shape per the in-code comment at `:1555`; the mac/allowlist one differs only by key type.)
2. The three axis-merge lowering fns — `lower_proto_axis` (`:1283`), `lower_vlan_axis` (`:1353`), `lower_mac_axis` (`:1392`) — into one `aggregate_axis<class Key, class Eq>` (mac differs by `xdpmf_mac` key + `memcmp` equality vs `==`, so the template takes a comparator).

~145 LOC deletable. Anchor: `docs/BACKLOG.md` B28 — the explicit follow-on to **B20** (apply_request table-driven, shipped MVP-4.8 `0265bcb`). No `architecture-v2.md` row (debt-paydown). `design.md` gets a housekeeping §-amendment.

## Context: prior work
- Prior brief: archived as `mint/task-brief-mvp-4.9.md` (MVP-4.9 B18/B19, shipped `9b3e6fc`).
- B20 (the structural prerequisite this follows) is **already shipped** (MVP-4.8): `populate_all_axes` (`loader.cpp:1858`) + `inactive_axis_fd` (`:1837`) exist and are called from both apply_request branches (`:2346` reattach, `:2473` fresh). B28 templates the *inner* populate/lower fns that `populate_all_axes` and `apply_request` call.
- **Phase A code-grep verification (brief author ran):** confirmed all 6 target fns exist at the cited anchors as SEPARATE near-dups; confirmed `populate_hash_inner_slot` + `aggregate_axis` do NOT yet exist; confirmed `0` test bodies reference any of the 6 internal symbols (rename-safe, no fixture/test-body ripple); confirmed VERSION `0.15.0` (no bump). See Phase 2 output.
- **PI continuity: ALL existing PIs CONTINUE byte-equivalent.** Behavior-preserving refactor — same populated map contents, same lowering output. No PI retired/extended/added.

## Workflow rules (brownfield)
- **Architect**: read `design.md` §5.37 (escape_util consolidation — the **guard #9 rule-of-three EXPLICIT OVERRIDE** precedent, D-3.4f-1) + the 6 target fns + their callsites (`populate_all_axes` `:1858`, `apply_request` lowering calls `:2120/2125/2129`). EDIT `design.md` in place; append a housekeeping §-amendment documenting the two template unifications + citing guard #9's rule-of-three override as the justification for extraction-over-duplication. Confirm the load-bearing precondition: the three populate fns are genuinely same-shape (bulk-clear-then-write, NO prefix-closure — that's the dst/src LPM path, OUT of scope) and the three lowering fns differ ONLY by key type/equality.
- **Impl**: introduce `template<class Key> populate_hash_inner_slot` (replaces the 3 populate fns) + `aggregate_axis<class Key, class Eq>` (replaces the 3 lower fns); update the callsites. NO behavior change, NO VERSION bump, NO src change beyond the unification + callsite updates.
- **Tester**: **NEW ctests target = 0.** Regression net = the 6 existing axis tests (`T_AND{,4,5,6}_ORACLE_AGREEMENT`, `T_PROTO_AND_COMPOSE`, `T_VLAN_AND_COMPOSE`) — a wrong template instantiation flips a proto/vlan/mac verdict → oracle disagreement. Run full suite with `-j4` and confirm green (B19 `build_cpu` lock holds). Tester MAY add a targeted canary ONLY if it judges the oracle net doesn't exercise the mac-vs-proto comparator divergence — justify against the corpus.
- **Reviewer**: 5-point brownfield. Load-bearing checks: (1) ONLY the 3+3 fns unified; populated-map contents + lowering output byte-identical; (2) mac's `memcmp`/`xdpmf_mac` divergence correctly handled via the `Eq` comparator (not silently coerced to `==`); (3) the dst/src LPM populate path (prefix-closure) is UNTOUCHED (different shape — not part of the rule-of-three); (4) no VERSION bump, oracle green; (5) guard #9 rule-of-three override is cited in the §-amendment (extraction is justified, not a guard violation).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.10-1: extract-via-template vs keep-duplicated → **extract**
Guard #9 (helper-location: prefer duplication over extraction) is OVERRIDDEN by the rule-of-three, per the established §5.37 / D-3.4f-1 precedent (escape_util). Three near-identical instances is the documented threshold. Architect overrides only if the template materially hurts readability or verifier-friendliness of the generated code.

### HG-mvp-4.10-2: both trios in ONE slice, or split → **one slice**
Both are the same rule-of-three near-dup class, behavior-preserving, ~145 LOC combined, no interlock risk. Bundling is within the pain threshold (2 mechanical pieces). Architect splits only if the template ergonomics of the two differ enough to warrant separate §-amendments.

## Open mechanism questions (architect decides; document in §-amendment)

### Q1: template shape for the lowering trio
- **A1**: `template<class Key, class Eq> aggregate_axis(...)` taking an equality comparator (handles mac `memcmp` vs proto/vlan `==`).
- **A2**: non-template table-driven (function-pointer/struct) à la `kManagedMaps`.
- **Recommendation**: **A1** — compile-time monomorphization, no indirect-call cost, matches backlog proposal; the comparator parameter cleanly absorbs the mac divergence. (Lowest-cost option satisfying all PIs.)

## Scope (cycle MVP-4.10 — concrete items)

### Item B28-1 — unify the HASH inner-slot populate trio
**Where**: `src/lib/loader.cpp` `populate_inner_slot` (`:1424`) / `populate_proto_inner_slot` (`:1516`) / `populate_vlan_inner_slot` (`:1559`) → one `template<class Key> populate_hash_inner_slot`. Update callsites in `populate_all_axes` (`:1869/1884/1894`).

### Item B28-2 — unify the axis-merge lowering trio
**Where**: `src/lib/loader.cpp` `lower_proto_axis` (`:1283`) / `lower_vlan_axis` (`:1353`) / `lower_mac_axis` (`:1392`) → one `aggregate_axis<class Key, class Eq>`. Update callsites in `apply_request` (`:2120/2125/2129`).

## Out of scope (explicit)
- B30 (id/slot decouple), B31 (EtherType axis), the IPv6 slice — separate slices.
- The dst/src **LPM** populate path (prefix-closure / `close_prefixes`) — different shape, NOT part of the rule-of-three. Do not touch.
- Any behavioral change to populated contents, lowering output, or the atomic-swap mechanism.
- VERSION bump.

## Definition of done
- §-amendment in `design.md` documenting both unifications + guard #9 rule-of-three override citation.
- All existing PIs continue byte-equivalent (behavior-preserving).
- ctest baseline green; **0 new ctests**; full `-j4` run no flake.
- No VERSION bump.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: existing CMake (C++20 templates already used in-tree).
- Runtime/kernel: none new (behavior-preserving; same BPF object).

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

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])
Mechanical, single-architect. NOT multi-axis: one blessed refactor pattern (template the rule-of-three), zero design-space forks, behavior-preserving, cheap-to-undo. `/mint-hld` NOT needed. Single-architect via `/mint-dev` handles it.

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author ran these; architect re-verifies + extends:
- `grep -nE 'populate_(inner|proto|vlan)_inner_slot' src/lib/loader.cpp` — confirm 3 separate, same-shape.
- `grep -nE 'lower_(proto|vlan|mac)_axis' src/lib/loader.cpp` — confirm 3 separate; inspect mac's `memcmp`/key-type divergence.
- `grep -rn 'populate_hash_inner_slot\|aggregate_axis' src/` — confirm ABSENT (introduce).
- `grep -rln '<any of the 6 fn names>' tests/` — confirm 0 (no test-body/fixture ripple).
- Inspect the dst/src LPM populate path to confirm it is NOT same-shape (prefix-closure) → correctly OUT of scope.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #9** (helper-location duplication-over-extraction) — DIRECTLY applies; this slice is the rule-of-three OVERRIDE. Architect MUST cite the §5.37 / D-3.4f-1 precedent in the §-amendment so the extraction reads as sanctioned, not as a guard violation.
- **Guard #5** (Phase A code-grep discipline) — always applies; architect re-runs the greps above independently.
- **Guard #10** (catalog arithmetic) — N/A (no new constexpr table/array).
- **Guard #12** (RESOURCE_LOCK for shared host state) — N/A (0 new ctests).

> Operative-semantic note: the "~145 LOC deletable" and line-number anchors above are SHOULD-level orientation for the reviewer's grep checks, not literal-match contracts. Impl deviations that preserve behavior (e.g. a helper landing at a different line, a slightly different template signature) are `inline-merge`, not `[UNRELATED-EDIT]`.
