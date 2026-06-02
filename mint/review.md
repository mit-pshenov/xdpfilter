# Review — MVP-4.24 exporter scrape consistency (active_idx seqlock) (mint triangulation)

## Verdict
`pass` (round-1, 0 findings, 1 out-of-triangulation → inline-merge)

Base for all diffs: `3d0f3ad` (MVP-4.23 final).

## Triangulation matrix (brownfield, 5-point)

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | both target tests pass; public export exercised |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved | 0 | all PIs hold trivially |

## Point 1 — Spec ↔ Code (D-mvp-4.24-* honored)
- **Seqlock shape** matches §5.64 Interfaces: open `active_idx` once (`rule_counters_reader.cpp:268`), loop `0..kRuleCountersGenRetryMax` (`:295`), `active_pre`=lookup (`:297`) → `read_generation` reads BOTH buffers (`:299`) → `active_post`=lookup (`:304`) → commit on `pre==post` (`:307-309`), retry on change.
- **D-WINDOW** — `read_generation` (`:153-217`) reads `rule_counters_<active>` (`:160-193`) AND `slot_rule_id` half `base=active*XDPMF_ALLOWLIST_MAX` (`:205-214`) keyed by the SAME `active`; `active_post` re-read only AFTER both → window wraps the id↔counter pair, no torn cross-gen.
- **Bounded, named constexpr** `kRuleCountersGenRetryMax = 3` (`:53`), ≤4 reads/iface, NO unbounded loop → decoupled from B27 DoS.
- **D-TEAR-HONESTY** — after-N serves `candidate` (last consistently-read gen, never torn/zero) + emits `exporter.scrape.warn.rule_counters_generation_unstable` once/iface (`:320-338`); comments (`:283-290`,`:311-312`,`:321-324`) state retry = FRESHNESS not tear-prevention; X→Y→X not claimed fixed.
- **D-FD-REUSE** (`:268`/`:132-141`), **D-NOPIN-LEGACY** (`:270-281`), **PI-31** (only `bpf_obj_get`+`bpf_map_lookup_elem`; grep update/delete/pin/link/prog_load = ∅).
- **Catalog** — `logger.hpp:90` kEventNames `<...,39>`, new event `:130` BEFORE `rule_counters_open_failed`; `kEventCount` 38→39 (`:135`). Zero-warning rebuild. RAII fds, `[[nodiscard]]`, `constexpr`, enum-class Level, no magic number.

## Point 2 — Spec ↔ Tests (§6.82 parts 1/2/3)
- Part 1 (gen-sensitivity control, frozen-reader catch) `T_EXPORTER_SCRAPE_CONSISTENCY.sh:186-251`: apply A→fp=={11}, apply B→fp=={22}.
- Part 2 (concurrency consistency) `:253-316`: every 200-scrape fingerprint ∈ {RA}|{RB}, never cross-mix, never empty. Asserts spec OUTCOME (rule_id-set fingerprint), not impl internals → not circular.
- Part 3 (non-vacuity/observability guard = negation control) `:318-346`: FAILs "could not stage the race" unless BOTH gens seen AND active_idx ≥2 distinct values.
- Catalog test carries its own (c) negation control.

## Point 3 — Code ↔ Tests (reviewer re-ran)
`sudo -E ctest -R 'T_EXPORTER_SCRAPE_CONSISTENCY|T_LOG_EVENT_CATALOG_STABILITY' -V` → 2/2 pass (`/tmp/mint-review-tests-mvp424.log`). **Non-vacuity proven at runtime**: 42 successful scrapes, distinct fingerprints {22,11}, distinct active_idx {1,0}, cross-mix=0, empty=0. `read_rule_counters` exercised via the exporter binary. No UNEXERCISED-EXPORT.

## Point 4 — Out-of-Scope Drift
No new BPF map, no loader/datapath/schema/map-count/VERSION change; stats_reader.cpp byte-identical (Q2); no B26/B27/ARCH-H1/CQ-H1 touch. ∅.

## Point 5 — Behaviour preserved (brownfield)
`git diff 3d0f3ad` → ZERO footprint outside exporter+test:
- PI-7: loader.hpp+config.hpp ∅ • PI-DATAPATH-IDENTICAL: src/bpf ∅ (3658) • PI-KMANAGEDMAPS-39: mac_filter.h ∅, loader.cpp ∅ • stats_reader.cpp ∅ • rule_counters_reader.hpp ∅ • VERSION ∅ (0.15.0, HG-2).
- PI-CATALOG: kEventCount 39 == kEventNames.size() 39 == `wc -l fixture` 39, sorted; catalog test green.
- No REGRESSION: tester 101/103; the 2 fails `T_EXPORTER_EXITS_6_ALL_IFACES_EACCES` (#48) + `T_LOG_JSON_EXPORTER_EVENTS` (#63, renumbered from #62 by the new test's alphabetical insert) are pre-existing env-fails ("Killed" at the unprivileged exporter spawn; red since e50a62d). ∅ INVARIANT-VIOLATED / UNRELATED-EDIT / REGRESSION.

## Out-of-triangulation findings

### [OOT] design §6.82 baseline prose cited stale env-fail index "#48/#62"
**Location**: `design.md` §6.82 Baseline + PI-mvp-4.24-BASELINE row.
**Evidence**: after the alphabetically-inserted new test renumbered indices, `T_LOG_JSON_EXPORTER_EVENTS` is now #63 not #62. Cosmetic; the *set* of pre-existing fails is unchanged.
**Disposition**: `inline-merge` (applied — see Post-review sweep below).

## Post-review sweep — round 1
- OOT (stale env-fail index #62→#63) → `mint/design.md` §6.82 Baseline + PI-mvp-4.24-BASELINE row edited: env-fails now identified BY NAME (`T_EXPORTER_EXITS_6_ALL_IFACES_EACCES` + `T_LOG_JSON_EXPORTER_EVENTS`) with a note that the index renumbers post-insert. Doc-clarity only; zero code/test impact.

Candidate guard #32 (read-side selector-seqlock vs gen-map) well-grounded; the test's non-vacuity discipline is demonstrated, not asserted. Clean round-1 pass.
