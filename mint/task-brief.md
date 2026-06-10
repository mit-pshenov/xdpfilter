# Task brief — MVP-4.41 / PERF-M1: bound exporter scrape loops by the live rule count (brownfield)

## Goal
Cut the exporter's per-scrape BPF syscall count from a fixed `2 × XDPMF_RULE_COUNTERS_MAX (=64)` lookups per iface down to ~`count` (the live rule count), by exploiting the existing **dense-prefix slot invariant**: occupied slots are `[0, count)` with an `XDPMF_SLOT_ID_EMPTY` tail (established by B30 §5.61 `compute_slot_to_id`, D-mvp-4.21-Q3 id-sorted rank). The win is ~10× syscall reduction at small-config × many-iface scale (review finding **PERF-M1**, 2026-06-07 sanitary-day review, deferred-with-rationale → now charged as its own slice). No forcing-function pressure — this is a bounded perf-hygiene slice, NOT an envelope-critical change.

**Scrape output MUST stay byte-identical**: `prom_format.cpp` already skips `XDPMF_SLOT_ID_EMPTY` slots (`prom_format.cpp:128-130`), so reading fewer dead slots is observationally invisible. This output-invariance is the slice's headline reviewer invariant.

## Context: prior work
- All prior briefs: archived in `mint/task-brief-*.md` (prior = `task-brief-mvp-4.40.md`).
- Existing design: `mint/design.md` §5.80 (B48) most recent; the read-side seqlock this slice operates inside = §5.64 (MVP-4.24); the dense-prefix slot model = §5.61 (B30).
- Architecture doc: not row-anchored — slice originates from the 2026-06-07 `/mint-review` finding PERF-M1 (recorded in session handoff; deferred list).
- Brief-author Phase 2 verification: see "Notes for architect" footer — all literals grep-verified against HEAD `25c6c44`.
- PI continuity: **PI-31** (exporter syscall surface = `bpf_obj_get` + `bpf_map_lookup_elem` ONLY — no update/delete/pin/link/prog_load) CONTINUES; **PI-32** (graceful empty/partial per-iface WARN-and-continue) CONTINUES; **PI-7** (`loader.hpp` zero-diff) trivially holds (no loader touch); **BPF insn 3477** trivially holds (no `src/bpf` touch); §5.64 seqlock semantics (D-mvp-4.24-SEQNUM / -TEAR-HONESTY / -Q1 retry bound) PRESERVED.

## Workflow rules (brownfield)
- Architect: read §5.61, §5.64, §5.71 (percpu_read extraction), guard #26 (§5.49 tail) + guard #32 (§5.64 notes); EDIT `mint/design.md` in place; append **§5.81**.
- Impl: FileList per §5.81; run **TARGETED tests only** (T_EXPORTER_*), NOT full ctest — tester owns the full run (2026-06-07 contention lesson).
- Tester: NEW ctests target ≥1 (see HG-2); EDITED ctests expected ZERO (output-invariance).
- Reviewer: 5-point brownfield framework; special attention = guard #26 two-leg discipline (comments at BOTH ends), seqlock window untouched, scrape-output byte-identity argument.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.41-1: legacy no-`slot_rule_id`-pin path → **preserve the full 64-slot walk**
A pre-§5.61 iface (no `slot_rule_id` pin; `rule_counters_reader.cpp:140-141` open fails) has NO id information → the bound is unknowable there. Default: that path keeps today's full-walk behavior unchanged (conservative, zero behavior delta on the legacy edge). Architect MAY instead argue skip-entirely (prom emits nothing for all-EMPTY ids anyway) — but that changes the `RuleCountersSample` contents on a path with no test coverage; default is the no-delta option.

### HG-mvp-4.41-2: NEW ctest oracle → **output-invariance, not syscall-count**
Default oracle: a scrape with `count < 64` live rules produces byte-identical `/metrics` text before/after (or vs a golden), plus the existing T_EXPORTER family stays green. A syscall-COUNT assertion (e.g. `strace -c -e bpf`) is attractive but environment-fragile; tester MAY add it as a local-gate-only assert if it proves stable, NOT as the primary oracle. (Note: T_EXPORTER tests #48/#63 are documented env-fails (EACCES) — don't let the new test inherit that env-dependency blindly; see guard #31 green-on-SKIP floor.)

## Open mechanism questions (architect decides; document in §5.81)

### Q1: how the reader learns the bound
- **A1 (recommended)**: reorder within `read_generation` — read `slot_rule_id` FIRST, early-`break` at the first `XDPMF_SLOT_ID_EMPTY` (guard #26 boundary sentinel), then PERCPU-sum only slots `[0, count)`. No new maps, no ABI, no new syscall class; stays inside the same seqlock generation window (§5.64 pre/post `active_idx` check unchanged).
- **A2**: `BPF_MAP_LOOKUP_BATCH` to fetch all 64 `slot_rule_id` entries in one syscall. REJECT-leaning: introduces a new syscall class against PI-31's letter ("only bpf_obj_get + PERCPU lookup"), kernel-version surface, and saves little once A1 bounds the loop anyway.
- **A3**: publish the live count in a map the exporter reads (e.g. widen `xdpmf_ruleset_state`). REJECT: `xdpmf_ruleset_state` is ABI-frozen (sizeof==80 static_assert, `xdpfilter.h:358-359`), touches datapath header + loader for an exporter-side nicety — disproportionate.
- **Recommendation**: A1. Guard #26's two legs are ALREADY satisfied upstream: (a) dense-at-front — `compute_slot_to_id` fills `[0,count)` and sentinel-fills the tail (`compiled_ruleset.cpp:87-99`); (b) no real entry masquerades as sentinel — `config.cpp:417-419` REJECTS `rule.id == XDPMF_SLOT_ID_EMPTY` at parse time. Architect documents the cross-file dependency comment at BOTH ends per guard #26 forward-defense.

### Q2: what the early-exit does to the per-slot `bpf_map_lookup_elem` MISS case
Per guard #26's boundary-vs-per-element distinction: a **lookup failure** on a `slot_rule_id` key (transient ENOENT) is a per-element miss — it MUST stay `continue`-equivalent (slot keeps sentinel), NOT a `break`; ONLY the successfully-read `XDPMF_SLOT_ID_EMPTY` value is the dense-prefix boundary. Architect rules the exact loop shape; the distinction itself is a hard fence.

## Scope (cycle MVP-4.41 — concrete items)

### Item PERF-M1-1 — bound the two 64-iteration loops in `read_generation`
**Where**: `src/exporter/rule_counters_reader.cpp` (the per-scrape operational codepath — loops at `:127` (PERCPU sums) and `:144` (slot_rule_id reads); reorder + bound per Q1/A1).
Today: 64 PERCPU sums + up to 64 id lookups per iface per scrape regardless of live count. After: ~`count`+1 id reads + `count` PERCPU sums on the modern path; legacy path per HG-1. The `RuleCountersSample` struct contract (`rule_counters_reader.hpp:37-40` — arrays value-initialized, "fills ALL entries (sentinel/zero)") is PRESERVED by construction (unread tail stays `{}`); the hpp doc-comment wording may need a touch — that's an EDIT, list it.

### Item PERF-M1-2 — guard #26 cross-file forward-defense comments
**Where**: consumer `src/exporter/rule_counters_reader.cpp` (at the new break) AND producer `src/lib/compiled_ruleset.cpp` (`compute_slot_to_id`) — name the dense-prefix + sentinel-rejection dependency at both ends, citing `config.cpp` id-sentinel rejection as leg (b). Comment-only on the producer side (NO loader/compile logic change).

### Item PERF-M1-3 — test coverage per HG-2
**Where**: `tests/` — ≥1 NEW ctest (tester names it; T_EXPORTER family); ZERO EDITED ctests expected. If the new test touches bpffs/iface/exporter port → RESOURCE_LOCK per guard #12.

## Out of scope (explicit)
- `stats_reader.cpp` — its loop is `STAT_MAX (=5)`-bounded, not a 64-walk; no win there.
- Any datapath / `src/bpf` / loader / `xdpfilter.h` ABI change (kills A3 by fence).
- `BPF_MAP_LOOKUP_BATCH` exploration (Q1/A2) unless architect overturns with evidence.
- SEC-L1 exporter sandboxing (separate deferred finding; deployment-gated).
- The documented env-fail cleanup of T_EXPORTER #48/#63 (BACKLOG B16-adjacent; not this slice).

## Definition of done
- §5.81 amendment in `mint/design.md` (problem, Q1/Q2 resolution, D-decisions, guard walk).
- PI-31 + PI-32 + §5.64 seqlock semantics explicitly re-affirmed in §5.81 invariants.
- Scrape `/metrics` output byte-identical for `count < 64` configs (reviewer-checked argument + test).
- ctest: full suite green minus the 4 documented env-flakes (#1/#9 timeout, #48/#63 EACCES); ≥1 NEW exporter ctest.
- NO VERSION bump (internal perf hygiene, no operator-visible surface change).
- `mint/review.md` round-1 verdict = pass; one git commit per phase boundary.

## Dependencies
- Build: existing (libbpf, clang-19, libc++). Runtime: root for exporter ctests (bpffs reads). No new deps.

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
Mechanical: single design axis (how the reader learns the bound), answer falls out of the existing dense-prefix invariant + guard #26; cheap to undo (exporter-only); NOT hld-shaped. Stateful-map PRESERVE-vs-RESET: N/A (no map promotion; reader-only). PO-filter: no PO-tier decisions — both HGs are engineering defaults.

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author ran (HEAD `25c6c44`); architect re-verifies independently per guard #5:
- `grep -rn 'XDPMF_RULE_COUNTERS_MAX' src/exporter/` → syscall loops ONLY in `rule_counters_reader.cpp:127,136,144` + `prom_format.cpp:128` (the latter is host-array iteration, NOT syscalls — leave it).
- `grep -n 'XDPMF_SLOT_ID_EMPTY' src/lib/config.cpp` → `:417-419` sentinel-id REJECTED at parse (guard #26 leg b).
- `sed -n '85,100p' src/lib/compiled_ruleset.cpp` → `compute_slot_to_id` dense-prefix `[0,count)` + sentinel tail (guard #26 leg a).
- `grep -n 'static_assert(sizeof(struct xdpmf_ruleset_state)' src/common/xdpfilter.h` → `:358` ABI-frozen 80B (fences Q1/A3).
- `prom_format.cpp:128-130` — EMPTY-skip already in place → output-invariance claim grounded.
- Exporter ctest cohort: 7 × `tests/T_EXPORTER_*.sh`; `rule_match_total` asserted in `T_EXPORTER_RULE_LABELS.sh` + `T_EXPORTER_SCRAPE_CONSISTENCY.sh`; counter semantics in `T_RULE_COUNTER_MAC_HIT_BUMPS.sh` + `T_RULE_COUNTER_SURVIVES_REORDER.sh` (B30 moved-keeps-counter — the reorder-density edge's existing net).
- Counts here are operative-semantic SHOULD-hints, not literal contracts; impl deviations mirroring precedent → `inline-merge` per design's resolution rule.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #26** (sentinel-array early-break, §5.49) — THE core guard: two-leg invariant (a) dense-at-front (b) sentinel-unreachable-for-real-data, comments at BOTH ends, boundary-break vs per-element-continue distinction (→ Q2).
- **Guard #32** (§5.64 read-side seqlock) — the reorder stays INSIDE one generation window; do not move reads across the `active_idx` pre/post checks; retry bound `kRuleCountersGenRetryMax` untouched.
- **Guard #29** (§5.61 slot/id decouple) — slot ≠ operator id; the bound is over SLOTS; never assume id ordering.
- **Guard #9** (duplication-over-extraction) — any new helper stays local to `rule_counters_reader.cpp`; do NOT extract into `percpu_read.hpp` at 1 consumer.
- **Guard #12** (RESOURCE_LOCK) — if the NEW ctest touches bpffs/iface/port shared state.
- **Guard #19** (WARN text convention) — only if any new WARN line is added (none expected).
- **Guard #31** (green-on-SKIP floor) — the NEW ctest must not silently SKIP-pass in the CI build-only env.
