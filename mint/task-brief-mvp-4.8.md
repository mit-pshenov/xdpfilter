# Task brief — MVP-4.8: `apply_request` table-driven inactive-slot populate (backlog B20, brownfield)

## Goal

Pay backlog **B20** (HIGH, code-quality) — a **behavior-preserving** refactor of `internal::apply_request` in `src/lib/loader.cpp`. The reattach branch and the fresh-attach branch each repeat the *same* per-axis inactive-slot fd-populate idiom; across the two branches it appears **14×** (7 axes × 2 branches), differing only in the `_a`/`_b` map-pair, the diagnostic string, and which `populate_*` is called. This is the **HK-9 lockstep-failure class**: a wrong `_a`/`_b` (or wrong slot) in any 1 of the 14 sites silently corrupts the atomic swap and is **compiler-invisible** — no test of the *un-mutated* axis catches it.

Collapse the 14 hand-rolled `(slot==0?_a:_b) → bpf_map__fd → throw-if-<0 → populate_*` blocks into a table-driven shape following the already-blessed single-TU precedents (`write_wildcard_slots`, `kManagedMaps[]`): a small `inactive_inner_fd(a, b, slot, what)` fd-selector helper + a `populate_all_axes(skel, slot, …)` wrapper that **both** branches call with their slot (fresh = 0, reattach = `inactive`). Target ≈250 → ≈60 LOC.

**Why now:** S8 (next slice) adds **axis #7** (IPv6 `cidr6`) and walks straight into this 14× idiom — paying B20 first means S8 adds *one table row*, not *two more hand-rolled blocks that must agree*.

Anchor: `docs/BACKLOG.md` B20 (no `architecture-v2.md` row — this is debt-paydown, not a feature; `design.md` gets a housekeeping §-amendment). Secondary item B25 (stale comment correctness) folded in per backlog's explicit "bundle w/ B20" note.

## Context: prior work
- All prior briefs: archived in `mint/task-brief-*.md` (this one archives `mvp-4.7` → `task-brief-mvp-4.7.md`).
- Existing design: `mint/design.md` §5.47 (MVP-4.7 MAC-axis return) is the most recent slice; match-model = **6 axes AND** (mac·dst_cidr·src_cidr·proto·dst_port·vlan), first-match-by-id, schema_version 2, IPv4-gated.
- Phase A code-grep verification (brief author): confirmed both branches' 14 idiom blocks (reattach `loader.cpp` ~2233-2380; fresh-attach ~2466-2554), confirmed the per-axis `populate_*` set, confirmed `copy_rule_counters_forward` differs per branch, confirmed no pre-existing `inactive_inner_fd`/`populate_all_axes` helper. See Phase 2 report in skill output.
- **PI continuity: ALL existing PIs CONTINUE byte-equivalent.** This slice changes *how* the inactive slot is populated, not *what* lands there. No PI is retired, extended, or added (a new internal-helper PI is optional, architect's call).
- ZERO-diff streaks: PI-7 `loader.cpp` streak is ALREADY broken (ended at MVP-4.3 per the OR→AND pivot); this slice edits `loader.cpp` by design. `config.hpp` is comment-only-touched (B25); no logic change.

## Workflow rules (brownfield)
- **Architect**: read `design.md` §5.43–§5.47 (the bit-vector AND apply-path lineage) + §6.5 invariants + guards #9/#10/#11/#15/#16. EDIT `design.md` in place; append a housekeeping §-amendment (e.g. §5.48 or §6.x) documenting the two new helpers + the explicit extraction boundary (see HG-3). Owns the final helper signature/shape (Q1) and the extraction boundary (HG-3).
- **Impl**: behavior-preserving refactor of `loader.cpp` apply_request per design's §-amendment. New helpers stay anon-namespace / single-TU (guard #9). B25 comment edits in `config.hpp` + `apply_internal.hpp`.
- **Tester**: **NEW ctests target = 0.** This is a behavior-preserving refactor; the regression net is the *existing* suite — `T_APPLY_ATOMIC_SWAP_NO_DROP`, `T_CIDR_ATOMIC_SWAP_NO_DROP`, `T_RULES_ATOMIC_SWAP_NO_DROP`, `T_RULE_COUNTERS_ATOMIC_SWAP`, `T_RULE_COUNTER_SURVIVES_APPLY`, and `T_AND{,4,5,6}_ORACLE_AGREEMENT` + `T_BITVEC_ORACLE_AGREEMENT` (every axis exercised through both fresh-attach and reattach). Tester may add a *targeted* regression ONLY if it finds an axis/branch combination the existing suite does not exercise (e.g. a reattach-path per-axis swap canary) — justify against the existing corpus, don't add for symmetry.
- **Reviewer**: 5-point brownfield framework. **Load-bearing checks:** (1) semantic diff of the populate sequence — same maps, same slots, same `populate_*` fns, same order, both branches; (2) the `_a`/`_b`↔slot mapping inside `inactive_inner_fd` is correct for BOTH slot=0 (→`_a`) and slot=1 (→`_b`) — this is the exact bug class B20 exists to kill, verify it by reading, not by trusting the green suite; (3) `copy_rule_counters_forward` (PRESERVE) and `populate_action_table` (shared static) are NOT swept into the uniform RESET-on-apply helper (guard #15).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.8-1: VERSION bump → **NO bump (stay 0.15.0)**
Behavior-preserving internal-loader refactor with zero operator-observable change. Mirrors the **MVP-3.4e precedent** ("No VERSION bump — internal hardening"). If the architect judges that a loader-internal structural change warrants release-traceability and bumps to `0.15.1`, then **guard #11** applies: propagate the literal to `T_EXPORTER_METRICS_FORMAT` (4 sites) + CHANGELOG. Default keeps it simple — no bump, no propagation.

### HG-mvp-4.8-2: B25 stale-comment fixes in scope → **YES (secondary, fenced)**
`docs/BACKLOG.md` B25 explicitly says "bundle w/ B20". Confirmed stale comments: `apply_internal.hpp:27` ("schema_version 1" — now `==2`), `config.hpp:45` ("MAC axis DEFERRED in v2 … rejected at parse" — MAC was re-accepted in MVP-4.7), plus the B25-cited `config.hpp:5,14-15,60` schema/mac comment block + the `config.cpp` stacked "REJECTED→RE-ACCEPTED" paragraphs. **Comment-only, zero behavior, zero test ripple.** Update to v2 / 6-axis reality; drop superseded history paragraphs (history lives in git / RETROSPECTIVES). Reviewer may split B25 to a follow-up if it judges the slice cleaner single-purpose — non-blocking.

### HG-mvp-4.8-3: extraction boundary → **helper covers the RESET-on-apply axes only**
`populate_all_axes` covers the **6 match axes + `rules` + `wildcard` + `defaults`** (all RESET-on-apply, identical select-fd-throw-populate shape). **EXCLUDED from the uniform helper, stay explicit per branch:**
- `copy_rule_counters_forward` — **PRESERVE semantics, and the args genuinely differ per branch** (reattach: `old_active → inactive`; fresh: self-copy `a → a`). Folding it into a RESET-shaped uniform helper would wipe the operator-grade counter monotonicity (PI-mvp-4.3-COUNTER-PRESERVE). This is **guard #15** — the load-bearing reason this refactor is non-trivial.
- `populate_action_table` — shared static `{PASS,DROP}`, no slot dimension; leave as its own explicit call.

Architect owns whether `inactive_inner_fd` also subsumes the wildcard/defaults fd-fetch or just the per-axis inner-map fetch.

## Open mechanism questions (architect decides; document in the §-amendment)

### Q1: helper shape
- **A1** — two helpers: `int inactive_inner_fd(bpf_map* a, bpf_map* b, std::uint32_t slot, const char* what)` (selects `slot==0?a:b`, `bpf_map__fd`, throws `LoadFailed` with `what` on `<0`) + `void populate_all_axes(xdpmacfilter_bpf* skel, std::uint32_t slot, <lowerings…>, DefaultAction)` that calls the fd-helper per axis then the matching `populate_*`. Both `apply_request` branches collapse to one `populate_all_axes(skel, slot, …)` call (fresh `slot=0`, reattach `slot=inactive`).
- **A2** — a static `constexpr` axis-descriptor table (à la `kManagedMaps[]`) of `{map-pair accessor, diag-string}` walked in a loop. Harder because the `populate_*` callee + its lowering-payload *type* varies per axis (mac entries vs `BitPrefix` vs `xdpmf_port_range` vs `Rule`) — a uniform loop needs type erasure or per-axis lambdas.
- **Recommendation**: **A1** — kills the 14× select-throw idiom (the actual HK-9 hazard) with zero type-erasure cost; keeps each `populate_*` call explicit and readable. A2's data-table elegance fights the heterogeneous payload types. Architect may blend (A1 fd-helper + a small per-axis lambda array) if it prefers.

## Scope (cycle — concrete items)

### Item B20-1 — `inactive_inner_fd` fd-selector helper
**Where**: `src/lib/loader.cpp` (anon namespace, near the other `populate_*` helpers ~1424-1798).
Extract the identical `(slot==0?a:b) → bpf_map__fd → throw_loader(LoadFailed, what) if <0 → return fd` idiom. Single-TU, single consumer family (guard #9 satisfied — internal, not cross-file over-sharing).

### Item B20-2 — `populate_all_axes` wrapper + branch collapse
**Where**: `src/lib/loader.cpp` `internal::apply_request` reattach (~2233-2380) + fresh-attach (~2466-2554).
Both branches call one `populate_all_axes(skel, slot, …)`. RESET-on-apply axes only (HG-3). Order preserved (the active_idx flip remains the single atomic commit AFTER populate). `copy_rule_counters_forward` + `populate_action_table` + the `active_idx`/link/sidecar steps stay branch-specific and unchanged.

### Item B25-1 — stale schema/mac comment correctness (secondary, HG-2)
**Where**: `src/lib/config.hpp` (:5,:14-15,:45,:60), `src/lib/apply_internal.hpp` (:27), `src/lib/config.cpp` (the stacked REJECTED→RE-ACCEPTED paragraphs).
Comment-only. Update "schema_version 1 / MAC DEFERRED / rejected" → v2 / 6-axis / MAC re-accepted reality. Drop superseded history prose.

## Out of scope (explicit)
- **B18** (port_scan `continue`→`break`) — datapath `mac_filter.bpf.c`, behavior-changing (perf), different file/concern. Separate cheap-win.
- **B28** (template the 3 near-dup HASH populate fns + 3 axis-merge fns) — the explicit *follow-on* to B20; expands scope into the `populate_*` definitions themselves. Natural NEXT refactor slice, not this one.
- **B19** (RESOURCE_LOCK build_cpu) — test-infra, separate.
- Any `.bpf.c` datapath change, any map/pin rename, any schema or axis change (that's S8).
- Any change to atomic-swap *semantics*, axis *set*, or `active_idx` flip *timing*.

## Definition of done
- Housekeeping §-amendment in `design.md` documenting the two helpers + the HG-3 extraction boundary + guard #15 rationale.
- All existing PIs CONTINUE byte-equivalent (no PI retired/added unless architect adds an optional internal-helper PI).
- ctest baseline GREEN unchanged (84/84 per MVP-4.7; NEW ctests target = 0). The atomic-swap + 6-axis oracle-agreement + counter-preserve suite is the regression net.
- VERSION unchanged at 0.15.0 (per HG-1 default).
- B25 comments corrected.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang-19 toolchain, libbpf, CMake ≥3.20 (unchanged).
- Runtime: root for the atomic-swap ctests (bpffs, XDP attach); kernel 6.1 host (5.15 untested — unchanged residual, not touched here).
- No new deps.

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
**MECHANICAL → single-architect via `/mint-dev`. NO `/mint-hld`.** Single-axis (one function in one TU), the answer falls out of the already-blessed table-driven precedents (`write_wildcard_slots`, `kManagedMaps[]`), and it's a behavior-preserving refactor with an existing regression net. The one subtle axis — the PRESERVE-vs-RESET boundary (`copy_rule_counters_forward` must stay branch-specific) — is surfaced as HG-3 + Phase-1-sub-check-#5 below; architect handles it in the §-amendment, not a design-space exploration.

### Phase 1 sub-check #5 — stateful-map PRESERVE-vs-RESET semantic
| Map | Prior | Post | Flag |
|---|---|---|---|
| `rule_counters` (PERCPU, atomic-swap) | PRESERVE-across-apply (PI-mvp-4.3-COUNTER-PRESERVE; `copy_rule_counters_forward` old_active→inactive) | **UNCHANGED — must remain PRESERVE** | **Do NOT fold `copy_rule_counters_forward` into the RESET-shaped `populate_all_axes`.** It stays an explicit branch-specific call (reattach copies forward, fresh self-copies). This is the load-bearing hazard of the refactor (guard #15). |
| 6 match axes + `rules` + `wildcard` + `defaults` | RESET-on-apply | UNCHANGED — RESET | These are exactly what `populate_all_axes` unifies. |

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author already ran these; architect re-verifies + extends:
- `grep -nE 'populate_inner_slot|populate_bitvec_inner_slot|populate_proto_inner_slot|populate_vlan_inner_slot|populate_port_inner_slot|populate_rules_inner_slot|write_wildcard_slots|write_default_slot|copy_rule_counters_forward|populate_action_table' src/lib/loader.cpp` — the full per-axis callee set + the two NON-uniform calls.
- Read `loader.cpp` ~2225-2400 (reattach) and ~2461-2580 (fresh-attach) side by side; confirm the 14 idiom blocks + the slot dimension (reattach `inactive`, fresh fixed-0) + the divergent `copy_rule_counters_forward` args.
- `grep -nE 'inactive_inner_fd|populate_all_axes' src/lib/loader.cpp` — confirm the new names don't collide.
- Confirm `xdpmacfilter_bpf*` skel type name + the exact `skel->maps.<name>_a/_b` accessors for all 7 axis pairs.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #9** (helper-location duplication-over-extraction) → APPLIES, and is SATISFIED by design: extraction is single-TU / anon-namespace (mirrors `write_wildcard_slots`, `kManagedMaps[]`), not cross-file over-sharing. Architect: confirm new helpers do NOT get hoisted to a header.
- **Guard #10** (catalog arithmetic) → `kManagedMaps[]` STAYS 30, no map added/removed. Confirm no count churn.
- **Guard #11** (VERSION-bump test-literal propagation) → conditional on HG-1. Default no bump → N/A. If architect bumps → propagate to `T_EXPORTER_METRICS_FORMAT` (4 sites).
- **Guard #15** (stateful-map PRESERVE-vs-RESET) → **CRITICAL.** `copy_rule_counters_forward` PRESERVE must stay outside the RESET-shaped uniform helper. See HG-3 + sub-check #5.
- **Guard #16** (retired pin-path/map-name ripple) → N/A; pure logic refactor, no pin/map rename, no test-body pin-dump ripple.
- **HK-9 lockstep class** (the bug B20 kills) → the whole point: post-refactor, the `_a`/`_b`↔slot decision lives in ONE place (`inactive_inner_fd`), not 14. Reviewer verifies that one place by reading both slot cases.
