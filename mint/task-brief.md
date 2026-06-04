# Task brief — MVP-4.30 / B35: wildcard+defaults → `ruleset_state` pack (brownfield, SPIKE-GATED, verdict-identity)

## Goal

Collapse the per-axis `wildcard` ARRAY lookups + the `defaults` lookup in the datapath into **one `ruleset_state[active]` struct read** carrying all 9 per-axis wildcard `__u64` + the `defaults` `__u32` as struct fields. Today each family arm independently issues a `bpf_map_lookup_elem(&wildcard, &computed_key)` per axis (`wildcard[active*BITVEC_NUM_AXES + axis]`) — **25 static wildcard-lookup sites across the 3 family arms** (per-packet dynamic ≈ 8–9, since only one arm runs) + 1 `defaults` lookup. Packing the values into a single per-ruleset struct turns those into one (or one-per-arm) struct lookup + field reads — fewer BPF helper calls, fewer instructions. This is **B35 = PERF-M1 promoted** (`docs/BACKLOG.md:196`).

**Honest framing: perf is NOT a fire.** The parked perf envelope ([[project_perf_envelope]], `mint/perf.md`) shows eBPF clears SLA#1 with ~1–2 core headroom; there is no classifier-cost forcing-function. B35 is **ceiling-lowering**, and its co-equal motives are (a) it is the structural home for the B34a-deferred fold #2 (`load_wildcards` — the 3 arms' divergent wildcard-load orderings, `src/bpf/classifier.h:223`, normalize through a single struct read), and (b) band-training value ([[project_dual_purpose_band_training]]).

**This is the ONLY slice in the cleanup arc with a real regression surface.** It is a **map-schema change** (the `wildcard` + `defaults` ARRAYs → a `ruleset_state` ARRAY-of-struct) ⇒ the compiled datapath is **NOT byte-identical**. Correctness is held by **verdict-identity**, not byte-identity: the existing `T_*_ORACLE_AGREEMENT.sh` family (datapath verdict vs userspace oracle across crafted vectors) MUST stay green. The B37 insn gate's 3658 baseline WILL change — this is the **sanctioned use of the `XDPMF_PROD_INSN_BASELINE` escape hatch** (`tests/T_PROD_VERIFIER_LOAD.sh:120,137` — "intentional codegen change … XDPMF_PROD_INSN_BASELINE=<actual>"), re-baselined to the new measured count, NOT a violation.

## SPIKE-GATED — measure-first is a hard prerequisite (can ABORT the slice)

Per the backlog's literal "**MEASURE instructions/cycles per packet first**" and the project's spike-gated precedent (S4 cidr6, S6 ext-walk: briefer→SPIKE→mint-dev), B35's first step is a verifier-load + perf spike:
- Prototype the `ruleset_state` pack (throwaway or a guarded branch), build the `.bpf.o`, and **measure**: (a) does it load on the verifier cleanly? (b) the new xdp insn count vs 3658 — does it actually go DOWN, or does the verifier expand the struct read back into N field-loads that net to ~zero (or worse)?
- **Gate**: if the measured instruction win is negligible (or the verifier rejects / regresses), the architect ESCALATES — the slice is not worth its verdict-identity regression risk and we abort/defer (surface to team-lead → user). Do NOT proceed to the full restructure on an unproven win. External value being weighed: ceiling-lowering + band-training vs the regression risk of a map-schema change; the spike discharges it.
- Spike tooling: [[reference_bpf_spike_tooling]] (`clang-19 -target bpf -O2 -g -D__TARGET_ARCH_x86 -Iinclude -Isrc` + bpftool load); insn-count recipe = `llvm-objdump-19 -d --section=xdp <obj> | grep -cE '^\s+[0-9a-f]+:'` (the B37 gate's own method).

## Context: prior work

- All prior briefs archived in `mint/task-brief-*.md` (B34b → `mint/task-brief-mvp-4.29.md`).
- Existing design: `mint/design.md` §5.69 (B34b module split — the post-split tree this builds on: `maps.h` holds the `wildcard`/`defaults` defs, `classifier.h`+`xdpfilter.bpf.c` hold the reads).
- BACKLOG: `docs/BACKLOG.md:196` (B35, PERF-M1).
- B34a fold #2 deferral: `src/bpf/classifier.h:223` (the 3 arms' divergent wildcard orderings, "LEFT AS-IS … NOT a regression") — B35 is its home.
- Perf baseline method: `mint/perf.md` / commit `e9bb321` (BPF_PROG_TEST_RUN).
- Phase A code-grep verification: brief author ran the greps in the evidence footer.
- PI continuity: PI-7 (C++ loader/config header tree) — wildcard/defaults populate lives in `src/lib/loader.cpp` so loader.cpp IS edited this slice; PI-7's loader.hpp/config.hpp zero-diff streak likely continues (impl edits .cpp, not the .hpp interface — architect confirms). PI-DATAPATH-IDENTICAL (byte) is **RETIRED for this slice**, replaced by PI-VERDICT-IDENTICAL.

## Workflow rules (brownfield, spike-gated)

- **Architect**: read §5.69 (post-split tree) + the `wildcard`/`defaults` map defs (`src/bpf/maps.h`) + the datapath reads + the loader populate path (`write_wildcard_slots`/`write_default_slot`) + the `T_*_ORACLE_AGREEMENT` harness + §6.5 invariants + the B37 gate. **Run the measure-first spike in Phase A** (or consume a standalone spike if run first) and record the measured win as a D-decision; ABORT-escalate if the win is not real. EDIT design.md in place; append §5.70. Owns the `ruleset_state` layout, the per-arm-vs-hoisted read strategy, the loader restructure, the re-baseline value, and the verdict-identity test plan.
- **Impl**: FileList per brownfield DIFF. The datapath restructure touches all 3 arms (25 static wildcard sites). Re-run the B37 gate AND the ORACLE_AGREEMENT family after the change. Re-baseline `XDPMF_PROD_INSN_BASELINE` to the measured value per the architect's D-decision (do NOT leave 3658 if the count legitimately changed).
- **Tester**: the **verdict-identity oracle is the bible** — the `T_*_ORACLE_AGREEMENT.sh` family must stay green across ALL crafted vectors (this is the regression control for a non-byte-identical change). Confirm the negation control still has teeth. A NEW `T_RULESET_STATE_*` test only if the architect identifies a struct-specific surface (e.g. the active-half flip writes the right slot). Re-run the B37 gate against the re-baselined count.
- **Reviewer**: 5-point brownfield. Special attention: (a) verdict-identity — every ORACLE_AGREEMENT vector still agrees; (b) the re-baseline is the MEASURED count + the bump is documented as intentional (not a silent weakening); (c) atomic-swap RESET semantic preserved (the struct is written fresh to the inactive half each apply, then flipped — no stale carry); (d) all 3 arms read consistently (the fold-#2 ordering divergence is GONE, not just relocated); (e) PI-7 loader.hpp/config.hpp diff.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.30-1: spike outcome gates the slice → **default = proceed ONLY if measured insn win is real**
If the Phase-A spike shows the pack does not meaningfully reduce instructions (verifier expands the struct read) or fails to load, ESCALATE and abort/defer rather than ship a verdict-identity-risky change for no gain. Default proceed-threshold is the architect's to set with the measured numbers; "real win" ≈ a clear net instruction reduction that survives the verifier. This is the one genuinely-conditional gate; everything below assumes the spike passed.

### HG-mvp-4.30-2: `ruleset_state` layout → **default = 9 wildcard `__u64` (indexed by `BV_AXIS_*`) + `defaults` `__u32`, one struct per ruleset, ARRAY[XDPMF_RULESET_COUNT]**
Mirrors the existing `wildcard[active*BITVEC_NUM_AXES+axis]` + `defaults[active]` semantics, just packed. Architect refines field order/padding for verifier-friendliness. Whether `defaults` folds INTO the struct or stays a sibling ARRAY is the architect's call (folding it in is the backlog's intent and saves the extra lookup; keeping it separate is lower-blast-radius). Default: fold in.

### HG-mvp-4.30-3: atomic-swap semantic → **RESET (UNCHANGED) — no copy-forward**
`wildcard` + `defaults` are config-derived (recomputed every `apply` via `write_wildcard_slots`/`write_default_slot` into the INACTIVE half, then the `active_idx` flip). They are NOT operator-observable counters — they carry no monotonic Prometheus contract. Prior semantic = RESET-on-apply; post-pack = RESET (UNCHANGED). Per the Phase-1.5 matrix RESET→RESET needs NO `copy_*_forward` helper — the atomic-swap shape alone is correct (the struct is written fresh each apply). (Contrast `rule_counters`, which DOES preserve — that is a different map.)

### HG-mvp-4.30-4: VERSION bump → **default = NO bump (internal perf restructure, no operator-facing API/schema change)**
No config-schema change, no new CLI surface, no metric rename — the `apply -f` contract and the operator-observable maps are unchanged. Default: VERSION stays 0.16.0. Architect overrides if a config/schema-version field is actually touched (it should not be).

## Open mechanism questions (architect decides; document in §5.70)

### Q1: datapath read strategy
- **A1**: one `ruleset_state` lookup per family arm (3 static sites, ≈1 dynamic/packet) — minimal restructure, each arm reads the struct it needs.
- **A2**: hoist a single `ruleset_state` lookup ABOVE the family dispatch (1 static site) — fewest lookups, but the pointer must thread into all 3 arms.
- **Recommendation**: architect picks from the spike's instruction numbers; **A2** likely wins on lookup count but **A1** may be more verifier-friendly / lower-blast-radius. Whichever the spike shows lower-insn-and-clean-verify.

### Q2: `defaults` — fold into the struct or keep sibling
- **A1**: fold `defaults` into `ruleset_state` (one read serves both) — backlog intent.
- **A2**: keep `defaults` as its own ARRAY (it is already a clean 2-slot ARRAY) — smaller blast radius.
- **Recommendation**: **A1** (the −1 lookup is the backlog's stated win); architect downgrades to A2 if folding complicates the verifier or the loader disproportionately.

## Scope (cycle MVP-4.30 — concrete items; UPPER-BOUND estimates)

### Item B35-0 — measure-first spike (PREREQUISITE, gates all below)
**Where**: throwaway / guarded prototype + `llvm-objdump` insn measurement. Prove the pack loads + reduces instructions before any real restructure. ABORT-escalate if not.

### Item B35-1 — `ruleset_state` type + map definition
**Where**: `src/common/xdpfilter.h` (the shared struct + map-name constant), `src/bpf/maps.h` (the `SEC(".maps")` def). Retire/repurpose the `wildcard` (+ maybe `defaults`) ARRAY defs per HG-2/Q2.

### Item B35-2 — datapath reads (all 3 arms)
**Where**: `src/bpf/xdpfilter.bpf.c` (the 3 family arms, 25 static wildcard sites + 1 defaults), `src/bpf/classifier.h` (any helper/comment touching wildcard loads, incl. the fold-#2 note). Replace per-axis lookups with struct-field reads per Q1.

### Item B35-3 — loader populate restructure
**Where**: `src/lib/loader.cpp` (`write_wildcard_slots` + `write_default_slot` → write the `ruleset_state` struct to the inactive half). Possibly `src/lib/sidecar.cpp`/`apply_internal.hpp`/`sidecar.hpp` if they reference the retired map names — grep-confirm (see footer). Keep the RESET/inactive-half-then-flip ordering.

### Item B35-4 — verdict-identity regression + re-baseline
**Where**: `tests/T_*_ORACLE_AGREEMENT.sh` (must stay green — the correctness oracle), `tests/T_PROD_VERIFIER_LOAD.sh` / the B37 baseline (re-baseline `XDPMF_PROD_INSN_BASELINE` to the measured count, documented intentional). NEW `T_RULESET_STATE_*` only if a struct-specific surface needs it.

## Out of scope (explicit)

- **Any match-semantic / verdict change** — verdict-identity is the contract; every ORACLE_AGREEMENT vector keeps its verdict. This is a pure representation change.
- **The OUTER per-axis map-reference lookups** (`dst_rulesets`/`cidr_rulesets`/`rules_outer`/ARRAY_OF_MAPS double-buffer) — those are map REFERENCES, NOT packable (backlog: "hard ceiling"). B35 packs only the VALUE class (wildcard + defaults).
- **Schema / axis / VERSION change** — none (HG-4).
- **B36** (64-rule `__u64` ceiling, DEBT) — separate, not-now.
- **Capability work** (mirror/redirect XDP→TC handoff) — the real product gap per [[project_real_requirements_and_strategy]]; a `/mint-hld` round when the cleanup arc closes. NOT this slice.

## Definition of done

- Phase-A spike measured + recorded (D-decision); slice proceeded only on a real win.
- §5.70 amendment in design.md (`ruleset_state` layout, read strategy, RESET semantic, re-baseline value, verdict-identity test plan; PI-DATAPATH-IDENTICAL retired → PI-VERDICT-IDENTICAL).
- PI-7 continues (loader.hpp/config.hpp zero-diff — impl edits .cpp). PI-VERDICT-IDENTICAL: all `T_*_ORACLE_AGREEMENT` green.
- B37 gate green against the re-baselined `XDPMF_PROD_INSN_BASELINE` (= measured count, intentional).
- ctest baseline preserved (the 2 known env-fails by NAME; no NEW regression).
- No VERSION bump (HG-4) unless architect finds a real schema touch.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies

- Build: clang-19 `-target bpf` (existing). Spike uses the same.
- Runtime: none new.
- Kernel/platform: the new struct-read map layout must load on the verifier (the spike proves this; prod floor 5.15, dev 6.1).

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  [lang/bpf.md, lang/cpp.md]      # BPF map/verifier idioms + the C++ loader populate path
  impl:       [lang/bpf.md, lang/cpp.md]
  tester:     [test/bpf-xdp.md]               # ORACLE_AGREEMENT family is the verdict-identity oracle
  reviewer:   [test/bpf-xdp.md]
```

---

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])

**Spike-gated single-architect → `/mint-dev`, NOT `/mint-hld`.** The APPROACH is committed by the backlog (pack the value-class into `ruleset_state`); the regression control already EXISTS (`T_*_ORACLE_AGREEMENT` family); the real unknowns are spike-resolvable (does it verify + actually reduce instructions) and design-resolvable (arm read strategy + loader restructure), NOT a wide design-space to farm to multiple architects. Farming "should we pack into a struct?" to a lens panel when the answer is given and the open question is "does it verify and win" (a measurement, not a debate) is the [[feedback_mint_hld_scope]] overkill case. The one genuinely-conditional decision (proceed iff the spike shows a real win) is an engineering gate discharged BY the spike, not a PO fork. Atomic-swap is decidable (RESET→RESET, no copy-forward). This is the S4/S6 mold: briefer → SPIKE → mint-dev.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief author ran these (evidence footer); architect re-verifies + extends:

- `grep -c 'bpf_map_lookup_elem(&wildcard' src/bpf/xdpfilter.bpf.c` → **25** static sites (NOT the backlog's per-packet "9" — that is the dynamic one-arm count; the restructure touches all 25). `grep -c 'bpf_map_lookup_elem(&defaults' …` → **1**.
- `grep -n 'BITVEC_NUM_AXES' src/common/xdpfilter.h` → **9**; `XDPMF_RULESET_COUNT` → **2**.
- `grep -rn 'ruleset_state' src/` → ∅ (NEW type/map).
- Populate path: `write_wildcard_slots` (`src/lib/loader.cpp:1669`) + `write_default_slot` (`:1704`) — re-anchor by name, not line. `grep -rln 'wildcard\|defaults' src/lib/` → loader.cpp + sidecar.{hpp,cpp} + apply_internal.hpp — confirm which actually WRITE vs merely reference the names (guard #16 pin-name ripple class).
- `ls tests/T_*_ORACLE_AGREEMENT.sh` → the verdict-identity harness (AND4/5/6/ETH/V6/BITVEC/MAC_MERGE) — the regression control.
- B37 re-baseline: `tests/T_PROD_VERIFIER_LOAD.sh:120,137` — `XDPMF_PROD_INSN_BASELINE` is the sanctioned escape hatch for an intentional codegen change.
- Run the measure-first spike (insn count pre/post) BEFORE committing to the restructure.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep)** — always; re-anchor every literal (the 25-vs-9 distinction is exactly the kind of approximation guard #5 catches).
- **Guard #15 / Phase-1.5 (atomic-swap PRESERVE-vs-RESET)** — resolved RESET→RESET UNCHANGED (HG-3); architect confirms wildcard/defaults carry no operator-observable monotonic contract (contrast `rule_counters`). NO copy-forward.
- **Guard #16 (retired pin-path / map-name ripple)** — `wildcard` / `defaults` are `XDPMF_MAP_*_NAME` pinned constants; if retired/renamed, grep tests/ AND src/ for direct pin reads (`bpftool map dump pinned …/wildcard`, `…/defaults`) and pre-list every consumer (exporter reader, test bodies, fixtures). The ORACLE_AGREEMENT tests likely dump these pins — check before assuming they "just work".
- **Guard #35 / #37 (gate-as-sole-arbiter; insn-gating discipline)** — the B37 gate arbitrates the insn count; here it is INTENTIONALLY re-baselined (the sanctioned escape-hatch use), not held at 3658. The new baseline = the measured post-spike count, documented.
- **Guard #28 (bounded-walk / verifier-load spikes)** — the new map layout is a verifier-load risk → the measure-first spike carries insns/stack/states, mirroring the S4/S6 spike discipline.
- **Guard #12 (RESOURCE_LOCK)** — applies if a NEW ctest touches the xdp fixture / real load; the ORACLE_AGREEMENT family already follows the project's fixture-lock pattern.

### Evidence footer — brief-author Phase 2 grep verification

```
File/path:
  ✓ src/common/xdpfilter.h         BITVEC_NUM_AXES=9 (:195), XDPMF_RULESET_COUNT=2 (:97), wildcard/defaults map-name consts
  ✓ src/bpf/maps.h                 wildcard ARRAY def (:119), defaults ARRAY def (:288)
  ✓ src/bpf/xdpfilter.bpf.c        25 wildcard lookups + 1 defaults lookup (3 family arms)
  ✓ src/bpf/classifier.h           fold-#2 deferral note (:223) — B35 is its home
  ✓ src/lib/loader.cpp             write_wildcard_slots (:1669), write_default_slot (:1704)
  ✓ tests/T_*_ORACLE_AGREEMENT.sh  AND4/5/6/ETH/V6/BITVEC/MAC_MERGE — verdict-identity oracle (regression control)
  ✓ tests/T_PROD_VERIFIER_LOAD.sh  XDPMF_PROD_INSN_BASELINE escape hatch (:120,137) — sanctioned re-baseline
  ✓ ruleset_state                  absent in src/ → NEW type + map

Estimate corrections vs backlog:
  Backlog "−9 lookups" = per-packet DYNAMIC (one arm). STATIC sites = 25 wildcard + 1 defaults across 3 arms;
  the restructure touches all 25. The dynamic per-packet win is ≈ 8–9 (one arm) + 1 defaults.

Surprising findings:
  • `wildcard` is ALREADY a single combined ARRAY (not 9 maps) — the win is fewer LOOKUPS into it
    (one struct read replaces N per-axis lookups), not fewer maps.
  • B35 naturally subsumes the deferred B34a fold #2 (the 3 arms' divergent wildcard-load orderings
    collapse into a single struct read) — track it, do not treat as separate.
  • This is the FIRST non-byte-identical slice in the arc → B37 baseline is re-based (sanctioned), and the
    pre-existing ORACLE_AGREEMENT family is the correctness oracle (test surface is NOT from scratch).
```
