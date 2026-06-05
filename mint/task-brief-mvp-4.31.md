# Task brief — MVP-4.31 / B38: simplify-harvest — exporter dedup + dead-code + bitvec template-merge (brownfield)

## Goal

Harvest the four BEDROCK/CONTESTED **code** subtractions from the `/mint-simplify` fresh-pass verdict (run `wf_c66d2b84`, post-cleanup-arc @ `0c73fd6`). All are pure subtractions with zero behavior change; the doc-truth items (BACKLOG demote + CHANGELOG arc) already shipped hand-done (`ca80fb9`). This slice is the code half: ~−70 LOC, 0 net new abstractions beyond one shared exporter header.

Four items:
1. **B4 (dead-code, UPHELD)** — delete the `read_all_attached(std::string_view)` single-arg trampoline (def + decl). Zero live callers; the sole scrape consumer (`http.cpp`) calls `read_all_attached_with_acc` directly. Its own comment ("keeps existing call sites byte-equivalent") is stale — no surviving call site.
2. **B2 (extract-shared, UPHELD ×3)** — hoist `round_up_8` + `percpu_sum_u64` (duplicated across the two exporter PERCPU readers) into one shared inline home; delete the duplicate copies. `round_up_8` char-identical; `percpu_sum_u64` differs only in the first param name (`stats_fd`/`map_fd`). NOT covered by the §5.31 byte-equivalence note (that note is attached ONLY to `list_iface_dirs`).
3. **C1 (extract-shared, WEAKENED → conscious reversal)** — hoist `list_iface_dirs` (also byte-identical across the two readers) into the same shared home, **but ONLY as an explicit, documented reversal of the §5.31 "deliberately duplicated, keep byte-equivalent" decision** (`rule_counters_reader.cpp:63-64`) — written down the way B37 reversed `D-mvp-4.23-H3-PRODOBJ`, NOT a silent factor-out. The comment's own rationale (keep the two readers byte-equivalent) is *better* served by a single shared definition (equivalent by construction), so the reversal is defensible — but it MUST be recorded.
4. **B5 (merge, UPHELD)** — collapse `populate_bitvec_inner_slot` / `populate_bitvec6_inner_slot` (near-identical fork) into one `template<class Key>` mirroring the house-style `populate_hash_inner_slot<Key>`. **PROVENANCE-SAFE**: the audited guard #23 (#1 bit-vector bug class) lives in `close_prefixes`/`close_prefixes6`, NOT the populate wrapper — the merged template MUST still receive the two close fns as separate args so the cover-direction surface stays eyeball-auditable. This is the userspace loader map-population path, NOT the protected datapath family-arm asymmetry.

## Context: prior work

- All prior briefs archived in `mint/task-brief-*.md` (B35 → `mint/task-brief-mvp-4.30.md`).
- Source: `/mint-simplify` verdict (run `wf_c66d2b84`, full output in the task transcript). Two substrates: Code Judo (source) + Entropy Controller (concept). These four survived dedup-by-replication + adversarial defense.
- Existing design: `mint/design.md` §5.70 (B35 ruleset_state pack — the most recent datapath slice).
- The §5.31 byte-equivalent-readers decision (the C1 reversal target) is in `src/exporter/rule_counters_reader.cpp:62-64`.
- Phase A code-grep verification: brief author ran the greps in the evidence footer.
- PI continuity: PI-7 (loader.hpp/config.hpp zero-diff) — B5 edits `loader.cpp` body only (the `.hpp` interface is untouched → streak likely continues; architect confirms). The exporter items touch `src/exporter` (outside the loader/config PI-7 surface).

## Workflow rules (brownfield)

- **Architect**: read §5.70 + the two exporter readers + the loader bitvec-populate path + §6.5 invariants. EDIT design.md in place; append §5.71. Owns the shared-header home (Q1), the C1 §5.31-reversal record (HG-2), and the B5 template signature. Phase A re-verify the body-identity claims (guard #5) — the verdict's per-helper diff is the starting point, not gospel.
- **Impl**: FileList per brownfield DIFF. Four independent subtractions; each is small and mechanical. Build clean + zero warnings. Userspace (no insn gate) for B2/B4/C1; B5 rebuilds the loader (no datapath `.bpf.c` change → xdp stays 3437).
- **Tester**: the existing oracles ARE the regression control — NO new behavioural test. Exporter ctests (`T_PERCPU_STATS_SUM`, `T_EXPORTER_VALUES_MATCH_STATS`, `T_RULE_COUNTER_*`, `T_EXPORTER_NO_ATTACHED_IFACE`) cover B2/B4/C1 end-to-end; the `T_*_ORACLE_AGREEMENT` family + `T_ANDV6_PREFIX_CLOSURE_OVERLAP` (the /40-/68-/127 cover canary) cover B5's map-population. Confirm the full ctest baseline is unchanged (104/106; the 2 known env-fails by NAME).
- **Reviewer**: 5-point brownfield. Special attention: (a) each subtraction is behavior-preserving (compiler/linker for B4 dead-code; exporter ctests for B2/C1; ORACLE_AGREEMENT for B5); (b) the C1 §5.31 reversal is DOCUMENTED, not silent (the anti-extraction comment must be removed/replaced with a reversal note, not just deleted); (c) B5 keeps `close_prefixes`/`close_prefixes6` as separate args (guard #23 surface intact); (d) PI-7 loader.hpp/config.hpp ∅; (e) no datapath `.bpf.c` change (xdp 3437 unchanged).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.31-1: shared exporter-helper home → **default = NEW `src/exporter/percpu_read.hpp` (or equivalent), included from both readers**
**CORRECTION to the verdict (Phase 2, guard #5):** the verdict claimed `rule_counters_reader.hpp` "already #includes `stats_reader.hpp`, so no new include required" — this is FALSE. `rule_counters_reader.cpp` does NOT include `stats_reader.hpp` (grep-confirmed; the `.hpp:3` mention is a prose comment "Sister to stats_reader.hpp", not an `#include`). So a shared home needs EITHER a new small header (`percpu_read.hpp`, namespace `xdpmf::exporter::detail`, holding `round_up_8`+`percpu_sum_u64`+`list_iface_dirs`) + 2 `#include`s, OR homing in `stats_reader.hpp` + adding 1 `#include` to `rule_counters_reader.cpp`. Either is still net-negative (~−18 LOC for B2 alone, ~−40 incl. C1). Default: NEW `percpu_read.hpp` (cleanest — neither reader is "primary"). Architect picks.

### HG-mvp-4.31-2: C1 §5.31 reversal → **default = REVERSE explicitly, documented**
The `list_iface_dirs` extraction reverses the `rule_counters_reader.cpp:62-64` "deliberately duplicated … §5.31 keeps the two readers byte-equivalent" decision. Default: do it, and record the reversal in §5.71 (cite the §5.31 rationale verbatim, state why a single shared def serves the byte-equivalence goal BETTER — equivalent by construction) + remove/replace the anti-extraction comment with a one-line "extracted in §5.71, reverses §5.31" note. Per [[impl-role-discipline]] / the B37 precedent (which reversed D-mvp-4.23). If the architect judges the §5.31 intent still load-bearing (e.g. a reason the comment doesn't state), DROP C1 and keep `list_iface_dirs` duplicated — B2/B4/B5 are independent and ship regardless.

### HG-mvp-4.31-3: VERSION bump → **default = NO bump**
Pure internal subtraction — no operator-facing API/schema/metric/CLI change. VERSION stays 0.16.0.

## Open mechanism questions (architect decides; document in §5.71)

### Q1: B5 template parameterization shape
- **A1**: `template<class Key>` param = key type (`xdpmf_cidr_v4`/`xdpmf_cidr_v6`) + prefix-vec type (`BitPrefix`/`BitPrefix6`) + close-fn (`close_prefixes`/`close_prefixes6`) passed as args — mirrors `populate_hash_inner_slot<Key>`.
- **A2**: leave the fork (do NOT merge) if the type divergence (`BitPrefix` vs `BitPrefix6`, `std::uint64_t` vs `__int128` masks live in the close fns) makes the template signature uglier than the saved LOC.
- **Recommendation**: **A1** (house-style precedent exists; the close fns stay separate args so guard #23 is untouched). Architect downgrades to A2 only if the signature exceeds the ~−38 LOC saving.

## Scope (cycle MVP-4.31 — concrete items; UPPER-BOUND estimates)

### Item B38-1 — delete dead `read_all_attached` trampoline (B4)
**Where**: `src/exporter/stats_reader.cpp` (def, ~`:140-148`), `src/exporter/stats_reader.hpp` (decl, ~`:69` + the 2 stale doc-comments ~`:15`,`:38`,`:75`). ~−12 LOC. Oracle: linker (no callers) + `T_EXPORTER_*` (only the `_with_acc` path via `http.cpp`).

### Item B38-2 — extract `round_up_8` + `percpu_sum_u64` to shared header (B2)
**Where**: NEW shared home per HG-1; delete copies from `src/exporter/rule_counters_reader.cpp` (~`:56-59`,`:102-121`); keep one definition. ~−18 LOC net.

### Item B38-3 — extract `list_iface_dirs` to the same shared home (C1, conscious §5.31 reversal)
**Where**: same shared home; delete copies from both readers (~`stats_reader.cpp:54-80` / `rule_counters_reader.cpp:65-91`); remove/replace the §5.31 anti-extraction comment (`rule_counters_reader.cpp:62-64`). ~−21 LOC net. **Gated by HG-2** — drop if architect judges §5.31 still load-bearing.

### Item B38-4 — template-merge `populate_bitvec_inner_slot` v4/v6 (B5)
**Where**: `src/lib/loader.cpp` (`populate_bitvec_inner_slot` ~`:1538` + `populate_bitvec6_inner_slot`), call sites uniform. ~−38 LOC. `close_prefixes`/`close_prefixes6` stay SEPARATE args (guard #23). Oracle: `T_*_ORACLE_AGREEMENT` + `T_ANDV6_PREFIX_CLOSURE_OVERLAP`.

## Out of scope (explicit)

- **Any behavior/verdict change** — all four are pure representation/dead-code subtractions; every existing ctest (esp. ORACLE_AGREEMENT + exporter) keeps its result.
- **The datapath `.bpf.c`** — untouched; xdp stays 3437 (B5 is the userspace loader, not the BPF program).
- **`close_prefixes`/`close_prefixes6` merge** — the FORK is a protected rent-payer (guard #23, PI-mvp-4.13); B5 merges only the populate WRAPPER, keeping the close fns separate.
- **The confirmed-KEEP rent-payers** from the verdict: 3 family arms + per-arm `wc_*`/acc asymmetry, `BitPrefix`/`AxisLowering` v4/v6 forks, `parse_prefix`/`parse_prefix6`, FFS_FALLBACK + inline ETH_P/IPPROTO shims, `consume_flag_value` (exit-vs-throw divergence), design-brief corpus + perf-scratch + task-brief chain + hybrid-review (all have live consumers). Do NOT touch.
- **B6** (collapse BACKLOG B1-B14 verbose bodies) — doc-only, deferred (marginal; interleaved with open items). Not this slice.
- **Schema / axis / VERSION change** — none.

## Definition of done

- §5.71 amendment in design.md (the 4 subtractions + the C1 §5.31-reversal record + B5 template decision).
- PI-7 continues (loader.hpp/config.hpp ∅). No datapath change (xdp 3437). No new behaviour.
- Full ctest baseline preserved (104/106; 2 known env-fails by NAME; ORACLE_AGREEMENT + exporter all green).
- No VERSION bump (HG-3).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies

- Build: clang++-19 / cmake (existing). Userspace + loader rebuild; no BPF datapath recompile needed for B2/B4/C1 (B5 rebuilds loader, datapath `.bpf.o` unchanged).
- Runtime / kernel: none new.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  [lang/cpp.md, lang/bpf.md]     # C++ exporter/loader + BPF map-ABI context for B5
  impl:       [lang/cpp.md, lang/bpf.md]
  tester:     [test/bpf-xdp.md]              # ORACLE_AGREEMENT (B5) + exporter ctests are the regression control
  reviewer:   [test/bpf-xdp.md]
```

---

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])

**Mechanical / single-architect → `/mint-dev`, NOT `/mint-hld`.** Four small independent subtractions, each with an existing oracle (exporter ctests for B2/B4/C1, ORACLE_AGREEMENT + prefix-closure canary for B5). No design SPACE to explore — the verdict + defense already settled what/how; the only judgment calls are the shared-header home (HG-1, derivable) and the C1 §5.31-reversal record (HG-2, a documented-decision-reversal, not a fork). B5 is provenance-safe (guard #23 in the close fns, kept separate). No PRESERVE/RESET axis (no map-shape change). No PO-tier decision (all engineering, external value = entropy reduction + maintenance-coupling removal).

## Notes for architect Phase A code-grep discipline (per architect spec rules)

- `grep -rnE 'read_all_attached\b' src/ tests/ | grep -v _with_acc` → only the def (`stats_reader.cpp:140`) + decl (`.hpp:69`) + 3 doc-comments; ZERO live callers (B4 dead). `http.cpp` uses `_with_acc`.
- `grep -nE 'round_up_8|percpu_sum_u64|list_iface_dirs' src/exporter/{stats_reader,rule_counters_reader}.cpp` → all three defined in BOTH readers. Verify body-identity yourself (guard #5): `round_up_8` char-identical; `percpu_sum_u64` modulo param name (`stats_fd`/`map_fd`); `list_iface_dirs` md5-identical.
- **§5.31 note covers ONLY `list_iface_dirs`** (`rule_counters_reader.cpp:62-64`) — confirm `round_up_8`/`percpu_sum_u64` carry NO such provenance (they don't → B2 is clean, no reversal needed; only C1 reverses §5.31).
- **Include reality (Phase-2 correction):** NO file includes `stats_reader.hpp` from the rule_counters side; a shared home needs a new include/header (HG-1). The verdict's "already includes" claim is refuted.
- `grep -nE 'populate_bitvec_inner_slot|populate_bitvec6_inner_slot|populate_hash_inner_slot|close_prefixes' src/lib/loader.cpp` → fork at `:1538`/`_v6`, house-style template at `:1492`, guard #23 lives in `close_prefixes` (`:1191`)/`close_prefixes6` (`:1327`) — NOT the wrapper.
- All anon-namespace / TU-local (no ODR hazard for the exporter extractions); error strings NOT test-pinned (grep tests/ for them = ∅ before assuming).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep)** — always; re-verify the body-identity diffs + the include reality (the verdict's "already includes stats_reader.hpp" was wrong).
- **Guard #9 (helper-location duplication-over-extraction)** — this slice INTENTIONALLY reverses the duplication for B2/C1. #9's caution (don't pull stable files into the edit surface) is acknowledged: the exporter readers ARE the edit surface here by design, and the §5.31 reversal (C1) is documented per HG-2. The shared header is the minimal new surface.
- **Guard #23 (#1 bit-vector bug class — cover-direction)** — B5 must keep `close_prefixes`/`close_prefixes6` as separate args to the merged template; the audited surface stays eyeball-auditable. Do NOT merge the close fns.
- **Guard #12 (RESOURCE_LOCK)** — applies only if a new ctest touches shared host state; this slice adds NO new ctest (existing oracles are the control).
- **Guard #16 (retired pin-path/map-name ripple)** — N/A (no map name retired; B5 is a wrapper merge, same maps; the exporter extractions touch no pin name).

### Evidence footer — brief-author Phase 2 grep verification

```
File/path:
  ✓ src/exporter/stats_reader.cpp/.hpp          read_all_attached(sv) def :140 + decl :69, ZERO non-_with_acc callers (B4 dead)
  ✓ src/exporter/rule_counters_reader.cpp       round_up_8/percpu_sum_u64/list_iface_dirs all dup'd
  ✓ §5.31 note                                  rule_counters_reader.cpp:63-64, covers ONLY list_iface_dirs (C1 target)
  ✓ src/lib/loader.cpp                          populate_bitvec_inner_slot :1538 + _v6; house-style populate_hash_inner_slot<Key> :1492; close_prefixes :1191 / close_prefixes6 :1327 (guard #23 home)
  ✗ "rule_counters_reader.hpp already #includes stats_reader.hpp"  → FALSE (only a prose comment); shared home needs a new include/header (HG-1)

Estimate corrections vs verdict:
  • "no new include needed" → REFUTED: rule_counters_reader.cpp does not include stats_reader.hpp → new header (percpu_read.hpp) or +1 include required (still net-negative).
  • Net LOC: B4 ~−12, B2 ~−18, C1 ~−21, B5 ~−38 → ~−89 gross / ~−70 net after the shared-header scaffold (~+6).

Surprising findings:
  • C1 (list_iface_dirs) is the ONLY extraction that touches a documented decision (§5.31) → gated HG-2 (drop if architect judges §5.31 still load-bearing; B2/B4/B5 independent).
  • B5 is the only loader/datapath-adjacent item; verdict-identity-gated via ORACLE_AGREEMENT (userspace map-population, no .bpf.c change).
```
