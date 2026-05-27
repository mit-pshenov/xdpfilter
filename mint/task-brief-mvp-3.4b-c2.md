# Task brief — MVP-3.4b cycle 2: `rules` atomic-swap promotion + datapath dispatch (brownfield, datapath + loader)

## Goal

Ship the **datapath-consultation half** of the per-rule action machinery deferred from MVP-3.4 (Open Q #13 RESOLUTION Option 2) + MVP-3.4b cycle 1. Concretely two coupled deliverables:

1. **`rules` map atomic-swap promotion** — promote the currently-SHARED `rules` ARRAY (declared at `src/bpf/mac_filter.bpf.c:172-178`) to parallel `rules_outer` ARRAY_OF_MAPS[2] of `rules_a` / `rules_b` inner ARRAYs, mirroring the §5.27 CIDR-axis pattern. Single `active_idx` flip swaps MAC inner + CIDR inner + defaults + rules atomically in one syscall. Closes D-3.4-4 carry-over.

2. **Datapath consultation + action dispatch** — `mac_filter_prog` extends both the MAC-HASH-hit branch AND the CIDR-LPM_TRIE-hit branch to read `rules[entry->rule_id]` → look up `action_table[rule.action_id]` → dispatch `XDP_PASS` or `XDP_DROP` based on `action_type`. Drop rules become **operative**: a `match.mac: X` + `action: drop` rule now drops X explicitly via the action_table path, rather than via the current indirect "X-not-in-allowlist → defaults[active]=drop fallthrough" mechanism. This requires the **schema cycle 2 → cycle 3 shift**: drop rules NOW populate the inner-allowlist (with their `rule_id`), so datapath can reach the rules-lookup step.

Reset-counters subcommand + rule_counter atomic-swap are explicitly **NOT** in this slice (carried to a separate small follow-up; brief author's scope decision, confirmed inline 2026-05-26).

## Context: prior work

- All prior briefs archived in `mint/task-brief-*.md`. Most recent ancestor of this slice: `mint/task-brief-mvp-3.4b.md` (cycle 1 — per-rule counters + inner-allowlist-value extension + datapath wiring of `bump_rule`).
- Existing design: `mint/design.md` §5.31 (MVP-3.4b cycle 1) — load-bearing PI-13-3.4b inner-VALUE extension; PI-28-3.4b + PI-29-3.4b carve-outs THAT THIS SLICE EXPLICITLY LIFTS.
- Architecture doc: `mint/architecture-v2.md` §"§MVP-3.4 Open Question #13 RESOLUTION" Option 2 + Caveat (b) — the cycle-1+2+3 phasing was pre-decided here; cycle 2 = atomic-swap promotion; cycle 3 (this slice's secondary deliverable) = action_table dispatch. Brief author's scope decision (2026-05-26) merges them since atomic-swap is meaningless without datapath consultation.
- Phase A code-grep verification: brief author ran the following before this brief was published — `grep -nE "rules|action_table" src/bpf/mac_filter.bpf.c`; `grep -nE "XDPMF_MAP_RULES_NAME|struct rule_entry|ACTION_PASS|ACTION_DROP" src/common/mac_filter.h`; `grep -nE "kManagedMaps|populate_rules_skeleton|populate_action_table|apply_request" src/lib/loader.cpp`; `grep -nE "struct Rule|RuleAction" src/lib/config.hpp`; `ls tests/T_RULES* tests/T_DROP_RULE* tests/T_RULE_COUNTER*`; `ctest -N | wc -l`. See "Phase 2 grep verification report" in conversation log for full output. Notable findings: `Config::Rule::action` already exists at `config.hpp:43` (brief does NOT propose adding); `kManagedMaps[]` is at 13 entries (12 non-alias + 1 alias) AFTER cycle 1; `populate_rules_skeleton(int rules_fd, …)` signature at `loader.cpp:1231` MUST change.
- PI continuity: PI-1..PI-26, PI-30..PI-34 preserved unchanged. PI-27 (inner-VALUE offset-0 byte-equivalence) preserved per §5.31. PI-13-3.4b adjudication preserved. **PI-28-3.4b LIFTED** (mac_filter_prog body extends with 2 new map lookups after inner-hit). **PI-29-3.4b LIFTED** (rules consulted; action_table consulted). New PIs needed: PI-29-3.4b-c2 (rules+action_table consulted + action_table dispatch contract), PI-13-3.4b-c2 (rules atomic-swap via active_idx flip — symmetric with §5.27 Q1 AS1 CIDR pattern). PI-7-3.4b-c2-hpp = **9th consecutive ZERO-diff cycle on loader.hpp**; PI-7-3.4b-c2-cpp = **4th consecutive ZERO-diff cycle on config.hpp**.

## Workflow rules (brownfield)

- **Architect**: read §5.26 (Q1 AS1 + Q2 A1 atomic-swap mechanism — the parent-pattern), §5.27 (CIDR axis precedent — direct mirror for `rules` axis), §5.29 (rules+action_table SKELETON + defer rationale — the contract being lifted), §5.31 (cycle 1 PI-13/28/29-3.4b — direct ancestor); EDIT `design.md` in place; append §5.34 (or §5.31 EDIT-3 — architect picks shape) covering the atomic-swap promotion + datapath dispatch + schema shift. Anti-misdiagnosis guards #5, #7, #10, #11, #12 from §7 OOS catalogue APPLY (see footer).
- **Impl**: FileList rows interpreted as the **regional-diff fence**. Brownfield: only the listed scopes within each EDITED file are touched; everything else byte-equivalent. NEW files created at the listed paths. PI-7-3.4b-c2-hpp/cpp = ZERO-diff on loader.hpp + config.hpp (architect surfaces only if a constraint forces a diff; otherwise verbatim preservation). [[impl-role-discipline]] holds — silent deviation forbidden; escalate via Phase B SendMessage if a constraint forces departure.
- **Tester**: NEW ctests target 3-4 (see Scope). EDITED ctests = up to 4 with carve-out (see Scope Item E-1 + E-2). Brief estimate is upper bound — Phase A grep will refine.
- **Reviewer**: 5-point brownfield framework (Spec ↔ Code, Spec ↔ Tests, Code ↔ Tests, OOS Drift, §6.5 PI preservation). Special attention items: (a) the schema-shift HG-3.4b-c2-2 is explicit-by-design and not OOS drift — reviewer dispositions any reviewer-flagged "drop-rule now appears in inner-allowlist" as `inline-merge` per HG-3.4b-c2-2; (b) the PI-28-3.4b + PI-29-3.4b LIFTs MUST be explicitly named in design.md — reviewer treats silent retire as `[CONTRACT-DRIFT]`.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-3.4b-c2-1: `rules` map promotion shape → **PARALLEL via `rules_outer` ARRAY_OF_MAPS[2] of `rules_a` / `rules_b` inner ARRAYs**

Direct mirror of §5.27 Q1 AS1 (CIDR axis) shape: outer ARRAY_OF_MAPS[2] indexed by `active_idx`; inner ARRAY[XDPMF_ALLOWLIST_MAX=64] of `struct rule_entry`. The §5.27 precedent is the load-bearing pattern; architect-override candidates (e.g. INNER HASH_OF_MAPS, or shared-with-rcu) are not motivated by any operator constraint and would diverge from the established CIDR-axis idiom.

### HG-3.4b-c2-2: Schema cycle 2 → cycle 3 semantic shift → **DROP RULES NOW POPULATE INNER-ALLOWLIST**

The §5.26 schema cycle 2 contract ("drop rules do NOT populate the inner allowlist") is **explicitly amended** by this slice. Post-cycle-2: drop rules with `match.mac: X` (or `match.cidr`) populate the inner-allowlist with `{present=1, rule_id=<X's rule.id>}`. Datapath reaches the entry → looks up `rules[rule_id]` → action=DROP → `XDP_DROP` + `bump_stat(STAT_DROP_DENY)` + `bump_rule(rule_id)`. Operator mental model becomes: "every rule that matches a frame contributes per-rule counter; action is explicit via the rule's `action:` field; the default-drop fallback only catches frames matching NO rule".

This must be documented in the new design.md amendment section as a **new PI** ("PI-30-3.4b-c2-schema" or architect-named), with the prior §5.26 contract explicitly cited as superseded. Silent retire = `[CONTRACT-DRIFT]` per reviewer.

### HG-3.4b-c2-3: `action_table` map shape → **STAYS SHARED ARRAY (no promotion to parallel)**

`action_table` contains static `{PASS, DROP}` entries written once at apply (via `populate_action_table` at `loader.cpp:1263`); these values do NOT mutate across applies. Atomic-swap is not motivated. If MVP-3.8+ adds mutable action types (MIRROR / RL / TAG with per-config parameters), action_table promotion is the natural next step — surfaced as new OOS fence.

### HG-3.4b-c2-4: Datapath dispatch order → **inner-hit → `rules[entry->rule_id]` → `action_table[rule.action_id]` → action_type → XDP_PASS / XDP_DROP**

Symmetric across MAC HASH and CIDR LPM_TRIE branches in `mac_filter_prog`. Miss-on-both-axes still falls through to `defaults[active]` (UNCHANGED — that's the default-action contract from §5.26 Q2-extension; this slice does not touch defaults semantics).

Pseudocode (impl-shape — architect picks exact C-level shape):
```
MAC HASH hit branch (replaces current §5.31 lines 270-275):
  struct allow_entry *entry = bpf_map_lookup_elem(inner, &key);
  if (entry) {
      bump_rule(entry->rule_id);
      __u32 rid = entry->rule_id;
      void *rules_inner = bpf_map_lookup_elem(&rules_outer, &active);  // NEW
      if (rules_inner) {
          struct rule_entry *r = bpf_map_lookup_elem(rules_inner, &rid);  // NEW
          if (r && r->present) {
              __u32 aid = r->action_id;
              struct action_entry *a = bpf_map_lookup_elem(&action_table, &aid);  // NEW
              if (a) {
                  if (a->action_type == ACTION_DROP) {
                      bump_stat(STAT_DROP_DENY);
                      return XDP_DROP;
                  }
              }
          }
      }
      bump_stat(STAT_PASS);
      return XDP_PASS;
  }
  // CIDR symmetric — same pattern, cidr_inner / cidr_hit, returns XDP_DROP or XDP_PASS_CIDR.
```

Verifier acceptance: 3 additional `bpf_map_lookup_elem` calls per match (rules_outer / rules_inner / action_table). Verifier-precedent from cycle 1 (`bump_rule` added similar inner-lookup) suggests no turbulence. If verifier rejects: impl peer-DMs architect (Phase B SendMessage per [[impl-role-discipline]]); fallback is a flattened helper that pre-loads action_type into a stack local from rules_inner lookup.

### HG-3.4b-c2-5: `rule_counters` bump policy at explicit-rule-DROP → **STILL BUMP**

A rule MATCHED a frame; the per-rule counter increments regardless of whether the resulting action is PASS or DROP. Distinction surfaced via the existing `xdpfilter_rule_match_total{rule_id="<N>", action="drop"}` label (cycle 1's A3 — action-as-label). The global `xdpfilter_packets_total{verdict="drop"}` (STAT_DROP_DENY) now sums explicit-rule-drops AND default-drop fallthroughs (the per-rule series disambiguates).

## Open mechanism questions (architect decides; document in §<new>)

### Q1: NEW STAT bucket for explicit-rule-DROP?

- **Q1.A**: Add `STAT_DROP_RULE` to `enum xdpmf_stat` (currently STAT_PASS=0, STAT_PASS_CIDR, STAT_DROP_DENY, STAT_DROP_MALFORMED → STAT_MAX=4); becomes STAT_MAX=5; new Prometheus series `xdpfilter_packets_total{verdict="rule_drop"}`. Operator gains direct visibility into "drops caused by explicit rules" vs "drops caused by default-deny fallthrough".
- **Q1.B**: Re-use `STAT_DROP_DENY` for both explicit-rule-drops AND default-deny-fallthrough; per-rule visibility comes only via `xdpfilter_rule_match_total{action="drop"}` (already exists from cycle 1).
- **Recommendation: Q1.B** — minimizes invariant-surface diff (`enum xdpmf_stat` byte-equivalent → `STAT_MAX=4` unchanged → PI-26-ish territory preserved); operator can still derive explicit-drop count via `sum(xdpfilter_rule_match_total{action="drop"}) by (iface)`. Q1.A is the natural future extension if operators ask for direct verdict-label.

### Q2: `T_RULES_SKELETON_NOT_WIRED.sh` disposition

The test (declared at `tests/CMakeLists.txt:573`, body at `tests/T_RULES_SKELETON_NOT_WIRED.sh`) tests the contract that this slice is **explicitly retiring** (rules+action_table NOT consulted by datapath). After this slice the test's contract no longer exists.

- **Q2.A**: DELETE the test (and its CMakeLists.txt entry). Net ctest count delta: -1.
- **Q2.B**: REPURPOSE → rename to `T_RULES_NOW_WIRED.sh` (or similar) with inverse semantics (verify datapath DOES consult rules + action_table on every match).
- **Q2.C**: STRIP-AND-RENAME → rename + replace body wholesale.
- **Recommendation: Q2.A** (clean delete). The NEW ctests `T_DROP_RULE_OPERATIVE.sh` + `T_RULES_ATOMIC_SWAP_NO_DROP.sh` cover the new contract. Q2.B/C add naming churn without semantic value.

### Q3: `T_DROP_RULE_BUMPS_COUNTER.sh` disposition

The test (declared at `tests/CMakeLists.txt:688`, body at `tests/T_DROP_RULE_BUMPS_COUNTER.sh`) currently verifies that a drop-rule's MAC does NOT enter the inner-allowlist and the per-rule counter STAYS 0 (the §5.26 schema cycle 2 contract that this slice's HG-3.4b-c2-2 amends).

- **Q3.A**: REWRITE body in-place → drop-rule's MAC NOW enters inner-allowlist + per-rule counter BUMPS + verdict is XDP_DROP via action_table.
- **Q3.B**: DELETE + replace with new test under different name.
- **Recommendation: Q3.A** (rewrite — keeps slot in catalogue; cheaper than delete+add+update).

### Q4: `defaults` map semantics post-shift

- **Q4.A**: `defaults[active]` UNCHANGED — still consulted on miss-both-axes (frames matching NO rule). PRESERVED across applies via existing parallel-swap.
- **Q4.B**: Retire `defaults` map — all dispatch via rules; require every operator to declare a catch-all rule.
- **Recommendation: Q4.A** — `defaults` keeps its current responsibility (fallback for unmatched frames). Q4.B is breaking-config-change, no operator demand.

## Scope (cycle 2 — concrete items)

### Item D-1 — BPF: `rules` map promotion to parallel ARRAY_OF_MAPS
**Where**: `src/bpf/mac_filter.bpf.c`

- Replace SHARED `rules` ARRAY (lines 172-178) with: `rules_outer` ARRAY_OF_MAPS[2] outer (template + `__inner_map = rules_inner_a`) + `rules_a` + `rules_b` inner ARRAYs (each ARRAY[XDPMF_ALLOWLIST_MAX=64] of `struct rule_entry`, both `LIBBPF_PIN_BY_NAME`).
- Update the SEC(".maps") declarations + the inner-template trick zero-call patterns to match §5.27 CIDR-axis precedent.
- `action_table` declaration UNCHANGED.
- `rule_counters` declaration UNCHANGED.

### Item D-2 — BPF: `mac_filter_prog` datapath dispatch
**Where**: `src/bpf/mac_filter.bpf.c:230+` (function body)

- MAC-HASH-hit branch (current §5.31 lines 270-275): after `bump_rule(entry->rule_id)`, consult `rules_outer` → `rules_inner` → `action_table` per HG-3.4b-c2-4. Dispatch `XDP_PASS` (action_type=PASS) or `XDP_DROP` (action_type=DROP).
- CIDR-LPM_TRIE-hit branch (current §5.31 lines 302-307): symmetric.
- All miss-paths (defaults[active] fallthrough at lines 312+) UNCHANGED.

### Item L-1 — Loader: `kManagedMaps[]` table update
**Where**: `src/lib/loader.cpp:147-167`

- REMOVE entry for `rules` (current line 157) — the old SHARED `rules` map disappears.
- ADD entries for `rules_outer` + `rules_a` + `rules_b` (impl picks placement; suggest alphabetical near `rulesets` group).
- New table count: 13 → 15 entries (12 → 14 non-alias; alias `allowlist` preserved at line 166).
- Comment count update: "13th entry" → "14th + 15th entries" (architect rewrites the surrounding comment).

### Item L-2 — Loader: `populate_rules_skeleton` signature change + parallel-axis logic
**Where**: `src/lib/loader.cpp:1231-1258` + call sites at lines 1785 + 1915 in `apply_request`

- Signature change: `populate_rules_skeleton(int rules_fd, ...)` → `populate_rules_inner_slot(int rules_inner_fd, const std::vector<Rule>& rules)` (similar shape to existing `populate_inner_slot` for MAC axis). Caller invokes against the **inactive** inner slot before active_idx flip.
- Apply orchestration step in `apply_request` body: populate `rules_<inactive>` BEFORE the existing active_idx flip (which now atomically commits MAC + CIDR + defaults + rules).
- `populate_action_table` UNCHANGED (action_table stays SHARED).

### Item L-3 — Loader: inner-allowlist population semantic shift (drop rules in)
**Where**: `src/lib/loader.cpp` `apply_request` rule-extraction step (~line 1745 — feeds `populate_inner_slot` for MAC axis + `populate_cidr_inner_slot` for CIDR axis with deduped MAC / CIDR vectors)

- Currently: rule-extraction step filters to `rule.action == RuleAction::Pass` only (drop rules excluded per §5.26 schema cycle 2 contract).
- Post-shift: filter ALSO includes `rule.action == RuleAction::Drop` rules — they populate inner-allowlist with their `rule_id`, datapath later dispatches via action_table.
- Architect documents exact filter expression in D-3.4b-c2-* decision.

### Item L-4 — Shared header: NEW map name constants
**Where**: `src/common/mac_filter.h`

- ADD `XDPMF_MAP_RULES_OUTER_NAME = "rules_outer"`, `XDPMF_MAP_RULES_INNER_A_NAME = "rules_a"`, `XDPMF_MAP_RULES_INNER_B_NAME = "rules_b"`.
- DELETE `XDPMF_MAP_RULES_NAME = "rules"` (line 125) — the SHARED-ARRAY pin disappears.
- `XDPMF_MAP_ACTION_TABLE_NAME` UNCHANGED.
- `struct rule_entry` + `struct action_entry` + enum UNCHANGED.

### Item T-1 — NEW ctest: `T_DROP_RULE_OPERATIVE.sh` (§6.NN)
**Where**: `tests/T_DROP_RULE_OPERATIVE.sh` + entry in `tests/CMakeLists.txt`

- Apply config with explicit drop rule (`action: drop, match.mac: X`).
- Inject 5 frames with source MAC X.
- Assert: `xdpfilter_packets_total{verdict="drop"}` increments by 5 (STAT_DROP_DENY); `xdpfilter_rule_match_total{rule_id="<X's id>", action="drop"}` increments by 5; XDP_DROP verdict observed.
- Negation: PASS rule with different MAC Y → 5 frames with MAC Y → `xdpfilter_packets_total{verdict="pass"}` increments; rule_id Y's drop-action label is NOT observed.
- RESOURCE_LOCK: `xdp_fixture` (touches veth) per anti-misdiagnosis guard #12.

### Item T-2 — NEW ctest: `T_RULES_ATOMIC_SWAP_NO_DROP.sh` (§6.NN+1)
**Where**: `tests/T_RULES_ATOMIC_SWAP_NO_DROP.sh` + CMakeLists entry

- Apply config A; in parallel, inject frames matching multiple rules across both axes (MAC + CIDR); during traffic, apply config B (different rule set, different action assignments).
- Assert: `drop_delta == 0` for frames that were-passing-by-config-A under config-A's view; `pass_delta == 0` for frames that were-dropping-by-config-A under config-A's view; in other words, no in-flight frame sees a half-applied rules+actions state.
- LOAD-BEARING for the atomic-swap promotion of `rules` (PI-13-3.4b-c2 or whatever the architect names).
- Template: `tests/T_APPLY_ATOMIC_SWAP_NO_DROP.sh` (§6.23 MAC-axis) + `tests/T_CIDR_ATOMIC_SWAP_NO_DROP.sh` (§6.31 CIDR-axis).
- RESOURCE_LOCK: `xdp_fixture`.

### Item T-3 — NEW ctest: `T_RULES_AXIS_FLIPS_WITH_ACTIVE_IDX.sh` (§6.NN+2)
**Where**: `tests/T_RULES_AXIS_FLIPS_WITH_ACTIVE_IDX.sh` + CMakeLists entry

- Apply config; read `bpftool map dump pinned ${PIN_DIR}/active_idx` (= 0 or 1); read corresponding `rules_<active>` slot (`rules_a` or `rules_b`) → matches applied rules.
- Apply again (different config); active_idx flips; new `rules_<active>` matches new config; OLD inner slot preserved (one-deep rollback history per §5.26 atomic-swap contract).
- RESOURCE_LOCK: `xdp_fixture`.

### Item E-1 — EDITED: `T_DROP_RULE_BUMPS_COUNTER.sh` body rewrite (Q3.A)
**Where**: `tests/T_DROP_RULE_BUMPS_COUNTER.sh`

- Per Q3.A recommendation: drop-rule's MAC NOW enters inner-allowlist; per-rule counter BUMPS; verdict is XDP_DROP via action_table (was previously: MAC absent from inner-allowlist, counter stays 0, drop via defaults fallthrough).
- Test name kept; body rewrite ~30-50 LOC.
- PI-3.4b-c2-* carve-out: explicit semantic-change EDIT (per HG-3.4b-c2-2).

### Item E-2 — DELETED: `T_RULES_SKELETON_NOT_WIRED.sh` (Q2.A)
**Where**: `tests/T_RULES_SKELETON_NOT_WIRED.sh` + `tests/CMakeLists.txt:573` entry

- Contract this test asserts no longer exists post-cycle-2; test deleted; CMakeLists entry removed.
- ctest count delta: -1 from this deletion; +3 from NEW T-1..T-3; net **ctest count: 58 → 60**.

### Item V-1 — EDITED: version bump
**Where**: `CMakeLists.txt:18`

- `VERSION 0.8.0` → `VERSION 0.9.0`. Datapath dispatch is operator-observable behavioural change (drop rules now operative explicitly); minor bump justified.
- Phase A architect MUST: `grep -rln '0\.8\.0' tests/` AND for each hit, pre-list affected test bodies in EDITED FileList row + carve-out PI-6 (anti-misdiagnosis guard #11).

### Item V-2 — EDITED: `CHANGELOG.md`
**Where**: `CHANGELOG.md`

- New `## [0.9.0] - 2026-05-NN` section. Documents (a) rules map atomic-swap promotion; (b) datapath dispatch via rules+action_table; (c) drop rules now operative (schema shift); (d) one-line note that `reset-counters` subcommand was scoped-out to follow-up slice.
- Build-pace table row update.

## Out of scope (explicit)

Carry-forward unchanged from §5.31 §7 OOS unless noted. NEW fences this slice:

- **`reset-counters` subcommand** — split out of this slice per brief-author decision 2026-05-26. Follow-up slice (working name `MVP-3.4d` — final name architect's call).
- **`rule_counters` atomic-swap** — same follow-up; cycle 2 preserves cycle 1's PI-3.4b-2 (counter-monotonicity across apply).
- **`action_table` promotion to parallel** — not motivated by cycle 2 (action_table contents static); becomes motivated if MVP-3.8+ adds mutable action types.
- **Action types beyond `{PASS, DROP}`** — carry-forward (MVP-3.8+).
- **`xdpfilter_packets_total{verdict="rule_drop"}` separate verdict bucket (Q1.A)** — Q1.B picked; future-cycle if operator demand surfaces.
- **`defaults` map retirement (Q4.B)** — Q4.A picked; defaults stays for unmatched-frame fallback.
- **Documentation pass** (FLEET_DEPLOYMENT.md exporter section; CHANGELOG migration-notes for the schema shift in cycle-2-savvy operator language) — separate manual doc pass per user direction (Doc bucket carry-forward from MVP-3.4.5).

## Definition of done

- §5.34 amendment (or §5.31 EDIT-3 — architect picks) in `design.md` covering: atomic-swap promotion shape; datapath dispatch contract; schema shift (HG-3.4b-c2-2 explicit); PI-28-3.4b + PI-29-3.4b explicit LIFT statements; new PI-29-3.4b-c2 + PI-13-3.4b-c2 + (architect-named) schema PI.
- PI continuation: PI-1..PI-26, PI-30..PI-34 preserved; PI-27 + PI-13-3.4b preserved; PI-7-3.4b-c2-hpp/cpp ZERO-diff (9th/4th consecutive).
- ctest baseline 58 → **60** (+3 NEW T-1..T-3; -1 DELETED E-2; +1 EDITED E-1).
- VERSION bumped 0.8.0 → 0.9.0; all test-body version literals follow per Phase A grep.
- `mint/review.md` round-1 verdict = pass (5-point brownfield).
- One git commit per phase boundary (design, impl+tests, review).

## Dependencies

- Build: libbpf 1.x (no new dep this slice).
- Runtime: kernel BPF support for ARRAY_OF_MAPS (kernel 5.x+ — already required by §5.27 CIDR axis).
- Platform: bpffs mounted; existing trust_model contract (`XDPMF_TRUST_MODEL=strict|trusted`).
- No new caps required (existing `CAP_BPF + CAP_NET_ADMIN` for loader; `CAP_BPF` for exporter).

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       []
  tester:     []
  reviewer:   []
```

(No language/platform packs needed — established 16-cycle precedent for this project is sufficient.)

---

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])

- Slice goal stated in one sentence: ✓ (atomic-swap promotion of `rules` + datapath dispatch via rules+action_table + schema cycle 2 → 3 shift).
- Multi-axis design space? — Brief author and user **resolved inline** 2026-05-26: scope chosen = "medium" (atomic-swap + datapath dispatch combined, reset-counters split out). Resolution rationale: atomic-swap meaningless without consultation → must combine; reset-counters orthogonal utility command → defer. `/mint-hld` overkill per [[mint-hld-scope-discipline]] (mechanical answer fell out of stated constraints once user picked between 4 enumerated options).
- Mechanical-answer check: ✓ — atomic-swap shape mirrors §5.27 CIDR-axis precedent verbatim; datapath dispatch follows verifier-safe pattern from cycle 1 `bump_rule`; schema shift is forced by the consultation-step requirement.
- Brief author overconfidence check: ⚠ — first dogfood of `/mint-briefer` skill. Phase 2 grep ran cleanly; one minor surprise found (kManagedMaps[] is at 13 entries with 12 non-alias, slight bookkeeping nuance — incorporated into Item L-1 above).

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief author already ran Phase 2 greps (see "Phase 2 grep verification report" in conversation log). Architect re-verifies INDEPENDENTLY + extends:

```bash
# Verify current rules+action_table+rule_counters declarations
grep -nE "rules|action_table|rule_counters" src/bpf/mac_filter.bpf.c | head -50

# Verify kManagedMaps[] count + contents (table starts at line 147)
sed -n '145,170p' src/lib/loader.cpp

# Verify populate_rules_skeleton + populate_action_table current shape
sed -n '1220,1300p' src/lib/loader.cpp

# Find apply_request rule-extraction + populate-call sites
grep -nE "populate_rules_skeleton|populate_action_table|populate_inner_slot|populate_cidr_inner_slot" src/lib/loader.cpp

# Verify Config::Rule shape (action field exists already)
grep -nE "struct Rule|RuleAction|action" src/lib/config.hpp

# bpftool standalone load tests (guard #7 — BTF asymmetry on outer ARRAY_OF_MAPS reshape)
grep -rln "bpftool prog load" tests/

# Version literal propagation (guard #11)
grep -rln '0\.8\.0' tests/ src/ docs/ CHANGELOG.md

# RESOURCE_LOCK declarations for NEW veth-touching tests (guard #12)
grep -nE "RESOURCE_LOCK|xdp_fixture|lo_iface|exporter_port_9417" tests/CMakeLists.txt | head -20

# Catalogue arithmetic — confirm BPF .maps declarations count + kManagedMaps[] count + STAT enum count (guard #10)
grep -cE "SEC\(\".maps\"\)" src/bpf/mac_filter.bpf.c
grep -cE "^\s*\{ &SkelMapsT::" src/lib/loader.cpp
```

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep discipline)** — always applies; architect re-runs the above independently from brief author's Phase 2.
- **Guard #7 (bpftool-vs-libbpf BTF inner-template asymmetry)** — `rules_outer` ARRAY_OF_MAPS reshape may cause standalone `bpftool prog load` failures even where libbpf-skeleton load succeeds. Phase A: grep `bpftool prog load` test sites + smoke-test each against the post-reshape .o.
- **Guard #9 (helper-location duplication-over-extraction)** — `populate_rules_inner_slot` SHOULD duplicate the per-axis-populate pattern from `populate_inner_slot` + `populate_cidr_inner_slot` rather than extract into a generic helper. Brownfield discipline.
- **Guard #10 (catalogue arithmetic slip)** — `kManagedMaps[]` 13 → 15 entries; BPF `SEC(".maps")` count grows by 2 (rules → rules_outer/rules_a/rules_b = +2 net); `XDPMF_MAP_*_NAME` constants count grows by +3 / −1. Architect counts independently.
- **Guard #11 (VERSION-bump propagation)** — `0.8.0 → 0.9.0`. `grep -rl '0\.8\.0' tests/` MUST run Phase A; affected test bodies pre-listed in FileList.
- **Guard #12 (RESOURCE_LOCK for shared host state in NEW ctests)** — T-1 / T-2 / T-3 ALL touch veth → all need `set_tests_properties(... PROPERTIES RESOURCE_LOCK xdp_fixture)` in their CMakeLists block.

### Cycle-2-specific anti-misdiagnosis (potentially new guards #13-#14)

- **Schema cycle 2 → cycle 3 semantic shift explicit-discipline** — HG-3.4b-c2-2 amends a previously-promised schema contract. Architect MUST cite the §5.26 contract being amended verbatim + write the new contract verbatim + flag it as PI. Silent contract drift = `[CONTRACT-DRIFT]` per reviewer.
- **Lifted PI explicit-declaration discipline** — PI-28-3.4b + PI-29-3.4b are formally LIFTED. Architect MUST name them explicitly in the new amendment + describe successor PIs ("PI-28-3.4b → superseded by PI-29-3.4b-c2 because …"). Silent PI retire = institutional-memory loss.
