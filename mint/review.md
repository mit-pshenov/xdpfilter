# Review — MVP-4.35/B42 redirect verb §5.75 (mint triangulation, brownfield 5-point)

## Verdict
`pass` (round 2). Round 1 = needs-rework (one [SPEC-UNTESTED] finding); fixed test-only in round 2 and re-reviewed clean. See "Round 2" addendum at the bottom.

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 1 | [SPEC-UNTESTED × 1] |
| 3. Code ↔ Tests | 0 | (109 pass / 2 pre-existing env-fail / 2 skip; targeted 13/13 green) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | (verdict-identity green, insn-rebaseline negotiated, all zero-diffs hold) |

## Point 1 — Spec ↔ Code (all match)
- enum REDIRECT=2/MIRROR=3 reserved/MAX=4 (xdpfilter.h:272-278); STAT_REDIRECT=4/MAX=5 (:68-74); map-name macro (:291); sizeof-4 static_asserts (:352-353) UNTOUCHED.
- redirect_devmap DEVMAP max_entries=1 (maps.h:366-372). Classifier append (classifier.h:199-202): exactly the spec'd REDIRECT branch APPENDED after the DROP test.
- populate_redirect_devmap (loader.cpp:1571-1597): steering→resolve_ifindex(fail-closed)→update[0]; no-steering→delete[0] swallow ENOENT. Both apply branches (:2147,:2267). populate_action_table appends REDIRECT[2] only (:1560-1566). action_id 3-way (:1402-1406). kManagedMaps single row (:193-198).
- config: RuleAction+Redirect (config.hpp:36), Steering (config.hpp:65-71), parse 'redirect' (config.cpp:128), schema {2,3} (config.cpp:359-369), steering parse+fence (config.cpp:578-600), find_key allowlist (config.cpp:618), cross-validation (config.cpp:602-609).
- exporter: verdict_label +redirect (prom_format.cpp:32), brace-init {0,0,0,0,0} (stats_reader.hpp:34).

## Point 2 — Spec ↔ Tests
SELECT-B (T_REDIRECT_DELIVERY) genuinely proves PHYSICAL cross-iface delivery (sink_count_prog on DISTINCT IFACE_D, peer of target IFACE_C; classifier bump can't reach it) + negation. SELECT-A (T_REDIRECT_COUNTER_AND_MAP) STAT_REDIRECT + devmap[0]==ifindex + negation. T_REDIRECT_TARGET_DOWN (optional, spike-PASS) PASS-on-miss. Negation controls present — no [NO-NEGATION-CONTROL].

### [SPEC-UNTESTED] Config-validation negative paths have zero coverage
**Location**: spec design.md:19823-19827 (§5.75.6 "Config validation … EXTENDED") vs tests.
**Evidence**: §5.75.6 lists 4 config-validation assertions. Two POSITIVE are implicitly covered (every redirect test applies a schema_version:3 + steering config rc=0; v2 ctests staying green). The two NEGATIVE paths are UNTESTED: (1) `action: redirect` without `steering.redirect_to` → exit 9 (cross-validation config.cpp:602-609); (2) unknown sub-key in `steering:` → exit 9 (fence config.cpp:592-597). `git diff HEAD~1 -- tests/T_EXIT_CODE_9_ON_CONFIG_ERROR.sh tests/T_SCHEMA_V2_CUTOVER.sh` = ∅. Cross-validation (1) is load-bearing: it is the soundness precondition the design relies on (no steering ⇒ no redirect rule ⇒ devmap unused); a silent regression would let a redirect rule reach the datapath with an empty devmap → PASS-on-miss → DPI feed silently dark, uncaught.
**Negotiated?**: no.
**Fix**: add a config-error ctest (or extend T_EXIT_CODE_9_ON_CONFIG_ERROR.sh) asserting exit 9 for (a) schema_version:3 + action:redirect + no steering; (b) steering: with unknown sub-key. Pure validate() path, unit-cheap (no netns/BPF).
**Assign to**: tester

## Point 3 — Code ↔ Tests
Targeted run (root, netns): 13/13 PASS — 8 *_ORACLE_AGREEMENT, both insn gates green at 3477, all 3 T_REDIRECT_*. Full suite: 109 pass / 2 fail / 2 skip / 111. The 2 fails = #48/#63 pre-existing unprivileged-exec EACCES env-fails (impl-notes §5.75 note 8 + §5.70); git diff src/exporter additive-only → NOT attributable, NOT regression.

## Point 4 — OOS drift
Clean. Only the reserved ACTION_MIRROR=3 hole (no branch, no populate entry — per §5.75.8). No per-rule target, no struct widen, no mirror/TC code.

## Point 5 — Behaviour preserved (brownfield, LOAD-BEARING — all hold)
- **PI-mvp-4.35-VERDICT-IDENTITY** ✓ — git diff HEAD~1 classifier.h = exactly ONE appended REDIRECT block; DROP test + STAT_PASS_CIDR/XDP_PASS fallthrough byte-identical. 8 ORACLE_AGREEMENT + PASS/DROP green.
- **PI-mvp-4.35-INSN-REBASELINE** ✓ — both gates pass at 3477 (T_INSN_BASELINE_GATE.sh:73, T_PROD_VERIFIER_LOAD.sh:127); impl-notes records 3437→3477 (+40). Second gate-file = FileList omission, escalated + architect-approved + design amended — NEGOTIATED, not [UNRELATED-EDIT].
- **PI-mvp-4.35-ACTIONTABLE-01** ✓ — only [2]=REDIRECT appended; PASS[0]/DROP[1] byte-identical.
- **PI-mvp-4.35-NO-STRUCT-WIDEN** ✓ — sizeof-4 static_asserts (xdpfilter.h:352-353) untouched.
- **PI-7** ✓ — git diff loader.hpp = ∅. compiled_ruleset.* / ruleset_delta.* = ∅.
- Guard #15/#16 ✓ — single non-double-buffered devmap rides apply walk; no pin-name collision. VERSION 0.17.0 propagated. Test count +3. No REGRESSION/INVARIANT-VIOLATED/UNRELATED-EDIT.

## Test execution (targeted)
```
 9/13 #102 T_PROD_VERIFIER_LOAD ............ Passed   0.30 sec
10/13 #105 T_INSN_BASELINE_GATE ........... Passed   1.13 sec
11/13 #109 T_REDIRECT_DELIVERY ............ Passed   4.01 sec
12/13 #110 T_REDIRECT_COUNTER_AND_MAP ..... Passed   2.22 sec
13/13 #111 T_REDIRECT_TARGET_DOWN ......... Passed   2.78 sec
100% tests passed, 0 failed out of 13
```
Full suite: 98% (2 fails = #48/#63 pre-existing env, 2 skips pre-existing).

## Rework assignments
- **tester**: add config-error test for the two §5.75.6 negative config-validation paths — (a) schema_version:3 + action:redirect with no steering → exit 9; (b) steering: with unknown sub-key → exit 9. Pure validate() path, unit-cheap. Smallest fix = extend T_EXIT_CODE_9_ON_CONFIG_ERROR.sh.
- architect / impl: none.

## Out-of-triangulation findings
None.

---

## Round 2 — re-review (fresh reviewer) — `pass`

The round-1 [SPEC-UNTESTED] finding is GENUINELY CLOSED; test-only fix, no new drift, all round-1 pass items hold.

- **Finding closed**: `tests/T_EXIT_CODE_9_ON_CONFIG_ERROR.sh` now covers both §5.75.6 negative paths via `run_redirect_cfg_subcase`: (e) schema_version:3 + `action: redirect` + no steering → exit 9 (cross-validation, "action: redirect requires a top-level steering.redirect_to"); (f) steering block with valid `redirect_to` + unknown sub-key `target_id` → exit 9 (forward-compat fence, "unknown steering field 'target_id'"). (f) keeps `redirect_to` valid so the ONLY defect is the unknown key — genuinely isolates the fence, not the cross-validation.
- **Assertions genuine, not vacuous**: each sub-case pins THREE conjuncts — rc==9 hard (not rc!=0), `^xdpfilter: config error:` prefix, and a `steering|redirect` reason-anchor (an unrelated exit-9 fails the anchor). No existing assertion weakened (git diff = 95 ins / 2 del, both deletions non-assertion: a comment + the trap widened to 3 temp files).
- **Scope test-only**: `git diff -- src/` = EMPTY; only `T_EXIT_CODE_9_ON_CONFIG_ERROR.sh` changed.
- **Round-1 pass items re-confirmed**: verdict-identity (T_AND_ORACLE_AGREEMENT green, classifier src/ ∅), insn both gates at 3477 (no revert to 3437), PI-7 / compiled_ruleset / ruleset_delta ∅.
- Execution: #28 T_EXIT_CODE_9_ON_CONFIG_ERROR Passed (sub-cases e/f both rc=9); spot-check T_AND_ORACLE_AGREEMENT + T_INSN_BASELINE_GATE green. #48/#63 pre-existing sandbox-exec env-fails, not this slice.

No rework. Ready to ship §5.75.
