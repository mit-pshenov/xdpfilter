# Review — MVP-4.8 apply_request table-driven inactive-slot populate (B20) (mint triangulation)

## Verdict
`pass` (round 1, 0 findings)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | (no UNEXERCISED-EXPORT — both helpers anon-namespace, called by both branches) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

Plus 1 `[OUT-OF-TRIANGULATION]` (cosmetic test comment; does not affect verdict).

## Point-by-point evidence

**1. Spec ↔ Code — CLEAN.**
- Helpers exist `loader.cpp:1829` (`inactive_axis_fd`) + `:1850` (`populate_all_axes`). Named `inactive_axis_fd` not the brief's `inactive_inner_fd` — architect-blessed flex in D-mvp-4.8-NAME-SHADOW (avoids shadowing the `copy_rule_counters_forward` parameter). NOT drift.
- **LOAD-BEARING (b) — `_a`/`_b`↔slot mapping**: `loader.cpp:1831` `bpf_map* inner = (slot == 0) ? a : b;` — slot==0→a, else(slot==1)→b. Correct for BOTH cases, single home. ✓
- **LOAD-BEARING (a) — semantic diff**: both branches' 9-block sequences (mac→dst→src→proto→port→vlan→wildcard→defaults→rules) collapse to one `populate_all_axes` call each (reattach `:2338` slot=inactive; fresh `:2465` slot=0u). Order byte-identical in effect; wildcard arg order `dst,src,proto,port,vlan,mac` matches pre-refactor. ✓
- **LOAD-BEARING (c) — guard #15**: `copy_rule_counters_forward` EXPLICIT per branch — reattach `:2373` `(old_rc_fd, inactive_rc_fd)`; fresh `:2489` `(rc_a_fd, rc_a_fd)`. `populate_action_table` explicit `:2350`/`:2474`. Neither folded into the RESET-shaped helper. ✓
- **(d) B25**: config.cpp/config.hpp/apply_internal.hpp diffs comment-only. `config.hpp:60` `schema_version = 1;` is CODE and UNTOUCHED ✓ (parser requires `==2`, overrides the inert default).
- **(e)**: VERSION `0.15.0`; `kManagedMaps`=30; `git diff 8335e2b -- loader.hpp src/bpf/ src/common/ CMakeLists.txt` EMPTY → UNCHANGED-BUT-AFFECTED byte-identical. ✓

**2. Spec ↔ Tests — CLEAN.**
- NEW-target=0 but justifies ONE reattach-twice canary (corpus gap = no existing test exercises reattach inactive=0→`_a`). `T_REATTACH_TWICE_SLOT_CANARY.sh` genuinely exercises it: A(fresh)→B(reattach#1, inactive=1→`_b`)→C(reattach#2, inactive=0→`_a`), ping-pong assertion `:166`, load-bearing verdict `MAC_C pass / MAC_B drop` `:174-175`. Targets outcome, not code-shape → no CIRCULAR-TEST.
- Negation control `:181` MAC_DENY MUST DROP. Present.
- Regression corpus maps to TestStrategy; all present.

**3. Code ↔ Tests — CLEAN.** Reviewer rebuilt build-asan (GREEN) + ran 8/8 load-bearing PASS. No UNEXERCISED-EXPORT (both helpers anon-namespace, called from both branches; no new public API).

**4. Out-of-Scope Drift — CLEAN.** No fold of copy-forward/action_table, no parameter rename, no `config.hpp:60` change, no `.bpf.c`/map/pin/schema/axis/VERSION change. No A2 constexpr-loop. No creep.

**5. Behaviour preserved — CLEAN.**
- PI-mvp-4.8-FD-SELECT/BEHAVIOR-EQUIV/ACTION-TABLE/SWAP-SEMANTICS/SINGLE-TU/CATALOG/VERSION/B25-COMMENT-ONLY + PI-mvp-4.3-COUNTER-PRESERVE — all verified by reading + diff + green suite.
- UNCHANGED-BUT-AFFECTED EMPTY diff → no UNRELATED-EDIT.
- REGRESSION floor: T_EXPORTER_RULE_LABELS (1 fail in tester's full run) re-verified standalone → PASS (4.17s); GREEN in MVP-4.7 baseline; refactor doesn't touch exporter scrape path → confirmed transient flake, NOT a regression.

## Test execution
```
1/8 T_REATTACH_TWICE_SLOT_CANARY ..... Passed 7.58 sec
2/8 T_APPLY_ATOMIC_SWAP_NO_DROP ...... Passed 7.17 sec
3/8 T_CIDR_ATOMIC_SWAP_NO_DROP ....... Passed 7.16 sec
4/8 T_RULE_COUNTER_SURVIVES_APPLY .... Passed 3.36 sec
5/8 T_RULES_ATOMIC_SWAP_NO_DROP ...... Passed 8.01 sec
6/8 T_RULE_COUNTERS_ATOMIC_SWAP ...... Passed 3.51 sec
7/8 T_BITVEC_ORACLE_AGREEMENT ........ Passed 9.43 sec
8/8 T_AND6_ORACLE_AGREEMENT .......... Passed 7.75 sec
100% tests passed, 0 tests failed out of 8
--- standalone flake re-verify ---
1/1 T_EXPORTER_RULE_LABELS ........... Passed 4.17 sec
```
Build: GREEN, no new warnings. Logs: /tmp/mint-review-tests-1780075335.log
Tester full run (Phase B): 82 pass / 1 fail (adjudicated flake) / 2 skip of 85 → mint/test-run.log

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] Canary test header comment uses brief's old helper name
**Location**: `tests/T_REATTACH_TWICE_SLOT_CANARY.sh:6`
**Evidence**: comment says `inactive_inner_fd` but impl named the helper `inactive_axis_fd` (D-mvp-4.8-NAME-SHADOW). Doc-comment drift; zero behavioral impact.
**Recommended disposition**: `inline-merge` (one-word comment fix).

No rework assignments — verdict is `pass`.

---

### Post-review sweep — round 1
- [OUT-OF-TRIANGULATION] canary header comment → `tests/T_REATTACH_TWICE_SLOT_CANARY.sh:6` edited → `inactive_inner_fd` renamed to `inactive_axis_fd` in the WHY-comment (matches the real symbol; rides Phase 6 final commit).
