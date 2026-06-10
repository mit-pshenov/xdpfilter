# Review — MVP-4.41 / PERF-M1: exporter scrape-loop bound (mint triangulation, §5.81, brownfield 5-point)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — (2 fails = documented env #48/#63) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — (all 8 PI rows checked; #65 re-judged NOT-a-regression) |

## Findings
None.

## Point-by-point evidence

**1. Spec ↔ Code** — §5.81.4 ordering implemented exactly:
- Step 1 counters-pin-first + WARN + `return false` before any `slot_rule_id` syscall: `rule_counters_reader.cpp:111-133` (D-mvp-4.41-OPEN-ORDER honored; WARN text byte-identical to pre-slice, guard #19).
- Step 2 sentinel-fill: `:136-138`.
- Step 3 id-scan: legacy open-fail → `bound=64` full walk `:146-149` (HG1-LEGACY-FULLWALK); lookup rc≠0 → `continue` `:155-160` (Q2-MISS-CONTINUE — per-element miss, never a boundary); read sentinel value → `bound=slot; break` `:161-169`; real id stored `:170`; loop-exhaust → bound stays 64; fd closed `:172`.
- **Guard #26 three anchors all present**: CONSUMER at the `break` (`rule_counters_reader.cpp:162-166`), PRODUCER leg-(a) at `compute_slot_to_id` (`compiled_ruleset.cpp:91-95`), leg-(b) back-ref ONE line in the D-mvp-4.21-SENTINEL block (`config.cpp:417`). compiled_ruleset/config diffs are comment-only (verified via git diff).
- `RuleCountersSample` byte-unchanged, hpp diff comment-only (`rule_counters_reader.hpp:25-27, 39-41`).
- `read_rule_counters` signature/noexcept unchanged (`rule_counters_reader.cpp:187-188`); NOEXTRACT honored (percpu_read.hpp zero-diff); NOVERSION honored (VERSION zero-diff). No LOOKUP_BATCH anywhere in src/exporter (grep clean).
- impl-notes.md has NO §5.81 entry → no negotiated deviations claimed; none needed — code conforms literally.

**2. Spec ↔ Tests** — TS-1 fully covered by `tests/T_EXPORTER_BOUNDED_SCAN_INVARIANT.sh`:
- (a) exactly-N series + id-set equality `:251-262` (ids 7/1000/4294967294 — sparse non-contiguous per spec, plus the max-legal-id boundary edge, a strengthening); (b) sentinel-leak grep `:264-268` + per-scrape re-checks `:325-328, :358-361`; (c) no rule_counters WARN (covers open_failed AND generation_unstable) `:364-368`; (d) families present + HELP/TYPE-exactly-once `:270-285`. MAY count=0 sub-case implemented as conditional (skips if loader rejects) `:330-362` — exactly per spec's "NOT a required assertion".
- **Negation controls (2)**: NC-1 leak-grep machinery self-test with synthetic sentinel line `:187-195`; NC-2 live shrink N=3→1, vacated ids must vanish `:308-324`. No `[NO-NEGATION-CONTROL]`.
- No `[CIRCULAR-TEST]` — oracle is scrape-output invariance (D-mvp-4.41-HG2-ORACLE), not loop shape; no syscall-count ctest committed (TS-3 stayed local-gate-only).
- TS-2: `git diff 7b09cbf -- tests/` shows ONLY CMakeLists.txt(+20) + the NEW test — ZERO edited ctest bodies.
- CMake registration per spec: `RESOURCE_LOCK "xdp_fixture;exporter_port_9417"`, `SKIP_RETURN_CODE 77`, TIMEOUT 90 (`tests/CMakeLists.txt:1846-1852`). Guard #31: `require_passwordless_sudo` exit-77 + curl-absent exit-77 (`:55-60`) — deterministic SKIP, no silent pass, no #48/#63 EACCES-pattern inheritance.

**3. Code ↔ Tests** — independent targeted run (`ctest -R 'EXPORTER|RULE_COUNTER|T_LOG_JSON_ENVELOPE_INVARIANTS|T_INSN_BASELINE_GATE'`, log `/tmp/mint-review-tests-1781092910.log`): **14/16 passed**; the 2 fails are exactly the documented env-fails #48 T_EXPORTER_EXITS_6_ALL_IFACES_EACCES + #63 T_LOG_JSON_EXPORTER_EVENTS (both the pre-existing unprivileged-spawn "Killed" pattern, present in prior cycles). NEW test #114 PASSED (2.64s). No unexercised exports: the only public symbol touched, `read_rule_counters`, is exercised by the exporter binary + the 8-test T_EXPORTER net.

**4. Out-of-Scope Drift** — footprint = exactly the FileList 5 EDITED + 1 NEW (git show --stat HEAD). stats_reader zero-diff; no batch lookup; no datapath/loader/ABI touch; no percpu_read growth; no committed syscall-count oracle; count=0 only as MAY.

**5. Behaviour preserved** — all §5.81.7 rows:
- **PI-mvp-4.41-OUTPUT-IDENTITY**: argument walk holds — `prom_format.cpp:128-130` skips sentinel slots, `:137` reads `s.counters[k]` only for non-sentinel ids; new code reads counters for the full `[0,bound)` prefix and every slot past `bound` keeps a sentinel id (the break means no real id is ever stored past it) → every rendered slot's counter IS read; unread tail counters (value-init 0) are never rendered. The one theoretical divergence vs old code (a real id sitting past a sentinel) is precisely what guard #26 legs (a)+(b) make impossible — and all three comment anchors now fence it. TS-1 + unmodified-green TS-2 corroborate.
- **PI-31**: grep over src/exporter — forbidden syscalls appear only in comments. ✓
- **PI-32**: counters-open-fail → WARN + skip with zero slot_rule_id syscalls (`:111-133` precedes `:147-148`); legacy no-pin → full walk, all-sentinel. ✓
- **PI-7 / DATAPATH / VERSION**: `git diff 7b09cbf -- src/bpf src/lib/loader.{cpp,hpp} src/common/xdpfilter.h src/exporter/prom_format.cpp src/exporter/percpu_read.hpp src/exporter/stats_reader.cpp VERSION` = ∅; T_INSN_BASELINE_GATE PASSED (3477). ✓
- **§5.64 seqlock (guard #32)**: all 4 diff hunks in rule_counters_reader.cpp sit in the header comment + `read_generation` (last hunk @144→152); outer `read_rule_counters` loop, `kRuleCountersGenRetryMax=3` (`:63`), pre/post `lookup_active` — zero diff. Both buffer reads keyed by the same `active` inside one window. ✓
- **PI-mvp-4.41-BASELINE**: tester full run 111/114 (mint/test-run.log); fails = #48/#63 (documented) + #65. ✓ with the #65 ruling below.

**#65 T_LOG_JSON_ENVELOPE_INVARIANTS re-judged — tester's NOT-a-regression ruling CONFIRMED on independent evidence**: (i) green in prior cycle; (ii) full-run failure output truncates exactly at "sweep step 3: exporter (json)" — an exporter-launch/bind failure shape, consistent with orphan-process port contention, NOT an envelope-invariant violation; (iii) this slice adds zero log lines (guard #19) and touches no exporter startup path; (iv) PASSED in reviewer's own re-run (8.67s) after confirming no orphan exporters were running. Not `[REGRESSION]`. Env-hygiene note (B16-adjacent, tester): #48's teardown should kill its unprivileged /tmp exporter copy — 11 orphaned /tmp/xdpmf-exporter-* processes (multi-day) were found holding ports 9417-10417 and reaped during Phase B.

## Test execution (tail of /tmp/mint-review-tests-1781092910.log)
```
12/16 Test  #65: T_LOG_JSON_ENVELOPE_INVARIANTS .........   Passed    8.67 sec
13/16 Test  #70: T_RULE_COUNTERS_ATOMIC_SWAP ............   Passed    3.76 sec
14/16 Test  #74: T_EXPORTER_BIND_NON_LOOPBACK_WARN ......   Passed    3.08 sec
15/16 Test #105: T_INSN_BASELINE_GATE ...................   Passed    0.43 sec
16/16 Test #114: T_EXPORTER_BOUNDED_SCAN_INVARIANT ......   Passed    2.64 sec
88% tests passed, 2 tests failed out of 16
The following tests FAILED:
	 48 - T_EXPORTER_EXITS_6_ALL_IFACES_EACCES (Failed)   [documented env]
	 63 - T_LOG_JSON_EXPORTER_EVENTS (Failed)              [documented env]
```

## Rework assignments
None — verdict is pass.

## Out-of-triangulation findings
None.
