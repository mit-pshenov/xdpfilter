# Task brief — MVP-3.5.5: mini housekeeping (brownfield, test-infra + design-text)

## Goal

Close the **chronic -j4 parallelism instability** that has been recurring across MVP-3.4.5, MVP-3.4b cycle 1, and MVP-3.5 — most acutely surfaced by MVP-3.5's A/B reviewer experiment where 3 independent ctest re-runs (tester + 2 reviewers) each produced a different flake victim set (T_MODE_NATIVE_UNSUPPORTED / T_BUILD / T_SANITIZER_BUILD / T_RULE_COUNTER_MAC_HIT_BUMPS / T_BPFFS_ROOT_SYMLINK). All pre-existing failures pass in isolation or serial — pure RESOURCE_LOCK omission on shared host state (`lo` iface; bpffs pin dirs after timeout cascades).

Pure test-infra cleanup. No new operator-facing feature, no datapath change, no production source touches except the design.md institutional-learning bake-in (anti-misdiagnosis guard #12) + one prior-cycle OOT closure (MVP-3.4.5 review's `xdpmf-exporter: shutdown` stderr marker clarification).

The slice ships **4 small items**:

1. **HK-A**: `RESOURCE_LOCK lo_iface` added to all ctests using `--iface lo` (6 candidates: T_APPLY_EXITS_1_ON_MISSING_CONFIG, T_CLI_BAD_MAC, T_CLI_CAPACITY, T_DETACH_NOTHING, T_EXIT_CODE_9_ON_CONFIG_ERROR, T_MODE_NATIVE_UNSUPPORTED — architect verifies which actually touch loader kernel state vs pure CLI parser).
2. **HK-B**: Cleanup-on-exit hardening — tests creating bpffs pin dirs (T_RULE_COUNTER_*, T_LINK_PERSIST, etc.) ensure trap EXIT removes their PID-scoped pin dirs even on timeout / SIGTERM. Prevents cascade failures into T_BPFFS_ROOT_SYMLINK + subsequent runs.
3. **HK-C**: Close MVP-3.4.5 OOT defer — `xdpmf-exporter: shutdown` stderr marker clarification in design.md (one-line note that the marker is benign and may appear before HK-17 ERROR — architect adds to §5.29 or §5.30 as a footnote, the choice is architect's).
4. **HK-D**: Anti-misdiagnosis institutional learning — bake "chronic -j4 parallelism instability" pattern into design.md as guard #12 (with actionable check: when adding NEW ctest that touches shared host state — bpffs root, `lo` iface, fixed port — REQUIRE RESOURCE_LOCK declaration matching that resource's lock domain).

Estimated budget: **<1 cycle, low risk**. Smallest LOC delta since MVP-3.4.5 housekeeping. Mostly tests/CMakeLists.txt edits + 2 design.md prose additions.

## Context: prior work

- **All prior briefs**: archived in `mint/task-brief-mvp{1,1.1*,2-*,3.1,3.2,3.3,3.4,3.4.5,3.4b-c1,3.5}.md`. Most recent: MVP-3.5 JSON structured logs (round-1 pass 2026-05-25; 58 ctests; 4 OOT inline-merges from A/B; first A/B reviewer experiment completed).
- **Existing design**: `mint/design.md` — §5.29 (exporter HTTP server + `shutdown` stderr marker site) + §5.30 (MVP-3.4.5 housekeeping precedent for this brief's shape) + §5.31 (per-rule counters) + §5.32 (JSON structured logs). This brief is a **direct descendant** of MVP-3.4.5's shape — small numbered HK items + design-text bake-ins + no new operator-facing surface.
- **MVP-3.5 review** (`mint/review.md`) — A/B synthesis flagged 1 OOT (logger.hpp:97 stale comment, already inline-merged) + the parallelism-flake observation as informational. The flake observation is now THIS slice's HK-A + HK-B.
- **MVP-3.4.5 review** (`git show 325e2ee:mint/review.md` for archived; current `mint/review.md` is MVP-3.5) — 1 OOT deferred: pre-existing `xdpmf-exporter: shutdown` stderr marker between `run()` return and HK-17 ERROR line. This brief's HK-C closes it.
- **Phase A code-grep discipline**: brief author already grepped to identify the 6 lo-touching ctests + the 3 bpffs-pin-touching ctests (T_RULE_COUNTER_MAC_HIT_BUMPS / T_RULE_COUNTER_CIDR_HIT_BUMPS / T_RULE_COUNTER_SURVIVES_APPLY). Architect re-verifies + extends as needed.
- **PI continuity**: `loader.hpp` is in its 7th consecutive ZERO-diff cycle + `config.hpp` 2nd. This brief is **strictly test-infra + design-text only** — ZERO C++ source touches expected. **PI-7-3.5.5-hpp** = 8th cycle ZERO diff on loader.hpp + 3rd on config.hpp + extends to ALL of `src/` (NO source touches whatsoever; userspace + BPF + headers all ZERO diff). Strongest PI-7 cycle since MVP-3.3 ("ENTIRE src+include+cmake tree ZERO diff").

## Workflow rules (brownfield mode)

- **Architect**: read existing `design.md` §5.29 / §5.30 / §6.5 PI-1..PI-34 + PI-3.5-1..7 + anti-misdiagnosis guards #1..#11. EDIT `design.md` in-place. Append `§5.33 MVP-3.5.5: mini housekeeping (test-infra parallelism + design-text bake-ins)`. **No new PIs** (housekeeping by nature). Update §6.5 — PI-1..PI-34 + PI-3.5-1..7 continue; **PI-7-3.5.5-hpp** extends ZERO-diff invariant to ALL of `src/` (no source touches). Add **anti-misdiagnosis guard #12** per HK-D. Update §7 OOS — close the 1 OOT (HK-C); surface no new fences. **Apply Phase A code-grep discipline** (architect-spec rule + sub-rule "where is X called per-runtime"): verify which of the 6 lo-touching ctests actually invoke the loader's kernel-side path vs pure CLI parse — only the former need lo_iface lock; pure parser tests don't touch `lo` state.
- **Impl**: brownfield mode. FileList is a DIFF. Expect **0 NEW files**. **3 EDITED**: `tests/CMakeLists.txt` (HK-A — add `RESOURCE_LOCK lo_iface` to 4-6 add_test entries per architect's filter); selected `tests/T_*.sh` files (HK-B — trap EXIT hardening for 3 bpffs-pin-touching tests); `mint/design.md` (HK-C inline footnote + HK-D guard #12 — architect handles these in-place). **NO C++ source touches** (PI-7-3.5.5-hpp ZERO diff on entire src/). **NO CMakeLists.txt VERSION bump expected** (PATCH-tier housekeeping at most: 0.8.0 → 0.8.1; architect decides — could even stay at 0.8.0 if no operator-facing change).
- **Tester**: NO new ctests this cycle (HK-A/HK-B fix EXISTING tests; HK-C/HK-D are design-text). EDIT existing ctests per HK-B catalog (architect specifies which tests need trap-EXIT hardening). Tester verifies via Phase B that all 58 existing ctests still pass + the targeted -j4 parallelism flakes no longer fire. Specifically: run `ctest -j4` 3 times in succession and verify ZERO failures across all 3 runs (stability canary for HK-A/HK-B).
- **Reviewer**: 5-point brownfield framework. Special attention:
  - **(1) PI-7-3.5.5-hpp** — ZERO diff on ALL of `src/`. `git diff <baseline> -- src/` MUST return zero lines.
  - **(2) PI-3.5.5-1 parallelism resilience** — 3 consecutive `ctest -j4` runs MUST all pass (zero failures across the 3 runs). This is the load-bearing canary for HK-A + HK-B.
  - **(3) PI-3.5-1 byte-equivalence preserved** — text-mode stderr untouched; no logger conversions this slice.
  - **(4) Anti-misdiagnosis guard #12 explicit + actionable** — design.md §5.33 adds guard #12 with the actionable check ("when adding NEW ctest that touches shared host state, REQUIRE RESOURCE_LOCK declaration").
  - **(5) MVP-3.4.5 OOT closure** — HK-C clarification added to design.md (architect decides §5.29 footnote OR §5.30 footnote OR §5.33 inline note); review.md "Deferred to next slice" list now empty.

## Human-gate decisions (defaults applied — override at architect Phase A)

### HG-3.5.5-1: HK-A scope — **all 6 lo-touching ctests get `RESOURCE_LOCK lo_iface`** by default; architect prunes if false positives

Brief-author's grep returned 6 candidates: T_APPLY_EXITS_1_ON_MISSING_CONFIG, T_CLI_BAD_MAC, T_CLI_CAPACITY, T_DETACH_NOTHING, T_EXIT_CODE_9_ON_CONFIG_ERROR, T_MODE_NATIVE_UNSUPPORTED. Some may be PURE CLI parse-and-exit tests where the `--iface lo` string never reaches the loader's kernel-side attach (e.g. config_open() throws first OR bad-MAC parse rejects before any iface state-machine work). Those don't need the lock.

**Default**: architect reads each test body + classifies. Add `RESOURCE_LOCK lo_iface` ONLY where the test actually invokes loader's kernel-side path on `lo` (attach/apply/detach state-machine reaches the iface). Pure-parser tests stay unlocked.

### HG-3.5.5-2: HK-B scope — **3 bpffs-pin-touching ctests get trap EXIT hardening**

T_RULE_COUNTER_MAC_HIT_BUMPS, T_RULE_COUNTER_CIDR_HIT_BUMPS, T_RULE_COUNTER_SURVIVES_APPLY all attach the loader to a veth and create per-iface pin dirs at `${PIN_DIR}/<iface>/`. On TIMEOUT (the -j4 contention scenario), the test's main script dies WITHOUT running its trap EXIT cleanup if the trap is registered too late or interrupted mid-cleanup. T_BPFFS_ROOT_SYMLINK then refuses to corrupt the non-empty `${PIN_DIR}` and fails cascading.

**Default**: tester adds defense-in-depth to the trap EXIT in those 3 tests: explicit `sudo rm -rf "${PIN_DIR}/${IFACE_A}/" "${PIN_DIR}/${IFACE_B}/"` (PID-scoped iface names, so safe). Also: pre-test sweep — at the START of each, `sudo rm -rf "${PIN_DIR}/xdpmf_*_${TEST_PID}/"` to clean up any stale dirs from a prior aborted run. Combined: cleanup happens on normal exit AND on the worst-case "test was killed mid-cleanup" + pre-test wipes residue.

### HG-3.5.5-3: HK-C OOT closure — **architect adds inline note in §5.29 (`run()` teardown)**

The OOT from MVP-3.4.5: pre-existing `xdpmf-exporter: shutdown` stderr marker between `http::run()` exit and HK-17 ERROR line. Contract not violated (HK-17 ERROR fires + exit(6); shutdown marker is teardown signal). Operator-observable: extra benign line under MVP-3.4 / MVP-3.4.5 baseline; under MVP-3.5 JSON mode, the shutdown marker becomes `exporter.shutdown` event (already in catalog).

**Default**: architect adds one-line note in §5.29 (next to the run() teardown discussion) — "the `xdpmf-exporter: shutdown` line emitted at run() exit is a benign teardown marker; under HK-17 trigger path it appears BEFORE the HK-17 ERROR line per the global-stop-then-final-error flow — assertion ERE for HK-17 uses substring match (not line-exclusive), so this is not contract-violating." ~3 LOC of prose. Closes the OOT.

### HG-3.5.5-4: HK-D anti-misdiagnosis guard #12 — **bake into design.md as institutional learning**

Across MVP-3.4.5, MVP-3.4b cycle 1, MVP-3.5: chronic -j4 parallelism instability has surfaced each cycle. Different victim per run; all pass in isolation/serial. Pattern: tests touching shared host state without RESOURCE_LOCK declaration race under -j4 scheduling.

**Default**: architect adds to design.md §5.33 (or a §6.6 anti-misdiagnosis notes block) — "guard #12: when adding a NEW ctest that touches shared host state (bpffs root, named iface like `lo`, fixed port, systemd unit, ansible inventory), the new ctest's `add_test()` entry MUST declare an appropriate `RESOURCE_LOCK` matching that resource's lock domain (xdp_fixture for veth; lo_iface for `lo`; exporter_port_9417 for the exporter port; etc.). MVP-3.5.5 HK-A fixes the inherited gap on `lo`. Future ctest additions are guard'ed by this rule."

## Open mechanism questions (architect decides; document in §5.33)

### Q1: HK-A — `lo_iface` lock name

- **L1**: `lo_iface` (matches `xdp_fixture` / `exporter_port_9417` naming convention — lowercase, underscore-separated, descriptive)
- **L2**: `loopback_iface`
- **L3**: `lo` (terse; matches Linux convention but loses lock-name clarity)

**Recommendation**: **L1**. Consistent with project convention.

### Q2: HK-B — pre-test cleanup vs trap-only cleanup

- **C1**: Trap EXIT cleanup ONLY (idempotent rm -rf at trap). Relies on trap firing.
- **C2**: Pre-test cleanup ONLY (rm -rf at test start, before any setup). No trap.
- **C3**: BOTH — pre-test + trap (defense-in-depth). Belt-and-suspenders.

**Recommendation**: **C3**. Pre-test wipe + trap cleanup = robust across both "previous run died" + "this run dies" scenarios. The -j4 chronic-instability scenario is exactly the case where one or the other is needed.

### Q3: Version bump 0.8.0 → 0.8.1 (PATCH)?

- **V1**: Yes — bump to 0.8.1. Standard Keep-a-Changelog practice for any release-tagged change.
- **V2**: No — keep 0.8.0. Pure test-infra + design-text, no operator-facing change; doesn't warrant a tag.

**Recommendation**: **V2**. The smallest housekeeping cycle to date — no operator-facing change, no new ctest, no new design contract (just clarification + guard bake-in). Defer version bump to next operator-facing slice. CHANGELOG.md can gain an `[Unreleased]` section note for traceability without bumping the released version.

### Q4: Stability canary — separate ctest or test-runner script?

- **K1**: NEW ctest `T_PARALLELISM_RESILIENCE.sh` — runs `ctest -j4` 3 times in succession, asserts ZERO failures across all 3 runs. Self-contained.
- **K2**: NO new ctest. Tester verifies manually in Phase B by running 3× ctest -j4 + reports stability.
- **K3**: Add a script `tests/ci/stability_probe.sh` (NOT a ctest) that operators / CI can invoke externally.

**Recommendation**: **K2**. K1 would itself contend with the very flakes it's measuring (recursion problem: a ctest-of-ctests under -j4 hits the same RESOURCE_LOCK contention). K3 is good but adds scope. Tester's Phase B manual verification is sufficient + cheap.

## Scope (cycle 1 — concrete items)

### Item HK-A — `RESOURCE_LOCK lo_iface` on lo-touching ctests
**Where**: `tests/CMakeLists.txt` — for each `add_test(NAME T_X COMMAND ...)` that touches `--iface lo` AND invokes loader's kernel-side path, ADD `RESOURCE_LOCK lo_iface` to its `set_tests_properties(T_X PROPERTIES ... RESOURCE_LOCK lo_iface)` block. Pure parser tests stay unlocked. Architect classifies; impl applies. ~6 line touches max, likely 4 (T_CLI_BAD_MAC + T_CLI_CAPACITY may be pure-parser).

### Item HK-B — Trap EXIT + pre-test cleanup hardening
**Where**: `tests/T_RULE_COUNTER_MAC_HIT_BUMPS.sh`, `tests/T_RULE_COUNTER_CIDR_HIT_BUMPS.sh`, `tests/T_RULE_COUNTER_SURVIVES_APPLY.sh` (and any other test architect identifies as bpffs-pin-creating). Each gets: pre-test `sudo rm -rf "${PIN_DIR}/<iface_a>/" "${PIN_DIR}/<iface_b>/"` ~3 LOC near top + defense-in-depth `sudo rm -rf` re-statement inside `cleanup_veth()` or trap. ~10-15 LOC across 3 files.

### Item HK-C — MVP-3.4.5 OOT closure (design-text)
**Where**: `mint/design.md` §5.29 (or §5.30 or §5.33 — architect's call per HG-3.5.5-3). ~3 LOC inline note on benign `xdpmf-exporter: shutdown` marker.

### Item HK-D — Anti-misdiagnosis guard #12 (institutional learning)
**Where**: `mint/design.md` §5.33 (the new section). ~5-10 LOC describing the chronic-parallelism class-of-bug + actionable check for future ctest additions.

## Out of scope (explicit)

- **No new ctests** (HK-A/HK-B fix existing tests; K1 stability-canary ctest rejected per Q4).
- **No C++ source touches** (PI-7-3.5.5-hpp ZERO diff on entire src/).
- **No CMakeLists.txt VERSION bump** (per Q3=V2; defer to next operator-facing slice).
- **No CHANGELOG.md entry** (no released version this cycle; can update `[Unreleased]` section if desired).
- **No new operator-facing surface** (no new env var, no new CLI flag, no new BPF map, no new exit code).
- **Consolidated anti-misdiagnosis guards file** (`~/.claude/agents/mint-dev/anti-misdiagnosis-guards.md`) — workflow-level edit, outside /mint-dev scope; user actions inline if desired.
- **MVP-3.5b** (XDPMF_LOG_DEST file/syslog/journald + XDPMF_LOG_LEVEL) — carry-forward.
- **MVP-3.4b cycle 2** (atomic-swap promotion of `rules` map; action_table dispatch) — carry-forward.
- **Doc bucket D1..D13** — user-driven manual, separate pass.

## Definition of done

- `§5.33 MVP-3.5.5 mini housekeeping` amendment in `design.md` documenting HK-A..HK-D + Q1-Q4 decisions + HG-3.5.5-1/2/3/4 confirmation.
- §6.5 Preserved invariants extended: **PI-7-3.5.5-hpp** ZERO diff on ALL of `src/` (strongest cycle since MVP-3.3); **PI-3.5.5-1** parallelism resilience (3 consecutive `ctest -j4` runs zero failures).
- Anti-misdiagnosis guard #12 added (chronic -j4 parallelism instability).
- 58 existing ctests still pass.
- Tester Phase B 3-run stability verification confirms zero flakes.
- `mint/review.md` round-1 verdict = `pass`.
- One git commit per phase boundary per workflow B.

## Dependencies

- No new build deps.
- No new test runtime deps.
- No new BPF features.
- No new kernel-version dependencies.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       [lang/cmake.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []
```

Note: `lang/cpp.md` + `lang/bpf.md` packs DROPPED from impl (no C++ source touches; no BPF touches). Only cmake pack needed for `tests/CMakeLists.txt` edits.

---

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])

Mechanical answer falls out of stated constraints: add `RESOURCE_LOCK lo_iface` to lo-touching tests; add cleanup hardening to bpffs-pin tests; close one OOT; bake one guard. No multi-axis design space to brainstorm. Single architect via standard /mint-dev is correct.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief author already ran initial greps. Architect should re-verify + extend:

- `grep -l 'iface lo' tests/T_*.sh` → 6 files. Read each + classify: pure-parser vs loader-kernel-touching. Only the latter need `RESOURCE_LOCK lo_iface`.
- `grep -rnE 'PIN_DIR.*/.*pin\|bpf_obj_pin' tests/T_*.sh` → find bpffs-pin-touching tests. Cross-check with HK-B target list (T_RULE_COUNTER_*); add any missed test to HK-B catalog.
- `Read tests/T_BPFFS_ROOT_SYMLINK.sh` — the cascade-victim test; understand its "refuse to corrupt non-empty bpffs root" precondition so HK-B trap cleanup targets the right pin dirs.
- `grep -nE "anti-misdiagnosis|guard #[0-9]+" mint/design.md` — locate the 11 existing guards; choose where #12 lives (§5.33 standalone block, OR extension to whichever section has the existing guards table).
- `git log --grep="-j4\|parallelism\|RESOURCE_LOCK" --oneline` — find prior commits that addressed similar issues (T_SANITIZER_BUILD timeout bump `e31cfcd`; T_BPFFS_ROOT_SYMLINK lock); use as precedent for HK-B+HK-D wording.
- `Read mint/review.md` (current MVP-3.5 review.md) — confirm the 1 OOT (`xdpmf-exporter: shutdown` stderr marker) is the right closure target per HG-3.5.5-3. **Wait** — the current `mint/review.md` is MVP-3.5's; the OOT defer was MVP-3.4.5's. Architect retrieves the MVP-3.4.5 review.md via `git log --grep "MVP-3.4.5 housekeeping" --oneline` → `c0b537a` → `git show c0b537a:mint/review.md` for the deferred-OOT block.
