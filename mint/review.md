# Review — MVP-4.27 / B37 decorative-gates (mint triangulation)

## Verdict
`pass` (round-1)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code (test-infra) | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

## Point-by-point

**1. Spec ↔ Code** — "code" here is test-infra (zero `src/`). Both Interfaces honored:
- `T_PROD_VERIFIER_LOAD.sh:120-145` — FATAL insn assert on the `rc==0` path; measures `llvm-objdump-19 -d --section=xdp | grep -cE '^\s+[0-9a-f]+:'` (the 3658 objdump LINE count, NOT the xlated-BYTE value) → **D-mvp-4.27-INSN-SOURCE honored**; `expected=${XDPMF_PROD_INSN_BASELINE:-3658}` (`:120`); failure msg NAMES the hatch (`:139-140`); xlated-byte read kept as labelled secondary NOTE (`:147-154`). SKIP-safe: missing objdump → NOTE+continue (`:125-127`), unparseable → NOTE+continue (`:131-133`), never FAIL/77.
- `T_LOADER_STDERR_GOLDEN.sh:78-114` — 3 MUST shapes driven through real `LOADER_BIN`, exact-match `diff` vs checked-in goldens; SKIP-77 on absent binary (`:41-44`); Permission arm SKIP-clean when privileged (`:120-121`); NO-LOCK confirmed (parse-throws before iface resolve). Goldens (`tests/fixtures/loader_stderr_*.golden`) are operator-REACHABLE rendered lines, no internal-only-code coupling.
- Sanctioned reversal: §5.63 markers present at design.md:17559/17566/17601 — verbatim reversed text cited + `[SUPERSEDED BY §5.67]`/`[RETIRED by §5.67]` (grep count = 3); Decisions block (18175-18177) quotes both reversed texts verbatim. **guard #35 candidate present** (18226-18229). Clean per impl-role-discipline — design, not silent drift.

**2. Spec ↔ Tests** — TestStrategy §6.83/§6.84 both covered. Negation controls present and real:
- `T_INSN_BASELINE_GATE.sh:100-147` drives the gate with a WRONG baseline (must fail-loud) + CORRECT baseline (must pass) + cross-track check.
- `T_LOADER_STDERR_SHAPE.sh:111-132` exact-golden-vs-self (empty) + mutated-golden (non-empty) discrimination. **[NO-NEGATION-CONTROL] not triggered.** No tautological/circular tests — assertions target stated outcomes (insn count == baseline; rendered stderr == golden; exit codes), not impl internals.

**3. Code ↔ Tests** — re-ran all 4 slice tests via ctest: 4/4 Passed (`/tmp/mint-review-tests-1780568921.log`). Teeth independently re-proven:
- Insn gate with `XDPMF_PROD_INSN_BASELINE=9999` → `FAIL: xdp-section instruction-count 3658 != baseline 9999`, names hatch, rc=1 (not 77). Confirmed xlated bytes = 39216B ≠ 3658 (proves D-mvp-4.27-INSN-SOURCE was a real catch).
- Mutated `loader_stderr_bad_trust_model.golden` → `FAIL[1-shape]: rendered stderr does NOT match`, rc=1; restored byte-clean (git diff empty). Bonus: the unprivileged OPS-canary Permission arm fired (exit 6, pinned shape) when run un-sudo'd.
- objdump count on `build/xdpfilter.bpf.o` == 3658 (independently). No UNEXERCISED-EXPORT (test-infra only).

**4. Out-of-Scope** — no code/test references B34/B35/B36 or the P3/P4/P6 folds; no `src/` touched. No OOS-DRIFT.

**5. Behaviour preserved (brownfield)**:
- PI-mvp-4.27-ZERO-SRC: `git diff 4a9aa5d -- src/` = ∅ ✓
- PI-7 RESUMES: `git diff 4a9aa5d -- src/lib/loader.hpp src/lib/config.hpp` = ∅ ✓
- PI-DATAPATH-IDENTICAL: `xdpfilter.bpf.c` ∅; xdp section == 3658 ✓
- PI-VERSION: `--version` ⇒ 0.16.0 ✓
- No REGRESSION: tester's full run = 104/106 pass; the only 2 failures are the pre-existing env-fails BY NAME (T_EXPORTER_EXITS_6_ALL_IFACES_EACCES #48, T_LOG_JSON_EXPORTER_EVENTS #63) — both untouched by the slice (`git diff 4a9aa5d` empty), prior 101/103 baseline preserved (+3 new green = 104/106).
- No UNRELATED-EDIT: footprint == FileList exactly (NEW T_LOADER_STDERR_GOLDEN.sh + 3 goldens; EDITED T_PROD_VERIFIER_LOAD.sh + CMakeLists.txt + design.md) PLUS the 2 meta-verification tests (T_INSN_BASELINE_GATE, T_LOADER_STDERR_SHAPE) sanctioned by team-lead as the expected triangulation layer — confirmed, not flagged. Existing T_PROD_VERIFIER_LOAD CMake registration untouched (diff is append-only at CMakeLists:1581+).

## Test execution
```
1/4 Test #102: T_PROD_VERIFIER_LOAD .............   Passed    0.26 sec
2/4 Test #104: T_LOADER_STDERR_GOLDEN ...........   Passed    0.07 sec
3/4 Test #105: T_INSN_BASELINE_GATE .............   Passed    0.58 sec
4/4 Test #106: T_LOADER_STDERR_SHAPE ............   Passed    0.07 sec
100% tests passed, 0 tests failed out of 4
```
Teeth (independent re-proof): insn-gate FAIL-loud on baseline=9999 (rc=1, hatch named); mutated-golden FAIL[1-shape] (rc=1); both restored clean. Tester's full-suite baseline: 104/106 (2 pre-existing env-fails by name).

## Out-of-triangulation findings
None. (Minor observation, NOT a finding: `loader_stderr_missing_config.golden` embeds the strerror tail "No such file or directory" — locale-fragile in principle, but design-sanctioned exact-match for the MUST corpus per D-mvp-4.27-Q1 and passes in the C/en CI locale. No action.)

All three artifacts agree. Ship it.
