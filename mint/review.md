# Review — MVP-3.5.5 mini housekeeping (mint triangulation, brownfield 5-point)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

## Evidence — point-by-point

### 1. Spec ↔ Code

**HK-A** (`design.md:9398` + Decisions table `:9455-9464`): 4 of 6 `lo`-touching ctests gain `RESOURCE_LOCK lo_iface`. Verified:
- `grep -c 'RESOURCE_LOCK lo_iface' tests/CMakeLists.txt` → **4** ✓
- `tests/CMakeLists.txt:181` — T_CLI_CAPACITY (single-lock; defensive read protection — split out of unlocked foreach into own add_test block)
- `tests/CMakeLists.txt:205` — T_DETACH_NOTHING `"xdp_fixture;lo_iface"` multi-lock ✓
- `tests/CMakeLists.txt:286` — T_MODE_NATIVE_UNSUPPORTED `lo_iface` ✓ (cleanup_native at `T_MODE_NATIVE_UNSUPPORTED.sh:42-43` unconditionally toggles xdp on lo)
- `tests/CMakeLists.txt:628` — T_APPLY_EXITS_1_ON_MISSING_CONFIG `lo_iface` ✓ (negation branch at `:87` invokes `apply --iface lo` + `:99` calls `detach --iface lo`)
- 2 NOT locked (T_CLI_BAD_MAC, T_EXIT_CODE_9_ON_CONFIG_ERROR) ✓ — classifier verified via header-citation evidence in each test

**HK-A T_CLI_CAPACITY foreach split-out**: impl chose to split out of unlocked foreach rather than 2nd set_tests_properties call. Design D-3.5.5-1 + design.md:9466 explicitly leaves CMake mechanism to impl. NOT spec-drift.

**HK-B** (`design.md:9399` + D-3.5.5-2 at `:9477-9498`): 3 RULE_COUNTER tests get pre-test wipe + trap signal-set extension. Verified:
- `grep -cE 'trap .* EXIT INT TERM HUP' tests/T_RULE_COUNTER_*.sh` → **3** ✓
- `grep -cE 'HK-B pre-test residue wipe' tests/T_RULE_COUNTER_*.sh` → **3** ✓
- Exact shape matches design.md:9486-9491 reference diff in all 3 files

**HK-C** (`design.md:6414`): inline note in §5.29 next to `http::run()` declaration. 7-LOC prose; cross-refs §5.30 EDIT-2 (HK-17 ordering) + §6.46 substring-match assertion contract.

**HK-D guard #12** (`design.md:9605-9621`): added with 4 lock domains (xdp_fixture, lo_iface NEW, exporter_port_9417, systemd_unit_install); actionable rule for future cycles; T_CLI_CAPACITY validates "reads don't need locks" anti-pattern. Catalogue extends #11 → #12 ✓.

### 2. Spec ↔ Tests

TestStrategy (design.md:9542-9558) specifies 7-step Phase B verification protocol — no new ctests, only verification mechanisms. All steps verified in `mint/test-run.log`:
- 3 RUN markers at lines 1, 128, 255
- All 3 runs `100% tests passed, 0 tests failed out of 58` (lines 120, 247, 374)
- Identical SKIP-77 set {T_DROP_MALFORMED, T_ANSIBLE_PLAYBOOK_SYNTAX} across all 3 (lines 125-126, 252-253, 379-380)
- PI-3.5.5-1 stability canary PASS

No SPEC-UNTESTED, no CIRCULAR-TEST, no new ctests this slice per Q4=K2.

### 3. Code ↔ Tests

Reviewer's independent `ctest -j4` re-run: `/tmp/mint-review-tests-1779784762.log` → `100% tests passed, 0 tests failed out of 58` (426.37 sec). Identical shape to tester's 3 runs — 4th-run parity confirmation.

No UNEXERCISED-EXPORT this slice (no NEW public symbols; PI-7-3.5.5-hpp/cpp ZERO diff).

### 4. Out-of-Scope Drift

Design §7 OOS (design.md:9660-9665) — verified no drift:
- NO new ctests this cycle ✓
- NO C++ source touches ✓
- NO CMakeLists.txt VERSION bump ✓
- NO CHANGELOG.md entry ✓
- NO new env var / CLI flag / exit code / BPF map ✓
- NO tests/lib/common.sh modifications ✓
- NO T_PARALLELISM_RESILIENCE.sh (Q4=K2 rejected) ✓

### 5. Behaviour preserved (brownfield §6.5)

**PI-7-3.5.5-hpp** (design.md:9575): `git diff 1c69348 -- src/lib/loader.hpp src/lib/config.hpp` → **0 lines** ✓ (8th cycle loader.hpp + 3rd cycle config.hpp ZERO-diff).

**PI-7-3.5.5-cpp** (design.md:9576): `git diff 1c69348 -- src/ include/ CMakeLists.txt CHANGELOG.md cmake/` → **0 lines** ✓ (**strongest PI-7 cycle since MVP-3.3**). `find src/ -newer mint/task-brief.md -print` → EMPTY ✓.

**PI-3.5.5-1 NEW** (design.md:9577): 4 total `ctest -j4` runs (3 tester + 1 reviewer), all 100% PASS with identical 56-PASS + 2-SKIP shape. Load-bearing canary HELD.

**PI-3.5-1 byte-equivalence** (carried forward): no logger conversions this slice → 13 stderr-grep ctests pass ✓.

**PI-6-3.5.5 / PI-34** (design.md:9582): 58-ctest strict superset with 3-EDIT carve-out for HK-B. `git diff 1c69348 -- tests/T_*.sh` shows exactly 3 modified files; per-file diff shows only trap-line extension + pre-test wipe lines. Carve-out respected ✓.

**PI-1..PI-34 + PI-3.5-1..7 + PI-7-3.4.5-hpp/cpp + PI-3.4b-***: all continue per original check mechanisms; this slice touches none of their assertion targets.

No REGRESSION, no UNRELATED-EDIT, no INVARIANT-VIOLATED.

## Test execution

```
100% tests passed, 0 tests failed out of 58
Total Test time (real) = 426.37 sec
The following tests did not run:
	  5 - T_DROP_MALFORMED (Skipped)
	 35 - T_ANSIBLE_PLAYBOOK_SYNTAX (Skipped)
```

Tester's 3 prior runs: 397.92s / 381.81s / 389.81s — identical 100%-PASS shape. Reviewer's 4th run: 426.37s. PI-3.5.5-1 canary held across 4 independent invocations.

## Findings

NONE. All 5 framework points clean.

## Rework assignments

N/A (verdict = pass).

## Out-of-triangulation findings

NONE. Smallest LOC delta to date (4 EDITED files, 0 NEW, 0 C++ touches, 0 CMakeLists.txt top-level diff, 0 CHANGELOG diff). PI-7-3.5.5-cpp strongest PI-7 cycle since MVP-3.3 ENTIRE src+include+cmake ZERO-diff. HK-A classifier rigor (4 locked + 2 explicitly unlocked with header-citation evidence) plus HK-B belt-and-suspenders shape exactly matches design's D-3.5.5-1/D-3.5.5-2 reference diff.

Ready to ship.
