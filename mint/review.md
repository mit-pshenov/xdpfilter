# Review — MVP-3.4g dead-code delete BpffsDir + XdpAttachment (mint triangulation, brownfield 5-point)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 (67/67 pass + 2 SKIP-77 baseline) | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |
| OOT (does not affect verdict) | 0 | — |

## Detailed triangulation

### Point 1 — Spec ↔ Code (D-3.4g-1..7 + FileList)

- **D-3.4g-1** (strict delete IfaceDirGuard preamble per Q1.A1): confirmed at `src/lib/loader.cpp:727` — 5-line §5.22 cite-preamble vanished; `class IfaceDirGuard` stands alone. ✓
- **D-3.4g-2** (`#include <filesystem>` drop): `grep -nE 'std::filesystem|<filesystem>|fs::' src/lib/raii.hpp` → 0 hits ✓ (verifiable invariant #2)
- **D-3.4g-3** (NO VERSION bump): no VERSION* changes in `git diff 7519ae3..HEAD --stat` ✓
- **D-3.4g-4** (NO new ctests): `tests/` byte-identical vs 7519ae3 ✓
- **D-3.4g-5** ([SUPERSEDED BY §5.38] 2-marker scope per HG-3.4g-4): `grep -nE '\[SUPERSEDED BY §5\.38\]' mint/design.md` → 2 hits at design.md:11836 + :12514 ✓; 5 archived refs at :28, :569-585, :903 confirmed untouched
- **D-3.4g-6 / -7** (NEW FENCES: no IfaceDirGuard rename, no raii.hpp relocation): no rename/move in diff ✓
- **FileList — src/lib/raii.hpp** (design.md:12700): full 114-LOC deletion (XdpAttachment :74-115 + comment :117-131 + BpffsDir :132-177 + `<filesystem>` :14). Result 1-65: only `BpfSkeleton` survives — verifiable invariant #5 `grep -nE '^class BpfSkeleton' src/lib/raii.hpp` → exactly 1 hit at :28 ✓
- **FileList — src/lib/loader.cpp** (design.md:12701): "; XdpAttachment unwinds" sub-clause dropped at :28-31; rewritten sentence matches architect-suggested wording; 5-line preamble at :727-731 deleted. -7 LOC actual (2282 vs prior 2289). Sentence flow preserved and reads cleanly. ✓
- **FileList — CHANGELOG.md** (design.md:12703): +3 lines (Housekeeping subhead + blank + entry) at CHANGELOG.md:7-9. ✓
- **FileList — mint/design.md**: §5.38 appended (12647-12809), 2 SUPERSEDED markers placed at Phase A. ✓

### Point 2 — Spec ↔ Tests (TestStrategy = T-baseline-67 only)

- **T-baseline-67** (design.md:12742): `ctest --output-on-failure -j4` → exit 0, 67/67 PASS (2 legitimate SKIP). Captured at `/tmp/mint-review-tests-1779904805.log`. ✓
- HG-3.4g-3 confirms NO new ctests required (pure deletion has no novel behavior). NO-NEGATION-CONTROL is N/A per architect spec for this cycle.

### Point 3 — Code ↔ Tests

Reviewer's independent `ctest -j4` rerun → **67/67 PASS, 0 FAIL, 2 SKIP** (T_DROP_MALFORMED + T_ANSIBLE_PLAYBOOK_SYNTAX). 550.90 sec wall-clock vs tester's 544.23 sec (sub-2% variance, same skip set). Log: `/tmp/mint-review-tests-1779904805.log`. Byte-similar to tester's mint/test-run.log.

UNEXERCISED-EXPORT: N/A (deletion only; no new exports).

### Point 4 — Out-of-Scope Drift

`git diff 0297223..HEAD --stat` (impl/tester scope, post-design commit) = exactly 3 files: CHANGELOG.md (+3), src/lib/loader.cpp (-7), src/lib/raii.hpp (-114). All in FileList. ✓

No NEW FENCE breached: no IfaceDirGuard rename (D-3.4g-6), no raii.hpp relocation (D-3.4g-7), no VERSION bump (D-3.4g-3), no doc-rewrite cascades (README/HANDOFF/docs/BACKLOG untouched), no carry-forward OOS items addressed (KC-1/KC-2/Theme D etc. all untouched). ✓

### Point 5 — Behaviour preserved (brownfield §6.5)

| PI | Result |
|---|---|
| PI-7-3.4g-hpp (13th ZERO-diff) | `git diff 7519ae3..HEAD -- src/common/logger.hpp` empty ✓ |
| PI-7-3.4g-cpp (8th ZERO-diff) | `git diff 7519ae3..HEAD -- src/lib/config.hpp` empty ✓ |
| PI-7-3.4g-loader-hpp | `git diff 7519ae3..HEAD -- src/lib/loader.hpp` empty ✓ |
| PI-7-3.4g-mac-filter-h | `git diff 7519ae3..HEAD -- src/common/mac_filter.h` empty ✓ |
| PI-32-3.4b PRESERVED | T_SIDECAR_JSON_SHAPE green → sidecar catch envelope intact ✓ |
| PI-3.5-1 PRESERVED | T_LOG_TEXT_BYTE_EQUIVALENT green → text-mode stderr byte-identical ✓ |
| PI-3.5-7 PRESERVED | `<filesystem>` removal is a reduction; CMakeLists.txt byte-identical; zero new deps ✓ |
| §5.22 BpffsRootFd / IfaceDirGuard PRESERVED | class IfaceDirGuard body at loader.cpp:727-773 byte-equivalent post-delete (only :727-731 preamble + :29 rollback-prose changed — both per design) ✓ |
| §5.36 KC-3 closure PRESERVED | T_RESET_COUNTERS_PATH_TRAVERSAL + T_SIDECAR_IFACE_SYMLINK_REFUSAL green ✓ |
| §5.37 PI-3.4f-1/-2/-3 PRESERVED | T_BYPASS_AUDIT_CONTROL_CHARS + JSON-shape suite green ✓ |
| PI-3.4g-1 NEW (dead-code byte-equivalent runtime) | all 67 pre-§5.38 ctests stay green ✓ |
| PI-3.4g-2 NEW (`<filesystem>` dropped without ripple) | clean `cmake --build build`; zero new TU includes ✓ |
| PI-6 (ctest baseline 67→67) | ✓ |
| PI-10 RELAXED for raii.hpp | only deletions in raii.hpp; no other header touched ✓ |
| Verifiable invariant #1 (zero src/+tests/+include/ hits for retired types) | 0 hits ✓ |
| Verifiable invariant #5 (BpfSkeleton survives) | exactly 1 hit at :28 ✓ |
| Verifiable invariant #8 (full sweep, ≤2 hits expected post-impl) | 2 hits in CHANGELOG.md — :9 new entry + :506 archived (matches impl's SHOULD-hint deviation #3 inline-merge per §5.38 resolution rule at design.md:12734) ✓ |
| Verifiable invariant #9 (CHANGELOG +1 hint operative-semantic) | impl used +3 (Housekeeping subhead + blank + entry); within explicit anchor-formatting allowance per design.md:12734 ✓ |
| Verifiable invariant #3 (raii.hpp ~80-90 LOC SHOULD-hint) | impl got 65 LOC (absent inter-class spacing); operative-semantic per resolution rule ✓ |

No REGRESSION: ctest delta = 0 (67→67).
No UNRELATED-EDIT: only 3 files in scope per FileList.

Anti-misdiagnosis catalog stays at 21 (no new guards; mechanical slice exercising existing guard #5 Phase A code-grep discipline cleanly).

## Test execution

```
100% tests passed, 0 tests failed out of 67

Total Test time (real) = 550.90 sec

The following tests did not run:
    5 - T_DROP_MALFORMED (Skipped)
   35 - T_ANSIBLE_PLAYBOOK_SYNTAX (Skipped)
```

Reviewer log: `/tmp/mint-review-tests-1779904805.log`. Byte-similar to tester `mint/test-run.log`.

## Findings

NONE.

## Rework assignments

N/A (verdict = pass).

## Out-of-triangulation findings

NONE. The 3 SHOULD-hint deviations flagged by impl (raii.hpp 65 LOC vs ~80-90 hint; CHANGELOG +3 vs +1; sweep 2 hits vs 1) are PRE-DISPOSED to inline-merge by architect's §5.38 resolution rule (design.md:12734) and SHOULD-hint annotations in verifiable invariants #1/#3/#8/#9. No reviewer disposition needed; no orchestrator Phase 4.5 sweep action.

---

**Triangulation summary**: smallest impl footprint in the §5.x series (3 files, -118 LOC net). All 5 framework points come up clean on the first round. PI-7-3.4g-hpp = **13th** + PI-7-3.4g-cpp = **8th** consecutive ZERO-diff streak (new project records — strongest streaks in project history). Phase A grep discipline (guard #5) successfully eliminated the entire dead-code class without surfacing surprises. **First ZERO-OOT round-1 pass** in the OOT-tracking trajectory (5 → 2 → 2 → 2 → 1 → **0**).
