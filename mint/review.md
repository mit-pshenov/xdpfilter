# Review — MVP-3.4f Theme B extraction + audit-escape policy extension (mint triangulation, brownfield 5-point)

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
| OOT (does not affect verdict) | 1 | inline-merge × 1 |

## Detailed triangulation

### 1. Spec ↔ Code

- NEW `src/common/escape_util.hpp` (D-3.4f-4, design.md:12211-12269 + 12338-12340) → pragma once + `namespace xdpmf::escape_util` + 3 free function decls (`escape_json` / `escape_audit` / `format_timestamp_utc`), stdlib-only includes. Matches Interfaces block verbatim (escape_util.hpp:1-67). ✓
- NEW `src/common/escape_util.cpp` body shape (design.md:12271-12296):
  - `escape_json` byte-equivalent to pre-§5.37 logger.cpp:68-92 / sidecar.cpp:93-117 (compared via `git show c55f6e5` — identical 7-named-switch + `<0x20 → \u00xx` lowercase via `std::format("\\u{:04x}", ...)`). ✓
  - `escape_audit` extended form with named-5 hit FIRST + extended branch `if (c < 0x20 || c == 0x7F) → std::format("\\x{:02x}", c)` exactly as specified at escape_util.cpp:52-80. ✓
  - `format_timestamp_utc` byte-equivalent to canonical sidecar.cpp:70-87 form at escape_util.cpp:82-99. ✓
- D-3.4f-1 EXPLICIT OVERRIDE rationale CITED at design.md:12303-12320 — cites §5.32 D-3.5-2 + §5.35 D-3.4d-6 + body-count 6 + module-count 4 + cross-dimensional /mint-review trigger. Inline supersession markers verified at design.md:8946 + 11044. ✓
- D-3.4f-5 rename adoption: post-rename grep `grep -rn 'json_escape\|escape_audit_value' src/ include/` returns 5 hits, ALL inside doc-comments referencing the historical pre-§5.37 names (logger.cpp:9,47 + sidecar.cpp:68 + reset_counters.cpp:26 + escape_util.hpp:33,39). ZERO actual call-sites or declarations use old names. Per D-3.4f-5 inline-merge clause + §5.37 invariants-block MAY-resolution rule, historical doc-comment citations are not contract drift. ✓
- D-3.4f-6 include-path convention: 5 `#include "common/escape_util.hpp"` lines across logger.cpp:18 + sidecar.cpp:37 + bypass.cpp:19 + reset_counters.cpp:38 + escape_util.cpp:17 (4 callers + self). Matches verifiable invariant #3. ✓
- D-3.4f-7 dup-TU: `escape_util.cpp` listed in BOTH `xdpmf_internal` (CMakeLists.txt:119) AND `xdpmf-exporter` (CMakeLists.txt:148) source lists with `§5.37 (MVP-3.4f)` annotations. Q6=B1 pattern preserved; build green. ✓
- Call-site enumeration (vs design.md:12077-12080 + EDIT-1 §5.37 FileList): 11 FQN call-sites total — logger.cpp 5×escape_json (:110,152,158,166,177) + 1×format_timestamp_utc (:144); sidecar.cpp 1×escape_json (:85) + 1×format_timestamp_utc (:88); bypass.cpp 2×escape_audit (:183,193); reset_counters.cpp 1×escape_audit (:89). Total 5+2+1+1+1+1=11. Matches Phase A grep #2 + invariant #4 (≥11). No `using`-elision; all FQN form per D-3.4f-5 preference. ✓
- D-3.4f-8 throw-semantic: escape_util functions return `std::string` non-noexcept; escape_util.cpp:9-10 + .hpp:14-19 header comment cites call-site catch envelopes. JSON-shape + sidecar tests GREEN → PI-32-3.4b PRESERVED by construction. ✓

### 2. Spec ↔ Tests

- T-1 `T_BYPASS_AUDIT_CONTROL_CHARS.sh` at FileList path + registered via `add_test` + `set_tests_properties` block with `RESOURCE_LOCK xdp_fixture` + `TIMEOUT 60` + `SKIP_RETURN_CODE 77` at tests/CMakeLists.txt:929-939 (15 LOC additive). Matches EDITED row exactly. ✓
- Sub-case (a) — extended bytes: T-1:81-83 triggers `--reason $'\x01\x07\x0b\x0e\x1f\x7f tail'` (all 6 literal bytes per §5.37 + EDIT-1 spec — NOT a sample); :106 asserts literal `\x01\x07\x0b\x0e\x1f\x7f` substring via `grep -qF`; :117 asserts trailing `tail` (anti-truncation); :127 asserts NO raw 0x01 byte in stderr (negation control). ✓
- Sub-case (b) — 4-of-5 named escapes via integration per EDIT-1: T-1:147-148 triggers `--reason $'has\\backslash and \"quote and\nnewline and\rCR tail'` (omits `\0NUL` per EDIT-1 argv-truncation rationale, retains `\r` per EDIT-1 "CR IS argv-passable" ruling); :172-179 assert `\\backslash`, `\"quote`, `\nnewline`, `\rCR` literals in audit-line; :184-192 anti-theatricality assert NO `\x0a` or `\x0d` substring (named precedence). Matches design.md:12581-12589 verbatim. ✓
- `\0` named-case via code-review (EDIT-1 verifiable invariant #15): `grep -nE "case '\\\\0':" src/common/escape_util.cpp` returns exactly 1 hit at line 66 (`case '\0': out.append("\\0");  break;`). Body byte-equivalent to pre-§5.37 reset_counters.cpp:67 — verified via `git show c55f6e5`. PI-3.4f-3 `\0` coverage satisfied via code-review per D-3.4f-EDIT-1-NUL-INTEGRATION-OOS. ✓
- Sub-case (c) — printable ASCII negation control: T-1:201-238 triggers `--reason 'simple_safe-reason.42'`; asserts literal substring present + asserts NO `\x` substring (printable-branch quiet). Combined with sub-case (b) anti-theatricality + sub-case (a) raw-byte negation gives multiple known-bad-input checks → NO-NEGATION-CONTROL not triggered. ✓
- PI-3.4f-1 byte-equivalence canaries: 6 existing JSON-shape + audit-line tests cited at design.md:12455-12465 all PASS (T_LOG_JSON_BYPASS_AUDIT, T_LOG_JSON_LOADER_EVENTS, T_LOG_JSON_EXPORTER_EVENTS, T_LOG_JSON_ENVELOPE_INVARIANTS, T_SIDECAR_JSON_SHAPE, T_BYPASS_CMD_DETACHES). ✓

### 3. Code ↔ Tests

`ctest --test-dir build -j4 --output-on-failure` (reviewer rerun) → **67/67 PASS, 0 FAIL, 2 SKIP** (T_DROP_MALFORMED + T_ANSIBLE_PLAYBOOK_SYNTAX — pre-existing environment skips). Byte-identical to tester's `mint/test-run.log`. Total 539.90 sec. Log: `/tmp/mint-review-tests-1779900034.log`.

UNEXERCISED-EXPORT spot-check: all 3 escape_util exports exercised — `escape_json` via 6+ JSON-shape ctests; `escape_audit` via NEW T_BYPASS_AUDIT_CONTROL_CHARS + 3 sibling audit-line ctests; `format_timestamp_utc` via T_LOG_JSON_* + T_SIDECAR_JSON_SHAPE. Zero unexercised exports.

### 4. Out-of-Scope Drift

Spot-checked §7 OOS items (design.md:12508-12527): KC-1 action label escape, KC-2 exporter `--bind` WARN, BpffsDir/XdpAttachment deletion, dispatch_match helper, xdpmf_logger STATIC promotion, module rename to `log_util`, `xdpmf_common` static lib, `sudo_user` env-lookup extraction, tab disposition, JSON-mode `\xHH` parity, VERSION bump, README/HANDOFF rewrite — ALL untouched. `git diff c55f6e5..HEAD --stat` confirms source/test edits are precisely the FileList: src/common/escape_util.{hpp,cpp} (NEW) + src/cli/bypass.cpp + src/cli/reset_counters.cpp + src/common/logger.cpp + src/lib/sidecar.cpp + CMakeLists.txt (EDITED) + tests/T_BYPASS_AUDIT_CONTROL_CHARS.sh (NEW) + tests/CMakeLists.txt (EDITED). Zero scope creep.

### 5. Behaviour preserved (brownfield §6.5)

| PI | Result |
|---|---|
| PI-7-3.4f-hpp (12th ZERO-diff) | `git diff c55f6e5..HEAD -- src/common/logger.hpp` empty ✓ |
| PI-7-3.4f-cpp (7th ZERO-diff) | `git diff c55f6e5..HEAD -- src/lib/config.hpp` empty ✓ |
| PI-7-3.4f-loader-hpp | `git diff c55f6e5..HEAD -- src/lib/loader.hpp` empty ✓ |
| PI-7-3.4f-mac-filter-h | `git diff c55f6e5..HEAD -- src/common/mac_filter.h` empty ✓ |
| PI-32-3.4b PRESERVED | T_SIDECAR_JSON_SHAPE PASS → sidecar catch envelope intact ✓ |
| PI-3.5-1 PRESERVED | T_LOG_TEXT_BYTE_EQUIVALENT PASS → text-mode stderr byte-identical ✓ |
| PI-3.5-7 PRESERVED | `grep -nE 'find_package\|pkg_check_modules\|FetchContent' CMakeLists.txt` returns 2 pre-existing hits; zero new deps ✓ |
| §5.36 PI-3.4e-1 + PI-3.4e-2 + KC-3 closure PRESERVED | T_RESET_COUNTERS_PATH_TRAVERSAL + T_SIDECAR_IFACE_SYMLINK_REFUSAL both PASS ✓ |
| PI-3.4f-1 NEW (escape_json + format_timestamp_utc byte-equiv extraction) | Bodies byte-equivalent vs `git show c55f6e5`; JSON-shape canaries GREEN ✓ |
| PI-3.4f-2 NEW (extended \xHH policy operational) | T_BYPASS_AUDIT_CONTROL_CHARS sub-case (a) PASS — extended-policy branch active for 6 bytes ✓ |
| PI-3.4f-3 NEW (5 named escapes backward-compat) | T-1 sub-case (b) PASS for 4 named; `\0` covered via escape_util.cpp:66 per EDIT-1 invariant #15 ✓ |
| PI-6 (ctest baseline) | 66 → 67 (+1 NEW T-1; ZERO existing ctest body EDITs per `git diff c55f6e5..HEAD --stat tests/`) ✓ |
| PI-10 (additive-only header invariants) | `git diff c55f6e5..HEAD -- src/lib/ src/cli/ src/common/*.hpp src/common/*.h` shows additions only in escape_util.hpp (NEW); no edits to existing headers ✓ |

No REGRESSION: ctest delta from baseline = +1 NEW PASS; 0 prior-green tests went red.

No UNRELATED-EDIT: `git diff c55f6e5..HEAD --stat -- src/ tests/ CMakeLists.txt` shows ONLY the 9 expected files. Admin edits to mint/design.md + mint/task-brief*.md are meta-files outside FileList scope (expected).

Anti-misdiagnosis guards #20 (rule-of-three escape-valve activation) + #21 (TestStrategy IO-model audit) verified present in design.md §5.37 + EDIT-1. Catalog now at 21.

## Test execution

```
100% tests passed, 0 tests failed out of 67

Total Test time (real) = 539.90 sec

The following tests did not run:
    5 - T_DROP_MALFORMED (Skipped)
   35 - T_ANSIBLE_PLAYBOOK_SYNTAX (Skipped)
```

Reviewer log: `/tmp/mint-review-tests-1779900034.log`. Byte-identical to tester `mint/test-run.log`.

## Findings

NONE.

## Rework assignments

N/A (verdict = pass).

## Out-of-triangulation findings

### OOT-1: `escape_util.hpp` doc-comment miscounts named-escape set as "5" while listing 7
**Location**: `src/common/escape_util.hpp:29-30`
**Disposition**: `inline-merge`
**Rationale**: hpp comment block reads "5 named: `\\`, `\"`, `\n`, `\r`, `\t`, `\b`, `\f`" — the prefix says "5 named" but the list enumerates 7 names. The pre-§5.37 `json_escape` body at logger.cpp:68-92 / sidecar.cpp:93-117 (verified via `git show c55f6e5`) had 7 named escapes (the same 7); new escape_util.cpp:26-50 body is byte-equivalent. Design wording at design.md:12072 + 12275 also says "5 named" with the same RFC-8259 7-name list — sloppy wording inherited into the .hpp comment. No contract breach; cited list is correct; only the leading numeral disagrees.

---

**Triangulation summary**: Theme B extraction clean. Rule-of-three escape valve activated for guard #9 per cross-dimensional /mint-review signal. PI-7-3.4f-hpp **12th** + PI-7-3.4f-cpp **7th** consecutive ZERO-diff streak (strongest streaks in project history extended). Sec M1 (KC-1 control-char limb) closed via PI-3.4f-2 operational evidence + PI-3.4f-3 backward-compat preserved across integration (4 of 5 named) + code-review (1 named via `\0` invariant #15). NEW guards #20 + #21 added to anti-misdiagnosis catalog. ZERO test failures across 67/67 in 2 independent runs.

### Post-review sweep — round 1

OOT-1 disposed as `inline-merge`. Edits ride in Phase 6 final commit.

- **OOT-1** → `src/common/escape_util.hpp:29` (`5 named` → `7 named`); `mint/design.md:12072` (`5 named escapes` → `7 named escapes` with full name list inlined); `mint/design.md:12275` (`switch over 5 named` → `switch over 7 named` with full name list inlined). Numeral prose hygiene; zero code/behavior impact; existing 67/67 PASS unchanged.

No `defer` or `promote-to-rework`. Verdict stays `pass` round-1.
