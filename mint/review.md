# Review — MVP-1.1A: hybrid-review quick wins (refactor mode) (mint triangulation)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 1 (info-only borderline) | [INFO × 1] |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |

## Triangulation detail

### 1. Spec ↔ Code

**§5.17 — FileList drift correction (`raii.hpp`, `loader.hpp`)** — verified.
- `mint/design.md:28` claims `raii.hpp` declares `BpfSkeleton, XdpAttachment, BpffsDir`.
  Code: `src/loader/raii.hpp:29` (`class BpfSkeleton`), `:74` (`class XdpAttachment`), `:125` (`class BpffsDir`). No stray `BpfObject` or `BpfMap`. ✓
- `mint/design.md:31` claims `loader.hpp` exports `attach()`, `detach()`, and `LoaderError` enum, with allow-list population inline in `attach()`.
  Code: `src/loader/loader.hpp:42` (`std::uint32_t attach(const AttachConfig&)`), `:47` (`std::uint32_t detach(const std::string&)`), `:21-27` (`enum class LoaderError`). No `populate_allowlist()` exported. ✓
- §5.17 "going forward §2 is authoritative contract" — §2 rows at `design.md:28,31` literally match impl. ✓

**§5.18 — `XDPMF_SANITIZERS` build option** — verified end-to-end.
- Option name + default OFF: `CMakeLists.txt:56`
  (`option(XDPMF_SANITIZERS "Build C++ loader with ASAN+UBSAN (test-only)" OFF)`). ✓
- Byte-identical when OFF: flag injection lives entirely inside `if(XDPMF_SANITIZERS) … endif()` at `CMakeLists.txt:85-93`. With OFF default, no `add_compile_options`/`add_link_options` mutation, no target-property mutation, no extra link deps. Confirmed by `git diff HEAD~3..HEAD -- CMakeLists.txt`: the entire delta is two additive comment+block hunks. ✓
- Flags: `-fsanitize=address,undefined -fno-omit-frame-pointer` on compile (`CMakeLists.txt:86-89`), `-fsanitize=address,undefined` on link (`CMakeLists.txt:90-92`). UBSAN+ASAN combined. No TSAN. ✓
- C++ targets only: `target_compile_options(xdpmacfilter PRIVATE …)` scoped to the loader binary, NOT `add_compile_options`. ✓
- BPF object NOT sanitized: `cmake/BpfBuild.cmake:25-47` uses `add_custom_command` with a hand-rolled flag list that does not consume `${CMAKE_C_FLAGS}` or generator-expression-inherited project flags. Sanitizer-isolation invariant documented in a 10-line comment block at `cmake/BpfBuild.cmake:14-24` (purely comment-only change — confirmed by `git diff HEAD~3..HEAD -- cmake/BpfBuild.cmake`; the `function add_bpf_object` body is byte-identical). ✓
- libbpf NOT sanitized: consumed via `pkg_check_modules` as imported target — out of our build's reach. ✓

**§2 new row — `README.md`** — verified.
- File exists at `/home/user/mint-l2-mac-filter/README.md` (109 lines, well over brief's ≥30 floor).
- Sections present in spec order: title (`:1`), "What it does" (`:3-18`), "Prerequisites" + apt line + kernel ≥ 5.15 mention (`:20-37`, kernel floor at `:22`), "Build" (`:42-63`, includes optional sanitizer-build subsection), "Run" (`:65-84`), "Test" (`:86-98`), "Where docs live" pointer (`:100-109`). ✓

**§2 new row — `tests/T_SANITIZER_BUILD.sh`** — file exists, structure matches §6.8 outcomes (see point 2). ✓

**`mint/task-brief-mvp1.md` Dependencies** — `libc++-19-dev` present at `mint/task-brief-mvp1.md:13`. ✓ (Brief calls this a "1-line edit"; the f1e6c18 commit actually renames `task-brief.md → task-brief-mvp1.md` then writes the new MVP-1.1A brief, so in git terms it's `A task-brief-mvp1.md` + `M task-brief.md`. Either way, the dependency line is present and correct. No tag.)

### 2. Spec ↔ Tests

**§6.8 T_SANITIZER_BUILD — every stated outcome has a matching assertion** (no SPEC-UNTESTED, no CIRCULAR-TEST).
- Outcome: "Step 2 build exits 0 with no compiler warnings"
  → Assertion: `tests/T_SANITIZER_BUILD.sh:56` (`cmake --build … | tee -a LOG`) + `:59-63` (`grep -E '(^|[: ])warning:' "${LOG}"` → fail on hit). ✓
- Outcome: "Steps 4 and 7 attach/detach exit 0"
  → Assertion: `tests/T_SANITIZER_BUILD.sh:84,100,114-117` (capture `$?` into `attach_rc`/`detach_rc`, then `[[ … == 0 ]]`). ✓
- Outcome: "`stats[STAT_PASS] == 1` — positive correctness check confirming the sanitized binary actually executed the hot path"
  → Assertion: `tests/T_SANITIZER_BUILD.sh:93` (`read -r pass deny mal < <(read_stats)`) + `:123-124` (`[[ "${pass}" == "1" ]]`). ✓
- Outcome: "captured stderr contains zero matches for ERE `AddressSanitizer|UndefinedBehavior` — match = fail"
  → Assertion: `tests/T_SANITIZER_BUILD.sh:128-132` (`grep -q -E 'AddressSanitizer|UndefinedBehavior' "${STDERR_FILE}" && fail=1`). Negation form per §6.8 spec ("match means fail"). ✓
- ctest properties: TIMEOUT ≥ 120 (`tests/CMakeLists.txt:76` → 180) ✓; RESOURCE_LOCK xdp_fixture (`tests/CMakeLists.txt:75`) ✓; included in default `ctest --test-dir build` run (no label exclusion). ✓
- No-negation-control: per brief explicit relaxation for refactor pass + §6.8 last bullet — `T_NEGATION_CONTROL` (§6.7) remains in the suite as the suite-level floor and ran green this pass.

Assertions target spec-stated **outcomes** (exit codes, BPF-map counter values, stderr content) — not impl-internal state. No CIRCULAR-TEST.

### 3. Code ↔ Tests

Re-ran with the host's sudo per brief: `sudo -E ctest --test-dir /home/user/mint-l2-mac-filter/build --output-on-failure`. Log: `/tmp/mint-review-tests-mvp1.1a-1779522118.log`.

```
1/8 Test #1: T_BUILD ..........................   Passed   13.51 sec
2/8 Test #2: T_LOAD_ATTACH ....................   Passed    1.15 sec
3/8 Test #3: T_PASS_ALLOWED ...................   Passed    2.57 sec
4/8 Test #4: T_DROP_DENY ......................   Passed    2.62 sec
5/8 Test #5: T_DROP_MALFORMED .................***Skipped   1.58 sec
6/8 Test #6: T_IDEMPOTENT_RELOAD ..............   Passed    1.71 sec
7/8 Test #7: T_NEGATION_CONTROL ...............   Passed    2.56 sec
8/8 Test #8: T_SANITIZER_BUILD ................   Passed   26.86 sec

100% tests passed, 0 tests failed out of 8
Total Test time (real) =  52.55 sec
The following tests did not run:
	  5 - T_DROP_MALFORMED (Skipped)
```

- T_DROP_MALFORMED skip is the §6.5-documented kernel-padding limitation (exit 77 → ctest Skipped, with explicit reason). NOT a failure.
- T_SANITIZER_BUILD ran a fresh `/tmp/xdpmf-asan-d0bClf` build with `-DXDPMF_SANITIZERS=ON`, configured + built + attached + injected + observed `stats: PASS=1 DROP_DENY=0 DROP_MALFORMED=0` + detached, all with zero sanitizer hits in captured stderr. Sanitizer build is actually exercised, not just configured. ✓
- No UNEXERCISED-EXPORT applicable: MVP-1.1A introduces no new exported C/C++ symbols (only a CMake option, new test, and docs).

### 4. Out-of-Scope Drift

Brief's anti-drift fence explicitly forbids touching §5.4 hardening / PERCPU stats / `--mode` flag / M+L hybrid-review findings / existing 7 tests during MVP-1.1A.

- `git diff HEAD~3..HEAD --name-only` shows ZERO files under `src/**` were touched. ✓
- `git diff HEAD~3..HEAD -- tests/CMakeLists.txt` is purely additive (T_SANITIZER_BUILD block appended at the bottom; the existing T_BUILD entry and the `foreach(T … T_NEGATION_CONTROL) … endforeach()` block + the `T_DROP_MALFORMED SKIP_RETURN_CODE` + `T_NEGATION_CONTROL WILL_FAIL` property lines are byte-identical to the MVP-1 baseline). ✓
- `git diff HEAD~3..HEAD -- cmake/BpfBuild.cmake` is comment-only (the §5.18 sanitizer-isolation guard documentation block — verified). The `function(add_bpf_object …)` body is unchanged. ✓
- No new files under `src/loader/`, `src/bpf/`, `src/common/`, `include/`. ✓
- No new tests beyond `T_SANITIZER_BUILD.sh`. The existing 7 test scripts in `tests/` were not modified. ✓

Brief acceptance #6 (byte-identical default build): confirmed by the additive-only CMakeLists.txt diff + the `if(XDPMF_SANITIZERS) … endif()` scoping — with the default OFF, zero compile/link flags differ from MVP-1.
Brief acceptance #9 (no test regressions): 6/6 passing pre-existing tests still pass; 1 legitimate environmental skip preserved.
Brief acceptance #10 (zero warnings both configs): T_BUILD covers default build with warning-grep; T_SANITIZER_BUILD covers the asan build with warning-grep at `T_SANITIZER_BUILD.sh:59-63`. Both pass.

## Findings

### [INFO] §5.18 link-options flag list omits `-fno-omit-frame-pointer`
**Location**: `CMakeLists.txt:90-92` (vs `mint/design.md:387-388`)
**Evidence**: design §5.18 line 388 reads "Flags injected (both compile and link): `-fsanitize=address,undefined -fno-omit-frame-pointer`." Code at `CMakeLists.txt:86-89` (compile) includes all three tokens; `:90-92` (link) includes only `-fsanitize=address,undefined`. `-fno-omit-frame-pointer` is missing from the link line.
**Negotiated?**: no (not in `mint/impl-notes.md`)
**Assessment**: practically a no-op — `-fno-omit-frame-pointer` is a codegen flag with no link-time semantics (clang driver accepts-and-ignores it on a link command). The spec's parenthetical "(both compile and link)" most naturally scopes to the `-fsanitize=` token set (which IS on both); the frame-pointer token is a compile-only concern. Sanitizer build works correctly end-to-end (T_SANITIZER_BUILD green). Sub-SPEC-DRIFT severity — not blocking.
**Fix** (optional housekeeping for a future pass): architect tightens §5.18 wording to "compile gets all three flags; link gets `-fsanitize=address,undefined`" — OR impl adds `-fno-omit-frame-pointer` to `target_link_options` for literal compliance (clang will silently drop it).
**Assign to**: architect (preferred; spec clarification) or impl (alternative; trivial edit). Defer to next pass.

## Test execution

```
log: /tmp/mint-review-tests-mvp1.1a-1779522118.log
Internal ctest changing into directory: /home/user/mint-l2-mac-filter/build
Test project /home/user/mint-l2-mac-filter/build
    Start 1: T_BUILD
1/8 Test #1: T_BUILD ..........................   Passed   13.51 sec
    Start 2: T_LOAD_ATTACH
2/8 Test #2: T_LOAD_ATTACH ....................   Passed    1.15 sec
    Start 3: T_PASS_ALLOWED
3/8 Test #3: T_PASS_ALLOWED ...................   Passed    2.57 sec
    Start 4: T_DROP_DENY
4/8 Test #4: T_DROP_DENY ......................   Passed    2.62 sec
    Start 5: T_DROP_MALFORMED
5/8 Test #5: T_DROP_MALFORMED .................***Skipped   1.58 sec
    Start 6: T_IDEMPOTENT_RELOAD
6/8 Test #6: T_IDEMPOTENT_RELOAD ..............   Passed    1.71 sec
    Start 7: T_NEGATION_CONTROL
7/8 Test #7: T_NEGATION_CONTROL ...............   Passed    2.56 sec
    Start 8: T_SANITIZER_BUILD
8/8 Test #8: T_SANITIZER_BUILD ................   Passed   26.86 sec

100% tests passed, 0 tests failed out of 8
Total Test time (real) =  52.55 sec
The following tests did not run:
	  5 - T_DROP_MALFORMED (Skipped)
EXIT=0
```

## Summary

All four triangulation points line up. The amendments do what the spec says, the spec says what the test asserts, the test exercises what the code does, and nothing outside the brief's 3-item scope was touched. The single INFO finding is a borderline literal-vs-intent reading of §5.18 line 388 — non-functional and not blocking. Refactor-mode workflow stress test on this codebase: clean run, no leakage into out-of-scope items, byte-identical default-build invariant preserved.

**Verdict: pass.**
