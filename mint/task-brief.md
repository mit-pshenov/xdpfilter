# Task brief — MVP-2 Polish-2: netns isolation + CMake-gen + version-sync + inject_runt:37 (refactor mode)

## Goal

Knock down the four remaining janitorial items deferred to MVP-2 Polish-2 throughout MVP-1.1C and MVP-2 Sec/Perf/Robust. This is **the final MVP-2 slice** — after this, the MVP-2 sequence is fully shipped and the project enters MVP-3 territory.

All four items are non-behavioural (no exit codes, no public API touches, no CLI surface changes) — pure hardening/cleanup. Similar in shape to MVP-1.1C polish batch but with only 4 items instead of 12, each item more substantive (the netns refactor and CMake-gen items each touch real infrastructure).

## Context: prior work

- **All prior briefs**: `mint/task-brief-mvp1{,.1a,.1b,.1c}.md` + `mint/task-brief-mvp2-{sec,perf,robust}.md`.
- **Existing design**: `mint/design.md` — ~3260 lines through §5.24 + §6.20 + §7 MVP-2 Sec/Perf/Robust additions. Each Polish-2 item has explicit OOS fence pointing here.
- **MVP-2 Robust review**: `mint/review.md` (round-1 pass, 1 negotiated minor resolved via EDIT-12).
- **Hybrid review source**: `mint/hybrid-review.md` — items M3/M5/M6 (most of these) + the architect-fenced deferral entries during MVP-1.1C and MVP-2 Sec/Perf decisions.
- **Origin trail per item**:
  - **netns Path A** — MVP-1.1C §5.21 C3 Decision 1: "Path A is recorded as MVP-2 hardening" (§7 line 1428-1433).
  - **CMake-gen `PIN_ROOT`** — MVP-1.1C §5.21 B3 Decision: "CMake-generation of `tests/lib/common.sh:PIN_ROOT` … MVP-2 hardening" (§7 line 1434-1438).
  - **Version-string sync** — MVP-1.1C §5.21 B4 Decision: "no version-string sync between CHANGELOG.md and the loader binary's `--version` output" (§7 line 1439-1444).
  - **inject_runt.py:37 inline comment** — MVP-1.1C reviewer OUT-OF-TRIANGULATION advisory in `mint/review.md` (the latest one before MVP-2 series).

## Workflow rules (refactor mode — same as all prior slices)

- **Architect**: read existing `design.md` (focus the four deferred entries cited above + §6.x test-fixture invariants the netns refactor touches) + this brief. EDIT design.md in place. Append `§5.25 MVP-2 Polish-2 batch` after §5.24. Update §7 OOS — move all four items from deferred to shipped. Each item warrants explicit decision documentation since the mechanism choice has real ripple (netns affects every veth-fixture test).
- **Impl**: EDIT relevant files. **Probable** loader.cpp touch for version-string (if architect's Q3 picks runtime constant injection vs compile-time `configure_file`). loader.hpp probably untouched (version is in cli.cpp / generated header). New CMake codegen files in `cmake/` or `include/` per architect's choice.
- **Tester**: HEAVY EDIT to `tests/lib/common.sh` for netns infrastructure (this is the bulk of the work). Existing 20 tests must still pass — netns is transparent to test bodies if the helper API stays the same (`setup_veth`/`cleanup_veth` semantics preserved). May add small fixture-test for the CMake-gen `PIN_ROOT` correctness (~optional per architect Q2).
- **Reviewer**: 4-point triangulation. Special attention: (1) netns refactor must not break any existing test — 20/20 pass is the regression floor; (2) `PIN_ROOT` codegen must produce byte-identical value to current hardcoded string (otherwise loader+tests diverge); (3) version-string sync must not break smoke-test `--version` assertions (T_CLI_HELP_VERSION).

## Open mechanism questions (architect decides; document in §5.25)

### Q1: netns isolation mechanism

**Option N1 (per-test netns)**: each `T_*.sh` test creates its own netns (`ip netns add xdpmf-test-${$}_${test_name}`), spins veth pair INSIDE the netns, runs loader + injects inside the netns, teardown nukes the netns. Strongest isolation; ~+0.5s per test for netns create/destroy.

**Option N2 (shared-namespace pool)**: one netns per ctest invocation (created at suite start, destroyed at suite end); all tests use it. Lighter overhead; less isolation between tests (each test still has to clean its own veth pair).

**Option N3 (setup_veth-level wrap)**: `tests/lib/common.sh setup_veth` transparently runs the veth-pair lifecycle inside a netns; test bodies stay byte-identical. The netns is per-`setup_veth` call. Architect-recommended path: keeps test bodies untouched, centralizes the netns logic in one place.

**Option N4 (keep PID-suffix)**: don't actually do netns; close the §7 item as "Path B was sufficient, Path A explicitly declined as overkill". Honest if architect determines netns isolation is theoretical-only on a single-user dev host.

Architect picks. **N3** is the recommended default — minimum blast radius across existing tests. If architect picks N4, document why netns is unnecessary in practice (and update the §7 line 1428-1433 entry accordingly).

### Q2: CMake-gen mechanism for `PIN_ROOT`

The header `src/common/mac_filter.h:41` defines `#define XDPMF_BPFFS_ROOT "/sys/fs/bpf/xdpmacfilter"`. `tests/lib/common.sh:34` mirrors this as `PIN_ROOT=/sys/fs/bpf/xdpmacfilter`. The MVP-1.1C B3 fix added a comment marker; this slice replaces the manual mirror with codegen.

**Option C1 (sed/awk extraction in CMake)**: CMake runs `execute_process(COMMAND sed -nE 's/.*XDPMF_BPFFS_ROOT[ \t]+"([^"]+)".*/\1/p' src/common/mac_filter.h)` at configure time, exports the value to a generated `tests/lib/pins.sh` companion (which `common.sh` sources). Simple, no extra build target.

**Option C2 (C preprocessor extraction)**: `cpp -E -dD -I src/common src/common/mac_filter.h | grep XDPMF_BPFFS_ROOT`. More robust against header reformat but requires `cpp` invocation at configure time.

**Option C3 (companion `.h.in` + `configure_file`)**: split the macro into a `mac_filter.h.in` template + `configure_file()` driven by a CMake variable; the variable is the source of truth, both the header AND the shell mirror are generated from it. Most "correct" but reorganizes the source-of-truth.

**Option C4 (decline, keep manual mirror + comment marker)**: deem the MVP-1.1C B3 comment-marker sufficient; codegen is overkill for a single constant.

Architect picks. **C1** is the recommended pragmatic choice — solves the actual problem (silent drift if header is renamed) with minimum new infrastructure.

### Q3: Version-string sync mechanism

Currently:
- `CMakeLists.txt:13` says `VERSION 0.1.0` (project version).
- `src/loader/cli.cpp:21` says `constexpr std::string_view kVersion = "0.1.0";` (hardcoded in source).
- `CHANGELOG.md` has entries `[0.1.0]`..`[0.2.2]`.
- Loader's `--version` output: `xdpmacfilter 0.1.0` (stuck at the initial value across all subsequent MVP releases).

The MVP-1.1C B4 OOS rationale was "CHANGELOG versions are documentary only; loader's compiled-in --version is independent and unchanged". Polish-2 closes the loop.

**Option V1 (project(VERSION) as source-of-truth)**: bump `CMakeLists.txt:13 VERSION 0.1.0` → `VERSION 0.2.3` (post-Polish-2). Generate a `version.h` (via `configure_file`) from `${PROJECT_VERSION}`. cli.cpp `#include "version.h"` and uses the generated constant. CHANGELOG entries (kept manually) document changes; CMake version is the binary-shipped truth.

**Option V2 (CHANGELOG as source-of-truth)**: parse the latest `[X.Y.Z]` heading from CHANGELOG.md at CMake configure time (sed/awk), feed into `project(VERSION)`, propagate via `configure_file`. CHANGELOG becomes load-bearing for build.

**Option V3 (decline, document the disconnect)**: keep the manual disconnect, update §5.21 B4 deferral entry to "permanent — versions stay split". Honest only if architect judges the sync not worth the build pipeline complexity.

Architect picks. **V1** is the recommended path — `project(VERSION)` is the canonical CMake idiom; `configure_file` is one new file; cli.cpp gains one `#include` swap.

### Q4: T_CLI_HELP_VERSION test interaction

`tests/T_CLI_HELP_VERSION.sh` currently asserts `--version` matches ERE `xdpmacfilter.*[0-9]+\.[0-9]+\.[0-9]+`. This is loose enough to survive the version change (still passes for `xdpmacfilter 0.2.3`). But: should the test also assert version-monotonicity (e.g., reject `0.1.0` as too-old after Polish-2)?

**Option T1 (no test edit)**: regex is forward-compatible; the test passes as-is. Polish-2 doesn't touch the test.

**Option T2 (strict assertion)**: test asserts `--version` equals a specific value (e.g., `xdpmacfilter 0.2.3`). Forces tester to update the test every release — couples test maintenance to version bumps. Probably overkill.

Architect picks. **T1** is the floor; **T2** only if architect wants version-regression protection.

## Scope (4 items — anything else is OOS)

### Item 1 — netns isolation (per architect Q1)

**Where**: `tests/lib/common.sh` (the heavy edit — `setup_veth`/`cleanup_veth` and any helper functions involved); possibly `tests/T_BPFFS_ROOT_SYMLINK.sh` and `tests/T_MODE_NATIVE_UNSUPPORTED.sh` (the two tests that don't use the standard veth fixture — netns may or may not apply).

**Action**: per architect's Q1 mechanism choice. If Q1 = N3, `setup_veth` becomes a thin wrapper that creates a netns + spawns the veth pair inside it; test bodies stay byte-identical. If Q1 = N4 (decline), update design.md §7 line 1428-1433 to "permanent decline" and skip this item.

### Item 2 — CMake-gen `PIN_ROOT` (per architect Q2)

**Where**: `CMakeLists.txt` (configure-time codegen step), `tests/lib/common.sh:33-34` (replace hardcoded mirror with sourced value), possibly `tests/CMakeLists.txt` for wiring.

**Action**: per Q2 mechanism choice. If Q2 = C1, add a `configure_file` or `file(GENERATE)` step that emits `tests/lib/pins.sh` with `PIN_ROOT="<extracted value>"`; common.sh sources it. Verify the generated value byte-equals the current hardcoded `/sys/fs/bpf/xdpmacfilter`.

### Item 3 — Version-string sync (per architect Q3)

**Where**: `CMakeLists.txt:13` (bump VERSION), `src/loader/cli.cpp:21` (replace hardcoded constant), new `include/version.h.in` or similar template per Q3.

**Action**: per Q3 mechanism choice. If Q3 = V1, bump `project(VERSION)` to `0.2.3`, add `configure_file(include/version.h.in include/version.h)`, cli.cpp includes the generated header. Verify `--version` output now reads `xdpmacfilter 0.2.3`.

### Item 4 — `inject_runt.py:37` inline comment fix (MVP-1.1C reviewer advisory)

**Where**: `tests/inject/inject_runt.py:37` (a single inline comment line).

**Action**: rewrite the comment to match the corrected docstring + actual bytes. The docstring (lines 14-19) says "13 bytes — full 6-byte dst MAC + full 6-byte src MAC + 1 ethertype byte"; the inline comment at :37 currently says "13 bytes: complete 6-byte dst MAC + partial src MAC" (wrong — src is complete, ethertype is partial). One-line edit.

## Out of scope (explicit)

- **Any behaviour change to loader CLI surface** — `--help` / `--version` semantics + exit codes unchanged.
- **Any new CLI flag** (e.g., `--no-version-probe`, `--bpf-object-path`) — explicitly fenced from MVP-2 Robust additions; stays MVP-3+.
- **CHANGELOG version-policy change** — Polish-2 syncs the loader binary version with CHANGELOG; the policy of "manual CHANGELOG editing per slice" is unchanged.
- **MVP-3 feature work** — no new features. Polish-2 is pure cleanup.
- **README updates** — README's kernel-floor + dependency list is current per MVP-2 Robust; no need to touch unless Q1 netns choice affects test-run instructions.
- **`tests/inject/inject_runt.py` body rewrite** — Item 4 is comment-only; do NOT touch the bytes themselves.

## Definition of done

- §5.25 amendment in `design.md` documenting Q1/Q2/Q3/Q4 decisions with rationale
- §7 OOS — all four Polish-2 items moved from deferred to shipped (or explicitly declined per architect's Q-options)
- Per-item file changes per scope above
- 20 ctest entries still pass (or legitimately SKIP per §6.5); the netns refactor is the main regression risk
- `XDPMF_SANITIZERS=ON` build clean
- Loader's `--version` reflects the new version (per Q3)
- `mint/review.md` round-1 verdict = `pass`
- One git commit per phase boundary per workflow B

## Dependencies

No new system dependencies. `ip netns` is `iproute2` (already required for `ip link`). `sed`/`awk` POSIX. `configure_file` is core CMake. No new C++ libraries.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
packs:
  architect:  []
  impl:       [lang/cpp.md, lang/cmake.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []
```
