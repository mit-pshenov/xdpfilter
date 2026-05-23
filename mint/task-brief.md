# Task brief — MVP-1.1C: hybrid-review polish batch (refactor mode)

## Goal

Knock down the long tail of LOW/MEDIUM polish items from `mint/hybrid-review.md` that survived the first two refactor passes (MVP-1.1A landed quick wins #1-3, MVP-1.1B landed trust-boundary items #4-6+9). Everything in this brief is from synthesizer's "Top actionable list" items #10-15 plus four sub-items from the testing-reviewer LOW table — no design re-thinks, no architectural changes, no new design contracts.

This is the **third refactor pass** on the MVP-1 codebase. Scope is wide (12 items) but per-item depth is shallow: most are ≤10 LOC. The point of bundling is to clean the whole polish backlog in one /mint cycle.

## Context: prior work

- **MVP-1 brief**: `mint/task-brief-mvp1.md`
- **MVP-1.1A brief**: `mint/task-brief-mvp1.1a.md`
- **MVP-1.1B brief**: `mint/task-brief-mvp1.1b.md`
- **Existing design**: `mint/design.md` — already amended through §5.20 + §6.9; **this pass appends §5.21 + new §6.x as needed**
- **MVP-1.1B review**: `mint/review.md` (round-1 pass, overwritten each cycle)
- **Hybrid review source**: `mint/hybrid-review.md` — the synthesized report. All scope items reference its line numbers / Top-actionable-list IDs.

## Workflow rules (refactor mode — same as MVP-1.1A/B)

- **Architect**: read existing `design.md` + `hybrid-review.md` + this brief. EDIT design.md in place. Append a single new amendment block (e.g. `§5.21 — MVP-1.1C polish batch (2026-05-23)`) summarising the 12 changes with file:line targets. Append new `§6.x` TestStrategy items for each new ctest (4 of them). For each ctest, specify intent + expected exit code + 1-line assertion list. NO design rewrites; NO new architectural contracts; this is a janitorial pass.
- **Impl**: EDIT existing files in place. The only NEW file in this pass is `CHANGELOG.md` at repo root (item D5 below). Cross-cutting renames or extractions OK where required (item B1 moves a struct between headers).
- **Tester**: ADD 4 new ctest scripts (`tests/T_CLI_HELP_VERSION.sh`, `tests/T_CLI_CAPACITY.sh`, `tests/T_CLI_BAD_MAC.sh`, `tests/T_DETACH_NOTHING.sh`) + register all 4 in `tests/CMakeLists.txt`. Also EDIT `tests/lib/common.sh` to add the `wait_for_stats_sum` helper (item C1) AND to make the sudo + veth + prog_count infrastructure changes (items C2/C3/C4). Existing tests stay green; tester may need to adjust their use of `wait_for_stats_sum` (replacing `sleep 0.3`) and `sudo` → `sudo -n` calls — those edits are in scope.
- **Reviewer**: 4-point triangulation focused on the 12 items + new tests. Existing-and-unchanged code regions are out of scope.

## Scope (exactly 12 items in 4 sections — anything else is OOS)

### Section A — Architecture polish (2 items)

#### A1. Move `AttachConfig`/`DetachConfig` from `cli.hpp` to `loader.hpp` (hybrid-review #13, arch M1)

**Where**: `src/loader/cli.hpp:18-25` (struct defs); `src/loader/loader.hpp:17` (`#include "cli.hpp"  // AttachConfig` — verified line 17).

**Why**: `loader.hpp` currently pulls in `cli.hpp` solely to use `AttachConfig`/`DetachConfig` — backwards layering (control-plane should not depend on CLI parser). Both structs are pure data; `cli.hpp` keeps `Subcommand`/`HelpRequest`/`VersionRequest`/`ParsedCommand` and includes `loader.hpp` if it still needs the configs in its `variant`.

**Action**: relocate the two struct definitions to `loader.hpp` (just above the `LoaderError` enum), delete the `#include "cli.hpp"` from `loader.hpp`, add `#include "loader.hpp"` to `cli.hpp`, update `using ParsedCommand = std::variant<AttachConfig, DetachConfig, …>;` to compile with the new layering. Verify `loader.cpp` and `cli.cpp` still compile without further changes.

#### A2. Fix `raii.hpp:120-124` doc-vs-code drift (hybrid-review arch M2)

**Where**: `src/loader/raii.hpp:118-124` (the comment block above `class BpffsDir`).

**Why**: comment claims "call create() or arm() depending on whether you want it created or just tracked-for-removal" but `BpffsDir` exposes only `arm()` and `release()` — there is NO `create()` method. Misleading future readers.

**Action**: rewrite the comment to accurately describe the actual API: directory creation happens via `std::filesystem::create_directories()` in `loader.cpp`; the class owns the removal lifecycle via `arm()` (mark for removal on destruction) and `release()` (cancel removal after a successful operation). 1 comment-block edit, no behavior change.

### Section B — Documentation polish (4 items)

#### B1. Fix `inject_runt.py` docstring (hybrid-review #10, doc M3)

**Where**: `tests/inject/inject_runt.py:14-19` (docstring).

**Why**: docstring claims the script "would produce a src MAC of `02:00:00:00:00:99`" and "only the first 6 bytes plus a partial 7th survive". Both verified wrong:
- inline comment + `bytes([…])` literal (lines 37-43) explicitly produce `02:00:00:00:00:00` not `:99`
- the actual send is 13 bytes (6 dst MAC + 6 src MAC + 1 ethertype) — not "6 + partial 7th"

**Action**: rewrite the relevant docstring paragraph to match reality. The `:99` claim becomes `:00`; the "first 6 bytes plus partial 7th" sentence becomes the accurate "13 bytes — full 6-byte dst MAC + full 6-byte src MAC + 1 ethertype byte". ~5-line docstring edit.

#### B2. Add `>=1.1` version qualifier to `pkg_check_modules(LIBBPF …)` (hybrid-review #14, doc M5)

**Where**: `CMakeLists.txt:48` (`pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)`).

**Why**: MVP-1 uses `bpf_xdp_query_id()`, `bpf_xdp_attach()` etc. — these are post-1.0 libbpf APIs; building against an older libbpf would silently fail at link or behave wrongly. The required floor (1.1) is asserted in `design.md` §3 but unenforced by build config.

**Action**: change line 48 to `pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf>=1.1)`. 1-token edit. Verify CMake configure still succeeds on the dev host.

#### B3. Annotate `tests/lib/common.sh:25 PIN_ROOT` as mirror-of `XDPMF_BPFFS_ROOT` (hybrid-review #15, arch L3 + doc M6)

**Where**: `tests/lib/common.sh:25` (`PIN_ROOT=/sys/fs/bpf/xdpmacfilter`).

**Why**: this string is the hard-coded test mirror of `XDPMF_BPFFS_ROOT` macro from `include/common/mac_filter.h`. Future renames of the macro will silently break the tests unless someone notices both copies. A one-line `# MUST match XDPMF_BPFFS_ROOT in include/common/mac_filter.h` comment makes the coupling explicit.

**Action**: add the comment above line 25. CMake-generation is a possible MVP-2 hardening but explicitly out of scope here.

#### B4. Add minimal `CHANGELOG.md` at repo root (hybrid-review doc L3)

**Where**: new file `CHANGELOG.md`.

**Why**: README exists (added MVP-1.1A) but there is no version history; a contributor opening the repo at 0.1.0 cannot quickly answer "what changed in 1.1A vs 1.1B?". Even a sparse changelog gives them an entry point into git history.

**Action**: create `CHANGELOG.md` following the Keep-a-Changelog convention (Unreleased → 0.1.x sections). Populate with entries for `0.1.0` (MVP-1), `0.1.1` (MVP-1.1A), `0.1.2` (MVP-1.1B), `0.1.3` (this batch). Each section: one bullet per non-trivial change, derived from git log + the four `mint/task-brief-mvp1*.md` files. Keep terse — ~20-40 lines total. No version numbers in code yet; the changelog is purely documentary.

### Section C — Test infrastructure (4 items)

#### C1. Replace fixed `sleep 0.3` with `wait_for_stats_sum` poll helper (hybrid-review #12, testing M3)

**Where**: `tests/lib/common.sh` (add helper); all existing tests that currently `sleep 0.3` (or similar fixed sleeps) after an inject and before reading stats.

**Why**: fixed sleeps are flaky on loaded CI (under-sleep → race, over-sleep → wasted runtime). A bounded poll that exits as soon as the expected stats delta is observed is both faster on the happy path and more reliable under load.

**Action**: add to `tests/lib/common.sh`:
```bash
# wait_for_stats_sum <iface> <expected_sum> [timeout_ms=2000] [poll_ms=20]
# Polls read_stats.py until the (PASS+DROP_DENY+DROP_MALFORMED) sum equals
# expected_sum, or timeout. Returns 0 on match, 1 on timeout.
wait_for_stats_sum() { ... }
```
Then sweep all callers of `sleep 0.3` (or `sleep 0.5` etc.) in `tests/T_*.sh` that follow a packet inject and replace with `wait_for_stats_sum <iface> <expected>`. Sleeps that are NOT post-inject synchronization (e.g. fixture setup waits) stay as-is. Tester documents per-test which sleeps were replaced in `mint/impl-notes.md` if non-obvious.

#### C2. Switch `sudo` → `sudo -n` + preflight (hybrid-review #11, testing M8)

**Where**: every `sudo` call in `tests/T_*.sh` and `tests/lib/common.sh` fixture setup; also a new top-of-test preflight check.

**Why**: stale sudo timestamp on dev host or CI without passwordless sudo causes `sudo` to hang on stdin → ctest waits the full 60s timeout → confusing failure. `sudo -n` errors out immediately if no cached credential / no NOPASSWD rule.

**Action**:
1. Add to `tests/lib/common.sh` a `require_passwordless_sudo()` helper that runs `sudo -n true 2>/dev/null` and on failure prints a clear message + exits with **77** (ctest "skip" convention) so the test SKIPs cleanly rather than failing.
2. Each `tests/T_*.sh` that needs root calls `require_passwordless_sudo` near the top (after sourcing common.sh).
3. Replace all `sudo …` invocations with `sudo -n …` throughout `tests/`.

#### C3. Replace host-scope `veth_a`/`veth_b` with netns isolation OR uniquified names (hybrid-review testing M4)

**Where**: `tests/lib/common.sh:20-21` (`IFACE_A=veth_a`, `IFACE_B=veth_b`); fixture create/destroy paths.

**Why**: hard-coded `veth_a`/`veth_b` collide with any real interface a developer or CI host happens to have named the same. Particularly nasty: test cleanup deletes the colliding real interface.

**Action**: architect chooses one of two paths and documents the choice in §5.21:
- **Path A (preferred — cleaner)**: spin a dedicated network namespace per test (`ip netns add xdpmf-test-$$`), run veth pair + loader + traffic gen inside it; teardown nukes the netns. Adds ~50 LOC of fixture infra but isolates host completely.
- **Path B (cheaper — pragmatic)**: keep host-scope but uniquify names with PID suffix (`IFACE_A=xdpmf_a_$$`, `IFACE_B=xdpmf_b_$$`). Add a `pre-flight` that errors out if either name already exists on the host. ~10 LOC.

Either path is acceptable. Architect picks based on perceived ROI vs. risk of breaking the (already MVP-1.1B-passed) test suite.

#### C4. Fix `prog_count` host-global → per-iface (hybrid-review testing M6)

**Where**: `tests/lib/common.sh` (the `prog_count` helper if it exists, otherwise wherever the baseline/final comparison is done — grep for `bpftool prog`).

**Why**: current logic does `bpftool prog show | wc -l` baseline → run test → diff against final. On a host with concurrent BPF activity (other tests, monitoring agents, container runtimes) the delta is racy and incorrect. The correct check is "is OUR program attached to THIS iface?" which is per-iface.

**Action**: replace the global count with `bpf_xdp_query_id`-equivalent per-iface check using `bpftool net show dev <iface>` or `ip link show <iface> | grep xdp`. Test asserts "after attach: xdp program present on <iface>; after detach: no xdp program on <iface>", not "global prog count delta == 0".

### Section D — New CLI tests (4 items)

Each is a thin shell script (≤30 LOC) registered in `tests/CMakeLists.txt`. None requires root or veth fixtures; they exercise the loader binary's CLI parsing paths only.

#### D1. `tests/T_CLI_HELP_VERSION.sh` (hybrid-review testing LOW)

**Intent**: `xdpmacfilter --help` exits 0 and prints non-empty usage to stdout containing `Usage:` and the subcommand names. `xdpmacfilter --version` exits 0 and prints a single line containing `xdpmacfilter` and a version string (semver-shaped, regex `[0-9]+\.[0-9]+\.[0-9]+`). Both checked.

**Why**: trivially covered by users in the wild, never asserted by any ctest. Locks the contract that help/version exit cleanly without touching the kernel.

#### D2. `tests/T_CLI_CAPACITY.sh` (hybrid-review testing LOW)

**Intent**: invoke `xdpmacfilter attach --iface lo --allow <N+1 MACs>` where `N = XDPMF_ALLOWLIST_MAX` (64 per design §3). Assert exit code = `CliError` mapped value (look up the actual exit code from `cli.cpp:121-123` "too many --allow entries" path — likely exit **1** for CLI-level error per design §4.1) AND stderr contains the substring `too many --allow entries`.

**Why**: the capacity-limit branch in `cli.cpp` is untested; regression in the bounds check would silently let oversized allow-lists through.

**Helper**: generate `N+1` synthetic MACs in the test via `printf '02:00:00:00:%02x:%02x ' …` loop. No fixture needed since the failure happens before any kernel call.

#### D3. `tests/T_CLI_BAD_MAC.sh` (hybrid-review testing LOW)

**Intent**: invoke `xdpmacfilter attach --iface lo --allow not-a-mac` (and a couple of malformed variants: `gg:gg:gg:gg:gg:gg`, `01:02:03:04:05` short, `01:02:03:04:05:06:07` long). For each, assert exit code = CLI-error (per `cli.cpp` tokenizer) AND stderr mentions malformed-mac in a recognizable way.

**Why**: tokenizer error path uncovered.

#### D4. `tests/T_DETACH_NOTHING.sh` (hybrid-review testing LOW)

**Intent**: invoke `xdpmacfilter detach --iface lo` on an interface that has no XDP program attached and no bpffs dir. Per design §5.4, this should be the no-op recoverable cleanup path (exit 0) introduced in MVP-1.1B item §5.4 4-state machine. Assert exit 0; assert no `error:` in stderr.

**Why**: the "detach nothing" path was added in MVP-1.1B but never asserted by ctest. Locks the contract that detach is idempotent on a clean iface.

**Note for tester**: this test DOES touch the kernel (calls `bpf_xdp_query_id`) so `require_passwordless_sudo` applies. Use `lo` to avoid any veth fixture cost.

## Out of scope (explicit)

These are NOT to be touched in this pass — they belong to MVP-2 (separate brief, separate /mint cycle):

- `mac_filter.bpf.c` PERCPU stats migration (perf HIGH, design §5.3 explicit MVP-2)
- `--mode {generic,native,offload}` CLI flag (perf MED, design §5.6 explicit MVP-2)
- T_VERIFIER_REJECT + kernel-version probe + `LoaderError::KernelUnsupported` (testing MED, MVP-2)
- Tag-check security follow-up on top of name-check (sec MED, MVP-2 per §5.19 + §7)
- O_PATH fd hardening for bpffs root (sec MED, MVP-2 per §7)
- Removing `mint/test-run.log` from the gitignore list (verified already gitignored AND untracked — no work needed, doc L1 is a stale finding)

## Definition of done

- All 12 items addressed per their per-item action specs
- `mint/design.md` has a new `§5.21` amendment block + 4 new `§6.x` TestStrategy items
- Build is clean under both default flags and `XDPMF_SANITIZERS=ON` (no regression on the MVP-1.1A sanitizer test)
- All 9 existing ctest entries still pass (or legitimately SKIP per `T_DROP_MALFORMED` §6.5 + new `require_passwordless_sudo` SKIPs)
- All 4 new ctest entries pass on the dev host
- `mint/review.md` round-1 verdict = `pass` (no rework needed)
- One git commit per phase boundary per workflow B

## Dependencies

No new system dependencies. `bpftool` is already required by existing tests (used in `T_LOAD_ATTACH`). No new Python modules. No new C++ libraries.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
packs:
  architect:  []                                       # janitorial pass, no new abstractions
  impl:       [lang/cpp.md, lang/cmake.md]             # no .bpf.c edits this pass
  tester:     [test/bpf-xdp.md]
  reviewer:   []                                       # generic framework + LSP
```

