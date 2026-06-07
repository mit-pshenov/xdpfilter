# Task brief — MVP-4.40 / B48: harden the DEFAULT dry-run output (human-view golden + sanitizer coverage) (brownfield)

## Goal

An **additive test-depth** sanitary-day slice (Batch C of 2026-06-07) closing the
review's two High findings that the **human `apply --dry-run` view — the DEFAULT
operator output — is the weakest-tested of the three formats**. Today
`format_dryrun_human` has ZERO offline-harness coverage (its only test is ~25
loose substring greps in `T_CLI_APPLY_DRYRUN.sh`), and it is never executed under
ASAN/UBSAN (the sanitizer test runs only `apply`+`detach`, never `--dry-run`).
This slice adds (1) a byte-exact `dryrun_human.golden` driven through the existing
libbpf-free offline harness, and (2) a `--dry-run` invocation under the sanitizer.

NOT subtractive. No `src/` behavior change, no schema/datapath touch, **no VERSION
bump** (test-only). Natural follow-up to B47/MVP-4.39 (just shipped) which landed
B46 — so the new human golden bakes the canonical `0x0806` ethertype form.

## Context: prior work

- All prior briefs: archived in `mint/task-brief-*.md` (prior = `task-brief-mvp-4.39.md`).
- Existing design: `mint/design.md` §5.78 (B45 human view), §5.79 (B47 subtraction), §5.76/§5.77 (B43/B44 dryrun harness + CLI verb).
- Source: `/mint-review` 2026-06-07 TEST-H1 (High) + TEST-H2 (High).
- Phase-2 brief-author grep verification ran (below); every literal CONFIRMED, zero discrepancies.
- PI continuity: PI-mvp-4.37-LIBBPF-FREE (harness stays libbpf-free — the OPS-canary), PI-mvp-4.38-GOLDEN-UNCHANGED (image golden + #112 untouched — this ADDS a human golden alongside), PI-7 (loader.hpp ∅ — no `src/` touch), insn 3477 (no `src/bpf` touch).

## Workflow rules (brownfield)

- **Architect**: read §5.76/§5.77/§5.78 + the dryrun_harness structure; EDIT design.md in place; append a §5.80 amendment. Resolve HG-mvp-4.40-1 (H1 location) + HG-mvp-4.40-2 (H2 approach). FileList is a DIFF (NEW golden + EDIT harness + EDIT tests/CMakeLists.txt + EDIT T_SANITIZER_BUILD.sh). Include a §6.5-style Preserved-invariants note.
- **Impl**: NOTE — most of this slice is TEST-side (harness C++, a golden file, a shell test, CMake). The impl agent owns the C++ harness render-path + CMake wiring; the tester owns the golden content + the shell-test `--dry-run` step + negation. Architect splits ownership in §5.80 (the harness .cpp is impl-or-tester per project convention — flag it; dryrun_harness.cpp is test infra, likely tester-owned, but it's a build target so impl may own the CMake). Keep the harness **libbpf-free** (no `bpf_*`, no libbpf link, no loader.cpp/skeleton-object dep) — the clean link IS the contract.
- **Tester**: the human golden is FROZEN once checked in (mirror §5.77.7 "do NOT regenerate after the fact"). Author it via the generator affordance, then freeze. Mandatory: SMOKE + byte-exact IDENTITY + NEGATION-control (one-byte corruption must FAIL), mirroring the existing `test_image_identity`/`test_negation_control`. The golden MUST bake the `0x0806` ethertype form (B46).
- **Reviewer**: 5-point brownfield. Special attention: (a) harness still links NO libbpf (grep the link line; PI-mvp-4.37-LIBBPF-FREE); (b) image golden `dryrun_image.golden` + #112 BYTE-UNCHANGED (this slice only ADDS); (c) the human golden has a working negation control (deliberately-wrong golden FAILS); (d) the `--dry-run` sanitizer step actually runs both formats against the instrumented binary; (e) no `src/` or `src/bpf` diff (PI-7, insn 3477).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.40-1: H1 (human golden) location → **extend the offline `dryrun_harness`** (default)
Render `format_dryrun_human(build_corpus(), compile(build_corpus()))` in `tests/dryrun/dryrun_harness.cpp` and byte-compare against a NEW `tests/dryrun/dryrun_human.golden`, adding `test_human_identity` + `test_human_negation_control` + an `--emit-golden-human` generator affordance, mirroring the existing image-golden trio. **Strongest**: libbpf-free, offline, byte-exact, reuses the proven pattern; the harness ALREADY links `map_image.cpp` (`format_dryrun_human`) + `compiled_ruleset.cpp` (`compile()`), so no new link deps. Same `build_corpus()` config the image golden uses (which carries the ethertype axis → exercises B46's `0x0806`). **Alternative** the architect may weigh: a CLI-level golden compare added to `T_CLI_APPLY_DRYRUN.sh` (simpler but not libbpf-free, and couples to CLI env). Prefer the harness path.

### HG-mvp-4.40-2: H2 (sanitizer coverage) approach → **add a `--dry-run` step to `T_SANITIZER_BUILD.sh`** (default)
After the existing sanitized `apply`, add an invocation of the already-built sanitized `xdpfilter apply --iface … -f <config> --dry-run` for BOTH formats (default human + `--format=golden`) so `compile()` + `format_dryrun_human` + `render_dryrun_image` + `diff()` execute under ASAN/UBSAN against a real config. **Cheap, high coverage** (drives the real instrumented binary; a few seconds added). **Alternative**: also add `-fsanitize=address,undefined` to the `dryrun_harness` target when `XDPMF_SANITIZERS=ON` (sanitizes the harness recompile too) — architect may add this if low-cost, but the `T_SANITIZER_BUILD` step is the primary. Do NOT attempt to fix the pre-existing #9 T_SANITIZER_BUILD timeout (BACKLOG B16) — OOS.

## Open mechanism questions (architect decides; document in §5.80)

### Q1: human-golden generator affordance shape
- **A1**: a `--emit-golden-human` argv branch (mirrors `--emit-golden`), printing `format_dryrun_human(build_corpus(), compile(build_corpus()))`.
- **A2**: reuse a single `--emit-golden <which>` arg.
- **Recommendation**: A1 — lowest-surprise, mirrors the existing `--emit-golden`/`--emit-live` argv convention exactly.

## Scope (cycle 1 — concrete items)

### Item B48-1 — human-view offline golden (TEST-H1)
**Where**: `tests/dryrun/dryrun_harness.cpp` (EDIT — add render path + 2 tests + emit affordance), `tests/dryrun/dryrun_human.golden` (NEW, FROZEN).
- Add `test_human_identity(golden_path)`: render `format_dryrun_human(build_corpus(), compile(build_corpus()))`, byte-compare to `dryrun_human.golden`.
- Add `test_human_negation_control()`: corrupt one byte of the rendered human output, assert the comparator detects the mismatch.
- Add the generator affordance (Q1) to produce the frozen golden.
- Wire both into `main()` alongside the existing image tests.
- The golden bakes the corpus render incl. ethertype `0x0806` (B46).

### Item B48-2 — sanitizer coverage of the human view + diff() (TEST-H2)
**Where**: `tests/T_SANITIZER_BUILD.sh` (EDIT — add a `--dry-run` step), optionally `tests/CMakeLists.txt`/`CMakeLists.txt` (architect's call on HG-2 alt).
- After the existing sanitized `apply`, run the sanitized binary `apply … --dry-run` (default human) AND `apply … --dry-run --format=golden` against a real config (reuse the existing sanitized-apply config, e.g. `config_valid_andv6.yaml`), asserting exit 0 + non-empty output. This drives `compile()` + `format_dryrun_human` + `render_dryrun_image` + `diff()` under ASAN/UBSAN.

### Item B48-3 — CMake/ctest wiring (if harness gains a sub-test or the architect adds harness sanitization)
**Where**: `tests/CMakeLists.txt` — the human golden runs inside the existing `T_DRYRUN_IMAGE_IDENTITY` harness binary (no NEW ctest needed; the harness `main` runs all sub-tests), so likely NO ctest registration change — confirm. If the architect splits a separate ctest, register it with the same TEST_ENV/TIMEOUT pattern + Guard #12 note (no shared host state).

## Out of scope (explicit)

- ANY change to `dryrun_image.golden` or #112 (frozen; this slice only ADDS).
- Fixing the #9 T_SANITIZER_BUILD timeout (BACKLOG B16, environmental).
- Any `src/` or `src/bpf` change (test-only slice).
- VERSION bump.
- The shared `axis_format` extraction (still declined per D-mvp-4.39-NOEXTRACT).
- SEC-L1 / PERF-M1 (separate slices).

## Definition of done

- §5.80 amendment in `mint/design.md`.
- NEW `tests/dryrun/dryrun_human.golden` (frozen, bakes `0x0806`); harness renders + byte-compares it with a working negation control.
- `T_SANITIZER_BUILD.sh` exercises `--dry-run` (both formats) under ASAN/UBSAN.
- PIs held: PI-mvp-4.37-LIBBPF-FREE (harness link still libbpf-free), PI-mvp-4.38-GOLDEN-UNCHANGED (image golden + #112 ∅), PI-7 (loader.hpp ∅), insn 3477 (src/bpf ∅).
- Existing suite green (modulo the documented env-flakes #1/#9/#48/#63); #112 still green; the harness binary now also passes the human-golden sub-tests.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang-19 / libc++-19 (unchanged). Harness stays libbpf-free.
- Runtime: ASAN/UBSAN build (XDPMF_SANITIZERS=ON) for the T_SANITIZER_BUILD step (existing).
- Kernel/platform: none new (harness is offline; the sanitizer apply uses the existing veth fixture).

## Packs to load (orchestrator: inject into spawn prompts)
```yaml
mode: brownfield
packs:
  architect:  []
  impl:       []
  tester:     []
  reviewer:   []
```

---

## Pre-brief sanity check (per mint-hld-scope-discipline)

**MECHANICAL (single-architect).** Not multi-axis: both items extend WELL-ESTABLISHED existing patterns (the dryrun_harness image-golden trio for H1; the T_SANITIZER_BUILD apply step for H2). The two HG forks each have a clearly-dominant recommended option that mirrors existing code; not ≥3 viable options, not expensive-to-undo (test code). No `/mint-hld` needed. NOT hld-derived → no ladder to re-discharge. PO-filter applied: both HG decisions are engineering test-architecture choices with clear recommendations — neither is on the user's plate.

## Notes for architect Phase A code-grep discipline

Brief author already ran these (CONFIRMED 2026-06-07); architect re-verifies + extends:
- `grep -n format_dryrun_human src/lib/map_image.hpp src/lib/map_image.cpp` — sig `format_dryrun_human(const Config&, const CompiledRuleset&)` (hpp:32, def map_image.cpp:219); already linked by the harness.
- `sed -n '/int main/,$p' tests/dryrun/dryrun_harness.cpp` — confirm the `--emit-golden`/`--emit-live` argv convention + the `test_smoke_minimal`/`test_image_identity`/`test_negation_control` trio to mirror; `build_corpus()` is the shared config (lock-step with `tests/dryrun/dryrun_cli.yaml`).
- `sed -n '1765,1815p' tests/CMakeLists.txt` — the `dryrun_harness` target links materialize/map_writer/map_image/compiled_ruleset/loader_error + **NO** PkgConfig::LIBBPF / loader.cpp / skel object (the libbpf-free OPS-canary). Adding the human render keeps this — verify the link line is unchanged in kind.
- `grep -n "apply\|--dry-run\|config_valid" tests/T_SANITIZER_BUILD.sh` — confirm the sanitized-apply config to reuse for the `--dry-run` step.
- `test -e tests/dryrun/dryrun_human.golden` — must be absent (NEW).
- Post-impl: `git diff tests/dryrun/dryrun_image.golden` MUST be empty (image golden frozen); `git diff --stat src/ src/bpf` MUST be empty (test-only slice).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **guard #5** (Phase A code-grep discipline) — always; architect repeats the greps above.
- **guard #12** (RESOURCE_LOCK for shared host state) — the human golden runs INSIDE the existing offline harness (no bpffs/iface/port) → no lock, like #112. The `--dry-run` step in T_SANITIZER_BUILD runs inside that test's existing isolated /tmp build + veth fixture → no NEW shared-state surface. Confirm no NEW ctest with host state.
- **§5.77.7 frozen-golden discipline** — the human golden, once emitted + checked in, is FROZEN; the `--emit-golden-human` affordance is generator-only, never auto-regenerated to "make it pass".
- **PI-mvp-4.37-LIBBPF-FREE** — the load-bearing invariant: the harness link must stay libbpf-free after adding the human render path.

(N/A: guard #11 — no VERSION bump; guard #13/#16 — no retired string/pin; guard #15 — no stateful-map promotion.)
