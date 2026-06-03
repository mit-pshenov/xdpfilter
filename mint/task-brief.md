# Task brief — MVP-4.25 / B32: comment-collapse — traceability-preserving archaeology pass (brownfield)

## Goal

A **behavior-preserving, comment-ONLY** editorial pass across the comment-bloated
C/C++/BPF source files: collapse dev-time archaeology that no longer serves a
**linear reader** — WITHOUT shaking off the band's traceability anchors. The
codebase carries ~2300 comment-lines in 11 src files (bpf.c 32%, loader.cpp 31%,
mac_filter.h 58%); much is decision-narration, net-delta archaeology, verbatim-
duplicated rationale, and **stale comments that now LIE about the code** (the
pilot's headline catch: the bpf.c header described a 2-axis OR-then-AND model that
hasn't existed since MVP-4.3). Reading the code by jumping tag-to-tag works; reading
it linearly is "чёрт ногу сломит" — this pass fixes that without losing the tags.

FIRST of the agreed tidiness workstream (comments → **B33 rename `xdpfilter`** →
**B34 de-monolith split**); B33/B34 are SEPARATE later slices — do NOT bundle.

**PO-validated rubric** via a hand-pilot already committed (`42e7326`: bpf.c
header + the 5×-duplicated `#define` rationale → -30 net lines, every anchor kept,
xdp byte-identical). The impl REPRODUCES that exact pattern across the rest.

## Context: prior work

- Prior slice: **MVP-4.24** (`e88bd84`) — exporter scrape consistency; archived as `mint/task-brief-mvp-4.24.md`.
- Worked-example: **`42e7326`** — bpf.c header+defines collapse (the template the impl follows).
- Existing design: `mint/design.md` (most recent §5.64); this slice appends §5.65.
- Phase A code-grep verification (brief author, this slice):
  - 11 scope files confirmed present; comment-line counts: bpf.c 451 (header+defines already done), loader.cpp 935, config.cpp 124, rule_counters_reader.cpp 100, stats_reader.cpp 74, sidecar_reader.cpp 42, http.cpp 100, prom_format.cpp 66, sidecar.cpp 161, logger.cpp 78, mac_filter.h 212.
  - **Guard #13 check passed**: NO ctest asserts a SOURCE comment string (tests carry §-refs in their OWN headers, and tag-check tests verify the prog BYTECODE tag — comments don't change codegen, so byte-identity covers it). Safe to edit comments freely.
  - `§5.x`/`D-mvp-*`/`PI-*`/`guard #N` are the band's grep-able traceability spine — the design.md sections they point at still exist (lineage anchors).
- PI continuity: **PI-7 (loader.hpp + config.hpp byte-identical)** holds — this slice touches `.cpp` + comment regions of `mac_filter.h` only, NO public-header API change. **PI-DATAPATH-IDENTICAL** (bpf.c xdp 3658 insns) holds trivially — comments don't change codegen. **kManagedMaps=39 / VERSION 0.15.0** unchanged.

## Workflow rules (brownfield)

- **Architect**: read §5.64 tail + §6.5 invariants + guards #1..#32; EDIT `design.md` in place, append §5.65 codifying THE RUBRIC (below) as the contract + the per-file care levels + the invariants. This is a thin design (no new code) — the value is the precise rubric + the reviewer's traceability-audit mandate. Run the Phase A grep discipline.
- **Impl**: comment-ONLY edits across the 11 files, reproducing the `42e7326` pilot pattern. NO code/logic/whitespace-of-code change. Work file-by-file. Rebuild after bpf.c → assert xdp 3658. Build the C++ → zero warnings (a comment edit must not break a `\`-continuation or a `/* */` nesting).
- **Tester**: NO new ctest to write (comment-only, no behavior change). Phase B = run the FULL suite, confirm the 101/103 baseline is preserved (the 2 pre-existing env-fails unchanged) + assert bpf.c `xdp` section is byte-identical at 3658 insns + `git diff <base> -- src/lib/loader.hpp src/lib/config.hpp` empty (PI-7). The negation/non-vacuity here = "a comment edit that accidentally changed behavior would flip a ctest" — the existing suite IS the guard.
- **Reviewer (THE heavy role — traceability-guardian)**: 5-point brownfield, but point #1 priority = **verify NO traceability anchor (`§/PI/guard/D-mvp`) that the band greps was lost**, AND **NO WHY-rationale or load-bearing invariant was cut**. Over-cutting is the PO-flagged failure mode ("не стряхнуть traceability, чувакам потом сложнее"). Concretely: diff the set of `§5.x`/`PI-*`/`guard #N` tokens before vs after per file (a dropped GOVERNING anchor for a construct = needs-rework; collapsed STACK-duplicates = fine); spot-check a sample of design.md §-refs still resolve from the code; confirm no stale/lying comment was LEFT (the inverse failure). Also verify zero behavior change (re-run suite + byte-identity).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.25-1: scope → **the 11 comment-bloated src/ files listed below**; NOT test `.sh`, NOT the rename
Test scripts have a different comment style (not §/D/PI archaeology) → out of scope. The `xdpfilter` rename is B33 (separate). Architect may trim/add a src file with grep evidence (e.g. if `cli.cpp`/`bypass.cpp` carry the same bloat, they may join).

### HG-mvp-4.25-2: VERSION → **no bump** (comment-only; zero operator-visible or behavioral change)

### HG-mvp-4.25-3: `mac_filter.h` → **highest-care, bias toward KEEP**
It is the BPF↔userspace ABI hub (58% comments) — most of its comments DOCUMENT the on-wire map/struct contract (load-bearing WHY for any future editor). Cut ONLY pure §-history/narration/net-delta; **never** the map-layout / key-value / alignment / ABI rationale. When in doubt on this file, KEEP. (Its comment % will drop the least of any file — that is correct, not under-performance.)

## THE RUBRIC (the contract — architect codifies in §5.65; impl reproduces from pilot `42e7326`)

**CUT:**
- (a) **STALE / LYING** comments — describing superseded behavior (the highest-value catch; e.g. the bpf.c header's dead 2-axis model). Replace with the accurate current-state description.
- (b) **decision-NARRATION prose** — "we chose A over B / unified 3 fns / the old code was byte-identical" — history lives in `design.md` + `CHANGELOG`.
- (c) **net-delta archaeology** — "kManagedMaps 13→15→…→39", "was struct X now `__u64`".
- (d) **WHAT-restatement** — comment paraphrases obvious code.
- (e) **verbatim-DUPLICATED rationale** repeated across sites (pilot: 5× identical "vmlinux.h is BTF-derived" → 1).
- (f) **tag-STACKING** — 5 `§`-refs decorating one line → the single GOVERNING anchor.

**KEEP (traceability + rationale are LOAD-BEARING):**
- WHY rationale (why this masking / bound / never-throw / security gate / ordering).
- concrete values + the load-bearing invariant a future editor MUST respect (e.g. "writes BEFORE the active_idx flip", "INACTIVE inner fd").
- spike-evidence numbers (e.g. guard #28 insn/stack counts).
- security rationale (§5.19 / §5.22 / never-throw guard #30).
- **ONE canonical anchor-POINTER per construct** (`§5.x` / `PI-N` / `guard #N` / `D-mvp-*` as a compact pointer, NOT as narration). Never drop the LAST pointer for a construct.

**Net effect (pilot-measured):** ~halve comment density WITHOUT losing a single grep-able anchor. Counts here are operative-semantic SHOULD-hints (≈, not literal) — the reviewer checks anchor-PRESERVATION + no-stale-left, not a target line count.

## Scope (cycle 1 — the 11 files)

| File | comment-lines | note |
|---|---|---|
| `src/bpf/mac_filter.bpf.c` | 451 | header+defines DONE (`42e7326`) — finish the **body** (map decls, 3 family arms, helpers). Rebuild → assert xdp 3658. |
| `src/lib/loader.cpp` | 935 | the biggest; heaviest §/D narration. |
| `src/lib/config.cpp` | 124 | |
| `src/exporter/rule_counters_reader.cpp` | 100 | |
| `src/exporter/stats_reader.cpp` | 74 | |
| `src/exporter/sidecar_reader.cpp` | 42 | |
| `src/exporter/http.cpp` | 100 | |
| `src/exporter/prom_format.cpp` | 66 | |
| `src/lib/sidecar.cpp` | 161 | |
| `src/common/logger.cpp` | 78 | |
| `src/common/mac_filter.h` | 212 | **HG-3 highest-care, bias KEEP** (ABI hub). |

## Out of scope (explicit)

- **B33 rename** `mac_filter`/`xdpmacfilter` → `xdpfilter` (+ repo align) — separate slice.
- **B34 de-monolith** (helper extraction + file split) — separate; this pass does NOT extract helpers or move code, ONLY edits comments.
- **Test `.sh` scripts**, fixtures, docs (README/CHANGELOG/design.md prose) — not this slice.
- **B35 wildcard-pack / B36 64-rule** — datapath perf/capacity, unrelated.
- Any code/logic/behavior/whitespace-of-code/map/schema/VERSION change. Public-header API (`loader.hpp`/`config.hpp`) byte-identical (PI-7).

## Definition of done

- §5.65 amendment in `design.md` (the rubric + per-file care + invariants + candidate guard #33 "comment-collapse must preserve grep-able traceability anchors").
- **PI-7** (`loader.hpp`+`config.hpp` ∅) + **PI-DATAPATH-IDENTICAL** (bpf.c xdp 3658) + **kManagedMaps=39** + **VERSION 0.15.0** all hold.
- ctest: 101/103 baseline preserved (2 pre-existing env-fails unchanged); NO new ctest.
- Reviewer confirms: zero traceability-anchor loss + zero WHY/invariant loss + zero stale-comment-left + zero behavior change.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies

- Build/test: existing toolchain; full ctest needs root (the suite's attach/apply/scrape tests). Comment edits themselves need nothing extra.
- Platform: unchanged.

## Packs to load (orchestrator: inject into spawn prompts)
```yaml
mode: brownfield
packs:
  architect:  [cpp, bpf]
  impl:       [cpp, bpf]
  tester:     [cpp, bpf-xdp]
  reviewer:   [cpp]
```

---

## Pre-brief sanity check (per mint-hld-scope-discipline)

**Mechanical — single-architect OK.** Goal fits one line ("traceability-preserving comment-collapse across 11 src files per the pilot rubric"). NO design space: the rubric IS the contract, validated by a committed pilot; no mechanism fork; behavior-preserving (byte-identity + ctest). The only judgment is per-file care-level (framed as HG-3 for the one risky file, mac_filter.h). Not expensive-to-undo (comment edits; git-revertable). No `/mint-hld`. Large in LINE-count but uniform in operation — one slice.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief author already ran these; architect re-verifies + extends:
- `for f in <11 files>; do grep -coE '§5\.[0-9]+|PI-[a-z0-9]+|guard #[0-9]+|D-mvp-[0-9.]+' $f; done` — capture the per-file anchor census BEFORE edit so the reviewer can diff it after (the anti-over-cut tripwire).
- `grep -rn '§5\.\|D-mvp-\|guard #' tests/ | grep -v '\.md:'` — confirm no ctest asserts a SOURCE comment string (brief author: clean; tag-check tests verify bytecode tag, byte-identity-covered).
- Re-read `42e7326` (the pilot diff) as the worked-example before designing the rubric.
- For bpf.c: after the body pass, `llvm-objdump-19 -d --section=xdp build/mac_filter.bpf.o | grep -cE '^\s+[0-9a-f]+:'` must == 3658.
- For `mac_filter.h`: enumerate which comments document the map/struct ABI (KEEP) vs §-history (cut) — this is the highest over-cut risk (HG-3).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep discipline)** — APPLIES (always); plus the NEW per-file anchor-census tripwire above.
- **Guard #13 (fixture cross-reference)** — CHECKED clean (no ctest asserts a source comment); architect re-confirms, esp. that no comment edit in `mac_filter.h` perturbs a `static_assert` line (those are CODE, not comments — leave them).
- **Guard #30 (never-throw catch backstop)** / **#28 (bounded-walk spike evidence)** / **#15 (PRESERVE-before-flip)** — these are the load-bearing WHY/invariants the rubric MUST KEEP; architect lists the exact comments carrying them so impl does not cut them.
- **Guard #10 (catalogue arithmetic)** — N/A (no catalog/array size change; `kEventNames` untouched).
- **Guard #11 (VERSION-bump)** / **#12 (RESOURCE_LOCK)** — N/A (no bump, no new ctest).
- Operative-semantic note: comment-line COUNTS are SHOULD-level orientation; the contract is anchor-preservation + no-stale-left + zero-behavior-change, NOT a target density.
