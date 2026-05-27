# Task brief — MVP-3.4g: dead-code delete `BpffsDir` + `XdpAttachment` from `src/lib/raii.hpp` (brownfield, housekeeping)

## Goal

Pure removal of the two dead RAII types `BpffsDir` (`src/lib/raii.hpp:132`) and `XdpAttachment` (`src/lib/raii.hpp:74`). Neither has any construction site in active code per Phase 2 grep — only the class definitions themselves + 2 stale comment references in `src/lib/loader.cpp`. Both types were superseded by the §5.22 `IfaceDirGuard` (which inherits the BpffsRootFd symlink defense and is the canonical rollback RAII for per-iface bpffs directories) without the old types being removed at the time.

Closes /mint-review 2026-05-27 Theme C (cross-validated 2-way: **code-quality H1** dead-code + **architecture L4** overlap with kManagedMaps pattern; severity HIGH retained per CQ's stronger evidence — CQ grep covered both classes, arch only saw BpffsDir overlap).

**Source of truth**: `/home/user/agent-teams-review/runs/mint-review-mint-l2-mac-filter-202605271147/report.md` lines 114-115 (Theme C) + line 144 (top-actionable item #6). Carry-forward from §5.36 §7 OOS + §5.37 §7 OOS.

## Context: prior work

- All prior briefs: archived in `mint/task-brief-*.md` (27 prior cycles)
- Existing design: `mint/design.md` §5.37 + EDIT-1 (MVP-3.4f, commit `7519ae3`)
- Architecture doc: `mint/architecture-v2.md` — no row for this slice (housekeeping; treat as §5.38 brownfield amendment, mirroring §5.30 / §5.33 / §5.36 / §5.37 housekeeping/hardening precedents)
- Phase A code-grep verification: brief-author ran exhaustive Phase 2 greps (see "Notes for architect Phase A code-grep discipline" footer); architect repeats independently
- PI continuity: PI-7-3.4f-hpp 12th + PI-7-3.4f-cpp 7th + loader-hpp + mac-filter-h ZERO-diff streaks active. This slice targets **13th + 8th** consecutive ZERO-diff on the 4 fence paths. `src/lib/raii.hpp` is NOT in the fence list — editing it is in-scope EDIT, not fence violation.

## Workflow rules (brownfield)

- **Architect**: read §5.22 (origin of IfaceDirGuard superseding BpffsDir; established §5.22 impl-surface table that explicitly carved BpffsDir as "stays as-is — single-callsite-rule" — that carve-out is now obsolete since no callsite exists) + §5.37 §7 OOS (where this slice was carried forward). EDIT design.md in place; append §5.38. Phase A code-grep MUST independently re-verify ZERO construction sites for both types.
- **Impl**: FileList interpretation per brownfield mode — strict in-scope EDIT on `src/lib/raii.hpp` (delete 2 classes + their comment block + `<filesystem>` include); strict in-scope EDIT on `src/lib/loader.cpp` (delete 2 stale cite-comments); strict additive on UNCHANGED files (4 PI-7 fence paths).
- **Tester**: NO new ctests. Pure deletion has no operator-observable behavior change. Existing 67 ctests stay green by construction. Tester's role this cycle is the SHORTEST in project history — just confirm `ctest -j4` passes 67/67 + capture log.
- **Reviewer**: 5-point brownfield framework. Special attention items: (a) PI-7-3.4g-hpp / cpp / loader-hpp / mac-filter-h ZERO-diff fences (13th + 8th + loader-hpp + mac-filter-h streaks); (b) reviewer-side independent grep confirms ZERO live references to `BpffsDir` / `XdpAttachment` in src/, tests/, include/, docs/ post-delete; (c) `<filesystem>` include actually drops from raii.hpp (no other user remains); (d) baseline 67/67 ctest holds with ZERO regressions; (e) net LOC reduction ≥ ~75 (matching /mint-review estimate, operative-semantic SHOULD-hint per Phase 4.4).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-3.4g-1: scope of cleanup → **strict delete + minimal CHANGELOG only**

Strict delete of: (a) `XdpAttachment` class def at raii.hpp:74-121; (b) BpffsDir-preamble comment block at raii.hpp:122-130; (c) `BpffsDir` class def at raii.hpp:132-178; (d) `#include <filesystem>` at raii.hpp:14 (only used inside `BpffsDir::reset()` per Phase 2 grep); (e) 2 stale cite-comments in `src/lib/loader.cpp` at :29 ("XdpAttachment unwinds" in apply_iface_load header) + :725-731 (the "BpffsDir stays as-is per §5.22 impl-surface table" block above IfaceDirGuard); (f) ONE-LINE CHANGELOG entry under §5.38. The pre-existing CHANGELOG:503 archived prior-cycle entry ("`src/loader/raii.hpp` `BpffsDir` comment — described the real") stays as immutable release history — do NOT retroactively edit. Architect may flip on (b/c) if a `BpfSkeleton`-class-preamble lifecycle comment is preferred over deleting the standalone comment block — but default is strict delete.

### HG-3.4g-2: PI-7-3.4g ZERO-diff fence → **YES, preserve streak**

`src/common/logger.hpp` (12th → 13th hpp); `src/lib/config.hpp` (7th → 8th cpp); `src/lib/loader.hpp` (extension); `src/common/mac_filter.h` (extension). All 4 fence paths UNTOUCHED. raii.hpp is NOT in the fence list — its EDIT is in-scope per FileList. Result: strongest streaks in project history extend cleanly.

### HG-3.4g-3: NEW ctests → **NONE**

Pure deletion; no behavior change to verify. Existing 67 ctests stay green by construction. Reviewer's framework point 3 (Code ↔ Tests) satisfied by 67/67 baseline holding. Architect may flag a NEW canary if they identify some non-obvious behavior dependent on the dead types (extremely unlikely — Phase 2 grep showed no callsites) — but default is NO.

### HG-3.4g-4: design.md `[SUPERSEDED BY §5.38]` markers scope → **2 OOS-fence carry-forward records only**

Architect adds `[SUPERSEDED BY §5.38]` inline markers at the 2 records that explicitly fence this slice as deferred: design.md:11836 (§5.36 §7 OOS) + :12514 (§5.37 §7 OOS). Other 5 archived historical refs (design.md:28 initial FileList, :569-585 §5.18-19 prose, :903 §5.27 A2 finding) are immutable archived sections — architect spec rule "Do NOT rewrite prior sections (those are immutable history)" applies; no markers there.

## Open mechanism questions (architect decides; document in §5.38)

### Q1: `src/lib/loader.cpp` 2 stale cite-comments — delete entirely vs replace with anchor?

- **A1**: delete both blocks entirely (no replacement). The "XdpAttachment unwinds" mention at :29 is replaced by silence; the "BpffsDir stays as-is per §5.22 impl-surface table — single-callsite-rule, BpffsRootFd is not exported" block at :725-731 is replaced by silence (IfaceDirGuard's purpose is self-evident from its docstring and §5.22 context).
- **A2**: replace each with a short anchor comment (`// see §5.38 for raii.hpp shape post-cleanup`). Preserves audit-trail for git-archaeologists looking up "why was this comment removed?".
- **Recommendation**: **A1**. The comments described historical design choices that no longer reflect code reality. A1 is cleanest; future archaeology has `git blame` + `git log` for traceability. If architect's judgment leans toward A2 for `:725-731` specifically (that block has more historical context value), brief accepts the split — but default = A1 uniform.

## Scope (cycle MVP-3.4g — concrete items)

### Item E-1 — EDIT `src/lib/raii.hpp` (~-95 LOC delete + 1 LOC include drop)

**Where**: `src/lib/raii.hpp` (current 179 LOC)
Diff:
- DELETE line 14: `#include <filesystem>` (sole user is `BpffsDir::reset()` per Phase 2 grep — verifies on Phase A re-grep)
- DELETE lines 74-121: `class XdpAttachment` (~48 LOC including class body + dtor + move ctors)
- DELETE lines 122-130: BpffsDir-preamble comment block (~9 LOC; the multi-paragraph rationale block describing the owner workflow with `std::filesystem::create_directories()`)
- DELETE lines 132-178: `class BpffsDir` (~47 LOC)
- PRESERVE lines 1-73: license/header/includes (minus `<filesystem>`) + `class BpfSkeleton` (still actively used; loader.cpp:14 + :30 references it)
- PRESERVE namespace boilerplate (line 25 + closing `}`)
- Net LOC: ~-95 (Theme C estimated ~-75; the extra ~20 is comment-block-density that Phase 2 grep surfaced — operative-semantic SHOULD-hint per Phase 4.4).

### Item E-2 — EDIT `src/lib/loader.cpp` (~-5 LOC delete)

**Where**: `src/lib/loader.cpp` (current ~2280 LOC)
Diff:
- DELETE the "XdpAttachment unwinds" mention at line ~29 (inside apply_iface_load header comment) per HG-3.4g-1.(e) + Q1.A1 — the surrounding sentence flow needs to be preserved (architect picks: drop the whole sub-clause OR rewrite the sentence to retain BpfSkeleton-only unwind description).
- DELETE lines ~725-731: the 7-line comment block "Replaces the §5.17 BpffsDir wrapper for new code paths so rollback inherits the symlink defense (raii.hpp BpffsDir stays as-is per §5.22 impl-surface table — single-callsite-rule, BpffsRootFd is not exported)." per Q1.A1. Operative-semantic note: brief estimates ~5 LOC; impl may need ~3-7 depending on adjacent whitespace preservation (Phase 4.4 SHOULD-hint).
- NO other changes to loader.cpp; remaining ~2275 LOC byte-equivalent.

### Item E-3 — EDIT `mint/design.md` (~2 SUPERSEDED markers)

**Where**: `mint/design.md` lines 11836 + 12514 (architect re-confirms by `grep -nE '^[[:space:]]*- \*\*Theme C|^[[:space:]]*- \*\*Dead .BpffsDir' mint/design.md`)
Diff: inline `[SUPERSEDED BY §5.38]` marker added per architect spec rule. Two 1-line additions. The 5 other archived refs are immutable history — NO markers there.

### Item E-4 — EDIT `CHANGELOG.md` (+1 LOC entry)

**Where**: `CHANGELOG.md` (current top section, architect picks anchor — under "MVP-3.4 housekeeping" sub-block, mirroring §5.36/§5.37 entries, OR a new "MVP-3.4g" sub-block).
Diff: single-line entry: `- src/lib/raii.hpp: dead-code cleanup — BpffsDir + XdpAttachment removed (superseded by IfaceDirGuard since §5.22)`. Minimal prose discipline; release-notes are operator-facing, not designer-prose.

### NO new items, NO new ctests

This is the SHORTEST scope of any MVP-3.4x slice. Pure deletion + 2 stale comment cleanups + 1 CHANGELOG line + 2 design.md SUPERSEDED markers.

## Out of scope (explicit)

- **Renaming `IfaceDirGuard` to reflect its post-§5.22 canonical-RAII status** — no operator-observable benefit; rename churns 1 file for cosmetic gain. NEW FENCE.
- **Consolidating `raii.hpp` into a different location** (e.g., `src/lib/internal/raii.hpp` or merging into `apply_internal.hpp`) — architecture-level decision belonging to a future housekeeping mini; not this slice. NEW FENCE.
- **Refactoring `BpfSkeleton`'s reset/move semantics** — UNTOUCHED; orthogonal to this slice. NEW FENCE.
- **VERSION bump** — pure deletion + no operator-observable behavior change → no bump. (Architect override only if they identify some operator-visible surface — extremely unlikely.)
- **Doc rewrite cascades** — CHANGELOG gets ONE line; README + HANDOFF + docs/BACKLOG stay UNTOUCHED. NEW FENCE.
- **Theme C action item #6 follow-on cleanups** (e.g., other dead RAII types not flagged by /mint-review) — if Phase A grep surfaces additional dead types, architect adds them in a separate §5.38b/c amendment OR carves them as NEW FENCE for a follow-up slice.
- **KC-1 closure half (action label defensive escape, sec L2)** — separate slice per /mint-review backlog.
- **KC-2 (exporter --bind non-loopback WARN)** — separate slice per /mint-review backlog.
- **Theme D / CQ M1 (dispatch_match helper)** — separate slice.

## Definition of done

- §5.38 amendment in `mint/design.md` (estimated ~80-120 LOC: scope + HG/Q resolutions + D-decisions + FileList table + PI block + OOS block + Phase A grep notes). This is the SHORTEST §-amendment expected since §5.33 mini housekeeping.
- PI continuity:
  - PI-7-3.4g-hpp = **13th** consecutive ZERO-diff on `src/common/logger.hpp`
  - PI-7-3.4g-cpp = **8th** consecutive ZERO-diff on `src/lib/config.hpp`
  - PI-7-3.4g-loader-hpp + PI-7-3.4g-mac-filter-h extensions (continuing from §5.37)
  - All §6.5 prior invariants PRESERVED (no behavior change → all checks pass by construction)
- ctest baseline: 67 → 67 (NO new ctests; reviewer confirms zero existing-test regressions)
- mint/review.md round-1 verdict = pass
- One git commit per phase boundary

## Dependencies

- C++23 stdlib only — drops `<filesystem>` dep from raii.hpp
- No CMake changes (raii.hpp is header-only, already in xdpmf_internal include path)
- No kernel/platform deps
- No external BPF/libbpf changes

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

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])

- **Multi-axis design space?** No. One axis: delete-the-dead-code (chosen) vs leave-as-is (rejected by /mint-review Theme C HIGH severity).
- **Brief-author uncertain across ≥2 axes?** No. /mint-review report prescribes the resolution verbatim ("Delete dead BpffsDir + XdpAttachment from raii.hpp (~75 LOC)").
- **Expensive to undo?** No. Pure deletion; rollback = revert single commit.
- **≥3 distinct viable options?** No. Delete is the one viable option per cross-validated /mint-review signal.
- **Mechanical-answer check**: ✓ yes — answer falls out of /mint-review report's Theme C Resolution prose + Phase 2 grep confirming ZERO construction sites.
- **Has /mint-hld been run?** No — not needed. Single-architect `/mint-dev` handles it.
- **Brief-author overconfidence flag**: Phase 2 grep was exhaustive (construction sites + member-type uses + type aliases + public-surface + test fixtures + doc cross-refs). Architect repeats per guard #5.

**Verdict**: this slice is the most mechanical of any MVP-3.4x. `/mint-hld` overkill. Proceed with `/mint-dev`.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief-author already ran these greps per Phase 2 — architect re-verifies + extends:

1. **Confirm ZERO construction sites for both types** (load-bearing):
   - `grep -rnE 'BpffsDir\s*\(|XdpAttachment\s*\(|BpffsDir\{|XdpAttachment\{' src/` — expect zero hits (class defs in raii.hpp match pattern but with `class` prefix; architect filters)
   - `grep -rnE 'BpffsDir [a-z]|XdpAttachment [a-z]' src/` — variable-decl-style construction; expect zero hits
   - `grep -rn '\.release()\|->release()' src/ | grep -v 'IfaceDirGuard\|BpfSkeleton'` — RAII release-pattern callsites; confirm no caller still uses the deleted types' release method

2. **Confirm `<filesystem>` sole-user is `BpffsDir::reset()`**:
   - `grep -nE 'std::filesystem|fs::|<filesystem>' src/lib/raii.hpp` — expect ALL hits inside the BpffsDir class body (so deletion drops them in lockstep)
   - Brief-author confirmed Phase 2: 3 hits at lines 122-125 (comment), 169 (`std::filesystem::remove_all(path_, ec)` in reset()), 14 (include). Architect re-confirms post-Phase-A grep.

3. **2 stale cite-comments in loader.cpp surgery** (per Q1.A1 default):
   - `grep -nE 'XdpAttachment|BpffsDir' src/lib/loader.cpp` — expect 3 hits: line ~29 (XdpAttachment in apply_iface_load header), lines ~729-731 (BpffsDir block above IfaceDirGuard class). Brief-author confirmed Phase 2; architect picks exact sentence-flow restoration on the :29 cleanup.

4. **design.md `[SUPERSEDED BY §5.38]` marker placement** (per HG-3.4g-4):
   - `grep -nE 'Theme C.*BpffsDir|Dead.*BpffsDir.*XdpAttachment.*deletion' mint/design.md` — expect 2 hits at lines ~11836 + ~12514 (the 2 OOS-fence carry-forward records). 5 other archived refs at lines 28, 569-585, 903 are IMMUTABLE HISTORY — no markers.

5. **Reviewer-side post-delete sweep** (architect documents in §5.38 invariants block):
   - Reviewer's framework point 5 walks: `grep -rn 'BpffsDir\|XdpAttachment' src/ tests/ include/ docs/ CHANGELOG.md` post-impl-commit returns at most ONE hit: `CHANGELOG.md:503` archived prior-cycle entry (`src/loader/raii.hpp BpffsDir comment...`). That's expected — frozen release history. Operative-semantic per Phase 4.4: hint is ≤1 hit, not literal zero.

6. **`<filesystem>` sole-user post-delete** (architect documents invariant):
   - Reviewer confirms: `grep -nE 'std::filesystem|<filesystem>' src/lib/raii.hpp` returns ZERO hits post-impl. If hit, impl missed the include drop.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep discipline)**: ✓ applies; architect repeats brief-author's Phase 2 greps independently. This slice is the most grep-load-bearing of any MVP-3.4x since the verification IS the design (no behavior change to verify other than "the deleted types had no callers").
- **Guards #9 / #10 / #11 / #12 / #17 / #18 / #19 / #20 / #21**: N/A — no helper extraction, no constexpr tables, no VERSION bump, no new ctests, no bilateral invariants, no host-vs-netns, no logger text-mode, no rule-of-three trigger, no NEW test IO-model.
- **Guard #13 (fixture cross-reference for retired strings)**: ⚠ partial — applies for retired SYMBOLS not strings; brief-author ran symbol-grep equivalent at Phase 2 (✓ zero fixture hits, ✓ zero test-body hits). Architect re-confirms.

**Operative-semantic discipline reminder (Phase 4.4)**: counts in this brief (~75 LOC `/mint-review estimate`; ~95 LOC `brief-author re-grep`; 2 cite-comments; 3 hits in raii.hpp for filesystem; 7 archived design.md refs vs 2 OOS-fence-carry-forward records) are SHOULD-level orientation, not contracts. Impl deviations on those (slightly different LOC delta, different sentence-flow restoration on loader.cpp:29, marginally different CHANGELOG anchor) are `inline-merge` per design's resolution rule.
