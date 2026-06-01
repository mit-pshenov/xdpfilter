# Task brief — MVP-4.20 / test-honesty: stop T_BITVEC_VERIFIER_LOAD over-claiming the 5.15 floor (B23-min, brownfield, TEST+DOC ONLY)

## Goal
`tests/T_BITVEC_VERIFIER_LOAD.sh` claims more than it verifies. Its PASS line (`:159`) prints **"prototype verifies on the 5.15 floor"** and its header (`:7`) asks "VERIFY on the 5.15 floor?" — but the test actually (a) runs on whatever the dev kernel is (**6.1**, NOT 5.15 — `uname -r` = `6.1.0-44-cloud-amd64`), and (b) loads the **4-axis PROTOTYPE** object `bitvec_proto.bpf.o`, NOT the production 9-axis `mac_filter.bpf.c` (now dst/src/proto/port/vlan/mac/dst6/src6/ethertype + IPv6 ext-walk + variable IHL-offset L4 read). So the production object is untested on the stated floor, and the test's own output over-states its guarantee.

**B23-min = the takeable, NO-INFRA slice**: reword the misleading prose so the test states what it ACTUALLY verifies (the prototype object loads/verifies on the **dev kernel**, NOT the prod object on a 5.15 floor), and add an honest gap-note in design.md recording that the production object remains unverified on the 5.15 floor → tracked as the **infra-gated full-B23** (a CI lane that `bpftool prog load`s the production `.o` on a real 5.15 image — explicitly OUT OF SCOPE here). Same spirit as MVP-4.19's correction that ASAN instruments the userspace binary only. PURE test+doc honesty — no datapath/loader logic change.

## Context: prior work
- Prior briefs archived in `mint/task-brief-*.md` (latest: `task-brief-mvp-4.19.md` = B22, shipped+pushed `5e339ac`).
- Clean tree, `main == origin/main`. Match model = 9 axes across 3 family arms; VERSION 0.15.0, schema 2, guards catalog at #28.
- **Phase-2 grep verification (run — see footer):**
  - `T_BITVEC_VERIFIER_LOAD.sh` EXISTS; misleading strings at `:7` (comment) + `:159` (PASS message). Sanity-floor prose at `:22-28` also frames "the 5.15 floor".
  - The test loads `bitvec_proto.bpf.o` (the prototype — `:43-57` find_proto_obj) and/or `bitvec_harness populate` (`:62-75`), NOT the production object. Confirmed.
  - `uname -r` = `6.1.0-44-cloud-amd64` — the test runs on 6.1, not 5.15.
  - design `§5.44` (bitvec axes 3-4) + `§5.47` (MAC axis) both EXIST → candidate homes for the honest note (architect picks; a NEW §5.60 is also fine).
  - Guard #13 ripple: the literal "5.15 floor" is referenced by `T_BITVEC_VERIFIER_LOAD.sh`, `docs/BACKLOG.md:151` (the B23 entry itself), and **4 design-intent comments in `src/bpf/mac_filter.bpf.c` (`:578/:600/:641/:782`)**. The bpf.c comments are PROD design-rationale (constructs *designed* 5.15-safe: bounded `#pragma unroll`, no `bpf_loop`, FFS/ihl fallbacks) — NOT the test's over-claim. See Q1 for whether they're in-scope.
  - Guard #12: `tests/CMakeLists.txt:1086+` gives `T_BITVEC_VERIFIER_LOAD` `RESOURCE_LOCK xdp_fixture` (harness populate attaches to veth) — retained (no ctest add).
- **B15 (.pyc hygiene) is ALREADY SATISFIED — dropped from scope.** Phase-2 grep: `git ls-files` tracks NO `__pycache__`/`*.pyc`, and `.gitignore:33-34` already carries `__pycache__/` + `*.pyc`. The backlog B15 entry is stale (the artifact was removed earlier); nothing to do. Recorded in Out-of-scope.
- PI continuity: loader.hpp PI-7 trivially CONTINUES (untouched); no product PI moves. **`git diff -- src/bpf/ src/lib/` MUST stay empty UNLESS the architect rules the bpf.c comments in-scope (Q1) — in which case the ONLY src change is comment text, zero datapath bytes.**

## Workflow rules (brownfield)
- **Architect**: read design.md §5.44 + §5.47 (the bitvec verifier / axis lowering context) + §6.46 (the T_BITVEC_VERIFIER_LOAD design, if a §6.x block exists). EDIT design.md in place; append the honest gap-note (own §-number — §5.60 or a sub-note under §5.44; architect's call). Decide Q1 (bpf.c comment scope) + Q2 (where the design note lives + exact honest wording). You own realizability: the precise reworded strings must be ACCURATE (don't replace one over-claim with another — e.g. don't claim "verifies on 6.1" as if that were a guarantee of floor-safety).
- **Impl**: FileList DIFF — Edit `tests/T_BITVEC_VERIFIER_LOAD.sh` (the reworded prose) + `docs/BACKLOG.md` (update the B23 entry: reword-shipped, fix stale "6 axes"→9, full CI-lane remains infra-gated) + (architect-gated) the 4 `mac_filter.bpf.c` comments. NO datapath/loader logic edit. Keep the test's load mechanism, assertions, and RESOURCE_LOCK byte-identical — ONLY the human-readable prose changes.
- **Tester**: VERIFY the reworded test still PASSES (the load/verify assertion is unchanged — only message text differs) AND the new message is accurate (states "prototype" + "dev kernel", not "prod object" / "5.15 floor"). Full suite stays green (96/96). NO new ctest expected.
- **Reviewer**: 5-point brownfield; **special attention**: (a) the reworded prose no longer over-claims (no "5.15 floor" guarantee, no "production object" implication) AND introduces no NEW over-claim; (b) the test's behavioral core (object find, `bpftool prog load` rc=0 assertion, harness populate path, RESOURCE_LOCK) is byte-unchanged — pure prose; (c) `git diff -- src/lib/` EMPTY and `git diff -- src/bpf/` EMPTY-or-comment-only (per Q1); (d) the design.md note honestly scopes the gap (prod object untested on 5.15 → infra-gated full-B23) without claiming the gap is closed; (e) docs/BACKLOG.md B23 entry reflects partial-completion, not full closure.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.20-1: scope = test+doc honesty ONLY, full CI-lane stays deferred → **reword + design-note + backlog-update; NO 5.15 CI lane**
The production-object-on-5.15 verification needs a real 5.15 kernel image / CI lane (infra-gated) — explicitly OUT OF SCOPE. This slice only stops the over-claim and records the gap honestly.

### HG-mvp-4.20-2: keep the test's behavioral assertions byte-identical → **prose-only edit**
Do NOT change what the test loads, how it asserts rc=0, the harness-populate fallback, or the RESOURCE_LOCK. The test's *verification* is fine; only its *description of what it verifies* is wrong. Prose-only.

## Open mechanism questions (architect decides; document in the new note)

### Q1: are the 4 `mac_filter.bpf.c` 5.15 design-intent comments in scope?
- **A1 — leave bpf.c untouched (RECOMMENDED)**: the `:578/:600/:641/:782` comments are PROD design-rationale (the constructs are *intended* 5.15-safe). They're not the test's runtime over-claim. Leaving them keeps the slice test+doc-only (`git diff -- src/` EMPTY). Capture the "designed-5.15-safe but UNVERIFIED on 5.15" caveat ONCE in the design.md note instead.
- **A2 — lightly caveat bpf.c**: if the architect judges `:578` ("verifies on the 5.15 floor") itself over-claims (it asserts a property never tested), add a 1-word caveat ("*designed to* verify") at those sites. Cost: widens the diff into prod source (comment-only, zero datapath bytes) + a guard #13 ripple to keep wording consistent.
- **Recommendation**: **A1** — concentrate the honesty fix in the test + one design note; treat bpf.c comments as accurate design-intent and caveat them collectively in the note. Architect overrides to A2 if `:578`'s specific wording reads as a test-result claim rather than a design goal.

### Q2: where does the honest gap-note live + what's the exact wording?
- **A1**: a NEW `§5.60` (MVP-4.20) block — clean, self-contained, mirrors the per-slice §-numbering.
- **A2**: a sub-note appended under `§5.44` (the bitvec-verifier home) and/or `§5.47`.
- **Recommendation**: architect's call (realizability — wherever the T_BITVEC_VERIFIER_LOAD guarantee is currently documented). The note MUST state: (1) the test verifies the PROTOTYPE object on the DEV kernel; (2) the production 9-axis object is UNVERIFIED on the 5.15 floor; (3) closing the gap = infra-gated full-B23 (CI lane on a 5.15 image). Operative-semantic: the wording is SHOULD-level orientation, not a literal contract.

## Scope (concrete items — FileList DIFF)

### B23-1 — reword the over-claiming prose
**Where**: `tests/T_BITVEC_VERIFIER_LOAD.sh` (EDIT, prose-only)
- `:159` PASS message: drop "prototype verifies on the 5.15 floor" → an accurate statement (the prototype object verifies/loads on the dev kernel; this is NOT a 5.15-floor nor a production-object guarantee).
- `:7` header comment + `:22-28` sanity-floor prose: reframe from "the 5.15 floor" to what's actually exercised (prototype verifier acceptance on the dev kernel), with a pointer to the design note for the real-floor gap.
- KEEP byte-identical: the object-find logic (`:43-80`), the `bpftool prog load` rc=0 assertion, the harness-populate fallback, `RESOURCE_LOCK xdp_fixture`, the SKIP guard.

### B23-2 — honest gap-note in design.md
**Where**: `mint/design.md` (EDIT/APPEND, per Q2)
- Record the prototype-vs-production + dev-kernel-vs-5.15-floor gap; scope closing it to the infra-gated full-B23.

### B23-3 — update the backlog entry
**Where**: `docs/BACKLOG.md` (EDIT, `:151` B23 block)
- Mark B23-min reword as shipped; fix the stale "6 axes" → 9 axes; note the full CI-lane (prod `.o` on 5.15 image) remains the deferred/infra-gated remainder.

## Out of scope (explicit)
- **B15 (.pyc + .gitignore hygiene) — ALREADY SATISFIED** (no tracked `__pycache__`/`*.pyc`; `.gitignore:33-34` already covers it). Nothing to do; the backlog B15 entry is stale and may be marked done.
- ANY datapath / loader logic change; ANY new axis / schema / VERSION change.
- The **full B23**: a CI lane that loads the PRODUCTION `mac_filter.bpf.c` object on a real 5.15 kernel image (infra-gated — needs a 5.15 image / CI runner).
- B26 (pass_cidr rename — stat-enum slice), B30 (slot/id decouple — PO-gated designed slice), B27 (exporter DoS — security, HELD).

## Definition of done
- design.md honest gap-note (per Q2) — prototype/dev-kernel vs prod/5.15 gap recorded, full-B23 scoped as infra-gated.
- `tests/T_BITVEC_VERIFIER_LOAD.sh` reworded prose no longer over-claims; behavioral assertions byte-identical.
- `docs/BACKLOG.md` B23 entry reflects partial completion.
- `git diff -- src/lib/` EMPTY; `git diff -- src/bpf/` EMPTY (Q1=A1) or comment-only (Q1=A2). loader.hpp PI-7 trivially continues.
- Full ctest stays green (96/96) — T_BITVEC_VERIFIER_LOAD still PASSES (reworded message, unchanged verdict).
- NO schema/VERSION change (stays 0.15.0 / schema 2 / 9 axes).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang-19/C++23 + the bitvec prototype object (`bitvec_proto.bpf.o`) + `bitvec_harness` (existing).
- Runtime: veth + bpffs + sudo (existing fixture, unchanged).
- Kernel/platform: dev kernel 6.1 (existing). The full-B23 (deferred) would need a 5.15 image — NOT this slice.

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
**MECHANICAL.** One small realizability axis (Q1: bpf.c comment scope — recommended A1=leave) + one placement axis (Q2: where the note lives — architect's call). Neither is multi-axis, expensive-to-undo, nor ≥3-viable-options design space — it's a prose-honesty fix on a test + a design note. No PO-tier value question (PO-filter: no external value to name — pure engineering/honesty coverage; the full-B23 CI-lane IS infra-gated but that's explicitly deferred, not a fork for this slice). **No /mint-hld, no spike.** Single-architect, light path per [[feedback_band_by_default]]. **Scope shrank during Phase 2**: B15 fell out (already done) → slice is B23-min solo.

## Notes for architect Phase A code-grep discipline
Re-run (guard #5):
- `grep -nE '5\.15|floor|prototype verifies|VERIFY on' tests/T_BITVEC_VERIFIER_LOAD.sh` — confirm the exact over-claiming strings + line anchors (line numbers shift; anchor on the string).
- `grep -nE 'bitvec_proto|mac_filter\.bpf|bpftool prog load|find_proto_obj|find_harness' tests/T_BITVEC_VERIFIER_LOAD.sh` — confirm WHAT the test loads (prototype, not prod) so the reworded message is accurate.
- `grep -rln '5\.15 floor\|prototype verifies' tests/ docs/ src/` — confirm the guard #13 ripple set (test + BACKLOG:151 + bpf.c:578/600/641/782) before deciding Q1.
- `uname -r` — confirm the dev kernel is NOT 5.15 (the core of the over-claim).
- Confirm `git ls-files | grep -E '__pycache__|\.pyc'` is EMPTY and `.gitignore` already has the rules (B15 already-done; do not re-add).
- Verify whichever §-section you attach the note to actually exists / is the right home (§5.44 / §5.47 / new §5.60).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #13 (retired-string ripple)** — the over-claiming "5.15 floor" prose is reworded in the test; check no OTHER consumer asserts the old PASS string (grep above: only the test + BACKLOG + bpf.c design-intent comments reference it; BACKLOG is updated in B23-3; bpf.c is Q1).
- **Guard #12 (RESOURCE_LOCK for shared host state)** — the test keeps touching veth + bpffs; `RESOURCE_LOCK xdp_fixture` (CMakeLists:1086+) MUST be retained (prose-only edit; no ctest add/split).
- **Guard #5 (Phase A grep discipline)** — architect re-runs the greps above to prove the reworded strings are accurate (prototype + dev-kernel) and not a new over-claim.
- **Operative-semantic discipline** — the exact reworded wording + the design-note text are SHOULD-level orientation; the architect owns the precise accurate phrasing; deviations preserving the honesty intent are `inline-merge`.
- **Guard #11 (VERSION-bump propagation)** — N/A (no bump).
