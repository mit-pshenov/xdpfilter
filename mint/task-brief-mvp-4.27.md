# Task brief — MVP-4.27 / B37: make the two decorative regression gates real (brownfield)

## Goal

Two of the project's regression gates are **decorative on exactly the surfaces a
behavior-preserving refactor mutates** — they observe the invariant but never
assert it, so a regression passes silently:

1. **BPF instruction-stream gate.** `tests/T_PROD_VERIFIER_LOAD.sh` loads the
   shipped `xdpfilter.bpf.o`, reads the xlated insn count, **prints** it, but
   asserts only `rc==0` (verifier accepted). The 3658-insn baseline — the
   number every byte-identity claim leans on — has **no automated gate**. This
   was a deliberate SHOULD-level decision (`D-mvp-4.23-H3-PRODOBJ`,
   design.md:17559 / §6.80:17601). This slice **consciously reverses** it.
2. **Operator-facing loader stderr gate.** `throw_loader` / `classify`
   (`src/lib/loader.cpp:333,342`) emit `std::system_error` whose `what()` renders
   to the operator as `"<label>: <category-message>"` (via `main.cpp:112-197`).
   That text is part of the operator/audit ABI (greppable prefix,
   `docs/FLEET_DEPLOYMENT.md:37`) and is **pinned by NO ctest** — only `T_BUILD`
   compile-clean. ~20 existing tests grep stderr *substrings* incidentally; none
   pin the **shape corpus**.

**Why now / payoff.** This is the **test-hardening prerequisite for B34** (the
`__always_inline` extraction + `.bpf.c`/`.h` module split), which rests entirely
on the "xdp 3658 byte-identical" guard these gates would make real. It also
unblocks the deferred behavior-preserving folds catalogued in the external review
(`SESSION-SUMMARY-20260603` P3/P4 objdump-gated, P6 stderr-gated) and catches
future codegen/message regressions. Source finding: `docs/BACKLOG.md` B37 +
`/home/user/agent-teams-review/runs/SESSION-SUMMARY-20260603-simplifier-trial.md`.

Not an architecture-v2.md row — this is a `docs/BACKLOG.md` B37 test-hardening
item, sequenced BEFORE B34 in the tidiness workstream.

## Context: prior work

- All prior briefs archived in `mint/task-brief-*.md` (this one supersedes mvp-4.26/B33 rename).
- Most recent slice: **MVP-4.26 / B33** rename → `xdpfilter` (`00e28ea`, round-1, VERSION 0.16.0, xdp 3658 byte-identical).
- Existing design: `mint/design.md` §5.63 (T_PROD_VERIFIER_LOAD origin / D-mvp-4.23-H3-PRODOBJ), §6.80 (the test's verifiable-invariants block), §5.66 (rename, current tail).
- **Brief-author Phase 2 grep verification** (this brief) — greps run, see evidence footer. Both surfaces confirmed live; guard count confirmed **#34** (`Guard #34 (candidate)` design.md:18012).
- PI continuity: this slice is **test-infra + design-doc only**. PI-7 (`loader.hpp`/`config.hpp` zero-diff) trivially CONTINUES (no source touched). The `xdpfilter.bpf.c` program bytecode stays **byte-identical** (the slice asserts that fact, does not change it).

## Workflow rules (brownfield)

- **Architect**: read design.md §5.63, §6.80, §5.66 + this brief. EDIT design.md in place; append a new §5.67. **Must cite the prior `D-mvp-4.23-H3-PRODOBJ` text + the §6.80 point-8 "missing insn-count assert is NOT a gap" line VERBATIM and mark them RETIRED/SUPERSEDED** (per [[impl-role-discipline]] — this is a sanctioned design reversal, not silent deviation). Decide Q1/Q2; document tactical D-mvp-4.27-* choices.
- **Impl**: FileList per mode. Source untouched (`grep` should confirm `git diff -- src/` is EMPTY at the end — this is a test+design slice). Work lives in `tests/`.
- **Tester**: NEW ctest(s) for the golden-stderr corpus; EDITED `T_PROD_VERIFIER_LOAD.sh` (promote insn check) + `tests/CMakeLists.txt` registration. Honor SKIP discipline (tooling-absence ≠ failure).
- **Reviewer**: 5-point brownfield framework. **Special attention**: (a) the insn-assert must NOT convert a SKIP/tooling-absence path into a hard FAIL (only assert when the count was actually read on the `rc==0` path); (b) the escape hatch must actually let an intentional codegen change pass with a one-line baseline bump; (c) the golden corpus must pin operator-REACHABLE shapes, not internal-only messages; (d) confirm `git diff -- src/` empty (no datapath/loader change).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.27-1: VERSION bump → **NO bump (stay 0.16.0)**
Test-infra + design-doc only; zero operator-visible surface change (no binary/CLI/schema/metric/env change). Mirrors the **MVP-4.23 CI-gate precedent** (zero-src test-hardening shipped without a bump). Architect overrides only if some operator surface is unexpectedly touched. ⇒ guard #11 (VERSION literal propagation) is **N/A** under this default.

### HG-mvp-4.27-2: insn-count assert + escape hatch → **fatal compare against 3658 baseline, overridable by env**
Promote the existing informational `insns` read in `T_PROD_VERIFIER_LOAD.sh` to a **fatal** assert: when the count is successfully read on the `rc==0` path, `insns != baseline` ⇒ test FAILS with a loud "complexity/codegen regression OR intentional change — bump baseline" message. **Escape hatch**: an env override (default name suggestion `XDPMF_PROD_INSN_BASELINE`, architect/tester finalize) lets an intentional codegen change pass by setting the new expected value, AND the failure message names that hatch. This **consciously reverses `D-mvp-4.23-H3-PRODOBJ`** — architect documents the reversal + new PI.

### HG-mvp-4.27-3: SKIP/tooling-absence discipline → **PRESERVED — absence never becomes failure**
The insn assert fires ONLY on the path where `rc==0` AND the count was actually parsed from `bpftool prog show`. All existing SKIP 77 paths (no bpftool / object not built / no passwordless sudo / count unparseable) stay SKIP, never FAIL. `D-mvp-4.23-H3-NOLOCK` (no RESOURCE_LOCK on this test) is UNCHANGED — promoting print→assert does not add iface/attach state.

## Open mechanism questions (architect decides; document in §5.67)

### Q1: golden-stderr corpus scope + match strategy
- **A1 — full LoaderError corpus**: golden file enumerating every operator-reachable `LoaderError` code's rendered `"<label>: <message>"` shape; exact-match diff.
- **A2 — targeted operator-throw sites**: golden only for the handful of throw sites an operator actually triggers via the CLI (kernel-too-old, path-refused, permission, load-failed), driven through the real CLI entry points; exact-match.
- **A3 — shared golden helper extending existing stderr tests**: factor a `tests/lib` golden-compare helper, repoint a representative subset.
- **Recommendation**: **A2** (operator-REACHABLE shapes via the real CLI, exact-match against a small checked-in golden) — it pins the audit-ABI contract the finding names without over-coupling to internal-only error codes that never reach an operator. Architect owns realizability + exact corpus membership (which `LoaderError` codes are operator-reachable is an architect grep, not a brief literal).

### Q2: where the insn-fatal assert lives
- **A1 — promote in place** in `T_PROD_VERIFIER_LOAD.sh` (the object is already loaded+pinned there).
- **A2 — new dedicated test** that re-loads + reads the count.
- **Recommendation**: **A1** — A2 doubles the privileged `bpftool prog load`; the count is already computed at `:97-98`, the change is print→assert + escape hatch. Keeps the verifier-load privileged path single-owner.

D-mvp-4.27-* (tactical, architect documents in Phase A; NOT pre-loaded): exact env-var name, golden file path/naming convention, exact-match vs normalized diff (trailing-strerror locale stability), the precise set of operator-reachable LoaderError codes, golden-test RESOURCE_LOCK need per guard #12.

## Scope (cycle — concrete items; UPPER-BOUND estimates)

### Item B37-1 — insn-count gate: print → fatal assert (+ escape hatch)
**Where**: `tests/T_PROD_VERIFIER_LOAD.sh` (the `if rc==0` block ~`:91-101`; header comment ~`:30-32`).
Promote the informational `insns` read to a fatal `insns == baseline(3658)` assert on the read path; add the env escape hatch + a failure message naming it. Update the header comment block that currently documents the SHOULD/non-fatal intent (`:30-32`, `:94-96`) to the new fatal-with-hatch contract.

### Item B37-2 — golden-stderr ctest (operator error-shape corpus)
**Where**: NEW `tests/T_LOADER_STDERR_GOLDEN.sh` (name architect/tester final) + NEW `tests/fixtures/loader_stderr_*.txt` golden(s) + `tests/CMakeLists.txt` `add_test` registration.
Drive the operator-reachable loader error paths through the real CLI, capture stderr, compare against the checked-in golden per Q1. SKIP-clean where the path needs unavailable privilege/tooling.

### Item B37-3 — design amendment §5.67
**Where**: `mint/design.md`.
New §5.67: reverse `D-mvp-4.23-H3-PRODOBJ` (verbatim-cite + RETIRE the §6.80 point-8 "not a gap" line), record the new fatal-gate PI for both surfaces, and a candidate **guard #35** ("a regression gate that only PRINTS is decorative — a gate must fail-loud on its watched invariant, with an explicit intentional-change escape hatch; promoting print→assert may consciously reverse a prior SHOULD-level decision → cite it verbatim").

## Out of scope (explicit)
- **B34** (de-monolith helpers + module split) — this slice is its prerequisite, not part of it.
- **B35** (wildcard `ruleset_state` pack), **B36** (64-rule ceiling) — later workstream items.
- Applying the P3/P4/P6 folds from `SESSION-SUMMARY-20260603` — unblocked BY this slice, not done IN it.
- Any `src/` change — datapath/loader bytecode + strings are asserted-as-is, not modified. (`git diff -- src/` must be empty.)
- Fixing the stale `mac_filter.bpf.o` references in the historical D-mvp-4.23 design prose (design.md:17559/17566) — historical record, not this slice's job.
- VERSION bump / CHANGELOG entry (per HG-1 default).

## Definition of done
- §5.67 amendment in `mint/design.md` (reversal cited verbatim + RETIRED; new PI; guard #35 candidate).
- PI-7 trivially continues (source untouched); `xdpfilter.bpf.c` byte-identical (now asserted by B37-1).
- ctest baseline +N new (golden-stderr) and the promoted insn assert; full suite green to current baseline (101/103 with the 2 known env-fails by NAME — `T_EXPORTER_EXITS_6_ALL_IFACES_EACCES`, `T_LOG_JSON_EXPORTER_EVENTS`).
- No VERSION bump (HG-1).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build deps: unchanged (CMake/clang/libbpf as-is).
- Runtime deps: `bpftool` + passwordless sudo for the insn-load path (already SKIP-gated); golden test runs the built CLI.
- Kernel/platform: dev 6.1 (the insn baseline 3658 is the dev-host figure — the escape hatch is precisely for legit cross-env codegen differences; architect notes whether the baseline is host-pinned or a hard expectation).

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
**Mechanical, single-axis → single-architect `/mint-dev`, no `/mint-hld`.** The answer falls out of B37's stated scope (two named gates → assert them). No multi-axis design space: the only genuine choices are golden-corpus scope (Q1) and assert-placement (Q2), both defaultable with rationale and architect-overridable. Expensive-to-undo? No — test-only, reversible. The single design-flavored nuance (which error shapes are operator-reachable) is an architect grep, not a product/PO fork. PO-filter (POF-M2): no decision here carries external/product value requiring the user — all are engineering, discharged in-brief or routed to the architect. No prior `/mint-hld` ladder feeds this slice (BACKLOG-sourced, not hld-sourced).

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author already ran these (evidence footer); architect re-verifies + extends:
- `grep -nE '3658|insns=|xlated|rc.*-eq 0' tests/T_PROD_VERIFIER_LOAD.sh` — the print-not-assert site.
- `grep -nE 'D-mvp-4.23-H3-PRODOBJ' mint/design.md` — the decision to reverse (17559) + §6.80 point-8 (17601) to RETIRE.
- `sed -n '311,345p' src/lib/loader.cpp` — `LoaderCategory::message` + `throw_loader` + `classify` (the stderr shape source).
- `sed -n '85,200p' src/cli/main.cpp` — the catch arms that render `what()` to the operator (the exact `"<label>: <message>"` shape + any sentinel-suppression at `:95`).
- `grep -rln 'loader_error_category\|LoaderError::' src/lib/loader.cpp` — enumerate the operator-reachable code set for Q1 corpus membership.
- `grep -nE 'add_test' tests/CMakeLists.txt` — registration pattern + nearby `RESOURCE_LOCK`/`SKIP_RETURN_CODE 77` precedent for the new golden test.
- Confirm at end: `git diff --stat -- src/` empty (no source change).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #5 (Phase A code-grep discipline)** — always; architect repeats the brief's greps independently.
- **Guard #12 (RESOURCE_LOCK for shared host state)** — applies to the NEW golden-stderr ctest IF it touches bpffs/iface/fixed-port/systemd. If it only drives CLI error paths that fail before touching shared state, no lock; tester decides per actual codepath. `T_PROD_VERIFIER_LOAD` itself stays NO-LOCK (`D-mvp-4.23-H3-NOLOCK`).
- **Guard #13 (fixture cross-reference for retire/rename emit-sites)** — INVERTED here: the new golden fixture deliberately COUPLES to the loader message corpus, so a future `LoaderCategory::message` change ripples to the golden — that coupling is the GATE's purpose, not a hazard. No emit-site is retired this slice.
- **Guard #10 (catalog arithmetic)** — operative-semantic only: the golden corpus line-count is a SHOULD orientation for the reviewer, not a literal-match contract (per operative-semantic discipline; impl may add/normalize lines for shape symmetry → `inline-merge`).
- **Guard #11 (VERSION-bump literal propagation)** — **N/A** under HG-1 (no bump). Becomes applicable only if architect flips HG-1.
- **Guard #34 (operator-surface rename)** — **N/A** (no rename).

> Operative-semantic note for architect: counts/sizes/line-numbers in this brief and in the §5.67 verifiable-invariants block are SHOULD-level orientation, not literal-match contracts. Impl deviations mirroring existing precedent (golden line membership, fixture symmetry, retirement-citation comments at the reversed-decision sites) are `inline-merge` per design's resolution rule.
