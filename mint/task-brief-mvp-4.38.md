# Task brief — MVP-4.38 / B45: `apply --dry-run` human-decoded operator view (brownfield)

## Goal

Roadmap-① slice 1c (PO Dmitry, confirmed): the last piece that makes `apply --dry-run` fully
usable by an OPERATOR — a **human-decoded view** that lets ops SEE what's wrong with a config
before applying it. B44/§5.77 shipped the production render seam + the machine `# xdpfilter-image v1`
golden, but that golden is a raw hex map-dump — a test oracle, useless to an operator who needs to
verify "did my config compile to what I meant?" (wrong redirect target, a CIDR that lowered to
unexpected bits, an unintended default action, a rule that matches nothing). This slice adds the
readable, vocabulary-correct decode that turns dry-run from a test tool into an ops debugging tool.

**BAKED PO DECISION (not a fork):** the human view becomes the **DEFAULT** output of
`apply --dry-run` (the operator is the audience). The machine golden moves behind an explicit
`--format=golden` (alias `--format=image` if the architect wants). This is host-side
output-formatting ONLY — zero datapath/live change.

## Context: prior work

- Prior brief: MVP-4.37/B44 `apply --dry-run` → archived `mint/task-brief-mvp-4.37.md`.
- Design to amend: `mint/design.md` (append **§5.78**); highest prior = §5.77. Architecture
  `mint/architecture-dryrun.md` (image-format lens touched the human-vs-golden representation).
- Brief-author Phase 2 greps (confirmed against current code):
  - B44 seam: `ApplyConfig.dry_run` (`src/cli/apply.hpp:33`); `render_dryrun_image(parsed)` called
    at `src/cli/apply.cpp:136`; `[[nodiscard]] std::string render_dryrun_image(const Config& cfg)`
    + `format_dryrun_image(const std::vector<RecordedWrite>& recs, …)` in `src/lib/map_image.hpp`
    (render does compile→record→**format** internally and returns the golden STRING today — see Q2,
    it must be split so the CLI can pick the formatter); `cfg.dry_run = true` set at
    `src/cli/cli.cpp:249` (the `--dry-run` parse).
  - `RecordedWrite` = the dumb `(map,key,value)` trace in CALL order (`src/lib/map_writer.hpp:72`);
    `kMapCatalog` maps tag→{name,key_sz,val_sz}. **The trace carries the GLOBAL lowered structure
    (per-axis maps, the action_table keyed by action_type, the devmap), NOT an ordered per-rule
    view** — `action_table` is identity-keyed by action_type (the B42 single-tap model), so a clean
    "rule N → its match + action" reconstruction from the trace alone is lossy/fiddly (see Q1).
  - `T_CLI_APPLY_DRYRUN.sh` (#113) currently asserts on the DEFAULT `apply --dry-run` stdout:
    first line `== "# xdpfilter-image v1"` (`:76`), `grep '^map=redirect_devmap '` (`:85`),
    `grep 'dpi0 RESOLVED-AT-APPLY'` (`:89`), NODEV absent (`:94`). These golden assertions MUST
    move behind `--format=golden`; the default-output assertions become human-view greps.
  - `docs/CONFIG_SCHEMA.md` vocabulary: `default_action: drop|pass`, `rules[].action:
    pass|drop|redirect`, `match: {…}`, `steering: { redirect_to: <iface> }` — the operator-facing
    names the human view should use.
  - `T_DRYRUN_IMAGE_IDENTITY` (#112) calls `format_dryrun_image` directly → UNAFFECTED by the
    default-format change.
- PI continuity: PI-mvp-4.36/4.37-LIVE-IDENTITY (live apply byte-identical — this slice touches no
  live/materialize/seam code), PI-mvp-4.37-FAILCLOSED, PI-mvp-4.37-SSOT, PI-7, insn 3477, the
  golden byte-UNCHANGED.

## Workflow rules (brownfield)

- **Architect (Phase A):** read `mint/architecture-dryrun.md` (image-format lens) + design.md §5.77
  (B44 seam) + §6.5 invariants. Re-run the Phase-2 greps. EDIT `design.md`, append **§5.78**.
  Resolve Q1 (human-view render SOURCE) + Q2 (split render_dryrun_image so the CLI picks the
  formatter) + the HG-2 diagnostic-depth call. **Architect owns realizability** — the brief frames
  the source fork; the architect picks + grounds it.
- **Impl:** the human formatter + the `--format` flag, per the resolved design. NO change to the
  live apply path, the materialize seam, or `format_dryrun_image` (the golden formatter).
- **Tester:** switch `T_CLI_APPLY_DRYRUN`'s golden assertions to `--format=golden`; ADD assertions
  on the DEFAULT human output (greps for readable per-rule lines + default_action + the redirect
  target). MANDATORY: a NEGATION — a config with a deliberate issue (e.g. a rule whose match is
  empty / a redirect with no steering target) → the human view surfaces it, AND a comparator-can-
  fail control.
- **Reviewer:** 5-point brownfield. Special attention: PI-LIVE-IDENTITY (this slice is pure
  host-side formatting — `git diff` of the live path/materialize/map_writer must be ∅), PI-SSOT
  (the human formatter does NOT become a parallel image-builder / a reimplementation of the
  lowering — it renders from a TESTED source per Q1), golden byte-UNCHANGED (now via
  `--format=golden`), the `--format` default is human.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.38-1: default output format → **human** (BAKED, PO)
`apply --dry-run` with no `--format` prints the human view. `--format=golden` prints the
`# xdpfilter-image v1` machine image (byte-unchanged from B44). Not a fork — the operator is the
audience.

### HG-mvp-4.38-2: diagnostic depth → **useful-but-bounded** (default)
The human view does a faithful per-rule / per-axis decode in operator vocabulary + the
redirect-target-resolution note (`redirect_to=<iface> → RESOLVED-AT-APPLY (verify it's up)`) + a
cheap "rule N matches nothing / empty axis" hint where it falls out for free. DEFER heavier linting
(rule-overlap/shadowing analysis, unreachable-rule proofs) to a future slice. Architect sets the
exact depth; the bar is "an operator can spot a config mistake," not "a full linter."

## Open mechanism questions (architect decides; document in §5.78)

### Q1: what does the human view render FROM? (the SSoT-honesty fork)
- **A1 — from the validated `Config` / `CompiledRuleset`** (the semantic pre-image): cr already
  carries per-rule id→slot→bit→action + the match (from Config) in named, ordered form — the
  natural source for a readable "your rule X → compiled to Y" view. SSoT note: this is the
  compile-output view (pre-materialize), distinct from the golden's post-materialize bytes — BUT
  `compile()` is already offline-tested (`compile_harness`/`T_COMPILE_LOWERING_IDENTITY`) to
  produce the correct cr, so it renders from a TESTED-correct source, not a fresh reimplementation.
- **A2 — decode the recorded `(map,key,value)` trace** (the same one the golden formatter consumes):
  maximally faithful to what materialize WROTE, single source with the golden. BUT (grounded above)
  the trace is the GLOBAL lowered structure with action_table identity-keyed — reconstructing an
  ordered per-rule semantic view from it is lossy/fiddly and needs to cross-join the Config anyway.
- **A3 — hybrid:** render the per-rule semantic view from Config/cr (A1) AND cross-check/annotate
  against the trace ("rule 7 → slot 2 bit 0x04, present in the written image") for faithfulness.
- **Recommendation:** the grounding favors **A1** (render from Config/cr) for genuine readability —
  the trace (A2) is lossy for the ordered per-rule view ops want, and cr is a tested source so the
  guard-#9 / SSoT concern is mild (the golden retains the byte-faithful role; the human view's job
  is operator readability). The architect confirms cr carries everything needed (match + action +
  target + slot) and rules on A1-vs-A3. **Do NOT build a fresh lowering reimplementation** (that
  would be the real guard-#9 violation) — render from cr/Config, the existing tested compile output.

### Q2: split `render_dryrun_image` so the CLI can choose the formatter
`render_dryrun_image(const Config&)` currently does compile→record→format→returns the golden
string. The CLI needs to render once then pick human|golden.
- **Recommendation:** factor render (compile→record→**trace**) from format; the CLI calls the
  chosen formatter (`format_dryrun_image` for golden / the new human formatter for human). Keep
  `format_dryrun_image` byte-identical. For A1, the human formatter also needs the Config/cr (pass
  it through). Architect picks the exact signature; `render_dryrun_image`'s public name/semantics
  may shift — PI-7 does NOT apply (it's not loader.hpp), but keep the harness's `format_dryrun_image`
  entry stable (T_DRYRUN_IMAGE_IDENTITY links it).

## Scope (cycle B45 — concrete items; architect refines)

### Item B45-1 — human formatter
**Where**: `src/lib/map_image.{hpp,cpp}` (a `format_dryrun_human` sibling to `format_dryrun_image`,
consuming the source Q1 settles) + whatever Q2 render-split needs. Per-rule readable decode +
default_action + redirect target + the bounded diagnostic (HG-2).

### Item B45-2 — `--format=human|golden` flag (default human)
**Where**: `src/cli/cli.cpp` (`parse_apply` — accept `--format=`), `src/cli/apply.hpp`
(`ApplyConfig` gains a `format` enum, default human), `src/cli/apply.cpp` (the dry-run branch picks
the formatter). The B44 `--dry-run` branch already exists.

### Item B45-3 — test switch + human-output coverage
**Where**: `tests/T_CLI_APPLY_DRYRUN.sh` (golden assertions → `--format=golden`; NEW default-human
assertions; NEGATION on a config-with-an-issue), possibly a NEW fixture under `tests/dryrun/` for
the diagnostic-negation config. `tests/CMakeLists.txt` only if a new fixture/test is added.

## Out of scope (explicit)

- **② per-rule redirect targets**, **Option-4 gate-shrink**, **mirror/rate-limit** (later roadmap).
- **Heavy config-linting** beyond the bounded HG-2 diagnostic (rule-overlap/shadowing/unreachable
  analysis → a future slice if wanted).
- **Any live/datapath/materialize change** — this is host-side formatting only.
- **VERSION bump** — architect's call (completes a user-facing feature); default no-bump.

## Definition of done

- §5.78 amendment in `mint/design.md` (Q1/Q2 + HG-2 resolved).
- `apply --dry-run` default = human view; `--format=golden` = the byte-unchanged machine image.
- Human formatter renders a readable per-rule/per-axis decode + default_action + redirect target +
  the bounded diagnostic, from a TESTED source (no fresh lowering reimpl).
- `T_CLI_APPLY_DRYRUN` updated (golden → `--format=golden`; new human assertions + NEGATION);
  `T_DRYRUN_IMAGE_IDENTITY` still green; golden byte-UNCHANGED.
- PI continuity: PI-LIVE-IDENTITY (live path/materialize/map_writer git-diff ∅), PI-FAILCLOSED,
  PI-SSOT, PI-7, insn 3477.
- Full local ctest suite green; `mint/review.md` round-1 = pass.
- One git commit per phase boundary.

## Dependencies

- Build: clang-19 / libc++ / C++23 (existing). No new deps (host-side formatting; dry-run stays
  ZERO kernel calls).
- Runtime: the human view + the CLI test run offline (no root/veth/kernel).

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

**Single-axis design slice → single-architect `/mint-dev`, NO new `/mint-hld`.** The one fork is the
human-view render SOURCE (Q1: from Config/cr vs the trace) — ONE axis, the image-format lens already
touched human-vs-golden, and the grounding points clearly at A1 (render from the tested cr). The
human-is-default decision is PO-baked (not a fork). Q2 (render split) is a mechanical refactor. The
diagnostic depth (HG-2) is a bounded engineering call. No multi-axis residue → no HLD.

## Notes for architect Phase A code-grep discipline

Re-run independently (briefer ran these; verify + extend):
- `grep -nE 'render_dryrun_image|format_dryrun_image|RecordedWrite' src/lib/map_image.hpp src/lib/map_writer.hpp` — the seam the human formatter is a sibling to + the render-split point (Q2).
- `grep -nE 'dry_run|format' src/cli/apply.hpp src/cli/apply.cpp src/cli/cli.cpp` — the `--format` threading points (ApplyConfig + parse_apply + the dry-run branch).
- Confirm the `CompiledRuleset` (compiled_ruleset.hpp) carries per-rule match + action + target + slot needed for A1 — i.e. the human view can render the operator-meaningful view WITHOUT a fresh lowering reimplementation (the guard-#9 line).
- `grep -nE 'xdpfilter-image|--format|first_line' tests/T_CLI_APPLY_DRYRUN.sh` — the current golden assertions to migrate behind `--format=golden`.
- `docs/CONFIG_SCHEMA.md` — the operator vocabulary (default_action/action/match/steering.redirect_to) the human view should mirror.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #9 (SSoT / no parallel builder):** THE central guard — the human formatter must render from
  a TESTED source (the existing `CompiledRuleset` compile output, or the recorded trace), NOT a fresh
  reimplementation of the lowering. A second hand-rolled config→image computation is
  [INVARIANT-VIOLATED]. The golden (`format_dryrun_image`) stays the byte-faithful SSoT.
- **Guard #36 (capture-vs-format split):** the human view is another FORMATTER over the same captured
  result; keep format logic separate from the render/capture (mirrors the B44 format_dryrun_image
  split).
- **Guard #8 (interactive-vs-log / output-surface distinction):** the human view is operator-facing
  stdout, not a log event — keep it out of the structured-log catalog; it's a CLI render.
- **PI-mvp-4.36/4.37-LIVE-IDENTITY:** verify `git diff` of the live apply path / materialize.cpp /
  map_writer.cpp / live_map_writer.cpp = ∅ (this slice adds a formatter + a flag, touches no live
  code).
- **Guard #11 (VERSION-bump test-literal propagation):** only if the architect elects a VERSION bump
  (default no-bump) — then grep the version literal sites.
