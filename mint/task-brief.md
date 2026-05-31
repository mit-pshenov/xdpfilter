# Task brief — MVP-4.17 / housekeeping: dead-code + stale-comment cleanup (brownfield, CLEANUP)

## Goal
Two pure-cleanup backlog items, **zero behavior change**, bundled as one housekeeping slice:

- **B24** — delete vestigial dead code in the exporter sidecar reader: `classify_match_kind()` scans for a retired bare `"cidr"` key the producer NEVER emits (it emits `dst_cidr`/`src_cidr`/`dst_cidr6`/… — never bare `"cidr"`), so `has_cidr` is permanently false; the function's result `match_kind` is **written but never read** (the live label path = the per-axis `extract_axis` fields). Delete the function, its single assignment, and the `RuleMeta::match_kind` member (~−12 LOC).
- **B25** — fix comments + one dead initializer that still assert the **pre-S4/S5/S6** reality ("at-least-one-of mac/src_cidr", "6-axis", `schema_version = 1`). The match model is now **9 axes** (dst/src/proto/port/vlan/mac/dst6/src6/ethertype); the loader only ever applies v2. These are live-misleading prose, not history.

This is the cleanup-cluster first slice after the S1→S6 ladder + C3 fast-follow shipped. No schema change, no VERSION bump, verdict-identical. The `prom_format.hpp:16` "6-axis" fix is a direct C3 follow-on — C3 (`9abb02d`) changed the `prom_format.cpp` HELP line to "9-axis" but the `.hpp` doc-mirror still says "6-axis" (now self-contradictory).

**Bundle**: the uncommitted `docs/BACKLOG.md` status-marking edits (B21/B28/B31 + IPv4-gate marked SHIPPED, "ladder+C3 SHIPPED" section) ride in this slice's commit.

## Context: prior work
- Prior briefs archived in `mint/task-brief-*.md` (latest archived: `task-brief-mvp-4.15.md` = S6 ext-walk).
- Recent slices: S4 cidr6 (`971f2fd`), S5 EtherType (`99eb17e`), S6 ext-walk (`ce59a5e`), C3 sidecar match-kinds (`9abb02d`). Match model = 9 axes AND-composed across 3 family arms.
- Brief-author Phase 2 greps (all run, see verification footer): B24 sites (`sidecar_reader.cpp:7/39-47/93`, `.hpp:30`); confirmed `match_kind` has ZERO consumers (only the write at `:93`); B25 sites enumerated below.
- PI continuity: **loader.hpp PI-7 zero-diff CONTINUES** (this slice does NOT touch loader.hpp). No schema/VERSION PI moves.

## Workflow rules (brownfield)
- **Architect**: read design.md §5.46 (sidecar_reader axis-extraction), §5.43/§5.47 (config schema/mac re-accept), §5.56 (C3); EDIT design.md in place; append a short §5.57 (MVP-4.17) cleanup amendment. Re-run the Phase 2 greps independently (guard #5).
- **Impl**: FileList is EXACT — delete/edit only the listed sites. No opportunistic refactor beyond B24/B25.
- **Tester**: NO new ctests expected (pure cleanup, nothing new to assert). Confirm the full suite stays **96/96** green; the deleted `classify_match_kind`/`match_kind` are asserted by NO test (verified — guard #13). If the architect identifies a genuine assertion gap, a regression-guard ctest is OPTIONAL, not required.
- **Reviewer**: 5-point brownfield framework; **special attention**: (a) verdict-identity — diff the loader/exporter behavior is byte-identical except the deleted dead code; (b) no fixture/test references the retired `match_kind`/`classify_match_kind`/`"mac"`/`"cidr"`/`"both"` strings (guard #13); (c) `prom_format.cpp` HELP ("9-axis") and `prom_format.hpp:16` doc-mirror now AGREE.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.17-1: `schema_version` dead init value → **`= 2`**
`config.hpp:63` currently `= 1` (dead — `validate()` always overwrites from the parsed config, which `config.cpp:286-297` requires `== 2`). Set the in-struct default to `2` (the only supported value) so the init reflects reality rather than a retired `{1}` default. Architect MAY instead choose `= 0` (an obviously-invalid sentinel that would fail-loud if ever observed unvalidated) — both are behavior-identical since validate always writes. Default `= 2` for "reflects the only legal value".

### HG-mvp-4.17-2: comment-edit depth → **minimal-truthful**
Update each stale comment to state CURRENT reality (9 axes, v2-only) in ≤1 line; do NOT expand into history/changelog prose (that belongs in git/RETROSPECTIVES). Retain the existing `§5.xx` citation anchors.

## Open mechanism questions (architect decides; document in §5.57)

### Q1: regression-guard ctest for the B24 deletion?
- **A1**: none — pure dead-code removal, no observable behavior to assert; rely on the existing exporter tests staying green.
- **A2**: add a tiny ctest asserting the exporter still emits well-formed `xdpfilter_rule_info` after the delete (redundant with `T_EXPORTER_RULE_LABELS`).
- **Recommendation**: **A1**. `match_kind` was never in any output surface; `T_EXPORTER_RULE_LABELS` + `T_SIDECAR_V6_ETH_KINDS` already cover the live label path. Adding a test would assert nothing new.

## Scope (concrete items — FileList EXACT)

### B24-1 — delete `classify_match_kind` + `match_kind`
**Where**: `src/exporter/sidecar_reader.cpp` + `src/exporter/sidecar_reader.hpp`
- `sidecar_reader.cpp:39-47` — delete the `classify_match_kind` function definition.
- `sidecar_reader.cpp:93` — delete the `rm.match_kind = classify_match_kind(body);` assignment.
- `sidecar_reader.cpp:7` — fix the file-header comment that references `match_kind` "derived by substring scan" (now removed).
- `sidecar_reader.hpp:30` — delete the `std::string match_kind;` member + its comment.
- Verified: NO consumer of `RuleMeta::match_kind` anywhere (`prom_format.cpp`, `http.cpp`, tests) — only the deleted write.

### B25-1 — config.hpp stale prose + dead init
**Where**: `src/lib/config.hpp`
- `:12-13` — "§5.27 rule 7: at-least-one-of **mac/src_cidr** required" → reflect the current grammar: at-least-one-of the **9** match axes (the live error string at `config.cpp:457-459` already enumerates all 9 correctly).
- `:63` — `schema_version = 1` dead init → per HG-mvp-4.17-1.
- `:4` — "The schema (cycles 1+2)" — OPTIONAL light touch (mildly historical; architect's call).

### B25-2 — config.cpp + apply_internal.hpp header comments
**Where**: `src/lib/config.cpp`
- `:6` — header comment "match.* mapping MUST contain at-least-one-of {mac, src_cidr}" → 9 axes.
- (apply_internal.hpp:27 already says "schema_version 2" correctly — NO edit; listed only to fence it as verified-clean.)
- (config.cpp:457-459 error STRING already correct — NO edit; operator-facing, do not touch.)

### B25-3 — "6-axis" prose now stale at 9 axes
**Where**: `src/lib/loader.cpp` + `src/exporter/prom_format.hpp`
- `loader.cpp:2452` — "the single u32 store commits the whole **6-axis**+rules+wildcard+…" → 9-axis.
- `prom_format.hpp:16` — HELP doc-mirror "Per-rule match constraints (**6-axis**)" → "9-axis" (matches the C3 `prom_format.cpp` change; closes a self-contradiction C3 introduced).

## Out of scope (explicit)
- B26 (pass_cidr→pass_rule rename — metric contract, own slice), B29 (legacy allowlist map delete — ctest-gated), B30 (slot/id decouple — designed slice), B22/B23 (test hardening), B27 (security — held by PO).
- Any behavior/schema/VERSION change. Any loader.hpp touch (PI-7 zero-diff must continue).
- Reformatting / re-flowing unrelated comments. FileList sites ONLY.

## Definition of done
- §5.57 (MVP-4.17) cleanup amendment in design.md.
- PI-7 loader.hpp zero-diff CONTINUES (loader.hpp untouched).
- ctest baseline **96/96** unchanged (no new tests required; suite stays green).
- NO VERSION bump (stays 0.15.0), NO schema change (stays 2).
- `docs/BACKLOG.md` status-marking edits committed in this slice.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang-19/C++23 toolchain (unchanged). No new deps.
- Runtime/kernel: none (no datapath change).

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
**MECHANICAL.** Single design axis (none, really — it's deletion + comment truth-fixing). Answer falls out of stated constraints + grep-verified current code. No expensive-to-undo decision, no ≥3-option fork. **No /mint-hld, no spike.** Single-architect via /mint-dev handles it. Light path per "additive/low-risk → lighter band run" ([[feedback_band_by_default]] — band IS used, just without hld/spike).

## Notes for architect Phase A code-grep discipline
Re-run (guard #5 — brief author already ran these; verify independently):
- `grep -rn 'classify_match_kind\|match_kind' src/ tests/ include/` — confirm only the 4 B24 sites; ZERO test/fixture hits.
- `grep -rn '\.match_kind\|->match_kind' src/ tests/ include/` — confirm only the `:93` write (no reader).
- `grep -nE 'at-least-one|at least one|mac/src_cidr' src/lib/config.hpp src/lib/config.cpp` — confirm header sites stale, error STRING (config.cpp:457-459) already correct.
- `grep -rnE '6-axis|6 axis|schema_version = 1' src/lib/ src/exporter/` — confirm the loader.cpp:2452 + prom_format.hpp:16 + config.hpp:63 sites.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #13 (retired emit-site string ripple)** — B24 retires `classify_match_kind` + `match_kind` + the return values `"mac"`/`"cidr"`/`"both"`. Brief verified NO test/fixture asserts these (the values never reached any output surface). Architect: re-confirm `grep -rln 'match_kind\|classify_match_kind' tests/`.
- **Guard #5 (Phase A code-grep discipline)** — always applies; architect re-runs the greps above.
- **Operative-semantic discipline** — the "9-axis" / "−12 LOC" / site-count figures in this brief are SHOULD-level orientation, not literal-match contracts. Impl deviations that preserve the intent (e.g. retaining a `§5.xx` citation comment at a retired site, a slightly different LOC delta) are `inline-merge`, not OOT.
- **Guard #11 (VERSION-bump propagation)** — N/A (no bump).
