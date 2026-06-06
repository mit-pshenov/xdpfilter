# Review — MVP-4.38/B45 `apply --dry-run` human-decoded operator view (mint triangulation)

## Verdict
`pass` (round 1)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 blocking | — |
| 2. Spec ↔ Tests | 0 | (negation control present ✓) |
| 3. Code ↔ Tests | 0 | #112 + #113 green; no UNEXERCISED-EXPORT |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | no REGRESSION / UNRELATED-EDIT / INVARIANT-VIOLATED |

Plus 1 `[OUT-OF-TRIANGULATION]` (design-internal inconsistency, non-blocking, disposition `inline-merge`).

## Point 1 — Spec ↔ Code
- `format_dryrun_human(const Config&, const CompiledRuleset&)` — `map_image.hpp:32`, body `map_image.cpp:218-270`. Header block + per-rule block match §5.78.4(a) exactly.
- `DryrunFormat{Human=0,Golden=1}` + `ApplyConfig::format=Human` — `apply.hpp:28,42`. Default Human (HG-1) ✓.
- `dryrun_render_for_file` — `apply.cpp:136-143`: `Golden→render_dryrun_image(parsed)` else `format_dryrun_human(parsed, compile(parsed))`. Renamed per D-mvp-4.38-RENAME; single call site `main.cpp:61` ✓.
- `parse_apply --format` — `cli.cpp:226-232` (human/golden/image, unknown→CliError) + `format_seen && !dry_run → CliError` (`cli.cpp:282-284`) ✓.
- **PI-SSOT / guard #9 (central check) — HOLDS.** `format_dryrun_human` reads ONLY `cr.rules` / `cr.id_to_slot.at(r.id)` / `cr.default_action` / `cfg.steering` / `cfg.schema_version` / `r.match`. No `bpf_*`, no `materialize`/`populate_*`, no re-lowering of bits/prefixes. Axis renderers (`map_image.cpp:52-104`) ECHO validated stored values, do not re-derive lowering. The golden stays the byte-faithful SSoT.
- Decisions honored: NOSPLIT, DIAG (bounded), EMPTYMATCH-NA, NOVER.

## Point 2 — Spec ↔ Tests
Every §5.78.6 item (1)-(10) has a matching outcome-targeted assertion (golden behind `--format=golden` byte-EQ; default human observable switch; 10 per-rule decode + 9 axis value-forms; redirect note; MANDATORY empty-ruleset blackhole negation 3-token same-line; comparator-can-fail control; `--format` requires `--dry-run`; unknown format rejected; zero-touch negation; golden corrupt-comparator). NO-NEGATION-CONTROL satisfied; no CIRCULAR-TEST.

## Point 3 — Code ↔ Tests
- `T_DRYRUN_IMAGE_IDENTITY` (#112) + `T_CLI_APPLY_DRYRUN` (#113) Passed (re-run independently, `/tmp/mint-review-tests-1780765635.log`).
- No UNEXERCISED-EXPORT: `format_dryrun_human`←`apply.cpp:142`, `dryrun_render_for_file`←`main.cpp:61`, both exercised by #113.

## Point 4 — Out-of-Scope Drift
None. No JSON/typed output, no heavy linting, no empty-match diagnostic, no per-rule targets, no VERSION bump. Diagnostics bounded to the 2 sanctioned notes (`map_image.cpp:253-267`).

## Point 5 — Behaviour preserved (brownfield)
- **PI-LIVE-IDENTITY**: `git diff 474c041 --` materialize.{cpp,hpp}/map_writer.{cpp,hpp}/live_map_writer.cpp/loader.{cpp,hpp}/apply_internal.hpp/compiled_ruleset.{cpp,hpp}/src/bpf = **∅**. PI-7 + insn 3477 + FAILCLOSED carried.
- **PI-GOLDEN-UNCHANGED**: `map_image.cpp` diff = 151 ins / 0 del (purely additive); `format_dryrun_image` + `render_dryrun_image` bodies byte-identical (md5 match); `dryrun_image.golden` byte-unchanged; #112 green.
- **No REGRESSION**: 111/113. The 2 fails (#48 + #63) are identical pre-existing exporter env-fails (prior `mint/test-run.log:97,165`); both test files git-unchanged vs 474c041; reference no slice symbols.
- **No UNRELATED-EDIT**: changed set = exactly §5.78.2 FileList + mint docs.
- The golden→`--format=golden` migration is the PO-baked default switch (D-mvp-4.38-DEFAULT-BREAK), correctly NOT a regression.
- **2 impl deviations (impl-notes.md) within contract:** (a) value-first axis spelling `protocol=6(tcp)` — pinned value `protocol=6` is a substring (§5.78.4(a) base), name is a MAY suffix; (b) `dryrun_empty.yaml` omits `rules:` key (yaml_subset rejects flow-style `[]`) → omission = zero rules = exit 0 reaches the formatter.

## Test execution (tail)
```
#112 T_DRYRUN_IMAGE_IDENTITY Passed ; #113 T_CLI_APPLY_DRYRUN Passed
98% tests passed, 2 failed out of 113
FAILED: 48 T_EXPORTER_EXITS_6_ALL_IFACES_EACCES, 63 T_LOG_JSON_EXPORTER_EVENTS (pre-existing env-fails, git-unchanged)
```

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] Design §5.78.4(a) ethertype value-form is internally inconsistent
**Location**: `design.md` §5.78.4(a) pinned value-form table line vs the design's own grep-target example two lines down (impl `map_image.cpp:90-97`, test `T_CLI_APPLY_DRYRUN.sh:234`)
**Evidence**: The PINNED value-form table says ethertype renders `0x` + **4-digit zero-padded** → `0x0806`. The design's OWN grep-target example uses non-padded `ethertype=0x806`. Impl emits `0x{:x}` → `0x806`; the tester pins `0x806`. So impl + test + the design's operative grep example all agree on `0x806`; only the table line is the outlier (`0x0806` is not a substring of `0x806`). Isolated to the one corpus ethertype (arp); cosmetic.
**Recommended disposition**: `inline-merge`
**Rationale**: The system is self-consistent (impl ↔ test ↔ the design's grep example); the lone inconsistent artifact is the table's "4-digit zero-padded" wording, which contradicts §5.78.4(a)'s own example. Per §5.78.7a the fix is to reconcile the design table line to `0x806`. Non-blocking — the load-bearing test is green and the contract base ("the number") is satisfied.

### Post-review sweep — round 1
- OOT "ethertype value-form inconsistency" → `mint/design.md` §5.78.4(a) ethertype table line edited → `0x` + 4-digit-zero-padded (`0x0806`) corrected to the non-padded `0x{:x}` form (`0x806`), matching impl (`map_image.cpp:90-97`), the test (`T_CLI_APPLY_DRYRUN.sh:234`), and the design's own grep-target example. Rides in the Phase 6 final commit.
