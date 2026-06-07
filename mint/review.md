# Review — MVP-4.39 / B47 sanitary-day code-subtraction (mint triangulation)

## Verdict
`pass` (round 1, 0 findings)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — (no new exports; deleted one) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

All 4 items land exactly per §5.79. Pure-subtractive slice verified clean.

## Point 1 — Spec ↔ Code (all 4 interfaces match contract)
- **B47-1** `map_writer.cpp:57` def + `map_writer.hpp:63` decl of `active_writer()` DELETED; `set_active_writer` KEPT with 3 live callers (`map_writer.hpp:122` RecordingScope ctor, `:123` dtor, `live_map_writer.cpp:59` install). Comment trimmed "/inspect"→"Install…" (`map_writer.hpp:60`). Wrapper bodies (`map_fd/update/next_key/delete/resolve_ifindex` null-check→`no_writer_installed`) byte-identical — diff is exactly getter-delete + comment-trim.
- **B47-2** `cidr.cpp` merged to `[[nodiscard]] int parse_prefix(std::string_view s, int ceiling) noexcept`; `parse_prefix6` DELETED (grep tree-wide = ∅). Callers `parse_cidr_v4:110`→`parse_prefix(...,32)`, `parse_cidr_v6:195`→`parse_prefix(...,128)`. Caller-side ConfigError throws ("empty prefix"/"out of range") untouched → message catalogue byte-identical (guard #13).
- **B47-3** `loader.cpp:1465` `static void populate_shared_maps(xdpfilter_bpf*, const Config&)` (file-local, `namespace internal`). Both dup blocks collapse to `populate_shared_maps(skel.get(), req.config)` (reattach `:1700`, fresh `:1807`). `materialize(...)` + `copy_rule_counters_forward(...)` stay EXPLICIT at BOTH sites (guard #15). §5.29/§5.34/§5.75 anchor comments relocated into helper (guard #33). Error strings canonicalized to single form per D-mvp-4.39-ERRSTR ("action_table map fd unavailable" / "redirect_devmap map fd unavailable" — `(reattach)` suffix dropped, `map` word kept).
- **B47-4** `map_image.cpp:96` BOTH literals `0x{:x}`→`0x{:04x}`; comment `:88-89` rewritten to canonical-4-digit rationale, §5.78.4(a) anchor kept. Sole residual `0x806` is intentional "(not `0x806`)" rationale prose in the comment.
- D-mvp-4.39-NOEXTRACT honored: `sidecar.cpp` NOT touched (git-diff ∅); no shared axis_format module. SETTLED — not re-raised.

## Point 2 — Spec ↔ Tests
- TestStrategy mandates NO new ctest (behavior-preserving). The one behavioral change (B46 spelling) is asserted on the **stated outcome**: `T_CLI_APPLY_DRYRUN.sh` updates all THREE sites `0x806`→`0x0806` (`:233` comment, `:234` grep regex, `:235` FAIL diag) and asserts `match:.*ethertype=0x0806` for id7 — targets spec token, not code-shape. Negation control present (per-assertion FAIL diagnostics + #112 SMOKE+NEGATION). Golden assertion + #112 stay green.

## Point 3 — Code ↔ Tests
- Targeted run (log `/tmp/mint-review-tests-b47.log`): **10/10 passed** — #21 #22 #28 #29 #30 #32 #33 #100 #112 #113. Clean build confirms B47-1 dead-symbol delete links with no unresolved ref.
- No UNEXERCISED-EXPORT: slice removes one export (`active_writer()`), adds none; `populate_shared_maps`/`parse_prefix` are file-local.

## Point 4 — Out-of-Scope Drift
- No axis_format extraction, no VERSION bump (stays 0.17.0), no schema/datapath touch, `mint/impl-notes.md` historical prose untouched. 0 OOS-DRIFT.

## Point 5 — Behaviour preserved (brownfield)
git-diff verified ∅ for all UNCHANGED-BUT-AFFECTED:
- **PI-7**: `loader.hpp` ∅ ✓ (streak preserved — same-TU helper)
- **PI-mvp-4.37-FAILCLOSED** (re-scoped): `map_writer.{cpp,hpp}` diff = ONLY getter-delete + comment-trim; wrapper null-check bodies + `set_active_writer` + `g_active_writer` byte-identical ✓
- **insn 3477**: `src/bpf/*` ∅ ✓
- **PI-mvp-4.38-GOLDEN-UNCHANGED**: `tests/dryrun/dryrun_image.golden` ∅; #112 green ✓
- **PI-mvp-4.38-LIVE-IDENTITY** (re-scoped): `materialize.{cpp,hpp}` / `live_map_writer.cpp` / `apply_internal.hpp` ∅; apply sequence (materialize→populate shared→copy-forward→flip) preserved; apply suite green ✓
- **CIDR message catalogue**: caller throws byte-identical; cidr/config tests green ✓
- No REGRESSION: §5.78.4(a) prose all `0x0806` per architect amendment.

## Baseline
`mint/test-run.log`: 109/113, 4 fails = #1/#9 (build/sanitizer TIMEOUT) + #48/#63 (exporter EACCES env). All pre-existing/environmental per handoff — none touch slice files. NOT regressions. Skipped: #5, #38 (env-gated).

## Rework assignments
None — `pass`.

## Out-of-triangulation findings
None.
