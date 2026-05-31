# Review — MVP-4.17 housekeeping cleanup (B24+B25) (mint triangulation)

## Verdict
`pass` (round 1)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — (D-mvp-4.17-Q1=A1: no new test by design; existing suite carries negation control T_NEGATION_CONTROL #7 GREEN) |
| 3. Code ↔ Tests | 0 | — (96/96, classify_match_kind deleted not orphaned) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — (PI-7 ∅, no REGRESSION, no UNRELATED-EDIT, no INVARIANT-VIOLATED) |

## What was verified (cite-by-cite)

**Point 1 — Spec ↔ Code (FileList §5.57):** git diff = exactly the 7 src/ files + docs/BACKLOG.md.
- B24 dead-code (`sidecar_reader.{cpp,hpp}`): `classify_match_kind` def deleted, `rm.match_kind` assignment deleted, `match_kind` member deleted, header comments fixed. `grep -rn 'match_kind\|classify_match_kind' src/ include/ tests/` = ZERO.
- B25 comment/dead-init: `config.hpp:4/12-13` + dead-init `schema_version = 1`→`= 2` (HG-mvp-4.17-1, validate() always overwrites — behavior-neutral); `config.cpp:6` header → "9 match axes"; `loader.cpp:2452` "6-axis"→"9-axis"; `prom_format.hpp:16` HELP + :18 sample line gains dst_cidr6/src_cidr6/ethertype mirroring `prom_format.cpp:192`; `sidecar.cpp:142-148` now-false "config.cpp rejects mac" → "re-accepted §5.47".
- `parse_rule_index` signature/return UNCHANGED; `classify_match_kind` was file-local (no external linkage) — clean removal. No VERSION/schema bump.

**Point 5 — MUST invariants (§6.5 delta) all hold:**
- PI-7: `git diff ce59a5e -- src/lib/loader.hpp` = ∅ (streak continues).
- PI-mvp-4.17-EXPORTER-BEHAVIOR: `git show HEAD -- src/exporter/prom_format.cpp` = ∅ (already correct from C3; only the .hpp doc-mirror aligned to it).
- PI-mvp-4.17-ERRSTRING: `config.cpp:457-459` operator-facing error string byte-unchanged.
- PI-mvp-4.17-NO-MOVE: footprint = the 7 listed src/ + BACKLOG.md only; no schema/axis/BITVEC/kManagedMaps/version literal moved.

**Point 4 — OOS fence:** no code touches B26/B29/B30/B22/B23/B27; no "while-I'm-here" edits; guard #13 holds.

## Test execution

Independent rebuild (rc=0) + full suite `sudo -n ctest --output-on-failure -j2`:
```
100% tests passed, 0 tests failed out of 96
Total Test time (real) = 650.93 sec
Skipped: #5 T_DROP_MALFORMED, #38 T_ANSIBLE_PLAYBOOK_SYNTAX (env, pre-existing — NOT regressions)
```
Byte-identical outcome to tester's `mint/test-run.log`. Live-label-path GREEN: T_EXPORTER_RULE_LABELS #54, T_SIDECAR_V6_ETH_KINDS #55, T_SIDECAR_JSON_SHAPE #52, T_NEGATION_CONTROL #7. Verdict-identity (PI-mvp-4.17-VERDICT) confirmed: behavior diff = ∅.

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] BACKLOG.md B25 entry body still said "Update to v2/6-axis"
**Location**: `docs/BACKLOG.md` B25 entry (under "✅ SHIPPED MVP-4.17").
**Evidence**: the original B25 task-description "Update to v2/6-axis" survived verbatim under the now-SHIPPED header — ironic in a 6→9-axis-drift-correction slice. Historical task-description prose, not live-misleading code prose; non-blocking.
**Disposition**: `inline-merge`.

### Post-review sweep — round 1
- OOT: BACKLOG.md B25 "Update to v2/6-axis" → `docs/BACKLOG.md` B25 entry edited → corrected to "v2/**9-axis**" + noted the broader shipped scope (8 sites incl. dead-init, sidecar.cpp false-comment, prom_format.hpp doc-mirror). Rides in the Phase 6 final commit.

No SPEC-DRIFT, no SPEC-UNTESTED, no CIRCULAR-TEST, no OOS-DRIFT, no REGRESSION, no UNRELATED-EDIT, no INVARIANT-VIOLATED. Clean pure-cleanup slice. **pass.**
