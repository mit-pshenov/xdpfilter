# Review — MVP-4.18 remove legacy `allowlist` alias map (B29) (mint triangulation)

## Verdict
`pass` (round 1)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | (negation control PRESENT) |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | (PI-7 ∅, no REGRESSION/UNRELATED-EDIT/INVARIANT-VIOLATED) |

Plus 2 [OUT-OF-TRIANGULATION] (both `inline-merge`, do NOT affect verdict).

## Point-by-point (all cites independently re-verified by reviewer)

**1. Spec ↔ Code:** alias map decl GONE (`grep '\ballowlist\b SEC' src/bpf/` = ∅); allowlist_a/_b + xdpmf_allowlist_inner TYPE + rulesets AOM KEPT. loader.cpp: kManagedMaps alias row + `legacy_alias` field + both skip-guards + the §5.26 special-pin block all removed; kManagedMaps = 38 rows (was 39, guard #10 ✓), 2-tuple. mac_filter.h XDPMF_MAP_ALLOWLIST_NAME deleted. Skeleton regen green (no `&SkelMapsT::allowlist` build error — member-pointer safety net).

**2. Spec ↔ Tests:** all 4 canaries assert `${PIN_DIR}/allowlist_a` + FAIL strings updated. NEGATION CONTROL present (T_LOAD_ATTACH.sh:32-33 `! test -e ${PIN_DIR}/allowlist` proves legacy pin GONE). T_VERIFIER_REJECT bad-input backstop. No CIRCULAR-TEST.

**3. Code ↔ Tests:** reviewer re-ran full suite (sole owner, exit 0): 100% passed, 0 failed out of 96 (2 env-skips, baseline-identical). bpftool prog loadall rc=0; live map list shows allowlist_a/allowlist_b only, bare allowlist GONE.

**4. OOS:** no live-datapath edit; no schema(2)/VERSION(0.15.0)/axis(9)/BITVEC change. T_DROP_RULE_OPERATIVE + T_DROP_RULE_BUMPS_COUNTER green = verdict-identity.

**5. Brownfield:** PI-7 `git diff 9aa68fd -- src/lib/loader.hpp` = ∅. ABI-discharge re-run: filtered grep returns ONLY §5.58 invariant-#7 residue; ZERO dangling ref to deleted alias/constant/field; ZERO external consumer. D-mvp-4.18-FIXTURE honored (mac_filter_bad.bpf.c independent map untouched; T_VERIFIER_REJECT green). No REGRESSION, no UNRELATED-EDIT.

## Test execution
Reviewer's independent sole-owner run: `100% tests passed, 0 tests failed out of 96` (2 env-skips). Log `/tmp/mint-review-4.18-1780255427.log`. Matches the team-lead's canonical run (exit 0, mint/test-run.log).

> Session note: heavy output-lag caused multiple FS-lag confabulations in the tester's secondary reporting (timings/provenance). The VERDICT (96/96) was correct throughout; it was independently re-grounded by the team-lead's sole-owner clean run AND the reviewer's independent re-run. Code + the 4 ctest edits were verified on-disk by the team-lead.

## Out-of-triangulation findings (both inline-merge, pre-classified by §5.58 MAY-invariants #8/#9)

### [OUT-OF-TRIANGULATION] docs/BACKLOG.md B29 not marked DONE → inline-merge
B29 fully implemented but its backlog entry wasn't flipped. Disposition: inline-merge.

### [OUT-OF-TRIANGULATION] T_MODE_GENERIC_DEFAULT.sh:18 header comment stale → inline-merge
`{allowlist,stats}` orienting comment not updated alongside the :95 assertion migration. Disposition: inline-merge.

### Post-review sweep — round 1
- OOT: BACKLOG.md B29 → `docs/BACKLOG.md:154` flipped to "✅ SHIPPED MVP-4.18 (194be4f)" with the full removal summary.
- OOT: T_MODE_GENERIC_DEFAULT header → `tests/T_MODE_GENERIC_DEFAULT.sh:18` `{allowlist,stats}` → `{allowlist_a,stats}`.
Both ride in the Phase 6 final commit.

**Verdict: pass.**
