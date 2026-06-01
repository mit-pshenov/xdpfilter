# Task brief — MVP-4.18 / housekeeping: remove the legacy `allowlist` alias map (brownfield, CLEANUP)

## Goal
Remove the vestigial bare `allowlist` BPF map + its bespoke special-pin/skip control-flow (BACKLOG **B29**). The map is a typed alias of `allowlist_a`, retained ONLY so MVP-2-era out-of-tree harnesses / ctests that grep the `${PIN_DIR}/allowlist` pin still resolve. Runtime ruleset data lives ONLY in the live `allowlist_a`/`allowlist_b` ARRAY_OF_MAPS pair; the datapath program NEVER reads the alias. This is dead-infrastructure removal, **verdict-identical for the live datapath**.

The legacy `${PIN_DIR}/allowlist` pin is literally `allowlist_a` pinned a SECOND time at the legacy path by a dedicated apply step (loader.cpp special-pin block, grep-anchor `"§5.26 backward-compat: pin allowlist_a ALSO at the legacy"`). Four ctests assert that pin's existence as an "attach succeeded" canary — they migrate to assert the live `allowlist_a` pin (`XDPMF_MAP_INNER_A_NAME = "allowlist_a"`) instead.

**ABI-promise discharge (DONE at brief time — code-grounded, NOT a PO gate):** `bpf.c` frames the alias as a compat promise for "any out-of-tree harness that linked against MVP-2's allowlist symbol." Tree-wide grep (`src/ tests/ ansible/ systemd/ include/`) finds the ONLY consumers are: the alias definition itself, the loader special-pin/skip flow, and the 4 ctest pin-assertions being migrated. **No external/out-of-tree consumer exists** (consistent with project reality: filter output consumed at-the-network, CLI+YAML integration surface, libxdpmf deferred-no-consumer). The promise is vestigial → safe to retire. If the architect's independent Phase-A grep finds a genuine live consumer, HALT.

## Context: prior work
- Prior briefs archived in `mint/task-brief-*.md` (latest archived: `task-brief-mvp-4.17.md` = the B24/B25 cleanup, just shipped `9aa68fd`).
- Recent: S4/S5/S6 ladder + C3 + MVP-4.17 cleanup all on origin/main. Match model = 9 axes; kManagedMaps = 39.
- Phase-2 grep verification (brief author ran — see footer): confirmed the loader sites, the 4-ctest migration set, the constant's 2 uses, and the ABI discharge.
- PI continuity: **loader.hpp PI-7 zero-diff EXPECTED to continue** (kManagedMaps table + struct live in loader.cpp anon-namespace; the `legacy_alias` field is on that anon struct — architect VERIFIES loader.hpp is untouched). **PI-6** (byte-equivalent pin existence) has a legacy-alias clause that this slice RETIRES — architect amends PI-6.

## Workflow rules (brownfield)
- **Architect**: read design.md §5.26/§5.27 (allowlist/cidr ARRAY_OF_MAPS topology + PI-6), the `kManagedMaps` HK-9 single-table section, §5.43 (cidr reshape mirror); EDIT design.md in place; append §5.58 (MVP-4.18). Re-run the Phase-2 greps + the ABI-discharge grep INDEPENDENTLY (guard #5). Amend PI-6 (retire the legacy-alias byte-equivalent clause; the live `allowlist_a` pin is the surviving surface).
- **Impl**: FileList is a DIFF — Edit only. The 3 kManagedMaps call-site loops (clear / pin / reuse) MUST still walk the table correctly with the entry + `legacy_alias` field gone. Remove the special-pin step as a whole block.
- **Tester**: NO new ctests. Migrate the 4 pin-assertion ctests (`${PIN_DIR}/allowlist` → `${PIN_DIR}/allowlist_a`). Confirm the suite stays **96/96**. The migrated assertions are the regression guard (they prove `allowlist_a` is pinned + attach succeeded).
- **Reviewer**: 5-point brownfield; **special attention**: (a) live datapath verdict-identity (allowlist_a/_b untouched, program never read the alias); (b) `bpftool prog load` rc=0 on the prod object with the map gone (impl Phase 2.5); (c) no dangling ref to `allowlist`/`XDPMF_MAP_ALLOWLIST_NAME`/`legacy_alias` anywhere (`grep -rn` = ∅ except retirement-citation comments); (d) the 4 migrated ctests assert the LIVE pin and still pass; (e) kManagedMaps 39→38 (guard #10); (f) PI-7 loader.hpp ∅.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.18-1: the MVP-2 out-of-tree-harness ABI promise → **RETIRE**
Discharge passed (no consumer tree-wide). Retire the alias + its compat promise with a one-line "retired vestigial MVP-2 ABI alias — no consumer; superseded by allowlist_a/_b" note in §5.58 + the bpf.c header. Architect re-confirms the discharge grep independently before deleting (the one judgment item — it is a code-grounded discharge, not a PO question).

### HG-mvp-4.18-2: the 4 canary ctests → **MIGRATE to `allowlist_a`, do NOT delete the assertion**
The pin-existence check is a useful "attach succeeded" canary. Re-point it at the live `${PIN_DIR}/allowlist_a` pin rather than deleting the assertion outright — keeps the test's intent intact. (Q1 below.)

## Open mechanism questions (architect decides; document in §5.58)

### Q1: how to migrate the 4 canary ctests?
- **A1**: re-point each `test -e ${PIN_DIR}/allowlist` → `test -e ${PIN_DIR}/allowlist_a` (the live inner-A pin, always created via kManagedMaps).
- **A2**: delete the pin-existence assertions (rely on other attach-success signals in each test).
- **Recommendation**: **A1** — preserves each test's attach-canary intent with a one-token change; `allowlist_a` is guaranteed pinned by the normal kManagedMaps pin loop (loader.cpp `XDPMF_MAP_INNER_A_NAME` row, `legacy_alias=false`).

### Q2: delete the `XDPMF_MAP_ALLOWLIST_NAME` constant?
- **A1**: delete it (mac_filter.h) once its 2 uses (kManagedMaps row + special-pin step) are gone.
- **A2**: keep it (harmless unused macro).
- **Recommendation**: **A1** — leaving an unused pin-name macro is exactly the dead-infra this slice removes. Verify ∅ uses after the loader edits, then delete.

## Scope (concrete items — FileList DIFF; line anchors are SHOULD-level, grep to confirm)

### B29-1 — delete the BPF alias map
**Where**: `src/bpf/mac_filter.bpf.c`
- Delete `struct xdpmf_allowlist_inner allowlist SEC(".maps");` (grep-anchor: the `allowlist SEC` line that is NOT `_a`/`_b`).
- Delete the legacy-alias header-comment paragraph (grep-anchor `"The legacy \`allowlist\` symbol is RETAINED"`) + the inline `"/* Legacy \`allowlist\` symbol — retained for MVP-2 compat-time wiring"` comment. KEEP allowlist_a/_b, `xdpmf_allowlist_inner` type, the rulesets ARRAY_OF_MAPS.

### B29-2 — remove the loader special-pin + skip flow
**Where**: `src/lib/loader.cpp`
- Remove the `kManagedMaps` entry `{ &SkelMapsT::allowlist, XDPMF_MAP_ALLOWLIST_NAME, true }`.
- Remove the `bool legacy_alias;` field from the kManagedMaps struct + update the 2 branch guards (`if (entry.legacy_alias) continue;` in the pin loop + the reuse loop) — with the entry gone, the field + its guards are dead; remove both so the 3 loops walk a clean table.
- Remove the whole special-pin block (grep-anchor `"§5.26 backward-compat: pin allowlist_a ALSO at the legacy"` through the `bpf_obj_pin(inner_a_fd, legacy...)` step).
- Update the now-stale comments (grep-anchors `"legacy alias (\`allowlist\`, kept ONLY"`, `"INCLUDING the legacy \`allowlist\` alias"`, `"EXCEPT the legacy \`allowlist\` alias"`) — drop or retire-cite.
- **PI-7**: confirm all edits are in loader.cpp (anon-namespace table/struct) → loader.hpp byte-unchanged.

### B29-3 — delete the unused pin-name constant
**Where**: `src/common/mac_filter.h`
- Delete `#define XDPMF_MAP_ALLOWLIST_NAME "allowlist"` once its uses are ∅ (Q2=A1). The `:17` doc comment "looked up in the `allowlist` hash map" is inner-map semantics (allowlist_a) — light-touch OPTIONAL, architect's call.

### B29-4 — migrate the 4 canary ctests
**Where**: `tests/T_LOAD_ATTACH.sh`, `tests/T_ATTACH_TAG_MISMATCH.sh`, `tests/T_MODE_GENERIC_DEFAULT.sh`, `tests/T_BPFFS_ROOT_SYMLINK.sh`
- Each asserts `test -e "${PIN_DIR}/allowlist"` → change to `"${PIN_DIR}/allowlist_a"` (per Q1=A1). Update the adjacent FAIL message strings. Grep-confirmed set = exactly these 4 (the broad `allowlist` grep's other hits are `inner-allowlist` prose / `allowlist_a/_b` / `cidr_allowlist` — NOT the bare legacy pin; do NOT touch them).

## Out of scope (explicit)
- B26 (pass_cidr→pass_rule — metric contract, defer to a stat-enum slice), B30 (slot/id decouple — designed slice), B22/B23 (test hardening), B27 (security — held by PO), B15 (.pyc/gitignore hygiene).
- Any live-datapath change (allowlist_a/_b, cidr_allowlist_a/_b, rulesets, all 9 axes untouched). Any schema/VERSION change.
- Renaming/reshaping any LIVE map. The `cidr_allowlist*` maps (named with the `allowlist` substring) are NOT touched.

## Definition of done
- §5.58 (MVP-4.18) amendment in design.md; PI-6 legacy-alias clause retired + documented.
- PI-7 loader.hpp zero-diff CONTINUES (verify).
- kManagedMaps 39 → 38 (guard #10 catalog arithmetic).
- LIVE datapath verdict-identical; `bpftool prog load` rc=0 on the prod object (impl Phase 2.5).
- ctest stays **96/96** after the 4-ctest migration (no new tests).
- NO schema/VERSION change (stays 0.15.0 / schema 2).
- `grep -rn 'XDPMF_MAP_ALLOWLIST_NAME\|legacy_alias' src/` = ∅; `grep -rn '\ballowlist\b SEC' src/bpf/` = ∅.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang-19 / C++23 + the BPF skeleton regen (the `.bpf.c` map-set changes → skeleton struct loses the `allowlist` member; impl rebuilds the skeleton).
- Runtime/kernel: veth + bpffs + sudo for the attach ctests (existing fixture).

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
**MECHANICAL.** Single axis (dead-infra removal). No design fork: the one judgment item (ABI-promise retirement) is a code-grounded discharge that PASSED at brief time (no consumer tree-wide) — framed as an architect Phase-A re-confirm, NOT a PO question (PO-filter: no external value to name; "out-of-tree harness" is hypothetical with zero in-tree evidence). No ≥3-option fork, no expensive-to-undo (git-revertable; the alias can be re-added if a phantom consumer ever surfaces). **No /mint-hld, no spike** (map REMOVAL, not a new verifier-bounded loop; impl Phase-2.5 `bpftool prog load` is the load check). Single-architect via /mint-dev. Light path per [[feedback_band_by_default]].

## Notes for architect Phase A code-grep discipline
Re-run (guard #5 — brief author already ran these; verify independently):
- ABI discharge: `grep -rn 'allowlist' src/ tests/ ansible/ systemd/ include/ | grep -vE 'allowlist_a|allowlist_b|cidr_allowlist|inner-allowlist|MAC allowlist'` — confirm the ONLY bare-`allowlist` consumers are the alias def + loader special-pin/skip + the 4 ctests. No external consumer ⇒ HG-1 RETIRE holds.
- `grep -rn 'XDPMF_MAP_ALLOWLIST_NAME' src/ include/` — confirm exactly 2 uses (kManagedMaps row + special-pin step); both removed ⇒ delete the constant (Q2).
- `grep -n 'legacy_alias' src/lib/loader.cpp` — confirm the field + the 2 branch guards (pin-skip + reuse-skip); all removed with the entry.
- `grep -rn 'PIN_DIR}/allowlist"' tests/*.sh` — confirm the 4-ctest migration set EXACTLY (T_LOAD_ATTACH, T_ATTACH_TAG_MISMATCH, T_MODE_GENERIC_DEFAULT, T_BPFFS_ROOT_SYMLINK).
- Confirm `XDPMF_MAP_INNER_A_NAME == "allowlist_a"` (the live pin the ctests migrate to).
- Confirm the kManagedMaps struct/table are loader.cpp anon-namespace (PI-7 loader.hpp ∅).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #10 (catalog arithmetic)** — kManagedMaps drops 39→38; verify the table count + all 3 walking loops (clear/pin/reuse) stay correct with the entry gone.
- **Guard #16 (retired pin-path / map-name ripple)** — the `${PIN_DIR}/allowlist` pin is RETIRED; the 4 ctests asserting it are pre-listed as EDITED (migrate to allowlist_a). This is the exact guard-#16 class.
- **Guard #13 (retired symbol ripple)** — `allowlist` map symbol + `XDPMF_MAP_ALLOWLIST_NAME` retired; confirm ∅ test/fixture refs to the bare pin survive (only allowlist_a/_b/cidr_allowlist remain).
- **Guard #5 (Phase A grep discipline)** — always; architect re-runs the discharge + site greps above.
- **Operative-semantic discipline** — line anchors / the "−30-ish LOC" / "39→38" figures are SHOULD-level orientation; impl deviations preserving intent (retirement-citation comments, slightly different LOC) are `inline-merge`.
- **Guard #11 (VERSION-bump propagation)** — N/A (no bump). **Guard #12 (RESOURCE_LOCK)** — N/A (no new ctest; migrated ones keep their existing locks).
