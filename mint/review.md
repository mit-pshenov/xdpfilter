# Review — MVP-4.26 / B33 rename mac_filter/xdpmacfilter/mac_filter_prog → xdpfilter (mint triangulation)

## Verdict
`pass` (round-1, 0 findings, 1 out-of-triangulation → inline-merge)

Base for all diffs: `7fdecda` (design commit; src = pre-rename state).

## Triangulation matrix
| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved | 0 | 1 OOT inline-merge (T7 KEEP wording) |

## Point 1 — Spec ↔ Code
- **6 git mv** (history-preserving R-status): `mac_filter.bpf.c→xdpfilter.bpf.c` (R099), `mac_filter.h→xdpfilter.h` (R096), the 2 fixtures, `systemd/xdpmacfilter@→xdpfilter@.service`, `ansible/xdpmacfilter-deploy→xdpfilter-deploy.yml`.
- **§5.19 security gate end-to-end consistent**: `kOwnedProgName{"xdpfilter_prog"}` (`loader.cpp:84`) == SEC `int xdpfilter_prog` (`xdpfilter.bpf.c:614`) == `skel->progs.xdpfilter_prog` (`loader.cpp:1026,2585,2676`) == fixtures' name-asserts. **ZERO `mac_filter_prog` survives.**
- **VERSION 0.16.0** (HG-1): `CMakeLists.txt:13`; `grep '0\.15\.0'` → ∅ (guard #11).
- **KEEPs**: `XDPMF_*` = 54 symbols (HG-4, unchanged; only path VALUES changed); `xdpfilter_*` metrics + `BITVEC_NUM_AXES`/`kManagedMaps`/schema untouched.

## Point 2 — Spec ↔ Tests
NO new ctest (design-correct; canaries ARE the verification). Negation controls present (xdpfilter_bad/alt, T_NEGATION_CONTROL, T_SYSTEMD_UNIT_SYNTAX neg-arm, xdp_pass alien-refusal). T6 VERSION canaries green.

## Point 3 — Code ↔ Tests (reviewer re-ran)
Sample `/tmp/mint-review-mvp426.log` — **7/7 PASS**: T_LOAD_ATTACH, T_ATTACH_TAG_MISMATCH, T_VERIFIER_REJECT, T_BITVEC_VERIFIER_LOAD, T_PROD_VERIFIER_LOAD, T_CLI_HELP_VERSION, **T_SYSTEMD_UNIT_SYNTAX (#35 now GREEN** after the team-lead's `/usr/bin/xdpfilter` symlink fix). The 5 §5.19 canaries green with new prog name + object path = empirical proof of tag name-independence (D-Q1/A1). The 2 full-suite env-fails (#48/#63, bpffs-root unmounted — logs show the correct NEW path `/sys/fs/bpf/xdpfilter does not exist`) + #57 transient -j flake are NOT rename defects.

## Point 4 — Out-of-Scope Drift
Clean. `src/bpf/` = only `xdpfilter.bpf.c`; `src/common/` = only `xdpfilter.h` (+ pre-existing) → NO B34 split. No `XDPMF_*` symbol rename, no logic/schema/map change.

## Point 5 — Behaviour preserved (§6.5)
- **PI-DATAPATH-IDENTICAL**: xdp section = **3658**; `git diff -M 7fdecda -- src/bpf/` non-rename-token lines = ZERO (pure token rename).
- **PI-7-mvp-4.26-SUSPENDED** (HG-3 + EDIT-1): loader.hpp/config.hpp diff = exactly 4 line-pairs (2× include-path + 2× doc-prose); NO symbol/signature/body change → inline-merge per EDIT-1, NOT [INVARIANT-VIOLATED].
- **PI-RENAME-COMPLETENESS**: grep → zero LIVE-surface survivors; only deliberate KEEPs (BACKLOG historical ledger + CHANGELOG migration note).
- PI-SECURITY-GATE / PI-ENV-ABI / PI-SCHEMA-METRICS / PI-VERSION all ✓.

## Completeness grep (T7 — load-bearing)
ZERO hits in any LIVE surface (src/, tests/, systemd/, ansible/, CMakeLists.txt, cmake/, .github/, README.md, CONFIG_SCHEMA.md, FLEET_DEPLOYMENT.md). Surviving hits ONLY in: `CHANGELOG.md` 0.16.0 migration note (intentional — must name what it migrated from); `docs/BACKLOG.md` historical-ledger entries (B7/B18/B20/B26/B33/B34) citing past commits by their then-current filenames (renaming would falsify the shipped record). Both correct KEEPs.

## Out-of-triangulation findings

### [OOT] T7 KEEP wording narrower than the correct KEEP set → inline-merge (applied)
**Location**: `design.md` §5.66 T7 row + PI-RENAME-COMPLETENESS row.
**Evidence**: the design literally said "ONLY `docs/BACKLOG.md` B33 entry"; the actual & correct surviving set is the WHOLE BACKLOG historical ledger (every entry citing a past commit by its then-current filename). Tester + reviewer concur this is correct historical-ledger preservation.
**Disposition**: `inline-merge` (applied — see Post-review sweep).

## Post-review sweep — round 1
- OOT (T7 KEEP wording too narrow) → `mint/design.md` §5.66 T7 row + PI-RENAME-COMPLETENESS row edited (EDIT-2): broadened the KEEP set from "B33 entry only" to "all `docs/BACKLOG.md` historical-ledger entries citing past commits by their then-current names + the CHANGELOG migration note". Design-prose correction to match reality; zero impl/behavior impact.

## Rework assignments
None — `pass`.

Net: rename complete + behavior-identical; security gate consistent (zero `mac_filter_prog`); xdp 3658; VERSION 0.16.0; XDPMF_=54; 6 git mv; #35 green post-symlink-fix; sample 7/7. Candidate guard #34 (operator-surface rename = minor bump + migration note + the CMake bpffs-extraction-assert is a high-miss site) validated. Ship-ready.
