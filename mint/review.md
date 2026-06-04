# Review — MVP-4.28 / B34a datapath helper-extraction (§5.68) (mint triangulation)

## Verdict
`pass` (round-1)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 (1 flaky, see OOT) | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

## What was verified (independently, not from logs)

**Load-bearing PI-mvp-4.28-DATAPATH-IDENTICAL — 3658 ✓.** Forced fresh recompile (`touch src/bpf/xdpfilter.bpf.c && cmake --build build --target xdpfilter_bpf`), then `llvm-objdump-19 -d --section=xdp build/xdpfilter.bpf.o | grep -cE '^\s+[0-9a-f]+:'` = **3658**. Byte-identity holds. B37 gates green in-suite: `T_PROD_VERIFIER_LOAD` (#102) + `T_INSN_BASELINE_GATE` (#105) both Passed.

**PI-mvp-4.28-NONDATAPATH-ZERO + PI-7 ✓.** `git diff 71addf0 -- src/lib src/common src/cli src/exporter src/common/xdpfilter.h` = **0 lines**. `git diff 71addf0 --name-only` = exactly `mint/design.md`, `mint/impl-notes.md`, `src/bpf/xdpfilter.bpf.c`. Net `src/bpf` delta −46 (155 ins / 201 del). VERSION `0.16.0` unchanged.

**4 folds land faithfully (every site read):**
- #1 `DISPATCH_MATCH` macro — def `:623-641`; 3 calls guarded by `acc != 0` (`:967`/`:1159`/`:1259`). `do/while(0)`, two caller early-returns in scope. Phase-B EDIT-1 (helper→macro, negotiated).
- #3 `LOOKUP_INNER_OR_DROP` macro — def `:657-662`; exactly **15** sites (eth `:782` + v4×6 `:833-838` + v6×6 `:1044-1049` + non-IP×2 `:1177-1178`). No `do/while`, `unlikely` preserved — byte-identical by construction.
- #12 `mac_axis()` helper — def `:683-693`; 3 calls. Faithful `{0}`/memcpy-6/lookup/NULL→0.
- #13 `READ_DPORT` macro — def `:711-728`; 2 calls. MALFORMED bump+`return XDP_DROP` preserved 1:1. Design-authorized macro FALLBACK (out-param helper measured +50).

**Fold #2 `load_wildcards` DROPPED — inline-merge, NOT a gap.** Per verifiable-invariant #5 + D-mvp-4.28-Q2 Phase-B EDIT-2. 3 inline 8-axis blocks left byte-for-byte; drop documented in-file `:664-673`. Root cause (per-arm ordering asymmetry, 3657/3659 brackets-never-3658) consistent with the held gate.

**RENT-PAYERS intact ✓.** 3 family arms (`:796`/`:970`/`:1162`); per-arm `acc` AND-asymmetry preserved (PI-mvp-4.13-CROSS-FAMILY uncollapsed); `XDPMF_FFS_FALLBACK` #ifdef `:510-520`; inline `ETH_P_*`/`IPPROTO_*` `#ifndef` `:43-80`; hoisted `eth`/`wc_eth` 9th half kept.

**ANCHORS migrated 1-canonical (guard #33) ✓.** HG-mvp-4.3-4 → `DISPATCH_MATCH:618`; §5.26/§5.27 verifier-NULL → `LOOKUP_INNER_OR_DROP:653`; §5.47 MAC → `mac_axis:677`; §5.44 dport → `READ_DPORT:708`. §5.43 wildcard note correctly stays inline (#2 dropped). Per-arm cross-family AND comments preserved.

**Spec↔Tests / OOS ✓.** §5.68 mandates NO new test — the B37 insn gate IS the oracle (green at 3658). No module split, no rent-payer collapse, no loader fork-merge, no non-bpf `src/` edit, no VERSION/schema/axis/map change. Footprint == FileList.

## Test execution

`sudo -E ctest --test-dir build` → **97% passed, 3 failed / 106** (2 skipped). Full log: `/tmp/mint-review-tests-1780577235.log`.
- #48 `T_EXPORTER_EXITS_6_ALL_IFACES_EACCES` — known env-fail (bpffs/EACCES, exporter-side).
- #63 `T_LOG_JSON_EXPORTER_EVENTS` — known env-fail (exporter-side).
- #54 `T_EXPORTER_RULE_LABELS` — **FLAKE**: green in tester baseline (`mint/test-run.log:147`) + green isolated (`ctest -R '^T_EXPORTER_RULE_LABELS$'` 1/1); red only in the 682s full-suite run. ∅ `src/exporter` diff → structurally impossible for this byte-identical datapath slice to cause. Resource contention (port 9417 / veth / sidecar timing), not code.

**[REGRESSION] ruled out.** The slice is byte-identical datapath (3658) with ∅ exporter diff.

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] T_EXPORTER_RULE_LABELS flakes under full-suite load
**Location**: `tests/T_EXPORTER_RULE_LABELS.sh` (§6.51); failed in full-suite, passes isolated.
**Evidence**: green baseline `mint/test-run.log:147` + green isolated (4.39s); red only in the 682s full-suite run. Zero exporter diff this slice → cause is test-infra contention, not code.
**Recommended disposition**: `defer` (pre-existing test-infra flake, unrelated to this slice; a future test-infra slice could add port/fixture isolation or a retry).

## Rework assignments
None — verdict `pass`. The 2 Phase-B design EDITs (fold #1 helper→macro, fold #2 drop) + the READ_DPORT macro fallback are all gate-arbitrated `inline-merge` per verifiable-invariants #4/#5/#7, not findings.

---

### Deferred to next slice
- **T_EXPORTER_RULE_LABELS full-suite flake** (`tests/T_EXPORTER_RULE_LABELS.sh`, §6.51) — pre-existing test-infra resource-contention flake (exporter port 9417 / veth / sidecar timing under a ~680s parallel run); passes isolated + in the tester baseline. NOT caused by this byte-identical datapath slice (∅ `src/exporter` diff). Candidate for a future test-infra hardening slice (per-test port/fixture isolation or a bounded retry). Surfaced MVP-4.28 review.
