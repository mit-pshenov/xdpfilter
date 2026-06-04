# Review — MVP-4.30 / B35 wildcard+defaults → ruleset_state pack (mint triangulation)

## Verdict
`pass` (round 1, 0 findings, 0 OOT)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour (VERDICT) preserved | 0 | — |

## The 6 load-bearing questions — all answered (3 independent insn measurements: impl/tester/reviewer all 3437)

**1. VERDICT-IDENTITY ✓** — full `T_*_ORACLE_AGREEMENT` family green (BITVEC/AND/AND4/AND5/AND6/MAC_MERGE/ANDV6/ANDETH); oracle VECTOR bodies UNTOUCHED (`git diff fc96a45` on the 6 pin-smokes = pin-name token + echo strings only; zero vector/expected-verdict edits). No verdict masked.

**2. REAL INSN WIN ✓** — reviewer re-measured (3rd independent, guard #35): `llvm-objdump-19 -d --section=xdp build/xdpfilter.bpf.o | grep -cE '^\s+[0-9a-f]+:'` = **3437** (−221 vs 3658), `bpftool prog load … type xdp` rc=0. The spike gate (D-mvp-4.30-FEAS) cleared decisively; ABORT not triggered.

**3. RE-BASELINE INTEGRITY ✓** — both gates default to the MEASURED 3437 (`T_PROD_VERIFIER_LOAD.sh:120`, `T_INSN_BASELINE_GATE.sh:67`), documented sanctioned `XDPMF_PROD_INSN_BASELINE` escape-hatch use (intentional codegen change), NOT silent. Teeth verified: 3438→FAIL loud, 3437→PASS. Re-baseline is DOWN to measured, not up.

**4. RESET semantic (HG-3) ✓** — `write_ruleset_state` zero-inits `struct xdpmf_ruleset_state val{}`, fills `wc[BV_AXIS_*]`+`default_action`, one `bpf_map_update_elem` to the inactive slot BEFORE the active_idx flip. No copy-forward, no stale carry. `T_APPLY_ATOMIC_SWAP_NO_DROP` green.

**5. PIN-RIPPLE LOCKSTEP (guard #16, D-mvp-4.30-PINNAME) ✓** — post-edit `grep -rnE "test -e .*[/ ]wildcard|for pin in.*wildcard" tests/` = ∅. All 6 smokes swapped wildcard→ruleset_state in lockstep with the SEC(".maps") symbol. `defaults` pin had zero consumers (folding safe). [This is the team-lead-caught 2→6 undercount, corrected pre-impl.]

**6. PI-7 ∅ + footprint ✓** — `git diff fc96a45 -- src/lib/loader.hpp src/lib/config.hpp` = ∅; exporter/CMakeLists/cmake/VERSION/cli/sidecar/defs.h/apply_internal.hpp = ∅. VERSION 0.16.0 (no bump). Footprint = 13 EDITED (5 src + 2 gates + 6 smokes) + design.md + impl-notes.md.

## Spec ↔ Code spot-checks
- `struct xdpmf_ruleset_state` (`xdpfilter.h:233`): `wc[9]` u64 + `default_action` u32 + `_pad` u32; static_asserts sizeof==80 / offsetof(default_action)==72 — matches DataStructures.
- Map def (`maps.h:122`): ARRAY, value `struct xdpmf_ruleset_state`, max_entries `XDPMF_RULESET_COUNT`, PIN_BY_NAME.
- Datapath (`xdpfilter.bpf.c:94`): ONE hoisted `bpf_map_lookup_elem(&ruleset_state,&active)` + `if(!rs) DROP`; all 3 arms read `rs->wc[axis]` UNIFORMLY (fold-#2 divergence RESOLVED — PI-UNIFORM-ARMS); fallthrough `rs->default_action` — Q1-A2 hoist honored.
- `write_ruleset_state` matches Interfaces; `write_wildcard_slots`/`write_default_slot` DELETED; kManagedMaps net −1.

## Test execution
- `/tmp/mint-review-tests-*.log` + `mint/test-run.log`.
- Targeted acceptance: 16/16 (oracle family + both insn gates + atomic-swap + compose/pin smokes). Full ctest: 104/106 — the 2 FAILs (#48 T_EXPORTER_EXITS_6_ALL_IFACES_EACCES, #63 T_LOG_JSON_EXPORTER_EVENTS) are the documented pre-existing env-fails BY NAME (exporter reads NO wildcard/defaults/ruleset_state pin → not B35-caused). 2 skips (#5/#38) unchanged. No [REGRESSION].

```
insn re-measure (3 independent): 3437 | verifier load rc=0
teeth: WRONG=3438 → FAIL ✓ | RIGHT=3437 → PASS ✓
```

## PI delta
- RETIRED going-forward: `PI-mvp-4.29-DATAPATH-IDENTICAL` (byte/3658) — cited verbatim + `[RETIRED]` marker; stays true as B34b's record.
- NEW: `PI-mvp-4.30-VERDICT-IDENTITY` (oracle agreement is the control), `PI-mvp-4.30-RESET`, `PI-mvp-4.30-PINRIPPLE`, `PI-UNIFORM-ARMS`. PI-7 continues.
- Candidate guard #38 (map-schema VALUE-pack discipline: measure-first/verdict-identity/sanctioned-rebaseline/broad-grep-pin-ripple/bash-less-FEAS-ABORT).

## Out-of-triangulation findings
None.

All §6.5 PI-mvp-4.30-* rows hold; no unnegotiated drift; no OOS creep. Ship it.
