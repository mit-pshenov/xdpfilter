# Review — MVP-4.1 VLAN-tagged-frame L3 parse-path fix (mint triangulation)

## Verdict: pass (round 1)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |
| (out-of-triangulation) | 1 | [OUT-OF-TRIANGULATION] CHANGELOG.md — see Phase 4.5 sweep (FALSE POSITIVE) |

## Point 1 — Spec ↔ Code (all match)
- Macros `mac_filter.bpf.c:56-62`: `ETH_P_8021Q 0x8100` + `ETH_P_8021AD 0x88A8` (`#ifndef`-guarded) + `XDPMF_VLAN_MAX_DEPTH 2` per D-mvp-4.1-MACROS / DataStructures.
- Helper `mac_filter.bpf.c:319`: `static __always_inline __u16 l3_after_vlan(void *eth, void *data_end, void **l3hdr)` — byte-matches Interfaces §5.41. Bounded `#pragma unroll` over XDPMF_VLAN_MAX_DEPTH, two break-guards (TPID test + `cursor + sizeof(struct vlan_hdr) > data_end`), no bpf_loop → D-mvp-4.1-WALK. Verifier accepted.
- L3 gate rewrite `mac_filter.bpf.c:423-431`: inner-proto compare + bounds-check → STAT_DROP_MALFORMED + `ip = (struct iphdr *)l3hdr`. Matches FileList DIFF.
- Single-consumer (guard #9): one call-site (:423), def (:319).
- Injector `--vlan` repeatable argparse, VID 0..4095, outermost-first, zero-`--vlan` byte-identical.
- D-mvp-4.1-MALFORMED (b): truncated/overflow tag → break → ETH_P_IP test fails → defaults; STAT_DROP_MALFORMED 3→3.
- PI-mvp-4.1-MAC (c): MAC branch + preamble + defaults byte-unchanged vs 84be9d3.
- No-VLAN fast path (e): 5 untagged datapath tests GREEN.

## Point 2 — Spec ↔ Tests (all match)
- §6.43 T_PASS_CIDR_VLAN:136-151 step-4 asserts STAT_PASS_CIDR Δ==1 / PASS Δ==0 / DROP_DENY Δ==0 (regression differential, non-circular). Negation control step-5 (:163-175) out-of-range → DROP_DENY Δ==1.
- §6.44 T_PASS_CIDR_QINQ:133-145 depth-2 in-range → PASS_CIDR Δ==1; step-5 (:158-179) depth-3 overflow → DROP_DENY Δ==1, PASS_CIDR Δ==0, STAT_DROP_MALFORMED Δ==0 (load-bearing anti-vacuity fence / guard #22 / PI-mvp-4.1-NONIP-PRESERVED). No CIRCULAR-TEST.
- Both carry offload-disable (ethtool -K rxvlan/txvlan off) per guard #22.

## Point 3 — Code ↔ Tests
- Rebuilt (cmake reconfigure rc=0, -j4 rc=0); ran 2 NEW + 6 core datapath = 8/8 PASS.
- l3_after_vlan is static (TU-local), exercised end-to-end via inject tests → no UNEXERCISED-EXPORT.
- Full -j4 run (mint/test-run.log): 67 pass / 2 SKIP-77 / 1 fail (#70). Confirmed #70 = known pre-existing T_EXPORTER_BIND_NON_LOOPBACK_WARN port-9524 flake: re-ran isolated → 1/1 Passed. src/exporter/** zero-diff → NOT a regression.

## Point 4 — Out-of-Scope Drift
- No OOS item implemented. No --svlan/per-tag-TPID (S-TAG OOS respected). No inner-encap parsing. No VERSION bump. §7 OOS fences present.

## Point 5 — Behaviour preserved (brownfield)
git diff 84be9d3 zero-line confirmations: config.hpp ZERO; loader.hpp ZERO (PI-7 streaks); mac_filter.h ZERO; top CMakeLists ZERO (no VERSION); tests/lib + tests/fixtures ZERO; T_*.sh diff = only 2 NEW files; no new build dep; injector additive-only; PI-mvp-4.1-NO-ENCAP documented invariant + OOS fence. No REGRESSION / INVARIANT-VIOLATED / UNRELATED-EDIT.

## Test execution
```
T_PASS_CIDR_VLAN Passed; T_PASS_CIDR_QINQ Passed; T_DROP_DENY Passed; T_PASS_ALLOWED Passed;
T_PASS_MAC_OR_CIDR Passed; T_PASS_CIDR Passed; T_DROP_CIDR_NOT_IN_RANGE Passed; T_LOAD_ATTACH Passed
100% tests passed, 0 failed out of 8
isolated: T_EXPORTER_BIND_NON_LOOPBACK_WARN Passed 3.32s
```

## Out-of-triangulation findings (as reported by reviewer)

### [OUT-OF-TRIANGULATION] CHANGELOG.md edited but (claimed) absent from §5.41 FileList
- Reviewer claim: CHANGELOG.md:8-10 edited but design.md §5.41 FileList omits it. Recommended disposition: inline-merge (add to FileList).

## Rework assignments
None — pass.

---

### Post-review sweep — round 1 (orchestrator, Phase 4.5)

- **OOT "CHANGELOG.md not in FileList" → VERIFIED FALSE POSITIVE → no action.** On verification against the source, CHANGELOG.md **is already listed** in the §5.41 FileList EDITED block at `design.md:13391` ("`CHANGELOG.md` | OPTIONAL ~1 line under `[Unreleased]` (Fixed): … reviewer inline-merge."). The reviewer skimmed past the last EDITED row (CHANGELOG, marked OPTIONAL). No design.md edit performed — the FileList already covers it; the committed CHANGELOG.md entry (b63d14d) is in-scope per that row. Verdict unaffected (pass).
- No other OOT items.
