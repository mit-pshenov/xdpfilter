# Review — MVP-4.14 S5 EtherType axis (§5.54) (mint triangulation)

## Verdict
`pass` — round-1, 5-point brownfield triangulation, 0 findings, 0 OOT. Reviewer independently re-ran/rebuilt (BUILD_RC=0, 0 failures) + read the authoritative Phase B log (93/93, 91 pass + 2 pre-existing env skips). FS-read lag this session caused buffered output that LOOKED like confabulation; reviewer correctly treated every such read as untrusted and re-verified each load-bearing fact with clean single-call reads + `git show`/`diff` ground-truth ([[feedback_fs_lag_confabulation]] discipline holding) — no verdict rests on an unverified read.

## Triangulation matrix
| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

## Load-bearing facts (reviewer-verified, file:line + git ground-truth)
- **Q1 = FULL SYMMETRIC non-IP arm** (NOT ethertype-only): new `else` arm (`mac_filter.bpf.c:1193+`) = 9-term AND, IP-family axes wildcard-only, mac/vlan/ethertype real; `acc==0`→defaults, NO MALFORMED path (D-mvp-4.14-NONIP-NO-MALFORMED). Verified, not assumed.
- **Hoisted ethertype lookup** above the family dispatch: host-order key `(u32)bpf_ntohs(inner_proto)`, NULL→DROP, exact-HASH (clone of proto, NO closure — guard #23 N/A); composed `& (eth_mask|wc_eth)` into all 3 arms. PI-ETHKEY.
- **guard #27 verdict-identity**: v4 (`:884+`) + v6 (`:1163-1171`) arms gained the eth term (source changed) — v4+v6 oracle net GREEN proves verdict-identity, correctly NOT byte-identity. Not flagged as unrelated edit.
- **§5.47 supersession**: T_MAC_NON_IP step (2) rewrite (deny 0→1, family-blind mac fires on non-IP) is design-mandated (D-mvp-4.14-MAC-NONIP-SUPERSEDE) — NOT circular, NOT impl bug. Audit trail: D-mvp-4.7-Q2-GATE-DEFER predicted this L2-universal target (S7 deferred → S5 realized).
- **kManagedMaps 36→39, BITVEC_NUM_AXES 9, wildcard 16→18; loader.hpp byte-identical (PI-7); VERSION 0.15.0 no bump** (git show 86441e3:CMakeLists.txt == HEAD); config +1 optional<u16> ethertype; parse_ethertype names+hex+decimal bounds sound; sidecar.cpp 0-diff (D-mvp-4.14-SIDECAR-DEFER honored).
- Tests not circular: #92 asserts datapath rule_id vs independent O(N) oracle (`--ruleset andeth`); #93 headline arp-DROP-on-non-IP + cross-arm wc_eth exclusion; negation controls present (steer-d, oracle E7/E8, T_MAC_NON_IP step1).

## Out-of-triangulation findings
None. (`config_steer_arp_drop.yaml` NEW fixture is §6.75-TestStrategy-mandated test support, in-scope.)

## Reviewer's full review (verbatim)
(5-point matrix all-0; point-by-point file:line evidence — see structured report. Q1 full-symmetric non-IP arm, guard #27 verdict-identity, §5.47 supersession design-mandated, exact-HASH no-closure, hoisted lookup consistent across 3 arms, PI-7 zero-diff + 0.15.0 no-bump all independently verified despite FS-lag.)

**Verdict: pass.** Additive exact-HASH axis (clone of proto), full symmetric non-IP arm landing the L2-universal target deferred since S7; 93/93 green; no regression; round-1.
