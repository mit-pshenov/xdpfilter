# Review — MVP-4.7 MAC-axis return (6th exact-HASH axis, src-MAC) (§5.47) (mint triangulation)

## Verdict
`pass` (round 1, 0 findings, 0 OOT requiring disposition)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — (negation controls present) |
| 3. Code ↔ Tests | 0 | 84 ran, 82 pass + 2 legit skip, 0 fail (serial) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

Baseline (design git-diff) = `480e95b`. Prior shipped slice = `548d402` (§5.46).

## Assess-points (all confirmed independently)
- **(a) src-MAC**: `.bpf.c:797` `memcpy(mac_key.octets, eth->h_source, 6)` — h_source (NOT h_dest), v1 semantic; eth bounds-checked at :576; read once, VLAN-agnostic (base-eth offset).
- **(b) IPv4-GATE (PO-accepted)**: MAC lookup (:790-802) + 6-way acc (:809-814) inside `if (inner_proto==ETH_P_IP)` (:617); non-IPv4 → defaults[active] (:844). T_MAC_NON_IP (#84) exercises it. OOS fence reframed DEFERRED-to-IPv6-slice (D-mvp-4.7-Q2-GATE-DEFER, design:15025), not dropped.
- **(c) reshape**: `xdpmf_allowlist_inner` value `allow_entry`→`__u64` (:95); pin names + rulesets topology UNCHANGED; `kManagedMaps[]`=**30** (counted; no new row); BITVEC_NUM_AXES=6, BV_AXIS_MAC=5; index active*6+5 (:715); `lower_mac_axis` per-MAC aggregate, NO closure (loader.cpp:1392-1416).
- **(d) MAC parser RE-ADDED** (FINDING-2): `hex_nibble`+`parse_mac` (config.cpp:229-269); 17-char + non-hex/bad-sep→exit9; reject removed; `mac` in whitelist + at-least-one-of; config.hpp diff EMPTY (RuleMatch.mac reused). T_SCHEMA_V2_CUTOVER c2 (malformed→exit9) passes.
- **(e) PI-mvp-4.3-MAC-DEFERRED retirement** DOCUMENTED verbatim (D-mvp-4.7-MAC-RETURN-SHIFT, design:14962 + §6.5 row). MAC bitmask RESET-on-apply (bulk-clear+insert, inactive half before flip); close_prefixes + copy_rule_counters_forward git-diff UNTOUCHED (guard #23 not extended).
- **(f) rule_info +mac** (8 keys, mac LAST, :189; HELP "(6-axis)"); the two COUNTER blocks BYTE-UNCHANGED (PI-mvp-4.6-COUNTER-CONTRACT). T_EXPORTER_RULE_LABELS ERE 7→8.
- **(g) 5 un-SKIP'd tests** assert LIVE MAC verdicts (no still-skip/weaken; only legit env-SKIP residue: jq-missing, runner-rate). T_PASS_MAC_OR_CIDR genuinely RE-AUTHORED OR→AND (4-case truth table; M-only & C-only both DROP). T_SCHEMA_V2_CUTOVER (c) reject→accept. Non-MAC corpus green.
- **(h) git-diff fences**: config.hpp / loader.hpp / sidecar.cpp EMPTY vs 480e95b. T_SCHEMA_V2_CUTOVER + config_v2_mac edits §5.47-FileList-mandated → NOT [UNRELATED-EDIT]. All source EDITs ⊆ FileList.

## Point-5 brownfield
No REGRESSION (full corpus green), no UNRELATED-EDIT (31-file `git diff --stat` maps to FileList), no INVARIANT-VIOLATED (PI-mvp-4.7-* + CONTINUES set hold; VERSION 0.15.0, `grep 0.14.0`=ZERO). close_prefixes/copy_rule_counters_forward untouched.

## Test execution
`/tmp/mint-review-tests-1780064939.log` — ran SERIALLY with root (avoids B16 -j4 flake):
```
100% tests passed, 0 tests failed out of 84
Total Test time (real) = 579.92 sec
Did not run: #5 T_DROP_MALFORMED (Skipped, legit runt-pad), #37 T_ANSIBLE_PLAYBOOK_SYNTAX (Skipped, ansible absent)
```
T_BUILD (88.6s) + T_SANITIZER_BUILD (180.5s) PASS serially — NO flake (the -j4 timeouts in the tester's parallel run are backlog-B16 contention, not regressions). All MAC tests + T_AND6_ORACLE_AGREEMENT (#83) + T_MAC_NON_IP (#84) green.

## UNEXERCISED-EXPORT
None — new helpers (lower_mac_axis, parse_mac, populate_inner_slot reshape) anon-namespace/single-TU (guard #9), exercised via integration ctests; no public-API symbol added.

## Out-of-triangulation findings
None requiring disposition. (Informational: tester added MAC fixtures beyond the FileList NEW enumeration — within the §5.47 tester-fixture grant, NOT a finding.)

— mint-dev-reviewer (round 1)

**FINAL: pass on round 1, 0 findings.** Effective tally 82/84 pass + 2 legit skip, 0 genuine fail (serial). 6-axis AND model (mac·dst·src·proto·port·vlan) live, observable, IPv4-gate boundary test-pinned.
