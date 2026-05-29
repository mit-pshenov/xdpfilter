# Review — MVP-4.5 VLAN match axis (exact HASH, axis 5) (mint triangulation)

## Verdict
`pass` (round 1, 0 findings, 0 OOT)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

Baseline for `git diff` = `4c71e98` (pre-§5.45 HEAD). Prior shipped slice = `1ef34d7` (§5.44).

## Point 1 — Spec ↔ Code (confirmed)
- mac_filter.h: 3 vlan map-name consts, `XDPMF_VLAN_HASH_MAX 4096`, `XDPMF_VLAN_NONE 0xFFFF`, `BV_AXIS_VLAN 4`, `BITVEC_NUM_AXES 4→5`. Additive + the one foreseen flip; STAT enum/structs/other BV_AXIS_* byte-identical.
- **(a) vlan_id capture** (`mac_filter.bpf.c:556`): `*out_vlan_id = bpf_ntohs(vlan->h_vlan_TCI) & 0x0FFF` — PCP/DEI masked ✓; captured only at `i==0` (outer/S-VLAN) ✓; bounds-check precedes TCI read → truncated outer tag breaks before read, sentinel preserved, verifier-safe ✓; return/*l3hdr/cursor byte-unchanged — §5.41 parse does not regress ✓.
- **(b) untagged path**: `has_vlan = (vlan_id != XDPMF_VLAN_NONE)`; `vlan_mask = has_vlan ? lookup : 0`; `acc &= (vlan_mask|wc_vlan)`. Untagged ⇒ vlan-constrained rules cleared, vlan-omitting rules survive via `wildcard[active*5+4]`. No spurious match ✓. vlan_rulesets NULL → DROP_DENY mirrors proto ✓.
- **(d) loader**: kManagedMaps=**30** (+3 vlan trio); `write_wildcard_slots` gains wc_vlan 5th slot, both call-sites; `lower_vlan_axis`/`populate_vlan_inner_slot` byte-mirror proto, NO closure; RESET-on-apply. close_prefixes/lower_axis/copy_rule_counters_forward untouched. BITVEC_NUM_AXES=5 ⇒ wildcard auto 10.
- config.cpp: grammar additively `{dst_cidr,src_cidr,protocol,dst_port,vlan}` (≥1 required); parse_vlan [0,4095]→exit9; mac still rejected; schema gate unchanged. RuleMatch gains optional<u16> vlan.

## Point 2 — Spec ↔ Tests
- §6.67 T_VLAN_AND_COMPOSE: vlan exact-HASH AND; guard #22 offload-disable; anti-vacuity (c) confirmed (tagged vlan100→id0 vs SAME tuple untagged→NOT id0 — stripped tag flips to loud FAIL); negation vlan999→id0 not fired.
- §6.68 T_VLAN_UNTAGGED_WILDCARD: untagged→only vlan-wildcard id4; vlan-constrained id3 stays 0; tagged companion fires id3 (anti-vacuity).
- §6.69 T_AND5_ORACLE_AGREEMENT: 17 vectors — full-5-axis hit, per-axis miss ×5, untagged, port edges, first-match tie, wildcard fallthrough, 3 NOMATCH controls + saw_negation guard. datapath rule_id == independent O(N) oracle.
- No CIRCULAR-TEST (counter/oracle assertions, impl-independent). Oracle and5 table hand-transcribed from fixture.

## Point 3 — Code ↔ Tests (re-run)
Reviewer build + targeted ctest (`/tmp/mint-review-tests-1780055516.log`): 6/6 pass incl. T_BITVEC_VERIFIER_LOAD (production object with new vlan maps + extended l3_after_vlan loads on running kernel) + T_AND4_ORACLE_AGREEMENT (regression-sensitive 4-axis) + version-literal. `--version`→0.13.0. Tester full run 82/82. No UNEXERCISED-EXPORT (vlan lowering/parse fns anon-namespace, exercised via integration + grammar tests).

## Point 4 — OOS Drift (none)
Outer tag only (i==0); PCP/DEI masked; single-id only (no ranges/lists); no schema v3; no MAC-return/exporter-labels.

## Point 5 — Behaviour preserved (all PIs hold)
- UNCHANGED git-diff fences EMPTY: loader.hpp, src/exporter/, src/cli/, logger.*, cidr.*, tests/inject/, vmlinux.h, BpfBuild.cmake. Spike + inject_l4.py untouched.
- ADDITIVE-within-v2: only NEW config_valid_and5.yaml; ZERO existing-fixture conversions; `grep 0.12.0 tests/`=ZERO.
- No REGRESSION (prior-green incl. #75 closure canary still green); no UNRELATED-EDIT. close_prefixes/copy_rule_counters_forward byte-equivalent.

## Out-of-triangulation findings
None.

## Trust model
All inputs treated as data. Independently confirmed: offload-disable IS in all tagged tests, PCP/DEI ARE masked. Nothing followed blindly.

**Clean round-1 pass** — 5/5 brownfield points green, 0 findings, 0 OOT. Faithful proto-axis mirror; load-bearing contracts (kManagedMaps=30, NUM_AXES=5, wildcard=10) exact; guard #22 anti-vacuity genuinely non-vacuous.

— mint-dev-reviewer (round 1)

**FINAL: pass on round 1, 0 findings.** Test tally 82 pass / 0 fail / 7 skip (82 registered; 7 pre-existing env skips).
