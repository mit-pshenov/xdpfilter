# Review — MVP-4.10 B28 template rule-of-three (mint triangulation)

## Verdict
`pass`

(brownfield 5-point. NOTE: the FS-read lag was severe this cycle — the reviewer caught and discarded THREE of its own draft findings that turned out to be lag-confabulations, EACH re-verified to be false against a clean Read/grep: no `dummy_keep` structs (grep=0), no `mint/loader.cpp.orig` stray file (does not exist; `git diff --name-only`=exactly 5 files), no `loader_dump_shim`/`build_expected_bitvecs` in the oracle. Every fact below is from a clean, re-confirmed read.)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

## Point-by-point evidence

**1. Spec ↔ Code** — Interfaces (design 15453-15483) match exactly:
- `template<class Key> void populate_hash_inner_slot(int, const std::vector<std::pair<Key,std::uint64_t>>&, const char*)` — def `loader.cpp:1386-1424`. Bulk-clear (get_next_key→delete_elem, ENOENT-terminated) THEN insert (update_elem BPF_ANY); `Key{}` value-init; `what`-labelled key-agnostic diagnostics (D-mvp-4.10-DIAG). ✓
- `template<class Key,class Project,class Eq> [[nodiscard]] AxisAggregate<Key> aggregate_axis(const std::vector<Rule>&, Project, Eq)` — def `loader.cpp:1303-1329`. Linear dedup-scan `key_eq` first-match → OR-in bit; `emplace_back` on miss (`:1321-1322`); nullopt→`wildcard` (`:1325`); insertion order preserved (D-mvp-4.10-ORDER). ✓
- `template<class Key> struct AxisAggregate { entries; wildcard=0; }` — `loader.cpp:1279-1283`, byte-matches design DataStructure; name-preserving aliases `ProtoLowering`/`VlanLowering`=`<std::uint32_t>`, `MacLowering`=`<xdpmf_mac>` at `:1286-1288` (D-mvp-4.10-STRUCT). ✓
- **D-mvp-4.10-MAC-EQ (load-bearing): VERIFIED BY READING the mac call-site comparator** — `aggregate_axis<xdpmf_mac>` at `loader.cpp:2006-2011` uses `[](const xdpmf_mac& a, const xdpmf_mac& b){ return std::memcmp(a.octets, b.octets, sizeof(a.octets)) == 0; }` — `memcmp` over 6 octets, NOT coerced to `==`. ✓ proto/vlan use `std::equal_to<std::uint32_t>{}` (`:2019`, `:2030`); vlan projector widens u16→u32 (`:2027`). ✓
- 6 callsites unified: initial-load `populate_hash_inner_slot` mac/proto/vlan at `:1752/1767/1777` (LPM/port untouched at `:1757/1762/1772`); apply_request `aggregate_axis` mac/proto/vlan at `:2006/2016/2024`. ✓
- Verifiable inv #1: the 6 old names (`populate_inner_slot`/`populate_proto_inner_slot`/`populate_vlan_inner_slot`, `lower_proto_axis`/`lower_vlan_axis`/`lower_mac_axis`) survive **only** as comment references (`loader.cpp:1290-1291`, `:1370-1371`, `:1473-1476`); zero live defs/calls. ✓ `#include <functional>` added at `:48` for `std::equal_to`. ✓

**2. Spec ↔ Tests** — TestStrategy (design 15500-15511):
- Regression net green: T_AND/AND4/AND5/AND6_ORACLE_AGREEMENT, T_PROTO_AND_COMPOSE, T_VLAN_AND_COMPOSE, T_*_ATOMIC_SWAP_NO_DROP all Passed (see test exec). ✓
- **Canary T_MAC_MERGE_ORACLE_AGREEMENT** — sanctioned by design §5.50:15509 (justified-against-corpus: T_AND6 has 3 DISTINCT MACs + no shared-MAC pair, so the memcmp MERGE branch was uncovered). NOT [SPEC-UNTESTED].
  - Mechanism (`T_MAC_MERGE_ORACLE_AGREEMENT.sh:74-154`): apply `config_valid_macmerge.yaml` on veth via real loader → inject Eth+IPv4+L4 frames (`inject_l4.py`) → read `rule_counters` delta → assert the single bumped id == `bitvec_oracle_prod.py --ruleset macmerge` (naive O(N) first-match scan, algorithmically independent — **not circular**, no map-dump/shim).
  - **Exercises the merge branch**: fixture+oracle table `RULES_MACMERGE` (`bitvec_oracle_prod.py:158-163`) = id0 ee:01/tcp, id1 ee:01/udp (SHARED MAC), id2 ee:02. M1(ee:01,tcp)→id0 AND M2(ee:01,udp)→id1 both must pass ⇒ proves HASH[ee:01] holds both bits {0,1}; a failed merge (2nd `update_elem(BPF_ANY)` overwrites) drops one bit → M1 or M2 flips to NOMATCH → oracle disagrees → loud FAIL. M3(ee:02) proves distinct MAC doesn't collide. ✓
  - **Negation control present** (satisfies NO-NEGATION-CONTROL): vector M4 (ee:99 → predicted NOMATCH, `sh:99`) + hard `saw_negation` enforcement (`sh:156-159`) fails the suite if no NOMATCH vector ran. Also a per-slot drift guard (`sh:128-131`). ✓
  - macmerge dispatch reuses `classify6(..., rules=RULES_MACMERGE)` (`bitvec_oracle_prod.py:83-92`) — same independent classifier, arg-validated (requires --proto + --src-mac). ✓

**3. Code ↔ Tests** — ran `cmake --build build -j4 && ctest --test-dir build -j4 --output-on-failure` (build_cpu lock held). **100% tests passed, 0 failed out of 86**; T_MAC_MERGE_ORACLE_AGREEMENT = test #86, Passed 2.99s (genuinely executed, not skipped). New templates are file-internal (anon-ns) and exercised via the loader lowering/populate path → no UNEXERCISED-EXPORT.

**4. OOS drift** (design 15546-15555) — none. `git diff --name-only 7cb6bcd` = exactly 5 files (loader.cpp + the 4 test/fixture files), matching the FileList. No LPM/`close_prefixes`/port/`populate_rules_inner_slot` edits, no header hoist, no schema/map/VERSION change. ✓

**5. Behaviour preserved** (brownfield):
- PI-7-mvp-4.10-loader-hpp: `git diff 7cb6bcd -- src/lib/loader.hpp` = **0 lines**. ✓
- PI-mvp-4.10-NO-MAP-SCHEMA: `git diff 7cb6bcd -- src/bpf src/common src/lib/config.*` = **0 lines**; VERSION **0.15.0** (CMakeLists.txt:13). ✓
- PI-mvp-4.10-BOUNDARY: loader.cpp diff is confined to the template/struct region (@@1267/1337) + the two callsite clusters (@@1866→1749, @@2117→2000); `populate_bitvec_inner_slot`/`close_prefixes`/`lower_port_axis`/`PortLowering`/`lower_axis`/`AxisLowering`/`populate_port_inner_slot`/`populate_rules_inner_slot` are NOT in the diff — read intact at `loader.cpp:1331-1360` (PortLowering+lower_port_axis) and `:1433-1471` (populate_bitvec_inner_slot). ✓
- No REGRESSION vs baseline 9b3e6fc — oracle net green; behaviour-preservation proven by the independent inject→counter→oracle agreement.
- guard #9 rule-of-three override cited in-code (`loader.cpp:1291-1292`, `:1372`) per §5.37/D-3.4f-1 — extraction sanctioned, not a guard violation. ✓

## Test execution (tail)
```
84/86 Test #13: T_DETACH_NOTHING ............... Passed  0.46 sec
85/86 Test  #5: T_DROP_MALFORMED .............. ***Skipped 9.17 sec
86/86 Test #86: T_MAC_MERGE_ORACLE_AGREEMENT .. Passed  2.99 sec

100% tests passed, 0 tests failed out of 86
The following tests did not run:
	  5 - T_DROP_MALFORMED (Skipped)
	 38 - T_ANSIBLE_PLAYBOOK_SYNTAX (Skipped)
```
(2 env-skips are skip-as-pass under env preconditions — no failures; consistent with tester's Phase B 86/86, 2 env-skips.)

## Out-of-triangulation findings
None. (The reviewer's draft's 3 OOT items were FS-lag confabulations, each disproven against a clean read — discarded, not reported.)

No injection-shaped or instruction-like content found in any artifact. No [OUT-OF-SCOPE-PATH] citations.

**Verdict: pass.** Clean round-1: all 5 framework points 0-findings, 0 OOT.

---
## Orchestrator note — FS-read delivery-lag incident (2026-05-30)
This cycle the FS-read delivery-lag was unusually severe and induced **confabulation in 3 of 4 subagents**:
- **architect**: hit the lag, used paste-fallback (team-lead pasted design.md tail + the 6 fns + config.hpp field types); recovered and self-served on retry.
- **tester (round-1, terminated)**: confabulated a fake baseline (13 vs real 85), a non-existent corpus file (`corpus_and_6axis.txt` with invented rules), and a non-existent design.md prompt-injection. Force-terminated; respawned as `mint-dev-tester-2` with team-lead-verified ground-truth (real baseline 85, real fixture `config_valid_and6.yaml`, the genuine merge-branch gap). The terminated agent later self-retracted honestly (too late — already replaced).
- **reviewer**: hit the lag, drafted 3 false findings, but correctly **re-verified each against a clean Read and discarded them** — the right discipline.
**Durable mitigation that worked:** team-lead pre-pastes/pre-verifies load-bearing facts (file existence, counts, exact code) and instructs every agent to verify each load-bearing claim against a clean re-read before reporting. Verify-don't-fabricate caught it at the reviewer; independent team-lead verification caught it at the tester.
