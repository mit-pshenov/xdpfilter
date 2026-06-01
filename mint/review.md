# Review — MVP-4.21 B30 slot/id decouple (§5.61) (mint triangulation)

## Verdict
`pass`  (round 1; 1 OOT resolved inline, 1 OOT deferred)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — (negation control present) |
| 3. Code ↔ Tests | 0 functional | T_BUILD env-timeout under -j4 (re-run green in isolation — OOT-2) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — (PI-7 ∅, datapath byte-identical, no REGRESSION/UNRELATED-EDIT) |

## Load-bearing invariants — independently verified by the reviewer

**(a) PI-mvp-4.21-DATAPATH-IDENTICAL — VERIFIED.** Compiled baseline `73e2964` + current `mac_filter.bpf.c` side-by-side (clang-19 `-target bpf -O2`), `llvm-objdump -d --section=xdp` → disassembly diff EMPTY (3658 insns each); `slot_rule_id` present ONLY in current's maps section, referenced by no instruction. The committed bpf.c diff = ONLY the one `SEC(".maps")` decl.

**(b) PI-3.4b-2 counter-by-id continuity — VERIFIED.** `copy_rule_counters_forward` (loader.cpp:~1930) is keyed-by-id (finds OLD slot where `old_slot_to_id[old]==new_slot_to_id[k]`, copies that counter, zeros new/empty ids, writes all [0,64)) — NOT a slot-indexed blanket copy. Reads OLD-active half before the flip; fresh-attach passes all-EMPTY. §6.76 negation ({rule_id=50}==0, would be 4 under blanket copy) is real and passed.

**(c) §6.76 T_RULE_COUNTER_SURVIVES_REORDER** — asserts via exporter /metrics STABLE-ID labels (not raw slot → not circular): id100 counter survives slot 1→2 move, id50 new==0 (negation), monotonic, Q3 priority parity (lower id 50 wins overlap), Q2 sentinel/count-cap reject + large-u32 accept. PASSED.

**(d) PI-7 — `git diff 73e2964 -- src/lib/loader.hpp src/lib/config.hpp` = ∅.** src/ diff = exactly the 7-file FileList footprint.

**(e) PI-KMAPS — kManagedMaps = 39** (was 38); slot_rule_id row added; single table walked by all 3 clear/pin/reuse loops (HK-9 intact).

**(f) PI-PRIORITY (Q3)** — `compute_id_to_slot` = id-sorted rank; all 4 lowering bit-shifts + populate_rules_inner_slot use `id_to_slot.at(r.id)` coherently; ffsll still returns lowest-id survivor.

**(g) OOS / scope** — no most-specific-wins / N>64; VERSION 0.15.0, schema 2, 9 axes, BITVEC unchanged.

**Exporter (Scope-4)** — rule_counters_reader.cpp reads slot_rule_id active half into slot_to_id[], read-only (PI-31), graceful-empty (PI-32); prom_format.cpp labels by stable id, skips EMPTY. Cluster-1 (8 by-id raw-map tests) use the id_to_slot remap (committed, EDIT-1 ruling A).

## Test execution
Reviewer `sudo ctest -j4` (log `/tmp/mint-review-tests-1780315746.log`): 99% passed, 1 failed = T_BUILD (Timeout 300s under -j4 contention) → re-ran T_BUILD in isolation → Passed 94.04s (environmental, NOT a build break). All slice-relevant tests passed. Effective = tester's 97/97 (95 pass + 2 env skips: T_DROP_MALFORMED, T_ANSIBLE_PLAYBOOK_SYNTAX).

Final (b) shippable-tree confirmation (team-lead, post-OOT-1 restore, sole owner): `ctest -R 'T_CLI_RESET_COUNTERS|T_RULE_COUNTER_SURVIVES_REORDER'` → 4/4 passed (T_RULE_COUNTER_SURVIVES_REORDER 4.62s, T_CLI_RESET_COUNTERS, T_CLI_RESET_COUNTERS_RULE_ID, T_CLI_RESET_COUNTERS_NO_IFACE).

## Out-of-triangulation findings

### OOT-1 [RESOLVED INLINE — disposition 1] — dirty working tree: Cluster-2 reset tests reverted (a) over committed (b)
The committed slice (`dc964d1`) implements EDIT-1 Cluster-2 as ruling **(b)** (sparse fixture + id→slot remap + pass SLOT to --rule-id + audit `rule_id=<slot>`), which **matches design §5.61 EDIT-1 / D-mvp-4.21-RAWMAP-REMAP exactly**. The working tree had uncommitted edits reverting both reset tests to ruling (a) + an untracked `config_reset_counters_dense.yaml` — a coordination message-race artifact (architect↔tester crossed during the a→b→a churn; both (a) and (b) are design-sanctioned equivalents). **Resolution (team-lead, Phase 4.5):** disposition 1 — `git checkout dc964d1 -- tests/T_CLI_RESET_COUNTERS*.sh` + `rm tests/fixtures/config_reset_counters_dense.yaml`. Working tree now clean == dc964d1 (b); design(b) = committed-tests(b) = test-run.log(b), all consistent. Final (b) tree re-confirmed green (4/4 above). NOT a correctness defect.

### OOT-2 [DEFERRED] — T_BUILD env-timeout under -j4
T_BUILD (from-scratch cmake configure+build meta-test) timed out at 300s under -j4 concurrency (sanitizer + oracle compiles starved it); passed at 94s in isolation. Environmental, not a B30 defect. Deferred: consider bumping T_BUILD's ctest TIMEOUT or excluding it from -j parallel fixtures (test-infra, future slice).

## Rework assignments
None blocking. OOT-1 resolved inline by team-lead; OOT-2 deferred.

## Process note (for retrospective)
This slice's Phase-B saw heavy Cluster-2 coordination thrash (the reset-test mechanism flip-flopped (a)↔(b) ≥4× across architect/tester due to message-ordering races + one tester confabulation of a "clean (b)" tree that was actually (a)-dirty). The LOAD-BEARING product invariants (datapath byte-identity, counter-by-id continuity) were never in question — the thrash was confined to a design-sanctioned-equivalent test mechanism. Resolved deterministically via orchestrator git-restore to the reviewer-validated committed (b). Lesson: freeze ALL agents before issuing a convergence ruling on a contested point; verify working-tree claims on ground truth.
