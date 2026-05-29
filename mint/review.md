# Review — MVP-4.6 exporter per-axis labels (§5.46) (mint triangulation)

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

Baseline = `3f69d0a` (pre-§5.46). Prior shipped slice = `9d29fbf` (§5.45).

## Assess-points (all confirmed independently)
- **(a) COUNTER-CONTRACT byte-identical + rule_info LAST**: `git diff 3f69d0a -- prom_format.cpp` = only the additive 3rd block (`:150-193`) before `return out`; `packets_total` (`:67-82`) + `rule_match_total` (`:89-148`) byte-unchanged. Test asserts block order. PI-mvp-4.6-COUNTER-CONTRACT holds.
- **(b) rule_info correctness**: all 7 keys `{iface,rule_id,dst_cidr,src_cidr,protocol,dst_port,vlan}` fixed-order, value `1` (`:184`); escape_label_value reused; sourced from `rule_meta_by_iface` only → counter-orphan rule_id gets NO series; HELP/TYPE-once gauge unconditional (PI-32). Unconstrained axis → `""`.
- **(c) reader no-JSON + noexcept + read-only**: `extract_axis` (`sidecar_reader.cpp:56-67`) key-anchored regex over group-2, NO parser dep (`grep nlohmann|json.hpp`=ZERO); `parse_rule_index` noexcept (PI-32); read-only ifstream (PI-31); `classify_match_kind` untouched.
- **(d) PI shift documented**: PI-mvp-4.3-EXPORTER-AGNOSTIC retirement recorded verbatim (D-mvp-4.6-EXPORTER-AXIS-AWARE-SHIFT + §6.5 row + §7 OOS); COUNTER half re-expressed as PI-mvp-4.6-COUNTER-CONTRACT. Not silently broken.
- **(e) CONSUMER-ONLY fences**: `git diff 3f69d0a` EMPTY for sidecar.cpp, src/bpf/, loader.*, config.*, mac_filter.h, logger.*, cidr.*, + main/http/stats_reader/rule_counters_reader. Changed set = FileList exactly. No UNRELATED-EDIT.
- **(f) VERSION**: CMakeLists 0.14.0; `grep 0.13.0 tests/ src/`=ZERO; T_EXPORTER_METRICS_FORMAT 4 sites updated; `--version`→0.14.0.
- **(g) negation control present + non-circular**: 3 controls (id2/id5 unconstrained→"" never bogus; non-configured rule_id=99→ZERO series; pre-existing orphan→action=unknown), all config-derived (not impl-state). T_BPFFS_ROOT_SYMLINK B16 flake did not recur.

## Test execution
```
1/4 T_EXPORTER_METRICS_FORMAT ... Passed 3.05s
2/4 T_SIDECAR_JSON_SHAPE ........ Passed 1.82s
3/4 T_EXPORTER_RULE_LABELS ...... Passed 3.97s
4/4 T_AND5_ORACLE_AGREEMENT ..... Passed 9.63s
100% passed, 0 failed of 4 (reviewer; --version 0.14.0)
```
Tester full suite (test-run.log): 82 pass / 0 fail / 7 env-skip. No UNEXERCISED-EXPORT (parse_rule_index/emit_metrics exercised end-to-end via /metrics tests; extract_axis anon-namespace single-TU).

## Out-of-triangulation findings
None.

## Rework assignments
None — ship it.

— mint-dev-reviewer (round 1)

**FINAL: pass on round 1, 0 findings, 0 OOT.** Test tally 82 pass / 0 fail / 7 skip.
