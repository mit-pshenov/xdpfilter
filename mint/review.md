# Review — MVP-3.4d `reset-counters` + `rule_counters` atomic-swap (mint triangulation, brownfield 5-point)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 (64/64 PASS + 2 SKIP-77 baseline) | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |
| OOT (does not affect verdict) | 2 | [OUT-OF-TRIANGULATION × 2, both `inline-merge`] |

## Verification walk (cited)

### 1. Spec ↔ Code

- **D-3.4d-1 + B-1** `rule_counters_inner` template + `rule_counters_a`/`_b` PERCPU_ARRAY + `rule_counters_outer` ARRAY_OF_MAPS at `src/bpf/mac_filter.bpf.c:231-249`. ✓
- **D-3.4d-2 + B-2** `bump_rule(__u32 rule_id, __u32 active)` at `src/bpf/mac_filter.bpf.c:273-289`. ✓
- **B-3** both call-sites pass `active`: `mac_filter.bpf.c:344` (MAC HASH-hit) + `:395` (CIDR LPM_TRIE-hit). ✓
- **D-3.4d-3 + L-A** `copy_rule_counters_forward` at `src/lib/loader.cpp:1318-1346` (anon-namespace, per-rule-id × per-CPU bounded loop). Called from BOTH reattach `:1873-1894` + fresh-attach `:2029-2042`, BEFORE `write_active_idx`. ✓
- **L-1** `kManagedMaps[]` 15 → 17 (`grep -c '^\s*{ &SkelMapsT::' loader.cpp` = 17). ✓
- **L-2** `mac_filter.h` +3/-1 constants. ✓
- **C-1/C-2** `reset_counters.{hpp,cpp}` NEW following bypass template. ✓
- **D-3.4d-RESET-BOTH** both `rid` branches write to inner_a AND inner_b at `reset_counters.cpp:233-244`. ✓
- **HG-3.4d-1** `libbpf_num_possible_cpus()` per-CPU buffer at `reset_counters.cpp:217-225` + `loader.cpp:1320`. ✓
- **HG-3.4d-2 + Q1.A** parse-time range validation at `cli.cpp:322-337`. ✓
- **HG-3.4d-3** precondition check + `reset_counters.refused.no_pin` event at `reset_counters.cpp:137-158`. ✓
- **HG-3.4d-6** audit-log format + emit BEFORE BPF writes at `reset_counters.cpp:181-199`. ✓
- **C-3** dispatch chain at `cli.cpp:314-346` + `:375-377` + `cli.hpp:16,26` + `main.cpp:76-78,150-151`. ✓
- **C-3h** `kEventNames` 33 → 35 at `logger.hpp:85,99-100,126`. ✓
- **PI-3.4d-EXPORTER** carve-out at `rule_counters_reader.cpp:141-176`. ✓
- **V-1/V-2** VERSION `0.10.0` at `CMakeLists.txt:13` + CHANGELOG `[0.10.0]` section. ✓
- **D-3.4d-FEAS smoke** per commit `f161aef`: `bpftool prog load rc=0` — fallback NOT activated. ✓
- **Anti-misdiagnosis guards #14 + #15** at `design.md:11260-11262`. ✓

### 2. Spec ↔ Tests

- **§6.NN T_CLI_RESET_COUNTERS** at `tests/T_CLI_RESET_COUNTERS.sh:144-218` — dual-bump-reset-rebump negation. ✓
- **§6.NN+1 T_CLI_RESET_COUNTERS_RULE_ID** at `:117-216` — selectivity + 2 parse-time negations (`--rule-id 64` out-of-range; `--rule-id foo` non-integer); both negations assert NO audit-log. ✓
- **§6.NN+2 T_CLI_RESET_COUNTERS_NO_IFACE** at `:51-102` — precondition + negation control. ✓
- **§6.NN+3 T_RULE_COUNTERS_ATOMIC_SWAP** (LOAD-BEARING) at `:131-232` — explicit active_idx-flip negation `:173-176`; post-flip preserve assertion `:188-199` with copy-forward-broken vs bump-broken diagnostics. ✓
- **§6.NN+4 T_CLI_HELP_VERSION** EDIT at `:54-60` — `reset-counters` substring assertion. ✓
- **§6.NN+5 T_EXPORTER_METRICS_FORMAT** EDIT — 4 sites bumped 0.9.0 → 0.10.0. ✓
- All 4 NEW tests `RESOURCE_LOCK xdp_fixture` at `tests/CMakeLists.txt:906-908` per guard #12. ✓

NO-NEGATION-CONTROL/CIRCULAR-TEST/SPEC-UNTESTED: not triggered.

### 3. Code ↔ Tests

Reviewer's `ctest -j4` → **100% tests passed, 0 failed out of 64** (Total 533.69 sec). 2 SKIP-77 baseline. Matches tester's run. ✓

### 4. Out-of-Scope Drift

`stats` PERCPU_ARRAY NOT promoted (D-3.4d-5 held; STAT_MAX=4 unchanged). No `--all-ifaces`/`--dry-run`/`--reason`/`--no-iface` flags. No "reset-on-apply" semantic (copy_rule_counters_forward ALWAYS runs). No action types beyond `{PASS, DROP}`. No new `loader::` public symbol (D-3.4d-4 held; loader.hpp ZERO-diff). ✓

### 5. Behaviour preserved (brownfield)

- **PI-7-3.4d-hpp**: `git diff 74ad632 HEAD -- src/lib/loader.hpp src/lib/config.hpp` → **0 lines**. 10th consecutive ZERO-diff on loader.hpp + 5th on config.hpp — strongest streak in project history. ✓
- **PI-7-3.4d-cpp**: all loader.cpp hunks within allowed-scope set `{apply_request, copy_rule_counters_forward, kManagedMaps[] table + adjacent comment}`. ✓
- **PI-10-3.4d**: ADD 3 / REMOVE 1 in mac_filter.h; XDPMF_RULE_COUNTERS_MAX alias byte-equivalent. ✓
- **PI-31-3.4d** (exporter READ-ONLY): no `bpf_map_update_elem` / `bpf_obj_pin` in `src/exporter/`. ✓
- **PI-3.4b-2 PRESERVE-across-apply**: load-bearing canary T_RULE_COUNTERS_ATOMIC_SWAP + T_RULE_COUNTER_SURVIVES_APPLY both green. ✓
- **PI-8-3.4d**: both binaries → 0.10.0. ✓
- **PI-3.5-4 (kEventNames stability)**: count = 35 at `logger.hpp:85,126`; T_LOG_EVENT_CATALOG_STABILITY green. ✓
- **PI-3.4d-EXPORTER carve-out**: T_EXPORTER_VALUES_MATCH_STATS green. ✓
- No prior-cycle regression: all 60 pre-§5.35 ctests still green (specifically the 6 fixture-rippled tests at T_RULE_COUNTER_MAC_HIT_BUMPS/_CIDR_HIT_BUMPS/_SURVIVES_APPLY/T_DROP_RULE_BUMPS_COUNTER/_OPERATIVE/T_RULES_ATOMIC_SWAP_NO_DROP). ✓

No REGRESSION/INVARIANT-VIOLATED/UNRELATED-EDIT.

## Test execution

```
100% tests passed, 0 tests failed out of 64
Total Test time (real) = 533.69 sec

The following tests did not run:
  5 - T_DROP_MALFORMED (Skipped)              [legitimate per §6.5]
  35 - T_ANSIBLE_PLAYBOOK_SYNTAX (Skipped)    [legitimate per §6.35]
```

Reviewer log: `/tmp/mint-review-tests-*.log`.

## Findings

NONE. All 5 framework points clean.

## Rework assignments

N/A (verdict = pass).

## Out-of-triangulation findings

### OOT-1: 6 pre-existing ctest bodies edited beyond §5.35 carve-out
**Location**: `T_RULE_COUNTER_MAC_HIT_BUMPS.sh` (+44), `T_RULE_COUNTER_CIDR_HIT_BUMPS.sh` (+30), `T_RULE_COUNTER_SURVIVES_APPLY.sh` (+24), `T_RULES_ATOMIC_SWAP_NO_DROP.sh` (+20), `T_DROP_RULE_BUMPS_COUNTER.sh` (+30), `T_DROP_RULE_OPERATIVE.sh` (+19). Vs `design.md:11003` ("All 60 pre-§5.35 ctest BODIES UNCHANGED with explicit 2-EDIT carve-out").
**Disposition**: `inline-merge`
**Rationale**: Mechanical pin-name swap `rule_counters` → `rule_counters_<a|b>` via duplicated `rule_counters_active_pin()` helper (guard #9 compliant). 6 tests would FAIL on the missing-`rule_counters`-pin condition. Symmetric oversight to PI-3.4d-EXPORTER carve-out — design enumerated exporter ripple but not test-body parallel.

### OOT-2: tests/fixtures/log_events_v1.txt edited (not in §5.35 FileList)
**Location**: `tests/fixtures/log_events_v1.txt:28-29` — +`reset_counters.activated`, +`reset_counters.refused.no_pin`. Vs `design.md:11005` ("tests/fixtures/* (existing fixtures) UNCHANGED").
**Disposition**: `inline-merge`
**Rationale**: Structural consequence of authorized `kEventNames` extension (C-3h: 33→35). Without this fixture update, T_LOG_EVENT_CATALOG_STABILITY would FAIL on set-equality check. Same class as §5.32 EDIT-1 catalog-count correction propagation.

---

**Triangulation summary**: 5-axis atomic-swap (MAC+CIDR+defaults+rules+rule_counters) operationally green; PI-3.4b-2 PRESERVE-across-apply preserved via D-3.4d-3 copy_rule_counters_forward; D-3.4d-FEAS empirically confirmed (PERCPU-as-inner works; fallback NOT activated); D-3.4d-RESET-BOTH idempotence across active_idx flips. ZERO test failures across 60/60 cycle-2 baseline + 4/4 NEW = 64/64 in 2 independent runs (tester + reviewer). 2 OOT observations both `inline-merge` (test-body ripples + fixture catalog — symmetric to PI-3.4d-EXPORTER carve-out class). PI-7 streak extended to 10th/5th consecutive ZERO-diff on loader.hpp/config.hpp. Ready to ship.

### Post-review sweep — round 1

Both OOT findings disposed as `inline-merge`. Edits ride in Phase 6 final commit (no separate commit per skill spec).

- **OOT-1** → `design.md` §5.35 EDIT-1: NEW `PI-3.4d-fixture-ripple` carve-out row added to §5.35 EDITED FileList — enumerates 6 test-body pin-name-swap ripples mirroring PI-3.4d-EXPORTER row precedent. Verifiable-invariant added.
- **OOT-2** → `design.md` §5.35 EDIT-1: fixture ripple `tests/fixtures/log_events_v1.txt` added to same PI-3.4d-fixture-ripple row (lockstep with authorized kEventNames C-3h 33→35 extension).

No `defer` or `promote-to-rework` OOTs. Verdict stays `pass` round-1.
