# Review — MVP-3.4b cycle 1 per-rule counters (mint triangulation)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — (T_SANITIZER_BUILD flake under -j4 explained below; not a real failure) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |
| OOT | 1 | [OUT-OF-TRIANGULATION × 1] |

## Triangulation evidence

### Framework Point 1 — Spec ↔ Code (all anchors verified)

- **`struct allow_entry` byte layout** (`src/common/mac_filter.h:143-147`) matches §5.31 DataStructures byte-by-byte: offset 0 = `present`, offsets 1-3 = `_pad[3]`, offsets 4-7 = `rule_id`. Total 8 bytes.
- **`rule_counters` PERCPU_ARRAY[64] of __u64** declared at `src/bpf/mac_filter.bpf.c:195-201` with LIBBPF_PIN_BY_NAME; matches §5.31 DataStructures and PI-3.4b-1.
- **`bump_rule(__u32 rule_id)`** helper with bounds-check at `src/bpf/mac_filter.bpf.c:219-228` matches Q1 B3 contract; folds verifier-required `rule_id < XDPMF_RULE_COUNTERS_MAX` bounds-check inline.
- **Datapath wiring**: MAC HASH hit at `src/bpf/mac_filter.bpf.c:270-275` (`bump_rule(entry->rule_id)` then `bump_stat(STAT_PASS)` then `XDP_PASS`); CIDR LPM_TRIE hit at `src/bpf/mac_filter.bpf.c:302-307`. Matches design Q1 B3 exactly.
- **`kManagedMaps[]` 13th entry** at `src/lib/loader.cpp:155-163` (rule_counters with `legacy_alias=false`); HK-9 dividend one-line refactor.
- **`populate_inner_slot` / `populate_cidr_inner_slot`** rewritten to write full `struct allow_entry` (`src/lib/loader.cpp:1095-1149, 1151-1182`) with `present=1` + `rule_id` per entry; D-3.4b-15 Option A picked.
- **`apply_request` sidecar-write POST-flip** at `src/lib/loader.cpp:1793` (reattach branch) AND `:1906` (fresh-attach branch); matches D-3.4b-16.
- **`sidecar::write_rule_index`** (`src/lib/sidecar.cpp:238-316`) is `noexcept`, atomic write idiom (write-to-.tmp → fsync → close → rename), mode 0644, mkdir-p'd dir; matches Q3 P4 + D-3.4b-21 path correction (`XDPMF_SIDECAR_ROOT="/run/xdpmacfilter"`).
- **Symlink-refuse guard** at `src/lib/sidecar.cpp:248-278` (lstat + S_ISLNK + non-dir refusal) mirrors §5.22 O_PATH discipline.
- **Roll-your-own JSON writer** at `src/lib/sidecar.cpp:38-158`; NO `nlohmann/json` dep in CMakeLists.txt; matches D-3.4b-10.
- **Exporter rule-label join** in `src/exporter/http.cpp:215-232` (per-scrape inside `handle_connection`).
- **`xdpfilter_rule_match_total{iface, rule_id, action}`** emission at `src/exporter/prom_format.cpp:79-121`; sidecar-orphan tolerance via `action="unknown"` at line 117-119 (PI-32-3.4b).
- **`parse_rule_index`** at `src/exporter/sidecar_reader.cpp:51-81`: line-oriented ERE per D-3.4b-14; matches D-3.4b-20 one-rule-per-line writer output.
- **Version bump** at `CMakeLists.txt:13` (0.6.1 → 0.7.0); both binaries report `0.7.0`.

### Framework Point 2 — Spec ↔ Tests (all §6.47..§6.52 + PI-3.4b-9 catalog)

| TestStrategy item | Test file | Assertion targets stated outcome | Negation control |
|---|---|---|---|
| §6.47 MAC HASH-hit | `tests/T_RULE_COUNTER_MAC_HIT_BUMPS.sh:124-207` | rule_counters[5]=5, [0]=3; STAT_PASS delta=8 | non-matching MAC; counters STAY |
| §6.48 CIDR LPM-hit | `tests/T_RULE_COUNTER_CIDR_HIT_BUMPS.sh:99-186` | rule_counters[42]=4; STAT_PASS_CIDR delta=4 | src_ip OUTSIDE; counter STAYS; MAC short-circuit isolation |
| §6.49 SURVIVES_APPLY (load-bearing canary) | `tests/T_RULE_COUNTER_SURVIVES_APPLY.sh:94-161` | rule_counters[5]=7 after step 2; STILL 7 post-reapply; =10 after step 5; active_idx-flip assertion at :124-131 | differential pre/post-apply IS the negation |
| §6.50 SIDECAR_JSON_SHAPE | `tests/T_SIDECAR_JSON_SHAPE.sh:77-180` | `/run/xdpmacfilter/<iface>/rule_index.json` mode 0644; schema/applied_at/per-rule shape | malformed apply; sidecar md5 UNCHANGED |
| §6.51 EXPORTER_RULE_LABELS | `tests/T_EXPORTER_RULE_LABELS.sh:120-262` | HTTP 200; ≥1 sample matching rule_id+action ERE; packets_total preserved | sidecar delete mid-scrape; exporter alive; action="unknown" |
| §6.52 DROP_RULE | `tests/T_DROP_RULE_BUMPS_COUNTER.sh:131-256` | STAT_DROP_DENY+=5; rule_counters[17]==0; rules[17].action_id=1 | PASS-rule MAC bumps; DROP-rule counter STAYS 0 |

All 6 NEW ctests carry an explicit negation control.

**PI-3.4b-9 carve-out catalog** (per §5.31 EDIT-2, 3 ctest-body EDITs):
1. `tests/T_RULES_SKELETON_NOT_WIRED.sh:13-15, 296-300` — comment + stderr-msg rewrite per PI-13-3.4b adjudication.
2. `tests/T_EXPORTER_METRICS_FORMAT.sh:21, 100` — version literal 0.6.1 → 0.7.0 per HK-8.
3. `tests/T_ATTACH_TAG_MISMATCH.sh:151-181` — hybrid preflight per D-3.4b-22 (bpftool-vs-libbpf-skeleton BTF asymmetry).

### Framework Point 3 — Code ↔ Tests (test execution)

Re-run (`ctest -j4`): 51/52 passed + 2 SKIP-77 = 100% functional pass. One -j4-induced timeout on **T_SANITIZER_BUILD** (180s ceiling) — re-ran serially in 115s. Tester's baseline ran in 171s serial. NOT a code/test defect; CPU contention.

**UNEXERCISED-EXPORT spot-check**: every public function in NEW source files exercised by tests.

### Framework Point 4 — Out-of-Scope Drift

- No `nlohmann/json` dep added.
- No `reset-counters` API.
- No `xdpfilter_drop_match_total` separate series.
- No `rules` map atomic-swap promotion.
- No sidecar S2/S3 schema fields.

### Framework Point 5 — Behaviour preserved (brownfield)

| Invariant | Check | Result |
|---|---|---|
| **PI-7-3.4b-hpp** (loader.hpp + config.hpp ZERO diff, 6th cycle) | `git diff main -- src/lib/loader.hpp src/lib/config.hpp \| wc -l` | **0** ✓ |
| **PI-7-3.4b-cpp** regional-diff | Inspected `git diff 0984a88..HEAD -- src/lib/loader.cpp` hunk-by-hunk | All hunks within scope; attach/detach/state-machine/§5.4/§5.19/§5.22/§5.24 untouched ✓ |
| **PI-10-3.4b** (mac_filter.h additive-only) | New additions; existing unchanged | ✓ |
| **PI-13-3.4b** (inner-VALUE 8B struct allow_entry, byte 0 = present) | bpf source + struct def in mac_filter.h:143-147; T_RULES_SKELETON_NOT_WIRED + drop-MAC ABSENCE assertion via mac_in_inner_pin | ✓ |
| **PI-28-3.4b** (mac_filter_prog body extends; rest byte-equivalent) | `:270-275, :302-307` + new map + helper; default-fallthrough/drop/IPv4-gate/ethhdr-bounds byte-equivalent | ✓ |
| **PI-29-3.4b** (rules + action_table NOT consulted by datapath; inner-VALUE rule_id IS) | No `bpf_map_lookup_elem(&rules,...)` or `&action_table` inside `mac_filter_prog`; T_DROP_RULE_BUMPS_COUNTER asserts drop-MAC → 0 bump | ✓ |
| **PI-31-3.4b** (exporter READ-ONLY incl. new TUs) | `grep` returns only comment-mentions | ✓ |
| **PI-32-3.4b** (sidecar-orphan tolerance) | T_EXPORTER_RULE_LABELS step (g) deletes sidecar; exporter survives; `action="unknown"` emitted | ✓ |
| **PI-6-3.4b / PI-34-3.4b** (3-EDIT carve-out per §5.31 EDIT-2) | `git diff 0984a88..HEAD --stat tests/T_*.sh` shows 3 modified files + 6 NEW | ✓ |
| **PI-3.4b-8** (kManagedMaps[] = 13 entries) | `grep -c '^\s*{ &SkelMapsT::' src/lib/loader.cpp` = **13** | ✓ |
| **PI-8-3.4b** (binaries report 0.7.0) | `--version` on both | ✓ |

No `[REGRESSION]` / `[UNRELATED-EDIT]` / `[INVARIANT-VIOLATED]` triggers.

## Test execution

```
98% tests passed, 1 tests failed out of 52   (T_SANITIZER_BUILD timeout under -j4)
SKIP-77: T_DROP_MALFORMED, T_ANSIBLE_PLAYBOOK_SYNTAX
```

Re-run of T_SANITIZER_BUILD serially: 115.33s, Passed.

→ 52/52 functionally pass; 2 legitimate SKIP-77. Matches tester baseline.

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] design FileList row for src/exporter/main.cpp says EDITED but impl placed per-scrape wiring in src/exporter/http.cpp
**Location**: design.md FileList row (formerly line 7774); actual wiring at `src/exporter/http.cpp:215-232` (`read_rule_counters` + `parse_rule_index` + `emit_metrics` call chain). `git diff -- src/exporter/main.cpp` → ZERO output.
**Evidence**: Design row prose targeted `main.cpp`; reality has the per-scrape codepath in `handle_connection` inside `http.cpp` (called from `http::run` invoked by `main.cpp`). Functional contract met; only the FILE NAME in prose was imprecise.
**Recommended disposition**: `inline-merge`
**Rationale**: Non-substantive prose imprecision; impl picked the correct file per project's actual layering. Anti-misdiagnosis guard #4 in design §7 anticipates this. NOT promote-to-rework — impl's placement is operationally correct.

## Summary

All three artifacts (design.md §5.31 + EDIT-1 + EDIT-2, impl across 4 NEW + 8 EDITED source files, tests across 6 NEW + 3 EDITED ctests) agree triangulation-wise. The load-bearing PI-13-3.4b adjudication holds end-to-end. PI-7-3.4b-hpp ZERO diff streak holds (6th consecutive cycle on loader.hpp; 1st cycle on config.hpp). No regressions, no out-of-scope drift, no invariant violations.

— mint-dev-reviewer

---

### Post-review sweep — round 1

- **OOT-1**: `src/exporter/main.cpp` → `src/exporter/http.cpp` FileList row correction → design.md lines 7589 + 7774 edited (FileList EDITED summary + FileList row both now point at `src/exporter/http.cpp` with inline `[Phase 4.5 OOT inline-merge]` audit marker preserving the original prose context) → impl's placement of per-scrape wiring in `handle_connection` is now design-authoritative; `src/exporter/main.cpp` confirmed UNCHANGED this slice (PI-7-3.4b-cpp ZERO-diff extends by one more file).
