# Review — MVP-3.4b cycle 2: rules atomic-swap + datapath dispatch (mint triangulation, brownfield 5-point)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield §6.5) | 0 | — |

## Evidence — point-by-point

### 1. Spec ↔ Code

- **D-1 BPF map promotion** (`src/bpf/mac_filter.bpf.c:175-202`): SHARED `rules` ARRAY replaced by `struct rules_inner` template + `rules_a` + `rules_b` named instances + `rules_outer` ARRAY_OF_MAPS with inline `.values = { &rules_a, &rules_b }` initializer. Pins land at the 3 expected basenames. Mirrors the §5.27 CIDR axis shape (template + 2 inners + outer). ✓
- **D-2 datapath dispatch** (`src/bpf/mac_filter.bpf.c:289-322` MAC HASH branch, `:343-373` CIDR LPM_TRIE branch): both branches gain the 3-step chain `rules_outer[active] → rules_inner[rid] → action_table[aid]` with NULL-checks at every step + `STAT_DROP_DENY` bump + `XDP_DROP` on `action_type == ACTION_DROP`. `bump_rule()` runs BEFORE the dispatch chain (HG-3.4b-c2-5). Matches HG-3.4b-c2-4 pseudocode. ✓
- **L-1 kManagedMaps[]** (`src/lib/loader.cpp:154-175`): 13 → 15 entries; REMOVE `{rules, RULES_NAME}`; ADD `rules_a` / `rules_b` / `rules_outer`. `grep -c '^\s*{ &SkelMapsT::' src/lib/loader.cpp` = **15**. ✓
- **L-2 populate_rules_inner_slot** (`src/lib/loader.cpp:1230-1276`): function renamed from `populate_rules_skeleton`; body byte-equivalent (clear-all-64 + write-occupied); fd-source shifted to inactive inner-fd. Both call-sites (state-b reattach `loader.cpp:1773-1786`, fresh-attach `:1911-1924`) compute `inactive_rules_inner` via skel ternary BEFORE active_idx flip. ✓
- **L-3 schema cycle 3 shift** (`src/lib/loader.cpp:1503,1525`): `if (r.action != RuleAction::Pass) continue;` removed from both `extract_pass_macs` and `extract_pass_cidrs`; function names kept per D-3.4b-c2-3. ✓
- **L-4 mac_filter.h constants** (`src/common/mac_filter.h:124-133`): 3 new `XDPMF_MAP_RULES_OUTER_NAME` / `_INNER_A_NAME` / `_INNER_B_NAME` constants added; `XDPMF_MAP_RULES_NAME` define removed. Rest byte-equivalent. ✓
- **D-3.4b-c2-4 WARN retirement** (`loader.cpp:1566-1574` replaced the prior emit block with a comment-only retirement note; `logger.hpp:74-86` removes the `loader.warn.rules_skeleton_not_wired` entry and updates `kEventCount` literal 34 → 33). ✓
- **V-1 VERSION bump** (`CMakeLists.txt:13`): `0.8.0 → 0.9.0`. Both binaries report `0.9.0` via shared `version.h`. ✓
- **V-2 CHANGELOG** (`CHANGELOG.md:8-60`): new `[0.9.0] - 2026-05-27` section per Keep-a-Changelog with Added/Changed/Removed/Notes/Preserved-invariants/OOS-fences/Build-pace. ✓
- **PI-28-3.4b + PI-29-3.4b**: both LIFTED with explicit `[SUPERSEDED]` markers in §5.31. Successor `PI-29-3.4b-c2` + `PI-13-3.4b-c2` + `PI-30-3.4b-c2-schema` written. No silent retire. ✓

### 2. Spec ↔ Tests

- **§6.NN T_DROP_RULE_OPERATIVE** (`tests/T_DROP_RULE_OPERATIVE.sh:1-339`): all 8 assertion regions (a)..(h) green; pass-rule MAC negation control isolates rc keying. ✓
- **§6.NN+1 T_RULES_ATOMIC_SWAP_NO_DROP** (`tests/T_RULES_ATOMIC_SWAP_NO_DROP.sh:1-358`): 12-step canary with concurrent alternating injector + ~10% atomicity tolerance + MAC_DENY negation. ✓
- **§6.NN+2 T_RULES_AXIS_FLIPS_WITH_ACTIVE_IDX** (`tests/T_RULES_AXIS_FLIPS_WITH_ACTIVE_IDX.sh:1-244`): bpftool-only one-deep rollback verification. ✓
- **§6.52-revised T_DROP_RULE_BUMPS_COUNTER**: assertions INVERTED per Q3.A — drop-MAC NOW in inner-allowlist + `rule_counters[17] += 5`. ✓
- **PI-3.4b-c2-fixture-ripple**: exactly 2 EDITED test bodies + 1 DELETED + 3 NEW under `tests/T_*.sh`. ✓

NO-NEGATION-CONTROL: not triggered. CIRCULAR-TEST: not triggered. SPEC-UNTESTED: not triggered.

### 3. Code ↔ Tests

- Reviewer's own `ctest -j4`: `/tmp/mint-review-tests-1779866591.log` → **100% tests passed, 0 tests failed out of 60** (465.29 sec). Same 2 SKIP-77 baseline.
- PI-13-3.4b-c2 / PI-29-3.4b-c2 / PI-30-3.4b-c2-schema load-bearing canaries: T-1 + T-2 + T-3 each PASS in tester's 60/60 + reviewer's 4th-run 60/60. ✓

### 4. Out-of-Scope Drift

All §7 OOS items NOT touched: reset-counters / rule_counter atomic-swap / action_table promotion / new action types / Q1.A new STAT slot / drop-precedence-dedup / documentation pass. No new CLI flag / env var / exit code / public API symbol. ✓

### 5. Behaviour preserved (brownfield §6.5)

- **PI-7-3.4b-c2-hpp** (loader.hpp 9th + config.hpp 4th ZERO diff): `git diff a1b6597 HEAD -- src/lib/loader.hpp src/lib/config.hpp` → **0 lines** ✓
- **PI-8-3.4b-c2**: both binaries → `0.9.0`. ✓
- **PI-10-3.4b-c2**: 3 added + 1 removed defines; STAT_MAX stays at 4. ✓
- **PI-3.4b-c2-fixture-ripple**: 2 EDIT + 1 DELETE + 3 NEW. ✓
- **PI-3.4b-c2-warn-removed**: no `rules: section parsed` substring. ✓
- **PI-3.5-4 AMENDED 34→33**: kEventCount=33, kEventNames sized 33, fixture 33 lines. ✓
- **PI-3.4b-1..PI-3.4b-8** (carry-forward §5.31): UNCHANGED except PI-3.4b-8 kManagedMaps 13→15. ✓
- **PI-13-3.4b** (struct allow_entry 8-byte): UNCHANGED. ✓
- **PI-1..PI-12, PI-14..PI-27, PI-30..PI-34**: ZERO-diff on exporter/sidecar/cli/yaml/cidr/config/systemd/ansible. ✓
- **PI-28-3.4b LIFTED / PI-29-3.4b LIFTED**: `[SUPERSEDED]` markers verified. ✓

No REGRESSION. No INVARIANT-VIOLATED. No UNRELATED-EDIT.

## Test execution

```
100% tests passed, 0 tests failed out of 60
Total Test time (real) = 465.29 sec

The following tests did not run:
	  5 - T_DROP_MALFORMED (Skipped)
	 35 - T_ANSIBLE_PLAYBOOK_SYNTAX (Skipped)
```

Reviewer log: `/tmp/mint-review-tests-1779866591.log`. NEW canaries: T_DROP_RULE_OPERATIVE 20.17s / T_RULES_ATOMIC_SWAP_NO_DROP 7.95s / T_RULES_AXIS_FLIPS_WITH_ACTIVE_IDX 2.92s.

## Findings

NONE. All 5 framework points clean.

## Rework assignments

N/A (verdict = pass).

## Out-of-triangulation findings

### OOT-1: CMakeLists.txt project DESCRIPTION updated alongside VERSION
**Location**: `CMakeLists.txt:14` (+ vs `design.md` V-1 "ZERO other CMake changes" hint)
**Disposition**: `inline-merge`
**Rationale**: DESCRIPTION is metadata with NO user-observable surface tied to any PI-* contract. Reverting leaves stale "MVP-3.5" tag on a 0.9.0 binary. SHOULD-level per verifiable-invariants framing.

### OOT-2: 2 new fixture files vs design's "at most 1 new fixture" SHOULD hint
**Location**: `tests/fixtures/config_rules_swap_{a,b}.yaml`
**Disposition**: `inline-merge`
**Rationale**: Atomic-swap canary structurally requires action-inverted pair. SHOULD-level hint.

### OOT-3: `loader.warn.rules_skeleton_not_wired` retirement-annotation comments remain in 2 files
**Location**: `src/lib/loader.cpp:1574` + `src/common/logger.hpp:75`
**Disposition**: `inline-merge`
**Rationale**: Both are retirement-discipline citation comments per D-3.4b-c2-4. Operative grep (emit-site / kEventNames entry / test stderr assertion) returns ZERO.

### OOT-4: SEC(".maps") post-§5.34 count = 15 not 16 (pseudocode said 16)
**Location**: `src/bpf/mac_filter.bpf.c` template-without-SEC pattern
**Disposition**: `inline-merge`
**Rationale**: Impl mirrored existing `xdpmf_allowlist_inner` / `xdpmf_cidr_inner` precedents. Per design's resolution rule "invariants block wins, prose loses". PI-29-3.4b-c2 + PI-13-3.4b-c2 verified end-to-end via T-1/T-2/T-3.

### OOT-5: Stale comment block in shared fixture `config_per_rule_counters.yaml`
**Location**: `tests/fixtures/config_per_rule_counters.yaml:11-15`
**Disposition**: `inline-merge`
**Rationale**: Comment-only hygiene; YAML data unchanged. Header block still cites §5.26 cycle-2 contract retired by §5.34.

---

**Triangulation summary**: 4-axis atomic-swap mechanism (MAC + CIDR + defaults + rules) operationally green; PI-28-3.4b + PI-29-3.4b correctly LIFTED with successors PI-13-3.4b-c2 + PI-29-3.4b-c2 + PI-30-3.4b-c2-schema written; schema cycle 3 shift cleanly inverts T_DROP_RULE_BUMPS_COUNTER assertions per Q3.A inline-merge rule. ZERO test failures across 60/60 in 2 independent runs (tester + reviewer). 5 OOT observations all dispose to `inline-merge`. Ready to ship.

### Post-review sweep — round 1

All 5 OOT findings disposed as `inline-merge`. Edits ride in the final Phase 6 commit (no separate commit — keeps git log clean per /mint-dev skill spec).

- **OOT-1** → `design.md` verifiable-invariant relaxed: `CMakeLists.txt` `DESCRIPTION` string MAY track the latest shipped slice (metadata, no PI-* tie).
- **OOT-2** → `design.md` verifiable-invariant relaxed: at most **2** new fixtures under `tests/fixtures/` (paired action-inverted symmetric fixtures accepted for the atomic-swap canary structural requirement).
- **OOT-3** → `design.md` verifiable-invariant refined: `grep -c 'loader.warn.rules_skeleton_not_wired' src/` operative meaning = ZERO emit-sites + ZERO kEventNames entries + ZERO test stderr assertions; retirement-citation comments MAY remain per D-3.4b-c2-4.
- **OOT-4** → `design.md` verifiable-invariant amended: `SEC(".maps")` count = **15** not 16 (template-without-SEC mirror of existing `xdpmf_allowlist_inner` / `xdpmf_cidr_inner` precedents; pseudocode lines 9849-9855 yield per "invariants block wins, prose loses").
- **OOT-5** → `tests/fixtures/config_per_rule_counters.yaml` header comment block refreshed for post-§5.34 schema cycle 3 contract (id=17 drop-rule MAC NOW in inner-allowlist; rule_counters[17] NOW bumps; XDP_DROP via action_table dispatch).

No `defer` or `promote-to-rework` OOTs. Verdict stays `pass` round-1.
