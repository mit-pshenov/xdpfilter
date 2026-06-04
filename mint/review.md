# Review — MVP-4.31 / B38 simplify-harvest (mint triangulation)

## Verdict
`pass` (round 1, 0 findings, 0 OOT)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — (NO new test per TestStrategy; existing oracle suite is the control — design-sanctioned) |
| 3. Code ↔ Tests | 0 | — (104/106; 2 pre-existing env-fails by name) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

All 4 subtractions land clean, ZERO behavior change. Footprint = exactly **1 NEW + 4 EDITED + design.md** (`git diff --stat b53f534`).

## The 5 load-bearing questions — all answered

**1. B4 dead-code** — `read_all_attached(sv)` def + decl DELETED; 3 stale doc-comments refreshed to `_with_acc`. `grep -rn read_all_attached src/ tests/ | grep -v _with_acc` → only a tombstone comment, ZERO call sites. Clean link = oracle.

**2. B2 + C1 extraction** — NEW `src/exporter/percpu_read.hpp` (ns `xdpmf::exporter::detail`, 3 `inline`/`constexpr` helpers, ODR-safe); bodies byte-identical vs `b53f534` (only sanctioned deltas: `inline` + `percpu_sum_u64` param `stats_fd`→`map_fd`). Both readers `#include` it; 6 old local copies GONE. PI-31 holds incl new header (no `bpf_map_update/delete/pin/link/prog_load` in `src/exporter/`; only `bpf_map_lookup_elem`).

**3. C1 §5.31 reversal documented** — `rule_counters_reader.cpp` carries the reversal note citing §5.31 + D-mvp-4.31-HG2 (equivalence-by-construction); old "Deliberately duplicated … §5.31" comment GONE. Reversed-with-note, not silent-deleted (B37 precedent).

**4. B5 bitvec template-merge** — `loader.cpp` single `template<class Prefix, class CloseFn> populate_bitvec_inner_slot(...)`; **guard #23 intact** — `close_prefixes`/`close_prefixes6` remain two separate named defs (bodies UNTOUCHED), passed as SEPARATE args; labels byte-preserved; 4 call-sites correct; `BPF_ANY` map writes identical. Reviewer re-ran ORACLE_AGREEMENT + T_ANDV6_PREFIX_CLOSURE_OVERLAP — all green (verdict-identity = control).

**5. xdp insn + fences** — reviewer re-measured: xdp = **3437** (unchanged). PI-7 `loader.hpp`/`config.hpp` ∅; `src/bpf` ∅; `CMakeLists.txt`/`VERSION`/`tests` ∅. VERSION 0.16.0 (no bump).

## Test execution
- `/tmp/mint-review-tests-1780607736.log` + `mint/test-run.log`.
- Targeted 17/17 PASS (full ORACLE_AGREEMENT family + prefix-closure canary + exporter suite). Full ctest 104/106 — the 2 FAILs are the documented pre-existing env-fails BY NAME (#48 T_EXPORTER_EXITS_6_ALL_IFACES_EACCES, #63 T_LOG_JSON_EXPORTER_EVENTS — sudo-unpriv exporter OOM-Killed env; identical in the pre-slice baseline). NOT a regression. 2 skips unchanged.

## Net result
−71 LOC (+170 new header / −241 edited). 4 pure subtractions, all behavior-preserving. The `/mint-simplify` code harvest (B2/B4/B5/C1) shipped clean.

## Out-of-triangulation findings
None.

All §6.5 PI-mvp-4.31-* rows hold; no unnegotiated drift; no OOS creep. Ship it.
