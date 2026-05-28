# Review — MVP-3.4i compound exporter scrape-path perf (mint triangulation, brownfield 5-point)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | NO-NEGATION-CONTROL N/A (preservation slice; contract = output-preservation, verified by 3 grep oracles + T_NEGATION_CONTROL #7) |
| 3. Code ↔ Tests | 0 | 68/68 green; no UNEXERCISED-EXPORT |
| 4. Out-of-Scope Drift | 0 | Med-4 fd-cache untouched; no /metrics semantic change; no VERSION |
| 5. Behaviour preserved (brownfield) | 0 | PI-3.4i-A/B verified; PI-7-3.4i-cpp 10th |
| OOT (does not affect verdict) | 1 | inline-merge × 1 |

## Detailed triangulation

### Point 1 — Spec ↔ Code (D-3.4i-1..4 + Q1/Q2/Q3)

- **D-3.4i-1** (buffer hoist + `std::span` + drop zero-init): `stats_reader.cpp:193-195` + `:244-245` hoist `percpu_buf` once above per-iface loop, sized `round_up_8(8)*num_cpus`, pass `std::span{percpu_buf}`. `percpu_sum_u64` (:92-113) overwrites FULL span on `rc==0` (bpf_map_lookup_elem @:100) + returns 0 WITHOUT reading on `rc<0` (:101-103) → no stale-data leak across reuse. Identical in `rule_counters_reader.cpp:98-117` + :150-152 + :223-224. **T_EXPORTER_VALUES_MATCH_STATS #38 GREEN** = runtime correctness oracle ✓
- **D-3.4i-2** (format_to in-place): `prom_format.cpp:76,132,144` — 3 `std::format_to(std::back_inserter(out),…)` sites; FMT literals byte-identical; HELP/TYPE append-literal lines UNCHANGED ✓
- **D-3.4i-3** (two-step write + build_headers): `http.cpp:165-177` new `build_headers`; /metrics path :264-267 `write_all(build_headers(...,body.size()))` then `write_all(body)`; Content-Length pre-write @:266. `build_response` :179-193 DRY-delegates to build_headers + .append(body) — header literal minus trailing `{}` body placeholder → wire bytes byte-identical (verified vs db7e00e:http.cpp). 5 small error/healthz paths keep single-write (:201,209,221,278,282). 6 build_response call-sites total (not 7) ✓
- **D-3.4i-4** (sorted-vector FIRST-WINS dedup, linear scan): `prom_format.cpp:109` vector replaces unordered_map; populate :112-119 skips already-present rule_id via `std::any_of` :113-116 = first-wins (matches `unordered_map::emplace`, NOT overwrite); `std::sort` by `.first` :121-122; first emission loop iterates sorted vector :128; orphan membership :140-142 linear any_of. `rule_meta_by_iface.find` (std::map parameter) NOT touched. **T_EXPORTER_RULE_LABELS #51 GREEN** = line-SET oracle ✓
- **D-3.4i-PI7-LOGGER**: logger.hpp untouched ✓
- **Interfaces**: `percpu_sum_u64(int,uint32_t,int,std::span<uint8_t>)` identical both readers; `build_headers(int,sv,sv,size_t)->string` NEW anon-ns; build_response sig retained; emit_metrics/read_*/run/write_all UNCHANGED ✓

### Point 2 — Spec ↔ Tests

No new ctest per HG-3.4i-3. T-ORACLE-1/2/3 (T_EXPORTER_VALUES_MATCH_STATS / T_EXPORTER_METRICS_FORMAT #37 / T_EXPORTER_RULE_LABELS) all GREEN, assert on /metrics OUTPUT (stated outcome) not code-shape → no SPEC-UNTESTED, no CIRCULAR-TEST. NO-NEGATION-CONTROL N/A (preservation slice); suite carries T_NEGATION_CONTROL #7 + oracle-internal negations (post-sidecar-delete action="unknown"; empty-scrape T_EXPORTER_NO_ATTACHED_IFACE #39) all GREEN ✓

### Point 3 — Code ↔ Tests

Reviewer rebuild (clean, zero warnings) + `sudo ctest -j4` → **100% passed, 0 failed out of 68** (66 PASS + 2 legitimate SKIP: T_DROP_MALFORMED + T_ANSIBLE_PLAYBOOK_SYNTAX) — identical to tester's mint/test-run.log. No UNEXERCISED-EXPORT (build_headers is .cpp-local anon-ns, exercised via /metrics oracle path). Log: `/tmp/mint-review-tests-1779953478.log` (551.59s). ✓

### Point 4 — Out-of-Scope Drift

Med-4 fd-cache NOT touched (bpf_obj_get still per-scrape; grep `static.*fd|fd_cache|cached` → none). No /metrics semantic change (FMT/header literals byte-identical). No VERSION bump (CMakeLists.txt zero-diff). No new ctest. build_response NOT made always-two-step (Q2.A2 fence respected). percpu_sum_u64/list_iface_dirs kept duplicated per-TU. ✓

### Point 5 — Behaviour preserved (brownfield §6.5)

| PI | Result |
|---|---|
| PI-7-3.4i-cpp (10th ZERO-diff) | `git diff db7e00e..HEAD -- src/lib/config.hpp` empty ✓ |
| PI-7-3.4i-loader-hpp | empty ✓ |
| PI-7-3.4i-mac-filter-h | empty ✓ |
| logger.hpp (restart-at-1 post-§5.39) | empty ✓ |
| PI-3.4i-A byte-STREAM (patches 1/2/3) | oracles #37 + #38 green ✓ |
| PI-3.4i-B line-SET (patch 4) | oracle #51 green ✓ |
| PI-31 read-only | no update/delete/pin/attach in src/exporter/; reads bpf_obj_get + bpf_map_lookup_elem only ✓ |
| PI-32 | T_EXPORTER_NO_ATTACHED_IFACE #39 + T_EXPORTER_EXITS_6 #45 green ✓ |
| PI-3.5-1 | T_LOG_TEXT_BYTE_EQUIVALENT #55 green ✓ |
| PI-8/PI-33 (--version 0.10.0) | #37 pins `xdpmf-exporter 0.10.0` ✓ |
| PI-3.5-7 (no new build dep) | <span>/<algorithm>/<iterator>/<utility> all stdlib ✓ |

No REGRESSION (0 fail). No UNRELATED-EDIT (only 4 FileList .cpp + CHANGELOG + design.md + impl-notes.md in impl commit 1c3ef31; task-brief*.md belong to prep commit 0d609e9). ✓

UNCHANGED-BUT-AFFECTED sweep: `git diff db7e00e -- src/exporter/*.hpp main.cpp sidecar_reader.* logger.cpp tests/ CMakeLists.txt` → all empty.

Anti-misdiagnosis catalog stays at 21 (+1 forward-defense note: future prom_format container swaps must re-check observable-iteration-order + insert-dedup-semantics).

## 5 impl-flex notes (impl-notes.md) — all MAY-level inline-merge per D-3.4i-PROSE-VS-INVARIANTS, NOT [SPEC-DRIFT]

1. build_response DRY-delegate — Q2.A1 explicit grant; wire byte-identical ✓
2. `<iterator>`+`<utility>` includes — necessity for design-mandated mechanisms (see OOT-1 below) ✓
3. std::any_of linear dedup+membership — Q3 linear choice ✓
4. MAY-invariant #9 off-by-one — architect inline-fixed design.md (write_all count 7→8 corrected to 6→7; +1 delta always correct; baseline=6, post=7) ✓
5. CHANGELOG ### Performance subsection — impl-flex wording ✓

## Test execution

```
100% tests passed, 0 tests failed out of 68
Total Test time (real) = 551.59 sec
The following tests did not run:
    5 - T_DROP_MALFORMED (Skipped)
   35 - T_ANSIBLE_PLAYBOOK_SYNTAX (Skipped)
```

Reviewer log: `/tmp/mint-review-tests-1779953478.log`. Oracle tests #37 + #38 + #51 all GREEN.

## Findings

NONE (blocking).

## Rework assignments

N/A (verdict = pass).

## Out-of-triangulation findings

### OOT-1: verifiable-invariant #6 include-list under-enumerates the necessity includes
**Location**: `design.md` MAY-invariant #6 vs `prom_format.cpp:10,14` (`#include <iterator>`, `#include <utility>`)
**Disposition**: `inline-merge`
**Rationale**: MAY-invariant #6 enumerated only `+<algorithm> / -<unordered_map> / <map> kept`. Impl additionally adds `<iterator>` (required by design-mandated `std::format_to(std::back_inserter(out),…)` D-3.4i-2) + `<utility>` (required by design-mandated `std::vector<std::pair<…>>` D-3.4i-4). Both stdlib, no new build dep (PI-3.5-7 holds). Exactly the D-3.4i-PROSE-VS-INVARIANTS scenario architect pre-authorized — MAY-hint, reviewer disposition = inline-merge, NOT [UNRELATED-EDIT]. No code/rework needed.

---

**Triangulation summary**: clean round-1 pass. design ↔ code ↔ tests all agree. PI-3.4i-A byte-stream-identical (patches 1/2/3) + PI-3.4i-B line-set-identical (patch 4 sorted-vector + FIRST-WINS dedup) both verified by the 3 grep oracles. D-3.4i-1 buffer-reuse correctness (dropped zero-init safe) + D-3.4i-4 first-wins dedup (load-bearing) both verified at code-level + runtime-oracle level. PI-7-3.4i-cpp = **10th** consecutive config.hpp ZERO-diff. Med-4 fd-cache correctly deferred. 1 OOT inline-merge (include-list completeness).

### Post-review sweep — round 1

OOT-1 disposed as `inline-merge`. Edit rides in Phase 6 final commit.

- **OOT-1** → `mint/design.md` MAY-invariant #6 — appended `[§5.40 EDIT]` note enumerating the 2 necessity includes (`<iterator>` for format_to/back_inserter per D-3.4i-2 + `<utility>` for vector<pair> per D-3.4i-4); both stdlib, PI-3.5-7 unaffected. Prose-completeness only; zero code/behavior impact; 68/68 unchanged.

No `defer` or `promote-to-rework`. Verdict stays `pass` round-1.
