# Task brief — MVP-3.4i: compound exporter scrape-path perf (4 byte/set-equivalent patches) (brownfield, performance)

## Goal

Apply 4 micro-optimizations to the `xdpmf-exporter` `/metrics` scrape path, each preserving the emitted output's line-SET (and for 3 of 4, the exact byte-STREAM). Pure CPU/allocation reduction: ~1.3 ms/scrape on a 50-iface fleet (~40% of the compound win identified by /mint-review's performance dimension). This is a **behavior-preservation slice** — the contract is "output line-set unchanged", the perf is the motivation.

Closes 4 of 5 /mint-review performance findings (Major-1 + Med-1/2/3). The 5th (Med-4 fd-cache) is EXPLICITLY DEFERRED to a separate slice — it introduces cross-scrape state + an apply/detach race window whose invalidation strategy is a genuine multi-axis design question (out of scope here).

**Source of truth**: `/home/user/agent-teams-review/runs/mint-review-mint-l2-mac-filter-202605271147/raw/performance-reviewer.md` (Major findings §1 + Medium findings §1/2/3) + `report.md` compound chain (line 131-133).

## Context: prior work

- All prior briefs: archived in `mint/task-brief-*.md` (29 prior cycles)
- Existing design: `mint/design.md` §5.39 (MVP-3.4h exporter bind WARN, commit `db7e00e`)
- Architecture doc: `mint/architecture-v2.md` — no row for this slice (perf hardening from /mint-review; treat as §5.40 brownfield amendment)
- Phase A code-grep verification: brief-author ran exhaustive Phase 2 greps (see footer); confirmed patch-coupling for patches 1 + 3, and a byte-equivalence nuance for patch 4 (see below)
- PI continuity: PI-7-3.4h-cpp 9th + loader-hpp + mac-filter-h ZERO-diff streaks active. logger.hpp was carve-out-EDITed in §5.39 (PI-3.4h-K); this slice does NOT touch logger.hpp. All 4 edited files are exporter `.cpp` — none are PI-7 fence-path headers.

## Workflow rules (brownfield)

- **Architect**: read §5.29 (exporter origin; stats_reader/http/prom_format module roles) + §5.32 (PI-3.5-1 text-mode byte-equivalence; the /metrics format contract) + §5.31/§5.34 (rule_counters_reader + rule_match label emission) + §6.5 invariants summary. EDIT design.md in place; append §5.40. Phase A code-grep MUST independently re-verify the patch-coupling findings (patch 1 signature change; patch 3 multi-callsite; patch 4 ordering nuance).
- **Impl**: FileList interpretation per brownfield mode — strict in-scope EDIT on 4 exporter `.cpp` files; NO touch to UNCHANGED-BUT-AFFECTED (PI-7 fence paths, logger.hpp, headers unless a signature change forces a `.hpp` edit — see Q1).
- **Tester**: likely NO new ctest. Existing T_EXPORTER_METRICS_FORMAT + T_EXPORTER_VALUES_MATCH_STATS + T_EXPORTER_RULE_LABELS are the byte/set-equivalence oracle (all grep-per-line → order-insensitive). Tester's role is largely "confirm the 3 oracle tests + full suite stay green". Architect MAY spec a small determinism-assert for Patch 4 if desired.
- **Reviewer**: 5-point brownfield framework. Special attention items: (a) PI-3.4i-A byte-STREAM-identical for patches 1/2/3 (curl /metrics pre/post → identical bytes modulo counter values); (b) PI-3.4i-B line-SET-identical for patch 4 (sorted order acceptable; grep oracle green); (c) patch 1 signature change correctness (buffer reuse across keys+ifaces — no aliasing/stale-data bug); (d) patch 3 Content-Length correctness on the two-step path + 6 small error paths byte-identical; (e) no PI-7 fence-path edits.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-3.4i-1: scope = patches 1-4; Med-4 fd-cache DEFERRED → **CONFIRMED**

In-scope: Major-1 (PERCPU buf hoist) + Med-1 (format_to in-place) + Med-2 (build_response two-step) + Med-3 (sorted-vector). Med-4 (per-scrape bpf_obj_get fd cache) is DEFERRED — it introduces cross-scrape state + an apply/detach race window; the invalidation strategy (TTL vs mtime-stat vs inotify vs per-scrape revalidate) is multi-axis and likely warrants /mint-hld. NEW OOS fence; mvp-3.4j candidate.

### HG-3.4i-2: byte-equivalence PI split → **PI-3.4i-A (stream) + PI-3.4i-B (set)**

Phase 2 grep found patch 4 (sorted-vector) is NOT byte-stream-identical: `prom_format.cpp` currently iterates `unordered_map` in unspecified order, so the /metrics rule_match line order is ALREADY non-deterministic. Sorted-vector makes it deterministic but changes the byte stream vs hash-order.
- **PI-3.4i-A** (patches 1, 2, 3): byte-STREAM-identical /metrics output (modulo live counter values). format_to writes identical bytes; two-step write produces identical wire bytes (TCP concatenation); buf hoist is invisible to output.
- **PI-3.4i-B** (patch 4): line-SET-identical (every rule_match line still emitted; order may change to deterministic-sorted). Prometheus is order-insensitive; the 3 oracle tests grep per-line so they stay green. Deterministic output is a minor bonus.

### HG-3.4i-3: NO new ctest → **CONFIRMED (existing oracle suffices)**

T_EXPORTER_METRICS_FORMAT (per-line `grep -qE`/`grep -cE`) + T_EXPORTER_VALUES_MATCH_STATS (per-line `grep -E`) + T_EXPORTER_RULE_LABELS are the byte/set-equivalence oracle. They pass under both stream-identical (1/2/3) and set-identical (4) changes. Architect MAY add a sorted-determinism assert for patch 4 but it's not required (the grep oracle is sufficient; perf numbers are NOT independently benchmarkable per report's residual_uncertainty note — do NOT add a flaky timing-based ctest).

### HG-3.4i-4: NO VERSION bump → **CONFIRMED**

Pure internal perf; no operator-observable surface change (output line-set unchanged; same metrics, same labels, same values).

### HG-3.4i-5: PI-7 fences → **logger.hpp NOT touched; cpp/loader-hpp/mac-filter-h extensions continue**

All 4 edited files are exporter `.cpp`. No PI-7 fence-path header is touched (UNLESS Q1's signature change forces a `.hpp` edit — see Q1; `percpu_sum_u64` is a static function in each reader's `.cpp`, NOT exposed via a header, so the signature change stays `.cpp`-local). config.hpp + loader.hpp + mac_filter.h ZERO-diff streaks extend. logger.hpp untouched (its §5.39 PI-3.4h-K carve-out re-baseline restarts cleanly; architect adjudicates whether PI-7-3.4i-hpp counts as restart-at-1 or continuation).

## Open mechanism questions (architect decides; document in §5.40)

### Q1: Patch 1 — `percpu_sum_u64` signature change to accept caller-provided buffer

- **A1**: `percpu_sum_u64(fd, key, num_cpus, std::span<std::uint8_t> buf)` — caller allocates ONE buffer above the per-iface loop, resize(num_cpus*8) once, passes span. C++23 idiomatic.
- **A2**: raw `std::uint8_t* buf` + size param (C-style; matches libbpf call shape).
- **Recommendation**: **A1** (`std::span` — bounds-carrying, idiomatic, zero-overhead). Both readers' `percpu_sum_u64` is a static anon-namespace function in the `.cpp` (Phase 2 confirmed: NOT declared in any `.hpp`), so the signature change stays `.cpp`-local → no header edit, no PI-7 ripple. Architect picks span-vs-pointer.

### Q2: Patch 3 — `build_response` two-step refactor shape

- **A1**: add `build_headers(status, status_text, content_type, body_size)` helper; the /metrics 200 path (http.cpp:237) does `write_all(headers) + write_all(body)` directly; the 6 small error paths (400/405/404/ok at :180,188,200,250,254) keep single `build_response`. Minimal blast radius.
- **A2**: change `build_response` to always-two-step internally (all 7 paths).
- **Recommendation**: **A1** — only the hot /metrics path (large body) needs the optimization; the 6 error responses have tiny bodies where the copy is negligible AND keeping them on the existing single-write path guarantees their wire bytes are byte-identical (no regression risk). Content-Length computed from body.size() BEFORE writing headers (load-bearing — the header must be correct or the HTTP response breaks).

### Q3: Patch 4 — sorted-vector shape

- Sorted `std::vector<std::pair<std::uint32_t, std::string_view>>` populated from the per-iface RuleMeta list, then linear scan (≤64 entries; report says fits cache-line ~30 ns vs ~50 ns) OR binary search. Architect picks linear-vs-binary (linear is simpler + report-recommended at this cardinality). Output line order becomes sorted-by-rule_id (deterministic) — acceptable per PI-3.4i-B.

## Scope (cycle MVP-3.4i — concrete items)

### Item P-1 — Patch 1: PERCPU buf alloc hoist (Major-1)

**Where**: `src/exporter/stats_reader.cpp` (`percpu_sum_u64` @:84-91 + per-key call loop @:230) + `src/exporter/rule_counters_reader.cpp` (parallel `percpu_sum_u64` @:89-94 + its call loop)
Diff: move the `std::vector<std::uint8_t>` alloc OUT of `percpu_sum_u64` to ABOVE the per-iface read loop in each reader's `read_all*` function; resize(num_cpus*8) once; pass buffer (span per Q1) into `percpu_sum_u64`. Drop the per-call zero-init `std::uint8_t{0}` (unnecessary — `bpf_map_lookup_elem` overwrites fully; this is a documented micro-win in the finding). ~500 µs/scrape on 50-iface host. Net LOC: roughly neutral (~+5 signature/hoist, ~-3 alloc).

### Item P-2 — Patch 2: `std::format_to` in-place (Med-1)

**Where**: `src/exporter/prom_format.cpp` (`out.append(std::format(...))` @:71-76, :110-112, :117-119)
Diff: replace each `out.append(std::format(FMT, ...))` with `std::format_to(std::back_inserter(out), FMT, ...)` (C++23). Eliminates the temp-string heap alloc + copy + free per emitted line. Byte-identical output (PI-3.4i-A). ~700 µs/scrape + ~3400 fewer allocs. Net LOC: ~neutral.

### Item P-3 — Patch 3: `build_response` two-step write for /metrics path (Med-2)

**Where**: `src/exporter/http.cpp` (`build_response` @:159-172 + /metrics 200 call-site @:237)
Diff per Q2.A1: add `build_headers(...)` helper; /metrics path writes headers + body via 2 `write_all` calls (no full-body copy into a format result); Content-Length computed from body.size() pre-write. 6 small error paths unchanged. ~45 µs + 250 KiB peak heap saved on max-fleet. Costs +1 write(2) syscall (~3 µs — net win). Net LOC: ~+5-8.

### Item P-4 — Patch 4: sorted-vector vs unordered_map (Med-3)

**Where**: `src/exporter/prom_format.cpp` (`std::unordered_map<std::uint32_t, std::string_view> action_for_rule` @:94 + its populate loop + the 2 iteration loops @:107 + the `.contains()` check @ orphan loop)
Diff per Q3: replace `unordered_map` with sorted `std::vector<std::pair<std::uint32_t, std::string_view>>`; populate + sort once per iface; replace `.find()`/`.contains()`/range-for with vector scan. Drop `#include <unordered_map>` (verify no other user in prom_format.cpp). Output line order becomes deterministic-sorted (PI-3.4i-B — line-set-identical, grep oracle green). ~60 µs/scrape + ~500 fewer small allocs. Net LOC: ~neutral.

### NO new ctest, NO new files

Existing 3 oracle tests are the byte/set-equivalence verification. Tester confirms full suite (68 ctests) stays green.

## Out of scope (explicit)

- **Med-4 fd cache across scrapes** (`stats_reader.cpp:193,232` + `rule_counters_reader.cpp:155-178,210`) — ~1.4 ms/scrape, BUT introduces cross-scrape state + apply/detach race window; invalidation strategy is multi-axis (TTL vs mtime-stat vs inotify vs per-scrape revalidate). DEFERRED to mvp-3.4j; likely /mint-hld first. NEW FENCE.
- **Low findings** (BPF batch API for apply ops; action_table identity-map elision; O(N²) dedup in extract_pass_macs) — separate slices; the first two touch the datapath/loader hot paths (higher blast radius). NEW FENCES.
- **Benchmark/timing ctest** — perf numbers are algorithmic estimates, NOT independently benchmarked (report residual_uncertainty). A timing-based ctest would be flaky under -j4 contention (see guard #12 history). NO perf-assertion test. NEW FENCE.
- **VERSION bump** — pure internal perf. NEW FENCE.
- **Changing /metrics output semantics** (new labels, new metrics, value changes) — strictly forbidden; this is preservation-only. NEW FENCE.
- **KC-1 / KC-2 mitigation halves, Theme C/D remnants, CI/CD** — separate slices.

## Definition of done

- §5.40 amendment in `mint/design.md` (estimated ~150-250 LOC: scope + HG/Q resolutions + D-decisions + FileList table + PI-3.4i-A/B split + OOS block + Phase A grep notes)
- PI continuity:
  - PI-3.4i-A NEW (byte-STREAM-identical /metrics for patches 1/2/3)
  - PI-3.4i-B NEW (line-SET-identical for patch 4; sorted order acceptable)
  - PI-7-3.4i-cpp (config.hpp) + loader-hpp + mac-filter-h ZERO-diff continue; logger.hpp untouched
  - PI-3.5-1 text-mode byte-equivalence preserved (the /metrics format contract)
  - PI-32-3.4b sidecar-never-throws preserved (no sidecar changes)
- ctest baseline: 68 → 68 (NO new ctests; reviewer confirms zero regressions on 3 oracle tests + full suite)
- mint/review.md round-1 verdict = pass
- One git commit per phase boundary

## Dependencies

- C++23 stdlib (`<span>` for Q1.A1; `std::format_to` + `std::back_inserter` for P-2; already on C++23)
- No CMake changes
- No kernel/platform deps
- No external BPF/libbpf changes (same bpf_map_lookup_elem calls; just buffer lifetime moves)

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       []
  tester:     []
  reviewer:   []
```

---

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])

- **Multi-axis design space?** No (for the 4 in-scope patches). Each is a mechanical optimization with a clear answer from the report. The ONE multi-axis item (Med-4 fd-cache invalidation) is explicitly DEFERRED out.
- **Brief-author uncertain across ≥2 axes?** No. Patch 4's ordering nuance resolved via grep-oracle verification (tests are order-insensitive).
- **Expensive to undo?** No. Pure refactor; rollback = revert single commit. Byte/set-equivalence makes correctness verifiable.
- **≥3 distinct viable options?** No (per patch). Each patch's mechanism is report-prescribed; the Q-decisions are minor shape choices (span vs ptr, helper-split vs inline, linear vs binary).
- **Mechanical-answer check**: ✓ yes — 4 report-prescribed optimizations + byte/set-equivalence oracle.
- **Has /mint-hld been run?** No — not needed for 1-4. Med-4 may want it when scoped.
- **Brief-author overconfidence flag**: ⚠ brief invocation claimed "all 4 byte-identical" — Phase 2 corrected (Patch 4 is line-set-identical, order may change). Also flagged patch-1 signature-change + patch-3 multi-callsite coupling. Architect repeats Phase 2 greps per guard #5.

**Verdict**: mechanical perf slice; `/mint-hld` overkill for 1-4 (Med-4 correctly split out). Proceed with `/mint-dev`.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief-author already ran these greps per Phase 2 — architect re-verifies + extends:

1. **Patch 1 signature scope** — confirm `percpu_sum_u64` is static/anon-namespace in BOTH readers' `.cpp` (NOT declared in any `.hpp`):
   - `grep -rn 'percpu_sum_u64' src/exporter/` — expect defs + call-sites ONLY in stats_reader.cpp + rule_counters_reader.cpp; ZERO hits in any `.hpp`. Confirms signature change stays `.cpp`-local (no PI-7 header ripple).
2. **Patch 3 callsite enumeration** — `grep -n 'build_response' src/exporter/http.cpp` — expect 1 def + 7 call-sites (:180,188,200,237,250,254 + the def @:159). Confirm only the :237 /metrics path has a large body; the other 6 are small error responses that stay single-write.
3. **Patch 4 ordering + include** — `grep -n 'unordered_map\|action_for_rule\|\.contains(\|\.find(' src/exporter/prom_format.cpp` — enumerate all uses; confirm dropping `#include <unordered_map>` is safe (no other user). Verify the iteration order is observable in output (it is — feeds rule_match line emission) so sorted-vector is line-set-equivalent NOT byte-stream (PI-3.4i-B).
4. **Byte/set-equivalence oracle confirm** — `grep -nE 'grep -qE|grep -cE|grep -E' tests/T_EXPORTER_METRICS_FORMAT.sh tests/T_EXPORTER_VALUES_MATCH_STATS.sh tests/T_EXPORTER_RULE_LABELS.sh` — confirm all assertions are per-line grep (order-insensitive). This is what lets patch 4 (order change) stay green.
5. **PI-7 fence smoke (pre-commit)** — `git diff db7e00e..HEAD -- src/common/logger.hpp src/lib/config.hpp src/lib/loader.hpp src/common/mac_filter.h` MUST be empty (these 4 exporter .cpp edits touch none of them).
6. **No /metrics semantic change** — diff the format strings: the FMT literals in prom_format.cpp + build_response must be byte-identical pre/post (only the EMISSION MECHANISM changes — append→format_to, map→vector — NOT the format strings themselves).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep)**: ✓ applies; architect independently re-verifies the 3 patch-coupling findings (patch-1 signature, patch-3 multi-callsite, patch-4 ordering) + the order-insensitive oracle. Phase 2 caught the "byte-identical" imprecision on patch 4 — guard discipline pays off.
- **Guards #8 / #10 / #11 / #13 / #19**: N/A — no logger emit changes, no kEventNames catalog, no VERSION bump, no fixture, no logger text-mode prose.
- **Guard #12 (RESOURCE_LOCK)**: N/A — no new ctest (existing grep oracle is the verification; no timing-based perf test per OOS).
- **Guards #14-21**: N/A — no map-shape/atomic-swap/bilateral/host-vs-netns/rule-of-three/IO-model concerns.

**Operative-semantic discipline reminder (Phase 4.4)**: counts in this brief (~1.3 ms/scrape; ~500/700/45/60 µs per patch; net LOC ~neutral-to-+15) are SHOULD-level orientation, not contracts — AND the perf numbers are algorithmic estimates, NOT benchmarked. The HARD contract is PI-3.4i-A (byte-stream-identical 1/2/3) + PI-3.4i-B (line-set-identical 4) verified by the 3 grep oracle tests. Impl deviations on patch shape (span vs ptr, linear vs binary scan, helper-split granularity) are `inline-merge` per design's resolution rule. Architect SHOULD include the prose-vs-invariants conflict resolution rule in §5.40 per §5.37/§5.38/§5.39 precedent.
