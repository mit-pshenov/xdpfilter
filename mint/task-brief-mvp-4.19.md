# Task brief — MVP-4.19 / test-hardening: sanitize the 9-axis lowering + datapath (brownfield, TEST-ONLY)

## Goal
Enrich `tests/T_SANITIZER_BUILD.sh` so the ASAN/UBSAN-built binary exercises the **9-axis** lowering + datapath, not just one axis (BACKLOG **B22**). The test currently applies a single-rule fixture (`config_valid_cidr.yaml`, src_cidr `10.0.0.0/8` → STAT_PASS_CIDR) + one matched inject — so under the sanitizer ONLY the src-CIDR lowering path is covered. The net-new / highest-risk lowering added since has NEVER been sanitized: `close_prefixes6` (`__int128` 128-bit prefix closure, S4), the `populate_hash_inner_slot<Key>` + `aggregate_axis<Key>` templates (proto/port/vlan/mac/ethertype, B28), `write_wildcard_slots` (all axes), the IPv6 ext-header walk (S6, bounded `#pragma unroll` with a variable per-hop advance — the sharpest UB-catch target), and the per-axis bounds reads.

**PURE test enrichment — NO product-code change** (`git diff -- src/` MUST be empty). The sanitizer just drives more of the existing datapath. Enrich the EXISTING test in-place — do NOT add a second `XDPMF_SANITIZERS=ON` build (that doubles the slow ~64 MB `/tmp` ASAN rebuild). Keep vectors minimal (each apply+inject adds wall-clock under the already-slow rebuild).

## Context: prior work
- Prior briefs archived in `mint/task-brief-*.md` (latest: `task-brief-mvp-4.18.md` = B29, just shipped `0acca78`).
- Match model = 9 axes (dst/src/proto/port/vlan/mac/dst6/src6/ethertype) across 3 family arms; IPv6 with ext-header L4 depth. Clean tree, main == origin/main.
- Phase-2 grep verification (run — see footer): the current fixture is `config_valid_cidr.yaml` (NOT `and6` as the backlog note guessed); the 3 richer fixtures (and6/andv6/andeth) + both injectors (inject_ipv4, inject_l6 with `--ext`) all exist; T_SANITIZER_BUILD carries `RESOURCE_LOCK build_cpu`.
- PI continuity: loader.hpp PI-7 trivially CONTINUES (untouched); no product PI moves (test-only).

## Workflow rules (brownfield)
- **Architect**: read design.md §5.43/§5.44/§5.45/§5.47 (axis lowering), §5.53 (close_prefixes6 `__int128`), §5.55 (S6 ext-walk), §5.50 (B28 templates), §6.8 (the T_SANITIZER_BUILD design). EDIT design.md in place; append §5.59 (MVP-4.19). Decide Q1 (fixture/vector matrix) — you own realizability (which fixture + which inject vectors actually drive `close_prefixes6`/`write_wildcard_slots`/the ext-walk; how the post-inject stats read must change vs the current 4-col `read_stats_with_cidr`).
- **Impl**: FileList DIFF — Edit `tests/T_SANITIZER_BUILD.sh` (+ a fixture if the architect needs a new one, though the 3 existing ones likely suffice). `git diff -- src/` MUST stay EMPTY. NO product-code edit.
- **Tester**: this slice IS test work — but per the mint split, the ARCHITECT specs the vectors in §5.59 and the IMPL writes them into T_SANITIZER_BUILD.sh; the tester VERIFIES the enriched sanitizer test runs clean (no ASAN/UBSAN diag) + the full suite stays green. No NEW ctest expected (enrich in place); if the architect splits a vector into its own assertion, ctest count may tick — flag it.
- **Reviewer**: 5-point brownfield; **special attention**: (a) `git diff -- src/` EMPTY (test-only); (b) the enriched test ACTUALLY exercises the claimed net-new paths (the chosen fixture's axes map to `close_prefixes6`/`populate_hash_inner_slot`/`write_wildcard_slots`/ext-walk — not just a different single axis); (c) the sanitizer assertion (`grep -E 'AddressSanitizer|UndefinedBehavior'` → must be absent) still fires; (d) the post-inject stats read matches the chosen fixture's verdict slot; (e) build_cpu RESOURCE_LOCK retained (guard #12).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.19-1: enrich in-place vs new test → **enrich `T_SANITIZER_BUILD.sh` in-place**
Do NOT add a second ASAN-build test (doubles the slow `/tmp` rebuild + disk). The single existing build, exercised by more vectors, gets the coverage. Architect MAY add a fixture file but NOT a second `cmake -DXDPMF_SANITIZERS=ON` build.

### HG-mvp-4.19-2: vector count → **3 (full-match, wildcard, NOMATCH)**
Minimal set that hits the three datapath regions: the populated AND path (full-match), `write_wildcard_slots` / the wildcard accumulator (a rule omitting some axes + a frame that matches via wildcard), and the defaults path (NOMATCH). Architect MAY trim to 2 or add 1 if a specific net-new path needs a dedicated vector (e.g. an `--ext` frame to drive the ext-walk).

## Open mechanism questions (architect decides; document in §5.59)

### Q1: which fixture + vector matrix maximizes sanitized coverage of the net-new lowering, in the fewest vectors?
- **A1 — andv6 primary**: `config_valid_andv6.yaml` drives `close_prefixes6` (`__int128`, the highest-risk net-new code) + the v6 LPM populate + proto/port/vlan; inject via `inject_l6.py`. Best single-fixture coverage of the v6 closure math.
- **A2 — andeth primary**: `config_valid_andeth.yaml` drives the ethertype HASH + the non-IP `else` arm + mac; inject via `inject_l6.py`/raw eth. Best for the S5 non-IP path.
- **A3 — sequence**: apply andv6 (closure + LPM) THEN andeth (ethertype + non-IP), 1-2 vectors each — broadest coverage, more wall-clock. Optionally an `inject_l6.py --ext` frame to sanitize the S6 ext-walk (a bounded loop with a data-dependent advance — genuine UB-catch value).
- **Recommendation**: **A1 (andv6) + one `--ext` vector** — concentrates the sanitizer on the two genuinely-net-new sharp edges (the `__int128` closure and the ext-header walk) for the least wall-clock; the v4 HASH templates (proto/vlan/mac) are lower-risk (exact-match, no pointer math) and already partially exercised. Architect overrides if a fuller sweep is cheap.

## Scope (concrete items — FileList DIFF)

### B22-1 — enrich the sanitizer exercise
**Where**: `tests/T_SANITIZER_BUILD.sh` (EDIT)
- Replace the single `config_valid_cidr.yaml` apply + single `10.0.0.5` inject with the architect's chosen fixture(s) + the 3-vector matrix (HG-2). Update the post-inject stats read to the verdict slot the chosen fixture produces (the current `read_stats_with_cidr` 4-col helper assumes a CIDR-axis PASS; a different fixture may land on STAT_PASS or STAT_DROP_DENY — architect/impl adjust the assertion accordingly).
- The header-comment "Trigger" block (steps 3-7) must be updated to describe the enriched exercise (retirement-discipline on the now-stale "single src_cidr" prose).
- Keep: the `XDPMF_SANITIZERS=ON` configure+build, the `grep -E 'AddressSanitizer|UndefinedBehavior'` clean-run assertion, the build_cpu RESOURCE_LOCK, the mktemp `/tmp` ASAN dir + its trap cleanup (the leak-on-kill is a session-fragility note, not this slice's concern).

### B22-2 (CONDITIONAL) — new fixture only if needed
**Where**: `tests/fixtures/` (NEW, only if the architect determines the 3 existing fixtures can't drive a required net-new path)
- Default expectation: the existing and6/andv6/andeth suffice → NO new fixture. Flag if a new one is genuinely required (e.g. a wildcard-specific layout).

## Out of scope (explicit)
- ANY product-code change (`src/` byte-untouched). ANY new axis / schema / VERSION change.
- A second ASAN build / a separate sanitizer ctest (HG-1).
- B26 (pass_cidr rename — deferred to a stat-enum slice), B30 (slot/id decouple — designed slice), B23 (5.15 verifier-load — infra-gated), B27 (security — held), B15 (.pyc/gitignore hygiene).
- The T_SANITIZER_BUILD `/tmp` ASAN-temp leak-on-abnormal-kill (a session-hygiene artifact, not a product/test defect — the trap handles clean exits).

## Definition of done
- §5.59 (MVP-4.19) amendment in design.md (the chosen fixture/vector matrix + rationale).
- `git diff -- src/` EMPTY (test-only); loader.hpp PI-7 trivially continues.
- The enriched T_SANITIZER_BUILD runs CLEAN under ASAN/UBSAN (no diag) AND drives the chosen net-new paths.
- Full ctest stays green (96/96, or +N if the architect splits vectors into assertions — flagged).
- NO schema/VERSION change (stays 0.15.0 / schema 2 / 9 axes).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang-19/C++23, `XDPMF_SANITIZERS=ON` (ASAN+UBSAN) toolchain (existing). The ASAN rebuild is slow (~minutes) + mktemps a ~64 MB `/tmp` dir.
- Runtime: veth + bpffs + sudo (existing fixture); python3 scapy for inject_l6 `--ext`.

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

## Pre-brief sanity check (per mint-hld-scope-discipline)
**MECHANICAL-ish.** One design axis: the fixture/vector selection (Q1), which is an architect realizability call (which inject actually drives `close_prefixes6` / the ext-walk + how the stats read changes), NOT a multi-axis design fork or expensive-to-undo decision (it's a test; trivially revertable). No PO-tier value question (PO-filter: no external value to name — it's pure engineering coverage). **No /mint-hld, no spike.** Single-architect. Light path per [[feedback_band_by_default]].

## Notes for architect Phase A code-grep discipline
Re-run (guard #5):
- `grep -nE 'config_valid_cidr|read_stats_with_cidr|inject_ipv4|SANITIZERS' tests/T_SANITIZER_BUILD.sh` — confirm the current single-axis exercise + the stats-read helper that must change.
- `grep -rn 'close_prefixes6\|populate_hash_inner_slot\|write_wildcard_slots\|MAX_EXT_HOPS' src/bpf/ src/lib/loader.cpp` — confirm the net-new lowering you intend the enriched vectors to exercise (so the brief's coverage claim is real, not assumed).
- Inspect `tests/fixtures/config_valid_{andv6,andeth,and6}.yaml` + `tests/inject/inject_l6.py --ext` to confirm a vector that lands on the intended path.
- Verify which STAT_* slot each candidate fixture's full-match produces (STAT_PASS vs STAT_PASS_CIDR vs STAT_DROP_DENY) so the post-inject assertion is correct.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #12 (RESOURCE_LOCK for shared host state)** — the enriched test still touches veth + does a full compile; the existing `build_cpu` + xdp_fixture locks MUST be retained (do not drop them when editing). If a NEW ctest is split out, it needs the same locks.
- **Guard #5 (Phase A grep discipline)** — architect re-runs the coverage greps above to prove the chosen vectors actually reach the net-new paths.
- **Operative-semantic discipline** — "3 vectors" / "9-axis" / the net-new-path list are SHOULD-level orientation; the architect's realizability call on fixture/vector count is authoritative, deviations preserving coverage intent are `inline-merge`.
- **Guard #11 (VERSION-bump propagation)** — N/A (no bump). **Guard #13 (retired-string ripple)** — minor: the stale "single src_cidr" header-comment prose in T_SANITIZER_BUILD is retired/updated in-place (no fixture/test references it elsewhere — confirm).
