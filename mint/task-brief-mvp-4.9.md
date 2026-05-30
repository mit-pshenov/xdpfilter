# Task brief — MVP-4.9: cheap-wins B18 (port_scan early-break) + B19 (build_cpu RESOURCE_LOCK) (brownfield)

## Goal

A small two-item "cheap-wins" slice the PO chose to clear before the (HLD-gated) IPv6/S8 work. Both are HIGH→cheap backlog items, different files/concerns, PO-bundled:

1. **B18 (datapath perf, behavior-preserving)** — `src/bpf/mac_filter.bpf.c` `port_scan()` runs a fixed 64 `bpf_map_lookup_elem` per L4 packet even with N<64 port rules, because the unused-slot sentinel uses `continue` (full loop walk) instead of `break`. Used slots are dense-at-front (`populate_port_inner_slot` clears all 64 to the `lo>hi` sentinel, then writes `ranges[0..N-1]` contiguously), so the first unused slot marks the end → `continue`→`break` is safe and saves ~`(64-N)` lookups/packet (N=4 → ~−59). The `#pragma unroll` stays 64-block (5.15-verifier-safe straight-line code); only the runtime trip count drops via a forward jump. **Same match result** — guaranteed by the dense-pack invariant.

2. **B19 (test-infra, harness-only)** — `tests/CMakeLists.txt`: `T_BUILD` + `T_SANITIZER_BUILD` are both full compiles that oversubscribe CPU under `ctest -j4`, causing SIGKILL-timeout flakes that cascade (orphan pin → `T_BPFFS_ROOT_SYMLINK`). Add a shared `RESOURCE_LOCK build_cpu` so the two compile-heavy tests serialize against each other. Structural resolution of the recurring `-j4` contention flake (supersedes B16's option-a).

Anchor: `docs/BACKLOG.md` B18 + B19. No `architecture-v2.md` row (debt-paydown). `design.md` gets a housekeeping §-amendment.

## Context: prior work
- All prior briefs: archived in `mint/task-brief-*.md` (this archives `mvp-4.8` → `task-brief-mvp-4.8.md`).
- Most recent slice: MVP-4.8 (B20 apply_request table-driven, commit `0265bcb`). Match-model = 6 axes AND, IPv4-gated.
- Phase A code-grep verification (brief author): confirmed the two `continue` sites in `port_scan` + the dense-pack guarantee in `populate_port_inner_slot`; confirmed `T_BUILD` has NO RESOURCE_LOCK and `T_SANITIZER_BUILD` ALREADY has `RESOURCE_LOCK xdp_fixture`. See Phase 2 report.
- **PI continuity: ALL existing PIs CONTINUE byte-equivalent.** B18 is behavior-preserving (same match result, fewer lookups); B19 touches only the test harness. No PI retired/extended/added (an optional B18 dense-pack-coupling PI is the architect's call).

## Workflow rules (brownfield)
- **Architect**: read `design.md` §5.44 (port axis / `port_scan` / `populate_port_inner_slot` / D-mvp-4.4-* origin) + §6.3-§6.6 (RESOURCE_LOCK / xdp_fixture conventions) + guards #12. EDIT `design.md` in place; append a housekeeping §-amendment documenting (a) the B18 `continue`→`break` + the dense-pack correctness invariant it relies on, (b) the B19 `build_cpu` lock. Confirm the load-bearing B18 precondition: **config validation guarantees every real port range has `lo<=hi`**, so the ONLY `lo>hi` slots are sentinels (else `break` could skip a legit slot). If that invariant is NOT enforced upstream, B18 is unsafe → flag it.
- **Impl**: B18 = the second `continue` (`r->lo > r->hi` unused-slot, `mac_filter.bpf.c:509`) → `break`. The FIRST `continue` (`!r` null-check, `:506`) STAYS (verifier-required; never fires on a bounded ARRAY, cannot be a `break`). B19 = `tests/CMakeLists.txt` lock edits. NO src change for B19; NO VERSION bump.
- **Tester**: **NEW ctests target = 0.** B18 regression net = existing `T_PORT_RANGE_AND_COMPOSE` + `T_AND{,4,5,6}_ORACLE_AGREEMENT` (port matching exercised; a wrong `break` would flip a port verdict → oracle disagreement). B19 is validated by the `-j4` run itself no longer flaking (tester runs the full suite with `-j4` and confirms `T_BUILD`/`T_SANITIZER_BUILD` no longer SIGKILL-timeout). Tester MAY add a targeted B18 canary ONLY if it judges the oracle net doesn't exercise a "used slot at index >0 with a sentinel-looking neighbor" case — justify against the corpus.
- **Reviewer**: 5-point brownfield. Load-bearing checks: (1) B18 — ONLY the unused-slot `continue` became `break`; the `!r` continue is untouched; the dense-pack invariant is documented and actually holds (read `populate_port_inner_slot` + confirm port-range validation enforces `lo<=hi`); (2) B19 — `build_cpu` lock added to BOTH compiles, `T_SANITIZER_BUILD`'s existing `xdp_fixture` lock PRESERVED (becomes a 2-lock list); (3) no behavioral delta in port matching (oracle green); (4) no VERSION bump, no src change beyond the one `break`.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.9-1: VERSION bump → **NO bump (stay 0.15.0)**
B18 is a behavior-preserving perf micro-opt; B19 is test-harness-only. Zero operator-observable change. Mirrors the internal-hardening precedent (MVP-3.4e / MVP-4.8). No literal propagation needed.

### HG-mvp-4.9-2: bundle B18 + B19 in one slice → **YES (PO-directed)**
Two different files (`mac_filter.bpf.c` datapath vs `CMakeLists.txt` harness), two different concerns (perf vs test-infra), but both genuinely cheap and explicitly PO-bundled as a "clear the cheap wins before S8" slice. Reviewer may split if it judges the slice cleaner single-purpose — non-blocking. They share no code surface, so cross-contamination risk is nil.

## Open mechanism questions (architect decides; document in the §-amendment)

### Q1: B19 lock mechanism — `RESOURCE_LOCK build_cpu` vs ctest `PROCESSORS`
- **A1** — `RESOURCE_LOCK build_cpu`: add the named lock to `T_BUILD` (new) and to `T_SANITIZER_BUILD` (append to its existing `xdp_fixture` → `"xdp_fixture;build_cpu"`). Serializes the two compiles against each other regardless of `-jN`. Mirrors the existing multi-lock precedent (`RESOURCE_LOCK "xdp_fixture;lo_iface"` already in the file).
- **A2** — ctest `PROCESSORS N`: declare each compile as costing N cores so ctest's scheduler won't co-run them. Softer (advisory weight, not a hard mutex), depends on `--parallel-level` cost accounting.
- **Recommendation**: **A1** — a hard named lock is the deterministic fix and matches the file's established RESOURCE_LOCK idiom; PROCESSORS is advisory and easier to defeat. Architect may add PROCESSORS as a complement.

## Scope (cycle — concrete items)

### Item B18-1 — port_scan early-break
**Where**: `src/bpf/mac_filter.bpf.c` `port_scan()` (the `if (r->lo > r->hi) { continue; }` unused-slot sentinel).
Change that `continue` → `break`. Leave the `!r` null-check `continue` untouched. Document the dense-pack coupling (and the `lo<=hi`-for-real-ranges precondition) at BOTH `port_scan` and `populate_port_inner_slot` (the two ends of the invariant).

### Item B19-1 — build_cpu RESOURCE_LOCK
**Where**: `tests/CMakeLists.txt` `T_BUILD` + `T_SANITIZER_BUILD` `set_tests_properties`.
Add `RESOURCE_LOCK build_cpu` to `T_BUILD`; extend `T_SANITIZER_BUILD`'s existing `RESOURCE_LOCK xdp_fixture` to `"xdp_fixture;build_cpu"`. (Optionally any other full-compile test — architect confirms which ctest entries are full compiles.)

## Out of scope (explicit)
- **IPv6 / S8** — HLD-gated (multi-axis gate-rework); deferred per PO. NOT this slice.
- **B20/B28** — already paid (B20=MVP-4.8) / follow-on refactor.
- Any datapath change beyond the single `break`; any new port-axis semantics; any map/schema/VERSION change.
- B16's option-a (superseded by B19's structural lock).

## Definition of done
- Housekeeping §-amendment in `design.md` (B18 break + dense-pack invariant + `lo<=hi` precondition; B19 build_cpu lock).
- All existing PIs CONTINUE byte-equivalent.
- ctest baseline GREEN (85 per MVP-4.8; NEW ctests target = 0). Port-matching oracle green = B18 behavior-preserved. `-j4` full run no longer flakes on the two compiles = B19 confirmed.
- VERSION unchanged at 0.15.0.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang-19, libbpf, CMake ≥3.20 (unchanged).
- Runtime: root for the port-axis/atomic-swap ctests; kernel 6.1 host (5.15 untested — B18's unroll stays 64-block so the 5.15 verifier story is unchanged).
- No new deps.

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
**MECHANICAL → single-architect via `/mint-dev`. NO `/mint-hld`.** Two small, well-bounded backlog items; both answers fall out of stated constraints (B18 = a one-keyword change gated on an existing dense-pack invariant; B19 = the file's own RESOURCE_LOCK idiom). Not multi-axis. The one substantive check — B18's `lo<=hi`-for-real-ranges precondition — is a verifiable code fact (architect confirms config validation), not a design-space exploration. (Contrast: the IPv6/S8 slice WAS assessed multi-axis this session and correctly routed to /mint-hld-then-deferred — this cheap-wins slice is the opposite end of the scope spectrum.)

### Phase 1 sub-check #5 — stateful-map PRESERVE-vs-RESET semantic
N/A — neither item promotes a stateful map or touches atomic-swap. B18 reads the port inner; B19 is harness-only.

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author already ran these; architect re-verifies + extends:
- `grep -nE 'continue|r->lo > r->hi|!r|break' src/bpf/mac_filter.bpf.c` in `port_scan` — confirm exactly TWO continues, change ONLY the unused-slot one.
- Read `populate_port_inner_slot` in `src/lib/loader.cpp` — confirm clears-all-to-sentinel-then-writes-dense; confirm the sentinel is `lo=1,hi=0` (lo>hi).
- **Confirm port-range config validation enforces `lo<=hi`** for real ranges (grep the config parser / range construction): `grep -rnE 'lo *> *hi|lo *<= *hi|port.*range|range.*valid' src/lib/config.cpp src/lib/*.hpp`. This is the load-bearing B18 correctness precondition.
- `grep -nE 'T_BUILD|T_SANITIZER_BUILD|RESOURCE_LOCK|build_cpu' tests/CMakeLists.txt` — confirm T_BUILD lacks any lock, T_SANITIZER_BUILD has `xdp_fixture`; identify any OTHER full-compile ctest that should join `build_cpu`.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #12** (RESOURCE_LOCK for shared host state) → DIRECTLY B19's domain. `build_cpu` is a CPU-contention lock (a logical resource, not a host fixture) — same RESOURCE_LOCK mechanism, mirrors the existing multi-lock `"xdp_fixture;lo_iface"` precedent. Architect: ensure the lock name is consistent across all entries that take it.
- **Guard #5** (Phase A code-grep discipline) → always; architect independently re-runs the greps above, especially the `lo<=hi` precondition.
- **Guard #10** (catalog arithmetic) → N/A (no catalog/array-size change).
- **Guard #11** (VERSION-bump propagation) → N/A (no bump per HG-1).
- **B18 dense-pack coupling** (not a numbered guard — a load-bearing correctness invariant): the `break` is correct ONLY IF (a) used slots are dense-at-front AND (b) real ranges never have `lo>hi`. Both must hold and be documented at the two ends of the invariant.
