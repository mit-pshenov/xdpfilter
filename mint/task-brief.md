# Task brief — MVP-4.24: exporter scrape consistency (active_idx seqlock) (brownfield)

## Goal

Close the exporter scrape-consistency gap (P1 in `mint/external-review-2026-06.md`;
the 2026-06-01 band's "dual-source coupling to watch" in the ARCH framework
section): `rule_counters_reader` reads `active_idx` and then opens/reads the
matching `rule_counters_<active>` inner pin in SEPARATE bpf syscalls, so a
loader atomic-swap (`apply -f`) landing between those reads makes the scrape
report the PRE-apply generation (one scrape stale). Third and last of the three
hardening slices (MVP-4.22 robustness + MVP-4.23 CI already shipped).

**Grounding correction to the original framing (briefer Phase A — important).**
The atomic-swap architecture is **populate-INACTIVE-buffer → single-u32 store to
`active_idx[0]` commits** (loader.cpp `write_active_idx`; the active buffer is
NEVER mutated in place; `copy_rule_counters_forward` copies counters into the
inactive buffer BEFORE the flip). Consequently the reader only ever reads a
**stable** buffer:
- A single concurrent apply → the reader gets **consistent but one-apply-stale**
  data (NOT torn, NOT zero — the old generation is fully valid).
- A genuinely TORN/zero read would require reading a buffer mid-repopulation,
  which needs **two `apply -f` within one sub-second scrape** (operationally
  impossible; an apply is a full multi-syscall BPF repopulation).

So the fix is a **lightweight seqlock using `active_idx` itself as the sequence
number** — read `active_idx`, read the 64 slots, **re-read `active_idx`; if it
changed, retry (bounded)**. This needs **NO new BPF map, NO loader change, NO
`kManagedMaps` growth, NO datapath change**. The heavyweight options from the
original ask (a new generation BPF map + loader write-side bracketing) are
**dominated** — their only added coverage is the X→Y→X double-flip, which is the
operationally-impossible two-applies-in-one-scrape case. That case is documented
as a known OOS limitation (§5.60 honesty precedent), not engineered for.

## Context: prior work

- Prior slice: **MVP-4.23** (`3d0f3ad`) — CI gate + coverage-floor; archived as `mint/task-brief-mvp-4.23.md`.
- Existing design: `mint/design.md` (most recent §5.63); this slice appends §5.64.
- Phase A code-grep verification (brief author, this slice):
  - `active_idx` = `ARRAY[1]` of `__u32` (mac_filter.h `XDPMF_MAP_ACTIVE_IDX_NAME`), `XDPMF_RULESET_COUNT=2` (A/B double-buffer). `write_active_idx` (loader.cpp) = single u32 store; loader comments confirm "writes BEFORE the active_idx flip" + "single active_idx u32 store commits".
  - `src/exporter/rule_counters_reader.cpp` reads `active_idx` (`bpf_obj_get` + `bpf_map_lookup_elem`, the `iface_dir + XDPMF_MAP_ACTIVE_IDX_NAME` pin), then opens `rule_counters_<active>` and sums the 64 PERCPU slots — the two-syscall window this slice closes.
  - `src/exporter/stats_reader.cpp` reads the **single** `stats` PERCPU_ARRAY (`XDPMF_MAP_STATS_NAME`, STAT-enum-indexed, NOT active-indexed, accumulates across applies) → **NO active_idx indirection → NO TOCTOU → out of scope** (architect confirms).
  - Event catalog `src/common/logger.hpp` `kEventNames` currently **38** (`kEventCount = 38`), pattern `exporter.scrape.warn.*` (3 existing: stats_open_failed, rule_counters_open_failed, sidecar_read_exception). The MVP-4.22 +1-event ripple (logger.hpp count + `tests/fixtures/log_events_v1.txt`) is the exact precedent for the new diagnostic event.
- PI continuity: **PI-7 (loader.hpp + config.hpp byte-identical)** holds trivially (no `src/lib` change). **PI-DATAPATH-IDENTICAL** (mac_filter.bpf.c ∅, xdp 3658) holds trivially. **kManagedMaps UNCHANGED (39)** — no new map.

## Workflow rules (brownfield)

- **Architect**: read §5.63 tail + §6.5 invariants + guards #1..#31; EDIT `design.md` in place, append §5.64. Resolve Q1 (retry bound + after-N fallback). Run the Phase A grep discipline below. Confirm the grounding (single-buffer `stats` is exempt; active buffer never mutated in place).
- **Impl**: FileList = EDITED `src/exporter/rule_counters_reader.cpp`, `src/common/logger.hpp` (catalog +1), `tests/fixtures/log_events_v1.txt` (catalog +1) + NEW ctest. NO `src/lib`, NO `src/bpf`, NO new map.
- **Tester**: NEW concurrency ctest (§6.82) — drive a scrape concurrent with an `apply -f` and assert the reader never returns a torn/zero generation (it returns either the old or the new full generation, and after a bounded retry prefers current). Plus a negation/non-vacuity control (prove the test can actually observe a generation change — e.g. without the seqlock retry it would catch a stale read). The existing 100/102 baseline must stay green.
- **Reviewer**: 5-point brownfield. Special attention: (a) the seqlock loop re-reads `active_idx` AFTER the data read and retries on change, bounded N; (b) the after-N fallback is consistent (serves one full generation, never a tear) + emits the diagnostic; (c) `stats_reader` correctly left untouched (single map, no TOCTOU); (d) PI-7 + datapath + kManagedMaps all trivially hold (zero `src/lib`+`src/bpf` footprint); (e) catalog arithmetic (38→39) + fixture ripple correct; (f) the X→Y→X two-apply tear is documented as OOS-impossible, not silently claimed fixed.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.24-1: consistency mechanism → **`active_idx`-as-seqnum (re-read + bounded retry), NO new gen map**
Per the grounding above, this fully covers every operationally-reachable race (single apply mid-scrape) with zero loader/map/datapath change. A dedicated monotonic generation map is REJECTED as dominated machinery (its only delta is the impossible X→Y→X case). Architect overrides only with evidence that an active-buffer in-place mutation exists (it does not — `copy_rule_counters_forward` + populate-inactive-then-flip).

### HG-mvp-4.24-2: VERSION → **no bump** (exporter-internal read-consistency hardening; same metrics, just fresher under a concurrent apply — no operator-visible API/metric/label change)
Architect may bump if it judges the new diagnostic event operator-visible enough to warrant it.

### HG-mvp-4.24-3: X→Y→X two-apply tear → **documented OOS limitation** (§5.60 honesty precedent)
The fix does not claim to defend the two-rapid-applies-within-one-scrape tear (operationally impossible). Design states this plainly rather than implying total consistency.

## Open mechanism questions (architect decides; document in §5.64)

### Q1: retry bound N + after-N fallback
- **A1** — N small (e.g. 2–3) + after-N serve the LAST consistently-read generation (best-effort, never a tear) + emit a NEW `exporter.scrape.warn.*` diagnostic event. **Recommended** — a single apply needs exactly one retry to converge; N=2–3 is generous; the fallback is still a consistent generation (just possibly stale), and the diagnostic makes the rare event observable.
- **A2** — N + after-N skip that iface's rule_counters block for this scrape (serve nothing). More conservative but creates a metrics gap.
- **A3** — unbounded retry until stable. Rejected — a pathological apply storm could stall the scrape (the exporter is single-threaded; ties into B27 DoS surface — do NOT introduce an unbounded loop).
- **Recommendation**: A1. Architect picks the exact N and the diagnostic event name (`exporter.scrape.warn.rule_counters_generation_unstable` or similar).

### Q2: scope of the seqlock — `rule_counters_reader` only?
- Grounding says YES (only this reader has the active_idx-then-data pattern; `stats` is a single non-active map). Architect confirms via grep before finalizing; if `stats_reader` or any other reader shares the pattern, extend symmetrically (but grounding indicates it does not).

## Scope (cycle 1 — concrete items)

### Item G-1 — active_idx seqlock in rule_counters_reader
**Where**: `src/exporter/rule_counters_reader.cpp`.
Wrap the `active_idx`-read → open `rule_counters_<active>` → sum-64-slots sequence in a bounded retry loop: snapshot `active_idx`, do the read, re-read `active_idx`; if it changed, discard and retry up to N (Q1). Preserve the existing fall-through WARN paths (`rule_counters_open_failed`) and the PI-31-3.4b "only bpf_obj_get + PERCPU lookup" contract. On retry-exhaustion, the after-N fallback (Q1/A1) + the new diagnostic event.

### Item G-2 — diagnostic event (catalog 38→39)
**Where**: `src/common/logger.hpp` (`kEventNames` + the `kEventCount = 38` comment → 39) + `tests/fixtures/log_events_v1.txt` (+1 sorted line). NEW `exporter.scrape.warn.<name>` event for retry-exhaustion, emitted from G-1. Mirror the MVP-4.22 +1-event ripple exactly (guard #10 catalog arithmetic + guard #13 fixture cross-reference).

### Item G-3 — concurrency consistency ctest (§6.82)
**Where**: NEW `tests/T_EXPORTER_SCRAPE_CONSISTENCY.sh` (name architect's call) + `tests/CMakeLists.txt` registration.
Drive a `/metrics` scrape (or a direct rule_counters read) concurrent with an `apply -f` flip and assert the returned rule_counters are a single consistent generation (never torn/zero). Non-vacuity: demonstrate the test can observe a generation transition (so a regression that drops the retry would be caught). Sudo-gated (needs attach + apply) → `require_passwordless_sudo` + SKIP-77 + RESOURCE_LOCK as the existing exporter/xdp_fixture tests do (guard #12).

## Out of scope (explicit)

- **New generation BPF map + loader write-side bracketing** — dominated by HG-1; not built.
- **`stats_reader` / any non-active-indexed reader** — no TOCTOU (single map); untouched.
- **X→Y→X two-apply-in-one-scrape tear** — operationally impossible; documented OOS, not engineered (HG-3).
- **B27 exporter single-thread DoS, B26 `pass_cidr`, ARCH-H1 datapath triplication, CQ-H1 dead read_all_attached** — separate slices.
- Any `src/lib`, `src/bpf`, schema, axis, map-count, or datapath change.

## Definition of done

- §5.64 amendment in `design.md` (G-1..G-3 + Q1 resolution + HG-3 OOS honesty note + any guard #32 candidate).
- **PI-7 + PI-DATAPATH-IDENTICAL + kManagedMaps=39 hold trivially** (verify `git diff <base> -- src/lib src/bpf src/common/mac_filter.h` empty; `kManagedMaps` count unchanged).
- ctest: 100/102 MVP-4.23 baseline preserved + 1 NEW concurrency ctest. The 2 pre-existing env-fails (#48/#62) remain pre-existing.
- Event catalog 38→39 consistent across logger.hpp + fixture; catalog-stability test green.
- VERSION per HG-2 (default no bump).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies

- Build/test: existing toolchain; the concurrency ctest needs root (attach + apply) + the veth/xdp fixture; bpftool.
- Runtime: exporter + loader as built.
- Platform: unchanged.

## Packs to load (orchestrator: inject into spawn prompts)
```yaml
mode: brownfield
packs:
  architect:  [cpp]
  impl:       [cpp]
  tester:     [cpp, bpf-xdp]
  reviewer:   [cpp]
```

---

## Pre-brief sanity check (per mint-hld-scope-discipline)

**Mechanical — single-architect OK (after grounding collapsed the design space).** The original ask LOOKED borderline-HLD (seqlock-encoding × retry-policy × counter-location, ≥3 options, concurrency-correctness). But Phase A grounding REFUTED the heavyweight axes: because the loader populates-inactive-then-atomic-flips and the active buffer is never mutated in place, `active_idx`-as-seqnum (re-read + bounded retry) dominates the new-gen-map and full-seqlock options — same coverage of every reachable race, zero new map / zero loader change. The remaining decisions (retry bound, fallback, diagnostic name) are single-architect-tier (Q1). No expensive-to-undo concurrency subtlety survives (the read target is always a stable buffer). `/mint-hld` NOT needed — this is the same "grep collapses the apparent design space" outcome as the 2026-05-30 S4 re-grounding, in reverse.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief author already ran these; architect re-verifies + extends:
- `grep -n 'active_idx\|bpf_map_lookup\|rule_counters_' src/exporter/rule_counters_reader.cpp` — confirm the exact active_idx-read → inner-open → 64-slot-read sequence the seqlock wraps; preserve the existing fall-through WARN.
- `grep -n 'write_active_idx\|active_idx flip\|copy_rule_counters_forward' src/lib/loader.cpp` — CONFIRM populate-inactive-then-single-store-flip + copy-forward (the grounding that makes the active buffer stable; if this is wrong, HG-1 must be revisited).
- `grep -n 'active\|XDPMF_MAP_STATS' src/exporter/stats_reader.cpp src/common/mac_filter.h` — confirm `stats` is single/non-active (Q2 exemption).
- `grep -nE 'kEventNames|kEventCount' src/common/logger.hpp` + `wc -l tests/fixtures/log_events_v1.txt` — confirm 38→39 arithmetic + the sorted-insert position for the new event (guard #10/#13).
- For the new ctest (guard #12): grep how `T_EXPORTER_*` / `T_LOAD_ATTACH` tests take RESOURCE_LOCK (xdp_fixture / exporter_port) and gate on `require_passwordless_sudo` + `SKIP_RETURN_CODE 77`.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep discipline)** — APPLIES (always).
- **Guard #10 (catalogue arithmetic)** — APPLIES (G-2: kEventNames 38→39; recount + the `kEventCount` comment).
- **Guard #13 (fixture cross-reference)** — APPLIES (G-2: `tests/fixtures/log_events_v1.txt` +1 sorted line; the catalog-stability test asserts logger.hpp ↔ fixture lockstep).
- **Guard #12 (RESOURCE_LOCK for shared host state)** — APPLIES (G-3: the concurrency ctest attaches + applies + scrapes → needs xdp_fixture / exporter_port RESOURCE_LOCK like the existing exporter tests).
- **Guard #11 (VERSION-bump test-literal propagation)** — N/A (default no bump per HG-2; re-activates if architect bumps).
- **Guard #15 (PRESERVE-vs-RESET atomic-swap semantic)** — N/A here (no map promotion; this slice READS the existing atomic-swap, does not change its write-side semantic). But the architect MUST rely on the existing PRESERVE copy-forward as the grounding for active-buffer stability.
