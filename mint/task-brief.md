# Task brief — MVP-4.22: robustness hardening batch (brownfield)

## Goal

A single low-risk, **non-feature** slice that closes 5 small correctness /
defense-in-depth findings surfaced by the 2026-06-01 hybrid `/mint-review`
(`~/agent-teams-review/runs/mint-review-mint-l2-mac-filter-20260601213046/report.md`)
and the external review (`mint/external-review-2026-06.md`). No schema
change, no new match axis, no datapath behaviour change. The five items are
independent and additive; they share a theme (close the "robustness debt"
both reviews independently flagged) but do not interact.

The batch is deliberately sequenced FIRST among three planned hardening
slices (this one → CI gate → exporter generation-counter), per the
strategy agreed with the PO: shore up the foundation cheaply before the
next big capability (XDP/TC mirror/redirect actions) is designed.

## Context: prior work

- Prior slice: **MVP-4.21 / B30** (`beae59e`) — slot/id decouple; archived as `mint/task-brief-mvp-4.21.md`.
- Existing design: `mint/design.md` (most recent §5.61); this slice appends a new §5.62 amendment.
- Phase A code-grep verification (brief author, this slice):
  - `grep -rn validate_iface_name src/lib/loader.cpp` → defined `validate_iface_name(const std::string&, LoaderError)`; the ONLY real callsite is `reset_counters_request` (uses `LoaderError::PathRefused`); a doc-comment block enumerates the gate order and explicitly says apply/detach are "Not retrofitted this slice per Q2.A2 scope discipline" — i.e. SEC-H1 is a pre-acknowledged gap.
  - `detach(const std::string& iface)` and `apply_request(const ApplyRequest& req)` definitions located; `attach()` routes through `internal::apply_request` (so fixing `apply_request` covers the attach path too).
  - `grep -nE 'struct ' src/common/mac_filter.h` → boundary structs `xdpmf_mac`, `xdpmf_cidr_v4`, `xdpmf_cidr_v6`, `xdpmf_port_range`, `rule_entry`, `action_entry`, `allow_entry`; `grep static_assert src/common/mac_filter.h` → **none** (item R-2 confirmed net-new).
  - `grep -nE 'v = v \* 10u' src/lib/config.cpp` → base-10 accumulator appears in BOTH `parse_u32_or_throw` AND `parse_bounded_uint` (item R-3 widened to both).
  - `grep -n g_format src/common/logger.cpp` → `Format g_format = Format::Text;` (non-atomic global), read in the lazy-init-once path (with a documented recursive-emit subtlety).
  - `grep -rn catch src/lib/sidecar.cpp src/common/logger.cpp src/exporter/sidecar_reader.cpp` → 5 `catch (...)` sites: logger.cpp ×2 (the D-3.5-4 format/bad_alloc guards), sidecar.cpp ×1 (never-throw writer), sidecar_reader.cpp ×2 (never-throw reader).
- PI continuity: **PI-7 (loader.hpp + config.hpp byte-identical)** is expected to CONTINUE — every edit lands in `.cpp` anon-namespace/internal or in `mac_filter.h` (additive static_asserts), no new public symbol. `LoaderError` enum already carries every code SEC-H1 needs.

## Workflow rules (brownfield)

- **Architect**: read §5.61 tail + §6.5 invariants + guards #1..#29; EDIT `design.md` in place, append §5.62. Resolve Q1/Q2 (item R-5 catch strategy + diagnostic channel). Run the Phase A grep discipline below.
- **Impl**: FileList is EDITED-only (no NEW source files expected). Each item is independently committable but ships as one slice.
- **Tester**: NEW ctests target ~2-3 (iface-shape rejection on apply/detach; oversized-integer config rejection; sidecar graceful-degradation diagnostic). R-2 is compile-time (a green build IS the assertion). R-4 has no practical runtime test (race is theoretical; a TSAN build or a smoke that text/json selection still works is sufficient).
- **Reviewer**: 5-point brownfield framework. Special attention: (a) SEC-H1 exit-code uniformity; (b) item R-5 must PRESERVE the never-throw daemon-resilience contract — narrowing that lets a non-std exception propagate is a REGRESSION, not a fix; (c) PI-7 zero-diff; (d) datapath untouched (xdp section stays 3658 insns).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.22-1: SEC-H1 failure exit code → **`LoaderError::PathRefused` (exit 8)** for all three entry points
The existing `validate_iface_name` callsite (`reset_counters_request`) uses `PathRefused`, and the loader's own gate-order doc-comment labels `validate_iface_name` the "shape gate (exit 8)". Using the same code in `apply_request`/`detach` makes the fence uniform and matches the established semantic. (The review's suggestion of AttachFailed/DetachFailed would split the semantic across entry points — rejected for inconsistency.) Architect overrides with evidence if a per-entry-point code is genuinely better.

### HG-mvp-4.22-2: static_assert guard mechanism → **`#ifdef __cplusplus`**, assert `sizeof` (alignof/offsetof at architect discretion)
The header is included by both the BPF target (clang `-target bpf`) and the C++ loader. The ABI concern is the C++ side matching the on-wire layout, so guarding the asserts to the C++ TU is sufficient and avoids any BPF-target surprise. Architect picks the exact struct set (default: all 7 boundary structs above) and whether to add `alignof`/`offsetof` asserts on top of `sizeof`.

### HG-mvp-4.22-3: VERSION → **no bump** (internal hardening; no operator-visible behaviour change)
None of the 5 items changes a documented operator surface (SEC-H1 only tightens rejection of already-invalid iface names; the rest are internal). Default = stay `0.15.0`. Architect may bump if it judges the catch-diagnostic surface (R-5) operator-visible.

## Open mechanism questions (architect decides; document in §5.62)

### Q1: item R-5 `catch (...)` narrowing strategy (the one real fork in this batch)
- **A1** — pure narrow to `catch (const std::exception& e)` + log `e.what()`. **Problem**: a non-`std::exception` throw now PROPAGATES → breaks the never-throw contract the band flagged as intentional clean-surface. Rejected as a resilience regression.
- **A2** — two-arm: `catch (const std::exception& e) { /* log e.what() */ } catch (...) { /* log "non-std/unknown" */ }`. PRESERVES never-throw AND adds the diagnostic the external review wants. **Recommended** for the sidecar/sidecar_reader never-throw sites.
- **A3** — keep `catch (...)` but add a diagnostic log line inside (no std/non-std split). Minimal; preserves never-throw. **Recommended for the logger-internal D-3.5-4 sites** (logging from inside the logger's OWN format/bad_alloc catch risks recursion — architect confirms whether a diagnostic is even safe there; leaving those two sites unchanged is an acceptable outcome).
- **Recommendation**: A2 for sidecar/sidecar_reader; A3-or-leave-as-is for the two logger.cpp D-3.5-4 catches. Per-site contract confirmation is mandatory (the brief item explicitly required it).

### Q2: item R-5 diagnostic channel → minimize catalog ripple
- **A1** — reuse an existing structured log-event name (generic `*.warn.*`).
- **A2** — add ONE new `kEventName` for "swallowed exception" reused across sites.
- **A3** — plain `fprintf(stderr, ...)` (no structured event).
- **Recommendation**: prefer A1/A2 over per-site new events. If new `kEventNames` entries are added, guard #10 (catalog arithmetic) + guard #13 (fixture cross-reference) apply — grep `tests/fixtures/` for log-event catalogs and pre-list any ripple.

## Scope (cycle 1 — concrete items)

### Item R-1 — SEC-H1: uniform iface shape-fence on apply/detach
**Where**: `src/lib/loader.cpp` — `apply_request(const ApplyRequest&)` and `detach(const std::string&)`.
Call `validate_iface_name(<iface>, LoaderError::PathRefused)` as the FIRST statement of each. `attach()` is covered transitively (it funnels through `apply_request`). Removes the implicit reliance on `if_nametoindex` as the sole shape gate. Update the loader.cpp:514-517 self-documenting comment to reflect that the retrofit is now DONE (retire the "Not retrofitted this slice" note).

### Item R-2 — ABI static_asserts on boundary structs
**Where**: `src/common/mac_filter.h`.
Add `#ifdef __cplusplus` `static_assert(sizeof(T) == N, "ABI: ...")` for each BPF↔userspace boundary struct so a padding/layout drift fails the C++ build instead of silently desyncing the kernel ABI. Sizes are computed by the architect/impl from the current layout (SHOULD-level orientation, not pre-pinned here).

### Item R-3 — integer-parse overflow guard
**Where**: `src/lib/config.cpp` — `parse_u32_or_throw` AND `parse_bounded_uint`.
Add a pre-multiplication overflow guard (`v > (UINT32_MAX / 10u)` or equivalent, applied against the relevant bound) so an oversized digit string throws `ConfigError` (exit 9) instead of silently wrapping `uint64_t` and possibly landing under the bound. Both base-10 accumulators get the guard.

### Item R-4 — logger g_format data-race fix
**Where**: `src/common/logger.cpp`.
Change the `g_format` global to `std::atomic<Format>` (relaxed ordering is sufficient) and add `<atomic>`. Preserve the lazy-init-once semantics and the documented recursive-emit guard (the recursive `emit()` must still observe `Format::Text`). No `logger.hpp` change (g_format is `.cpp`-private).

### Item R-5 — narrow exception-swallowing catches + add diagnostics
**Where**: `src/lib/sidecar.cpp`, `src/exporter/sidecar_reader.cpp` (never-throw sites — apply Q1/A2); `src/common/logger.cpp` (D-3.5-4 sites — apply Q1/A3 or leave, per recursion-safety).
Stop SILENTLY swallowing: add a diagnostic (Q2) while PRESERVING the never-throw contract. Per-site contract confirmation required before changing each site.

## Out of scope (explicit)

- **CI gate** (TEST-H1/H2/H3) — the NEXT slice (MVP-4.23), not this one.
- **Exporter generation-counter / TOCTOU P1** (rule_counters_reader read-skew) — the THIRD slice (MVP-4.24); do NOT pull forward.
- **`pass_cidr`→`pass_rule` rename (ARCH-H2 / B26)** — metric-ABI change, separate slice.
- **Datapath triplication refactor (ARCH-H1 / CQ-L1)** — separate refactor slice.
- **Dead `read_all_attached` removal (CQ-H1)** — separate cleanup; not bundled here to keep this batch a pure robustness pass.
- **`__int128` portability guard (external P2)** — project is x86_64-only by design (XDP/BPF); cosmetic, deferred.
- **`yaml_subset → loader.hpp` decoupling (external P3)** — band judged the include direction clean; not pursued.
- Any schema, axis, datapath, map, or operator-surface change.

## Definition of done

- §5.62 amendment in `design.md` (the 5 items + Q1/Q2 resolutions + any new guard #30 candidate).
- **PI-7 CONTINUES**: `git diff <base> -- src/lib/loader.hpp src/lib/config.hpp` = ∅.
- **Datapath untouched**: the `xdp` section of `build/mac_filter.bpf.o` stays at 3658 instructions (none of these items touch `mac_filter.bpf.c`).
- ctest: baseline 97/97 green + ~2-3 NEW ctests (iface-shape rejection on apply/detach; oversized-integer config rejection; sidecar graceful-degradation diagnostic). Final count ~99-100/100.
- VERSION per HG-mvp-4.22-3 (default no bump).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies

- Build: existing toolchain (clang-19, libc++-19, libbpf ≥1.1, cmake). `<atomic>` is stdlib.
- Runtime/test: existing veth+inject ctest fixture; root for the iface-rejection ctests (validate_iface_name runs before any privileged op, but the apply/detach paths the test drives need the harness). No new external dep.
- Kernel/platform: unchanged (≥5.15 target, dev 6.1).

## Packs to load (orchestrator: inject into spawn prompts)
```yaml
mode: brownfield
packs:
  architect:  [cpp, bpf]
  impl:       [cpp, bpf]
  tester:     [cpp, bpf-xdp]
  reviewer:   [cpp]
```

---

## Pre-brief sanity check (per mint-hld-scope-discipline)

**Mechanical — single-architect OK.** Goal fits one line ("close 5 small independent robustness findings"). Not multi-axis: each item is a localized, well-understood fix with at most one micro-fork (R-5 catch strategy, framed as Q1 with a clear recommendation). Not expensive-to-undo. No `/mint-hld` needed. The only genuine decision (R-5 never-throw preservation) is an architect-tier mechanism choice, pre-framed, not a design-space exploration.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief author already ran these; architect re-verifies + extends:
- `grep -rn 'validate_iface_name' src/lib/loader.cpp` — confirm the only callsite is reset_counters_request before adding the two new ones; confirm `attach()` funnels through `apply_request` (so it needs no separate call).
- `grep -nE 'struct (xdpmf_mac|xdpmf_cidr_v4|xdpmf_cidr_v6|xdpmf_port_range|rule_entry|action_entry|allow_entry)' src/common/mac_filter.h` — confirm the layout each static_assert will pin; compute sizes from the actual fields, do NOT trust any number in this brief (none given on purpose).
- `grep -nE 'v = v \* 10u' src/lib/config.cpp` — confirm BOTH parse_u32_or_throw and parse_bounded_uint need the guard; check whether either already length-caps input.
- `grep -n 'g_format' src/common/logger.cpp` — confirm all read/write sites move to the atomic consistently; preserve the recursive-emit guard semantics.
- `grep -rn 'catch (\.\.\.)' src/lib/sidecar.cpp src/common/logger.cpp src/exporter/sidecar_reader.cpp` — confirm each site's contract (never-throw vs internal-format-guard) before narrowing; logger-internal D-3.5-4 sites are recursion-sensitive.
- If R-5 adds any `kEventNames` entry: `grep -rln '<new-event-name>' tests/fixtures/` (guard #13) + recount the catalog (guard #10).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep discipline)** — APPLIES (always). Architect repeats the greps above independently.
- **Guard #8 (interactive-vs-log emission distinction)** — APPLIES to R-5: the new diagnostic emissions are in daemon/non-interactive paths (sidecar/exporter/logger), but confirm none is an interactive UI primitive before wrapping.
- **Guard #10 (catalogue arithmetic)** — CONDITIONAL on R-5/Q2: applies only if a new `kEventNames` entry is added; recount the catalog if so.
- **Guard #13 (fixture cross-reference)** — CONDITIONAL on R-5/Q2: applies only if a new log-event name is added; grep `tests/fixtures/` for log-event catalogs.
- **Guard #11 (VERSION-bump test-literal propagation)** — N/A (default no bump per HG-3; if architect bumps, this re-activates).
- **Guard #12 (RESOURCE_LOCK for shared host state)** — N/A: the R-3 config-parse ctest is pure userspace; the R-1 iface-rejection ctest rejects BEFORE any bpffs/iface mutation (validate runs first), so it touches no shared host state. Architect confirms the new ctests don't attach/pin.
- **Guard #15 (PRESERVE-vs-RESET atomic-swap semantic)** — N/A (no stateful-map promotion).
