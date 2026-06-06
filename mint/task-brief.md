# Task brief — MVP-4.36 / B43: `dryrun_harness` — offline map-image golden (Option 1 "Recording-fake floor", GOLDEN-ONLY) (brownfield, test-infra + pure-move)

## Goal

Roadmap item ① slice 1 (PO Dmitry, locked 2026-06-05; design `mint/architecture-dryrun.md`,
mint-hld round 2026-06-06, reviewer pass r2 / grounder clean-with-gates). Close the last
host-side correctness gap: the step between `CompiledRuleset` and the kernel — `materialize()` —
is today welded to a live `xdpfilter_bpf*` skeleton and so is tested ONLY live (netns+root+BPF).
This slice renders the **map-image** (`compile()` → `materialize` write-set) **offline** and
asserts it against a canonical golden, moving the "config → map-image" correctness class to a
CI-green libbpf-free harness in the `compile_harness`/`ruleset_delta_harness` mold — advancing the
B39 CI boundary one stage toward the kernel.

**PO ruling ① (baked):** slice 1 is **GOLDEN-ONLY, NO `apply --dry-run` CLI verb.** The CLI verb +
human-decoded operator view share the same underlying image and are a zero-rework follow-on
(slice 1b). Do NOT add a CLI verb or a human pretty-printer this slice.

**SPIKE-1 = PASS (already discharged, 2026-06-06):** a C++ TU including the real
`build/xdpfilter.skel.h` for the `xdpfilter_bpf` type + `skel->maps.*` derefs, exercising the full
render libbpf surface, **links to a running executable with fake symbols and NO `-lbpf`** (skel's
libbpf-calling fns are all `inline` → unreferenced include emits zero libbpf symbols). Option 1
holds at low-risk; no degrade to the Option 3 factored-`render()` rewrite. The harness uses a
**fake `xdpfilter_bpf*` + fake `bpf_map__fd`** (returning fd-tags), not a real skeleton.

## Context: prior work

- Prior brief: MVP-4.35/B42 redirect verb → archived `mint/task-brief-mvp-4.35.md`.
- Design to amend: `mint/design.md` (append a new §5.76); architecture `mint/architecture-dryrun.md`
  (carries the full synthesis + discharge ledger + the SPIKE-1 PASS result).
- Precedent harnesses: `tests/compile/compile_harness.cpp` (`T_COMPILE_LOWERING_IDENTITY`) and
  `tests/delta/ruleset_delta_harness.cpp` (`T_RULESET_DELTA_TRUTHTABLE`) — bare-main, no gtest,
  **libbpf-free link IS the contract**, independent oracle + mandatory NEGATION + SMOKE.
- Brief-author Phase 2 greps (all confirmed against current code):
  - NEW paths absent: `src/lib/materialize.{cpp,hpp}`, `tests/dryrun/` ✓
  - The 3-call apply write-set sequence verified at BOTH apply branches:
    `materialize` (loader.cpp:2136 / 2258) → `populate_action_table` (2146 / 2266) →
    `populate_redirect_devmap` (2154 / 2273); `copy_rule_counters_forward` (2188 / 2293) is
    OUTSIDE and EXCLUDED (reads the live old-active inner — irreducibly live).
  - LPM closure: `const std::vector<std::uint64_t> closed = close_fn(prefixes)` at
    `populate_bitvec_inner_slot` (loader.cpp:1266); `cr.<axis>.prefixes` carry the PRE-closure
    bits → the golden MUST serialize POST-closure masks (this fact kills any "print
    `CompiledRuleset`" oracle — confirmed `close_prefixes`/`close_prefixes6` still vector-of-u64).
  - Error-machinery cluster (the extraction wrinkle): render helpers live in the loader.cpp
    anon-namespace (`namespace {` at :78) and call `throw_loader` (:350) / `classify` (:341) on
    map-op failure; those use `LoaderError` + `loader_error_category()` defined at
    `LoaderCategory` (loader.cpp:319) / `loader_error_category()` (loader.cpp:1769) /
    `loader.hpp:43-57`. This machinery is **host-only `std::error_category`, NOT libbpf** — but it
    currently sits in loader.cpp, so materialize.cpp must reach it WITHOUT linking the rest of
    loader.cpp (which would drag libbpf attach/load code). See Q1.
  - Render subset (loader.cpp:1180-1715) touches **ZERO** `bpf_object__`/`skeleton`/
    `bpf_program__` symbols — the only libbpf surface is flat map-op syscall wrappers
    (`bpf_map__fd`, `bpf_map_update_elem`, `bpf_map_delete_elem`, `bpf_map_get_next_key`,
    `bpf_map_lookup_elem`, `bpf_num_possible_cpus`) — all fakeable.
  - insn baseline **3477** confirmed in `T_INSN_BASELINE_GATE.sh:73` + `T_PROD_VERIFIER_LOAD.sh:127`.
  - NO VERSION bump this slice (additive test-infra + an internal host-side move; no datapath,
    behavior, schema, or feature-surface change).
- PI continuity: PI-7 loader.hpp zero-diff streak continues (keep the loader.hpp PUBLIC surface
  stable — prefer the new `materialize.hpp`, Q2); PI-mvp-4.35-VERDICT-IDENTITY + insn-3477 +
  CompiledRuleset/RulesetDelta shapes preserved.

## Workflow rules (brownfield)

- **Architect (Phase A):** read `mint/architecture-dryrun.md` (Option 1 + PO rulings + SPIKE-1
  result + discharge ledger), `mint/design.md` §5.73 (CompiledRuleset/materialize) + §5.74
  (RulesetDelta) + §6.5 invariants. Independently re-run the Phase 2 greps (esp. the error-machinery
  cluster + the 3-call sequence). EDIT `design.md` in place, append **§5.76**. Resolve Q1/Q2/Q3 with
  evidence; may override the HG golden-format defaults with rationale.
- **Impl:** the FileList's ONLY production edit is the materialize/render extraction (a near-pure
  move mirroring B40/B34b) + whatever shared error-machinery factoring Q1 settles. Everything else
  is NEW test infra.
- **Tester:** NEW `T_DRYRUN_IMAGE_IDENTITY` (libbpf-free ctest, no fixture/veth/root). Mandatory
  SMOKE (a minimal config renders a sane image) + NEGATION (the comparator can actually FAIL).
- **Reviewer:** 5-point brownfield. Special attention: (a) the move is byte-identity-preserving for
  the LIVE path (loader.cpp's apply still produces the same writes — prove via the existing live
  ctests + diff vs HEAD); (b) the harness link is genuinely libbpf-free (no `PkgConfig::LIBBPF`, no
  `*_skel` dep); (c) the golden is deterministic (single source of truth — guard #9 — the harness
  drives the SAME `materialize`+`populate_action_table`+`populate_redirect_devmap` the live path
  calls, NOT a parallel image-builder).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.36-1: golden format → **`# xdpfilter-image v1` canonical text** (default)
Fixed apply-write-set **map order** (the live call order: the 9 match axes + ruleset_state + rules
+ slot_rule_id as `materialize` issues them, THEN `action_table`, THEN `redirect_devmap`);
**within-map** rows sorted by stored-key bytes; each row fixed-width hex of the stored key+value
bytes; LPM masks are **POST-closure**; the devmap target ifindex is rendered **symbolically**
(`<name> RESOLVED-AT-APPLY`), never a live ifindex. Occupied-writes-only (the bulk-clear
`get_next_key`→`delete` traffic is excluded as kernel-state-dependent — confirm it carries no
config→image truth). Architect may refine the exact textual shape but MUST preserve: post-closure
masks, deterministic ordering, symbolic ifindex, zero kernel calls.

### HG-mvp-4.36-2: image scope → **FULL apply write-set** (default, grounded)
The golden covers `materialize`'s body PLUS `action_table` + `redirect_devmap` (issued at the apply
call-sites, NOT inside materialize — verified 2146/2154/2266/2273). `copy_rule_counters_forward` is
EXCLUDED (reads the live old-active inner). This is why the harness drives the 3-call sequence, not
`materialize` alone.

## Open mechanism questions (architect decides; document in §5.76)

### Q1: how materialize.cpp reaches the error-machinery without dragging libbpf
- **A1 (recommended):** extract the host-only error machinery (`LoaderError` is already in
  loader.hpp; move `LoaderCategory`/`loader_error_category()`/`throw_loader`/`classify` into a
  shared **libbpf-free** TU, e.g. `src/lib/loader_error.{hpp,cpp}`), linked by loader.cpp AND
  materialize.cpp AND the harness. Clean SSoT; no duplication (these are not values — guard #9's
  duplicate-don't-share rule does NOT apply to a `std::error_category` singleton/throw helper).
- **A2:** keep `throw_loader`/`classify` as a tiny inline header shim over `loader_error_category()`
  (still needs the category symbol in the link set).
- **A3 (reject):** link materialize.cpp against the whole loader.cpp object → drags libbpf attach
  code → breaks the libbpf-free contract. Named only to kill.
- **Recommendation:** A1 — smallest libbpf-free link set, mirrors the B40 `compiled_ruleset.cpp`
  extraction discipline. The architect confirms exactly which symbols the render subset references
  and sizes the shared TU.

### Q2: materialize.cpp public surface
- **A1 (recommended):** new `src/lib/materialize.hpp` declaring `materialize`,
  `populate_action_table`, `populate_redirect_devmap` (+ any helper the harness must call),
  included by BOTH loader.cpp (live apply) and the harness. The populate_* render helpers stay
  internal to materialize.cpp's anon-namespace except the three the apply sequence needs.
- **A2:** declare them in loader.hpp. (Risks PI-7 loader.hpp zero-diff streak — prefer A1.)
- **Recommendation:** A1, protecting the PI-7 streak.

### Q3: fake-skel + fd-tag scheme
- The fake `bpf_map__fd(skel->maps.X)` must return a stable per-map tag the recording sink decodes
  back to a map name + key/value sizes. Architect designs the tag table (a fixed enum or a
  `constexpr` map-descriptor array). The fake `xdpfilter_bpf` is a zeroed struct whose `maps.X`
  pointers are set to sentinel tags. Recommendation: a single `constexpr` descriptor table
  (`{tag → name, key_sz, val_sz}`) the sink and the fake `bpf_map__fd` share — guard #10 catalog
  arithmetic applies (the table must enumerate exactly the maps the write-set touches).

## Scope (cycle B43 — concrete items)

### Item B43-1 — extract `materialize` + render helpers into libbpf-free `src/lib/materialize.{hpp,cpp}`
**Where:** NEW `src/lib/materialize.cpp` (+ `.hpp` per Q2-A1); EDIT `src/lib/loader.cpp` (remove the
moved code, `#include "materialize.hpp"`, keep the apply call-sites calling the now-external
symbols). Near-pure move (B40/B34b precedent): `materialize` (loader.cpp:1637) + the `populate_*` /
`write_*` render helpers it calls + `populate_action_table` + `populate_redirect_devmap`. Per Q1,
the error machinery moves to its own shared TU first. **The LIVE apply path must produce
byte-identical writes** (prove via existing live ctests + `git diff` of the apply logic = pure
relocation).

### Item B43-2 — `tests/dryrun/dryrun_harness.cpp` + fake-bpf sink
**Where:** NEW `tests/dryrun/dryrun_harness.cpp`, NEW fake-bpf TU (recording
`bpf_map_update_elem`/`delete_elem`/`get_next_key`/`bpf_map__fd`/`bpf_num_possible_cpus` +
`resolve_ifindex` stub), NEW fd-tag descriptor table (Q3). The harness: builds an in-memory `Config`
corpus (exercise LPM-closure, a same-key HASH aggregation, a port range, an unconstrained-axis
wildcard, ≥1 Pass + ≥1 Drop, AND a `steering: redirect` rule so `action_table`+`redirect_devmap`
are non-trivial), runs `compile()` → `cr`, then drives the **3-call sequence**
`materialize(fake_skel, slot, cr)` → `populate_action_table(at_fd)` →
`populate_redirect_devmap(dm_fd, config)`, captures the recorded write-set, formats it per the
golden spec, and compares.

### Item B43-3 — golden fixture + `T_DRYRUN_IMAGE_IDENTITY` ctest (libbpf-free)
**Where:** NEW golden fixture (under `tests/dryrun/` or `tests/fixtures/`), EDIT
`tests/CMakeLists.txt` (add the `dryrun_harness` executable + `T_DRYRUN_IMAGE_IDENTITY` test, wired
EXACTLY like `compile_harness`: links `{materialize.cpp, compiled_ruleset.cpp, loader_error.cpp,
fake-bpf TU}` ONLY, **no `PkgConfig::LIBBPF`, no `*_skel` dep, no `RESOURCE_LOCK`, no
`XDPMF_CI_BUILD_ONLY` skip**). Mandatory SMOKE + NEGATION controls inside the harness.

## Out of scope (explicit)

- **`apply --dry-run` CLI verb + human-decoded operator view** (PO ruling ① → slice 1b follow-on;
  same underlying image, zero rework).
- **Option 4 slice-2 bounded gate-shrink** (migrate the image-side of genuinely-split live ctests —
  `T_APPLY_VALID_CONFIG`/`T_APPLY_REPLACES_RULESET`/`T_REDIRECT_COUNTER_AND_MAP` — and thin them).
  A separate slice AFTER the golden format freezes; this slice is purely ADDITIVE coverage,
  touches NO existing live ctest.
- **Typed `MapImage` API / factored `render()`** (Option 3 — YAGNI, no consumer; link-seam gives
  SSoT). Not unless SPIKE-1 had failed (it passed).
- **`copy_rule_counters_forward` in the image** (irreducibly live — reads old-active inner).
- **VERSION bump** (no behavior/feature change).

## Definition of done

- §5.76 amendment in `mint/design.md` (Q1/Q2/Q3 resolved; HG defaults confirmed or overridden).
- NEW `src/lib/materialize.{hpp,cpp}` (+ `loader_error.{hpp,cpp}` per Q1-A1); loader.cpp apply path
  byte-identical (live ctests green + diff = pure relocation).
- NEW `tests/dryrun/dryrun_harness.cpp` + fake-bpf TU + golden fixture; `T_DRYRUN_IMAGE_IDENTITY`
  passes, links libbpf-free, with SMOKE + NEGATION.
- PI continuity: PI-7 loader.hpp zero-diff (Q2-A1), PI-mvp-4.35-VERDICT-IDENTITY, insn 3477,
  CompiledRuleset/RulesetDelta shapes, B42 redirect verb — all preserved.
- Full local ctest suite green (the live datapath gate still passes — the move didn't change writes).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies

- Build: clang-19 / libc++ / C++23 (existing). `<bpf/libbpf.h>` must be on the harness COMPILE
  include path (the skel header `#include`s it) — at `/usr/include/bpf/libbpf.h`; treat the build
  dir as `-isystem` per `bitvec_harness`. NOTHING from libbpf at LINK (SPIKE-1).
- Runtime: none new — the harness is a bare-main offline binary (no root, no veth, no kernel).

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

**Mechanical / single-axis → single-architect `/mint-dev` is correct.** The design space was just
closed by the 2026-06-06 `/mint-hld` round (Option 1 selected, reviewer pass r2, grounder
clean-with-gates); the one load-bearing uncertainty (SPIKE-1: does the fake skel link libbpf-free?)
was DISCHARGED PASS this session. The 2 surviving PO-plate forks were ruled by the PO (golden-only,
gate-shrink-as-separate-slice) and baked into the architecture doc. The 4 disguised-PO items were
reclassified to engineering and re-grounded here. No multi-axis residue → NO further `/mint-hld`.

## Notes for architect Phase A code-grep discipline

Re-run independently (briefer ran these; verify + extend):
- `grep -nE 'materialize\(|populate_action_table\(|populate_redirect_devmap\(|copy_rule_counters_forward\(' src/lib/loader.cpp` — confirm the 3-call sequence + the EXCLUDED copy-forward at BOTH apply branches (currently 2136-2154 / 2258-2273; line numbers volatile — anchor on names).
- `grep -nE 'close_prefixes6?|close_fn\(|populate_bitvec_inner_slot' src/lib/loader.cpp` — confirm closure stays at `populate_bitvec_inner_slot` (~1266) and masks are post-closure ⇒ golden carries post-closure bits.
- `grep -nE 'LoaderCategory|loader_error_category|throw_loader|classify' src/lib/loader.cpp src/lib/loader.hpp` — size the error-machinery cluster for the Q1 shared-TU extraction; confirm it is host-only (`std::error_category`, no libbpf).
- `sed -n '1180,1715p' src/lib/loader.cpp | grep -cE 'bpf_object__|skeleton|bpf_program__'` — confirm render subset's only libbpf surface is flat map-op wrappers (briefer got 0 for the heavy symbols).
- Confirm where `materialize` is currently DECLARED (header vs loader.cpp-local) to protect the PI-7 loader.hpp zero-diff streak under Q2.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #9 (helper-location: duplicate-over-extract for byte-identity / share-don't-duplicate for non-values):** the render extraction is a MOVE not a re-impl — the harness drives the SAME `materialize` the live path calls (single source of truth; a parallel image-builder is the explicit anti-pattern). For the error machinery (a `std::error_category` singleton + throw helper, NOT a value) SHARE via one TU; do NOT duplicate (ODR).
- **Guard #10 (catalog arithmetic):** the fd-tag descriptor table (Q3) must enumerate EXACTLY the maps the apply write-set touches — count them against `materialize` + `populate_action_table` + `populate_redirect_devmap`.
- **Guard #12 (RESOURCE_LOCK for shared host state):** `T_DRYRUN_IMAGE_IDENTITY` touches NO shared host state (no bpffs, iface, port, root) → it MUST NOT take `RESOURCE_LOCK xdp_fixture` (mirrors `compile_harness`/`ruleset_delta_harness`).
- **Guard #36 (dumb-aggregate / value-type discipline):** the recorded write-set + the in-memory image are dumb value aggregates; keep formatting logic separate from capture.
- **PI-7 (loader.hpp zero-diff streak):** prefer the new `materialize.hpp` over touching loader.hpp (Q2-A1).
