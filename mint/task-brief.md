# Task brief — MVP-4.29 / B34b: datapath module split (de-monolith part b) (brownfield)

## Goal

Split the (now helper-extracted) datapath monolith `src/bpf/xdpfilter.bpf.c` (live tree **1280 lines**, single `.c`) into per-concern header modules so the single translation unit reads as a set of cohesive includes instead of one 1280-line wall. This is **part (b)** of B34 — the explicit follow-up to B34a (§5.68, commit `8c9a110`), which extracted the shared idioms into in-file `static __always_inline` helpers + statement macros and **deferred the file split to a separate slice briefed against the POST-extraction tree** (the `#4-before-#5` ordering — boundaries only become legible once the arms shrank).

The §5.68 sketch named five candidate modules: `ipv4_match.h` / `ipv6_match.h` / `vlan.h` / `classifier.h` / `maps.h`. **That set is a sketch, NOT a contract** — the architect refines the final boundary set against the post-extraction tree (collapse a boundary that doesn't carry its weight; the entropy-control bar applies). The `.bpf.c` retains `SEC("xdp")` + the includes; the headers carry the moved code.

**Load-bearing contract: byte-identical pure code-movement.** A `#include` split changes nothing after preprocessing — the compiled datapath bytecode MUST be unchanged. Arbitrated by the B37 insn gate (`tests/T_INSN_BASELINE_GATE.sh` + `tests/T_PROD_VERIFIER_LOAD.sh`, objdump xdp-section instruction-line count `== ${XDPMF_PROD_INSN_BASELINE:-3658}`) re-run AFTER the split. This is the same guard B34a leaned on (xdp 3658).

## Context: prior work

- All prior briefs archived in `mint/task-brief-*.md` (B34a → `mint/task-brief-mvp-4.28.md`).
- Existing design: `mint/design.md` §5.68 (B34a helper-extraction) — most recent datapath section; names B34b in its OOS (`design.md:18380`).
- BACKLOG: `docs/BACKLOG.md:193` (B34 "datapath de-monolith: helpers → module split").
- B37 gate (the byte-identity teeth this slice rests on): §5.67, `tests/T_PROD_VERIFIER_LOAD.sh` FATAL-asserts `== 3658` with the `XDPMF_PROD_INSN_BASELINE` escape hatch named in the failure message.
- Brief-author Phase 2 grep verification: ran the file/symbol/build/gate greps below (see evidence footer).
- PI continuity: PI-7 (C++/header tree zero-diff) continues trivially. **PI-mvp-4.28-NONDATAPATH-ZERO is EXTENDED, not continued verbatim** — see HG-mvp-4.29-3.

## Workflow rules (brownfield)

- **Architect**: read `design.md` §5.68 (the B34a extraction it builds on) + §6.5 invariants + the B37 gate sections; EDIT `design.md` in place; append a new §5.69 (MVP-4.29). Owns the final module boundary set + include style + the BpfBuild.cmake dependency question (HG-mvp-4.29-2).
- **Impl**: FileList per brownfield mode. The move is mechanical (cut from `.bpf.c`, paste into `.h`, add `#include`); the discipline is running the B37 gate after the split and NOT letting any `mov`/verdict-merge creep in (none should — same TU).
- **Tester**: NO new behaviour to test. Re-run the existing B37 gate (`T_INSN_BASELINE_GATE`, `T_PROD_VERIFIER_LOAD`) as the acceptance oracle. Add a NEW ctest ONLY if the architect identifies a split-specific regression surface (e.g. a "no `src/bpf/*.h` orphaned / every header included exactly once" structural assert) — otherwise the insn gate IS the test.
- **Reviewer**: 5-point brownfield framework. Special attention: (a) xdp insn count `== 3658` post-split (byte-identity); (b) no header included more than once / no double-definition (ODR within the single TU); (c) PI-7 + extended-NONDATAPATH-ZERO diff fences; (d) the new headers carry ONLY moved code — zero behavioural edit smuggled into the move.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.29-1: module boundary set → **default = §5.68 five-file sketch, architect refines against post-extraction tree**
`maps.h` (the 39 `SEC(".maps")` map definitions + their inner structs, currently ~lines 91–460 — the cleanest, biggest cut), plus the match/classifier split across `ipv4_match.h` / `ipv6_match.h` / `vlan.h` / `classifier.h`. The architect MAY collapse boundaries that don't carry weight (e.g. fold `ipv4_match.h`+`ipv6_match.h` if the post-extraction arms are too thin to justify two files) — fewer, cohesive files beat five thin ones. The entropy-control bar (don't manufacture structure) governs. **Architect-overridable with a one-line rationale per merged/kept boundary.**

### HG-mvp-4.29-2: BpfBuild.cmake header-dependency GLOB → **default = ADD `src/bpf/*.h` to `_shared_headers`**
`cmake/BpfBuild.cmake:28-31` GLOBs only `src/common/*.h` + `include/*.h` into the `DEPENDS` of the BPF compile command. New `src/bpf/*.h` headers would therefore NOT trigger an incremental rebuild when edited → stale-object footgun. Default: add `${CMAKE_SOURCE_DIR}/src/bpf/*.h` to that GLOB (build-correctness, derivable — NOT a PO fork). This is the ONE edit outside `src/bpf/` this slice needs; it is NOT `src/lib|common|cli|exporter` so PI-7 is unaffected. Architect confirms / picks an equivalent (explicit `DEPENDS` list).

### HG-mvp-4.29-3: NONDATAPATH-ZERO invariant → **EXTEND, do not inherit verbatim**
B34a's `PI-mvp-4.28-NONDATAPATH-ZERO` forbade ANY new `.h`/file. This slice's whole point is new `src/bpf/*.h` files, so the architect RE-STATES the invariant for B34b: NEW files allowed ONLY under `src/bpf/`; `git diff -- src/lib src/common src/cli src/exporter` MUST stay ∅; `git diff -- src/common/xdpfilter.h` MUST stay ∅. The only sanctioned non-`src/bpf/` touch is the HG-2 CMake dependency line. Cite the retired B34a PI text verbatim per [[impl-role-discipline]].

## Open mechanism questions (architect decides; document in §5.69)

### Q1: include path style for the new headers
- **A1**: relative quoted — `#include "maps.h"` (resolves relative to the including `.bpf.c`, which lives in `src/bpf/`).
- **A2**: src-rooted — `#include "bpf/maps.h"` (via the existing `-I${CMAKE_SOURCE_DIR}/src`, mirroring the current `#include "common/xdpfilter.h"`).
- **Recommendation**: **A1** for the sibling `src/bpf/*.h` headers (shortest, conventional for co-located headers); keep the existing `"common/xdpfilter.h"` form untouched. Architect's call — low-stakes, no codegen impact.

### Q2: include-guard convention for the new headers
- **A1**: `#pragma once`.
- **A2**: classic `#ifndef XDPMF_BPF_MAPS_H` triple.
- **Recommendation**: match whatever the existing project headers use (`grep` `src/common/*.hpp` / `include/*.h`); pick the dominant form. Pure consistency choice.

## Scope (cycle MVP-4.29 — concrete items)

### Item B34b-1 — carve `maps.h`
**Where**: NEW `src/bpf/maps.h`; cut from `src/bpf/xdpfilter.bpf.c`.
Move the map-definition block (the 39 `SEC(".maps")` objects + their `xdpmf_*_inner` struct definitions + the `rulesets`/`rules`/`rule_counters` ARRAY_OF_MAPS wrappers, currently ~lines 91–460). The cleanest, lowest-risk cut — pure data declarations.

### Item B34b-2 — carve match/classifier headers
**Where**: NEW `src/bpf/{ipv4_match,ipv6_match,vlan,classifier}.h` (final set per HG-1); cut from `src/bpf/xdpfilter.bpf.c`.
Move the `static __always_inline` helpers + statement macros into their cohesive homes:
- `vlan.h`: `l3_after_vlan` (`:577`).
- shared/classifier: `bump_stat` (`:463`), `bump_rule` (`:480`), `first_set_u64` (`:508`), `port_scan` (`:541`), `mac_axis` (`:683`), `DISPATCH_MATCH` (`:623`), `LOOKUP_INNER_OR_DROP` (`:657`), `READ_DPORT` (`:711`).
- The per-family AND-composition arms move into `ipv4_match.h` / `ipv6_match.h` (or a merged `match.h` per HG-1).
Architect assigns each helper/macro to a module against the post-extraction tree.

### Item B34b-3 — reduce `xdpfilter.bpf.c` to includes + `SEC("xdp")`
**Where**: EDIT `src/bpf/xdpfilter.bpf.c`.
After the carves, the `.c` retains: the top `#include` block (vmlinux, bpf helpers, `common/xdpfilter.h`) + the new `#include "…"` lines (in dependency order — `maps.h` before the match headers) + the `SEC("xdp")` program (`:730`+) + `char _license[] SEC("license")`. Include ORDER matters for the single TU (maps before consumers).

### Item B34b-4 — BpfBuild.cmake dependency (per HG-2)
**Where**: EDIT `cmake/BpfBuild.cmake` (`_shared_headers` GLOB, `:28-31`).
Add `src/bpf/*.h` so header edits trigger BPF rebuild. One-line change.

## Out of scope (explicit)

- **ANY behavioural / codegen change.** If the split shifts the insn count off 3658, the split is wrong (not the baseline) — fix the move, do NOT bump `XDPMF_PROD_INSN_BASELINE`. (The escape hatch is for *intentional* codegen changes; B34b has none.)
- **Schema / axis / map-count / VERSION change** — none. VERSION stays 0.16.0.
- **`src/lib` / `src/common` / `src/cli` / `src/exporter`** — zero diff (PI-7). `src/common/xdpfilter.h` — zero diff.
- **B35** (ruleset_state / wildcard-pack — where the B34a-dropped fold #2 `load_wildcards` belongs) — separate follow-up slice, MEASURE-FIRST (`docs/BACKLOG.md:196`). The B34b module homes should leave a natural seam for it but NOT implement it.
- **`.bpf.c` → `.bpf.o` skeleton / loader changes** — the loader consumes the same single object; nothing downstream of the compile changes.

## Definition of done

- §5.69 amendment in `design.md` (B34b module boundary set + include style + HG resolutions + the extended NONDATAPATH-ZERO PI).
- PI-7 continues (C++/header tree zero-diff). PI-mvp-4.29-DATAPATH-IDENTICAL: xdp section `== 3658` post-split.
- ctest: existing baseline GREEN (esp. `T_INSN_BASELINE_GATE`, `T_PROD_VERIFIER_LOAD`); NEW structural ctest only if architect identifies a split-regression surface.
- No VERSION bump.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies

- Build: clang `-target bpf` (existing, `cmake/BpfBuild.cmake`); `-I${CMAKE_SOURCE_DIR}/include -I${CMAKE_SOURCE_DIR}/src` already on the compile line.
- Runtime: none new.
- Kernel/platform: none new (byte-identical object → same verifier acceptance as today; dev floor 6.1, prod floor 5.15 unchanged).

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  [lang/bpf.md, lang/cmake.md]   # BPF idioms + the BpfBuild.cmake header-dep GLOB (HG-2)
  impl:       [lang/bpf.md, lang/cmake.md]
  tester:     [test/bpf-xdp.md]              # NOTE: acceptance oracle is the B37 insn gate, not veth injection
  reviewer:   [test/bpf-xdp.md]
```

---

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])

**Mechanical / single-axis → single-architect via `/mint-dev`, NO `/mint-hld`.** The one design axis is "where to draw module boundaries", §5.68 already sketched it, and the byte-identity gate makes any boundary choice cheaply reversible (it's pure code movement — re-merge is a `cat`). Not expensive-to-undo; not ≥3-axis. The architect refining a sketched boundary set against the live tree is exactly Phase-1 single-architect work. The only non-`src/bpf/` decision (the CMake GLOB) is derivable build-correctness, not a PO fork — handled as HG-2 default, not a user gate.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief author already ran these (evidence footer); architect re-verifies independently + extends:

- `wc -l src/bpf/xdpfilter.bpf.c` → **1280** (NOT §5.68's 1327 — the post-extraction tree is smaller; guard #5: re-anchor every literal, do NOT trust this brief's line numbers — they will drift as you carve).
- `grep -nE '^(static __always_inline|#define [A-Z_]+\()' src/bpf/xdpfilter.bpf.c` → the 9 move-candidates (5 helpers + 4 macros, listed in B34b-2 with current line numbers).
- `grep -cE 'SEC\(".maps"\)' src/bpf/xdpfilter.bpf.c` → **39** map objects (the `maps.h` payload).
- `ls src/bpf/` → single `.c`, no `.h` yet; confirm each target `.h` is NEW (`! test -f`).
- `sed -n '25,55p' cmake/BpfBuild.cmake` → confirm the `_shared_headers` GLOB omits `src/bpf/*.h` (HG-2 rationale).
- After EACH carve (or at minimum once post-split): run the B37 gate / objdump xdp-section count and confirm `== 3658`. Re-measure recipe in the `bpf-spike-tooling` pack.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep discipline)** — ALWAYS applies; the live tree is 1280 lines, not §5.68's 1327. Re-anchor every literal by pattern; line numbers in THIS brief are orientation, not contract.
- **Guard #9 (helper-location duplication-over-extraction)** — applies in SPIRIT (inverted): this slice MOVES helpers into co-located headers within the SAME TU — it does NOT extract into a cross-module shared abstraction or pull any stable external file into the edit surface. Watch that the split does not accidentally invite a "DRY across files" temptation; the contract is relocation, not abstraction.
- **Guard #35 / #36 (gate-as-sole-arbiter; statement-macro-over-value-helper for byte-identity)** — applies: B34a learned (D-mvp-4.28 Phase B) that even a value-returning helper form shifts the insn count (+3). The split MUST preserve the exact helper/macro FORMS as-extracted; moving them across a `#include` boundary changes nothing post-preprocessing, but any incidental reshaping (e.g. turning a macro back into a function "while we're here") will break 3658. The B37 gate is the sole arbiter.
- **Guard #12 (RESOURCE_LOCK for shared host state)** — applies ONLY if a NEW structural ctest touches the xdp fixture / a real load; if the acceptance oracle stays the existing B37 gate, no new lock surface.

### Evidence footer — brief-author Phase 2 grep verification

```
File/path:
  ✓ src/bpf/xdpfilter.bpf.c           1280 lines, single .c (will EDIT + carve from)
  ✓ src/bpf/{ipv4_match,ipv6_match,vlan,classifier,maps}.h   all absent (NEW)
  ✓ src/common/xdpfilter.h            exists (MUST stay zero-diff)
  ✓ cmake/BpfBuild.cmake              _shared_headers GLOBs common/*.h + include/*.h ONLY (HG-2)
  ✓ CMakeLists.txt:106                add_bpf_object(xdpfilter src/bpf/xdpfilter.bpf.c) — single TU, unchanged
  ✓ tests/T_INSN_BASELINE_GATE.sh     exists
  ✓ tests/T_PROD_VERIFIER_LOAD.sh     exists; FATAL-asserts == ${XDPMF_PROD_INSN_BASELINE:-3658}

Symbol/structure:
  ✓ 9 move-candidates: bump_stat:463 bump_rule:480 first_set_u64:508 port_scan:541
    l3_after_vlan:577 DISPATCH_MATCH:623 LOOKUP_INNER_OR_DROP:657 mac_axis:683 READ_DPORT:711
  ✓ 39 SEC(".maps") objects (maps.h payload)
  ✓ SEC("xdp") program at :730

Estimate corrections vs §5.68 sketch:
  §5.68 cited file as 1327 lines; LIVE tree (post-B34a) is 1280 → use 1280.

Surprising findings:
  • BpfBuild.cmake _shared_headers GLOB omits src/bpf/*.h → new headers wouldn't trigger
    incremental rebuild. Surfaced as HG-mvp-4.29-2 (the one sanctioned non-src/bpf/ edit).
```
