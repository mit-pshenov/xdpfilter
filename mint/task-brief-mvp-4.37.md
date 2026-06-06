# Task brief — MVP-4.37 / B44: `apply --dry-run` — production offline map-image render (brownfield)

## Goal

Roadmap-① slice 1b (PO Dmitry): ship the literally-named **`apply --dry-run`** — print the would-be
map-image OFFLINE (zero kernel calls, zero map writes, zero attach) and exit 0. B43/§5.76 shipped the
offline GOLDEN + the extracted libbpf-free `materialize.cpp`, but it produces the image via a
**TEST-ONLY link-seam** (the `dryrun_harness` links a fake `bpf_map__fd`/`bpf_map_*_elem` against
`materialize.cpp`). The PRODUCTION CLI binary links REAL libbpf, so it **cannot reuse that link-seam** —
it needs a PRODUCTION runtime mechanism to render the same `# xdpfilter-image v1` image without touching
the kernel. **That render mechanism is the load-bearing design fork of this slice** (Q1); the CLI verb
itself is thin on top of it.

The output content is already fixed (B43 ruling B: faithful dense final map-image, `# xdpfilter-image v1`,
§5.76.4(6a)). This slice does NOT redesign the format — it builds the production path that emits it and
the `--dry-run` verb that triggers it, and reconciles the B43 harness to drive the SAME production path
(stronger SSoT than B43's test-only fake).

## Context: prior work

- Prior brief: MVP-4.36/B43 `dryrun_harness` → archived `mint/task-brief-mvp-4.36.md`.
- Design to amend: `mint/design.md` (append §5.77); architecture `mint/architecture-dryrun.md` (the HLD
  image-render lens already scored the render-mechanism options — carry forward, NO new `/mint-hld`).
- Brief-author Phase 2 greps (confirmed against current code):
  - `materialize.cpp` has **36 map-op call sites** (`bpf_map_update_elem`/`get_next_key`/`delete_elem`)
    across 9 render helpers (`populate_hash/bitvec/port_inner_slot`, `write_ruleset_state`,
    `populate_rules_inner_slot`, `write_slot_rule_id`, `inactive_axis_fd`, `populate_action_table`,
    `populate_redirect_devmap`) + `materialize` — these are the seam insertion points the writer
    abstraction must thread.
  - `struct ApplyRequest` (`src/lib/apply_internal.hpp`) = `{iface, mode, config}` — **no `dry_run`
    field today** (clean addition).
  - `parse_apply` at `src/cli/cli.cpp:226`; dispatch at `:370`.
  - `dryrun_harness` (tests/CMakeLists.txt) compiles `{dryrun_harness.cpp, fake_bpf.cpp,
    materialize.cpp, compiled_ruleset.cpp, loader_error.cpp}` — the harness↔production-seam
    reconciliation point.
  - **No `dry-run`/`dry_run` token anywhere in `src/`** — net-new surface.
- PI continuity: PI-7 (loader.hpp ∅), PI-mvp-4.36-LIVE-IDENTITY (live apply writes byte-identical),
  insn 3477 (src/bpf ∅ — host-loader-only slice), the B43 golden + `T_DRYRUN_IMAGE_IDENTITY` (#112).

## Workflow rules (brownfield)

- **Architect (Phase A):** read `mint/architecture-dryrun.md` (image-render lens) + `mint/design.md`
  §5.76 (materialize/B43) + §6.5 invariants. Re-run the Phase-2 greps (esp. the 36 call sites + the
  harness link). EDIT `design.md`, append **§5.77**. Resolve Q1 (render mechanism) + Q2 (harness
  reconciliation) + Q3 (slice a/b split or co-ship) with evidence. **Architect owns realizability —
  the brief frames the fork; the architect picks the seam shape.**
- **Impl:** the production render seam + the CLI verb per the resolved design. The live apply path must
  stay byte-identical (the seam's live writer issues the SAME `bpf_map_update_elem (map,key,value)`
  tuples).
- **Tester:** keep `T_DRYRUN_IMAGE_IDENTITY` green (now ideally via the production seam); ADD a CLI-level
  test of `apply --dry-run` (a no-kernel offline invocation asserting the printed image + exit 0 + that
  NO map/attach happened — e.g. no bpffs pin created). MANDATORY: the dry-run-makes-zero-kernel-calls
  assertion, plus a NEGATION proving the assertion can fail.
- **Reviewer:** 5-point brownfield. Special attention: SSoT/guard-#9 (the production render drives the
  SAME `materialize`, not a parallel image-builder — the CLI dry-run and the harness must both route
  through the one production render path), PI-mvp-4.36-LIVE-IDENTITY (live writes byte-identical — diff
  the live apply path), the dry-run path makes ZERO kernel calls (no `bpf_map_update_elem`/attach
  reachable on the dry-run branch).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.37-1: output representation → **machine golden only** (`# xdpfilter-image v1`)
`apply --dry-run` emits the B43 golden format to stdout (default). The HUMAN-decoded operator
pretty-print (typed fields, CONFIG_SCHEMA vocabulary) is a SEPARATE concern → **defer to a thin
slice-1c** to keep THIS slice one-intent (the production render mechanism is the real work), UNLESS the
architect finds the human view falls out cheaply. Rationale: one-intent slice discipline; the machine
golden is the load-bearing contract (already frozen by B43); the human view is additive UX with its own
drift surface.

### HG-mvp-4.37-2: live apply behavior → **unchanged** (PO ruling)
The `--dry-run` flag is a read-only offline branch. Non-dry-run `apply` behavior is byte-identical to
today (the writer seam's live path = the current direct `bpf_map_update_elem` calls).

## Open mechanism questions (architect decides; document in §5.77)

### Q1: the production offline-render mechanism (THE load-bearing fork)
How does the production CLI render the image without the kernel (it cannot link the B43 test fake)?
- **A1 — object-seam (recommended):** introduce a thin `MapWriter`/`MapSink` abstraction (fn-ptr struct
  or small interface) that the 9 render helpers + `materialize` call instead of `bpf_map_update_elem`/
  `get_next_key`/`delete_elem` directly (36 call sites). The **LIVE writer** forwards to the real
  `bpf_map_*` (byte-identical writes → PI-mvp-4.36-LIVE-IDENTITY preserved); the **DRY-RUN writer**
  records the ordered `(map,key,value)` trace. The recording writer + the image FORMATTER move into
  `src/lib` (production) so BOTH the CLI dry-run AND the B43 harness consume ONE production render path.
  Cost: ~36 call-site swaps + a signature thread through ~9 helpers + 2 writer impls. **Architect owns
  the exact seam shape** (writer-as-param vs a threaded context vs a `map_update()` wrapper free-fn);
  the brief does NOT prescribe the BPF/C++ mechanism.
- **A2 — factored render→MapImage:** pure `render(cr, slot, ifindex) -> MapImage`; the live path
  iterates the image issuing `bpf_map_update_elem`. Bigger refactor (HLD Option 3, deferred YAGNI);
  re-exposes live write-order to re-proof.
- **A3 — REJECT (parallel builder):** the CLI computes the image from `cr` via a reimplementation. This
  is the guard-#9 anti-pattern (a fiction that drifts from `materialize`). Named only to kill.
- **Recommendation:** A1 — smallest change that keeps the live path byte-identical AND unifies test+prod
  render (SSoT win). Architect confirms the 36-site count + picks the seam ergonomics.

### Q2: B43 harness reconciliation
With the production recording writer in `src/lib`, does the `dryrun_harness` retire/shrink its test-only
`fake_bpf` and drive the production seam directly?
- **Recommendation:** YES where the production seam subsumes the fake — the harness should test the
  PRODUCTION render path (stronger than a test-only fake). Keep `T_DRYRUN_IMAGE_IDENTITY` green; the
  `fake_bpf` may shrink to only what the production seam doesn't cover (e.g. the fake skel's `bpf_map__fd`
  tag mapping, if still needed). Architect scopes the exact retirement.

### Q3: slice a/b split vs co-ship
The mechanism (Q1, ~90% of the work) and the thin `--dry-run` CLI verb could split:
- **B44a** = the production render-seam + harness reconciliation (no CLI verb); **B44b** = the thin verb.
- OR co-ship both as one slice if the verb is genuinely thin once the seam exists.
- **Recommendation:** architect's call on sizing — co-ship IF the verb is thin once the seam lands; SPLIT
  if the object-seam refactor (36 sites + harness) is already a full slice. Do NOT bundle the human view
  (HG-1) regardless.

## Scope (cycle B44 — concrete items; architect refines)

### Item B44-1 — production offline-render seam (the Q1 mechanism)
**Where**: `src/lib/materialize.{cpp,hpp}` (the writer abstraction + thread it through the 9 helpers +
`materialize`), NEW production recording-writer + image formatter in `src/lib` (e.g.
`map_image.{hpp,cpp}` or folded into materialize — architect's call). The LIVE path stays byte-identical.

### Item B44-2 — `apply --dry-run` CLI verb
**Where**: `src/cli/cli.cpp` (`parse_apply` @:226 — accept `--dry-run`), `src/lib/apply_internal.hpp`
(`ApplyRequest` gains `bool dry_run`), the apply entry (on dry-run: `compile()`→`cr`, run the render via
the recording writer, format, print to stdout, exit 0 — BEFORE any skeleton load/attach/map write).

### Item B44-3 — harness reconciliation + CLI test
**Where**: `tests/dryrun/*` + `tests/CMakeLists.txt` (Q2: harness drives the production seam, `fake_bpf`
shrinks), NEW CLI-level ctest for `apply --dry-run` (offline, asserts printed image + exit 0 + zero
kernel side-effects + NEGATION).

## Out of scope (explicit)

- **Human-decoded operator pretty-print** (HG-1 → slice-1c, unless it falls out cheaply).
- **Option 4 slice-2 gate-shrink** (separate slice — migrate live ctests' image-side to the golden).
- **② per-rule redirect targets**, **③ mirror costing**, **④ rate-limit/mirror** (later roadmap).
- **VERSION bump** unless the architect deems the new CLI verb a user-facing feature warranting it
  (HG: default no-bump; it's additive read-only — architect's call).

## Definition of done

- §5.77 amendment in `mint/design.md` (Q1/Q2/Q3 resolved).
- Production render seam: live apply byte-identical (PI-mvp-4.36-LIVE-IDENTITY — live ctests green +
  diff); the recording writer + formatter in `src/lib`.
- `apply --dry-run` prints the `# xdpfilter-image v1` image offline, exit 0, ZERO kernel calls/map
  writes/attach.
- `T_DRYRUN_IMAGE_IDENTITY` green (ideally now via the production seam); NEW CLI dry-run ctest +
  NEGATION.
- PI continuity: PI-7 ∅, insn 3477 (src/bpf ∅), CompiledRuleset/RulesetDelta shapes, B42 redirect verb.
- Full local ctest suite green; `mint/review.md` round-1 = pass.
- One git commit per phase boundary.

## Dependencies

- Build: clang-19 / libc++ / C++23 (existing). No new deps (dry-run is host-only, no kernel).
- Runtime: the dry-run path needs NO root/veth/kernel; the CLI test runs offline.

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

**Single-axis design slice → single-architect `/mint-dev`, NO new `/mint-hld`.** The one design fork is
the production render-mechanism (Q1: object-seam vs factored-render vs reject-parallel-builder) — ONE
axis, already scored by the `mint/architecture-dryrun.md` image-render lens; the output format is frozen
(B43), the CLI threading is mechanical. 2-3 bounded HLD-informed options on one axis ≠ multi-axis. The
architect resolves Q1 with the 36-call-site grounding. (If the architect finds the object-seam refactor
explodes scope, that's a Phase-A sizing escalation → Q3 a/b split, not a new HLD.)

## Notes for architect Phase A code-grep discipline

Re-run independently (briefer ran these; verify + extend):
- `grep -cE 'bpf_map_update_elem|bpf_map_get_next_key|bpf_map_delete_elem' src/lib/materialize.cpp` —
  confirm the seam call-site count (briefer got 36) the writer abstraction must thread; enumerate which
  helpers take `int fd` vs derive it.
- `grep -nE 'struct ApplyRequest' src/lib/apply_internal.hpp` + `parse_apply` @ `src/cli/cli.cpp:226` —
  confirm the dry_run threading points (no field today; line numbers volatile — anchor on names).
- `grep -nE 'dryrun_harness|fake_bpf' tests/CMakeLists.txt` — the harness link set, to plan the Q2
  production-seam reconciliation (does the harness drive the production render after the seam lands).
- Confirm the dry-run branch can run BEFORE any skeleton load/attach (compile()→cr is libbpf-free; the
  render via the recording writer must not require a real skel — the object-seam must allow a
  null/sentinel skel on the dry-run path).
- `grep -rnE 'dry[-_]run' src/` — confirm net-new (briefer got zero).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #9 (SSoT, duplicate-over-extract / no parallel builder):** THE central guard — the production
  dry-run render MUST drive the same `materialize` the live path uses (the recording writer is a seam,
  NOT a reimplementation). The CLI dry-run + the B43 harness route through ONE production render path.
  A parallel image-builder in the CLI is [INVARIANT-VIOLATED].
- **Guard #36 (dumb-aggregate / value-type discipline):** the recording writer captures a dumb
  `(map,key,value)` trace; the formatter (trace→`# xdpfilter-image v1`) is separate from capture.
- **Guard #10 (catalog arithmetic):** if the fd-tag descriptor table moves to production, it must still
  enumerate exactly the maps the write-set touches.
- **PI-7 (loader.hpp zero-diff):** prefer materialize.hpp / new `src/lib` headers; do NOT touch
  loader.hpp.
- **PI-mvp-4.36-LIVE-IDENTITY:** the live writer's `(map,key,value)` writes are byte-identical to
  today — prove via the live apply ctests + a diff of the live path.
