# Design-brief — `apply --dry-run`: the output contract + the offline/live test boundary

## Topic

Roadmap item ① (PO Dmitry, locked 2026-06-05): add **`apply --dry-run`** — print the
would-be map-image OFFLINE, without touching the kernel — and use it to **migrate the
"config → map-image" correctness class out of the live datapath**. This is the missing
*RuntimeImage consumer* the loader-datamodel HLD parked: the host-side pipeline is now cleanly
layered (`RawConfig → ValidatedConfig → CompiledRuleset → materialize → maps`), `compile()` is
already offline-tested (`compile_harness`), but the **last host-side step — `materialize()` —
is coupled to a live `xdpfilter_bpf*` skeleton and is therefore tested ONLY live** (netns +
root + BPF). dry-run closes that gap by rendering the image a real run would write, offline.

This round designs **ONE load-bearing fork** (PO scoping: a *light* design-pass, not a full
capability HLD): the **dry-run OUTPUT CONTRACT** — because that output becomes the **input
oracle of a golden test**, so its shape is an API, not a print statement. Concretely:

> What does `apply --dry-run` emit, in what representation, at what slice of the map-image — and
> where exactly does the offline/live test boundary fall — such that the "config → map-image"
> correctness class moves to an offline CI-green golden while "map-image → packet verdict/
> delivery" stays the (irreducible) live datapath surface, WITHOUT forking `materialize()` into
> a second sources-of-truth or over-building a format for tests that don't exist yet?

## Grounding (architects: verify against code; don't trust verbatim)

- **The pipeline is already layered + half-tested offline.** `compile(const Config&) ->
  CompiledRuleset` (`src/lib/compiled_ruleset.{hpp,cpp}`) is a pure, libbpf-free lowering,
  already asserted offline by `tests/compile/compile_harness.cpp` (`T_COMPILE_LOWERING_IDENTITY`,
  bare-main, links `compiled_ruleset.cpp` ONLY — a clean libbpf-free link is itself the contract).
  `RulesetDelta` (`src/lib/ruleset_delta.{hpp,cpp}`) is likewise offline-tested
  (`ruleset_delta_harness.cpp`). **The untested-offline step is the one between
  `CompiledRuleset` and the kernel: `materialize()`.**
- **`materialize()` is the render step, and it is welded to the live skeleton.**
  `void materialize(xdpfilter_bpf* skel, std::uint32_t slot, const CompiledRuleset& cr)`
  (`src/lib/loader.cpp:1637`) and its helpers (`populate_rules_inner_slot:1380`,
  `populate_action_table:1540`, the redirect_devmap write `:1573-1587`, `ruleset_state` /
  `active_idx` writers `:1325-1366`) each turn the CompiledRuleset into concrete
  `bpf_map_update_elem(fd, &key, &val, …)` calls against `skel->maps.*` (~13 maps: allowlist
  LPM v4/v6 dst+src, port_inner, rules_inner, slot_rule_id, ruleset_state, active_idx,
  action_table, redirect_devmap, rule_counters_inactive). **The "map-image" = the full ordered
  set of (map, key, value) writes materialize would issue.** Whatever dry-run prints, THIS is
  the thing being rendered; the central architectural question is how to produce that image
  offline without a second reimplementation (the compile_harness header's own warning: a
  PARALLEL reimplementation is the anti-pattern — guard #9 byte-identity discipline).
- **The CLI seam exists.** `apply` is parsed at `src/cli/cli.cpp:369` (`parse_apply`). There is
  currently **no `dry-run` / `dry_run` token anywhere** in `src/` (greps clean) — this is net-new
  surface. The dry-run flag must thread through the apply request the same way the existing
  apply path does.
- **The live test surface that would migrate.** The veth/netns ctests (`tests/CMakeLists.txt`,
  RESOURCE_LOCK `xdp_fixture`) include a large "config → behavior" cohort whose CONFIG-SIDE
  (does this config produce the right map-image?) is currently only observable by running the
  datapath: e.g. `T_APPLY_VALID_CONFIG`, `T_APPLY_REPLACES_RULESET`,
  `T_IDEMPOTENT_RELOAD`, `T_REDIRECT_COUNTER_AND_MAP`, the oracle-agreement family. Their
  VERDICT-SIDE (does the map-image produce the right packet verdict/delivery?) is irreducibly
  live. dry-run lets the config-side half become an offline golden; the verdict-side half stays
  live. (Architects: confirm which ctests actually split this way — not all do.)
- **Precedent for the test style + the CI reframe this extends.** `compile_harness` /
  `ruleset_delta_harness` are the offline bare-main, libbpf-free pattern. B39/MVP-4.32
  (`XDPMF_CI_BUILD_ONLY=1`) already moved the non-privileged subset to hosted CI; this round
  *extends that boundary toward the kernel* — every config-side assertion dry-run unlocks is a
  new CI-green check, shrinking the local-root-only datapath gate.

## Design space (seeds — enumerate ALL viable, then select by diversification)

Non-exhaustive; the band must go beyond these and score them:

- **How the image is produced offline** (the crux — must not fork materialize into 2 truths):
  (a) a **recording fake** — a thin `bpf_map_update_elem` capture sink / fake-fd that the
  EXISTING `materialize()` writes into (one code path, prints what it recorded; needs
  materialize decoupled from `skel->maps.*` to an injectable map-handle); (b) a **`render()`
  pure function** factored OUT of materialize that returns the image as data, which BOTH the
  live path (then issues the bpf calls) and dry-run consume (single source, but a real
  refactor of loader.cpp); (c) a **parallel image-builder** in the dry-run path (REJECT-candidate
  — the guard-#9 anti-pattern; name it only to kill it). Score on single-source-of-truth.
- **Output representation**: human pretty-print (operator reads it) vs a machine-checkable
  **golden** (stable, diffable, the test oracle's input) vs **both** (human view + a
  `--format=json|golden` machine view). Determinism contract for a golden: stable map/key
  ordering, no kernel fds / addresses / timestamps / run-to-run nondeterminism, endianness.
- **Image slice / granularity**: the full map-by-map (map, key, value) dump; vs a higher-level
  per-rule/per-axis summary (slots, bits, action, target); vs the `CompiledRuleset` itself
  printed (but that's pre-materialize — misses the map-key lowering dry-run exists to cover); vs
  the `RulesetDelta` (a *diff* view — relevant to apply-over-existing, maybe a later mode). Which
  slice is the RIGHT oracle for the "config → map-image" class?
- **Test-boundary discipline**: which existing live ctests' config-side actually migrates;
  what the new offline golden harness looks like (a `dryrun_harness` in the compile/delta mold,
  or golden-file fixtures under `tests/fixtures/`); and the bound — migrate ONLY what dry-run
  newly covers, NOT a blanket test rewrite.

## Constraints / invariants

- **Single source of truth — do NOT fork `materialize()`.** The whole value is that dry-run
  renders *the same image the live path writes*. A parallel image-builder that drifts from
  materialize is worse than no dry-run (it would assert a fiction). Whatever the mechanism, the
  live and dry-run images must be provably the same code (guard #9 / the compile_harness
  no-reimplementation discipline).
- **Compose, don't disturb.** PASS/DROP datapath byte-identity, `PI-mvp-4.35-VERDICT-IDENTITY`,
  the insn baseline (3477), the double-buffer atomic swap, PI-7 loader.hpp, the
  `CompiledRuleset`/`RulesetDelta` shapes, and the redirect verb (B42) must all survive. dry-run
  is **read-only and offline** — it must make ZERO kernel calls and write NO maps.
- **The output is a contract.** Once a golden test consumes dry-run output, its format is an
  API: a casual format change breaks the oracle. Treat stability/versioning explicitly.
- **Bounded test-migration.** "dry-run-DRIVEN" = migrate the config-side of tests dry-run newly
  covers, then thin/retire the now-redundant heavy ctests — NOT a blanket rewrite. The boundary
  is "what dry-run newly proves offline", nothing wider.
- **Offline means offline.** The dry-run path + its golden harness must link libbpf-free where
  possible (the compile_harness contract) OR, if materialize can't fully decouple from the
  skeleton, the design must say exactly what minimal kernel-shaped dependency survives and why.

## Out of scope

- **per-rule redirect targets (Option 2)**, **mirror/TC costing**, **rate-limit** — roadmap ②③④,
  not this round. dry-run must not foreclose printing a future `target_id`, but does not design it.
- **A full apply rewrite.** The live apply path stays; dry-run is an additive read-only mode.
- **Replacing the live datapath gate.** The "map-image → packet verdict/delivery" class
  (oracle-agreement, SELECT-B redirect delivery) stays live — dry-run does NOT try to test it.

## What a good outcome looks like

A recommended **dry-run output contract**: (1) the offline image-production mechanism (recording
fake vs factored `render()` vs — rejected — parallel builder), scored on single-source-of-truth
vs refactor cost; (2) the output representation (human / golden / both) with the golden's
determinism + versioning contract spelled out; (3) the image slice that is the right oracle for
the config→map-image class; (4) the offline/live test-boundary principle + the concrete (bounded)
list of which ctests' config-side migrates and what the new golden harness looks like; (5) a lean
slice decomposition (is dry-run-the-CLI-feature one slice and the test-migration a second? or
co-shipped?). The synthesis must flag where operator-UX, test-oracle-stability, and
refactor-cost disagree, and the grounder must surface the genuine PO forks (human-vs-golden-vs-both;
whether the materialize decouple is in-scope here or its own slice).

```yaml
architects:
  parallel:
    - name: image-render
      lens: "Render-mechanism engineer. You own the pivotal question every other lens depends on: how is the map-image produced OFFLINE without forking materialize() into a second source of truth. materialize() (loader.cpp:1637) is today welded to skel->maps.* via bpf_map_update_elem. Enumerate the ways to render the SAME image without the kernel: (a) a recording fake-fd / capture sink the existing materialize writes into (requires decoupling materialize from skel->maps.* to an injectable map handle/fd-abstraction — characterize that refactor precisely), (b) a pure render(CompiledRuleset)->Image factored OUT of materialize that both live-apply and dry-run consume (single source, bigger loader.cpp refactor), (c) a parallel image-builder in the dry-run path (the guard-#9 anti-pattern — name it ONLY to kill it, with the drift argument). Score each on single-source-of-truth strength, refactor blast-radius on loader.cpp, and whether it links libbpf-free. You see the bpf_map_update_elem coupling, the populate_* helper structure, and the double-buffer slot/active_idx writes the format/boundary lenses treat as a black box. Do NOT design the output text format (image-format's call) or which tests migrate (test-boundary's call)."
      scope: "Enumerate ALL viable offline-render mechanisms (recording-fake / factored-render / parallel-builder-REJECT, plus any you find), score on single-source-of-truth + loader.cpp refactor cost + libbpf-free-linkability + PASS/DROP byte-identity non-disturbance, select 1-2 by diversification, justify, and detail exactly what changes in materialize()/loader.cpp and what the rendered Image data structure is (the in-memory thing, before formatting). Characterize the materialize-decouple refactor's blast radius precisely (which helpers, what signature change, does it touch the live write path's byte-identity). Verify against src/lib/loader.cpp (materialize:1637, populate_action_table:1540, populate_rules_inner_slot:1380, redirect_devmap:1573, ruleset_state/active_idx:1325-1366), src/lib/compiled_ruleset.hpp. Do NOT decide human-vs-golden text format or the test-migration list — defer."
      sources:
        - "src/lib/loader.cpp — materialize:1637 + populate_* helpers + bpf_map_update_elem call sites (the welded-to-skel render step to decouple)"
        - "src/lib/compiled_ruleset.{hpp,cpp} — the CompiledRuleset input + the compile_harness libbpf-free precedent the render path should match"
        - "src/cli/cli.cpp:369 (parse_apply) — where the --dry-run flag threads into the apply request"
    - name: image-format
      lens: "Output-contract & operator-UX architect. The dry-run output is consumed by TWO audiences with different needs: an operator eyeballing 'what would apply do?' (readable, oriented to rules/actions) and a golden TEST asserting byte-stability (deterministic, diffable, no nondeterminism). You own the representation + the stability/versioning contract. Score human-pretty-print vs machine-checkable-golden vs both (human default + --format=json|golden). For a golden you OWN the determinism contract: stable map+key ordering, endianness, NO fds/addresses/timestamps/pointers, reproducible across runs+hosts; and the format-versioning story (the output is an API the oracle binds to). You take the rendered Image (image-render's output) as given data — you decide how it SERIALIZES. Do NOT decide how the image is produced (image-render) or which tests consume it (test-boundary)."
      scope: "Design the dry-run output representation: score human / golden / both, recommend one, and FULLY specify the golden's determinism contract (ordering, byte-stability, what's excluded, endianness) + a format-versioning/stability policy (this is a test oracle's input API). Specify the image SLICE that is the right oracle for the config→map-image class (full map-by-map (map,key,value) dump vs per-rule/per-axis summary vs CompiledRuleset-print vs RulesetDelta-diff) — argue which slice actually covers the materialize lowering dry-run exists to assert (a CompiledRuleset print does NOT — it is pre-materialize). Show a concrete worked example of the chosen output for a small 2-3 rule config (incl. a redirect rule). Take the render mechanism as given; defer the migration list. Verify the map set + key/value shapes against loader.cpp populate_* + src/common/xdpfilter.h ABI + docs/CONFIG_SCHEMA.md."
      sources:
        - "src/lib/loader.cpp populate_* — the actual (map,key,value) shapes that must serialize deterministically"
        - "src/common/xdpfilter.h — the ABI of the values (rule_entry/action_entry/cidr/mac) the golden serializes; byte-order + padding concerns"
        - "tests/compile/compile_harness.cpp + tests/fixtures/ — the offline assertion + fixture style the golden should match; docs/CONFIG_SCHEMA.md for the operator-facing vocabulary"
    - name: test-boundary
      lens: "Test-boundary & migration architect. dry-run's PRODUCT value is the CLI verb; its TEST value is moving the config→map-image correctness class offline (CI-green) and leaving only map-image→verdict/delivery live. You own the boundary placement + the bounded migration. For the live veth/netns ctest cohort, classify each candidate as: (i) config-side migratable to an offline dry-run golden, (ii) verdict/delivery-side irreducibly live, (iii) genuinely both (split into an offline golden + a thinned live check). You see what compile_harness/ruleset_delta_harness already cover offline, what the dry-run golden newly covers, and the bound: migrate ONLY what dry-run newly proves — NOT a blanket rewrite. You take the output format (image-format) + render mechanism (image-render) as given."
      scope: "Define the offline/live test boundary as a PRINCIPLE (config→map-image = offline golden; map-image→verdict/delivery = live), then apply it concretely: walk the live ctest cohort (T_APPLY_VALID_CONFIG, T_APPLY_REPLACES_RULESET, T_IDEMPOTENT_RELOAD, T_REDIRECT_COUNTER_AND_MAP, the oracle-agreement family, etc. — VERIFY which actually split) and classify each migratable / irreducibly-live / split. Specify the new offline golden harness (a dryrun_harness in the compile/delta mold, or golden fixtures under tests/fixtures/ + a driver) and the CI wiring (this extends the B39 XDPMF_CI_BUILD_ONLY boundary toward the kernel). State the explicit BOUND (what stays live, why). Take render+format as given; defer them. Verify against tests/CMakeLists.txt + the named ctest .sh files + tests/compile|delta."
      sources:
        - "tests/CMakeLists.txt + tests/T_APPLY_*.sh / T_IDEMPOTENT_RELOAD.sh / T_REDIRECT_COUNTER_AND_MAP.sh / oracle-agreement .sh — the live cohort whose config-side may migrate"
        - "tests/compile/ + tests/delta/ — the offline bare-main libbpf-free harness pattern the dryrun golden harness should follow"
        - "src/cli/common.sh or the CI gate (XDPMF_CI_BUILD_ONLY, B39/MVP-4.32) — the boundary this round extends toward the kernel"
  sequential:
    - name: contrarian
      lens: "Skeptical staff engineer. You read image-render + image-format + test-boundary and ask what none is incentivized to: is the materialize-decouple refactor actually IN-SCOPE for this slice, or does it dwarf the dry-run feature and deserve its own slice first? Is 'both human + golden' gold-plating when one audience could be served now? Could the config→map-image class be covered by simply EXTENDING compile_harness to drive materialize against a fake fd — making 'dry-run the CLI feature' and 'the offline test' two separable things, where only ONE is on the critical path? Is the test-migration scope-creeping past 'what dry-run newly covers'? What is the LEANEST first slice that delivers a real, test-bearing dry-run?"
      scope: "Read the three parallel outputs. Poke holes: is the render-decouple a hidden mega-refactor that should precede dry-run as its own slice (or conversely, is it small enough to co-ship); is human-AND-golden over-built for slice 1 (which single audience is load-bearing now); is the test-migration list creeping beyond the dry-run-newly-covers bound; does dry-run-the-feature actually need to ship for the test win, or is the fake-fd offline test the real prize with the CLI verb as a thin follow-on. Integrate into a single recommendation: the MINIMAL defensible first slice + an explicit now/defer split (CLI verb vs offline golden vs materialize-decouple vs test-migration) + the leanest output format. If 'offline-test-first, CLI-verb-second' or 'decouple-is-its-own-slice' is the honest answer, say so plainly."
      inputs: [image-render, image-format, test-boundary]
      sources:
        - "memory: project_session_handoff_2026-06-05 (the roadmap-① intent: dry-run-DRIVEN migration, output format = load-bearing fork) + project_libxdpmf_deferred (no-API-consumer discipline — dry-run is host-CLI, not a library API)"
        - "mint/architecture-loader-datamodel.md — the dry-run parking note (the 'missing RuntimeImage consumer' framing this round discharges)"

output:
  path: "mint/architecture-dryrun.md"
  mode: create

options:
  skip_design_reviewer: false
  max_rework_rounds: 2
```
