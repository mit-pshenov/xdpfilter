# Design-brief — loader data-model cleanup (pre-mirror/redirect tidy)

## Topic

`src/lib/loader.cpp` (2819 LOC) drives the whole `Config → kernel` apply path. Its
**compile** half (pure, side-effect-free lowering of a validated `Config` into per-axis
bit-structures) is already physically separated from its **runtime** half (skeleton load,
pin classification, attach/reattach, double-buffer flip). But the apply pipeline carries
**four-plus distinct data models, several of which have never received a name or a
boundary** — and that, not the size of `loader.cpp`, is the load-bearing source of
complexity going into the next workstream.

This round answers ONE question, framed as a **pure, byte-identical cleanup**:

> Given the loader's apply pipeline already contains these partly-unnamed data models,
> what is the right set of **named entities + boundaries** to introduce as a tidy-up
> **before** the mirror/redirect (XDP→TC) workstream begins — and, critically, **is it
> worth doing now at all**, or is some of it gold-plating that should wait until TC forces
> the boundaries?

This is **NOT** a forward-architecture round. TC-redirect is, per PO, "nothing special —
everything as before"; the forward constraint here is *non-foreclosure only*, not design.

## The models, as they exist today (grounding — architects: verify against code, don't trust this verbatim)

1. **Validated `Config`** — `src/lib/config.hpp:62` (`Config{schema_version, iface,
   default_action, rules}`). Produced by `validate()` (config.cpp). This is the
   "normalized ruleset". Named, bounded, already test-covered. *Probably fine as-is.*

2. **Per-axis lowerings** — `loader.cpp:1387` (`AxisAggregate<Key>`, with aliases
   `MacLowering`/`ProtoLowering`/`VlanLowering`/`EthertypeLowering`), `AxisLowering`/
   `AxisLowering6`, `PortLowering` (`loader.cpp:1448`), `BitPrefix` (`loader.cpp:1165`,
   already `#include`d from `tests/bitvec`). These **have names** and are produced by pure
   functions (`aggregate_axis` `loader.cpp:1415`, `lower_axis`, `lower_port_axis`). The
   compile block in `apply_request` is `loader.cpp:2206–2293`; runtime begins at the
   `kernel_version_probe()` call (`loader.cpp:2296`).

3. **The compiled aggregate — UNNAMED.** There is no `struct CompiledRuleset`. Instead the
   compile output is **12 anonymous locals** in `apply_request` (`id_to_slot`, `slot_to_id`,
   `mac_low`, `dst_low`, `src_low`, `dst6_low`, `src6_low`, `proto_low`, `port_low`,
   `vlan_low`, `eth_low`, `default_action`) threaded **positionally** into the
   **16-argument** `populate_all_axes` (`loader.cpp:1903`). This is the sharpest smell.

4. **The id-reconciliation delta — UNNAMED, and hidden in plain sight.** `copy_rule_counters_forward`
   (`loader.cpp:1805`) is, in effect, a hand-rolled **CurrentState→DesiredState diff** over
   operator-id space: for each new slot it classifies the id as *survived* (copy counter),
   *new* (zero), *dropped* (discard), and handles *moved* (id kept its counter across a slot
   change — the whole point of B30 slot↔id decouple, §5.61). It is an **O(n²) nested loop**
   over two raw `std::span` arrays (`old_slot_to_id` / `new_slot_to_id`, `loader.cpp:1816–1834`),
   driven by a real requirement (Prometheus counter monotonicity, §5.35). The apply is
   therefore **not** a clean stateless recompute — this is the one place two state-versions
   meet, and the concept has no name.

5. **Kernel map materialization** — `populate_*_inner_slot` / `populate_all_axes`
   (`loader.cpp:1493+`, `1903`), writing the inactive double-buffer half + the single atomic
   `active_idx` flip (`write_ruleset_state`, §5.70 B35). This is runtime; stays runtime.

## Design space (seeds — enumerate ALL viable carvings, then select 2-3 by diversification)

Non-exhaustive starting points; the band must enumerate beyond these and score them:

- **Minimal**: name only the compiled aggregate (`CompiledRuleset` bundling the 12 locals),
  kill the 16-arg signature, leave the delta as-is.
- **Compile/materialize split**: `CompiledRuleset compile(const Config&)` (pure, = lines
  2206–2293) + `void materialize(skel, slot, const CompiledRuleset&)` (consumes the
  16-arg body). Explicit compile|runtime seam.
- **Name the delta**: extract a pure `RulesetDelta diff(old_slot_to_id, new_slot_to_id)`
  ({survived+remap, added, dropped}) from `copy_rule_counters_forward`; the counter copy
  becomes a thin consumer. (Bonus: O(n²)→O(n) with one map — but identity of *behavior*,
  not of code, is what's mandatory.)
- **Full staged pipeline**: `NormalizedRuleset → CompiledRuleset → RuntimeImage →
  materialize`, with `RuntimeImage` as a standalone in-memory map-image. (Likely overkill —
  the band should say so if so; `RuntimeImage`-as-snapshot has no current consumer.)
- **Where it lives**: in-place in `loader.cpp`; a new `compiled_ruleset.hpp`; or a small
  module. Weigh against the project's header/byte-identity ethos.

## Hard invariants (non-negotiable — this is cleanup)

- **Datapath byte-identity.** Zero behavior change. The project gates on **BPF instruction
  count identical across all 3 family arms** and **oracle-agreement on the test corpus**
  (see prior slices B30/B35: "3658→3437 −221 insns ×3, oracle-agreement held"). Any carving
  whose *only* defense is "it's cleaner" but that risks datapath drift is disqualified.
- **No new BPF-side anything.** Host-side C++ refactor of `loader.cpp` data models only.
- **Behavioral identity of `copy_rule_counters_forward`** if the delta is extracted: the
  survived/moved/new/dropped semantics + counter-monotonicity (§5.35) must hold exactly.
- **Project ethos**: macros-over-helpers where byte-identity demands it (guard #36); named
  abstractions must earn their keep, not become thin wrappers that obscure (the contrarian
  owns this critique).

## Forward constraint (LIGHT — non-foreclosure, NOT design)

The next workstream is **mirror/redirect (XDP→TC)**. PO: "TC появится… ничего особенного,
всё как было." The carving chosen here must **not foreclose** cheaply adding a redirect
action/target later (action space may grow from the pass/drop verdict). The forward-compat
lens checks **only non-foreclosure** — it must **NOT** design the TC entity, propose its
schema, or add machinery for it. A carving that would force a redo during mirror/redirect is
a strike; building *for* TC now is equally a strike (gold-plating).

## Explicitly OUT of scope

- **`apply --dry-run` / preview / `--diff`** — an additive *product* feature (it would print
  the `RulesetDelta`). Genuinely cheap once the delta is named, but it is NOT "tidy what
  exists"; parked for a later product decision. Do not design it here.
- **Plan-as-execution-engine** (incremental map create/update/remove) — rejected: maps are a
  fixed managed table (`kManagedMaps`), double-buffer flip already gives atomic swap +
  rollback. No forcing function.
- **mirror/redirect / TC design itself** — the next workstream, not this one.
- **The 64-rule ceiling** (`XDPMF_ALLOWLIST_MAX=64`) — a fixed architectural limit, not a
  work item.

## What a good outcome looks like

A recommended **named-entity set + boundary map** for the loader's data models, scored on
clarity / coupling-reduction / testability / non-foreclosure, with an explicit
**worth-it-now verdict** per entity (which to introduce before mirror/redirect, which to
defer, which to drop), a **byte-identity cutover oracle**, and a **suggested slice
decomposition** (this likely lands as 1-2 `/mint-dev` slices). Convergence is only a signal
if the lenses are independent — the synthesis must flag any carving where structure,
testability, and non-foreclosure disagree.

```yaml
architects:
  parallel:
    - name: structure
      lens: "Data-model cartographer. You see the apply pipeline as a sequence of typed values and the transformations between them. You own the question: WHICH of the 4+ models deserve a name, WHERE exactly the boundaries fall (compile|runtime seam; aggregate-vs-module vs minimal), and what each named entity owns vs leaks. You see coupling and conceptual-surface that the test/forward/skeptic lenses structurally cannot weigh."
      scope: "Enumerate ALL viable carvings of the loader data models (minimal -> compile/materialize split -> name-the-delta -> full staged pipeline), score each on conceptual clarity + coupling reduction + fit with the EXISTING named lowerings (AxisAggregate et al.), select 2-3 BY DIVERSIFICATION (not favorites), justify, detail the entity definitions + boundaries + where they live (in-place / new header / module). Do NOT decide testability (testability's call), non-foreclosure of TC (forward-compat's call), or worth-it-now (contrarian's call) — defer each explicitly. Read loader.cpp / config.hpp / apply_internal.hpp first-hand; verify the brief's line cites."
      sources:
        - "src/lib/loader.cpp — the apply pipeline (compile block ~2206-2293; populate_all_axes:1903; copy_rule_counters_forward:1805; lowerings 1165-1480)"
        - "src/lib/config.hpp / src/lib/apply_internal.hpp — the validated Config + the internal apply entry"
        - "mint/architecture-rule-model.md — prior rule-model architecture (Wave A/B), for the existing model vocabulary"
    - name: testability
      lens: "Verification engineer. You own the PAYOFF axis the structure lens can't price: what offline test surface each carving unlocks, and how the cutover is PROVEN byte-identical. Naming CompiledRuleset/RulesetDelta is worthless unless it lets us assert Config->bits and the survived/moved/new/dropped delta WITHOUT a kernel. You also own the cutover oracle: how the existing insn-count-x3 + oracle-corpus gate proves zero datapath drift across a pure refactor."
      scope: "For each candidate carving (take the structure lens's space as given — do NOT re-decide the shape), evaluate the testability/provability delta: what NEW offline unit tests become possible (e.g. Config->CompiledRuleset bit-identity; RulesetDelta truth-table without BPF), what the MINIMUM test scaffold is, and what the byte-identity cutover oracle should be (insn-count x3 arms + oracle-agreement corpus — cite how B30/B35 proved it). Recommend the carving that maximizes provable-correctness-per-effort. Defer structure shape to `structure`, non-foreclosure to `forward-compat`, worth-it to the contrarian."
      sources:
        - "tests/ — existing test harness; how bitvec/oracle/corpus tests are structured (BitPrefix is already #include'd from tests/bitvec per loader.cpp:1173)"
        - "src/lib/loader.cpp:1805 copy_rule_counters_forward — the un-unit-tested id-reconciliation"
        - "CHANGELOG / mint/design.md §5.70 §5.61 — how B30/B35 proved -221 insns x3 + oracle-agreement (the byte-identity gate to reuse)"
    - name: forward-compat
      lens: "Non-foreclosure sentry. You own ONLY one question: does each candidate carving paint us into a corner for the NEXT workstream (mirror/redirect, XDP->TC), where the per-rule action may grow from a pass/drop verdict to a redirect/mirror target? You are NOT a TC designer — you check seams, you do not build them."
      scope: "For each candidate carving, judge non-foreclosure ONLY: would naming the compiled action/verdict model THIS way make adding a redirect action/target later cheap or expensive? Flag any carving that would force a redo during mirror/redirect (a strike) — AND equally flag any carving that builds machinery FOR TC now (gold-plating, also a strike; PO: 'nothing special, all as before'). Recommend the cheapest non-foreclosing seam. Do NOT design the TC entity, its schema, or its maps. Do NOT weigh clarity (structure's) or testability (testability's) or worth-it (contrarian's)."
      sources:
        - "memory: project_real_requirements_and_strategy + project_dpi_pre_filter_purpose — the action/steering space (allow/drop/mirror/redirect/tag) at the spec level, for non-foreclosure context ONLY"
        - "src/bpf/defs.h + src/common/xdpfilter.h — current action representation (RuleAction / action_table) the TC work would extend"
        - "src/lib/loader.cpp populate_action_table:1851 + rules_inner population — where action lives in the compiled form today"
  sequential:
    - name: contrarian
      lens: "Skeptical staff engineer. You read structure + testability + forward-compat and ask the question none of them is incentivized to: is this cleanup worth doing BEFORE mirror/redirect at all, or is part of it gold-plating a 64-rule, microsecond-recompute problem? Does CompiledRuleset/RulesetDelta over-abstract, or become thin wrappers that fight the project's macros-over-helpers / byte-identity ethos (guard #36)? Where is the leanest cut that still earns its keep?"
      scope: "Read the three parallel outputs. Poke holes: which named entity is genuinely load-bearing vs decorative; whether the delta-extraction risks datapath/behavior drift for marginal gain; whether any of it should DEFER until TC forces the boundary (let the next workstream pay for the abstraction it needs). Integrate into a single recommendation: the MINIMAL defensible entity-set to introduce now + an explicit per-entity now/defer/drop verdict + the worth-it-now argument. If the honest answer for some entity is 'do nothing until mirror/redirect', say so plainly."
      inputs: [structure, testability, forward-compat]
      sources:
        - "memory: feedback_convergence_thrash_freeze_first + project_mint_workflow_status — the project's bias toward byte-identity and earned abstraction"
        - "mint/architecture-rule-model.md — to check the proposed entities against the already-committed model vocabulary (avoid renaming churn)"

output:
  path: "mint/architecture-loader-datamodel.md"
  mode: create

options:
  skip_design_reviewer: false
  max_rework_rounds: 2
```
