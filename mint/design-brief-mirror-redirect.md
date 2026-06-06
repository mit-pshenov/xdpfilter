# Design-brief — mirror / redirect (XDP→TC steering): the real product capability

## Topic

`xdpfilter` today is a terminal **allow/drop** L2/L3 filter. Its actual product purpose (PO,
[[project_dpi_pre_filter_purpose]] + [[project_real_requirements_and_strategy]]) is to
**SELECT and STEER** traffic for downstream DPI — a per-rule action space of
allow/drop/**mirror**/**redirect**/tag/rate-limit, of which mirror + redirect are the first
real steering verbs. Everything shipped so far is the match-model + the host-side pipeline
(now cleanly layered: RawConfig → ValidatedConfig → CompiledRuleset → materialize → maps).
This round designs the **steering datapath + the action-model extension** that turns the
filter into a selector.

This round answers:

> What is the right architecture to add per-rule **mirror** (copy the packet to a monitor
> target, original verdict continues) and **redirect** (divert the packet to another
> target) — across the datapath mechanism (XDP-native vs a TC component), the action-model /
> ABI extension, the operator/deployment surface, and the test surface — and what is the
> **leanest first slice** that delivers real steering without over-building?

## Grounding (architects: verify against code; don't trust verbatim)

- **The action model is ALREADY a 2-level indirection, built to extend.** `rule_entry.action_id`
  (`src/common/xdpfilter.h:263`) indexes `action_table[action_id] → action_entry.action_type`
  (`:268`); `enum xdpmf_action_type { ACTION_PASS=0, ACTION_DROP=1, ACTION_MAX=2 }` (`:272`)
  with the in-code comment *"future MVP-3.8+ may extend (MIRROR/RL/TAG)"* (`:275`). The
  action axis was deliberately kept **RAW** through B40's `CompiledRuleset` (no lowering into
  a mask — `compiled_ruleset.hpp:100`) precisely for this path.
- **Today the verdict is binary.** The XDP program returns only `XDP_PASS` / `XDP_DROP`
  (`src/bpf/xdpfilter.bpf.c:453` / `:456`); a rule's `action_type` selects between them.
- **No steering scaffolding exists.** Zero `bpf_redirect` / `clsact` / `devmap` /
  `bpf_clone_redirect` / TC / AF_XDP in `src/bpf/`, `src/lib/`, `src/common/`.
- **Realizability crux (the pivotal uncertainty):** REDIRECT (divert) is XDP-native
  (`bpf_redirect` / `XDP_REDIRECT` via a devmap). MIRROR (clone-and-continue) is **NOT**
  natively expressible in XDP — it requires a TC `clsact` program + `bpf_clone_redirect`, or
  a devmap/AF_XDP tap, or a multicast devmap. This is why "TC появится" (PO): some steering
  verbs force a second BPF program on a different hook. The HLD must determine exactly which
  verb forces what, and how the XDP and TC components compose.
- **Pipeline to compose with:** the 9-axis AND match-model (§5.31–§5.54) → a per-rule verdict
  → `action_id`; the named `CompiledRuleset` (compile output) + `RulesetDelta` (counter
  reconciliation); the double-buffer atomic-swap apply; the host-global pin model; the
  exporter/Prometheus counter surface; ansible/systemd/fleet deployment.

## Design space (seeds — enumerate ALL viable, then select 2-3 by diversification)

Non-exhaustive; the band must go beyond these and score them:

- **Datapath placement**: redirect via `XDP_REDIRECT` + a `devmap` (XDP-native); mirror via a
  TC `clsact` egress program + `bpf_clone_redirect`; OR push BOTH verbs to TC (XDP stays the
  classifier, tail-calls / hands a verdict to TC); OR a devmap-multicast tap for mirror.
- **Verdict→steering handoff**: how the XDP classifier's per-rule action reaches the steering
  action — extend the XDP return path directly (XDP_REDIRECT inline), vs a metadata/`xdp_md`
  hand-off to a TC program, vs a shared map the TC prog reads.
- **Action-model / ABI extension**: `action_type` grows MIRROR/REDIRECT; where the **target**
  lives — inline in `action_entry` (an ifindex / devmap-key field), vs a separate
  steering-target table the action indexes (mirrors the slot↔id decouple discipline), vs a
  devmap whose entries ARE the targets. Config schema: a rule's `action: mirror|redirect`
  + a `target:` field; validation of target existence.
- **Target representation**: raw ifindex vs a named target registry vs devmap membership.
- **Scope sequencing**: redirect-only first (XDP-native, no TC) vs mirror-first (the stated
  DPI purpose) vs both together.

## Constraints / invariants

- **Compose, don't disturb.** The 9-axis match-model, the `CompiledRuleset`/`RulesetDelta`
  pipeline, the double-buffer atomic swap, PI-7, and the existing datapath byte-identity gate
  for the PASS/DROP path must survive. Adding steering must not silently change PASS/DROP
  semantics for rules that don't use it.
- **Line-rate non-foreclosure.** Target is 40Gbps GGSN-Gi ([[project_perf_envelope]]); mirror
  duplicates traffic. The chosen mechanism must not foreclose the measured eBPF envelope (this
  is non-foreclosure, NOT an optimization round) — and AF_XDP/DPDK remain the eventual
  high-perf path (forward-compat only; do NOT design them here).
- **Operator surface is real.** This project ships ansible/systemd/fleet; a second BPF
  program + a `clsact` qdisc is a new lifecycle (attach order, detach, target-iface existence,
  failure when a target is down). The operator story is load-bearing, not an afterthought.
- **The action_table 2-level indirection is the intended extension point** — prefer extending
  it over a parallel mechanism (the code was built for this).

## Out of scope

- **tag / rate-limit** action verbs — the action model should not FORECLOSE them, but this
  round designs mirror + redirect only.
- **AF_XDP / DPDK** datapaths — forward-compat (non-foreclosure) only; not designed here.
- **`apply --dry-run`** — parked product feature (would help test the materialization; revisit
  after this capability lands), NOT in this round.
- **The 64-rule ceiling** — fixed architectural limit.

## What a good outcome looks like

A recommended **steering architecture**: the datapath placement (what runs on XDP vs a TC
component, and exactly which verb forces which), the **action-model + ABI extension** (how
`action_type`/`action_entry`/the target representation grow, composed with the existing
pipeline), the **config schema** for `action: mirror|redirect` + `target:`, the **operator
lifecycle**, the **test surface** (how mirror-copies and redirect-diverts are proven), and a
**slice decomposition** with an explicit leanest-first-slice recommendation. The synthesis must
flag where realizability, semantics, operability and testability disagree, and the grounder must
surface the genuine PO scoping forks (redirect-first vs mirror-first; target model).

```yaml
architects:
  parallel:
    - name: realizability
      lens: "Datapath mechanism engineer. You own the pivotal uncertainty the other lenses depend on: what is ACTUALLY buildable on the eBPF datapath for each verb. REDIRECT (divert) vs MIRROR (clone-and-continue) have different feasibility — XDP can XDP_REDIRECT to a devmap, but cloning needs TC clsact + bpf_clone_redirect (or a devmap-multicast / AF_XDP tap). You see verifier limits, helper availability per hook, the XDP↔TC composition, packet-clone semantics, and devmap mechanics that the semantics/ops/test lenses cannot weigh. You also own line-rate NON-FORECLOSURE (mirror duplicates traffic — does the mechanism foreclose the measured envelope?)."
      scope: "Enumerate ALL viable datapath placements for mirror + redirect (XDP-native redirect + TC-clsact mirror; both-on-TC; devmap-multicast; tail-call handoff), score each on buildability (verifier/helper/hook constraints) + clone-correctness + line-rate non-foreclosure, select 2-3 by diversification, justify, detail the XDP↔TC composition + the verdict→steering handoff mechanism. Do NOT design the config schema (action-model's call), the operator lifecycle (operability's call), or the test oracle (testability's call) — defer each. Verify against src/bpf/xdpfilter.bpf.c (return paths :453/:456), src/common/xdpfilter.h (action enum :272). Web-research current (2024-2026) XDP/TC redirect + clone helper landscape + verifier constraints."
      sources:
        - "src/bpf/xdpfilter.bpf.c — XDP verdict path (XDP_PASS:453 / XDP_DROP:456), where action_type is consumed"
        - "src/bpf/{classifier.h,maps.h,defs.h} + src/common/xdpfilter.h — action_table/action_entry ABI (:252-283), the extension point"
        - "kernel docs / recent sources on bpf_redirect, bpf_redirect_map, devmap, XDP_REDIRECT, TC clsact + bpf_clone_redirect, tcx — feasibility per hook"
    - name: action-model
      lens: "Action-model & ABI architect. You own how the per-rule action grows from the binary PASS/DROP verdict into a steering verb with a TARGET, composed with the existing match-model → action_id → action_table indirection. Where does the target live (inline in action_entry / a separate steering-target table indexed by the action / devmap membership)? How does the config schema express `action: mirror|redirect` + `target:`, and how does validation prove the target? You see the schema/ABI/lowering/CompiledRuleset composition that the realizability lens treats as a black box."
      scope: "Design the action-model extension: the action_type/action_entry growth, the target representation (score inline-field vs separate-target-table vs devmap-membership — apply the project's slot↔id-decouple discipline), the config schema (action + target grammar, schema_version bump?), validation (target existence/shape), and how it threads through CompiledRuleset (the raw action axis) + materialize without disturbing the PASS/DROP byte-identity. Take realizability's mechanism space as a constraint (do NOT re-decide XDP-vs-TC), defer the operator lifecycle + test oracle. Verify the current action ABI (xdpfilter.h:252-283), the raw-action decision (compiled_ruleset.hpp:100), config.hpp RuleAction. Score for non-foreclosure of tag/rate-limit."
      sources:
        - "src/common/xdpfilter.h:252-283 — rule_entry/action_entry/xdpmf_action_type ABI + the MVP-3.8 extension comment"
        - "src/lib/config.hpp (RuleAction/RuleMatch/Rule) + docs/CONFIG_SCHEMA.md — the schema to extend"
        - "src/lib/compiled_ruleset.hpp:100 + the materialize action path (loader.cpp populate_rules_inner_slot / populate_action_table) — where action threads through the pipeline"
    - name: operability
      lens: "Operator & deployment lens. A second BPF program on a TC hook + a clsact qdisc + steering targets is a NEW operational surface on a fleet-deployed line-rate box. You own the lifecycle the datapath/semantics lenses don't: attach/detach ordering of XDP+TC, qdisc management, target-interface existence + failure modes (target down / removed), observability (mirror/redirect counters in the exporter), rollback, and the ansible/systemd/fleet integration. You see the run/debug/operate story."
      scope: "Design the operator lifecycle for the steering capability: XDP+TC attach order + atomicity + rollback, clsact qdisc management, target-iface existence/validation/failure handling, the observability surface (new counters through the existing exporter/Prometheus path), and ansible/systemd/fleet touchpoints. Take the datapath mechanism (realizability) + action model (action-model) as given; do NOT re-decide them. Defer the test oracle to testability. Verify against the existing attach lifecycle (loader.cpp), systemd/ansible/, the exporter counter surface (src/exporter/)."
      sources:
        - "src/lib/loader.cpp — current XDP attach/detach/pin lifecycle + double-buffer swap (the model a TC component must compose with)"
        - "systemd/ + ansible/ + docs/FLEET_DEPLOYMENT.md — the deployment surface a 2nd program touches"
        - "src/exporter/ — the counter/Prometheus surface where mirror/redirect observability lands"
    - name: testability
      lens: "Verification lens (A/B-validated as load-bearing for datapath HLD with a new test-surface). Steering is HARD to test — proving a mirror COPY actually reaches a target and a redirect DIVERTS the packet needs a multi-interface / netns oracle, unlike the in-process PASS/DROP corpus. You own: what test surface each candidate architecture unlocks, the oracle design for clone/divert, what the existing harness (veth/netns ctests, the offline compile_harness/ruleset_delta_harness) can and cannot cover, and whether a dry-run-style offline materialization of the steering maps would de-risk it."
      scope: "For each candidate architecture (take realizability's mechanism + action-model's schema as given — do NOT re-decide them), evaluate the testability delta: the oracle for proving mirror-copy-reaches-target + redirect-diverts (netns/veth topology, packet capture), what's offline-assertable (steering-map materialization, the action lowering) vs what needs a live datapath, the minimum new test scaffold, and whether the parked dry-run feature would materially help here. Recommend the architecture with the best provable-correctness-per-effort. Defer shape/mechanism/ops to their owners."
      sources:
        - "tests/ — the existing veth/netns datapath ctests + inject harness + the offline *_harness pattern (compile_harness/ruleset_delta_harness)"
        - "src/bpf/xdpfilter.bpf.c — the datapath whose steering effects must be observed"
        - "mint/architecture-loader-datamodel.md — the dry-run parking note (a possible test-surface synergy)"
  sequential:
    - name: contrarian
      lens: "Skeptical staff engineer. You read realizability + action-model + operability + testability and ask what none of them is incentivized to: is the TC component needed NOW, or does XDP-native redirect alone cover the immediate DPI-steering need (divert-to-DPI) with mirror deferred? Is a separate target-table over-abstraction for a first slice? What is the LEANEST first slice that delivers real steering value, and what is being gold-plated for verbs (tag/RL) not in scope?"
      scope: "Read the four parallel outputs. Poke holes: which capability is load-bearing for the actual product need (steer-for-DPI) vs speculative; whether mirror's TC complexity should DEFER behind a redirect-only first slice; whether the target-model / schema is over-built for slice 1; the real perf cost of mirror at line rate. Integrate into a single recommendation: the MINIMAL defensible first slice + an explicit verb-by-verb now/defer ladder + the leanest target model. If redirect-first-mirror-later is the honest answer, say so plainly."
      inputs: [realizability, action-model, operability, testability]
      sources:
        - "memory: project_perf_envelope (mirror doubles traffic) + project_real_requirements_and_strategy (the full action ladder) + project_dpi_pre_filter_purpose (steer-for-DPI is the WHY)"
        - "mint/architecture-rule-model.md — the committed match-model vocabulary the steering action composes with"

output:
  path: "mint/architecture-mirror-redirect.md"
  mode: create

options:
  skip_design_reviewer: false
  max_rework_rounds: 2
```
