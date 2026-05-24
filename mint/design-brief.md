# Design Brief — Per-rule counter map shape (PERCPU_HASH vs PERCPU_ARRAY)

## Topic

Resolve `architecture-v2.md` Open Question #13: choose between `BPF_MAP_TYPE_PERCPU_HASH` (architect B's preference, sparse `rule_id` keys) and `BPF_MAP_TYPE_PERCPU_ARRAY` (architect C's preference, dense `rule_id` 0..N-1 indices, capped at 64 rules) for the per-rule counter map landing in MVP-3.4. This is a narrow technical fork with substantive downstream consequences (BPF datapath layout, rule_id allocation policy, verifier path complexity, exporter binary's read protocol) — small mini-hld round (2 architects + optional contrarian) before writing the MVP-3.4 task-brief.

## Motivating context

`architecture-v2.md` MVP-3.4 row (line 312) ships per-rule counter map + `rules`+`action_table` (B.2 partial) + `xdpmf-exporter` binary + Prometheus `/metrics` + manual bypass primitive. The exporter binary reads per-rule counters and serves them on `/metrics`. The choice between HASH and ARRAY shapes the BPF program's per-packet rule-counter increment path, the userspace rule-id allocation policy, and the exporter's read loop.

Per `architecture-v2.md` Divergence #7 (lines 96-97):
> **(B vs C): per-rule counter map type — `PERCPU_HASH` vs `PERCPU_ARRAY`.** B (architect-B.md:24, 136) proposes `BPF_MAP_TYPE_PERCPU_HASH` keyed by `rule_id`. C (architect-C.md:560) explicitly asks B to "use PERCPU_ARRAY indexed by rule-id; cap at 64 rules for now". This is a substantive technical disagreement: PERCPU_ARRAY = pre-allocated dense slots, O(1) lookup, requires contiguous rule_id allocation 0..N-1; PERCPU_HASH = sparse dynamic keys, supports rule_id gaps (e.g., operator deletes rule 5, rule_ids 1..4, 6..N stay valid).

Per `architecture-v2.md` Open Question #13 (lines 391):
> **Per-rule counter map type — `PERCPU_HASH` (B) vs `PERCPU_ARRAY` (C)?** Substantive technical disagreement promoted from Convergence after round-1 review. Why architects couldn't resolve: cross-lens — depends on rule_id allocation policy (dense 0..N-1 vs sparse / operator-assigned) which neither has fully specified. What answer unlocks: gates MVP-3.4 BPF map layout — wrong choice is moderately expensive to undo (verifier paths differ).

Per `architecture-v2.md` MVP-3.4 risk register row (line 338):
> **Per-rule counter map type choice (PERCPU_HASH vs PERCPU_ARRAY) commits BPF layout — wrong choice is expensive to undo.** Mitigation: Open Question #13 — human-gate decision based on rule_id allocation policy (dense 0..63 → ARRAY; sparse/UUID → HASH).

## Scope

- **In scope**: choose ONE of {PERCPU_HASH, PERCPU_ARRAY}; specify rule_id allocation policy (dense vs sparse); cardinality bound; BPF datapath increment shape; userspace read protocol shape; exporter binary read-loop shape; impact on MVP-3.4 schema (does YAML expose explicit `id:` per rule, or is id implicit-sequential?); migration path if the choice turns out wrong.
- **Out of scope**: per-rule counter SEMANTICS (what gets counted — pass-hits per rule? drop-hits per rule? bytes?); Prometheus label set; sFlow integration; CIDR-axis counters (orthogonal to MAC-axis counters; question applies symmetrically); exporter binary's full architecture (covered by MVP-3.4 brief proper).

## Current state (MVP-3.3 shipped, 2026-05-24 ~20:41)

- 11 mint-dev cycles complete; MVP-3.1+3.2+3.3 (Composite 6 architecture) shipped
- Config schema currently:
  - YAML `rules:` list at `/etc/xdpfilter/<iface>.yaml`
  - Each rule has `id: <integer>` field (per §5.26 design — operator-assigned)
  - `mac:` and `src_cidr:` match axes
- BPF maps currently: `mac_allowlist_a`/`mac_allowlist_b` (HASH), `cidr_allowlist_a`/`cidr_allowlist_b` (LPM_TRIE), `stats` (PERCPU_ARRAY with 4 indices: STAT_PASS, STAT_DROP_DENY, STAT_DROP_MALFORMED, STAT_PASS_CIDR)
- Per-rule counters do NOT exist yet — global aggregates only

The rule_id allocation question is partially constrained by existing schema:
- `id: <integer>` is operator-assigned per existing schema
- Schema does NOT enforce id contiguity (operator could write `id: 1`, `id: 5`, `id: 100`)
- T_APPLY_REJECTS_MALFORMED sub-case 3 already rejects duplicate id within same config

So the existing schema is **sparse-id-permissive**: operator-assigned, can be non-contiguous. This is a load-bearing constraint for the choice.

## Decisions to make in this round

1. **PERCPU_HASH or PERCPU_ARRAY** — the core question.
2. **rule_id allocation policy** — operator-assigned-sparse (current) OR auto-allocated-dense (would require schema change) OR hybrid (operator-supplies-name, loader-auto-allocates-internal-id).
3. **Cardinality bound** — current schema accepts arbitrary id range; should there be a hard cap? (Architect C's 64-rule cap was conditional on PERCPU_ARRAY choice.)
4. **Schema impact** — if any (probably none if HASH; possibly a `max_rules: <N>` field if ARRAY).
5. **Migration path** — if cycle-2 choice (e.g., HASH) turns out wrong in MVP-3.5+, what's the cost to flip? (Spec a 1-paragraph migration sketch.)

## Reference materials

- `mint/architecture-v2.md` — Divergence #7 (line 96), Open Question #13 (line 391), MVP-3.4 row + risk register row 338
- `mint/design.md` §5.26 (config harness — schema), §5.27 (CIDR rule type extending), §5.28 (systemd OPS slice — references trust_model stderr format which exporter docs cite)
- `/tmp/mvp3-brainstorm/architect-B.md` and `architect-C.md` from architecture round-1 — original proposals for HASH vs ARRAY
- Kernel BPF map docs:
  - `Documentation/bpf/map_hash.rst` (PERCPU_HASH semantics)
  - `Documentation/bpf/map_array.rst` (PERCPU_ARRAY semantics)
  - LWN coverage of PERCPU map types — verifier complexity, atomicity guarantees
- Production references:
  - Cilium's per-policy counter implementation (uses PERCPU_HASH keyed by policy_id) — `pkg/maps/policymap/` and `bpf/lib/policy.h`
  - Katran's per-VIP stats (uses PERCPU_ARRAY with dense vip-index) — `katran/lib/bpf/balancer_consts.h`
- Project's existing `stats` PERCPU_ARRAY pattern (`src/common/mac_filter.h:54-60`, `tests/lib/read_stats.py`) — the read protocol we'd extend or parallel

## Non-goals (explicit OOS for this round)

- **MVP-3.4 task-brief itself** — this round produces ONE technical decision + supporting context; the broader MVP-3.4 brief (per-rule counter + rules ARRAY + action_table + exporter + Prometheus + manual bypass) writes AFTER this question is answered.
- **Prometheus label cardinality** — orthogonal to map-type choice; covered by MVP-3.4 brief.
- **sFlow / JSON logs** — MVP-3.5+/3.6+ slices.
- **AF_XDP / per-action growth** — MVP-3.8+/3.10+.
- **CIDR-axis per-rule counters** — applies symmetrically once MAC-axis choice is made (or earlier if architect surfaces a reason to diverge — probably won't).
- **Sub-architecting the exporter binary** — read-loop SHAPE only ("hot-path read pattern" — full vs delta, polled vs streamed), not full binary architecture.

## What success looks like for this round

`mint/design.md` gets a new amendment `§5.29 MVP-3.4 pre-decision: per-rule counter map shape` (or written into the MVP-3.4 task-brief.md once written) answering:

- Chosen map type (HASH or ARRAY) + 1-paragraph rationale
- Chosen rule_id allocation policy (sparse-operator-assigned / dense-auto / hybrid)
- Cardinality bound (if any) + how enforced (schema validator / runtime check / both)
- Schema impact (none / new field / breaking change)
- Migration path sketch if cycle-2 choice turns out wrong (≤3 sentences)
- Open questions surfaced for human gate (if any remain after architect rounds)

The decision becomes the controlling input for the MVP-3.4 task-brief.

---

```yaml
architects:
  parallel:
    - name: HASH
      lens: |
        BPF datapath / map mechanics. Argue FOR PERCPU_HASH. Cover: sparse-id-allows
        non-contiguous operator ids (existing schema permits this — load-bearing
        constraint); deletion handles cleanly (key removed, no hole); cardinality
        is dynamic (operator can have 1 rule or 500 without pre-allocation);
        BPF verifier paths for HASH lookup; per-CPU atomicity guarantees;
        sync semantics with `bpf_map_update_elem(MAP_TYPE_PERCPU_HASH, key, val, BPF_ANY)`;
        Cilium's prior art with policy-id keyed PERCPU_HASH. Address the cost-side
        honestly: hash-collision risk, slightly more verifier complexity, slight
        per-packet overhead vs ARRAY's O(1) deref.
      scope: |
        COVER: PERCPU_HASH semantics, atomicity, lookup latency, deletion semantics,
        rule_id allocation policy (sparse-operator-assigned default; argue why this
        fits), cardinality (none / soft cap / hard cap), schema impact (likely
        zero — existing id:<int> works as-is), BPF program increment pattern,
        userspace read protocol for exporter, migration to ARRAY if needed.
        DO NOT COVER: ARRAY shape (steel-man it briefly only to compare); broader
        MVP-3.4 scope (exporter binary architecture, Prometheus labels — out).
      sources:
        - "Linux kernel BPF docs: Documentation/bpf/map_hash.rst — PERCPU_HASH semantics"
        - "Cilium policymap (pkg/maps/policymap + bpf/lib/policy.h) — production prior art"
        - "LWN coverage of BPF percpu maps + verifier complexity"
        - "mint/architecture-v2.md Divergence #7 line 96-97 (your starting position)"
        - "mint/architecture-v2.md Open Q #13 line 391 (gating question)"
        - "Project's existing src/bpf/mac_filter.bpf.c map layout (the maps you'd join)"
    - name: ARRAY
      lens: |
        BPF datapath / map mechanics. Argue FOR PERCPU_ARRAY. Cover: O(1) dense-index
        lookup (faster per-packet, simpler verifier path); pre-allocated slots
        (no map_create overhead at apply-time); architect C's 64-rule cap proposal
        — argue it's a reasonable hard cap (no production deployment of a per-VM
        L2/L3 filter needs > 64 rules; if it does, the rules layer is the wrong
        abstraction). REQUIRES dense rule_id 0..N-1 — which means EITHER (a)
        loader auto-allocates internal rule_id from operator's symbolic name AND
        the operator's `id:` becomes a label not a direct map key, OR (b) schema
        change to enforce contiguity. Pick one and defend. Address the cost-side
        honestly: schema change might break MVP-3.1/3.2 fixtures (PI-17 hinge);
        dense-realloc on rule delete is awkward; cardinality hard-cap can surprise
        operators.
      scope: |
        COVER: PERCPU_ARRAY semantics, O(1) lookup advantage, dense-allocation
        requirement and how to satisfy it (auto-allocate vs schema enforce),
        64-rule cap defense, BPF program increment pattern (lookup_elem + atomic
        increment), userspace read protocol for exporter, migration to HASH if
        cap turns out too low.
        DO NOT COVER: HASH shape (steel-man it briefly only to compare); broader
        MVP-3.4 scope.
      sources:
        - "Linux kernel BPF docs: Documentation/bpf/map_array.rst — PERCPU_ARRAY semantics"
        - "Katran balancer_consts.h + per-VIP stats (production prior art for dense-array per-entity counters)"
        - "Project's existing src/common/mac_filter.h:54-60 + tests/lib/read_stats.py (the existing PERCPU_ARRAY read pattern you'd extend)"
        - "mint/architecture-v2.md Divergence #7 line 96-97 (your starting position)"
        - "mint/architecture-v2.md Open Q #13 line 391"
        - "mint/design.md §5.26 rule schema (line refs for the id: field as-currently-spec'd)"
  sequential:
    - name: T
      lens: |
        Skeptical engineer / productive grouch (T3 pattern from architecture-v2
        round 2 — proven effective). Read HASH + ARRAY architects. Attack their
        selections for hidden assumptions, premise weaknesses, false dichotomies.
        Specifically: (a) is the question even the right one? Should the answer
        be "neither — defer per-rule counters to MVP-3.5+ and ship MVP-3.4 with
        just the exporter for global counters + manual bypass"? (b) Is there a
        third option the architects missed (e.g., per-rule counters in a SHARED
        PERCPU_ARRAY indexed by `rule_id mod 64` with hash-style collision
        handling — Cuckoo-style)? (c) Is the 64-rule cap a real constraint or
        architect-C bias? (d) Does the migration path from one to the other
        actually exist in 1 cycle, or is it 3+? (e) Is the question better-posed
        as "what's the right rule_id allocation policy" with map type falling
        out as a consequence?
      scope: |
        COVER: steel-manned attacks on each of HASH and ARRAY selections;
        hidden assumptions across both; counter-proposals where you see better
        paths; honest "if you do anyway" risk mitigations. CAN propose deferral
        of the whole question to MVP-3.5+ if you genuinely think the per-rule
        counter feature isn't ready to ship.
        DO NOT COVER: your own deep design from scratch (you build on architects'
        work; if a counter-proposal is needed, sketch but don't fully design).
      inputs: [HASH, ARRAY]
      sources:
        - "All HASH + ARRAY architect outputs from this round"
        - "mint/architecture-v2.md MVP-3.4 row (line 312) + risk register (line 338) — your sanity-check"
        - "mint/RETROSPECTIVES.md (~/.claude/agents/mint-dev/) — pattern history (e.g., scope-explosion heuristic, deferral discipline)"
        - "mint/design.md §5.28 (most recent slice) — gauge current code complexity ceiling"

output:
  path: "mint/architecture-v2.md"
  mode: amend
  amend_section: "§MVP-3.4 Open Question #13 RESOLUTION"

options:
  skip_design_reviewer: false
  max_rework_rounds: 1
```
