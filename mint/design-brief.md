# Design Brief — Rule-model classification architecture (Wave B)

## Topic

Choose the **packet-classification architecture** for `xdpfilter`'s real match model — the
structure that lets a rule match on **multiple fields AND-composed** (dst-IP + L4 port + VLAN +
EtherType + src-IP + MAC + …), evaluated **first-match** with an explicit default, on the XDP
datapath. This is the pivotal decision flagged by the Wave A discovery catalog
(`mint/selection-scenarios.md` §6.2): the current datapath is **axis-keyed independent maps**
(MAC-HASH, CIDR-LPM_TRIE) that structurally produce **OR-compose** and cannot express
multi-field AND. Moving to the industry-standard AND-compose is therefore an **architecture
change** (the classic packet-classification problem), not a schema bump.

This is a **brownfield** architecture round: the design must EVOLVE the existing datapath
(parallel `ARRAY_OF_MAPS` per axis + a single shared `active_idx` atomic swap + `rule_id →
rules_inner → action_table` dispatch), not greenfield-replace it.

## Motivating context

Read `mint/selection-scenarios.md` in full — it is the demand-side catalog this round serves.
Key anchors:
- **Narrow path, expansion-friendly.** Target = the narrow **Gi-DPI pass/drop pre-selector**.
  Near-term action vocabulary is pass/drop + explicit default; steering (mirror/redirect/tag),
  rate-limit, L7 (SNI/JA3) and stateful (conntrack) are **deferred / out of scope** — but the
  chosen structure must not FORECLOSE them (see catalog Appendix B "expansion-door" items).
- **eBPF = model-validation vehicle.** DPDK/AF_XDP and perf-validation are deferred; do NOT
  design for them, but keep the classification semantics separable from XDP specifics so a
  future datapath swap can reuse the rule model (portability boundary, not a port).
- **Match-field target set** (catalog §4): Tier-1 5-tuple (dst/src IP-CIDR, proto, dst/src port)
  + Tier-2 (VLAN, EtherType, MAC, iface) reducible to six encoding primitives (prefix/LPM,
  exact, range, set, bitmask, negation). dst-IP is the #1 gap.
- **Latent bug to fix in-architecture** (catalog §6.4): VLAN-tagged IP frames currently skip the
  CIDR axis (`mac_filter.bpf.c:367` gates on `h_proto == ETH_P_IP`). VLAN support must fix the
  tagged-frame L3 parse path.

The candidate classification structures to enumerate, score, and select among (catalog §6.2 +
Appendix B.1) — NONE pre-selected; diversify by trade-off:
1. Sequential per-rule scan (AND fields, first-match by id).
2. Bit-vector / bitset intersection (per-axis map → rule-bitmask, AND, ffsll → lowest id).
3. Composite-key map (concatenated tuple; breaks on mixed LPM/range/exact).
4. Decision-tree (HiCuts/HyperCuts) — likely over-engineering for the vehicle stage.
5. Layered-pipeline via eBPF tail calls (per-layer first-match, chained) — a peer candidate
   surfaced by an external artifact; treat as ONE option, do NOT promote because it was seen.

## Scope

- **In scope**: the classification structure choice (above) with explicit trade-off scoring;
  how it AND-composes arbitrary subsets of the field set with the six primitives + "absent field
  = wildcard"; first-match ordering semantics (id-as-priority vs most-specific-wins) and how it
  binds to the structure; the OR→AND migration story for existing v1 rules; how it evolves the
  current `ARRAY_OF_MAPS` + shared-`active_idx` atomic-swap and the `rules_inner→action_table`
  dispatch; rule cardinality bound (`XDPMF_ALLOWLIST_MAX`) and its effect on the choice; the
  VLAN-tagged parse-path fix; IPv6 second-LPM shape (when, not full design); the eBPF-verifier
  feasibility of each candidate; the portability boundary (separable rule semantics) WITHOUT
  designing AF_XDP/DPDK; the per-packet cost-envelope (instruction/lookup count) of each
  candidate as a **relative structural selection criterion** + performance **non-foreclosure**
  (see Amendment 2026-05-30); a recommended `/mint-dev` slice sequence consistent with the choice.
- **Out of scope**: the action model beyond pass/drop (mirror/RL/tag/redirect — deferred);
  L7/stateful match; dynamic feed-backed objects + their refresh (object-lifecycle — note as an
  open question only, it's orthogonal); the YAML config-grammar surface details (Wave A §7
  already sketched the direction; this round is the DATAPATH/structure, not the parser); perf
  optimization / benchmarking / absolute throughput numbers / µ-tuning of shipped code (NOTE:
  per-packet cost-envelope as a *relative structural selection axis* is now IN scope — see
  Amendment 2026-05-30); DPDK/AF_XDP datapath design.

## Current datapath (read before designing)

- `src/bpf/mac_filter.bpf.c` — the XDP program: axis-keyed lookups, 5 parallel `ARRAY_OF_MAPS`
  (allowlist/cidr/rules/rule_counters + defaults) sharing one `active_idx`, `rule_id →
  rules_inner[rule_id] → action_table[action_id]` dispatch, OR-compose (MAC short-circuit, CIDR
  on MAC-miss + IPv4-only).
- `src/lib/config.{hpp,cpp}` — schema, strict unknown-key gate, `id` range/uniqueness, schema_version.
- `src/lib/loader.cpp` — `kManagedMaps[]`, per-iface pin loop, apply/atomic-swap, copy-forward.
- `mint/selection-scenarios.md` — the Wave A catalog (THE demand anchor).
- `docs/REQUIREMENTS.md` — canonical spec + implementation-status table.
- `mint/design.md` §5.27/§5.34/§5.35 — the axis-map + atomic-swap + dispatch history (brownfield context).

```yaml
architects:
  parallel:
    - name: classifier
      lens: "Datapath classification-structure architect. You own the central decision: which packet-classification structure realizes AND-composed multi-field first-match on XDP. Enumerate ALL viable candidates (sequential scan, bit-vector/bitset intersection, composite-key, decision-tree, layered-pipeline-tail-call, plus any you find), score each on: AND-compose correctness, first-match ordering, support for all six encoding primitives (prefix/LPM, exact, range, set, bitmask, negation) including mixed primitives in one rule, eBPF-verifier feasibility (bounded loops, map-in-map, stack), rule-cardinality scaling, and compatibility with the existing ARRAY_OF_MAPS + shared active_idx atomic-swap. Select 2-3 by trade-off diversification, not by favorite; the layered-pipeline option is a peer candidate, do NOT privilege it because it appears in an external artifact."
      scope: "Cover the structure + how it evolves the current 5-axis ARRAY_OF_MAPS datapath. Do NOT design the YAML parser, the action model beyond pass/drop, or AF_XDP/DPDK. Viability filter: must be implementable in XDP under the verifier on the project's kernel; must preserve the single-u32 active_idx atomic-swap promise."
      sources:
        - "mint/selection-scenarios.md (THE demand anchor — §4 fields, §6 realizability, Appendix B)"
        - "src/bpf/mac_filter.bpf.c (current axis-keyed datapath to evolve)"
        - "Packet classification survey — Gupta & McKeown; tuple space search; Lakshman-Stiliadis bit-vector; HiCuts/HyperCuts (web)"
        - "Cilium / Katran XDP policy datapath + bpf map-in-map / tail-call patterns (web)"
        - "RFC 8955/8956 FlowSpec component model + most-specific precedence (web)"
    - name: semantics
      lens: "Rule-semantics & ordering architect. You own what a rule MEANS and how rules combine: first-match-by-ascending-id vs most-specific-wins (FlowSpec), and how that binds to each classification structure; 'absent field = wildcard' representation; negation semantics; and the OR→AND migration of existing v1 rules (auto-split a 2-axis OR rule into two? load-time rewrite? require v2 re-author? what breaks?). Also: the dual role of `id` (operator-assigned priority AND rule_counters[] index) and whether multi-axis stresses it."
      scope: "Cover ordering + composition + v1→v2 migration semantics + default-action. Do NOT design the datapath structure (that's classifier's) — but state which ordering models each structure supports. Do NOT design the action model beyond pass/drop. Viability filter: migration must not silently change the meaning of a deployed v1 file without an explicit, detectable bump."
      sources:
        - "mint/selection-scenarios.md (§5 composition, §6.1-6.2 OR-structural finding, §7 ordering)"
        - "src/lib/config.cpp (id range/uniqueness, schema_version gate, strict unknown-key)"
        - "tests/fixtures/config_valid_mac_or_cidr.yaml (the load-bearing OR-compose fixture)"
        - "RFC 8955 most-specific precedence algorithm; nftables/Calico/VyOS ordering models (web)"
    - name: realizability
      lens: "eBPF-realizability & forward-portability architect. You pressure-test feasibility and keep the door open. For each classification candidate: verifier constraints (bounded loops, map-in-map nesting, stack/instruction limits), map-topology evolution from the current 5-axis ARRAY_OF_MAPS, hot-reload/atomic-swap compatibility, rule cardinality (XDPMF_ALLOWLIST_MAX growth; the large-cardinality feed-object door), the VLAN-tagged parse-path fix (catalog §6.4), and IPv6 second-LPM shape. Define the PORTABILITY BOUNDARY: which rule semantics stay datapath-agnostic so a future AF_XDP/DPDK swap reuses them — WITHOUT designing those datapaths."
      scope: "Cover feasibility + map topology + VLAN/IPv6 parse + portability boundary + cardinality. Do NOT pick the structure (defer to classifier) — instead give a feasibility verdict per candidate. Do NOT design AF_XDP/DPDK, perf, or the action model. Viability filter: every claim must be checkable against the verifier / current loader mechanism."
      sources:
        - "src/bpf/mac_filter.bpf.c + src/lib/loader.cpp (kManagedMaps, pin loop, atomic swap, copy-forward)"
        - "mint/selection-scenarios.md (§6.3 per-field XDP cost, §6.4 VLAN gap, Appendix B.2 feed-object cardinality)"
        - "Linux BPF verifier docs; XDP VLAN/802.1Q parsing (xdp-tutorial); bpf map-in-map limits (web)"
        - "mint/design.md §5.27/§5.34/§5.35 (axis-map + atomic-swap + dispatch brownfield history)"
    - name: testability
      lens: "Verification & test-oracle architect. You own ONE question per candidate structure: how is its correctness PROVEN, and what MUST be tested? Per candidate: (a) differential-oracle friendliness — can a simple reference impl (SCAN) run side-by-side and be asserted bit-identical on every fixture (the existing T_AND*_ORACLE_AGREEMENT / T_BITVEC_ORACLE_AGREEMENT pattern); (b) the test surface for load-bearing invariants — prefix-closure correctness, the wildcard-half mutual-exclusion invariant (rule in axis-map XOR wildcard-half), first-match-by-id, AND-compose-as-intersection; (c) negation-correctness verification (how to test a negated /16 is NOT cover-closed like a positive one); (d) verifier-load gating of the PRODUCTION object on the kernel floor; (e) fuzzability of the YAML->per-axis-mask lowering. Recommend WHAT to test and HOW per structure; name who owns prefix-closure/mask correctness + its oracle."
      scope: "Verification strategy + oracle design + invariant test surface + negation test difficulty + verifier-load gating. Do NOT pick the structure or design the datapath. Viability filter: every check expressible as a ctest against the current harness (shell T_*.sh, bpftool prog load, fixture-driven oracle agreement)."
      sources:
        - "tests/T_AND*_ORACLE_AGREEMENT.sh + T_BITVEC_ORACLE_AGREEMENT.sh (differential-oracle pattern)"
        - "tests/T_BITVEC_VERIFIER_LOAD.sh (verifier-load gate); tests/fixtures/* (corpus)"
        - "mint/selection-scenarios.md §6; src/lib/loader.cpp (mask lowering / prefix-closure callsites)"
    - name: perf-envelope
      lens: "Per-packet cost-envelope & performance-foreclosure architect (Amendment 2026-05-30). For EACH candidate structure score the per-packet INSTRUCTION/LOOKUP-count envelope and whether the choice FORECLOSES good performance later. Flag structural anti-patterns (e.g. re-reading packet-invariant data every packet; O(N) scans where O(1) is structurally available; redundant map lookups). RELATIVE comparison only — no absolute numbers."
      scope: "Non-foreclosure + relative structural cost-envelope. Do NOT benchmark, produce absolute throughput numbers, µ-optimize shipped code, or design AF_XDP/DPDK. Feasibility is realizability's call — assume it, score ONLY the cost-envelope. Viability filter: every claim must be a per-packet instruction/lookup count or a named structural anti-pattern."
      sources:
        - "src/bpf/mac_filter.bpf.c (per-packet datapath: axis lookups, wildcard reads, port_scan, AND-compose)"
        - "mint/selection-scenarios.md §6.3 (per-field XDP cost)"
        - "Gupta & McKeown survey (per-structure query-cost framing); BV vs decision-tree vs scan per-packet cost (web)"
  sequential:
    - name: contrarian
      lens: "Skeptical engineer / integrator. Read classifier + semantics + realizability. Poke holes: is the recommended structure the MINIMUM that proves the AND match-model on the eBPF vehicle, or is it over-engineered (decision-tree-class complexity for a model-validation stage)? Does it serve the NARROW Gi-DPI pass/drop path while not foreclosing the expansion-door items? Does the slice sequence (dst-IP → proto+port → AND-architecture → VLAN → objects) still hold under the choice? Is the OR→AND migration honest about what breaks? Flag any place the design quietly enforces a seen external approach."
      scope: "Critique + integrate into a single coherent recommendation-with-caveats. Do NOT introduce a brand-new structure unless the three parallels missed an obviously-superior one. Viability filter: complexity must be justified by the narrow path's actual needs, not the expansion vision."
      inputs: [classifier, semantics, realizability, testability, perf-envelope]
      sources:
        - "mint/selection-scenarios.md (esp. framing + Appendix B 'do not enforce seen approach')"

output:
  path: "mint/architecture-rule-model.md"
  mode: create

options:
  skip_design_reviewer: false
  max_rework_rounds: 2
```

## Amendment — 2026-05-30 (perf-envelope + added lenses)

- **Performance posture relaxed from "out of scope" to "non-foreclosure + structural cost as a
  selection axis".** Rationale: eBPF is the model-validation vehicle and will NOT meet the full
  throughput requirements (a future AF_XDP/DPDK datapath is the production target) — but within
  what the technology allows, the structure choice should still not be perf-hostile. We do NOT
  optimize, benchmark, or produce absolute numbers this round; we DO score each candidate's
  per-packet instruction/lookup-count envelope and refuse structures that foreclose good perf —
  exactly mirroring the brief's existing "narrow now, door open later" non-foreclosure principle.
  Concrete motivation: a prior code review found the shipped BV datapath re-reads 6 packet-invariant
  wildcard masks per packet and does up to 64 port lookups per L4 packet — structural costs a
  design-time perf-envelope lens would have flagged before they shipped.
- **Two lenses added to the parallel roster**: `testability` (verification/oracle — owns "how is
  correctness PROVEN per structure", incl. the prefix-closure oracle that open-Q #3 flagged as
  load-bearing) and `perf-envelope` (above). Both are independent Phase-1 lenses (no sibling reads).
- **Provenance**: lens-roster expansion driven by the Workflow-port A/B of this round (runs/hld-*).
  Each added lens is on empirical trial — kept only if its synthesis delta surfaces signal the
  original three lenses missed; dropped as noise otherwise.

## Notes for architects

- **Dual purpose**: this serves the product (real match model) AND trains the mint band. Weigh
  recommendations on both — a clean, teachable structure beats a clever opaque one.
- **Brownfield discipline**: evolve the existing datapath; cite `file:line` for what you change.
- **External artifacts are weak signals**: the layered-pipeline candidate came from a reviewed
  third-party config; treat it as one option among peers, never as a template to enforce.
- **Narrow now, door open later**: optimize for the Gi-DPI pass/drop selector; the only duty to
  the expansion vision is non-foreclosure, not implementation.
