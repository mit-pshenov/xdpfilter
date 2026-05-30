# Design Brief — L2/L3 demux gate-rework: EtherType + IPv6, and the slice sequence (v2 — +testability lens, A/B vs v1)

> **A/B variant.** Identical to `design-brief-l2l3-gate.md` EXCEPT it adds a `testability` lens
> (4th parallel) and feeds it to the `sequencer`. Run to measure whether the verification/oracle
> axis surfaces orthogonal signal the v1 roster (gate/addr-axis/ethertype/sequencer) missed —
> per the documented add-by-trial-and-measure discipline. `perf-envelope` deliberately NOT added
> (its cost-envelope axis is folded into the `gate` lens; a separate perf lens here would mostly
> re-derive gate's per-packet scoring → fake convergence).


## Topic

The match model is **IPv4-only-gated**. `src/bpf/mac_filter.bpf.c` unwraps L2/VLAN
(`vlan_aware_l3`, `:533-549`), then gates the whole 6-axis bit-vector AND-compose on a single
test — `:630 if (inner_proto == bpf_htons(ETH_P_IP))` — and parses a fixed `struct iphdr`
(`:633-657`, `ihl*4` L4 offset). **Every non-IPv4 EtherType (IPv6, ARP, …) falls through to
`defaults[active_idx]`** and is never classified on any L3/L4 axis (`:616` comment).

Two backlog items both require breaking this single gate open and neither is meaningful alone:
- **B31** — expose **EtherType** as a real L2 match concept (PO decision, per the
  `architecture-rule-model.md` ratification addendum, commit `27a9d1a`).
- **IPv6 / S8** — add **`cidr6`** (and IPv6 L4 extraction) so IPv6 frames can match on L3/L4
  axes, not just fall to defaults. HLD-gated, deferred per PO.

**They are the same structural change.** `cidr6` cannot be added "additively": to match IPv6 you
MUST touch the gate at `:630` to add an IPv6 branch. And an EtherType axis without IPv6 is
degenerate (0x0800 is redundant with the existing gate; 0x86DD can only be EtherType-only with no
`cidr6`/port to compose; only coarse ARP/non-IP steering stands alone). The 2026-05-29 plan
bundled them as **S8 = "IPv6 cidr6 + multi-ethertype gate-rework"** for exactly this reason.

So the decision this round is NOT "B31 or IPv6" — it is **how to evolve the IPv4-only gate into a
multi-EtherType demux, and in what `/mint-dev` slice sequence**, such that each slice is small,
behavior-preserving where possible, and round-1-passable (the additive-slices-pass /
structural-slices-rework lesson — see Notes).

This is a **brownfield** round: EVOLVE the existing single-XDP-program, parallel-`ARRAY_OF_MAPS`,
shared-`active_idx`, bit-vector-AND datapath (B28 just unified its axis lowering/populate into
`aggregate_axis<Key,…>` + `populate_hash_inner_slot<Key>`). Do NOT greenfield-replace it.

## Motivating context

- **The IPv4 gate is the choke point.** `:630` is a hard `ETH_P_IP` equality. The rework must
  decide the gate's NEW shape: an EtherType-keyed dispatch that routes IPv4 → existing parse+axes,
  IPv6 → a new parse+`cidr6` axes, other → L2-only / defaults — while the IPv4 path stays
  bit-identical (behavior-preservation is the de-risking lever).
- **Bit-vector axis model is the target structure** (`mint/architecture-rule-model.md`, ratified
  2026-05-28; bit-vector ratified, EtherType=real L2 match → B31, negation deferred 5/6, id/slot
  decouple = B30). New axes are added by mirroring an existing axis (B28 made the per-axis
  lowering/populate generic; the axis COUNT is driven by the `BITVEC_NUM_AXES` macro +
  `kManagedMaps[]`). `cidr6` is a 2nd-family LPM axis pair (dst/src) mirroring the IPv4
  `dst_cidr`/`src_cidr` LPM axes (`close_prefixes`/`populate_bitvec_inner_slot`, loader.cpp
  `:1220/:1433`, key `xdpmf_cidr_v4`) but with a 128-bit key.
- **EtherType's honest use cases** (catalog Tier-2 + `mint/selection-scenarios.md`): family demux
  (IPv4/IPv6), coarse non-IP steering (ARP/drop-IPv6-wholesale/mirror-by-L2 — the DPI-prefilter
  "select/steer traffic" purpose, valuable even pre-IPv6-L3), and VLAN-TPID already handled.
- **Negation is OUT** (deferred 5/6 primitives per ratification). **Actions stay pass/drop** (no
  mirror/RL/tag/redirect — but don't foreclose steering, per the standing non-foreclosure rule).

## Scope

- **In scope**: the NEW gate/demux structure (how the datapath branches by inner EtherType into
  per-family L3/L4 parse + axis evaluation); how IPv6 `cidr6` (dst+src) fits the bit-vector LPM
  axis pattern (128-bit key shape, prefix-closure over 128 bits, IPv6 L4/proto/port extraction +
  the extension-header walk and its verifier bounding); whether EtherType is an internal demux
  only, a coarse L2 match axis, or both, and how (if at all) an EtherType axis AND-composes with
  L3 axes; the per-family-axis-set vs unified-axis-set question (do IPv4 and IPv6 share the
  proto/port/vlan/mac axes and differ only in the CIDR family, or are they parallel stacks?);
  map-topology growth (`BITVEC_NUM_AXES`, `kManagedMaps[]`, new `cidr6_a/b` ARRAY_OF_MAPS) and its
  atomic-swap/copy-forward impact; **the IPv4-path behavior-preservation guarantee** through the
  rework; eBPF-verifier feasibility of each gate shape (branch-in-one-prog vs tail-call per
  family; 128-bit LPM_TRIE; bounded ext-header walk; stack/instruction budget); the per-packet
  **cost-envelope as a RELATIVE structural selection criterion** + performance **non-foreclosure**
  (consistent with the Wave-B brief's 2026-05-30 amendment — no absolute numbers); and the crux:
  **a recommended `/mint-dev` slice sequence** — what ships first (a behavior-preserving
  gate-scaffold? the `cidr6` axis? a coarse EtherType axis?), the dependency order, and which
  slices are additive (round-1-passable) vs structural.
- **Out of scope**: negation (deferred 5/6); the action model beyond pass/drop
  (mirror/RL/tag/redirect — non-foreclosure only); L7/stateful; the YAML config-grammar surface
  details (note the `cidr6`/`ethertype` key DIRECTION only, not the full parser); AF_XDP/DPDK
  datapath design; absolute throughput / benchmarking / µ-tuning; B30 id/slot-decouple internals
  (note only if it interacts with the axis-count growth); IPv6 beyond CIDR + basic L4 (no flow
  label, no IPsec/AH-ESP deep parse).

## Current datapath (read before designing)

- `src/bpf/mac_filter.bpf.c` — XDP program: `vlan_aware_l3` L2/VLAN unwrap (`:533-549`), the
  IPv4 gate (`:630`), fixed `iphdr` + `ihl*4` L4 parse (`:633-657`), the 6-axis bit-vector
  AND-compose + `ffsll` first-match + `defaults[active_idx]` fallthrough.
- `src/lib/loader.cpp` — `kManagedMaps[]` (30 entries), `BITVEC_NUM_AXES`-driven axis count
  (`:181/:192`), `close_prefixes` (`:1220`) + `populate_bitvec_inner_slot` (`:1433`) the LPM
  prefix-closure to mirror for 128-bit; `aggregate_axis`/`populate_hash_inner_slot` (B28, §5.50);
  per-iface pin loop + shared-`active_idx` atomic swap + copy-forward.
- `src/lib/config.{hpp,cpp}` — `RuleMatch` (`config.hpp:44-50`: `mac`/`dst_cidr`/`src_cidr`/
  `protocol`/`dst_port`/`vlan`, all `std::optional`); `xdpmf_cidr_v4`; strict unknown-key gate;
  schema_version 2.
- `mint/architecture-rule-model.md` — the ratified bit-vector axis model + the EtherType/IPv6/
  negation/id-slot ratification addendum (commit `27a9d1a`).
- `mint/selection-scenarios.md` — Wave A demand catalog (Tier-2 fields, §6.4 VLAN/parse gap).
- `docs/REQUIREMENTS.md` — canonical spec (L2/L3 GGSN-Gi filter; EtherType + IPv6 are real
  requirements) + implementation-status table.
- `mint/design.md` §5.43/§5.47/§5.50 — the LPM-axis + mac-axis + B28-template brownfield history.

```yaml
architects:
  parallel:
    - name: gate
      lens: "Datapath demux-gate architect. You own the central structural decision: what the inner-EtherType gate at mac_filter.bpf.c:630 BECOMES once more than one L3 family is classified. Enumerate ALL viable shapes — (a) an EtherType if/switch branch inside the single XDP program (per-family parse + shared-or-per-family axis eval); (b) tail-call per family (L2-classify prog tail-calls an IPv4 prog / IPv6 prog); (c) EtherType folded in as a 7th exact-match bit-vector axis with the L3 parse still branched separately; (d) a two-stage L2-then-L3 classify split. Score each on: behavior-preservation of the existing IPv4 path (can it stay bit-identical?), eBPF-verifier feasibility (instruction/stack budget of a second parse path, tail-call count limits, map-in-map interaction), additive-ness (can it land as a behavior-preserving scaffold BEFORE any new family is matched?), per-packet cost-envelope (RELATIVE — branch mispredict / extra lookups / tail-call overhead; flag structural anti-patterns; NO absolute numbers), and atomic-swap/active_idx compatibility. Select 2-3 by trade-off diversification, NOT a favorite."
      scope: "The gate/demux structure + how the IPv4 path is preserved + verifier feasibility of a second parse path + relative cost-envelope. Do NOT design the cidr6 axis internals (addr-axis owns that), the EtherType match SEMANTICS (ethertype owns that), the YAML parser, actions beyond pass/drop, or AF_XDP/DPDK. Viability filter: must load under the verifier on the 6.1 kernel floor and preserve the single-u32 active_idx atomic-swap."
      sources:
        - "src/bpf/mac_filter.bpf.c (vlan_aware_l3 :533-549, the IPv4 gate :630, iphdr/ihl parse :633-657, bit-vector AND + ffsll + defaults fallthrough)"
        - "src/lib/loader.cpp (kManagedMaps, BITVEC_NUM_AXES :181/:192, atomic swap, copy-forward)"
        - "mint/architecture-rule-model.md (ratified bit-vector model + EtherType/IPv6 addendum)"
        - "Linux BPF verifier: tail-call limits, program stack/instruction budget, XDP multi-protocol parse (xdp-tutorial, web)"
        - "Cilium/Katran XDP per-family dispatch + bpf_tail_call patterns (web)"
    - name: addr-axis
      lens: "IPv6 address-axis & parse-feasibility architect. You own how IPv6 enters the bit-vector axis model. Design the cidr6 dst+src LPM axes by MIRRORING the IPv4 dst_cidr/src_cidr axes (close_prefixes / populate_bitvec_inner_slot, loader.cpp :1220/:1433, key xdpmf_cidr_v4) but with a 128-bit key (xdpmf_cidr_v6): LPM_TRIE 128-bit feasibility + prefix-closure over 128 bits, the per-rule bitmask lowering (does B28's aggregate_axis/populate_hash_inner_slot generalize, or is this the LPM family that B28 explicitly fenced as different-shape?), and the IPv6 L4 extraction — fixed 40B base header + the extension-header chain walk to reach the L4 proto/port, and how to BOUND that walk for the verifier (fixed unrolled depth? bpf_loop? skip-ext-headers cap?). Decide whether IPv4 and IPv6 SHARE the proto/port/vlan/mac axes (only the CIDR family differs) or run as parallel per-family axis stacks, and the map-topology cost (new cidr6_a/b ARRAY_OF_MAPS → BITVEC_NUM_AXES + kManagedMaps growth, atomic-swap/copy-forward impact). Select 2-3 shapes by trade-off."
      scope: "cidr6 axis shape + 128-bit LPM/prefix-closure + IPv6 L4/ext-header parse + verifier bounding + shared-vs-parallel axis sets + map-topology growth. Do NOT design the gate branch structure (gate owns it), the EtherType semantics, the YAML parser, negation, or actions. Viability filter: every claim checkable against the verifier / the existing LPM loader mechanism; 128-bit LPM must be a real BPF_MAP_TYPE_LPM_TRIE capability, not assumed."
      sources:
        - "src/lib/loader.cpp (close_prefixes :1220, populate_bitvec_inner_slot :1433, xdpmf_cidr_v4, BitPrefix, BITVEC_NUM_AXES)"
        - "src/bpf/mac_filter.bpf.c (IPv4 iphdr/ihl L4 parse :633-657 — the path IPv6 mirrors; the CIDR LPM axis lookups)"
        - "src/lib/config.hpp:44-50 (RuleMatch optional fields; xdpmf_cidr_v4 → where xdpmf_cidr_v6 goes)"
        - "mint/design.md §5.43 (LPM bit-vector axis genesis), §5.50 (B28 — what aggregate_axis covers vs the LPM family it fenced out)"
        - "BPF_MAP_TYPE_LPM_TRIE 128-bit key support; XDP IPv6 extension-header parsing + verifier-bounded loops (kernel docs, xdp-tutorial, web)"
    - name: ethertype
      lens: "EtherType match-semantics architect. You own what EtherType MEANS in the rule model and the standalone-value question. Decide among: (i) internal demux ONLY (no operator-facing ethertype match key — the gate routes by family, rules never name an ethertype); (ii) a coarse L2 exact-match axis (operator writes `ethertype: arp` / `0x86dd` + action — valuable for non-IP steering/drop even before IPv6 L3, per the DPI-prefilter select/steer purpose); (iii) both (demux internally AND an exposed axis). For (ii)/(iii): how does an ethertype axis AND-compose with L3 axes — is an `ethertype:ipv6`+`dst_cidr` rule coherent (needs cidr6) or must the lowering reject/auto-relate ethertype↔family? Is ethertype a 7th bit-vector axis (exact-match HASH, like proto/vlan — B28's populate_hash_inner_slot<u16> generalizes) or a gate-only concept? Address the dual relationship with the existing implicit IPv4 gate (does adding `ethertype:ipv4` duplicate it?). Score the options on operator value pre-IPv6, foreclosure, and lowering complexity. Select a recommendation with the trade-off explicit."
      scope: "EtherType match semantics + composition with L3 axes + axis-vs-demux + operator value pre-IPv6. Do NOT design the gate branch mechanics (gate owns), the cidr6 internals (addr-axis owns), the YAML parser details, negation, or actions beyond pass/drop. Viability filter: an exposed ethertype axis must fit the existing exact-match bit-vector axis pattern (HASH inner, aggregate_axis/populate_hash_inner_slot) or be justified as gate-only."
      sources:
        - "src/bpf/mac_filter.bpf.c (the inner-EtherType read in vlan_aware_l3 :533-549 + the :630 gate + :616 non-IPv4 fallthrough comment)"
        - "src/lib/config.hpp:44-50 (RuleMatch — where an `ethertype` optional field would sit) + config.cpp exact-match axis parse precedent (protocol/vlan)"
        - "mint/architecture-rule-model.md (EtherType=real L2 match PO decision → B31, the ratification addendum)"
        - "mint/selection-scenarios.md (Tier-2 EtherType field, the steer/select demand) + docs/REQUIREMENTS.md (EtherType requirement)"
        - "mint/design.md §5.44/§5.45/§5.50 (proto/vlan exact-HASH axis + B28 aggregate_axis<Key> — the pattern an ethertype axis would reuse)"
    - name: testability
      lens: "Verification & test-oracle architect. You own ONE question the structure/feasibility/semantics lenses do NOT: for each slice of the gate-rework, how is correctness PROVEN, and what MUST be tested? Concretely: (a) the S1 behavior-preservation proof — how do you assert the IPv4 verdict is bit-identical after the gate becomes an EtherType dispatch (oracle-agreement on the existing v4 corpus + a non-IPv4→default NEGATION control — an IPv6/ARP frame must still hit defaults[active]); what is the minimal control that fails a botched scaffold? (b) the IPv6 differential oracle — extend the bitvec_oracle_prod.py naive-scan reference to v6 (cidr6 + ext-header), and the inject-side reality: does inject_l4.py emit IPv6 frames at all, or is injector work itself a prerequisite slice? (c) 128-bit cidr6 prefix-closure correctness — how to test close_prefixes6 (the FI-1 cover-direction trap / guard #23 carried from the v4 LPM); what fixture proves a /48 covers a /64 it should and NOT one it shouldn't; (d) the ext-header-walk completeness test for S3-G AND its detectable fallback-to-S3-F (how does a test tell 'matched base-L4' from 'walked ext-headers'); (e) the EtherType axis test + the E6 coherence-guard test (a config with ethertype:ipv6 + dst_cidr must be REJECTED at lowering — how is that asserted, and what does E2-blind look like in a test instead); (f) verifier-load gating of the PRODUCTION object on the 5.15 floor per slice (T_BITVEC_VERIFIER_LOAD pattern). Recommend WHAT to test and HOW per slice; name who owns the cidr6-closure oracle. Score each candidate slice on differential-oracle friendliness (can a SCAN reference run side-by-side and assert bit-identical?)."
      scope: "Verification strategy + oracle design + the per-slice test surface + negation/fallback detectability + verifier-load gating. Do NOT pick the gate structure (gate's call), the cidr6 internals (addr-axis's), or the EtherType semantics (ethertype's) — instead, for each, say how its correctness is PROVEN and flag any UNTESTABLE choice. Viability filter: every check expressible as a ctest against the current harness (shell T_*.sh, bpftool prog load, fixture-driven oracle agreement, inject_l4.py)."
      sources:
        - "tests/T_AND*_ORACLE_AGREEMENT.sh + T_BITVEC_ORACLE_AGREEMENT.sh + T_MAC_MERGE_ORACLE_AGREEMENT.sh (the differential-oracle pattern this round extends to v6)"
        - "tests/T_BITVEC_VERIFIER_LOAD.sh (verifier-load gate on the kernel floor); tests/inject/inject_l4.py (does it emit IPv6? — the injector test-surface question); tests/bitvec/bitvec_oracle_prod.py (the naive-scan reference to extend for v6/cidr6)"
        - "src/lib/loader.cpp:1220 close_prefixes (the v4 LPM closure whose 128-bit mirror's correctness must be proven) + the FI-1 cover-direction trap / guard #23 in mint/design.md"
        - "mint/design.md §5.43/§5.50 (LPM axis + B28 oracle-net history); mint/architecture-rule-model.md (the ratified oracle-agreement verification posture)"
  sequential:
    - name: sequencer
      lens: "Slice-sequencing & minimality architect (this lens owns the human's actual question). Read gate + addr-axis + ethertype + testability. Fold testability's per-slice proof obligations into the sequence — a slice whose correctness cannot be PROVEN (no oracle, no negation control, untestable on the harness) is not round-1-ready regardless of how additive it looks. Produce the recommended /mint-dev SLICE SEQUENCE for the gate-rework + EtherType + IPv6 bundle: what ships FIRST and why. Pressure-test against the band's hardest-won lesson — additive-within-structure slices pass round-1, structural/cutover slices draw rework (mint-band-retro). Concretely evaluate the three candidate orderings: (A) IPv6-led — gate-rework + cidr6 together first, EtherType axis follows; (B) EtherType-gate-scaffold FIRST — rework the IPv4-only gate into an ethertype-dispatch that still routes only IPv4 to L3 (non-IPv4 → defaults, BEHAVIOR-PRESERVING + independently testable), THEN IPv6 as a purely additive cidr6 branch, THEN/with an exposed ethertype axis; (C) one big S8 slice. For the leading slice, state exactly what is behavior-preserving (the IPv4 verdict is bit-identical), how it is proven (oracle agreement + a non-IPv4→default negation control), and what each subsequent slice adds. Also rule on the human's premise: is a standalone EtherType axis before IPv6 a stub, a coarse-steering win, or a scaffold — and does any ordering FORECLOSE the others? Deliver a single recommendation-with-caveats + the slice list."
      scope: "Integrate the three lenses into ONE coherent slice-sequence recommendation + minimality critique. Do NOT introduce a brand-new gate structure or axis the parallels missed unless it is obviously superior. Viability filter: each proposed slice must be a plausible single /mint-dev cycle (small, testable, behavior-preserving where claimed); the sequence must not silently change a deployed config's meaning without an explicit schema bump."
      inputs: [gate, addr-axis, ethertype, testability]
      sources:
        - "mint/architecture-rule-model.md + docs/BACKLOG.md (B30 id/slot-decouple, B31 EtherType — how they interleave with this sequence)"
        - "mint/design.md §5.48/§5.49/§5.50 (the recent additive/housekeeping slices that passed round-1 — the shape to emulate)"
        - "docs/REQUIREMENTS.md (which of EtherType/IPv6 the spec prioritizes)"

output:
  path: "mint/architecture-l2l3-gate.md"
  mode: create

options:
  skip_design_reviewer: false
  max_rework_rounds: 2
```

## Notes for architects

- **Dual purpose**: serves the product (real L2/L3 filter — EtherType + IPv6 are canonical spec
  requirements, `docs/REQUIREMENTS.md`) AND trains the mint band. A clean, teachable,
  incrementally-shippable sequence beats a clever big-bang.
- **Behavior-preservation is the de-risking lever**: the strongest first slice is one where the
  IPv4 verdict stays bit-identical and the only observable change is structural — provable by the
  existing oracle-agreement harness + a non-IPv4→default negation control.
- **Additive beats structural** (mint-band-retro): additive-within-structure slices pass round-1;
  structural/cutover slices draw rework. Favor a sequence that front-loads the unavoidable
  structural change as ONE small, isolated, behavior-preserving slice, then makes the rest additive.
- **Brownfield discipline**: evolve the existing single-XDP-prog + ARRAY_OF_MAPS datapath; cite
  `file:line` for every change. B28 just made the axis lowering/populate generic — reuse it; know
  what it fenced out (the LPM family).
- **Narrow now, door open later**: pass/drop + non-foreclosure of steering; no actions, no L7, no
  negation this round.
- **EtherType is a weak-standalone signal**: do NOT manufacture an EtherType-first slice just to
  close B31 if it is a stub without IPv6 — say so plainly if the analysis shows it.
