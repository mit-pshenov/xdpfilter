# Architecture — L2/L3 demux gate-rework: EtherType + IPv6 (HLD synthesis)

> **Status:** design-space exploration (`/mint-hld`), 2026-05-30. NOT an implementation commitment — the PO forks in "Open questions" are resolved at `/mint-briefer` time, slice by slice.
> **Provenance:** `/mint-hld` on `mint/design-brief-l2l3-gate-v2.md` — 5-lens roster (parallel: **gate · addr-axis · ethertype · testability**; sequential: **sequencer**). Coherence-reviewer verdict: **pass (round 1)**. Run `wf_98f05ec8-a16`; raw per-lens artifacts + the v1 comparison under `~/agent-teams-review/runs/hld-l2l3-gate-202605301400/`.
> **A/B provenance (why this is the v2 synthesis):** chosen over a 4-lens v1 run (`design-brief-l2l3-gate.md`). The added **`testability` lens FIRED** — it surfaced the load-bearing **IPv6-injector prerequisite**: `tests/inject/inject_l4.py` cannot emit IPv6 frames, so every IPv6 oracle test would be *vacuously green* until a new `inject_l6.py` lands — which reorders the slice sequence (injector becomes S2, before any cidr6 slice). The 4-lens v1 run missed this. Lens kept in the methodology for any round introducing a new datapath test-surface. `perf-envelope` deliberately not added (folded into the `gate` lens; a separate perf lens would re-derive its per-packet scoring → fake convergence).

---

## Convergence (where architects agree)

- **(gate, addr-axis, ethertype, testability): The structural cutover must be ONE small, isolated, behavior-preserving slice, front-loaded.** All four converge on reshaping `:630` into an `if/else-if` demux with a dead IPv6 arm (gate's `i-scaffold-first`), proven bit-identical by re-running the unchanged v4 oracle corpus (testability VA-1). Everything after is additive-within-structure.

- **(gate, addr-axis): IPv4 and IPv6 share the proto/port/vlan/mac axes — only the CIDR family is per-family.** gate's "shared-axes = hoist the family-independent lookups above the gate"; addr-axis's `BITVEC_NUM_AXES 6→8` (+DST6/+SRC6 only). Parallel per-family stacks (addr-axis C, +6 axes) rejected by both as pure churn.

- **(gate, addr-axis, ethertype): The new axes ride the existing single-`active_idx` atomic swap "for free."** New ARRAY_OF_MAPS trios index off the same `active` snapshot at `:609`; `wildcard` ARRAY auto-grows via `XDPMF_RULESET_COUNT*BITVEC_NUM_AXES`; `kManagedMaps[]` extends by +3 rows per axis. No swap-protocol change.

- **(gate, sequencer): The tail-call-per-family split is explicitly foreclosed.** PROG_ARRAY (fixed 4B key, literal-indexed) is NOT an `active_idx`-keyed ARRAY_OF_MAPS — it can't ride the atomic swap; plus stack drops 512→256B; no instruction-limit pressure justifies it at 2 families. Reserve only for a future >2-family/AF_XDP explosion.

- **(ethertype, sequencer, addr-axis): The EtherType axis is weak-standalone — `ethertype:ipv4` is redundant with the gate; only non-IP coarse steering (`ethertype:arp drop`, `0x86dd drop`) is genuine pre-IPv6 value.** It is a clone of the proto exact-HASH axis (B28 `aggregate_axis<u16>`), and family-coherence rejection (the `ethertype:ipv6 + dst_cidr` cross-axis validation) is deferred polish, not front-loaded structural validation (which draws rework).

- **(addr-axis, testability): The two genuinely sharp edges are the 128-bit prefix closure (FI-1/guard #23 cover-direction) and the IPv6 ext-header walk — and they should NOT share a slice.** Both are new bug surfaces; bundling them = rework magnet. addr-axis splits cidr6 into no-ext-walk (E) then ext-walk (A); testability validates the split via the VA-5 detectability trap.

## Divergence (where architects substantively disagree)

- **(gate vs addr-axis): Which subsystem owns the front-loaded structural slice — datapath or loader?** gate argues slice-1 is the `:630` datapath reshape (no map change) because the gate is the choke point. addr-axis argues slice-1 is the LPM-template refactor F (loader-only, no datapath change) because B28 fenced the LPM family out and a copy-paste `cidr6` violates rule-of-three. **Implication:** these are NOT competitors — they touch disjoint files and neither changes a verdict. sequencer resolves: TWO independent behavior-preserving de-riskers, shippable in either order (or parallel).

- **(sequencer vs ethertype/PO): Does the EtherType axis co-ship with cidr6 or land earlier as its own slice?** ethertype (echoing the PO ratification) argues co-ship "with the IPv6 axis slice" because it's the same ethertype-gate touch. sequencer argues split it EARLIER as a free-standing additive HASH axis because (a) the gate-scaffold S1 already absorbs the single gate touch, (b) the ethertype axis is testable NOW via `inject_eth.py` while cidr6's test is blocked on the injector, so front-loading its non-IP-steering value is pure upside. **Implication:** a genuine fork for the PO — split (lean) vs fuse S4+S5 into one `6→9` flip.

- **(addr-axis vs testability, on parse depth): Is the no-ext-walk variant (E) a safe first cut?** addr-axis presents E as the de-risked first v6 slice (zero loops = zero verifier loop-risk). testability flags that E's proto-axis sees the FIRST nexthdr (an ext-header number, not true L4) on ext-bearing frames, and that "matched base-L4 vs walked ext-headers" is undetectable by a port-wildcard rule — so E is only honest if proto-matching is gated to the recognized-L4 case AND the eventual walk (A) is tested with a purpose-built port-constrained rule. **Implication:** E is acceptable as a first cut only with the proto-gating discipline; the walk's correctness proof is itself a non-trivial test-construction task deferred to S6.

## Composite directions (cross-lens combinations)

### Option 1 — Five-Step Additive Ladder (the sequencer spine)

- **Composition:** gate.`i-scaffold-first` (S1) + testability.VA-4 `inject_l6.py` (S2) + addr-axis.F LPM-template (S3) + addr-axis.E cidr6-no-walk (S4) + ethertype.Approach-3 coarse axis (S5), with addr-axis.A ext-walk + ethertype.Approach-5 reject deferred to S6. Proofs: testability VA-1/VA-2/VA-3/VA-5/VA-10.
- **First slice scope:** S1 — reshape `mac_filter.bpf.c:630` into `if(ETH_P_IP){…unchanged…} else if(ETH_P_IPV6){ bounds-check ipv6hdr only; fall to defaults }`. No `BITVEC_NUM_AXES` change, no new map, no `kManagedMaps[]` row.
- **Risk profile:** LOW for S1/S2/S3 (behavior-preserving or tool-only, disjoint files); MED for S4 (axis-count growth + 128-bit closure); the two sharp edges (closure in S4, walk in S6) are kept in separate slices.
- **User value cycle 1:** none observable (S1 is bit-identical by design) — the value is a proven-shippable structural cutover + a passing oracle. Operator-visible value starts at S4 (IPv6 CIDR matching) and S5 (ARP/non-IP steering).
- **Costs:** TTFW ~5-6 `/mint-dev` cycles to full IPv6+EtherType; small per-slice LOC (S1 ~datapath-local, S2 ~new test tool, S3 ~templating, S4 ~+2 axes+closure+parse, S5 ~axis clone). Deps: S4 needs S1∥S2∥S3; S5 needs S4's flip (or fuse); S6 needs S4. Sacrifices: ext-header port-matching until S6; loud family-coherence rejection until S6.
- **Preserves:** IPv4 verdict bit-identical; single-`active_idx` atomic swap; schema_version 2 (additive `std::optional` fields); strict-unknown-key gate; first-match-by-id + `ffsll` + `defaults[active]` fallthrough.
- **Open Qs:** split vs fuse S4/S5 (Divergence 2); is S2 a standalone slice or folded into S4's prep?

### Option 2 — Co-Ship IPv6+EtherType (PO-literal "land together")

- **Composition:** S1 + S2 + S3 as in Option 1, then a FUSED S4' = addr-axis.E cidr6 axes **+** ethertype.Approach-3 axis in one `BITVEC_NUM_AXES 6→9` flip (one macro bump, one `kManagedMaps[]` growth batch, one verifier-load gate), ext-walk + reject still deferred to S6.
- **First slice scope:** identical S1 (gate scaffold).
- **Risk profile:** MED — S4' carries three axes' worth of change (DST6, SRC6, ETHERTYPE) but all three are individually additive; the gate touch was already paid in S1.
- **User value cycle 1:** same as Option 1 (S1 bit-identical); but the IPv6 + EtherType operator value lands together in one later cycle, honoring the PO co-ship intent and the "same gate touch" reasoning.
- **Costs:** TTFW ~5 cycles (one fewer than Option 1 by fusing); larger S4' diff (harder to bisect/review); the ethertype non-IP-steering value is delayed vs Option 1 (can't ship before the injector lands).
- **Preserves:** identical invariants to Option 1.
- **Open Qs:** does a 3-axis flip stay round-1-passable, or does the larger surface re-introduce the structural-rework risk the split was avoiding?

### Option 3 — EtherType-First Early-Value (challenge the co-ship)

- **Composition:** S1 gate-scaffold + ethertype.Approach-3 as an EARLY standalone L2-only coarse-steering axis (testable now via `inject_eth.py`, testability VA-10) BEFORE the injector/cidr6 work; then S2/S3/S4 cidr6 afterward.
- **First slice scope:** S1, then immediately the ethertype HASH axis (`BV_AXIS_ETHERTYPE`, clone of proto) closing B31's `ethertype:arp/0x86dd drop` value.
- **Risk profile:** LOW-MED — the ethertype axis is small/additive and testable today; but it inverts the PO co-ship hint and front-loads B31 ahead of its "natural" IPv6 partner.
- **User value cycle 1 (after S1):** real — coarse non-IP steering (drop ARP / drop-IPv6-wholesale-pre-cidr6) ships before any IPv6 plumbing.
- **Costs:** TTFW to *EtherType value* ~2 cycles; full IPv6 still ~5-6. Sacrifices the PO's "one gate touch / co-ship" tidiness; risks shipping `ethertype:ipv6` as L2-only (composes with nothing below L3) until cidr6 lands — must document.
- **Preserves:** same invariants; `ethertype:ipv4` documented legal-but-redundant.
- **Open Qs:** is early non-IP steering worth inverting the PO ratification, given it shares the same axis-count/verifier surface as IPv6 anyway?

### Option 4 — Two-Stage Steady-State (gate.d as the end-shape, not just slice-1)

- **Composition:** Option 1's ladder PLUS an explicit commitment to gate.`d-two-stage` as the steady-state datapath: hoist the family-independent axis lookups (mac/vlan/etype) ABOVE the gate into Stage-1, leaving only CIDR/proto/port in the family switch (Stage-2). Pays down the addendum perf-TODO ("~12 packet-invariant lookups re-fetched") structurally.
- **First slice scope:** S1 scaffold unchanged; the hoist becomes its own additive behavior-preserving slice (relocate lookups, same expressions → bit-identical) inserted before or alongside S4.
- **Risk profile:** MED — the hoist is behavior-preserving by construction but touches more of the datapath than the minimal scaffold; provable bit-identical via the same VA-1 corpus.
- **User value cycle 1:** none observable; the value is lower per-packet cost (relative, no absolute numbers per the perf-envelope amendment) + a cleaner shared-vs-per-family code structure.
- **Costs:** +1 slice (the hoist) vs Option 1; larger cumulative datapath churn. Sacrifices nothing functionally; pure structural refinement.
- **Preserves:** all Option 1 invariants + makes the shared-axis decision explicit in code.
- **Open Qs:** is the hoist worth a dedicated slice now, or deferred as a later optimization once IPv6 is functionally complete?

## Recommendation (with caveat)

**Lean: Option 1 (Five-Step Additive Ladder).** It is the tightest fit to the documented additive-beats-structural lesson: it isolates each unavoidable structural move (gate reshape S1, LPM-template S3, axis-count growth S4) in its own behavior-preserving slice, makes everything else additive, and — critically — honors testability's orthogonal finding that **the IPv6 injector (S2) is a hard prerequisite, without which every IPv6 oracle test is vacuously green.** That injector-gating is the single signal the v1 roster would have missed, and it is load-bearing: it reorders the naive sequence and prevents shipping a slice with a vacuous proof. Fold gate.d's hoist (Option 4) in later only if the relative per-packet cost matters.

**Biggest caveat:** the split-vs-co-ship of the EtherType axis (S5 vs fused S4') is a genuine PO fork, not an architect's call. The sequencer leans split (early non-IP-steering value, testable now), but this mildly inverts the PO's ratified "land EtherType WITH the IPv6 slice" decision (B31). The justification — that S1's scaffold already absorbs the single "ethertype-gate touch" the co-ship reasoning was protecting — is sound but should be ratified by the PO before S5 is sequenced. If the PO wants the literal co-ship, collapse to Option 2 (fuse into one `6→9` flip).

## Open questions (need human input)

1. **Split or co-ship the EtherType axis?** Option 1 (split, ethertype as its own additive S5, possibly early per Option 3) vs Option 2 (fuse S4+S5 into one `BITVEC_NUM_AXES 6→9` flip). The PO ratified "co-ship"; the sequencer leans split. PO call.
2. **No-ext-walk first (S4=E) then walk later (S6=A), or walk in S4 directly?** All architects lean split (two sharp edges apart), but it sacrifices IPv6 port-matching on ext-header-bearing frames until S6. Acceptable on Gi?
3. **Family-coherence: silent-never-match (ethertype Approach 3) or loud exit-9 reject (Approach 5)?** Lean silent-now / loud-later-polish. Confirm the silent-never-match operator footgun is tolerable in the interim.
4. **Is the gate.d hoist (Option 4) worth a dedicated slice in this arc, or deferred?** Relative per-packet cost vs added churn.
5. **`ethertype:ipv4` — accept-as-redundant or reject?** Lean accept-and-document. Confirm.

## Hidden assumptions

- **The existing v4 oracle corpus is a sufficient behavior-preservation proof for the gate reshape.** If the corpus has coverage gaps (e.g., no VLAN-stacked or malformed-IPv4 vectors near the gate boundary), "green = bit-identical" is weaker than claimed and S1's de-risking evaporates — flips the recommendation toward Option 4's explicit hoist-with-proof or a corpus-expansion pre-slice.
- **`inject_l6.py` is genuinely additive and round-1-passable.** If IPv6 frame construction (ext-header chains, ICMPv6) proves fiddly enough to need iteration, S2 becomes a critical-path blocker rather than a parallel tool-slice — flips the parallel S1∥S2∥S3 DAG into a serial dependency and lengthens TTFW.
- **128-bit `close_prefixes6` is "just a wider masked compare."** If the FI-1 cover-direction arithmetic has a width-dependent subtlety (partial-last-byte masking at 128 bits), S4's sharp edge is sharper than scored and may itself warrant splitting closure from axis-introduction.
- **Schema stays at version 2 (additive `std::optional` fields don't reinterpret any existing key).** If any deployed config or downstream consumer treats schema_version as a compatibility gate on field-set size, the "no bump" assumption breaks and S4/S5 need a schema migration story.
- **The PO's "co-ship" reasoning was purely about the shared gate touch.** If the PO co-ship intent was actually about operator-facing coherence (don't expose `ethertype:ipv6` before `cidr6` makes it meaningful), then the split (Option 1/3) is wrong regardless of the gate-touch argument, and Option 2 is mandatory.
