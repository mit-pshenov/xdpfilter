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


---

## S4 cidr6 — IPv6 CIDR axes (design round)

> mint-hld round (Workflow `wf_fb92d53a-22f`, 2026-05-31). Roster: classifier · closure · realizability · testability (parallel) + contrarian (sequential). Coherence verdict: pass (round 2). Grounder verdict: `claims-refuted`. **Read the discharge ledger at the end of this section before treating any sizing/sequencing claim as settled.**

# Synthesis (round 2)

## Convergence (where architects agree)

- **(classifier, closure, realizability, contrarian): The datapath shape is settled — two new sibling LPM axes `dst6`/`src6` with kernel-canonical key `{__u32 prefixlen; __u8 addr6[16]}` in network byte order (`addr6[0]=MSB`), `memcpy(...,16)` straight from `ip6->daddr/saddr`.** All four converge here; this is the additive-within-stamp path every prior slice took round-1-pass. [needs-grep — key shape mirrors `xdpmf_cidr_v4` at `mac_filter.h:40`]
- **(classifier, realizability): The bit-vector AND composition does NOT reshape — it only gains two `__u64` terms.** The per-axis result is already a `__u64` bitmask regardless of v4-vs-v6 key width, so `ffsll` first-match + dispatch tail are width-agnostic. `BITVEC_NUM_AXES 6→8`; `wildcard` max_entries auto-grows 12→16 via the existing formula (no literal edit). [needs-grep — `XDPMF_RULESET_COUNT * BITVEC_NUM_AXES` formula at `mac_filter.h:210`]
- **(closure, contrarian): The 128-bit closure is PURE userspace host code with ZERO verifier exposure** — the kernel LPM trie does the prefix match, the datapath only `memcpy`s 16 bytes and does a map lookup. This dissolves the brief's "does the 128-bit compare load on 5.15" open-Q *for the closure*. Realizability authors the companion datapath-half discharge (the datapath arm itself is proven loadable: 40B stack / 66 insns / clean load on 6.1.0-44), affirming the datapath/closure split but not the closure's zero-verifier-exposure claim. [needs-spike for the datapath arm; closure math is host-side, not on the verifier path]
- **(closure, contrarian): The template-vs-copy decision resolves to FORK/copy-paste, not template** — rule-of-three is at TWO (v4+v6), and the two closure bodies have *different UB profiles* (v4 only `==0`; v6 adds limb-boundary or partial-byte cases). Coupling them prematurely couples two correctness-critical bodies. [grounded — this is an architectural-discipline judgment the architects defend, not a code fact]
- **(closure, testability, contrarian): The #1 risk is correctness (cover-direction + partial-byte/limb-boundary masking), NOT realizability or config-surface.** Guard #23 (covering rule has lower id) is *more* load-bearing for v6 because realistic prefixes (/32,/48,/64) sit far apart, so naive "longest-match-is-the-winner" tests pass vacuously. [grounded — both lenses independently identify the same blind spot]
- **(testability, classifier, closure): The oracle must mask in the 128-bit integer domain (not per-byte/per-limb)** so non-aligned prefixes (/40,/68,/127) are exercised by construction, and the v6 oracle is algorithm-different from the datapath (kernel trie vs Python arbitrary-precision int) per guard #23. [needs-grep — oracle 32-bit mask at `bitvec_oracle_prod.py`]

## Divergence (where architects substantively disagree)

- **(classifier vs closure+realizability+contrarian) — key representation as a live fork:** classifier surfaces A5 (`__u64[2]` limb key) and C/D (typed keys) as a scoreable representation fork to ease closure arithmetic. closure/realizability/contrarian collapse it: a host-order limb key silently mis-matches the trie's byte-wise MSB-first walk (byte-order trap); the LPM key MUST be the network-order byte array, and closure works on `__int128`/byte-array *internally* then serializes to those bytes. **Implication: no key fork survives scrutiny — the key is settled as `addr6[16]`; the only live choice is the closure's *internal* arithmetic representation, which never touches the trie.** [needs-grep — confirm `loader.cpp:1462` "addr already network order" for v4 serialization precedent]

- **(closure vs contrarian) — closure internal representation:** closure offers Selection A (`unsigned __int128`, visually-auditable v4 mirror) vs Selection B (16-byte array, UB-immune, no special-case at /0). contrarian adopts `__int128` for visual auditability of the cover-direction invariant, with byte-array as the `__SIZEOF_INT128__`-absent fallback. **Implication: `__int128` preferred IF the toolchain has it; otherwise byte-array. A grep settles it.** [needs-grep — `__SIZEOF_INT128__` / C++ std + compiler in loader build flags]

- **(contrarian vs brief+testability) — config-surface scope:** the brief frames the IPv6 reject as two `config.cpp:408/421` sites + a guard-#24 `attach --allow` bypass parity concern; testability proposes a config-parity vector. contrarian REFUTES: the reject is a *single* chokepoint at `cidr.cpp:68-72` (any `:` in the string), and `attach --allow` synthesizes Config from MACs only (`loader.cpp:1867`) and structurally cannot carry a v6 CIDR. **Implication: config-widening is NARROWER than framed (one chokepoint), and the guard-#24 parity vector tests an unreachable path — drop it.** [needs-grep — verify single reject at `cidr.cpp:68-72` + MAC-only synthesis at `loader.cpp:1867`]

- **(realizability "DISCHARGED" vs contrarian "uncorroborated") — spike confidence:** realizability tags the load-proof `[DISCHARGED — spike]` (40B stack / 66 insns / clean load on 6.1.0-44). contrarian downgrades to `[DISCHARGED — spike, UNCORROBORATED externally]` because the cited `subnet6_rules` corroboration lives in a *different* project (`/home/user/filter/`) and the session is unreplayable. **Implication: re-confirm with a fresh load at slice-time; do not lean on the external artifact.** [needs-spike — fresh `bpftool prog load` at slice-time]

## Composite directions (cross-lens combinations)

### Option 1 — One Gated Slice (`__int128` fork)
- **Composition:** classifier.A1 (sibling +2, byte-array key) + closure.A (`unsigned __int128`) + closure.C (spike-as-inner-gate, NOT slice) + realizability.A (proven-load mirror) + testability.A1+A6+A7 (clone-triad + golden-dump + ext-honesty) + contrarian's integrated lean.
- **First slice scope:** key struct + `host_mask6`/`close_prefixes6`/`BitPrefix6` + `BITVEC_NUM_AXES 6→8` + 6 maps + 6 `kManagedMaps[]` rows + `:861` datapath arm + `cidr.cpp` family-dispatch + `Rule.match` optional v6 fields + oracle `--ruleset andv6` + 3 ctests (agreement battery, closure canary, golden-dump). **Inner gate (sequencing constraint, NOT a slice split): the closure partial-byte + cover-direction unit/golden test goes GREEN before the `:861` datapath arm is wired** [grounded — composes closure ⟦SEQ⟧ ("the partial-byte cover-matrix unit test MUST gate before the datapath arm at `mac_filter.bpf.c:861`") + contrarian "[SEQ — inner gate, NOT a slice split]"; both architects defend it as in-slice ordering, parallel to the fork-not-template discipline].
- **Risk profile:** MED — realizability settled green by spike; residual risk is closure correctness, contained by the mandatory pre-datapath gate. [needs-spike — fresh load; needs-grep — closure LOC]
- **User value cycle 1:** IPv6 src/dst CIDR rules become matchable end-to-end — closes the #1 functional gap after IPv4. [genuine-PO-value — IPv6 is a real Gi traffic class; today every v6 frame is unclassifiable]
- **Costs:** TTFW = 1 cycle [needs-grep]. LOC ≈ closure ~30-40 + datapath arm ~40 + maps/header ~60 + config ~20 + tests ~200 [needs-grep — count `loader.cpp:1199-1236` + v4 arm at slice-time]. Deps: inject_l6.py (S2, shipped). Sacrifices: no templating (deferred to 3rd LPM family), no ext-walk (S6), no EtherType axis (S5).
- **Preserves:** IPv4 verdict bit-identical (v4 arm untouched), single-`active_idx` atomic swap, schema_version 2 additive, first-match-by-id + `defaults[active]` fallthrough, closure output type `std::vector<std::uint64_t>`.
- **Open Qs:** cross-family rule-bit-allocation (same id in axes 0+6?) [needs-grep]; `__SIZEOF_INT128__` availability [needs-grep].

### Option 2 — One Gated Slice (byte-array fork, toolchain-agnostic)
- **Composition:** identical to Option 1 EXCEPT closure.B (16-byte array, memcmp+partial-byte) replaces closure.A.
- **First slice scope:** same as Option 1 with `covers6()` byte-loop instead of `__int128` masking; `BitPrefix6` carries `addr6_bytes[16]` instead of `host_addr6` `__int128`. **Same inner gate (sequencing constraint, NOT a slice split): closure partial-byte + cover-direction unit/golden test GREEN before the `:861` arm is wired** [grounded — composes closure ⟦SEQ⟧ + contrarian "[SEQ — inner gate, NOT a slice split]"].
- **Risk profile:** MED — removes the `__int128` toolchain assumption and the shift-by-128 UB site entirely (every shift ≤7); /0 falls out naturally with no special-case. Trades the visual-v4-symmetry that makes cover-direction auditable. [grounded — UB-immunity is structural]
- **User value cycle 1:** identical to Option 1. [genuine-PO-value — IPv6 Gi traffic class, today unclassifiable]
- **Costs:** TTFW = 1 cycle [needs-grep]. LOC ≈ Option 1, byte-loop slightly longer than `__int128` body [needs-grep]. Same deps/sacrifices.
- **Preserves:** same as Option 1, PLUS no new toolchain dependency.
- **Open Qs:** same cross-family question [needs-grep]; byte-loop is harder to eyeball-verify against the v4 cover-direction invariant.

### Option 3 — Spike-First Two-Step (closure as committed pre-slice)
- **Composition:** closure.C-as-slice (ship `host_mask6`/`close_prefixes6` + partial-byte cover-matrix unit test + golden-dump tooling in isolation) THEN a second slice wires `:861` + maps + config.
- **First slice scope:** host-only closure math + unit tests + `read_v6_closure.py` tooling; NO datapath, NO maps, NO config widening.
- **Risk profile:** LOW per-slice but HIGH process-waste — closure has no independently-shippable value with no axis to feed. contrarian explicitly flags this as repeating the S1→S6 over-decomposition mistake the brief warns against. [grounded — architects converge AGAINST this]
- **User value cycle 1:** NONE at the network — no v6 frame matches until slice 2. [genuine-PO-value — negative: zero operator-visible value cycle 1]
- **Costs:** TTFW = 2 cycles [genuine-PO-value — two committed cycles before first operator-visible v6 match]. Higher total orchestration overhead.
- **Preserves:** same invariants.
- **Open Qs:** is there ANY consumer of a standalone `close_prefixes6`? (architects say no.) [grounded — architects converge no]

### Option 4 — Template-Now (pay the abstraction)
- **Composition:** classifier.A2 (macro `XDPMF_DEFINE_LPM_AXIS` + templated `close_prefixes<AddrT>`/`lower_lpm_axis<AddrT>`) — re-express the shipped v4 LPM axes through the shared template, instantiate 4 axes.
- **First slice scope:** Option 1 scope PLUS refactoring the existing v4 dst/src/cidr decls through the macro/template + a byte-identical-v4 proof (BTF/map-dump diff).
- **Risk profile:** HIGH — perturbs shipped v4 axes at the source level; demands a binary-identical proof Option 1 gets for free; couples two bodies with divergent UB profiles. [grounded — contradicts the rule-of-three-at-2 + divergent-UB rationale all architects accept]
- **User value cycle 1:** same v6 matching as Option 1, but at higher risk to the v4 invariant. [genuine-PO-value — value-neutral vs Option 1 while risk-positive]
- **Costs:** TTFW = 1 cycle but higher rework probability [needs-grep]. LOC: lower long-term (DRY) but higher this-slice churn [needs-grep].
- **Preserves:** v4 verdict (IF the byte-identical proof passes — the load-bearing IF).
- **Open Qs:** can the macro reproduce the v4 BTF/map layout byte-identically? [needs-spike — BTF/map-dump diff].

## Recommendation (with caveat)

**Lean: Option 1 (One Gated Slice, `__int128` fork), with Option 2 (byte-array) as the automatic fallback if the `__int128` grep fails.** It is the additive-within-stamp path the project has repeatedly shipped round-1, realizability proves the datapath loads, and the closure-unit-test-as-inner-gate removes the only real (correctness) risk up front without the process waste of a slice split. The `__int128` body makes the cover-direction invariant visually auditable against the shipped v4 body — the single highest-leverage defense against the #1 bug class. The inner gate is a sequencing constraint *inside* the one slice: **the closure partial-byte + cover-direction unit/golden test must go GREEN before the `:861` arm is wired** [grounded — composes closure ⟦SEQ⟧ + contrarian "[SEQ — inner gate, NOT a slice split]"].

**Single biggest caveat:** the cross-family rule-bit-allocation semantics (can one rule-id set bits in both axis-0 `dst_cidr` and axis-6 `dst_cidr6`, and the wildcard-fill MUST populate all 8 halves so v4-only rules set unconstrained bits in `wc_dst6/wc_src6`) is genuine non-obvious in-scope work that is NOT a stamp-copy — if the briefer treats it as out-of-scope, cross-family rules will spuriously drop. [needs-grep — wildcard-fill loop in `populate_all_axes` / `loader.cpp:2006-2030`]

## Open questions (need human input)

1. **Cross-family rule semantics:** may a single rule carry BOTH `dst_cidr` (v4) and `dst_cidr6` (v6) — matching v4-frames-via-axis-0 OR v6-frames-via-axis-6 as one id — or are they mutually exclusive per rule? [needs-grep — structurally one id can occupy all 8 axes; decision drives wildcard-fill]
2. **`__int128` vs byte-array closure:** is `__SIZEOF_INT128__` defined in the loader toolchain? Settles Option 1 vs Option 2 mechanically. [needs-grep — loader build flags / C++ std]
3. **Ext-header honesty test (testability.A7):** ship the `--ext` injector + honesty contract in S4 (cheap red→green hand-off for S6), or defer entirely to S6? [genuine-PO-value — cheap insurance vs S4 scope-boundary cleanliness; PO call on slice-boundary discipline]
4. **Spike re-confirmation:** accept realizability's spike numbers, or require a fresh `bpftool prog load` at slice-time before sizing is locked? [needs-spike — external corroboration was a different project]

## Hidden assumptions

- **`__SIZEOF_INT128__` is available in the loader's host toolchain.** If FALSE → Option 1 is infeasible, recommendation flips to Option 2 (byte-array). [needs-grep — grep build flags + confirm at config-time]
- **The IPv6 reject is a single chokepoint at `cidr.cpp:68-72`, and `attach --allow` is MAC-only.** If FALSE (reject is genuinely multi-site, or `--allow` can carry CIDR) → config-surface scope grows and the guard-#24 parity vector returns to scope. [needs-grep — verify `cidr.cpp:68-72` + `loader.cpp:1867`]
- **The v6 datapath arm loads within the 5.15 verifier budget.** If FALSE → S4 may need a pre-slice spike-as-commit, flipping toward Option 3. Spike says green (40B/66insns) but is externally uncorroborated. [needs-spike — fresh load at slice-time]
- **Closure output stays `std::vector<std::uint64_t>` (bit-vector width unchanged at 64); only the address widens.** If FALSE (rule count exceeds 64 → wider bit-vector) → `populate_bitvec_inner_slot` and the whole composition reshape. Architects verified the bit-vector is rule-indexed, not address-indexed. [needs-grep — `populate_bitvec_inner_slot` consumes vector unchanged at `loader.cpp:1460-1463`]
- **The wildcard-fill currently populates per-axis halves in a loop that bumping `BITVEC_NUM_AXES` auto-extends, AND v4-only rules will get v6-axis wildcard bits set.** If FALSE (wildcard-fill is hand-enumerated per axis, or doesn't set bits for unconstrained axes) → cross-family rules spuriously drop and the wildcard-fill is manual net-new work, not auto-grown. [needs-grep — wildcard-fill in `populate_all_axes`, `loader.cpp:2006-2030`]

---

## S4 cidr6 — discharge ledger (grounder, claims-refuted)

> Terminal discharge-pass of the synthesis above (mint-hld grounder phase). Verdict **`claims-refuted`**. Spike subsequently RUN — see note.

**Summary:** Final pass (full code now read). ONE sizing claim refuted: the synthesis's Hidden assumption that "wildcard-fill populates per-axis halves in a loop that bumping BITVEC_NUM_AXES auto-extends" is FALSE — write_wildcard_slots (loader.cpp:1529-1555) is HAND-ENUMERATED (6-row struct table + 6-arg signature wc_dst..wc_mac); only the map's max_entries auto-grows, the WRITE path does not. Adding DST6/SRC6 wildcard slots is net-new wiring (2 struct rows + 2 params + 2 call-site args at :1787-1790), real work the synthesis under-stated. Everything else grounded: closure returns std::vector<std::uint64_t> (synthesis RIGHT — I withdraw an erroneous earlier refutation), closure address math is 32-bit (brief refutation GROUNDED), wildcard formula / empty :861 seam / single cidr.cpp chokepoint / MAC-only attach / 32-bit oracle / populate consumption all GROUNDED. __SIZEOF_INT128__ effectively grounded (C++23, gnu ext on x86-64). One required pre-slice spike survives: 5.15 verifier load (existing spike was wrong-kernel/reduced-stub/uncorroborated). PO plate: 1 genuine survivor; 3 reclassified off.

### Refuted (the plan was wrong here — use the correction)
- **Claim:** Hidden assumption: 'The wildcard-fill currently populates per-axis halves in a loop that bumping BITVEC_NUM_AXES auto-extends' (synthesis Hidden assumptions block; underpins the 'additive auto-grow' sizing of the v6-axis wildcard work and the cross-family caveat).
  - **Ground truth:** loader.cpp:1529-1555 write_wildcard_slots: the write path is a HAND-ENUMERATED struct array with exactly 6 rows {BV_AXIS_DST,SRC,PROTO,PORT,VLAN,MAC} and a fixed 6-parameter signature (wc_dst,wc_src,wc_proto,wc_port,wc_vlan,wc_mac); the call site at loader.cpp:1787-1790 passes 6 explicit .wildcard args. The `for (const auto& s : slots)` loop iterates the hand-built 6-row table, NOT all BITVEC_NUM_AXES. Only the MAP max_entries auto-grows via the formula (mac_filter.bpf.c:210); the write function does not.
  - **Corrected:** Bumping BITVEC_NUM_AXES 6->8 does NOT auto-extend the wildcard WRITE. Adding dst6/src6 wildcard halves is NET-NEW wiring: +2 rows in the write_wildcard_slots `slots[]` table (BV_AXIS_DST6/SRC6), +2 params on the signature, +2 args at the populate_all_axes call site (loader.cpp:1787-1790), plus lower_axis6 producing dst6_low.wildcard/src6_low.wildcard. It is mechanical and low-risk (mirrors the existing rows) but it is REAL code, not a free auto-grow — the briefer must size it and ensure v4-only rules get their bit set in the DST6/SRC6 wildcard (else cross-family rules spuriously drop in the v6 arm).

### PO plate (genuinely needed human input)
- **Q:** Ship the ext-header honesty test + inject_l6.py --ext in S4 (cheap red->green hand-off for S6), or defer entirely to S6? (synthesis Open-Q 3 / testability A7)
  - **External value:** Slice-boundary scope discipline / TTFW-of-S4 vs S6-de-risking. Absorbing net-new --ext injector tooling into S4 for a future-S6 benefit vs keeping S4's acceptance surface minimal is a genuine process/risk-appetite trade a code-only engineer cannot settle: it depends on how the operator values an executable honesty-contract now vs later. Survives the filter as a real slice-boundary call.
  - **PO decision (2026-05-31):** ext-header honesty → ship base-nexthdr, mark the boundary honestly, ext-walk deferred to S6 (derived from project strategy: model-validation, not production; all S to be closed).

### Reclassified off the PO plate (anti-leak — discharged, NOT human questions)
- **Q:** Cross-family rule semantics: may a single rule carry BOTH dst_cidr (v4) and dst_cidr6 (v6) as one id, or are they mutually exclusive? (synthesis Open-Q 1, routed to 'need human input')
  - **Why not PO:** No external value survives. lower_axis (loader.cpp:1265-1266) already routes a rule that does NOT set an axis to that axis's wildcard (out.wildcard |= bit), and one rule-id structurally occupies a bit in every axis. A v4-only rule lands in the v6-axis wildcard by the SAME mechanism it already lands in proto/port/vlan/mac wildcards today — a mechanical consequence of the existing lowering + the (net-new, see refuted[]) write_wildcard_slots v6 rows, NOT a product decision. Whether to allow both in one rule falls out of the wildcard mechanism + round-1-passability. A competent engineer with lower_axis + write_wildcard_slots answers this with zero product/risk input.
  - **Rerouted:** `grounded`
- **Q:** __int128 vs byte-array closure: is __SIZEOF_INT128__ defined in the loader toolchain? (synthesis Open-Q 2 / Hidden assumption)
  - **Why not PO:** Pure code/toolchain fact, now discharged: CMakeLists.txt:30 sets CMAKE_CXX_STANDARD 23 with no CMAKE_CXX_EXTENSIONS OFF => gnu++23, and `unsigned __int128` is a GNU extension always available on the x86-64 target (GCC/Clang). So __SIZEOF_INT128__ is defined; Option 1 (__int128) is feasible. Zero external value; mechanically settled.
  - **Rerouted:** `grounded`
- **Q:** Spike re-confirmation: accept realizability's spike numbers, or require a fresh bpftool prog load at slice-time? (synthesis Open-Q 4)
  - **Why not PO:** Not a PO value call — a hard engineering prerequisite. The spike ran on 6.1.0-44 (not the 5.15 floor), used a reduced 2-lookup stub (not the full 8-term arm), and was externally uncorroborated (cited subnet6_rules belong to a different project). Re-confirmation is mandatory regardless of product/priority judgment.
  - **Rerouted:** `needs-spike`

### Required pre-slice spike — RUN 2026-05-31, **PASS**
- **Must prove:** The FULL S4 v6 datapath arm at mac_filter.bpf.c:861 (ipv6hdr bounds-check + 2x __builtin_memcpy(...,16) into stack keys + 2 LPM lookups over 16-byte-data NO_PREALLOC tries + the 8-term AND reusing the shared proto/port/vlan/mac axes + ffsll + dispatch tail) LOADS on the 5.15 verifier floor within instruction/stack/state budget.
  - **Pass/fail:** PASS = bpftool prog load of the ACTUAL S4 arm (not a minimal 2-lookup stub) on a 5.15 kernel: stack <=512B, processed insns well under 1M, no max_states_per_insn rejection, full 8-term arm verifies. FAIL = verifier rejects or budget exceeded => S4 needs a pre-slice spike-as-commit (flips toward synthesis Option 3).
  - **Gates:** S4 datapath wiring (Option 1/2 step 4) AND the sizing claims 'S4 is ONE slice from load/verify standpoint' + 'TTFW = 1 cycle'. The realizability architect's spike does NOT discharge it: wrong kernel (6.1.0-44 vs 5.15 floor), reduced 2-lookup stub (not the 8-term arm), external corroboration was a different project's maps.

> **Spike result (2026-05-31):** full 8-term v6 arm (dst6/src6 LPM trio, `xdpmf_cidr_v6{u32 prefixlen; u8 addr6[16]}`, ipv6hdr bounds-check, 2×memcpy(16), 8-axis AND reusing proto/port/vlan/mac, ffsll, dispatch) compiled with the production clang-19 recipe and `bpftool prog load` on the 6.1 host: **processed 12826 insns (limit 1M), stack depth 224B (<512), max_states_per_insn 5, clean verify.** Baseline 6-axis = 2054 insns; spike 8-axis = 2894 code insns — linear, tiny growth, huge headroom. CAVEAT: ran on 6.1, NOT the 5.15 floor (no 5.15 box available); margins make a 5.15 pass near-certain but this is a STRONG SIGNAL, not a floor-proof. Recommendation Option 1 (one gated slice) holds; the sizing claim 'S4 is one slice from load/verify standpoint' is DISCHARGED (modulo the 5.15-floor caveat). Tooling + result recorded in memory `reference_bpf_spike_tooling`.

### Slice-time rechecks (the briefer MUST re-run these against current code)
- **Check:** Re-confirm write_wildcard_slots is STILL hand-enumerated (6-row slots[] + 6-arg signature) at slice-time: grep -n 'write_wildcard_slots\|BV_AXIS_' src/lib/loader.cpp around :1529-1555 and the call site :1787-1790. Confirms the v6 wildcard slots are net-new wiring to add (+2 rows, +2 params, +2 args), not a free auto-grow. VOLATILE (read this round at loader.cpp:1529-1555).
  - **For:** Refuted claim: 'wildcard-fill auto-extends with BITVEC_NUM_AXES' — it does NOT; write path is hand-enumerated. The briefer must size the v6-slot wiring as real work.
- **Check:** Re-confirm close_prefixes/host_mask STILL 32-bit-address-typed: grep -n 'host_mask\|host_addr\|close_prefixes' src/lib/loader.cpp. Read this round: host_mask returns std::uint32_t (loader.cpp:1202), BitPrefix.host_addr std::uint32_t (:1195), cover-test on uint32_t m (:1229-1230). VOLATILE — the v6-analog of the once-true 32-bit fact; re-confirm, do not trust line numbers.
  - **For:** Brief central refutation (GROUNDED): 'close_prefixes is 32-bit-typed; v6 closure is net-new 128-bit arithmetic'.
- **Check:** Re-confirm close_prefixes RETURN type STILL std::vector<std::uint64_t>: grep -n 'close_prefixes\|std::vector<std::uint64_t> closed' src/lib/loader.cpp (read this round at :1219-1222 + consumer :1460). VOLATILE. A v6 close_prefixes6 keeps this 64-bit RULE-bit return; only the ADDRESS widens to 128.
  - **For:** Hidden assumption / Option 1 Preserves: 'Closure output stays std::vector<std::uint64_t>' — GROUNDED (my earlier refutation was withdrawn).
- **Check:** Re-confirm C++ standard at slice-time: grep -n 'CMAKE_CXX_STANDARD\|CMAKE_CXX_EXTENSIONS' CMakeLists.txt. Read this round: CMAKE_CXX_STANDARD 23 (CMakeLists.txt:30), no EXTENSIONS OFF => gnu++23 => __int128 available. VOLATILE (build config can change).
  - **For:** Open-Q 2 / Hidden assumption: '__SIZEOF_INT128__ available' — GROUNDED; Option 1 (__int128) feasible.
