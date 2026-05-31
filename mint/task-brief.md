# Task brief — MVP-4.15 / S6: IPv6 extension-header walk (brownfield, SHARP-EDGE)

## Goal

Walk the IPv6 extension-header chain in the v6 datapath arm so the **proto** and **dst_port** axes see the TRUE upper-layer protocol + L4 header on ext-header-bearing IPv6 frames, instead of the first `nexthdr` at the fixed 40B base offset (the S4 base-header-only boundary, `PI-mvp-4.13-BASE-HEADER`). Closes the last honesty gap of the L2/L3 gate ladder: today a v6 frame carrying e.g. a Hop-by-Hop or Destination-Options header has `proto = ip6->nexthdr = 0/60` (an ext-header number, NOT the real L4), so a `proto:tcp` or `dst_port:443` rule silently never matches it.

This is the LAST sharp edge of the ladder (the hld addr-axis + testability lenses explicitly split it from the 128-bit closure into its own slice — "the two sharp edges should NOT share a slice"). The sharp edge here is a **verifier-bounded loop** over the ext-header chain in the XDP datapath — exactly the class where a pre-slice spike pays for itself (mirrors S4's 128-bit closure spike). `design.md` gets a new §5.55 amendment.

## Context: prior work
- Prior brief: archived as `/home/user/mint-l2-mac-filter/mint/task-brief-mvp-4.14.md` (S5 EtherType, shipped `99eb17e`).
- Match model now: **9 AND-composed axes** (BITVEC_NUM_AXES 9: DST/SRC/PROTO/PORT/VLAN/MAC/DST6/SRC6/ETHERTYPE). S6 adds NO axis — it changes how the EXISTING proto/port axes read their key on v6 frames.
- **Phase A code-grep verification (brief author ran — see footer):**
  - The v6 arm reads base-header-only TODAY: `proto = ip6->nexthdr` (`mac_filter.bpf.c:1001`), `l4 = (void*)(ip6+1)` at the fixed 40B offset (`:1007`), has_port only for TCP/UDP (`:1010-1026`). This is the exact block S6 replaces with a chain-walk.
  - The v4 arm is UNAFFECTED (IPv4 has no ext-header chain; `ip->ihl` already handles v4 options at `:748-783`).
  - **Bounded-loop precedent EXISTS**: `port_scan` uses `#pragma unroll` + a fixed-bound `for (i < XDPMF_ALLOWLIST_MAX)` (`:589-605`) — the verifier-safe straight-line pattern the ext-walk mirrors (fixed MAX_EXT_HOPS unroll, NOT an unbounded loop).
  - ext-header structs are in `vmlinux.h` (`ipv6_opt_hdr` :39927, `frag_hdr` :63996). ext-header proto numbers (HOPOPTS=0, ROUTING=43, FRAGMENT=44, DSTOPTS=60, NONE=59) are NOT defined → impl inline-defines them (the `ETH_P_*`/`IPPROTO_*` inline-define precedent at `:55-89`).
  - **`inject_l6.py` left an explicit S6 SEAM** (`tests/inject/inject_l6.py:31-34,72`): a documented insertion point in `build_frame()` for the ext-header chain + a planned `--ext` CLI option. The test surface was pre-planned in S2 — extend it, don't rebuild it.
  - ctest baseline 93; VERSION 0.15.0; guards through #27.
- **PI continuity:** ALL existing PIs CONTINUE. IPv4 verdict bit-identical (v4 arm untouched). IPv6 verdict for NON-ext-bearing frames identical (the walk is a no-op when nexthdr is already L4 — same first-match outcome). single-`active_idx` swap, schema_version 2, first-match-by-id, guard #27 verdict-identity. loader.hpp likely zero-diff (PI-7 — this is a pure datapath change, no map/lowering touch) — architect confirms. NO new axis, NO BITVEC growth, NO kManagedMaps change.

## Workflow rules (brownfield)
- **Architect**: read `architecture-l2l3-gate.md` (addr-axis ext-walk = "Approach A"; testability VA-5 detectability trap) + `design.md` §5.53 (the v6 arm S6 amends) + §5.44 (the v4 ihl/has_port L4 precedent) + §6.5 invariants. EDIT `design.md` in place; append §5.55. Resolve Q1 (walk mechanism / MAX_HOPS bound — THE crux, verifier-gated) + Q2 (malformed/truncated-chain + unrecognized-ext semantics) + D-mvp-4.15-* tactical. **The pre-slice verifier spike result (see below) is your realizability ground-truth — design to what the spike proved loadable.**
- **Impl**: per the §5.55 FileList. The ext-walk replaces the base-only proto/port block in the v6 arm. Build clean + zero warnings; verifier-load the prod .bpf.o (THE load-bearing smoke for a bounded-loop slice).
- **Tester**: NEW ctests target ≈2-3. The headline + the testability VA-5 trap: a v6 frame WITH an ext-header chain, matched by a `proto:tcp`/`dst_port:N` rule that base-only would MISS — proving the walk reaches true L4. Plus malformed/truncated-chain → MALFORMED; non-ext frame → identical verdict (walk no-op). Real frames via `inject_l6.py --ext` (extend the S6 seam). Negation control mandatory. Full suite green; count 93 → ~95.
- **Reviewer**: 5-point brownfield. Load-bearing checks: (1) IPv4 + non-ext-IPv6 verdict identical (the walk is a no-op on those); (2) the walk is verifier-bounded (fixed MAX_HOPS unroll, NOT an unbounded loop — the spike's pass/fail criterion); (3) ext-bearing frame with `proto:tcp`/`dst_port:N` now MATCHES where base-only missed (VA-5 detectability — a walk that didn't actually reach L4 must FAIL the test); (4) truncated/malformed chain → DROP_MALFORMED, no OOB read.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

> **PO plate: EMPTY.** No decision hinges on external value. The walk mechanism, MAX_HOPS bound, and malformed semantics are all engineering/realizability calls (architect-owned, spike-gated). The one prior PO-flavored question — "is base-only acceptable on Gi until S6" (hld Open-Q #2) — is now moot: this slice IS S6, closing it.

### HG-mvp-4.15-1: walk bound → **fixed MAX_EXT_HOPS unroll (verifier-safe straight-line, mirror port_scan), spike-validated**
A small fixed cap (the common ext-header chains are ≤2-3 headers; pick a conservative bound like 4-8). NOT an unbounded `while`. The exact bound is the architect's call, informed by the spike's verifier-budget headroom.

### HG-mvp-4.15-2: no VERSION bump → **default no bump** (HG-able — architect bumps to 0.16.0 if it wants operator-visible "full IPv6 L4 matching" in `--version`)
Mirrors S4/S5 internal-model-validation precedent.

## Open mechanism questions (architect decides; document in §5.55)

### Q1: ext-header walk mechanism + MAX_HOPS bound (THE crux — verifier-gated, spike-informed)
How to walk `{HOPOPTS, ROUTING, DSTOPTS, FRAGMENT}` → terminal L4, bounded for the verifier. Options the architect weighs (do NOT pre-commit the BPF mechanism):
- **A1**: `#pragma unroll` fixed-N loop (mirror `port_scan`): each iteration reads `ipv6_opt_hdr{nexthdr, hdrlen}`, advances `cursor += (hdrlen+1)*8` (or +8 for frag_hdr fixed size), bounds-checks each step, stops at a recognized L4 / unrecognized nexthdr / N-cap. The straight-line precedent.
- **A2**: bpf-helper-based (if any dynptr/`bpf_*` chain helper is available on the 6.1 floor) — likely overkill, flag if considered.
- **Recommendation**: A1 (bounded unroll) — it's the proven-in-this-codebase pattern (`port_scan`), the spike validates its verifier cost, and it has no kernel-version dependency. The MAX_HOPS bound is the spike-tuned knob.

### Q2: malformed / unrecognized-chain semantics
- truncated chain (bounds-check fails mid-walk) → **DROP_MALFORMED** (mirror the v6 base-header bounds-miss, D-mvp-4.13-NO-MALFORMED-NONV6 extended to the chain).
- chain exceeds MAX_HOPS (more ext-headers than the cap) → **recommendation: treat as non-L4** (has_port=0, proto=last-seen-nexthdr) — a pathological frame, fail-safe to "only wildcard rules match" rather than MALFORMED. Architect confirms.
- unrecognized nexthdr (not a known ext-header, not TCP/UDP) → stop, proto=that value, has_port=0 (exact today's base-only semantic for non-TCP/UDP).

## Scope (cycle MVP-4.15 — concrete items; estimates are UPPER BOUNDS)

### Item S6-1 — ext-header proto constants
**Where**: `src/bpf/mac_filter.bpf.c` (or `src/common/mac_filter.h`). Inline-define IPPROTO_HOPOPTS=0, ROUTING=43, FRAGMENT=44, DSTOPTS=60, NONE=59 (the ETH_P_*/IPPROTO_* inline-define precedent).

### Item S6-2 — the bounded ext-header walk (the sharp edge)
**Where**: `src/bpf/mac_filter.bpf.c` v6 arm, replacing the base-only `proto = ip6->nexthdr` + fixed-40B-L4 block (`:1000-1026`). Bounded MAX_HOPS unroll per Q1; advances the cursor over `{HOPOPTS,ROUTING,DSTOPTS}` via `(hdrlen+1)*8`, handles `FRAGMENT` (fixed 8B) per Q2, bounds-checks each hop, terminates at L4 / unrecognized / cap. Sets `proto` = true upper-layer + `l4`/`has_port` from the walked offset. Per Q2 malformed/cap/unrecognized semantics.

### Item S6-3 — injector ext-header support
**Where**: `tests/inject/inject_l6.py` — fill the documented S6 SEAM (`:31-34,72`): `--ext` CLI option that inserts an ext-header chain (e.g. HopByHop/DestOpt/Routing/Fragment via scapy) between the IPv6 base header and the L4 layer in `build_frame()`.

### Item S6-4 — oracle + ctests
**Where**: `tests/bitvec/bitvec_oracle_prod.py` (the oracle must model the walk — predict true-L4 for ext-bearing v6 frames so it stays algorithm-different yet outcome-equal) + NEW fixtures + NEW ctests (≈2-3: the VA-5 headline — ext-bearing v6 frame matched by proto:tcp/dst_port:N that base-only would miss; truncated-chain → MALFORMED; non-ext v6 → identical verdict / walk no-op). Real frames via `inject_l6.py --ext`.

## Out of scope (explicit)
- Any NEW match axis or BITVEC growth (S6 is pure datapath read-depth; the proto/port axes are unchanged in shape).
- IPv4 arm (no ext-header chain in v4).
- ICMPv6-specific matching beyond proto=58 passthrough.
- **C3 sidecar match-kinds gap** (v6 + ethertype omitted from status JSON — carried fast-follow, not this slice).
- schema_version bump.
- Deep fragment reassembly (FRAGMENT header is walked for nexthdr, NOT reassembled — first-fragment L4 only; document the boundary).

## Definition of done
- §5.55 amendment in `design.md` (walk mechanism + MAX_HOPS + Q1/Q2 resolutions + the spike result + the VA-5 detectability note).
- ext-bearing v6 frame: proto/dst_port axes match true L4 (VA-5 headline GREEN); IPv4 + non-ext-IPv6 verdict identical.
- truncated chain → MALFORMED; verifier-bounded walk (prod .bpf.o loads on 6.1; spike pre-validated).
- `inject_l6.py --ext` emits ext-header chains; oracle models the walk; NEW ctests GREEN; full `-j4` no flake; count 93 → ~95.
- `mint/review.md` round-1 verdict = pass; one git commit per phase boundary.

## Dependencies
- Build: existing CMake clang-19 BPF toolchain. Runtime: python3 + scapy (inject_l6.py --ext); root/sudo for veth/netns/bpffs ctests. Kernel: 6.1 host (spike target; 5.15-floor caveat per S4 precedent — margins permitting).
- **Pre-slice spike (REQUIRED before mint-dev): verifier-load the bounded ext-walk** — prove the MAX_HOPS unroll + per-hop bounds-checks load within the verifier instruction/complexity/state budget on the 6.1 host (mirror the S4 cidr6 spike method, `reference_bpf_spike_tooling`). The spike's pass/fail tunes MAX_HOPS and confirms the "one slice" sizing. Brief author runs this BEFORE invoking /mint-dev.

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

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])
**Mechanical + sharp-edge-spiked, single-architect.** The design space (ext-header walk) was explored in `architecture-l2l3-gate.md` (addr-axis Approach A + testability VA-5). NOT multi-axis — the one real consideration is the walk mechanism + MAX_HOPS (Q1), which is architect-tier realizability resolved by the pre-slice spike, not a design fork. `/mint-hld` NOT needed. BUT this slice HAS a sharp edge (verifier-bounded loop) → a pre-slice spike IS required (unlike S5's plain additive clone), mirroring S4's 128-bit-closure spike. PO plate empty. Single-architect via `/mint-dev` AFTER the spike passes. (Forward-discipline: re-grounded fresh, not pre-committed from the numbered ladder.)

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author ran these; architect re-verifies + extends:
- `grep -nE 'ip6->nexthdr|void \*l4|has_port|IPPROTO_(TCP|UDP)' src/bpf/mac_filter.bpf.c` — the base-only v6 proto/port block (`:1000-1026`) that S6 replaces.
- `grep -nE 'pragma unroll|XDPMF_ALLOWLIST_MAX|port_scan' src/bpf/mac_filter.bpf.c` — the bounded-loop straight-line precedent (`:589-605`).
- `grep -nE 'ipv6_opt_hdr|frag_hdr' include/vmlinux.h` — the ext-header structs (`:39927`, `:63996`).
- Read `tests/inject/inject_l6.py:31-34,72` — the documented S6 SEAM (`--ext` insertion point).
- Read `src/bpf/mac_filter.bpf.c:748-783` (v4 ihl/has_port L4 precedent — the analog for variable-offset L4).
- Confirm the spike result (the brief author runs it pre-/mint-dev; design to what it proved loadable).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #5** (Phase A code-grep) — always; architect re-runs the greps above.
- **Guard #27** (cross-arm verdict-identity) — applies softly: S6 touches ONLY the v6 arm's proto/port read; the v4 arm + non-ext-v6 verdict MUST stay identical (oracle GREEN). Not a multi-arm axis add, but the same verdict-identity discipline on the unchanged paths.
- **Guard #25** (5.15-verifier-floor) — DIRECTLY applies: the bounded walk is new verifier surface; the spike targets 6.1 (5.15-floor caveat per S4). Document the floor stance.
- **Guard #12** (RESOURCE_LOCK) — new datapath ctests touch veth/netns/bpffs → `RESOURCE_LOCK xdp_fixture`.
- **Guard #23** (closure cover-direction) — N/A (no closure; this is parse-depth, not LPM).
- **Guard #11** (VERSION-bump) — N/A unless architect bumps (HG-2 default no).

> Operative-semantic note: line/count anchors (`:1000-1026`, MAX_HOPS value, 93→~95) are SHOULD-level orientation — re-grep at slice-time. MUST contracts: verifier-bounded walk (loads on 6.1), ext-bearing v6 proto/port matches true L4 (VA-5), IPv4 + non-ext-v6 verdict-identical, truncated chain → MALFORMED no OOB. Impl deviations preserving these are `inline-merge`.
