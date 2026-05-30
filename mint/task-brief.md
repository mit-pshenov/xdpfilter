# Task brief — MVP-4.11 / S1: EtherType gate-scaffold (brownfield, BEHAVIOR-PRESERVING)

## Goal

First slice of the L2/L3 gate-rework ladder (`mint/architecture-l2l3-gate.md`, Option 1 "Five-Step Additive Ladder", S1). Reshape the single IPv4-only datapath gate into an **EtherType dispatch** with a named, reachable IPv6 arm that currently does nothing but fall through to `defaults[active]` — establishing the structural SEAM that S4 (cidr6) will later fill. **Zero observable behavior change**: the IPv4 verdict stays bit-identical, and every non-IPv4 frame (IPv6, ARP, …) still lands on `defaults[active]` exactly as today.

This is the de-risking slice the HLD identified: isolate the one unavoidable structural cutover into a provably-no-op change, so S2..S6 are additive. Anchor: `mint/architecture-l2l3-gate.md` §"Option 1 / S1" + the reviewer-passed synthesis (`528a2cc`). No `architecture-v2.md` row (that doc is the Wave-B classifier round; this arc's design lives in `architecture-l2l3-gate.md`). `design.md` gets a new §5.51 amendment.

## Context: prior work
- Prior brief: archived as `mint/task-brief-mvp-4.10.md` (B28 template rule-of-three, shipped `54a2aa0`).
- HLD just shipped (`528a2cc`): `architecture-l2l3-gate.md` — EtherType = weak-leader/strong-rider; gate-scaffold-first; SHARED axis-set; tail-call foreclosed.
- **Phase A code-grep verification (brief author ran — see evidence footer):** gate confirmed at `mac_filter.bpf.c:630` (`if (inner_proto == bpf_htons(ETH_P_IP))`); `ETH_P_IPV6`/`0x86dd`/`ipv6hdr` confirmed ABSENT from `.bpf.c` (clean add); `l3_after_vlan` (`:545`) already returns `inner_proto`; `BITVEC_NUM_AXES` = 6 (`mac_filter.h:161`); non-IPv4 frames ALREADY fall to `defaults[active]` (`:855` "No match (non-IPv4, or IPv4 with acc==0)"); `inject_eth.py` exists (emits EtherType 0x88B5, hardcoded); `T_MAC_NON_IP.sh` is the exact non-IPv4→defaults boundary-test template; VERSION 0.15.0.
- **PI continuity: ALL existing PIs CONTINUE byte-equivalent.** No PI retired/extended/added (behavior-preserving). PI-7 loader.hpp zero-diff continues (loader untouched).

## Workflow rules (brownfield)
- **Architect**: read `architecture-l2l3-gate.md` (Option 1 / S1 scope + the testability lens's S1 proof obligation VA-1) + `design.md` §6.5 invariants + the gate region `mac_filter.bpf.c:620-867` (the `ETH_P_IP` gate, the IPv4 body, the `:855` defaults fallthrough) + `l3_after_vlan` `:545-578`. EDIT `design.md` in place; append §5.51 documenting the gate reshape + the behavior-preservation argument (non-IPv4 already → defaults, so the empty IPv6 arm is a true no-op). Resolve Q1 (IPv6-arm shape) + Q2 (negation-control tooling). Confirm the load-bearing precondition: the IPv4 body is a self-contained block whose lift into the `if`-arm does NOT reorder the `acc` AND-compose / `ffsll` / `defaults[active]` fallthrough.
- **Impl**: EDIT `src/bpf/mac_filter.bpf.c` ONLY — reshape `:630` from terminal `if (inner_proto == bpf_htons(ETH_P_IP)) {…}` into `if (…ETH_P_IP) {…IPv4 body byte-identical…} else if (inner_proto == bpf_htons(ETH_P_IPV6)) {…per Q1…}`, with the post-chain `defaults[active]` fallthrough (`:855`) UNCHANGED as the catch-all. Define `ETH_P_IPV6 0x86DD` inline (mirror the existing `ETH_P_IP` `#ifndef` precedent at `:55-56`). NO `mac_filter.h` / `config.*` / `loader.cpp` change, NO `BITVEC_NUM_AXES` change, NO new map, NO VERSION bump.
- **Tester**: regression net = the existing v4 oracle corpus (`T_AND{,4,5,6}_ORACLE_AGREEMENT`, `T_PROTO/VLAN_AND_COMPOSE`, the atomic-swap net) stays GREEN (IPv4 unchanged) — that is the bit-identical proof (VA-1). PLUS a NEW negation-control ctest (per Q2): inject a frame that enters the NEW IPv6 arm and assert it still routes to `defaults[active]` (NOT dropped, DROP_MALFORMED delta 0) — mirror `T_MAC_NON_IP.sh`'s mechanism exactly. Full `-j4` run green (B19 `build_cpu` lock holds). The new ctest touches shared host state (veth/netns/bpffs) → `RESOURCE_LOCK xdp_fixture` per guard #12.
- **Reviewer**: 5-point brownfield. Load-bearing checks: (1) the IPv4 arm is byte-identical (the `acc` AND-compose, `ffsll`, per-rule dispatch, and `defaults[active]` fallthrough are unchanged — `git diff` shows only the `if`→`if/else-if` wrapping + the new arm); (2) the IPv6 arm is behavior-preserving per Q1 (falls to defaults, does NOT early-return DROP/PASS — a botched arm that drops/passes IPv6 directly is `[INVARIANT-VIOLATED]`); (3) NO axis/map/schema/VERSION change (`git diff -- src/common/ src/lib/ CMakeLists.txt` empty except possibly the inject tool); (4) the negation ctest genuinely enters the new arm (0x86DD, not just generic non-IP) and asserts →defaults; (5) v4 oracle net green (bit-identical).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.11-1: IPv6-arm body in S1 → **empty/fall-through seam (no early return)**
The HLD said "bounds-check ipv6hdr only." But since the bounds-check guards a deref that does NOT exist until S4, and a bounds-check that DROPs a truncated v6 frame WOULD change behavior (today malformed v6 → defaults, not DROP), the minimal provably-behavior-preserving S1 arm is an **empty (comment-only) `else if (ETH_P_IPV6)` that falls through to `defaults[active]`**. Architect MAY include a no-early-return bounds-check if it wants the verifier to exercise the v6-header bounds pattern early — but it MUST fall through to defaults on failure, never DROP/PASS. (Resolve as Q1.)

### HG-mvp-4.11-2: negation-control tooling → **parametrize `inject_eth.py` for 0x86DD; new ctest mirrors `T_MAC_NON_IP`**
The S1 negation needs a frame that enters the NEW IPv6 arm (EtherType 0x86DD), which `inject_eth.py` (hardcoded 0x88B5) cannot emit. A ~2-line parametrization (`--ethertype`, or a 0x86DD default variant) is S1-scope tooling — it is NOT `inject_l6.py` (S2, which builds valid IPv6 L3/L4 headers for cidr6 matching). Do NOT pull S2 forward. (Resolve as Q2.)

## Open mechanism questions (architect decides; document in §5.51)

### Q1: IPv6-arm shape
- **A1**: empty/comment-only `else if (ETH_P_IPV6)` → falls through to `defaults[active]`. (Provably no-op; the bounds-check lands in S4 with its deref.)
- **A2**: `else if (ETH_P_IPV6)` with a no-early-return `ipv6hdr` bounds-check that ALSO falls through to defaults (exercises the v6 bounds pattern early).
- **Recommendation**: **A1** — strongest behavior-preservation (zero new early-return path), smallest diff, cleanest "true no-op" proof. A2 only if the architect wants the v6-bounds verifier pattern present now; A2 must NOT DROP on bounds failure.

### Q2: negation-control frame + tooling
- **A1**: parametrize `inject_eth.py` to emit 0x86DD; new ctest `T_IPV6_GATE_DEFAULT.sh` (mirror `T_MAC_NON_IP`) asserts a 0x86DD frame → NOT dropped (defaults), DROP_MALFORMED delta 0 — proving the NEW arm routes correctly.
- **A2**: reuse the existing 0x88B5 frame (generic non-IPv4) — zero tooling change, but does NOT specifically exercise the new ETH_P_IPV6 arm (0x88B5 matches neither arm; it only re-proves the pre-existing fallthrough).
- **Recommendation**: **A1** — only a 0x86DD frame actually traverses the new seam; A2 would leave the new arm unexercised by tests. The inject_eth parametrization is in-scope S1 tooling, distinct from S2's `inject_l6.py`.

## Scope (cycle MVP-4.11 — concrete items)

### Item S1-1 — reshape the EtherType gate
**Where**: `src/bpf/mac_filter.bpf.c` `:630` (the `if (inner_proto == bpf_htons(ETH_P_IP))` gate) + inline `#define ETH_P_IPV6 0x86DD` near `:55`. Lift the existing IPv4 body byte-identical into the `if`-arm; add the `else if (ETH_P_IPV6)` arm per Q1; leave the `:855` `defaults[active]` fallthrough as the unchanged catch-all.

### Item S1-2 — negation-control test (per Q2)
**Where**: NEW `tests/T_IPV6_GATE_DEFAULT.sh` (mirror `tests/T_MAC_NON_IP.sh`); EDIT `tests/inject/inject_eth.py` (parametrize EtherType / add 0x86DD); EDIT `tests/CMakeLists.txt` (register the ctest with `RESOURCE_LOCK xdp_fixture`, guard #12). Assertion: a 0x86DD frame → NOT dropped (defaults=pass), STAT_DROP_DENY + STAT_DROP_MALFORMED deltas == 0.

## Out of scope (explicit)
- **S2 `inject_l6.py`** (valid IPv6 L3/L4 frame construction for cidr6 matching), **S3 LPM-template refactor**, **S4 cidr6 axes**, **S5 ethertype match-axis**, **S6 ext-header walk + family-coherence reject** — all later ladder slices.
- ANY `BITVEC_NUM_AXES` change, new map, `kManagedMaps[]` row, schema bump, VERSION bump, `config.*`/`loader.cpp`/`mac_filter.h` change.
- Classifying IPv6 on ANY axis (the S1 arm recognizes the family and falls to defaults — it does NOT match cidr6/proto/port/etc.).
- The PO forks deferred to their slices: EtherType split-vs-co-ship (S5), ext-walk split (S6), gate.d hoist (Option 4), `ethertype:ipv4` accept/reject.

## Definition of done
- §5.51 amendment in `design.md` (gate reshape + behavior-preservation argument + Q1/Q2 resolutions).
- All existing PIs continue byte-equivalent; IPv4 verdict bit-identical (v4 oracle net green).
- New negation ctest GREEN (0x86DD → defaults); full `-j4` run no flake.
- NO VERSION bump; `git diff -- src/common src/lib CMakeLists.txt` empty (only `.bpf.c` + tests + inject tool touched).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: existing CMake (clang BPF target; the `.bpf.c` recompiles into the skeleton).
- Runtime/kernel: none new — the IPv6 arm adds one branch; must still verifier-load on the **5.15 floor** (no `bpf_loop`, no back-edge; straight-line — trivially satisfied by an empty/bounds-only arm).

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
**Mechanical, single-architect.** The L2/L3 design-space was JUST resolved by `/mint-hld` (`architecture-l2l3-gate.md`, `528a2cc`); S1's scope is the precisely-bounded first rung. Not multi-axis — behavior-preserving structural reshape with one blessed shape (Option 1 S1). `/mint-hld` NOT needed (just ran). Single-architect via `/mint-dev` handles it.

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author ran these; architect re-verifies + extends:
- `grep -nE 'inner_proto == bpf_htons|ETH_P_IP\b' src/bpf/mac_filter.bpf.c` — confirm the gate at `:630` + the `ETH_P_IP` `#define` `:55-56`.
- `grep -nE 'ETH_P_IPV6|0x86dd|ipv6hdr' src/bpf/mac_filter.bpf.c` — confirm ABSENT (you are introducing the first reference).
- `grep -nE 'defaults|default_p|active' src/bpf/mac_filter.bpf.c` near `:855` — confirm non-IPv4 ALREADY falls to `defaults[active]` (this is WHY the empty IPv6 arm is a true no-op).
- `grep -nE 'BITVEC_NUM_AXES' src/common/mac_filter.h` — confirm 6, stays 6 (the `:104/:119/:141` comments are stale evolution history; the live `#define` is `:161`).
- Read `tests/T_MAC_NON_IP.sh` + `tests/inject/inject_eth.py` — the negation-control template + the injector to parametrize.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #5** (Phase A code-grep) — always; architect re-runs the greps above.
- **Guard #12** (RESOURCE_LOCK for shared host state) — DIRECTLY applies: the new negation ctest sets up veth/netns + loads the BPF object → MUST carry `RESOURCE_LOCK xdp_fixture` (mirror `T_MAC_NON_IP`'s lock).
- **Guard #9** (helper-location duplication-over-extraction) — watch: if the IPv6 arm tempts a shared parse helper, prefer in-place per the rule-of-three threshold (only 1 instance here → no extraction).
- **Guard #11** (VERSION-bump literal propagation) — N/A (no bump).
- **Guard #10** (catalog arithmetic) — N/A (no new constexpr table/array; `BITVEC_NUM_AXES` unchanged).
- **Guard #22** (NIC VLAN offload disable in tests) — applies IF the negation frame is VLAN-tagged; the S1 0x86DD frame is untagged, so likely N/A, but mirror `T_MAC_NON_IP`'s fixture setup faithfully.

> Operative-semantic note: line-number anchors (`:630`, `:855`, `:55`, `:161`) are SHOULD-level orientation for the reviewer's grep checks, not literal-match contracts — they shift across commits. Impl deviations preserving behavior (the arm landing at a slightly different line, an equivalent `#define` placement) are `inline-merge`, not `[UNRELATED-EDIT]`. The bit-identical IPv4 verdict + the →defaults IPv6 routing are the MUST contracts.
