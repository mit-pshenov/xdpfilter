# Task brief — MVP-4.13 / S4: IPv6 CIDR matching axes (cidr6) (brownfield, STRUCTURAL-additive)

## Goal

Fill the proven-empty IPv6 datapath seam (`src/bpf/mac_filter.bpf.c:861`) with real IPv6 CIDR matching: two new sibling LPM axes **`dst6`/`src6`** in the existing bit-vector AND classifier, so rules match IPv6 source/destination subnets exactly as they already match IPv4. Closes the #1 functional gap after the IPv4 rule-model — today every IPv6 frame is unclassifiable (→ defaults only).

Anchor: `/home/user/mint-l2-mac-filter/mint/architecture-l2l3-gate.md` **S4 cidr6 design round + discharge ledger** (committed `00a077d`). hld recommendation = **Option 1 (One Gated Slice, `__int128` closure fork)**. The required pre-slice verifier spike was RUN 2026-05-31 = **PASS** (full 8-term v6 arm: 12826 insns/1M, stack 224B/512, clean load on 6.1; 5.15-floor caveat noted). `design.md` gets a new §5.52 amendment.

## Context: prior work
- Prior brief: archived as `/home/user/mint-l2-mac-filter/mint/task-brief-mvp-4.12.md` (S2 inject_l6.py, shipped `35b2ca9`).
- Ladder so far: S1 gate-scaffold (`c6e6b8d`, the `else if ETH_P_IPV6` empty seam at `mac_filter.bpf.c:861`), S2 inject_l6.py (`35b2ca9`, the IPv6 frame injector + harness). S3 (LPM-template) was REJECTED as premature abstraction — template-vs-copy decision lives INSIDE this slice (resolved: FORK, see HG-4.13-2).
- hld design round: `architecture-l2l3-gate.md` S4 section (Workflow `wf_fb92d53a-22f`, 5 lenses + grounder). Grounder verdict `claims-refuted` (one sizing claim corrected — see below).
- **Phase A code-grep verification (brief author ran — see evidence footer + the sub-check-6 re-discharge of the hld ledger's 4 slice-time rechecks):**
  - **wildcard-fill REFUTED-claim CONFIRMED:** `write_wildcard_slots` (`loader.cpp:1529`) is a HAND-ENUMERATED 6-row `slots[]` table + 6-arg signature; call site `loader.cpp:1787`. Adding dst6/src6 wildcard halves is NET-NEW wiring (+2 rows, +2 params, +2 args + `lower_axis6` producing the `.wildcard`), NOT a free auto-grow. v4-only rules MUST get their bit set in the dst6/src6 wildcard (else cross-family rules spuriously drop in the v6 arm).
  - **closure is 32-bit-typed:** `host_mask` returns `std::uint32_t` (`loader.cpp:1202`), `BitPrefix.host_addr` is `std::uint32_t` (`:1195`), cover-test `(pi.host_addr & m)` on `std::uint32_t m` (`:1230`). v6 closure = net-new 128-bit arithmetic.
  - **closure RETURN type stays** `std::vector<std::uint64_t>` (`:1222`, consumer `:1460`) — 64-bit RULE-bit unchanged; only the ADDRESS widens to 128.
  - **`__int128` feasible UNDER STRICT c++23:** ledger premise ("no `CMAKE_CXX_EXTENSIONS OFF`") was REFUTED — `CMakeLists.txt:32` IS `CMAKE_CXX_EXTENSIONS OFF` (strict `-std=c++23`, not gnu++23). BUT the OUTCOME holds: `unsigned __int128` compiles clean under `clang++-19 -std=c++23 -pedantic -Werror` (verified, rc=0). Option 1 stands.
  - **IPv6 reject is a SINGLE chokepoint:** `cidr.cpp:60-63` (`s.find(':')` → throw). `config.cpp:408/421` are COMMENTS, not separate rejects. `attach --allow` synthesizes Config from MACs only (cannot carry a v6 CIDR) → guard-#24 bypass parity is N/A this slice (drop the parity vector). Config-widening is NARROWER than the v1 brief framed.
  - `RuleMatch` (`config.hpp:44`): `std::optional<xdpmf_cidr_v4> dst_cidr/src_cidr` — v6 adds `std::optional<xdpmf_cidr_v6> dst_cidr6/src_cidr6` (additive).
  - `kManagedMaps[]` = 30 rows (`loader.cpp`); `BITVEC_NUM_AXES 6` (`mac_filter.h:161`); ctest baseline 79; struct `xdpmf_cidr_v4` (`mac_filter.h:40`).
- **PI continuity:** ALL existing PIs CONTINUE. IPv4 verdict bit-identical (v4 arm untouched), single-`active_idx` atomic swap, `schema_version 2` (additive `std::optional` fields), first-match-by-id + `defaults[active]` fallthrough. NEW PIs for the v6 axes (architect numbers them in §5.52). PI-7 loader.hpp zero-diff likely BREAKS this slice (loader gains v6 lowering/populate/wildcard) — architect confirms.

## Workflow rules (brownfield)
- **Architect**: read `architecture-l2l3-gate.md` S4 section + discharge ledger + `design.md` §5.43/§5.51 (the v4 LPM-axis stamp + the S1 seam) + §6.5 invariants. EDIT `design.md` in place; append §5.52. Resolve Q1 (closure internal representation) + Q2 (cross-family wildcard semantics — the grounder's load-bearing caveat). Add D-mvp-4.13-* for tactical choices. **The hld discharge ledger is your starting point — the sizing/sequencing claims are already discharged; do NOT re-litigate Option 1, build it.**
- **Impl**: per the §5.52 FileList. The v6 arm goes at `mac_filter.bpf.c:861` (the empty seam) WITH the ipv6hdr bounds-check + deref. Inner gate (sequencing constraint, NOT a slice split): **the closure partial-byte + cover-direction unit/golden test goes GREEN before the `:861` arm is wired.**
- **Tester**: NEW ctests target ≈3 (v6 oracle-agreement battery, closure cover-direction canary per guard #23, golden-dump). Oracle (`bitvec_oracle_prod.py`) gains a v6 axis-representation + a new rule table (`--ruleset andv6`); mask in the 128-bit integer domain (NOT per-byte) so non-aligned prefixes (/40,/68,/127) are exercised. Real v6 frames via `inject_l6.py` (S2, shipped). Base-header only (no ext-walk → S6). Full suite stays green; count 79 → ~82.
- **Reviewer**: 5-point brownfield. Load-bearing checks: (1) IPv4 verdict bit-identical (v4 arm untouched — `git diff` the v4 block); (2) cross-family wildcard correctness — a v4-only rule sets its bit in dst6/src6 wildcard (else spurious v6 drop) — guard #23 + the grounder caveat; (3) closure cover-direction at 128 bits incl. partial-byte/limb boundaries (the #1 bug class — verify the guard-#23 overlap vector where a less-specific covering rule has LOWER id); (4) LPM v6 key is network-order byte array `{u32 prefixlen; u8 addr6[16]}` (NOT host-order limbs — byte-order trap); (5) base-header-only honesty (proto/port see first nexthdr; documented, ext-walk = S6).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

> **PO plate from the hld grounder: EMPTY.** The one genuine PO question (ext-header honesty) was resolved by the PO 2026-05-31: **ship base-nexthdr, mark the boundary honestly, ext-walk → S6** (derived from project strategy: model-validation, not production; all S to be closed). No decisions are routed to the user in this brief.

### HG-mvp-4.13-1: address representation → **two independent sibling axes dst6/src6 (A1), kernel-canonical byte-array LPM key**
hld convergence (all 4 lenses + contrarian): `struct xdpmf_cidr_v6 { unsigned int prefixlen; unsigned char addr6[16]; }`, network byte order (addr6[0]=MSB), `memcpy(...,16)` straight from `ip6->daddr/saddr`. NOT a unified v4-in-v6 axis (that reshapes v4 — fails the viability filter), NOT host-order `__u64[2]` limbs (byte-order trap in the trie's MSB-first walk). The closure's INTERNAL arithmetic representation is separate (Q1) and never touches the trie.

### HG-mvp-4.13-2: template vs copy-paste → **FORK (copy-paste the v4 LPM stamp for v6), do NOT template**
Rule-of-three is at TWO (v4+v6); the two closure bodies have different UB profiles (v4 only `==0`; v6 adds limb-boundary/partial-byte cases). Coupling them prematurely couples two correctness-critical bodies. This is why S3 (template-now) was rejected. Template deferred to a 3rd LPM family if one ever lands.

## Open mechanism questions (architect decides; document in §5.52)

### Q1: closure internal arithmetic representation (`__int128` vs 16-byte array)
- **A1 (recommended)**: `unsigned __int128` for `host_addr6` + `host_mask6` — visually mirrors the shipped v4 cover-direction body (`(pi & m) == (pj & m)`), making the #1-bug-class invariant eyeball-auditable. VERIFIED feasible under strict `-std=c++23` (this slice's Phase A: clang++-19 `-pedantic -Werror` clean). Watch the shift-by-128 UB at `/0` (special-case or mask-build via `prefixlen==0 ? 0 : ...`).
- **A2**: 16-byte array + byte-loop `covers6()` — UB-immune (every shift ≤7), `/0` falls out naturally, no toolchain assumption. Harder to eyeball against the v4 invariant.
- **Recommendation**: A1 (`__int128`) — auditability against the proven v4 body is the highest-leverage defense for the cover-direction bug class, and feasibility is verified. A2 is the fallback if the architect judges the `/0` shift-UB site riskier than the toolchain reliance. Either keeps the closure RETURN `std::vector<std::uint64_t>` (rule-bit width unchanged). **Note: the LPM KEY is always the byte array (HG-1) regardless of Q1 — this is the closure's INTERNAL repr only.**

### Q2: cross-family wildcard semantics (the grounder's load-bearing caveat)
- **Context**: `write_wildcard_slots` is hand-enumerated (refuted-claim: NOT auto-grow). Adding dst6/src6 means +2 `slots[]` rows + 2 params + 2 args + `lower_axis6` producing `dst6_low.wildcard`/`src6_low.wildcard`.
- **The question**: a v4-only rule does not constrain dst6/src6 → it MUST land in the dst6/src6 wildcard half (via the SAME `lower_axis` `out.wildcard |= bit` mechanism it already uses for proto/port/vlan/mac), so it survives the v6 axes unconditionally and is NOT spuriously dropped when a v6 frame is classified. Symmetrically a v6-only rule lands in the v4 dst/src wildcard.
- **Recommendation**: treat it exactly as the existing wildcard mechanism — one rule-id occupies a bit in EVERY axis; unconstrained axes get the wildcard bit. This falls out of `lower_axis` + the +2 `write_wildcard_slots` rows; no new concept. Architect documents the cross-family wildcard population as an explicit §5.52 item (NOT a side-effect) so impl wires the +2 rows AND `lower_axis6` sets v4-only rules' bits.

## Scope (cycle MVP-4.13 — concrete items; estimates are UPPER BOUNDS)

### Item S4-1 — v6 key struct + header axis growth
**Where**: `src/common/mac_filter.h`. NEW `struct xdpmf_cidr_v6 { unsigned int prefixlen; unsigned char addr6[16]; } __attribute__((packed));`. `BITVEC_NUM_AXES 6→8`; NEW `BV_AXIS_DST6=6`, `BV_AXIS_SRC6=7`. `wildcard` map max_entries auto-grows 12→16 via the `XDPMF_RULESET_COUNT * BITVEC_NUM_AXES` formula (no literal edit). NEW map-name constants for the dst6/src6 AOM trios.

### Item S4-2 — datapath v6 arm
**Where**: `src/bpf/mac_filter.bpf.c:861` (the empty `else if ETH_P_IPV6` seam). NEW: dst6/src6 LPM map decls (mirror the v4 dst trio); ipv6hdr bounds-check + deref; `memcpy(key.addr6, &ip6->daddr, 16)`; the 8-term AND reusing the shared proto/port/vlan/mac axes + the 2 new wildcard halves; ffsll + the existing dispatch tail. Base-header only — proto axis sees `ip6->nexthdr` (first nexthdr; documented honesty boundary, ext-walk = S6).

### Item S4-3 — loader lowering + populate + wildcard
**Where**: `src/lib/loader.cpp`. NEW `xdpmf_cidr_v6`-typed `BitPrefix6` + `host_mask6` + `close_prefixes6` (128-bit, per Q1) + `lower_axis6`; +6 `kManagedMaps[]` rows (2 axes × 3: inner_a/inner_b/outer) → 30→36; **+2 `write_wildcard_slots` `slots[]` rows + 2 params + 2 call-site args (the refuted net-new wiring)**; populate the dst6/src6 inners per slot.

### Item S4-4 — config surface widening
**Where**: `src/lib/cidr.cpp` (the SINGLE reject chokepoint :60-63) + `src/lib/config.cpp` + `src/lib/config.hpp`. NEW `parse_cidr_v6` (or family-dispatch in `parse_cidr_*`); `RuleMatch` gains `std::optional<xdpmf_cidr_v6> dst_cidr6/src_cidr6`; YAML keys `dst_cidr6`/`src_cidr6`. Retire/branch the `:`-scan reject so v6 strings parse instead of throwing. NO `attach --allow` change (MAC-only; cannot carry v6).

### Item S4-5 — oracle + ctests
**Where**: `tests/bitvec/bitvec_oracle_prod.py` (NEW v6 axis repr + `RULES_ANDV6` table, 128-bit-integer masking) + NEW fixtures + NEW ctests (≈3: v6 oracle-agreement, closure cover-direction canary per guard #23, golden-dump). Real v6 frames via `inject_l6.py`. Inner gate: closure unit/golden test GREEN before the datapath arm.

## Out of scope (explicit)
- **IPv6 extension-header walk** (proto/port on ext-bearing frames see first nexthdr only) — deferred to a later slice; documented honesty boundary.
- **EtherType match-axis** — a separate later slice; do not fold in.
- **LPM-family templating** — deferred (HG-2 FORK; revisit at a 3rd LPM family).
- **schema_version bump** — additive `std::optional` fields stay at v2.
- The 5.15-floor verifier re-confirmation (spike ran on 6.1; floor-proof deferred — margins make it near-certain, see ledger caveat). If a 5.15 box becomes available, re-run; not a blocker for the 6.1 deployment.

## Definition of done
- §5.52 amendment in `design.md` (v6 axes + closure + cross-family wildcard + Q1/Q2 resolutions + the base-header honesty boundary).
- `BITVEC_NUM_AXES 8`; `xdpmf_cidr_v6` struct; dst6/src6 AOM trios + 6 `kManagedMaps[]` rows; +2 `write_wildcard_slots` rows.
- `close_prefixes6` 128-bit closure with the guard-#23 cover-direction proof GREEN.
- v6 datapath arm at `:861` loads + classifies; IPv4 verdict bit-identical.
- config parses `dst_cidr6`/`src_cidr6`; cross-family wildcard correct (v4-only rule not dropped on v6 frames).
- oracle `--ruleset andv6` agreement GREEN; NEW ctests GREEN; full `-j4` run no flake; count 79 → ~82.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: existing CMake clang-19 BPF toolchain (`cmake/BpfBuild.cmake`); `__int128` if Q1=A1 (verified available under strict c++23).
- Runtime: python3 + scapy (inject_l6.py, S2); root/sudo for veth/netns/bpffs ctests.
- Kernel/platform: 6.1 host (spike PASS). 5.15-floor re-confirmation deferred (caveat).

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
**Mechanical + hld-discharged, single-architect.** The design space was resolved by `/mint-hld` (`architecture-l2l3-gate.md` S4 round, Option 1) with a terminal grounder discharge pass. Sub-check 6 re-discharge (this brief's Phase A) re-ran the ledger's 4 slice-time rechecks against current code: wildcard-fill-hand-enum CONFIRMED, closure-32-bit CONFIRMED, return-type CONFIRMED, `__int128`-feasibility CONFIRMED (ledger's "no EXTENSIONS OFF" premise refuted but outcome holds). Required pre-slice spike DISCHARGED (PASS, committed `00a077d`). PO plate EMPTY (ext-header resolved). `/mint-hld` NOT needed again. Single-architect via `/mint-dev`.

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author ran these; architect re-verifies + extends:
- `grep -n 'write_wildcard_slots\|BV_AXIS_' src/lib/loader.cpp` — confirm the hand-enumerated 6-row `slots[]` + 6-arg signature (`:1529`) + call site (`:1787`); the +2 v6 rows are the refuted net-new wiring.
- `grep -n 'host_mask\|host_addr\|close_prefixes' src/lib/loader.cpp` — confirm 32-bit closure (`:1195/:1202/:1230`); v6 = net-new 128-bit; return type `std::vector<std::uint64_t>` (`:1222`).
- `grep -n 'find(.:.)\|IPv6 CIDR not supported' src/lib/cidr.cpp` — confirm SINGLE reject chokepoint (`:60-63`); config.cpp 408/421 are comments.
- Read `src/bpf/mac_filter.bpf.c:638-883` (the v4 arm = the stamp to mirror) + `:861` (the empty seam) + the v4 dst LPM map trio decls (`:120-215`).
- `grep -n 'struct RuleMatch\|std::optional<xdpmf_cidr' src/lib/config.hpp` — confirm the additive v6-field landing site (`:44`).
- Confirm `unsigned __int128` under `clang++-19 -std=c++23 -pedantic -Werror` if Q1=A1 (this brief verified rc=0).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #5** (Phase A code-grep) — always; architect re-runs the greps above.
- **Guard #23** (bit-vector prefix-closure cover-direction / overlap-vector mandate) — DIRECTLY load-bearing: the v6 closure MUST have a test vector where a less-specific covering rule has a LOWER id (higher priority) than a more-specific one, at 128 bits incl. a non-aligned prefix (/40,/68,/127). The #1 bug class.
- **Guard #10** (catalog arithmetic) — `kManagedMaps[]` 30→36 (+6); `BITVEC_NUM_AXES 6→8`; `wildcard` max_entries 12→16 (formula-derived). Verify the counts.
- **Guard #16** (new map-name ripple) — NEW dst6/src6 pin names; ensure no test directly dumps a pin that doesn't exist yet (these are additive, low ripple).
- **Guard #12** (RESOURCE_LOCK) — new datapath ctests touch veth/netns/bpffs → `RESOURCE_LOCK xdp_fixture`.
- **Guard #24** (config-surface widening / alternate Config constructors) — verified N/A: `attach --allow` is MAC-only and cannot carry a v6 CIDR; the parity vector is unreachable (drop it). The widening is the single `cidr.cpp` chokepoint.
- **Guard #11** (VERSION-bump) — N/A unless architect bumps for operator-visible IPv6 support (HG-able; default no bump per internal-model-validation precedent).

> Operative-semantic note: line/count anchors (`:861`, `:1529`, 30→36, 79→~82) are SHOULD-level orientation, not literal-match contracts. The MUST contracts: IPv4 verdict bit-identical, cross-family wildcard correct (no spurious v6 drop of v4-only rules), guard-#23 cover-direction GREEN, kernel-canonical byte-array v6 LPM key, base-header-only honesty. Impl deviations preserving these are `inline-merge`.
