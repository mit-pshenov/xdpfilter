# Task brief — MVP-4.14 / S5: EtherType match axis (brownfield, additive)

## Goal

Add an **EtherType match axis** to the bit-vector AND classifier: a 9th axis (`BV_AXIS_ETHERTYPE`) so rules can match on L2 EtherType — closing the coarse non-IP steering gap (`ethertype: arp` drop, `ethertype: 0x86dd` drop, drop whole families pre-L3). This is the additive HASH-axis clone of the existing proto axis (B28 `aggregate_axis<u16>` style), the next slice of the L2/L3 gate ladder after S4 cidr6.

Anchor: `/home/user/mint-l2-mac-filter/mint/architecture-l2l3-gate.md` (ethertype lens / Option 3 — coarse non-IP steering explored there). NOT carried as a committed-ladder slice (per the discharge discipline, the prior ladder was a sketch); this brief re-grounds it fresh against current code. `design.md` gets a new §5.54 amendment.

## Context: prior work
- Prior brief: archived as `/home/user/mint-l2-mac-filter/mint/task-brief-mvp-4.13.md` (S4 cidr6, shipped `971f2fd`).
- Match model now: **8 AND-composed axes** — `BITVEC_NUM_AXES 8` (DST=0,SRC=1,PROTO=2,PORT=3,VLAN=4,MAC=5,DST6=6,SRC6=7). Composition: per-axis `__u64` bitmask intersection + `__builtin_ffsll` first-match; wildcard halves at `wildcard[active*BITVEC_NUM_AXES+axis]`.
- The **proto axis is the clone template**: HASH `ARRAY_OF_MAPS[2]` of `__u64` (`proto_bitmask_a/_b` + `proto_rulesets`), exact-match keyed lookup, NO closure (unlike the LPM axes). EtherType mirrors this exactly — exact-match u16 key, no closure.
- **Phase A code-grep verification (brief author ran — see footer):**
  - 3 datapath arms exist: `ETH_P_IP` (`mac_filter.bpf.c:638`), `ETH_P_IPV6` (`:861`), `else`/non-IP (`:866` → defaults, no classification today).
  - `inner_proto` (the EtherType after VLAN-walk) is computed at `:633` — BEFORE the family dispatch. EtherType is the family SELECTOR itself, not a per-arm L3/L4 field like proto.
  - `kManagedMaps[]` = 36 rows → +3 (ethertype inner_a/inner_b/outer) = 39.
  - `RuleMatch` (`config.hpp:44`) = 8 optional fields → +1 `std::optional<std::uint16_t> ethertype`.
  - ctest baseline 91; VERSION 0.15.0; guards through #27; ethertype ABSENT as a match axis today (NEW).
- **PI continuity:** ALL existing PIs CONTINUE. IPv4/IPv6 verdicts identical for configs with NO ethertype rule (new axis's terms are all-ones no-ops — same verdict-identity discipline as S4 guard #27). single-`active_idx` swap, schema_version 2 additive, first-match-by-id. loader.hpp likely stays zero-diff (PI-7) — architect confirms (the proto-axis add was anon-namespace-only).

## Workflow rules (brownfield)
- **Architect**: read `architecture-l2l3-gate.md` (ethertype lens) + `design.md` §5.44 (the proto-axis HASH clone template) + §5.53 (S4 — the symmetric-cross-arm + guard #27 precedent, directly relevant) + §6.5 invariants. EDIT `design.md` in place; append §5.54. Resolve Q1 (axis placement — THE crux) + Q2 (ethertype:ipv4 redundancy) + D-mvp-4.14-* tactical. Apply the guard-#27 verdict-identity lesson from S4.
- **Impl**: per the §5.54 FileList. Build clean + zero warnings; verifier-load the prod .bpf.o (the load-bearing smoke).
- **Tester**: NEW ctests target ≈2-3 (ethertype oracle-agreement incl. a non-IP `arp`/`0x88B5` drop vector — the headline value; cross-axis composition; negation control). Oracle (`bitvec_oracle_prod.py`) gains an ethertype axis + `--ethertype` arg. Real frames via `inject_eth.py` (exists). Full suite stays green; count 91 → ~93.
- **Reviewer**: 5-point brownfield. Load-bearing checks: (1) IPv4/IPv6 verdict identical for non-ethertype configs (guard #27 verdict-identity, NOT byte-identity — the proto/v6 arms' source may gain an ethertype term); (2) ethertype:arp/0x86dd actually DROPS a non-IP frame (the headline coarse-steering value — exercised in the non-IP arm that previously only hit defaults); (3) exact-match HASH (no closure) keyed by the post-VLAN EtherType; (4) cross-family composition correct per Q1 placement.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

> **PO plate: EMPTY.** No decision here hinges on external value. Axis placement, ethertype:ipv4 handling, and cross-arm composition are all engineering/realizability calls (architect-owned). The one prior PO fork (split vs co-ship with IPv6) is moot — IPv6 already shipped in S4; ethertype lands as its own additive slice as you directed.

### HG-mvp-4.14-1: axis representation → **HASH exact-match clone of the proto axis (u16 EtherType key), BITVEC_NUM_AXES 8→9, BV_AXIS_ETHERTYPE=8**
Mirror the proto-axis HASH `ARRAY_OF_MAPS[2]` topology + the family-blind `lower_axis` wildcard mechanism. No closure (exact-match like proto/vlan/mac). +3 `kManagedMaps[]` rows.

### HG-mvp-4.14-2: no VERSION bump → **default no bump** (HG-able — architect bumps to 0.16.0 if it wants operator-visible EtherType in `--version`)
Mirrors S4's internal-model-validation no-bump precedent.

## Open mechanism questions (architect decides; document in §5.54)

### Q1: EtherType axis placement (THE crux — architect owns realizability)
EtherType differs from proto: it is `inner_proto` (computed at `:633`, BEFORE the family dispatch), and its headline value — `ethertype:arp/0x86dd drop` — is COARSE NON-IP STEERING, so the axis must be evaluable in the **non-IP `else` arm** (`:866`) which today does ZERO classification (→defaults). Options the architect weighs (do NOT let the brief pre-commit the BPF mechanism):
- **A1**: hoist the EtherType axis lookup ABOVE the family dispatch (compute `eth_mask` once from `inner_proto`), compose it into all 3 arms' AND (IP/IPv6 arms gain `& (eth_mask|wc_eth)`; the non-IP else arm gets a NEW ethertype-only classification path instead of bare defaults).
- **A2**: per-arm lookup (clone proto literally into each arm) + a new else-arm path. More duplication; likely worse.
- **Recommendation**: A1 (hoist-once) — EtherType is family-independent (it IS the family key), single lookup is natural, and it cleanly extends the guard-#27 cross-arm verdict-identity model from S4. But realizability (verifier, the else-arm classification path) is the architect's call.

### Q2: `ethertype:ipv4` / `ethertype:ipv6` redundancy
A rule `ethertype: ipv4` is redundant with the existing IP arm (and composes with dst_cidr etc.). Options: accept-and-document as legal-but-redundant (hld lean) vs reject at config. **Recommendation**: accept-and-document — it's harmless and uniform with the axis model; rejecting adds a special-case. Architect confirms.

## Scope (cycle MVP-4.14 — concrete items; estimates are UPPER BOUNDS)

### Item S5-1 — header axis growth + map names
**Where**: `src/common/mac_filter.h`. `BITVEC_NUM_AXES 8→9`; NEW `BV_AXIS_ETHERTYPE=8`; NEW ethertype HASH map-name consts (inner_a/inner_b/outer, mirror proto). `wildcard` max_entries auto-grows 16→18 via the formula.

### Item S5-2 — datapath ethertype axis
**Where**: `src/bpf/mac_filter.bpf.c`. NEW ethertype HASH AOM trio (clone proto); axis composed per Q1 placement (hoist + all-3-arms incl. a non-IP classification path). Exact-match keyed by post-VLAN `inner_proto`.

### Item S5-3 — loader lowering + populate + wildcard
**Where**: `src/lib/loader.cpp`. ethertype `lower_axis` (exact-match, family-blind wildcard like proto); +3 `kManagedMaps[]` rows (36→39); +1 `write_wildcard_slots` row + param + arg (the hand-enumerated table — same net-new wiring as S4's dst6/src6, NOT auto-grow); populate the ethertype inner per slot.

### Item S5-4 — config surface
**Where**: `src/lib/config.{hpp,cpp}`. `RuleMatch` +`std::optional<std::uint16_t> ethertype`; YAML key `ethertype` accepting named (`ipv4`/`ipv6`/`arp`) + hex (`0x86dd`) + numeric forms (clone `parse_l4_proto`'s named-or-numeric pattern). Extend the at-least-one-match-set check.

### Item S5-5 — oracle + ctests
**Where**: `tests/bitvec/bitvec_oracle_prod.py` (NEW ethertype axis + `--ethertype` arg + `RULES_*` extension) + NEW fixtures + NEW ctests (≈2-3: ethertype oracle-agreement WITH a non-IP arp/0x88B5 drop vector — the headline; cross-axis compose; negation control). Real frames via `inject_eth.py`.

## Out of scope (explicit)
- **IPv6 ext-header walk** (S6 — separate slice).
- **C3 sidecar v6 match-kinds gap** (carried from S4 — fast-follow, not this slice; though if the architect adds ethertype to sidecar's match-kind enumeration for symmetry, that's an inline-merge call).
- schema_version bump (additive optional field stays v2).
- Any L3/L4 axis change; the v4/v6 CIDR/proto/port/vlan/mac axes are untouched except the cross-arm ethertype compose term.

## Definition of done
- §5.54 amendment in `design.md` (ethertype axis + Q1/Q2 resolutions + the non-IP-arm classification path + guard-#27 verdict-identity note).
- `BITVEC_NUM_AXES 9`; ethertype HASH AOM trio + 3 `kManagedMaps[]` rows + 1 `write_wildcard_slots` row.
- ethertype:arp/0x86dd DROPS a non-IP frame (headline); IPv4/IPv6 verdict identical for non-ethertype configs.
- config parses `ethertype` (named/hex/numeric); oracle agreement GREEN; NEW ctests GREEN; full `-j4` no flake; count 91 → ~93.
- `mint/review.md` round-1 verdict = pass; one git commit per phase boundary.

## Dependencies
- Build: existing CMake clang-19 BPF toolchain. Runtime: python3 + scapy (inject_eth.py); root/sudo for veth/netns/bpffs ctests. Kernel: 6.1 host.

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
**Mechanical, single-architect, additive.** EtherType is an additive HASH-axis clone of the shipped proto axis; the design space (coarse non-IP steering) was explored in `architecture-l2l3-gate.md` (ethertype lens). The one real design consideration — axis placement vs the family dispatch / non-IP arm (Q1) — is architect-tier realizability, NOT a multi-axis design fork (one clear recommendation, A1). No sharp edge (exact-match, no closure → no spike needed, unlike S4's 128-bit closure). PO plate empty (all decisions engineering). `/mint-hld` NOT needed. Single-architect via `/mint-dev`. (Forward-discipline note: this slice was NOT pre-committed from a numbered ladder — re-grounded fresh per the discharge discipline.)

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author ran these; architect re-verifies + extends:
- `grep -nE 'proto_rulesets|proto_bitmask|xdpmf_proto_inner|aggregate_axis' src/bpf/mac_filter.bpf.c src/common/mac_filter.h` — the HASH-axis clone template (topology + map decl + the u64-aggregate lookup).
- Read `mac_filter.bpf.c:630-872` — the 3-arm dispatch (`:638` IP / `:861` IPv6 / `:866` else-non-IP→defaults) + `inner_proto` at `:633`; this is where Q1 placement lands.
- `grep -nE 'write_wildcard_slots|BV_AXIS_' src/lib/loader.cpp` — the hand-enumerated wildcard table (+1 ethertype row = net-new wiring, the S4 refuted-claim lesson).
- `grep -nE 'parse_l4_proto|protocol' src/lib/config.cpp` — the named-or-numeric parse pattern to clone for ethertype.
- Confirm `kManagedMaps[]`=36 (→39) and `RuleMatch` 8 fields (→9) at slice-time (FS-lag noise this session — re-grep to confirm before writing FileList).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #5** (Phase A code-grep) — always; architect re-runs the greps above.
- **Guard #27** (cross-family/multi-arm verdict-identity, NEW from S4) — DIRECTLY applies: the ethertype axis composes into the IP/IPv6 arms, so those arms' SOURCE changes (gain `& (eth_mask|wc_eth)`); the correct invariant is VERDICT-identity (oracle GREEN for non-ethertype configs), NOT byte-identity. Do not flag the cross-arm term as an unrelated edit.
- **Guard #10** (catalog arithmetic) — `kManagedMaps[]` 36→39 (+3); `BITVEC_NUM_AXES 8→9`; `wildcard` max_entries 16→18 (formula). Verify counts.
- **Guard #12** (RESOURCE_LOCK) — new datapath ctests touch veth/netns/bpffs → `RESOURCE_LOCK xdp_fixture`.
- **Guard #23** (closure cover-direction) — N/A: ethertype is exact-match HASH, NO closure (like proto/vlan/mac).
- **Guard #11** (VERSION-bump) — N/A unless architect bumps (HG-mvp-4.14-2 default no).

> Operative-semantic note: count/section anchors (kManagedMaps 36→39, §5.54, 91→~93, line numbers) are SHOULD-level orientation, not literal-match contracts — re-grep at slice-time (FS-lag noise observed during this brief's Phase A). MUST contracts: ethertype:arp/0x86dd drops a non-IP frame, IPv4/IPv6 verdict-identity for non-ethertype configs, exact-match HASH no closure, additive schema. Impl deviations preserving these are `inline-merge`.
