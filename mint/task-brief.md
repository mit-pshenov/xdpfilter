# Task brief — MVP-4.5: bit-vector axis 5 — VLAN match (exact HASH, APN selector) (rule-model S5, brownfield)

## Goal

Add **VLAN** as a 5th bit-vector match axis on the production AND classifier (axes 1-4 = dst_cidr/src_cidr/proto/dst_port, landed §5.43-§5.44). On the Gi link **VLAN is the APN carrier** — the real subscriber/APN selector for downstream DPI (per [[dpi-pre-filter-purpose]] + `mint/selection-scenarios.md` §3.A). PO picked this over MAC-axis-return (MAC is a weak selector on an L3 Gi link) for product value.

The tagged-frame parse path already exists (§5.41 `l3_after_vlan` walks ≤2 802.1Q/QinQ tags to reach L3) — but it currently **discards the tag's TCI** (only follows `h_vlan_encapsulated_proto` to find L3). This slice extends the walk to **capture the outer tag's `vlan_id`** (`ntohs(h_vlan_TCI) & 0x0FFF`) and adds a `vlan` exact-match HASH axis (`vlan_id u32 → u64 bitmask`), **symmetric to the proto axis** (§5.44). `BITVEC_NUM_AXES` 4→5; `wildcard` ARRAY grows to `RULESET_COUNT*5=10`; `kManagedMaps[]` +3 (vlan trio). Additive within `schema_version 2` (new optional `vlan` key, NO cutover). Datapath: `acc &= (vlan_mask | wc_vlan)`; an **untagged** frame has no vlan_id → the vlan axis contributes 0, so only vlan-wildcard rules survive (exactly the `has_port=0` parallel from §5.44).

Anchors: §5.44 (proto exact-HASH axis — the closest template, including the additive-within-v2 grammar + RESET-on-apply + wildcard-growth pattern), §5.41 (`l3_after_vlan` + the guard #22 VLAN-offload-disable test discipline), `mint/architecture-rule-model.md` (VLAN-match = catalog axis, APN proxy).

## Context: prior work

- **All prior briefs**: archived in `mint/task-brief-*.md` (this supersedes `mint/task-brief-mvp-4.4.md`).
- **Existing design**: `mint/design.md` §5.44 (MVP-4.4 — proto exact-HASH + dst_port range axes; the additive-within-v2 grammar extension, `wildcard` auto-grow via `RULESET_COUNT*BITVEC_NUM_AXES`, RESET-on-apply lowering, the `xdpmf_proto_inner` HASH-AOM topology this VLAN axis mirrors). §5.41 (MVP-4.1 — `l3_after_vlan` ≤2-tag walk; the depth-3 anti-vacuity fence + the `ethtool -K rxvlan/txvlan off` offload-disable test discipline = guard #22).
- **Architecture doc**: `mint/architecture-rule-model.md` — VLAN-match is a planned axis; VLAN = APN proxy (selection-scenarios §3.A); the tagged parse path was split into S1 precisely so the VLAN-MATCH axis could land cleanly later (now).
- **Phase A code-grep verification**: brief author ran the greps in the Phase-2 report below (BITVEC_NUM_AXES=4, BV_AXIS_PROTO/PORT=2/3, wildcard width=8, kManagedMaps=27, VERSION=0.12.0, RuleMatch shape, `l3_after_vlan` DISCARDS the TCI today, `vlan_hdr.h_vlan_TCI` exists in vmlinux.h, proto axis topology as template). See footer.
- **PI continuity**: PI-mvp-4.3-AND / -WILDCARD / -SCHEMA-V2 extend (now 5 axes); PI-mvp-4.4-PROTO pattern is the template; PI-mvp-4.3-COUNTER-PRESERVE + EXPORTER-AGNOSTIC + close_prefixes-UNCHANGED CONTINUE; config.hpp gains one more optional field. New vlan maps RESET-on-apply (guard #15). **No schema_version cutover** (additive within v2) ⇒ existing v2 corpus stays green (the mvp-4.4 lesson: a clean additive cycle).

## Workflow rules (brownfield)

- **Architect**: read `design.md` §5.44 (the axis-add template — grammar, HASH-AOM topology, wildcard-index formula, RESET-on-apply) + §5.41 (`l3_after_vlan` + guard #22) + the brief. EDIT `design.md` in place; append **§5.45**. Resolve Q1–Q3 + HG defaults with Phase A grep evidence. State explicitly that VLAN is exact-match (NO prefix-closure — guard #23 does NOT extend; the dst/src §6.62 closure canary + close_prefixes stay UNCHANGED).
- **Impl**: brownfield FileList DIFF. **Extend `l3_after_vlan` in place** to thread out the outer `vlan_id` (it is a SINGLE-CONSUMER datapath helper — extend-in-place is correct, NOT a guard-#9 duplication case; confirm single call-site). Add the vlan HASH axis mirroring proto (`xdpmf_proto_inner`→`xdpmf_vlan_inner` analog). `BITVEC_NUM_AXES` 4→5 (the `wildcard` width auto-derives 8→10 via the formula — no literal edit in the .bpf.c decl). Re-run the bpftool-load smoke.
- **Tester**: extend the independent O(N) oracle to 5 axes (vlan exact membership). NEW tests: vlan-AND compose, untagged→vlan-wildcard survival, vlan-miss negation, 5-axis oracle agreement. **Guard #22 MANDATORY**: VLAN tests inject tagged frames — disable NIC VLAN offload in setup (`ethtool -K ${IFACE} rxvlan off txvlan off`, best-effort) so the kernel does NOT strip the tag before XDP, else the assertion is vacuous (§5.41 precedent). Existing corpus stays GREEN (additive). Reconcile baseline via fresh `ctest -N` (was 79).
- **Reviewer**: 5-point brownfield. Special attention: (a) `vlan_id` capture correctness — outer tag, `ntohs(TCI)&0x0FFF` (low 12 bits; the high 4 PCP/DEI bits MUST be masked off); (b) untagged-frame path → vlan_mask=0 → only vlan-wildcard rules survive (no spurious match); (c) guard #22 — VLAN tests actually disable offload (else vacuous); (d) vlan maps ride active_idx RESET-on-apply (no copy-forward); (e) wildcard 8→10 + index `active*5+axis` correct; (f) kManagedMaps 27→30 exact; (g) `l3_after_vlan` extension is single-consumer in-place (not a needless duplicate); existing v2 corpus green with zero conversions.

## Human-gate decisions (defaults applied — architect overrides at Phase A with evidence)

### HG-mvp-4.5-1: Axis → **VLAN exact-match HASH (axis 5)**
`vlan_id u32 → u64 bitmask`, mirroring the proto axis (§5.44). `BITVEC_NUM_AXES` 4→5, `BV_AXIS_VLAN=4`. NO prefix-closure (exact).

### HG-mvp-4.5-2: Which tag on QinQ depth-2 → **OUTER (first/S-VLAN) tag**
The outer tag is typically the APN/S-VLAN selector on a Gi link. Default: capture the FIRST tag's `vlan_id` during the `l3_after_vlan` walk. Inner-tag (C-VLAN) matching → OOS (later if a use-case needs it). Architect may override with evidence (e.g. if selection-scenarios says inner).

### HG-mvp-4.5-3: `vlan` config grammar → **`vlan: <0-4095>` (single id), additive within schema_version 2**
A rule's `match.vlan` is a single VLAN id in [0,4095]. Ranges/lists → OOS (multi = multiple rules, mirroring dst_port single-value default). New optional key in the existing v2 grammar; existing v2 configs (no `vlan`) parse unchanged. NO schema bump.

### HG-mvp-4.5-4: Untagged-frame semantics → **vlan axis contributes 0 (only vlan-wildcard rules survive)**
A frame with no VLAN tag has no vlan_id → `vlan_mask=0`; a rule that constrains `vlan` cannot match an untagged frame; a rule omitting `vlan` survives via `wildcard[active*5+VLAN]`. Exact parallel to §5.44 `has_port=0` for ICMP. (Document the sentinel/has_vlan mechanism — architect picks: a `has_vlan` flag or an out-of-range sentinel id.)

### HG-mvp-4.5-5: VERSION → **bump 0.12.0 → 0.13.0 + DESCRIPTION update**
New match capability (VLAN/APN axis). Propagate the literal per guard #11 (mvp-4.4 left only `T_EXPORTER_METRICS_FORMAT` pinning it). Architect picks exact bump.

### HG-mvp-4.5-6: Exporter → **UNCHANGED** (rule_id-keyed, axis-agnostic; per-axis labels stay a later slice). PI-mvp-4.3-EXPORTER-AGNOSTIC continues.

## Open mechanism questions (architect decides; document in §5.45)

### Q1: vlan axis map topology
- **A1**: NEW `ARRAY_OF_MAPS[2]` of inner HASH (`vlan_bitmask_a/_b` + `vlan_rulesets`), key `__u32` vlan_id, value `__u64` bitmask, rides `active_idx`. Mirrors the proto axis (§5.44 D-mvp-4.4-Q1) exactly. +3 kManagedMaps. NO closure.
- **Recommendation**: **A1** — proto is the proven template for an exact-match axis; copy its shape.

### Q2: vlan_id capture in `l3_after_vlan`
- **A1**: extend `l3_after_vlan` in place to thread out the outer vlan_id via an out-param (e.g. `__u16 *out_vlan_id` set from the FIRST tag's `ntohs(h_vlan_TCI)&0x0FFF`, + a `has_vlan` signal — out-of-range sentinel or bool). Single call-site → extend-in-place, NOT a guard-#9 duplicate.
- **A2**: a separate parallel walk helper — rejected (re-walks the frame, wasteful + two sources of truth for the tag chain).
- **Recommendation**: **A1** — one walk, one consumer; capture the outer TCI during the existing loop; mask the low 12 bits (drop PCP/DEI). Confirm the single call-site via grep.

### Q3: wildcard growth + axis index
- `wildcard` max_entries `RULESET_COUNT*BITVEC_NUM_AXES` auto 8→10; `BV_AXIS_VLAN=4`; datapath `wildcard[active*5+4]`; loader writes the inactive half's 5 axis slots; RESET-on-apply (guard #15, no copy-forward). Architect confirms the `active*5+axis` formula holds for all 5 axes (same mechanism as §5.44 Q4, just N=5).

## Scope (cycle S5 / mvp-4.5 — concrete items; estimates are UPPER BOUNDS)

### Item S5-1 — config grammar + parse (vlan)
**Where**: `src/lib/config.cpp`, `src/lib/config.hpp`
- `RuleMatch` gains `std::optional<std::uint16_t> vlan;` (architect picks the exact width; vlan_id ≤4095 fits u16).
- v2 grammar accepted-key set `{dst_cidr,src_cidr,protocol,dst_port}` → `+vlan`; parse + validate [0,4095]; at-least-one-of stays (now any of 5). Schema stays 2.

### Item S5-2 — datapath: vlan_id capture + vlan axis + 5-axis acc
**Where**: `src/bpf/mac_filter.bpf.c`
- Extend `l3_after_vlan` to capture the outer vlan_id (+ has_vlan signal) per Q2.
- ADD `vlan_bitmask_a/_b` + `vlan_rulesets` HASH-AOM decls (mirror proto); `BV_AXIS_VLAN=4`.
- EXTEND acc: `&= (vlan_mask | wildcard[active*5+4])`; vlan_mask from `vlan_bitmask[active]` HASH lookup if has_vlan else 0. `first_set_u64`/dispatch/`bump_rule`/defaults/close_prefixes/dst+src+proto+port axes UNCHANGED.

### Item S5-3 — loader: lower vlan axis
**Where**: `src/lib/loader.cpp`, `src/common/mac_filter.h`
- NEW `XDPMF_MAP_VLAN_*_NAME` constants (vlan trio); `BITVEC_NUM_AXES` 4→5 (mac_filter.h); `kManagedMaps[]` 27→30 (+3: vlan_bitmask_a/_b, vlan_rulesets).
- Lower `Config::rules` → vlan HASH bitmask (exact, NO closure) + extend the wildcard-write to 5 axes; RESET-write inactive inners before the single `active_idx` flip. `close_prefixes`/`copy_rule_counters_forward` UNCHANGED.

### Item S5-4 — VERSION bump + DESCRIPTION + literal propagation
**Where**: `CMakeLists.txt` + `T_EXPORTER_METRICS_FORMAT` (the one version-pinning test, guard #11).

### Item S5-5 — sidecar
**Where**: `src/lib/sidecar.cpp` — emit `vlan` in the per-rule match object (mirrors the §5.44 protocol/dst_port emission). Verify via grep it enumerates match axes (it does per §5.44).

### Item S5-6 — tests: vlan axis + 5-axis oracle
**Where**: `tests/` (NEW T_VLAN_AND_COMPOSE + untagged-wildcard + vlan-miss negation; extend 5-axis oracle agreement), `tests/bitvec/bitvec_oracle_prod.py` (→5 axes), fixtures (NEW v2 config with `vlan`), `tests/CMakeLists.txt`. **Guard #22**: VLAN tests disable NIC offload (`ethtool -K rxvlan/txvlan off`) + a depth/strip anti-vacuity check (§5.41 precedent). `inject_l4.py` supports `--vlan` (verify). Existing corpus stays green. `RESOURCE_LOCK xdp_fixture` (guard #12).

## Out of scope (explicit)
- **MAC-axis return; exporter per-axis labels** — later slices (the frozen MAC maps stay pinned-but-unconsulted since §5.43). NEW FENCE.
- **Inner-VLAN (C-VLAN) matching; PCP/DEI bits; VLAN ranges/lists per rule** — outer single-id only this slice. NEW FENCE.
- **IPv6 cidr6; feed-objects; N>64; most-specific-wins; sequential lowering** — later (carry §5.42-§5.44 fences). NEW FENCE.
- **schema_version v2→v3** — additive within v2; no cutover. NEW FENCE.
- **Non-eBPF datapath / 40 Gbps line-rate** — deferred per [[real-requirements-and-strategy]].
- Carry-forward §5.41-§5.44 OOS items not superseded — UNCHANGED.

## Definition of done
- §5.45 amendment appended to `mint/design.md` (Phase A grep report + HG/Q resolutions + vlan lowering notes + new PIs).
- **PIs**: NEW PI-mvp-4.5-VLAN (exact HASH axis, outer-tag, low-12-bit), PI-mvp-4.5-UNTAGGED (untagged→vlan-wildcard-only), PI-mvp-4.5-VLAN-CAPTURE (l3_after_vlan threads outer vlan_id, single-consumer); PI-mvp-4.3-AND/-WILDCARD/-SCHEMA-V2 extended to 5 axes; PI-mvp-4.4-* + COUNTER-PRESERVE + EXPORTER-AGNOSTIC + close_prefixes-UNCHANGED CONTINUE.
- ctest baseline = **79** (mvp-4.4 left it here; tester reconciles) + NEW vlan/5-axis tests; existing corpus green (additive — confirm zero conversions).
- VERSION 0.12.0 → 0.13.0, literal propagated.
- impl Phase 2.5 bpftool-load smoke rc=0 (5-axis + vlan_id capture verifies on the floor).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang-19 / libbpf / CMake; `bpftool` for ctest map dumps; `inject_l4.py --vlan` for tagged-frame injection.
- Runtime: `bpf()` HASH + ARRAY_OF_MAPS (all used); bounded VLAN walk (5.15-safe, exists §5.41).
- Platform: passwordless sudo for XDP/veth/bpffs ctests; `ethtool -K` for offload-disable (guard #22).

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
- **One-sentence goal**: add VLAN (outer tag, exact-match HASH) as bit-vector axis 5 on the production AND structure, additive within schema_version 2, capturing vlan_id in the existing l3_after_vlan walk.
- **Multi-axis design space?** NO — structure resolved (bit-vector); the proto axis (§5.44) is a proven exact-match template; the only new mechanism is vlan_id capture in an existing walk. `/mint-hld` NOT needed.
- **Mechanical?** YES — "copy the proto axis + extend l3_after_vlan to capture the outer tag." Single-architect via `/mint-dev`.
- **Scope-size**: moderate, ONE coherent slice (smaller than mvp-4.4: one axis not two, no new L4 parse — the VLAN walk already exists). No split.
- **Overconfidence check**: VERIFIED that `l3_after_vlan` currently DISCARDS the TCI (only follows the encapsulated proto) — the capture is genuinely NEW, flagged, not assumed-present. BITVEC_NUM_AXES=4 / wildcard=8 / kManagedMaps=27 / VERSION=0.12.0 grep-verified (not memory). Guard #22 (offload-disable) is a known vacuity trap from §5.41 — pre-listed.

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author ran these (Phase 2). Architect re-verifies independently + extends:
- `grep -nE 'BITVEC_NUM_AXES|BV_AXIS_' src/common/mac_filter.h` (=4; DST/SRC/PROTO/PORT=0/1/2/3; add VLAN=4).
- `sed -n '/l3_after_vlan/,/^}/p' src/bpf/mac_filter.bpf.c` (CONFIRM: reads `h_vlan_encapsulated_proto`, DISCARDS `h_vlan_TCI` — the capture is new; single call-site).
- `grep -nE 'struct vlan_hdr|h_vlan_TCI' include/vmlinux.h` (TCI field exists at :57636; vlan_id = `bpf_ntohs(TCI)&0x0FFF`).
- `sed -n '/kManagedMaps/,/};/p' src/lib/loader.cpp` (27 entries — confirm before/after delta = +3).
- `grep -nE 'proto_bitmask|proto_rulesets|xdpmf_proto_inner|XDPMF_MAP_PROTO' src/common/mac_filter.h src/bpf/mac_filter.bpf.c` (the exact-HASH axis template to mirror for vlan).
- `grep -nE 'dst_cidr|protocol|dst_port|not supported' src/lib/config.cpp` (v2 grammar accepted-key set to extend with `vlan`).
- `grep -nE 'vlan|protocol|dst_port' src/lib/sidecar.cpp` (match-object emission to extend).
- `grep -rn '0\.12\.0' CMakeLists.txt tests/ docs/ CHANGELOG.md` (VERSION propagation surface).
- `grep -rn 'rxvlan\|txvlan\|ethtool -K' tests/` (the §5.41 guard #22 offload-disable pattern to reuse).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #5 (Phase A code-grep)** — always; architect repeats independently.
- **Guard #9 (helper duplication-over-extraction)** — `l3_after_vlan` is SINGLE-CONSUMER → extend-in-place is correct (NOT a duplicate); confirm the single call-site. Do NOT `#include tests/bitvec/*` (transcribe any spike pattern).
- **Guard #10 (catalog arithmetic)** — `kManagedMaps[]` 27→30 (+3); `wildcard` 8→10; `BITVEC_NUM_AXES` 4→5. State EXACT counts; load-bearing.
- **Guard #11 (VERSION-bump test-literal propagation)** — applies (HG-5); grep every `0.12.0`.
- **Guard #12 (RESOURCE_LOCK)** — new VLAN ctests take `RESOURCE_LOCK xdp_fixture` + cleanup trap.
- **Guard #15 (PRESERVE-vs-RESET)** — NEW vlan maps + grown wildcard are RESET-on-apply (no copy-forward); rule_counters stays PRESERVE.
- **Guard #22 (L2-mutation test vacuity)** — **DIRECTLY APPLIES**: VLAN-match tests inject tagged frames; MUST disable NIC VLAN offload (`ethtool -K rxvlan/txvlan off`) so the kernel doesn't strip the tag before XDP, else the vlan assertion is vacuous. Reuse the §5.41 pattern + a strip/depth anti-vacuity check.
- **Guard #23 (prefix-closure)** — does NOT extend to vlan (exact-match, like proto). dst/src §6.62 closure canary + close_prefixes() UNCHANGED. State explicitly.
- **Guard #25 (variable-length L4 offset)** — N/A (vlan_id captured at a fixed offset within the existing bounded VLAN walk; no new variable-offset surface).
- **Operative-semantic discipline**: counts in §5.45 verifiable-invariants (kManagedMaps=30, wildcard=10, BITVEC_NUM_AXES=5 are load-bearing MUST; ctest delta, PI numbering SHOULD) — impl deviations mirroring precedent / structural-symmetry fixtures are `inline-merge`.
