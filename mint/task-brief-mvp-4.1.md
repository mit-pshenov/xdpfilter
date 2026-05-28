# Task brief — MVP-4.1: VLAN-tagged-frame L3 parse-path fix (rule-model S1) (brownfield, bugfix-foundation)

## Goal

Fix the latent datapath bug where **VLAN-tagged IPv4 frames silently skip the CIDR (L3) match branch**, so the existing `src_cidr` axis works on a VLAN-segmented Gi link. Today `mac_filter_prog` reaches the CIDR lookup only when `eth->h_proto == ETH_P_IP` (`src/bpf/mac_filter.bpf.c:367`); on an 802.1Q-tagged frame `h_proto == 0x8100`, so the frame never reaches L3 matching and falls to `defaults[active]`. On a GGSN-Gi link APN context is carried as a VLAN tag (Wave A `mint/selection-scenarios.md` §3.A / §4), so real Gi traffic is tagged — meaning the src-CIDR axis is effectively broken there today.

This is **slice S1 of the rule-model build** per `mint/architecture-rule-model.md`. It is deliberately scoped to the parse-path fix ONLY. The Rule IR, first-match-by-`id` ordering, and `schema_version:2` hard-cutover described in that doc's S1 are **deferred to S2** (the AND-architecture landing), because: (a) `config.cpp:152` only supports `schema_version {1}` and bumping to 2 is meaningless before v2 AND-features exist; (b) a Rule IR with no consumer is premature abstraction; (c) first-match ordering is moot in the current single-axis OR model. The parse fix is the one piece that is independently valuable now and is a prerequisite for every future dst-IP/port/VLAN axis (they all need tagged frames to reach L3).

## Context: prior work
- Architecture anchor: `mint/architecture-rule-model.md` (Wave B synthesis; §6.4 = this fix; "Recommended slice sequence" S1). PO decisions block records the framing.
- Demand anchor: `mint/selection-scenarios.md` §3.A (VLAN = APN carrier), §6.4 (this latent bug).
- Prior brief: `mint/task-brief-mvp-3.4i.md` (archived). No carried-over OOT items bear on this slice.
- Phase A code-grep verification (brief author, see Phase 2 report in conversation): `mac_filter.bpf.c:367` gate confirmed; MAC key read at `:304-306` is BEFORE the L3 gate → MAC axis unaffected; `struct vlan_hdr` present in `vmlinux.h`; no existing VLAN datapath handling; no VLAN ctests; `tests/inject/inject_ipv4.py` has no Dot1Q support.
- PI continuity: PI-7 ZERO-diff streaks on `loader.hpp`/`config.hpp` should continue (this slice does NOT touch the loader or config schema). The datapath verdict semantics (STAT_PASS / STAT_PASS_CIDR / STAT_DROP_*) are PRESERVED — a tagged in-range IPv4 frame must now hit STAT_PASS_CIDR exactly as an untagged one does.

## Workflow rules (brownfield)
- **Architect**: read `mint/architecture-rule-model.md` §6.4 + the demand anchor; EDIT `design.md` in place; append a new §5.41 amendment. Re-run the Phase A greps below independently.
- **Impl**: FileList is upper-bound. Primary EDIT = `src/bpf/mac_filter.bpf.c` datapath; NEW/EDIT test injector + ctests. If `tests/CMakeLists.txt` is EDITED, run `cmake -B build -S .` reconfigure before `ctest` (else new tests don't enumerate).
- **Tester**: NEW ctests target the tagged-frame pass/drop paths; reuse the `T_PASS_CIDR` / `T_DROP_CIDR_NOT_IN_RANGE` template + `setup_veth` + `tests/inject`. New ctests MUST take `RESOURCE_LOCK xdp_fixture` (guard #12).
- **Reviewer**: 5-point brownfield framework. Special attention: (a) verifier-feasibility of the tag-walk (bounded, no unbounded loop); (b) non-IPv4-after-VLAN semantic preservation; (c) MAC-axis path untouched.

## Human-gate decisions (defaults applied — architect overrides at Phase A with evidence)

### HG-mvp-4.1-1: VLAN parse depth → **802.1Q + QinQ stacked, depth ≤ 2, then inner EtherType**
Walk up to two stacked VLAN tags (`0x8100` / `0x88A8`), then apply the existing `ETH_P_IP` check on the inner EtherType. Bounded unroll (depth 2), no loop. Architect may reduce to single-tag if QinQ is confirmed absent on Gi, but ≤2 is the safe default and verifier-cheap.

### HG-mvp-4.1-2: non-IPv4-after-VLAN (ARP / IPv6 / other) → **preserve current semantic**
After tag-walk, a non-IPv4 inner EtherType behaves exactly as a non-IPv4 untagged frame does today: skip the CIDR branch, fall through to the MAC-axis result + `defaults[active]`. This slice ONLY adds IPv4-after-VLAN reach; it does NOT change any other verdict.

### HG-mvp-4.1-3: "no residual tunneling on Gi" → **documented invariant; inner-IP-under-encap is OUT OF SCOPE**
Assume Gi frames are plain (optionally VLAN/QinQ-tagged, depth ≤2) IP with GTP-U terminated upstream at the GGSN (Wave A §1, HA#5). The parser extracts the FIRST IP header after the L2/VLAN headers. If a future deployment shows residual tunneling (the "dst-IP" being an inner IP under encap), that is a separate slice — document the invariant in §5.41 so the assumption is explicit and falsifiable. (PO flagged this needs NOC detail; S1 proceeds on the safe assumption and does not block on it.)

### HG-mvp-4.1-4: VERSION bump → **none** (internal datapath bugfix)
Consistent with prior internal-hardening slices (no operator-facing CLI/schema surface change). Architect overrides if it judges the behavior change operator-visible enough to warrant it (guard #11 then applies).

## Open mechanism questions (architect decides; document in §5.41)

### Q1: VLAN tag-walk placement
- **A1**: inline the tag-walk in `mac_filter_prog` immediately before the `ETH_P_IP` gate (`:367`), computing inner EtherType + L3 offset locally.
- **A2**: a `static __always_inline` helper (e.g. `l3_after_vlan(eth, data_end, &l3_off, &inner_proto)`).
- **Recommendation**: A2 as a small `static __always_inline` helper but kept **single-consumer** (guard #9 duplication-over-extraction — do NOT build a shared/general parser; there is exactly one call-site). Either is fine; bias to whichever keeps the verifier instruction-path simplest.

### Q2: does the MAC-axis branch need any change?
- **Recommendation: NO.** The MAC key is read from the outer Ethernet header (`:304-306`) before the L3 gate, so MAC matching already works on tagged frames. S1 touches ONLY the L3-reach path. State this explicitly so the architect does not gratuitously modify the MAC branch.

## Scope (cycle S1 — concrete items)

### Item 4.1-1 — datapath VLAN-tag-walk before L3 match
**Where**: `src/bpf/mac_filter.bpf.c` (the `eth->h_proto == ETH_P_IP` gate at `:367` and the surrounding L3 branch).
Walk ≤2 VLAN tags from the Ethernet header, derive the inner EtherType + L3 start offset, and apply the existing CIDR lookup when the inner EtherType is IPv4. Preserve bounds-checks (verifier-required) at each tag step. Verdict semantics unchanged (STAT_PASS_CIDR / STAT_DROP_* exactly as untagged).

### Item 4.1-2 — test injector gains optional VLAN tag(s)
**Where**: `tests/inject/inject_ipv4.py` (raw-frame builder).
Add an optional `--vlan <id>` (and optionally a second `--vlan` for QinQ) that inserts `0x8100`+TCI tag(s) between src/dst MAC and the `0x0800` EtherType. Keep the existing untagged path byte-identical (default = no tag).

### Item 4.1-3 — NEW ctests for tagged-frame match
**Where**: `tests/T_PASS_CIDR_VLAN.sh` (NEW) + `tests/CMakeLists.txt` (register, with `RESOURCE_LOCK xdp_fixture`). Optionally `tests/T_PASS_CIDR_QINQ.sh` for depth-2.
Tagged in-range IPv4 src → STAT_PASS_CIDR (the regression the fix closes); tagged out-of-range src → STAT_DROP_DENY; (optional) tagged ARP/non-IP → unchanged. Template: `T_PASS_CIDR` (§6.28) + `setup_veth` + `tests/inject`.

## Out of scope (explicit)
- Rule IR, first-match-by-`id` ordering, `schema_version:2` — all deferred to S2 (AND-landing).
- Any new match field (dst_ip / port / vlan-as-match-axis / ethertype) — later slices. **This slice makes tagged frames REACH L3; it does NOT add `vlan` as a match key.**
- Classification-structure choice (sequential vs bit-vector) — S2 spike.
- Inner-IP-under-residual-tunneling parsing (HG-mvp-4.1-3 invariant).
- VERSION bump (HG-mvp-4.1-4).

## Definition of done
- §5.41 amendment in `design.md` (with the HG-mvp-4.1-3 "no residual tunneling" invariant documented).
- PI-7 ZERO-diff streaks on `loader.hpp`/`config.hpp` continue (this slice touches neither).
- ctest baseline preserved + NEW tagged-frame ctest(s) green, taking `RESOURCE_LOCK xdp_fixture`.
- Non-IPv4-after-VLAN and MAC-axis verdicts demonstrably unchanged.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: existing BPF/CO-RE toolchain; `struct vlan_hdr` from `vmlinux.h`.
- Runtime: root for veth/bpffs ctests (already standard).
- Kernel/platform: project floor 5.15 — bounded tag-walk via `#pragma unroll` / fixed depth, no `bpf_loop` (5.17+).

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
Single-axis, mechanical datapath fix that falls out of the Wave-B architecture decision (§6.4). NOT multi-axis; NOT expensive-to-undo; one viable mechanism (walk VLAN tags → reach existing L3 branch). → single-architect `/mint-dev`; `/mint-hld` NOT needed. Slice boundary resolved by code-grep (Phase 2): IR/ordering/schema:2 are S2-coupled and excluded; §6.4 parse-fix is the clean independent S1.

## Notes for architect Phase A code-grep discipline
Re-verify independently:
- `grep -nE 'h_proto == .*ETH_P_IP|bpf_htons\(ETH_P_IP\)' src/bpf/mac_filter.bpf.c` — the L3 gate to widen (currently `:367`).
- Confirm MAC key read precedes the L3 gate (currently `:304-306`) → MAC axis needs no change.
- `grep -nE 'struct vlan_hdr|h_vlan_encapsulated_proto|vlan_tci' include/vmlinux.h` — the tag struct to use.
- `grep -rln 'RESOURCE_LOCK xdp_fixture' tests/CMakeLists.txt` — registration pattern for new veth ctests.
- Inspect `tests/inject/inject_ipv4.py` raw-frame layout before adding the tag option (manual bytes + ip_checksum, NOT scapy Dot1Q).

### Anti-misdiagnosis guards applicable to this slice
- **Guard #5 (Phase A code-grep discipline)** → re-run the greps above; do not trust this brief's line numbers (they shift).
- **Guard #12 (RESOURCE_LOCK for shared host state)** → every NEW ctest touches `veth_a/veth_b` + bpffs → MUST set `RESOURCE_LOCK xdp_fixture` + cleanup trap. Highest-risk item.
- **Guard #9 (helper-location duplication-over-extraction)** → if a VLAN-parse helper is introduced (Q1/A2), keep it single-consumer; do NOT generalize a shared parser for hypothetical future axes (rule-of-three not met).
- **Guard #6 (bpffs ≠ tmpfs)** → ctests load via the real loader and touch bpffs pins; reuse the established fixture teardown.
- Counts/depths in verifiable-invariants prose are operative-semantic (e.g. "depth ≤2"), not literal-match contracts; impl deviations mirroring existing precedent are `inline-merge`.
