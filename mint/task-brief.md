# Task brief — MVP-4.4: bit-vector axes 3-4 — proto (HASH) + dst_port (range) (rule-model S4, brownfield)

## Goal

Extend the now-production bit-vector AND classifier (landed in MVP-4.3 / §5.43) with **two more match axes**: **`proto`** (L4 protocol, exact-match HASH bitmask) and **`dst_port`** (L4 destination port, bounded range-scan). Each is a **spike-proven +1 axis** — the §5.42 prototype (`tests/bitvec/bitvec_proto.bpf.c`) already exercised all four axes (dst/src LPM, proto HASH, dst-port range); this slice transcribes the proto+port halves into the production datapath that mvp-4.3 built for dst/src.

After this slice the v2 AND grammar is `{dst_cidr, src_cidr, protocol, dst_port}` (≥1 required), composed: `acc = (dmask|wc_dst) & (smask|wc_src) & (proto_mask|wc_proto) & (port_mask|wc_port)`, first-match-by-`id` via `ffsll`. This is a **purely additive extension within schema_version 2** (no new cutover): existing v2 configs (dst/src only) keep parsing unchanged; the new keys are optional. `BITVEC_NUM_AXES` 2→4.

Anchors: `mint/design.md` §5.43 (the production structure this extends — map topology, wildcard ×2 swap, close_prefixes, ffsll, RESET-on-apply); §5.42 spike (the proto/port reference lowerings); `mint/architecture-rule-model.md` (catalog §9 axis-building, six-primitive target).

## Context: prior work

- **All prior briefs**: archived in `mint/task-brief-*.md` (this supersedes `mint/task-brief-mvp-4.3.md`).
- **Existing design**: `mint/design.md` §5.43 (MVP-4.3 — the bit-vector AND production landing: `dst_bitmask`/`cidr_allowlist` LPM axes, single combined `wildcard` ARRAY indexed `active*BITVEC_NUM_AXES+axis`, `first_set_u64`, `close_prefixes()` in loader, `rules_outer→action_table` dispatch, RESET-on-apply match maps). §5.42 (spike — `bv_proto_hash` exact HASH→u64, `bv_port_ranges` ARRAY of `bv_port_range{lo,hi,bit}` + `bitvec_port_scan` bounded unroll, TCP/UDP dport extraction with `has_port` logic).
- **Architecture doc**: `mint/architecture-rule-model.md` — proto+port are catalog axes; R.7 noted dst-port range → bounded scan (or prefix-LPM); the six-primitive target includes exact (proto) + range (port).
- **Spike reference (read-only template — guard #9, transcribe NOT #include)**: `tests/bitvec/bitvec_proto.bpf.c` (`bv_proto_hash` lookup `:272`, `bitvec_port_scan` `:146-164`, TCP/UDP dport extract `:251-267`, the 4-axis `acc` chain `:277-280`), `tests/bitvec/bitvec_proto.h` (`struct bv_port_range{u32 lo; u32 hi; u64 bit}`, `BITVEC_AXIS_PROTO=2`/`BITVEC_AXIS_PORT=3`), `tests/bitvec/bitvec_oracle.py` (the 4-axis O(N) oracle — port/proto match logic to extend the mvp-4.3 2-axis `bitvec_oracle_prod.py`).
- **Phase A code-grep verification**: brief author ran the greps in the Phase-2 report below (BITVEC_NUM_AXES=2, wildcard max_entries=4, kManagedMaps=21, VERSION=0.11.0, RuleMatch shape, v2 grammar gate, production datapath has NO L4 parse yet, `inject_l4.py` exists, XDPMF_RULESET_COUNT=2). See footer.
- **PI continuity**: PI-mvp-4.3-AND / -WILDCARD / -SCHEMA-V2 extend (now 4 axes); PI-mvp-4.3-COUNTER-PRESERVE + EXPORTER-AGNOSTIC CONTINUE unchanged; PI-7 config.hpp streak already ended (§5.43) — config.hpp gains 2 more optional fields. New maps (proto/port) are RESET-on-apply (guard #15, like dst/src). **No new schema_version cutover** (additive within v2) ⇒ NO MAC-style test-corpus ripple this slice — a much lighter cycle than mvp-4.3.

## Workflow rules (brownfield)

- **Architect**: read `design.md` §5.43 (the structure being extended — map topology, wildcard-index formula, `close_prefixes`, RESET-on-apply, FFS) + §5.42 (proto/port spike lowerings) + the brief. EDIT `design.md` in place; append **§5.44**. Resolve Q1–Q4 + HG defaults with Phase A grep evidence. Note: proto (exact) + port (range) do NOT need prefix-closure (that is LPM-only — dst/src); guard #23 does NOT extend to these axes (state this explicitly so reviewer doesn't demand a closure canary for proto/port).
- **Impl**: brownfield FileList DIFF (Write NEW, Edit EDITED, do NOT touch UNCHANGED-BUT-AFFECTED). Transcribe `bitvec_port_scan` + the proto HASH lookup into production-owned datapath code (guard #9 — do NOT `#include tests/bitvec/*`). Add L4 (TCP/UDP) header parse with verifier bounds-checks (the datapath has NONE today — new verifier surface; re-run the bpftool-load smoke). `BITVEC_NUM_AXES` 2→4 ripples the `wildcard` max_entries (4→8) + the loader wildcard-write loop + the datapath axis indices.
- **Tester**: extend the independent O(N) oracle to 4 axes (proto exact, port range membership). NEW tests for proto-AND, port-range-AND, full-4-axis compose, port-miss/proto-miss negation. The existing converted v2 corpus stays GREEN (additive grammar — dst/src-only fixtures unaffected). Reconcile baseline via fresh `ctest -N` (mvp-4.3 left it at 76).
- **Reviewer**: 5-point brownfield. Special attention: (a) L4 parse verifier-safety (bounds-checks on TCP/UDP headers — new code, the #1 new-bug surface); (b) port range-scan bounded (no unbounded loop; `#pragma unroll` like the spike); (c) proto/port maps ride `active_idx` atomic-swap (RESET, no copy-forward); (d) wildcard max_entries 4→8 + index formula `active*4+axis` correct for all 4 axes; (e) kManagedMaps arithmetic (21→27 expected); (f) additive-within-v2 (existing v2 configs still parse; NO schema_version bump); (g) close_prefixes UNCHANGED (still dst/src LPM only).

## Human-gate decisions (defaults applied — architect overrides at Phase A with evidence)

### HG-mvp-4.4-1: Axis set → **proto + dst_port (BOTH, this slice)**
Both are spike-proven and coupled via the same L4 header parse (you must parse TCP/UDP to get dport; proto reads `ip->protocol` directly). One slice avoids touching the datapath/grammar/lowering twice. `BITVEC_NUM_AXES` 2→4.

### HG-mvp-4.4-2: `dst_port` config grammar → **single port OR inclusive range "lo-hi"**
Default: a `dst_port` value is either a single port (`443`) or a range (`1000-2000`), parsed to a `{lo,hi}` pair (single ⇒ lo==hi). Range is the general case (the spike's `bv_port_range`). Architect picks the exact YAML scalar form + validation (port ∈ [0,65535], lo≤hi). Lists/multi-range → OOS (a rule = one range; multiple ranges = multiple rules).

### HG-mvp-4.4-3: `protocol` config grammar → **names {tcp, udp, icmp} (+ numeric fallback)**
Default: accept `tcp`→6, `udp`→17, `icmp`→1; optionally a raw numeric 0-255. Architect picks the canonical set + whether numeric is allowed. Exact-match (HASH), no ranges/wildcards beyond the axis-wildcard (rule omitting `protocol` ⇒ proto-wildcard).

### HG-mvp-4.4-4: schema_version → **STAYS 2 (additive, NO new cutover)**
The new keys are optional additions to the existing v2 AND grammar; v2 configs without them parse unchanged. No M.x migration, no v2→v3 bump, no fixture-wide ripple. (Contrast mvp-4.3's M.1 cutover.)

### HG-mvp-4.4-5: VERSION → **bump 0.11.0 → 0.12.0 + DESCRIPTION update**
New match capability (L4 proto + port). DESCRIPTION reflects the 4-axis AND. Propagate the literal per guard #11 (mvp-4.3 left only `T_EXPORTER_METRICS_FORMAT` pinning it). Architect picks exact bump.

### HG-mvp-4.4-6: Exporter → **UNCHANGED**
Still rule_id-keyed + axis-agnostic; `bump_rule(rid)` feeds the `ffsll` winner. Per-axis labels stay mvp-4.5. PI-mvp-4.3-EXPORTER-AGNOSTIC continues.

## Open mechanism questions (architect decides; document in §5.44)

### Q1: proto axis map topology
- **A1**: NEW `ARRAY_OF_MAPS[2]` of inner HASH (`proto_bitmask_a/_b` + `proto_rulesets`), inner key `__u32` proto, value `__u64` bitmask; rides `active_idx`. Mirrors the dst topology (§5.43 Q1).
- **A2**: a single combined indexed ARRAY (like `wildcard`) — but proto is a sparse keyed lookup, so HASH-inner is the natural fit.
- **Recommendation**: **A1** — HASH inner ×2 + outer, mirrors the established axis pattern; exact-match, NO prefix-closure. +3 kManagedMaps.

### Q2: dst_port axis map topology + scan
- **A1**: NEW `ARRAY_OF_MAPS[2]` of inner ARRAY (`port_ranges_a/_b` + `port_rulesets`), inner value `struct {u32 lo; u32 hi; u64 bit}` (production-owned analog of `bv_port_range`), `max_entries XDPMF_ALLOWLIST_MAX`; datapath does the spike's `bitvec_port_scan` bounded `#pragma unroll` (OR `bit` of every used slot whose `[lo,hi]` contains dport). +3 kManagedMaps.
- **A2**: encode port ranges as an LPM prefix-expansion (R.7 alt) — rejected: more complex, the spike proved the bounded scan works at N≤64.
- **Recommendation**: **A1** — transcribe the spike's range-scan; bounded unroll is 5.15-safe (like `l3_after_vlan`/`first_set_u64`). NO prefix-closure (ranges, not prefixes).

### Q3: L4 header parse in the datapath
- **A1**: after the existing IPv4 parse, read `ip->protocol`; if TCP/UDP, bounds-check + parse the L4 header for `dest` (dport, `bpf_ntohs`); non-TCP/UDP (ICMP/other) ⇒ `dport` absent ⇒ port axis contributes 0 (only port-wildcard rules survive) — exactly the spike's `has_port` logic. proto axis uses `ip->protocol` always (present for every IPv4 packet).
- **Recommendation**: **A1** (mirror spike `:251-267`). This is NEW datapath code (no L4 parse exists today) — the main new verifier surface; reviewer special-attention (a).

### Q4: wildcard growth + axis indices
- The single combined `wildcard` ARRAY max_entries `XDPMF_RULESET_COUNT*BITVEC_NUM_AXES` goes 4→8; new `BV_AXIS_PROTO=2`, `BV_AXIS_PORT=3`; datapath reads `wildcard[active*4+axis]` for all four; loader writes the inactive half's 4 axis slots. RESET-on-apply (guard #15, no copy-forward). Architect confirms the index formula holds for 4 axes.

## Scope (cycle S4 / mvp-4.4 — concrete items; estimates are UPPER BOUNDS)

### Item S4-1 — config grammar + parse (proto + dst_port)
**Where**: `src/lib/config.cpp`, `src/lib/config.hpp`
- `RuleMatch` gains `std::optional<...> protocol` + `std::optional<...> dst_port` (architect picks the value types — e.g. `std::optional<std::uint8_t> protocol`, `std::optional<PortRange> dst_port{lo,hi}`).
- v2 grammar accepted-key set `{dst_cidr, src_cidr}` → `{dst_cidr, src_cidr, protocol, dst_port}` (config.cpp:230); at-least-one-of stays (now any of 4); parse + validate per HG-2/HG-3.

### Item S4-2 — datapath 4-axis AND + L4 parse
**Where**: `src/bpf/mac_filter.bpf.c`
- ADD `proto_bitmask_a/_b`+`proto_rulesets` (HASH inner, Q1) + `port_ranges_a/_b`+`port_rulesets` (ARRAY inner, Q2) map decls; `wildcard` max_entries 4→8.
- ADD L4 parse (Q3) + the production `port_scan` helper (transcribe `bitvec_port_scan`, guard #9, bounded unroll).
- EXTEND `acc` chain: `&= (proto_mask|wc[active*4+2]) & (port_mask|wc[active*4+3])`. `first_set_u64`/dispatch/`bump_rule`/defaults UNCHANGED. `BV_AXIS_PROTO=2`/`PORT=3` in mac_filter.h.

### Item S4-3 — loader: lower proto + port axes
**Where**: `src/lib/loader.cpp`, `src/common/mac_filter.h`
- NEW `XDPMF_MAP_*_NAME` constants (proto trio + port trio); `BITVEC_NUM_AXES` 2→4 (mac_filter.h); `kManagedMaps[]` 21→27 (+6: proto_bitmask_a/_b, proto_rulesets, port_ranges_a/_b, port_rulesets).
- Lower `Config::rules` → proto HASH bitmask (exact, NO closure) + port range slots ({lo,hi,bit}) + extend the wildcard-write to 4 axes; RESET-write inactive inners before the single `active_idx` flip. `close_prefixes()` UNCHANGED (dst/src LPM only). `copy_rule_counters_forward` UNCHANGED.

### Item S4-4 — VERSION bump + DESCRIPTION + literal propagation
**Where**: `CMakeLists.txt` + `T_EXPORTER_METRICS_FORMAT` (the one version-pinning test, guard #11).

### Item S4-5 — sidecar (if it emits match objects)
**Where**: `src/lib/sidecar.cpp` — if the sidecar JSON emits per-rule match keys (it emits dst_cidr/src_cidr per §5.43 C1), extend to emit `protocol`/`dst_port`. Architect/impl verify via grep whether sidecar enumerates match axes (likely EDITED, mirroring the mvp-4.3 C1 finding).

### Item S4-6 — tests: 4-axis oracle + new vectors
**Where**: `tests/` (NEW T_PROTO_*/T_PORT_*/4-axis compose), `tests/bitvec/bitvec_oracle_prod.py` (extend to 4 axes), fixtures (NEW v2 configs with protocol/dst_port), `tests/CMakeLists.txt`. Existing v2 corpus stays green (additive). `inject_l4.py` (exists) injects TCP/UDP with dport. `RESOURCE_LOCK xdp_fixture` (guard #12).

## Out of scope (explicit)
- **Exporter per-axis labels; MAC-axis return** — mvp-4.5 (the frozen MAC maps re-shape into a bit-vector axis there). NEW FENCE.
- **dst_port lists / multiple ranges per rule** — one range per rule this slice (multi = multiple rules). NEW FENCE.
- **`src_port`, ICMP type/code, proto ranges** — not in the six-primitive near-term target; later if needed. NEW FENCE.
- **IPv6 `cidr6`; VLAN-as-match; feed-objects; N>64; most-specific-wins; sequential lowering** — later slices (carry §5.42/§5.43 fences). NEW FENCE.
- **schema_version v2→v3** — this slice is additive within v2; no cutover. NEW FENCE.
- **Non-eBPF datapath / 40 Gbps line-rate** — deferred per [[real-requirements-and-strategy]].
- Carry-forward §5.41/§5.42/§5.43 OOS items not superseded — UNCHANGED.

## Definition of done
- §5.44 amendment appended to `mint/design.md` (Phase A grep report + HG/Q resolutions + the proto/port lowering notes + new PIs).
- **PIs**: NEW PI-mvp-4.4-PROTO (exact HASH axis), PI-mvp-4.4-PORT (range-scan axis, bounded), PI-mvp-4.4-L4PARSE (TCP/UDP parse verifier-safe; non-TCP/UDP → port-wildcard only); PI-mvp-4.3-AND/-WILDCARD/-SCHEMA-V2 extended to 4 axes; PI-mvp-4.3-COUNTER-PRESERVE + EXPORTER-AGNOSTIC + close_prefixes-UNCHANGED CONTINUE.
- ctest baseline = **76** (mvp-4.3 left it here; tester reconciles via fresh `ctest -N`) + NEW proto/port/4-axis tests; existing v2 corpus stays green (additive — confirm zero conversions needed).
- VERSION 0.11.0 → 0.12.0, literal propagated.
- impl Phase 2.5 bpftool-load smoke rc=0 (new L4 parse + 4-axis acc verifies on the 5.15 floor).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang-19 / libbpf / CMake; `bpftool` for ctest map dumps; `inject_l4.py` (exists) for TCP/UDP injection.
- Runtime: `bpf()` HASH + ARRAY + ARRAY_OF_MAPS (all used); `__builtin_ffsll` (proven §5.42/§5.43); bounded `#pragma unroll` port-scan (5.15-safe, mirrors `l3_after_vlan`).
- Platform: passwordless sudo for XDP/veth/bpffs ctests.

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
- **One-sentence goal**: add proto (exact HASH) + dst_port (bounded range-scan) as bit-vector axes 3-4 on the mvp-4.3 production AND structure, additive within schema_version 2.
- **Multi-axis design space?** NO — the structure is RESOLVED (bit-vector, landed §5.43) and the spike (§5.42) already proved both new axes' lowerings. Q1–Q4 are architect-tier mechanism picks with clear spike-anchored defaults. `/mint-hld` NOT needed.
- **Mechanical?** YES — "transcribe the spike's proto/port halves into the production structure + extend the grammar." Single-architect via `/mint-dev`.
- **Scope-size**: moderate, ONE coherent slice (proto+port coupled via L4 parse). Smaller than mvp-4.3 (no structural pivot, no schema cutover, no MAC-removal ripple — additive only). No split.
- **Overconfidence check**: production datapath has NO L4 parse today (grep-verified) — the new TCP/UDP parse + bounds-checks are genuinely NEW verifier surface (the main new-bug risk), flagged as reviewer special-attention (a), not assumed-trivial. kManagedMaps=21 / BITVEC_NUM_AXES=2 / wildcard=4 all grep-verified (not memory).

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author ran these (Phase 2). Architect re-verifies independently + extends:
- `grep -nE 'BITVEC_NUM_AXES|BV_AXIS_|XDPMF_MAP_WILDCARD' src/common/mac_filter.h` (=2; DST=0/SRC=1; wildcard name).
- `grep -nE 'wildcard|BITVEC_NUM_AXES|RULESET_COUNT' src/bpf/mac_filter.bpf.c` (wildcard max_entries=RULESET_COUNT*NUM_AXES=4; index `active*2+axis`).
- `sed -n '/kManagedMaps/,/};/p' src/lib/loader.cpp` (21 entries — confirm before/after delta = +6).
- `grep -nE 'dst_cidr|src_cidr|"mac"|not supported' src/lib/config.cpp` (v2 grammar gate at :218-243 — accepted-key set to extend).
- `grep -nE 'tcphdr|udphdr|IPPROTO|->dest|l4' src/bpf/mac_filter.bpf.c` (CONFIRM: production datapath has NO L4 parse — this slice adds it).
- `grep -nE 'schema_version|dst_cidr|src_cidr' src/lib/sidecar.cpp` (does sidecar enumerate match axes? → likely EDITED for protocol/dst_port, mirroring §5.43 C1).
- `grep -rn '0\.11\.0' CMakeLists.txt tests/ docs/ CHANGELOG.md` (VERSION propagation surface).
- spike reference: `tests/bitvec/bitvec_proto.bpf.c` (`bitvec_port_scan`, proto HASH lookup, TCP/UDP dport extract), `bitvec_proto.h` (`bv_port_range`).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #5 (Phase A code-grep)** — always; architect repeats independently.
- **Guard #9 (helper duplication-over-extraction)** — transcribe `bitvec_port_scan` + proto lookup into production-owned code; do NOT `#include tests/bitvec/*`.
- **Guard #10 (catalog arithmetic)** — `kManagedMaps[]` 21→27 (+6); `wildcard` max_entries 4→8; `BITVEC_NUM_AXES` 2→4. State EXACT counts; load-bearing.
- **Guard #11 (VERSION-bump test-literal propagation)** — applies (HG-5); grep every `0.11.0`.
- **Guard #12 (RESOURCE_LOCK for shared host state)** — new datapath ctests take `RESOURCE_LOCK xdp_fixture` + cleanup trap.
- **Guard #15 (stateful-map PRESERVE-vs-RESET)** — NEW proto/port maps + grown wildcard are **RESET-on-apply** (no copy-forward); `rule_counters` stays PRESERVE (`copy_rule_counters_forward` UNCHANGED). Same as the mvp-4.3 dst/src axes.
- **Guard #23 (prefix-closure / overlap-vector)** — **does NOT extend to proto/port** (exact + range, NOT LPM — no closure). It STILL applies to the dst/src LPM axes (unchanged from §5.43). Architect states this explicitly so reviewer doesn't demand a proto/port closure canary; the §6.62 dst/src closure canary stays green.
- **Guard #24 (config-surface narrowing + schema-bypass)** — N/A this slice (additive, no axis removed, no cutover; `attach --allow` still synthesizes a frozen-MAC config, already SKIP-fenced in §5.43).
- **Operative-semantic discipline**: counts/sizes in §5.44 verifiable-invariants (kManagedMaps=27, wildcard=8, BITVEC_NUM_AXES=4 are load-bearing MUST; ctest delta, PI numbering are SHOULD) — impl deviations mirroring precedent / structural-symmetry fixtures are `inline-merge`.
