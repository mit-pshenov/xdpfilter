# Task brief — MVP-4.3: production OR→AND pivot, axis-1 (dst_ip + src_cidr bit-vector) (rule-model S3, brownfield, structural)

## Goal

Land the **proven bit-vector AND-classification structure** (spike MVP-4.2, §5.42, verdict ADOPT) into the **production datapath** — the OR→AND structural pivot the whole rule-model is built toward. This is the realization of HLD Wave-B Option 3's structure-landing step (`mint/architecture-rule-model.md` §Recommendation), on the structure the spike de-risked end-to-end (`tests/bitvec/`: `close_prefixes()`, `ffsll` FEAS, range-scan, per-axis wildcard).

**Scope is the MINIMAL coherent pivot (PO decision 2026-05-29 "split по осям"):** two LPM axes only — **`dst_ip`** (the #1 selection gap, NEW) **AND `src_cidr`** (reshaped from today's OR axis) — composed with bit-vector intersection. This ships the two headline wins in one cycle (the dst-IP feature **and** the OR→AND pivot) at the smallest possible structural delta. `proto` + `dst_port` axes follow in **mvp-4.4** (each is a spike-proven +1 axis on the now-production structure); exporter axis-labels + MAC-axis follow in **mvp-4.5**.

Anchors: HLD `mint/architecture-rule-model.md` Option 1/Option 3 first-slice scope; `mint/design.md` §5.42 §7 OOS (the explicit S3 enumeration); spike reference under `tests/bitvec/`.

## Context: prior work

- **All prior briefs**: archived in `mint/task-brief-*.md` (this one supersedes `mint/task-brief-mvp-4.2.md`, the spike brief).
- **Existing design**: `mint/design.md` §5.41 (MVP-4.1 VLAN parse-fix — `l3_after_vlan`, the tagged-frame L3 reach this slice's axes ride) + §5.42 (MVP-4.2 bit-vector spike — the structure being productionized; §7 OOS enumerates exactly this slice's mandate).
- **Architecture doc**: `mint/architecture-rule-model.md` — Option 1 "Stay-course bit-vector" first-slice scope + Option 3 IR-first foundation; OR→AND = structure change (`mac_filter.bpf.c:342`/`:393` are the OR dispatch branches being replaced).
- **Spike reference (NOT production — read-only template)**: `tests/bitvec/bitvec_proto.bpf.c` (datapath: `acc &= (mask|wildcard)` × axes → `ffsll`), `tests/bitvec/bitvec_proto.h` (axis enum, `bv_cidr_v4` LPM key, `bv_port_range`), `tests/bitvec/bitvec_harness.cpp` (`close_prefixes()` at :107 — the FI-1 prefix-closure algorithm to port to the production loader), `tests/bitvec/bitvec_oracle.py` (independent O(N) scan — reuse pattern for the tester's oracle).
- **Phase A code-grep verification**: brief author ran the greps in the Phase-2 report below (FileList paths, `Config::Rule`/`RuleMatch` shape, `kManagedMaps[]` count=17, VERSION=0.10.0, `schema_version` gate, v1 fixtures, exporter rule_id-keying). See "Notes for architect" footer.
- **PI continuity — IMPORTANT BREAK**: the **PI-7 `config.hpp` ZERO-diff streak ENDS this slice** (config.hpp MUST gain `dst_cidr` + schema_version:2 logic — unavoidable for v2 AND-features; this was foreseen in §5.42). The `loader.hpp` ZERO-diff streak likely also ends (new map-fd accessors). This is expected and correct, not a regression — document the streak-end explicitly in design §5.43.

## Workflow rules (brownfield)

- **Architect**: read `design.md` §5.41 + §5.42 (incl. §7 OOS + the FI-1..FI-7 enumeration + D-mvp-4.2-* decisions) + §5.26/§5.27 (the `active_idx` / `defaults[active_idx]` / `cidr_rulesets` atomic-swap precedent this slice extends) + §5.31/§5.34 (`rules_outer→action_table` dispatch chain reused for action lookup) + `architecture-rule-model.md`. EDIT `design.md` in place; append **§5.43**. Resolve Q1–Q4 + the HG defaults with Phase A grep evidence.
- **Impl**: FileList interpretation per brownfield mode (EDIT existing in place; NEW only where named). Port `close_prefixes()` from the spike harness into the production loader — do NOT `#include` the prototype header (guard #9, do NOT share prototype code; re-implement/transcribe into production types). New production first-set helper is the production's own (guard #9), with the `ffsll` default + `-D…_FALLBACK` bounded-unroll alternate per D-mvp-4.2-FFS.
- **Tester**: reuse the spike's independent-oracle pattern (naive O(N) scan, no bitmask/closure logic) for the AND-compose agreement test. **Guard #23 MANDATORY**: at least one overlapping-prefix vector where a less-specific covering rule has a LOWER `id` (higher priority) than the more-specific entry — proves prefix-closure cover-direction. Adapt the OR-era tests (see Scope S3-6).
- **Reviewer**: 5-point brownfield framework. Special attention: (a) prefix-closure correctness in the production loader (FI-1 — the #1 bit-vector trap); (b) wildcard ×2 atomic-swap actually rides `active_idx` (FI-7 — the layer the spike deferred); (c) M.1 hard-cutover rejects v1 cleanly; (d) no MAC-matching silently survives the cutover unfenced; (e) `kManagedMaps[]` count arithmetic exact (guard #10); (f) VERSION-literal propagation complete (guard #11).

## Human-gate decisions (defaults applied — architect overrides at Phase A with evidence)

### HG-mvp-4.3-1: Axis set for this slice → **`dst_ip` + `src_cidr` (2 LPM axes) ONLY**
PO "split по осям" (2026-05-29). `proto` (HASH) + `dst_port` (range-scan) → mvp-4.4; MAC-axis, IPv6, VLAN-as-match, feed-objects → later. Smallest coherent OR→AND pivot; both axes are LPM so one lowering primitive this slice.

### HG-mvp-4.3-2: MAC matching under v2 → **DEFERRED, fenced as intentional narrowing (NOT a regression)**
Today's MAC HASH axis (`allowlist`/`rulesets`) is a v1 OR-axis. v2's match grammar is `dst_ip` + `src_cidr` only; MAC-axis returns in a later slice (§5.42 OOS). Since M.1 hard-rejects v1 at load, there is **no live MAC matching after cutover** until the MAC-axis slice — this is a deliberate semantic narrowing of the *config surface*, documented as a NEW PI in §5.43 (cite the §5.42 OOS fence verbatim). **Architect decides**: physically retire the MAC maps (`allowlist_a/_b`, `rulesets`) from `kManagedMaps[]` + datapath, OR keep them pinned-but-unconsulted (frozen). Recommendation: keep pinned-but-unconsulted this slice (smaller diff, no retired-pin-name ripple — guard #16) and retire in the MAC-axis slice when they're re-shaped; architect overrides if frozen-dead-maps offend more than the ripple.

### HG-mvp-4.3-3: Migration → **M.1 hard cutover (`schema_version: 2` only)**
The supported set flips `{1}` → `{2}`. Loader/config **hard-reject** `schema_version: 1` (and absent⇒default) at load with a "re-author to schema_version 2" diagnostic. PO-confirmed safe (0 deployments). v1 fixtures rewritten to v2 (Scope S3-6).

### HG-mvp-4.3-4: Ordering → **first-match-by-`id` (S.1)**
`id` = bit position in `[0, XDPMF_ALLOWLIST_MAX-1]`; `ffsll(acc)-1` yields the lowest-`id` survivor for free. most-specific-wins (S.3) is a future loader sort-key change (OOS).

### HG-mvp-4.3-5: Exporter → **UNCHANGED this slice**
The bit-vector still produces a `rule_id` (the `ffsll` winner) and `bump_rule(rid, active)` keeps the existing `rule_counters` PERCPU semantics. The exporter reads `rule_counters` keyed by `rule_id` (`rule_counters_reader.hpp:25`) — agnostic to which axes matched — so it keeps working with **zero edits**. New per-axis labels → mvp-4.5. (Verify: `bump_rule` is fed the `ffsll` `rid`, preserving the PI-3.4d PRESERVE-across-apply counter contract — guard #15 below.)

### HG-mvp-4.3-6: VERSION → **bump (minor) + DESCRIPTION update**
v2 AND-compose is a real user-facing capability. Default 0.10.0 → **0.11.0**; DESCRIPTION "OR-compose" → "AND-compose (dst-IP + src-CIDR bit-vector)". Propagate to test literals (guard #11). Architect picks exact bump.

## Open mechanism questions (architect decides; document in §5.43)

### Q1: Per-axis bitmask map topology (dst NEW vs src reshape)
- **A1**: `dst_ip` = **NEW** `ARRAY_OF_MAPS[2]` LPM axis (`dst_bitmask_a/_b` + `dst_rulesets` outer), inner value `__u64`; `src_cidr` = **reshape** the existing `cidr_allowlist_a/_b` inner VALUE `struct allow_entry` → `__u64` bitmask (topology + pin names unchanged, value-type change only).
- **A2**: both as fresh parallel axes; retire `cidr_allowlist`'s match role.
- **Recommendation**: **A1** — smallest delta, reuses `cidr_rulesets` topology + the §5.27 LPM precedent; the src reshape mirrors the §5.31 `__u8 present`→`struct allow_entry` value-evolution precedent. `kManagedMaps[]` grows +3 (dst trio) → 20, before Q2.

### Q2: Wildcard / aux-mask atomic-swap placement (the FI-7 layer the spike deferred)
- **A1**: parallel **`ARRAY[2]`** per the `defaults[active_idx]` precedent — `wildcard` as two flat `ARRAY[BITVEC_NUM_AXES=2]` of `__u64` (`wildcard_a/_b`), indexed by the SAME `active_idx`. A single `active_idx` u32 store commits the swap for match-maps AND wildcards together.
- **A2**: fold the wildcard into a reserved sentinel entry inside each axis map.
- **Recommendation**: **A1** — mirrors `defaults` verbatim (§5.26, proven atomic-swap shape); the spike used a single non-swapped slot **precisely because the swap was deferred to here** (`bitvec_proto.bpf.c:60` D-mvp-4.2-WILDCARD). `kManagedMaps[]` +2 (`wildcard_a/_b`) → ~22.

### Q3: Prefix-closure recompute location
- **A1**: port `close_prefixes()` (spike harness `bitvec_harness.cpp:107`) into the **production loader** — recompute the OR-closed bitmask per LPM entry per `apply -f`, store into the inactive inner before the `active_idx` flip.
- **A2**: compute closure in `config.cpp` at IR-emit time.
- **Recommendation**: **A1** — closure is a *lowering* detail (depends on bitmask width + map shape), belongs **below** the Rule IR boundary (C.4), i.e. in the loader, keeping the IR portable + structure-agnostic.

### Q4: Rule IR (`NormalizedRule`) — distinct type vs sorted `Config::Rule`
- **A1**: `config.cpp` emits a lightweight ordered `NormalizedRule` list (structure-agnostic: `{id, action, dst_cidr?, src_cidr?}`, sorted by `id`) as the C.4 portability boundary + where first-match-by-`id` lives; loader lowers it to bitmask maps.
- **A2**: skip a distinct type — the sorted `Config::Rule` vector + the in-loader bitmask table together *are* the IR (realizability noted "the in-map table IS the portable IR").
- **Recommendation**: **architect's call** — the IR's *job* (ordered, structure-agnostic rule list above the lowering boundary, first-match-by-`id` sort) is what's load-bearing, not a new type per se. Prefer the lightest thing that names the boundary; don't over-abstract (the mvp-4.1 rescope retired premature Rule-IR abstraction for exactly this reason — only build it now that v2 AND-features make it real).

## Scope (cycle S3 / mvp-4.3 — concrete items; estimates are UPPER BOUNDS)

### Item S3-1 — v2 config schema + parse + M.1 cutover
**Where**: `src/lib/config.cpp`, `src/lib/config.hpp`
- `RuleMatch` (config.hpp:36) gains `std::optional<xdpmf_cidr_v4> dst_cidr;` (`src_cidr` already exists at :38; MAC stays but is rejected/ignored under v2 per HG-2).
- `schema_version` gate (config.cpp:152-159): supported `{1}`→`{2}`; reject v1 + absent with re-author diagnostic (M.1).
- v2 match-key grammar: `dst_ip` (+ existing `src_cidr`); the "match type not supported in schema_version 1" path (config.cpp:240) inverts to the v2 grammar. Architect fixes exact key names/validation.
- first-match-by-`id` sort at load (HG-4).

### Item S3-2 — Rule IR emission (per Q4)
**Where**: `src/lib/config.cpp` (+ `config.hpp` if A1 distinct type)

### Item S3-3 — bit-vector AND datapath (the OR→AND pivot)
**Where**: `src/bpf/mac_filter.bpf.c`
- Replace the independent MAC + src-CIDR OR dispatch (the `allow_entry` lookup ~:392 + `cidr_hit` ~:451 branches) with: per-axis `__u64` bitmask lookup → `acc = (lpm_dst(daddr)|wc[DST]) & (lpm_src(saddr)|wc[SRC])` → `rid = first_set(acc)-1` → existing `rules_outer[active]→action_table[action_id]` dispatch + `bump_rule(rid, active)`. Reuse `l3_after_vlan` (§5.41), the `active_idx` head-read (:364), the dispatch chain.
- NEW production first-set helper (own; ffsll default + bounded-unroll fallback per D-mvp-4.2-FFS).
- Map decls: NEW dst LPM `ARRAY_OF_MAPS[2]`; `cidr_allowlist` inner value `allow_entry`→`__u64` (Q1); NEW `wildcard` ×2 (Q2).

### Item S3-4 — loader + maps + names
**Where**: `src/lib/loader.cpp`, `src/common/mac_filter.h`
- NEW `XDPMF_MAP_*_NAME` constants (dst bitmask trio + wildcard pair); `kManagedMaps[]` (loader.cpp:154, **currently 17**) grows to ~22 (guard #10 — exact arithmetic per architect; this is a SHOULD-level estimate).
- Port `close_prefixes()` into the loader (Q3); per-apply bitmask + wildcard population; wildcard ×2 swap rides `active_idx`.

### Item S3-5 — VERSION bump + DESCRIPTION + test-literal propagation
**Where**: `CMakeLists.txt` (VERSION 0.10.0→0.11.0, DESCRIPTION), + every test asserting the version string (guard #11 — grep `0\.10\.0` across tests/docs/CHANGELOG).

### Item S3-6 — fixture rewrite (v1→v2) + ctest adaptation + NEW AND tests
**Where**: `tests/fixtures/config_valid_*.yaml`, `tests/T_*.sh`, `tests/CMakeLists.txt`
- Valid-config fixtures → `schema_version: 2` + v2 grammar. `config_malformed_schema.yaml` semantics updated to the new unsupported-version.
- OR-era tests: `T_PASS_MAC_OR_CIDR` (MAC-axis gone in v2 → retire/convert); `T_PASS_CIDR*` adapt to AND-compose; `T_DROP_CIDR_NOT_IN_RANGE`, atomic-swap CIDR tests adapt to the bitmask value.
- NEW: AND-compose agreement test vs an independent O(N) oracle (spike pattern) + **guard #23 overlapping-prefix lower-id vector** + dst_ip-specific PASS/DROP. `RESOURCE_LOCK xdp_fixture` (guard #12).

## Out of scope (explicit)
- **`proto` (HASH) + `dst_port` (range-scan) axes** — mvp-4.4 (+1 spike-proven axis each). NEW FENCE.
- **Exporter per-axis labels; MAC-axis (re-add as bit-vector axis)** — mvp-4.5. NEW FENCE.
- **IPv6 `cidr6` LPM_TRIE axis; VLAN-as-match-field; feed-objects; N>64 multi-word bitmask** — later slices (carry §5.42 fences). NEW FENCE.
- **most-specific-wins ordering (S.3)** — future loader sort-key. NEW FENCE.
- **Sequential lowering** — the documented escape hatch; NOT built (bit-vector ADOPTED). NEW FENCE.
- **Non-eBPF (DPDK/AF_XDP) datapath; 40 Gbps line-rate** — deferred per [[real-requirements-and-strategy]].
- Carry-forward §5.41/§5.42 OOS items not superseded above — UNCHANGED.

## Definition of done
- §5.43 amendment appended to `mint/design.md` (Phase A grep report + HG/Q resolutions + FI-1/FI-7 production-landing notes + the new PIs).
- **PIs**: NEW PI for AND-compose datapath semantic; NEW PI for M.1 `schema_version:2` cutover; NEW PI for v2 schema/`dst_cidr`; NEW PI for MAC-matching-deferred narrowing (HG-2); PI-3.4d PRESERVE-across-apply counter contract CONTINUES (guard #15). **PI-7 config.hpp ZERO-diff streak documented as ENDED** (expected).
- ctest baseline = **58** (`build-asan` `ctest -N`; build may predate the §5.42 spike ctests — tester reconciles with a fresh `ctest -N` at Phase 2.5) + NEW AND/closure tests; OR-era tests converted, not silently dropped.
- VERSION 0.10.0 → 0.11.0 with literal propagation complete.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: existing clang-19 / libbpf / CMake toolchain; `bpftool` for ctest map dumps.
- Runtime: `bpf()` LPM_TRIE + ARRAY_OF_MAPS + PERCPU_ARRAY (all already used); `__builtin_ffsll` (D-mvp-4.2-FFS confirmed inlined on the 5.15 verifier floor in the spike).
- Platform: passwordless sudo for XDP/veth/bpffs ctests (available).

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
- **One-sentence goal**: land the spike-proven bit-vector AND structure into the production datapath on two LPM axes (dst_ip + src_cidr), with v2 schema + M.1 cutover.
- **Multi-axis design space?** NO — the structure decision (bit-vector) is RESOLVED (HLD Wave-B Option 3 + spike ADOPT verdict, PO-confirmed). Remaining choices (Q1–Q4) are architect-tier Phase A mechanism picks with clear lowest-cost defaults, not a design-space exploration. `/mint-hld` NOT needed.
- **Mechanical?** YES — the answer falls out of the spike + the HLD Option-1 first-slice scope + the §5.42 §7 OOS S3 enumeration. Single-architect via `/mint-dev` handles it.
- **Scope-size guard**: full S3 (all 4 axes + exporter) was too big for one cycle → PO split "по осям" (2026-05-29); this brief is the MINIMAL pivot (2 axes). proto/port → mvp-4.4, exporter/MAC → mvp-4.5.
- **Overconfidence check**: PI-7 config.hpp ZERO-diff streak WILL break (verified unavoidable — v2 needs `dst_cidr` + schema gate); flagged, not assumed-away. `kManagedMaps[]`=17 grep-verified (not memory).

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author already ran these (Phase 2). Architect re-verifies independently + extends:
- `grep -nE 'struct (Rule|RuleMatch)' src/lib/config.hpp` (RuleMatch:36, Rule:41 — `src_cidr` present, `dst_cidr` absent).
- `sed -n '/constexpr ManagedMapEntry kManagedMaps/,/};/p' src/lib/loader.cpp` (17 entries — confirm before/after delta).
- `grep -nE 'schema_version' src/lib/config.cpp` (gate at :152-159, :240 unsupported-match path, :296 unknown-key path).
- `grep -nE 'cidr_hit|allow_entry|active_idx|l3_after_vlan|bump_rule' src/bpf/mac_filter.bpf.c` (OR dispatch :392/:451, the chain + `active_idx` head-read :364 to preserve).
- `grep -rn '0\.10\.0' CMakeLists.txt tests/ docs/ CHANGELOG.md` (VERSION propagation surface).
- `grep -rln 'schema_version\|src_cidr\|CIDR\|MAC_OR_CIDR' tests/` (fixture + ctest ripple surface for S3-6).
- `rule_counters_reader.hpp` / `prom_format.cpp` — confirm exporter is rule_id-keyed + axis-agnostic (HG-5 zero-edit claim).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #5 (Phase A code-grep)** — always; architect repeats this brief's greps independently.
- **Guard #9 (helper duplication-over-extraction)** — DO NOT `#include`/share the prototype (`tests/bitvec/*`) into production; transcribe `close_prefixes()` + first-set into production types as production-owned code.
- **Guard #10 (catalog arithmetic)** — `kManagedMaps[]` 17→~22; state the EXACT count + each new row; counts here are SHOULD-level (operative-semantic), not literal contracts.
- **Guard #11 (VERSION-bump test-literal propagation)** — applies (HG-6); grep every `0.10.0` site.
- **Guard #12 (RESOURCE_LOCK for shared host state)** — every new datapath ctest takes `RESOURCE_LOCK xdp_fixture` + cleanup trap.
- **Guard #15 (stateful-map PRESERVE-vs-RESET)** — the NEW match maps (dst/src bitmask) + wildcard ×2 are **RESET-on-apply** (reflect current config only) → atomic-swap shape ALONE is correct, **no copy-forward needed**. `rule_counters` stays **PRESERVE-across-apply** (PI-3.4d, `copy_rule_counters_forward` UNCHANGED). Do not confuse the two.
- **Guard #16 (retired pin-path / map-name ripple)** — IF the architect retires MAC maps (HG-2 A2 path) or renames `cidr_allowlist`, grep test bodies dumping those pins; pre-list as EDITED. (Recommendation HG-2 keeps MAC pinned-but-unconsulted to AVOID this ripple.)
- **Guard #22 (L2-mutation test vacuity)** — if any new vector uses `--vlan`, disable NIC VLAN offload in setup.
- **Guard #23 (bit-vector prefix-closure / overlap-vector mandate)** — MANDATORY: ≥1 overlapping-prefix vector where a less-specific covering rule has a LOWER `id` than the more-specific entry (proves closure cover-direction); pair with the independent O(N) oracle. This is the #1 bit-vector bug class — the spike's V1 vector is the reference mechanism.
- **Operative-semantic discipline**: counts/sizes in §5.43 verifiable-invariants (kManagedMaps delta, ctest delta, new-PI numbering) are SHOULD-level orientation for the reviewer's greps, not literal-match assertions; impl deviations mirroring precedent / adding fixtures for structural symmetry / retirement-citation comments are `inline-merge`.
