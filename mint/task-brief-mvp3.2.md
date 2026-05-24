# Task brief — MVP-3.2: L3 src-CIDR rule type (brownfield)

## Goal

Extend MVP-3.1's `config-first foundation` harness with **L3 src-CIDR matching as a new in-config rule type**. Per `mint/architecture-v2.md` MVP-3.2 row: this is the first extension *within* the config-driven path (NOT as a CLI flag — that path was deliberately rejected during architecture round-2 rework to avoid throwaway surface).

The slice adds 4 pieces:

1. **BPF datapath** — `cidr_allowlist_*` LPM_TRIE maps + `xdpmf_cidr_v4` key type + OR-compose with MAC match in `mac_filter_prog`. Per design Q1 (architect), the existing `ARRAY_OF_MAPS` atomic-swap mechanism extends to both MAC + CIDR consistently.
2. **Config schema** — `RuleMatch` gains optional `cidr` field (e.g., `match: {cidr: "10.0.0.0/8"}`); validator accepts a rule with `mac` only, `cidr` only, or BOTH (OR-semantic within a single rule — first match wins). `xdpmf_subset` YAML parser already accepts arbitrary string scalars per HG1 grammar, so no parser changes (only validator).
3. **Apply orchestrator** — `internal::apply_request` extends to populate both `mac_allowlist_*` and `cidr_allowlist_*` inner slots atomically.
4. **Counter + tests** — new `STAT_PASS_CIDR` PERCPU_ARRAY index (per §5.23 pattern) incremented when the CIDR axis matched (not MAC). 3 ctests minimum: `T_PASS_CIDR`, `T_DROP_CIDR_NOT_IN_RANGE`, `T_PASS_MAC_OR_CIDR` (the OR-compose verification per risk-register MVP-3.2 row 2 mitigation).

**IPv4 only for cycle 1** — IPv6 LPM_TRIE shape (128-bit key) is fenced to MVP-3.2.5 or later. If product owner wants v4+v6 in this cycle, escalate at human-gate; default is v4-only.

Estimated budget per `architecture-v2.md` per-phase scope summary: ~1 cycle, ~120-180 LOC source + ~80 LOC test, **3-5 ctests**. Smaller than MVP-3.1 (config harness is built; this slice extends it).

## Context: prior work

- **All prior briefs**: `mint/task-brief-mvp1{,.1a,.1b,.1c}.md` + `mint/task-brief-mvp2-{sec,perf,robust,polish2}.md` + `mint/task-brief-mvp3.1.md`.
- **Existing design**: `mint/design.md` — §5.26 (MVP-3.1 config harness) is the immediate ancestor; §6.21-§6.27 TestStrategy is the pattern this slice extends; §6.5 PI-1..PI-14 invariants must continue to hold; §4.1 exit-code table currently active through row 9 `ConfigError`.
- **Architecture document**: `mint/architecture-v2.md` —
  - **MVP-3.2 dependency graph row**: lines 215-223 (concise scope sketch).
  - **MVP-3.2 per-phase scope summary**: line 310.
  - **MVP-3.2 risk register**: lines 333-334 — 2 risks named (atomic swap consistency across MAC+CIDR inner maps; OR-compose UX surprise).
- **MVP-3.1 review**: `mint/review.md` — round-1 pass with 4 deferred OOT items; 2 are "housekeeping" candidates this slice could opportunistically tackle if scope allows (architect decides per Q5 below).
- **MVP-3.1 deviations**: `mint/impl-notes.md` D-3.1-1..D-3.1-4 are the legacy carry-overs (apply_internal.hpp internal helper, ${PIN_DIR}/allowlist alias, file-IO→CliError, reuse_fd state-b) — all stand; do NOT undo any.

## Workflow rules (brownfield mode)

- **Architect**: read existing `design.md` (focus §5.26 — your harness contract; §6.21-§6.27 — your TestStrategy pattern; §4.1 — you may add row 10 if a new exit code is warranted, OR confirm `ConfigError = 9` covers CIDR validation failures too; §6.5 — extend PI table for MVP-3.2 invariants) + `architecture-v2.md` MVP-3.2 rows + this brief. EDIT `design.md` in place. Append `§5.27 MVP-3.2: L3 src-CIDR rule type` after §5.26. Add new §6.x TestStrategy entries for the 3-5 new ctests. Update §6.5 Preserved invariants for MVP-3.2 (PI-1..PI-14 from MVP-3.1 must continue + new PIs for CIDR axis). Update §7 OOS — move MVP-3.2 components from deferred to shipped; surface what's NEXT (MVP-3.3 systemd / MVP-3.4 per-rule counters).
- **Impl**: EDIT `src/bpf/mac_filter.bpf.c` (add LPM_TRIE inner maps + ARRAY_OF_MAPS wiring per Q1 + OR-compose match logic + STAT_PASS_CIDR increment); EDIT `src/lib/config.{cpp,hpp}` (RuleMatch.cidr field + validator + CIDR string parse to {addr, prefix_len}); EDIT `src/lib/loader.cpp` `internal::apply_request` (populate cidr inner alongside mac inner); EDIT `src/common/mac_filter.h` (new LPM_TRIE key struct + map names + STAT_PASS_CIDR enum). loader.hpp PUBLIC-API is fenced UNCHANGED (per PI-7-style invariant — `LoaderError` enum stays at 9 values unless architect adds new error category). NEW file likely: `src/lib/cidr.{cpp,hpp}` for CIDR string parsing (`10.0.0.0/8` → `{network: 0x0A000000, prefix_len: 8}`) — architect decides whether to inline this in config.cpp or carve out.
- **Tester**: ADD 3-5 ctests + 2-3 YAML fixtures (e.g., `config_valid_cidr.yaml`, `config_valid_mac_or_cidr.yaml`, `config_malformed_cidr.yaml`). DO NOT modify existing 27 tests (the 20 pre-MVP-3.1 PI-6 invariant continues + the 7 MVP-3.1 ctests should not regress). Use the established AF_PACKET persistent-socket pattern from `tests/T_APPLY_ATOMIC_SWAP_NO_DROP.sh` for any high-rate concurrent traffic. Existing helpers in `tests/lib/common.sh` (apply_config, NSEXEC, MAC_GOOD/MAC_BAD constants) ARE part of TestStrategy context — read freely.
- **Reviewer**: 5-point brownfield framework. Special attention:
  - **(1) MVP-3.1 invariants preserved**: ALL of PI-1..PI-14 still hold. New CIDR axis must not regress trust_model, P0a, atomic swap, or identity gates.
  - **(2) ARRAY_OF_MAPS atomic-swap consistency** (per risk register MVP-3.2 row 1): if architect picks two-step swap (independent MAC + CIDR inner maps), a `T_CIDR_ATOMIC_SWAP_NO_DROP_HALF_APPLIED` ctest must demonstrate no packet drop during the half-applied window. `[INVARIANT-VIOLATED]` if test is theatrical.
  - **(3) OR-compose negation**: `T_PASS_MAC_OR_CIDR` must verify BOTH branches independently (rule with MAC only matches, rule with CIDR only matches, rule with BOTH matches via either axis). `[NO-NEGATION-CONTROL]` if only happy-path.
  - **(4) PI-13 stats**: STAT_PASS_CIDR is a new index; the existing 3 indices (STAT_PASS, STAT_DROP_DENY, STAT_DROP_MALFORMED) must continue to fire as before. `[REGRESSION]` if existing T_PERCPU_STATS_SUM breaks.
  - **(5) PI-10 mac_filter.h additions-only**: new constants for LPM_TRIE + STAT_PASS_CIDR enum index are additions; existing constants untouched. `[UNRELATED-EDIT]` otherwise.

## Human-gate decision (default applied — see Out-of-Scope to override)

**HG-3.2-1: IPv4 only for cycle 1**. IPv6 LPM_TRIE shape (128-bit key) deferred to MVP-3.2.5 or later. Rationale: v4 establishes the LPM_TRIE pattern; v6 is mechanical repetition with a wider key; combining v4+v6 in one slice doubles ctest count and inflates schema design (operators want `{cidr: "...""}` to accept either family with auto-detection, which adds validator complexity). If product owner wants v4+v6 simultaneously, escalate at architect Phase A or at human gate; baseline is v4-only.

## Open mechanism questions (architect decides; document in §5.27)

### Q1: ARRAY_OF_MAPS atomic-swap shape for two inner-map types

MVP-3.1 wired `rulesets_outer = ARRAY_OF_MAPS[2]` pointing at `mac_allowlist_a` / `mac_allowlist_b` (both HASH). Adding LPM_TRIE for CIDR breaks the type-uniformity of ARRAY_OF_MAPS (one outer can only point at one inner-type). Architect picks:

- **Option AS1 (parallel outer maps)**: add `cidr_rulesets_outer = ARRAY_OF_MAPS[2]` → `cidr_allowlist_a` / `cidr_allowlist_b` (both LPM_TRIE). Both outers share the same `active_idx`. Apply orchestrator populates inactive slot of BOTH outers, then flips `active_idx`. Single u32 flip is still atomic for BOTH axes — same Composite-6 promise.
- **Option AS2 (combined outer struct)**: change `rulesets_outer` value type to a struct `{mac_inner_fd, cidr_inner_fd}` (via a new outer map type or by widening the slot value). More complex but single outer.
- **Option AS3 (two-step swap, half-applied tolerance)**: keep MAC and CIDR as independent maps, swap in two steps, make BPF read tolerant of half-applied state. Risk-register MVP-3.2 row 1 flags this as the riskier path.

**Recommendation**: **AS1** — single `active_idx` flipping two outers in a single u32-write is still atomic per kernel BPF map semantics; preserves the Composite-6 swap promise; no new outer-map type needed. AS2 is over-clever; AS3 violates the atomic-swap invariant.

### Q2: OR-compose precedence + short-circuit order

When a rule has both `mac:` and `cidr:`, which axis is checked first? Architect picks:

- **Option OR1 (MAC first, then CIDR)**: hot-path lookups MAC HASH first (O(1)); if miss, falls through to LPM_TRIE CIDR (O(log n)). Optimizes for the common case where MAC matches (fewer comparisons per packet).
- **Option OR2 (CIDR first, then MAC)**: opposite order.
- **Option OR3 (parallel, no short-circuit)**: both checked regardless; OR'd at the end. Slowest per-packet but simplest semantics.

**Recommendation**: **OR1** (MAC first). HASH is O(1); LPM_TRIE is O(prefix-length); short-circuit on first match shaves cycles on the common path.

### Q3: CIDR schema key naming

Per `architecture-v2.md` line 220 ("OR-compose with MAC match") the term is generic. The YAML key for the CIDR matcher needs to be named. Architect picks:

- **Option K1 (`cidr`)**: `match: {cidr: "10.0.0.0/8"}` — short, generic, family-agnostic (auto-detect v4/v6 — but v4-only per HG-3.2-1).
- **Option K2 (`src_cidr`)**: `match: {src_cidr: "10.0.0.0/8"}` — explicit about WHICH field of the packet is matched. Future-proof if dst_cidr lands later.
- **Option K3 (`cidr_v4`)**: explicit family in the key. Future schema: `cidr_v4` + `cidr_v6` as siblings.

**Recommendation**: **K2** (`src_cidr`). Brief language uses "L3 src-CIDR" consistently; explicit `src_cidr` makes future `dst_cidr` an obvious sibling without breaking change. K1 reads cleaner but couples the schema to "always src" which is an unwritten assumption. K3 over-commits to family-in-key naming.

### Q4: Single CIDR per rule vs list

Architect picks:

- **Option L1 (single CIDR per rule)**: `match: {src_cidr: "10.0.0.0/8"}`. Operator writes multiple rules for multiple CIDRs.
- **Option L2 (list of CIDRs per rule)**: `match: {src_cidr: ["10.0.0.0/8", "192.168.0.0/16"]}`. Operator can union CIDRs in one rule.

**Recommendation**: **L1** for cycle 1. Matches the MVP-3.1 pattern (`mac:` is single string, not list). L2 is sugar that can be added in a later slice without breaking L1; reverse direction would be a breaking schema change. Plus: with L1, rule-counting (and future per-rule counters in MVP-3.4) is unambiguous.

### Q5: Schema versioning bump?

MVP-3.1 shipped `schema_version: 1` (or implicit-default-1) accepting only `mac:` in match. Architect picks:

- **Option V1 (stay at schema_version 1, additive extension)**: accept `mac:` (MVP-3.1) AND `cidr:` (new) AND both-together (OR-compose). Existing configs still valid. No breaking change.
- **Option V2 (bump to schema_version 2)**: signals operators that the schema has grown. Existing `schema_version: 1` configs still accepted (per SV2 from MVP-3.1), but new `cidr:` features require explicit `schema_version: 2`.

**Recommendation**: **V1** (additive). The MVP-3.1 SV2 policy was explicitly "future breaking changes ship as schema_version 2 with 1 still accepted"; adding a new match key is NOT breaking (existing configs work unchanged). Bumping to 2 cheapens the signal for actual future breakage.

### Q6 (optional): Tackle MVP-3.1 OOT-deferred housekeeping items?

Two MVP-3.1 OOT items are cheap to fix:
- **OOT-1**: orphan map pins at `/sys/fs/bpf/` root from T_ATTACH_TAG_MISMATCH (one-line cleanup in test's trap).
- **OOT-2**: T_APPLY_ATOMIC_SWAP_NO_DROP stale NOTE comment (1-line edit).

Architect picks: include in MVP-3.2 scope, OR defer to dedicated housekeeping cycle. **Recommendation**: include if architect judges scope budget allows; defer otherwise. These are NOT in the canonical MVP-3.2 scope per `architecture-v2.md` and adding them is opportunistic only.

## Scope (4 core items + tests — anything else is OOS)

### Item 1 — BPF datapath: LPM_TRIE inner + OR-compose (per Q1 + Q2)

**Where**: EDIT `src/bpf/mac_filter.bpf.c` (add `xdpmf_cidr_v4` key struct per common header; declare `cidr_allowlist_a` + `cidr_allowlist_b` LPM_TRIE maps; declare `cidr_rulesets_outer` per Q1 AS1; extend `mac_filter_prog` with LPM_TRIE lookup after MAC lookup per Q2 OR1 ordering); EDIT `src/common/mac_filter.h` (new LPM_TRIE key struct + map names per architect).

**Action**: implement OR-compose datapath. If MAC matches → PASS + STAT_PASS. If MAC misses, derive `src_ip` from packet (IPv4 ethertype 0x0800), lookup CIDR LPM_TRIE → if match → PASS + STAT_PASS_CIDR. Otherwise → DROP_DENY + STAT_DROP_DENY. Non-IPv4 ethertypes go through MAC-only path (preserve MVP-3.1 semantics for ARP, IPv6, VLAN-tagged, etc.).

### Item 2 — Schema extension + CIDR string parser (per Q3 + Q4 + Q5)

**Where**: EDIT `src/lib/config.{cpp,hpp}` (RuleMatch gains optional `std::optional<xdpmf_cidr_v4> src_cidr` per Q3; validator accepts rule with mac-only, cidr-only, or both; rejects neither-axis-set with ConfigError exit 9); NEW `src/lib/cidr.{cpp,hpp}` (CIDR string → struct parser — accepts `A.B.C.D/N` where 0≤N≤32; rejects malformed input). EDIT `src/lib/yaml_subset.cpp` ONLY IF needed (already accepts string scalars; likely no edit needed).

**Action**: parse `src_cidr: "10.0.0.0/8"` strings into `{network: u32_be, prefix_len: u8}`; validator ensures `network & mask == network` (catches "10.0.0.5/8" operator mistake → ConfigError with `network bits set below prefix: 10.0.0.5/8 → did you mean 10.0.0.0/8?`).

### Item 3 — Apply orchestrator: populate CIDR inner (per Q1)

**Where**: EDIT `src/lib/loader.cpp` `internal::apply_request` flow (populate both `mac_allowlist_<inactive>` AND `cidr_allowlist_<inactive>` before flipping `active_idx`).

**Action**: extend the populate-inactive-then-flip sequence to cover both axes. Single `active_idx` u32-write is the atomic commit for BOTH axes per Q1 AS1.

### Item 4 — STAT_PASS_CIDR counter

**Where**: EDIT `src/common/mac_filter.h` (add `STAT_PASS_CIDR = 3` to stats enum — index 3 after existing STAT_PASS=0/STAT_DROP_DENY=1/STAT_DROP_MALFORMED=2); EDIT `src/bpf/mac_filter.bpf.c` (increment STAT_PASS_CIDR when CIDR axis matches); EDIT `tests/lib/read_stats.py` ONLY if it hardcodes the 3-counter sum (probably needs a 4th column).

**Action**: differentiate "passed because MAC matched" from "passed because CIDR matched" in counters. Operators reading stats post-apply can see the split.

### Tests (3-5 per `architecture-v2.md` line 222 + risk-register OR-compose mitigation)

- **`T_PASS_CIDR`** — apply config with single CIDR rule (`10.0.0.0/8`), inject packet with src_ip in range → PASS; STAT_PASS_CIDR incremented. Negation: inject packet with src_ip OUT of range → DROP_DENY; STAT_DROP_DENY incremented.
- **`T_DROP_CIDR_NOT_IN_RANGE`** (may be merged into T_PASS_CIDR negation step) — explicit negation case if not folded above.
- **`T_PASS_MAC_OR_CIDR`** — apply config with single rule `{mac: AA:BB:.., cidr: 10.0.0.0/8}` (OR-compose within rule). 3 sub-cases: (a) packet matches MAC only (different src_ip) → PASS + STAT_PASS; (b) packet matches CIDR only (different src_mac) → PASS + STAT_PASS_CIDR; (c) packet matches NEITHER → DROP_DENY. Negation control built-in (sub-case c).
- **OPTIONAL `T_CIDR_ATOMIC_SWAP_NO_DROP`** — extension of MVP-3.1's T_APPLY_ATOMIC_SWAP_NO_DROP for CIDR axis (concurrent injector at AF_PACKET rate, apply A→B with overlapping-allowed src_ip across both rulesets, assert STAT_DROP_DENY delta == 0). Architect-recommended given the risk-register MVP-3.2 row 1 flagging; defer if Q1 AS1 makes the test theatrical (single `active_idx` flip = identical mechanism to MVP-3.1, already covered by T_APPLY_ATOMIC_SWAP_NO_DROP).
- **OPTIONAL `T_CIDR_INVALID_REJECTED`** — config with `src_cidr: "not-a-cidr"` or `src_cidr: "10.0.0.5/8"` (network bits below prefix) → exit 9. May fold into existing T_APPLY_REJECTS_MALFORMED as new sub-case.

## Out of scope (explicit)

- **IPv6 CIDR matching** — fenced to MVP-3.2.5 (or integrated in 3.2 only on explicit human-gate override per HG-3.2-1). The schema MAY accept `src_cidr_v6` as a future sibling, but cycle 1 ships v4-only and rejects v6 strings (`::1/128` etc.) with `ConfigError` exit 9 + "IPv6 CIDR not supported until MVP-3.2.5".
- **Destination CIDR matching (`dst_cidr`)** — naming chosen (Q3=K2) leaves space; not in cycle 1.
- **L4 port matching** — MVP-3.5+ candidate, not in this slice.
- **Per-rule counters with rule_id** — MVP-3.4 slice (per `architecture-v2.md` MVP-3.4 row). Cycle 2 keeps the 4-counter global PERCPU shape (STAT_PASS, STAT_DROP_DENY, STAT_DROP_MALFORMED, STAT_PASS_CIDR).
- **Rule actions other than `pass`** — MVP-3.8+ (mirror, rate-limit, tag, redirect). All MVP-3.2 rules ship as `action: pass` with implicit drop-default.
- **List-of-CIDRs per rule (Option L2)** — MVP-3.2.x candidate if operators ask; cycle 1 is L1 per Q4.
- **Schema_version bump to 2** — V1 additive extension per Q5; bump deferred to first actual breaking change.
- **CIDR set-arithmetic semantics** (e.g., "block 10.0.0.0/8 except 10.5.0.0/16") — not in schema; LPM_TRIE longest-prefix-match handles overlapping prefixes naturally but no explicit `deny` rule action for cycle 2.
- **VLAN-aware CIDR matching** — MVP-3.x candidate (architect's lens B mentions VLAN as an axis); not here.
- **Binary rename `xdpmacfilter` → `xdpfilter`** — still MVP-3.12.
- **Public `libxdpmf.so.0` library extraction** — still MVP-3.6+ optional branch.
- **Tackling MVP-3.1 OOT-deferred items 3 (cli.hpp ParsedAttach wrapper design-text fix) and 4 (§6.25 "replacing existing program" grep)** — these are pure design-text/test-strengthen items; if architect picks Q6=YES for housekeeping, only items 1 and 2 are in scope (3 and 4 stay deferred per their original disposition).

## Definition of done

- `§5.27 MVP-3.2: L3 src-CIDR rule type` amendment in `design.md` documenting Q1-Q6 decisions with rationale + HG-3.2-1 confirmation
- New `§6.x TestStrategy` entries for the 3-5 new ctests
- `§6.5 Preserved invariants` extended: PI-1..PI-14 from MVP-3.1 hold + new PIs for MVP-3.2 (CIDR axis additive; schema_version 1 still accepted; STAT_PASS_CIDR additive; 27 existing ctests pass byte-equivalent)
- `§7 OOS`: MVP-3.2 components moved from deferred to shipped; MVP-3.3 (systemd) and MVP-3.4 (per-rule counters / exporter) become the next-natural slices
- `loader.hpp` PUBLIC-API UNCHANGED (PI-7-style); enum stays at 9 values
- 3-5 new ctests pass; OR-compose verification (`T_PASS_MAC_OR_CIDR`) is the load-bearing item for the architectural correctness of the OR-semantic
- 27 existing ctests still pass (or legitimately SKIP per §6.5) — strict superset growth
- `XDPMF_SANITIZERS=ON` build clean
- `xdpmacfilter --version` reports `xdpmacfilter 0.4.0` (bump from 0.3.0 to mark MVP-3.2 feature add; CMake `project(VERSION)` per MVP-2 Polish-2 V1 mechanism)
- `CHANGELOG.md` entry `[0.4.0] - 2026-05-NN` (Keep-a-Changelog format)
- `mint/review.md` round-1 verdict = `pass`
- One git commit per phase boundary per workflow B

## Dependencies

No new system dependencies. `BPF_MAP_TYPE_LPM_TRIE` is kernel ≥ 4.11 (well below floor 5.15). CIDR string parsing is in-tree (small custom parser; no libc dependency beyond `inet_pton` from `<arpa/inet.h>` if architect picks the standard route). No new C++ libraries.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       [lang/cpp.md, lang/cmake.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []
```
