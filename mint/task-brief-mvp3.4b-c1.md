# Task brief — MVP-3.4b: per-rule counters cycle 1 (brownfield)

## Goal

Ship **per-rule visibility** via `/metrics` — the first cycle of MVP-3.4b. Operator gains `xdpfilter_rule_match_total{iface, rule_id}` counter series exposing per-rule match counts. Lands the deferred-from-MVP-3.4 mechanics: per-rule counter map + inner-allowlist-value extension carrying `rule_id` to datapath + datapath wiring (`bump_rule` at the MAC-HASH-hit and CIDR-LPM_TRIE-hit sites) + loader-written `rule_index.json` sidecar for human-readable labels + exporter join of BPF + sidecar.

**This is MVP-3.4b cycle 1**, NOT the entire feature. Subsequent cycles can address:
- Atomic-swap promotion of `rules` map (D-3.4-4 — was a stub in §5.29; now becomes datapath-consulted in this cycle so the question becomes load-bearing).
- Counter-survival-across-apply discipline + dedicated ctests (Hidden Assumption #4 from /mint-hld Open Q #13).
- Action-table consultation (currently `rules` carries `action_id` but datapath ignores — out of scope this cycle; PASS-on-allowlist-hit branch retained as-is, drop-rule counters work but action dispatch stays implicit).
- Schema-v2 named-rules migration (Option 4 from /mint-hld, deferred indefinitely).

Estimated budget: **~1.5 cycle, medium risk**. Largest risk vectors: (a) PI-13-3.1 adjudication on inner-value extension (PASS as additive vs. VIOLATE as byte-shape break — default PASS); (b) datapath verifier passes after `bump_rule` introduction at MAC + CIDR sites (BPF function-body changes beyond MVP-3.4 hint annotations — first substantive datapath edit since MVP-3.2).

## Context: prior work

- **All prior briefs**: archived in `mint/task-brief-mvp{1,1.1*,2-*,3.1,3.2,3.3,3.4,3.4.5}.md`. Most recent: MVP-3.4.5 housekeeping (round-1 pass 2026-05-25).
- **Existing design**: `mint/design.md` — §5.29 (MVP-3.4 observability + skeleton + defer) is the immediate ancestor for the inner-value defer. §5.30 (MVP-3.4.5 housekeeping) confirmed PI-13-3.4.5/PI-27 untouched. Inner-allowlist-value still `__u8 present` byte (PI-27); `rules` and `action_table` BPF maps DECLARED and POPULATED but datapath does NOT consult either (PI-29). This brief LIFTS both fences.
- **Architecture document**: `mint/architecture-v2.md` — MVP-3.4b row + §"§MVP-3.4 Open Question #13 RESOLUTION" (committed `2d4b31a` 2026-05-24) is the load-bearing /mint-hld output. Option 2 ("Sparse-direct-bounded ARRAY") is the standing default; Option 3 (two-map shadow) is the fallback if PI-13 adjudication returns VIOLATE.
- **Source-of-truth claims from /mint-hld Open Q #13** (architects-HASH/ARRAY/T, synthesizer, design-reviewer; human-gate 2026-05-24):
  - **Option 2 wins** if MVP-3.4b ships per-rule counters and PI-13 adjudication returns PASS-as-additive.
  - **Open Q #3** (PI-13-3.1 inner-value adjudication) — **STILL OPEN at time of /mint-hld**. This brief PRE-DECIDES it (see HG-3.4b-1) but architect can override at Phase A with evidence.
  - **Open Q #4** (does `rules`+`action_table` skeleton REQUIRE inner-value extension regardless?) — **RESOLVED by MVP-3.4 shipping**: NO. `rules`+`action_table` shipped at §5.29 WITHOUT inner-value extension; PI-13-3.1 cost was deferred. MVP-3.4b pays it now.
- **MVP-3.4 review report** (`agent-teams-review/runs/mint-review-mint-l2-mac-filter-202605250825/report.md`): no MVP-3.4b-blocking items (the audit's MVP-3.4-targeted findings landed in MVP-3.4.5). Cross-doc consistency findings about `rules` map atomic-swap mechanics surface here as Q5.
- **Prior PI continuity**: `loader.hpp` is in its 5th consecutive ZERO-diff cycle post-MVP-3.4.5; this brief is likely to break that streak (the `Config` schema needs a `rule_id` field carry-through, and the loader needs new sidecar-write logic — but `AttachConfig` / `DetachConfig` / `attach()` / `detach()` / `LoaderError` enum signatures stand to remain UNCHANGED). Brief author's expectation: **PI-7-3.4b-hpp is _strictly_ additive** (no removed/renamed symbols; no signature changes to attach/detach; new private helpers OK; new public `apply_config_inmemory` Config schema fields OK if pure-additive at the C++ struct level). 6th consecutive byte-equivalent-or-additive cycle on the public-API headers if architect agrees.

## Workflow rules (brownfield mode)

- **Architect**: read existing `design.md` §5.29 (MVP-3.4 ancestor) + §5.30 (MVP-3.4.5 housekeeping ancestor) + §6.5 PI-1..PI-34 + §7 OOS + `architecture-v2.md` MVP-3.4b row + Open Q #13 RESOLUTION block fully. EDIT `design.md` in place. Append `§5.31 MVP-3.4b cycle 1: per-rule counters + inner-allowlist-value extension + datapath wiring + exporter labels`. Update §6.5 — PI-1..PI-34 mostly continue; **PI-13-3.4b adjudication is the big new PI** (architect formally rules on inner-value extension shape per HG-3.4b-1, documents the bytes layout, records the cross-reference to PI-27's prior strict reading); PI-7-3.4b-hpp additive-only continuation; PI-29 (rules+action_table populated NOT consulted) gets a documented carve-out for the bump_rule consult-but-not-action-dispatch read; PI-30 (bypass=detach-alias) and PI-31 (exporter READ-ONLY) UNCHANGED; new PI-35-3.4b candidates emerge from the rule-counter contract. Update §7 OOS — close MVP-3.4b cycle 1 deliverables; surface MVP-3.4b cycle 2 (atomic-swap promotion of `rules` per D-3.4-4 if datapath consultation makes it load-bearing now), MVP-3.4b cycle 3 (action-table dispatch — drop rules become operative), and MVP-3.5 JSON logs (carry-forward).
- **Impl**: brownfield mode. FileList is a DIFF. Expect 0-1 NEW source files (potentially `src/cli/sidecar_writer.{cpp,hpp}` if architect chooses to split rule_index.json write from `apply_internal`; OR keep it inline in `apply_internal` and have 0 NEW source files). 8-12 EDITED source/build files. Inner-allowlist-value extension is the biggest single change — touches `src/bpf/mac_filter.bpf.c` (struct definition + datapath read), `src/lib/loader.cpp` (HASH populate path writes new struct), `src/lib/cidr.cpp` or `src/lib/loader.cpp` (LPM_TRIE populate path writes new struct — symmetric per T.5 OQ #3), AND ALL test fixtures + helpers that currently write a literal `__u8 present` byte to the inner maps (the impl-side discipline rule from MVP-3.4.5 [[impl-role-discipline]] applies — if `grep -rE 'present.*[=:]\s*1' src/ tests/` surfaces a literal `present=1` write outside the loader, that's an inner-value consumer that needs to update to the new struct shape).
- **Tester**: NEW ctests (target 5-7):
  - `T_RULE_COUNTER_MAC_HIT_BUMPS.sh` — attach with a config of N rules; inject K packets matching rule_id=R; assert `xdpfilter_rule_match_total{iface=...,rule_id="R"}` exporter output reports `K`; assert other rule_ids stay 0. Negation control: re-run with packets matching rule_id=R+1; assert R's counter unchanged.
  - `T_RULE_COUNTER_CIDR_HIT_BUMPS.sh` — same but for CIDR LPM_TRIE matches. Important: CIDR has its own rule_id from the inner-LPM-value extension. Negation: inject MAC-matching-no-cidr packet; CIDR counter stays 0.
  - `T_RULE_COUNTER_SURVIVES_APPLY.sh` — apply config A; bump counters via injection; apply config B (same rules, swap_count++); assert counters PRESERVED (Prometheus counter semantic per HG-3.4b-3). Per /mint-hld Hidden Assumption #4: this default is "preserve" matching D-3.1-4 reuse_fd, NOT "reset" matching existing global `stats`. Architect picks the canonical behaviour and tester locks it.
  - `T_SIDECAR_JSON_SHAPE.sh` — apply known config; cat `${PIN_DIR}/<iface>/rule_index.json` (path per Q3); parse with `jq`; assert each rule entry contains expected `{rule_id, mac OR cidr, action, iface}` fields. Negation: malformed config triggers no sidecar write (exit 9 from existing ConfigError path).
  - `T_EXPORTER_RULE_LABELS.sh` — exporter scrapes `/metrics`; assert `xdpfilter_rule_match_total{iface=..., rule_id="..."}` series appear with valid Prometheus label syntax; assert sidecar-orphan tolerance (per /mint-hld Option 3 OQ — sidecar-bpf consistency window means exporter MAY observe a rule_id in counter map that's not in sidecar across an apply boundary; expected behaviour: drop and reconcile next scrape, NOT crash, NOT loud-warn-per-orphan).
  - `T_DROP_RULE_BUMPS_COUNTER.sh` — config has 1 PASS rule + 1 DROP rule (per §5.29 drop-rules-are-counted-but-action-still-implicit semantic — drop rules in `rules` map have action_id=1 but the datapath still drops via the "not in allowlist → defaults_map DROP" path; the per-rule counter for the drop rule bumps because the inner-allowlist-value still has its `rule_id`, even though the dispatch is via the existing PASS branch's _negation_). Sub-case: assert `xdpfilter_drop_match_total{iface, rule_id="<drop-rule-id>"}` (if architect chooses to separately count drop rules) OR a single `xdpfilter_rule_match_total{iface, rule_id, action}` with action label (per Q4 below).
  - Optional: `T_RULE_COUNTER_VERIFIER_GREEN.sh` — micro-test that boots the BPF object and verifies it loads cleanly (the inner-value extension + bump_rule introduction is the first substantive datapath edit since MVP-3.2 — verifier is reviewer-critical).
  - Existing 46 ctests post-MVP-3.4.5 should continue to pass (PI-6-3.4b strict superset). PI-13's existing strict-byte-shape readings on the 4 ctests that explicitly inspect inner-value bytes (typically `T_DROP_NOT_IN_ALLOWLIST`, `T_DROP_CIDR_NOT_IN_RANGE`, `T_APPLY_ATOMIC_SWAP_NO_DROP`, `T_PERCPU_STATS_SUM`) may need surgical fixes if their fixtures encode the old `__u8` literal — tester surfaces these to architect / impl during Phase B per [[impl-role-discipline]].
- **Reviewer**: 5-point brownfield framework. Special attention:
  - **(1) PI-13-3.4b adjudication is the load-bearing decision** — verify the new struct layout is documented byte-by-byte in §5.31 (offset 0 = `__u8 present`, offsets 1-3 = padding, offsets 4-7 = `__u32 rule_id` — total 8 bytes per slot), AND verify that the offset-0 byte stays byte-equivalent to PI-27's prior reading (a write of `present=1` at offset 0 followed by `bpftool map dump ... format c` SHOULD still show `0x01` at byte 0 for occupied slots — the old single-byte readers' interpretation survives).
  - **(2) PI-29 carve-out for datapath read of `rules` map** — verify the carve-out is explicit + scoped. The bump_rule path reads from inner-allowlist-value's `rule_id` field directly THEN bumps `rule_counters[rule_id]`. It does NOT consult `action_table`. The PI-29 invariant becomes: `rules` map is now READ by datapath (for per-rule counting) but action dispatch still uses the existing PASS/DROP branches, not action_table lookups. Document this carefully.
  - **(3) PI-7-3.4b-hpp additive continuation** — `loader.hpp` MAY add a new internal helper signature or extend `Config::Rule` struct with an internal `rule_id` field (set by loader during apply, not parsed from YAML — assigned 0..N-1 by source-order or by operator's `id:` field per architect Q decision). NO removed symbols, NO renamed symbols, NO signature breaks to `attach()`/`detach()`. Reviewer's regional-diff on `loader.hpp`: hunks ARE allowed this cycle but each hunk MUST be classifiable as "additive only" (new struct field, new helper declaration, new optional parameter — NOT removed parameter, NOT changed return type).
  - **(4) Datapath verifier health** — the bump_rule introduction adds a per-packet read from inner-allowlist-value's `rule_id` field. This is a 4-byte read after offset 4 in the struct. Verifier must accept this; if it rejects (e.g. due to alignment or zero-init pessimism), impl peer-DMs architect and Option 3 fallback (two-map shadow) becomes load-bearing.
  - **(5) Counter-survival-across-apply semantic preserved** — T_RULE_COUNTER_SURVIVES_APPLY ctest is the load-bearing canary. If apply resets counters, that's a contract bug at the bpf_map__reuse_fd discipline level (D-3.1-4) — reviewer flags as `[REGRESSION]`.

## Human-gate decisions (defaults applied — override at architect Phase A if you disagree)

### HG-3.4b-1: PI-13-3.1 inner-allowlist-value adjudication — **PASS as additive**

Per /mint-hld Open Q #3 (architecture-v2.md line 535): the question is whether extending the inner-allowlist-value from `__u8 present` to `struct allow_entry { __u8 present; __u8 _pad[3]; __u32 rule_id; }` (total 8 bytes) counts as additive PASS (PI-27's prior contract preserved at offset 0) or byte-shape break VIOLATE (the value's _size_ changed from 1 byte to 8 bytes; any external reader expecting 1-byte values gets garbage).

**Default**: **PASS as additive**.

**Rationale**:
- **At the operator-observable layer**, PI-27's contract is "present-or-not". A reader doing `bpftool map dump ... format c | head -1` on the value still sees `0x01` (the first byte). The extension doesn't break what operators observe.
- **At the BPF datapath layer**, the existing reads in `mac_filter_prog` are all "is this slot occupied?" — they look at offset 0 only (the `present` byte). Verifier-passing reads of offset 0 are byte-equivalent. New reads at offset 4 (`rule_id`) are net additions, not changes to existing reads.
- **At the ctest fixture layer**, ANY test that literally writes a 1-byte `present=1` payload via `bpf_map_update_elem` from userspace will break (value_size mismatch). Impl flags these via grep during Phase 2.5 smoke + tester picks up surgical fixes during Phase A/B. **This is the dominant cost of PI-13 PASS** — ~5 fixture touches per /mint-hld Option 2 cost estimate.
- **Symmetric CIDR LPM_TRIE inner-value**: the `cidr_allowlist_a/_b` inner-value MUST extend identically per T.5 OQ #3 (else MAC and CIDR rule_ids live in different shape-spaces — bug-shaped). The 8-byte struct applies to BOTH MAC HASH inner-value AND CIDR LPM_TRIE inner-value.

**If architect disagrees** (e.g. holds PI-27 strictly and treats value-size change as VIOLATE): peer-DM architect at Phase A with the VIOLATE ruling; default flips to **Option 3 fallback (two-map shadow)** which keeps inner-value byte-equivalent. The brief's scope items below all need to be re-shaped for Option 3 (new `mac_to_rule_id` HASH + `cidr_to_rule_id` LPM_TRIE + datapath extra-lookup per match). Option 3 is ~1 cycle larger than Option 2 due to the extra maps.

### HG-3.4b-2: Counter survival across `apply -f` — **PRESERVE** (Prometheus counter semantic)

Per /mint-hld Hidden Assumption #4: per-rule counters should survive `apply -f` so that Prometheus counter-monotonicity holds. This matches D-3.1-4's existing reuse_fd discipline (which already preserves global `stats` across apply per §5.26).

**Default**: counter map uses LIBBPF_PIN_BY_NAME + bpf_map__reuse_fd on state-b reattach loop (same idiom as the other 10 managed maps in `kManagedMaps[]` post-MVP-3.4.5 HK-9). Counter map should be added to `kManagedMaps[]` as a NEW entry (13th — `{member_ptr, "rule_counters", legacy_alias=false}`) — this is the cleanest cycle-1 demonstration that the HK-9 refactor saved the next-cycle's cost.

**If architect picks RESET semantic instead** (matching existing global `stats` operator-mental-model): document the divergence from D-3.1-4 in §5.31 + amend D-3.4b-1 with the rationale; T_RULE_COUNTER_SURVIVES_APPLY flips to T_RULE_COUNTER_RESETS_ON_APPLY (still load-bearing as a canary, just for the opposite contract).

### HG-3.4b-3: `rule_index.json` sidecar — **INCLUDE** in cycle 1

Per /mint-hld Option 2 composition: sidecar JSON is part of cycle 1 scope. Exporter joins `rule_counters` (BPF) with `rule_index.json` (sidecar) and emits `xdpfilter_rule_match_total{iface, rule_id}` with human-readable labels.

**Default sidecar shape** (architect Q2 below for finalization):
```json
{
  "iface": "eth0",
  "schema_version": 1,
  "applied_at": "2026-05-NN-HH:MM:SS",
  "rules": [
    {"rule_id": 0, "match": {"mac": "aa:bb:cc:dd:ee:ff"}, "action": "pass"},
    {"rule_id": 1, "match": {"cidr": "10.0.0.0/24"}, "action": "pass"},
    {"rule_id": 2, "match": {"mac": "11:22:33:44:55:66"}, "action": "drop"}
  ]
}
```

**Default path** (architect Q3 below for finalization): `${PIN_DIR}/<iface>/rule_index.json`. Per-iface sidecar pairs naturally with the per-iface bpffs pin layout. Loader writes atomically (rename-into-place idiom) on apply.

**If architect picks DEFER sidecar to a later cycle**: exporter falls back to emitting `xdpfilter_rule_match_total{iface=..., rule_id="N"}` with bare integer labels (no mac/cidr human-readable label). Cycle 1 cost shrinks ~30%; future cycle adds the sidecar + label join. Tester's T_SIDECAR_JSON_SHAPE.sh moves to the deferred cycle.

### HG-3.4b-4: `rules` map atomic-swap (D-3.4-4) — **STAY SHARED with clear-and-rewrite** for cycle 1

§5.29 declared `rules` as a SHARED ARRAY (single map, not parallel-outer via ARRAY_OF_MAPS) because the datapath ignored it. **MVP-3.4b cycle 1 makes the datapath consume rule_id from inner-allowlist-value** — but the consumption is via the INNER allowlist (already parallel-outer via `rulesets`/`cidr_rulesets` per §5.26/§5.27 atomic-swap), NOT via `rules` itself. So `rules` map can stay SHARED.

**Default**: keep `rules` as SHARED ARRAY. The datapath does NOT read `rules` (it reads `rule_counters` via `bump_rule(rule_id)` after extracting rule_id from the inner-allowlist-value which itself is parallel-swapped). No new atomic-swap promotion needed this cycle.

**If architect picks atomic-swap promotion** (D-3.4-4 closes now): `rules` flips to parallel-outer via new `rulesets_outer` ARRAY_OF_MAPS like the MAC and CIDR allowlists. Cost: +1 ARRAY_OF_MAPS + kManagedMaps[] gains 2 entries (parallel `rules_a/b` instead of single `rules`). This is a future-cycle architectural move; cycle 1 doesn't need it.

## Open mechanism questions (architect decides; document in §5.31)

### Q1: `bump_rule(rule_id)` datapath call-site placement

- **B1**: Bump in BOTH the MAC HASH hit branch AND the CIDR LPM_TRIE hit branch. Two `bump_rule` calls in `mac_filter_prog`. Distinct rule_id per match (MAC and CIDR rules have disjoint rule_id allocation per architect's allocator decision in Q5).
- **B2**: Bump in ONLY the MAC HASH hit branch — CIDR matches don't get per-rule counters in cycle 1, only aggregate via existing STAT_PASS_CIDR. Defer CIDR per-rule counters to a follow-up cycle.
- **B3**: Bump in a unified post-decision branch — single `bump_rule(rule_id)` call after either MAC OR CIDR match, using rule_id read from whichever inner-value was the hit source.

**Recommendation**: **B3**. Single call-site is cleaner, easier for verifier, symmetric MAC/CIDR semantic from cycle 1, no follow-up needed. B2 is the "defer half the feature" shape; B1 is correct but visually duplicative.

### Q2: Sidecar JSON schema fields beyond the default

Default shape above has `{rule_id, match, action}` per rule + `{iface, schema_version, applied_at}` top-level. Architect picks:

- **S1**: Defaults-only. Cycle 1 ships exactly the default shape.
- **S2**: Add a `description` free-form field per rule (operator-supplied annotation from YAML; optional). Forward-fit for future operator UX.
- **S3**: Add metadata like `loader_version`, `kernel_version`, `bpffs_root` to top-level. Forward-fit for debugging across deployment heterogeneity.

**Recommendation**: **S1** (defaults-only). Cycle 1 ships the minimum that the exporter needs to emit labeled metrics. S2/S3 are nice-to-have additive shifts; future-cycle.

### Q3: `rule_index.json` sidecar path

- **P1**: `${PIN_DIR}/<iface>/rule_index.json` (per-iface, paired with bpffs pin layout). Concern: bpffs is for BPF objects, not JSON files — but the per-iface pin directory ALREADY contains non-BPF files in the §5.28 systemd layout (and config files in some deployment patterns), so the precedent is mild.
- **P2**: `/var/lib/xdpmacfilter/<iface>/rule_index.json` (standard /var/lib spot for application state). Pairs with FHS conventions; requires new directory creation + permissions setup. Slightly more "right" but introduces a new filesystem touchpoint.
- **P3**: `/etc/xdpmacfilter/<iface>/rule_index.json` (config-adjacent). Wrong-shape: this is loader-WRITTEN output, not operator-EDITED input. /etc is for the latter.

**Recommendation**: **P1**. Pairs with bpffs pin layout, no new filesystem touchpoint, exporter already scans bpffs root by iface (HK-16 startup WARN/exit-6 codepath). Per-iface sidecar mirrors per-iface pinned maps. **Caveat**: bpffs is `tmpfs`-mounted in standard configurations; rule_index.json survives only as long as the bpffs mount survives — but THAT'S ALREADY TRUE for the pinned maps too (they survive loader restart but not bpffs unmount). Sidecar inherits the same lifecycle naturally. If architect picks P2 (FHS-correct), add `/var/lib/xdpmacfilter/<iface>/` mkdir + chown in apply path + corresponding cleanup in detach + ansible playbook touch + systemd RuntimeDirectory= or StateDirectory= update — all small but each-touch coordination cost.

### Q4: Action label on `xdpfilter_rule_match_total`

- **A1**: Single series `xdpfilter_rule_match_total{iface, rule_id}` — action info comes from joining with sidecar's `action` field at scrape consumer's side (operator queries Prometheus with `xdpfilter_rule_match_total * on(rule_id) group_left(action) xdpfilter_rule_meta`). Two-series approach.
- **A2**: Two series `xdpfilter_rule_pass_total{iface, rule_id}` + `xdpfilter_rule_drop_total{iface, rule_id}` — action baked into series name. Simpler operator query.
- **A3**: Single series `xdpfilter_rule_match_total{iface, rule_id, action}` — action as a label. Operator query is `sum by (action)(xdpfilter_rule_match_total)`. Highest cardinality but most natural Prometheus shape.

**Recommendation**: **A3**. Action as a label is Prometheus-idiomatic; sidecar already carries action; exporter joins both. A1's "join at query time" pushes work to operator; A2's "split series" multiplies metric count.

### Q5: Rule_id allocation policy in loader

The /mint-hld synthesizer didn't pin this down — left to MVP-3.4b architect. Options:

- **R1**: Operator's `id:` from YAML config IS the BPF key directly (sparse-but-bounded usage per Option 2 default). Operator writes `id: 5`, datapath bumps `rule_counters[5]`. Cap stays at 64.
- **R2**: Source-order allocation (loader assigns 0..N-1 by YAML order). Operator's `id:` becomes display-only. Risk: re-ordering rules in YAML invalidates Prometheus counter continuity across applies.
- **R3**: Sort-by-name allocation (Option 4 from /mint-hld). Out of scope per architecture-v2 — requires schema-v2.

**Recommendation**: **R1**. Honors the operator-observable §5.26 rule 3 contract (operator's `id` is the canonical identifier; gaps in 0..63 are normal). Matches Option 2 synthesizer default. R2 violates Prometheus counter monotonicity on YAML edits (operator surprise). R3 is Option 4 and out of scope.

## Scope (cycle 1 — concrete items)

### Item PI-3.4b-1 — `rule_counters` PERCPU_ARRAY[64] map
**Where**: `src/bpf/mac_filter.bpf.c` (NEW map declaration `rule_counters` PERCPU_ARRAY[64] of `__u64`; `bump_rule(__u32 rule_id)` inline helper adjacent to existing `bump_stat`); `src/lib/loader.cpp` (add to `kManagedMaps[]` as 13th entry per HK-9 refactor); `src/exporter/stats_reader.cpp` or new helper (read PERCPU sum across all CPUs per slot); `src/exporter/main.cpp` (emit Prometheus series — see PI-3.4b-6).

### Item PI-3.4b-2 — Inner-allowlist-value extension to `struct allow_entry`
**Where**: `src/bpf/mac_filter.bpf.c` (replace `__u8` inner-value type for BOTH MAC HASH `allowlist_a/b` AND CIDR LPM_TRIE `cidr_allowlist_a/b` with `struct allow_entry { __u8 present; __u8 _pad[3]; __u32 rule_id; }` — symmetric; verify total size is 8 bytes via `BPF_CORE_READ`-safe layout). PI-13-3.4b adjudication output documented per HG-3.4b-1.

### Item PI-3.4b-3 — Loader writes new struct shape
**Where**: `src/lib/loader.cpp` `internal::apply_request` step 8 (populate inactive inner allowlist) — replace literal `__u8 present = 1` writes with full `struct allow_entry{present=1, rule_id=<R>}` per rule entry. Loader assigns `rule_id` per Q5 (default R1: operator's YAML `id:`). Symmetric for both MAC HASH and CIDR LPM_TRIE populate paths. Out-of-band cleanup: `${PIN_DIR}/<iface>/allowlist` legacy alias (D-3.1-2) — needs the same struct shape; legacy single-byte reader breaks; this is a documented break (PI-13-3.4b's PASS-as-additive reading covers the case at the offset-0 byte level — old single-byte readers see `0x01` for occupied slots which preserves their semantic).

### Item PI-3.4b-4 — Datapath `bump_rule` wiring
**Where**: `src/bpf/mac_filter.bpf.c` `mac_filter_prog` — on MAC HASH hit OR CIDR LPM_TRIE hit, read `rule_id` from inner-value's offset-4 `__u32`; call `bump_rule(rule_id)` per Q1 (default B3: unified post-decision branch — single call-site). Verifier-pass critical; impl runs T_VERIFIER_REJECT-equivalent if not already covered.

### Item PI-3.4b-5 — `rule_index.json` sidecar write
**Where**: `src/lib/loader.cpp` `internal::apply_request` step 9 (or new step 10 — after inner-map populate + before active_idx flip) — write `rule_index.json` to per-iface path (default P1) per Q2 default shape (S1). Atomic write idiom: write to `rule_index.json.tmp`, fsync, rename. Schema_version=1 hard-coded. NEW one-off helper function (could live in new file `src/lib/sidecar.cpp` OR inline in `apply_internal` — architect's call).

### Item PI-3.4b-6 — Exporter rule label join
**Where**: `src/exporter/stats_reader.cpp` (read `rule_counters` PERCPU_ARRAY); `src/exporter/main.cpp` or new helper (parse `rule_index.json` per iface; build rule_id → {match, action} lookup); `src/exporter/prom_format.cpp` (NEW series emission — `xdpfilter_rule_match_total{iface, rule_id, action}` per Q4 A3). Sidecar-orphan tolerance: if BPF map has `rule_id=R` but sidecar doesn't, emit `rule_id="R"` with `action="unknown"` label (drop-and-reconcile next scrape; do NOT crash; do NOT loud-warn-per-orphan).

### Item PI-3.4b-7 — `Config::Rule` struct gains `rule_id` field (loader-internal)
**Where**: `src/lib/config.{cpp,hpp}` — `Config::Rule` struct adds `rule_id` field (loader-internal; not parsed from YAML directly; set by loader during apply per Q5). Public-API impact: minor (additive on a config struct that's already plumbed through `apply()`). PI-7-3.4b-hpp additive-only continuation.

### Item PI-3.4b-8 — Tests (5-7 new ctests)
**Where**: `tests/T_RULE_COUNTER_MAC_HIT_BUMPS.sh`, `tests/T_RULE_COUNTER_CIDR_HIT_BUMPS.sh`, `tests/T_RULE_COUNTER_SURVIVES_APPLY.sh`, `tests/T_SIDECAR_JSON_SHAPE.sh`, `tests/T_EXPORTER_RULE_LABELS.sh`, `tests/T_DROP_RULE_BUMPS_COUNTER.sh`, optional `tests/T_RULE_COUNTER_VERIFIER_GREEN.sh`. Plus tests/CMakeLists.txt entries.

### Item PI-3.4b-9 — Fixture surgical fixes (PI-13 ripple)
**Where**: ANY ctest fixture that literally writes a 1-byte `present=1` payload to inner-allowlist maps via `bpf_map_update_elem` from userspace. Impl Phase 2.5 smoke runs `grep -rE 'value_size.*1\b\|__u8.*present' tests/` and `grep -rE 'bpf_map_update_elem.*allowlist' tests/` to find them. Surgical fixes only (replace 1-byte literal with the new struct shape; preserve test semantic). Counted as EDITED-test-bodies carve-out per PI-34-3.4b strict-superset (5-10 EDITs estimated).

### Item PI-3.4b-10 — Version bump 0.6.1 → 0.7.0 + CHANGELOG
**Where**: `CMakeLists.txt` (project VERSION 0.6.1 → 0.7.0 — MINOR bump because this is a new operator-facing feature, not a patch). `CHANGELOG.md` (new `[0.7.0] - 2026-05-NN` entry per Keep-a-Changelog format; sub-groups: Added — per-rule counters, sidecar JSON, exporter rule labels; Changed — inner-allowlist-value struct shape (PI-13-3.4b adjudication note); Internal — `kManagedMaps[]` gains 13th entry, datapath consumes rule_id).

## Out of scope (explicit)

- **`action_table` datapath consultation** — `rules` map carries action_id but datapath does NOT dispatch via action_table lookup. PASS-on-allowlist-hit and DROP-via-defaults-map branches retained from §5.26. **MVP-3.4c future cycle** if needed.
- **Atomic-swap promotion of `rules` map (D-3.4-4)** — stays SHARED with clear-and-rewrite per HG-3.4b-4. MVP-3.4c if datapath consultation makes it load-bearing.
- **Action types beyond {PASS, DROP}** — still MVP-3.8+.
- **Cap-lift beyond 64 rules** — 64 stays per /mint-hld Option 5 rejection + Open Q #13 Q5 human-gate (permanent product contract).
- **Named rules schema-v2 (Option 4 from /mint-hld)** — deferred indefinitely. operator's `id:` is canonical identifier per R1.
- **Sidecar JSON history / versioning** — single rule_index.json, overwritten on apply; no rotation, no .prev backup, no audit log of past rule sets.
- **Sidecar JSON path under FHS /var/lib (P2)** — staying with bpffs-adjacent P1 per Q3 default. Future-cycle if operator demand surfaces.
- **`xdpfilter_drop_match_total` as separate series (Q4 A2)** — `action` as label per A3 default. Future-cycle if operator demand surfaces.
- **JSON structured logs (MVP-3.5)** — carry-forward.
- **sFlow (MVP-3.6 conditional)** — carry-forward.
- **Library extraction `libxdpmf.so.0` (MVP-3.6+)** — carry-forward.
- **Daemon `xdpmfd` (MVP-3.6+)** — carry-forward.
- **Binary rename `xdpmacfilter` → `xdpfilter` (MVP-3.12)** — carry-forward.
- **L4 ports / VLAN / IPv6 CIDR** — carry-forward.
- **Documentation pass (13 items D1..D13 from `/mint-review` report)** — separate manual pass per user direction. NOT in this slice.
- **Systemd sandbox directives (security M3 from /mint-review)** — separate security cycle, NOT in this slice.
- **TSAN build / CO-RE field-probe failure test** — coverage scope, NOT in this slice.

## Definition of done

- `§5.31 MVP-3.4b cycle 1` amendment in `design.md` documenting PI-3.4b-1..PI-3.4b-10 + Q1-Q5 decisions + HG-3.4b-1/2/3/4 confirmation; cross-references to `/mint-hld` Open Q #13 RESOLUTION + Option 2 composition.
- New `§6.x TestStrategy` entries for 5-7 new ctests + EDITed-fixture catalog for the PI-3.4b-9 surgical fixes.
- `§6.5 Preserved invariants` extended: **PI-13-3.4b adjudication** (the headline new PI — byte-layout of `struct allow_entry` documented + offset-0 byte-equivalence to PI-27 claimed); PI-7-3.4b-hpp additive-only (NO removed/renamed symbols); PI-29-3.4b carve-out (rules+action_table previously NOT consulted; now `rules` is still NOT consulted by datapath but inner-allowlist-value's rule_id IS read; action_table still NOT consulted); PI-31 (exporter READ-ONLY) UNCHANGED; PI-34 strict-superset 46-ctest baseline.
- `xdpmacfilter --version` reports `xdpmacfilter 0.7.0` (MINOR bump from 0.6.1; new operator-facing feature).
- `xdpmf-exporter --version` reports `xdpmf-exporter 0.7.0`.
- `CHANGELOG.md` entry `[0.7.0] - 2026-05-NN`.
- 5-7 new ctests pass; 46 existing ctests still pass modulo PI-3.4b-9 surgical fixes (5-10 EDITed-fixture-body carve-out documented in PI-34-3.4b — third "fixture-body carve-out" cycle after MVP-3.4 (4 EDITs) and MVP-3.4.5 (7 EDITs) — pattern is stable).
- `XDPMF_SANITIZERS=ON` build clean.
- BPF object verifier-loads cleanly (T_RULE_COUNTER_VERIFIER_GREEN OR existing T_VERIFIER_REJECT-style canary).
- `mint/review.md` round-1 verdict = `pass` (cycle 1 is medium-risk; round-2 rework is acceptable if verifier or PI-13 adjudication surfaces issues; aim for round-1 pass).
- One git commit per phase boundary per workflow B.

## Dependencies

- libbpf (existing); no new build deps.
- `nlohmann/json` or equivalent JSON library for `rule_index.json` write + read. Current project does NOT have a JSON dep (config is custom YAML subset per §5.26). Architect picks: vendor `nlohmann/json` single-header via `FetchContent` / `find_package`, OR roll a minimal JSON writer in `src/lib/sidecar.cpp` (~150 LOC for the writer; exporter reads via existing test-stack idioms — `jq` for assertions, custom parse if no dep).
- `jq` in test runtime (already a dep for several existing ctests; T_SIDECAR_JSON_SHAPE leverages it).
- No new BPF features. No new kernel-version dependencies (struct layout in BPF is verifier-trivial; CO-RE relocations not needed).

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       [lang/cpp.md, lang/cmake.md, lang/bpf.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []
```

---

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])

This brief defers no questions to /mint-hld; all open questions are tactical (architect-tier). /mint-hld already ran for Open Q #13 (architecture-v2.md commit `2d4b31a` 2026-05-24) — synthesizer's Option 2 + Caveat (b) human-gate held → MVP-3.4b ships Option 2 when re-asked. This brief IS the re-ask. No multi-axis design space to brainstorm; mechanical answer falls out of stated constraints. Single architect via standard /mint-dev is correct.

## Notes for architect Phase A code-grep discipline (per architect spec rule)

Before publishing §5.31:
- `grep -nE '__u8.*present\|present.*__u8' src/bpf/mac_filter.bpf.c src/lib/*.cpp tests/lib/*.sh tests/T_*.sh` — find every inner-value-shape touch site (PI-3.4b-9 fixture ripple).
- `grep -nE 'allowlist|cidr_allowlist' src/lib/loader.cpp | grep -v "// "` — find the populate paths that need to write the new struct.
- `Read src/lib/loader.cpp` around the post-MVP-3.4.5 `kManagedMaps[]` table (line 127-158 per MVP-3.4.5 review.md) — verify the 13th entry addition for `rule_counters` is one-line clean.
- `Read src/exporter/stats_reader.cpp` `read_all_attached*` overloads — verify the rule_counters read fits the existing pattern.
- `grep -nE '0.6.1|VERSION' CMakeLists.txt CHANGELOG.md tests/T_EXPORTER_METRICS_FORMAT.sh` — version bump touch sites.

The Phase A code-grep discipline rule was added to architect spec post-MVP-3.4.5 (where 3 Phase B EDITs surfaced via impl peer-DM precisely because the architect's design literals weren't grep-verified against the existing code). For MVP-3.4b — where the inner-value extension touches ~5-10 fixtures + the kManagedMaps[] table gains an entry + datapath verifier-passes are critical — a 15-minute Phase A grep pass should keep Phase B EDITs to ≤1.
