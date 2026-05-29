# Task brief — MVP-4.7: MAC-axis return (un-freeze) — 6th bit-vector axis (src-MAC exact HASH) (rule-model S7, brownfield)

## Goal

Return **MAC** as the 6th bit-vector match axis, un-freezing the maps deferred at the v2 cutover. When §5.43's M.1 cutover landed AND-compose, MAC matching was DEFERRED (HG-mvp-4.3-2, PI-mvp-4.3-MAC-DEFERRED): the `allowlist_a/_b` HASH + `rulesets` ARRAY_OF_MAPS stayed declared+pinned but **UNCONSULTED** (frozen), and the `mac` config key was REJECTED at parse with a "MAC matching deferred" diagnostic. This slice makes MAC a first-class exact-match axis again — symmetric to proto (§5.44) / vlan (§5.45) — keyed on the **source MAC** (`eth->h_source`, the original v1 semantic — design.md §5.26: "Reads `h_source` only").

Mechanically: reshape the frozen `allowlist` inner VALUE `struct allow_entry` → `__u64` bitmask (exactly the §5.43 `cidr_allowlist` reshape pattern), re-consult it in the datapath, `acc &= (mac_mask | wc_mac)`. The `allowlist_a/_b` + `rulesets` topology ALREADY exists and ALREADY rides `active_idx` (it was the original v1 MAC axis) → **`kManagedMaps[]` UNCHANGED at 30** (reshape, not add); only `BITVEC_NUM_AXES` 5→6 + `wildcard` 10→12 + `BV_AXIS_MAC=5`. Re-accept the `mac` key (RETIRE the reject + PI-mvp-4.3-MAC-DEFERRED — a PI shift, like §5.46's EXPORTER-AGNOSTIC retirement). Un-SKIP + convert the 5 MAC-verdict SKIP-77 tests. Add a `mac` label to the §5.46 `xdpfilter_rule_info` metric so the now-6-axis model stays fully observable. Additive within `schema_version 2` (no cutover). VERSION 0.14.0→0.15.0.

Anchors: §5.43 (the MAC-freeze + the `cidr_allowlist` value-reshape pattern), §5.44/§5.45 (proto/vlan exact-HASH axis template), §5.26 (original src-MAC allowlist semantic), §5.46 (`rule_info` per-axis labels).

## Context: prior work

- **All prior briefs**: archived in `mint/task-brief-*.md` (this supersedes `mint/task-brief-mvp-4.6.md`).
- **Existing design**: `mint/design.md` §5.43 (MAC-freeze decision + the `cidr_allowlist` `allow_entry`→`__u64` reshape — the byte-for-byte template for the MAC reshape; PI-mvp-4.3-MAC-DEFERRED), §5.44/§5.45 (proto/vlan exact-HASH axes), §5.46 (the `rule_info` metric this extends with a `mac` label), §5.26 (the original src-MAC allowlist: `h_source` only, src-MAC is at the base-eth fixed offset even on VLAN-tagged frames — design.md:512-513).
- **Phase A code-grep verification** (brief author): `xdpmf_allowlist_inner` = HASH<`xdpmf_mac`, `allow_entry`> frozen (`mac_filter.bpf.c`); `allowlist_a/_b` + `rulesets` declared + ride `active_idx`; the `mac` reject at `config.cpp` (~"MAC matching deferred"); `RuleMatch.mac` field ALREADY EXISTS (`config.hpp:45`, dormant — rejected not absent → config.hpp UNCHANGED); sidecar `append_kind("mac", …)` branch ALREADY EXISTS (`sidecar.cpp:121`, dormant → fires once `r.match.mac` is populated → sidecar.cpp likely UNCHANGED); src-MAC = `h_source` (design.md §5.26); BITVEC_NUM_AXES=5/BV_AXIS_VLAN=4; kManagedMaps=30; VERSION=0.14.0; ctest baseline=82; 5 SKIP-77 tests confirmed (T_PASS_ALLOWED/T_DROP_DENY/T_PASS_MAC_OR_CIDR/T_RULE_COUNTER_MAC_HIT_BUMPS/T_APPLY_ATOMIC_SWAP_NO_DROP); `rule_info` currently emits 5 axis labels (NO mac).
- **PI continuity — IMPORTANT SHIFT**: `PI-mvp-4.3-MAC-DEFERRED` ("`mac` rejected; datapath does not consult MAC maps; MAC maps frozen") is **INTENTIONALLY RETIRED** — MAC returns as a live axis. Document the shift (cite the retired PI verbatim per [[impl-role-discipline]], mirror §5.46's EXPORTER-AGNOSTIC retirement). PI-mvp-4.3-AND/-WILDCARD/-SCHEMA-V2 extend to 6 axes; proto/vlan exact-axis PIs are the template; COUNTER-PRESERVE + close_prefixes-UNCHANGED CONTINUE; PI-mvp-4.6-COUNTER-CONTRACT continues (the rule_info label-set change is the ONE intended exporter delta).

## Workflow rules (brownfield)

- **Architect**: read §5.43 (MAC-freeze + cidr_allowlist reshape template) + §5.44/§5.45 (exact-axis pattern) + §5.46 (rule_info) + §5.26 (h_source semantic) + brief. EDIT `design.md` in place; append **§5.47**. Resolve Q1–Q4 + HG defaults. Document the PI-mvp-4.3-MAC-DEFERRED retirement. State that MAC is exact (NO closure — guard #23 does not extend) + that src-MAC is at the fixed base-eth offset (no VLAN-walk interaction).
- **Impl**: brownfield FileList DIFF. Reshape the frozen `allowlist` inner value `allow_entry`→`__u64` (mirror the §5.43 cidr reshape); read `eth->h_source` (already bounds-checked for the ethhdr; before the VLAN walk); MAC HASH lookup in `allowlist[active]`; `acc &= (mac_mask|wc_mac)`. `BITVEC_NUM_AXES` 5→6 (wildcard auto 10→12). Every Ethernet frame HAS a src MAC (no "absent" sentinel like vlan-untagged) — a rule omitting `mac` survives via `wildcard[active*6+5]`. Re-run the bpftool-load smoke.
- **Tester**: UN-SKIP + convert the 5 MAC tests to the AND-model (MAC matching is live again — they assert real MAC verdicts now, not SKIP-77). Extend the oracle to 6 axes. Extend T_EXPORTER_RULE_LABELS for the new `mac` label. Existing non-MAC corpus stays green (additive). Reconcile baseline (was 82; the 5 un-SKIPs become active, count unchanged but 5 move SKIP→pass).
- **Reviewer**: 5-point brownfield. Special attention: (a) src-MAC (`h_source`) semantic preserved (NOT h_dest); (b) the allowlist reshape mirrors cidr (value-only, pin names + topology unchanged — guard #16); (c) kManagedMaps UNCHANGED at 30 (reshape not add — guard #10); (d) MAC maps RESET-on-apply (no copy-forward; they were frozen, now live-populated each apply); (e) PI-mvp-4.3-MAC-DEFERRED retirement documented, not silently broken; (f) the 5 un-SKIP'd tests assert real MAC verdicts (not still-skipping, not weakened); (g) rule_info `mac` label added + T_EXPORTER_RULE_LABELS ERE updated (the existing counter families STILL byte-identical — only rule_info's label-set grows, PI-mvp-4.6-COUNTER-CONTRACT holds).

## Human-gate decisions (defaults applied — architect overrides at Phase A with evidence)

### HG-mvp-4.7-1: MAC → **6th exact-match HASH axis on src-MAC (`h_source`)**
Keyed by `xdpmf_mac` (6-byte), value `__u64` bitmask, mirroring proto/vlan. `BITVEC_NUM_AXES` 5→6, `BV_AXIS_MAC=5`. NO prefix-closure (exact). src-MAC per the original v1 semantic (design.md §5.26 "h_source only"); dst-MAC matching → OOS.

### HG-mvp-4.7-2: `mac` config key → **RE-ACCEPTED in v2 (RETIRE the deferral)**
Remove the parse-reject; parse `mac` via the existing MAC parser; `mac` joins the at-least-one-of set `{mac, dst_cidr, src_cidr, protocol, dst_port, vlan}`. `RuleMatch.mac` field already exists (config.hpp UNCHANGED). PI-mvp-4.3-MAC-DEFERRED RETIRED (documented). Additive within schema_version 2 — no cutover.

### HG-mvp-4.7-3: maps → **reshape the frozen `allowlist` (value-only), +0 kManagedMaps**
`allowlist_a/_b` inner VALUE `allow_entry`→`__u64` (mirror §5.43 cidr reshape); pin names + topology + the `rulesets` outer UNCHANGED (they already ride `active_idx`). `kManagedMaps[]` STAYS 30. RESET-on-apply (guard #15; the maps were frozen, now populated from mac-constrained rules each apply; no copy-forward).

### HG-mvp-4.7-4: exporter `rule_info` → **add a `mac` label (6th axis)**
The §5.46 `xdpfilter_rule_info` gauge gains a `mac` label so mac-constrained rules are observable (else they'd show all-empty axes — inconsistent). Label-set grows 5→6 axes (7→8 total keys). The two COUNTER families (`packets_total`, `rule_match_total`) stay byte-identical (PI-mvp-4.6-COUNTER-CONTRACT). T_EXPORTER_RULE_LABELS's stable-key ERE ripples (guard #13). Architect Q to weigh vs deferring the label (rejected default — leaves mac-rules unlabeled).

### HG-mvp-4.7-5: the 5 SKIP-77 tests → **un-SKIP + convert to live MAC-AND assertions** (MAC is a real axis again; they assert MAC verdicts under the AND-model, NOT SKIP, NOT weakened).

### HG-mvp-4.7-6: VERSION → **bump 0.14.0 → 0.15.0 + DESCRIPTION** (MAC axis restored; propagate the literal, guard #11 — only T_EXPORTER_METRICS_FORMAT pins it).

## Open mechanism questions (architect decides; document in §5.47)

### Q1: MAC axis map (reshape vs new)
- **A1**: reshape the existing frozen `allowlist_a/_b` inner value `allow_entry`→`__u64`; `rulesets` outer unchanged (rides active_idx). +0 kManagedMaps. NO closure.
- **A2**: fresh parallel `mac_bitmask` axis + retire the frozen allowlist — rejected (gratuitous pin churn + map count growth; the frozen maps are PRECISELY the right shape).
- **Recommendation**: **A1** — value-only reshape, mirrors §5.43 cidr exactly; guard #16 satisfied (no pin rename).

### Q2: datapath MAC read
- **A1**: read `eth->h_source` (fixed offset in the base ethhdr — already bounds-checked; BEFORE the VLAN walk, so VLAN-agnostic per design.md:513); HASH lookup `allowlist[active]` by `xdpmf_mac`; `mac_mask = lookup_or_0`; `acc &= (mac_mask|wc_mac)`. Every frame has a src MAC → no "absent" case (unlike vlan-untagged); a rule omitting `mac` → wildcard.
- **Recommendation**: **A1** (preserves the v1 `h_source` semantic).

### Q3: rule_info `mac` label placement + T_EXPORTER_RULE_LABELS ripple
- **A1**: add `mac` as a label key in the `xdpfilter_rule_info` line (architect picks position — e.g. first, mirroring axis order, or last); empty "" sentinel when unconstrained (same convention as the other 5); update the T_EXPORTER_RULE_LABELS stable-key ERE 7→8 keys.
- **Recommendation**: **A1** — keeps the metric complete; the ripple is one test's ERE (guard #13, pre-listed).

### Q4: wildcard growth + axis index
- `wildcard` max_entries `RULESET_COUNT*BITVEC_NUM_AXES` auto 10→12; `BV_AXIS_MAC=5`; datapath `wildcard[active*6+5]`; loader writes 6 axis slots; RESET-on-apply (guard #15). Architect confirms `active*6+axis` holds for 6 axes (same mechanism as §5.44/§5.45, N=6).

## Scope (cycle S7 / mvp-4.7 — concrete items; estimates are UPPER BOUNDS)

### Item S7-1 — config grammar: re-accept `mac`
**Where**: `src/lib/config.cpp` (config.hpp UNCHANGED — `RuleMatch.mac` exists)
- Remove the `mac`-reject branch (the "MAC matching deferred" diagnostic); parse `mac` via the existing MAC parser; add `mac` to the at-least-one-of set. Schema stays 2.

### Item S7-2 — datapath: MAC axis + reshape
**Where**: `src/bpf/mac_filter.bpf.c`
- Reshape `xdpmf_allowlist_inner` value `allow_entry`→`__u64`; read `eth->h_source`; MAC HASH lookup; `acc &= (mac_mask|wildcard[active*6+5])`; `BV_AXIS_MAC=5`; `BITVEC_NUM_AXES` 5→6. first_set_u64/dispatch/bump_rule/defaults/close_prefixes/other 5 axes UNCHANGED.

### Item S7-3 — loader: lower MAC bitmask
**Where**: `src/lib/loader.cpp`, `src/common/mac_filter.h`
- `BITVEC_NUM_AXES` 5→6 (mac_filter.h); `BV_AXIS_MAC=5`. Lower mac-constrained rules → `allowlist` `__u64` bitmask (exact, NO closure; mirror the cidr/proto populate); extend `write_wildcard_slots` to 6 axes; RESET-write the inactive allowlist inner + inactive wildcard half before the `active_idx` flip. `kManagedMaps[]` UNCHANGED (30). close_prefixes/copy_rule_counters_forward UNCHANGED.

### Item S7-4 — exporter: rule_info `mac` label
**Where**: `src/exporter/sidecar_reader.{hpp,cpp}` (RuleMeta gains a `mac` field + extract_axis for "mac") + `src/exporter/prom_format.cpp` (add the `mac` label to the rule_info line). Counter families byte-unchanged.

### Item S7-5 — VERSION + DESCRIPTION + literal propagation
**Where**: `CMakeLists.txt` + `T_EXPORTER_METRICS_FORMAT` (guard #11).

### Item S7-6 — tests: un-SKIP + convert + 6-axis
**Where**: `tests/T_PASS_ALLOWED.sh`, `T_DROP_DENY.sh`, `T_PASS_MAC_OR_CIDR.sh`, `T_RULE_COUNTER_MAC_HIT_BUMPS.sh`, `T_APPLY_ATOMIC_SWAP_NO_DROP.sh` (un-SKIP → live MAC-AND assertions), `tests/T_EXPORTER_RULE_LABELS.sh` (+mac label, ERE 7→8 keys), `tests/bitvec/bitvec_oracle_prod.py` (→6 axes), a NEW mac-AND fixture/test if the converted set doesn't cover the AND-compose-with-mac case, `tests/CMakeLists.txt` if SKIP_RETURN_CODE bookkeeping changes. `RESOURCE_LOCK xdp_fixture` (guard #12). NOTE: src-MAC is at base-eth (NOT VLAN-offload-stripped) → guard #22 likely N/A for MAC, but the un-SKIP'd tests inject L2 frames — verify their setup.

## Out of scope (explicit)
- **dst-MAC matching; MAC ranges/masks/OUI-prefix** — src-MAC exact only (v1 semantic). NEW FENCE.
- **IPv6 cidr6; feed-objects; N>64; most-specific-wins; sequential** — later slices. NEW FENCE.
- **schema_version v2→v3** — re-accepting `mac` is additive within v2. NEW FENCE.
- **Non-eBPF datapath / 40 Gbps** — deferred per [[real-requirements-and-strategy]].
- Carry-forward §5.41-§5.46 OOS items not superseded — UNCHANGED.

## Definition of done
- §5.47 amendment appended to `mint/design.md` (Phase A grep report + HG/Q resolutions + PI-mvp-4.3-MAC-DEFERRED retirement + new PIs).
- **PIs**: NEW PI-mvp-4.7-MAC (src-MAC exact HASH axis, h_source); PI-mvp-4.3-MAC-DEFERRED RETIRED (verbatim cite); PI-mvp-4.3-AND/-WILDCARD/-SCHEMA-V2 → 6 axes; PI-mvp-4.6-COUNTER-CONTRACT continues (only rule_info label-set grows); COUNTER-PRESERVE + close_prefixes-UNCHANGED CONTINUE.
- ctest baseline = **82** (mvp-4.6; tester reconciles — the 5 SKIP-77 become live pass, count unchanged); existing non-MAC corpus green.
- VERSION 0.14.0 → 0.15.0, literal propagated.
- impl Phase 2.5 bpftool-load smoke rc=0 (6-axis + MAC HASH verifies).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang-19 / libbpf / CMake; `bpftool`; `inject_eth.py` (`<iface> <src_mac> <dst_mac>`) for MAC injection.
- Runtime: `bpf()` HASH + ARRAY_OF_MAPS (all used); fixed metrics port for exporter ctests (guard #12, B17).
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
- **One-sentence goal**: un-freeze MAC as the 6th exact-HASH bit-vector axis (src-MAC, value-reshape of the frozen allowlist), re-accept the `mac` key, un-SKIP the 5 MAC tests, add a rule_info mac label — additive within schema_version 2.
- **Multi-axis design space?** NO — structure resolved (bit-vector); proto/vlan are proven exact-axis templates; the maps already exist (frozen) in exactly the right shape; src-MAC semantic is documented (§5.26). `/mint-hld` NOT needed.
- **Mechanical?** YES — "reshape the frozen allowlist like §5.43 did cidr + re-accept the key + un-SKIP." Single-architect via `/mint-dev`.
- **Scope-size**: moderate, ONE coherent slice. Slightly more touch than 4.4-4.6 (un-SKIP 5 tests + a 2nd exporter touch) but no structural change. No split.
- **Overconfidence check**: VERIFIED RuleMatch.mac + sidecar mac-branch ALREADY EXIST (dormant) → config.hpp + likely sidecar.cpp UNCHANGED (not new code). VERIFIED src-MAC=h_source (§5.26, not assumed). kManagedMaps=30 stays (reshape not add). The rule_info label-change re-touches the just-stabilized §5.46 metric — flagged as the one intended exporter ripple (guard #13), not assumed-away.

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author ran these (Phase 2). Architect re-verifies + extends:
- `sed -n '/struct xdpmf_allowlist_inner/,/};/p' src/bpf/mac_filter.bpf.c` (value = `allow_entry`, frozen → reshape to `__u64`).
- `grep -nE 'h_source|h_dest' mint/design.md src/bpf/mac_filter.bpf.c` (CONFIRM v1 = `h_source` only, design.md §5.26 / :242/:512; the datapath MAC branch was removed in §5.43 — re-add reading h_source).
- `grep -nE '"mac"|MAC matching deferred' src/lib/config.cpp` (the reject to remove) + `grep -nE 'mac;' src/lib/config.hpp` (RuleMatch.mac EXISTS → config.hpp UNCHANGED).
- `grep -nE 'append_kind\("mac"' src/lib/sidecar.cpp` (the dormant emit branch — fires once mac is set; likely sidecar.cpp UNCHANGED).
- `sed -n '/kManagedMaps/,/};/p' src/lib/loader.cpp` (30 entries — CONFIRM stays 30; allowlist_a/_b + rulesets already present).
- `grep -nE 'BITVEC_NUM_AXES|BV_AXIS_' src/common/mac_filter.h` (=5; add BV_AXIS_MAC=5, flip→6).
- `grep -nE 'rule_info|dst_cidr.*src_cidr' src/exporter/prom_format.cpp` (the 5-axis label line → add mac) + `grep -nE 'rule_info|stable.*key|7' tests/T_EXPORTER_RULE_LABELS.sh` (the ERE to update 7→8 keys).
- `grep -rn '0\.14\.0' CMakeLists.txt tests/` (VERSION propagation).
- the 5 SKIP tests: `grep -l 'exit 77' tests/T_PASS_ALLOWED.sh tests/T_DROP_DENY.sh tests/T_PASS_MAC_OR_CIDR.sh tests/T_RULE_COUNTER_MAC_HIT_BUMPS.sh tests/T_APPLY_ATOMIC_SWAP_NO_DROP.sh` (the SKIP guards to remove).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #5 (Phase A code-grep)** — always; architect repeats independently.
- **Guard #9 (helper duplication-over-extraction)** — the MAC populate/lookup mirrors the proto/cidr helpers; reuse the established pattern, don't over-share.
- **Guard #10 (catalog arithmetic)** — `kManagedMaps[]` STAYS 30 (reshape, NOT add — state explicitly it does NOT grow); `wildcard` 10→12; `BITVEC_NUM_AXES` 5→6. Load-bearing.
- **Guard #11 (VERSION-bump test-literal propagation)** — applies (HG-6); grep every `0.14.0`.
- **Guard #12 (RESOURCE_LOCK)** — the un-SKIP'd + new MAC ctests take `RESOURCE_LOCK xdp_fixture` + cleanup trap.
- **Guard #13 (retired/changed emit-site string ripple)** — the `rule_info` label-set grows 5→6 axes → T_EXPORTER_RULE_LABELS's stable-key ERE (7→8 keys) MUST update; pre-listed. The retired "string" = the MAC-deferred reject diagnostic + PI-mvp-4.3-MAC-DEFERRED (document the retirement). Also: the 5 SKIP-77 tests' "MAC deferred to mvp-X" echo lines are retired — grep + remove.
- **Guard #15 (PRESERVE-vs-RESET)** — the reshaped MAC bitmask + grown wildcard are RESET-on-apply (no copy-forward; were frozen, now live each apply); `rule_counters` stays PRESERVE.
- **Guard #16 (retired pin-path/map-name ripple)** — NO pin rename (value-only reshape keeps `allowlist`/`rulesets` names) → no test-body pin-dump ripple. Confirm.
- **Guard #22 (L2-mutation test vacuity)** — src-MAC is at the base-eth fixed offset, NOT a NIC-offloaded/stripped field (unlike VLAN) → likely N/A for MAC; but the un-SKIP'd tests inject L2 frames — verify their setup doesn't need it.
- **Guard #23 (prefix-closure)** — does NOT extend to MAC (exact-match, like proto/vlan). close_prefixes + the dst/src §6.62 canary UNCHANGED. State explicitly.
- **Operative-semantic discipline**: counts in §5.47 verifiable-invariants (kManagedMaps=30 UNCHANGED, wildcard=12, BITVEC_NUM_AXES=6 are load-bearing MUST; ctest delta, PI numbering SHOULD) — impl deviations mirroring precedent are `inline-merge`.
