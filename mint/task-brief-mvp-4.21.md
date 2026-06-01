# Task brief — MVP-4.21 / B30: decouple internal bit-vector `slot` from operator rule `id` (counter-continuity, brownfield)

## Goal
Today the operator-facing rule `id` is **triple-coupled**: it is simultaneously (1) the match priority (first-match by lowest id), (2) the bit position in the u64 match accumulator (`bit = 1ULL << r.id`), and (3) the per-rule Prometheus counter index (`rule_counters[id]`). Consequence (the footgun): an operator who **renumbers a rule to re-prioritize** or **inserts a rule between two others under dense numbering** moves that rule's bit position — which moves its Prometheus counter series and breaks per-rule monotonicity (the counter appears to jump/reset). The `id < XDPMF_ALLOWLIST_MAX(64)` cap also forces operators into the dense [0,63] space where insertion-without-renumber is impossible.

**B30 = decouple the three roles.** Operator `id` becomes a **pure stable identity + the counter key**. The loader assigns a dense internal **`slot`** (rank of the rule in id-sorted order), sets `bit = 1ULL << slot`, and keeps per-rule counters addressable by the stable `id` via a `slot → id` mapping. Net operator value: reorder/insert/renumber rules without breaking per-rule counter continuity; id freed from the dense [0,63] cap (sparse numbering, VyOS-style).

**Priority is UNCHANGED**: still first-match by lowest `id` — the loader assigns `slot` in **id-sorted order**, so `slot` rank mirrors `id` rank and `ffsll(acc)-1` still yields the lowest-id survivor (HG-mvp-4.3-4 preserved). This slice does NOT introduce most-specific-wins or N>64 (both explicitly OUT OF SCOPE — see below).

## Context: prior work
- Prior briefs archived in `mint/task-brief-*.md` (latest: `task-brief-mvp-4.20.md` = B23-min, shipped+pushed `73e2964`).
- **Source = a prior `/mint-hld` round** (`/home/user/agent-teams-review/runs/hld-mint-l2-mac-filter-20260530084033/architecture-rule-model.SYNTHESIS.md`, "Option 4 — Ratify + id/slot decouple", contrarian #5). That round CHOSE this approach and named the load-bearing pieces; **per the rolling-wave discharge discipline it is a HYPOTHESIS, re-grounded against current code in this brief's Phase-2 (below) — not echoed as a committed plan.** The two open-Qs the hld left are now both DISCHARGED: (Q "is reordering near-term?" → **PO greenlit 2026-06-01**, overrides the backlog defer-gate; Q "does any datapath site hardcode id==bit?" → **NO, grep-confirmed below**).
- Clean tree, `main == origin/main` @ `73e2964`. Match model = 9 axes; VERSION 0.15.0, schema 2, guards catalog at #28, kManagedMaps = 38.

**Phase-2 grep verification (brief author ran — load-bearing facts):**
- The `bit = std::uint64_t{1} << r.id` lowering lives at **4 sites in `src/lib/loader.cpp`** (the populate loops) + the `bit` field in `struct ... { unsigned long long bit; }` (`src/common/mac_filter.h`, comment "rule bit = 1ULL << rule_id"). These are the sites that change to `<< slot`.
- **Datapath bit-position opacity HOLDS (the critical claim).** In `src/bpf/mac_filter.bpf.c` the winner is `__u32 rid = first_set_u64(acc) - 1;` then `bump_rule(rid, active)` (→ `rule_counters[rid] += 1`) and `bpf_map_lookup_elem(rules_inner_map, &rid)` → `struct rule_entry{present, action_id}`. **`rid` is used ONLY as an opaque dense map index — it is never compared to, or derived from, a config `id` value.** `struct rule_entry` (rules_inner value) carries `present` + `action_id` ONLY — NO `rule_id` field. ⟹ if the loader fills the axis-maps' bit at `slot` and fills `rules_inner[slot]`/`rule_counters[slot]` by `slot`, the **datapath instruction stream is byte-identical** (it already treats the bit position as an opaque slot).
- **Where the per-rule identity currently lives**: `struct allow_entry{present,_pad,rule_id}` (offset-4 `rule_id`) is the value of the per-axis lookup maps — that's how an axis key contributes its rule's bit. The COUNTER (`rule_counters[]`, `bump_rule`) and the ACTION array (`rules_inner[]`) are indexed by the **bit position**, NOT by a stored id.
- **The counter-preservation helper already exists**: `copy_rule_counters_forward(old_active_inner_fd, inactive_inner_fd)` (`src/lib/loader.cpp:~1814`, PRESERVE semantic, guard #15, PI-3.4b-2 monotonicity). Today it copies **by index** (safe because slot==id today). Under decoupling it must copy **keyed by `id`** (remap old-slot-of-id → new-slot-of-id) — this is THE load-bearing change (Phase-1 sub-check 5 / MVP-3.4d precedent).
- Config: `src/lib/config.cpp` parses `rule.id`, validates `id < XDPMF_ALLOWLIST_MAX(64)`, dedups via `seen_ids`. No separate priority field — `id` is priority today (via bit position).
- The exporter reads counters via `src/exporter/rule_counters_reader.hpp` (scans `${bpffs_root}/<iface>/rule_counters` pins, PERCPU-sums each slot). It currently reports each slot's sum; under decoupling it must report each counter **under its stable `id`** (needs slot→id at read time).
- PI continuity: loader.hpp **PI-7 will MOVE this slice** (loader.cpp changes; loader.hpp may or may not — architect confirms whether any signature changes leak to the header). Datapath verdict-identity is the target.

## Workflow rules (brownfield)
- **Architect**: read design.md §5.31/§5.34/§5.35 (rules + rule_counters ARRAY_OF_MAPS shape + the PI-3.4b-2 monotonicity + copy_rule_counters_forward / D-3.4d-3 / guard #15), §5.43 (the ffsll first-match-by-id datapath), §6.5 invariants. EDIT design.md in place; append **§5.61** (MVP-4.21). Resolve Q1/Q2/Q3 (you own realizability — esp. WHERE the slot→id mapping lives, given the datapath-byte-identity goal). The grep facts above are inputs to re-verify independently (guard #5), not gospel.
- **Impl**: FileList DIFF. Likely EDITED: `src/lib/loader.cpp` (slot assignment + the 4 `<<r.id`→`<<slot` sites + copy_rule_counters_forward keyed-by-id + slot→id exposure), `src/lib/config.cpp` (id-range relaxation per Q2, if taken), `src/exporter/rule_counters_reader.{hpp,cpp}` (+ maybe `prom_format.cpp`) for slot→id labelling, possibly `src/common/mac_filter.h` (a NEW slot→id map decl per Q1 / kManagedMaps row), `src/bpf/mac_filter.bpf.c` ONLY if Q1 forces a new SEC(".maps") decl (datapath CODE must stay identical — a new userspace-only map the datapath never references is acceptable IFF the per-packet instruction stream is unchanged). NO most-specific-wins, NO N>64.
- **Tester**: the headline NEW test is the **counter-continuity-across-reorder** executable spec (apply ruleset → bump per-rule counters via injects → re-apply with a rule inserted/renumbered so slots shift → assert each **id's** counter VALUE survived the slot move, i.e. monotonic, not reset/jumped). Plus: datapath verdict-identity (existing fixtures still classify identically) + the existing rule_counters/oracle suite stays green. Negation control: a rule whose id is reassigned a different slot must still accumulate under its id.
- **Reviewer**: 5-point brownfield; **special attention**: (a) datapath verdict-identity — the per-packet instruction stream byte-identical (verifier reload rc=0; ideally the `.text`/prog bytes unchanged modulo any Q1 userspace-only map); (b) **PI-3.4b-2 counter monotonicity PRESERVED across slot reassignment** — the copy_rule_counters_forward-keyed-by-id is correct (guard #15); (c) the bit-position-opacity guarantee actually held (no datapath site started depending on id-value); (d) kManagedMaps arithmetic correct if a slot→id map was added (guard #10); (e) first-match-by-lowest-id priority UNCHANGED (slot assigned in id-sorted order); (f) no most-specific-wins / N>64 scope creep.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.21-1: datapath instruction stream stays byte-identical → **loader/userspace-only change; datapath CODE untouched**
The decoupling is a loader-lowering + userspace-reader change. The datapath already treats the bit position as an opaque slot (grep-confirmed). If Q1 requires a NEW `slot→id` map, it must be a map the **datapath never references** (userspace-written/read only) so the per-packet instruction stream is unchanged — verified by a verifier reload (rc=0) + a prog-bytes/verdict-identity check. **If the architect finds ANY datapath site that does depend on id==bit (opacity violated), STOP and escalate to me** — that flips the slice from loader-only to a datapath change (different risk/spike profile).

### HG-mvp-4.21-2: counter monotonicity PRESERVED (PI-3.4b-2) → **copy_rule_counters_forward becomes keyed-by-id (load-bearing Scope item, not a side-effect)**
This is the whole point of the slice. The existing PRESERVE helper (guard #15) must remap old-slot-of-id → new-slot-of-id so a rule's accumulated counter follows its **id** across a slot reassignment. List it as an explicit Scope item (the MVP-3.4d lesson: the copy-forward helper gets missed when treated as a populate side-effect).

## Open mechanism questions (architect decides; document in §5.61)

### Q1: where does the `slot → id` mapping live (for the exporter reader), keeping the datapath byte-identical?
- **A1 — NEW userspace-only pinned map** (the hld's choice, "slot→id table sized under kManagedMaps[]"): a small ARRAY the loader writes + the exporter reads; datapath never references it → instruction stream unchanged. Cost: +1 kManagedMaps row (guard #10), a pin path, atomic-swap parity question (does it need a/b parallel shape like the others, or is it apply-atomic via a single write?).
- **A2 — add `rule_id` to `struct rule_entry`** (rules_inner value): the reader derives slot→id from the existing rules pin. Cost: changes the rule_entry layout → the datapath `.o` value_size grows (NOT byte-identical even if code is) — heavier verifier/ABI surface; weighs against HG-1.
- **A3 — derive slot→id another way** (e.g. a sidecar JSON the exporter already emits, or the loader exposing it through the existing sidecar surface).
- **Recommendation**: architect's realizability call. A1 matches the hld and most cleanly preserves datapath-code-identity, at the cost of one new userspace-only map; A3 may avoid even that if a sidecar surface already carries id↔slot. Pick the least-datapath-invasive that the exporter can consume per-scrape.

### Q2: relax the `id < 64` config validation (free sparse numbering) in THIS slice, or keep it minimal?
- **A1 — relax**: change the cap from `id < 64` to **`count ≤ 64` (the slot space) + `id` any u32** — this is what actually delivers the operator value (sparse ids, insert-without-renumber). Adds the dense-slot-count check.
- **A2 — keep `id < 64` for now**: ship only the slot/counter decouple; defer the id-range relaxation. Smaller diff, but the operator still can't use sparse ids > 63 (partial value).
- **Recommendation**: **A1** — the sparse-numbering freedom is the operator-visible payoff the PO greenlit; the slot space is what now carries the ≤64 cap. Architect trims to A2 if the validation change materially widens risk.

### Q3: slot assignment order → **id-sorted (dense rank), preserving first-match-by-lowest-id**
Confirm: `slot[r] = rank of r in ascending-id order`. Keeps `ffsll(acc)-1` = lowest-id survivor (priority UNCHANGED). This is the hld's S.1 default; document explicitly so the reviewer can assert priority parity.

## Scope (concrete items — FileList DIFF, UPPER-BOUND)
1. **Loader slot assignment** (`src/lib/loader.cpp`): compute dense `slot` per rule (id-sorted rank); change the 4 `1ULL << r.id` sites → `<< slot`; populate `rules_inner[slot]`, the axis-map bits, and `rule_counters[slot]` by slot.
2. **Counter copy-forward keyed-by-id** (`src/lib/loader.cpp` `copy_rule_counters_forward` + the apply path): remap old-slot-of-id → new-slot-of-id so per-id counters survive (HG-2, guard #15, PI-3.4b-2).
3. **slot→id exposure** (per Q1): NEW map / struct field / sidecar — whatever the architect picks; the exporter must label counters by stable id.
4. **Exporter reader** (`src/exporter/rule_counters_reader.{hpp,cpp}` + maybe `prom_format.cpp`): report each counter under its stable `id` (slot→id remap).
5. **Config id-range** (`src/lib/config.cpp`, per Q2): relax `id<64` → `count≤64` + sparse id.
6. **NEW test**: counter-continuity-across-reorder (the executable spec) + datapath verdict-identity confirmation.
7. **design.md §5.61** + (if Q1=A1) kManagedMaps row + a NEW PI for the slot/id contract.

## Out of scope (explicit)
- **Most-specific-wins / RFC-8955 ordering (S.3)** — B30 unblocks it but does NOT implement it; priority stays first-match-by-lowest-id.
- **N > 64 rules** — the slot space stays ≤64 this slice; only the *id range* may be freed (Q2).
- Any datapath classification/semantic change; any new match axis; any schema/VERSION bump.
- B26 (pass_cidr→pass_rule — fold into a stat-enum slice), B27 (exporter DoS — security, HELD).

## Definition of done
- §5.61 (MVP-4.21) amendment in design.md (Q1/Q2/Q3 resolutions + the slot/id contract + a NEW PI).
- Datapath verdict-identity: existing fixtures classify identically; verifier reload rc=0; per-packet instruction stream unchanged (datapath code byte-identical; at most a userspace-only map added per Q1).
- PI-3.4b-2 counter monotonicity PRESERVED across slot reassignment (the new test proves it).
- Full ctest green (96/96 + the NEW reorder test = 97, flagged).
- NO most-specific-wins, NO N>64, NO schema/VERSION change.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang-19/C++23 + the BPF toolchain (existing).
- Runtime: veth + bpffs + sudo (existing fixture).
- Kernel: dev 6.1 (existing); no new kernel feature.

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

## Pre-brief sanity check (per mint-hld-scope-discipline)
**Carry-over from a DISCHARGED prior /mint-hld round (Option 4) — NOT a fresh-hld case.** The design space (id-triple-coupling) was enumerated + an option chosen by the 2026-05-30 hld round; the two gating open-Qs are now both discharged (PO greenlit reordering; bit-position-opacity grep-confirmed NO datapath id==bit dependency). The remaining decisions (Q1 slot→id location, Q2 id-range, Q3 sort order) are **realizability calls the architect owns**, not multi-axis product forks — no genuinely-external-value decision left for the user beyond the greenlight already given (PO-filter: the operator value = reorder-without-counter-break, already affirmed). **No new /mint-hld.** Single-architect. **Careful (not additive)** — heaviest slice since S4 cidr6; the load-bearing risk is the counter-copy-forward-by-id (PI-3.4b-2) + the datapath-opacity guarantee, both flagged. **No spike needed IFF opacity holds** (datapath code unchanged → no verifier-floor question); the verifier reload is a normal test-phase check, not a pre-slice spike. If the architect's Phase-A grep REFUTES opacity (a datapath site depends on id==bit), escalate — that would warrant a spike.

## Notes for architect Phase A code-grep discipline (guard #5 — re-run independently)
- `grep -nE '1ULL?\s*<<\s*.*\.id|<< r\.id|<< slot' src/lib/loader.cpp` — confirm the 4 bit-assignment sites (do NOT trust the count blind; verify it's 4 and they're all the populate loops).
- `grep -nE 'first_set_u64|ffsll|bump_rule|rules_inner.*&rid|rule_counters' src/bpf/mac_filter.bpf.c` — **re-verify bit-position opacity**: `rid` is an opaque dense index, never compared to a config id value; `struct rule_entry` carries no id. This is the load-bearing guarantee for HG-1; if it fails, escalate.
- `grep -nE 'copy_rule_counters_forward' src/lib/loader.cpp` — the PRESERVE helper (guard #15) that must become keyed-by-id.
- `grep -nE 'rule\.id|seen_ids|XDPMF_ALLOWLIST_MAX|< 64' src/lib/config.cpp` — the id-range validation (Q2).
- `grep -nE 'rule_counters|read_rule_counters|slot|rule_id' src/exporter/rule_counters_reader.*` — where the exporter labels counters (slot→id remap site).
- `grep -cE 'kManagedMaps' src/lib/loader.cpp` + read the table — if Q1=A1 adds a map, the count + all walking loops update (guard #10).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #15 (PRESERVE-vs-RESET atomic-swap copy-forward)** — THE central guard: copy_rule_counters_forward must be keyed-by-id (PRESERVE PI-3.4b-2 across slot move). Prior=PRESERVE, post=PRESERVE-UNCHANGED-semantic-but-remapped-index. Brief lists it as explicit Scope item #2, NOT a populate side-effect (MVP-3.4d precedent).
- **Guard #10 (catalog arithmetic)** — if Q1=A1 adds a `slot→id` map, kManagedMaps 38→39 + every walk loop (clear/pin/reuse) updates in lockstep.
- **Guard #5 (Phase A grep discipline)** — architect re-runs the opacity + bit-site greps above; the datapath-byte-identity claim is load-bearing.
- **Guard #12 (RESOURCE_LOCK)** — the NEW reorder test touches veth+bpffs+apply → needs `RESOURCE_LOCK xdp_fixture` (+ build_cpu if it compiles).
- **Operative-semantic discipline** — the "4 bit sites" / "kManagedMaps 38→39" / scope-item counts are SHOULD-level orientation; the architect's realizability call (Q1 mechanism, exact site count) is authoritative; coverage-preserving deviations are `inline-merge`.
- **Guard #11 (VERSION-bump propagation)** — N/A (no bump).
