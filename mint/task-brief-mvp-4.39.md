# Task brief — MVP-4.39 / B47: sanitary-day code-subtraction harvest (brownfield)

## Goal

A **pure-subtractive** sanitary-day slice harvesting four small, independent
items from the 2026-06-07 `/mint-review` + `/mint-simplify` pass. Three are
simplify BEDROCK subtractions (dead-symbol delete, function merge, dup-block
extract); one is the PO-approved queued B46 cosmetic polish (review TEST-C1).
No new capability, no schema change, no datapath touch, **no VERSION bump**
(mirrors B43–B45 staying at 0.17.0). Net target ≈ **−30 LOC + 1 small
file-local helper**, **−1 dead public symbol**, **−1 lockstep drift hazard**.

This slice deliberately does NOT extract a shared `axis_format` module (the
review ARCH-H1/CQ-H1 "High"): that was declined this pass on rule-of-three /
guard #9 grounds — the two axis-formatter copies (`sidecar.cpp`,
`map_image.cpp`) are exactly **2** consumers, below the rule-of-three escape
valve (D-3.4f-1). B46 lands **in place** instead. Re-charge the extraction
when a 3rd consumer appears.

## Context: prior work

- All prior briefs: archived in `mint/task-brief-*.md` (prior = `task-brief-mvp-4.38.md`, B45 human view).
- Existing design: `mint/design.md` §5.78 (B45 dry-run human view) is the most recent section; §5.78.4(a) defines the ethertype value-form B46 amends.
- Source of items: `/mint-review` report + `/mint-simplify` synth verdict (2026-06-07). simplify BEDROCK #1/#2/#3 + review TEST-C1/B46.
- Phase-2 brief-author grep verification: ran below (see Phase 2 output); every literal CONFIRMED, zero discrepancies.
- PI continuity: **PI-7** (loader.hpp byte-equivalence) continues — item 3 is same-TU in `loader.cpp`, no header change. **PI-mvp-4.37-FAILCLOSED** continues — item 1 deletes only the unused `active_writer()` getter, never the fail-closed wrappers. BPF datapath byte-identity (**insn 3477**) holds trivially (no `src/bpf` touch). dryrun golden byte-identity holds (B46 touches only the human view, not the machine map-dump golden).

## Workflow rules (brownfield)

- **Architect**: read `mint/design.md` §5.77–§5.78 + the guard catalogue (#9, #13, #15); EDIT design.md in place; append a §5.79 amendment covering the four items + the explicit `axis_format`-extraction-declined decision (record as a D-* with the rule-of-three/guard-#9 rationale so the next reviewer doesn't re-raise it). Resolve HG-mvp-4.39-1 (item-3 error-string handling).
- **Impl**: FileList below; pure subtraction + 1 helper + the B46 2-line format change. NO new abstractions beyond the file-local helper.
- **Tester**: NO new ctest needed (all items are behavior-preserving except B46's human-view spelling). EDIT `tests/T_CLI_APPLY_DRYRUN.sh` for the B46 grep (two sites). Confirm the existing suite stays green; confirm `dryrun_image.golden` is UNCHANGED (machine image untouched).
- **Reviewer**: 5-point brownfield framework. Special attention: (a) `active_writer()` truly has zero callers post-delete; (b) `parse_prefix` merge preserves the caller-side message catalogue byte-identical; (c) the `loader.cpp` extraction keeps both populate paths behaviorally identical AND leaves `copy_rule_counters_forward` EXPLICIT (guard #15); (d) B46 changed every `fmt_ethertype` format string + its comment + both test sites + the §5.78.4(a) design prose, and the golden is unchanged; (e) PI-7 — `git diff` on `loader.hpp` is EMPTY.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.39-1: item-3 populate-block error-string handling → **canonicalize both forms to one**
The two duplicated blocks throw slightly-divergent `LoadFailed` strings:
- reattach: `"action_table fd unavailable (reattach)"` / `"redirect_devmap fd unavailable (reattach)"`
- fresh:    `"action_table map fd unavailable"` / `"redirect_devmap map fd unavailable"`
They differ in BOTH the word `map` and the `(reattach)` suffix — not a clean stem+suffix.
**Verified: NO test pins these strings** (`grep -rn "fd unavailable" tests/` → empty). So the extracted `populate_shared_maps()` may canonicalize both to a single form (e.g. `"<map> map fd unavailable"`) — simplest, and these are internal throws on an fd-unavailable condition that does not occur in practice. **Default: canonicalize.** Architect MAY instead preserve the exact two forms via a `const char* ctx` label param if they judge the diagnostic divergence worth keeping — either is acceptable since nothing observes them; prefer the lower-LOC option.

### HG-mvp-4.39-2: B46 rendering site → **in place in `map_image.cpp`, NOT via a shared formatter** (locked)
The shared-`axis_format` extraction is declined this pass (rule-of-three: 2 consumers < 3; guard #9 duplication-over-extraction is cited inline at `map_image.cpp:49-51`). This is settled, not an open question — architect records it as a D-* so it is not re-litigated. B46 = a 2-line format-string change where the renderer already lives.

## Open mechanism questions (architect decides; document in §5.79)

None rise to a Q-tier mechanism choice — every item is mechanical with a verified single shape. (HG-mvp-4.39-1 is the only genuine fork and it is defaulted with grep evidence.)

## Scope (cycle 1 — concrete items)

### Item B47-1 — delete dead `active_writer()` getter
**Where**: `src/lib/map_writer.cpp` (def), `src/lib/map_writer.hpp` (decl + comment).
- Delete the def `MapWriter* active_writer() { return g_active_writer; }` (currently `map_writer.cpp:57`).
- Delete the decl `MapWriter* active_writer();` (currently `map_writer.hpp:63`).
- Trim the comment at `map_writer.hpp:60-61`: `"Install/inspect the process-global active writer..."` → `"Install the process-global active writer..."` (the inspect getter is gone).
- **KEEP** `set_active_writer` (3 live callers: `map_writer.hpp:123-124` RecordingScope ctor/dtor, `live_map_writer.cpp:59` install). **Verified zero callers** of `active_writer()` tree-wide.
~−2 LOC, −1 dead public symbol.

### Item B47-2 — merge `parse_prefix` / `parse_prefix6`
**Where**: `src/lib/cidr.cpp` (anonymous-namespace helpers + 2 call sites).
- The two helpers (currently `:42` v4 ceiling 32, `:57` v6 ceiling 128) are byte-identical except the ceiling constant and a comment. Merge into one `parse_prefix(std::string_view s, int ceiling) noexcept`.
- Callers: `parse_cidr_v4` (currently `:110`) passes `32`; `parse_cidr_v6` (currently `:195`) passes `128`.
- Diagnostics live caller-side (the callers throw the distinct "empty prefix" vs "out of range" messages) → **message catalogue preserved byte-identical**. These helpers are file-local (anon namespace); no external/test consumer.
~−10 LOC.

### Item B47-3 — extract file-local `populate_shared_maps()` in `loader.cpp`
**Where**: `src/lib/loader.cpp` — the two duplicated `action_table` + `redirect_devmap` fd-get-and-populate blocks (reattach path currently `~:1676-1691`, fresh path currently `~:1797-1810`).
- Extract a file-local helper `populate_shared_maps(skel, cfg)` (exact signature architect's call) that does the `bpf_map__fd` + null-check + `populate_action_table` + `populate_redirect_devmap` for both shared maps.
- **Same TU** → guard #9 (cross-file duplication-over-extraction) is INAPPLICABLE; this is a within-file dedup, allowed.
- **guard #15**: `copy_rule_counters_forward` and `materialize` stay EXPLICIT at both call sites — they are NOT pulled into the helper (PRESERVE-semantic boundary). The helper covers ONLY the two static shared maps.
- Error strings per HG-mvp-4.39-1.
- **PI-7**: no `loader.hpp` change — `git diff loader.hpp` must be EMPTY.
~−18 LOC net (+1 helper).

### Item B47-4 — B46 ethertype canonical 4-digit hex (in place)
**Where**: `src/lib/map_image.cpp` `fmt_ethertype` + comment; `tests/T_CLI_APPLY_DRYRUN.sh`; `mint/design.md` §5.78.4(a).
- `map_image.cpp:96`: BOTH format strings `0x{:x}` → `0x{:04x}` (the name-suffix form `"0x{:x}({})"` AND the bare `"0x{:x}"`). Rewrite the `:88-89` comment that currently says `"NO fixed-width leading zeros (0x806, not 0x0806)"` → the canonical-4-digit rationale.
- `tests/T_CLI_APPLY_DRYRUN.sh`: two sites — the `(3j)` comment at `:233` and the grep at `:234` (`ethertype=0x806` → `ethertype=0x0806`).
- `mint/design.md` §5.78.4(a): the ethertype value-form prose/table → 4-digit zero-padded (reverses the B45-r1 reconcile-DOWN to `0x806`).
- **Verified no collateral**: the only other `ethertype=` render sites are name-based (sidecar/prom emit `arp`) or already `0x{:04x}` (sidecar); `dryrun_image.golden:81` is the machine map-dump (`map=ethertype_bitmask_a` metadata) and does NOT render the human hex → **golden UNCHANGED**.

## Out of scope (explicit)

- **Shared `axis_format` module extraction** (review ARCH-H1/CQ-H1) — declined this pass (2 consumers < rule-of-three; guard #9). Re-charge at 3rd consumer.
- **SEC-L1** exporter systemd sandbox (deployment-gated, defense-in-depth).
- **PERF-M1** bound exporter scrape loops by live rule count (no forcing-function; own slice).
- **TEST-H1/H2** dryrun_human.golden + sanitizer `--dry-run` coverage — Batch C, separate additive slice (NOT this subtraction slice).
- Any VERSION bump (pure subtraction + cosmetic).

## Definition of done

- §5.79 amendment in `mint/design.md` (the 4 items + the D-* recording the declined extraction).
- PI continuity held: PI-7 (loader.hpp ∅), PI-mvp-4.37-FAILCLOSED, BPF insn 3477, dryrun golden unchanged.
- Existing ctest suite green; `T_CLI_APPLY_DRYRUN.sh` updated (B46 grep) and passing; `dryrun_image.golden` byte-unchanged.
- `active_writer()` gone (zero refs); `parse_prefix` single-arg→two-arg merged; `populate_shared_maps` extracted; B46 4-digit live.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies

- Build: clang-19 / libc++-19 / libbpf (unchanged).
- Runtime/kernel: none new.

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

**MECHANICAL.** Not multi-axis: each of the 4 items has a single verified shape that falls out of the simplify/review findings + a 30-second grep. No expensive-to-undo choice, no ≥3-option design space. The one fork (item-3 error strings) is defaulted with grep evidence (HG-mvp-4.39-1). No `/mint-hld` needed; single-architect `/mint-dev` is correct. NOT derived from a prior hld ladder → no ladder to re-discharge; PO-filter applied (no decision is on the user's plate — the declined extraction is engineering-doctrine, the error-string fork is internal).

## Notes for architect Phase A code-grep discipline

Brief author already ran these (all CONFIRMED 2026-06-07); architect re-verifies + extends:
- `grep -rn "active_writer" src/ tests/ include/` — confirm `active_writer()` (no args) has ZERO callers; `set_active_writer` has 3 (RecordingScope ×2, install_live_map_writer). Verify again post-delete.
- `sed -n '42,68p' src/lib/cidr.cpp` — confirm the two `parse_prefix*` bodies differ ONLY by ceiling (32/128) + comment; callers at the `parse_cidr_v4`/`parse_cidr_v6` bodies pass the ceiling.
- `grep -n "populate_action_table\|populate_redirect_devmap" src/lib/loader.cpp` — the two call blocks; confirm `copy_rule_counters_forward` sits OUTSIDE them (guard #15 boundary).
- `grep -rn "fd unavailable" tests/` — empty (HG-mvp-4.39-1 canonicalize is safe).
- `grep -n "0x{:x}\|ethertype" src/lib/map_image.cpp` + `grep -n "ethertype=0x" tests/T_CLI_APPLY_DRYRUN.sh` + `find tests -name dryrun_image.golden` — confirm golden has no human-hex ethertype line.
- Post-impl: `git diff --stat src/lib/loader.hpp` MUST be empty (PI-7).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **guard #5** (Phase A code-grep discipline) — always; architect repeats the greps above independently.
- **guard #9** (helper-location duplication-over-extraction via rule-of-three) — HEADLINE. (a) Item 3 is SAME-TU dedup → guard #9 (which governs cross-FILE duplication) does NOT block it. (b) The declined `axis_format` extraction IS a guard-#9 call: 2 consumers < 3, extraction premature. Record both as D-* so neither is re-litigated.
- **guard #13** (retired emit-site string ripple) — B46: the `ethertype=0x806` literal lives in `T_CLI_APPLY_DRYRUN.sh` (2 sites) — update both. Item-3 strings: verified no test ripple.
- **guard #15** (`copy_rule_counters_forward` PRESERVE boundary) — item 3 must leave the copy-forward + materialize EXPLICIT at both call sites; the helper covers ONLY the two static shared maps.
- **guard #33** (anchor preservation on comment moves) — item 3 moves §-tagged comments into the helper; keep the grep-able §5.29/§5.75 anchors. B46 rewrites the §5.78.4(a) comment; keep the §-tag.

(N/A this slice: guard #11 — no VERSION bump; guards #27/#28 — no cross-arm/header-walk axis change.)
