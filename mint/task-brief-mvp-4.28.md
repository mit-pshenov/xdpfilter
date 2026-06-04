# Task brief — MVP-4.28 / B34a: datapath helper-extraction (de-monolith part a) (brownfield)

## Goal

`src/bpf/xdpfilter.bpf.c` (1326 lines) carries the same idioms triplicated
across its three family arms (IPv4 / IPv6 / non-IP). Extract the genuinely-
shared idioms into `static __always_inline` helpers / macros so each arm
shrinks to its legitimately-distinct head. This is **part (a) of the B34
de-monolith** (BACKLOG B34); **part (b), the `.bpf.c`/`.h` module split into
`ipv4_match.h`/`ipv6_match.h`/`vlan.h`/`classifier.h`/`maps.h`, is a SEPARATE
follow-up slice** — its FileList only becomes definable once extraction has
shrunk the arms (split-before-extract just scatters spaghetti; #4-before-#5).

The extraction targets, ranking, and the rent-payers (what must NOT be
collapsed) are the **discharged output of the `/mint-simplify` subtractive
pass** (workflow `wf_37ca9d53`, synth verdict; the doc-corpus prerequisites
it surfaced shipped in `0d7f415`). The slice is **byte-identical pure
refactor**: every fold must preserve the datapath bytecode, arbitrated by the
**brand-new B37 insn gate** (`T_INSN_BASELINE_GATE.sh` + `T_PROD_VERIFIER_LOAD.sh`,
objdump xdp-section line-count `== 3658`) re-run **after each fold**. No
schema / axis / map / VERSION change; PI-7 continues; `git diff -- src/lib
src/common src/cli src/exporter` stays ∅ (only `src/bpf/xdpfilter.bpf.c`
changes, plus possibly new `.h` includes IF the architect chooses to land a
helper in a header — but no module split this slice).

## Context: prior work

- Prior brief archived `mint/task-brief-mvp-4.27.md` (B37 gates — the oracle this slice leans on).
- Recent: MVP-4.27/B37 (`bb62891`, the 3658 gate now has teeth) → corpus-refresh (`0d7f415`, design.md §2 no longer misleads on paths).
- Design tail: `mint/design.md` §5.67 (B37); guards #1..**#35** (max).
- Source of the extraction list: `/mint-simplify` run `wf_37ca9d53` (synth verdict + SESSION writeup). **Its line numbers are APPROXIMATE** (cited up to :1305 vs the file's 1326 lines) — architect MUST re-grep the live tree.
- Brief-author Phase 2 grep verification (this brief): dispatch-tail `rules_outer` lookup = **exactly 3** (triplication confirmed); 3 family arms confirmed (`bpf.c:6`); `BITVEC_NUM_AXES 9` + `BV_AXIS_*` confirmed (`xdpfilter.h:195-200`); a shared counter-bump helper already exists (`bpf.c:471`, §5.31) — precedent for in-file `__always_inline` sharing.
- PI continuity: PI-7 (`loader.hpp`/`config.hpp` zero-diff) continues trivially (not touched); **PI-DATAPATH-IDENTICAL** (xdp 3658) is the load-bearing contract of this slice.

## Workflow rules (brownfield)

- **Architect**: read `mint/design.md` §5.43 (the 9-axis AND model), §5.55 (ext-walk), §5.67 (the gate), + this brief. EDIT design.md in place; append §5.68. **Re-grep the live `src/bpf/xdpfilter.bpf.c`** for every extraction target (line numbers in this brief are approximate-from-simplify). Produce a FileList DIFF + the per-fold extraction spec + §6.5 Preserved invariants. Decide Q1/Q2.
- **Impl**: FileList per mode. ONLY `src/bpf/xdpfilter.bpf.c` (+ optionally a new in-tree `.h` IF the architect lands a helper in a header — but NO module split). **Re-run the 3658 gate after EACH fold**; do NOT batch-then-pray. If a fold cannot hold 3658 byte-identical, invoke the per-fold FALLBACK (drop that fold from the slice — the others still land) and SendMessage architect. `git diff -- src/lib src/common src/cli src/exporter` must stay ∅.
- **Tester**: the B37 gates ARE the regression oracle — confirm they re-run green at 3658 post-extraction; confirm full-suite no-regression (101/103 + B37's tests). NO new test needed unless a fold changes an observable (it must not). Negation already lives in the B37 gates.
- **Reviewer**: 5-point brownfield. **Special attention**: (a) byte-identity — xdp 3658 after the full extraction (re-run the gate yourself, don't trust the log); (b) the rent-payers (below) were NOT collapsed; (c) provenance anchors preserved per guard #33 (one canonical copy migrates onto each helper); (d) `git diff -- src/{lib,common,cli,exporter}` ∅; (e) the per-arm 9-term AND asymmetry intact.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.28-1: scope = extraction ONLY; module split DEFERRED → **extraction only**
The 5 folds (#1/#2/#3/#12/#13). The `.bpf.c`/`.h` module split (`ipv4_match.h` etc.) is a SEPARATE follow-up slice briefed against the POST-extraction tree (boundaries emerge only after the arms shrink). Bundling both = an oversized, hard-to-review cycle + a premature split FileList.

### HG-mvp-4.28-2: VERSION bump → **NO bump (stay 0.16.0)**
Internal byte-identical refactor; zero operator-visible surface. (guard #11 N/A.)

### HG-mvp-4.28-3: byte-identity contract + per-fold FALLBACK → **3658 after EACH fold; a fold that can't hold it is DROPPED, not forced**
Pure code-movement ⇒ both verdict-identity AND byte-identity expected. The gate is re-run after each fold. **Per-fold FALLBACK** (pre-negotiated, NOT a rework trigger): if a fold's `__always_inline`/macro realization shifts the xdp section off 3658 (esp. #2's struct-array-vs-named-scalars stack layout), impl first tries an alternate realization; if none holds 3658, that ONE fold is dropped from this slice and noted — the remaining folds still ship. A dropped fold is `inline-merge`, not `[REGRESSION]`.

## Open mechanism questions (architect decides; document in §5.68)

### Q1: #3 inner-lookup-or-deny realization — macro vs helper
The idiom does `lookup(inner); if (!p) { bump(DROP_DENY); return XDP_DROP; }` — a BPF helper **cannot** early-return `XDP_DROP` from the caller. mint-simplify's defense WEAKENED this from helper→**macro**.
- **A1**: a statement macro `LOOKUP_INNER_OR_DROP(...)` that expands in the caller scope and `return XDP_DROP`s from there.
- **A2**: an `__always_inline` helper returning a sentinel the caller checks then returns on (keeps it a function, adds one `if` per call site).
- **Recommendation**: **A1** if it holds 3658 and reads cleanly; A2 as the fallback if the macro is too sharp-edged. Architect owns the exact form (carry ONE canonical §5.26/§5.27 verifier-required-NULL note onto it).

### Q2: #2 wildcard-load helper signature
- **A1**: `static __always_inline void load_wildcards(__u32 active, __u64 wc[BITVEC_NUM_AXES])`, index `wc[BV_AXIS_*]` (simplify's suggestion).
- **A2**: individual `__u64*` out-params (closer to current named scalars → lower stack-layout risk).
- **A3**: a small `struct` out.
- **Recommendation**: **A1** for the cleanest −LOC, BUT this carries the documented **stack-layout risk** (array-vs-named-scalars may shift insns). Architect/impl pick whichever HOLDS 3658; if A1 breaks it, A2 is the byte-safe fallback. The gate decides, not a read. (Leave the already-hoisted `eth`/`wc_eth` 9th half alone.)

D-mvp-4.28-* (tactical, architect documents): exact helper names/signatures for #1/#12/#13, fold ordering + commit granularity (recommend #1→#2→#3→#12→#13, gate after each), where each migrated §-anchor lands.

## Scope (cycle — concrete items; line numbers APPROXIMATE, architect re-greps)

### Item #1 — dispatch-match tail → `dispatch_match()` (do FIRST, cleanest)
**Where**: `src/bpf/xdpfilter.bpf.c`, the 3 `rules_inner_map = bpf_map_lookup_elem(&rules_outer …)` → first-set → bump → DROP/PASS tails (byte-IDENTICAL ×3, confirmed count=3).
Extract `static __always_inline int dispatch_match(__u64 acc, __u32 active)` → 3 arms become `if (acc) return dispatch_match(acc, active);`. Carry the HG-mvp-4.3-4 first-match-by-id comment onto the helper. ~−27 LOC.

### Item #2 — 8-axis wildcard load → `load_wildcards()`
**Where**: the per-arm `wc_dst…wc_src6` load blocks (×3: v4 / v6 / non-IP). Leave the hoisted `eth`/`wc_eth` 9th half. ~−80…110 LOC. **Stack-layout risk — Q2 + HG-3 FALLBACK govern.**

### Item #3 — inner-lookup + NULL→DROP_DENY → `LOOKUP_INNER_OR_DROP` macro
**Where**: the per-axis `lookup; if(!p) drop_deny` idiom (×3). MACRO not helper (Q1). ~−25…42 LOC.

### Item #12 — src-MAC exact-HASH fetch → `mac_axis()`
**Where**: the 3× ~7-line MAC inner-fetch idiom. ~−12 LOC. Bundle with the pass.

### Item #13 — TCP/UDP dport-read → `read_dport()`
**Where**: the v4 + v6 dport reads (2 copies; non-IP has no L4). Return `has_port`; **preserve the MALFORMED bounds-miss branch 1:1** via an out-of-band sentinel → `STAT_DROP_MALFORMED`. ~−12 LOC.

## Out of scope (explicit) — RENT-PAYERS, do NOT touch / collapse
- **The module split (part b)** — separate follow-up slice (briefed post-extraction).
- **The THREE family arms themselves stay split** — they genuinely differ (v4 ihl L4 offset; v6 `MAX_EXT_HOPS` ext-walk + /128 LPM; non-IP no L3/L4). Extract shared **tails/loads**, NOT the heads.
- **Per-arm 9-term `acc` AND-expressions** — each arm zeroes a DIFFERENT axis subset (cross-family exclusion, **PI-mvp-4.13-CROSS-FAMILY**); the asymmetry IS the family semantics. Collapsing reintroduces zeroed lookups (breaks 3658) or adds masks costing more than the dup. **Do NOT blanket-collapse the AND-composition comments — they meaningfully differ per arm.**
- **`XDPMF_FFS_FALLBACK` #ifdef branch** (§5.42) — verifier-floor portability hatch, conditionally-dead by design. KEEP.
- **Inline `ETH_P_*`/`IPPROTO_*` `#ifndef` defs** (`bpf.c:43-47`+) — no header to include in the BPF-target build. KEEP.
- **loader FORK-merges** (`close_prefixes`/`populate_bitvec` templates) — a SEPARATE later **loader.cpp** slice (verdict-identity, different file/oracle). NOT this byte-identical `.bpf.c` slice.
- **B35** (wildcard `ruleset_state` pack — perf, verdict-identity), **B36** (64-rule ceiling), mirror/redirect — later.
- Any `src/{lib,common,cli,exporter}` change. VERSION bump. Schema/axis/map change.

## Definition of done
- §5.68 amendment in `mint/design.md` (per-fold extraction spec + §6.5 PI rows + the migrated anchors).
- PI-7 continues; **PI-DATAPATH-IDENTICAL: xdp section == 3658 after the full extraction** (the B37 gate green).
- `git diff <base> -- src/lib src/common src/cli src/exporter` = ∅; only `src/bpf/xdpfilter.bpf.c` (+ any new in-tree `.h` IF a helper lands in a header, no split) changed.
- Full ctest no-regression: 101/103 baseline (2 known env-fails BY NAME — `T_EXPORTER_EXITS_6_ALL_IFACES_EACCES`, `T_LOG_JSON_EXPORTER_EVENTS`) + B37's gates green at 3658.
- No VERSION bump.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang/libbpf as-is; `llvm-objdump-19` for the gate (already used by B37).
- Runtime: `bpftool` + passwordless sudo for `T_PROD_VERIFIER_LOAD` (SKIP-gated).
- Kernel/platform: dev 6.1; the verifier must still accept the post-extraction object (`__always_inline` ⇒ expected, but the standalone-load gate confirms).

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
**Mechanical/single-axis → single-architect `/mint-dev`, no `/mint-hld`.** The design-space exploration was ALREADY done by `/mint-simplify` (it enumerated the folds, ranked by replication, ran an adversarial keep-defense that produced the rent-payer list + the helper→macro correction). What remains is bounded extraction against a discharged list with a built oracle. The one real risk (#2 stack-layout) is an impl-time, gate-arbitrated realizability question with a pre-negotiated FALLBACK — NOT a multi-axis design fork. PO-filter (POF-M2): no decision here carries external/product value for the user; all engineering, discharged in-brief or routed to the architect. Scope-split (extraction now / module-split later) derived from the FileList-can't-exist-yet constraint, not punted.

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author ran these (evidence above); architect RE-RUNS on the live tree (simplify line numbers are approximate — bpf.c is 1326 lines, simplify cited to :1305):
- `grep -n 'rules_inner_map = bpf_map_lookup_elem(&rules_outer' src/bpf/xdpfilter.bpf.c` — the 3 dispatch tails (#1).
- `grep -nE 'wc_dst|wc_src6' src/bpf/xdpfilter.bpf.c` — the wildcard load blocks (#2); confirm the 3 arms + the hoisted 9th half to LEAVE.
- `grep -nE 'DROP_DENY|drop_deny|bpf_map_lookup_elem.*inner' src/bpf/xdpfilter.bpf.c` — the inner-lookup-or-deny idiom (#3).
- `grep -nE 'dport|src_mac|mac_inner' src/bpf/xdpfilter.bpf.c` — #12/#13.
- `grep -nE 'BV_AXIS_|BITVEC_NUM_AXES' src/common/xdpfilter.h` — axis indices for the `wc[]` helper.
- Confirm at end of EACH fold: `llvm-objdump-19 -d --section=xdp build/xdpfilter.bpf.o | grep -cE '^\s+[0-9a-f]+:'` == 3658, AND `git diff --stat -- src/lib src/common src/cli src/exporter` empty.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #5 (Phase A code-grep discipline)** — always; architect re-greps the live tree (the simplify line numbers are stale-ish).
- **Guard #33 (D-ANCHOR-PRESERVE / traceability)** — load-bearing here: on extraction, ONE canonical copy of each migrated §-anchor (HG-mvp-4.3-4 first-match, §5.26/§5.27 verifier-NULL, §5.42 FFS, PI-mvp-4.13-CROSS-FAMILY) lands on its helper; do NOT drop anchors, do NOT blanket-collapse the per-arm AND comments (they differ per arm).
- **Guard #35 (a print-only gate is decorative / the insn gate is the arbiter)** — this slice is the FIRST real consumer of B37's teeth: the 3658 gate is RUN, not read; byte-identity is asserted by the gate, never from a code read (esp. #2).
- **Guard #9 (helper-location duplication-over-extraction)** — INVERTED context: here extraction IS the goal, but the helpers are in-file `static __always_inline` (single TU), not cross-file — so #9's "duplicate don't extract across files" does not fire; the module split (part b) is where cross-file sharing gets decided.
- **Guard #11 (VERSION-bump literal propagation)** — N/A (no bump).
- **Guard #12 (RESOURCE_LOCK)** — N/A (no new ctest; B37 gates already correctly locked/unlocked).

> Operative-semantic note: the −LOC figures (−27/−90/−35/−12/−12) and line ranges are SHOULD-level orientation, not contracts; the authoritative contract is **xdp 3658 byte-identical + the rent-payer list intact**. A fold landing fewer/more lines, or dropped under the HG-3 FALLBACK, is `inline-merge`.
