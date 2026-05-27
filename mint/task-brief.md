# Task brief — MVP-3.4d: `reset-counters` subcommand + `rule_counter` atomic-swap promotion (brownfield, CLI + loader)

## Goal

Ship the **counter management API** deferred from MVP-3.4b cycle 2 §7 OOS. Two coupled deliverables:

1. **NEW `xdpmacfilter reset-counters --iface X [--rule-id N]` subcommand** — explicit operator-initiated zero-write of `rule_counters` PERCPU_ARRAY. Without `--rule-id` flag = zero all 64 slots; with flag = zero only slot N. State requirement: iface MUST be attached (rule_counters pin exists at `${PIN_DIR}/<iface>/rule_counters`). Audit-stderr line at action time mirroring `bypass` shape. Closes the §7 OOS "counter zero / reset API" fence.

2. **`rule_counter` atomic-swap promotion (structural-only)** — promote `rule_counters` PERCPU_ARRAY to parallel ARRAY_OF_MAPS shape mirroring §5.34 4-axis pattern (rule_counters_outer + rule_counters_a + rule_counters_b). **PI-3.4b-2 counter-monotonicity-across-apply PRESERVED** (semantic UNCHANGED — counters survive `apply -f`); atomic-swap shape is structural prep for hypothetical future "reset-on-apply" semantic, NOT a behavior change this slice. Reset zeroing comes ONLY via the new CLI. **Architect Phase A MUST verify PERCPU-as-inner-of-ARRAY_OF_MAPS libbpf feasibility**; if NOT supported, architect peer-DM impl + fall back to "CLI-only, no atomic-swap promotion" (atomic-swap stays NEW OOS fence for future slice).

This is a small slice — estimate ~1-1.5 cycles. Honest about the trade-off: atomic-swap promotion without semantic shift is structural-only (architect-style "dead infra" pattern). User accepted this trade-off inline 2026-05-27 (Medium scope chosen over Narrow).

## Context: prior work

- All prior briefs archived in `mint/task-brief-*.md`. Most recent ancestor: `mint/task-brief-mvp-3.4b-c2.md` (cycle 2 — rules atomic-swap + datapath dispatch + schema cycle 2→3 shift).
- Existing design: `mint/design.md` §5.34 (MVP-3.4b cycle 2 amendment) — PI-29-3.4b-c2 + PI-13-3.4b-c2 + PI-30-3.4b-c2-schema established; 5 OOT inline-merge'd post-review-sweep round 1.
- Architecture doc: `mint/architecture-v2.md` — no dedicated `3.4d` row; this slice is surfaced as next-natural in §5.34 §7 OOS (design.md:10406-10419).
- Phase A code-grep verification: brief author ran the following before this brief was published — `grep -nE "subcommand|argv\[1\]" src/cli/cli.cpp`; `grep -nE "rule_counters|XDPMF_RULE_COUNTERS" src/common/mac_filter.h src/bpf/mac_filter.bpf.c src/lib/loader.cpp`; `cat src/cli/bypass.hpp` (pattern reference for new subcommand); `ls tests/T_CLI_*.sh`; `ls tests/fixtures/`; `grep -rln '0\.9\.0' tests/ src/ docs/ CHANGELOG.md`. See Phase 2 grep verification report in conversation log for full output. Notable findings: CLI dispatch is hand-rolled string-compare at `cli.cpp:308-330` (5th subcommand = trivial branch addition); bypass.hpp/cpp pattern is direct template for reset_counters.hpp/cpp; rule_counters declaration at `mac_filter.bpf.c:220-226` is single PERCPU_ARRAY (atomic-swap reshape feasibility uncertain — architect Phase A verifies); version 0.9.0 sites = exactly 3 (CMakeLists.txt, CHANGELOG.md, T_EXPORTER_METRICS_FORMAT.sh); T_CLI_HELP_VERSION.sh checks `--help` output (NEW fixture cross-reference per anti-misdiagnosis guard #13).
- PI continuity: PI-1..PI-34 preserved unchanged. PI-3.4b-1..PI-3.4b-8 carry-forward §5.31. PI-29-3.4b-c2 + PI-13-3.4b-c2 + PI-30-3.4b-c2-schema preserved §5.34. **PI-3.4b-2 counter-monotonicity-across-apply EXPLICITLY PRESERVED** — atomic-swap shape change is structural; semantic UNCHANGED. New PIs needed: PI-3.4d-1 (reset-counters CLI behavioral contract), PI-3.4d-2 (atomic-swap structural shape if shipped; or PI-3.4d-2-DEFERRED if architect determines PERCPU-as-inner not feasible). PI-7-3.4d-hpp = **10th consecutive ZERO-diff cycle target on loader.hpp**; PI-7-3.4d-cpp = **5th consecutive ZERO-diff cycle on config.hpp**.

## Workflow rules (brownfield)

- **Architect**: read §5.27 (CIDR axis precedent — direct mirror if atomic-swap ships), §5.29 (bypass subcommand precedent — direct template for new reset_counters subcommand), §5.31 (PI-3.4b-2 counter-monotonicity — preserved this slice), §5.34 (4-axis atomic-swap pattern — mirrored if PERCPU-as-inner feasible); EDIT `design.md` in place; append §5.35 (architect's call on §-number). Anti-misdiagnosis guards #5, #7, #9, #10, #11, #12, #13 all applicable (see footer). **Critical Phase A check**: PERCPU-as-inner-of-ARRAY_OF_MAPS libbpf feasibility — `bpftool prog load build/src/bpf/mac_filter.bpf.o /sys/fs/bpf/probe type xdp` smoke after a minimal reshape proof-of-concept. If NOT feasible → HG-3.4d-4 fallback (defer atomic-swap to future slice; ship reset-counters CLI only).
- **Impl**: FileList interpreted as regional-diff fence. Brownfield: only listed scopes within EDITED files touched; everything else byte-equivalent. NEW files at listed paths. PI-7-3.4d-hpp/cpp = ZERO-diff on loader.hpp + config.hpp (architect surfaces only if forced). [[impl-role-discipline]] holds — silent deviation forbidden; escalate via Phase B SendMessage to architect if PERCPU-as-inner doesn't pass verifier or libbpf rejects.
- **Tester**: NEW ctests target 3-4. EDITED ctests = 2 (T_CLI_HELP_VERSION per guard #13 + T_EXPORTER_METRICS_FORMAT per guard #11). Brief estimates are upper bounds.
- **Reviewer**: 5-point brownfield framework. Special attention items: (a) PI-3.4b-2 preservation (this is the load-bearing semantic check — if reviewer detects counter-clear-on-apply behavior, that's `[INVARIANT-VIOLATED]`); (b) HG-3.4d-4 fallback path if architect peer-DM'd impl into "CLI-only" mode — that's negotiated deviation per [[impl-role-discipline]], NOT spec drift; reviewer disposition `inline-merge` on atomic-swap-deferral if architect documented Phase A reasoning.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-3.4d-1: PERCPU zero-write mechanism → **`bpf_map_update_elem(rule_counters_fd, &rule_id, zero_per_cpu, BPF_ANY)`**

Stack-allocated `__u64 zero_per_cpu[libbpf_num_possible_cpus()] = {}` (zeroed by C ABI struct-init). Explicit + idiomatic libbpf pattern. Alternative `bpf_map_delete_elem` for PERCPU_ARRAY has subtle "kernel-side zero, not delete" semantic — less operator-explainable.

### HG-3.4d-2: `--rule-id N` optional argument

Without flag → zero all 64 slots (loop key 0..63). With flag → zero only slot N. Validation: `0 ≤ N < 64`, else `CliError` exit 1 + stderr `"reset-counters: --rule-id N out of range [0,63]"`.

### HG-3.4d-3: state requirement → **iface MUST be attached**

If pin `${PIN_DIR}/<iface>/rule_counters` absent → exit 1 + stderr `"reset-counters: no rule_counters pin at <path>; iface '<iface>' not attached?"`. Reuse existing exit code 1 (CliError); no new exit code this slice.

### HG-3.4d-4: `rule_counter` atomic-swap promotion → **SHIP (mirror §5.34 4-axis pattern)** — *with architect-Phase-A fallback*

Default ship: rule_counters_outer ARRAY_OF_MAPS[2] of rule_counters_a / rule_counters_b inner PERCPU_ARRAYs (each MAX=64 u64). kManagedMaps[] gains 3 entries, drops 1; bump_rule helper updated to look up `rule_counters_outer[active]` → `rule_counters_inner[rule_id]` → bump. **Architect Phase A MUST verify PERCPU-as-inner-of-ARRAY_OF_MAPS feasibility in our libbpf version** (uncertain). If verifier rejects OR libbpf rejects skel codegen → architect peer-DM impl + fall back to "CLI-only mode, defer atomic-swap promotion to future slice"; impl skips the BPF reshape work and only ships items C-1, C-2, C-3 (reset-counters CLI). This fallback path is documented as negotiated-deviation D-3.4d-* (architect adds).

### HG-3.4d-5: semantic post-atomic-swap → **PRESERVE-across-apply (PI-3.4b-2 UNCHANGED)**

Atomic-swap shape change is **structural-only**. Counters survive `apply -f` exactly as in §5.31 PI-3.4b-2; reuse_fd discipline extends to the new parallel pins. Reset zeroing is ONLY available via the new `reset-counters` CLI. This is operator-explainable: "Prometheus monotonicity holds; explicit reset is an explicit operator action".

### HG-3.4d-6: audit-stderr line for reset-counters → **mirror bypass shape**

Format: `xdpmacfilter: RESET-COUNTERS on <iface> by uid=<N> euid=<M> sudo_user="<X or empty>" rule_id=<N or "ALL">`. Single line. Fires AT action time, BEFORE the BPF map writes (consistent with bypass timing — operator sees the action announcement; subsequent BPF write failures show up as separate stderr errors).

## Open mechanism questions (architect decides; document in §<new>)

### Q1: `--rule-id N` range validation timing

- **A1**: CLI-parse-time (in `parse_reset_counters` in cli.cpp). Early reject, consistent with existing `--allow` MAC parse validation.
- **A2**: `reset_counters_main`-time. Slightly later; consistent with semantic-validation-after-syntax-parse separation.
- **Recommendation: A1** — early reject is operator-friendlier; matches existing `--allow` MAC + `--iface` validation timing.

### Q2: `reset-counters` without `--rule-id` semantics

- **A1**: Zero all 64 slots (loop). Operator-friendly batch.
- **A2**: Require `--rule-id` always (no batch). More explicit, less convenient.
- **Recommendation: A1** — batch is the common operator case; per-rule-id is the special case.

### Q3: atomic-swap shape if HG-3.4d-4 ships AND PERCPU-as-inner is feasible

- **A1**: Mirror §5.34 — `rule_counters_outer` ARRAY_OF_MAPS[2] of `rule_counters_a`/`rule_counters_b` inner PERCPU_ARRAYs.
- **A2**: Twin pins managed by active_idx-aware bump_rule (no outer map; BPF datapath chooses pin based on active_idx).
- **A3**: Single pin with cgroup-tagged active versioning (esoteric, unlikely).
- **Recommendation: A1** — direct §5.34 mirror, 4-axis pattern extended to 5-axis. Architect verifies feasibility Phase A.

### Q4: counter survival across `reset-counters --rule-id N` followed by `apply -f`

- **A1**: counter[N] stays 0 (zero-write persisted via reuse_fd discipline). Document as expected behavior.
- **A2**: Apply -f restores counter[N] to pre-reset value (would require reset to be config-aware — complex, no operator demand).
- **Recommendation: A1** — consistent with PI-3.4b-2 preserve-across-apply (the now-zero value is preserved).

## Scope (cycle MVP-3.4d — concrete items)

### Item C-1 — NEW CLI subcommand header: `src/cli/reset_counters.hpp`
**Where**: NEW file
- Mirror `src/cli/bypass.hpp` shape: `ResetCountersConfig` struct + `int reset_counters_main(const ResetCountersConfig&)` entry.
- Fields: `std::string iface`; `std::optional<std::uint32_t> rule_id` (or `int rule_id = -1` sentinel — impl picks).

### Item C-2 — NEW CLI subcommand impl: `src/cli/reset_counters.cpp`
**Where**: NEW file
- Mirror `src/cli/bypass.cpp` shape: emit audit-stderr line (HG-3.4d-6 format) → `bpf_obj_get` on `rule_counters` pin → branch on `rule_id`: single-slot zero-write OR loop 0..63 zero-writes via `bpf_map_update_elem` (HG-3.4d-1 mechanism).
- Error paths: pin not present (HG-3.4d-3); BPF errno propagates as `std::system_error` (loader exit-code mapping in main.cpp catch arm).

### Item C-3 — Wire reset-counters into CLI dispatch
**Where**: EDIT `src/cli/cli.cpp` + `src/cli/cli.hpp` + `src/cli/main.cpp`
- `cli.cpp`: add `parse_reset_counters` function (~30 LOC, mirror `parse_bypass`); extend subcommand dispatch at lines 308-330 with `else if (sub == "reset-counters") { return parse_reset_counters(rest); }`; extend `--help` text at lines 84+99+102 area with new subcommand line + flag descriptions.
- `cli.hpp`: `#include "reset_counters.hpp"`.
- `main.cpp`: add `run_reset_counters(const ResetCountersConfig&)` dispatcher (~5 LOC, mirror `run_bypass`).

### Item B-1 — BPF: `rule_counters` map atomic-swap reshape (IF HG-3.4d-4 ships)
**Where**: `src/bpf/mac_filter.bpf.c:212-226` + neighboring `bump_rule` helper
- Current single PERCPU_ARRAY `rule_counters` replaced with: `struct rule_counters_inner` template + `rule_counters_a` + `rule_counters_b` PERCPU_ARRAY instances + `rule_counters_outer` ARRAY_OF_MAPS[2] (Q3.A1).
- `bump_rule` extended: `rule_counters_outer[active] → rule_counters_inner[rule_id] → bump`.
- **IF architect Phase A determines PERCPU-as-inner not feasible**: skip this item entirely; only Items C-1/C-2/C-3 + L-1 ship.

### Item L-1 — Loader: `kManagedMaps[]` update (IF HG-3.4d-4 ships)
**Where**: `src/lib/loader.cpp:147-175`
- Remove `rule_counters` entry; add `rule_counters_a` + `rule_counters_b` + `rule_counters_outer` entries.
- New table count: 15 → 17 (12→14 non-alias + 1 alias preserved). Comment count update.
- **IF Item B-1 deferred**: skip this item; kManagedMaps[] stays at 15.

### Item L-2 — Shared header: NEW constants for atomic-swap pins (IF HG-3.4d-4 ships)
**Where**: `src/common/mac_filter.h`
- ADD `XDPMF_MAP_RULE_COUNTERS_OUTER_NAME = "rule_counters_outer"`, `XDPMF_MAP_RULE_COUNTERS_INNER_A_NAME = "rule_counters_a"`, `XDPMF_MAP_RULE_COUNTERS_INNER_B_NAME = "rule_counters_b"`.
- DELETE `XDPMF_MAP_RULE_COUNTERS_NAME = "rule_counters"` (single-map pin retires).
- **IF Item B-1 deferred**: skip; constants unchanged.

### Item L-3 — reset-counters opens the right pin (IF HG-3.4d-4 ships, must address active_idx)
**Where**: `src/cli/reset_counters.cpp`
- IF Item B-1 ships: reset-counters must zero BOTH inner_a + inner_b pins (because the active one may flip post-reset on next apply; zeroing both = consistent post-reset state regardless of next active_idx flip). OR zero only active, document semantic.
- IF Item B-1 deferred: reset opens single `rule_counters` pin; no active_idx awareness needed.
- Architect chooses behavior + documents D-3.4d-* tactical.

### Item T-1 — NEW ctest: `T_CLI_RESET_COUNTERS.sh`
**Where**: NEW; entry in `tests/CMakeLists.txt`
- Attach iface with config containing several rules → inject frames → verify rule_counters bumped → run `reset-counters --iface X` → verify all 64 slots = 0 (bpftool map dump).
- Negation: re-inject same frames → counters bump again from 0 baseline (not blocked).
- RESOURCE_LOCK: `xdp_fixture`.

### Item T-2 — NEW ctest: `T_CLI_RESET_COUNTERS_RULE_ID.sh`
**Where**: NEW; entry in CMakeLists
- Attach + bump multiple rule_counters[a, b, c] → run `reset-counters --iface X --rule-id <b>` → verify counter[b]=0, counters[a]+[c] unchanged.
- Negation: `--rule-id 64` (out of range) → exit 1 + stderr error match.
- RESOURCE_LOCK: `xdp_fixture`.

### Item T-3 — NEW ctest: `T_CLI_RESET_COUNTERS_NO_IFACE.sh`
**Where**: NEW; entry in CMakeLists
- DON'T attach iface; run `reset-counters --iface X` → exit 1 + stderr matches `"no rule_counters pin"` substring.
- Negation: attach, then run → exit 0.
- RESOURCE_LOCK: `xdp_fixture`.

### Item T-4 — NEW ctest: `T_RULE_COUNTERS_ATOMIC_SWAP.sh` (IF HG-3.4d-4 ships)
**Where**: NEW; entry in CMakeLists
- Apply config A → bump rule_counters in active inner → apply config B (active_idx flips) → bump in NEW active inner → verify both inner pins have expected values (one-deep rollback history per §5.26 atomic-swap contract).
- IF Item B-1 deferred: skip this ctest.
- RESOURCE_LOCK: `xdp_fixture`.

### Item E-1 — EDITED: `tests/T_CLI_HELP_VERSION.sh`
**Where**: existing test file
- Per anti-misdiagnosis guard #13 (fixture cross-reference): `--help` output gains 1 new subcommand line + new flag descriptions for `reset-counters`. Test's regex/grep assertions on `--help` content extend to match the new lines.
- Brief estimate: 5-10 LOC delta.

### Item E-2 — EDITED: `tests/T_EXPORTER_METRICS_FORMAT.sh`
**Where**: existing test file
- VERSION literal `0.9.0` → `0.10.0` at the assertion sites (`tests/T_EXPORTER_METRICS_FORMAT.sh:21,22,101,102` — confirmed Phase A grep). Per anti-misdiagnosis guard #11.

### Item V-1 — EDITED: `CMakeLists.txt`
**Where**: line 13 area (project VERSION)
- `VERSION 0.9.0 → 0.10.0`. NEW user-facing CLI subcommand = minor bump. DESCRIPTION metadata MAY track latest slice per /mint-briefer Phase 4.4 operative-semantic discipline.

### Item V-2 — EDITED: `CHANGELOG.md`
**Where**: top of file
- NEW `## [0.10.0] - 2026-05-NN` section per Keep-a-Changelog: Added (reset-counters CLI; atomic-swap if shipped), Changed (kManagedMaps[] catalog if shipped), Notes (PI-3.4b-2 preserve-across-apply still holds; explicit reset is operator-action-only), Preserved-invariants block.

## Out of scope (explicit)

Carry-forward unchanged from §5.34 §7 OOS unless noted. NEW fences:

- **`rule_counters` semantic shift to "reset-on-apply"** — explicitly NOT this slice. PI-3.4b-2 preserve-across-apply is the operator-grade Prometheus-monotonicity contract; flipping to reset-on-apply requires explicit operator demand that has not surfaced. Atomic-swap promotion is structural-prep ONLY.
- **`reset-counters --all-ifaces` / batch reset across multiple ifaces** — NEW FENCE. Per-iface this slice.
- **`reset-counters --dry-run`** — NEW FENCE. Always commits.
- **`reset-counters` without `--iface` (default to attached iface auto-discovery)** — NEW FENCE. `--iface` required.
- **`dump-counters` complementary read-side subcommand** — operator can already use `bpftool map dump pinned ${PIN_DIR}/<iface>/rule_counters` or query Prometheus `/metrics`. NEW FENCE.
- **Counter zero-on-detach** — detach currently preserves pin (D-3.1-4 reuse_fd discipline); not changing this.
- **Atomic-swap promotion fallback if HG-3.4d-4 PERCPU-as-inner NOT feasible** — atomic-swap stays NEW OOS fence for future slice; this slice ships reset-counters CLI only. Documented as negotiated-deviation if it happens.
- All §5.34 carry-forward OOS items: `action_table` promotion to parallel / action types beyond {PASS,DROP} / Q1.A new STAT bucket / drop-precedence-dedup / documentation pass — unchanged.

## Definition of done

- §5.35 amendment (or architect-named §-number) in `design.md` covering: reset-counters CLI contract; PERCPU zero-write mechanism; atomic-swap promotion shape (if shipped) OR deferral rationale (if fallback path); new PIs (PI-3.4d-1 reset-counters behavioral; PI-3.4d-2 atomic-swap structural OR PI-3.4d-2-DEFERRED).
- PI continuation: PI-1..PI-34 preserved; PI-7-3.4d-hpp/cpp ZERO-diff (10th/5th consecutive).
- **PI-3.4b-2 preserve-across-apply EXPLICITLY UNCHANGED**.
- ctest baseline 60 → **63** (+3 NEW T-1..T-3) OR **64** if T-4 ships per HG-3.4d-4.
- VERSION bumped 0.9.0 → 0.10.0; all test-body version literals follow.
- `mint/review.md` round-1 verdict = pass (5-point brownfield).
- One git commit per phase boundary.

## Dependencies

- Build: libbpf 1.x (no new dep). PERCPU-as-inner-of-ARRAY_OF_MAPS feasibility = architect Phase A check.
- Runtime: kernel BPF support for ARRAY_OF_MAPS + PERCPU_ARRAY (kernel 5.x+ — already required).
- Platform: bpffs mounted; existing trust_model contract; existing cap-set (CAP_BPF + CAP_NET_ADMIN for loader).
- No new caps required (reset-counters does `bpf_obj_get` + `bpf_map_update_elem` — covered by existing CAP_BPF).

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       []
  tester:     []
  reviewer:   []
```

(No language/platform packs — established 17-cycle precedent sufficient.)

---

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])

- Slice goal in one sentence: ✓ (reset-counters CLI + structural-only atomic-swap promotion).
- Multi-axis design space? — Slight. Resolved inline 2026-05-27 with user picking Medium scope (over Narrow + over Counter-mgmt+). Atomic-swap promotion + reset-counters combined; mechanism details deferred to architect Phase A (PERCPU-as-inner feasibility check).
- Mechanical-answer check: ✓ — bypass subcommand pattern is direct template for reset-counters; §5.34 4-axis pattern is direct template for atomic-swap shape (if feasibility verified).
- Brief author overconfidence check: ⚠ — Second `/mint-briefer` dogfood (post Phase 2.7 + 4.4 patches from cycle 2 retrospective). Phase 2.7 (fixture cross-reference) caught T_CLI_HELP_VERSION dependency explicitly. Phase 4.4 (operative-semantic SHOULD-hint discipline) applied to verifiable-invariants framing.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief author already ran Phase 2 greps (see Phase 2 verification report in conversation log). Architect re-verifies INDEPENDENTLY + extends:

```bash
# Verify current rule_counters declaration + bump_rule call-site
grep -nE "rule_counters|bump_rule" src/bpf/mac_filter.bpf.c | head -20

# Verify CLI dispatch + --help block locations
sed -n '300,335p' src/cli/cli.cpp     # subcommand dispatch
sed -n '80,110p' src/cli/cli.cpp       # --help body

# Verify bypass.{hpp,cpp} pattern (template for reset_counters.{hpp,cpp})
cat src/cli/bypass.hpp
grep -nE "bypass_main|audit" src/cli/bypass.cpp

# Verify kManagedMaps[] table location + count
sed -n '145,175p' src/lib/loader.cpp

# Verify PERCPU-as-inner-of-ARRAY_OF_MAPS libbpf feasibility (CRITICAL Phase A check)
# Smoke: write a minimal mac_filter.bpf.c with rule_counters reshaped to test pattern,
# build, then: sudo -n bpftool prog load build/<obj> /sys/fs/bpf/probe type xdp; rc=$?
# If rc != 0 → HG-3.4d-4 fallback path; peer-DM impl.

# Version literal propagation (guard #11)
grep -rln '0\.9\.0' tests/ src/ docs/ CHANGELOG.md

# --help output cross-reference (guard #13)
grep -nE 'help|usage|attach.*iface' tests/T_CLI_HELP_VERSION.sh | head -10

# RESOURCE_LOCK declarations for NEW veth-touching tests (guard #12)
grep -nE "RESOURCE_LOCK|xdp_fixture" tests/CMakeLists.txt | head -10
```

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep discipline)** — always applies; architect re-runs above independently.
- **Guard #7 (bpftool-vs-libbpf BTF inner-template asymmetry)** — POSSIBLE if HG-3.4d-4 ships AND PERCPU-as-inner. Phase A: smoke `bpftool prog load` after reshape.
- **Guard #9 (helper-location duplication-over-extraction)** — `reset_counters.cpp` SHOULD duplicate the audit-message + uid/euid lookup helpers from `bypass.cpp` rather than extract into a shared common helper. Brownfield discipline.
- **Guard #10 (catalogue arithmetic slip)** — `kManagedMaps[]` 15 → 17 if Medium ships; BPF `SEC(".maps")` count grows similarly. Architect counts independently.
- **Guard #11 (VERSION-bump propagation)** — `0.9.0 → 0.10.0`. Sites already verified Phase A = 3 (CMakeLists.txt, CHANGELOG.md, T_EXPORTER_METRICS_FORMAT.sh).
- **Guard #12 (RESOURCE_LOCK for shared host state in NEW ctests)** — T-1/T-2/T-3 (and T-4 if shipped) ALL touch veth → all need `RESOURCE_LOCK xdp_fixture`.
- **Guard #13 (test-fixture cross-reference for retire/rename emit-sites)** — applies via `T_CLI_HELP_VERSION.sh` (`--help` gains new subcommand line). Pre-listed as Item E-1 in scope above.

### Cycle-3.4d-specific candidate guard (potentially formalized as #14)

- **PERCPU map as inner-of-ARRAY_OF_MAPS feasibility check**. Pattern: when a brief proposes promoting a PERCPU_* map to atomic-swap parallel pattern, architect Phase A MUST smoke-test feasibility via minimal BPF object + `bpftool prog load` BEFORE publishing design. If libbpf rejects skel codegen OR verifier rejects loads from inner → fall back to alternative shape (twin pins with active_idx-aware datapath, OR defer atomic-swap entirely). Cost: ~5 min of Phase A smoke. Benefit: catches THIS class of design uncertainty before Phase B impl turbulence.

### Operative-semantic discipline for SHOULD-hints (per /mint-briefer Phase 4.4 — anti-OOT-inflation from MVP-3.4b cycle 2 retrospective)

Counts / sizes in verifiable-invariants prose are **operative-semantic, not literal-precise**. Examples:
- `kManagedMaps[]` count "15 → 17 if Medium ships" — actual count depends on architect picking exact entry-order; brief's number is orientation, not contract.
- BPF `SEC(".maps")` count delta uncertain (PERCPU-as-inner mechanism unknown until Phase A); brief's "+2 if shipped" is orientation.
- `--help` line additions "+1 subcommand line" — actual count depends on architect picking flag-description granularity.

Impl deviations on these counts (mirroring existing precedent, atomic-swap fallback if PERCPU-inner not feasible, audit-line format refinements) are **`inline-merge` per design's resolution rule** — NOT `[CONTRACT-DRIFT]` per reviewer.
