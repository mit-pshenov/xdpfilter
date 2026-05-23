# Task brief — MVP-2 Perf: PERCPU stats migration + `--mode {generic,native,offload}` CLI flag (refactor mode)

## Goal

Close the two remaining performance items deferred to MVP-2 in design.md §7, both flagged HIGH (cross-validated:3 from hybrid-review) for PERCPU and MEDIUM (perf + sec, two distinct impacts) for `--mode`:

1. **PERCPU stats migration** — change `stats` map from `BPF_MAP_TYPE_ARRAY` to `BPF_MAP_TYPE_PERCPU_ARRAY`. Closes the **counter-loss-under-load** + **cache-line-bouncing** twin perf problems documented in hybrid-review.md (perf HIGH "Non-atomic counter") and design.md §5.3 ("Single shared — see Decision §5.3" with explicit MVP-2 note). `read_stats.py` becomes a sum-across-CPUs reader.

2. **`--mode {generic,native,offload}` CLI flag** — let operators choose XDP attachment mode at attach time. Default remains `generic` (current SKB-only baseline) for backwards compatibility. Native and offload modes are kernel-and-NIC dependent; loader exits cleanly (existing exit 3 `AttachFailed`) when the requested mode is rejected by the kernel. Closes hybrid-review.md perf MED ("SKB-mode hardcoded") + sec MED M2 ("alien-detection bypass via non-SKB modes" — partially closed in MVP-1.1B §5.20 all-modes probe; this completes the loop by exposing the CLI surface).

This is the **second MVP-2 pass** (sixth /mint cycle overall). Touches `src/bpf/mac_filter.bpf.c` for the **first time since MVP-1** — workflow stress test for the BPF-pack-loaded tester + impl-side BPF skeleton regeneration.

## Context: prior work

- **All prior briefs**: `mint/task-brief-mvp1{,.1a,.1b,.1c}.md` + `mint/task-brief-mvp2-sec.md`
- **Existing design**: `mint/design.md` — 2493 lines through §5.22 + §6.15 + §7 MVP-2 Sec additions. §5.3 + §5.5 + §5.6 are your edit targets; §5.22 needs minor amendment for the `is_ours` predicate's mode axis.
- **MVP-2 Sec review**: `mint/review.md` (round-1 pass, 0 findings).
- **Hybrid review source**: `mint/hybrid-review.md` — perf HIGH (PERCPU) + perf MED + sec M2 (—mode).

## Workflow rules (refactor mode — same convention as 1.1A/B/C + MVP-2 Sec)

- **Architect**: read existing `design.md` (focus §5.3, §5.5, §5.6, §5.22 `is_ours`, §6.x stats-touching tests) + this brief. EDIT design.md in place. Append `§5.23 MVP-2 Perf: PERCPU stats + --mode flag` after §5.22. The amendment MUST resolve the open mechanism questions below. Update §5.3 + §5.6 in place to reflect the new design (these sections become **superseded** with a pointer to §5.23 — same pattern §5.4 used in MVP-1.1B). Update §5.22 `is_ours` to reflect the mode axis change. Append new §6.x TestStrategy entries for any new tests. Update §7 OOS — MOVE PERCPU + --mode entries from "deferred" to "shipped in §5.23".
- **Impl**: EDIT `src/bpf/mac_filter.bpf.c` (stats map type), `src/loader/cli.cpp` + `cli.hpp` (--mode parser), `src/loader/loader.hpp` (`AttachConfig` gains a `mode` field — first loader.hpp **public API** change since MVP-2 Sec's 1-line PathRefused; this pass relaxes that invariant for the AttachConfig surface, recorded in design §5.23), `src/loader/loader.cpp` (mode-aware attach + identity gate), `tests/lib/read_stats.py` (PERCPU sum), and any `main.cpp` plumbing. raii.hpp stays byte-identical.
- **Tester**: ADD new ctest scripts for new §6.x entries (architect specifies the exact list; expect 1-3 new tests around --mode flag + a PERCPU correctness assertion). Update `tests/T_CLI_HELP_VERSION.sh` if `--help` text grows to include --mode (assertion may need to also grep `--mode`). Update `tests/T_CLI_BAD_MAC.sh` and `T_CLI_CAPACITY.sh` if architect deems necessary (probably no change — they exercise --allow not --mode).
- **Reviewer**: 4-point triangulation. Special attention: (1) `wait_for_stats_sum` helper must still work — `read_stats.py`'s PERCPU sum is what makes that opaque, so the helper itself is unchanged. (2) `is_ours` predicate's mode-axis behavior under both attach and detach must be coherent.

## Open mechanism questions (architect decides; document in §5.23)

### Q1: `detach` semantics for `--mode`

`attach --mode native` is straightforward — operator asks for native, loader picks `XDP_FLAGS_DRV_MODE`. `detach` is less obvious because the operator may not know what mode was used at the last attach. Options:

- **Option S (strict)**: `detach --mode <X>` is required; if `--mode` omitted, default to `generic` (matches default attach). If the actually-attached prog is in a different mode → state-(c) (alien) refusal. **Pro**: simplest, symmetric to attach. **Con**: surprising for operators who attached with `--mode native` and forget on detach (they get exit 4 + alien refusal — confusing).
- **Option W (wildcard)**: `detach` accepts our prog in ANY mode (`is_ours_for_detach = name && tag && mode∈{generic,native,offload}`). `--mode` is silently ignored on detach if specified. **Pro**: operator-friendly; one less thing to remember. **Con**: asymmetric with attach; tag-check still gates identity so security isn't weakened.
- **Option A (auto-detect)**: `detach` always queries the actually-attached prog's mode (per §5.20 all-modes probe — already implemented) and uses that for the `bpf_xdp_detach` call. `--mode` on detach is rejected with a clean CLI error ("detach does not accept --mode; mode is auto-detected"). **Pro**: explicit + operator-friendly. **Con**: one more CLI rule to remember.

Architect picks. **Option W** is the recommended pragmatic choice; **Option A** is the cleanest if you don't mind the explicit rejection.

### Q2: Kernel-rejected mode handling

`attach --mode native` on a device that doesn't support native XDP (e.g. `lo`) → `bpf_xdp_attach` returns `-EOPNOTSUPP` (or `-EINVAL` on some kernel versions). Current `classify()` in `loader.cpp` translates kernel errnos to `LoaderError::AttachFailed` (exit 3). Options:

- **Option K (keep existing)**: stay on exit 3 + stderr captures the kernel errno via `strerror`. Operator sees "XDP attach failed: Operation not supported". **Pro**: no new exit code; consistent with all other kernel-attach failures. **Con**: operator doesn't immediately see "your hardware/driver doesn't support this mode".
- **Option N (new exit code 9 = ModeUnsupported)**: new `LoaderError::ModeUnsupported`. Pre-classify EOPNOTSUPP/EINVAL on the bpf_xdp_attach call as "mode-unsupported" when the requested mode is not `generic`. **Pro**: distinct audit signal. **Con**: another exit code (we just added 8 in MVP-2 Sec; the table is filling up); EOPNOTSUPP from XDP attach can also mean "interface gone away mid-attach" — false positives possible. Exit 7 stays reserved for KernelUnsupported (MVP-2 Robust).

Architect picks. **Option K** is the recommended floor; **Option N** is justifiable only if the audit-signal value clearly beats the false-positive risk.

### Q3: PERCPU stats test coverage

`read_stats.py` updates to sum across CPUs. Existing tests (T_PASS_ALLOWED, T_DROP_DENY) become transparent — they just check sum, which is what they always checked. But: should there be a **dedicated** test asserting that the PERCPU aggregation is actually happening (vs. silently still reading a single-CPU value because the test machinery never noticed)?

- **Option D (defensive)**: add `T_PERCPU_AGGREGATION` — inject N packets from `${IFACE_B}`, read the raw PERCPU slot layout via `bpftool map dump --json` (without summing), assert at least 2 CPU slots have non-zero values (proves real aggregation, not single-CPU coincidence). Hard to construct reliably on a single-CPU test runner; would need `taskset` or kernel rebalancer cooperation.
- **Option I (implicit)**: rely on existing test coverage — if `read_stats.py` PERCPU sum is correctly implemented, T_PASS_ALLOWED passing is sufficient evidence. Add a code-review checklist item for the reviewer (verify the new sum loop is correct).
- **Option F (fixture-level)**: add a tiny `T_READ_STATS_SCHEMA` unit-shaped test that loads a known-state PERCPU map, sums via the script, asserts the sum matches the known total. No traffic injection needed.

Architect picks. **Option F** is the recommended sweet spot — proves the sum logic without flaky multi-CPU assumptions.

## Scope (3 items — anything else is OOS)

### Item 1 — PERCPU stats migration

**Where**:
- `src/bpf/mac_filter.bpf.c:30-34` (stats map declaration: change `BPF_MAP_TYPE_ARRAY` → `BPF_MAP_TYPE_PERCPU_ARRAY`).
- `tests/lib/read_stats.py` (sum across CPUs — bpftool's `--json` output for PERCPU maps wraps `value` in a nested array per CPU).
- `src/bpf/mac_filter.bpf.c:41-44` `bump_stat` — verify the lookup-and-bump pattern still compiles and is correct for PERCPU (kernel returns pointer to current-CPU slot, so `*v += 1` is now per-CPU local — no atomicity needed across CPUs).

**Action**: change map type; update read_stats; verify all stats-reading tests still pass with the new sum semantics.

### Item 2 — `--mode {generic,native,offload}` CLI flag

**Where**:
- `src/loader/cli.cpp` (add `--mode` parser entry; default `generic`).
- `src/loader/cli.hpp` (if any new enum needed; otherwise just doc the flag).
- `src/loader/loader.hpp` — `AttachConfig` gains `XdpMode mode;` field. **This is the second loader.hpp public API change since MVP-2 Sec.** Spec the diff explicitly: one new enum class declaration + one new struct field. Document the relaxation in §5.23.
- `src/loader/loader.cpp` (mode-aware attach: select `XDP_FLAGS_SKB_MODE` / `XDP_FLAGS_DRV_MODE` / `XDP_FLAGS_HW_MODE` per `cfg.mode`); `is_ours` predicate per Q1 decision.
- `src/loader/main.cpp` (plumb the parsed mode through to `attach()`).

**Action**: add the CLI flag; update internals to use it; resolve Q1 (detach mode semantics) per architect's decision.

### Item 3 — Tests (per Q3 + architect-specified §6.x entries)

**Where**:
- New: `tests/T_MODE_GENERIC_DEFAULT.sh` (probable) — `attach` with no `--mode` defaults to generic; probe confirms attached-mode is SKB; detach succeeds.
- New: `tests/T_MODE_NATIVE_UNSUPPORTED.sh` (probable) — `attach --mode native --iface lo` → kernel rejects (lo doesn't support native XDP) → exit 3 per Q2 Option K (or exit 9 per Option N).
- New: `tests/T_PERCPU_*` per Q3 decision (Option F most likely).
- Edit: `tests/T_CLI_HELP_VERSION.sh` — if `--help` text now includes `--mode`, assertion may grep for it. Architect decides if this counts as in-scope.

**Action**: register all new tests in `tests/CMakeLists.txt` with appropriate `TIMEOUT` + `RESOURCE_LOCK xdp_fixture` + `SKIP_RETURN_CODE 77`.

## Out of scope (explicit)

- **Kernel-version probe + `LoaderError::KernelUnsupported` (exit 7)** — MVP-2 Robust slice. Exit 7 stays reserved.
- **`T_VERIFIER_REJECT`** — MVP-2 Robust slice (depends on the kernel-version probe).
- **Netns isolation for tests (C3 Path A)** — MVP-2 Polish-2 slice.
- **CMake-generation of `PIN_ROOT`** — MVP-2 Polish-2 slice.
- **Version-string sync between CHANGELOG.md and `--version`** — MVP-2 Polish-2 slice.
- **`inject_runt.py:37` inline comment fix** — MVP-2 Polish-2 slice.
- **`stats` subcommand in `xdpmacfilter`** — MVP-3+ per §7. PERCPU migration does NOT add a userspace dump CLI.
- **Atomic counter ops (e.g. `__sync_fetch_and_add`)** — PERCPU eliminates the cross-CPU race; intra-CPU race is not a concern for our single-threaded XDP per-CPU dispatch model.
- **PERCPU for the `allowlist` map** — allowlist is read-only at runtime (populated once at attach); PERCPU offers no benefit.
- **`--mode`-specific behavior in `is_ours` for §6.9 T_ATTACH_ALIEN_REFUSAL** — that test pre-attaches a `xdp_pass`-named alien; mode of that fixture stays SKB; refusal happens on name+tag axes before mode comparison even runs. No test edit needed unless architect spots otherwise.

## Definition of done

- §5.23 amendment block in `mint/design.md` documenting Q1/Q2/Q3 decisions with rationale
- §5.3 + §5.6 updated in place (or superseded with §5.23 pointer per architect's preference)
- §5.22 `is_ours` predicate amended for mode-axis behavior
- 1-3 new §6.x TestStrategy entries per Q3 + Item 2 tests
- `mac_filter.bpf.c` stats map migrated to PERCPU; `read_stats.py` sums across CPUs
- `--mode` CLI flag works for attach; detach per Q1 decision
- All 15 existing ctest entries still pass (or legitimately SKIP); new tests pass
- `XDPMF_SANITIZERS=ON` build clean
- `mint/review.md` round-1 verdict = `pass`
- One git commit per phase boundary per workflow B

## Dependencies

No new system dependencies. `bpftool` already used in tests + read_stats.py; its `--json` PERCPU output schema is stable libbpf-bound API. libbpf 1.1+ already required. No new C++ libraries.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
packs:
  architect:  []                                       # design at abstract level
  impl:       [lang/cpp.md, lang/bpf.md, lang/cmake.md]  # touches .bpf.c (first time since MVP-1)
  tester:     [test/bpf-xdp.md]
  reviewer:   []                                       # generic framework + LSP
```
