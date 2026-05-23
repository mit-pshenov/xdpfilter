# Review — MVP-2 Perf: PERCPU stats migration + `--mode` CLI flag (mint triangulation)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 (2 in-spirit deviations flagged, not SPEC-DRIFT) | — |
| 3. Code ↔ Tests | 0 (all 18 PASS + 1 expected SKIP, matches tester log) | — |
| 4. Out-of-Scope Drift | 0 | — |

Plus 2 `[OUT-OF-TRIANGULATION]` advisory items for architect — spec-wording amendments to consider in a future pass; do NOT block this verdict.

---

## Findings

### Spec ↔ Code (point 1)

All §5.23 items implemented per contract; cross-checked file:line. No findings.

- **A1 — loader.hpp public-API diff exactly matches §5.23 "Public-API surface diff"**:
  - `enum class XdpMode : int { Generic=0, Native=1, Offload=2 };` at `src/loader/loader.hpp:24-28` matches design.md:1606-1610 (underlying type `int` ✓, values 0/1/2 ✓, comments naming XDP_FLAGS_*_MODE ✓).
  - `XdpMode mode = XdpMode::Generic;` at `src/loader/loader.hpp:36` matches design.md:1622-1626.
  - `git diff HEAD~2 HEAD -- src/loader/loader.hpp` shows 9 lines added — matches the "~6 lines incl. comments + one line" envelope at design.md:1637-1640.
  - **raii.hpp, cli.hpp, src/common/*, main.cpp** all byte-identical (`git diff HEAD~2 HEAD --stat` shows zero entries) per design.md:1632-1634.

- **A2 — BPF stats map PERCPU migration** at `src/bpf/mac_filter.bpf.c:33` (`__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY)`) ✓. Comment update at lines 25-30 documents §5.3 supersede. `bump_stat` helper at lines 41-47 unchanged (correct per design.md:1659 "verify only").

- **A3 — read_stats.py PERCPU sum** at `tests/lib/read_stats.py:91-98` iterates `entry["values"]` and sums per-CPU `value` arrays. Schema matches design.md:1707-1713. Defensive fallback to singular `value` (line 99-105) is conservative belt-and-suspenders; doesn't break the contract.

- **A4 — `--mode` parser** at `src/loader/cli.cpp:167-174` (`parse_mode_token`) — accepts `generic`/`native`/`offload`, throws CliError with exact `--mode: expected one of {generic, native, offload}, got '<X>'` per design.md:1668. Detach `--mode` rejection at `src/loader/cli.cpp:208-213` with `attach-only` substring per design.md:1668 + 1509.

- **A5 — `--help` includes `--mode`** at `src/loader/cli.cpp:91-93`. Verified by T_CLI_HELP_VERSION grep at `tests/T_CLI_HELP_VERSION.sh:50`. Per design.md:1689.

- **A6 — `mode_to_flags` + detach mode-aware**:
  - Anon-ns `mode_to_flags(XdpMode m)` at `src/loader/loader.cpp:99-107` ✓.
  - attach uses `bpf_xdp_attach(... mode_to_flags(cfg.mode), ...)` at `src/loader/loader.cpp:840-842` ✓ (design.md:1671).
  - detach uses `bpf_xdp_detach(... probed_mode_to_flags(probe.mode), ...)` at `src/loader/loader.cpp:928` ✓ (design.md:1537-1539, 1052-1054).
  - is_ours drops `mode == SKB` clause at `src/loader/loader.cpp:611-613`: `out.is_ours = (out.mode != ProbedMode::None) && name_matches && (out.tag == self_tag)` — `mode != None` is exactly `mode ∈ {SKB, NATIVE, HW}` ✓ (design.md:1533-1534, 1028-1030).
  - Idempotent reload in attach state (b) at `src/loader/loader.cpp:770-771` uses `probed_mode_to_flags(probe.mode)` — reload uses ACTUALLY-ATTACHED mode, not new mode. Correct per design.md:1672.

- **A7 — main.cpp UNCHANGED** ✓ (`git diff HEAD~2 HEAD --stat` shows no entry for `src/loader/main.cpp`). ParsedCommand variant carries AttachConfig by value, mode flows automatically.

- **A8 — Stderr discipline**:
  - `mode=<m>` substring at `src/loader/loader.cpp:845-846` (attach failure format: `"bpf_xdp_attach (mode={}): {}"` with `to_string(cfg.mode)`). T_MODE_NATIVE_UNSUPPORTED `grep -E 'native|mode=native'` (test line 93) matches ✓.
  - `attach-only` substring at `src/loader/cli.cpp:211-213` (literal `detach: --mode is attach-only; mode is auto-detected from the attached program`). T_MODE_DETACH_REJECTS `grep -F 'attach-only'` (test line 70) matches ✓.

**Impl deviations from spawn message — both in-spirit, not SPEC-DRIFT**:
- Anon-ns `XdpMode` enum in loader.cpp renamed to `ProbedMode` (loader.cpp:82) — necessary collision avoidance after public `xdpmf::XdpMode` was added; the design (1614-1617) said "mapping happens via a switch in `loader.cpp`'s anon namespace" without naming the anon enum, so naming flexibility is implicit.
- `mode_to_flags` + `probed_mode_to_flags` return `std::uint32_t` not the design.md:1671-spec'd `int` — libbpf's `bpf_xdp_attach` flags param is `__u32`; warning-cleanliness under `-Wsign-conversion` per cpp pack policy. In-spirit; documented inline at loader.cpp:99 + impl-notes precedent for `std::uint32_t` (§5.16).

### Spec ↔ Tests (point 2)

All §6.16-§6.19 test entries present + §6.10 amendment honored. Two judgment calls flagged below — both in-spirit per design intent; flagged for architect's future spec-amendment, NOT requiring rework.

- **T1 — T_MODE_GENERIC_DEFAULT** at `tests/T_MODE_GENERIC_DEFAULT.sh:67-92` (case statement). Asserts exit 0 (line 47 implicit via `set -e`), mode probe via `ip -j link show | jq` (lines 63-65), and pin paths (lines 95-102). **Deviation from design.md:2633 spec wording** ("accept both `generic` and `xdpgeneric` for kernel-version variance"): tester extended `case` to accept numeric `2` (XDP_ATTACHED_SKB enum value when iproute2 emits numeric instead of string mode). **Judgment: in-spirit, NOT SPEC-DRIFT.** Numeric `2` is the same XDP_ATTACHED_SKB value the strings name. Tester added explicit FAIL branches at lines 76-80 (1/native/xdpdrv) and 81-85 (3/offload/xdpoffload) — strict-superset of spec intent (catches actual regression). On test host this fires the numeric path (`probed mode='2'` per test stdout). See `[OUT-OF-TRIANGULATION-1]` below.

- **T2 — T_MODE_NATIVE_UNSUPPORTED** at `tests/T_MODE_NATIVE_UNSUPPORTED.sh:78-110` matches design.md:2654-2663 outcomes exactly: rc==3 (line 78), stderr `grep -E 'native|mode=native'` (line 93), post-state `lo` XDP slot empty (line 99-103), no orphan pin dir (line 106). Pre-check for clean `lo` at lines 51-61 is defensive belt-and-suspenders, not in spec but matches design.md:2652 "Pre-test snapshot" note.

- **T3 — T_PERCPU_STATS_SUM** at `tests/T_PERCPU_STATS_SUM.sh:84-150`. **Deviation from design.md:2680-2691 spec mechanism** ("seed each CPU slot with `c+1` for `c ∈ [0, nr_cpus-1]`, expected_sum = `nr_cpus*(nr_cpus+1)/2`"). Tester used broadcast V=42 → expected_sum = `nr_cpus * V`. **Judgment: in-spirit, NOT SPEC-DRIFT** — root cause is bpftool v7.1.0's `fill_per_cpu_value()` (src/map.c) BROADCASTS a single u64 across all per-CPU slots; no CLI syntax for distinct per-CPU values. Architect's spec mechanism hint was empirically unimplementable. Tester documented this exhaustively at test lines 14-33 + inline diagnostics at lines 117-125. The §6.18 outcome ("STAT_PASS field equals expected_sum") is preserved — only the construction of expected_sum changed. Discriminator (sum=`V*N` vs single-CPU-read=V) is preserved on multi-CPU test hosts. See `[OUT-OF-TRIANGULATION-2]` below.

- **T4 — T_MODE_DETACH_REJECTS** at `tests/T_MODE_DETACH_REJECTS.sh:42-75` matches design.md:2705-2715. Loops `modes_to_test=(native generic)` — exercises §6.19 optional sub-variant (line 2716) proving rule is flag-presence-driven not flag-value-driven. Both sub-cases assert rc=1 (line 58) + `grep -F 'attach-only'` (line 70). ✓

- **T5 — tests/CMakeLists.txt** at lines 196-239 registers all 4 new tests with per-test ctest properties:
  - T_MODE_GENERIC_DEFAULT: TIMEOUT 60, RESOURCE_LOCK xdp_fixture, SKIP_RETURN_CODE 77 (matches design.md:2640) ✓
  - T_MODE_NATIVE_UNSUPPORTED: TIMEOUT 30, no RESOURCE_LOCK, SKIP 77 (matches design.md:2665) ✓
  - T_PERCPU_STATS_SUM: TIMEOUT 30, RESOURCE_LOCK xdp_fixture, SKIP 77 (matches design.md:2693) ✓
  - T_MODE_DETACH_REJECTS: TIMEOUT 10, no RESOURCE_LOCK, no SKIP_RETURN_CODE (matches design.md:2714) ✓

- T_CLI_HELP_VERSION.sh:50-53 grep for `--mode` substring per design.md:1689. ✓

- **Negation control**: suite-level §6.7 T_NEGATION_CONTROL with `WILL_FAIL TRUE` at tests/CMakeLists.txt:80 — meets the framework's NO-NEGATION-CONTROL gate. The 4 new tests intentionally skip per-test negation controls per design.md:2641, 2667, 2695, 2715. ✓

### Code ↔ Tests (point 3)

Re-ran `cmake --build . -j16 && ctest --output-on-failure` myself, captured to `/tmp/mint-review-tests-1748019xxx.log`:
- 18/19 PASS + 1 expected SKIP (T_DROP_MALFORMED — pre-existing kernel-padding skip from MVP-1, unchanged from pre-MVP-2-Perf).
- Result byte-identical to tester's mint/test-run.log (same pass/skip pattern; minor wallclock variance).
- Build is clean (no warnings emitted by cmake --build).
- **No `[UNEXERCISED-EXPORT]`**: `XdpMode` symbol used in cli.cpp:167-171 (parse), loader.cpp:99-104 (flag map), loader.cpp:111-116 (to_string), loader.hpp:24,36 (decl+field). End-to-end exercise via §6.16/§6.17/§6.18/§6.19. ✓

### Out-of-Scope Drift (point 4)

`git diff HEAD~2 HEAD --stat` shows only files within §5.23 spec'd surface:
- src/bpf/mac_filter.bpf.c (Item 1)
- src/loader/{cli,loader}.cpp + loader.hpp (Item 2)
- tests/lib/read_stats.py (Item 1)
- 4 new tests + tests/T_CLI_HELP_VERSION.sh edit (Item 3)
- tests/CMakeLists.txt (Item 3)
- mint/design.md (architect)

No OOS files touched. No code references to deferred items (kernel-version probe, T_VERIFIER_REJECT, netns isolation, CMake `PIN_ROOT` gen, stats subcommand, atomic counter ops, PERCPU for allowlist) — all OOS per §7 §5.23 additions.

---

## [OUT-OF-TRIANGULATION] advisory items for architect (do NOT block this verdict)

Spec-wording cleanups for a future iteration's design. **Both inline-merged into design.md by team-lead 2026-05-23 post-review per established orchestrator-Edit pattern.**

### [OUT-OF-TRIANGULATION-1] §6.16 spec wording misses numeric mode variance
**Location**: `mint/design.md:2630, 2633, 2637`
**Evidence**: spec said "accept both `generic` and `xdpgeneric` for kernel-version variance" — but on this host `ip -j link show` emits numeric `2` (= XDP_ATTACHED_SKB per uapi/linux/if_link.h). Tester extended the case to include `2` and documented the kernel/iproute2 schema divergence.
**Fix applied inline**: §6.16 amended to accept `generic`, `xdpgeneric`, OR numeric `2`; FAIL-branch language added for `1`/`3` (DRV/HW) as regression-guards.

### [OUT-OF-TRIANGULATION-2] §6.18 mechanism hint is empirically unimplementable via bpftool CLI
**Location**: `mint/design.md:2680-2683, 1593-1595`
**Evidence**: spec mechanism said "seed each CPU slot with `c+1`, expected_sum = `nr_cpus*(nr_cpus+1)/2`". Tester investigation of bpftool v7.1.0 source (src/map.c `fill_per_cpu_value()`) — and confirmed by empirical parse error on multi-value attempts — established bpftool `map update` ONLY broadcasts a single value across all CPU slots.
**Fix applied inline**: §6.18 + §5.23 Q3 mechanism hint amended to broadcast V=42 / expected_sum = `nr_cpus * V` with preserved discriminator (sum=V*N vs single-CPU-read=V) on multi-CPU hosts.

---

## Test execution

```
13/19 Test #13: T_DETACH_NOTHING .................   Passed    0.17 sec
14/19 Test #14: T_ATTACH_TAG_MISMATCH ............   Passed    2.19 sec
15/19 Test #15: T_BPFFS_ROOT_SYMLINK .............   Passed    1.59 sec
16/19 Test #16: T_MODE_GENERIC_DEFAULT ...........   Passed    1.23 sec
17/19 Test #17: T_MODE_NATIVE_UNSUPPORTED ........   Passed    0.22 sec
18/19 Test #18: T_PERCPU_STATS_SUM ...............   Passed    1.32 sec
19/19 Test #19: T_MODE_DETACH_REJECTS ............   Passed    0.03 sec

100% tests passed, 0 tests failed out of 19

Total Test time (real) =  70.64 sec

The following tests did not run:
	  5 - T_DROP_MALFORMED (Skipped)
```

---

## Summary

Verdict: **pass**.

Triangulation clean across all 4 framework points. Impl matches §5.23 contract byte-for-byte where the spec mandated it (loader.hpp diff, BPF map type, CLI surface, attach/detach mode plumbing, is_ours predicate relaxation). All 18 tests pass + 1 expected pre-existing skip — reproduced independently. No OOS drift.

Two tester adaptations (T1 numeric mode in §6.16, T3 broadcast vs per-CPU in §6.18) are forced by external constraints (kernel/iproute2 JSON schema variance, bpftool CLI limitation), preserve all diagnostic intent of the original spec, and are documented exhaustively in-script. Both judged **in-spirit** rather than SPEC-DRIFT — the architect's spec wording was the empirical-reality-checking party in this round, not the tester. Inline spec amendments applied post-review to keep design.md authoritative.

Two impl deviations (anon-ns enum rename `XdpMode`→`ProbedMode`, return-type `int`→`std::uint32_t`) are necessary side-effects of adding the public `xdpmf::XdpMode` and conforming to the codebase's existing `std::uint32_t`-for-libbpf-flags convention; both in-spirit, in line with §5.16 + impl-notes precedent.

Architect can mark task #1 (design) completed at convenience. Ready to ship MVP-2 Perf.
