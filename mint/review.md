# Review — MVP-2 Robust: kernel-version probe + T_VERIFIER_REJECT (mint triangulation)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 1 (minor, negotiated) | [SPEC-DRIFT × 1 — TIMEOUT 30→60, EDIT-12 merged] |
| 3. Code ↔ Tests | 0 (20/20 pass) | — |
| 4. Out-of-Scope Drift | 0 | — |

All 4 framework points clean modulo one minor pre-negotiated TIMEOUT bump now resolved via EDIT-12 inline-merge.

## Detailed framework results

### 1. Spec ↔ Code — clean

- **A1 loader.hpp invariant** ✓ — `git diff HEAD~2 HEAD -- src/loader/loader.hpp` shows EXACTLY one added line `KernelUnsupported = 7,` between `Permission = 6,` (line 48) and `PathRefused = 8,` (line 50). Cite: `src/loader/loader.hpp:49`.
- **A1' byte-identical files** ✓ — `git diff HEAD~2 HEAD -- src/loader/raii.hpp src/loader/cli.hpp src/loader/cli.cpp src/loader/main.cpp src/bpf/ src/common/` returns empty.
- **A2 kernel_version_probe()** ✓ — `src/loader/loader.cpp:294-329` anon-namespace, uses `::uname(&u)`, `parse_major_minor`, and `std::pair{maj,min} < std::pair{kKernelFloorMajor, kKernelFloorMinor}` lexicographic compare. Three throw branches: uname syscall fail (line 298), parse fail (line 310), too-old (line 323). All throw `LoaderError::KernelUnsupported`.
- **A3 probe call-site (Q3 Option B symmetry)** ✓ — FIRST statement of `attach()` at `loader.cpp:921` and FIRST statement of `detach()` at `loader.cpp:1042`. Both precede `resolve_ifindex` (which wraps `if_nametoindex`) at lines 923 and 1044 respectively.
- **A4 stderr discipline** ✓ — `loader.cpp:323-327` format string: `"xdpmacfilter: kernel {}.{} too old, need ≥ {}.{}"` — contains literally `xdpmacfilter`, `kernel`, `<maj>.<min>`, `too old`, `≥`, and (via `kKernelFloorMajor/Minor=5/15`) the floor `5.15`. Matches recommended exact format from `design.md:1912-1913`.
- **A5 floor constants** ✓ — `loader.cpp:85-86`: `constexpr int kKernelFloorMajor = 5;` and `kKernelFloorMinor = 15;`.
- **A6 parse_major_minor()** ✓ — `loader.cpp:255-292`: accepts digit-lead, requires `.`, requires ≥1 digit after `.`, has overflow guard via `kMaxComponent = 1'000'000`. Rejects null pointer (line 263), non-digit first char (lambda lines 268-270), missing dot (line 284), empty minor (line 286 — same guard via parse_digits returning false on first non-digit). Tolerates trailing garbage (e.g. `-100-generic`, `-rc4+`) by stopping at first non-digit, exactly matching spec.
- **A7 XDPMF_BPF_OBJECT_PATH override symmetric** ✓ — env-var consumed inside `load_skeleton()` at `loader.cpp:804-833`. `load_skeleton()` is called from BOTH `attach()` (line 934) and `detach()` (line 1064). Default behaviour (env unset/empty) preserves `mac_filter_bpf__open()` path (line 829) — byte-identical to pre-§5.24.
- **A8 open_skeleton_from_path mechanism** ✓ (in-spirit) — `loader.cpp:751-793`: file → `std::vector<char>` buffer → `calloc(mac_filter_bpf)` → `mac_filter_bpf__create_skeleton(obj)` → `obj->skeleton->data/data_sz` substitution → `bpf_object__open_skeleton`. Q4 design left mechanism to impl; this is one of the documented libbpf 1.1 idioms (manual skeleton-data substitution). Comment at lines 745-749 explains lifetime.
- **A9 LoaderCategory::message() case** ✓ (in-spirit) — `loader.cpp:218`: `case LoaderError::KernelUnsupported: return "kernel version too old for xdpmacfilter";` — required for `-Wswitch` cleanliness under cpp pack zero-tolerance.
- **A10 New headers** ✓ — design names `<sys/utsname.h>`, `<cstdlib>`, `<utility>`. Impl also adds `<fstream>` (line 42) and `<vector>` (line 48) — BOTH actually used by `open_skeleton_from_path` (`std::ifstream` line 757 + `std::vector<char> buf` line 768). NOT dead-include drift. In-spirit.

### 2. Spec ↔ Tests — 1 minor finding (resolved post-review)

- **T1 T_VERIFIER_REJECT.sh structure** ✓ — `tests/T_VERIFIER_REJECT.sh:80` trap on `EXIT INT TERM HUP`; `:102-118` SKIP probe FIRST via `bpftool prog load`; `:128-134` active branch with `XDPMF_BPF_OBJECT_PATH=… sudo -n -E "${LOADER_BIN}" attach`; `:152` asserts `rc == 2`; `:169` asserts non-empty stderr; `:182` grep regex matches EDIT-11 list; `:189` no XDP attached; `:198` no orphan pin dir.
- **T2 mac_filter_bad.bpf.c fixture** ✓ — `tests/fixtures/mac_filter_bad.bpf.c:75-92` unbounded `for (int i = 0; i < n; i++)` with `volatile int acc` (defeats compile-time folding), NO `#pragma unroll`. Declares `allowlist` (HASH, xdpmf_mac→u8, lines 57-62) + `stats` (PERCPU_ARRAY, u32→u64, lines 68-73) maps with shapes matching real `mac_filter.bpf.c` — Phase B finding now captured at `design.md:2947`.
- **T3 tests/CMakeLists.txt wiring** ✓ — `tests/CMakeLists.txt:41` `add_bpf_object(mac_filter_bad …)`; `:271-280` `add_test(T_VERIFIER_REJECT)` + `set_tests_properties` with `RESOURCE_LOCK xdp_fixture` + `SKIP_RETURN_CODE 77` + `TIMEOUT 60`.
- **T4 EDIT-11 substring list** ✓ — design.md `:2934` and `:2941` list `BPF program load failed|BPF object load failed|PROG LOAD LOG|verifier|Invalid argument`; test `tests/T_VERIFIER_REJECT.sh:182` grep regex is byte-identical.

#### [SPEC-DRIFT × 1] T_VERIFIER_REJECT TIMEOUT 30 → 60 — RESOLVED via EDIT-12

**Original finding**: design §6.20 said `TIMEOUT 30`; CMake used `60`; inline CMake comment narrated `30` (drift across all three artifacts).
**Resolution applied post-review by team-lead**: design.md §6.20 ctest-properties bullet amended to `TIMEOUT 60` with EDIT-12 post-publication note explaining the libbpf-stderr-volume rationale; `tests/CMakeLists.txt` inline comment updated to reflect 60s value with EDIT-12 reference. Same orchestrator-Edit pattern as MVP-2 Sec Sections A+B+C and MVP-2 Perf [OUT-OF-TRIANGULATION] amendments. design.md is canonical again; no other action needed.

### 3. Code ↔ Tests — 20/20 pass

Re-run on dev host (kernel `uname -r` ≫ 5.15) — 19 PASS + 1 expected SKIP (T_DROP_MALFORMED #5), matches tester's test-run.log exactly:

- **C1 probe doesn't fire on dev kernel** ✓ — T_VERIFIER_REJECT reached the verifier-reject branch (rc=2, not rc=7). Probe is silent on `≥ 5.15`.
- **C2 impl honors XDPMF_BPF_OBJECT_PATH in attach()** ✓ — without the override, loader would load real `mac_filter.bpf.o` which verifies clean → rc=0 → FAIL[A1]. T_VERIFIER_REJECT PASS proves override is honored.
- **C3 stderr satisfies EDIT-11 regex** ✓ — grep on `BPF program load failed|BPF object load failed|PROG LOAD LOG|verifier|Invalid argument` succeeded inside the test (no FAIL[A3] printed).
- **C4 20/20 ctest** ✓ — confirmed (log captured to `/tmp/mint-review-tests-…log`).

UNEXERCISED-EXPORT check: `attach()` / `detach()` / `loader_error_category()` exposed in `loader.hpp`. All three are invoked from `src/loader/main.cpp:23` (attach) / similar (detach) / category by `main.cpp` exit-code mapping. Tests exercise these transitively via the `xdpmacfilter` binary in every ctest entry. No UNEXERCISED-EXPORT findings.

### 4. Out-of-Scope Drift — clean

- **Touched-files audit** — `git diff HEAD~2 HEAD --name-only`: `src/loader/loader.hpp` (+1 line), `src/loader/loader.cpp`, `tests/T_VERIFIER_REJECT.sh` (new), `tests/fixtures/mac_filter_bad.bpf.c` (new), `tests/CMakeLists.txt`, `mint/design.md` (architect). README.md UNCHANGED — Q2 chose 5.15 which already matched `README.md:22`. Matches §5.24 spec'd surface.
- **No `--no-version-probe` escape hatch** (OOS line `design.md:3212-3217`) — `grep -n "no-version-probe\|skip-kernel-check" src/loader/cli.cpp` returns empty. Not added.
- **No `libbpf_probe_bpf_*` calls** (OOS `:3218-3221`) — `grep -rn "libbpf_probe" src/` returns empty.
- **No BPF_PROG_LOAD trivial probe** (OOS `:3222-3225`) — no calls beyond the legitimate skeleton load path.
- **No `--version` kernel-range** / **No `--help` probe call** (OOS `:3226-3229`) — `kernel_version_probe()` is only called from `attach()`+`detach()` per LSP findReferences result (2 callsites, both first-statement).
- **No XDPMF_BPF_OBJECT_PATH in --help** (OOS `:3235-3238`) — `grep XDPMF_BPF_OBJECT_PATH src/loader/cli.cpp` returns empty (env var only documented in `loader.cpp` and the test).
- **No `--bpf-object-path` CLI flag** (OOS `:3239-3241`) — confirmed by grep.
- **No T_KERNEL_VERSION_PROBE_UNIT** (OOS `:3246-3251`) — only T_VERIFIER_REJECT was added.
- **No fallback fixture pattern auto-selection** (OOS `:3242-3245`) — fixture is single-pattern (unbounded loop). Per design, manual swap is the documented escape.

## Test execution

Last 30 lines of `ctest --output-on-failure` (full log at `/tmp/mint-review-tests-<ts>.log`):

```
13/20 Test #13: T_DETACH_NOTHING .................   Passed    0.17 sec
14/20 Test #14: T_ATTACH_TAG_MISMATCH ............   Passed    2.11 sec
15/20 Test #15: T_BPFFS_ROOT_SYMLINK .............   Passed    1.49 sec
16/20 Test #16: T_MODE_GENERIC_DEFAULT ...........   Passed    1.19 sec
17/20 Test #17: T_MODE_NATIVE_UNSUPPORTED ........   Passed    0.20 sec
18/20 Test #18: T_PERCPU_STATS_SUM ...............   Passed    1.31 sec
19/20 Test #19: T_MODE_DETACH_REJECTS ............   Passed    0.03 sec
20/20 Test #20: T_VERIFIER_REJECT ................   Passed   23.75 sec

100% tests passed, 0 tests failed out of 20

Total Test time (real) = 102.87 sec

The following tests did not run:
	  5 - T_DROP_MALFORMED (Skipped)
```

T_VERIFIER_REJECT real wall = 23.75s (well under both spec'd 30s and tester-bumped 60s budgets).

## Summary

Smallest of the MVP-2 slices delivered cleanly: 1 enum line + 1 probe helper + 1 env-var override + 1 test + 1 fixture. 4-point triangulation passes on all hard rules. The single TIMEOUT 30→60 spec-drift finding is now resolved via EDIT-12 inline-merge (design and CMake comment aligned to the empirical 60s value tester chose for libbpf-stderr-volume safety margin).

**Verdict: `pass`. No rework needed.**

Architect can mark task #1 (design) completed at convenience. Ready to ship MVP-2 Robust.
