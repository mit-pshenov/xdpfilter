# Task brief — MVP-2 Robust: kernel-version probe + `T_VERIFIER_REJECT` (refactor mode)

## Goal

Close the two remaining MVP-2 items deferred to the Robust slice (hybrid-review.md testing M7: "no kernel-version compatibility matrix / runtime probe"):

1. **Kernel-version probe + `LoaderError::KernelUnsupported` (exit 7)** — fast-fail when the runtime kernel is too old to support the BPF features `xdpmacfilter` actually uses. The exit-7 row in §4.1 is **already reserved** (per §4.1 row 7 + §5.22 Q3 + §5.23 Q2 OOS fences); this slice fills it. Goal: replace deep-libbpf cryptic failures ("BPF_PROG_LOAD: Invalid argument") with a clear `xdpmacfilter: kernel X.Y too old, need ≥ A.B` + exit 7.

2. **`T_VERIFIER_REJECT`** — regression test asserting the loader produces a clean error (not a crash, not silent success) when libbpf hands the verifier a program it can't accept. Two interpretations possible (architect picks per Q4 below): (a) hand-craft a deliberately-bad `.bpf.o` fixture and assert the loader's `LoadFailed` (exit 2) path is reachable + has a sane error message; (b) on too-old kernels, this test SKIPs because the probe (Item 1) already gated us out at exit 7 (so the verifier path is unreachable in the wild).

This is the **third MVP-2 pass** (seventh /mint cycle). Scope is the smallest of the MVP-2 slices — 1 substantive impl item (the probe) + 1 test (verifier-reject regression). No BPF C changes. Probably no `loader.hpp` public-API change (the new `LoaderError::KernelUnsupported = 7` enumerator is the only candidate; same precedent as MVP-2 Sec's `PathRefused = 8` one-line enum addition).

## Context: prior work

- **All prior briefs**: `mint/task-brief-mvp1{,.1a,.1b,.1c}.md` + `mint/task-brief-mvp2-sec.md` + `mint/task-brief-mvp2-perf.md`.
- **Existing design**: `mint/design.md` — ~2970 lines through §5.23 + §6.19. §4.1 row 7 reserved with explicit `KernelUnsupported (MVP-2 Robust)` annotation. §7 OOS includes the deferred-to-Robust entries you're now fulfilling.
- **MVP-2 Perf review**: `mint/review.md` (round-1 pass, 0 findings + 2 spec-wording amendments inline-merged).
- **Hybrid review source**: `mint/hybrid-review.md` line 130 — testing M7 (the only line on this topic; vague intentionally).
- **README.md** at repo root says "kernel ≥ 5.15" (line 22). design.md mentions kernel ≥ 5.7 implicitly (via libbpf 1.1 floor). **This inconsistency is in-scope for architect to resolve** — pick one floor, document the rationale, fix the README OR the design.

## Workflow rules (refactor mode — same as MVP-2 Sec/Perf)

- **Architect**: read existing `design.md` (focus §4.1 row 7 reservation language, §5.20 all-modes probe — Robust probe lives in similar early-attach position, §5.22 Q1 attach() flow — where probe slots in) + `README.md` (kernel floor inconsistency) + this brief. EDIT design.md in place. Append `§5.24 MVP-2 Robust: kernel-version probe + T_VERIFIER_REJECT` after §5.23. Update §4.1 row 7 from "reserved" to active. Append new §6.x TestStrategy entry for T_VERIFIER_REJECT. Update §7 OOS — MOVE the deferred-to-Robust entries to shipped.
- **Impl**: EDIT `src/loader/loader.cpp` (add the probe helper + invocation in attach()/detach() entry). EDIT `src/loader/loader.hpp` for the new enumerator (one line, like MVP-2 Sec's `PathRefused = 8`). Probably touch `README.md` to align with architect's Q2-chosen kernel floor. raii.hpp / src/bpf/* / src/common/* MUST be byte-identical.
- **Tester**: ADD `tests/T_VERIFIER_REJECT.sh` per architect's Q4 mechanism choice (likely needs a new fixture `tests/fixtures/mac_filter_bad.bpf.c` with a deliberate verifier violation IF architect picks (a)). Register in `tests/CMakeLists.txt` with `SKIP_RETURN_CODE 77` (test SKIPs cleanly on hosts where probe already gated us out). No edits to existing tests.
- **Reviewer**: 4-point triangulation. Special attention: (1) `LoaderError::KernelUnsupported = 7` is exactly the one-line loader.hpp addition (mirror MVP-2 Sec `PathRefused = 8` precedent); (2) probe fires BEFORE any libbpf BPF_PROG_LOAD call (so error message is clear, not cryptic).

## Open mechanism questions (architect decides; document in §5.24)

### Q1: Probe detection mechanism

How does the loader determine "kernel is too old"? Options:

- **Option U (uname syscall)**: `uname(2)` → parse `release` field → compare against floor. **Pro**: simple, no extra deps, one syscall. **Con**: kernel version strings are variable (`5.15.0-100-generic`, `6.1.0-rc4+`, etc.); backported features in older versions miss the cutoff (rare in mainline distros but real for custom kernels).
- **Option F (libbpf feature probe)**: use libbpf's `libbpf_probe_bpf_helper` / `libbpf_probe_bpf_map_type` / `libbpf_probe_bpf_prog_type` API to probe for the specific features we need (e.g. `BPF_PROG_TYPE_XDP`, `BPF_MAP_TYPE_PERCPU_ARRAY`). **Pro**: feature-accurate (catches backports + custom kernels); same library we already depend on. **Con**: more code, each probe is a kernel call (~5+ syscalls total), and libbpf's probe API is itself somewhat fragile across libbpf versions.
- **Option C (combined: uname for floor, then BPF_PROG_LOAD a trivial probe)**: uname for quick rejection of obviously-too-old; then attempt a no-op `BPF_PROG_LOAD` (e.g. a 2-instruction "return 0" program) and if it fails, reject with KernelUnsupported. **Pro**: cheap fast-path + accurate slow-path. **Con**: most complex.
- **Option L (lazy: catch verifier rejection at real load, translate)**: do nothing proactive; intercept `bpf_object__load` failure and check if the errno + dmesg pattern matches "kernel too old" heuristics. **Pro**: zero proactive work. **Con**: error message arrives AFTER a failed `BPF_PROG_LOAD`; not a fast-fail; heuristics are fragile.

Architect picks. **Option U** is the recommended floor — fast, simple, the version-string parse is well-trodden (existing utilities like `linux-version`, kernel's own `init/version.c`, etc. have stable patterns). **Option F** is the cleanest if the architect judges feature-accuracy worth the libbpf API surface.

### Q2: Minimum kernel version floor

What version do we claim to support? Current inconsistency:
- `README.md:22` says **5.15**.
- `mint/design.md:765, 2670` mentions **5.7** as the implicit floor (libbpf 1.1's `bpf_xdp_attach`/`bpf_xdp_query`).

Architect picks ONE floor, documents the rationale, fixes the divergent file. Options:
- **5.7** — the minimum kernel that supports the libbpf 1.1 APIs we use (`bpf_xdp_attach`, `bpf_xdp_query`). Aggressive, broadest compat.
- **5.15** — the README's current claim. More conservative; matches LTS kernels in most distros (Debian Bookworm, Ubuntu 22.04, etc.). Includes BPF verifier improvements + `bpf_loop()`.
- **6.x** — fresh, but unjustified by current feature use.

Recommendation: **5.15** to match README + LTS reality + leave 5.7-5.14 in the "untested, may work" gray zone. Architect picks; the floor becomes the `XDPMF_KERNEL_FLOOR_MAJOR_MINOR` constant the probe compares against.

### Q3: Probe call-site placement

Where does the probe fire?

- **Option A (attach only)**: probe at start of `attach()`, before any libbpf call. Detach skips probe (a too-old kernel that somehow got our program attached can still be detached via raw `bpf_xdp_detach` — no advanced BPF features needed).
- **Option B (attach + detach)**: probe at start of BOTH `attach()` and `detach()`. Symmetric with §5.22 detach() identity gate; consistent operator UX.
- **Option O (once-per-process via static)**: probe runs once at first call into `attach()`/`detach()`, result cached in a function-local static. **Pro**: minimal overhead on repeated calls (rare — loader typically attaches and exits). **Con**: static-in-anon-namespace adds tiny complexity; almost-zero benefit since the loader is short-lived.

Recommendation: **Option B** for symmetry. The probe is microseconds; double-running is fine.

### Q4: T_VERIFIER_REJECT mechanism

Two interpretations of "verifier-reject test" — architect picks:

- **Option (a) Active fixture**: create `tests/fixtures/mac_filter_bad.bpf.c` with a deliberate verifier violation (e.g., unbounded loop without `#pragma unroll`, OOB pointer deref). Test: attempt to load via `bpftool prog load` and assert it fails with verifier rejection THEN attempt to load via `xdpmacfilter` (using a path-swap or env-var override IF the loader supports it) and assert exit 2 (`LoadFailed`) + recognizable stderr.
- **Option (b) Passive gating**: T_VERIFIER_REJECT becomes the test that the probe (Item 1) ACTUALLY prevents reaching the verifier. On the test host (modern kernel), the probe passes; the test SKIPs (exit 77 — "probe says kernel is fine, verifier-reject path is unreachable in normal operation, this is by design"). On a hypothetical too-old kernel, the probe would exit 7 BEFORE the test gets a chance to run, so the test never actually runs.
- **Option (c) Hybrid**: Option (a) with `SKIP_RETURN_CODE 77` if the bad-fixture loads cleanly via bpftool (means the verifier on this kernel doesn't reject what we expected to be a violation → fixture is wrong for this kernel, skip).

Recommendation: **Option (c)** is the cleanest — actively tests the loader's clean-error path on a real verifier rejection AND degrades gracefully if the fixture doesn't trigger a violation on the running kernel. **Option (a)** is acceptable if the architect picks a violation that's reliably rejected across all supported kernels (e.g., a deliberate unbounded loop is a verifier-universal reject for all 5.7+ kernels).

## Scope (2 items + 1 test — anything else is OOS)

### Item 1 — Kernel-version probe + `LoaderError::KernelUnsupported` (exit 7)

**Where**:
- `src/loader/loader.hpp` — add `KernelUnsupported = 7,` to the `LoaderError` enum body (one line, between `Permission = 6,` and `PathRefused = 8,`).
- `src/loader/loader.cpp` — add `kernel_version_probe()` helper in anon namespace per Q1 mechanism. Invoke at start of `attach()` AND/OR `detach()` per Q3. On probe failure: `throw_loader(LoaderError::KernelUnsupported, std::format("kernel {}.{} too old, need ≥ {}.{}", running_major, running_minor, floor_major, floor_minor))`.
- `README.md:22` — update kernel floor line to match architect's Q2 decision.
- `mint/design.md` §4.1 row 7 — change "*reserved*" to active `KernelUnsupported` row (architect handles this in their amendment).

**Action**: implement the probe + invocation + new enum + README fix. Stderr discipline: stderr MUST contain literal substring `kernel` AND `too old` AND the running version AND the floor version. Load-bearing for §6.x T_VERIFIER_REJECT (the SKIP branch).

### Item 2 — `T_VERIFIER_REJECT` regression test

**Where** (per architect's Q4 decision):
- `tests/T_VERIFIER_REJECT.sh` — new ctest script.
- IF Q4 = (a) or (c): `tests/fixtures/mac_filter_bad.bpf.c` — new BPF source with deliberate verifier violation. Wire in `tests/CMakeLists.txt` via existing `add_bpf_object` pattern.

**Action**: implement per Q4 spec. Register in `tests/CMakeLists.txt` with `TIMEOUT 30 + SKIP_RETURN_CODE 77 + RESOURCE_LOCK xdp_fixture` (if veth needed) or no RESOURCE_LOCK (if test stays pure-CLI / lo-only).

## Out of scope (explicit)

- **Netns isolation for tests (C3 Path A)** — MVP-2 Polish-2 slice.
- **CMake-generation of `PIN_ROOT`** — MVP-2 Polish-2 slice.
- **Version-string sync between CHANGELOG.md and `--version`** — MVP-2 Polish-2 slice.
- **`inject_runt.py:37` inline comment fix** — MVP-2 Polish-2 slice.
- **Per-feature probe (Q1 Option F) if Q1 picks Option U** — explicitly fenced: not running BPF_PROG_LOAD probes per-feature; we trust uname + the runtime to behave consistently within a kernel version.
- **Kernel-version probe at `--help`/`--version`** — those subcommands don't touch kernel; probe stays gated to attach/detach.
- **Backporting / "kernel X has feature Y backported" detection** — single floor only; users on backported kernels who hit `KernelUnsupported` can use the `--no-version-probe` escape hatch (if architect adds one; OOS unless they explicitly do).
- **Probe caching across processes** (e.g. via a file in `/var/run/`) — probe is fast; per-invocation re-probe is fine.
- **Userspace `--version` extension to report supported kernel range** — `--version` stays single-line per MVP-1.

## Definition of done

- §5.24 amendment in `design.md` documenting Q1/Q2/Q3/Q4 decisions with rationale
- §4.1 row 7 updated from reserved to active `KernelUnsupported`
- New §6.x TestStrategy entry for T_VERIFIER_REJECT
- `loader.hpp` gains exactly one new line (`KernelUnsupported = 7,`) — verifiable via `git diff`
- `loader.cpp` extended with the probe per Q1/Q3
- `README.md` kernel floor aligned with architect's Q2 decision
- 1 new ctest entry passes on dev host (or legitimately SKIPs per Q4)
- 19 existing ctest entries still pass (or legitimately SKIP per §6.5)
- `XDPMF_SANITIZERS=ON` build clean
- `mint/review.md` round-1 verdict = `pass`
- One git commit per phase boundary per workflow B

## Dependencies

No new system dependencies. `uname(2)` is POSIX. libbpf 1.1+ already required. No new C++ libraries.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
packs:
  architect:  []
  impl:       [lang/cpp.md, lang/cmake.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []
```
