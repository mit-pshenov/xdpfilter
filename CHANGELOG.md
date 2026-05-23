# Changelog

All notable changes to this project are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.3] — 2026-05-23

MVP-2 Polish-2 — netns isolation + CMake-gen `PIN_ROOT` + version-string sync + `inject_runt:37` comment fix (fourth and final MVP-2 pass).

### Added
- Per-PID netns isolation for veth-fixture tests (design §5.25 P1, Q1 = N3). `tests/lib/common.sh setup_veth` creates `xdpmf_ns_$$`, builds the veth pair inside it, and runs loader/injectors through `${NSEXEC}` (= `sudo -n nsenter --net=/var/run/netns/${NETNS}` — `nsenter --net` is used instead of `ip netns exec` to preserve the mount namespace so host bpffs at `/sys/fs/bpf` remains visible to the loader child; rationale in design.md EDIT-15). Closes the sysctl-pollution gap left by PID-suffix-only iface naming.
- Configure-time `XDPMF_BPFFS_ROOT` extraction in `CMakeLists.txt` (design §5.25 P2, Q2 = C1) → generated `${CMAKE_BINARY_DIR}/tests/pins.sh` (template: `tests/lib/pins.sh.in`). `tests/lib/common.sh` sources it (with `:?` integrity guards) instead of mirroring the literal — silent drift between header and test fixture is now impossible.
- Configure-time `version.h` generation from `project(VERSION ...)` (design §5.25 P3, Q3 = V1) → `${CMAKE_BINARY_DIR}/include/version.h` (template: `include/version.h.in`). `src/loader/cli.cpp` consumes the generated `XDPMF_VERSION_STRING` macro; the hardcoded `kVersion` constant is removed.

### Changed
- CMake `project(VERSION ...)` bumped from `0.1.0` → `0.2.3` (semver patch — Polish-2 is maintenance; no new features, no breaking changes).
- `xdpmacfilter --version` output now reflects `project(VERSION)` (was hardcoded `0.1.0`; is now `0.2.3` and tracks the CMake version automatically going forward).
- `tests/lib/common.sh` `PIN_ROOT` is sourced from generated `pins.sh` (was hardcoded mirror of the header macro).

### Fixed
- `tests/inject/inject_runt.py:37` inline comment (design §5.25 P4): now matches the lines 18-19 docstring corrected in MVP-1.1C B1 — 13 bytes = full 6-byte dst MAC + full 6-byte src MAC + 1 ethertype byte. Byte literals at lines 41-43 untouched (explicit OOS).

## [0.2.2] — 2026-05-23

MVP-2 Robust — kernel-version probe + `T_VERIFIER_REJECT` (third MVP-2 pass).

### Added
- Kernel-version probe via `uname(2)` + parse `release` field; floor is `5.15`. Fires at the head of both `attach()` and `detach()` BEFORE any libbpf call — replaces cryptic `BPF_PROG_LOAD: Invalid argument` from deep libbpf with a clear `xdpmacfilter: kernel <maj>.<min> too old, need ≥ 5.15`.
- New exit code 7 = `LoaderError::KernelUnsupported` (the long-reserved row in §4.1 is now active; enum is now contiguous-from-2 through code 8).
- `T_VERIFIER_REJECT` — regression test for the verifier-reject path. Uses a deliberately-bad BPF fixture (`tests/fixtures/mac_filter_bad.bpf.c` — unbounded loop without `#pragma unroll`); asserts loader exits 2 (`LoadFailed`) with recognizable libbpf stderr. Degrades gracefully (`SKIP_RETURN_CODE 77`) if the running kernel happens to accept the bad fixture.
- `XDPMF_BPF_OBJECT_PATH` environment variable — testing-only override of the compiled-in BPF object path; honored symmetrically in attach/detach. Intentionally undocumented in `--help` (production operators don't set it).

### Operational notes
- The probe is operator-UX, not a security mechanism — its purpose is replacing cryptic libbpf errors with a clear "upgrade your kernel" message. No `--no-version-probe` escape hatch; operators on backported kernels can locally patch `kKernelFloorMajor/Minor` constants in `loader.cpp` and rebuild.

## [0.2.1] — 2026-05-23

MVP-2 Perf — PERCPU stats migration + `--mode {generic,native,offload}` CLI flag (second MVP-2 pass).

### Added
- `--mode {generic,native,offload}` CLI flag on the `attach` subcommand (default `generic` — preserves MVP-1 SKB baseline). Maps to `XDP_FLAGS_SKB_MODE` / `XDP_FLAGS_DRV_MODE` / `XDP_FLAGS_HW_MODE`. `detach` does NOT accept `--mode` (mode is auto-detected from the §5.20 all-modes probe; explicit rejection with exit 1 + `attach-only` stderr).
- `enum class XdpMode` in `loader.hpp` (public API addition; second relaxation of the MVP-2 Sec "byte-identical" invariant — intentional, the cleanest CLI-to-loader carrier).
- `T_MODE_GENERIC_DEFAULT` — default-mode attach + mode-probe assertion (accepts string `generic`/`xdpgeneric` AND numeric `2` for kernel/iproute2 variance).
- `T_MODE_NATIVE_UNSUPPORTED` — `attach --mode native --iface lo` → exit 3 + `native` stderr (kernel rejects native XDP on loopback).
- `T_PERCPU_STATS_SUM` — fixture-level PERCPU sum-correctness test. Seeds `STAT_PASS` with broadcast value V=42 via `bpftool map update`, asserts `read_stats.py` returns `nr_cpus * V` (discriminator: a CPU-0-only read would return V, not the sum).
- `T_MODE_DETACH_REJECTS` — `detach --mode <X>` → exit 1 + `attach-only` stderr. Two sub-cases (`native` + `generic`) prove the rule is flag-presence-driven, not flag-value-driven.

### Changed
- `stats` BPF map type: `BPF_MAP_TYPE_ARRAY` → `BPF_MAP_TYPE_PERCPU_ARRAY`. Closes counter-loss-under-load + cache-line-bouncing flagged by hybrid-review.md perf HIGH. First `.bpf.c` edit since MVP-1.
- `read_stats.py` sums across CPUs (bpftool `--json` PERCPU schema: `entry["values"]` plural array). Output format unchanged for callers.
- `is_ours` identity-gate predicate mode-axis: relaxed from `(mode == SKB)` to `(mode != None)` — accepts our prog in any of SKB / NATIVE / HW. Required for multi-mode attach correctness.
- `detach()` now passes the §5.20-probed mode through to `bpf_xdp_detach` instead of hardcoded `XDP_FLAGS_SKB_MODE` — closes the symmetric mode-handling gap.
- `--help` text now documents `--mode` (attach-only).

### Fixed
- Pre-existing typo in design.md §3.4 callout (`Decision §5.5` → `Decision §5.3`) — opportunistic cleanup during MVP-2 Perf §5.3 supersede edit.

## [0.2.0] — 2026-05-23

MVP-2 Sec — §5.19 tag-check identity gate + O_PATH bpffs root hardening (first MVP-2 pass).

### Added
- §5.22 tag-check identity gate: `bpf_prog_info.tag` (SHA-1 of post-libbpf-preprocessing bytecode) added to the `is_ours` predicate on top of the MVP-1.1B name-check. Self-tag captured via Q1 Option E (load skeleton first, query own tag, then probe). Closes the attacker-recompile vector (same `SEC()` name + altered bytecode → tag mismatch → refuse).
- §5.22 O_PATH bpffs root hardening: `BpffsRootFd` RAII opens `/sys/fs/bpf/xdpmacfilter/` with `O_PATH | O_DIRECTORY | O_NOFOLLOW`; all bpffs ops converted to fd-relative `*at()` syscalls (`faccessat`/`mkdirat`/`openat`+`fdopendir`+`unlinkat` walk/`fstatat AT_SYMLINK_NOFOLLOW`). Closes the symlink-vortex vector at both root and per-iface levels.
- New exit code 8 = `PathRefused`: fires when bpffs root or per-iface entry is a symlink / not-a-directory. Distinct audit signal from exit 4 (alien-prog refusal) and exit 6 (kernel permission).
- `T_ATTACH_TAG_MISMATCH` — tag-mismatch refusal regression test with defensive tag-distinctness preflight + loader-twice negation control (state-(b) idempotent reload via fresh prog id assertion).
- `T_BPFFS_ROOT_SYMLINK` — symlink-refusal regression test (root + per-iface variants) with trap-driven destructive-setup cleanup.
- `tests/fixtures/mac_filter_alt.bpf.c` — alt BPF fixture (same SEC name, minimal body) for the tag-mismatch test.

### Changed
- `detach()` is now symmetric to `attach()` for the identity gate: also early-loads skeleton, captures self_tag, runs the probe — closes a parallel attacker-recompile vector where an attacker's planted same-named alien could be detached by an operator running `xdpmacfilter detach`.
- §6.13 T_DETACH_NOTHING ctest property gains `RESOURCE_LOCK xdp_fixture` to prevent races with T_BPFFS_ROOT_SYMLINK's destructive setup.

### Operational notes (NOT a behaviour bug — strictness consequence of tag-check)
- Cross-loader idempotency is NOT supported: if you manually load `mac_filter.bpf.o` via `bpftool prog load` or `ip link set xdpgeneric obj` outside of `xdpmacfilter`, the loader will refuse to recognize it as ours (exit 4 + `tag mismatch`). Reason: kernel-computed `bpf_prog_info.tag` differs across libbpf rewrite paths (CO-RE relocations, subprog inlining) even for the same `.bpf.o`. Workaround: detach the external load first (`ip link set <iface> xdp off`), then run `xdpmacfilter attach`.

## [0.1.3] — 2026-05-23

MVP-1.1C — hybrid-review polish batch (third refactor pass).

### Added
- `CHANGELOG.md` (this file).
- CLI-surface tests: `T_CLI_HELP_VERSION`, `T_CLI_CAPACITY`, `T_CLI_BAD_MAC`.
- `T_DETACH_NOTHING` — idempotent-detach regression test.
- `wait_for_stats_sum` poll helper in `tests/lib/common.sh` (replaces
  post-inject `sleep` calls — flake reducer).
- `require_passwordless_sudo` preflight — root-requiring tests now skip
  (ctest code 77) instead of failing when sudo would prompt.

### Changed
- `AttachConfig` / `DetachConfig` moved from `src/loader/cli.hpp` to
  `src/loader/loader.hpp`; CLI parser now depends on the loader header
  (control plane no longer transitively depends on the CLI parser).
- `detach()` is now fully idempotent — running it on an interface with
  no XDP attached and no bpffs dir returns exit 0 (was exit 5).
- Test iface names are PID-suffixed (`xdpmf_a_$$` / `xdpmf_b_$$`) to
  avoid collisions on multi-tenant CI / developer hosts; `setup_veth`
  preflights for name collisions.
- `T_IDEMPOTENT_RELOAD` outcome check replaces racy global
  `bpftool prog show | wc -l` delta with per-iface `xdp_prog_id`.
- `CMakeLists.txt` `pkg_check_modules` now requires `libbpf >= 1.1`
  (already implicit via `bpf_xdp_query`/`bpf_xdp_attach` API use).

### Fixed
- `tests/inject/inject_runt.py` docstring — corrected the wire-format
  description (13 bytes, full dst+src MAC + 1 ethertype byte) and the
  src-MAC-after-padding value (`:00`, not `:99`).
- `src/loader/raii.hpp` `BpffsDir` comment — described the real
  `arm()`/`release()` API (no `create()` method exists; creation is in
  `loader.cpp` via `std::filesystem::create_directories`).

## [0.1.2] — 2026-05-23

MVP-1.1B — §5.4 trust-boundary hardening.

### Added
- §5.19 identity-verified ownership: `bpf_prog_info.name` match against
  `"mac_filter_prog"` gates the "ours" classification.
- §5.20 all-modes XDP probe (`bpf_xdp_query` with `flags=0`) — alien
  programs attached in NATIVE / HW modes now classify correctly
  (previously invisible to the SKB-only query → silent clobber attempt).
- `T_ATTACH_ALIEN_REFUSAL` end-to-end test; vendored foreign-XDP
  fixture `tests/fixtures/xdp_pass.bpf.c`.

### Fixed
- KC-A kill-chain (planted-pin-dir spoofed ownership → drop-all
  blackhole DoS) closed by the identity gate above.
- KC-B detection blind-spot (non-SKB alien programs slipped past the
  refusal path) closed by the all-modes probe above.

## [0.1.1] — 2026-05-23

MVP-1.1A — hybrid-review quick wins.

### Added
- `XDPMF_SANITIZERS` CMake option (default OFF) — combined ASAN+UBSAN
  build mode for the C++ loader (test-only; byte-identical to the
  default build when OFF).
- `T_SANITIZER_BUILD` end-to-end memory-safety smoke test.
- `README.md` — repo entry-point doc.

### Changed
- Namespace and shared-header cleanups; `loader.hpp` return type
  tightened to `std::uint32_t` (matches kernel `__u32`).

## [0.1.0] — 2026-05-22

MVP-1 — initial vertical slice.

### Added
- XDP program (`src/bpf/mac_filter.bpf.c`): L2 source-MAC allow-list
  with `XDP_PASS` / `XDP_DROP` decisions; three pinned counters
  (`STAT_PASS`, `STAT_DROP_DENY`, `STAT_DROP_MALFORMED`).
- C++23 loader (`xdpmacfilter`) with `attach` / `detach` subcommands;
  per-iface bpffs pin layout at `/sys/fs/bpf/xdpmacfilter/<iface>/`;
  4-state idempotent-reload probe (Decision §5.4).
- ctest suite: `T_BUILD`, `T_LOAD_ATTACH`, `T_PASS_ALLOWED`,
  `T_DROP_DENY`, `T_DROP_MALFORMED`, `T_IDEMPOTENT_RELOAD`,
  `T_NEGATION_CONTROL`.

---

## Build pace

Wall-clock per `/mint` phase boundary (commit-to-commit, from `git log`).
Includes agent work, peer dialog, AND human-gate decision time —
the slow phases are usually the ones where the human spent the most
time reading and asking clarifying questions, not where the agents
got stuck.

| Pass | Scope | Phase 1 (architect) | Phase 2–3 (impl + tester) | Phase 4 (reviewer) | Total active | Rework |
|---|---|---|---|---|---|---|
| MVP-1 (greenfield) | 10 src files, 7 ctest entries | — | 18m | 9m | — | round 1 ✓ + post-pass §4.3/§5.16 amendment (3m) |
| MVP-1.1A (additive refactor) | 3 items: sanitizer mode, README, FileList drift | — | 8m | 7m | — | round 1 ✓ |
| MVP-1.1B (source-change refactor) | 4 items: §5.4 4-state machine, identity verification, all-modes probe, alien-refusal test | 12m | 11m | 6m | 30m | round 1 ✓ |
| MVP-1.1C (polish batch) | 12 items × 4 sections + D4 detach idempotency | 60m | 18m | 10m | 88m | round 1 ✓ |
| MVP-2 Sec (security pass) | 2 items + 2 tests + 3 architect decisions (Q1/Q2/Q3) + Phase B amendments (detach symmetry, §6.14 reshape, tag-stability finding) + 1-line loader.hpp relaxation | 34m | 34m | 7m | 75m | round 1 ✓ (0 findings) |
| MVP-2 Perf (performance pass) | 3 items + 4 tests + 3 architect decisions (Q1/Q2/Q3) + Phase B test fixups (3 empirical issues: bpftool broadcast-only, jq numeric mode, stale-pin cleanup) + 2 OUT-OF-TRIANGULATION spec-wording fixes inline-merged + public-API relaxation (XdpMode enum + AttachConfig.mode field) | 14m | 24m | 10m | 48m | round 1 ✓ (0 findings) |
| MVP-2 Robust (robustness pass) | 2 items + 1 test + 4 architect decisions (Q1=uname / Q2=5.15 / Q3=attach+detach / Q4=hybrid fixture) + Phase B fixups (libbpf 1.x substring reality EDIT-11, fixture-must-have-maps for skeleton-populate, TIMEOUT 30→60 EDIT-12) + 1-line loader.hpp relaxation (KernelUnsupported=7) | 14m | 26m | 9m | 49m | round 1 ✓ (1 negotiated minor) |

Phase 1 ≈ architect time + human-gate read/approve.
Phase 2–3 ≈ impl + tester running in parallel, plus the build-green / tests-ready handoff.
Phase 4 ≈ reviewer 4-point triangulation + own test re-run.
