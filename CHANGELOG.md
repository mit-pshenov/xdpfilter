# Changelog

All notable changes to this project are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

Phase 1 ≈ architect time + human-gate read/approve.
Phase 2–3 ≈ impl + tester running in parallel, plus the build-green / tests-ready handoff.
Phase 4 ≈ reviewer 4-point triangulation + own test re-run.
