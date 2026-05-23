# Changelog

All notable changes to this project are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

Phase 1 ≈ architect time + human-gate read/approve.
Phase 2–3 ≈ impl + tester running in parallel, plus the build-green / tests-ready handoff.
Phase 4 ≈ reviewer 4-point triangulation + own test re-run.
