# Changelog

All notable changes to this project are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.5.0] — 2026-05-24

MVP-3.3 — systemd + Ansible + fleet docs (brownfield amendment §5.28). Ops-integration slice that makes the existing loader operator-deployable on a Linux host fleet. **Smallest C++/BPF surface area of MVP-3.x to date — zero `src/`/`include/`/`cmake/` diff except the CMake version bump + optional systemd-unit install rule (PI-26).** Loader, BPF datapath, CLI grammar, and exit-code table all byte-identical to 0.4.0.

### Added
- `systemd/xdpmacfilter@.service` — template-instanced systemd unit per §5.28 PI-24 directive catalogue (`Type=oneshot RemainAfterExit=yes`; `ExecStart` = `ExecReload` = `apply -f /etc/xdpfilter/%i.yaml --iface %i`; `ExecStop=detach --iface %i`; `Restart=on-failure RestartSec=5` rate-limited to `StartLimitBurst=5 StartLimitIntervalSec=300` under `[Unit]` per Q4 RT2; `AmbientCapabilities`/`CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE`; `NoNewPrivileges=true`; `After=network-pre.target Wants=network-pre.target` per D-3.3-4; `ConditionPathExists=/etc/xdpfilter/%i.yaml` per D-3.3-5). NO baked-in `Environment=XDPMF_TRUST_MODEL=…` per D-3.3-2 (secure-by-default = strict; operator opts into fleet via Drop-In).
- `ansible/xdpmacfilter-deploy.yml` — minimal example playbook per HG-3.3-2 (single playbook + 1 Jinja2 template + 2 handlers; NOT a role/collection). Play-level `become: true` per D-3.3-7; `daemon-reload` runs as HANDLER not task per D-3.3-8 (idempotency PI-21).
- `ansible/templates/xdpfilter-config.yaml.j2` — Jinja2 template emitting a §5.26+§5.27 schema_version-1 config (PI-17: `schema_version: 1` is a literal at line 1, NOT templated).
- `docs/FLEET_DEPLOYMENT.md` — operator docs (~95 lines) per Q3 D1 covering: `XDPMF_TRUST_MODEL` decision matrix, audit-log story citing the exact stderr prefix `xdpmacfilter: trust_model=` (PI-23 verbatim), systemd Drop-In recipe for fleet posture, Prometheus alert semantic (fleet-wide trust-model uniformity; exporter implementation deferred to MVP-3.4), and the §5.4/§5.19/§5.22/§5.24 fence callout (fleet relaxes ONLY §5.4).
- README "Production deployment" section per Q5 N1 (~15 lines) pointing to the docs/unit/playbook.
- 5 new ctests (§6.32..§6.36): `T_SYSTEMD_UNIT_SYNTAX`, `T_SYSTEMD_LIFECYCLE` (LOAD-BEARING OPS canary), `T_SYSTEMD_RESTART_ON_FAILURE` (Q4 RT2 enforcement), `T_ANSIBLE_PLAYBOOK_SYNTAX` (SKIP-77 if ansible-playbook not in PATH), `T_FLEET_DOCS_SUBSTRING` (PI-23 6-substring grep).
- `XDPMF_INSTALL_SYSTEMD_UNIT` CMake option (default ON per D-3.3-9) — `cmake --install` drops the unit into `${CMAKE_INSTALL_PREFIX}/lib/systemd/system/`.

### Changed
- CMake `project(VERSION)` bumped from `0.4.0` → `0.5.0` (semver minor: new ops-integration artefacts; no functional binary change).

### Preserved invariants (verified by impl smoke)
- PI-7-3.3: `loader.hpp` ZERO diff — THIRD consecutive cycle (MVP-3.1 added one enumerator; MVP-3.2 and MVP-3.3 added zero). Strengthened to ENTIRE `src/lib/` + `src/cli/` + `src/bpf/` + `src/common/` tree being byte-identical.
- PI-26: `git diff main -- src/ include/ cmake/` shows ZERO output; `git diff main -- CMakeLists.txt` shows ONLY the version-bump line + the optional install-rule + the `option(XDPMF_INSTALL_SYSTEMD_UNIT …)` declaration.
- PI-6-3.3: 31 pre-§5.28 ctest bodies BYTE-EQUIVALENT (`git diff --stat tests/T_*.sh` shows ZERO body changes; only NEW T_SYSTEMD_*/T_ANSIBLE_*/T_FLEET_* files appear). STRICT SUPERSET — no carve-outs this slice.
- PI-8-3.3: `xdpmacfilter --version` reports `xdpmacfilter 0.5.0` (driven by CMake `project(VERSION)` via `include/version.h.in` per §5.25 P3).
- PI-9: `--help` / `--version` output FORMAT unchanged (no new CLI flag per D-3.3-1).
- PI-10-3.2: `src/common/mac_filter.h` constants + struct layout UNCHANGED (strengthened — this slice adds zero new constants).
- PI-17: `schema_version: 1` literal at line 1 of the Jinja2 template (NOT templated — load-bearing for the architectural promise that the rendered config is grammar-compatible with the existing apply -f validator).
- PI-19: `systemd-analyze verify` accepts the unit with zero stderr warnings.
- PI-23: `docs/FLEET_DEPLOYMENT.md` cites the EXACT runtime stderr prefix `xdpmacfilter: trust_model=` (verbatim, not paraphrased).
- PI-24: unit file directive set EXACTLY matches the §5.28 PI-24 catalogue.

### Out-of-scope fences (per §5.28)
- Binary rename `xdpmacfilter` → `xdpfilter` — still MVP-3.12 (transitional alias to come).
- Per-rule counters / `xdpmf-exporter` binary / Prometheus exporter — MVP-3.4 slice. Fleet docs describe the alert SEMANTIC only.
- SIGHUP signal handler — fenced by Q2 R1 (reload is re-exec-of-apply, atomic-swap-preserving).
- `--quiet` / `--syslog` / `--log-format=json` CLI flag — fenced by D-3.3-1 (PI-7-3.3 ZERO-diff loader.hpp).
- Baked-in `Environment=XDPMF_TRUST_MODEL=…` in the shipped unit — fenced by D-3.3-2 (secure-by-default; Drop-In is the explicit-opt-in mechanism).
- Full Ansible role/collection — minimal example only per HG-3.3-2.
- systemd hardening beyond `AmbientCapabilities` + `NoNewPrivileges` + `CapabilityBoundingSet` (no `ProtectSystem=` / seccomp / `User=` non-root) — operator's call.
- MVP-3.1/3.2 OOT-deferred housekeeping items — per Q6 DEFER (candidate dedicated MVP-3.3.5 cycle).

## [0.4.0] — 2026-05-24

MVP-3.2 — L3 src-CIDR rule type (Composite 6 cycle 2). First extension WITHIN the §5.26 config-driven path: adds a CIDR axis OR-composed with the existing MAC axis at the BPF datapath. IPv4-only per HG-3.2-1 (v6 explicitly rejected at the validator with a recognizable stderr).

### Added
- `src_cidr` rule-match key (§5.27 Q3 K2): `match: {src_cidr: "10.0.0.0/8"}`. Rules may set `mac` only, `src_cidr` only, or BOTH (OR-compose; first axis to match wins). Validator enforces "at-least-one-of mac/src_cidr" per rule (§5.27 rule 7, supersedes §5.26 rule 5).
- `src/lib/cidr.{cpp,hpp}` — IPv4 CIDR string parser (`A.B.C.D/N`) with host-bits-set rejection (`"10.0.0.5/8"` → hint to `10.0.0.0/8`), v6 rejection (any `:` in the value → `IPv6 CIDR not supported until MVP-3.2.5`), and standard `inet_pton(AF_INET, ...)` address parsing. All failures throw `LoaderError::ConfigError` (exit 9) — `loader.hpp` enum is UNCHANGED (PI-7-3.2 strengthened from §5.26).
- BPF datapath gains CIDR axis (§5.27 Q1 AS1 + Q2 OR1): `cidr_allowlist_a`/`cidr_allowlist_b` LPM_TRIE inners + `cidr_rulesets` ARRAY_OF_MAPS outer (parallel to existing MAC `rulesets`). Both outers share the same `active_idx` map; a single u32 store on `active_idx[0]` is the atomic commit for BOTH axes simultaneously (Composite-6 swap promise preserved byte-for-byte). The BPF program reads `active_idx` ONCE per packet and uses the snapshot for both MAC + CIDR lookups — no intra-packet axis split.
- `STAT_PASS_CIDR = 3` PERCPU counter (§5.27 stats split): operators reading `read_stats.py --include-pass-cidr` see the MAC-vs-CIDR pass split. `STAT_MAX` sentinel bumps `3 → 4` (additive accounting; existing slots 0/1/2 byte-identical per PI-10-3.2).
- `tests/lib/read_stats.py --include-pass-cidr` flag (opt-in 4-column output). Default 3-column output BYTE-IDENTICAL to pre-§5.27 per PI-13-3.2 (back-compat for the 27 existing ctests).
- `tests/lib/common.sh` helpers: `read_stats_with_cidr <pin>` (4-column reader) + `wait_for_stats_sum_with_cidr <iface> <expected_sum>` (4-counter sum poll). Existing `read_stats`/`wait_for_stats_sum` UNCHANGED.

### Changed
- CMake `project(VERSION)` bumped from `0.3.0` → `0.4.0` (semver minor: new feature axis, backward-compatible CLI surface AND backward-compatible YAML schema).
- `mac_filter.bpf.c` datapath extended with the OR-compose branch: MAC HASH first (O(1) short-circuit per Q2 OR1), then on IPv4 ethertype lookup src_ip in the CIDR LPM_TRIE (O(prefix-length)). Non-IPv4 frames (ARP, IPv6, VLAN-tagged) bypass the CIDR branch entirely — preserves MVP-3.1 semantic for non-IP traffic. IP-header bounds check is verifier-mandatory before `ip->saddr` deref; truncated IPv4 frames bump `STAT_DROP_MALFORMED` (consistent with §5.5).
- `src/common/mac_filter.h` gains `struct xdpmf_cidr_v4 {prefixlen, addr}` (LPM_TRIE key shape) + 3 new map-name macros (`XDPMF_MAP_CIDR_{RULESETS_OUTER,INNER_A,INNER_B}_NAME`) + `STAT_PASS_CIDR = 3` enum value + `STAT_MAX = 4` bump. Existing constants UNCHANGED.
- `internal::apply_request` populates the inactive CIDR LPM_TRIE inner alongside the inactive MAC HASH inner BEFORE the single `active_idx` flip (§5.27 apply ordering steps 1-5). D-3.1-4 state-b `bpf_map__reuse_fd` loop extends 6 → 9 maps to cover `cidr_allowlist_a`/`cidr_allowlist_b`/`cidr_rulesets`.
- `tests/T_APPLY_REJECTS_MALFORMED.sh` (§6.22) extended with 3 new sub-cases (6/7/8 — v6 reject, host-bits-set reject, not-a-cidr reject) per PI-6-3.2 carve-out (the only ctest body diff allowed in MVP-3.2; all other 27 ctest bodies BYTE-EQUIVALENT). [Tester ships sub-cases; impl provides fixtures.]

### Preserved invariants (verified by impl smoke)
- PI-7-3.2: `loader.hpp` ZERO diff (strengthened from §5.26's "one new enumerator"). `LoaderError` enum stays at 9 values; CIDR validation reuses `ConfigError = 9`.
- PI-10-3.2: existing `mac_filter.h` constants + `struct xdpmf_mac` layout + enum slots 0/1/2 BYTE-IDENTICAL.
- PI-13-3.2: `stats` map type UNCHANGED (PERCPU_ARRAY); `read_stats.py` default mode 3-column output BYTE-IDENTICAL.
- PI-15: MAC-only configs (`match: {mac: ...}` only) produce byte-equivalent runtime behaviour; the CIDR-inner population path runs as a no-op when no rule has `src_cidr`.
- PI-17: `schema_version: 1` continues as the only supported value; `src_cidr` is grandfathered into v1 per the §5.26 Q5 SV2 migration-policy refinement (one additive match-key does NOT justify a version bump).

### Out-of-scope fences (per §5.27)
- IPv6 CIDR matching — fenced to MVP-3.2.5+ (v6 strings rejected with recognizable stderr).
- `dst_cidr`/port/VLAN match-keys — Q3 K2 leaves space; not in cycle 2.
- List-of-CIDRs per rule (Option L2) — Q4 L1; additive forward path.
- Per-rule counters keyed by `rule_id` — MVP-3.4 slice.
- MVP-3.1 OOT-deferred housekeeping items (OOT-1..OOT-4) — Q6 DEFER.

## [0.3.0] — 2026-05-24

MVP-3.1 — config-first foundation (Composite 6 cycle 1; six bundled pieces). The largest mint slice to date and the architectural foundation for MVP-3.N.

### Added
- `apply` subcommand: `xdpmacfilter apply --iface <IFNAME> -f <PATH> [--mode <M>]`. Reads YAML config; atomic hot-swap when an existing link pin is present (no packet drop window; verified by `T_APPLY_ATOMIC_SWAP_NO_DROP`).
- Custom YAML 1.2 subset parser in `src/lib/yaml_subset.{cpp,hpp}` (no third-party deps per HG1). Accepted constructs: block mapping, block sequence, single/double-quoted scalars, bareword scalars, signed-decimal integers, null/`~`, `#` comments, optional leading `---`. DoS guards: 1 MiB file, 4 KiB scalar, 8-level nesting. Everything else → `ConfigError` (exit 9) with `xdpmacfilter: config error: <feature>: <file>:<line>:<col>` stderr.
- Typed config schema in `src/lib/config.{cpp,hpp}`: `Config` / `Rule` / `RuleMatch` / `DefaultAction` / `RuleAction`. Schema version 1: `default_action` REQUIRED ∈ {drop,pass}; `rules` list of `{id, action, match.mac}`; rule id ∈ [0, 63] unique; only `mac` match type in cycle 1 (forward-compat hinge for MVP-3.2 CIDR).
- BPF map architecture for atomic apply (Q2 A1 + Q2-extension): `ARRAY_OF_MAPS[2]` outer (`rulesets`) + `ARRAY[1]` `active_idx` selector + `ARRAY[2]` `defaults` (drop/pass per slot). Userspace populates the inactive slot, then writes a single u32 `active_idx[0]` — kernel-atomic on aligned word stores; the swap atomically replaces ruleset AND default.
- `bpf_link__pin` survival across loader exit (HG2 P0a): the XDP attachment is pinned at `${XDPMF_BPFFS_ROOT}/<iface>/link`. Filter persists past `apply` invocation exit; subsequent applies hot-swap via `bpf_link__update_program` (no kernel detach, no fresh attach).
- `XDPMF_TRUST_MODEL` env var (HG3): `strict` (default) | `fleet`. `fleet` relaxes the §5.4 alien-program refusal ONLY (still detaches the alien and proceeds). `§5.19` (name-check) and `§5.22` (tag-check + O_PATH path-discipline) remain enforced in both modes. Audit story: mandatory stderr-log `xdpmacfilter: trust_model=<m>` at `attach`/`apply` entry.
- Internal STATIC library `xdpmf_internal` (Q1 R1) aggregating `src/lib/*.cpp` (loader + config + yaml_subset). No installed headers; no SONAME; no public ABI surface (promotion to `libxdpmf.so.0` is MVP-3.6+ optional branch).
- New exit code 9 = `LoaderError::ConfigError`: YAML parse failure / schema-validation failure / interface-mismatch / unknown trust model. Distinct from exit 1 (CLI usage) and exit 8 (path-refused).
- 7 new ctests: `T_APPLY_VALID_CONFIG`, `T_APPLY_REJECTS_MALFORMED`, `T_APPLY_ATOMIC_SWAP_NO_DROP`, `T_APPLY_REPLACES_RULESET`, `T_LINK_PERSIST_ACROSS_LOADER_EXIT`, `T_TRUST_MODEL_FLEET_RELAXES_GATE`, `T_EXIT_CODE_9_ON_CONFIG_ERROR` (tester output; impl ships fixtures `tests/fixtures/config_*.yaml`).
- New `tests/lib/common.sh` helpers: `apply_config <path> <iface>`, `wait_for_active_idx_flip <iface> <expected>`, `kill_loader_keep_link <iface>`.

### Changed
- `src/loader/` → `src/lib/` + `src/cli/` directory split per Q1 R1 minimum split. `loader.{cpp,hpp}` / `raii.hpp` / new `yaml_subset.{cpp,hpp}` / new `config.{cpp,hpp}` live under `src/lib/`. `cli.{cpp,hpp}` / `main.cpp` / new `apply.{cpp,hpp}` live under `src/cli/`. Binary moves from `${BUILD_DIR}/xdpmacfilter` to `${BUILD_DIR}/src/cli/xdpmacfilter`; `find_loader` in `common.sh` searches the new path first.
- CMake `project(VERSION)` bumped from `0.2.3` → `0.3.0` (semver minor — new feature, backward-compatible CLI surface).
- `attach --allow <MAC>` (existing MVP-1+ surface) is now a silent shorthand for the apply path per Q3 BC1: the CLI synthesizes a Drop-default Config and feeds it through the same `internal::apply()` helper that `apply -f` uses. Byte-identical invocation; no deprecation warning; 20 existing ctests pass unchanged.
- `mac_filter.bpf.c` datapath rewritten to use the chained `active_idx` → `rulesets[active]` → inner MAC lookup → `defaults[active]` pattern. `mac_filter_prog` symbol name + SEC unchanged (§5.19 / §5.22 identity-gate contract preserved).
- `loader.hpp` gains EXACTLY ONE new enumerator: `ConfigError = 9` (PI-7 single-line invariant; mirrors §5.22 `PathRefused = 8` and §5.24 `KernelUnsupported = 7` precedent).
- `--help` text gains `apply` row + `-f` option + `9 config-error` row in the exit-code table.

### Internal (not part of public CLI surface)
- New private header `src/lib/apply_internal.hpp` (NOT in design FileList; deviation documented in `mint/impl-notes.md`). Exposes `internal::apply(ApplyRequest)` — the single atomic-apply implementation shared between `loader::attach()` (legacy AttachConfig path) and `apply_config_inmemory()` (Config path). Keeps the atomic-swap machinery in exactly one place per §5.26 design intent ("ONE helper (impl detail)") while honouring PI-7 (loader.hpp diff = exactly one enumerator).

### Preserved invariants (verified by impl smoke)
- PI-7: `loader.hpp` diff = file rename `src/loader/` → `src/lib/` + ONE added enumerator line `ConfigError = 9,`. No other line changes.
- PI-8: `xdpmacfilter --version` reports `xdpmacfilter 0.3.0` (CMake `project(VERSION)`-driven via `include/version.h.in`).
- PI-9: `--help` text format compatible with `T_CLI_HELP_VERSION`'s forward-flexible ERE (just adds rows; doesn't break the existing capture groups).
- HG3 sub-decision: `XDPMF_TRUST_MODEL=<garbage> --version` does NOT exit 9 (trust_model is parsed only on attach/apply paths). Verified.

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
| MVP-2 Polish-2 (final MVP-2 slice) | 4 janitorial items + 4 architect decisions (Q1=N3 netns wrap / Q2=C1 sed extraction / Q3=V1 project(VERSION) source-of-truth + version bump 0.1.0→0.2.3 / Q4=T1 no test edit) + 3 Phase B EDITs inline-merged (EDIT-13 opt-out roster correction, EDIT-14 env-after-NSEXEC idiom, EDIT-15 mount-ns preservation via `nsenter --net` instead of `ip netns exec`) + 3 OUT-OF-TRIANGULATION sweep | 16m | 21m | 10m | 47m | round 1 ✓ (0 findings) |
| MVP-3.2 (additive within config harness) | 1 axis (L3 src-CIDR LPM_TRIE) + OR-compose datapath + parallel ARRAY_OF_MAPS outer + 6 architect decisions (Q1=AS1 parallel outers / Q2=OR1 MAC-first / Q3=K2 src_cidr naming / Q4=L1 single CIDR per rule / Q5=V1 schema-additive / Q6=DEFER housekeeping) + HG-3.2-1 v4-only + new STAT_PASS_CIDR counter (STAT_MAX bump 3→4) + 4 new ctests + 3 sub-cases on §6.22 + `loader.hpp` ZERO diff (PI-7 strengthened) | TBD | TBD | TBD | TBD | TBD |
| MVP-3.3 (ops integration, brownfield) | 4 NEW text artefacts (systemd unit + Ansible playbook + Jinja2 template + fleet-deployment docs) + 5 new ctests (§6.32..§6.36) + 6 architect Q-decisions (Q1=I1 system-path / Q2=R1 re-exec-apply / Q3=D1 single MD / Q4=RT2 rate-limited / Q5=N1 1-section README / Q6=DEFER) + 3 human-gate confirmations + 9 D-3.3-N rationale decisions + CMake `XDPMF_INSTALL_SYSTEMD_UNIT` option + version 0.4.0→0.5.0 + 8 NEW preserved invariants (PI-19..PI-26) — **ENTIRE `src/`/`include/`/`cmake/` tree ZERO diff** (PI-7-3.3 + PI-26 strengthened) | TBD | TBD | TBD | TBD | TBD |

Phase 1 ≈ architect time + human-gate read/approve.
Phase 2–3 ≈ impl + tester running in parallel, plus the build-green / tests-ready handoff.
Phase 4 ≈ reviewer 4-point triangulation + own test re-run.
