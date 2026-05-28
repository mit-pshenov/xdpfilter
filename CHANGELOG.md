# Changelog

All notable changes to this project are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Performance
- **MVP-3.4i (§5.40)** — `xdpmf-exporter`: reduce `/metrics` scrape CPU + allocations (PERCPU read-buffer hoist out of the per-key loop in both readers, `std::format_to` in-place emission, two-step HTTP header/body write on the hot `/metrics` path, sorted-vector rule_id→action lookup replacing `unordered_map`); output is byte-stream-identical for the first three and line-set-identical for the fourth (deterministic ascending-`rule_id` order). No semantic/label/value change; no VERSION bump. Closes /mint-review performance Major-1 + Med-1/2/3 (Med-4 fd-cache DEFERRED).

### Housekeeping
- **MVP-3.4g (§5.38)** — `src/lib/raii.hpp`: dead-code cleanup — `BpffsDir` + `XdpAttachment` removed (superseded by `IfaceDirGuard` since §5.22).

### Security
- **MVP-3.4h (§5.39)** — `xdpmf-exporter` emits startup WARN (event `exporter.warn.bind_non_loopback`) when `--bind` resolves to a non-loopback IPv4 address (anything outside `127.0.0.0/8`); `/metrics` endpoint exposure on a routable interface is now audit-visible (closes /mint-review sec M2; KC-2 observability half — KC-2 mitigation half / auth+TLS remains OOS). Text-mode prose `xdpmf-exporter: WARN --bind <addr> is not loopback (127.0.0.0/8); /metrics will be exposed on a routable interface`. WARN-only posture (no refusal — legitimate fleet-ops sidecar patterns preserved); default `--bind=127.0.0.1` stays silent → PI-3.5-1 byte-equivalence on all existing exporter paths PRESERVED. `kEventNames` catalog 36 → 37; `tests/fixtures/log_events_v1.txt` lockstep 36 → 37 lines. 1 new ctest (`T_EXPORTER_BIND_NON_LOOPBACK_WARN`; `RESOURCE_LOCK exporter_port_9417`); ctest baseline 67 → 68. No VERSION bump (pure observability addition).
- **KC-3 closure (MVP-3.4e / §5.36)** — bilateral restoration of the §5.22 BpffsRootFd / `O_PATH|O_NOFOLLOW` invariant across two paths that opted out of it in earlier slices. (1) `reset-counters --iface X` now routes through a new internal helper (`xdpmf::internal::reset_counters_request`) that composes `validate_iface_name` (shape-check) + `BpffsRootFd` + `iface_entry_is_real_dir` BEFORE constructing pin paths or calling `bpf_obj_get`. Path-traversal-shaped or symlink-shaped `--iface` inputs are refused with exit 8 + stderr `refusing to operate` instead of silently zeroing arbitrary PERCPU pins under `/sys/fs/bpf/`. (2) Sidecar `write_rule_index` (`/run/xdpmacfilter/<iface>/rule_index.json`) upgraded from path-based `lstat`+`open`/`mkdir`/`rename` to fd-relative `mkdirat`/`fstatat`/`openat(O_NOFOLLOW)`/`renameat` rooted in an `O_PATH|O_DIRECTORY|O_NOFOLLOW` SIDECAR_ROOT fd, with per-iface symlink detection via `fstatat(AT_SYMLINK_NOFOLLOW)`. Per-iface symlink at `/run/xdpmacfilter/<iface>` now triggers new `sidecar.warn.iface_dir_symlink` event + skip-and-return (apply continues, exits 0 — PI-32-3.4b sidecar-never-throws PRESERVED; exporter degrades to `action="unknown"` per existing PI-32-3.4b path). No version bump — internal security hardening with no operator-observable feature surface change beyond exit-code/stderr disposition on attack-shaped inputs.
- **1 new logger event** — `sidecar.warn.iface_dir_symlink`. `kEventNames` catalog 35 → 36; `tests/fixtures/log_events_v1.txt` lockstep 35 → 36 lines.
- **2 new ctests** — `T_RESET_COUNTERS_PATH_TRAVERSAL` (KC-3 reset-counters limb — `--iface ../foo` + whitespace-shaped iface → exit 8) + `T_SIDECAR_IFACE_SYMLINK_REFUSAL` (KC-3 sidecar limb — per-iface symlink at `/run/xdpmacfilter/<iface>` → WARN + skip + apply exit 0; attacker target file absent). Both `RESOURCE_LOCK xdp_fixture` (D-3.4e-T2-LOCK — no new lock domain). ctest baseline 64 → 66.

## [0.10.0] — 2026-05-27

MVP-3.4d — `reset-counters` subcommand + `rule_counters` axis atomic-swap promotion (brownfield amendment §5.35). Closes the **counter management API** + `rule_counter` atomic-swap split out from §5.34 §7 OOS as the follow-up `reset-counters` fence. Two coupled deliverables — (1) NEW `xdpmacfilter reset-counters --iface X [--rule-id N]` subcommand that explicitly zeros the per-rule packet counters; (2) `rule_counters` PERCPU_ARRAY promoted to parallel `rule_counters_outer` ARRAY_OF_MAPS[2] of `rule_counters_a`/`_b` inner PERCPU_ARRAYs — 5th axis of atomic-swap. **PI-3.4b-2 counter-monotonicity-across-apply EXPLICITLY PRESERVED**: the atomic-swap shape change is structural-only; counters survive `apply -f` via a NEW apply-step per-CPU **copy-forward** from old-active inner to inactive inner BEFORE the active_idx flip. Reset zeroing is operator-action-only via the new CLI.

### Added
- **`reset-counters` CLI subcommand** — `xdpmacfilter reset-counters --iface X [--rule-id N]` zeros the per-rule counter map(s) on the named iface. Without `--rule-id` → zero all 64 slots; with `--rule-id` → zero only slot N (range [0, 63]; out-of-range → exit 1 + stderr error). Requires the iface to be attached (`${PIN_DIR}/<iface>/rule_counters_a` pin must exist) → exit 1 + stderr `"no rule_counters pin"` substring if absent. Audit-log line emitted at action time mirroring `bypass.activated` shape verbatim (per HG-3.4d-6): `xdpmacfilter: RESET-COUNTERS on <iface> by uid=<N> euid=<M> sudo_user="<X or <none>>" rule_id=<N or "ALL">`.
- **`rule_counters` axis parallel ARRAY_OF_MAPS** — promoted from single PERCPU_ARRAY to parallel `rule_counters_outer` ARRAY_OF_MAPS[2] of `rule_counters_a` / `rule_counters_b` inner PERCPU_ARRAYs. Single `active_idx` u32 flip now atomically commits **all 5 axes** (MAC HASH inner + CIDR LPM_TRIE inner + defaults + rules inner + rule_counters inner). New pins under `${PIN_DIR}/<iface>/`: `rule_counters_outer`, `rule_counters_a`, `rule_counters_b`.
- **`bump_rule` helper signature extension** — `bump_rule(__u32 rule_id)` → `bump_rule(__u32 rule_id, __u32 active)`. Both call-sites in `mac_filter_prog` (MAC HASH-hit + CIDR LPM_TRIE-hit branches) pass the existing `active` snapshot. Body changes to `rule_counters_outer[active]` → `rule_counters_inner[rule_id]` → bump (5-axis active_idx-snapshot discipline per D-3.4d-7).
- **`copy_rule_counters_forward` apply-step helper** — NEW userspace per-rule-id per-CPU loop in `loader.cpp` anon namespace; called from `apply_request` BEFORE the active_idx flip (both reattach and fresh-attach branches). Copies per-CPU rule_counters values from old-active inner to inactive inner so the post-flip new-active inner carries the operator-observable counter state. PI-3.4b-2 PRESERVE-across-apply held.
- **2 new logger events** — `reset_counters.refused.no_pin` (HG-3.4d-3 iface-not-attached precondition fail) + `reset_counters.activated` (HG-3.4d-6 audit-log). `kEventNames` catalog 33 → 35.
- **3 new ctests** — `T_CLI_RESET_COUNTERS`, `T_CLI_RESET_COUNTERS_RULE_ID`, `T_CLI_RESET_COUNTERS_NO_IFACE` + 1 conditional `T_RULE_COUNTERS_ATOMIC_SWAP` (LOAD-BEARING canary for PI-3.4b-2 PRESERVE + D-3.4d-3 copy-forward). All take `RESOURCE_LOCK xdp_fixture`.

### Changed
- **`kManagedMaps[]` table grows 15 → 17 entries** — REMOVE `{rule_counters, RULE_COUNTERS_NAME}`; ADD `{rule_counters_a, RULE_COUNTERS_INNER_A_NAME}` + `{rule_counters_b, RULE_COUNTERS_INNER_B_NAME}` + `{rule_counters_outer, RULE_COUNTERS_OUTER_NAME}`. 4th consecutive HK-9 dividend collected.
- **Exporter `rule_counters_reader.cpp`** adapted to active_idx-indirection: reads `${PIN_DIR}/<iface>/active_idx` to pick which inner is live ({0,1} → suffix `_a`/`_b`), then opens that inner. Existing per-CPU read + per-rule-id loop UNCHANGED. PI-31-3.4d (exporter READ-ONLY) PRESERVED — exporter touches only `bpf_obj_get` + PERCPU lookup.
- **`T_CLI_HELP_VERSION` extends `--help` assertions** for new `reset-counters` subcommand line + `--rule-id` flag (per anti-misdiagnosis guard #13 fixture cross-reference).
- **`T_EXPORTER_METRICS_FORMAT` version-literal bump** `0.9.0 → 0.10.0` at the 4 literal sites (PI-8-3.4d carve-out + guard #11).
- VERSION 0.9.0 → 0.10.0 (MINOR — operator-observable: NEW CLI subcommand). Both binaries report `0.10.0` via `--version` per shared `version.h` (PI-8-3.4d).

### Removed
- **Single `rule_counters` PERCPU_ARRAY pin** — `${PIN_DIR}/<iface>/rule_counters` no longer exists; replaced by `rule_counters_outer` + `rule_counters_a` + `rule_counters_b` pins. The `XDPMF_MAP_RULE_COUNTERS_NAME` constant is removed from `src/common/mac_filter.h`.

### Notes
- **PI-3.4b-2 counter-monotonicity-across-apply EXPLICITLY PRESERVED**. The atomic-swap shape change is **structural-only** per HG-3.4d-5 (LOAD-BEARING). Counters survive `apply -f` exactly as in §5.31 PI-3.4b-2; the mechanism is the NEW apply-step copy-forward (D-3.4d-3). Reset zeroing is ONLY available via the new `reset-counters` CLI. The structural shape enables a hypothetical future "reset-on-apply" semantic (skip the copy step → flip alone resets the now-active view) — NEW FENCE.
- `reset-counters` zeros BOTH inner_a + inner_b at each chosen slot (D-3.4d-RESET-BOTH — semantically idempotent vs subsequent active_idx flips). Operator mental model: "reset is sticky regardless of apply-induced flip".
- Helper duplication over extraction (anti-misdiagnosis guard #9): `reset_counters.cpp` duplicates `escape_audit_value` + sudo_user-env-lookup pattern from `bypass.cpp` rather than extracting into a shared `audit_helpers.hpp`. Rule-of-three extraction is a separate concern (NEW FENCE — MVP-3.4e+).

### Preserved invariants
- **PI-7-3.4d-hpp**: `src/lib/loader.hpp` ZERO diff — **10th consecutive cycle** (strongest PI-7 streak in project history). `src/lib/config.hpp` ZERO diff — **5th consecutive cycle**. No public symbol added; reset-counters CLI is self-contained per D-3.4d-4 (direct `bpf_obj_get` + `bpf_map_update_elem` from `src/cli/reset_counters.cpp`).
- **PI-7-3.4d-cpp**: `src/lib/loader.cpp` SCOPED EDIT — diffs confined to kManagedMaps[] 15 → 17, NEW `copy_rule_counters_forward` anon-namespace helper, 2 call-site insertions in `apply_request` (reattach + fresh-attach).
- **PI-10-3.4d**: `src/common/mac_filter.h` ADDITIVE-modulo-deletion (3 added + 1 removed); all other constants/structs/enums byte-equivalent. `XDPMF_RULE_COUNTERS_MAX` alias UNCHANGED (operator-observable index space per §5.31 Q5 R1).
- **PI-3.4b-2 PRESERVE** (NEW LOAD-BEARING canary this slice): counters survive `apply -f`; mechanism is the apply-step copy-forward (D-3.4d-3). T_RULE_COUNTERS_ATOMIC_SWAP is the operator-grade verification surface.
- **PI-3.4d-1 (NEW)**: reset-counters CLI behavioral contract — exit 0 on attached iface + audit-log + zero-writes; exit 1 on parse error / out-of-range / iface-not-attached.
- **PI-3.4d-2 (NEW, structural)**: `rule_counters` axis in parallel-outer atomic-swap shape; `${PIN_DIR}/<iface>/rule_counters_outer` + `rule_counters_a` + `rule_counters_b` pinned.
- **PI-3.4d-EXPORTER (carve-out)**: exporter adapts to the new pin shape — opens active_idx, picks `rule_counters_<active>`. PI-31-3.4d (exporter READ-ONLY) PRESERVED.
- **PI-3.5-4 AMENDED**: `kEventNames` count 33 → 35 per HG-3.4d-3 + HG-3.4d-6 NEW events. T_LOG_EVENT_CATALOG_STABILITY reference updates 33 → 35.

### Out-of-scope fences (per §5.35)
- `reset-counters --all-ifaces` / batch across ifaces — NEW FENCE. Per-iface this slice.
- `reset-counters --dry-run` — NEW FENCE. Always commits.
- `reset-counters` without `--iface` (auto-discovery) — NEW FENCE. `--iface` required.
- `reset-counters --reason "<text>"` — NEW FENCE.
- `dump-counters` complementary read-side — NEW FENCE (operators already have `bpftool map dump` + Prometheus `/metrics`).
- Counter zero-on-detach — NEW FENCE (detach preserves pin per D-3.1-4).
- "Reset-on-apply" semantic flip — atomic-swap shape enables it (skip the copy-forward step), but no operator demand. NEW FENCE.
- `stats` PERCPU_ARRAY atomic-swap (6th axis) — global counters; not motivated. NEW FENCE.
- `action_table` parallel-promotion — unchanged from §5.34 carry-forward.
- Action types beyond `{PASS, DROP}` — carry-forward.
- Drop-precedence-over-pass / later-rule-wins — carry-forward.
- Rule-of-three helper extraction (`audit_helpers.hpp` for escape_audit_value + sudo_user lookup) — NEW FENCE; future cycle when 3rd subcommand needs it.

### Build pace
| Cycle | Slice | Anchor | Source delta |
|---|---|---|---|
| MVP-3.4d | reset-counters CLI + rule_counters atomic-swap promotion (structural) | §5.35 | ~9 EDITED + 2 NEW source files (mac_filter.bpf.c map block + bump_rule sig; mac_filter.h constants 3+/1−; loader.cpp kManagedMaps + copy_rule_counters_forward + 2 call-sites; logger.hpp catalog 33→35; cli.cpp + cli.hpp + main.cpp dispatch; reset_counters.{hpp,cpp} NEW; src/cli/CMakeLists.txt entry; rule_counters_reader.cpp exporter adapt; CMakeLists.txt version bump; CHANGELOG.md entry); tests: 3 NEW + 1 conditional NEW + 2 EDITED |

## [0.9.0] — 2026-05-27

MVP-3.4b cycle 2 — `rules` map atomic-swap promotion + datapath dispatch + schema cycle 2 → 3 shift (brownfield amendment §5.34). Closes the **datapath-consultation half** of the per-rule action machinery deferred from MVP-3.4 Open Q #13 Option 2 + MVP-3.4b cycle 1. The two coupled deliverables — (1) `rules` map promotion to parallel `rules_outer` ARRAY_OF_MAPS[2] of `rules_a` / `rules_b` inner ARRAYs; (2) `mac_filter_prog` consultation of the rules → action_table dispatch chain — ship together because carving them apart creates half-applied state. Operator-observable behavioural change: **drop rules are now operative explicitly** — a `match.mac: X` + `action: drop` rule drops X via the action_table dispatch path rather than via the indirect default-deny fallthrough.

### Added
- **`rules` axis parallel ARRAY_OF_MAPS** — promoted from SHARED ARRAY to parallel `rules_outer` ARRAY_OF_MAPS[2] of `rules_a` / `rules_b` inner ARRAYs. Single `active_idx` u32 flip now atomically commits **all 4 axes** (MAC HASH inner + CIDR LPM_TRIE inner + defaults + rules inner). Direct mirror of the §5.27 CIDR-axis pattern. New pins under `${PIN_DIR}/<iface>/`: `rules_outer`, `rules_a`, `rules_b`.
- **Explicit drop-rule action dispatch** — `mac_filter_prog` extends BOTH the MAC HASH-hit AND CIDR LPM_TRIE-hit branches with a 3-step chain: `rules_outer[active]` → `rules_inner[entry->rule_id]` → `action_table[rule.action_id]` → `XDP_PASS` or `XDP_DROP`. Per-rule counter `bump_rule()` runs BEFORE the dispatch chain — counter bumps on every match regardless of verdict (HG-3.4b-c2-5).
- **3 new ctests**: `T_DROP_RULE_OPERATIVE` (explicit drop-rule produces XDP_DROP via action_table; per-rule counter bumps; verdict observable in STAT_DROP_DENY), `T_RULES_ATOMIC_SWAP_NO_DROP` (load-bearing canary for PI-13-3.4b-c2 — atomic swap under concurrent traffic with inverted actions across configs), `T_RULES_AXIS_FLIPS_WITH_ACTIVE_IDX` (rules-axis content correlates with active_idx; one-deep rollback history preserved).

### Changed
- **Schema cycle 2 → cycle 3 SEMANTIC SHIFT** — drop rules now populate the inner-allowlist (MAC HASH for `match.mac`, CIDR LPM_TRIE for `match.src_cidr`) with their `rule_id`. The prior §5.26 schema cycle 2 contract — "drop rules do NOT populate the inner allowlist" — is EXPLICITLY AMENDED per HG-3.4b-c2-2. Operator mental model shift: every rule that matches a frame contributes per-rule counter; verdict is explicit via the rule's `action:` field; default-deny only catches frames matching NO rule. Sidecar `rule_index.json`'s `action: "drop"` label flow-through is byte-equivalent — only the data flowing through it changes (the label now correlates with non-zero per-rule counter values).
- **`mac_filter_prog` datapath body** — MAC HASH-hit + CIDR LPM_TRIE-hit branches grow with the 3-step rules→action_table dispatch chain + XDP_DROP verdict path; 3 new chained `bpf_map_lookup_elem` calls per match. All NULL-checked (verifier-required). Active snapshot discipline preserved — the SAME `active` u32 read at the head of the datapath indexes all 4 outers (MAC + CIDR + defaults + rules).
- **`populate_rules_skeleton` renamed to `populate_rules_inner_slot`** — function body byte-equivalent (clear-all-64 + write occupied); only fd-source semantic shifts (caller passes the inactive `rules_<a|b>` inner-fd, NOT a shared `rules` fd). Called BEFORE the active_idx flip per §5.34 D-3.4b-c2-8 atomic-swap discipline.
- **`extract_pass_macs` + `extract_pass_cidrs` action filter REMOVED** — the `if (r.action != RuleAction::Pass) continue;` line is gone (one line per axis, two total). Function names retained per D-3.4b-c2-3 to minimize diff (rename would inflate call-site touches with no semantic benefit). Drop rules NOW feed both axes alongside pass rules.
- **`kManagedMaps[]` table grows 13 → 15 entries** — REMOVE `{rules, RULES_NAME}`; ADD `{rules_a, RULES_INNER_A_NAME}` + `{rules_b, RULES_INNER_B_NAME}` + `{rules_outer, RULES_OUTER_NAME}`. Single-line table extension is the MVP-3.4.5 HK-9 landmine refactor dividend (3rd consecutive cycle collecting it).
- **`T_DROP_RULE_BUMPS_COUNTER` assertion semantic INVERTED** — drop-rule MAC NOW enters inner-allowlist; per-rule counter NOW bumps; verdict is XDP_DROP via action_table (was: MAC absent, counter stays 0, drop via defaults fallthrough). Test name kept — semantic now matches the literal name (it was somewhat ironic pre-§5.34). Explicit schema-shift carve-out per PI-6-3.4b-c2.
- **`T_RULES_SKELETON_NOT_WIRED` DELETED** — the contract this test asserted (rules+action_table NOT consulted by datapath) is RETIRED by this slice. Body deleted; foreach entry removed.
- VERSION 0.8.0 → 0.9.0 (MINOR — operator-observable behavioural change: drop rules now operative explicitly). Both binaries report `0.9.0` via `--version` per shared `version.h` (PI-8-3.4b-c2).

### Removed
- **SHARED `rules` ARRAY pin** — `${PIN_DIR}/<iface>/rules` no longer exists; replaced by `rules_outer` + `rules_a` + `rules_b` pins. The `XDPMF_MAP_RULES_NAME` constant is removed from `src/common/mac_filter.h`.
- **§5.29 stderr WARN** — `xdpmacfilter: rules: section parsed (<N> entries) but per-rule action dispatch deferred to MVP-3.4b — datapath uses MAC/CIDR-only matching this cycle` is GONE. The contract it announced no longer applies — datapath consults the chain per HG-3.4b-c2-4.
- **`loader.warn.rules_skeleton_not_wired` event** — REMOVED from `kEventNames` catalog in lockstep with the WARN emission removal. Catalog count 34 → 33. PI-3.5-4 amended per D-3.4b-c2-4. T_LOG_EVENT_CATALOG_STABILITY reference value updates 34 → 33.

### Notes
- `reset-counters` subcommand + `rule_counter` atomic-swap explicitly scoped-out of this slice → follow-up cycle (working name MVP-3.4d — architect's call when the brief lands).
- `action_table` map STAYS SHARED per HG-3.4b-c2-3 (D-3.4b-c2-6) — values are static `{PASS=0, DROP=1}`, never mutate at runtime; atomic-swap is meaningless. Promotion to parallel ARRAY_OF_MAPS becomes motivated when MVP-3.8+ adds mutable action types (MIRROR / RL / TAG with per-config parameters). NEW FENCE.
- First-rule-wins dedup semantic preserved per D-3.4b-c2-7: if operator declares `id=5 action=pass match.mac=X` AND `id=17 action=drop match.mac=X` (same MAC, two rule entries), the inner-allowlist gets `{mac=X, rule_id=5}` (first encountered); the drop-rule is shadowed. Consistent with §5.26 dedup precedent. Operators wanting alternative semantics (later-rule-wins / drop-precedence) → MVP-3.4e future cycle. NEW FENCE.

### Preserved invariants
- **PI-7-3.4b-c2-hpp**: `src/lib/loader.hpp` ZERO diff — **9th consecutive cycle**. `src/lib/config.hpp` ZERO diff — **4th consecutive cycle**. No public symbol added; `Config::Rule::action` field already exists.
- **PI-7-3.4b-c2-cpp**: `src/lib/loader.cpp` SCOPED EDIT — diffs confined to kManagedMaps[] 13→15, `populate_rules_inner_slot` rename + signature semantic shift, `apply_request` call-site updates (2 sites) + WARN-emission removal, `extract_pass_macs` / `extract_pass_cidrs` filter-line removal.
- **PI-10-3.4b-c2**: `src/common/mac_filter.h` ADDITIVE-modulo-deletion (3 added + 1 removed); all other constants/structs/enums byte-equivalent. STAT_MAX = 4 unchanged (Q1.B re-uses STAT_DROP_DENY for explicit-rule-drops, no new enum slot).
- **PI-13-3.4b-c2 (NEW, load-bearing)**: rules atomic-swap via active_idx flip, symmetric with §5.27 Q1 AS1 CIDR pattern; single u32 commits 4-axis swap.
- **PI-29-3.4b-c2 (NEW, load-bearing — SUPERSEDES PI-28-3.4b + PI-29-3.4b)**: datapath consults `rules_outer → rules_inner → action_table` chain per match in both MAC HASH-hit AND CIDR LPM_TRIE-hit branches.
- **PI-30-3.4b-c2-schema (NEW, load-bearing)**: drop rules NOW populate inner-allowlist (their `rule_id` AND their `match.*` clause). The prior §5.26 schema cycle 2 contract is explicitly amended; reviewer's disposition rule for "drop-rule semantic change" flag is `inline-merge` (NOT `[CONTRACT-DRIFT]`).
- **PI-3.5-4 AMENDED**: `kEventNames` count 34 → 33 per D-3.4b-c2-4. The change is direct consequence of the §5.29 WARN-emission removal; explicit-by-design per `inline-merge` reviewer disposition.
- **PI-6-3.4b-c2 / PI-3.4b-c2-fixture-ripple**: 2 ctest body EDITs (T_DROP_RULE_BUMPS_COUNTER semantic-shift rewrite per Q3.A; T_EXPORTER_METRICS_FORMAT version-literal bump 0.8.0 → 0.9.0) + 1 DELETED ctest (T_RULES_SKELETON_NOT_WIRED) + 3 NEW ctests. All other 55 ctest bodies byte-equivalent.
- **PI-28-3.4b LIFTED** + **PI-29-3.4b LIFTED** — replaced by PI-29-3.4b-c2 above (`mac_filter_prog` body extends with the dispatch chain; rules + action_table NOW consulted — the entire purpose of this slice).

### Out-of-scope fences (per §5.34)
- `reset-counters` subcommand + `rule_counter` atomic-swap — follow-up cycle MVP-3.4d (working name). NEW FENCE.
- `action_table` promotion to parallel ARRAY_OF_MAPS — not motivated by cycle 2 (values static); motivated if MVP-3.8+ adds mutable action types. NEW FENCE.
- Action types beyond `{PASS, DROP}` — MVP-3.8+ carry-forward.
- `xdpfilter_packets_total{verdict="rule_drop"}` separate verdict bucket (Q1.A alternative) — Q1.B re-use picked; future-cycle if operator demand surfaces. NEW FENCE.
- Drop-precedence-over-pass / later-rule-wins dedup — first-rule-wins preserved per D-3.4b-c2-7. NEW FENCE.
- `defaults` map retirement (Q4.B alternative) — Q4.A unchanged; defaults stays for unmatched-frame fallback.
- Documentation pass for the schema cycle 3 shift (FLEET_DEPLOYMENT.md migration notes; Prometheus alert wording update) — separate manual doc pass per user direction.

### Build pace
| Cycle | Slice | Anchor | Source delta |
|---|---|---|---|
| MVP-3.4b cycle 2 | rules atomic-swap promotion + datapath dispatch + schema cycle 3 shift | §5.34 | ~7 EDITED source files (mac_filter.bpf.c map block + datapath dispatch; mac_filter.h constant set; loader.cpp kManagedMaps + populate_rules_inner_slot + extract_* filter removal + WARN removal + 2 call-sites; logger.hpp catalog 34→33; CMakeLists.txt version bump; CHANGELOG.md entry; tests/CMakeLists.txt foreach trim); tests: 2 EDITED + 1 DELETED + 3 NEW |

## [0.8.0] — 2026-05-25

MVP-3.5 — JSON structured logs in loader + exporter (brownfield amendment §5.32). Operator-facing structured-logging surface deferred from §5.30 §7 OOS for 5 consecutive cycles. New env var `XDPMF_LOG_FORMAT={text,json}` (default `text`) selects rendering for every diagnostic stderr emission in BOTH `xdpmacfilter` + `xdpmf-exporter`. Text mode is byte-equivalent to the pre-§5.32 line (load-bearing **PI-3.5-1** — the 52-ctest baseline is the validation surface). JSON mode emits one NDJSON object per event with a flat envelope `{ts, level, event, iface, msg, fields:{}}` and a stable 34-event catalog (33 emission-site-derived + 1 logger self-emit). Strictly additive — only a 1-EDIT carve-out on the 52 pre-§5.32 ctests (T_EXPORTER_METRICS_FORMAT version-literal bump per §5.32 EDIT-2), NO touch to BPF datapath, NO new external build dependency.

### Added
- **Structured-logging module** — new `src/common/logger.{cpp,hpp}` (~300 LOC, stdlib-only per **PI-3.5-7**) ownership: format selector + envelope renderer + 34-event constexpr catalog (33 emission-site-derived + 1 logger self-emit per §5.32 EDIT-1). Compiled into BOTH `xdpmf_internal` static lib AND `xdpmf-exporter` binary target (Q6=B1 dup-TU; no new CMake target).
- **`XDPMF_LOG_FORMAT` env var** — read ONCE on first `logger::emit()` call (lazy init under `std::once_flag`; Q4=R1); cached for process lifetime. Values: unset/empty/`text` → `Format::Text` (default); `json` → `Format::Json`; any other value → one-shot WARN (`logger.warn.unknown_log_format`) + Text fallback (per PI-3.5-3 edge cases).
- **JSON envelope** — per HG-3.5-2: `{"ts":"<iso8601-utc-sec>","level":"<info|warn|error>","event":"<dotted.name>","iface":<"str"|null>,"msg":"<json-escaped>","fields":{...}}` followed by `\n`. ISO-8601 UTC second-precision timestamp (Q2=T1, sidecar.cpp:57 helper duplicated per D-3.5-2). Fixed field order (D-3.5-9). `fields` allows flat scalars only (string / int64 / bool / null, Q5=F1).
- **34-event catalog** — `kEventNames` constexpr `std::array` in `logger.hpp` locks the operator-visible event surface (33 emission-site events + 1 logger self-emit `logger.warn.unknown_log_format` per §5.32 EDIT-1). Dot-delimited lowercase snake_case identifiers (Q3=E1): `loader.trust_model`, `bypass.activated`, `exporter.listening`, `exporter.warn.bpffs_root_missing`, etc.
- **6 new ctests** (T_LOG_TEXT_BYTE_EQUIVALENT [load-bearing canary for PI-3.5-1], T_LOG_JSON_LOADER_EVENTS, T_LOG_JSON_EXPORTER_EVENTS, T_LOG_JSON_BYPASS_AUDIT, T_LOG_JSON_ENVELOPE_INVARIANTS, T_LOG_EVENT_CATALOG_STABILITY) + 2 new fixtures (`log_text_reference.txt`, `log_events_v1.txt`).

### Changed
- **40 stderr emission sites converted** to `logger::emit(...)` across 8 source files: `src/cli/main.cpp` (6 sites), `src/cli/bypass.cpp` (4 converted + 1 EXEMPT), `src/lib/loader.cpp` (4 sites), `src/lib/sidecar.cpp` (6 sites), `src/exporter/main.cpp` (7 sites), `src/exporter/http.cpp` (8 sites), `src/exporter/stats_reader.cpp` (3 sites), `src/exporter/rule_counters_reader.cpp` (2 sites). **Text-mode byte-equivalence** preserved at every site (PI-3.5-1).
- **HK-4 bypass audit-log structurally exposed** under JSON — `bypass.activated` event surfaces `fields.uid`, `fields.euid`, `fields.sudo_user`, `fields.reason` for log-shipper query (`jq 'select(.event=="bypass.activated" and .fields.sudo_user=="alice")'`); text-mode line byte-equivalent to MVP-3.4.5 HK-4 (PI-3.5-5).
- VERSION 0.7.0 → 0.8.0 (MINOR — new operator-facing env var + structured-logging surface). Both binaries report `0.8.0` via `--version` per shared `version.h` (PI-8-3.5).

### Internal
- **`json_escape` + `format_timestamp_utc` duplicated** in `src/common/logger.cpp` anon namespace from `src/lib/sidecar.cpp:38-158` per **D-3.5-2** (NOT extracted to `src/common/json.{cpp,hpp}` — keeps the slice scope-contained; the §5.31 sidecar.cpp regional-diff fence is unaffected by helper-side touches). Future cycle MAY extract if a 3rd JSON emitter surfaces.
- **`src/cli/bypass.cpp:96` interactive prompt EXEMPT** from logger conversion per **D-3.5-7 / PI-3.5-6** — UI primitive (no trailing `\n`, fflushed, awaits stdin). Converting it would render `}\n` BEFORE the `[y/N]: ` ending in JSON mode, breaking the prompt UX. JSON-mode operators using bypass interactively see one non-JSON line (the prompt); documented wart. Non-interactive `bypass --unsafe` users (the audit-typical path) see pure JSON.

### Preserved invariants
- **PI-3.5-1 (NEW, load-bearing)**: every emission in text mode is byte-identical to its pre-§5.32 prose. T_LOG_TEXT_BYTE_EQUIVALENT is the focused canary; the 13 pre-§5.32 ctests grep'ing stderr text pass byte-equivalent without modification — **PI-6-3.5 1-EDIT carve-out per §5.32 EDIT-2** (only T_EXPORTER_METRICS_FORMAT.sh's 4-LOC version-literal bump 0.7.0 → 0.8.0; the 13 stderr-grep ctests under PI-3.5-1 pass byte-equivalent without modification).
- **PI-3.5-2 / PI-3.5-3 / PI-3.5-4 / PI-3.5-5 / PI-3.5-6 / PI-3.5-7** (NEW): JSON envelope stability + env-var contract + event-catalog stability + HK-4 fields surfacing + interactive-prompt exemption + no-external-dep all locked.
- **PI-7-3.5-hpp**: `src/lib/loader.hpp` ZERO diff — **7th consecutive cycle**. `src/lib/config.hpp` ZERO diff — **2nd consecutive cycle**. Logger module owns its own header (`src/common/logger.hpp`); no public LoaderError addition; no new public symbol in loader.hpp.
- **PI-10**: `src/common/mac_filter.h` UNCHANGED (stricter than its previous ADDITIVE-ONLY baseline — this slice doesn't add to mac_filter.h at all).
- **PI-28-3.4b**: `mac_filter.bpf.c` UNCHANGED — JSON logging is userspace-only (D-3.5-10 NEW FENCE).
- **PI-29-3.4b / PI-31-3.4b / PI-32-3.4b**: exporter read-only + datapath consultation discipline unchanged.

### Out-of-scope fences (per §5.32)
- `XDPMF_LOG_DEST={file,syslog,journald}` + log rotation — MVP-3.5b candidate. NEW FENCE.
- `XDPMF_LOG_LEVEL={info,warn,error}` level filtering — MVP-3.5b candidate. NEW FENCE.
- Live SIGHUP env-var re-read (Q4 R3 rejected) / per-emit getenv (Q4 R2 rejected). NEW FENCES.
- `schema_version` field in JSON envelope — cycle 1 implicit version=1; added when a breaking change ships. NEW FENCE.
- `bpf_printk` JSON-ification (kernel-side) — userspace-only this slice. NEW FENCE.
- Nested objects / arrays in `fields:{}` — flat scalars only. NEW FENCE.
- `nlohmann/json` or any JSON library build dep — explicitly REJECTED (D-3.4b-10 zero-deps precedent extended).
- Color/ANSI escape codes in text mode — none; plain bytes byte-equivalent. NEW FENCE.

### Build pace
| Cycle | Slice | Anchor | Source delta |
|---|---|---|---|
| MVP-3.5 | JSON structured logs | §5.32 | ~300 LOC NEW (logger.{cpp,hpp}); ~40 emission-site EDITs across 8 files; tests: 6 NEW + 2 NEW fixtures; ZERO ctest-body modifications |

## [0.7.0] — 2026-05-25

MVP-3.4b cycle 1 — per-rule observability (brownfield amendment §5.31). First operator-facing feature since MVP-3.4: `xdpfilter_rule_match_total{iface, rule_id, action}` Prometheus series exposing per-rule packet match counts. Lifts the §5.29 PI-13-3.1 inner-allowlist-value defer fence (adjudicated PASS as additive per HG-3.4b-1) and the PI-29 datapath-non-consultation fence (RELAXED with documented carve-out — inner-VALUE's `rule_id` IS read by datapath; `rules` + `action_table` maps STILL NOT consulted). First substantive `mac_filter_prog` body edit since MVP-3.2 (verifier-pass critical).

### Added
- **Per-rule packet counters** — new `rule_counters` PERCPU_ARRAY[64] of `__u64` BPF map, pinned per-iface at `${PIN_DIR}/<iface>/rule_counters`. Bumped by `bump_rule(rule_id)` on every MAC HASH-hit and CIDR LPM_TRIE-hit in the datapath (Q1=B3 unified per-match semantic).
- **`rule_index.json` sidecar** — loader-written under `/run/xdpmacfilter/<iface>/rule_index.json` (Q3 P4 per §5.31 EDIT-1 Phase B platform-constraint correction; the initial Q3 P1 path `${PIN_DIR}/...` under bpffs was retracted because bpffs rejects regular-file creation) describing the LIVE config per apply, schema_version=1, defaults-only shape (Q2 S1). Loader mkdir-p's the per-iface dir under /run; atomic write idiom (write-to-.tmp → fsync → rename); writer is roll-your-own JSON (~150 LOC, NO new build dep per D-3.4b-10). Failure is non-fatal (D-3.4b-17 — exporter degrades to `action="unknown"` labels). Lifecycle: tmpfs (cleared on reboot; survives loader restart — symmetric to bpffs-pinned map lifecycle on unmount).
- **Exporter rule-label join** — new `xdpfilter_rule_match_total{iface, rule_id, action}` Prometheus series, joining BPF `rule_counters` with sidecar `rule_index.json` action labels. New translation units `src/exporter/rule_counters_reader.{cpp,hpp}` (PERCPU sum) + `src/exporter/sidecar_reader.{cpp,hpp}` (line-oriented regex extraction per D-3.4b-14). Sidecar-orphan tolerance: non-zero counter slot for rule_id absent from sidecar emits `action="unknown"` (PI-32-3.4b).
- 6 new ctests (`T_RULE_COUNTER_MAC_HIT_BUMPS`, `T_RULE_COUNTER_CIDR_HIT_BUMPS`, `T_RULE_COUNTER_SURVIVES_APPLY`, `T_SIDECAR_JSON_SHAPE`, `T_EXPORTER_RULE_LABELS`, `T_DROP_RULE_BUMPS_COUNTER`) + 1 new fixture (`config_per_rule_counters.yaml`) + 1 new helper (`tests/lib/read_rule_counters.py`).

### Changed
- **Inner-allowlist-value byte shape** — `xdpmf_allowlist_inner` (MAC HASH) and `xdpmf_cidr_inner` (CIDR LPM_TRIE) inner-VALUE extends from `__u8` (1 byte) to `struct allow_entry { unsigned char present; unsigned char _pad[3]; unsigned int rule_id; }` (8 bytes). **PI-13-3.4b adjudicated PASS-as-additive** (HG-3.4b-1, D-3.4b-1): offset-0 `present` byte stays byte-equivalent to PI-27 (`bpftool map dump ... format c | head -c 1` still returns `0x01` for occupied slots); `value_size 1 → 8` is documented + intended. Symmetric across MAC HASH + CIDR LPM_TRIE per T.5 OQ #3.
- `kManagedMaps[]` table grows 12 → 13 entries (adds `rule_counters`). Single-line table extension — MVP-3.4.5 HK-9 landmine refactor dividend.

### Internal
- `populate_inner_slot` + `populate_cidr_inner_slot` signatures carry rule_id alongside the key (new anon-namespace `MacRule` / `CidrRule` structs per D-3.4b-15 Option A); body writes a full `struct allow_entry` per insert with `rule_id` sourced from operator's YAML `id:` (Q5 R1 + D-3.4b-9).
- `apply_request` invokes `sidecar::write_rule_index` POST active_idx-flip (D-3.4b-16) so the sidecar describes the LIVE config.
- BPF datapath gains `bump_rule(__u32 rule_id)` inline helper adjacent to `bump_stat` (verifier-required bounds check folded inline).

### Preserved invariants
- **PI-7-3.4b-hpp**: `loader.hpp` ZERO diff — **6th consecutive cycle**. `config.hpp` also ZERO diff (D-3.4b-11 Phase A correction: `Rule::id` already serves Q5 R1).
- **PI-7-3.4b-cpp**: `loader.cpp` SCOPED EDIT — diffs confined to kManagedMaps[] table 12→13, populate_inner_slot + populate_cidr_inner_slot signatures + bodies, apply_request rule-extraction + sidecar-write steps, new anon-namespace MacRule/CidrRule structs.
- **PI-10-3.4b**: `src/common/mac_filter.h` ADDITIVE-ONLY (new `struct allow_entry`, `XDPMF_MAP_RULE_COUNTERS_NAME`, `XDPMF_RULE_COUNTERS_MAX`, `XDPMF_SIDECAR_ROOT` per §5.31 EDIT-1; existing constants + struct layouts UNCHANGED).
- **PI-13-3.4b**: NEW — inner-allowlist-value byte layout documented byte-by-byte; offset-0 byte-equivalence to PI-27 preserved.
- **PI-28-3.4b**: `mac_filter_prog` body extends with `bump_rule` calls + typed-pointer inner-value reads at MAC HASH-hit and CIDR LPM_TRIE-hit branches. All other body lines byte-equivalent. First substantive body change since MVP-3.2.
- **PI-29-3.4b**: `rules` + `action_table` maps STILL NOT consulted by datapath; inner-VALUE's `rule_id` IS read.
- **PI-31-3.4b**: exporter still READ-ONLY (new `rule_counters_reader.cpp` + `sidecar_reader.cpp` covered).
- **PI-32-3.4b**: STRENGTHENED — exporter handles missing rule_index.json gracefully (degrades to `action="unknown"` labels, NOT crash).
- **PI-6-3.4b / PI-34-3.4b**: 46 pre-§5.31 ctests pass byte-equivalent with 2-ctest-body EDIT carve-out (T_RULES_SKELETON_NOT_WIRED comment-rewrite + T_EXPORTER_METRICS_FORMAT version-literal bump per PI-3.4b-9 catalog).

### Out-of-scope fences (per §5.31)
- `action_table` datapath consultation (action-dispatch) — MVP-3.4c future cycle.
- `rules` map atomic-swap promotion (D-3.4-4 close-out) — MVP-3.4b cycle 2 if cycle 3 makes it load-bearing.
- Sidecar schema S2 (free-form description) / S3 (deployment metadata) — future-cycle if operator demand surfaces.
- `nlohmann/json` as build dep — explicitly REJECTED for cycle 1 (roll-your-own writer + line-regex reader).
- Counter zero / reset API — MVP-3.4b cycle 2 candidate.
- Cap-lift beyond 64 rules — permanent product contract.

### Build pace
| Cycle | Slice | Anchor | Source delta |
|---|---|---|---|
| MVP-3.4b | Per-rule counters cycle 1 | §5.31 | ~400 LOC across 8 EDITED + 4 NEW source files; tests: 2 EDITs + 6 NEW + 1 fixture + 1 helper |

## [0.6.1] — 2026-05-25

MVP-3.4.5 — housekeeping (defer-posture audit + landmine removal) (brownfield amendment §5.30). Pure non-functional cleanup of the backlog accumulated through MVP-3.1..3.4 plus the `/mint-review` audit findings. 17 housekeeping items in three themes: contract-drift fixes (HK-1..HK-8), landmine removal (HK-9..HK-10), and OOT-deferred backlog (HK-11..HK-17). **No new operator-facing feature, no new BPF map, no datapath behaviour change, no new public API, no schema change, no new exit code.** Smallest LOC delta of MVP-3.x to date.

### Fixed
- HK-1: `xdpmacfilter apply -f <missing> --iface <X>` now exits **1** (CLI usage error per §4.1) instead of leaking out of the `std::visit` body and tripping the generic `LoadFailed` (exit 2) arm. `main.cpp` SECOND try block gains a `catch (CliError)` arm that mirrors the FIRST try (parser) arm. Existing `xdpmacfilter: config error:` stderr prefix preserved verbatim; YAML parse / schema-validation failures of a file that DOES exist continue to exit 9 (D-3.4.5-5 rationale: file-IO is upstream of YAML and belongs in usage-error space).
- HK-4: `bypass --reason "<text>"` audit-log line is now log-injection-safe. `truncate_reason()` post-truncation now escapes `\` `"` `\n` `\r` `\0` per Prometheus label-value discipline; UTF-8 rewind-safety on mid-codepoint truncation; budget tightened to 253 bytes + 3-byte ellipsis (256 total). Audit-log line now also includes the operator's effective identity: `uid=<UID> euid=<EUID> sudo_user="<SUDO_USER or <none>>"` as structural fields BEFORE the existing `reason="..."`. Order is fixed for grep stability (D-3.4.5-8).
- HK-10: `T_LINK_PERSIST_ACROSS_LOADER_EXIT` no longer issues a broad `pkill -9 -f xdpmacfilter` that could collateral-kill concurrent loaders during parallel ctest runs; the kill is now iface-scoped.
- HK-11: `T_SYSTEMD_RESTART_ON_FAILURE` flake mitigated via internal 2-attempt retry within the test body. The strict band [4,5] StartLimit-placement-footgun guard remains the load-bearing assertion.
- HK-12: `T_APPLY_ATOMIC_SWAP_NO_DROP` NOTE comment corrected — stats counters PRESERVED across apply per §5.26 D-3.1-4's `bpf_map__reuse_fd` loop (the prior NOTE incorrectly claimed stats reset).
- HK-13: `T_ATTACH_TAG_MISMATCH` cleanup trap now explicitly unpins orphan map dentries left at bpffs root by the fixture's `bpftool prog load` (which runs without `pinmaps`).
- HK-16: `xdpmf-exporter` now emits the PI-32 startup WARN line when the configured `--bpffs-root` does not exist: `xdpmf-exporter: WARN bpffs root <path> does not exist; will serve empty metrics`. One-shot at startup; the daemon continues serving empty metrics per PI-32 (W1 mechanism, D-3.4.5-1).
- HK-17: `xdpmf-exporter` exit-code 6 now fires on the all-iface-EACCES condition: `total_discovered > 0 && eacces_failures == total_discovered && successes == 0`. Per-iface partial-EACCES continues to WARN-and-continue (PI-31). Empty bpffs root remains a normal state (exit 0 + the HK-16 startup WARN). E1 trigger semantics + per-scrape check; D-3.4.5-2 rationale.

### Changed
- HK-2: `xdpmacfilter --help` exit-code list now includes `7 kernel-unsupported,` between `6 permission,` and `8 path-refused,` (PI-9 forward-compatibility preserved; T_CLI_HELP_VERSION ERE still matches).
- HK-3: `XDPMF_BPF_OBJECT_PATH` env-var override is now compile-gated behind `XDPMF_ENABLE_BPF_OBJECT_OVERRIDE` CMake option (default OFF). Release builds (`-DBUILD_TESTING=OFF`) have the env-var code path `#ifdef`'d out of the binary — `nm $(which xdpmacfilter) | grep -c XDPMF_BPF_OBJECT_PATH` returns 0. In-tree dev/test builds force the option ON via `tests/CMakeLists.txt`, so `T_VERIFIER_REJECT.sh` continues to pass.
- HK-5: `mac_filter.bpf.c` adds `__builtin_expect(!!(x), 0)` (`unlikely(x)`) hints on the six verifier-mandated leaf null-checks/bounds-checks. Functional verdicts byte-equivalent (PI-28).
- HK-6: `xdpmacfilter --help` `--unsafe` line clarified — `--unsafe` is required in non-interactive context AND suppresses the interactive y/N prompt when passed at a tty. New `Environment variables:` sub-block documents `XDPMF_TRUST_MODEL`. `xdpmf-exporter --help` gains an `Environment variables:` block documenting `XDPMF_BPFFS_ROOT` plus a cross-reference note that `XDPMF_TRUST_MODEL` is loader-only.
- HK-9: 3-callsite `LIBBPF_PIN_BY_NAME` lockstep landmine in `src/lib/loader.cpp` consolidated into one anon-namespace `kManagedMaps[]` constexpr table; the three callsites (`open_skeleton_only`'s clear-list, `apply_request`'s `pin_specs[]` per-iface pinning, and `apply_request`'s `reuse_specs[]` state-b reattach) all walk the same table with a `legacy_alias` filter for the legacy `allowlist` symbol. Member-pointer representation (T1) — compile-time-checked against the libbpf-skel struct (rename = build break, not runtime cryptic error). 42-ctest baseline is the byte-equivalence validation (D-3.4.5-7).
- HK-15: `mint/design.md` §5.26 ParsedAttach/ParsedDetach/ParsedApply wrapper-struct prose retracted with an inline `[CORRECTION §5.30 HK-15 …]` marker. Reality is the CLI uses `ParsedCommand = std::variant<AttachConfig, DetachConfig, ApplyConfig, BypassConfig>` directly — no wrapper layer ever shipped.

### Added
- HK-7: `docs/FLEET_DEPLOYMENT.md` is now installed under `${CMAKE_INSTALL_PREFIX}/share/doc/xdpmacfilter/` alongside the systemd units, gated on the same `XDPMF_INSTALL_SYSTEMD_UNIT` option. The two units' `Documentation=file:///usr/share/doc/xdpmacfilter/FLEET_DEPLOYMENT.md` URI now resolves on the operator's host post-install.
- 4 new ctests (`T_APPLY_EXITS_1_ON_MISSING_CONFIG`, `T_BYPASS_INTERACTIVE_PROMPT`, `T_BYPASS_REASON_TRUNCATE`, `T_EXPORTER_EXITS_6_ALL_IFACES_EACCES`) — written by tester in parallel against `design.md` §5.30 TestStrategy.

### Internal / docs only
- HK-14: §6.25 step 8 `replacing existing program` stderr stays UNASSERTED — design explicitly marks it as impl-shape flexibility (D-3.4.5-4).

### Preserved invariants
- PI-7-3.4.5-hpp: `loader.hpp` ZERO diff — **5th consecutive cycle**.
- PI-7-3.4.5-cpp: `loader.cpp` SCOPED EDIT only — HK-3 `#ifdef` blocks + HK-9 `kManagedMaps[]` refactor on the three call-sites; ZERO diff elsewhere.
- PI-8-3.4.5: Both binaries report `0.6.1`.
- PI-13-3.4.5 / PI-27: inner-allowlist-value shape **UNTOUCHED** (the load-bearing defer PI).
- PI-28: `mac_filter_prog` semantic byte-equivalent; HK-5 only adds compiler branch hints.
- PI-31: exporter still READ-ONLY; HK-16 + HK-17 are read-side only.
- PI-32 strengthens: WARN substring now asserted at startup.
- PI-34 / PI-6-3.4.5 (relaxed with explicit carve-out): 42 pre-§5.30 ctests pass byte-equivalent with 5 EDITED bodies + 4 NEW files.

### Out-of-scope fences (per §5.30)
- No new operator-facing feature, no new BPF map, no new public API, no new exit code.
- 13-item documentation bucket (README rewrite, FLEET_DEPLOYMENT.md sections, CONFIG_SCHEMA.md, HANDOFF.md move, Ansible Jinja fixes) — separate manual pass per user direction.
- Per-rule counters / inner-allowlist-value extension — still MVP-3.4b (defer posture preserved).

### Build pace
| Cycle | Slice | Anchor | Source delta |
|---|---|---|---|
| MVP-3.4.5 | Housekeeping | §5.30 | ~150 LOC across 8 source files; no new source files; tests: 5 EDITs + 4 NEW |

## [0.6.0] — 2026-05-24

MVP-3.4 — observability exporter + manual bypass primitive + `rules`/`action_table` BPF skeleton (brownfield amendment §5.29; defer posture per Open Q #13 RESOLUTION). First NEW binary since MVP-2 (`xdpmf-exporter`). Per-rule counters DEFERRED to MVP-3.4b; inner-allowlist-value shape preserved byte-equivalent (PI-13-3.4 / PI-27 — the load-bearing defer PI). Datapath byte-equivalent to MVP-3.2 modulo two new `.maps` declarations (PI-28).

### Added
- `xdpmf-exporter` binary (§5.29 HG-3.4-3, Q1 D1) — long-running Prometheus `/metrics` daemon, embedded minimal C++23 HTTP/1.0 server (~250 LOC plain sockets, NO third-party HTTP dep per D-3.4-3). Reads existing global `stats` `BPF_MAP_TYPE_PERCPU_ARRAY[STAT_MAX=4]` via libbpf RO fds (PI-31). Routes: `GET /metrics` (text/plain; version=0.0.4 — `xdpfilter_packets_total{iface,verdict}` counter family with `verdict ∈ {pass, drop_deny, drop_malformed, pass_cidr}`), `GET /healthz` (200 OK). Defaults: `--port 9417 --bind 127.0.0.1 --bpffs-root ${XDPMF_BPFFS_ROOT}`. Links `xdpmf_internal` STATIC (D-3.4-2). Installed at `${CMAKE_INSTALL_BINDIR}/xdpmf-exporter`.
- `systemd/xdpmf-exporter.service` (§5.29 Q5 N3) — single-instance unit (NOT @-templated). `Type=simple` long-running, `Restart=on-failure RestartSec=5`, rate-limited via `StartLimitBurst=5 StartLimitIntervalSec=300`. Capability set INTENTIONALLY MINIMAL: `AmbientCapabilities=CAP_BPF` ONLY (D-3.4-6; explicit anti-misdiagnosis rationale — no `CAP_SYS_ADMIN`/`CAP_NET_ADMIN`/`CAP_SYS_RESOURCE`/`CAP_PERFMON` because the exporter does not load programs, attach/detach, set rlimits, or use perfcount).
- `xdpmacfilter bypass --iface <X> [--unsafe] [--reason "<text>"]` subcommand (§5.29 HG-3.4-2) — operator-facing manual bypass primitive wrapping the existing `loader::detach()` codepath. Interactive tty prompts `y/N`; non-tty REQUIRES `--unsafe` (audit safety gate; exit 1 + recognisable stderr message on absence). ALWAYS emits an audit-log line to stderr BEFORE the detach (D-3.4-5): `xdpmacfilter: BYPASS activated on <iface> by uid=<UID> reason="<text or UNSPECIFIED>"`. NO new BPF map flag, NO new datapath state (PI-30); the cleanest path that preserves the defer-posture invariants.
- `rules` BPF map (ARRAY[XDPMF_ALLOWLIST_MAX=64] of `struct rule_entry`) + `action_table` BPF map (ARRAY[ACTION_MAX=2] of `struct action_entry`) — DECLARED-AND-POPULATED-NOT-WIRED skeleton per HG-3.4-1. `mac_filter.bpf.c` datapath body is BYTE-EQUIVALENT to MVP-3.2 modulo the two new `.maps` declarations (PI-28). Populated from `Config.rules` on every `apply` (clear-and-rewrite per D-3.4-8; SHARED — not parallel-swapped — per D-3.4-4 because the datapath does not consult them). Forward-compatibility scaffold for MVP-3.4b wiring once PI-13-3.1 adjudication on the inner-allowlist-value extension lands.
- `apply` orchestrator emits a one-shot stderr WARN when `Config.rules` is non-empty: `xdpmacfilter: rules: section parsed (<N> entries) but per-rule action dispatch deferred to MVP-3.4b — datapath uses MAC/CIDR-only matching this cycle`. Operator-facing signature of PI-29.
- `src/common/mac_filter.h` additive types: `struct rule_entry`, `struct action_entry`, `enum xdpmf_action_type` (`ACTION_PASS=0`, `ACTION_DROP=1`, `ACTION_MAX=2`), `XDPMF_MAP_RULES_NAME`, `XDPMF_MAP_ACTION_TABLE_NAME` (PI-10-3.4 strengthened: pure additive diff; existing constants/structs/enum values UNCHANGED).
- 6 new ctests (§6.37..§6.42 — written by tester in parallel against `design.md` §5.29 TestStrategy): `T_EXPORTER_METRICS_FORMAT`, `T_EXPORTER_VALUES_MATCH_STATS`, `T_EXPORTER_NO_ATTACHED_IFACE`, `T_BYPASS_CMD_DETACHES`, `T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE`, `T_RULES_SKELETON_NOT_WIRED`.

### Changed
- CMake `project(VERSION)` bumped from `0.5.0` → `0.6.0` (semver minor: new observability binary + new CLI subcommand + new BPF maps; backward-compatible CLI grammar + backward-compatible YAML schema).
- `--help` lists the new `bypass` subcommand + the new `--unsafe` / `--reason` flags (PI-9: help-text format preserved; only an additive line block).
- `CMake install()` rule: both `xdpmacfilter` and `xdpmf-exporter` now install to `${CMAKE_INSTALL_BINDIR}` (single `install(TARGETS …)` line). The `XDPMF_INSTALL_SYSTEMD_UNIT` rule now also installs `systemd/xdpmf-exporter.service` alongside the existing template unit.

### Preserved invariants (verified by impl smoke)
- PI-7-3.4: `loader.hpp` ZERO diff — **FOURTH consecutive cycle** (MVP-3.1 added one enumerator; MVP-3.2/3.3/3.4 added zero). `loader.cpp`'s `apply_request` body extends in step 8.5 + step 4 fd opening + the state-b reuse_fd loop grows 9 → 11 — see impl-notes D-3.4-1 (peer-noted; design §5.29 EDITED-row label resolves to loader.cpp in physical layout).
- PI-13-3.4 / PI-27 (the load-bearing defer PI): inner-allowlist-value shape `unsigned char present` UNCHANGED in `allowlist_a/b` HASH and `cidr_allowlist_a/b` LPM_TRIE. `__type(value, __u8)` byte-equivalent. **The defer was specifically about NOT making this change.**
- PI-28: `mac_filter_prog` BPF function body BYTE-EQUIVALENT to MVP-3.2 modulo two new `.maps` declarations (`rules` ARRAY + `action_table` ARRAY). Datapath does NOT issue `bpf_map_lookup_elem` against either new map.
- PI-29: `rules` + `action_table` POPULATED on apply but NOT consulted by datapath; the WARN line above is the operator-facing signature.
- PI-30: `bypass` primitive = `detach`-alias + audit-log + `--unsafe` gate (no new BPF map flag, no datapath touch).
- PI-31: exporter READ-ONLY by construction; `grep -rE 'bpf_(map_(update|delete)_elem|obj_pin|link_create|link_destroy|xdp_(attach|detach)|prog_load)' src/exporter/` returns ZERO matches.
- PI-33: `xdpmacfilter --version` AND `xdpmf-exporter --version` BOTH report `0.6.0` (shared `version.h` from CMake `project(VERSION)`).
- PI-34 (= PI-6-3.4): 36 pre-§5.29 ctests pass byte-equivalent OR legitimately SKIP-77; existing test bodies UNCHANGED.

### Out-of-scope fences (per §5.29; expanded list in design.md §7 OOS)
- Per-rule counter map (`per_rule_counters` `BPF_MAP_TYPE_PERCPU_*`) — MVP-3.4b per Open Q #13 RESOLUTION.
- Inner-allowlist-value extension (`__u8` → `struct {__u8 present; __u32 rule_id;}`) — MVP-3.4b. Gated by PI-13-3.1 adjudication.
- Datapath wiring of `rules` or `action_table` — MVP-3.4b.
- Action types beyond `{PASS, DROP}` — MVP-3.8+.
- JSON structured logs from exporter / sFlow / HTTPS / authentication / histograms / IPv6 bind / inotify on bpffs root — all MVP-3.5+ or operator-wrap-with-reverse-proxy.
- Bypass via BPF map flag (versus detach-alias) — fenced by HG-3.4-2.
- Ansible installs of `xdpmf-exporter` / `docs/EXPORTER.md` — MVP-3.5+ candidates.
- Atomic-swap on `rules` map (parallel-outer pattern from §5.27) — fenced this slice (D-3.4-4); surfaced as MVP-3.4b Open Q.
- MVP-3.1/3.2/3.3 OOT-deferred housekeeping items — per Q6 DEFER.

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
