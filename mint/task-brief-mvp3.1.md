# Task brief — MVP-3.1: config-first foundation (brownfield)

## Goal

Ship **Composite 6 — "Config-first foundation"** per `mint/architecture-v2.md` (round-2 rework) as the first MVP-3 slice. This is the **architectural foundation** for the long-horizon system described in the v2 architecture: every byte of cycle-1 surface must remain load-bearing through MVP-3.N (zero deprecation work allowed).

Six interlocking pieces land together:

1. **Internal code reorg** — `src/loader/` splits into `src/lib/` (loader + raii + identity) + `src/cli/` (argv parsing + apply orchestrator); internal `xdpmf_internal` CMake target (no SONAME, no installed headers). Mechanical refactor — no behaviour change.
2. **YAML config schema** — `/etc/xdpfilter/<iface>.yaml` describes the interface ruleset. MAC-only matching for cycle 1 (CIDR / ports / etc. land in MVP-3.2+ as in-config rule-type extensions, NOT as new CLI flags).
3. **Parser + validator + `LoaderError::ConfigError = 9`** — custom ~150-LOC subset YAML parser (human gate decision — see "Human-gate decisions" below); structured error reporting; exit code 9 reserved for any config-layer failure.
4. **Atomic apply via `ARRAY_OF_MAPS`** — outer `BPF_MAP_TYPE_ARRAY_OF_MAPS[2]` containing two inner `mac_allowlist` HASH maps; userspace writes new ruleset to inactive inner, flips `active_idx`. Single-syscall atomic swap. One-deep rollback history (old ruleset alive until next apply).
5. **`bpf_link__pin()` + idempotent reattach (P0a)** — pin at `/sys/fs/bpf/xdpmacfilter/<iface>/link`; loader detects existing pin on attach, uses `BPF_F_REPLACE` for hot reattach. Validates the "filter continues across loader exit" semantics that `architecture-v2.md` relies on for the bypass-on-failure story.
6. **`XDPMF_TRUST_MODEL=strict|fleet` env var** — single switch (human gate decision). `strict` is default and preserves all MVP-2 identity-gate behaviour (§5.4 / §5.19 / §5.22 untouched); `fleet` relaxes §5.4 alien-program check only; §5.19 O_PATH bpffs ops and §5.22 tag-check stay enforced in both modes.

Estimated budget per `architecture-v2.md`: ~250-300 LOC source + ~120 LOC test, 5-7 ctests. This is the **largest mint slice to date** (~3× MVP-2 Sec/Perf/Robust) — scope is deliberately bundled because the six pieces are interlocking (atomic apply needs ARRAY_OF_MAPS; ARRAY_OF_MAPS needs config harness to write to; config harness needs parser; reorg makes the apply orchestrator's home obvious; P0a is the survival contract atomic apply assumes; trust model is the env-var on the new code path). Carving them apart would create the throwaway surface Composite 6 was selected to avoid.

## Context: prior work

- **All prior briefs**: `mint/task-brief-mvp1{,.1a,.1b,.1c}.md` + `mint/task-brief-mvp2-{sec,perf,robust,polish2}.md`.
- **Existing design**: `mint/design.md` — ~3410 lines through §5.25 + §6.20 + §7 OOS (MVP-2 fully shipped).
- **MVP-2 Polish-2 review**: `mint/review.md` (round-1 pass, 0 findings).
- **Architecture brief**: `mint/design-brief.md` — the mint-hld brief that drove the v2 round.
- **Architecture document (load-bearing for this brief)**: `mint/architecture-v2.md` (round-2 rework, ~419 lines).
  - **Composite 6 spec**: lines 147–168 — read this section verbatim before architect Phase A.
  - **Per-phase risk register MVP-3.1 rows**: lines 328–332 — five risks identified, mitigations sketched.
  - **Open Questions answered at human gate** (NOT for architect to re-open): Q #1 (Composite 6 chosen), Q #8 (single trust-model switch), Q #10 (custom ~150-LOC YAML subset parser), Q #12 (P0a folded into MVP-3.1).
  - **Open Questions remaining for architect to decide in §5.26**: Q #11 (binary rename — keep `xdpmacfilter` for MVP-3.1; do NOT rename to `xdpfilter` in this slice).
- **Round-1 brainstorm** (datapath/UX/migration): `/tmp/mvp3-brainstorm/architect-{A,B,C}.md` + `synthesis.md` — reference material.
- **Round-2 config-design brainstorm**: `/tmp/mvp3-config-design/architect-{T1,T2,T3}.md` + `synthesis.md` — schema-shape thinking already explored; T1 in particular pre-thought the parsing problem.

## Workflow rules (brownfield mode)

- **Architect**: read existing `design.md` (focus §4.1 exit-code table — new row 9 `ConfigError` slots in; §5.4 / §5.19 / §5.22 identity-gate sections — the trust-model env var fences which checks the `fleet` mode relaxes; §5.20 attach() flow — P0a slots in as pin-after-attach + idempotent-detach-on-pin-present; §6.x TestStrategy invariants the apply-flow ctests extend) + `architecture-v2.md` Composite 6 spec verbatim + this brief. EDIT `design.md` in place. Append `§5.26 MVP-3.1: config-first foundation` after §5.25. Add new row 9 `ConfigError` to §4.1. Append new §6.x TestStrategy entries per the new ctests. Update §7 OOS — move the relevant deferred entries (Composite 6 components) from deferred-to-MVP-3 to shipped. Append new §6.5 invariants for the post-reorg directory layout (`src/lib/` + `src/cli/`) so reviewer can flag any future regression. Update §6.5 `Preserved invariants` section explicitly: MVP-2 §5.4/§5.19/§5.22 identity gates remain enforced in `strict` mode (the default); 20 existing ctests pass unchanged.
- **Impl**: HEAVY EDIT across multiple files (largest impl scope to date). NEW files: `src/cli/apply.{cpp,hpp}`, `src/cli/config.{cpp,hpp}` (or per architect's reorg layout), `include/xdpmf/config.h` or similar for the parsed-config types, `src/bpf/mac_filter.bpf.c` (extend with ARRAY_OF_MAPS outer + inner-deref read pattern). EDITED files: `src/loader/loader.{cpp,hpp}` → relocate to `src/lib/` per Q1; `src/loader/cli.{cpp,hpp}` → relocate to `src/cli/` per Q1; `CMakeLists.txt` for new target + new source files; `tests/CMakeLists.txt` for new ctest entries. `src/loader/main.cpp` becomes the `xdpmacfilter` binary entry shim. `src/common/mac_filter.h` likely extended with new map definitions (`active_idx_map`, `rulesets_outer` per Q4 — see below). loader.hpp public-API: ONE new `LoaderError::ConfigError = 9` enumerator line (precedent: MVP-2 Sec `PathRefused = 8`, MVP-2 Robust `KernelUnsupported = 7`).
- **Tester**: ADD 5-7 ctests per `architecture-v2.md` line 158 list: `T_APPLY_VALID_CONFIG`, `T_APPLY_REJECTS_MALFORMED`, `T_APPLY_ATOMIC_SWAP_NO_DROP`, `T_APPLY_REPLACES_RULESET`, `T_LINK_PERSIST_ACROSS_LOADER_EXIT`, `T_TRUST_MODEL_FLEET_RELAXES_GATE`, `T_EXIT_CODE_9_ON_CONFIG_ERROR`. NEW fixture files: `tests/fixtures/config_valid.yaml`, `tests/fixtures/config_malformed.yaml`, possibly more per architect's schema choices. EDIT `tests/lib/common.sh` if new helpers needed (`apply_config()`, `wait_for_active_idx_flip()`). DO NOT edit existing 20 tests' bodies — they must still pass byte-equivalent invocations of `--allow <mac>` per the backward-compat contract.
- **Reviewer**: 4-point triangulation + the brownfield 5th point `Existing behaviour preserved`. Special attention:
  - **(1) MVP-2 invariants preserved**: §5.4 / §5.19 / §5.22 untouched in `strict` mode (default) — `[REGRESSION]` tag mandatory if ANY existing identity-gate check is bypassed when `XDPMF_TRUST_MODEL` is unset or set to `strict`.
  - **(2) 20 existing ctests pass**: refactor moved files but didn't change behaviour. `[REGRESSION]` if any existing ctest fails or requires modification beyond path updates.
  - **(3) Atomic apply ctest is real**: `T_APPLY_ATOMIC_SWAP_NO_DROP` must demonstrate concurrent traffic + reload without packet drop (not just "apply succeeded"). `[INVARIANT-VIOLATED]` if the test is theatrical (e.g., sequential apply-then-traffic).
  - **(4) `LoaderError::ConfigError = 9`**: exactly one new enumerator line in loader.hpp (mirror MVP-2 Sec/Robust precedent). `[UNRELATED-EDIT]` if other lines in the enum body changed.
  - **(5) `bpf_link__pin()` survival**: `T_LINK_PERSIST_ACROSS_LOADER_EXIT` must actually kill the loader and verify the filter is still enforcing on a fresh packet — not just "pin file exists on bpffs".

## Human-gate decisions (NOT open for architect re-opening)

These three were resolved at human gate based on `architecture-v2.md` open questions + project context. Architect documents the decision in §5.26 but does NOT re-explore the option space.

### HG1: YAML parser → custom ~150-LOC subset (Open Q #10 resolved)

**Decision**: implement a custom subset YAML parser in `src/lib/yaml_subset.{cpp,hpp}` (or per architect's directory layout). Architect declares the accepted grammar in §5.26 and a §6.x TestStrategy entry; anything outside the subset → `ConfigError` exit 9 with a clear `unsupported YAML feature: <feature>` message.

**Rationale**: `cli.cpp:1-3` documents "zero non-standard deps" as a load-bearing project value (held across MVP-1 → MVP-2). yaml-cpp tags ~70KB .so + transitive libstdc++ dependency; vendored single-header alternatives (rapidyaml etc.) add ~5-10K LOC to the repo. Composite 6's schema is small — top-level map + `rules:` list of rule-maps + scalar values — and architect-controlled subset grammar IS a feature (validator can be sharper than full YAML). Synthesis recommendation (architecture-v2.md line 328) defaults to this option for the same reason.

**What's left for architect to decide**: the exact accepted subset (must support top-level mapping, list-of-mappings, double-quoted string scalars, integer scalars, `null` for default values; MAY support comments, anchors, block scalars — architect picks YES/NO per construct and documents in §5.26 + §6.x).

### HG2: P0a (`bpf_link__pin()`) folded into MVP-3.1 (Open Q #12 resolved)

**Decision**: implement P0a as part of this slice. Verification of the libbpf API behaviour across (loader exit → loader restart → `BPF_F_REPLACE` reattach) is covered by ctest `T_LINK_PERSIST_ACROSS_LOADER_EXIT`. If the API misbehaves at Phase B, escalate via the standard mint inline-merge / architect-amendment pattern (MVP-2 Sec/Robust precedent); do not carve out a separate preliminary cycle.

**Rationale**: `bpf_link__pin()` is standard libbpf 1.x API actively used in production by Cilium and Katran; ABI stable since 5.7. Hidden assumption #4 in `architecture-v2.md` flags it as never-verified-on-our-code, but the ctest IS the verification. Carving a separate MVP-3.0.5 cycle for one API call + two ctests is ceremony without ROI; mint's Phase B peer-dialog + inline-merge has handled comparable surprises in 3 of 4 MVP-2 slices.

### HG3: `XDPMF_TRUST_MODEL` → single switch `strict|fleet` (Open Q #8 resolved)

**Decision**: one env var, two literal values. `XDPMF_TRUST_MODEL=strict` (or unset → default strict) preserves all MVP-2 identity-gate behaviour (§5.4 alien-program check + §5.19 O_PATH bpffs ops + §5.22 tag-check all enforced). `XDPMF_TRUST_MODEL=fleet` relaxes ONLY §5.4 alien-program check; §5.19 + §5.22 stay enforced in both modes. Unknown values → `ConfigError` exit 9 at startup with `unknown trust model: <value>` (fail-closed).

**Rationale**: audit story is critical — one env var → one state, greppable in logs and Prometheus-alertable as `xdpmf_trust_model_label`. Per-axis (3 independent env vars → 2³=8 combinations) is over-engineered for the actual use-case (fleet operators think binary: "this VM is in trusted segment / not"). A+C architects converged on env-var; T narrowed to env-var-only. Asymmetric reversibility: single → multi is cheap to add later (additional override env vars on top); multi → single is breaking env-var surface change.

**What's left for architect to decide**: stderr-logging policy on attach (suggested: always emit `xdpmacfilter: trust_model=<strict|fleet>` to stderr at attach so the operator + audit trail see the active mode); whether `T_TRUST_MODEL_FLEET_RELAXES_GATE` exercises the relax-path with a real alien-program fixture (Y/N).

## Open mechanism questions (architect decides; document in §5.26)

### Q1: Internal code reorg layout

`architecture-v2.md` line 155 specifies `src/loader/` → `src/lib/` + `src/cli/` with internal `xdpmf_internal` STATIC target. Architect picks the precise layout:

- **Option R1 (minimum split)**: `src/lib/{loader.cpp,loader.hpp,raii.hpp}` (the BPF-facing code) + `src/cli/{cli.cpp,cli.hpp,main.cpp,apply.cpp,config.cpp}` (the user-facing code) + new `src/lib/config.cpp` for the parser. One static lib target `xdpmf_internal` from `src/lib/*`; CLI binary links it.
- **Option R2 (three-way split)**: `src/lib/` (loader + raii) + `src/config/` (parser, validator, schema types) + `src/cli/` (argv + apply orchestrator). Two static targets (`xdpmf_internal` + `xdpmf_config`). Cleaner separation; one extra CMake target.
- **Option R3 (object lib)**: `OBJECT` library target instead of `STATIC` — objects relinked into each binary at link time. Equivalent until MVP-3.4 exporter binary lands; defer-the-decision option.

**Recommendation**: **R1** for cycle 1 (smallest disruption to existing ctest paths); promote to R2 if MVP-3.4 exporter binary needs it. `STATIC` over `OBJECT` (R3) — `STATIC` is conventional and exposes link-time correctness immediately.

### Q2: Atomic apply mechanism — `ARRAY_OF_MAPS[2]` vs alternatives

`architecture-v2.md` line 153 specifies outer `BPF_MAP_TYPE_ARRAY_OF_MAPS[2]` + inner `mac_allowlist` HASH × 2 + `active_idx` flip. Architect picks how the BPF program reads the active inner:

- **Option A1 (active_idx in separate ARRAY[1])**: dedicated `BPF_MAP_TYPE_ARRAY` of size 1 holds the current active index; BPF program reads it, then `bpf_map_lookup_elem(&rulesets_outer, &active_idx)` to get the inner FD, then looks up the MAC in the inner. Atomic swap = single userspace update to the active_idx ARRAY[0].
- **Option A2 (active_idx as flag in inner)**: each inner map has a sentinel key holding "I am active"; BPF program iterates outer slots and picks the active one. More complex on hot-path; rejected unless A1 has a verifier issue.
- **Option A3 (`BPF_F_REPLACE` direct on inner map FD)**: userspace replaces the entire inner map's contents via `bpf_map_update_batch`; no outer map needed. **Pro**: simpler structure. **Con**: not actually atomic across multiple keys (interleaved with concurrent reads on hot-path); fails `T_APPLY_ATOMIC_SWAP_NO_DROP` if traffic hits the half-applied state.

**Recommendation**: **A1**. A2 is too clever; A3 is not atomic across keys (defeats Composite 6's promise).

### Q3: `--allow <mac>` backward-compatibility semantics

`architecture-v2.md` line 154 says "existing `--allow <mac>` flag kept for backward compatibility (one-rule shorthand that synthesizes a single-rule config in-memory)". Architect picks:

- **Option BC1 (silent shorthand)**: `--allow AA:BB:CC:DD:EE:FF` synthesizes an in-memory single-rule YAML `{interface: <inferred>, default_action: drop, rules: [{id: 0, action: pass, match: {mac: AA:BB:CC:DD:EE:FF}}]}` and feeds it through the same apply path. No warning. Operator UX unchanged from MVP-2.
- **Option BC2 (deprecation warning)**: same as BC1 + `stderr` warning `--allow is deprecated; use 'apply -f <file>'; will be removed in MVP-3.5`. Honest about the path forward; slight noise in MVP-2 ops scripts.
- **Option BC3 (drop)**: refuse `--allow` with `error: --allow removed; use 'apply -f <file>'` + exit 1. Breaks every existing ctest invocation; only acceptable if every existing ctest is rewritten to use the new surface (huge scope creep).

**Recommendation**: **BC1** through MVP-3.4. Existing 20 ctests pass byte-identically; the `apply -f` surface gets exercised separately by the new MVP-3.1 ctests. Promote to BC2 at MVP-3.4 once exporter binary lands and operator docs converge on apply-only.

### Q4: Apply subcommand grammar

`architecture-v2.md` line 154 sketches `xdpmacfilter apply -f /etc/xdpfilter/<iface>.yaml --iface <iface>`. Architect picks the exact CLI surface:

- **Option G1 (subcommand)**: `xdpmacfilter apply -f <file> --iface <iface>` (verb-first); MVP-2 invocations stay verb-less (`xdpmacfilter --allow ...`, `xdpmacfilter bypass`, `xdpmacfilter detach`). Subcommand `apply` is the first one; `bypass` and `detach` become subcommands too in a future cycle for consistency.
- **Option G2 (flag form)**: `xdpmacfilter --apply -f <file> --iface <iface>`; all MVP-2 flag-form invocations stay flag-form. No subcommand syntax introduced.
- **Option G3 (full subcommand from day 1)**: rename `bypass` / `detach` to subcommands now (`xdpmacfilter bypass --iface ...` instead of `xdpmacfilter bypass ...` — already subcommand-ish). Consistent UX from MVP-3.1; minor surface churn for the two existing MVP-2 subcommands.

**Recommendation**: **G1**. Pragmatic — `apply` is naturally a subcommand (it has its own flags `-f` / `--iface`); leaving the existing MVP-2 surface alone preserves backward compat (HG-aligned). G3 is the "right" long-term shape but costs MVP-2 ops-script breakage for a cosmetic win.

### Q5: Schema versioning

`architecture-v2.md` line 332 recommends `schema_version: 1` from day 1. Architect confirms or revises:

- **Option SV1 (mandatory top-level field)**: every config file MUST start with `schema_version: 1`; absent or unknown → `ConfigError` exit 9. Locks in evolvability from cycle 1.
- **Option SV2 (optional, default 1)**: `schema_version` is optional; if absent, treated as `1`; if present, must match supported list. Friendlier to early adopters writing minimal configs.
- **Option SV3 (defer)**: no schema versioning in cycle 1; introduce when first breaking change happens (MVP-3.3+). Risk: breaking change has no clean migration path.

**Recommendation**: **SV2**. Best of both — supports minimal configs in docs and tests, but mandatory once a `schema_version` is present means the field is real (not advisory). Future breaking change at MVP-3.3+ ships as `schema_version: 2` with `1` still accepted.

### Q6: BPF map definitions placement

`src/common/mac_filter.h` will gain new map definitions. Architect picks:

- **Option M1 (extend `mac_filter.h`)**: all new maps (`rulesets_outer`, `active_idx_map`, two inner `mac_allowlist` slots) declared in the same header. Single source of truth; header gets larger.
- **Option M2 (new `config_maps.h`)**: split config-layer map declarations into a sibling header. Separation of concerns; one new file.

**Recommendation**: **M1** for cycle 1; promote to M2 at MVP-3.4 when `rules` / `action_table` maps add more surface.

## Scope (6 items — anything else is OOS)

### Item 1 — Internal code reorg (per Q1)

**Where**: `src/loader/` → `src/lib/` + `src/cli/` per architect's Q1 layout. `CMakeLists.txt` rewires source paths. `tests/lib/common.sh` may need binary-path updates (the `xdpmacfilter` binary path doesn't move — output stays `build/src/cli/xdpmacfilter` or wherever; just CMake source paths change).

**Action**: file-move commit first (Phase B git hygiene if possible), then logic additions. New `xdpmf_internal` CMake static target. Zero behaviour change in this item; the existing 20 ctests must pass after this item alone.

### Item 2 — YAML schema + custom parser + validator (per Q5 + HG1)

**Where**: NEW `src/lib/yaml_subset.{cpp,hpp}` (parser) + `src/lib/config.{cpp,hpp}` (schema types + validator) per Q1 layout. NEW `tests/fixtures/config_valid.yaml` + `tests/fixtures/config_malformed.yaml` + 1-2 more variants per architect.

**Action**: implement the subset YAML parser + the typed config schema (struct `xdpmf_config { string iface; default_action; vector<rule>; }`); validator catches schema mismatches with structured error reporting. New `LoaderError::ConfigError = 9` enum addition to `loader.hpp`. Architect documents accepted subset + schema in §5.26 + §6.x.

### Item 3 — Atomic apply via `ARRAY_OF_MAPS` (per Q2 + Q6)

**Where**: EDIT `src/bpf/mac_filter.bpf.c` (extend with outer `rulesets_outer` ARRAY_OF_MAPS + inner-deref read pattern); EDIT or extend `src/common/mac_filter.h` per Q6.

**Action**: BPF program reads `active_idx`, then dereferences `rulesets_outer[active_idx]` for the inner MAC map, then looks up the source MAC. Userspace `apply` orchestrator writes the new ruleset to the inactive inner slot, then flips `active_idx` atomically. One-deep rollback history (old inactive inner stays populated until next apply overwrites it).

### Item 4 — Apply subcommand + `--allow` backward-compat (per Q3 + Q4)

**Where**: NEW `src/cli/apply.{cpp,hpp}` (apply orchestrator); EDIT `src/cli/cli.cpp` (argv parser gains the subcommand grammar); existing `--allow` handler synthesizes an in-memory config and feeds it through the apply path per BC1.

**Action**: argv parser dispatches `apply` subcommand to apply orchestrator; orchestrator parses config, validates, applies via Item 3 mechanism. `--allow <mac>` invokes the same code path with a synthesized config.

### Item 5 — `bpf_link__pin()` + idempotent reattach (P0a per HG2)

**Where**: EDIT `src/lib/loader.cpp` (post-attach: pin the link at `${XDPMF_BPFFS_ROOT}/<iface>/link`; on attach entry: detect existing pin via `bpf_obj_get` and use `BPF_F_REPLACE` for the new program load). EDIT `src/lib/loader.cpp` detach() to unpin before detach. New helper `pin_link()` / `is_pin_present()` in anon namespace.

**Action**: implement pin lifecycle + idempotent reattach. Stderr discipline: on idempotent reattach, log `xdpmacfilter: replacing existing program on <iface>` so the operator sees the path. `T_LINK_PERSIST_ACROSS_LOADER_EXIT` exercises the survival contract.

### Item 6 — `XDPMF_TRUST_MODEL` env var (per HG3)

**Where**: EDIT `src/lib/loader.cpp` (parse env var at attach entry; gate the §5.4 alien-program check on `trust_model == strict`). EDIT `src/lib/identity.cpp` if §5.4 check lives there. Stderr-log active trust-model at attach (per Q3 sub-decision).

**Action**: parse env var at start of `attach()`; default `strict` if unset; reject unknown values with `ConfigError` exit 9 + clear message. Gate §5.4 alien-program check on `strict`. §5.19 + §5.22 unconditional (both modes). New ctest `T_TRUST_MODEL_FLEET_RELAXES_GATE` exercises the relax-path.

### Tests (5-7 per `architecture-v2.md` line 158)

- **`T_APPLY_VALID_CONFIG`** — parse + apply a valid YAML; assert MAC filtering matches the rule.
- **`T_APPLY_REJECTS_MALFORMED`** — malformed YAML → exit 9 + clear stderr.
- **`T_APPLY_ATOMIC_SWAP_NO_DROP`** — concurrent traffic + apply; assert no packet drop during swap. **Load-bearing for Composite 6 promise** — this test makes or breaks the architectural story.
- **`T_APPLY_REPLACES_RULESET`** — second apply with different rules replaces first; old rules no longer match.
- **`T_LINK_PERSIST_ACROSS_LOADER_EXIT`** — apply → kill loader → send traffic → assert filter still enforces (P0a survival per HG2).
- **`T_TRUST_MODEL_FLEET_RELAXES_GATE`** — alien-program fixture + `XDPMF_TRUST_MODEL=fleet`; assert §5.4 check is bypassed; same fixture + `strict`; assert §5.4 fires.
- **`T_EXIT_CODE_9_ON_CONFIG_ERROR`** — bad `XDPMF_TRUST_MODEL=garbage` OR bad config → exit 9.

## Out of scope (explicit)

- **L3 src-CIDR axis** — MVP-3.2 slice (lands as in-config rule type, NOT as new CLI flag). `architecture-v2.md` dependency graph line 217.
- **`systemd xdpfilter@.service` template + Ansible playbook** — MVP-3.3 slice. `architecture-v2.md` line 226.
- **Per-rule counters + `xdpmf-exporter` binary + Prometheus** — MVP-3.4 slice. Composite 6 cycle 1 keeps existing global PERCPU_ARRAY stats untouched (`STAT_PASS` / `STAT_DROP` per §5.23).
- **Public `libxdpmf.so.0` SONAME-committed library** — MVP-3.6+ optional branch. The MVP-3.1 internal reorg makes this future promotion mechanical but does NOT ship it.
- **`xdpmfd` daemon** — MVP-3.6+ optional branch (only if measured reload cadence demands sub-second).
- **AF_XDP / mirror / rate-limit / redirect actions** — MVP-3.8+ deferred.
- **JSON structured logs** — MVP-3.5 slice.
- **sFlow ringbuf emitter** — MVP-3.6 (conditional on hw-sFlow absence).
- **Binary rename `xdpmacfilter` → `xdpfilter`** — MVP-3.12 slice. Keep `xdpmacfilter` name throughout MVP-3.1.
- **Automatic kernel tripwire (C.5)** — **KILLED** (not deferred). `architecture-v2.md` line 297 — fail-open inverts allowlist policy; manual bypass primitive in MVP-3.4 covers ops need.
- **Per-axis trust model env vars** — explicitly fenced by HG3. Single switch only.
- **Full YAML parser (yaml-cpp, rapidyaml)** — explicitly fenced by HG1. Custom subset only.
- **Schema versions other than `1`** — Q5: `1` only in cycle 1; `schema_version: 2` is for future breaking changes.
- **Multi-interface config in one file** — out of scope; one file = one interface (`/etc/xdpfilter/<iface>.yaml` per `architecture-v2.md` line 43).
- **Hot-reload signal handler** (e.g., `SIGHUP` triggers re-read of config) — apply happens via re-invoking `xdpmacfilter apply -f`, not via signals. Daemon-style reload is the MVP-3.6+ daemon branch.

## Definition of done

- `§5.26 MVP-3.1: config-first foundation` amendment in `design.md` documenting Q1-Q6 decisions with rationale + HG1/HG2/HG3 captured as inherited human-gate decisions
- `§4.1` exit-code table: new row 9 `ConfigError` (active, not reserved)
- New `§6.x TestStrategy` entries for the 5-7 new ctests
- `§6.5 Preserved invariants` updated: MVP-2 §5.4/§5.19/§5.22 identity gates remain enforced in `strict` mode (default); 20 existing ctests pass byte-equivalent invocations
- `§7 OOS`: Composite 6 components moved from deferred to shipped
- `src/loader/` reorg complete per Q1 (paths under `src/lib/` + `src/cli/`); existing 20 ctests pass after reorg alone (verify before adding logic)
- `loader.hpp` gains exactly one new line: `ConfigError = 9,` — verifiable via `git diff`
- 5-7 new ctests pass; **`T_APPLY_ATOMIC_SWAP_NO_DROP` and `T_LINK_PERSIST_ACROSS_LOADER_EXIT` are the load-bearing pair** (Composite 6 promise + P0a verification)
- 20 existing ctests still pass (or legitimately SKIP per §6.5)
- `XDPMF_SANITIZERS=ON` build clean
- `xdpmacfilter --version` reports `xdpmacfilter 0.3.0` (bump from 0.2.3 to mark MVP-3.1; CMake `project(VERSION)` per MVP-2 Polish-2 V1 mechanism)
- `CHANGELOG.md` entry `[0.3.0] - 2026-05-NN` (Keep-a-Changelog format per MVP-1.1C precedent)
- `mint/review.md` round-1 verdict = `pass`
- One git commit per phase boundary per workflow B

## Dependencies

No new system dependencies. `bpf_link__pin` is libbpf 1.0+ (kernel ≥ 5.7; well below floor 5.15). `ARRAY_OF_MAPS` is kernel ≥ 4.12 (well below floor). YAML parsing is in-tree (custom subset per HG1). No new C++ libraries.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       [lang/cpp.md, lang/cmake.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []
```
