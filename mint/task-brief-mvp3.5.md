# Task brief — MVP-3.5: JSON structured logs (brownfield)

## Goal

Add `XDPMF_LOG_FORMAT={text,json}` env var to BOTH binaries (`xdpmacfilter` and `xdpmf-exporter`). When `XDPMF_LOG_FORMAT=json`, every diagnostic stderr line becomes a single-line JSON object with a stable schema (one event per line, NDJSON-style). When unset OR `text` (default), the existing stderr lines are byte-equivalent to current behaviour — fleet operators who grep text don't break.

The slice closes the **carry-forward fence** that's been sitting in §7 OOS since MVP-3.4.5 (5 consecutive cycles). It's the next-natural architectural slice per `architecture-v2.md` post-MVP-3.4b sequencing, and it pairs naturally with MVP-3.4b's structural fields work (per-rule counters → operator-readable Prometheus labels; JSON logs → operator-readable diagnostic stream). Together they complete the "observability surface" promise.

Scope is **41 stderr emission sites across 8 files** (grep-counted, brief-author Phase A discipline applied — see notes at bottom). Mostly mechanical conversion once the logger module + event-name catalog are in place. Estimated budget: **~1 cycle, low-medium risk**. Largest risk vectors: (a) text-mode byte-equivalence regression on the 52-ctest baseline (any text-mode drift = `[REGRESSION]`); (b) JSON shape decisions baking in long-lived contracts (event names, field types, timestamp format — operators will write log-shipping pipelines against these).

## Context: prior work

- **All prior briefs**: archived in `mint/task-brief-mvp{1,1.1*,2-*,3.1,3.2,3.3,3.4,3.4.5,3.4b-c1}.md`. Most recent: MVP-3.4b cycle 1 per-rule counters (round-1 pass 2026-05-25; 52/52 ctests + 0 findings + 1 OOT inline-merge).
- **Existing design**: `mint/design.md` — §5.31 (MVP-3.4b cycle 1 — per-rule counters + sidecar JSON writer in `src/lib/sidecar.cpp`) is the **direct ancestor** for the JSON-writing idiom. The roll-your-own JSON writer pattern is now established (zero `nlohmann/json` dep; ~200 LOC for sidecar; expect ~250-300 LOC for the logger module given more event types). `src/lib/sidecar.cpp` is the reference implementation — its `json_escape`, atomic-write idiom, line-oriented format are all relevant.
- **Architecture document**: `mint/architecture-v2.md` — MVP-3.5 row sketches "JSON structured logs in loader + exporter". §"§5.30 §7 OOS" introduced the explicit fence + likely-shape sketch: `{"ts":"<iso8601>","level":"<info|warn|error>","event":"<name>","iface":"<iface or null>","msg":"<existing prose>","fields":{...}}`. This brief refines that sketch with concrete decisions.
- **`/mint-review` audit (commit `325e2ee`)** has no MVP-3.5-specific findings — pre-3.5 audit so JSON logs weren't reviewable. Cross-cutting "structured-logging" sentiment was an implicit M2-class fleet-ops finding.
- **PI continuity**: `loader.hpp` is in its 6th consecutive ZERO-diff cycle + `config.hpp` 1st cycle (per Phase A grep dividend in MVP-3.4b). This brief is **likely to break** the loader.hpp streak only if a new internal helper signature lands in the header (architect decides where logger module's public surface lives — `src/lib/logger.{cpp,hpp}` is the natural shape, NOT in `loader.hpp`). Brief author's expectation: **PI-7-3.5-hpp is byte-equivalent on `loader.hpp` (7th consecutive cycle)** + ZERO-or-additive on `config.hpp` (2nd cycle); the logger module owns its own header.

## Workflow rules (brownfield mode)

- **Architect**: read existing `design.md` §5.29 (MVP-3.4 — exporter stderr lines + bypass primitive audit-log) + §5.30 (MVP-3.4.5 — HK-4 escape + sudo identity in audit-log; HK-16 startup WARN format) + §5.31 (MVP-3.4b — `src/lib/sidecar.cpp` JSON-writer pattern; D-3.4b-10 zero-deps discipline; D-3.4b-14/20 line-oriented format) + §6.5 PI-1..PI-34 + new PI-3.4b-1..9 + §7 OOS. **Apply Phase A code-grep discipline** (post-MVP-3.4.5 architect-spec rule, sub-rule added post-MVP-3.4b): grep ALL stderr emission sites (`grep -rnE '(std::|f)?(printf|fprintf|cerr <<|fputs|fputc).*stderr' src/` → **41 sites across 8 files** per brief-author count); for each, identify whether it's an event (gets a stable event-name) or a free-form message (gets `msg` field only). EDIT `design.md` in place. Append `§5.32 MVP-3.5: JSON structured logs in loader + exporter`. Update §6.5 — PI-1..PI-34 + PI-3.4b-1..9 continue; **NEW PI-3.5-1 text-mode byte-equivalence** is the load-bearing invariant; PI-7-3.5-hpp byte-equivalent-or-additive continuation. Update §7 OOS — close MVP-3.5 deliverables; surface MVP-3.4b cycle 2 (atomic-swap promotion of `rules` map per D-3.4-4; action_table dispatch) AND MVP-3.5+ candidates (file/syslog destinations; log rotation; per-iface routing — all OOS this cycle).
- **Impl**: brownfield mode. FileList is a DIFF. Expect 1 NEW source pair `src/lib/logger.{cpp,hpp}` (logger module — format selector via env var + per-event emitter helpers + event-name catalog as `constexpr` table). ~9-12 EDITED source files (the 8 stderr-emitting files + CMakeLists.txt + CHANGELOG + design.md). Each existing stderr emission site converts to a `logger::emit(level, event_name, "<prose>", fields...)` call. Text mode renders byte-equivalent to the pre-§5.32 line (this is the load-bearing PI-3.5-1 contract); JSON mode renders the JSON envelope.
- **Tester**: NEW ctests (target 5-7):
  - `T_LOG_JSON_ATTACH_EVENTS.sh` — set `XDPMF_LOG_FORMAT=json`, run `attach`, capture stderr, parse with `jq`, assert each line is valid JSON with `{ts, level, event, msg}` + appropriate `iface` + `fields`. Negation: same trigger with `XDPMF_LOG_FORMAT=text` → no JSON lines (or default behaviour).
  - `T_LOG_JSON_APPLY_EVENTS.sh` — same for `apply` (richer event set: rule counts, atomic_swap flip, sidecar write).
  - `T_LOG_TEXT_BYTE_EQUIVALENT.sh` — **LOAD-BEARING canary for PI-3.5-1**: run a known stderr-producing sequence (attach + apply + detach with deterministic inputs) under `XDPMF_LOG_FORMAT=text` (default) and compare stderr byte-for-byte against MVP-3.4b's expected output. ANY drift = fail.
  - `T_LOG_JSON_EXPORTER_EVENTS.sh` — exporter under `XDPMF_LOG_FORMAT=json`; verify HK-16 startup WARN + HK-17 exit-6 ERROR (when triggered) + normal startup `listening on …` line are valid JSON with matching `event` names.
  - `T_LOG_JSON_BYPASS_AUDIT.sh` — bypass primitive's audit-log line under JSON mode; verify HK-4 structural fields (uid, euid, sudo_user, reason) map to JSON `fields:{}` cleanly.
  - Optional: `T_LOG_EVENT_CATALOG_STABILITY.sh` — micro-test asserting that the event-name catalog (a compile-time constexpr table in `logger.hpp` per architect's choice) contains the expected set of event names; locked-in to prevent silent rename of an event-name across cycles.
  - Existing 52 ctests post-MVP-3.4b must continue to pass (PI-6-3.5 strict superset). PI-3.5-1 byte-equivalence is the explicit fence — any ctest that greps stderr text MUST still pass without modification.
- **Reviewer**: 5-point brownfield framework. Special attention:
  - **(1) PI-3.5-1 byte-equivalence is the load-bearing invariant** — verify `T_LOG_TEXT_BYTE_EQUIVALENT` passes AND verify NO ctest body changes (the 52 existing ctests' stderr-grep assertions all hold byte-equivalent).
  - **(2) Event-name catalog stability** — verify the catalog is a compile-time `constexpr` table (per architect's design decision in Q1) so that adding/removing an event is grep-visible in the diff. No magic string literals scattered across emission sites.
  - **(3) JSON shape compliance** — verify each JSON line parses with `jq`; verify required fields (`ts`, `level`, `event`, `msg`) always present; verify `iface` is null-or-string (not missing); verify `fields:{}` is always an object (possibly empty, never absent).
  - **(4) PI-7-3.5-hpp** — `loader.hpp` byte-equivalent OR additive-only (impl-discretion — architect picks). `git diff main -- src/lib/loader.hpp` MUST be empty OR purely additive (new declarations, no removed/renamed symbols).
  - **(5) Out-of-scope drift fence**: no file destination logic, no log rotation, no syslog/journald-specific code, no per-iface routing. Logger emits to stderr only this cycle.

## Human-gate decisions (defaults applied — override at architect Phase A if you disagree)

### HG-3.5-1: Text-mode backward compat — **MUST be byte-equivalent**

Per `XDPMF_LOG_FORMAT` default `text` semantic: existing stderr lines are byte-equivalent to MVP-3.4b shape. No reordering, no field additions, no prose changes. Operators grepping for `"xdpmacfilter: config error: open"` continue to see the same line. The 52-ctest baseline IS the validation — any drift in text-mode stderr breaks at least one ctest's grep assertion.

**Default**: **PI-3.5-1 byte-equivalence is MUST**. The new logger's text-rendering MUST produce identical output to the pre-§5.32 emission site. Implementation-wise this means: each emission site's pre-§5.32 `fprintf(stderr, "...")` string becomes the `msg` parameter of `logger::emit(level, event, "<exact-old-string>", ...)`; in text mode the logger just writes `<exact-old-string>` + newline; in JSON mode it wraps. Architect may amend the test grep patterns if a future-cycle wants to evolve text-mode (e.g. add a `[level]` prefix) — that would be a deliberate breaking change requiring its own slice; OOS for MVP-3.5.

**If architect picks "text mode adds [level] prefix"** (semantically richer text output): all 52 ctests' grep patterns need updating + PI-3.5-1 framed as a STRENGTHENING of existing format. Architect's stronger call.

### HG-3.5-2: JSON shape — **single-line flat envelope** (one NDJSON line per event)

Per architecture-v2.md sketch + JSON Lines / NDJSON convention:
```json
{"ts":"2026-05-25T17:30:00Z","level":"info","event":"attach.success","iface":"veth_v0","msg":"attached prog id 29760 to veth_v0","fields":{"prog_id":29760}}
```

- **One event = one line** (newline-terminated; no pretty-printed multi-line JSON).
- **Required fields**: `ts`, `level`, `event`, `msg` (always present, never null).
- **Conditional fields**: `iface` (null if event isn't iface-scoped; string if it is — never absent).
- **Free-form**: `fields:{}` (object; empty `{}` if no structural data; never absent).
- **No schema_version field in MVP-3.5** — operators can detect via presence of `ts` field; explicit schema_version added when a breaking change ships.

**Default**: **above shape**. Architect can prune (e.g., drop `iface` and put it in `fields:{}`) but the flat top-level fields make jq queries cleaner (`jq 'select(.iface=="veth_v0")'` vs `jq 'select(.fields.iface=="veth_v0")'`).

### HG-3.5-3: Bypass audit-log under JSON mode — **emit as event `bypass.activated`**

HK-4 / D-3.4.5-8 already gave the bypass audit-log structural fields (uid, euid, sudo_user, reason). Under JSON mode these slot naturally into `fields:{}` of a `bypass.activated` event. This is the cleanest demonstration that "JSON mode = structural fields exposed", and it pairs with HK-4's permissive regex extension in T_BYPASS_CMD_DETACHES (the test already accepts both shapes per MVP-3.4.5 EDIT-3).

**Default**: yes — `bypass.activated` event with the 4 fields. Architect picks event-name (`bypass.activated` vs `bypass.audit` vs alternatives) per Q3 below.

### HG-3.5-4: Event-name discovery vs assignment — **architect catalogs all event names in design.md §5.32**

Each of the ~41 stderr sites maps to ONE of:
- A specific named event (loader: ~15 events; exporter: ~5 events; bypass: ~3 events; ~23 events total).
- A generic free-form "info" / "warn" / "error" line that doesn't deserve an event (these get `event="generic"` OR the architect inlines them into specific events; default: architect groups them under ~5 generic event names like `loader.info`, `exporter.error`).

**Default**: architect grep-walks the 41 sites + proposes a catalog of ~25-30 event names in §5.32. Brief author has NOT pre-cataloged them (would require reading 41 sites — that's architect's Phase A work per the spec rule). Catalog goes into design.md as a constexpr table + becomes the `constexpr` table in `logger.hpp` per Q1.

## Open mechanism questions (architect decides; document in §5.32)

### Q1: Logger module location — **`src/lib/logger.{cpp,hpp}`** (new file pair)

- **M1**: NEW `src/lib/logger.{cpp,hpp}` — separate module; `src/lib/logger.hpp` exposes `logger::emit(level, event, msg, fields)` + the event-name catalog as a `constexpr` table; `src/lib/logger.cpp` implements format selection (text vs JSON via env var read once at startup) + JSON envelope rendering. Mirrors the §5.31 sidecar split.
- **M2**: Inline helper functions in `src/cli/cli.cpp` (loader) + `src/exporter/main.cpp` (exporter) — DUPLICATE the logger logic. Smaller LOC delta but less DRY.
- **M3**: Single `src/common/logger.{cpp,hpp}` shared between loader + exporter — slightly different from M1 (`src/common` vs `src/lib`). `src/common` is the right home for shared-by-both-binaries headers (cf. `mac_filter.h`).

**Recommendation**: **M3** — `src/common/logger.{cpp,hpp}`. Both binaries need it; `src/common` is the established home for cross-binary code. Compiles into both `xdpmf_internal` library and the exporter binary.

### Q2: Timestamp format — **ISO-8601 UTC with `Z` suffix**

- **T1**: `"2026-05-25T17:30:00Z"` (ISO-8601, UTC, second-precision). Matches `src/lib/sidecar.cpp::format_timestamp_utc` from MVP-3.4b — already implemented helper that can be promoted to `src/common/logger.cpp` (or stay in sidecar and be called from there).
- **T2**: `"2026-05-25T17:30:00.123456Z"` (ISO-8601 with microsecond precision). Useful for ordering events fired within the same second.
- **T3**: `1748192195` (epoch seconds) or `1748192195000000000` (epoch nanoseconds). Smaller, sort-friendly, but operator-unfriendly (need to convert for human reading).

**Recommendation**: **T1** (ISO-8601 second-precision). Matches existing sidecar precedent. Operators can grep `2026-05-25T17:` for hourly windows. Microsecond precision (T2) is over-engineering for current event rates (which are operator-action events, not packet-rate events).

### Q3: Event-name convention — **`<subsystem>.<action>[.<outcome>]`** dot-delimited

- **E1**: Dot-delimited path: `attach.success`, `attach.fail.tag_mismatch`, `apply.start`, `apply.complete`, `bypass.activated`, `exporter.scrape.error.permission_denied`. Hierarchical, easy to filter (`.startswith("attach.")`).
- **E2**: snake_case flat: `attach_success`, `attach_fail_tag_mismatch`, etc. Simpler; matches existing C++ snake_case identifiers.
- **E3**: camelCase flat: `attachSuccess` etc. Inconsistent with project's C/snake_case convention.

**Recommendation**: **E1** (dot-delimited). Hierarchical event-names are the convention in structured-logging ecosystems (ECS, OpenTelemetry); easy to filter via `jq 'select(.event | startswith("attach."))'`. Slightly more characters than E2 but operator-readable wins.

### Q4: Env-var read timing — **once at startup, cached for process lifetime**

- **R1**: Read `XDPMF_LOG_FORMAT` once at startup; cache the format choice in a `constexpr` (no — `const`) module-static; every emission site reads the cached value. **Process restart required to switch format.**
- **R2**: Read on every emission. Cost: a `getenv` per stderr write. **Live-toggleable via env var update.**
- **R3**: Re-read on SIGHUP. Compromise.

**Recommendation**: **R1**. Matches the existing pattern (`XDPMF_TRUST_MODEL`, `XDPMF_BPFFS_ROOT` — all read once). Live-toggleable logging is over-engineering; if an operator wants to switch they restart the binary (cheap).

### Q5: `fields:{}` value types — **flat scalars only** (string, int, bool, null)

- **F1**: Only scalar values in `fields:{}`. No nested objects, no arrays. Each field is `"key":"string"|123|true|null`.
- **F2**: Allow nested objects (e.g., `fields: {"pin_paths": {"a": "/sys/fs/bpf/...", "b": "/sys/fs/bpf/..."}}`).
- **F3**: Allow arrays (e.g., `fields: {"failed_ifaces": ["veth0", "veth1"]}`).

**Recommendation**: **F1** (flat scalars). Matches the §5.31 sidecar one-rule-per-line shape; minimal JSON writer complexity (no recursive nesting); operators can re-construct nested structures from multiple events if needed.

### Q6: Logger build into both binaries — **CMake target inclusion**

- **B1**: `src/common/logger.cpp` added to BOTH `xdpmf_internal` (linked by loader) AND `xdpmf-exporter` target. Two compilations of the same TU.
- **B2**: `src/common/logger.cpp` becomes a separate STATIC library `xdpmf_common`; both binaries link it. Cleaner CMake but introduces a new target.
- **B3**: `src/common/logger.{cpp,hpp}` in `xdpmf_internal` only; exporter linked against `xdpmf_internal` (already half-true — exporter doesn't link `xdpmf_internal` today; would change build graph). Probably wrong shape.

**Recommendation**: **B1** (duplicate compilation). Minimal CMake change; symmetric to `src/lib/sidecar.cpp` which is only in `xdpmf_internal` (exporter has its own `sidecar_reader.cpp`). One TU compiled twice is negligible cost.

## Scope (cycle 1 — concrete items)

### Item PI-3.5-1 — Logger module (`src/common/logger.{cpp,hpp}`)
**Where**: NEW `src/common/logger.{cpp,hpp}` (~250-300 LOC total). `logger.hpp` exposes `enum class Level {Info, Warn, Error}`, `enum class Format {Text, Json}`, `void emit(Level, std::string_view event, std::string_view msg, std::span<const Field> fields = {})` where `struct Field { std::string_view key; FieldValue value; }` and `FieldValue` is a variant of `string_view | int64_t | bool | nullptr_t`. Module-static `Format g_format` cached from `XDPMF_LOG_FORMAT` env var at first call. Event-name catalog as `constexpr std::array<std::string_view, N> kEventNames` for stability checks. JSON writer reuses `json_escape` idiom from `src/lib/sidecar.cpp:38-158` (architect picks whether to refactor sidecar's escape helper into `src/common/json.{cpp,hpp}` shared OR duplicate the helper in logger.cpp).

### Item PI-3.5-2 — Stderr-emission site conversion (~41 sites across 8 files)
**Where**: EDIT `src/cli/main.cpp`, `src/cli/cli.cpp`, `src/cli/bypass.cpp`, `src/cli/apply.cpp` (if it has emission sites — check during Phase A), `src/lib/loader.cpp`, `src/lib/sidecar.cpp`, `src/exporter/main.cpp`, `src/exporter/http.cpp`, `src/exporter/stats_reader.cpp`, `src/exporter/rule_counters_reader.cpp` — convert each `fprintf(stderr, "<prose>", ...)` to `logger::emit(Level::<...>, "<event-name>", "<prose>", {Field{...},...})`. Text mode preserves byte-equivalence per HG-3.5-1.

### Item PI-3.5-3 — Event-name catalog in design.md + logger.hpp
**Where**: §5.32 in design.md contains the full table (~25-30 events: `attach.success`, `attach.fail.config`, `attach.fail.tag_mismatch`, `attach.fail.kernel_unsupported`, `detach.success`, `apply.start`, `apply.complete`, `apply.fail`, `bypass.activated`, `bypass.cancelled`, `exporter.listening`, `exporter.warn.bpffs_root_missing`, `exporter.error.all_ifaces_eacces`, `exporter.scrape.warn.iface_eacces`, `loader.warn`, `loader.info`, `exporter.warn`, `exporter.error`, ...). Architect commits the catalog in §5.32; `logger.hpp` mirrors it as a `constexpr` table.

### Item PI-3.5-4 — Tests (5-7 new ctests)
**Where**: `tests/T_LOG_JSON_ATTACH_EVENTS.sh`, `tests/T_LOG_JSON_APPLY_EVENTS.sh`, `tests/T_LOG_TEXT_BYTE_EQUIVALENT.sh`, `tests/T_LOG_JSON_EXPORTER_EVENTS.sh`, `tests/T_LOG_JSON_BYPASS_AUDIT.sh`, optional `tests/T_LOG_EVENT_CATALOG_STABILITY.sh`. Plus tests/CMakeLists.txt entries.

### Item PI-3.5-5 — Version bump 0.7.0 → 0.8.0 + CHANGELOG
**Where**: `CMakeLists.txt` (VERSION 0.7.0 → 0.8.0 — MINOR bump because new operator-facing env var + new structured-logging surface). `CHANGELOG.md` (new `[0.8.0]` entry per Keep-a-Changelog; sub-groups: Added — logger module + JSON format + 5-7 ctests; Internal — 41 stderr-site conversions).

## Out of scope (explicit)

- **File / syslog / journald destinations** — `XDPMF_LOG_DEST={stderr,file,syslog,journald}` is candidate scope for a follow-up cycle (MVP-3.5+; brief author calls it MVP-3.5b if/when it surfaces). This cycle is stderr-only.
- **Log rotation** — operators wrap stderr with their own log shippers (rsyslog, vector, fluentbit); native rotation is OOS forever.
- **Per-iface log routing** — separate stderr streams per iface; not needed at current event rate.
- **Log level filtering via env var** — `XDPMF_LOG_LEVEL={info,warn,error}` could mute info-level events; OOS this cycle (all events always emitted).
- **Schema_version field in JSON envelope** — added when a future cycle ships a breaking change; cycle 1 implicit schema_version=1.
- **bpf_printk JSON-ification** — kernel-side BPF debug-prints stay text; only userspace stderr converts.
- **MVP-3.4b cycle 2** (atomic-swap promotion of `rules` map; action_table dispatch) — carry-forward.
- **Doc bucket D1..D13** — user-driven manual pass, not /mint-dev.
- **Security M3 / Perf M1-M4 / TSAN / CO-RE field-probe** — separate cycles.

## Definition of done

- `§5.32 MVP-3.5` amendment in `design.md` with full event-name catalog (~25-30 entries) + Q1-Q6 decisions + HG-3.5-1/2/3/4 confirmation.
- `xdpmacfilter --version` reports `xdpmacfilter 0.8.0` (MINOR bump from 0.7.0).
- `xdpmf-exporter --version` reports `xdpmf-exporter 0.8.0`.
- `CHANGELOG.md` entry `[0.8.0] - 2026-05-NN`.
- 5-7 new ctests pass; 52 existing ctests still pass byte-equivalent (PI-3.5-1 text-mode contract — load-bearing canary T_LOG_TEXT_BYTE_EQUIVALENT).
- `XDPMF_SANITIZERS=ON` build clean.
- `mint/review.md` round-1 verdict = `pass` (cycle is low-medium risk; aim for round-1 pass).
- One git commit per phase boundary per workflow B.

## Dependencies

- No new build deps (roll-your-own JSON writer per MVP-3.4b D-3.4b-10 precedent).
- `jq` in test runtime (existing dep; multiple new ctests grep JSON output).
- No new BPF features.
- No new kernel-version dependencies.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       [lang/cpp.md, lang/cmake.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []
```

Note: `lang/bpf.md` pack DROPPED from impl this cycle (no datapath edit; pure userspace work). Tester pack stays since ctests still attach loader against veth fixture.

---

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])

This brief defers no questions to /mint-hld; all open questions are tactical (architect-tier). The JSON shape, event-name convention, env-var timing, etc., have strong defaults (industry conventions: NDJSON, dot-delimited event names, read-once env vars). No multi-axis design space to brainstorm. Single architect via standard /mint-dev is correct.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief author already ran these greps (April 2026 sense of "Phase A discipline" applied at brief-write time per [[mint-hld-scope-discipline]] post-MVP-3.4b retrospective). Architect should re-verify:

- `grep -rnE '(std::|f)?(printf|fprintf|cerr <<|fputs|fputc).*stderr' src/` → **41 sites across 8 files** (cli/{main,bypass,apply}.cpp, lib/{loader,sidecar}.cpp, exporter/{main,http,stats_reader,rule_counters_reader}.cpp). Architect catalog event names against this list during Phase A.
- `Read src/lib/sidecar.cpp:38-158` — the existing `json_escape` + `format_timestamp_utc` helpers. Decide: promote to `src/common/json.{cpp,hpp}` shared OR duplicate in `src/common/logger.cpp`.
- `grep -nE "XDPMF_LOG_FORMAT\|XDPMF_LOG" .` — should return ZERO matches (env var doesn't exist yet).
- `grep -nE 'XDPMF_(BPFFS_ROOT|TRUST_MODEL|ENABLE_BPF_OBJECT_OVERRIDE|SANITIZERS)' src/ docs/` — existing env-var patterns; new XDPMF_LOG_FORMAT follows the same idiom (read-once at startup; documented in `--help` env-var block per HK-6).
- `grep -rnE 'fprintf\(stderr.*[A-Z][a-z]+ ' src/` — find sites that emit identifying prefixes (`xdpmacfilter:`, `xdpmf-exporter:`); these become `event` candidates rather than `msg` candidates per the architect-spec sub-rule "where is X called per-runtime".
- Read existing ctests that grep stderr (`grep -rnE 'grep.*stderr\|grep.*\.stderr' tests/` or similar) — these are the byte-equivalence canaries. Architect catalogs the regex set so PI-3.5-1 has explicit invariant list.
