# Task brief — MVP-3.4.5: housekeeping (brownfield, code-only)

## Goal

Close the **code/test/build housekeeping backlog** accumulated through MVP-3.1..3.4 and the recent `/mint-review` audit (commit `325e2ee` of report.md in `agent-teams-review/`). Pure non-functional cleanup: no new operator-facing features, no scope expansion, no datapath behavior change. Documentation work (README rewrite, FLEET_DEPLOYMENT.md update, config schema doc) is split into a separate manual pass — NOT in this brief.

The slice ships **17 small items grouped into 3 themes**:

1. **Contract drift fixes** (HK-1..HK-8) — exit-code triple drift (KC-A from /mint-review), security gate on `XDPMF_BPF_OBJECT_PATH` (KC-C), bypass audit-trail hardening (KC-B partial), perf microopt, --help completeness.
2. **Refactor / landmine removal** (HK-9, HK-10) — 3-callsite `LIBBPF_PIN_BY_NAME` lockstep → single `kManagedMaps[]` table; broad `pkill -9 -f xdpmacfilter` → iface-scoped.
3. **OOT-deferred backlog** (HK-11..HK-17) — 7 items from MVP-3.1/3.3/3.4 OOT-defer queues; mostly comment/spec-text cleanup + 2 small "implement-or-retract" calls.

Estimated budget per `architecture-v2.md` per-phase scope summary (custom slice between MVP-3.4 and MVP-3.5): **~1 cycle, low risk**. Smallest LOC delta of MVP-3.x to date — mostly per-item Edits, one mechanical refactor, one new ctest, two test fixes. No new public API, no new BPF maps, no new binary.

## Context: prior work

- **All prior briefs**: archived in `mint/task-brief-mvp{1,1.1*,2-*,3.1,3.2,3.3,3.4}.md`.
- **Existing design**: `mint/design.md` — §5.29 (MVP-3.4) is the immediate ancestor. PI-1..PI-34 must continue to hold; this slice adds no new PIs (housekeeping by nature).
- **Architecture document**: `mint/architecture-v2.md` — no MVP-3.4.5 row added; this is an inserted maintenance slice that does NOT alter the dependency graph (MVP-3.5 JSON-logs remains the next architectural slice).
- **Review report** (driving this brief): `/home/user/agent-teams-review/runs/mint-review-mint-l2-mac-filter-202605250825/report.md` — 64 findings consolidated, 15 Critical+High citations verified by re-Read. 2 Critical + 4 of 5 Documentation-Highs are NOT in this slice (separated to manual doc pass per user direction).
- **MVP-3.4 review** (in-repo): `mint/review.md` — round-1 pass + 2 deferred OOTs (PI-32 startup WARN, exporter exit-6 unreachable) — both addressed here as HK-16/HK-17.
- **Previous-slice OOTs**: MVP-3.1 deferred 4 items (orphan map pins, stale NOTE, ParsedAttach wrapper text, §6.25 grep — per `project_mint_workflow_status.md` memory); MVP-3.3 deferred 1 (T_SYSTEMD_RESTART_ON_FAILURE flake — per `5a4760c` addendum). All 5 picked up here.
- **MVP-3.1..3.4 deviations**: `mint/impl-notes.md` D-3.1-1..D-3.4-2 stand. Do NOT undo any. D-3.1-1 (`apply_internal.hpp` is private; `apply_request` body lives in `loader.cpp`) is load-bearing for this slice — HK-1 touches the catch-arm in `main.cpp`, NOT a phantom `apply_internal.cpp`.

## Workflow rules (brownfield mode)

- **Architect**: read existing `design.md` §5.29 (MVP-3.4 — immediate ancestor) + §6.5 PI-1..PI-34 + §4.1 exit codes + the review report's TOP-15 actionable list. EDIT `design.md` in place. Append `§5.30 MVP-3.4.5: housekeeping (defer-posture audit + landmine removal)` after §5.29. This amendment documents the per-item decisions, NOT new contracts (most items are pure-fix). Update §6.5 — PI-1..PI-34 continue; PI-7-3.4-hpp ZERO diff continues (PI-7-3.4.5-hpp strengthening if you like the naming). NO new PIs unless a Q decision creates one. Update §7 OOS — surface MVP-3.5 (JSON structured logs in loader+exporter) as next slice; explicitly close out the 7 OOT-deferred items picked up here.
- **Impl**: EDIT-only slice (no NEW source files). Touched files: `src/cli/main.cpp` (HK-1 catch arm), `src/cli/apply.cpp` (HK-1 comment delete), `src/cli/cli.cpp` (HK-2 usage_text — add `7 kernel-unsupported`, HK-7 --unsafe semantic, HK-8 env-var block), `src/lib/loader.cpp` (HK-3 compile-gate XDPMF_BPF_OBJECT_PATH; HK-9 kManagedMaps refactor — biggest delta, ~50 LOC), `src/cli/bypass.cpp` (HK-4 log-escape in truncate_reason + sudo identity in audit log), `src/bpf/mac_filter.bpf.c` (HK-5 `unlikely()` wraps on 6 verifier null-check sites), `src/exporter/main.cpp` (HK-8 --help env-var block; HK-17 decision per Q3), `src/exporter/stats_reader.cpp` (HK-16 decision per Q2), `CMakeLists.txt` (HK-3 XDPMF_ENABLE_BPF_OBJECT_OVERRIDE option; HK-10 install(FILES docs/FLEET_DEPLOYMENT.md); version bump 0.6.0 → 0.6.1), `CHANGELOG.md` (new [0.6.1] entry), `tests/T_LINK_PERSIST_ACROSS_LOADER_EXIT.sh` (HK-10 iface-scoped pkill), `tests/lib/common.sh` (HK-10 kill_loader_keep_link — same fix), `tests/T_SYSTEMD_RESTART_ON_FAILURE.sh` (HK-11 per Q5 — retry/widen-band/SKIP-fallback), `tests/T_APPLY_ATOMIC_SWAP_NO_DROP.sh` (HK-12 stale NOTE comment fix), `tests/T_ATTACH_TAG_MISMATCH.sh` (HK-13 orphan pin cleanup). `loader.hpp` UNCHANGED — PI-7-3.4.5-hpp ZERO diff continues (5th cycle).
- **Tester**: NEW ctests (3-4, per Q decisions):
  - `T_APPLY_EXITS_1_ON_MISSING_CONFIG.sh` — asserts `xdpmacfilter apply -f /nonexistent --iface lo` exits 1 (HK-1 fix verification).
  - `T_BYPASS_INTERACTIVE_PROMPT.sh` — interactive y/N branch via `script -qc` or `expect`; SKIP-77 if neither present. Sub-cases: positive (y → detach exit 0), negative (n/EOF → cancel exit 0).
  - `T_BYPASS_REASON_TRUNCATE.sh` (or sub-cases in T_BYPASS_CMD_DETACHES.sh) — 256-byte (no truncation), 257-byte (truncated to 253+`…`), 300-byte ending mid 4-byte UTF-8 codepoint (rewind-safety).
  - `T_EXPORTER_EXITS_6_ALL_IFACES_EACCES.sh` (HK-17) — create per-iface bpffs dirs with chmod 000 (req. root + ability to reproduce EACCES on bpf_obj_get); launch exporter; assert exit 6 within healthz timeout. SKIP-77 if reproduction not possible in test env.
  - Existing 42 ctests must continue to pass (PI-6-3.4.5 = PI-6-3.4 strict superset). The only test-side EDITs are: HK-10/11/12/13 surgical fixes to already-named tests + HK-16 WARN assertion added to T_EXPORTER_NO_ATTACHED_IFACE.sh.
- **Reviewer**: 5-point brownfield framework. Special attention:
  - **(1) PI-1..PI-34 preserved** — no new public API, no datapath behavior change.
  - **(2) Defer-posture invariants from MVP-3.4 still hold**: PI-27 (inner-allowlist-value byte-equiv `__u8`), PI-28 (`mac_filter_prog` body byte-equiv modulo .maps), PI-29 (rules+action_table populated NOT consulted), PI-30 (bypass=detach alias), PI-31 (exporter READ-ONLY).
  - **(3) HK-9 refactor is byte-equivalent at semantics**: 3-callsite consolidation → kManagedMaps[] table; all 3 loops walk the same table; legacy_alias flag suppresses `allowlist` from pin/reuse loops; net effect identical to today's behavior; the 42-test baseline IS the validation.
  - **(4) HK-3 compile-time gate**: XDPMF_BPF_OBJECT_PATH must be unreachable in default release build (no `-DXDPMF_ENABLE_BPF_OBJECT_OVERRIDE`); T_VERIFIER_REJECT.sh continues to pass because tests/CMakeLists.txt sets the define.
  - **(5) PI-7-3.4.5-hpp ZERO diff on `src/lib/loader.hpp`**: 5th consecutive cycle. PI-7-3.4.5-cpp scope is now the kManagedMaps refactor + the XDPMF_BPF_OBJECT_PATH gate + the existing MVP-3.4 EDIT-1/EDIT-2 scopes — architect documents the new fence in §5.30.

## Human-gate decisions (defaults applied — override at architect Phase A if you disagree)

### HG-3.4.5-1: HK-16 PI-32 startup WARN — **IMPLEMENT per design**

Per `mint/review.md:82-85` OOT-1: design wants the WARN; impl chose silent graceful return. Reviewer flagged the gap and editorialized that silent is "arguably more conservative". **Rule [[impl-role-discipline]]: impl follows design; silent divergence is forbidden. Disagreement is allowed but ONLY via explicit escalation (peer SendMessage to architect during Phase B).** Design says WARN — impl emits WARN. **Default**: implement one-shot `std::filesystem::exists(bpffs_root)` check at exporter start; emit `xdpmf-exporter: WARN bpffs root <path> does not exist; will serve empty metrics` once at startup if missing. If impl genuinely thinks the WARN is wrong, peer-DM architect during Phase B; architect amends design OR holds firm. No silent fallback to "the MVP-3.4 silent behavior" without an architect ruling.

### HG-3.4.5-2: HK-17 Exporter exit-6 (permission denied) — **IMPLEMENT per design (architect specifies trigger condition)**

Per `mint/review.md:84-86` OOT-2: design declares exit 6 in §5.29 exporter exit-codes table; impl has no reachable path. The design declares the exit code EXISTS but does not specify WHEN it fires. **Rule [[impl-role-discipline]]: impl follows design; silent divergence forbidden; disagreement via explicit escalation only.** Design has a gap (no trigger condition), not a defect — architect must specify the trigger in Phase A. **Default trigger** (architect can override during Phase A; impl can peer-DM architect during Phase B if the trigger is impossible to surface or wrong-shape): exporter exits 6 when ALL discovered ifaces fail with EACCES/EPERM at `bpf_obj_get` AND there is no successful read; per-iface EACCES with at least one successful read remains the documented WARN-and-continue path (`stats_reader.cpp:141-145`). Architect amends §5.29 with the explicit trigger; impl surfaces exit 6 on that condition.

### HG-3.4.5-3: HK-9 `kManagedMaps[]` refactor — **shipping in this cycle**

This is the project-memory landmine `[[libbpf-pin-by-name-three-callsites]]`. MVP-3.4 added rules+action_table to all 3 arrays manually; the next datapath-map addition (MVP-3.5+) will likely fire the 27/42 ctest fail signature again. **Default**: refactor as `constexpr struct { auto get_map; const char* name; bool legacy_alias; } kManagedMaps[]` at anon-namespace scope in `loader.cpp`. All 3 loops (`open_skeleton_only`'s pinned_maps[], `apply_request`'s pin_specs[] and reuse_specs[]) walk the same table; the `legacy_alias` flag filters `allowlist` from pin/reuse loops (kept in clear-list only). ~50 LOC net delta (probably -20 LOC actual after dedup). Architect MAY defer to MVP-3.6+ if they think the refactor risk exceeds the landmine cost (low likelihood — pattern is mechanical).

### HG-3.4.5-4: HK-11 T_SYSTEMD_RESTART_ON_FAILURE flake — **internal retry, NOT widen-band**

Reviewer offered 3 options (internal retry / widen band / SKIP-77 fallback). **Default**: internal 2-attempt retry within the test (reset systemd state + re-run before declaring fail). Retains the strict band [4,5] assertion as the StartLimit-placement-footgun guard (the original purpose). Surface attempt count in PASS message. Architect can pick widen-band if retry adds too much test-runtime.

## Open mechanism questions (architect decides; document in §5.30)

### Q1: HK-1 exit-code triple-drift fix — catch placement in main.cpp

- **C1**: Add `catch (const xdpmf::CliError& e)` arm to main.cpp's SECOND try block (around `std::visit`). 3 LOC. Mirrors the FIRST try block's existing arm (line 99-103).
- **C2**: Wrap the whole `int main()` in a single try/catch with a switch on exception type (refactor). ~15 LOC.

**Recommendation**: **C1**. Smaller, mirrors existing pattern, lower review surface.

### Q2: HK-16 PI-32 startup WARN trigger details (per HG-3.4.5-1 — IMPLEMENT)

Default implementation per HG-3.4.5-1 covers: one-shot `std::filesystem::exists(bpffs_root)` check at exporter start; emit `xdpmf-exporter: WARN bpffs root <path> does not exist; will serve empty metrics`. ~10 LOC impl + 5 LOC test assertion in T_EXPORTER_NO_ATTACHED_IFACE.sh. Architect Q-decisions for nuance:

- **W1**: Check exactly once at startup BEFORE first listen; emit WARN to stderr; continue.
- **W2**: Check on every `/metrics` scrape (rate-limited to once per N seconds via static last-emit timestamp); emit WARN on transition exists→missing.

**Recommendation**: **W1**. Matches "ONE warning line at startup" literal language in PI-32; simplest impl; matches fleet-ops expectation (startup-time diagnostic, not per-scrape noise). W2 is over-engineering for the design's intent.

### Q3: HK-17 Exporter exit-6 trigger condition (per HG-3.4.5-2 — IMPLEMENT, architect specifies)

Default per HG-3.4.5-2: exit 6 when ALL ifaces fail EACCES/EPERM AND no successful read. Architect picks precise trigger semantics:

- **E1**: Exit 6 when ALL discovered ifaces fail with EACCES/EPERM and the discovered set is non-empty (i.e., directories exist but unreadable). Per-iface EACCES with at least one successful read = WARN+continue (current impl). Empty bpffs root = exit 0 (no-ifaces is a normal state per HK-16/PI-32).
- **E2**: Exit 6 when ANY iface fails EACCES/EPERM (fail-loud on partial-permission).
- **E3**: Exit 6 only when `bind()` fails EACCES (e.g., port < 1024 without CAP_NET_BIND_SERVICE) — purely process-startup permission, not per-iface.

**Recommendation**: **E1**. Matches the principle "if we can't read ANYTHING then permission-denied is the right exit code" while preserving "partial visibility better than no visibility" for normal fleet operation. E2 risks unit flapping if a single iface gets bpffs permission issue. E3 is a different failure mode (bind-time, not scrape-time) and probably warrants its own exit code anyway.

### Q4: HK-9 kManagedMaps[] table representation

- **T1**: `constexpr struct { bpf_map* (mac_filter*)::* member; const char* name; bool legacy_alias; }` — member-pointer table; loops walk via `(skel->maps).*entry.member`.
- **T2**: `constexpr struct { const char* name; bool legacy_alias; }` — name-only table; loops resolve map via `bpf_object__find_map_by_name(skel->obj, entry.name)`.
- **T3**: function-pointer / lambda dispatch table.

**Recommendation**: **T1** (member-pointer). Compile-time-checked, no runtime lookup, mirrors the existing literal-array structure most closely. T2 is simpler but adds a per-iteration name lookup.

### Q5: HK-11 T_SYSTEMD_RESTART_ON_FAILURE retry strategy (per HG-3.4.5-4)

- **S1**: Internal 2-attempt retry — reset systemd state + re-run before declaring fail.
- **S2**: Widen band from [4,5] to [1,50] permanently — still catches the misplacement footgun.
- **S3**: SKIP-77 on first flake — gives operator visibility but degrades coverage.

**Recommendation**: **S1** (HG-3.4.5-4). S2 is the fallback if S1 adds >30s to ctest runtime.

### Q6 (optional): tackle additional MVP-3.4 review findings deferred to follow-up?

Items 11-15 from `report.md` Top-15 list. Architect picks: include if scope budget allows; defer to a hypothetical MVP-3.4.6 otherwise.

- testing M5+M6: T_BYPASS_INTERACTIVE_PROMPT + truncation sub-cases — **already in scope (Tester section, NEW ctest list)**.
- perf H1: `__builtin_expect` on 6 verifier null checks — **already in scope (HK-5)**.
- doc H5: xdpmf-exporter section in FLEET_DEPLOYMENT.md — **excluded (doc pass, separate manual work)**.
- arch H2: 3-callsite refactor — **already in scope (HK-9)**.

**Recommendation**: **No additional items**. Scope as-stated is already 17 items + 3 new ctests; adding more risks scope explosion. Doc items are user-deferred to manual work.

## Scope (17 items + 2-3 new ctests + 3 existing-test EDITs — anything else is OOS)

### Item HK-1 — Apply exit-code triple drift fix (per Q1)
**Where**: EDIT `src/cli/main.cpp` (add CliError catch arm to second try around std::visit, returning kExitUsageErr); EDIT `src/cli/apply.cpp:14-29` (delete or rewrite the stale `ApplyFileIoError` planning comment); NEW `tests/T_APPLY_EXITS_1_ON_MISSING_CONFIG.sh` (assert exit code 1 on missing config).

### Item HK-2 — `--help` exit-code list adds `7 kernel-unsupported`
**Where**: EDIT `src/cli/cli.cpp:104-106` (usage_text — insert `7 kernel-unsupported,` between `6 permission,` and `8 path-refused,`).

### Item HK-3 — Compile-time gate XDPMF_BPF_OBJECT_PATH
**Where**: EDIT `src/lib/loader.cpp:97 (constant), :762/768/775 (error messages), :814-818 (consumer)` — wrap all uses in `#ifdef XDPMF_ENABLE_BPF_OBJECT_OVERRIDE` / `#endif`. EDIT `CMakeLists.txt` — add `option(XDPMF_ENABLE_BPF_OBJECT_OVERRIDE "Allow loader to honor XDPMF_BPF_OBJECT_PATH env var (testing-only)" OFF)` + propagate via `target_compile_definitions(xdpmf_internal PRIVATE $<$<BOOL:${XDPMF_ENABLE_BPF_OBJECT_OVERRIDE}>:XDPMF_ENABLE_BPF_OBJECT_OVERRIDE>)`. EDIT `tests/CMakeLists.txt` — set the option to ON for the test build (so T_VERIFIER_REJECT.sh continues to work). If T_VERIFIER_REJECT depends on a separately-built loader, this needs the override env-var-readable in test mode only.

### Item HK-4 — bypass log-injection escape + sudo identity
**Where**: EDIT `src/cli/bypass.cpp:38-53` (`truncate_reason` — after byte truncation, escape `\` → `\\`, `"` → `\"`, `\n` → `\\n`, `\r` → `\\r`, `\0` → `\\0`; mirror `prom_format.cpp:34-47` `escape_label_value`). EDIT `src/cli/bypass.cpp:124-129` (audit-log line) — read `getenv("SUDO_USER")` + `getenv("SUDO_UID")` if non-null; emit `BYPASS activated on %s by uid=%u euid=%u sudo_user="%s" reason="%s"` (sudo_user="<none>" if SUDO_USER null — keeps structural-field consistency).

### Item HK-5 — `__builtin_expect` on 6 verifier null-check sites
**Where**: EDIT `src/bpf/mac_filter.bpf.c` — add `#define unlikely(x) __builtin_expect(!!(x), 0)` near top; wrap the 6 null checks at lines 188, 204, 211, 229, 236, 254. ~8 LOC diff.

### Item HK-6 — usage_text `--unsafe` semantic clarification + env-var block
**Where**: EDIT `src/cli/cli.cpp` (usage_text) — fix `--unsafe` line to read `--unsafe    bypass: required in non-interactive context; ALSO suppresses interactive y/N prompt when passed at a tty.` (current wording reads as "non-interactive only"). Add new Environment variables sub-block: `XDPMF_TRUST_MODEL={strict|fleet}   Default strict. fleet relaxes only §5.4 alien-program refusal — see docs/FLEET_DEPLOYMENT.md.`. EDIT `src/exporter/main.cpp` (print_usage) — same Environment variables sub-block.

### Item HK-7 — install docs/FLEET_DEPLOYMENT.md
**Where**: EDIT `CMakeLists.txt:140-185` — add `install(FILES ${CMAKE_SOURCE_DIR}/docs/FLEET_DEPLOYMENT.md DESTINATION ${CMAKE_INSTALL_PREFIX}/share/doc/xdpmacfilter/)` inside the `XDPMF_INSTALL_SYSTEMD_UNIT` block (so both unit files' `Documentation=file://...` URI resolves post-install). Note: install gated on the existing systemd-unit-install option since they pair.

### Item HK-8 — version bump + CHANGELOG entry
**Where**: EDIT `CMakeLists.txt` (project VERSION 0.6.0 → 0.6.1); EDIT `CHANGELOG.md` (new `[0.6.1] - 2026-05-NN` entry per Keep-a-Changelog format; document all HK-1..HK-17 changes).

### Item HK-9 — `kManagedMaps[]` refactor (per HG-3.4.5-3 + Q4)
**Where**: EDIT `src/lib/loader.cpp` — introduce `constexpr` table at anon-namespace scope (per Q4 T1 default); rewrite `open_skeleton_only`'s `pinned_maps[]` (line 828), `internal::apply_request`'s `pin_specs[]` (line 1705), and `internal::apply_request`'s `reuse_specs[]` (line 1566) to walk the table. Legacy alias `allowlist` flagged `legacy_alias=true` so pin/reuse loops skip it (it stays in the clear-list only via the special-pin path at line 1739). PI-7-3.4.5-cpp adds this as an allowed-hunk scope. Net delta: ~50 LOC declarations + ~30 LOC loop simplification = net likely -10 to -20 LOC.

### Item HK-10 — iface-scoped pkill in T_LINK_PERSIST + kill_loader_keep_link
**Where**: EDIT `tests/T_LINK_PERSIST_ACROSS_LOADER_EXIT.sh:46, :110` — replace `sudo -n pkill -9 -f xdpmacfilter` with PID-tracked kill OR `sudo -n pkill -9 -f "xdpmacfilter.*${IFACE_A}"` (matching the `kill_loader_keep_link` pattern in common.sh:322). Tester picks the safer of the two — PID-tracked preferred. EDIT `tests/lib/common.sh:320-323` (`kill_loader_keep_link`) — same hardening if Tester picks PID-tracked (already iface-scoped; doesn't need change if argv-match is the chosen approach). Net delta: ~5-10 LOC.

### Item HK-11 — T_SYSTEMD_RESTART_ON_FAILURE flake fix (per HG-3.4.5-4 + Q5)
**Where**: EDIT `tests/T_SYSTEMD_RESTART_ON_FAILURE.sh` — add internal 2-attempt retry per Q5 S1 default (or alternative per architect override). Surface attempt count in PASS message: `PASS: T_SYSTEMD_RESTART_ON_FAILURE (attempt N/2)`. ~20 LOC.

### Item HK-12 — T_APPLY_ATOMIC_SWAP_NO_DROP stale NOTE comment fix
**Where**: EDIT `tests/T_APPLY_ATOMIC_SWAP_NO_DROP.sh` — the stale NOTE claims stats reset on apply; reality is D-3.1-4 preserves via bpf_map__reuse_fd. Rewrite NOTE to match documented contract: "stats counters PRESERVED across apply per §5.26 D-3.1-4 reuse_fd loop". ~3 LOC.

### Item HK-13 — Orphan map pins from T_ATTACH_TAG_MISMATCH cleanup
**Where**: EDIT `tests/T_ATTACH_TAG_MISMATCH.sh` — fixture's `bpftool prog load` runs without `pinmaps`, leaving orphan map pins at bpffs root. Add explicit cleanup in trap. ~5 LOC.

### Item HK-14 — §6.25 step 8 grep for "replacing existing program" stderr
**Where**: EDIT `tests/T_LINK_PERSIST_ACROSS_LOADER_EXIT.sh` (or wherever §6.25 step 8 is enforced — check current location) — add an assertion that the reattach path emits the documented stderr substring. Architect MAY confirm whether design's "explicit impl-shape flexibility" comment means this should remain unasserted (skip if so). ~5 LOC if added.

### Item HK-15 — `cli.hpp` ParsedAttach wrapper design-text inaccuracy
**Where**: EDIT `mint/design.md` — remove or rewrite the §5.26 prose claiming `ParsedAttach`/`ParsedDetach`/`ParsedApply` wrappers exist. Reality (verified in MVP-3.4): they never existed; `ParsedCommand` is a `std::variant<AttachConfig, DetachConfig, ApplyConfig, BypassConfig>` directly. Pure design-text cleanup. ~10 LOC.

### Item HK-16 — PI-32 startup WARN — implement per design (per HG-3.4.5-1 + Q2)
**Where**: NEW one-shot check in `src/exporter/main.cpp` (or `src/exporter/stats_reader.cpp` if architect prefers — Phase B dialog if unclear): at exporter startup, `std::filesystem::exists(cfg.bpffs_root)` — if false, emit `xdpmf-exporter: WARN bpffs root <path> does not exist; will serve empty metrics` to stderr once, then continue normally (no abort). EDIT `tests/T_EXPORTER_NO_ATTACHED_IFACE.sh` — add assertion grep'ing for the WARN substring (use `script -qc` or temp-redirected stderr file). ~10 LOC impl + ~5 LOC test. PI-32 design text unchanged (impl now matches it).

### Item HK-17 — Exporter exit-6 — implement per design (per HG-3.4.5-2 + Q3)
**Where**: architect amends `mint/design.md §5.29` exporter exit-codes table to specify the explicit trigger condition (default per Q3 E1: ALL discovered ifaces fail EACCES/EPERM with non-empty discovered set). EDIT `src/exporter/stats_reader.cpp` (or `main.cpp` depending on where the discovery-result is observable) — track total-discovered vs total-EACCES counters; if discovered>0 AND EACCES==discovered AND successes==0, exit 6 from main(). EDIT `src/exporter/main.cpp` — add exit code constant `kExitPermissionDenied = 6` (or follow loader's enum-pattern). NEW ctest `T_EXPORTER_EXITS_6_ALL_IFACES_EACCES.sh` — create per-iface bpffs dirs with `chmod 000` (requires root + ability to make EACCES reproducible — SKIP-77 if not), launch exporter, assert exit 6 within healthz timeout. ~25 LOC impl + ~40 LOC test (incl. SKIP-77 fallback if test env can't produce EACCES).

## Out of scope (explicit)

- **Documentation work** (README rewrite, FLEET_DEPLOYMENT.md update, docs/CONFIG_SCHEMA.md, HANDOFF.md move, xdpmf-exporter section, ansible Jinja `action: pass`, ansible `xdpfilter_trust_model` template task) — separate manual pass, not in this brief.
- **Per-rule counters / inner-allowlist-value extension** — still MVP-3.4b. PI-13-3.4 / PI-27 strictly preserved.
- **JSON structured logs** — MVP-3.5.
- **sFlow** — MVP-3.6 (conditional).
- **Library extraction `libxdpmf.so.0`** — MVP-3.6+ optional.
- **Daemon `xdpmfd`** — MVP-3.6+ optional.
- **Binary rename `xdpmacfilter` → `xdpfilter`** — still MVP-3.12.
- **Systemd sandbox directives** (ProtectSystem strict, PrivateTmp, etc. — security M3 from review) — defense-in-depth scope; not minimal-fix housekeeping. Deferable to MVP-3.5 or dedicated security cycle.
- **`std::format_to` / writev microopts** in exporter (perf M1-M4) — performance scope; not contract-drift housekeeping.
- **TSAN build** (testing H2) — coverage scope; not housekeeping. Deferable.
- **CO-RE field-probe failure test** (testing L3) — known coverage gap; not housekeeping.
- **L4 ports / VLAN / IPv6 CIDR** — still fenced per MVP-3.2 §7 OOS.

## Definition of done

- `§5.30 MVP-3.4.5: housekeeping` amendment in `design.md` documenting HK-1..HK-17 + Q1-Q6 decisions + HG-3.4.5-1/2/3/4 confirmation; cross-references to `/agent-teams-review/.../report.md` for rationale.
- New `§6.x TestStrategy` entries for 2-3 new ctests.
- `§6.5 Preserved invariants` extended: PI-1..PI-34 hold; PI-7-3.4.5-hpp ZERO diff continues (5th cycle); PI-7-3.4.5-cpp scope-set updated to allow kManagedMaps[] refactor + XDPMF_BPF_OBJECT_PATH compile-gate hunks.
- `loader.hpp` PUBLIC-API UNCHANGED (PI-7-3.4.5-hpp strengthening — ZERO diff continues across 5 cycles).
- `xdpmacfilter --version` reports `xdpmacfilter 0.6.1` (bump from 0.6.0).
- `xdpmf-exporter --version` reports `xdpmf-exporter 0.6.1`.
- `CHANGELOG.md` entry `[0.6.1] - 2026-05-NN`.
- 3-4 new ctests pass; 42 existing ctests still pass (PI-6-3.4.5 = PI-6-3.4 strict superset — including 4 fixed-in-place: T_LINK_PERSIST, T_SYSTEMD_RESTART_ON_FAILURE, T_APPLY_ATOMIC_SWAP_NO_DROP, T_ATTACH_TAG_MISMATCH; + 1 EDIT: T_EXPORTER_NO_ATTACHED_IFACE for HK-16 WARN assertion).
- `XDPMF_SANITIZERS=ON` build clean.
- `mint/review.md` round-1 verdict = `pass` (architect should aim for round-1 pass; this is housekeeping with bounded risk).
- One git commit per phase boundary per workflow B.

## Dependencies

- libbpf (existing); no new build deps.
- Test-time: `script` (for T_BYPASS_INTERACTIVE_PROMPT.sh; util-linux, should be present); OR `expect` (alternative — SKIP-77 if neither available).
- No new C++ libraries. No new BPF features. No new kernel-version dependencies.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       [lang/cpp.md, lang/cmake.md, lang/bpf.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []
```

---

## Doc bucket (NOT in this slice — manual pass, separately)

For user reference — these are the documentation items from `/mint-review` report.md that are EXCLUDED from this slice:

| # | Item | File | Effort |
|---|---|---|---|
| D1 | README path fix + full rewrite for 0.6.0 (doc C1 + C2) | README.md | 1-2 hr |
| D2 | README "Where docs live" table refresh (doc M6) | README.md | 15 min |
| D3 | README cap-set sync (doc M1) | README.md | 5 min |
| D4 | README install line for non-Debian (doc L1) | README.md | 10 min |
| D5 | README "Inspect counters" exporter path mention (doc L2) | README.md | 5 min |
| D6 | README T_ANSIBLE_PLAYBOOK_SYNTAX skip explanation (doc L3) | README.md | 5 min |
| D7 | docs/CONFIG_SCHEMA.md (doc H4) | docs/CONFIG_SCHEMA.md (NEW) | 2-3 hr |
| D8 | FLEET_DEPLOYMENT.md exporter shipped + alert example (doc H3) | docs/FLEET_DEPLOYMENT.md | 30 min |
| D9 | FLEET_DEPLOYMENT.md xdpmf-exporter section + Prometheus job (doc H5) | docs/FLEET_DEPLOYMENT.md | 1-2 hr |
| D10 | FLEET_DEPLOYMENT.md Bypass operator runbook (doc H6) | docs/FLEET_DEPLOYMENT.md | 2 hr |
| D11 | HANDOFF.md move to mint/ + retitle (doc M5) | HANDOFF.md → mint/dev-workflow.md | 10 min |
| D12 | Ansible xdpfilter_trust_model template task (doc M2) | ansible/xdpmacfilter-deploy.yml | 30 min |
| D13 | Ansible Jinja `action: pass` fix (doc M3) | ansible/templates/xdpfilter-config.yaml.j2 | 5 min |

Total doc bucket: ~8-10 hours sustained writing. Not technical work; user-facing prose discipline.
