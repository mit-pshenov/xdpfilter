# Task brief — MVP-3.4h: exporter `--bind` non-loopback startup WARN (brownfield, security-observability)

## Goal

Emit a startup WARN line via `xdpmf::logger::emit(Level::Warn, "exporter.warn.bind_non_loopback", ...)` when `xdpmf-exporter` is invoked with `--bind <addr>` resolving to a non-loopback IPv4 address (i.e., NOT in `127.0.0.0/8`). No refusal — operator may have legitimate reason (k8s sidecar mesh, monitoring proxy, fleet-wide remote-scrape pattern); the WARN makes the choice visible in audit logs.

Closes /mint-review 2026-05-27 sec M2 (exporter `--bind` non-loopback no WARN) and the **observability half** of KC-2 kill chain. KC-2 mitigation half (auth/TLS for the exposed `/metrics` endpoint) remains OOS — separate slice.

Mirrors §5.30 HK-16 W1 startup-warn pattern (PI-32 trust-model-flip / bpffs-root-missing logged at startup so fleet-wide divergence is detectable).

**Source of truth**: `/home/user/agent-teams-review/runs/mint-review-mint-l2-mac-filter-202605271147/report.md` (sec M2; KC-2 lines 127-129 + line 144 top-actionable item #10).

## Context: prior work

- All prior briefs: archived in `mint/task-brief-*.md` (28 prior cycles)
- Existing design: `mint/design.md` §5.38 (MVP-3.4g dead-code delete, commit `315a6e7`)
- Architecture doc: `mint/architecture-v2.md` — no row for this slice (security-observability hardening from /mint-review; treat as §5.39 brownfield amendment, mirroring §5.30 / §5.36 / §5.37 / §5.38 hardening precedents)
- Phase A code-grep verification: brief-author ran exhaustive Phase 2 greps (see "Notes for architect Phase A code-grep discipline" footer)
- PI continuity: PI-7-3.4g-hpp 13th + cpp 8th + loader-hpp + mac-filter-h ZERO-diff streaks active post-MVP-3.4g.

**Critical: PI-7-3.4h-hpp streak BREAKS this cycle**. kEventNames catalog at `src/common/logger.hpp:90` (`std::array<std::string_view, 36>`) MUST extend to 37 entries to register the new event-name token — `logger.hpp` cannot stay byte-identical. This carve-out is well-precedented: §5.36 MVP-3.4e also extended kEventNames (35→36) with explicit PI-3.4e-K scoped carve-out. Brief proposes the same shape for §5.39: scoped catalog-extension carve-out at PI-3.4h-K; baseline re-starts post-§5.39 EDIT-point. **PI-7-3.4h-cpp = 9th** + loader-hpp + mac-filter-h streaks continue cleanly.

## Workflow rules (brownfield)

- **Architect**: read §5.30 HK-16 W1 startup-warn precedent (the W1-vs-W2 placement decision; `validate_bpffs_root_or_warn()` helper pattern in stats_reader.cpp:130) + §5.36 PI-3.4e-K kEventNames carve-out precedent + §5.32 (MVP-3.5 logger spec; emit() signature; PI-3.5-1 byte-equivalence for text mode) + §6.5 invariants summary. EDIT design.md in place; append §5.39. Phase A code-grep MUST re-verify parse_bind_addr IPv4-only constraint + sibling exporter.bind.* events placement.
- **Impl**: FileList interpretation per brownfield mode — strict in-scope EDIT on `src/exporter/http.cpp` (WARN emission) + `src/common/logger.hpp` (kEventNames +1 entry + 2 sub-comment counts) + `tests/fixtures/log_events_v1.txt` (+1 alphabetical line); NEW `tests/T_EXPORTER_BIND_NON_LOOPBACK_WARN.sh` + EDIT `tests/CMakeLists.txt` (+15 LOC add_test block). NO touch to UNCHANGED-BUT-AFFECTED files (3 PI-7 fence paths minus logger.hpp).
- **Tester**: 1 NEW ctest target. Existing ctests stay green by construction (PI-3.4h-1 byte-equivalence on default --bind=127.0.0.1 paths; existing T_LOG_JSON_EXPORTER_EVENTS may need fixture-cross-reference EDIT if it pins kEventCount or sub-counts — Phase 2 grep flags this for architect re-check).
- **Reviewer**: 5-point brownfield framework. Special attention items: (a) PI-3.4h-K scoped carve-out rationale citation in §5.39; (b) PI-7-3.4h-cpp + loader-hpp + mac-filter-h ZERO-diff fences (3 paths, NOT 4 this cycle); (c) NEW ctest exercises BOTH loopback (negation control) AND non-loopback (positive) cases; (d) text-mode WARN line shape matches `xdpmf-exporter: WARN ...\n` convention per guard #19; (e) kEventNames alphabetical placement of `exporter.warn.bind_non_loopback` (slots before `exporter.warn.bpffs_root_missing` since `bi` < `bp`).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-3.4h-1: PI-7-3.4h-hpp scoped carve-out for kEventNames extension → **YES, mirror §5.36 PI-3.4e-K precedent**

13-cycle PI-7-hpp ZERO-diff streak ends here by necessity — kEventNames catalog is the canonical event-name registry, and adding a NEW emit-site REQUIRES a catalog extension per guard #10. Architect documents new `PI-3.4h-K` (kEventNames-extension-only carve-out: ONE +1 entry + size literal 36→37 + 2 sub-comment counts) in §6.5; reviewer's framework point 5 walks the carve-out instead of asserting full byte-identical. Baseline re-starts post-§5.39 EDIT-point so future cycles (§5.40+) extend a new PI-7-3.4i-hpp streak from 1.

### HG-3.4h-2: loopback detection scope → **127.0.0.0/8 entire range, numerical post-parse check**

Detection logic: after `parse_bind_addr(cfg.bind_addr, bind_inaddr)` succeeds in `http.cpp::run()`, check `(bind_inaddr.s_addr & htonl(0xff000000)) == htonl(0x7f000000)`. Anything in 127.0.0.0/8 (kernel loopback range) is NOT WARN-worthy; everything else (including 0.0.0.0 wildcard, RFC1918 private, public IPv4) is. NOT just exact 127.0.0.1 — operators legitimately use 127.0.0.2 / 127.1.0.1 / etc. for sidecar separation. IPv6 `::1` and string-literal "localhost" are OOS (parse_bind_addr is IPv4-only via `inet_pton(AF_INET, ...)`; "localhost" gets rejected with existing `exporter.bind.invalid_addr`).

### HG-3.4h-3: new kEventNames entry token → **`exporter.warn.bind_non_loopback`**

Slots alphabetically in log_events_v1.txt BEFORE `exporter.warn.bpffs_root_missing` (since `bi` < `bp`). In logger.hpp:90-130 array, slots within the "exporter (xdpmf-exporter)" sub-comment group between `exporter.bind.listen_failed` and `exporter.listening` (alphabetical within group) OR at end of `exporter.warn.*` cluster — architect's tactical D-decision.

### HG-3.4h-4: NO refusal — WARN-only posture → **CONFIRMED**

Emit warn + continue normal startup. KC-2 mitigation half (auth/TLS for `/metrics`) explicit OOS — separate slice. Refusal would break legitimate fleet-ops use cases (k8s sidecar mesh) without operator opt-in.

### HG-3.4h-5: NO VERSION bump → **CONFIRMED**

Pure observability addition; no operator-observable API change (default --bind=127.0.0.1 keeps current silent behavior; only non-loopback bind triggers new line). Architect overrides only if KC-2 mitigation also lands same cycle (it won't — explicit OOS).

## Open mechanism questions (architect decides; document in §5.39)

### Q1: WARN emission placement — main.cpp helper (Option A) vs http.cpp::run() post-parse (Option B)?

- **A**: helper called from `main()` after cmdline parse, BEFORE `http::run()`. Matches §5.30 HK-16 W1 precedent (`validate_bpffs_root_or_warn` shape). Uses `cfg.bind_addr` STRING; loopback check string-based (case-insensitive prefix match for `127.`). Fail-fast: warns before socket() syscall.
- **B**: inside `http.cpp::run()` AFTER `parse_bind_addr(cfg.bind_addr, bind_inaddr)` succeeds, BEFORE `::socket()`. Sibling to existing `exporter.bind.*` events at http.cpp:288-330. Uses parsed `struct in_addr`; loopback check numerical `(s_addr & htonl(0xff000000)) == htonl(0x7f000000)`. Cleaner per architect spec sub-rule "where is X executed per-runtime".
- **Recommendation**: **B**. Per-runtime correctness; numerical loopback check is robust (string-prefix `"127."` misses edge-cases like trailing whitespace OR matches non-loopback "127a.b.c.d"); same TU as siblings simplifies code review + future maintenance. If architect flips to A, the brief accepts — both options satisfy HG-3.4h-2 contract; only the helper-location + check-mechanism differ.

### Q2: text-mode WARN message shape — D-decision territory

Architect picks at Phase A per guard #19. Reference shape (NOT contractual): `"xdpmf-exporter: WARN: --bind <addr> is not loopback (127.0.0.0/8); /metrics will be exposed on a routable interface\n"`. JSON-mode envelope is automatic per logger.hpp Q1=A1 structured field shape (`bind_addr` field).

## Scope (cycle MVP-3.4h — concrete items)

### Item E-1 — EDIT `src/exporter/http.cpp` (Option B default per Q1) — WARN emission

**Where**: `src/exporter/http.cpp` (current 17501 bytes; `run()` entry @:288; `parse_bind_addr` @:261)
Diff (if Q1.B):
- ADD `is_loopback_ipv4()` static helper (~5 LOC) — takes `struct in_addr`, returns `bool`; bitmask check 127.0.0.0/8 per HG-3.4h-2.
- ADD WARN emission block after `parse_bind_addr()` success at run() entry, BEFORE `::socket()` call. ~20 LOC: `if (!is_loopback_ipv4(bind_inaddr)) { ... logger::emit(...Warn, "exporter.warn.bind_non_loopback", msg, fs); }`. Includes structured field `bind_addr` (matches sibling `exporter.bind.*` field shape).
- Net LOC: ~+25 in http.cpp.

If Q1.A picked, swap to main.cpp + helper file/path; mechanism otherwise unchanged.

### Item E-2 — EDIT `src/common/logger.hpp` (PI-3.4h-K scoped carve-out)

**Where**: `src/common/logger.hpp:90-132`
Diff:
- Update array size literal: `std::array<std::string_view, 36>` → `std::array<std::string_view, 37>` at :90.
- ADD ONE new entry `"exporter.warn.bind_non_loopback",` alphabetically placed within the "exporter (xdpmf-exporter)" sub-comment cluster — architect picks exact position (between `exporter.bind.listen_failed` + `exporter.listening` OR among `exporter.warn.*` group).
- Update exporter sub-comment at :114 `15 events` → `16 events`.
- Update kEventCount comment at :132 from `// = 36 (§5.36: 35 → 36; +1 sidecar.warn.iface_dir_symlink per HG-3.4e-4)` to mirror new shape: `// = 37 (§5.39: 36 → 37; +1 exporter.warn.bind_non_loopback per HG-3.4h-3)`.
- Net LOC: ~+3 (1 new entry + 2 count adjustments).

### Item E-3 — EDIT `tests/fixtures/log_events_v1.txt` (guard #13 fixture lockstep)

**Where**: `tests/fixtures/log_events_v1.txt` (current 36 lines, alphabetical)
Diff: ADD one line `exporter.warn.bind_non_loopback` slotted alphabetically BEFORE `exporter.warn.bpffs_root_missing` (since `bi` < `bp`). Net +1 LOC.

### Item T-1 — NEW `tests/T_EXPORTER_BIND_NON_LOOPBACK_WARN.sh`

**Where**: `tests/T_EXPORTER_BIND_NON_LOOPBACK_WARN.sh` (NEW)
Body (high-level — impl/tester picks exact shape):
- **PRIMARY** (positive): launch `xdpmf-exporter --bind 0.0.0.0 --port <ephemeral>` (background); poll for "listening" emit; assert stderr contains `WARN.*bind.*not.*loopback` regex OR `exporter.warn.bind_non_loopback` event-name in JSON mode; kill exporter.
- **NEGATION** (default loopback): launch `xdpmf-exporter --port <ephemeral>` (default --bind=127.0.0.1); poll for listening; assert stderr does NOT contain bind_non_loopback WARN regex; kill.
- **Sub-case** (127.0.0.0/8 non-default loopback): launch `xdpmf-exporter --bind 127.0.0.2 --port <ephemeral>`; assert NO WARN (127.0.0.0/8 covers entire range per HG-3.4h-2).
- RESOURCE_LOCK: `exporter_port_9417` (port-clash serialization with sibling exporter tests; mirror `T_EXPORTER_NO_ATTACHED_IFACE` shape at tests/CMakeLists.txt:657). xdp_fixture lock NOT required (no veth/loader interaction).
- SKIP: passwordless sudo (exporter doesn't need sudo for self-test; but mirror project convention for consistency — architect picks).

### Item E-4 — EDIT `tests/CMakeLists.txt` — add_test block

**Where**: `tests/CMakeLists.txt`
Diff: ~+15 LOC `add_test(...) + set_tests_properties(... RESOURCE_LOCK exporter_port_9417 TIMEOUT 60 SKIP_RETURN_CODE 77)` block, mirroring `T_EXPORTER_NO_ATTACHED_IFACE` shape.

### Item T-EXISTING — UNCHANGED-BUT-AFFECTED ctest carve-out

**Where**: §6.5 invariants block in design.md §5.39
List existing tests that touch kEventNames or exporter startup as UNCHANGED-BUT-AFFECTED zero-diff fence:
- `T_LOG_JSON_EXPORTER_EVENTS.sh` — consumes kEventNames indirectly via JSON envelope assertions; verify Phase A grep — does it pin kEventCount (36) or full count? If yes, +1 EDIT needed; if no, byte-equivalent.
- Existing exporter ctests (`T_EXPORTER_*`) — default --bind=127.0.0.1 path stays silent per HG-3.4h-2; ZERO regressions.

Reviewer point 5 confirms zero diff via `git diff` against prior cycle baseline.

## Out of scope (explicit)

- **KC-2 mitigation half (auth/TLS for `/metrics`)** — separate slice; explicit OOS. This slice closes observability gap ONLY.
- **IPv6 `::1` loopback detection** — parse_bind_addr is IPv4-only via inet_pton(AF_INET); IPv6 binding explicitly OOS per existing http.cpp:260 comment. NEW FENCE.
- **String-literal "localhost" detection** — parse_bind_addr rejects "localhost" with existing `exporter.bind.invalid_addr`; no WARN needed (different error class). NEW FENCE.
- **Rate-limiting the WARN** — one-shot startup emission; no per-scrape repetition needed (mirrors W1 HK-16 design). NEW FENCE.
- **REFUSAL on non-loopback** — operator legitimate reasons exist; WARN-only per HG-3.4h-4. NEW FENCE.
- **VERSION bump** — pure observability addition; no operator-observable API change. NEW FENCE.
- **README / fleet-ops docs update** — minimal CHANGELOG entry (1 line under Security section in [Unreleased]) is the only doc touch; README updates are part of B1 doc-backlog slice. NEW FENCE.
- **Other /mint-review backlog items** (KC-1 escape-action-label-defensive, Theme D dispatch_match helper, perf compound, TUN/TAP injector, CI/CD) — all separate slices.

## Definition of done

- §5.39 amendment in `mint/design.md` (estimated ~120-180 LOC: scope + HG/Q resolutions + D-decisions + FileList table + PI block including PI-3.4h-K carve-out + OOS block + Phase A grep notes)
- PI continuity:
  - PI-3.4h-K NEW (scoped kEventNames-extension carve-out for logger.hpp; mirrors §5.36 PI-3.4e-K)
  - PI-7-3.4h-cpp = **9th** consecutive ZERO-diff on `src/lib/config.hpp`
  - PI-7-3.4h-loader-hpp + PI-7-3.4h-mac-filter-h extensions
  - PI-3.5-1 byte-equivalence text-mode emissions preserved (new WARN follows existing emit() shape)
  - PI-32-3.4b sidecar-never-throws preserved (no sidecar changes)
- ctest baseline: 67 → 68 (+T_EXPORTER_BIND_NON_LOOPBACK_WARN)
- CHANGELOG.md `[Unreleased]` Security subsection: +1 line entry for §5.39 / sec M2 closure
- mint/review.md round-1 verdict = pass
- One git commit per phase boundary

## Dependencies

- C++23 stdlib (`<arpa/inet.h>` already included via `<netinet/in.h>` in http.cpp; `htonl` for bitmask)
- No CMake changes (escape_util already wired; logger.hpp is header-only)
- No kernel/platform deps
- No external BPF/libbpf changes

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       []
  tester:     []
  reviewer:   []
```

---

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])

- **Multi-axis design space?** No. One mechanism axis (Q1 placement A vs B); answer falls out of per-runtime-correctness rule.
- **Brief-author uncertain across ≥2 axes?** No. /mint-review prescribes resolution + §5.30 HK-16 + §5.36 kEventNames-extension precedents both apply directly.
- **Expensive to undo?** No. Pure observability addition + 1 NEW ctest; rollback = revert single commit.
- **≥3 distinct viable options?** No. WARN emission is the one viable mechanism per /mint-review signal.
- **Mechanical-answer check**: ✓ yes — extension of established precedent.
- **Has /mint-hld been run?** No — not needed.
- **Brief-author overconfidence flag**: ⚠ initial brief invocation had 2 wrong claims (LOC estimate 3x too low; PI-7-hpp 14th streak target impossible). Phase 2 grep corrected both. Architect repeats Phase 2 greps per guard #5.

**Verdict**: mechanical extension; `/mint-hld` overkill. Proceed with `/mint-dev`.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief-author already ran these greps per Phase 2 — architect re-verifies + extends:

1. **Confirm Q1 placement**:
   - `grep -nE 'parse_bind_addr|run\(const HttpConfig' src/exporter/http.cpp` — should match :261 parse_bind_addr + :288 run() entry.
   - `grep -nE 'cfg\.bind_addr|consume_flag_value.*bind' src/exporter/main.cpp` — :140 default + :177-178 parse loop.
   - Verify Option B is the per-runtime-correct placement vs Option A per spec sub-rule.

2. **Confirm sibling exporter.bind.* event shape + Field schema**:
   - `grep -nE 'exporter\.bind\.|exporter\.warn\.' src/exporter/ src/common/logger.hpp | head -20` — observe field-name conventions; new emit must match (`bind_addr` field name, std::string_view type, etc.).

3. **Confirm kEventNames catalog position**:
   - `grep -nE 'exporter\.warn\.bpffs_root_missing|exporter\.warn\.cpu_count_invalid' src/common/logger.hpp` — slot new entry alphabetically in the cluster.

4. **PI-3.4h-K carve-out fence smoke (pre-commit)**:
   - `git diff 315a6e7..HEAD -- src/common/logger.hpp` MUST show EXACTLY: +1 entry, size literal 36→37, 2 sub-comment count updates. No other changes (no struct edits, no Field type changes, no emit() signature changes). Architect documents fence in §5.39 PI block.

5. **Test fixture cross-reference (guard #13)**:
   - `grep -nE 'kEventCount|kEventNames' tests/` — find tests that pin the catalog count. If `T_LOG_JSON_EXPORTER_EVENTS.sh` or `T_LOG_JSON_ENVELOPE_INVARIANTS.sh` asserts exact kEventCount=36, +1 EDIT body adjustment needed.
   - `grep -c '^' tests/fixtures/log_events_v1.txt` — currently 36; will become 37 post-impl. Alphabetical placement verified by reviewer.

6. **RESOURCE_LOCK for NEW ctest (guard #12)**:
   - `grep -nE 'RESOURCE_LOCK.*exporter_port|T_EXPORTER_NO_ATTACHED_IFACE' tests/CMakeLists.txt` — confirm precedent shape at :657; mirror for NEW ctest.

7. **Text-mode prose vs event-name convention (guard #19)**:
   - `grep -nE '"xdpmf-exporter: WARN' src/exporter/` — observe existing prose convention; new WARN follows verbatim shape.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep)**: ✓ applies; architect repeats brief-author's Phase 2 greps independently. Phase 2 caught 2 brief-invocation errors (LOC undercount + PI-7-hpp 14th streak impossibility) — guard discipline pays off again.
- **Guard #8 (interactive-vs-log distinction)**: ✓ trivially — exporter daemon; no UI primitive surface. NEW emit is unambiguously log-class.
- **Guard #10 (catalog arithmetic)**: ✓ **LOAD-BEARING** — kEventNames 36→37 with size literal + sub-comment + fixture lockstep. Architect MUST cite §5.36 PI-3.4e-K precedent in §5.39 D-decision for PI-3.4h-K scoped carve-out.
- **Guard #11 (VERSION-bump test-literal propagation)**: N/A — no VERSION bump (per HG-3.4h-5 + §7 OOS).
- **Guard #12 (RESOURCE_LOCK for shared host state)**: ✓ NEW ctest needs `exporter_port_9417` lock (mirror tests/CMakeLists.txt:657 precedent). NO xdp_fixture lock needed (no veth interaction).
- **Guard #13 (fixture cross-reference)**: ✓ `tests/fixtures/log_events_v1.txt` +1 alphabetical line. Reviewer point 5 grep-checks alphabetical placement.
- **Guard #19 (logger text-mode prose vs event-name token convention)**: ✓ text-mode WARN prose follows `xdpmf-exporter: WARN: ...\n` precedent; event-name token follows `exporter.warn.*` cluster convention.
- **Guards #17 / #18 / #20 / #21**: N/A — no bilateral invariants, no host-vs-netns, no rule-of-three trigger, no NEW test IO-model.

**Operative-semantic discipline reminder (Phase 4.4)**: counts in this brief (~25 LOC E-1; +3 LOC E-2; +1 LOC E-3; ~80-120 LOC T-1; +15 LOC E-4; net ~+120-160 LOC) are SHOULD-level orientation, not contracts. Impl deviations on those (different LOC delta, different position in catalog cluster, different ctest sub-case count, different text-mode prose shape per guard #19) are `inline-merge` per design's resolution rule. Architect SHOULD explicitly include the prose-vs-invariants conflict resolution rule in §5.39 per [[mint-human-gate-self-approve]] + §5.37/§5.38 precedent.
