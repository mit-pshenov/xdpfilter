# Task brief — MVP-3.4f: extract `src/common/escape_util.{hpp,cpp}` + extend audit-escape policy (brownfield, code-quality + security-hardening)

## Goal

Consolidate the three Theme B duplicated helpers (`json_escape`, `escape_audit_value`, `format_timestamp_utc`) from `src/common/logger.cpp` + `src/lib/sidecar.cpp` + `src/cli/bypass.cpp` + `src/cli/reset_counters.cpp` into a NEW shared module `src/common/escape_util.{hpp,cpp}`, AND extend the `escape_audit_value` policy to escape ALL bytes <0x20 + 0x7F as `\xHH` (currently only the 5 named escapes `\\`/`\"`/`\n`/`\r`/`\0` are covered, leaving 0x01-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F passing through raw — sec M1 finding from /mint-review 2026-05-27).

Closes /mint-review 6-dim run Theme B (cross-validated 3-way: sec M1 + arch M2 + CQ M2) and partially closes KC-1 log-injection kill chain (control-char gap). KC-1 fully closes when the companion slice ships the `action label defensive escape` (security L2) — out-of-scope for this brief. KC-2 (exporter --bind non-loopback WARN) is a separate slice.

**Source of truth**: `/home/user/agent-teams-review/runs/mint-review-mint-l2-mac-filter-202605271147/report.md` lines 108-112 (Theme B Resolution) + 127-128 (KC-1) + 143 (top-actionable item #5).

## Context: prior work

- All prior briefs: archived in `mint/task-brief-*.md` (26 prior cycles)
- Existing design: `mint/design.md` §5.36 (MVP-3.4e KC-3 closure, commit `c55f6e5`)
- Architecture doc: `mint/architecture-v2.md` — no row for this slice (out-of-roadmap code-quality + security hardening from /mint-review; treat as §5.37 brownfield amendment, mirroring §5.30 / §5.33 / §5.34 / §5.35 / §5.36 housekeeping/hardening precedents)
- Phase A code-grep verification: brief-author ran exhaustive Phase 2 greps (see "Notes for architect Phase A code-grep discipline" footer); architect repeats independently
- PI continuity: PI-7-3.4e-hpp 11th + PI-7-3.4e-cpp 6th ZERO-diff streaks active. This slice targets **12th + 7th** consecutive ZERO-diff on `src/common/logger.hpp` + `include/xdpmf/config.hpp`. No public-surface touch to `mac_filter.h`. PI-3.5-1 byte-equivalence (text-mode pre-§5.32 emissions) preserved by construction — `json_escape` policy is bytewise UNCHANGED.

## Workflow rules (brownfield)

- **Architect**: read §5.32 D-3.5-2 (origin of helper duplication + guard #9 rationale) + §5.35 D-3.4d-6 (reset_counters DUP-INTENT comment) + §5.36 §7 OOS (where escape_util was explicitly fenced out as deferred) + §6.5 invariants summary. EDIT design.md in place; append §5.37. Phase A code-grep MUST re-verify the 4 helper bodies are byte-identical to each other in pairs (or document any divergence).
- **Impl**: FileList interpretation per brownfield mode — strict additive on UNCHANGED files (logger.hpp, config.hpp, mac_filter.h); regional-diff fences on EDITED .cpp files (only the helper-removal + #include + zero call-site changes).
- **Tester**: NEW ctest(s) target ≥1 (control-char policy evidence per HG-3.4f-3). Existing 5 JSON-shape ctests + audit-line ERE tests stay green by construction (json_escape policy byte-equivalent; escape_audit_value extended-NOT-changed for existing 5 named escapes).
- **Reviewer**: 5-point brownfield framework. Special attention items: (a) guard #9 EXPLICIT OVERRIDE rationale citation in §5.37; (b) PI-7-3.4f-hpp + PI-7-3.4f-cpp + PI-7-3.4f-mac-filter-h ZERO-diff fences; (c) NEW ctest exercises ALL extended bytes (not just one sample); (d) byte-equivalence of remaining 5 named escapes preserved for backward-compat with T_LOG_JSON_BYPASS_AUDIT + audit-line ERE tests.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-3.4f-1: extended `escape_audit_value` policy form → **keep 5 named + add `\xHH` (lowercase) for the rest**

Existing audit-line escape policy at `bypass.cpp:48-67` (DUP at `reset_counters.cpp:55-74`) covers ONLY `\\` `\"` `\n` `\r` `\0` via the switch's named cases; all other bytes (including 0x01-0x08, 0x0B-0x0C, 0x0E-0x1F, 0x7F) fall through `default` and emit raw. Extended policy: keep the 5 named escapes EXACTLY (preserves byte-equivalence with T_LOG_JSON_BYPASS_AUDIT step (i) + all audit-line ERE assertions); add an inner conditional in `default` for `c < 0x20 || c == 0x7F` → `\xHH` lowercase. Rationale: (a) audit-line is plain-text-mode emission (NOT JSON), so `\xHH` C-style escape matches operator-readable convention; (b) lowercase hex matches `json_escape`'s `\u00xx` format already in use at logger.cpp:82; (c) preserves backward-compat with existing 5 named escapes used in audit-line tests. Architect may flip to "all <0x20 + 0x7F → `\xHH` uniform" if they see a reason — but default = backward-compat preserving.

### HG-3.4f-2: PI-7-3.4f ZERO-diff fence → **YES, preserve streak**

`src/common/logger.hpp` + `include/xdpmf/config.hpp` + `src/common/mac_filter.h` all UNTOUCHED. The new escape_util has its OWN header (`src/common/escape_util.hpp`); logger.cpp + sidecar.cpp + bypass.cpp + reset_counters.cpp `#include "escape_util.hpp"` and drop their local helper defs. Result: PI-7-3.4f-hpp = **12th consecutive ZERO-diff** (extending PI-7-3.4e-hpp's 11-streak); PI-7-3.4f-cpp = **7th consecutive** for config.hpp (extending 6-streak). Architect may carve out if a deeply pragmatic reason surfaces — but the default is strong: this streak is the strongest in project history per session handoff memory.

### HG-3.4f-3: NEW ctest for extended-policy operational evidence → **YES, at least ONE**

Sec M1 closure needs operational evidence. At minimum ONE NEW ctest exercises the extended-policy bytes (e.g., `xdpmacfilter bypass --iface IFACE_A --unsafe --reason $'\x01\x07\x1f\x7f'` → stderr audit-line contains `\x01\x07\x1f\x7f` literal). Shape choice (impl/tester): pure-unit-test of `escape_util::escape_audit_value()` directly (preferred — no veth needed; no RESOURCE_LOCK; ~30-50 LOC bash invoking a small C++ test harness OR exit-code via xdpmacfilter subcommand) vs full integration test via real bypass (heavy; needs xdp_fixture lock per guard #12). Architect picks; default = at least ONE NEW ctest, shape flexible. Existing 5 JSON-shape ctests + audit-line ERE tests need NO body edits (escape_util preserves prior policies for those bytes).

### HG-3.4f-4: explicit guard #9 OVERRIDE → **YES, with rule-of-three rationale citation in §5.37**

§5.37 MUST explicitly cite §5.32 D-3.5-2's guard #9 ("helper-location duplication-over-extraction; prefer duplication of small <100 LOC helpers in brownfield slices") and explain why THIS slice escapes it: rule-of-three trigger — 6 duplicate function bodies × 4 modules (`json_escape` × 2 + `escape_audit_value` × 2 + `format_timestamp_utc` × 2) total ≈80 LOC of duplication. /mint-review Theme B cross-validation across 3 independent dimensions (security + architecture + code-quality) is the operational signal that the rule-of-three line has been crossed. Architect documents this as a §5.37 D-decision (e.g., `D-3.4f-1 — guard #9 escape valve via rule-of-three`).

## Open mechanism questions (architect decides; document in §5.37)

### Q1: scope of consolidation — include `format_timestamp_utc` OR carve out?

- **A1**: include `format_timestamp_utc()` in `src/common/escape_util.{hpp,cpp}` alongside the 2 escape helpers (one cycle, one file, ~10-15 extra LOC).
- **A2**: defer `format_timestamp_utc` to a separate `src/common/time_util.{hpp,cpp}` carve-out (cleaner semantic separation; second cycle of effort).
- **Recommendation**: **A1**. Same D-3.5-2 source duplication; same Theme B cluster framing; consolidates the 3 Theme B helpers in one pass. Module name `escape_util` is mildly inaccurate (timestamp ≠ escape) but the alternative is shipping the same refactor twice. Naming alternatives if A1: rename module to `xdpmf::common::format_util` OR `xdpmf::common::log_helpers` (architect's call at Phase A — D-decision territory). If architect prefers A2, brief accepts; the carve-out is shippable in the same cycle if scope still fits.

### Q2: extended-byte escape notation — `\xHH` vs `\u00HH`?

- **A1**: `\xHH` (C-style; 4 chars per escape). The /mint-review report cites this verbatim ("escape all bytes <0x20 + 0x7F as `\xHH`").
- **A2**: `\u00HH` (RFC 8259 / JSON Unicode escape; 6 chars per escape; matches `json_escape`'s policy internal at logger.cpp:82).
- **Recommendation**: **A1**. Audit-line is text-mode emission via stderr prose, NOT JSON. Mixing JSON-syntax escapes in text-mode log lines confuses operators (especially when grepping audit-line ERE). The two policies stay SEPARATE: `json_escape` continues to use `\u00xx` for JSON envelopes; `escape_audit_value` uses `\xHH` for text-mode audit prose. PI-3.5-1 byte-equivalence preserved (those 5 named escapes are byte-identical in both before/after).

### Q3: namespace + header naming (D-decision territory; architect picks at Phase A)

- Options: `xdpmf::escape_util` (matches /mint-review prescription); `xdpmf::common::escape`; `xdpmf::common::strings`; `xdpmf::common` (if format_util consolidated per Q1.A1).
- Architect resolves via Phase A grep + style consistency with existing `xdpmf::logger` (logger.hpp:28) and `xdpmf::internal` (apply_internal.hpp).

## Scope (cycle MVP-3.4f — concrete items)

### Item E-1 — NEW `src/common/escape_util.hpp`

**Where**: `src/common/escape_util.hpp` (NEW)
Public surface:
- `[[nodiscard]] std::string escape_json(std::string_view raw)` — moved verbatim from logger.cpp:68-94 / sidecar.cpp:93-119 (RFC 8259; `\\` `\"` `\n` `\r` `\t` `\b` `\f` + `\u00xx` for <0x20).
- `[[nodiscard]] std::string escape_audit(std::string_view raw)` — moved + EXTENDED from bypass.cpp:48-67 / reset_counters.cpp:55-74. Policy per HG-3.4f-1: 5 named escapes preserved; ADD `\xHH` (lowercase) for `c < 0x20 || c == 0x7F` in the `default` branch.
- `[[nodiscard]] std::string format_timestamp_utc()` — moved from logger.cpp:49-66 / sidecar.cpp:70-92 (IF Q1.A1).

Naming convention notes: rename `json_escape` → `escape_json` (verb-first; preserves call-site shape `escape_json(x)`); rename `escape_audit_value` → `escape_audit` (verb-first; drops `_value` redundancy). Architect may opt to keep original names if preferred — brief flags rename as recommendation, not contract.

### Item E-2 — NEW `src/common/escape_util.cpp`

**Where**: `src/common/escape_util.cpp` (NEW)
Body: 3 function defs (or 2 if Q1.A2 splits timestamp out). Compiles with C++23. NO new external deps (stdlib `<string>` `<string_view>` `<format>` `<ctime>` only). Approximate size: ~80-100 LOC including comments + the 5-line policy table doc-comment for `escape_audit`.

### Item E-3 — EDIT `src/common/logger.cpp`

**Where**: `src/common/logger.cpp` (current 318 LOC)
Diff:
- `#include "escape_util.hpp"` near top
- DELETE local `format_timestamp_utc()` def at :49-66 (IF Q1.A1) — keep if Q1.A2
- DELETE local `json_escape()` def at :68-94
- REPLACE 5 call-sites: `json_escape(...)` → `xdpmf::escape_util::escape_json(...)` at :149, :191, :197, :205, :216 (5 callers per Phase 2 grep; namespace path TBD by Q3)
- REPLACE 1 call-site: `format_timestamp_utc()` → `xdpmf::escape_util::format_timestamp_utc()` at :183 (IF Q1.A1)
- Net LOC: -40 to -50 (removed defs) + 5-6 namespace-prefix changes (~5 LOC longer total); ~35-45 LOC net reduction in logger.cpp.

### Item E-4 — EDIT `src/lib/sidecar.cpp`

**Where**: `src/lib/sidecar.cpp` (current 521 LOC)
Diff (symmetric with E-3):
- `#include "escape_util.hpp"` (or relative path via `<>`/`""` per project convention)
- DELETE local `format_timestamp_utc()` def at :70-92 (IF Q1.A1)
- DELETE local `json_escape()` def at :93-119
- REPLACE 1 call-site: `json_escape(...)` → `escape_json(...)` at :129
- REPLACE 1 call-site: `format_timestamp_utc()` at :131 (IF Q1.A1)
- Net LOC: -45 to -55 in sidecar.cpp.

### Item E-5 — EDIT `src/cli/bypass.cpp`

**Where**: `src/cli/bypass.cpp` (current 246 LOC)
Diff:
- `#include "escape_util.hpp"` (path relative to src/common/ per `#include "../common/escape_util.hpp"` OR via include-dir if CMake adds src/common as PUBLIC include — architect picks)
- DELETE local `escape_audit_value()` def at :48-67
- REPLACE 2 call-sites: `escape_audit_value(...)` → `escape_audit(...)` at :196, :206
- Net LOC: -20 in bypass.cpp.

### Item E-6 — EDIT `src/cli/reset_counters.cpp`

**Where**: `src/cli/reset_counters.cpp` (current 155 LOC)
Diff (symmetric with E-5):
- `#include "escape_util.hpp"`
- DELETE local `escape_audit_value()` def at :55-74 + the DUP-INTENT comment at :49-54 (now obsolete; replace with brief `// escape via escape_util.hpp` if architect prefers, or no comment)
- REPLACE 1 call-site: `escape_audit_value(...)` → `escape_audit(...)` at :112
- Net LOC: -20 in reset_counters.cpp.

### Item E-7 — EDIT `CMakeLists.txt` (top-level)

**Where**: `CMakeLists.txt` lines 118-119 (xdpmf_internal target) + line 146-147 (xdpmf-exporter target) per Phase 2 grep
Diff: ADD `src/common/escape_util.cpp` to BOTH `xdpmf_internal` and `xdpmf-exporter` source lists (mirroring `src/common/logger.cpp`'s Q6=B1 dup-TU pattern from §5.32). Two 1-line additions; total ~2 LOC. NO change to include-dirs UNLESS architect picks the relative-path `#include` route (then no include-dir change needed) vs the project-wide approach (then add src/common to include path — but project already does this via `${CMAKE_SOURCE_DIR}/src/common/mac_filter.h` extraction at line 68, so the pattern is established).

### Item T-1 — NEW ctest exercising extended-policy bytes

**Where**: `tests/T_BYPASS_AUDIT_CONTROL_CHARS.sh` (NEW) — name impl-flexible
Body (high-level — impl/tester decides exact shape):
- Setup: setup_veth + attach (default mode) on IFACE_A with allow=MAC_GOOD.
- Invocation: `xdpmacfilter bypass --iface IFACE_A --unsafe --reason $'\x01\x07\x1f\x7f literal'` (or pure-unit-test variant calling escape_audit() directly via a tiny test harness binary IF architect prefers; pure-unit shape is preferred — no veth, no RESOURCE_LOCK).
- Assertions: stderr audit-line contains literal `\x01\x07\x1f\x7f` (4 escaped bytes, each as `\x` + 2 hex chars); existing 5 named escapes (`\n`/`\r`/etc.) NOT replaced for sample reason containing newline (preservation check for backward-compat).
- NEGATION control: reason with ONLY printable ASCII → no `\x` sequences in audit-line.
- Shape decision is impl/tester's; brief specifies the policy contract (HG-3.4f-1), not the test mechanics.
- RESOURCE_LOCK (guard #12): IF veth-shape → `xdp_fixture`; IF pure-unit-shape (no veth) → no lock declaration needed.

### Item T-2 — UNCHANGED ctest carve-out attestation

**Where**: §6.5 invariants block in design.md §5.37
List all existing escape-policy-sensitive ctests as UNCHANGED-BUT-AFFECTED zero-diff fence:
- T_SIDECAR_JSON_SHAPE — uses `json_escape` via real loader; output byte-equivalent.
- T_LOG_JSON_LOADER_EVENTS / T_LOG_JSON_EXPORTER_EVENTS / T_LOG_JSON_ENVELOPE_INVARIANTS — JSON envelope tests; byte-equivalent.
- T_LOG_JSON_BYPASS_AUDIT — includes step (i) `has"quote` escape check; byte-equivalent (`\"` is in the 5 named).
- Audit-line ERE tests (T_BYPASS_CMD_DETACHES, T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE, T_CLI_RESET_COUNTERS*, etc.) — audit-line shape byte-equivalent for the 5 named escapes.

Reviewer's point 5 walks each + confirms zero diff in git diff of each test body.

## Out of scope (explicit)

- **KC-1 closure of the OTHER half** (security L2 — action label defensive escape via `kActionLabels`-anchored allowlist instead of raw value). Separate slice; this brief ONLY closes the control-char gap (sec M1).
- **KC-2 (exporter --bind non-loopback WARN)** — separate slice per /mint-review action item #10.
- **Theme C (dead BpffsDir + XdpAttachment delete from raii.hpp)** — separate slice per /mint-review action item #6.
- **Theme D / CQ M1 (dispatch_match helper in mac_filter.bpf.c)** — separate slice per action item #12.
- **xdpmf_logger OBJECT/STATIC lib promotion** (/mint-review action item #13) — NEW FENCE; pure-cosmetic; deferred indefinitely.
- **VERSION bump** — pure refactor + sec hardening; no operator-observable API change; no bump. (Architect overrides if they conclude the extended audit-escape policy IS an observable operator surface needing a 0.10.1 patch bump — defaultable but flag-worthy.)
- **Doc updates** (CHANGELOG.md / README.md / docs/BACKLOG.md cross-out for this item) — minimal CHANGELOG entry SHOULD be added (single-line under MVP-3.4f or §5.37 anchor); README untouched (it's still in CRITICAL backlog state per B1 — separate prose-work slice).
- **Renaming `json_escape` → `escape_json` and `escape_audit_value` → `escape_audit`** is recommended in E-1 but NOT contractual; architect MAY keep originals if preferred — brief defers naming to architect's tactical D-decisions.

## Definition of done

- §5.37 amendment in `mint/design.md` (estimated ~150-250 lines: scope + HG/Q resolutions + D-decisions + FileList tables + PI block + OOS block + Phase A notes)
- PI continuity:
  - PI-7-3.4f-hpp = **12th** consecutive ZERO-diff on `src/common/logger.hpp`
  - PI-7-3.4f-cpp = **7th** consecutive ZERO-diff on `include/xdpmf/config.hpp`
  - PI-3.5-1 byte-equivalence text-mode emissions preserved
  - PI-32-3.4b sidecar-never-throws preserved (escape_util has no throws — pure stdlib `std::string` ops)
  - Existing 5 named escapes byte-equivalent in escape_audit (backward-compat fence)
- ctest baseline: 66 → ≥67 (T-1 NEW; possibly +1 more if architect splits into 2 ctests for veth-vs-unit shapes)
- mint/review.md round-1 verdict = pass
- One git commit per phase boundary

## Dependencies

- C++23 stdlib (`<string>`, `<string_view>`, `<format>`, `<ctime>`) — already required by current logger/sidecar code; no new deps.
- CMake source-list edits in top-level CMakeLists.txt (xdpmf_internal + xdpmf-exporter dup-TU pattern preserved per §5.32 Q6=B1).
- No kernel/platform deps.
- No external BPF/libbpf changes.

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

- **Multi-axis design space?** No. One axis: extract-pattern (chosen) vs status-quo-duplication (rejected by /mint-review).
- **Brief-author uncertain across ≥2 axes?** No. /mint-review report prescribes the resolution verbatim (Theme B → `src/common/escape_util.{hpp,cpp}` + extend policy).
- **Expensive to undo?** No. Pure refactor + additive policy extension; rollback = revert single commit.
- **≥3 distinct viable options?** No. Extract pattern is the one viable option per cross-validated /mint-review signal.
- **Mechanical-answer check**: ✓ yes — answer falls out of /mint-review report's Theme B Resolution prose + rule-of-three trigger met (escape from guard #9 documented).
- **Has /mint-hld been run?** No — not needed. Single-architect `/mint-dev` handles it.
- **Brief-author overconfidence flag**: Phase 2 grep was exhaustive (file/symbol/call-site/test-fixture); architect repeats independently per guard #5.

**Verdict**: this slice is mechanical extension of /mint-review prescription. `/mint-hld` overkill. Proceed with `/mint-dev`.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief-author already ran these greps per Phase 2 — architect re-verifies + extends:

1. **Confirm 4 helper bodies byte-identical in pairs** (or document divergence):
   - `diff <(sed -n '49,66p' src/common/logger.cpp) <(sed -n '70,92p' src/lib/sidecar.cpp)` (format_timestamp_utc)
   - `diff <(sed -n '68,94p' src/common/logger.cpp) <(sed -n '93,119p' src/lib/sidecar.cpp)` (json_escape)
   - `diff <(sed -n '48,67p' src/cli/bypass.cpp) <(sed -n '55,74p' src/cli/reset_counters.cpp)` (escape_audit_value)
   - If any pair diverges, architect documents the divergence as a D-decision + picks the canonical form for escape_util.

2. **Call-site enumeration (exhaustive)**:
   - `grep -rn 'json_escape(' src/ include/` — expect 6 internal callers + 2 defs (8 total grep hits per Phase 2)
   - `grep -rn 'escape_audit_value(' src/ include/` — expect 3 internal callers + 2 defs (5 total)
   - `grep -rn 'format_timestamp_utc(' src/ include/` — expect 2 internal callers + 2 defs (4 total)
   - Architect spot-checks no additional callers were added between brief-time and design-time.

3. **CMakeLists.txt source-list pattern** (Q6=B1 dup-TU mirror):
   - `grep -nE 'logger\.cpp|src/common' CMakeLists.txt` to locate the 2 anchor lines (118 + 146 per Phase 2 grep); confirm escape_util.cpp goes in BOTH; confirm no src/common/CMakeLists.txt subfile exists (it doesn't per Phase 2).

4. **PI-7-3.4f-hpp fence smoke** (pre-commit):
   - `git diff f2122c7..HEAD -- src/common/logger.hpp include/xdpmf/config.hpp src/common/mac_filter.h` MUST be empty after impl + tester complete. Architect documents the fence in §5.37 PI block.

5. **Existing test fixture / regex impact (guard #13 territory)**:
   - `grep -rn 'has\"quote\|\\\\u00\|\\\\x[0-9a-fA-F]' tests/` — Phase 2 confirmed no fixture stores extended-policy literal output; T_LOG_JSON_BYPASS_AUDIT step (i) covers `\"` (preserved by HG-3.4f-1).
   - `grep -rn 'json_escape\|escape_audit_value\|format_timestamp_utc' tests/` — should return NO hits (helpers are internal C++ symbols, not bash-test surface). Confirms zero ctest body EDITs are needed for the refactor itself.

6. **Rename impact (E-1 recommendation)**: IF architect adopts `escape_json`/`escape_audit` rename, run `grep -rn 'json_escape\|escape_audit_value' src/ include/` AFTER edit — must return zero hits. Else (kept original names), no rename grep needed.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep discipline)**: ✓ applies; architect repeats brief-author's Phase 2 greps independently.
- **Guard #9 (helper-location duplication-over-extraction, MVP-3.5-specific)**: ⚠ **EXPLICIT OVERRIDE this slice** — rule-of-three trigger (6 duplicates × 4 modules ≈80 LOC) escapes the brownfield-duplication-preference fence. /mint-review Theme B cross-validation (3 dims) is the documented signal. Architect MUST cite this override in §5.37 as a D-decision (`D-3.4f-1 — guard #9 escape valve via rule-of-three`).
- **Guard #10 (catalogue arithmetic)**: N/A — `kEventNames` (36 entries) UNTOUCHED.
- **Guard #11 (VERSION-bump test-literal propagation)**: N/A — no VERSION bump (per OOS).
- **Guard #12 (RESOURCE_LOCK for shared host state)**: ⚠ conditional — IF T-1 takes veth-shape, `RESOURCE_LOCK xdp_fixture` REQUIRED; IF pure-unit-shape (preferred), no lock needed. Architect's pick at Phase A.
- **Guard #13 (fixture cross-reference for retired strings)**: N/A — no strings retired; policy is additive (existing 5 named escapes preserved).
- **Guards #14–#19**: N/A — netns/map-shape/bilateral-invariant territory; not applicable to pure-refactor + policy-extension slice.

**Operative-semantic discipline reminder (Phase 4.4)**: counts in this brief (~80 LOC duplication; ~10 LOC net reduction; 6 callers; 3 callers; 2 callers) are SHOULD-level orientation, not contracts. Impl deviations on those (different namespace pick, different rename choice, different ctest shape, marginally different LOC reduction) are `inline-merge` per design's resolution rule. Architect documents the operative shape in §5.37; reviewer verifies the shape, not the literal numbers.
