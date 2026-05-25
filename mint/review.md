# Review — MVP-3.4 observability exporter + bypass + skeleton (mint triangulation)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 (42/42 — 40 PASS + 2 SKIP, matches tester's run byte-for-byte) | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |
| Out-of-triangulation | 2 | — |

## Triangulation evidence (key checks)

**Point 1 — Spec ↔ Code (signature/contract match):**
- `xdpmf-exporter` binary: 4 .cpp+.hpp pairs present per FileList NEW (`src/exporter/main.cpp:109..162`, `http.cpp:232..309`, `prom_format.cpp:51..72`, `stats_reader.cpp:108..157`). Routes `/metrics`, `/healthz`, `*→404`, `Content-Type: text/plain; version=0.0.4` (`http.cpp:191`).
- `bypass` subcommand: `src/cli/bypass.cpp:87..141` honours tty-check (`isatty` AND on stdin+stderr, line 101), `--unsafe` gate (102-107), interactive `[y/N]` (111-116), pre-detach audit-log (118-129), `loader::detach()` delegation (134). Reason 256-byte cap with U+2026 (line 36-53).
- `rules` + `action_table` BPF maps DECLARED at `src/bpf/mac_filter.bpf.c:140-170` (NEW `.maps` block only); POPULATED in `src/lib/loader.cpp:1102-1170` (new `populate_rules_skeleton` + `populate_action_table` anon-namespace helpers) called from both fresh-attach (1775-1799) and state-b reattach (1638-1660) paths in `internal::apply_request()`.
- WARN emission: `src/lib/loader.cpp:1430-1437` — fires after `log_trust_model`, before kernel-touch, when `req.config.rules.size() > 0`. Per impl-notes D-3.4-2 it ALSO fires on the `attach --allow` synth path (architect-flagged disposition: design-literal).
- Negotiated deviations both documented: D-3.4-1 (apply_internal.cpp → loader.cpp resolved via §5.29 EDIT-1; `mint/impl-notes.md:343..425`), D-3.4-2 (WARN universal vs synth-suppressed; `mint/impl-notes.md:427..445`).

**Point 2 — Spec ↔ Tests (assertion targets stated outcomes):**
- §6.37 → `tests/T_EXPORTER_METRICS_FORMAT.sh:188-224` — asserts HELP/TYPE/sample EREs verbatim; PI-33 smoke (line 95-102).
- §6.38 → `tests/T_EXPORTER_VALUES_MATCH_STATS.sh:197-201` — strict per-verdict equality vs `read_stats.py`, not function shape.
- §6.39 → `tests/T_EXPORTER_NO_ATTACHED_IFACE.sh:131-176` — graceful empty (HELP+TYPE only, 0 samples, alive across two requests).
- §6.40 → `tests/T_BYPASS_CMD_DETACHES.sh:81-100` — audit-line ERE + XDP detached + link pin removed; sub-case at 129-133 covers `UNSPECIFIED` default.
- §6.41 NEGATION CONTROL → `tests/T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE.sh:85-121` — non-tty without `--unsafe` MUST exit 1 + XDP still attached. Explicit fail-open regression guard.
- §6.42 LOAD-BEARING DEFER → `tests/T_RULES_SKELETON_NOT_WIRED.sh:223-300` — direct map-dump approach (architect-preferred): rules+action_table populated AND drop-MAC ABSENT from active inner allowlist; assertion (fC) at 294-299 cites BOTH the PI-29 violation AND the PI-27/PI-13-3.4 violation in the diagnostic.
- Negation control coverage: T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE explicitly named as such + T_NEGATION_CONTROL (baseline) still green.

**Point 3 — Code ↔ Tests:**
- Re-ran `cd /home/user/mint-l2-mac-filter/build && ctest --output-on-failure -j$(nproc)` independently → 42/42 entries; 40 PASS + 2 SKIP. Matches tester's `test-run.log` byte-for-byte. Log: `/tmp/mint-review-tests-mvp34-1779667370.log`.
- UNEXERCISED-EXPORT spot-check: all new exports reachable from binary surface that ctest exercises. No dead exports.

**Point 4 — Out-of-Scope Drift:**
- `grep -nE 'bpf_map_lookup_elem\(\s*&?(rules|action_table)\W' src/bpf/mac_filter.bpf.c` → ZERO matches. Datapath does NOT consult either new skeleton map. `mac_filter_prog` body lookups (lines 174..253) untouched: `stats`, `active_idx`, `rulesets`, `inner`, `cidr_rulesets`, `cidr_inner`, `defaults`. No `per_rule_counters` / `rule_id` references anywhere in `src/` or `include/`.

**Point 5 — Brownfield invariants (PI-1..PI-34, with focus on PI-27..PI-34 NEW + PI-7-3.4 split):**
- **PI-7-3.4-hpp**: `git diff 7ac2d06 -- src/lib/loader.hpp` = empty. 4th consecutive ZERO-diff cycle. ✓
- **PI-7-3.4-cpp** (regional-diff check): 9 hunks in `loader.cpp`. By enclosing-function classification:
   - hunk @836 (+2 lines): `open_skeleton_only`'s `pinned_maps[]` literal additive 10→12 — allowed per §5.29 EDIT-2 scope (iv). Loop body byte-equivalent.
   - hunk @1102 (+67 lines): NEW anon-namespace helpers — allowed scope (b).
   - hunks @1425, @1556, @1573, @1638, @1698, @1712, @1775 (all inside `internal::apply_request`): step 8.5 WARN, `reuse_specs[]` 9→11, step 8.5 reattach populate, `pin_specs[]` 9→11, step 8.5 fresh-attach populate — all allowed scope (a). ✓
- **PI-10-3.4 / PI-13-3.4 / PI-27**: `mac_filter.h` diff (`src/common/mac_filter.h:93..125`) is pure additive (struct rule_entry, struct action_entry, enum xdpmf_action_type, 2 name macros). Existing constants / inner-value `__u8/unsigned char present` shape byte-equivalent. ✓
- **PI-28**: `mac_filter.bpf.c` single hunk at line 140 (+28 lines) inside `.maps` block only; `mac_filter_prog` function body (lines 181..255) ZERO diff. ✓
- **PI-29**: rules+action_table POPULATED on apply; NOT consulted by datapath (Point 4 grep above). WARN line is operator-facing signature. ✓
- **PI-30**: bypass = detach-alias only. No new BPF map flag; no new XDP verdict; lives entirely in `src/cli/bypass.{cpp,hpp}` (NEW files); invokes `xdpmf::detach()` at bypass.cpp:134. ✓
- **PI-31**: `grep -rE 'bpf_(map_(update|delete)_elem|obj_pin|link_create|link_destroy|xdp_(attach|detach)|prog_load)' src/exporter/` — only comment-line matches (stats_reader.cpp:10-11, documenting the constraint). Zero non-comment matches. ✓
- **PI-32**: §6.39 confirms graceful empty + no crash + alive across two requests. ✓ (See OOT #1 for "additionally logs WARN" sub-clause.)
- **PI-33**: `xdpmacfilter --version` → `xdpmacfilter 0.6.0`; `xdpmf-exporter --version` → `xdpmf-exporter 0.6.0`. ✓
- **PI-34 / PI-6-3.4**: `git diff --stat 7ac2d06 -- tests/T_*.sh` shows 6 NEW files only, ZERO existing test bodies touched. 36 baseline tests strict superset honoured. ✓
- **PI-19 extension**: `systemd-analyze verify systemd/xdpmf-exporter.service` exits 0 with zero stderr.
- **No [UNRELATED-EDIT]**: every "UNCHANGED-BUT-AFFECTED" file in §5.29 FileList confirmed ZERO diff.
- **No [REGRESSION]**: all 34 pre-existing non-skip tests still PASS post-§5.29.

## Test execution

`100% tests passed, 0 tests failed out of 42` — full ctest run, 270.04 sec wall-clock. Two legitimate SKIPs (T_DROP_MALFORMED kernel-pad; T_ANSIBLE_PLAYBOOK_SYNTAX ansible absent — both inherited from prior cycles, neither a regression).

## Out-of-triangulation findings

### [OOT-1] PI-32 "additionally logs ONE warning line at startup" sub-clause not implemented and not asserted
**Location**: `src/exporter/stats_reader.cpp:54-58` (silent ec-return when bpffs root absent) vs `mint/design.md:6792` (PI-32 table cell prose).
**Recommended disposition**: `defer`
**Rationale**: PI-32 core contract (bind+serve+not-crash+stay-alive) honoured + tested; the "additionally" prose attaches an auxiliary operator-friendly hint, not a load-bearing signature. Silent graceful return is arguably MORE conservative than emitting a startup line for a transient bpffs absence in fleet ops. MVP-3.4b housekeeping pickup.

### [OOT-2] Exporter exit-code 6 (permission denied) per §5.29 CLI grammar has no reachable code path
**Location**: `src/exporter/main.cpp:32` declares only `kExitOk`/`kExitUsageErr`; per-iface EACCES/EPERM logged WARN + continue (`stats_reader.cpp:141-145`) — no path returns 6.
**Recommended disposition**: `defer`
**Rationale**: Consistent with PI-32 graceful-continuation preference (partial-permission bpffs state degrades to "scrape returns only the accessible ifaces" rather than crashing the daemon). MVP-3.4b housekeeping — either impl surfaces exit 6 when ALL ifaces fail with EACCES, OR architect retracts the exit-6 row from §5.29 exporter exit codes.

## Notes

Architect's §5.29 EDIT-2 disposition note ("if you flag `open_skeleton_only` diff as [UNRELATED-EDIT] the correct disposition is `inline-merge`") was anticipated; I checked the hunk against the (iv) scope-fence and it qualifies under the EDIT-2 amendment, so no UNRELATED-EDIT raised. Pre-emptive disposition resolution worked cleanly — anti-misdiagnosis guard fires.

Total review wall-clock: ~30 minutes. 5-point brownfield framework all green. Verdict: **pass**.

### Deferred to next slice

Both OOT items deferred to MVP-3.4b housekeeping (verdict pass; neither blocks):
- **OOT-1**: PI-32 startup WARN line for absent bpffs root — design wants it; impl chose silent graceful return; verdict prefers impl choice but design prose remains as written. Pick during MVP-3.4b: either add the WARN (cheap impl ask) or amend PI-32 prose to drop the auxiliary clause.
- **OOT-2**: exporter exit code 6 (permission denied) — declared in §5.29 CLI grammar, no reachable path. Pick during MVP-3.4b: either surface exit 6 when ALL ifaces fail EACCES, or architect retract the row.
