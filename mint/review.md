# Review — MVP-3.4.5 housekeeping (mint triangulation)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 (46/46 pass, 2 legit SKIP-77, 0 fail — matches tester baseline) | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

Plus 1 `[OUT-OF-TRIANGULATION]` informational item (disposition `defer`, see below).

## Triangulation evidence (per point, summarized)

### Point 1 — Spec ↔ Code (all 17 HK items realized + EDIT-1/-2/-3 honoured)

| HK | Spec anchor | Code anchor | Status |
|---|---|---|---|
| HK-1 catch arm | §5.30 Q1 C1; D-3.4.5-5 | `src/cli/main.cpp:128-137` `catch (CliError)`; `src/cli/apply.cpp:60-62` `throw CliError("xdpmacfilter: config error: open ... No such file or directory")` | ✓ exits 1 + preserved stderr prefix (verified live: `apply -f /nonexistent --iface lo` → exit=1) |
| HK-2 --help adds `7 kernel-unsupported` | §5.30 Interfaces | `src/cli/cli.cpp:105-107` | ✓ `--help \| grep -c '7 kernel-unsupported'` == 1 (verified) |
| HK-3 compile-gate `XDPMF_BPF_OBJECT_PATH` | §5.30 D-3.4.5-6 | `src/lib/loader.cpp:105-107` (decl), `:806`, `:874` (`open_skeleton_from_path` body + `#endif`), `:883-895` (consumer); `CMakeLists.txt:93-94, 215-228`; `tests/CMakeLists.txt:16-17` | ✓ all five sites guarded; test build has symbol (`strings ... \| grep -c XDPMF_BPF_OBJECT_PATH` = 4 — expected ≥1 for in-tree build per brief) |
| HK-4 escape + sudo identity | §5.30 D-3.4.5-8 | `src/cli/bypass.cpp:46-89` (`escape_audit_value` + `truncate_reason` with UTF-8 rewind), `:174-181` (audit line `uid=<u> euid=<e> sudo_user="<v>" reason="<r>"` in fixed order; `<none>` sentinel) | ✓ structural fields in fixed order |
| HK-5 6 `unlikely()` wraps | §5.30 Interfaces | `src/bpf/mac_filter.bpf.c:38-40` macro; wraps at `:198, :214, :221, :239, :246, :264` | ✓ exactly 6 wraps (grep returns 7 — 1 macro definition + 6 wraps as design notes line numbers shift slightly post `#define`) |
| HK-6 --unsafe wording + env-var block | §5.30 Interfaces | `src/cli/cli.cpp:99-101` (--unsafe), `:109-113` (env block); `src/exporter/main.cpp:52-56` (env block) | ✓ both binaries get env-var block |
| HK-7 docs install | §5.30 Interfaces | `CMakeLists.txt:203-205` inside `XDPMF_INSTALL_SYSTEMD_UNIT` block | ✓ install path matches systemd unit `Documentation=file:///usr/share/doc/xdpmacfilter/FLEET_DEPLOYMENT.md` |
| HK-8 version 0.6.1 | §5.30 Interfaces | `CMakeLists.txt:13` `VERSION 0.6.1` | ✓ both binaries report `0.6.1` (verified live) |
| HK-9 kManagedMaps[] | §5.30 DataStructures + EDIT-1 (12 entries) + D-3.4.5-3 | `src/lib/loader.cpp:127-158` (table — 12 entries, `SkelMapsT = remove_reference_t<decltype(...)>`); loops at `:907` (open_skeleton_only clear-list), `:1627` (reuse_specs, skip legacy_alias), `:1751` (pin_specs, skip legacy_alias) | ✓ matches design EDIT-1: 11 real + 1 legacy alias; member-pointer T1 form; loops walk same table |
| HK-10 iface-scoped pkill | §5.30 EDITED row | `tests/T_LINK_PERSIST_ACROSS_LOADER_EXIT.sh:51, :117` use `pkill -9 -f "xdpmacfilter.*${IFACE_A}"` | ✓ unscoped `pkill -9 -f xdpmacfilter$` grep returns 0 matches |
| HK-11 internal 2-attempt retry | §5.30 Q5 S1 | `tests/T_SYSTEMD_RESTART_ON_FAILURE.sh:124+` `run_probe_attempt(N/2)` + `reset-failed` between attempts; strict band [4,5] preserved | ✓ |
| HK-12 NOTE comment | §5.30 EDITED row | `tests/T_APPLY_ATOMIC_SWAP_NO_DROP.sh:242, :245, :258` cite §5.26 D-3.1-4 reuse_fd loop | ✓ |
| HK-13 orphan-pin cleanup | §5.30 EDITED row | `tests/T_ATTACH_TAG_MISMATCH.sh:68-90` pre/post `find /sys/fs/bpf -maxdepth 1` snapshot diff in cleanup trap | ✓ |
| HK-14 SKIPPED | §5.30 D-3.4.5-4 | (no code; deliberate non-action) | ✓ |
| HK-15 inline correction | §5.30 EDITED row | `mint/design.md:4193` `[CORRECTION §5.30 HK-15 — see §5.30 (MVP-3.4.5)]` marker in §5.26 | ✓ |
| HK-16 startup WARN | §5.30 Q2 W1; D-3.4.5-1 | `src/exporter/stats_reader.cpp:108-125` `validate_bpffs_root_or_warn`; `src/exporter/main.cpp:170` call site BEFORE `http::run(cfg)` | ✓ exact wording: `xdpmf-exporter: WARN bpffs root %.*s does not exist; will serve empty metrics` |
| HK-17 exit-6 trigger | §5.30 Q3 E1; D-3.4.5-2; EDIT-2 | `src/exporter/stats_reader.hpp:49-54` (`DiscoveryAccounting`); `src/exporter/stats_reader.cpp:139-211` (acc-aware variant); `src/exporter/http.cpp:38-48` (globals), `:198-218` (trigger eval after response write), `:303` (`while (g_stop == 0 && g_exit_six == 0)`), `:340-342` (return 6), `:346-353` (getter); `src/exporter/main.cpp:185-191` (HK-17 ERROR line + `return rc`) | ✓ exact wording matches design |

**EDIT-1 (12-entry kManagedMaps[])**: realized at `loader.cpp:145-158` — `rulesets` (line 148) + `cidr_rulesets` (line 151) present alongside the 10 "originally enumerated" maps; `MapsT` realized as `SkelMapsT = std::remove_reference_t<decltype(...)>` (semantically equivalent; impl-discretion acceptable).

**EDIT-2 (http.cpp EDITED)**: realized — anon-namespace globals (`http.cpp:38, :47-48`); handler hook at `:198-218`; while-loop extension at `:303`; getter at `:346`. Order of operations matches D-3.4.5-2 ("AFTER writing the response body").

**EDIT-3 (7-EDIT carve-out)**: realized — `tests/T_BYPASS_CMD_DETACHES.sh:86` uses permissive regex per option (b); `tests/T_EXPORTER_METRICS_FORMAT.sh:100-101` literal `xdpmf-exporter 0.6.1`.

### Point 2 — Spec ↔ Tests (all TestStrategy entries realized + each test has a negation control)

| TestStrategy | Test file | Negation control | Status |
|---|---|---|---|
| §6.43 T_APPLY_EXITS_1_ON_MISSING_CONFIG | `tests/T_APPLY_EXITS_1_ON_MISSING_CONFIG.sh` | line 70-103: re-run with valid config → assert rc != 1 | ✓ |
| §6.44 T_BYPASS_INTERACTIVE_PROMPT | `tests/T_BYPASS_INTERACTIVE_PROMPT.sh` | sub-cases 2 (`n`) + 3 (EOF) ARE negation probes — XDP MUST stay attached | ✓ HK-4 field assertion at line 309 |
| §6.45 T_BYPASS_REASON_TRUNCATE | `tests/T_BYPASS_REASON_TRUNCATE.sh` | sub-case 1 (253 bytes, no truncation) is the negation; sub-case 3 mid-UTF-8 rewind-safety | ✓ all three byte targets match architect amendment (253/254/300) |
| §6.46 T_EXPORTER_EXITS_6_ALL_IFACES_EACCES | `tests/T_EXPORTER_EXITS_6_ALL_IFACES_EACCES.sh` | lines 305-371: re-run as root with default perms → assert rc != 6 | ✓ HK-17 ERE matched + N extraction |
| §6.39 EDIT T_EXPORTER_NO_ATTACHED_IFACE | `tests/T_EXPORTER_NO_ATTACHED_IFACE.sh:178-250` | sub-case 2: existing-but-empty bpffs root → WARN MUST NOT fire | ✓ both positive + negative |

**No `[CIRCULAR-TEST]`**: each assertion targets observable contract; none peek at internal state shapes.

### Point 3 — Code ↔ Tests (re-ran ctests)

Re-ran `cd /home/user/mint-l2-mac-filter/build && ctest --output-on-failure -j4`. Final tally identical to tester baseline:

```
100% tests passed, 0 tests failed out of 46
Total Test time (real) = 309.12 sec
The following tests did not run:
        5 - T_DROP_MALFORMED (Skipped)
       35 - T_ANSIBLE_PLAYBOOK_SYNTAX (Skipped)
```

Both SKIP-77 are legitimate, pre-existing (not MVP-3.4.5-introduced).

44/44 active tests pass — including the 4 new §6.43–§6.46 + the 7 EDITED ctest bodies. Zero regressions.

### Point 4 — Out-of-Scope Drift

- No NEW source files this slice (per design): confirmed via `git diff --name-only 325e2ee HEAD`.
- No code or test references any §7 OOS item (per-rule counters, datapath wiring of rules, JSON logs, IPv6, etc.).
- The 7 OOT-deferred items closed by this slice (HK-11/13/12/15/14/16/17) are all design-explicit.

### Point 5 — Behaviour preserved (brownfield)

All PI-1..PI-34 + PI-7-3.4.5-hpp/cpp checked:

| Invariant | Check | Result |
|---|---|---|
| PI-7-3.4.5-hpp (loader.hpp ZERO diff, 5th cycle) | `git diff main -- src/lib/loader.hpp \| wc -l` | 0 ✓ |
| PI-7-3.4.5-cpp (regional diff) | `git diff 325e2ee HEAD -- src/lib/loader.cpp` hunk classification | 9 hunks, ALL inside allowed scope set ✓ |
| PI-8-3.4.5 (both binaries 0.6.1) | `xdpmacfilter --version` and `xdpmf-exporter --version` | both report `0.6.1` ✓ |
| PI-9 (--help format) | T_CLI_HELP_VERSION re-run | passed ✓ |
| PI-10-3.4.5 (mac_filter.h ZERO diff) | `git diff main -- src/common/mac_filter.h \| wc -l` | 0 ✓ |
| PI-11 (dir layout) | `find src -type d` | unchanged ✓ |
| PI-13-3.4.5/PI-27 (inner-value byte-equivalent) | bpf source inner-value types | UNCHANGED ✓ |
| PI-28 (BPF function-body semantic byte-equivalent) | full 42-test baseline pre-§5.30 still green | 35/42 byte-equivalent bodies + 7 explicit EDITs + 4 NEW, all green ✓ |
| PI-29 (rules/action_table populated but NOT consulted) | T_RULES_SKELETON_NOT_WIRED | passed ✓ |
| PI-30 (bypass = detach-alias + audit + --unsafe gate) | T_BYPASS_CMD_DETACHES + T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE + T_BYPASS_INTERACTIVE_PROMPT | all passed ✓ |
| PI-31 (exporter READ-ONLY) | grep for mutation syscalls in `src/exporter/` | only comment-mentions; no actual call-sites ✓ |
| PI-32 (WARN realized) | T_EXPORTER_NO_ATTACHED_IFACE HK-16 sub-cases | both positive + negation pass ✓ |
| PI-33 (shared version.h) | both binaries report `0.6.1` | ✓ |
| PI-34 / PI-6-3.4.5 (42 pre-§5.30 + 4 NEW, 7-EDIT carve-out) | `git diff --name-only 325e2ee HEAD -- tests/T_*.sh` | exactly 4 NEW + 7 EDITED ✓ |

No `[INVARIANT-VIOLATED]`, no `[REGRESSION]`, no `[UNRELATED-EDIT]`.

`stats_reader.hpp` modified (added `DiscoveryAccounting` + `read_all_attached_with_acc` declaration) — design's UNCHANGED-BUT-AFFECTED row explicitly grants impl this discretion. Not a finding.

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] Pre-existing `xdpmf-exporter: shutdown` stderr line appears between run() return and HK-17 ERROR line
**Location**: `src/exporter/http.cpp:336` vs `mint/design.md` HK-17 Interfaces.
**Evidence**: The shutdown line fires unconditionally on `run()` exit. Verified pre-existing: `git show 325e2ee:src/exporter/http.cpp` already contained the line at the MVP-3.4-shipped baseline. HK-17's contract is on the ERROR line + exit code, NOT on stderr exclusivity. The HK-17 ERROR is still emitted "immediately before exit(6) from main()" (last printf before `return rc` in `main.cpp:192`). `T_EXPORTER_EXITS_6_ALL_IFACES_EACCES.sh` asserts via `grep -qE` substring, robust to the extra line.
**Recommended disposition**: `defer`
**Rationale**: pre-existing benign teardown marker; not a §5.30 introduction; design's HK-17 contract preserved. Optional design clarification (one-line note "the run() teardown shutdown marker is benign and may appear before the HK-17 line") is harmless documentation cleanup but not load-bearing.

## Rework assignments

None — verdict `pass`.

## Final summary

All 17 HK items realized per design. All 3 architect Phase B EDITs (EDIT-1 12-entry kManagedMaps[], EDIT-2 http.cpp HK-17 hook, EDIT-3 7-EDIT carve-out) landed in expected shape. PI-7-3.4.5-hpp clean for the 5th consecutive cycle. PI-7-3.4.5-cpp regional-diff confined to allowed scope set. PI-13-3.4.5/PI-27 (load-bearing inner-value defer) untouched. All 46 ctests pass (44 + 2 legit SKIP-77), 0 fail, zero regressions vs MVP-3.4 baseline.

— mint-dev-reviewer

---

## Deferred to next slice

- **OOT-1**: Pre-existing `xdpmf-exporter: shutdown` stderr line between `run()` return and HK-17 ERROR line. Disposition: `defer`. Pre-existing benign teardown marker (not §5.30 introduction). Optional design clarification in a future slice ("the run() teardown shutdown marker is benign and may appear before the HK-17 line"). Not load-bearing — HK-17 contract preserved (`exit(6)` + ERROR ERE match). `T_EXPORTER_EXITS_6_ALL_IFACES_EACCES.sh` assertion is robust to the extra line (uses `grep -qE` substring, not line exclusivity).
