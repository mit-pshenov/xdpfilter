# Review — MVP-3.4h exporter `--bind` non-loopback startup WARN (mint triangulation, brownfield 5-point)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — (negation controls b/c/d present; no CIRCULAR-TEST; no SPEC-UNTESTED) |
| 3. Code ↔ Tests | 0 | 68/68 green, 2 SKIP-77 baseline matching MVP-3.4g |
| 4. Out-of-Scope Drift | 0 | — (KC-2 mitigation half + IPv6 + "localhost" + refusal + VERSION + README all UNTOUCHED) |
| 5. Behaviour preserved (brownfield) | 0 | PI-7-3.4h fences ZERO-diff; PI-3.4h-K scope confirmed; PI-3.4h-CTEST-BASELINE 67→68 with ZERO existing-body EDITs |
| OOT (does not affect verdict) | 0 | — |

## Special-attention checklist (all green)

- **(a) D-3.4h-7 LOAD-BEARING prose** — `grep -F 'xdpmf-exporter: WARN --bind' src/exporter/http.cpp` → 1 hit at `:314`. No colon after `WARN` per HK-16/guard #19 convention ✓
- **(b) D-3.4h-2 bitmask exact form** — `(addr.s_addr & ::htonl(0xff000000)) == ::htonl(0x7f000000)` at `src/exporter/http.cpp:272` ✓
- **(c) D-3.4h-6 alphabetical slot** — `logger.hpp:125-127`: `exporter.shutdown` → `exporter.warn.bind_non_loopback` (NEW) → `exporter.warn.bpffs_root_missing` ✓
- **(d) D-3.4h-T1-LOCK** — `tests/CMakeLists.txt:998` `RESOURCE_LOCK exporter_port_9417` ONLY; no `xdp_fixture` ✓
- **(e) Fixture alphabetical insert** — `log_events_v1.txt:22` slotted between `:21 exporter.usage_error` and `:23 exporter.warn.bpffs_root_missing`; total 37 ✓
- **(f) PI-3.4h-K scope** — `git diff 315a6e7..HEAD -- src/common/logger.hpp` shows EXACTLY 4 hunks (size 36→37 at :90 + 1 entry at :126 + sub-comment 15→16 at :114 + kEventCount comment at :133). No struct/Field/emit-signature changes ✓
- **(g) PI-7-3.4h fences** — `git diff 315a6e7..HEAD -- src/lib/loader.hpp src/lib/config.hpp src/common/mac_filter.h` empty; full UNCHANGED-BUT-AFFECTED sweep across 12 paths all empty ✓
- **(h) Test-machinery fixes legitimacy** — Phase A→B helper-shape fixes (poll_host arg + readiness-timeout port cleanup) at T_EXPORTER_BIND_NON_LOOPBACK_WARN.sh:150-192; assertions at :230-373 target spec contract (D-3.4h-7 prose + event token + level=warn + fields.bind_addr), NOT impl internal state. Not [CIRCULAR-TEST]; not [SPEC-DRIFT] ✓
- **(i) Impl deviation independent grep** — `is_loopback_ipv4` 2 hits (:270 def + :312 call); event-name emit 1 hit at :321; both `[[nodiscard]]` in anon namespace; no header leakage. Matches "Deviations: None" ✓

## Detailed triangulation

### Point 1 — Spec ↔ Code

| Design item | Code citation | Status |
|---|---|---|
| D-3.4h-1 — placement Q1.B (post-parse, pre-socket) | http.cpp:308-323 between parse-fail return @:306 and `::socket()` @:325 | ✓ |
| D-3.4h-2 — bitmask numerical loopback | http.cpp:272 exact match | ✓ |
| D-3.4h-3 — event-name token | http.cpp:321 + logger.hpp:126 + fixture:22 | ✓ |
| D-3.4h-4 — WARN-only (no refusal) | http.cpp:312-323 `if (!loopback) { emit(); }` then falls through; no `return` in WARN block | ✓ |
| D-3.4h-5 — NO VERSION bump | `git diff -- CMakeLists.txt` empty | ✓ |
| D-3.4h-6 — alphabetical slot in `exporter.warn.*` cluster | logger.hpp:125-127 ordering | ✓ |
| D-3.4h-7 — text-mode prose verbatim | http.cpp:314-316 exact match | ✓ |
| D-3.4h-T1-LOCK — `exporter_port_9417` only | tests/CMakeLists.txt:998 | ✓ |
| Caller idiom contracts | Level=Warn @:320; Field `bind_addr` @:318; before `::socket()` @:325 + before `exporter.listening` (PI-3.4h-1) | ✓ |

### Point 2 — Spec ↔ Tests

| T-1 sub-case | Test citation | Status |
|---|---|---|
| (a) positive `--bind 0.0.0.0` text-mode 3 substrings + guard #19 prefix | T_EXPORTER_BIND_NON_LOOPBACK_WARN.sh:219-248 | ✓ |
| (b) upper-edge negation `--bind 127.255.255.255` | :259-275 | ✓ negation control |
| (c) default negation no `--bind` | :280-301 | ✓ negation control |
| (d) in-range non-default negation `--bind 127.0.0.2` | :306-328 | ✓ negation control (proves /8 coverage not exact-match) |
| (e) JSON-mode positive (jq probe) | :333-374 | ✓ |

3 negation controls (b/c/d) make suite falsifiable; degenerate impl that always emits WARN would fail all three. NO-NEGATION-CONTROL not triggered. Assertions target externalized contract — NO CIRCULAR-TEST.

### Point 3 — Code ↔ Tests

Reviewer's independent rerun: `ctest -j4` → **68/68 PASS, 0 FAIL, 2 SKIP** (T_DROP_MALFORMED #5 + T_ANSIBLE_PLAYBOOK_SYNTAX #35 — same baseline). Log: `/tmp/mint-review-tests-1779909194.log`. T_EXPORTER_BIND_NON_LOOPBACK_WARN (#68) ran in 4.55s on tester's run + green on reviewer's independent run.

T_BPFFS_ROOT_SYMLINK passed cleanly (no host-pollution intervention needed; impl's manual cleanup carried over).

UNEXERCISED-EXPORT: N/A (`is_loopback_ipv4` is anon-namespace internal helper; not exported via http.hpp).

### Point 4 — Out-of-Scope Drift

§7 OOS fences walked: KC-2 auth/TLS untouched · IPv6 `::1` untouched (parse_bind_addr still AF_INET at :265) · "localhost" string detection none · rate-limiting none (single-shot in run() startup) · refusal none (falls through to ::socket()) · `--strict-loopback` flag none (main.cpp UNCHANGED) · VERSION bump none · README/HANDOFF empty diff · richer fields none (only `bind_addr`). ✓

### Point 5 — Behaviour preserved (brownfield §6.5)

| PI | Check | Result |
|---|---|---|
| PI-3.4h-K NEW (scoped carve-out) | logger.hpp diff CONFINED to 4 enumerated items; no other changes | ✓ |
| PI-7-3.4h-cpp (9th ZERO-diff on config.hpp) | empty diff | ✓ |
| PI-7-3.4h-loader-hpp | empty diff | ✓ |
| PI-7-3.4h-mac-filter-h | empty diff | ✓ |
| PI-3.4h-1 NEW (1 WARN before listening on non-loopback) | T-1(a)+(e) positive; T-1(c)+(d) negation; all green | ✓ |
| PI-3.4h-CTEST-BASELINE (67→68 + ZERO existing-body EDITs) | 1 NEW test file; 0 existing test edits | ✓ |
| PI-32-3.4b PRESERVED | T_SIDECAR_JSON_SHAPE + T_SIDECAR_IFACE_SYMLINK_REFUSAL green | ✓ |
| PI-3.5-1 PRESERVED | T_LOG_TEXT_BYTE_EQUIVALENT + 5 exporter tests green | ✓ |
| PI-3.5-4 PRESERVED (catalog lockstep +1) | T_LOG_EVENT_CATALOG_STABILITY green (set-equality fixture↔logger.hpp) | ✓ |
| PI-3.5-7 PRESERVED (no new deps) | CMakeLists.txt empty diff | ✓ |
| PI-8 (VERSION stability) | CMakeLists.txt empty diff | ✓ |
| PI-6 (67→68) | ctest output | ✓ |
| §5.36 PI-3.4e-* + KC-3 closure PRESERVED | T_RESET_COUNTERS_PATH_TRAVERSAL + T_SIDECAR_IFACE_SYMLINK_REFUSAL green | ✓ |
| §5.37 PI-3.4f-* + §5.38 PI-3.4g-* PRESERVED | baseline holds | ✓ |

No REGRESSION / INVARIANT-VIOLATED / UNRELATED-EDIT.

Anti-misdiagnosis catalog stays at 21.

## Test execution

```
100% tests passed, 0 tests failed out of 68
Total Test time = ~540 sec wall-clock under -j4

The following tests did not run:
    5 - T_DROP_MALFORMED (Skipped)
   35 - T_ANSIBLE_PLAYBOOK_SYNTAX (Skipped)
```

Reviewer log: `/tmp/mint-review-tests-1779909194.log`.

## Findings

NONE.

## Rework assignments

N/A (verdict = pass).

## Out-of-triangulation findings

NONE. Second consecutive ZERO-OOT round-1 pass in the OOT-tracking trajectory: 5 → 2 → 2 → 2 → 1 → 0 → **0**.

---

**Triangulation summary**: §5.39 closes KC-2 observability half (sec M2) cleanly. PI-3.4h-K scoped carve-out for logger.hpp catalog extension executed precisely per §5.36 35→36 precedent. D-3.4h-7 LOAD-BEARING text-mode prose verbatim at http.cpp:314. PI-7-3.4h-cpp = **9th** consecutive ZERO-diff on config.hpp + loader-hpp + mac-filter-h fence extensions intact. logger.hpp ZERO-diff streak intentionally narrowed for 1 cycle (PI-3.4h-K); re-baselines from §5.39 EDIT-point for future cycles. 2 test-machinery bugs caught + fixed Phase A→B (poll_host arg + readiness-timeout port cleanup) — impl peer-DM diagnosis discipline working as designed (tester did NOT need to read impl src/).
