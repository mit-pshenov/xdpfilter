# Review — MVP-4.25 B32 comment-collapse (mint triangulation, brownfield 5-point)

## Verdict
`pass` (round-1, 0 findings, 0 out-of-triangulation)

Base for all diffs: `daa8160` (design commit; src-identical to the pre-impl state).

## Triangulation matrix
| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code (rubric + traceability) | 0 | — |
| 2. Spec ↔ Tests | 0 | NO new ctest — correct per §5.65 (comment-only; existing suite IS the guard) |
| 3. Code ↔ Tests | 0 | sample 4/4 pass; xdp 3658; zero-warning |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved | 0 | PI-7 ∅, code-token diff 0, #48/#63 pre-existing env-fails (not REGRESSION) |

## Point #1 — TRACEABILITY ANCHOR AUDIT (the crux)
Method: `git show daa8160:<f> | grep -oE '§5\.[0-9]+|PI-[a-z0-9.-]+|guard #[0-9]+|D-mvp-[0-9.]+' | sort -u` vs working tree, per file, comment-lines.

**16 distinct anchors dropped across the 11 files — EVERY ONE a collapsed stack-duplicate or stale CUT-class narration; ZERO governing/last-pointer losses.** No [TRACEABILITY-LOSS], no [INVARIANT-DOC-LOSS]. Examples: bpf.c dropped PI-29-3.4b/§5.29/§5.3/§5.58 (all stale/net-delta/superseded) while keeping rules→§5.34/§5.35+PI-3.4b-2, counter-bump→§5.31, ethertype-no-closure→§5.54; loader.cpp dropped a stacked "HK-9 / guard #10" dup, kept HK-9 (~14 sites); prom_format dropped D-mvp-4.21/4.6/4.7 stacked dups, kept §5.46/§5.47/§5.61; mac_filter.h (highest-care) dropped only adjudication-history, kept every map/struct/ABI-layout WHY + byte-identical static_asserts.

Load-bearing KEEP list — all PRESENT: guard #15 (loader copy_rule_counters_forward PRESERVE), guard #28 spike numbers (bpf.c MAX_EXT_HOPS=8, 26548/1M insns, stack 280/512), guard #30 never-throw (sidecar_reader/http/logger), §5.64 seqlock+PI-31 (rule_counters_reader), §5.19/§5.22 O_PATH/O_NOFOLLOW security (loader/sidecar).

Inverse-failure (no stale comment LEFT) — verified: all 7 impl-claimed fixes now accurate (bpf.c header "9-axis AND / 3 family arms" replacing the dead "MAC FROZEN / only-IPv4" lie, etc.); `grep` over src for stale markers (`dead under v2|FROZEN|only IPv4|8-term|NOT consulted|max_entries = 4|5 match-axis|7-label`) → only hit is the accurate `loader.cpp "MAC axis is UN-FROZEN"`. Surviving §-refs resolve to real design.md sections.

## Points 2–5 evidence
- **Code-token invariance:** comment-stripped before/after diff across all 11 files = **0 non-comment code-token lines** (the strongest behavior-preservation proof).
- **PI-DATAPATH-IDENTICAL:** rebuilt object, `xdp` section = **3658** insns.
- **PI-7:** `git diff daa8160 -- src/lib/loader.hpp src/lib/config.hpp` = ∅.
- **PI-VERSION / PI-KMANAGEDMAPS:** VERSION ∅ (0.15.0); no map/schema/axis token change.
- **Footprint:** `git diff daa8160 --name-only` = the 11 EDITED src files + impl-notes.md; no file outside FileList, no B33-rename/B34-split token, no new file.
- **Build:** forced C++ recompile → zero warnings.
- **Sample ctest:** T_LOAD_ATTACH, T_LOG_EVENT_CATALOG_STABILITY, T_SIDECAR_READ_EXCEPTION_DIAGNOSTIC, T_PROD_VERIFIER_LOAD → 4/4 PASS.
- **Baseline:** tester's full run 101/103; the 2 fails (#48 T_EXPORTER_EXITS_6_ALL_IFACES_EACCES + #63 T_LOG_JSON_EXPORTER_EVENTS) are pre-existing env-fails by NAME (bpffs root unmounted), byte-impossible from a comment-only slice (code-token diff = 0). Not regressions.

## Rework assignments
None — `pass`.

## Out-of-triangulation findings
None.

Net: −274 comment lines, traceability spine intact (zero governing-anchor loss), zero behavior change proven three ways (code-token strip + xdp 3658 + suite). The PO's dominant worry — over-cutting / "не стряхнуть traceability" — did NOT materialize. Candidate guard #33 (comment-collapse preserves grep-able anchors + leaves no stale comment) validated. Ship-ready.
