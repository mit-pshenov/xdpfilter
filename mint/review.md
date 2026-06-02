# Review — MVP-4.23 CI gate + coverage-floor guards (mint triangulation)

## Verdict
`pass` (round-1, 0 findings, 0 out-of-triangulation)

Base for all diffs: `e50a62d` (MVP-4.22 final).

## Triangulation matrix (brownfield, 5-point)

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | negation control PRESENT |
| 3. Code ↔ Tests | 0 | all pass; no UNEXERCISED-EXPORT (zero new exports) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved | 0 | zero-src, datapath identical, 0 regressions, VERSION held |

## Point 1 — Spec ↔ Code
- `T_COVERAGE_FLOOR.sh:43-49` — pure `floor_verdict <require> <sudo_ok>` per §5.63 Interfaces; RED iff require==1 && sudo_ok==0 (D-mvp-4.23-Q1-A2).
- `T_COVERAGE_FLOOR.sh:95-114` live gate reads `XDPMF_REQUIRE_FULL_COVERAGE`; flag=1+no-sudo→exit 1, else exit 0.
- `T_PROD_VERIFIER_LOAD.sh:48,86` — `bpftool prog load <prod_obj> /sys/fs/bpf/xdpmf_prod_verifier_probe_$$ type xdp`, PID-unique bpffs-root pin, assert rc==0 (D-mvp-4.23-H3-PRODOBJ). PROD_BPF_OBJ→${BUILD_DIR}/mac_filter.bpf.o (`:53-64`). NO attach/veth/netns (verifier-only).
- `tests/CMakeLists.txt:1541-1545` — T_PROD_VERIFIER_LOAD: SKIP_RETURN_CODE 77, TIMEOUT 90, NO RESOURCE_LOCK (D-H3-NOLOCK), `PROD_BPF_OBJ=${CMAKE_BINARY_DIR}/mac_filter.bpf.o`.
- `tests/CMakeLists.txt:1560-1563` — T_COVERAGE_FLOOR: NO SKIP_RETURN_CODE, TIMEOUT 15, no lock (PI-NO-SKIP-FLOOR).
- `ci.yml:25-67` — push(main)+PR; ubuntu-latest; checkout→toolchain→cmake build→`sudo -E env XDPMF_REQUIRE_FULL_COVERAGE=1 ctest --output-on-failure` (serial).

## Point 2 — Spec ↔ Tests + negation control
- §6.80 (TEST-H3): rc==0 contract; negation = verifier-reject path surfaces verifier log (`T_PROD_VERIFIER_LOAD.sh:86,102-108`).
- §6.81 (TEST-H2): intrinsic self-test (`T_COVERAGE_FLOOR.sh:54-92`) asserts the full truth-table incl. load-bearing `verdict(1,0)==RED` (`:57-62`). NON-VACUITY PROVEN (D-Q1-SELFTEST).
- Suite negation controls present (global `T_NEGATION_CONTROL` WILL_FAIL + the 2 intrinsic). No CIRCULAR-TEST.

## Point 3 — Code ↔ Tests (reviewer re-ran)
- `sudo -E env XDPMF_REQUIRE_FULL_COVERAGE=1 ctest -R 'T_PROD_VERIFIER_LOAD|T_COVERAGE_FLOOR' -V`: 2/2 passed. T_PROD: rc=0, verifier ACCEPTED prod 9-axis object on 6.1.0-49. T_COVERAGE_FLOOR: selftest OK + PASS (sudo present).
- **Independent RED-path proof** (shimmed a failing `sudo` on PATH): flag=1+sudo-absent → exit 1 with masking-hole diagnostic ("guard #31"); flag unset → exit 0; flag=0 → exit 0. The gate genuinely goes RED on a live coverage-zero context — NOT theatre. The crux holds.
- Log: /tmp/mint-review-tests-mvp423.log

## Point 4 — Out-of-Scope Drift
None. No src/ change; no B26/B27/datapath/schema/map touch; no VERSION bump; no CHANGELOG edit; ci.yml branch-protection is INTENT comment only (`:18-21`); A3 skip-% parser left COMMENTED OUT (`ci.yml:69-76`) per D-Q1-NO-A3-IN-CTEST.

## Point 5 — Behaviour preserved (brownfield)
- `git diff e50a62d -- src/` = ∅ → PI-ZERO-SRC ✓. loader.hpp+config.hpp = ∅ → PI-7 streak continues ✓. mac_filter.bpf.c = ∅ → PI-DATAPATH-IDENTICAL ✓ (xdp 3658).
- VERSION 0.15.0 unchanged (`CMakeLists.txt:13`) → PI-VERSION ✓.
- No REGRESSION: full suite 100/102; the 2 fails (#48/#62) are pre-existing env-fails (bpffs root unmounted) red at the e50a62d baseline (98/100) — not introduced here.

## Honesty note
`ci.yml:8-16` carries the UNVALIDATED-until-first-push HONESTY block ("Do NOT claim it works"), §5.60 precedent (D-CI-UNVALIDATED). `actionlint` NOT installed → ci.yml reviewed STRUCTURALLY only; runtime behaviour on a live runner remains unverified by design.

## Rework assignments
None — `pass`.

## Out-of-triangulation findings
None.

Candidate guard #31 (non-skipping coverage-floor) is well-founded and empirically demonstrated. Clean round-1 pass.
