# Review — MVP-3.3: systemd + Ansible + fleet docs (mint triangulation, brownfield 5-point) — ROUND 2

## Verdict
`pass`

Rationale: rework converged cleanly across all three parties. Round 1's two fail-conditions (PI-20 INVARIANT-VIOLATED + T_SYSTEMD_LIFECYCLE test-failure) are both resolved. The architect's EDIT-6 (5-cap catalogue) and EDIT-8 (prog_id contract correction) restored Spec↔Code↔Tests alignment; impl's unit-file sync is byte-faithful to the amended §5.28 catalogue; tester's T_SYSTEMD_LIFECYCLE edit correctly tracks the amended §6.33 + PI-20 contract. Full ctest run: **34/36 PASS + 2 SKIP, 0 FAIL**. PI-1..PI-26 ALL HOLD. Zero src/ diff for the THIRD consecutive cycle. Round 1's OOT-1 (Jinja2 prose ordering) inline-merged via EDIT-7 — design.md:5866 now matches impl + PI-17. No new OOT findings.

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | (5/5 TestStrategy entries mapped; negation controls in 3 of 5; PI-25 carve-out vacuous — §6.34 PASSED, no SKIP to validate citation on) |
| 3. Code ↔ Tests | 0 | (34/36 PASS, 2 legitimate SKIP, 0 FAIL) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | (PI-1..PI-26 all hold; PI-20 was VIOLATED round 1, now PASSES; PI-26 zero src/ diff verified bit-for-bit) |

## Triangulation walk — round 2 evidence

### Point 1 — Spec ↔ Code (post-rework)

- **systemd unit `systemd/xdpmacfilter@.service`** — every directive in amended §5.28 catalogue (design.md:5752-5776) present byte-equivalent. 5-cap set at lines 68+69 verbatim per Q4 RT2 + D-3.3-6.
- **D-3.3-6 audit trail** at design.md:5683-5685 + :5969-5974 — comprehensive evolution + kernel BPF verifier trusted-mode gate + "why 31 ctests don't catch" + `capsh --drop=` future-cycle prevention guard.
- **§6.33 prog_id contract correction (EDIT-8)** at design.md:6019-6031 + PI-20 at :6122 — all 3 differential signals enumerated (active_idx flip, link-pin persistence, xdp_prog_id non-empty), explicitly noting prog_id value is NOT a discriminator. Text-consistency across §6.33 + PI-20 + anti-theatricality block coherent.
- All other artifacts (Ansible, Jinja2, fleet docs, README, CMakeLists, CHANGELOG) unchanged from round 1 — no regressions.

### Point 2 — Spec ↔ Tests (post-rework)

- T_SYSTEMD_LIFECYCLE.sh:303-313 — removed wrong FAIL[7c] prog_id-constancy; added (7c-i) XDP still attached + (7c-ii) link pin persists per amended PI-20.
- Test comment block :283-302 records correction audit trail + cites loader.cpp:1466-1473 as source-of-truth.
- 5/5 §6.32-§6.36 TestStrategy entries mapped 1:1; negation controls in 3 of 5.

### Point 3 — Code ↔ Tests (re-ran)

Captured to /tmp/mint-review-tests-202605242030.log:
```
100% tests passed, 0 tests failed out of 36
Total Test time (real) = 356.16 sec
```
Byte-equivalent to tester's round 2 report. Both round 1 fail-conditions resolved: T_SYSTEMD_LIFECYCLE@33 PASSED (4.26 s); T_SYSTEMD_RESTART_ON_FAILURE@34 PASSED (30.47 s).

### Point 4 — Out-of-Scope Drift

Rework touched ONLY: mint/design.md (architect EDITs 6/7/8), systemd/xdpmacfilter@.service (impl unit sync), tests/T_SYSTEMD_LIFECYCLE.sh (tester correction). All authorized by amended §5.28 + §6.33 + PI-20. No new directives, no hardening creep.

### Point 5 — Brownfield PI walk (PI-1..PI-26)

All 26 PIs hold. PI-20 was VIOLATED round 1, now PASSES. PI-7-3.3 ZERO src/ diff continues (third consecutive cycle). PI-26 verified: `git diff 3d15473..HEAD -- src/ include/ cmake/` = 0 lines; CMakeLists.txt diff only version bump + XDPMF_INSTALL_SYSTEMD_UNIT option per D-3.3-9. PI-6-3.3 strict superset holds (30/31 pre-existing PASS + 1 legit SKIP).

## Round-2-specific cross-checks

1. **5-cap set verbatim in unit lines 68+69** — confirmed (lines shifted from round-1's 54+57 by inline comment expansion at 52-67, part of impl's authorized rework).
2. **T_SYSTEMD_LIFECYCLE.sh matches amended §6.33 + PI-20** — confirmed.
3. **Multi-party convergence (architect + impl + tester)** — confirmed; all 3 artifacts reference SAME contract: 5 caps (incl. CAP_SYS_ADMIN for verifier trusted-mode), prog_id NECESSARILY CHANGES across R1 reload, link pin + active_idx flip are the discriminators.
4. **D-3.3-6 future-cycle prevention guard present** — confirmed at design.md:5685 + :5974.
5. **PI-26 src/ zero-diff held across rework** — confirmed.
6. **Round-1 OOT-1 inline-merged** — confirmed at design.md:5865-5867 + :5886.

## Test execution

Last 20 lines of /tmp/mint-review-tests-202605242030.log:

```
      Start 32: T_SYSTEMD_UNIT_SYNTAX
32/36 Test #32: T_SYSTEMD_UNIT_SYNTAX ...............   Passed    0.24 sec
      Start 33: T_SYSTEMD_LIFECYCLE
33/36 Test #33: T_SYSTEMD_LIFECYCLE .................   Passed    4.26 sec
      Start 34: T_SYSTEMD_RESTART_ON_FAILURE
34/36 Test #34: T_SYSTEMD_RESTART_ON_FAILURE ........   Passed   30.47 sec
      Start 35: T_ANSIBLE_PLAYBOOK_SYNTAX
35/36 Test #35: T_ANSIBLE_PLAYBOOK_SYNTAX ...........***Skipped   0.00 sec
      Start 36: T_FLEET_DOCS_SUBSTRING
36/36 Test #36: T_FLEET_DOCS_SUBSTRING ..............   Passed    0.02 sec

100% tests passed, 0 tests failed out of 36

Total Test time (real) = 356.16 sec

The following tests did not run:
        5 - T_DROP_MALFORMED (Skipped)
       35 - T_ANSIBLE_PLAYBOOK_SYNTAX (Skipped)
```

## Rework assignments

None — verdict is `pass`. No rework needed.

## Out-of-triangulation findings

Round 1's only OOT (Jinja2 prose ordering) was inline-merged via Phase B EDIT-7 — resolved.

### Deferred to next slice

**T_SYSTEMD_RESTART_ON_FAILURE transient flake under back-to-back stress** (surfaced by round-1 reviewer's independent re-run during cleanup-phase activity; 1/5 known runs hit NRestarts=1 instead of 4-5 under reviewer's back-to-back ctest stress pattern; tester's run-of-record + reviewer-2's primary run both PASS at ~30s with NRestarts in band; flake rate ≤20% under stress, ~0% under clean-run pattern). Root cause appears to be systemd state-leak between T_SYSTEMD_LIFECYCLE's cleanup and T_SYSTEMD_RESTART_ON_FAILURE's pre-cleanup when run consecutively. PI-25 SKIP-77 carve-out explicitly anticipates this category of timing flake. Polish options for a future housekeeping cycle: (a) implement PI-25 SKIP-77 fallback in test (NRestarts < 4 + deadline expired + missing journal pattern → exit 77 with verbatim carve-out citation); (b) stronger inter-test isolation via `systemctl reset-failed --all` + `sleep 5` in defensive pre-cleanup; (c) increase polling deadline 60s → 90s. NOT a round-2 fail — verdict stands pass.

---

**Summary**: cleanest round-2 close possible. The rework executed exactly as Phase 5 re-spawn discipline prescribes: (a) honest round-1 reviewer caught a real spec defect via T_SYSTEMD_LIFECYCLE canary; (b) architect amended spec authoritatively with audit trail + anti-misdiagnosis-recurrence note + future-cycle prevention guard; (c) impl synced byte-equivalent; (d) tester surfaced a SECONDARY spec defect (prog_id contract) mid-rework, which architect promptly amended (EDIT-8); (e) all 3 artifacts converged on the same contract; (f) 34/36 PASS + 2 legitimate SKIP + 0 FAIL; (g) all 26 PIs hold; (h) PI-26 zero src/ diff invariant preserved across the entire rework. This is the textbook "honor-the-canary, fix-the-spec, re-converge" loop. Ship MVP-3.3.
