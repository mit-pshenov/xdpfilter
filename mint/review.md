# Review — MVP-3.3: systemd + Ansible + fleet docs (mint triangulation, brownfield 5-point) — ROUND 1

## Verdict
`needs-rework`

Reasoning: (a) test failure in Code ↔ Tests triangulation (T_SYSTEMD_LIFECYCLE FAILS — auto-needs-rework per verdict rule "test failure → needs-rework"); (b) brownfield Point 5 → PI-20 (systemd lifecycle correctness) is INVARIANT-VIOLATED at runtime. Both fail-conditions independently trigger rework. impl is honest-faithful to design.md §5.28 directive catalogue (PI-24 byte-equivalent — confirmed below); the spec itself omitted `CAP_SYS_ADMIN`, so the fix must land BOTH spec-side (architect) AND impl-side (impl) to converge. Architect-only or impl-only would create [SPEC-DRIFT not negotiated].

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 1 | [DESIGN-DEFECT × 1 — design itself wrong, no impl drift] |
| 2. Spec ↔ Tests | 0 | (all 5 TestStrategy entries §6.32–§6.36 mapped 1:1; negation controls in 3 of 5) |
| 3. Code ↔ Tests | 1 | [test-failures × 1: T_SYSTEMD_LIFECYCLE step 5/7] |
| 4. Out-of-Scope Drift | 0 | (no OOS items implemented) |
| 5. Behaviour preserved (brownfield) | 1 | [INVARIANT-VIOLATED × 1: PI-20 systemd lifecycle correctness] |

Other PIs walked & confirmed holding (PI-1..PI-19, PI-21..PI-26).

## Findings

### [INVARIANT-VIOLATED + test-failures] PI-20 systemd lifecycle correctness — BPF prog load fails under unit's caps
**Location**:
- runtime failure: `/tmp/mint-review-tests-202605242000.log` lines 92-114 (re-run) + `mint/test-run.log:91-117` (tester's prior run, identical kernel verifier message)
- ExecStart caps source: `systemd/xdpmacfilter@.service:54` (`AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE`) + `:57` (`CapabilityBoundingSet=` same)
- spec source: `design.md:5766-5767` (architect's prescribed directive catalogue — IMPL MATCHES BYTE-FOR-BYTE)
- invariant declaration: `design.md:6109` (PI-20)

**Evidence**:
- T_SYSTEMD_LIFECYCLE fails at step 5 (`systemctl start` → rc=1; `is-active='activating'` looping; `PROG_ID_START=<empty>`; `pin missing`; `active_idx=''`; journal shows `xdpmacfilter: trust_model=strict` correctly emitted, then libbpf load fails).
- Kernel verifier root cause (journal verbatim): `R2 has pointer with unsupported alu operation, pointer arithmetic with it prohibited for !root` followed by `error: mac_filter_bpf__load: Permission denied: permission denied (need CAP_BPF / CAP_NET_ADMIN)`. The "!root" message is the kernel's verifier-mode gate: pointer arithmetic in BPF programs requires CAP_SYS_ADMIN ("trusted verifier mode"), not just CAP_BPF — this is a 5.8+ kernel behaviour where CAP_BPF alone gates loading but CAP_SYS_ADMIN (or CAP_PERFMON for some checks) gates the permissive verifier path the MVP-1 BPF program uses for its `data + sizeof(ethhdr) > data_end` bounds check.
- The other 31 tests don't catch this because they invoke the loader directly via NSEXEC (per `tests/lib/common.sh` setup) which preserves the caller's full root caps (CAP_SYS_ADMIN included). Only systemd-managed launch strips down to the declared AmbientCapabilities, exposing the gap.

**Negotiated?**: no — impl-notes.md MVP-3.3 section only flags the Jinja2 line-ordering minor; no negotiation about CAP_SYS_ADMIN. spec authoritatively omitted it.

**Fix** (two-sided, both must land):
1. **architect** edit `design.md`:
   - §5.28 directive catalogue (lines 5766-5767) — add `CAP_SYS_ADMIN` to both `AmbientCapabilities=` and `CapabilityBoundingSet=` (recommend also `CAP_PERFMON` belt-and-suspenders for kernel ≥ 5.8 verifier-permission split).
   - §5.28 Decisions block (around D-3.3-6) — extend rationale: "CAP_SYS_ADMIN gates the kernel BPF verifier's trusted-verifier mode (pointer arithmetic in pkt-bounds checks the loader's BPF program performs); CAP_BPF alone is insufficient. CAP_PERFMON added as belt-and-suspenders for kernel ≥ 5.8 verifier-permission split. Empirically validated post-MVP-3.3 round 1 rework via T_SYSTEMD_LIFECYCLE."
   - §6.5 PI-24 — update declaration to reflect the new 5-cap catalogue (CAP_BPF, CAP_NET_ADMIN, CAP_SYS_RESOURCE, CAP_SYS_ADMIN, CAP_PERFMON).
   - Add a sentence in §5.28 explaining why existing 31 tests don't catch this (NSEXEC preserves caller's full caps) — this is the audit trail.
2. **impl** edit `systemd/xdpmacfilter@.service`:
   - Line 54: `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_SYS_ADMIN CAP_PERFMON`
   - Line 57: `CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_SYS_ADMIN CAP_PERFMON`
   - DO NOT touch any other file (preserves PI-7-3.3, PI-10, PI-26 — fix stays inside the OPS-slice surface).

**Assign to**: architect (spec-side first to authorize PI-24 evolution), then impl (sync to amended catalogue), then tester (re-run T_SYSTEMD_LIFECYCLE green + full ctest no-regression).

## Triangulation walk — point-by-point evidence

### Point 1 — Spec ↔ Code

For each spec artifact in §5.28:

- **systemd unit `systemd/xdpmacfilter@.service`** — every directive in design.md:5749-5772 catalogue present byte-equivalent at the cited file:line (Description@19, Documentation@20, After@23, Wants@24, ConditionPathExists@27, StartLimitBurst@33, StartLimitIntervalSec@34, Type=oneshot@40, RemainAfterExit=yes@41, ExecStart@42, ExecReload@46, ExecStop@49, Restart@50, RestartSec@51, AmbientCapabilities@54, CapabilityBoundingSet@57, NoNewPrivileges@58, [Install] WantedBy@61). ExecStart byte-identical to ExecReload (Q2 R1 contract) ✓. StartLimit pair under `[Unit]` not `[Service]` (Q4 RT2 placement) ✓. CapabilityBoundingSet mirrors AmbientCapabilities (D-3.3-6) ✓. PI-24 byte-equivalence holds — **the bug is in the catalogue ITSELF, not in impl's transcription of it.**
- **Ansible playbook `ansible/xdpmacfilter-deploy.yml`** — structure matches design.md:5800-5853. `become: true` (D-3.3-7) at line 28 ✓; tasks in prescribed order at lines 35-66; handlers (daemon-reload + reload) at lines 71-78. `daemon-reload` is a HANDLER not a task (D-3.3-8) ✓.
- **Jinja2 template** — schema_version:1 LITERAL at line 1 (PI-17 verbatim), comment at line 2. NOTE: internal design inconsistency vs prose example. Impl chose PI-17 (the invariant), documented in impl-notes.md. Captured below as OOT.
- **Fleet docs** — all 6 PI-23 substrings present ✓.
- **README "Production deployment" section** — present per Q5 N1 (19 lines) ✓.
- **CMakeLists.txt** — version 0.5.0 + XDPMF_INSTALL_SYSTEMD_UNIT option + conditional install (per D-3.3-9) ✓.
- **CHANGELOG.md** — [0.5.0] entry with Added/Changed/Preserved invariants/OOS subsections ✓.

**No SPEC-DRIFT findings** — impl is faithful. The unit-file directive catalogue itself is the defect.

### Point 2 — Spec ↔ Tests

All 5 TestStrategy entries §6.32-§6.36 mapped 1:1 to test files with negation controls in 3 of 5. Iface naming D-3.3-10 host-netns veth carve-out and §6.32 [Service]-removal negation are architect-blessed via design.md inline-merges during Phase B. No [SPEC-UNTESTED], no [CIRCULAR-TEST], no [NO-NEGATION-CONTROL].

### Point 3 — Code ↔ Tests

ctest re-run captured `/tmp/mint-review-tests-202605242000.log`: **33/36 PASS, 1 FAIL (T_SYSTEMD_LIFECYCLE), 2 SKIP (T_DROP_MALFORMED legitimate per §6.5; T_ANSIBLE_PLAYBOOK_SYNTAX SKIP-77 per PI-25).** Reproduces tester's report byte-equivalent: same FAIL[5]/[5a]/[5b]/[5c]/[5d]/[7]/[7a]/[7b]/[7c] cascade, same kernel verifier "!root pointer-arithmetic" diagnostic. Test IS the messenger; spec/impl is the message.

### Point 4 — Out-of-Scope Drift

Walked §7 OOS list: no SIGHUP/--quiet/exporter/per-rule-counters/binary-rename/Ansible-role/baked-env/extra-hardening. PI-7-3.3 ZERO src/ diff verified. No [OOS-DRIFT].

### Point 5 — Brownfield preserved invariants walk (PI-1..PI-26)

All PIs hold EXCEPT **PI-20 ✗ FAIL — [INVARIANT-VIOLATED]** (see top finding). PI-24 holds (impl byte-equivalent to spec; defect is IN the spec). PI-7-3.3 + PI-26 ZERO src/ diff continues (third consecutive cycle). PI-6-3.3 strict superset holds (30/31 pre-existing PASS + 1 legit SKIP). PI-17 holds via Jinja2 line-1 placement.

## Test execution

```
33/36 Test #33: T_SYSTEMD_LIFECYCLE .................***Failed    3.52 sec
34/36 Test #34: T_SYSTEMD_RESTART_ON_FAILURE ........   Passed   30.03 sec
35/36 Test #35: T_ANSIBLE_PLAYBOOK_SYNTAX ...........***Skipped   0.01 sec
36/36 Test #36: T_FLEET_DOCS_SUBSTRING ..............   Passed    0.02 sec

97% tests passed, 1 tests failed out of 36
Total Test time (real) = 206.93 sec

The following tests did not run:
  5 - T_DROP_MALFORMED (Skipped)
 35 - T_ANSIBLE_PLAYBOOK_SYNTAX (Skipped)

The following tests FAILED:
 33 - T_SYSTEMD_LIFECYCLE (Failed)
```

Critical journal excerpt from the failure (verbatim):
```
xdpmacfilter[…]: 16: (0f) r2 += r1
xdpmacfilter[…]: R2 has pointer with unsupported alu operation, pointer arithmetic with it prohibited for !root
xdpmacfilter[…]: libbpf: prog 'mac_filter_prog': failed to load: -13
xdpmacfilter[…]: error: mac_filter_bpf__load: Permission denied: permission denied (need CAP_BPF / CAP_NET_ADMIN)
```

The loader's own error message ("need CAP_BPF / CAP_NET_ADMIN") is misleading — those caps ARE granted; the missing one is `CAP_SYS_ADMIN` (kernel verifier trusted-mode gate for pointer arithmetic). Loader's error catalogue is its own opportunity but OOS for this rework cycle.

## Rework assignments

### architect
- Edit `mint/design.md` §5.28:
  - Line 5766: `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_SYS_ADMIN CAP_PERFMON`
  - Line 5767: `CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_SYS_ADMIN CAP_PERFMON`
  - Around D-3.3-6: extend Rationale paragraph documenting kernel BPF verifier trusted-mode gate (CAP_SYS_ADMIN for pointer arithmetic ≥ 5.8; CAP_PERFMON belt-and-suspenders); cite empirical T_SYSTEMD_LIFECYCLE failure round 1 + journal evidence as audit trail.
  - PI-24: update the directive enumeration to reflect 5 caps not 3.
  - Add brief note explaining why the existing 31 ctests don't catch this (NSEXEC preserves caller's full root caps; only systemd-managed launch strips down to declared AmbientCapabilities), preventing future cycles from re-treading the misdiagnosis path.
- Bundle the OOT Jinja2 prose-example fix (line 5862) into the same edit per inline-merge below.
- SendMessage me + impl + tester with diff summary.

### impl
- Edit `systemd/xdpmacfilter@.service`:
  - Line 54: append `CAP_SYS_ADMIN CAP_PERFMON` to `AmbientCapabilities=`.
  - Line 57: append `CAP_SYS_ADMIN CAP_PERFMON` to `CapabilityBoundingSet=`.
- Update inline comment at lines 52-53 to reflect the new caps + verifier-mode rationale.
- DO NOT touch any src/ file (preserves PI-7-3.3 / PI-26 across the rework).
- Smoke-verify locally before handing off: `systemctl daemon-reload` after staging amended unit, manual `systemctl start xdpmacfilter@<iface>.service` against a host-netns veth + config — assert XDP attaches green.
- SendMessage me with "build green" again.

### tester
- Re-run T_SYSTEMD_LIFECYCLE in isolation: `cd build && ctest -V -R T_SYSTEMD_LIFECYCLE` — assert PASS green.
- Re-run full suite: `ctest --output-on-failure -j 1` — assert ≥ 33 PASS (no new regressions); T_DROP_MALFORMED + T_ANSIBLE_PLAYBOOK_SYNTAX legitimate SKIPs allowed; everything else PASS.
- Update `mint/test-run.log` with post-rework output.
- SendMessage me with results.

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] Jinja2 template line-1 ordering: design has internal inconsistency between prose example and PI-17
**Location**:
- `ansible/templates/xdpfilter-config.yaml.j2:1` ships `schema_version: 1` at line 1, comment at line 2 — chooses PI-17.
- `mint/design.md:5862-5878` prose example puts comment at line 1, `schema_version: 1` at line 2.
- `mint/design.md:6101` PI-17 declares "Jinja2 template emits `schema_version: 1` at line 1 (verbatim, NOT templated)".
- Documented in `mint/impl-notes.md:298-321` with explicit ask to architect to clarify.

**Evidence**: impl correctly chose the invariant (PI-17 binds reviewer) over the prose example. Zero behavioural impact; pure design-text alignment issue.

**Recommended disposition**: `inline-merge` — architect amends design.md:5862 prose example to put `schema_version: 1` on line 1 (matching PI-17 + impl). Bundle with the architect's round-2 amendment for the CAP_SYS_ADMIN fix.

**Rationale**: Same pattern as MVP-3.2's 3 inline-merged OOTs (clean precedent). Architect is editing §5.28 anyway for the cap-fix; absorbing this is zero-marginal-cost.

---

Triangulation conclusion: this is the cleanest possible rework cycle — impl is honest, tests are honest, the spec is the single point of failure, and the fix surface is small (2 directive lines + spec doc updates). The T_SYSTEMD_LIFECYCLE canary did exactly the job design assigned it (PI-20 + "OPS-slice canary" per design.md:5989). Don't dismiss; honor the canary, fix the spec, re-converge.

Per workflow notes: this is the FIRST FORMAL ROUND-2 across 11 mint-dev cycles, and it's the RIGHT call — design defect cleanly surfaced by a real test catching real OPS breakage. Inline-merging this would compromise the workflow's audit invariants (PI-24 is a load-bearing reviewer-check; bypassing it via "impl just adds the caps" would silently break PI-24's spec-vs-unit byte-equivalence promise without architect signoff).
