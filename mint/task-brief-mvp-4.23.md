# Task brief — MVP-4.23: CI gate + coverage-floor guards (brownfield)

## Goal

Close the TEST-dimension High findings from the 2026-06-01 hybrid review
(`~/agent-teams-review/runs/mint-review-mint-l2-mac-filter-20260601213046/report.md`):
the project has **no CI** (TEST-H1 — nothing gates `main`), a **green-on-SKIP**
masking hole (TEST-H2 — 88/100 ctests SKIP-77 without passwordless sudo,
INCLUDING the `T_NEGATION_CONTROL` sanity canary, so a coverage-zero run is
indistinguishable from a healthy one), and **no standalone verifier coverage
of the PRODUCTION BPF object** (TEST-H3 — the only verifier proof of the real
9-axis `mac_filter.bpf.o` is the sudo-gated full attach; the standalone
"verifier" test loads a 4-axis PROTOTYPE).

This is pure **test-infra + CI** — zero `src/` change, zero datapath change,
no schema/axis/map. Second of three hardening slices (MVP-4.22 robustness
batch shipped; exporter generation-counter is the third).

## Context: prior work

- Prior slice: **MVP-4.22** (`e50a62d`) — robustness batch; archived as `mint/task-brief-mvp-4.22.md`.
- Existing design: `mint/design.md` (most recent §5.62); this slice appends §5.63.
- Phase A code-grep verification (brief author, this slice):
  - `ls .github` → does NOT exist (TEST-H1 `ci.yml` is net-new).
  - `build/mac_filter.bpf.o` exists (144 KB production object, `xdp` section 3658 insns); source `src/bpf/mac_filter.bpf.c`. TEST-H3 LOADS this object (no rebuild of it, no src change).
  - `T_BITVEC_VERIFIER_LOAD.sh` loads `bitvec_proto.bpf.o` (the 4-axis prototype) via `bpftool prog load <obj> <pin> type xdp` (lines 53-60, 107-109) — confirms TEST-H3's premise AND gives the exact reusable mechanism (clone the structure, point at `build/mac_filter.bpf.o`).
  - `T_NEGATION_CONTROL.sh:18` calls `require_passwordless_sudo` → the canary itself SKIP-77s without sudo (TEST-H2's load-bearing premise). `set_tests_properties(T_NEGATION_CONTROL PROPERTIES WILL_FAIL TRUE)` at CMakeLists.txt:120.
  - `grep -rl require_passwordless_sudo tests/T_*.sh | wc -l` → **88** of 100 T_*.sh (review said 86 — actual 88); `SKIP_RETURN_CODE 77` declared 66× in tests/CMakeLists.txt.
  - `bpftool` at `/usr/local/bin/bpftool` (available for TEST-H3); `build_cpu` + `xdp_fixture` RESOURCE_LOCKs already exist in tests/CMakeLists.txt (B19 shipped — CI parallelism context).
- PI continuity: **PI-7 (loader.hpp + config.hpp byte-identical)** holds trivially (no `src/lib` change). **PI-DATAPATH-IDENTICAL** holds trivially (no `src/bpf` change; TEST-H3 only LOADS the object). New tests are additive.

## Workflow rules (brownfield)

- **Architect**: read §5.62 tail + §6.5 invariants + guards #1..#30; EDIT `design.md` in place, append §5.63. Resolve Q1 (TEST-H2 coverage-floor mechanism). Run the Phase A grep discipline below.
- **Impl**: FileList is NEW (`.github/workflows/ci.yml`, 2 new test scripts) + EDITED (`tests/CMakeLists.txt` registration). No `src/` files. The CI yaml is best-effort-unvalidated locally (see HG-2).
- **Tester**: this slice IS mostly test-infra, so the line between impl and tester blurs — the 2 NEW ctests (TEST-H3, TEST-H2) are the deliverable that impl writes; tester's Phase B runs the full suite to confirm the 2 new tests pass with sudo, the coverage-floor gate behaves correctly (RED when it should be, green otherwise), and ZERO regressions vs the 98/100 MVP-4.22 baseline. Tester also validates `ci.yml` with `actionlint` IF available (else structural review + honest "unvalidated" note). Negation control: the coverage-floor gate must itself be proven non-vacuous (it must actually go RED in a simulated coverage-zero condition).
- **Reviewer**: 5-point brownfield. Special attention: (a) TEST-H3 loads the PRODUCTION object (not the prototype) and is verifier-only (no attach/netns); (b) TEST-H2 gate runs WITHOUT requiring sudo (else it defeats itself) and is non-vacuous; (c) zero `src/` footprint (PI-7 + datapath trivially hold); (d) the `ci.yml` honesty note (unvalidated-until-first-push) is present; (e) no OOS drift into B27/B26/datapath.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.23-1: CI platform → **GitHub Actions** (`.github/workflows/ci.yml`)
The repo is `github.com/mit-pshenov/mint-filter`. Default runner: GitHub-hosted `ubuntu-latest` (has `sudo`/root via passwordless sudo, kernel ~6.x, can `apt-get install` clang-19 + libbpf-dev + bpftool + python3-scapy + jq, OR build bpftool). The workflow runs `cmake build` + `ctest`, fails on any non-SKIP failure, gates merges (branch protection is a repo setting, out of scope — document the intent). Architect may add a `# self-hosted runner alternative` comment block for environments where GitHub-hosted XDP/veth doesn't work.

### HG-mvp-4.23-2: CI YAML validation → **best-effort-unvalidated until first push** (honest gap-note, §5.60 precedent)
We cannot execute a GitHub Actions workflow in this environment. Validate with `actionlint` if present (impl/tester check `command -v actionlint`); otherwise structural review only. The design + a comment in `ci.yml` MUST state plainly that the workflow is unvalidated against a live runner until the first push triggers it (mirroring the §5.60 prototype-vs-production honesty precedent — do NOT claim it "works").

### HG-mvp-4.23-3: VERSION → **no bump** (test-infra/CI only; no operator-visible change)

## Open mechanism questions (architect decides; document in §5.63)

### Q1: TEST-H2 coverage-floor gate mechanism (the one real fork)
The gate must turn a SHOULD-have-sudo run that silently SKIPs the datapath suite (incl. the negation canary) from near-all-green into RED — WITHOUT itself skipping (else it's theatre).
- **A1** — standalone post-`ctest` parser script invoked by `ci.yml`: parses `Testing/Temporary/LastTest.log` for skip-count + asserts `T_NEGATION_CONTROL` actually ran (not SKIP). NOT a ctest itself; CI-only. Pro: no local-run friction. Con: invisible to a plain local `ctest`.
- **A2** — a NEW ctest `T_COVERAGE_FLOOR` that does NOT call `require_passwordless_sudo` and FAILS (exit 1, not 77) when `sudo -n true` fails AND an opt-in env flag (e.g. `XDPMF_REQUIRE_FULL_COVERAGE=1`) is set. CI sets the flag → a sudo-less CI run goes RED; local userspace-only runs (flag unset) stay green. Self-contained in the same ctest invocation. **Recommended** — cleanly separates "CI demands full coverage" from "local userspace-only is legitimately fine," and it's a real ctest so `ci.yml` doesn't need a bespoke log-parser.
- **A3** — both: the A2 floor ctest for the negation-skipped detection + `ci.yml` additionally asserts a skip-% threshold from ctest output.
- **Recommendation**: A2 as the primary mechanism; `ci.yml` exports `XDPMF_REQUIRE_FULL_COVERAGE=1`. Architect refines the exact env-name + whether to also pin a skip-% ceiling (A3) for defense-in-depth.

## Scope (cycle 1 — concrete items)

### Item C-1 — TEST-H3: standalone verifier-load of the PRODUCTION object
**Where**: NEW `tests/T_PROD_VERIFIER_LOAD.sh` (name architect's call) + `tests/CMakeLists.txt` registration.
Clone the `T_BITVEC_VERIFIER_LOAD.sh` structure but point at the PRODUCTION `build/mac_filter.bpf.o` (resolve path like the prototype test does under `BUILD_DIR`). `bpftool prog load <prod_obj> <unique_pin> type xdp` → assert rc=0 (verifier accepts the shipped 9-axis program), then `bpftool prog del`/unpin in teardown. Verifier-only: NO attach, NO netns. Sudo-gated (CAP_BPF to load) → `require_passwordless_sudo` + `SKIP_RETURN_CODE 77` + a pin-cleanup trap. Optionally assert the loaded insn count (3658) if cheap, but the load-rc=0 is the contract. This makes a verifier-complexity/stack regression in the real program visible without a full attach.

### Item C-2 — TEST-H2: coverage-floor gate (non-vacuous, sudo-free)
**Where**: per Q1 (default A2) — NEW `tests/T_COVERAGE_FLOOR.sh` + `tests/CMakeLists.txt` registration (no `SKIP_RETURN_CODE 77`; it must not skip).
The gate fails RED when the suite is running in a coverage-expected context (env flag set) but passwordless sudo is absent (→ the datapath suite + negation canary would all SKIP). Must be proven non-vacuous: a simulated coverage-zero condition (flag set + sudo unavailable) makes it FAIL; the normal local condition (flag unset) makes it PASS/no-op. Document the env contract.

### Item C-3 — TEST-H1: CI workflow
**Where**: NEW `.github/workflows/ci.yml`.
GitHub Actions workflow (HG-1): checkout → install toolchain (clang-19, libbpf-dev, bpftool, python3-scapy, jq, cmake) → `cmake -S . -B build` → `cmake --build build` (zero-warning `-Werror` already enforced by the build) → `sudo -E ctest --test-dir build --output-on-failure` with `XDPMF_REQUIRE_FULL_COVERAGE=1` (per Q1) → fail on any non-SKIP failure. Honesty comment per HG-2 (unvalidated until first push). Parallelism: respect the existing `build_cpu` / `xdp_fixture` RESOURCE_LOCKs (B16/B19 context) — a `-j` choice that doesn't starve `T_SANITIZER_BUILD` (architect picks; serial `ctest` or a conservative `-j` is safe).

## Out of scope (explicit)

- **Exporter generation-counter / TOCTOU P1** — the THIRD hardening slice (MVP-4.24); not here.
- **`pass_cidr`→`pass_rule` (B26)**, **datapath triplication (ARCH-H1)**, **dead `read_all_attached` (CQ-H1)**, **B27 regex DoS** — separate slices; no touch.
- **Branch-protection / merge-gating repo settings** — a GitHub repo-admin action, not a file in the tree; document the intent in `ci.yml`, do not attempt to configure it.
- **Fixing the 2 pre-existing environmental fails (#48/#62, bpffs root unmounted)** — environmental, not this slice's job; the CI runner (with a proper bpffs mount) may make them pass, but do NOT change their test bodies here.
- Any `src/` change, schema, axis, datapath, or VERSION bump.

## Definition of done

- §5.63 amendment in `design.md` (the 3 items + Q1 resolution + any new guard candidate).
- **PI-7 + PI-DATAPATH-IDENTICAL hold trivially** (zero `src/` footprint — verify `git diff <base> -- src/` is empty).
- ctest: 98/100 MVP-4.22 baseline preserved + 2 NEW ctests (TEST-H3 + TEST-H2). The 2 pre-existing env-fails (#48/#62) remain pre-existing. Final ~100/102 with sudo.
- `.github/workflows/ci.yml` present + honesty-note; `actionlint`-clean if the tool is available (else structural-review noted).
- VERSION unchanged (no bump).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies

- Build/test: existing toolchain; `bpftool` (present) for TEST-H3; `actionlint` OPTIONAL (tester checks `command -v`).
- Runtime: TEST-H3 needs root/CAP_BPF (sudo-gated like the prototype test). TEST-H2 must run sudo-FREE.
- Platform: GitHub Actions for C-3 (cannot be exercised here — HG-2 honesty gap).

## Packs to load (orchestrator: inject into spawn prompts)
```yaml
mode: brownfield
packs:
  architect:  [bpf]
  impl:       [bpf]
  tester:     [bpf-xdp]
  reviewer:   []
```

---

## Pre-brief sanity check (per mint-hld-scope-discipline)

**Mechanical — single-architect OK.** Goal fits one line ("close the 3 TEST-dimension High findings: CI + coverage-floor + production-verifier-load"). Not multi-axis: TEST-H3 is a mechanical clone of an existing test; TEST-H1 is a standard CI yaml; only TEST-H2 has a real mechanism fork (Q1) with a clear recommendation. Not expensive-to-undo (test-infra; deletable). The TEST-H1 "can't validate locally" is a known honesty caveat (HG-2), NOT a design-space uncertainty. No `/mint-hld` needed.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief author already ran these; architect re-verifies + extends:
- `ls .github` — confirm net-new (no existing workflow to merge with).
- `sed -n '40,120p' tests/T_BITVEC_VERIFIER_LOAD.sh` — read the prototype-load mechanism to clone for TEST-H3 (object path resolution under BUILD_DIR, `bpftool prog load … type xdp`, pin cleanup trap, SKIP-77 gating).
- `grep -n 'require_passwordless_sudo' tests/T_NEGATION_CONTROL.sh` — confirm the canary skips without sudo (TEST-H2 premise).
- `grep -c 'SKIP_RETURN_CODE 77' tests/CMakeLists.txt` (=66) + `grep -rl require_passwordless_sudo tests/T_*.sh | wc -l` (=88/100) — the masked-skip surface TEST-H2 addresses.
- Confirm `build/mac_filter.bpf.o` is the path the build emits (and how the CMake `add_bpf_object` names it) so TEST-H3 resolves it the way the prototype test resolves `bitvec_proto.bpf.o`.
- For TEST-H2 mechanism (Q1): grep how other tests read env vars + how `ctest` SKIP is wired, to pick the env-gate name + ensure the floor test is registered WITHOUT `SKIP_RETURN_CODE 77`.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep discipline)** — APPLIES (always). Architect repeats the greps above independently.
- **Guard #12 (RESOURCE_LOCK for shared host state)** — APPLIES to TEST-H3: it loads/pins a BPF prog under bpffs (a shared host path), like `T_BITVEC_VERIFIER_LOAD` (which uses a unique probe-pin + cleanup). Use a unique pin name + teardown trap; assess whether a RESOURCE_LOCK is needed (the prototype test's pattern is the precedent). TEST-H2 touches NO shared state (it inspects env/sudo only) → no lock.
- **Guard #11 (VERSION-bump test-literal propagation)** — N/A (no bump).
- Operative-semantic note: the "88/100", "3658 insns", "66× SKIP_RETURN_CODE" counts are SHOULD-level orientation for the reviewer's grep checks, not literal-match contracts (impl/tester may find the exact registration count shifts by ±1 as they add the 2 new tests).
