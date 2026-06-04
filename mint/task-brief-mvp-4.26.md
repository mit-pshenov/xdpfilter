# Task brief — MVP-4.26 / B33: rename mac_filter / xdpmacfilter → xdpfilter (brownfield)

## Goal

The artifact no longer filters only MAC — it is a 9-axis L2/L3 classifier. Purge
the "mac" misnomer: rename the whole `mac_filter` / `xdpmacfilter` / `mac_filter_prog`
surface to **`xdpfilter`** (the metrics are ALREADY `xdpfilter_*`, so this aligns
everything to that namespace; pairs with the user's `pktgate`). Mechanical-but-big
find-replace + `git mv`, verified end-to-end by a clean build + the full ctest suite
(a rename that misses a site fails the build / a fixture). B33 of the tidiness
workstream (B32 comment-collapse SHIPPED → **this rename** → B34 de-monolith split,
SEPARATE later).

## Context: prior work

- Prior slice: **MVP-4.25 / B32** (`1d31f51`) — comment-collapse; archived as `mint/task-brief-mvp-4.25.md`.
- Existing design: `mint/design.md` (most recent §5.65); this slice appends §5.66.
- Phase A code-grep verification (brief author — counts CORRECTED from the original ask):
  - `xdpmacfilter` = **371** occurrences (operator surface); `mac_filter` = 166; `mac_filter_prog` = **38** (security-coupled); `mac_filter.` (file refs) = 83.
  - **git mv targets**: `src/bpf/mac_filter.bpf.c`→`xdpfilter.bpf.c`, `src/common/mac_filter.h`→`xdpfilter.h`, + test fixtures `tests/fixtures/mac_filter_alt.bpf.c` / `mac_filter_bad.bpf.c` (architect: rename for consistency vs keep — HG-2).
  - **Skeleton/object ripple**: `src/lib/raii.hpp` `#include "mac_filter.skel.h"`; CMake `add_bpf_object(mac_filter …)` + `add_bpf_skeleton(mac_filter)` + `add_dependencies(xdpmf_internal mac_filter_skel)` → renaming the CMake object target `mac_filter`→`xdpfilter` propagates to `mac_filter.skel.h`→`xdpfilter.skel.h` AND `build/mac_filter.bpf.o`→`build/xdpfilter.bpf.o`; `skel->progs.mac_filter_prog` (loader.cpp) regenerates when the SEC() name changes.
  - **Security literal**: `src/lib/loader.cpp` `constexpr std::string_view kOwnedProgName{"mac_filter_prog"}` (the §5.19 name-check) + the `bpf_obj_get_info_by_fd(skel->progs.mac_filter_prog…).tag` self-tag capture.
  - **CMake special sites** (the brief's original ask MISSED these — surface to architect): `CMakeLists.txt project(xdpmacfilter …)`; the **§5.25 P2 bpffs-root extraction-assert** (`CMakeLists.txt` greps `mac_filter.h` for `XDPMF_BPFFS_ROOT` and ASSERTS it equals `"/sys/fs/bpf/xdpmacfilter"` — BOTH the header path AND the asserted literal change).
  - **Build-object-path tests**: `T_ATTACH_TAG_MISMATCH.sh` (`REAL_OBJ=${BUILD_DIR}/mac_filter.bpf.o`), `T_PROD_VERIFIER_LOAD.sh` (`PROD_BPF_OBJ=…/mac_filter.bpf.o`), `T_BITVEC_VERIFIER_LOAD.sh`.
  - **Repo-name in-tree refs**: ONLY `docs/BACKLOG.md:190` (this slice's own B33 entry — leave it). ci.yml / README / CHANGELOG do NOT hardcode the repo URL → the GitHub `gh repo rename` (external, post-ship) updates `.git/config` only.
  - **STAYS**: Prometheus metrics already `xdpfilter_*` (verified — no change); env-var spelling `XDPMF_*` STAYS (54 symbols, operator-ABI — PO decision, reinterpret acronym).
  - VERSION 0.15.0 sites (bump ripples here): `CMakeLists.txt`, `tests/T_EXPORTER_METRICS_FORMAT.sh`, `CHANGELOG.md` (guard #11).
- **PI continuity — NOTE**: **PI-7 (loader.hpp+config.hpp byte-identical) is EXPLICITLY SUSPENDED this slice** (HG-3): the `#include "common/mac_filter.h"`→`"common/xdpfilter.h"` path change lands in those headers — an unavoidable, documented rename diff, NOT an API change. **PI-DATAPATH-IDENTICAL** holds on the INSTRUCTION stream (xdp section stays 3658; the rename changes the prog SYMBOL/BTF name, not codegen — so the `.bpf.o` is NOT whole-file byte-identical, but the disassembled xdp instruction count is).

## Workflow rules (brownfield)

- **Architect**: read §5.65 tail + §6.5 invariants + guards #1..#33; EDIT `design.md`, append §5.66. Resolve HG-1 (VERSION), HG-2 (fixture rename), Q1 (prog-tag verification approach). Run the Phase A grep discipline (the CMake special sites + skeleton + security literal are the high-miss-risk spots).
- **Impl**: `git mv` the 2 (or 4) files; tree-wide find-replace `mac_filter`→`xdpfilter`, `xdpmacfilter`→`xdpfilter`, `mac_filter_prog`→`xdpfilter_prog` across src/ tests/ systemd/ ansible/ docs/ CMakeLists.txt cmake/ .github/ — EXCEPT the `XDPMF_*` env symbols (keep) and the metrics `xdpfilter_*` (already correct). Regenerate skeleton (build). Build clean. The `git mv` preserves history.
- **Tester**: NO new ctest. Phase B = full `sudo -E ctest` MUST stay 101/103 — ESPECIALLY the prog-name/object-path-coupled tests (`T_ATTACH_TAG_MISMATCH`, `T_VERIFIER_REJECT`, `T_PROD_VERIFIER_LOAD`, `T_LOAD_ATTACH`, `T_BITVEC_VERIFIER_LOAD`) must pass with the NEW prog name + object path. Confirm xdp section == 3658. Confirm NO surviving `mac_filter`/`xdpmacfilter` token outside the deliberate keeps (`grep -rIn 'mac_filter\|xdpmacfilter' src/ tests/ systemd/ ansible/ docs/ CMakeLists.txt cmake/ .github/` → only the BACKLOG B33 entry + any historical mint/ doc).
- **Reviewer**: 5-point brownfield. Special attention: (a) ZERO surviving `mac_filter`/`xdpmacfilter` token (completeness — a rename's failure mode is a MISS); (b) the §5.19 security name-check literal + fixtures updated consistently (prog identity gate still works); (c) the §5.25 CMake bpffs-root extraction-assert updated (path + literal); (d) behavior unchanged (full suite + xdp 3658); (e) `XDPMF_*` env + `xdpfilter_*` metrics UNtouched; (f) OOS: no B34 split, no logic change.

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.26-1: VERSION → **minor bump `0.15.0`→`0.16.0`** + CHANGELOG migration note
The rename changes OPERATOR-VISIBLE names (binary `xdpmacfilter`→`xdpfilter`, bpffs-root `/sys/fs/bpf/xdpmacfilter`→`/sys/fs/bpf/xdpfilter`, systemd unit `xdpmacfilter@`→`xdpfilter@`) — a breaking rename for any existing deployment (must re-create pins/units). That is release-worthy → minor bump + a CHANGELOG entry "renamed xdpmacfilter→xdpfilter (binary/bpffs-root/unit); existing pins+units must be re-created; metrics + config schema + env vars UNCHANGED". Bump ripples to `T_EXPORTER_METRICS_FORMAT.sh` (guard #11). Architect may keep 0.15.0 if it judges the rename non-release, but the operator-surface change argues for the bump.

### HG-mvp-4.26-2: file renames → **`git mv` (preserve history)**; test fixtures → rename for consistency
`git mv src/bpf/mac_filter.bpf.c src/bpf/xdpfilter.bpf.c` + `git mv src/common/mac_filter.h src/common/xdpfilter.h`. Default: ALSO rename `tests/fixtures/mac_filter_alt.bpf.c`/`mac_filter_bad.bpf.c` → `xdpfilter_alt`/`xdpfilter_bad` (they simulate alt/bad versions OF the product prog — consistency). Architect may keep the fixture names if the rename ripples awkwardly into the tag-mismatch test harness.

### HG-mvp-4.26-3: PI-7 → **EXPLICITLY SUSPENDED this slice** (documented, expected)
`loader.hpp`/`config.hpp` carry `#include "common/mac_filter.h"` → they NECESSARILY change to `"common/xdpfilter.h"`. This is a rename, not an API change — no symbol/signature change. Document the expected diff in §5.66 so the reviewer does not flag it; PI-7 resumes next slice.

### HG-mvp-4.26-4: `XDPMF_*` env spelling → **KEEP** (reinterpret acronym, do NOT rename)
`XDPMF_TRUST_MODEL`/`XDPMF_LOG_FORMAT`/`XDPMF_BPFFS_ROOT`/`XDPMF_*` macros stay (operator-ABI; 54 symbols). Add ONE note (in `xdpfilter.h` or docs) that `MF` now reads "Match/Multi-Filter". PO decision. The `XDPMF_BPFFS_ROOT` *value* changes (`/sys/fs/bpf/xdpmacfilter`→`/sys/fs/bpf/xdpfilter`) but the *symbol name* stays.

## Open mechanism questions (architect decides; document in §5.66)

### Q1: prog-TAG behavior verification (the security-sensitive bit)
Renaming `mac_filter_prog`→`xdpfilter_prog` changes the SEC() symbol → the skeleton accessor + the §5.19 name-check literal + the fixtures asserting the name STRING all change. The prog **self-tag** is the bytecode SHA-1 (name-independent — instructions stay 3658), so `T_ATTACH_TAG_MISMATCH`'s self-consistency holds; but VERIFY, don't assume.
- **A1** — rename + rebuild + run the 5 prog-coupled tests; if all green, the tag is confirmed name-independent. **Recommended** (the build IS the proof; no spike needed).
- **A2** — pre-spike: build both objects, `bpftool prog show` both tags, confirm equal before the full slice. Only if A1 surfaces a tag-dependent failure.
- **Recommendation**: A1. The full ctest is the verification; the prog-identity tests are the canaries.

## Scope (cycle 1 — concrete items)

### Item RN-1 — git mv the source files + fixtures
`src/bpf/mac_filter.bpf.c`→`xdpfilter.bpf.c`, `src/common/mac_filter.h`→`xdpfilter.h` (+ fixtures per HG-2). Fix every `#include` + the `raii.hpp` skeleton include.

### Item RN-2 — CMake (object target, project, bpffs-extraction-assert)
`add_bpf_object(mac_filter …)`/`add_bpf_skeleton(mac_filter)`/`mac_filter_skel`→`xdpfilter`; `project(xdpmacfilter)`→`project(xdpfilter)`; the §5.25 bpffs-root extraction-assert (header path + the asserted `/sys/fs/bpf/xdpmacfilter`→`/sys/fs/bpf/xdpfilter` literal); the binary target name.

### Item RN-3 — security prog-name (§5.19 / §5.22)
`mac_filter_prog`→`xdpfilter_prog` everywhere: the SEC() symbol in the bpf.c, `kOwnedProgName`, the skeleton accessor `skel->progs.*`, the self-tag capture comment, and the fixtures/tests asserting the name (`T_ATTACH_TAG_MISMATCH`, `T_VERIFIER_REJECT`, `xdp_pass.bpf.c` comment, `mac_filter_alt/bad.bpf.c`).

### Item RN-4 — operator surface + tests + docs
`xdpmacfilter`→`xdpfilter`: binary name, bpffs-root value `/sys/fs/bpf/xdpmacfilter`→`/sys/fs/bpf/xdpfilter`, systemd unit file + its contents, ansible, README/FLEET_DEPLOYMENT/CONFIG_SCHEMA, all ~45 test sites referencing the binary/root/object-path, VERSION bump (HG-1) + CHANGELOG migration note.

## Out of scope (explicit)

- **B34 de-monolith** (split `xdpfilter.bpf.c`/`xdpfilter.h` into `ipv4_match.h` etc.) — separate slice. This pass ONLY renames; it does NOT move code or split files.
- **GitHub `gh repo rename mint-filter→xdpfilter`** — EXTERNAL op, done by the orchestrator AFTER this ships (updates `.git/config` remote). In-tree has no repo-URL hardcode to change (only the BACKLOG B33 note, which stays).
- **`XDPMF_*` env symbol rename** (HG-4 keep) / **metrics rename** (already `xdpfilter_*`).
- Any logic / behavior / map-layout / schema / datapath-instruction change. It is a pure rename.

## Definition of done

- §5.66 amendment in `design.md` (the rename map + HG-1..4 + Q1 + the PI-7-suspended note + candidate guard #34 "operator-surface rename = minor bump + migration note + the CMake bpffs-extraction-assert is a high-miss site").
- **PI-DATAPATH-IDENTICAL** (xdp section 3658 insns) holds; **PI-7 SUSPENDED** (HG-3, documented).
- ctest: 101/103 baseline preserved — the 5 prog-name/object-path-coupled tests GREEN with new names; the 2 pre-existing env-fails by NAME unchanged.
- **Completeness**: zero surviving `mac_filter`/`xdpmacfilter`/`mac_filter_prog` token in src/ tests/ systemd/ ansible/ docs/ CMakeLists.txt cmake/ .github/ (except the BACKLOG B33 entry + historical `mint/` docs). `XDPMF_*` env + `xdpfilter_*` metrics intact.
- VERSION 0.16.0 (HG-1) consistent across CMakeLists + T_EXPORTER_METRICS_FORMAT + CHANGELOG.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary (the impl commit will be large but is a pure rename — `git diff -M` shows the moves).

## Dependencies

- Build/test: existing toolchain; full ctest needs root. `git mv` for history.
- Post-ship (orchestrator, external): `gh repo rename` + verify `git remote -v`.
- Platform: unchanged.

## Packs to load (orchestrator: inject into spawn prompts)
```yaml
mode: brownfield
packs:
  architect:  [cpp, bpf, cmake]
  impl:       [cpp, bpf, cmake]
  tester:     [cpp, bpf-xdp]
  reviewer:   [cpp]
```

---

## Pre-brief sanity check (per mint-hld-scope-discipline)

**Mechanical — single-architect OK.** Goal fits one line ("rename the mac-bearing surface to xdpfilter"). NOT multi-axis: it is a find-replace + `git mv`; no design space, no novel mechanism. The decisions are routine (VERSION bump default, git-mv, fixture-rename, PI-7-suspend-note) — none is expensive-to-undo (a rename is git-revertable) and none has ≥3 viable design options. The ONLY sensitive spot (prog-name → security gate) is a VERIFICATION (Q1/A1: the build + 5 prog-coupled tests prove it), not a design choice. No `/mint-hld`. Large in token-count but uniform in operation — one slice (splitting would create ugly half-renamed inconsistent intermediate states; the full build+ctest is the atomic verification).

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief author already ran these; architect re-verifies + extends:
- `grep -rIn 'mac_filter_prog' src/ tests/` — the security prog name (38 sites): the `kOwnedProgName` literal, `skel->progs.mac_filter_prog`, the SEC() symbol, fixtures.
- `grep -rIn 'mac_filter' CMakeLists.txt cmake/` — the object target / skeleton / bpffs-extraction-assert / project name (the HIGH-MISS sites the original ask omitted).
- `grep -rIn 'xdpmacfilter' CMakeLists.txt src/cli systemd/ ansible/` — binary name + bpffs-root + unit.
- `grep -rln 'mac_filter\.bpf\.o\|/sys/fs/bpf/xdpmacfilter' tests/` — the object-path + pin-path coupled tests (guard #16 symmetric-consumer class).
- After the rename: full build → `llvm-objdump-19 -d --section=xdp build/xdpfilter.bpf.o | grep -cE '^\s+[0-9a-f]+:'` == 3658; then the completeness grep (zero surviving tokens).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep discipline)** — APPLIES (always); rename completeness depends entirely on grep thoroughness.
- **Guard #11 (VERSION-bump test-literal propagation)** — APPLIES (HG-1 bump → `T_EXPORTER_METRICS_FORMAT.sh` + CHANGELOG; grep `0\.15\.0` and `0\.16\.0` consistency post-bump).
- **Guard #16 (retired pin-path / map-name ripple)** — APPLIES: the bpffs-root path `/sys/fs/bpf/xdpmacfilter`→`/sys/fs/bpf/xdpfilter` is the canonical pin-path; every test/CMake site reading it must follow (the §5.25 extraction-assert is the load-bearing one).
- **Guard #13 (fixture cross-reference)** — APPLIES: the prog-name STRING in `T_ATTACH_TAG_MISMATCH`/`T_VERIFIER_REJECT` + the `mac_filter_alt/bad.bpf.c` fixtures + `xdp_pass.bpf.c` comment.
- **Guard #12 (RESOURCE_LOCK)** — N/A (no new ctest).
- Operative-semantic note: the "371 / 166 / 38" counts are orientation; the binding contract = ZERO surviving token (completeness) + behavior-identical (full suite + xdp 3658) + the deliberate keeps (`XDPMF_*`, `xdpfilter_*` metrics) untouched.
