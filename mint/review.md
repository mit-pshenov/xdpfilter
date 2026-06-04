# Review — MVP-4.29 / B34b datapath module split (mint triangulation)

## Verdict
`pass` (round 1)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — (D-mvp-4.29-NOTEST sanctioned) |
| 3. Code ↔ Tests | 0 | — (1 flake, non-regression, see OOT) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

## What was verified (load-bearing question: is this a PURE BYTE-IDENTICAL #include split?)

**YES — proven, not assumed.**

**MOVE-ONLY (PI-mvp-4.29-MOVE-ONLY) — byte-for-byte against `git show 8c9a110:src/bpf/xdpfilter.bpf.c`:**
- `defs.h` body (12–71) ≡ orig `:28–87` → IDENTICAL
- `maps.h` body (15–386) ≡ orig `:89–460` → IDENTICAL
- `classifier.h` body (21–287) ≡ orig `:462–728` → IDENTICAL
- `.bpf.c` header+includes (1–26) ≡ orig 1–26 → IDENTICAL
- `.bpf.c` program body (31–581) ≡ orig `:730–1280` (SEC, 3 inline arms, `__license`) → IDENTICAL
- Only new bytes: `#pragma once` + doc-comment + self-includes per header, + 3 `#include` lines in `.bpf.c`. Nothing reshaped/renamed/re-macroed (guard #36/#37 satisfied).

**Insn count (PI-mvp-4.29-DATAPATH-IDENTICAL) — third independent measurement:** rebuild → `llvm-objdump-19 -d --section=xdp build/xdpfilter.bpf.o | grep -cE '^\s+[0-9a-f]+:'` = **3658** ✓; `T_INSN_BASELINE_GATE` + `T_PROD_VERIFIER_LOAD` both PASS.

**Include order (PI-mvp-4.29-ODR):** `defs.h`→`maps.h`→`classifier.h` (`src/bpf/xdpfilter.bpf.c:27–29`) ✓.

**HG-2 (D-mvp-4.29-CMAKE):** `cmake/BpfBuild.cmake` diff = exactly one line (`+ ${CMAKE_SOURCE_DIR}/src/bpf/*.h` in `_shared_headers`). `touch src/bpf/maps.h` → rebuild re-runs BPF compile ✓.

**Diff fences (PI-mvp-4.29-NONDATAPATH-ZERO + PI-7):** `git diff 8c9a110 -- src/lib src/common src/cli src/exporter src/common/xdpfilter.h CMakeLists.txt tests/` = ∅ ✓. New files ONLY under src/bpf/. VERSION unchanged (0.16.0).

**HG-1 / OOS:** no `ipv4_match.h`/`ipv6_match.h`/`vlan.h`; 3 family arms stayed inline (`.bpf.c` v4 `:97`, v6 `:271`, non-IP `:464`); no schema/axis/map/VERSION change.

## Test execution
- `/tmp/mint-review-tests-1780581986.log`
- B37 gates PASS (xdp==3658). Full `sudo -E ctest`: 2 skip (T_DROP_MALFORMED, T_ANSIBLE_PLAYBOOK_SYNTAX), 2 known env-fails BY NAME (#48 T_EXPORTER_EXITS_6_ALL_IFACES_EACCES, #63 T_LOG_JSON_EXPORTER_EVENTS) — baseline-matched, PI-6 holds.

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] T_EXPORTER_METRICS_FORMAT flaked under full-parallel run → `defer`
**Location**: test #40 (exporter suite — NOT touched by this slice).
**Evidence**: failed once in reviewer's 705s full-parallel `ctest`; green in tester's `mint/test-run.log`; re-ran isolated → Passed (10.5s). `git diff 8c9a110 -- src/exporter` = ∅ (exporter byte-identical, not recompiled) — a src/bpf header split cannot causally affect exporter metrics formatting. Classified flaky/resource-contention, NOT [REGRESSION].
**Disposition**: `defer` — pre-existing exporter-suite flakiness under parallel load, orthogonal to B34b. Does not block this slice.

## Result
No rework. Clean byte-identical #include split; all 5 brownfield points green.

### Deferred to next slice
- **T_EXPORTER_METRICS_FORMAT (#40) parallel-run flakiness** — exporter metrics test flakes under full `-j` ctest contention (passes isolated; exporter source ∅-diff this slice). Candidate backlog item: add RESOURCE_LOCK / serialize the exporter metrics tests, or investigate the contention source. Orthogonal to the datapath; surfaced during B34b review only as a parallel-load artifact.
