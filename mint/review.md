# Review — MVP-2 Polish-2: §5.25 netns + CMake-gen PIN_ROOT + version-sync + inject_runt:37 (mint triangulation)

## Verdict
**pass**

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |

Plus 4 OUT-OF-TRIANGULATION informational items (3 stale `ip netns exec` doc-wording artifacts surviving EDIT-15 — all 3 now swept inline post-review; 1 deferred CHANGELOG Build-pace row — orchestrator chore per precedent). All non-blocking.

---

## Triangulation evidence (all green)

### 1. Spec ↔ Code

- **A1 — CMakeLists.txt** (`CMakeLists.txt`): VERSION 0.1.0→0.2.3 ✓; `configure_file(version.h.in)` ✓; `execute_process(sed)` + FATAL_ERROR fail-fast ✓; `configure_file(pins.sh.in)` ✓; `target_include_directories` non-SYSTEM ✓.
- **A2 — include/version.h.in:1-4** ✓ — `#define XDPMF_VERSION_STRING "@PROJECT_VERSION@"`.
- **A3 — tests/lib/pins.sh.in:1-3** ✓ — `PIN_ROOT="@XDPMF_BPFFS_ROOT@"`.
- **A4 — src/loader/cli.cpp**: git diff shows EXACTLY 3 spec'd edits — `+#include "version.h"`, `-kVersion` constant, swap to `XDPMF_VERSION_STRING`. NO other functional changes ✓.
- **A5 — Impl byte-identical invariants**: `loader.hpp`/`loader.cpp`/`raii.hpp`/`cli.hpp`/`main.cpp`/`src/bpf/`/`src/common/` ZERO deltas ✓.
- **A6 — CHANGELOG.md** new `## [0.2.3] — 2026-05-23` block above `## [0.2.2]` ✓.
- **Generated artifacts verified**: `build/include/version.h` → `XDPMF_VERSION_STRING "0.2.3"`; `build/tests/pins.sh` → `PIN_ROOT="/sys/fs/bpf/xdpmacfilter"`; `./xdpmacfilter --version` → `xdpmacfilter 0.2.3` ✓.

### 2. Spec ↔ Tests

- **T1 — common.sh NETNS/NSEXEC** ✓ — EDIT-15 form (`nsenter --net=…`, NOT `ip netns exec`), mount-ns preservation honored. PIN_ROOT sourced from generated pins.sh via `source` + `:?` integrity guards.
- **T2 — setup_veth body** ✓ — defensive netns-del + rm-rf → ip netns add → preflight NSEXEC → veth pair in netns → sysctl/ifup NSEXEC-prefixed → quiesce.
- **T3 — cleanup_veth body** ✓ — ip netns del (atomic) + rm-rf PIN_DIR (bpffs host-global).
- **T4 — inject_eth/inject_runt/xdp_prog_id NSEXEC-prefixed; read_stats/wait_for_stats_sum/prog_count UNCHANGED** ✓.
- **T5 — tests/CMakeLists.txt TEST_ENV PINS_SH** ✓.
- **T6 — 13-test ENTER roster** ✓ — `grep -l 'setup_veth'` yields exactly the EDIT-13 set; per-test audit confirms every loader/xdpgeneric/ip-j-link-show invocation is NSEXEC-prefixed.
- **T7 — 7-test STAY roster** ✓ — T_BUILD/T_CLI_*/T_DETACH_NOTHING/T_MODE_NATIVE_UNSUPPORTED/T_MODE_DETACH_REJECTS have ZERO NSEXEC references.
- **T8 — T_VERIFIER_REJECT env-after-NSEXEC idiom** ✓ — `${NSEXEC} env XDPMF_BPF_OBJECT_PATH=… "${LOADER_BIN}" …` matches EDIT-14.
- **T9 — inject_runt.py:37 comment** ✓ — exactly one comment line changed; byte literals + socket.send + imports UNCHANGED.
- **Negation control preserved** — T_NEGATION_CONTROL in ENTER roster, swept correctly, still WILL_FAIL TRUE.

### 3. Code ↔ Tests

- Re-built + re-ran ctest on dev host: 20/20 (19 PASS + 1 expected SKIP T_DROP_MALFORMED). Total 97.02s. Same partition as tester's mint/test-run.log.
- `xdpmacfilter --version` → `xdpmacfilter 0.2.3` ✓.
- C1-C5 all green: version-sync, pins.sh codegen, version.h codegen, 20/20 ctest, pre-existing stderr discipline preserved across all 13 NSEXEC-swept tests.
- LSP findReferences on `XDPMF_VERSION_STRING` confirms one usage at cli.cpp:103 + end-to-end exercise via T_CLI_HELP_VERSION. No `[UNEXERCISED-EXPORT]`.

### 4. Out-of-Scope Drift

- §7 MVP-1.1C OOS — 3 deferred items + 1 advisory all SHIPPED in §5.25 with cross-references ✓.
- §7 MVP-2 Polish-2 OOS additions sub-section explicit ✓.
- Touched-files audit: exactly the brief-spec'd surface; ZERO drift outside the 13-test ENTER roster + impl scope.

---

## OUT-OF-TRIANGULATION informational items (post-review sweep)

3 of 4 resolved inline by team-lead post-review (per established orchestrator-Edit precedent for doc-wording fixes — MVP-2 Robust EDIT-12 pattern):

1. **§7 OOS shipped-entry NSEXEC wording (design.md:3036)** — updated to `nsenter --net=/var/run/netns/${NETNS}` per EDIT-15.
2. **CHANGELOG.md:13 first bullet NSEXEC wording** — updated to `nsenter --net=…` with EDIT-15 cross-reference.
3. **T_VERIFIER_REJECT.sh:129-133 inline comment** — updated to mention EDIT-14 + EDIT-15 NSEXEC corrections.

4th item (CHANGELOG Build-pace row for MVP-2 Polish-2) — orchestrator adds in post-review chore commit per `11d0146` precedent.

---

## Test execution

20/20 PASS round 1 (19 PASS + 1 expected SKIP T_DROP_MALFORMED). Reviewer re-run idempotent vs tester's mint/test-run.log.

## Summary

Final MVP-2 slice delivered cleanly. 4 janitorial items (netns isolation per Q1=N3, CMake-gen PIN_ROOT per Q2=C1, version-string sync per Q3=V1 + project VERSION bump 0.1.0→0.2.3, inject_runt:37 comment per P4) — all spec'd correctly, all in-spec, all green. Phase B exercised 3 substantive empirical findings (EDIT-13 opt-out roster, EDIT-14 env-after-NSEXEC idiom, EDIT-15 mount-ns preservation via nsenter) — all merged inline; design.md canonical.

After this commit MVP-2 is fully complete; project enters MVP-3 territory.

**Verdict: `pass`. No rework needed.**
