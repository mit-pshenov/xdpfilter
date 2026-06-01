# Review — MVP-4.22 robustness hardening batch (mint triangulation)

## Verdict
`pass` (round-1, 0 findings, 0 out-of-triangulation)

Base for all diffs: `f4f3308` (parent of the design commit; src-identical to HEAD~2).

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

## Point 1 — Spec ↔ Code (all R-1..R-5 honor the §5.62 contract)
- **R-1** ✓ `validate_iface_name(..., LoaderError::PathRefused)` is the FIRST statement of `detach` (`loader.cpp:2209`) AND `apply_request` (`loader.cpp:2322`); exit 8 / `refusing to operate` token reused. `attach` covered transitively (`attach`→`apply_request`). Doc-comment "Not retrofitted this slice" retired (`loader.cpp:514-517`). No `loader.hpp` symbol added.
- **R-2** ✓ `mac_filter.h:345-362` — 7 `static_assert(sizeof)` (6/8/20/16/4/4/8) + 2 `offsetof` (`xdpmf_port_range.bit==8`, `allow_entry.rule_id==4`), inside `#ifdef __cplusplus extern "C"`, `#include <cstddef>`. Sizes match design DataStructures exactly. BPF (`-target bpf`, C) compile skips them → `mac_filter.bpf.o` rebuilt clean, xdp section **3658 insns** (unchanged). `allow_entry` honestly noted vestigial in the assert string.
- **R-3** ✓ pre-multiply guard `v > (uint64_max - 9)/10` added to BOTH accumulators (`config.cpp:90` parse_u32_or_throw, `config.cpp:153` parse_bounded_uint); post-checks kept. Cannot reject in-range maxima. Honest defense-in-depth framing in comment. `config.hpp` zero-diff.
- **R-4** ✓ `g_format` → `std::atomic<Format>` (`logger.cpp:44`), `#include <atomic>`; ALL sites consistent: stores at `:78/:82/:86/:92/:245` relaxed, load at `:268` relaxed. Recursive-emit queued-WARN guard preserved (still observes settled `Text`). No `logger.hpp` Format/g_format change.
- **R-5** ✓ two-arm catches with trailing `catch(...)` backstop retained at both never-throw sites: `sidecar.cpp:556`+`:572` (reuses `sidecar.warn.write_exception`, std arm adds `e.what()`); `sidecar_reader.cpp:104`+`:123` (NEW `exporter.scrape.warn.sidecar_read_exception`, both arms). `emit()` is `noexcept` (logger.hpp:177/185) ⇒ no throw escapes the std arm. Inner `:81` stoul catch + logger `:224`/`:242` catches LEFT byte-identical (absent from diff).

## Point 2 — Spec ↔ Tests
- §6.77 `T_IFACE_SHAPE_REJECT_APPLY_DETACH` — apply(a/b) + detach(c/d) → exit 8 + token; **negation (e)** valid name must NOT trip gate. Asserts stated outcome, not code-shape.
- §6.78 `T_CONFIG_INT_OVERFLOW_REJECT` — oversized id/protocol/dst_port/vlan → exit 9 + overflow-message discriminator; **parity control** in-range maxima → `rc!=9` (uses `ID_PARITY_MAX=4294967294` per EDIT-1; plus separate B30 sentinel `0xFFFFFFFF→9` check). Root-free/lock-free via nonexistent iface (EDIT-3).
- §6.79 `T_SIDECAR_READ_EXCEPTION_DIAGNOSTIC` — deterministic never-throw core (a: corrupt/missing/dir → /metrics 200, no crash) is load-bearing; **negation** baseline clean scrape emits 0 events. (b) event-fire DROPPED per EDIT-4 (the long-line lever is a SIGSEGV on OOS B27 DoS, not a catchable throw) — correctly NOT tested. Event existence pinned by catalog-stability test.
- Catalog stability green at 38; no CIRCULAR-TEST; every suite carries a negation control → no NO-NEGATION-CONTROL.

## Point 3 — Code ↔ Tests
Build: ZERO warnings on forced recompile of all 7 edited TUs (clang-19 -Wall -Wextra -Wpedantic -Wconversion -Wshadow). Targeted run 4/4 pass (`/tmp/mint-review-tests-mvp422.log`):
```
T_LOG_EVENT_CATALOG_STABILITY ......... Passed
T_IFACE_SHAPE_REJECT_APPLY_DETACH ..... Passed
T_CONFIG_INT_OVERFLOW_REJECT .......... Passed
T_SIDECAR_READ_EXCEPTION_DIAGNOSTIC ... Passed
100% tests passed, 0 failed out of 4
```
No new public export; `detach` exercised, R-2 asserts are compile-time (green build IS the assertion).

## Point 4 — Out-of-Scope Drift
Footprint = exactly the FileList (7 src + 3 new tests + CMakeLists + fixture). No `src/bpf/` change, no B27 regex/DoS touch, no B26 `pass_cidr`, no schema/axis/map, no VERSION/CHANGELOG/root-CMakeLists change. §6.79(b) DoS lever explicitly dropped, not fed to a live exporter. No OOS-DRIFT.

## Point 5 — Behaviour preserved (brownfield)
- **PI-7**: `git diff f4f3308 -- src/lib/loader.hpp src/lib/config.hpp` = ∅ ✓
- **PI-DATAPATH-IDENTICAL**: `mac_filter.bpf.c` diff ∅; xdp insn count **3658** ✓
- **PI-NEVER-THROW (guard #30)**: grep audit — every `catch(const std::exception&)` immediately followed by trailing `catch(...)`; inner stoul + both logger catches byte-identical ✓
- **PI-CATALOG**: kEventNames 37→38, kEventCount 38, fixture 38 lines (sorted), catalog test green ✓
- **PI-ABI / PI-10**: `mac_filter.h` diff = ONLY the additive assert block; no struct/enum/define body change ✓
- **PI-LOGGER-HPP-FORMAT**: `logger.hpp` diff = ONLY the +1 catalog entry + 37→38 count bumps ✓
- **REGRESSION fence**: tester's `test-run.log` = 98/100 (#48/#62 fail, 2 baseline skips). Reviewer reproduced #48/#62 — BOTH fail on the SAME pre-existing environmental cause: the HK-17 "all-interfaces-EACCES → exit 6" path is not inducible in this sandbox (`/sys/fs/bpf/xdpmacfilter` unmounted; exporter `Killed`/999 instead of self-exiting 6). The slice touched `sidecar_reader.cpp`, NOT the iface-discovery/exit-6 path → NOT a regression. No UNRELATED-EDIT, no INVARIANT-VIOLATED.

## Out-of-triangulation findings
None.

All three artifacts agree. Clean round-1 pass.
