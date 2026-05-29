# Review — MVP-4.9 cheap-wins (B18 port_scan break + B19 build_cpu lock) (mint triangulation)

## Verdict
`pass` (round 1, 0 findings, 0 OOT)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — (NEW ctests=0 per TestStrategy; existing oracle net is the fence) |
| 3. Code ↔ Tests | 0 | — (7/7 green on load-bearing subset) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — (all 8 §6.5 PIs hold) |

Diff is exactly 3 files, 31 insertions / 6 deletions; working tree clean.

## Point 1 — Spec ↔ Code
- **B18 break**: `mac_filter.bpf.c:519-523` — the `r->lo > r->hi` sentinel `continue`→`break`, EXACTLY one keyword. The `!r` null-check `continue` at `:516-518` UNTOUCHED (PI-mvp-4.9-NULL-CHECK-STAYS). Exactly ONE `continue` + ONE `break`.
- **Unroll + bound intact**: `:512-513` `#pragma unroll` + `for (i < XDPMF_ALLOWLIST_MAX)` straight-line, no back-edge.
- **Guard #26 two-end doc**: consumer comment `mac_filter.bpf.c:498-508` + producer comment `loader.cpp:1602-1613` both document the dense-pack + `lo<=hi` coupling.
- **B19 lock**: `tests/CMakeLists.txt:80` `RESOURCE_LOCK build_cpu` on T_BUILD; `:139` `"xdp_fixture;build_cpu"` on T_SANITIZER_BUILD (xdp_fixture PRESERVED). Corroborated in generated `build/tests/CTestTestfile.cmake:8,24`.
- VERSION stays `0.15.0` (D-mvp-4.9-NO-BUMP).

## Point 2 — Spec ↔ Tests
NEW ctests = 0 per TestStrategy; B18 fenced by the existing full-walk-oracle net, B19 by the `-j4` run. Oracle asserts the stated outcome (bit-identical port verdict via independent O(N) oracle), not code-shape → no [CIRCULAR-TEST]. Negation controls carried by existing suite.

## Point 3 — Code ↔ Tests
Rebuilt + ran the load-bearing subset under `sudo ctest -j4`: T_SANITIZER_BUILD, T_AND6/5/4_ORACLE_AGREEMENT, T_PORT_RANGE_AND_COMPOSE, T_AND_ORACLE_AGREEMENT, T_BUILD → 7/7 Passed. `port_scan` is `static __always_inline`, exercised via inject→counter→oracle → no [UNEXERCISED-EXPORT].

## Point 4 — OOS drift
Only the 3 FileList paths touched. No cidr6/IPv6-matching/PROCESSORS code (the IPv6 hits at `mac_filter.bpf.c:15,616` are PRE-EXISTING ethertype-fastpath comments). S8 fence intact.

## Point 5 — Behaviour preserved
- PI-mvp-4.9-PORT-MATCH-EQUIV: oracle net GREEN → break bit-identical. ✓
- PI-mvp-4.9-DENSE-PACK: `config.cpp:199` `lo>hi` rejection UNCHANGED; loader clear-then-dense-write CODE unchanged (comment-only edit). ✓
- PI-mvp-4.9-B19-LOCK: `grep -c build_cpu tests/CMakeLists.txt` = 2; -j4 serialization empirically observed (T_BUILD started only after T_SANITIZER_BUILD finished; never co-ran). ✓
- UNCHANGED-BUT-AFFECTED: `git diff HEAD` EMPTY for config.cpp, mac_filter.h, loader.hpp, T_BUILD.sh, T_SANITIZER_BUILD.sh, CMakeLists.txt → no [UNRELATED-EDIT]. ✓
- No [REGRESSION] vs MVP-4.8 baseline (`0265bcb`); tester full log = 85 tests, 0 fail, 2 env-skip.

## Impl's 1 documented deviation — adjudicated COMPLIANT (not a finding)
The T_BUILD comment (`tests/CMakeLists.txt:69-72`) references "the shared compile-serialization RESOURCE_LOCK (see below)" WITHOUT naming the literal `build_cpu` token, to keep `grep build_cpu` = exactly 2 hits (PI-mvp-4.9-B19-LOCK). Sanctioned by D-mvp-4.9-PROSE-VS-INVARIANTS (invariants win over prose hints; disposition inline-merge). §6.5 invariant satisfied; not [UNRELATED-EDIT]/[SPEC-DRIFT]. No finding, not even OOT.

## Test execution (tail, /tmp/mint-review-tests-1780081982.log)
```
1/7 Test  #9: T_SANITIZER_BUILD ................   Passed  170.65 sec
2/7 Test #84: T_AND6_ORACLE_AGREEMENT ..........   Passed   15.42 sec
3/7 Test #83: T_AND5_ORACLE_AGREEMENT ..........   Passed   23.00 sec
4/7 Test #80: T_AND4_ORACLE_AGREEMENT ..........   Passed   20.07 sec
5/7 Test #79: T_PORT_RANGE_AND_COMPOSE .........   Passed   15.96 sec
6/7 Test #75: T_AND_ORACLE_AGREEMENT ...........   Passed   13.12 sec
7/7 Test  #1: T_BUILD ..........................   Passed  111.78 sec
100% tests passed, 0 tests failed out of 7
```
(T_BUILD #1 started only after T_SANITIZER_BUILD #9 completed — build_cpu mutual-exclusion confirmed.)

## Rework assignments
None — clean pass.

## Out-of-triangulation findings
None.

Tester full Phase B run: 83/85 pass, 0 fail, 2 env-skip (T_DROP_MALFORMED, T_ANSIBLE_PLAYBOOK_SYNTAX) → mint/test-run.log. -j4 contention flake structurally resolved.
