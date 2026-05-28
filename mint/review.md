# Review — MVP-4.2 bit-vector AND-classification SPIKE (mint triangulation)

## Verdict: pass (round 1)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — (negation control: V9) |
| 3. Code ↔ Tests | 0 | — (T_BITVEC 2/2 PASS on reviewer re-run) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — (all PI fences empty) |

No findings. No out-of-triangulation items.

## Point 1 — Spec ↔ Code
- 7 prototype maps (`bitvec_proto.bpf.c:64-113`) match §5.42 DataStructures: bv_dst_lpm/bv_src_lpm LPM_TRIE+NO_PREALLOC, bv_proto_hash HASH(8), bv_port_ranges ARRAY, bv_wildcard ARRAY[4], bv_action ARRAY u8, bv_result PERCPU_ARRAY[65]. `struct bv_port_range{lo,hi,bit}` per spec.
- AND-compose datapath (`:277-280`): `acc=(lpm(dst)|wc0)&(lpm(src)|wc1)&(proto|wc2)&(port|wc3)` verbatim §5.42 Interfaces #1; `acc==0→NOMATCH→XDP_PASS`; `rid=ffsll(acc)-1`; action dispatch.
- FI-1 prefix-closure (`bitvec_harness.cpp:106-123`) cover-direction CORRECT (less-specific flows into more-specific). Hand-verified 10.1.2.128/25→{0,1,2,8}.
- FI-4 range inclusivity + ICMP-no-port; FI-2 wildcard mutual-exclusion (exactly one per axis); unused-port sentinel lo=1,hi=0.
- D-mvp-4.2-FFS-FEAS held: llvm-nm/objdump → NO __ffsdi2/__ctzdi2; no bpf_loop; __builtin_ffsll inlined; fallback compiled-but-unused.
- Isolation honored: separate types header, separate bpffs root /sys/fs/bpf/xdpmf-bitvec-proto, maps NOT in kManagedMaps[].

## Point 2 — Spec ↔ Tests
- §6.45 T_BITVEC_ORACLE_AGREEMENT: full V1–V11, each asserts datapath matched-id == live oracle prediction; asserts exactly one slot bumps + non-target-drift guard.
- Negation control present & enforced: V9 (NOMATCH) + saw_negation sanity-floor (suite FAILS if no NOMATCH vector ran).
- Oracle independence verified: bitvec_oracle.py is naive O(N) ascending-id scan, NO bitmask/closure/ffsll/range-table; canonical set hand-transcribed (not read from canonical_ruleset.inc). NOT circular.
- §6.46 T_BITVEC_VERIFIER_LOAD: rc=0 via standalone bpftool prog load + harness populate.

## Point 3 — Code ↔ Tests (reviewer re-ran)
- Rebuilt + `ctest -R T_BITVEC -V`: 2/2 PASS (8.34s + 0.93s). All 12 vectors matched oracle incl. V1 first-match-tie (r0 DROP beats more-specific r8 PASS), V3/V6 range-edge misses, V7 ICMP port-wildcard, V10a/b src-LPM flip, V9 negation. Log /tmp/mint-review-tests-1780011407.log.

## Point 4 — OOS drift: none
grep of tests/bitvec/ + inject_l4.py for schema_version|active_idx|exporter|rule_match_total|ACTION_MIRROR|ipv6|AF_INET6 → only comment hits documenting deliberate non-goals. No §7 OOS fence implemented.

## Point 5 — Behaviour preserved (brownfield, all PI GREEN)
- git diff a638433 --stat: changes ONLY in CHANGELOG.md, mint/{design,impl-notes}.md, tests/CMakeLists.txt, the 2 test scripts, tests/bitvec/*, tests/inject/inject_l4.py. Zero src/** change.
- Every fence empty: mac_filter.bpf.c, mac_filter.h, loader.hpp, config.hpp, src/lib/, src/cli/, src/exporter/, cmake/BpfBuild.cmake, vmlinux.h, top CMakeLists.txt, existing injectors, tests/lib/, tests/fixtures/ — 0-line. PI-7 loader.hpp/config.hpp ZERO-diff continues.
- kManagedMaps 7→7 (PI-mvp-4.2-ISOLATION). CMakeLists diff purely additive (isolated bitvec block, RESOURCE_LOCK xdp_fixture + SKIP_77).
- PI-mvp-4.2-PROD-70-GREEN: tester test-run.log 70/72 green; the 2 -j4 failures (T_SANITIZER_BUILD timeout + cascaded T_BPFFS_ROOT_SYMLINK) confirmed PASS on serial re-run after orphan cleanup = documented pre-existing environmental flake. All-additive slice → production regression structurally impossible. No REGRESSION/INVARIANT-VIOLATED/UNRELATED-EDIT.

## Complexity verdict assessment (headline deliverable — SUBSTANTIATED)
The §5.42 "TRACTABLE, lean ADOPT" verdict is substantiated, independently re-confirmed:
- ffsll FEAS held (verifier rc=0, no libcall, fallback never activated).
- FI-1 prefix-closure clean first-try (overlap V1/V2/V11 + first-match-tie green, zero rework spiral, no escalation peer-DM).
- Range-via-A2-scan works (V3–V6 edge behavior) — confirms the "ranges are awkward" cost caveat without being a blocker.
- Full oracle↔prototype agreement 12/12 incl. negation. FI-7 (×2 atomic-swap) correctly deferred to S3.
- Loader-side bug-surface = ~24-LOC close_prefixes + derivation — bounded/teachable at N≤64.
The "very hard → sequential" escape (closure spiral / verifier reject) did NOT trigger. **Evidence supports ADOPT bit-vector for S3.**

## Test execution (tail)
```
1/2 Test #71: T_BITVEC_ORACLE_AGREEMENT ........ Passed 8.34 sec
2/2 Test #72: T_BITVEC_VERIFIER_LOAD ........... Passed 0.93 sec
100% tests passed, 0 tests failed out of 2
```

## Rework assignments
None — clean pass.

## PO decision pending (S3 gate — for the morning)
The spike's deliverable: **bit-vector is the recommended lowering for the S3 production AND-landing** (ADOPT). The PO's "bit-vector unless very hard → else sequential" rule resolves to bit-vector. S3 owes: v2 config schema/parser (dst_ip/protocol/dst_port), Rule IR emission, schema_version:2 hard-cutover, the per-axis ×2 wildcard atomic-swap (FI-7, deferred here), exporter wiring. Sequential remains the documented escape hatch (not built).
