# Review — MVP-4.19 sanitize 9-axis lowering (B22, test-only) (mint triangulation)

## Verdict
`pass`  (round 1, 0 findings, 0 out-of-triangulation)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — (test-only; src/ contract = empty fence, verified) |
| 2. Spec ↔ Tests | 0 | — (negation control present) |
| 3. Code ↔ Tests | 0 | — (ran it: PASS, ASAN-clean, "0 1 0 2") |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — (src/ diff ∅, suite 96/96) |

## Evidence per point

**1. Spec ↔ Code.** Slice is TEST-ONLY (§5.59). Load-bearing contract `git diff -- src/` = ∅, verified two ways: working tree clean + `git show dd35da9 -- src/ | wc -l` = 0. Commit touched exactly one file — `tests/T_SANITIZER_BUILD.sh` (+70/-24); `src/`, `tests/lib/common.sh`, `tests/CMakeLists.txt` all 0-delta. PI-7 (loader.hpp byte-identical) continues trivially. Net-new lowering (close_prefixes6 `__int128`/host_mask6 shift, port-range, v6 LPM populate, write_wildcard_slots, aggregate_axis/populate_hash_inner_slot) lives in `src/lib/loader.cpp` — unchanged, exercised via the richer apply, not modified.

**2. Spec ↔ Tests.** All 6 TestStrategy items mapped:
- Sanitizer clean-run → `:181` negation-form `grep -q -E 'AddressSanitizer|UndefinedBehavior'` (match=fail), RETAINED, fires over apply+detach stderr.
- Positive correctness → `:176` asserts `pass==0 && deny==1 && mal==0 && pass_cidr==2`.
- src/ fence → verified externally.
- build cleanliness → warning-grep `:77` + binary `find` `:86` retained.
- 96/96 → `ctest -N` = 96, no test added/removed.
- vectors reach net-new paths → traced below.
- Negation control: T_NEGATION_CONTROL #7 present; sanitizer grep is itself negation-form; V3 is a NOMATCH negative vector. No `[NO-NEGATION-CONTROL]`.

**Coverage trace (traced, not accepted blind).** Against `config_valid_andv6.yaml`:
- V1 (`:123` dst 2001:db8:1::1234 / src 2001:db8:5::9 / tcp / dport 1500 / vlan 100 / --ext hbh dstopt) → id0 → STAT_PASS_CIDR. Drives close_prefixes6 ×2 + port-range + wildcard slots at sanitized apply; --ext functional in-kernel S6 (NOT ASAN) per D-mvp-4.19-EXT-FUNCTIONAL.
- V2 (`:131` dst 2001:db8:2::5 / tcp / dport 80 / no vlan) → id1 dst6-only → STAT_PASS_CIDR. Drives write_wildcard_slots accumulator.
- V3 (`:139` dst 2001:db8:dead::1 / tcp / dport 22) → NOMATCH → andv6 default-drop → STAT_DROP_DENY.
- Cumulative = pass_cidr 2 / deny 1 / mal 0 / pass 0 = "0 1 0 2". Matches `:176` exactly.

Helper interfaces confirmed independently: `inject_l6.py:127-147` accepts all matrix args; `read_stats.py:133` `--include-pass-cidr` slot order = pass deny mal pass_cidr; `common.sh:190/:225` readers/pollers consistent.

**3. Code ↔ Tests.** Ran `ctest --output-on-failure -R T_SANITIZER_BUILD` (sole owner of build_cpu/veth; full ASAN rebuild). **Passed, 188.60 sec**, exit 0. `stats: PASS=0 DROP_DENY=1 DROP_MALFORMED=0 PASS_CIDR=2`, `PASS: T_SANITIZER_BUILD`, **0** lines matching `AddressSanitizer|UndefinedBehavior|runtime error:`. Sanitized binary at `/tmp/xdpmf-asan-uz29v3/src/cli/xdpmacfilter`. Log `/tmp/mint-review-tests-1780301194.log`.

**4. Out-of-Scope Drift.** None. No andeth/A3 sequence, no v4 inject, no second ASAN build (HG-1; CMakeLists 0-delta), no fixture add/edit (andv6 reused read-only), no schema/VERSION/axis change.

**5. Behaviour preserved (brownfield).** `git diff -- src/` = ∅ (PI-mvp-4.19-TEST-ONLY + PI-7 load-bearing fence). common.sh + CMakeLists byte-identical. `T_SANITIZER_BUILD` CMakeLists entry unchanged: `RESOURCE_LOCK "xdp_fixture;build_cpu"` + TIMEOUT 240 RETAINED (guard #12). mktemp /tmp + `trap cleanup EXIT` retained. No REGRESSION (suite 96/96, 0 failed, 2 pre-existing env SKIPs #5/#38). No UNRELATED-EDIT, no INVARIANT-VIOLATED.

**Guard #13 retirement (verified):** no stale `10.0.0.5` / `config_valid_cidr` / `inject_ipv4` / `PASS_CIDR==1` references remain. Surviving "src_cidr" mentions (`:17/:99/:103`) are deliberate contrast prose describing superseded behavior — accurate, not dangling.

## Test execution

```
1/1 Test #9: T_SANITIZER_BUILD ................   Passed  188.60 sec
100% tests passed, 0 tests failed out of 1
sanitized loader = /tmp/xdpmf-asan-uz29v3/src/cli/xdpmacfilter
stats: PASS=0 DROP_DENY=1 DROP_MALFORMED=0 PASS_CIDR=2
PASS: T_SANITIZER_BUILD
(AddressSanitizer|UndefinedBehavior|runtime error: matches in LastTest.log = 0)
```

Full suite (tester, mint/test-run.log): 96/96, 0 failed, 2 pre-existing env SKIPs (#5 T_DROP_MALFORMED, #38 T_ANSIBLE_PLAYBOOK_SYNTAX — not regressions, different files).

## Out-of-triangulation findings
None.
