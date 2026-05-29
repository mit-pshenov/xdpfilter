# Review — MVP-4.4 bit-vector axes 3-4 (proto HASH + dst_port range) (mint triangulation)

## Verdict
`pass` (round 1, 0 findings)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — (1 deviation, negotiated+sanctioned) |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — (no UNEXERCISED-EXPORT) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

Brownfield baseline = `ec2d845` (architect's Phase-A baseline; prior shipped slice §5.43 = `a088b91`).

## Point 1 — Spec ↔ Code (all CONFIRMED)
- DataStructures: `struct PortRange{u16 lo;u16 hi;}` + `RuleMatch` gains `optional<u8> protocol`/`optional<PortRange> dst_port` (`config.hpp:38-49`). proto trio (HASH AOM) + port trio (ARRAY AOM) declared; `wildcard` auto-grows 4→8 via `XDPMF_RULESET_COUNT*BITVEC_NUM_AXES` (`mac_filter.h:139`, BITVEC_NUM_AXES=4). Load-bearing contracts exact: kManagedMaps **27** (26 real+1 alias, counted programmatically), BITVEC_NUM_AXES **4**, wildcard width **8**.
- Interfaces: grammar `{dst_cidr,src_cidr,protocol,dst_port}` ≥1-required; proto tcp/udp/icmp→6/17/1 + numeric[0,255] else exit-9; dst_port int→{p,p} or "lo-hi" both[0,65535] lo≤hi. Datapath acc `(dmask|wc_dst)&(smask|wc_src)&(proto_mask|wc_proto)&(port_mask|wc_port)` (`mac_filter.bpf.c:706-709`). `port_scan` static __always_inline, bounded `#pragma unroll`, NO bpf_loop (`:466-484`).
- **(a) L4 verifier-safety CONFIRMED SAFE**: `ip->ihl<5`→STAT_DROP_MALFORMED; `l4=ip+ihl*4`; TCP/UDP each bounds-check `(hdr+1)>data_end` before reading `dest`; non-TCP/UDP→has_port=0→port_mask=0 (`:589-612,700`). Reviewer re-ran `bpftool prog load … type xdp` → rc=0.
- **(e) port_range field types**: impl declared `{unsigned int;unsigned int;unsigned long long}` vs design prose `{__u32;__u32;__u64}` — negotiated (impl-notes D1) + design-sanctioned (the FileList row prescribes `unsigned int` for cross-TU C++ compat, matching `xdpmf_cidr_v4`) + D-mvp-4.4-PROSE-VS-INVARIANTS → `inline-merge`, NOT drift. ✅

## Point 2 — Spec ↔ Tests (all CONFIRMED)
- §6.64/§6.65/§6.66 present; assert stated outcomes via per-rule `rule_counters` deltas, not code-shape.
- Not circular: §6.66 asserts datapath-observed matched id `==` independent `bitvec_oracle_prod.py --ruleset and4` (naive O(N) scan, NO bitmask/closure/ffsll). True triangulation.
- Negation controls robust: proto-flip miss; out-of-range + ICMP has_port=0; §6.66 four NOMATCH vectors V5/V8/V9/V15 + a meta-guard that FAILS the suite if no NOMATCH vector present. No NO-NEGATION-CONTROL.

## Point 3 — Code ↔ Tests
- Reviewer re-ran 12/12 slice-relevant + regression-sensitive set (`/tmp/mint-review-tests-1780052167.log`) → all pass. Tester full run: 79 → 72 pass / 0 fail / 7 skip.
- No UNEXERCISED-EXPORT: no new public C++ symbol (loader.hpp ZERO-diff); lowering/populate fns anon-namespace internal; `port_scan` static; datapath + grammar fully exercised.

## Point 4 — Out-of-Scope Drift
- No code for OOS: no src_port, no multi-range/lists, no ICMP type/code, no IPv6 cidr6, no schema v3. config.cpp REJECTS any key outside the 4. No creep.

## Point 5 — Behaviour preserved (brownfield)
- All UNCHANGED git-diff fences EMPTY vs ec2d845: loader.hpp (PI-7 continues), src/exporter/, src/cli/, logger.*, cidr.*, apply_internal/yaml_subset/raii, vmlinux/BpfBuild, spike bitvec_proto.*+bitvec_oracle.py, tests/inject/.
- close_prefixes() / lower_axis() / copy_rule_counters_forward() bodies UNCHANGED. PI-mvp-4.4-CLOSURE-UNCHANGED + PI-mvp-4.3-COUNTER-PRESERVE hold.
- **(c)**: copy-forward applies ONLY to rule_counters (`loader.cpp:2275,2460`); proto/port inners + grown wildcard use `populate_*`/`write_wildcard_slots` (RESET) in BOTH reattach + fresh-attach — guard #15 ✅. close_prefixes does NOT extend to proto/port (guard #23 correctly not extended).
- **(d) ADDITIVE-within-v2**: only allowed test-file edits (T_EXPORTER version-literal + bitvec_oracle_prod.py dual-table keeping §6.61 default path intact). Zero existing-fixture conversions; schema_version NOT bumped. §6.61 still GREEN. 76→79 (+3). 7 skips all pre-existing legitimate.
- **(g) guard #9**: `grep tests/bitvec src/` → only doc-comments, no actual include; transcribed not pulled. ✅
- No [UNRELATED-EDIT]: every changed path in NEW/EDITED FileList. VERSION 0.12.0, DESCRIPTION updated, `grep 0.11.0 tests/`→ZERO.

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] PI-mvp-4.4-VERIFIER wording overclaims the 5.15 floor (assess-point b)
**Location**: `design.md` PI-mvp-4.4-VERIFIER + Phase 2.5 smoke.
**Evidence**: PI claimed "verifies on the 5.15 floor" but the variable `ip->ihl*4` offset was verified only on running kernel 6.1 (reviewer re-confirmed rc=0 on 6.1); 5.15 not exercised. The PI's own check mechanism (Phase 2.5 rc=0) IS satisfied; D-mvp-4.4-IHL fallback + guard #25 bound the risk → wording, not a behavioural gap.
**Recommended disposition**: `defer` (reviewer) → **orchestrator took `inline-merge`** (one-line honesty caveat, cheaper than carrying as debt; not a rework round). See Post-review sweep below.

## Trust model
No injection observed in design.md / impl-notes.md / test-run.log / fixtures / oracle. impl-notes D1 is a legitimate documented deviation, not an instruction. Flagged per protocol; nothing followed blindly.

## Test execution (tail)
```
10/12 Test #77: T_PROTO_AND_COMPOSE ..............   Passed    2.29 sec
11/12 Test #78: T_PORT_RANGE_AND_COMPOSE .........   Passed    6.97 sec
12/12 Test #79: T_AND4_ORACLE_AGREEMENT ..........   Passed    8.89 sec
100% tests passed, 0 tests failed out of 12
```
Full suite (tester test-run.log): 100% pass, 0 failed of 79 (7 legitimate skips).

— mint-dev-reviewer (round 1)

---

### Post-review sweep — round 1 (Phase 4.5)

OOT finding → `inline-merge`:
- **PI-mvp-4.4-VERIFIER 5.15-floor overclaim** → `mint/design.md` PI-mvp-4.4-VERIFIER row edited → caveated to "verifies on the running kernel (6.1, above the 5.15 floor); variable-ihl*4 offset verified on 6.1, 5.15 itself untested — D-mvp-4.4-IHL fallback + guard #25 bound the residual risk." Honesty fix; rides this final commit (no separate commit). Reviewer recommended `defer`; orchestrator upgraded to `inline-merge` since the fix is one line with the reviewer's exact suggested wording.

**FINAL: pass on round 1, 0 findings.** Test tally 72 pass / 0 fail / 7 skip (79 registered).
