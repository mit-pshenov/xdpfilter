# Review — §5.73 MVP-4.33/B40 CompiledRuleset bundle (mint triangulation, brownfield)

## Verdict
`pass` (round 1)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 1 minor | (sub-field coverage, OOT-1) |
| 3. Code ↔ Tests | 0 fail | [UNEXERCISED-EXPORT × 2] (non-fatal, by design — OOT-2) |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

## Point 1 — Spec ↔ Code (clean)
- `struct CompiledRuleset` (compiled_ruleset.hpp:102–116) matches DataStructures byte-for-byte: 12 branch-INVARIANT members + `std::span<const Rule> rules` (Q1=A1). Dumb aggregate, zero methods — guard #36 ✓.
- `compile()` (compiled_ruleset.cpp:282–338) pure / libbpf-free / **non-throwing** — D-mvp-4.33-Q2=A2 honored (bound-checks stay in apply_request). Assembly order matches the old apply_request lowering block 1:1; `cr.rules = span{c.rules}` (:336).
- `materialize(skel,slot,cr)` (loader.cpp:396) — 16-arg→3-arg collapse; body = old `populate_all_axes` with positional→member rename ONLY; 9-axis populate order + ruleset_state/rules/slot_rule_id order preserved → BPF write order intact.
- `close_prefixes`/`close_prefixes6` external linkage decls (hpp:126/129), defs moved to .cpp; `populate_rules_inner_slot` sig `const std::vector<Rule>&`→`std::span<const Rule>` (loader.cpp:367) — range-for + `.at` span-identical.
- Q2=A2 + HELPER-MOVE are NEGOTIATED design Decisions (design.md:19073/19093) — judged as design, not drift.

## Point 2 — Spec ↔ Tests (substantially complete)
- T_COMPILE_LOWERING_IDENTITY covers every TestStrategy axis: v4/v6 LPM prefixes+wildcard, mac/proto/vlan/eth HASH entries+wildcard (mac via 6-octet memcmp), port ranges, default_action, slot_to_id array, id_to_slot via `unordered_map::operator==` (HG-5), both Pass+Drop carried (recheck #4).
- **NEGATION CONTROL present** (compile_harness.cpp:450) + tester re-proved machinery teeth (test-run.log:70–74, corrupted copy → exit 1). NO-NEGATION-CONTROL satisfied.
- Independent oracle (re-derives slot model), not tautological → no CIRCULAR-TEST.

## Point 3 — Code ↔ Tests
- Reviewer rebuilt + ran: `./build/compile_harness` → all assertions passed; `ctest -R T_COMPILE_LOWERING_IDENTITY|T_INSN_BASELINE_GATE|T_AND_ORACLE_AGREEMENT` → **3/3 passed**. Log: /tmp/mint-review-tests-1780664710.log.
- UNEXERCISED-EXPORT (non-fatal): `close_prefixes`/`close_prefixes6` exported but not called from compile_harness — by design (closure runs in materialize, covered by T_*_ORACLE_AGREEMENT). compile() itself IS directly exercised. OOT-2.

## Point 4 — OOS drift (clean)
No RulesetDelta/diff(), no loader_error.cpp, no schema/axis/map/VERSION change. `git diff src/bpf` = ∅, `git diff config.*/xdpfilter.h` = ∅.

## Point 5 — Behaviour preserved (brownfield, LOAD-BEARING — all hold)
- **Datapath byte-identity**: `git diff HEAD~1 -- src/bpf` = ∅; T_INSN_BASELINE_GATE PASS, measured xdp section == **3437** (test-run.log:31 + reviewer re-run); negation arm fails loud on 3438. ✓
- **PI-7**: `git diff HEAD~1 -- src/lib/loader.hpp` = ∅. ✓
- **Guard #9 (move byte-identical)**: diffed deleted loader.cpp block vs added compiled_ruleset.{hpp,cpp} — all function bodies (host_mask/host_mask6/host_addr6_of/compute_id_to_slot/compute_slot_to_id/lower_axis/lower_axis6/aggregate_axis/lower_port_axis/close_prefixes/6) LOGIC-identical. Only 2 comment-only edits (stale `1ULL<<rule_id`→`1ULL<<slot` BitPrefix doc; `populate_all_axes' signature`→`materialize's signature` alias doc). No logic change. ✓
- **Guard #15**: `copy_rule_counters_forward` (loader.cpp:2133/2230, branch-divergent args) + `populate_action_table` stay EXPLICIT at both call sites, NOT folded; read `cr.slot_to_id`. ✓
- **span lifetime**: `cr.rules` spans `req.config.rules` (`const ApplyRequest&` outlives function); cr consumed in-scope, never escapes — no dangling. ✓
- **3 pre-existing fails (#48/#63 exporter env, #101 leaked-port flake)**: `git diff HEAD~1 -- src/exporter` = ∅ → env/flake, NOT this slice. ✓

## Test execution (tail)
```
1/3 Test #78:  T_AND_ORACLE_AGREEMENT .... Passed 6.23 sec
2/3 Test #105: T_INSN_BASELINE_GATE ...... Passed 0.42 sec
3/3 Test #107: T_COMPILE_LOWERING_IDENTITY Passed 0.00 sec
100% tests passed, 0 tests failed out of 3
./build/compile_harness → compile_harness: all assertions passed
```

## Out-of-triangulation findings (do NOT affect verdict)

### OOT-1: v6 `host_addr6` sub-field not asserted in the offline unit — `defer`
tests/compile/compile_harness.cpp:196 vs design.md:19150. v4 asserts `host_addr`; v6 omits derived `host_addr6` (__int128). Pure deterministic fn of `cidr.addr6` (memcmp-asserted) consumed only by close_prefixes6 (oracle-agreement-covered). One-line tester add closes the literal gap next cycle.

### OOT-2: close_prefixes/close_prefixes6 not directly unit-tested by compile_harness — `defer`
compiled_ruleset.cpp:233/258 exported; closure applied in materialize, not compile(). Matches TestStrategy intent (design.md:19150-21); oracle-agreement is the decisive cheap oracle for closure.

### OOT-3: test v4 oracle masks host_addr; production stores unmasked — `defer` (+ inline-note to tester)
compile_harness.cpp:211 (`host_order_v4 & host_mask4`) vs compiled_ruleset.cpp:119 (`ntohl(addr)`, unmasked). Agree for ALL valid inputs (config rejects host-bits-set CIDRs — cidr.cpp:155 v4 / :250 v6). Worth a tester comment so masking isn't mistaken for production semantics.

---

### Deferred to next slice (Phase 4.5 sweep — round 1)
All three OOT findings dispositioned `defer` (none affect the pass verdict; all are test-completeness niceties with proven substantive coverage, NOT correctness gaps):
- **OOT-1** — add an offline assertion on the derived v6 `host_addr6` sub-field in compile_harness.
- **OOT-2** — (optional) a direct unit exercise of `close_prefixes`/`close_prefixes6`, if ever decoupled from oracle-agreement.
- **OOT-3** — add a one-line comment in compile_harness near the v4 oracle masking, noting it is test-derivation-only (production stores unmasked; equivalent under the host-bits-zero config invariant).

These are candidates for the NEXT slice's tester scope (cheap, low-priority). Natural home: **slice 2 (RulesetDelta)** if/when its spike passes, or a standalone test-polish slice.
