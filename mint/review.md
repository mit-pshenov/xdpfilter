# Review — MVP-4.3 production OR→AND bit-vector pivot (§5.43) (mint triangulation)

## Verdict
`needs-rework`

Single blocker: confirmed UBSan failure (T_SANITIZER_BUILD) = genuine defect at `sidecar.cpp:65`. Everything else triangulates cleanly — all 4 new tests pass, all load-bearing contracts hold, every git-diff fence is empty. One trivial impl fix unblocks a `pass`.

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 1 | [test-failure × 1] |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 1 | [REGRESSION × 1] |

(Points 3 & 5 are the SAME root cause — the sidecar UB — counted under both.)

## Findings

### [REGRESSION]/[test-failure] T_SANITIZER_BUILD — misaligned-reference-bind UB at sidecar.cpp:65
**Location**: `src/lib/sidecar.cpp:65` (`format_cidr`) — independently reproduced (reviewer run: `Test #9 ***Failed 173.23s`, `UndefinedBehaviorSanitizer: undefined-behavior sidecar.cpp:65:56`).
**Evidence**: `return std::format("{}.{}.{}.{}/{}", a, b, d, e, c.prefixlen);` — `a/b/d/e` are local `unsigned int` copies, but `c.prefixlen` is passed directly. `std::format` binds each arg by `const T&` (via `make_format_args`); `xdpmf_cidr_v4` is `__attribute__((packed))` (`mac_filter.h:43`), so binding `const unsigned int&` to the packed `prefixlen` field at a misaligned address is UB. Latent pre-§5.43 (format_cidr only ran on CIDR rules), but this slice's M.1 v2 cutover makes EVERY rule CIDR → `format_cidr` now ALWAYS runs → UB fires on every applied config with rules. Prior cycle (§5.42) had this test GREEN; design §5.43 TestStrategy lists T_SANITIZER_BUILD under (T-UNAFFECTED) "stay GREEN" → now RED = regression.
**Negotiated?**: no (not in impl-notes; not a verifiable-invariants hint deviation)
**Test correct (not weakened)?**: YES — diffed `T_SANITIZER_BUILD.sh`. It was converted MAC-attach→CIDR-apply (legitimate, MAC deferred), but the load-bearing negation assertion ("a sanitizer report in stderr ⇒ FAIL") is byte-intact. Tester correctly left it red rather than masking the UB.
**Fix**: copy the field to a local before formatting — e.g. `const unsigned int plen = c.prefixlen;` then `std::format("{}.{}.{}.{}/{}", a, b, d, e, plen);`. One line, inside an already-EDITED file, no interface change. (PI-mvp-4.3-SIDECAR requires the sidecar to emit dst_cidr/src_cidr, which forces format_cidr to always run → it MUST be UB-clean.)
**Assign to**: impl

## What triangulates cleanly (evidence)

**Point 1 — Spec ↔ Code (all match):**
- DataStructures: `RuleMatch.dst_cidr` added (`config.hpp:38`, diff = exactly that). cidr inner VALUE reshaped `allow_entry`→`__u64` (`mac_filter.bpf.c:119-126`). NEW `dst_bitmask_a/_b`+`dst_rulesets`+`wildcard` declared.
- **Load-bearing contracts ALL hold**: `kManagedMaps[]`=21 (20 real + `allowlist` alias; +4 exact: dst_bitmask_a/_b, dst_rulesets, wildcard — `loader.cpp`); `BITVEC_NUM_AXES`=2 (`mac_filter.h:116`); `wildcard` max_entries=`XDPMF_RULESET_COUNT*BITVEC_NUM_AXES`=4 (`mac_filter.bpf.c:189`).
- Interface #2 AND-compose EXACT: `acc=(dmask|wc_dst)&(smask|wc_src)` (`mac_filter.bpf.c:534`); `rid=first_set_u64(acc)-1` (`:542`); acc==0→defaults (`:559-564`); DROP→STAT_DROP_DENY, PASS→STAT_PASS_CIDR (`:551/:556`).
- **FI-1 prefix-closure cover-direction CORRECT** (`loader.cpp:1209-1226`): skips `pj.prefixlen > pi.prefixlen`, ORs covering shorter-prefix bit into the more-specific entry — the #1 trap is avoided. Verified by §6.62 canary passing.
- `first_set_u64` production-owned (`__builtin_ffsll` default + `#ifdef XDPMF_FFS_FALLBACK`, `:374-387`); guard #9 satisfied (no `#include tests/bitvec`).
- config.cpp M.1: supported {2}, v1+absent reject exit-9 re-author (`:136-147`); `mac` rejected w/ MAC-deferred diagnostic (`:224-228`); at-least-one-of {dst_cidr,src_cidr} (`:241-243`).
- MAC maps frozen: declared in `.maps` (`mac_filter.bpf.c:87-107`) but ZERO datapath MAC lookup → PI-mvp-4.3-MAC-DEFERRED holds.
- VERSION 0.11.0 + DESCRIPTION AND-compose (`CMakeLists.txt:13-14`); `grep 0\.10\.0 tests/` = only IP-substring false-positives (`10.10.0.0/16`), no version literal.

**Point 2 — Spec ↔ Tests (all 4 TestStrategy items covered, no circular, negation present):**
- §6.60 T_AND_COMPOSE_OK ✓ pass; §6.61 T_AND_ORACLE_AGREEMENT ✓ pass (independent O(N) `bitvec_oracle_prod.py`, algorithm-distinct from datapath); §6.62 T_AND_PREFIX_CLOSURE_OVERLAP ✓ pass (guard #23 lower-id-covering canary); §6.63 T_SCHEMA_V2_CUTOVER ✓ pass.
- **Negation control present** in T_AND_ORACLE_AGREEMENT (V2/V3/V7 → NOMATCH=64) with a self-guard (`:160` `FAIL[sanity]: no NOMATCH vector present`). No [NO-NEGATION-CONTROL].
- SKIPs all carry MAC-deferred citations + `exit 77` (T_PASS_ALLOWED, T_DROP_DENY, T_PASS_MAC_OR_CIDR, T_RULE_COUNTER_MAC_HIT_BUMPS) — converted-not-dropped, legitimate. T_APPLY_ATOMIC_SWAP_NO_DROP SKIP cites CIDR-equivalent coverage. T_ANSIBLE/T_DROP_MALFORMED = pre-existing env skips. All 7 skips legitimate.

**Point 4 — OOS**: no proto/dst_port, no most-specific-wins, no NormalizedRule type, no MAC-map retirement, MAC maps frozen-not-retired. Clean.

**Point 5 — Behaviour preserved:** every git-diff fence EMPTY (loader.hpp, src/exporter/, src/cli/, logger.*, cidr.*, apply_internal/yaml_subset/raii, systemd/ansible/docs, tests/bitvec spike files — only NEW bitvec_oracle_prod.py added). `copy_rule_counters_forward` NOT in loader.cpp diff (PRESERVE holds). mac_filter.h additive-only (STAT enum + structs byte-identical). config.hpp = exactly the dst_cidr add. The ONLY broken invariant is the sidecar UBSan regression above.

**Impl's 2 documented deviations — both sanctioned, NOT drift:**
1. Sidecar emits explicit `dst_cidr`/`src_cidr` keys (retiring `"cidr"`) — mandated by PI-mvp-4.3-SIDECAR + T_SIDECAR_JSON_SHAPE; resolved via D-mvp-4.3-PROSE-VS-INVARIANTS. `inline-merge`, not drift. T_SIDECAR_JSON_SHAPE passes.
2. Removed dead `parse_mac_canonical`/`hex_nibble` from config.cpp (v2 rejects `mac` at parse → `-Werror=unused-function`). Mechanical consequence inside an EDITED file; in-scope, not [UNRELATED-EDIT].

## Test execution

Reviewer runs (sandbox, sudo ctest):
```
T_RULE_COUNTER_SURVIVES_APPLY ... Passed
T_SIDECAR_JSON_SHAPE .......... Passed
T_AND_COMPOSE_OK .............. Passed
T_AND_ORACLE_AGREEMENT ........ Passed
T_AND_PREFIX_CLOSURE_OVERLAP .. Passed
T_SCHEMA_V2_CUTOVER ........... Passed   (6/6)

T_SANITIZER_BUILD ............. ***Failed 173.23 sec
  src/lib/sidecar.cpp:65:56: runtime error: reference binding to misaligned
  address 0x5030000000b5 for type 'const unsigned int', requires 4 byte alignment
  SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior sidecar.cpp:65:56
  FAIL: sanitizer report detected in captured stderr
```
Matches tester's reported 68 pass / 1 fail / 7 skip. The 1 failure is real and reproducible.

## Rework assignments

- **impl**: fix `sidecar.cpp:65` `format_cidr` — bind `c.prefixlen` to an aligned local copy before `std::format` (one line). Re-run T_SANITIZER_BUILD to green. No design change, no test change needed.
- architect: none.
- tester: none (T_SANITIZER_BUILD is correct as-is; do NOT weaken).

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] Stale MAC-era comments in converted T_DROP_RULE_BUMPS_COUNTER.sh
**Location**: `tests/T_DROP_RULE_BUMPS_COUNTER.sh:15-39` (header comments still narrate "drop-MAC frames", "MAC IS in active inner-allowlist"); fixture+body correctly converted to v2 src_cidr (`config_per_rule_counters.yaml`, body injects `inject_ipv4.py` at `:200`). Test PASSES.
**Evidence**: comment/code mismatch only; assertions exercise the CIDR drop-dispatch correctly. Possibly-vestigial `mac_to_oct_json`/`mac_in_inner_pin` helpers remain.
**Recommended disposition**: `defer`
**Rationale**: cosmetic; zero behavioral impact; tidy up when the MAC axis returns (mvp-4.5) and the helpers are needed again.

### [OUT-OF-TRIANGULATION] MAY-invariant #11 literal grep non-zero (harmless)
**Location**: `src/bpf/mac_filter.bpf.c:366`, `src/lib/loader.cpp:1191` — comments reading "NOT #include'd from tests/bitvec".
**Evidence**: design verifiable-invariant #11 says `grep -rn 'tests/bitvec' src/` returns ZERO; it returns 2 hits, both prose disclaimers. The actual guard #9 contract (no `#include` of the spike) IS satisfied — close_prefixes/first_set are transcribed.
**Recommended disposition**: `defer`
**Rationale**: MAY-invariant, not a contract; the literal-grep is a proxy for guard #9 which holds. No action required.

— mint-dev-reviewer (round 1)

---

### Deferred to next slice (Phase 4.5 OOT sweep — round 1)

Both OOT findings dispositioned `defer` (per reviewer recommendation; no promote-to-rework, verdict stays needs-rework on the sidecar blocker alone):

1. **Stale MAC-era comments in `tests/T_DROP_RULE_BUMPS_COUNTER.sh:15-39`** + possibly-vestigial `mac_to_oct_json`/`mac_in_inner_pin` helpers — cosmetic comment/code mismatch, test passes. Tidy when the MAC axis returns (mvp-4.5).
2. **MAY-invariant #11 literal `grep 'tests/bitvec' src/` returns 2 prose-comment hits** (`mac_filter.bpf.c:366`, `loader.cpp:1191`) — the guard #9 contract (no `#include` of the spike) holds; the literal grep is a proxy. Optionally reword the §5.43 invariant or the comments in a future cycle.

---

## ROUND 2 — verdict: `pass` (mint-dev-reviewer-2, fresh/independent)

Round-1 sole blocker (UBSan misaligned-reference-bind at `sidecar.cpp:65`) INDEPENDENTLY confirmed FIXED. Reviewer-2 re-derived all 5 points from scratch (did not trust round-1).

| Framework point | Findings |
|---|---|
| 1. Spec ↔ Code | 0 |
| 2. Spec ↔ Tests | 0 |
| 3. Code ↔ Tests | 0 |
| 4. Out-of-Scope Drift | 0 |
| 5. Behaviour preserved | 0 ([REGRESSION] RESOLVED) |

- **Fix verified**: `sidecar.cpp:69` `const unsigned int plen = c.prefixlen;` then `std::format(..., plen)` — packed field copied to aligned local before the `const&` bind. 1-line + comment, no interface change.
- **T_SANITIZER_BUILD** Passed 175.38s; `grep -ciE 'UndefinedBehaviorSanitizer|misaligned|undefined-behavior'` over the full 76-test log = **0**.
- Full run: **100% tests passed, 0 failed out of 76; 7 skipped**.
- All round-1 clean findings re-confirmed: FI-1 prefix-closure cover-direction correct (`loader.cpp:1209-1226`), FI-7 wildcard ×2 swap rides `active_idx`, M.1 cutover, MAC frozen-not-retired, `kManagedMaps[]`=21, `BITVEC_NUM_AXES`=2, `wildcard` max_entries=4, guard #9 transcription (no `#include tests/bitvec`), all git-diff fences empty, `copy_rule_counters_forward` PRESERVE byte-equivalent.
- 7 skips all legitimate (4 MAC-deferred cited, 1 dup, 2 pre-existing env). Impl's 2 deviations design-sanctioned (inline-merge).
- 2 OOT findings re-confirmed, both still `defer` — do NOT affect verdict.
- Reviewer-2 run log: `/tmp/mint-review2-tests-1780048026.log`.

**FINAL: pass on round 2.** Test tally 69 pass / 0 fail / 7 skip (76 registered).
