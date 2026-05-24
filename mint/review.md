# Review — MVP-3.2: L3 src-CIDR rule type (mint triangulation, brownfield 5-point)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 (30/31 PASS + 1 legitimate SKIP) | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (PI-1..PI-18) | 0 | — |
| Out-of-triangulation | 3 | — (all `inline-merge`) |

## Findings (each with cite + recommendation)

None blocking. Three documentation-shape OOT items listed below.

## Test execution

Independent re-run on this reviewer machine, captured to
`/tmp/mint-review-tests-202605241845.log`. Last 30 lines:

```
20/31 Test #20: T_VERIFIER_REJECT ...................   Passed   12.15 sec
21/31 Test #21: T_APPLY_VALID_CONFIG ................   Passed    4.93 sec
22/31 Test #22: T_APPLY_REJECTS_MALFORMED ...........   Passed    2.04 sec
23/31 Test #23: T_APPLY_REPLACES_RULESET ............   Passed    5.19 sec
24/31 Test #24: T_LINK_PERSIST_ACROSS_LOADER_EXIT ...   Passed    6.02 sec
25/31 Test #25: T_TRUST_MODEL_FLEET_RELAXES_GATE ....   Passed    3.27 sec
26/31 Test #26: T_APPLY_ATOMIC_SWAP_NO_DROP .........   Passed    7.49 sec
27/31 Test #27: T_EXIT_CODE_9_ON_CONFIG_ERROR .......   Passed    0.02 sec
28/31 Test #28: T_PASS_CIDR .........................   Passed    1.55 sec
29/31 Test #29: T_DROP_CIDR_NOT_IN_RANGE ............   Passed    1.34 sec
30/31 Test #30: T_PASS_MAC_OR_CIDR ..................   Passed    1.72 sec
31/31 Test #31: T_CIDR_ATOMIC_SWAP_NO_DROP ..........   Passed    6.49 sec

100% tests passed, 0 tests failed out of 31
Total Test time (real) = 176.53 sec
The following tests did not run:
  5 - T_DROP_MALFORMED (Skipped)
```

Third independent confirmation: matches impl's pre-Phase-B smoke
(30/31) and tester's formal Phase B (30/31). T_DROP_MALFORMED skip is
the longstanding kernel-pad behaviour per §6.5 — unrelated to MVP-3.2.

## Point-by-point evidence

### Point 1 — Spec ↔ Code (Design §5.27 ↔ source)

- **FileList NEW**: `src/lib/cidr.{cpp,hpp}` present ✓.
  - `cidr.hpp:33-36` declares `parse_cidr_v4(string_view, string_view, uint32_t, uint32_t) → xdpmf_cidr_v4` — byte-matches design §5.27 lines 5201-5205.
  - `cidr.cpp:69-72` performs v6 detection by scanning for `:` BEFORE the slash-split → matches design §5.27 line 5114 ("Validator detects v6 by scanning for `:` in the value").
  - `cidr.cpp:104-114` uses `inet_pton(AF_INET, ...)` per design §5.27 line 5216.
- **FileList EDITED**:
  - `src/bpf/mac_filter.bpf.c`: BPF datapath at lines 152-236 implements Q2 OR1 (MAC HASH first short-circuit at line 188-192; CIDR LPM_TRIE on IPv4 ethertype at lines 199-220). Single `active_idx` snapshot at line 180 used for BOTH outers (lines 182, 207) → Q1 AS1 race-window invariant honored. LPM_TRIE key at 212-215 sets `prefixlen=32` (host-route lookup) and `addr=ip->saddr` in network byte order — matches design §5.27 lines 4844 + 5156. STAT_PASS_CIDR increment at line 218 — matches design §5.27 line 4846.
  - `src/common/mac_filter.h:24` `xdpmf_mac` unchanged (PI-10-3.2 ✓). `mac_filter.h:40-43` `xdpmf_cidr_v4` packed 8-byte struct prefix-len-first per kernel LPM_TRIE convention. `mac_filter.h:54-60` enum `mac_filter_stat`: STAT_PASS=0/STAT_DROP_DENY=1/STAT_DROP_MALFORMED=2 byte-identical; STAT_PASS_CIDR=3 + STAT_MAX bumped 3→4 (additive per design §5.27 lines 5176-5191).
  - `src/lib/config.{cpp,hpp}`: `config.hpp:36-39` adds `std::optional<xdpmf_cidr_v4> src_cidr` to `RuleMatch` — matches design §5.27 line 5225. `config.cpp:236-243` accepts `{mac, src_cidr}` keyset; rejects `cidr`/`port`/`dst_cidr`/`vlan` with the design §5.27 line 4912 forward-compat hinge. `config.cpp:247-252` enforces schema-rule-7 ("at-least-one-of mac or src_cidr"). `config.cpp:266-280` delegates CIDR parse to `cidr::parse_cidr_v4`.
  - `src/lib/loader.cpp:1043-1076` `populate_cidr_inner_slot` mirrors `populate_inner_slot` per design §5.27 lines 5349-5352. The state-b reuse_fd loop at lines 1482-1492 now covers 9 maps (was 6) — matches D-3.1-4 extension at design §5.27 lines 5373-5378. `loader.cpp:1533-1545` populates inactive CIDR inner BEFORE active_idx flip per Q1 AS1 apply-ordering (design §5.27 lines 4770-4783). The single `write_active_idx` call at line 1578 (state-b) / 1680 (fresh attach) is the unchanged atomic-commit point.
- **PI-7-3.2 fence**: `git diff 7f4c56a HEAD -- src/lib/loader.hpp` yields zero lines. `LoaderError` enum unchanged at 9 values.
- **Q1-Q6 decisions all honored**: AS1 parallel outers (`mac_filter.bpf.c:93-101` `cidr_rulesets` ARRAY_OF_MAPS shares `active_idx`); OR1 MAC-first (datapath order is MAC then CIDR with explicit short-circuit returns); K2 `src_cidr` key (`config.cpp:237`); L1 single CIDR scalar (no list-handling code; `config.hpp:38` is `optional<xdpmf_cidr_v4>` not `vector`); V1 additive at schema_version 1 (`config.cpp:155-159` rejects v != 1); Q6 DEFER housekeeping (no OOT-1/OOT-2 changes — diff confirmed).
- **HG-3.2-1 v6 fail-closed**: smoke-tested via `xdpmacfilter apply -f config_malformed_cidr_v6.yaml --iface notexist` → rc=9 + `xdpmacfilter: config error: IPv6 CIDR not supported until MVP-3.2.5: '::1/128': .../config_malformed_cidr_v6.yaml:9:7: config error ...`. Specific stderr substring confirmed.
- **D-3.1-1..D-3.1-4 unchanged**: `apply_internal.hpp` zero-diff (verified); legacy `${PIN_DIR}/allowlist` alias still emitted (`loader.cpp:1618-1629`); `apply -f` file-IO still raises `CliError` (no change to `apply.cpp`); reuse_fd loop covers 9 maps now per D-3.1-4 extension.

### Point 2 — Spec ↔ Tests (Design TestStrategy ↔ tests)

- **§6.28 T_PASS_CIDR** (`tests/T_PASS_CIDR.sh:1-156`): asserts STAT_PASS_CIDR delta == 1 on in-range src_ip with non-allowlist MAC (line 118-126: explicitly distinguishes MAC vs CIDR axis pass). Out-of-range step asserts STAT_DROP_DENY delta == 1 with no STAT_PASS_CIDR movement (line 141-153) — outcome-based per design §6.28 "Anti-theatricality control" (line 5470).
- **§6.29 T_DROP_CIDR_NOT_IN_RANGE** (`tests/T_DROP_CIDR_NOT_IN_RANGE.sh:1-101`): two-injection idempotent-denial pattern per design §6.29 (lines 5479-5480). Counter SPLIT enforced (lines 64-76, 87-98).
- **§6.30 T_PASS_MAC_OR_CIDR** (`tests/T_PASS_MAC_OR_CIDR.sh:1-191`): 3 sub-cases in sequence per design §6.30 (lines 5489-5499) — (a) MAC-only match → STAT_PASS (Q2 OR1 short-circuit); (b) CIDR-only match → STAT_PASS_CIDR; (c) neither match → STAT_DROP_DENY (the load-bearing negation control per design line 5496). Both inner pins asserted non-empty (lines 95-109) — single OR-compose rule populates BOTH axes.
- **§6.31 T_CIDR_ATOMIC_SWAP_NO_DROP** (`tests/T_CIDR_ATOMIC_SWAP_NO_DROP.sh:1-315`): persistent AF_PACKET injector pattern (lines 92-161) matches §6.31 spec. Overlap of `10.0.0.0/8` across configs A and B (fixtures lines 6-8 of each), concurrent `apply` during traffic (line 228), assertion `STAT_DROP_DENY == 0` post-swap (line 277-284), lower-bound `STAT_PASS_CIDR >= LOWER_BOUND` (line 287-294), active_idx flip verified (line 246-252), negation control by injecting one OUT-of-CIDR packet to prove drops are detectable on the runner (lines 296-311). SKIP 77 path on under-rate runners (lines 210-214).
- **§6.22 sub-cases 6/7/8** (`tests/T_APPLY_REJECTS_MALFORMED.sh:175-181`): 6 asserts stderr substring `IPv6 CIDR not supported until MVP-3.2.5` (line 177); 7 asserts `malformed CIDR: host bits set below prefix` (line 179); 8 asserts `malformed CIDR: missing prefix length` (line 181). All distinct per design §5.27 message catalogue (lines 5057-5066).
- **Negation controls**: §6.28 step 5 + §6.29 (whole test) + §6.30 sub-case (c) + §6.31 step 11 = four independent negation paths in the new suite. NO `[NO-NEGATION-CONTROL]`.
- **No `[CIRCULAR-TEST]`**: all assertions read external observables (stats counters, pin existence, bpftool map dump, stderr text), not impl-internal state.

### Point 3 — Code ↔ Tests

- **All exports exercised**: `parse_cidr_v4` invoked by `config.cpp:277` (config validation), which is reached by all CIDR fixtures (config_valid_cidr.yaml, config_valid_mac_or_cidr.yaml, config_valid_cidr_swap_a/b.yaml, all 3 malformed CIDR fixtures). `populate_cidr_inner_slot` invoked by `loader.cpp:1544 + 1653` — reached by every test that applies a CIDR config.
- **Test re-run**: 30/31 PASS + 1 legitimate SKIP, matching impl/tester reports. Zero failures.

### Point 4 — Out-of-Scope Drift

Walked design §5.27 §7 OOS fences against impl + tests:
- **No IPv6** — confirmed via v6 reject path (smoke + sub-case 6).
- **No `dst_cidr`** — `config.cpp:237` whitelist is `{mac, src_cidr}`; unsupported-match sub-case (T_APPLY_REJECTS_MALFORMED sub-case 5 unchanged) still works.
- **No L4 port** — no port-handling code anywhere; validator rejects.
- **No VLAN-aware** — datapath only branches on ETH_P_IP (`bpf/mac_filter.bpf.c:199`).
- **No L2 list** — `RuleMatch.mac` is still `optional<xdpmf_mac>`, not `vector` (`config.hpp:37`).
- **No schema_version: 2** — `config.cpp:155-159` rejects v != 1.
- **No new exit code** — `LoaderError` enum unchanged (PI-7-3.2 ✓).
- **No `T_CIDR_INVALID_REJECTED.sh`** — folded into §6.22 sub-cases per design line 5400-5407 ✓.
- **No `--allow CIDR`** — CLI grammar unchanged (`--help` output unchanged for `attach --allow`).
- **No rename / no library / no systemd / no per-rule counter / no exporter / no JIT-size assertion** — none of these surface in diff.

### Point 5 — Behaviour preserved (PI-1..PI-18)

| PI | Status | Evidence |
|---|---|---|
| PI-1 strict alien-refusal | ✓ | T_ATTACH_TAG_MISMATCH + T_ATTACH_ALIEN_REFUSAL + T_TRUST_MODEL_FLEET_RELAXES_GATE all PASS |
| PI-2 name-identity gate both modes | ✓ | Same trio + name-check code unchanged in `loader.cpp` |
| PI-3 tag-check both modes | ✓ | T_ATTACH_TAG_MISMATCH PASS |
| PI-4 O_PATH path-discipline | ✓ | T_BPFFS_ROOT_SYMLINK PASS |
| PI-5 kernel-version probe | ✓ | T_VERIFIER_REJECT PASS |
| PI-6-3.2 27 pre-§5.27 tests byte-equivalent + §6.22 carve-out | ✓ | `git diff --stat 7f4c56a HEAD -- 'tests/T_*.sh'` shows ONLY T_APPLY_REJECTS_MALFORMED + 4 NEW; all other 26 test bodies byte-identical |
| PI-7-3.2 loader.hpp ZERO diff | ✓ | `git diff 7f4c56a HEAD -- src/lib/loader.hpp` empty |
| PI-8-3.2 --version reports 0.4.0 | ✓ | `xdpmacfilter --version` → `xdpmacfilter 0.4.0` |
| PI-9 --help format unchanged | ✓ | T_CLI_HELP_VERSION PASS |
| PI-10-3.2 mac_filter.h additions-only | ✓ | Diff confirmed: existing constants byte-identical; only additions + STAT_MAX sentinel bump |
| PI-11 dir layout | ✓ | `find src -type d` → 4 dirs (lib, cli, bpf, common); no new |
| PI-12 pin paths host-global | ✓ | Tests pass with NSEXEC pattern; new pins under same PIN_DIR |
| PI-13-3.2 default read_stats.py 3-column | ✓ | `read_stats.py` w/o flag prints 3 cols (diff confirms); existing helpers in common.sh unchanged |
| PI-14 --mode flag unchanged | ✓ | T_MODE_GENERIC_DEFAULT + T_MODE_NATIVE_UNSUPPORTED + T_MODE_DETACH_REJECTS all PASS |
| PI-15 CIDR additive (MAC-only configs still work) | ✓ | T_APPLY_VALID_CONFIG PASS; T_APPLY_ATOMIC_SWAP_NO_DROP (MAC-only swap) PASS |
| PI-16 STAT_PASS_CIDR additive | ✓ | T_PERCPU_STATS_SUM PASS; STAT_PASS/DENY/MALFORMED indices 0/1/2 byte-identical |
| PI-17 schema_version: 1 still accepted | ✓ | T_APPLY_VALID_CONFIG PASS (fixture omits schema_version → defaulted to 1) |
| PI-18 §6.23 MAC-axis swap byte-equivalent | ✓ | T_APPLY_ATOMIC_SWAP_NO_DROP (test #26) PASS |

No `[REGRESSION]` / `[INVARIANT-VIOLATED]` / `[UNRELATED-EDIT]`.

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] design.md §5.27 uses `__u32` for `xdpmf_cidr_v4` fields; impl uses `unsigned int`
**Location**: `src/common/mac_filter.h:40-43` vs `design.md:5158-5161`
**Evidence**: design schema-illustrative block uses `__u32 prefixlen; __u32 addr`; impl uses `unsigned int prefixlen; unsigned int addr`. Header comment (`mac_filter.h:36-38`) explicitly explains the choice ("`unsigned int` is used … because this header is included from BOTH userspace C++ (where `__u32` isn't a libc type) AND BPF C"). Structurally byte-identical on all supported architectures (4-byte unsigned). The existing `struct xdpmf_mac` in the same header (`mac_filter.h:24-26`) uses the same convention with `unsigned char` (not `__u8`) — impl matched the pre-existing convention, which is the right call.
**Recommended disposition**: `inline-merge`
**Rationale**: design's illustrative kernel-side typing differs from the header's own portability convention; the impl's choice is consistent with the file's longstanding "shared-header uses plain C types" pattern and is documented inline. Architect should update §5.27 DataStructures block to match the header convention. No code change required.

### [OUT-OF-TRIANGULATION] design.md §5.27 declares `namespace xdpmf` for cidr.hpp; impl uses `namespace xdpmf::cidr`
**Location**: `src/lib/cidr.hpp:19` vs `design.md:5193`
**Evidence**: design says "Userspace (`src/lib/cidr.hpp`, namespace `xdpmf`)"; impl uses sub-namespace `xdpmf::cidr` (and call-site `xdpmf::cidr::parse_cidr_v4` at `config.cpp:277`). Sub-namespacing the parser is a reasonable scope-narrowing choice (mirrors the `xdpmf::yaml` subset namespace).
**Recommended disposition**: `inline-merge`
**Rationale**: pure design-text alignment; impl is structurally fine and follows the existing `xdpmf::yaml` precedent. Architect should update §5.27 namespace declaration.

### [OUT-OF-TRIANGULATION] `xdpmacfilter --help` does not mention `src_cidr`
**Location**: `src/cli/cli.cpp` help block (no edit this slice; `xdpmacfilter --help` output verified)
**Evidence**: design §5.27 line 5319 says "--help text gains ONE line mentioning the new `src_cidr` match-key" (impl-flexible wording). Design §5.27 verifiable-invariant block at line 5627 relaxes this to "MAY list `src_cidr` (impl-flexible; tester asserts substring presence in §6.30 setup if applicable, otherwise no assertion)". Inconsistency is internal to design.md; the controlling line is the "MAY" relaxation. Impl chose not to add the line; tester chose not to assert. No test fails.
**Recommended disposition**: `inline-merge`
**Rationale**: design self-inconsistency between §5.27 main block ("gains ONE line") and verifiable-invariant section ("MAY list"). Architect should normalize §5.27 to "MAY" so the brief, design, impl, and tests all line up. Per RETROSPECTIVES backlog item 2: "design.md verifiable invariants … MAY be too strict if impl needed extras to satisfy contracts elsewhere" — same pattern applies in reverse here (design over-stated; impl chose the relaxed reading; both internally consistent with the MAY clause).

## Rework assignments

None — verdict is `pass`. Three OOT items are all `inline-merge` (design-text harmonization), not impl/tester rework.

---

Test log archived at `/tmp/mint-review-tests-202605241845.log`.
Independent verification of impl's 30/31 smoke + tester's 30/31 formal
Phase B = third confirmation. Greenlight Phase 4 ship.

---

### Post-review sweep — round 1

Orchestrator applied 3 `inline-merge` OOT findings before Phase 6 commit. All are pure design-text harmonization — no impl, test, or behaviour changes:

1. **OOT-1 (`__u32` → `unsigned int` for `xdpmf_cidr_v4` fields)** → `mint/design.md:5158-5161` edited. New explanatory comment cites the shared-header convention (mirrors `xdpmf_mac`'s `unsigned char`). 1-line summary: design.md `xdpmf_cidr_v4` struct illustration now matches the impl's `unsigned int` typing — both consistent with `mac_filter.h`'s longstanding "shared-header uses plain C types" pattern.

2. **OOT-2 (namespace `xdpmf` → `xdpmf::cidr`)** → `mint/design.md:5193` edited. Added comment noting the precedent (`xdpmf::yaml`) and call-site form. 1-line summary: design.md namespace declaration for `cidr.hpp` now matches the impl's sub-namespacing choice, consistent with the existing `xdpmf::yaml` parser module precedent.

3. **OOT-3 (design self-inconsistency on `--help` `src_cidr` mention)** → `mint/design.md:5315-5321` edited. Normalized "gains ONE line" → "MAY gain a line" to align with the verifiable-invariant block's "MAY list" relaxation. 1-line summary: design.md `--help` text requirement softened from MUST to MAY; impl correctly chose the relaxed reading; tester correctly chose not to assert. This is the **same pattern as MVP-3.1's OOT-3** (design verifiable-invariant too strict) but in the inverse direction (design over-stated, impl pulled back to the consistent reading). Validates RETROSPECTIVES backlog item #2.

No `defer` items this cycle. No `promote-to-rework`.
