# Review — MVP-4.36/B43 dryrun_harness (mint triangulation)

## Verdict
`pass` (round 1)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

OOT: 1 (`inline-merge`, non-verdict-affecting).

## What I verified (evidence)

**Point 1 — Spec ↔ Code.** Every §5.76.4 interface located and proven a byte-identical MOVE (not a re-impl, guard #9). Brace-matched each moved definition from pre-slice `loader.cpp` (`625c5a9~1`) against the new TUs:
- `materialize` (77 lines), `populate_hash_inner_slot`, `populate_bitvec_inner_slot`, `populate_port_inner_slot`, `write_ruleset_state`, `populate_rules_inner_slot`, `write_slot_rule_id`, `inactive_axis_fd`, `populate_action_table`, `populate_redirect_devmap` → **all 10 byte-identical** in `src/lib/materialize.cpp`.
- `LoaderCategory`/`loader_error_category()`/`classify`/`throw_loader` → byte-identical in `src/lib/loader_error.cpp:25-67` (promoted anon→external, def-only move; loader.hpp:57 decl untouched).
- `resolve_ifindex` body byte-identical at `loader.cpp:1300`, promoted anon→external `xdpmf::` (D-mvp-4.36-RESOLVE-SEAM); 2 surviving callers (`:1349` detach, `:1505` attach) textually unchanged; moved defs all removed from loader.cpp.
- fd-tag table `fake_bpf.cpp:66-81` = 14 written maps via `sizeof()` (guard #10, zero magic numbers); fake skel sets all 24 dereferenced `maps.X` (14 written-tag + 10 shadow). Decisions Q1/Q2/Q3/RESOLVE-SEAM/CLEAR-EMPTY/IMAGE-FINAL-STATE/SLOT0 all honored.

**Point 2 — Spec ↔ Tests.** `T_DRYRUN_IMAGE_IDENTITY` corpus (`dryrun_harness.cpp:92-116`) exercises every TestStrategy trigger: v4 LPM closure (10.0.0.0/8 covering 10.1.2.0/24), v6 dst6+src6, same-proto HASH aggregation (proto 6 ×2 → bits OR), dst_port range, wildcard axes, ≥1 Pass + ≥1 Drop, steering:redirect. SMOKE (`:423`) and NEGATION (`:449`, one-byte flip → comparator must report mismatch) both present and non-vacuous → NO-NEGATION-CONTROL does not fire. Not circular: the checked-in golden is produced by an **independent oracle** (`oracle_expected_records`, `--emit-golden`) that does NOT call `materialize` — spec-derived, not impl-captured.

**Point 3 — Code ↔ Tests.** Ran it myself (log `/tmp/mint-review-tests-1780745388.log`):
- `T_DRYRUN_IMAGE_IDENTITY` PASS (direct + ctest #112).
- `--emit-golden` (oracle) == checked-in golden **byte-for-byte**.
- `--emit-live` (impl's materialize via fake) == golden **byte-for-byte**. → spec-oracle == golden == impl-render, three-way agreement.
- Hand-derived spot values match: mac slot-bits (0x200/0x10), LPM closure (0x01 / 0x03), proto aggregation 0x0c, port range `50000000bb0100000800…`, vlan 0x20, ethertype 0x40, dst-wildcard 0x03fc, rules_a redirect `01020000`, action_table=3 rows, redirect_devmap symbolic `dpi0 RESOLVED-AT-APPLY`.
- No UNEXERCISED-EXPORT: all 3 entry points + `resolve_ifindex` driven by the harness.

**Point 4 — OOS drift.** None. No CLI verb, no human decoder, no typed MapImage, `copy_rule_counters_forward` stays in loader.cpp/excluded, no signature/call-site change, slot-0/`_a` only, zero datapath change.

**Point 5 — Behaviour preserved (brownfield).**
- **PI-mvp-4.36-LIVE-IDENTITY (hard gate):** byte-identical MOVE proven (above) + live ctests GREEN — `T_APPLY_VALID_CONFIG`, `T_APPLY_REPLACES_RULESET`, `T_REDIRECT_DELIVERY`, `T_REDIRECT_COUNTER_AND_MAP`, `T_INSN_BASELINE_GATE` (xdp **3477**).
- **PI-7:** `git diff src/lib/loader.hpp` = ∅.
- **src/bpf** = ∅ (insn 3477 held); **compiled_ruleset.* / ruleset_delta.* / config.* / common/xdpfilter.h** all = ∅ over `625c5a9~1..HEAD`.
- **Link contract (OPS-canary):** built `dryrun_harness`; `ldd` shows **no libbpf**; `nm -u` shows **no undefined bpf_map_/libbpf/if_nametoindex** (all satisfied by fake). CMake adds no `PkgConfig::LIBBPF`/`xdpmf_internal`/`loader.cpp`/`RESOURCE_LOCK`/`CI_BUILD_ONLY`.
- **Adjudication independently confirmed:** clash artifact `T_BPFFS_ROOT_SYMLINK` re-run PASS standalone (3.2s). #48/#63 reproduce as env-fails — host `/sys/fs/bpf` mode **1700** → `nobody` exporter hits ENOENT not EACCES → exit-6 path never fires (exit 999). They are **git-unchanged by the slice** (slice tests/ diff = only the 5 dryrun files, additively) AND were **already red in the prior baseline** `mint/test-run.prev.log` (#48 + #62-now-#63, identical exit-999 root cause) → **NOT regressions**.
- Design is internally consistent on ruling B (dense ARRAYs, action_table=3, no occupied filter) — no residual ruling-A contradiction → no [INCOHERENCE].

## Test execution (tail)
```
T_DRYRUN_IMAGE_IDENTITY ... Passed (ctest #112)
GOLDEN == ORACLE (spec-derived) ; LIVE == GOLDEN (impl render)
T_APPLY_VALID_CONFIG/T_APPLY_REPLACES_RULESET/T_INSN_BASELINE_GATE(3477)/
T_REDIRECT_DELIVERY/T_REDIRECT_COUNTER_AND_MAP ... 5/5 Passed
T_BPFFS_ROOT_SYMLINK ... Passed (standalone)
#48/#63 ... Failed (host /sys/fs/bpf mode 1700 — env, pre-existing, git-unchanged)
```

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] `add_dependencies(dryrun_harness xdpfilter_skel)` vs FileList "NO *_skel dep"
**Location**: `tests/CMakeLists.txt:1791` (+ vs `design.md` §5.76.2 "NO `*_skel` dep")
**Evidence**: FileList text fences "NO `*_skel` dep"; impl added a build-ORDER-only `add_dependencies` (materialize.cpp #includes generated `xdpfilter.skel.h`, so the header must exist first). It is NOT a link dep — verified `ldd`/`nm -u` show zero libbpf/skel-object symbols, so the OPS-canary link contract (§5.76.6, the load-bearing MUST) is fully preserved. Impl flagged the deviation inline (`tests/CMakeLists.txt:1785-1790`) with rationale.
**Recommended disposition**: `inline-merge`
**Rationale**: The §5.76.6 OPS-canary (which fences the *link line*) is satisfied; the §5.76.2 "NO *_skel dep" hint reads as link-scope, and per §5.76.7a the correct move is to amend the design hint to distinguish "no skel link/object dep" from "build-order header-gen dependency" — architect's call. No verdict impact.

### Post-review sweep — round 1
- OOT "add_dependencies skel build-order dep" → `mint/design.md` §5.76.2 FileList note edited → clarified that the `tests/CMakeLists.txt` "NO `*_skel` dep" fence is LINK-scope (no skel object/libbpf on the link line, per the §5.76.6 OPS-canary); a build-ORDER `add_dependencies(dryrun_harness xdpfilter_skel)` is REQUIRED + permitted because materialize.cpp `#include`s the generated `xdpfilter.skel.h`. Rides in the Phase 6 final commit.
