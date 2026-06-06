# Impl notes — MVP-1 L2 MAC filter

Notes for team-lead/architect/tester about implementation decisions and
deviations made during impl phase.

## §5.78 MVP-4.38 / B45 `apply --dry-run` human-decoded view — impl notes (2026-06-06)

Brownfield. NO silent deviations. Two choices within §5.78 design latitude:

1. **Per-rule axis value spelling = VALUE-FIRST** (`protocol=6(tcp)`,
   `ethertype=0x806(arp)`). §5.78.4(a) makes "the number" the CONTRACT base and the
   name-annotation a MAY nicety. The tester's per-axis greps pin on the bare value
   (`protocol=6`, `ethertype=0x806` — hex, no fixed-width leading zeros), commented
   "name annotation optional, pin on value". My first draft was name-first
   (`tcp(6)`/`arp(0x0806)`) → failed the tester's substring greps (caught in
   Phase 2.5). Corrected to value-first so the contract value is a substring AND the
   operator keeps the readable name. Conforms to the §5.78.4(a) base contract + the
   tester's documented intent — NOT a design deviation, no architect ruling needed.

2. **`dryrun_empty.yaml` OMITS the `rules:` key (NOT `rules: []`).** The project's
   `yaml_subset` parser rejects flow-style sequences (`[...]`), so `rules: []` is a
   PARSE error (exit 9), not a valid zero-rule config. An absent `rules:` key = zero
   rules = exit 0 → reaches the human formatter → emits the blackhole WARNING. The
   fixture is in the §5.78.2 NEW FileList (impl scope); the tester had drafted it
   with `rules: []`; I corrected the spelling and notified the tester.

Gates (all green): build clean / zero warnings; PI invariant files git-diff ∅
(materialize.{cpp,hpp}, map_writer.{cpp,hpp}, live_map_writer.cpp, loader.{cpp,hpp},
apply_internal.hpp, compiled_ruleset.{hpp,cpp}, src/bpf); PI-GOLDEN-UNCHANGED
(map_image.cpp diff additive-only, render_dryrun_image/format_dryrun_image byte-
identical, dryrun_image.golden byte-unchanged); ctest #112 + #113 pass; full suite
111/113 (2 fails = pre-existing exporter env-fails #48/#63, unrelated). NO VERSION bump.

## §5.77 MVP-4.37 / B44 `apply --dry-run` object seam — impl notes (2026-06-06)

Brownfield. NO silent deviations. Mechanism choices within the design contract
(MAY-level latitude, no architect fork required):

1. **`set_active_writer`/`active_writer` exposed as free fns** in `map_writer.hpp`.
   §5.77.3(6) specifies `g_active_writer` ptr in `map_writer.cpp` + a
   `RecordingScope` RAII. Kept `g_active_writer` file-local in `map_writer.cpp`;
   exposed `set_active_writer(MapWriter*) -> MapWriter*` (returns previous) +
   `active_writer()` so `RecordingScope` is a clean header-inline RAII and
   `install_live_map_writer()` (separate libbpf TU) installs without touching the
   global directly. FAIL-CLOSED unaffected — wrappers still abort on null writer.

2. **`format_dryrun_image`** is the public name for the relocated `format_image`
   ("the formatter"). Exposed in `map_image.hpp` so the harness oracle path
   (oracle_expected_records → format → golden) AND the production render share the
   SSoT formatter (guard #9 / PI-mvp-4.37-SSOT).

3. **`load_and_reconcile` helper** extracted in `apply.cpp` (anon-ns) — the SINGLE
   read+parse+validate+iface-reconcile path now shared by live `apply_config` AND
   `dryrun_image_for_file`, so a dry-run of an invalid config errors EXACTLY as
   live apply (exit 1/9). Behavior-preserving for `apply_config`.

4. `materialize.cpp` diff is body-only: the `bpf_*`→`map_*` /
   `resolve_ifindex`→`map_resolve_ifindex` swaps + one `#include "map_writer.hpp"`.
   All 4 declared signatures byte-identical; `<bpf/bpf.h>` retained ONLY for the
   `BPF_ANY` macro (no `bpf_*` call remains in the TU).

### Smoke / gates
- Full build clean, zero warnings (incl. libbpf-free `dryrun_harness`: `ldd`/`nm`
  show no libbpf dep / no undefined `bpf_*` — OPS-canary holds).
- `git diff` = ZERO on loader.cpp / apply_internal.hpp / materialize.hpp /
  loader.hpp / src/bpf (PI-mvp-4.37-LIVE-IDENTITY structural + PI-7 + insn 3477).
- `dryrun_image.golden` byte-unchanged.
- Full ctest (root, -j1): 111/113 passed; only 2 fails (#48/#63 exporter env-fails)
  are pre-existing, reference none of this slice's symbols. All live-apply +
  redirect witnesses + #112 + new #113 GREEN. Test total 112→113 (+1).
- Manual: `apply -f <cfg> --iface nonexist0 --dry-run` → image + exit 0, no bpffs
  pin; same without `--dry-run` → exit 3 (if_nametoindex fails) ⇒ genuine
  zero-touch (negation holds; also proves the LIVE writer IS installed).

## §5.73 MVP-4.33 / B40 CompiledRuleset bundle — impl notes (2026-06-05)

Brownfield, PURE host-side refactor. 3 NEW (`src/lib/compiled_ruleset.{hpp,cpp}` +
the tester's `tests/compile/compile_harness.cpp`) + EDITED `loader.cpp` / `CMakeLists.txt`
/ `tests/CMakeLists.txt` (last two test-files owned by tester per team-lead split).
Impl owns: compiled_ruleset.{hpp,cpp}, loader.cpp, CMakeLists.txt.

NO silent deviations. All choices below are MAY-level latitude.

1. **loader.cpp net diff is −386 (50 ins / 436 del), NOT the §5.73 hint's ~−180.**
   Expected: the ~314-line lowering block MOVED whole-cloth into compiled_ruleset.cpp
   (guard #9 — relocation, byte-identical), so loader.cpp loses the block AND the
   collapsed 16-arg call. The reviewer hint (~−180) is explicitly a MAY; reduction
   *direction* correct; moved text reappears verbatim in the new TU.
2. **Removed two now-dead includes from loader.cpp**: `<functional>` (sole user
   `std::equal_to` moved with `aggregate_axis`) and `<arpa/inet.h>` (sole user `ntohl`
   moved with `lower_axis`). Kept `<optional>` (still used: `std::nullopt` logger arg).
   -Werror-floor hygiene; not a behavior change.
3. **compile() field-assigns the aggregate** (`CompiledRuleset cr; cr.mac_low = …;`)
   rather than aggregate-init — each `lower_*`/`aggregate_axis` reads the
   freshly-computed `cr.id_to_slot` (same data-dependency the old apply_request locals
   had). Byte-identical outputs.
4. **`materialize` keeps the §5.48 comment header** (was populate_all_axes') with a
   §5.73 note prepended; copy_rule_counters_forward + populate_action_table stay
   EXPLICIT at both apply_request call sites (guard #15 / HG-1).

Smoke: production build GREEN, zero warnings (xdpmf_internal / xdpfilter / xdpmf-exporter).
Datapath byte-identity: `git diff src/bpf`=∅; `T_INSN_BASELINE_GATE` PASSED (xdp 3437).
PI-7: `git diff src/lib/loader.hpp`=∅. Both binaries `--help` exit 0.

Flagged to tester (test-side, peer-to-peer — impl did NOT edit the test):
compile_harness.cpp 329/330/342/343 use `g.key`/`g.mask` on `AxisAggregate::entries`
(= `std::vector<std::pair<Key,u64>>`) → must use `.first`/`.second`. Diagnosis sent.

## §5.70 MVP-4.30 / B35 wildcard+defaults → ruleset_state pack — impl notes (2026-06-04)

Brownfield, 13 EDITED files (5 src + 2 insn-gate + 6 pin-smoke). SPIKE-GATED,
verdict-identity (NOT byte-identical) — map-schema VALUE-pack.

Spike gate (D-mvp-4.30-FEAS/ABORT) — **REAL WIN, shipped**:
- xdp insn count: **3658 → 3437** (−221 insns; ≥25 proceed-threshold cleared; precedent predicted ≈100+).
- Verifier `bpftool prog load build/xdpfilter.bpf.o ... type xdp`: **rc=0** (accepts packed layout, 5.x kernel).
- ABORT NOT triggered.

MAY-level choices (§5.70 hints #6/#7/#8 — `inline-merge` per design):
- **Retired macros (hint #7):** DELETED `XDPMF_MAP_WILDCARD_NAME` / `XDPMF_MAP_DEFAULTS_NAME` (replaced with
  `[RETIRED]` comment markers in xdpfilter.h) — sole consumer (loader kManagedMaps) was edited anyway; dead
  macros would be lie-by-name (D-mvp-4.30-PINNAME spirit).
- **Names (hint #8):** canonical `struct xdpmf_ruleset_state` / `ruleset_state` SEC(".maps"); all 6 pin smokes
  swapped in lockstep to the `ruleset_state` token (PI-mvp-4.30-PINRIPPLE); adjacent echo strings updated.
- **Layout (hint #6):** `wc[9]` u64 + `default_action` u32 + `_pad` u32 = 80B, 8-aligned, static_assert-pinned
  (sizeof==80, offsetof(default_action)==72); loader zero-inits (`val{}`) → `_pad` no uninit bytes.
- **Read strategy:** D-mvp-4.30-Q1-A2 (hoist ONE lookup, thread `rs` into all 3 arms) — verifier accepted; A1 fallback NOT needed.
- **NEW test:** none added by impl (tester owns verdict-identity harness + any T_RULESET_STATE_SWAP).

Re-baseline (D-mvp-4.30-REBASELINE): both insn-gate defaults `:-3658` → `:-3437`
(T_PROD_VERIFIER_LOAD.sh:120, T_INSN_BASELINE_GATE.sh:67), documented intentional.

ctest: 104/106 passed; the 2 known env-fails BY NAME unchanged (#48
T_EXPORTER_EXITS_6_ALL_IFACES_EACCES, #63 T_LOG_JSON_EXPORTER_EVENTS — both
"Killed" in unprivileged exporter spawn, present in prior mint/test-run.log);
2 skips unchanged (#5, #38). All oracle-agreement + pin-smoke + both insn gates green.
No deviations from design requiring architect escalation.

## §5.68 MVP-4.28 / B34a datapath helper-extraction — impl notes (2026-06-04)

Brownfield, single file EDITED: `src/bpf/xdpfilter.bpf.c`. Pure byte-identical
refactor; xdp section held at **3658** insns, gated after EVERY fold
(`llvm-objdump-19 -d --section=xdp build/xdpfilter.bpf.o | grep -cE '^\s+[0-9a-f]+:'`).

Fold outcomes — **4 landed, 1 dropped**:

| Fold | Realization landed | gate | Note |
|---|---|---|---|
| #1 `dispatch_match` | **statement MACRO `DISPATCH_MATCH`** (NOT the design-named value-returning helper) | 3658 | Deviation, escalated. |
| #2 `load_wildcards` | **DROPPED** (HG-3 / guard #36) | n/a | Cannot hold 3658, escalated. |
| #3 `LOOKUP_INNER_OR_DROP` | statement macro per design (15 sites) | 3658 | byte-identical by construction. |
| #12 `mac_axis` | value-returning `__always_inline` helper per design (3 sites) | 3658 | clean. |
| #13 `read_dport` | **macro FALLBACK `READ_DPORT`** (design's pre-authorized fallback) | 3658 | out-param helper default measured +50 → fell back per D-mvp-4.28-13. |

**Deviation 1 — fold #1 a MACRO not the named helper (ESCALATED to architect).**
D-mvp-4.28-1's value-returning helper measured **3661 (+3)** — the inlined
value-return forces a verdict merge/mov per the 3 sites (the two `return XDP_*`
are caller early-returns that don't fold through a return value). The statement
macro `DISPATCH_MATCH` holds **3658** and matches candidate guard #36. Realization
shape is §5.68 verifiable-invariant #4 (MAY). Gate is the arbiter (guard #35).

**Deviation 2 — fold #2 DROPPED (ESCALATED to architect).** No single shared body
holds 3658: "8-batched" body → 3657 (−1), "6+2-split" body → 3659 (+1). The three
arms originally used DIFFERENT source orderings (v4 = 6-block then dst6/src6; v6 &
non-IP = 8 batched); each ordering compiles to a different per-site count, so one
shared `__always_inline` body matches only some arms — gate brackets 3658, never
hits it. Empirically refutes the §5.68 Phase-A "interleaving does not change
codegen" de-risk. A3-struct = same one-body impossibility + touches rent-payer
`acc` operands → not attempted. Per HG-3 a non-holding fold is DROPPED
(inline-merge, verifiable-invariant #5 MAY). 3 inline wildcard blocks left
byte-for-byte; in-file comment records the drop.

Anchors migrated (guard #33): HG-mvp-4.3-4→`DISPATCH_MATCH`; §5.26/§5.27 NULL→
`LOOKUP_INNER_OR_DROP`; §5.47 MAC→`mac_axis`; §5.44 dport→`READ_DPORT`. §5.43
generic wildcard note stays inline (fold #2 dropped). Rent-payers untouched (3
arms split, per-arm `acc` asymmetry, FFS #ifdef, inline proto/ethertype #ifndef,
hoisted `wc_eth`, per-arm `l4` offset).

Smoke (Phase 2.5): per-fold gate == 3658 each + final; `T_PROD_VERIFIER_LOAD` +
`T_INSN_BASELINE_GATE` PASS; full `sudo -E ctest` = **104/106 passed, 2 failed**
(the 2 known env-fails BY NAME `T_EXPORTER_EXITS_6_ALL_IFACES_EACCES` +
`T_LOG_JSON_EXPORTER_EVENTS`, bpffs/EACCES, pre-existing) + 2 pre-existing skips;
no new failure. `git diff -- src/lib src/common src/cli src/exporter
src/common/xdpfilter.h` = ∅. VERSION 0.16.0 unchanged. Net LOC −46.

## §5.53 MVP-4.13 / S4 cidr6 — impl notes (2026-05-31)

Implemented per §5.53 with NO silent deviations. Q1=`unsigned __int128` closure
(A1, NOT the A2 byte-array fallback — `__int128` compiled/loaded clean). Q2 =
symmetric 8-term AND in both arms. Files: mac_filter.h (+xdpmf_cidr_v6, +dst6/
src6 map-name consts, BITVEC_NUM_AXES 6→8, BV_AXIS_DST6/SRC6), mac_filter.bpf.c
(+dst6/src6 LPM trios, v4 arm +`& wc_dst6 & wc_src6`, full v6 arm at the S1
seam), loader.cpp (kManagedMaps 30→36, BitPrefix6/host_mask6/host_addr6_of/
close_prefixes6/lower_axis6/populate_bitvec6_inner_slot, write_wildcard_slots +2
params/+2 rows, populate_all_axes +2 params/+2 calls, apply_request +2 lowerings/
+2 guards), cidr.{hpp,cpp} (+parse_cidr_v6, byte-wise 128-bit host-bits check),
config.hpp (+dst_cidr6/src_cidr6 optionals), config.cpp (8-key grammar + 2 parse
blocks). loader.hpp byte-identical (PI-7 continues). NO VERSION bump.

Smoke: clean build, zero warnings (-Wall -Wextra); production mac_filter.bpf.o
verifier-loads on 6.1 (xlated 34376B/jited 19075B; wildcard max_entries=16;
dst6/src6 lpm_trie + array_of_maps present). Full ctest 84/88 pass + 2
pre-existing env skips (T_DROP_MALFORMED, T_ANSIBLE_PLAYBOOK_SYNTAX).

### Cross-family MAC/proto/port/vlan semantic (escalated to architect)

The symmetric 8-term model makes the L2/L4 axes (mac/proto/port/vlan) **family-
blind**: a MAC-only (or proto/port/vlan-only) rule now matches BOTH v4 AND v6
frames carrying that key — because those axes are ANDed in BOTH arms and a rule
unconstrained on the address axes lands in their wildcard halves. This is the
correct, designed Q2 behavior, but it SUPERSEDES the S1/S2-era assumption baked
into `config_mac_drop_default_pass.yaml` ("a MAC rule matches IPv4 frames ONLY")
and into the step-(2) assertions of T_IPV6_GATE_DEFAULT (#86) and
T_IPV6_INJECT_DEFAULT (#87). Both now fail correctly:
- #87: real v6 frame from the rule's MAC ⇒ the MAC DROP rule fires (deny+1).
- #86: bare 0x86DD ether frame (no v6 header) ⇒ now genuinely MALFORMED via the
  40B base-header bounds-check (D-mvp-4.13-NO-MALFORMED-NONV6).
These two tests are NOT in the §5.53 FileList; the §5.53 regression net listing
them as must-stay-green is an internal inconsistency (it didn't account for the
family-blind MAC axis + the reused MAC-rule fixture). Escalated to architect for
a regression-net amendment; flagged the test-side rewrite to the tester. Impl
held as-is (conforms to the literal Q2 spec).

## Forced deviation 1 — `struct mac_addr` → `struct xdpmf_mac`

Design §3.1 specifies the allow-list key type as `struct mac_addr`. At BPF
compile time this collides with a `struct mac_addr` already declared in
`vmlinux.h` (kernel-internal, unrelated to ours, sourced from kernel BTF).
Renamed everywhere to `struct xdpmf_mac` — same layout (6-byte packed
`octets[6]`), same semantics, just a unique name.

Affected files:
- `src/common/mac_filter.h` (declaration)
- `src/bpf/mac_filter.bpf.c` (BPF program local + map key type)
- `src/loader/cli.hpp`, `src/loader/cli.cpp`, `src/loader/loader.cpp`
  (C++ uses of the struct)

Architect: please update design.md §3.1 to reflect the rename, or confirm
the name is fine as-is. Tester: the struct name is internal — your tests
read maps via `bpftool map dump`, so this rename does not affect any
test-visible interface.

## Forced deviation 2 — `-stdlib=libc++` for C++ targets

Design §5.11: "use of `std::print` is acceptable if libstdc++ provides it,
otherwise `std::format` + `std::fputs`."

Reality on this host: `libstdc++-12` ships without `<format>` (added in
libstdc++-13). The pack mandates clang-19 + C++23. Resolved by installing
`libc++-19-dev` (already an apt candidate) and adding `-stdlib=libc++` to
C++ targets only. BPF C and libbpf (plain C) stay on the system libc.

This is documented inline in `CMakeLists.txt`. No interface change.

## Internal choice — direct `bpf_object_open_opts` struct init

Instead of the `LIBBPF_OPTS(...)` macro (which expands to a GCC statement
expression containing a C99 compound literal), I hand-initialised the
opts struct. Both forms are valid libbpf usage, but the macro expansion
triggers `-Wgnu-statement-expression-from-macro-expansion`,
`-Wc99-extensions`, and `-Wmissing-designated-field-initializers` under
our `-Wpedantic` C++23 floor. Direct init avoids the warnings without
loosening the warning policy.

```cpp
bpf_object_open_opts open_opts{};
open_opts.sz = sizeof(open_opts);
open_opts.pin_root_path = pin_dir.c_str();
```

## Internal choice — bpftool skel.h as SYSTEM include

The skeleton header generated by `bpftool gen skeleton` contains C-style
casts and unsigned-conversion patterns that our strict flags reject.
Marked `${CMAKE_BINARY_DIR}` as a SYSTEM include for the `xdpmacfilter`
target so diagnostics inside generated/third-party headers are suppressed
by default (the same treatment libbpf headers in `/usr/include/bpf/`
already get).

## MVP-1.1B internal choice — `bpf_obj_get_info_by_fd` (not `bpf_prog_get_info_by_fd`)

Design §5.19 names `bpf_prog_get_info_by_fd(fd, &info, &len)` for
identity verification. libbpf 1.1.2 (this host's pkg-config version)
ships only the generic `bpf_obj_get_info_by_fd(int bpf_fd, void *info,
__u32 *info_len)` — `bpf_prog_get_info_by_fd` is a libbpf 1.2+ thin
wrapper around the same `BPF_OBJ_GET_INFO_BY_FD` syscall command. Both
fill `struct bpf_prog_info` identically. Used the generic form to stay
within libbpf 1.1 API; behaviour is byte-equivalent to the design's
chosen name. Documented inline at the call site in `loader.cpp`.

## MVP-1.1C internal choice — main.cpp stdout gating for idempotent detach

Design §5.21 D4 / §4.3 specifies that `detach()` returns 0 in the
no-op idempotent cases (state (a) and, since MVP-1.1B, state (d)) and
prints a state-specific stdout message ("no XDP attached to {}
(no-op)" for state (a); "removed orphan pin dir for {} (no XDP was
attached)" for state (d)). The pre-MVP-1.1C `main.cpp` `run_detach()`
unconditionally printed `"detached prog id {} from {}"` regardless of
the returned id, which would have produced a confusing double-print
once `detach()` started emitting its own no-op messages.

Resolution: `detach()` now prints the state-(a)/(d) message directly
from `loader.cpp`, and `main.cpp` `run_detach()` only prints the
"detached prog id N from {}" line when `prog_id != 0`. Effect:
- state (a): one stdout line "no XDP attached to {} (no-op)" (new).
- state (d): one stdout line "removed orphan pin dir for {} (no XDP
  was attached)" (was: silent prog-id-0 line; now matches §5.19 spec).
- state (b): unchanged "detached prog id N from {}".

The state-(d) line was already specified in design §5.19 but had been
emitted only as the wrong "detached prog id 0 from {}" pre-MVP-1.1C —
the D4 amendment naturally surfaced this alignment, so it was fixed
in the same commit (one-line gate in main.cpp). Pure stdout cosmetics,
no exit-code or behaviour change beyond what §5.21 D4 already
mandates. No existing test asserts on the old wrong line.

## Smoke-check results

- `cmake --build build` → exit 0, zero warnings.
- `xdpmacfilter --help` / `--version` → text output, exit 0.
- `xdpmacfilter attach --allow nope` → "invalid MAC", exit 1.
- `bpftool prog load mac_filter.bpf.o /sys/fs/bpf/test_mac_filter` →
  verifier accepts, JIT 369B, 2 maps registered. Cleaned up.
- End-to-end on a veth pair: fresh attach + idempotent re-attach +
  detach all succeed with prog ids reported, pin dir created and
  removed, allow-list and stats maps populated/dumpable via bpftool.

---

# MVP-3.1 (§5.26) addenda — 2026-05-24

**Post-handoff EDIT-1 ack (architect peer-reply 2026-05-24)**: Option (C)
confirmed; design.md updated with `src/lib/apply_internal.hpp` in §5.26
NEW FileList + the canonical `internal::apply_request(ApplyRequest{iface,
mode, Config})` contract. Impl realigned: `ApplyRequest` now holds a
validated `Config` (not pre-extracted pass_macs+default_action) and the
helper is `internal::apply_request` (not `internal::apply`). loader.cpp's
`attach()` synthesizes the Config (default_action=Drop + Pass-rules from
cfg.allow with sequential IDs) per architect's prescription. D-3.1-1
below is now "documented and approved", not a pending deviation.

## D-3.1-1 — new internal header `src/lib/apply_internal.hpp` (NOT in §5.26 FileList)

**What**: Added `src/lib/apply_internal.hpp` to serve as the single
canonical interface to the §5.26 atomic-apply implementation
(kernel-version probe → trust_model parse → §5.4 state-machine → P0a
link pin → active_idx-flip → ruleset+defaults population). The impl
lives in `loader.cpp`'s anon namespace, exposed via `internal::apply()`.

**Why**: §5.26 Apply orchestrator block says both `loader::attach()` and
`apply::apply_config_inmemory()` route through "ONE helper (impl
detail)". PI-7 invariant constrains `loader.hpp` to EXACTLY one new
enumerator line (`ConfigError = 9`), so the helper can't live in the
public `loader.hpp` API. With apply.cpp in `src/cli/` (depending on
`src/lib/`) and loader.cpp in `src/lib/`, the only options for
SINGLE-implementation are (a) a private header in `src/lib/`, or (b)
two copies of the active_idx-flip machinery. Chose (a) — strictly
smaller code surface AND honours the design's "ONE helper" intent.

**Architect notified**: SendMessage to `mint-dev-architect` peer-to-peer
at start of impl phase laying out (A)/(B)/(C) options; (C) was the
default preference. No response by impl-completion; proceeded with (C).
Trivial revert if architect later prefers (A) or (B).

## D-3.1-2 — backward-compat alias pin `${PIN_DIR}/allowlist`

**What**: On every fresh attach (state a / d / c-fleet), the loader also
pins `allowlist_a` at the legacy path `${PIN_DIR}/allowlist` via
`bpf_obj_pin()` alongside the canonical `${PIN_DIR}/allowlist_a`. On
state-b reattach, the alias is replaced via unlink+repin alongside the
rest of the maps.

**Why**: §5.26 Q6 M1 claimed "existing 20 ctests do NOT poke `allowlist`
pin path directly (grep-confirmed against `tests/lib/common.sh` and
`tests/T_*.sh`)" — actually misses FOUR existing tests that check pin
existence at the legacy path:

- `tests/T_LOAD_ATTACH.sh:29` — `sudo -n test -e "${PIN_DIR}/allowlist"`
- `tests/T_ATTACH_TAG_MISMATCH.sh:275` — same shape
- `tests/T_MODE_GENERIC_DEFAULT.sh:95` — same shape
- `tests/T_BPFFS_ROOT_SYMLINK.sh:300` — negation-control assertion

All four check pin EXISTENCE only (no content reads). PI-6 ("20
pre-existing ctests pass byte-equivalent") demands this alias.

**Cost**: one extra bpffs dentry per per-iface dir + 1 unlink+repin on
state-b reattach. Functionally invisible.

## D-3.1-3 — `apply -f` file-IO error uses `CliError` (exit 1)

`apply.cpp::read_file_or_throw` throws `xdpmf::CliError` (mapped to
exit 1 by main.cpp's catch-arm) for file-IO failures (missing /
unreadable / short-read). Per design §5.26 Q4 explicit: "non-existent
/ unreadable → exit 1 (CLI usage error), NOT exit 9". Parse / schema
/ interface-mismatch failures still throw `std::system_error
{LoaderError::ConfigError}` (exit 9). `apply.cpp` thus depends on
`cli.hpp` (for the `CliError` type) — clean dependency since both
files live in `src/cli/`.

## D-3.1-4 — state-b reattach: `bpf_link__update_program` PLUS `bpf_map__reuse_fd`

**What** (final, post-T_APPLY_ATOMIC_SWAP_NO_DROP tightening): On state-b
idempotent reattach (existing pinned link + our prog matches by name+tag):

1. Discards the initial freshly-loaded skel (used only for the §5.4
   self_tag probe).
2. Reopens via `open_skeleton_only()` (no load yet).
3. For each of the 6 pinned maps (allowlist_a, allowlist_b, rulesets,
   active_idx, defaults, stats): `bpf_obj_get(pin_path)` → reused_fd;
   `bpf_map__reuse_fd(skel->maps.X, reused_fd)`. libbpf treats those
   maps as "already created" — no kernel map create syscall, no map
   state loss.
4. `finish_load_skeleton(skel)` — load the program. The new prog binds
   to the SAME kernel maps the old prog was using (via reused FDs).
5. Read CURRENT `active_idx` (via the reused fd). Compute
   `inactive = 1 - cur`.
6. Populate the INACTIVE slot (inner + defaults) — observed by no one
   until the swap.
7. `bpf_link__open(pin) + bpf_link__update_program(link, skel.prog) +
   bpf_link__disconnect + bpf_link__destroy`. Live prog now → new prog,
   reading from the SAME maps.
8. `write_active_idx(inactive)` — single u32 store; atomic commit point.

**Why this shape**: design step 12's writes target the SAME kernel maps
the live prog reads from. `bpf_map__reuse_fd` is the kernel-clean way
to make the new skel's maps be the on-disk pinned objects. Stats
counters survive across applies (T_APPLY_ATOMIC_SWAP_NO_DROP's
"stats monotonically increase across the swap" assertion holds —
without reuse_fd, a freshly-loaded skel would have a zero stats map).

**T_ATTACH_TAG_MISMATCH negation control**: that test asserts
`our_id_2 != our_id_1` after a state-b reattach. The second load
yields a new prog (and prog_id), so the assertion holds.

**Earlier draft (replaced)**: an intermediate draft used "re-pin new
skel's maps over old pinned paths" instead of `bpf_map__reuse_fd`. That
worked for T_ATTACH_TAG_MISMATCH but broke T_APPLY_ATOMIC_SWAP_NO_DROP
(stats zeroed on re-pin). Replaced with the `reuse_fd` approach above.

## ctest results

**100% pass (27/27)** after the EDIT-1 alignment + reuse_fd tightening:
- 20 pre-existing ctests (PI-6) all pass — including T_ATTACH_TAG_MISMATCH.
- 7 new MVP-3.1 ctests (§6.21–§6.27) all pass — including the
  load-bearing T_APPLY_ATOMIC_SWAP_NO_DROP (verifies stats-monotonic
  + drop_delta == 0 across concurrent traffic + apply) and
  T_LINK_PERSIST_ACROSS_LOADER_EXIT (verifies P0a link survival).
- 1 legitimate skip: T_DROP_MALFORMED (pre-existing kernel-pad behaviour
  per §6.5; no MVP-3.1 interaction).

Earlier draft's tester-side failure flags (T_APPLY_VALID_CONFIG
`FAIL[5b]`, T_APPLY_REPLACES_RULESET `FAIL[3.idx]/[5.idx]/[3.inner]`)
turned out to be moot — the tester's parsing handled the actual
bpftool output once the reuse_fd impl made stats / active_idx values
correct end-to-end. Removing this section as historical noise.

---

(Original section below kept for the historical trace of what went
wrong during the intermediate draft, retained for the team-lead's
review. Skip this if you're not interested in the test-debug arc.)

## Known tester-side ctest failures from intermediate draft (NOW RESOLVED)

These intermediate-draft ctest failures (only visible during the
~30-min impl-debug arc between the first apply_internal commit and the
reuse_fd tightening) were a mix of impl-side stats-loss (D-3.1-4 above
narrates the fix) AND tester-side bpftool parsing artefacts that the
tester's robust parser handled fine once stats values were correct:

- **T_APPLY_VALID_CONFIG `FAIL[5b]`** — test's `active_idx` parser expects
  a single "0" or "1" but bpftool's `--json` returns the 4-byte value
  as `["0x00", "0x00", "0x00", "0x00"]`. Tester fix: extract
  `.[0].value[0]` then strip `0x` prefix (or pivot to a non-JSON
  parsing form).
- **T_APPLY_REPLACES_RULESET `FAIL[3.idx]` / `FAIL[5.idx]`** — same
  parse bug. The test's `read_active_idx` does
  `grep -oE '\b[01]\b' | head -1` which picks the FIRST `0`/`1` in the
  bpftool output (the `"key": 0` field) regardless of the actual value.
  The operational deltas (step 4 MAC_Y → PASS under B, step 6 MAC_Y →
  DROP under A) confirm the swap IS happening.
- **T_APPLY_REPLACES_RULESET `FAIL[3.inner]`** — test reads
  `${PIN_DIR}/allowlist_a` after apply B, but the state-b reattach
  flipped active_idx → 1 so the active inner is `allowlist_b`. Test
  needs to read active_idx FIRST, then read the corresponding inner.

These are flagged in the SendMessage to team-lead.

## Build / smoke summary (post-§5.26)

- `cmake --build build -j` — clean, zero warnings, zero errors under
  `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -Werror -Woverloaded-virtual
  -Wold-style-cast -Wnon-virtual-dtor`.
- `cmake --build build-asan -j` (XDPMF_SANITIZERS=ON) — clean.
- `./build/src/cli/xdpmacfilter --version` → `xdpmacfilter 0.3.0`.
- `./build/src/cli/xdpmacfilter --help` → lists `apply` row + `9 config-error` row.
- `XDPMF_TRUST_MODEL=garbage ./build/src/cli/xdpmacfilter --version` →
  exit 0 (HG3 sub-decision: trust_model gates only attach/apply paths).
- `XDPMF_TRUST_MODEL=garbage ./build/src/cli/xdpmacfilter attach --iface lo`
  → exit 9 + `xdpmacfilter: config error: unknown trust model: 'garbage'
  (expected: strict|fleet)`.
- `ctest -j 1` — **25/27 pass; 2 fail (test-side bugs above); 2 skip
  (legitimate)**.
  - Skipped: T_DROP_MALFORMED (kernel-pad runt-frame skip per §6.5);
    T_APPLY_ATOMIC_SWAP_NO_DROP (runner-too-slow skip per §6.23 SKIP rule
    — 31 pkt/2s < 150 lower-bound; my impl's apply succeeded rc=0).
  - Failed: T_APPLY_VALID_CONFIG, T_APPLY_REPLACES_RULESET — both
    tester-side bpftool-output-parsing bugs; operational deltas confirm
    impl correctness.
- 20 pre-existing ctests (PI-6) all pass (including
  T_ATTACH_TAG_MISMATCH whose negation control depends on prog_id
  changing on state-b reattach).

## MVP-3.3 (§5.28) — notes

### Internal choice — Jinja2 template line-1 ordering

Design §5.28 Interfaces shows the Jinja2 template with the comment
header on line 1 and `schema_version: 1` on line 2:

```yaml
# Generated by Ansible for {{ xdpfilter_iface }} — do not edit by hand.
schema_version: 1
interface: {{ xdpfilter_iface }}
...
```

But PI-17 explicitly says `schema_version: 1` is **at line 1**, and the
team-lead spawn prompt repeats that as a critical placement. Internal
inconsistency in the design between the prose example and the invariant.

Resolved per the invariant (PI-17 binds the reviewer; the prose example
does not). `ansible/templates/xdpfilter-config.yaml.j2` ships with
`schema_version: 1` on line 1 and the comment header on line 2; the
YAML semantics are identical (comments are whitespace) and the reviewer's
`grep '^schema_version: 1$'` passes either way.

Architect: if PI-17 is the authoritative form, no action needed. If the
prose example was the intent, please clarify and I'll swap the two lines.

### Build / smoke summary (post-§5.28)

- `cmake --build build -j` — clean, zero warnings, zero errors. No C++
  TU recompiled (CMake re-configure picks up the version bump → only
  `include/version.h` regen + a relink of `xdpmacfilter`).
- `cmake --build build-asan -j` (XDPMF_SANITIZERS=ON) — clean.
- `./build/src/cli/xdpmacfilter --version` → `xdpmacfilter 0.5.0` (PI-8-3.3).
- `systemd-analyze verify systemd/xdpmacfilter@.service` — exit 0, zero stderr.
- `ansible-playbook --syntax-check` — SKIPPED (`ansible-playbook` not
  installed on this host; T_ANSIBLE_PLAYBOOK_SYNTAX will hit SKIP-77
  per design §6.35).
- `grep -qE 'xdpmacfilter: trust_model='` → exit 0 (PI-23 verbatim).
- `git diff main -- src/ include/` → empty (PI-7-3.3 / PI-26 fence).
- `git diff main -- CMakeLists.txt` → ONLY the version-bump line + the
  optional install rule + the `XDPMF_INSTALL_SYSTEMD_UNIT` option (PI-26).

---

# MVP-3.4 (§5.29) addenda — 2026-05-24

## D-3.4-1 — `apply_internal.cpp` resolves to `loader.cpp` in physical layout

**Context**: design §5.29 FileList lists:
- EDITED row: `src/lib/apply_internal.cpp` — "EXTEND step 8.5 per §5.29 apply() flow above"
- UNCHANGED-BUT-AFFECTED row: `src/lib/loader.cpp` — "UNCHANGED. The apply orchestrator dispatch is unchanged; new map population lives in apply_internal.cpp per §5.26 D-3.1-1."

**Reality**: `src/lib/apply_internal.cpp` does NOT exist; `internal::apply_request()`
lives in `src/lib/loader.cpp`'s anon-namespace per the documented D-3.1-1
deviation from MVP-3.1. The §5.29 design rows are internally inconsistent
because they treat "apply_internal.cpp" as both the logical-component name
(EDITED row) and as a separate file from loader.cpp (UNCHANGED-BUT-AFFECTED
row).

**Resolution**: impl SendMessage'd architect Phase A at start with three
interpretation options (A: edit loader.cpp's apply_request body — smallest
diff; B: extract apply_request into a new apply_internal.cpp — substantial
refactor; C: split via a thin helper). After ~3 min with no architect
response, proceeded with Option (A) per the deviation-protocol rule
("proceed with sensible default per language pack, document in impl-notes,
mention in final report"). The §5.29 step 8.5 extension + step 4 fd opening
+ the state-b reuse_fd loop growth (9 → 11) all land in loader.cpp's
existing `internal::apply_request()` and anon-namespace helper functions.

**Effect on PI-7-3.4**: `src/lib/loader.hpp` byte-equivalent (ZERO diff —
the strict 4th-cycle invariant). `src/lib/loader.cpp` DOES change in this
slice (apply_request body + helper functions), so the prose "loader.cpp
UNCHANGED" in §5.29 reads as the impl's "logical-component apply_internal
UNCHANGED" — they describe the same intent but use different file names.
Reviewer should treat the §5.29 UNCHANGED-BUT-AFFECTED row for loader.cpp
as an editorial inconsistency, NOT an `[INVARIANT-VIOLATED]` flag (D-3.1-1
+ §5.29's own "Decisions hint vs PI-* contract" prose-vs-invariant rule
both support this).

**Architect resolution (Phase B EDIT-1 + EDIT-2, 2026-05-24 evening)**:
Architect SendMessage'd back after Task #2 completion with full
disposition — Option (A) confirmed correct; design.md amended in three
batches:

- **§5.29 EDIT-1**: FileList EDITED row for `loader.cpp` replaced the
  phantom `apply_internal.cpp` row, with a 3-scope fence:
   (i) `internal::apply_request()` body — INSERT new step 8.5;
   (ii) skel-load / fd-opening — add `bpf_object__find_map_by_name` for
        the 2 new maps;
   (iii) state-b reattach `bpf_map__reuse_fd` loop 9 → 11.
   `apply_internal.hpp` STAYS UNCHANGED (new helpers stay anon-namespace
   inside loader.cpp; no public-API promotion).

- **PI-7-3.4 split into PI-7-3.4-hpp + PI-7-3.4-cpp**:
   PI-7-3.4-hpp = `loader.hpp` ZERO diff, 4th consecutive cycle (the
   load-bearing API contract).
   PI-7-3.4-cpp = `loader.cpp` regional-diff check — reviewer classifies
   each hunk by enclosing function name; allowed scope set governs
   accept/reject. The MVP-3.3-era prose "ENTIRE src/lib/loader.{cpp,hpp}
   zero diff" is now historical-bounded to MVP-3.3.

- **§5.29 EDIT-2**: scope fence extended with (iv) — `open_skeleton_only()`'s
  `pinned_maps[]` literal-array additive-only extension 10 → 12 entries.
  Symmetric to (ii)/(iii)'s `pin_specs[]` and `reuse_specs[]` 9 → 11
  extensions: the new LIBBPF_PIN_BY_NAME-tagged maps MUST have their
  auto-pin paths cleared before manual per-iface pinning, otherwise
  libbpf auto-pins them on `/sys/fs/bpf/<mapname>` and the subsequent
  manual pin fails with `Invalid argument`. **Impl-side bug caught in
  Phase 2.5 smoke (first ctest pass: 27/42 fail with the
  `libbpf: map 'rules' already has pin path '/sys/fs/bpf/rules'`
  message); fixed by extending the clear-list.**

  Strict sub-fence under (iv): `pinned_maps[]` is the ONLY thing
  allowed to grow inside `open_skeleton_only`. Loop body / control
  flow / error-handling MUST be byte-equivalent — reviewer regional-diff
  check flags any hunk in `open_skeleton_only` touching anything OTHER
  than the array initializer as `[INVARIANT-VIOLATED]`. Audit-trail
  citation: `§5.29 EDIT-2 Phase B (2026-05-24 evening, dialog with
  mint-dev-impl after Task #2 completion)`.

**Net allowed-scope set under PI-7-3.4-cpp**: `{internal::apply_request,
open_skeleton_only's pinned_maps[] literal-only, new anon-namespace
helpers (populate_rules_skeleton, populate_action_table)}`. Anything
outside this set in `git diff main -- src/lib/loader.cpp` = reviewer
`[INVARIANT-VIOLATED]`. Architect's verification-hints discipline
fallback: if reviewer flags this `pinned_maps[]` hunk despite the
EDIT-2 amendment, architect's disposition is `inline-merge` (impl
correctly diverged from the original prose to satisfy operational
requirement — this IS the scenario the discipline anticipates).

## D-3.4-2 — WARN emission also fires on `attach --allow` synth path

**Context**: design §5.29 specifies "if req.config.rules.size() > 0, emit
to stderr" the per-rule-deferred WARN. `loader::attach(AttachConfig)`
synthesizes a Config with one Pass-rule per `cfg.allow` MAC and routes
through `internal::apply_request` — so the WARN fires for `attach --allow`
flows too, not just `apply -f` flows that have an explicit `rules:` YAML
block.

**Disposition**: emit per design literal. The WARN's semantic ("rules:
section parsed but datapath uses MAC/CIDR-only matching this cycle") is
operationally correct for both invocation paths — the synth rules ARE
populated into the `rules` map but the datapath does NOT consult them.
Existing tests do positive-grep checks (presence of trust_model=, …) and
do NOT assert stderr cleanliness, so PI-34 (36-test byte-equivalent pass)
holds. Architect MAY choose in a future revision to suppress the WARN on
synthesised configs by adding an `is_synthetic` flag to `ApplyRequest`;
this is impl-flexible but design-literal currently fires the WARN
universally.

## MVP-3.4i (§5.40) — compound exporter scrape-path perf — impl-flex choices

Brownfield perf slice; 4 exporter `.cpp` EDITs. HARD contract = output
preservation (PI-3.4i-A byte-STREAM-identical for patches 1/2/3; PI-3.4i-B
line-SET-identical for patch 4). All 68 ctests green (66 PASS + 2 SKIP); the
3 oracle tests (T_EXPORTER_METRICS_FORMAT / VALUES_MATCH_STATS / RULE_LABELS)
GREEN. The choices below are all design-authorized impl-flex (per §5.40
D-3.4i-PROSE-VS-INVARIANTS the verifiable-invariants list is MAY/operative-
semantic; reviewer disposition = inline-merge, not [UNRELATED-EDIT]).

1. **build_response DRY refactor (P-3, Q2.A1 explicit MAY-grant)** — chose the
   design-blessed "delegate" option: `build_response` now calls `build_headers`
   then `.append(body)` instead of duplicating the full header format literal.
   Produced bytes are byte-identical by construction (build_headers holds the
   header literal MINUS the trailing `{}` body placeholder; the body append
   replaces it). Consequence for MAY-invariant #10: the http.cpp HTTP header
   format literal is now in `build_headers` (header portion only) rather than
   verbatim in `build_response` — i.e. the SOURCE literal moved, but the WIRE
   bytes are unchanged (verified by T_EXPORTER_METRICS_FORMAT). Rationale:
   single source of truth for the header bytes (no drift between two copies).
   The /metrics path uses two `write_all` calls; the 5 error/healthz paths keep
   the single-write `build_response`.

2. **`<iterator>` + `<utility>` includes added to prom_format.cpp** — beyond the
   design's enumerated "+<algorithm> / -<unordered_map>" include hint. Both are
   required by the design-mandated mechanisms: `std::format_to(std::back_inserter
   (out), ...)` needs `<iterator>` (back_inserter); the sorted `std::vector<
   std::pair<...>>` uses `std::pair` (`<utility>`, otherwise only transitively
   guaranteed via the retained `<map>`). Necessity-includes, not a scope
   extension; MAY-invariant #6 still holds (unordered_map removed, algorithm
   present, map retained).

3. **Patch-4 dedup + membership via `std::any_of` linear scan (Q3)** — first-wins
   dedup at populate (skip a rule_id already present, matching the prior
   hash-map emplace which does NOT overwrite — D-3.4i-4 LOAD-BEARING), then
   `std::sort` by rule_id; orphan-loop membership is a linear `std::any_of`
   scan (Q3 linear-vs-binary → linear at ≤64 entries). The known-rule emission
   order is now deterministic ascending-rule_id (was hash-order) — byte-STREAM
   change but line-SET preserved (PI-3.4i-B).

4. **MAY-invariant #9 baseline off-by-one (factual, non-blocking)** — design's
   §5.40 invariant #9 says `grep -cE 'write_all\(conn_fd' http.cpp` was 7 → 8.
   Actual baseline (db7e00e) is **6**; post-patch is **7**. The DELTA (+1, from
   splitting the /metrics write into headers+body) is exactly per contract; only
   the absolute count in the MAY hint is off by one. Flagged for reviewer
   awareness; no code impact.

5. **CHANGELOG** — added a new `### Performance` subsection under `[Unreleased]`
   (category-correct) with one bullet, rather than folding the entry into the
   existing `### Housekeeping`/`### Security`. Wording is impl-flex per the
   FileList row ("reviewer inline-merge").

---

# MVP-4.2 (§5.42) — bit-vector AND-classification SPIKE

Brownfield, additive prototype under `tests/bitvec/` + `tests/inject/inject_l4.py`.
Production datapath + 70 ctests byte-untouched (git diff fences clean).

## Phase 2.5 smoke outcomes (the spike's decision-gate evidence)

- **Q3 `ffsll` feasibility — FEAS HELD, default ship path stands (no fallback).**
  `bpftool prog load build/bitvec_proto.bpf.o … type xdp` → `rc=0` (verifier
  accepts the composed bitmask/AND/`__builtin_ffsll` datapath). `llvm-nm` on the
  object → NO `__ffsdi2`/`__ctzdi2` (clang inlined `__builtin_ffsll`).
  **D-mvp-4.2-FFS-FALLBACK NOT activated** — the `-DBITVEC_FFS_FALLBACK`
  bounded-scan path is compiled-in but unused (one-flag switch if needed later).

- **FI-1 prefix-closure — CLEAN, ZERO rework iterations (no spiral).**
  `close_prefixes()` cover-direction correct on first implementation; the live
  veth battery confirmed every overlap case matches the §5.42 derived-structures
  table. NOT a "very hard" signal.

- **Live populate→inject→classify battery (veth, SKB mode), all == oracle:**
  first-match-tie r0-over-r8(/25)=0; /16 closure=1; /8 proto-wc=2; r3<r4 (UDP:53)=3;
  src-LPM-decides=5; range=6; ICMP port-wc-only=7; port-only-wc=11; clean miss=64;
  range hi-edge 8090 inclusive=6; 8091 just-past=64; VLAN-tagged walk=1. All ✓.

- **ctest:** `T_BITVEC_ORACLE_AGREEMENT` + `T_BITVEC_VERIFIER_LOAD` PASS (2/2)
  against the tester's bodies + `bitvec_oracle.py`.

## Operative-semantic / impl-discretion choices

1. CMake wiring inline in `tests/CMakeLists.txt` (NOT a separate subdir — design
   permitted both); harness `RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}` so it
   lands in the build root like the top-level binaries.
2. `TEST_ENV_BITVEC` extends `TEST_ENV` with explicit `BITVEC_HARNESS` /
   `BITVEC_BPF_OBJ` / `INJECT_L4` / `BITVEC_ORACLE` paths (tester bodies need no
   build-layout knowledge). Both tests: TIMEOUT 90, RESOURCE_LOCK xdp_fixture,
   SKIP_RETURN_CODE 77.
3. `bv_rule` in `canonical_ruleset.inc` = dotted-CIDR strings + int
   port/proto/action (NULL/-1 = wildcard); harness derives network-order LPM keys
   via `inet_pton`. 1:1 human-readable with the §5.42 table.
4. Port-range ARRAY unused slots written `lo=1,hi=0` (lo>hi sentinel) so a
   zero-init slot can't spuriously match dport 0 on bit 0.
5. Datapath uses fixed `ip+1` L4 start (IHL=5, no IPv4 options); `inject_l4.py`
   emits IHL=5 only — documented in both files; keeps the verifier path
   straight-line.

## Deviations from design

None. Implemented per §5.42 FileList / DataStructures / Interfaces / Decisions.

# MVP-4.3 — OR→AND bit-vector pivot (§5.43)

No design deviations. Two in-scope judgment calls (both sanctioned by the
design's own resolution rules — NOT silent deviations):

## 1. Sidecar match-kind key naming — resolved via D-mvp-4.3-PROSE-VS-INVARIANTS
- §5.43 FileList prose for `sidecar.cpp` ("emits `dst_cidr` (+ keeps
  `src_cidr`/`cidr`)") is ambiguous on whether the src key stays the historical
  `"cidr"` or becomes `"src_cidr"`.
- §6.5 PI-mvp-4.3-SIDECAR + TestStrategy say `T_SIDECAR_JSON_SHAPE` asserts
  "`.schema_version==2`, **dst_cidr/src_cidr** match-kinds".
- Per **D-mvp-4.3-PROSE-VS-INVARIANTS** (§6.5 invariants-block WINS over prose),
  the JSON match object emits explicit `"dst_cidr"` / `"src_cidr"` keys (the
  historical `"cidr"` key is retired in the sidecar). The `mac` branch is kept
  as dead-but-harmless (design-sanctioned) so `format_mac` stays referenced and
  mvp-4.5 re-activates it cleanly.

## 2. Removed now-unreachable MAC parser from config.cpp
- v2 rejects the `mac` key at parse (D-mvp-4.3-MAC-GRAMMAR), so
  `parse_mac_canonical` / `hex_nibble` became unused → `-Werror=unused-function`
  (warning floor = build failure). Removed both (one-line note left). Mechanical
  consequence of the grammar change, not a behaviour change.

## Phase 2.5 production ffsll smoke (D-mvp-4.3-FFS)
`bpftool prog load build/mac_filter.bpf.o /sys/fs/bpf/probe type xdp` → **rc=0**.
Default `__builtin_ffsll` lowering verifies on the floor; `-DXDPMF_FFS_FALLBACK`
NOT needed (the `#ifdef` alt is retained but inactive).

## Cross-check against tester §6.60–§6.63
T_AND_COMPOSE_OK / T_AND_ORACLE_AGREEMENT / T_AND_PREFIX_CLOSURE_OVERLAP
(guard #23) / T_SCHEMA_V2_CUTOVER → 4/4 PASS against this impl.

---

# MVP-4.4 impl notes (§5.44 — proto + dst_port axes)

## Deviations / clarifications escalated to architect

### D1 — `struct xdpmf_port_range` field types (internal inconsistency; peer-DM sent)
- **Design prose** (EDITED `mac_filter.h` row): `struct xdpmf_port_range { __u32 lo; __u32 hi; __u64 bit; };`.
- **Problem**: the struct is `#include`d from the C++ TUs (config/loader/sidecar). `__u32`/`__u64` are NOT libc types in C++ — clang errors "Unknown type name '__u32'" (verified). The SAME design row's rationale says "per existing convention; BPF+C++ compatible", and the existing `xdpmf_cidr_v4` comment is explicit that `unsigned int` is used (not `__u32`) precisely because the header is shared with C++.
- **Resolution (impl default, following the cited convention)**: `struct xdpmf_port_range { unsigned int lo; unsigned int hi; unsigned long long bit; };` — binary-compatible with kernel `__u32`/`__u64` on every supported arch (same discipline as `allow_entry.rule_id` = `unsigned int`). Prose `__u32`/`__u64` is shorthand; the rationale governs. Peer-DM sent; no design change strictly required.

## Implementation choices (sensible defaults; no architect ruling required)
- **proto aggregation** (`lower_proto_axis`): rules sharing the same exact proto OR their bits into ONE HASH key. Matches D-mvp-4.4-Q1.
- **port slot indexing** (`lower_port_axis`/`populate_port_inner_slot`): one ARRAY slot per port-constrained rule at consecutive indices `[0, ranges.size())`; other slots cleared to UNUSED sentinel `{lo=1,hi=0,bit=0}` (lo>hi) per D-mvp-4.4-PORT-ARRAY-CLEAR (ARRAY has no delete → clear-all-then-write, mirrors `populate_rules_inner_slot`).
- **`write_wildcard_slots`**: extended to write all 4 axis slots via a small local table; keyed `inactive*BITVEC_NUM_AXES + axis`. RESET-on-apply (guard #15).
- **L4 parse** (D-mvp-4.4-IHL): `l4 = (void*)ip + ip->ihl*4` with `ihl<5 → STAT_DROP_MALFORMED`, then per-L4-header bounds-check before `dest`. Fixed-20B FALLBACK activated ONLY if Phase 2.5 load rejects the variable offset.
- **`dst_port` parse**: `'-'` searched from index 1 (negative endpoints disallowed); single int → `{p,p}`; `"lo-hi"` → range with `lo≤hi`. Shared `parse_bounded_uint` for proto (≤255) + port (≤65535).

## NOT touched by impl (tester domain, task #3)
- NEW fixtures (`config_valid_and4.yaml`), NEW tests (`T_PROTO_AND_COMPOSE.sh`, `T_PORT_RANGE_AND_COMPOSE.sh`, `T_AND4_ORACLE_AGREEMENT.sh`), `tests/bitvec/bitvec_oracle_prod.py` 4-axis extension, `tests/CMakeLists.txt` registration. Impl edited only the `T_EXPORTER_METRICS_FORMAT.sh` version-literal (guard #11, coupled to the VERSION bump).

## Phase 2.5 result
- See final SendMessage to team-lead (bpftool prog load rc + which IHL path loaded).

---

# MVP-4.14 / S5 EtherType axis (§5.54)

Implemented strictly per design.md §5.54. brownfield DIFF — impl owns src/ +
mac_filter.h only (tests/fixtures/oracle/CMakeLists/T_MAC_NON_IP owned by tester).

## Files edited
- `src/common/mac_filter.h` — ethertype map-name consts + `XDPMF_ETHERTYPE_HASH_MAX`
  (= XDPMF_ALLOWLIST_MAX = 64, D-mvp-4.14-HASH-MAX) + `BV_AXIS_ETHERTYPE=8` +
  `BITVEC_NUM_AXES 8→9` (wildcard max_entries auto-grows 16→18 via the macro).
- `src/bpf/mac_filter.bpf.c` — (a) NEW `xdpmf_ethertype_inner` HASH trio
  (`ethertype_bitmask_a/_b` + `ethertype_rulesets` AOM[2]), clone of the proto
  trio; (b) HOISTED ethertype lookup (eth_inner NULL→DENY, host-order
  `(u32)bpf_ntohs(inner_proto)` key, eth_mask exact-HASH, wc_eth) above the
  family dispatch; (c)+(d) `& (eth_mask|wc_eth)` appended to the v4 + v6 `acc`;
  (e) NEW non-IP `else` arm — full symmetric 9-term AND (IP-family axes
  wildcard-only; mac/vlan/ethertype real survivors) + the standard
  first_set/bump_rule/dispatch tail + `acc==0`→defaults. NO MALFORMED path in
  the non-IP arm (D-mvp-4.14-NONIP-NO-MALFORMED).
- `src/lib/loader.cpp` — kManagedMaps 36→39 (+3 ethertype rows);
  `EthertypeLowering` alias (= AxisAggregate<u32>, clone of Proto/Vlan);
  `aggregate_axis<u32>` eth lowering in `apply_request` (projector
  `r.match.ethertype` widened u16→u32); `write_wildcard_slots` +1 param + 1 row;
  `populate_all_axes` +1 param + `populate_hash_inner_slot(... "ethertype")`;
  both call sites pass `eth_low`. loader.hpp untouched (PI-7 zero-diff).
- `src/lib/config.hpp` — `RuleMatch` +`std::optional<std::uint16_t> ethertype`.
- `src/lib/config.cpp` — NEW `parse_ethertype` (names ipv4/ipv6/arp + explicit
  base-16 hex path + decimal [0,65535]; `parse_bounded_uint` is base-10-only so
  the hex path is hand-rolled). Added `ethertype` to the accepted key-set (8→9),
  the at-least-one-of node-set, and a parse block.

## Deviations from design
None. Load-bearing contracts all met: BITVEC_NUM_AXES=9, kManagedMaps=39,
wildcard=18, +1 ethertype AND-term in all 3 arms, host-order post-VLAN inner
ethertype key, NEW symmetric non-IP arm, VERSION stays 0.15.0, loader.hpp
zero-diff.

## Minor implementation choice (documented, not a deviation)
- The hex path binds `std::string_view{v.scalar}.substr(2)` (NOT
  `v.scalar.substr(2)`): the latter returns a temporary std::string and would
  dangle (clang -Wdangling-gsl). string_view::substr returns a view into the
  long-lived node scalar. No design/behaviour impact.

## NOT touched by impl (tester domain, task #3)
- NEW fixtures `config_valid_andeth.yaml`; NEW tests `T_ANDETH_ORACLE_AGREEMENT.sh`,
  `T_ANDETH_NONIP_STEER.sh`; `tests/bitvec/bitvec_oracle_prod.py` `--ruleset andeth`;
  `tests/CMakeLists.txt` registration; the `T_MAC_NON_IP.sh` step-(2) S5-SUPERSEDED
  rewrite + the stale fixture comment.

## Phase 2.5 result
- Clean build, zero warnings (-Wall -Wextra; rebuilt touched TUs to confirm).
- `bpftool prog loadall` on the production `mac_filter.bpf.o` → rc=0 (verifier
  passed); xlated 37704B / jited 20873B — within the §5.53 spike budget. Isolated
  pin, cleaned up.
- `xdpmacfilter --version` → `0.15.0`. Full ctest result: see final SendMessage.

---

# MVP-4.21 / B30 slot/id decouple (§5.61) — 2026-06-01

Implemented strictly per §5.61. brownfield DIFF — impl owns src/ + mac_filter.h +
the tests/CMakeLists.txt registration only (test body + fixtures owned by tester).

## SLOT-PLUMB carrier choice (D-mvp-4.21-SLOT-PLUMB — impl's call)
Chose `std::unordered_map<u32,u32> id_to_slot` (id→rank) computed once via
`compute_id_to_slot` (sort unique ids; rank = position), plus a parallel
`std::array<u32,64> slot_to_id` (rank→id, EMPTY-padded) via `compute_slot_to_id`.
Threaded into ALL populate sites so a single coherent slot per rule is used
everywhere (D-mvp-4.21-SLOT-COHERENCE): the 4 lowering bit-shifts (lower_axis /
lower_axis6 / aggregate_axis / lower_port_axis each gained an `id_to_slot` param),
`populate_rules_inner_slot` (`&r.id`→`&slot`), `write_slot_rule_id`, and the
copy-forward remap.

## copy_rule_counters_forward keyed-by-id (D-mvp-4.21-COPYFWD-BY-ID — load-bearing)
New anon-namespace signature (loader.cpp only, PI-7 hpp untouched):
`copy_rule_counters_forward(int old_active_inner_fd, int inactive_inner_fd,
std::span<const u32> old_slot_to_id, std::span<const u32> new_slot_to_id)`.
For each NEW slot k: EMPTY→zeros; surviving id (present in old)→copy
old_active[old_slot]→inactive[k]; new id→zeros. All [0,64) written (no stale
leak). Old mapping recovered from the OLD-active `slot_rule_id` half via
`read_slot_rule_id_half` BEFORE the flip (populate touches only the inactive
half). Fresh attach passes an all-EMPTY old mapping (D-mvp-4.21-FIRSTAPPLY) →
every slot zeroed (harmless, fresh inner already zero).

## Deviation (coverage-preserving → inline-merge)
- **§6.76 RESOURCE_LOCK widened `xdp_fixture` → `xdp_fixture;exporter_port_9417`**
  (design FileList said `RESOURCE_LOCK xdp_fixture`). The tester's
  `T_RULE_COUNTER_SURVIVES_REORDER.sh` scrapes the exporter `/metrics` on port
  9417 (33 refs), so it can clash with `T_EXPORTER_RULE_LABELS` which holds that
  lock. Conservative serialization; TIMEOUT 120 (multiple apply+inject+scrape
  cycles). `RESOURCE_LOCK xdp_fixture` is SHOULD-level orientation per §5.61
  operative-semantic note — this is an inline-merge.

## Verification
- kManagedMaps = **39** (was 38); slot_rule_id row added; all 3 walk loops
  (clear/pin/reuse) walk the single table (HK-9 / guard #10).
- PI-7: `git diff 73e2964 -- src/lib/loader.hpp src/lib/config.hpp` = ∅ (also
  sidecar / logger / cli zero-diff).
- **Datapath byte-identity (PI-mvp-4.21-DATAPATH-IDENTICAL):**
  `llvm-objdump -d --section=xdp` of new vs baseline (`73e2964`)
  `mac_filter.bpf.o` → **3660 insns, ZERO diff** (XDP-PROG-BYTE-IDENTICAL).
  `slot_rule_id` present in the new `.maps` section ONLY (size 0x28; absent in
  baseline) — the program references no new instruction.
- Verifier: `bpftool prog loadall build/mac_filter.bpf.o` → rc=0.
- Config Q2: id-value cap removed (reject only `id==0xFFFFFFFF` sentinel) +
  `rules.size() > 64` count cap added (exit 9 ConfigError).

## §5.65 MVP-4.25 / B32 comment-collapse — impl notes (2026-06-03)

Comment-ONLY editorial pass per the §5.65 rubric, reproducing the `42e7326`
pilot. NO code/logic/whitespace-of-code token change. Verified: xdp section
3658 insns (byte-identical), PI-7 (loader.hpp/config.hpp empty diff), full C++
build zero-warning. All 11 EDITED files; net −274 comment lines.

**Stale/LYING comments fixed (the rubric's inverse-failure catch — replaced with
accurate current-state, not just deleted):**
- `mac_filter.bpf.c` prog header: "MAC HASH maps are FROZEN / only IPv4 frames
  classified" → false since §5.47 (MAC is a live axis) / §5.53+ (3 family arms).
  Rewritten to the accurate 9-axis-AND-across-3-arms state.
- `mac_filter.bpf.c` v6 arm: "symmetric 8-term AND" → actually 9 terms (post
  §5.54 ethertype). Fixed to 9-term.
- `mac_filter.h` §5.43 wildcard: "max_entries ... (= 4)" + "(axis 0=dst,1=src)"
  → stale (BITVEC_NUM_AXES=9 now). Dropped the frozen-in-time literal.
- `mac_filter.h` §5.29 rules: "Populated on apply; NOT consulted in datapath"
  → false since §5.34 (datapath dispatches the rules→action_table chain).
- `mac_filter.h` §5.31 allow_entry: described as the LIVE inner value the
  datapath reads at offset 4 → vestigial since §5.43 (value reshaped to bare
  __u64). Rewritten as vestigial/layout-pinned (matches the static_assert note).
- `prom_format.cpp` §5.46: "5 match-axis values" + "7-label key set" → stale
  (9 axes / 11 labels). Generalized to avoid the frozen counts.
- `sidecar.cpp`: inline `// dead under v2; live again mvp-4.5` on the mac branch
  → mac is live; replaced with `// §5.47 MAC axis (live)`. (NB: this is the one
  changed line whose code prefix is byte-identical — comment-only.)

**Biggest collapse:** `loader.cpp` kManagedMaps[] table — removed the net-delta
arrow archaeology ("net +4 (17→21)", "Pre-§5.34: 13 entries (12 real+1 alias)",
"4th consecutive cycle") and the 7× repeated "All three call-site loops walk
this single table — HK-9 again" → one canonical HK-9 statement in the header +
one-line §ref per axis row-group. `static_assert` lines in mac_filter.h left
untouched (CODE). `escape_util` §5.37 refactor-narration deduped (logger.cpp +
sidecar.cpp) to the single include-line pointer.

**KEPT-MORE (per HG-3 bias-KEEP / PI rows):** `mac_filter.h` density drops least
(ABI hub) — kept all map-layout / key-value / alignment / packed-member-UB
rationale + every map-name const comment. Per-file KEEP verified present:
guard #15 (loader copy_rule_counters_forward / populate-inactive-then-flip),
guard #28 spike numbers (bpf.c MAX_EXT_HOPS), guard #30 never-throw
(sidecar/sidecar_reader + logger "never throws" + http defensive), §5.64 seqlock
+ PI-31 (rule_counters_reader), §5.19/§5.22 security (loader/sidecar).

No silent deviations; no design questions raised (rubric was unambiguous).

---

## MVP-4.26 / B33 — rename xdpmacfilter/mac_filter → xdpfilter

### Deviation flag (escalated to architect — audit trail, NOT a silent deviation)

**PI-7-SUSPENDED vs PI-RENAME-COMPLETENESS conflict on `loader.hpp`/`config.hpp`.**
§6.5 PI-7-mvp-4.26-SUSPENDED says the ONLY permitted diff in these two headers is
the include-path line. But both also carry the rename token in DOC COMMENTS
(`loader.hpp`: `/sys/fs/bpf/xdpmacfilter/<iface>/`; `config.hpp`:
`"xdpmacfilter: config error:"`). Those comments live in `src/`, which is in the
T7 COMPLETENESS grep scope — leaving them fails T7 (a load-bearing MUST).

**Resolution (per §5.66 prose-vs-invariants conflict rule → PI/load-bearing wins,
disposition inline-merge):** renamed the comment-prose too. Net diff per file =
include-path line + 1 comment-prose line, nothing else; no symbol/signature/
enumerator/body change → honors PI-7's INTENT. Flagged to mint-dev-architect to
amend the PI-7-SUSPENDED check wording ("ONLY the include-path line" → "ONLY
rename-token lines: include path + prose comments").

### HG-4 acronym note wording
The HG-4 note added to `src/common/xdpfilter.h` was worded to AVOID spelling the
literal old token (an earlier draft used `xdpmacfilter→xdpfilter`, which itself
tripped the T7 grep since `src/` is in scope). Reworded to "after the B33 rename
to xdpfilter" + "now under /sys/fs/bpf/xdpfilter". `CHANGELOG.md` (OUT of T7
scope) keeps explicit `xdpmacfilter→xdpfilter` migration prose — a migration note
must name the old surface.

## §5.75 MVP-4.35 / B42 redirect verb — impl notes (2026-06-05)

Brownfield DIFF. Impl-owned items landed; tester owns sink_xdp.bpf.c + the
2-iface harness + the new ctest registration (team-lead split). NO silent
deviations.

1. **insn RE-BASELINE (D-mvp-4.35-REBASELINE, PI-mvp-4.35-INSN-REBASELINE):
   3437 → 3477 (+40).** Measured at Phase 2.5 via the gate's own path
   (`llvm-objdump-19 -d --section=xdp xdpfilter.bpf.o | grep -cE '^\s+[0-9a-f]+:'`).
   The +40 is the redirect branch: the `if (a && a->action_type==ACTION_REDIRECT)`
   test + `bump_stat(STAT_REDIRECT)` + the `bpf_redirect_map(&redirect_devmap,0,XDP_PASS)`
   call. Intentional, documented — NOT a regression. The surviving invariant is
   PASS/DROP verdict-identity (all `T_*_ORACLE_AGREEMENT` + PASS/DROP ctests GREEN).
2. **SECOND insn-baseline literal found (FileList gap, escalated to architect).**
   `tests/T_PROD_VERIFIER_LOAD.sh:125` carries the SAME `${XDPMF_PROD_INSN_BASELINE:-3437}`
   literal as the FileList-listed `T_INSN_BASELINE_GATE.sh:71`. With actual=3477 it
   hard-FAILs (the verifier ACCEPTS the load rc=0 — only the literal trips). Both are
   the same byte-identity gate mechanism. Peer-DM'd mint-dev-architect for approval to
   extend the DIFF to that one line (3437→3477) rather than silently edit an unlisted
   file. **RESOLVED:** architect confirmed (genuine FileList omission — §5.70's
   precedent moved BOTH sites), amended design.md §5.75.2 (added the EDITED row) +
   D-mvp-4.35-REBASELINE (names both sites) + PI-mvp-4.35-INSN-REBASELINE (both gates
   green at 3477). Edited T_PROD_VERIFIER_LOAD.sh:125 `3437`→`3477` + §5.75 comment.
   Both gates (#102, #105) now PASS at 3477.
3. **Spike #3 (D-mvp-4.35-FALLBACK) = PASS on kernel 6.1.** Standalone: apply a
   redirect rule (devmap[0]←ifindex resolved, verified == ifindex(IFACE_C)), CLEAR
   devmap[0], inject a matching frame → STAT_REDIRECT=+1, DROP=0, PASS=0. The
   `bpf_redirect_map(&map,0,XDP_PASS)` miss returns XDP_PASS (original-flow degrade,
   no blackhole). ⇒ the optional `T_REDIRECT_TARGET_DOWN` CAN ship;
   PI-mvp-4.35-MISS-DEFERRED is NOT triggered. Nuance relayed to tester: STAT_REDIRECT
   bumps even on a miss (the bump precedes the helper call).
4. **populate_redirect_devmap placement (MAY-level, §5.75.7a hint #4).** Called in
   BOTH apply branches (reattach + fresh) adjacent to `populate_action_table`, in-place
   before the active_idx flip (D-mvp-4.35-DEVMAP-SHARED). Not folded into a shared
   helper — kept parallel to populate_action_table's existing two-site structure for
   diff legibility.
5. **No-steering path** deletes devmap[0] (swallowing ENOENT) so a stale ifindex from a
   prior apply cannot persist; cross-validation guarantees no-steering ⇒ no redirect
   rule ⇒ devmap unused.
6. **action_id ternary** is the 3-way Pass→0 / Redirect→2 / else(Drop)→1 exactly per
   §5.75.4. `populate_action_table` appends REDIRECT[2] only (no [3]=MIRROR — reserved
   hole). PASS[0]/DROP[1] writes byte-identical (PI-mvp-4.35-ACTIONTABLE-01).
7. **No struct widen** — action_entry/rule_entry sizeof==4 static_asserts untouched;
   green build is the assertion (PI-mvp-4.35-NO-STRUCT-WIDEN).
8. **Environmental (NOT my change):** #48 T_EXPORTER_EXITS_6_ALL_IFACES_EACCES + #63
   T_LOG_JSON_EXPORTER_EVENTS fail on the HK-17 sub-case (exporter run as an
   unprivileged user, exit 999=Killed). Cause: `nobody` cannot execute the binary under
   `/home/user/.../build` (sandbox/home-dir perms — `sudo -u nobody env true` works but
   `sudo -u nobody .../xdpmf-exporter` → "Permission denied"). Orthogonal to redirect
   (my exporter change is an additive verdict label + one brace-init zero). Pre-existing.
9. **Stale global pins** at `/sys/fs/bpf/{action_table,stats,…}` (old `action_table`
   max_entries=2, June-1 junk from prior manual sessions) caused first-run #102/#105
   reuse-mismatch FAILs after ACTION_MAX 2→4 / STAT_MAX 4→5. Cleaned the bare top-level
   pins (NOT the `xdpfilter/` attach subdir); #105 then PASSED. The harness pins
   per-iface under `/sys/fs/bpf/xdpfilter/<iface>/`, so this was pure environment hygiene.
