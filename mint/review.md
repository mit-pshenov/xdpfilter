# Review — MVP-1.1B §5.4 trust-boundary hardening (mint triangulation, round 1)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 1 minor (negotiated) + 1 informational | [NEGOTIATED-DEVIATION × 1, INFO × 1] |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 (9/9 green, T_DROP_MALFORMED legit SKIP) | — |
| 4. Out-of-Scope Drift | 0 | — |

## Findings

### [NEGOTIATED-DEVIATION] libbpf 1.1 portability: `bpf_obj_get_info_by_fd` instead of `bpf_prog_get_info_by_fd`
**Location**: `src/loader/loader.cpp:188` (vs `mint/design.md:511`)
**Evidence**: design §5.19 names `bpf_prog_get_info_by_fd(fd, &info, &len)`; code calls `bpf_obj_get_info_by_fd(fd.get(), &info, &info_len)`. Both invoke the same `BPF_OBJ_GET_INFO_BY_FD` syscall command and fill `struct bpf_prog_info` byte-identically; the latter is the libbpf 1.1 spelling (this host's pkg-config version), the former is a libbpf 1.2+ wrapper.
**Negotiated?**: yes — `mint/impl-notes.md:62-71` ("MVP-1.1B internal choice — `bpf_obj_get_info_by_fd` (not `bpf_prog_get_info_by_fd`)"), explicitly framed as a portability deviation with semantic equivalence cited.
**Fix**: none required — the agent-spec negotiation record is the contract.
**Assign to**: —

### [INFO] `XdpProbe::name` type: `std::string` vs design's `std::array<char, BPF_OBJ_NAME_LEN>`
**Location**: `src/loader/loader.cpp:81` (vs `mint/design.md:567`)
**Evidence**: design §5.19 (POD layout, line 562-569) specifies `std::array<char, BPF_OBJ_NAME_LEN> name; // kernel-truncated NUL-padded` and notes `sizeof(XdpProbe) ≤ 32` and "no heap on the success path". Code uses `std::string name` (which on libstdc++/libc++ is 24-32 bytes itself, may heap on longer names — though `BPF_OBJ_NAME_LEN=16` so SSO covers it on libc++ -stdlib). Same line in §5.19 explicitly grants: *"Impl may rename `XdpMode`/`XdpProbe` if it prefers, but the field set is the contract."*
**Negotiated?**: implicit via the "field set is the contract" grant; the field set `{prog_id, mode, is_ours, name}` is preserved, functional semantics unchanged. Not in impl-notes.md but the design clause permits it.
**Fix**: optional — if architect wants the sizeof/heap-discipline invariant enforced, impl-notes.md should note the std::string choice; or §5.19 line 567 could be relaxed to "string-like, kernel-truncated NUL-padded". Not blocking.
**Assign to**: architect (next pass, doc tightening) — informational only.

## Triangulation evidence (detailed)

### 1. Spec ↔ Code — all amendments implemented

- **§5.4 4-state matrix in `attach()`** (`loader.cpp:280-313`):
  - state (a) — `probe.prog_id == 0 && !pin_dir_exists` → falls through to `ensure_bpffs_dir` + fresh attach (line 316+). ✓
  - state (b) — `probe.is_ours && pin_dir_exists` → `bpf_xdp_detach` + `bpffs_remove_iface` + fresh attach (`loader.cpp:286-294`). ✓
  - state (c) — `probe.prog_id != 0 && !probe.is_ours` → `throw_loader(AttachRefusedAlien, …)` (`loader.cpp:295-305`). ✓ Stderr format includes prog_id, mode, AND name per §5.19 line 590.
  - state (d) — `probe.prog_id == 0 && pin_dir_exists` → `bpffs_remove_iface` + fresh attach (`loader.cpp:306-312`). ✓ Same exit 0 path, no new exit code (matches §4.1 MVP-1.1B note line 157-162).
- **§5.4 detach() mirroring** (`loader.cpp:384-424`):
  - state (a) in detach (no prog, no dir) → `DetachFailed` exit 5 (`loader.cpp:399-402`). ✓
  - state (d) in detach → orphan cleanup, return 0 (`loader.cpp:392-398`). ✓ Matches §5.4 line 278-281.
  - state (c) in detach → `DetachFailed` (`loader.cpp:405-414`). ✓
  - state (b) in detach → `bpf_xdp_detach` + cleanup, return prog_id (`loader.cpp:416-423`). ✓
- **§5.19 identity check**:
  - `bpf_prog_info.name` compared against `"mac_filter_prog"` literal via `kOwnedProgName` constant (`loader.cpp:58`). ✓
  - `strnlen`-bounded byte compare (`loader.cpp:194-196`). ✓ — exactly matches §5.19 line 514-517.
  - Fail-closed on `bpf_prog_get_fd_by_id` errno (`loader.cpp:175-180`) AND on info-fetch errno (`loader.cpp:188-190`) — both return false, caller treats as alien. ✓ Matches §5.19 line 579-585.
  - `UniqueFd` RAII deterministic close (`loader.cpp:86-114`, used at `loader.cpp:181`). ✓ Kept in `loader.cpp` anon namespace per §5.19 line 575-578 ("NOT exported in `raii.hpp`").
- **§5.20 all-modes XDP query**:
  - Single `bpf_xdp_query(ifindex, 0, &opts)` with `opts.sz = sizeof(opts)` (`loader.cpp:210-213`). ✓
  - Mode priority HW > NATIVE > SKB at `loader.cpp:220-228`. ✓ Matches §5.20 line 651-656.
  - is_ours conjunction: `name_match && (mode == XdpMode::Skb)` (`loader.cpp:237`). ✓ Matches §5.19 line 567 + §5.20 line 658-660.
- **§4.3 anon-namespace discipline**:
  - All new helpers (`XdpMode`, `XdpProbe`, `UniqueFd`, `to_string`, `fetch_prog_identity`, `probe_attached_xdp`) live inside `namespace { ... }` at `loader.cpp:49-268`. ✓
  - `loader.hpp` byte-identical to MVP-1 (`git diff HEAD~2..HEAD -- src/loader/loader.hpp` → empty). ✓ Public `attach()`/`detach()` signatures unchanged per §4.3 line 216-219.
- **State (c) stderr contract**: format string `"XDP prog id {} (mode {}, name '{}') already attached to {} (not ours — refusing to clobber)"` at `loader.cpp:301-304` includes the foreign prog id as the first `{}`. Runtime evidence: `mint/test-run.log:53` — `"XDP prog id 11536 (mode SKB, name 'xdp_pass_prog') already attached to veth_a (not ours — refusing to clobber)"`. ✓

### 2. Spec ↔ Tests — §6.9 outcomes all present

| §6.9 outcome | Test assertion | Location |
|---|---|---|
| (a) rc == 4 | `[[ "${rc}" != 4 ]]` aggregator with KC-A/KC-B regression hints | `tests/T_ATTACH_ALIEN_REFUSAL.sh:88-95` |
| (b) stderr contains foreign prog id | `grep -q -F -- "${foreign_id}" "${stderr_file}"` | `tests/T_ATTACH_ALIEN_REFUSAL.sh:98-101` |
| (c) foreign STILL attached | `[[ "${now_id}" != "${foreign_id}" ]]` | `tests/T_ATTACH_ALIEN_REFUSAL.sh:104-108` |
| (d) no orphan pin dir | `[[ -e "${PIN_DIR}" ]]` | `tests/T_ATTACH_ALIEN_REFUSAL.sh:111-115` |

All four assertions use the `fail=0` aggregator + final `exit "${fail}"` pattern (§6.9 line 959-960) — every failure is reported, not short-circuited.

Fixture wiring: `tests/CMakeLists.txt:22` `add_bpf_object(xdp_pass …)` ✓ per §6.9 line 885-889. Foreign fixture `tests/fixtures/xdp_pass.bpf.c:22` `int xdp_pass_prog(...)` ✓ — function name differs from `mac_filter_prog` per §6.9 line 880-884.

Test registration: `tests/CMakeLists.txt:44` adds `T_ATTACH_ALIEN_REFUSAL` to the existing veth-fixture `foreach` block (recommended path per §6.9 line 982-988), inherits `RESOURCE_LOCK xdp_fixture` + `TIMEOUT 60`. ✓

NO-NEGATION-CONTROL rule: per brief, T_NEGATION_CONTROL (§6.7) still serves suite-level floor. ✓

### 3. Code ↔ Tests — 9/9 green, alien-refusal end-to-end verified

Re-ran `sudo -E ctest --test-dir /home/user/mint-l2-mac-filter/build --output-on-failure` — captured to `/tmp/mint-review-tests-mvp1.1b-1779524244.log`. Result: 100% pass, T_DROP_MALFORMED legit SKIP (matches §6.5 design note + `mint/test-run.log` Phase B). Verbose re-run of T_ATTACH_ALIEN_REFUSAL confirms loader stderr at runtime: `XDP prog id 11586 (mode SKB, name 'xdp_pass_prog') already attached to veth_a (not ours — refusing to clobber)` — exit 4 observed (acceptance #9 met).

UNEXERCISED-EXPORT spot-check: this pass adds zero new exported symbols (all helpers anon-namespace per §4.3 amendment). `attach()`/`detach()` exercised by T_LOAD_ATTACH, T_PASS_ALLOWED, T_DROP_DENY, T_IDEMPOTENT_RELOAD, T_NEGATION_CONTROL, T_ATTACH_ALIEN_REFUSAL, T_SANITIZER_BUILD. No flags.

### 4. OOS Drift — clean

`git diff HEAD~2..HEAD --name-only` shows: `mint/design.md`, `mint/impl-notes.md`, `src/loader/loader.cpp`, `tests/CMakeLists.txt`, `tests/T_ATTACH_ALIEN_REFUSAL.sh`, `tests/fixtures/xdp_pass.bpf.c` (+ `.cache/clangd/` index file, ignorable build artifact). ✓ Brief OOS fence verified:
- PERCPU stats: not touched. ✓
- `--mode` CLI flag: no new flags in cli.cpp (untouched, `git diff` empty). ✓
- raii.hpp ghost comment, inject_runt.py docstring, pkg_check_modules version qualifier, all M/L hybrid findings beyond KC-A/KC-B/H1/M1: untouched. ✓
- 8 pre-existing tests byte-identical: `git diff HEAD~2..HEAD -- tests/T_*.sh tests/lib/common.sh` (excluding new T_ATTACH_ALIEN_REFUSAL.sh) → zero lines. ✓ Acceptance #7 met.
- `src/loader/{cli,main,raii}.{cpp,hpp}`, `src/bpf/`, `src/common/`: `git diff HEAD~2..HEAD` → zero lines. ✓
- `CMakeLists.txt`, `cmake/BpfBuild.cmake`: zero lines. ✓

### Brief acceptance criteria — all met

| # | Criterion | Evidence |
|---|---|---|
| 1 | §5.4 amended in-place + §5.19 amendment | `design.md:247-303` (§5.4 4-state table); `design.md:490-609` (§5.19 identity gate) |
| 2 | KC-A identity mechanism documented | `design.md §5.19` |
| 3 | KC-B all-modes query documented | `design.md §5.20` (lines 611-691) |
| 4 | §6.9 TestStrategy exists | `design.md:866-996` |
| 5 | `loader.cpp` queries all modes + 4-state + identity | `loader.cpp:206-239` (probe), `loader.cpp:280-312` (4-state) |
| 6 | T_ATTACH_ALIEN_REFUSAL exists & passes | test-run.log:18 + my re-run |
| 7 | 8 pre-existing tests still pass | re-run log lines 4-16, 20 (incl. T_DROP_MALFORMED legit SKIP) |
| 8 | Zero warnings default + sanitizer | T_BUILD passes 14.72s + T_SANITIZER_BUILD passes 25.79s |
| 9 | Exit 4 observed in T_ATTACH_ALIEN_REFUSAL | runtime stderr captures rc=4, foreign id 11536/11586 named |

## Test execution (last 30 lines)

```
Internal ctest changing into directory: /home/user/mint-l2-mac-filter/build
Test project /home/user/mint-l2-mac-filter/build
    Start 1: T_BUILD
1/9 Test #1: T_BUILD ..........................   Passed   14.72 sec
    Start 2: T_LOAD_ATTACH
2/9 Test #2: T_LOAD_ATTACH ....................   Passed    1.19 sec
    Start 3: T_PASS_ALLOWED
3/9 Test #3: T_PASS_ALLOWED ...................   Passed    2.57 sec
    Start 4: T_DROP_DENY
4/9 Test #4: T_DROP_DENY ......................   Passed    2.55 sec
    Start 5: T_DROP_MALFORMED
5/9 Test #5: T_DROP_MALFORMED .................***Skipped   1.57 sec
    Start 6: T_IDEMPOTENT_RELOAD
6/9 Test #6: T_IDEMPOTENT_RELOAD ..............   Passed    1.74 sec
    Start 7: T_NEGATION_CONTROL
7/9 Test #7: T_NEGATION_CONTROL ...............   Passed    2.53 sec
    Start 8: T_ATTACH_ALIEN_REFUSAL
8/9 Test #8: T_ATTACH_ALIEN_REFUSAL ...........   Passed    1.18 sec
    Start 9: T_SANITIZER_BUILD
9/9 Test #9: T_SANITIZER_BUILD ................   Passed   25.79 sec

100% tests passed, 0 tests failed out of 9
Total Test time (real) =  53.84 sec
The following tests did not run:
	  5 - T_DROP_MALFORMED (Skipped)
```

Verbose alien-refusal run, runtime stderr captured:
```
8: foreign prog id = 11586
8: loader rc=4
8: error: XDP prog id 11586 (mode SKB, name 'xdp_pass_prog') already attached to veth_a (not ours — refusing to clobber): alien XDP program already attached
8: PASS: T_ATTACH_ALIEN_REFUSAL
```

## Rework assignments
None — verdict is `pass`. Two informational notes (XdpProbe::name type, INFO; bpf_obj_get_info_by_fd, NEGOTIATED) are non-blocking and have negotiation records.

Log artifact: `/tmp/mint-review-tests-mvp1.1b-1779524244.log`.
