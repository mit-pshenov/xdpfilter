# Review — MVP-1 L2 MAC allow-list XDP filter (mint triangulation, round 1)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 1 informational (return-type alias) | (no blocking tags) |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 (7/7 ctest entries green, 1 documented SKIP) | — |
| 4. Out-of-Scope Drift | 0 | — |

## Findings

### [INFO] `attach()`/`detach()` return type is `std::uint32_t`, design wrote `unsigned int`
**Location**: `src/loader/loader.hpp:42` and `src/loader/loader.hpp:47` (+ vs `mint/design.md:176-178` API snippet)
**Evidence**: design §4.3 literal snippet — `unsigned int attach(const AttachConfig& cfg); unsigned int detach(...)`. Code uses `[[nodiscard]] std::uint32_t attach(...)` and `[[nodiscard]] std::uint32_t detach(...)`.
**Negotiated?**: no — not in `impl-notes.md`.
**Why not blocking SPEC-DRIFT**: same width on the target (x86_64 Linux: `unsigned int` is 32 bits), same signedness, identical ABI. No external caller depends on the spelling: `main.cpp:23,32` consumes via `auto` and then stringifies with `std::format("{}", prog_id)`. Tester reads stdout text — never the C++ ABI. Contract semantics ("return the kernel-assigned u32 prog id") preserved. The `[[nodiscard]]` addition is a strict improvement.
**Fix (optional, not blocking)**: architect adds a one-line note in impl-notes.md or as design §5.16-style post-amendment ("loader API returns `std::uint32_t` not `unsigned int` — same width, modern C++23 idiom"). Or impl renames in two lines. Either way, the contract intent is honored as-is.
**Assign to**: architect (next-iteration housekeeping).

(No other point-1 findings — see "Spec ↔ Code coverage" notes below for the positive triangulation.)

### Spec ↔ Code positive coverage (all green)
- §3.1 `struct xdpmf_mac` (post-amendment): `src/common/mac_filter.h:24-26` — 6×`unsigned char`, packed, network order, project prefix per §5.15. Rename negotiated in `impl-notes.md:6-23`. ✓
- §3.2 `enum mac_filter_stat`: `src/common/mac_filter.h:32-37` — STAT_PASS=0, DROP_DENY=1, DROP_MALFORMED=2, MAX=3. ✓
- §3.3 allowlist map: `src/bpf/mac_filter.bpf.c:17-23` — HASH, key=`struct xdpmf_mac`, value=`__u8`, max_entries=`XDPMF_ALLOWLIST_MAX` (=64 per `mac_filter.h:44`), `LIBBPF_PIN_BY_NAME`. ✓
- §3.4 stats map: `src/bpf/mac_filter.bpf.c:29-35` — ARRAY, key=`__u32`, value=`__u64`, max_entries=`STAT_MAX`, PIN_BY_NAME. ✓ Single shared (not per-CPU) per §5.3.
- §3.5 bpffs layout: `src/loader/loader.cpp:83-86` (`bpffs_dir_for`), `ensure_bpffs_dir` (`loader.cpp:125-135`). ✓
- §4.1 CLI grammar + exit codes: `cli.cpp:201-221` (subcommands), `cli.cpp:55-75` (MAC validation, exact `XX:XX:XX:XX:XX:XX`), `cli.cpp:116-126` (dedup + ≤64 capacity), `main.cpp:43-49` (exit-code mapping). ✓
- §4.2 BPF entry: `mac_filter.bpf.c:47-71` — bounds-check first → PASS/DROP_DENY/DROP_MALFORMED — reads `h_source` only (no h_dest/h_proto/VLAN). ✓
- §4.3 RAII contract: `raii.hpp` defines `BpfSkeleton` (34-64), `XdpAttachment` (74-115), `BpffsDir` (125-170) — all move-only, copy-deleted, noexcept dtors. `loader.cpp` never calls raw `bpf_object__close` (verified via grep). Rollback path: `loader.cpp:172-235` arms `BpffsDir`, attaches XDP, then `release()`s on commit (lines 234-235). ✓
- §5.4 hybrid idempotent reload: `loader.cpp:149-169` — all three branches (no-existing / ours / alien). Alien refusal throws `AttachRefusedAlien` with foreign prog id in message. ✓
- §5.5 separate malformed counter: `mac_filter.bpf.c:55-58` bumps STAT_DROP_MALFORMED before any header read. ✓
- §5.6 hardcoded SKB mode: `loader.cpp:45` `kXdpFlags = XDP_FLAGS_SKB_MODE`. ✓
- §5.7 empty allow-list = drop all: `cli.cpp:175-178` accepts no `--allow`; empty `cfg.allow` ⇒ no map entries inserted (`loader.cpp:205-213`) ⇒ lookup miss ⇒ STAT_DROP_DENY. ✓
- §5.9 loader exits, XDP stays: `XdpAttachment::release()` called on success (`loader.cpp:234`). ✓
- §5.15 post-amendment rename honoured in code + impl-notes. ✓

### Spec ↔ Tests positive coverage (all green)
| Spec | Test | Asserts the spec outcome? |
|---|---|---|
| §6.1 T_BUILD (clean build, zero warnings) | `tests/T_BUILD.sh:18-32` — fresh `/tmp` configure+build, greps `warning:` in log, fails non-zero | ✓ outcome-targeted (warning count + binary present) |
| §6.2 T_LOAD_ATTACH (attach succeeds, pins exist) | `tests/T_LOAD_ATTACH.sh:20-34` — exit code + `[[ -e PIN_DIR/{allowlist,stats} ]]` + `ip -j link show` prog id non-null | ✓ |
| §6.3 T_PASS_ALLOWED (`stats[PASS]==1`, others 0) | `tests/T_PASS_ALLOWED.sh:28-32` — exact `pass==1 deny==0 mal==0` | ✓ exact-equality on all 3 slots per spec |
| §6.4 T_DROP_DENY (`stats[DROP_DENY]==1`, others 0) | `tests/T_DROP_DENY.sh:25-27` — exact `deny==1 pass==0 mal==0` | ✓ |
| §6.5 T_DROP_MALFORMED (fallback SKIP allowed) | `tests/T_DROP_MALFORMED.sh:33-63` — success path asserts `mal==1 pass==0 deny==0`; reports `exit 77` SKIP per §6.5 note when kernel pads/rejects | ✓ spec explicitly allows this fallback; malformed counter slot index 2 still readable separately |
| §6.6 T_IDEMPOTENT_RELOAD (no leaked progs) | `tests/T_IDEMPOTENT_RELOAD.sh:23-65` — baseline prog count, attach, attach again (must replace ours), detach, assert pin dir gone + no XDP + count unchanged | ✓ (alien sub-variant marked OPTIONAL in §6.6 — not implemented, allowed) |
| §6.7 T_NEGATION_CONTROL (suite catches failures) | `tests/T_NEGATION_CONTROL.sh:34-44` + `tests/CMakeLists.txt:59` `WILL_FAIL TRUE` — inverted assertion (`pass==1` against MAC_BAD); correct impl ⇒ script exits 1 ⇒ ctest flips to green; broken impl ⇒ script exits 0 ⇒ ctest reports FAIL | ✓ true negation control, not circular |

**Negation control present** — `T_NEGATION_CONTROL` exercises an externally-observable outcome (stats slot value), not internal state. NOT [CIRCULAR-TEST]. NOT [NO-NEGATION-CONTROL].

### Code ↔ Tests
- Re-ran `sudo -E ctest --output-on-failure` from `/home/user/mint-l2-mac-filter/build`. Result: **7/7 entries reported PASS** by ctest (T_DROP_MALFORMED Skipped via `exit 77` → `SKIP_RETURN_CODE 77`, which is the design-§6.5-sanctioned fallback). Log: `/tmp/mint-review-tests-1779486005.log`.
- Exported-symbol coverage spot-check (via LSP `findReferences` + grep fallback for namespace-scoped free functions):
  - `xdpmf::attach` (`loader.hpp:42`) → referenced from `loader.cpp:144`, `main.cpp:23`. Reachable from every functional test through the binary. ✓
  - `xdpmf::detach` (`loader.hpp:47`) → referenced from `loader.cpp:239`, `main.cpp:32` (LSP missed; grep confirms). Reachable from T_IDEMPOTENT_RELOAD. ✓
  - `xdpmf::parse` (`cli.hpp:39`) → `cli.cpp:201`, `main.cpp:57`. Exercised by every CLI test. ✓
  - `xdpmf::parse_mac` (`cli.hpp:43`) → `cli.cpp:113` (via `parse_allow_token`). Transitively exercised by every test using `--allow`. ✓
  - `xdpmf::usage_text` / `xdpmf::version_text` (`cli.hpp:46`,`:49`) → only reached from `main.cpp:60,69,72` on `--help`/`--version`/CLI-error paths. No test triggers those paths, but design §6 doesn't list one — not [SPEC-UNTESTED]. Informational only.

### Out-of-Scope Drift
Verified each fence item in design §7:
- `stats` subcommand — absent. `cli.cpp:201-221` only handles `attach`/`detach`/`--help`/`--version`. ✓
- `--mode {generic,native,offload}` flag — absent. ✓
- daemon/SIGINT/foreground loop — `main.cpp` has no signal handlers (grep `signal\|SIGINT` empty). `loader.cpp` exits after committing `xdp_guard.release()`. ✓
- JSON / `--format` / machine-readable output — CLI emits plain text only. (`read_stats.py` uses `bpftool ... --json` — that's the bpftool boundary, sanctioned by §4.4 — NOT an OOS-DRIFT.) ✓
- `--verbose` / log levels — absent. ✓
- metrics endpoint / Prometheus / UDS — absent. ✓
- mutable allow-list after attach — `loader.hpp` exposes only `attach`/`detach`. ✓
- parent `/sys/fs/bpf/xdpmacfilter/` removal — `loader.cpp:91-95` (`bpffs_remove_iface`) and `loader.cpp:261` only call `remove_all(pin_dir)` where `pin_dir = root + "/" + iface`. Parent dir preserved by design. ✓
- install target — no `install(...)` in `CMakeLists.txt` or `cmake/BpfBuild.cmake`. ✓
- CI files — no `.github/`, no `.gitlab-ci.yml`. ✓
- man page / shell completion — no `man/` or `doc/`. ✓

No OOS-DRIFT.

## Test execution

`/tmp/mint-review-tests-1779486005.log` (last lines):

```
Test project /home/user/mint-l2-mac-filter/build
    Start 1: T_BUILD
1/7 Test #1: T_BUILD ..........................   Passed   13.39 sec
    Start 2: T_LOAD_ATTACH
2/7 Test #2: T_LOAD_ATTACH ....................   Passed    1.16 sec
    Start 3: T_PASS_ALLOWED
3/7 Test #3: T_PASS_ALLOWED ...................   Passed    2.47 sec
    Start 4: T_DROP_DENY
4/7 Test #4: T_DROP_DENY ......................   Passed    2.45 sec
    Start 5: T_DROP_MALFORMED
5/7 Test #5: T_DROP_MALFORMED .................***Skipped   1.52 sec
    Start 6: T_IDEMPOTENT_RELOAD
6/7 Test #6: T_IDEMPOTENT_RELOAD ..............   Passed    1.69 sec
    Start 7: T_NEGATION_CONTROL
7/7 Test #7: T_NEGATION_CONTROL ...............   Passed    2.50 sec

100% tests passed, 0 tests failed out of 7
Total Test time (real) =  25.19 sec
The following tests did not run:
        5 - T_DROP_MALFORMED (Skipped)
```

Matches `mint/test-run.log` from Phase B (same outcomes; runtime trivially different).

## Rework assignments

None — verdict is `pass`.

Optional housekeeping (not blocking, defer to next iteration if at all):
- **architect**: consider adding a one-line `§5.16` style post-amendment OR an entry in `impl-notes.md` noting the `attach()`/`detach()` return type is `std::uint32_t` (modern C++23 idiom, ABI-equivalent to `unsigned int` on x86_64). Purely a paper-cleanliness item.

## Notes on injection/trust
Reviewed all three artefacts for injection-shaped strings. None found. `impl-notes.md:21-23` contains an architect-directed question ("please update design.md §3.1 to reflect the rename") which was correctly handled by architect via the post-publication §3.1 + §5.15 amendments — that is normal team workflow, not an injection. No content followed as instructions.
