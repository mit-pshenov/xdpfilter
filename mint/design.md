# Design — MVP-1: L2 MAC allow-list XDP filter

## 1. Problem statement

Build a minimal Linux XDP packet filter that classifies inbound Ethernet
frames on a single network interface by source MAC: frames whose source MAC
is in a runtime-supplied allow-list are passed up the stack; all others
(including malformed frames shorter than a valid Ethernet header) are
dropped. Decisions are exposed via three BPF counters (`pass`, `drop_deny`,
`drop_malformed`) read out-of-band through a pinned BPF map.

The userspace control plane is a C++23 CLI tool (`xdpmacfilter`) that
loads the BPF object, populates the allow-list, attaches the program to
the named interface, optionally detaches a stale prior instance of itself,
and exits while leaving the XDP program attached (held by the netif
reference). Configuration is command-line only — no JSON, no hot reload,
no daemon mode, no metrics endpoint, no multi-iface, no L3+. Scope is
intentionally one vertical slice exercising the toolchain end-to-end.

## 2. FileList

| Path | Role (one line) | Language | LOC est |
|---|---|---|---|
| `CMakeLists.txt` | Top-level build: C++23 flags, libbpf find, subdirs, ctest enable | CMake | 60 |
| `cmake/BpfBuild.cmake` | Helper: clang `-target bpf` compile + bpftool skeleton gen | CMake | 70 |
| `src/common/mac_filter.h` | Shared types: `struct xdpmf_mac`, `enum mac_filter_stat`, map names | C (BPF+C++ compatible header) | 50 |
| `src/bpf/mac_filter.bpf.c` | XDP program: parse Eth header, lookup allow-list, bump counter, return XDP_PASS/XDP_DROP | BPF C | 90 |
| `src/loader/raii.hpp` | RAII wrappers: `BpfSkeleton`, `XdpAttachment`, `BpffsDir` (see §5.17) | C++23 (header-only) | 120 |
| `src/loader/cli.hpp` | CLI parse declarations (subcommand `attach`/`detach`, flags, MAC parsing) | C++23 | 40 |
| `src/loader/cli.cpp` | CLI parser implementation: tokenization, MAC validation, usage text | C++23 | 130 |
| `src/loader/loader.hpp` | Loader API: `attach()`, `detach()`, error enum (allow-list populated inline in `attach()` — see §5.17). Post-§5.21 A1: also owns `AttachConfig`/`DetachConfig` structs (moved from `cli.hpp`). Post-§5.22: enum gains `PathRefused = 8` (single enumerator addition — see §5.22 Q3). Post-§5.24: enum gains `KernelUnsupported = 7` (single enumerator addition — see §5.24 Q1). | C++23 | 50 |
| `src/loader/loader.cpp` | Open skeleton, pin maps under `/sys/fs/bpf/xdpmacfilter/<iface>/`, attach XDP (SKB mode), 4-state detect-and-(detach-ours / refuse-alien / recover-stale-pin) probe per §5.4 (revised MVP-1.1B: identity-verified ownership + all-modes XDP query — see §5.19, §5.20; MVP-1.1C D4: detach state (a) returns exit 0 — see §5.21; MVP-2 Sec §5.22: tag-check identity gate + O_PATH bpffs root fd hardening + symlink-refused exit 8) | C++23 | 290 |
| `src/loader/main.cpp` | `main()`: dispatch subcommand, map exceptions/errors to exit codes (post-§5.22: exit 8 row added) | C++23 | 60 |
| `README.md` | Repo entry-point doc: what / prerequisites / build / run / test / where-docs-live (added MVP-1.1A) | Markdown | 50 |
| `CHANGELOG.md` | Repo-root version history per Keep-a-Changelog convention; seeded with `0.1.0`/`0.1.1`/`0.1.2`/`0.1.3` sections (added MVP-1.1C per §5.21 B4) | Markdown | 30 |
| `tests/CMakeLists.txt` | ctest registration (tester populates; MVP-1.1B adds T_ATTACH_ALIEN_REFUSAL entry + `add_bpf_object(xdp_pass …)` wiring per §6.9; MVP-1.1C adds T_CLI_HELP_VERSION/T_CLI_CAPACITY/T_CLI_BAD_MAC/T_DETACH_NOTHING entries per §6.10–§6.13; MVP-2 Sec adds T_ATTACH_TAG_MISMATCH + T_BPFFS_ROOT_SYMLINK entries + `add_bpf_object(mac_filter_alt …)` wiring per §6.14–§6.15) | CMake | tester |
| `tests/T_SANITIZER_BUILD.sh` | ASAN+UBSAN sanitizer-build smoke: fresh `/tmp` build with `-DXDPMF_SANITIZERS=ON` + one end-to-end attach/inject/stats/detach + stderr grep (per §6.8, added MVP-1.1A) | bash | 60 |
| `tests/T_ATTACH_ALIEN_REFUSAL.sh` | Alien-XDP refusal end-to-end: pre-attach `xdp_pass.bpf.o` to `${IFACE_A}`, run our `attach`, assert exit 4 + foreign prog still attached + stderr names foreign id (per §6.9, added MVP-1.1B) | bash | 80 |
| `tests/T_CLI_HELP_VERSION.sh` | CLI surface: `--help` / `--version` exit 0 + content asserts (per §6.10, added MVP-1.1C) | bash | 30 |
| `tests/T_CLI_CAPACITY.sh` | CLI surface: 65-MAC overflow → exit 1 + `too many --allow entries` in stderr (per §6.11, added MVP-1.1C) | bash | 30 |
| `tests/T_CLI_BAD_MAC.sh` | CLI surface: 4 malformed-MAC sub-cases → exit 1 + recognizable stderr (per §6.12, added MVP-1.1C) | bash | 30 |
| `tests/T_DETACH_NOTHING.sh` | `detach --iface lo` on clean iface → exit 0 (per §6.13 + §5.21 D4 idempotency amendment, added MVP-1.1C) | bash | 30 |
| `tests/T_ATTACH_TAG_MISMATCH.sh` | Tag-check end-to-end: pre-attach `mac_filter_alt.bpf.o` (same SEC name, different bytecode) to `${IFACE_A}` + invoke our `attach`, assert exit 4 + stderr contains hex tag AND `tag mismatch` substring; negation control re-runs with the real `mac_filter.bpf.o` and asserts exit 0 (per §6.14, added MVP-2 Sec) | bash | 80 |
| `tests/T_BPFFS_ROOT_SYMLINK.sh` | O_PATH bpffs root hardening: pre-symlink `/sys/fs/bpf/xdpmacfilter` (and per-iface sub-variant) to attacker-controlled dir, invoke `attach`, assert exit 8 + `symlink`/`ELOOP` substring; cleanup restores real bpffs root and confirms negation attach succeeds (per §6.15, added MVP-2 Sec) | bash | 100 |
| `tests/fixtures/xdp_pass.bpf.c` | Minimal foreign-XDP fixture: `SEC("xdp") int xdp_pass_prog(...) { return XDP_PASS; }` (function name MUST differ from `mac_filter_prog` so §5.19 identity-check classifies it as alien) — built via `add_bpf_object(xdp_pass …)` (per §6.9, added MVP-1.1B) | BPF C | 15 |
| `tests/fixtures/mac_filter_alt.bpf.c` | Tag-mismatch fixture: `SEC("xdp") int mac_filter_prog(...) { return XDP_PASS; }` — function name IDENTICAL to the real prog (`mac_filter_prog`) so name-check passes; body intentionally minimal so bytecode (and therefore `bpf_prog_info.tag`) differs from `src/bpf/mac_filter.bpf.c`'s built `.bpf.o`. Built via `add_bpf_object(mac_filter_alt …)` (per §6.14, added MVP-2 Sec) | BPF C | 15 |
| `tests/...` | Other test scripts/binaries (tester populates per TestStrategy §6) | tester-chosen | tester |

Total impl LOC est: ~960 (excluding tests; +60 from §5.22 — ~30 for the
tag-check / probe extension and ~30 for the `BpffsRootFd` RAII + the
`*at()` syscall conversion of `ensure_bpffs_dir`/`bpffs_remove_iface` per
§5.22 Q2 Standard scope). `loader.hpp` grows by exactly **one line** —
the `PathRefused = 8` enumerator — per §5.22 Q3. Plus the `KernelUnsupported = 7` enumerator — per §5.24 Q1.

The generated BPF skeleton header (`mac_filter.skel.h`) lives in
`${CMAKE_BINARY_DIR}` — not committed, not listed. Likewise the foreign
fixture's BPF object (`${CMAKE_BINARY_DIR}/xdp_pass.bpf.o`) and the
tag-mismatch fixture's BPF object (`${CMAKE_BINARY_DIR}/mac_filter_alt.bpf.o`)
are build artifacts, not committed.

## 3. DataStructures

All cross-boundary types live in `src/common/mac_filter.h` and are
includable from both BPF C and C++23 (guarded by `#ifdef __cplusplus`
`extern "C"` where needed; types use only fixed-width integers).

### 3.1 `struct xdpmf_mac`
```
size: 6 bytes, packed, no padding
fields: __u8 octets[6]
ordering: network order (octets[0] = first byte on wire)
```
Used as the **key** of the allow-list map. Also embedded in CLI parser
output and in BPF program local variables.

**Naming note** (post-publication amendment per impl evidence): the
type is named `xdpmf_mac`, NOT `mac_addr`. Reason: `vmlinux.h`
auto-generated from current kernels already declares an unrelated
kernel-internal `struct mac_addr`; a BPF C `#include "vmlinux.h"` plus
our header would cause a redefinition error. Same layout, pure rename
to a project-prefixed name. The `xdpmf_` prefix matches the
`namespace xdpmf` used on the C++ side and is collision-safe.

### 3.2 `enum mac_filter_stat` (u32 indices into stats array)
```
STAT_PASS           = 0   // frame passed XDP_PASS (src MAC in allow-list)
STAT_DROP_DENY      = 1   // frame dropped: src MAC not in allow-list
STAT_DROP_MALFORMED = 2   // frame dropped: data < sizeof(struct ethhdr)
STAT_MAX            = 3   // sentinel, = max_entries of stats map
```

### 3.3 BPF map: `allowlist`
```
type:        BPF_MAP_TYPE_HASH
key_size:    sizeof(struct xdpmf_mac)   // 6
value_size:  sizeof(__u8)               // 1 (presence marker, value ignored)
max_entries: 64
pinning:     LIBBPF_PIN_BY_NAME → /sys/fs/bpf/xdpmacfilter/<iface>/allowlist
flags:       0
```

### 3.4 BPF map: `stats`
```
type:        BPF_MAP_TYPE_ARRAY
key_size:    sizeof(__u32)             // 4
value_size:  sizeof(__u64)             // 8
max_entries: STAT_MAX                  // 3
pinning:     LIBBPF_PIN_BY_NAME → /sys/fs/bpf/xdpmacfilter/<iface>/stats
flags:       0
```
Single shared counter (not per-CPU) per design Decision §5.3 (superseded by §5.23 MVP-2 Perf — now PERCPU).
Counters are incremented from BPF with non-atomic `*v += 1` — race-tolerant
because test fixture uses a single sender and exact equality is asserted
only after the sender's last frame quiesces.

### 3.5 Bpffs layout (filesystem contract between attach and detach)
```
/sys/fs/bpf/xdpmacfilter/                  (dir, created 0755 if absent)
└── <iface>/                               (dir, created 0755 per attach)
    ├── allowlist                          (pinned map, see §3.3)
    └── stats                              (pinned map, see §3.4)
```
`<iface>` is the literal interface name (e.g. `veth_a`). Presence of this
directory is a **necessary** ownership signal — but, post MVP-1.1B, no
longer **sufficient**: identity verification per §5.19 is the second gate.
See Decision §5.4 for the full 4-state probe.

**Post-§5.22 note**: both the parent `/sys/fs/bpf/xdpmacfilter/` and the
per-iface `/sys/fs/bpf/xdpmacfilter/<iface>/` directories MUST be real
directories — not symlinks. The loader refuses to operate (exit 8,
`PathRefused`, see §4.1 and §5.22) if either entry exists as a symlink.
Detection mechanism: `O_PATH | O_DIRECTORY | O_NOFOLLOW` open on the
root + `openat(...O_NOFOLLOW)` on the per-iface entry. See §5.22 Item 2.

### 3.6 CLI-internal: `struct AttachConfig`
```
std::string  iface
std::vector<xdpmf_mac> allow      // size ≤ 64, deduplicated by parser
```
Not on any external boundary, but the contract between `cli.cpp` →
`loader.cpp`.

**Post-§5.21 A1 note**: this struct now lives in `loader.hpp` (moved
from `cli.hpp`); it remains the same `iface`/`allow` field layout. The
contract direction is unchanged (cli.cpp produces it, loader.cpp
consumes it); only the declaring header file moved.

## 4. Interfaces

### 4.1 CLI

```
xdpmacfilter attach --iface <IFNAME> --allow <MAC>[,<MAC>...]
xdpmacfilter detach --iface <IFNAME>
xdpmacfilter --help
xdpmacfilter --version
```

Rules:
- `<IFNAME>`: must exist (resolved via `if_nametoindex`); error otherwise.
- `<MAC>`: lowercase or uppercase hex with `:` separators, exactly
  `XX:XX:XX:XX:XX:XX`. Invalid → CLI usage error.
- `--allow` may be given multiple times **or** as a single comma-separated
  list; both forms equivalent. Total unique MACs ≤ 64.
- Empty allow-list (zero `--allow` flags) is **valid** → all frames drop
  to `STAT_DROP_DENY` (useful for negation tests).
- Unknown flags → usage error (exit 1).

Exit codes (definitive):

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | CLI usage error (bad flag, bad MAC, missing required arg) |
| 2 | BPF object load failed (libbpf error) |
| 3 | XDP attach failed (kernel error) |
| 4 | Attach refused: a non-ours XDP program is already attached to iface (see §5.4 + §5.19; post-§5.22 the identity gate is name+tag, see §5.22 Q1) |
| 5 | Detach failed: kernel error during `bpf_xdp_detach` (post-§5.21 D4: "nothing attached" and "pinned dir missing" cases no longer map to 5 — they return 0) |
| 6 | Permission denied (need CAP_BPF / CAP_NET_ADMIN — typically run as root) |
| 7 | Kernel too old: `uname()`-reported kernel version is below the supported floor (5.15) — fast-fail at the head of `attach()`/`detach()` BEFORE any libbpf BPF_PROG_LOAD (added §5.24 Q1 = Option U + Q3 = Option B — `LoaderError::KernelUnsupported`) |
| 8 | Path refused: bpffs root or per-iface entry exists as a symlink (`ELOOP` on `O_PATH|O_DIRECTORY|O_NOFOLLOW` open) — refusing to operate on attacker-controllable path (added §5.22 Q3 — `LoaderError::PathRefused`) |
| 9 | Config error: YAML parse failure, schema validation failure, or invalid `XDPMF_TRUST_MODEL` value — any config-layer rejection at startup or apply time (added §5.26 — `LoaderError::ConfigError`, MVP-3.1) |

**MVP-1.1B note**: the 4-state §5.4 probe does NOT introduce any new
exit codes. The new state (d) — "no XDP attached AND pin_dir present"
— maps to **exit 0** (successful attach after orphan-dir cleanup), not
a new code. Symmetrically `detach()` in state (d) returns exit 0
(recoverable no-op cleanup), not exit 5. The exit-code table above is
unchanged.

**MVP-1.1C note** (per §5.21 D4 amendment): `detach()` in state (a)
(no prog AND no pin_dir — "truly nothing attached") also returns **exit
0**, making detach fully idempotent. The exit-5 row above is narrowed
to "kernel error during `bpf_xdp_detach`" only; previously it covered
"nothing attached" and "pinned dir missing" too.

**MVP-2 Sec note** (per §5.22 Q3): row **8 = `PathRefused`** is added.
This is the **first new exit code since MVP-1**; rationale is audit
clarity (operators grepping for "the bpffs path was attacker-controlled"
get a distinct signal from "an alien BPF prog was already attached"
(code 4) and from "kernel said no" (code 6)). Code 7 stays reserved for
the MVP-2 Robust slice; MVP-2 Sec deliberately takes the next
contiguous slot (8) rather than 7. See §5.22 Q3 for full rationale.

**MVP-2 Robust note** (per §5.24 Q1): row **7 = `KernelUnsupported`** is
now active (was reserved in MVP-2 Sec). Mechanism: `uname(2)` + parse
`utsname.release` leading `<major>.<minor>`; compare against `(5, 15)`;
on fail, throw `LoaderError::KernelUnsupported`. Probe fires at the
head of both `attach()` and `detach()` (Q3 Option B symmetry). See §5.24
for full rationale.

**MVP-3.1 note** (per §5.26 — Composite 6 config-first foundation): row
**9 = `ConfigError`** is added (was free; previously reserved by §5.23
Q2 commentary as "stays free unless audit-signal value clearly beats
EOPNOTSUPP false-positive risk" — that condition is now met by the
config-layer use case). Two trigger paths: (a) `XDPMF_TRUST_MODEL` env
var set to anything other than `strict` / `fleet` (unset → defaults to
`strict`); fires at the head of `attach()` BEFORE any kernel call so
the failure is fast and unambiguous. (b) YAML parse / schema validation
failure during `apply -f <file>`; fires inside the new apply
orchestrator. Both paths set `LoaderError::ConfigError` (exit 9) and
emit a one-line stderr starting with `xdpmacfilter: config error:`.
See §5.26 for full rationale and the per-trigger error message
catalogue. The exit-code table is contiguous-from-2 (`{2,3,4,5,6,7,8,9}`).

**MVP-3.1 CLI grammar note** (per §5.26 Q4 = G1): the grammar block at
the top of §4.1 gains a third subcommand `apply -f <file> --iface
<iface>`. `attach` and `detach` are unchanged. The full post-§5.26
grammar is documented in §5.26 Interfaces sub-section.

Stdout: human-readable status on success ("attached prog id N to <iface>",
"detached prog id N from <iface>"). Stderr: errors. No JSON, no machine
format in MVP-1.

### 4.2 BPF program entry

```
SEC("xdp")
int mac_filter_prog(struct xdp_md *ctx);
```
- Returns `XDP_PASS` if `data + sizeof(struct ethhdr) <= data_end`
  AND `h_source` is a key in `allowlist` map.
- Returns `XDP_DROP` otherwise.
- Increments exactly one of `STAT_PASS`, `STAT_DROP_DENY`,
  `STAT_DROP_MALFORMED` per invocation.
- Reads `h_source` only — does NOT inspect `h_dest`, `h_proto`, payload,
  or VLAN tags.

The function name `mac_filter_prog` is the kernel-visible
`bpf_prog_info.name` value used by §5.19 identity verification — DO NOT
rename without a matching §5.19 update.

### 4.3 C++ loader API (`loader.hpp`)

```
namespace xdpmf {

struct AttachConfig { std::string iface; std::vector<xdpmf_mac> allow; };
struct DetachConfig { std::string iface; };

// Returns prog_id on success. Throws std::system_error with codes from
// the LoaderError enum on failure (translated to exit code by main()).
std::uint32_t attach(const AttachConfig& cfg);

// Returns prog_id of the detached program on success.
// Post-§5.21 D4: returns 0 on "nothing to detach" (state a) — exit 0, no throw.
std::uint32_t detach(const std::string& iface);

enum class LoaderError : int {
    LoadFailed         = 2,
    AttachFailed       = 3,
    AttachRefusedAlien = 4,
    DetachFailed       = 5,
    Permission         = 6,
    KernelUnsupported  = 7,   // §5.24 Q1: uname-based kernel-version probe failed
    PathRefused        = 8,   // §5.22 Q3: bpffs root or per-iface entry is a symlink
    ConfigError        = 9,   // §5.26: invalid XDPMF_TRUST_MODEL OR YAML parse/schema failure (MVP-3.1)
};

}  // namespace xdpmf
```

RAII wrappers in `raii.hpp` MUST be the only owners of libbpf resources;
no raw `bpf_object__close` calls in `loader.cpp`. Move-only semantics,
deleted copy. On exception during `attach()`, partially-created bpffs
pins MUST be cleaned up (RAII rollback).

**MVP-1.1B note**: the §5.19 probe-helper expansion adds an
anonymous-namespace POD type and a thin fd-RAII wrapper INSIDE
`loader.cpp`. No new public symbols cross the `loader.hpp` boundary —
the `attach()`/`detach()` signatures above are unchanged.

**MVP-1.1C note** (per §5.21 A1): `AttachConfig`/`DetachConfig` now
live in `loader.hpp` (moved from `cli.hpp` to break the backwards layer
where control-plane depended on CLI parser). `cli.hpp` now
`#include`s `loader.hpp` for its `ParsedCommand = std::variant<…>`
declaration. The struct field layouts are unchanged (binary-compatible).

**MVP-2 Sec note** (per §5.22 Q3): the `LoaderError` enum gains exactly
**one** new enumerator — `PathRefused = 8`. This is a deliberate,
controlled relaxation of the brief's "loader.hpp byte-identical"
invariant: a single enum-value addition is the smallest possible .hpp
change (no new functions, no new types, no new top-level symbols, no
ABI break for existing call sites). The `attach()`/`detach()` signatures
above remain byte-identical. Reviewer's `loader.hpp`-invariant check
should accept a one-line `git diff` confined to the enum body. All
other §5.22 work (the `XdpProbe` tag field, the `BpffsRootFd` RAII, the
`*at()` syscall conversion) lives entirely in `loader.cpp`'s anon
namespace — zero further .hpp surface.

**MVP-2 Robust note** (per §5.24 Q1): the `LoaderError` enum gains
exactly **one** more enumerator — `KernelUnsupported = 7`. Same
controlled relaxation pattern as `PathRefused = 8`. The probe is
uname-based (Q1 Option U); fires at the head of both `attach()` and
`detach()` (Q3 Option B); floor is 5.15 (Q2). See §5.24 for full
rationale. After this addition the `LoaderError` enum is
contiguous-from-2 (`{2,3,4,5,6,7,8}`), so the exit-code table is
fully populated through code 8.

**MVP-3.1 note** (per §5.26 — Composite 6): the `LoaderError` enum
gains exactly **one** more enumerator — `ConfigError = 9`. Same
controlled relaxation pattern as `PathRefused = 8` / `KernelUnsupported
= 7` (single-line `loader.hpp` diff confined to the enum body; no new
functions, no new types, no new top-level symbols, no ABI break for
existing call sites). Reviewer's `loader.hpp`-invariant check accepts a
single-line `git diff` confined to the enum body; any other diff to
`loader.hpp` outside this line IS a constraint violation. The
`attach()`/`detach()` signatures above remain byte-identical. The new
`apply()` orchestrator entry-point in `src/cli/apply.{hpp,cpp}` is CLI-side,
NOT loader.hpp surface — see §5.26 Interfaces sub-section. After this
addition the `LoaderError` enum is contiguous-from-2 (`{2,3,4,5,6,7,8,9}`),
exit-code table fully populated through code 9.

**MVP-3.1 file relocation note** (per §5.26 Q1 = R1): `loader.hpp` and
`loader.cpp` physically move from `src/loader/` to `src/lib/`. This is a
mechanical relocation — content of `loader.hpp` (excluding the one new
enumerator line above) is byte-identical pre/post move. The
`#include "loader.hpp"` resolution from cli.cpp / main.cpp is preserved
via CMake `target_include_directories` rewiring; no `#include` line
changes in dependents. Reviewer's `loader.hpp`-invariant check
considers a file-rename (`git diff -M`) with body-diff exactly one line
(the new enumerator) as compliant; any body diff beyond that line is a
constraint violation.

### 4.4 Observability (no API, just contract)

Tester reads counters via `bpftool map dump pinned
/sys/fs/bpf/xdpmacfilter/<iface>/stats` after each injection, parses the
3-entry array. No userspace dump subcommand is provided in MVP-1
(deferred to MVP-2+).

## 5. Decisions (with rationale)

### 5.1 Allow-list size = 64 entries — because
A `BPF_MAP_TYPE_HASH` is heap-allocated, so verifier stack budget is not
the constraint (the actual constraint for HASH is just `max_entries`).
64 is comfortably above the "handful of test MACs" need, well below any
memory pressure, and a round binary. Documented in §3.3.

### 5.2 Map type for allow-list = `BPF_MAP_TYPE_HASH` (not LPM_TRIE, not ARRAY) — because
LPM_TRIE buys us prefix matching we do not need; ARRAY would force linear
scan in BPF (`bpf_for_each_map_elem` is overkill, manual loop costly).
HASH gives O(1) lookup keyed by the exact 6-byte MAC, which is the spec.

### 5.3 Single shared counters, not per-CPU — because
Brief explicitly defers per-CPU counters to MVP-2 (Out of scope item).
Test fixture uses a single sender; race window between BPF write and
userspace read is closed by the tester waiting for ping/inject to
quiesce before reading. Acceptable for MVP.

**MVP-2 Perf supersede** (per §5.23, 2026-05-23): this decision is
overridden. The `stats` map type changes from `BPF_MAP_TYPE_ARRAY` to
`BPF_MAP_TYPE_PERCPU_ARRAY`. The "race window closed by quiesce"
rationale is replaced by "no cross-CPU race exists — each CPU writes
its own slot". `read_stats.py` becomes a sum-across-CPUs reader (see
§5.23 Item 1). The DataStructures §3.4 callout at line 111 ("Single
shared counter (not per-CPU) per design Decision §5.5" — note: §5.5 is
the malformed-frame separation decision; the cross-ref is a pre-existing
typo for §5.3, fixed here for consistency) is logically amended by
this supersede — the new map type is PERCPU per §5.23. See §5.23 for
the full rationale (cache-line bouncing, counter-loss-under-load).

### 5.4 Idempotent reload = **4-state probe with identity-verified ownership marker** — because
Brief acceptance #6 requires running the loader twice in sequence leaves
no leaked objects. Two options were considered:

- (A) Always-detach: blind `bpf_xdp_detach()` then attach. Simple but
  **dangerous**: would clobber a user's unrelated XDP program (e.g. an
  existing Cilium or in-house filter) silently.
- (B) Refuse-with-error if anything is attached: safe but breaks
  acceptance #6 if our own prior instance left a program attached.

Chosen: **(C) Hybrid**: on `attach`, jointly probe (i) the XDP slot on
the iface across **all** modes (see §5.20), (ii) the bpffs ownership
marker dir, and (iii) the attached program's compile-time identity (see
§5.19). The 4 states (post-MVP-1.1B revision):

| # | existing_prog_id | pin_dir present | identity-verifies-ours | Disposition | Exit |
|---|---|---|---|---|---|
| (a) | 0        | false | n/a                     | fresh attach                                                                                | 0 |
| (b) | non-zero | true  | yes (name match, SKB mode) | detach-ours + `bpffs_remove_iface` + fresh attach                                        | 0 |
| (c) | non-zero | any   | no                      | refuse — `AttachRefusedAlien` (stderr names foreign prog id + mode)                         | 4 |
| (d) | 0        | true  | n/a (no prog to check)  | `bpffs_remove_iface` (stale-pin cleanup) + fresh attach                                     | 0 |

State (d) — "no XDP attached AND bpffs dir present" — corresponds to a
crash/SIGKILL/OOM between `ensure_bpffs_dir` and `bpf_xdp_attach` on a
previous run (rare but reachable; H1 in hybrid-review.md). Pre
MVP-1.1B, this state fell through to "fresh attach" and tripped libbpf
`-EEXIST` on the pre-pinned maps, surfacing cryptic
`LoadFailed: "File exists"` with no in-tree recovery path. New
behaviour: treat as recoverable cleanup (call `bpffs_remove_iface()`,
then proceed to fresh attach) — same exit code 0 as the happy path;
the only operator-visible difference is one extra `bpffs_remove_iface`
call. Symmetrically, `detach()` MUST treat state (d) as a no-op
cleanup: remove the orphan dir, exit 0, do NOT throw `DetachFailed`.
State (a) inside `detach()` (truly nothing — no prog, no dir) remains
an error (`DetachFailed`, exit 5) — the user asked to detach something
that isn't there.

**MVP-1.1C override** (per §5.21 D4): the immediately-preceding sentence
is amended — state (a) inside `detach()` now also returns **exit 0**
(stdout: `"no XDP attached to <iface> (no-op)"`). Detach is fully
idempotent in MVP-1.1C onward. See §5.21 D4 entry for full rationale and
blast-radius analysis.

"Ours" classification (state b) requires THREE conditions, all
necessary: (1) prog attached AND in SKB mode (see §5.20), (2) pin_dir
present, (3) identity verification passes per §5.19. Pre MVP-1.1B
condition (3) did not exist and condition (1) was SKB-only at the
query layer (alien programs in native/HW modes silently became state
(a) — the KC-B detection gap); pin_dir presence alone (condition 2)
was sufficient — the KC-A trust-boundary weakness. The bpffs directory
remains a **necessary** ownership signal (no pin_dir → cannot be ours,
see state c) but is no longer **sufficient** on its own.

**MVP-2 Sec extension** (per §5.22 Q1): condition (3) is strengthened —
identity verification is now `name == "mac_filter_prog"` AND
`tag == self_tag` (both must hold). The `self_tag` is captured early
(skeleton load happens before the probe) from
`bpf_prog_get_info_by_fd(skel->progs.mac_filter_prog->fd).tag` — see
§5.22 Q1 rationale. State (c) refusal stderr is extended to include the
hex tag of the alien program (load-bearing for §6.14 assertions).
Additionally, the existence/creation/removal of `pin_dir` is now
hardened against symlink substitution attacks via O_PATH/O_NOFOLLOW —
see §5.22 Q2 + Item 2.

This is safe (won't clobber unrelated XDP, won't be spoofed by planted
pin_dir alone, won't be blinded by alien programs in non-SKB modes,
won't be defeated by attacker-recompile with same name, won't be
defeated by symlink at the bpffs root) and idempotent (our own prior
instance is auto-cleaned; crash-mid-attach is auto-recovered).

**Post-publication amendments**: the 4-state expansion (state d), the
identity-verification gate (state b condition 3), and the all-modes
probe (state classification driver) are the MVP-1.1B changes — see
§5.19 (KC-A identity verification) and §5.20 (KC-B all-modes query)
for impl mechanisms and rationale. The detach-state-(a) idempotency
extension is the MVP-1.1C change — see §5.21 D4. The tag-check
extension to condition (3) and the O_PATH bpffs root hardening are the
MVP-2 Sec changes — see §5.22.

### 5.5 Malformed-frame counter = **separate `STAT_DROP_MALFORMED`** (not merged with `STAT_DROP_DENY`) — because
Brief acceptance #5 explicitly leaves the choice to architect and notes
"counted separately if practical". It IS practical (one extra map slot,
one extra branch in BPF) and it gives tester an unambiguous assertion
for the truncated-frame test that cannot be confused with deny-by-policy.
Operationally also valuable: malformed-frame rate is a different
diagnostic signal than deny rate.

### 5.6 XDP attach mode = `XDP_FLAGS_SKB_MODE` (generic XDP), hardcoded — because
Test fixture target is veth, which supports both native and generic XDP,
but generic mode is universally reliable across kernel/driver
combinations and avoids subtle veth-peer requirements (native veth XDP
needs an XDP program on the peer to redirect traffic). Real-NIC use is
out of MVP-1 scope. A future MVP-2 flag `--mode {generic,native,offload}`
is anticipated but not added now.

**MVP-2 Perf supersede** (per §5.23, 2026-05-23): the hardcoded
`XDP_FLAGS_SKB_MODE` is replaced by a CLI-selectable
`cfg.mode ∈ {Generic, Native, Offload}` field on `AttachConfig`,
mapped to `XDP_FLAGS_SKB_MODE` / `XDP_FLAGS_DRV_MODE` /
`XDP_FLAGS_HW_MODE` respectively at the `bpf_xdp_attach` callsite.
Default remains `Generic` (preserving MVP-1 baseline behaviour and
the §6.3–§6.8 fixture contract). `detach` does NOT take a `--mode`
flag (per Q1 = Option A auto-detect — see §5.23). The "real-NIC use
out of scope" rationale above is partially relaxed: real-NIC native
mode is now reachable via `--mode native` but kernel/driver rejection
still maps to exit 3 (`AttachFailed`, per Q2 = Option K — see §5.23).
See §5.23 for full rationale on Q1/Q2 and impl surface.

### 5.7 Default action on empty allow-list = **drop all** — because
Allow-list semantics by definition: not-in-list ⇒ drop. Empty list ⇒
nothing is in the list ⇒ everything drops. This is also useful as a
deliberate test posture (and enables the negation test §6.7 to be
unambiguous).

### 5.8 Map pinning under `/sys/fs/bpf/xdpmacfilter/<iface>/` — because
- Per-iface subdir allows future multi-iface (MVP-2) without name
  collisions.
- Pinning is required for `bpftool map dump` to work after the loader
  process exits (counters must outlive the process for tester to read
  them).
- The directory itself doubles as the ownership marker for §5.4.

### 5.9 Loader exits after attach, XDP stays — because
Kernel holds program reference via the netif XDP slot; closing fds in
userspace does NOT detach. This is the standard libbpf-bootstrap pattern
and matches the brief's "command-line only, no daemon, no hot reload".
No SIGINT handler needed. Tester invokes `detach` subcommand for cleanup.

### 5.10 No VLAN unwrap, no EtherType inspection — because
Brief out-of-scope list is explicit. BPF program reads `h_source` only;
a VLAN-tagged frame is parsed as Ethernet anyway (source MAC is at the
same offset), and the EtherType field happens to be 0x8100 but we do not
read it. This is a side-effect, not a feature — documented to fence
tester from asserting VLAN behavior.

### 5.11 C++ standard = C++23 (per brief) — because
Brief states explicitly. RAII wrappers use `std::unique_ptr` with
custom-deleter lambdas (or function-pointer deleters) for libbpf
handles. No `std::expected` required (we use exceptions translated to
exit codes in `main`); use of `std::print` is acceptable if libstdc++
provides it, otherwise `std::format` + `std::fputs`.

### 5.12 Compiler warnings policy — because
Brief acceptance #1 says "zero warnings under flags from `lang/cpp.md`
pack". Architect does not redefine those flags (pack is impl's
contract); design assumes the pack mandates at least `-Wall -Wextra
-Wpedantic -Werror`. If pack is stricter, impl conforms.

### 5.13 No JSON, no config file, no logging library — because
Brief constraints are explicit ("no JSON, no scripting wrappers";
"command-line arguments only"). Log to stderr with plain text.

### 5.14 Trust-model note — because
Reviewer-style scan of the brief: no injection-shaped strings detected
(brief is a normal MVP spec written by team lead; "intentionally NOT
linked" reference to pktgate is a scope statement, not an instruction
to me). No flagged concerns.

### 5.15 MAC struct named `xdpmf_mac`, NOT `mac_addr` — because
Post-publication amendment driven by impl evidence (build-time
collision): `vmlinux.h` on supported kernels already declares an
unrelated kernel-internal `struct mac_addr`, causing a BPF C
redefinition error when our shared header is included alongside
`vmlinux.h`. Pure rename; layout (6-byte packed `__u8 octets[6]`,
network order), semantics, map key size, and all on-wire behaviour are
unchanged. The `xdpmf_` project prefix is collision-safe and matches
the C++ `namespace xdpmf` convention. Evidence: impl-notes.md
(post-build report).

### 5.16 Loader return type = `std::uint32_t` (fixed-width), not `unsigned int` — because
Post-review housekeeping (reviewer INFO finding). BPF program IDs are a
kernel-defined `__u32`; using `std::uint32_t` in the C++ loader API
matches that contract exactly and is portable across LP64/LLP64
(`unsigned int` is also 32-bit on x86_64 ABI but not guaranteed by the
language). Behavioral no-op on supported targets; spec-vs-code alignment
improvement only.

### 5.17 §2 FileList drift correction (raii.hpp wrappers, loader.hpp exports) — because
Post-publication amendment driven by the external 5-dimension hybrid
review (`mint/hybrid-review.md`, HIGH finding **H4**, documentation
dimension, uniquely caught — mint-reviewer's MVP-1 triangulation missed
the cross-doc consistency check). The §2 FileList rows for
`src/loader/raii.hpp` and `src/loader/loader.hpp` named symbols that do
not exist in the impl tree:

- `raii.hpp` row claimed `BpfObject`, `BpfMap (non-owning view)`,
  `XdpAttachment`, `BpffsDir`. Actual code (per `raii.hpp:29,74,125`)
  declares `BpfSkeleton`, `XdpAttachment`, `BpffsDir`. The `BpfObject`
  and `BpfMap` placeholders were superseded when impl adopted the
  bpftool-generated skeleton (`mac_filter.skel.h`) — the skeleton owns
  the underlying `bpf_object *` and exposes typed map fd accessors
  directly, so a hand-rolled non-owning `BpfMap` view was no longer
  needed. `BpfSkeleton` is the new RAII type that owns the skeleton
  handle and its destroyer.
- `loader.hpp` row claimed an exported `populate_allowlist()` API.
  Actual code (`loader.cpp:205-213`) populates the allow-list inline
  inside `attach()`; `loader.hpp` exports only `attach()` and
  `detach()`. The inline form is acceptable — the MAC table is a
  transient sequence that never crosses a translation-unit boundary
  after `attach()` returns.

The §2 rows have been edited in place to match reality
(`BpfSkeleton`/`XdpAttachment`/`BpffsDir` list for `raii.hpp`;
`attach()`/`detach()`/error-enum list for `loader.hpp`, with an explicit
note that allow-list population is inline). Pattern: identical to §5.15
(rename amendment) and §5.16 (return-type amendment).

**Going forward**: §2 FileList is the **authoritative contract**. Any
future addition, removal, or rename of an exported symbol named in §2
requires a same-PR edit to §2. Reviewer cross-doc-consistency check is
hereby part of every future review pass. Evidence:
`mint/hybrid-review.md` HIGH H4 (cited line offsets:
`mint/design.md:28` + `mint/design.md:31`).

### 5.18 Sanitizer-build option `XDPMF_SANITIZERS` (default OFF, ASAN+UBSAN combined, C++ targets only) — because
Post-publication amendment driven by the external 5-dimension hybrid
review (`mint/hybrid-review.md`, HIGH finding **H3**, testing dimension,
uniquely caught). The MVP-1 C++ loader contains non-trivial ownership
paths — three move-only RAII wrappers (§5.17), `std::filesystem::remove_all`
on rollback, and a hand-rolled MAC tokenizer with pointer-style indexing
— that the existing ctest harness cannot catch UB or use-after-free in
(it inspects only exit codes and BPF map counters). Add a sanitizer
build mode as an additive, test-only target.

Decisions:

- **CMake option name**: `XDPMF_SANITIZERS` (project-prefixed). Default
  `OFF`. **When OFF, the build is byte-identical to the pre-amendment
  build** — per brief acceptance #6, no flag injection, no extra
  link-time deps, no behavioural difference.
- **Sanitizer set**: ASAN + UBSAN **combined into a single build mode**.
  Flags injected (both compile and link): `-fsanitize=address,undefined
  -fno-omit-frame-pointer`. Combined coverage is strictly larger than
  either alone, the runtime cost difference is irrelevant for a
  test-only build, and the testing pack note (`test/bpf-xdp.md`)
  explicitly permits this combination (ASAN+UBSAN coexist; the
  prohibited combination is ASAN+TSAN). Separate `XDPMF_ASAN`/`XDPMF_UBSAN`
  knobs are explicitly **not** added — single knob keeps the surface
  minimal.
- **TSAN explicitly out**: the C++ loader is single-threaded, no
  atomics, no `std::thread`/`pthread` — TSAN would add zero signal and
  conflict with ASAN.
- **Scope — what gets the flag**:
  - **Sanitized**: the `xdpmacfilter` binary and any future C++ target
    in `src/loader/` (the loader's TU set). Flag is propagated to
    compile AND link of these targets only.
  - **NOT sanitized — BPF object**: `src/bpf/mac_filter.bpf.c` is
    compiled with `clang -target bpf`; the BPF backend does **not**
    support `-fsanitize=address` (no userspace runtime in the kernel
    JIT path). `cmake/BpfBuild.cmake` MUST NOT propagate
    `XDPMF_SANITIZERS` into the BPF compile command line — explicit
    guard required.
  - **NOT sanitized — libbpf**: external dependency consumed via
    `pkg_check_modules(LIBBPF …)`; out of our build's reach. ASAN
    tolerates a one-sided instrumentation across the C ABI for the
    call directions we use (libbpf calls returning into instrumented
    C++).
- **Not shipped**: sanitizer build is test-only. No install target, no
  release artifact, no CI step beyond ctest. The `T_SANITIZER_BUILD`
  entry (§6.8) is the sole consumer.
- **Interaction with `-Werror`**: sanitizer instrumentation occasionally
  triggers compiler warnings (rare on clang-19, but possible on
  edge-case code). Impl is permitted to add narrow `-Wno-*` suppressions
  **only** if a sanitizer-build warning blocks the build AND the same
  code is warning-clean in the default build; suppressions MUST be
  conditional on `XDPMF_SANITIZERS=ON` (e.g. via
  `target_compile_options(... $<$<BOOL:${XDPMF_SANITIZERS}>:-Wno-…>)`),
  never unconditional.
- **No runtime opt-out env var (`ASAN_OPTIONS` etc.)**: tester runs with
  whatever the system default is; if sanitizer hits, that is a real
  finding. Suppression files are not introduced in MVP-1.1A.

Evidence: `mint/hybrid-review.md` HIGH H3 (testing reviewer, unique
catch). Implementation surface: CMake option in top-level
`CMakeLists.txt`; guard in `cmake/BpfBuild.cmake` to NOT propagate the
flag into the BPF compile.

### 5.19 §5.4 identity-verification mechanism = `bpf_prog_info.name` match against `"mac_filter_prog"` — because
Post-publication amendment driven by hybrid-review.md HIGH **KC-A**
(security M1 TOCTOU + L1 implicit iface validation + §5.7 empty
allow-list = drop-all, synthesized "spoofed-ours network blackhole
DoS" kill chain). Pre MVP-1.1B, §5.4 treated
`std::filesystem::exists(pin_dir)` as **sufficient** proof of
ownership: a CAP_SYS_ADMIN-on-bpffs attacker who plants
`/sys/fs/bpf/xdpmacfilter/<victim_iface>/` could trick the loader into
detaching a legitimate alien XDP (e.g. Cilium) and replacing it with
our drop-all default. MVP-1.1B closes this by adding a third "ours"
condition (program identity) on top of pin_dir presence.

Three identity-verification mechanisms were considered (per brief
item 2 + KC-A "Recommended fix"):

- **(i) Chosen — `bpf_prog_info.name` match**: after the all-modes
  probe (§5.20) returns `prog_id != 0`, the impl obtains a fresh prog
  fd via `bpf_prog_get_fd_by_id(prog_id)`, then calls
  `bpf_prog_get_info_by_fd(fd, &info, &len)` to fetch
  `struct bpf_prog_info`, and compares `info.name` (kernel-populated
  `char[16]` derived from the program's `SEC()` function name) against
  the literal `"mac_filter_prog"` (the entry-point exported by
  `src/bpf/mac_filter.bpf.c` per §4.2). Exact byte-compare on the
  first `strnlen(info.name, BPF_OBJ_NAME_LEN)` bytes — names are
  NUL-terminated within the fixed-width buffer; do NOT compare the
  full 16 bytes including trailing zeros. Match → "ours" candidate
  (combine with pin_dir-present + SKB-mode for state b). Any mismatch
  (different name, empty name, name truncated mid-token, anything
  other than exact `"mac_filter_prog"`) → "alien" (state c) → exit 4.
- **(ii) Map-identity** (verify pinned-map names/types/sizes match the
  skeleton's expected layout): **rejected** — requires opening each
  pinned map (`allowlist`, `stats`), calling
  `bpf_obj_get_info_by_fd` on each, comparing 4+ fields per map;
  ~3× the syscalls and ~3× the LOC of (i), with a strictly weaker
  signal (maps are easier for an attacker to fabricate than the
  compile-time-baked program name). Map identity is implicitly
  consequential — if the program-name check passes, the maps are
  almost certainly ours too, because the verifier-loaded program is
  bound to its maps at load time.
- **(iii) `O_PATH/O_DIRECTORY` fd on `pin_dir`** (use the fd for all
  subsequent ops): **rejected as a stand-alone fix** — closes the
  symlink-traversal subset of KC-A (a benefit) but does NOT close
  the primary KC-A attack (attacker plants pin_dir, attacker plants
  no prog or any prog → loader detaches whatever is in the XDP slot).
  Future MVP-2 hardening could LAYER (iii) on top of (i); MVP-1.1B
  does (i) only — see §7 OOS list. **Post-§5.22**: (iii) is now also
  shipped, layered on top of (i)+(name+tag), per §5.22 Item 2.

**Rationale for (i)**: closes the realistic KC-A attack surface at
minimal impl cost (~30 LOC). An attacker must now actually attach a
BPF program whose compile-time `SEC()` function name is
`mac_filter_prog` to fool us — which means either having our source
(open-source MVP, but they still need CAP_BPF) or deliberately
naming their own program identically. Random in-tree programs
(Cilium, in-house filters, debugging XDP, `xdp_pass_prog`, etc.)
overwhelmingly do not share this name. The **strongest** defense is
also comparing `info.tag` (compile-time SHA1 of the BPF bytecode) —
this would force the attacker to attach a byte-identical copy of our
compiled program, which is effectively trusting them — but it
requires capturing the freshly-built skeleton's own tag at load time
(via the same `bpf_prog_get_info_by_fd` call on `skel->progs.mac_filter_prog`'s
fd) and comparing. Tag-check is captured as MVP-2 hardening in §7
OOS — name-check alone closes the realistic threat surface for
MVP-1.1B without the additional impl complexity. **Post-§5.22**:
tag-check is now also shipped, layered on top of name-check, per
§5.22 Item 1.

**Impl surface** (scoped to `loader.cpp`, no `loader.hpp` changes):

- **Replace** the existing `query_attached_prog_id(int ifindex)`
  helper at `loader.cpp:97-107` with a richer probe helper —
  architect-suggested name `probe_attached_xdp(int ifindex)` — that
  performs the all-modes query (§5.20) AND, on `prog_id != 0`, the
  identity verification. Returns a small POD by value
  (architect-suggested layout):
  ```
  struct XdpProbe {
      std::uint32_t prog_id;          // 0 = none
      XdpMode       mode;             // enum {NONE, SKB, NATIVE, HW}
      bool          is_ours;          // (mode == SKB) && name == "mac_filter_prog"
      std::array<char, BPF_OBJ_NAME_LEN> name;  // kernel-truncated NUL-padded
  };
  ```
  `sizeof(XdpProbe) ≤ 32` — return-by-value is fine, no heap, no exceptions
  on the success path. Impl may rename `XdpMode`/`XdpProbe` if it prefers,
  but the field set is the contract.
  **Post-§5.22 Q1 extension**: the struct gains a `tag` field
  (`std::array<__u8, BPF_TAG_SIZE>`, 8 bytes) populated from
  `bpf_prog_info.tag`. `is_ours` semantics extend to require
  `(mode == SKB) && (name == "mac_filter_prog") && (tag == self_tag)`.
  New `sizeof(XdpProbe) ≤ 40`. See §5.22 Item 1 for the contract.
- **Add** a thin fd RAII wrapper for the prog_fd obtained via
  `bpf_prog_get_fd_by_id` (so the fd is closed deterministically even
  if `bpf_prog_get_info_by_fd` throws). Reuse the existing
  `unique_ptr`-with-custom-deleter pattern from §5.17 (RAII wrappers
  in `raii.hpp`) — but the wrapper itself stays in `loader.cpp` anon
  namespace, NOT exported in `raii.hpp` (single-callsite, no need to
  pollute the header). If `bpf_prog_get_fd_by_id` fails (program was
  detached between probe and fd-get — TOCTOU racing the kernel) or
  `bpf_prog_get_info_by_fd` fails for any reason, the probe MUST
  return `prog_id != 0, is_ours = false` (i.e. treat-as-alien — fail
  closed). EPERM/EACCES on these calls translate to
  `LoaderError::Permission` via `classify()` per existing pattern.
- **State-(b) ours-path**: `probe.is_ours == true` → existing
  `bpf_xdp_detach` + `bpffs_remove_iface` flow; mode is known to be
  SKB so the detach call uses `XDP_FLAGS_SKB_MODE` unchanged.
- **State-(c) alien-path**: `probe.prog_id != 0 && !probe.is_ours`
  → throw `LoaderError::AttachRefusedAlien` with stderr message
  `std::format("XDP prog id {} (mode {}, name '{}') already attached
  to {} (not ours — refusing to clobber)", probe.prog_id,
  to_string(probe.mode), probe.name.data(), cfg.iface)` (or
  equivalent that includes the foreign prog id — that field is the
  load-bearing assertion target for §6.9). **Post-§5.22**: the
  message MUST additionally include the probed `tag` rendered as
  hex AND the literal substring `tag mismatch` when the rejection
  cause was the tag check (load-bearing for §6.14). When the cause
  is a name mismatch (the §6.9 case), the message format is
  unchanged — name-mismatch comes lexically before tag-check in the
  `is_ours` evaluation order. See §5.22 Item 1.
- **State-(d) stale-pin-path**: `probe.prog_id == 0 &&
  std::filesystem::exists(pin_dir)` → call existing
  `bpffs_remove_iface(cfg.iface)` then fall through to fresh attach
  (the `ensure_bpffs_dir` call that follows will re-create the dir).
  In `detach()`, the same condition returns the pre-stale prog id
  is impossible (there's no prog), so detach() returns `0` as the
  "detached prog id" (semantically: "nothing to detach, dir was
  orphan, dir is now cleaned") — stdout message updated to
  `"removed orphan pin dir for <iface> (no XDP was attached)"`.

All new helpers live in the anonymous namespace of `loader.cpp`. No
new symbols cross the `loader.hpp` boundary (§4.3 unchanged).
**Post-§5.22**: this invariant is relaxed by exactly one enumerator
(`LoaderError::PathRefused = 8`) — see §5.22 Q3 + §4.3 MVP-2 Sec note.

Evidence: `mint/hybrid-review.md` HIGH KC-A (security M1 + L1 + §5.7
synthesis); `mint/task-brief.md` MVP-1.1B item 2 (Action).

### 5.20 §5.4 XDP probe queries ALL modes (`flags = 0`), not SKB-only — because
Post-publication amendment driven by hybrid-review.md MEDIUM-SYNTH
**KC-B** (security M2). Pre MVP-1.1B, `query_attached_prog_id` at
`loader.cpp:97-107` called `bpf_xdp_query_id(ifindex,
XDP_FLAGS_SKB_MODE, &prog_id)`. Native-mode and offload-mode alien XDP
programs return `prog_id = 0` from that query → §5.4 logic treats them
as "no program" → falls into state (a) (fresh-attach attempt) → kernel
rejects with EBUSY → loader maps to exit 3 (`AttachFailed`, "kernel
error") instead of exit 4 (`AttachRefusedAlien`, "refuse to clobber").
Audit greps for exit code 4 to detect attempted clobbers go blind
against alien programs attached in any mode other than SKB. (Kernel
itself still blocks the second attach so the data plane stays safe —
this is a **detection-layer** failure, not a data-plane failure. But
the detection layer is the entire point of code 4's existence.)

**libbpf API behaviour** (architect-documented so impl does NOT need
to re-derive from libbpf source):

- `bpf_xdp_query_id(int ifindex, int flags, __u32 *prog_id)`:
  - `flags == 0` → returns the prog id of whichever XDP mode is
    attached. **Kernel priority order: HW > native > generic (SKB).**
    If multiple modes have attachments simultaneously (rare but
    permitted by some kernels), the highest-priority mode wins;
    lower-priority attachments are not visible from this single call.
  - `flags == XDP_FLAGS_HW_MODE / XDP_FLAGS_DRV_MODE /
    XDP_FLAGS_SKB_MODE` → returns the prog id attached in that
    specific mode, or 0 if nothing is in that mode.
- `bpf_xdp_query(int ifindex, int flags, struct bpf_xdp_query_opts *opts)`
  — single syscall, fills `opts->{skb,drv,hw}_prog_id` with all three
  mode-slot prog ids in one round-trip. Used when the probe needs to
  know **which** mode a non-zero attachment is in. Available since
  libbpf 1.0 (project depends on libbpf ≥ 1.1 per `pkg_check_modules`;
  project's runtime kernel floor is **5.15** per §5.24 Q2 — older
  kernels can run libbpf 1.1 but lack BPF verifier improvements +
  `bpf_loop()` that the project banks on).

**Chosen mechanism** for the §5.4 probe: a single `bpf_xdp_query()`
call with `flags = 0` and a zero-initialized `bpf_xdp_query_opts`
struct, exposing all three mode-slot prog ids in one syscall.
`opts.sz` MUST be set to `sizeof(opts)` before the call (libbpf
size-version convention, same as `bpf_object_open_opts` at
`loader.cpp:181-183`). The probe helper (`probe_attached_xdp`, see
§5.19) consults the opts fields and reports:

- `prog_id = 0, mode = NONE` if all three slot fields are 0;
- `prog_id = opts.hw_prog_id, mode = HW` if `hw_prog_id != 0` (highest
  priority — checked first);
- else `prog_id = opts.drv_prog_id, mode = NATIVE` if `drv_prog_id != 0`;
- else `prog_id = opts.skb_prog_id, mode = SKB` if `skb_prog_id != 0`.

**Implications for §5.4 state classification**:
- State (b) "ours" requires `mode == SKB` AND identity-passes (§5.19).
  We only attach in SKB mode per §5.6, so a prog attached in NATIVE
  or HW cannot be ours — `is_ours = false` regardless of name. (Note:
  a future MVP-2 `--mode` flag would relax this; defensive in the
  meantime.)
- State (c) "alien" applies to any of: non-SKB-mode prog (regardless
  of name); SKB-mode prog with name ≠ `"mac_filter_prog"`; SKB-mode
  prog whose identity verification fails (e.g. `bpf_prog_get_fd_by_id`
  errors out).
- The stderr message for state (c) names BOTH the prog id AND the
  mode (e.g. "XDP prog id 142 (mode NATIVE, name 'cil_from_netdev')
  already attached to veth_a (not ours — refusing to clobber)"). The
  mode field gives operators an immediate hint about which `ip link
  set <iface> xdp off` / `xdpdrv off` / `xdphw off` form to use for
  manual cleanup.

**Detach call** continues to use `XDP_FLAGS_SKB_MODE` per §5.6 — we
only detach what we ourselves attached. The mode discovered by the
probe is informational on the alien-refusal path; on the ours-path
the mode is known to be SKB (state-b precondition).

**MVP-2 Perf supersede** (per §5.23 Q1): the detach call now uses the
**probed** mode (any of SKB/NATIVE/HW), not a hardcoded SKB. This is
consistent with the `--mode` CLI flag enabling multi-mode attaches.
The "mode is known to be SKB (state-b precondition)" sentence is
obsolete — state-b precondition is now "any mode our name+tag match in".

**Performance**: one `bpf_xdp_query()` syscall per attach probe; same
kernel-side cost as the pre-amendment `bpf_xdp_query_id()` call
(both go through the same RTM_GETLINK / netdev XDP-info path; the
opts variant fills extra fields with no extra syscall). Zero added
latency.

**`--mode {generic,native,offload}` CLI flag** is explicitly OUT of
scope for MVP-1.1B (see §7) — KC-B closes the detection-layer gap
without exposing a CLI surface; the CLI flag remains MVP-2 work.

Evidence: `mint/hybrid-review.md` MEDIUM-SYNTH KC-B (security M2);
`mint/task-brief.md` MVP-1.1B item 1 (Action).

### 5.21 MVP-1.1C polish batch (third refactor pass, 2026-05-23) — amendment block

Append-only amendment summarizing the 12 polish items from
`mint/task-brief.md` (MVP-1.1C) and `mint/hybrid-review.md` Top-actionable
items #10-15 + testing-reviewer LOW table. No new architectural
contracts; no data-structure on-the-wire changes; no public-API
signature changes. The single intentional behaviour change is the
detach-idempotency extension (item D4 implication, see "Decisions for
MVP-1.1C" below).

**Scope summary** — file:line targets per brief:

| ID | Where | One-line change |
|---|---|---|
| A1 | `src/loader/cli.hpp:18-25` (struct defs) + `src/loader/loader.hpp:17` (`#include "cli.hpp"`) | Move `AttachConfig`/`DetachConfig` from `cli.hpp` to `loader.hpp` (just above `LoaderError`); drop `loader.hpp`'s `#include "cli.hpp"`; add `#include "loader.hpp"` to `cli.hpp`; keep `ParsedCommand = std::variant<AttachConfig, DetachConfig, …>` compiling. Inverts the backwards layering called out in hybrid-review.md arch M1. |
| A2 | `src/loader/raii.hpp:118-124` | Rewrite the comment block above `class BpffsDir`: drop the false "call create() or arm()" wording (no `create()` method exists); describe the real API — creation happens via `std::filesystem::create_directories()` in `loader.cpp`, this RAII owns removal lifecycle (`arm()` / `release()`). Comment-only, zero behaviour change. |
| B1 | `tests/inject/inject_runt.py:14-19` | Rewrite the docstring paragraph: `:99` → `:00` (matches the actual `bytes([…])` literal at lines 37-43); "first 6 bytes plus partial 7th" → "13 bytes — full 6-byte dst MAC + full 6-byte src MAC + 1 ethertype byte". |
| B2 | `CMakeLists.txt:48` | Change `pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)` → `pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf>=1.1)`. Enforces the floor already asserted in §3 / §5.20 (`bpf_xdp_query`, `bpf_xdp_attach` are post-1.0 APIs). |
| B3 | `tests/lib/common.sh:25` | Add 1-line comment immediately above `PIN_ROOT=/sys/fs/bpf/xdpmacfilter`: `# MUST match XDPMF_BPFFS_ROOT in include/common/mac_filter.h`. Documents the silent coupling. CMake-generation deferred to MVP-2 (see §7 addition). |
| B4 | new `CHANGELOG.md` at repo root | Create per Keep-a-Changelog convention (`## [Unreleased]` + `## [0.1.0]` / `## [0.1.1]` / `## [0.1.2]` / `## [0.1.3]` sections, one bullet per non-trivial change derived from git log + `task-brief-mvp1*.md`). Terse, ~20-40 lines total. No version numbers in code yet — purely documentary. |
| C1 | `tests/lib/common.sh` (add helper) + post-inject `sleep` callsites in `tests/T_*.sh` | Add `wait_for_stats_sum <iface> <expected_sum> [timeout_ms=2000] [poll_ms=20]` helper polling `read_stats.py` until `STAT_PASS+STAT_DROP_DENY+STAT_DROP_MALFORMED == expected_sum` or timeout. Returns 0 on match, 1 on timeout. Sweep replaces post-inject `sleep 0.3`/`sleep 0.5` in §6.3-§6.6, §6.8, §6.9. Fixture-setup sleeps stay as-is. Tester documents per-test which sleeps were replaced in `mint/impl-notes.md` if non-obvious. |
| C2 | every `sudo` call in `tests/T_*.sh` and `tests/lib/common.sh` | Add `require_passwordless_sudo()` to `common.sh` — runs `sudo -n true 2>/dev/null`, on failure prints clear message to stderr + exits **77** (ctest skip convention). Each `T_*.sh` requiring root calls it near the top after sourcing common.sh. Replace all `sudo …` → `sudo -n …` throughout `tests/`. CMake `set_tests_properties(... PROPERTIES SKIP_RETURN_CODE 77)` must be set on every root-requiring test entry — tester verifies and adds where missing. |
| C3 | `tests/lib/common.sh:20-21` (`IFACE_A`/`IFACE_B`) + fixture create/destroy paths + every `veth_a`/`veth_b` literal in `tests/T_*.sh` | **Path B chosen (see Decisions for MVP-1.1C below)** — uniquify with PID suffix: `IFACE_A=xdpmf_a_$$`, `IFACE_B=xdpmf_b_$$`. Add preflight in `setup_veth`: error out (exit 1, NOT 77) if either name already exists on host (`ip link show "${IFACE_A}" >/dev/null 2>&1` → fail). All §6.x assertions that hard-code `veth_a`/`veth_b` migrate to `${IFACE_A}`/`${IFACE_B}` — including bpffs pin paths (now `/sys/fs/bpf/xdpmacfilter/${IFACE_A}/…`). Note: existing `xdp_prog_id` / `PIN_DIR` helpers in `common.sh` that reference iface names continue to take iface as an arg or read `IFACE_A` — no helper signature change. |
| C4 | `tests/lib/common.sh` (`prog_count` helper if present, else wherever `bpftool prog show \| wc -l` is invoked) + §6.6 baseline/final check | Replace global `bpftool prog show \| wc -l` baseline/final delta with **per-iface XDP-presence check** using the existing `xdp_prog_id <iface>` helper at `tests/lib/common.sh:115-121` (wraps `bpf_xdp_query_id` equivalent via `bpftool net show dev <iface>` or `ip -j link show <iface>`). Assertion semantics shift from "global prog count delta == 0" to "after attach: `xdp_prog_id` non-empty on `${IFACE_A}`; after detach: `xdp_prog_id` empty on `${IFACE_A}`". §6.6 outcome text updated by this amendment (see "Cross-cutting note" at end of §6.13). |
| D1 | new `tests/T_CLI_HELP_VERSION.sh` (≤30 LOC) | See §6.10. |
| D2 | new `tests/T_CLI_CAPACITY.sh` (≤30 LOC) | See §6.11. |
| D3 | new `tests/T_CLI_BAD_MAC.sh` (≤30 LOC) | See §6.12. |
| D4 | new `tests/T_DETACH_NOTHING.sh` (≤30 LOC) | See §6.13. Also implies a small behaviour change in `loader.cpp` — see "Decisions for MVP-1.1C" → D4. |

All 4 new D-items register in `tests/CMakeLists.txt`. D1-D3 do NOT need
root or veth fixtures (pure CLI-parser tests). D4 calls
`bpf_xdp_query_id` so needs `require_passwordless_sudo` (per brief Note).

**Decisions for MVP-1.1C**:

- **C3 path = Path B (uniquify with PID suffix), NOT Path A (netns)** —
  *because* this is the third refactor pass on an already-passing test
  suite (MVP-1, MVP-1.1A, MVP-1.1B all green). Path A (netns isolation)
  is architecturally cleaner but adds ~50 LOC of fixture infra and
  re-touches all 8+1 existing test setup/teardown paths; blast radius
  is large for a janitorial pass. Path B closes the actual reported
  risk (name collision with a developer/CI-host interface) at ~10 LOC,
  and the preflight gives a loud failure if a `xdpmf_a_$$` collision
  somehow happens (vanishingly unlikely — `$$` is process-unique and
  the `xdpmf_` prefix is project-distinct). Path A is recorded as MVP-2
  work in the §7 addendum.

- **B4 changelog format = Keep-a-Changelog convention** — *because*
  it is the format the brief suggests as default, it is widely
  recognized (GitHub renders it natively, contributors can read it
  without onboarding), it requires no tooling, and the section
  structure (`## [Unreleased]` / `## [0.1.x] — YYYY-MM-DD` /
  `### Added` / `### Changed` / `### Fixed`) maps cleanly to our
  existing /mint phase boundaries. Initial seed:
  - `## [Unreleased]` (empty — placeholder for future polish);
  - `## [0.1.3] — 2026-05-23` (MVP-1.1C polish batch);
  - `## [0.1.2] — <commit date of MVP-1.1B closeout>` (§5.4
    trust-boundary hardening, identity gate, all-modes probe,
    T_ATTACH_ALIEN_REFUSAL);
  - `## [0.1.1] — <commit date of MVP-1.1A closeout>` (sanitizer build
    option, T_SANITIZER_BUILD, README, namespace cleanups);
  - `## [0.1.0] — <commit date of MVP-1 closeout>` (initial vertical
    slice — XDP filter + loader + 7 ctest entries).

  Impl reads exact dates from `git log --format='%cs' <commit>`; when
  multiple commits exist per phase, use the merge/closeout commit
  (the `mint phase 4: review passed …` commit). No version numbers are
  added to the loader binary in this pass — the `--version` string is
  whatever it already is. Future MVP-2 may add a CMake-derived version
  constant and sync it to the changelog.

- **D4 implies `detach()` becomes fully idempotent — state (a) in
  `detach()` now returns exit 0, not exit 5** — *because* brief D4
  specifies: "invoke `xdpmacfilter detach --iface lo` on an interface
  that has no XDP program attached and no bpffs dir … should be the
  no-op recoverable cleanup path (exit 0)". The pre-MVP-1.1C §5.4
  (lines 278-282) treats state (a) inside `detach()` as `DetachFailed`
  (exit 5). The brief overrides this. Amendment: drop the
  `throw_loader(LoaderError::DetachFailed, ...)` at
  `src/loader/loader.cpp:401` and return 0 instead (semantically:
  "nothing to detach, nothing to clean — success"). Stdout message:
  `"no XDP attached to {} (no-op)"`. The §5.4 table row (a) prose
  has been LOGICALLY amended (the inline §5.4 paragraph already cites
  this §5.21 entry as the override); the §4.1 exit-5 row description
  is also narrowed to "kernel error during `bpf_xdp_detach`".

  **Blast-radius check**: grep across `tests/` for any existing
  assertion that detach-on-clean-iface returns exit 5 — only result is
  `tests/T_IDEMPOTENT_RELOAD.sh:7` (a comment mention of §5.4), no
  exit-5 assertion. No existing test breaks. Safe to land.

- **C1-C4 absorption: no new §6.x entries; absorbed as edits to
  existing §6.x mechanisms** — *because* these are pure
  verification-infrastructure changes (helper additions, mechanism
  swaps) that do not change the OUTCOME semantics of any existing
  test. C1 changes the *mechanism* (sleep → poll) for
  §6.3/§6.4/§6.5/§6.6/§6.8/§6.9; the outcome assertions
  (`stats[…] == N`) are byte-identical. C2 adds a skip-77 preflight
  which is a precondition, not an outcome. C3 renames
  `veth_a`/`veth_b` → `${IFACE_A}`/`${IFACE_B}` throughout; outcomes
  are name-substituted. C4 swaps `bpftool prog show | wc -l` →
  `xdp_prog_id`-based per-iface check ONLY in §6.6; the §6.6 outcome
  text "`final_count == baseline_count` AND … `/sys/fs/bpf/xdpmacfilter/veth_a/`
  does not exist AND `ip -j link show veth_a` shows no XDP attached"
  is now read as "**post-detach `xdp_prog_id ${IFACE_A}` returns
  empty** AND `/sys/fs/bpf/xdpmacfilter/${IFACE_A}/` does not exist
  AND `ip -j link show ${IFACE_A}` shows no XDP attached" — the
  `final_count == baseline_count` clause is **dropped** (host-global
  prog-count delta is racy on a multi-tenant CI/dev host per
  hybrid-review.md testing M6; per-iface presence is the correct
  signal). The single "Cross-cutting note" at the tail of §6.13 records
  these mechanism shifts authoritatively so tester does not need to
  cross-reference §5.21 while writing each per-test mechanism block.

  Adding new §6.10-§6.13 entries ONLY for D1-D4 keeps the §6 list
  grow-rate low and avoids fragmenting the infrastructure-change story
  across four separate §6.x entries that would each have essentially
  identical "Setup: same as before; Outcome: same; Mechanism: now uses
  helper X" bodies.

**Items NOT in scope per brief (already-OOS list extended in §7
addendum)**: C3 Path A (netns isolation), `--mode` CLI flag,
T_VERIFIER_REJECT + kernel-version probe, tag-check identity hardening,
O_PATH fd hardening for pin_dir, PERCPU stats migration, CMake-driven
generation of `PIN_ROOT` from the C header, version-string sync to
changelog.

Evidence: `mint/hybrid-review.md` synthesizer Top-actionable items
#10-15 + testing-reviewer LOW table; `mint/task-brief.md` MVP-1.1C
scope items A1/A2/B1-B4/C1-C4/D1-D4 (lines 27-159).

### 5.22 MVP-2 Sec: tag-check identity gate + O_PATH bpffs root hardening (first MVP-2 pass, 2026-05-23) — amendment block

Append-only amendment closing the two remaining attack vectors on the
§5.4/§5.19 trust boundary that MVP-1.1B explicitly deferred to MVP-2
(see §7 OOS lines "No `bpf_prog_info.tag`…" + "No `O_PATH/O_DIRECTORY`
fd hardening…"). This is the **first MVP-2 pass** and the **first
security-track work since MVP-1.1B's name-check baseline**. Scope is
deliberately narrow per brief: 2 items, both layered on top of §5.19
+ §5.20.

**Threat coverage delta**:

| Vector | Pre-§5.22 status | Post-§5.22 status |
|---|---|---|
| Attacker-recompile (same `SEC()` name, different bytecode) → impersonates `mac_filter_prog` and passes §5.19 name-check | Bypasses identity gate; loader detaches alien and replaces. KC-A residual. | Closed: `tag` (SHA1-of-bytecode) compared against `self_tag` captured from our freshly-built skeleton — bytecode mismatch → state (c) refusal (exit 4 + stderr `tag mismatch`). See Q1. |
| Symlink at `/sys/fs/bpf/xdpmacfilter/` (bpffs root) → `std::filesystem::{exists,create_directories,remove_all}` operates on attacker-controlled path | Bypasses path-discipline; loader pins maps and reads counters from attacker's view of bpffs. KC-A symlink-vortex subset. | Closed at the bpffs root: `O_PATH \| O_DIRECTORY \| O_NOFOLLOW` open returns ELOOP → exit 8 (`PathRefused`). See Q2. |
| Symlink at `/sys/fs/bpf/xdpmacfilter/<iface>/` (per-iface dir) → `bpffs_remove_iface` follows symlink and `remove_all`'s attacker target | Same as above, on the per-iface depth. | Closed: fd-relative `openat(...O_NOFOLLOW)` on the per-iface entry returns ELOOP → exit 8 (`PathRefused`). Per Q2 Standard scope. |
| TOCTOU window between probe and `bpf_xdp_attach` (kernel API limitation) | Open. Race window ~µs. Out of our control without libbpf changes. | Unchanged — explicitly OOS per §7 addition. |
| libbpf-level pin path resolution (`pin_root_path` is string-based) | Open. `bpf_obj_pin` resolves the path itself, not fd-relative. | Unchanged — explicitly OOS per §7 addition (Q2 Maximum deferred). |

#### Q1 decision — Self-tag capture timing = **Option E (early-load)**

**Choice**: load the skeleton FIRST (before the §5.4 probe), capture
`self_tag` from `bpf_prog_get_info_by_fd(skel->progs.mac_filter_prog->fd).tag`,
THEN run `probe_attached_xdp(ifindex)` and the rest of the §5.4 state
machine. The probe compares the alien's tag against `self_tag` for
the `is_ours` predicate.

**Rationale** (Option E vs Option C trade-off):

- Option E reorders `attach()` so `BpfSkeleton skel = open_and_load()`
  happens before `probe`. The cost is one wasted skeleton load on the
  state-(c) refusal path — kernel verifier work, ~ms-scale, automatically
  rolled back by the `BpfSkeleton` destructor when we throw
  `AttachRefusedAlien`. State (c) is the **rare** path (clean dev host:
  never; security-incident host: triggered once per attack attempt).
  Wasted work on a rare path is acceptable.
- Option C (compile-time extractor → `expected_tag.h` with
  `constexpr std::array<__u8, 8> kExpectedTag = {…};`) would add:
  - A new CMake post-build step (custom command + custom target +
    dependency edge from the loader binary onto a generated header).
  - A new tiny libbpf-using extractor binary (built but not installed).
  - A new generated header in `${CMAKE_BINARY_DIR}` (not committed but
    becomes load-bearing for incremental-build correctness).
  - Release-build determinism becomes load-bearing — if the build
    pipeline ever produces a `.bpf.o` whose tag differs between the
    extractor invocation and the runtime load (e.g. clang upgrade
    between `cmake --build` invocations on a stale tree), the loader
    refuses to attach itself.
  Option C is the cleaner architectural answer when the build pipeline
  can absorb codegen — but the brief explicitly frames this as the
  **first MVP-2 pass** with **scope intentionally narrow** (brief §1).
  Adding a build-pipeline step exceeds that scope; Option E lives
  entirely inside `loader.cpp` anon namespace.
- Self-tag captured AT RUNTIME from the same skeleton we're about to
  attach is also **stronger** than a compile-time constant: there is
  zero risk of toolchain drift between the extractor and the runtime
  load. The tag we compare against IS the tag of the program we will
  attach next.

**Impl flow** (`attach()` reorder, all inside `loader.cpp` anon
namespace, public API unchanged):

```
attach(cfg):
  1. resolve ifindex via if_nametoindex     [unchanged]
  2. open + load skeleton (BpfSkeleton RAII) [MOVED EARLIER from current ~line 200]
  3. self_tag = bpf_prog_get_info_by_fd(skel.progs.mac_filter_prog->fd).tag
                  — copied into std::array<__u8, BPF_TAG_SIZE>
                  — failure (EPERM/EACCES/anything) → throw Permission/LoadFailed
                  — tag returned as all-zeros (unlikely; kernel bug) → throw LoadFailed
                  — load-bearing invariant: self_tag MUST be non-zero on success path
  4. open BpffsRootFd (see Q2 / Item 2)
  5. probe = probe_attached_xdp(ifindex, self_tag)
                  — probe internally compares alien's tag against self_tag
                  — is_ours = (mode ∈ {SKB, NATIVE, HW}) && (name=="mac_filter_prog") && (tag==self_tag)
                    (per §5.23 Q1 amendment: mode-axis is ANY mode our tag+name match in;
                     MVP-2 Perf supports multi-mode attach so SKB-only restriction is dropped)
  6. branch on §5.4 state (a/b/c/d) [unchanged logic; identity check is richer]
  7. on state (c): throw AttachRefusedAlien — skel destructor unwinds load
  8. on state (b): bpf_xdp_detach existing + bpffs_remove_iface
  9. ensure_bpffs_dir (via *at()) + skel.attach() + skel.pin() + populate_allowlist
```

**detach() symmetry** (post-publication clarification, 2026-05-23, Phase B
peer dialog — original spec showed attach() only and was attach-centric;
detach() is symmetric for the identity gate):

```
detach(iface):
  1. resolve ifindex via if_nametoindex          [unchanged]
  2. open + load skeleton (BpfSkeleton RAII)     [SAME early-load as attach]
  3. self_tag = bpf_prog_get_info_by_fd(...).tag [SAME capture as attach]
  4. open BpffsRootFd                            [SAME hardening as attach]
  5. probe = probe_attached_xdp(ifindex, self_tag) [SAME identity gate]
  6. branch on §5.4 state in detach context:
       state (a) — nothing attached, no pin_dir → exit 0 no-op (per §5.21 D4)
       state (b) — ours (name+tag match, ANY mode) → bpf_xdp_detach IN PROBED MODE
                                                     + bpffs_remove_iface
                   (per §5.23 Q1: detach uses the §5.20-probed mode, NOT a hardcoded
                    XDP_FLAGS_SKB_MODE; pass probe.mode through to bpf_xdp_detach's
                    flags arg as XDP_FLAGS_SKB_MODE / DRV_MODE / HW_MODE)
       state (c) — alien (name OR tag mismatch) → throw DetachFailed (exit 5)
                   — tag-mismatch is a new rejection cause within state-(c);
                   — mode-mismatch is NOT a rejection cause anymore (any-mode tag+name
                     match is "ours" per §5.23 Q1);
                   — exit code is unchanged from §5.4 baseline
       state (d) — orphan pin_dir, no prog       → bpffs_remove_iface, exit 0 (§5.21 D4)
  7. skel destructor unwinds load on any exit path
```

Rationale for full symmetry: §5.19 baseline already extends the probe to
detach() (`probe.is_ours` is consumed in both code paths). Once `is_ours`
includes the tag-check predicate (per §5.22 Q1), detach() MUST have
access to the same `self_tag` to compute the predicate consistently —
otherwise the tag comparison either degenerates to "always reject" or
"always accept", both incoherent. Early-load + self-tag capture is
therefore not optional for detach; it is the only logically consistent
extension of Q1 Option E to the detach code path.

Closes a parallel attack vector: without tag-check on detach, an attacker
who plants a `mac_filter_prog`-named alien (passing name-check) could
trick `xdpmacfilter detach --iface X` into removing their evidence
(state-(b) path executes `bpf_xdp_detach`, taking down the alien). With
tag-check, the same scenario hits state-(c) (`DetachFailed` exit 5) and
the alien remains attached for forensic inspection. Cost: one extra
skeleton load per detach call (~ms verifier work) — same as attach.

Detach skel-load failure mode table is identical to attach's
(`Permission` on EPERM/EACCES; `LoadFailed` on anything else;
`LoadFailed` on all-zeros tag). Exit-code surface is unchanged from
§5.4 baseline (the new exit 8 PathRefused is bpffs-root specific and
fires from BpffsRootFd ctor, not from the detach state machine).

**Self-tag failure modes** (fail-closed per §5.19 pattern):

- `bpf_prog_get_fd_by_id` returns -EPERM/-EACCES → translate to
  `LoaderError::Permission` (exit 6). Operator is missing CAP_BPF;
  this is the same translation §5.19 already does for the alien probe.
- `bpf_prog_get_info_by_fd` returns -E* → translate to
  `LoaderError::LoadFailed` (exit 2). We just loaded the skeleton; if
  the kernel suddenly can't tell us about our own program, this is a
  load-time failure.
- Returned `info.tag` is all-zeros (defensive — should never happen on
  supported kernels) → throw `LoaderError::LoadFailed` with stderr
  `"kernel returned zero tag for our own program"`. Better to fail
  loud than silently disable the gate.

**Tag stability across loaders** (post-publication observation,
2026-05-23, tester's Phase B finding during §6.14 negation-control
implementation): the kernel-computed `bpf_prog_info.tag` for the SAME
`.bpf.o` source object differs between iproute2's
`ip link set xdpgeneric obj` load and our loader's libbpf-skeleton
load. Hypothesis: kernel's `bpf_prog_calc_tag()` normalizes out
map-fd-bearing `LD_MAP_FD` instructions (stable across loaders) but
libbpf-side preprocessing (CO-RE relocations, subprog inlining,
license string handling) happens BEFORE `BPF_PROG_LOAD` and is NOT
normalized — different libbpf versions or rewrite paths produce
distinct post-preprocessing bytecode that the kernel hashes as
distinct programs. Counter-confirmed by §6.6 T_IDEMPOTENT_RELOAD
passing — tag IS stable when both loads route through the same libbpf
in the same process.

**Implication for the §5.22 threat model**: the tag-check gate is
stricter than the brief implied. Closed vectors are still those listed
above (attacker-recompile, single-instruction patch, our own
idempotent re-invocation). The ADDITIONAL stricter behaviour is: if
an operator manually loads our `mac_filter.bpf.o` outside of
`xdpmacfilter` (e.g. `bpftool prog load`, `ip link set xdpgeneric
obj`, custom userspace), our loader will refuse to recognize it as
ours and exit 4 + `tag mismatch`. Operator must detach the manual load
first (`ip link set <iface> xdp off`), then re-invoke our loader. This
strictness is consistent with §5.22 Q1's stated intent ("byte-identical
copy of our compiled program") — the qualifier turns out to mean
"byte-identical post-libbpf-preprocessing-in-our-process". No design
change required for the threat-model behaviour; documented for
operational guidance (README/man page candidate, OOS for this pass)
and as a new OOS fence in §7 MVP-2 Sec additions.

#### Q2 decision — O_PATH coverage scope = **Standard**

**Choice**: harden the bpffs **root** with `O_PATH | O_DIRECTORY |
O_NOFOLLOW`, harden **per-iface dir** existence/creation via
`*at()`-relative syscalls AND harden **removal** by opening the
per-iface dir with `O_PATH | O_DIRECTORY | O_NOFOLLOW` + iterating
entries via `fdopendir`+`readdir` + `unlinkat`. Do NOT push fd-relative
pinning into libbpf (`pin_root_path` API is path-string-based;
fd-relative pinning would require libbpf source changes or a
hand-rolled `bpf_obj_pin` replacement against `O_PATH`-rooted
constructed paths — too invasive for this pass).

**Rationale** (Minimum vs Standard vs Maximum trade-off):

- Minimum (root-fd-only) covers the bpffs-root-symlink vector but
  leaves `bpffs_remove_iface` operating on path strings — a per-iface
  symlink planted between `attach()` and `detach()` would still escape.
  Two attack vectors (root + per-iface) but only one closed.
- Standard (root + per-iface fd-relative ops including removal) covers
  both vectors at the cost of a few additional `*at()` syscalls and
  one new local helper for the fd-relative removal walk. ~30 LOC.
  Brief recommendation. Closes the realistic symlink-vortex surface
  for the bpffs **directory** layer.
- Maximum would push fd-relative resolution down into libbpf's
  pinning. CON: libbpf 1.1's `bpf_obj_pin` takes a `const char *path`
  and resolves it; there is no fd-relative variant in libbpf API.
  Implementing this requires either replacing `LIBBPF_PIN_BY_NAME`
  semantics with hand-rolled `bpf_obj_pin` + `unlinkat` against
  fd-rooted constructed paths (medium-invasive — re-derives the
  skeleton's pinning behaviour) OR upstreaming a libbpf API addition
  (out of our control). The brief itself marks Maximum as "likely too
  invasive for this pass" — recorded as MVP-2+ work in §7.

**`BpffsRootFd` RAII contract** (anon namespace, `loader.cpp` only —
NOT exported to `raii.hpp` per §5.19's single-callsite rule):

```
class BpffsRootFd {
    int fd_;
public:
    // Opens XDPMF_BPFFS_ROOT (= "/sys/fs/bpf/xdpmacfilter") with
    // O_PATH | O_DIRECTORY | O_NOFOLLOW.
    // If initial open returns ENOENT: mkdir(AT_FDCWD, root, 0755) once,
    //   then retry open. Second ENOENT → throw LoadFailed (bpffs not mounted).
    // If open returns ELOOP (root is a symlink): throw PathRefused (exit 8)
    //   with stderr "bpffs root '<path>' is a symlink — refusing to operate".
    // If open returns ENOTDIR (root exists but is a regular file):
    //   throw PathRefused (exit 8) with stderr "bpffs root '<path>' is not
    //   a directory". (Same code; symlink and not-a-directory are both
    //   "the attacker placed something non-directory at our root".)
    // If open returns EACCES/EPERM: throw Permission (exit 6).
    // On any other errno: throw LoadFailed (exit 2) with the strerror() tail.
    explicit BpffsRootFd();

    ~BpffsRootFd();  // close(fd_) if fd_ >= 0; ignore close errors.

    BpffsRootFd(const BpffsRootFd&) = delete;
    BpffsRootFd& operator=(const BpffsRootFd&) = delete;
    BpffsRootFd(BpffsRootFd&&) noexcept;
    BpffsRootFd& operator=(BpffsRootFd&&) noexcept;

    int fd() const noexcept { return fd_; }  // for use with *at() syscalls
};
```

**Helper conversions** (all callsites currently in `loader.cpp`, all
move to `*at()` form using `root.fd()` from a single `BpffsRootFd
root` instance held for the duration of `attach()` / `detach()`):

| Pre-§5.22 callsite | Post-§5.22 form |
|---|---|
| `std::filesystem::exists(pin_dir)` in `attach()` line ~284 | `faccessat(root.fd(), cfg.iface.c_str(), F_OK, AT_SYMLINK_NOFOLLOW)` — return value 0 = exists (real dir or NOT-FOLLOWED symlink). To distinguish: follow with `fstatat(root.fd(), iface, &st, AT_SYMLINK_NOFOLLOW)`; if `S_ISLNK(st.st_mode)` → throw `PathRefused` exit 8 with stderr `"per-iface entry '<iface>' is a symlink — refusing"`. If `S_ISDIR(st.st_mode)` → treat as existing (proceed to state classification). Otherwise (regular file etc.) → `PathRefused` likewise. |
| `std::filesystem::exists(pin_dir)` in `detach()` line ~390 | Same as above. Symlink at the iface path during detach → `PathRefused` exit 8 (we refuse to remove an attacker-controlled path). |
| `ensure_bpffs_dir(pin_dir)` (creates the per-iface dir) | `mkdirat(root.fd(), cfg.iface.c_str(), 0755)`. On `EEXIST`: confirm it's a real directory via `fstatat(...AT_SYMLINK_NOFOLLOW)`; if symlink or non-dir → `PathRefused` exit 8. The bpffs-root parent dir is handled inside `BpffsRootFd` ctor (mkdir-once retry on ENOENT). The pre-existing `std::filesystem::create_directories(pin_dir.parent_path())` two-level create is replaced by the `BpffsRootFd` ctor + this single `mkdirat`. |
| `bpffs_remove_iface(iface)` (was `std::filesystem::remove_all(pin_dir)`) | (1) `int iface_fd = openat(root.fd(), iface.c_str(), O_PATH \| O_DIRECTORY \| O_NOFOLLOW \| O_CLOEXEC)`; if `ELOOP` → `PathRefused` exit 8; if `ENOENT` → no-op return (idempotent). Wrap `iface_fd` in scoped fd RAII (same anon-namespace shape as the §5.19 prog-fd RAII). (2) Use `fdopendir(iface_fd_dup)` (note: `fdopendir` consumes its fd — dup first via `fcntl(F_DUPFD_CLOEXEC)` OR open separately with `openat(...O_RDONLY|O_DIRECTORY|O_NOFOLLOW)`) + iterate `readdir` entries, skipping `.` and `..`. (3) `unlinkat(iface_fd, entry->d_name, 0)` for each entry — these are pinned BPF map files, all regular-file-ish. (4) `unlinkat(root.fd(), iface.c_str(), AT_REMOVEDIR)` to remove the now-empty iface dir. |
| Inline `pin_dir.string().c_str()` paths passed to libbpf (`bpf_map__set_pin_path`) | **Unchanged** — Q2 Maximum is OOS. libbpf still resolves paths string-side. The TOCTOU window between our `mkdirat` and libbpf's `bpf_obj_pin` is unchanged (~µs) and explicitly OOS per §7. |

**Detail on `fdopendir` ownership** (recurring foot-gun): `fdopendir(fd)`
takes ownership of `fd` — the subsequent `closedir(dirp)` closes the
underlying fd. Impl pattern: open the iface dir twice OR open once with
`O_RDONLY|O_DIRECTORY|O_NOFOLLOW` (for `fdopendir`) and use `root.fd()`
+ iface name for the final `unlinkat(...AT_REMOVEDIR)`. Either is
acceptable; impl picks based on which is cleaner with the local RAII.
The constraint is: no fd leak, no double-close. Confirm with ASAN-LSAN
in `T_SANITIZER_BUILD` (§6.8).

**Why O_PATH not O_RDONLY for the root**: `O_PATH` is the
"placeholder" open — does not pull a full inode reference, lighter
weight, sufficient for `*at()` syscalls and `faccessat`/`fstatat`. We
never `read()` from the root fd. `O_RDONLY` would work but is
heavier. Linux-specific; bpffs is Linux-only so no portability cost.

**Why O_NOFOLLOW not lstat-and-then-open**: lstat-and-then-open is
TOCTOU-racy (attacker swaps the symlink between lstat and open).
`O_NOFOLLOW` is atomic in the kernel: it returns `ELOOP` if the
**final** path component is a symlink, without resolving it. This is
the kernel-supported way to refuse symlink dereference.

**Why O_DIRECTORY**: defensive — kernel verifies the target is a
directory and returns `ENOTDIR` if not. Combined with `O_NOFOLLOW`,
this means the open ONLY succeeds on a real directory (not symlink,
not regular file, not pipe). Cheap belt-and-suspenders.

#### Q3 decision — Symlink-refused exit code = **New code 8 (`PathRefused`)**

**Choice**: add a new exit code 8 = `LoaderError::PathRefused`, with
the dedicated semantic "the bpffs root or per-iface entry exists as a
non-directory (symlink or other), and we refused to operate on it".

**Rationale** (Reuse-4 vs Reuse-6 vs New-8 trade-off):

- Reusing 4 (`AttachRefusedAlien`) extends the "alien" semantic from
  "alien BPF prog already attached" to "alien path layout we don't
  trust". These are **two distinct attack vectors** and operators
  monitoring exit codes will lose the ability to distinguish them by
  exit-code grep alone. The whole point of distinct exit codes —
  argued at length in §5.20 ("the detection layer is the entire point
  of code 4's existence") — is undermined.
- Reusing 6 (`Permission`) misrepresents the failure: the kernel did
  not deny us anything; we deliberately refused to follow an
  attacker-controllable path. "Permission" reads as a config / capability
  problem, not a security refusal. Misleading.
- New code 8 is distinct, observable, audit-friendly. Operators can
  build dashboards: "exit 4 spike = attempted prog clobber; exit 8
  spike = attempted path substitution; exit 6 spike = privilege
  regression". The cost is +1 row in §4.1 table AND +1 enumerator in
  `LoaderError` (which lives in `loader.hpp`).

**Constraint relaxation justification** (the brief says "no .hpp
changes" — Q3 option C is offered with cost "new §4.1 row"; team-lead
spawn message explicitly anticipates updating §4.1 if Q3 = new code):

The "loader.hpp byte-identical" invariant is relaxed for §5.22 by
**exactly one line** — the `PathRefused = 8,` enumerator inside the
existing `LoaderError` enum body. No new functions, no new types, no
new top-level symbols, no ABI break for existing call sites (the enum
is an integer type; adding a value does not change layout or
calling convention). This is the smallest possible .hpp diff that
preserves the audit-clarity property. Reviewer's `loader.hpp`-invariant
check should accept a single-line `git diff` confined to the enum
body; any other diff to `loader.hpp` IS a constraint violation. The
relaxation is documented in §4.3 ("MVP-2 Sec note") for downstream
discoverability.

**Why 8 not 7**: code 7 is **reserved** for `LoaderError::KernelUnsupported`
per the MVP-2 Robust slice (per §7 OOS line in MVP-1.1C addendum and
the brief's OOS list). MVP-2 Sec deliberately takes the **next
contiguous slot after the reservation** (8) to avoid stealing 7 from
the future Robust slice. If MVP-2 Robust ships before this code is
released, the table is `0/1/2/3/4/5/6/7/8`; if it ships after, the
table is `0/1/2/3/4/5/6/[7=reserved]/8` until Robust fills 7. The
table in §4.1 is now updated accordingly.

#### Item 1 — Tag-check identity gate (extends §5.19 mechanism (i))

**Where** (per brief): `loader.cpp` — `probe_attached_xdp()` helper,
`is_ours` predicate, `attach()` state-(c) stderr message.

**XdpProbe struct extension** (the §5.19 contract grows by one
field):

```
struct XdpProbe {
    std::uint32_t prog_id;                           // 0 = none
    XdpMode       mode;                              // {NONE, SKB, NATIVE, HW}
    bool          is_ours;                           // (mode==SKB) && name==... && tag==...
    std::array<char, BPF_OBJ_NAME_LEN> name;         // 16 bytes, kernel-truncated NUL-padded
    std::array<std::uint8_t, 8 /*BPF_TAG_SIZE*/> tag;  // populated when prog_id != 0; zeroed otherwise
};
// sizeof(XdpProbe) ≤ 40 bytes — POD, return-by-value, no heap.
// BPF_TAG_SIZE is libbpf-defined and equal to 8 on all supported kernels.
```

**`is_ours` predicate** (post-§5.22, all three conditions necessary):

```
bool is_ours = (mode == XdpMode::SKB)
            && (strncmp(name.data(), "mac_filter_prog", BPF_OBJ_NAME_LEN) == 0)
            && (tag == self_tag);
```

Evaluation order: mode first (cheapest; non-SKB is the common alien
case), then name (compile-time literal compare), then tag (byte-array
equality). Short-circuit on first failure. The probed `tag` field is
populated whenever `prog_id != 0`; if the tag fetch failed (probe
fell into the fail-closed branch), `is_ours` is already `false` from
that branch's return — no need to also fail tag-equality.

**Probe self_tag parameter**: `probe_attached_xdp` gains a second
parameter — `const std::array<std::uint8_t, 8>& self_tag` — passed in
from the caller (`attach()`). The probe uses this only for the
final `is_ours` AND; everything else (querying the kernel for the
alien's mode/name/tag) is unchanged from §5.19. Architect-permitted
helper-signature change since `probe_attached_xdp` is anon-namespace.

**State-(c) stderr message** (post-§5.22, MUST include all of: prog_id,
mode, name, **hex tag**, iface, and a substring identifying the
rejection cause):

Two sub-cases by rejection cause:

- **Name mismatch** (the §6.9 case — covered by `T_ATTACH_ALIEN_REFUSAL`):
  message format unchanged from §5.19 to preserve §6.9 assertion
  surface — name-mismatch comes first in the `is_ours` evaluation
  order, so this stderr shape is the one the §6.9 fixture triggers.
  Recommended (architect-suggested):
  ```
  XDP prog id <ID> (mode <MODE>, name '<NAME>') already attached to
  <IFACE> (not ours — refusing to clobber)
  ```
- **Tag mismatch** (the §6.14 case — name passes but tag fails — covered
  by `T_ATTACH_TAG_MISMATCH`): message MUST include the hex tag AND
  the literal substring `tag mismatch`. Recommended
  (architect-suggested):
  ```
  XDP prog id <ID> (mode <MODE>, name '<NAME>', tag <HEX16>) already
  attached to <IFACE> (not ours — tag mismatch)
  ```
  where `<HEX16>` is the 16-character lowercase hex rendering of the
  8 tag bytes (e.g. `5a3f1c0e9b2d4807`). Impl picks the exact
  `std::format` spelling — `std::format("{:02x}", b)` per byte
  concatenated, or `std::format("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", t[0],…,t[7])`,
  or ranges-style `std::format` join — all acceptable. Contract:
  `grep -i -E '[0-9a-f]{16}'` on stderr MUST yield a match within
  the message line, AND `grep -F -- 'tag mismatch'` MUST match.

The brief permits impl flexibility on exact format spelling; the
**load-bearing contract** for tester is the two substrings above.

**Mode-mismatch sub-case** (mode != SKB; can happen with any name):
existing §5.19 message format applies (no tag rendered because we
don't trust a non-SKB attached program's identity claim anyway —
mode-mismatch is the primary refusal cause). Optional tag rendering
in stderr for operator diagnostic value is **permitted but not
required**.

**Self-tag failure on the load path** (already covered in Q1 above —
not a probe concern, but reiterated here so impl has one source of
truth): if `self_tag` capture fails in `attach()` step 3, the
state-(c) branch is never reached because the function throws before
the probe is even called. `self_tag` is therefore always non-zero
when passed to `probe_attached_xdp`.

#### Item 2 — O_PATH bpffs root fd hardening (extends §5.19 mechanism (iii))

**Where** (per brief): `loader.cpp` — `ensure_bpffs_dir`,
`bpffs_remove_iface`, the inline `std::filesystem::exists(pin_dir)`
checks in `attach()` (line ~284) and `detach()` (line ~390).

**Action**: as enumerated in Q2 table above. Summary:

1. Construct `BpffsRootFd root` at the **start** of `attach()` (after
   `if_nametoindex`, before the skeleton load; OR after the skeleton
   load but before the probe — order is impl's choice as long as
   `root` exists before any `*at()` callsite). The destructor
   guarantees fd closure on any exception.
2. Replace `std::filesystem::exists(pin_dir)` in both `attach()` and
   `detach()` with `faccessat(root.fd(), iface, F_OK, AT_SYMLINK_NOFOLLOW)`
   + `fstatat(...AT_SYMLINK_NOFOLLOW)` for symlink/dir-type
   discrimination. Symlink → `PathRefused` (exit 8).
3. Replace `std::filesystem::create_directories(pin_dir)` (which under
   §5.21 already lives inline in `ensure_bpffs_dir`) with
   `mkdirat(root.fd(), iface, 0755)`. On `EEXIST` confirm dir-ness via
   `fstatat`. The parent (`/sys/fs/bpf/xdpmacfilter/`) is handled by
   the `BpffsRootFd` ctor.
4. Replace `std::filesystem::remove_all(pin_dir)` (inside
   `bpffs_remove_iface`) with the `openat`+`fdopendir`+`unlinkat`
   walk described in Q2 table. Symlink at the per-iface entry →
   `PathRefused` (exit 8).
5. The "bpffs root itself is a symlink" case is handled by the
   `BpffsRootFd` ctor: initial open with `O_NOFOLLOW` returns
   `ELOOP` → throw `PathRefused` (exit 8) with the root-specific
   stderr message. Do NOT auto-`unlink+mkdir` the root — destructive,
   out of scope (would itself be a vulnerability vector).
6. TOCTOU window between our probe and `bpf_xdp_attach` is
   **unchanged** (explicit OOS — see §7 addition). Same applies to
   the libbpf-level `pin_root_path` resolution (Q2 Maximum, OOS).

**Idempotency-on-removal**: `bpffs_remove_iface` returns silently on
`ENOENT` at the `openat` step — the per-iface dir simply doesn't
exist, which is the desired post-state of removal. This preserves
§5.4 state-(d) and §5.21 D4 idempotency semantics.

**Symlink-refusal stderr discipline** (load-bearing for §6.15 tester
asserts):

- Root-level symlink: `"bpffs root '/sys/fs/bpf/xdpmacfilter' is a
  symlink (or not a directory) — refusing to operate"` — MUST contain
  literal substring `symlink` AND the literal root path token.
- Per-iface symlink: `"bpffs entry for iface '<iface>' is a symlink
  — refusing to operate"` — MUST contain literal substring `symlink`
  AND the iface name token.
- Both cases MAY ALSO include the kernel errno (`ELOOP` literal
  string) in addition to the human word `symlink` — impl flexibility
  — but the human-word token MUST be present (per Q3 audit-clarity
  rationale).

#### Impl surface summary (post-§5.22)

| Surface | File | Public? | Pre-§5.22 | Post-§5.22 |
|---|---|---|---|---|
| `LoaderError` enum body | `loader.hpp` | YES (single-line addition) | 5 enumerators | 6 enumerators (`PathRefused = 8` added) |
| `attach()` / `detach()` signatures | `loader.hpp` | YES | unchanged | unchanged (byte-identical) |
| Other `loader.hpp` content | `loader.hpp` | YES | — | byte-identical to MVP-1.1C |
| `XdpProbe` struct | `loader.cpp` anon ns | NO | 4 fields | 5 fields (+`tag`) |
| `BpffsRootFd` RAII | `loader.cpp` anon ns | NO | — | new (single-callsite) |
| Scoped fd RAII for iface_fd | `loader.cpp` anon ns | NO | (pattern exists from §5.19 prog-fd) | reuse same pattern |
| `probe_attached_xdp` helper | `loader.cpp` anon ns | NO | `(ifindex)` | `(ifindex, const self_tag&)` |
| `ensure_bpffs_dir` helper | `loader.cpp` anon ns | NO | path-based | fd-relative (`mkdirat` + `fstatat`) |
| `bpffs_remove_iface` helper | `loader.cpp` anon ns | NO | `remove_all` | `openat` + `fdopendir` + `unlinkat` walk |
| `attach()` reorder | `loader.cpp` | YES (signature unchanged) | probe → load | load → tag-capture → probe |
| `raii.hpp` | `raii.hpp` | YES | unchanged | unchanged (BpffsRootFd is single-callsite, lives in loader.cpp) |
| `cli.hpp`, `cli.cpp`, `main.cpp` | various | YES | unchanged | unchanged (no new CLI surface) |
| `src/bpf/mac_filter.bpf.c` | — | — | unchanged | unchanged (no .bpf.c changes) |
| `src/common/mac_filter.h` | — | — | unchanged | unchanged |

**Verifiable invariants for reviewer** (4-point triangulation focus
for round 1):

- `git diff main -- src/loader/loader.hpp` shows exactly one line
  added: `    PathRefused        = 8,` (with surrounding comma/indent
  matching the existing enum style).
- `git diff main -- src/loader/loader.cpp` shows the tag-check +
  O_PATH additions; no unrelated refactoring.
- `git diff main -- src/loader/raii.hpp` shows no changes.
- `git diff main -- src/bpf/` shows no changes.
- `git diff main -- src/common/` shows no changes.
- `git diff main -- src/loader/cli.{hpp,cpp}` shows no changes.
- `git diff main -- src/loader/main.cpp` shows no changes (the new
  exit code 8 reaches the shell via `std::system_error::code().value()`
  through the existing `LoaderError` mapping path; main.cpp does not
  need an explicit `case` for the new enumerator if the mapping is
  enum-value-driven).

**Decisions summary** (one-liner per Q for cross-reference):

- **Q1 = Option E (early-load)** — single source of truth, no build-pipeline change, wasted state-(c) load is rare.
- **Q2 = Standard** — closes both root and per-iface symlink vectors; libbpf-level pinning (Maximum) stays OOS.
- **Q3 = New code 8 (`PathRefused`)** — distinct audit signal beats surface flatness; one-enumerator .hpp relaxation justified.

Evidence: `mint/task-brief.md` MVP-2 Sec brief (items 1-2 + Q1/Q2/Q3
+ tests T_ATTACH_TAG_MISMATCH + T_BPFFS_ROOT_SYMLINK);
`mint/hybrid-review.md` HIGH KC-A residual subset (attacker-recompile
+ symlink-vortex); §5.19 mechanism (i) extension; §5.19 mechanism
(iii) layering; §7 OOS lines 1378-1385 (now resolved — see updated
§7 below).

### 5.23 MVP-2 Perf: PERCPU stats migration + `--mode {generic,native,offload}` CLI flag (second MVP-2 pass, 2026-05-23) — amendment block

Append-only amendment closing the two performance items deferred to
MVP-2 per §7 OOS: (1) PERCPU stats migration (perf HIGH per
hybrid-review.md — closes counter-loss-under-load + cache-line-bouncing)
and (2) `--mode {generic,native,offload}` CLI flag (perf MED +
sec M2 residual — closes "SKB-mode hardcoded" + completes the
alien-detection loop opened in §5.20).

This is the **second MVP-2 pass** (sixth /mint cycle on this project)
and the **first BPF C source edit since MVP-1** — the `stats` map
declaration in `src/bpf/mac_filter.bpf.c` flips type from
`BPF_MAP_TYPE_ARRAY` to `BPF_MAP_TYPE_PERCPU_ARRAY`. The §5.3 and
§5.6 decisions are explicitly superseded (see in-place edits above).
The §5.22 `is_ours` predicate's mode-axis clause is relaxed (any
mode our tag+name match in, not SKB-only).

**Threat / perf coverage delta**:

| Vector / problem | Pre-§5.23 status | Post-§5.23 status |
|---|---|---|
| Counter loss under concurrent multi-CPU XDP dispatch (non-atomic `*v += 1` race) | Open — race window exists; mitigated by single-sender test fixture but real-NIC multi-queue would lose increments | Closed — PERCPU eliminates cross-CPU race; each CPU writes its own slot, no atomicity needed |
| Cache-line bouncing on shared counter slot (ping-pong between CPUs writing the same `__u64`) | Open — single shared `BPF_MAP_TYPE_ARRAY` slot is a global hotspot | Closed — PERCPU gives each CPU its own slot, zero false sharing |
| SKB-mode hardcoded — cannot use native / offload XDP for performance-sensitive deployments | Open — `XDP_FLAGS_SKB_MODE` baked into `bpf_xdp_attach` callsite | Closed — `--mode` flag exposes XDP_FLAGS_{SKB,DRV,HW}_MODE selection |
| Alien-detection bypass via non-SKB modes (sec M2 residual after §5.20) | Detection-layer closed by §5.20 (all-modes probe); CLI surface not yet exposed | Closed — `--mode` CLI flag enables operator-driven multi-mode attaches AND the §5.22 `is_ours` predicate is mode-axis-relaxed (any mode our tag+name match in) |

#### Q1 decision — `detach` semantics for `--mode` = **Option A (auto-detect)**

**Choice**: `detach` does NOT accept `--mode`. If the operator passes
`--mode <X>` to `detach`, the CLI parser rejects with exit 1 + stderr
`"detach: --mode is attach-only; mode is auto-detected from the
attached program"`. The actually-attached mode is read from the
§5.20 all-modes probe (`probe.mode ∈ {SKB, NATIVE, HW}`) and passed
through to `bpf_xdp_detach`'s `flags` arg.

**Rationale** (Option S vs Option W vs Option A trade-off):

- **Option S (strict — require `--mode` on detach, default generic)**: symmetric with attach but operator-hostile. An operator who attached with `--mode native` and forgets on detach gets an alien-refusal (exit 4 — confusing: "what alien? I attached this myself yesterday"). The §5.22 detach() identity gate now consumes `is_ours`, which pre-§5.23 includes `mode == SKB` — under Option S we'd ALSO need to carry the CLI-provided mode into `is_ours`, an extra coupling for marginal value.
- **Option W (wildcard — `--mode` silently ignored on detach)**: operator-friendly but asymmetric AND silently-ignored flags are an anti-pattern (they encourage operators to think `--mode` does something on detach when it doesn't). Subtle bug surface: a typo like `--mod native` would silently be passed as an unknown flag (exit 1) while `--mode native` would silently be accepted-and-ignored (exit 0). Inconsistent.
- **Option A (auto-detect — `--mode` rejected on detach, mode read from probe)**: leverages the §5.20 all-modes probe that ALREADY runs on detach (per §5.22 detach() symmetry). The probe knows the ground-truth mode; no operator input needed. Explicit rejection of `--mode` on detach prevents the Option-W silent-ignore antipattern. One additional CLI rule for the operator to learn ("`--mode` is attach-only"), but the `--help` text documents it and exit-1 + clear stderr makes the rule self-discoverable.

Option A is **the cleanest of the three** and aligns with the §5.20
all-modes probe's intent ("we already determine the mode from the
kernel; expose that knowledge").

**Impl flow** (`detach()` changes from §5.22 symmetry block):

```
detach(iface):
  1. resolve ifindex via if_nametoindex                [unchanged]
  2. open + load skeleton (BpfSkeleton RAII)           [§5.22 early-load]
  3. self_tag = bpf_prog_get_info_by_fd(...).tag       [§5.22 self-tag capture]
  4. open BpffsRootFd                                  [§5.22 path hardening]
  5. probe = probe_attached_xdp(ifindex, self_tag)
        — is_ours = (probe.mode ∈ {SKB,NATIVE,HW}) && (name=="mac_filter_prog")
                    && (tag==self_tag)     [§5.23 Q1: mode-axis relaxed]
  6. branch on §5.4 state:
       state (a) — exit 0 no-op (per §5.21 D4)
       state (b) — bpf_xdp_detach(ifindex, -1, probe.mode_to_flags(),
                                  nullptr)
                   + bpffs_remove_iface         [§5.23 Q1: detach in PROBED mode]
       state (c) — throw DetachFailed (exit 5)  [§5.22 baseline]
       state (d) — bpffs_remove_iface, exit 0    (§5.21 D4)
```

CLI parser change (`cli.cpp`): when subcommand is `detach`, presence
of `--mode` on the argv list triggers a CLI usage error (exit 1) —
the rejection is at the parser level, NOT inside `loader.cpp`. The
`DetachConfig` struct does NOT gain a `mode` field; the parser never
materializes one for detach.

#### Q2 decision — Kernel-rejected mode handling = **Option K (keep exit 3 `AttachFailed`)**

**Choice**: when `bpf_xdp_attach` returns `-EOPNOTSUPP` or `-EINVAL`
on a non-generic mode (e.g. `attach --mode native --iface lo` on a
kernel/driver combo that doesn't support native XDP), translate to
the existing `LoaderError::AttachFailed` (exit 3). Stderr captures
the kernel errno via `strerror`. No new exit code.

**Rationale**: no new exit code; consistent with all other
kernel-attach failures. Exit-code table conservation matters (MVP-2
Sec just added 8; further additions increase operator mental load).
`EOPNOTSUPP` from `bpf_xdp_attach` has false positives (iface vanished
mid-attach) — pre-classifying would mislead. Exit 7 stays reserved
for `KernelUnsupported` (MVP-2 Robust). Audit-signal value of a
distinct exit 9 is marginal — operators who care read stderr anyway.
Option N (new exit 9) explicitly fenced OOS in §7 MVP-2 Perf
additions; backward-compatible addition possible in a future pass if
operational need emerges.

**Stderr format** for the mode-rejected case (impl-shape guidance):
`xdpmacfilter: XDP attach failed on '<iface>' (mode=<native|offload>): Operation not supported`.
The literal `mode=<requested-mode-name>` is recommended; tester does
NOT assert exact format. §6.17 asserts only `exit 3` + stderr
non-empty + stderr contains `native` (or `mode=native`).

#### Q3 decision — PERCPU stats test coverage = **Option F (fixture-level unit-shaped sum-correctness)**

**Choice**: add `T_PERCPU_STATS_SUM` (§6.18) — a deterministic
test that bypasses BPF traffic injection entirely and seeds known
per-CPU values directly into the `stats` map via `bpftool map update`,
then reads via the new `read_stats.py` and asserts the sum matches
the seeded total.

**Rationale**: Option F gives the cleanest diagnostic signal at the
lowest fixture complexity. Option D (defensive multi-CPU aggregation
via traffic injection) is flaky on single-CPU runners — requires
`taskset` or kernel rebalancer cooperation, both unreliable. Option I
(implicit — rely on T_PASS_ALLOWED) has poor diagnostic attribution
(BPF correctness conflated with sum-logic correctness). Option F seeds
known per-CPU values, asserts sum equality — failure signal is
unambiguous: "PERCPU sum logic is wrong".

Implementation hint (mechanism-only; tester picks exact bytes):
`nr_cpus=$(nproc --all); V=42; expected_sum=$(( nr_cpus * V ))`;
seed broadcast value `V` to all CPU slots via `bpftool map update`
(post-publication amendment 2026-05-23: bpftool CLI only supports
broadcast, not per-CPU distinct seeding — see §6.18 amendment for
full rationale); assert `read_stats.py` sum equals `expected_sum`.
Discriminator preserved on multi-CPU: silent CPU-0-only read returns
`V`, broadcast sum returns `nr_cpus * V`.

#### Public-API surface diff (`loader.hpp` relaxation)

This pass intentionally relaxes the MVP-2 Sec "loader.hpp
byte-identical" invariant. The diff:

**Addition 1** — new enum class declaration (inside `namespace xdpmf`,
above `struct AttachConfig`):

```cpp
enum class XdpMode : int {
    Generic = 0,   // XDP_FLAGS_SKB_MODE — MVP-1 default, universally supported
    Native  = 1,   // XDP_FLAGS_DRV_MODE — driver-native XDP, faster, hardware-dependent
    Offload = 2,   // XDP_FLAGS_HW_MODE  — NIC-offloaded XDP, rare hardware support
};
```

The underlying type is `int` (explicit) for stability across compilers
and to make the kernel-flags mapping trivial in `loader.cpp`. Values
0/1/2 are arbitrary; do NOT map them directly to XDP_FLAGS_* (the
mapping happens via a switch in `loader.cpp`'s anon namespace —
keeps the kernel-ABI coupling out of the public header).

**Addition 2** — new field on `struct AttachConfig`:

```cpp
struct AttachConfig {
    std::string iface;
    std::vector<xdpmf_mac> allow;
    XdpMode mode = XdpMode::Generic;   // NEW: default preserves MVP-1 SKB-only behaviour
};
```

`DetachConfig` is **unchanged** — per Q1 Option A, `detach` does not
accept `--mode`.

**No changes** to `attach()` / `detach()` function signatures, no new
`LoaderError` enumerator (per Q2 Option K — no new exit code), no
changes to `raii.hpp`.

**Reviewer's `loader.hpp`-invariant check** should accept a diff
containing exactly: one new `enum class XdpMode { … };` declaration
(~6 lines incl. comments), one new field initializer on `AttachConfig`
(`XdpMode mode = XdpMode::Generic;`, one line). Any other diff in
`loader.hpp` is out of spec for this pass.

**Rationale for relaxing the invariant**: the `--mode` CLI flag's
parsed value MUST cross the `cli.cpp → loader.cpp` boundary (the CLI
parser produces an `AttachConfig`; `loader.cpp` consumes it and
selects the kernel flags). The cleanest carrier is a field on
`AttachConfig`. A struct-field addition is the smallest surface change
consistent with the existing architecture (§5.21 A1: `AttachConfig`
is "the contract between `cli.cpp` → `loader.cpp`"). Recorded as a
deliberate relaxation; the invariant returns to "byte-identical" in
MVP-2 Robust / Polish-2 unless further design pressure emerges.

#### Impl surface (file:line targets, mirror to brief Scope items 1/2/3)

**Item 1 — PERCPU stats migration**:

| Where | Change |
|---|---|
| `src/bpf/mac_filter.bpf.c` (stats map declaration, ~lines 30-34) | `BPF_MAP_TYPE_ARRAY` → `BPF_MAP_TYPE_PERCPU_ARRAY`. Other fields unchanged (key_size=4, value_size=8, max_entries=3, pinning). |
| `src/bpf/mac_filter.bpf.c` `bump_stat` helper (~lines 41-44) | Verify `*v += 1` compiles and is correct for PERCPU. Per kernel docs: `bpf_map_lookup_elem` on a PERCPU_ARRAY returns a pointer to the **current CPU's** slot — `*v += 1` is now per-CPU local, no `__sync_fetch_and_add` needed. No code change expected; verify only. |
| `tests/lib/read_stats.py` | Update parser: bpftool's `--json` for PERCPU maps emits `value` as an array of per-CPU objects, e.g. `[{"cpu": 0, "value": 0x05}, {"cpu": 1, "value": 0x03}, …]` wrapped under `"values"` key per entry. Sum across CPUs per key: `sum(int(v["value"], 0) for v in slot["values"])` (or equivalent). |
| `src/common/mac_filter.h` | No change — the user-facing `enum mac_filter_stat` indices are unchanged; PERCPU is a kernel-side storage change. |
| `tests/lib/common.sh` `wait_for_stats_sum` helper | No change — already reads via `read_stats.py`; the sum semantics are now PERCPU-aware transparently. |

**Item 2 — `--mode {generic,native,offload}` CLI flag**:

| Where | Change |
|---|---|
| `src/loader/cli.cpp` (parser) | Add `--mode` long-option parsing for the `attach` subcommand. Accepts literal strings `generic`, `native`, `offload` (case-sensitive). Unknown value → exit 1 with stderr `"--mode: expected one of {generic, native, offload}, got '<X>'"`. Default if `--mode` omitted: `XdpMode::Generic`. For the `detach` subcommand: if `--mode` appears in argv, exit 1 with stderr `"detach: --mode is attach-only; mode is auto-detected from the attached program"`. |
| `src/loader/cli.hpp` | No new declarations (uses `XdpMode` from `loader.hpp`); update the `--help` text to include the `--mode` line for the `attach` subcommand. |
| `src/loader/loader.hpp` | Add `enum class XdpMode { Generic, Native, Offload };` (above `AttachConfig`). Add `XdpMode mode = XdpMode::Generic;` field on `AttachConfig`. See "Public-API surface diff" above. |
| `src/loader/loader.cpp` (attach call) | Replace hardcoded `XDP_FLAGS_SKB_MODE` at `bpf_xdp_attach` callsite with a switch on `cfg.mode` → `XDP_FLAGS_SKB_MODE` / `XDP_FLAGS_DRV_MODE` / `XDP_FLAGS_HW_MODE`. The switch lives in an anon-namespace helper `static int mode_to_flags(XdpMode m)`. |
| `src/loader/loader.cpp` (detach call) | Use `mode_to_flags(probe.mode)` instead of hardcoded `XDP_FLAGS_SKB_MODE`. Per Q1 Option A. |
| `src/loader/loader.cpp` (`is_ours` predicate) | Drop the `mode == SKB` clause; replace with `mode != NONE` (i.e. any of SKB/NATIVE/HW). Per Q1 Option A + §5.22 amendment above. |
| `src/loader/main.cpp` | Plumb the parsed `--mode` value through the `ParsedCommand` variant into the `attach()` call. No exit-code table change. |

**Item 3 — Tests** (per Q3 + Item 2):

| New test | §6.x | One-line summary |
|---|---|---|
| `T_MODE_GENERIC_DEFAULT` | §6.16 | `attach` without `--mode` defaults to generic (SKB); probe confirms SKB mode after attach |
| `T_MODE_NATIVE_UNSUPPORTED` | §6.17 | `attach --mode native --iface lo` → exit 3 (per Q2 Option K); lo doesn't support native XDP |
| `T_PERCPU_STATS_SUM` | §6.18 | Seed PERCPU `stats` map via `bpftool map update`, read via `read_stats.py`, assert sum == known total (Q3 Option F) |
| `T_MODE_DETACH_REJECTS` | §6.19 | `detach --mode native --iface ${IFACE_A}` → exit 1 + stderr substring `"--mode is attach-only"` (per Q1 Option A) |

**Edit to existing test**:

| Existing test | Edit |
|---|---|
| `tests/T_CLI_HELP_VERSION.sh` (§6.10) | Assertion grows: `--help` output must now contain the substring `--mode` (verifies the new flag is documented in the help text). |

No edits needed to §6.3–§6.8 (stats-touching tests) — `read_stats.py`
internally absorbs the PERCPU sum semantics; the outcome assertions
(`stats[…] == N`) stay byte-identical. No edits to §6.9
T_ATTACH_ALIEN_REFUSAL — the alien fixture stays in SKB mode (per
fixture's `xdpgeneric` attach); §6.9 exercises the name+tag axes,
not the mode axis.

#### Bpftool PERCPU JSON schema (architect-documented, impl reference)

For `BPF_MAP_TYPE_PERCPU_ARRAY`, `bpftool map dump --json pinned <path>`
returns an array of entries, each entry shaped like:

```json
[
  {
    "key": ["0x00","0x00","0x00","0x00"],
    "values": [
      {"cpu": 0, "value": ["0x05","0x00","0x00","0x00","0x00","0x00","0x00","0x00"]},
      {"cpu": 1, "value": ["0x03","0x00","0x00","0x00","0x00","0x00","0x00","0x00"]}
    ]
  }
]
```

Key differences from non-PERCPU schema: `"value"` field is replaced
by `"values"` (plural) — an array of per-CPU records. Each per-CPU
record has `"cpu"` (integer index) and `"value"` (byte array,
little-endian for native byte order). `read_stats.py` MUST iterate
`entry["values"]`, parse each `per_cpu["value"]` as a little-endian
u64 (8 bytes), and sum across all CPU entries for each `key`.

Stability note: this schema is libbpf 1.1+ stable per the bpftool
JSON contract. Project depends on libbpf ≥ 1.1 (per §5.21 B2). No
schema-version probe needed.

#### Performance characterization (architect-asserted, not tested)

- **Counter throughput**: PERCPU eliminates the cross-CPU race on the shared counter slot. On a multi-queue NIC with N RX queues, pre-§5.23 throughput is bounded by cache-line bouncing on the single shared slot (worst case: ~1 increment per cache-line transfer, often ~50 ns/transfer on modern x86 → ~20M increments/sec ceiling). Post-§5.23: each CPU writes its own slot, no contention.
- **Read latency**: `read_stats.py` now sums N values instead of reading 1. For N ≤ 256 (typical max CPU count), the sum is a few µs of Python work — negligible vs the `bpftool map dump` syscall overhead.
- **No new perf tests**: the brief explicitly does not request benchmark tests (perf characterization is documentary). T_PERCPU_STATS_SUM is correctness-only.

**Evidence**: `mint/hybrid-review.md` perf HIGH (PERCPU); perf MED
(SKB-mode hardcoded); sec MED M2 (alien-detection bypass via non-SKB,
detection-layer closed in §5.20, CLI surface now closed here);
`mint/task-brief.md` MVP-2 Perf (full brief). §5.3 + §5.6 supersede.
§5.22 is_ours predicate mode-axis amendment.

### 5.24 MVP-2 Robust: kernel-version probe + `T_VERIFIER_REJECT` (third MVP-2 pass, 2026-05-23) — amendment block

Append-only amendment closing the two remaining MVP-2 items deferred to
the Robust slice per §7 OOS (testing M7 in hybrid-review.md line 130):
(1) **kernel-version probe + `LoaderError::KernelUnsupported` (exit 7)**
— fast-fail with a clear error before any libbpf BPF_PROG_LOAD call
that would otherwise yield a cryptic `Invalid argument` from the deep
libbpf stack; (2) **`T_VERIFIER_REJECT`** — regression test asserting
the loader produces a clean error (not a crash, not silent success) on
a verifier-rejected program.

This is the **third MVP-2 pass** (seventh /mint cycle) and the
**smallest** of the MVP-2 slices: 1 impl item (the probe), 1 test
(verifier-reject regression). No BPF C changes. `loader.hpp` gains
**exactly one line** (`KernelUnsupported = 7,`) — same precedent as
§5.22 Q3's `PathRefused = 8`.

**Coverage delta**:

| Vector / problem | Pre-§5.24 status | Post-§5.24 status |
|---|---|---|
| Operator runs `xdpmacfilter` on a kernel too old → libbpf returns cryptic `BPF_PROG_LOAD: Invalid argument` from deep inside `bpf_object__load` | Open — operator sees a generic libbpf message; root-cause guesswork | Closed — `kernel_version_probe()` fires at the head of `attach()`/`detach()` and throws `LoaderError::KernelUnsupported` (exit 7) with stderr literal `xdpmacfilter: kernel <maj>.<min> too old, need ≥ 5.15` |
| Verifier-reject path silently passes or crashes — no regression coverage | Open — implicit reliance on `T_LOAD_ATTACH` happy-path | Closed — `T_VERIFIER_REJECT` (§6.20) loads a deliberately-bad `.bpf.o` fixture, asserts loader exits 2 (`LoadFailed`) with clear stderr; degrades gracefully (`SKIP_RETURN_CODE 77`) if fixture happens to load cleanly |
| README ↔ design.md kernel-floor inconsistency | Open — divergent docs | Closed — single floor **5.15** (per Q2). design.md `≥ 5.7` references at lines 765 and 2670 reworded to `≥ 5.15`. README stays |

#### Q1 decision — Detection mechanism = **Option U (uname syscall + version-string parse)**

**Choice**: `uname(2)` syscall, parse the `release` field's leading
`<major>.<minor>` numeric prefix, compare against floor constants
`kKernelFloorMajor = 5` and `kKernelFloorMinor = 15`. On parse failure
(defensive), fail closed → throw `LoaderError::KernelUnsupported`.

**Rationale**: one syscall, no libbpf API churn, well-trodden parse
pattern. Custom-backport edge case is rare; addressed via OOS fence +
future escape hatch if demand emerges. Option F (libbpf feature probe)
rejected: 5+ extra syscalls + libbpf probe API churn; cost-benefit
poor for our feature set. Option C (uname + BPF_PROG_LOAD trivial
probe) rejected: complexity + CAP_BPF mid-probe interaction. Option L
(lazy) rejected: defeats the brief's "replace cryptic libbpf message"
goal.

#### Q2 decision — Minimum kernel version floor = **5.15**

**Choice**: minimum kernel version is **5.15**. `kKernelFloorMajor = 5`,
`kKernelFloorMinor = 15`. README.md:22 already correct; design.md
references corrected in place (EDIT-7 + EDIT-8).

**Rationale**: matches LTS reality (Debian Bookworm, Ubuntu 22.04,
modern AlmaLinux/Rocky) + the README's existing claim. Includes BPF
verifier improvements + `bpf_loop()`. 5.7-5.14 is the "untested, may
work" gray zone — shipping "supported" against an untested band
invites unreproducible bug reports. 6.x rejected as unjustified by
current feature use.

#### Q3 decision — Probe call-site placement = **Option B (attach + detach, symmetric)**

**Choice**: probe fires at the head of BOTH `attach()` and `detach()`,
before ANY libbpf API call (in particular: before the §5.22 early
skeleton load step 2). Symmetric with the §5.22 detach() identity-gate
symmetry pattern.

**Impl flow** (per Q1 + Q3):

```
attach(cfg):
  0. kernel_version_probe()                  [§5.24 Q3: NEW step 0]
       — uname() → parse_major_minor() → compare floor
       — fail → throw LoaderError::KernelUnsupported (exit 7)
  1. resolve ifindex via if_nametoindex      [unchanged]
  2. open + load skeleton (BpfSkeleton RAII) [§5.22 early-load]
  3. self_tag capture                         [§5.22]
  4. open BpffsRootFd                         [§5.22 Q2]
  5. probe = probe_attached_xdp(...)          [§5.22 Q1]
  6. branch on §5.4 state                     [unchanged]
  ...

detach(iface):
  0. kernel_version_probe()                  [§5.24 Q3: NEW step 0]
       — same as attach
  1. resolve ifindex via if_nametoindex      [unchanged]
  2..6. same as §5.22 detach symmetry        [unchanged]
```

**Rationale**: §5.22 detach() symmetry already early-loads the
skeleton + captures self_tag — detach() ALREADY consumes the BPF
features the probe gates. Skipping the probe in detach makes the
detach side fail with the same cryptic libbpf error attach was
protected against. Option A (attach only) rejected for asymmetry.
Option O (once-per-process via static) rejected as essentially
never the hot path (loader is short-lived).

#### Q4 decision — `T_VERIFIER_REJECT` mechanism = **Option (c) Hybrid (active fixture + `SKIP_RETURN_CODE 77` fallback)**

**Choice**: build `tests/fixtures/mac_filter_bad.bpf.c` with deliberate
verifier violation (unbounded loop without `#pragma unroll` — verifier-universal reject for 5.15+). Test:
- **SKIP probe first**: standalone `bpftool prog load` on the bad
  fixture. If exits 0 → verifier accepted on this kernel → SKIP (exit
  77). If non-zero → expected, proceed.
- **Active branch**: invoke `xdpmacfilter attach` with `XDPMF_BPF_OBJECT_PATH`
  env-var override pointing at the bad fixture; assert exit **2**
  (`LoadFailed`) + recognizable stderr substring.

**Fixture-path override** = env var `XDPMF_BPF_OBJECT_PATH` (Option (i),
NOT CLI flag). Loader: if env var set + non-empty, use that path
instead of compiled-in default. ~3 lines impl, symmetric in
`attach()`/`detach()`. Testing-only mechanism; undocumented in `--help`
per §7 Robust OOS.

**Rationale**: Option (a) pure-active rejected because a future kernel
verifier silently accepting our violation produces a confusing false
fail. Option (b) pure-passive rejected because the test ASSERTS NOTHING
about the loader's verifier-reject error path — name "T_VERIFIER_REJECT"
becomes dishonest. Option (c) actively tests the path on the common
case AND degrades gracefully — best of both.

**Fallback violation pattern**: if unbounded loop unexpectedly verifies
clean on some kernel, tester swaps to OOB-deref backup pattern
(verifier-universal for all 5.15+); manual fixture update, not
runtime auto-switch (preserves test reproducibility).

#### Impl surface summary

**`src/loader/loader.hpp`** — exactly ONE new line (`KernelUnsupported = 7,`
between `Permission = 6,` and `PathRefused = 8,`). Reviewer's
`loader.hpp` invariant check MUST accept a single-line `git diff`
confined to the enum body.

**`src/loader/loader.cpp`** (anon-namespace additions):
- Floor constants: `constexpr int kKernelFloorMajor = 5;` + `constexpr int kKernelFloorMinor = 15;`.
- `parse_major_minor(const char* release, int* out_major, int* out_minor) noexcept -> bool` — parses leading `<major>.<minor>` of utsname.release. Accepts `5.15.0`, `5.15.0-100-generic`, `6.1.0-rc4+`, `5.15` (no patch level), etc. Rejects: null, non-digit first char, missing `.`, no digits after `.`, integer overflow.
- `kernel_version_probe()` — `void`, throws `LoaderError::KernelUnsupported`:
  1. `uname(&u)` — on EAGAIN/EFAULT → throw with `strerror(errno)`.
  2. `parse_major_minor(u.release, &maj, &min)` — on false → throw with `unable to parse kernel release '<raw>'`.
  3. `std::pair{maj,min} < std::pair{kKernelFloorMajor, kKernelFloorMinor}` → throw with `kernel <maj>.<min> too old, need ≥ 5.15`.
- **Invocation**: `kernel_version_probe();` as FIRST statement of `attach()` AND `detach()`, BEFORE `if_nametoindex`.
- **Env-var fixture-path override** (Q4): `const char* env_path = std::getenv("XDPMF_BPF_OBJECT_PATH"); const char* obj_path = (env_path && *env_path) ? env_path : nullptr;` near skeleton open. If non-null, pass to libbpf open call. Default behaviour byte-identical to pre-§5.24. Symmetric in attach()/detach().
- **Headers**: `#include <sys/utsname.h>`, `#include <cstdlib>`, `#include <utility>`.

**`tests/fixtures/mac_filter_bad.bpf.c`** (NEW): unbounded-loop violation. Must clang-compile cleanly; verifier rejects only at `bpf()`-syscall load time. Wired via existing `add_bpf_object` pattern.

**`tests/T_VERIFIER_REJECT.sh`** (NEW): per §6.20.

**`tests/CMakeLists.txt`**: 1 new `add_bpf_object(mac_filter_bad …)` + 1 new `add_test` entry per §6.20 ctest properties.

**`README.md`**: NO change (already says `kernel ≥ 5.15` — Q2 aligns to existing).

#### Stderr discipline contract (load-bearing for §6.20)

The probe's stderr message MUST contain ALL of: `kernel`, `too old`,
running `<maj>.<min>`, floor `5.15` (or `≥ 5.15`), program name
`xdpmacfilter`. Recommended exact format: `xdpmacfilter: kernel
<maj>.<min> too old, need ≥ 5.15`. Impl picks exact wording; reviewer
asserts substring presence.

#### Threat-model boundary

The probe is **not** a security mechanism — it's operator-UX
(replacing cryptic libbpf errors). An attacker with root can do
anything; an attacker without root cannot manipulate `uname()`.
Audit-clarity improvement, not defence layer.

#### Performance

One additional `uname(2)` syscall per `attach()`/`detach()`
(~microseconds). Below noise floor.

#### Constraint relaxation justification

`loader.hpp` byte-identical invariant relaxes by exactly one line
(`KernelUnsupported = 7,`). No new functions, no new types, no new
top-level symbols, no ABI break. Same precedent as §5.22 Q3's
`PathRefused = 8`. After this addition the enum is contiguous-from-2
(`{2,3,4,5,6,7,8}`); exit-code table fully populated through 8.

Evidence: `mint/hybrid-review.md` line 130 (testing M7);
`mint/task-brief.md` MVP-2 Robust items 1+2; §5.22 Q3 / §5.23
precedent for one-enumerator additions to `LoaderError`.

## 6. TestStrategy

Test fixture (per `test/bpf-xdp.md` pack — exact mechanism is tester's
choice but **direction semantics below are mandatory**):

- Two veth endpoints, `veth_a` and `veth_b`, peered.
- **XDP attaches to `veth_a`** (the "filter side").
- **Frames are INJECTED on `veth_b`** (the "sender side"); they arrive
  at `veth_a` RX path, where the XDP program runs.
- **Stats are OBSERVED on `veth_a` side** by reading the pinned map at
  `/sys/fs/bpf/xdpmacfilter/veth_a/stats`.
- Whether `veth_a`/`veth_b` are in separate netns or the same netns is
  tester's choice (separate netns is recommended to avoid kernel
  local-delivery shortcuts), but the injection→observation direction
  above is fixed.

**Post-§5.21 C3 note**: `veth_a`/`veth_b` literals throughout §6 are
read as `${IFACE_A}`/`${IFACE_B}` (PID-suffixed `xdpmf_a_$$`/`xdpmf_b_$$`)
in actual test invocations. Bpffs pin paths follow:
`/sys/fs/bpf/xdpmacfilter/${IFACE_A}/…`. The fixed names retained in
§6 prose are for narrative consistency only.

MAC constants for tests:
- `MAC_GOOD = 02:00:00:00:00:01` (locally-administered, unicast)
- `MAC_BAD  = 02:00:00:00:00:02`
- All test frames use `MAC_DST = ff:ff:ff:ff:ff:ff` (broadcast) for
  destination; filter ignores destination per spec.

Each test below specifies: **trigger** / **observable outcome** /
**assertion mechanism**. Tester implements; tester does NOT need to read
impl source to write these.

### 6.1 T_BUILD — build cleanliness (acceptance #1)
- **Trigger**: `cmake -S . -B build && cmake --build build` from clean tree.
- **Outcome**: exit 0, zero warnings on stderr from clang/clang++.
- **Mechanism**: ctest `add_test(BUILD ...)` or shell wrapper checking
  exit code AND grepping build log for `warning:` (must be zero matches).

### 6.2 T_LOAD_ATTACH — load+attach succeeds (acceptance #2)
- **Trigger**: setup veth pair; `xdpmacfilter attach --iface veth_a
  --allow 02:00:00:00:00:01`.
- **Outcome**: exit 0; `ip -j link show veth_a` JSON contains
  non-null `xdp.prog.id`; `/sys/fs/bpf/xdpmacfilter/veth_a/{allowlist,stats}`
  exist.
- **Mechanism**: shell assertions on exit code + `ip -j` parse + `test
  -e` on pin paths.
- **Cleanup**: `xdpmacfilter detach --iface veth_a`.

### 6.3 T_PASS_ALLOWED — allowed source MAC passes (acceptance #3)
- **Setup**: attach with allow-list = `{MAC_GOOD}`.
- **Trigger**: inject 1 Ethernet frame on `veth_b` with `src=MAC_GOOD,
  dst=MAC_DST`, payload arbitrary (e.g. 46-byte zero-fill so total ≥
  60). Wait for quiescence (tester chooses delay, e.g. 100 ms).
- **Outcome**: `stats[STAT_PASS] == 1` AND `stats[STAT_DROP_DENY] == 0`
  AND `stats[STAT_DROP_MALFORMED] == 0`.
- **Mechanism**: `bpftool map dump pinned /sys/fs/bpf/xdpmacfilter/veth_a/stats`
  → parse → exact-equality assertion on all three slots.

### 6.4 T_DROP_DENY — disallowed source MAC dropped (acceptance #4)
- **Setup**: attach with allow-list = `{MAC_GOOD}`.
- **Trigger**: inject 1 frame on `veth_b` with `src=MAC_BAD,
  dst=MAC_DST`.
- **Outcome**: `stats[STAT_DROP_DENY] == 1` AND `stats[STAT_PASS] == 0`
  AND `stats[STAT_DROP_MALFORMED] == 0`.
- **Mechanism**: same as 6.3.

### 6.5 T_DROP_MALFORMED — truncated frame dropped (acceptance #5)
- **Setup**: attach with allow-list = `{MAC_GOOD}` (content irrelevant).
- **Trigger**: inject a frame with total Ethernet length < 14 bytes
  (e.g. 13-byte raw buffer via `AF_PACKET SOCK_RAW`). Tester note:
  kernel may pad short frames; ensure the injection mechanism delivers a
  genuinely sub-14-byte `xdp_md` data range — `AF_PACKET` with
  `ETH_P_ALL` and manual byte-count is the recommended path.
- **Outcome**: `stats[STAT_DROP_MALFORMED] == 1` AND `stats[STAT_PASS]
  == 0` AND `stats[STAT_DROP_DENY] == 0`.
- **Mechanism**: same as 6.3.
- **Note**: if the test environment cannot reliably deliver sub-14-byte
  frames to XDP (kernel padding interferes), tester reports the
  limitation and the test is marked SKIP with explicit reason — NOT
  silently merged with T_DROP_DENY. The malformed counter MUST still
  exist and be readable (assertable separately).

### 6.6 T_IDEMPOTENT_RELOAD — no leaked kernel objects (acceptance #6)
- **Trigger** (sequential):
  1. `baseline_count = bpftool prog show | wc -l`
  2. `xdpmacfilter attach --iface veth_a --allow MAC_GOOD` (exit 0)
  3. `xdpmacfilter attach --iface veth_a --allow MAC_GOOD` (exit 0 — second attach detects ours and replaces)
  4. `xdpmacfilter detach --iface veth_a` (exit 0)
  5. `final_count = bpftool prog show | wc -l`
- **Outcome**: `final_count == baseline_count` AND
  `/sys/fs/bpf/xdpmacfilter/veth_a/` does not exist AND
  `ip -j link show veth_a` shows no XDP attached.
- **Mechanism**: shell arithmetic assertion + `test ! -e` + `ip -j` parse.
- **Sub-variant** (alien-program refusal, design §5.4): attach an
  unrelated minimal XDP program to `veth_a` via raw `ip link set veth_a
  xdpgeneric obj <foreign.o> sec xdp` (tester provides a trivial pass-all
  BPF blob, or uses `xdp-loader` if available); then run `xdpmacfilter
  attach --iface veth_a --allow MAC_GOOD` → expect **exit code 4**,
  stderr contains the foreign prog id, veth_a XDP slot unchanged. This
  sub-variant is OPTIONAL for MVP-1 (it tests Decision §5.4) but
  recommended. **MVP-1.1B note**: this sub-variant has been promoted
  to a standalone first-class test — see §6.9 `T_ATTACH_ALIEN_REFUSAL`,
  with vendored foreign-XDP fixture and stronger assertion set. The
  "OPTIONAL" framing here is superseded by §6.9.
- **MVP-1.1C amendment** (per §5.21 C4): steps 1 and 5 (the
  `baseline_count`/`final_count` global prog-count) are **dropped** —
  the `final_count == baseline_count` clause in Outcome is **removed**.
  Surviving outcome: "post-step-4 `xdp_prog_id ${IFACE_A}` returns empty
  AND `/sys/fs/bpf/xdpmacfilter/${IFACE_A}/` does not exist AND
  `ip -j link show ${IFACE_A}` shows no XDP attached". See the
  "Cross-cutting note" at the tail of §6.13.

### 6.7 T_NEGATION_CONTROL — proves test suite isn't a no-op (acceptance #7)
- **Construction**: a copy of T_DROP_DENY with the assertion inverted —
  asserts `stats[STAT_PASS] == 1` (which it WILL NOT be, since
  `MAC_BAD` is denied).
- **Outcome**: this test MUST FAIL when run.
- **Mechanism**: ctest `set_tests_properties(T_NEGATION_CONTROL
  PROPERTIES WILL_FAIL TRUE)` — ctest interprets actual failure as test
  pass for this entry, actual pass as test failure. If anyone breaks
  XDP and lets all frames pass, T_NEGATION_CONTROL flips and the suite
  catches the regression.

### 6.8 T_SANITIZER_BUILD — userspace memory-safety smoke (per §5.18, MVP-1.1A)
- **Setup** (one-shot, inside the test): use a fresh, isolated build
  directory disjoint from the default `build/` so the default build is
  untouched. Recommended: `BUILD_DIR=$(mktemp -d /tmp/xdpmf-asan-XXXXXX)`.
- **Trigger** (sequential):
  1. `cmake -S <repo_root> -B "$BUILD_DIR" -DXDPMF_SANITIZERS=ON`
     (default generator; `-DCMAKE_BUILD_TYPE` left to impl/tester —
     `Debug` or `RelWithDebInfo` for symbolized ASAN reports is fine).
  2. `cmake --build "$BUILD_DIR" --parallel` — MUST exit 0 and produce
     the `xdpmacfilter` binary somewhere under `"$BUILD_DIR"` at the
     same relative path the default build produces it (tester resolves
     via a small `find` or the known path).
  3. Set up the standard veth fixture (`veth_a`/`veth_b`, separate
     netns per the existing test convention).
  4. Run the sanitized binary:
     `<sanitized_xdpmacfilter> attach --iface veth_a --allow 02:00:00:00:00:01`
     — capture stderr to a file.
  5. Inject one Ethernet frame on `veth_b` with `src=MAC_GOOD,
     dst=MAC_DST` (reuse the existing inject helper, same mechanism as
     §6.3).
  6. Read `stats` from the pinned map (reuse the existing read helper).
  7. Run the sanitized binary:
     `<sanitized_xdpmacfilter> detach --iface veth_a` — capture stderr.
  8. Tear down the veth fixture.
- **Outcome** (ALL must hold):
  - Step 2 (build) exits 0 with no compiler warnings (per §5.12 policy;
    if a warning escapes, it is a real failure, not a test-suite issue).
  - Steps 4 and 7 (attach/detach) exit 0.
  - `stats[STAT_PASS] == 1` — positive correctness check confirming the
    sanitized binary actually executed the BPF-userspace hot path, not
    just exited cleanly without doing work.
  - Captured stderr from steps 4 and 7 contains **zero** lines matching
    the ERE `AddressSanitizer|UndefinedBehavior` (case-sensitive). Either
    token appearing — including in a "SUMMARY" line — fails the test,
    because a clean sanitizer run prints nothing to stderr from the
    sanitizer runtime.
- **Assertion mechanism** (concrete):
  - Exit-code: shell `[[ $? -eq 0 ]]` after each step.
  - Stats: `bpftool map dump pinned /sys/fs/bpf/xdpmacfilter/veth_a/stats`
    → parse → exact-equality `STAT_PASS == 1` (other slots not asserted
    in this test — they are covered by §6.3–6.5).
  - Sanitizer report: `grep -q -E 'AddressSanitizer|UndefinedBehavior'
    "$stderr_file" && exit 1`. **Negation form**: a regex match means
    the test fails.
- **Ctest properties**:
  - `TIMEOUT` ≥ 120 s — CMake configure + clean build of the sanitizer
    target dominates the runtime; allow headroom for slow/CI hosts.
  - `RESOURCE_LOCK xdp_fixture` — serializes against other veth-using
    tests (same lock name as §6.3–6.5 and §6.6).
  - Tester is free to add a label (e.g. `sanitizer`) for optional
    filtering, but the default `ctest --test-dir build` run MUST
    include this entry (per brief acceptance #8).
- **Cleanup**: `trap 'rm -rf "$BUILD_DIR"; ...' EXIT` (mirrors the
  existing `T_BUILD.sh` trap pattern). Veth/netns teardown reuses the
  existing fixture helpers.
- **Pre-existing tests are NOT modified** — this is purely additive;
  the 7 MVP-1 tests remain byte-identical to before MVP-1.1A. This is
  itself an assertion of the refactor-mode contract (brief acceptance
  #9).
- **Negation control NOT required** — per brief note for tester: the
  suite-level sanity floor was satisfied in MVP-1 by §6.7
  `T_NEGATION_CONTROL`; this additive pass does not need its own.

### 6.9 T_ATTACH_ALIEN_REFUSAL — alien-XDP refusal exit-code-4 reachable end-to-end (per §5.4 + §5.19, MVP-1.1B)
Closes hybrid-review.md testing MEDIUM **M1**: the exit-4 path
(`AttachRefusedAlien`, §5.4 state c) was untested end-to-end pre
MVP-1.1B (the §6.6 sub-variant was OPTIONAL and never implemented).
This test proves the code path is reachable from a real fixture, not
just theoretically present, AND that the §5.19 identity verification
correctly classifies a foreign program as alien even when the foreign
program is in our same SKB mode (the mode-axis case is also exercised
implicitly by the all-modes probe of §5.20).

- **Foreign-XDP fixture** (vendored in-tree, new MVP-1.1B):
  `tests/fixtures/xdp_pass.bpf.c` — ~15 LOC: includes `"vmlinux.h"`
  and `<bpf/bpf_helpers.h>`, declares `char LICENSE[] SEC("license") =
  "GPL";`, and one program `SEC("xdp") int xdp_pass_prog(struct xdp_md
  *ctx) { return XDP_PASS; }`. The function name MUST be
  `xdp_pass_prog` (or any literal name that is NOT `mac_filter_prog`)
  — this is the load-bearing differentiator: `bpf_prog_info.name` will
  report `xdp_pass_prog`, the §5.19 identity check compares to
  `mac_filter_prog`, and the mismatch drives the alien classification.
  Build wiring: `tests/CMakeLists.txt` adds one line invoking the
  existing helper `add_bpf_object(xdp_pass
  ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/xdp_pass.bpf.c)` (defined at
  `cmake/BpfBuild.cmake:25` and already used for
  `src/bpf/mac_filter.bpf.c`). Output: `${CMAKE_BINARY_DIR}/xdp_pass.bpf.o`.
  The §5.18 sanitizer-isolation invariant
  (`cmake/BpfBuild.cmake:14-24`) applies — the BPF object never
  receives `-fsanitize=`. No skeleton generation is needed (the
  fixture is loaded via `ip link` or `bpftool`, never opened by C++
  code).

- **Setup**: standard veth fixture (`setup_veth` from
  `tests/lib/common.sh`, same as §6.3–§6.8) — `veth_a` is the filter
  side, `veth_b` the sender side. Take `RESOURCE_LOCK xdp_fixture`
  (same lock as 6.3–6.6, 6.8).

- **Trigger** (sequential):
  1. `setup_veth` (creates `veth_a`/`veth_b`, both UP, quiesced).
  2. Pre-attach the foreign XDP to `veth_a` in generic (SKB) mode
     (same mode family as our loader uses, exercising the
     identity-check path rather than the mode-mismatch path):
     `sudo ip link set veth_a xdpgeneric obj
     "${BUILD_DIR}/xdp_pass.bpf.o" sec xdp`.
     **Equivalent alternative** (tester's choice, document which is
     used in script comment): `sudo bpftool prog load
     "${BUILD_DIR}/xdp_pass.bpf.o" /sys/fs/bpf/xdp_pass_tmp` + `sudo
     bpftool net attach xdpgeneric pinned /sys/fs/bpf/xdp_pass_tmp
     dev veth_a` (and a corresponding `rm -f
     /sys/fs/bpf/xdp_pass_tmp` in cleanup).
  3. Capture the foreign prog id: `foreign_id=$(xdp_prog_id veth_a)`
     (helper from `tests/lib/common.sh:115-121`). MUST be a non-empty
     non-zero integer; if empty, the foreign-attach step (2) failed
     and the test exits 1 with explicit error before invoking our
     loader (don't blame our loader for the fixture's failure).
  4. Run our loader, capturing both exit code and stderr:
     `set +e; sudo "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow
     "${MAC_GOOD}" 2> "${stderr_file}"; rc=$?; set -e`.

- **Outcome** (ALL four must hold — any single failure fails the test):
  - **rc == 4** — exit code matches `LoaderError::AttachRefusedAlien`
    per §4.1 exit table. (rc == 3 means KC-B fix didn't land
    correctly: the SKB-mode foreign prog was detected, but the
    classification logic threw `AttachFailed` instead of
    `AttachRefusedAlien`. rc == 0 means KC-A fix didn't land
    correctly: the loader detached the foreign prog and replaced it
    with ours — the spoofed-ours blackhole this test exists to
    prevent. Either is a hard fail.)
  - **stderr contains the foreign prog id as substring**:
    `grep -q -F -- "${foreign_id}" "${stderr_file}"` (`-F` for literal
    match since the id is a bare integer; `--` end-of-options for
    safety). Per §5.19 the message format includes the prog id,
    mode, and name — only the prog id is asserted here (the mode/name
    strings are impl-shape, not contract-shape).
  - **Foreign program STILL attached**, byte-identical id:
    `[[ "$(xdp_prog_id ${IFACE_A})" == "${foreign_id}" ]]`. This is
    the **safety floor** assertion — confirms the loader did NOT
    clobber the alien program (KC-A spoofed-ours blackhole scenario).
  - **No orphan pin dir** on `veth_a`:
    `[[ ! -e "${PIN_DIR}" ]]` (helper at `tests/lib/common.sh:26`).
    The loader's refusal happens before `ensure_bpffs_dir`, OR the
    RAII rollback unwinds cleanly — either way no
    `/sys/fs/bpf/xdpmacfilter/veth_a/` should remain post-attempt.

- **Assertion mechanism** (concrete):
  - Exit code: `[[ "${rc}" == 4 ]] || { echo "FAIL: expected rc=4,
    got ${rc}" >&2; fail=1; }`.
  - Stderr substring: `grep -q -F -- "${foreign_id}" "${stderr_file}"
    || { echo "FAIL: foreign id ${foreign_id} not in stderr" >&2;
    fail=1; }`.
  - Foreign still attached: `now=$(xdp_prog_id ${IFACE_A}); [[
    "${now}" == "${foreign_id}" ]] || { echo "FAIL: foreign clobbered
    (was ${foreign_id}, now ${now})" >&2; fail=1; }`.
  - No orphan pin dir: `[[ ! -e "${PIN_DIR}" ]] || { echo "FAIL:
    orphan ${PIN_DIR} remained" >&2; fail=1; }`.
  - Pattern mirrors `tests/T_IDEMPOTENT_RELOAD.sh` `fail=0` aggregator
    + final `exit "${fail}"`.

- **Cleanup** (trap on EXIT, idempotent):
  - Detach foreign prog: `sudo ip link set "${IFACE_A}" xdpgeneric
    off 2>/dev/null || true`. (If the alternative `bpftool` path was
    used: also `sudo bpftool net detach xdpgeneric dev "${IFACE_A}"
    2>/dev/null || true; sudo rm -f /sys/fs/bpf/xdp_pass_tmp`.)
  - `cleanup_veth` (existing helper) — wipes veth + any pin dir.
  - Remove stderr capture file: `rm -f "${stderr_file}"`.

- **Ctest properties**:
  - `TIMEOUT 60` — same floor as §6.3–§6.6 (no fresh cmake configure,
    no asan build; one foreign attach + one loader run + cleanup).
  - `RESOURCE_LOCK xdp_fixture` — serializes against §6.3–§6.6, §6.8.
  - **No** `SKIP_RETURN_CODE` — if `xdp_pass.bpf.o` is missing or
    `ip link set xdpgeneric` fails (kernel doesn't support generic
    XDP — extremely unlikely on supported kernels), the test SHOULD
    fail loudly, not silently skip. The fixture is universally
    available where the rest of the suite runs.
  - **No** `WILL_FAIL` — this is a positive-outcome test; success
    means `rc == 4` was correctly observed and the four assertions
    held.
  - Tester registers in `tests/CMakeLists.txt` either by appending
    `T_ATTACH_ALIEN_REFUSAL` to the existing veth-fixture `foreach`
    list at `tests/CMakeLists.txt:29-47` (cleanest — inherits ENV,
    RESOURCE_LOCK, TIMEOUT properties automatically) OR as a separate
    `add_test` block mirroring the T_SANITIZER_BUILD pattern at
    `tests/CMakeLists.txt:68-77`. Tester's choice; the `foreach`
    extension is recommended for symmetry with §6.3–§6.6.

- **Pre-existing tests are NOT modified** — this is purely additive
  (brief acceptance #7). The 8 MVP-1/1A tests remain byte-identical.

- **Negation control NOT required** — `T_NEGATION_CONTROL` (§6.7)
  remains the suite-level floor; this test's own positive/negative
  symmetry (assert exit 4 AND assert foreign-not-clobbered) is
  internal sanity, not a substitute for §6.7.

### 6.10 T_CLI_HELP_VERSION — help/version exit cleanly (per §5.21 D1, MVP-1.1C)
- **Setup**: none. Pure binary-invocation test; no veth, no root, no
  kernel call. Does NOT need `require_passwordless_sudo`.
- **Trigger** (two sub-cases, both must pass):
  1. `${LOADER_BIN} --help` → capture stdout, capture exit code.
  2. `${LOADER_BIN} --version` → capture stdout, capture exit code.
- **Outcome**:
  - Sub-case 1: exit 0; stdout non-empty; stdout contains literal
    substring `Usage:`; stdout contains literal substring `attach`;
    stdout contains literal substring `detach`.
  - Sub-case 2: exit 0; stdout is a single non-empty line (allowing
    optional trailing newline); contains literal substring
    `xdpmacfilter`; matches ERE `[0-9]+\.[0-9]+\.[0-9]+` (semver-shaped
    version token anywhere in the line).
- **Assertion mechanism** (concrete):
  - Exit per sub-case: `set +e; "${LOADER_BIN}" --help >"$stdout_file"
    2>&1; rc=$?; set -e; [[ $rc -eq 0 ]] || fail=1`.
  - Stdout content (sub-case 1): `grep -q -F -- 'Usage:' "$stdout_file"
    && grep -q -F -- 'attach' "$stdout_file" && grep -q -F -- 'detach'
    "$stdout_file"`.
  - Stdout content (sub-case 2): `grep -q -F -- 'xdpmacfilter'
    "$stdout_file" && grep -qE '[0-9]+\.[0-9]+\.[0-9]+' "$stdout_file"`.
  - Sub-case 2 line count: `[[ "$(wc -l < "$stdout_file")" -le 1 ]]`
    (tolerates 0 newlines if impl uses `fputs` without `\n`; the
    assertion is "single line", not "exactly one `\n`").
  - Aggregator pattern: `fail=0` accumulator over both sub-cases,
    final `exit "$fail"`.
- **Ctest properties**: `TIMEOUT 10` (binary launch + parse only).
  No `RESOURCE_LOCK` (no shared kernel/fixture state). No
  `SKIP_RETURN_CODE` (no sudo needed).
- **Why**: locks the contract that `--help`/`--version` exit cleanly
  without touching the kernel. Trivially exercised by users in the
  wild, untested by any pre-MVP-1.1C ctest.

### 6.11 T_CLI_CAPACITY — allow-list overflow rejected (per §5.21 D2, MVP-1.1C)
- **Setup**: none (no veth, no root, no kernel call — error happens in
  the CLI parser before any libbpf call). Does NOT need
  `require_passwordless_sudo`.
- **Trigger**: invoke `${LOADER_BIN} attach --iface lo --allow <list>`
  where `<list>` contains **65 distinct MACs** (one more than
  `XDPMF_ALLOWLIST_MAX = 64` per §3.3). Helper to generate the list
  (bash, in-test): `list=$(for i in $(seq 0 64); do printf
  '02:00:00:00:%02x:%02x,' $(( i / 256 )) $(( i % 256 )); done | sed
  's/,$//')`. Either single-flag comma-separated or repeated-flag form
  is acceptable per §4.1.
- **Outcome**:
  - Exit code = **1** (per §4.1: "CLI usage error" — the
    `XDPMF_ALLOWLIST_MAX` check at `cli.cpp:121-123` throws `CliError`,
    which `main.cpp:58-62` maps to `kExitUsageErr` = 1).
  - Stderr contains the literal substring `too many --allow entries`
    (the format-string in `cli.cpp:122-123`; the `(max 64)` tail is
    impl-shape and is NOT asserted).
  - No kernel side-effect: `xdp_prog_id lo` returns empty AFTER the
    invocation (sanity floor — proves we never reached the attach
    path). Pre-check optional but recommended.
- **Assertion mechanism**:
  - Exit: `set +e; "${LOADER_BIN}" attach --iface lo --allow "$list"
    2> "$stderr_file"; rc=$?; set -e; [[ $rc -eq 1 ]] || fail=1`.
  - Stderr substring: `grep -q -F -- 'too many --allow entries'
    "$stderr_file" || fail=1`.
  - No-side-effect: `[[ -z "$(xdp_prog_id lo 2>/dev/null)" ]] ||
    fail=1`.
- **Ctest properties**: `TIMEOUT 10`. No `RESOURCE_LOCK`. No
  `SKIP_RETURN_CODE`.
- **Why**: the capacity-limit branch in `cli.cpp:121-123` is untested
  by any pre-MVP-1.1C ctest. Regression in the bounds check would
  silently let oversized allow-lists through (the BPF verifier might
  still catch the map-overflow at runtime but the contract is "parser
  rejects" — that is the stronger guarantee we lock here).

### 6.12 T_CLI_BAD_MAC — malformed MAC rejected (per §5.21 D3, MVP-1.1C)
- **Setup**: none (parser-only failure, no kernel call). Does NOT need
  `require_passwordless_sudo`.
- **Trigger** (four sub-cases, all four must fail with exit 1):
  1. `${LOADER_BIN} attach --iface lo --allow not-a-mac` (totally
     malformed).
  2. `${LOADER_BIN} attach --iface lo --allow gg:gg:gg:gg:gg:gg` (right
     shape, non-hex octets).
  3. `${LOADER_BIN} attach --iface lo --allow 01:02:03:04:05` (too few
     octets — 5 instead of 6).
  4. `${LOADER_BIN} attach --iface lo --allow 01:02:03:04:05:06:07` (too
     many octets — 7 instead of 6).
- **Outcome** (per sub-case):
  - Exit code = **1** (CLI usage error per §4.1; tokenizer error path
    throws `CliError` → `kExitUsageErr`).
  - Stderr contains a recognizable malformed-MAC token: the substring
    `mac` (case-insensitive grep `-i`) appearing anywhere in stderr —
    the exact wording is impl-shape (could be "invalid MAC", "malformed
    MAC address", "bad MAC token"); assertion stays loose on wording
    but firm on the token.
- **Assertion mechanism** (per sub-case, in a loop over the 4 bad-MAC
  strings):
  - Exit: `set +e; "${LOADER_BIN}" attach --iface lo --allow "$bad" 2>
    "$stderr_file"; rc=$?; set -e; [[ $rc -eq 1 ]] || fail=1`.
  - Stderr: `grep -qi -- 'mac' "$stderr_file" || fail=1`.
  - Aggregator pattern mirrors §6.9: `fail=0` accumulator over the 4
    sub-cases, final `exit "$fail"`.
- **Ctest properties**: `TIMEOUT 10`. No `RESOURCE_LOCK`. No
  `SKIP_RETURN_CODE`.
- **Why**: the tokenizer error path in `cli.cpp` is uncovered by any
  pre-MVP-1.1C ctest. Four sub-cases sweep the realistic malformed-MAC
  variety (non-hex chars, short, long, totally non-MAC) and lock the
  contract that all four produce CLI error + recognizable stderr.

### 6.13 T_DETACH_NOTHING — detach is idempotent on clean iface (per §5.21 D4 + §5.4 amendment, MVP-1.1C)
- **Setup**:
  - `require_passwordless_sudo` (per brief Note — the call reaches
    `bpf_xdp_query_id`/`bpf_xdp_query` which needs root or CAP_BPF;
    missing privilege → SKIP 77, not fail).
  - Assert preconditions: `xdp_prog_id lo` returns empty AND `[[ ! -e
    /sys/fs/bpf/xdpmacfilter/lo ]]`. (If `lo` has somehow accumulated
    XDP/pin state from a previous run, abort early with explicit error
    — fixture is dirty, do not blame the loader.) Test uses `lo` per
    brief, NOT a veth fixture (no fixture setup/teardown cost).
- **Trigger**: `sudo -n "${LOADER_BIN}" detach --iface lo` → capture
  stdout, stderr, exit code.
- **Outcome**:
  - Exit code = **0** (per §5.21 D4 detach-idempotency amendment to
    §5.4: state (a) in `detach()` — no prog AND no pin_dir — returns
    0).
  - Stderr does NOT contain the literal substring `error:`
    (case-sensitive — matches the `error: ` prefix the loader/main
    use for thrown errors at `main.cpp:59`). Empty stderr is fine;
    informational lines without an `error:` prefix are fine.
  - No new kernel side-effect: `xdp_prog_id lo` still returns empty
    post-call; `/sys/fs/bpf/xdpmacfilter/lo` still does not exist.
- **Assertion mechanism**:
  - Exit: `set +e; sudo -n "${LOADER_BIN}" detach --iface lo 2>
    "$stderr_file" > "$stdout_file"; rc=$?; set -e; [[ $rc -eq 0 ]]
    || fail=1`.
  - Stderr: `! grep -q -F -- 'error:' "$stderr_file" || fail=1`.
  - Post-state: `[[ -z "$(xdp_prog_id lo 2>/dev/null)" ]] || fail=1`
    AND `[[ ! -e /sys/fs/bpf/xdpmacfilter/lo ]] || fail=1`.
  - Aggregator pattern: `fail=0` + final `exit "$fail"`.
- **Ctest properties**: `TIMEOUT 10`. **Post-§5.22 amendment**:
  add `RESOURCE_LOCK xdp_fixture` to this entry so it serializes
  against the new `T_BPFFS_ROOT_SYMLINK` (§6.15) — that test
  destructively corrupts `/sys/fs/bpf/xdpmacfilter` for its duration,
  and a concurrent T_DETACH_NOTHING would either trip the new
  `PathRefused` exit 8 (failure) or observe a wrong post-state.
  Pre-§5.22 this entry took no RESOURCE_LOCK; the addition is a
  one-line ctest-property amendment, test logic unchanged.
  **`SKIP_RETURN_CODE 77`** required (for
  `require_passwordless_sudo` skip path).
- **Why**: the detach-on-clean-iface idempotent path was extended in
  MVP-1.1C (§5.21 D4 amendment to §5.4) but never asserted by ctest.
  Locks the contract that detach is fully idempotent — repeated
  invocations on a clean iface succeed without error. Pairs with
  §6.6's "detach on dirty iface" (T_IDEMPOTENT_RELOAD) for full
  coverage of `detach()`'s state machine.

### 6.14 T_ATTACH_TAG_MISMATCH — same-name-different-bytecode alien refused (per §5.22 Item 1, MVP-2 Sec)
Closes the attacker-recompile vector: a BPF prog whose compile-time
`SEC()` function name is `mac_filter_prog` (so §5.19 name-check passes)
but whose bytecode differs from our build (so `bpf_prog_info.tag` differs
from our captured `self_tag`) MUST be classified as alien and refused
with exit 4 + a stderr message that identifies the rejection cause as
tag mismatch. Symmetric to §6.9 (which exercises name-mismatch); together
they prove both gates of the §5.22 Q1 identity predicate.

- **Tag-mismatch fixture** (vendored in-tree, new MVP-2 Sec):
  `tests/fixtures/mac_filter_alt.bpf.c` — ~15 LOC. The skeleton shape
  (architect-specified; tester writes the file verbatim):

  ```c
  #include "vmlinux.h"
  #include <bpf/bpf_helpers.h>

  char LICENSE[] SEC("license") = "GPL";

  SEC("xdp")
  int mac_filter_prog(struct xdp_md *ctx) {
      /* Intentionally minimal body so the bytecode (and therefore
         bpf_prog_info.tag, which is SHA1 over the bytecode) differs
         from src/bpf/mac_filter.bpf.c's built .bpf.o. Function name
         is IDENTICAL on purpose — that's what makes this a tag-check
         test (name check passes; tag check must fail). */
      (void)ctx;
      return XDP_PASS;
  }
  ```

  Load-bearing constraints (tester MUST preserve):
  - Function name `mac_filter_prog` — IDENTICAL to the real prog
    (`src/bpf/mac_filter.bpf.c`). This makes the §5.19 name-check pass.
  - Body MUST NOT be a verbatim copy of `mac_filter.bpf.c`'s logic
    (no allowlist lookup, no stats bumps). Any body that compiles to
    different bytecode works; `return XDP_PASS;` is the minimum.
  - `SEC("license") = "GPL"` is mandatory (kernel rejects non-GPL XDP
    progs that touch GPL-only helpers; XDP_PASS itself doesn't need
    it but the kernel still requires a license string).
  - `SEC("xdp")` is mandatory; same SEC as the real prog so the
    foreign-attach step uses the same `ip link set ... xdpgeneric obj
    ... sec xdp` invocation pattern as §6.9.

  Build wiring: `tests/CMakeLists.txt` adds one line invoking the
  existing helper `add_bpf_object(mac_filter_alt
  ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/mac_filter_alt.bpf.c)` (same
  pattern as `xdp_pass` per §6.9). Output:
  `${CMAKE_BINARY_DIR}/mac_filter_alt.bpf.o`. The §5.18
  sanitizer-isolation invariant applies — BPF object never receives
  `-fsanitize=`. No skeleton generation needed (loaded via `ip link`
  or `bpftool` from the test script).

  Tag-distinctness check (defensive, tester executes once at script
  start): `bpftool prog show -j` after a one-shot
  `bpftool prog load ${BUILD_DIR}/mac_filter_alt.bpf.o ...` returns a
  `tag` field. Compare with the tag of the real `mac_filter.bpf.o`
  similarly. If equal, the fixture is mis-built (compiler stripped
  the difference) and tester aborts early with an explicit error
  message — do NOT proceed to assert tag-mismatch refusal on a fixture
  that doesn't actually differ. Architect notes: this check is
  paranoia; clang's instruction selection on `return XDP_PASS;` vs the
  real allowlist-lookup body always produces distinct bytecode in
  practice, but the script SHOULD include the defensive check so a
  silent fixture regression surfaces loudly.

- **Setup**: standard veth fixture (`setup_veth` from
  `tests/lib/common.sh`, same as §6.3–§6.9) — `veth_a` is the filter
  side. Take `RESOURCE_LOCK xdp_fixture` (same lock as §6.3–§6.6, §6.8,
  §6.9). `require_passwordless_sudo` (root needed for `ip link set xdp`
  and for `bpf_xdp_query`).

- **Trigger** (sequential — mirrors §6.9 with the tag-mismatch fixture):
  1. `setup_veth` (creates `veth_a`/`veth_b`, both UP, quiesced).
  2. Pre-attach the tag-mismatch fixture to `veth_a` in generic (SKB)
     mode (same mode as our loader's attach mode, so the mode-axis
     check passes and only the tag-axis check is what fails):
     `sudo -n ip link set "${IFACE_A}" xdpgeneric obj
     "${BUILD_DIR}/mac_filter_alt.bpf.o" sec xdp`.
     Equivalent `bpftool` alternative as in §6.9 is acceptable.
  3. Capture the foreign prog id and the foreign tag for assertion:
     `foreign_id=$(xdp_prog_id ${IFACE_A})` AND `foreign_tag=$(bpftool
     -j prog show id "${foreign_id}" | jq -r '.tag')` (or equivalent
     `bpftool prog show id <id>` text parse — tester picks parser).
     Both MUST be non-empty.
  4. Run our loader with the standard attach invocation:
     `set +e; sudo -n "${LOADER_BIN}" attach --iface "${IFACE_A}"
     --allow "${MAC_GOOD}" 2> "${stderr_file}"; rc=$?; set -e`.

- **Outcome — primary scenario** (ALL must hold):
  - **rc == 4** — exit code matches `LoaderError::AttachRefusedAlien`
    per §4.1 (NOT exit 8 — exit 8 is for path-symlink refusals; the
    program is alien, the path is fine). If rc == 0 the §5.22 tag-check
    didn't land (loader accepted a bytecode-different alien as ours —
    the attacker-recompile vector is open). If rc != 4 and != 0, some
    other classification went wrong.
  - **stderr contains the foreign tag in 16-char lowercase hex form**:
    `grep -qE -- "${foreign_tag}" "${stderr_file}"` (the tag value
    rendered as e.g. `5a3f1c0e9b2d4807` per §5.22 Item 1). If
    `foreign_tag` from `bpftool -j` is uppercase, normalize via
    `tr 'A-F' 'a-f'` before greping; impl is required to render
    lowercase per the §5.22 stderr discipline.
  - **stderr contains literal substring `tag mismatch`** (per §5.22
    Item 1 contract): `grep -q -F -- 'tag mismatch' "${stderr_file}"`.
  - **stderr contains the foreign prog id** as substring (legacy
    §6.9 contract, still holds): `grep -q -F -- "${foreign_id}"
    "${stderr_file}"`.
  - **Foreign program STILL attached, byte-identical id**:
    `[[ "$(xdp_prog_id ${IFACE_A})" == "${foreign_id}" ]]`. Safety
    floor — loader MUST NOT have clobbered the alien.
  - **No orphan pin dir** on `${IFACE_A}`: `[[ ! -e "${PIN_DIR}" ]]`.
    The refusal happens before `ensure_bpffs_dir`, OR RAII rollback
    unwinds cleanly.

- **Outcome — negation control scenario** (reshaped Phase B 2026-05-23;
  triangulation: proves the identity gate ACCEPTS our own program
  identity via the full state-(b) path, not just rejects arbitrary
  aliens):

  **Why reshaped from the originally-specified "pre-attach REAL .bpf.o
  via ip link" pattern**: tester's Phase B run surfaced two independent
  problems that made the original spec unreachable in practice. (1)
  §5.4 state (b) requires THREE conditions simultaneously — prog
  attached in SKB mode, **pin_dir present**, identity verifies.
  Pre-attaching via `ip link set xdpgeneric obj` does NOT create our
  bpffs pin_dir (libbpf-managed pins are created by our loader's
  `bpf_obj_pin` calls only). (2) Empirically the kernel-computed
  `bpf_prog_info.tag` for the SAME `.bpf.o` differs between iproute2's
  `ip link xdpgeneric` load and our loader's libbpf-skeleton load —
  libbpf-side preprocessing (CO-RE relocations, subprog inlining)
  happens BEFORE BPF_PROG_LOAD and is not normalized by the kernel's
  `bpf_prog_calc_tag()`. Either problem alone kills the original spec.
  The "loader-twice idempotent-reload" pattern below avoids both by
  routing both loads through OUR libbpf in OUR process.

  Sequence (continued in the same script after primary scenario's
  trap-cleanup has restored a clean iface):

  1. Verify cleanup left the iface clean: `[[ -z "$(xdp_prog_id
     ${IFACE_A})" ]]` AND `[[ ! -e "${PIN_DIR}" ]]`. (If not clean,
     primary-scenario cleanup is broken — fail loud with explicit error,
     do NOT proceed; that's a separate bug not a negation-control
     failure.)
  2. **First loader invocation** (state (a) fresh attach):
     `set +e; sudo -n "${LOADER_BIN}" attach --iface "${IFACE_A}"
     --allow "${MAC_GOOD}" 2> "${stderr1_file}"; rc1=$?; set -e`.
     Assert `[[ $rc1 -eq 0 ]]` AND `[[ -n "$(xdp_prog_id
     ${IFACE_A})" ]]` AND `[[ -e "${PIN_DIR}/allowlist" ]]` AND
     `[[ -e "${PIN_DIR}/stats" ]]`.
  3. Capture the prog id our loader just attached:
     `our_id_1=$(xdp_prog_id ${IFACE_A})`.
  4. **Second loader invocation** — the load-bearing negation-control
     assertion (state (b) idempotent reload):
     `set +e; sudo -n "${LOADER_BIN}" attach --iface "${IFACE_A}"
     --allow "${MAC_GOOD}" 2> "${stderr2_file}"; rc2=$?; set -e`.
     Assert (ALL hold):
     - `[[ $rc2 -eq 0 ]]` — state (b) idempotent reload succeeded;
       identity gate accepted our previously-attached prog as ours
       (name match AND tag match AND pin_dir present).
     - `! grep -q -F -- 'tag mismatch' "${stderr2_file}"` — gate did
       NOT trigger tag-mismatch refusal.
     - `! grep -q -F -- 'error:' "${stderr2_file}"` — no error-prefixed
       stderr lines.
     - `our_id_2=$(xdp_prog_id ${IFACE_A})` is non-empty AND
       `[[ "$our_id_2" != "$our_id_1" ]]` — state (b) detaches the old
       and attaches a fresh skeleton load → new prog id; if the ids
       were equal, the loader skipped the re-attach and we wouldn't
       have exercised the gate (silent test-machinery failure detector).
  5. **Detach** (symmetric proof per §5.22 Q1 detach() symmetry —
     detach() identity gate also accepts our own program):
     `set +e; sudo -n "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>
     "${stderr_d_file}"; rc_d=$?; set -e`.
     Assert `[[ $rc_d -eq 0 ]]` AND `[[ -z "$(xdp_prog_id
     ${IFACE_A})" ]]` AND `[[ ! -e "${PIN_DIR}" ]]`.

  This loader-twice control proves the test isn't a no-op: identity
  gate ACCEPTS our own program identity through both attach (state b)
  AND detach paths. Without this control, an impl bug that always
  rejected SKB-mode alien (regardless of tag) would still pass the
  primary scenario.

- **Assertion mechanism** (concrete): same `fail=0` aggregator pattern
  as §6.9. Single script, run primary scenario then cleanup, then run
  negation-control scenario then cleanup. Each sub-scenario contributes
  to the same `fail` accumulator; final `exit "$fail"`.

- **Cleanup** (trap on EXIT, idempotent, runs between sub-scenarios
  AND on script exit):
  - Detach our prog if attached: `sudo -n "${LOADER_BIN}" detach
    --iface "${IFACE_A}" 2>/dev/null || true`.
  - Detach foreign prog: `sudo -n ip link set "${IFACE_A}" xdpgeneric
    off 2>/dev/null || true`.
  - `cleanup_veth` (existing helper) — wipes veth + any pin dir.
  - Remove stderr capture file: `rm -f "${stderr_file}"`.

- **Ctest properties**:
  - `TIMEOUT 60` — same floor as §6.9 (two scenarios, two foreign
    attaches, two loader runs, two cleanups; still well under 60s on
    a dev host).
  - `RESOURCE_LOCK xdp_fixture` — serializes against §6.3–§6.6, §6.8,
    §6.9.
  - `SKIP_RETURN_CODE 77` — `require_passwordless_sudo` skip path.
  - **No** `WILL_FAIL` — positive-outcome test; success means both
    scenarios passed.

- **Pre-existing tests NOT modified** — additive only. §6.13 takes a
  new RESOURCE_LOCK (see its amendment above) but that is for §6.15;
  §6.14 itself does not require pre-existing test changes.

- **Negation control built-in** — the in-script "real prog reload"
  scenario IS the triangulation; no separate `T_NEGATION_CONTROL`-style
  WILL_FAIL entry needed for this test.

### 6.15 T_BPFFS_ROOT_SYMLINK — symlink at bpffs root and per-iface dir refused (per §5.22 Item 2, MVP-2 Sec)
Closes the symlink-vortex vector: a symlink placed at
`/sys/fs/bpf/xdpmacfilter/` (the bpffs root) OR at
`/sys/fs/bpf/xdpmacfilter/<iface>/` (the per-iface dir) MUST cause the
loader to refuse with exit 8 (`PathRefused`) + a stderr message
identifying the path-symlink rejection cause. Negation control: after
cleanup restores the real bpffs root, a fresh attach must succeed
(proving the refusal is symlink-specific, not a permanent break).

**DESTRUCTIVE setup**: this test deliberately corrupts the system's
real bpffs path `/sys/fs/bpf/xdpmacfilter/` for the duration of the
test. Cleanup MUST run in `trap EXIT` to restore the path even on
script error. `RESOURCE_LOCK` MUST exclude all other tests that touch
the bpffs path.

- **Setup**:
  - `require_passwordless_sudo` (corruption requires root: `mkdir`
    under `/sys/fs/bpf/`, `ln -sfn` in same).
  - Pre-check: if `/sys/fs/bpf/xdpmacfilter/` exists as a real
    directory and is non-empty, abort early (exit 1, NOT 77) with
    explicit error: "real bpffs path is in use; refusing to corrupt".
    If it exists but is empty, snapshot it (record so cleanup
    re-creates) then `sudo -n rmdir /sys/fs/bpf/xdpmacfilter` before
    placing the symlink. If it does not exist, no snapshot needed.
  - Create attacker-controlled target: `sudo -n mkdir -p
    /tmp/xdpmf-fake-bpffs` (the symlink will point here so the
    attacker's view of "bpffs" is a tmpfs-or-disk dir we control).
  - Install `trap` to run cleanup on EXIT, INT, TERM, HUP — see
    Cleanup section.

- **Trigger — primary scenario (root-level symlink)**:
  1. `sudo -n ln -sfn /tmp/xdpmf-fake-bpffs /sys/fs/bpf/xdpmacfilter`
     — the bpffs root is now a symlink pointing at our controlled
     dir. `lstat /sys/fs/bpf/xdpmacfilter` MUST return `S_IFLNK` (sanity
     check before invoking the loader).
  2. Run our loader: `set +e; sudo -n "${LOADER_BIN}" attach --iface
     "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"; rc=$?;
     set -e`. (Uses a veth iface for the `--iface` arg — `setup_veth`
     must run BEFORE the symlink installation so the veth itself is
     real.)

- **Outcome — primary scenario** (ALL must hold):
  - **rc == 8** — exit code matches `LoaderError::PathRefused` per
    §4.1 / §5.22 Q3. (rc == 0 means the loader followed the symlink
    and pinned maps in the attacker dir — the symlink-vortex is open.
    rc == 4 means the impl reused `AttachRefusedAlien` for path
    refusals — semantic regression, Q3 decision not honored. rc == 6
    means impl picked `Permission` semantic — likewise wrong.)
  - **stderr contains literal substring `symlink`** (per §5.22 Item 2
    discipline): `grep -q -F -- 'symlink' "${stderr_file}"`. The
    word MAY appear inside a longer phrase ("…is a symlink…" or
    "…symlink — refusing to operate…").
  - **stderr contains the bpffs root path token** (operator-pinpoint
    for the corrupted entry): `grep -q -F --
    '/sys/fs/bpf/xdpmacfilter' "${stderr_file}"`.
  - **Loader did NOT write into the attacker's fake dir**:
    `[[ -z "$(ls -A /tmp/xdpmf-fake-bpffs 2>/dev/null)" ]]` — the fake
    dir MUST be empty post-attempt. If non-empty, the loader followed
    the symlink before refusing — partial-write data leak.
  - **No XDP attached on `${IFACE_A}`**: `[[ -z "$(xdp_prog_id
    ${IFACE_A} 2>/dev/null)" ]]` — refusal happened before
    `bpf_xdp_attach`.

- **Trigger — sub-variant (per-iface symlink)** (Q2 Standard scope —
  required because we picked Standard, not Minimum):
  1. Remove the root-level symlink and restore the real root: `sudo -n
     rm /sys/fs/bpf/xdpmacfilter && sudo -n mkdir
     /sys/fs/bpf/xdpmacfilter`.
  2. Place the per-iface symlink: `sudo -n mkdir -p
     /tmp/xdpmf-fake-iface && sudo -n ln -sfn /tmp/xdpmf-fake-iface
     /sys/fs/bpf/xdpmacfilter/${IFACE_A}`. `lstat` confirm
     `S_IFLNK`.
  3. Run our loader: `set +e; sudo -n "${LOADER_BIN}" attach --iface
     "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"; rc=$?;
     set -e`.

- **Outcome — per-iface sub-variant** (ALL must hold):
  - **rc == 8** — same as primary.
  - **stderr contains `symlink`**: same predicate as primary.
  - **stderr contains the iface name token**: `grep -q -F --
    "${IFACE_A}" "${stderr_file}"` (per §5.22 Item 2 message
    discipline — the per-iface message includes the iface name).
  - **Fake iface dir was NOT written into**: `[[ -z "$(ls -A
    /tmp/xdpmf-fake-iface 2>/dev/null)" ]]`.
  - **No XDP attached on `${IFACE_A}`**: same as primary.

- **Trigger — negation control (real bpffs root)**:
  1. Cleanup tears down all symlinks AND `mkdir
     /sys/fs/bpf/xdpmacfilter` (the real path is back).
  2. Run our loader: `set +e; sudo -n "${LOADER_BIN}" attach --iface
     "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"; rc=$?;
     set -e`. Then immediate detach: `sudo -n "${LOADER_BIN}" detach
     --iface "${IFACE_A}"`.
  3. Outcome: **rc == 0** for attach; **rc == 0** for detach; pin
     paths existed during the attach window; no errors. Proves the
     refusal in the primary/sub-variant scenarios is symlink-specific,
     not a permanent break of the loader.

- **Assertion mechanism** (concrete): same `fail=0` aggregator pattern
  as §6.9 / §6.14. Three scenarios in one script (primary, per-iface
  sub-variant, negation control); each scenario contributes assertions
  to the same `fail` accumulator; final `exit "$fail"`.

- **Cleanup** (trap on EXIT/INT/TERM/HUP — idempotent, runs in this
  exact order):
  1. `sudo -n "${LOADER_BIN}" detach --iface "${IFACE_A}" 2>/dev/null
     || true` (in case negation-control attach succeeded but script
     died before its detach).
  2. `sudo -n rm -f /sys/fs/bpf/xdpmacfilter/${IFACE_A}` (per-iface
     symlink — may not exist; `-f` swallows ENOENT).
  3. `sudo -n rm -f /sys/fs/bpf/xdpmacfilter` (root symlink — may
     not exist).
  4. If the snapshot from Setup indicated the real root pre-existed:
     `sudo -n mkdir -p /sys/fs/bpf/xdpmacfilter` to restore. If the
     real root did NOT pre-exist (was created by step 1 of the
     sub-variant trigger), leave it removed — restores host state.
     If snapshot indicated content, the test bails in Setup (already
     handled).
  5. `sudo -n rm -rf /tmp/xdpmf-fake-bpffs /tmp/xdpmf-fake-iface`.
  6. `cleanup_veth` (existing helper) — wipes veth fixture.
  7. `rm -f "${stderr_file}"`.

  **Idempotency contract**: cleanup MUST be safe to run multiple times
  (e.g. if `trap EXIT` fires AND the script's normal-exit cleanup
  also runs). All `rm -f` / `|| true` patterns above ensure this.

- **Ctest properties**:
  - `TIMEOUT 60` — three scenarios; same floor as §6.9 / §6.14.
  - **`RESOURCE_LOCK xdp_fixture`** — serializes against §6.3–§6.6,
    §6.8, §6.9, §6.14 (all veth-fixture tests). AND serializes against
    §6.13 per the §5.22 amendment to §6.13 (T_DETACH_NOTHING now also
    takes `xdp_fixture` — see §6.13 ctest-properties block above). The
    shared lock name ensures NO other test that touches the bpffs path
    can run concurrently with the destructive setup window.
  - `SKIP_RETURN_CODE 77` — `require_passwordless_sudo` skip path.
  - **No** `WILL_FAIL`.

- **Pre-existing tests NOT modified** — additive only. The one
  exception is §6.13's ctest-property amendment (one-line addition of
  `RESOURCE_LOCK xdp_fixture`) which is required by this test's
  destructive setup; that amendment is documented inline in §6.13 above
  and does not change §6.13's test logic.

- **Negation control built-in** — the in-script "real bpffs root"
  scenario IS the triangulation; no separate `WILL_FAIL` entry needed.

### Cross-cutting note for §6.3-§6.6, §6.8, §6.9 (per §5.21 C1+C2+C3+C4)

These are infrastructure-level mechanism shifts that apply uniformly to
the pre-existing test entries listed; the per-test Outcome assertions
(`stats[…] == N`, exit-code values, foreign-id substring match, etc.)
are byte-identical to the pre-MVP-1.1C versions.

- **C1 (sleep → poll)**: post-inject `sleep 0.3` (and `sleep 0.5` etc.)
  callsites in §6.3 / §6.4 / §6.5 / §6.8 / §6.9 are replaced by
  `wait_for_stats_sum "${IFACE_A}" <expected_sum>` (helper defined in
  `tests/lib/common.sh` per §5.21 C1). `expected_sum` is the count of
  injected frames that should land in any of the three counter slots
  (typically 1 per test). Fixture-setup sleeps (waiting for veth
  carrier-up, etc.) are NOT post-inject synchronization and stay
  as-is.
- **C2 (sudo -n + preflight skip-77)**: tests requiring root (§6.2,
  §6.3, §6.4, §6.5, §6.6, §6.8, §6.9, §6.13, **§6.14, §6.15** — last
  two added MVP-2 Sec) call `require_passwordless_sudo` near the top
  after sourcing `common.sh`; SKIP 77 on missing passwordless sudo is
  the expected behaviour, NOT a test failure. All `sudo …` invocations
  are `sudo -n …` (no password prompt — fail-fast instead of hang).
  CMake `set_tests_properties(... PROPERTIES SKIP_RETURN_CODE 77)`
  must be set on every root-requiring entry.
- **C3 (uniquified iface names)**: every literal `veth_a`/`veth_b` in
  §6.3-§6.9 (and §6.14, §6.15) reads as `${IFACE_A}`/`${IFACE_B}`
  (PID-suffixed `xdpmf_a_$$`/`xdpmf_b_$$`); bpffs pin paths follow
  (`/sys/fs/bpf/xdpmacfilter/${IFACE_A}/…`). `setup_veth` preflights
  that neither name collides with an existing host interface and
  errors out (exit 1) if collision detected.
- **C4 (per-iface XDP-presence check)**: the `final_count ==
  baseline_count` clause in §6.6 Outcome is **dropped**; surviving
  §6.6 outcome is "post-detach `xdp_prog_id ${IFACE_A}` returns empty
  AND `/sys/fs/bpf/xdpmacfilter/${IFACE_A}/` does not exist AND
  `ip -j link show ${IFACE_A}` shows no XDP attached". The
  `baseline_count` / `final_count` capture steps (1 and 5 in the §6.6
  Trigger sequence) are also removed.

### Test ordering and isolation

Tests 6.3, 6.4, 6.5 each require a fresh attach (stats start at zero).
Each test MUST do: setup veth → attach → inject → assert → detach →
teardown veth. ctest `RESOURCE_LOCK` on a shared resource name (e.g.
`xdp_fixture`) is recommended to serialize, since they all use the same
fixture name. Tester decides whether to share veth between tests
(faster, requires explicit stats reset) or re-create per test (slower,
simpler — recommended for MVP-1).

**Post-§5.22 isolation note**: §6.15 (T_BPFFS_ROOT_SYMLINK) destructively
corrupts the bpffs root path. It takes `RESOURCE_LOCK xdp_fixture` AND
§6.13 (T_DETACH_NOTHING) is amended to also take `xdp_fixture` — this
ensures the destructive setup window does not overlap with any other
bpffs-touching test. All other tests with veth fixtures already take
`xdp_fixture` per the existing convention.

### 6.16 T_MODE_GENERIC_DEFAULT — `attach` without `--mode` defaults to generic (per §5.23 Q1, MVP-2 Perf)

Closes the implicit-default-mode question raised by §5.23 Item 2: the
`--mode` flag, when omitted, MUST default to `XdpMode::Generic` (SKB
mode) to preserve the MVP-1 baseline behaviour that §6.3–§6.8 depend
on. This test asserts that default end-to-end.

- **Setup**: standard veth fixture (`setup_veth`, `${IFACE_A}`/`${IFACE_B}`). `RESOURCE_LOCK xdp_fixture`. Requires `require_passwordless_sudo`.
- **Trigger** (sequential):
  1. `sudo "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"` (NO `--mode` flag — exercises the default).
  2. Probe the attached mode via `ip -j link show "${IFACE_A}"` → JSON parse → `.[0].xdp.attached[*].mode` (kernel/iproute2 emit `generic` / `xdpgeneric` / numeric `2` — see post-implementation amendment below).
- **Outcome** (ALL must hold):
  - Step 1 exits 0.
  - Step 2 confirms the attached XDP mode is generic/SKB. **Accept all three forms** for kernel/iproute2 variance: `generic`, `xdpgeneric`, OR numeric `2` (XDP_ATTACHED_SKB enum value per uapi/linux/if_link.h — NONE=0, DRV=1, **SKB=2**, HW=3, MULTI=4). Test SHOULD add explicit FAIL branches for `1`/`native`/`xdpdrv` and `3`/`offload`/`xdpoffload` as regression guards (catches a regression to a non-SKB default mode with a clear diagnostic, not a blanket "unknown mode" fall-through).
  - `/sys/fs/bpf/xdpmacfilter/${IFACE_A}/{allowlist,stats}` exist.
- **Mechanism**:
  - Exit code: `[[ $? -eq 0 ]]`.
  - Mode check: `ip -j link show "${IFACE_A}" | jq -r '.[0].xdp.attached[]?.mode // .[0].xdp.mode'` → must equal `generic`, `xdpgeneric`, OR numeric `2` (case branches). Post-publication note (2026-05-23): the spec wording originally said only `generic`/`xdpgeneric`; tester's empirical run on libbpf 1.1.2 / iproute2 on this host emits numeric `2`. Amendment adds numeric variant + diagnostic FAIL branches per `[OUT-OF-TRIANGULATION-1]` advisory in MVP-2 Perf review.
  - Pin paths: `sudo -n test -e "${PIN_DIR}/allowlist" && sudo -n test -e "${PIN_DIR}/stats"`.
- **Cleanup**: `xdpmacfilter detach --iface "${IFACE_A}"` (NO `--mode` per Q1 Option A) + `cleanup_veth`.
- **Ctest properties**: `TIMEOUT 60`, `RESOURCE_LOCK xdp_fixture`, `SKIP_RETURN_CODE 77`.
- **Negation control NOT required** — covered by suite-level §6.7.

### 6.17 T_MODE_NATIVE_UNSUPPORTED — `--mode native` on unsupported iface exits 3 (per §5.23 Q2, MVP-2 Perf)

Closes the Q2 Option K choice: when the kernel rejects a non-generic
mode (EOPNOTSUPP / EINVAL), the loader maps to exit 3 (`AttachFailed`).
Uses `lo` (the loopback iface) — universally does NOT support native
XDP — as the unsupported target.

- **Setup**: NO veth fixture (test targets `lo`). NO `RESOURCE_LOCK xdp_fixture` (does not touch the veth pair). Requires `require_passwordless_sudo`. Pre-test snapshot: `xdp_prog_id lo` should be empty; if not, exit 1 with diagnostic (test environment dirty, not our loader's fault).
- **Trigger** (sequential):
  1. Pre-check: `[[ -z "$(xdp_prog_id lo)" ]]`; otherwise exit 1 with "lo already has XDP attached; test environment dirty".
  2. Run: `set +e; sudo "${LOADER_BIN}" attach --iface lo --allow "${MAC_GOOD}" --mode native 2> "${stderr_file}"; rc=$?; set -e`.
- **Outcome** (ALL must hold):
  - `rc == 3` — exit code matches `LoaderError::AttachFailed` per §4.1 + Q2 Option K.
  - Stderr is non-empty AND contains the substring `native` OR `mode=native` (impl-shape; asserts stderr names the mode, not exact format).
  - Post-test: `[[ -z "$(xdp_prog_id lo)" ]]` — lo's XDP slot still empty.
  - No orphan pin dir: `sudo -n test ! -e "/sys/fs/bpf/xdpmacfilter/lo"`.
- **Mechanism**:
  - `[[ "${rc}" == 3 ]] || fail`
  - `grep -q -E -- 'native|mode=native' "${stderr_file}" || fail`
  - `[[ -z "$(xdp_prog_id lo)" ]] || fail`
  - `sudo -n test ! -e "/sys/fs/bpf/xdpmacfilter/lo" || fail`
- **Cleanup**: `sudo -n ip link set lo xdpgeneric off 2>/dev/null || true` (belt-and-suspenders); `rm -f "${stderr_file}"`.
- **Ctest properties**: `TIMEOUT 30`, **no** `RESOURCE_LOCK xdp_fixture`, `SKIP_RETURN_CODE 77`.
- **Flakiness consideration**: `lo` is universally available; native XDP universally unsupported on `lo`. Stable on any Linux host meeting the project's libbpf ≥ 1.1 / kernel ≥ 5.15 floor (per §5.24 Q2). If a future kernel adds native XDP to `lo` (extremely unlikely), this test would need a different unsupported-target iface (tap/dummy).
- **Negation control NOT required** — §6.7 covers suite-level.
- **Note on Q2 Option K rationale**: this test asserts ONLY exit 3 + stderr substring; does NOT assert any specific exit-code value beyond 3 (would NOT need rewriting if architect later opts for Option N exit 9).

### 6.18 T_PERCPU_STATS_SUM — PERCPU sum-correctness via direct map seed (per §5.23 Q3 Option F, MVP-2 Perf)

Closes the Q3 Option F choice: deterministic verification that the
new `read_stats.py` correctly sums across CPU slots in the PERCPU
`stats` map. No traffic injection; seeds known per-CPU values
directly via `bpftool map update`, asserts script's sum matches
seeded total.

- **Setup**: standard veth fixture (`setup_veth`, `${IFACE_A}`/`${IFACE_B}`). Run `xdpmacfilter attach --iface "${IFACE_A}" --allow "${MAC_GOOD}"` (default mode) so the PERCPU `stats` map exists at `${PIN_DIR}/stats`. `RESOURCE_LOCK xdp_fixture`. Requires `require_passwordless_sudo`.
- **Trigger** (sequential):
  1. `nr_cpus=$(nproc --all)` — number of possible CPUs (matches PERCPU map slot count).
  2. Pick a known broadcast value `V` (recommend non-zero magic number, e.g. `V = 0x2a = 42`). Expected sum = `nr_cpus * V`.
  3. Build the 8-byte little-endian u64 byte sequence for `V` (exactly `value_size = 8` bytes; bpftool's PERCPU `map update` CLI accepts only one `value_size`-sized value and BROADCASTS it across all CPU slots — see post-publication amendment below).
  4. Seed `STAT_PASS` slot (key 0) via `sudo -n bpftool map update pinned "${PIN_DIR}/stats" key hex 00 00 00 00 value hex <8-bytes-of-V>`.
  5. Read sum via `read_stats.py` (whatever invocation form `read_stats.py` exposes; tester uses the documented interface — script returns `<pass> <drop_deny> <drop_malformed>` per MVP-1 convention).
- **Outcome** (ALL must hold):
  - Step 4 exits 0 (`bpftool map update` accepts the PERCPU value format).
  - Step 5 exits 0 and the STAT_PASS field of the returned tuple equals `expected_sum = nr_cpus * V`.
  - Other stats slots (`STAT_DROP_DENY`, `STAT_DROP_MALFORMED`) NOT asserted in this test (they're at default zero; the test focuses on the sum-correctness of STAT_PASS).
- **Mechanism**:
  - `bpftool map update` exit: `[[ $? -eq 0 ]]`.
  - Sum equality: `read -r pass _ _ < <(read_stats); [[ "${pass}" == "${expected_sum}" ]] || fail`.
- **Cleanup**: `xdpmacfilter detach --iface "${IFACE_A}"` + `cleanup_veth`.
- **Ctest properties**: `TIMEOUT 30`, `RESOURCE_LOCK xdp_fixture`, `SKIP_RETURN_CODE 77`.
- **Flakiness consideration**: `nproc --all` returns possible CPUs. Even on single-CPU runners (`nr_cpus == 1`), test is deterministic: expected_sum = `1 * V = V`, sole CPU's slot seeded with `V`, sum reads back `V`. Discriminator preserved on multi-CPU: if `read_stats.py` silently reads only CPU 0 (PERCPU sum bug), returns `V` ≠ `nr_cpus * V` on any host with `nr_cpus ≥ 2`.
- **Post-publication amendment** (2026-05-23, per `[OUT-OF-TRIANGULATION-2]` advisory in MVP-2 Perf review): the original spec text said "seed each CPU slot with `c + 1` for `c ∈ [0, nr_cpus-1]`, expected_sum = `nr_cpus*(nr_cpus+1)/2`". Tester empirically established that bpftool's PERCPU `map update` CLI (v7.1.0 src/map.c `fill_per_cpu_value()`) reads exactly `value_size` bytes and BROADCASTS them to all CPU slots — there is no CLI syntax for distinct per-CPU values. Adapted to broadcast-V semantic above; preserves Q3 Option F's diagnostic intent (sum-correctness vs single-CPU-read bug discriminator) on multi-CPU hosts. Distinct per-CPU seeding would require raw `bpf()` syscall via Python ctypes — out of §6.18 unit-test scope.
- **Negation control NOT required** — `read_stats.py` sum-logic failure propagates to §6.3–§6.8 immediately. §6.7 covers suite-level no-op floor.
- **Diagnostic value**: if T_PERCPU_STATS_SUM fails but §6.3 passes, likely cause is `read_stats.py` reading CPU 0 only OR a bpftool JSON schema mismatch. If T_PERCPU_STATS_SUM passes but §6.3 fails, bug is in BPF program's PERCPU lookup-and-bump, NOT the sum logic — diagnostic separation is the point.

### 6.19 T_MODE_DETACH_REJECTS — `detach --mode <X>` rejected with usage error (per §5.23 Q1 Option A, MVP-2 Perf)

Closes the Q1 Option A explicit-rejection rule: `detach` does NOT
accept `--mode`; if the operator passes one, the CLI parser exits 1
with a clear stderr message.

- **Setup**: minimal — no veth needed, no attach needed. NO `RESOURCE_LOCK`. Does NOT require root (parser rejects before any privileged syscall).
- **Trigger** (sequential):
  1. `set +e; "${LOADER_BIN}" detach --iface "${IFACE_A:-xdpmf_test}" --mode native 2> "${stderr_file}"; rc=$?; set -e`.
- **Outcome** (ALL must hold):
  - `rc == 1` — CLI usage error per §4.1 exit code 1.
  - Stderr contains `--mode is attach-only` (recommended literal) OR at least the substring `attach-only` (impl-shape flexibility).
- **Mechanism**:
  - Exit code: `[[ "${rc}" == 1 ]] || fail`
  - Stderr: `grep -q -F -- 'attach-only' "${stderr_file}" || fail`.
- **Cleanup**: `rm -f "${stderr_file}"`.
- **Ctest properties**: `TIMEOUT 10`, **no** `RESOURCE_LOCK`, **no** `SKIP_RETURN_CODE 77` — does not need root. Pure CLI-parser test, parallels §6.10–§6.12 pattern.
- **Negation control**: an `attach --mode native` invocation does NOT exit 1 with the same stderr — covered implicitly by §6.17 (attach --mode native on lo exits 3, not 1).
- **Test variant** (optional, tester's choice): also test `detach --mode generic` — proves rule is flag-presence-driven, not mode-value-driven.

### 6.20 T_VERIFIER_REJECT — verifier-reject path produces clean LoadFailed (per §5.24 Q4 Option (c), MVP-2 Robust)

Closes the Q4 Option (c) hybrid choice: assert the loader exits **2**
(`LoadFailed`) with a recognizable stderr when handed a verifier-rejected
BPF program. Degrades gracefully (`SKIP_RETURN_CODE 77`) if the verifier
on the running kernel happens to accept the bad fixture.

- **Setup**: standard veth fixture (`setup_veth`, `${IFACE_A}`/`${IFACE_B}`). NO attach in setup. `RESOURCE_LOCK xdp_fixture`. Requires `require_passwordless_sudo`. Path to bad fixture: `${BUILD_DIR}/mac_filter_bad.bpf.o` (built via existing `add_bpf_object` pattern).
- **SKIP probe** (BEFORE active branch): `sudo -n bpftool prog load "${BUILD_DIR}/mac_filter_bad.bpf.o" /sys/fs/bpf/xdpmf_verifier_probe type xdp 2>/dev/null`. If exits 0 → verifier accepted on this kernel → cleanup probe pin → exit **77** (SKIP). If non-zero → expected; proceed.
- **Trigger** (active branch): `set +e; XDPMF_BPF_OBJECT_PATH="${BUILD_DIR}/mac_filter_bad.bpf.o" sudo -n -E "${LOADER_BIN}" attach --iface "${IFACE_A}" --allow "${MAC_GOOD}" 2> "${stderr_file}"; rc=$?; set -e`. (`-E` preserves env var across privilege boundary.)
- **Outcome** (ALL must hold on active branch):
  - `rc == 2` — `LoadFailed`.
  - Stderr non-empty.
  - Stderr contains AT LEAST ONE of: `BPF program load failed` OR `BPF object load failed` OR `PROG LOAD LOG` OR `verifier` OR `Invalid argument` (impl-shape flexibility — captures libbpf 1.x wrapping + verifier-direct output paths; post-publication amendment 2026-05-23 EDIT-11, see post-publication note below).
  - No XDP attached: `[[ -z "$(xdp_prog_id ${IFACE_A})" ]]`.
  - No orphan pin dir: `sudo -n test ! -e "/sys/fs/bpf/xdpmacfilter/${IFACE_A}"`.
- **Mechanism**:
  - SKIP exit: `[[ $skip_rc -eq 0 ]] && { sudo -n rm -f /sys/fs/bpf/xdpmf_verifier_probe; exit 77; }`.
  - rc: `[[ "${rc}" == 2 ]] || fail`.
  - Stderr non-empty: `[[ -s "${stderr_file}" ]] || fail`.
  - Stderr substring: `grep -q -E -- 'BPF program load failed|BPF object load failed|PROG LOAD LOG|verifier|Invalid argument' "${stderr_file}" || fail`.
- **Cleanup**: `sudo -n ip link set "${IFACE_A}" xdpgeneric off 2>/dev/null || true`; `sudo -n rm -rf "/sys/fs/bpf/xdpmacfilter/${IFACE_A}" 2>/dev/null || true`; `sudo -n rm -f /sys/fs/bpf/xdpmf_verifier_probe 2>/dev/null || true`; `cleanup_veth`; `rm -f "${stderr_file}"`.
- **Ctest properties**: `TIMEOUT 60`, `RESOURCE_LOCK xdp_fixture`, `SKIP_RETURN_CODE 77`. (Post-publication amendment 2026-05-23 EDIT-12: original spec wording was `TIMEOUT 30`; tester's Phase B empirical run showed actual wall ~24s with the libbpf-stderr head/tail trim optimization — 60s kept as safe margin matching other veth-fixture tests' floor, since libbpf-stderr volume can spike under load. CMake inline comment in `tests/CMakeLists.txt` also updated to reflect the 60s value.)
- **Flakiness consideration**: SKIP branch absorbs the only known flake source (future kernel verifier accepting unbounded loop). If that happens, tester swaps `mac_filter_bad.bpf.c` to OOB-deref backup pattern (verifier-universal for 5.15+).
- **Negation control NOT required** — §6.7 covers suite-level.
- **Sanity coupling**: this test depends on §5.24 probe NOT firing (modern kernel). If probe false-positive rejects modern kernel, this test exits 7 instead of 2 — §5.24 Q1 impl bug surfacing, not §6.20 design flaw.
- **Fixture coupling**: `tests/fixtures/mac_filter_bad.bpf.c` MUST be built via `add_bpf_object` in `tests/CMakeLists.txt`. `add_bpf_object` only invokes `clang -target bpf` (compile-time); verifier fires at `bpf()`-syscall load time (what we test). Fixture MUST also declare `allowlist` + `stats` maps with names/types matching the real `mac_filter.bpf.c` shapes — the libbpf skeleton-populate step runs BEFORE BPF_PROG_LOAD and fails earlier (`failed to find skeleton map`) if maps are absent; the verifier-reject path needs to reach BPF_PROG_LOAD to be exercised.
- **Post-publication amendment 2026-05-23 EDIT-11** (Phase B finding by mint-tester): the original substring list `verifier|BPF_PROG_LOAD|Invalid argument` was a guess against libbpf wording that doesn't match libbpf 1.x reality. Verifier emits register-state dumps (no literal `verifier` word); libbpf wraps with `BPF program load failed` / `PROG LOAD LOG` (space-separated, no underscore in `PROG LOAD`); kernel can return E2BIG (`Argument list too long` — insn-limit hit) instead of EINVAL (`Invalid argument`) for unbounded-loop rejections. List broadened to `BPF program load failed|BPF object load failed|PROG LOAD LOG|verifier|Invalid argument` — captures libbpf 1.x wrapping (standard wrap + verifier-log header), impl's own wrap (resilient to future libbpf wording changes), preserves original tokens for forward-compat. Tight enough to mean "actually a load failure", not "any non-empty stderr".

## 7. Out of scope

The brief's out-of-scope list applies verbatim. Additionally, the
architect explicitly fences out the following items that impl or tester
might be tempted to add:

- **No `stats` subcommand** in `xdpmacfilter` — stats are read via
  `bpftool map dump`. Adding a userspace dump is MVP-2.
- ~~**No `--mode {generic,native,offload}` flag** — generic (SKB) mode is
  hardcoded per §5.6.~~ **— SHIPPED in §5.23 (MVP-2 Perf, 2026-05-23)**.
  `--mode {generic,native,offload}` is now a CLI flag on the `attach`
  subcommand, default `generic` (preserves MVP-1 baseline). `detach`
  does NOT accept `--mode` (per §5.23 Q1 = Option A auto-detect; mode
  is read from the §5.20 all-modes probe). Kernel-rejected modes (e.g.
  `--mode native --iface lo`) map to exit 3 (`AttachFailed`, per §5.23
  Q2 = Option K). Test coverage: §6.16 T_MODE_GENERIC_DEFAULT, §6.17
  T_MODE_NATIVE_UNSUPPORTED, §6.19 T_MODE_DETACH_REJECTS.
- ~~**No `bpf_prog_info.tag` (SHA1-of-bytecode) identity check** in §5.19~~
  **— SHIPPED in §5.22 (MVP-2 Sec, 2026-05-23)**. Tag-check is now
  layered on top of name-check per §5.22 Q1 = Option E (early-load):
  skeleton loads first, `self_tag` is captured from our own program's
  `bpf_prog_info.tag`, probe compares the alien's tag against it.
  Stderr on tag-mismatch refusal includes the hex tag + literal
  `tag mismatch` substring. Test coverage: §6.14 T_ATTACH_TAG_MISMATCH.
- ~~**No `O_PATH/O_DIRECTORY` fd hardening** on `pin_dir` (the §5.19~~
  ~~option (iii))~~ **— SHIPPED in §5.22 (MVP-2 Sec, 2026-05-23) at Q2
  = Standard scope**. `BpffsRootFd` RAII opens the bpffs root with
  `O_PATH | O_DIRECTORY | O_NOFOLLOW`; all bpffs operations use
  fd-relative `*at()` syscalls (`mkdirat`, `faccessat`, `fstatat`,
  `openat`, `unlinkat`). Symlink at the root → exit 8 (`PathRefused`);
  symlink at a per-iface entry → likewise. Test coverage: §6.15
  T_BPFFS_ROOT_SYMLINK (primary + per-iface sub-variant + negation
  control).
- **No `--mode`-specific detach in MVP-1.1B** — detach always uses
  `XDP_FLAGS_SKB_MODE` per §5.6; we only detach what we ourselves
  attached, and we only attach in SKB. Alien progs in non-SKB modes
  hit state (c) and are refused, not detached.
- **No new exit codes** for the §5.4 4-state expansion — state (d)
  (stale-pin recovery) maps to exit 0 (successful attach after orphan
  cleanup) in `attach()`, and to exit 0 (successful no-op cleanup) in
  `detach()`. The MVP-1 exit-code table (§4.1) is unchanged.
  **Post-§5.22 note**: this fence applies to the §5.4 4-state expansion
  specifically; MVP-2 Sec adds exactly one new exit code (8 =
  `PathRefused`) for the orthogonal path-symlink-refusal case per
  §5.22 Q3. That addition is documented in §4.1.
- **No restructure of `loader.hpp`** in MVP-1.1B — all §5.19/§5.20
  changes are confined to `loader.cpp` anon-namespace helpers. Public
  API (§4.3) is unchanged. (Architecture M1 backwards layering —
  `loader.hpp → cli.hpp` — is addressed in MVP-1.1C per §5.21 A1.)
  **Post-§5.22 note**: this fence relaxes by exactly one enumerator
  (`LoaderError::PathRefused = 8`) per §5.22 Q3 — the smallest
  possible .hpp diff. All other §5.22 work lives in `loader.cpp` anon
  namespace.
- **No changes to the 8 pre-existing tests** — they remain
  byte-identical; only the new `T_ATTACH_ALIEN_REFUSAL` is added.
- **No changes to other `src/**` files** — only `src/loader/loader.cpp`
  is touched in MVP-1.1B (per task brief Notes for impl).
- **No daemon mode, no SIGINT handler, no foreground loop** — loader
  attaches and exits.
- **No machine-readable output** (no JSON, no `--format`). stdout/stderr
  is human plain text only.
- **No log levels, no `--verbose`** — single verbosity, terse.
- **No metrics endpoint, no Prometheus, no UDS** — bpffs is the only
  observability surface.
- **No support for interface names with characters that break a
  filesystem path** (`/`, NUL) — `if_nametoindex` already prevents
  this; loader does not double-validate.
- **No allow-list mutation after attach** — to change the list, detach
  and re-attach. MVP-3 may add a `set-allowlist` subcommand.
- **No removal of empty parent `/sys/fs/bpf/xdpmacfilter/` directory on
  detach** — only the `<iface>/` subdir is removed. The parent persists
  across runs (harmless empty dir).
- **No IPv4/IPv6/ARP-specific handling** — see brief.
- **No multi-iface, no VLAN, no L3+, no per-CPU counters, no JSON
  config, no hot reload** — see brief.
- **No installation target** (`make install`) — build artifacts stay in
  `build/`. Packaging is post-MVP series.
- **No CI configuration files** (GitHub Actions, etc.) — local ctest
  only for MVP-1.
- **No man page, no shell completion** — `--help` text only.

### MVP-1.1C additions to OOS (per §5.21)

- ~~**No netns isolation for the test fixture (C3 Path A)**~~
  **— SHIPPED in §5.25 (MVP-2 Polish-2, 2026-05-23)** via Q1 = N3
  (setup_veth-level wrap). `tests/lib/common.sh` exports
  `NETNS="xdpmf_ns_$$"` + `NSEXEC="sudo -n nsenter --net=/var/run/netns/${NETNS}"` (per EDIT-15 — `nsenter --net` preserves mount-ns so host bpffs at `/sys/fs/bpf` remains visible to the loader child);
  `setup_veth` creates the netns and runs the veth pair inside it;
  `cleanup_veth` deletes the netns (atomic veth + XDP teardown).
  Test bodies edit only the loader-invocation callsites
  (`sudo -n "${LOADER_BIN}"` → `${NSEXEC} "${LOADER_BIN}"`); pin
  paths under `/sys/fs/bpf/xdpmacfilter/${IFACE_A}` remain
  host-global (bpffs is not netns-isolated; PID-suffix continues to
  be the pin-path uniqueness guarantee). T_BPFFS_ROOT_SYMLINK +
  T_MODE_NATIVE_UNSUPPORTED opt out by not calling setup_veth.
- ~~**No CMake-generation of `tests/lib/common.sh:PIN_ROOT`**~~
  **— SHIPPED in §5.25 (MVP-2 Polish-2, 2026-05-23)** via Q2 = C1
  (sed extraction in CMake). `CMakeLists.txt` `execute_process`
  extracts `XDPMF_BPFFS_ROOT` from `src/common/mac_filter.h` at
  configure time (FATAL_ERROR fail-fast on empty); `configure_file`
  emits `${CMAKE_BINARY_DIR}/tests/pins.sh`; `tests/CMakeLists.txt`
  `TEST_ENV` passes `PINS_SH=<path>`; `tests/lib/common.sh:33-35`
  sources `${PINS_SH}` with `:?` integrity guards. Silent
  header-rename drift now produces a hard configure-time failure.
- ~~**No version-string sync between `CHANGELOG.md` and the loader
  binary's `--version` output**~~ **— SHIPPED in §5.25 (MVP-2
  Polish-2, 2026-05-23)** via Q3 = V1 (`project(VERSION)`
  source-of-truth). `CMakeLists.txt:13 VERSION 0.1.0` bumped to
  `VERSION 0.2.3`; new `include/version.h.in` template +
  `configure_file` emits `${CMAKE_BINARY_DIR}/include/version.h`
  carrying `#define XDPMF_VERSION_STRING "@PROJECT_VERSION@"`;
  `src/loader/cli.cpp` includes the generated header, drops the
  hardcoded `kVersion` constant. Loader's `--version` output now
  reads `xdpmacfilter 0.2.3`. CHANGELOG entry `## [0.2.3]` documents
  the bump.
- ~~**No `inject_runt.py:37` inline-comment fix** (MVP-1.1C reviewer
  OUT-OF-TRIANGULATION advisory)~~ **— SHIPPED in §5.25 (MVP-2
  Polish-2, 2026-05-23)** via P4. The `:37` inline comment rewritten
  from `complete 6-byte dst MAC + partial src MAC` →
  `full 6-byte dst MAC + full 6-byte src MAC + 1 ethertype byte` —
  agrees with the corrected lines 18-19 docstring (MVP-1.1C B1).
  Byte literals at lines 41-43 untouched (brief explicit OOS).
- ~~**No T_VERIFIER_REJECT + kernel-version probe +
  `LoaderError::KernelUnsupported`**~~ **— SHIPPED in §5.24 (MVP-2
  Robust, 2026-05-23)**. Kernel-version probe is uname-based (Q1
  Option U); fires at the head of both `attach()` and `detach()`
  (Q3 Option B); floor is 5.15 (Q2 — README floor unchanged,
  design.md 5.7-references corrected at lines 765 and 2670).
  `LoaderError::KernelUnsupported = 7` is the exit-7 enumerator
  (single-line `loader.hpp` addition, same precedent as MVP-2 Sec's
  `PathRefused = 8`). T_VERIFIER_REJECT (§6.20) is hybrid (Q4 Option
  (c) — active fixture `tests/fixtures/mac_filter_bad.bpf.c` with
  unbounded-loop verifier violation + `SKIP_RETURN_CODE 77` fallback
  if the running kernel happens to accept the bad fixture).
  Test coverage: §6.20 T_VERIFIER_REJECT.
- ~~**No PERCPU stats migration** — performance HIGH finding per brief
  OOS section; design §5.3 + §5.5 explicit MVP-2 (Perf slice).~~
  **— SHIPPED in §5.23 (MVP-2 Perf, 2026-05-23)**. `stats` map type
  is now `BPF_MAP_TYPE_PERCPU_ARRAY`; `read_stats.py` sums across
  CPUs via the libbpf-stable bpftool `--json` PERCPU schema (per-CPU
  `"values"` array). §5.3 and §5.6 are explicitly superseded by §5.23.
  Test coverage: §6.18 T_PERCPU_STATS_SUM (Q3 Option F unit-shaped
  sum-correctness).
- **No removal of `mint/test-run.log` from the gitignore list** — brief
  flags this as a stale finding (already gitignored AND untracked, no
  work needed). Not a change; documented here so reviewer does not flag
  the non-edit as a miss.

### MVP-2 Sec additions to OOS (per §5.22)

- **No libbpf-level fd-relative pinning (Q2 Maximum)** — `bpf_obj_pin`
  in libbpf 1.1 is path-string-based; fd-relative pinning would
  require either re-implementing the pin step manually against
  `O_PATH`-rooted constructed paths OR upstreaming a libbpf API
  addition. Both exceed the §5.22 "first MVP-2 pass, narrow scope"
  framing. Recorded as MVP-2+ hardening; if upstream libbpf gains
  fd-relative `bpf_obj_pin` we revisit. The residual surface this
  leaves open is the µs-scale window between our `mkdirat(root.fd(),
  iface, …)` and libbpf's subsequent path-based `bpf_obj_pin` — a
  symlink-substitution attack in that window would succeed, but the
  attacker needs root-on-bpffs and µs-precision timing, AND the
  resulting pinned maps would be in the attacker's dir (operator
  notices via `bpftool map show`); the attack value is low.
- **No TOCTOU closure between our probe and `bpf_xdp_attach`** —
  requires single-syscall atomic attach-only-if-empty semantics not
  available in libbpf 1.1 (and arguably not in the kernel XDP attach
  API itself). A future kernel feature (e.g. `XDP_FLAGS_REPLACE` with
  expected-prog-id atomicity) could close this; out of our control.
  The residual window is ~µs; an attacker would have to win an
  inter-syscall race.
- **No `LoaderError::PathRefused` use beyond symlink/non-directory
  refusal at the bpffs root or per-iface entry** — exit 8 is reserved
  for the §5.22 Item 2 path-discipline cases. Other path-shaped errors
  (e.g. permission-denied on bpffs mount, ENOSPC on pin) continue to
  use `Permission` (6) / `LoadFailed` (2) per existing classification.
  This fences impl from broadening exit 8's semantic during
  implementation.
- **No `expected_tag.h` compile-time tag header (Q1 Option C)** —
  Option E (early-load runtime tag capture) was chosen per §5.22 Q1.
  Option C is recorded as MVP-3+ work if a future build-pipeline
  redesign makes codegen cheaper; the runtime cost of Option E
  (one skeleton load on the rare state-(c) refusal path) is not
  pressuring us toward Option C in MVP-2.
- **No `--no-tag-check` / `--tag-check-mode` escape hatch** — the
  tag-check is unconditional. An operator who wants to attach a
  custom-built variant of the program must update their build
  pipeline so the variant's tag matches what the loader expects; the
  loader does not expose an opt-out. (If a future MVP-2+ adds
  multi-variant support, the design becomes "variant registry of
  acceptable tags", not a bypass flag.)
- **No `T_PROBE_ELOOP_UNIT` micro-test** — the `BpffsRootFd` ctor's
  ELOOP branch is exercised end-to-end by §6.15 T_BPFFS_ROOT_SYMLINK;
  a separate unit-test entry point would duplicate coverage at the
  cost of a new test surface. If §6.15 turns out to be flaky on some
  hosts (kernel symlink semantics regression — extremely unlikely),
  a unit-level entry is reconsidered.
- **No bpffs mount preflight** — the loader assumes
  `/sys/fs/bpf` is mounted as `bpf` filesystem (the standard
  distro/systemd setup). If `/sys/fs/bpf` is not mounted, `mkdirat`
  for the root will fail with whatever errno the kernel returns
  (ENOTDIR/ENOSYS/etc.) → `LoadFailed` (exit 2). Adding an explicit
  `statfs(/sys/fs/bpf, ...) == BPF_FS_MAGIC` preflight is MVP-2+
  Robust-slice work; the current behaviour (fail with kernel errno
  surfaced via stderr) is the floor.
- **No support for cross-loader idempotency** — operator-managed
  external loads of our `.bpf.o` (via `ip link set xdpgeneric obj`,
  `bpftool prog load`, custom userspace, etc.) are NOT recognized by
  our loader as state-(b) "ours" because the resulting
  `bpf_prog_info.tag` differs from our loader's own libbpf-skeleton
  load (see §5.22 Q1 "Tag stability across loaders" sub-section).
  Operators must use `xdpmacfilter attach` exclusively for our program,
  or manually detach external loads (`ip link set <iface> xdp off`)
  before invoking our loader. A future MVP-3+ pass could expose an
  `--accept-tag <hex>` registry CLI flag for advanced multi-loader
  scenarios; OOS for MVP-2 Sec.

### MVP-2 Perf additions to OOS (per §5.23)

- **No `detach --mode` acceptance (Q1 Options S and W rejected)** —
  per §5.23 Q1 = Option A, `detach` rejects `--mode` as a CLI usage
  error (exit 1). The "strict require --mode on detach" (Option S)
  and "wildcard silently-ignore --mode on detach" (Option W)
  alternatives are explicitly OOS. If a future operational pattern
  emerges where operators want to assert the mode on detach (e.g. as
  a safety check), an `--expect-mode <X>` flag could be added later —
  semantically distinct from `--mode` and OOS for MVP-2 Perf.
- **No new exit code 9 `ModeUnsupported` (Q2 Option N rejected)** —
  per §5.23 Q2 = Option K, kernel-rejected modes (EOPNOTSUPP /
  EINVAL on non-generic mode requests) map to existing exit 3
  (`AttachFailed`). Exit 9 stays free; exit 7 stays reserved for
  `KernelUnsupported` (MVP-2 Robust). If a future operational
  pattern emerges where the audit-signal value of a distinct exit
  code clearly beats the EOPNOTSUPP false-positive risk (e.g.
  rich-error stderr is also added), exit 9 can be carved out then.
- **No defensive multi-CPU PERCPU aggregation test (Q3 Option D
  rejected)** — per §5.23 Q3 = Option F, the test machinery uses
  `bpftool map update` to seed known per-CPU values directly,
  bypassing traffic injection. Option D is rejected as flaky on
  single-CPU runners and overcomplicated.
- **No implicit-only PERCPU coverage (Q3 Option I rejected)** —
  per §5.23 Q3, T_PERCPU_STATS_SUM (§6.18) is the dedicated
  Option-F entry. Relying solely on T_PASS_ALLOWED to catch PERCPU
  sum bugs is rejected — failure signal would be opaque.
- **No `--accept-any-mode` / multi-mode-simultaneous attach** — the
  §5.23 design allows ONE mode per attach (operator picks one of
  `generic` / `native` / `offload`). Some kernels permit multiple
  mode-slots simultaneously; this loader does NOT. The §5.4 state
  machine's "ours" check accepts any single mode (relaxed from
  SKB-only per §5.23 Q1) but the attach itself produces a single
  attachment.
- **No PERCPU migration for the `allowlist` map** — allowlist is
  read-only at runtime (populated once at attach); PERCPU offers no
  benefit (each CPU would have an identical copy, wasting memory).
  Stays `BPF_MAP_TYPE_HASH`.
- **No atomic counter ops (`__sync_fetch_and_add` etc.)** — PERCPU
  eliminates cross-CPU race; intra-CPU race is not a concern for the
  single-threaded XDP per-CPU dispatch model (no preemption inside
  BPF program execution).
- **No userspace `stats` subcommand** — PERCPU migration is a
  kernel-side storage change; the userspace dump interface stays
  `bpftool map dump` + `read_stats.py`. Adding a `xdpmacfilter
  stats` subcommand remains MVP-3+ (per pre-existing §7).
- **No bpftool `--json` schema-version probe** — bpftool's PERCPU
  JSON schema (`"values"` plural array per entry) is libbpf 1.1+
  stable. If a future libbpf changes the schema, `read_stats.py`
  breaks and the bug surfaces via §6.18 immediately. Robust-slice
  work could add a probe; OOS for MVP-2 Perf.
- **No `--mode` removal at detach via global CLI grammar** — the
  `detach`'s `--help` text MUST document that `--mode` is
  attach-only (so operators can discover the rule). Removing the
  flag from the global CLI grammar is not possible without breaking
  the `attach` use case. The explicit-rejection-on-detach pattern
  is the correct semantic.
- **No `--mode` for `T_ATTACH_TAG_MISMATCH` (§6.14) fixture** — the
  tag-check fixture stays in SKB mode; the mode axis is not what
  §6.14 exercises. If a future test slice wants mode-axis tag-check
  coverage, a new test is added; §6.14 stays mode-axis-agnostic.
- **No bpftool dependency version pin beyond libbpf ≥ 1.1** —
  bpftool packaging varies by distro; the `--json` PERCPU schema
  is stable per libbpf API. Adding a `bpftool --version` probe is
  OOS.

### MVP-2 Robust additions to OOS (per §5.24)

- **No `--no-version-probe` / `--skip-kernel-check` escape hatch** —
  the kernel-version probe is unconditional. Operators on
  backported-feature kernels (5.14 or earlier with relevant features
  backported) who hit `KernelUnsupported` (exit 7) can locally patch
  `kKernelFloorMajor`/`kKernelFloorMinor` in `loader.cpp` and
  rebuild. If upstream demand emerges, a future pass adds the flag.
- **No `libbpf_probe_bpf_*` feature probing (Q1 Option F rejected)**
  — Q1 picks Option U (uname-string parse) for the simplicity /
  cost-benefit profile. Feature-probe-style detection (one syscall
  per probed feature, fragile across libbpf versions) is OOS.
- **No `BPF_PROG_LOAD` trivial-probe (Q1 Option C rejected)** —
  most accurate of the four Q1 options but requires CAP_BPF
  mid-probe + careful choice of trivial program. Complexity not
  justified by feature-accuracy gain over Option U.
- **No `--version` kernel-range reporting** — `--version` stays
  single-line per MVP-1.
- **No probe at `--help`/`--version` subcommands** — those don't
  touch the kernel; probe stays gated to `attach`/`detach`.
- **No backporting / "kernel X has feature Y backported" detection**
  — single floor only. Option U doesn't detect backports; Option F
  would but is rejected.
- **No probe-result caching across processes** — probe is
  microseconds; per-invocation re-probe is fine.
- **No `XDPMF_BPF_OBJECT_PATH` documentation in `--help`** — env var
  is testing-only infrastructure (per Q4 Option (i)). Production
  operators do not set it; intentionally undocumented in public CLI
  surface.
- **No `--bpf-object-path` CLI flag (Q4 Option (ii) rejected)** —
  env-var override (Option (i)) is picked. CLI flag would pollute
  user-visible surface with testing-only mechanism.
- **No fallback fixture-pattern auto-selection in T_VERIFIER_REJECT**
  — ships with ONE bad-fixture pattern (unbounded loop). If a future
  kernel accepts it, tester swaps to OOB-deref backup manually; no
  runtime auto-detect-and-switch (preserves test reproducibility).
- **No `T_KERNEL_VERSION_PROBE_UNIT` micro-test for the probe
  itself** — probe correctness on modern kernels is exercised
  implicitly by every test calling `attach`/`detach` (20 tests). A
  separate unit-test for `parse_major_minor` would add maintenance
  burden for low signal value. MVP-3+ candidate if exotic parse
  edge cases emerge.

### 5.25 MVP-2 Polish-2: netns isolation + CMake-gen `PIN_ROOT` + version-string sync + `inject_runt.py:37` comment fix (fourth and final MVP-2 pass, 2026-05-23) — amendment block

Append-only amendment closing the four remaining janitorial items
deferred to MVP-2 Polish-2 throughout MVP-1.1C and MVP-2 Sec/Perf/Robust.
**This is the final MVP-2 slice** — after Polish-2 ships, the MVP-2
sequence is fully closed and the project enters MVP-3 territory.

Scope is intentionally narrow: 4 items, all non-behavioural. No new
exit codes, no public C++ API changes, no CLI surface changes, no
on-the-wire / on-disk format changes. Items 1-3 are infrastructure
hardening (test isolation, build-pipeline robustness, version-sync
discipline); Item 4 is a one-line comment fix.

**Scope summary** — file:line targets per brief:

| ID | Where | One-line change |
|---|---|---|
| P1 | `tests/lib/common.sh` (`setup_veth`/`cleanup_veth` + new `NETNS`/`NSEXEC` constants + helper wraps) + test-body loader-invocation sweep across `tests/T_*.sh` | Q1 = **N3 (setup_veth-level wrap)**. setup_veth owns a per-PID netns `xdpmf_ns_$$`; veth pair lives inside it; loader/inject helpers run via `ip netns exec` wrapper. Pin paths remain host-global (bpffs is not netns-isolated). Two existing tests (T_BPFFS_ROOT_SYMLINK, T_MODE_NATIVE_UNSUPPORTED) opt out by not calling setup_veth. |
| P2 | `CMakeLists.txt` (configure-time extraction + `configure_file`) + new `tests/lib/pins.sh.in` template + `tests/CMakeLists.txt` (`PINS_SH` env wiring) + `tests/lib/common.sh:33-34` (replace hardcoded mirror with sourced value + integrity guards) | Q2 = **C1 (sed extraction in CMake)**. CMake `execute_process` extracts `XDPMF_BPFFS_ROOT` value from `src/common/mac_filter.h`, fails fast if empty; `configure_file` emits `${CMAKE_BINARY_DIR}/tests/pins.sh` with `PIN_ROOT="<extracted>"`; ctest `TEST_ENV` passes `PINS_SH=<path>`; common.sh sources it. |
| P3 | `CMakeLists.txt:13` (VERSION bump) + new `include/version.h.in` template + `CMakeLists.txt` (`configure_file` + include dir) + `src/loader/cli.cpp:6-21,103` (header include + drop hardcoded `kVersion` + use generated macro) + `CHANGELOG.md` (new `## [0.2.3]` section) | Q3 = **V1 (project(VERSION) source-of-truth)**. Bump `VERSION 0.1.0` → `VERSION 0.2.3`; generate `${CMAKE_BINARY_DIR}/include/version.h` from `@PROJECT_VERSION@`; cli.cpp `#include "version.h"`, drop hardcoded `kVersion`. CHANGELOG entry documents Polish-2. |
| P4 | `tests/inject/inject_runt.py:37` (single inline comment line) | Pure rewrite of one line to agree with the corrected lines 18-19 docstring (MVP-1.1C B1). No question — brief is explicit. |

#### Q1 decision — netns isolation mechanism = **Option N3 (setup_veth-level wrap)**

**Choice**: `tests/lib/common.sh setup_veth` creates a per-PID network
namespace `NETNS="xdpmf_ns_$$"`, creates the veth pair INSIDE it, and
runs loader + injectors + iface queries via `nsenter --net=/var/run/netns/${NETNS} …` (NSEXEC wrapper, per EDIT-15).
`cleanup_veth` deletes the netns (atomic teardown of veth + XDP) plus
the bpffs pin dir. Test bodies retain `${IFACE_A}`/`${IFACE_B}` and
`${PIN_DIR}` references unchanged; the only mechanical edit at test-body
level is `sudo -n "${LOADER_BIN}"` → `${NSEXEC} "${LOADER_BIN}"`
(`NSEXEC` exported by common.sh).

**Rationale**: N1 (per-test netns named after test) needs `${TEST_NAME}`
threading which breaks helper-signature stability — PID-only netns
achieves equivalent isolation under existing `RESOURCE_LOCK xdp_fixture`
serialization. N2 (one netns per ctest invocation) needs CMake fixture
hooks that don't compose cleanly with per-test setup_veth. N4 (decline)
leaves sysctl-per-iface mutations polluting the host's sysctl table —
PID-suffix closed the name-collision risk but NOT the sysctl-isolation
gap. N3 closes it cleanly.

**Helper-wrap topology** (centralized in `tests/lib/common.sh`):
- `NETNS="xdpmf_ns_$$"`, `NSEXEC="sudo -n nsenter --net=/var/run/netns/${NETNS}"` (per EDIT-15 — uses `nsenter --net=<path>`, NOT `ip netns exec`, to enter the netns WITHOUT unsharing the mount namespace; see "Mount-ns preservation" rationale at end of §5.25 Q1. `ip netns add` creates the `/var/run/netns/<name>` bind-mount that `nsenter` follows. `nsenter` is util-linux, universally present on Linux ≥ 2.6.x — no new dep vs iproute2's `ip netns exec`.)
- `setup_veth`: defensive netns-del + pin-dir rm → `ip netns add` → collision preflight (now scoped inside netns) → `${NSEXEC} ip link add veth pair` → sysctl/ifup steps all prefixed `${NSEXEC}` → final 0.5s quiesce
- `cleanup_veth`: `ip netns del` (atomic veth+XDP teardown) + `rm -rf "${PIN_DIR}"` (bpffs host-global, explicit removal preserved)
- Helpers re-pointed: `inject_eth`/`inject_runt` (`python3` → `${NSEXEC} python3`); `xdp_prog_id` (`ip -j link show` → `${NSEXEC} ip -j link show`); `read_stats`/`wait_for_stats_sum`/`prog_count` UNCHANGED (bpffs host-global, pin paths are same regardless of netns)
- Test-body sweep: every `sudo -n "${LOADER_BIN}"` callsite that follows `setup_veth` → `${NSEXEC} "${LOADER_BIN}"` (NSEXEC includes `sudo -n`)
- **Env-var-carrying loader invocations** (EDIT-14, 2026-05-23): tests that pass env vars to the loader (e.g. `XDPMF_BPF_OBJECT_PATH` per §5.24 Q4 testing override) MUST use the explicit `env`-after-NSEXEC form: `${NSEXEC} env XDPMF_BPF_OBJECT_PATH="${BAD_OBJ}" "${LOADER_BIN}" attach --iface "${IFACE_A}" ...`. **Rationale**: NSEXEC's outer `sudo -n` strips env (no `-E` — would conflict with `ip netns exec` child-launch semantic); `ip netns exec` passes env through cleanly to its child; explicit `env` AFTER the netns boundary sets the var directly in the loader child process. The pre-§5.25 idiom `VAR=... sudo -n -E "${LOADER_BIN}" ...` does NOT translate. Currently only T_VERIFIER_REJECT (§6.20) uses this idiom; future env-carrying tests follow the same pattern. Discovered by mint-tester during Phase B prep.

**Mechanical opt-out rule**: a test enters the netns iff it calls
`setup_veth`. There is no other axis. Tester verifies via
`grep -l 'setup_veth' tests/T_*.sh` — every file in that list gets
the NSEXEC sweep at its `sudo -n "${LOADER_BIN}"` callsites; every
file NOT in that list stays in host namespace and keeps `sudo -n`
loader invocations.

**Tests that ENTER the netns (call setup_veth → NSEXEC-sweep required)** — empirical roster grep-verified 2026-05-23 (EDIT-13):

- T_LOAD_ATTACH (§6.2), T_PASS_ALLOWED (§6.3), T_DROP_DENY (§6.4), T_DROP_MALFORMED (§6.5), T_IDEMPOTENT_RELOAD (§6.6), T_NEGATION_CONTROL (§6.7) — the MVP-1 veth-fixture set.
- T_ATTACH_ALIEN_REFUSAL (§6.9) — MVP-1.1B; calls setup_veth.
- T_SANITIZER_BUILD (§6.8) — MVP-1.1A; calls setup_veth at line 78 (end-to-end attach/inject/stats/detach via sanitized binary).
- T_ATTACH_TAG_MISMATCH (§6.14) — MVP-2 Sec; calls setup_veth.
- T_BPFFS_ROOT_SYMLINK (§6.15) — MVP-2 Sec; calls setup_veth at line 124 (loader needs `${IFACE_A}` for `--iface` resolution). Destructive bpffs manipulations on `/sys/fs/bpf/xdpmacfilter/` remain host-global (bpffs is not netns-isolated in 5.15+), but the test's loader invocations + iface resolution still benefit from the netns wrap (sysctl isolation, clean iface namespace).
- T_MODE_GENERIC_DEFAULT (§6.16), T_PERCPU_STATS_SUM (§6.18) — MVP-2 Perf; both call setup_veth.
- T_VERIFIER_REJECT (§6.20) — MVP-2 Robust; calls setup_veth.

Total: 13 tests in the NSEXEC-sweep set.

**Tests that STAY host-namespace (do NOT call setup_veth)** — empirical roster grep-verified 2026-05-23 (EDIT-13):

- T_BUILD (§6.1) — pure build cleanliness; no veth, no loader-vs-iface.
- T_CLI_HELP_VERSION (§6.10), T_CLI_CAPACITY (§6.11), T_CLI_BAD_MAC (§6.12), T_MODE_DETACH_REJECTS (§6.19) — pure CLI-parser tests; loader exits before any kernel call.
- T_DETACH_NOTHING (§6.13) — uses `lo` directly (every netns has its own `lo`; wrapping would break the test's intent). Stays host-namespace; loader invocation remains `sudo -n "${LOADER_BIN}"`. `RESOURCE_LOCK xdp_fixture` continues to serialize against destructive bpffs tests.
- T_MODE_NATIVE_UNSUPPORTED (§6.17) — uses `lo`; native-XDP-on-lo is universally unsupported in both host-ns and netns; the host-vs-netns axis is not what this test exercises.

Total: 7 tests in the opt-out set. (13 + 7 = 20, matches the regression invariant.)

**Brief framing correction (EDIT-13, 2026-05-23)**: the task brief described T_BPFFS_ROOT_SYMLINK + T_MODE_NATIVE_UNSUPPORTED as "the two tests that don't use the standard veth fixture". This is descriptively incorrect — T_BPFFS_ROOT_SYMLINK DOES call setup_veth at line 124 (needs `${IFACE_A}` for `--iface` resolution); T_SANITIZER_BUILD ALSO calls setup_veth at line 78 (end-to-end scenario under sanitizer). The brief's framing was a guess; the grep-verified roster above is authoritative. Bpffs is not netns-isolated, so the bpffs-symlink manipulations work identically inside or outside a netns — the netns just gives clean iface + sysctl scope. Discovered by mint-tester during Phase B prep.

**Regression invariant**: 20/20 ctest pass (or legitimately SKIP-77) post-refactor. Any test failing due specifically to netns wrap (loader can't find iface, inject socket bound wrong ns, etc.) is a wrap bug not a test bug.

**Mount-ns preservation** (EDIT-15, 2026-05-23, post-Phase-B finding by mint-tester): the kernel's bpffs is global (not netns-isolated); programs/maps pinned under `/sys/fs/bpf/xdpmacfilter/<iface>/` are visible from any netns **IF** the host's `/sys/fs/bpf` bpffs mount is visible in the caller's mount namespace. Crucially, `ip netns exec` is NOT just a network-ns enter — iproute2's implementation (`lib/namespace.c → netns_switch()`) ALSO unshares the mount namespace and remounts `/sys` as a fresh per-netns sysfs (so `/sys/class/net/<iface>` reflects netns-local state — iproute2's internal design intent). The remount detaches the host's `/sys/fs/bpf` bpffs mount — inside the child, `/sys/fs/bpf` appears empty, the loader's `mkdirat(root.fd(), iface, 0755)` fails with `ENOENT`, attach aborts with `LoadFailed` (exit 2). The original §5.25 spec used `ip netns exec` for NSEXEC and consequently violated the host-global-bpffs assumption; mint-tester's empirical Phase B run flagged 11/20 tests failing this way.

**Resolution**: use `nsenter --net=/var/run/netns/<name>` instead of `ip netns exec <name>`. `nsenter --net=<path>` enters ONLY the network namespace, leaving the caller's mount namespace untouched. Host's `/sys/fs/bpf` remains visible to the child; loader operations succeed. All Q1 N3 invariants hold under nsenter: veth in netns (network-ns op), sysctl writes hit `/proc/sys/net/*` netns-local copy (nsenter --net rebinds per-netns `/proc/sys/net` analogously per util-linux `nsenter(1)` + kernel semantics), AF_PACKET binds to netns-local ifaces, `if_nametoindex` resolves netns-local.

**Diagnostic recipe** (run as root to verify the distinction):
```
$ sudo ip netns add diag_ns
$ sudo ip netns exec diag_ns ls /sys/fs/bpf       # ← empty (mount-ns unshared)
$ sudo nsenter --net=/var/run/netns/diag_ns ls /sys/fs/bpf   # ← host bpffs visible
$ sudo ip netns del diag_ns
```

**Pin-path host-globalness invariant (revised, EDIT-15)**: loader inside the netns creates pins at `/sys/fs/bpf/xdpmacfilter/${IFACE_A}/{allowlist,stats}`, AND those pins are visible to host-namespace processes (read_stats.py, cleanup_veth's `rm -rf "${PIN_DIR}"`) because the host's bpffs mount remains in the caller's mount namespace under `nsenter --net`. PID-suffix in `IFACE_A` is the cross-PID pin-path uniqueness guarantee; per-iface pin dir cleaned by `sudo -n rm -rf "${PIN_DIR}"` in cleanup_veth (executed from host namespace — bpffs path is the same address either way). MVP-3+ alternative would be `unshare(CLONE_NEWNS)` + private per-test bpffs mount — exceeds Polish-2 scope.

#### Q2 decision — CMake-gen `PIN_ROOT` mechanism = **Option C1 (sed extraction in CMake)**

**Choice**: configure-time `execute_process(COMMAND sed -nE …)` extracts the quoted value of `XDPMF_BPFFS_ROOT` from `src/common/mac_filter.h`; FATAL_ERROR fail-fast if empty; `configure_file()` emits shell stub `${CMAKE_BINARY_DIR}/tests/pins.sh`; ctest `TEST_ENV` carries `PINS_SH=…`; `tests/lib/common.sh` sources `${PINS_SH}` and consumes `PIN_ROOT`.

**Rationale**: C2 (`cpp -E`) needs include-path resolution for a single string macro — sed is exactly as reliable, zero new tool dep. C3 (.h.in template) reorganizes source-of-truth, makes `mac_filter.h` itself a generated artifact — exceeds Polish-2 scope. C4 (decline) keeps the MVP-1.1C comment marker but doesn't prevent silent rename drift; C1 closes that at one configure-time step.

**Impl substitution flexibility**: impl MAY swap `sed` for `file(READ)` + `string(REGEX MATCH)` if external sed dep is unwelcome — externally observable result (generated `pins.sh` with extracted value) is identical.

**Integrity coverage**: configure-time FATAL_ERROR (empty `XDPMF_BPFFS_ROOT`) + runtime `:?` guards in common.sh (`PINS_SH` unset OR `PIN_ROOT` unset → test exit). Every veth-fixture test exercises sourcing path indirectly. No dedicated `T_PINS_CODEGEN` ctest entry needed.

#### Q3 decision — Version-string sync mechanism = **Option V1 (project(VERSION) source-of-truth + configure_file → version.h)**

**Choice**: `CMakeLists.txt:13 VERSION 0.1.0` → `VERSION 0.2.3` (semver patch-bump — Polish-2 is maintenance release; no new features, no breaking changes). New `include/version.h.in` template → `${CMAKE_BINARY_DIR}/include/version.h` via `configure_file`. `src/loader/cli.cpp` `#include "version.h"`, drops hardcoded `kVersion`, uses `XDPMF_VERSION_STRING` macro. `CHANGELOG.md` gains `## [0.2.3] — 2026-05-23` entry.

**Rationale**: V2 (CHANGELOG as source-of-truth) inverts the dependency wrong — CHANGELOG should document the build, not gate it (typo → build failure). V3 (decline) leaves operators with two different version numbers (changelog vs `--version`) — MVP-1.1C B4 deferral entry flagged exactly this gap.

**Impl details**:
- `include/version.h.in`: `#define XDPMF_VERSION_STRING "@PROJECT_VERSION@"`
- `target_include_directories(xdpmacfilter PRIVATE ${CMAKE_BINARY_DIR}/include)` — non-SYSTEM (want diagnostics on our own template, unlike SYSTEM-suppressed skel.h)
- cli.cpp: `#include "version.h"`, delete line 21 `kVersion` constant, swap `kVersion` → `XDPMF_VERSION_STRING` at line 103 `version_text()` (impl MAY retain a local `constexpr std::string_view kVersion{XDPMF_VERSION_STRING}` alias for readability — same output either way)
- CHANGELOG.md: new `## [0.2.3]` block above `## [0.2.2]` summarizing Polish-2; Build-pace table gains a row

#### Q4 decision — T_CLI_HELP_VERSION test interaction = **Option T1 (no test edit)**

**Choice**: `tests/T_CLI_HELP_VERSION.sh` NOT modified. Existing ERE `[0-9]+\.[0-9]+\.[0-9]+` at line 81 matches `xdpmacfilter 0.2.3` without change; T1 is forward-compatible.

**Rationale**: T2 (strict exact-match) couples test maintenance to every version bump — low signal value. If future operational need emerges (distro packaging asserting version monotonicity), T2-style assertion added then, not preemptively.

#### Item 4 — `tests/inject/inject_runt.py:37` inline comment fix

Pure rewrite of one line. Current: `# 13 bytes: complete 6-byte dst MAC + partial src MAC.` Becomes: `# 13 bytes: full 6-byte dst MAC + full 6-byte src MAC + 1 ethertype byte.` Agrees with the lines 18-19 docstring (corrected in MVP-1.1C B1). Byte literals at lines 41-43 untouched (brief explicit OOS). One-line edit. Zero behaviour change.

#### Verifiable invariants for reviewer

- `git diff main -- src/loader/cli.cpp` shows: `#include "version.h"` added; `kVersion` constant deleted; `version_text()` switched to `XDPMF_VERSION_STRING`. NO other functional changes.
- `git diff main -- src/loader/loader.{hpp,cpp}` shows ZERO functional changes.
- `git diff main -- src/common/mac_filter.h` shows ZERO changes (header is codegen source-of-truth).
- `git diff main -- src/bpf/` shows ZERO changes.
- `git diff main -- CMakeLists.txt` shows: VERSION → 0.2.3; new `execute_process` for `XDPMF_BPFFS_ROOT`; new `configure_file` for `version.h`; new `configure_file` for `pins.sh`; target include-dir extension.
- `git diff main -- tests/CMakeLists.txt` shows: TEST_ENV gains `PINS_SH=…`.
- `git diff main -- tests/lib/common.sh` shows: NETNS/NSEXEC constants; PIN_ROOT block sourcing+guards; setup_veth/cleanup_veth rewritten for netns; inject_eth/inject_runt/xdp_prog_id prefixed; read_stats/wait_for_stats_sum/prog_count UNCHANGED.
- `git diff main -- tests/T_*.sh` shows: loader-invocation sweep `sudo -n "${LOADER_BIN}"` → `${NSEXEC} "${LOADER_BIN}"` in veth-fixture tests; opt-out tests UNCHANGED.
- `git diff main -- tests/inject/inject_runt.py` shows: ONE comment line text change at `:37`.
- New committed files: `include/version.h.in`, `tests/lib/pins.sh.in`.
- Build-time generated files NOT committed: `${CMAKE_BINARY_DIR}/include/version.h`, `${CMAKE_BINARY_DIR}/tests/pins.sh` (covered by existing `build/` gitignore).
- `xdpmacfilter --version` post-build: `xdpmacfilter 0.2.3` (single line, ends with newline).
- 20/20 ctest pass on dev host; T_BPFFS_ROOT_SYMLINK + T_MODE_NATIVE_UNSUPPORTED specifically re-verified post-refactor (netns opt-out candidates).
- `XDPMF_SANITIZERS=ON` build clean.

Evidence: `mint/task-brief.md` MVP-2 Polish-2 brief (Items 1-4 + Q1-Q4); §7 OOS lines 3033-3049 (3 deferred entries — all now SHIPPED via amended §7); `mint/hybrid-review.md` items M3 / M5 / M6 (inject_runt:37 docstring drift, PIN_ROOT silent coupling, version-string drift); `mint/review.md` MVP-1.1C OUT-OF-TRIANGULATION advisory (inject_runt:37 inline comment, deferred to Polish-2).

### MVP-2 Polish-2 additions to OOS (per §5.25)

- **No `T_PINS_CODEGEN` dedicated test** (Q2 sub-decision) — codegen integrity is covered by configure-time fail-fast PLUS runtime `:?` guards in common.sh. Every veth-fixture test exercises sourcing indirectly. Standalone codegen test would be redundant; reconsider if codegen gains conditional/branched extraction logic.
- **No T2 strict version assertion in T_CLI_HELP_VERSION** (Q4) — existing ERE is forward-compatible across version bumps; T2's exact-match would couple test maintenance to every release.
- **No netns isolation for tests that don't call `setup_veth`** (Q1 N3 carve-out) — T_BPFFS_ROOT_SYMLINK, T_MODE_NATIVE_UNSUPPORTED, T_CLI_*, T_DETACH_NOTHING, T_BUILD, T_SANITIZER_BUILD all stay host-namespace.
- **No parallel ctest execution post-netns refactor** — `RESOURCE_LOCK xdp_fixture` continues to serialize veth-fixture tests. Pin paths remain host-global; lifting RESOURCE_LOCK is MVP-3+ work (per-PID bpffs sub-root or global lockfile).
- **No netns-based bpffs isolation** — `/sys/fs/bpf` is host-global mount; bpffs not netns-isolated in 5.15+ (would require `unshare(CLONE_NEWNS)` + private mount, exceeds Polish-2 scope).
- **No `--version` build-id / commit-hash reporting** — V1 ships only the `PROJECT_VERSION` triplet. Git-describe / build-id is MVP-3+ release-engineering.
- **No automatic CHANGELOG entry generation** — `[0.2.3]` entry manually authored. Auto-generation from git log is MVP-3+.
- **No `inject_runt.py` body / bytes rewrite** — brief explicit OOS for Item 4; only the inline comment at `:37` touched. Byte sequence + `socket.send()` + Python imports all UNCHANGED.
- **No `cpp -E` / `string(REGEX MATCH)` / `.h.in` codegen alternatives** (Q2 C2/C3 rejected) — sed extraction is chosen; impl MAY swap to `file(READ)` + `string(REGEX MATCH)` for portability, externally-observable result invariant.
- **No `CHANGELOG.md`-as-source-of-truth (Q3 V2 rejected)** — CHANGELOG documents the build, not gates it. `project(VERSION)` stays canonical CMake source-of-truth.

### 5.26 MVP-3.1: config-first foundation (Composite 6 cycle 1, 2026-05-24) — amendment block

Append-only amendment landing **Composite 6 — Config-first foundation**
per `mint/architecture-v2.md` lines 147–168 (round-2 rework). This is
the **first MVP-3 slice**, the **largest mint slice to date**
(~250-300 LOC source + ~120 LOC test, 5-7 ctests; ~3× MVP-2 Sec / Perf /
Robust), and the **architectural foundation** for the long-horizon
system: every byte of cycle-1 surface is load-bearing through MVP-3.N
(zero deprecation work allowed). With §5.26 shipped, MVP-2 is fully
closed and the project enters MVP-3 territory.

Six interlocking pieces land together (deliberately bundled — carving
them apart creates the throwaway surface Composite 6 was selected to
avoid):

| # | Where | One-line |
|---|---|---|
| 1 | `src/loader/` → `src/lib/` + `src/cli/` (per Q1 R1 minimum split + STATIC `xdpmf_internal`) | Mechanical relocation; zero behaviour change. Existing 20 ctests pass after this item alone (commit-1 boundary). |
| 2 | NEW `src/lib/yaml_subset.{cpp,hpp}` + NEW `src/lib/config.{cpp,hpp}` (per HG1 custom subset + Q5 SV2 + Q-HG1 accepted grammar) | Custom ~150-LOC YAML parser + typed config validator. `LoaderError::ConfigError = 9` new enumerator. |
| 3 | EDIT `src/bpf/mac_filter.bpf.c` (extend with `ARRAY_OF_MAPS[2]` outer + `active_idx` ARRAY[1] + per-slot `defaults` ARRAY[2] + inner-deref read pattern); EDIT `src/common/mac_filter.h` (per Q6 M1: new map name constants + ruleset count) | Atomic apply via Q2 A1 mechanism. Single u32 `active_idx` write = atomic ruleset+default swap. |
| 4 | NEW `src/cli/apply.{cpp,hpp}` (apply orchestrator); EDIT `src/cli/cli.cpp` (Q4 G1 subcommand grammar) | `xdpmacfilter apply -f <file> --iface <iface>` subcommand. `--allow <mac>` per Q3 BC1 synthesizes in-memory config and feeds the same orchestrator. |
| 5 | EDIT `src/lib/loader.cpp` (post-attach: pin link at `${XDPMF_BPFFS_ROOT}/<iface>/link`; on attach entry: detect existing pin → idempotent reattach; on detach: unpin before detach) | P0a per HG2. `T_LINK_PERSIST_ACROSS_LOADER_EXIT` is the survival contract. |
| 6 | EDIT `src/lib/loader.cpp` (parse `XDPMF_TRUST_MODEL` env var at attach entry; gate §5.4 alien-program check on `strict`; stderr-log active mode unconditionally) | Per HG3. `strict` (default) preserves all MVP-2 identity-gate behaviour; `fleet` relaxes §5.4 ONLY. §5.19 + §5.22 stay enforced in both modes. |

#### Inherited human-gate decisions (closed BEFORE architect — NOT re-opened)

**HG1 — YAML parser = custom ~150-LOC subset** (Open Q #10 resolved):
the project's "zero non-standard deps" load-bearing value (per
`cli.cpp:1-3`) rules out yaml-cpp (70KB .so + transitive libstdc++) and
vendored single-header alternatives (rapidyaml etc., +5-10K LOC). The
accepted subset grammar is architect-controlled (see §5.26 Q-HG1
sub-section below); anything outside the subset → `ConfigError` (exit 9)
with `unsupported YAML feature: <feature>` stderr.

**HG2 — P0a (`bpf_link__pin()`) folded into MVP-3.1** (Open Q #12
resolved): `bpf_link__pin()` is standard libbpf 1.x API (Cilium /
Katran production use; ABI stable since 5.7). `T_LINK_PERSIST_ACROSS_LOADER_EXIT`
IS the verification of the libbpf API behaviour. If the API misbehaves
at Phase B, the standard mint inline-merge / architect-amendment
pattern (MVP-2 Sec/Robust precedent) handles it; no separate
preliminary cycle is carved.

**HG3 — `XDPMF_TRUST_MODEL` = single switch `strict|fleet`** (Open Q
#8 resolved): one env var, two literal values. `strict` (unset →
default `strict`) preserves all MVP-2 identity-gate behaviour
(§5.4 alien-program check + §5.19 O_PATH bpffs ops + §5.22 tag-check
all enforced). `fleet` relaxes ONLY the §5.4 alien-program check;
§5.19 + §5.22 stay enforced in both modes. Unknown values →
`ConfigError` exit 9 at startup with `unknown trust model: <value>`
(fail-closed). Audit story: one env var → one state, greppable in
logs / Prometheus-alertable as `xdpmf_trust_model_label`. Asymmetric
reversibility: single → multi is cheap to add later (additional
override env vars on top); multi → single is a breaking surface
change.

#### Q1 decision — Internal code reorg = **R1 (minimum split) + STATIC** — because

**Choice**: `src/loader/*` relocates to two directories:
- `src/lib/`  — `loader.{cpp,hpp}`, `raii.hpp`, `yaml_subset.{cpp,hpp}` (NEW), `config.{cpp,hpp}` (NEW)
- `src/cli/`  — `cli.{cpp,hpp}`, `main.cpp`, `apply.{cpp,hpp}` (NEW)
- `src/common/` and `src/bpf/` UNCHANGED locations.

One new CMake STATIC library target `xdpmf_internal` aggregates all
`src/lib/*.cpp` (loader + config + yaml). The `xdpmacfilter` binary
target moves to `src/cli/CMakeLists.txt` and links `xdpmf_internal`.
No installed headers; no SONAME; no public ABI surface.

**Rationale** (R1 vs R2 vs R3):

- R2 (three-way split: `src/lib/` + `src/config/` + `src/cli/`, two
  static targets) is cleaner separation but adds a CMake target with
  zero current consumer benefit; promotion R1 → R2 is a `git mv` +
  one CMake line when MVP-3.4's exporter binary lands. Defer the cost
  to when the value materializes.
- R3 (OBJECT lib) is equivalent until a second binary appears; STATIC
  exposes link-time correctness immediately (unresolved symbol → link
  fail at lib-build time, not at first consumer link). STATIC is the
  conventional choice and matches the brief recommendation.
- `yaml_subset` + `config` live under `src/lib/` (not `src/cli/`)
  because their consumer is `apply.cpp` (in `src/cli/`) — inverting
  the dependency would re-create the M1 backwards-layer that §5.21 A1
  closed in MVP-1.1C.

**Identity helpers** (§5.19 + §5.22 anon-namespace code) STAY inside
`loader.cpp`'s anon namespace; no separate `identity.{cpp,hpp}` is
introduced in this cycle. Brief Item 6 said "EDIT `src/lib/identity.cpp`
IF §5.4 check lives there" — by Q1 R1 minimum-split discipline, it
doesn't. Promotion to an `identity` sub-module is MVP-3.4+ work (when
per-rule counter machinery may pressure the anon namespace).

**`xdpmacfilter` binary placement**: build artifact at
`${CMAKE_BINARY_DIR}/src/cli/xdpmacfilter` (was `build/src/loader/xdpmacfilter`).
`tests/lib/common.sh:LOADER_BIN` updates to the new path; this is
the only test-infrastructure path change. The binary NAME stays
`xdpmacfilter` (per brief §1 explicit OOS: `xdpmacfilter → xdpfilter`
rename is MVP-3.12; architecture-v2.md Open Q #11 resolved at
human-gate-pre-architect to KEEP `xdpmacfilter`).

#### Q2 decision — Atomic apply mechanism = **A1 (active_idx in separate `ARRAY[1]`)** — because

**Choice**: BPF program reads a dedicated `BPF_MAP_TYPE_ARRAY` of size
1 holding the current active inner-map index (`__u32`, values {0, 1}),
then performs `bpf_map_lookup_elem(&rulesets_outer, active_idx_ptr)` to
obtain the inner-map fd, then performs `bpf_map_lookup_elem(inner,
&src_mac)` for the actual MAC check. Userspace atomic-swap = single
`bpf_map_update_elem(active_idx_map, &zero, &new_idx, BPF_ANY)` —
atomicity of the `__u32` write is kernel-guaranteed for aligned word
stores on all supported architectures.

**Rationale** (A1 vs A2 vs A3):

- A2 (active-flag-as-sentinel-key in each inner map): BPF program
  would iterate outer slots and pick the active one. Adds branch +
  lookup on every hot-path packet; A1 has one extra `bpf_map_lookup_elem`
  AND lets the verifier optimize the inner-deref pattern
  (well-trodden Cilium-style). A2 is "too clever".
- A3 (`BPF_F_REPLACE` direct on inner via `bpf_map_update_batch`): NOT
  atomic across multiple keys. `bpf_map_update_batch` issues per-key
  syscalls (or kernel-internal per-key updates with libbpf 1.1+ batch
  ops); a concurrent BPF read between two key-update transactions
  sees a half-applied state. Defeats T_APPLY_ATOMIC_SWAP_NO_DROP's
  promise. Hard-rejected.
- A1 has one correctness gotcha: the BPF program MUST handle the case
  where `bpf_map_lookup_elem(&rulesets_outer, &active_idx)` returns
  NULL (verifier-required NULL check on map-of-maps lookup). Treat
  NULL as "drop with STAT_DROP_DENY" (defensive; never reachable in
  practice because userspace populates both outer slots at first
  attach). See "BPF program flow" sub-section below.

**Race window analysis** (architecture-v2.md line 330 risk row,
mitigated): can the `active_idx` flip happen BETWEEN the BPF
program's `bpf_map_lookup_elem(&active_idx_map, &zero)` and the
subsequent `bpf_map_lookup_elem(&rulesets_outer, &active_idx)`? Yes
(BPF program is preemption-disabled on its CPU but userspace
`bpf_map_update_elem` is not blocked by it on other CPUs). Consequence
is benign: the program reads `active_idx == 0`, looks up
`rulesets_outer[0]` (OLD inner — valid pre-swap ruleset). OR reads
`active_idx == 1` POST-flip, looks up `rulesets_outer[1]` (NEW inner —
valid post-swap ruleset). Either way the program sees a consistent
ruleset; no half-applied state is visible. The new inner is FULLY
populated BEFORE the flip (userspace writes inactive slot then flips),
so even the post-flip read hits a complete ruleset.

#### Q2-extension — `default_action` participates in atomic swap

The schema's `default_action` field (drop / pass) MUST swap atomically
with the inner ruleset. A naive single `defaults_map = ARRAY[1]` written
BEFORE the `active_idx` flip would expose a gap where the NEW default
applies to the OLD inner (between defaults-write and flip), potentially
allowing OR dropping traffic the OLD ruleset would have decided
oppositely.

**Mechanism**: `defaults_map` is `BPF_MAP_TYPE_ARRAY` of size **2** (not
1), indexed by `active_idx` — same indexing key as the outer map of
maps. BPF program reads `defaults_map[active_idx]` AFTER inner-map miss.
Userspace apply ordering:

1. Write `defaults_map[inactive_idx] = new_default` (`__u32`, 0=drop, 1=pass).
2. Populate `inner[inactive_idx]` with the new rules.
3. Atomic flip: `active_idx_map[0] = inactive_idx`.
4. Old defaults slot and old inner remain populated (one-deep
   rollback history; overwritten on next apply).

Same race-window benignity as Q2: the program reads `active_idx` once,
uses the SAME value for both the inner lookup and the defaults lookup;
swap atomicity is single-u32 = guaranteed.

This adds **one** `BPF_MAP_TYPE_ARRAY` (size 2, key u32, value u32) +
one map-name constant in `src/common/mac_filter.h`. Acceptable cost.

#### Q3 decision — `--allow <mac>` backward-compat = **BC1 (silent shorthand)** — because

**Choice**: `xdpmacfilter attach --iface <iface> --allow MAC[,MAC...]`
keeps working byte-identically. The CLI parser synthesizes an in-memory
`xdpmf::Config { default_action: Drop, rules: [ {id: 0, action: Pass,
match: {mac: MAC_0}}, {id: 1, action: Pass, match: {mac: MAC_1}}, ... ] }`
and feeds it through the same apply orchestrator that `apply -f`
invokes. NO stderr deprecation warning; NO exit-code change; NO
machine-format change.

**Rationale** (BC1 vs BC2 vs BC3):

- BC2 (deprecation warning) is the "honest about path forward" choice
  but pollutes MVP-2 ops scripts' stderr with noise the operator can't
  act on until MVP-3.3+ ships the systemd/Ansible story. Cost-benefit
  unfavourable in MVP-3.1 — promote to BC2 at MVP-3.4 when exporter
  binary lands and operator docs converge on apply-only.
- BC3 (drop) breaks every existing ctest invocation; would require
  rewriting all 20 existing ctests to use the new surface. Massive
  scope creep against brief's "20 existing ctests pass byte-equivalent
  invocations" Done-Definition item. Hard-rejected.
- BC1 satisfies the "20 ctests pass byte-identically" invariant AND
  exercises the new apply orchestrator on every `--allow` invocation
  — meaning every MVP-2 test indirectly regression-tests the apply
  path. Free coverage.

**Synthesis details**:

- `attach --allow A,B,C` (or `--allow A --allow B --allow C`) →
  synthesized config:
  ```
  default_action: drop
  rules:
    - {id: 0, action: pass, match: {mac: A}}
    - {id: 1, action: pass, match: {mac: B}}
    - {id: 2, action: pass, match: {mac: C}}
  ```
  (rule IDs assigned by the CLI synthesizer in the order MACs appear
  on the command line; deduplication eliminates duplicate MACs BEFORE
  ID assignment).
- `attach --iface <X>` with NO `--allow` (per §5.7 "empty allow-list =
  drop-all") → synthesized config:
  ```
  default_action: drop
  rules: []
  ```
- The synthesized config is never written to disk; it lives in memory
  as `xdpmf::Config` and feeds directly into
  `xdpmf::apply_config(ifindex, config)` (see Interfaces below).

#### Q4 decision — Apply subcommand grammar = **G1 (subcommand, verb-first)** — because

**Choice**: `xdpmacfilter apply -f <file> --iface <iface>` is the
canonical new invocation. Existing MVP-2 invocations (`attach`,
`detach`, `--help`, `--version`) are UNCHANGED. `apply` is a third
subcommand alongside `attach` / `detach`.

**Rationale** (G1 vs G2 vs G3):

- G2 (flag form `--apply -f <file>`) is grammatically awkward for a
  subcommand that has its own dedicated flags (`-f`, `--iface`); flag-form
  encoding makes dispatch ambiguous (which flags belong to which
  "verb"?). Rejected.
- G3 (rename `bypass`/`detach` to subcommands now): `bypass` doesn't
  exist in MVP-2 (it's MVP-3.4 manual-bypass-primitive scope). `detach`
  is ALREADY a subcommand. G3 reduces to "no change needed for MVP-3.1",
  which is what we're picking. The cosmetic future-rename of
  `detach`-as-flag (it isn't a flag) is a no-op.
- G1 satisfies the "20 existing ctests pass byte-identical invocations"
  invariant cleanly; `apply -f` joins the subcommand set as a peer.

**Subcommand-dispatch contract** in `cli.cpp`:

- `attach` → existing parser; emits `ParsedCommand::Attach{AttachConfig}` (now wrapping the new `Config` per Q3 BC1).
- `detach` → existing parser; emits `ParsedCommand::Detach{DetachConfig}`.
- `apply` → NEW parser branch; emits `ParsedCommand::Apply{ApplyConfig}`.
- `--help` / `--version` → as before (`--help` text updated to LIST `apply` alongside `attach`/`detach`).
- Unknown subcommand → exit 1 with `unknown subcommand: '<arg>'` (existing pattern, see `cli.cpp:245`).

**Apply parser grammar** (in `cli.cpp`):

- Required: `-f <path>` (config file path; relative paths resolved
  against CWD; non-existent / unreadable → exit **1** `apply: config
  file '<path>' does not exist`-style usage error, NOT exit 9 — file-IO
  failure is a CLI usage error, not a config-content failure; this
  distinction matters for ops-script error handling).
- Required: `--iface <iface>` (per architecture-v2.md line 154 sketch;
  even though the config file MAY contain `interface: <name>`, the
  CLI `--iface` is authoritative — closes any ambiguity if the
  operator mistypes the filename → wrong interface).
- Validation: if config file contains `interface:` field AND its value
  differs from `--iface <X>`, the apply orchestrator throws `ConfigError`
  exit **9** with stderr `config error: interface mismatch (file
  declares '<Y>', --iface is '<X>')`. Strict equality check;
  case-sensitive.
- No additional flags in cycle 1 (no `--dry-run`, no `--validate-only`,
  no `--diff-against-current` — all explicitly OOS per §7 additions).

#### Q5 decision — Schema versioning = **SV2 (optional, default 1)** — because

**Choice**: `schema_version` is an OPTIONAL top-level field. If absent
→ treated as `1`. If present → MUST be in the supported-versions
set (currently `{1}`). Unsupported value → `ConfigError` exit 9 with
stderr `config error: unsupported schema_version: <n> (supported: 1)`.

**Rationale** (SV1 vs SV2 vs SV3):

- SV1 (mandatory) forces every minimal test fixture + every doc
  example to carry the boilerplate; raises the floor for "minimal
  valid config" unnecessarily. Reject.
- SV3 (defer until first breaking change) leaves no clean migration
  path at MVP-3.3+ when YAML semantics might evolve (new top-level
  fields, semantic clarifications on `default_action`, etc.). Reject.
- SV2 has both: minimal configs work without ceremony (smallest valid
  fixture: `default_action: drop` on one line); and once an operator
  opts into `schema_version:` the field is REAL (validator enforces
  the supported-set rather than treating the field as a comment).
  Future breaking change at MVP-3.3+ ships as `schema_version: 2`
  with `1` still accepted; supported-set becomes `{1, 2}`.

**Migration policy** for future cycles:

- New top-level fields → MUST stay backward-compatible with
  `schema_version: 1` parsers (i.e. new fields ignored if `schema_version: 1`).
- New rule-types in `match:` (e.g. CIDR at MVP-3.2) → MUST be
  rejected by a `schema_version: 1` config; documented via
  `unsupported match type 'cidr' for schema_version 1` stderr.
- Change EXISTING field semantics → REQUIRES bumping to
  `schema_version: 2` (or wider); old semantics stay accessible via
  `schema_version: 1` configs as long as the supported-set includes 1.

#### Q6 decision — BPF map definitions placement = **M1 (extend `src/common/mac_filter.h`)** — because

**Choice**: all new map name constants
(`XDPMF_MAP_ACTIVE_IDX_NAME = "active_idx"`,
`XDPMF_MAP_RULESETS_OUTER_NAME = "rulesets"`,
`XDPMF_MAP_INNER_A_NAME = "allowlist_a"`,
`XDPMF_MAP_INNER_B_NAME = "allowlist_b"`,
`XDPMF_MAP_DEFAULTS_NAME = "defaults"`)
+ the new ruleset-count constant (`XDPMF_RULESET_COUNT = 2`)
+ the link pin filename constant (`XDPMF_LINK_PIN_BASENAME = "link"`)
added to `src/common/mac_filter.h` alongside the existing
`XDPMF_MAP_ALLOWLIST_NAME` / `XDPMF_MAP_STATS_NAME`. Single source of
truth; header gains ~12 lines.

**Existing constant fate**: `XDPMF_MAP_ALLOWLIST_NAME = "allowlist"`
is KEPT (used by the BPF `__inner_map` template definition; the
verifier-time inner-map declaration uses this name so libbpf wires
the inner-map prototype to the two ARRAY_OF_MAPS slots). The
SHIPPED pin at `/sys/fs/bpf/xdpmacfilter/<iface>/allowlist` is
REPLACED by:
- `/sys/fs/bpf/xdpmacfilter/<iface>/allowlist_a` (inner slot 0)
- `/sys/fs/bpf/xdpmacfilter/<iface>/allowlist_b` (inner slot 1)
- `/sys/fs/bpf/xdpmacfilter/<iface>/rulesets` (outer ARRAY_OF_MAPS)
- `/sys/fs/bpf/xdpmacfilter/<iface>/active_idx` (ARRAY[1])
- `/sys/fs/bpf/xdpmacfilter/<iface>/defaults` (ARRAY[2])
- `/sys/fs/bpf/xdpmacfilter/<iface>/stats` (UNCHANGED from §5.23)
- `/sys/fs/bpf/xdpmacfilter/<iface>/link` (NEW per HG2 P0a)

The existing 20 ctests do NOT poke `allowlist` pin path directly
(grep-confirmed against `tests/lib/common.sh` and `tests/T_*.sh` —
only `stats` is read via `bpftool map dump pinned ${PIN_DIR}/stats`);
they observe behaviour through `stats` (UNCHANGED) and via traffic
injection. Therefore the pin-name change is invisible to the existing
test surface.

**Rationale** (M1 vs M2):

- M2 (new `src/common/config_maps.h` sibling) adds a file with one
  declaration block; doesn't simplify anything in cycle 1 (the BPF
  `.bpf.c` includes both, the userspace orchestrator includes both).
  Promote M1 → M2 at MVP-3.4 if `rules` + `action_table` maps add
  enough surface to make the unified header noisy. Defer the cost.

#### Q-HG1 — Accepted YAML subset grammar (architect decision under HG1)

The custom parser in `src/lib/yaml_subset.{cpp,hpp}` accepts EXACTLY
this subset of YAML 1.2 (anything else → `ConfigError` exit 9 with
stderr starting `xdpmacfilter: config error: <feature>` + 1-based
line:col + `<file>` path):

| Construct | Accepted? | Notes |
|---|---|---|
| Top-level: block mapping | YES | Only allowed top-level form. Flow-form `{a: 1, b: 2}` at top-level → reject. |
| Block mapping (nested) | YES | `key: value` per line. Keys MUST be bareword strings (no quoting; no `:`/`#`/whitespace in key). |
| Block sequence | YES | `- item` per line. Used for `rules:` list. |
| Flow mapping `{...}` | NO | Reject: `flow-style mapping not supported`. |
| Flow sequence `[...]` | NO | Reject: `flow-style sequence not supported`. |
| String — double-quoted `"..."` | YES | Escape sequences: `\\`, `\"`. Other escapes (`\n`, `\u`, etc.) → reject `unsupported escape sequence`. Multi-line quoted → reject. |
| String — single-quoted `'...'` | YES | Only `''` (escaped single-quote) accepted as escape. |
| String — bareword (plain) | YES | Non-empty sequence of `[A-Za-z0-9._\-:]`. `:` allowed in value (e.g. MAC `AA:BB:CC:DD:EE:FF`) but NEVER in a key. No leading/trailing whitespace. |
| Integer scalar | YES | Signed decimal `-?[0-9]+`. No `0x`/`0o`/`0b`/`_` separators. Range `[INT32_MIN, INT32_MAX]`; out-of-range → reject `integer out of range`. |
| `null` / `~` | YES | Both spellings accepted. Bare empty value (`key:` with nothing after EOL) ALSO null. |
| Boolean `true` / `false` | NO (cycle 1) | Schema has no boolean field yet. Bareword `true`/`false` → reject `boolean scalars not supported`. |
| Comments | YES | `#` to end-of-line. Inline comments after a value accepted (`key: value  # comment`). |
| Anchors (`&anchor`) / aliases (`*alias`) | NO | Reject `anchors/aliases not supported`. |
| Tags (`!type`) | NO | Reject `explicit tags not supported`. |
| Block scalars (`\|`, `>`) | NO | Reject `block scalar not supported`. |
| Multi-document (`---`) | LIMITED | Leading `---` (no following content) OPTIONALLY accepted as a no-op marker (YAML convention); a SECOND `---` mid-stream → reject `multi-document streams not supported`. |
| BOM | NO | UTF-8 BOM at file start → reject `BOM not supported`. |
| Tabs in indentation | NO | Reject `tab in indentation`. Spaces only. |
| Indentation width | flexible | First nested block sets the width (MUST be ≥ 1 space); subsequent lines at the same nesting MUST match exactly. Inconsistent indent → reject `inconsistent indentation`. |
| Trailing whitespace | accepted | Stripped silently. |
| File size cap | enforced | > 1 MiB → reject `config file exceeds 1 MiB limit`. DoS guard. |
| Scalar length cap | enforced | > 4096 bytes per scalar → reject `scalar exceeds 4 KiB limit`. DoS guard. |
| Nesting depth cap | enforced | > 8 levels → reject `nesting depth exceeds 8`. DoS guard. |
| Duplicate map keys | NO | Repeated key in same mapping → reject `duplicate key: <name>`. Strict (YAML 1.2 says "should fail" — we say "must"). |
| Trailing newline | optional | File may or may not end with `\n`. |

**Stderr discipline for rejections**: every rejection emits a
single-line stderr `xdpmacfilter: config error: <feature>: <file>:<line>:<col>`
where `<line>:<col>` is the 1-based position in the YAML source. The
parser MUST track line/col across reads (single-pass cursor). Assertion
in §6.22.

**Why this subset and not larger / smaller**:

- Larger (full YAML 1.2) requires ~5-10K LOC. Custom parser stays
  ~150-250 LOC. Brief HG1 explicit fence.
- Smaller (e.g. KEY=VALUE-with-list-extension per architecture-v2.md
  T-architect's E.4) doesn't express `rules:` list-of-mappings
  cleanly. Block-mapping + block-sequence + scalars is the MINIMUM
  that expresses the schema (see §5.26 schema sub-section below)
  without cosmetic compromise.
- Anchors / aliases / tags are the highest-LOC features per "yes"
  with the least operator-visible value for a config of this size.
  Always reject — operators who need them are using full YAML tooling
  elsewhere and can pre-render to flat form before feeding us.

#### §5.26 schema (data on disk)

The on-disk YAML at `/etc/xdpfilter/<iface>.yaml` has the following
shape (cycle 1):

```
# All fields optional EXCEPT default_action; rules defaults to empty.
schema_version: 1                  # optional; default 1; supported set {1}
interface: eth0                    # optional; if present MUST equal CLI --iface or exit 9
default_action: drop               # REQUIRED; values: "drop" | "pass" (no other)
rules:                             # optional; list (possibly empty)
  - id: 0                          # REQUIRED u32; unique within rules; range [0, 63]
    action: pass                   # REQUIRED; values: "pass" | "drop" (no other)
    match:                         # REQUIRED mapping
      mac: "AA:BB:CC:DD:EE:FF"     # REQUIRED in cycle 1 (only match type allowed)
  - id: 1
    action: pass
    match:
      mac: "11:22:33:44:55:66"
```

**Cycle-1 schema rules** (validator enforces; all → exit 9 on failure):

1. `default_action` REQUIRED; ∈ {`drop`, `pass`}; any other value
   (including `null`) → `default_action must be 'drop' or 'pass'`.
2. `rules` MAY be absent (treat as empty list). Empty `rules:` (key
   present, no `- ` entries) is equivalent. `rules: []` is REJECTED
   (flow-form not in subset; use omission instead).
3. Each rule's `id` MUST be ∈ [0, `XDPMF_ALLOWLIST_MAX - 1`] = [0, 63];
   IDs MUST be unique within the rules list. Duplicate →
   `duplicate rule id: <n>`.
4. Each rule's `action` MUST be ∈ {`pass`, `drop`}; in cycle 1 ONLY
   `pass` is meaningful (the inner-map presence-marker semantic) and
   `drop` rules are accepted-but-no-op (operator may explicitly mark
   drop rules for documentation; they do not populate the inner map).
   Future MVP-3.4+ counters distinguish action types at apply time.
5. Each rule's `match.mac` MUST be a 17-char canonical-MAC string
   (`XX:XX:XX:XX:XX:XX`, hex case-insensitive, lowercased on parse).
   Same validation regex as MVP-1's `--allow` flag — reuse the
   existing MAC parser from `cli.cpp` (no duplicate impl).
   **[SUPERSEDED BY §5.27 — see schema rule 7 — MAC is now OPTIONAL when `src_cidr` is set]**
6. Schema-version 1 supports EXACTLY ONE match type per rule (`mac`);
   presence of any other match key (`cidr`, `port`, etc.) →
   `match type '<X>' not supported in schema_version 1`. Load-bearing
   forward-compat hinge for MVP-3.2.
   **[SUPERSEDED BY §5.27 for `src_cidr` ONLY — `src_cidr` is accepted at schema_version 1; `cidr`/`port`/`vlan`/`dst_cidr`/etc. continue to be rejected]**

**Apply-time computation of inner-map contents and default**:

- For each rule with `action: pass` AND `mac` match → add the MAC to
  the inactive-inner-slot's contents (presence-marker value = 1).
- Rules with `action: drop` → no inner-map entry (drop is the default
  for non-matching MACs given `default_action: drop`; accepted-but-no-op
  in cycle 1).
- `default_action: pass` with empty `rules` == "blanket pass" mode.
  Accepted (operator may want it for staging). Inner map is empty;
  BPF program falls through to `defaults_map[active_idx]` evaluation.
- `default_action: pass` with non-empty `rules` (all `action: pass`):
  rules are semantically redundant but accepted (defensive documentation).
  Validator emits NO warning.

#### §5.26 DataStructures additions

(NEW types live in `src/lib/config.hpp`; one BPF-side struct lives in
`src/common/mac_filter.h`.)

##### Userspace (`src/lib/config.hpp`, namespace `xdpmf`)

```
enum class DefaultAction : std::uint8_t { Drop = 0, Pass = 1 };
enum class RuleAction    : std::uint8_t { Drop = 0, Pass = 1 };

struct RuleMatch {
    std::optional<xdpmf_mac> mac;  // cycle 1: MAC-only. Future: cidr, ports, etc.
};

struct Rule {
    std::uint32_t id;       // unique within rules; range [0, 63]
    RuleAction    action;
    RuleMatch     match;
};

struct Config {
    std::uint32_t              schema_version = 1;  // SV2 default
    std::optional<std::string> iface;               // empty if not declared; CLI --iface authoritative
    DefaultAction              default_action = DefaultAction::Drop;
    std::vector<Rule>          rules;               // empty allowed
};
```

`sizeof(Config) ≈ 64-96 bytes` depending on STL impl; trivially
movable. Used both by `apply.cpp` (parsed) and by the `--allow`
synthesizer in `cli.cpp` (no I/O involved). NO public constructor
contracts beyond default-construct + member-init; impl free to add
helpers.

##### Userspace (`src/lib/yaml_subset.hpp`, namespace `xdpmf::yaml`)

```
struct ParseError {
    std::string feature;   // human-readable category, matches Q-HG1 table
    std::string file;      // path supplied by caller
    std::uint32_t line;    // 1-based
    std::uint32_t col;     // 1-based
    std::string message;   // optional additional context
};

// Minimal value-tree (suitable for the cycle-1 schema; not a full YAML AST).
struct Node {
    enum class Kind { Null, Scalar, Mapping, Sequence };
    Kind kind = Kind::Null;
    std::string scalar;                                     // valid when Kind::Scalar
    std::vector<std::pair<std::string, Node>> mapping;      // valid when Kind::Mapping (preserves insertion order; duplicates rejected at parse time)
    std::vector<Node> sequence;                             // valid when Kind::Sequence
    std::uint32_t line = 0, col = 0;                        // 1-based; populated for diagnostic provenance
};

// Throws std::system_error{LoaderError::ConfigError, ...} on parse failure.
// On success returns the root Node (always Kind::Mapping at top-level).
[[nodiscard]] Node parse(std::string_view source, std::string_view file_path_for_diagnostics);
```

##### BPF + userspace shared (`src/common/mac_filter.h`)

Additions to the existing header (post-§5.26):

```
/* §5.26 (MVP-3.1): atomic apply via ARRAY_OF_MAPS[2] — see design §5.26 Q2. */
#define XDPMF_RULESET_COUNT            2                 /* outer map_of_maps max_entries */
#define XDPMF_MAP_ACTIVE_IDX_NAME      "active_idx"     /* ARRAY[1] of __u32 */
#define XDPMF_MAP_RULESETS_OUTER_NAME  "rulesets"       /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] */
#define XDPMF_MAP_INNER_A_NAME         "allowlist_a"    /* inner slot 0 */
#define XDPMF_MAP_INNER_B_NAME         "allowlist_b"    /* inner slot 1 */
#define XDPMF_MAP_DEFAULTS_NAME        "defaults"       /* ARRAY[XDPMF_RULESET_COUNT] of __u32 */

/* §5.26 P0a: bpf_link pin basename under the per-iface bpffs dir. */
#define XDPMF_LINK_PIN_BASENAME        "link"
```

The legacy `XDPMF_MAP_ALLOWLIST_NAME` constant STAYS (used as the BPF
`__inner_map` template name — libbpf consumes the symbol for outer-map
wiring). The legacy single-pin `${PIN_DIR}/allowlist` is GONE; the two
new pins `allowlist_a` / `allowlist_b` take its place. Tests' grep
scope on `allowlist` is empty (verified) so no test edits required for
this rename.

#### §5.26 Interfaces additions

##### CLI (post-§5.26 full grammar — supersedes §4.1 grammar block headline)

```
xdpmacfilter attach --iface <IFNAME> --allow <MAC>[,<MAC>...]   # unchanged
xdpmacfilter detach --iface <IFNAME>                            # unchanged
xdpmacfilter apply  --iface <IFNAME> -f <PATH>                  # NEW (Q4 G1)
xdpmacfilter --help                                             # unchanged (text updated to list apply)
xdpmacfilter --version                                          # unchanged (still reports project version)
```

Rules for `apply`:
- `--iface <IFNAME>` REQUIRED; same `if_nametoindex` validation as
  `attach`.
- `-f <PATH>` REQUIRED; file MUST exist and be readable as UTF-8; size
  cap 1 MiB (per Q-HG1). I/O failures → exit **1** (CLI usage error);
  parse / schema failures → exit **9** (`ConfigError`).
- `--mode` accepted iff specified (per §5.23 Q1); defaults to
  `generic` if absent. Forwarded to the underlying loader attach.
  (Rationale: `apply -f` may auto-attach if not already attached, in
  which case the mode choice matters; if the link pin is already
  present, the existing mode is retained and `--mode` is silently
  ignored — see "P0a flow" below.)

Env vars consumed at startup (in `attach()` / `apply()` orchestrator
entry; both paths inherit):

- `XDPMF_TRUST_MODEL` (NEW per HG3): `strict` (default, unset →
  default) or `fleet`. Any other value → `ConfigError` exit 9 with
  stderr `xdpmacfilter: config error: unknown trust model: '<value>'
  (expected: strict|fleet)`.
- `XDPMF_BPF_OBJECT_PATH` (testing-only, per §5.24 Q4): UNCHANGED.

##### Loader (`src/lib/loader.hpp`)

ONE new enumerator (`ConfigError = 9`) added to existing `LoaderError`
enum (per §4.3 MVP-3.1 note). No new functions; no new types in
`loader.hpp`. `AttachConfig` / `DetachConfig` UNCHANGED (the apply
orchestrator lives in CLI-side `src/cli/apply.hpp`, NOT in
`loader.hpp` — public-API surface of the loader is the same).

The `attach()` function's runtime behaviour gains the
`XDPMF_TRUST_MODEL` gating + P0a pin lifecycle (impl detail in
`loader.cpp` anon namespace; no signature change).

##### Apply orchestrator (`src/cli/apply.hpp`, namespace `xdpmf`)

```
struct ApplyConfig {
    std::string iface;          // from CLI --iface
    std::string config_path;    // from CLI -f
    XdpMode     mode = XdpMode::Generic;  // from CLI --mode (forwarded)
};

// Parses the YAML at cfg.config_path, validates against schema_version 1,
// reconciles with cfg.iface (interface-mismatch → ConfigError), then
// applies via the atomic-swap mechanism (Q2 A1 + Q2-extension).
// On first invocation: behaves like attach() (loads skel, attaches XDP,
// pins link). On subsequent invocations against an already-pinned link:
// re-uses the existing link (no re-attach), writes new ruleset to
// inactive inner slot + inactive defaults slot, flips active_idx.
// Throws std::system_error with LoaderError codes on failure.
// Returns the prog id of the (possibly pre-existing) attached program.
[[nodiscard]] std::uint32_t apply_config(const ApplyConfig& cfg);

// Same atomic-swap semantics, but accepts an already-parsed Config
// (used by the --allow shorthand path in cli.cpp per Q3 BC1).
[[nodiscard]] std::uint32_t apply_config_inmemory(const std::string& iface,
                                                  const Config& parsed,
                                                  XdpMode mode);
```

Both functions internally route through ONE shared helper —
`xdpmf::internal::apply_request()` declared in `src/lib/apply_internal.hpp`
— that implements the active_idx-flip-based atomic swap. See "Internal
layering helper" sub-section below for the contract.

##### Internal layering helper (`src/lib/apply_internal.hpp`, namespace `xdpmf::internal`)

Added per §5.26 Phase B clarification 2026-05-24 EDIT-1 (impl flagged
the under-spec: §5.26 attach() flow step 12 referenced `cfg.default_action`,
but `AttachConfig` is UNCHANGED per PI-7 — it carries no `default_action`
field. Resolution = a single shared internal helper that both
`loader::attach()` and `apply::apply_config_inmemory()` route through;
neither AttachConfig nor loader.hpp gain any new field/symbol).

```
struct ApplyRequest {
    std::string  iface;
    XdpMode      mode;
    Config       config;     // fully-validated; if config.iface is set, caller has
                             // already reconciled it against `iface` (interface-mismatch
                             // check happens in apply_config/apply_config_inmemory,
                             // NOT here — apply_request trusts its input).
};

// Performs the full atomic-apply sequence:
//   1. kernel_version_probe (§5.24)
//   2. parse XDPMF_TRUST_MODEL + stderr log (§5.26 Item 6)
//   3. resolve ifindex (§5.4)
//   4. open + load skel + capture self_tag (§5.22 Q1)
//   5. open BpffsRootFd (§5.22 Q2)
//   6. probe_attached_xdp + state-(a/b/c/d) branching with trust_model gating
//      (§5.4 + §5.26 §5.4 trust_model gating sub-section)
//   7. P0a link-pin detection (§5.26 Item 5):
//        existing pin → bpf_link__open + bpf_link__update_program (hot-swap)
//        no pin       → bpf_program__attach_xdp_opts + bpf_link__pin
//   8. populate inactive defaults_map slot (req.config.default_action) +
//      populate inactive inner allowlist (req.config.rules with action == Pass +
//      MAC match)
//   9. atomic bpf_map_update_elem(active_idx_map, &zero, &inactive_idx, BPF_ANY)
// Returns prog_id of the attached program (post-attach probe).
// Throws std::system_error with LoaderError codes on failure.
[[nodiscard]] std::uint32_t apply_request(const ApplyRequest& req);
```

**Routing contract** (replaces the original "ONE helper (impl detail)"
hand-wave):

- `loader::attach(const AttachConfig& cfg)` (public API, signature
  unchanged from MVP-2): body synthesizes a Config per Q3 BC1
  semantics (`default_action: Drop`, `rules:` one `action: Pass` rule
  per MAC in `cfg.allow` with sequential IDs starting at 0), then
  calls `internal::apply_request(ApplyRequest{cfg.iface, cfg.mode,
  std::move(synth_config)})`. ATTACHCONFIG STAYS UNCHANGED — no
  `default_action` field is added.
- `apply::apply_config_inmemory(const std::string& iface, const Config&
  parsed, XdpMode mode)` (NEW, in src/cli/apply.hpp): if
  `parsed.iface` is set, asserts it equals `iface` (else throws
  `ConfigError` exit 9 with `interface mismatch (file declares '<Y>',
  --iface is '<X>')`); then calls `internal::apply_request(ApplyRequest{iface,
  mode, parsed})`.
- `apply::apply_config(const ApplyConfig& cfg)` (NEW, in
  src/cli/apply.hpp): reads `cfg.config_path` (1 MiB cap per Q-HG1)
  → `yaml::parse()` → `config::validate()` → builds Config →
  delegates to `apply_config_inmemory(cfg.iface, parsed_config, cfg.mode)`.

**Layering**: `src/cli/apply.cpp` includes `src/lib/apply_internal.hpp`
and `src/lib/config.hpp`; `src/lib/loader.cpp` includes
`src/lib/apply_internal.hpp` (header co-located with the
implementation). `internal::apply_request()` body lives in
`src/lib/loader.cpp` (where the BPF/kernel-touch machinery already
lives — single source of truth; no duplication). `apply_internal.hpp`
is NOT installed; NOT in loader.hpp public API; reviewer asserts
`git diff loader.hpp` shows ONLY the `ConfigError = 9,` enumerator
line (PI-7 holds). The `xdpmf::internal` namespace makes the
"internal-only" intent textually obvious to grep-readers.

**`AttachConfig` post-§5.26 semantic note**: AttachConfig STAYS at
`{iface, allow, mode}` (MVP-2 + §5.23 layout); the `default_action`
information is implicit in the routing — `loader::attach()` ALWAYS
synthesizes a `default_action: Drop` Config (matching MVP-1's §5.7
"empty allow-list = drop-all" semantic and the post-§5.7 "explicit
allow-list = drop-others" semantic). An operator who wants `default_action:
pass` MUST use `apply -f` with a YAML file declaring it; `--allow`
shorthand never produces a pass-default. This is consistent with the
brief's Q3 BC1 "synthesizes a single-rule config in-memory" semantic
and matches MVP-2 behaviour byte-for-byte.

**CLI variants UNCHANGED from initial §5.26 spec**: `cli.cpp`'s `attach`
parser still emits `ParsedAttach{AttachConfig}`; `main.cpp`'s `attach`
dispatch arm still calls `loader::attach(cfg.attach)`. The `apply`
parser emits `ParsedApply{ApplyConfig}`; dispatch arm calls
`apply::apply_config(cfg.apply)`. Zero CLI-surface or main-dispatch
restructure beyond the new `apply` arm.

**[CORRECTION §5.30 HK-15 — see §5.30 (MVP-3.4.5)]**: the prose above + the code block below describe `ParsedAttach` / `ParsedDetach` / `ParsedApply` wrapper structs. Reality (verified during MVP-3.4 + MVP-3.4.5): these wrapper structs NEVER shipped. The CLI uses `ParsedCommand = std::variant<AttachConfig, DetachConfig, ApplyConfig, BypassConfig>` DIRECTLY (no wrapper layer); dispatch is via `std::visit` on the variant arms directly. The wrapper-struct framing was a design-side speculation that impl correctly skipped as unnecessary. **Authoritative current shape** is documented in §5.30 HK-15. The code block below is HISTORICAL ASPIRATIONAL — keep for audit trail but do NOT treat as the contract.

##### CLI variants (`src/cli/cli.hpp`)

```
struct ParsedAttach { AttachConfig cfg; };       // unchanged
struct ParsedDetach { DetachConfig cfg; };       // unchanged
struct ParsedApply  { ApplyConfig cfg; };        // NEW

using ParsedCommand = std::variant<ParsedAttach, ParsedDetach, ParsedApply, /* existing --help/--version variants */>;
```

`main.cpp` dispatch gains a `[](const ParsedApply& p) {
return apply_config(p.cfg); }` arm. Exit-code mapping unchanged: each
`apply_config` failure throws `std::system_error` with a
`LoaderError` value, `main()` translates to the integer exit code via
the existing `loader_error_category()` mechanism.

#### §5.26 BPF program flow (`mac_filter.bpf.c` post-amendment)

Datapath pseudocode (verifier-aware; replaces existing
single-`allowlist`-lookup path):

```
xdp_md *ctx → src_mac (parse Ethernet header, malformed → STAT_DROP_MALFORMED + XDP_DROP, unchanged from §3-§4):

__u32 zero = 0;
__u32 *active_idx_p = bpf_map_lookup_elem(&active_idx_map, &zero);
if (!active_idx_p) {                       // verifier-required NULL check (never hits in practice)
    STAT_DROP_DENY++; return XDP_DROP;
}
__u32 active = *active_idx_p;

void *inner = bpf_map_lookup_elem(&rulesets_outer, &active);
if (!inner) {                              // verifier-required NULL check (never hits in practice)
    STAT_DROP_DENY++; return XDP_DROP;
}

__u8 *present = bpf_map_lookup_elem(inner, &src_mac);
if (present) {
    STAT_PASS++; return XDP_PASS;          // explicit allow-rule hit
}

__u32 *default_p = bpf_map_lookup_elem(&defaults_map, &active);
if (!default_p) {                          // verifier-required NULL check (never hits in practice)
    STAT_DROP_DENY++; return XDP_DROP;
}
if (*default_p == 1u) {
    STAT_PASS++; return XDP_PASS;          // default_action: pass — blanket allow
}
STAT_DROP_DENY++; return XDP_DROP;         // default_action: drop — the MVP-1 default
```

**Verifier interactions** (impl notes):

- `bpf_map_lookup_elem(&rulesets_outer, &active)` returns an `void *`
  that the verifier treats as a "map_value" of the inner-map FD; the
  subsequent `bpf_map_lookup_elem(inner, &src_mac)` is a verifier
  builtin recognising the chained pattern. Verified working on libbpf
  ≥ 1.0 / kernel ≥ 4.12 (well below floor 5.15).
- Both NULL checks are MANDATORY per verifier; impl MUST NOT elide
  them via `__builtin_assume` etc. (the verifier doesn't trust user
  hints on map lookup return values).
- `defaults_map` lookup return type is `__u32 *` (the map's value
  type); deref with explicit NULL check.

#### §5.26 attach() flow update (P0a + trust_model gating)

Post-§5.26 `attach()` flow (incremental over §5.22 attach() flow):

```
attach(cfg):
  1.  kernel_version_probe()                                            [§5.24 — unchanged]
  2.  trust_model = parse_xdpmf_trust_model_env()                       [§5.26 NEW]
       — unset|"strict" → Strict (default)
       — "fleet"        → Fleet
       — other          → throw ConfigError (exit 9) "unknown trust model: '<v>'"
  3.  stderr: "xdpmacfilter: trust_model=<strict|fleet>"                [§5.26 NEW; ALWAYS emitted]
  4.  ifindex = resolve_ifindex(cfg.iface, AttachFailed)                [unchanged]
  5.  BpfSkeleton skel = open_and_load()                                [§5.22 Q1 early-load]
  6.  self_tag = capture_self_tag(skel)                                 [§5.22 Q1]
  7.  BpffsRootFd root{}                                                [§5.22 Q2]
  8.  probe = probe_attached_xdp(ifindex, self_tag)                     [§5.4 / §5.19 / §5.20]
  9.  branch on §5.4 state (with trust_model gating on state (c)):
        (a) clean attach              — proceed to step 10 (fresh attach + new link)
        (b) "ours" (name+tag match)   — detect existing link pin (step 10) → IDEMPOTENT REATTACH path
        (c) alien (name OR tag fail):
              IF trust_model == Strict → throw AttachRefusedAlien exit 4         [§5.4 + §5.22 unchanged]
              IF trust_model == Fleet  → stderr log
                                          "xdpmacfilter: trust_model=fleet — bypassing alien-program check; \
                                            replacing prog id <N> (mode=<M>, name='<n>')"
                                          + bpf_xdp_detach(ifindex, probe.mode_flags, 0)
                                          + bpffs_remove_iface (if pin_dir present, per §5.4 cleanup)
                                          + fall through to step 10 (fresh attach)
                                          NOTE: §5.19 + §5.22 hardening (path discipline, BpffsRootFd ELOOP,
                                                 etc.) ALREADY fired BEFORE this branch; fleet relaxes ONLY
                                                 §5.4 (alien-program refusal), NOT path discipline.
        (d) stale-pin               — bpffs_remove_iface + step 10 (fresh attach)
 10.  P0a link pin detection + attach branching:
        link_pin_path = "${XDPMF_BPFFS_ROOT}/<iface>/link"
        IF state == (b) AND link pin exists:
          link = bpf_link__open(link_pin_path)
          bpf_link__update_program(link, skel.progs.mac_filter_prog)              [hot-swap atomic]
          (NO bpf_xdp_attach call; NO bpf_link__pin call)
        ELSE:
          link = bpf_program__attach_xdp_opts(skel.progs.mac_filter_prog, ifindex, {.flags = mode_to_flags(cfg.mode)})
                                                                                  [returns bpf_link*]
          bpf_link__pin(link, link_pin_path)                                      [persists across loader exit]
 11.  ensure_bpffs_dir(*at-based, root.fd())                                       [§5.22 Item 2]
 12.  populate active_idx slot:
        — if first attach: write defaults_map[0] = (cfg.default_action == Pass)
                          + populate inner[0] with rules
                          + active_idx_map[0] = 0
        — if reattach (state b): write defaults_map[1 - active_idx]
                                + populate inner[1 - active_idx]
                                + active_idx_map[0] = 1 - active_idx   (atomic flip)
       (impl reads CURRENT active_idx_map[0] to compute inactive slot.)
 13.  commit; return after-probe's prog_id
```

`detach(iface)` flow update (incremental over §5.22 detach() flow):
- Same trust_model env parse (step 2) + stderr log (step 3) at entry.
  (Trust_model affects ONLY state-(c) refusal disposition; detach's
  state-(c) still throws DetachFailed exit 5 regardless of mode — the
  alien is not "ours" so we have nothing to detach. fleet does NOT
  override this; the operator can manually `ip link set <X> xdp off`
  to remove the alien if they really want to.)
- After §5.22 detach state-(b) branch: BEFORE `bpf_xdp_detach(ifindex,
  probe.mode_flags, 0)`, call `unlinkat(iface_fd, "link", 0)` to remove
  the pinned link — this drops the kernel-side refcount that was
  keeping the XDP slot occupied after our loader exited. THEN
  `bpf_xdp_detach` cleans up the slot itself (or fails idempotently if
  the unlink already triggered teardown — both outcomes treated as
  success in detach context). Then the existing `bpffs_remove_iface`
  walk cleans the remaining pins.

#### §5.26 §5.4 trust_model gating (specific to alien-refusal disposition)

**Scope of relaxation under `XDPMF_TRUST_MODEL=fleet`**:

- §5.4 alien-program refusal (state (c) → exit 4) → RELAXED in fleet:
  alien is detached, fresh attach proceeds, exit 0.
- §5.19 identity-verification mechanism (`bpf_prog_info.name` match)
  → ENFORCED in both modes. Still runs to compute `is_ours`; in fleet
  the false result merely changes the disposition (detach-alien-and-attach
  instead of refuse), not the predicate.
- §5.22 Item 1 tag-check → ENFORCED in both modes. Same as §5.19:
  still computed; only the state-(c) disposition is affected.
- §5.22 Item 2 path-discipline (`BpffsRootFd`, O_PATH, `*at()`-relative
  ops, symlink → exit 8) → ENFORCED in both modes UNCONDITIONALLY.
  The path-symlink threat vector is orthogonal to the
  trusted-vs-fleet axis; an operator who wants to replace an alien
  program does NOT want to do so via attacker-controlled bpffs paths.

The audit story is sharp: stderr's `trust_model=<X>` log line at
attach entry is the single greppable signal that distinguishes the
two modes. Combined with exit-code monitoring (exit 4 absent in fleet
mode under same-alien-traffic condition), operators can verify the
mode took effect.

**Sub-decision — `T_TRUST_MODEL_FLEET_RELAXES_GATE` uses REAL alien-program fixture**:
YES. Reuse `tests/fixtures/xdp_pass.bpf.c` (already exists per §6.9 —
the alien fixture for `T_ATTACH_ALIEN_REFUSAL`). Test runs same
scenario:
- Strict (or unset): pre-attach alien → invoke our loader → exit 4
  (re-confirms MVP-1.1B behaviour; this is the negation control for
  the relaxation).
- Fleet: pre-attach alien → invoke our loader with
  `XDPMF_TRUST_MODEL=fleet` → exit 0 + our prog is now attached + alien
  is gone. Stderr contains both `trust_model=fleet` AND
  `bypassing alien-program check`.

This makes T_TRUST_MODEL_FLEET_RELAXES_GATE a true differential test
of the §5.4 gate behaviour, not a synthetic exercise.

**Sub-decision — stderr-logging policy on attach for trust_model**:
ALWAYS emit `xdpmacfilter: trust_model=<strict|fleet>` to stderr at
attach() entry (AFTER env parse, BEFORE identity probe). One line,
fixed format. Audit-grep-friendly. Applies to `attach` AND `apply -f`
(both route through `attach()` internally). Does NOT apply to
`detach` (the trust-model relaxation is attach-specific). Does NOT
apply to `--help` / `--version` (no kernel touch). Tester asserts the
log line presence + format in §6.26 + §6.25.

#### §5.26 FileList (brownfield DIFF — NEW / EDITED / UNCHANGED-BUT-AFFECTED)

##### NEW (created this slice)

| Path | Role (one line) | Language | LOC est |
|---|---|---|---|
| `src/lib/yaml_subset.hpp` | Header for custom YAML subset parser per Q-HG1: `parse()` + `Node` + `ParseError` types | C++23 | 40 |
| `src/lib/yaml_subset.cpp` | Custom ~150-LOC YAML subset parser implementation per Q-HG1 (single-pass cursor, line/col tracking, DoS guards) | C++23 | 200 |
| `src/lib/config.hpp` | Header for typed config schema per §5.26 schema: `Config`, `Rule`, `RuleMatch`, `DefaultAction`, `RuleAction` | C++23 | 30 |
| `src/lib/config.cpp` | Schema validator: takes `yaml::Node` root → produces `Config` or throws `ConfigError` (rules 1-6 per §5.26 schema) | C++23 | 100 |
| `src/cli/apply.hpp` | Header for apply orchestrator: `ApplyConfig`, `apply_config()`, `apply_config_inmemory()` declarations | C++23 | 25 |
| `src/cli/apply.cpp` | Apply orchestrator: parse → validate → reconcile-with-iface → routes through `internal::apply_request()` (see `src/lib/apply_internal.hpp`) | C++23 | 80 |
| `src/lib/apply_internal.hpp` | Internal-only helper exposing the shared atomic-apply implementation (skel-load + probe + identity-gate + active_idx flip + populate-inner + link-pin / update-program) used by BOTH `loader::attach()` (synthesized-Config wrapper per Q3 BC1) AND `apply::apply_config_inmemory()`. NOT in loader.hpp public API; NOT installed; namespace `xdpmf::internal`. See "Internal layering helper" sub-section in §5.26 Interfaces additions. Added per §5.26 Phase B clarification 2026-05-24 EDIT-1 (impl flagged ambiguity in attach() flow step 12 — `cfg.default_action` reference vs PI-7 `loader.hpp` byte-equivalence). | C++23 | 25 |
| `tests/T_APPLY_VALID_CONFIG.sh` | §6.21 test | bash | tester |
| `tests/T_APPLY_REJECTS_MALFORMED.sh` | §6.22 test | bash | tester |
| `tests/T_APPLY_ATOMIC_SWAP_NO_DROP.sh` | §6.23 test (load-bearing for Composite 6 promise) | bash | tester |
| `tests/T_APPLY_REPLACES_RULESET.sh` | §6.24 test | bash | tester |
| `tests/T_LINK_PERSIST_ACROSS_LOADER_EXIT.sh` | §6.25 test (load-bearing for P0a per HG2) | bash | tester |
| `tests/T_TRUST_MODEL_FLEET_RELAXES_GATE.sh` | §6.26 test | bash | tester |
| `tests/T_EXIT_CODE_9_ON_CONFIG_ERROR.sh` | §6.27 test | bash | tester |
| `tests/fixtures/config_valid.yaml` | Minimal valid YAML: `default_action: drop` + `rules:` with 2-3 `pass`-MAC entries (used by §6.21 + §6.23 + §6.24) | YAML | 12 |
| `tests/fixtures/config_valid_blanket_pass.yaml` | Valid YAML with `default_action: pass` + empty rules (used by §6.21 sanity sub-case) | YAML | 4 |
| `tests/fixtures/config_malformed_yaml.yaml` | Malformed: flow-form `{a: 1}` at top-level (used by §6.22 sub-case 1) | YAML | 1 |
| `tests/fixtures/config_malformed_schema.yaml` | Malformed: `default_action: maybe` (used by §6.22 sub-case 2) | YAML | 2 |
| `tests/fixtures/config_malformed_dup_id.yaml` | Malformed: two rules with same `id` (used by §6.22 sub-case 3) | YAML | 8 |
| `tests/fixtures/config_malformed_iface_mismatch.yaml` | Valid YAML with `interface: not-the-iface-we-pass` (used by §6.22 sub-case 4) | YAML | 6 |
| `tests/fixtures/config_malformed_unsupported_match.yaml` | Malformed: `match: {cidr: 10.0.0.0/8}` (used by §6.22 sub-case 5; forward-compat hinge for MVP-3.2) | YAML | 7 |
| `tests/fixtures/config_apply_swap_a.yaml` | Apply-A ruleset for §6.23 + §6.24 (`pass` MAC_X only) | YAML | 5 |
| `tests/fixtures/config_apply_swap_b.yaml` | Apply-B ruleset for §6.23 + §6.24 (`pass` MAC_X + MAC_Y) | YAML | 6 |

##### EDITED (existing files touched this slice)

| Path | Role (one line) | What changes |
|---|---|---|
| `src/loader/loader.hpp` | → relocated to `src/lib/loader.hpp` per Q1 R1 | `git mv` + EXACTLY ONE line added: `ConfigError = 9,` inside `enum class LoaderError`. Body otherwise byte-identical. |
| `src/loader/loader.cpp` | → relocated to `src/lib/loader.cpp` per Q1 R1 | `git mv` + (a) early-attach `parse_xdpmf_trust_model_env()` + stderr log; (b) state-(c) disposition gated on trust_model; (c) attach: replace `bpf_xdp_attach` with `bpf_program__attach_xdp_opts` + `bpf_link__pin`; on state-(b) idempotent reattach via `bpf_link__open` + `bpf_link__update_program`; (d) detach: `unlinkat("link",0)` before `bpf_xdp_detach`; (e) new BPF map names handled (active_idx / rulesets / inner_a / inner_b / defaults / link pin via skeleton). |
| `src/loader/raii.hpp` | → relocated to `src/lib/raii.hpp` per Q1 R1 | `git mv` only; body unchanged. |
| `src/loader/cli.hpp` | → relocated to `src/cli/cli.hpp` per Q1 R1 | `git mv` + (a) `ParsedApply` variant added; (b) `apply`-parser declarations added. Existing types UNCHANGED. |
| `src/loader/cli.cpp` | → relocated to `src/cli/cli.cpp` per Q1 R1 | `git mv` + (a) `apply` subcommand branch added per Q4 G1; (b) `--allow` handler synthesizes `Config` per Q3 BC1 (instead of building `AttachConfig.allow` vector directly — the synthesized Config feeds the same internal apply path); (c) `--help` text gains `apply` line. |
| `src/loader/main.cpp` | → relocated to `src/cli/main.cpp` per Q1 R1 | `git mv` + dispatch arm for `ParsedApply` added. |
| `src/bpf/mac_filter.bpf.c` | XDP program | (a) new map declarations (`active_idx_map`, `rulesets_outer` with `__inner_map = allowlist_inner` template, `allowlist_a`, `allowlist_b`, `defaults_map`); (b) datapath rewritten per §5.26 BPF program flow above. The `mac_filter_prog` function name + SEC name UNCHANGED (§5.19 / §5.22 identity-gate contract holds). |
| `src/common/mac_filter.h` | Shared header | +~12 lines: `XDPMF_RULESET_COUNT`, `XDPMF_MAP_ACTIVE_IDX_NAME`, `XDPMF_MAP_RULESETS_OUTER_NAME`, `XDPMF_MAP_INNER_A_NAME`, `XDPMF_MAP_INNER_B_NAME`, `XDPMF_MAP_DEFAULTS_NAME`, `XDPMF_LINK_PIN_BASENAME`. Existing constants UNCHANGED. |
| `CMakeLists.txt` | Top-level build | (a) new STATIC target `xdpmf_internal` aggregating `src/lib/*.cpp`; (b) `xdpmacfilter` binary moves to `src/cli/` and links `xdpmf_internal`; (c) `target_include_directories` updates for the relocated headers; (d) version bump `VERSION 0.2.3 → 0.3.0` per Done-Definition. |
| `tests/CMakeLists.txt` | ctest registration | (a) `LOADER_BIN` path bumped to `${CMAKE_BINARY_DIR}/src/cli/xdpmacfilter`; (b) `add_test` entries for the 7 new T_APPLY_* / T_LINK_* / T_TRUST_* / T_EXIT_CODE_9 tests; (c) `TEST_ENV` carries fixture-dir path for the YAML fixtures. |
| `tests/lib/common.sh` | Shared helpers | New helpers: `apply_config <path> <iface>` (wraps the loader invocation); `wait_for_active_idx_flip <iface> <expected>` (polls `bpftool map dump pinned ${PIN_DIR}/active_idx` until value matches or timeout); `kill_loader_keep_link <iface>` (sends SIGKILL — link pin survives). Existing helpers UNCHANGED. |
| `CHANGELOG.md` | Version history | New `## [0.3.0] - 2026-05-NN` section per Keep-a-Changelog (MVP-1.1C B4 + §5.25 Q3 V1 precedent). |

##### UNCHANGED-BUT-AFFECTED (zero git-diff; behaviour must hold)

| Path | Why it matters |
|---|---|
| `src/loader/main.cpp`'s dispatch logic for `attach` / `detach` | After file-move to `src/cli/main.cpp`, the BEHAVIOUR of the `attach` and `detach` arms MUST remain identical (only the `apply` arm is added). Reviewer asserts via re-running existing 20 ctests. |
| `tests/lib/common.sh` existing functions (setup_veth, cleanup_veth, NSEXEC, NETNS, inject_eth, inject_runt, xdp_prog_id, read_stats, wait_for_stats_sum, prog_count, require_passwordless_sudo, ...) | The §5.25 EDIT-13 / EDIT-14 / EDIT-15 contracts (mount-ns preservation via `nsenter --net`, env-carrying loader invocations via `${NSEXEC} env VAR=...`, etc.) MUST hold. NEW helpers (`apply_config`, `wait_for_active_idx_flip`, `kill_loader_keep_link`) layer ON TOP without modifying existing helper bodies. |
| `tests/T_*.sh` (all 20 existing tests) | Bodies UNCHANGED. The ONLY consequence of §5.26 reaching them is `LOADER_BIN` path bump in common.sh (which is sourced; tests don't reference the path directly). Reviewer asserts via 20/20 ctest pass post-§5.26 with `git diff --stat tests/T_*.sh` showing zero changes. |
| `tests/fixtures/xdp_pass.bpf.c` | Reused as the alien fixture for §6.26 T_TRUST_MODEL_FLEET_RELAXES_GATE; CONTENT unchanged from §6.9. |
| `tests/fixtures/mac_filter_alt.bpf.c` | UNCHANGED. Still used by §6.14 T_ATTACH_TAG_MISMATCH; §5.26 does not interact with the tag-mismatch fixture. |
| `tests/fixtures/mac_filter_bad.bpf.c` | UNCHANGED. Still used by §6.20 T_VERIFIER_REJECT. |
| `include/version.h.in` + `tests/lib/pins.sh.in` | UNCHANGED (templates from §5.25 P2/P3 still authoritative; CMake just reads the new `VERSION 0.3.0` into the `version.h.in` substitution). |
| `cmake/BpfBuild.cmake` | UNCHANGED. The new BPF maps are declared inside `mac_filter.bpf.c`; no build-system contract change. |
| `tests/inject/inject_runt.py`, `tests/inject/inject_eth.py`, `tests/inject/read_stats.py` | UNCHANGED. `read_stats.py` still reads `stats` pin (per §5.23 PERCPU sum). Apply-time atomicity is observed via STAT_DROP_DENY counter delta (no new reader). |
| `src/common/mac_filter.h` existing constants (`xdpmf_mac`, `mac_filter_stat`, `XDPMF_BPFFS_ROOT`, `XDPMF_ALLOWLIST_MAX`, `XDPMF_MAP_ALLOWLIST_NAME`, `XDPMF_MAP_STATS_NAME`) | UNCHANGED. New constants are ADDITIVE; reviewer asserts `git diff` shows ONLY additions (no removals or modifications to existing lines). |

Any file NOT listed above is off-limits for impl. If impl needs to edit
a file not listed, that's a design gap — SendMessage architect.

#### §5.26 TestStrategy entries

##### §6.21 T_APPLY_VALID_CONFIG — minimal valid YAML parsed + applied; MAC filtering matches the rule

- **Trigger**: `apply_config tests/fixtures/config_valid.yaml ${IFACE_A}` (via the new common.sh helper that wraps `${NSEXEC} ${LOADER_BIN} apply -f <path> --iface <iface>`). Standard veth fixture (`setup_veth`/`cleanup_veth`); `RESOURCE_LOCK xdp_fixture`; root sudo required.
- **Observable outcome (all)**:
  - Exit code 0 (`apply` invocation).
  - Stderr contains `xdpmacfilter: trust_model=strict` (one-line audit log per §5.26 sub-decision).
  - Stderr DOES NOT contain `config error:` or `unsupported`.
  - Pin `${PIN_DIR}/link` exists.
  - Pin `${PIN_DIR}/active_idx` exists; value (via `bpftool map dump`) is one of {0, 1}.
  - Pin `${PIN_DIR}/allowlist_a` OR `${PIN_DIR}/allowlist_b` (whichever active_idx selects) contains exactly the MACs from the fixture.
  - Inject a packet from a MAC in the fixture → STAT_PASS increments by 1.
  - Inject a packet from a MAC NOT in the fixture → STAT_DROP_DENY increments by 1.
  - Sanity sub-case: re-run apply with `config_valid_blanket_pass.yaml` (`default_action: pass`, empty rules); inject from a random MAC → STAT_PASS increments (blanket-pass works).
- **Assertion mechanism**: bash `[[ rc == 0 ]]`, `grep -q`, `bpftool map dump pinned ... -j | jq`, `wait_for_stats_sum`, `inject_eth`.
- **SKIP conditions**: none.
- **Cleanup**: `cleanup_veth` removes the netns and the bpffs per-iface dir (PID-suffixed).

##### §6.22 T_APPLY_REJECTS_MALFORMED — every malformed YAML / schema-violation sub-case → exit 9 + recognizable stderr

- **Trigger**: 5 sub-cases, all invoking `${NSEXEC} ${LOADER_BIN} apply -f <fixture_path> --iface ${IFACE_A}`:
  1. `config_malformed_yaml.yaml`         (flow-form top-level)
  2. `config_malformed_schema.yaml`       (`default_action: maybe`)
  3. `config_malformed_dup_id.yaml`       (two rules, same `id`)
  4. `config_malformed_iface_mismatch.yaml` (file `interface:` differs from `--iface`)
  5. `config_malformed_unsupported_match.yaml` (`match: {cidr: ...}` — flow-form AND unsupported match-type; ASSERT the parser rejects it before reaching schema validator OR the validator catches it — either path produces exit 9, so test allows either error message)
- **Observable outcome (each sub-case)**:
  - Exit code EXACTLY 9.
  - Stderr matches `xdpmacfilter: config error:`.
  - For sub-cases 1-3, 5: stderr contains the fixture path AND a `<line>:<col>` position.
  - For sub-case 4: stderr contains BOTH the file's declared interface name AND the `--iface` arg value (case-sensitive substring match).
  - No XDP attached afterwards: `[[ -z "$(xdp_prog_id ${IFACE_A})" ]]`.
  - No bpffs per-iface dir created: `sudo -n test ! -e "${PIN_DIR}"`.
- **Assertion mechanism**: bash `[[ rc -eq 9 ]]`, `grep -qE`, `xdp_prog_id`, `test ! -e`.
- **SKIP conditions**: none.
- **Cleanup**: `cleanup_veth`.

##### §6.23 T_APPLY_ATOMIC_SWAP_NO_DROP — concurrent traffic + apply; zero packet drop for overlapping-allowed MAC

- **Load-bearing for Composite 6 promise** — this test makes or breaks the architectural story. Architect explicitly fences against making it theatrical.
- **Trigger**:
  1. `setup_veth` + initial `apply config_apply_swap_a.yaml --iface ${IFACE_A}` (config A = `default_action: drop`, rules: pass MAC_X only).
  2. Start background traffic injector on the peer veth: continuous `inject_eth ${IFACE_B} MAC_X` at ~100 Hz (bash loop calling the Python injector with a short sleep; configurable via env `XDPMF_INJECT_RATE_HZ` defaulting to 100).
  3. After ~2 seconds (sustained traffic baseline established): snapshot `STAT_DROP_DENY_baseline = read_stats(${IFACE_A}, STAT_DROP_DENY)`.
  4. Invoke `apply config_apply_swap_b.yaml --iface ${IFACE_A}` (config B = `default_action: drop`, rules: pass MAC_X + MAC_Y — MAC_X overlap is the load-bearing element).
  5. Continue traffic for ~2 more seconds.
  6. Stop the injector; let stats quiesce; snapshot `STAT_DROP_DENY_final = read_stats(${IFACE_A}, STAT_DROP_DENY)`.
- **Observable outcome (all)**:
  - Both apply invocations exit 0.
  - `STAT_DROP_DENY_final - STAT_DROP_DENY_baseline == 0` (MAC_X traffic NEVER dropped during the swap).
  - `STAT_PASS_final > STAT_PASS_baseline + N_packets_lower_bound` (where lower-bound is conservatively ~150 = 2s × 100Hz × 0.75 fudge for injection scheduling jitter).
  - `active_idx_map[0]` value changed (was 0 initially; is 1 after — or vice versa; test reads both endpoints and asserts inequality).
- **Assertion mechanism**: bash `[[ "$drop_delta" -eq 0 ]]`, `[[ "$pass_delta" -ge $lower_bound ]]`, `bpftool map dump pinned ${PIN_DIR}/active_idx -j | jq -r '.[0].value'`, two snapshots compared.
- **Anti-theatricality controls**:
  - Background injection MUST be concurrent with the apply (`&` in bash, NOT sequential apply-then-traffic).
  - The 100-Hz rate gives ~200 packets crossing the swap boundary; even a microsecond half-applied state would manifest as a ≥ 1 drop on the load-bearing MAC.
  - Negation control: if the test is run with a synthetic non-atomic apply path (impl-level switch — OOS for this slice but architect documents the mechanism for future spike testing), drop_delta becomes non-zero. Cycle 1 ships without the synthetic toggle.
- **SKIP conditions**: if `setup_veth` reports veth load < lower_bound packets/s (very slow CI runner), SKIP with rc 77 + stderr `XDPMF_INJECT_RATE_HZ too low for swap test on this runner`. Threshold check after step 2 baseline.
- **Cleanup**: stop background injector via `kill ${INJECT_PID}`; `cleanup_veth`.

##### §6.24 T_APPLY_REPLACES_RULESET — second apply with different rules replaces the first

- **Trigger**:
  1. `setup_veth`; `apply config_apply_swap_a.yaml --iface ${IFACE_A}` (pass MAC_X only).
  2. Inject 1 packet from MAC_Y → expect STAT_DROP_DENY += 1.
  3. `apply config_apply_swap_b.yaml --iface ${IFACE_A}` (pass MAC_X + MAC_Y).
  4. Inject 1 packet from MAC_Y → expect STAT_PASS += 1.
  5. `apply config_apply_swap_a.yaml --iface ${IFACE_A}` again (back to MAC_X-only; verifies bidirectional swap).
  6. Inject 1 packet from MAC_Y → expect STAT_DROP_DENY += 1.
- **Observable outcome (each apply)**: exit 0; active_idx flipped between successive applies (read before/after via `bpftool map dump`); inner-map contents (read via `bpftool map dump pinned ${PIN_DIR}/allowlist_{a,b}`) reflect the new ruleset on the now-active slot.
- **Assertion mechanism**: bash `[[ rc -eq 0 ]]`, `wait_for_stats_sum`, `bpftool map dump`.
- **SKIP conditions**: none.
- **Cleanup**: `cleanup_veth`.

##### §6.25 T_LINK_PERSIST_ACROSS_LOADER_EXIT — kill loader; filter still enforces on fresh traffic (P0a survival)

- **Load-bearing for P0a per HG2.** Reviewer's 5th framework point ASSERTS this test actually kills the loader process and verifies enforcement on subsequent traffic — not just "pin file exists on bpffs".
- **Trigger**:
  1. `setup_veth`; `apply config_apply_swap_a.yaml --iface ${IFACE_A}` (pass MAC_X only). Foreground apply exits 0 (this is the post-MVP-3.1 normal-exit pattern; the loader process exits after pinning the link).
  2. Confirm pin exists: `sudo -n test -e ${PIN_DIR}/link`.
  3. Confirm XDP slot occupied: `[[ -n "$(xdp_prog_id ${IFACE_A})" ]]`.
  4. (No loader process to kill — `apply` already exited. P0a's contract is the LINK persists across loader exit; the apply invocation IS the loader-exit event.)
  5. Wait 1 second (defensive — gives kernel any async settle).
  6. Inject 1 packet from MAC_X → expect STAT_PASS += 1.
  7. Inject 1 packet from MAC_Y → expect STAT_DROP_DENY += 1.
  8. Re-invoke `apply config_apply_swap_b.yaml --iface ${IFACE_A}` (this exercises the idempotent-reattach via `bpf_link__update_program`).
  9. Inject 1 packet from MAC_Y → expect STAT_PASS += 1 (now allowed under config B).
  10. (Optional belt-and-suspenders): `pkill -9 -f xdpmacfilter || true` between steps 5 and 6 to assert no zombie loader.
- **Observable outcome (all)**:
  - Step 2 succeeds (link pin present after loader exit).
  - Step 3 succeeds (XDP attached after loader exit).
  - Step 6's STAT_PASS delta == 1 (filter active, allow-rule enforced).
  - Step 7's STAT_DROP_DENY delta == 1 (filter active, default drop enforced).
  - Step 8 exits 0 with stderr containing `replacing existing program on ${IFACE_A}` OR equivalent operator-readable signal (impl-shape flexibility; architect commits to "stderr names the idempotent-reattach path took").
  - Step 9's STAT_PASS delta == 1 (new ruleset took effect).
- **Assertion mechanism**: bash `test -e`, `xdp_prog_id`, `inject_eth`, `wait_for_stats_sum`, `grep -qE`.
- **SKIP conditions**: if `bpf_link__pin` fails at attach with `ENOSYS` (kernel ≥ 5.7 floor breached — should not happen given §5.24 sets 5.15 floor), test exits 77 with stderr `bpf_link__pin unsupported on this kernel`. Otherwise no skip.
- **Cleanup**: `pkill -9 -f xdpmacfilter || true`; `sudo -n rm -f ${PIN_DIR}/link`; `cleanup_veth`. (The pin removal triggers kernel-side XDP detach since the link's last reference is dropped — verifies the unpin contract on teardown.)

##### §6.26 T_TRUST_MODEL_FLEET_RELAXES_GATE — fleet bypasses §5.4 alien refusal; strict re-confirms refusal

- **Differential test** (per §5.26 sub-decision): uses REAL alien-program fixture `tests/fixtures/xdp_pass.bpf.c` (already built per §6.9 / §6.14 `add_bpf_object` infrastructure).
- **Trigger** (4 sub-cases for full coverage):
  1. **Strict-default refuses alien**: `setup_veth`; pre-attach `xdp_pass.bpf.o` to ${IFACE_A}; invoke loader (NO env var set); assert exit 4 + `trust_model=strict` in stderr + alien still attached.
  2. **Strict-explicit refuses alien**: same setup; invoke loader with `XDPMF_TRUST_MODEL=strict`; same assertions as sub-case 1.
  3. **Fleet bypasses + replaces alien**: same setup; invoke loader with `XDPMF_TRUST_MODEL=fleet`; assert exit 0 + `trust_model=fleet` in stderr + `bypassing alien-program check` in stderr + our program is now attached (verified via §5.19 name-check helper `xdp_prog_id` + `bpftool prog show id <N>`).
  4. **Garbage value fails closed**: clean iface (no pre-attached alien); invoke loader with `XDPMF_TRUST_MODEL=garbage`; assert exit 9 + `config error: unknown trust model: 'garbage'` in stderr + no XDP attached + no bpffs dir.
- **Observable outcome (per sub-case)**: as above (exit code + stderr substring + XDP slot state).
- **Assertion mechanism**: bash `[[ rc -eq <N> ]]`, `grep -qE`, `xdp_prog_id`, `bpftool prog show id`.
- **Negation control**: sub-case 1+2 IS the negation of sub-case 3 (same fixture, different env → different outcome). The differential makes this NOT theatrical.
- **Env-var carrying loader invocations**: MUST use the `${NSEXEC} env XDPMF_TRUST_MODEL=<value> ${LOADER_BIN} ...` form per §5.25 EDIT-14 (since `setup_veth` is called, the test enters the netns; the §5.25 mount-ns/sudo idiom applies).
- **SKIP conditions**: none.
- **Cleanup**: `sudo -n ip link set ${IFACE_A} xdpgeneric off 2>/dev/null || true`; `sudo -n rm -rf ${PIN_DIR}`; `cleanup_veth`.

##### §6.27 T_EXIT_CODE_9_ON_CONFIG_ERROR — exit-code-9 reachable end-to-end via at least one minimal trigger

- **Trigger**: bad `XDPMF_TRUST_MODEL=garbage` invocation (smallest reachable trigger; also covered as sub-case 4 in §6.26 — this test is the bare-bones exit-code-9 audit-grep that doesn't require veth fixture). NO `setup_veth`. NO `--iface` validation matters (loader rejects env-parse before resolving iface).
- **Observable outcome**:
  - Exit code EXACTLY 9.
  - Stderr starts with `xdpmacfilter: config error:`.
  - Stderr contains `unknown trust model` (specific error message).
  - No XDP touched (no iface change).
  - No bpffs dir created.
- **Assertion mechanism**: bash `[[ rc -eq 9 ]]`, `grep -qE`.
- **SKIP conditions**: none.
- **Cleanup**: none required (test does not touch netns or bpffs).
- **Rationale for separate test from §6.26**: §6.26 requires veth + alien-fixture infrastructure; §6.27 is the smoke-test that exit 9 is wired through `main()` → `loader_error_category()` correctly with ZERO fixture dependencies. If §6.26 fails for fixture-infrastructure reasons, §6.27 still proves the exit-code path. Ops-script writers grep for "exit 9" — §6.27 is the canonical reference.

#### §5.26 Preserved invariants (MVP-3.1 brownfield)

Per architect spec section 6.5 (brownfield mode), the following MVP-2-and-earlier
invariants MUST hold post-§5.26. The reviewer's 5th framework point
walks this list and reports `[INVARIANT-VIOLATED]` per failed check.

| # | Invariant | Check mechanism |
|---|---|---|
| PI-1 | §5.4 alien-program identity-gate ENFORCED in strict mode (default) | Re-run §6.14 T_ATTACH_TAG_MISMATCH + §6.9 T_ATTACH_ALIEN_REFUSAL with `XDPMF_TRUST_MODEL` unset → both still pass exit 4. Cross-check with §6.26 sub-case 1 (strict-default refuses alien). |
| PI-2 | §5.19 `bpf_prog_info.name` identity-gate ENFORCED in BOTH modes (strict + fleet) | §6.9 still passes in strict; §6.26 sub-case 3 verifies fleet detaches-and-replaces (which means the name check still RAN to compute `is_ours = false`, then disposition changed). If name-check were SKIPPED in fleet, the alien would be treated as ours and the existing pin/cleanup flow would diverge. |
| PI-3 | §5.22 Item 1 tag-check ENFORCED in BOTH modes | §6.14 T_ATTACH_TAG_MISMATCH passes in strict; ENVISIONED Phase-B addition: re-run the same fixture with `XDPMF_TRUST_MODEL=fleet` (NOT a separate ctest per §7 OOS — fold into §6.14's existing negation-control if appropriate) and assert exit 0 + `bypassing alien-program check` (tag-mismatch is one trigger of the §5.4 state-(c) disposition that fleet relaxes). If §6.14 starts failing in strict mode, PI-3 is violated. |
| PI-4 | §5.22 Item 2 O_PATH bpffs path-discipline ENFORCED in BOTH modes (UNCONDITIONALLY) | §6.15 T_BPFFS_ROOT_SYMLINK passes in strict; ENVISIONED Phase-B addition: re-run same with `XDPMF_TRUST_MODEL=fleet` and assert EXIT 8 (still refused — fleet does NOT relax path discipline). If §6.15 starts failing OR if the fleet-mode variant starts EXITING 0 instead of 8, PI-4 is violated. |
| PI-5 | §5.24 kernel-version probe ENFORCED in BOTH modes | §6.20 T_VERIFIER_REJECT continues to gate on kernel version per §5.24; no change. |
| PI-6 | 20 pre-existing ctests pass byte-equivalent invocations OR legitimately SKIP-77 | Re-run all 20 tests post-§5.26 → all pass (or skip with rc 77 per §5.24 Q4 hybrid). Diff `tests/T_*.sh` shows zero body changes (only `tests/lib/common.sh` and `tests/CMakeLists.txt` may diff per §5.26 EDITED list above). |
| PI-7 | `loader.hpp` diff scope EXACTLY one new enumerator line (`ConfigError = 9`) + file relocation | `git diff -M src/loader/loader.hpp src/lib/loader.hpp` shows: rename + body diff equal to one line added (`    ConfigError        = 9,`) inside the existing `LoaderError` enum body. ANY other line diff (including reformatting, whitespace, comment changes) is `[INVARIANT-VIOLATED]`. Same precedent as §5.22 `PathRefused = 8` and §5.24 `KernelUnsupported = 7`. |
| PI-8 | `xdpmacfilter --version` reports `xdpmacfilter 0.3.0` | Run `${LOADER_BIN} --version`; output MUST be `xdpmacfilter 0.3.0` (single line, ending newline). Version bump from 0.2.3 → 0.3.0 per Done-Definition (MVP-3.1 is a minor release: new feature, backward-compatible CLI surface). |
| PI-9 | `xdpmacfilter --version` / `--help` output FORMAT unchanged (just version number bumps + `apply` line in --help) | `T_CLI_HELP_VERSION` re-run passes (existing ERE in §6.10 is forward-compatible per §5.25 Q4 T1). The `--help` text gains one line listing `apply`; ERE in T_CLI_HELP_VERSION does NOT pin help-text length, so this passes. |
| PI-10 | Existing constants in `src/common/mac_filter.h` UNCHANGED | `git diff src/common/mac_filter.h` shows ONLY additions (the new §5.26 Q6 constants); zero modifications/removals on existing lines (`xdpmf_mac`, `mac_filter_stat`, `XDPMF_BPFFS_ROOT`, `XDPMF_ALLOWLIST_MAX`, `XDPMF_MAP_ALLOWLIST_NAME`, `XDPMF_MAP_STATS_NAME`). |
| PI-11 | Internal directory layout = `src/lib/` + `src/cli/` + `src/common/` + `src/bpf/` (no `src/loader/` after this slice) | `test -d src/loader` returns false (or directory exists empty post `git rm`); CMake target `xdpmf_internal` exists per Q1 R1 + STATIC; reviewer asserts `find src -type d` matches exactly the four-directory layout. |
| PI-12 | Pin paths under `${XDPMF_BPFFS_ROOT}/<iface>/` are host-global (visible from any netns under `nsenter --net` per §5.25 EDIT-15) | `nsenter --net=/var/run/netns/xdpmf_ns_$$ ls /sys/fs/bpf/xdpmacfilter/<iface>/` shows all new pins (`link`, `active_idx`, `rulesets`, `allowlist_a`, `allowlist_b`, `defaults`, `stats`). Same test infrastructure as §5.25 used; no new mechanism. |
| PI-13 | `stats` map type + read protocol UNCHANGED from §5.23 (`BPF_MAP_TYPE_PERCPU_ARRAY` + `read_stats.py` sum-across-CPUs) | `read_stats` helper still works on the post-§5.26 build; PERCPU schema unchanged; STAT_PASS / STAT_DROP_DENY / STAT_DROP_MALFORMED semantics unchanged. |
| PI-14 | `--mode {generic,native,offload}` flag on `attach` UNCHANGED from §5.23 (and forwarded by `apply`) | §6.16 T_MODE_GENERIC_DEFAULT + §6.17 T_MODE_NATIVE_UNSUPPORTED + §6.19 T_MODE_DETACH_REJECTS all pass. `apply` accepts the same flag with the same semantics. |

#### §5.26 OOS — Composite 6 components SHIPPED + new fences

##### Moved from deferred to SHIPPED (per Composite 6)

- ~~**No YAML config file** — config is CLI-only.~~ **— SHIPPED in §5.26 (MVP-3.1, 2026-05-24)** via Items 2 + 4 (custom YAML subset parser per HG1 + Q-HG1 grammar; `apply -f <file>` subcommand per Q4 G1). MAC-only matching in cycle 1 (CIDR / ports etc. lands in MVP-3.2+ as in-config rule-type extensions, NOT as new CLI flags).
- ~~**No `--allow` post-attach mutation** — to change the list, detach and re-attach. MVP-3 may add a `set-allowlist` subcommand.~~ **— SHIPPED in §5.26 (MVP-3.1, 2026-05-24)** via Item 3 atomic apply (ARRAY_OF_MAPS[2] + active_idx flip per Q2 A1). `xdpmacfilter apply -f <new-config>` is the hot-reload primitive; the existing `--allow` remains as a one-rule shorthand per Q3 BC1.
- ~~**No `bpf_link__pin()` survival across loader exit** (P0a — Open Q #12 in architecture-v2.md)~~ **— SHIPPED in §5.26 (MVP-3.1, 2026-05-24)** via Item 5 (HG2). Filter persists at `${XDPMF_BPFFS_ROOT}/<iface>/link` across loader-process termination; verified by §6.25 T_LINK_PERSIST_ACROSS_LOADER_EXIT.
- ~~**No internal code reorg** — `src/loader/` is a single dir.~~ **— SHIPPED in §5.26 (MVP-3.1, 2026-05-24)** via Item 1 + Q1 R1 minimum split. `src/loader/` → `src/lib/` (BPF-facing) + `src/cli/` (user-facing). Internal STATIC target `xdpmf_internal`. No SONAME; no installed headers; this is a refactor, not a library promotion (library promotion remains MVP-3.6+ optional branch per architecture-v2.md line 261).
- ~~**No `XDPMF_TRUST_MODEL` env var** — single-mode loader (strict-only).~~ **— SHIPPED in §5.26 (MVP-3.1, 2026-05-24)** via Item 6 + HG3. `strict|fleet`; strict default; relaxes §5.4 ONLY. Audit story via mandatory stderr log at attach.

##### NEW out-of-scope fences (per §5.26)

- **No L3 src-CIDR axis** — MVP-3.2 slice (lands as in-config rule type, NOT as new CLI flag). `architecture-v2.md` dependency graph line 217 + brief §1.
- **No per-rule counters + `xdpmf-exporter` binary + Prometheus** — MVP-3.4 slice. Composite 6 cycle 1 keeps existing global PERCPU_ARRAY stats untouched (`STAT_PASS` / `STAT_DROP_DENY` / `STAT_DROP_MALFORMED` per §5.23).
- **No `systemd xdpfilter@.service` template + Ansible playbook** — MVP-3.3 slice.
- **No public `libxdpmf.so.0` SONAME-committed library** — MVP-3.6+ optional branch. The internal STATIC target `xdpmf_internal` per Q1 R1 makes future promotion mechanical but does NOT ship it now (no installed headers; no SONAME; no pkg-config).
- **No `xdpmfd` daemon** — MVP-3.6+ optional branch (only if measured reload cadence demands sub-second).
- **No AF_XDP / mirror / rate-limit / redirect actions** — MVP-3.8+ deferred.
- **No JSON structured logs** — MVP-3.5 slice. `--version` / `--help` / error stderrs stay plain text per MVP-1.
- **No sFlow ringbuf emitter** — MVP-3.6 (conditional on hw-sFlow absence).
- **No binary rename `xdpmacfilter` → `xdpfilter`** — MVP-3.12 slice. The on-disk YAML path `/etc/xdpfilter/<iface>.yaml` (with `xdpfilter` in the path) is the FUTURE name; the binary stays `xdpmacfilter` for now. Operator docs MAY note the path-vs-binary asymmetry as a known forward-rename hint.
- **No automatic kernel tripwire (C.5)** — **KILLED** (not deferred). `architecture-v2.md` line 297 — fail-open inverts allowlist policy; manual bypass primitive in MVP-3.4 covers ops need.
- **No per-axis trust model env vars** — explicitly fenced by HG3. Single switch `XDPMF_TRUST_MODEL=strict|fleet` only. Future MVP-3.3+ MAY add additive override env vars on top, but the base axis stays single.
- **No full YAML parser (yaml-cpp, rapidyaml)** — explicitly fenced by HG1. Custom subset per Q-HG1 only.
- **No schema versions other than `1`** — Q5: `1` only in cycle 1; `schema_version: 2` is for future breaking changes at MVP-3.3+.
- **No multi-interface config in one file** — one file = one interface (`/etc/xdpfilter/<iface>.yaml` per `architecture-v2.md` line 43). The `interface:` field in YAML is a redundant declaration that MUST match `--iface`; multi-iface fan-out via Ansible/systemd template per MVP-3.3.
- **No hot-reload signal handler** (e.g. `SIGHUP` triggers re-read of config) — apply happens via re-invoking `xdpmacfilter apply -f`, not via signals. Daemon-style reload is the MVP-3.6+ daemon branch.
- **No `--dry-run` / `--validate-only` / `--diff-against-current` flags on `apply`** — cycle 1 is verb-only (Q4 G1). Future MVP-3.3+ MAY add `--dry-run` (validate + report would-apply changes, no kernel touch) if operator demand emerges; out of cycle 1.
- **No fleet-mode relaxation of §5.19 OR §5.22 (path discipline / tag-check)** — HG3 fences this hard. Fleet relaxes ONLY §5.4 alien-program disposition; PI-3 + PI-4 + PI-5 in Preserved invariants enforce this. Reviewer's 5th framework point checks PI-3/PI-4/PI-5 explicitly.
- **No identity helper extraction to `src/lib/identity.{cpp,hpp}`** (Q1 R1 carve-out) — identity helpers stay in `loader.cpp` anon namespace; promotion to a sub-module is MVP-3.4+ if per-rule counter machinery pressures the anon namespace.
- **No `XDPMF_BPFFS_ROOT` rename to `XDPMF_CONFIG_ROOT` or similar** — the bpffs root constant stays `XDPMF_BPFFS_ROOT` (the YAML config root `/etc/xdpfilter/` is OPERATOR-side, not loader-coded; the loader takes `-f <path>` and does not search a default location in cycle 1).
- **No CHANGELOG auto-generation** — `[0.3.0]` entry manually authored per §5.25 V1 precedent.
- **No T2-strict version assertion in T_CLI_HELP_VERSION** — §5.25 Q4 T1 ERE remains forward-compatible across 0.2.3 → 0.3.0 bump; no test edit required.
- **No `bpf_link__update_program` fallback for kernels that don't support hot-swap** — assumed-supported per libbpf 1.x + kernel 5.7+; floor 5.15 enforces this. If a future kernel regresses, impl falls back to unpin + fresh-attach (one extra packet-window) and emits stderr `link update unsupported on this kernel; falling back to detach+attach` — but this fallback path is OOS for cycle 1 (no test, no contract; if observed in Phase B, fold via standard inline-merge per HG2).
- **No background-injector framework abstraction** — §6.23 ships with a one-off bash `&` loop; if MVP-3.2+ tests need more concurrent traffic patterns, a generic `inject_continuous` helper lands then.
- **No `XDPMF_INJECT_RATE_HZ` documentation in `--help`** — env var is test-only infrastructure (per §6.23 SKIP-rate threshold mechanism); intentionally undocumented in public CLI surface.
- **No exposing of `internal::apply_request` on `loader.hpp` public API** (per Phase B clarification EDIT-1) — the shared atomic-apply helper lives in `src/lib/apply_internal.hpp`, namespace `xdpmf::internal`. `loader.hpp` byte-equivalence (PI-7) is load-bearing for reviewer's invariant check. Promoting `apply_request` to a public `xdpmf::` symbol is MVP-3.6+ work (only if the library extraction branch lands AND a named external consumer needs it).
- **No `default_action` field on `AttachConfig`** (per Phase B clarification EDIT-1) — AttachConfig stays at MVP-2/§5.23 `{iface, allow, mode}`. `loader::attach()` ALWAYS synthesizes `default_action: Drop` per Q3 BC1; operators needing pass-default use `apply -f`. This preserves AttachConfig binary compatibility AND matches the MVP-2 §5.7 "empty allow-list = drop-all" semantic.
- **No alternative layering where `apply.cpp` calls into `loader.cpp` anon-namespace machinery directly** (per Phase B clarification EDIT-1) — anon-namespace symbols are translation-unit-private; cross-TU access requires the named `internal::` symbol exported via `apply_internal.hpp`. The internal header is the ONLY mechanism for sharing the atomic-apply machinery between loader.cpp and apply.cpp.

#### §5.26 verifiable invariants for reviewer

In addition to §5.26 Preserved invariants (PI-1..PI-14) above:

- `git diff main -- src/lib/loader.hpp` (post file-move) shows: rename
  from `src/loader/loader.hpp` + ONE added line (`    ConfigError        = 9,`).
  NO other line diff. Reviewer's `loader.hpp`-invariant check accepts
  this exact pattern.
- `git diff main -- src/common/mac_filter.h` shows: ONLY additions (the
  new §5.26 Q6 constants); zero modifications to existing lines.
- `git diff main -- src/cli/main.cpp` (post file-move) shows: rename +
  `ParsedApply` dispatch arm + `is_config_error` helper + try/catch
  refactor to suppress `error: ` prefix on `ConfigError` so stderr
  starts EXACTLY with `xdpmacfilter: config error:` per Q-HG1 stderr
  contract (load-bearing for `T_EXIT_CODE_9_ON_CONFIG_ERROR.sh:62`
  `grep -qE '^xdpmacfilter: config error:'`). The original "ONE added
  dispatch arm. NO other line diff" budget was too strict — the
  `is_config_error` helper is REQUIRED by the start-of-line stderr
  contract. Reviewer accepts this expanded shape; OOT [POST-REVIEW
  SWEEP round 1] amended this invariant for accuracy.
- `git diff main -- tests/T_*.sh` (existing 20) shows ZERO body
  changes.
- 7 new ctests pass (§6.21..§6.27); §6.23 + §6.25 are the load-bearing
  pair (Composite 6 promise + P0a verification).
- 20 existing ctests still pass (or legitimately SKIP-77 per §5.24
  Q4 hybrid).
- `XDPMF_SANITIZERS=ON` build clean.
- `xdpmacfilter --version` reports `xdpmacfilter 0.3.0` (bump from
  0.2.3 to mark MVP-3.1; CMake `project(VERSION)` per MVP-2 Polish-2
  V1 mechanism).
- `xdpmacfilter --help` lists `apply` alongside `attach` / `detach`.
- `CHANGELOG.md` entry `[0.3.0] - 2026-05-NN` (Keep-a-Changelog
  format per MVP-1.1C precedent).
- Build-pace table in CHANGELOG gains a row for MVP-3.1.

Evidence: `mint/task-brief.md` MVP-3.1 brief (Items 1-6 + Q1-Q6
+ HG1-HG3); `mint/architecture-v2.md` lines 147-168 (Composite 6
spec) + lines 328-332 (per-phase risk register MVP-3.1 rows); §5.4 /
§5.19 / §5.20 / §5.22 / §5.23 / §5.24 / §5.25 (the invariants this
slice preserves); §4.1 (exit-code table, gains row 9); §4.3
(LoaderError enum, gains `ConfigError = 9`).

### 5.27 MVP-3.2: L3 src-CIDR rule type (Composite 6 cycle 2, 2026-05-24) — amendment block

Append-only amendment landing **MVP-3.2 — L3 src-CIDR rule type**
per `mint/architecture-v2.md` lines 215-223 (MVP-3.2 dependency-graph
row) + line 310 (per-phase scope summary) + lines 333-334 (per-phase
risk register MVP-3.2 rows). This is the **first extension WITHIN
the config-driven path** built by §5.26 — not a CLI-flag bolt-on
(that path was explicitly rejected at architecture round-2 to avoid
throwaway surface).

Estimated cost: **~120-180 LOC source + ~80 LOC test**, **3-5 new
ctests**. Smaller than §5.26 (config harness is built; this slice
extends it). MVP-3.1 deviations D-3.1-1..D-3.1-4 STAND unchanged:
the `apply_internal.hpp` helper, the `${PIN_DIR}/allowlist` alias
pin, `apply -f` file-IO → `CliError` exit 1, and the `bpf_map__reuse_fd`
state-b reattach path are all the load-bearing scaffolding this
slice extends.

Four interlocking pieces land together (carving them apart creates
half-applied state in the BPF datapath):

| # | Where | One-line |
|---|---|---|
| 1 | EDIT `src/bpf/mac_filter.bpf.c` (LPM_TRIE inner maps + parallel ARRAY_OF_MAPS outer per Q1 AS1 + OR-compose datapath per Q2 OR1 + STAT_PASS_CIDR increment); EDIT `src/common/mac_filter.h` (new map names + LPM_TRIE key struct `xdpmf_cidr_v4` + `STAT_PASS_CIDR = 3` + `STAT_MAX = 4`) | BPF datapath learns the CIDR axis. Existing MAC-only datapath is preserved (OR1 short-circuits on MAC hit). |
| 2 | NEW `src/lib/cidr.{cpp,hpp}` (CIDR string parser: `A.B.C.D/N` → `xdpmf_cidr_v4{prefixlen, addr}`); EDIT `src/lib/config.{cpp,hpp}` (`RuleMatch.src_cidr` field per Q3 K2 + validator extension: rule MUST have `mac` OR `src_cidr` OR both; v6 strings rejected with exit 9 per HG-3.2-1) | Schema gains optional `src_cidr` rule-match key. v4-only; v6 explicitly rejected. |
| 3 | EDIT `src/lib/loader.cpp` `internal::apply_request` (populate inactive `cidr_allowlist_<a\|b>` LPM_TRIE alongside inactive `allowlist_<a\|b>` HASH BEFORE the active_idx flip per Q1 AS1) | Apply orchestrator populates BOTH axes' inactive inner before the single u32 flip commits the swap. |
| 4 | STAT_PASS_CIDR counter (folded into Item 1's BPF + header edit). EDIT `tests/lib/read_stats.py` (new optional `--include-pass-cidr` flag emits 4-column output; default 3-column output unchanged for PI-6 back-compat) | Operators reading stats see the MAC-vs-CIDR split when they ask for it; existing tests' read protocol UNCHANGED. |

#### Inherited human-gate decision (closed BEFORE architect — NOT re-opened)

**HG-3.2-1 — IPv4 only for cycle 1, IPv6 fenced to MVP-3.2.5+**:
LPM_TRIE with a 128-bit IPv6 key doubles ctest count and inflates
validator complexity (operator-friendly auto-detect of v4 vs v6 in
a single `src_cidr` string is a non-trivial axis on its own). The
v4 LPM_TRIE shape (8-byte key: `__u32 prefixlen` + `__u32 addr_be`)
establishes the pattern; v6 is mechanical repetition with a 20-byte
key in a future slice. **v6 strings MUST be rejected at the validator
with `ConfigError` exit 9 + recognizable stderr** (`xdpmacfilter:
config error: IPv6 CIDR not supported until MVP-3.2.5: '<value>'`).
Silent accept-and-ignore is explicitly forbidden — operators who
write `src_cidr: "::1/128"` MUST hear about it.

#### Q1 decision — ARRAY_OF_MAPS atomic-swap shape = **AS1 (parallel outer maps)** — because

**Choice**: ADD a SECOND ARRAY_OF_MAPS outer
`cidr_rulesets_outer = ARRAY_OF_MAPS[XDPMF_RULESET_COUNT]` pointing
at two LPM_TRIE inner maps (`cidr_allowlist_a` slot 0,
`cidr_allowlist_b` slot 1). The existing `rulesets_outer` (HASH
inners, per §5.26 Q2 A1) is UNCHANGED. **Both outers share the same
`active_idx` map** (one `BPF_MAP_TYPE_ARRAY[1]` of `__u32`). A
single `bpf_map_update_elem(&active_idx_map, &zero, &new_idx,
BPF_ANY)` userspace write is atomic for the `__u32` slot on all
supported architectures — and it simultaneously commits the swap
for BOTH the MAC HASH inner AND the CIDR LPM_TRIE inner because
both outers index the same slot. **Composite-6 atomic-swap promise
preserved byte-for-byte**: one u32 write = one commit point = one
race-window (same benignity proof as §5.26 Q2 A1).

**Rationale** (AS1 vs AS2 vs AS3):

- AS2 (combined outer struct: one outer slot value = `{mac_inner_fd,
  cidr_inner_fd}` pair) requires either a wider value type in
  ARRAY_OF_MAPS (not supported by BPF — outer value is exactly one
  fd) OR a kernel-side join structure (custom BTF type). Over-clever;
  no kernel-builtin map type does this. Hard-rejected.
- AS3 (independent maps, two-step swap) violates §5.26's load-bearing
  atomic-swap invariant. Risk-register MVP-3.2 row 1 explicitly
  flags this as the riskier path: a half-applied window where MAC
  inner is swapped but CIDR inner isn't would cause asymmetric
  drops on cross-axis traffic. Tester would have to write a
  half-applied-tolerance test that proves no drops despite the
  window — strictly more work AND strictly weaker invariant than
  AS1. Hard-rejected.
- AS1 is the smallest possible extension of §5.26 Q2 A1: the
  mechanism is bit-for-bit identical (single u32 indexes a parallel
  outer), just doubled. The BPF program reads `active_idx` ONCE
  and uses the same value to index BOTH outers — guaranteeing
  intra-packet axis consistency. The kernel verifier accepts the
  pattern (Cilium-style chained inner-deref on ARRAY_OF_MAPS, well-
  trodden on libbpf ≥ 1.0 / kernel ≥ 4.12, well below floor 5.15).

**Race-window analysis** (per §5.26 Q2 A1 precedent): can the
`active_idx` flip happen between the BPF program's MAC-axis lookup
and its CIDR-axis lookup? Yes (userspace flip is not BPF-preemption-
blocked on other CPUs). Consequence is benign by mandatory program
structure — **the BPF program reads `active_idx` ONCE at the head
of the datapath, captures it into a local variable, and uses that
captured value for BOTH the MAC-outer-deref AND the CIDR-outer-
deref**. Even if the userspace flip races in mid-program, the
program operates on the snapshot it already read. The new inner is
fully populated BEFORE the flip (steps 1+2 below); so even the
post-flip read hits a complete CIDR ruleset.

**Apply ordering** (extends §5.26 attach() flow step 12 / D-3.1-4
state-b reattach):

1. Compute `inactive_idx = 1 - current_active_idx` (read current
   active_idx via the reused fd per D-3.1-4).
2. Populate `cidr_allowlist_<inactive>` LPM_TRIE with all rules
   that have `match.src_cidr` set (per Q4 L1: single CIDR per
   rule). Key = `xdpmf_cidr_v4{prefixlen, addr_be}`; value = `__u8{1}`
   (presence marker). Order-independent within the LPM_TRIE.
3. Populate `allowlist_<inactive>` HASH with all rules that have
   `match.mac` set (per existing §5.26 mechanism).
4. Populate `defaults_map[inactive_idx]` (per existing §5.26
   Q2-extension).
5. **Atomic flip**: `active_idx_map[0] = inactive_idx`. Single u32
   commit. The NEW MAC ruleset, NEW CIDR ruleset, and NEW
   default_action all become live at the same kernel instruction.

#### Q2 decision — OR-compose precedence + short-circuit order = **OR1 (MAC first, then CIDR)** — because

**Choice**: BPF datapath checks the MAC HASH first. On hit
(`STAT_PASS` + `XDP_PASS`, short-circuit). On miss, if the frame's
EtherType is IPv4 (`htons(0x0800)`), parse the IPv4 header (verifier
bounds-checked) and look up the source IP in the CIDR LPM_TRIE. On
hit, `STAT_PASS_CIDR` + `XDP_PASS`. On miss (or non-IPv4 ethertype),
fall through to the existing `defaults_map[active_idx]` evaluation
(per §5.26 BPF program flow).

**Rationale** (OR1 vs OR2 vs OR3):

- OR2 (CIDR first) inverts the cost-benefit: LPM_TRIE is O(prefix-
  length) per lookup; HASH is O(1). For a fleet where most packets
  match by MAC (operator's typical "known device" scenario), OR2
  costs LPM_TRIE work on every packet before the cheap HASH check.
  Rejected.
- OR3 (parallel, both checked, OR'd at the end) precludes short-
  circuit; per-packet cost is `O(1) + O(prefix-length)` always. The
  semantic gain (no precedence to remember) doesn't justify the
  per-packet cost. Rejected.
- OR1 short-circuits on the cheap axis. Cost profile: MAC-hit packets
  cost O(1); CIDR-hit packets cost O(1) HASH miss + O(prefix-length)
  LPM_TRIE hit. Miss-both packets cost O(1) + O(prefix-length) +
  defaults lookup — the worst case stays bounded by tree depth.

**Counter discipline**: a packet that hits the MAC axis ALWAYS
increments STAT_PASS (not STAT_PASS_CIDR). A packet that misses
MAC AND hits CIDR increments STAT_PASS_CIDR (the new counter).
Operators reading the split see "how much traffic is matched by
device identity vs network identity", which is the load-bearing
ops signal for migrations (e.g. moving a fleet from MAC-allowlists
to subnet-allowlists). **Per-rule counters that distinguish
individual rules** are MVP-3.4 work, OOS here.

**Datapath pseudocode** (replaces §5.26 BPF program flow; verifier-
aware):

```
xdp_md *ctx → parse Eth header (malformed → STAT_DROP_MALFORMED + XDP_DROP, unchanged from §3-§4 / §5.26):

__u32 zero = 0;
__u32 *active_idx_p = bpf_map_lookup_elem(&active_idx_map, &zero);
if (!active_idx_p) { STAT_DROP_DENY++; return XDP_DROP; }   /* verifier-required */
__u32 active = *active_idx_p;                               /* snapshot — used for ALL subsequent lookups this pass */

/* ── MAC axis (short-circuit per Q2 OR1) ─────────────────────────────────── */
void *mac_inner = bpf_map_lookup_elem(&rulesets_outer, &active);
if (!mac_inner) { STAT_DROP_DENY++; return XDP_DROP; }      /* verifier-required */
__u8 *mac_hit = bpf_map_lookup_elem(mac_inner, &src_mac);
if (mac_hit) { STAT_PASS++; return XDP_PASS; }              /* MAC axis matched */

/* ── CIDR axis (only if MAC missed AND frame is IPv4) ───────────────────── */
if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        STAT_DROP_MALFORMED++; return XDP_DROP;             /* IP header truncated */
    }
    struct iphdr *ip = (struct iphdr*)(data + sizeof(struct ethhdr));
    void *cidr_inner = bpf_map_lookup_elem(&cidr_rulesets_outer, &active);
    if (!cidr_inner) { STAT_DROP_DENY++; return XDP_DROP; } /* verifier-required */
    struct xdpmf_cidr_v4 key = { .prefixlen = 32u, .addr = ip->saddr };
    __u8 *cidr_hit = bpf_map_lookup_elem(cidr_inner, &key);
    if (cidr_hit) { STAT_PASS_CIDR++; return XDP_PASS; }    /* CIDR axis matched */
}
/* non-IPv4 ethertypes (ARP, IPv6, etc.) skip the CIDR axis entirely —
 * preserves MVP-3.1 semantic for non-IP traffic per brief §1. */

/* ── Fall through to defaults_map[active] (per §5.26 Q2-extension) ──────── */
__u32 *default_p = bpf_map_lookup_elem(&defaults_map, &active);
if (!default_p) { STAT_DROP_DENY++; return XDP_DROP; }
if (*default_p == 1u) { STAT_PASS++; return XDP_PASS; }     /* default_action: pass */
STAT_DROP_DENY++; return XDP_DROP;                          /* default_action: drop */
```

**Verifier interactions** (impl notes):

- The IPv4-header bounds check (`data + sizeof(ethhdr) + sizeof(iphdr) > data_end`)
  is MANDATORY before dereferencing `ip->saddr`. Impl MUST NOT elide
  via `__builtin_assume`.
- `ip->saddr` is in NETWORK BYTE ORDER (big-endian on wire). The
  LPM_TRIE key's `addr` field MUST also be in network byte order —
  see DataStructures §5.27 below. Userspace `inet_pton(AF_INET, ...)`
  returns network-byte-order; no swap on impl side.
- LPM_TRIE key MUST start with `__u32 prefixlen` per BPF kernel
  convention (kernel-internal LPM_TRIE expects this layout); the
  `addr` field follows. Total key size = 8 bytes (4 prefixlen + 4
  addr).
- Both `bpf_map_lookup_elem(&rulesets_outer, &active)` AND
  `bpf_map_lookup_elem(&cidr_rulesets_outer, &active)` are verifier-
  recognized chained-inner-deref patterns; both share the same
  active_idx snapshot. Verified working on libbpf ≥ 1.0 / kernel ≥
  4.12.

#### Q3 decision — CIDR schema key naming = **K2 (`src_cidr`)** — because

**Choice**: the YAML key for the CIDR matcher is `src_cidr`.
Example minimal config:

```
default_action: drop
rules:
  - id: 0
    action: pass
    match:
      src_cidr: "10.0.0.0/8"
```

**Rationale** (K1 vs K2 vs K3):

- K1 (`cidr`) is shortest but implicitly couples the schema to
  "always src" — an unwritten assumption. The future `dst_cidr`
  sibling can't be added without either: a breaking change (`cidr`
  → `src_cidr` rename) or a confusing dual-meaning (`cidr` = src
  but `dst_cidr` = dst). Rejected on schema-evolution grounds.
- K3 (`cidr_v4`) over-commits to family-in-key naming. Per HG-3.2-1
  cycle 1 is v4-only and v6 is rejected at the validator — there
  is no `cidr_v6` sibling to disambiguate against. When MVP-3.2.5+
  lands v6, the natural shape is auto-detect on a `src_cidr`
  string (`10.0.0.0/8` → v4; `2001:db8::/32` → v6), NOT a
  family-suffixed key. K3 paints us into the wrong corner.
- K2 (`src_cidr`) makes "src" explicit, leaves space for `dst_cidr`
  as a future sibling, and auto-detects family per HG-3.2-1's
  forward path. Matches the brief's consistent "L3 src-CIDR"
  language.

**Validator behaviour** for sibling-name discipline: the future
`dst_cidr` is NOT in cycle 1's accepted match-key set. Any rule
with a `dst_cidr` (or `port`, etc.) match-key → `ConfigError` exit
9 with `match type 'dst_cidr' not supported in schema_version 1`
(reuses the §5.26 schema rule 6 forward-compat hinge).

**MAC key naming UNCHANGED**: the existing `match.mac` from §5.26
is NOT renamed to `src_mac` for symmetry. Rationale: PI-6 requires
existing MVP-3.1 configs to keep working byte-equivalent (PI-15
below). Renaming `mac` → `src_mac` would be a breaking schema
change requiring a `schema_version: 2` bump (per §5.26 Q5 SV2
policy) — out of cycle 2's additive-extension scope. Schema thus
ships ASYMMETRIC names (`mac` is implicit-src; `src_cidr` is
explicit-src); this is documented in the schema sub-section
below as a known-and-accepted irregularity.

#### Q4 decision — Single CIDR per rule vs list = **L1 (single CIDR per rule)** — because

**Choice**: each rule's `match.src_cidr` is a SINGLE CIDR string
(scalar), not a list. Operators wanting multiple CIDRs write
multiple rules:

```
rules:
  - id: 0
    action: pass
    match: { src_cidr: "10.0.0.0/8" }
  - id: 1
    action: pass
    match: { src_cidr: "192.168.0.0/16" }
```

**Rationale** (L1 vs L2):

- L2 (list of CIDRs per rule) is convenience sugar that can be
  added in a later slice without breaking L1 configs (additive
  schema extension — single-scalar still parsed as the
  one-element-list shorthand). Reverse direction (L2 → L1) would
  be a breaking schema change. Asymmetric reversibility favours
  starting at L1.
- L1 matches the existing MVP-3.1 `match.mac` pattern (single
  string, not list). Schema-symmetry across match-keys is
  pedagogically simpler for operators new to the config.
- Rule-counting (and future MVP-3.4 per-rule counters keyed by
  `id`) is unambiguous with L1: one rule = one match expression
  on each axis. L2 would force a "which CIDR within the rule
  matched" sub-axis that complicates the future per-rule counter
  story.

**Implication on max rules**: existing `XDPMF_ALLOWLIST_MAX = 64`
(§5.1) was the MAC HASH inner's max_entries. The new CIDR
LPM_TRIE inner uses the SAME constant for its `max_entries`
(`XDPMF_ALLOWLIST_MAX = 64`). Total rule capacity is 64 rules,
each contributing at most one MAC entry AND at most one CIDR
entry — so 64 MACs + 64 CIDRs across the whole config. Operators
asking for more capacity → MVP-3.4 (per-rule counters slice can
re-evaluate the 64 cap).

#### Q5 decision — Schema versioning = **V1 (additive at schema_version 1)** — because

**Choice**: `schema_version: 1` continues to be the only supported
value. `src_cidr` is an ADDITIVE extension to the cycle-1 schema
(per §5.26 Q5 SV2 migration policy: "new rule-types in `match:`
→ MUST be rejected by a `schema_version: 1` config" — superseded
here for `src_cidr` SPECIFICALLY because it is the only new match-
type landing in cycle 2; bumping to `schema_version: 2` solely
for one match-key addition cheapens the version-signal). Existing
MVP-3.1 configs (with `match.mac` only, no `src_cidr`) MUST
continue to validate without change (PI-15 below).

**§5.26 Q5 SV2 migration-policy refinement** (this amendment):
the §5.26 rule "new rule-types in `match:` MUST be rejected by a
`schema_version: 1` config" applies to FUTURE rule-types added
AFTER MVP-3.2 (e.g. `port`, `dst_cidr`, `vlan` if any of those
ship later). The MVP-3.2 `src_cidr` extension is grandfathered
into `schema_version: 1` because:
- It lands in the same cycle-2 slice as the §5.26 forward-compat
  hinge documented "MVP-3.2 lands `cidr` as in-config rule type";
  the hinge already named CIDR by intent.
- The §5.26 Q-HG1 forward-compat reject of `match: {cidr: ...}`
  (with `cidr` key) was the rejection for the UNKNOWN key name
  at schema_version 1; the chosen Q3 K2 (`src_cidr`) is now the
  KNOWN key name — additive at v1.
- Bumping to v2 for the addition of one match-key would force
  EVERY existing MVP-3.1 config writer to migrate just to use
  CIDR. Too much friction for too little signal.

The next genuine breaking change (e.g. semantic shift on
`default_action`, removal of the `mac` key, etc.) will bump to
`schema_version: 2` per §5.26 SV2 policy. Supported-set stays at
`{1}` until then.

#### Q6 decision — MVP-3.1 OOT-deferred housekeeping items = **DEFER** — because

**Choice**: items OOT-1 (orphan map pins at bpffs root from
T_ATTACH_TAG_MISMATCH) and OOT-2 (T_APPLY_ATOMIC_SWAP_NO_DROP
stale NOTE comment) are **NOT** included in MVP-3.2. They are
explicitly fenced to a dedicated housekeeping cycle (MVP-3.2.x or
folded into MVP-3.3 prep work).

**Rationale**:
- MVP-3.2 scope is tight (~120-180 LOC source + ~80 LOC test; 4
  load-bearing items with risk-register coverage on AS1 atomic-
  swap AND OR-compose semantic). Adding even cheap unrelated
  items risks anti-drift (architect's brief: "Out-of-scope is
  the anti-drift fence — if tempted to 'while I'm here, also
  add X', X belongs in section 7").
- Both items are pure hygiene (test-fixture cleanup + comment
  text); no operator-facing behaviour change. The cost-benefit
  of bundling them into MVP-3.2 is negligible.
- Brief's exact wording: "include if architect judges scope
  budget allows; defer otherwise" — architect judges scope is
  load-bearing on the AS1 atomic-swap test (T_CIDR_ATOMIC_SWAP_NO_DROP
  per §6.31), which is itself non-trivial; deferring hygiene is
  the conservative call.

**Carve-out plan**: items OOT-1, OOT-2, OOT-3 (`cli.hpp ParsedAttach`
wrapper design-text fix from MVP-3.1 review), and OOT-4 (§6.25
"replacing existing program" grep tightening) remain in their
original disposition — flagged in `mint/review.md` MVP-3.1
deferral table; a future "MVP-3.x housekeeping" or "MVP-3.3 prep"
cycle picks them up. If MVP-3.3 lands first, fold OOT-1/2 into
the systemd-prep groundwork.

#### §4.1 exit-code table — row 9 (`ConfigError`) REUSED, no new row added

CIDR validation failures (malformed `A.B.C.D/N` string, prefix-
length out of `[0, 32]`, network bits set below prefix, IPv6
string per HG-3.2-1) ALL map to `LoaderError::ConfigError = 9`.
The `LoaderError` enum gains **ZERO** new enumerators in this
slice — PI-7-style invariant from §5.26 is preserved at strength
(see PI-7-3.2 below).

**Rationale**: CIDR is purely a config-layer rejection (the YAML
content is the only source of the malformed input; no kernel
call has happened yet). A new exit code would create an audit-
grep distinction between "YAML schema wrong" and "CIDR value
wrong", but operators reading exit 9 already learn the failure
class via the stderr message (`config error: malformed CIDR:
'<value>': ...` vs `config error: default_action must be 'drop'
or 'pass'`). The stderr-message resolution is sufficient; another
enum value cheapens the signal-per-code ratio.

**Stderr message catalogue** for CIDR-validation failures (impl
emits ONE of these, prefixed `xdpmacfilter: config error: `):

| Trigger | Stderr message |
|---|---|
| `src_cidr: ""` (empty) | `malformed CIDR: empty string` |
| `src_cidr: "10.0.0.0"` (no `/N`) | `malformed CIDR: missing prefix length: '10.0.0.0'` |
| `src_cidr: "10.0.0.0/"` (empty N) | `malformed CIDR: empty prefix length: '10.0.0.0/'` |
| `src_cidr: "10.0.0.0/33"` (prefix > 32) | `malformed CIDR: prefix length out of range [0,32]: '10.0.0.0/33'` |
| `src_cidr: "10.0.0.0/-1"` (negative) | same as above (validator collapses negatives + overflow) |
| `src_cidr: "999.0.0.0/8"` (octet > 255) | `malformed CIDR: invalid IPv4 address: '999.0.0.0/8'` |
| `src_cidr: "10.0.0.5/8"` (net-bits set) | `malformed CIDR: host bits set below prefix: '10.0.0.5/8' (did you mean 10.0.0.0/8?)` |
| `src_cidr: "::1/128"` (any IPv6) | `IPv6 CIDR not supported until MVP-3.2.5: '::1/128'` |
| `src_cidr: "not-a-cidr"` (no `/`) | `malformed CIDR: missing prefix length: 'not-a-cidr'` |
| `match: {}` (neither mac nor src_cidr) | `rule must specify 'mac' or 'src_cidr' (or both)` |

Tester asserts only the LEADING substring per case (`xdpmacfilter:
config error: malformed CIDR:` OR `xdpmacfilter: config error:
IPv6 CIDR not supported`) — operator-facing text past the prefix
is impl-shape-flexible.

#### §5.27 schema extension (data on disk)

The on-disk YAML at `/etc/xdpfilter/<iface>.yaml` gains the
`src_cidr` match-key (post-§5.27 shape):

```
# schema_version: 1 (default 1; UNCHANGED from §5.26)
default_action: drop
rules:
  - id: 0
    action: pass
    match:
      mac: "AA:BB:CC:DD:EE:FF"      # MAC-only rule (MVP-3.1 shape; still valid)
  - id: 1
    action: pass
    match:
      src_cidr: "10.0.0.0/8"        # CIDR-only rule (NEW MVP-3.2)
  - id: 2
    action: pass
    match:
      mac: "11:22:33:44:55:66"      # MAC + CIDR within one rule (OR-compose; NEW MVP-3.2)
      src_cidr: "192.168.0.0/16"
```

**Cycle-2 schema rules** (validator enforces; ALL failures → exit 9):

7. Each rule's `match` mapping MUST contain AT LEAST ONE of `mac`
   or `src_cidr`. Empty `match: {}` → `rule must specify 'mac' or
   'src_cidr' (or both)`. (Replaces §5.26 schema rule 5's
   "REQUIRED in cycle 1" framing of `mac`; cycle 2 relaxes to
   either axis.)
8. `match.src_cidr` (when present) MUST be a string in the form
   `A.B.C.D/N` where each `A.B.C.D` is a valid IPv4 dotted-decimal
   (4 octets, each `[0, 255]`) and `N` is an integer `[0, 32]`.
   The network address (`A.B.C.D`) MUST have all bits below
   prefix `N` set to zero (host-bits-set rejected per the message
   catalogue above). Both axes (`mac` AND `src_cidr`) may be set
   on the same rule — interpretation is OR-compose (see Q2 OR1).
9. IPv6 CIDR strings (any input containing `:` other than as a
   schema-key separator, e.g. `::1/128`, `2001:db8::/32`) → reject
   per HG-3.2-1 with the IPv6-specific stderr. Validator detects
   v6 by scanning for `:` in the value; v4 has no colons.
   (Edge case: an IPv4-mapped-IPv6 string like `::ffff:10.0.0.0/104`
   is rejected as v6 — operators wanting that traffic write the
   v4 CIDR `10.0.0.0/8`.)
10. Schema rule 5 from §5.26 (cycle 1: `mac` REQUIRED in `match`)
    is SUPERSEDED by rule 7 above. Add `[SUPERSEDED BY §5.27]`
    inline at the §5.26 schema-rule-5 listing — see Edit-2 below.
11. Schema rule 6 from §5.26 (cycle 1: ONE match type per rule)
    is SUPERSEDED by rules 7+8 above. The new rule allows BOTH
    `mac` AND `src_cidr` on the same rule (OR-compose). Other
    match-keys (`port`, `vlan`, `dst_cidr`, etc.) STILL rejected
    per §5.26 schema rule 6's forward-compat hinge — add
    `[SUPERSEDED BY §5.27 for src_cidr ONLY]` inline at the
    §5.26 schema-rule-6 listing.

**Apply-time computation of inner-map contents** (extends §5.26):
- For each rule with `action: pass` AND `match.mac` set → add the
  MAC to the inactive `allowlist_<inactive>` HASH inner (presence-
  marker value = 1). UNCHANGED from §5.26.
- For each rule with `action: pass` AND `match.src_cidr` set →
  add the `xdpmf_cidr_v4{prefixlen, addr_be}` key to the inactive
  `cidr_allowlist_<inactive>` LPM_TRIE inner (presence-marker
  value = 1). NEW.
- A rule with BOTH `mac` AND `src_cidr` set populates BOTH inners
  (the kernel-side OR-compose at lookup time is what makes it
  "either axis matches → PASS"). The single `id` is shared across
  axes — future MVP-3.4 per-rule counters will key by `id` for
  the union.
- Rules with `action: drop` populate NEITHER inner (drop is
  default; accepted-but-no-op in cycle 2 per §5.26).

#### §5.27 DataStructures additions

##### BPF + userspace shared (`src/common/mac_filter.h`)

Additions to the existing header (post-§5.27):

```
/* §5.27 (MVP-3.2): L3 src-CIDR axis — see design §5.27 Q1 + Q2. */

/* LPM_TRIE key for IPv4 CIDR matching. Kernel BPF LPM_TRIE requires
 * the key to begin with `__u32 prefixlen`; the trailing field holds
 * the address in NETWORK BYTE ORDER (big-endian; matches `iphdr.saddr`
 * on the wire — no swap needed in datapath). Total size = 8 bytes. */
struct xdpmf_cidr_v4 {
    unsigned int prefixlen;  /* bits in network mask, range [0, 32] */
    unsigned int addr;       /* IPv4 address, big-endian (network order) */
} __attribute__((packed));
/* NOTE: `unsigned int` (not `__u32`) per the existing shared-header
 * convention — this header is included from BOTH userspace C++
 * (where `__u32` isn't a libc type) AND BPF C. Mirrors `xdpmf_mac`'s
 * use of `unsigned char` over `__u8` at mac_filter.h:24. Structurally
 * byte-identical on all supported architectures. [POST-REVIEW SWEEP
 * round 1, OOT-1 inline-merge.] */

#define XDPMF_MAP_CIDR_RULESETS_OUTER_NAME  "cidr_rulesets"     /* ARRAY_OF_MAPS[XDPMF_RULESET_COUNT] of LPM_TRIE fds */
#define XDPMF_MAP_CIDR_INNER_A_NAME         "cidr_allowlist_a"  /* inner slot 0, LPM_TRIE */
#define XDPMF_MAP_CIDR_INNER_B_NAME         "cidr_allowlist_b"  /* inner slot 1, LPM_TRIE */
```

And the existing `enum mac_filter_stat` gains ONE new value +
STAT_MAX bumps:

```
enum mac_filter_stat {
    STAT_PASS           = 0,   /* UNCHANGED */
    STAT_DROP_DENY      = 1,   /* UNCHANGED */
    STAT_DROP_MALFORMED = 2,   /* UNCHANGED */
    STAT_PASS_CIDR      = 3,   /* §5.27 NEW: frame passed via CIDR-axis match */
    STAT_MAX            = 4,   /* §5.27 BUMP: was 3; sentinel = stats map max_entries */
};
```

**On STAT_MAX bumping** (PI-10 nuance, see PI-10-3.2 below): the
existing PI-10 invariant ("existing constants UNCHANGED") fenced
the **named map constants** and the **layout of `xdpmf_mac`**;
STAT_MAX has always been an internally-derived sentinel
(`STAT_MAX = max_entries of stats map`). Bumping STAT_MAX from
3 → 4 in lockstep with the new STAT_PASS_CIDR slot is an
ADDITIVE change to the enum, not a modification to existing
slot values. STAT_PASS / STAT_DROP_DENY / STAT_DROP_MALFORMED
keep their indices 0/1/2. Reviewer's PI-10 check accepts the
diff pattern: new enum value `STAT_PASS_CIDR = 3` added + STAT_MAX
incremented `3 → 4`; existing enum values byte-identical.

##### Userspace (`src/lib/cidr.hpp`, namespace `xdpmf::cidr`)

<!-- [POST-REVIEW SWEEP round 1, OOT-2 inline-merge.] Sub-namespace
     `xdpmf::cidr` mirrors the existing `xdpmf::yaml` precedent for
     parser modules (scope-narrowing). Call site: `xdpmf::cidr::
     parse_cidr_v4(...)`. -->


NEW file. Pure parser + struct converter (no I/O, no kernel touch):

```
/* CIDR string parsing. Accepts ONLY IPv4 (HG-3.2-1).
 * Throws std::system_error{LoaderError::ConfigError, ...} on any
 * malformed input per §5.27 §4.1 stderr message catalogue. */
[[nodiscard]] xdpmf_cidr_v4 parse_cidr_v4(std::string_view  s,
                                          std::string_view  file_path_for_diagnostics,
                                          std::uint32_t     line,
                                          std::uint32_t     col);
```

Returns `xdpmf_cidr_v4{prefixlen, addr}` where:
- `prefixlen ∈ [0, 32]` validated against the input.
- `addr` is in network byte order (`htonl` not needed: `inet_pton`
  output already is). Validated to have ALL bits below `prefixlen`
  set to zero (`addr & ~mask == 0` where `mask = (prefixlen == 0
  ? 0 : htonl(0xFFFFFFFFu << (32 - prefixlen)))`).
- v6 input detected by presence of `:` in the value before the
  `/` boundary → throws with the IPv6-specific stderr.

Impl uses `inet_pton(AF_INET, ...)` (POSIX, no new dep — already
implicitly available via `<arpa/inet.h>`). No `inet_aton` fallback
(brief permits either; `inet_pton` is the stricter modern API).

##### Userspace (`src/lib/config.hpp`) — `RuleMatch` extension

```
struct RuleMatch {
    std::optional<xdpmf_mac>      mac;       /* UNCHANGED from §5.26 */
    std::optional<xdpmf_cidr_v4>  src_cidr;  /* §5.27 NEW (Q3 K2) */
};
```

`Rule` and `Config` structs are UNCHANGED. The validator (in
`config.cpp`) is extended to:
1. Recognize `src_cidr` as a known match-key (per Q3 K2).
2. Delegate `src_cidr` string parsing to `cidr::parse_cidr_v4()`.
3. Enforce schema rule 7 (at-least-one-of-mac-or-src_cidr per
   rule); previously enforced "mac REQUIRED" from §5.26 schema
   rule 5 — supersession noted above.

##### BPF map declarations (`src/bpf/mac_filter.bpf.c`)

Added alongside existing maps:

```
/* Inner LPM_TRIE template — referenced by cidr_rulesets_outer.value.value. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct xdpmf_cidr_v4);
    __type(value, __u8);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);     /* required for LPM_TRIE */
} cidr_allowlist_inner SEC(".maps");          /* template; NOT pinned directly */

/* Two pinned inner LPM_TRIE instances (slot 0 / slot 1). */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct xdpmf_cidr_v4);
    __type(value, __u8);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cidr_allowlist_a SEC(".maps");              /* pinned at ${PIN_DIR}/cidr_allowlist_a */

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct xdpmf_cidr_v4);
    __type(value, __u8);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cidr_allowlist_b SEC(".maps");              /* pinned at ${PIN_DIR}/cidr_allowlist_b */

/* Outer ARRAY_OF_MAPS parallel to existing rulesets_outer. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, XDPMF_RULESET_COUNT);
    __type(key, __u32);
    __array(values, struct cidr_allowlist_inner);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} cidr_rulesets_outer SEC(".maps");           /* pinned at ${PIN_DIR}/cidr_rulesets */
```

Pinning paths (post-§5.27, per LIBBPF_PIN_BY_NAME):
- `${PIN_DIR}/cidr_allowlist_a` (LPM_TRIE inner slot 0)
- `${PIN_DIR}/cidr_allowlist_b` (LPM_TRIE inner slot 1)
- `${PIN_DIR}/cidr_rulesets` (ARRAY_OF_MAPS outer)

`stats` map's `max_entries` BUMPS 3 → 4 in `mac_filter.bpf.c`:
```
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);     /* now 4 instead of 3 (header sentinel) */
    ...
} stats SEC(".maps");
```

The `stats` map's pin path is UNCHANGED (`${PIN_DIR}/stats`); the
schema (PERCPU_ARRAY of u64) is UNCHANGED; only the slot count grows
by 1 (additive). Existing readers (`read_stats.py` default mode)
keep printing indices 0/1/2 unchanged (PI-13 preserved).

#### §5.27 Interfaces additions

##### Apply orchestrator routing — `internal::apply_request` (UNCHANGED signature)

`xdpmf::internal::apply_request(const ApplyRequest& req)` in
`src/lib/apply_internal.hpp` (per D-3.1-1) keeps its signature
byte-identical. The IMPL inside `loader.cpp` is extended at step 8
(populate inactive inner) to also populate the CIDR inner per
Q1 AS1 + apply-ordering above.

`ApplyRequest` carries the validated `Config` which now has rules
with optional `src_cidr` — no struct shape change to `ApplyRequest`
either (the new field is inside the nested `RuleMatch`).

##### CLI surface — UNCHANGED

`xdpmacfilter apply -f <file> --iface <iface>` / `attach --allow
<MAC>` / `detach` / `--help` / `--version` — all UNCHANGED.
`--help` text MAY (not MUST) gain a line mentioning the new
`src_cidr` match-key under the `apply` subcommand description
(impl-flexible wording AND impl-flexible presence per the
verifiable-invariant block below; tester does NOT assert
presence — `src_cidr` discoverability via docs/CHANGELOG is
sufficient). The grammar block at the top of §4.1 needs NO
change. [POST-REVIEW SWEEP round 1, OOT-3 inline-merge: normalized
"gains ONE line" → "MAY gain a line" to match verifiable-invariant
section's "MAY list" relaxation; impl correctly chose the relaxed
reading.]

##### Loader public API (`src/lib/loader.hpp`) — ZERO diff

PI-7-3.2 (see §6.5 below): `git diff` on `src/lib/loader.hpp`
shows ZERO lines changed. The `LoaderError` enum is UNCHANGED
(`ConfigError = 9` already covers CIDR validation failures per
§5.27 §4.1 sub-section). `AttachConfig` / `DetachConfig` /
`attach()` / `detach()` signatures all UNCHANGED.

#### §5.27 attach()/apply() flow update (CIDR inner population)

Post-§5.27 `internal::apply_request()` body (incremental over
§5.26 attach() flow step 12 / D-3.1-4 state-b reattach):

```
internal::apply_request(req):
  1..7. UNCHANGED from §5.26 attach() flow (kernel probe,
        trust_model parse + log, ifindex, skel load + self_tag,
        BpffsRootFd, §5.4 state-machine, P0a link pin detect).
  8.   populate inactive slot:
         active_cur = read active_idx_map[0]
         inactive   = 1 - active_cur

         ── MAC axis (UNCHANGED from §5.26) ────────────────────
         for each rule in req.config.rules with action==Pass AND match.mac.has_value():
             bpf_map_update_elem(allowlist_<inactive>_fd, &rule.match.mac, &one, BPF_ANY)

         ── CIDR axis (NEW §5.27) ──────────────────────────────
         for each rule in req.config.rules with action==Pass AND match.src_cidr.has_value():
             bpf_map_update_elem(cidr_allowlist_<inactive>_fd, &rule.match.src_cidr, &one, BPF_ANY)
         (key is the validated xdpmf_cidr_v4{prefixlen, addr_be} — no further conversion.)

         ── defaults (UNCHANGED from §5.26) ────────────────────
         bpf_map_update_elem(defaults_map, &inactive, &(req.config.default_action == Pass ? 1u : 0u), BPF_ANY)

  9.   atomic flip (UNCHANGED from §5.26):
         bpf_map_update_elem(active_idx_map, &zero, &inactive, BPF_ANY)
       ─ single u32 store ─ atomic commit point for BOTH axes ─

 10.   post-flip cleanup (UNCHANGED from §5.26): leave previous
       slot populated (one-deep rollback history; overwritten
       next apply). NO clear of the now-inactive CIDR inner —
       same policy as MAC inner.

 11.   bpffs alias pin (D-3.1-2): `${PIN_DIR}/allowlist` legacy
       alias UNCHANGED. NO `${PIN_DIR}/cidr_allowlist` alias
       (the legacy alias was for PI-6 byte-equivalence of the
       20 pre-§5.26 tests — they pre-date the CIDR axis, so no
       CIDR alias is needed for back-compat).
```

State-b reattach path (D-3.1-4) extends symmetrically: the
`bpf_map__reuse_fd` loop iterates over BOTH the existing 6 pinned
maps (allowlist_a, allowlist_b, rulesets, active_idx, defaults,
stats) AND the 3 new pinned maps (cidr_allowlist_a, cidr_allowlist_b,
cidr_rulesets) — 9 reuse_fd calls total. Stats counters (including
STAT_PASS_CIDR) survive across applies, same mechanism as MVP-3.1.

#### §5.27 FileList (brownfield DIFF — NEW / EDITED / UNCHANGED-BUT-AFFECTED)

##### NEW (created this slice)

| Path | Role (one line) | Language | LOC est |
|---|---|---|---|
| `src/lib/cidr.hpp` | Header for IPv4 CIDR string parser: `parse_cidr_v4()` declaration | C++23 | 25 |
| `src/lib/cidr.cpp` | IPv4 CIDR parser implementation (`A.B.C.D/N` → `xdpmf_cidr_v4{prefixlen, addr_be}`; v6 reject; host-bits-set reject; uses `inet_pton(AF_INET, ...)`) | C++23 | 80 |
| `tests/T_PASS_CIDR.sh` | §6.28 test: in-range src_ip PASS + out-of-range src_ip DROP + STAT_PASS_CIDR counter assertion | bash | 80 |
| `tests/T_DROP_CIDR_NOT_IN_RANGE.sh` | §6.29 test: explicit negation case (separate from §6.28 happy-path for clarity per brief) | bash | 60 |
| `tests/T_PASS_MAC_OR_CIDR.sh` | §6.30 test (load-bearing for OR-compose risk register row 2): single rule with BOTH mac+src_cidr, 3 sub-cases (MAC-only match, CIDR-only match, neither match) | bash | 110 |
| `tests/T_CIDR_ATOMIC_SWAP_NO_DROP.sh` | §6.31 test (recommended optional): atomic swap on CIDR axis under concurrent traffic; extends §6.23 pattern for CIDR inner — load-bearing for risk register row 1 (AS1 atomic swap correctness) | bash | 100 |
| `tests/fixtures/config_valid_cidr.yaml` | Minimal valid YAML with single CIDR rule (`src_cidr: 10.0.0.0/8`); used by §6.28 + §6.29 + §6.31 | YAML | 6 |
| `tests/fixtures/config_valid_mac_or_cidr.yaml` | Valid YAML with single rule containing BOTH `mac:` AND `src_cidr:` (OR-compose fixture); used by §6.30 | YAML | 8 |
| `tests/fixtures/config_valid_cidr_swap_a.yaml` | CIDR-swap-A ruleset for §6.31 (single CIDR `10.0.0.0/8`) | YAML | 6 |
| `tests/fixtures/config_valid_cidr_swap_b.yaml` | CIDR-swap-B ruleset for §6.31 (two CIDRs `10.0.0.0/8` + `192.168.0.0/16`) | YAML | 8 |
| `tests/fixtures/config_malformed_cidr_v6.yaml` | Malformed: `src_cidr: "::1/128"` (IPv6 rejected per HG-3.2-1); used as new sub-case 6 in §6.22 (folded — see EDITED below) | YAML | 5 |
| `tests/fixtures/config_malformed_cidr_bad.yaml` | Malformed: `src_cidr: "10.0.0.5/8"` (host-bits-set); used as new sub-case 7 in §6.22 (folded) | YAML | 5 |
| `tests/fixtures/config_malformed_cidr_notcidr.yaml` | Malformed: `src_cidr: "not-a-cidr"` (no `/`); used as new sub-case 8 in §6.22 (folded) | YAML | 5 |

`tests/T_CIDR_INVALID_REJECTED.sh` is **NOT** a separate file —
the 3 CIDR-validation failure modes (v6 reject, host-bits-set
reject, not-a-cidr reject) are FOLDED into the existing §6.22
`T_APPLY_REJECTS_MALFORMED.sh` as sub-cases 6/7/8. Architect
prefers folding (per brief: "May fold into existing
T_APPLY_REJECTS_MALFORMED as new sub-case") — keeps test count
tight (3-5 new ctests target per brief; folded approach = 4 new
ctests: §6.28/§6.29/§6.30/§6.31 + sub-case additions to §6.22).

##### EDITED (existing files touched this slice)

| Path | Role (one line) | What changes |
|---|---|---|
| `src/bpf/mac_filter.bpf.c` | XDP program | (a) new BPF map declarations (`cidr_allowlist_inner` template, `cidr_allowlist_a`, `cidr_allowlist_b`, `cidr_rulesets_outer`); (b) `stats` map `max_entries` bumps from 3 → 4 (via `STAT_MAX` sentinel); (c) datapath extended per §5.27 BPF program flow pseudocode (OR-compose: MAC HASH first, then CIDR LPM_TRIE on IPv4, then defaults_map; STAT_PASS_CIDR increment on CIDR hit). `mac_filter_prog` function name + SEC name UNCHANGED (§5.19/§5.22 identity gates hold). |
| `src/common/mac_filter.h` | Shared header | +~10 lines: `struct xdpmf_cidr_v4` (8-byte packed); `XDPMF_MAP_CIDR_RULESETS_OUTER_NAME`, `XDPMF_MAP_CIDR_INNER_A_NAME`, `XDPMF_MAP_CIDR_INNER_B_NAME` constants; `enum mac_filter_stat` gains `STAT_PASS_CIDR = 3` + `STAT_MAX` bumps from 3 → 4. Existing constants UNCHANGED (per PI-10-3.2). |
| `src/lib/config.hpp` | Config schema header | `RuleMatch` gains `std::optional<xdpmf_cidr_v4> src_cidr`; `#include "cidr.hpp"` added. |
| `src/lib/config.cpp` | Validator | (a) recognize `src_cidr` match-key in the rule-match validator; (b) delegate string parsing to `cidr::parse_cidr_v4()`; (c) enforce schema rule 7 (at-least-one-of-mac-or-src_cidr); (d) supersede §5.26 schema rule 5 ("mac REQUIRED" → "mac OR src_cidr REQUIRED"); (e) update §5.26 schema rule 6's forward-compat reject list (remove `src_cidr` from the rejected-keys set; keep `cidr`/`port`/`vlan`/`dst_cidr` rejected). |
| `src/lib/loader.cpp` | Loader + apply orchestrator | `internal::apply_request` body extended at step 8 (populate inactive CIDR inner alongside inactive MAC inner per §5.27 flow); state-b reattach path's `bpf_map__reuse_fd` loop extended to cover 3 new pinned maps (`cidr_allowlist_a`, `cidr_allowlist_b`, `cidr_rulesets`) — 9 reuse_fd calls total. `loader.hpp` ZERO diff (PI-7-3.2). |
| `src/lib/loader.hpp` | Public loader API | **ZERO diff** — PI-7-3.2 enforced. `LoaderError` enum UNCHANGED (ConfigError = 9 covers CIDR validation per §5.27 §4.1). |
| `CMakeLists.txt` | Top-level build | (a) `xdpmf_internal` STATIC target gains `src/lib/cidr.cpp` in its source list; (b) version bump `VERSION 0.3.0 → 0.4.0` per Done-Definition (MVP-3.2 is a minor release: new match-type axis, backward-compatible CLI surface and schema). |
| `tests/CMakeLists.txt` | ctest registration | (a) `add_test` entries for §6.28 T_PASS_CIDR, §6.29 T_DROP_CIDR_NOT_IN_RANGE, §6.30 T_PASS_MAC_OR_CIDR, §6.31 T_CIDR_ATOMIC_SWAP_NO_DROP (with `RESOURCE_LOCK xdp_fixture`); (b) NO new fixture-dir wiring beyond existing pattern. |
| `tests/T_APPLY_REJECTS_MALFORMED.sh` | §6.22 test | Add 3 sub-cases (6/7/8) for CIDR validation failures: v6 reject, host-bits-set reject, not-a-cidr reject. Existing sub-cases 1-5 UNCHANGED. Total sub-case count: 5 → 8. This is the ONLY MVP-3.1-or-earlier ctest body that is edited; PI-6 invariant carve-out applies (see PI-6-3.2 below). |
| `tests/lib/read_stats.py` | Stats reader | NEW optional `--include-pass-cidr` flag emits 4-column output (`<pass> <drop_deny> <drop_malformed> <pass_cidr>`). DEFAULT (no flag) output UNCHANGED (3 columns) — back-compat with existing 27 tests. Detects 4-slot stats map automatically (loops over `stats.get(0..3)` internally; only print logic varies on flag). |
| `tests/lib/common.sh` | Shared helpers | NEW helpers: `read_stats_with_cidr <pin>` (4-column reader, prefixes `read_stats.py` with `--include-pass-cidr`); `wait_for_stats_sum_with_cidr <iface> <expected_sum> [timeout_ms] [poll_ms]` (sums all 4 counters). Existing `read_stats()` + `wait_for_stats_sum()` UNCHANGED (PI-6 preserved). |
| `CHANGELOG.md` | Version history | New `## [0.4.0] - 2026-05-NN` section per Keep-a-Changelog (MVP-1.1C B4 + §5.25 Q3 V1 precedent + §5.26 [0.3.0] precedent). |

##### UNCHANGED-BUT-AFFECTED (zero git-diff; behaviour must hold)

| Path | Why it matters |
|---|---|
| `src/lib/loader.hpp` | PUBLIC API fenced UNCHANGED per PI-7-3.2 (zero diff, including the `LoaderError` enum). Reviewer asserts via `git diff main -- src/lib/loader.hpp` showing zero output. |
| `src/cli/cli.cpp`, `src/cli/cli.hpp`, `src/cli/apply.cpp`, `src/cli/apply.hpp`, `src/cli/main.cpp` | CLI grammar UNCHANGED (`apply -f` + `attach --allow` + `detach` byte-equivalent). The `apply` orchestrator's CLI front delegates to `internal::apply_request` UNCHANGED (the CIDR-axis extension lives entirely behind the helper boundary). Help text MAY gain one line mentioning `src_cidr` (impl-flexible; tester asserts substring). |
| `src/lib/apply_internal.hpp` | Header UNCHANGED (signature byte-equivalent per §5.26 D-3.1-1). Impl in `loader.cpp` extends; header surface is invariant. |
| `src/lib/yaml_subset.{cpp,hpp}` | UNCHANGED. Q-HG1 subset already accepts string scalars like `"10.0.0.0/8"`; no parser change needed. (Same forward-compat hinge §5.26 documented for the future CIDR feature.) |
| `src/lib/raii.hpp` | UNCHANGED. |
| Existing 27 ctests except `tests/T_APPLY_REJECTS_MALFORMED.sh` | Bodies UNCHANGED. Reviewer asserts `git diff --stat tests/T_*.sh` shows ZERO body changes EXCEPT `T_APPLY_REJECTS_MALFORMED.sh` (per PI-6-3.2 carve-out). |
| `tests/lib/common.sh` existing helpers (`setup_veth`, `cleanup_veth`, `NSEXEC`, `NETNS`, `inject_eth`, `inject_runt`, `xdp_prog_id`, `read_stats`, `wait_for_stats_sum`, `prog_count`, `require_passwordless_sudo`, `apply_config`, `wait_for_active_idx_flip`, `kill_loader_keep_link`) | UNCHANGED. NEW helpers (`read_stats_with_cidr`, `wait_for_stats_sum_with_cidr`) layer ON TOP without modifying existing helper bodies. |
| `tests/fixtures/xdp_pass.bpf.c`, `tests/fixtures/mac_filter_alt.bpf.c`, `tests/fixtures/mac_filter_bad.bpf.c` | UNCHANGED. Used by alien-fixture / tag-mismatch / verifier-reject tests; §5.27 does not interact. |
| `tests/fixtures/config_valid.yaml`, `config_valid_blanket_pass.yaml`, `config_malformed_*.yaml`, `config_apply_swap_*.yaml` | UNCHANGED. The pre-existing fixtures (used by §6.21–§6.27) continue to validate post-§5.27 (PI-15 below). |
| `tests/inject/inject_eth.py`, `inject_runt.py`, `read_stats.py` (default mode) | `read_stats.py` is EDITED (per EDITED above) but its default-mode 3-column output is UNCHANGED; the new `--include-pass-cidr` flag is purely additive. `inject_eth.py` is UNCHANGED — for §6.28/§6.29/§6.31 tests that need to inject IPv4 packets with a specific src_ip, the existing `inject_eth.py` is extended in-place if needed for IPv4 payload (impl-flexible: tester may add `inject_ipv4.py` as a NEW file if cleaner — architect leaves to tester per TestStrategy below). |
| `include/version.h.in`, `tests/lib/pins.sh.in` | UNCHANGED (templates from §5.25 P2/P3 still authoritative; CMake reads new `VERSION 0.4.0`). |
| `cmake/BpfBuild.cmake` | UNCHANGED. New BPF maps are declared inside `mac_filter.bpf.c`; no build-system contract change. |
| `src/common/mac_filter.h` existing constants/struct (`xdpmf_mac`, `XDPMF_BPFFS_ROOT`, `XDPMF_ALLOWLIST_MAX`, `XDPMF_MAP_ALLOWLIST_NAME`, `XDPMF_MAP_STATS_NAME`, `XDPMF_RULESET_COUNT`, `XDPMF_MAP_ACTIVE_IDX_NAME`, `XDPMF_MAP_RULESETS_OUTER_NAME`, `XDPMF_MAP_INNER_A_NAME`, `XDPMF_MAP_INNER_B_NAME`, `XDPMF_MAP_DEFAULTS_NAME`, `XDPMF_LINK_PIN_BASENAME`, existing `enum mac_filter_stat` values 0/1/2) | UNCHANGED. New constants are ADDITIVE; STAT_MAX sentinel bump is additive accounting (per PI-10-3.2). Reviewer asserts `git diff` shows ONLY additions to the constants block + one-line edits to the enum (`STAT_PASS_CIDR = 3,` added + `STAT_MAX = 4,` bumped). |

**Note on inject helper extension** (architect deferred to tester
per TestStrategy below): the existing `inject_eth.py` injects raw
Ethernet frames with a configurable src/dst MAC but a fixed minimal
payload. CIDR tests need to inject IPv4 packets with a CONFIGURABLE
src_ip. Tester may either (a) extend `inject_eth.py` to accept an
optional `--src-ip` flag (preserving back-compat for callers that
don't pass it), OR (b) introduce a new `inject_ipv4.py` adjacent
helper. Either approach is acceptable; architect commits only to
"the test must inject an IPv4 frame with attacker-chosen src_ip
and verify the CIDR LPM_TRIE matches". TestStrategy §6.28 specifies
the contract; impl-shape flexibility on the inject helper.

Any file NOT listed above is off-limits for impl. If impl needs to
edit a file not listed, that's a design gap — SendMessage architect.

#### §5.27 TestStrategy entries

##### §6.28 T_PASS_CIDR — CIDR rule applied; in-range src_ip PASSES with STAT_PASS_CIDR counter increment

- **Trigger**: `setup_veth`; `apply_config tests/fixtures/config_valid_cidr.yaml ${IFACE_A}` (config = `default_action: drop` + single rule `pass {src_cidr: "10.0.0.0/8"}`). Standard veth fixture + `RESOURCE_LOCK xdp_fixture` + root sudo.
- **Observable outcome (all)**:
  - `apply` exits 0.
  - Pin `${PIN_DIR}/cidr_rulesets` exists; pin `${PIN_DIR}/cidr_allowlist_a` OR `${PIN_DIR}/cidr_allowlist_b` (whichever active_idx selects) contains exactly one entry with `prefixlen=8, addr=0x0A000000_be` (`10.0.0.0/8`).
  - Inject IPv4 packet with `src_ip = 10.5.6.7` (in `10.0.0.0/8`) and arbitrary src MAC (e.g. `99:99:99:99:99:99`, NOT in any MAC allowlist) → STAT_PASS_CIDR delta == 1; STAT_PASS / STAT_DROP_DENY deltas == 0 within ~2 seconds.
  - Inject IPv4 packet with `src_ip = 192.168.1.1` (NOT in `10.0.0.0/8`) and arbitrary src MAC → STAT_DROP_DENY delta == 1; STAT_PASS_CIDR delta == 0.
- **Assertion mechanism**: `apply_config` helper + `bpftool map dump pinned ${PIN_DIR}/cidr_allowlist_<a|b> --json | jq` for inner-map contents + `read_stats_with_cidr` (4-column) + `wait_for_stats_sum_with_cidr` polling helper + bash `[[ pass_cidr_delta -eq 1 ]]` assertions.
- **Anti-theatricality control**: BOTH sub-cases use the same fixture; the only differential is src_ip. If src_ip-based dispatch were broken (e.g. CIDR axis ignored), the out-of-range packet would PASS via the wrong path or both packets would behave identically.
- **SKIP conditions**: none.
- **Cleanup**: `cleanup_veth`.

##### §6.29 T_DROP_CIDR_NOT_IN_RANGE — explicit negation case (separate test from §6.28's happy-path step)

- **Trigger**: `setup_veth`; `apply_config tests/fixtures/config_valid_cidr.yaml ${IFACE_A}` (same fixture as §6.28).
- **Observable outcome (all)**:
  - `apply` exits 0.
  - Inject IPv4 packet with `src_ip = 8.8.8.8` (NOT in any rule's CIDR range) and arbitrary src MAC (NOT in any MAC allowlist) → STAT_DROP_DENY delta == 1; STAT_PASS delta == 0; STAT_PASS_CIDR delta == 0.
  - Inject second packet `src_ip = 100.64.0.1` → same outcome (idempotent denial).
- **Assertion mechanism**: same as §6.28 (`read_stats_with_cidr` + delta assertions).
- **Rationale for separate test from §6.28**: §6.28 has 2 sub-cases (in-range pass + out-of-range drop). §6.29 is the focused negation: drops with NO matching rule on either axis, exit-code-and-stats-only assertion. Operator-facing audit grep "did the drop happen because CIDR missed" is unambiguous via §6.29 alone.
- **SKIP conditions**: none.
- **Cleanup**: `cleanup_veth`.

##### §6.30 T_PASS_MAC_OR_CIDR — OR-compose verification (load-bearing for risk register MVP-3.2 row 2)

- **Load-bearing for the architectural correctness of the OR-semantic** per `architecture-v2.md` line 334 risk register MVP-3.2 row 2 mitigation. Architect explicitly fences against making it theatrical.
- **Trigger**: `setup_veth`; `apply_config tests/fixtures/config_valid_mac_or_cidr.yaml ${IFACE_A}` (config = `default_action: drop` + single rule `pass {mac: "AA:BB:CC:DD:EE:FF", src_cidr: "10.0.0.0/8"}`). Three sub-cases in sequence (one apply, three injections):
  1. **MAC-only match**: inject packet with src MAC = `AA:BB:CC:DD:EE:FF` (matches MAC axis) AND src_ip = `192.168.1.1` (does NOT match CIDR axis) → expect STAT_PASS delta == 1 (per Q2 OR1 short-circuit: MAC hit fires first); STAT_PASS_CIDR delta == 0.
  2. **CIDR-only match**: inject packet with src MAC = `11:22:33:44:55:66` (does NOT match MAC axis) AND src_ip = `10.5.6.7` (matches CIDR axis) → expect STAT_PASS_CIDR delta == 1; STAT_PASS delta == 0.
  3. **Neither match (negation)**: inject packet with src MAC = `11:22:33:44:55:66` AND src_ip = `192.168.1.1` (neither axis matches) → expect STAT_DROP_DENY delta == 1; STAT_PASS + STAT_PASS_CIDR deltas == 0.
- **Observable outcome (all 3 sub-cases)**: the counter deltas above; `apply` exits 0; pin `${PIN_DIR}/allowlist_<a|b>` contains the MAC; pin `${PIN_DIR}/cidr_allowlist_<a|b>` contains the CIDR; both populated by the single OR-compose rule.
- **Assertion mechanism**: `read_stats_with_cidr` + delta assertions per sub-case + `bpftool map dump` for inner-map content inspection.
- **Anti-theatricality controls**:
  - Sub-case 3 is the negation control (neither axis matches → drop); if OR-compose were broken to "always-pass-when-either-axis-set", sub-case 3 would PASS. The differential is critical.
  - Sub-cases 1 and 2 use DIFFERENT counters (STAT_PASS vs STAT_PASS_CIDR) — the test asserts the SPLIT, not just "passed". A broken OR-compose that always incremented STAT_PASS would fail sub-case 2's STAT_PASS_CIDR delta assertion.
  - Sub-case ordering: 1 (MAC-only), 2 (CIDR-only), 3 (neither). Architect commits to the ORDER (stats deltas are cumulative across sub-cases; tester reads + asserts after EACH injection, not at end).
- **SKIP conditions**: none.
- **Cleanup**: `cleanup_veth`.

##### §6.31 T_CIDR_ATOMIC_SWAP_NO_DROP — atomic swap on CIDR axis under concurrent traffic (RECOMMENDED OPTIONAL)

- **Recommended-OPTIONAL** per brief — architect's call: **INCLUDE**. Per Q1 AS1 the swap mechanism is byte-identical to §6.23 (single `active_idx` u32 flip), but the CIDR-axis lookup path is a different code path in the BPF datapath (LPM_TRIE chained-deref instead of HASH chained-deref). A focused CIDR-axis test that proves no-drop-under-load on the CIDR path is NON-theatrical — verifies risk-register MVP-3.2 row 1 mitigation specifically for the CIDR axis.
- **Trigger**:
  1. `setup_veth` + initial `apply_config tests/fixtures/config_valid_cidr_swap_a.yaml ${IFACE_A}` (config A = `default_action: drop`, rules: `pass {src_cidr: "10.0.0.0/8"}` only).
  2. Start background traffic injector on the peer veth: continuous IPv4 packets with `src_ip = 10.5.6.7` (overlap-allowed CIDR), arbitrary src MAC, ~100 Hz (same pattern as §6.23; `XDPMF_INJECT_RATE_HZ` env-tunable).
  3. After ~2 seconds (baseline established): snapshot `STAT_DROP_DENY_baseline = read_stats(${IFACE_A}, STAT_DROP_DENY)` AND `STAT_PASS_CIDR_baseline = read_stats_with_cidr(${IFACE_A}, STAT_PASS_CIDR)`.
  4. Invoke `apply_config tests/fixtures/config_valid_cidr_swap_b.yaml ${IFACE_A}` (config B = `default_action: drop`, rules: `pass {src_cidr: "10.0.0.0/8"}` + `pass {src_cidr: "192.168.0.0/16"}` — `10.0.0.0/8` is the load-bearing overlap that proves the swap doesn't drop in-range traffic).
  5. Continue traffic ~2 more seconds.
  6. Stop the injector; let stats quiesce; snapshot `STAT_DROP_DENY_final` and `STAT_PASS_CIDR_final`.
- **Observable outcome (all)**:
  - Both apply invocations exit 0.
  - `STAT_DROP_DENY_final - STAT_DROP_DENY_baseline == 0` (overlapping `10.0.0.0/8` traffic NEVER dropped during the CIDR-axis swap).
  - `STAT_PASS_CIDR_final - STAT_PASS_CIDR_baseline >= 150` (conservative lower-bound for 2s × 100Hz × 0.75 fudge; mirrors §6.23 pattern).
  - `active_idx_map[0]` value changed across the apply (read before/after; assert inequality).
- **Assertion mechanism**: `read_stats_with_cidr` for STAT_PASS_CIDR (4-column reader required) + bash arithmetic on deltas + `bpftool map dump pinned ${PIN_DIR}/active_idx`.
- **Anti-theatricality controls**:
  - Background injection MUST be concurrent with the apply (`&` in bash, not sequential).
  - Overlap of `10.0.0.0/8` across configs A and B is the load-bearing element — any half-applied state would manifest as STAT_DROP_DENY increments on the overlapping CIDR.
  - Negation/contrast: the test verifies the CIDR axis (different from §6.23's MAC axis). Both must pass for full Composite-6 atomic-swap coverage.
- **SKIP conditions**: same as §6.23 — if `XDPMF_INJECT_RATE_HZ` baseline falls below 150 (2s × 100Hz × 0.75), SKIP with rc 77 + stderr `runner too slow for CIDR-axis swap test`.
- **Cleanup**: stop background injector via `kill ${INJECT_PID}`; `cleanup_veth`.

##### §6.22 T_APPLY_REJECTS_MALFORMED — EXTENDED with CIDR-validation sub-cases (PI-6-3.2 carve-out)

- **Existing 5 sub-cases UNCHANGED**: flow-form / default_action wrong / duplicate id / iface mismatch / unsupported match-type.
- **3 new sub-cases ADDED** (architect-mandated FOLD per brief; preferred over a separate `T_CIDR_INVALID_REJECTED.sh`):
  - **Sub-case 6** (`config_malformed_cidr_v6.yaml`: `src_cidr: "::1/128"`): exit 9 + stderr matches `xdpmacfilter: config error: IPv6 CIDR not supported until MVP-3.2.5`.
  - **Sub-case 7** (`config_malformed_cidr_bad.yaml`: `src_cidr: "10.0.0.5/8"`): exit 9 + stderr matches `xdpmacfilter: config error: malformed CIDR: host bits set below prefix`.
  - **Sub-case 8** (`config_malformed_cidr_notcidr.yaml`: `src_cidr: "not-a-cidr"`): exit 9 + stderr matches `xdpmacfilter: config error: malformed CIDR: missing prefix length`.
- **PI-6 carve-out rationale**: PI-6 invariant ("20 pre-existing ctests pass byte-equivalent") is preserved at strength for the 20 pre-§5.26 tests. The 7 §5.26 ctests are the natural extension targets for additive validator coverage; adding sub-cases to §6.22 IS the design-intended extension mechanism (the §6.22 spec literally says "5 sub-cases" — extending the count IS the contract, not a regression). Reviewer's PI-6-3.2 check distinguishes "20 pre-§5.26" (zero diff) from "7 §5.26" (§6.22 ONLY may gain sub-cases additively).
- **Assertion mechanism**: same as existing §6.22 (bash `[[ rc -eq 9 ]]` + `grep -qE` on stderr prefix + `xdp_prog_id` empty assertion). Each sub-case asserts its OWN stderr substring (case-by-case).
- **SKIP conditions**: none.
- **Cleanup**: `cleanup_veth` per existing pattern.

#### §6.5 Preserved invariants (MVP-3.2 brownfield) — PI-1..PI-14 continue + PI-15..PI-18 NEW

All MVP-3.1 invariants (PI-1..PI-14 per §5.26 Preserved Invariants
sub-section) continue to hold post-§5.27. NEW invariants
PI-15..PI-18 capture MVP-3.2-specific guarantees. Reviewer's 5th
framework point walks the COMBINED list (PI-1..PI-18) and reports
`[INVARIANT-VIOLATED]` per failed check.

**Continuing invariants** (per §5.26; ALL still apply post-§5.27):

| # | Invariant | §5.27 check mechanism |
|---|---|---|
| PI-1 | §5.4 alien-program identity-gate ENFORCED in strict mode | Re-run §6.14 T_ATTACH_TAG_MISMATCH + §6.9 T_ATTACH_ALIEN_REFUSAL + §6.26 sub-case 1; all still pass exit 4 in strict. |
| PI-2 | §5.19 name-identity gate ENFORCED in BOTH modes | §6.9 in strict + §6.26 sub-case 3 in fleet — both compute the name-check. |
| PI-3 | §5.22 Item 1 tag-check ENFORCED in BOTH modes | §6.14 still passes in strict. |
| PI-4 | §5.22 Item 2 O_PATH path-discipline ENFORCED in BOTH modes | §6.15 still passes in strict. |
| PI-5 | §5.24 kernel-version probe ENFORCED in BOTH modes | §6.20 T_VERIFIER_REJECT gates on kernel version. |
| PI-6-3.2 | **27 pre-§5.27 ctests pass byte-equivalent OR legitimately SKIP-77 — WITH ONE EXPLICIT CARVE-OUT for §6.22 (allowed additive sub-case growth: 5 → 8)**. | Re-run all 27 tests post-§5.27 → all pass; `git diff --stat tests/T_*.sh` shows zero changes EXCEPT `tests/T_APPLY_REJECTS_MALFORMED.sh` (additive sub-cases 6/7/8 per §5.27 EDITED). All 20 pre-§5.26 test bodies BYTE-EQUIVALENT. |
| PI-7-3.2 | **`loader.hpp` ZERO diff** in §5.27 (strengthened from PI-7's "one new enumerator" — this slice adds NO new `LoaderError` enumerator; `ConfigError = 9` is reused for CIDR-layer errors per §5.27 §4.1). | `git diff main -- src/lib/loader.hpp` shows ZERO lines changed. Any diff = `[INVARIANT-VIOLATED]`. |
| PI-8-3.2 | `xdpmacfilter --version` reports `xdpmacfilter 0.4.0` | Run `${LOADER_BIN} --version`; output MUST be `xdpmacfilter 0.4.0` (single line, ends with newline). Bump from 0.3.0 → 0.4.0 per Done-Definition (MVP-3.2 minor release: new feature, backward-compatible CLI surface AND backward-compatible YAML schema). |
| PI-9 | `--version` / `--help` output FORMAT unchanged (just version-number bump + optional one-line `src_cidr` mention in --help) | §6.10 T_CLI_HELP_VERSION re-run passes (existing ERE forward-compatible). The `--help` MAY gain a line mentioning `src_cidr`; ERE does NOT pin help-text length. |
| PI-10-3.2 | `src/common/mac_filter.h` existing constants and `struct xdpmf_mac` layout UNCHANGED; enum `mac_filter_stat` slots 0/1/2 unchanged (STAT_PASS=0, STAT_DROP_DENY=1, STAT_DROP_MALFORMED=2); STAT_MAX sentinel-only bump from 3 → 4 (additive accounting per §5.27 DataStructures) IS allowed and explicitly excluded from PI-10's "unchanged" set (sentinel is a derived value, not a public constant). | `git diff src/common/mac_filter.h` shows: NEW `struct xdpmf_cidr_v4`, NEW `XDPMF_MAP_CIDR_*` macros, NEW `STAT_PASS_CIDR = 3` enum value, BUMP `STAT_MAX = 3 → 4`. Existing constants/struct/enum-values 0/1/2 byte-identical. |
| PI-11 | Internal directory layout = `src/lib/` + `src/cli/` + `src/common/` + `src/bpf/` (no new top-level dirs) | `find src -type d` shows the same 4 dirs as MVP-3.1 + the existing structure. New files `src/lib/cidr.{cpp,hpp}` are added to `src/lib/` per Q1 R1's "library code lives in `src/lib/`" rule. |
| PI-12 | Pin paths host-global per `nsenter --net` (§5.25 EDIT-15) | New pins `${PIN_DIR}/cidr_rulesets`, `${PIN_DIR}/cidr_allowlist_a`, `${PIN_DIR}/cidr_allowlist_b` visible from `nsenter --net` test invocations. Same mechanism as MVP-3.1; no new path-discipline machinery. |
| PI-13-3.2 | `stats` map type UNCHANGED (`BPF_MAP_TYPE_PERCPU_ARRAY`); read protocol BACKWARD-COMPATIBLE (default `read_stats.py` 3-column output unchanged); STAT_PASS / STAT_DROP_DENY / STAT_DROP_MALFORMED semantics unchanged; STAT_MAX bumps 3 → 4 (additive). | `read_stats.py` without `--include-pass-cidr` flag → 3 columns (binary-identical to MVP-3.1 output for the same trigger). With flag → 4 columns. Existing 27 ctests' callers UNCHANGED. |
| PI-14 | `--mode {generic,native,offload}` flag UNCHANGED | §6.16 + §6.17 + §6.19 all still pass. `apply` still accepts `--mode` per §5.26 forwarding. |

**NEW invariants** (MVP-3.2-specific):

| # | Invariant | Check mechanism |
|---|---|---|
| **PI-15** | **CIDR axis is purely additive**: existing MVP-3.1 configs (with `match.mac` only, no `src_cidr`) MUST continue to validate AND produce byte-equivalent runtime behaviour. No MAC-only path regression. | Re-run §6.21 T_APPLY_VALID_CONFIG (uses MAC-only fixture `config_valid.yaml`) → passes byte-equivalent. Re-run §6.23 T_APPLY_ATOMIC_SWAP_NO_DROP (MAC-only swap fixtures) → passes byte-equivalent (the CIDR-inner population step is a no-op when no rule has `src_cidr`). |
| **PI-16** | **STAT_PASS_CIDR is an ADDITIVE enum slot**; existing STAT_PASS=0, STAT_DROP_DENY=1, STAT_DROP_MALFORMED=2 indices UNCHANGED; the 4-slot PERCPU_ARRAY's slots 0/1/2 fire under identical triggers as the pre-§5.27 3-slot map. | `read_stats.py` (default mode) prints same 3 values pre/post-§5.27 for the same workload. §6.21 (which already triggers STAT_PASS + STAT_DROP_DENY via MAC-only fixture) passes byte-equivalent. |
| **PI-17** | **`schema_version: 1` STILL accepted** post-§5.27 with the additive `src_cidr` extension. Existing MVP-3.1 configs at `schema_version: 1` (no `src_cidr`) validate without change. `schema_version: 2+` configs still rejected (supported-set `{1}`). | Re-run §6.21 (existing config with `schema_version` defaulted/absent → validates). Re-run §6.22 sub-case 5 (`unsupported_match.yaml` with `cidr` key — NOT `src_cidr`) → still rejected as unknown match-key. ADD §6.22 sub-case 6 (v6 CIDR) → rejected as IPv6 CIDR (not as unsupported match-key — the validation message catalogue distinguishes). |
| **PI-18** | **The §5.26 §6.23 T_APPLY_ATOMIC_SWAP_NO_DROP (MAC-axis swap) continues to pass byte-equivalent**. The MVP-3.2 atomic-swap mechanism (Q1 AS1 parallel outers + single active_idx) MUST NOT regress MAC-axis swap correctness. | Re-run §6.23 with its original MAC-only fixtures → drop_delta == 0 across the swap (the CIDR-inner population path runs as a no-op for MAC-only rules; the single `active_idx` flip still commits the MAC swap atomically). |

**No deletions/relaxations** of PI-1..PI-14 in this slice. PI-6 is
RENAMED to PI-6-3.2 to reflect the explicit §6.22 sub-case-growth
carve-out (5 → 8); this is a transparent extension, not a relaxation
— reviewer's `git diff --stat` check explicitly enumerates the
ONE allowed test-body diff (`T_APPLY_REJECTS_MALFORMED.sh`).

#### §7 OOS — MVP-3.2 components SHIPPED + new fences

##### Moved from deferred to SHIPPED (per MVP-3.2)

- ~~**No L3 src-CIDR axis** — MVP-3.2 slice (lands as in-config rule type, NOT as new CLI flag).~~ **— SHIPPED in §5.27 (MVP-3.2, 2026-05-24)** via Items 1-4. `src_cidr` match-key per Q3 K2; IPv4 only per HG-3.2-1; OR-compose with MAC per Q2 OR1; parallel ARRAY_OF_MAPS outer per Q1 AS1 with shared `active_idx` (single u32 flip = atomic for both axes). New STAT_PASS_CIDR counter. 4 new ctests + 3 new sub-cases on §6.22.

##### NEW out-of-scope fences (per §5.27)

- **No IPv6 src-CIDR matching** — fenced to MVP-3.2.5+ per HG-3.2-1. v6 strings (anything containing `:` in the `src_cidr` value) rejected at the validator with exit 9 + recognizable stderr (`IPv6 CIDR not supported until MVP-3.2.5: '<value>'`). Reviewer's PI-17 check verifies the explicit-rejection behaviour (no silent accept-and-ignore).
- **No `dst_cidr` matching** — Q3 K2 naming leaves space for the future sibling, but cycle 2 does NOT ship it. The validator MUST still reject `match: {dst_cidr: ...}` with `match type 'dst_cidr' not supported in schema_version 1` (per §5.26 schema rule 6 forward-compat hinge, unchanged here).
- **No L4 port matching** — MVP-3.5+ candidate, not in this slice. Validator rejects `match: {port: ...}` (and `src_port` / `dst_port`) the same way as `dst_cidr`.
- **No VLAN-aware CIDR matching** — architect lens B mentions VLAN as a future axis; not in cycle 2.
- **No list-of-CIDRs per rule (Option L2)** — Q4 L1; MVP-3.2.x candidate if operator demand emerges. Additive forward path.
- **No schema_version bump to 2** — Q5 V1 additive; `src_cidr` extension does NOT trigger version bump per the migration-policy refinement in Q5. Bump deferred to first genuine breaking change.
- **No new exit code for CIDR validation failures** — §5.27 §4.1: `ConfigError = 9` covers all CIDR validation failures; PI-7-3.2 strengthens the §5.26 `loader.hpp` invariant to ZERO diff.
- **No CIDR set-arithmetic semantics** (e.g. "allow 10.0.0.0/8 except 10.5.0.0/16") — LPM_TRIE longest-prefix-match handles overlapping prefixes naturally but no explicit `deny` action for cycle 2. MVP-3.8+ action-set growth.
- **No rename of `mac` match-key to `src_mac` for symmetry with `src_cidr`** — explicit Q3 K2 sub-decision: schema ships ASYMMETRIC names to preserve MVP-3.1 config byte-equivalence (PI-15). Renaming `mac` would be a breaking schema change requiring `schema_version: 2`.
- **No per-rule counters keyed by rule_id** — MVP-3.4 slice (architecture-v2.md MVP-3.4 row). Cycle 2 keeps the 4-counter GLOBAL PERCPU shape (STAT_PASS, STAT_DROP_DENY, STAT_DROP_MALFORMED, STAT_PASS_CIDR — only adds STAT_PASS_CIDR).
- **No tackling of MVP-3.1 OOT-deferred items (OOT-1..OOT-4)** — Q6 DEFER; dedicated housekeeping cycle or fold into MVP-3.3 prep. The 4 OOT items stay in their §5.26 review.md disposition.
- **No `T_CIDR_INVALID_REJECTED.sh` as a separate file** — architect-chosen FOLD of CIDR-validation failure modes into §6.22 sub-cases 6/7/8 per brief's "May fold" hint. Keeps ctest count tight (4 new ctests instead of 5).
- **No `inject_ipv4.py` mandate** — architect leaves to tester whether to extend existing `inject_eth.py` (adding optional `--src-ip` flag) OR introduce a new `inject_ipv4.py`. Either is acceptable; the contract is "inject IPv4 packet with chosen src_ip + src_mac on the test veth". TestStrategy §6.28 specifies the WHAT; tester chooses the HOW.
- **No `read_stats.py` schema-version field** — the new `--include-pass-cidr` flag is the entire surface change; no version negotiation, no JSON-mode toggle. Future expansion lands flag-by-flag the same way.
- **No backward-compat alias pin for CIDR maps** (`${PIN_DIR}/cidr_allowlist` legacy single-pin) — the §5.26 `${PIN_DIR}/allowlist` alias (D-3.1-2) existed to keep 4 pre-§5.26 tests passing (PI-6). No pre-§5.27 test checks for `${PIN_DIR}/cidr_*` paths (the entire CIDR axis is new in §5.27), so no alias is needed.
- **No CIDR-axis support in `--allow <MAC>` shorthand** — Q3 BC1 (synthesized config) per §5.26 stays MAC-only. Operators wanting CIDR rules write a YAML config and use `apply -f`. Synthesizing a CIDR rule from a CLI flag would require new CLI surface; explicitly OOS.
- **No automatic-detect of v6 vs v4 via family-detection in `src_cidr`** — strict v4-only per HG-3.2-1; MVP-3.2.5+ refactors the validator to auto-detect via family heuristic (`:` → v6; otherwise v4). Cycle 2's validator just rejects v6 with the clear stderr.
- **No CIDR-axis trust_model interaction** — `XDPMF_TRUST_MODEL` continues to gate ONLY the §5.4 alien-program disposition (per HG3); the new CIDR axis runs at the BPF datapath layer, post-attach, with no trust_model interaction. No `XDPMF_CIDR_TRUST_MODEL` env var; no axis multiplication of the trust-model state.
- **No CIDR-axis interaction with `default_action: pass` other than via the existing fall-through** — the new `cidr_rulesets_outer` lookup happens BEFORE `defaults_map` evaluation per the §5.27 BPF datapath pseudocode. `default_action: pass` with empty `rules: []` continues to mean blanket-pass per §5.26; `default_action: pass` with CIDR-only rules means "CIDR-matched → STAT_PASS_CIDR + PASS; non-match → STAT_PASS via defaults (NOT STAT_PASS_CIDR)". The counter discipline distinguishes the path.
- **No expansion of allow-list max beyond 64** — Q4 footnote: `XDPMF_ALLOWLIST_MAX = 64` continues to bound BOTH the MAC HASH and the CIDR LPM_TRIE. Operators needing > 64 rules → MVP-3.4 capacity revisit.
- **No `STAT_DROP_MALFORMED_IP` separate counter for IPv4-header-truncation drops** — IP-header truncation in the new CIDR branch increments the EXISTING `STAT_DROP_MALFORMED` counter (consistent with §5.5's separate-malformed-counter policy; the new branch is "still malformed, just a deeper parse"). No new sentinel value.
- **No `bpftool prog show` JIT-size assertion** in §6.28-§6.31 — the new datapath grows BPF program byte-count; no explicit upper-bound is asserted (impl shape might shift; tester verifies behaviour, not size).
- **No `XDPMF_TEST_CIDR_RATE_HZ` separate env var** — §6.31 reuses the §6.23 `XDPMF_INJECT_RATE_HZ` env var for the SKIP threshold. One knob; consistent across MAC + CIDR swap tests.

#### §5.27 verifiable invariants for reviewer

In addition to PI-1..PI-18 above:

- `git diff main -- src/lib/loader.hpp` shows ZERO output (PI-7-3.2 strengthened from §5.26).
- `git diff main -- src/common/mac_filter.h` shows ONLY additions (new `xdpmf_cidr_v4` struct + 3 new map-name macros + new enum value `STAT_PASS_CIDR = 3` + sentinel `STAT_MAX` bump 3 → 4); zero modifications to existing constants or to enum values 0/1/2.
- `git diff main -- src/bpf/mac_filter.bpf.c` shows: new map declarations (CIDR template + 2 pinned inners + outer); new datapath branch (OR-compose MAC-first then CIDR-on-IPv4); `stats` map `max_entries` change `3 → 4` via the bumped `STAT_MAX`. NO change to existing MAC-axis or malformed-frame branches beyond the IPv4-ethertype branch addition.
- `git diff main -- src/lib/config.{cpp,hpp}` shows: `RuleMatch.src_cidr` field added; validator extension for `src_cidr` key; schema-rule-5/6 superseded inline.
- `git diff main -- src/lib/loader.cpp` shows: `internal::apply_request` step-8 extension (populate CIDR inner alongside MAC inner); D-3.1-4 state-b `bpf_map__reuse_fd` loop extension to 9 maps; ZERO change to §5.4/§5.19/§5.22/§5.26 identity-gate or trust-model paths.
- `git diff main -- tests/T_*.sh` shows: 4 NEW test files (T_PASS_CIDR.sh, T_DROP_CIDR_NOT_IN_RANGE.sh, T_PASS_MAC_OR_CIDR.sh, T_CIDR_ATOMIC_SWAP_NO_DROP.sh) + ONE modified existing test (T_APPLY_REJECTS_MALFORMED.sh — sub-cases 6/7/8 added). NO other existing test bodies modified.
- `git diff main -- tests/lib/read_stats.py` shows: NEW `--include-pass-cidr` flag handling; default-mode output BYTE-IDENTICAL.
- `git diff main -- tests/lib/common.sh` shows: NEW helpers `read_stats_with_cidr`, `wait_for_stats_sum_with_cidr`; existing helpers UNCHANGED.
- 4 new ctests pass (§6.28..§6.31); §6.30 + §6.31 are the load-bearing pair (OR-compose correctness + CIDR atomic-swap correctness).
- 27 pre-§5.27 ctests still pass (or legitimately SKIP-77 per §5.24 Q4 hybrid) — PI-6-3.2 carve-out for §6.22's additive sub-cases respected.
- `XDPMF_SANITIZERS=ON` build clean.
- `xdpmacfilter --version` reports `xdpmacfilter 0.4.0` (bump from 0.3.0 to mark MVP-3.2 feature add; CMake `project(VERSION)` per §5.25 Q3 V1 mechanism).
- `xdpmacfilter --help` MAY list `src_cidr` (impl-flexible; tester asserts substring presence in §6.30 setup if applicable, otherwise no assertion).
- `CHANGELOG.md` entry `[0.4.0] - 2026-05-NN` (Keep-a-Changelog format per §5.26 [0.3.0] precedent).
- Build-pace table in CHANGELOG gains a row for MVP-3.2.

Evidence: `mint/task-brief.md` MVP-3.2 brief (Items 1-4 + Q1-Q6 +
HG-3.2-1); `mint/architecture-v2.md` lines 215-223 (MVP-3.2
dependency-graph row) + line 310 (per-phase scope summary) + lines
333-334 (per-phase risk register MVP-3.2 rows); §5.26 (the
foundation this slice extends); §5.4 / §5.19 / §5.20 / §5.22 /
§5.23 / §5.24 / §5.25 (the invariants this slice preserves);
§4.1 (exit-code table, row 9 REUSED — no new row); §4.3
(LoaderError enum, ZERO diff this slice); `mint/impl-notes.md`
D-3.1-1..D-3.1-4 (MVP-3.1 deviations that STAND unchanged).

---

### §5.28 MVP-3.3: systemd + Ansible + fleet docs (brownfield amendment)

**Purpose**: ship an ops-integration slice that makes the existing
loader operator-deployable on a Linux host fleet. Four
text-artifact additions (systemd template unit + Ansible example
playbook + a Jinja2 config template + a fleet-deployment Markdown
doc) + 3-5 ctests that exercise the systemd + Ansible surfaces
end-to-end via real `sudo systemctl` and (optional) `ansible-playbook
--syntax-check`.

**Anchor sections**: §5.20 (attach/detach flow — ExecStart/ExecStop
call into the unchanged loader CLI surface); §5.26 (config harness,
`XDPMF_TRUST_MODEL` env-var, `apply -f` subcommand, `trust_model=<mode>`
stderr-log format used by fleet docs); §5.27 (the immediate ancestor;
adds CIDR axis but is otherwise byte-equivalent to §5.26 for the
purposes of this OPS slice). §4.1 exit-code table UNCHANGED (no new
exit code). §4.3 LoaderError enum UNCHANGED (PI-7-3.3 strengthening).

**Scope contract (§5.28 short form)**:
- NEW: `systemd/xdpmacfilter@.service` (template unit), `ansible/xdpmacfilter-deploy.yml` (playbook), `ansible/templates/xdpfilter-config.yaml.j2` (config template), `docs/FLEET_DEPLOYMENT.md` (operator docs), 5 NEW test scripts (`T_SYSTEMD_UNIT_SYNTAX.sh`, `T_SYSTEMD_LIFECYCLE.sh`, `T_SYSTEMD_RESTART_ON_FAILURE.sh`, `T_ANSIBLE_PLAYBOOK_SYNTAX.sh`, `T_FLEET_DOCS_SUBSTRING.sh`).
- EDITED: `README.md` (1 new section, per Q5 N1), `CMakeLists.txt` (version bump 0.4.0 → 0.5.0; optional `install(FILES systemd/…)` rule), `CHANGELOG.md` (`[0.5.0]` entry + MVP-3.3 build-pace row), `tests/CMakeLists.txt` (5 new `add_test` entries).
- UNCHANGED-BUT-AFFECTED (zero git-diff fence): ALL C++/BPF sources (`src/**/*.{cpp,hpp,h,bpf.c}`), `tests/lib/*` (existing helpers), `tests/T_*.sh` (the 31 pre-existing test bodies), `tests/fixtures/*`, `cmake/BpfBuild.cmake`, `include/version.h.in`, `tests/lib/pins.sh.in`.

**Phase B EDIT-6 rework note (rework round 1 — 2026-05-24 evening; see review.md)**: the original §5.28 directive catalogue spec'd a 3-cap set (`CAP_BPF + CAP_NET_ADMIN + CAP_SYS_RESOURCE`). T_SYSTEMD_LIFECYCLE failed at `systemctl start` step on first run; impl was byte-faithful to spec (PI-24 round 1 satisfied); spec itself was the defect. Root cause: **kernel BPF verifier trusted-mode gate** on kernel ≥ 5.8 requires `CAP_SYS_ADMIN` for pointer-arithmetic in BPF programs (the loader's ethhdr/iphdr offset deref triggers this). `CAP_PERFMON` added as belt-and-suspenders for the kernel-5.8+ verifier-permission split. New 5-cap set spec'd below.

**Why the existing 31 ctests did not catch this** (anti-misdiagnosis-recurrence note for future cycles): the existing tests invoke the loader via `${NSEXEC} = sudo -n nsenter --net=/var/run/netns/${NETNS} <cmd>`. `nsenter` PRESERVES the calling process's full capability set — under `sudo -n` (root), that's the full root capability mask including `CAP_SYS_ADMIN`. The verifier sees its trusted-mode gate satisfied via the inherited caps and the BPF prog loads cleanly. Only `systemd`-managed launch STRIPS the inherited cap set down to exactly the declared `AmbientCapabilities` — T_SYSTEMD_LIFECYCLE is the FIRST test in the suite to exercise the minimal-cap contract end-to-end. **Future cycles touching cap declarations**: design phase MUST cross-check `AmbientCapabilities` against the BPF verifier's trusted-mode requirements for the actual BPF object being loaded. A `capsh --drop=cap_sys_admin -- xdpmacfilter attach …` smoke-check during the design-dialog (Phase B) would have caught this pre-impl. Added as a backlog item to MEMORY.

**Human-gate decisions (confirmed)**:
- **HG-3.3-1**: Unit name = `xdpmacfilter@.service` (matches current binary; the architecture-v2 component-map name `xdpfilter@.service` defers to MVP-3.12). Reviewer asserts: unit file exists at `systemd/xdpmacfilter@.service`; NO `systemd/xdpfilter@.service` file in this slice.
- **HG-3.3-2**: Ansible scope = single example playbook + 1 Jinja2 template + 1 handler block. NOT a role or collection. Reviewer asserts: `ansible/` contains exactly `xdpmacfilter-deploy.yml` + `templates/xdpfilter-config.yaml.j2`; NO `roles/`, NO `collections/`, NO `inventory/`, NO `group_vars/`.
- **HG-3.3-3**: systemd test approach = real `sudo systemctl`. Tests install to `/etc/systemd/system/`, daemon-reload, start/reload/stop, aggressive trap-cleanup. Stub-only validation is forbidden.

#### §5.28 Q-decisions (mechanism)

##### Q1: systemd unit install path for ctest → **I1 (system path)**

`/etc/systemd/system/xdpmacfilter@.service` per brief recommendation. Rationale:
- Production-realistic path; the unit will live there in real deployments anyway.
- BPF attach requires CAP_BPF (root) → user-systemd (I2) is awkward because ExecStart would need an inner `sudo`, defeating the unit-encapsulation intent.
- Drop-in override (I3) adds complexity without clearer signal — a stale system-path install (test trap failure) is a single greppable artefact that's easy to spot and cleanup pattern is well-understood.

Tests MUST use a unique-per-run unit filename or trap-on-EXIT cleanup; architect prescribes **trap-on-EXIT cleanup** (the unit file is template-instanced, not unique-per-run, since systemd-analyze verify wants the canonical name `xdpmacfilter@.service`).

##### Q2: ExecReload mechanism → **R1 (re-exec `apply -f`)**

`ExecReload=/usr/bin/xdpmacfilter apply -f /etc/xdpfilter/%i.yaml --iface %i` (literally the SAME line as `ExecStart`). Rationale:
- §5.26 Composite-6 atomic-swap was BUILT to make re-exec-of-apply the natural reload semantic; the apply orchestrator detects an existing link pin and routes through `bpf_link__update_program` for an idempotent swap (D-3.1-4 state-(b) reattach path).
- SIGHUP (R2) is explicitly fenced as OOS by MVP-3.1; introducing a signal handler now would invalidate PI-7-3.3 (loader.hpp ZERO diff) and the §5.26 atomic-swap promise.
- Restart-as-reload (R3) introduces a brief drop window contrary to T_APPLY_ATOMIC_SWAP_NO_DROP (§6.23) and T_CIDR_ATOMIC_SWAP_NO_DROP (§6.31) invariants.

ExecReload is therefore EQUAL to ExecStart at the byte level (this is intentional — a `diff <(grep ExecStart unit) <(grep ExecReload unit)` after stripping the directive name yields empty).

##### Q3: Fleet-mode docs depth → **D1 (single MD file)**

`docs/FLEET_DEPLOYMENT.md` ~50-100 lines. README pointer per N1. Covers:
1. When to use `XDPMF_TRUST_MODEL=fleet` (decision matrix: trusted-segment-network vs operator-managed-only fleet; references PI-2/PI-3/PI-4/PI-5 fleet-mode invariants from §5.26).
2. Audit story citing the EXACT stderr-log format from §5.26: `xdpmacfilter: trust_model=<strict|fleet>` emitted at every attach() entry. Mandatory verbatim citation (PI-23 — see §6.5 below).
3. Example systemd Drop-In to set the env var: `/etc/systemd/system/xdpmacfilter@.service.d/trust-model.conf` containing `[Service]\nEnvironment=XDPMF_TRUST_MODEL=fleet`.
4. Recommended Prometheus alert SEMANTIC (NOT implementation): fleet-wide `trust_model` literal distribution should be uniform; alert on divergence. Forward-references MVP-3.4 exporter scope.
5. Fence callout: `XDPMF_TRUST_MODEL=fleet` relaxes ONLY §5.4 alien-program disposition (PI-1 strict-default). It does NOT relax §5.19 name-check (PI-2), §5.22 Item 1 tag-check (PI-3), §5.22 Item 2 O_PATH path-discipline (PI-4), or §5.24 kernel-version probe (PI-5). All four PI-2..PI-5 invariants hold in BOTH modes.

D2 (multi-doc sprint) is explicit scope-creep; deferred.

##### Q4: Restart=on-failure tuning → **RT2 (rate-limited)**

```
Restart=on-failure
RestartSec=5
StartLimitBurst=5
StartLimitIntervalSec=300
```

Rationale: handles transient failures (boot races, brief config push blip) without infinite-loop on permanent failures (malformed YAML). Operator must `systemctl reset-failed xdpmacfilter@<iface>` after 5 retries in 5 min — alerting hook.

Note: `StartLimitBurst` and `StartLimitIntervalSec` belong to the `[Unit]` section, NOT `[Service]`, on modern systemd (≥230). Impl MUST place them under `[Unit]`. Reviewer asserts via `systemd-analyze verify` (it warns on misplacement) AND substring-grep on the unit body.

##### Q5: README integration → **N1 (1 new section)**

README gains a "Production deployment" section (~10-15 lines) pointing to `docs/FLEET_DEPLOYMENT.md`, the systemd unit (`systemd/xdpmacfilter@.service`), and the Ansible playbook (`ansible/xdpmacfilter-deploy.yml`). Inserted BEFORE the existing test/dev sections; preserves existing README ordering.

##### Q6: MVP-3.1/3.2 OOT-deferred housekeeping items → **DEFER**

Per brief recommendation. 5 deferred items from MVP-3.1/3.2 retros (orphan map pins from T_ATTACH_TAG_MISMATCH; stale NOTE comment; cli.hpp ParsedAttach wrapper design-text; §6.25 "replacing existing program" grep; MVP-3.2 had 0) stay in their dispositions. Mixing them with an OPS slice dilutes review focus. Architect surfaces "MVP-3.3.5 housekeeping" as a candidate dedicated cycle if backlog accumulates further.

#### §5.28 Interfaces additions

##### systemd unit template (`systemd/xdpmacfilter@.service`)

Template-instanced unit (`@` suffix). `%i` is the iface name (e.g. `eth0`, `veth-test0`). One unit instance per iface; multi-iface = multiple instance names (`xdpmacfilter@eth0.service`, `xdpmacfilter@eth1.service`, …). NOT a multi-iface single unit (OOS).

**Directive catalogue** (architect-prescribed; impl MAY add comments inline but the directive set is fixed):

```
[Unit]
Description=XDP MAC/CIDR filter on %i
Documentation=file:///usr/share/doc/xdpmacfilter/FLEET_DEPLOYMENT.md
After=network-pre.target
Wants=network-pre.target
ConditionPathExists=/etc/xdpfilter/%i.yaml
StartLimitBurst=5
StartLimitIntervalSec=300

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/xdpmacfilter apply -f /etc/xdpfilter/%i.yaml --iface %i
ExecReload=/usr/bin/xdpmacfilter apply -f /etc/xdpfilter/%i.yaml --iface %i
ExecStop=/usr/bin/xdpmacfilter detach --iface %i
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_SYS_ADMIN CAP_PERFMON
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_SYS_ADMIN CAP_PERFMON
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Rationale per directive (non-obvious only):
- `ConditionPathExists=/etc/xdpfilter/%i.yaml`: unit silently skips (not "failed") if the per-iface config is absent. Avoids alert storm when the operator hasn't yet pushed config for a unit they enabled. Reviewer asserts presence.
- `Type=oneshot` + `RemainAfterExit=yes`: the loader `apply -f` exits after pinning the BPF link; the kernel holds the XDP program. Without `RemainAfterExit`, systemd would consider the unit inactive immediately after ExecStart exits — `systemctl reload` would re-attach instead of update-program. **Load-bearing for Q2 R1 atomic-reload semantic.**
- `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_SYS_ADMIN CAP_PERFMON` (Phase B EDIT-6, see D-3.3-6 rationale + review.md round 1 evidence): BPF map/prog load (CAP_BPF) + XDP attach (CAP_NET_ADMIN) + rlimit-memlock on kernels <5.11 (CAP_SYS_RESOURCE) + BPF verifier trusted-mode gate for pointer arithmetic on kernel ≥ 5.8 (CAP_SYS_ADMIN — see review.md round 1 + journal evidence `permission denied (-EACCES) on bpf(BPF_PROG_LOAD)`) + verifier-permission split belt-and-suspenders (CAP_PERFMON — covers the kernel-5.8+ split where some BPF helpers route through CAP_PERFMON instead of CAP_SYS_ADMIN). The earlier 3-cap set was correct-on-paper for a "pure" BPF program but the loader's actual BPF object uses pointer arithmetic (struct iphdr / struct ethhdr offset deref in the CIDR-axis branch from §5.27) that the verifier gates on CAP_SYS_ADMIN trusted-mode. Architect leaves `User=root` as default (running as non-root with caps is an operator's hardening call; OOS for this slice).
- `NoNewPrivileges=true`: prevents privilege escalation from within the unit. Compatible with AmbientCapabilities (caps are granted, not setuid'd).
- `ExecStop=/usr/bin/xdpmacfilter detach --iface %i`: idempotent per §5.21 D4 (`detach` on clean iface → exit 0). Safe to call on already-detached unit.
- `Documentation=`: points to the FLEET_DEPLOYMENT.md (path is operator-install location; the build does NOT install docs to `/usr/share/doc/` in this slice — docs path is for human discoverability via `systemctl status` only).

**What the unit does NOT contain** (anti-creep guard):
- NO `Type=notify` (daemon-style; OOS — MVP-3.6+).
- NO `WatchdogSec=` (no daemon to watchdog).
- NO `ProtectSystem=` / `ProtectHome=` / `PrivateTmp=` / seccomp filter (hardening is operator's call — OOS).
- NO `User=` / `Group=` non-root (BPF needs CAP_BPF; non-root-with-caps is operator hardening — OOS).
- NO multi-iface logic (template unit; one instance per iface).
- NO `Environment=XDPMF_TRUST_MODEL=…` baked in (operator sets via Drop-In per Q3 fleet-docs example).

##### Ansible playbook (`ansible/xdpmacfilter-deploy.yml`)

Minimal example play with one host group, idempotent. Required variables (operator supplies via inventory or `-e`):
- `xdpfilter_iface` (string, e.g. `eth0`)
- `xdpfilter_default_action` (string, `pass` or `drop`)
- `xdpfilter_rules` (list of dicts; each dict has `id`, optional `mac`, optional `src_cidr`)
- `xdpfilter_trust_model` (string, `strict` or `fleet`; OPTIONAL; default `strict`)

Play tasks (architect-prescribed order; impl uses standard Ansible modules):

```yaml
---
- name: Deploy xdpmacfilter to fleet host
  hosts: xdpfilter_hosts
  become: true
  vars:
    xdpfilter_iface: eth0
    xdpfilter_default_action: drop
    xdpfilter_rules: []
    xdpfilter_trust_model: strict
  tasks:
    - name: Ensure /etc/xdpfilter directory exists
      ansible.builtin.file:
        path: /etc/xdpfilter
        state: directory
        owner: root
        group: root
        mode: '0755'

    - name: Render per-iface config
      ansible.builtin.template:
        src: xdpfilter-config.yaml.j2
        dest: "/etc/xdpfilter/{{ xdpfilter_iface }}.yaml"
        owner: root
        group: root
        mode: '0644'
      notify: reload xdpmacfilter

    - name: Install systemd unit
      ansible.builtin.copy:
        src: ../systemd/xdpmacfilter@.service
        dest: /etc/systemd/system/xdpmacfilter@.service
        owner: root
        group: root
        mode: '0644'
      notify: daemon-reload systemd

    - name: Enable + start xdpmacfilter@{{ xdpfilter_iface }}
      ansible.builtin.systemd:
        name: "xdpmacfilter@{{ xdpfilter_iface }}.service"
        enabled: true
        state: started
        daemon_reload: true

  handlers:
    - name: daemon-reload systemd
      ansible.builtin.systemd:
        daemon_reload: true

    - name: reload xdpmacfilter
      ansible.builtin.systemd:
        name: "xdpmacfilter@{{ xdpfilter_iface }}.service"
        state: reloaded
```

**Idempotency contract**: re-running the play with identical variables MUST yield zero changes (`changed=0` in Ansible summary). Architect lists this as PI-21 (see §6.5 below). The `template:` module is content-based-idempotent; the `copy:` of unit file is byte-identical; `systemd: state=started` is idempotent.

Note: the `ansible.builtin.copy: src: ../systemd/…` path assumes the playbook is invoked from the `ansible/` directory; impl MAY use `role_path` or absolute path conventions, but the test (T_ANSIBLE_PLAYBOOK_SYNTAX) just checks `--syntax-check`, not runtime correctness against a real host.

##### Jinja2 config template (`ansible/templates/xdpfilter-config.yaml.j2`)

```yaml
schema_version: 1
# Generated by Ansible for {{ xdpfilter_iface }} — do not edit by hand.
interface: {{ xdpfilter_iface }}
default_action: {{ xdpfilter_default_action }}
rules:
{% for rule in xdpfilter_rules %}
  - id: {{ rule.id }}
    action: pass
    match:
{% if rule.mac is defined %}
      mac: "{{ rule.mac }}"
{% endif %}
{% if rule.src_cidr is defined %}
      src_cidr: "{{ rule.src_cidr }}"
{% endif %}
{% endfor %}
```

The output of this template MUST be a valid §5.26+§5.27 schema_version-1 config that the loader's `apply -f` validator accepts. Architect does NOT prescribe a separate Jinja2-output ctest in this slice — `T_ANSIBLE_PLAYBOOK_SYNTAX` covers playbook validity; semantic round-trip is operator-runtime concern. (Folded-out test variant `T_ANSIBLE_TEMPLATE_RENDERS_VALID_CONFIG` is explicitly OOS.)

**Phase B EDIT-7 (rework round 1 bundle, OOT-1 cleanup)**: the earlier prose example put the `# Generated by Ansible …` comment on line 1 and `schema_version: 1` on line 2. PI-17 requires `schema_version: 1` on line 1 verbatim (reviewer's `grep '^schema_version: 1$' ansible/templates/xdpfilter-config.yaml.j2` check). Impl chose PI-17 (correct). Prose example reordered to match impl + PI-17 (schema_version: 1 on line 1; comment on line 2). Zero-marginal-cost cleanup bundled with the CAP_SYS_ADMIN fix.

##### Fleet deployment docs (`docs/FLEET_DEPLOYMENT.md`)

Required substring set (load-bearing for T_FLEET_DOCS_SUBSTRING — see §6.34):
1. `XDPMF_TRUST_MODEL` (variable name appears verbatim).
2. `trust_model=strict` (exact stderr-log literal from §5.26 for strict mode).
3. `trust_model=fleet` (exact stderr-log literal for fleet mode).
4. The literal `xdpmacfilter: trust_model=` (the stderr prefix as audit-grep target).
5. `XDPMF_TRUST_MODEL=fleet` in a code-block context showing a Drop-In `[Service]\nEnvironment=` snippet (anti-prose-drift: docs cite the operational mechanism, not just describe it).
6. References to PI-1..PI-5 invariants (by §-number `§5.4`, `§5.19`, `§5.22`, `§5.24`) — the documented fence that fleet relaxes ONLY §5.4.

Architect leaves prose style/length to impl (~50-100 lines target per brief Q3 D1) but the substring set is contractual. PI-23 (see §6.5) is checked by T_FLEET_DOCS_SUBSTRING and by reviewer's manual scan.

##### CMakeLists.txt amendments

- Version bump: `project(xdpmacfilter VERSION 0.4.0 …)` → `project(xdpmacfilter VERSION 0.5.0 …)`. This bump cascades to `--version` output (PI-22 below) and to `CHANGELOG.md` `[0.5.0]` entry.
- OPTIONAL install rule (architect: include): `install(FILES systemd/xdpmacfilter@.service DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system/)` — gated on a CMake option `XDPMF_INSTALL_SYSTEMD_UNIT` defaulting to `ON`. System install is operator's `cmake --install` call, not the build. NO install rule for the Ansible playbook or for `docs/` in this slice (OOS).

NO new `find_package` / `pkg_check_modules` / build dependency. NO change to the `xdpmf_internal` STATIC target or to the `xdpmacfilter` binary target.

##### tests/CMakeLists.txt amendments

5 new `add_test` entries (T_SYSTEMD_UNIT_SYNTAX, T_SYSTEMD_LIFECYCLE, T_SYSTEMD_RESTART_ON_FAILURE, T_ANSIBLE_PLAYBOOK_SYNTAX, T_FLEET_DOCS_SUBSTRING). The 3 `T_SYSTEMD_*` tests get `RESOURCE_LOCK xdp_fixture` (they need exclusive use of the dev VM's systemd manager) AND `RESOURCE_LOCK systemd_unit_install` (a NEW lock label preventing two systemd tests from racing on `/etc/systemd/system/xdpmacfilter@.service`). `T_FLEET_DOCS_SUBSTRING` and `T_ANSIBLE_PLAYBOOK_SYNTAX` need NO lock (file-content / syntax checks).

Test env: `SYSTEMD_UNIT_SRC=${CMAKE_SOURCE_DIR}/systemd/xdpmacfilter@.service`, `ANSIBLE_PLAYBOOK=${CMAKE_SOURCE_DIR}/ansible/xdpmacfilter-deploy.yml`, `FLEET_DOCS=${CMAKE_SOURCE_DIR}/docs/FLEET_DEPLOYMENT.md`.

#### §5.28 FileList (brownfield DIFF — NEW / EDITED / UNCHANGED-BUT-AFFECTED)

##### NEW (created this slice)

| Path | Role (one line) | Language | LOC est |
|---|---|---|---|
| `systemd/xdpmacfilter@.service` | systemd template unit per Q1+Q2+Q4 directive catalogue above | systemd unit | 35 |
| `ansible/xdpmacfilter-deploy.yml` | Minimal example playbook (HG-3.3-2): file dir + template config + copy unit + systemd enable+start; 2 handlers | YAML/Ansible | 65 |
| `ansible/templates/xdpfilter-config.yaml.j2` | Jinja2 template emitting a §5.26+§5.27 schema_version-1 config | Jinja2/YAML | 15 |
| `docs/FLEET_DEPLOYMENT.md` | Operator docs for `XDPMF_TRUST_MODEL=fleet` audit story + Drop-In example + Prometheus alert semantic + PI fence references (Q3 D1) | Markdown | 80 |
| `tests/T_SYSTEMD_UNIT_SYNTAX.sh` | §6.32 test: `systemd-analyze verify systemd/xdpmacfilter@<iface>.service` after stage-copy → exit 0 | bash | 40 |
| `tests/T_SYSTEMD_LIFECYCLE.sh` | §6.33 test: install unit + minimal config + `systemctl start` / `reload` / `stop` against veth fixture; assert XDP attach + active_idx flip + clean detach (HG-3.3-3) | bash | 160 |
| `tests/T_SYSTEMD_RESTART_ON_FAILURE.sh` | §6.34 test (OPTIONAL — architect: INCLUDE): malformed config → systemd Restart attempts → eventually hits StartLimit per Q4 RT2 | bash | 110 |
| `tests/T_ANSIBLE_PLAYBOOK_SYNTAX.sh` | §6.35 test: `ansible-playbook --syntax-check ansible/xdpmacfilter-deploy.yml` → exit 0; SKIP-77 if `ansible-playbook` not in PATH | bash | 35 |
| `tests/T_FLEET_DOCS_SUBSTRING.sh` | §6.36 test: 6-substring grep over `docs/FLEET_DEPLOYMENT.md` per Q3 substring catalogue + PI-23 verbatim stderr-format citation | bash | 50 |

**Note on test numbering**: this slice ships 5 new tests (§6.32..§6.36). The brief target was 3-5; architect INCLUDES T_SYSTEMD_RESTART_ON_FAILURE because Q4 RT2's rate-limit semantic is non-trivial and operator-facing (StartLimitBurst behaviour MUST be verified — easy to misplace under [Service] instead of [Unit]). Architect leaves it as the lowest-priority slot; if impl/tester finds it flaky and cannot stabilize within budget, it MAY be marked as SKIP-77 with a clear rationale in stderr (decision deferred to tester via PI-25 carve-out below).

##### EDITED (existing files touched this slice)

| Path | Role (one line) | What changes |
|---|---|---|
| `README.md` | Repo entry-point doc | INSERT 1 new section "Production deployment" (~10-15 lines) per Q5 N1, BEFORE the existing test/dev sections. Pointers to `docs/FLEET_DEPLOYMENT.md`, `systemd/xdpmacfilter@.service`, `ansible/xdpmacfilter-deploy.yml`. Existing README structure UNCHANGED outside the new section. |
| `CMakeLists.txt` | Top-level build | (a) `project(xdpmacfilter VERSION 0.4.0 …)` → `project(xdpmacfilter VERSION 0.5.0 …)`; (b) NEW `option(XDPMF_INSTALL_SYSTEMD_UNIT "Install systemd unit template" ON)` and conditional `install(FILES systemd/xdpmacfilter@.service DESTINATION …/lib/systemd/system/)`. NO other CMake changes. |
| `CHANGELOG.md` | Version history | NEW `## [0.5.0] - 2026-05-NN` section per Keep-a-Changelog (precedent: [0.4.0] from §5.27, [0.3.0] from §5.26, [0.1.x] from MVP-1.1C). Build-pace table gains a row for MVP-3.3. |
| `tests/CMakeLists.txt` | ctest registration | (a) 5 new `add_test(…)` entries (§6.32..§6.36) with `RESOURCE_LOCK xdp_fixture` for systemd-lifecycle tests AND new `RESOURCE_LOCK systemd_unit_install`; (b) `TEST_ENV` carries `SYSTEMD_UNIT_SRC`, `ANSIBLE_PLAYBOOK`, `FLEET_DOCS` paths; (c) NO modification of the 31 existing `add_test` entries (PI-6-3.3 strict superset). |

##### UNCHANGED-BUT-AFFECTED (zero git-diff; behaviour must hold)

| Path | Why it matters |
|---|---|
| `src/lib/loader.hpp` | PI-7-3.3 strengthening: ZERO diff for the THIRD consecutive cycle (MVP-3.1 had +1 line; MVP-3.2 had 0; MVP-3.3 has 0). Reviewer asserts `git diff main -- src/lib/loader.hpp` shows zero output. |
| `src/lib/loader.cpp` | UNCHANGED. ExecStart's `xdpmacfilter apply -f …` calls into the existing apply path; ExecStop's `xdpmacfilter detach …` calls into the existing detach path. NO loader behaviour change. |
| `src/lib/config.{cpp,hpp}` | UNCHANGED. The Jinja2 template emits a §5.26+§5.27-compliant config; no schema change. |
| `src/lib/yaml_subset.{cpp,hpp}` | UNCHANGED. |
| `src/lib/cidr.{cpp,hpp}` | UNCHANGED. CIDR axis from §5.27 is operator-config concern, not OPS-slice concern. |
| `src/lib/apply_internal.hpp` | UNCHANGED. |
| `src/lib/raii.hpp` | UNCHANGED. |
| `src/cli/cli.{cpp,hpp}`, `src/cli/apply.{cpp,hpp}`, `src/cli/main.cpp` | UNCHANGED. systemd unit ExecStart/Reload/Stop call into the EXISTING CLI grammar (`apply -f … --iface …` / `detach --iface …`). NO `--quiet`, NO `--syslog`, NO new flag (architect explicitly considered + rejected — see Decisions D-3.3-1). |
| `src/common/mac_filter.h` | UNCHANGED. No new shared constants needed. |
| `src/bpf/mac_filter.bpf.c` | UNCHANGED. OPS slice; zero BPF datapath change. |
| `cmake/BpfBuild.cmake` | UNCHANGED. |
| `include/version.h.in`, `tests/lib/pins.sh.in` | UNCHANGED (templates from §5.25 P2/P3 still authoritative; CMake reads new `VERSION 0.5.0` into `version.h.in`). |
| Existing 31 ctests (T_*.sh under `tests/`) | Bodies UNCHANGED. Reviewer asserts `git diff --stat tests/T_*.sh` shows ZERO body changes; only NEW T_SYSTEMD_*, T_ANSIBLE_*, T_FLEET_* files. |
| `tests/lib/common.sh`, `tests/lib/read_stats.py`, `tests/lib/pins.sh.in` | UNCHANGED. New tests MAY introduce a new `tests/lib/systemd_helpers.sh` (optional, tester's call); existing helper bodies UNCHANGED regardless. |
| `tests/fixtures/*` (all existing YAML + BPF fixtures) | UNCHANGED. T_SYSTEMD_LIFECYCLE reuses `tests/fixtures/config_valid.yaml` (or `config_valid_cidr.yaml`) via stage-copy to `/etc/xdpfilter/<iface>.yaml`; no new fixture file required. |

Any file NOT listed above is off-limits for impl. If impl needs to edit a file not listed, that's a design gap — SendMessage architect.

#### §5.28 Decisions (additional, with rationale)

- **D-3.3-1 — NO `--quiet` flag** — because journal noise from `apply -f` is one line (`trust_model=…`) + (potentially) a P0a reattach line. NOT a flood. Adding `--quiet` would breach PI-7-3.3 loader.hpp ZERO-diff for an aesthetic gain. Operators can `LogLevelMax=` in the unit if needed (impl does NOT prescribe it — Q-of-quietness left to operator hardening).
- **D-3.3-2 — NO `Environment=XDPMF_TRUST_MODEL=` BAKED into the shipped unit** — because the default `strict` is the secure-by-default posture (PI-1). Operators opt INTO fleet via Drop-In per Q3 fleet-docs example. Baking it in would either (a) hard-default to strict (redundant — that's already the loader default per §5.26) or (b) hard-default to fleet (insecure-by-default — antithetical to PI-1).
- **D-3.3-3 — `xdpmacfilter detach --iface %i` on ExecStop, NOT `xdpmacfilter detach --iface %i || true`** — because §5.21 D4 already made `detach` on a clean iface return exit 0 (idempotent). Adding `|| true` would mask actual detach failures (e.g. permission denied, kernel bug) from systemd's failure-state tracking. Trust the existing idempotency contract.
- **D-3.3-4 — `After=network-pre.target Wants=network-pre.target`** (NOT `network-online.target`) — because XDP attach uses `if_nametoindex(%i)` on a netlink device; the iface needs to EXIST but NOT to be UP-with-IP. `network-pre.target` is the right ordering anchor. `network-online.target` would block until DHCP completes — wrong semantic (we want the filter UP BEFORE the address is configured, to filter the first frame).
- **D-3.3-5 — `ConditionPathExists=/etc/xdpfilter/%i.yaml`** — because the unit is template-instanced and operators may `systemctl enable xdpmacfilter@eth1` BEFORE writing `/etc/xdpfilter/eth1.yaml`. Without ConditionPathExists, the unit goes into `failed` state at boot → alert storm. With it, the unit silently no-ops at boot and starts cleanly once the config arrives + `systemctl start` is invoked. Operator-pleasing default.
- **D-3.3-6 — `CapabilityBoundingSet` mirrors `AmbientCapabilities`; 5-cap set (CAP_BPF + CAP_NET_ADMIN + CAP_SYS_RESOURCE + CAP_SYS_ADMIN + CAP_PERFMON)** — because the unit hands the loader EXACTLY the caps it needs. Setting BoundingSet to the same value enforces that even if a CVE in the loader allowed cap-escalation, the bounding set caps the blast radius. Defense in depth without behavioural change.
  - **Phase B EDIT-6 evolution (rework round 1 — 2026-05-24 evening; see review.md)**: original spec was 3-cap (CAP_BPF + CAP_NET_ADMIN + CAP_SYS_RESOURCE). T_SYSTEMD_LIFECYCLE first run under the 3-cap unit reproducibly failed with `permission denied (-EACCES)` on `bpf(BPF_PROG_LOAD)`. Root cause: **kernel BPF verifier trusted-mode gate** — on kernel ≥ 5.8, the verifier requires CAP_SYS_ADMIN for pointer-arithmetic operations (struct-field offset dereference) and CAP_PERFMON for some BPF-helper subsets that were split out of CAP_SYS_ADMIN's umbrella. The loader's BPF object uses pointer arithmetic in the existing MAC-axis parse (struct ethhdr) AND the §5.27 CIDR-axis parse (struct iphdr), so the verifier's trusted-mode requirement applies. The 3-cap set was correct on paper for "pure BPF without trusted-mode features" but the loader is not pure-BPF-only in that sense.
  - **CAP_SYS_ADMIN justification**: load-bearing — without it, `bpf(BPF_PROG_LOAD)` returns -EACCES on kernel ≥ 5.8 for any program using pointer arithmetic that the verifier classifies as trusted-mode-gated. This is NOT a relaxation of security posture (root-equivalent capability) but a correct declaration of what the loader's BPF object actually needs at load-time.
  - **CAP_PERFMON justification**: belt-and-suspenders for the kernel-5.8+ verifier-permission split. Some BPF helpers (e.g. `bpf_probe_read*` family — not currently used by our loader but adjacent to the parser code path) routed CAP_SYS_ADMIN → CAP_PERFMON in newer kernels. Adding it now insulates against future kernel-version-skew if any helper in the parse path gets re-classified.
  - **Audit trail**: review.md round 1 cites T_SYSTEMD_LIFECYCLE step 5 (`systemctl start xdpmacfilter@xsd_a_$$.service`) returning rc=1 with `journalctl -u xdpmacfilter@xsd_a_$$.service` showing `xdpmacfilter: bpf prog load failed: Operation not permitted`. Spec defect — impl was byte-faithful to the 3-cap catalogue (PI-24 round 1 satisfied; the catalogue itself was wrong).
  - **Why the existing 31 ctests don't catch this** (anti-misdiagnosis-recurrence note): the existing tests invoke the loader via `${NSEXEC}` = `sudo -n nsenter --net=/var/run/netns/${NETNS} <cmd>`. `nsenter` PRESERVES the calling process's full capability set — under sudo-as-root, that's the full root capability mask including CAP_SYS_ADMIN. The verifier sees the trusted-mode gate satisfied via the inherited caps, and the BPF prog loads cleanly. Only systemd-managed launch — which STRIPS the inherited cap set to exactly the declared `AmbientCapabilities` per the unit file — actually exercises the minimal-cap contract. T_SYSTEMD_LIFECYCLE is the FIRST test in the suite to do that, and the first to catch this kind of spec defect. Future cycles touching cap declarations: design phase MUST cross-check `AmbientCapabilities` against the BPF verifier's trusted-mode requirements for the actual prog being loaded (consider running `bpftool prog load … type xdp` under a stripped cap mask via `capsh --drop=… --` during design dialog if uncertain).
- **D-3.3-7 — Ansible playbook uses `become: true`, NOT per-task `become`** — because every task touches root-owned files (`/etc/xdpfilter/`, `/etc/systemd/system/`, `systemctl`); per-task `become` is noisier with no security gain. The systemd handler ALSO inherits the playbook-level `become`.
- **D-3.3-8 — Ansible playbook `daemon-reload` is a HANDLER, not a task** — because Ansible's idiom: `daemon-reload` runs ONCE per play even if many units are dropped, AND only if SOMETHING changed (handler-fires-on-notify). Putting it as a task would run unconditionally — non-idempotent (no functional harm, but cosmetic `changed=1` on re-runs, violating PI-21). Handler form: idiomatic + idempotent.
- **D-3.3-9 — `XDPMF_INSTALL_SYSTEMD_UNIT` CMake option DEFAULTS to ON, not OFF** — because the default `cmake --install` of a project that ships a systemd unit SHOULD install the unit. Operators who want pure-binary install (e.g. distro packagers who handle the unit separately) can set `-DXDPMF_INSTALL_SYSTEMD_UNIT=OFF`. Off-by-default would surprise the default packaging path.
- **D-3.3-10 — T_SYSTEMD_LIFECYCLE + T_SYSTEMD_RESTART_ON_FAILURE use a HOST-NETNS veth, NOT `setup_veth`** — because systemd-as-PID-1 runs in the HOST netns; ExecStart's `/usr/bin/xdpmacfilter apply -f … --iface %i` calls `if_nametoindex(%i)` in the host netns. The existing `setup_veth` helper (per §5.25 P1) creates the veth inside the per-PID netns `${NETNS}` accessed via `${NSEXEC}` — invisible to systemd. Three alternatives were considered:
  - (A) **host-netns veth confined to these 2 tests** (CHOSEN): inline `sudo ip link add xsd_a_$$ type veth peer name xsd_b_$$` (no `ip netns add`); aggressive trap-cleanup `ip link del xsd_a_$$ || true`; RESOURCE_LOCK xdp_fixture already serializes; mirrors real ops (operators install units against real host ifaces); CONFINED to T_SYSTEMD_LIFECYCLE + T_SYSTEMD_RESTART_ON_FAILURE (the only systemd-touching tests this slice). **Iface-naming rationale (Phase B EDIT-4)**: Linux `IFNAMSIZ = 16` (15 visible chars + NUL); the earlier-spec'd `xdpmf_sysd_a_$$` (13-char prefix + up to 7-digit PID under `kernel.pid_max=4194304`) overflows to 20 chars and `ip link add` rejects with `wrong: not a valid ifname`. Tester evidence confirmed via Phase 2.5 ctest. The `xsd_*_$$` form (6-char prefix `xsd_a_` / `xsd_b_` + up to 7-digit PID = 13 chars max) fits any PID under kernel default. Project-distinguishability via `xsd` = `x`dpmacfilter-`s`ystemd-test-`d`ev; greppable in stale `ip link` output post-failed-cleanup. NO loss of namespace clarity vs the older `xdpmf_sysd_*_$$` (the test filename `T_SYSTEMD_*.sh` is the canonical reviewer-grep anchor anyway).
  - (B) Drop-In `NetworkNamespacePath=/var/run/netns/${NETNS}` on the installed unit — keeps netns isolation but MUTATES the shipped unit at test time (extra Drop-In file installed alongside); drift between "what the test exercises" and "what operators ship" — operators won't usually wrap units in a netns. Worse signal-to-noise.
  - (C) NEW helper `setup_host_veth` in `tests/lib/common.sh` — would breach PI-6-3.3 unchanged-but-affected fence (`tests/lib/common.sh` zero git-diff this slice).
  Rationale for (A): self-contained per test; no helper-file diff (PI-6-3.3 preserved); RESOURCE_LOCK + trap-on-EXIT handles host-netns pollution; reflects operator deployment reality. Trade-off accepted: T_SYSTEMD_LIFECYCLE and T_SYSTEMD_RESTART_ON_FAILURE are the TWO non-netns-isolated tests in the suite (post-§5.25-P1 fence). Both are tightly scoped to systemd-host-netns coupling and aggressively cleaned. Reviewer's PI-6-3.3 check distinguishes "31 pre-§5.28 ctests byte-equivalent" (which they ARE; the new tests don't touch existing ones) from "all NEW tests use the netns-isolated pattern" (which is NOT a PI — the netns-isolation pattern is a helper-pattern, not an invariant). Tester MAY also inline `read_active_idx` (bpftool dump pinned `${PIN_DIR}/active_idx` with `.formatted.value` fallback to byte-array) directly in these tests rather than adding a `tests/lib/common.sh` helper — same PI-6-3.3 fence preservation.

#### §5.28 TestStrategy entries

##### §6.32 T_SYSTEMD_UNIT_SYNTAX — `systemd-analyze verify` accepts the unit

- **Trigger**: stage `systemd/xdpmacfilter@.service` into a temporary directory (the canonical unit name MUST be preserved for template-instance verification: copy to `${TMPDIR}/xdpmacfilter@.service`); invoke `systemd-analyze verify ${TMPDIR}/xdpmacfilter@<arbitrary-iface>.service` (instance form per systemd-analyze convention). NO sudo needed (verify is read-only).
- **Observable outcome**:
  - Exit code 0.
  - Stderr EMPTY (no warnings).
  - Stdout MAY emit informational lines; assertion is "no warnings/errors", not "silent".
- **Assertion mechanism**: bash `rc=0` check + `[[ -z "$(cat stderr.log)" ]]` (or `grep -vE '^(Loading|Created)' stderr.log | wc -l == 0` if systemd-analyze emits info lines on stderr in some versions; tester picks the robust form).
- **Anti-theatricality control**: NEGATION sub-case (REQUIRED) — also run `systemd-analyze verify` against a deliberately-broken copy of the unit AND assert "actually rejected". **Corruption mechanism** (Phase B EDIT-5 per tester evidence): the original "`Type=invalid` substitution" suggestion is INSUFFICIENT — empirically, Debian's `systemd-analyze` accepts unknown `Type=` values with only a soft stderr warning + rc=0 (does NOT fail). Tester replaced with **`[Service]`-section REMOVAL** via an awk state-machine (strip lines from `[Service]` header through the next `[…]` section header) — empirically yields rc=1 + stderr `Service has no ExecStart=, ExecStop=, or SuccessAction=. Refusing.`. **Failure criterion**: `rc != 0` OR stderr matches the rejection-token ERE `Failed to|missing|Refusing|Invalid|no \[?Service|service has no|nothing to start`. Either signal MUST fire on the broken copy; BOTH MUST be absent on the canonical unit (positive case). Tester MAY choose a different corruption (e.g. malformed `ExecStart=`) IF it triggers the same rejection-token catalogue; the contract is "verifier MUST reject some realistic corruption", not "use exactly the [Service]-removal corruption".
- **SKIP conditions**: SKIP-77 if `systemd-analyze` not in PATH (rare on modern Linux; brief notes systemd is assumed present).
- **Cleanup**: `rm -rf ${TMPDIR}`.

##### §6.33 T_SYSTEMD_LIFECYCLE — install + start + reload + stop end-to-end against veth fixture

- **Load-bearing**: this is the OPS-slice canary. If this passes, the systemd integration is real; if it fails, the unit file's directives are wrong somewhere.
- **Trigger**:
  1. **HOST-netns veth** (per D-3.3-10 — NOT `setup_veth`): `IFACE_A=xsd_a_$$`; `IFACE_B=xsd_b_$$` (IFNAMSIZ-safe per D-3.3-10 Phase B EDIT-4); `sudo ip link add ${IFACE_A} type veth peer name ${IFACE_B}`; `sudo ip link set ${IFACE_A} up`; `sudo ip link set ${IFACE_B} up`. NO `ip netns add`. systemd-as-PID-1 sees the iface in the host netns where `if_nametoindex(%i)` resolves.
  2. `sudo install -D -m 0644 ${SYSTEMD_UNIT_SRC} /etc/systemd/system/xdpmacfilter@.service`.
  3. `sudo install -D -m 0644 ${CMAKE_SOURCE_DIR}/tests/fixtures/config_valid.yaml /etc/xdpfilter/${IFACE_A}.yaml`.
  4. `sudo systemctl daemon-reload`.
  5. `sudo systemctl start xdpmacfilter@${IFACE_A}.service`.
- **Observable outcome (post-start)**:
  - `systemctl is-active xdpmacfilter@${IFACE_A}.service` → `active` (exits 0).
  - `xdp_prog_id ${IFACE_A}` (existing helper) → non-empty (XDP attached).
  - Pin `${PIN_DIR}/link` exists (P0a link pin per §5.26).
  - `bpftool map dump pinned ${PIN_DIR}/active_idx` → value `0` (first apply lands in slot 0 per §5.26 invariant).
  - `journalctl -u xdpmacfilter@${IFACE_A}.service` contains `xdpmacfilter: trust_model=strict` (PI-23 verbatim format; the unit's `journal=` mode forwards stderr).
- **Reload sub-step**:
  6. Modify `/etc/xdpfilter/${IFACE_A}.yaml` (e.g. swap to a different valid fixture).
  7. `sudo systemctl reload xdpmacfilter@${IFACE_A}.service`.
- **Observable outcome (post-reload)**:
  - `systemctl is-active` still `active`.
  - `bpftool map dump pinned ${PIN_DIR}/active_idx` → value `1` (active_idx flipped — atomic swap occurred, Q2 R1 contract).
  - `xdp_prog_id ${IFACE_A}` MAY change across reload (Phase B EDIT-8 spec correction — see anti-theatricality note below): R1's `bpf_link__update_program` per `src/lib/loader.cpp:1466-1473` loads a FRESH BPF skeleton with a NEW prog_id and rebinds the persistent link to point at that fresh prog. LINK and MAPS persist; PROG_ID does NOT. Test MUST NOT assert prog-id-constancy. R1-vs-R3 differential is captured instead by the link-pin-persistence + active_idx-flip pair (next bullets).
  - **Link pin `${PIN_DIR}/link` still exists post-reload** (load-bearing R3 discriminator: R3 = restart-as-reload would `unlinkat("link",0)` in detach() then re-pin in attach() — observable as a brief absence + new inode; R1 keeps the same link pin inode throughout the swap).
  - XDP still attached post-reload (`xdp_prog_id` non-empty; the prog_id value itself differs from pre-reload, but that's the R1 contract).
- **Stop sub-step**:
  8. `sudo systemctl stop xdpmacfilter@${IFACE_A}.service`.
- **Observable outcome (post-stop)**:
  - `systemctl is-active` → `inactive` (or `failed` only if stop itself errored — assert `inactive`).
  - `xdp_prog_id ${IFACE_A}` → empty (XDP detached).
  - Pin `${PIN_DIR}/link` absent.
- **Assertion mechanism**: bash exit-code checks + `systemctl is-active` substring + an **inline `host_xdp_prog_id()` helper** defined within the test script (per D-3.3-10 host-netns rationale + Phase B EDIT-2 below) — bare `sudo -n ip -j link show "${iface}" | jq …` WITHOUT `${NSEXEC}` wrapping (the existing `tests/lib/common.sh::xdp_prog_id` is netns-LOCKED via NSEXEC and would enter the per-PID netns where the host-netns iface is invisible — NOT netns-agnostic as architect initially claimed; CORRECTION per tester evidence 2026-05-NN) + pin existence via `test -e` + `bpftool map dump … | jq` (inlined, NOT a new common.sh helper) + `journalctl` grep. PI-6-3.3 preserved — `host_xdp_prog_id()` lives INSIDE the test script, not in `tests/lib/common.sh`.
- **Anti-theatricality controls**:
  - The active_idx flip across reload is the differential — if `systemctl reload` were no-oping or restarting (R3 instead of R1), the flip would NOT occur (restart re-attaches from scratch → active_idx = 0 again).
  - The R1-vs-R3 differential is captured by the **active_idx flip + link-pin persistence** pair across reload (Phase B EDIT-8 — replaces the architect's earlier "prog-id-constancy" claim which was based on a misreading of `bpf_link__update_program` semantics): R1 per `src/lib/loader.cpp:1466-1473` loads a fresh skeleton (new prog_id) and rebinds the existing link to it (link pin file persists, active_idx flips 0→1). R3 (wrong path, restart-as-reload) would `unlinkat` the link pin and recreate it (link pin inode changes; active_idx resets to 0 because the inactive slot is the freshly-pinned one). The active_idx 0→1 flip ALONE is sufficient to discriminate (R3 lands at idx=0 again); link-pin persistence is the belt-and-suspenders check that distinguishes "link reused" (R1) from "link recreated" (R3). Prog-id-constancy is NOT a discriminator and the spec MUST NOT assert it.
- **SKIP conditions**:
  - SKIP-77 if `systemctl` not in PATH (extremely rare; treat as test infra bug otherwise).
  - SKIP-77 if `require_passwordless_sudo` (existing helper) fails (project context says it's available).
- **Cleanup**: aggressive trap-on-EXIT — `systemctl stop xdpmacfilter@${IFACE_A}.service || true; systemctl disable xdpmacfilter@${IFACE_A}.service || true; rm -f /etc/systemd/system/xdpmacfilter@.service /etc/xdpfilter/${IFACE_A}.yaml; systemctl daemon-reload; systemctl reset-failed xdpmacfilter@${IFACE_A}.service || true; sudo ip link del ${IFACE_A} || true` (host-netns veth cleanup per D-3.3-10; deleting one end of the veth pair auto-removes the peer). NO `cleanup_veth` (no netns to delete).

##### §6.34 T_SYSTEMD_RESTART_ON_FAILURE — Restart=on-failure + StartLimit per Q4 RT2

- **Architect's INCLUDE rationale**: Q4 RT2's StartLimit directives are operator-visible (alert-pattern hinge). The misplacement risk (under `[Service]` vs `[Unit]`) is a real failure mode that `systemd-analyze verify` warns about but does not always reject. A behaviour-level ctest proves the rate-limit kicks in.
- **Trigger**:
  1. **HOST-netns veth** (per D-3.3-10 — NOT `setup_veth`): same pattern as §6.33 step 1. `IFACE_A=xsd_a_$$`; `IFACE_B=xsd_b_$$` (shared name with §6.33; IFNAMSIZ-safe per D-3.3-10 Phase B EDIT-4). Serialization is via `RESOURCE_LOCK xdp_fixture` + `RESOURCE_LOCK systemd_unit_install`, so the two systemd-touching tests never overlap, and `$$` PID-uniqueness handles re-runs within the same kernel. Per-test-disambiguation (architect's earlier `xdpmf_sysd_rof_a_$$` / current `xsd_rof_a_$$`) is unnecessary under RESOURCE_LOCK — shared name reduces touchpoints (Phase B EDIT-3). `sudo ip link add ${IFACE_A} type veth peer name ${IFACE_B}`; both `up`. NO `ip netns add`.
  2. Install unit + install DELIBERATELY MALFORMED config at `/etc/xdpfilter/${IFACE_A}.yaml` (e.g. `tests/fixtures/config_malformed_schema.yaml`).
  3. `sudo systemctl daemon-reload`.
  4. `sudo systemctl start xdpmacfilter@${IFACE_A}.service` → expect exit-nonzero from systemctl (start fails because apply exits 9 because config is malformed).
  5. Wait ~RestartSec (5s) + observe systemd attempts restart automatically.
  6. After ~30 seconds (5 restarts × ~5s each + a bit of slack), assert:
- **Observable outcome**:
  - `systemctl is-active xdpmacfilter@${IFACE_A}.service` → `failed`.
  - `systemctl show xdpmacfilter@${IFACE_A}.service -p NRestarts` → `NRestarts` value is `>= 4 AND <= 5` (the rate-limit kicked in at 5 burst).
  - `journalctl -u xdpmacfilter@${IFACE_A}.service` contains `start request repeated too quickly` OR `Start request repeated too quickly` (systemd's StartLimit message).
  - `xdp_prog_id ${IFACE_A}` → empty (no successful attach).
- **Assertion mechanism**: `systemctl show … -p NRestarts` parse + bash arithmetic + `journalctl … | grep -iE 'start request repeated too quickly'`.
- **Anti-theatricality controls**:
  - The NRestarts bound is `>= 4 AND <= 5` (NOT `== 5` exactly) — slack for systemd-version variations (some emit the message after 5 attempts, some after 4-then-give-up). Tester verifies the BAND, not the exact count.
  - The negation: also assert NRestarts is NOT 0 (would mean Restart= directive is missing entirely) AND NOT 100+ (would mean StartLimit is misplaced and the rate-limit never kicks in).
- **SKIP conditions**:
  - SKIP-77 if `systemctl` not in PATH.
  - SKIP-77 if `require_passwordless_sudo` fails.
  - **OPTIONAL SKIP-77**: if tester finds this test flaky in the ctest harness (systemd timing variation across kernels), MAY SKIP-77 with a stderr message `T_SYSTEMD_RESTART_ON_FAILURE: timing-flaky on this kernel; see §5.28 PI-25 carve-out`. PI-25 enumerates this carve-out explicitly (NOT a free pass — tester MUST document the flakiness mode if invoking).
- **Cleanup**: same aggressive trap as §6.33 (including `sudo ip link del ${IFACE_A} || true` host-netns veth cleanup per D-3.3-10), plus `systemctl reset-failed xdpmacfilter@${IFACE_A}.service` to clear the failed state.

##### §6.35 T_ANSIBLE_PLAYBOOK_SYNTAX — `ansible-playbook --syntax-check` passes

- **Trigger**: `ansible-playbook --syntax-check ${ANSIBLE_PLAYBOOK}` (`${ANSIBLE_PLAYBOOK}` = `${CMAKE_SOURCE_DIR}/ansible/xdpmacfilter-deploy.yml`).
- **Observable outcome**:
  - Exit code 0.
  - Stdout contains `playbook: ${ANSIBLE_PLAYBOOK}` (or a similar ansible-version-dependent confirmation line).
  - Stderr EMPTY of warnings (some ansible versions emit deprecation noise — tester uses `grep -vE '\[WARNING\]'` if needed; the assertion is "no syntax errors", not "silent").
- **Assertion mechanism**: `rc=0` + stdout substring.
- **Anti-theatricality control**: NEGATION sub-case — also run `ansible-playbook --syntax-check` against a deliberately-broken copy (e.g. with the top-level `hosts:` key removed) and assert exit-nonzero. Same pattern as §6.32 negation control. **OPTIONAL** (architect leaves to tester per budget); the positive case is sufficient if negation tooling is awkward.
- **SKIP conditions**: SKIP-77 if `ansible-playbook` not in PATH (per brief — ansible-core is OPTIONAL test-time dep). Stderr message `T_ANSIBLE_PLAYBOOK_SYNTAX: ansible-playbook not in PATH; skipping per OPTIONAL dep`.
- **Cleanup**: nothing (read-only check).

##### §6.36 T_FLEET_DOCS_SUBSTRING — `docs/FLEET_DEPLOYMENT.md` cites actual stderr format

- **Load-bearing for PI-23**: docs MUST cite the live `trust_model=<mode>` format from §5.26, not a stale paraphrase. Mitigates risk-register MVP-3.3 row 2 (silent posture change escapes audit if docs say one thing and runtime emits another).
- **Trigger**: a series of `grep -qE` invocations against `${FLEET_DOCS}` (= `${CMAKE_SOURCE_DIR}/docs/FLEET_DEPLOYMENT.md`).
- **Observable outcome (all 6 substrings present)**:
  1. `grep -qE '\bXDPMF_TRUST_MODEL\b' ${FLEET_DOCS}` → rc 0.
  2. `grep -qE 'trust_model=strict\b' ${FLEET_DOCS}` → rc 0.
  3. `grep -qE 'trust_model=fleet\b' ${FLEET_DOCS}` → rc 0.
  4. `grep -qE 'xdpmacfilter: trust_model=' ${FLEET_DOCS}` → rc 0 (the exact stderr prefix from §5.26 sub-decision, audit-grep target).
  5. `grep -qE 'XDPMF_TRUST_MODEL=fleet' ${FLEET_DOCS}` → rc 0 (Drop-In Environment= snippet target).
  6. `grep -qE '§5\.(4|19|22|24)\b' ${FLEET_DOCS}` → rc 0 (PI-1..PI-5 fence references; one match suffices — Pythagoras-style "at least one of the four").
- **Assertion mechanism**: 6 sequential `grep -qE … && echo PASS || echo FAIL`; test exits 0 iff all 6 PASS.
- **Anti-theatricality control**: if ANY of the 6 substrings is missing, the test fails with a specific line indicating WHICH substring was missing (not a generic "docs broken"). Operators reading the failure log can fix the docs directly.
- **SKIP conditions**: none (read-only file check; no dep).
- **Cleanup**: nothing.

#### §6.5 Preserved invariants (MVP-3.3 brownfield) — PI-1..PI-18 continue + PI-19..PI-26 NEW

All MVP-3.1 + MVP-3.2 invariants (PI-1..PI-18 per §5.26 + §5.27 Preserved Invariants sub-sections) continue to hold post-§5.28. NEW invariants PI-19..PI-26 capture MVP-3.3-specific guarantees. Reviewer's 5th framework point walks the COMBINED list (PI-1..PI-26) and reports `[INVARIANT-VIOLATED]` per failed check.

**Continuing invariants** (per §5.27; ALL still apply post-§5.28):

| # | Invariant | §5.28 check mechanism |
|---|---|---|
| PI-1 | §5.4 alien-program identity-gate ENFORCED in strict mode | Re-run §6.14, §6.9, §6.26 sub-case 1; all pass. |
| PI-2 | §5.19 name-identity gate ENFORCED in BOTH modes | §6.9 + §6.26 sub-case 3 — both compute name-check. |
| PI-3 | §5.22 Item 1 tag-check ENFORCED in BOTH modes | §6.14 still passes. |
| PI-4 | §5.22 Item 2 O_PATH path-discipline ENFORCED in BOTH modes | §6.15 still passes. |
| PI-5 | §5.24 kernel-version probe ENFORCED in BOTH modes | §6.20 still passes. |
| PI-6-3.3 | **31 pre-§5.28 ctests pass byte-equivalent OR legitimately SKIP-77 — STRICT SUPERSET, NO carve-outs this slice** | Re-run all 31 tests post-§5.28 → all pass; `git diff --stat tests/T_*.sh` shows ZERO body changes. PI-6-3.2's §6.22 sub-case carve-out is HISTORICAL (already shipped); the 31-ctest baseline this slice inherits is byte-equivalent. |
| PI-7-3.3 | **`loader.hpp` ZERO diff** — THIRD consecutive slice with zero diff (MVP-3.2 had 0, MVP-3.3 has 0; MVP-3.1 was the only slice that added an enumerator). Strengthened: ENTIRE `src/lib/` AND `src/cli/` AND `src/bpf/` AND `src/common/` tree has ZERO diff this slice. | `git diff main -- src/lib/ src/cli/ src/bpf/ src/common/` shows ZERO lines changed. Any diff = `[INVARIANT-VIOLATED]`. |
| PI-8-3.3 | `xdpmacfilter --version` reports `xdpmacfilter 0.5.0` | Run `${LOADER_BIN} --version`; output MUST be `xdpmacfilter 0.5.0` (single line, ends with newline). Bump from 0.4.0 → 0.5.0 per Done-Definition (MVP-3.3 minor release: ops integration, no functional binary change but operator-visible ship). |
| PI-9 | `--version` / `--help` output FORMAT unchanged | §6.10 T_CLI_HELP_VERSION re-run passes (existing ERE forward-compatible). NO new flag added (per D-3.3-1); `--help` text BYTE-IDENTICAL except possibly the trailing version-number-in-banner. |
| PI-10-3.2 | `src/common/mac_filter.h` existing constants + struct layout UNCHANGED | `git diff main -- src/common/mac_filter.h` shows ZERO lines changed (strengthens PI-10-3.2: this slice adds NO new constants). |
| PI-11 | Internal directory layout = `src/lib/` + `src/cli/` + `src/common/` + `src/bpf/` | `find src -type d` shows EXACTLY 4 dirs (no new src dirs). NEW top-level dirs `systemd/`, `ansible/`, `docs/` are OUTSIDE `src/` — not a layout change. |
| PI-12 | Pin paths host-global per `nsenter --net` | UNCHANGED by §5.28 (no new pin paths). |
| PI-13-3.2 | `stats` map type UNCHANGED + read protocol unchanged | UNCHANGED by §5.28. |
| PI-14 | `--mode {generic,native,offload}` flag UNCHANGED | UNCHANGED. Unit's ExecStart does NOT pass `--mode` (defaults to `generic` per §5.23 Q1). Operators MAY add `--mode native` via Drop-In or by editing the unit; OPS docs note this. |
| PI-15 | CIDR axis purely additive | UNCHANGED by §5.28 (no CIDR change). |
| PI-16 | STAT_PASS_CIDR additive enum slot | UNCHANGED. |
| PI-17 | `schema_version: 1` accepted; Jinja2 template emits schema_version: 1 | The `xdpfilter-config.yaml.j2` template emits `schema_version: 1` at line 1 (verbatim, NOT templated — it's a literal in the .j2). Reviewer asserts via `grep '^schema_version: 1$' ansible/templates/xdpfilter-config.yaml.j2`. |
| PI-18 | §6.23 MAC-axis atomic-swap continues | UNCHANGED by §5.28. Re-run §6.23 post-§5.28 → passes. |

**NEW invariants** (MVP-3.3-specific):

| # | Invariant | Check mechanism |
|---|---|---|
| **PI-19** | **`systemd-analyze verify systemd/xdpmacfilter@<iface>.service` exits 0 with zero warnings/errors on stderr**. | §6.32 T_SYSTEMD_UNIT_SYNTAX positive case + reviewer manual re-run during framework point 5 walk. Treats stderr WARNINGS as failures (some warning patterns like "Unknown key name" indicate typos in directives). |
| **PI-20** | **systemd lifecycle correctness**: `systemctl start` → XDP attached + active_idx=0 + `trust_model=` in journal; `systemctl reload` → active_idx flipped 0→1 + link pin `${PIN_DIR}/link` PERSISTS across reload (R1-vs-R3 discriminator pair per Phase B EDIT-8 — see §6.33 anti-theatricality note); `systemctl stop` → XDP detached + link pin removed. | §6.33 T_SYSTEMD_LIFECYCLE end-to-end; load-bearing OPS canary. **Differential signals (3)**: (a) active_idx flip 0→1 across reload (sufficient on its own — R3 would land at idx=0 again); (b) link-pin existence pre/post reload (R1 keeps the SAME pin file; R3 would unlinkat + re-pin); (c) `xdp_prog_id` non-empty post-reload (just "still attached"; the prog_id VALUE itself differs across reload per R1's `bpf_link__update_program` contract at `src/lib/loader.cpp:1466-1473` — NOT a discriminator). The earlier formulation "prog id UNCHANGED (NOT re-attached)" was based on a misreading of bpf_link__update_program semantics; corrected post-rework-round-1 per tester evidence (round 2 ctest 34/36 PASS after spec correction). |
| **PI-21** | **Ansible playbook idempotent**: re-running `ansible-playbook xdpmacfilter-deploy.yml` against the same fleet host with identical variables MUST yield `changed=0` in the summary. | Mitigation for risk-register MVP-3.3 row 1 (Ansible idempotency drift). NOT enforced by a ctest this slice (would require a real host or molecule-style harness — OOS for the slice); reviewer asserts via DESIGN-LEVEL inspection of the playbook (handlers-on-notify pattern, idempotent modules `copy:`/`template:`/`systemd: state=started`). Tester MAY add a runtime check via `ansible-playbook … 2>&1 | grep -E 'changed=0'` against localhost if budget allows (architect leaves to tester; PI-21 stays a DESIGN-LEVEL invariant if not). |
| **PI-22** | **`ansible-playbook --syntax-check` exits 0** | §6.35 T_ANSIBLE_PLAYBOOK_SYNTAX positive case (with SKIP-77 if ansible not present). |
| **PI-23** | **`docs/FLEET_DEPLOYMENT.md` cites the EXACT stderr format `xdpmacfilter: trust_model=<strict|fleet>` from §5.26 sub-decision (verbatim, not paraphrased)** | §6.36 T_FLEET_DOCS_SUBSTRING grep set (substring 4: `xdpmacfilter: trust_model=` prefix; substrings 2+3: `trust_model=strict` and `trust_model=fleet` literals). Mitigation for risk-register MVP-3.3 row 2. |
| **PI-24** | **Unit file directive set EXACTLY matches the §5.28 catalogue** — `Type=oneshot`, `RemainAfterExit=yes`, `ExecStart` = `ExecReload` (byte-identical command), `ExecStop=… detach …`, `Restart=on-failure`, `StartLimitBurst=5`, `StartLimitIntervalSec=300`, `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_RESOURCE CAP_SYS_ADMIN CAP_PERFMON` (5-cap set per Phase B EDIT-6, see D-3.3-6), `CapabilityBoundingSet=` matching the same 5 caps, `ConditionPathExists=/etc/xdpfilter/%i.yaml` | Reviewer manual grep of `systemd/xdpmacfilter@.service` against the catalogue; failure modes: missing directive, misplaced StartLimit under `[Service]` (Q4 RT2 spec), divergent ExecStart vs ExecReload (Q2 R1 spec), cap-set drift from the 5-cap baseline. T_SYSTEMD_UNIT_SYNTAX positive case + T_SYSTEMD_LIFECYCLE successful `bpf(BPF_PROG_LOAD)` under systemd-managed launch (the real cap-set enforcement signal — see D-3.3-6 "Why the existing 31 ctests don't catch this") + T_SYSTEMD_RESTART_ON_FAILURE NRestarts bound (Q4 RT2 enforcement signal). |
| **PI-25** | **T_SYSTEMD_RESTART_ON_FAILURE flakiness carve-out**: if §6.34 SKIPs-77, the SKIP stderr MUST cite "PI-25 carve-out: timing-flaky on this kernel" verbatim. NO silent skip; NO skip without the carve-out citation. | Reviewer greps test output for the carve-out string on SKIP; absence = `[INVARIANT-VIOLATED]`. Default expectation: §6.34 PASSES; SKIP is the escape hatch, not the norm. |
| **PI-26** | **NO C++/BPF source change**: `git diff main -- src/ include/ cmake/` shows ZERO changes EXCEPT (a) `CMakeLists.txt` version bump 0.4.0 → 0.5.0 + optional `install(FILES systemd/…)` rule + `option(XDPMF_INSTALL_SYSTEMD_UNIT …)` declaration. ALL other diff lines = `[INVARIANT-VIOLATED]`. | `git diff main -- src/` empty; `git diff main -- include/` empty; `git diff main -- cmake/` empty; `git diff main -- CMakeLists.txt` shows ONLY the version-bump line + the optional install-rule lines. |

**No deletions/relaxations** of PI-1..PI-18 in this slice. PI-6-3.3 STRENGTHENS PI-6-3.2 (zero ctest body diff — strict superset, no carve-out). PI-7-3.3 STRENGTHENS PI-7-3.2 (zero diff across ALL of `src/`, not just `loader.hpp`). PI-10-3.2 STRENGTHENS implicitly (this slice adds no new constants).

#### §5.28 verifiable invariants for reviewer

In addition to PI-1..PI-26 above:

- `git diff main -- src/lib/loader.hpp` shows ZERO output (PI-7-3.3 strengthened, third consecutive cycle).
- `git diff main -- src/` shows ZERO output (PI-7-3.3 STRENGTHENED — entire src/ tree byte-identical).
- `git diff main -- include/ cmake/` shows ZERO output (PI-26).
- `git diff main -- CMakeLists.txt` shows ONLY the version-bump line `VERSION 0.5.0` and the optional install-rule + option declaration (PI-26).
- `git diff main -- tests/T_*.sh` shows ZERO output for the 31 pre-existing test bodies; only 5 NEW test files (T_SYSTEMD_UNIT_SYNTAX, T_SYSTEMD_LIFECYCLE, T_SYSTEMD_RESTART_ON_FAILURE, T_ANSIBLE_PLAYBOOK_SYNTAX, T_FLEET_DOCS_SUBSTRING) appear (PI-6-3.3).
- `git diff main -- tests/lib/` shows ZERO output (no helper change this slice; PI-6-3.3 implicit).
- `git diff main -- tests/fixtures/` shows ZERO output (PI-6-3.3 implicit).
- `git diff main -- tests/CMakeLists.txt` shows ONLY 5 NEW `add_test(…)` entries; the 31 existing entries are byte-identical.
- New files exist: `systemd/xdpmacfilter@.service`, `ansible/xdpmacfilter-deploy.yml`, `ansible/templates/xdpfilter-config.yaml.j2`, `docs/FLEET_DEPLOYMENT.md`, plus 5 T_*.sh under `tests/`.
- `systemd-analyze verify systemd/xdpmacfilter@<iface>.service` exits 0 with no warnings (PI-19).
- `ansible-playbook --syntax-check ansible/xdpmacfilter-deploy.yml` exits 0, OR `ansible-playbook` absent and §6.35 SKIPs-77 (PI-22).
- T_FLEET_DOCS_SUBSTRING 6-substring grep passes (PI-23).
- `xdpmacfilter --version` reports `xdpmacfilter 0.5.0` (PI-8-3.3 + CMake `project(VERSION)` per §5.25 Q3 V1 mechanism).
- `xdpmacfilter --help` output FORMAT UNCHANGED (PI-9; no new flag per D-3.3-1).
- `CHANGELOG.md` entry `[0.5.0] - 2026-05-NN` (Keep-a-Changelog format).
- Build-pace table in CHANGELOG gains a row for MVP-3.3.
- 5 new ctests pass (§6.32..§6.36); §6.33 + §6.36 are the load-bearing pair (systemd lifecycle correctness + fleet-docs verbatim citation).
- §6.33 + §6.34 use HOST-netns veth (`ip link add … type veth …`, NO `ip netns add`) per D-3.3-10, NOT `setup_veth`. Trap-cleanup deletes the veth (`ip link del`); no netns to remove. PI-6-3.3 holds (no `tests/lib/common.sh` diff; `read_active_idx` inlined in test scripts, not promoted to a helper).
- 31 pre-§5.28 ctests still pass (or legitimately SKIP-77 per §5.24 Q4 hybrid) — PI-6-3.3 STRICT SUPERSET, no carve-out.
- `XDPMF_SANITIZERS=ON` build clean (no C++ change; build must continue to compile clean under sanitizers).

#### §7 OOS — MVP-3.3 components SHIPPED + new fences

##### Moved from deferred to SHIPPED (per MVP-3.3)

- ~~**systemd `xdpfilter@.service` template** — MVP-3.3 slice (architecture-v2.md MVP-3.3 row).~~ **— SHIPPED in §5.28 (MVP-3.3, 2026-05-NN)** as `systemd/xdpmacfilter@.service` per HG-3.3-1 (the architecture-v2 name `xdpfilter@.service` defers to MVP-3.12 binary rename).
- ~~**Ansible example playbook** — MVP-3.3 slice.~~ **— SHIPPED in §5.28** as `ansible/xdpmacfilter-deploy.yml` + `ansible/templates/xdpfilter-config.yaml.j2` per HG-3.3-2 (minimal example, not a role/collection).
- ~~**Fleet-mode operator docs `XDPMF_TRUST_MODEL=fleet` audit story** — MVP-3.3 slice.~~ **— SHIPPED in §5.28** as `docs/FLEET_DEPLOYMENT.md` per Q3 D1 (single MD file) + README pointer per Q5 N1.

##### NEW out-of-scope fences (per §5.28)

- **Binary rename `xdpmacfilter` → `xdpfilter`** — explicitly fenced to MVP-3.12 per HG-3.3-1. Unit name in this slice is `xdpmacfilter@.service`; MVP-3.12 will ship `xdpfilter@.service` with a transitional alias.
- **Per-rule counters / `xdpmf-exporter` binary / Prometheus exporter implementation** — MVP-3.4 slice. Fleet docs (§5.28 Q3 D1 item 4) describe the ALERT SEMANTIC only; the exporter implementation is OOS.
- **SIGHUP signal handler in loader** — explicitly fenced by Q2 R1 (re-exec apply -f is the reload mechanism). Adding a SIGHUP handler would breach PI-7-3.3.
- **Full Ansible role / collection** — fenced by HG-3.3-2. The shipped artifact is a single example playbook. Production-grade collections (with `roles/xdpfilter/{tasks,handlers,defaults,vars,templates}/`, `collections/`, `inventory/`, `group_vars/`) are operator scope.
- **Multi-iface single unit** — fenced by §5.28 Interfaces (template unit, one instance per iface). Multi-iface = multiple instance names (`xdpmacfilter@eth0.service`, `xdpmacfilter@eth1.service`).
- **systemd hardening beyond AmbientCapabilities + NoNewPrivileges + CapabilityBoundingSet** — explicitly OOS. NO `ProtectSystem=`, NO `PrivateTmp=`, NO `MemoryDenyWriteExecute=`, NO `RestrictAddressFamilies=`, NO seccomp filter. Operator hardening is operator's call.
- **`User=`/`Group=` non-root with caps** — fenced. Running as non-root with `AmbientCapabilities=CAP_BPF …` works in principle but adds operator burden (kernel-version conditional, kernel.unprivileged_bpf_disabled sysctl interaction); architect leaves the existing default-root posture. Operators can override via Drop-In.
- **`Type=notify` daemon-style unit** — fenced. Loader is `Type=oneshot RemainAfterExit=yes`; the daemon branch is MVP-3.6+ optional (`xdpmfd`).
- **JSON structured logs** — MVP-3.5 slice. Fleet docs MAY (and DO, in `docs/FLEET_DEPLOYMENT.md`) describe `journalctl -u xdpmacfilter@<iface>.service` as the log query mechanism; the LOG FORMAT itself is plain stderr (per §5.26).
- **sFlow / per-rule counters / library (`libxdpmf.so`) / daemon (`xdpmfd`)** — all later phases per architecture-v2.md.
- **L4 ports / VLAN / IPv6 CIDR** — still fenced per MVP-3.2 §7 OOS (unchanged from §5.27).
- **MVP-3.1/3.2 OOT-deferred housekeeping items** — per Q6 DEFER. The 5 deferred items (orphan map pins from T_ATTACH_TAG_MISMATCH; stale NOTE comment; cli.hpp ParsedAttach wrapper design-text; §6.25 "replacing existing program" grep) stay in their dispositions. Architect surfaces "MVP-3.3.5 housekeeping" as a candidate dedicated cycle.
- **`--quiet` / `--syslog` / `--log-format=json` CLI flag** — fenced by D-3.3-1 (PI-7-3.3 ZERO-diff loader.hpp). Future log-shape changes land at MVP-3.5.
- **Baked-in `Environment=XDPMF_TRUST_MODEL=…` in the shipped unit** — fenced by D-3.3-2 (secure-by-default = strict; operators opt INTO fleet via Drop-In).
- **`ansible-playbook --check` (dry-run) ctest** — fenced. T_ANSIBLE_PLAYBOOK_SYNTAX is syntax-only; full --check requires a real or simulated target host (molecule-style harness — OOS).
- **`T_ANSIBLE_TEMPLATE_RENDERS_VALID_CONFIG`** — fenced. The Jinja2 template emits a §5.26+§5.27-compliant config (PI-17 implicit); semantic verification is operator-runtime concern.
- **Installing the playbook / docs via CMake `install(…)`** — fenced. Only the systemd unit MAY be installed via CMake (optional, default ON per D-3.3-9). The playbook is repo-relative (operators clone or copy); docs are repo-relative (and Documentation= path is for human discoverability via `systemctl status`, not a CMake-install target).
- **Drop-In overlay shipped in the repo** — fenced. The fleet-docs example shows the Drop-In SNIPPET (`Environment=XDPMF_TRUST_MODEL=fleet`); the actual Drop-In file is operator's deployment artefact, not a shipped repo file.
- **Systemd socket activation / path activation** — fenced. The unit is plain `Type=oneshot`; no socket / no path-unit companion.
- **systemd `BindPaths=/etc/xdpfilter`** — fenced. Operators MAY add it via Drop-In; not in the shipped unit (would imply assumptions about the bpffs / netns layout).
- **`xdpmacfilter-cli`-style local control socket** — fenced. There is no daemon; CLI talks directly to BPF via libbpf (the existing architecture).

##### Surfaced as next-natural slice

**MVP-3.4 — observability**:
- per-rule counter map (B vs C type per architecture-v2.md Open Q #13; PERCPU_HASH vs PERCPU_ARRAY decision human-gated)
- `rules` ARRAY + `action_table` (B.2 partial — wires rule_id → counter index)
- `xdpmf-exporter` binary
- Prometheus `/metrics` endpoint (consumes the fleet-mode alert semantic described in §5.28 Q3 D1 item 4)
- manual bypass primitive (mitigates risk-register MVP-3.4 row 4 via `--unsafe` flag)

Per architecture-v2.md per-phase scope summary line 312: 2-3 cycles, medium risk (Q13 B-vs-C decision is the load-bearing pre-cycle question).

Evidence: `mint/task-brief.md` MVP-3.3 brief (Items 1-4 + Q1-Q6 + HG-3.3-1/2/3); `mint/architecture-v2.md` lines 226-231 (MVP-3.3 dependency-graph row) + line 311 (per-phase scope summary, 1 cycle low risk) + lines 335-336 (per-phase risk register MVP-3.3 rows) + line 24 component-map MVP-3.12 rename deferral; §5.20 attach/detach flow (ExecStart/ExecStop call site); §5.26 (config harness + `apply -f` subcommand + `trust_model=` stderr-log format Q3 fleet-docs cites verbatim); §5.27 (immediate ancestor — CIDR axis preserved unchanged); §4.1 exit-code table (UNCHANGED — no new exit code); §4.3 LoaderError enum (UNCHANGED — PI-7-3.3 ZERO diff); `mint/impl-notes.md` D-3.1-1..D-3.1-4 (MVP-3.1 deviations that STAND unchanged; MVP-3.2 had 0 deviations).

---

### §5.29 MVP-3.4: observability exporter + manual bypass + rules/action_table skeleton (brownfield amendment, defer posture)

**Purpose**: ship the first observability surface (`xdpmf-exporter` Prometheus `/metrics` binary serving the existing global `stats` PERCPU_ARRAY) + a manual operator bypass primitive (`xdpmacfilter bypass`) + forward-compatibility skeleton for MVP-3.4b's per-rule counter wiring (`rules` and `action_table` BPF maps declared and populated, **NOT** consulted on the per-packet datapath). Per Open Q #13 RESOLUTION (architecture-v2.md §"§MVP-3.4 Open Question #13 RESOLUTION", committed 2d4b31a 2026-05-24): **per-rule counters DEFERRED to MVP-3.4b** under Option 1 "Honest defer". Option 2 ("Sparse-direct-bounded ARRAY") is the standing default if MVP-3.4b re-asks; PI-13-3.1 adjudication on inner-allowlist-value extension is the gating Open Q #3 that MVP-3.4b inherits.

**Anchor sections**: §5.26 (config harness — the schema this slice extends with `rules:` block + per-rule `action:` field; the `apply -f` orchestrator that populates the new skeleton maps); §5.27 (CIDR axis — second-axis precedent for additive datapath extension that this slice **explicitly does NOT use** because skeleton maps are not consulted); §5.28 (systemd unit template idiom — exporter unit mirrors directive catalogue under HG-3.4-3 Q5 N3); §4.1 exit-code table (UNCHANGED — no new exit code; bypass uses existing exit 0 / 1 / 5; exporter uses existing exit 0 / 1 / 6); §4.3 LoaderError enum (UNCHANGED — PI-7-3.4 ZERO diff loader.hpp continues for the 4th consecutive cycle); §5.4 / §5.19 / §5.22 trust+identity invariants (bypass primitive MUST NOT silently bypass any of these — it is a wrapper over the EXISTING `detach()` path which already enforces zero of them on its way out, and zero gating logic is bypassed at attach-time-equivalent because bypass does not attach).

**Scope contract (§5.29 short form)**:
- NEW (binary): `xdpmf-exporter` (project's first NEW binary since MVP-2). Long-running daemon (Q1 D1), embedded minimal HTTP/1.0 server (HG-3.4-3), reads existing global `stats` PERCPU_ARRAY[STAT_MAX=4] per attached iface, emits Prometheus text format on `/metrics`.
- NEW (CLI subcommand): `xdpmacfilter bypass --iface <X> [--unsafe] [--reason "<text>"]` — wraps existing `loader::detach()` path with audit-stderr + interactive y/N prompt + non-tty `--unsafe` gate (HG-3.4-2). NO new BPF map flag; NO datapath touch.
- NEW (BPF maps, DECLARED-ONLY): `rules` ARRAY[XDPMF_ALLOWLIST_MAX=64] of `struct rule_entry` + `action_table` ARRAY[ACTION_MAX=2] of `struct action_entry`. Populated from config on `apply` (loader-userspace side). **NOT consulted on the per-packet datapath** (HG-3.4-1; the BPF `mac_filter_prog` function body is byte-equivalent to MVP-3.2 modulo the new map *declarations*).
- NEW (schema extension): `apply -f` accepts a per-rule `action:` field (`pass` | `drop`) and a top-level `rules:` block grammar (already shipped at §5.26; this slice adds the apply-time map-population side + the WARN emission when the block is non-empty).
- EDITED: `src/bpf/mac_filter.bpf.c` (two new map declarations only); `src/common/mac_filter.h` (new map-name constants, new structs, new action enum); `src/lib/apply_internal.{cpp,hpp}` (rules+action_table population + WARN emission); `src/lib/config.{cpp,hpp}` (validator extension if needed — `action:` field already accepted per §5.26 schema rule 4 — verify, do not duplicate); `src/lib/yaml_subset.cpp` (no change expected — likely already handles the block); `src/cli/cli.cpp` + `src/cli/main.cpp` (register `bypass` subcommand + dispatch); `CMakeLists.txt` (new `xdpmf-exporter` target linking `xdpmf_internal` + libbpf, version 0.5.0 → 0.6.0); `CHANGELOG.md` ([0.6.0] entry); `tests/CMakeLists.txt` (new add_test entries).
- UNCHANGED-BUT-AFFECTED (zero git-diff fence): `src/lib/loader.hpp` (PI-7-3.4 strengthening — 4th consecutive ZERO-diff cycle); `src/lib/loader.cpp` (apply orchestrator dispatch is unchanged; rule+action population lives in `apply_internal.cpp` per §5.26 D-3.1-1 layering); `src/bpf/mac_filter.bpf.c` xdp_filter function body (only `SEC(".maps")` declaration block grows); all 36 pre-existing ctest bodies; `tests/lib/common.sh` (new exporter-helper if any is OPTIONAL and additive); systemd existing unit `xdpmacfilter@.service` (zero diff — exporter is a SEPARATE unit at `systemd/xdpmf-exporter.service`).

**Human-gate decisions (confirmed)**:

- **HG-3.4-1 — `rules`+`action_table` = STRUCTURAL-ONLY (not wired in datapath).** Confirmed. The two new maps are DECLARED in `mac_filter.bpf.c` and POPULATED from config in `apply_internal.cpp` on `apply -f`; the `mac_filter_prog` BPF program body does NOT consult them on the per-packet path. Datapath stays MVP-3.2 shape: ethhdr parse → MAC HASH lookup OR (IPv4) CIDR LPM_TRIE lookup → STAT_PASS / STAT_PASS_CIDR / STAT_DROP_DENY / STAT_DROP_MALFORMED. Loader emits stderr WARN if config has non-empty `rules:` block: `xdpmacfilter: rules: section parsed (<N> entries) but per-rule action dispatch deferred to MVP-3.4b — datapath uses MAC/CIDR-only matching this cycle`. This is what the defer realizes — see architecture-v2.md §"§MVP-3.4 Open Question #13 RESOLUTION" Convergence + Composite Option 1 paragraphs.

- **HG-3.4-2 — bypass primitive = CLI subcommand wrapping existing `detach` + audit warning.** Confirmed. `xdpmacfilter bypass --iface <X> [--unsafe] [--reason "<text>"]`. Interactive tty: `BYPASS will detach XDP filter on <iface>. Continue? [y/N]:` prompt; non-`y` → exit 0 (no-op). Non-tty (e.g. systemd, cron, ansible): require `--unsafe` flag; absent → exit 1 with `xdpmacfilter: refusing to bypass in non-interactive context without --unsafe flag (audit safety)`. **Always** logs to stderr BEFORE the detach call: `xdpmacfilter: BYPASS activated on <iface> by uid=<UID> reason="<text or UNSPECIFIED>"`. Implementation: construct `loader::DetachConfig{iface}`, call `loader::detach()`; exit 0 on success, propagate `detach()` exit codes (typically 5 only on kernel detach failure; per §5.21 D4 "nothing attached" maps to 0). NO new BPF map flag; NO new datapath state; NO `loader.hpp` diff.

- **HG-3.4-3 — exporter HTTP = embedded minimal C++23 HTTP/1.0 server, `/metrics` over TCP.** Confirmed. ~150-200 LOC plain-socket implementation in `src/exporter/http.{cpp,hpp}`. Default listen `127.0.0.1:9417` (port checked against the prometheus_exporter_default_ports public registry — `9417` is currently unassigned; if collision discovered during impl/test, impl SendMessages architect and the default flips to the next free port in the 941x range). NO HTTP library dependency, NO third-party dep — aligns with the `cli.cpp:1-3` zero-deps project value (PI-26-equivalent for this slice).

#### §5.29 Q-decisions (mechanism)

##### Q1: exporter runtime model → **D1 (long-running daemon)**

Confirmed per brief recommendation. Reasons: (a) lower per-scrape latency vs `Type=socket-activated` oneshot pattern (no fresh `bpf_obj_get` + `mmap` per scrape); (b) standard Prometheus operational pattern (node_exporter, blackbox_exporter, kube-state-metrics all are long-running); (c) aligns with Q5 N3 single-instance unit shape; (d) D2 (oneshot per scrape via xinetd / `systemd.socket`) adds a per-scrape `accept()`→`fork`→`exec` overhead that for our PERCPU-sum workload (microseconds) is dwarfed by the process startup cost (millseconds) — wrong trade.

##### Q2: exporter binary install path → **`/usr/bin/xdpmf-exporter`**

Confirmed per brief recommendation. Consistent with `xdpmacfilter` at `/usr/bin/xdpmacfilter`. `libexec` convention (`/usr/libexec/xdpmf/exporter`) is for binaries invoked by other binaries, not by operators / systemd directly; this is a user-facing daemon binary, so `/usr/bin/` is correct. CMake `install()` rule uses `${CMAKE_INSTALL_BINDIR}` (which resolves to `${CMAKE_INSTALL_PREFIX}/bin/` under standard layout).

##### Q3: `rules` map value shape (for skeleton-only purposes) → **minimal: `{present, action_id}` + `{action_type}`**

Confirmed per brief recommendation. Definitive structs (live in `src/common/mac_filter.h`; see §5.29 DataStructures additions below):

```c
struct rule_entry {
    unsigned char present;     /* 0 = empty slot; 1 = occupied. Mirrors `__u8` semantic of allowlist inner-value PI-13. */
    unsigned char action_id;   /* index into action_table; valid range [0, ACTION_MAX-1] */
    unsigned char _pad[2];     /* explicit padding; total sizeof == 4 (u32-aligned for ARRAY value efficiency) */
};

struct action_entry {
    unsigned char action_type; /* enum xdpmf_action_type; valid range [0, ACTION_MAX-1] */
    unsigned char _pad[3];     /* explicit padding; total sizeof == 4 */
};

enum xdpmf_action_type {
    ACTION_PASS = 0,
    ACTION_DROP = 1,
    ACTION_MAX  = 2,           /* sentinel; future MVP-3.8+ may extend with MIRROR/RL/TAG */
};
```

Rationale:
- Minimal — only the fields strictly necessary for MVP-3.4b's wiring (the action_id indirection lets future action-extensibility happen without touching `rules` value layout; `action_type` is an explicit enum byte for forward-fit).
- `unsigned char` (not `__u8`) per the existing shared-header convention (§5.27 D-3.2 note on `xdpmf_cidr_v4`): `mac_filter.h` is included from BOTH BPF C and userspace C++; the libc types are the portable choice.
- 4-byte total per entry → ARRAY map value is naturally u32-aligned (`max_entries = 64 × 4 B = 256 B` for rules; `max_entries = 2 × 4 B = 8 B` for action_table — both rounding errors).
- NO `rule_id` field embedded in inner allowlist value — the inner allowlist value (HASH `__u8 present` and LPM_TRIE `__u8`) MUST stay byte-equivalent (PI-27 below; load-bearing for the defer).
- NO operator-name field; if MVP-3.4b picks Option 4 (schema-evolve to named rules per architecture-v2.md §"§MVP-3.4 Open Question #13 RESOLUTION" Option 4) the action_id indirection absorbs the change at userspace; the BPF value shape stays stable.

##### Q4: stats map exposure — direct read vs cached snapshot → **E1 (direct read on scrape)**

Confirmed per brief recommendation. PERCPU sum on a 32-CPU box reading 4 u64 slots × 32 CPUs × N attached ifaces (typical N ≤ 4) = 512 u64 reads = microseconds. Caching layer would introduce a staleness contract operators don't want for at-most-one-scrape-per-15s typical Prometheus cadence. The exporter MAY add caching in a future cycle if a real workload demands it; not in scope here.

`stats_reader.cpp` opens each pinned `${XDPMF_BPFFS_ROOT}/<iface>/stats` map READ-ONLY (no `BPF_F_RDONLY` map-flag needed; `bpf_obj_get` returns an fd whose mode is governed by the pin's `read` discipline — exporter does NOT call `bpf_map_update_elem` ever, per PI-31).

##### Q5: exporter systemd integration → **N3 (single-instance unit, multi-iface inside)**

Confirmed per brief recommendation. `systemd/xdpmf-exporter.service` (single instance, no `@` template). The exporter scans `${XDPMF_BPFFS_ROOT}/*/stats` at boot AND on every scrape (Q4 E1) — operator adds/removes ifaces simply by attach/detach via `xdpmacfilter` and the exporter picks them up dynamically. Per-scrape filesystem stat is microseconds; no inotify needed.

Directive catalogue mirrors §5.28's `xdpmacfilter@.service` template idiom, adapted for `Type=simple` daemon:

```
[Unit]
Description=XDP MAC/CIDR filter Prometheus exporter
Documentation=file:///usr/share/doc/xdpmacfilter/FLEET_DEPLOYMENT.md
After=network-pre.target
Wants=network-pre.target
StartLimitBurst=5
StartLimitIntervalSec=300

[Service]
Type=simple
ExecStart=/usr/bin/xdpmf-exporter --port 9417 --bind 127.0.0.1
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_BPF
CapabilityBoundingSet=CAP_BPF
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

Rationale for cap-set divergence from §5.28's 5-cap baseline (anti-misdiagnosis note — see Decisions D-3.4-6 below):
- Exporter does NOT load BPF programs (no verifier-pass needed) → NO `CAP_SYS_ADMIN`, NO `CAP_PERFMON`.
- Exporter does NOT attach/detach XDP (no `xdp_attach` ioctl) → NO `CAP_NET_ADMIN`.
- Exporter does NOT set `rlimit-memlock` (no map creation; reads existing pinned maps via fd) → NO `CAP_SYS_RESOURCE`.
- ONLY `CAP_BPF` is required (the `BPF_OBJ_GET` syscall on the existing pin path goes through the BPF token check on kernel ≥ 5.8 → minimum cap is `CAP_BPF`).

**Anti-misdiagnosis cross-reference**: MVP-3.3 rework round 1 surfaced that `AmbientCapabilities` declarations MUST be cross-checked against the actual BPF object operations under a stripped-cap shell (the `capsh --drop=` test). For this exporter, the relevant smoke-check is `capsh --drop=cap_sys_admin,cap_net_admin,cap_sys_resource,cap_perfmon -- xdpmf-exporter --port 9417` against a pinned-stats fixture; if this fails with -EPERM, the declared cap-set is wrong. Impl SHOULD run this smoke-check during dev; if it fails, SendMessage architect — do NOT add caps silently. See D-3.4-6.

##### Q6: tackle MVP-3.1/3.2/3.3 OOT-deferred housekeeping items? → **DEFER**

Confirmed per brief recommendation. This slice already ships project's first NEW binary since MVP-2 + 3 distinct piece-types (exporter, bypass, skeleton) + 4-6 new ctests including the first network-server-style test. Folding 5+ OOT items in dilutes review focus. The 5 deferred items (T_SYSTEMD_RESTART_ON_FAILURE flake from MVP-3.3 OOT-1; orphan map pins from T_ATTACH_TAG_MISMATCH; T_APPLY_ATOMIC_SWAP_NO_DROP stale NOTE; §6.25 "replacing existing program" grep; ParsedAttach/Detach/Apply wrapper design-text inaccuracy) stay in their dispositions. Architect surfaces "MVP-3.4.5 housekeeping" as the candidate dedicated cycle if backlog accumulates further; alternatively MVP-3.4b will likely pick up at least the T_SYSTEMD_RESTART_ON_FAILURE flake (which may auto-resolve as ctest stress profile shifts between slices).

#### §5.29 schema extension (data on disk) — `action:` field + `rules:` block apply-time semantic

Per-rule `action:` field is ALREADY in the §5.26 schema (rule 4 — accepted `{pass, drop}`). §5.26 documented `drop` as "accepted-but-no-op (operator may explicitly mark drop rules for documentation; they do not populate the inner map). Future MVP-3.4+ counters distinguish action types at apply time." This slice realizes the **apply-time map-population side** of that promise (write `action_id` into the `rules` map slot, write `action_type` into `action_table[action_id]`), without realizing the **per-packet datapath side** (which is deferred to MVP-3.4b). The schema itself is byte-equivalent to §5.26 + §5.27.

Concretely:
- For each `rules:` entry with `action: pass` AND `match.mac` → populate `allowlist_<inactive>` HASH with `__u8 present = 1` (UNCHANGED from §5.26).
- For each `rules:` entry with `action: pass` AND `match.src_cidr` → populate `cidr_allowlist_<inactive>` LPM_TRIE with `__u8 = 1` (UNCHANGED from §5.27).
- **NEW (§5.29)**: For each `rules:` entry → populate `rules[id] = {present=1, action_id=<0 for pass, 1 for drop>}` AND ensure `action_table[0] = {action_type=ACTION_PASS}` and `action_table[1] = {action_type=ACTION_DROP}` are pre-populated by the loader on `apply` (idempotent). `drop` rules now have a kernel-visible representation (a `rules` slot with `action_id=1`) — but the datapath does NOT read it. The forward-fit is: MVP-3.4b will replace the datapath's "PASS-on-allowlist-hit" branch with "look up `rule_id` from the inner-allowlist-value (PI-13 extension) → look up `action_id` in `rules` → look up `action_type` in `action_table` → dispatch", at which point `drop` rules become operative.
- **NEW WARN (§5.29)**: if `req.config.rules.size() > 0`, emit to stderr: `xdpmacfilter: rules: section parsed (<N> entries) but per-rule action dispatch deferred to MVP-3.4b — datapath uses MAC/CIDR-only matching this cycle`. Single-line, fires ONCE per `apply` invocation, AFTER the trust_model log line and BEFORE the apply-completion log line. Operators see this in `journalctl -u xdpmacfilter@<iface>.service` when they push a config with explicit rules.

#### §5.29 DataStructures additions

##### BPF + userspace shared (`src/common/mac_filter.h`)

Additions to the existing header (post-§5.29):

```c
/* §5.29 (MVP-3.4): rules + action_table skeleton — see design §5.29 HG-3.4-1 + Q3.
 * STRUCTURAL-ONLY this slice. Populated on apply; NOT consulted in datapath (mac_filter_prog).
 * MVP-3.4b will wire datapath consumption (requires PI-13-3.1 adjudication on inner-value extension). */

struct rule_entry {
    unsigned char present;     /* 0 = empty slot; 1 = occupied */
    unsigned char action_id;   /* index into action_table */
    unsigned char _pad[2];
};

struct action_entry {
    unsigned char action_type; /* enum xdpmf_action_type */
    unsigned char _pad[3];
};

enum xdpmf_action_type {
    ACTION_PASS = 0,
    ACTION_DROP = 1,
    ACTION_MAX  = 2,
};

#define XDPMF_MAP_RULES_NAME         "rules"        /* ARRAY[XDPMF_ALLOWLIST_MAX] of struct rule_entry */
#define XDPMF_MAP_ACTION_TABLE_NAME  "action_table" /* ARRAY[ACTION_MAX] of struct action_entry */
```

Pinning paths (post-§5.29, per LIBBPF_PIN_BY_NAME):
- `${PIN_DIR}/rules`
- `${PIN_DIR}/action_table`

**Critical invariant (PI-27 below)**: existing inner-allowlist value shape stays `unsigned char present` (byte-equivalent to §5.26's `__u8 present` semantic) for `allowlist_a` / `allowlist_b` HASH; stays `unsigned char` (byte-equivalent to §5.27's `__u8`) for `cidr_allowlist_a` / `cidr_allowlist_b` LPM_TRIE. **NO `rule_id` field embedded in either inner value.** This is what the defer realizes; touching this byte-shape would defeat the entire purpose of MVP-3.4 defer-posture.

##### Exporter-internal (`src/exporter/stats_reader.hpp`, namespace `xdpmf::exporter`)

```cpp
struct StatsSample {
    std::string      iface;              /* iface name (e.g. "eth0", "veth-test0") */
    std::uint64_t    stats[STAT_MAX];    /* PERCPU-summed; indices 0..STAT_MAX-1 follow enum mac_filter_stat */
};

/* Scans ${XDPMF_BPFFS_ROOT}/<iface>/stats for all attached ifaces, opens each RO,
 * libbpf_map_lookup_elem PERCPU-array reads, sums across CPUs. */
[[nodiscard]] std::vector<StatsSample> read_all_attached(std::string_view bpffs_root);
```

##### Exporter-internal (`src/exporter/prom_format.hpp`, namespace `xdpmf::exporter`)

```cpp
/* Emits Prometheus text-format (version 0.0.4) per scrape.
 * Output content-type: text/plain; version=0.0.4 (HG-3.4-3).
 * Format: HELP + TYPE + one sample line per (iface, verdict) tuple.
 * Verdicts: "pass", "drop_deny", "drop_malformed", "pass_cidr" (mirrors enum mac_filter_stat slot order). */
[[nodiscard]] std::string emit_metrics(const std::vector<StatsSample>& samples);
```

Sample expected output (single iface, illustrative):
```
# HELP xdpfilter_packets_total Total packets processed by xdpfilter, per iface and verdict.
# TYPE xdpfilter_packets_total counter
xdpfilter_packets_total{iface="eth0",verdict="pass"} 12345
xdpfilter_packets_total{iface="eth0",verdict="drop_deny"} 67
xdpfilter_packets_total{iface="eth0",verdict="drop_malformed"} 2
xdpfilter_packets_total{iface="eth0",verdict="pass_cidr"} 891
```

Empty case (no attached iface): the output is JUST the HELP+TYPE lines, no sample lines. Prometheus tolerates this (it scrapes "0 timeseries" cleanly).

##### Exporter-internal (`src/exporter/http.hpp`, namespace `xdpmf::exporter`)

```cpp
struct HttpConfig {
    std::string  bind_addr;   /* default "127.0.0.1" */
    std::uint16_t port;       /* default 9417 */
    std::string  bpffs_root;  /* default XDPMF_BPFFS_ROOT */
};

/* Blocking. Single-threaded acceptor; per-conn synchronous handle.
 * Returns on SIGINT / SIGTERM (signal handler sets a stop flag the accept loop polls).
 * Routes: GET /metrics → 200 OK + text/plain; GET /healthz → 200 OK + "ok\n"; other → 404. */
int run(const HttpConfig& cfg);
```

NO multithreading, NO async I/O, NO keep-alive (HTTP/1.0 → connection: close per response). The acceptor loop uses `poll()` on the listening socket with a 1-second timeout so the SIGTERM stop-flag is observed promptly. Per-conn budget: read until `\r\n\r\n` or 4 KiB or 5-second timeout; reject malformed requests with 400.

#### §5.29 Interfaces additions

##### CLI grammar (post-§5.29 — supersedes §5.26 grammar block)

```
xdpmacfilter attach --iface <IFNAME> --allow <MAC>[,<MAC>...]   # unchanged
xdpmacfilter detach --iface <IFNAME>                            # unchanged
xdpmacfilter apply  --iface <IFNAME> -f <PATH>                  # unchanged from §5.26 (apply-time WARN added §5.29)
xdpmacfilter bypass --iface <IFNAME> [--unsafe] [--reason "<text>"]   # NEW (§5.29 HG-3.4-2)
xdpmacfilter --help                                             # unchanged (text updated to list `bypass`)
xdpmacfilter --version                                          # unchanged (reports 0.6.0)
```

Rules for `bypass`:
- `--iface <IFNAME>` REQUIRED; same `if_nametoindex` validation as `attach`/`detach`/`apply`. Unknown iface → exit 1 with `xdpmacfilter: bypass: unknown interface '<iface>'`.
- `--unsafe` (boolean flag, no value): mandatory in non-interactive context (`!isatty(STDIN_FILENO) || !isatty(STDERR_FILENO)`); optional in interactive context (interactive prompt is the safety gate there).
- `--reason "<text>"` (string, optional): free-form audit text. If absent, audit-log line uses literal `UNSPECIFIED`. Length cap 256 bytes; impl truncates with `…` if exceeded (no exit-1, just truncate — audit-log must succeed).
- Interactive flow: `printf 'BYPASS will detach XDP filter on %s. Continue? [y/N]: ', iface;` read response; ONLY `y` or `Y` → proceed (case-insensitive single char or `yes` exact-match; everything else → exit 0 no-op + stderr `xdpmacfilter: bypass cancelled by operator`).
- Non-interactive without `--unsafe` → exit 1 + stderr: `xdpmacfilter: refusing to bypass in non-interactive context without --unsafe flag (audit safety)`.
- Audit-log line (ALWAYS emitted to stderr BEFORE the `loader::detach()` call, regardless of interactive/non-interactive): `xdpmacfilter: BYPASS activated on <iface> by uid=<UID> reason="<reason or UNSPECIFIED>"` — newline-terminated, single line.
- Implementation: construct `loader::DetachConfig{iface}`, invoke `loader::detach()`; on `std::system_error{LoaderError::*}` propagate exit code per existing §4.1 table; on success → exit 0. NO new exit code; NO loader.hpp diff.

##### Exporter CLI (`xdpmf-exporter`)

```
xdpmf-exporter [--port <N>] [--bind <addr>] [--bpffs-root <path>]
xdpmf-exporter --help
xdpmf-exporter --version
```

Flags:
- `--port <N>` (uint16, default `9417`).
- `--bind <addr>` (string, default `127.0.0.1`). IPv4 dotted-quad OR `0.0.0.0` (all-interfaces); IPv6 fenced (OOS per §7 below — exporter v1 is IPv4-only-listen).
- `--bpffs-root <path>` (string, default `${XDPMF_BPFFS_ROOT}` macro from `mac_filter.h` = `/sys/fs/bpf/xdpmacfilter`).
- `--help` (boolean): print usage + exit 0.
- `--version` (boolean): print `xdpmf-exporter 0.6.0\n` + exit 0. Same version string as `xdpmacfilter --version` (PI-33 — shared `version.h` from §5.25 P3).

Exit codes (subset of §4.1; NO new code):
- `0` — clean shutdown (SIGINT/SIGTERM).
- `1` — CLI usage error (bad flag, bad port, etc.).
- `6` — Permission denied (lacks CAP_BPF for the `BPF_OBJ_GET` on pinned stats maps).

HTTP routes (HG-3.4-3):
| Method | Path | Response |
|---|---|---|
| `GET` | `/metrics` | `200 OK`, `Content-Type: text/plain; version=0.0.4`, body per `emit_metrics()` |
| `GET` | `/healthz` | `200 OK`, `Content-Type: text/plain`, body `ok\n` |
| anything else | anything else | `404 Not Found`, `Content-Type: text/plain`, body `not found\n` |

Stdout: NONE in normal operation (the daemon is silent on stdout). Stderr: a single startup line `xdpmf-exporter: listening on <bind>:<port>\n` on bind success; subsequent log lines for SIGINT/SIGTERM / accept errors / per-scrape errors (e.g. `WARN: failed to read stats for <iface>: <errno>`). NO per-scrape success log (would flood at 15s cadence).

##### Loader public API (`src/lib/loader.hpp`) — ZERO diff (PI-7-3.4 strengthening, 4th consecutive cycle)

`AttachConfig` / `DetachConfig` / `attach()` / `detach()` / `LoaderError` enum: ALL UNCHANGED. The new `bypass` subcommand lives entirely in `src/cli/bypass.{cpp,hpp}` and dispatches to `loader::detach()` via the existing public surface. The new BPF maps (`rules`, `action_table`) and their population live in `src/lib/apply_internal.{cpp,hpp}` (internal-namespace, NOT in `loader.hpp`). The exporter lives in `src/exporter/` and links against `xdpmf_internal` static lib for the map-name constants ONLY; it does NOT include `loader.hpp` (no need — exporter doesn't attach/detach).

##### systemd unit (`systemd/xdpmf-exporter.service`)

Per Q5 N3 (single-instance unit). Directive catalogue per §5.29 Q5 above (reproduced inline there). Mirrors §5.28's `xdpmacfilter@.service` template idiom for `[Unit]` After/Wants/StartLimit*, but `Type=simple` (long-running daemon) vs §5.28's `Type=oneshot RemainAfterExit=yes`. NO `Documentation=` install rule shipped (the `file:///usr/share/doc/...` path is for human discoverability via `systemctl status`; we do not install `docs/`).

#### §5.29 apply() flow update (rules + action_table population)

Post-§5.29 `internal::apply_request()` body (incremental over §5.27 step 8 / 9):

```
internal::apply_request(req):
  1..7. UNCHANGED from §5.26 (kernel probe, trust_model parse + log, ifindex,
        skel load + self_tag, BpffsRootFd, §5.4 state-machine, P0a link pin detect).

  8.   populate inactive slot (UNCHANGED from §5.27):
         active_cur = read active_idx_map[0]
         inactive   = 1 - active_cur

         ── MAC axis (UNCHANGED) ──────────────────────────────
         for each rule in req.config.rules with action==Pass AND match.mac.has_value():
             bpf_map_update_elem(allowlist_<inactive>_fd, &rule.match.mac, &one, BPF_ANY)
         (one == __u8(1); inner-value shape UNCHANGED per PI-27)

         ── CIDR axis (UNCHANGED §5.27) ───────────────────────
         for each rule in req.config.rules with action==Pass AND match.src_cidr.has_value():
             bpf_map_update_elem(cidr_allowlist_<inactive>_fd, &rule.match.src_cidr, &one, BPF_ANY)

         ── defaults (UNCHANGED §5.26) ────────────────────────
         bpf_map_update_elem(defaults_map, &inactive, &(default_action==Pass ? 1u : 0u), BPF_ANY)

  8.5. NEW §5.29 — populate skeleton maps (idempotent across applies):
         ── action_table prepopulation (ONE-TIME per apply; cheap to re-do) ─
         action_table[ACTION_PASS] = struct action_entry{ ACTION_PASS, {0,0,0} }
         action_table[ACTION_DROP] = struct action_entry{ ACTION_DROP, {0,0,0} }
         bpf_map_update_elem(action_table_fd, &k, &v, BPF_ANY)   for both k=0,1

         ── rules population ───────────────────────────────────
         /* Note: rules is a SHARED map (NOT swapped via ARRAY_OF_MAPS; the slice
          * does not need atomicity here because the datapath doesn't consult it).
          * We clear-and-rewrite on every apply for simplicity. */
         /* zero-out: write {present=0, action_id=0, _pad[]=0} to all 64 slots. */
         for k in 0..XDPMF_ALLOWLIST_MAX-1:
             bpf_map_update_elem(rules_fd, &k, &empty_rule_entry, BPF_ANY)
         /* populate occupied slots */
         for rule in req.config.rules:
             entry = { present=1, action_id=(rule.action==Pass ? 0 : 1), _pad={0,0} }
             bpf_map_update_elem(rules_fd, &rule.id, &entry, BPF_ANY)

         ── WARN emission (HG-3.4-1 contract) ──────────────────
         if !req.config.rules.empty():
             fprintf(stderr, "xdpmacfilter: rules: section parsed (%zu entries) but "
                             "per-rule action dispatch deferred to MVP-3.4b — datapath "
                             "uses MAC/CIDR-only matching this cycle\n",
                             req.config.rules.size())

  9.   atomic flip (UNCHANGED §5.26):
         bpf_map_update_elem(active_idx_map, &zero, &inactive, BPF_ANY)
       ─ single u32 store ─ atomic commit point for BOTH MAC + CIDR axes ─
       (NOTE: `rules` and `action_table` are NOT swapped — the apply ABOVE leaves
       them in a consistent state pre-flip; the flip itself does not touch them.)

 10.   post-flip cleanup (UNCHANGED): leave previous slot populated; no clear.
       (rules + action_table need no cleanup — they were written in-place above.)

 11.   bpffs alias pin (UNCHANGED).
```

State-b reattach path (D-3.1-4 / §5.27 9-map reuse): extends to **11 maps** post-§5.29 (add `rules` + `action_table` to the reuse_fd loop). The two new maps are pinned with `LIBBPF_PIN_BY_NAME`; reuse semantics identical to existing pinned maps.

**Datapath untouched**: `mac_filter_prog` body in `mac_filter.bpf.c` is byte-equivalent to MVP-3.2 — only the `.maps` declaration block grows by two new map definitions (`rules` ARRAY, `action_table` ARRAY). Reviewer asserts via `git diff main -- src/bpf/mac_filter.bpf.c` shows ONLY the new `.maps` declarations; the `xdp` SEC function body shows ZERO diff lines (PI-28 below).

#### §5.29 FileList (brownfield DIFF — NEW / EDITED / UNCHANGED-BUT-AFFECTED)

##### NEW (created this slice)

| Path | Role (one line) | Language | LOC est |
|---|---|---|---|
| `src/exporter/main.cpp` | Exporter entry-point: parse args, signal handlers, invoke `http::run()` | C++23 | 80 |
| `src/exporter/http.cpp` | Embedded minimal HTTP/1.0 server (HG-3.4-3); routes `/metrics`, `/healthz`, `*` → 404 | C++23 | 180 |
| `src/exporter/http.hpp` | `HttpConfig` struct + `run()` declaration | C++23 | 30 |
| `src/exporter/prom_format.cpp` | Prometheus text-format emitter for `xdpfilter_packets_total{iface,verdict}` | C++23 | 70 |
| `src/exporter/prom_format.hpp` | `emit_metrics()` declaration | C++23 | 20 |
| `src/exporter/stats_reader.cpp` | Scan `${BPFFS_ROOT}/*/stats` pins; libbpf PERCPU lookup + sum-across-CPUs | C++23 | 110 |
| `src/exporter/stats_reader.hpp` | `StatsSample` struct + `read_all_attached()` declaration | C++23 | 25 |
| `src/cli/bypass.cpp` | `xdpmacfilter bypass` subcommand: tty-check, audit-log, invoke `loader::detach()` | C++23 | 90 |
| `src/cli/bypass.hpp` | `bypass_main(argc, argv)` declaration | C++23 | 15 |
| `systemd/xdpmf-exporter.service` | systemd unit per Q5 N3 directive catalogue above | systemd unit | 30 |
| `tests/T_EXPORTER_METRICS_FORMAT.sh` | §6.37 test: `curl localhost:9417/metrics` + Prometheus-format regex compliance; SKIP-77 if `curl` absent | bash | 80 |
| `tests/T_EXPORTER_VALUES_MATCH_STATS.sh` | §6.38 test: inject known traffic via persistent AF_PACKET socket, query exporter, query bpftool stats, assert sum-equal | bash | 140 |
| `tests/T_EXPORTER_NO_ATTACHED_IFACE.sh` | §6.39 test: exporter starts on system with no attached XDP; `/metrics` returns HELP+TYPE only, no sample lines | bash | 60 |
| `tests/T_BYPASS_CMD_DETACHES.sh` | §6.40 test: `xdpmacfilter bypass --iface veth-test0 --unsafe --reason test` → XDP detached + stderr audit line matches regex | bash | 70 |
| `tests/T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE.sh` | §6.41 test: bypass in non-tty without `--unsafe` → exit 1 + stderr instructs to use --unsafe | bash | 55 |
| `tests/T_RULES_SKELETON_NOT_WIRED.sh` | §6.42 test: apply config with `rules:` section, generate traffic that would match if wired, verify datapath behaviour BYTE-IDENTICAL to MVP-3.2 + stderr WARN matches | bash | 110 |

**Note on test numbering**: this slice ships 6 new tests (§6.37..§6.42). Brief target was 4-6; architect picks 6 (all listed in brief, none optional — each one verifies a distinct invariant from PI-27..PI-32, see §6.5 mapping below).

##### EDITED (existing files touched this slice)

| Path | Role (one line) | What changes |
|---|---|---|
| `src/bpf/mac_filter.bpf.c` | XDP BPF program + .maps block | ADD two new map declarations (`rules` ARRAY[XDPMF_ALLOWLIST_MAX] of `struct rule_entry`; `action_table` ARRAY[ACTION_MAX] of `struct action_entry`) inside the existing `SEC(".maps")` block. **`mac_filter_prog` xdp function body BYTE-EQUIVALENT to MVP-3.2** (reviewer asserts via `git diff main -- src/bpf/mac_filter.bpf.c` shows ZERO lines changed inside the `mac_filter_prog` function body; only the `.maps` block grows). PI-28 below. |
| `src/common/mac_filter.h` | Shared header (BPF + userspace) | ADD `struct rule_entry`, `struct action_entry`, `enum xdpmf_action_type` (`ACTION_PASS=0`, `ACTION_DROP=1`, `ACTION_MAX=2`), `XDPMF_MAP_RULES_NAME`, `XDPMF_MAP_ACTION_TABLE_NAME`. No modification of existing constants / structs / enum values (PI-10 strengthened). |
| `src/lib/loader.cpp` | Apply orchestrator (per D-3.1-1: `internal::apply_request()` body lives here, NOT in a separate `apply_internal.cpp` — the `apply_internal.hpp` companion file ships only declarations) | **SCOPED EDIT** confined to: (i) the `internal::apply_request()` function body at the existing `step 8` ladder — INSERT new step 8.5 per §5.29 apply() flow above (populate `rules` + `action_table` from `req.config.rules` + emit stderr WARN if non-empty); (ii) the existing skel-load / fd-opening step (step 4) — add `bpf_object__find_map_by_name` calls + the `pin_specs[]` literal extension (9 → 11 entries) for the two new `rules` and `action_table` maps; (iii) the state-b reattach `bpf_map__reuse_fd` loop — extend `reuse_specs[]` literal from 9 → 11 maps; **(iv) `open_skeleton_only()`'s `pinned_maps[]` literal-array — additive-only extensions (10 → 12 entries) to mirror the `pin_specs`/`reuse_specs` extensions in (ii)/(iii). Rationale: the new maps carry `LIBBPF_PIN_BY_NAME` (matching all other pinned maps in `mac_filter.bpf.c`); libbpf auto-pins them to bpffs root unless `bpf_map__set_pin_path(m, nullptr)` clears the auto-pin BEFORE `mac_filter_bpf__load()`. Without this clear-call list extension, the subsequent per-iface manual `bpf_map__pin("/sys/fs/bpf/xdpmacfilter/<iface>/rules")` fails with `libbpf: map 'rules' already has pin path` (impl caught this in Phase 2.5 ctest smoke — 27/42 fail before, all green after). This (iv) scope-fence ADDED Phase B EDIT-2 (2026-05-24 evening, dialog with mint-dev-impl after Task #2 completion).** **NO change** to: `attach()` / `detach()` public-API bodies, §5.4 state-machine, §5.19 name-check, §5.22 tag-check + O_PATH path-discipline, §5.24 kernel-version probe, §5.26 trust_model parse+log, §5.27 CIDR populate step, the link-pin P0a logic, any RAII wrapper, any error-translation path, `open_skeleton_only`'s LOOP BODY (only the static `pinned_maps[]` array literal grows — the iteration logic byte-equivalent). Reviewer asserts via `git diff main -- src/lib/loader.cpp` shows changes localized inside the 4 enumerated regions — zero diff elsewhere in the file. **D-3.1-1 disposition unchanged**: the §5.26 architectural decision to keep apply_request in `loader.cpp` (rather than a separate `.cpp`) STANDS for this slice. |
| `src/lib/apply_internal.hpp` | Apply orchestrator interface — declaration-only companion per D-3.1-1 | Expected UNCHANGED. The new step 8.5 helper logic lives inline in `loader.cpp`'s anon namespace alongside existing `apply_request` (no new public-internal symbol needed). If impl factors out a static helper (e.g. `populate_rules_and_action_table()`) for readability, it stays as `static` / anon-namespace in `loader.cpp` — NOT promoted to `apply_internal.hpp`. If impl finds a strong reason to promote a declaration, SendMessage architect. |
| `src/lib/config.cpp` | Config validator | **VERIFY** (not modify): the §5.26 schema rule 4 already accepts `action: {pass, drop}`. If the existing validator path silently dropped `drop` rules from `Config.rules` rather than carrying them through with `action=Drop`, fix to carry them through (impl reads §5.26 validator before deciding — SendMessage architect if §5.26 actually drops them; this is a §5.26 design promise that this slice realizes). Expected: NO config.cpp change OR minimal change to ensure `Config.rules` contains all rules with their action faithfully preserved. |
| `src/lib/config.hpp` | Config types | UNCHANGED. `Rule { id, action, match }` from §5.26 already carries the full per-rule shape. |
| `src/lib/yaml_subset.cpp` | YAML subset parser | Expected UNCHANGED. The parser already handles arbitrary mapping keys; the `action:` and `rules:` keys are recognized at the validator layer in `config.cpp`. Impl verifies; if a parser extension IS required (e.g. depth or key-name budget), architect MUST be SendMessage'd (this would invalidate the "no parser change" expectation). |
| `src/cli/cli.cpp` | CLI dispatch table | ADD `bypass` subcommand entry; register `bypass.hpp`'s `bypass_main(argc, argv)` in the verb dispatch. NO change to `attach` / `detach` / `apply` / `--help` / `--version` paths beyond the help-text update listing `bypass`. |
| `src/cli/cli.hpp` | CLI types | ADD `ParsedBypass { iface, unsafe, reason }` to the `ParsedCommand = std::variant<...>` if the existing CLI uses the variant pattern; else add an entry to the dispatch enum/table. |
| `src/cli/main.cpp` | CLI entry-point | DISPATCH `ParsedBypass` to `cli::bypass_main()` per the existing variant-visit pattern. |
| `CMakeLists.txt` | Top-level build | (a) `project(xdpmacfilter VERSION 0.5.0 ...)` → `project(xdpmacfilter VERSION 0.6.0 ...)`; (b) NEW `add_executable(xdpmf-exporter src/exporter/...)` target linking `xdpmf_internal` + libbpf; (c) `install(TARGETS xdpmf-exporter DESTINATION ${CMAKE_INSTALL_BINDIR})` (and existing `xdpmacfilter` install MAY be amended to also use BINDIR for symmetry — impl-flexible); (d) extend `XDPMF_INSTALL_SYSTEMD_UNIT` install rule list to also install `systemd/xdpmf-exporter.service` (alongside §5.28's `xdpmacfilter@.service`); (e) NO other CMake changes. |
| `CHANGELOG.md` | Version history | NEW `## [0.6.0] - 2026-05-NN` section per Keep-a-Changelog. Build-pace table gains a row for MVP-3.4. |
| `tests/CMakeLists.txt` | ctest registration | (a) 6 new `add_test(...)` entries (§6.37..§6.42); (b) `RESOURCE_LOCK xdp_fixture` for the 5 tests that touch veth (T_EXPORTER_VALUES_MATCH_STATS, T_EXPORTER_NO_ATTACHED_IFACE, T_BYPASS_CMD_DETACHES, T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE, T_RULES_SKELETON_NOT_WIRED); T_EXPORTER_METRICS_FORMAT MAY share `xdp_fixture` lock OR run on its own background-spawned exporter against a mocked bpffs root — tester's call; (c) NEW `RESOURCE_LOCK exporter_port_9417` to prevent two parallel exporter-running tests from binding the same port; (d) `TEST_ENV` gains `XDPMF_EXPORTER_BIN=${CMAKE_BINARY_DIR}/xdpmf-exporter`, `EXPORTER_UNIT_SRC=${CMAKE_SOURCE_DIR}/systemd/xdpmf-exporter.service`; (e) NO modification of the 36 existing `add_test` entries (PI-34 strict superset). |
| `tests/lib/common.sh` | Test helpers | OPTIONAL additive: new helpers `start_exporter_in_background(port, bpffs_root)`, `stop_exporter()`, `curl_metrics(port)` MAY be added. Existing helpers UNCHANGED — additive-only. Tester's call: if a helper would only be used by ONE ctest, inline it instead. |

##### UNCHANGED-BUT-AFFECTED (zero git-diff; behaviour must hold)

| Path | Why it matters |
|---|---|
| `src/lib/loader.hpp` | **PI-7-3.4 strengthening — 4th consecutive ZERO-diff cycle** (MVP-3.1 +1 line; MVP-3.2/3.3/3.4 = 0). `git diff main -- src/lib/loader.hpp` shows ZERO output. Any diff = `[INVARIANT-VIOLATED]`. The new `bypass` subcommand uses the EXISTING `loader::detach()` public surface; no new public symbol. |
| `src/lib/loader.cpp` `attach()` / `detach()` PUBLIC-API function bodies + all trust+identity gate codepaths (§5.4 state-machine, §5.19 name-check, §5.22 tag-check + O_PATH, §5.24 kernel-version probe, §5.26 trust_model parse+log) | UNCHANGED at the function-body level. ONLY `internal::apply_request()` body is touched per the EDITED row above (scoped edit). The detach codepath used by `bypass` is the existing `loader::detach()` — byte-equivalent. Reviewer asserts via `git diff main -- src/lib/loader.cpp` that diff lines are confined to (a) `internal::apply_request()` body extension, (b) the anon-namespace helper / map-name string addition for skel-load. Any diff outside these two regions = `[INVARIANT-VIOLATED]`. **§5.29 EDIT-1 clarification (Phase B dialog with mint-dev-impl, 2026-05-24)**: original §5.29 FileList wrote `src/lib/apply_internal.cpp` as the EDITED target; that file does not exist per D-3.1-1 (`apply_request` lives in `loader.cpp`). FileList corrected to target `loader.cpp` with the precise scope-fence above; PI-7-3.4 below is correspondingly split into PI-7-3.4-hpp (loader.hpp ZERO diff — 4th cycle, unchanged contract) and PI-7-3.4-cpp (loader.cpp scoped-edit only, NEW formulation). |
| `src/lib/cidr.cpp`, `src/lib/cidr.hpp` | UNCHANGED. §5.27 CIDR axis is preserved byte-equivalent. |
| `src/lib/raii.hpp` | UNCHANGED. Exporter MAY introduce its own RAII fd wrapper INSIDE `src/exporter/`; the shared lib's RAII surface stays put. |
| `src/cli/apply.cpp`, `src/cli/apply.hpp` | UNCHANGED. The new apply-time WARN fires inside `apply_internal.cpp` (per D-3.1-1 layering), not at the CLI surface. |
| `src/cli/attach.{cpp,hpp}`, `src/cli/detach.{cpp,hpp}` | UNCHANGED. Bypass is a NEW subcommand alongside, not a modification of detach. |
| `src/bpf/mac_filter.bpf.c` `mac_filter_prog` xdp function body | UNCHANGED (PI-28). Only the `.maps` declaration block grows. The function body byte-diff is zero. |
| Existing 36 ctests (`tests/T_*.sh` from MVP-1 + MVP-1.1 + MVP-2 + MVP-3.1 + MVP-3.2 + MVP-3.3) | Bodies UNCHANGED. Reviewer asserts `git diff --stat tests/T_*.sh` shows ZERO body changes; only 6 NEW T_EXPORTER_*, T_BYPASS_*, T_RULES_SKELETON_* files. PI-34 strict superset. |
| `tests/lib/read_stats.py` | UNCHANGED. The exporter does its OWN PERCPU sum via libbpf; it does not invoke `read_stats.py`. Existing ctests' usage byte-equivalent. |
| `tests/fixtures/*` (all existing YAML + BPF fixtures) | UNCHANGED. T_RULES_SKELETON_NOT_WIRED introduces a NEW fixture `tests/fixtures/config_rules_skeleton.yaml` (NEW file, not a modification of an existing fixture). |
| `systemd/xdpmacfilter@.service` | UNCHANGED. The exporter ships a SEPARATE unit `xdpmf-exporter.service`. |
| `ansible/xdpmacfilter-deploy.yml`, `ansible/templates/xdpfilter-config.yaml.j2` | UNCHANGED this slice. Forward-compat note: the Jinja2 template ALREADY emits a `rules:` block (see §5.28 §5.27-compat template), and the loader at §5.29 will WARN on it; this is intended forward-compat behaviour. Operators authoring `rules:` blocks via Ansible see the WARN in `journalctl` but `apply` exits 0 — feature is forward-ready. NO Ansible template touch required this slice. |
| `docs/FLEET_DEPLOYMENT.md` | UNCHANGED. The existing Prometheus-alert-semantic prose forward-references MVP-3.4's exporter; this slice realizes that forward-ref but does not require a docs edit (operator-facing material for the exporter ship lives in `CHANGELOG.md [0.6.0]` entry — sufficient for v1). Architect leaves an OPTIONAL impl-discretion FLEET_DEPLOYMENT.md `## Exporter (MVP-3.4)` section addition; if added, it MUST cite the exact `/metrics` endpoint + the exporter unit name + the new alertable counter names. Default: skip; CHANGELOG suffices. |
| `README.md` | UNCHANGED. The "Production deployment" section (§5.28 Q5 N1) MAY (impl-discretion) gain a one-line pointer to the exporter; default: skip; CHANGELOG suffices. |
| `cmake/BpfBuild.cmake` | UNCHANGED. New BPF maps are pure header + .bpf.c declaration additions; no Build.cmake change required. |
| `include/version.h.in`, `tests/lib/pins.sh.in` | UNCHANGED (templates from §5.25 still authoritative; CMake reads new `VERSION 0.6.0` into `version.h.in`). Same version string for both `xdpmacfilter --version` and `xdpmf-exporter --version` (PI-33). |
| All §5.4 / §5.19 / §5.22 / §5.24 trust+identity gates (alien refusal, name-check, tag-check, O_PATH path-discipline, kernel-version probe) | UNCHANGED. Bypass primitive does NOT invoke `attach()`; it invokes `detach()` only. The trust-model gates fire on `attach()` entry, NEVER on `detach()` (per §5.4/§5.19/§5.22 sub-section flow). Exporter does NOT invoke `attach()` or `detach()`; it reads pinned maps RO. No invariant relaxation; reviewer re-runs §6.9, §6.14, §6.15, §6.20, §6.26 sub-cases — all still pass. |

#### §5.29 Decisions (additional, with rationale)

##### D-3.4-1 — Exporter as separate binary in `src/exporter/`, NOT a subcommand of `xdpmacfilter` — because

A separate long-running daemon is the standard Prometheus exporter shape (node_exporter, blackbox_exporter, kube-state-metrics). Folding it into `xdpmacfilter` as a `serve` subcommand would (a) inflate the loader binary that runs from systemd `Type=oneshot` (LOC + linking surface), (b) confuse the "loader = one-shot CLI" mental model that §5.28 systemd integration depends on, (c) make `xdpmf-exporter --version`-style audit-tooling harder. The cost is one extra ctest harness for binary discovery + one extra systemd unit; the benefit is operational clarity and link-surface minimization.

##### D-3.4-2 — Exporter links against `xdpmf_internal` static lib, NOT against `xdpmacfilter` binary — because

`xdpmf_internal` was created at §5.26 Q1 R1 specifically to be a SHARED INTERNAL static lib for non-test consumers. Exporter is the first non-test consumer outside the `xdpmacfilter` binary. Linking against `xdpmacfilter` would force `xdpmacfilter` to be a library; linking against `xdpmf_internal` is the documented MVP-3.1 idiom paying off. Reviewer asserts `ldd xdpmf-exporter` shows ONLY libbpf + libc + libstdc++ (no `xdpmacfilter`, no third-party dep).

##### D-3.4-3 — Embedded HTTP/1.0 server, NOT a library (HG-3.4-3) — because

Three alternatives evaluated (per brief Q5 rationale): (a) prometheus-cpp adds a new build dep — violates "zero non-standard deps" project value from `src/cli/cli.cpp:1-3`; (b) node_exporter textfile-collector requires `node_exporter` on every operator host + file rotation + extra cron — net cost > embedded server cost AND operator-runtime burden; (c) microhttpd / cpp-httplib smaller deps but still deps. ~150-200 LOC plain-socket HTTP/1.0 server is small, auditable, has no failure mode unrelated to BPF-side concerns, and inherits zero CVE surface. Project value alignment is load-bearing.

##### D-3.4-4 — Rules map is SHARED (not ARRAY_OF_MAPS-swapped), because the datapath does not consult it — because

§5.27 introduced parallel ARRAY_OF_MAPS for CIDR atomicity because the CIDR datapath DOES consult that map per-packet. The `rules` map in §5.29 is NOT consulted per-packet (HG-3.4-1 — datapath byte-equivalent to MVP-3.2). Therefore no atomicity is needed on `rules`; clear-and-rewrite on every apply is fine. MVP-3.4b will need to revisit this decision when wiring the datapath: either promote `rules` to a parallel-outer (`rules_a` / `rules_b` + outer ARRAY_OF_MAPS) for atomic swap, OR rely on per-rule-counter copy-on-write semantic. Surfaced as Open Q for MVP-3.4b scoping (see §7 OOS below).

##### D-3.4-5 — Bypass audit-log fires BEFORE `loader::detach()`, not after — because

The audit-log line is operationally meaningful even if the detach fails (operator's intent was recorded). If we logged AFTER detach and detach raised, the audit trail would be silent on a half-completed bypass attempt. Pre-detach logging mirrors the §5.26 `trust_model=<mode>` log-line discipline (logged at attach() ENTRY, before any kernel call). Reviewer asserts via §6.40 ordering: stderr first shows `BYPASS activated…`, then any detach exit / err output.

##### D-3.4-6 — Exporter cap-set MUST be `CAP_BPF` ONLY; not the §5.28 5-cap set — because

The MVP-3.3 review.md round-1 rework surfaced that the §5.28 5-cap set (CAP_BPF + CAP_NET_ADMIN + CAP_SYS_RESOURCE + CAP_SYS_ADMIN + CAP_PERFMON) is the MINIMUM for loading + attaching XDP programs (verifier trusted-mode gate). The exporter does NONE of those operations: it does `BPF_OBJ_GET` (cap_bpf), reads PERCPU map values (cap_bpf), and serves HTTP (no cap). Declaring extra caps would VIOLATE the principle of least privilege and dilute the audit story (operator wonders "why does the read-only exporter need CAP_SYS_ADMIN?"). The minimal `AmbientCapabilities=CAP_BPF` is the correct decision.

**Anti-misdiagnosis institutional learning (cross-references §5.28 D-3.3-6 + MEMORY entry)**: future cycles touching cap declarations on NEW binaries / NEW invocation paths MUST run `capsh --drop=<all-other-caps> -- <binary> <typical-args>` as a Phase-B smoke check during design dialog. The §5.28 round-1 failure on `xdpmacfilter@.service` happened precisely because no one ran `capsh --drop=cap_sys_admin -- xdpmacfilter attach` before the 3-cap set was committed. For this slice, the equivalent smoke check is:

```
sudo capsh --keep=1 --user=root --inh=cap_bpf --addamb=cap_bpf -- \
    -c '/usr/bin/xdpmf-exporter --port 9417 --bpffs-root /sys/fs/bpf/xdpmacfilter'
```

If this fails with `permission denied` on `BPF_OBJ_GET`, the cap-set declaration in the unit is wrong; impl SendMessages architect, do NOT add caps silently to "make it work" (that masks a different root cause — most likely the pinned-map's permission bits are wrong, OR libbpf path is wrong, OR kernel < 5.8 fallback path is missing). The §5.28 round-1 root cause was the cap-set, not the BPF code; the SAME diagnostic discipline applies here in reverse.

##### D-3.4-7 — Exporter is READ-ONLY by construction; no map mutations, no attach/detach — because

The exporter's only BPF interaction is `bpf_obj_get(pin_path)` (read-only fd) followed by `bpf_map_lookup_elem(fd, key, value)` (read PERCPU value, no `BPF_F_LOCK`, no `update_elem`, no `delete_elem`). The codebase MUST NOT have ANY call to `bpf_map_update_elem`, `bpf_map_delete_elem`, `bpf_obj_pin`, `bpf_link_create`, `bpf_xdp_attach`, `bpf_xdp_detach`, `bpf_prog_load`, `bpf_link_destroy` in `src/exporter/`. Reviewer asserts via `grep -E 'bpf_(map_(update|delete)_elem|obj_pin|link_create|xdp_(attach|detach)|prog_load|link_destroy)' src/exporter/` → zero matches. PI-31 below.

##### D-3.4-8 — `rules` skeleton is clear-and-rewrite, not differential update — because

For MVP-3.4 the apply path writes all 64 slots on every apply (set occupied slots to their `{present=1, action_id=X}` values; clear unoccupied slots to `{present=0, action_id=0}`). This is O(64) BPF syscalls per apply — at most one apply per `systemctl reload` (so per-minute at worst in fleet ops), totally negligible. Differential-update logic would be a premature optimization that adds bug surface (e.g. "operator removed rule id=5 → did we clear slot 5?"). MVP-3.4b MAY revisit if measurement shows it matters.

#### §5.29 TestStrategy entries

##### §6.37 T_EXPORTER_METRICS_FORMAT — `/metrics` endpoint returns Prometheus text-format compliant output

**Trigger**: attach `xdpmacfilter` to a veth fixture (existing `setup_veth` helper) with one MAC-only rule (`config_valid.yaml`); inject N packets so STAT_PASS counter advances; start `xdpmf-exporter` in background bound to ephemeral port (chosen at test setup, exported as `EXPORTER_PORT`); wait for HTTP listener readiness (≤1s, poll loop); `curl -s http://127.0.0.1:${EXPORTER_PORT}/metrics`.

**Observable outcome**: HTTP 200 OK; Content-Type header contains `text/plain; version=0.0.4`; body contains:
- `# HELP xdpfilter_packets_total ...` substring
- `# TYPE xdpfilter_packets_total counter` substring (exact match for the Prometheus type-line ERE `^# TYPE xdpfilter_packets_total counter$`)
- At least one sample line matching ERE `^xdpfilter_packets_total\{iface="[^"]+",verdict="(pass|drop_deny|drop_malformed|pass_cidr)"\} [0-9]+$`
- Sample lines MUST follow HELP+TYPE; HELP+TYPE MUST appear exactly once each.

**Assertion mechanism**: bash `[[ $rc -eq 0 ]]` on `curl`; `grep -qE` on the 3 required patterns; `wc -l` on `^xdpfilter_packets_total` lines is ≥ 1.

**SKIP conditions**: `curl` not in PATH → SKIP-77 with `EXPORTER_PORT_SKIP: curl absent` rationale (DEV VM should have curl; if not, ctest skips legitimately).

**Cleanup**: kill exporter (PID captured in test setup); `cleanup_veth`.

**Maps to**: PI-31 (exporter READ-ONLY — implicit: if exporter wrote to maps, this test would still pass but T_EXPORTER_VALUES_MATCH_STATS would catch it via subsequent value drift), PI-32 (graceful empty for unattached ifaces — implicit fallthrough), HG-3.4-3 (Prometheus format).

##### §6.38 T_EXPORTER_VALUES_MATCH_STATS — exporter PERCPU sum matches bpftool sum

**Trigger**: attach + apply MAC+CIDR-mixed config; inject **known** counts of (a) allowed-MAC frames N_pass, (b) denied-MAC frames N_drop, (c) malformed (runt) frames N_malf, (d) CIDR-matched IPv4 frames N_pcidr — using the existing persistent AF_PACKET socket idiom from MVP-3.1+ (no per-packet exec overhead); wait for traffic quiesce; start exporter in background on `EXPORTER_PORT`; `curl -s http://127.0.0.1:${EXPORTER_PORT}/metrics > /tmp/metrics.out`; in parallel: `bpftool map dump pinned ${PIN_DIR}/stats --json | jq` and PERCPU-sum via `tests/lib/read_stats.py` (existing helper).

**Observable outcome**: for each of the 4 verdicts (pass, drop_deny, drop_malformed, pass_cidr), the integer in the corresponding `xdpfilter_packets_total{iface="<iface>",verdict="<v>"} <N>` line in `/tmp/metrics.out` MUST EQUAL the corresponding sum from `read_stats.py`.

**Assertion mechanism**: parse each `xdpfilter_packets_total{...} <N>` line via `awk` / `grep -oE`; compare against the `read_stats.py` output via `[[ "$exporter_val" == "$bpftool_val" ]]` for each verdict. Strict equality (NOT approximate — both are reading the SAME PERCPU map).

**SKIP conditions**: `curl` or `jq` not in PATH → SKIP-77. `bpftool` already required by existing tests.

**Cleanup**: kill exporter; `cleanup_veth`.

**Maps to**: PI-31 (READ-ONLY — values match what bpftool sees byte-for-byte), HG-3.4-3 (correctness of `prom_format::emit_metrics` sum logic), Q4 E1 (direct read on scrape: values are FRESH, not cached).

##### §6.39 T_EXPORTER_NO_ATTACHED_IFACE — exporter serves cleanly on system with zero attached XDP

**Trigger**: ensure NO XDP attached anywhere under `${XDPMF_BPFFS_ROOT}` (delete any stale pin dirs); start exporter in background on `EXPORTER_PORT`; `curl -s http://127.0.0.1:${EXPORTER_PORT}/metrics`.

**Observable outcome**: HTTP 200 OK; body contains the HELP + TYPE lines (header-only output is valid for "no series"); NO `xdpfilter_packets_total{...}` sample lines. Exit code 0 on `curl`. Exporter still alive after the request (does NOT crash on empty bpffs).

**Assertion mechanism**: `grep -q '^# HELP xdpfilter_packets_total'`, `grep -q '^# TYPE xdpfilter_packets_total counter'`, AND `grep -cE '^xdpfilter_packets_total\{' /tmp/metrics.out` equals 0. Additionally `kill -0 $EXPORTER_PID` succeeds (proves exporter still running).

**SKIP conditions**: `curl` absent → SKIP-77.

**Cleanup**: kill exporter; cleanup_veth (no-op if no veth created).

**Maps to**: PI-32 (graceful empty / no crash), PI-31 (exporter does not try to attach anything when no iface is present).

**Anti-misdiagnosis note (OPS canary, per architect-spec)**: this test is the load-bearing OPS canary for the exporter binary. The existing 36 ctests invoke other binaries (`xdpmacfilter`) via `nsenter` which preserves full caller caps; the exporter is the FIRST long-running daemon ctest in the suite, and it is also the first test that exercises `BPF_OBJ_GET` on a NON-PRESENT path (the unattached-iface case). If `bpf_obj_get(non-existent)` raises an exception that isn't caught, the exporter crashes on its first scrape against an empty fleet — operationally meaningful failure. This test must NOT be skipped lightly.

##### §6.40 T_BYPASS_CMD_DETACHES — `bypass --unsafe --reason X` detaches XDP + emits audit-log

**Trigger**: attach `xdpmacfilter` to veth-test0 (existing fixture); confirm `bpftool net show dev veth-test0` shows the prog id; run `xdpmacfilter bypass --iface veth-test0 --unsafe --reason "T_BYPASS_test"` capturing stderr.

**Observable outcome**: exit code 0; stderr line matches ERE `^xdpmacfilter: BYPASS activated on veth-test0 by uid=[0-9]+ reason="T_BYPASS_test"$`; `bpftool net show dev veth-test0` shows NO xdp prog attached (matches §6.13 T_DETACH_NOTHING-style assertion); pin dir `${PIN_DIR}/veth-test0/link` does NOT exist (detach cleaned up).

**Assertion mechanism**: `[[ $rc -eq 0 ]]`, `grep -qE` on the audit ERE, `bpftool net show dev veth-test0 2>&1` does NOT contain `prog id`, `[[ ! -e ${PIN_DIR}/veth-test0/link ]]`.

**Additional sub-check**: re-run with `--reason` ABSENT (just `xdpmacfilter bypass --iface veth-test0 --unsafe` after a re-attach setup) → stderr line ends `reason="UNSPECIFIED"`. Confirms the default-reason text per §5.29 CLI grammar above.

**SKIP conditions**: none.

**Cleanup**: `cleanup_veth`.

**Maps to**: PI-30 (bypass = detach-alias + audit, no BPF map flag, no datapath touch), HG-3.4-2.

##### §6.41 T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE — bypass without `--unsafe` in non-tty refuses + exit 1

**Trigger**: attach `xdpmacfilter` to veth-test0; run `xdpmacfilter bypass --iface veth-test0` via `setsid sh -c '...' < /dev/null > /tmp/stdout 2> /tmp/stderr` (forces non-tty for stdin/stderr — `isatty()` returns false in this shell).

**Observable outcome**: exit code 1; stderr matches `xdpmacfilter: refusing to bypass in non-interactive context without --unsafe flag (audit safety)`; `bpftool net show dev veth-test0` STILL shows the prog id attached (bypass refused → no detach happened); pin dir `${PIN_DIR}/veth-test0/link` STILL exists.

**Assertion mechanism**: `[[ $rc -eq 1 ]]`, `grep -qE 'refusing to bypass'` on stderr, `bpftool net show dev veth-test0 | grep -qE 'prog id'`, `[[ -e ${PIN_DIR}/veth-test0/link ]]`.

**SKIP conditions**: none.

**Cleanup**: explicit `xdpmacfilter detach --iface veth-test0` (since bypass refused, the test must clean up manually); `cleanup_veth`.

**Maps to**: PI-30 (bypass audit-safety contract — non-interactive context REQUIRES `--unsafe`), risk-register MVP-3.4 row 4 (manual bypass misused as automatic fail-open — the `--unsafe` gate is the named mitigation).

##### §6.42 T_RULES_SKELETON_NOT_WIRED — `rules:` config parsed + maps populated + datapath byte-equivalent to MVP-3.2

**Trigger**: attach `xdpmacfilter` via `apply -f tests/fixtures/config_rules_skeleton.yaml` where the fixture contains an explicit `rules:` block with mixed `action: pass` AND `action: drop` rules (≥ 3 entries, including at least one `drop` rule for a MAC that WOULD otherwise be passed under MVP-3.4b wiring). Inject 5 frames: one matching a `pass` MAC, one matching the `drop` MAC, one matching no rule.

**Observable outcome (all THREE conditions MUST hold)**:
1. **Schema accepted**: `apply` exits 0 (NOT exit 9 — `rules:` block + `action:` field MUST be accepted post-§5.29).
2. **WARN emitted**: stderr contains line matching ERE `^xdpmacfilter: rules: section parsed \([0-9]+ entries\) but per-rule action dispatch deferred to MVP-3.4b — datapath uses MAC/CIDR-only matching this cycle$`. The `<N>` MUST equal the entry-count in the fixture.
3. **Datapath byte-equivalent to MVP-3.2**: frame matching a `pass` MAC increments STAT_PASS (NOT STAT_DROP_DENY); frame matching the `drop` MAC ALSO increments STAT_PASS (the rule is parsed but NOT wired — datapath sees it as "in allowlist" because §5.26 added it to inner-map via the `action: pass` lookup in apply step 8); frame matching no rule increments STAT_DROP_DENY. **Key assertion**: the drop-MAC frame's verdict is PASS, not DROP — this is the operationally-observable signature of "datapath does not consult rules map". If the datapath consulted the `rules` map, the drop-MAC would actually drop.

   Wait — re-read §5.26 apply step 8: "For each rule with `action: pass` AND `mac` match → add the MAC to the inactive-inner-slot ... Rules with `action: drop` → no inner-map entry". So under §5.26 semantic, the drop-MAC was NEVER added to the inner allowlist; therefore that MAC falls through to `default_action: drop` and increments STAT_DROP_DENY. The skeleton's `rules[id].action_id=1` for the drop rule is populated but NOT consulted — so the drop-MAC's verdict matches MVP-3.2 (drop because not in allowlist), NOT a hypothetical MVP-3.4b verdict (drop because rules[id].action_id=1). For the skeleton-not-wired assertion, we want a packet whose verdict WOULD CHANGE under wired vs unwired semantics — that is, a MAC matched by a `drop` rule with the MAC ALSO in the allowlist. Per §5.26: drop rules do NOT populate inner; so the only MAC in the inner is from a `pass` rule. Constructing a divergent case: use a fixture where `id=0` is `action: pass match.mac=AA:..` AND `id=1` is `action: drop match.mac=AA:..` (same MAC, two rule entries, one pass one drop). Per §5.26 the inner-map gets the MAC once (from id=0 pass); per MVP-3.4b wired semantic, the per-packet path would consult `rules[matching_rule_id].action_id`. Either rule id matches — depends on rule-priority semantic which MVP-3.4b will define. Skeleton-unwired semantic: the MAC is in the inner → STAT_PASS. So the test is: same MAC has `pass` AND `drop` rules; under §5.29 skeleton semantic the verdict is PASS; under hypothetical MVP-3.4b wired, the verdict would depend on which rule wins (TBD). The assertion is `verdict == PASS` — matches §5.29; would FAIL under any wiring choice. This is the load-bearing test for HG-3.4-1.

   **Tester note**: if constructing this dual-rule fixture is awkward (validator may reject duplicate MAC?), the simpler alternative is to verify that a `drop`-only rule (no `pass` companion) sees its MAC NOT-in-inner-map (via direct `bpftool map dump pinned ${PIN_DIR}/allowlist_*` inspection of the active inner — assert the drop-MAC is absent), AND simultaneously confirm `bpftool map dump pinned ${PIN_DIR}/rules` shows the drop-rule slot occupied (`present=1, action_id=1`). This is more direct: rules map is POPULATED + allowlist is NOT — proves skeleton-not-wired without traffic injection. Tester chooses; both are acceptable. Architect's preference: the direct map-dump approach (more robust, no kernel-traffic flake risk).

**Assertion mechanism**: `[[ $rc_apply -eq 0 ]]`, `grep -qE` on the WARN-line ERE, `read_stats.py` shows expected (pass, drop_deny, malformed, pass_cidr) tuple, `bpftool map dump pinned ${PIN_DIR}/rules --json | jq` shows occupied slots matching the fixture's id set with the right action_ids, `bpftool map dump pinned ${PIN_DIR}/allowlist_<active> --json | jq` shows only pass-rule MACs.

**SKIP conditions**: none.

**Cleanup**: `cleanup_veth`.

**Maps to**: PI-27 (inner-allowlist-value byte-equivalent — the inner allowlist still uses `__u8 present` semantic; if it had been extended to embed `rule_id`, the bpftool dump would show a different value shape), PI-28 (`mac_filter_prog` body byte-equivalent — verified indirectly via the verdict matching MVP-3.2 expectation), PI-29 (rules+action_table populated but NOT consulted — verified directly via the bpftool map dumps + the verdict expectation), HG-3.4-1, D-3.4-4 (skeleton clear-and-rewrite + WARN).

#### §6.5 Preserved invariants (MVP-3.4 brownfield) — PI-1..PI-26 continue + PI-27..PI-34 NEW

All MVP-3.1 + MVP-3.2 + MVP-3.3 invariants (PI-1..PI-26 per §5.26 + §5.27 + §5.28 sub-sections) continue to hold post-§5.29. NEW invariants PI-27..PI-34 capture MVP-3.4-specific guarantees. Reviewer's 5th framework point walks the COMBINED list (PI-1..PI-34) and reports `[INVARIANT-VIOLATED]` per failed check.

**Continuing invariants** (per §5.28; ALL still apply post-§5.29):

| # | Invariant | §5.29 check mechanism |
|---|---|---|
| PI-1 | §5.4 alien-program identity-gate ENFORCED in strict mode | Re-run §6.9, §6.14, §6.26 sub-case 1; all pass. Bypass does NOT invoke attach, so PI-1 is unaffected. |
| PI-2 | §5.19 name-identity gate ENFORCED in BOTH modes | §6.9 + §6.26 sub-case 3 — both compute name-check. Bypass irrelevant. |
| PI-3 | §5.22 Item 1 tag-check ENFORCED in BOTH modes | §6.14 still passes. |
| PI-4 | §5.22 Item 2 O_PATH path-discipline ENFORCED in BOTH modes | §6.15 still passes. |
| PI-5 | §5.24 kernel-version probe ENFORCED in BOTH modes | §6.20 still passes. |
| PI-6-3.4 | **36 pre-§5.29 ctests pass byte-equivalent OR legitimately SKIP-77 — STRICT SUPERSET, NO carve-out this slice** | Re-run all 36 tests post-§5.29 → all pass; `git diff --stat tests/T_*.sh` shows ZERO body changes; only 6 NEW test files appear. PI-6-3.3's STRICT SUPERSET property continues. |
| PI-7-3.4-hpp | **`loader.hpp` ZERO diff — FOURTH consecutive slice** (MVP-3.1 had +1 line for `ConfigError = 9`; MVP-3.2/3.3/3.4 have 0). Public-API surface byte-equivalent. | `git diff main -- src/lib/loader.hpp` shows ZERO output. Any diff = `[INVARIANT-VIOLATED]`. |
| PI-7-3.4-cpp | **`loader.cpp` SCOPED EDIT only** — diff lines confined to: (a) `internal::apply_request()` body (step 8.5 insertion + step 4 fd-opening for `rules`+`action_table` + `pin_specs[]` literal extension 9→11 + state-b reattach `reuse_specs[]` literal extension 9→11); (b) anon-namespace helpers introduced for step 8.5 population (`populate_rules_skeleton`, `populate_action_table`, or similar); **(c) `open_skeleton_only()`'s `pinned_maps[]` literal-array — additive-only 10→12 entries to clear `LIBBPF_PIN_BY_NAME` auto-pinning for the two new maps before `__load()`; loop body itself byte-equivalent (per §5.29 EDIT-2 Phase B clarification — symmetric prerequisite to (ii)/(iii)).** ZERO diff in: `attach()` / `detach()` public-API bodies, §5.4 state-machine, §5.19 name-check, §5.22 tag-check + O_PATH path-discipline, §5.24 kernel-version probe, §5.26 trust_model parse+log, §5.27 CIDR populate step, link-pin P0a logic, RAII wrappers, error-translation paths, `open_skeleton_only`'s LOOP BODY (only the static literal array grows). **NOTE on prior formulation**: original §5.29 PI-7-3.4 claimed "loader.cpp ZERO diff" predicated on `apply_internal.cpp` being a separate file — that premise was incorrect (per D-3.1-1 `apply_request` lives in `loader.cpp`); see §5.29 EDIT-1 clarification under FileList UNCHANGED-BUT-AFFECTED row for the loader.cpp scope-fence. §5.29 EDIT-2 added scope (c) after Phase B dialog with mint-dev-impl (Task #2 completion report) — `pinned_maps[]` clear-list was a symmetric prerequisite not enumerated in the original fence but operationally necessary for the new maps' per-iface pinning to work. The MVP-3.3 PI-7-3.3 strengthening ("ENTIRE `src/lib/` zero diff") is HISTORICAL-BOUNDED to MVP-3.3; MVP-3.4 explicitly relaxes the loader.cpp leg to "scoped edit confined to three regions above". | `git diff main -- src/lib/loader.cpp` shows changes confined to the regions above. Reviewer applies a regional-diff check: produce `git diff main -- src/lib/loader.cpp` output; classify each hunk by enclosing function name; allowed function names = {`internal::apply_request`, `open_skeleton_only` (only the `pinned_maps[]` literal-array hunk; loop body / control flow MUST be byte-equivalent), new anon-namespace helpers introduced in step 8.5}. Any hunk outside this set = `[INVARIANT-VIOLATED]`; any hunk inside `open_skeleton_only` that touches loop body or control flow = `[INVARIANT-VIOLATED]`. |
| PI-8-3.4 | `xdpmacfilter --version` reports `xdpmacfilter 0.6.0` AND `xdpmf-exporter --version` reports `xdpmf-exporter 0.6.0` (shared `version.h` per §5.25 P3) | Run both `--version` invocations; outputs MUST match the version 0.6.0 (single line each, ends with newline). |
| PI-9 | `--version` / `--help` output FORMAT unchanged (version-bump only + new line listing `bypass` subcommand in `--help`) | §6.10 T_CLI_HELP_VERSION re-run passes (existing ERE forward-compatible — does NOT pin help-text length). `bypass` MAY (not MUST) appear in --help. |
| PI-10-3.4 | `src/common/mac_filter.h` existing constants + struct layout UNCHANGED; new additions are purely ADDITIVE (PI-10 strengthens) | `git diff main -- src/common/mac_filter.h` shows ONLY additions: `struct rule_entry`, `struct action_entry`, `enum xdpmf_action_type`, `XDPMF_MAP_RULES_NAME`, `XDPMF_MAP_ACTION_TABLE_NAME`. Zero modifications/removals on existing constants. Inner-allowlist-value shape definitions (the `__u8` / `unsigned char` value type for `allowlist_*` HASH and `cidr_allowlist_*` LPM_TRIE) byte-equivalent. |
| PI-11 | Internal directory layout = `src/lib/` + `src/cli/` + `src/common/` + `src/bpf/` + NEW `src/exporter/` (additive) | `find src -type d` shows the existing 4 dirs + `src/exporter/` (one new). The new dir is additive — does NOT change the existing four. |
| PI-12 | Pin paths host-global per `nsenter --net` | New pins `${PIN_DIR}/rules`, `${PIN_DIR}/action_table` visible from `nsenter --net` per existing mechanism (LIBBPF_PIN_BY_NAME under the per-iface dir). |
| PI-13-3.4 | **inner-allowlist-value byte-equivalent: `allowlist_*` HASH stays `__u8/unsigned char present`; `cidr_allowlist_*` LPM_TRIE stays `__u8/unsigned char`** — THE LOAD-BEARING DEFER PI | `git diff main -- src/bpf/mac_filter.bpf.c` shows ZERO modification to `__type(value, __u8)` for `allowlist_a/b` and `cidr_allowlist_a/b`; `git diff main -- src/common/mac_filter.h` shows ZERO modification to the inner-value type definitions. `bpftool map dump pinned ${PIN_DIR}/allowlist_a --json` value-size is 1 byte. Any extension to `struct {__u8 present; __u32 rule_id; ...}` here = `[INVARIANT-VIOLATED]` — the defer was specifically about NOT making this change. **This is PI-27 below restated for the PI-13 namespace; the two are identical.** |
| PI-14 | `--mode {generic,native,offload}` flag UNCHANGED | §6.16 + §6.17 + §6.19 all pass. |
| PI-15 | CIDR axis purely additive | UNCHANGED by §5.29 (no CIDR change). |
| PI-16 | STAT_PASS_CIDR additive enum slot | UNCHANGED. |
| PI-17 | `schema_version: 1` accepted; Jinja2 template emits schema_version: 1 | UNCHANGED. The §5.29 `rules:` block + `action:` field is ALREADY part of the §5.26 schema_version 1 grammar; this slice realizes apply-time semantic, not schema. |
| PI-18 | §6.23 MAC-axis atomic-swap continues | UNCHANGED. The new `rules` + `action_table` maps are NOT swapped (D-3.4-4), but the MAC + CIDR axes' atomic-swap mechanism (single `active_idx` flip) is preserved exactly. |
| PI-19 | systemd-analyze verify passes on the unit file | EXTENDS to `systemd/xdpmf-exporter.service`: `systemd-analyze verify systemd/xdpmf-exporter.service` exits 0 with zero warnings (PI-19 implicit extension; reviewer verifies during framework point 5 walk). |
| PI-20 | systemd lifecycle correctness for `xdpmacfilter@.service` | UNCHANGED. The new `xdpmf-exporter.service` lifecycle is NOT covered by §6.33 T_SYSTEMD_LIFECYCLE (that test is iface-specific); the exporter's lifecycle is covered indirectly by §6.37/§6.38/§6.39 spawning the binary manually + verifying liveness. PI-20 invariant preserved for `xdpmacfilter@.service`. |
| PI-21 | Ansible playbook idempotent | UNCHANGED. The playbook does not yet install the exporter (the `xdpmf-exporter.service` install is OUT-OF-SCOPE for the Ansible playbook this cycle — surfaced as MVP-3.5+ enhancement; see §7 OOS). PI-21 preserved as-is. |
| PI-22 | `ansible-playbook --syntax-check` exits 0 | UNCHANGED (playbook unchanged). |
| PI-23 | FLEET_DEPLOYMENT.md cites exact stderr-format from §5.26 | UNCHANGED (docs unchanged). |
| PI-24 | Unit file directive set matches §5.28 catalogue | UNCHANGED for `xdpmacfilter@.service`. The new `xdpmf-exporter.service` has its OWN directive catalogue per §5.29 Q5 above — reviewer verifies that catalogue separately as part of PI-19's extension. |
| PI-25 | T_SYSTEMD_RESTART_ON_FAILURE flakiness carve-out | UNCHANGED. |
| PI-26 | NO C++/BPF source change for §5.28 was correct (PI-26 was MVP-3.3-specific "no C++ change"). §5.29 INVALIDATES PI-26 by intent — this slice ADDS the exporter binary in `src/exporter/` + the bypass CLI in `src/cli/bypass.{cpp,hpp}` + extends `src/lib/apply_internal.cpp`. PI-26's MVP-3.3-bounded check still passes (PI-26 was a check on `git diff main^^^` vs MVP-3.3 boundary, NOT on the current cycle). | Reviewer treats PI-26 as MVP-3.3-historical: its check fires on the MVP-3.3 commit set, NOT on the MVP-3.4 commit set. MVP-3.4 explicitly ships new C++ code. **No re-strengthening of PI-26 needed**; the four §5.29-new C++ piece-types (exporter binary, bypass CLI, apply_internal extension, mac_filter.h additions) ARE the deliverable. |

**NEW invariants** (MVP-3.4-specific):

| # | Invariant | Check mechanism |
|---|---|---|
| **PI-27** | **Inner-allowlist-value shape BYTE-EQUIVALENT to MVP-3.2** — `allowlist_a/b` HASH `__type(value, __u8)` UNCHANGED; `cidr_allowlist_a/b` LPM_TRIE `__type(value, __u8)` UNCHANGED. **THE load-bearing PI of the defer posture.** Touching this shape would defeat Open Q #13 RESOLUTION's defer rationale entirely. | `git diff main -- src/bpf/mac_filter.bpf.c` matched against the LPM_TRIE + HASH `__type(value, __u8)` lines — zero modifications. `bpftool map show pinned ${PIN_DIR}/allowlist_a` reports `value_size 1`; same for `allowlist_b`, `cidr_allowlist_a`, `cidr_allowlist_b`. Any value_size ≠ 1 on any of the 4 inner maps = `[INVARIANT-VIOLATED]`. **Identical to PI-13-3.4 above (cross-referenced for emphasis — this is the central defer-posture PI).** |
| **PI-28** | **`mac_filter_prog` BPF function body BYTE-EQUIVALENT to MVP-3.2** modulo new `.maps` block declarations (the `rules` + `action_table` map definitions). Per-packet datapath does NOT consult `rules` or `action_table`. | `git diff main -- src/bpf/mac_filter.bpf.c` shows: (a) NEW `rules` map declaration inside `SEC(".maps")`, (b) NEW `action_table` map declaration inside `SEC(".maps")`, (c) ZERO diff lines inside the `SEC("xdp") int mac_filter_prog(...)` function body. Reviewer verifies via `git diff main -- src/bpf/mac_filter.bpf.c` + manual scope check (the function-body braces enclose zero diff lines). Additionally: `bpftool prog show id $(...)` `xlated bytes` and `jited bytes` SHOULD be greater than MVP-3.2 baseline by an amount consistent with the new map definitions ONLY (`.maps` declarations get translated to map-reuse hints + skel symbols — typically a small overhead, not zero, but the xdp prog itself does not grow). Acceptable diff range: < 200 xlated bytes growth attributable to skel symbol emission. Larger growth = function body changed → `[INVARIANT-VIOLATED]`. |
| **PI-29** | **`rules` + `action_table` POPULATED on apply but NOT consulted by datapath** — populated per §5.29 apply step 8.5 with `{present, action_id}` / `{action_type}`; the per-packet `mac_filter_prog` function does NOT issue `bpf_map_lookup_elem` against either. | `bpftool map dump pinned ${PIN_DIR}/rules` shows occupied slots matching the applied config's rule set. `bpftool map dump pinned ${PIN_DIR}/action_table` shows two entries: index 0 = `{action_type=0 (PASS)}`, index 1 = `{action_type=1 (DROP)}`. Datapath non-consultation verified via PI-28 (function-body byte-equivalence) AND via §6.42 T_RULES_SKELETON_NOT_WIRED expected-verdict assertion. **Additionally**: stderr line `xdpmacfilter: rules: section parsed (<N> entries) but per-rule action dispatch deferred to MVP-3.4b ...` MUST appear in the apply log when `rules:` block is non-empty (the WARN is the operator-facing signature of this PI; absence on non-empty `rules:` = `[INVARIANT-VIOLATED]`). |
| **PI-30** | **`bypass` primitive = `detach`-alias + audit-log + `--unsafe` gate; NO new BPF map flag, NO datapath touch** — `xdpmacfilter bypass --iface X --unsafe --reason Y` is observably equivalent to `xdpmacfilter detach --iface X` PLUS an audit-stderr-line. | §6.40 + §6.41. Additionally: `git diff main -- src/lib/loader.hpp` shows ZERO output (PI-7-3.4); `git diff main -- src/lib/loader.cpp` shows ZERO output; `git diff main -- src/bpf/mac_filter.bpf.c` shows NO new map-flag definitions / NO new XDP_BYPASS-style verdict / NO new bypass-state state-machine. The bypass primitive lives ENTIRELY in `src/cli/bypass.{cpp,hpp}` (newly-added userspace files). |
| **PI-31** | **Exporter is READ-ONLY by construction** — no `bpf_map_update_elem`, no `bpf_map_delete_elem`, no `bpf_obj_pin`, no `bpf_link_*`, no `bpf_xdp_attach/detach`, no `bpf_prog_load` calls in `src/exporter/`. | `grep -rE 'bpf_(map_(update\|delete)_elem\|obj_pin\|link_create\|link_destroy\|xdp_(attach\|detach)\|prog_load)' src/exporter/` returns ZERO matches. Reviewer asserts during framework point 5 walk. Test signals: §6.38 T_EXPORTER_VALUES_MATCH_STATS — the values served on `/metrics` equal the `bpftool` view BYTE-FOR-BYTE; if the exporter were mutating values, the equality would not hold. |
| **PI-32** | **Exporter handles missing/empty bpffs gracefully** — `xdpmf-exporter --bpffs-root <nonexistent>` OR `--bpffs-root <empty>` MUST: bind to port; serve `/metrics` with HELP+TYPE only (no sample lines); serve `/healthz` with `ok\n`; not crash; remain alive across requests. | §6.39 T_EXPORTER_NO_ATTACHED_IFACE. Additionally: if `${XDPMF_BPFFS_ROOT}` does not exist, exporter logs ONE warning line at startup (`WARN: bpffs root <path> does not exist; will serve empty metrics`) but continues to run; periodic `/metrics` scrapes return HELP+TYPE only. |
| **PI-33** | **Both binaries report version `0.6.0`** — `xdpmacfilter --version` AND `xdpmf-exporter --version` BOTH report `0.6.0` (shared `version.h` per §5.25 P3 V1 mechanism). | Run both `--version` invocations; assert single-line output with `0.6.0` and trailing newline. CMake `project(VERSION)` is the single source of truth; both binaries `#include "version.h"`. |
| **PI-34** | **36 pre-§5.29 ctests pass byte-equivalent OR legitimately SKIP-77 — STRICT SUPERSET, NO carve-out this slice** | Re-run all 36 tests post-§5.29 → all pass (or skip with rc 77 per §5.24 Q4 hybrid). `git diff main -- tests/T_*.sh` shows ZERO body changes; only 6 NEW test files appear (T_EXPORTER_METRICS_FORMAT, T_EXPORTER_VALUES_MATCH_STATS, T_EXPORTER_NO_ATTACHED_IFACE, T_BYPASS_CMD_DETACHES, T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE, T_RULES_SKELETON_NOT_WIRED). NEW fixture `tests/fixtures/config_rules_skeleton.yaml` MAY appear; existing fixtures byte-equivalent. **PI-34 == PI-6-3.4 above (cross-referenced; this is the suite-level strict-superset PI restated for the MVP-3.4 namespace).** |

**No deletions/relaxations** of PI-1..PI-26 in this slice. PI-7-3.4 STRENGTHENS PI-7-3.3 (4th consecutive ZERO-diff cycle on `loader.hpp`). PI-10-3.4 STRENGTHENS PI-10-3.3 implicitly via additive-only diff. PI-13-3.4 is identical to PI-27 and is the load-bearing defer PI. PI-6-3.4 is identical to PI-34 (the suite-level strict-superset PI for MVP-3.4).

#### §5.29 verifiable invariants for reviewer

(Per architect-spec §6.5 "Verification-hints discipline": these are GUIDANCE for the reviewer, NOT contracts for impl. Default MAY. Reserve MUST only for true PI-* contracts (PI-27..PI-34 above ARE MUSTs by definition; the items below MAY be relaxed by impl if a contract-elsewhere demands it). Resolution rule for prose-vs-invariants conflict: invariants block wins, prose loses; if impl deviates on a hint to satisfy a PI-* contract, reviewer's correct disposition is `inline-merge` on the hint text, NOT `[UNRELATED-EDIT]` on impl.)

In addition to PI-1..PI-34 above:

- `git diff main -- src/lib/loader.hpp` SHOULD show ZERO output (PI-7-3.4-hpp, 4th consecutive cycle).
- `git diff main -- src/lib/loader.cpp` SHOULD show changes confined to `internal::apply_request()` body + anon-namespace helpers introduced for step 8.5 + `open_skeleton_only`'s `pinned_maps[]` literal-array additive 10→12 extension (PI-7-3.4-cpp scoped-edit fence per §5.29 EDIT-1 + EDIT-2 clarifications). Reviewer applies regional-diff check; allowed hunk scopes = {`internal::apply_request`, `open_skeleton_only` (literal-array only, loop body byte-equivalent), new anon-namespace helpers}.
- `git diff main -- src/common/mac_filter.h` SHOULD show ONLY additions (new `struct rule_entry`, `struct action_entry`, `enum xdpmf_action_type`, `XDPMF_MAP_RULES_NAME`, `XDPMF_MAP_ACTION_TABLE_NAME`); zero modifications of existing constants / struct layouts / enum values.
- `git diff main -- src/bpf/mac_filter.bpf.c` SHOULD show: NEW `rules` ARRAY map declaration, NEW `action_table` ARRAY map declaration. ZERO modification to inner-allowlist value `__type(value, __u8)` for `allowlist_a/b` or `cidr_allowlist_a/b`. ZERO modification to the `SEC("xdp") int mac_filter_prog(...)` function body.
- `git diff main -- src/lib/apply_internal.cpp` SHOULD show the step 8.5 extension (rules + action_table population + WARN emission) + the state-b reattach loop extension from 9 → 11 reuse_fd maps. ZERO change to the trust_model / identity-gate / kernel-version-probe codepaths.
- `git diff main -- src/lib/config.cpp` SHOULD show ZERO or near-zero change (the schema already accepts `rules:` block + `action:` field per §5.26; this slice only realizes apply-time semantic). If a config.cpp change IS made, impl SendMessages architect for confirmation (the §5.26 schema is supposed to already accept the grammar — a real change implies a §5.26 promise was not fully realized).
- `git diff main -- tests/T_*.sh` SHOULD show: 6 NEW test files (T_EXPORTER_METRICS_FORMAT, T_EXPORTER_VALUES_MATCH_STATS, T_EXPORTER_NO_ATTACHED_IFACE, T_BYPASS_CMD_DETACHES, T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE, T_RULES_SKELETON_NOT_WIRED). ZERO modification to the 36 existing test bodies.
- `git diff main -- tests/lib/common.sh` SHOULD show ZERO OR ADDITIVE-ONLY (new exporter helpers `start_exporter_in_background`, `stop_exporter`, `curl_metrics`); existing helpers byte-equivalent. Tester's discretion whether to add helpers or inline.
- `git diff main -- tests/lib/read_stats.py` SHOULD show ZERO output.
- `git diff main -- tests/fixtures/` SHOULD show: NEW `config_rules_skeleton.yaml` (for §6.42 T_RULES_SKELETON_NOT_WIRED); existing fixtures byte-equivalent.
- `git diff main -- tests/CMakeLists.txt` SHOULD show ONLY 6 new `add_test(...)` entries + `RESOURCE_LOCK exporter_port_9417` declaration; the 36 existing entries byte-equivalent.
- New files SHOULD exist: `src/exporter/{main,http,prom_format,stats_reader}.{cpp,hpp}`, `src/cli/bypass.{cpp,hpp}`, `systemd/xdpmf-exporter.service`, plus 6 T_*.sh under `tests/` + 1 new fixture.
- `systemd-analyze verify systemd/xdpmf-exporter.service` SHOULD exit 0 with no warnings (PI-19 extension).
- 6 new ctests SHOULD pass (§6.37..§6.42); §6.38 + §6.42 are the load-bearing pair (exporter values match stats + skeleton-not-wired).
- 36 pre-§5.29 ctests SHOULD still pass (or legitimately SKIP-77) — PI-34 STRICT SUPERSET, no carve-out.
- `xdpmacfilter --version` SHOULD report `xdpmacfilter 0.6.0` AND `xdpmf-exporter --version` SHOULD report `xdpmf-exporter 0.6.0` (PI-33).
- `XDPMF_SANITIZERS=ON` build SHOULD be clean for BOTH binaries.
- `CHANGELOG.md` entry `[0.6.0] - 2026-05-NN` (Keep-a-Changelog format).
- Build-pace table in CHANGELOG SHOULD gain a row for MVP-3.4.
- `ldd $(which xdpmf-exporter)` SHOULD show ONLY libbpf + libc + libstdc++ (D-3.4-3 zero-deps).
- `grep -rE 'bpf_(map_(update|delete)_elem|obj_pin|link_create|link_destroy|xdp_(attach|detach)|prog_load)' src/exporter/` SHOULD return ZERO matches (PI-31).
- `capsh --keep=1 --user=root --inh=cap_bpf --addamb=cap_bpf -- -c '/usr/bin/xdpmf-exporter --port 9417 ... &'` SHOULD start successfully against a pinned-stats fixture (D-3.4-6 anti-misdiagnosis smoke-check; tester MAY add as a final ctest sub-step in T_EXPORTER_METRICS_FORMAT, OPTIONAL).

#### §7 OOS — MVP-3.4 components SHIPPED + new fences

##### Moved from deferred to SHIPPED (per MVP-3.4)

- ~~**`xdpmf-exporter` binary / Prometheus exporter implementation** — MVP-3.4 slice.~~ **— SHIPPED in §5.29 (MVP-3.4, 2026-05-NN)** as `xdpmf-exporter` long-running daemon (Q1 D1) with embedded HTTP/1.0 server (HG-3.4-3) serving `/metrics` (Q4 E1 direct read) + `/healthz`. Single-instance unit (Q5 N3). Installed at `/usr/bin/xdpmf-exporter` (Q2).
- ~~**Manual bypass primitive** — MVP-3.4 slice (mitigates risk-register MVP-3.4 row 4).~~ **— SHIPPED in §5.29** as `xdpmacfilter bypass --iface X [--unsafe] [--reason Y]` (HG-3.4-2). `detach`-alias + audit-stderr + non-tty `--unsafe` gate.
- ~~**`rules` + `action_table` BPF skeleton (B.2 partial — wires rule_id → counter index, structurally only)** — MVP-3.4 slice.~~ **— SHIPPED in §5.29** as DECLARED-AND-POPULATED-NOT-WIRED maps per HG-3.4-1 + Q3 minimal struct layout. Forward-compatibility scaffold for MVP-3.4b wiring; datapath untouched.

##### NEW out-of-scope fences (per §5.29)

- **Per-rule counter map (`per_rule_counters` BPF_MAP_TYPE_PERCPU_*)** — MVP-3.4b slice per Open Q #13 RESOLUTION (architecture-v2.md §"§MVP-3.4 Open Question #13 RESOLUTION"). DO NOT add this map in §5.29. The Option 2 default ("Sparse-direct-bounded ARRAY") becomes the candidate when MVP-3.4b is scoped.
- **Inner-allowlist-value extension (`__u8` → `struct {__u8 present; __u32 rule_id;}`)** — MVP-3.4b. Gated by PI-13-3.1 adjudication (Open Q #3 in arch-v2 §"§MVP-3.4 Open Question #13 RESOLUTION" Open questions). MVP-3.4 explicitly DOES NOT touch this shape (PI-27/PI-13-3.4).
- **Datapath wiring of `rules` or `action_table`** — MVP-3.4b. Per HG-3.4-1, `mac_filter_prog` body byte-equivalent to MVP-3.2 (PI-28). Adding any `bpf_map_lookup_elem(&rules, ...)` or `bpf_map_lookup_elem(&action_table, ...)` inside `mac_filter_prog` = `[INVARIANT-VIOLATED]`.
- **Action types beyond {PASS, DROP}** — MVP-3.8+. The `enum xdpmf_action_type` reserves ACTION_MAX = 2 for cycle; MIRROR / RATE_LIMIT / TAG / REDIRECT are future additive enum slots, gated by their own scoping.
- **JSON structured logs from exporter** — MVP-3.5 candidate. Exporter v1 emits plain stderr lines only (startup bind notice + accept errors).
- **sFlow integration** — MVP-3.6 conditional.
- **Exporter HTTPS / TLS** — operator wraps with stunnel / nginx-as-reverse-proxy if required. Adding TLS to the embedded HTTP/1.0 server would violate D-3.4-3 (zero-deps).
- **Exporter authentication** — Prometheus scrape is unauthenticated by convention. Operators wanting auth wrap with a reverse-proxy.
- **Exporter histograms / summary / labels beyond `{iface, verdict}`** — kept minimal. Histograms ship with MVP-3.5 candidate (per-packet-size distribution) or later; new labels (e.g. `verdict_reason`) gate on operator demand.
- **Bypass via BPF map flag (in-datapath bypass-bit)** — explicitly fenced by HG-3.4-2. The datapath stays byte-equivalent (PI-28). A future "fast bypass" via map-flag would require a datapath branch + a new BPF map; MVP-3.6+ optional, gated on actual operator demand for "bypass without detach" (currently zero demand).
- **Library extraction `libxdpmf.so.0`** — MVP-3.6+ optional. The exporter linking against `xdpmf_internal` STATIC is the v1 mechanism (D-3.4-2).
- **Daemon `xdpmfd`** — MVP-3.6+ optional. The exporter is a daemon but does NOT do attach/detach; it's read-only observability, not control-plane.
- **L4 ports / VLAN / IPv6 CIDR** — still fenced per MVP-3.2 §7 OOS (unchanged from §5.27).
- **Binary rename `xdpmacfilter` → `xdpfilter`** — still MVP-3.12 (per §5.28 HG-3.3-1 disposition). The exporter is named `xdpmf-exporter` (NOT `xdpfilter-exporter`) — same naming-prefix discipline as the loader; both rename together at MVP-3.12.
- **Exporter listening on IPv6 / dual-stack** — v1 IPv4-only (`--bind` accepts dotted-quad or `0.0.0.0` only). v6 fenced; operators wanting v6 wrap with HAProxy / nginx.
- **Exporter inotify on `${XDPMF_BPFFS_ROOT}/`** — v1 polls on every scrape (Q4 E1). Inotify-based dynamic-iface-detection is MVP-3.5+ candidate IF a workload demands sub-15s detection of new ifaces (no current demand).
- **Exporter `--include-pass-cidr` flag parallel to `read_stats.py`** — exporter ALWAYS emits all 4 verdicts (pass, drop_deny, drop_malformed, pass_cidr). The `read_stats.py` `--include-pass-cidr` flag is for the test helper, NOT the exporter; the exporter emits the full PERCPU map content. No flag parity needed.
- **Ansible installs of `xdpmf-exporter`** — MVP-3.5+ candidate. `ansible/xdpmacfilter-deploy.yml` UNCHANGED this slice (operators add exporter install manually OR fork the playbook).
- **`docs/EXPORTER.md` operator docs** — MVP-3.5+ candidate. CHANGELOG `[0.6.0]` entry + `xdpmf-exporter --help` text are the v1 operator docs surface; if operator demand surfaces, a dedicated docs file ships in MVP-3.5+.
- **Per-rule counters / labels in exporter output beyond global stats** — MVP-3.4b. The exporter does NOT emit per-rule counters because the BPF datapath does not produce them (HG-3.4-1).
- **Exporter unit drop-in for non-default `${XDPMF_BPFFS_ROOT}`** — the unit defaults to `XDPMF_BPFFS_ROOT` macro; operators wanting non-default override via Drop-In with `Environment=XDPMF_BPFFS_ROOT=/custom/path` + `ExecStart=/usr/bin/xdpmf-exporter ...`. Not shipped in repo.
- **Bypass via SIGTERM / signal-handler in the long-running loader** — fenced. The loader is `Type=oneshot`; there is no long-running process to send signals to. `xdpmacfilter bypass --iface X --unsafe` is the operator path.
- **Bypass with auto-reattach after N seconds** — fenced. v1 bypass is permanent until next `apply` / `attach`. Auto-reattach is operator scope (cron / systemd timer).
- **Bypass auditing to syslog instead of (or in addition to) stderr** — fenced. v1 is stderr-only; under systemd this lands in `journalctl` (which IS syslog-equivalent in modern deployments). MVP-3.5+ JSON-log slice MAY add structured-logging surface.
- **Atomic-swap on `rules` map (parallel-outer pattern from §5.27)** — fenced this slice (D-3.4-4: skeleton-only doesn't need atomicity). Surfaced as a question for MVP-3.4b scoping: if datapath wires `rules`, the map MUST be promoted to a parallel-outer or copy-on-write equivalent. Architect surfaces explicitly: "MVP-3.4b atomic-swap question on `rules` map" as a pre-cycle Open Q.
- **MVP-3.1/3.2/3.3 OOT-deferred housekeeping items** — per Q6 DEFER. The 5 items stay in their dispositions.

##### Surfaced as next-natural slice

**MVP-3.4b — per-rule counter wiring** (this is the explicit next-slice surfaced by the Open Q #13 RESOLUTION):
- per-rule counter map (Option 2 default per arch-v2.md §"§MVP-3.4 Open Question #13 RESOLUTION" Recommendation: PERCPU_ARRAY[64] with `XDPMF_RULE_COUNTERS_MAX = XDPMF_ALLOWLIST_MAX = 64` alias from T.9)
- inner-allowlist-value extension (`__u8` → `struct {__u8 present; __u32 rule_id;}` for BOTH `allowlist_*` HASH and `cidr_allowlist_*` LPM_TRIE — symmetric per T.5 OQ #3)
- datapath wiring of `rules` → `action_table` lookup chain inside `mac_filter_prog`
- atomic-swap promotion of `rules` to parallel-outer (D-3.4-4 surfaced Open Q)
- Prometheus `xdpfilter_rule_match_total{iface, rule_id}` series in exporter
- sidecar JSON `${PIN_DIR}/rule_index.json` (optional; per arch-v2.md Option 2)
- PI-13-3.1 adjudication (Open Q #3) BEFORE the slice starts

Estimated budget per arch-v2.md §"§MVP-3.4 Open Question #13 RESOLUTION" Option 2 cost row: ~5 fixture touches (PI-13 migration); CIDR LPM_TRIE inner-value sister change; +16 KiB BPF memory (negligible). Risk: medium (gated on PI-13-3.1 adjudication). If adjudication returns VIOLATE, fall back to Option 3 ("Decouple via two-map shadow") which inflates the slice budget; if VIOLATE confirms persistently, defer per-rule counters indefinitely.

Evidence: `mint/task-brief.md` MVP-3.4 brief (Items 1-4 + Q1-Q6 + HG-3.4-1/2/3); `mint/architecture-v2.md` MVP-3.4 row (lines 234-243) + per-phase scope summary (line 312) + risk register (lines 337-340) + **§"§MVP-3.4 Open Question #13 RESOLUTION" (lines 421-561) — the load-bearing defer-rationale source**; §5.26 (schema's `rules:` block + `action:` field this slice realizes apply-time semantic for); §5.27 (CIDR axis — second-axis precedent for additive datapath extension, NOT used here because skeleton maps are NOT consulted); §5.28 (systemd unit template idiom + D-3.3-6 anti-misdiagnosis pattern that D-3.4-6 inherits); §4.1 exit-code table (UNCHANGED — no new exit code); §4.3 LoaderError enum (UNCHANGED — PI-7-3.4 ZERO diff); §5.4 / §5.19 / §5.22 (trust+identity gates preserved untouched — bypass invokes `detach` which does NOT consult them); `mint/impl-notes.md` D-3.1-1..D-3.3-10 (prior deviations that STAND unchanged).

##### Anti-misdiagnosis notes (institutional learning, per architect-spec §6.6)

This slice carries two anti-misdiagnosis guards forward from prior rework rounds:

1. **Cap-set declaration on a NEW invocation path** (inherited from §5.28 D-3.3-6 rework round 1): the exporter is a NEW binary with a NEW systemd unit declaring `AmbientCapabilities=CAP_BPF`. Future cycles touching cap declarations on NEW binaries MUST run `capsh --drop=<all-other-caps> -- <binary> <typical-args>` as a Phase-B smoke-check during design dialog BEFORE committing the cap-set. The §5.28 round-1 failure was a 3-cap set that worked under NSEXEC-preserved-caps but failed under systemd-stripped-caps. The §5.29 risk surface is the inverse: declaring TOO MANY caps would dilute the audit story but would not fail-loud. Mitigation: D-3.4-6 explicit cap-set rationale (CAP_BPF only, with explicit "we do NOT need CAP_SYS_ADMIN/NET_ADMIN/SYS_RESOURCE/PERFMON because we do not load/attach/rlimit/perfcount" justification).

2. **Silent-inheritance-pattern recurrence** (inherited from the Open Q #13 RESOLUTION round, architecture-v2.md Hidden Assumption #1): the brief BODY at lines 35-40 of the design-brief contained a factual contradiction with shipped §5.26 schema rule 3 (`id ∈ [0, 63]`). ARRAY + T architects caught it; HASH architect inherited the brief framing silently. **Mitigation for this slice**: the MVP-3.4 task-brief is faithful to the defer posture (Open Q #13 RESOLUTION human-gate Option 1) — the architect (this document) verified against the just-amended architecture-v2.md section before drafting. **Future-cycle guard**: when MVP-3.4b is scoped, the architect drafting that brief MUST cross-check the inner-allowlist-value PI (PI-13-3.4 / PI-27 in this design) against shipped `src/common/mac_filter.h` and `src/bpf/mac_filter.bpf.c` BEFORE assuming any extension; the brief MUST cite the PI's current shape verbatim. If the brief misframes the existing inner-value as anything other than `__u8 / unsigned char`, the synthesizer's "line of defense" must catch it (per arch-v2.md Hidden Assumption #1 register entry).

### §5.30 MVP-3.4.5: housekeeping (defer-posture audit + landmine removal) (brownfield amendment, 2026-05-25)

**Purpose**: pure non-functional cleanup of the backlog accumulated through MVP-3.1..3.4 + the `/mint-review` audit (commit `325e2ee` of `agent-teams-review/runs/mint-review-mint-l2-mac-filter-202605250825/report.md`). 17 housekeeping items in 3 themes: (1) contract-drift fixes HK-1..HK-8 (exit-code triple-drift, `XDPMF_BPF_OBJECT_PATH` compile-gate, bypass audit-trail hardening, perf micro-opt, --help completeness, version bump 0.6.0 → 0.6.1); (2) landmine removal HK-9..HK-10 (3-callsite `LIBBPF_PIN_BY_NAME` lockstep → single `kManagedMaps[]` table; broad `pkill` → iface-scoped); (3) OOT-deferred backlog HK-11..HK-17 (5 items from MVP-3.1/3.3/3.4 deferral queues + 2 "implement-per-design" from MVP-3.4 review.md). **No new operator-facing feature, no new BPF map, no datapath behaviour change, no new public API, no schema change, no new exit code.** Smallest LOC delta of MVP-3.x to date. Documentation pass (13-item doc bucket from `/mint-review` report — README rewrite, FLEET_DEPLOYMENT.md sections, CONFIG_SCHEMA.md, HANDOFF.md move, Ansible Jinja fixes) is EXCLUDED from this slice per user direction (separate manual pass — see task-brief.md "Doc bucket").

**Anchor sections**: §5.29 (MVP-3.4 ancestor — defer-posture; `rules`+`action_table` skeleton; bypass primitive; exporter); §4.1 exit-code table (UNCHANGED — no new codes; HK-1 fixes exit-1 propagation; HK-2 updates `--help` to list code 7; HK-17 surfaces the existing code 6 trigger for exporter); §5.26 D-3.1-1 (`apply_request` lives in `loader.cpp`, NOT `apply_internal.cpp` — HK-1 catch arm lands in `main.cpp`, HK-9 refactor is `loader.cpp`-internal); §5.27 + §5.28 + §5.29 invariant chain (PI-1..PI-34 all preserved); MVP-3.3 §5.28 D-3.3-6 + MVP-3.4 §5.29 D-3.4-6 (anti-misdiagnosis cap-set discipline — HK-3 + HK-17 inherit).

**Scope contract (§5.30 short form)**:
- NEW (tests only — NO new source files this slice): `tests/T_APPLY_EXITS_1_ON_MISSING_CONFIG.sh` (HK-1), `tests/T_BYPASS_INTERACTIVE_PROMPT.sh` (HK-4 / new-coverage), `tests/T_BYPASS_REASON_TRUNCATE.sh` (HK-4 truncation), `tests/T_EXPORTER_EXITS_6_ALL_IFACES_EACCES.sh` (HK-17).
- EDITED (source): `src/cli/main.cpp` (HK-1 catch arm), `src/cli/apply.cpp` (HK-1 stale comment), `src/cli/cli.cpp` (HK-2 + HK-6 usage_text), `src/lib/loader.cpp` (HK-3 compile-gate + HK-9 kManagedMaps refactor), `src/cli/bypass.cpp` (HK-4 escape + sudo identity), `src/bpf/mac_filter.bpf.c` (HK-5 unlikely() wraps), `src/exporter/main.cpp` (HK-6 env-var block + HK-17 exit-6), `src/exporter/stats_reader.cpp` (HK-16 WARN + HK-17 trigger), `CMakeLists.txt` (HK-3 option + HK-7 docs install + HK-8 version bump 0.6.0 → 0.6.1).
- EDITED (tests + meta): `tests/CMakeLists.txt` (HK-3 propagate XDPMF_ENABLE_BPF_OBJECT_OVERRIDE + 4 new add_test entries), `tests/T_LINK_PERSIST_ACROSS_LOADER_EXIT.sh` (HK-10 iface-scoped pkill), `tests/lib/common.sh` (HK-10 kill_loader_keep_link — if PID-track approach chosen), `tests/T_SYSTEMD_RESTART_ON_FAILURE.sh` (HK-11 internal retry), `tests/T_APPLY_ATOMIC_SWAP_NO_DROP.sh` (HK-12 NOTE comment), `tests/T_ATTACH_TAG_MISMATCH.sh` (HK-13 orphan-pin cleanup), `tests/T_EXPORTER_NO_ATTACHED_IFACE.sh` (HK-16 WARN grep), `CHANGELOG.md` (HK-8 new `[0.6.1]` entry + MVP-3.4.5 build-pace row), design.md (HK-15 §5.26 ParsedAttach/Detach/Apply wrapper text correction — inline retraction note).
- UNCHANGED-BUT-AFFECTED (zero git-diff fence): `src/lib/loader.hpp` (**PI-7-3.4.5-hpp — 5th consecutive ZERO-diff cycle**); all 42 pre-§5.30 ctest BODIES except the 5 EDITED listed above; `src/lib/loader.cpp` outside the two explicit hunks (HK-3 compile-gate + HK-9 refactor) — see PI-7-3.4.5-cpp scope-fence below; `src/bpf/mac_filter.bpf.c` `.maps` block + `mac_filter_prog` function body (HK-5 only touches the 6 verifier null-checks at the listed lines — a leaf branch micro-opt, byte-equivalent JIT semantics; PI-28 holds); `src/common/mac_filter.h` (UNCHANGED — no new constants); `src/lib/{config,yaml_subset,cidr}.{cpp,hpp}` (UNCHANGED); `src/cli/{attach,detach,apply}.{cpp,hpp}` (UNCHANGED except HK-1 comment delete in `apply.cpp`); §5.4 / §5.19 / §5.22 / §5.24 trust+identity gates (UNCHANGED); systemd unit files (UNCHANGED — HK-7 installs the docs FILE, not the units); Ansible playbook (UNCHANGED — Jinja template doc fixes are in the EXCLUDED doc bucket).

**Human-gate decisions (defaults from brief — confirmed by architect, all defaults stand)**:

- **HG-3.4.5-1 — HK-16 PI-32 startup WARN → IMPLEMENT per design (W1 startup-only).** Confirmed. The MVP-3.4 review.md round-1 disposition was "silent graceful return"; per [[impl-role-discipline]] silent divergence from design is forbidden. PI-32 text (§5.29) literally says "logs ONE warning line at startup"; impl now emits it. W1 (one-shot `std::filesystem::exists(bpffs_root)` at exporter start) chosen over W2 (per-scrape rate-limited) — matches PI-32 literal phrasing, simpler impl, matches fleet-ops expectation (startup-time diagnostic, not per-scrape noise). See D-3.4.5-1 below for exact stderr-line wording + emission ordering.

- **HG-3.4.5-2 — HK-17 exporter exit-6 → IMPLEMENT per design (E1: ALL ifaces fail EACCES/EPERM + non-empty discovered set + zero successes).** Confirmed. The MVP-3.4 §5.29 declared exit 6 EXISTS but did NOT specify the trigger condition; this slice fills the gap. E1 chosen over E2 (any-iface fail → fail-loud) and E3 (bind-time only) because: (a) E2 risks unit flapping if one iface gets bpffs permission issue while others read fine — operationally hostile; (b) E3 is a different failure mode (bind-time vs scrape-time) that probably deserves its own exit code anyway; (c) E1 aligns with "if we can't read ANYTHING then permission-denied is the right exit code" while preserving "partial visibility better than no visibility" for normal fleet operation. Empty bpffs root = exit 0 (no-ifaces is a normal state per HK-16/PI-32). Per-iface EACCES with at least one success continues to WARN-and-continue (preserved from MVP-3.4 `stats_reader.cpp:141-145`). See D-3.4.5-2 below for the precise counter accounting.

- **HG-3.4.5-3 — HK-9 `kManagedMaps[]` refactor → SHIP this cycle (Q4 T1 member-pointer).** Confirmed. The 3-callsite landmine (open_skeleton_only `pinned_maps[]` / apply_request `pin_specs[]` / apply_request `reuse_specs[]`) bit during MVP-3.4 EDIT-2 (27/42 ctest fail signature). MVP-3.5+ datapath-map additions will fire it again unless consolidated. T1 (member-pointer) chosen over T2 (name-lookup) and T3 (lambda dispatch) — compile-time-checked, no runtime lookup overhead, mirrors existing literal-array structure. See D-3.4.5-3 below + DataStructures additions.

- **HG-3.4.5-4 — HK-11 T_SYSTEMD_RESTART_ON_FAILURE → S1 (internal 2-attempt retry).** Confirmed. Retains the strict band [4,5] StartLimit-placement-footgun guard (the original purpose of the test). S2 (widen band to [1,50]) is the fallback ONLY if S1 measured-adds >30s to ctest runtime. Surface attempt count in PASS message (`PASS: T_SYSTEMD_RESTART_ON_FAILURE (attempt N/2)`).

#### §5.30 Q-decisions (mechanism)

##### Q1: HK-1 catch placement → **C1 (catch arm to main.cpp's SECOND try, mirroring FIRST)**

Confirmed per brief default. 3 LOC. Mirrors `main.cpp:99-103`'s existing `catch (const xdpmf::CliError& e)` arm on the FIRST try (parser). Apply via the same exception type. C2 (whole-main try/catch with switch on exception type, ~15 LOC) is over-engineering for a single missing arm — and given D-3.1-1 (`apply_request` body lives in `loader.cpp`; main.cpp dispatches via `std::visit`), the SECOND try is the natural fence: catch `CliError` raised during the visit body, return `kExitUsageErr` (= 1). The visited `apply_main` already raises `CliError` on `LoaderError::ConfigError` (= 9) and on `LoaderError::AttachRefused` (= 4), but the missing-file case `LoaderError::ConfigError` from `apply_internal::load_config_file()` was escaping unwrapped — the C1 arm catches it.

##### Q2: HK-16 PI-32 WARN trigger → **W1 (one-shot startup check; stderr; continue)**

Confirmed per brief default + HG-3.4.5-1. Exact mechanism (impl reference, see Interfaces additions for the precise stderr line):

1. `xdpmf-exporter::main()` parses CLI; `cfg.bpffs_root` populated (default `XDPMF_BPFFS_ROOT` macro = `/sys/fs/bpf/xdpmacfilter`).
2. BEFORE the first `http::run()` invocation, ONE `std::filesystem::exists(cfg.bpffs_root)` check.
3. If false: emit ONE stderr line per Interfaces below; continue (do NOT exit).
4. If true: silent (no positive log line — would be noise; the existing `xdpmf-exporter: listening on <bind>:<port>` line at HTTP bind time is the operator's "I started" signal).

No per-scrape check (W2). No rate-limiting (W1 fires at most once per process lifetime).

##### Q3: HK-17 exporter exit-6 trigger → **E1 (ALL ifaces EACCES/EPERM + non-empty discovered set + zero successes)**

Confirmed per brief default + HG-3.4.5-2. Precise trigger semantics (see Interfaces + Decisions below):

- During scrape-loop / discovery pass: `stats_reader::read_all_attached(bpffs_root)` returns a vector of `StatsSample` PLUS (NEW for HK-17) a small accounting struct counting `{total_discovered, eacces_failures, other_failures, successes}` per-iface counters.
- After ANY scrape (or at end of an explicit "verify discovery" pre-flight if architect prefers), if `total_discovered > 0 AND eacces_failures == total_discovered AND successes == 0` → exit from `main()` with code 6 + ONE stderr line: `xdpmf-exporter: ERROR all <N> discovered interfaces failed permission-denied; check CAP_BPF and bpffs read mode (exit 6)`.
- Per-iface partial-EACCES (some succeed, some EACCES) → unchanged from MVP-3.4: WARN-and-continue per existing `stats_reader.cpp:141-145` handler (PI-31 preserved).
- Empty `total_discovered` (bpffs root exists but no per-iface subdirs OR doesn't exist) → exit 0 — no-ifaces is a normal state (HK-16 WARN at startup, then quiet running).
- See D-3.4.5-2 for the precise counter accounting + "when does the check fire" detail.

##### Q4: HK-9 kManagedMaps[] table representation → **T1 (member-pointer)**

Confirmed per brief default + HG-3.4.5-3. Concrete shape in DataStructures sub-section below. Rationale recap: T1 is compile-time-checked (the member-pointer expression `&mac_filter_bpf::maps::allowlist_a` will fail to compile if libbpf-skel renames the map field, fail-fast at build-time) and has zero runtime overhead (the three loops walk the table once each per apply / open). T2 (name-based `bpf_object__find_map_by_name`) adds a per-iteration name lookup AND defers all rename-failures to runtime. T3 (lambda dispatch table) is over-engineering for a 10-entry table.

##### Q5: HK-11 retry strategy → **S1 (internal 2-attempt retry within test)**

Confirmed per brief default + HG-3.4.5-4. Exact retry shape: after first attempt fails, the test resets systemd state (`systemctl reset-failed xdpmacfilter@${IFACE}.service`; small `sleep 1`; clear any pin-dir residue if present) and re-runs the same probe sequence. PASS message: `PASS: T_SYSTEMD_RESTART_ON_FAILURE (attempt N/2)`. If both attempts fail → FAIL (NOT SKIP — test still gates correctness; the StartLimit-placement-footgun signature is band [4,5], and the band MUST hold). Tester measures end-to-end runtime; if S1 measured-adds >30s to ctest runtime, escalate to architect via SendMessage and the fallback is S2 (widen band [1,50] permanently).

##### Q6: tackle additional MVP-3.4 review findings? → **No additional items** (per brief default)

Confirmed. M5+M6 testing (interactive prompt + reason truncation) are already in scope (HK-4 + new ctest list). H1 perf (`__builtin_expect`) is HK-5. H2 arch (3-callsite refactor) is HK-9. H5 doc (FLEET_DEPLOYMENT.md exporter section) is in the EXCLUDED doc bucket. Adding more items risks scope explosion on a "small housekeeping" cycle that's already 17 items. Doc items deferred to the user's separate manual doc pass.

#### §5.30 DataStructures additions

##### `kManagedMaps[]` (HK-9 refactor; anon-namespace in `src/lib/loader.cpp`)

The 3-callsite literal arrays from MVP-3.4 (`open_skeleton_only`'s `pinned_maps[]` clear-list at line 828; `internal::apply_request`'s `pin_specs[]` per-iface manual-pin list at line 1705; `internal::apply_request`'s `reuse_specs[]` state-b reattach list at line 1566) are consolidated into ONE constexpr table at anon-namespace scope. All three call-sites walk the SAME table; the `legacy_alias` flag filters the `allowlist` entry out of pin/reuse loops (it stays in the clear-list only because LIBBPF auto-pin must be cleared on the alias too, even though its actual per-iface pin happens via the special-pin path at `loader.cpp:1739`).

```cpp
// src/lib/loader.cpp anon namespace (HK-9 §5.30, MVP-3.4.5)
namespace {

// The libbpf-generated `mac_filter_bpf` skeleton declares its `maps` member as
// an ANONYMOUS struct (no nameable `mac_filter_bpf::maps_struct` type exists).
// Use decltype to get the member-pointer-able type. Per §5.30 EDIT-1 (Phase B
// dialog with mint-dev-impl, 2026-05-25).
using MapsT = decltype(std::declval<mac_filter_bpf>().maps);

struct ManagedMapEntry {
    // Pointer to the bpf_map* member in the skel's anon `maps` struct.
    // Compile-time-checked: any rename in mac_filter.bpf.h skeleton auto-fails build.
    ::bpf_map* MapsT::* member_ptr;
    const char* name;       // pin file name under ${PIN_DIR}/<iface>/
                            // MUST come from XDPMF_MAP_*_NAME constants in
                            // src/common/mac_filter.h to avoid string-literal drift
                            // vs. the .bpf.c SEC(".maps") declarations.
    bool legacy_alias;      // true → SKIP from pin_specs and reuse_specs; KEEP in pinned_maps clear-list
};

// Order matches existing apply_request pin_specs[] for line-diff readability.
// 12 entries: 11 "real" maps (incl. MAP_OF_MAPS outers from §5.26 / §5.27) +
// 1 legacy MVP-1 alias. Per §5.30 EDIT-1 (Phase B dialog with mint-dev-impl,
// 2026-05-25): count corrected from initial draft's 10 — `rulesets` and
// `cidr_rulesets` (MAP_OF_MAPS outer maps for MAC / CIDR atomic-swap) were
// omitted from the initial enumeration and are restored. All 12 carry
// LIBBPF_PIN_BY_NAME per the .bpf.c source.
constexpr ManagedMapEntry kManagedMaps[] = {
    { &MapsT::allowlist_a,      XDPMF_MAP_INNER_A_NAME,             false },
    { &MapsT::allowlist_b,      XDPMF_MAP_INNER_B_NAME,             false },
    { &MapsT::rulesets,         XDPMF_MAP_RULESETS_OUTER_NAME,      false },  // §5.26 MAC MAP_OF_MAPS outer
    { &MapsT::cidr_allowlist_a, XDPMF_MAP_CIDR_INNER_A_NAME,        false },
    { &MapsT::cidr_allowlist_b, XDPMF_MAP_CIDR_INNER_B_NAME,        false },
    { &MapsT::cidr_rulesets,    XDPMF_MAP_CIDR_RULESETS_OUTER_NAME, false },  // §5.27 CIDR MAP_OF_MAPS outer
    { &MapsT::active_idx,       XDPMF_MAP_ACTIVE_IDX_NAME,          false },
    { &MapsT::defaults,         XDPMF_MAP_DEFAULTS_NAME,            false },
    { &MapsT::stats,            XDPMF_MAP_STATS_NAME,               false },
    { &MapsT::rules,            XDPMF_MAP_RULES_NAME,               false },  // §5.29 skeleton
    { &MapsT::action_table,     XDPMF_MAP_ACTION_TABLE_NAME,        false },  // §5.29 skeleton
    { &MapsT::allowlist,        XDPMF_MAP_ALLOWLIST_NAME,           true  },  // legacy MVP-1 alias
};

}  // anon namespace
```

**Notes on the exact field + constant naming** (per §5.30 EDIT-1 clarification):
- The skel's `maps` member is an anonymous struct → use `MapsT = decltype(std::declval<mac_filter_bpf>().maps)` to get a nameable type for the member-pointer. Architect's initial draft wrote `mac_filter_bpf::maps_struct` as an illustrative pseudo-name; the `decltype` workaround is the correct idiom.
- All 12 entries' `name` fields use `XDPMF_MAP_*_NAME` constants from `src/common/mac_filter.h` (NOT string literals) — preserves byte-equivalence with the existing `pin_specs[]` / `reuse_specs[]` / `pinned_maps[]` literals and avoids any string-drift between this table, the .bpf.c SEC(".maps") declarations, and the operator-facing pin paths.
- `rulesets` (MAC MAP_OF_MAPS outer, §5.26) + `cidr_rulesets` (CIDR MAP_OF_MAPS outer, §5.27) MUST appear in the table even though their inner maps are swapped via the atomic-idx mechanism — the OUTER map dentries themselves are pinned at apply time for external bpftool observability + state-b reattach. Omitting them would regress T_RULES_SKELETON_NOT_WIRED and the atomic-swap tests per D-3.4.5-7.
- Test-build verification: zero-diff in `bpftool map show` output before/after HK-9 for ALL 12 maps (PI-29 + the 42-test baseline jointly cover this).

**Three call-sites post-HK-9** (all in `loader.cpp`):

1. **`open_skeleton_only()` clear-list** (was pinned_maps[10] literal; ~12 LOC):
   ```cpp
   for (const auto& entry : kManagedMaps) {
       ::bpf_map_set_pin_path(skel->maps.*entry.member_ptr, nullptr);
   }
   // Walks ALL 10 entries including legacy_alias=true.
   ```

2. **`internal::apply_request()` pin_specs loop** (was pin_specs[9] literal at line 1705; ~10 LOC):
   ```cpp
   for (const auto& entry : kManagedMaps) {
       if (entry.legacy_alias) continue;          // skip the alias from per-iface pinning
       const std::string p = pin_dir + "/" + entry.name;
       if (auto rc = ::bpf_map_pin(skel->maps.*entry.member_ptr, p.c_str()); rc < 0) {
           throw std::system_error(LoaderError::AttachFailed, "pin " + p);
       }
   }
   ```

3. **`internal::apply_request()` reuse_specs loop** (was reuse_specs[9] literal at line 1566; ~10 LOC):
   ```cpp
   for (const auto& entry : kManagedMaps) {
       if (entry.legacy_alias) continue;          // alias is not pin-by-name-reused
       const std::string p = pin_dir + "/" + entry.name;
       int fd = ::bpf_obj_get(p.c_str());
       if (fd < 0) {
           if (errno == ENOENT) continue;          // state-a path: no prior pin
           throw std::system_error(LoaderError::AttachFailed, "obj_get " + p);
       }
       ::bpf_map_reuse_fd(skel->maps.*entry.member_ptr, fd);  // libbpf manages fd lifetime post-reuse
   }
   ```

Net LOC: ~12 + ~10 + ~10 + 14 (table — 12 entries) = ~46 LOC code (replaces ~80 LOC of literals + per-call-site verbose error strings; the literals were 12/11/11 entries respectively per §5.30 EDIT-1 correction); net delta is roughly **neutral-to-negative** (probably -20 to -30 LOC after dedup of the per-site error messages). HK-9's value is NOT LOC reduction — it's eliminating the future-cycle 3-callsite-lockstep landmine.

##### No other DataStructures changes

HK-1..HK-8, HK-10..HK-17 are pure-fix items; no new types, no struct changes, no enum changes. `struct rule_entry`, `struct action_entry`, `enum xdpmf_action_type` from §5.29 stand byte-equivalent. `LoaderError` enum stands byte-equivalent (PI-7-3.4.5-hpp ZERO diff). Existing `exporter::StatsSample` / `HttpConfig` stand byte-equivalent. HK-17 adds a small internal accounting struct (impl-private to `stats_reader.cpp`; NOT in `stats_reader.hpp`):

```cpp
// src/exporter/stats_reader.cpp (HK-17 §5.30, MVP-3.4.5) — file-static, NOT exported.
struct DiscoveryAccounting {
    std::size_t total_discovered = 0;   // per-iface stats-pin paths found under bpffs_root
    std::size_t eacces_failures = 0;    // bpf_obj_get failed with EACCES or EPERM
    std::size_t other_failures = 0;     // bpf_obj_get failed with anything else
    std::size_t successes = 0;          // bpf_obj_get + lookup succeeded
};
```

Returned alongside the existing `std::vector<StatsSample>` either via `std::pair` or via an out-parameter — impl picks (Phase B SendMessage if impl wants a new struct type promoted to the header). `read_all_attached()` signature change is acceptable since `stats_reader.hpp` is an INTERNAL header (not shipped, not in `loader.hpp` PI-7 fence). Default expectation: out-parameter form (`read_all_attached(bpffs_root, /* out */ DiscoveryAccounting& acc)`) keeps the return type stable.

#### §5.30 Interfaces additions

##### HK-1 — `xdpmacfilter apply -f <missing> --iface <iface>` exits 1 (NOT 9 — current bug)

After fix: `main.cpp`'s SECOND try block (around `std::visit`) catches `xdpmf::CliError` (raised by `apply_main` when `apply_internal::load_config_file()` throws `LoaderError::ConfigError` on missing file) and returns `kExitUsageErr` (= 1, per §4.1). The exit-code table is UNCHANGED; only the existing entry is now actually reachable on missing-file. Stderr message: existing `xdpmacfilter: config error: open <path>: No such file or directory` line is preserved verbatim. NO new stderr line. Reviewer verifies via T_APPLY_EXITS_1_ON_MISSING_CONFIG (§6.43 below).

##### HK-2 — `xdpmacfilter --help` lists code 7

usage_text edit at `cli.cpp:104-106`: the exit-code list becomes `1 usage, 2 load, 3 attach, 4 attach-refused, 5 detach, 6 permission, 7 kernel-unsupported, 8 path-refused, 9 config`. Insert `7 kernel-unsupported,` between `6 permission,` and `8 path-refused,`. Single-line change; T_CLI_HELP_VERSION ERE is forward-compatible (it does NOT pin the exact list length).

##### HK-3 — `XDPMF_BPF_OBJECT_PATH` is compile-gated behind `XDPMF_ENABLE_BPF_OBJECT_OVERRIDE`

Post-HK-3 contract: in a default release build (`cmake -DCMAKE_BUILD_TYPE=Release`), the env var `XDPMF_BPF_OBJECT_PATH` is IGNORED (the code paths that read it are `#ifdef`'d out at compile time; the var simply has no effect). In a test build (`cmake -DXDPMF_ENABLE_BPF_OBJECT_OVERRIDE=ON`), behaviour is identical to today. CMake mechanism:

```cmake
# CMakeLists.txt (top-level)
option(XDPMF_ENABLE_BPF_OBJECT_OVERRIDE
       "Allow loader to honor XDPMF_BPF_OBJECT_PATH env var (testing-only)" OFF)
target_compile_definitions(xdpmf_internal PRIVATE
    $<$<BOOL:${XDPMF_ENABLE_BPF_OBJECT_OVERRIDE}>:XDPMF_ENABLE_BPF_OBJECT_OVERRIDE>)
```

```cmake
# tests/CMakeLists.txt
set(XDPMF_ENABLE_BPF_OBJECT_OVERRIDE ON CACHE BOOL "" FORCE)
```

The test-side override is set BEFORE `add_subdirectory(tests)` evaluates the top-level option default OR via a CMake `set(... CACHE ... FORCE)` pattern — impl picks the cleanest mechanism per existing CMake idioms; the contract is "default OFF, test ON". `T_VERIFIER_REJECT.sh` (which uses `XDPMF_BPF_OBJECT_PATH` to point loader at a verifier-reject artifact) continues to pass because the test build sets the define. Reviewer asserts: `nm $(which xdpmacfilter) | grep XDPMF_BPF_OBJECT_PATH` in a release build returns ZERO references (string literal optimized out).

##### HK-4 — bypass log-injection escape + sudo identity

`bypass.cpp:38-53` `truncate_reason()` post-fix contract:
- Input: raw `--reason "<text>"` string (any bytes, any length).
- Step 1: byte-truncate to 253 bytes (leave room for `…` 3-byte UTF-8 ellipsis). UTF-8 rewind-safety: if byte 253 falls mid-codepoint (lead byte = `0b11xxxxxx` AND the 4 bytes around it form a multi-byte sequence), rewind to the last codepoint boundary before 253.
- Step 2: append `…` (U+2026, 3 bytes `0xE2 0x80 0xA6`) IFF the input was longer than 253 bytes.
- Step 3: escape per `prom_format.cpp:34-47` `escape_label_value()`: `\` → `\\`, `"` → `\"`, `\n` → `\\n`, `\r` → `\\r`, `\0` → `\\0`. No other byte-class escaping (matches Prometheus label-value contract).
- Output: safe-for-embed-in-double-quoted-string-in-stderr.

`bypass.cpp:124-129` audit-log line post-fix contract: AFTER the existing per-§5.29 line format, ADD `SUDO_USER` and `SUDO_UID` env-vars (read via `getenv()`) into the line as additional structural fields:

`xdpmacfilter: BYPASS activated on <iface> by uid=<UID> euid=<EUID> sudo_user="<value or <none>>" reason="<escaped reason or UNSPECIFIED>"`

Fields:
- `uid=<UID>` — `getuid()` (decimal, no leading zero).
- `euid=<EUID>` — `geteuid()` (decimal). Both fields are emitted ALWAYS (NOT just when they differ).
- `sudo_user="<value>"` — `getenv("SUDO_USER")`; if `NULL` OR empty string → emit literal `<none>` (NOT empty quotes, NOT the literal string `null`; the angle-bracket convention mirrors `UNSPECIFIED` for reason).
- `reason="<escaped>"` — escaped via the §HK-4 escape step above. `UNSPECIFIED` if `--reason` absent.

NO read of `SUDO_UID` (the original brief mentioned it but `SUDO_USER` is the operator-meaningful identity; `SUDO_UID` is just a decimal echo of what `getuid()` already shows for the wrapping shell). Impl MAY include `SUDO_UID` as an OPTIONAL trailing field if it adds operational value; default: skip per design simplicity. Single-line output; no newline within fields.

##### HK-5 — `__builtin_expect` on 6 verifier null-check sites

Add `#define unlikely(x) __builtin_expect(!!(x), 0)` near the top of `src/bpf/mac_filter.bpf.c` (after existing includes). Wrap the 6 null-check sites at lines 188, 204, 211, 229, 236, 254 — these are leaf null-checks that the verifier mandates (e.g. `if (data + sizeof(ethhdr) > data_end) return XDP_PASS;` style or `if (unlikely(!hdr)) return XDP_PASS;`). The contract: source-level annotations are added; JIT semantics are byte-equivalent (the branch direction hint affects the JIT code layout but NOT the functional verdict). Reviewer asserts via T_VERIFIER_REJECT-equivalent pass (PI-28 holds — function-body semantic byte-equivalent).

**Caveat**: the brief lists 6 site line-numbers (188, 204, 211, 229, 236, 254); these were captured against the current `mac_filter.bpf.c`. Impl verifies each site is genuinely a "verifier-mandated null check on a pointer that ALWAYS-OR-USUALLY is non-null at runtime" before wrapping — wrapping a check that's expected to fail (e.g. an actual error-handling branch) is wrong-shape. If any of the 6 sites is genuinely a 50/50 branch, impl skips that site + SendMessages architect; default is wrap all 6.

##### HK-6 — `--unsafe` semantic clarification + `XDPMF_TRUST_MODEL` env-var block in --help

`cli.cpp` usage_text post-fix:
- `--unsafe` line: `--unsafe    bypass: required in non-interactive context; ALSO suppresses interactive y/N prompt when passed at a tty.` (current wording reads as "non-interactive only", missing the prompt-suppression case).
- New `Environment variables:` sub-block at the end of the help text:
  ```
  Environment variables:
    XDPMF_TRUST_MODEL={strict|fleet}   Default: strict. fleet relaxes only
                                        §5.4 alien-program refusal — see
                                        docs/FLEET_DEPLOYMENT.md for the full
                                        gate diff between modes.
  ```
- Same `Environment variables:` sub-block added to `xdpmf-exporter` print_usage in `src/exporter/main.cpp` (consistent help-text discipline; the exporter does NOT read `XDPMF_TRUST_MODEL` but DOES read `XDPMF_BPFFS_ROOT` implicitly via the `--bpffs-root` default; the env-var block can also list `XDPMF_BPFFS_ROOT` since the exporter respects it). Impl picks: exporter block lists either both env vars or just `XDPMF_BPFFS_ROOT`; default: list both with a note that `XDPMF_TRUST_MODEL` does NOT affect the exporter.

T_CLI_HELP_VERSION ERE is forward-compatible. No new test required (HK-6 is a usage-text expansion; existing T_CLI_HELP_VERSION verifies clean exit, not text length).

##### HK-7 — `docs/FLEET_DEPLOYMENT.md` installed alongside systemd units

`CMakeLists.txt:140-185` post-fix: inside the existing `XDPMF_INSTALL_SYSTEMD_UNIT` block:

```cmake
install(FILES ${CMAKE_SOURCE_DIR}/docs/FLEET_DEPLOYMENT.md
        DESTINATION ${CMAKE_INSTALL_PREFIX}/share/doc/xdpmacfilter/)
```

Pairing rationale: the systemd units' `Documentation=file:///usr/share/doc/xdpmacfilter/FLEET_DEPLOYMENT.md` URI (per §5.28 + §5.29 unit catalogues) now resolves on the operator's host post-install. Gated on the existing systemd-install option (operators not installing units don't need the docs file copied either). NO change to the units themselves.

##### HK-8 — version bump 0.6.0 → 0.6.1 + CHANGELOG `[0.6.1]` entry

`CMakeLists.txt`: `project(xdpmacfilter VERSION 0.6.0 ...)` → `project(xdpmacfilter VERSION 0.6.1 ...)`. Both binaries (`xdpmacfilter --version` AND `xdpmf-exporter --version`) report `0.6.1` post-bump (shared `version.h.in` from §5.25 P3 mechanism — PI-33 extends to 0.6.1).

`CHANGELOG.md`: new `## [0.6.1] - 2026-05-NN` section per Keep-a-Changelog format. Document all HK-1..HK-17 changes grouped under Keep-a-Changelog sub-headers (Fixed / Changed / Added). Build-pace table gains a row for MVP-3.4.5. Impl picks the exact prose; suggested grouping:
- **Fixed** — HK-1 (apply exit-code triple drift), HK-4 (bypass log-injection escape + sudo identity), HK-10 (iface-scoped pkill), HK-11 (T_SYSTEMD_RESTART_ON_FAILURE flake), HK-12 (T_APPLY_ATOMIC_SWAP_NO_DROP stale comment), HK-13 (orphan map-pin cleanup), HK-16 (PI-32 startup WARN now emitted), HK-17 (exit-6 now reachable on all-iface EACCES).
- **Changed** — HK-2 (--help exit-code list completeness), HK-3 (`XDPMF_BPF_OBJECT_PATH` compile-gated), HK-5 (`__builtin_expect` perf hint), HK-6 (--unsafe semantic + env-var block), HK-9 (kManagedMaps[] refactor — internal), HK-15 (design.md ParsedAttach wrapper inaccuracy).
- **Added** — HK-7 (FLEET_DEPLOYMENT.md installed), 4 new ctests (T_APPLY_EXITS_1_ON_MISSING_CONFIG, T_BYPASS_INTERACTIVE_PROMPT, T_BYPASS_REASON_TRUNCATE, T_EXPORTER_EXITS_6_ALL_IFACES_EACCES).
- **Internal / docs only** — HK-14 (§6.25 step 8 grep — see Decision D-3.4.5-4 below: SKIP), HK-15 (design.md correction).

##### HK-16 — exporter startup WARN exact format

Exact stderr-line wording (W1 mechanism per Q2):

```
xdpmf-exporter: WARN bpffs root <path> does not exist; will serve empty metrics
```

Where `<path>` is the resolved `cfg.bpffs_root` (the literal string the operator passed via `--bpffs-root`, OR the default `/sys/fs/bpf/xdpmacfilter` if no flag). Single line, newline-terminated, written to stderr. Fires EXACTLY ONCE per process lifetime, BEFORE the existing `xdpmf-exporter: listening on <bind>:<port>` startup line. No emission if the path exists at startup (even if it later disappears mid-run — that's per-scrape graceful-empty, not WARN-worthy at the W1 design level; PI-32 only mandates the startup-time WARN). Reviewer asserts via T_EXPORTER_NO_ATTACHED_IFACE EDIT (§6.39 sub-case in §5.30 TestStrategy below).

##### HK-17 — exporter exit-6 exact stderr line

Exact stderr-line wording (E1 trigger per Q3):

```
xdpmf-exporter: ERROR all <N> discovered interfaces failed permission-denied; check CAP_BPF and bpffs read mode (exit 6)
```

Where `<N>` is the integer `total_discovered`. Single line, newline-terminated, written to stderr. Fires ONCE immediately before `exit(6)` from `main()`. `<N>` is at minimum 1 (the trigger requires `total_discovered > 0`). No emission on the partial-EACCES-with-some-success path (existing WARN-per-iface handler still fires). No emission on empty `total_discovered` (exit 0 path). Reviewer asserts via T_EXPORTER_EXITS_6_ALL_IFACES_EACCES (§6.46 below).

##### CLI grammar — UNCHANGED

Verb set is `attach | detach | apply | bypass` plus `--help | --version`; no new subcommand, no new flag. Exporter grammar `--port | --bind | --bpffs-root | --help | --version` UNCHANGED.

##### `loader.hpp` PUBLIC-API — ZERO diff (PI-7-3.4.5-hpp, 5th cycle)

`AttachConfig` / `DetachConfig` / `attach()` / `detach()` / `LoaderError` enum: ALL UNCHANGED. HK-9 kManagedMaps[] lives in `loader.cpp` anon namespace ONLY. HK-3 compile-gate is `#ifdef` in `loader.cpp` ONLY. No public symbol added / removed / renamed. `git diff main -- src/lib/loader.hpp` MUST show ZERO output.

#### §5.30 FileList (brownfield DIFF — NEW / EDITED / UNCHANGED-BUT-AFFECTED)

##### NEW (created this slice — 4 test files, NO new source files)

| Path | Role (one line) | Language | LOC est |
|---|---|---|---|
| `tests/T_APPLY_EXITS_1_ON_MISSING_CONFIG.sh` | §6.43: HK-1 exit-1 fix verification; assert `apply -f /nonexistent --iface lo` exits 1 + stderr message preserved | bash | 50 |
| `tests/T_BYPASS_INTERACTIVE_PROMPT.sh` | §6.44: HK-4-adjacent / new-coverage; interactive y/N branch via `script -qc` (SKIP-77 if absent); positive (y → detach exit 0), negative (n/EOF → cancel exit 0) | bash | 90 |
| `tests/T_BYPASS_REASON_TRUNCATE.sh` | §6.45: HK-4 truncation contract; 256B (no trunc), 257B (trunc to 253+`…`), 300B mid-UTF-8 (rewind-safety) | bash | 90 |
| `tests/T_EXPORTER_EXITS_6_ALL_IFACES_EACCES.sh` | §6.46: HK-17 fix verification; create per-iface bpffs dirs with chmod 000; launch exporter; assert exit 6 within healthz timeout; SKIP-77 if EACCES reproduction not possible in test env | bash | 130 |

**No new source files this slice.** All HK changes are EDITs on existing files; the kManagedMaps[] refactor (HK-9) is a `loader.cpp`-internal consolidation. No new header, no new translation unit, no new binary.

##### EDITED (existing files touched this slice)

| Path | Role (one line) | What changes |
|---|---|---|
| `src/cli/main.cpp` | CLI entry-point + dispatch | **HK-1 (Q1 C1)**: ADD `catch (const xdpmf::CliError& e)` arm to the SECOND try block around `std::visit(...)`; in the catch body, `std::cerr << ...e.what()...; return kExitUsageErr;` mirroring the FIRST try block's existing arm. ~3 LOC. No other edits. |
| `src/cli/apply.cpp` | apply subcommand handler | **HK-1 (comment cleanup)**: DELETE OR REWRITE the stale `ApplyFileIoError` planning comment at `apply.cpp:14-29`. Reality is the missing-file case maps to `LoaderError::ConfigError` (= 9 at the loader; the HK-1 main.cpp catch translates the wrapped `CliError` to exit 1 — see Decision D-3.4.5-5 below). NO logic change, only the comment. ~5 LOC. |
| `src/cli/cli.cpp` | CLI usage_text + verb dispatch | **HK-2**: insert `7 kernel-unsupported,` in the exit-code list at `cli.cpp:104-106`. **HK-6**: fix `--unsafe` line wording + ADD `Environment variables:` sub-block listing `XDPMF_TRUST_MODEL`. ~10 LOC total. Verb dispatch table UNCHANGED. |
| `src/lib/loader.cpp` | Loader + apply orchestrator (per D-3.1-1) | **HK-3 compile-gate**: wrap ALL uses of `XDPMF_BPF_OBJECT_PATH` (constant at line 97; error messages at lines 762, 768, 775; consumer at lines 814-818) in `#ifdef XDPMF_ENABLE_BPF_OBJECT_OVERRIDE` / `#endif`. ~10 LOC of `#ifdef` lines added. **HK-9 kManagedMaps[] refactor**: ADD anon-namespace `kManagedMaps[]` constexpr table per DataStructures sub-section above (~12 LOC); REPLACE `open_skeleton_only`'s `pinned_maps[]` literal-array + loop with `for (const auto& entry : kManagedMaps) bpf_map__set_pin_path(...)` (saves ~10 LOC); REPLACE `internal::apply_request`'s `pin_specs[]` literal + loop (~10 LOC saved); REPLACE `internal::apply_request`'s `reuse_specs[]` literal + loop (~10 LOC saved). **NET delta**: ~30 LOC saved on the refactor + ~10 LOC added on the #ifdef = roughly -20 LOC. NO change to: `attach()` / `detach()` public bodies, §5.4 state-machine, §5.19 name-check, §5.22 tag-check + O_PATH path-discipline, §5.24 kernel-version probe, §5.26 trust_model parse+log, §5.27 CIDR populate step, §5.29 apply step 8.5 (rules+action_table populate + WARN), the link-pin P0a logic, any RAII wrapper, any error-translation path. Reviewer applies regional-diff check: allowed hunk scopes = {`open_skeleton_only` (loop refactor only), `internal::apply_request` (pin_specs + reuse_specs sub-blocks only, NOT the step 8 / 8.5 sub-blocks which UNCHANGED), anon-namespace (kManagedMaps[] table + the `#ifdef XDPMF_ENABLE_BPF_OBJECT_OVERRIDE` blocks at the listed line ranges)}. Any hunk outside this set = `[INVARIANT-VIOLATED]` (PI-7-3.4.5-cpp). |
| `src/cli/bypass.cpp` | bypass subcommand (§5.29 NEW file) | **HK-4 escape**: extend `truncate_reason()` post-truncation to apply `\` → `\\`, `"` → `\"`, `\n` → `\\n`, `\r` → `\\r`, `\0` → `\\0` (mirror `prom_format::escape_label_value`); UTF-8 rewind on mid-codepoint truncation. **HK-4 sudo identity**: extend audit-log line per HK-4 Interfaces sub-section above (add `euid=` and `sudo_user="..."` fields). ~25 LOC. NO change to the tty-check, prompt, `loader::detach()` invocation, exit-code semantics. |
| `src/bpf/mac_filter.bpf.c` | XDP BPF program | **HK-5**: ADD `#define unlikely(x) __builtin_expect(!!(x), 0)` near top (after existing includes). WRAP 6 verifier null-checks at lines 188, 204, 211, 229, 236, 254. ~8 LOC. **NO** change to `mac_filter_prog` SEC, .maps block, any map declaration. JIT semantics byte-equivalent (PI-28 holds — branch hints, not branch logic). |
| `src/exporter/main.cpp` | exporter entry-point (§5.29 NEW file) | **HK-6**: ADD `Environment variables:` sub-block to print_usage. **HK-17 exit-6**: after `http::run()` returns (the run() return code is now 6 when the per-scrape trigger fired; see http.cpp EDITED row below for the trigger-detection mechanism per §5.30 EDIT-2), emit the HK-17 stderr line with `<N>` from `http::last_exit_six_total()` getter, then `return 6` from main(). ~20 LOC total. NO change to signal handling, HTTP binding, default flag values. |
| `src/exporter/http.cpp` | exporter HTTP/1.0 server (§5.29 NEW file) | **HK-17 trigger hook** (per §5.30 EDIT-2, Phase B dialog with mint-dev-impl, 2026-05-25): add anon-namespace globals `static volatile std::sig_atomic_t g_exit_six = 0` + `static std::size_t g_exit_six_total = 0`; in `handle_connection`'s `/metrics` arm, after the existing `read_all_attached(bpffs_root, /* out */ acc)` call, evaluate the Q3 E1 trigger (`acc.total_discovered > 0 && acc.eacces_failures == acc.total_discovered && acc.successes == 0`) — if it fires, set `g_exit_six_total = acc.total_discovered; g_exit_six = 1;` AFTER writing the (last-ever) /metrics response body. Extend the accept loop's while condition from `while (g_stop == 0)` to `while (g_stop == 0 && g_exit_six == 0)`. Change `run()` return type semantic: returns 6 if `g_exit_six` was set during the loop; returns 0 on clean SIGINT/SIGTERM (existing semantic). Add public `[[nodiscard]] std::size_t last_exit_six_total() noexcept;` getter that returns `g_exit_six_total` (or 0 if HK-17 didn't fire). ~10-15 LOC delta; pure additive — NO change to bind/listen/HTTP framing, NO change to `/healthz` or 404 arms, NO change to per-conn budget / timeout / SIGTERM observation cadence. |
| `src/exporter/http.hpp` | exporter HTTP/1.0 server header (§5.29 NEW file) | **HK-17 EDIT-2**: ADD `[[nodiscard]] std::size_t last_exit_six_total() noexcept;` declaration alongside existing `int run(const HttpConfig& cfg)`. Header is INTERNAL (not in `loader.hpp` PI-7 fence); the signature addition is acceptable. ~2 LOC. |
| `src/exporter/stats_reader.cpp` | exporter stats reader (§5.29 NEW file) | **HK-16 startup WARN**: in `read_all_attached()` first-call OR via a separate startup-helper function called from `main()` BEFORE first `http::run()` — one-shot `std::filesystem::exists(bpffs_root)` check; emit HK-16 WARN line per Interfaces if false. **HK-17 accounting**: populate `DiscoveryAccounting` struct per Q3 E1; thread it back to main() (via out-param OR pair-return — impl picks per DataStructures sub-section). ~25 LOC total. NO change to PERCPU-sum logic, RO discipline (PI-31 holds), value-byte-equivalence (PI-29 holds). |
| `CMakeLists.txt` | top-level build | **HK-3**: ADD `option(XDPMF_ENABLE_BPF_OBJECT_OVERRIDE "..." OFF)` + `target_compile_definitions(xdpmf_internal PRIVATE $<$<BOOL:${XDPMF_ENABLE_BPF_OBJECT_OVERRIDE}>:XDPMF_ENABLE_BPF_OBJECT_OVERRIDE>)`. **HK-7**: inside `XDPMF_INSTALL_SYSTEMD_UNIT` block, ADD `install(FILES docs/FLEET_DEPLOYMENT.md DESTINATION ${CMAKE_INSTALL_PREFIX}/share/doc/xdpmacfilter/)`. **HK-8**: bump `project(... VERSION 0.6.0 ...)` → `... VERSION 0.6.1 ...`. ~10 LOC total. NO other CMake change. |
| `tests/CMakeLists.txt` | ctest registration | (a) ADD 4 new `add_test(...)` entries (§6.43..§6.46) with appropriate RESOURCE_LOCK declarations matching §5.29's `xdp_fixture` / `exporter_port_9417` patterns where applicable. (b) **HK-3 propagation**: set `XDPMF_ENABLE_BPF_OBJECT_OVERRIDE=ON` for the test build (impl picks the cleanest mechanism — `set(... CACHE BOOL "" FORCE)` before `add_subdirectory` OR per-test `target_compile_definitions` on the test binary — note tests are shell scripts invoking the loader binary, so the option must be ON at the loader's compile time; impl ensures this by setting the option ON in the top-level CMakeLists when `BUILD_TESTING=ON`, OR via `tests/CMakeLists.txt` setting a cache var BEFORE the top-level option line evaluates). (c) NO modification of the 42 existing add_test entries (PI-34 strict superset extension). |
| `CHANGELOG.md` | version history | NEW `## [0.6.1] - 2026-05-NN` section per Keep-a-Changelog format; sub-groups per HK-8 Interfaces sub-section above. Build-pace table gains a row for MVP-3.4.5. |
| `tests/T_LINK_PERSIST_ACROSS_LOADER_EXIT.sh` | persist-across-exit ctest (existing) | **HK-10**: REPLACE `sudo -n pkill -9 -f xdpmacfilter` at `:46, :110` with PID-tracked kill OR `sudo -n pkill -9 -f "xdpmacfilter.*${IFACE_A}"`. Tester picks (PID-tracked preferred — safer; argv-match acceptable if PID capture is awkward in the test fixture flow). ~5 LOC. |
| `tests/lib/common.sh` | test helpers | **HK-10 (conditional)**: if Tester picked PID-tracked for T_LINK_PERSIST, MAY add a `kill_loader_keep_link_by_pid()` helper. If Tester picked argv-match, common.sh's existing `kill_loader_keep_link()` at `:320-323` is ALREADY iface-scoped — NO change. Tester's discretion. ~5 LOC if added. |
| `tests/T_SYSTEMD_RESTART_ON_FAILURE.sh` | systemd restart-band ctest (existing) | **HK-11 (Q5 S1)**: ADD internal 2-attempt retry. After first attempt fails, run `systemctl reset-failed xdpmacfilter@${IFACE}.service`, `sleep 1`, clear any pin-dir residue, re-run the probe sequence. PASS message: `PASS: T_SYSTEMD_RESTART_ON_FAILURE (attempt N/2)`. ~20 LOC. Strict band [4,5] assertion UNCHANGED (the StartLimit-placement-footgun guard preserves). |
| `tests/T_APPLY_ATOMIC_SWAP_NO_DROP.sh` | atomic-swap stat-preservation ctest (existing) | **HK-12**: REWRITE the stale NOTE comment that claims stats reset on apply; reality is D-3.1-4 preserves via `bpf_map__reuse_fd`. New NOTE: `# NOTE: stats counters PRESERVED across apply per §5.26 D-3.1-4 reuse_fd loop`. ~3 LOC (delete + rewrite). NO test logic change. |
| `tests/T_ATTACH_TAG_MISMATCH.sh` | tag-mismatch alien-refusal ctest (existing) | **HK-13**: ADD orphan map-pin cleanup in trap. The fixture's `bpftool prog load` runs without `pinmaps`, leaving orphan pins at bpffs root after the test; add explicit `rm -f /sys/fs/bpf/<orphan-map-name>` (or `bpftool map show pinned ... | ... bpftool unpin`) in the cleanup trap. ~5 LOC. NO test-body logic change. |
| `tests/T_EXPORTER_NO_ATTACHED_IFACE.sh` | §6.39 ctest (existing — §5.29 NEW) | **HK-16**: ADD assertion that stderr (captured via temp-redirect at exporter launch) contains the WARN substring `WARN bpffs root .* does not exist; will serve empty metrics` when the test sets `--bpffs-root` to a nonexistent path. ~5 LOC. NO other change. |
| `tests/T_BYPASS_CMD_DETACHES.sh` | §6.40 ctest (existing — §5.29 NEW) | **HK-4-forced permissive regex** (per §5.30 EDIT-3, Phase B dialog 2026-05-25): RELAX the audit-log regex from `^xdpmacfilter: BYPASS activated on veth-test0 by uid=[0-9]+ reason="T_BYPASS_test"$` to a permissive `^xdpmacfilter: BYPASS activated on veth-test0 by uid=[0-9]+ .*reason="T_BYPASS_test"$` so the test continues to pass against the new HK-4 audit line (which inserts `euid=` + `sudo_user=` between `uid=` and `reason=`). Strict HK-4 field-shape assertions live in §6.44 (T_BYPASS_INTERACTIVE_PROMPT) per D-3.4.5-8 option (b). ~2 LOC (single-line regex swap). NO test logic change; the observable contract (exit 0 + audit-line presence + detach effect) is byte-equivalent. |
| `tests/T_EXPORTER_METRICS_FORMAT.sh` | §6.37 ctest (existing — §5.29 NEW) | **HK-8-forced version-literal bump** (per §5.30 EDIT-3, Phase B dialog 2026-05-25): the test has hardcoded `xdpmf-exporter 0.6.0` literal-string assertions at lines :21 + :99 (version check sub-cases); update both to `xdpmf-exporter 0.6.1` to match PI-8-3.4.5. ~2 LOC (two literal swaps). NO test logic change; the assertion is the literal-bump's natural verification surface. |
| `mint/design.md` | design (THIS file) | **HK-15**: ADD an inline correction note next to §5.26 prose that claims `ParsedAttach`/`ParsedDetach`/`ParsedApply` wrappers exist — they never existed; reality is `ParsedCommand = std::variant<AttachConfig, DetachConfig, ApplyConfig, BypassConfig>` directly. Insert a `[CORRECTION §5.30 HK-15: see this slice]` marker at the misleading prose location in §5.26 + an authoritative one-paragraph correction here in §5.30 (the inline marker is the audit trail; the §5.30 paragraph is the canonical statement). Architect handles this Edit during Phase A. ~10 LOC. |

##### UNCHANGED-BUT-AFFECTED (zero git-diff; behaviour must hold)

| Path | Why it matters |
|---|---|
| `src/lib/loader.hpp` | **PI-7-3.4.5-hpp — 5th consecutive ZERO-diff cycle** (MVP-3.1 +1; MVP-3.2/3.3/3.4/3.4.5 = 0). `git diff main -- src/lib/loader.hpp` MUST show ZERO output. Any diff = `[INVARIANT-VIOLATED]`. The HK-9 kManagedMaps[] table lives in `loader.cpp` anon namespace; no public symbol added/removed/renamed. HK-3 `#ifdef` is `loader.cpp`-internal. |
| `src/lib/loader.cpp` outside the HK-3 + HK-9 hunks | **PI-7-3.4.5-cpp** scope-fence below. Diff lines confined to: (a) HK-3 `#ifdef XDPMF_ENABLE_BPF_OBJECT_OVERRIDE` blocks wrapping the constant + 3 error-message strings + 1 consumer site; (b) HK-9 anon-namespace `kManagedMaps[]` table addition; (c) HK-9 `open_skeleton_only`'s `pinned_maps[]` literal replaced with `for-each-kManagedMaps` loop (loop body byte-equivalent semantic: walk all entries, call `bpf_map__set_pin_path(..., nullptr)`); (d) HK-9 `internal::apply_request`'s `pin_specs[]` literal replaced with the `for-each-kManagedMaps` loop (skip `legacy_alias`); (e) HK-9 `internal::apply_request`'s `reuse_specs[]` literal replaced with the `for-each-kManagedMaps` loop (skip `legacy_alias`). ZERO diff in: `attach()` / `detach()` public bodies, §5.4 state-machine, §5.19 name-check, §5.22 tag-check + O_PATH path-discipline, §5.24 kernel-version probe, §5.26 trust_model parse+log, §5.27 CIDR populate step, §5.29 apply step 8.5 (rules+action_table populate + WARN), the link-pin P0a logic, any RAII wrapper, any error-translation path, the special-pin path at line 1739 for the legacy `allowlist` alias. Reviewer applies regional-diff check per the listed allowed hunks. |
| `src/lib/loader.hpp` LoaderError enum | UNCHANGED. No new error code; HK-17 surfaces existing exit 6 via direct `exit(6)` from `xdpmf-exporter::main()`, NOT via `LoaderError`. The exporter does NOT throw `LoaderError`. |
| `src/common/mac_filter.h` | UNCHANGED. No new constant, no new struct, no new enum (HK-9 is loader-internal; the kManagedMaps[] table references existing skel field names that DERIVE from the existing map declarations in `mac_filter.bpf.c`). |
| `src/bpf/mac_filter.bpf.c` outside the HK-5 hunk | UNCHANGED `.maps` block (no new map declaration). UNCHANGED `mac_filter_prog` function body LOGIC (HK-5 only adds the `unlikely(x)` macro wrap on 6 leaf null-checks; the branch taken is identical, only the JIT hint differs — PI-28 byte-equivalent semantic holds). |
| `src/lib/{config,yaml_subset,cidr}.{cpp,hpp}` | UNCHANGED. No schema change, no CIDR change. |
| `src/lib/raii.hpp` | UNCHANGED. |
| `src/cli/{attach,detach}.{cpp,hpp}` | UNCHANGED. HK-1 only touches `main.cpp` catch arm + `apply.cpp` comment. |
| `src/cli/apply.hpp` | UNCHANGED. HK-1 is comment-only on `apply.cpp`. |
| `src/cli/cli.hpp` | UNCHANGED. HK-2 + HK-6 only touch usage_text in `cli.cpp`. |
| `src/cli/bypass.hpp` | UNCHANGED. HK-4 is internal to `bypass.cpp` (`truncate_reason()` + audit-log function bodies). |
| `src/exporter/prom_format.{cpp,hpp}` | UNCHANGED. HK-16 is localized to `main.cpp` + `stats_reader.cpp`. **Per §5.30 EDIT-2** (Phase B dialog with mint-dev-impl, 2026-05-25): `http.cpp` + `http.hpp` MOVED from this UNCHANGED row to the EDITED table above — HK-17's per-scrape trigger semantic (D-3.4.5-2) is incompatible with `http.cpp` UNCHANGED because the accept loop owns main's execution context while scrapes fire; original UNCHANGED claim was a design slip. The http.cpp scope-fence for HK-17 is enumerated in the EDITED row: anon-namespace globals + handler check + while-loop condition + getter — no change to bind/listen/HTTP framing. |
| `src/exporter/stats_reader.hpp` | EXPECTED UNCHANGED (impl ideally adds `DiscoveryAccounting` as an OUT-parameter to `read_all_attached`, which is a signature change to the INTERNAL header — acceptable, NOT in PI-7 fence). If impl prefers pair-return, the header signature changes; either way, since the header is not in `loader.hpp` and not shipped public, this is impl-discretion per Phase B. |
| `systemd/xdpmacfilter@.service`, `systemd/xdpmf-exporter.service` | UNCHANGED. HK-7 only installs the docs FILE; no unit change. |
| Existing 42 ctest BODIES except the 5 explicitly EDITED above | Bodies UNCHANGED. Reviewer asserts `git diff --stat tests/T_*.sh` shows changes confined to: T_LINK_PERSIST_ACROSS_LOADER_EXIT (HK-10), T_SYSTEMD_RESTART_ON_FAILURE (HK-11), T_APPLY_ATOMIC_SWAP_NO_DROP (HK-12), T_ATTACH_TAG_MISMATCH (HK-13), T_EXPORTER_NO_ATTACHED_IFACE (HK-16); plus 4 NEW files (T_APPLY_EXITS_1_ON_MISSING_CONFIG, T_BYPASS_INTERACTIVE_PROMPT, T_BYPASS_REASON_TRUNCATE, T_EXPORTER_EXITS_6_ALL_IFACES_EACCES). All OTHER ctest bodies byte-equivalent. PI-34 strict superset preserved with this scoped 5-file EDIT carve-out. |
| `tests/lib/read_stats.py` | UNCHANGED. |
| `tests/fixtures/*` | UNCHANGED. HK-13 cleanup is runtime trap-time work, NOT a fixture change. The new ctests use existing fixtures OR construct their inputs in-line via the test body. T_BYPASS_REASON_TRUNCATE builds its `--reason` strings via `printf` / `head -c` / `python -c` (test body inline) — NO new fixture file. |
| `ansible/xdpmacfilter-deploy.yml`, `ansible/templates/xdpfilter-config.yaml.j2` | UNCHANGED. Ansible Jinja `action: pass` fix + `xdpfilter_trust_model` template task are in the EXCLUDED doc bucket (separate manual pass). |
| `docs/FLEET_DEPLOYMENT.md`, `README.md`, `HANDOFF.md`, `docs/CONFIG_SCHEMA.md` (does-not-exist), all README sections | UNCHANGED. ALL 13 doc-bucket items D1..D13 are in the EXCLUDED separate manual pass. |
| `cmake/BpfBuild.cmake` | UNCHANGED. |
| `include/version.h.in`, `tests/lib/pins.sh.in` | UNCHANGED (templates from §5.25 still authoritative; CMake reads new `VERSION 0.6.1` into `version.h.in`). Both binaries report `0.6.1` (PI-33 extends). |
| All §5.4 / §5.19 / §5.22 / §5.24 / §5.26 / §5.27 / §5.29 trust+identity gates | UNCHANGED. HK-3 compile-gate hides a test-only env var; HK-9 is structural-only refactor; HK-4 hardens audit-log without changing detach semantics; HK-5 is JIT-hint-only; HK-1/2/6 are CLI surface. Reviewer re-runs §6.9, §6.14, §6.15, §6.20, §6.26 sub-cases — all still pass. |

#### §5.30 Decisions (additional, with rationale)

##### D-3.4.5-1 — HK-16 startup WARN fires from `stats_reader.cpp` (NOT `main.cpp`) — because

The `bpffs_root` validation is conceptually a stats-reader concern (the stats reader is the consumer that needs the path); putting the check in `stats_reader.cpp` keeps the cohesion. `main.cpp` invokes a small `stats_reader::validate_bpffs_root_or_warn(cfg.bpffs_root)` helper at startup BEFORE `http::run()`. The helper returns void (no error propagation — PI-32 is "WARN and continue"). Impl MAY put it in `main.cpp` instead if preferred (the function is small enough); architect's stronger preference is `stats_reader.cpp` for cohesion + future-extensibility (if we add more bpffs-path checks, they all live in one place). Phase B SendMessage if impl wants to invert the call.

##### D-3.4.5-2 — HK-17 exit-6 fires from `main.cpp` AFTER discovery in `stats_reader.cpp` — because

The decision to exit cannot live inside `stats_reader.cpp` (the reader is a library-style component; `exit(6)` from a library is a code smell). Mechanism:

1. `stats_reader::read_all_attached(bpffs_root, /* out */ DiscoveryAccounting& acc)` populates `acc.{total_discovered, eacces_failures, other_failures, successes}`.
2. The caller (either `main.cpp` directly OR the HTTP-handler glue) reads `acc` after EVERY scrape.
3. If trigger holds (`total_discovered > 0 && eacces_failures == total_discovered && successes == 0`), the caller emits the HK-17 stderr line and calls `std::exit(6)` from main thread.
4. The check fires on EVERY scrape, NOT just the first scrape — if the system transitions from "all-EACCES" to "some-success" between scrapes (e.g. operator fixes bpffs perms), the exporter does NOT die on that gap; if it transitions the other way, it dies on the first all-EACCES scrape after the transition. This is "exit on next scrape that meets condition" semantic.

**Implementation mechanism (per §5.30 EDIT-2, Phase B dialog with mint-dev-impl, 2026-05-25)**: the per-scrape trigger detection lives inside `http.cpp`'s `handle_connection` `/metrics` arm. After the handler invokes `read_all_attached(bpffs_root, /* out */ acc)` and writes the response body to the client, it evaluates the Q3 E1 trigger; if it fires, the handler sets two anon-namespace globals (`g_exit_six_total = acc.total_discovered; g_exit_six = 1;`). The accept loop's while condition (`while (g_stop == 0 && g_exit_six == 0)`) observes the flag and exits the loop on the next iteration; `run()` returns 6. `main.cpp` post-`http::run()` reads `http::last_exit_six_total()` getter for `<N>`, emits the HK-17 stderr line, returns 6.

Rationale for the http.cpp hook (vs. a "main polls a file-static in stats_reader.cpp" alternative): main is blocked inside `http::run()`'s accept loop for the entire long-running daemon's lifetime; without a callback hook OR a flag-and-poll mechanism rooted IN the accept loop, main can't observe the trigger between scrapes. The flag-set-from-handler + while-loop-condition pattern is the minimal-diff realization (~10-15 LOC delta in http.cpp; pure additive — see http.cpp EDITED row). The original §5.30 draft marked http.cpp as UNCHANGED-BUT-AFFECTED with the intent that HK-17 lives in main.cpp + stats_reader.cpp; that was a design slip — there is no realization of per-scrape semantic that leaves http.cpp byte-equivalent. §5.30 EDIT-2 corrects by moving http.cpp + http.hpp from UNCHANGED to EDITED with the scope-fence above.

**Pre-flight discovery alternative** (architect notes for completeness, NOT recommended): a pre-flight discovery pass at startup could exit 6 if the FIRST discovery hits the trigger. Drawback: if all ifaces transiently EACCES at startup (e.g. systemd unit ordering issue with bpffs mount) but recover quickly, the exporter dies in a unit-restart-storm. Per-scrape check is more forgiving for transient startup races. Q3 E1 default fires per-scrape; pre-flight is rejected.

##### D-3.4.5-3 — HK-9 kManagedMaps[] member-pointer (T1) over name-lookup (T2) — because

Member-pointer is compile-time-checked. If MVP-3.5+ renames `mac_filter.bpf.c`'s `rules` map to `rule_table` (say), the kManagedMaps[] table entry `&mac_filter_bpf::maps::rules` fails to compile — the build fails loudly, NOT silently at runtime. Name-lookup (T2) defers all rename-mismatches to runtime (`bpf_object__find_map_by_name(..., "rules")` returns NULL → cryptic libbpf error at pin/reuse time). The CI catches T2 errors via ctest, but T1 catches them at build time which is cheaper + faster.

T3 (lambda dispatch) is over-engineering for a 10-entry static table; rejected outright.

##### D-3.4.5-4 — HK-14 §6.25 step 8 grep stays UNASSERTED in this slice — because

The brief flagged HK-14 as architect-discretion ("architect MAY confirm whether design's 'explicit impl-shape flexibility' comment means this should remain unasserted"). Re-reading §5.26 / §6.25 step 8 prose: the design explicitly says the `replacing existing program` stderr is an impl-shape detail, NOT a contract. Asserting on it would over-constrain impl; if impl rewords the stderr line in a future cycle (legitimate refactor), the test would false-fail. Default: HK-14 stays SKIPPED (not assertion-added). Reviewer accepts; if a future cycle DOES want to lock the stderr line, it gets explicit PI-* status then.

##### D-3.4.5-5 — HK-1 exit-1 path: `LoaderError::ConfigError` from missing-file translates to exit 1 (NOT exit 9) — because

This requires careful reading. `apply_internal::load_config_file()` throws `LoaderError::ConfigError` (= 9 per §4.1) on missing file. The QUESTION is: should `apply -f /nonexistent` exit 1 (CLI usage error: "you gave me a bad arg") OR exit 9 (config error: "the YAML can't be loaded")?

Per the brief framing (HK-1 = "exit-code triple drift fix"; T_APPLY_EXITS_1_ON_MISSING_CONFIG asserts exit 1): the expected exit code on missing file is **1** (CLI usage error). Rationale: a missing-file is a flag-pointed-at-bad-path error, semantically equivalent to "bad MAC" (= 1) or "missing required arg" (= 1) — the operator gave the CLI an invalid argument. ConfigError (= 9) should fire on YAML parse failure or schema validation failure of a file that EXISTS but is malformed. The missing-file case is upstream of YAML/schema and should NOT bundle with ConfigError.

**Mechanism**: `apply_main` catches `LoaderError::ConfigError` raised specifically by `load_config_file`'s `open()` failure path (impl distinguishes via errno OR by inspecting the exception's what() string OR — cleanest — by `load_config_file` throwing a distinct error type for missing-file vs parse-fail). Default impl: `apply_main` wraps the open-failure case in `xdpmf::CliError`, which the HK-1 main.cpp catch arm translates to exit 1; YAML parse / schema validation failures continue to throw `LoaderError::ConfigError` (= 9) and exit 9 via the existing path. Impl picks the cleanest mechanism; default is "open() ENOENT → CliError → exit 1; parse/schema → ConfigError → exit 9".

**Caveat**: if impl finds this exit-code split semantically awkward (e.g. "all config-layer failures should exit 9 uniformly"), peer-DM architect during Phase B. Architect's strong preference is the split per brief framing. The test T_APPLY_EXITS_1_ON_MISSING_CONFIG locks in the split.

##### D-3.4.5-6 — HK-3 compile-gate covers ALL `XDPMF_BPF_OBJECT_PATH` references — because

The brief lists "constant at line 97, error messages at lines 762/768/775, consumer at lines 814-818" — impl wraps ALL these in the `#ifdef` block. Specifically: the string constant declaration, the literal occurrences in any `xdpmacfilter: error: ...XDPMF_BPF_OBJECT_PATH...` error messages, AND the `getenv("XDPMF_BPF_OBJECT_PATH")` call site PLUS the conditional branch that consumes its return value. Reviewer asserts `nm $(which xdpmacfilter) | grep -c XDPMF_BPF_OBJECT_PATH` returns 0 in a release build (string literal absent from binary). If ANY reference leaks (e.g. an error message in `apply_internal.cpp` that mentions the var name), that's [INVARIANT-VIOLATED].

##### D-3.4.5-7 — HK-9 ZERO functional change to byte-shape of pinned maps + reuse semantics — because

The 42-test baseline IS the validation. If HK-9 byte-equivalence is broken (e.g. a typo in the table swaps two member-pointers), at least one of the 42 existing ctests will fail (typically T_ATTACH_TAG_MISMATCH or T_IDEMPOTENT_RELOAD or T_APPLY_ATOMIC_SWAP_NO_DROP — they all exercise the pin/reuse paths). Reviewer treats "42-test baseline still green post-HK-9" as the load-bearing validation; NO new ctest for HK-9 itself (the refactor is mechanical + the existing tests provide the safety net).

##### D-3.4.5-8 — HK-4 audit-log MUST hold `uid=` AND `euid=` AND `sudo_user=` as STRUCTURAL fields — because

Operators grep audit logs for these fields (the §5.29 line already had `uid=`; HK-4 extends with `euid=` and `sudo_user=`). Structural-field consistency means: the order is FIXED (uid → euid → sudo_user → reason), the format is FIXED (`<key>=<value>` for numeric; `<key>="<value>"` for string), the `<none>` sentinel for null `SUDO_USER` is FIXED (NOT empty quotes, NOT the literal string `null`). T_BYPASS_CMD_DETACHES (§6.40) is EXTENDED at the regex level to verify the new fields appear; tester picks whether to extend §6.40's regex OR keep §6.40 byte-equivalent and add the field assertions to a sub-case of T_BYPASS_REASON_TRUNCATE. Architect preference: extend §6.40's regex (one test, one regex, less duplication).

**T_BYPASS_CMD_DETACHES extension (per §5.30 EDIT-3, Phase B dialog with team-lead/tester, 2026-05-25)**: §6.40's existing regex `^xdpmacfilter: BYPASS activated on veth-test0 by uid=[0-9]+ reason="T_BYPASS_test"$` is broken by HK-4 audit-log extension (the line now contains `euid=` + `sudo_user=` fields between `uid=` and `reason=`). Option (b) — "no NEW field-DETAIL assertions in §6.40" — is the chosen disposition (architect preference confirmed), but option (b) REQUIRES §6.40's regex to be relaxed to a permissive shape (e.g. `^xdpmacfilter: BYPASS activated on veth-test0 by uid=[0-9]+ .*reason="T_BYPASS_test"$`) so that the existing test continues to pass against the new audit-log line WITHOUT asserting on the new fields. The strict HK-4 field-shape assertions (euid present + sudo_user="<value or <none>>" format + ordering) live in T_BYPASS_INTERACTIVE_PROMPT positive-case (§6.44) and optionally as a sub-case of T_BYPASS_REASON_TRUNCATE (§6.45). The §6.40 permissive-regex EDIT is therefore REQUIRED (not optional) per option (b) — it is the literal embodiment of "extend regex to accept both shapes, do not assert new fields here". Counted as the 6th EDITED ctest body in PI-34-3.4.5 below.

#### §5.30 TestStrategy entries

##### §6.43 T_APPLY_EXITS_1_ON_MISSING_CONFIG — HK-1 fix: missing config file exits 1, not 9

**Trigger**: `${LOADER_BIN} apply -f /nonexistent/path/config.yaml --iface lo` (with `lo` always available; alternative `--iface veth-test0` if the fixture is set up).

**Observable outcome**: exit code 1 (`kExitUsageErr`); stderr contains the existing `xdpmacfilter: config error:` prefix (NOT a NEW stderr line — the existing message format is preserved per HK-1 Interfaces above); the process does NOT touch the kernel (no `bpftool prog show id` change in the system; the loader exits BEFORE `bpf_prog_load`).

**Assertion mechanism**: `[[ $rc -eq 1 ]]`; `grep -qE '^xdpmacfilter: config error:' /tmp/stderr.out`; verify NO new BPF prog was loaded (capture `bpftool prog show` count before + after; expect equal). Negation control: re-run with a VALID minimal config file (existing fixture) and assert it does NOT exit 1 (proves the test would catch a regression where ALL apply invocations exit 1).

**SKIP conditions**: none.

**Cleanup**: none (no kernel state mutated).

**Maps to**: HK-1 (exit-code triple drift fix); D-3.4.5-5 (exit-1-vs-9 split rationale). NO new PI required (PI-9 / PI-34 cover help-text + ctest-baseline; HK-1's fix is a bug-fix realizing existing §4.1 exit-code 1 contract).

##### §6.44 T_BYPASS_INTERACTIVE_PROMPT — interactive y/N branch via `script -qc`

**Trigger**: setup veth + attach `xdpmacfilter` per existing T_BYPASS_CMD_DETACHES fixture pattern. Use `script -qc 'echo y | xdpmacfilter bypass --iface veth-test0' /tmp/log.out` (or equivalent `expect` if `script` unavailable; both provide a pseudo-tty) for positive branch. Use `script -qc 'echo n | xdpmacfilter bypass --iface veth-test0' /tmp/log.out` for negative branch. Use `script -qc '< /dev/null xdpmacfilter bypass --iface veth-test0' /tmp/log.out` for EOF branch.

**Observable outcome**:
- **Positive (`y`)**: exit code 0; XDP detached (`bpftool net show dev veth-test0` shows NO prog); audit-log line per §5.29 + HK-4 (with `sudo_user=...` per HK-4) appears in stderr.
- **Negative (`n`)**: exit code 0; XDP STILL attached; stderr contains `xdpmacfilter: bypass cancelled by operator`.
- **EOF / empty input**: exit code 0; XDP STILL attached; stderr contains `xdpmacfilter: bypass cancelled by operator` (EOF treated as non-`y` per §5.29 grammar).

**Assertion mechanism**: per branch, `[[ $rc -eq 0 ]]`; `bpftool net show dev veth-test0` parsed for `prog id` presence/absence; `grep -qE` on the expected stderr line.

**SKIP conditions**: neither `script` (util-linux) NOR `expect` available → SKIP-77 with rationale `T_BYPASS_INTERACTIVE_PROMPT: needs script or expect for pty; neither in PATH`. DEV/CI VMs should have `script`; SKIP is the legitimate escape hatch.

**Cleanup**: explicit re-attach if detached + re-detach via existing helper; `cleanup_veth`.

**Maps to**: HK-4-adjacent (covers the interactive prompt branch that §5.29's T_BYPASS_CMD_DETACHES does NOT exercise — it uses `--unsafe` to skip the prompt). PI-30 (bypass = detach-alias + audit; the prompt is part of the audit-safety contract for interactive context).

##### §6.45 T_BYPASS_REASON_TRUNCATE — HK-4 truncation contract verification

**Trigger**: setup veth + attach per fixture. Three sub-cases:
1. **256 bytes (no truncation)**: build a 256-byte ASCII reason string via `head -c 256 /dev/urandom | base64 | head -c 256` OR `python -c 'print("a"*256)'`; `xdpmacfilter bypass --iface veth-test0 --unsafe --reason "${REASON}"` capturing stderr; assert the stderr `reason="..."` field contains the FULL 256 bytes (no `…` ellipsis suffix). Wait — re-read HK-4: truncation kicks in at >253 bytes (leaving room for `…`). So 256 bytes WILL trigger truncation. Adjust to 253 bytes (no truncation) and 254 bytes (truncation). The brief said "256 (no truncation), 257 (truncated to 253+`…`)" — that contradicts HK-4 byte budget. Architect amends: case 1 is 253 bytes (boundary), case 2 is 254 bytes (first truncation), case 3 is 300 bytes ending mid-UTF-8.
2. **254 bytes (first truncation)**: 254-byte ASCII reason → stderr `reason="..."` field is 253 bytes + `…` (3 bytes UTF-8) = 256 bytes total inside the quotes.
3. **300 bytes ending mid 4-byte UTF-8 codepoint**: build a 300-byte string where byte 253 falls mid a 4-byte UTF-8 codepoint (impl-friendly construction: `python -c 'print("a"*251 + chr(0x1F600))'` produces 251 ASCII + 4-byte 😀 emoji = 255 bytes; pad to 300 with more codepoints). Assert truncation rewinds to the codepoint boundary BEFORE byte 253 (NOT cutting mid-codepoint) + appends `…`. Reviewer verifies the truncated bytes form valid UTF-8 (`python -c 'open("/tmp/stderr").read().encode("utf-8").decode("utf-8")'` succeeds without raising).

**Observable outcome (each sub-case)**: exit code 0 (bypass succeeds); audit-log line per HK-4 format; the `reason="..."` content matches the truncation spec exactly. NO escape-side-effect (none of the test inputs contain `\`, `"`, `\n`, `\r`, `\0` — those are HK-4 escape concerns, covered implicitly by §6.44 + a sub-case if Tester wishes to add one).

**Assertion mechanism**: per sub-case, capture stderr to `/tmp/stderr.out`, extract `reason="..."` via `grep -oE 'reason="[^"]*"'`, compute byte length via `wc -c`, compare against expected. UTF-8 validity check via `python3 -c 'open(...).read()'` (assert no UnicodeDecodeError).

**SKIP conditions**: `python3` absent → use `iconv -f UTF-8 -t UTF-8` (POSIX) as fallback; if neither → SKIP-77 with rationale `needs python3 or iconv for UTF-8 validity check`.

**Cleanup**: `cleanup_veth`; explicit re-attach + detach between sub-cases (or re-attach once + detach per case via the bypass primitive).

**Maps to**: HK-4 (truncation + escape contract); D-3.4.5-8 (HK-4 audit-log structural fields).

##### §6.46 T_EXPORTER_EXITS_6_ALL_IFACES_EACCES — HK-17 fix verification

**Trigger**: setup ≥2 veth interfaces + `xdpmacfilter attach` per existing fixture. After attach + pin creation, `chmod 000` ALL `${PIN_DIR}/<iface>/stats` files (or chmod 000 the per-iface dirs — impl picks the level that REPRODUCIBLY surfaces EACCES on `bpf_obj_get`; per-file is more surgical, per-dir is more sledgehammer). Verify EACCES is reproducible: `sudo -u nobody bpftool map show pinned ${PIN_DIR}/veth-test0/stats` MUST fail with EACCES (or run the test under a non-root user; SKIP-77 if neither approach works in the test env — many CI runners can't drop privileges cleanly). Launch `xdpmf-exporter --port ${EPORT} --bpffs-root ${PIN_DIR}` (background, capture PID + stderr).

**Observable outcome**: within `healthz_timeout` seconds (default 10s — give the first scrape time to fire OR explicitly hit `/metrics` once to force a scrape), the exporter process exits with code 6; stderr contains the HK-17 line matching ERE `^xdpmf-exporter: ERROR all [0-9]+ discovered interfaces failed permission-denied; check CAP_BPF and bpffs read mode \(exit 6\)$`; the `<N>` integer in the line equals the number of attached interfaces.

**Assertion mechanism**: `wait $EPID; rc=$?; [[ $rc -eq 6 ]]`; `grep -qE` on the ERE; extract `<N>` and compare against `ls ${PIN_DIR} | wc -l` (the discovered count). Negation control: re-run the test WITHOUT the chmod step (normal permissions); assert the exporter does NOT exit 6 (kill it manually after a brief scrape window; the negation proves the test isn't false-failing on a different exit path).

**SKIP conditions**: cannot reproduce EACCES in test env (root + Linux Capabilities make EACCES tricky for the BPF subsystem — kernel may bypass DAC checks for root with CAP_DAC_OVERRIDE) → SKIP-77 with rationale `T_EXPORTER_EXITS_6_ALL_IFACES_EACCES: EACCES not reproducible in this test env; needs unprivileged user or DAC_OVERRIDE drop`. Tester MAY use `capsh --drop=cap_dac_override --user=nobody -- xdpmf-exporter ...` OR run the exporter directly under `sudo -u nobody` (if `nobody` has CAP_BPF via `setcap`) — these are TEST-RUNTIME mechanisms; the test SKIPs gracefully if neither works.

**Cleanup**: `chmod` restore on pin files; kill exporter (if still alive); `cleanup_veth`.

**Maps to**: HK-17 (exit-6 trigger condition); D-3.4.5-2 (per-scrape check mechanism); HG-3.4.5-2 (IMPLEMENT per design).

**OPS canary note (per architect-spec)**: this test exercises a NEW invocation context — exporter running with restricted DAC + restricted CAP. The existing exporter ctests (§6.37..§6.39) all run with full root caps preserved via NSEXEC; they CAN'T catch a class of bug where the exit-6 logic only fires correctly under stripped-cap conditions. T_EXPORTER_EXITS_6_ALL_IFACES_EACCES is the OPS canary for HK-17's exit-6 path AND the indirect canary for D-3.4-6's cap-set declaration (if `AmbientCapabilities=CAP_BPF` is wrong, this test fails at the EACCES-reproduction step BEFORE the exit-6 check).

##### §6.39 EDIT — T_EXPORTER_NO_ATTACHED_IFACE gains HK-16 WARN assertion

**Existing trigger (§5.29)**: launch exporter on a system with no attached XDP; query `/metrics`; verify HELP+TYPE only.

**HK-16 EXTENSION**: capture exporter stderr to `/tmp/exporter.stderr`; after the existing `/metrics` assertions, `grep -qE 'WARN bpffs root .* does not exist; will serve empty metrics' /tmp/exporter.stderr`. Sub-case: run with `--bpffs-root /nonexistent/path` → WARN MUST fire; run with the EXISTING (but empty) `${PIN_DIR}` → WARN MUST NOT fire (the dir exists; empty is graceful-empty, NOT WARN-worthy per PI-32 W1 semantic).

**Failure modes new to this EDIT**: missing WARN on nonexistent path = `[INVARIANT-VIOLATED]` (PI-32). Extra WARN on existing-empty path = `[INVARIANT-VIOLATED]` (over-WARN noise; W1 contract is "exists check, not contents check").

##### Surgical fixes to existing ctests (HK-10, HK-11, HK-12, HK-13, HK-15) — no NEW test entries

These are EDITS to existing ctest bodies per the FileList EDITED table above. No new `add_test(...)` entry, no new §6.X numbering. The 42-test baseline post-§5.30 contains the SAME 42 entries with 5 modified bodies (T_LINK_PERSIST_ACROSS_LOADER_EXIT, T_SYSTEMD_RESTART_ON_FAILURE, T_APPLY_ATOMIC_SWAP_NO_DROP, T_ATTACH_TAG_MISMATCH, T_EXPORTER_NO_ATTACHED_IFACE) + 4 NEW entries (§6.43..§6.46) = **46 total ctests post-§5.30**. PI-34-3.4.5 fence below documents the explicit 5-file-EDIT carve-out.

#### §6.5 Preserved invariants (MVP-3.4.5 brownfield) — PI-1..PI-34 hold + PI-7-3.4.5-hpp/cpp continuation; NO NEW PIs

All MVP-3.1..3.4 invariants (PI-1..PI-34 per §5.26 + §5.27 + §5.28 + §5.29 sub-sections) continue to hold post-§5.30. **No new PIs introduced** (housekeeping by nature). PI-7 strengthens further (5th consecutive ZERO-diff cycle on loader.hpp; cpp-leg scope-fence extends to allow the kManagedMaps[] refactor + the XDPMF_BPF_OBJECT_PATH compile-gate hunks). PI-34 (strict-superset 42-ctest baseline from §5.29) generalizes with a small explicit carve-out for the 5 EDITED ctest bodies (HK-10/11/12/13/16 surgical fixes).

Reviewer's 5th framework point walks the COMBINED list (PI-1..PI-34 + PI-7-3.4.5-hpp/cpp) and reports `[INVARIANT-VIOLATED]` per failed check.

**Continuing invariants — restatement for the MVP-3.4.5 namespace**:

| # | Invariant | §5.30 check mechanism |
|---|---|---|
| PI-1..PI-5 | Trust+identity gates ENFORCED in both modes (alien-program refusal, name-identity, tag-check, O_PATH path-discipline, kernel-version probe) | Re-run §6.9 / §6.14 / §6.15 / §6.20 / §6.26 sub-cases; all pass. HK-3/4/5/9 do not touch any gate codepath. |
| **PI-6-3.4.5** | **42 pre-§5.30 ctests pass byte-equivalent OR legitimately SKIP-77 — STRICT SUPERSET with explicit 7-ctest-body EDIT carve-out** (5 surgical-fix EDITs + 2 HK-fix-forced EDITs per §5.30 EDIT-3) | Re-run all 42 tests post-§5.30 → all pass (or SKIP-77); `git diff --stat tests/T_*.sh` shows changes confined to the 7 EDITED ctests PLUS 4 NEW files (§6.43..§6.46). The 7 EDITED ctests are: (1) T_LINK_PERSIST_ACROSS_LOADER_EXIT (HK-10 iface-scoped pkill), (2) T_SYSTEMD_RESTART_ON_FAILURE (HK-11 internal retry), (3) T_APPLY_ATOMIC_SWAP_NO_DROP (HK-12 NOTE comment), (4) T_ATTACH_TAG_MISMATCH (HK-13 orphan-pin cleanup), (5) T_EXPORTER_NO_ATTACHED_IFACE (HK-16 WARN assertion), (6) T_BYPASS_CMD_DETACHES (HK-4-forced permissive regex per §5.30 EDIT-3 + D-3.4.5-8 option (b) — existing regex broken by new audit-log fields, relaxed to accept both shapes; no new field-detail assertions), (7) T_EXPORTER_METRICS_FORMAT (HK-8-forced version-literal bump per §5.30 EDIT-3 — `0.6.0` → `0.6.1` literal swap aligned with PI-8-3.4.5). All OTHER ctest bodies byte-equivalent (35 of 42 = unchanged). PI-6-3.4 had ZERO-edit STRICT SUPERSET; PI-6-3.4.5 RELAXES to 7-edit-carve-out — this is explicit, NOT a regression. EDITs 1-5 are surgical OOT-fix; EDITs 6-7 are HK-FORCED (HK-4 audit-line shape change + HK-8 version bump — both operator-observable-contract-byte-equivalent because the audit-line is a superset and the version bump is the natural verification of PI-8-3.4.5). Reviewer accepts all 7 EDITs as scope-fenced. |
| **PI-7-3.4.5-hpp** | **`loader.hpp` ZERO diff — 5TH consecutive slice** (MVP-3.1 +1; MVP-3.2/3.3/3.4/3.4.5 = 0). Public-API surface byte-equivalent. | `git diff main -- src/lib/loader.hpp` shows ZERO output. Any diff = `[INVARIANT-VIOLATED]`. |
| **PI-7-3.4.5-cpp** | **`loader.cpp` SCOPED EDIT only** — diff lines confined to: (a) HK-3 `#ifdef XDPMF_ENABLE_BPF_OBJECT_OVERRIDE` blocks wrapping the existing constant + 3 error-message strings + 1 consumer site (line ranges per §5.30 EDITED table); (b) HK-9 anon-namespace `kManagedMaps[]` table addition; (c) HK-9 `open_skeleton_only` loop body replacement (pinned_maps[] literal → for-each-kManagedMaps); (d) HK-9 `internal::apply_request` pin_specs[] loop replacement; (e) HK-9 `internal::apply_request` reuse_specs[] loop replacement. ZERO diff in: `attach()` / `detach()` public bodies, §5.4 state-machine, §5.19 name-check, §5.22 tag-check + O_PATH, §5.24 kernel-version probe, §5.26 trust_model parse+log, §5.27 CIDR populate step, §5.29 apply step 8.5 (rules+action_table populate + WARN), link-pin P0a logic, RAII wrappers, error-translation paths, the special-pin path at line 1739 for the legacy `allowlist` alias. **NOTE on relation to PI-7-3.4-cpp**: PI-7-3.4.5-cpp EXTENDS the prior cpp-leg fence with TWO new allowed scopes (HK-3 #ifdef hunks + HK-9 kManagedMaps[] refactor). The prior MVP-3.4 scope (apply_request step 8.5 + step 4 fd-opening + pin_specs/reuse_specs 9→11 + open_skeleton_only pinned_maps[] 10→12) was the THEN-shipped delta; MVP-3.4.5 BUILDS ON that baseline (the literals are already 11/12 entries from MVP-3.4) and now REPLACES the literals with table-walking loops (HK-9). The cumulative cpp-leg invariant for MVP-3.4.5 is "diff-confined to the union of {MVP-3.4-shipped scope, MVP-3.4.5-NEW scope}"; for reviewer-clarity, the MVP-3.4.5 incremental scope is what's enumerated in (a)-(e) above. | `git diff <MVP-3.4-baseline> -- src/lib/loader.cpp` shows changes confined to (a)-(e). Reviewer applies regional-diff: classify each hunk by enclosing function name; allowed function names = {`open_skeleton_only`, `internal::apply_request`, anon-namespace (kManagedMaps[] table + #ifdef blocks)}. Any hunk outside this set = `[INVARIANT-VIOLATED]`. **Cross-cycle baseline note**: reviewer compares against the MVP-3.4-shipped HEAD (not the project's pristine main), because PI-7-3.4-cpp already permitted the MVP-3.4 hunks; this slice's invariant is the MVP-3.4.5-incremental diff on top of MVP-3.4. |
| PI-8-3.4.5 | `xdpmacfilter --version` reports `xdpmacfilter 0.6.1` AND `xdpmf-exporter --version` reports `xdpmf-exporter 0.6.1` (shared `version.h` per §5.25 P3) | Run both `--version`; both single-line outputs `0.6.1` + newline. Bump from 0.6.0. |
| PI-9 | `--help` / `--version` output FORMAT unchanged modulo HK-2 (exit-code list completeness) + HK-6 (--unsafe wording + Environment block) | §6.10 T_CLI_HELP_VERSION re-run passes (forward-compatible ERE). HK-2/6 are content additions, not format changes. |
| PI-10-3.4.5 | `src/common/mac_filter.h` UNCHANGED this slice | `git diff main -- src/common/mac_filter.h` shows ZERO output (no new constant, no new struct, no new enum). |
| PI-11 | Internal directory layout UNCHANGED | `find src -type d` UNCHANGED from §5.29 (same `src/lib/`, `src/cli/`, `src/common/`, `src/bpf/`, `src/exporter/`). No new dir. |
| PI-12 | Pin paths host-global per `nsenter --net` | UNCHANGED (HK-9 refactor preserves pin paths byte-equivalent; the table entries match the existing pinned_maps[] literal exactly). |
| **PI-13-3.4.5 = PI-27** | **inner-allowlist-value byte-equivalent** (the LOAD-BEARING DEFER PI) — `allowlist_*` HASH value `__u8 present`; `cidr_allowlist_*` LPM_TRIE value `__u8`. UNTOUCHED. | `git diff main -- src/bpf/mac_filter.bpf.c` shows ZERO modification to inner-value types. `bpftool map show pinned ${PIN_DIR}/allowlist_a` reports `value_size 1`. **MVP-3.4.5 contributes NO change here**; the defer continues. |
| PI-14 | `--mode {generic,native,offload}` UNCHANGED | §6.16/§6.17/§6.19 still pass. |
| PI-15..PI-18 | CIDR axis + STAT_PASS_CIDR + schema_version 1 + MAC atomic-swap | UNCHANGED. HK items don't touch these. |
| PI-19 | systemd-analyze verify passes on unit files | UNCHANGED. HK-7 only installs the docs FILE, not unit content. |
| PI-20 | systemd lifecycle for `xdpmacfilter@.service` | UNCHANGED. |
| PI-21..PI-25 | Ansible playbook + syntax-check + FLEET_DEPLOYMENT.md cites + directive catalogue + systemd-restart flake carve-out | UNCHANGED. T_SYSTEMD_RESTART_ON_FAILURE flake handling MOVES from "PI-25 carve-out" to "HK-11 internal retry" (still a carve-out flavour; the test now retries internally rather than being SKIP-77'd by external decision). PI-25 STRENGTHENS: fewer SKIPs expected on this test post-HK-11. |
| PI-26 | MVP-3.3 historical "no C++/BPF source change" check | UNCHANGED (PI-26 fires on the MVP-3.3 commit set, not the MVP-3.4.5 commit set). |
| PI-27 = PI-13-3.4.5 | inner-allowlist-value byte-equivalent (cross-referenced — IDENTICAL invariant) | Same check. |
| PI-28 | `mac_filter_prog` BPF function body BYTE-EQUIVALENT to MVP-3.2 modulo new `.maps` declarations | UNCHANGED BUT HK-5 EXTENDS: the source-level `unlikely()` macro wraps add `__builtin_expect` hints on 6 leaf null-checks. JIT-emitted code MAY differ slightly (branch reordering), but the FUNCTIONAL semantic is byte-equivalent (same verdicts for same inputs). PI-28 generalizes to "function body semantic byte-equivalent; source-level annotations + compiler hints permitted". Reviewer verifies via the 42-ctest baseline (which IS the functional verdict test). If any of the 42 ctests change verdict due to HK-5, that's `[INVARIANT-VIOLATED]`. |
| PI-29 | `rules` + `action_table` POPULATED on apply but NOT consulted by datapath | UNCHANGED. HK-9 refactor preserves the populate-step semantic (the kManagedMaps[] table includes `rules` and `action_table`; the pin/reuse semantics for these maps are byte-equivalent — verified by §6.42 T_RULES_SKELETON_NOT_WIRED re-running green). |
| PI-30 | `bypass` primitive = `detach`-alias + audit-log + `--unsafe` gate | UNCHANGED in shape; HK-4 EXTENDS the audit-log line with `euid=` + `sudo_user=` structural fields (additive — operators grepping for old format still find the line; new format is a superset). |
| PI-31 | Exporter is READ-ONLY by construction | UNCHANGED. HK-16/17 are read-side only (existence check, accounting); no `bpf_map_update_elem` introduced. Reviewer's `grep -rE 'bpf_(map_(update|delete)_elem|obj_pin|link_create|...)' src/exporter/` STILL returns ZERO matches post-§5.30. |
| PI-32 | Exporter handles missing/empty bpffs gracefully | UNCHANGED in shape; HK-16 REALIZES the WARN-emission side of PI-32 (previously the implementation was "silent graceful return"; now matches design literal "logs ONE warning line at startup"). PI-32 STRENGTHENS: T_EXPORTER_NO_ATTACHED_IFACE now asserts the WARN substring (was unasserted at §5.29). |
| PI-33 | Both binaries report same version (shared version.h) | UNCHANGED in shape; bump to 0.6.1 (PI-8-3.4.5). |
| **PI-34 = PI-6-3.4.5** | 42 pre-§5.30 ctests strict-superset with 7-EDIT carve-out per §5.30 EDIT-3 (5 surgical-fix + 2 HK-fix-forced; cross-referenced) | Same check. |

**No deletions/relaxations** of PI-1..PI-34 in this slice. PI-7-3.4.5-hpp STRENGTHENS PI-7-3.4-hpp (5th consecutive ZERO-diff cycle). PI-7-3.4.5-cpp EXTENDS PI-7-3.4-cpp with TWO new allowed-hunk scopes (HK-3 #ifdef + HK-9 kManagedMaps[] refactor), all other scopes preserved. PI-6-3.4.5 / PI-34 RELAXES PI-6-3.4 / PI-34 from "ZERO ctest body edits" to "5 specifically-enumerated EDITED ctest bodies + 4 NEW ctests"; this is explicit, documented, and scope-fenced (not a silent regression). PI-10-3.4.5 STRENGTHENS PI-10-3.4 from "additive-only" to "ZERO diff" (no header change this slice). PI-13-3.4.5 / PI-27 PRESERVED untouched (the load-bearing defer PI; MVP-3.4.5 contributes nothing to it).

#### §5.30 verifiable invariants for reviewer

(Per architect-spec §6.5 "Verification-hints discipline": these are GUIDANCE for the reviewer, NOT contracts for impl. Default MAY. Reserve MUST only for true PI-* contracts (PI-1..PI-34 + PI-7-3.4.5-hpp/cpp ARE MUSTs by definition; the items below MAY be relaxed by impl if a contract elsewhere demands it). Resolution rule for prose-vs-invariants conflicts: invariants block wins, prose loses; if impl deviates on a hint to satisfy a PI-* contract, reviewer's correct disposition is `inline-merge` on the hint text, NOT `[UNRELATED-EDIT]` on impl.)

In addition to PI-1..PI-34 + PI-7-3.4.5-hpp/cpp above:

- `git diff main -- src/lib/loader.hpp` SHOULD show ZERO output (PI-7-3.4.5-hpp, 5th consecutive cycle).
- `git diff <MVP-3.4-HEAD> -- src/lib/loader.cpp` SHOULD show changes confined to the HK-3 #ifdef line ranges (5 sites) + HK-9 kManagedMaps[] table + 3 loop replacements (open_skeleton_only, pin_specs, reuse_specs). No diff in attach()/detach() bodies or any gate codepath (PI-7-3.4.5-cpp).
- `git diff main -- src/common/mac_filter.h` SHOULD show ZERO output (PI-10-3.4.5).
- `git diff main -- src/bpf/mac_filter.bpf.c` SHOULD show ONLY the HK-5 `#define unlikely(x)` macro definition + 6 `unlikely()` wraps on the listed null-check lines. ZERO modification to `.maps` block, ZERO modification to `mac_filter_prog` function-body logic (the wraps are source-annotations on existing conditions). Functional semantic byte-equivalent per PI-28.
- `git diff main -- src/cli/main.cpp` SHOULD show ONLY the HK-1 catch-arm addition (3 LOC).
- `git diff main -- src/cli/apply.cpp` SHOULD show ONLY the HK-1 stale-comment deletion/rewrite (5 LOC, comment-only).
- `git diff main -- src/cli/cli.cpp` SHOULD show ONLY HK-2 + HK-6 usage_text edits (10 LOC).
- `git diff main -- src/cli/bypass.cpp` SHOULD show HK-4 escape + sudo identity edits (~25 LOC); ZERO change to tty-check, prompt, `loader::detach()` invocation.
- `git diff main -- src/exporter/main.cpp` SHOULD show HK-6 env-var block + HK-17 post-`http::run()` exit-6 emission (~20 LOC); ZERO change to signal handling, HTTP binding, default flag values.
- `git diff main -- src/exporter/stats_reader.cpp` SHOULD show HK-16 WARN + HK-17 DiscoveryAccounting (~25 LOC); ZERO change to PERCPU-sum logic.
- `git diff main -- src/exporter/http.cpp` SHOULD show HK-17 stop-signal hook ONLY (per §5.30 EDIT-2): anon-namespace globals (`g_exit_six`, `g_exit_six_total`), `handle_connection` `/metrics` arm trigger evaluation post-response-write, accept-loop while-condition extension, `run()` return-6-on-flag, `last_exit_six_total()` getter (~10-15 LOC). ZERO change to bind/listen/HTTP framing, `/healthz` arm, 404 arm, per-conn budget/timeout, SIGTERM observation cadence.
- `git diff main -- src/exporter/http.hpp` SHOULD show ONLY the `last_exit_six_total()` declaration addition (~2 LOC); `run()` declaration UNCHANGED (only its return-code semantic extends).
- `git diff main -- CMakeLists.txt` SHOULD show HK-3 + HK-7 + HK-8 (~10 LOC).
- `git diff main -- tests/CMakeLists.txt` SHOULD show 4 NEW `add_test` entries + HK-3 propagation; ZERO modification of the 42 existing add_test entries.
- `git diff main -- tests/T_*.sh` SHOULD show: 4 NEW files (§6.43..§6.46) + 7 EDITED files (HK-10/11/12/13/16 surgical-fix + HK-4-forced T_BYPASS_CMD_DETACHES permissive-regex + HK-8-forced T_EXPORTER_METRICS_FORMAT version-literal-bump per §5.30 EDIT-3); 35 of 42 existing ctests byte-equivalent.
- `git diff main -- CHANGELOG.md` SHOULD show NEW `[0.6.1]` entry + build-pace row.
- `git diff main -- mint/design.md` SHOULD show §5.30 amendment addition + HK-15 inline correction marker in §5.26.
- 4 new ctests SHOULD pass (§6.43..§6.46); the load-bearing pair is §6.43 (HK-1 fix) + §6.46 (HK-17 fix).
- 7 EDITED ctests SHOULD pass with their new bodies: 5 surgical-fix (HK-10/11/12/13/16) + 2 HK-fix-forced per §5.30 EDIT-3 (T_BYPASS_CMD_DETACHES permissive regex per D-3.4.5-8 option (b); T_EXPORTER_METRICS_FORMAT version-literal bump per PI-8-3.4.5).
- 37 unchanged existing ctests SHOULD still pass (or legitimately SKIP-77) — PI-6-3.4.5 strict-superset with carve-out.
- `xdpmacfilter --version` SHOULD report `xdpmacfilter 0.6.1` AND `xdpmf-exporter --version` SHOULD report `xdpmf-exporter 0.6.1` (PI-8-3.4.5).
- `XDPMF_SANITIZERS=ON` build SHOULD be clean for BOTH binaries.
- `CHANGELOG.md` entry `[0.6.1] - 2026-05-NN` (Keep-a-Changelog format).
- Build-pace table SHOULD gain a row for MVP-3.4.5.
- `nm $(which xdpmacfilter) | grep -c XDPMF_BPF_OBJECT_PATH` SHOULD return 0 in a release build (HK-3 compile-gate evidence; the string literal is absent from the binary).
- `nm $(which xdpmacfilter) | grep -c XDPMF_BPF_OBJECT_PATH` SHOULD return ≥1 in a test build (HK-3 propagation evidence; the symbol IS present when override is enabled).
- `xdpmacfilter apply -f /nonexistent --iface lo; echo $?` SHOULD output `1` (HK-1 fix).
- `xdpmacfilter --help | grep -c '7 kernel-unsupported'` SHOULD return 1 (HK-2 fix).
- `xdpmf-exporter --bpffs-root /nonexistent` SHOULD emit the HK-16 WARN line within the first 1s of startup, then continue running (HK-16 fix).
- 6 `unlikely()` macro wraps SHOULD appear in `mac_filter.bpf.c` at the listed line numbers (HK-5 verification — line numbers MAY shift slightly due to the `#define` insertion; reviewer checks `grep -cE '\bunlikely\(' src/bpf/mac_filter.bpf.c` returns 6).
- `grep -E 'pkill -9 -f xdpmacfilter\s*$' tests/T_LINK_PERSIST_ACROSS_LOADER_EXIT.sh` SHOULD return ZERO matches (HK-10 — the unscoped pkill is gone; either PID-tracked OR argv-scoped form replaces it).
- HK-12 NOTE comment in T_APPLY_ATOMIC_SWAP_NO_DROP.sh SHOULD cite §5.26 D-3.1-4 (the corrected attribution).
- HK-13 orphan-pin cleanup SHOULD appear in T_ATTACH_TAG_MISMATCH.sh's trap (visible via `grep -E 'bpftool.*unpin|rm.*sys/fs/bpf' tests/T_ATTACH_TAG_MISMATCH.sh` ≥1 match).
- HK-15 design-text correction SHOULD appear in §5.30 + an inline `[CORRECTION §5.30 HK-15]` marker SHOULD appear in §5.26.

#### §7 OOS — MVP-3.4.5 components SHIPPED + close OOT-deferred queue + surface MVP-3.5

##### Moved from deferred to SHIPPED (per MVP-3.4.5)

The following items were OOT-deferred in prior cycles' OOS sections and are now CLOSED by this slice:

- ~~**T_SYSTEMD_RESTART_ON_FAILURE flake (MVP-3.3 OOT-1, per `5a4760c` addendum)**~~ **— SHIPPED in §5.30** as HK-11 (Q5 S1 internal 2-attempt retry).
- ~~**Orphan map pins from T_ATTACH_TAG_MISMATCH (MVP-3.1 OOT)**~~ **— SHIPPED in §5.30** as HK-13 (cleanup trap added).
- ~~**T_APPLY_ATOMIC_SWAP_NO_DROP stale NOTE comment (MVP-3.1 OOT)**~~ **— SHIPPED in §5.30** as HK-12 (NOTE rewritten to cite §5.26 D-3.1-4).
- ~~**cli.hpp ParsedAttach wrapper design-text inaccuracy (MVP-3.1 OOT)**~~ **— SHIPPED in §5.30** as HK-15 (design.md correction + inline marker in §5.26).
- ~~**§6.25 step 8 grep for "replacing existing program" stderr (MVP-3.1 OOT)**~~ **— DELIBERATELY CLOSED-AS-WONT-DO in §5.30** as HK-14 / D-3.4.5-4 (architect ruling: stays UNASSERTED per §5.26's "impl-shape flexibility" prose; if a future cycle wants to lock it, gets explicit PI-* status then).
- ~~**PI-32 exporter startup WARN (MVP-3.4 OOT-1 per `review.md:82-85`)**~~ **— SHIPPED in §5.30** as HK-16 (per HG-3.4.5-1 IMPLEMENT-per-design + Q2 W1).
- ~~**Exporter exit-6 unreachable (MVP-3.4 OOT-2 per `review.md:84-86`)**~~ **— SHIPPED in §5.30** as HK-17 (per HG-3.4.5-2 IMPLEMENT-per-design + Q3 E1).

All 7 previously-OOT-deferred items are now in their dispositions: 6 SHIPPED (HK-11, HK-13, HK-12, HK-15, HK-16, HK-17), 1 CLOSED-AS-WONT-DO (HK-14). The MVP-3.x OOT-deferred queue is **EMPTY post-§5.30** — no carry-forward to MVP-3.5.

##### Additional MVP-3.4.5 deliverables (NOT in prior OOT queues; surfaced in this slice)

- **HK-1 apply exit-1 fix** — surfaced by `/mint-review` KC-A (commit `325e2ee`). Not previously OOT-tracked. SHIPPED.
- **HK-2 --help exit-code list completeness** — surfaced by `/mint-review` (no specific KC reference in brief; minor doc-of-help fix). SHIPPED.
- **HK-3 XDPMF_BPF_OBJECT_PATH compile-gate** — surfaced by `/mint-review` KC-C. SHIPPED.
- **HK-4 bypass log-escape + sudo identity** — surfaced by `/mint-review` KC-B partial. SHIPPED.
- **HK-5 __builtin_expect** — surfaced by `/mint-review` perf H1. SHIPPED.
- **HK-6 --unsafe + env-var block** — surfaced by `/mint-review` (operator-clarity finding). SHIPPED.
- **HK-7 FLEET_DEPLOYMENT.md install** — surfaced by `/mint-review` (pairing with systemd unit Documentation= URI). SHIPPED.
- **HK-8 version bump 0.6.0 → 0.6.1** — standard housekeeping per Keep-a-Changelog discipline. SHIPPED.
- **HK-9 kManagedMaps[] refactor** — surfaced by project-memory landmine [[libbpf-pin-by-name-three-callsites]] + `/mint-review` arch H2. SHIPPED.
- **HK-10 iface-scoped pkill** — surfaced by `/mint-review` (test-hygiene finding). SHIPPED.
- **NEW ctests (4)** — testing M5/M6/L-coverage from `/mint-review`. SHIPPED (§6.43..§6.46).

##### Closed-as-WONT-DO (architect ruling this slice)

- **HK-14 — §6.25 step 8 grep for "replacing existing program" stderr** — see D-3.4.5-4 above. Design §5.26 explicitly permits impl-shape flexibility on the stderr line wording; asserting on it would over-constrain impl + risk false-fails on future legitimate refactors. CLOSED.

##### Surfaced as next-natural slice

**MVP-3.5 — JSON structured logs in loader + exporter** (NOT in MVP-3.4.5 scope; next architectural slice per `architecture-v2.md` post-MVP-3.4-row sequencing):

- Loader (`xdpmacfilter`) emits structured JSON log lines (one per significant event) to stderr when `XDPMF_LOG_FORMAT=json` env var is set; default `XDPMF_LOG_FORMAT=text` (current shape preserved for operator-grep compatibility).
- Exporter (`xdpmf-exporter`) emits structured JSON log lines (startup, accept errors, scrape errors, HK-16 WARN, HK-17 ERROR) under the same env-var contract.
- Log schema TBD at MVP-3.5 architect phase; likely shape per event: `{"ts":"<iso8601>","level":"<info|warn|error>","event":"<name>","iface":"<iface or null>","msg":"<existing prose>","fields":{...}}`.
- This is candidate scope; brief at MVP-3.5 start.

**MVP-3.4b — per-rule counter wiring** (already surfaced as next-natural at §5.29; UNCHANGED by §5.30):

- per-rule counter map (Option 2 default per arch-v2.md §"§MVP-3.4 Open Question #13 RESOLUTION" Recommendation)
- inner-allowlist-value extension gated on PI-13-3.1 adjudication
- datapath wiring of `rules` → `action_table` lookup chain
- atomic-swap promotion of `rules` to parallel-outer (D-3.4-4 surfaced Open Q)
- exporter `xdpfilter_rule_match_total{iface, rule_id}` series

**Documentation pass (13 items D1..D13 from `/mint-review` report.md)** — see task-brief.md "Doc bucket" section. NOT a /mint-dev slice; user-driven manual writing pass. ~8-10 hours sustained. Includes README rewrite, FLEET_DEPLOYMENT.md sections, CONFIG_SCHEMA.md, HANDOFF.md move, Ansible Jinja fixes. **DO NOT include in any /mint-dev slice without explicit user request.**

##### NEW out-of-scope fences (per §5.30; carry-forward unchanged from §5.29 unless noted)

- **Per-rule counters / labels in exporter output** — MVP-3.4b (carry-forward).
- **Inner-allowlist-value extension** — MVP-3.4b gated on PI-13-3.1 (carry-forward — PI-13-3.4.5 = PI-27 is the LOAD-BEARING DEFER PI, untouched this slice).
- **Datapath wiring of `rules` or `action_table`** — MVP-3.4b (carry-forward).
- **Action types beyond {PASS, DROP}** — MVP-3.8+ (carry-forward).
- **JSON structured logs** — MVP-3.5 candidate (now SURFACED explicitly as next-natural; was "MVP-3.5 candidate" at §5.29 OOS, now explicit).
- **sFlow integration** — MVP-3.6 conditional (carry-forward).
- **Exporter HTTPS / TLS** — operator wraps with reverse-proxy (carry-forward).
- **Exporter authentication** — operator wraps (carry-forward).
- **Exporter histograms / new labels** — MVP-3.5+ (carry-forward).
- **Bypass via BPF map flag** — MVP-3.6+ optional (carry-forward).
- **Library extraction `libxdpmf.so.0`** — MVP-3.6+ optional (carry-forward).
- **Daemon `xdpmfd`** — MVP-3.6+ optional (carry-forward).
- **L4 ports / VLAN / IPv6 CIDR** — fenced per MVP-3.2 §7 OOS (carry-forward).
- **Binary rename `xdpmacfilter` → `xdpfilter`** — MVP-3.12 (carry-forward).
- **Exporter listening on IPv6 / dual-stack** — v1 IPv4-only (carry-forward).
- **Exporter inotify on bpffs root** — MVP-3.5+ candidate (carry-forward).
- **Ansible installs of `xdpmf-exporter`** — MVP-3.5+ candidate (carry-forward).
- **`docs/EXPORTER.md` operator docs** — MVP-3.5+ candidate; part of the EXCLUDED doc bucket (carry-forward).
- **Atomic-swap on `rules` map (parallel-outer)** — MVP-3.4b scoping question (carry-forward).
- **Systemd sandbox directives (ProtectSystem strict, PrivateTmp, etc.)** — defense-in-depth; deferable to MVP-3.5 OR dedicated security cycle. NEW FENCE this slice (was security M3 from `/mint-review` report).
- **`std::format_to` / writev microopts in exporter (perf M1-M4)** — performance scope; not contract-drift housekeeping. NEW FENCE this slice.
- **TSAN build (testing H2)** — coverage scope; not housekeeping. NEW FENCE this slice.
- **CO-RE field-probe failure test (testing L3)** — known coverage gap; not housekeeping. NEW FENCE this slice.
- **README full rewrite + FLEET_DEPLOYMENT.md sections + CONFIG_SCHEMA.md + HANDOFF.md move + Ansible Jinja fixes (doc bucket D1..D13)** — separate manual pass per user direction. NEW FENCE this slice.
- **PI-32 W2 (per-scrape rate-limited WARN)** — explicitly REJECTED at Q2; HK-16 ships W1 only. NEW FENCE.
- **HK-17 E2 (any-iface EACCES → exit 6)** — explicitly REJECTED at Q3; HK-17 ships E1 only. NEW FENCE.
- **HK-17 E3 (bind-time EACCES → exit 6)** — explicitly REJECTED at Q3; would warrant its own exit code if surfaced. NEW FENCE.
- **HK-1 C2 (whole-main try/catch refactor)** — explicitly REJECTED at Q1; HK-1 ships C1 (catch-arm only). NEW FENCE.
- **HK-9 T2 (name-lookup table) / T3 (lambda dispatch)** — explicitly REJECTED at Q4; HK-9 ships T1 (member-pointer). NEW FENCE.
- **HK-11 S2 (widen-band [1,50] permanently) / S3 (SKIP-77 on first flake)** — Q5 default S1; S2 is fallback ONLY if S1 runtime cost >30s. NEW FENCE.

##### Anti-misdiagnosis notes (institutional learning, per architect-spec §6.6)

This slice carries forward all anti-misdiagnosis guards from prior cycles + adds two specific to MVP-3.4.5:

1. **Cap-set declaration on a NEW invocation path** (inherited from §5.28 D-3.3-6 + §5.29 D-3.4-6 rework rounds): unchanged. T_EXPORTER_EXITS_6_ALL_IFACES_EACCES (§6.46) is an OPS canary for both HK-17 AND the §5.29 D-3.4-6 cap-set declaration — if the cap-set is wrong, this test fails at the EACCES-reproduction step before reaching the exit-6 check.

2. **Silent-divergence-from-design pattern** (inherited from MVP-3.4 review.md OOT-1/OOT-2 misdiagnosis pair, formalized as [[impl-role-discipline]]): impl follows design; disagreement is OK but ONLY via explicit Phase B escalation (peer SendMessage to architect). Silent "implementation chose silent graceful return" without escalation is forbidden. MVP-3.4 OOT-1 (PI-32 silent) AND OOT-2 (exit-6 unreachable) BOTH instances of this silent-divergence pattern; this slice flips both back to "implement per design" (HK-16 + HK-17). **Future-cycle guard for any impl agent**: if you read the design and disagree with a contract, SendMessage architect during Phase B with your rationale; do NOT silently implement a different behaviour. The reviewer's correct disposition on silent divergence is `[CONTRACT-VIOLATED]`, NOT `[ACCEPTABLE-VARIATION]` — even if the divergence is "arguably more conservative".

3. **Three-callsite lockstep landmine** (project memory [[libbpf-pin-by-name-three-callsites]]): SHIPPED-FIX via HK-9 kManagedMaps[] refactor. **Future-cycle guard for any architect agent**: when adding a NEW BPF map declared with `LIBBPF_PIN_BY_NAME`, the kManagedMaps[] table MUST be extended (one line) AND that's it — the three loops (open_skeleton_only clear, apply_request pin, apply_request reuse) walk the table automatically. NO more per-callsite literal-array maintenance. If a future cycle's MAP is NOT `LIBBPF_PIN_BY_NAME` (e.g. a global non-per-iface map), it does NOT belong in kManagedMaps[]; the architect documents the exception in the new slice's Decisions section.

4. **Verification-hints discipline trap** (inherited from MVP-3.1/3.2/3.3 verification-hints rework cycles): the §5.30 verifiable invariants section above is GUIDANCE for the reviewer, NOT contracts for impl. Items default to SHOULD/MAY; MUST is reserved for PI-* contracts. If impl deviates on a SHOULD/MAY hint to satisfy a PI-* contract, reviewer disposition is `inline-merge` on the hint text — NOT `[UNRELATED-EDIT]` on impl. Resolution rule for prose-vs-invariants conflicts within this amendment: invariants block wins, prose loses (stated once per the amendment template; this single statement covers all §5.30 prose vs. PI-* conflicts).

Evidence: `mint/task-brief.md` MVP-3.4.5 brief (HK-1..HK-17 + Q1-Q6 + HG-3.4.5-1/2/3/4); `mint/review.md` MVP-3.4 round-1 (OOT-1 PI-32 silent → HK-16; OOT-2 exit-6 unreachable → HK-17); `/agent-teams-review/runs/mint-review-mint-l2-mac-filter-202605250825/report.md` (15 Critical+High citations + the 13-item doc bucket EXCLUDED); `architecture-v2.md` MVP-3.4 → MVP-3.5 row sequencing (no MVP-3.4.5 row added; this is an inserted maintenance slice that does NOT alter the dependency graph); §5.29 (MVP-3.4 ancestor — all PI-1..PI-34 preserved); §5.26 D-3.1-1 (apply_request lives in loader.cpp); project memory [[libbpf-pin-by-name-three-callsites]] (HK-9 landmine source); [[impl-role-discipline]] (HK-16 + HK-17 rationale).

### §5.31 MVP-3.4b cycle 1: per-rule counters + inner-allowlist-value extension + datapath wiring + exporter rule labels (brownfield amendment, 2026-05-25)

**Purpose**: ship the per-rule observability surface deferred from MVP-3.4 (§5.29 + Open Q #13 RESOLUTION). Operator gains `xdpfilter_rule_match_total{iface, rule_id, action}` Prometheus series via `/metrics` showing per-rule match counts. The slice composes Option 2 from `architecture-v2.md` §"§MVP-3.4 Open Question #13 RESOLUTION":
- NEW BPF map `rule_counters` PERCPU_ARRAY[XDPMF_ALLOWLIST_MAX=64] of `__u64` — per-rule packet counts.
- Inner-allowlist-value EXTENSION from `__u8 present` (1 byte) to `struct allow_entry { __u8 present; __u8 _pad[3]; __u32 rule_id; }` (8 bytes total) — SYMMETRIC across MAC HASH `allowlist_a/b` AND CIDR LPM_TRIE `cidr_allowlist_a/b` (T.5 OQ #3).
- Datapath `bump_rule(rule_id)` wiring at the MAC HASH-hit AND CIDR LPM_TRIE-hit branches in `mac_filter_prog` (Q1=B3 unified per-match semantic — first substantive datapath body edit since MVP-3.2).
- Loader-written `rule_index.json` sidecar at `${PIN_DIR}/<iface>/rule_index.json` (Q3=P1 per-iface bpffs path).
- Exporter joins `rule_counters` (BPF) with `rule_index.json` (sidecar) → emits `xdpfilter_rule_match_total{iface, rule_id, action}` (Q4=A3 action-as-label).
- `kManagedMaps[]` gains a 13th entry for `rule_counters` (LIBBPF_PIN_BY_NAME + bpf_map__reuse_fd discipline so counters SURVIVE `apply -f` per Prometheus counter-monotonicity semantic; HG-3.4b-2). This is the second-cycle dividend on the MVP-3.4.5 HK-9 landmine refactor.

This slice LIFTS two fences from MVP-3.4 §5.29:
- (1) **PI-13-3.1 defer fence** on inner-allowlist-value byte shape — adjudicated PASS-as-additive per HG-3.4b-1 (full byte-layout rationale in §6.5 PI-13-3.4b below).
- (2) **PI-29 "rules+action_table populated NOT consulted"** fence is RELAXED with a documented carve-out: `rules` map is STILL NOT consulted by datapath this cycle (HG-3.4b-4); `action_table` is STILL NOT consulted (action dispatch via existing PASS/DROP branches retained); BUT the inner-allowlist-value's `rule_id` field IS now read on every match. New PI-29-3.4b restates this precisely.

PI-7-3.4b-hpp continues the additive-only streak on `loader.hpp` (6th consecutive cycle). PI-13-3.4b is the LOAD-BEARING NEW PI (the byte-by-byte adjudication of the inner-value extension).

**Anchor sections**: §5.26 (config harness + Config::Rule `id` field with [0, XDPMF_ALLOWLIST_MAX-1] range validation — the rule_id source per Q5 R1); §5.27 (CIDR LPM_TRIE — parallel-swap mechanism preserved; inner-value extension is SYMMETRIC with the MAC HASH branch); §5.29 (MVP-3.4 ancestor — defer posture; `rules`+`action_table` skeleton declared+populated but NOT consulted; bypass primitive; exporter); §5.30 (MVP-3.4.5 housekeeping — HK-9 `kManagedMaps[]` table is the foundation this slice extends; PI-13-3.4.5 = PI-27 was preserved untouched, now formally LIFTED by PI-13-3.4b); §4.1 exit-code table (UNCHANGED — no new exit code; sidecar write failures map to existing LoaderError::AttachFailed); §4.3 LoaderError enum (UNCHANGED — PI-7-3.4b-hpp additive-only); `mint/architecture-v2.md` §"§MVP-3.4 Open Question #13 RESOLUTION" Option 2 + Caveat (b) human-gate Caveat-held (committed `2d4b31a` 2026-05-24).

**Scope contract (§5.31 short form)**:
- NEW (source files): `src/lib/sidecar.hpp` + `src/lib/sidecar.cpp` (rule_index.json writer; ~150 LOC roll-your-own per D-3.4b-10 — NO new build dep this slice).
- NEW (BPF map declaration): `rule_counters` PERCPU_ARRAY[XDPMF_ALLOWLIST_MAX=64] of `__u64`, LIBBPF_PIN_BY_NAME → `${PIN_DIR}/<iface>/rule_counters`.
- NEW (BPF datapath helper): `static __always_inline void bump_rule(__u32 rule_id)` adjacent to existing `bump_stat`.
- NEW (BPF struct): `struct allow_entry { __u8 present; __u8 _pad[3]; __u32 rule_id; }` in `src/common/mac_filter.h` (BPF + userspace shared, additive only per PI-10-3.4b).
- NEW (exporter helpers): `src/exporter/rule_counters_reader.{cpp,hpp}` (PERCPU sum across CPUs for the new map — sister to existing `stats_reader`); `src/exporter/sidecar_reader.{cpp,hpp}` (line-oriented regex extraction from rule_index.json per D-3.4b-14 — sidesteps full-JSON-parser need).
- NEW (exporter Prometheus series): `xdpfilter_rule_match_total{iface, rule_id, action}` counter emitted from `src/exporter/prom_format.cpp`.
- NEW (6 ctests): `T_RULE_COUNTER_MAC_HIT_BUMPS.sh`, `T_RULE_COUNTER_CIDR_HIT_BUMPS.sh`, `T_RULE_COUNTER_SURVIVES_APPLY.sh`, `T_SIDECAR_JSON_SHAPE.sh`, `T_EXPORTER_RULE_LABELS.sh`, `T_DROP_RULE_BUMPS_COUNTER.sh`. Tests/CMakeLists.txt entries.
- EDITED (BPF source): `src/bpf/mac_filter.bpf.c` — inner-value `__type(value, struct allow_entry)` on BOTH `xdpmf_allowlist_inner` (line 55) AND `xdpmf_cidr_inner` (line 95); MAC hit branch (line 226) reads `entry->rule_id` then calls `bump_rule`; CIDR hit branch (line 254) reads `cidr_entry->rule_id` then calls `bump_rule`; NEW `rule_counters` map declaration in `.maps` block; NEW `bump_rule` helper.
- EDITED (loader): `src/lib/loader.cpp` — `populate_inner_slot` + `populate_cidr_inner_slot` write the new struct shape (write `{.present=1, ._pad={0,0,0}, .rule_id=<rule.id>}` per entry, NOT a 1-byte literal); the existing functions' signatures EXTEND to carry rule_id alongside the key (impl-flexible — Decisions D-3.4b-15); `kManagedMaps[]` gains 13th entry `{ &SkelMapsT::rule_counters, XDPMF_MAP_RULE_COUNTERS_NAME, false }` (line 158 area); apply_request body gains a sidecar-write step (post-flip OR post-populate — D-3.4b-16) that invokes `sidecar::write_rule_index(...)`.
- EDITED (shared header): `src/common/mac_filter.h` — ADD `struct allow_entry`, `XDPMF_MAP_RULE_COUNTERS_NAME`, `XDPMF_RULE_COUNTERS_MAX` (alias for XDPMF_ALLOWLIST_MAX=64); existing struct/enum/constants UNCHANGED (PI-10-3.4b additive-only).
- EDITED (exporter per-scrape handler): `src/exporter/http.cpp` — wire in `rule_counters_reader` + `sidecar_reader` consumption per scrape inside `handle_connection`'s `/metrics` arm; pass to `emit_metrics`. [Phase 4.5 OOT inline-merge: original FileList row said `src/exporter/main.cpp` — operationally the per-scrape codepath lives in `http.cpp::handle_connection` called from `http::run()` invoked by main; corrected here. `src/exporter/main.cpp` stays UNCHANGED this slice.]
- EDITED (CMakeLists.txt): version bump `0.6.1 → 0.7.0`; new library deps for `src/lib/sidecar.{cpp,hpp}`; new translation units for `src/exporter/rule_counters_reader.{cpp,hpp}` + `src/exporter/sidecar_reader.{cpp,hpp}`.
- EDITED (CHANGELOG.md): NEW `## [0.7.0] - 2026-05-NN` section; Build-pace table gains MVP-3.4b row.
- EDITED (ctest fixtures — minimal PI-3.4b-9 ripple per Phase A grep finding): `T_RULES_SKELETON_NOT_WIRED.sh` ONLY (comments at line 14 + 297 reference "1-byte values" and "extended to embed rule_id (PI-27/PI-13-3.4 violation)" — both STALE post-§5.31 PI-13-3.4b PASS adjudication; comments rewritten; assertions byte-equivalent — see PI-3.4b-9 catalog in §6.5 below). `T_EXPORTER_METRICS_FORMAT.sh` line 100 pins literal `xdpmf-exporter 0.6.1` — HK-8-forced bump to `0.7.0` (Cf. MVP-3.4.5 EDIT-3 precedent — version-literal in test bodies is HK-bump-forced; precedent is stable). Total: 2 EDITED ctest bodies — significantly less than brief's ~5 estimate due to **Phase A grep finding: ZERO tests write a literal `present=1` payload via `bpf_map_update_elem` from userspace** (all such writes live inside `loader.cpp:1097, 1137`). Brief's 5-fixture-touch ceiling is upper bound; actual cost is 2 surgical-fix EDITs.
- UNCHANGED-BUT-AFFECTED (zero git-diff fence): `src/lib/loader.hpp` (**PI-7-3.4b-hpp — 6th consecutive ZERO-diff cycle**); `src/lib/config.hpp` (PI-7-3.4b-hpp extends — `Config::Rule` already carries `id` field per §5.26; Q5 R1 uses `id` directly; NO field addition needed — see D-3.4b-11); existing exporter `stats_reader.cpp` (`xdpfilter_packets_total` series preserved byte-equivalent — the NEW series is additive); the 44 non-EDITED ctest bodies; `src/lib/cidr.cpp`, `src/lib/cidr.hpp`, `src/lib/yaml_subset.cpp`, `src/cli/*` (no CLI surface change this slice — `xdpmacfilter apply -f <path>` semantics byte-equivalent; only the apply BODY extends to write rule_index.json sidecar); systemd unit `xdpmf-exporter.service` (UNCHANGED — exporter discovers new map via existing bpffs scan); the bypass primitive (UNCHANGED — PI-30 preserved); §5.4 / §5.19 / §5.22 / §5.24 trust+identity gates (UNCHANGED — no `attach`/`detach` path change).

#### §5.31 Human-gate decisions (confirmed)

- **HG-3.4b-1 — PI-13-3.1 inner-allowlist-value adjudication = PASS as additive.** **Confirmed by architect at Phase A.** Byte-layout documented byte-by-byte:

  ```
  struct allow_entry {           offset  size  semantic
      unsigned char present;     // 0     1     PI-27-byte-equivalent: 0x01 = occupied; 0x00 = empty.
                                 //              `bpftool map dump ... format c | head -c 1` still
                                 //              returns 0x01 for occupied slots — old single-byte
                                 //              readers observe the SAME byte at the same offset.
      unsigned char _pad[3];     // 1-3   3     EXPLICIT padding for u32 alignment of `rule_id`.
                                 //              Verifier-friendly: the padding bytes are zero-initialized
                                 //              by C ABI struct-init (`{}`); userspace writes always
                                 //              memcpy a fully-initialized `struct allow_entry` (no
                                 //              uninitialized-byte verifier-pessimism concern).
      __u32 rule_id;             // 4-7   4     NEW: identifies which Config::Rule produced this entry.
                                 //              Range [0, XDPMF_ALLOWLIST_MAX-1] = [0, 63] per Q5 R1
                                 //              (operator's YAML `id:` IS the BPF key directly; rule.id
                                 //              already validated to this range at config.cpp:204).
  };                             // total: 8 bytes
  ```

  **Rationale for PASS adjudication** (cross-references §5.29 PI-27 / PI-13-3.4 prior strict reading + §5.30 PI-13-3.4.5 = PI-27 5th-cycle preservation):
  - **Operator-observable byte 0 is PI-27-byte-equivalent**: a `bpftool map dump ... format c | head -c 1` on the value still returns `0x01` (the `present` byte at offset 0). The MVP-3.4 PI-27 contract was "occupied-or-not visible at offset 0"; that contract HOLDS post-§5.31. The defer's `bpftool map show ... | grep value_size` answer changes (`1 → 8`) — but PI-27's TEXT, re-read literally, was about offset-0 byte semantics, not about total `value_size`. PI-13-3.4b formalizes the offset-0 byte invariant + explicitly declares the `value_size 1 → 8` change as ADDITIVE not VIOLATE. See §6.5 PI-13-3.4b for the full check mechanism.
  - **BPF datapath verifier-acceptance**: existing reads at offset 0 (line 226 + 254) are byte-equivalent: `__u8 *present` becomes `struct allow_entry *entry`, and `if (present)` becomes `if (entry)` — same pointer-null-check shape. New read at offset 4 (`entry->rule_id`) is a 4-byte aligned load on a successfully looked-up pointer — verifier-trivial. The bounded `rule_id` (verifier-required range check before using as array index) lives in `bump_rule` per the datapath wiring contract below.
  - **PI-3.4b-9 fixture-ripple cost is LOW** (Phase A grep finding): only T_RULES_SKELETON_NOT_WIRED.sh and T_EXPORTER_METRICS_FORMAT.sh ctest bodies need surgical fixes (2 ctest EDITs vs brief's ≤5 estimate). NO test writes a 1-byte literal payload via `bpf_map_update_elem` from userspace; all writes happen inside `loader.cpp` populate paths.
  - **Symmetric MAC HASH + CIDR LPM_TRIE** (T.5 OQ #3): the inner-value extension applies to BOTH `xdpmf_allowlist_inner` (MAC HASH) AND `xdpmf_cidr_inner` (CIDR LPM_TRIE). NOT extending CIDR would put MAC and CIDR rule_ids in different shape-spaces — bug-shaped, rejected.

  If verifier rejects (impl smoke-tests during Phase 2; T_VERIFIER_GREEN canary surfaces it): impl peer-DMs architect; fall-back is Option 3 (two-map shadow `mac_to_rule_id` HASH + `cidr_to_rule_id` LPM_TRIE). Option 3 inflates the slice ~1 cycle larger; documented in §7 OOS as the contingent fallback.

- **HG-3.4b-2 — Counter survival across `apply -f` = PRESERVE (Prometheus counter-monotonicity semantic).** **Confirmed.** `rule_counters` is `LIBBPF_PIN_BY_NAME`; pinned at `${PIN_DIR}/<iface>/rule_counters`; on state-b reattach loop, `bpf_map__reuse_fd` opens the existing fd and the kernel-side PERCPU values are preserved. Matches D-3.1-4 reuse_fd discipline (preserves global `stats` PERCPU_ARRAY across `apply -f`). NOT matching MVP-1 global `stats` "reset on attach" semantic — but global `stats` predates the reuse_fd discipline; the consistent post-§5.26 contract is PRESERVE.

  Mechanically: `rule_counters` is the 13th entry in `kManagedMaps[]` (HK-9 dividend); the open_skeleton_only clear-list, the apply_request pin loop, and the apply_request reuse loop all walk the same table — adding the entry is the ONLY refactor cost. Confirms the MVP-3.4.5 HK-9 landmine-removal pays off in this cycle.

- **HG-3.4b-3 — `rule_index.json` sidecar = INCLUDE in cycle 1.** **Confirmed.** Cycle 1 ships the sidecar so the exporter can emit `xdpfilter_rule_match_total{iface, rule_id, action}` with human-readable `action` labels. Sidecar shape per Q2 S1 (defaults-only). Sidecar path per Q3 P1 (`${PIN_DIR}/<iface>/rule_index.json`). Writer: `src/lib/sidecar.{cpp,hpp}` ~150 LOC roll-your-own (D-3.4b-10); NO `nlohmann/json` build dep cycle 1 (brownfield discipline).

- **HG-3.4b-4 — `rules` map atomic-swap (D-3.4-4) = STAY SHARED with clear-and-rewrite.** **Confirmed.** `rules` map is STILL NOT consulted by datapath this cycle (PI-29-3.4b carve-out below). The per-rule counter pipeline reads `rule_id` from the inner-allowlist-value (which is already parallel-swapped via the §5.26/§5.27 `rulesets`/`cidr_rulesets` ARRAY_OF_MAPS mechanism), NOT from the `rules` map. So `rules` needs no atomic-swap. MVP-3.4c future cycle (action-table dispatch) will revisit if datapath consultation makes it load-bearing.

#### §5.31 Q-decisions (mechanism)

##### Q1: `bump_rule(rule_id)` datapath call-site placement → **B3 (unified per-match semantic)**

Confirmed per brief recommendation. **Semantic contract**: each successful match (MAC HASH OR CIDR LPM_TRIE) results in ONE `bump_rule(rule_id)` call, using `rule_id` read from the inner-value of whichever inner-map produced the hit. The `rule_id` value comes from `struct allow_entry::rule_id` at offset 4 of the looked-up inner-value pointer.

**Verifier-friendly C-level layout** (impl picks the exact shape — the SEMANTIC is the contract):

```
// MAC HASH hit branch (replaces existing line 226-230):
struct allow_entry *entry = bpf_map_lookup_elem(inner, &key);
if (entry) {
    bump_rule(entry->rule_id);          // PER-RULE COUNT
    bump_stat(STAT_PASS);                // EXISTING GLOBAL COUNT (preserved)
    return XDP_PASS;
}

// CIDR LPM_TRIE hit branch (replaces existing line 254-258):
struct allow_entry *cidr_hit = bpf_map_lookup_elem(cidr_inner, &cidr_key);
if (cidr_hit) {
    bump_rule(cidr_hit->rule_id);       // PER-RULE COUNT (SAME counter map; symmetric)
    bump_stat(STAT_PASS_CIDR);           // EXISTING GLOBAL COUNT (preserved)
    return XDP_PASS;
}
```

This is the verifier-friendly relaxation of "single call expression" — `bump_rule` is invoked from TWO source-line call-sites that share the SAME inline helper and produce semantically symmetric per-rule counts. If a future cycle refactors to a true single tail call (e.g. via a `pass_with_rule:` label and a shared stack-local `rule_id` variable), it's a refactor that does NOT change the contract.

**`bump_rule` inline helper definition** (adjacent to `bump_stat`):
```
static __always_inline void bump_rule(__u32 rule_id) {
    /* Verifier-required bounds check on ARRAY index (verifier rejects
     * unbounded user-supplied keys into ARRAY maps). XDPMF_ALLOWLIST_MAX=64
     * matches max_entries of rule_counters. */
    if (rule_id >= XDPMF_ALLOWLIST_MAX) return;
    __u64 *v = bpf_map_lookup_elem(&rule_counters, &rule_id);
    if (v) {
        *v += 1;     /* PERCPU: pointer returned is to THIS CPU's slot; no atomic. */
    }
}
```

**Default-action PASS path does NOT bump rule_counters**: a frame that misses BOTH MAC HASH AND CIDR LPM_TRIE and falls through to `defaults[active]=PASS` has no rule_id (there's no rule that matched it) — only `STAT_PASS` increments. Document this explicitly: per-rule counters track per-rule MATCH counts, NOT per-rule decision counts. Operators querying "total passes" via `sum(xdpfilter_packets_total{verdict="pass"}) by (iface)` get the full count; per-rule sum (`sum(xdpfilter_rule_match_total) by (iface)`) is a SUBSET (matched-by-some-rule).

##### Q2: Sidecar JSON schema fields beyond the default → **S1 (defaults-only)**

Confirmed per brief recommendation. Cycle 1 ships exactly the default shape:
```json
{
  "iface": "eth0",
  "schema_version": 1,
  "applied_at": "2026-05-25T10:30:00Z",
  "rules": [
    {"rule_id": 0, "match": {"mac": "aa:bb:cc:dd:ee:ff"}, "action": "pass"},
    {"rule_id": 1, "match": {"cidr": "10.0.0.0/24"}, "action": "pass"},
    {"rule_id": 2, "match": {"mac": "11:22:33:44:55:66"}, "action": "drop"}
  ]
}
```

Field semantics:
- `iface`: string, the operator's `--iface` argument (NOT the optional YAML `interface:` field — they reconcile pre-apply per §5.26).
- `schema_version`: integer literal `1` (hard-coded; future schema changes increment).
- `applied_at`: ISO-8601 UTC timestamp at apply time, format `YYYY-MM-DDTHH:MM:SSZ` (single trailing `Z`; no fractional seconds — for human readability + grep-friendliness in fleet ops).
- `rules`: array of rule objects in source-order (matches the YAML `rules:` block order; useful for human inspection alongside the source config).
- Per-rule object: `rule_id` integer in [0, 63] per Q5 R1; `match` object with EITHER `mac` OR `cidr` (whichever the YAML rule specified — if a rule had BOTH per the §5.27 schema, both keys appear); `action` string `"pass"` or `"drop"`.

S2 (free-form `description`) + S3 (loader/kernel/bpffs metadata) explicitly REJECTED for cycle 1 — additive in future cycles if operator demand surfaces. See §7 OOS NEW FENCE block.

##### Q3: `rule_index.json` sidecar path → **P1 (`${PIN_DIR}/<iface>/rule_index.json`)**  **[SUPERSEDED BY §5.31 EDIT-1 → Q3 = P4 `/run/xdpmacfilter/<iface>/rule_index.json`; see EDIT-1 + D-3.4b-21 below]**

Confirmed per brief recommendation. **Per-iface sidecar pairs with per-iface bpffs pin layout.** The exporter already scans `${XDPMF_BPFFS_ROOT}/<iface>/` for the `stats` map (existing `stats_reader.cpp`); discovering `rule_index.json` and `rule_counters` in the SAME directory is the natural fleet operations pattern. Reviewer's HK-16 startup discovery codepath is the precedent.

**Lifecycle**: rule_index.json survives loader restart (file persists in `tmpfs`-mounted bpffs as long as bpffs is mounted — SAME lifecycle as the pinned BPF maps). On bpffs unmount, both pins and sidecar disappear together — consistent operator mental model.

**Permissions**: written with mode 0644 (operator-readable; needed for `--bpffs-root` non-root scan from exporter). Loader runs as root (CAP_BPF + CAP_NET_ADMIN); the sidecar inherits root ownership but world-read mode 0644 so the CAP_BPF-only exporter (D-3.4-6) can read it.

**Atomic-write idiom**: write to `${PIN_DIR}/<iface>/rule_index.json.tmp`, `fsync(fd)`, `rename(tmp, final)`. Same pattern as the existing `pin_fd` idiom inside loader.cpp for BPF map pins. Ensures partial-write atomicity vs concurrent exporter scrape.

P2 (`/var/lib/xdpmacfilter/<iface>/`) REJECTED for cycle 1 — would require new mkdir + chown + ansible playbook touch + systemd `StateDirectory=` update — coordination cost without clear value over P1. P3 (`/etc/xdpmacfilter/...`) is wrong-shape (config-adjacent is for operator-edited input, not loader-written output).

##### Q4: Action label on `xdpfilter_rule_match_total` → **A3 (action as label)**

Confirmed per brief recommendation. Single series `xdpfilter_rule_match_total{iface, rule_id, action}`. Action is read from the sidecar's `action` field per scrape.

**Prometheus series shape**:
```
# HELP xdpfilter_rule_match_total Total per-rule packet matches by iface and rule_id, labelled with action.
# TYPE xdpfilter_rule_match_total counter
xdpfilter_rule_match_total{iface="eth0",rule_id="0",action="pass"} 12345
xdpfilter_rule_match_total{iface="eth0",rule_id="1",action="pass"} 567
xdpfilter_rule_match_total{iface="eth0",rule_id="2",action="drop"} 89
```

**Cardinality bound**: at most XDPMF_ALLOWLIST_MAX × #ifaces × #actions = 64 × N × 2 series. For a typical fleet (N ≤ 4 ifaces), worst-case 512 series per host — negligible Prometheus storage.

**Sidecar-orphan tolerance** (per /mint-hld Option 3 OQ): if BPF `rule_counters` has a non-zero value at index R but `rule_index.json` does NOT list rule_id R (race window across apply: counter from prior config persists across apply, BUT old rule R is no longer in the new config) → emit `xdpfilter_rule_match_total{iface="<iface>",rule_id="<R>",action="unknown"} <value>`. The `action="unknown"` label is the load-bearing signal: exporter does NOT crash, does NOT loud-warn-per-orphan, does NOT skip the data point. Drop-and-reconcile next scrape; operator alerts can target `action="unknown"` if they want to surface the race window. **Symmetric**: sidecar lists rule_id R but BPF counter is 0 (newly-added rule, no traffic yet) → emit `xdpfilter_rule_match_total{...,action="<from-sidecar>"} 0` (Prometheus convention: emit zeroes for known series).

A1 (separate `xdpfilter_rule_meta` series) REJECTED — pushes join work to operator; metric-relabeling at scrape time is brittle. A2 (split series by action) REJECTED — multiplies metric count, hostile to alert aggregation.

##### Q5: Rule_id allocation policy in loader → **R1 (operator's `id` IS the BPF key directly)**

Confirmed per brief recommendation. **Phase A grep evidence**: `src/lib/config.cpp:204` already validates `rule.id >= XDPMF_ALLOWLIST_MAX` and rejects with ConfigError (= 9). Range [0, 63] is enforced at config-validation time. The `rule_counters[k]` ARRAY index space and the operator's YAML `id:` namespace are IDENTICAL. Sparse usage (operator uses `id: 0, 5, 17`) is the normal case; the unused slots stay at counter value 0 (PERCPU init).

**Datapath implication**: when a packet matches via inner-allowlist HASH or CIDR LPM_TRIE, the looked-up `struct allow_entry::rule_id` is written by the loader to be exactly `config.rules[i].id` for the matching rule. `bump_rule(rule_id)` then bumps `rule_counters[rule_id]`. Operator's mental model is: "id 5 in my YAML maps to `rule_counters[5]` in `bpftool map dump`".

**Counter-survival semantic (HG-3.4b-2)**: across applies, if operator's rule with `id: 5` is REMOVED, the next apply's `rule_counters[5]` is NOT reset by the loader (only the inner-allowlist's slot for that MAC/CIDR is removed). `rule_counters[5]` continues to carry its prior count value. Operators querying `xdpfilter_rule_match_total{rule_id="5"}` after the rule's removal see the orphan-label (`action="unknown"`) until next apply OR until counter is explicitly zeroed (out of scope — counter-zeroing API is MVP-3.5+).

R2 (source-order allocation) REJECTED — violates counter-monotonicity on YAML re-ordering (operator surprise). R3 (sort-by-name) REJECTED — schema-v2 / Option 4 / MVP-future scope.

#### §5.31 FileList (brownfield DIFF)

##### NEW (created this slice)

| Path | Role (one line) | Language | LOC est |
|---|---|---|---|
| `src/lib/sidecar.hpp` | rule_index.json writer API (one public function: `write_rule_index(iface, bpffs_root, cfg)`) | C++23 | 30 |
| `src/lib/sidecar.cpp` | rule_index.json writer impl: roll-your-own JSON emitter + atomic write idiom + ISO-8601 timestamp (D-3.4b-10) | C++23 | 150 |
| `src/exporter/sidecar_reader.hpp` | sidecar parser API: `parse_rule_index(path) → std::vector<RuleMeta>` (or per-rule_id map) | C++23 | 25 |
| `src/exporter/sidecar_reader.cpp` | line-oriented regex extraction of `{rule_id, action, match}` from rule_index.json (D-3.4b-14 — sidesteps full-JSON-parser) | C++23 | 80 |
| `src/exporter/rule_counters_reader.hpp` | PERCPU sum reader for `rule_counters` map: `read_rule_counters(bpffs_root)` overload | C++23 | 25 |
| `src/exporter/rule_counters_reader.cpp` | scan `${bpffs_root}/<iface>/rule_counters` pins; libbpf PERCPU lookup + sum-across-CPUs for all 64 slots | C++23 | 100 |
| `tests/T_RULE_COUNTER_MAC_HIT_BUMPS.sh` | §6.47 test: MAC-HASH-hit increments `rule_counters[rule_id]`; negation: other rule_ids stay 0 | bash | 100 |
| `tests/T_RULE_COUNTER_CIDR_HIT_BUMPS.sh` | §6.48 test: CIDR-LPM_TRIE-hit increments `rule_counters[cidr_rule_id]`; negation: MAC-only hit leaves CIDR rule_id counter at 0 | bash | 110 |
| `tests/T_RULE_COUNTER_SURVIVES_APPLY.sh` | §6.49 test: apply config A; bump counters; apply same config (swap); assert counters PRESERVED (HG-3.4b-2 canary) | bash | 110 |
| `tests/T_SIDECAR_JSON_SHAPE.sh` | §6.50 test: apply known config; cat rule_index.json; jq-validate per-rule shape + top-level fields | bash | 90 |
| `tests/T_EXPORTER_RULE_LABELS.sh` | §6.51 test: exporter scrapes /metrics; assert `xdpfilter_rule_match_total{iface,rule_id,action}` series present with valid Prometheus label syntax + sidecar-orphan tolerance | bash | 130 |
| `tests/T_DROP_RULE_BUMPS_COUNTER.sh` | §6.52 test: config with PASS + DROP rules; verify per-rule counter for drop rule is bumped via inner-value's rule_id (drop rule is in inner-allowlist via §5.26 schema cycle 2 carry-through if MAC matches) | bash | 100 |
| `tests/fixtures/config_per_rule_counters.yaml` | NEW test fixture: 4 rules with explicit `id:` values (sparse: 0, 5, 17, 42), mix of MAC-only + CIDR-only + mixed | YAML | 30 |

##### EDITED (existing files touched this slice)

| Path | Role (one line) | What changes |
|---|---|---|
| `src/bpf/mac_filter.bpf.c` | XDP BPF program + .maps block | (i) Replace `__type(value, __u8)` at line 55 with `__type(value, struct allow_entry)` for `xdpmf_allowlist_inner` (MAC HASH inner template). (ii) Replace `__type(value, __u8)` at line 95 with `__type(value, struct allow_entry)` for `xdpmf_cidr_inner` (CIDR LPM_TRIE inner template). (iii) ADD new `rule_counters` PERCPU_ARRAY[XDPMF_ALLOWLIST_MAX=64] of `__u64`, LIBBPF_PIN_BY_NAME, in `.maps` block. (iv) ADD `static __always_inline void bump_rule(__u32 rule_id)` helper adjacent to `bump_stat` (per Q1 contract above). (v) Replace `__u8 *present = bpf_map_lookup_elem(inner, &key)` at line 226 with `struct allow_entry *entry = bpf_map_lookup_elem(inner, &key); if (entry) { bump_rule(entry->rule_id); bump_stat(STAT_PASS); return XDP_PASS; }`. (vi) Replace `__u8 *cidr_hit = bpf_map_lookup_elem(cidr_inner, &cidr_key)` at line 254 with `struct allow_entry *cidr_hit = bpf_map_lookup_elem(cidr_inner, &cidr_key); if (cidr_hit) { bump_rule(cidr_hit->rule_id); bump_stat(STAT_PASS_CIDR); return XDP_PASS; }`. NO change to default-fallthrough path (line 263-273); NO change to STAT_DROP_DENY / STAT_DROP_MALFORMED counters; NO new XDP verdict. **First substantive `mac_filter_prog` function-body edit since MVP-3.2.** PI-28 RELAXES with documented carve-out (PI-28-3.4b — adds bump_rule calls + inner-value field access at offset 4 — see §6.5). |
| `src/common/mac_filter.h` | Shared header (BPF + userspace) | ADD `struct allow_entry { unsigned char present; unsigned char _pad[3]; unsigned int rule_id; }` (note: `unsigned int` not `__u32` for shared-header convention per §5.29 D-3.4-3); ADD `#define XDPMF_MAP_RULE_COUNTERS_NAME "rule_counters"`; ADD `#define XDPMF_RULE_COUNTERS_MAX XDPMF_ALLOWLIST_MAX` (=64, alias). NO modification to existing `struct rule_entry`, `struct action_entry`, `enum xdpmf_action_type`, `struct xdpmf_mac`, `struct xdpmf_cidr_v4`, `enum mac_filter_stat`, or any existing `XDPMF_MAP_*_NAME` / `XDPMF_*_MAX` constants. PI-10-3.4b additive-only. |
| `src/lib/loader.cpp` | Apply orchestrator + kManagedMaps table + populate helpers | (a) `kManagedMaps[]` literal-array at line 145-158 gains 13th entry: `{ &SkelMapsT::rule_counters, XDPMF_MAP_RULE_COUNTERS_NAME, false }` (inserted alphabetically OR at end before legacy-alias — impl picks). Table comment count updates 12 → 13. (b) `populate_inner_slot` signature CHANGES to carry rule_id per entry: caller passes `std::vector<MacRulePair>` (or similar — impl picks shape per D-3.4b-15) instead of `std::vector<xdpmf_mac>`; body writes `struct allow_entry{.present=1, ._pad={}, .rule_id=pair.rule_id}` per entry. (c) `populate_cidr_inner_slot` symmetric signature change: carries rule_id per entry; writes `struct allow_entry` per entry. (d) `apply_request` body extends the existing rule-extraction step to ALSO produce per-rule rule_id values alongside the deduplicated MAC + CIDR vectors (rule_id IS `rule.id` per Q5 R1). (e) `apply_request` adds a NEW step after the active_idx flip (or before — impl picks per D-3.4b-16): invoke `sidecar::write_rule_index(req.iface, ${BPFFS_ROOT}, req.config)` to emit/refresh rule_index.json. Sidecar-write failure is non-fatal (LOG to stderr with `WARN: rule_index.json write failed: <errno>`; apply continues + exits 0 — sidecar's absence degrades exporter to `action="unknown"` labels, NOT a fatal apply error per D-3.4b-17). (f) Drop the legacy `populate_rules_skeleton` + `populate_action_table` if architect chooses (D-3.4b-18 — they were skeleton-only per §5.29; this slice does NOT consult rules/action_table from datapath, but per HG-3.4b-4 the `rules` map STAYS populated for forward-compat with cycle 2/3). **Default: KEEP `populate_rules_skeleton` + `populate_action_table` calls UNCHANGED** — `rules` + `action_table` maps continue to be populated identically to §5.29 (per HG-3.4b-4 confirmation). NO change to: §5.4 state-machine, §5.19 name-check, §5.22 tag-check + O_PATH, §5.24 kernel-version probe, §5.26 trust_model parse+log, attach()/detach() public bodies, the special-pin legacy alias path. Reviewer's regional-diff fence: allowed scopes = {kManagedMaps[] table 12→13 entries, populate_inner_slot body + signature, populate_cidr_inner_slot body + signature, apply_request rule-extraction step, apply_request sidecar-write step, optional new private helpers for the rule_id-carrying intermediate vectors}. |
| `src/lib/config.cpp` | Config validator | **VERIFY** (not modify): existing `rule.id >= XDPMF_ALLOWLIST_MAX` check at line 204 is preserved + load-bearing for Q5 R1. NO modification. If impl finds a code path where `rule.id` is silently clipped or remapped, SendMessage architect (would invalidate Q5 R1). Expected: ZERO diff in config.cpp. |
| `src/lib/config.hpp` | Config types | UNCHANGED (PI-7-3.4b-hpp ZERO diff continues — Phase A grep confirms `Rule::id` field already present at line 42; brief's "Config::Rule gains rule_id loader-internal field" was OVERSTATED — see D-3.4b-11). |
| `src/lib/loader.hpp` | Loader public API | UNCHANGED. `AttachConfig` / `DetachConfig` / `attach()` / `detach()` / `LoaderError` enum: ALL byte-equivalent. **PI-7-3.4b-hpp — 6th consecutive ZERO-diff cycle**. |
| `src/exporter/stats_reader.cpp` | Existing PERCPU sum reader for global `stats` | EXTEND ONLY if impl chooses to share PERCPU-sum scaffolding with new `rule_counters_reader.cpp`. Default: keep `stats_reader.cpp` byte-equivalent; new `rule_counters_reader.cpp` duplicates the PERCPU-sum scaffolding (~60 LOC), which is cycle 1 budget-acceptable. If impl factors out a shared helper (e.g. `percpu_sum_pinned_map(path, max_entries, cpu_count)`), it lives in a NEW translation unit (`src/exporter/percpu_sum.{cpp,hpp}`); SendMessage architect for sign-off. Default expectation: ZERO change to `stats_reader.cpp`. |
| `src/exporter/http.cpp` | Exporter per-scrape handler (`handle_connection` `/metrics` arm) | ADD per-scrape calls: `read_rule_counters(bpffs_root)` + `parse_rule_index(/run/xdpmacfilter/<iface>/rule_index.json)` (per EDIT-1 D-3.4b-21) for each discovered iface; pass to `emit_metrics()` for the new series. Existing `xdpfilter_packets_total` emission preserved. `--version` literal bump (0.6.1 → 0.7.0) flows via shared `version.h` per §5.25 P3 (CMakeLists.txt VERSION change auto-propagates; no main.cpp edit needed). [Phase 4.5 OOT inline-merge — was `src/exporter/main.cpp` in design.md initial draft; corrected to `http.cpp` per impl's operationally-correct placement of the per-scrape codepath in `handle_connection`. `src/exporter/main.cpp` stays UNCHANGED this slice (PI-7-3.4b-cpp extends one more file to ZERO diff).] |
| `src/exporter/prom_format.cpp` | Prometheus text-format emitter | EXTEND `emit_metrics()` signature to accept `const std::vector<RuleCountersSample>&` and `const std::map<std::string, std::vector<RuleMeta>>&` (or analogous shapes — impl picks per D-3.4b-19) alongside the existing `std::vector<StatsSample>`. Output gains the new HELP+TYPE+samples block for `xdpfilter_rule_match_total` after the existing `xdpfilter_packets_total` block. Empty case (no rules in any sidecar) → emit ONLY HELP+TYPE for the new series, no samples; symmetric to existing empty-fleet behavior. |
| `src/exporter/prom_format.hpp` | Emitter declaration | EXTEND signature per .cpp change. |
| `CMakeLists.txt` | Top-level build | (a) `project(xdpmacfilter VERSION 0.6.1 ...)` → `project(xdpmacfilter VERSION 0.7.0 ...)`; (b) `xdpmf_internal` target list extends with `src/lib/sidecar.cpp`; (c) `xdpmf-exporter` target extends with `src/exporter/sidecar_reader.cpp` + `src/exporter/rule_counters_reader.cpp`; (d) NO other CMake changes (no new compile flags, no new external deps). |
| `CHANGELOG.md` | Version history | NEW `## [0.7.0] - 2026-05-NN` section per Keep-a-Changelog. Sub-groups: **Added** — per-rule counters (`rule_counters` PERCPU_ARRAY[64]); inner-allowlist-value `struct allow_entry` with embedded `rule_id`; datapath `bump_rule(rule_id)` wiring; loader-written `rule_index.json` sidecar; exporter `xdpfilter_rule_match_total{iface, rule_id, action}` Prometheus series; 6 new ctests + 1 new fixture. **Changed** — `xdpmf_allowlist_inner` / `xdpmf_cidr_inner` inner-value `__u8 → struct allow_entry` (PI-13-3.4b adjudication: PASS as additive; `value_size 1 → 8`; offset-0 byte byte-equivalent to PI-27); `kManagedMaps[]` table grows 12 → 13 entries (HK-9 landmine refactor dividend). **Internal** — `populate_inner_slot` + `populate_cidr_inner_slot` signatures carry rule_id alongside the key; `apply_request` writes sidecar after each apply. Build-pace table gains a row for MVP-3.4b. |
| `tests/CMakeLists.txt` | ctest registration | 6 new `add_test(...)` entries (§6.47..§6.52); RESOURCE_LOCK `xdp_fixture` for the 4 tests that touch veth (T_RULE_COUNTER_MAC_HIT_BUMPS, T_RULE_COUNTER_CIDR_HIT_BUMPS, T_RULE_COUNTER_SURVIVES_APPLY, T_DROP_RULE_BUMPS_COUNTER); RESOURCE_LOCK `xdp_fixture` + `exporter_port_9417` for T_EXPORTER_RULE_LABELS; T_SIDECAR_JSON_SHAPE shares xdp_fixture lock OR runs against mocked bpffs root (tester's call); ZERO modification of the 44 non-PI-3.4b-9-EDITED `add_test` entries; the 2 EDITED ctest BODIES (T_RULES_SKELETON_NOT_WIRED, T_EXPORTER_METRICS_FORMAT) keep their existing CMakeLists entries byte-equivalent. |
| `tests/T_RULES_SKELETON_NOT_WIRED.sh` | §6.42 — `rules` + `action_table` populated but datapath byte-equivalent to MVP-3.2 | **PI-3.4b-9 surgical fix #1** (HG-3.4b-1 PASS-adjudication-forced edit): line 14 comment "(the bpftool dump of the active allowlist returns 1-byte values)" → "(the bpftool dump of the active allowlist returns 8-byte `struct allow_entry` values per §5.31 PI-13-3.4b adjudication)". Line 297 stderr message in the FAIL[fC] branch — the prose "(ii) the inner-value shape was extended to embed rule_id (PI-27/PI-13-3.4 violation, defer broken)" becomes a NO-OP scenario post-§5.31 — rewrite to: "(ii) the apply path INCORRECTLY added the drop-rule MAC to the inner allowlist (per §5.26 schema cycle 2 'drop rules do NOT populate inner-allowlist' contract — that contract is preserved post-§5.31)". The ASSERTION on MAC_C absence from the inner-allowlist is BYTE-EQUIVALENT (no test logic change). Body diff is comment-only + one stderr-string rewrite (~5 LOC EDIT). |
| `tests/T_EXPORTER_METRICS_FORMAT.sh` | §6.37 — `/metrics` Prometheus format | **PI-3.4b-9 surgical fix #2** (HK-8-forced version-literal bump per MVP-3.4.5 EDIT-3 precedent): line 100 literal `"xdpmf-exporter 0.6.1"` → `"xdpmf-exporter 0.7.0"`. Line 21-22 comment updates the version-bump epoch reference (§5.30 → §5.31). Body diff is 2 LOC EDIT (the literal + comment). |

##### UNCHANGED-BUT-AFFECTED (zero git-diff fence; behaviour must hold)

| Path | Why it matters |
|---|---|
| `src/lib/loader.hpp` | **PI-7-3.4b-hpp — 6th consecutive ZERO-diff cycle** (MVP-3.1 +1; MVP-3.2/3.3/3.4/3.4.5/3.4b = 0). `git diff main -- src/lib/loader.hpp` MUST show ZERO output. Any diff = `[INVARIANT-VIOLATED]`. |
| `src/lib/config.hpp` | UNCHANGED. `Config::Rule::id` already present at line 42 (`std::uint32_t`); Q5 R1 uses this field directly. NO new field. Brief's wording overstated; D-3.4b-11 documents the correction. |
| `src/lib/loader.cpp` outside the EDITED regions enumerated above | UNCHANGED. `attach()` / `detach()` public-API function bodies; §5.4 state-machine; §5.19 name-check; §5.22 tag-check + O_PATH path-discipline; §5.24 kernel-version probe; §5.26 trust_model parse+log; §5.27 CIDR-axis active_idx flip mechanism; the special legacy-alias pin at line 1761-1778; §5.29 `populate_rules_skeleton` + `populate_action_table` calls (HG-3.4b-4 — these maps STAY populated unchanged this cycle); §5.30 HK-3 compile-gate, HK-9 kManagedMaps[] table structure (only ONE entry added; existing 12 entries byte-equivalent), HK-4 bypass audit line. Reviewer's regional-diff fence per PI-7-3.4b-cpp below. |
| `src/lib/cidr.cpp`, `src/lib/cidr.hpp` | UNCHANGED. CIDR-axis match logic unchanged; only the LPM_TRIE inner-VALUE shape changed (in mac_filter.bpf.c + loader.cpp populate path). |
| `src/lib/yaml_subset.cpp`, `src/lib/yaml_subset.hpp` | UNCHANGED. Schema is byte-equivalent (Q5 R1: rule.id is already in [0, 63] schema; no new keys). |
| `src/cli/*` (attach.cpp, detach.cpp, apply.cpp, bypass.cpp, cli.cpp, main.cpp) | UNCHANGED. No CLI surface change. `xdpmacfilter apply -f <path>` and `xdpmacfilter attach` semantics byte-equivalent; the only new effect is the implicit `rule_index.json` write during apply (D-3.4b-17 — non-fatal warn-and-continue if write fails). |
| `src/exporter/stats_reader.{cpp,hpp}` | UNCHANGED. The new `rule_counters_reader.{cpp,hpp}` is sister-shape, NOT a modification of stats_reader. Existing `xdpfilter_packets_total` series byte-equivalent. PI-31-3.4b — exporter READ-ONLY contract preserved. |
| `src/exporter/http.{cpp,hpp}` | UNCHANGED. HTTP routing + bind + accept loop preserved. The new metric series is emitted as additional lines in the `/metrics` response body; HTTP framing unchanged. |
| `src/bpf/mac_filter.bpf.c` outside the EDITED regions (lines 55, 95, 226, 254, .maps block) | UNCHANGED. `bump_stat` helper, defaults-map fallthrough, STAT_DROP_DENY / STAT_DROP_MALFORMED branches, ETH_P_IP check, the existing 6 `unlikely()` annotations from MVP-3.4.5 HK-5. **NEW `bump_rule` is ADDITIVE.** `mac_filter_prog` body BYTE-EQUIVALENT to MVP-3.4.5 EXCEPT the 4 enumerated edit-points (PI-28-3.4b carve-out). |
| `systemd/xdpmacfilter@.service` + `systemd/xdpmf-exporter.service` | UNCHANGED. Exporter discovers new `rule_counters` pin via existing `${XDPMF_BPFFS_ROOT}/<iface>/` scan; no unit edit required. |
| `ansible/xdpmacfilter-deploy.yml`, `ansible/templates/xdpfilter-config.yaml.j2` | UNCHANGED. The Jinja template already emits `id:` for each rule (§5.28 §5.27-compat template); the loader picks it up per Q5 R1 with NO Ansible touch. |
| `docs/FLEET_DEPLOYMENT.md` | UNCHANGED this slice. The new metric series is documented in CHANGELOG `[0.7.0]` entry. A future docs pass (separate manual user-driven scope) may add a Prometheus-alert-semantic section for `xdpfilter_rule_match_total`. |
| The 44 non-EDITED pre-§5.31 ctest BODIES (out of 46 total) | UNCHANGED. `git diff main -- tests/T_*.sh` shows 2 EDITED files (T_RULES_SKELETON_NOT_WIRED, T_EXPORTER_METRICS_FORMAT) + 6 NEW files. The other 44 ctest bodies byte-equivalent. PI-34-3.4b strict-superset with 2-ctest-body-EDIT carve-out per PI-3.4b-9. |
| `tests/lib/common.sh`, `tests/lib/read_stats.py`, `tests/lib/pins.sh.in` | UNCHANGED. `read_stats.py` is for global `stats` map (4-slot); new `rule_counters` reader is a sister tool — impl picks whether to add `tests/lib/read_rule_counters.py` as a NEW helper (additive) OR have each ctest do `bpftool map dump pinned ${PIN_DIR}/<iface>/rule_counters --json | jq` inline. Default: NEW helper script `tests/lib/read_rule_counters.py` (parallels read_stats.py; ~50 LOC; counts as NEW file, not an EDIT). Tester's call. |
| §5.4 / §5.19 / §5.22 / §5.24 trust+identity gates | UNCHANGED. The new map declaration + inner-value extension are detected and verified by all existing gate codepaths transparently (libbpf handles the map-shape diff at load time; tag-check is byte-equivalent at the per-iface attach because the BPF object's tag is recomputed from the new bytecode). PI-1..PI-5 all still pass. |

#### §5.31 DataStructures

##### Inner-allowlist value shape (BPF + userspace shared)

In `src/common/mac_filter.h`:
```
struct allow_entry {
    unsigned char present;        /* offset 0, size 1: 0x01 = occupied, 0x00 = empty.
                                     PI-27 byte-equivalent: byte-for-byte same as
                                     the prior `__u8 present` at offset 0. */
    unsigned char _pad[3];        /* offsets 1-3, size 3: explicit padding. Zero-init
                                     by ABI on struct-init `{}`; loader writes via
                                     fully-initialized struct (no uninitialized-byte
                                     verifier concern). */
    unsigned int  rule_id;        /* offsets 4-7, size 4: rule_id in [0, 63]. Read
                                     by datapath for bump_rule. `unsigned int` (not
                                     `__u32`) for shared-header BPF+userspace convention
                                     per §5.29 D-3.4-3. */
};                                /* total: 8 bytes */
```

Used as the inner-VALUE for BOTH `xdpmf_allowlist_inner` (MAC HASH) AND `xdpmf_cidr_inner` (CIDR LPM_TRIE) per T.5 OQ #3.

##### `rule_counters` BPF map declaration

In `src/bpf/mac_filter.bpf.c` (`.maps` block, adjacent to existing `stats` map):
```
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, XDPMF_ALLOWLIST_MAX);     /* = 64; mirrors rule.id range */
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rule_counters SEC(".maps");
```

Pinned at `${PIN_DIR}/<iface>/rule_counters`. PERCPU semantics: 64 slots × N CPUs × 8 bytes = ~16 KiB per attached iface (negligible).

##### `rule_index.json` schema (sidecar — written by loader, read by exporter)

```json
{
  "iface": "<string; same as --iface>",
  "schema_version": 1,
  "applied_at": "<ISO-8601 UTC: YYYY-MM-DDTHH:MM:SSZ>",
  "rules": [
    {
      "rule_id": <int in [0, 63]>,
      "match": { "mac": "<lowercase-hex MAC AA:BB:...>" }
               or { "cidr": "<dotted-quad IPv4/prefixlen>" }
               or BOTH keys (if the rule had both),
      "action": "pass" | "drop"
    },
    ...
  ]
}
```

**Stable ordering**: `rules` array is in source-order of the operator's YAML (preserves `Config::rules` vector order); within each rule object, key order is `rule_id, match, action` — useful for the line-oriented exporter regex extraction (D-3.4b-14). Per-line one-rule format is preferred but not strictly required (jq-validators accept multi-line too).

##### `kManagedMaps[]` table growth (loader.cpp line 145-158)

Post-§5.31: 13 entries (was 12 per §5.30 HK-9):
```cpp
constexpr ManagedMapEntry kManagedMaps[] = {
    { &SkelMapsT::allowlist_a,      XDPMF_MAP_INNER_A_NAME,             false },
    { &SkelMapsT::allowlist_b,      XDPMF_MAP_INNER_B_NAME,             false },
    { &SkelMapsT::rulesets,         XDPMF_MAP_RULESETS_OUTER_NAME,      false },
    { &SkelMapsT::cidr_allowlist_a, XDPMF_MAP_CIDR_INNER_A_NAME,        false },
    { &SkelMapsT::cidr_allowlist_b, XDPMF_MAP_CIDR_INNER_B_NAME,        false },
    { &SkelMapsT::cidr_rulesets,    XDPMF_MAP_CIDR_RULESETS_OUTER_NAME, false },
    { &SkelMapsT::active_idx,       XDPMF_MAP_ACTIVE_IDX_NAME,          false },
    { &SkelMapsT::defaults,         XDPMF_MAP_DEFAULTS_NAME,            false },
    { &SkelMapsT::stats,            XDPMF_MAP_STATS_NAME,               false },
    { &SkelMapsT::rules,            XDPMF_MAP_RULES_NAME,               false },
    { &SkelMapsT::action_table,     XDPMF_MAP_ACTION_TABLE_NAME,        false },
    { &SkelMapsT::rule_counters,    XDPMF_MAP_RULE_COUNTERS_NAME,       false },  // §5.31 NEW
    { &SkelMapsT::allowlist,        XDPMF_MAP_ALLOWLIST_NAME,           true  },
};
```

Position is at index 11 (before the legacy alias). Insertion line is 1; all 3 call-site loops (clear, pin, reuse) walk the table automatically. **The MVP-3.4.5 HK-9 dividend is this one-line insertion.**

##### Exporter-internal data shape (sister to existing `stats_reader::StatsSample`)

```cpp
// src/exporter/rule_counters_reader.hpp
namespace xdpmf::exporter {

struct RuleCountersSample {
    std::string   iface;
    std::uint64_t counters[XDPMF_ALLOWLIST_MAX] = {};   /* index k = rule_id; value = PERCPU-summed count */
};

[[nodiscard]] std::vector<RuleCountersSample> read_rule_counters(std::string_view bpffs_root) noexcept;

}  // namespace xdpmf::exporter
```

```cpp
// src/exporter/sidecar_reader.hpp
namespace xdpmf::exporter {

struct RuleMeta {
    std::uint32_t rule_id;
    std::string   action;     /* "pass" | "drop" */
    std::string   match_kind; /* "mac" | "cidr" | "both" — informational, not currently used by exporter */
};

/* Reads rule_index.json at <path>; returns empty vector if file missing or
 * unreadable (PI-32-3.4b sidecar-orphan tolerance — exporter degrades to
 * action="unknown" labels, NOT a crash). Logs ONE stderr WARN line on
 * first-time-per-process missing-sidecar discovery per iface. */
[[nodiscard]] std::vector<RuleMeta> parse_rule_index(std::string_view path) noexcept;

}  // namespace xdpmf::exporter
```

#### §5.31 Interfaces

##### `bump_rule(rule_id)` datapath contract (per Q1 B3)

Per-match per-rule counter bump. Signature: `static __always_inline void bump_rule(__u32 rule_id)` in `src/bpf/mac_filter.bpf.c`. Verifier-required range check on `rule_id < XDPMF_ALLOWLIST_MAX` before PERCPU map lookup. PERCPU pointer returned → `*v += 1` (no atomic, per-CPU local). NULL-check on the PERCPU lookup result is verifier-required and folded into the helper. **Call-sites**: TWO syntactic call-sites (MAC HASH-hit branch + CIDR LPM_TRIE-hit branch); SEMANTICALLY a single per-match contract.

##### `sidecar::write_rule_index()` contract (loader-side)

```cpp
// src/lib/sidecar.hpp
namespace xdpmf::sidecar {

/* Writes rule_index.json atomically under ${bpffs_root}/<iface>/rule_index.json.
 *
 * Idempotent: overwrites prior file in-place via rename-into-place. Atomic
 * write: write to <path>.tmp, fsync(fd), close, rename(<path>.tmp, <path>).
 * NEVER throws — sidecar-write failures are non-fatal per D-3.4b-17:
 * loader logs `xdpmacfilter: WARN: rule_index.json write failed: <errno>`
 * on stderr and returns silently. Exporter degrades to action="unknown"
 * labels for the affected iface (PI-32-3.4b orphan tolerance).
 *
 * Schema_version emitted = 1. Timestamp uses CLOCK_REALTIME ISO-8601 UTC.
 * File mode 0644 (operator + exporter readable). */
void write_rule_index(std::string_view iface,
                      std::string_view bpffs_root,
                      const Config&    cfg) noexcept;

}  // namespace xdpmf::sidecar
```

Roll-your-own JSON emitter per D-3.4b-10 (no `nlohmann/json` dep this slice).

##### `sidecar_reader::parse_rule_index()` contract (exporter-side)

Per D-3.4b-14: line-oriented regex extraction, NOT full JSON parse. Reads file content; for each line that matches an ERE like `^\s*\{"rule_id":\s*([0-9]+),\s*"match":\s*\{[^\}]*\},\s*"action":\s*"(pass|drop)"\s*\}\s*,?\s*$`, captures `(rule_id, action)`. The `match` object is parsed naively into `match_kind` (looks for `"mac"` substring → `"mac"`, `"cidr"` substring → `"cidr"`, both → `"both"`). The top-level `iface`, `schema_version`, `applied_at` fields are NOT consumed by the exporter cycle 1 (informational; future cycle MAY add a per-scrape staleness alert if `applied_at` > N hours old).

Cycle 1 budget discipline: ~80 LOC regex-extract is significantly less than a full JSON parser (~300+ LOC) and is robust against the stable writer's output shape. The writer's contract (D-3.4b-20) is "one-rule-per-line shape" — the regex assumes it. If a future cycle adds nested fields per rule, the writer + reader can co-evolve.

##### Prometheus output shape

Per Q4 A3 above. The exporter's `/metrics` output post-§5.31 grows with a NEW block:
```
# HELP xdpfilter_rule_match_total Total per-rule packet matches by iface and rule_id, labelled with action.
# TYPE xdpfilter_rule_match_total counter
xdpfilter_rule_match_total{iface="eth0",rule_id="0",action="pass"} 12345
xdpfilter_rule_match_total{iface="eth0",rule_id="5",action="pass"} 67
xdpfilter_rule_match_total{iface="eth0",rule_id="17",action="drop"} 89
xdpfilter_rule_match_total{iface="eth0",rule_id="42",action="unknown"} 3   # orphan
```

Block ordering: existing `xdpfilter_packets_total` HELP+TYPE+samples FIRST, then `xdpfilter_rule_match_total` HELP+TYPE+samples (Prometheus tolerates either order; emitting global-stats first preserves byte-equivalence of the existing prefix for any operator scrapers that pin head-of-output substring matches).

##### Loader API (`src/lib/loader.hpp`) — ZERO diff (PI-7-3.4b-hpp 6th consecutive cycle)

`AttachConfig` / `DetachConfig` / `attach()` / `detach()` / `LoaderError` enum: ALL UNCHANGED. The new sidecar-write happens INSIDE `apply_request` body — no public symbol added. The new exporter helpers live in `src/exporter/` and do NOT include `loader.hpp` (they include `common/mac_filter.h` for `XDPMF_RULE_COUNTERS_MAX` + `XDPMF_MAP_RULE_COUNTERS_NAME` only).

##### Config API (`src/lib/config.hpp`) — ZERO diff (Phase A correction)

`Config::Rule::id` field at line 42 already serves Q5 R1's needs. No new struct field, no new validator (the `rule.id >= XDPMF_ALLOWLIST_MAX` check at config.cpp:204 is load-bearing + preserved). D-3.4b-11 documents the brief's overstatement.

#### §5.31 Decisions (with rationale)

##### D-3.4b-1 — PI-13-3.1 adjudication: PASS as additive — because

Per HG-3.4b-1 confirmation. The byte-by-byte layout (`present` at offset 0; `_pad[3]` at offsets 1-3; `rule_id` at offsets 4-7; total 8 bytes) preserves PI-27's prior contract at offset 0: a `bpftool map dump ... format c | head -c 1` still returns `0x01` for occupied slots. The strict-byte-shape reading of PI-27 was about offset-0 byte semantics, not about total `value_size`. Extending `value_size` from 1 → 8 with offset-0 byte-equivalence is ADDITIVE under any reasonable reading. **Verifier acceptance**: 4-byte read at offset 4 on a successfully-looked-up inner pointer is verifier-trivial; the bounded `rule_id` range check happens in `bump_rule` before any ARRAY index use. Phase A grep confirms ZERO tests write a literal `present=1` payload from userspace (all such writes happen inside loader.cpp); fixture-ripple cost is bounded to 2 ctest body EDITs (T_RULES_SKELETON_NOT_WIRED comment + T_EXPORTER_METRICS_FORMAT version literal).

##### D-3.4b-2 — Counter survival across apply via PIN_BY_NAME + reuse_fd — because

Per HG-3.4b-2 confirmation + D-3.1-4 reuse_fd discipline. `rule_counters` joins the 12 existing maps in `kManagedMaps[]`; all 3 call-site loops (clear, pin, reuse) walk the table. State-b reattach preserves the PERCPU values intact via `bpf_map__reuse_fd` — Prometheus counter-monotonicity holds. Tester locks this contract via T_RULE_COUNTER_SURVIVES_APPLY (load-bearing canary per /mint-hld Hidden Assumption #4).

##### D-3.4b-3 — rule_index.json sidecar INCLUDED in cycle 1 — because

Per HG-3.4b-3 confirmation. Without sidecar, exporter's `xdpfilter_rule_match_total` labels can only carry bare integer `rule_id="N"` — no human-readable `action` or `match` context. Operators would have to join with their external config to interpret. Cycle 1 cost (~150 LOC writer + ~80 LOC line-regex reader = ~230 LOC) is modest and pays off immediately at the operator UX layer. The sidecar PATH (Q3 P1) + SHAPE (Q2 S1) + READER (D-3.4b-14 line-regex) are all decided concretely — impl has no Open Qs to escalate.

##### D-3.4b-4 — `rules` map STAYS SHARED with clear-and-rewrite — because

Per HG-3.4b-4 confirmation. The per-rule counter pipeline reads `rule_id` from the inner-allowlist-value (which IS parallel-swapped via §5.26/§5.27 `rulesets`/`cidr_rulesets`). `rules` map remains skeleton-only — populated for forward-compat with MVP-3.4c action-dispatch, NOT consulted by datapath. PI-29-3.4b carve-out states this explicitly. MVP-3.4c future cycle will revisit if action_table lookup becomes load-bearing.

##### D-3.4b-5 — Unified bump_rule per-match semantic (Q1 B3) — because

Two source-line call-sites (MAC HASH-hit branch + CIDR LPM_TRIE-hit branch) calling the SAME `bump_rule` helper with the SAME rule_id-extraction shape. Verifier-friendly: each call-site dereferences a freshly-looked-up inner pointer + reads rule_id at offset 4 in the local stack-allocated copy chain. Symmetric MAC/CIDR from cycle 1, no follow-up needed, no behavior asymmetry. B1 (two literally-duplicate call expressions) is the worse readable shape; B2 (only MAC, defer CIDR) is the "ship half the feature" anti-pattern.

##### D-3.4b-6 — Sidecar defaults-only schema (Q2 S1) — because

Cycle 1 ships the minimum the exporter needs (rule_id + action label). S2 description-field is operator-UX nice-to-have; gating on demand. S3 deployment-metadata is debug-tool nice-to-have; gating on demand. Cycle 1 brownfield budget discipline prefers narrow scope; future cycles widen as use cases surface.

##### D-3.4b-7 — Per-iface bpffs sidecar path (Q3 P1) — because  **[SUPERSEDED BY D-3.4b-21 — see §5.31 EDIT-1 Phase B platform-constraint correction below]**

`${PIN_DIR}/<iface>/rule_index.json` pairs naturally with the existing `${PIN_DIR}/<iface>/stats`, `${PIN_DIR}/<iface>/allowlist_a/b`, etc. Exporter discovery via the EXISTING per-iface scan loop — zero new filesystem touchpoints. bpffs tmpfs lifecycle is consistent with the pinned maps' lifecycle (both disappear on bpffs unmount; both survive loader restart). P2 (/var/lib) adds mkdir + chown + systemd `StateDirectory=` coordination cost without clear value; gate on future operator demand.

**[SUPERSEDED — D-3.4b-7's premise that "bpffs is tmpfs" is factually WRONG; bpffs is `bpf` filesystem type (kernel/bpf/inode.c) which REJECTS regular-file creation via EPERM at inode_create. See D-3.4b-21 below for the corrected Q3 = P4 = `/run/xdpmacfilter/<iface>/rule_index.json` decision.]**

##### D-3.4b-8 — Action as label, single series (Q4 A3) — because

Prometheus-idiomatic; sidecar already carries action; exporter joins both at scrape time. Operator queries like `sum(xdpfilter_rule_match_total) by (action, iface)` work directly. Sidecar-orphan tolerance via `action="unknown"` label is graceful + alertable. A1 (separate _meta series + scrape-time join) pushes work to operator; A2 (separate pass/drop series names) multiplies metric count + complicates query rules.

##### D-3.4b-9 — Operator's `id` IS the BPF key (Q5 R1) — because

Phase A grep evidence: `Rule::id` field already validated to [0, XDPMF_ALLOWLIST_MAX-1] = [0, 63] at config.cpp:204. The BPF ARRAY (`rule_counters[64]`) AND the operator's YAML `id:` namespace are IDENTICAL. Operator's mental model is direct: "id 5 in my YAML → `rule_counters[5]` in bpftool dump → `xdpfilter_rule_match_total{rule_id=\"5\"}` in Prometheus". Counter-monotonicity holds across YAML edits as long as operator keeps `id` assignments stable. R2 (source-order) violates this; R3 (sort-by-name) is schema-v2 / Option 4 / out of scope.

##### D-3.4b-10 — Roll-your-own JSON writer, NO `nlohmann/json` dep — because

Brief noted the dep choice. ~150 LOC for the writer (well-bounded; the schema has only 3 top-level fields + a homogeneous `rules` array of 3-field objects + simple string/integer literals). NO new external dep this slice — cycle 1 brownfield discipline + `cli.cpp:1-3` zero-deps project value (cited in §5.29 D-3.4-3 HTTP-server-no-deps decision; this is the symmetric decision for JSON). Future cycles can adopt `nlohmann/json` if a 2nd/3rd sidecar emission point (e.g. exporter metrics summary export, structured-log JSON output) demands a robust parser/serializer.

##### D-3.4b-11 — Config::Rule.id field already exists; NO struct change — because

Phase A grep: `src/lib/config.hpp:42` already declares `std::uint32_t id = 0;` inside `struct Rule`. Brief's wording "Config::Rule struct gains rule_id loader-internal field" was OVERSTATED — the field exists. Q5 R1 uses `Rule::id` directly without any rename / additional field. This is a positive surprise: PI-7-3.4b-hpp / config.hpp ZERO-diff continuation is automatic, no additional carve-out needed.

##### D-3.4b-12 — `rule_counters` declared in mac_filter.bpf.c, PERCPU_ARRAY, max_entries=XDPMF_ALLOWLIST_MAX — because

Mirrors the existing `stats` map's PERCPU_ARRAY shape (line 145-151). PERCPU semantics ensure no cross-CPU race + no atomic-add overhead. max_entries = 64 = XDPMF_ALLOWLIST_MAX (alias `XDPMF_RULE_COUNTERS_MAX` for clarity) matches the rule.id range. LIBBPF_PIN_BY_NAME so libbpf auto-pins to bpffs root (cleared via `kManagedMaps[]` open_skeleton_only loop, then per-iface pinned via `kManagedMaps[]` pin_specs loop) — same idiom as all 12 prior managed maps.

##### D-3.4b-13 — `kManagedMaps[]` gains 13th entry; MVP-3.4.5 HK-9 dividend — because

Single one-line table extension. All 3 call-site loops automatically pick it up. NO new literal-array maintenance. **Validation of MVP-3.4.5 HK-9 landmine refactor**: this slice would have needed 3 lockstep updates (open_skeleton_only `pinned_maps[]`, apply_request `pin_specs[]`, apply_request `reuse_specs[]`) pre-MVP-3.4.5. Now it's 1 line.

##### D-3.4b-14 — Sidecar reader uses line-oriented regex extraction, NOT full JSON parse — because

Cycle 1 budget discipline. The writer's output shape is stable + controlled (D-3.4b-20); a simple ERE captures the `(rule_id, action)` tuple per rule with high reliability. ~80 LOC reader vs ~300+ LOC JSON parser. If a future cycle needs nested object extraction (e.g. richer `match` queries), the reader can co-evolve OR pull in `nlohmann/json` then.

##### D-3.4b-15 — `populate_inner_slot` / `populate_cidr_inner_slot` signatures carry rule_id — because

Each entry must be written as a full `struct allow_entry{.present=1, ._pad={}, .rule_id=R}`. The existing signatures pass `std::vector<xdpmf_mac>` / `std::vector<xdpmf_cidr_v4>` — without the rule_id, the populate functions can't write the new struct. Impl picks the exact shape:
- **Option A (preferred)**: vector of struct: `struct MacRule { xdpmf_mac mac; std::uint32_t rule_id; };` and `struct CidrRule { xdpmf_cidr_v4 cidr; std::uint32_t rule_id; };` declared in loader.cpp's anon-namespace.
- **Option B**: refactor the caller to walk `const Config& cfg` directly and inline the populate (eliminates the deduplicated-vector intermediate; ~10 LOC apply_request extension).
- **Option C**: vector of `std::pair<xdpmf_mac, std::uint32_t>` — simpler but less self-documenting.

Impl SendMessages architect if a non-trivial refactor is forced; otherwise picks A by default. The CONTRACT is: each `bpf_map_update_elem` writes a full 8-byte `struct allow_entry` with rule_id populated from the matching `Config::Rule::id`.

##### D-3.4b-16 — Sidecar write location in apply_request flow — because

The sidecar write can happen:
- **Pre-flip** (right after step 8.5 rules+action_table populate, before active_idx flip): rule_index.json reflects the about-to-be-applied config. If the apply path subsequently fails BEFORE the flip, the sidecar is stale (refers to a config that wasn't committed). Operator visible inconsistency window.
- **Post-flip** (right after active_idx flip): rule_index.json reflects the committed config. Apply-time failures BEFORE the sidecar write are clean (no inconsistency); failures AFTER the sidecar write are also clean (sidecar matches the flipped config). **Preferred** for the "rule_index.json describes the LIVE config" semantic.

Impl picks **post-flip** by default. Sidecar-write failures are non-fatal (D-3.4b-17). Reviewer verifies via T_SIDECAR_JSON_SHAPE: the sidecar content matches the LIVE active_idx-selected ruleset.

##### D-3.4b-17 — Sidecar-write failures are NON-FATAL — because

If `sidecar::write_rule_index` fails (disk full, permission denied, transient filesystem error), the apply ALREADY committed the new config via active_idx flip. Failing the apply at this point would leave the operator in a confusing state: "I asked for apply, the kernel filter changed, but the CLI reported an error". Better: log a stderr WARN line (`xdpmacfilter: WARN: rule_index.json write failed: <errno> — exporter rule labels will show action=unknown until next successful apply`) + return exit 0. The exporter gracefully degrades to `action="unknown"` labels per PI-32-3.4b. Operator notices via Prometheus alert on `action="unknown"` (recommended fleet alert per future docs).

##### D-3.4b-18 — `populate_rules_skeleton` + `populate_action_table` calls PRESERVED — because

§5.29 introduced these for forward-compat with MVP-3.4b. This slice does NOT remove them. The `rules` + `action_table` maps continue to be populated with `{present, action_id}` / `{action_type}` entries. PI-29 carve-out (PI-29-3.4b) explicitly states: `rules` map is still populated, still NOT consulted by datapath this cycle. MVP-3.4c future cycle will wire action_dispatch via these maps. Removing them now would be a regression on the §5.29 forward-compat scaffold.

##### D-3.4b-19 — `emit_metrics` signature growth — because

The existing signature takes `const std::vector<StatsSample>&`. Adding two new parameters (`const std::vector<RuleCountersSample>&` + `const std::map<...>&` or equivalent for per-iface rule meta) is the natural extension. Impl picks the exact arg shapes (struct-aggregate vs separate vector params); CONTRACT is: the function emits BOTH the existing `xdpfilter_packets_total` block AND the new `xdpfilter_rule_match_total` block per scrape. Empty cases handled gracefully (HELP+TYPE only, no samples).

##### D-3.4b-20 — Sidecar writer outputs ONE rule per line — because

Stable + grep-friendly + line-regex-friendly. The writer's contract: each `{rule_id, match, action}` rule object lives on its own line; outer `{`, `"iface"`, `"schema_version"`, `"applied_at"`, `"rules": [`, `]`, outer `}` are on separate lines too. Total file structure (illustrative):
```
{
  "iface": "eth0",
  "schema_version": 1,
  "applied_at": "2026-05-25T10:30:00Z",
  "rules": [
    {"rule_id": 0, "match": {"mac": "aa:bb:cc:dd:ee:ff"}, "action": "pass"},
    {"rule_id": 1, "match": {"cidr": "10.0.0.0/24"}, "action": "pass"},
    {"rule_id": 2, "match": {"mac": "11:22:33:44:55:66"}, "action": "drop"}
  ]
}
```

This is valid JSON (jq accepts it) AND line-oriented (the exporter regex matches per-rule lines independently). `T_SIDECAR_JSON_SHAPE.sh` validates with jq; `src/exporter/sidecar_reader.cpp` extracts per-rule with regex.

#### §5.31 TestStrategy entries

##### §6.47 T_RULE_COUNTER_MAC_HIT_BUMPS — MAC HASH-hit increments rule_counters[rule_id]

**Trigger**: attach via `apply -f tests/fixtures/config_per_rule_counters.yaml` (fixture has 4 rules with sparse `id:` values 0, 5, 17, 42 — mix of MAC-only and CIDR-only). Inject N=5 frames matching rule_id=5's MAC; inject K=3 frames matching rule_id=17's MAC. Both rules are PASS rules.

**Observable outcome**:
- `bpftool map dump pinned ${PIN_DIR}/<iface>/rule_counters --json` shows: slot[5] = 5 (PERCPU-summed); slot[17] = 3; all other slots (incl. 0, 1..4, 6..16, 18..41, 43..63) = 0.
- `STAT_PASS` global stat advances by 8 (existing global counter still bumps, byte-equivalent to MVP-3.4.5).
- Negation control: re-inject 1 frame matching rule_id=0's MAC; `rule_counters[5]` STILL equals 5 (unchanged); `rule_counters[0]` equals 1 (NEW).

**Assertion mechanism**: `tests/lib/read_rule_counters.py` (NEW helper script — parallels `read_stats.py` for `rule_counters`) PERCPU-sums per slot; bash `[[ "${count_5}" == "5" ]]`-style comparisons per slot; `read_stats.py` for global PASS sanity.

**SKIP conditions**: `bpftool`, `jq` already required. No new SKIP-77 conditions.

**Cleanup**: `cleanup_veth`.

**Maps to**: PI-3.4b-1 (rule_counters map exists + populated correctly), PI-3.4b-4 (bump_rule wiring on MAC HASH-hit), HG-3.4b-1 (PI-13-3.4b PASS confirmation — datapath reads rule_id from inner-value), Q1 B3, Q5 R1.

##### §6.48 T_RULE_COUNTER_CIDR_HIT_BUMPS — CIDR LPM_TRIE-hit increments rule_counters[rule_id]

**Trigger**: same fixture as §6.47 (config_per_rule_counters.yaml has rule_id=42 as a CIDR rule, e.g. `src_cidr: 10.0.0.0/24`). Inject N=4 IPv4 frames with src IP in 10.0.0.0/24 range (e.g. 10.0.0.5) and src MAC NOT in any other rule.

**Observable outcome**:
- `rule_counters[42]` = 4 (PERCPU-summed).
- `STAT_PASS_CIDR` global counter advances by 4.
- Negation control: inject 1 frame matching rule_id=5's MAC (MAC-only PASS); `rule_counters[5]` advances; `rule_counters[42]` UNCHANGED (CIDR branch short-circuited by MAC-hit-first per §5.27 OR1 ordering — symmetric MAC/CIDR semantic).
- Additional negation: inject 1 IPv4 frame with src IP OUTSIDE 10.0.0.0/24 (e.g. 192.168.1.1) and src MAC NOT in any rule; `rule_counters[42]` stays 4 (no CIDR match); STAT_DROP_DENY advances by 1.

**Assertion mechanism**: same as §6.47.

**SKIP conditions**: none new.

**Cleanup**: `cleanup_veth`.

**Maps to**: PI-3.4b-4 (bump_rule wiring on CIDR LPM_TRIE-hit), PI-13-3.4b CIDR symmetry (T.5 OQ #3), Q1 B3.

##### §6.49 T_RULE_COUNTER_SURVIVES_APPLY — counters PRESERVED across apply -f (HG-3.4b-2 canary)

**Trigger**:
1. Attach via `apply -f config_per_rule_counters.yaml`.
2. Inject 7 frames matching rule_id=5's MAC; assert `rule_counters[5]` = 7.
3. RE-apply the SAME `config_per_rule_counters.yaml` (forces an active_idx swap_count++; same rules, same ids).
4. Assert `rule_counters[5]` STILL equals 7 (PRESERVED across apply per HG-3.4b-2 Prometheus counter-monotonicity).
5. Inject 3 more frames matching rule_id=5's MAC; assert `rule_counters[5]` = 10 (continued from 7).

**Observable outcome**: post-step-3 `rule_counters[5]` = 7 (NOT 0); post-step-5 = 10.

**Assertion mechanism**: `read_rule_counters.py` between each step; bash `[[ "${count_5}" == "7" ]]` after step 3 (load-bearing) + `[[ "${count_5}" == "10" ]]` after step 5.

**SKIP conditions**: none.

**Cleanup**: `cleanup_veth`.

**Maps to**: PI-3.4b-2 (counter survival), HG-3.4b-2, D-3.4b-2 (PIN_BY_NAME + reuse_fd discipline + kManagedMaps[] 13th entry).

**Load-bearing**: this test is the canary for D-3.1-4 reuse_fd discipline applied to the new map. If it fails post-step-3 with `rule_counters[5]` = 0, the kManagedMaps[] 13th entry was likely added but NOT carrying through to the reuse_fd loop — impl peer-DM architect to root-cause.

##### §6.50 T_SIDECAR_JSON_SHAPE — rule_index.json correctness

**Trigger**: attach via `apply -f config_per_rule_counters.yaml`.

**Observable outcome**:
- File `/run/xdpmacfilter/<iface>/rule_index.json` exists, mode 0644, non-empty (path per §5.31 EDIT-1 Q3 P4 correction; was `${PIN_DIR}/<iface>/...` at initial publish — SUPERSEDED because bpffs rejects regular-file creation).
- `jq -e '.iface == "<expected iface>"' rule_index.json` succeeds.
- `jq -e '.schema_version == 1' rule_index.json` succeeds.
- `jq -e '.applied_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")' rule_index.json` succeeds (ISO-8601 UTC pattern).
- `jq -e '.rules | length == 4' rule_index.json` succeeds (fixture has 4 rules).
- For each rule_id in {0, 5, 17, 42}: `jq -e ".rules[] | select(.rule_id == ${id}) | .action == \"<expected>\""` succeeds.
- Match-kind sanity per rule per fixture.

**Negation control**: invoke `apply -f /dev/null` or a malformed config; assert sidecar is NOT written / NOT truncated (the prior sidecar from a successful apply persists; new failed apply does NOT corrupt it). Exit code from apply is 9 (existing ConfigError path).

**Assertion mechanism**: `jq -e` for shape + value asserts; `test -f` for existence; `stat -c %a` for mode 0644.

**SKIP conditions**: `jq` is already required.

**Cleanup**: `cleanup_veth`.

**Maps to**: PI-3.4b-5 (sidecar exists + correct shape), Q2 S1, Q3 P1, D-3.4b-10 (writer correctness), D-3.4b-20 (one-rule-per-line shape).

##### §6.51 T_EXPORTER_RULE_LABELS — exporter emits xdpfilter_rule_match_total

**Trigger**: attach + apply config_per_rule_counters.yaml; inject mixed traffic so multiple rule_ids advance; start xdpmf-exporter in background on `EXPORTER_PORT`; `curl http://127.0.0.1:${EXPORTER_PORT}/metrics`.

**Observable outcome**:
- HTTP 200 OK; Content-Type contains `text/plain; version=0.0.4`.
- Body contains `# HELP xdpfilter_rule_match_total ...` line AND `# TYPE xdpfilter_rule_match_total counter` line (exactly once each).
- For each rule_id with non-zero traffic: `xdpfilter_rule_match_total{iface="<iface>",rule_id="<N>",action="<pass|drop>"} <count>` line present, matching ERE `^xdpfilter_rule_match_total\{iface="[^"]+",rule_id="[0-9]+",action="(pass|drop|unknown)"\} [0-9]+$`.
- The `action` label value matches the sidecar's `action` field for each rule_id (no drift between BPF + sidecar).
- Existing `xdpfilter_packets_total` series UNCHANGED (PI-31-3.4b — additive series, not modification of existing).

**Sidecar-orphan tolerance sub-test**: artificially delete `rule_index.json` (between scrapes); re-scrape `/metrics`; for any rule_id with non-zero `rule_counters[]` value, the emitted label MUST be `action="unknown"`. Exporter MUST NOT crash; subsequent scrapes (after re-apply) MUST show real labels again.

**Assertion mechanism**: `curl -s` + `grep -qE` on the Prometheus pattern; `jq`-free regex on each rule's series; `kill -0 $EXPORTER_PID` for liveness across scrapes.

**SKIP conditions**: `curl` absent → SKIP-77.

**Cleanup**: kill exporter; `cleanup_veth`.

**Maps to**: PI-3.4b-6 (exporter emits new series), PI-31-3.4b (exporter READ-ONLY), PI-32-3.4b (sidecar-orphan graceful), Q4 A3, D-3.4b-8.

##### §6.52 T_DROP_RULE_BUMPS_COUNTER — drop-rule's inner-allowlist absence + counter behavior

**Trigger**: fixture `config_per_rule_counters.yaml` has rule_id=17 as `action: drop match.mac=...`. Per §5.26 schema cycle 2: drop rules do NOT populate the inner allowlist (the MAC is NOT added to `allowlist_<active>`). Inject 5 frames matching the drop-rule's MAC. Per §5.27 + §5.31 datapath: the MAC misses inner-HASH; if MAC is not also in CIDR; falls through to defaults[active] — default `drop` → STAT_DROP_DENY bumps; per-rule counter for rule_id=17 STAYS 0 because the MAC was never in the inner-allowlist (no bump_rule call site reached for that MAC).

**Observable outcome**:
- `STAT_DROP_DENY` advances by 5.
- `rule_counters[17]` STAYS 0 (the inner-allowlist absence is what generates the drop behavior; per-rule counters only fire on MATCH).
- `bpftool map dump pinned ${PIN_DIR}/<iface>/rules --json | jq '.[] | select(.key == 17) | .formatted.value.action_id'` returns 1 (DROP — confirms `rules` map is POPULATED with the drop-rule entry per §5.29 forward-compat; just not consulted by datapath).
- Sidecar `rule_index.json` for rule_id=17 shows `"action": "drop"`.

**Negation control**: same fixture, inject 2 frames matching rule_id=5's PASS MAC; `rule_counters[5]` advances; `rule_counters[17]` STAYS 0; STAT_PASS advances; STAT_DROP_DENY UNCHANGED.

**Assertion mechanism**: `read_rule_counters.py`; `read_stats.py`; `bpftool map dump pinned ${PIN_DIR}/rules --json | jq` for rules-map verification; `jq -e` on rule_index.json.

**SKIP conditions**: none.

**Cleanup**: `cleanup_veth`.

**Maps to**: PI-29-3.4b (drop rules in `rules` map populated NOT consulted; rule_id NOT bumped because inner-allowlist absent), HG-3.4b-4 (rules map shared NOT swapped — drop rule entry persists across applies as long as the rule is in the config), Q5 R1 (rule_id correspondence to YAML id).

**Note**: this test confirms the §5.29 + §5.31 boundary — `rules` map carries the drop-rule's metadata for future MVP-3.4c action-dispatch, but the bump_rule pipeline ONLY fires on actual MAC/CIDR matches. The drop-rule's MAC produces no match (it's not in the inner-allowlist by §5.26 design). MVP-3.4c will wire action-dispatch via `rules[i].action_id → action_table[action_id]` to make drop rules operative — at which point `rule_counters[17]` WOULD bump for actual drop-rule activations. **For cycle 1, `rule_counters[drop_rule_id]` stays at 0 — this is the operationally-observable signature of "datapath wiring is for PASS rules only, drop semantics via existing defaults[active]=drop fallthrough"**.

##### Optional: §6.53 T_RULE_COUNTER_VERIFIER_GREEN — BPF object loads cleanly post-extension

**Status**: OPTIONAL, tester's call. The 5-6 tests above already exercise the verifier indirectly (any one of them failing on BPF object load = verifier-reject signal). A dedicated micro-test would: invoke `xdpmacfilter attach --iface lo` (or fixture iface) with default attach config; assert exit 0; assert `bpftool prog show name mac_filter_prog` lists the prog. If verifier rejects, exit 2 (LoadFailed). Per /mint-hld T_VERIFIER_REJECT-equivalent.

Architect's recommendation: **NOT required** as a separate ctest unless impl reports verifier turbulence during Phase 2 — in which case impl peer-DMs architect and tester adds it then.

##### PI-3.4b-9 fixture-ripple catalog (per Phase A grep + impl Phase 2.5 smoke)

**Confirmed touch sites** (2 ctests, ZERO library/helper changes):

| Path | Line(s) | Change kind | Reason |
|---|---|---|---|
| `tests/T_RULES_SKELETON_NOT_WIRED.sh` | 14 (comment) | comment rewrite | "1-byte values" → "8-byte struct allow_entry values per §5.31 PI-13-3.4b" |
| `tests/T_RULES_SKELETON_NOT_WIRED.sh` | 297 (stderr-msg) | comment rewrite | "(ii) the inner-value shape was extended to embed rule_id (PI-27/PI-13-3.4 violation, defer broken)" → "(ii) the apply path INCORRECTLY added the drop-rule MAC to the inner allowlist (per §5.26 schema cycle 2 'drop rules do NOT populate inner' contract — that contract is preserved post-§5.31)" |
| `tests/T_EXPORTER_METRICS_FORMAT.sh` | 21-22 (comments), 100-101 (assertion) | version-literal bump | `xdpmf-exporter 0.6.1` → `xdpmf-exporter 0.7.0`; HK-8-forced per MVP-3.4.5 EDIT-3 precedent |

**Tests that REMAIN BYTE-EQUIVALENT despite touching `allowlist_*` / `cidr_allowlist_*` pins** (these check KEY shape or per-iface pin existence, NOT inner-value byte shape):

| Path | Why byte-equivalent |
|---|---|
| `tests/T_APPLY_VALID_CONFIG.sh` | `mac_in_inner_pin()` queries `.key.octets`, NOT inner-value. Value byte shape changes (1 → 8) but query path is key-only. |
| `tests/T_APPLY_REPLACES_RULESET.sh` | Same — checks key presence (MAC octets), not value byte shape. |
| `tests/T_PASS_CIDR.sh`, `tests/T_PASS_MAC_OR_CIDR.sh` | Check `length` of inner-map (count of entries) or active_idx value, NOT inner-value byte shape. |
| `tests/T_APPLY_ATOMIC_SWAP_NO_DROP.sh`, `tests/T_CIDR_ATOMIC_SWAP_NO_DROP.sh` | Check active_idx flip behavior + traffic counters, NOT inner-value byte shape. |
| `tests/T_PERCPU_STATS_SUM.sh` | Operates on `stats` PERCPU_ARRAY (value_size 8 unchanged), NOT on allowlist inner-values. |
| `tests/T_RULES_SKELETON_NOT_WIRED.sh` (assertion body lines 283-299) | Tests MAC PRESENCE in inner-allowlist (key match), NOT inner-value byte shape. Assertion is byte-equivalent; ONLY comments need updating (above). |

**Phase A grep summary**: `grep -rE 'value_size.*1\b\|__u8.*present\|bpf_map_update_elem.*allowlist' tests/` returned ZERO matches for value_size literals + ZERO matches for userspace `bpf_map_update_elem` writes against allowlist pins. The only writes happen inside `loader.cpp:1097, 1137` (which this slice modifies). **Fixture-ripple cost: 2 ctest body EDITs total** — significantly less than brief's ~5 ceiling.

**Brief's "the 4 ctests that explicitly inspect inner-value bytes" enumeration was speculative** — Phase A grep confirms NONE of T_DROP_NOT_IN_ALLOWLIST (doesn't exist as named — likely T_DROP_DENY), T_DROP_CIDR_NOT_IN_RANGE, T_APPLY_ATOMIC_SWAP_NO_DROP, T_PERCPU_STATS_SUM inspect inner-value bytes (they all check key/active_idx/stats counters). Architect explicitly LISTS them as byte-equivalent in the table above so impl + tester don't waste cycles re-investigating.

#### §6.5 Preserved invariants (MVP-3.4b brownfield) — PI-1..PI-34 hold (with adjudications) + PI-3.4b-* NEW

All MVP-3.1..3.4.5 invariants (PI-1..PI-34 + PI-7-3.4.5-hpp/cpp per §5.26 + §5.27 + §5.28 + §5.29 + §5.30 sub-sections) continue to hold post-§5.31 EXCEPT where this slice explicitly ADJUDICATES (PI-13: now PASS-as-additive per HG-3.4b-1) OR carves out (PI-29: rules+action_table still NOT consulted, but inner-value's rule_id IS read). PI-7-3.4b-hpp continues the streak. PI-13-3.4b is the LOAD-BEARING NEW PI of this slice.

Reviewer's 5th framework point walks the COMBINED list (PI-1..PI-34 + PI-3.4b-*) and reports `[INVARIANT-VIOLATED]` per failed check.

**Continuing invariants — restatement for the MVP-3.4b namespace**:

| # | Invariant | §5.31 check mechanism |
|---|---|---|
| PI-1..PI-5 | Trust+identity gates ENFORCED in both modes (alien-program refusal, name-identity, tag-check, O_PATH path-discipline, kernel-version probe) | Re-run §6.9 / §6.14 / §6.15 / §6.20 / §6.26 sub-cases; all pass. The new BPF map declaration + new inner-value shape do NOT touch any gate codepath. The bpf object tag CHANGES (bytecode differs), but tag-check at `T_ATTACH_TAG_MISMATCH` is about REFUSING ALIEN tags — our own self-tag is recomputed each cycle, byte-equivalent to MVP-3.4.5's recomputation. |
| **PI-6-3.4b** | **46 pre-§5.31 ctests pass byte-equivalent OR legitimately SKIP-77 — STRICT SUPERSET with explicit 3-ctest-body EDIT carve-out per §5.31 EDIT-2 amendment** (T_RULES_SKELETON_NOT_WIRED comment-rewrite + T_EXPORTER_METRICS_FORMAT version-literal bump + T_ATTACH_TAG_MISMATCH preflight hybrid-rewrite per PI-3.4b-9 catalog above; was 2-EDIT at initial publish, bumped to 3-EDIT post-§5.31 EDIT-2 Phase B adjudication — see §5.31 EDIT-2 + D-3.4b-22) | Re-run all 46 tests post-§5.31 → all pass (or SKIP-77); `git diff --stat tests/T_*.sh` shows changes confined to the 2 EDITED ctests PLUS 6 NEW files (§6.47..§6.52) PLUS 1 NEW fixture (`config_per_rule_counters.yaml`) PLUS 1 NEW helper (`tests/lib/read_rule_counters.py`). The 2 EDITED ctest BODIES are scope-fenced + documented. All 44 other ctest bodies byte-equivalent. PI-6-3.4.5 had 7-EDIT carve-out; PI-6-3.4b has 2-EDIT carve-out (narrower). Reviewer accepts both EDITs as scope-fenced. |
| **PI-7-3.4b-hpp** | **`loader.hpp` ZERO diff — 6TH consecutive slice** (MVP-3.1 +1; MVP-3.2/3.3/3.4/3.4.5/3.4b = 0). Public-API surface byte-equivalent. ALSO: `src/lib/config.hpp` ZERO diff this slice (D-3.4b-11 — `Rule::id` field already serves Q5 R1; no new field needed). | `git diff main -- src/lib/loader.hpp src/lib/config.hpp` shows ZERO output. Any diff = `[INVARIANT-VIOLATED]`. |
| **PI-7-3.4b-cpp** | **`loader.cpp` SCOPED EDIT only** — diff lines confined to: (a) kManagedMaps[] table 12 → 13 entries (one-line insertion + table-comment count update); (b) `populate_inner_slot` body + signature (rule_id-carrying); (c) `populate_cidr_inner_slot` body + signature (rule_id-carrying); (d) `apply_request` rule-extraction step extension (produces rule_id-tagged vectors alongside the existing dedup vectors); (e) `apply_request` new sidecar-write step (post-flip per D-3.4b-16, calling `sidecar::write_rule_index`); (f) optional new private helpers in anon-namespace for the rule_id-tagged-vector intermediate (`MacRule`, `CidrRule` structs per D-3.4b-15 Option A). ZERO diff in: `attach()` / `detach()` public bodies, §5.4 state-machine, §5.19 name-check, §5.22 tag-check + O_PATH, §5.24 kernel-version probe, §5.26 trust_model parse+log, §5.27 CIDR-axis active_idx flip mechanism, link-pin P0a logic, RAII wrappers, error-translation paths, the special-pin legacy-alias path (lines 1761-1778), §5.29 `populate_rules_skeleton` + `populate_action_table` body bytes (UNCHANGED — they still write `rule_entry` / `action_entry` to `rules` / `action_table` maps per HG-3.4b-4). | `git diff <MVP-3.4.5-HEAD> -- src/lib/loader.cpp` shows changes confined to scopes (a)-(f). Reviewer applies regional-diff: classify each hunk by enclosing function name; allowed function names = {`populate_inner_slot`, `populate_cidr_inner_slot`, `apply_request`, anon-namespace (kManagedMaps[] table + new MacRule/CidrRule struct definitions)}. Any hunk outside this set = `[INVARIANT-VIOLATED]`. Cross-cycle baseline: reviewer compares against MVP-3.4.5-shipped HEAD (not project's pristine main). |
| PI-8-3.4b | `xdpmacfilter --version` reports `xdpmacfilter 0.7.0` AND `xdpmf-exporter --version` reports `xdpmf-exporter 0.7.0` (shared `version.h` per §5.25 P3) | Run both `--version`; both single-line outputs `0.7.0` + newline. MINOR bump from 0.6.1 (operator-facing feature: per-rule observability). |
| PI-9 | `--help` / `--version` output FORMAT unchanged modulo optional one-line addition mentioning the new `xdpfilter_rule_match_total` series in exporter's --help | §6.10 T_CLI_HELP_VERSION re-run passes (forward-compatible ERE). The mention IS optional — impl-flexible. |
| **PI-10-3.4b** | `src/common/mac_filter.h` additions purely ADDITIVE; existing constants + struct layouts UNCHANGED | `git diff main -- src/common/mac_filter.h` shows ONLY additions: `struct allow_entry`, `XDPMF_MAP_RULE_COUNTERS_NAME`, `XDPMF_RULE_COUNTERS_MAX`. ZERO modifications to `struct xdpmf_mac`, `struct xdpmf_cidr_v4`, `enum mac_filter_stat`, `struct rule_entry`, `struct action_entry`, `enum xdpmf_action_type`, or any existing `XDPMF_MAP_*_NAME` / `XDPMF_*_MAX` / `XDPMF_BPFFS_ROOT`. |
| PI-11 | Internal directory layout UNCHANGED | `find src -type d` shows the SAME 5 dirs as MVP-3.4.5 (`src/lib/`, `src/cli/`, `src/common/`, `src/bpf/`, `src/exporter/`). No new dir; new files live within existing dirs. |
| PI-12 | Pin paths host-global per `nsenter --net` | NEW pin `${PIN_DIR}/<iface>/rule_counters` + NEW sidecar file `${PIN_DIR}/<iface>/rule_index.json` visible from `nsenter --net` per existing mechanism. The new map's LIBBPF_PIN_BY_NAME flag is the same idiom as the existing 12 managed maps. |
| **PI-13-3.4b** | **Inner-allowlist-value byte shape EXTENDS from `__u8 present` (1 byte) to `struct allow_entry { __u8 present; __u8 _pad[3]; __u32 rule_id; }` (8 bytes)** — adjudicated PASS-AS-ADDITIVE per HG-3.4b-1 + D-3.4b-1. **THE load-bearing NEW PI of this slice. Cross-references PI-27 STRICT-byte-shape-reading from §5.29: PI-27's text was about offset-0 byte semantics (`bpftool map dump format c | head -c 1` returns 0x01); PI-13-3.4b PRESERVES that offset-0 byte invariant + EXTENDS with bytes 1-7. The change in `value_size` (1 → 8) is documented + intended.** Applied SYMMETRICALLY to `allowlist_a/b` (MAC HASH) AND `cidr_allowlist_a/b` (CIDR LPM_TRIE). | (a) `git diff <MVP-3.4.5-HEAD> -- src/bpf/mac_filter.bpf.c` shows `__type(value, __u8)` → `__type(value, struct allow_entry)` at lines 55 (MAC HASH template) AND 95 (CIDR LPM_TRIE template). (b) `bpftool map show pinned ${PIN_DIR}/<iface>/allowlist_a` reports `value_size 8`; same for `allowlist_b`, `cidr_allowlist_a`, `cidr_allowlist_b`. (c) `bpftool map dump pinned ${PIN_DIR}/<iface>/allowlist_<active> --json | jq '.[0].formatted.value.present'` returns `1` for occupied slots (NEW BTF-aware reading); `bpftool map dump pinned ${PIN_DIR}/<iface>/allowlist_<active> format c | head -c 1` returns `0x01` for occupied slots (PI-27 byte-equivalent — old single-byte readers still see the SAME byte at offset 0). (d) `bpftool map dump pinned ${PIN_DIR}/<iface>/allowlist_<active> --json | jq '.[0].formatted.value.rule_id'` returns the rule.id of the matched-against rule (NEW); for the apply with `id: 5` MAC rule the value reads 5. **Negation check**: a write to inner-allowlist with `value_size != 8` would fail with EINVAL at kernel (libbpf-side validates against map's declared value_size). |
| PI-14 | `--mode {generic,native,offload}` UNCHANGED | §6.16/§6.17/§6.19 still pass. |
| PI-15 | CIDR axis purely additive | UNCHANGED — CIDR LPM_TRIE inner-VALUE extends (PI-13-3.4b SYMMETRIC), but the AXIS itself (LPM_TRIE matching, src_ip extraction, IPv4 ETH_P_IP gate) is byte-equivalent. |
| PI-16 | STAT_PASS_CIDR additive enum slot | UNCHANGED. The new `bump_rule` is ALSO bumped on CIDR-hit, BUT STAT_PASS_CIDR continues to bump independently per the existing call-site. Both increment together on each CIDR match. |
| PI-17 | `schema_version: 1` accepted; Jinja2 template emits schema_version: 1 | UNCHANGED. No YAML schema change this slice. The Q5 R1 contract is met by the EXISTING `id:` field per `Rule::id`. |
| PI-18 | §6.23 MAC-axis atomic-swap continues | UNCHANGED. The active_idx flip mechanism is preserved; inner-value extension does NOT affect the swap atomicity (the kernel-side u32 store at active_idx[0] commits BOTH MAC and CIDR axes; the inner-value's struct shape is per-entry, not per-swap). |
| PI-19 | systemd-analyze verify passes on unit files | UNCHANGED. No unit-file change this slice. |
| PI-20 | systemd lifecycle for `xdpmacfilter@.service` | UNCHANGED. |
| PI-21..PI-25 | Ansible playbook + syntax-check + FLEET_DEPLOYMENT.md + directive catalogue + systemd-restart flake handling | UNCHANGED. |
| PI-26 | MVP-3.3 historical "no C++/BPF source change" check | UNCHANGED (PI-26 fires on the MVP-3.3 commit set, not the MVP-3.4b commit set). |
| PI-27 ≡ PI-13-3.4b adjudicated | inner-allowlist-value offset-0 byte semantics PRESERVED (occupied slots return 0x01 at byte 0); `value_size` EXTENDED 1 → 8 (PI-13-3.4b PASS-as-additive adjudication) | See PI-13-3.4b above for the full check mechanism. The PRIOR strict-byte-shape reading of PI-27 is SUPERSEDED by PI-13-3.4b for slices post-§5.31. PI-27's "load-bearing defer PI" status from §5.29 is REPLACED by PI-13-3.4b's "load-bearing PASS-as-additive PI" — the defer ends here, with byte-level evidence the offset-0 byte is preserved. |
| PI-28 → **PI-28-3.4b** | **`mac_filter_prog` BPF function body EXTENDS (no longer byte-equivalent to MVP-3.2/3.4.5)**: adds `bump_rule(entry->rule_id)` call in the MAC HASH-hit branch (line ~228 area, was just `bump_stat(STAT_PASS); return XDP_PASS;`); adds `bump_rule(cidr_hit->rule_id)` call in the CIDR LPM_TRIE-hit branch (line ~256 area, was just `bump_stat(STAT_PASS_CIDR); return XDP_PASS;`); adds `struct allow_entry *entry` typed-pointer (vs `__u8 *present`) reads at lines 226 + 254. **First substantive `mac_filter_prog` body change since MVP-3.2.** All OTHER body lines (default fallthrough, drop branches, IPv4 ethertype check, ethhdr bounds check) BYTE-EQUIVALENT. Functional semantic: same verdicts for same inputs PLUS rule_counters bump per hit. | `git diff main -- src/bpf/mac_filter.bpf.c` shows the EDITED line-set per the FileList table above + new `bump_rule` helper + new `rule_counters` map declaration. All other diff lines (default fallthrough, drop branches, etc.) zero. Reviewer's regional-diff check on the function-body: allowed hunks = {line 55 inner-VALUE typedef, line 95 inner-VALUE typedef, line 226 typed-pointer + bump_rule call, line 254 typed-pointer + bump_rule call, NEW `rule_counters` map decl in .maps block, NEW `bump_rule` helper definition}. Any hunk outside this set in the function body = `[INVARIANT-VIOLATED]`. |
| PI-29 → **PI-29-3.4b** | **`rules` map STILL NOT consulted by datapath**; **`action_table` map STILL NOT consulted by datapath**; **inner-allowlist-value's `rule_id` IS read by datapath** (NEW). | `bpftool map dump pinned ${PIN_DIR}/<iface>/rules` shows occupied slots matching applied config (UNCHANGED from MVP-3.4 — still populated by `populate_rules_skeleton` per D-3.4b-18); `bpftool map dump pinned ${PIN_DIR}/<iface>/action_table` shows two entries (UNCHANGED). **Datapath non-consultation of `rules` + `action_table` verified via PI-28-3.4b regional-diff**: no `bpf_map_lookup_elem(&rules, ...)` or `bpf_map_lookup_elem(&action_table, ...)` calls inside `mac_filter_prog` function body. **Datapath read of inner-VALUE rule_id IS the only NEW datapath map-related read this slice** (a struct-field deref on a successfully-looked-up inner pointer, NOT a separate `bpf_map_lookup_elem` call). T_DROP_RULE_BUMPS_COUNTER + T_RULES_SKELETON_NOT_WIRED jointly confirm the carve-out: drop-rule entry in `rules` map populated but `rule_counters[drop_rule_id]` stays 0 because the drop-rule's MAC is NOT in inner-allowlist (datapath never executes bump_rule for that MAC). |
| PI-30 | `bypass` primitive UNCHANGED | UNCHANGED. Bypass invokes `detach`; no map change; no datapath change for bypass. |
| PI-31 → **PI-31-3.4b** | **Exporter is READ-ONLY by construction** — extends to cover NEW `rule_counters_reader.cpp` + `sidecar_reader.cpp`. NO `bpf_map_update_elem`, no `bpf_map_delete_elem`, no map mutations; sidecar_reader is filesystem-READ-ONLY (no write to rule_index.json). | `grep -rE 'bpf_(map_(update\|delete)_elem\|obj_pin\|link_create\|link_destroy\|xdp_(attach\|detach)\|prog_load)' src/exporter/` returns ZERO matches post-§5.31. `grep -rE '\b(fopen\|fwrite\|open).*rule_index' src/exporter/` returns ZERO writes (only reads). Reviewer asserts during framework point 5 walk. |
| PI-32 → **PI-32-3.4b** | **Exporter handles missing/empty bpffs gracefully + missing-sidecar gracefully** — extends PI-32 to include sidecar-orphan tolerance. Missing rule_index.json → degrade to `action="unknown"` labels (NOT crash, NOT skip series). Missing rule_counters pin → exporter emits NO rule_match samples for that iface (graceful). | T_EXPORTER_RULE_LABELS sidecar-orphan sub-test (above) — delete rule_index.json mid-scrape; assert exporter survives + labels become `action="unknown"`. PI-32-3.4b STRENGTHENS PI-32 with two new degradation paths. |
| PI-33 | Both binaries report same version (shared version.h) | UNCHANGED in shape; bump to 0.7.0 (PI-8-3.4b). |
| PI-34 ≡ PI-6-3.4b | 46 pre-§5.31 ctests strict-superset with 2-EDIT carve-out (T_RULES_SKELETON_NOT_WIRED comment-rewrite + T_EXPORTER_METRICS_FORMAT version-literal bump per PI-3.4b-9 catalog) | Same check as PI-6-3.4b above. |

**NEW invariants** (MVP-3.4b-specific):

| # | Invariant | Check mechanism |
|---|---|---|
| **PI-3.4b-1** | **`rule_counters` PERCPU_ARRAY[64] of __u64 EXISTS + PINNED at `${PIN_DIR}/<iface>/rule_counters`** for every attached iface. Pinning via LIBBPF_PIN_BY_NAME (matches `kManagedMaps[]` discipline). | `bpftool map show pinned ${PIN_DIR}/<iface>/rule_counters` reports `type percpu_array`, `max_entries 64`, `value_size 8`, `key_size 4`. Existence verified via `test -e ${PIN_DIR}/<iface>/rule_counters` post-apply. |
| **PI-3.4b-2** | **Counter survival across apply -f** — PIN_BY_NAME + reuse_fd discipline preserves PERCPU values across re-apply. Prometheus counter-monotonicity holds. | T_RULE_COUNTER_SURVIVES_APPLY (§6.49). If counters reset on re-apply, this PI is VIOLATED — root cause is likely the 13th kManagedMaps[] entry missing from the reuse loop (which would be impossible if HK-9 refactor is intact). |
| **PI-3.4b-3** | **`struct allow_entry` is the INNER-VALUE type for both `xdpmf_allowlist_inner` (MAC HASH) AND `xdpmf_cidr_inner` (CIDR LPM_TRIE)** — symmetric per T.5 OQ #3. Total size 8 bytes. PI-13-3.4b documents the byte-by-byte layout. | `bpftool map show pinned ${PIN_DIR}/<iface>/allowlist_a` reports `value_size 8`; same for `allowlist_b` (MAC). `bpftool map show pinned ${PIN_DIR}/<iface>/cidr_allowlist_a` reports `value_size 8`; same for `cidr_allowlist_b` (CIDR). |
| **PI-3.4b-4** | **`bump_rule(rule_id)` is called per-match from BOTH MAC HASH-hit and CIDR LPM_TRIE-hit branches in `mac_filter_prog`** — Q1 B3 contract. rule_id read from `struct allow_entry::rule_id` (offset 4) of the looked-up inner-value pointer. NO bump_rule call in default-fallthrough or drop branches. | (a) `git diff` of `mac_filter.bpf.c` shows TWO new `bump_rule` call-sites (lines ~228 and ~256 areas). (b) T_RULE_COUNTER_MAC_HIT_BUMPS + T_RULE_COUNTER_CIDR_HIT_BUMPS verify per-hit increment. (c) T_DROP_RULE_BUMPS_COUNTER negation: drop-rule MAC produces NO bump_rule call (MAC not in inner-allowlist; fallthrough to defaults). |
| **PI-3.4b-5** | **`rule_index.json` sidecar exists at `/run/xdpmacfilter/<iface>/rule_index.json` after every successful apply** — Q3 P4 path per §5.31 EDIT-1 (was Q3 P1 `${PIN_DIR}/<iface>/...` at initial publish; SUPERSEDED — bpffs rejects regular-file creation per impl Phase B finding). Schema per Q2 S1. File mode 0644. Atomic-write via rename-into-place. Loader does `mkdir -p /run/xdpmacfilter/<iface>` if not present. | T_SIDECAR_JSON_SHAPE (§6.50). Sidecar-write failure is non-fatal (D-3.4b-17) — apply still exits 0 + WARN logged. |
| **PI-3.4b-6** | **Exporter emits `xdpfilter_rule_match_total{iface, rule_id, action}` Prometheus series** for each iface with non-empty `rule_counters` AND/OR non-empty sidecar — Q4 A3 + D-3.4b-8. Sidecar-orphan tolerance: `action="unknown"` label for rule_id present in counters but absent from sidecar. | T_EXPORTER_RULE_LABELS (§6.51). |
| **PI-3.4b-7** | **`Config::Rule::id` field is the rule_id source for both inner-VALUE `rule_id` AND `rule_counters` ARRAY index AND sidecar JSON `rule_id`** — Q5 R1 + D-3.4b-9 + D-3.4b-11. Range [0, XDPMF_ALLOWLIST_MAX-1] = [0, 63] enforced at `config.cpp:204`. | T_RULE_COUNTER_MAC_HIT_BUMPS + T_RULE_COUNTER_CIDR_HIT_BUMPS verify rule_id correspondence end-to-end (YAML `id: 5` → inner-VALUE.rule_id = 5 → rule_counters[5] bumps → sidecar `"rule_id": 5` → Prometheus `rule_id="5"` label). Negation: rule_id out of range would FAIL config validation (existing path; not a new check). |
| **PI-3.4b-8** | **`kManagedMaps[]` table has 13 entries post-§5.31** — `rule_counters` joins the table; all 3 call-site loops walk it automatically. | `grep -c '^\s*{ &SkelMapsT::' src/lib/loader.cpp` returns 13 (was 12 pre-§5.31). The new entry's `member_ptr` is `&SkelMapsT::rule_counters`; `name` is `XDPMF_MAP_RULE_COUNTERS_NAME`; `legacy_alias` is `false`. |
| **PI-3.4b-9** | **PI-13-3.4b fixture-ripple cost is 3 ctest body EDITs per §5.31 EDIT-2** (T_RULES_SKELETON_NOT_WIRED comment-rewrite + T_EXPORTER_METRICS_FORMAT version-literal bump + T_ATTACH_TAG_MISMATCH preflight hybrid-rewrite). All 43 other ctest bodies BYTE-EQUIVALENT. Documented + scope-fenced. Was "2 EDITs" at initial §5.31 publish; bumped to 3 post-§5.31 EDIT-2 Phase B adjudication on bpftool-vs-libbpf-skeleton BTF asymmetry (D-3.4b-22). | `git diff <MVP-3.4.5-HEAD> --stat tests/T_*.sh` shows 3 modified files (plus 6 NEW files). The 3 MODIFIED files have diffs confined to: T_RULES_SKELETON_NOT_WIRED — 2 lines of comment-rewrite (lines 14 + 297 ranges); T_EXPORTER_METRICS_FORMAT — 2 lines of version-literal-bump (lines 21-22 comment + line 100-101 assertion literal); T_ATTACH_TAG_MISMATCH — ~5-7 LOC preflight body rewrite at line 124-131 area (real-fixture branch flips from bpftool standalone to xdpmacfilter attach-based tag-read; alt-fixture branch unchanged). Any additional diff = `[INVARIANT-VIOLATED]` (impl/tester SendMessages architect for any 4th EDIT). |

**No deletions/relaxations** of PI-1..PI-34 in this slice EXCEPT:
- **PI-13 ADJUDICATED** (PASS-as-additive per HG-3.4b-1 + D-3.4b-1; offset-0 byte preserved; value_size 1 → 8 documented + intended).
- **PI-28 EXTENDED** (PI-28-3.4b — `mac_filter_prog` body adds `bump_rule` calls + typed-pointer reads; first substantive body change since MVP-3.2; all OTHER body lines byte-equivalent; functional verdict for same inputs unchanged + per-rule counter bump per match).
- **PI-29 CARVE-OUT** (PI-29-3.4b — `rules` + `action_table` maps STILL NOT consulted; inner-VALUE's `rule_id` IS read; carve-out is explicit + scope-fenced).
- **PI-31 STRENGTHENED** (PI-31-3.4b — extends to new exporter translation units; READ-ONLY contract preserved).
- **PI-32 STRENGTHENED** (PI-32-3.4b — extends to sidecar-orphan tolerance).
- **PI-6 / PI-34 RELAXED** (PI-6-3.4b — 2-ctest-body-EDIT carve-out per PI-3.4b-9; narrower than PI-6-3.4.5's 7-EDIT carve-out; explicit + documented).

PI-7-3.4b-hpp STRENGTHENS PI-7-3.4.5-hpp (6th consecutive ZERO-diff cycle on loader.hpp AND config.hpp). PI-10-3.4b STRENGTHENS PI-10-3.4.5 (additive-only on mac_filter.h continues — though MVP-3.4.5 had ZERO diff on the header; this slice has ADDITIVE-ONLY, which is a relaxation from MVP-3.4.5's stricter ZERO).

#### §5.31 verifiable invariants for reviewer

(Per architect-spec §6.5 "Verification-hints discipline": these are GUIDANCE for the reviewer, NOT contracts for impl. Default MAY. Reserve MUST only for true PI-* contracts (PI-1..PI-34 + PI-3.4b-* + PI-7-3.4b-hpp/cpp ARE MUSTs by definition; the items below MAY be relaxed by impl if a contract elsewhere demands it). **Resolution rule for prose-vs-invariants conflicts within this amendment: invariants block wins, prose loses; if impl deviates on a SHOULD/MAY hint to satisfy a PI-* contract, reviewer's correct disposition is `inline-merge` on the hint text — NOT `[UNRELATED-EDIT]` on impl.**)

In addition to PI-1..PI-34 + PI-3.4b-* + PI-7-3.4b-hpp/cpp above:

- `git diff main -- src/lib/loader.hpp src/lib/config.hpp` SHOULD show ZERO output (PI-7-3.4b-hpp, 6th consecutive cycle on loader.hpp + 1st cycle on config.hpp).
- `git diff <MVP-3.4.5-HEAD> -- src/lib/loader.cpp` SHOULD show changes confined to the 6 enumerated scopes (a)-(f) in PI-7-3.4b-cpp.
- `git diff main -- src/common/mac_filter.h` SHOULD show ONLY additions (PI-10-3.4b additive-only).
- `git diff <MVP-3.4.5-HEAD> -- src/bpf/mac_filter.bpf.c` SHOULD show the PI-28-3.4b enumerated edit-set (inner-VALUE typedef × 2, MAC hit branch + bump_rule, CIDR hit branch + bump_rule, new `rule_counters` map decl, new `bump_rule` helper). ZERO diff to default-fallthrough / drop branches / IPv4 gate / ethhdr bounds-check.
- `git diff main -- tests/T_*.sh` SHOULD show: 6 NEW files (§6.47..§6.52) + 2 EDITED files (T_RULES_SKELETON_NOT_WIRED + T_EXPORTER_METRICS_FORMAT) per PI-3.4b-9 catalog. 44 of 46 pre-§5.31 ctest bodies byte-equivalent.
- `git diff main -- tests/CMakeLists.txt` SHOULD show 6 new `add_test` entries; ZERO modification to the 46 existing entries.
- `git diff main -- tests/fixtures/` SHOULD show: NEW `config_per_rule_counters.yaml` (for §6.47..§6.49 + §6.52); existing fixtures byte-equivalent.
- `git diff main -- tests/lib/` SHOULD show: NEW `read_rule_counters.py` (parallels read_stats.py); existing helpers byte-equivalent.
- `git diff main -- CMakeLists.txt` SHOULD show: VERSION bump 0.6.1 → 0.7.0 + 3-line addition (sidecar.cpp to xdpmf_internal + sidecar_reader.cpp + rule_counters_reader.cpp to xdpmf-exporter target sources).
- `git diff main -- CHANGELOG.md` SHOULD show NEW `[0.7.0]` entry + build-pace row.
- New files SHOULD exist: `src/lib/sidecar.{cpp,hpp}` (writer), `src/exporter/sidecar_reader.{cpp,hpp}` (parser), `src/exporter/rule_counters_reader.{cpp,hpp}` (PERCPU sum), 6 T_*.sh under `tests/`, 1 fixture under `tests/fixtures/`, 1 new helper under `tests/lib/`.
- 6 new ctests SHOULD pass (§6.47..§6.52); §6.49 (counter survival) + §6.51 (exporter labels) are the load-bearing pair.
- 44 of 46 pre-§5.31 ctests SHOULD still pass byte-equivalent (or legitimately SKIP-77).
- 2 PI-3.4b-9-EDITED ctests SHOULD pass with their updated bodies (T_RULES_SKELETON_NOT_WIRED comment-rewrite preserves assertion semantic; T_EXPORTER_METRICS_FORMAT version-literal bump aligns with PI-8-3.4b).
- `xdpmacfilter --version` SHOULD report `xdpmacfilter 0.7.0` AND `xdpmf-exporter --version` SHOULD report `xdpmf-exporter 0.7.0` (PI-8-3.4b).
- `XDPMF_SANITIZERS=ON` build SHOULD be clean for BOTH binaries (no UB / no leaks from new code).
- BPF object SHOULD verifier-load cleanly: `xdpmacfilter attach` on a fixture iface exits 0 (T_LOAD_ATTACH or equivalent existing test).
- `bpftool map show pinned ${PIN_DIR}/<iface>/rule_counters` SHOULD report `type percpu_array max_entries 64 value_size 8 key_size 4`.
- `bpftool map show pinned ${PIN_DIR}/<iface>/allowlist_a` SHOULD report `value_size 8` post-§5.31 (was 1 pre-§5.31 — PI-13-3.4b adjudicated extension).
- `bpftool map show pinned ${PIN_DIR}/<iface>/cidr_allowlist_a` SHOULD report `value_size 8` post-§5.31 (was 1 pre-§5.31 — PI-13-3.4b symmetric CIDR extension).
- `bpftool map dump pinned ${PIN_DIR}/<iface>/allowlist_a format c | head -c 1` for an occupied slot SHOULD return `0x01` (PI-13-3.4b offset-0 byte-equivalence to PI-27).
- `bpftool map dump pinned ${PIN_DIR}/<iface>/allowlist_a --json | jq '.[0].formatted.value.rule_id'` SHOULD return the rule.id of the matching applied rule (PI-13-3.4b new offset-4 field).
- `test -f /run/xdpmacfilter/<iface>/rule_index.json` SHOULD return success after every successful apply (PI-3.4b-5; SUPERSEDED path per §5.31 EDIT-1 — was `${PIN_DIR}/<iface>/...` at initial publish).
- `jq -e '.schema_version == 1' /run/xdpmacfilter/<iface>/rule_index.json` SHOULD return success (PI-3.4b-5).
- `curl -s http://127.0.0.1:9417/metrics | grep -cE '^xdpfilter_rule_match_total\{'` SHOULD return ≥1 for an exporter against a non-empty fleet (PI-3.4b-6).
- `grep -c '^\s*{ &SkelMapsT::' src/lib/loader.cpp` SHOULD return 13 (PI-3.4b-8 — kManagedMaps[] grew 12 → 13).
- `grep -rE 'bpf_(map_(update\|delete)_elem\|obj_pin\|link_create\|link_destroy\|xdp_(attach\|detach)\|prog_load)' src/exporter/` SHOULD return ZERO matches (PI-31-3.4b — exporter READ-ONLY extended to NEW exporter translation units).
- Optional verifier-canary: `xdpmacfilter attach --iface lo` exits 0 on a kernel that supports BPF (sanity check that PI-13-3.4b inner-VALUE extension + PI-28-3.4b new bump_rule reads do NOT trigger verifier-reject).

#### §7 OOS — MVP-3.4b cycle 1 components SHIPPED + new fences + cycle 2/3 surfaced

##### Moved from deferred to SHIPPED (per MVP-3.4b cycle 1)

The following items were deferred at §5.29 OOS (MVP-3.4) + carried forward through §5.30 OOS (MVP-3.4.5) and are now CLOSED by this slice:

- ~~**Per-rule counter map (`per_rule_counters` BPF_MAP_TYPE_PERCPU_*)** — MVP-3.4b slice per Open Q #13 RESOLUTION.~~ **— SHIPPED in §5.31** as `rule_counters` PERCPU_ARRAY[64] of __u64 (Q1 B3 + D-3.4b-12 + PI-3.4b-1).
- ~~**Inner-allowlist-value extension (`__u8` → `struct {__u8 present; __u32 rule_id;}`)** — MVP-3.4b. Gated by PI-13-3.1 adjudication.~~ **— SHIPPED in §5.31** as `struct allow_entry` (HG-3.4b-1 PASS-as-additive adjudication + D-3.4b-1 + PI-13-3.4b). Byte layout `present` at offset 0, `_pad[3]` at offsets 1-3, `rule_id` at offsets 4-7 — total 8 bytes. SYMMETRIC across MAC HASH + CIDR LPM_TRIE.
- ~~**Datapath wiring of `rules` via inner-value's rule_id** — MVP-3.4b.~~ **— SHIPPED in §5.31** as `bump_rule(entry->rule_id)` calls in MAC HASH-hit and CIDR LPM_TRIE-hit branches (Q1 B3 + PI-3.4b-4 + PI-28-3.4b). The `rules` map ITSELF is still NOT consulted by datapath (PI-29-3.4b carve-out) — only the inner-allowlist-value's rule_id is read; full action-dispatch via rules+action_table is MVP-3.4c future.
- ~~**Prometheus `xdpfilter_rule_match_total{iface, rule_id}` series in exporter** — MVP-3.4b.~~ **— SHIPPED in §5.31** as `xdpfilter_rule_match_total{iface, rule_id, action}` (Q4 A3 — action added as label per D-3.4b-8 + PI-3.4b-6).
- ~~**Sidecar JSON `${PIN_DIR}/rule_index.json`** — MVP-3.4b optional per arch-v2.md Option 2.~~ **— SHIPPED in §5.31** as `${PIN_DIR}/<iface>/rule_index.json` per Q3 P1 + Q2 S1 + D-3.4b-3 + PI-3.4b-5.
- ~~**PI-13-3.1 adjudication BEFORE the slice starts** — Open Q gating MVP-3.4b.~~ **— SHIPPED in §5.31** as HG-3.4b-1 + D-3.4b-1 PASS-as-additive ruling (cross-references PI-27 strict reading + offset-0 byte-equivalence proof). PI-13-3.4b documents the byte-by-byte adjudication.

##### Additional MVP-3.4b cycle 1 deliverables (NOT in prior OOT queues; surfaced in this slice)

- **PI-3.4b-9 surgical fix catalog** — Phase A grep finding shrinks brief's ~5-fixture estimate to 2 actual EDITs. Confirms [[impl-role-discipline]] dividend from MVP-3.4.5 (Phase A code-grep discipline catches scope-fence accurately).
- **`kManagedMaps[]` 13th entry** — MVP-3.4.5 HK-9 landmine refactor dividend. One-line table extension instead of 3-callsite lockstep updates.
- **Sidecar writer + reader (roll-your-own JSON, no new build dep)** — cycle 1 brownfield discipline preserves zero-deps project value.

##### Surfaced as next-natural slice

**MVP-3.4b cycle 2 — atomic-swap promotion of `rules` map + counter management API** (gating on operator demand):

- Promote `rules` map from SHARED ARRAY to parallel-outer via `rules_outer` ARRAY_OF_MAPS (mirrors §5.27 CIDR axis pattern). Required IF MVP-3.4c action-dispatch wires `rules` consumption from datapath (per HG-3.4b-4 surfaced Open Q).
- `xdpmacfilter` subcommand `reset-counters --iface X [--rule-id N]` for explicit counter zero (currently no API; operators must `detach` + re-`attach` to clear).
- Atomic-swap of `rule_counters` IF a future use case demands "counters reflect ONLY the currently-applied config" (today PI-3.4b-2 PRESERVES across apply — operator-grade Prometheus monotonicity).

**MVP-3.4c — action-table dispatch (drop rules operative)**:

- `mac_filter_prog` extends to read `rules[rule_id].action_id` then `action_table[action_id].action_type` and DISPATCH (PASS / DROP based on action_type — currently DROP is via defaults[active]=drop fallthrough; cycle 2/3 makes drop rules per-rule-operative).
- Allows drop rules with `match.mac` (or CIDR) that's ALSO in the inner-allowlist via a PASS rule — currently §5.26 schema's "drop rules don't populate inner" means drop is via absence-from-allowlist; cycle 2/3 enables explicit drop semantics.
- Requires MVP-3.4b cycle 2 (`rules` atomic-swap) OR copy-on-write rules-map semantics.

**MVP-3.5 — JSON structured logs in loader + exporter** (carry-forward from §5.30 surfaced-next-natural; UNCHANGED by §5.31):

- Loader (`xdpmacfilter`) emits structured JSON log lines when `XDPMF_LOG_FORMAT=json` env var is set; default `XDPMF_LOG_FORMAT=text`.
- Exporter (`xdpmf-exporter`) emits structured JSON log lines under same env-var contract.
- Likely shape per event: `{"ts":"<iso8601>","level":"<info|warn|error>","event":"<name>","iface":"<iface or null>","msg":"<existing prose>","fields":{...}}`.
- Sidecar `rule_index.json`'s `applied_at` field forward-compats with this slice (loader already emits ISO-8601 timestamps).

##### NEW out-of-scope fences (per §5.31; carry-forward unchanged from §5.30 unless noted)

- **`action_table` datapath consultation (action-dispatch)** — MVP-3.4c future cycle. PI-29-3.4b explicitly: action_table is still NOT consulted by datapath this cycle. Action dispatch via existing PASS/DROP branches retained.
- **`rules` map atomic-swap promotion (D-3.4-4 close-out)** — MVP-3.4b cycle 2 / MVP-3.4c. `rules` stays SHARED with clear-and-rewrite this slice (HG-3.4b-4 + D-3.4b-4). Lifting this fence requires the datapath to consult `rules` map (which cycle 1 explicitly does NOT do).
- **Action types beyond {PASS, DROP}** — MVP-3.8+ (carry-forward).
- **Cap-lift beyond 64 rules** — permanent product contract per /mint-hld Option 5 + Open Q #13 Q5 human-gate (carry-forward; XDPMF_ALLOWLIST_MAX = XDPMF_RULE_COUNTERS_MAX = 64).
- **Named rules schema-v2 (Option 4 from /mint-hld)** — deferred indefinitely. Operator's `id:` IS the canonical identifier per Q5 R1 (carry-forward).
- **Sidecar JSON history / versioning** — single rule_index.json, overwritten on apply; no rotation, no .prev backup, no audit log of past rule sets (carry-forward fence).
- **Sidecar JSON path under FHS /var/lib (P2)** — staying with bpffs-adjacent P1 per Q3 default (carry-forward; future-cycle if operator demand surfaces).
- **`xdpfilter_drop_match_total` as separate series (Q4 A2)** — action as label per A3 default (carry-forward; future-cycle if operator demand surfaces).
- **Sidecar schema S2 description-field + S3 deployment-metadata** — explicitly REJECTED at Q2 + D-3.4b-6; future-cycle if operator demand surfaces. NEW FENCE.
- **`nlohmann/json` as build dep** — explicitly REJECTED at D-3.4b-10; roll-your-own writer + line-regex reader for cycle 1. Future cycles MAY adopt if 2nd-3rd JSON emission point surfaces. NEW FENCE.
- **Full JSON parser in sidecar_reader** — explicitly REJECTED at D-3.4b-14; line-oriented regex extraction sufficient for cycle 1 schema. NEW FENCE.
- **Counter zero / reset API (`xdpmacfilter reset-counters`)** — MVP-3.4b cycle 2 candidate; cycle 1 has no zeroing primitive (operators must detach + re-attach to clear). NEW FENCE.
- **rule_counter atomic-swap** — MVP-3.4b cycle 2 candidate if "counters reflect ONLY current config" semantic surfaces. Cycle 1 preserves across apply (PI-3.4b-2). NEW FENCE.
- **Q1 B1 (two-call-site bump_rule, literally duplicate)** — REJECTED at Q1; cycle 1 ships B3 unified per-match semantic (still two source-line call-sites for verifier acceptance; semantically B3). NEW FENCE.
- **Q1 B2 (MAC-only bump_rule, defer CIDR)** — REJECTED at Q1; symmetric MAC/CIDR from cycle 1. NEW FENCE.
- **Q5 R2 (source-order allocation) + Q5 R3 (sort-by-name)** — REJECTED at Q5; R1 operator-id is canonical. NEW FENCE.
- **Option 3 fallback (two-map shadow `mac_to_rule_id` + `cidr_to_rule_id`)** — contingent fallback ONLY IF PI-13-3.4b verifier-rejects during Phase 2 impl. Cycle 1 ships Option 2; Option 3 is the documented contingency per arch-v2.md §"§MVP-3.4 Open Question #13 RESOLUTION" Convergence. If verifier-rejects: impl peer-DMs architect; architect re-scopes to Option 3 + the slice budget inflates ~1 cycle.
- **Optional sub-test §6.53 T_RULE_COUNTER_VERIFIER_GREEN** — REJECTED at Phase A; existing tests exercise verifier indirectly. If impl reports verifier turbulence during Phase 2, tester adds it then. NEW FENCE.
- **Documentation pass (Prometheus alert semantics for `xdpfilter_rule_match_total`, FLEET_DEPLOYMENT.md exporter section)** — separate manual pass per user direction. NOT in this slice. NEW FENCE.
- **TSAN build / CO-RE field-probe failure test** — coverage scope, NOT in this slice (carry-forward from §5.30 NEW FENCE).
- **Systemd sandbox directives (ProtectSystem strict, PrivateTmp, etc.)** — defense-in-depth security cycle; deferable to MVP-3.5+ (carry-forward).
- **Library extraction `libxdpmf.so.0` (MVP-3.6+)** — carry-forward.
- **Daemon `xdpmfd` (MVP-3.6+)** — carry-forward.
- **Binary rename `xdpmacfilter` → `xdpfilter` (MVP-3.12)** — carry-forward.
- **L4 ports / VLAN / IPv6 CIDR** — carry-forward per MVP-3.2 §7 OOS.
- **JSON structured logs (MVP-3.5)** — carry-forward (surfaced explicitly as next-natural; no scope change).
- **sFlow (MVP-3.6 conditional)** — carry-forward.

##### Anti-misdiagnosis notes (institutional learning, per architect-spec §6.6)

This slice carries forward all anti-misdiagnosis guards from prior cycles + adds three specific to MVP-3.4b:

1. **Cap-set declaration on a NEW invocation path** (inherited from §5.28 D-3.3-6 + §5.29 D-3.4-6 + §5.30 anti-misdiagnosis carry): unchanged. Exporter cap-set (`AmbientCapabilities=CAP_BPF`) unchanged this slice. New BPF map `rule_counters` is `BPF_OBJ_GET`-readable with CAP_BPF only (same as existing `stats` map) — no new cap requirement.

2. **Silent-divergence-from-design pattern** (inherited from MVP-3.4 review.md OOT-1/OOT-2 misdiagnosis pair, formalized as [[impl-role-discipline]]): impl follows design; disagreement is OK but ONLY via explicit Phase B escalation. Specific to this slice: PI-13-3.4b adjudication is the load-bearing call; **if impl encounters verifier-reject AT ANY POINT during Phase 2, impl MUST SendMessage architect BEFORE attempting workarounds**. The default workaround surface is broad (rewrap `bump_rule` differently, change `struct allow_entry` layout, use `BPF_CORE_READ`, etc.) and silent workarounds could mask a fundamental Option 2 vs Option 3 question. Architect Open Q to re-evaluate; impl does NOT decide unilaterally.

3. **Three-callsite lockstep landmine** (project memory [[libbpf-pin-by-name-three-callsites]]): RESOLVED in MVP-3.4.5 HK-9; **dividend collected in §5.31** (kManagedMaps[] gains 13th entry — one-line edit instead of 3 lockstep literal-array updates). Anti-misdiagnosis note: this slice is the validation that the HK-9 refactor was the correct architecture. **Future-cycle guard for any architect agent**: when adding a NEW BPF map declared with `LIBBPF_PIN_BY_NAME`, the kManagedMaps[] table MUST be extended (one line) AND that's it — the three loops walk the table automatically. If a future cycle's MAP is NOT `LIBBPF_PIN_BY_NAME` (e.g. a global non-per-iface map), it does NOT belong in kManagedMaps[]; the architect documents the exception in the new slice's Decisions section.

4. **Verification-hints discipline trap** (inherited from MVP-3.1/3.2/3.3 verification-hints rework cycles + MVP-3.4.5 reinforcement): the §5.31 verifiable invariants section above is GUIDANCE for the reviewer, NOT contracts for impl. Items default to SHOULD/MAY; MUST is reserved for PI-* contracts. If impl deviates on a SHOULD/MAY hint to satisfy a PI-* contract, reviewer disposition is `inline-merge` on the hint text — NOT `[UNRELATED-EDIT]` on impl. Resolution rule for prose-vs-invariants conflicts within this amendment: invariants block wins, prose loses (stated once per the amendment template; this single statement covers all §5.31 prose vs. PI-* conflicts).

5. **Phase A code-grep discipline pays off** (NEW anti-misdiagnosis note): the Phase A grep of inner-value touch sites + fixture-ripple sites + version-literal sites caught (a) the actual fixture-ripple count is 2 EDITs NOT 5, (b) `Config::Rule::id` field already exists (brief's overstatement on `Config::Rule gains rule_id`), (c) the `kManagedMaps[]` table is at 12 entries (not 9 or 10 per prior cycle counts) and grows to 13. **Future-cycle guard for any architect agent**: BEFORE publishing brownfield design.md, grep the literal field counts / table sizes / version strings the brief mentions. The 15-minute Phase A pass during this slice's architecture phase reduced expected Phase B EDITs from ~3 (MVP-3.4.5 average) to ~0 expected (TBD pending impl). Citation: this anti-misdiagnosis note IS the Phase A discipline rule from architect spec, validated by this slice.

Evidence: `mint/task-brief.md` MVP-3.4b cycle 1 brief (HG-3.4b-1/2/3/4 + Q1-Q5 + PI-3.4b-1..PI-3.4b-10); `mint/architecture-v2.md` §"§MVP-3.4 Open Question #13 RESOLUTION" Option 2 + Caveat (b) human-gate (committed 2d4b31a 2026-05-24 — the load-bearing pre-decision); §5.29 (MVP-3.4 ancestor — `rules` + `action_table` skeleton declared, PI-27/PI-13-3.4 STRICT-byte-shape defer fence, PI-28 mac_filter_prog byte-equivalent fence — BOTH LIFTED this slice with documented adjudications); §5.30 (MVP-3.4.5 ancestor — HK-9 kManagedMaps[] refactor SHIPPED + landmine resolved, PI-7-3.4.5-hpp 5th-cycle ZERO-diff); §5.26 D-3.1-1 (apply_request lives in loader.cpp); §5.26 schema rule 4 + rule 3 (id ∈ [0, 63], action ∈ {pass, drop} — preserved); §5.27 Q1 AS1 (CIDR-axis active_idx flip mechanism — preserved + SYMMETRIC inner-VALUE extension); project memory [[libbpf-pin-by-name-three-callsites]] (HK-9 dividend collected); [[impl-role-discipline]] (Phase B escalation discipline); architect-spec Phase A code-grep discipline (15-minute grep pass during this slice — fixture-ripple count corrected, Config::Rule pre-existing-field finding, kManagedMaps[] 12-entry baseline).

#### §5.31 EDIT-1 — Phase B platform-constraint correction: Q3 sidecar path P1 → P4 (2026-05-25, dialog with mint-dev-impl)

**Trigger**: mint-dev-impl Phase B peer-DM with concrete platform-constraint evidence that Q3 P1 (`${PIN_DIR}/<iface>/rule_index.json` under bpffs) is **infeasible**.

**Evidence (impl-supplied, reproduced verbatim)**:
```
$ sudo mkdir -p /sys/fs/bpf/xdpmacfilter/test_dir       # OK
$ sudo touch /sys/fs/bpf/xdpmacfilter/test_dir/foo.txt
touch: cannot touch '/sys/fs/bpf/xdpmacfilter/test_dir/foo.txt': Operation not permitted

$ sudo /home/user/mint-l2-mac-filter/build/src/cli/xdpmacfilter attach --iface veth_v0
xdpmacfilter: trust_model=strict
xdpmacfilter: WARN: rule_index.json write failed: Operation not permitted
attached prog id 28562 to veth_v0   # apply succeeds; sidecar write fails per D-3.4b-17 non-fatal
```

**Root cause**: bpffs (`bpf` filesystem type, kernel/bpf/inode.c) only accepts pinned BPF objects (maps/programs/links) via the `bpf_obj_pin` syscall plus `mkdir` for directories. Regular file creation via `open(O_CREAT)` returns EPERM at the bpffs inode_create hook. My D-3.4b-7 + Q3 P1 prose (and the task-brief's mirrored claim at line 127) — "bpffs is `tmpfs`-mounted in standard configurations; rule_index.json survives only as long as the bpffs mount survives" — was **factually wrong**. bpffs is its OWN filesystem type, not tmpfs.

**Disposition**: D-3.4b-21 (NEW) supersedes D-3.4b-7. New Q3 winning option is **P4 = `/run/xdpmacfilter/<iface>/rule_index.json`** (a 4th option not enumerated in the original Q3; introduced Phase B per impl's recommendation). All initial PI-3.4b-5 references to `${PIN_DIR}/<iface>/rule_index.json` are SUPERSEDED with the new `/run/xdpmacfilter/<iface>/rule_index.json` path; inline `[SUPERSEDED]` markers added on the affected items in the prior §5.31 sub-sections.

**This is a tactical platform-constraint correction within Q3 scope (path choice)**, not a HG human-gate-tier decision. HG-3.4b-3 ("INCLUDE sidecar in cycle 1") stands UNCHANGED. The feature ships; only the path moves. Team-lead notified at SendMessage time; ack pending but architect proceeding per "design flaw → re-design item Z + edit design.md" path in architect spec.

##### D-3.4b-21 — Sidecar path = `/run/xdpmacfilter/<iface>/rule_index.json` (Q3 P4 — supersedes D-3.4b-7) — because

bpffs **rejects regular-file creation** per kernel/bpf/inode.c; D-3.4b-7's P1 premise (bpffs is tmpfs) is factually wrong. `/run` is the systemd-blessed tmpfs convention for ephemeral state (FHS 3.0 §3.15; systemd `RuntimeDirectory=` family of directives) and is universally writable as root on any systemd host. Adopting P4 preserves the ORIGINAL design intent that motivated P1 (ephemeral; tracks bpffs lifecycle) — the corrected premise is that `/run` is the actual tmpfs filesystem, not bpffs. Smallest delta from build state at the time of impl's peer-DM (build was already green at 0.7.0; only path constants + mkdir-p + 3 ctest path strings change). Avoids the FHS coordination cost that Q3 P2 explicitly rejected at Phase A (`/var/lib/...` would need mkdir + chown + systemd `StateDirectory=` + ansible touch).

**Lifecycle** (post-correction): `/run/xdpmacfilter/<iface>/rule_index.json` survives loader restart but NOT reboot (tmpfs). Symmetric to pinned-map lifecycle on bpffs unmount: BOTH bpffs unmount AND reboot clear the sidecar; operator's mental model is preserved ("ephemeral state, refreshed on next apply"). Exporter sidecar-orphan tolerance (PI-32-3.4b) handles the post-reboot pre-first-apply window via `action="unknown"` labels.

**Concrete impl contract changes** (Phase B-amended):
- `src/common/mac_filter.h` (additive — PI-10-3.4b ADDITIVE-ONLY preserved):
  ```
  /* §5.31 EDIT-1 (Phase B Q3 P4 correction): sidecar lives on tmpfs under
   * /run because bpffs rejects regular-file creation. */
  #define XDPMF_SIDECAR_ROOT  "/run/xdpmacfilter"
  ```
- `src/lib/sidecar.cpp` `write_rule_index()`: writes to `${XDPMF_SIDECAR_ROOT}/<iface>/rule_index.json` with `mkdir -p ${XDPMF_SIDECAR_ROOT}/<iface>` before atomic-write. Failure to create directory OR write file remains non-fatal per D-3.4b-17 (WARN-and-continue; apply still exits 0).
- `src/exporter/sidecar_reader.cpp` (parser): reads from `${XDPMF_SIDECAR_ROOT}/<iface>/rule_index.json` (NEW path constant) — exporter still discovers per-iface via the existing-iface set, but the sidecar-root scan is now `/run/xdpmacfilter/*/rule_index.json` instead of `${XDPMF_BPFFS_ROOT}/*/rule_index.json`. Discovery model unchanged; root constant changes.
- `src/exporter/main.cpp`: NO change required if discovery delegates iface enumeration to the existing bpffs stats-pin scan (per-iface set comes from there; sidecar reader is keyed by iface name). If impl chose to enumerate from sidecar root directly, that scan path moves to `XDPMF_SIDECAR_ROOT` — impl picks the cleaner shape.

**FileList row update for `src/common/mac_filter.h`** (supersedes the row in §5.31 EDITED table):
> ADD `XDPMF_SIDECAR_ROOT "/run/xdpmacfilter"` (NEW constant per §5.31 EDIT-1) — in addition to the prior-listed `struct allow_entry`, `XDPMF_MAP_RULE_COUNTERS_NAME`, `XDPMF_RULE_COUNTERS_MAX`. ALL additions; ZERO modifications to existing types/constants. PI-10-3.4b ADDITIVE-ONLY contract preserved.

**Test path corrections** (supersedes the path strings in §6.50 / §6.51 / §6.52 / §6.49 / §6.47 / §6.48):
- `T_SIDECAR_JSON_SHAPE` (§6.50): asserts existence + jq-validation at `/run/xdpmacfilter/<iface>/rule_index.json` (was `${PIN_DIR}/...`). Permission check `stat -c %a` against the new path. Negation: apply-fail does not corrupt prior sidecar at the SAME `/run/...` path.
- `T_EXPORTER_RULE_LABELS` (§6.51): orphan sub-test deletes `/run/xdpmacfilter/<iface>/rule_index.json` (was `${PIN_DIR}/...`).
- `T_DROP_RULE_BUMPS_COUNTER` (§6.52): asserts `jq` on `/run/xdpmacfilter/<iface>/rule_index.json` for the drop-rule action label (was `${PIN_DIR}/...`).
- `T_RULE_COUNTER_MAC_HIT_BUMPS` (§6.47), `T_RULE_COUNTER_CIDR_HIT_BUMPS` (§6.48), `T_RULE_COUNTER_SURVIVES_APPLY` (§6.49): assertions for `rule_counters` map are UNCHANGED (counters live in bpffs under `${PIN_DIR}/<iface>/rule_counters` — pinned BPF map, NOT a sidecar file). ONLY tests that touch `rule_index.json` need path updates (3 tests).
- Cleanup: ctests SHOULD `rm -f /run/xdpmacfilter/<iface>/rule_index.json` in their cleanup paths (or `rm -rf /run/xdpmacfilter/<iface>/` if no other state lives there) — symmetric to existing bpffs pin-dir cleanup.

**PI-3.4b-9 fixture-ripple count update**: still 2 EDITed ctest BODIES (the path correction does NOT add new EDIT files; T_SIDECAR_JSON_SHAPE / T_EXPORTER_RULE_LABELS / T_DROP_RULE_BUMPS_COUNTER are NEW ctests and so their path strings are written-from-scratch per EDIT-1, not "edited"). Only T_RULES_SKELETON_NOT_WIRED + T_EXPORTER_METRICS_FORMAT continue to be the EDITED bodies. **PI-6-3.4b / PI-34 strict-superset with 2-EDIT carve-out UNCHANGED**.

**PI-7-3.4b-hpp impact**: ZERO. `loader.hpp` + `config.hpp` byte-equivalent still. The new `XDPMF_SIDECAR_ROOT` constant is in `src/common/mac_filter.h` (additive — PI-10-3.4b), NOT in any public-API header.

**PI-7-3.4b-cpp impact**: scopes (a)-(f) in PI-7-3.4b-cpp's scope-fence UNCHANGED; the path string change inside `apply_request`'s sidecar-write step (scope (e)) is BYTE-EQUIVALENT in terms of which function the hunk lives in. Reviewer's regional-diff check passes as before.

##### Anti-misdiagnosis institutional learning from §5.31 EDIT-1 (NEW; supplements §7 anti-misdiagnosis notes)

**Add to §7 OOS anti-misdiagnosis notes after item 5 (Phase A code-grep discipline):**

6. **bpffs ≠ tmpfs — filesystem-semantics misdiagnosis trap**. The original D-3.4b-7 + Q3 P1 + task-brief.md line 127 ALL described bpffs as "tmpfs-mounted". This is FALSE: bpffs is its own filesystem type (kernel/bpf/inode.c) which rejects regular-file creation. The factual error was inherited from the task-brief and not caught by Phase A code-grep discipline (which checked LITERAL code sites, NOT conceptual claims about kernel filesystem semantics). **Future-cycle architect anti-misdiagnosis rule**: when picking a path under bpffs OR any non-mainline filesystem for a regular-file write, RUN `sudo touch ${PATH}/probe.txt; ls -l ${PATH}/probe.txt; rm -f ${PATH}/probe.txt` smoke-check during Phase A grep discipline BEFORE publishing the design. Cost: 5 seconds. Benefit: catches THIS class of bug before it becomes a Phase B platform-constraint surprise. **Validated by §5.31 EDIT-1 (2026-05-25)**: impl peer-DM caught it cleanly via [[impl-role-discipline]] mechanism, but cycle-1 cost was 1 architect EDIT + 1 impl context-switch + path-rewire across 4 source files. A 5-second Phase A `sudo touch` would have surfaced it during initial design.

This learning is recorded as a permanent guard for any future cycle that introduces a NEW sidecar / log / state file under bpffs OR any unusual filesystem (procfs, sysfs, debugfs, configfs). Cite §5.31 EDIT-1 as the source.

##### §7 OOS update (post-EDIT-1)

The "**Sidecar JSON path under FHS /var/lib (P2)**" NEW FENCE entry stands UNCHANGED — P2 still out of scope per the FHS coordination cost rationale. The original Q3 P1 (bpffs-path) becomes RETROACTIVELY OOS (was never feasible; reviewer notes the platform-constraint as the gating reason, not architect preference).

NEW FENCE: **`/run` as sidecar lifetime guarantee** — `/run/xdpmacfilter/<iface>/rule_index.json` is cleared on reboot (tmpfs). Operators wanting persistent rule_id → action labels across reboot must EITHER (a) ensure `xdpmacfilter apply -f <config>` runs on boot (e.g. via systemd unit `Before=...network-pre.target` with `Type=oneshot`) — recommended pattern per FLEET_DEPLOYMENT.md, OR (b) wait for Q3 P2 migration in a future cycle. Cycle 1 ships /run only.

##### Notifications dispatched (Phase B closure dispatch)

Per architect spec "design flaw" scenario:
1. team-lead notified via SendMessage at correction-flag time with the diff summary + Option A pick + 60s implicit-ack window.
2. mint-dev-impl will be notified via SendMessage with the design.md diff line ranges + the XDPMF_SIDECAR_ROOT constant name + approval for Option A.
3. mint-dev-tester will be notified via SendMessage with the path change so ctest path-string assertions reflect `/run/xdpmacfilter/<iface>/rule_index.json` instead of `${PIN_DIR}/<iface>/...`.

#### §5.31 EDIT-2 — Phase B 3rd PI-3.4b-9 carve-out: T_ATTACH_TAG_MISMATCH preflight (bpftool-vs-skeleton BTF asymmetry; 2026-05-25, dialog with mint-dev-tester + mint-dev-impl)

**Trigger**: Phase 2.5 smoke surfaced T_ATTACH_TAG_MISMATCH (§6.14, MVP-2 Sec-era test) red post-§5.31. Impl confirmed root cause; tester peer-DM'd architect for adjudication on a 3rd PI-3.4b-9 EDIT.

**Root cause** (bpftool-API asymmetry, NOT a §5.31 contract bug):
- `tests/T_ATTACH_TAG_MISMATCH.sh:124-131` runs a **defensive tag-distinctness preflight** that uses standalone `bpftool prog load ${MAC_FILTER_BPF_O} ${SCRATCH_PIN} type xdp` to compute the real fixture's kernel-side tag BEFORE invoking the loader.
- Pre-§5.31 the preflight worked because the inner-VALUE was `__u8` (size 1).
- Post-§5.31 the standalone `bpftool prog load` path doesn't propagate the BTF inner-template's `value_size=8` to the outer ARRAY_OF_MAPS shape; the verifier sees `vs=1` and rejects the offset-4 `entry->rule_id` load with `invalid access to map value, value_size=1 off=4 size=4`.
- **The actual `xdpmacfilter attach` path works correctly** — counters bump, sidecar writes, exporter emits new series. Impl's end-to-end is green. ONLY the standalone bpftool-load preflight breaks due to bpftool-vs-libbpf-skeleton BTF propagation asymmetry.
- The alt fixture (`mac_filter_alt.bpf.c`, trivial body returning XDP_PASS — no inner-value load) does NOT trigger this; its preflight branch works fine via bpftool standalone.

**Options considered**:
- A — drop bpftool real-fixture preflight, rely on downstream alien-refusal assertion as suspenders-only.
- **B (CHOSEN)** — hybrid: alt-fixture preflight stays via bpftool (works; trivial body); real-fixture preflight uses real loader path (`xdpmacfilter attach` → `bpftool prog show id <id>` → `xdpmacfilter detach`).
- C — mark preflight skipped with TODO; loses defensive-paranoia, creates tech debt.
- D — SKIP-77 whole test, defer fix to MVP-3.4c; rejected (gates PI-1 + PI-3 alien-refusal security-critical invariants).

**Disposition (D-3.4b-22)**: Option B. Real-fixture tag computed via real loader path (methodologically clean — test's real contract is exercised); alt-fixture tag computed via bpftool standalone (defensive belt preserved — catches alt-fixture build regression independent of the loader). Both belt + suspenders intact.

##### D-3.4b-22 — T_ATTACH_TAG_MISMATCH preflight: Option B hybrid (Phase B §5.31 EDIT-2) — because

The bpftool-based preflight's PURPOSE is to verify alt-fixture tag ≠ real-fixture tag (so the downstream alien-refusal assertion is testing TAG-mismatch, not name-mismatch). Two ways to read tags:
1. **Standalone bpftool prog load** (pre-§5.31 path) — works for trivial programs (alt fixture); breaks for our real program post-PI-13-3.4b due to bpftool-vs-libbpf BTF propagation asymmetry on inner-template ARRAY_OF_MAPS value_size.
2. **Real loader path** (`xdpmacfilter attach`) — works for our real program (skeleton init handles BTF correctly).

Option B uses the right tool per fixture: standalone bpftool for alt (still works), real loader for real (works post-§5.31). The hybrid keeps the test methodologically clean: the real fixture's tag is whatever the actual loader sees post-load — which is what the test downstream actually verifies. Cost: ~5-7 LOC delta in T_ATTACH_TAG_MISMATCH.sh:124-131 area.

Concrete shape (impl reference; tester picks exact bash idiom):
```
# Real-fixture tag via real loader (§5.31 EDIT-2 Option B — bpftool standalone
# can't load post-PI-13-3.4b inner-VALUE-extended fixtures due to BTF asymmetry):
sudo -n ${XDPMF_BIN} attach --iface ${IFACE_A}
REAL_PROG_ID=$(sudo -n bpftool net show dev ${IFACE_A} | awk '/prog id/ {print $3}')
REAL_TAG=$(sudo -n bpftool prog show id ${REAL_PROG_ID} --json | jq -r '.tag')
sudo -n ${XDPMF_BIN} detach --iface ${IFACE_A}

# Alt-fixture tag via bpftool (trivial body, no offset-4 load — still works):
sudo -n bpftool prog load ${MAC_FILTER_ALT_BPF_O} ${SCRATCH_PIN_ALT} type xdp
ALT_TAG=$(sudo -n bpftool prog show pinned ${SCRATCH_PIN_ALT} --json | jq -r '.tag')
sudo -n bpftool prog unpin ${SCRATCH_PIN_ALT}

[[ "${REAL_TAG}" != "${ALT_TAG}" ]] || { echo "preflight FAIL: tags identical"; exit 1; }
```

##### PI-3.4b-9 carve-out amendment (§5.31 EDIT-2): 2 EDITs → 3 EDITs

The PI-3.4b-9 fixture-ripple catalog gains a 3rd EDITed ctest body. Updated table:

| Path | Line(s) | Change kind | Reason |
|---|---|---|---|
| `tests/T_RULES_SKELETON_NOT_WIRED.sh` | 14 (comment), 297 (stderr-msg) | comment + stderr-message rewrite | PI-13-3.4b PASS-adjudication-forced (no assertion change) — see §5.31 PI-3.4b-9 catalog above |
| `tests/T_EXPORTER_METRICS_FORMAT.sh` | 21-22 (comments), 100-101 (assertion) | version-literal bump | HK-8-forced 0.6.1 → 0.7.0 — see §5.31 PI-3.4b-9 catalog above |
| **`tests/T_ATTACH_TAG_MISMATCH.sh`** (NEW per §5.31 EDIT-2) | **124-131 (defensive preflight)** | **preflight body rewrite — real-fixture branch flips from bpftool standalone to `xdpmacfilter attach`-based tag-read (hybrid; alt-fixture branch unchanged)** | **bpftool standalone `prog load` rejects post-PI-13-3.4b inner-VALUE-extended fixtures due to bpftool-vs-libbpf-skeleton BTF propagation asymmetry on inner-template ARRAY_OF_MAPS value_size. Real loader path (skeleton init) handles BTF correctly. Hybrid preserves defensive belt + suspenders.** |

**PI-6-3.4b / PI-34 carve-out language amendment (supersedes prior 2-EDIT phrasing)**:

> **PI-6-3.4b** | **46 pre-§5.31 ctests pass byte-equivalent OR legitimately SKIP-77 — STRICT SUPERSET with explicit 3-ctest-body EDIT carve-out** (T_RULES_SKELETON_NOT_WIRED comment-rewrite + T_EXPORTER_METRICS_FORMAT version-literal bump + T_ATTACH_TAG_MISMATCH preflight hybrid-rewrite per PI-3.4b-9 catalog updated by §5.31 EDIT-2)

The 3rd EDIT is scope-fenced + documented. Reviewer accepts. The post-§5.31 EDIT-2 ctest-body count is 3 EDITed + 6 NEW + 43 byte-equivalent (out of 46 pre-§5.31 baseline) + the 6 NEW ctests for §6.47..§6.52.

##### Anti-misdiagnosis institutional learning from §5.31 EDIT-2 (NEW guard #7)

**Add to §7 OOS anti-misdiagnosis notes after item 6 (bpffs ≠ tmpfs trap):**

7. **bpftool-vs-libbpf-skeleton BTF propagation asymmetry — inner-template ARRAY_OF_MAPS value_size**. When the inner-VALUE of an outer ARRAY_OF_MAPS / HASH_OF_MAPS changes shape (size or layout), STANDALONE `bpftool prog load <obj.o> type xdp` may FAIL where skeleton-based libbpf load SUCCEEDS, because bpftool's standalone path doesn't always propagate the BTF inner-template's value_size to the outer map shape. The verifier then rejects loads from the inner with `invalid access to map value, value_size=<wrong> off=<X> size=<Y>`. **Future-cycle architect anti-misdiagnosis rule**: when the inner-value of an outer ARRAY_OF_MAPS / HASH_OF_MAPS changes (especially size, alignment, or new offset access in the datapath), grep tests for `bpftool prog load <our-obj>` invocations and validate each ONE against the new value_size BEFORE publishing the design:
```
grep -nE 'bpftool prog load.*mac_filter\.bpf\.o' tests/T_*.sh tests/lib/*.sh
```
For each hit, smoke-test the load with `sudo -n bpftool prog load <built-obj.o> /sys/fs/bpf/probe type xdp; rc=$?; sudo -n bpftool prog unpin /sys/fs/bpf/probe; echo $rc` — non-zero rc means the test will break post-rebuild and needs preflight migration (Option B pattern: real loader path for the affected fixture; standalone bpftool only for fixtures whose body avoids the new field access). Cost: ~30 seconds of Phase A grep + 5 seconds per smoke-test. Benefit: catches THIS class of bug before Phase 2.5 surfaces a red ctest. **Validated by §5.31 EDIT-2 (2026-05-25)**: only T_ATTACH_TAG_MISMATCH was affected (1 hit per Phase B grep), but Phase A would have caught it pre-publish. Combined with guard #6 (bpffs ≠ tmpfs) and guard #5 (Phase A code-grep discipline pays off): the Phase A discipline now covers literals + filesystem semantics + bpftool-API smokes.

**Bug 1 (T_RULE_COUNTER_MAC_HIT_BUMPS bpftool format-string drift) closure note** (per tester's report): tester switched to `--json | jq -r '.value_size'` per impl's Suggestion A; the test is NEW per §6.47 (write-from-scratch; PI-3.4b-9 unaffected). NO design.md amendment needed — captured here only as Phase B audit-trail.

##### Notifications dispatched (§5.31 EDIT-2 closure)

1. team-lead notified via SendMessage with the EDIT-2 carve-out bump 2 → 3 (not human-gate worthy; tactical Q within PI-3.4b-9 scope).
2. mint-dev-tester notified with Option B pick + concrete preflight rewrite shape + cite of D-3.4b-22 + PI-3.4b-9 catalog 3rd-row text.
3. mint-dev-impl notified via cc on the tester DM (audit-trail; no impl-side action needed — the fix is test-body, not impl-body).

### §5.32 MVP-3.5: JSON structured logs in loader + exporter (brownfield amendment, 2026-05-25)

**Purpose**: ship the structured-logging surface deferred from §5.30 §7 OOS (5 consecutive cycles' carry-forward). New env var `XDPMF_LOG_FORMAT={text,json}` (default `text`) selects the rendering for ALL diagnostic stderr lines in BOTH binaries (`xdpmacfilter` + `xdpmf-exporter`). In `text` mode, every emission is byte-equivalent to the pre-§5.32 line (load-bearing PI-3.5-1 — 52-ctest baseline IS the validation). In `json` mode, each emission becomes a single-line NDJSON object with a stable flat envelope `{ts, level, event, iface, msg, fields:{}}`. One NEW shared module `src/common/logger.{cpp,hpp}` owns the format selector + envelope renderer + event-name catalog as a compile-time constexpr table (operator log-shipping pipelines depend on stable event names).

The slice CLOSES the carry-forward fence on JSON logs. It LIFTS nothing — strictly additive. PI-7-3.5-hpp continues the loader.hpp/config.hpp ZERO-diff streak (7th consecutive cycle on loader.hpp; 2nd on config.hpp — the logger module owns its own header, not loader.hpp).

**Anchor sections**: §5.13 (no-logging-library decision — historically "no library at all"; §5.32 builds a TINY in-tree logger with NO external dep, preserving the spirit); §5.26 (`XDPMF_TRUST_MODEL` env-var read-once-at-startup idiom — `XDPMF_LOG_FORMAT` follows identical pattern); §5.29 (exporter stderr-line shapes — `exporter.listening` startup line, per-scrape WARN per-iface, exit-6 ERROR); §5.30 HK-4 (bypass audit-log structural fields uid/euid/sudo_user/reason — under JSON these become `fields:{}` of the `bypass.activated` event), HK-16 (exporter startup WARN — `exporter.warn.bpffs_root_missing`), HK-17 (exit-6 ERROR — `exporter.error.all_ifaces_eacces`); §5.31 D-3.4b-10 (roll-your-own JSON writer + zero-deps discipline — extends to logger.cpp), D-3.4b-14 (line-oriented format precedent), `src/lib/sidecar.cpp:38-158` (`json_escape` + `format_timestamp_utc` helpers — duplicated in logger.cpp per D-3.5-2 below, NOT extracted to shared module).

**Scope contract (§5.32 short form)**:
- NEW (source files): `src/common/logger.hpp` + `src/common/logger.cpp` (~280-320 LOC total; cross-binary shared per Q1=M3 + Q6=B1 dup-TU compile).
- NEW (env var): `XDPMF_LOG_FORMAT={text,json}` default `text`. Read ONCE at first `logger::emit()` call (lazy init under a `std::once_flag`); cached in module-static `Format g_format`.
- NEW (event-name catalog): 33 unique event names (40 emission sites; 31 unique events for loader-side + 2 events for events shared across multiple sites). Catalogued as `constexpr std::array<std::string_view, kEventCount> kEventNames` in `logger.hpp`; T_LOG_EVENT_CATALOG_STABILITY locks the set.
- EDITED (8 stderr-emission files): convert each `fprintf(stderr, "<prose>", args)` → `logger::emit(Level::<L>, "<event>", "<prose>", {Field{...},...})`. 40 sites converted; 1 site EXEMPT (`src/cli/bypass.cpp:96` interactive `BYPASS will detach... [y/N]:` prompt — UI primitive, not a log event; stays as raw fprintf — see D-3.5-7).
- EDITED (CMakeLists.txt): add `src/common/logger.cpp` to BOTH `xdpmf_internal` lib AND `xdpmf-exporter` binary target (Q6=B1); VERSION bump 0.7.0 → 0.8.0 (MINOR — new operator-facing env var + structured-logging surface).
- EDITED (CHANGELOG.md): new `[0.8.0]` Keep-a-Changelog entry.
- NEW (6 ctests): T_LOG_TEXT_BYTE_EQUIVALENT (load-bearing canary for PI-3.5-1), T_LOG_JSON_LOADER_EVENTS, T_LOG_JSON_EXPORTER_EVENTS, T_LOG_JSON_BYPASS_AUDIT, T_LOG_JSON_ENVELOPE_INVARIANTS, T_LOG_EVENT_CATALOG_STABILITY.
- UNCHANGED-BUT-AFFECTED: `loader.hpp` (7th consecutive ZERO-diff cycle — PI-7-3.5-hpp), `config.hpp` (2nd consecutive ZERO-diff), all 52 pre-§5.32 ctest bodies (PI-3.5-1 byte-equivalence MUST in text mode — ANY ctest grep'ing stderr text passes WITHOUT modification).

#### §5.32 Human-gate decisions (confirmed; brief defaults stand)

- **HG-3.5-1 — text-mode byte-equivalence = MUST.** Confirmed (no architect override). PI-3.5-1 contract: every text-mode emission is byte-identical to the pre-§5.32 line (same prose, same level-keyword embedding if any, same newline). Logger in text mode writes `<msg>\n` and nothing else — no `[level]` prefix, no decoration, no reordering. 52-ctest baseline (specifically the 12 ctests that grep stderr text — catalogued in §6.5 invariant block below) IS the validation surface. T_LOG_TEXT_BYTE_EQUIVALENT is the focused canary that runs a known stderr-producing sequence under `XDPMF_LOG_FORMAT=text` (default) AND under empty/unset env-var AND under explicit `XDPMF_LOG_FORMAT=text`, captures stderr each way, byte-compares all three against a captured reference. Any drift = `[REGRESSION]`.

- **HG-3.5-2 — JSON envelope = flat NDJSON with required + conditional fields.** Confirmed. Shape per emission:
  ```json
  {"ts":"<iso8601>","level":"<info|warn|error>","event":"<dotted.name>","iface":<"<iface>"|null>,"msg":"<original-prose>","fields":{<k>:<v>,...}}
  ```
  **Required (always present, never null/absent)**: `ts`, `level`, `event`, `msg`, `fields`. **`iface`**: ALWAYS present; type is string-or-null (null for events not iface-scoped — e.g. `cli.usage_error`, `exporter.listening`). **`fields`**: ALWAYS object (possibly empty `{}`, never absent, never null, never scalar). **Schema_version**: NO explicit field in cycle 1 (implicit schema_version=1; future breaking shipped with explicit `schema_version` field).

- **HG-3.5-3 — bypass.activated event with HK-4 structural fields.** Confirmed. `src/cli/bypass.cpp:174` converts to `logger::emit(Level::Info, "bypass.activated", "<full original audit-line prose>", {Field{"uid", uid_int}, Field{"euid", euid_int}, Field{"sudo_user", sudo_user_or_none}, Field{"reason", escaped_reason}})`. In text mode, byte-equivalent to MVP-3.4.5 HK-4 line (PI-3.5-1). In JSON mode, structural fields appear in `fields:{}` for log-shipping query (operators query `jq '.event=="bypass.activated" and .fields.sudo_user=="alice"'`). NOTE: the `iface` is ALSO emitted as the top-level `iface` field (operator's `--iface` arg) — convenient for cross-event correlation by iface — AND duplicated in the prose `msg`. Slight redundancy is acceptable per HG-3.5-2's flat-envelope convenience rationale (`jq 'select(.iface=="veth_v0")'` works for ANY iface-scoped event without reaching into prose).

- **HG-3.5-4 — architect catalogs all event names.** Confirmed. §5.32 Decisions sub-section "Event-name catalog (full)" below lists all 33 unique events with file:line cross-reference + Level + iface-scoped flag + fields keys. The catalog mirrors `kEventNames` in `logger.hpp`; T_LOG_EVENT_CATALOG_STABILITY asserts the set matches.

#### §5.32 Q-decisions (mechanism)

##### Q1: Logger module location → **M3 (`src/common/logger.{cpp,hpp}`)**

Confirmed per brief recommendation. `src/common/` is the established home for cross-binary shared code (mirrors `mac_filter.h` precedent). Compiled into BOTH `xdpmf_internal` static lib (linked by loader) AND `xdpmf-exporter` binary target (Q6=B1 dup-TU compile — one TU compiled twice, negligible cost vs. introducing a new static lib target). NOT in `src/lib/` (which is loader-internal; exporter would have to take a dependency on `xdpmf_internal` it doesn't currently have). NOT in `src/cli/` (CLI-specific). M2 (inline in each cli/main.cpp + exporter/main.cpp) rejected — duplicate logic across binaries violates DRY for a non-trivial module.

##### Q2: Timestamp format → **T1 (ISO-8601 UTC second-precision)**

Confirmed. `"2026-05-25T17:30:00Z"` (single trailing `Z`; no fractional seconds; no timezone offset). Matches `src/lib/sidecar.cpp::format_timestamp_utc` precedent (§5.31 D-3.4b-3 / D-3.4b-20). Operator-friendly (`grep '2026-05-25T17:'` for hourly windows). Second precision is sufficient for operator-action event rates (attach/apply/bypass/scrape — at most one-per-second; never packet-rate). Microsecond precision (T2) is over-engineering. Epoch-seconds (T3) is operator-hostile (must convert for human reading). Helper `format_timestamp_utc()` is DUPLICATED in logger.cpp anon namespace per D-3.5-2 (NOT promoted to shared `src/common/json.{cpp,hpp}` — see D-3.5-2 rationale).

##### Q3: Event-name convention → **E1 (dot-delimited `<subsystem>.<action>[.<outcome>][.<reason>]`)**

Confirmed. Examples: `attach.success`, `attach.fail.tag_mismatch`, `apply.complete`, `bypass.activated`, `exporter.scrape.warn.stats_open_failed`, `loader.warn.rules_skeleton_not_wired`. Hierarchical (operators write `jq 'select(.event | startswith("bypass."))'`); matches ECS / OpenTelemetry conventions. Lowercase snake_case within each segment (`stats_open_failed`, NOT `statsOpenFailed`). Catalogued in `kEventNames` constexpr table per HG-3.5-4. E2 (snake_case flat) rejected — loses hierarchical filtering. E3 (camelCase) rejected — inconsistent with project's snake_case convention.

##### Q4: Env-var read timing → **R1 (read once at first emit; cached for process lifetime)**

Confirmed. `XDPMF_LOG_FORMAT` is read on the FIRST call to `logger::emit()` (lazy init under `std::once_flag`); the parsed `Format` enum value is cached in module-static `Format g_format`; every subsequent emit uses the cached value. **Process restart required to switch format.** Matches `XDPMF_TRUST_MODEL` / `XDPMF_BPFFS_ROOT` precedent — both read-once. R2 (per-emit getenv) rejected — per-line syscall cost is negligible BUT live-toggleable logging is over-engineering for operator workflows (if they want to switch they restart the binary; cheap). R3 (SIGHUP re-read) rejected — adds signal handling for a marginal use case.

Edge cases:
- Env var unset OR empty string OR exact literal `"text"` → `Format::Text`.
- Exact literal `"json"` → `Format::Json`.
- Any other value (e.g. `"JSON"`, `"yaml"`, `"on"`) → emit a ONE-SHOT warning to stderr on first emit (`xdpmacfilter: WARN: unknown XDPMF_LOG_FORMAT value '<val>', defaulting to 'text'`) THEN default to `Format::Text`. The warning itself is a logger event (`logger.warn.unknown_log_format`) — chicken-and-egg avoided because text-mode emits raw prose so the WARN is human-readable regardless. Catalogued.

##### Q5: `fields:{}` value types → **F1 (flat scalars only)**

Confirmed. Allowed value types in `fields`:
- string (JSON-escaped per logger's internal `json_escape` helper).
- 64-bit signed integer.
- bool (`true` / `false`).
- null.

NO nested objects. NO arrays. Matches §5.31 sidecar one-rule-per-line shape. Minimal JSON writer complexity (no recursive nesting). Operators reconstruct nested structures from multiple correlated events if needed (e.g. for per-iface apply summary: one `apply.start` event + one `apply.complete` event with summary fields). F2 (nested objects) rejected — adds writer recursion + parse complexity. F3 (arrays) rejected — same.

##### Q6: Build inclusion → **B1 (dup-TU compile into both targets)**

Confirmed. `src/common/logger.cpp` added to BOTH `xdpmf_internal` (existing static lib linked by loader) AND `xdpmf-exporter` (existing executable target). One TU compiled twice. NO new CMake target. NO new static library. B2 (extract to new `xdpmf_common` static lib) rejected — adds a target for a single 280-LOC TU, over-engineering for cycle 1; can refactor in a future cycle if a 2nd shared TU surfaces (e.g. if D-3.5-2 reverses and `src/common/json.cpp` joins).

#### §5.32 FileList (brownfield DIFF)

##### NEW (created this slice)

| Path | Role (one line) | Language | LOC est |
|---|---|---|---|
| `src/common/logger.hpp` | Public API: `enum Level`, `enum Format`, `struct Field`, `void emit(...)`, `kEventNames` constexpr catalog | C++23 (header) | 80 |
| `src/common/logger.cpp` | Impl: format selector via env (lazy-init under `once_flag`), text-mode raw write, JSON envelope renderer, duplicated `json_escape` + `format_timestamp_utc` helpers (D-3.5-2) | C++23 | 220 |
| `tests/T_LOG_TEXT_BYTE_EQUIVALENT.sh` | §6.53 LOAD-BEARING canary for PI-3.5-1: known stderr sequence under text mode (default, unset env, explicit "text") all byte-identical to captured reference | bash | 110 |
| `tests/T_LOG_JSON_LOADER_EVENTS.sh` | §6.54: attach + apply + detach under `XDPMF_LOG_FORMAT=json`; jq-validate each stderr line; assert event-name + level + iface + fields per catalog | bash | 130 |
| `tests/T_LOG_JSON_EXPORTER_EVENTS.sh` | §6.55: exporter startup + listening + HK-16 WARN (missing bpffs root) + HK-17 ERROR (all-iface EACCES); jq-validate; assert event names | bash | 130 |
| `tests/T_LOG_JSON_BYPASS_AUDIT.sh` | §6.56: bypass under `XDPMF_LOG_FORMAT=json`; assert `bypass.activated` event with HK-4 structural fields in `fields:{}` (uid/euid/sudo_user/reason); negation = text mode preserves audit line byte-equivalent | bash | 100 |
| `tests/T_LOG_JSON_ENVELOPE_INVARIANTS.sh` | §6.57: across ALL events emitted in a sweep run, assert envelope invariants (required fields always present; iface null-or-string; fields always object; level ∈ {info,warn,error}) | bash | 90 |
| `tests/T_LOG_EVENT_CATALOG_STABILITY.sh` | §6.58: assert `kEventNames` catalog has exactly the expected 33 entries (locked set); micro-test prevents silent event rename across cycles | bash | 60 |

Total NEW source LOC est: ~300 (logger.hpp + logger.cpp). Total NEW test LOC est: ~620.

##### EDITED (existing files touched this slice)

| Path | What changes |
|---|---|
| `src/cli/main.cpp` | 6 stderr sites (lines 100, 101, 136, 140, 142, 146) → `logger::emit(...)`. Line 101 `fputs(usage_text, stderr)` is special — usage-text is multi-line; converts to ONE `logger::emit(Level::Info, "cli.usage_text", usage_text, {})` event (NOT 100s of per-line events). Text mode preserves the multi-line `\n`-embedded usage text byte-equivalent (PI-3.5-1). JSON mode produces ONE line with the embedded `\n` JSON-escaped inside `msg`. See D-3.5-5 below for multi-line msg discipline. |
| `src/cli/bypass.cpp` | 5 stderr sites: lines 129, 139, 149, 174 → `logger::emit(...)`. **EXEMPT**: line 96 (interactive `BYPASS will detach... [y/N]:` prompt) stays as raw `fprintf(stderr, ...)` per D-3.5-7 (UI primitive, not log event). |
| `src/lib/loader.cpp` | 4 stderr sites (lines 1031, 1545, 1606, 1784) → `logger::emit(...)`. Existing comments referencing the literal stderr-prefix (e.g. "audit log per §5.26") preserved (logger preserves the literal prose byte-equivalent). |
| `src/lib/sidecar.cpp` | 6 stderr sites (lines 259, 266, 273, 289, 305, 312) → `logger::emit(...)`. All 6 are `sidecar.warn.*` events (write failures); fields include `errno_str` (text via `std::strerror`) and `path` where relevant. Existing §5.31 D-3.4b-17 non-fatal contract preserved: emit + return; do NOT throw. |
| `src/exporter/main.cpp` | 7 stderr sites (lines 91, 100, 110, 143, 154, 176, 187) → `logger::emit(...)`. Site 91 + 100 collapse into shared event `exporter.usage_error` (5 sites total share this event; arg `flag` carries the offending `--flag` name in `fields`). |
| `src/exporter/http.cpp` | 8 stderr sites (lines 288, 295, 310, 317, 323, 336, 353, 362) → `logger::emit(...)`. Line 323 (`listening on`) is the startup INFO event — load-bearing operator signal. |
| `src/exporter/stats_reader.cpp` | 3 stderr sites (lines 119, 157, 194) → `logger::emit(...)`. Line 119 is HK-16 WARN — `exporter.warn.bpffs_root_missing`. |
| `src/exporter/rule_counters_reader.cpp` | 2 stderr sites (lines 116, 137) → `logger::emit(...)`. Line 116 shares event `exporter.warn.cpu_count_invalid` with stats_reader:157 (same prose, same context). |
| `CMakeLists.txt` | (a) VERSION bump `0.7.0 → 0.8.0` (MINOR — new operator-facing env var + structured-logging surface; HG-3.5 family). (b) Add `src/common/logger.cpp` to `xdpmf_internal` target source list. (c) Add `src/common/logger.cpp` to `xdpmf-exporter` target source list (Q6=B1 dup-TU). (d) NO new compile flags, NO new external deps. |
| `CHANGELOG.md` | NEW `## [0.8.0] - 2026-05-NN` section (Keep-a-Changelog). **Added** — structured-logging surface via `XDPMF_LOG_FORMAT={text,json}` env var; `src/common/logger.{cpp,hpp}` module; 33-event catalog; 6 new ctests. **Changed** — 40 stderr emission sites converted to `logger::emit` (text-mode byte-equivalent per PI-3.5-1; JSON-mode wraps per HG-3.5-2 envelope). Build-pace table gains an MVP-3.5 row. |
| `tests/CMakeLists.txt` | 6 new `add_test(...)` entries (§6.53..§6.58). T_LOG_TEXT_BYTE_EQUIVALENT + T_LOG_JSON_LOADER_EVENTS + T_LOG_JSON_BYPASS_AUDIT require `xdp_fixture` RESOURCE_LOCK (touch veth). T_LOG_JSON_EXPORTER_EVENTS requires `xdp_fixture` + `exporter_port_9417`. T_LOG_JSON_ENVELOPE_INVARIANTS shares `xdp_fixture`. T_LOG_EVENT_CATALOG_STABILITY needs neither lock (binary-grep / nm-style check). ZERO modification of 52 existing `add_test` entries. |

##### UNCHANGED-BUT-AFFECTED (zero git-diff fence; behaviour must hold)

| Path | Why it matters |
|---|---|
| `src/lib/loader.hpp` | **PI-7-3.5-hpp — 7TH consecutive ZERO-diff cycle** (MVP-3.1 +1; MVP-3.2/3.3/3.4/3.4.5/3.4b/3.5 = 0). `git diff main -- src/lib/loader.hpp` MUST show ZERO output. Logger module owns its own header (`src/common/logger.hpp`); NO public LoaderError addition; NO new public symbol in loader.hpp. Any diff = `[INVARIANT-VIOLATED]`. |
| `src/lib/config.hpp` | **PI-7-3.5-hpp — 2ND consecutive ZERO-diff cycle**. No schema change. `git diff main -- src/lib/config.hpp` MUST show ZERO output. |
| `src/common/mac_filter.h` | UNCHANGED. Logger constants live in `src/common/logger.hpp` (separate file). `mac_filter.h` byte-equivalent. PI-10 continues. |
| `src/bpf/mac_filter.bpf.c` | UNCHANGED. JSON logging is userspace-only; no kernel-side BPF code touch. `bpf_printk` (if used) stays text. PI-28-3.4b continues byte-equivalent for `mac_filter_prog` body. |
| `src/lib/cidr.{cpp,hpp}`, `src/lib/yaml_subset.{cpp,hpp}`, `src/lib/config.cpp`, `src/lib/raii.hpp` | UNCHANGED. None of these emit stderr in the current codebase (Phase A grep confirmed — see catalog above). |
| `src/cli/attach.{cpp,hpp}`, `src/cli/detach.{cpp,hpp}`, `src/cli/apply.{cpp,hpp}`, `src/cli/cli.{cpp,hpp}` | UNCHANGED. None of these emit stderr directly (Phase A grep confirmed). Errors propagate via exceptions caught in `src/cli/main.cpp`. `cli.cpp` `usage_text()` is a string GENERATOR; its stderr write is via main.cpp:101. |
| `src/exporter/prom_format.{cpp,hpp}`, `src/exporter/sidecar_reader.{cpp,hpp}` | UNCHANGED. Neither emits stderr (Phase A grep). |
| `systemd/xdpmacfilter@.service`, `systemd/xdpmf-exporter.service` | UNCHANGED. Default systemd capture of stderr → journald applies in BOTH modes; in JSON mode operators add `--output=json-pretty` to their `journalctl` or hook a JSON shipper. Optional future env-var injection (`Environment=XDPMF_LOG_FORMAT=json`) is documented in CHANGELOG but NOT shipped by default this slice (operators opt-in). |
| `ansible/xdpmacfilter-deploy.yml`, `ansible/templates/xdpfilter-config.yaml.j2` | UNCHANGED. No Ansible touch (operators add `XDPMF_LOG_FORMAT=json` to their environment template if desired; not baked in). |
| `docs/FLEET_DEPLOYMENT.md` | UNCHANGED this slice. Future docs pass (separate user-driven scope) MAY add a "structured-logging" section + per-event jq examples. |
| All 52 pre-§5.32 ctest BODIES | **UNCHANGED — load-bearing PI-3.5-1**. `git diff main -- tests/T_*.sh` shows ZERO modified files (only 6 NEW files). Any ctest body diff = `[INVARIANT-VIOLATED]`. The 12 ctests known to grep stderr text (catalogued in §6.5 PI-3.5-1 invariant block below) pass byte-equivalent without modification under default `XDPMF_LOG_FORMAT=text`. |
| `tests/lib/common.sh`, `tests/lib/read_stats.py`, `tests/lib/pins.sh.in`, `tests/lib/read_rule_counters.py` | UNCHANGED. Logger is userspace-only; no test helper change. |
| `tests/fixtures/*` | UNCHANGED. The 6 NEW ctests reuse existing fixtures (config_default.yaml, config_per_rule_counters.yaml, xdp_pass.bpf.o, mac_filter_alt.bpf.o) or construct inputs inline; NO new fixture file. |
| §5.4 / §5.19 / §5.22 / §5.24 / §5.26 / §5.27 / §5.29 / §5.30 / §5.31 trust+identity gates | UNCHANGED. Logger sits ABOVE the gates (gates raise exceptions OR call `logger::emit` directly); gate codepaths byte-equivalent. PI-1..PI-5 all pass. |

#### §5.32 DataStructures

##### `logger::Level` enum

In `src/common/logger.hpp`:
```
namespace xdpmf::logger {

enum class Level : std::uint8_t {
    Info  = 0,
    Warn  = 1,
    Error = 2,
};

}  // namespace xdpmf::logger
```

Renders to JSON `"level"` field as lowercase string `"info"` / `"warn"` / `"error"`. Renders to text mode as: NOTHING (text mode emits raw msg + `\n` — the level enum is JSON-only metadata). The historical embedded "WARN" / "ERROR" / "error:" tokens in some existing prose lines (e.g. `"xdpmf-exporter: WARN bpffs root..."`) STAY EMBEDDED IN PROSE per PI-3.5-1 (byte-equivalence); the JSON `"level"` field is the structural mirror, not a replacement.

##### `logger::Format` enum

```
namespace xdpmf::logger {

enum class Format : std::uint8_t {
    Text = 0,   // default; byte-equivalent to pre-§5.32 emissions
    Json = 1,   // NDJSON envelope per HG-3.5-2
};

}  // namespace xdpmf::logger
```

Cached in module-static `Format g_format` in logger.cpp after first emit (lazy init under `std::once_flag`). NOT exposed via getter (logger is fire-and-forget; callers don't need to query the format).

##### `logger::FieldValue` variant

```
namespace xdpmf::logger {

using FieldValue = std::variant<
    std::string_view,   // string scalar (JSON-escaped at render time)
    std::int64_t,       // integer scalar (signed 64-bit; covers u32/u64-as-i64 sufficient)
    bool,
    std::nullptr_t      // explicit null
>;

struct Field {
    std::string_view key;       // must be a stable literal or owned by caller for the call duration
    FieldValue       value;
};

}  // namespace xdpmf::logger
```

Q5 F1 flat-scalars-only contract. Caller owns the lifetime of any `string_view` (key OR value) — logger reads-then-writes synchronously within `emit()`; no async / no copy / no allocation beyond `std::string` for JSON rendering. Integer choice = `int64_t` (signed) covers all natural emitter cases (uid, euid, prog_id, port, errno, count). Unsigned values up to `INT64_MAX` (~9.2 × 10^18) round-trip safely; values above (extremely rare for our use case) would wrap — flagged in D-3.5-3.

##### `logger::kEventNames` constexpr catalog

In `src/common/logger.hpp`:
```
namespace xdpmf::logger {

inline constexpr std::array<std::string_view, 33> kEventNames = {
    /* loader (xdpmacfilter) — 17 events */
    "cli.usage_error",                       /* src/cli/main.cpp:100 */
    "cli.usage_text",                        /* src/cli/main.cpp:101 (multi-line usage dump) */
    "cli.error",                             /* src/cli/main.cpp:136, 142, 146 (generic LoaderError + system_error + std::exception) */
    "config.error",                          /* src/cli/main.cpp:140 (ConfigError variant) */
    "loader.trust_model",                    /* src/lib/loader.cpp:1031 (audit log — PI-23) */
    "loader.warn.rules_skeleton_not_wired",  /* src/lib/loader.cpp:1545 (HG-3.4-1 WARN) */
    "loader.attach.fleet_replace",           /* src/lib/loader.cpp:1606 (trust_model=fleet replace) */
    "loader.attach.replace",                 /* src/lib/loader.cpp:1784 (existing program replace) */
    "logger.warn.unknown_log_format",        /* src/common/logger.cpp self-emit (Q4 edge case) */
    "bypass.usage_error",                    /* src/cli/bypass.cpp:129 (--iface missing) */
    "bypass.refused.requires_unsafe",        /* src/cli/bypass.cpp:139 (non-tty without --unsafe) */
    "bypass.cancelled",                      /* src/cli/bypass.cpp:149 (operator typed 'n') */
    "bypass.activated",                      /* src/cli/bypass.cpp:174 — HK-4 audit log */
    "sidecar.warn.root_symlink",             /* src/lib/sidecar.cpp:259 */
    "sidecar.warn.root_not_dir",             /* src/lib/sidecar.cpp:266 */
    "sidecar.warn.lstat_failed",             /* src/lib/sidecar.cpp:273 */
    "sidecar.warn.mkdir_failed",             /* src/lib/sidecar.cpp:289 */
    "sidecar.warn.write_failed",             /* src/lib/sidecar.cpp:305 */
    "sidecar.warn.write_exception",          /* src/lib/sidecar.cpp:312 */

    /* exporter (xdpmf-exporter) — 14 events */
    "exporter.usage_error",                  /* src/exporter/main.cpp:91, 100, 110, 143, 154 (5 sites share) */
    "exporter.fatal",                        /* src/exporter/main.cpp:176 */
    "exporter.error.all_ifaces_eacces",      /* src/exporter/main.cpp:187 — HK-17 */
    "exporter.bind.invalid_addr",            /* src/exporter/http.cpp:288 */
    "exporter.bind.socket_failed",           /* src/exporter/http.cpp:295 */
    "exporter.bind.failed",                  /* src/exporter/http.cpp:310 */
    "exporter.bind.listen_failed",           /* src/exporter/http.cpp:317 */
    "exporter.listening",                    /* src/exporter/http.cpp:323 — startup signal */
    "exporter.accept.poll_failed",           /* src/exporter/http.cpp:336 */
    "exporter.accept.failed",                /* src/exporter/http.cpp:353 */
    "exporter.shutdown",                     /* src/exporter/http.cpp:362 */
    "exporter.warn.bpffs_root_missing",      /* src/exporter/stats_reader.cpp:119 — HK-16 */
    "exporter.warn.cpu_count_invalid",       /* src/exporter/stats_reader.cpp:157 + rule_counters_reader.cpp:116 (2 sites share) */
    "exporter.scrape.warn.stats_open_failed",         /* src/exporter/stats_reader.cpp:194 */
    "exporter.scrape.warn.rule_counters_open_failed", /* src/exporter/rule_counters_reader.cpp:137 */
};

inline constexpr std::size_t kEventCount = kEventNames.size();   // = 33

}  // namespace xdpmf::logger
```

**Coverage**: 41 emission sites − 1 EXEMPT (`src/cli/bypass.cpp:96` interactive prompt, D-3.5-7) = 40 converted sites. Event-name count = 33 unique (5 exporter usage-error sites share 1 event; 3 cli error sites share 1 event; 2 cpu_count_invalid sites share 1 event = 7 site-collapses). 40 − 7 = 33 unique events. ✓

T_LOG_EVENT_CATALOG_STABILITY asserts `kEventCount == 33` AND each expected literal is present (set equality). Adding a new event in a future cycle = one-line addition to `kEventNames` + bump the array size + update test expectation.

##### Env-var constant

In `src/common/logger.cpp` (anon namespace):
```
constexpr std::string_view kLogFormatEnv{"XDPMF_LOG_FORMAT"};
constexpr std::string_view kLogFormatTextValue{"text"};
constexpr std::string_view kLogFormatJsonValue{"json"};
```

Mirrors §5.26's `kTrustModelEnv` constant at loader.cpp:1000.

#### §5.32 Interfaces

##### `logger::emit` signature (public)

In `src/common/logger.hpp`:
```
namespace xdpmf::logger {

/* Emit one log event to stderr. Format selected by XDPMF_LOG_FORMAT env var
 * (read once at first call; cached for process lifetime per Q4 R1):
 *   text mode (default) — writes <msg> + '\n' byte-equivalent to pre-§5.32
 *                         emission site (PI-3.5-1 contract);
 *   json mode           — writes one NDJSON line per HG-3.5-2 envelope.
 *
 * THREAD SAFETY: emit() is async-signal-unsafe (uses std::fprintf + std::string
 * for JSON rendering). Callers from signal handlers MUST use raw write(2) on
 * stderr instead (no logger sites in current codebase emit from signal handlers
 * — Phase A grep verified: all sites are sync caller-thread).
 *
 * MULTI-LINE msg: msg MAY contain embedded '\n'. In text mode, written
 * byte-equivalent (the embedded newlines surface as separate lines, mirroring
 * pre-§5.32 behaviour — e.g. cli.usage_text which dumps the multi-line
 * usage block). In JSON mode, embedded '\n' is JSON-escaped to "\\n"
 * inside the "msg" string field (one JSON line; reader's view of embedded
 * newlines is via jq -r '.msg').
 *
 * iface: pass std::nullopt for events not scoped to an interface (cli usage,
 * exporter startup); pass the iface name otherwise (attach, apply, bypass,
 * per-iface scrape warnings). In JSON mode, std::nullopt renders as
 * "iface": null; a non-nullopt iface renders as "iface": "<value>".
 *
 * Logger NEVER throws. Failures to write to stderr are silently ignored
 * (consistent with fprintf(stderr,...) semantics — there's no recovery path
 * for a stderr write failure).
 */
void emit(Level                              level,
          std::string_view                   event,
          std::optional<std::string_view>    iface,
          std::string_view                   msg,
          std::span<const Field>             fields = {}) noexcept;

/* Convenience overload for events without iface (renders iface:null in JSON;
 * omits iface concept in text). Equivalent to emit(level, event, std::nullopt,
 * msg, fields). */
void emit(Level                  level,
          std::string_view       event,
          std::string_view       msg,
          std::span<const Field> fields = {}) noexcept;

}  // namespace xdpmf::logger
```

**Caller idiom** (per emission site):
```
// Pre-§5.32 (current):
std::fprintf(stderr, "xdpmacfilter: trust_model=%s\n",
             std::string{to_string(m)}.c_str());

// Post-§5.32:
auto trust_str = std::string{to_string(m)};
logger::emit(logger::Level::Info,
             "loader.trust_model",
             /* no iface — trust_model is process-scoped */
             "xdpmacfilter: trust_model=" + trust_str,
             {{ logger::Field{"trust_model", std::string_view{trust_str}} }});
```

Note that `msg` carries the FULL prose including the `xdpmacfilter:` prefix — preserved byte-equivalent for text mode (PI-3.5-1). The `fields` carry the same value structurally for JSON consumers.

##### `XDPMF_LOG_FORMAT` env var contract (operator-facing)

| Value | Effect |
|---|---|
| unset OR empty | `Format::Text` (default) |
| `text` (exact, case-sensitive) | `Format::Text` |
| `json` (exact, case-sensitive) | `Format::Json` |
| any other value (e.g. `JSON`, `yaml`, `on`, `1`) | one-shot WARN emitted (event `logger.warn.unknown_log_format`); defaults to `Format::Text` |

Read ONCE on the first `logger::emit()` call (lazy init under `std::once_flag`; thread-safe). Cached for process lifetime. Documented in `xdpmacfilter --help` Environment-variables block + `xdpmf-exporter --help` Environment-variables block (HK-6 idiom; extends to `XDPMF_LOG_FORMAT={text|json}   Default: text. json emits NDJSON envelope per event.`).

##### JSON envelope render contract (Format::Json)

Per event, one line (terminated by `\n`):
```
{"ts":"<iso8601>","level":"<info|warn|error>","event":"<dotted.name>","iface":<"string"|null>,"msg":"<json-escaped>","fields":{<k>:<v>,...}}
```

Field order: **fixed** for grep-friendliness AND test-assertion stability:
1. `ts` — `format_timestamp_utc(time(nullptr))` per D-3.5-2 (duplicated helper).
2. `level` — `"info" | "warn" | "error"` per Level enum.
3. `event` — literal from `kEventNames` (caller passes the string_view; logger does NOT validate it's in the catalog at runtime — that's compile-time-ish via T_LOG_EVENT_CATALOG_STABILITY).
4. `iface` — `"string"` if `optional` is set; `null` otherwise.
5. `msg` — JSON-escaped per `json_escape` helper (duplicated from sidecar.cpp:38-XX per D-3.5-2).
6. `fields` — object with keys in caller-supplied order (preserved); EMPTY `{}` if `fields.empty()`.

Fixed-order rationale: T_LOG_JSON_ENVELOPE_INVARIANTS asserts via `jq -e '.ts and .level and .event and (.iface != null or .iface == null) and .msg and .fields'` — order is jq-irrelevant for value assertion, BUT operators writing grep-style tooling (e.g. `grep '"event":"bypass.activated"'`) benefit from stable field position. Fixed order = future-cycle stability.

##### Text envelope render contract (Format::Text)

Per event, one OR more lines:
- `<msg>\n` written byte-for-byte to stderr.
- NO level prefix. NO event prefix. NO field decoration. NO `ts`. NOTHING wrapping.
- Embedded `\n` in msg → surfaces as multiple lines (mirrors pre-§5.32 multi-line `usage_text` dump from cli/main.cpp:101).

This is the load-bearing PI-3.5-1 contract. ANY decoration = breaking change requiring its own slice.

##### Loader public API (`src/lib/loader.hpp`) — ZERO diff (PI-7-3.5-hpp, 7th consecutive cycle)

`AttachConfig` / `DetachConfig` / `attach()` / `detach()` / `LoaderError` enum: ALL UNCHANGED. Logger module owns its own header (`src/common/logger.hpp`); NO public LoaderError addition; NO new public symbol in loader.hpp. The logger module is included from `loader.cpp` + `sidecar.cpp` + `cli/main.cpp` + `cli/bypass.cpp` + `exporter/main.cpp` + `exporter/http.cpp` + `exporter/stats_reader.cpp` + `exporter/rule_counters_reader.cpp` directly (8 `#include "common/logger.hpp"` lines added).

##### Config API (`src/lib/config.hpp`) — ZERO diff (2nd consecutive cycle)

`Config::Rule` / `Config` / parsers / validators: ALL UNCHANGED. No schema change; logger is orthogonal to config.

#### §5.32 Decisions (with rationale)

##### D-3.5-1 — Logger module in `src/common/`, dup-TU compile (Q1=M3 + Q6=B1) — because

`src/common/` is the established home for cross-binary shared code (mirror `mac_filter.h` precedent). Adding `logger.cpp` to BOTH `xdpmf_internal` AND `xdpmf-exporter` CMake target source lists costs one extra compile of a ~220-LOC TU — negligible vs. introducing a new static library target (B2) that adds an empty wrapper for one TU. Future cycle CAN refactor to a `xdpmf_common` static lib if a 2nd shared TU surfaces (e.g. if D-3.5-2 reverses and `src/common/json.cpp` joins as a 2nd shared TU); cycle 1 stays minimal.

##### D-3.5-2 — `json_escape` + `format_timestamp_utc` DUPLICATED in logger.cpp, NOT extracted to shared module — because

The existing helpers at `src/lib/sidecar.cpp:38-158` (~50 LOC combined) work and are stable. Extracting to `src/common/json.{cpp,hpp}` would:
- Add 2 new files + 1 CMake target dependency wiring (sidecar.cpp would need to include common/json.hpp; logger.cpp same).
- Touch sidecar.cpp (PI-7-3.4b-cpp scope-fence implications — sidecar.cpp is not in the regional-diff fence per §5.31, but altering its file-static helpers is a non-zero diff).
- Add library-extraction scope creep cycle 1 (architect-spec brownfield discipline).

Duplicating ~50 LOC in logger.cpp anon namespace keeps the slice contained. Both copies are simple (escape map for 5 control chars + strftime call). Future cycle MAY extract if a 3rd JSON emitter surfaces (e.g. exporter-side structured metrics summary export); the refactor is local + obvious. **The cost of duplication is intentional and small; the cost of premature abstraction would be a touchpoint on sidecar.cpp that destabilizes its §5.31 contracts.** Reviewer's regional-diff check on `src/lib/sidecar.cpp` post-§5.32 should show diffs CONFINED to the 6 emission-site conversions (line 259-312 area) — the helpers at lines 38-158 stay byte-equivalent. (Logger's COPY of those helpers in logger.cpp is byte-equivalent to sidecar.cpp's at write time.)

##### D-3.5-3 — `FieldValue` integer type = `int64_t` (signed), not `uint64_t` — because

Practical considerations:
- All natural emitter cases (uid, euid, prog_id, port, errno, count, prog_id) fit in `INT64_MAX` ~9.2 × 10^18 with millennia of headroom.
- `int64_t` round-trips cleanly through JSON (all major parsers — jq, Python `json` — represent integers as `int64_t` natively).
- `uint64_t` values > `INT64_MAX` are vanishingly rare for our domain (would require a counter > 9 quintillion). If a future cycle needs `uint64_t` (e.g. unsigned PERCPU sum at extreme scale), it can ADD a `uint64_t` variant alternative — cycle 1 doesn't gate this.
- Mixed-sign comparisons in callers are simpler with a single signed type.

The caller's idiom for unsigned values: `static_cast<std::int64_t>(uid_unsigned)`. For values up to `INT64_MAX`, this is lossless. Documented in logger.hpp comment.

##### D-3.5-4 — Logger emit is `noexcept` + silent-on-failure — because

`fprintf(stderr, ...)` itself is documented as not-throwing (returns negative on error; sets errno). Logger's `emit()` mirrors this semantic: writes via internal `std::fprintf(stderr, "%s\n", rendered.c_str())` (text) OR `std::fprintf(stderr, "%s\n", json_envelope.c_str())` (JSON); on write failure, silently returns. There is NO recovery path for a stderr write failure (we cannot log the log failure — that would loop). The `noexcept` annotation guarantees callers can use `emit()` from ANY context (including catch blocks where the wrapping function is `noexcept`) without unwinding concerns.

JSON envelope construction uses `std::string` (which CAN throw `bad_alloc`); per noexcept contract, ANY exception during envelope construction is CAUGHT inside emit() (`try { build_json(...); } catch (...) {}`) and silently dropped (the alternative — propagating bad_alloc up a logging call — is worse than a silent log loss). Mirrors `src/lib/sidecar.cpp::write_rule_index`'s D-3.4b-17 non-fatal-on-failure contract.

##### D-3.5-5 — Multi-line msg discipline (cli.usage_text edge case) — because

`src/cli/main.cpp:101` does `fputs(xdpmf::usage_text().c_str(), stderr)` where `usage_text()` returns a ~30-line multi-line string. Pre-§5.32, this is N stderr-text-lines for one CliError. Post-§5.32:
- **Text mode (PI-3.5-1)**: byte-equivalent — logger writes the full multi-line string + `\n`, surfaces as N stderr lines. (No double-newline; `usage_text()` already ends with `\n` per current convention; logger MAY emit `<msg>` without appending extra `\n` IF msg already ends with `\n` — impl picks. Document the convention: text mode appends `\n` ONLY if msg does NOT already end with `\n`. PI-3.5-1 byte-equivalence is the contract; the trailing-newline policy is whatever preserves the existing 52-ctest stderr captures byte-for-byte.)
- **JSON mode**: ONE JSON line with embedded `\\n` (escaped newlines) inside the `"msg"` field. `jq -r '.msg'` reproduces the multi-line text. Operators querying `jq 'select(.event=="cli.usage_text")'` get one event per CliError, matching the semantic "one error → one event log".

Alternative considered: split usage_text into per-line events (~30 events per CliError). REJECTED — explodes event count for a UI dump that's not log-shipping-pipeline-meaningful. One event with multi-line msg is the right shape.

##### D-3.5-6 — Trailing-newline policy: append `\n` ONLY IF msg does NOT already end with `\n` — because

Pre-§5.32 emissions are inconsistent: `fprintf(stderr, "...\n")` (most sites end the format with `\n`); `fputs(usage_text.c_str(), stderr)` where `usage_text()` ends with `\n` already. To preserve PI-3.5-1 byte-equivalence, logger's text-mode write must NOT append a redundant `\n` for sites whose msg already ends with one. Concrete impl: logger checks `msg.ends_with('\n')` and conditionally writes `<msg>` OR `<msg>\n`. **Caller convention**: emission-site rewriters SHOULD include the trailing `\n` in msg (matches the pre-§5.32 format-string convention) — logger's check is a safety net for the `usage_text` case where msg already includes terminal `\n`. JSON mode strips the trailing `\n` before embedding in `"msg"` (operators reading JSON don't want a stray trailing `\\n` in their parsed msg field) OR escapes it as `\\n` — impl picks; default = STRIP trailing-only `\n` for JSON envelope construction (embedded `\n` between content lines stays escaped).

##### D-3.5-7 — `src/cli/bypass.cpp:96` interactive prompt EXEMPT from logger conversion — because

The line `BYPASS will detach XDP filter on %s. Continue? [y/N]: ` is an INTERACTIVE prompt — no trailing newline, fflushed, expects user input on stdin within `~few seconds`. Converting it to `logger::emit(...)` would:
- In TEXT mode (preserves byte-equivalence): no functional change; works as before.
- In JSON mode: would render as `{"ts":"...","level":"info","event":"bypass.prompt","iface":"veth_v0","msg":"BYPASS will detach XDP filter on veth_v0. Continue? [y/N]: ","fields":{}}\n` — operator's terminal sees a JSON line ending in `}\n` BEFORE the `[y/N]: ` ends; the prompt-to-stdin UX is broken (no visible cursor at end of `[y/N]: `).

Decision: keep the prompt as a RAW `fprintf(stderr, ...)`. JSON-mode operators using `xdpmacfilter bypass` interactively see one non-JSON line during the prompt — acceptable wart for an interactive UI primitive. Non-interactive operators use `xdpmacfilter bypass --unsafe` (no prompt fires) — JSON stream stays pure. Document in §5.32 catalog: "40 of 41 emission sites converted; 1 exempt (interactive prompt at bypass.cpp:96)". `T_BYPASS_INTERACTIVE_PROMPT` text-mode behavior is byte-equivalent (the prompt is unchanged); JSON-mode coverage of bypass is via `bypass.activated` event (the audit line per HK-4 — fully converted).

##### D-3.5-8 — Lazy-init under `std::once_flag` for env-var read — because

The `XDPMF_LOG_FORMAT` env var is read on the FIRST call to `logger::emit()` (NOT at static-initialization time — that would risk SIOF / order-of-init issues). Lazy init under `std::once_flag` ensures:
- Thread-safe initialization (multiple threads calling `emit()` simultaneously serialize through the `call_once`).
- Cost: one branch + atomic flag check per emit AFTER the first (negligible).
- Env-var changes AFTER the first emit are NOT observed (matches R1 read-once contract).
- Test fixture can spawn the binary with `XDPMF_LOG_FORMAT=json` set in environment; the very first emit (typically `loader.trust_model` for xdpmacfilter at apply, OR `exporter.listening` for xdpmf-exporter at startup) captures the env-var value.

Alternative considered: static initialization. REJECTED — order-of-init is fragile across translation units; `getenv` at static-init time could race with anyone modifying the environment in a parent translation unit's static-init.

##### D-3.5-9 — JSON field order is FIXED (ts, level, event, iface, msg, fields) — because

Stable field order helps:
- Operators writing simple grep/awk tooling (`grep '"event":"bypass.activated"'` matches at consistent position).
- Diff-based regression tests on JSON-mode output (reduces noise; jq normalization optional).
- Future-cycle field additions (new field SHOULD go AFTER `fields` to preserve prefix-byte-equivalence — but schema_version is added BEFORE `ts` in a hypothetical future cycle as the first field, signaling the breaking change).

JSON parsers (jq, Python `json`) are order-insensitive; the FIXED order is purely operational discipline. Documented in logger.hpp comment.

##### D-3.5-10 — NO `bpf_printk` JSON-ification (kernel-side debug-prints) — because

`bpf_printk` writes to `/sys/kernel/debug/tracing/trace` (kernel ringbuffer). Operators tail this via `cat`; the format is dictated by kernel's printk infrastructure (`<6>xdpmf[NNNN]: ...`). Adding JSON wrapping on the kernel side would require BPF helper functions that don't exist; it's out of scope for a userspace-only logging slice. NEW FENCE in §7 OOS.

##### D-3.5-11 — Operator's existing-format `WARN` / `ERROR` / `error:` tokens stay EMBEDDED IN PROSE — because

The pre-§5.32 prose strings already embed level keywords inline (`"xdpmf-exporter: WARN bpffs root..."`, `"xdpmf-exporter: ERROR all..."`, `"error: <what>"`). PI-3.5-1 byte-equivalence requires preserving these embeddings byte-for-byte. The JSON envelope's `"level"` field is the STRUCTURAL mirror (for jq query); the embedded prose token is the HUMAN-READABLE artifact. NO logger pass strips or normalizes the embedded tokens — text mode emits raw prose; JSON mode emits raw prose inside `"msg"` PLUS the `"level"` field separately. Future-cycle text-format refactor (e.g. normalize all-WARN-emissions to `[WARN]` prefix) is a breaking change requiring its own slice; OOS for MVP-3.5.

#### §5.32 TestStrategy entries

##### §6.53 T_LOG_TEXT_BYTE_EQUIVALENT — load-bearing canary for PI-3.5-1

**Trigger**: run a deterministic stderr-producing sequence under THREE env conditions:
1. `XDPMF_LOG_FORMAT` UNSET (no env var present).
2. `XDPMF_LOG_FORMAT=""` (empty string).
3. `XDPMF_LOG_FORMAT="text"` (explicit literal).

Sequence: `xdpmacfilter attach --iface ${IFACE_A}` → `xdpmacfilter apply -f tests/fixtures/config_default.yaml --iface ${IFACE_A}` → `xdpmacfilter detach --iface ${IFACE_A}` → (optional negative) `xdpmacfilter attach --iface /nonexistent` (triggers a usage-error). Capture stderr from each invocation in each env condition.

**Observable outcome**:
- All 3 env conditions produce BYTE-IDENTICAL stderr (`cmp -s stderr_unset stderr_empty && cmp -s stderr_empty stderr_text` returns success).
- Stderr matches the captured-at-test-write-time reference (`cmp -s stderr_text tests/fixtures/log_text_reference.txt`). Reference is committed alongside the test (~50 lines of expected stderr; gen'd from MVP-3.4b shipped HEAD at test-write time).
- Reference comparison MUST be byte-equivalent except for timestamps (none in current loader stderr; the only timestamp in stderr is the sidecar's rule_index.json `applied_at` which is FILE content, not stderr) and process-specific ints (uid, euid, prog_id — these are normalized via `sed 's/uid=[0-9]\+/uid=N/g; s/euid=[0-9]\+/euid=N/g; s/prog id [0-9]\+/prog id N/g'` before comparison).

**Negation control**: run the same sequence under `XDPMF_LOG_FORMAT=json`. Stderr is DIFFERENT (each line is a JSON object). Assert: `cmp stderr_json stderr_text` returns NON-ZERO. This proves the test isn't a no-op (text mode genuinely is byte-equivalent to baseline; JSON mode is genuinely different).

**Assertion mechanism**: `cmp -s` for byte-equivalence between text-mode captures + against the committed reference; `cmp` (without `-s`) for the negation control with stderr to inspect on failure.

**SKIP conditions**: none new (uses existing veth fixture).

**Cleanup**: `cleanup_veth`.

**Maps to**: PI-3.5-1 (load-bearing text-mode byte-equivalence), HG-3.5-1, D-3.5-6 (trailing-newline policy).

**Load-bearing**: this test is the canary for PI-3.5-1. If it fails, EITHER the logger added decoration (a `[level]` prefix slipped in — code bug) OR an emission site's msg lost its `xdpmacfilter:` prefix (refactor regression). Failure mode is clear; impl peer-DMs architect to root-cause.

##### §6.54 T_LOG_JSON_LOADER_EVENTS — attach + apply + detach under JSON mode

**Trigger**: set `XDPMF_LOG_FORMAT=json`; run `xdpmacfilter attach --iface ${IFACE_A}` then `xdpmacfilter apply -f tests/fixtures/config_default.yaml --iface ${IFACE_A}` then `xdpmacfilter detach --iface ${IFACE_A}`. Capture stderr from each invocation.

**Observable outcome**:
- Each stderr line is a valid JSON object (`jq -e '.' < line.txt` returns success per line; `jq -s '.' < stderr.txt` parses as a valid JSON array of objects).
- The `loader.trust_model` event fires exactly once per invocation (attach + apply each emit it; detach does NOT — pre-§5.32 behavior preserved). Assert via `jq -s '[.[] | select(.event == "loader.trust_model")] | length == 2'` across attach + apply captures.
- Each emitted event's `level` value is in `{"info", "warn", "error"}`.
- For iface-scoped events (`loader.trust_model` is process-scoped per catalog — iface is null; `loader.attach.replace` IS iface-scoped — iface = `${IFACE_A}`), iface field matches catalog expectation.
- `loader.trust_model` event has `fields.trust_model == "strict"` (under default env).

**Negation control**: re-run sequence with `XDPMF_LOG_FORMAT=text`; assert NO line parses as JSON (`jq -e '.' < text_line.txt` returns NON-ZERO for any non-trivial line). Confirms the env var is doing real work.

**Assertion mechanism**: `jq -e` for shape; `jq -s '[ ... ] | length == N'` for event counts; bash `[[ "$(jq -r '.level' <<< $line)" == "info" ]]` for level extraction.

**SKIP conditions**: `jq` already required. No new SKIP-77.

**Cleanup**: `cleanup_veth`.

**Maps to**: PI-3.5-2 (JSON envelope shape), PI-3.5-4 (event-name catalog enforcement), HG-3.5-2, Q3 E1, Q4 R1.

##### §6.55 T_LOG_JSON_EXPORTER_EVENTS — exporter under JSON mode

**Trigger**: set `XDPMF_LOG_FORMAT=json`; start `xdpmf-exporter --port ${EXPORTER_PORT} --bpffs-root /tmp/does-not-exist-${RANDOM}` in background; let it settle (~500ms); capture stderr; kill via SIGTERM; capture trailing stderr too. THEN repeat with bpffs root that exists but has zero per-iface subdirs.

**Observable outcome**:
- HK-16 missing-bpffs-root path: stderr contains EXACTLY ONE `exporter.warn.bpffs_root_missing` event (JSON line) with `fields.bpffs_root == "/tmp/does-not-exist-${RANDOM}"`.
- Startup INFO event `exporter.listening` present with `fields.bind_addr` + `fields.port == ${EXPORTER_PORT}`.
- Shutdown INFO event `exporter.shutdown` present after SIGTERM (no fields required; iface null).
- Negation: re-run with `XDPMF_LOG_FORMAT=text`; assert lines are NOT JSON; specifically assert pre-§5.32 HK-16 text line shape `"xdpmf-exporter: WARN bpffs root .* does not exist; will serve empty metrics"` is present byte-equivalent (PI-3.5-1 cross-check at the exporter scope).

For HK-17 ERROR (exit-6 trigger): test setup creates per-iface bpffs dir with `chmod 000` (mirrors T_EXPORTER_EXITS_6_ALL_IFACES_EACCES setup); exporter exits 6 within healthz timeout; stderr captures contain `exporter.error.all_ifaces_eacces` JSON event with `fields.total_discovered == <N>`. If EACCES reproduction not possible in test env, SKIP-77 the HK-17 sub-case (consistent with T_EXPORTER_EXITS_6_ALL_IFACES_EACCES SKIP-77 conditions).

**Assertion mechanism**: `jq -e`; `grep -cE '"event":"exporter.warn.bpffs_root_missing"' stderr.txt == 1`.

**SKIP conditions**: `jq` already required; HK-17 sub-case SKIP-77 if EACCES not reproducible (parallels §6.46).

**Cleanup**: kill exporter; cleanup bpffs test dir.

**Maps to**: PI-3.5-2, PI-3.5-3 (HK-16 + HK-17 byte-equivalence under text-mode + JSON-mode event-name presence), HG-3.5-2.

##### §6.56 T_LOG_JSON_BYPASS_AUDIT — bypass under JSON mode carries HK-4 fields

**Trigger**: set `XDPMF_LOG_FORMAT=json`; `sudo -E -n xdpmacfilter bypass --iface ${IFACE_A} --unsafe --reason T_LOG_JSON_test`. Capture stderr.

**Observable outcome**:
- Exactly ONE JSON line with `.event == "bypass.activated"`.
- `.level == "info"`.
- `.iface == "${IFACE_A}"`.
- `.fields.uid` is an integer (matches `id -u` of the invoking process).
- `.fields.euid` is an integer.
- `.fields.sudo_user` is a string (the real SUDO_USER OR `<none>` if unset — accepts either per HK-4 contract).
- `.fields.reason == "T_LOG_JSON_test"`.
- `.msg` equals pre-§5.32 audit line prose (byte-equivalent under text mode — sub-case below).

**Negation control (PI-3.5-1 byte-equivalence under text mode for bypass.activated specifically)**: re-run with `XDPMF_LOG_FORMAT=text`. Assert stderr contains a line matching the pre-§5.32 HK-4 audit-line regex `^xdpmacfilter: BYPASS activated on ${IFACE_A} by uid=[0-9]+ euid=[0-9]+ sudo_user="[^"]*" reason="T_LOG_JSON_test"$`. This is the byte-equivalence cross-check at the bypass scope (T_LOG_TEXT_BYTE_EQUIVALENT covers the broad case; this one is the focused HK-4-specific check).

Second negation: bypass via `--reason` containing characters needing JSON-escape (e.g. `--reason 'has"quote'`). Assert: JSON-mode `.fields.reason == "has\"quote"` (jq-decoded back to `has"quote`); text-mode line preserves the existing HK-4 escape behavior byte-equivalent.

**Assertion mechanism**: `jq -e`; bash `[[ $(jq -r '.fields.reason') == "T_LOG_JSON_test" ]]`; `grep -qE -- "${audit_ere}" "${stderr_text}"`.

**SKIP conditions**: none new (uses existing bypass test setup).

**Cleanup**: `cleanup_veth`.

**Maps to**: PI-3.5-2, PI-3.5-5 (HK-4 structural fields in JSON `fields:{}`), HG-3.5-3, D-3.5-11 (level token embedding preserved).

##### §6.57 T_LOG_JSON_ENVELOPE_INVARIANTS — every JSON line has required fields

**Trigger**: set `XDPMF_LOG_FORMAT=json`; run a SWEEP that exercises many events: `attach` (loader.trust_model), `apply` (loader.trust_model + sidecar warns if applicable), `attach` (alien-refusal triggers loader.attach.replace or fail variant — pick the working subcase), `bypass --unsafe` (bypass.activated), `detach`, then start + stop exporter (exporter.listening + exporter.shutdown). Capture all stderr.

**Observable outcome**: every captured stderr line that's non-empty MUST:
- Parse as a single JSON object (`jq -e '.' < line`).
- Have ALL required fields present: `ts`, `level`, `event`, `msg`, `fields`, `iface`.
- `level` ∈ {`"info"`, `"warn"`, `"error"`} (exact string match).
- `event` ∈ kEventNames catalog (33 valid values — fetch list at test-time from a compile-time-baked C-string array in a tiny test-only helper, OR hard-coded in the test as a `KNOWN_EVENTS` bash array of 33 strings).
- `iface` is either a JSON string OR JSON null (NOT absent, NOT object/array/bool).
- `fields` is a JSON object (possibly empty `{}`; NOT absent, NOT array/scalar).
- `ts` matches ERE `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`.
- `msg` is a JSON string (possibly multi-line via escaped `\\n` — assert `.msg | type == "string"`).

**Negation control**: artificially construct a malformed JSON line (e.g. `echo '{"ts":"bad","level":"INFO","event":"unknown"}' > bad_line` — missing `msg` + `iface` + `fields`); pipe through the test's per-line validator; assert it REJECTS. Confirms the validator isn't a no-op.

**Assertion mechanism**: per-line `jq -e` for shape; `jq -e '.level | IN("info","warn","error")'`; `jq -e '.event | IN($KNOWN_EVENTS[])' --argjson KNOWN_EVENTS "[\"cli.usage_error\", ...]"` for catalog membership; `jq -e '.iface | type | IN("string", "null")'` for iface type; `jq -e '.fields | type == "object"'`.

**SKIP conditions**: none new.

**Cleanup**: `cleanup_veth`; kill exporter.

**Maps to**: PI-3.5-2, PI-3.5-4 (envelope invariants), HG-3.5-2.

**Load-bearing**: this test prevents drift in the JSON envelope shape across cycles. If a future cycle accidentally omits the `iface` field (or omits `fields`), this test catches it.

##### §6.58 T_LOG_EVENT_CATALOG_STABILITY — kEventNames set equality

**Trigger**: build the binary; introspect `src/common/logger.hpp` for `kEventNames`. Two mechanisms (impl + tester pick):
- **Mechanism A (simpler — compile-time-baked test helper)**: tester writes a small C++ helper test binary that links logger.cpp + dumps `kEventNames` to stdout (one event-name per line); ctest compares against `tests/fixtures/log_events_v1.txt` (committed reference of 33 names).
- **Mechanism B (grep-only — no new test binary)**: tester `grep -E '^\s*"[a-z_.]+",\s*/\*' src/common/logger.hpp | sed -E 's/^\s*"([^"]+)".*/\1/'` extracts the 33 names; sort + cmp against committed reference.

Tester picks. Mechanism B is simpler (no test-only TU); architect recommends Mechanism B + the committed reference file.

**Observable outcome**:
- Extracted list of event names from `kEventNames` source matches `tests/fixtures/log_events_v1.txt` exactly (sorted comparison, byte-equivalent).
- Count is exactly 33.

**Negation control**: temporarily inject an extra event-name into the source (or remove one) via `sed` on a copy; re-run extractor; assert MISMATCH. Confirms the comparator isn't a no-op. (This sub-case need NOT modify the real source — operate on a copy.)

**Assertion mechanism**: `sort | cmp`; `wc -l`.

**SKIP conditions**: none.

**Cleanup**: rm test-copy if generated.

**Maps to**: PI-3.5-4 (event catalog stability — locked set; one-line table extension required to add a new event in a future cycle), HG-3.5-4, D-3.5-1.

**Load-bearing**: this test enforces the "catalog is a compile-time constexpr table" contract. If a future cycle adds an event-name via magic string literal scattered in source (NOT updating `kEventNames`), this test catches it because the new event-name extracted from emission sites wouldn't be in the catalog (sister-test could grep `logger::emit\(.*"[a-z_.]+"` for actual emit-site usage — optional extension; impl decides).

##### Cross-test note: `xdp_fixture` RESOURCE_LOCK

T_LOG_TEXT_BYTE_EQUIVALENT + T_LOG_JSON_LOADER_EVENTS + T_LOG_JSON_BYPASS_AUDIT + T_LOG_JSON_ENVELOPE_INVARIANTS all use the existing veth fixture (`setup_veth` / `cleanup_veth`); these serialize via `RESOURCE_LOCK xdp_fixture`. T_LOG_JSON_EXPORTER_EVENTS additionally locks `exporter_port_9417`. T_LOG_EVENT_CATALOG_STABILITY needs neither lock (static analysis; can run in parallel with everything).

#### §6.5 Preserved invariants (MVP-3.5 brownfield) — PI-1..PI-34 + PI-3.4b-* hold + PI-3.5-* NEW

All prior invariants (PI-1..PI-34 + PI-3.4b-1..PI-3.4b-9 + PI-7-3.4b-hpp/cpp + PI-7-3.4.5-hpp/cpp + PI-7-3.4-hpp + PI-7-3.3-hpp + PI-7-3.2-hpp) continue to hold post-§5.32 with NO adjudications + NO carve-outs (this slice is strictly additive: NEW shared module + NEW env var + NEW 6 ctests; NO modification of existing data structures, BPF programs, public APIs, or test bodies). PI-7-3.5-hpp continues the loader.hpp ZERO-diff streak (7th consecutive cycle). PI-3.5-1 is the LOAD-BEARING NEW PI of this slice.

Reviewer's 5th framework point walks the COMBINED list (PI-1..PI-34 + PI-3.4b-* + PI-3.5-*) and reports `[INVARIANT-VIOLATED]` per failed check.

**Continuing invariants — restatement for the MVP-3.5 namespace**:

| # | Invariant | §5.32 check mechanism |
|---|---|---|
| PI-1..PI-5 | Trust+identity gates ENFORCED in both modes | Re-run §6.9 / §6.14 / §6.15 / §6.20 / §6.26 sub-cases; all pass (logger is orthogonal to gates; gates emit via logger but enforcement path byte-equivalent). |
| **PI-6-3.5** | **52 pre-§5.32 ctests pass byte-equivalent OR legitimately SKIP-77 — STRICT SUPERSET with ZERO ctest-body-EDIT carve-out** (loader's text-mode emissions are byte-equivalent per PI-3.5-1; no existing ctest needs body update). | Re-run all 52 tests post-§5.32 → all pass (or SKIP-77); `git diff main -- tests/T_*.sh` shows ZERO modified files; 6 NEW files (§6.53..§6.58). All 52 pre-§5.32 ctest bodies byte-equivalent. PI-6-3.4b had 2-EDIT carve-out (T_RULES_SKELETON_NOT_WIRED + T_EXPORTER_METRICS_FORMAT); PI-6-3.5 has ZERO carve-out (text-mode byte-equivalence eliminates the need for any test-body change). Reviewer asserts the empty-diff statement explicitly. |
| **PI-7-3.5-hpp** | **`loader.hpp` ZERO diff — 7TH consecutive slice** (MVP-3.1 +1; MVP-3.2/3.3/3.4/3.4.5/3.4b/3.5 = 0). ALSO: `src/lib/config.hpp` ZERO diff this slice (2nd cycle). | `git diff main -- src/lib/loader.hpp src/lib/config.hpp` shows ZERO output. Any diff = `[INVARIANT-VIOLATED]`. Logger module owns its own header (`src/common/logger.hpp`); the new public symbols (Level, Format, Field, emit, kEventNames) all live there, NOT in loader.hpp. |
| PI-8-3.5 | `xdpmacfilter --version` reports `xdpmacfilter 0.8.0` AND `xdpmf-exporter --version` reports `xdpmf-exporter 0.8.0` (shared `version.h` per §5.25 P3) | Run both `--version`; both single-line outputs `0.8.0` + newline. MINOR bump from 0.7.0 (operator-facing feature: structured-logging env var). |
| PI-9 | `--help` / `--version` output FORMAT preserved + optional one-line addition mentioning `XDPMF_LOG_FORMAT={text,json}` in the env-var block | §6.10 T_CLI_HELP_VERSION re-run passes (forward-compatible ERE). The mention IS optional per architect-spec — impl-flexible. Recommended: ADD `XDPMF_LOG_FORMAT` row to the Environment-variables block in BOTH `cli.cpp::usage_text()` AND `exporter/main.cpp::print_usage()` per HK-6 idiom. |
| PI-10 | `src/common/mac_filter.h` UNCHANGED | `git diff main -- src/common/mac_filter.h` shows ZERO output (logger constants live in `src/common/logger.hpp` — separate file). PI-10-3.4b ADDITIVE-ONLY continues; this slice doesn't even add to mac_filter.h. |
| PI-11 | Internal directory layout UNCHANGED | `find src -type d` shows the SAME 5 dirs (`src/lib/`, `src/cli/`, `src/common/`, `src/bpf/`, `src/exporter/`). No new dir; logger.cpp + logger.hpp live within existing `src/common/`. |
| PI-12 | Pin paths host-global per `nsenter --net` | UNCHANGED. Logger doesn't touch bpffs. |
| PI-13-3.4b ≡ PI-27 adjudicated | inner-allowlist-value offset-0 byte semantics PRESERVED; value_size 8 stable | UNCHANGED. Logger doesn't touch BPF maps. |
| PI-14..PI-25 | mode flag / CIDR / STAT_PASS_CIDR / yaml schema / atomic swap / systemd / Ansible | UNCHANGED. |
| PI-26 | MVP-3.3 historical "no C++/BPF source change" check | UNCHANGED (fires on MVP-3.3 commit set). |
| PI-28-3.4b | `mac_filter_prog` BPF function body byte-equivalent to MVP-3.4b shape | UNCHANGED. JSON logging is userspace-only; no BPF code touch. |
| PI-29-3.4b | `rules` map NOT consulted by datapath; `action_table` NOT consulted; inner-VALUE rule_id IS read | UNCHANGED. |
| PI-30 | `bypass` primitive UNCHANGED in mechanics | UNCHANGED — bypass.cpp:174 audit-line is byte-equivalent under text mode (PI-3.5-1) + structurally exposed under JSON mode. |
| PI-31-3.4b | Exporter is READ-ONLY by construction | UNCHANGED. Logger does NOT write any BPF map / sidecar file; logger emits to stderr ONLY. `grep -rE 'bpf_(map_(update\|delete)_elem\|obj_pin\|...)' src/exporter/` still returns ZERO. |
| PI-32-3.4b | Exporter graceful sidecar-orphan tolerance | UNCHANGED. Sidecar-orphan path is unchanged; logger just adds an `exporter.scrape.warn.*` event-name to the existing WARN emission. |
| PI-33 | Both binaries share version | UNCHANGED in shape; bump to 0.8.0 (PI-8-3.5). |
| PI-34 ≡ PI-6-3.5 | 52 pre-§5.32 ctests strict-superset with ZERO carve-out | Same check as PI-6-3.5. |
| PI-3.4b-1..PI-3.4b-9 (MVP-3.4b cycle 1) | rule_counters map / counter survival / struct allow_entry / bump_rule wiring / sidecar / exporter rule labels / config.id source / kManagedMaps[]=13 / 3-EDIT carve-out | UNCHANGED. Logger doesn't touch any of these surfaces. |

**NEW invariants** (MVP-3.5-specific):

| # | Invariant | Check mechanism |
|---|---|---|
| **PI-3.5-1** | **TEXT-MODE BYTE-EQUIVALENCE — load-bearing MUST.** Every emission site in TEXT mode (default, OR explicit `XDPMF_LOG_FORMAT=text`, OR `XDPMF_LOG_FORMAT=""`) writes byte-identical output to the pre-§5.32 emission. No `[level]` prefix added. No prose modification. No reordering. The 52-ctest baseline (specifically the 12 ctests that grep stderr text — see catalog below) passes WITHOUT modification. | T_LOG_TEXT_BYTE_EQUIVALENT (§6.53 — load-bearing canary): 3-way byte-equivalence across env conditions + byte-equivalence against committed reference. THE 12 stderr-grep ctests pass post-§5.32 byte-equivalent: T_APPLY_VALID_CONFIG (line 64), T_TRUST_MODEL_FLEET_RELAXES_GATE (lines 90, 118, 146, 185), T_APPLY_REJECTS_MALFORMED (line 110), T_APPLY_EXITS_1_ON_MISSING_CONFIG (line 65), T_EXIT_CODE_9_ON_CONFIG_ERROR (line 62), T_LINK_PERSIST_ACROSS_LOADER_EXIT (line 79), T_SYSTEMD_LIFECYCLE (line 240), T_FLEET_DOCS_SUBSTRING (line 66 — docs only, not stderr but cross-PI documentation), T_BYPASS_CMD_DETACHES (lines 86 + 134), T_BYPASS_INTERACTIVE_PROMPT (lines 309, 348, 391), T_RULES_SKELETON_NOT_WIRED (line 92), T_EXPORTER_NO_ATTACHED_IFACE (line 187), T_EXPORTER_EXITS_6_ALL_IFACES_EACCES (line 275). Total = 13 ctests with byte-equivalence dependency on text-mode emissions; all pass without modification. |
| **PI-3.5-2** | **JSON-MODE ENVELOPE STABILITY** — every emission under `XDPMF_LOG_FORMAT=json` is a single-line JSON object with fixed-field shape `{ts, level, event, iface, msg, fields}`. `ts` is ISO-8601 UTC second-precision. `level` ∈ {info, warn, error}. `event` is from `kEventNames`. `iface` is string-or-null. `msg` is JSON-escaped string. `fields` is object (possibly `{}`). | T_LOG_JSON_ENVELOPE_INVARIANTS (§6.57): per-line `jq -e` validation across the full sweep. T_LOG_JSON_LOADER_EVENTS (§6.54) + T_LOG_JSON_EXPORTER_EVENTS (§6.55) + T_LOG_JSON_BYPASS_AUDIT (§6.56) lock specific event shapes. |
| **PI-3.5-3** | **`XDPMF_LOG_FORMAT` ENV VAR CONTRACT** — read once at first emit (lazy init under once_flag); cached for process lifetime; unset/empty/`text` → Text; `json` → Json; any other value → WARN + Text fallback. Documented in both binaries' `--help` env-var block. | T_LOG_TEXT_BYTE_EQUIVALENT (§6.53) covers unset/empty/text 3-way equivalence (R1 + edge cases). T_LOG_JSON_LOADER_EVENTS (§6.54) negation control covers JSON vs Text distinguishability. `xdpmacfilter --help` AND `xdpmf-exporter --help` outputs contain `XDPMF_LOG_FORMAT` token under Environment variables block — verified via T_CLI_HELP_VERSION (recommended ERE forward-compat extension; not a hard fail if absent — see PI-9). |
| **PI-3.5-4** | **EVENT-NAME CATALOG STABILITY** — `kEventNames` constexpr array contains exactly 33 entries; each entry is a dot-delimited lowercase snake_case identifier; adding/removing an entry requires explicit table extension (grep-visible in diff). | T_LOG_EVENT_CATALOG_STABILITY (§6.58): sort + cmp against committed reference `tests/fixtures/log_events_v1.txt`. Any drift = `[INVARIANT-VIOLATED]`. |
| **PI-3.5-5** | **HK-4 STRUCTURAL FIELDS IN JSON `bypass.activated.fields:{}`** — uid (int), euid (int), sudo_user (string-or-`<none>`), reason (string, JSON-escaped) all present + correct type. Text-mode byte-equivalent to HK-4 audit line per PI-3.5-1. | T_LOG_JSON_BYPASS_AUDIT (§6.56): jq assertions on each fields entry + text-mode negation cross-check via existing HK-4 regex from T_BYPASS_INTERACTIVE_PROMPT.sh line 309 pattern. |
| **PI-3.5-6** | **ONE EMISSION SITE EXEMPT** — `src/cli/bypass.cpp:96` (interactive prompt) stays as raw `fprintf(stderr, ...)` per D-3.5-7. NOT converted. NO logger include in that single emission. JSON-mode operators using bypass interactively see one non-JSON line (the prompt); document as known wart. | `grep -nE 'fprintf\(stderr.*BYPASS will detach' src/cli/bypass.cpp` returns line 96; `grep -nE 'logger::emit.*bypass\.prompt' src/cli/bypass.cpp` returns ZERO. Documented in CHANGELOG. |
| **PI-3.5-7** | **NO NEW EXTERNAL BUILD DEP** — logger.cpp uses only stdlib (`<cstdio>`, `<ctime>`, `<string>`, `<string_view>`, `<variant>`, `<span>`, `<optional>`, `<array>`, `<mutex>`, `<cstdlib>` for getenv). NO `nlohmann/json`, NO `fmt`, NO `spdlog`, NO any logger library. Roll-your-own JSON envelope per D-3.4b-10 precedent extended. | `grep -E '^#include' src/common/logger.{cpp,hpp}` returns ONLY stdlib headers (`<...>`). `find_package` / `target_link_libraries` for logger TU adds NO new library link. CMake diff shows only `target_sources` additions. |

**No deletions/relaxations** of PI-1..PI-34 + PI-3.4b-* in this slice. Strictly additive. No carve-outs.

PI-7-3.5-hpp STRENGTHENS PI-7-3.4b-hpp (7th consecutive ZERO-diff cycle on loader.hpp + 2nd on config.hpp). PI-10 holds at ZERO diff (stronger than its previous "additive-only" baseline — this slice doesn't add to mac_filter.h at all).

#### §5.32 verifiable invariants for reviewer

(Per architect-spec §6.5 "Verification-hints discipline": these are GUIDANCE for the reviewer, NOT contracts for impl. Default MAY. Reserve MUST only for true PI-* contracts (PI-1..PI-34 + PI-3.4b-* + PI-3.5-* ARE MUSTs by definition; the items below MAY be relaxed by impl if a contract elsewhere demands it). **Resolution rule for prose-vs-invariants conflicts within this amendment: invariants block wins, prose loses; if impl deviates on a SHOULD/MAY hint to satisfy a PI-* contract, reviewer's correct disposition is `inline-merge` on the hint text — NOT `[UNRELATED-EDIT]` on impl.**)

In addition to PI-1..PI-34 + PI-3.4b-* + PI-3.5-* above:

- `git diff main -- src/lib/loader.hpp src/lib/config.hpp` SHOULD show ZERO output (PI-7-3.5-hpp — 7th consecutive cycle on loader.hpp + 2nd on config.hpp).
- `git diff main -- src/common/mac_filter.h` SHOULD show ZERO output (PI-10 stricter-than-additive this slice).
- `git diff main -- src/bpf/mac_filter.bpf.c` SHOULD show ZERO output (PI-28-3.4b continues — userspace-only slice).
- `git diff main -- tests/T_*.sh` SHOULD show: 6 NEW files (§6.53..§6.58) AND ZERO modified files (PI-6-3.5 strict superset with ZERO carve-out).
- `git diff main -- tests/CMakeLists.txt` SHOULD show 6 new `add_test` entries; ZERO modification to the 52 existing entries.
- `git diff main -- tests/fixtures/` SHOULD show: 2 NEW files (`log_text_reference.txt` for §6.53 + `log_events_v1.txt` for §6.58); ZERO modification of existing fixtures.
- `git diff main -- CMakeLists.txt` SHOULD show: VERSION bump 0.7.0 → 0.8.0; 2 lines added (logger.cpp added to xdpmf_internal AND xdpmf-exporter target_sources).
- `git diff main -- CHANGELOG.md` SHOULD show NEW `[0.8.0]` entry + Build-pace MVP-3.5 row.
- NEW files SHOULD exist: `src/common/logger.{cpp,hpp}`, 6 `tests/T_LOG_*.sh`, 2 `tests/fixtures/log_*.txt`.
- 6 new ctests SHOULD pass (§6.53..§6.58); §6.53 (T_LOG_TEXT_BYTE_EQUIVALENT) is THE load-bearing canary.
- 52 pre-§5.32 ctests SHOULD still pass byte-equivalent (or legitimately SKIP-77). The 13 stderr-grep ctests catalogued under PI-3.5-1 SHOULD pass byte-equivalent specifically without ctest-body modification.
- `xdpmacfilter --version` SHOULD report `xdpmacfilter 0.8.0` AND `xdpmf-exporter --version` SHOULD report `xdpmf-exporter 0.8.0` (PI-8-3.5).
- `XDPMF_SANITIZERS=ON` build SHOULD be clean for BOTH binaries (no UB / no leaks from new logger code; the `std::once_flag` + `std::variant` + `std::optional` usage is standard).
- `XDPMF_LOG_FORMAT=text xdpmacfilter --version` AND `XDPMF_LOG_FORMAT=json xdpmacfilter --version` AND unset-env-var `xdpmacfilter --version` SHOULD all produce IDENTICAL stdout `xdpmacfilter 0.8.0` (logger doesn't intercept stdout; --version goes to stdout per existing semantic).
- `grep -nE 'fprintf\(stderr.*BYPASS will detach' src/cli/bypass.cpp` SHOULD return line 96 (PI-3.5-6 — the EXEMPT site stays raw).
- `grep -c 'logger::emit' src/` SHOULD return ≥40 (40 converted emission sites; impl may collapse some into helper functions).
- `kEventNames` constexpr array SHOULD have exactly 33 entries (PI-3.5-4).
- Helper duplication SHOULD show: `grep -c 'json_escape' src/lib/sidecar.cpp` == 1 (the existing) + `grep -c 'json_escape' src/common/logger.cpp` == 1 (the new duplicate) — D-3.5-2 contract. (Both call-sites bear the same semantic, byte-equivalent escaping.)
- Optional: a tiny integration sanity-check: `XDPMF_LOG_FORMAT=json xdpmacfilter attach --iface ${IFACE_A} 2>&1 | head -1 | jq -e '.event == "loader.trust_model"'` SHOULD return success on a kernel that supports BPF.

#### §7 OOS — MVP-3.5 components SHIPPED + new fences + cycle 2/3 surfaced

##### Moved from deferred to SHIPPED (per MVP-3.5)

The following item was deferred at §5.30 §7 OOS (carry-forward through 5 cycles 3.4.5 / 3.4b / 3.4c-name / MVP-3.4b cycle 1 / informal pending) and is now CLOSED by this slice:

- ~~**JSON structured logs (MVP-3.5)**~~ **— SHIPPED in §5.32** as `XDPMF_LOG_FORMAT={text,json}` env var + `src/common/logger.{cpp,hpp}` module + 33-event catalog + 6 ctests + 40 emission-site conversions (1 exempt: bypass.cpp:96 interactive prompt). NDJSON envelope per HG-3.5-2; ISO-8601 sec-precision timestamps per Q2 T1; dot-delimited event names per Q3 E1; read-once env-var per Q4 R1; flat-scalars-only fields per Q5 F1; dup-TU compile per Q6 B1.

##### Additional MVP-3.5 deliverables (surfaced in this slice)

- **Phase A grep dividend**: 41 emission sites confirmed → 40 converted + 1 EXEMPT (bypass.cpp:96 interactive prompt). Brief's "8 files" enumeration corrected during Phase A: `src/cli/apply.cpp` listed in brief but has ZERO emissions (was a false-positive in brief author's count). Actual 8 files: `src/cli/{main,bypass}.cpp`, `src/lib/{loader,sidecar}.cpp`, `src/exporter/{main,http,stats_reader,rule_counters_reader}.cpp`. Documented in §5.32 FileList prose + D-3.5-7 exempt rationale.
- **PI-6-3.5 ZERO carve-out** — first multi-source-touch slice since MVP-3.4b cycle 1 with literally ZERO ctest body modifications. Achievable because PI-3.5-1 text-mode byte-equivalence is a strict MUST + the 52 existing ctests are all forward-compatible.
- **PI-7-3.5-hpp 7th-cycle ZERO-diff on loader.hpp + 2nd on config.hpp** — extends the streak. Logger module owns its own header per D-3.5-1.
- **13-stderr-grep ctests catalogued under PI-3.5-1** — explicit list of which existing ctests gate the load-bearing PI. Reviewer's framework point 5 walks this list specifically.

##### Surfaced as next-natural slice

**MVP-3.5b — Log destination + level filtering** (gating on operator demand):
- `XDPMF_LOG_DEST={stderr,file,syslog,journald}` — file destination + log rotation. NEW FENCE for MVP-3.5.
- `XDPMF_LOG_LEVEL={info,warn,error}` — level-based filtering. Mute info-level events at process-lifetime granularity.
- Live-toggle via SIGHUP — alternative R3 from Q4. Cycle 1 ships R1 read-once.

**MVP-3.4b cycle 2 — atomic-swap promotion of `rules` map + counter management API** (carry-forward unchanged from §5.31 surfaced-next-natural).

**MVP-3.4c — action-table dispatch (drop rules operative)** (carry-forward unchanged from §5.31).

##### NEW out-of-scope fences (per §5.32; carry-forward unchanged from §5.31 unless noted)

- **`XDPMF_LOG_DEST` (file/syslog/journald destinations)** — MVP-3.5b candidate. Cycle 1 is stderr-only. NEW FENCE.
- **Log rotation** — operators wrap stderr with their own log shippers (rsyslog, vector, fluentbit). Native rotation OOS forever. NEW FENCE.
- **`XDPMF_LOG_LEVEL` (level-based filtering)** — MVP-3.5b candidate. Cycle 1 emits all events always. NEW FENCE.
- **Per-iface log routing** — separate stderr streams per iface; not needed at current event rate. NEW FENCE.
- **`schema_version` field in JSON envelope** — added when a future cycle ships a breaking change; cycle 1 implicit schema_version=1. NEW FENCE.
- **`bpf_printk` JSON-ification** — kernel-side BPF debug-prints stay text (D-3.5-10). Userspace stderr only converts. NEW FENCE.
- **`src/common/json.{cpp,hpp}` extraction** — duplicated helpers in logger.cpp per D-3.5-2; future cycle MAY extract if 3rd JSON emitter surfaces. NEW FENCE.
- **`uint64_t` FieldValue variant** — `int64_t` only per D-3.5-3; future cycle MAY add if a use case surfaces. NEW FENCE.
- **Nested objects or arrays in `fields:{}`** — flat scalars only per Q5 F1; future cycle MAY relax. NEW FENCE.
- **Multi-line msg splitting into per-line events** — cli.usage_text stays as ONE event with embedded `\\n` (D-3.5-5); not split into N events. NEW FENCE.
- **Conversion of `src/cli/bypass.cpp:96` interactive prompt** — explicitly EXEMPT per D-3.5-7 + PI-3.5-6. JSON-mode operators using bypass interactively see one non-JSON line (the prompt). NEW FENCE.
- **Text-mode format evolution** (e.g. add `[level]` prefix to text-mode emissions) — PI-3.5-1 byte-equivalence is the load-bearing contract; ANY text-mode shape change is a breaking-change slice requiring its own cycle + ctest body updates. NEW FENCE.
- **Live env-var re-read on SIGHUP** — Q4 R3 rejected; cycle 1 ships R1 read-once. NEW FENCE.
- **Q4 R2 per-emit getenv** — REJECTED at Q4; read-once R1 ships. NEW FENCE.
- **`nlohmann/json` or any JSON library dep** — D-3.4b-10 zero-deps precedent extends to logger via D-3.5-2 + PI-3.5-7. NEW FENCE.
- **Async/queued logger** — synchronous fprintf only; async (e.g. lock-free queue + drain thread) is OOS forever (architecture-level complexity for marginal benefit at current event rates). NEW FENCE.
- **Color/ANSI escape codes in text mode** — none. Text mode is plain bytes byte-equivalent to MVP-3.4b shape. NEW FENCE.
- **Doc bucket D1..D13** — user-driven manual pass; not /mint-dev. (Carry-forward.)
- **Security M3 / Perf M1-M4 / TSAN / CO-RE field-probe** — separate cycles (carry-forward).
- **MVP-3.4b cycle 2** (atomic-swap promotion of `rules` map; action_table dispatch) — carry-forward.
- **Library extraction `libxdpmf.so.0` (MVP-3.6+)** — carry-forward.
- **Daemon `xdpmfd` (MVP-3.6+)** — carry-forward.
- **Binary rename `xdpmacfilter` → `xdpfilter` (MVP-3.12)** — carry-forward.
- **L4 ports / VLAN / IPv6 CIDR** — carry-forward.
- **sFlow (MVP-3.6 conditional)** — carry-forward.

##### Anti-misdiagnosis notes (institutional learning, per architect-spec §6.6)

This slice carries forward all anti-misdiagnosis guards from prior cycles + adds three specific to MVP-3.5:

1. **Cap-set declaration on a NEW invocation path** (inherited from §5.28 / §5.29 / §5.30 / §5.31): unchanged. No new systemd unit cap-mask changes; logger is userspace-only synchronous fprintf — no new syscalls beyond those already exercised.

2. **Silent-divergence-from-design pattern** (inherited from [[impl-role-discipline]]): impl follows design; disagreement is OK but ONLY via explicit Phase B escalation. Specific to this slice: PI-3.5-1 text-mode byte-equivalence is the load-bearing call; **if impl considers ANY decoration in text-mode output (level prefix, timestamp prefix, color codes, etc.), impl MUST SendMessage architect BEFORE shipping**. Default workaround surface is broad; silent decoration could mask the contract violation until a future cycle's ctest catches it.

3. **Verification-hints discipline trap** (inherited from prior cycles): the §5.32 verifiable invariants section above is GUIDANCE for the reviewer, NOT contracts for impl. Items default to SHOULD/MAY; MUST is reserved for PI-* contracts. Resolution rule for prose-vs-invariants conflicts within this amendment: invariants block wins, prose loses (stated once per the amendment template; this single statement covers all §5.32 prose vs. PI-* conflicts).

4. **Phase A code-grep discipline pays off (cont.)** (inherited from §5.31 EDIT-1 + EDIT-2 cycle): the Phase A grep of stderr emission sites + env-var existing patterns + helper-location decision caught (a) brief's "src/cli/apply.cpp" listed but ZERO emissions there (corrected to 8 actual files); (b) brief's "1 of 41 sites is interactive prompt at bypass.cpp:96" not flagged in brief but architect-spec sub-rule "where is X called per-runtime" caught it (interactive prompt ≠ log event semantic — D-3.5-7 EXEMPT decision flowed); (c) helper duplication vs extraction trade-off (D-3.5-2 keeps slice contained vs library-extraction scope creep). **Future-cycle guard for any architect agent**: BEFORE publishing brownfield design.md, grep ALL literal counts the brief mentions, classify each emission site by per-runtime semantic (UI vs log vs interactive prompt), and pre-decide helper-location trade-offs. The 30-minute Phase A pass during this slice's architecture phase reduced expected Phase B EDITs from ~2 (MVP-3.4b average) to ~0 expected (TBD pending impl).

5. **Interactive-vs-log emission distinction (NEW guard #8, MVP-3.5-specific)** — when adding a logger to a codebase that has mixed log + interactive-UI fprintf-to-stderr sites, an automatic "convert all stderr fprintf" pass would break interactive UX. **Future-cycle architect anti-misdiagnosis rule**: when introducing a NEW logger module that wraps stderr emissions in a structured envelope (JSON, key=value, etc.), grep ALL emission sites + classify each as (a) log event with trailing `\n` OR (b) interactive UI primitive (no trailing `\n`, fflushed before stdin read OR before terminal cursor positioning). UI primitives MUST be EXEMPT from wrapping. Cost: 10-30 seconds of manual review per emission site during Phase A. Benefit: catches THIS class of bug before Phase 2 surfaces broken interactive UX in test runs. **Validated by §5.32 D-3.5-7**: bypass.cpp:96 was the ONE interactive primitive in 41 sites; correctly identified at Phase A; PI-3.5-6 documents the exemption.

6. **Helper-location decision trap (NEW guard #9, MVP-3.5-specific)** — when a NEW source file (logger.cpp) needs the same helper functions as an EXISTING source file (sidecar.cpp), the temptation is to "DRY it up" by extracting to a new shared header. This pulls the existing source file into the slice's edit surface (sidecar.cpp's helper-section becomes "EDITED"), invalidating regional-diff fences. **Future-cycle architect anti-misdiagnosis rule**: prefer duplication of small (<100 LOC) helpers vs extraction-into-shared-module in brownfield slices. The cost of duplication is small + intentional + scope-contained; the cost of premature abstraction is a touchpoint on existing stable files that destabilizes their per-cycle contracts. **Validated by §5.32 D-3.5-2**: ~50 LOC of `json_escape` + `format_timestamp_utc` duplicated in logger.cpp vs extracted to src/common/json.{cpp,hpp}; the latter would have added 2 new files + a touchpoint on sidecar.cpp + a tester EDIT on T_SIDECAR_JSON_SHAPE's assertion regex (potentially). Duplication keeps the §5.32 slice strictly additive — PI-6-3.5 ZERO carve-out.

Evidence: `mint/task-brief.md` MVP-3.5 brief (HG-3.5-1/2/3/4 + Q1-Q6 + PI-3.5-1 framing); `mint/architecture-v2.md` §"§5.30 §7 OOS" carry-forward fence (5 cycles); §5.13 (project's no-logging-library historical decision — §5.32 re-reads as "no LIBRARY DEPENDENCY; in-tree logger is fine"); §5.26 D-3.4-3 (read-once env-var pattern); §5.29 (exporter stderr-line shapes — PI-32 startup WARN posture); §5.30 HK-4 (bypass audit-line structural fields), HK-16 (PI-32 startup WARN exact format), HK-17 (exit-6 ERROR exact format), HK-8 (version bump pattern); §5.31 D-3.4b-10 (roll-your-own JSON writer, zero-deps), D-3.4b-14 (line-oriented format precedent), D-3.4b-17 (non-fatal sidecar write failures); project memory [[impl-role-discipline]] (Phase B escalation discipline); [[mint-hld-scope-discipline]] (single-architect cycle, no /mint-hld); architect-spec Phase A code-grep discipline (30-minute grep pass — emission catalog + helper-location decision + interactive-vs-log classification).
