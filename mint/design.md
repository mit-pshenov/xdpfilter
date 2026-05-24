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
