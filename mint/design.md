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
| `src/loader/loader.hpp` | Loader API: `attach()`, `detach()`, error enum (allow-list populated inline in `attach()` — see §5.17). Post-§5.21 A1: also owns `AttachConfig`/`DetachConfig` structs (moved from `cli.hpp`). | C++23 | 50 |
| `src/loader/loader.cpp` | Open skeleton, pin maps under `/sys/fs/bpf/xdpmacfilter/<iface>/`, attach XDP (SKB mode), 4-state detect-and-(detach-ours / refuse-alien / recover-stale-pin) probe per §5.4 (revised MVP-1.1B: identity-verified ownership + all-modes XDP query — see §5.19, §5.20; MVP-1.1C D4: detach state (a) returns exit 0 — see §5.21) | C++23 | 230 |
| `src/loader/main.cpp` | `main()`: dispatch subcommand, map exceptions/errors to exit codes | C++23 | 60 |
| `README.md` | Repo entry-point doc: what / prerequisites / build / run / test / where-docs-live (added MVP-1.1A) | Markdown | 50 |
| `CHANGELOG.md` | Repo-root version history per Keep-a-Changelog convention; seeded with `0.1.0`/`0.1.1`/`0.1.2`/`0.1.3` sections (added MVP-1.1C per §5.21 B4) | Markdown | 30 |
| `tests/CMakeLists.txt` | ctest registration (tester populates; MVP-1.1B adds T_ATTACH_ALIEN_REFUSAL entry + `add_bpf_object(xdp_pass …)` wiring per §6.9; MVP-1.1C adds T_CLI_HELP_VERSION/T_CLI_CAPACITY/T_CLI_BAD_MAC/T_DETACH_NOTHING entries per §6.10–§6.13) | CMake | tester |
| `tests/T_SANITIZER_BUILD.sh` | ASAN+UBSAN sanitizer-build smoke: fresh `/tmp` build with `-DXDPMF_SANITIZERS=ON` + one end-to-end attach/inject/stats/detach + stderr grep (per §6.8, added MVP-1.1A) | bash | 60 |
| `tests/T_ATTACH_ALIEN_REFUSAL.sh` | Alien-XDP refusal end-to-end: pre-attach `xdp_pass.bpf.o` to `${IFACE_A}`, run our `attach`, assert exit 4 + foreign prog still attached + stderr names foreign id (per §6.9, added MVP-1.1B) | bash | 80 |
| `tests/T_CLI_HELP_VERSION.sh` | CLI surface: `--help` / `--version` exit 0 + content asserts (per §6.10, added MVP-1.1C) | bash | 30 |
| `tests/T_CLI_CAPACITY.sh` | CLI surface: 65-MAC overflow → exit 1 + `too many --allow entries` in stderr (per §6.11, added MVP-1.1C) | bash | 30 |
| `tests/T_CLI_BAD_MAC.sh` | CLI surface: 4 malformed-MAC sub-cases → exit 1 + recognizable stderr (per §6.12, added MVP-1.1C) | bash | 30 |
| `tests/T_DETACH_NOTHING.sh` | `detach --iface lo` on clean iface → exit 0 (per §6.13 + §5.21 D4 idempotency amendment, added MVP-1.1C) | bash | 30 |
| `tests/fixtures/xdp_pass.bpf.c` | Minimal foreign-XDP fixture: `SEC("xdp") int xdp_pass_prog(...) { return XDP_PASS; }` (function name MUST differ from `mac_filter_prog` so §5.19 identity-check classifies it as alien) — built via `add_bpf_object(xdp_pass …)` (per §6.9, added MVP-1.1B) | BPF C | 15 |
| `tests/...` | Other test scripts/binaries (tester populates per TestStrategy §6) | tester-chosen | tester |

Total impl LOC est: ~900 (excluding tests; bumped from ~870 by the §5.4
probe expansion in `loader.cpp` per MVP-1.1B). MVP-1.1C adds no net LOC
to impl (A1/A2 are relocate-and-comment edits; B2 is one CMake token).

The generated BPF skeleton header (`mac_filter.skel.h`) lives in
`${CMAKE_BINARY_DIR}` — not committed, not listed. Likewise the foreign
fixture's BPF object (`${CMAKE_BINARY_DIR}/xdp_pass.bpf.o`) is a build
artifact, not committed.

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
Single shared counter (not per-CPU) per design Decision §5.5.
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
| 4 | Attach refused: a non-ours XDP program is already attached to iface (see §5.4) |
| 5 | Detach failed: kernel error during `bpf_xdp_detach` (post-§5.21 D4: "nothing attached" and "pinned dir missing" cases no longer map to 5 — they return 0) |
| 6 | Permission denied (need CAP_BPF / CAP_NET_ADMIN — typically run as root) |

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

This is safe (won't clobber unrelated XDP, won't be spoofed by planted
pin_dir alone, won't be blinded by alien programs in non-SKB modes)
and idempotent (our own prior instance is auto-cleaned;
crash-mid-attach is auto-recovered).

**Post-publication amendments**: the 4-state expansion (state d), the
identity-verification gate (state b condition 3), and the all-modes
probe (state classification driver) are the MVP-1.1B changes — see
§5.19 (KC-A identity verification) and §5.20 (KC-B all-modes query)
for impl mechanisms and rationale. The detach-state-(a) idempotency
extension is the MVP-1.1C change — see §5.21 D4.

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
  does (i) only — see §7 OOS list.

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
MVP-1.1B without the additional impl complexity.

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
  load-bearing assertion target for §6.9).
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
  libbpf 1.0 (project depends on libbpf ≥ 1.1 per `pkg_check_modules`).

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
- **Ctest properties**: `TIMEOUT 10`. No `RESOURCE_LOCK` (lo is
  shared but we make NO state changes; concurrent veth-fixture tests
  are unaffected). **`SKIP_RETURN_CODE 77`** required (for
  `require_passwordless_sudo` skip path).
- **Why**: the detach-on-clean-iface idempotent path was extended in
  MVP-1.1C (§5.21 D4 amendment to §5.4) but never asserted by ctest.
  Locks the contract that detach is fully idempotent — repeated
  invocations on a clean iface succeed without error. Pairs with
  §6.6's "detach on dirty iface" (T_IDEMPOTENT_RELOAD) for full
  coverage of `detach()`'s state machine.

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
  §6.3, §6.4, §6.5, §6.6, §6.8, §6.9, §6.13) call
  `require_passwordless_sudo` near the top after sourcing
  `common.sh`; SKIP 77 on missing passwordless sudo is the expected
  behaviour, NOT a test failure. All `sudo …` invocations are
  `sudo -n …` (no password prompt — fail-fast instead of hang).
  CMake `set_tests_properties(... PROPERTIES SKIP_RETURN_CODE 77)`
  must be set on every root-requiring entry.
- **C3 (uniquified iface names)**: every literal `veth_a`/`veth_b` in
  §6.3-§6.9 reads as `${IFACE_A}`/`${IFACE_B}` (PID-suffixed
  `xdpmf_a_$$`/`xdpmf_b_$$`); bpffs pin paths follow
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

## 7. Out of scope

The brief's out-of-scope list applies verbatim. Additionally, the
architect explicitly fences out the following items that impl or tester
might be tempted to add:

- **No `stats` subcommand** in `xdpmacfilter` — stats are read via
  `bpftool map dump`. Adding a userspace dump is MVP-2.
- **No `--mode {generic,native,offload}` flag** — generic (SKB) mode is
  hardcoded per §5.6. The MVP-1.1B all-modes probe (§5.20) closes the
  detection-layer gap without exposing a CLI surface; the CLI flag
  itself remains MVP-2.
- **No `bpf_prog_info.tag` (SHA1-of-bytecode) identity check** in §5.19
  — tag-check is the strongest defense and is MVP-2 hardening; MVP-1.1B
  ships name-check only. Adding tag-check requires capturing the
  freshly-built skeleton's own tag at load time and comparing — extra
  complexity not warranted for the current threat model.
- **No `O_PATH/O_DIRECTORY` fd hardening** on `pin_dir` (the §5.19
  option (iii)) — defers to MVP-2 as a layered addition; MVP-1.1B ships
  the name-check identity gate only.
- **No `--mode`-specific detach in MVP-1.1B** — detach always uses
  `XDP_FLAGS_SKB_MODE` per §5.6; we only detach what we ourselves
  attached, and we only attach in SKB. Alien progs in non-SKB modes
  hit state (c) and are refused, not detached.
- **No new exit codes** for the §5.4 4-state expansion — state (d)
  (stale-pin recovery) maps to exit 0 (successful attach after orphan
  cleanup) in `attach()`, and to exit 0 (successful no-op cleanup) in
  `detach()`. The MVP-1 exit-code table (§4.1) is unchanged.
- **No restructure of `loader.hpp`** in MVP-1.1B — all §5.19/§5.20
  changes are confined to `loader.cpp` anon-namespace helpers. Public
  API (§4.3) is unchanged. (Architecture M1 backwards layering —
  `loader.hpp → cli.hpp` — is addressed in MVP-1.1C per §5.21 A1.)
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

- **No netns isolation for the test fixture (C3 Path A)** — per §5.21
  C3 decision, Path B (PID-suffixed names) was chosen as the
  janitorial-pass-appropriate option. Path A (per-test `ip netns add
  xdpmf-test-$$` with veth + loader + traffic gen inside the namespace,
  teardown nukes the netns) is recorded as MVP-2 hardening: ~50 LOC of
  fixture infra, cleaner host isolation, deferred.
- **No CMake-generation of `tests/lib/common.sh:PIN_ROOT`** — per
  §5.21 B3 decision, a 1-line `# MUST match XDPMF_BPFFS_ROOT in …`
  comment makes the coupling explicit for MVP-1.1C. CMake-driven
  generation of the shell constant from the C header
  (`include/common/mac_filter.h`) is MVP-2 hardening.
- **No version-string sync between `CHANGELOG.md` and the loader
  binary's `--version` output** — per §5.21 B4 decision, the changelog
  versions (`0.1.0`/`0.1.1`/`0.1.2`/`0.1.3`) are documentary only; the
  loader binary's compiled-in `--version` string is independent and
  unchanged. Future MVP-2 may add a CMake-derived version constant and
  sync it.
- **No T_VERIFIER_REJECT + kernel-version probe +
  `LoaderError::KernelUnsupported`** — testing MED finding per brief
  OOS section; explicitly MVP-2.
- **No PERCPU stats migration** — performance HIGH finding per brief
  OOS section; design §5.3 + §5.5 explicit MVP-2.
- **No removal of `mint/test-run.log` from the gitignore list** — brief
  flags this as a stale finding (already gitignored AND untracked, no
  work needed). Not a change; documented here so reviewer does not flag
  the non-edit as a miss.
