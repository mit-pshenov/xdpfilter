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
| `src/loader/raii.hpp` | RAII wrappers: `BpfObject`, `BpfMap` (non-owning view), `XdpAttachment`, `BpffsDir` | C++23 (header-only) | 120 |
| `src/loader/cli.hpp` | CLI parse declarations (subcommand `attach`/`detach`, flags, MAC parsing) | C++23 | 40 |
| `src/loader/cli.cpp` | CLI parser implementation: tokenization, MAC validation, usage text | C++23 | 130 |
| `src/loader/loader.hpp` | Loader API: `attach()`, `detach()`, `populate_allowlist()`, error enum | C++23 | 50 |
| `src/loader/loader.cpp` | Open skeleton, pin maps under `/sys/fs/bpf/xdpmacfilter/<iface>/`, attach XDP (SKB mode), detect-and-detach prior instance | C++23 | 200 |
| `src/loader/main.cpp` | `main()`: dispatch subcommand, map exceptions/errors to exit codes | C++23 | 60 |
| `tests/CMakeLists.txt` | ctest registration (tester populates) | CMake | tester |
| `tests/...` | Test scripts/binaries (tester populates per TestStrategy §6) | tester-chosen | tester |

Total impl LOC est: ~870 (excluding tests).

The generated BPF skeleton header (`mac_filter.skel.h`) lives in
`${CMAKE_BINARY_DIR}` — not committed, not listed.

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
directory is the loader's signal that a prior `attach` for this iface
exists and is "ours" (see Decision §5.4).

### 3.6 CLI-internal: `struct AttachConfig`
```
std::string  iface
std::vector<xdpmf_mac> allow      // size ≤ 64, deduplicated by parser
```
Not on any external boundary, but the contract between `cli.cpp` →
`loader.cpp`.

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
| 5 | Detach failed: nothing attached, or pinned dir missing, or kernel error |
| 6 | Permission denied (need CAP_BPF / CAP_NET_ADMIN — typically run as root) |

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

### 4.3 C++ loader API (`loader.hpp`)

```
namespace xdpmf {

struct AttachConfig { std::string iface; std::vector<xdpmf_mac> allow; };

// Returns prog_id on success. Throws std::system_error with codes from
// the LoaderError enum on failure (translated to exit code by main()).
std::uint32_t attach(const AttachConfig& cfg);

// Returns prog_id of the detached program on success.
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

### 5.4 Idempotent reload = **detect-and-detach if ours, refuse if alien** — because
Brief acceptance #6 requires running the loader twice in sequence leaves
no leaked objects. Two options were considered:

- (A) Always-detach: blind `bpf_xdp_detach()` then attach. Simple but
  **dangerous**: would clobber a user's unrelated XDP program (e.g. an
  existing Cilium or in-house filter) silently.
- (B) Refuse-with-error if anything is attached: safe but breaks
  acceptance #6 if our own prior instance left a program attached.

Chosen: **(C) Hybrid**: on `attach`, query iface for current XDP prog id.
  - No prog attached → fresh attach. Create bpffs dir, pin maps, attach.
  - Prog attached AND `/sys/fs/bpf/xdpmacfilter/<iface>/` exists → "ours":
    `bpf_xdp_detach()`, unpin maps, remove dir, then fresh attach.
  - Prog attached AND no bpffs dir → "alien": exit 4, refuse, print the
    foreign prog id in stderr for operator action.

The bpffs directory is the ownership marker. This is safe (won't clobber
unrelated XDP) and idempotent (our own prior instance is auto-cleaned).

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
  recommended.

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
  hardcoded per §5.6.
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
