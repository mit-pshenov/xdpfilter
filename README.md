# xdpmacfilter — L2 MAC allow-list XDP filter (MVP-1)

## What it does

Minimal Linux XDP packet filter: classifies inbound Ethernet frames on a
single network interface by source MAC. Frames whose source MAC is in a
runtime-supplied allow-list are passed up the stack (`XDP_PASS`); all
others — including malformed frames shorter than a valid Ethernet header —
are dropped (`XDP_DROP`). Three BPF counters (`pass`, `drop_deny`,
`drop_malformed`) are exposed via a pinned BPF map under
`/sys/fs/bpf/xdpmacfilter/<iface>/stats` and read out-of-band with
`bpftool map dump`.

The userspace control plane is a C++23 CLI tool (`xdpmacfilter`) that
loads the BPF object, populates the allow-list, attaches the program to
the named interface (generic XDP / SKB mode), and exits while leaving the
XDP program attached. No daemon, no hot reload, no JSON, no metrics
endpoint, no multi-iface, no L3+. One vertical slice end-to-end.

## Prerequisites

- Linux x86_64, kernel ≥ 5.15 (for the BPF features used).
- root or `CAP_BPF + CAP_NET_ADMIN` to attach XDP and pin maps.

Apt install line (Debian/Ubuntu) covering build, BPF tooling, and the
ctest fixture:

```sh
sudo apt install -y \
    clang-19 libc++-19-dev \
    libbpf-dev libelf-dev bpftool \
    cmake make pkg-config \
    iproute2 sudo \
    python3 python3-scapy jq
```

`libbpf-dev` must provide libbpf ≥ 1.1 (`pkg-config --modversion libbpf`).
`libc++-19-dev` is required because the loader uses `<format>` from
C++23, which `libstdc++-12` (Debian default) does not ship — see
`mint/impl-notes.md` for the deviation log.

## Build

Out-of-source build, no extra configure flags:

```sh
cmake -S . -B build
cmake --build build -j"$(nproc)"
```

Result: `build/xdpmacfilter` (loader binary), `build/mac_filter.bpf.o`
(BPF object), `build/mac_filter.skel.h` (generated skeleton header). Zero
warnings expected under `-Werror`; a warning is a build failure.

Optional sanitizer build (ASAN + UBSAN, test-only, **not** for release):

```sh
cmake -S . -B build-asan -DXDPMF_SANITIZERS=ON
cmake --build build-asan -j"$(nproc)"
```

The sanitizer flags are scoped to the C++ loader only — the BPF object is
built unmodified (`clang -target bpf` has no userspace ASAN runtime).

## Run

```sh
sudo build/xdpmacfilter attach --iface <IFNAME> --allow <MAC>[,<MAC>...]
sudo build/xdpmacfilter detach --iface <IFNAME>
sudo build/xdpmacfilter --help
```

`<MAC>` is colon-separated hex (`XX:XX:XX:XX:XX:XX`). Up to 64 unique
MACs. Empty allow-list is valid → drops everything.

Inspect counters while attached:

```sh
sudo bpftool map dump pinned /sys/fs/bpf/xdpmacfilter/<IFNAME>/stats
```

Exit codes: `0` ok · `1` CLI usage · `2` BPF load · `3` XDP attach · `4`
foreign XDP program already on iface (refuses to clobber — see design
§5.4) · `5` detach failed · `6` permission denied.

## Production deployment

The repo ships a systemd template unit and an example Ansible playbook
for fleet rollout. The template unit `systemd/xdpmacfilter@.service` is
template-instanced (`%i` = iface), runs as `Type=oneshot RemainAfterExit=yes`,
and treats `systemctl reload` as a Composite-6 atomic hot-swap via
`bpf_link__update_program` (no drop window). `cmake --install` drops it
into `${CMAKE_INSTALL_PREFIX}/lib/systemd/system/` (gated on the default-ON
`XDPMF_INSTALL_SYSTEMD_UNIT` option).

The example playbook `ansible/xdpmacfilter-deploy.yml` + Jinja2 config
template `ansible/templates/xdpfilter-config.yaml.j2` are a minimal
reference, not a full role/collection — operators adapt to their fleet.

Operator docs for `XDPMF_TRUST_MODEL=fleet` (strict-vs-fleet decision
matrix, audit-log story, Drop-In recipe, Prometheus alert semantic, and
the §5.4/§5.19/§5.22/§5.24 fence callout) live in
`docs/FLEET_DEPLOYMENT.md`.

## Test

The ctest suite drives a veth pair fixture and needs root (for BPF
attach, pin, packet inject):

```sh
sudo -E ctest --test-dir build --output-on-failure
```

The `T_DROP_MALFORMED` entry may report `Skipped` on kernels that pad
short Ethernet frames before XDP sees them — that's expected.
`T_NEGATION_CONTROL` deliberately asserts a wrong value: ctest's
`WILL_FAIL` flips the expected-failure into a green result.

## Where docs live

| File | Purpose |
|---|---|
| `mint/task-brief-mvp1.md` | Original MVP-1 brief (constraints, acceptance) |
| `mint/task-brief.md` | Current pass brief (MVP-1.1A refactor) |
| `mint/design.md` | Single source of truth: data structures, interfaces, decisions, test strategy |
| `mint/review.md` | mint-reviewer triangulation report (MVP-1) |
| `mint/hybrid-review.md` | 5-dimension external review (input for MVP-1.1A) |
| `mint/impl-notes.md` | Implementation deviations log |
