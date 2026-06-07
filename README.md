# xdpfilter — L2/L3 XDP traffic filter

## What it does

`xdpfilter` is a Linux XDP packet filter for L2/L3 traffic selection.
It classifies inbound Ethernet frames on a network interface against a
runtime-supplied rule set and renders a per-frame verdict (`XDP_PASS` /
`XDP_DROP` / `XDP_REDIRECT`). It is designed as a pre-filter that
**selects and steers** traffic for downstream processing, not only as a
terminal allow/drop gate.

The match model is **9 AND-composed axes**, evaluated as a bit-vector
classifier across three family arms (IPv4 / IPv6 / non-IP):

| Axis | Match kind | Config key |
|---|---|---|
| Source MAC | exact | `mac` |
| Destination IPv4 CIDR | longest-prefix | `dst_cidr` |
| Source IPv4 CIDR | longest-prefix | `src_cidr` |
| Destination IPv6 CIDR | longest-prefix | `dst_cidr6` |
| Source IPv6 CIDR | longest-prefix | `src_cidr6` |
| L4 protocol | exact | `protocol` |
| L4 destination port | inclusive range | `dst_port` |
| Outer 802.1Q VLAN VID | exact | `vlan` |
| Inner EtherType | exact | `ethertype` |

Rules are evaluated first-match-by-`id`; each rule carries an `action`
(`pass` / `drop` / `redirect`); a `default_action` covers frames matching
no rule. A `redirect` rule steers matched traffic to one operator-configured
DPI-feed interface via a top-level `steering: { redirect_to: <iface> }` block
(`schema_version: 3`). IPv6 matching walks extension headers to read the true
L4 header.

Counters are exposed two ways: a per-iface BPF stats map (read out-of-band
with `bpftool map dump`) and a Prometheus `/metrics` endpoint served by the
`xdpmf-exporter` daemon. JSON structured logging, multi-iface deployment
via a systemd template unit, and an example Ansible playbook are shipped.

> Full schema reference: [`docs/CONFIG_SCHEMA.md`](docs/CONFIG_SCHEMA.md).
> Fleet/operator guide: [`docs/FLEET_DEPLOYMENT.md`](docs/FLEET_DEPLOYMENT.md).

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
    python3 python3-scapy jq \
    ansible
```

`libbpf-dev` must provide libbpf ≥ 1.1 (`pkg-config --modversion libbpf`).
`libc++-19-dev` is required because the loader uses `<format>` from
C++23, which `libstdc++-12` (Debian default) does not ship — see
`mint/impl-notes.md` for the deviation log. `ansible` is optional — it only
gates the `T_ANSIBLE_PLAYBOOK_SYNTAX` ctest (skipped silently if absent).

## Build

Out-of-source build, no extra configure flags:

```sh
cmake -S . -B build
cmake --build build -j"$(nproc)"
```

Result: `build/xdpfilter` (loader binary), `build/xdpmf-exporter`
(Prometheus exporter daemon), `build/xdpfilter.bpf.o` (BPF object),
`build/xdpfilter.skel.h` (generated skeleton header). Zero warnings
expected under `-Werror`; a warning is a build failure.

### CMake options

| Option | Default | Purpose |
|---|---|---|
| `BUILD_TESTING` | `ON` | Build the ctest tree (CTest convention). |
| `XDPMF_SANITIZERS` | `OFF` | Build the C++ loader with ASAN+UBSAN (test-only; scoped to the loader, never the BPF object). |
| `XDPMF_INSTALL_SYSTEMD_UNIT` | `ON` | Install the systemd template unit + `FLEET_DEPLOYMENT.md` on `cmake --install`. |
| `XDPMF_ENABLE_BPF_OBJECT_OVERRIDE` | `OFF` | Allow the loader to honor `XDPMF_BPF_OBJECT_PATH` (testing-only; release builds strip the env lookup entirely). |

Optional sanitizer build (ASAN + UBSAN, test-only, **not** for release):

```sh
cmake -S . -B build-asan -DXDPMF_SANITIZERS=ON
cmake --build build-asan -j"$(nproc)"
```

The sanitizer flags are scoped to the C++ loader only — the BPF object is
built unmodified (`clang -target bpf` has no userspace ASAN runtime).

## Run

### Loader CLI (`xdpfilter`)

```sh
sudo build/xdpfilter attach --iface <IFNAME> [--allow <MAC>[,<MAC>...] ...] [--mode <M>]
sudo build/xdpfilter detach --iface <IFNAME>
sudo build/xdpfilter apply  --iface <IFNAME> -f <PATH> [--mode <M>] [--dry-run [--format human|golden]]
sudo build/xdpfilter bypass --iface <IFNAME> [--unsafe] [--reason "<text>"]
sudo build/xdpfilter reset-counters --iface <IFNAME> [--rule-id <N>]
sudo build/xdpfilter --help | --version
```

- **`attach`** — load + attach with an inline source-MAC allow-list. `<MAC>`
  is colon-separated hex (`XX:XX:XX:XX:XX:XX`), up to 64 unique. An empty
  allow-list is valid → drops everything.
- **`apply`** — load + attach (or hot-swap, no drop window) from a YAML
  config file driving the full 9-axis rule model. Schema version 2 or 3
  (3 enables the `steering:` redirect block); max 1 MiB. See
  [`docs/CONFIG_SCHEMA.md`](docs/CONFIG_SCHEMA.md). With `--dry-run` the
  resulting rules are rendered offline and the command exits **without
  touching the kernel** — default is a human-decoded per-rule view;
  `--format=golden` emits the byte-faithful `# xdpfilter-image v1` machine
  image instead.
- **`bypass`** — temporarily pass-all (`--unsafe` required non-interactively;
  `--reason` is audit-logged).
- **`reset-counters`** — zero all rule counters, or a single slot with
  `--rule-id <N>`. ⚠️ Despite the flag name, `<N>` is the internal **slot
  index** (`id`-sorted rank, range `[0, 63]`) — **not** the operator-assigned
  rule `id` nor the Prometheus `rule_id` label. To zero a specific rule,
  pass its rank among the sorted ids, or just omit the flag to zero all.
- **`--mode {generic|native|offload}`** — XDP attach mode (attach/apply
  only; default `generic`/SKB). `native` (driver XDP) is the perf-correct
  mode where the driver supports it; `detach` auto-detects.

### Prometheus exporter (`xdpmf-exporter`)

A read-only daemon that scans the bpffs root for per-iface stats pins and
serves them as Prometheus text:

```sh
sudo build/xdpmf-exporter [--port 9417] [--bind 127.0.0.1] [--bpffs-root <path>]
```

- `GET /metrics` — counter families `xdpfilter_packets_total`,
  `xdpfilter_rule_match_total`, and the `xdpfilter_rule_info` constant gauge
  (per-rule 9-axis constraints as labels).
- `GET /healthz` — liveness probe.
- Defaults to loopback (`127.0.0.1`); a non-loopback `--bind` emits a WARN.

### Inspect counters directly

```sh
sudo bpftool map dump pinned /sys/fs/bpf/xdpfilter/<IFNAME>/stats
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | CLI usage error |
| 2 | BPF load failed |
| 3 | XDP attach failed |
| 4 | Foreign XDP program already on iface (refuses to clobber — see design §5.4; relaxed by `XDPMF_TRUST_MODEL=fleet`) |
| 5 | Detach failed |
| 6 | Permission denied |
| 7 | Kernel unsupported (< 5.15) |
| 8 | Path refused (bpffs root symlink / O_PATH discipline) |
| 9 | Config error (bad YAML, bad schema, or `XDPMF_TRUST_MODEL=banana`) |

### Environment variables

| Variable | Values | Consumed by | Effect |
|---|---|---|---|
| `XDPMF_TRUST_MODEL` | `strict` (default) / `fleet` | loader | `fleet` relaxes only the §5.4 alien-program refusal; all other identity gates hold. Garbage → exit 9. See `docs/FLEET_DEPLOYMENT.md`. |
| `XDPMF_LOG_FORMAT` | `text` (default) / `json` | loader + exporter | Selects log line format; `json` suits Loki/Splunk/ELK pipelines. Unknown value → WARN + text fallback. |
| `XDPMF_BPFFS_ROOT` | path | exporter | Default bpffs root scanned for stats pins (default `/sys/fs/bpf/xdpfilter`); overridden by `--bpffs-root`. |

## Production deployment

The repo ships a systemd template unit and an example Ansible playbook
for fleet rollout. The template unit `systemd/xdpfilter@.service` is
template-instanced (`%i` = iface), runs as `Type=oneshot RemainAfterExit=yes`,
and treats `systemctl reload` as an atomic hot-swap via
`bpf_link__update_program` (no drop window). `cmake --install` drops it
into `${CMAKE_INSTALL_PREFIX}/lib/systemd/system/` (gated on the default-ON
`XDPMF_INSTALL_SYSTEMD_UNIT` option), and installs `FLEET_DEPLOYMENT.md`
alongside it at `${PREFIX}/share/doc/xdpfilter/` (the `Documentation=`
URI the units advertise).

The example playbook `ansible/xdpfilter-deploy.yml` + Jinja2 config
template `ansible/templates/xdpfilter-config.yaml.j2` are a minimal
reference, not a full role/collection — operators adapt to their fleet.

The full operator guide — `XDPMF_TRUST_MODEL` decision matrix, audit-log
story, systemd Drop-In recipe, Prometheus alert semantics, and the loader
env-var reference — lives in [`docs/FLEET_DEPLOYMENT.md`](docs/FLEET_DEPLOYMENT.md).

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
`T_ANSIBLE_PLAYBOOK_SYNTAX` skips if `ansible-playbook` is not installed.

## Where docs live

**Operator docs:**

| File | Purpose |
|---|---|
| `README.md` | This file — overview, build, run, exit codes, env vars |
| `docs/CONFIG_SCHEMA.md` | YAML config schema reference (schema_version 2/3, 9 axes) |
| `docs/FLEET_DEPLOYMENT.md` | Fleet rollout: trust model, systemd, Prometheus, audit |

**Contributor docs:**

| File | Purpose |
|---|---|
| `mint/README.md` | Index + reading order for the `mint/` design corpus |
| `mint/design.md` | Single source of truth: data structures, interfaces, decisions, test strategy |
| `mint/architecture-v2.md` | Architecture overview |
| `mint/task-brief.md` | Current pass brief (latest active MVP slice) |
| `docs/BACKLOG.md` | Documentation + test-infra backlog |
| `CHANGELOG.md` | Per-version change log |
| `docs/history/HANDOFF-mvp1.md` | Archived MVP-1 session handoff (historical) |
