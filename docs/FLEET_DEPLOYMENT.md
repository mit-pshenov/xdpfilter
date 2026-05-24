# Fleet deployment guide — xdpmacfilter

Operator docs for running `xdpmacfilter` across a Linux host fleet via the
shipped systemd template unit and the example Ansible playbook. Covers the
**`XDPMF_TRUST_MODEL`** decision matrix, the audit story, and the
Prometheus alert semantic. Scope: enough to make a fleet rollout sane;
**not** a turnkey production recipe (operators adapt to their inventory,
secrets, packaging, multi-iface variations).

See also: `systemd/xdpmacfilter@.service`, `ansible/xdpmacfilter-deploy.yml`,
`mint/design.md §5.26` (config harness), `mint/design.md §5.27` (CIDR axis).

## Decision matrix: `XDPMF_TRUST_MODEL=strict` vs `XDPMF_TRUST_MODEL=fleet`

The loader has two trust postures, selected by the **`XDPMF_TRUST_MODEL`**
environment variable. **Default is `strict`** (secure-by-default — see
design §5.4 / §5.19 / §5.22 / §5.24).

| Posture | When to use | What it relaxes | What it preserves |
|---|---|---|---|
| **`strict` (default)** | Hosts where a foreign XDP program on the iface is, by policy, a hard incident. Lone-tenant boxes, single-purpose appliances, anything operator-owned end-to-end. | Nothing. Foreign XDP attached → loader exits 4 (`alien program`) and refuses to touch the iface. | All four identity gates: §5.4 alien-program refusal, §5.19 name-check, §5.22 tag-check + O_PATH path-discipline, §5.24 kernel-version probe. |
| **`fleet`** | Operator-managed fleets where another sanctioned XDP program (e.g. an L4 load-balancer's eBPF firewall) may legitimately be on the iface, and the operator has out-of-band knowledge that displacing it is intended. Trusted-segment networks. | **Only** §5.4 alien-program disposition: the loader detaches the alien and proceeds. | §5.19 (name-check), §5.22 (tag-check + O_PATH), §5.24 (kernel-version probe) — **all four** of PI-2..PI-5 hold in BOTH postures. Fleet is NOT a "disable security gates" switch. |

If you're not sure, **leave it at `strict`** and add `fleet` per-host once
a real conflict surfaces. The fleet posture exists for the
operator-managed-fleet case, not as a quieter default.

## Audit story

Every `attach` and `apply` invocation emits a single line to stderr (and
therefore to the systemd journal when run via the shipped unit):

```
xdpmacfilter: trust_model=<strict|fleet>
```

This is the **exact verbatim stderr-log prefix** — grep it directly:

```sh
journalctl -u xdpmacfilter@eth0.service | grep -E '^xdpmacfilter: trust_model='
```

Concrete examples — copy-pasteable greps the audit pipeline can use:

```
xdpmacfilter: trust_model=strict
xdpmacfilter: trust_model=fleet
```

The line is emitted **before** any libbpf call, so even a load failure
leaves the trust-model posture on record. There is no `--quiet` flag
(see design D-3.3-1 — secure-by-default also means audit-by-default).

## Setting the trust model via systemd Drop-In

The shipped unit deliberately does **not** bake in an
`Environment=XDPMF_TRUST_MODEL=...` line (D-3.3-2 — secure-by-default
default = strict). Operators opt into `fleet` per-host via a Drop-In file:

Create `/etc/systemd/system/xdpmacfilter@.service.d/trust-model.conf`:

```ini
[Service]
Environment=XDPMF_TRUST_MODEL=fleet
```

Then:

```sh
sudo systemctl daemon-reload
sudo systemctl restart xdpmacfilter@eth0.service
journalctl -u xdpmacfilter@eth0.service | grep '^xdpmacfilter: trust_model='
# expect: xdpmacfilter: trust_model=fleet
```

Garbage values (`XDPMF_TRUST_MODEL=banana`) fail closed — the loader
exits 9 (`ConfigError`) at attach/apply entry. No silent fallback.

## Fleet-wide alert semantic (Prometheus pattern)

A homogeneous fleet should have a **uniform** trust-model distribution.
Divergence — one host on `fleet` when policy says everyone is on
`strict`, or vice versa — is the audit signal you want to alert on.

The alert **semantic** (label cardinality = number of distinct
trust-model values observed across the fleet):

```
ALERT XDPMacFilterTrustModelDivergence
  IF count(count by (trust_model) (xdpmacfilter_trust_model)) > 1
  FOR 5m
  LABELS { severity = "warning" }
  ANNOTATIONS {
    summary = "xdpmacfilter trust_model differs across the fleet"
    description = "Fleet-wide trust_model distribution is no longer uniform — investigate."
  }
```

The `xdpmacfilter_trust_model` time series is **not yet shipped** —
exporter implementation is the MVP-3.4 slice (per-rule counters +
`xdpmf-exporter` binary). Until then, scrape the journal directly:

```sh
ansible all -m shell -a "journalctl -u 'xdpmacfilter@*.service' --since '-1h' \
    | grep -oE 'trust_model=(strict|fleet)' | sort -u"
```

— if the aggregated set has more than one element, you have divergence.

## Fence callout — what `fleet` does NOT relax

`XDPMF_TRUST_MODEL=fleet` relaxes **only** §5.4 (alien-program disposition
— detach and proceed instead of refuse). It does **not** relax:

- **§5.19** name-check (PI-2): the loader still demands `bpf_prog_info.name`
  matches `mac_filter_prog`. A planted prog with the wrong name → refused.
- **§5.22 Item 1** tag-check (PI-3): the loader still demands the
  kernel-computed `bpf_prog_info.tag` (SHA-1 of the post-libbpf bytecode)
  matches the self-tag captured at load time. A recompiled-with-altered-bytecode
  prog under the same name → refused.
- **§5.22 Item 2** O_PATH path-discipline (PI-4): the loader still opens
  the bpffs root with `O_PATH | O_DIRECTORY | O_NOFOLLOW` and uses
  `*at()` syscalls throughout. Symlink at bpffs root → exit 8.
- **§5.24** kernel-version probe (PI-5): the loader still refuses on
  kernels older than 5.15 with a clear stderr message.

All four PI-2..PI-5 invariants hold in **both** strict and fleet
postures. `fleet` is a **single-axis** relaxation, not a security mode
selector.

## Quick operator checklist

1. Decide trust-model posture per host (matrix above). Default to `strict`.
2. Install `/usr/bin/xdpmacfilter` (build via `cmake --install` from this
   repo, or via your distro packager).
3. Install the unit: `sudo install -D -m 0644 systemd/xdpmacfilter@.service \
   /etc/systemd/system/xdpmacfilter@.service`. (The CMake build does this
   for you when `XDPMF_INSTALL_SYSTEMD_UNIT=ON` — default ON.)
4. Write per-iface config to `/etc/xdpfilter/<iface>.yaml`
   (`schema_version: 1` — see design §5.26 / §5.27 for the schema).
5. If `fleet` posture: drop in the Drop-In file shown above.
6. `sudo systemctl daemon-reload && sudo systemctl enable --now xdpmacfilter@<iface>.service`
7. Verify: `journalctl -u xdpmacfilter@<iface>.service | grep '^xdpmacfilter: trust_model='`
   matches the intended posture.
8. Add the fleet-wide divergence alert (above) to your monitoring once
   the MVP-3.4 exporter lands.
