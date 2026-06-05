# Config schema reference — xdpfilter

The `apply` subcommand loads a YAML config file driving the full 9-axis
rule model:

```sh
sudo xdpfilter apply --iface eth0 -f /etc/xdpfilter/eth0.yaml
```

This is the authoritative reference for that file. Source of truth:
`src/lib/config.hpp` (types) and `src/lib/config.cpp` (validation). All
validation failures throw a config error and exit **9**, with a stderr
message starting `xdpfilter: config error: ...` naming the offending
field, line, and column. Max file size: 1 MiB.

## Top-level structure

```yaml
schema_version: 3          # REQUIRED, must be 2 or 3 (3 enables steering)
interface: eth0            # optional (redundant with --iface)
default_action: drop       # REQUIRED: drop | pass
rules:                     # optional list of rule mappings
  - id: 0
    action: pass
    match:
      src_cidr: "10.0.0.0/8"
steering:                  # optional; REQUIRED iff any rule uses action: redirect
  redirect_to: dpi0        # single global DPI-feed interface (the tap)
```

| Key | Required | Type / values | Notes |
|---|---|---|---|
| `schema_version` | **yes** | integer, `2` or `3` | v1 is retired — absent or `1` both error. `3` enables the `steering:` block (§5.75); a steering-less `2` config still validates (additive). |
| `interface` | no | string | Redundant with `--iface`; informational. |
| `default_action` | **yes** | `drop` \| `pass` | Verdict for frames matching no rule. |
| `rules` | no | list of rule mappings | Absent/empty ⇒ every frame gets `default_action`. |
| `steering` | no¹ | mapping `{ redirect_to: <iface> }` | The single global redirect tap. ¹**Required** if any rule has `action: redirect`. Only `redirect_to` is accepted (any other sub-key errors). |

## Rule mapping

```yaml
- id: 0                    # REQUIRED, any u32 except 4294967295 (reserved)
  action: pass             # REQUIRED: pass | drop
  match:                   # REQUIRED mapping; at least one axis below
    protocol: tcp
    dst_port: "443"
```

| Key | Required | Type / values | Notes |
|---|---|---|---|
| `id` | **yes** | any u32 except `4294967295` (`0xFFFFFFFF`, reserved sentinel) | Sparse, operator-assigned. First-match-by-`id` (lowest wins); also the stable counter key (Prometheus `rule_id`). Need not be dense or zero-based — `id: 100` is valid. Duplicate ids rejected. The **rule count** (not the id value) is capped at 64. |
| `action` | **yes** | `pass` \| `drop` \| `redirect` | Verdict when this rule matches. `redirect` (§5.75) steers the frame out the `steering.redirect_to` tap via `bpf_redirect_map`; degrades to the original flow (pass) if the tap is missing/down. Requires a top-level `steering:` block. |
| `match` | **yes** | mapping | Must contain **at least one** of the 9 axes below. An unknown key in `match` is an error. |

## Match axes (9)

A rule's `match` is the **AND** of every axis it specifies — a frame
matches the rule only if it satisfies *all* listed axes. An axis left out
is a wildcard (matches anything). At least one axis is required per rule.

| Axis | Example | Grammar |
|---|---|---|
| `mac` | `"AA:BB:CC:DD:EE:FF"` | Source MAC, exact. 17-char colon-separated hex (`XX:XX:XX:XX:XX:XX`). Family-blind (fires on IPv4/IPv6/non-IP). |
| `dst_cidr` | `"10.0.0.0/8"` | Destination IPv4 CIDR, longest-prefix. Dotted-decimal `A.B.C.D/len`, `len ∈ [0,32]`. |
| `src_cidr` | `"192.168.1.0/24"` | Source IPv4 CIDR, longest-prefix. Same grammar as `dst_cidr`. |
| `dst_cidr6` | `"2001:db8::/32"` | Destination IPv6 CIDR, longest-prefix. `len ∈ [0,128]`. |
| `src_cidr6` | `"fe80::/10"` | Source IPv6 CIDR, longest-prefix. Same grammar as `dst_cidr6`. |
| `protocol` | `tcp` / `17` | L4 protocol, exact (matches the IP `protocol`/`nexthdr` byte). Name `tcp`(6) / `udp`(17) / `icmp`(1), or a numeric IP-protocol number in `[0,255]`. ⚠️ `icmp` is **ICMPv4 (1) only** — there is no `icmp6` alias; to match ICMPv6 in the IPv6 arm use the numeric value `58`. |
| `dst_port` | `"443"` / `"8000-8080"` | L4 destination port, inclusive range. Single integer in `[0,65535]`, or `"lo-hi"` with `lo ≤ hi`. |
| `vlan` | `100` | Outer 802.1Q VLAN VID, exact. Integer in `[0,4095]`. (Lists/ranges are out of scope — use multiple rules.) |
| `ethertype` | `arp` / `0x88b5` | Inner (post-VLAN) EtherType, exact. Name `ipv4`(0x0800) / `ipv6`(0x86dd) / `arp`(0x0806), a hex literal `0x…`, or a number in `[0,65535]`. |

### Notes on the family arms

The classifier evaluates three family arms — IPv4, IPv6, and non-IP —
and composes the axes within each. L3/L4 axes (`dst_cidr`, `protocol`,
`dst_port`, …) are only meaningful in their family arm; for IPv6, the
classifier walks extension headers to read the true L4 header before
reading `protocol`/`dst_port`. `mac`, `vlan`, and `ethertype` are
family-blind and fire across all arms.

## Steering: `redirect` (schema_version 3)

A rule with `action: redirect` actively diverts matched traffic out a single
global DPI-feed interface — the **tap** — using XDP-native `bpf_redirect_map`.
This is the first *steering* verb (the filter becomes a selector, not just a
terminal allow/drop). The tap is configured once at the top level:

```yaml
schema_version: 3
default_action: pass
rules:
  - id: 0
    action: redirect          # steer this traffic to the DPI feed
    match:
      dst_cidr: "203.0.113.0/24"
steering:
  redirect_to: dpi0           # the single global tap interface
```

- **Single global tap.** All `redirect` rules steer to the same
  `steering.redirect_to` interface — there is no per-rule target (that is a
  future Option-2 superset, out of scope).
- **Validation.** Any `action: redirect` rule **requires** a top-level
  `steering.redirect_to` (else config error, exit 9). `steering:` accepts only
  `redirect_to`; any other sub-key errors. An unresolvable target interface
  fails closed at `apply` time.
- **Miss behaviour.** If the tap is missing/down at runtime, the redirect
  degrades to the original flow (`XDP_PASS`) rather than blackholing.
- **Mirror (clone-and-continue) is NOT this verb** — redirect is terminal
  (XOR with pass/drop); mirror is deferred (needs a TC/TCX program).

## Full example

```yaml
schema_version: 3
interface: eth0
default_action: drop
rules:
  # Admit SSH from the management subnet.
  - id: 0
    action: pass
    match:
      src_cidr: "10.10.0.0/16"
      protocol: tcp
      dst_port: "22"

  # Steer flagged subnet traffic to the DPI feed.
  - id: 4
    action: redirect
    match:
      dst_cidr: "198.51.100.0/24"

  # Admit HTTPS to the service VIP range.
  - id: 1
    action: pass
    match:
      dst_cidr: "203.0.113.0/24"
      protocol: tcp
      dst_port: "443"

  # Steer all ARP for coarse non-IP handling.
  - id: 2
    action: pass
    match:
      ethertype: arp

  # Admit an IPv6 prefix on a tagged VLAN.
  - id: 3
    action: pass
    match:
      vlan: 100
      dst_cidr6: "2001:db8::/32"

steering:
  redirect_to: dpi0          # required because rule id 4 uses action: redirect
```

## Operational notes

- **`apply` is a hot-swap.** Re-running `apply` on an attached iface swaps
  the rule set atomically via `bpf_link__update_program` — no drop window.
- **Counter continuity.** The Prometheus per-rule series are keyed on the
  operator `id` (the exporter recovers it from the internal slot), so
  renumbering or inserting a rule preserves each rule's
  `xdpfilter_rule_match_total{rule_id=...}` series.
- **`reset-counters --rule-id <N>` takes a slot, not an `id`.** The kernel
  counter array is indexed by internal **slot** (the `id`-sorted rank,
  `[0, 63]`), so `--rule-id <N>` zeroes slot `N` — it does **not** look up
  the operator `id` / Prometheus `rule_id`. Omit the flag to zero all slots.
- **Ansible.** The example `ansible/templates/xdpfilter-config.yaml.j2`
  renders this schema from a `xdpfilter_rules` list (see
  `docs/FLEET_DEPLOYMENT.md`).
