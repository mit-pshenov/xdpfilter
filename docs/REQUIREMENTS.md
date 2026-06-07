# Requirements — line-rate L2/L3 GGSN–Gi traffic filter

> **Source-of-truth product spec.** Provided by the product owner 2026-05-28. This is the canonical statement of what the tool is meant to be. The codebase implements the *harness* around filtering (config, atomic hot-reload, fleet deploy, observability) plus the **full 9-axis AND-composed match model** (MAC / VLAN / EtherType / IPv4+IPv6 src+dst CIDR / L4 protocol / L4 port) across three family arms, with `pass` / `drop` / `redirect` actions. The genuine forward gap is now the **high-performance datapath** (DPDK / AF_XDP) and its perf validation (IXIA / TRex), plus mirror / rate-limit / tag actions and watchdog/hot-standby. See "Implementation status & strategy" at the end (refreshed 2026-06-07).

## Statement

We need to deploy a line-rate L2 traffic filtering layer on all 40 Gbps GGSN–Gi interfaces to gain fine-grained control, visibility, and protection at the packet level without introducing noticeable latency or impacting throughput.

## Purpose

To control and monitor raw network traffic directly on the Gi side — before it reaches higher layers — ensuring clean separation between trusted and untrusted segments, compliance with routing policy, and early mitigation of anomalous traffic.

## Scope

- Operates exclusively at Layer 2 / Layer 3 (Ethernet, VLAN, IPv4/IPv6)
- No DPI, protocol dissection, or L7 filtering
- Inline or mirror mode depending on site configuration
- Compatible with both DPDK and AF_XDP packet paths

## Performance & Reliability Targets

- Throughput: sustained 40 Gbps per site (bidirectional)
- Latency overhead: ≤ 500 µs added per packet
- Packet loss: < 0.01 % under peak load
- Failover: hot-standby or bypass mode in case of failure

## Functional Requirements

- Configurable rule hierarchy:
  - **L2**: interface, VLAN ID, MAC, EtherType
  - **L3**: source/destination IP, subnet, routing domain
  - **L4**: optional port-based matching for basic flow classification (no payload parsing)
- **Actions**: allow, drop, mirror, rate-limit, tag, or redirect
- Config source: central YAML/JSON rule file, reloadable at runtime (no restart)
- Sync: per-site configuration sync via control plane; optional push from NOC
- Observability: per-rule counters (pps/bps/drops), Prometheus metrics, sFlow export, structured logs
- Safety: watchdog monitoring of worker health; automatic restart and alert on failure

## Initial Tasks

1. **Architecture design**: per-core worker model pinned to NIC queues; zero-copy packet flow (DPDK or AF_XDP).
2. **Config engine**: define schema for hierarchical rules (interface → IP range → action).
3. **Control plane**: lightweight management service for rule updates and telemetry collection.
4. **Metrics & logging**: expose counters per rule and per interface; integrate with Prometheus and Grafana.
5. **Fail-safe mode**: ensure bypass or mirror mode if worker fails; validate watchdog recovery.
6. **Testing**: synthetic 40 Gbps load (IXIA or TRex) to validate throughput, latency, and drop rate.

## Expected Outcome

A stable, high-performance L2 filtering layer operating transparently between GGSN and Gi, providing:

- Configurable control at Ethernet/IP level
- Centralized rule management and observability
- Deterministic performance at 40 Gbps
- Safe failure behavior and operational visibility

---

## Implementation status & strategy (2026-05-28; status refreshed 2026-06-07)

**Strategy**: prototype and validate the *model* — rule hierarchy, config schema, statistics semantics, action semantics — on **eBPF/XDP** (fast to iterate, runs in the existing netns test harness). Defer the high-performance datapath (DPDK or AF_XDP, per-core workers pinned to NIC queues, zero-copy) and the perf-validation (IXIA/TRex, 40 Gbps / ≤500 µs / <0.01 % loss) to a **later phase**. eBPF validates *function + model + UX*, not the perf numbers — those require the real datapath. The management/config/stats layer is kept decoupled from the enforcement mechanism so the eventual datapath swap (the spec requires *both* DPDK and AF_XDP compatibility) reuses it.

**Built today (harness + observability + ops):**

- YAML config + atomic hot-reload (`apply -f`, ARRAY_OF_MAPS atomic swap)
- Fleet sync via Ansible push (the "control plane" as config-push)
- Prometheus `/metrics` + per-rule counters; `xdpmf-exporter` binary
- Structured JSON logs (`XDPMF_LOG_FORMAT={text,json}`)
- Manual bypass primitive (partial fail-safe)
- Security hardening (path-traversal / symlink defenses, log-injection escaping)

**Match model & actions — SHIPPED (9-axis AND-composed, 3 family arms):**

| Spec axis | Status |
|---|---|
| L2: interface | ✅ per-interface attach |
| L2: MAC | ✅ `mac` (family-blind: IPv4 / IPv6 / non-IP) |
| L2: VLAN ID | ✅ `vlan` (outer 802.1Q VID) |
| L2: EtherType | ✅ `ethertype` |
| L3: **source** IP/subnet | ✅ `src_cidr` (IPv4) + `src_cidr6` (IPv6), LPM_TRIE |
| L3: **destination** IP/subnet | ✅ `dst_cidr` (IPv4) + `dst_cidr6` (IPv6), LPM_TRIE |
| L3: IPv6 | ✅ full extension-header walk to the true L4 header |
| L3: routing domain | ❌ not a modeled concept |
| L4: port-based | ✅ `dst_port` (inclusive range) |
| Actions: allow, drop | ✅ |
| Actions: redirect | ✅ `action: redirect` + `steering: { redirect_to }` (Option-1 single global DPI tap, schema_version 3) |
| Actions: mirror, rate-limit, tag | ❌ not implemented (mirror needs TC/TCX; per-rule targets are Option-2) |
| Operator preview | ✅ `apply --dry-run [--format human\|golden]` (offline render, zero kernel touch) |
| Perf datapath (DPDK/AF_XDP, 40 G) | ❌ eBPF/XDP (intentional — model-validation vehicle) |
| Perf validation (IXIA/TRex) | ❌ functional netns tests only |
| Safety: watchdog / hot-standby | ⚠️ bypass primitive only |

**Next (forward target)**: the rule model + operator UX are validated on eBPF; the remaining arc is the **high-performance datapath** (DPDK or AF_XDP, per-core workers pinned to NIC queues, zero-copy) and its perf validation (IXIA/TRex: 40 Gbps / ≤500 µs / <0.01 % loss), plus the richer action set (mirror / rate-limit / tag) and watchdog/hot-standby. These need design passes first; the management/config/stats layer is already decoupled so the eventual datapath swap reuses it.
