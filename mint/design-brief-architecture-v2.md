# Design Brief — `xdpmacfilter` v2 architecture (MVP-3 roadmap)

## Topic

Map the full requirements for a production-grade line-rate L2/L3 packet filter (deployed on 40 Gbps GGSN-Gi interfaces) onto a concrete component decomposition + phased mint roadmap. Current `xdpmacfilter` (MVP-2 closed) is one foundation stone of the destination — this round defines what the full system looks like and how we get there from MVP-3.1 through MVP-3.N.

## Motivating requirements (from product owner)

> We need to deploy a line-rate L2 traffic filtering layer on all 40 Gbps GGSN–Gi interfaces to gain fine-grained control, visibility, and protection at the packet level without introducing noticeable latency or impacting throughput.

**Purpose**: control + monitor raw network traffic on Gi side, before higher layers; clean separation between trusted and untrusted segments; compliance with routing policy; early mitigation of anomalous traffic.

**Scope**:
- L2/L3 only (Ethernet, VLAN, IPv4/IPv6) + optional L4 port for flow classification
- No DPI, no protocol dissection, no L7
- Inline or mirror mode (depends on site)
- Compatible with both DPDK and AF_XDP paths

**Performance & reliability**:
- 40 Gbps per site (bidirectional, sustained)
- ≤ 500 µs added latency per packet
- < 0.01 % drop under peak load
- HA: hot-standby OR bypass mode on failure

**Functional**:
- Hierarchical rule config:
  - L2: interface, VLAN ID, MAC, EtherType
  - L3: src/dst IP, subnet, routing domain
  - L4: optional port matching (no payload parsing)
- Actions: allow, drop, mirror, rate-limit, tag, redirect
- Config: central YAML/JSON, hot-reloadable (no restart)
- Sync: per-site sync via control plane; optional push from NOC
- Observability: per-rule counters (pps/bps/drops), Prometheus, sFlow, structured logs
- Safety: worker watchdog, auto-restart, alert on failure

**Initial tasks per product owner**:
1. Architecture: per-core worker model pinned to NIC queues; zero-copy packet flow (DPDK or AF_XDP)
2. Config engine: hierarchical schema (interface → IP range → action)
3. Control plane: lightweight management service for rule updates + telemetry
4. Metrics & logging: per-rule + per-interface; integrate Prometheus + Grafana
5. Fail-safe: bypass or mirror mode on worker failure; watchdog recovery
6. Testing: synthetic 40 Gbps load (IXIA / TRex)

## Current state (MVP-2 closed, 2026-05-23)

- `xdpmacfilter` binary — XDP loader + L2 MAC allow-list (HASH map, pass/drop, default SKB-generic mode)
- C++23 loader + BPF C program; libbpf 1.1+; kernel ≥ 5.15
- Hardened identity gate (name+tag), O_PATH fd-relative bpffs ops, kernel-version probe, PERCPU stats, --mode {generic,native,offload}, netns-isolated test fixture
- 20 ctest entries pass (+ sanitizer build clean)
- See `mint/design.md` for full accumulated history (~3433 lines, §5.x through §5.25 amendments)

## Decisions already made (product owner Q&A, 2026-05-24)

1. **Datapath focus**: XDP/AF_XDP (testable on dev VM). DPDK off immediate critical path — can be added later or never. Bonus: separate **rules module** from **filter module** as natural architecture (rules in userspace lib, filter in BPF) — implies library shape.
2. **HA needed, type TBD** — to be decided in this round
3. **Identity gates**: tool sits inside trusted network. §5.4/§5.19/§5.22 hardening can be **relaxed** for fleet deployment (not removed) — likely via build flag or runtime mode (`XDPMF_TRUST_MODEL=fleet|strict`)
4. **Mirror**: per-rule action (mirror specific packets), NOT global mode
5. **Mirror + rate-limit**: late phases (in mind, not first phases)
6. **Config**: per-VM (per-site). No multi-tenant control plane.

## Reference materials

- **Round 1 brainstorm** (datapath/UX/migration lenses): `/tmp/mvp3-brainstorm/architect-{A,B,C}.md` + `synthesis.md`
- **Round 2 brainstorm** (config-design specifically: semantics/format/contrarian): `/tmp/mvp3-config-design/architect-{T1,T2,T3}.md` + `synthesis.md`
- **Project design.md**: `/home/user/mint-l2-mac-filter/mint/design.md` (full history)
- **External (telecom-context references for new questions)**:
  - GGSN-Gi interface semantics (3GPP TS 23.060)
  - Katran architecture (40 Gbps XDP load balancer at Meta)
  - Cilium daemon model + control plane

## Non-goals (explicit OOS for this round)

- DPDK datapath design (deferred — can be future addition, not MVP-3 critical path)
- Multi-tenant control plane (per-VM is decision)
- DPI / L7 filtering (out of product scope)
- Concrete code for ANY component (this round is architecture, not implementation)
- TRex/IXIA test harness specifics (acknowledged needed; implementation is Phase F-ish)

## What success looks like for this round

`mint/architecture-v2.md` answers:
- Component decomposition (what binaries/libraries/processes exist, their interfaces and lifecycle)
- Phase breakdown (MVP-3.1 through MVP-3.N) with dependency graph and per-phase scope
- Concrete first-slice scope (what `/mint .` cycle would ship as MVP-3.1)
- Critical decisions formalized: HA model, identity-gate relax mechanism, AF_XDP integration timing, kernel-floor policy
- Risk register: what can go wrong per phase
- Open questions surfaced for human gate

---

```yaml
architects:
  parallel:
    - name: A
      lens: |
        System architecture / component decomposition. What binaries, libraries, and processes exist; their public interfaces; their lifecycle; how they compose into a deployable system. Library boundaries (libxdpmf), CLI binary, future daemon process, BPF object structure. Identity-gate relax mechanism (XDPMF_TRUST_MODEL=fleet|strict). How "rules module separated from filter module" expresses concretely in C++/BPF.
      scope: |
        COVER: process model, library/binary split, public C++ API design, BPF object packaging, identity-gate parameterization, build modes.
        DO NOT COVER: rule grammar (that's how operators write rules — out of this lens), datapath internals (BPF prog structure — that's architect B), operational tooling (Prometheus/sFlow — that's architect C).
      sources:
        - "Katran (facebookincubator/katran): C++ library + BPF program shape — repo + Engineering blog"
        - "Cilium agent architecture (docs.cilium.io/en/stable/architecture)"
        - "systemd service + library separation patterns"
        - "C++ shared library design: ABI versioning, SONAME, header layout best practices"
        - "BPF object lifecycle: libbpf skeleton vs hand-loaded, pin/reuse semantics (kernel.org/doc/html/latest/bpf/libbpf/)"
        - "/tmp/mvp3-brainstorm/architect-A.md (round 1 datapath lens — for context, what kernel-side already constrains)"
    - name: B
      lens: |
        Datapath strategy / BPF design for the full action set. How the BPF program changes from current single-rule-allowlist to multi-rule multi-axis with actions {allow, drop, mirror, rate-limit, tag, redirect}. XDP modes (generic/native/offload) for 40 Gbps target. AF_XDP integration shape and timing. Per-rule counter infrastructure. Kernel-floor strategy (5.15 stays vs bump to 5.17 for bpf_loop, vs higher).
      scope: |
        COVER: BPF program structure (single-prog vs tail-call vs subprograms), map types per axis (HASH for MAC, LPM_TRIE for CIDR, ARRAY for port ranges), action implementations (mirror via bpf_clone_redirect/AF_XDP, rate-limit via token bucket, tag via VLAN push/meta, redirect via bpf_redirect_map), per-rule counter design, 40 Gbps strategy.
        DO NOT COVER: rule grammar/format (that's how operators describe rules — architect C touches it lightly through config), library/binary decomposition (architect A), operational concerns like Prometheus (architect C).
      sources:
        - "kernel.org Documentation/networking/xdp.rst + Documentation/networking/af_xdp.rst"
        - "AF_XDP socket integration: bpf_redirect_map XSKMAP usage"
        - "LWN.net BPF/XDP coverage 2024-2025 — kfuncs, struct_ops, dynptr"
        - "Cloudflare XDP performance writeups (blog.cloudflare.com — xdp, l4drop posts)"
        - "Katran XDP datapath (github.com/facebookincubator/katran/blob/main/katran/lib/bpf/)"
        - "BPF rate limiting patterns (cilium-style token bucket in BPF)"
        - "Round 1 architect-A output (/tmp/mvp3-brainstorm/architect-A.md) — read for context but go deeper on actions + AF_XDP"
    - name: C
      lens: |
        Operations / config / roadmap. How YAML config gets pushed/applied/reloaded per-VM. Observability stack (Prometheus exporter, sFlow exporter, structured logs). HA architecture (hot-standby vs bypass — make the decision). Watchdog + auto-restart mechanism. Phase breakdown (MVP-3.1 through MVP-3.N): what ships when, what depends on what, what's the concrete first-slice scope for MVP-3.1.
      scope: |
        COVER: YAML config schema shape (hierarchical interface→IP→action — what does it actually look like), hot-reload protocol (atomic map swap mechanism), per-VM NOC push (Ansible/Salt-style or custom RPC), Prometheus exporter (text format or pull endpoint), sFlow exporter (protocol mechanics), structured logs (JSON format), HA decision (recommend one of: hot-standby active+passive, bypass-on-failure with XDP_PASS injection, dual-instance round-robin), watchdog (systemd Notify, custom heartbeat, etc.), phase breakdown with dependencies and concrete first-slice scope.
        DO NOT COVER: rule grammar inside YAML (focus on shape/hierarchy, not field semantics — that's largely settled by round 2 T1 work), datapath BPF details (architect B), library API design (architect A).
      sources:
        - "Cilium NetworkPolicy YAML schema (docs.cilium.io/en/stable/security/policy/language)"
        - "Calico NetworkPolicy schema (docs.tigera.io/calico/latest/reference/resources/networkpolicy)"
        - "Prometheus exposition format (prometheus.io/docs/instrumenting/exposition_formats)"
        - "sFlow protocol overview (sflow.org) — specifically sFlow v5 datagram structure"
        - "Linux HA patterns: keepalived (active+passive), VRRP — when each fits"
        - "systemd Type=notify + WatchdogSec= patterns"
        - "Ansible Network Automation patterns for per-host config push"
        - "Round 2 T1 + T2 outputs (/tmp/mvp3-config-design/architect-T{1,2}.md) — config model is half-decided already; reference but go deeper on operations + phasing"
  sequential:
    - name: T
      lens: |
        Skeptical engineer / productive grouch (T3 pattern from round 2 — proven effective). Read A+B+C outputs. Attack their selections for hidden assumptions, premise weaknesses, scope creep, over-engineering. Reference prior brainstorm rounds — are A/B/C ignoring lessons learned from round 1+2? Specifically watch for: bpfilter-shaped failure (premature unification), Cilium-style scope creep, "yet another control plane" syndrome, 40 Gbps hand-waving (does the proposed datapath actually hit it on commodity NICs?), HA over-design (do we actually need active+passive or is bypass-on-fail enough?).
      scope: |
        COVER: steel-manned attacks on each A/B/C selection, hidden assumptions across all three, counter-proposals where you see better paths, "if you do anyway" risk mitigations.
        DO NOT COVER: your own designs from scratch (you build on architects' work; if a counter-proposal is needed, sketch but don't fully design).
      inputs: [A, B, C]
      sources:
        - "bpfilter post-mortem (LWN 1017705) — premature unification failure"
        - "iptables-extensions wisdom: what gets used vs nobody touches"
        - "Helm / Terraform complexity case studies — control planes that became their own products"
        - "/tmp/mvp3-brainstorm/synthesis.md — round 1 conclusions"
        - "/tmp/mvp3-config-design/architect-T3.md — your own prior contrarian work (continuity)"
        - "/tmp/mvp3-config-design/synthesis.md — round 2 conclusions"

output:
  path: "mint/architecture-v2.md"
  mode: create

options:
  skip_design_reviewer: false
  max_rework_rounds: 2
```
