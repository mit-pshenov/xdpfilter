# Selection Scenarios & Rule-Requirements Catalog (Wave A — discovery)

> **Purpose.** Ground the real match-model design in *what traffic we actually need to select*
> and *how the industry expresses such selection*, before designing the technical structure
> (Wave B = `/mint-hld` on the rule-model architecture). This is a DISCOVERY catalog: it says
> WHAT the model must express and WHY, not HOW to encode it in eBPF maps.
>
> **Framing (settled, do not re-litigate).** `xdpfilter` is a **pre-filter that SELECTS traffic
> for a downstream external DPI**. It is ONLY a filter: near-term action vocabulary = **pass /
> drop** (select / deselect) + an explicit default. *How* selected traffic reaches the DPI
> (mirror/redirect/tap) is deferred — consumed at the interface/network level; DPI is external
> and the filter does not inspect. eBPF is the model-validation vehicle; DPDK/AF_XDP and
> perf-validation are deferred. The RICH design axis is therefore **match (what to select)**.
>
> Sources: this catalog synthesizes three research surveys —
> `/tmp/wave-a-research/L1-dpi-selection.md` (Gi/DPI practice),
> `/tmp/wave-a-research/L2-rule-shapes.md` (rule-shape taxonomy / FlowSpec),
> `/tmp/wave-a-research/L3-config-grammar.md` (config grammar) — plus a code-grounded
> realizability pass against the current datapath (`src/bpf/mac_filter.bpf.c`).

---

## 1. Where the filter sits

```
            Gi / SGi-LAN  (GTP-U already decapsulated → naked inner IP on VLAN-tagged Ethernet)
 GGSN/PGW ──► [xdpfilter: SELECT (pass/drop)] ──► external DPI / VAS chain
                          │
                          └─ (deselected) ──► fast path / bypass
 config in (from NOC): subscriber IP pools, APN→VLAN map, service dst-CIDRs, port lists, bypass lists
 output: "selected (pass) / not (drop)"; handoff mechanism = out of scope
```

Architectural role = a **network-packet-broker / SFC-classifier** in front of DPI. The economic
driver: DPI is expensive per byte and a large fraction of Gi bytes are low-information for it
(video, encrypted bulk, CDN, OS updates). So the filter must **carve subsets by header fields**
and, crucially, **negatively select (bypass)** bulk/uninteresting traffic. (L1 §1–2.)

---

## 2. Selection-criteria taxonomy realistic at Gi

Everything observable in the packet at Gi is L2–L4 headers + topology. L7/app-identity
(SNI/URL/signatures) is explicitly the downstream DPI's job, NOT ours — a clean, finite scope
line. Five families (L1 §3):

| # | Family | Concrete criteria | Status today |
|---|---|---|---|
| A | Topology / encap | ingress interface, **VLAN-ID**, EtherType, MAC | iface ✅; VLAN/EtherType ❌ (top L2 gap) |
| B | L3 endpoints | **src-CIDR = subscriber side**, **dst-CIDR = service side**, direction, IPv6 | src-CIDR ✅; **dst-CIDR ❌ (#1 gap)**; IPv6 ❌ |
| C | L4 transport | IP protocol, **dst-port = coarse app class**, src-port, port ranges/sets | ❌ |
| D | Flow / session | 5-tuple flow, subscriber-session coherence | ❌ — stateful, edge of XDP; defer |
| E | **Negative selection / bypass** | bypass dst-CIDR allowlist (CDN/OTT), bypass by port/proto (ESP/QUIC), elephant-flow/volume bypass | ❌ — needs ordered allow/deny, not positive-only |

**Highest-leverage additions** (cheap at Gi, unlock most real patterns): **dst-IP/CIDR**
(services are destination-identified — the spec's #1 gap), **VLAN-ID** (carries APN context —
see §3), **L4 dst-port** (app class without L7). (L1 §5.)

---

## 3. Subscriber / APN verdict (the cross-lens question — RESOLVED)

**Raw subscriber/APN identifiers (IMSI/MSISDN/APN string) are NOT in the packet at Gi.** They
live in the GTP tunnel + control plane, both terminated at the GGSN/PGW *before* Gi. A stateless
reader on Gi sees only `UE-IP ↔ peer-IP` + ports. (That is *why* packet brokers do IMSI
filtering via GTP correlation on the tunneled Gn side, not at Gi.) But the context is
**recoverable as L2/L3 proxies**:

- **subscriber / subscriber-cohort = src-CIDR** (UE-IP is bound to the subscriber by the control
  plane via RADIUS/PCRF; a target subscriber = a /32 populated externally). Our existing
  `src_cidr` axis IS the subscriber axis at Gi.
- **APN = VLAN-ID** (operators conventionally map an APN to a designated VLAN on the Gi link —
  IETF SFC mobility draft). This is the strongest argument that **VLAN-ID is high-value**.

**Consequence for the model:** do **NOT** add IMSI/APN as datapath packet fields. Richness goes
into flexible **src/dst CIDR sets + VLAN**, populated externally by the NOC. Keeps the datapath
stateless and honest about what Gi packets carry. → No separate subscriber axis is needed.
(L1 §4.)

---

## 4. Match-field target set & encoding primitives

The industry converges on a small, near-fixed field set (BGP FlowSpec RFC 8955/8956 is the
canonical schema — 13 component types cover the whole stateless-match consensus; it omits L2,
which we must add). Ranked by universality (L2 §2):

- **Tier-1 (universal 5-tuple):** dst IP/CIDR, src IP/CIDR, L4 protocol, dst port, src port.
- **Tier-2 (telecom/Gi-relevant):** VLAN-ID (+QinQ), EtherType, src/dst MAC, ingress interface,
  DSCP, packet-length, TCP flags.
- **Tier-3 (specialized):** ICMP type/code, fragment flags, IPv6 flow label, TTL.

All match values reduce to **six encoding primitives** — a model supporting these covers the
whole field space (L2 §2, §5):

1. **prefix / LPM** (src/dst IP; IPv6 adds bit-offset prefixes)
2. **exact value** (proto, EtherType, VLAN, MAC, flow label)
3. **numeric range** (ports, packet-length, DSCP)
4. **value set / list** (port lists, proto lists, VLAN sets)
5. **bitmask** (TCP flags, fragment flags)
6. **negation / except** ("everything but X")

The bootstrap already has #1 (src_cidr via LPM_TRIE). The high-leverage additions are
**dst-prefix (LPM), port range/set, value-set, bitmask** — these four unlock nearly the entire
Tier-1/Tier-2 set. Negation is a convenience layered on top.

> The requested *future* action set (allow, drop, mirror, rate-limit, tag, redirect) is
> corroborated almost field-for-field by FlowSpec's standardized actions — external evidence the
> vocabulary is correctly scoped. But per framing, only **pass/drop** is near-term; the rest are
> Wave-C+ and out of this catalog. (L2 §5e.)

---

## 5. Rule composition, ordering & default

Industry consensus (every surveyed tool — L2 §3, L3 §2):

> A **rule** = an ordered entry with an explicit **action** + a **match block** where each named
> field holds a **list (OR within a field)**, fields **AND together (absent = wildcard)**, values
> may reference **named, typed, reusable objects** and may be **negated**, evaluated
> **first-match-wins** with an **explicit default action**.

- **AND-within-a-rule** is non-negotiable and identical everywhere (FlowSpec states it as
  "intersection of all components present"). **Our current schema does the OPPOSITE (OR-compose)
  — see §6.**
- **OR-within-a-field via lists** (`dst_port: [80, 443]`) — universal, intuitive.
- **Across rules:** two models — **ordered first-match with explicit integer priority** (ACL
  muscle-memory; the recommended default) vs **most-specific-wins** (FlowSpec; order-independent
  but needs a defined specificity comparator). *This is a genuine Wave-B fork.*
- **Default action:** explicit, mandatory, per-interface. Already correct in our schema (avoids
  the Cisco hidden-`deny any` foot-gun). Default-pass ("inspect all except…") vs default-drop
  ("only these…") is a deployment choice.
- **Negative selection (§2E) is naturally ordered allow/deny:** earlier `drop` rules win →
  bypass; this is why ordering + AND-compose matter, and why a positive-only allowlist is
  insufficient.

---

## 6. Realizability verdict (code-grounded — the headline)

Checked against `src/bpf/mac_filter.bpf.c` + `config.cpp` + fixtures.

**6.1 OR-compose is STRUCTURAL, not a config choice.** The datapath does not scan rules. Each
**axis is an independent map keyed by a packet field** — MAC-HASH (src-MAC) and CIDR-LPM_TRIE
(src-IP) — and a hit yields a `rule_id`, then `rules_inner[rule_id] → action_table[action_id]`
gives the verdict. A rule with both `mac` and `src_cidr` inserts its `rule_id` into BOTH axis
maps, so a hit on *either* axis selects that rule → **OR**. (Confirmed: `mac_filter.bpf.c:342`
MAC branch, `:393` CIDR-on-MAC-miss branch; fixture `config_valid_mac_or_cidr.yaml`.)

**6.2 Therefore "flip to AND" is an ARCHITECTURE change, not a schema-version semantic.**
Independent per-axis maps fundamentally cannot express "field X AND field Y AND field Z", because
a hit on one axis map carries no knowledge of the others. AND-compose multi-field matching is the
classic **packet-classification problem**. Candidate structures to weigh in Wave B:

- **(a) Sequential per-rule scan** — evaluate each rule's fields with AND, first-match by id.
  Simplest, most flexible (any primitive per field), but O(N rules)/packet; fine for small N.
- **(b) Bit-vector / bitset intersection** (Lakshman–Stiliadis) — each axis map returns a u64
  *rule-bitmask* (which rules specify this value for this axis), OR-ed with the axis's
  "unconstrained-rules" baseline (wildcard); AND the per-axis bitmasks; `ffsll` → lowest id =
  first-match. Preserves per-axis lookup strengths (LPM for CIDR, HASH for exact), is
  verifier-friendly for N≤64 (one u64) / N≤256 (small fixed loop), and unifies AND-compose +
  first-match ordering elegantly. Strong candidate.
- **(c) Composite-key map** (nftables-concatenation style) — one map keyed on a concatenated
  tuple. Breaks down when mixing LPM (CIDR) + ranges (ports) + exact in one key; only works for
  all-exact subsets.
- **(d) Decision-tree** (HiCuts/HyperCuts) — scales to large rule counts; heavy to build/maintain
  and awkward under the verifier. Likely over-engineering for the eBPF-vehicle stage.

This is exactly the diversified-trade-off space that makes Wave B genuine `/mint-hld` territory.

**6.3 Per-field datapath cost at Gi/XDP** (realizability of the §2/§4 fields):

| Field | XDP cost | Note |
|---|---|---|
| dst_ip / CIDR | trivial | same LPM_TRIE as src; key on `ip->daddr`. **Cheapest high-value add.** |
| protocol | trivial | `ip->protocol` |
| dst_port / src_port | cheap | needs L4 parse past `ihl` (IP options); proto-gated |
| EtherType | trivial | `eth->h_proto` |
| **VLAN-ID** | cheap **but** | requires 802.1Q parse; **latent bug today** (§6.4) |
| TCP flags / pkt-len / DSCP | cheap | Tier-2/3, incremental |
| IPv6 | moderate | second LPM key shape (128-bit) + dual parse path |
| flow / session (5-tuple state) | expensive | stateful; **defer** (edge of stateless XDP) |

**6.4 Latent VLAN gap (pre-existing).** Today the CIDR branch is gated on
`eth->h_proto == ETH_P_IP` (`mac_filter.bpf.c:367`). For **VLAN-tagged** IP frames `h_proto`
is `0x8100`, so tagged IP traffic **skips the CIDR axis entirely** and falls to defaults. On a
VLAN-segmented Gi link (the normal case), the current src-CIDR axis would not fire. Adding VLAN
support must also fix the tagged-frame L3 parse path — couple these in the relevant slice.

---

## 7. Config-grammar direction (bridge to YAML)

Adopt the convergent design (nftables/Calico/VyOS/Cilium — L3 §3–6). Backward-evolvable from the
current `schema_version: 1` via the existing strict unknown-key gate (a v2 bump unlocks new
vocabulary; v1 files keep exact strict meaning):

- **AND-within-a-rule at the v2 bump** (matches every surveyed tool; current OR-compose is the
  biggest latent operator foot-gun). *Carries the §6.2 architecture change — config + datapath
  must move together.*
- **Named, typed, reusable objects**: top-level `objects: { ip_sets:, port_sets: }`, referenced
  with an `@name` sigil (disambiguates literal vs reference). Typed (never a MAC in an IP-set;
  never a port-set shared across protocols — VyOS lesson). **Optional convenience** — inline
  values always legal. Highest leverage because dst-services and bypass/blocklists are natively
  named, frequently-updated sets pushed by the NOC.
- **New match keys** (all gated behind v2): `dst_ip`/`not_dst_ip`, `protocol`, `dst_port`/
  `not_dst_port` (pair port with protocol — Cilium lesson), `vlan`, `ethertype`; plus
  `src_port`, list/`@ref` forms for `src_cidr`.
- **Naming:** prefer `dst_ip`/`src_ip` (accepts host /32 and prefix; symmetric); keep `src_cidr`
  as a grandfathered deprecated alias so v1 files load unchanged.
- **Ordering:** make the existing `id` double as priority — **ascending `id`, first-match-wins,
  then `default_action`**. `id` is already sparse-allocated and is the counter index; reusing it
  (VyOS/Cisco numbered-with-gaps convention) avoids a second drift-prone `order:` field. *(Weigh
  against FlowSpec most-specific-wins in Wave B.)*
- **Keep** explicit `default_action`, strict validation, and file:line:col diagnostics; extend
  the same `throw_cfg` shape to new axes and to `@name` resolution.

---

## 8. Open questions for Wave B (the technical rule-model `/mint-hld`)

1. **Packet-classification structure** for AND-compose multi-field match — choose among §6.2
   (a)/(b)/(c)/(d). The pivotal decision; gates everything else.
2. **Ordering model** — first-match-by-`id` vs most-specific-wins (and how it interacts with the
   chosen classification structure; bit-vector naturally gives first-match-by-id).
3. **OR→AND migration** — how to handle existing v1 OR-compose rules across the v2 bump (auto-
   split a 2-axis OR rule into two rules? load-time rewrite? hard-require v2 re-author?).
4. **VLAN parse path** + the §6.4 latent tagged-frame gap (fix coupled with VLAN axis).
5. **IPv6** — second LPM shape + dual parse; when to introduce.
6. **Object resolution** — `@name` resolve/validate pass, type-checking, atomicity under the
   existing hot-reload (apply-time resolution).
7. **Rule cardinality** — N bound (current `XDPMF_ALLOWLIST_MAX`); informs (a) vs (b) vs (d).

---

## 9. Proposed `/mint-dev` slice sequence (post-Wave-B)

Each a full band cycle. Order de-risks by value and structural dependency:

1. **dst-IP/CIDR axis** — cheapest, #1 gap, reuses the LPM_TRIE pattern (still OR-compose era).
2. **L4 protocol + dst-port** — app-class selection; introduces L4 parse + range/set primitives.
3. **AND-compose + ordering + the chosen classification structure** (the Wave-B architecture
   landing) — the pivotal slice; flips OR→AND, lands first-match-by-id, v2 schema bump.
4. **VLAN + EtherType** (with the §6.4 tagged-frame fix).
5. **Named objects (`ip_sets`/`port_sets`, `@ref`)** — the reuse/ergonomics layer.
6. **(later) Tier-2/3 fields** (TCP flags, pkt-len, DSCP), IPv6, negation polish.

> Sequencing note: steps 1–2 are valuable even before the AND architecture (they extend the
> existing axis-map model). Step 3 is where the realizability headline (§6.2) is paid down.

---

## Appendix — Expansion-door signals (external corroboration; NOT adopted)

> **Status: narrow path.** The product target is the narrow Gi-DPI **pass/drop** pre-selector
> (§ framing). A real-world general-purpose L2–L4 programmable-filter config dialect (10
> security/ISP scenarios — DDoS scrubbing, PCI/zero-trust/OT segmentation, threat-intel feeds,
> FlowSpec) was reviewed on 2026-05-28 as a **weak corroboration signal**. It is recorded here
> without adopting its shape. Nothing below is a design decision; the match-model must merely
> **avoid foreclosing** these, to keep the door open for later expansion.

**A. Independent convergence (validation — already in §4–7, we reached these ourselves).**
The artifact independently exhibits: AND-compose within a rule; named **typed** objects with
references; numeric operators (`>`, `<`, range); negation; sparse-id + first-match + explicit
default; and a FlowSpec-style L3/L4 core (one scenario is ≈ a direct RFC 8955 mapping). That our
discovery wave arrived at the same core *before* seeing the artifact validates the catalog — it
is convergence, not adoption.

**B. Expansion-door items (UNIQUE to the artifact — NOT adopted; revisit only if scope widens).**

1. **Layered evaluation pipeline** — per-layer first-match lists chained by an explicit
   "advance to next stage" link (L2→L3→L4 progressive refinement). This is **one candidate
   classification structure** alongside §6.2 (a)–(d) — it maps naturally onto eBPF tail calls.
   *Held as a peer candidate, deliberately NOT promoted to favorite.*
2. **Dynamic feed-backed objects** — objects sourced from an external feed with periodic refresh
   and **large cardinality (10k–500k entries)**. An object-*lifecycle* dimension orthogonal to
   the match model: static-config vs feed-backed objects; a cardinality bound that breaks the
   current ~`XDPMF_ALLOWLIST_MAX` assumption; atomic per-object refresh without full re-apply.
   → Wave-B open question, not a commitment.
3. **Broader action vocabulary** (rate-limit / mirror / redirect / tag) — already deferred per
   framing. Non-foreclosure constraint only: keep the rule→action indirection so adding actions
   later does not reshape the match model.
4. **L7 / stateful fields** (TLS SNI, JA3, conntrack-established) — **OUT of scope by our own
   scope line** (L7 = the downstream DPI's job; stateful = edge of XDP). Noted; do not design for.
5. **Per-rule lifecycle hooks** (time-bounded rule windows; richer per-rule labels) —
   control-plane conveniences, not datapath concerns.
