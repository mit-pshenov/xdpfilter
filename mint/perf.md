# XDP MAC-filter — Tier-0 per-packet cost & throughput envelope

**Date:** 2026-06-01 · **Box:** single dev VM, kernel 6.1.0 (cloud), `nproc=2` ·
**Datapath:** `src/bpf/mac_filter.bpf.c` — `mac_filter_prog` (SEC `xdp`), 9-axis
AND-composed bit-vector classifier (dst/src CIDR LPM v4, dst6/src6 CIDR LPM v6 via
`__int128`, proto/dst_port/mac/ethertype exact-HASH, vlan), first-match-by-`ffsll`,
bounded IPv6 ext-header walk (`MAX_EXT_HOPS=8`).

> **TL;DR.** Program-only warm-cache cost is **~75–205 ns/packet** depending on
> vector. That is **4.9–13.3 Mpps per core**. For the realistic Gi SLA (5–8 Mpps)
> the eBPF classifier needs **~1–2 cores** even on the worst-case v6/64-rule path —
> comfortable headroom. **BUT** these are PROG_TEST_RUN numbers: warm-cache,
> program-only, NO driver/NAPI/DMA/cache-miss-under-load. They are a **lower bound
> on real per-packet cost** / **upper bound on achievable pps**. The eBPF-vs-DPDK
> call cannot be closed on Tier-0 alone — a Tier-1 RX-path bench (generator +
> xdp-bench) is the required next step. First-order verdict: **eBPF is plausibly
> sufficient for SLA#1; no obvious need to jump to DPDK yet.**

---

## 1. Methodology & method availability

All measurement is single-box, no traffic generator, no second host.

| # | Method | Status on this VM |
|---|--------|-------------------|
| 1 | `BPF_PROG_TEST_RUN` via `bpftool prog run id <id> data_in <pkt> repeat <N>` | **WORKS** — primary measurement |
| 2 | `bpf_stats` cross-check (`kernel.bpf_stats_enabled=1` → `run_time_ns/run_cnt`) | **WORKS** — confirms method 1 |
| 3 | `bpftool prog profile` (PMU cycles/instructions/llc) | **UNAVAILABLE** — bpftool v7.1.0 not built with the clang/skeleton support (`"profile command is not supported"`); `perf stat -e cycles` also yields no counters → **hardware PMU not exposed by the hypervisor**. Documented, not blocking. |
| 4 | Userspace per-axis callgrind harness | **NOT READILY AVAILABLE** — `build/bitvec_harness` is a *map populate/dump* tool that drives the real BPF maps, not a standalone userspace classifier; `bitvec_proto.bpf.c` is a verifier spike, not a perf driver. No `src/` modification allowed → axis attribution is done from the **matrix delta** (method 1 across crafted vectors) instead. |

**JIT confirmed ON** (`net.core.bpf_jit_enable = 1`; prog `jited 21719B`, `xlated 39216B`)
— numbers reflect native code, not the interpreter.

### Exact reproduction

```bash
# 1. netns + veth (nsenter --net, NOT `ip netns exec`, to preserve host /sys/fs/bpf)
sudo ip netns add xdpmf_perf
sudo ip netns exec xdpmf_perf ip link add xdpmf_perf0 type veth peer name xdpmf_perf0p
sudo ip netns exec xdpmf_perf sysctl -w net.ipv6.conf.xdpmf_perf0.disable_ipv6=1
sudo ip netns exec xdpmf_perf ip link set xdpmf_perf0 up
sudo ip netns exec xdpmf_perf ip link set xdpmf_perf0p up

# 2. apply a config (populates the maps the lookups read) — via nsenter
NSEXEC="sudo nsenter --net=/var/run/netns/xdpmf_perf"
$NSEXEC build/src/cli/xdpmacfilter apply --iface xdpmf_perf0 -f <config.yaml>
#   → prints "prog id <ID>"  (prog IDs are global; PROG_TEST_RUN runs by id)

# 3. measure
sudo bpftool prog run id <ID> data_in <pkt.bin> repeat 30000000   # → "duration (average): N ns"

# 4. bpf_stats cross-check
sudo sysctl -w kernel.bpf_stats_enabled=1
sudo bpftool prog run id <ID> data_in <pkt.bin> repeat 20000000 >/dev/null
sudo bpftool prog show id <ID> --json   # run_time_ns / run_cnt
sudo sysctl -w kernel.bpf_stats_enabled=0
```

Scratch artifacts (throwaway, not committed to `src/`/`tests/`):
`mint/perf-scratch/` — `build_vectors.py`, `build_v6.py`, `gen64.py` (packet/config
generators), `run.sh` (apply+measure driver), the `v_*.bin` vectors, and
`config_64rule.yaml`. Configs reused from `tests/fixtures/`:
`config_valid_cidr.yaml`, `config_valid_andv6.yaml`, `config_valid_andeth.yaml`.

Each vector = a raw L2 frame (Ethernet [+ VLAN] + L3…) handed to `data_in` exactly
as the NIC would deliver it to XDP. Repeat = 3×10⁷ per run; two trials per vector,
agreement within ±8 ns.

---

## 2. Results — ns/packet per vector

PROG_TEST_RUN `duration (average)`, kernel 6.1, JITed, warm cache.
`RV` = XDP return (1 = `XDP_DROP`, 2 = `XDP_PASS`).

| Vector | Config | Frame | RV | ns/pkt (t1) | ns/pkt (t2) | Exercises |
|---|---|---|---|---|---|---|
| **non-IP early-exit** | 64-rule | ARP 0x0806, 60 B | DROP | 75 | 76 | family dispatch + non-IP arm (floor) |
| non-IP (ethertype rules) | andeth | ARP 0x0806, 60 B | DROP | 93 | — | non-IP arm w/ ethertype-HASH + steer |
| **v4 matched, 1 rule** | cidr (1×) | v4 UDP src 10.5.6.7, 60 B | PASS | 134 | 131 | base v4 AND, single LPM rule |
| **v4 matched, 64 rules** | 64-rule | v4 UDP dst 10.0.63.5, 60 B | PASS | 180 | 179 | v4 AND, 64-entry dst LPM trie |
| **v4 NOMATCH → default** | 64-rule | v4 UDP 203.0.113.1→… , 60 B | DROP | 122 | 124 | full 9-term AND, no winner, defaults |
| **v6 + ext-hdr, matched** | andv6 | vlan100 / 2001:db8:5::→1:: / hbh+dstopt / TCP:1500, 94 B | PASS | 194 | 202 | v6 dual 128-bit LPM + ext-walk (worst) |

### Cross-checks & attribution micro-deltas

| Probe | ns/pkt | Interpretation |
|---|---|---|
| **bpf_stats** on v4-64-rule matched | **205.9** (4 117 288 992 ns / 20 000 000) | Confirms method-1 180 ns; the ~26 ns gap is the per-invocation test-run/syscall harness that `bpf_stats` includes and PROG_TEST_RUN's inner `duration` excludes. Same order of magnitude → numbers are real. |
| v6 **with** ext (hbh+dstopt) vs **without** | 196 vs 191 | **ext-header walk ≈ +5 ns** for 2 hops — the bounded unroll is cheap. |
| v4 single rule **+1 VLAN tag** vs untagged | 145 vs 131 | **VLAN tag walk ≈ +14 ns** per tag. |
| v6 base (191) vs v4 base (131) | Δ ≈ **+60 ns** | The two 128-bit (`__int128`) LPM trie walks (dst6+src6) are the single most expensive feature on the datapath. |
| v4 64-rule (180) vs v4 1-rule (131) | Δ ≈ **+49 ns** | Cost of a fully-populated 64-entry /24 dst LPM trie vs a single /8 — trie-depth/population, not the O(axes) AND step. |

---

## 3. Derived throughput: pps/core = 1e9 / ns_per_pkt

| Vector | ns/pkt | **pps/core (Mpps)** |
|---|---:|---:|
| non-IP early-exit | 75 | **13.3** |
| v4 matched, 1 rule | 133 | **7.5** |
| v4 NOMATCH → default | 123 | **8.1** |
| v4 matched, 64 rules | 180 | **5.6** |
| v6 + ext-hdr, matched (worst) | 198 | **5.05** |

*(ns/pkt = mean of the two trials.)*

---

## 4. Core budget

**SLA#1 (headline) — realistic Gi mix:** 40 Gbps @ ~600–1000 B avg ≈ **5–8 Mpps**.
**Adversarial reference:** 64 B line-rate @ 40 GbE = **59.5 Mpps** (shown to expose the gap).

cores = target_pps / pps_per_core.

| Vector | pps/core | **cores @ 5 Mpps** | **cores @ 8 Mpps** | cores @ 59.5 Mpps (64 B adversarial) |
|---|---:|---:|---:|---:|
| non-IP early-exit | 13.3 M | 0.38 | 0.60 | 4.5 |
| v4 matched, 1 rule | 7.5 M | 0.67 | 1.07 | 7.9 |
| v4 NOMATCH | 8.1 M | 0.62 | 0.99 | 7.3 |
| **v4 matched, 64 rules** | 5.6 M | **0.90** | **1.43** | 10.7 |
| **v6 + ext, matched (worst)** | 5.05 M | **0.99** | **1.58** | 11.8 |

**Reading:** for SLA#1, even the **worst-case** vector (v6+ext or full 64-rule v4)
fits in **~1 core at 5 Mpps and ~1.5–1.6 cores at 8 Mpps**. The common v4 path is
sub-core at 5 Mpps. The adversarial 64 B = 59.5 Mpps case needs **~11–12 cores**
program-only — visibly past a small core budget, but that is the deliberately
hostile framing, not SLA#1.

---

## 5. Which axis dominates

From the matrix deltas (method 4 callgrind unavailable; PMU unavailable):

1. **IPv6 dual 128-bit LPM (dst6 + src6) — ~+60 ns, the single biggest feature cost.**
   The v6 arm runs two `__int128` LPM-trie lookups vs the v4 arm's two 32-bit ones.
2. **LPM trie population/depth — ~+49 ns** going 1→64 dense /24 rules on the v4 dst
   axis. This is *trie* cost, not rule-count fan-out: the bit-vector AND itself is
   O(num_axes)=9, independent of rule count, so the growth is in the per-axis LPM
   walk, not the match composition.
3. **VLAN tag walk — ~+14 ns/tag** (bounded 2-tag unroll).
4. **IPv6 ext-header walk — ~+5 ns for 2 hops** (`MAX_EXT_HOPS=8` bounded unroll) —
   cheap; the S6 ext-walk does **not** dominate despite being the "scariest" path.
5. **Floor (non-IP) — ~75 ns**: Ethernet bounds-check + `active_idx` read + family
   dispatch + non-IP arm. The exact-HASH axes (proto/port/mac/ethertype) are
   effectively free relative to the LPM walks.

So the cost gradient is **LPM (esp. 128-bit v6) ≫ VLAN walk > ext-walk > HASH axes**.

---

## 6. First-order eBPF-vs-DPDK verdict

**Program-only cost leaves comfortable headroom for SLA#1.** The worst measured
vector is ~200 ns/pkt = ~5 Mpps/core; SLA#1's 5–8 Mpps therefore needs roughly
**1–2 cores of pure classifier time**. On any realistic multi-core Gi box that is
not a forcing function to abandon eBPF for DPDK on *classifier cost alone*.

**Caveats — stated loudly:**

- **PROG_TEST_RUN is warm-cache and program-only.** It excludes the NIC driver,
  NAPI poll loop, DMA, per-packet `xdp_buff` setup, and — critically —
  **cache-miss behaviour under real load** (cold map lines, DDIO eviction, TLB).
  Real RX-path ns/packet will be **higher**, possibly substantially, especially for
  the LPM-heavy v6 path whose trie nodes will not be L1-resident under a real
  address mix. → **These numbers are a LOWER bound on cost / UPPER bound on pps.**
- **PMU is unavailable on this VM** (no hypervisor-exposed counters; bpftool not
  profile-capable). We cannot see cycles/IPC/LLC-miss to confirm the program is
  front-end vs memory bound. Axis attribution here is *delta-inferred*, not
  PMU-measured.
- **Single 2-core VM**, not a 40 GbE host. Core-scaling above is *linear
  extrapolation* (RSS/XDP scales near-linearly across queues in practice, but that
  is an assumption, not a measurement here).
- 64 B adversarial line-rate (59.5 Mpps) is **not** comfortably covered
  program-only (~11–12 cores) — if the threat model includes small-packet floods,
  that is where DPDK/AF_XDP + hardware steering earns its keep.

**Recommended next step (Tier-1):** a real RX-path bench — `xdp-bench`/`xdpdump`
drop+pass throughput on the actual NIC, driven by a packet generator
(pktgen/TRex/Cisco) from a second host — to get **loaded** ns/packet and true
core-scaling. The user has a VPS available for the generator side; that is the
Tier-1 follow-up (explicitly out of scope for this Tier-0 single-box pass). Only
after Tier-1 can the eBPF-vs-DPDK decision be closed with confidence.

---

## 7. Hygiene

- netns `xdpmf_perf` + veth deleted; bpffs pins under `…/xdpmf_perf0` removed.
- `kernel.bpf_stats_enabled` returned to **0**.
- No `src/` or committed-test files modified. All throwaway artifacts confined to
  `mint/perf-scratch/`.

---

## 8. Tier-1 — single-box loaded RX-path (ATTEMPTED — generator-bound, NEGATIVE result)

**Setup:** veth pair `perf0`(TX)↔`perf1`(RX); filter applied on `perf1` in **NATIVE** XDP mode (`--mode native` → `XDP_FLAGS_DRV_MODE`, prog id 26, 1-rule `config_valid_cidr.yaml` src 10/8→PASS_CIDR); in-kernel **pktgen** on `kpktgend_0` (CPU0); `perf1` RX steered to CPU1 via `rps_cpus=0x2`.

**Result (bounded 2M-packet burst):**
- Filter correctness under load: **2,000,000 / 2,000,000** frames classified (`STAT_PASS_CIDR` 0→2e6), **0 spurious filter drops** — the native-mode datapath handles sustained real frames cleanly.
- But pktgen delivered only **~195,000 pps** (2e6 pkts in 10.2 s, 93 Mb/s). `clone_skb` returned **ENOTSUPP (524) on veth** → per-packet skb alloc → it is **generation-bound at ~0.2 Mpps**, two orders of magnitude BELOW the filter's Tier-0 capacity (5–13 Mpps/core).

**Conclusion — single-box Tier-1 is not measurable on this 2-core cloud VM:**
1. The generator (pktgen/veth, no `clone_skb`) tops out ~0.2 Mpps — it cannot stress a filter that classifies at 5–13 Mpps/core. The filter trivially absorbed everything offered; its loaded ceiling is **unmeasured**.
2. On 2 cores you cannot simultaneously generate at line rate AND run the DUT — they contend for the same cores. Pushing pktgen harder (more threads / unbounded) starves the box and drops the session (observed).
3. **Deeper truth: on cloud VMs (virtio, no real-NIC DMA, link-capped) no software generator we can run out-paces the filter** — its intrinsic capacity exceeds what these VMs generate. A true *loaded-ceiling* number needs real 40G NIC hardware + a hardware/DPDK generator (TRex / DPDK-pktgen) — a lab setup, not available here. Even the two-VPS variant (aeza generator → this NIC) is virtio+link-capped well below the filter's capacity, so it would confirm correctness-under-real-frames, NOT the ceiling.

**What Tier-1 still confirmed:** native-mode XDP attaches + runs correctly on the RX path under sustained real frames with zero spurious drops (correctness-under-load ✓).

**Decision-grade takeaway stays Tier-0:** for SLA#1 (realistic Gi mix, 5–8 Mpps) the classifier cost (~1–2 cores program-only, dominant = dual IPv6 LPM) leaves comfortable headroom; eBPF is viable with no classifier-cost forcing-function to DPDK. A real loaded ceiling (and the adversarial-64B verdict) needs 40G lab hardware — parked until real hardware is available.
