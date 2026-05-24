# xdpmacfilter v2 architecture — MVP-3 roadmap (synthesis, round 2 rework)

> Synthesis of round-3 HLD brainstorm: architects **A** (system arch), **B** (datapath), **C** (ops/config/roadmap), **T** (sequential contrarian). This document is the **whole content** of `mint/architecture-v2.md`. T's critique is treated as load-bearing — composite directions honor his deferrals rather than naïvely combining A+B+C selections.
>
> **Round-1 rework** (closed): re-attribution of 4 convergence claims (mis-citation), promotion of B-vs-C disagreement on per-rule counter map type to Divergence (silent-resolution), addition of Component decomposition / Dependency graph / Per-phase risk register sections (brief explicit deliverables), clarification of Option 1 composition vs scope.
>
> **Round-2 rework** (this revision): the recommendation has been re-derived after human-gate pushback that the round-1 recommendation rested on an obsolete priority axis ("cycle 1 must ship user-visible feature") AND an obsolete premise inherited from round-2 T3 ("zero external users → YAGNI"). The brief BODY itself (telecom GGSN-Gi requirements with central YAML/JSON config + NOC push + per-VM sync + control plane) is the resolution to "no external users" — the control plane is the named external consumer. The new recommendation is **Composite 6 — Config-first foundation**, and the caveat structure is inverted: flip TO D1 only on explicit PO override. Sections changed: Executive recommendation TL;DR; Destination component map (config-file phase moved 3.2 → 3.1); Composite directions (Composite 6 added; Option 1 label changed); Dependency graph + Per-phase scope summary (MVP-3.1 and 3.2 contents swapped); Per-phase risk register (3.1/3.2 rows updated); Recommendation (re-derived); Open Questions (Q#1 marked answered); Hidden Assumptions (obsolete-premise entry added). All other round-1 rework artifacts preserved.

---

## Executive recommendation (TL;DR)

Ship **Composite 6 — "Config-first foundation"** for MVP-3.1.

The priority axis is **architectural correctness > incremental stair-step**, not "visible feature vs foundation". The brief explicitly specifies hierarchical YAML/JSON config + per-VM sync + control-plane push as destination requirements; building D1 as a CLI flag in MVP-3.1 commits us to one cycle of throwaway surface that the MVP-3.2 config layer would then deprecate. Config-first lays the architectural foundation correctly for ~250–300 LOC in cycle 1 and pulls L3 src-CIDR axis to MVP-3.2 as the first extension *within* the config-driven path.

| What lands in MVP-3.1 | What is **deferred** to MVP-3.2+ (with explicit phasing) |
|---|---|
| **Config harness**: hierarchical YAML schema (interface → rule list) per brief explicit requirement, with **MAC-only matching** for cycle 1 (current MVP-2 functionality reframed as config-driven) | **L3 src-CIDR axis (D1)**: lands in MVP-3.2 as first extension within the config-driven path (LPM_TRIE map + new rule type, NOT a CLI flag) |
| **Atomic apply**: `apply -f /etc/xdpfilter/<iface>.yaml` swaps maps atomically via `ARRAY_OF_MAPS` (B.12) | A.2 library extraction (MVP-3.6+, only if external consumer surfaces) |
| **P0a**: `bpf_link` pinning at `/sys/fs/bpf/xdpmacfilter/<iface>/link` (mandatory prerequisite, not optional) | A.3 daemon `xdpmfd` (MVP-3.6+ only after measured reload cadence demand) |
| Internal code reorg: `src/loader/` → `src/lib/` + `src/cli/` (Option-2 style, no SONAME) so future library extraction is cheap | A.6 two-library hard split (**indefinite defer** — internal code-org only) |
| Schema validator + exit code 9 = `ConfigError` | B.5 tail-call dispatch (defer until ≥4 actions in regular use) |
| `XDPMF_TRUST_MODEL=strict|fleet` env var (identity-gate relax mechanism) | B.10 AF_XDP hybrid (defer to MVP-3.10+ behind hardware survey + packet-size profile decision) |
| All MVP-2 invariants preserved (§5.4 / §5.19 / §5.22 identity gate untouched in `strict` mode) | C.5 automatic kernel tripwire (**killed** — fail-open inverts allowlist policy; keep only manual bypass primitive) |
| ~250-300 LOC source + ~120 LOC test (5-7 ctests) | C.9 exporter binary (MVP-3.4+ after per-rule counters land) |

**Why**: (a) the brief's telecom destination requirements name the control plane / NOC push / per-VM YAML config as concrete consumers — round-2 T3's "no external users" objection is resolved by the brief itself; (b) building D1 as a CLI flag first creates exactly the kind of surface that the config layer would then deprecate (1 cycle of value purchased at the cost of 1 cycle of deprecation work); (c) per the user's stated priorities for THIS project, architectural correctness for known destination requirements outranks first-cycle visible-feature value. Composite 6 satisfies usefulness, team-exercise, AND architectural correctness; D1 satisfies the first two but trades off the third.

**Caveat (the condition under which this flips, inverted from round-1)**: by default, no override needed — Composite 6 stands. **Flip to Option 1 (D1-first) ONLY if the product owner explicitly states**: "L3 axis in MVP-3.1 is higher value than the config foundation, and I accept the cost of one cycle of CLI-flag surface that MVP-3.2 config layer will deprecate." Without this explicit override, Composite 6 is the recommendation. Note: this caveat is intentionally narrow — the brief body provides the architectural destination; only a PO-level priority reversal would justify front-loading visible-feature value over correct foundation.

---

## Destination component map

The "destination" (full system, all phases shipped) consists of the following components. Each row tags the phase of introduction so the MVP-3.1 slice is unambiguously distinguished from the long-horizon shape. (**Round-2 rework**: config file row moved from MVP-3.2 to MVP-3.1 to reflect Composite 6 phasing.)

| Component | Kind | Interfaces | Lifecycle | Phase of introduction |
|---|---|---|---|---|
| `xdpmacfilter` | CLI binary (existing) | argv flags (`--allow`, `apply -f <file>`, `--mode`, `--trust-model`, `bypass`, `detach`); stderr JSON log lines (added MVP-3.5); CIDR rule type (added MVP-3.2 as in-config rule type; NOT shipped as `--src-cidr` CLI flag, to avoid deprecation work) | Short-lived per invocation; XDP program + pinned link persist in kernel via `bpf_link__pin()` | MVP-2 (extant); extended each phase |
| `mac_filter.bpf.o` | BPF object (existing, embedded skeleton) | `xdp` SEC, reads `mac_allowlist` HASH + `cidr_allowlist` LPM_TRIE (MVP-3.2) + `stats` PERCPU_ARRAY; consumes outer `ARRAY_OF_MAPS` for atomic ruleset swap | Loaded by `xdpmacfilter`; attached via `bpf_xdp_attach`; lives in kernel until explicit detach | MVP-2 (extant) |
| `common/mac_filter.h` | Shared C header | Map structs (`xdpmf_mac`, `xdpmf_rule` from MVP-3.4, `xdpmf_action` from MVP-3.4); enum action_kind | Build-time; included by both BPF and userspace | MVP-2; extended MVP-3.4 |
| `/etc/xdpfilter/<iface>.yaml` | Config file (PRIMARY operator interface) | Hierarchical interface→rule-list schema; per brief explicit requirement (YAML/JSON, hot-reloadable). MAC-only matching at MVP-3.1; CIDR rule type added MVP-3.2 | Operator-owned; consumed by `xdpmacfilter apply -f`; loaded atomically via `ARRAY_OF_MAPS` swap | **MVP-3.1** (round-2 rework: was MVP-3.2) |
| `libxdpmf_internal` (internal static target) | Internal CMake `STATIC` or `OBJECT` library | Not installed; not versioned; CLI links it directly | Build-time only | **MVP-3.1** (round-2 rework: internal code reorg lands cycle-1 to enable future library extraction at zero forward cost; was MVP-3.4) |
| `xdpfilter@.service` | systemd unit template (one instance per iface) | `Type=oneshot RemainAfterExit=yes`; ExecStart/ExecReload/ExecStop; `Restart=on-failure` | One per managed iface; auto-starts at boot; reload via `systemctl reload` (Ansible handler) | MVP-3.3 |
| `xdpmf-exporter` | Long-running daemon binary | systemd `Type=notify` + `WatchdogSec=15s`; HTTP `/metrics` on configurable port (default 9469, **not reserved** — see Open Q #9); reads pinned maps via `bpf_obj_get`; CAP_BPF only (least privilege) | Long-lived; restarts via `Restart=on-watchdog`; never touches datapath state (read-only consumer) | MVP-3.4 |
| BPF ringbuf `samples_rb` | BPF map | Producer: BPF program at 1:N sampling rate; consumer: `xdpmf-exporter` sFlow thread | Created at attach; survives loader exit via standard pin | MVP-3.6 (only if operator confirms no hardware sFlow) |
| `libxdpmf.so.0` (shipped shared library) | Public C++ shared library (SONAME-committed) | PIMPL'd `xdpmf::v0::Loader` class; pkg-config `libxdpmf.pc`; headers under `/usr/include/xdpmf/v0/` | Process-lifetime per consumer | MVP-3.6+ (**only if** named external consumer materializes); otherwise indefinite defer. Note: internal reorg (above) means promoting `libxdpmf_internal` to `libxdpmf.so.0` is mechanical |
| `xdpmfd` | Long-running daemon binary | UNIX SOCK_SEQPACKET at `/run/xdpmfd.sock`; SO_PEERCRED auth; JSON wire protocol; systemd `Type=notify` | Long-lived; owns BPF program for daemon lifetime; CLI becomes dual-mode (direct vs daemon proxy) | MVP-3.6+ (**only if** measured reload cadence demands sub-second); otherwise indefinite defer |
| `action_*.bpf.o` (mirror, RL, tag, redirect) | Separate BPF objects in PROG_ARRAY | Tail-call from match program via `bpf_tail_call(ctx, &actions, action_kind)` | Each independently loaded + pinned; PROG_ARRAY slot update is atomic | MVP-3.8+ (deferred until ≥4 actions actually wanted AND match-prog verifier budget feels tight) |
| `xdpmf-worker` (per-RX-queue AF_XDP) | Long-running worker process(es) | XSK socket bound per RX queue; UMEM allocation; FILL/COMPLETION/RX/TX rings | One per RX queue, CPU-pinned; busy-poll loop | MVP-3.10+ (deferred behind hardware survey + packet-size profile + mirror demand evidence) |

**MVP-3.1 cycle 1 reality (Composite 6)**: rows 1–5 are touched. The first 3 are extended (binary, BPF object, header); row 4 (config file) and row 5 (internal static lib) are introduced fresh. Everything below `xdpfilter@.service` is roadmap shape, not work-in-flight.

**Component-count summary by phase** (round-2 rework):
- MVP-2 (current): 1 binary (`xdpmacfilter`), 1 BPF object, 1 shared header, 0 daemons.
- MVP-3.1 (config-first foundation): same binary count, +1 internal static lib, +1 config-file shape, +`apply -f` subcommand, +`bpf_link` pin.
- MVP-3.2 (L3 CIDR rule type): +`cidr_allowlist` LPM_TRIE in BPF, +CIDR rule schema entry in YAML.
- MVP-3.3 (systemd + Ansible): +1 systemd unit template.
- MVP-3.4 (observability): +1 binary (`xdpmf-exporter`), +new BPF maps (`rules`, `action_table`, `rule_stats`).
- MVP-3.6+ (optional library promotion): `libxdpmf.so.0` shipped if external-consumer condition triggers.
- MVP-3.6+ (optional daemon): `xdpmfd` added if cadence demands.

---

## Convergence (where N architects agree)

1. **(C, T) — `bpf_link` pinning is a mandatory prerequisite, not an optional polish.** Only C and T explicitly require link pinning. C (architect-C.md:18, 25, 199-200) calls it P0a and notes `RemainAfterExit=yes` semantics are unspecified without it. T (architect-T.md:84, 254, 492) confirms it as guard-rail #13. **Note**: A's hot-reload recipe (architect-A.md:90) describes MAP pinning + `bpf_map__reuse_fd` + `BPF_F_REPLACE` — this is compatible with link pinning but does not explicitly require it. B does not address link pinning. **Load-bearing finding regardless**: MVP-3.1 must include `bpf_link__pin()` and a regression test for survival across loader exit (T's guard-rail), and A's hot-reload pattern works correctly only when the link is pinned (synthesizer's inference, to be validated).

2. **(A, C) — `XDPMF_TRUST_MODEL=strict|fleet` env var is the canonical identity-gate-relax mechanism.** A proposes a precedence ladder (API > flag > env, all three mechanisms); C proposes env-var-only for Ansible-friendliness. T narrows the synthesis recommendation to env-var-only for audit cleanliness (single canonical mechanism). B does not address. Strict default (preserves MVP-2 behavior); fleet drops the §5.4 alien-program check but keeps `O_PATH` bpffs safety (§5.19 untouched).

3. **(B, C) — Atomic ruleset swap via map-in-map (`ARRAY_OF_MAPS`) is the recommended hot-reload mechanism** when config-harness lands. B (architect-B.md:44, B.12) describes the outer ARRAY[2] of inner rule-maps with `active_idx` flip. C (architect-C.md:29) calls it "map-in-map outer ARRAY с inner-fd swap, single syscall". **Note**: A does NOT propose this mechanism; A's only mention of "atomic ruleset swap" (architect-A.md:381) is a *question* to C — "If C wants atomic ruleset swap semantics, MapSink needs a commit() boundary" — raising the design question, not selecting an implementation.

4. **(B, T) — 40 Gbps at 64-byte packets is unrealistic on commodity NICs.** B's survey shows i40e single-core ~32 Mpps under bare XDP_DROP vs the 59.5 Mpps required; B itself flags this. T (cross-cutting concern D.2) elevates as load-bearing decision-shaper. **Note**: C does not analyze 40 Gbps feasibility (mentions 40 Gbps only as deployment context, never with packet-size or Mpps analysis). **Packet-size profile (IMIX / 256B / 64B) must be declared as an explicit acceptance criterion** before any datapath rework (B.2 vs B.10) is committed.

5. **(C, T) — kernel floor stays at 5.15 for MVP-3.1 through MVP-3.7.** C (architect-C.md:543-547) enumerates required primitives and confirms 5.15 sufficiency. T (guard-rails) validates. **Note**: A does not address kernel-floor policy (lens is system architecture, not kernel-version selection); no objection raised. All required primitives (LPM_TRIE 4.11, `bpf_ktime_get_ns` 4.1, ringbuf 5.8, `bpf_map__reuse_fd`, `BPF_F_REPLACE`) are well below floor. Bump-to-5.17 (`bpf_loop`) or higher is deferred until rate-limit / iteration patterns actually need it (MVP-3.10+).

6. **(C, T) — bypass-on-failure is satisfied by `bpf_link` persistence + systemd `Restart=on-failure`, not by an active+passive HA pair.** C correctly rejects keepalived/VRRP (C.3) as overkill; GGSN-Gi VMs sit behind ECMP/BGP at a higher layer. T validates and adds: **`bpf_link` pin alone means "filter continues to enforce last-known-good policy" through userspace death** — this is the operator-meaningful reading of "bypass on failure", not the fail-open reading. (A and B do not address HA topology.)

---

## Divergence (where architects substantively disagree)

1. **(A vs C vs B): MVP-3.1 first-slice scope.** A says "MVP-3.1 = A.2 library extraction (refactor only, zero feature)". B says "MVP-3.1 = B.2 multi-map + per-rule counters + action_table abstraction". C says "MVP-3.1 = D1 (L3 src-CIDR axis from round 1)". T sides with C and shows that A and B both implicitly override round-1 and round-2 synthesis decisions without challenging them. **Implication of resolving: A's and B's first-slices each cost 1-3 cycles of refactor with zero user-visible feature; C's ships immediate functional value (filter goes MAC-only → MAC+CIDR). Synthesizer must force-pick.** **Round-2 rework note**: this divergence is resolved at synthesis level — the brief body itself adjudicates by specifying YAML config + control plane as destination requirements (see Open Q #1, now answered). Composite 6 emerges from this resolution: config harness first, with MAC-only matching cycle 1, and L3 axis lands in MVP-3.2 *within* the config-driven path (not as CLI flag).

2. **(A vs T): daemon `xdpmfd` (A.3) yes/no for MVP-3.x.** A argues for daemon to enable sub-second hot-reload and provide a single point for `/metrics` / sFlow / structured logs colocation. T kills A.3 because (a) brief says "hot-reloadable", not "sub-second"; (b) `bpf_link` pin + CLI re-exec already gives hot-reload-without-restart; (c) operational reload cadence is unmeasured. **Implication of resolving: if cadence is < ~1/hour, A.3 is pure overhead (SEQPACKET ABI + privilege-drop policy + group management + watchdog). If cadence is sub-second, A.3 becomes mandatory by MVP-3.4. Product owner must answer.**

3. **(A vs T): two-library hard split A.6 — commitment or YAGNI?** A frames A.6 as "crystallise §5.4-Q&A decision in ABI" enabling third-party rule-engine replacement. T cites A's own Open Question 1 ("If never used, A.6 is pure overhead vs A.2") and concludes there is zero rule-engine-replacement demand. **Implication of resolving: A.6 lock-in is irreversible (two SONAMEs, MapSink ABI); reverse direction (start A.2 monolithic, split later) is cheap. Decision-debt asymmetry strongly favors defer.**

4. **(C vs T): automatic kernel tripwire C.5.** C proposes BPF heartbeat-map check that returns `XDP_PASS` if userspace stops updating heartbeat. T attacks on five grounds: (a) fail-open semantically REVERSES an allowlist policy (previously-blocked traffic now reaches the trusted segment); (b) `bpf_link` pin already gives the "datapath continues" reading of "bypass on failure" for free; (c) 0.5-2% per-packet fast-path tax for a rare-event mitigation; (d) heartbeat-flap on GC pauses; (e) "composable on top of C.1/C.9" actually adds new failure modes. C's own "What it costs" admits the semantic-inversion concern. **Implication of resolving: if product owner reads "bypass on failure" as fail-open, ship C.5 with explicit `--unsafe-fail-open` per-iface opt-in; if read as filter-continues-via-persisted-state, drop automatic C.5 and keep only the manual `xdpmacfilter bypass --on|off` primitive.**

5. **(B vs T): B.10 AF_XDP hybrid budget.** B claims "4 cores × 5-10 Mpps = 20-40 Mpps slow-path is sufficient if mirror/RL <50% of total". T runs the math: 64-byte 40 Gbps = 59.5 Mpps × 50% = ~30 Mpps slow-path which exceeds B's stated headroom; and "5-10 Mpps per core" is the bare-RX upper bound — with packet mutation and TX-ring submission, realistic sustained is ~3-5 Mpps per core. **Implication of resolving: under B's numbers, B.10 works at IMIX (avg 350B); under T's numbers, B.10 works only at IMIX OR larger. Either way, the 64-byte sustained case demands a different design (or admits "we don't support 64-byte mirror at line rate"). Packet-size profile decision again gates this.**

6. **(A vs C, secondary): library shape (A.2) vs no-library two-binary split (C.9) for the loader/exporter relationship.** A assumes `libxdpmf.so.0` will be the shared seam between CLI and exporter. C designs C.9 with two binaries linked against a shared static lib (no SONAME promise) — explicitly notes the "ABI version-skew" open question. **Implication: A.2 SONAME commitment and C.9 binary-split are interlocking; choose one resolution.** **Round-2 rework note**: Composite 6 picks the C.9 / internal-static-lib direction (no SONAME), preserving the option to promote to A.2 later when external consumer materializes. The internal reorg lands MVP-3.1 to make that future promotion mechanical rather than disruptive.

7. **(B vs C): per-rule counter map type — `PERCPU_HASH` vs `PERCPU_ARRAY`.** B (architect-B.md:24, 136) proposes `BPF_MAP_TYPE_PERCPU_HASH` keyed by `rule_id`. C (architect-C.md:560) explicitly asks B to "use PERCPU_ARRAY indexed by rule-id; cap at 64 rules for now". This is a substantive technical disagreement: PERCPU_ARRAY = pre-allocated dense slots, O(1) lookup, requires contiguous rule_id allocation 0..N-1; PERCPU_HASH = sparse dynamic keys, supports rule_id gaps (e.g., operator deletes rule 5, rule_ids 1..4, 6..N stay valid). **Implication of resolving: under the agreed 64-rule cap, PERCPU_ARRAY is more natural (pre-allocate 64 slots, dense indexing, no hash collisions, simpler verifier path). Under sparse allocation (e.g., if rule_ids are stable UUIDs or operator-provided integers), PERCPU_HASH is required. Synthesizer is not the arbiter — see Open Question #13.**

---

## Composite directions (cross-lens combinations)

### Option 1 — Brutal D1 first, defer architecture

- **Composition**: C.1 (stateless CLI extended) + B.2-subset (only `cidr_allowlist` LPM_TRIE added; keep MAC HASH + global PERCPU_ARRAY counters as-is, no `rules` / `action_table` / per-rule counters yet) + P0a (`bpf_link` pin). **No** library extraction, **no** internal code reorg, **no** SONAME, **no** daemon — pure D1 axis-add as T's E.1 prescribes. (Internal code reorg toward future library is Option 2's distinguishing feature, NOT Option 1's.)
- **First slice scope**: MVP-3.1 ships:
  - BPF: `cidr_allowlist` LPM_TRIE map; in `mac_filter_prog`, OR-compose CIDR match with MAC match (any hit → PASS).
  - CLI: `--src-cidr <CIDR>[,<CIDR>...]` peer-flag to `--allow`.
  - Counter: `STAT_PASS_CIDR` PERCPU_ARRAY index (existing pattern from §5.23).
  - `bpf_link__pin()` at `/sys/fs/bpf/xdpmacfilter/<iface>/link`; loader detects existing pin on attach.
  - 5 ctests: `T_PASS_CIDR`, `T_DROP_CIDR`, `T_PASS_CIDR_NO_ALLOW`, `T_PASS_MAC_OR_CIDR`, `T_LINK_PERSIST_ACROSS_LOADER_EXIT`.
  - ~120 LOC source + ~80 LOC test.
- **Risk profile**: **low** in isolation; **medium** when scored against the brief's destination requirements — the `--src-cidr` CLI flag becomes deprecated surface in MVP-3.2 when config-harness lands.
- **User value cycle 1**: filter graduates from MAC-only to MAC+CIDR; operator can now allow `10.0.0.0/8` instead of enumerating MACs.
- **Costs**: TTFW = 1 cycle. LOC delta ~200. Dependencies: none new. Sacrifices: no observability improvement, no config file, no daemon, no per-rule counters — all those are scope-creep risk for cycle 1 and land in MVP-3.2-3.7. **Hidden cost surfaced in round-2 rework**: one cycle of CLI-flag surface (`--src-cidr`) that MVP-3.2 config layer would then deprecate.
- **Preserves**: §5.4 / §5.19 / §5.22 identity gate; existing 20 ctests; `xdpmacfilter` binary name; no SONAME commitment; no systemd unit footprint change; kernel floor 5.15.
- **Phase plan after MVP-3.1**: see the dependency graph below; per-phase scope summary in the table that follows it.
- **Open Qs specific to this option**:
  1. Does the next /mint cycle treat P0a (`bpf_link` pin) as its own preliminary cycle or fold into MVP-3.1 slice?
  2. Is the OR-compose semantic for MAC-or-CIDR matches obvious to operators, or does it need an explicit precedence rule (e.g., "MAC hit short-circuits before CIDR lookup")?
  3. **Round-2 rework added**: is the throwaway `--src-cidr` CLI flag (deprecated by MVP-3.2 config layer) acceptable cost for one cycle of visible-feature value?

### Option 2 — Disciplined additive (D1 + light library prep)

- **Composition**: same as Option 1 for the BPF/datapath/ops dimensions, BUT MVP-3.1 also splits `src/loader/` into `src/lib/` and `src/cli/` directories **internally** (no public header tree, no SONAME, no shipped `libxdpmf.so`). When library actually needs to be exported (MVP-3.4 exporter binary or external consumer demand), the directory split is already done. This is the only composite from the first three that includes the "A.2-shadow" code-organization step.
- **First slice scope**: MVP-3.1 = Option 1 slice + a separate refactor cycle (or the same cycle if scope fits) that moves `loader.cpp` / `raii.cpp` / `identity.cpp` into `src/lib/` and adds an internal `xdpmf_internal` static CMake target. CLI links the static target. No installed headers; no pkg-config.
- **Risk profile**: **low-medium**. Adds one refactor cycle; mild risk of disrupting tests through file moves; no ABI risk because nothing exported.
- **User value cycle 1**: identical to Option 1 user-visible; internally sets up library extraction without committing.
- **Costs**: 1 extra cycle (refactor); ~+0 LOC; ~+5 CMakeLists.txt lines.
- **Preserves**: all of Option 1's preservations + adds a "library shape ready" property for future cycles.
- **Open Qs**:
  1. Is the refactor cycle worth doing now vs at MVP-3.3 / MVP-3.4 when exporter binary actually wants the shared code?
  2. Should the internal target be `OBJECT` library (links into each binary) or `STATIC` (compiled once)?

### Option 3 — Pragmatic library-first (A's preference)

- **Composition**: A.2 (library + CLI split with `libxdpmf.so.0` SONAME, public headers under `/usr/include/xdpmf/v0/`, pkg-config file) as MVP-3.1; D1 (L3 axis) deferred to MVP-3.2; B.2 partial (per-rule counters) deferred to MVP-3.4; C.1 (stateless CLI ext) for ops. No A.3 daemon. No A.6 two-lib split. No C.5 tripwire (manual bypass only). No B.5 / B.10 in MVP-3 horizon.
- **First slice scope**: MVP-3.1 ships `libxdpmf.so.0.3.0` + symlinks + pkg-config + PIMPL'd `Loader` class + `TrustModel` parameter + on-disk `.bpf.o` install. CLI becomes thin wrapper. Existing 20 ctests pass against library. **Zero new user-visible features.**
- **Risk profile**: **medium**. SONAME commitment is irreversible; T flags that "no-break" policy across MVP-3.x is undecided; on-disk `.bpf.o` is a tamper target unless mitigated.
- **User value cycle 1**: zero — refactor-only ship. Value accrues only when a library consumer materializes.
- **Costs**: TTFW = 2-3 cycles. LOC delta moderate (mostly CMake + PIMPL veil). Dependencies: ABI-diff CI check (`abidiff` or `abi-compliance-checker`). Sacrifices: postpones D1 feature by 1-2 cycles; pays SONAME-management overhead forever.
- **Preserves**: identity gate; ctest suite; binary name.
- **Open Qs**:
  1. Is `libxdpmf.so.0` a "no-break-within-MVP-3.x" commitment, or do we accept `libxdpmf.so.1` at MVP-3.5? (T recommends `libxdpmf-pre1.so` until freeze.)
  2. Is the on-disk `.bpf.o` shipped by default or opt-in? (T recommends opt-in to preserve identity-gate audit story.)
  3. Who is the named external library consumer that justifies the SONAME commitment?

### Option 6 — Config-first foundation (RECOMMENDED, round-2 rework)

- **Composition**: C.1 (stateless CLI: `apply -f` only, no daemon) + C's config-harness elements (hierarchical schema [format brief-mandated YAML; C designed format-orthogonal with TOML default], atomic apply, validator + exit code 9) + B.2-subset *minus L3 axis* (single XDP prog; current MAC HASH path stays; outer `ARRAY_OF_MAPS` from B.12 added for atomic swap; no per-rule counters yet, those land 3.4) + Option-2-style internal code reorg (no SONAME) so future library extraction is mechanical + P0a (`bpf_link` pin) + `XDPMF_TRUST_MODEL` env var (A/C convergence). **No L3 axis cycle 1** — pulled to MVP-3.2 as the first in-config extension. **No** SONAME-shipped library, **no** daemon, **no** exporter, **no** tripwire, **no** tail-call dispatch, **no** AF_XDP. T's KEY=VALUE simplicity argument (E.4) is *relaxed* to YAML because the brief explicitly specifies "central YAML/JSON" — this is a brief-mandated format choice, not a free design parameter. **The throwaway-surface concern that motivated round-1 D1 dismissal is now resolved**: Composite 6 lays the config layer correctly first; D1 then extends *within* that layer in MVP-3.2 with zero deprecation work.
- **First slice scope**: MVP-3.1 ships:
  - **Config schema**: YAML at `/etc/xdpfilter/<iface>.yaml`. Top-level `interface: <name>`, `default_action: drop`, `rules: [ {id, action, match: {mac: <...> }} ]`. MAC-only match at MVP-3.1 (CIDR added MVP-3.2; ports etc. later phases).
  - **Parser + validator**: YAML parser (TBD — vendored mini-yaml vs cpp-yaml; see Open Q #10, which now becomes load-bearing rather than 3.2-only); schema validator with structured error reporting; exit code 9 = `ConfigError` per C's design.
  - **Atomic apply**: outer `ARRAY_OF_MAPS[2]` containing two inner `mac_allowlist` HASH maps; userspace writes new ruleset to inactive inner, flips `active_idx`. Single-syscall atomic swap. Old ruleset alive until next apply (one-deep rollback history).
  - **CLI surface**: `xdpmacfilter apply -f /etc/xdpfilter/<iface>.yaml --iface <iface>` (canonical); existing `--allow <mac>` flag kept for backward compatibility (one-rule shorthand that synthesizes a single-rule config in-memory). Other MVP-2 invocations (`bypass`, `detach`) unchanged.
  - **Internal code reorg**: `src/loader/` → `src/lib/` (loader, raii, identity) + `src/cli/` (argv parsing, apply orchestrator). Internal `xdpmf_internal` STATIC target. No installed headers; no SONAME.
  - **P0a**: `bpf_link__pin()` at `/sys/fs/bpf/xdpmacfilter/<iface>/link`; loader detects existing pin on attach (idempotent reattach via `BPF_F_REPLACE`).
  - **Identity gate relax mechanism**: `XDPMF_TRUST_MODEL=strict|fleet` env var; strict default (preserves MVP-2 behavior); fleet documented but used cycle 1 only via tests.
  - 5-7 ctests: `T_APPLY_VALID_CONFIG`, `T_APPLY_REJECTS_MALFORMED`, `T_APPLY_ATOMIC_SWAP_NO_DROP`, `T_APPLY_REPLACES_RULESET`, `T_LINK_PERSIST_ACROSS_LOADER_EXIT`, `T_TRUST_MODEL_FLEET_RELAXES_GATE`, `T_EXIT_CODE_9_ON_CONFIG_ERROR`.
  - ~250-300 LOC source + ~120 LOC test.
- **Risk profile**: **medium**. YAML parser dependency is the main risk (Open Q #10 elevated). Internal-static-lib refactor is mild. Atomic swap via `ARRAY_OF_MAPS` is well-trodden (Cilium-style) but new to this codebase; one ctest specifically covers concurrent-reload-without-drop. No SONAME risk because nothing exported. **Architectural risk profile is LOWER than Option 1** because zero deprecated surface is committed.
- **User value cycle 1**: operator transitions from one-flag-per-MAC CLI invocations to a declarative YAML file describing the interface ruleset. Hot-reload via `xdpmacfilter apply -f` re-exec; old ruleset stays in-kernel until atomic swap. Foundation for control-plane push (`scp config + ssh apply`) is in place. MAC-only matching for cycle 1; CIDR / port / etc. land as in-config rule-type extensions in subsequent phases.
- **Costs**: TTFW = 1 cycle (LOC budget ~2.5x Option 1's). LOC delta ~370. Dependencies: one YAML library decision (vendored mini-yaml or single-header alternative; see Open Q #10). Sacrifices: visible L3 functional value delayed by 1 cycle (lands MVP-3.2 *within* config-driven path, no deprecation).
- **Preserves**: §5.4 / §5.19 / §5.22 identity gate (strict default + env-var-controlled relax); MVP-2 CLI invocations (`--allow`, `bypass`, `detach`) accepted for backward compatibility; existing 20 ctests pass; kernel floor 5.15; `xdpmacfilter` binary name. **NEW preservation**: zero deprecated surface committed — every byte of MVP-3.1 surface continues to be load-bearing through MVP-3.N.
- **Open Qs specific to this option**:
  1. **YAML parser choice (load-bearing)**: vendored mini-yaml single-header, cpp-yaml, custom ~150-LOC subset parser, or strict-subset of YAML expressible by KEY=VALUE-with-list-extension? Open Q #10 escalates from MVP-3.2 risk to MVP-3.1 blocker.
  2. **Schema versioning policy**: top-level `schema_version: 1` field from day 1? Or evolve schemaless until first breaking change? (Recommendation: `schema_version: 1` from day 1, enforce in validator.)
  3. **Backward-compat surface**: do we keep `--allow <mac>` as a flag, deprecate-with-warning, or remove? (Recommendation: keep through MVP-3.4 as in-memory single-rule shorthand; warn but don't drop.)

### Option 4 — Aggressive unified (architects' naïve combine — NOT RECOMMENDED, listed for contrast)

- **Composition**: A.2 + A.3 + B.2-full + B.5 + C.9 + C.5 all in MVP-3.1-3.4. This is what blindly merging the three architects' selected sets produces; T explicitly identifies this as the worst-case scope-creep outcome.
- **First slice scope**: would attempt to ship library + daemon + multi-map datapath + tail-call dispatch + exporter + heartbeat tripwire in 4-6 mint cycles.
- **Risk profile**: **high**. Three new long-running processes (daemon + exporter + workers); fail-open semantic inversion; SONAME lock-in; SEQPACKET ABI + Prometheus port allocation + sFlow XDR encoder all contemporaneously; 7 BPF object identity-gate tags to manage.
- **User value cycle 1**: none until cycle 4+ when the dust settles.
- **Costs**: per T's analysis, ~60+ mint cycles (months of work) to land. Exceeds plausible MVP-3 horizon by 3-5x.
- **Preserves**: nothing — touches every invariant.
- **Open Qs**: this option is included to be explicitly rejected. If the human gate considers it, T's guard-rails #1-#14 become mandatory mitigations.

### Option 5 — Sidestep via tame-the-target (T's E.2 as decision step, not slice)

- **Composition**: NOT an implementation slice. A meta-step that demands the product owner answer five gating questions (packet-size profile, hardware survey, reload cadence, external library consumer, NOC observability inventory) BEFORE the next /mint cycle. Then choose Option 1, 3, or 6 based on answers.
- **First slice scope**: 0 LOC. Output is `mint/architecture-v2.md` (this document) + a "Phase 1 human gate" with these questions front-and-center.
- **Risk profile**: **low**. Buys ~1 week of clarification before committing.
- **User value cycle 1**: none directly; unblocks future cycles to ship the right thing.
- **Costs**: human-gate delay; risk that product owner can't answer (in which case fall back to Composite 6 per the round-2 default).
- **Preserves**: everything; nothing changes.
- **Open Qs**: when does this human gate close? Are these questions answerable by product owner alone or do they require ops/NOC consultation?

---

## Dependency graph (adapted from architect-C.md:432-484, aligned with Composite 6 phasing)

**Round-2 rework**: MVP-3.1 contents and MVP-3.2 contents swapped (config harness now lands 3.1; L3 src-CIDR axis lands 3.2 within the config-driven path).

```
                       MVP-2 (closed)
                            │
                            ▼
              ┌──────── P0a: bpf_link pin ────────┐
              │   (mandatory; folded into MVP-3.1) │
              └─────────────────┬─────────────────┘
                                │
                                ▼
                  ┌───────────────────────────────────────┐
                  │  MVP-3.1 — Config harness foundation  │
                  │  • YAML schema (interface→rules)      │
                  │  • parser + validator + exit code 9   │
                  │  • atomic apply via ARRAY_OF_MAPS     │
                  │  • internal code reorg (src/lib/+cli/)│
                  │  • XDPMF_TRUST_MODEL env var          │
                  │  • MAC-only matching (cycle 1)        │
                  │  • 5-7 ctests                         │
                  └─────────────────┬─────────────────────┘
                                    │
                                    ▼
                  ┌─────────────────────────────────────┐
                  │  MVP-3.2 — L3 src-CIDR rule type    │
                  │  • cidr_allowlist LPM_TRIE          │
                  │  • CIDR rule schema entry in YAML   │
                  │  • OR-compose with MAC match        │
                  │  • STAT_PASS_CIDR counter           │
                  │  • 3 ctests (extends 3.1 harness)   │
                  └─────────────────┬───────────────────┘
                                    │
                                    ▼
                  ┌─────────────────────────────────────┐
                  │  MVP-3.3 — systemd + Ansible        │
                  │  • xdpfilter@.service template      │
                  │  • Ansible playbook (template+notify)│
                  │  • identity-gate relax fleet docs   │
                  └──────────────────┬──────────────────┘
                                     │
                                     ▼
                  ┌──────────────────────────┐
                  │ MVP-3.4 — observability  │
                  │ • per-rule counter map   │
                  │   (B vs C type, see Q13) │
                  │ • rules ARRAY + action_  │
                  │   table (B.2 partial)    │
                  │ • xdpmf-exporter binary  │
                  │ • Prometheus /metrics    │
                  │ • manual bypass primitive│
                  └──────────┬───────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
   ┌──────────────────────┐    ┌──────────────────────┐
   │ MVP-3.5 — JSON logs  │    │ MVP-3.6 — sFlow      │
   │ • loader+exporter    │    │   (conditional on    │
   │   stderr JSON schema │    │    hw-sFlow absent)  │
   │ • journald+Loki docs │    │ • BPF ringbuf        │
   └──────────────────────┘    │ • XDR encoder        │
                               │ • UDP send to        │
                               │   collector          │
                               └──────────────────────┘

   ┌─── OPTIONAL BRANCH (Option 3 flip-condition) ───┐
   │                                                 │
   │  MVP-3.6+ — library extraction (A.2)            │
   │  • libxdpmf.so.0 SONAME shipped                 │
   │  • public headers under /usr/include/xdpmf/v0/  │
   │  • pkg-config + ABI-diff CI                     │
   │  PRECONDITION: named external consumer          │
   │  NOTE: internal reorg at MVP-3.1 makes this     │
   │  promotion mechanical (rename target, install   │
   │  headers, add SONAME — not refactor)            │
   └─────────────────────────────────────────────────┘

   ┌─── OPTIONAL BRANCH (cadence demand) ────────────┐
   │                                                 │
   │  MVP-3.6+ — daemon xdpmfd (A.3)                 │
   │  • SOCK_SEQPACKET at /run/xdpmfd.sock           │
   │  • systemd Type=notify + WatchdogSec            │
   │  • dual-mode CLI                                │
   │  PRECONDITION: measured sub-second cadence need │
   │  AND: library (A.2) shipped first               │
   └─────────────────────────────────────────────────┘

   ┌─── DEFERRED — late phases (only if demand) ─────┐
   │                                                 │
   │  MVP-3.8+ — action set growth (B.5 tail-call    │
   │             dispatch when ≥4 actions wanted)    │
   │  MVP-3.9+ — mirror/RL/tag/redirect actions      │
   │  MVP-3.10+ — B.10 AF_XDP hybrid                 │
   │              PRECONDITION: hw survey + packet-  │
   │              size profile + mirror demand       │
   │  MVP-3.11+ — kernel-floor bump (5.17 for        │
   │              bpf_loop, if RL needs it)          │
   │  MVP-3.12 — xdpmacfilter → xdpfilter rename     │
   └─────────────────────────────────────────────────┘

   EXPLICITLY KILLED (not deferred — removed):
   • C.5 automatic kernel tripwire (fail-open
     inverts allowlist policy; manual bypass
     primitive in MVP-3.4 covers ops need)
   • A.6 two-library hard split (YAGNI; revisit
     only if rule-engine-replacement demand)
   • C.3 active+passive HA via keepalived (overkill;
     bpf_link pin + systemd Restart suffices)
```

Edges to note: MVP-3.2 (L3 CIDR rule type) directly extends MVP-3.1's harness — no parallel path. MVP-3.3 (systemd + Ansible) can begin in parallel with 3.2 (different code areas). MVP-3.4 fan-outs into 3.5 (cheap, JSON logs) and 3.6 (conditional, sFlow). The two optional branches (library, daemon) are independent of the main sequence and triggered by external answers. **Round-2 rework note**: the internal code reorg landing at MVP-3.1 (Option-2-style, no SONAME) means MVP-3.6+ optional library extraction is a mechanical promotion (rename target, install headers, add SONAME), not a refactor — reduces that conditional branch's risk profile from medium to low-medium.

### Per-phase scope summary

| Phase | Scope | Cycles | Risk (see register below) | Depends on |
|---|---|---|---|---|
| **MVP-3.1** | **Config harness foundation**: YAML parser + validator + atomic apply via `ARRAY_OF_MAPS` + internal code reorg (`src/lib/`+`src/cli/`) + `XDPMF_TRUST_MODEL` env var + P0a (`bpf_link__pin`) + MAC-only matching (cycle 1) + 5-7 ctests | 1 | medium (YAML parser choice load-bearing) | MVP-2 |
| **MVP-3.2** | L3 src-CIDR rule type within config-driven path (LPM_TRIE + CIDR schema entry + OR-compose + STAT_PASS_CIDR counter + 3 ctests) | 1 | low | MVP-3.1 |
| **MVP-3.3** | systemd `xdpfilter@.service` template + Ansible playbook + identity-gate-relax `fleet` mode docs | 1 | low | MVP-3.1 |
| **MVP-3.4** | per-rule counter map + `rules`+`action_table` (B.2 partial) + `xdpmf-exporter` + Prometheus `/metrics` + manual bypass primitive | 2-3 | medium | MVP-3.2 + B-vs-C map type resolution (Q13) |
| **MVP-3.5** | JSON structured log schema in loader+exporter; journald+Loki integration docs | 0.5 | low | MVP-3.3 |
| **MVP-3.6** | sFlow ringbuf emitter (BPF) + XDR encoder + UDP send (only if hw-sFlow absent) | 2 | medium-high | MVP-3.4 + B ringbuf design |
| **MVP-3.6+ (opt)** | `libxdpmf.so.0` library extraction (A.2) — mechanical promotion of internal static lib | 1-2 | low-medium (round-2 rework: lower because reorg already done MVP-3.1) | external consumer named |
| **MVP-3.6+ (opt)** | `xdpmfd` daemon (A.3) | 4-6 | medium-high | sub-second cadence + library shipped |
| **MVP-3.8+** | B.5 tail-call dispatch + action set growth | many | per-action | ≥4 actions in regular use |
| **MVP-3.10+** | B.10 AF_XDP hybrid + per-queue workers | 6-10 | high | hw survey + packet-size profile + demand |

---

## Per-phase risk register

Each row identifies the highest-leverage failure mode per phase and the planned mitigation. Adapted from architect-C.md:525-535, extended for phases C did not cover (3.6+ library, 3.6+ daemon, 3.10+ AF_XDP). **Round-2 rework**: MVP-3.1 and MVP-3.2 rows updated to reflect Composite 6 phasing.

| Phase | Top risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| **MVP-3.1** | YAML parser dependency decision unresolved at cycle start (Open Q #10 now load-bearing for 3.1, not 3.2) — could deadlock the slice | high | blocks Composite 6 cycle 1 | Pre-cycle human-gate decision: vendored mini-yaml single-header vs cpp-yaml find_package vs custom ~150-LOC subset parser. Default if no answer: custom subset parser (smallest dep risk, aligns with `cli.cpp:1-3` "zero non-standard deps" project value); document the subset of YAML accepted |
| **MVP-3.1** | `bpf_link` pin API behaves unexpectedly across loader exit + reattach (T's hidden assumption #7 — never verified experimentally) | medium | blocks Composite 6 atomic-apply story | Run one experimental cycle to validate libbpf API before committing P0a scope; if behaves correctly → fold into MVP-3.1 slice; if not → carve out as separate "P0a-prep" cycle to wrangle libbpf |
| **MVP-3.1** | Atomic apply via `ARRAY_OF_MAPS` has race window if `active_idx` flip happens between BPF lookup and dereference | low | correctness | Use `ARRAY_OF_MAPS` with kernel's documented atomic semantics; ctest `T_APPLY_ATOMIC_SWAP_NO_DROP` runs concurrent reload + traffic |
| **MVP-3.1** | Internal code reorg (`src/loader/` → `src/lib/`+`src/cli/`) disrupts existing 20 ctests through file path changes | low | regression | Move files in one commit with no logic changes; ctest run validates before adding any new logic |
| **MVP-3.1** | Schema decision (top-level YAML structure) committed before brief is reconfirmed; if operator pushes back on shape, MVP-3.2 extension becomes a breaking change | medium | architectural | Top-level `schema_version: 1` field from day 1; explicit "experimental — may break before MVP-3.5" disclaimer in docs; aggressive test coverage of schema validator to make incremental changes safe |
| **MVP-3.2** | CIDR rule type integration with `ARRAY_OF_MAPS` outer (introduced 3.1) — atomic swap must apply to both inner maps (MAC + CIDR) consistently | low | correctness | Extend outer map to point at a combined-ruleset record (two inner map FDs per active slot) OR keep MAC+CIDR as independent maps with two-step swap + reader tolerant of half-applied state. Decision in MVP-3.2 design phase |
| **MVP-3.2** | OR-compose semantic for MAC-or-CIDR matches surprises operators (precedence non-obvious) | low | doc/UX | Explicit `T_PASS_MAC_OR_CIDR` ctest + design.md note documenting "any axis match → PASS" |
| **MVP-3.3** | systemd unit template + Ansible idempotency drift across heterogeneous fleet | medium | ops | Reuse existing Ansible idiom (`template` module + `notify` handler); ctest runs `systemctl daemon-reload` + `start`/`stop` in netns fixture |
| **MVP-3.3** | `XDPMF_TRUST_MODEL` mis-set on a fleet node escapes audit (silent posture change) | medium | security | stderr always logs active trust-model literal at attach; alert rule on Prometheus when fleet-wide trust-model distribution diverges |
| **MVP-3.4** | Per-rule counter cardinality blow-up: 64 rules × N CPUs × multiple ifaces → NOC time-series storage growth | low | scaling | Documented hard cap (64 rules per iface, contract); Prometheus label `rule` = name only, no axis proliferation; cardinality audit at scrape |
| **MVP-3.4** | Per-rule counter map type choice (PERCPU_HASH vs PERCPU_ARRAY) commits BPF layout — wrong choice is expensive to undo | medium | architectural | Open Question #13 — human-gate decision based on rule_id allocation policy (dense 0..63 → ARRAY; sparse/UUID → HASH) |
| **MVP-3.4** | Exporter version-skew vs loader (two binaries, shared `common/mac_filter.h` via stringly-typed coupling) | low | correctness | Internal static lib already shipped MVP-3.1 (Composite 6); MVP-3.4 wires both binaries against it. Explicit `XDPMF_ABI_VERSION` constant in shared header + exporter refuses incompatible loader. |
| **MVP-3.4** | Manual bypass primitive misused as automatic fail-open by ops scripts (re-introduces the C.5 problem via human error) | low | security | Bypass write requires CAP_BPF + explicit `--unsafe` flag for non-interactive contexts; logs warning every invocation |
| **MVP-3.5** | JSON log schema breaking change between loader and exporter | low | observability | Version field in schema; ctest asserts key set; semver on `xdpmf_log_schema_version` |
| **MVP-3.6** | sFlow XDR encoder bugs cause silent NOC data loss | medium | observability | Roundtrip ctest (encode → `sflowtool` decode) verifies datagram structure |
| **MVP-3.6** | We ship software sFlow but operator's GGSN already emits hardware sFlow → duplicate / inconsistent telemetry | medium | wasted-work | Open Question #5 — gate sFlow work on explicit operator confirmation that hardware sFlow is absent or insufficient |
| **MVP-3.6+ (opt)** | `libxdpmf.so.0` SONAME committed prematurely → forced `libxdpmf.so.1` bump within MVP-3.x = consumer breakage | medium (round-2 rework: lower because internal lib has been baking since MVP-3.1) | ecosystem | T's guard-rail #11: ship as `libxdpmf-pre1.so` until MVP-3.N freeze, OR keep internal-only until external consumer signed off on API |
| **MVP-3.6+ (opt)** | Daemon `xdpmfd` SEQPACKET wire ABI grows incompatibly with CLI client → version-skew on rolling upgrades | medium | ops | Wire envelope versioned (`{"v":1,"op":...}`); backward-compat for at least one prior version; ctest matrix daemon × CLI |
| **MVP-3.6+ (opt)** | Daemon privilege model wrong (drops caps too early, breaks iface-flap re-attach OR keeps caps, expands attack surface) | medium | security | Open Question #4 — decision deferred to daemon implementation phase based on whether iface-flap auto-reattach is required |
| **MVP-3.8+** | Tail-call into empty PROG_ARRAY slot is silent XDP_PASS (B himself flags) | high (without mitigation) | correctness | Pre-populate ALL action slots with `action_default_drop.bpf.o` filler until real action arrives; ctest asserts no silent-pass |
| **MVP-3.10+** | B.10 AF_XDP re-injection mechanic untested on production NIC inventory | high | datapath functionality | Open Questions #4, #6 — hardware survey + per-NIC AF_XDP validation BEFORE B.10 scope committed |
| **MVP-3.10+** | AF_XDP worker death = slow-path action degradation (mirror/RL stop working silently) | medium | ops | systemd `WatchdogSec` on worker + kernel-side fallback config (per-action default-drop-with-counter when XSK ring fills) |
| **MVP-3.11+** | Kernel-floor bump from 5.15 → 5.17 breaks deployment on sites still on older kernels | depends on hw survey | deployment | Open Question (not yet numbered) — fleet kernel-version inventory before bump |
| **MVP-3.12** | Binary rename `xdpmacfilter` → `xdpfilter` breaks Ansible playbooks, systemd units, monitoring dashboards across fleet | high | ops | Coordinate rename with operator; ship transitional symlink + dual-name systemd template alias for one release cycle |

---

## Recommendation

I recommend **Composite 6 — "Config-first foundation"** for MVP-3.1, because: (a) the brief's destination requirements explicitly call for hierarchical YAML/JSON config + per-VM sync + control-plane push — the control plane IS the named external consumer that round-2 T3 said was missing, so the round-2 "zero external users" premise is obsolete; (b) the user's stated priority axis for THIS project is **architectural correctness for known destination requirements > incremental stair-step**, not "cycle 1 must ship user-visible feature" (the round-1 recommendation rested on the wrong axis); (c) Composite 6 satisfies all three of the user's priorities — usefulness (config-driven MAC filtering with hot-reload is a real operational capability), team-exercise (≥1 cycle of substantive work touching parser, BPF map-in-map, code reorg, ctests), and architectural correctness (every byte of cycle-1 surface remains load-bearing through MVP-3.N, zero deprecation work); (d) Option 1 / D1-first, by contrast, builds a `--src-cidr` CLI-flag surface that the MVP-3.2 config layer would then deprecate — 1 cycle of visible value purchased at the cost of 1 cycle of deprecation work, a wrong trade given the architectural destination is known; (e) Composite 6's internal code reorg (no-SONAME static lib) also lays the groundwork so MVP-3.6+ optional library extraction (Option 3 flip-condition) becomes mechanical rather than a refactor — Composite 6 preserves Option 3's flip-condition optionality at zero cost.

**Caveat (inverted from round-1)**: by default Composite 6 stands — no override required. **Flip to Option 1 (D1-first) ONLY if the product owner explicitly states**: "L3 axis in MVP-3.1 is higher-value than the config foundation, AND I accept the cost of one cycle of CLI-flag surface (`--src-cidr`) that MVP-3.2 config layer will deprecate." Without this explicit PO-level priority reversal, Composite 6 is the recommendation. The caveat is intentionally narrow: the brief body provides the architectural destination, and synthesis cannot independently override a PO-stated priority axis — but it also should not invert that axis silently as round-1 did.

A secondary fallback worth surfacing: if YAML parser choice (Open Q #10, now load-bearing) cannot be resolved within the human-gate window, default the parser to a custom ~150-LOC subset parser (smallest dep risk, aligns with `cli.cpp:1-3` "zero non-standard deps" project value); do NOT fall back to Option 1, because Option 1 has the deeper deprecation-cost problem.

---

## Open questions (for human gate)

1. ~~**First-slice scope: is D1 (Option 1) still the right MVP-3.1?**~~ **(ANSWERED, round-2 rework.)** The user's priority axis is "architectural correctness for known destination requirements > incremental stair-step", and the brief body specifies hierarchical YAML config + control-plane push as destination requirements. Resolution: ship Composite 6 (config-first foundation) for MVP-3.1; L3 axis lands in MVP-3.2 within the config-driven path. Round-1 D1 recommendation rested on an obsolete priority axis (visible-feature-cycle-1) and inherited an obsolete round-2 premise ("zero external users"). Both are resolved at synthesis level by the user's explicit framing.

2. **Is there a named external library consumer for `libxdpmf`?** A says A.2 is right shape IF a consumer exists; T says zero have surfaced for the C++ library API specifically (separate question from the control-plane consumer, which IS named). Why architects couldn't resolve: A doesn't have visibility into product-owner roadmap; T can only point to absence of C++ library evidence. What answer unlocks: if yes → MVP-3.6+ optional branch flips to mandatory (and may pull earlier, e.g., MVP-3.5); if no → MVP-3.6+ optional branch stays deferred indefinitely. Note: this is NOT the same question as "is there an external consumer at all" — the control plane / NOC push is a YAML-file consumer (resolved by brief), not a C++-API consumer.

3. **Operational reload cadence — per-day, per-hour, per-minute?** Determines whether A.3 daemon (sub-second reload) is required or whether CLI re-exec (~50ms) suffices forever. Why architects couldn't resolve: nobody has measured it on real deployment. What answer unlocks: defers or accelerates A.3 by 3-6 cycles.

4. **Packet-size profile for 40 Gbps acceptance criterion: IMIX (~350B avg = 14 Mpps), 256B (~20 Mpps), or 64B sustained (~60 Mpps)?** B notes 64B-at-40Gbps is unrealistic on commodity NICs but doesn't pick. T elevates as load-bearing. Why architects couldn't resolve: brief doesn't specify. What answer unlocks: gates B.10 AF_XDP necessity (only needed for 64B sustained) and shapes the perf-acceptance ctest harness design.

5. **"Bypass mode on failure" interpretation — filter-continues-via-bpf_link-pin OR filter-auto-disables-fail-open?** C reads it as fail-open (C.5 tripwire); T reads it as filter-continues-via-persisted-state. Why architects couldn't resolve: brief language is genuinely ambiguous. What answer unlocks: if filter-continues, drop C.5 entirely (keep only manual bypass); if fail-open, ship C.5 with `--unsafe-fail-open` opt-in flag and operator warning.

6. **Hardware survey — what NICs are in production GGSN-Gi sites?** mlx5 / i40e / ice / ixgbe have native XDP + zero-copy AF_XDP; Broadcom bnxt and some ice variants don't. Why architects couldn't resolve: no hardware inventory in materials. What answer unlocks: gates B.10 viability and per-site `--mode {native|generic|offload}` defaults.

7. **NOC observability inventory — Prometheus confirmed? sFlow confirmed (or covered by hardware sFlow on GGSN routers already)? Structured JSON to Loki/journald confirmed?** C lists all three; T notes sFlow at VM scope may duplicate hardware sFlow. Why architects couldn't resolve: depends on customer fleet specifics. What answer unlocks: scopes C.9 exporter content (Prometheus-only vs full triple) and defers sFlow indefinitely if already covered.

8. **Identity-gate relax — single switch or three independent axes?** Brief says "§5.4 / §5.19 / §5.22 hardening can be relaxed". A/C interpret as single `XDPMF_TRUST_MODEL=fleet` env var flipping all three; T questions whether each axis should be independently controllable. Why architects couldn't resolve: brief uses singular "relaxed" but lists three mechanisms. What answer unlocks: design of the `fleet` mode flag (single binary or per-axis `XDPMF_RELAX_5_4=1` / `XDPMF_RELAX_5_19=1` / `XDPMF_RELAX_5_22=1`).

9. **MVP-3 horizon — quarter or year?** If quarter, Composite 6 ships MVP-3.1-3.3 only. If year, Composite 6 ships through MVP-3.7. Why architects couldn't resolve: brief doesn't bound. What answer unlocks: aggressive deferral if quarter, paced ramp if year.

10. **YAML parser policy — LOAD-BEARING for MVP-3.1 under Composite 6** (escalated from MVP-3.2 risk in round 1): vendored mini-yaml single-header, cpp-yaml find_package, or custom ~150-LOC subset parser to preserve the `cli.cpp:1-3` documented "zero non-standard deps" project value? Why architects couldn't resolve: T flags it in TOML-context (E.4); others don't address YAML specifically. What answer unlocks: MVP-3.1 first-slice can begin. **Default if unanswered**: custom subset parser (per the secondary fallback in the Recommendation).

11. **Binary rename `xdpmacfilter → xdpfilter` timing.** C's systemd templates assume the rename; A's library naming (`libxdpmf-*`) also assumes it; but C's own roadmap puts the rename at MVP-3.12. Inconsistency. Why architects couldn't resolve: nobody picked. What answer unlocks: either rename early (MVP-3.1 or MVP-3.3) for consistency, or keep MVP-2 naming throughout MVP-3.

12. **bpf_link pin (P0a) — does the libbpf API actually behave as expected across loader exit + reattach + `BPF_F_REPLACE`?** T's hidden assumption #7 — never verified experimentally. Why architects couldn't resolve: nobody ran the test. What answer unlocks: confirms P0a is a small refactor (recommended) vs requires libbpf wrangling (rescope).

13. **Per-rule counter map type — `PERCPU_HASH` (B) vs `PERCPU_ARRAY` (C)?** Substantive technical disagreement promoted from Convergence after round-1 review. B (architect-B.md:24, 136) proposes PERCPU_HASH keyed by `rule_id` for sparse-key flexibility; C (architect-C.md:560) asks for PERCPU_ARRAY indexed by rule-id under the 64-rule cap. Why architects couldn't resolve: cross-lens — depends on rule_id allocation policy (dense 0..N-1 vs sparse / operator-assigned) which neither has fully specified. What answer unlocks: gates MVP-3.4 BPF map layout — wrong choice is moderately expensive to undo (verifier paths differ).

---

## Hidden assumptions (the unknown-unknowns the round surfaced)

1. **"Round-3 T's contrarian critique inherited round-2 T3's 'zero external users → YAGNI' premise without testing whether the brief body had moved the goalposts."** (Round-2 rework finding, explicitly named by the user at human gate.) Round-2 T3 was correct at the time: no external consumers had been named. But the brief BODY for round 3 (telecom GGSN-Gi requirements: hierarchical YAML/JSON config + NOC push + per-VM sync + control plane) **IS the resolution** to T3's open question — the control plane is exactly the kind of named external consumer that flips the premise. T's round-3 work, and round-1's synthesis recommendation built on it, inherited the obsolete framing without checking whether the brief itself had answered T3's gating question. Consequence of this hidden assumption surviving: round-1 recommended D1-first, which trades 1 cycle of visible-feature value for 1 cycle of MVP-3.2 deprecation work — wrong trade given the architectural destination is known. **Why this matters as a hidden assumption rather than just "T was wrong"**: T was right by his own reasoning given his inputs; the assumption that "round-2 conclusions remain valid unless explicitly revisited" is the silent inheritance pattern. The brief BODY should be re-read as a potential adjudicator on every prior open question at the start of each new round.

2. **"MVP-3 is one big architectural commitment."** All three primary architects produced HLDs detailing 9 selected approaches as if all were for MVP-3.1; their own roadmaps then defer 6 of 9 to MVP-3.4+. Brief language ("destination + phased roadmap") may have over-cued this framing. If false (MVP-3 is actually a sequence of small mint slices like MVP-2 was), the entire round's enumeration is correct but its phasing assumptions inflate cycle 1 scope by 3-5x. Consequence of falsity: synthesizer must do exactly what this document does — explicit per-approach defer-to-phase mapping.

3. **"40 Gbps acceptance criterion implies any packet size."** B and C analyses tacitly assume IMIX; T explicitly surfaces this. If false (e.g., spec actually means 64-byte sustained for DDoS scenarios), single-prog B.2 alone cannot satisfy the spec on commodity NICs; B.10 AF_XDP becomes mandatory; the entire phasing collapses to "AF_XDP-from-MVP-3.1 or we miss the spec". Consequence of falsity: roadmap reshape from Composite 6 to a B.10-first composite that nobody currently proposes.

4. **"`bpf_link` pinning gives free bypass-on-failure with no caveats."** C asserts this in takeaway #2; T agrees and uses it to kill C.5. Nobody has verified the libbpf API behaves correctly across (loader exit → loader restart → `bpf_map__reuse_fd` → `BPF_F_REPLACE` reattach) on libbpf 1.1+. Consequence of falsity: HA story collapses; either C.5 (with its policy-inversion problem) comes back into play or active+passive HA (C.3, overkill) re-emerges. Also blocks Composite 6's atomic-apply ctest until verified.

5. **"NOC consumes Prometheus + sFlow + structured-JSON simultaneously, all three at per-VM XDP-filter scope."** Brief lists all three. C bundles all three into C.9 exporter. T questions sFlow value at VM scope when GGSN routers likely emit hardware sFlow already. If false (NOC consumes only Prometheus, or only sFlow from hardware), C.9 scope shrinks 60-80%; sFlow XDR encoder is dead code. Consequence: substantial MVP-3.4-3.6 scope reduction.

6. **"Per-VM single-tenant deployment means our tool doesn't need a control plane (but Ansible-style external push counts as 'control plane')."** Brief decision section says explicit ("per-VM, no multi-tenant CP"). But brief body lists "per-site sync via control plane; optional push from NOC". Cross-VM consistency of rule-base IS operationally required and handled by Ansible templates (per C). If false (operator wants a dedicated control plane daemon for the rule-base itself, not Ansible push), C.7 (gRPC daemon) or similar pulls back into scope. Consequence: control-plane re-enters the design — exactly the "yet another control plane" T warns against. **Round-2 note**: this assumption interacts with hidden assumption #1 — the brief's "control plane" language was treated by some architects as Ansible-equivalent, by others as a separate daemon. The round-2 rework treats it as Ansible-equivalent (config push) for Composite 6 scope; explicit PO confirmation would lock this in.

---

## Per-architect summary (compact cross-reference)

**Architect A** (system arch). Surveyed Katran library shape, Cilium daemon shape, libbpf hot-reload patterns, C++ SONAME conventions. Selected **A.2 (library + CLI split with `libxdpmf.so.0`)**, **A.3 (add `xdpmfd` daemon with SEQPACKET JSON IPC + systemd notify watchdog)**, **A.6 (two-library hard split: `libxdpmf-filter` + `libxdpmf-rules` with MapSink ABI bridge)**. Key finding: library shape buys nothing without a named external consumer; A himself recommends "A.2 only for MVP-3.1, A.3 = MVP-3.2, A.6 = MVP-3.3+ or never". Identity-gate relax proposed as `TrustModel` parameter with env var + CLI flag + API precedence ladder (T narrows to env var only). **A does NOT address kernel-floor policy, packet-size profile for 40 Gbps, `bpf_link` pinning (explicitly), or HA topology** — those lenses belong to C and T. **Composite 6 absorbs A's contribution as**: internal code reorg (Option-2-style, no SONAME) at MVP-3.1 to enable mechanical promotion to A.2 later if external consumer materializes; `XDPMF_TRUST_MODEL` env var (A/C convergence); A.3 daemon and A.6 split remain deferred.

**Architect B** (datapath). Surveyed XDP/AF_XDP kernel docs, Katran tail-call patterns, Cloudflare L4Drop production, Cilium token-bucket, Cloudflare/Katran/Red Hat 40 Gbps benchmarks. Selected **B.2 (match-then-action two-pass with `rules` ARRAY + `action_table` + 9 maps including LPM_TRIE / PERCPU_HASH / XSKMAP / DEVMAP)**, **B.5 (Katran-shape tail-call PROG_ARRAY[6] indexed by action_kind)**, **B.10 (hybrid: BPF fast-path for allow/drop, AF_XDP slow-path for mirror/RL/tag/redirect)**. Key finding: 64-byte 40 Gbps is unrealistic on commodity NICs (i40e single-core ~32 Mpps under bare drop); native XDP mandatory for line rate; B himself roadmaps B.5 → MVP-3.3 and B.10 → MVP-3.4. T pulls B.2 scope back: for MVP-3.1 D1, only `mac_allowlist` + `cidr_allowlist` + `stats` are needed; the 9-map shape is right for MVP-3.4-3.5+. **B proposes PERCPU_HASH for per-rule counters** — substantively disagrees with C on map type (Divergence #7). **Composite 6 absorbs B's contribution as**: B.12 (outer `ARRAY_OF_MAPS` for atomic ruleset swap) lands MVP-3.1 as the atomic-apply mechanism; full B.2 multi-map shape lands MVP-3.4 with per-rule counters; B.5 / B.10 remain deferred.

**Architect C** (ops/config/roadmap). Surveyed Prometheus text format, sFlow v5 datagram spec, Calico/Cilium NetworkPolicy schemas, keepalived/VRRP, systemd Type=notify + WatchdogSec, `bpf_link` pinning, Ansible automation. Selected **C.1 (stateless CLI extended: `xdpfilter@.service` template, oneshot + RemainAfterExit + `bpf_link` pin, Ansible push, no daemon)**, **C.9 (two-binary split: stateless loader + `xdpmf-exporter` long-running daemon with Prometheus + sFlow + JSON logs)**, **C.5 outlier (kernel-resident tripwire: BPF heartbeat-map check, fail-open on userspace silence)**. Produced concrete 12-phase MVP-3.1 → MVP-3.12 roadmap with dependency graph (adapted into this document). Key finding: keepalived/VRRP active+passive is overkill (GGSN-Gi VMs already in ECMP); `bpf_link` pinning makes "userspace crash" a non-event for datapath. T accepts C.1, conditionally accepts C.9 (phasing + port + version-skew caveats), kills C.5 in automatic-tripwire form (keeps only manual bypass primitive) because fail-open semantically inverts allowlist policy. **C proposes PERCPU_ARRAY for per-rule counters** — substantively disagrees with B on map type. **Composite 6 absorbs C's contribution as**: C.1 stateless CLI is the cycle-1 shape (`apply -f` only, no daemon); C's hierarchical YAML schema design and atomic-apply-via-map-in-map mechanism land MVP-3.1; C.9 exporter binary lands MVP-3.4; C.5 tripwire killed.

**Architect T** (sequential contrarian). Read A+B+C; defended round-1 D1 first-slice decision; killed A.3 (no measured reload-cadence demand), killed A.6 (textbook YAGNI), deferred B.5 (premature production pattern), deferred B.10 (40 Gbps math doesn't check + AF_XDP plumbing is 2-3 weeks not a slice + re-injection mechanic unsolved on uncharacterized hardware), killed C.5 automatic mode (fail-open inverts allowlist; `bpf_link` already gives the right reading of "bypass on failure"). Surfaced 6 cross-cutting concerns (Front D: MVP-3 big-commit framing, 40Gbps packet-size ambiguity, full-observability-stack premise, identity-gate relax interpretation, three-architect first-slice divergence, per-rule counter cardinality). Produced 4 counter-proposals (E.1 brutal D1, E.2 tame 40Gbps as gating-question step, E.3 ditch tripwire keep manual bypass, E.4 KEY=VALUE if config) and 14 guard-rails for if-the-premise-survives. Surfaced 10 hidden assumptions and 12 human-gate open questions. **T's deferrals (A.3, A.6, B.5, B.10, C.5) are honored by Composite 6 exactly as by Option 1.** **T's D1-first first-slice recommendation is NOT honored by Composite 6** — the user's round-2 human-gate pushback established that T's round-3 critique inherited round-2 T3's "zero external users" premise without re-testing it against the brief body. The brief BODY (telecom destination requirements with named control plane) is the resolution to T3's gating question, making D1-first the wrong trade for THIS project's architectural-correctness priority axis. T's other critiques remain load-bearing for synthesis.
