# Task brief — MVP-4.12 / S2: `inject_l6.py` IPv6 frame injector + verifying ctest (brownfield, test-tooling only)

## Goal

Second slice of the L2/L3 gate-rework ladder (`mint/architecture-l2l3-gate.md`, Option 1, S2). Build the **IPv6 frame injector** `tests/inject/inject_l6.py` — the HARD PREREQUISITE the HLD's testability lens surfaced: `tests/inject/inject_l4.py` cannot emit IPv6, so every future IPv6/cidr6 oracle test (S4) would be *vacuously green* without a way to put a real IPv6 frame on the wire. S2 ships the injector + a verifying ctest NOW, so S4 can drop in cidr6 rules and actually assert matches.

**Pure test-tooling slice** — NO datapath/`.bpf.c`/`src/` change (S1 `c6e6b8d` already added the empty `ETH_P_IPV6` arm; the datapath does not classify IPv6 until S4). Anchor: `mint/architecture-l2l3-gate.md` Option 1 / S2 + the testability lens (the injector-prerequisite finding). `design.md` gets a new §5.52 amendment.

## Context: prior work
- Prior brief: archived as `mint/task-brief-mvp-4.11.md` (S1 gate-scaffold, shipped `c6e6b8d`).
- S1 (`c6e6b8d`, design.md §5.51): the `else if (inner_proto == bpf_htons(ETH_P_IPV6))` arm exists at `mac_filter.bpf.c:861` as an EMPTY seam → falls to `defaults[active]`. So a real IPv6 frame already routes to defaults (no classification yet).
- **Phase A code-grep verification (brief author ran — see evidence footer):** `inject_l4.py` is RAW-bytes (`struct.pack` + raw socket, NOT scapy); `inject_eth.py` is scapy (`Ether(...)`) — both styles coexist in-tree, scapy IS available. `inject_l6.py` confirmed ABSENT (NEW). `common.sh` provides `read_stats` (→ pass/drop_deny/drop_malformed), `wait_for_stats_sum`, `NSEXEC` discipline; L3/L4 injectors are called DIRECTLY (`${TEST_DIR}/inject/inject_*.py`), no common.sh wrapper. `T_IPV6_GATE_DEFAULT.sh` (S1) is the exact ctest template (step1 IPv4→DROP positive control via `inject_ipv4.py`; step2 0x86DD→defaults via `inject_eth.py`). Fixture `config_mac_drop_default_pass.yaml` reused. `inject_l4.py` CLI: `iface --dst-ip --src-ip --proto{tcp,udp,icmp} --dport --src-mac --dst-mac --vlan(append)`.
- **PI continuity: ALL existing PIs CONTINUE byte-equivalent.** No PI retired/extended/added (no datapath/src change). PI-7 loader.hpp zero-diff continues (loader untouched). PI-mvp-4.11-* (S1) all continue.

## Workflow rules (brownfield)
- **Architect**: read `architecture-l2l3-gate.md` (S2 + the testability-lens injector-prerequisite) + `design.md` §5.51 (S1 — the empty arm this injector exercises) + §6.5 invariants. EDIT `design.md` in place; append §5.52 documenting the injector + the verifying ctest. Resolve Q1 (impl style: scapy vs raw) + Q2 (ctest shape). **Be honest in §5.52** that the verifying ctest is primarily an INJECTOR SMOKE + harness-scaffold (a real-IPv6-header analog of S1's T_IPV6_GATE_DEFAULT) — it does NOT prove new datapath behavior (S1 already proved 0x86DD→defaults); its value is (a) inject_l6.py emits a frame the stack/datapath ingest without choking, (b) the inject→counter harness S4 reuses for cidr6 matching.
- **Impl**: write `tests/inject/inject_l6.py` per Q1; add the verifying ctest per Q2; register in `tests/CMakeLists.txt` with `RESOURCE_LOCK xdp_fixture` (guard #12). NO `src/`, NO `.bpf.c`, NO `mac_filter.h`, NO `config.*`, NO `loader.cpp`, NO VERSION change. `git diff -- src/` MUST be EMPTY.
- **Tester**: the verifying ctest IS the deliverable's proof (tester may author it or verify the impl's — per project convention the tester owns the ctest; coordinate via design FileList). Regression net = existing suite stays green (no datapath change → nothing should move). New ctest: real IPv6 frame from `inject_l6.py` → `defaults[active]` (DROP_DENY delta 0, DROP_MALFORMED delta 0) + a positive control (IPv4→DROP, proving the machinery is live). Full `-j4` run green (B19 `build_cpu` lock holds). Count baseline 87 → 88.
- **Reviewer**: 5-point brownfield. Load-bearing checks: (1) `git diff -- src/` EMPTY — pure tests/ slice, NO datapath change (the S1 arm is untouched); (2) `inject_l6.py` emits a well-formed IPv6 frame (40-byte base header: version=6, payload_len, next-header, hop-limit, 128-bit src/dst; EtherType 0x86DD; optional VLAN) — NO extension headers (S6); (3) the verifying ctest genuinely injects a REAL IPv6 frame (not raw 0x86DD) and asserts →defaults; (4) no axis/map/schema/VERSION change; (5) existing suite green (behaviour preserved — nothing moved). Honest-scope check: the ctest is an injector-smoke, not a new-behavior proof — do NOT flag the S1/S2 ctest similarity as redundancy ([OOS] N/A; it validates the NEW tool).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.12-1: injector implementation style → **architect's realizability call (scapy recommended)**
inject_l4.py is raw-`struct.pack`; inject_eth.py is scapy. Both coexist. Recommendation: **scapy `IPv6()/TCP()/UDP()/ICMPv6*()`** — correct-by-construction (checksums, payload_len), far simpler than hand-packing the 40-byte v6 header, scapy is already a test dependency, and S4 extends it trivially (cidr6 test addresses). But raw-`struct.pack` (mirror inject_l4 exactly, no new scapy reliance for the L3/L4 family) is a legitimate alternative. **Architect owns the realizability decision** (per the brief-author-doesn't-over-specify-mechanism rule) — resolve as Q1.

### HG-mvp-4.12-2: verifying ctest — new file vs extend S1's → **NEW `T_IPV6_INJECT_DEFAULT.sh`, do NOT edit `T_IPV6_GATE_DEFAULT.sh`**
A NEW ctest (mirroring T_IPV6_GATE_DEFAULT but step2 uses `inject_l6.py`) keeps S1's file byte-untouched (avoids the editing-an-S1-file confusion the prior cycle's review tripped on). Resolve as Q2.

## Open mechanism questions (architect decides; document in §5.52)

### Q1: `inject_l6.py` implementation style
- **A1 (recommended)**: scapy — `Ether(type=0x86DD)/Dot1Q(...)?/IPv6(src,dst,nh)/{TCP|UDP|ICMPv6EchoRequest}`. Correct-by-construction; mirrors inject_eth.py's scapy precedent; S4-extensible.
- **A2**: raw `struct.pack` — mirror inject_l4.py exactly (hand-pack the 40-byte v6 header + L4 + checksums). No new scapy reliance for the L3/L4 family.
- **Recommendation**: A1 (scapy) — simplicity + correctness for a 40-byte header with computed lengths; the manual-checksum surface of A2 is error-prone and buys only stylistic consistency with one sibling. Architect overrides if it wants raw-style parity with inject_l4 or to avoid scapy.

### Q2: verifying ctest shape
- **A1 (recommended)**: NEW `tests/T_IPV6_INJECT_DEFAULT.sh` mirroring `T_IPV6_GATE_DEFAULT.sh`: step1 IPv4→DROP (positive control, `inject_ipv4.py`), step2 a REAL IPv6 frame via `inject_l6.py` → NOT dropped (defaults): DROP_DENY delta 0 AND DROP_MALFORMED delta 0. Reuse fixture `config_mac_drop_default_pass.yaml`. `RESOURCE_LOCK xdp_fixture`.
- **A2**: a python-level injector self-test only (assert the emitted bytes parse as a valid IPv6 frame) — no datapath integration.
- **Recommendation**: A1 — it both smoke-tests the injector end-to-end (frame traverses veth→XDP→counter) AND establishes the inject→counter harness S4 reuses. A2 is weaker (no integration); MAY be added as a cheap extra (architect-flex) but is not a substitute.

## Scope (cycle MVP-4.12 — concrete items)

### Item S2-1 — `inject_l6.py` IPv6 frame injector
**Where**: NEW `tests/inject/inject_l6.py`. CLI mirrors `inject_l4.py`: `iface --dst-ip --src-ip` (IPv6 literals) `--proto {tcp,udp,icmp6} --dport --src-mac --dst-mac --vlan`(append). Emits Ethernet (+optional 802.1Q) + 40-byte IPv6 base header (EtherType 0x86DD) + L4. NO extension headers (base-header only; ext-walk is S6) — leave a clean seam/comment for S6. Implementation style per Q1.

### Item S2-2 — verifying ctest (per Q2)
**Where**: NEW `tests/T_IPV6_INJECT_DEFAULT.sh` (mirror `T_IPV6_GATE_DEFAULT.sh`); register in `tests/CMakeLists.txt` (`RESOURCE_LOCK xdp_fixture`, guard #12, timeout + skip-77 env-guard mirroring T_IPV6_GATE_DEFAULT). Assertion: real IPv6 frame → defaults (DROP_DENY + DROP_MALFORMED deltas 0); IPv4 positive control → DROP.

## Out of scope (explicit)
- **S3 LPM-template refactor** (loader-only — parallel slice, NOT bundled here), **S4 cidr6 axes + 128-bit `close_prefixes6` + `bitvec_oracle_prod.py` v6 extension**, **S5 ethertype match-axis**, **S6 ext-header walk + family-coherence reject**.
- ANY `src/` / `.bpf.c` / `mac_filter.h` / `config.*` / `loader.cpp` change; ANY axis/map/schema/VERSION change.
- IPv6 *matching* of any kind — S2 frames only ever hit `defaults[active]` (the S1 arm is empty). The injector builds frames; nothing classifies them until S4.
- IPv6 extension headers (S6); ICMPv6 beyond a basic echo (if `icmp6` is included at all — architect-flex).
- The PO forks deferred to their slices (EtherType split, schema bump, gate.d hoist, `ethertype:ipv4`).

## Definition of done
- §5.52 amendment in `design.md` (injector + verifying ctest + Q1/Q2 resolutions + the honest injector-smoke framing).
- `tests/inject/inject_l6.py` emits a well-formed base-header IPv6 frame (no ext-headers).
- NEW verifying ctest GREEN (real IPv6 → defaults); full `-j4` run no flake; count 87 → 88.
- `git diff -- src/` EMPTY; NO VERSION bump; all existing PIs continue byte-equivalent.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: existing CMake (no compile change — pure tests/; CMakeLists registers the new ctest).
- Runtime: python3 + scapy (already a test dep — `inject_eth.py` uses it) IF Q1=A1; raw socket + `CAP_NET_RAW`/sudo (the `NSEXEC` discipline, already in common.sh) regardless.
- Kernel/platform: none new — frames traverse the existing veth/netns fixture; the S1 datapath already recognizes 0x86DD.

## Packs to load (orchestrator: inject into spawn prompts)
```yaml
mode: brownfield
packs:
  architect:  []
  impl:       []
  tester:     []
  reviewer:   []
```

---

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])
**Mechanical, single-architect.** The L2/L3 design-space was resolved by `/mint-hld` (`architecture-l2l3-gate.md`); S2 is a precisely-bounded test-tooling slice (build the injector the testability lens demanded + its verifying ctest). Not multi-axis — the only open choice is the injector's impl style (Q1, a realizability call left to the architect). `/mint-hld` NOT needed. Single-architect via `/mint-dev`.

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author ran these; architect re-verifies + extends:
- `grep -nE 'struct.pack|scapy|Ether\(|socket' tests/inject/inject_l4.py tests/inject/inject_eth.py` — confirm inject_l4=raw, inject_eth=scapy (the two style precedents for Q1).
- `test -f tests/inject/inject_l6.py` — confirm ABSENT (you are creating it).
- `grep -nE 'read_stats|wait_for_stats_sum|NSEXEC|inject' tests/lib/common.sh` — confirm the stats-delta + NSEXEC helpers the ctest reuses; note L3/L4 injectors are called directly (no common.sh wrapper).
- Read `tests/T_IPV6_GATE_DEFAULT.sh` + `tests/inject/inject_ipv4.py` — the ctest template + the IPv4 positive-control injector.
- Confirm the S1 `ETH_P_IPV6` arm at `mac_filter.bpf.c:861` is the empty seam (so a real v6 frame → defaults, NOT drop) — you do NOT touch it.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #5** (Phase A code-grep) — always; architect re-runs the greps above.
- **Guard #12** (RESOURCE_LOCK for shared host state) — DIRECTLY applies: the new ctest sets up veth/netns + loads the BPF object → MUST carry `RESOURCE_LOCK xdp_fixture` (mirror T_IPV6_GATE_DEFAULT's registration).
- **Guard #9** (helper-location duplication-over-extraction) — watch: `inject_l6.py` will share structure with `inject_l4.py`; prefer a self-contained sibling script (the in-tree precedent is one script per family — inject_ipv4/inject_l4/inject_eth are separate) over extracting a shared module this slice.
- **Guard #11** (VERSION-bump literal propagation) — N/A (no bump).
- **Guard #10** (catalog arithmetic) — N/A (no constexpr table/array; BITVEC_NUM_AXES untouched).

> Operative-semantic note: line/count anchors (`:861`, count 87→88) are SHOULD-level orientation, not literal-match contracts. The MUST contracts: `git diff -- src/` EMPTY (pure tooling slice), a well-formed base-header IPv6 frame, real-IPv6→defaults, no VERSION/axis/map/schema change. Impl deviations preserving these (a differently-shaped but valid injector, the ctest landing at a different line) are `inline-merge`.
