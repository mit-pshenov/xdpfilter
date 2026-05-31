# Design brief — S4: IPv6 CIDR matching axes (cidr6) for the L2/L3 gate ladder

> **For `/mint-hld`.** This brief explores the design space for the heaviest slice of the L2/L3 gate-rework: adding IPv6 CIDR (`dst6` / `src6`) matching to the production bit-vector AND classifier. It is NOT an implementation commitment — the grounder discharges sizing/sequencing claims at the terminal phase, and the briefer re-discharges at slice-time. Author the synthesis with **discharge tags** on every sizing/sequencing/assumption/open-Q claim (the grounder enforces this).

## Topic

The L2/L3 gate ladder has shipped **S1** (gate-scaffold: `mac_filter.bpf.c` reshaped into `if(ETH_P_IP)/else if(ETH_P_IPV6)` with an empty IPv6 arm → defaults; IPv4 bit-identical) and **S2** (`tests/inject/inject_l6.py`: a real-IPv6-frame injector, the test prerequisite). The IPv6 arm at `mac_filter.bpf.c:861` is a **proven-empty seam** that currently falls through to `defaults[active]`. S3 (an LPM-template refactor) was **rejected as premature abstraction** — the template-vs-copy-paste decision belongs INSIDE this slice, because `close_prefixes` masking is 32-bit-typed and cannot be templated without first knowing the v6 representation.

**S4 fills that seam:** add IPv6 CIDR matching as new LPM axes in the existing bit-vector AND classifier, so rules can match on IPv6 source/destination subnets the same way they already match IPv4 (`dst_cidr`/`src_cidr`).

## Motivation

IPv6 is a real Gi-interface traffic class; today every IPv6 frame is unclassifiable (→ defaults only). This is the #1 functional gap after the IPv4 rule-model shipped. The injector (S2) now makes IPv6 oracle tests non-vacuous, so the slice is finally testable.

## Current state (code facts — anchor here, verify don't trust)

- **Match model:** 6 AND-composed axes — `BITVEC_NUM_AXES 6` at `src/common/mac_filter.h:161` (`BV_AXIS_DST=0, SRC=1, PROTO=2, PORT=3, VLAN=4, MAC=5`). Composition is per-axis `__u64` bitmask intersection + `__builtin_ffsll` first-match; wildcard halves at `wildcard[active*BITVEC_NUM_AXES + axis]`.
- **IPv4 CIDR axis:** `struct xdpmf_cidr_v4 { unsigned int prefixlen; unsigned int addr; }` packed, LPM_TRIE key (`mac_filter.h:40`). Maps `cidr_allowlist_a/_b` (LPM_TRIE inners) + `cidr_rulesets` (ARRAY_OF_MAPS outer), in `kManagedMaps[]` at `loader.cpp:157`.
- **Prefix closure (THE sharp edge):** `close_prefixes()` at `loader.cpp:1220` returns `std::vector<std::uint64_t>`; the cover test is `(pi.host_addr & m) == (pj.host_addr & m)` where `host_addr` and `host_mask(prefixlen)` are **32-bit** (`std::uint32_t m`). There is NO 128-bit path. A v6 closure is NET-NEW arithmetic over a 128-bit address (likely two `__u64` limbs or a byte array), not a parameterization of the existing function. Guard #23 (overlap-vector / cover-direction mandate) applies and must extend to 128 bits incl. partial-byte masking.
- **Datapath seam:** `mac_filter.bpf.c:861` — the empty `else if (inner_proto == ETH_P_IPV6)` arm. S4 lands the ipv6hdr bounds-check + deref + the dst6/src6 LPM lookups HERE. NO IPv6 extension-header walk this slice (that is the deferred S6; the proto/port axes see the base nexthdr only).
- **Config:** IPv6 CIDR is currently REJECTED at the validator (`config.cpp:408/421`, "IPv6 CIDR not supported"). S4 must WIDEN the config surface (retire that reject) — and there is a second Config-construction path (`attach --allow`, ~`loader.cpp:1476`) that bypasses the schema validator (guard #24 territory).
- **Oracle:** `tests/bitvec/bitvec_oracle_prod.py` — naive O(N) first-match, per-axis hand-transcribed tables, deliberately algorithm-different from the datapath (closure/wildcard/ffsll live only in production). v6 needs a new axis-representation + new oracle vectors.
- **Injector:** `tests/inject/inject_l6.py` (S2) emits base-header IPv6 frames; the inject→counter→oracle harness exists.

## Scope of this design round

How to add IPv6 dst/src CIDR matching to the bit-vector AND classifier. In scope: the v6 address representation (struct + LPM key), the new axes (`BITVEC_NUM_AXES` growth + new maps + `kManagedMaps[]` rows), the 128-bit prefix-closure, the datapath lookup at the seam, the config-surface widening, and the oracle/test strategy. The architects should map the full space, then the synthesizer composes directions with HONEST discharge tags on every sizing/sequencing/assumption claim.

## Constraints / non-goals

- **No IPv6 extension-header walk** — base nexthdr only; ext-walk is the deferred S6. Proto/port axes on ext-header-bearing v6 frames see the first nexthdr, not true L4 (document the honesty boundary).
- **No EtherType match-axis** — that is a separate slice (S5); do not fold it in.
- **Preserve IPv4 verdict bit-identical**, the single-`active_idx` atomic swap, `schema_version 2` (additive `std::optional` fields), first-match-by-id + `defaults[active]` fallthrough.
- **5.15 verifier floor** is the realizability target (datapath must load; 128-bit compare must not blow the instruction/stack budget).
- This is eBPF model-validation, NOT the perf datapath — relative-cost / non-foreclosure only, no absolute perf numbers.

## Open questions for the architects to surface (NOT to pre-answer)

- Is S4 one slice, or must the 128-bit closure split into its own slice / a required pre-slice spike? (The hidden assumption "128-bit closure is just a wider masked compare" is REFUTED by the code — `close_prefixes` is 32-bit-typed. Tag the sizing honestly.)
- v6 address representation: two `__u64` limbs vs 16-byte array vs `struct in6_addr` — which serves closure arithmetic, the LPM key, AND the oracle cleanly?
- Template the LPM family (v4+v6 shared) NOW, or copy-paste v6 and defer templating? (S3 was rejected to defer exactly this decision to here.)
- Does the 128-bit masked compare load on the 5.15 verifier within budget, or is a spike needed before the slice is sized?

```yaml
architects:
  parallel:
    - name: classifier
      lens: "The bit-vector AND classifier as the central artifact. You see how the new IPv6 dst6/src6 axes slot into the existing 6-axis per-__u64-bitmask-intersection + ffsll first-match model: the v6 address representation, the new xdpmf_cidr_v6 struct + LPM_TRIE key shape, BITVEC_NUM_AXES growth (6→8), the new ARRAY_OF_MAPS map trios + kManagedMaps[] rows, the wildcard-half indexing, and the datapath lookup landing at the mac_filter.bpf.c:861 seam. You own the STRUCTURE — how the pieces compose."
      scope: "Cover: address representation choice, struct/key layout, axis-count + map growth mechanics, datapath lookup shape at the seam, how dst6/src6 ride the single active_idx swap. Do NOT score verifier-load feasibility (realizability's call), the closure cover-direction correctness (closure's call), or oracle/test design (testability's call) — name them as cross-lens hooks. Viability filter: must compose with the existing v4 axes without reshaping them."
      sources:
        - "src/bpf/mac_filter.bpf.c (the AND classifier + the :861 seam + the v4 cidr lookup it mirrors)"
        - "src/common/mac_filter.h (BITVEC_NUM_AXES, BV_AXIS_*, xdpmf_cidr_v4, map-name constants)"
        - "src/lib/loader.cpp (kManagedMaps[], lower_axis, the populate path)"
        - "Linux LPM_TRIE map semantics (key must begin with u32 prefixlen; 128-bit address keys)"
    - name: closure
      lens: "Prefix-closure correctness at 128 bits — the sharp edge. You see ONLY the cover-direction arithmetic: given overlapping IPv6 prefixes where a less-specific covering rule may have a lower id (higher priority) than a more-specific one, does the closure store the covering rules' bits correctly? You own the 128-bit masked-compare math (two-limb vs byte-array masking, partial-last-byte/partial-limb masking at arbitrary prefixlen 0..128), the extension of close_prefixes() (which is 32-bit-typed today), and guard #23's overlap-vector mandate AT 128 BITS. The single most common bit-vector bug is closure cover-direction; your job is to make it impossible."
      scope: "Cover: the 128-bit cover test, masking at arbitrary prefix length, the host_mask analog, whether closure shares code with v4 (32-bit) or forks. Do NOT score the map/struct layout (classifier's call) or whether it verifier-loads (realizability's call) — but DO state the representation your math NEEDS as a cross-lens hook to classifier. Viability filter: the math must be provably correct for the full 0..128 prefixlen range incl. partial-byte boundaries."
      sources:
        - "src/lib/loader.cpp:1220 close_prefixes() + host_mask (the 32-bit precedent to extend)"
        - "mint/design.md guard #23 (overlap-vector / cover-direction mandate, §5.42 bit-vector spike origin)"
        - "IPv6 addressing / prefix arithmetic (RFC 4291 prefix semantics, 128-bit masking)"
    - name: realizability
      lens: "Can it actually be BUILT and LOADED on the target kernel? You see ONLY the platform constraints: does a 128-bit masked compare (or two-limb LPM lookup) fit the 5.15 BPF verifier's instruction/complexity budget and the 512→256B stack? Does the ipv6hdr bounds-check + deref at the seam satisfy the verifier's bounds tracking? Is the LPM_TRIE with a 128-bit-address key a kernel-supported shape? You own feasibility — distinct from 'is it correct' (closure) and 'is it cheap' (not in this round)."
      scope: "Cover: verifier instruction/complexity/stack budget for the v6 datapath path, LPM_TRIE 128-bit-key support, bounds-check shape, whether a spike (real bpftool prog load on the 6.1 host) is needed BEFORE the slice can be sized. Do NOT design the struct (classifier) or the closure math (closure) — assess whether THEIR proposals load. Flag any claim that needs a spike to discharge. Viability filter: must load on the 6.1 host; 5.15 floor is the documented target."
      sources:
        - "src/bpf/mac_filter.bpf.c (existing v4 datapath that already verifies; the stack/instruction precedent)"
        - "mint/design.md (guard #25 5.15-verifier-floor decisions, prior spike pattern §5.42)"
        - "Linux BPF verifier limits on 5.15 (instruction count, complexity, LPM_TRIE, stack)"
    - name: testability
      lens: "How is IPv6 CIDR matching PROVEN correct? You see ONLY the verification surface: how the oracle (bitvec_oracle_prod.py, naive O(N), algorithm-different by design) extends to v6 axes, what NEW test vectors prove the closure cover-direction at 128 bits (guard #23's must-have: an overlapping-prefix vector where a less-specific covering rule has LOWER id), how inject_l6.py (S2) drives real v6 frames through the inject→counter→oracle harness, and which behaviors are UNDETECTABLE without a purpose-built vector (e.g. closure-direction is invisible if the longest match happens to be the intended winner). You own provability — distinct from correctness (closure designs the math; you design the proof that catches it being wrong)."
      scope: "Cover: oracle v6 extension shape, the guard-#23 v6 overlap-vector, the inject→counter assertion design, base-header-only test honesty (no ext-walk), fixtures. Do NOT design the closure math (closure) or the struct (classifier) — design the tests that would CATCH them being wrong. Viability filter: every proposed axis must have a non-vacuous test (the S2 injector makes this possible)."
      sources:
        - "tests/bitvec/bitvec_oracle_prod.py (the O(N) oracle to extend; the per-axis table pattern)"
        - "tests/inject/inject_l6.py (S2 IPv6 injector) + tests/T_IPV6_INJECT_DEFAULT.sh (the harness)"
        - "mint/design.md guard #23 (the overlap-vector test mandate) + §6.61/§6.66/§6.69 oracle-agreement ctests"
  sequential:
    - name: contrarian
      lens: "Skeptical engineer. Read all four parallel outputs and poke holes. Your sharpest question: is S4 honestly ONE slice, or is the team about to repeat the S1→S6-ladder mistake by under-sizing it? Specifically interrogate: (a) does the 128-bit closure deserve its own slice or a required pre-slice spike, given close_prefixes is 32-bit-typed net-new work; (b) is the template-vs-copy-paste decision being dodged again; (c) does the config-surface widening (incl. the attach --allow bypass path, guard #24) hide scope; (d) are any 'one slice' / sequencing claims untagged or tagged grounded without evidence. You integrate the four lenses into a lean with EXPLICIT discharge tags."
      scope: "Read classifier + closure + realizability + testability. Surface contradictions and hidden scope; produce an integrated lean that sizes S4 honestly with discharge tags. Do NOT introduce a new axis no parallel architect proposed — note it as an open question. Re-test any premise inherited from the architecture-l2l3-gate.md prior round against the CURRENT code facts in this brief."
      inputs: [classifier, closure, realizability, testability]
      sources:
        - "mint/architecture-l2l3-gate.md (the prior gate-rework HLD whose S4 sizing this round re-grounds)"

output:
  path: "mint/architecture-l2l3-gate.md"
  mode: amend
  section: "## S4 cidr6 — IPv6 CIDR axes (design round)"
  position: after
  anchor: "## Open questions (need human input)"

options:
  skip_design_reviewer: false
  max_rework_rounds: 2
```
