# Task brief — MVP-4.35 / B42: redirect verb — XDP-native steer-to-DPI (brownfield, FIRST datapath-feature slice)

## Goal

Slice 1 ("Option 1 — Bare Verb") of `mint/architecture-mirror-redirect.md` (mint-hld synthesis
`eaeba64`; reviewer pass r3, grounder clean-with-gates, PO ruling: build redirect now, defer
mirror). Add a per-rule **redirect** action: matched traffic is actively diverted (XDP-native
`bpf_redirect_map` + a `DEVMAP`) to a single configured DPI-feed interface — the first **steering**
verb, turning the filter from terminal allow/drop into a selector. Redirect (active selective
divert by the 9-axis match-model) is distinct from passive hardware SPAN (which copies); mirror
(the passive-copy verb) is **deferred** (needs a TC/TCX program — spike-gated).

**This is the FIRST datapath-changing slice since the cleanup arc.** Unlike B40/B41 (pure host-side
refactors that held insn 3437), this ADDS a BPF branch → the xdp insn-count **re-baselines** (3437
→ a new N). The byte-identity invariant shifts accordingly (see §6.5 below): the new branch fires
**only for redirect rules**, so **PASS/DROP verdict-identity on the existing oracle corpus MUST
hold**, while `T_INSN_BASELINE_GATE` gets a documented new expected value.

## Context: prior work

- mint-hld synthesis + discharge ledger: `mint/architecture-mirror-redirect.md` (`eaeba64`).
  Recommendation Option 1 (single global tap, no target ABI); Option 2 (per-rule targets) +
  Option 3 (mirror/TCX) are no-rework forward supersets — OUT of this slice.
- The action ABI was pre-shaped for this: `enum xdpmf_action_type` carries the in-code comment
  "future MVP-3.8+ may extend (MIRROR/RL/TAG)" (`xdpfilter.h:275`); the action axis is kept RAW
  through `CompiledRuleset` (no mask-lowering changes).
- Phase-2 brief-author grep verification + the 8 discharge-ledger slice-time rechecks are
  **discharged here** (see evidence footer). The synthesis's "cheap" claims had understated costs
  the rechecks exposed (STAT_MAX brace-init, the BPF `.maps` decl, the NET-NEW 2-iface oracle) —
  all folded into the FileList below.
- PI continuity: **PI-7** (`loader.hpp` zero-diff) CONTINUES (no public API change). **§5.35
  counter-monotonicity** untouched. **CompiledRuleset/RulesetDelta** untouched (action stays raw).

## Workflow rules (brownfield)

- **Architect**: read the synthesis (`architecture-mirror-redirect.md` Option 1 + discharge ledger),
  the action ABI (`xdpfilter.h:252-283`), the classifier dispatch (`classifier.h:183-202`),
  `populate_action_table` + the rules-inner action_id ternary (`loader.cpp`), the config
  schema/validation (`config.{hpp,cpp}`), the exporter STAT path (`prom_format.cpp`/`stats_reader.*`),
  and the veth harness (`tests/lib/common.sh`). EDIT `mint/design.md` in place; append **§5.75**.
- **Impl**: FileList per brownfield DIFF. This slice spans the BPF datapath + loader + config +
  exporter + a NET-NEW test harness — larger than recent slices; expect a broad FileList.
- **Tester**: the headline deliverable is **SELECT-B** — a 2-iface RX-sink delivery oracle (inject
  on source → assert the sink counter bumped AND the original-path STAT did NOT) that proves the
  divert physically lands, not just that the classifier decided. Plus SELECT-A (STAT_REDIRECT
  counter + `bpftool` devmap-dump). SELECT-C (`BPF_F_TEST_XDP_LIVE_FRAMES`) optional.
- **Reviewer**: 5-point brownfield. Special attention: (a) **PASS/DROP verdict-identity** on the
  existing oracle corpus (the new branch must NOT alter non-redirect verdicts); (b) the insn
  re-baseline is DOCUMENTED + intentional (not silent drift); (c) `action_table` PASS/DROP entries
  [0]/[1] unchanged (REDIRECT appended at [2]); (d) the DEVMAP is handled cleanly by the
  single-non-double-buffered apply walk (guard #15/#16 territory).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-mvp-4.35-1: schema evolution → **additive; supported set {2,3}, NOT a hard cutover**
Adding an optional top-level `steering:` block is backward-compatible (existing v2 configs without
steering still validate) — UNLIKE the v1→v2 axis-retirement hard cutover (§5.43). Default: bump the
example/canonical to `schema_version: 3` but ACCEPT {2,3}; a v2 config simply has no steering. The
`find_key` unknown-key allowlist (`config.cpp` ~:580) MUST absorb `steering:` (else exit-9). Architect
may choose a hard {3} cutover only with explicit justification (it would break steering-less v2 — discouraged).

### HG-mvp-4.35-2: target-down fallback → **`bpf_redirect_map(..., XDP_PASS)` on miss (degrade to original flow)**
A down/absent devmap target should degrade to the packet's ORIGINAL disposition (PASS-on-miss), not
blackhole. **Spike #3** (discharge ledger): confirm the target kernel honors the low-flag-bits
miss-fallback as assumed. Default: ship happy-path redirect + set the PASS-on-miss flag; the
architect/impl runs the spike on the target kernel and adds a negative ctest (redirect to an
absent target → original verdict) if cheap. Target-down graceful-degradation is Option-1 hardening,
NOT a slice blocker.

### HG-mvp-4.35-3: config grammar → **top-level `steering: { redirect_to: <iface> }` (single global tap)**
No per-rule `target:` (that is the Option-2 superset, OOS). A rule opts in via `action: redirect`;
the destination is the one global `redirect_to` iface. Validation: `redirect_to` iface must resolve
to an ifindex at apply (fail-closed at apply on an unresolvable target).

### HG-mvp-4.35-4: action_table sizing → **reserve MIRROR; `ACTION_MAX 2→4`, ship only REDIRECT=2**
`enum xdpmf_action_type { PASS=0, DROP=1, REDIRECT=2, MIRROR=3 (reserved), MAX=4 }`. Reserving
MIRROR=3 now sizes the pinned `action_table ARRAY[ACTION_MAX]` once, so the deferred mirror slice
need not re-grow the pinned map. PASS/DROP entries [0]/[1] byte-identical; [2]=REDIRECT added;
[3] reserved.

### HG-mvp-4.35-5: VERSION → **bump 0.16.0 → 0.17.0** (first user-facing capability since the match-model)
Redirect is a new operator-visible feature (new config grammar + new verb). Guard #11 — propagate
the literal to all test/doc/CHANGELOG sites. Architect confirms the propagation set.

## Open mechanism questions (architect decides; document in §5.75)

### Q1: DEVMAP type + keying
- **A1**: plain `BPF_MAP_TYPE_DEVMAP`, single entry at key 0 = the global target ifindex.
- **A2**: `BPF_MAP_TYPE_DEVMAP_HASH`.
- **Recommendation**: **A1** (one global tap → one entry; `max_entries=1` or a small fixed size).
  Simplest; the redirect helper uses key 0.

### Q2: where the target ifindex is resolved + written into the devmap
- **A1**: loader resolves `redirect_to` name → ifindex and fills `redirect_devmap[0]` during apply
  (like other config-derived maps; via the `materialize`/apply path).
- **Recommendation**: **A1** — consistent with the existing config→maps materialization; the devmap
  is "just another pinned, userspace-filled map" in `kManagedMaps[]` (single, NOT double-buffered).

## Scope (cycle 1 — concrete items; estimates are UPPER BOUNDS)

### Item SR-1 — action + stat enums (`src/common/xdpfilter.h`)
`xdpmf_action_type`: add `ACTION_REDIRECT=2`, `ACTION_MIRROR=3` (reserved), `ACTION_MAX 2→4`
(`:272-276`). `xdpfilter_stat`: add `STAT_REDIRECT` (=4), `STAT_MAX 4→5` (`:68-73`). The
`action_table ARRAY[ACTION_MAX]` and `stats ARRAY[STAT_MAX]` max_entries follow ACTION_MAX/STAT_MAX.
The two `static_assert(sizeof(...)==4)` (`:344-345`) stay UNTOUCHED (no struct widen — Option 1).

### Item SR-2 — redirect devmap declaration (`src/bpf/maps.h`)
NEW `redirect_devmap` `SEC(".maps")` `BPF_MAP_TYPE_DEVMAP` (per Q1). The skeleton `SkelMapsT` member
is auto-generated from this decl (recheck #7 — the loader-side row alone is insufficient).

### Item SR-3 — classifier redirect branch (`src/bpf/classifier.h`)
**APPEND** after the existing `action_type == ACTION_DROP` test (`:195-202`, which falls through to
STAT_PASS_CIDR + XDP_PASS): `if (a && a->action_type == ACTION_REDIRECT) { bump STAT_REDIRECT;
return bpf_redirect_map(&redirect_devmap, 0, <PASS-on-miss flag>); }` → `XDP_REDIRECT`. The DROP
test + PASS fallthrough stay byte-identical → **PASS/DROP verdict-identity for non-redirect rules**.

### Item SR-4 — loader: devmap + action_table + action_id (`src/lib/loader.cpp`)
- `kManagedMaps[]` (`~:137-179`): one `redirect_devmap` row (single, NON-double-buffered — verify the
  clear/pin/reuse walk accepts it cleanly; guard #15/#16).
- `populate_action_table` (`~:1532-1552`): add the REDIRECT entry at index [2] (PASS/DROP [0]/[1]
  UNCHANGED — recheck #1).
- rules-inner `action_id` assignment (`~:1397-1399`): 2-way ternary → 3-way (Pass→PASS, Drop→DROP,
  Redirect→REDIRECT) — recheck #2.
- fill `redirect_devmap[0]` with the resolved `steering.redirect_to` ifindex at apply (Q2/A1);
  fail-closed at apply on an unresolvable target.

### Item SR-5 — config schema + validation (`src/lib/config.{hpp,cpp}`)
- `RuleAction` gains `Redirect` (`config.hpp:34`); `parse_rule_action` accepts `'redirect'`
  (`config.cpp:124-125`).
- NEW top-level `steering: { redirect_to: <iface> }` block parsed into `Config` (a steering target
  field); the `find_key` unknown-key allowlist (`~:580`) absorbs `steering:`.
- schema_version: per HG-1 ({2,3} additive). Cross-validation: `action: redirect` requires
  `steering.redirect_to` present (else config error).
- `docs/CONFIG_SCHEMA.md` updated (doc-ripple).

### Item SR-6 — exporter STAT_REDIRECT (`src/exporter/prom_format.cpp` + `stats_reader.hpp`)
- `verdict_label` switch (`prom_format.cpp:28-31`): add `case STAT_REDIRECT: return "redirect";`.
- `stats_reader.hpp:34` HARD-CODED brace-init `stats[STAT_MAX] = {0,0,0,0}` → `{0,0,0,0,0}`
  (recheck #5 — the literal the "cheap slot" framing omitted). STAT_MAX-bounded loops
  (`prom_format.cpp:72`, `stats_reader.cpp:157`) auto-adjust.

### Item SR-7 — test harness: 2-iface delivery oracle + ctests (NET-NEW — recheck #8)
- NEW `tests/inject/sink_xdp.bpf.c` — a counting sink XDP prog on the target peer.
- `tests/lib/common.sh` (`~:116-188`): grow `setup_veth`/`cleanup_veth` to a SECOND veth pair +
  a `read_sink` helper (the `STAT_PASS_CIDR` widening at `~:200,235` is the read-helper precedent).
- NEW `T_REDIRECT_*` ctests: **SELECT-B** (inject on source → sink counter==1 AND original STAT
  unchanged → divert landed + original consumed); **SELECT-A** (STAT_REDIRECT counter + `bpftool`
  devmap-dump); optional SELECT-C (`BPF_F_TEST_XDP_LIVE_FRAMES`). Local/self-hosted gate (netns/root);
  the build-only subset rides `XDPMF_CI_BUILD_ONLY` where applicable.
- `T_INSN_BASELINE_GATE.sh:71`: update `XDPMF_PROD_INSN_BASELINE` 3437 → the new measured N (the
  re-baseline; document the delta in design as the redirect-branch cost).

## Out of scope (explicit)

- **MIRROR** (clone-and-continue) — deferred; needs a TC/TCX program; gated by discharge spikes #1
  (TCX kernel ≥6.6) + #2 (XDP→TC metadata handoff + skb-clone perf). Reserved as `ACTION_MIRROR=3`.
- **Per-rule redirect targets** (Option 2: `target_id` + `steering_targets` table) — forward-compat
  superset; slice 2+.
- **tag / rate-limit** verbs; **AF_XDP/DPDK** datapaths; **`apply --dry-run`** — all OOS.
- **mirror×verdict interaction policy** (mirror-then-DROP, redirect+mirror co-existence) — mirror-gated,
  unowned semantics axis, PO/design input required before any mirror slice (NOT this one — redirect is
  XOR pass/drop, no interaction arises).

## Definition of done

- §5.75 amendment in `mint/design.md`.
- PI-7 (`loader.hpp` zero-diff) CONTINUES; §5.35 counter-monotonicity untouched; CompiledRuleset/
  RulesetDelta untouched.
- **§6.5 invariant shift (documented):** PASS/DROP **verdict-identity** on the existing oracle corpus
  HOLDS (T_*_ORACLE_AGREEMENT green for non-redirect rules); `T_INSN_BASELINE_GATE` re-baselined
  3437→N with the delta documented as the redirect-branch cost (NOT silent drift).
- NEW `T_REDIRECT_*` ctests green (SELECT-B delivery oracle is the headline; SELECT-A counter+dump).
- VERSION 0.16.0→0.17.0 propagated (guard #11).
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies

- Build: C++23 + clang BPF (existing); a new BPF object (`sink_xdp.bpf.c`) for the test oracle.
- Runtime/kernel: `XDP_REDIRECT` + `bpf_redirect_map` (≥4.14, mainstream); the redirect-miss fallback
  flag semantics (spike #3, target kernel). NO TCX dependency (that is mirror, deferred).
- Test: netns + root for SELECT-B (local gate); a second veth pair.

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

## Pre-brief sanity check (per mint-hld-scope-discipline)

**MECHANICAL (carry-over from a DISCHARGED hld)** — single-architect `/mint-dev`. The design-space
(XDP-native redirect vs TC, action-ABI growth, target model, sequencing) was resolved by the mint-hld
round (`eaeba64`, reviewer pass r3, grounder clean-with-gates). The 8 slice-time rechecks are
discharged in Phase 2 (below). Multi-axis? No — Option 1 selected + grounded. Expensive-to-undo?
Low-medium — additive verb, PASS/DROP verdict-identity preserved, the action ABI was pre-shaped.
PRESERVE-vs-RESET sub-check: the new `redirect_devmap` is config-derived (RESET-on-apply, like the
axis maps — reflects current config), NOT a stateful PRESERVE counter; no copy-forward needed.
Rolling-wave: discharge ledger present; spikes #1/#2 gate MIRROR (out of scope), spike #3 gates the
target-down HARDENING (not the happy-path slice). No undischarged blocker.

## Notes for architect Phase A code-grep discipline

Brief author ran these; architect re-verifies + extends:
- `grep -nE 'ACTION_PASS|ACTION_DROP|ACTION_MAX' src/common/xdpfilter.h` — enum + `static_assert sizeof==4` (:344-345) MUST stay.
- `grep -nE 'STAT_MAX|stats\[STAT_MAX\]' src/exporter/stats_reader.hpp` — the `{0,0,0,0}` brace-init (:34) is the literal to grow.
- classifier append point: `classifier.h:195-202` (DROP test → XDP_PASS fallthrough) — the REDIRECT branch APPENDS, never interposes.
- `populate_action_table` static identity-keyed (loader.cpp ~:1532) + the 2-way action_id ternary (~:1397) → 3-way.
- `find_key` allowlist + schema_version check (config.cpp ~:354/580) absorb `steering:` without exit-9.
- redirect_devmap needs BOTH `maps.h` `.maps` decl AND a `kManagedMaps[]` row; verify the single-non-double-buffered DEVMAP rides the clear/pin/reuse walk.
- **Architect MUST** measure + document the new insn baseline (3437→N) and confirm oracle-agreement holds for the existing PASS/DROP corpus.

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #10 (catalog arithmetic)**: `ACTION_MAX 2→4` (+ reserved MIRROR) and `STAT_MAX 4→5` — verify
  every array sized by these + the `stats[STAT_MAX]` brace-init literal grows. The action_table +
  stats map max_entries follow.
- **Guard #11 (VERSION-bump propagation)**: 0.16.0→0.17.0 — grep all test/doc/CHANGELOG literal sites.
- **Guard #15/#16 (atomic-swap boundary + pin-name)**: the NEW single `redirect_devmap` is
  non-double-buffered — confirm the apply clear/pin/reuse walk handles a single (non-_a/_b) map; new
  pin path → check no test/src hard-codes a conflicting name.
- **Datapath-identity caveat (NOT a guard — a deliberate shift)**: this slice CHANGES the BPF program
  (new branch). `PI-mvp-4.27-DATAPATH-IDENTICAL` (insn 3437) is intentionally RE-BASELINED; the
  surviving invariant is PASS/DROP verdict-identity on the existing corpus. Reviewer treats the insn
  delta as documented-intentional, not regression.

### Evidence footer — discharge-ledger slice-time rechecks (brief-time status)

1. `populate_action_table` static identity-keyed (loader.cpp:1532-1552) — CONFIRMED ✓ (Option-1 byte-identity premise holds).
2. rules-inner action_id 2-way ternary (loader.cpp:1397-1399) — CONFIRMED ✓ (→ 3-way, SR-4).
3. classifier tests ACTION_DROP then XDP_PASS (classifier.h:195-202) — CONFIRMED ✓ (REDIRECT branch appends, SR-3).
4. sizeof(action_entry/rule_entry)==4 static_asserts (xdpfilter.h:344-345) — CONFIRMED ✓ (untouched — Option 1 no struct widen).
5. STAT_MAX=4 + the HARD-CODED `stats[STAT_MAX]={0,0,0,0}` brace-init (stats_reader.hpp:34) + verdict_label + read-sibling — CONFIRMED ✓ (~5 sites, SR-6; brace-init is the load-bearing literal).
6. schema_version hard {2} + RuleAction {Drop,Pass} + parse_rule_action 'drop'/'pass' + find_key allowlist (config.cpp:354/124/580) — CONFIRMED ✓ (SR-5; HG-1 makes it {2,3} additive).
7. redirect_devmap needs maps.h `.maps` decl AND kManagedMaps row (loader.cpp:137-179) — CONFIRMED ✓ (SR-2+SR-4; single non-double-buffered DEVMAP).
8. setup_veth/cleanup_veth single veth pair (common.sh:116-188) → SELECT-B needs a 2nd pair + sink_xdp.bpf.c + read_sink (NET-NEW) — CONFIRMED ✓ (SR-7; the omitted line-item).
