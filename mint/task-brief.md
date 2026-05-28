# Task brief — MVP-4.2: bit-vector AND-classification spike (rule-model S2) (brownfield, isolated prototype)

## Goal

Prove (or disprove) the **bit-vector packet-classification structure** on the eBPF datapath — the PO-preferred, max-eBPF-perf lowering from `mint/architecture-rule-model.md` (Option 1 / Wave-B). Build it as an **isolated prototype** over a **hardcoded canonical Gi rule-set** (no v2 config parser), measure verifier-acceptance + correctness + control-plane complexity, and thereby resolve the PO decision gate: **take bit-vector unless the spike shows it is "very hard," else fall back to sequential.**

The deliverable is evidence, not production: does the bit-vector AND-classification (per-axis `u64` rule-bitmasks OR'd with a per-axis wildcard baseline → AND across axes → `ffsll` = lowest-`id` first-match) verify on the 5.15 floor, classify a mixed-primitive canonical rule-set correctly, and stay tractable on the control-plane side (the LPM **prefix-closure** + dst-port **range encoding** + wildcard/aux-mask atomic-swap that the contrarian flagged as the real cost)? If those prove intractable, that IS the "very hard" signal — escalate (peer-DM) and it feeds a fall-back-to-sequential PO call.

**This is a spike, scoped narrow on purpose** (PO chose scope A, 2026-05-28): bit-vector ONLY (sequential is the documented fallback, NOT built this slice); hardcoded/test-populated rules ONLY (the v2 config schema/parser, Rule IR emission, schema_version:2 cutover, exporter wiring, and the real atomic-swap apply path are **deferred to the S3 production-landing slice**). Build the real classification structure now, wire config to it later.

## Context: prior work
- Architecture anchor: `mint/architecture-rule-model.md` — Option 1 (bit-vector composition: classifier.2 + semantics.S.1 `id`=bit-position + realizability.R.2 wildcard baseline) + the "is bit-vector very hard?" decision rule. §6.2 candidate (b).
- Demand anchor: `mint/selection-scenarios.md` §4 (6 encoding primitives; the canonical set must exercise LPM + exact + range + wildcard).
- Prior slice: MVP-4.1 (`823cdca`) shipped the `l3_after_vlan` parse-fix — tagged IPv4 now reaches L3. design.md highest §ction = §5.41; ctests at §6.44; guard catalog at #22.
- Phase A code-grep (brief author, see Phase 2 report): `rule_entry{present,action_id}` + `allow_entry` + `action_entry` exist (`mac_filter.h`); `defaults` is ARRAY[XDPMF_RULESET_COUNT=2] of u32 swapped by `active_idx` — the precedent for a per-axis `wildcard_mask` ARRAY[2] of u64; populate path = `populate_inner_slot` / `populate_cidr_inner_slot` (`loader.cpp`, `bpf_map_update_elem`); **NO `ffsll`/`__builtin_ffs` precedent in src (new — architect verifies BPF-target + verifier acceptance)**; **all current rule population is via `apply -f <yaml>` — NO direct-map-write harness exists (the spike must add a test-only one)**; STAT enum = {PASS,DROP_DENY,DROP_MALFORMED,PASS_CIDR,MAX=4}.
- PI continuity: production `src/bpf/mac_filter.bpf.c` + its 70 ctests stay GREEN and byte-untouched (the spike is additive/isolated). PI-7 ZERO-diff on loader.hpp/config.hpp continues (the spike's test-loader is a SEPARATE path, not an edit to the production loader/config).

## Workflow rules (brownfield, additive/isolated)
- **Architect**: read `mint/architecture-rule-model.md` Option 1 + §6.2(b) + the §5.41 tail; EDIT design.md in place; append §5.42. Design the bit-vector prototype as ISOLATED new files (a prototype BPF object + a test-only populate harness + spike ctests) so the production datapath + its 70 ctests are untouched. Specify the exact canonical rule-set, the bitmask/wildcard map layout, the prefix-closure algorithm, the dst-port range encoding, and the userspace correctness oracle. Run the Phase A greps below independently.
- **Impl**: build the prototype BPF object + the test-only populate harness (writes the canonical rule-set's per-axis bitmasks + wildcard masks directly into the prototype maps — mirrors `populate_inner_slot` shape, NO config parser). Build green + verifier-accept the bitmask datapath (incl. `ffsll`) on the 5.15 floor. **If the prefix-closure / range-encoding / aux-mask work turns intractable or bug-prone, do NOT silently force it — peer-DM the architect; that escalation IS the "very hard" evidence.**
- **Tester**: write the correctness-oracle ctests — a userspace reference classifier over the canonical rule-set; inject frames spanning rules (hits, misses, overlapping-prefix, range-edge, wildcard, first-match-tie) and assert the prototype's verdict == oracle. New ctests take `RESOURCE_LOCK xdp_fixture` (guard #12). Negation control mandatory (a frame that should NOT match any rule → default).
- **Reviewer**: 5-point brownfield. Special attention: (a) verifier-acceptance of the `ffsll`/AND/wildcard datapath; (b) prefix-closure correctness (overlapping dst-IP prefixes must yield the correct bitmask — the classic bit-vector trap); (c) range-edge correctness for dst-port; (d) production `mac_filter.bpf.c` + 70 ctests untouched/green; (e) **the complexity assessment** — capture loader-side LOC + count of fiddly invariants as the "is it very hard" evidence (this is a first-class deliverable, not a side note).

## Human-gate decisions (defaults applied — architect overrides at Phase A with evidence)

### HG-mvp-4.2-1: scope → **bit-vector ONLY; sequential is the documented fallback, NOT built this slice**
The build itself is the difficulty test. Outcome feeds the PO "is it very hard → else sequential" gate. Do not build sequential for comparison; bit-vector's absolute control-plane complexity is the measure.

### HG-mvp-4.2-2: rule population → **test-only direct-map-write harness; NO v2 config parser**
The spike hardcodes the canonical rule-set into the prototype maps via a test-only populate path (mirroring `populate_inner_slot`). The v2 config schema/parser, Rule IR, schema_version:2 cutover, exporter wiring, and production atomic-swap apply are S3 (deferred).

### HG-mvp-4.2-3: isolation → **prototype is ADDITIVE; production `mac_filter.bpf.c` + its 70 ctests byte-untouched & green**
Build a separate prototype BPF object + test-loader + spike ctests. Keeps the green baseline and isolates the experiment. PI-7 loader.hpp/config.hpp ZERO-diff continues.

### HG-mvp-4.2-4: cardinality → **N≤64, single `u64` bitmask** (no multi-word loop)
Per PO (rule count ≤64 for now). The single-u64 sweet spot.

### HG-mvp-4.2-5: VERSION bump → **none** (internal spike, no operator surface).

### HG-mvp-4.2-6: canonical rule-set → **mixed-primitive, ~10–20 rules** exercising LPM (dst-IP + src-IP), exact (proto), range (dst-port), wildcard (absent axis), and overlapping dst-IP prefixes (to force prefix-closure) + a first-match-tie (two rules match → lowest id wins). Architect specifies the exact set in §5.42.

## Open mechanism questions (architect decides; document in §5.42)

### Q1: per-axis `wildcard_mask` placement + atomic-swap
- **A1**: parallel `ARRAY[2]` of `u64` per axis, swapped by the same `active_idx` (the `defaults` precedent).
- **A2**: fold the wildcard into the inner-map structure.
- **Recommendation**: A1 (proven `defaults`/`active_idx` swap precedent; spike can even use a single non-swapped slot since there's no live re-apply in the spike — architect simplifies as fits an isolated prototype).

### Q2: dst-port range encoding
- **A1**: prefix-expand the range into a port-LPM (ranges → set of prefixes).
- **A2**: an aux range-table scanned in the datapath (bounded).
- **Recommendation**: architect's call; whichever is cleaner under the verifier + simpler to populate. The *difficulty* of this choice is itself part of the "very hard" measurement — document the cost either way.

### Q3: `ffsll` mechanism
- `__builtin_ffsll` on the AND-accumulated `u64`. Architect verifies it lowers to valid BPF + the verifier accepts it on the 5.15 floor (no src precedent). If problematic, a bounded fallback (small unrolled bit-scan) — note as a cost.

## Scope (cycle S2 — concrete items; UPPER BOUND)

### Item 4.2-1 — bit-vector prototype datapath (NEW, isolated)
Per-axis maps return `u64` rule-bitmasks; `acc &= (matched | wildcard)` across axes; `ffsll(acc)-1` = first-match `id`; reuse a rules→action dispatch shape for the verdict. Axes: dst-IP (LPM), src-IP (LPM), proto (exact), dst-port (range) — minimum to span LPM+exact+range+wildcard. New prototype BPF object; production datapath untouched.

### Item 4.2-2 — test-only populate harness (NEW)
Writes the canonical rule-set's per-axis bitmasks + wildcard masks directly into the prototype maps (mirrors `populate_inner_slot`; NO config parser). Includes the **prefix-closure** computation for the LPM axes (each trie entry = OR of all rules whose prefix covers it).

### Item 4.2-3 — correctness-oracle spike ctests (NEW)
Userspace reference classifier over the canonical set + frame injection (`tests/inject`, incl. `--vlan`) asserting prototype verdict == oracle across hit/miss/overlap/range-edge/wildcard/first-match-tie. `RESOURCE_LOCK xdp_fixture`. Negation control mandatory.

### Item 4.2-4 — §5.42 design amendment + complexity assessment
design.md §5.42 records the prototype design + the **"is it very hard" evidence** (loader-side LOC, fiddly-invariant count, verifier-acceptance result, ffsll outcome) → feeds the PO bit-vector-vs-sequential decision.

## Out of scope (explicit)
- Sequential lowering (the fallback; built only if bit-vector is rejected).
- v2 config schema/parser (dst_ip/protocol/dst_port keys), Rule IR emission, schema_version:2 cutover — S3.
- Exporter/metrics/labels for the new axes; production atomic-swap apply wiring — S3.
- Editing production `mac_filter.bpf.c` / loader / config (isolation invariant).
- IPv6 axis, VLAN-as-match-field, feed-objects — later slices.
- VERSION bump.

## Definition of done
- §5.42 amendment in design.md incl. the complexity assessment (the decision evidence).
- Prototype verifies on the 5.15 floor; correctness ctests green (prototype verdict == oracle, incl. overlap/range-edge/first-match-tie); negation control green.
- Production `mac_filter.bpf.c` + 70 ctests byte-untouched & green; PI-7 loader.hpp/config.hpp ZERO-diff.
- A clear recommendation surfaced for the PO gate: bit-vector tractable (→ adopt, S3 wires config) OR very hard (→ fall back to sequential).
- `mint/review.md` round-1 verdict = pass. One git commit per phase boundary.

## Dependencies
- Build: existing BPF/CO-RE toolchain; `__builtin_ffsll`.
- Runtime: root for veth/bpffs ctests.
- Kernel/platform: 5.15 floor — bounded constructs only, no `bpf_loop`.

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
Carry-over from a prior `/mint-hld` decision (Wave B → Option 3 spike) — NOT a fresh multi-axis HLD question, so `/mint-hld` is not re-run. Single-architect `/mint-dev` fits. Slice boundary resolved (Phase 1): scope A = bit-vector prototype ONLY, isolated, test-populated; sequential + config plumbing deferred. **Caveat: this is the project's largest slice to date** (bitmask datapath + prefix-closure + range encoding + oracle harness) — the architect should bound the canonical set + prototype extent tightly, and the abort-to-sequential escalation is a first-class exit, not a failure.

## Notes for architect Phase A code-grep discipline
- `grep -nE 'struct rule_entry|struct allow_entry|struct action_entry' src/common/mac_filter.h` — the value shapes the bitmask replaces (in the prototype).
- `grep -nE 'defaults|active_idx|XDPMF_RULESET_COUNT' src/common/mac_filter.h` — the ARRAY[2]+active_idx swap precedent for the wildcard_mask.
- `grep -nE 'populate_inner_slot|populate_cidr_inner_slot|bpf_map_update_elem' src/lib/loader.cpp` — the populate shape the test-only harness mirrors.
- `grep -rnE 'ffsll|__builtin_ffs' src/` — confirm NO precedent; verify `__builtin_ffsll` lowers + verifies on the 5.15 floor before committing the datapath.
- `grep -rln 'RESOURCE_LOCK xdp_fixture' tests/CMakeLists.txt` — registration pattern for the new spike ctests.
- Confirm the prototype does NOT edit `src/bpf/mac_filter.bpf.c` / loader / config (isolation invariant; `git diff` must show those zero).

### Anti-misdiagnosis guards applicable to this slice
- **Guard #5 (Phase A code-grep)** → re-run the above; don't trust this brief's symbol claims blindly.
- **Guard #12 (RESOURCE_LOCK for shared host state)** → new veth/bpffs spike ctests MUST set `RESOURCE_LOCK xdp_fixture` + cleanup trap.
- **Guard #9 (helper duplication-over-extraction)** → keep prototype helpers single-consumer; do NOT refactor production code to "share" with the prototype.
- **Guard #10 (catalog arithmetic)** → if the prototype adds maps to any managed-maps table, keep the count arithmetic exact (or keep the prototype maps OUT of the production `kManagedMaps[]` to preserve isolation).
- **Guard #6 (bpffs ≠ tmpfs)** → prototype pins live on bpffs; reuse the established fixture teardown.
- Counts/sizes (canonical-set size, LOC) in verifiable-invariants prose are operative-semantic, not literal-match; impl deviations mirroring precedent are `inline-merge`.
