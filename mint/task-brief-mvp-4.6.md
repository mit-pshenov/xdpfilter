# Task brief — MVP-4.6: exporter per-axis labels (make the 5-axis match model observable) (rule-model S6, brownfield)

## Goal

Make the 5-axis match model (`dst_cidr/src_cidr/proto/dst_port/vlan`, landed §5.43-§5.45) **visible in Prometheus metrics**. The exporter has been deliberately axis-AGNOSTIC for several slices (`PI-mvp-4.3-EXPORTER-AGNOSTIC`), emitting only `xdpfilter_rule_match_total{iface,rule_id,action}` — an operator can see THAT rule N matched but not WHICH axes rule N selects on. This slice surfaces each rule's match constraints as Prometheus labels.

The data already flows: the loader's sidecar (`src/lib/sidecar.cpp`) ALREADY emits per-rule match objects with all 5 axes (`{"rule_id":N,"match":{"dst_cidr":"…","protocol":"tcp","dst_port":"443","vlan":"100",…},"action":"…"}`, verified — 5 `append_kind` emitters). The **exporter-side reader** (`src/exporter/sidecar_reader.cpp`) regex already CAPTURES the whole match-object body but `classify_match_kind()` collapses it to `match_kind ∈ {mac,cidr,both}`, **discarding the axis values**. So this slice is **consumer-only**: extend the reader to parse the per-axis values + extend `prom_format` to emit them. **`sidecar.cpp` is UNCHANGED** (producer already complete). NO BPF / datapath / loader / config / schema / map change. Rule count ≤64 bounds label cardinality.

Anchors: §5.43-§5.45 (the 5 axes the sidecar emits); the §5.31 sidecar/exporter split (`PI-31-3.4b` read-only reader, `D-3.4b-10` no-JSON-parser budget, `PI-32-3.4b` orphan-tolerance `action="unknown"`).

## Context: prior work

- **All prior briefs**: archived in `mint/task-brief-*.md` (this supersedes `mint/task-brief-mvp-4.5.md`).
- **Existing design**: `mint/design.md` §5.31 (MVP-3.4b — the sidecar `rule_index.json` + the exporter `sidecar_reader` + `prom_format` rule_id→action lookup; `PI-31/32-3.4b`), §5.43-§5.45 (the 5 axes now in the sidecar match objects).
- **Architecture doc**: `mint/architecture-rule-model.md` — observability of the selection axes is operator value; exporter labels were explicitly deferred from each axis slice to "a later exporter slice" (now).
- **Phase A code-grep verification** (brief author): `src/lib/sidecar.cpp` emits 5 axes (UNCHANGED this slice); `src/exporter/sidecar_reader.cpp` regex captures the match body (group 2) but `classify_match_kind` reduces it to a kind; `struct RuleMeta {rule_id, action, match_kind}` (sidecar_reader.hpp); `prom_format.cpp` emits `xdpfilter_rule_match_total{iface,rule_id,action}` from a rule_id→action vector; VERSION=0.13.0 (pinned only in `T_EXPORTER_METRICS_FORMAT.sh`); ctest baseline=82; T_EXPORTER_RULE_LABELS / T_EXPORTER_METRICS_FORMAT / T_SIDECAR_JSON_SHAPE exist.
- **PI continuity — IMPORTANT SHIFT**: `PI-mvp-4.3-EXPORTER-AGNOSTIC` ("exporter is rule_id-keyed + axis-agnostic; zero exporter edits") is **intentionally RETIRED/superseded** this slice — the exporter becomes axis-AWARE by design. Document the shift as a new PI (mirror the §5.34 PRESERVE→shift precedent; cite the retired PI text verbatim per [[impl-role-discipline]]). The existing `xdpfilter_rule_match_total` + `xdpfilter_packets_total` label sets stay byte-identical (the COUNTER contract is preserved; the new info is additive — see Q1). `PI-31-3.4b` (reader READ-ONLY) + `PI-32-3.4b` (orphan tolerance) CONTINUE.

## Workflow rules (brownfield)

- **Architect**: read `design.md` §5.31 (the sidecar/exporter split + reader regex + the D-3.4b-10 no-JSON-parser discipline + PI-31/32) + the brief. EDIT `design.md` in place; append **§5.46**. Resolve Q1–Q3 + HG defaults. Explicitly document the `PI-mvp-4.3-EXPORTER-AGNOSTIC` retirement + the new axis-aware PI.
- **Impl**: brownfield FileList DIFF. This is the slice that EDITS the exporter (`prom_format.cpp` + `sidecar_reader.{hpp,cpp}`) — previously fenced UNCHANGED. Keep the reader's no-full-JSON-parser discipline (D-3.4b-10 — line/regex extraction, not a parser dep). `sidecar.cpp` is NOT touched (producer already emits the axes).
- **Tester**: extend `T_EXPORTER_RULE_LABELS` to assert the per-axis labels/info-metric for a known 5-axis config; extend `T_EXPORTER_METRICS_FORMAT` (version literal + any new HELP/TYPE). Exporter tests bind a fixed port — `RESOURCE_LOCK` (guard #12) + be aware of the known port-9524 flake (backlog B17). Existing metric assertions must still hold (the counter contract is preserved per HG-2).
- **Reviewer**: 5-point brownfield. Special attention: (a) the new metric is Prometheus-valid (HELP/TYPE once per family, label escaping, stable label-key set across series); (b) label cardinality bounded (≤64 rules/iface, no unbounded value); (c) the existing `xdpfilter_rule_match_total` / `xdpfilter_packets_total` label sets are byte-UNCHANGED (counter contract preserved); (d) reader stays READ-ONLY (PI-31) + no full-JSON-parser dep (D-3.4b-10) + orphan tolerance (PI-32) holds; (e) `sidecar.cpp` + datapath/loader/config git-diff fences empty (consumer-only slice); (f) the EXPORTER-AGNOSTIC PI retirement is documented, not silently broken.

## Human-gate decisions (defaults applied — architect overrides at Phase A with evidence)

### HG-mvp-4.6-1: Scope → **exporter consumer-only** (prom_format + sidecar_reader)
NO datapath/loader/config/schema/map/sidecar-producer change. The sidecar already emits all 5 axes; this slice only reads + emits them. `sidecar.cpp` UNCHANGED.

### HG-mvp-4.6-2: Metric shape → **separate `xdpfilter_rule_info{iface,rule_id,<axis labels>} 1` gauge (Prometheus info-metric pattern)**
Default: emit a NEW info-metric (constant gauge value `1`) carrying the axis labels, keyed by `iface`+`rule_id`; operators join it to `xdpfilter_rule_match_total` on `(iface,rule_id)`. This leaves the existing counter's label set **byte-unchanged** (preserves its contract + the existing tests + avoids per-axis cardinality on the counter) — the Prometheus-idiomatic way to attach metadata. Architect Q to weigh vs enriching the counter directly (which would break the counter's label contract + ripple T_EXPORTER_METRICS_FORMAT/RULE_LABELS assertions).

### HG-mvp-4.6-3: Label encoding → **one label per axis carrying the constraint value; unconstrained axis → stable empty sentinel**
Labels `dst_cidr`, `src_cidr`, `protocol`, `dst_port`, `vlan`; value = the rule's constraint (e.g. `dst_cidr="10.1.2.0/24"`, `protocol="tcp"`, `dst_port="443"` or `"1000-2000"`, `vlan="100"`). A rule that does NOT constrain an axis emits that label as a stable sentinel (`""` default — architect picks `""` vs `"*"`) so every `rule_info` series carries the SAME label-key set (Prometheus best practice — avoid sometimes-present keys). Bounded cardinality (≤64 rules/iface).

### HG-mvp-4.6-4: VERSION → **bump 0.13.0 → 0.14.0 + DESCRIPTION** (new observability capability; propagate the literal per guard #11 — only `T_EXPORTER_METRICS_FORMAT` pins it).

### HG-mvp-4.6-5: Existing metrics → **UNCHANGED label sets** (`xdpfilter_rule_match_total`, `xdpfilter_packets_total` byte-identical). The new info is ADDITIVE. PI-31/32-3.4b continue.

## Open mechanism questions (architect decides; document in §5.46)

### Q1: info-metric vs enrich-the-counter
- **A1**: NEW `xdpfilter_rule_info{iface,rule_id,dst_cidr,src_cidr,protocol,dst_port,vlan} 1` gauge; counter untouched (join on iface+rule_id). Additive → existing tests hold; idiomatic; stable counter cardinality.
- **A2**: add the axis labels directly to `xdpfilter_rule_match_total`. Fewer series but CHANGES the counter's label contract (breaks existing format assertions + any operator query) + couples metadata to the counter's cardinality.
- **Recommendation**: **A1** (info-metric) — preserves the counter contract, additive test ripple, Prometheus-idiomatic.

### Q2: sidecar_reader per-axis extraction (keep D-3.4b-10 no-JSON-parser discipline)
- **A1**: keep the existing line-regex (it already captures the match-object body as group 2); add a small per-axis key extractor over that body (e.g. find `"dst_cidr":"…"` substrings) populating new `RuleMeta` fields. No full JSON parser. `classify_match_kind` MAY stay or be superseded.
- **Recommendation**: **A1** — minimal, respects D-3.4b-10; `RuleMeta` gains `dst_cidr/src_cidr/protocol/dst_port/vlan` string fields (empty when absent).

### Q3: wildcard-axis label sentinel
- `""` (empty) vs `"*"` vs `"(any)"` — **Recommendation**: `""` (stable key, empty value); architect picks. Always emit ALL axis label keys per `rule_info` series for a uniform label set.

## Scope (cycle S6 / mvp-4.6 — concrete items; estimates are UPPER BOUNDS)

### Item S6-1 — sidecar_reader: parse per-axis values
**Where**: `src/exporter/sidecar_reader.{hpp,cpp}`
- `struct RuleMeta` gains per-axis string fields (`dst_cidr/src_cidr/protocol/dst_port/vlan`); parse from the already-captured match body (Q2), no full-JSON dep (D-3.4b-10). READ-ONLY (PI-31).

### Item S6-2 — prom_format: emit axis labels
**Where**: `src/exporter/prom_format.{cpp,hpp}`
- Emit the `xdpfilter_rule_info` info-metric (Q1/A1) with HELP+TYPE once + one `… 1` line per (iface,rule_id) carrying the 5 axis labels (Q3 sentinel for unconstrained). Existing `xdpfilter_rule_match_total`/`xdpfilter_packets_total` emission UNCHANGED (HG-5). Label-value escaping per the existing escaper.

### Item S6-3 — VERSION bump + DESCRIPTION + literal propagation
**Where**: `CMakeLists.txt` + `T_EXPORTER_METRICS_FORMAT` (guard #11).

### Item S6-4 — tests
**Where**: `tests/T_EXPORTER_RULE_LABELS.sh` (assert the new info-metric + axis labels for a known 5-axis config + unconstrained-axis sentinel + a negation: an axis NOT in the config does not appear with a bogus value), `tests/T_EXPORTER_METRICS_FORMAT.sh` (version literal + new HELP/TYPE), `tests/CMakeLists.txt` if a NEW test is added. `RESOURCE_LOCK` (guard #12); known port-9524 flake (B17) awareness. Existing exporter assertions must still pass (counter contract preserved).

## Out of scope (explicit)
- **`sidecar.cpp` (producer)** — already emits all 5 axes; UNCHANGED. NEW FENCE.
- **Any datapath / loader / config / schema / BPF-map change** — consumer-only slice. NEW FENCE.
- **MAC-axis return; IPv6 cidr6; feed-objects; N>64; most-specific-wins; sequential** — later slices. NEW FENCE.
- **Per-axis MATCH counters** (a counter per axis-value) — this slice is metadata labels (info-metric), not new counters. NEW FENCE.
- **Non-eBPF datapath / 40 Gbps** — deferred per [[real-requirements-and-strategy]].
- Carry-forward §5.41-§5.45 OOS items not superseded — UNCHANGED.

## Definition of done
- §5.46 amendment appended to `mint/design.md` (Phase A grep report + HG/Q resolutions + the EXPORTER-AGNOSTIC PI retirement + new PIs).
- **PIs**: NEW PI-mvp-4.6-EXPORTER-AXIS-AWARE (the new info-metric carries the 5 axis labels; unconstrained→sentinel); NEW PI-mvp-4.6-COUNTER-CONTRACT (existing counter/packets label sets byte-unchanged); `PI-mvp-4.3-EXPORTER-AGNOSTIC` RETIRED (cite verbatim); `PI-31-3.4b` (reader READ-ONLY) + `PI-32-3.4b` (orphan tolerance) CONTINUE.
- ctest baseline = **82** (mvp-4.5 left it here; tester reconciles) + extended/NEW exporter-label tests; all existing exporter tests still green.
- VERSION 0.13.0 → 0.14.0, literal propagated.
- `mint/review.md` round-1 verdict = pass.
- One git commit per phase boundary.

## Dependencies
- Build: clang-19 / CMake; the exporter binary + its test harness.
- Runtime: a fixed metrics port for the exporter ctests (guard #12; known B17 port-9524 flake).
- No new third-party dep (D-3.4b-10 no-JSON-parser discipline).

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
- **One-sentence goal**: surface each rule's 5 match-axis constraints as Prometheus labels via an additive `xdpfilter_rule_info` metric, consumer-side only (the sidecar already emits the data).
- **Multi-axis design space?** BORDERLINE-NO. There is ONE real design fork (metric shape: info-metric vs enrich-counter, Q1) + a sub-choice (sentinel, Q3); both have clear Prometheus-idiomatic defaults (info-metric + stable-key labels). Not a sprawling ≥3-axis space; single-architect resolvable. Slightly expensive-to-undo (operator-facing metric contract) → mitigated by the info-metric default (additive, doesn't touch the existing contract). `/mint-hld` NOT needed; flagged as borderline.
- **Mechanical?** Mostly — "parse the axis values the sidecar already emits + emit an info-metric." Single-architect via `/mint-dev`.
- **Scope-size**: small, single-subsystem (exporter consumer-only). No split.
- **Overconfidence check**: VERIFIED the producer (sidecar.cpp) already emits all 5 axes (so it's OOS, not an EDIT) and the consumer (sidecar_reader) captures-but-discards the body — the change is genuinely consumer-only, not assumed. The EXPORTER-AGNOSTIC PI retirement is a real semantic shift, flagged (not silently broken).

## Notes for architect Phase A code-grep discipline (per architect spec rules)
Brief author ran these (Phase 2). Architect re-verifies + extends:
- `grep -nE 'append_kind\("(dst_cidr|src_cidr|protocol|dst_port|vlan)"' src/lib/sidecar.cpp` (CONFIRM producer emits all 5 → sidecar.cpp is OOS/UNCHANGED).
- `sed -n '/struct RuleMeta/,/};/p' src/exporter/sidecar_reader.hpp` + the regex in `sidecar_reader.cpp` (the match body is captured as group 2 today, reduced by `classify_match_kind`).
- `grep -nE 'xdpfilter_rule_match_total|xdpfilter_packets_total|HELP|TYPE|action=' src/exporter/prom_format.cpp` (the emission to keep byte-unchanged + the family to add).
- `grep -rn '0\.13\.0' CMakeLists.txt tests/` (VERSION propagation = only T_EXPORTER_METRICS_FORMAT).
- `git diff` fences: confirm `src/lib/sidecar.cpp`, `src/bpf/`, `src/lib/loader.cpp`, `src/lib/config.*` stay EMPTY (consumer-only).
- `grep -rn 'rule_match_total\|rule_info\|RULE_LABELS' tests/` (which tests assert the metric label schema → guard #13 ripple surface).

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)
- **Guard #5 (Phase A code-grep)** — always; architect repeats independently.
- **Guard #8 (interactive-vs-log distinction)** — N/A-ish: this is metric OUTPUT not a log event; but the same discipline (don't conflate the operator-facing metric contract with internal state) applies to the EXPORTER-AGNOSTIC PI shift.
- **Guard #9 (helper duplication-over-extraction)** — the per-axis extractor is exporter-internal single-consumer; do not over-share.
- **Guard #10 (catalog arithmetic)** — a NEW metric family (HELP/TYPE pair) is added; state it; no array/table size literal.
- **Guard #11 (VERSION-bump test-literal propagation)** — applies (HG-4); grep every `0.13.0`.
- **Guard #12 (RESOURCE_LOCK for shared host state)** — exporter ctests bind a fixed port; keep RESOURCE_LOCK + note the known port-9524 flake (backlog B17).
- **Guard #13 (retired/changed emit-site string ripple)** — the metric output format is asserted by `T_EXPORTER_METRICS_FORMAT` + `T_EXPORTER_RULE_LABELS`; the info-metric default is ADDITIVE (existing assertions hold + new ones added). If the architect picks Q1/A2 (enrich the counter) instead, the existing counter-format assertions RIPPLE — pre-list them. The EXPORTER-AGNOSTIC PI is the retired "string" here — document the retirement.
- **Guard #15 (PRESERVE-vs-RESET)** — N/A (no map change; rule_counters PRESERVE continues, untouched).
- **Operative-semantic discipline**: label-name/sentinel choices in §5.46 verifiable-invariants are SHOULD-level orientation; impl deviations mirroring the existing escaper / HELP-TYPE-once precedent are `inline-merge`.
