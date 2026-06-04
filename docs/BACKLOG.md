# Documentation Backlog

Tracks pending documentation work. Created 2026-05-27 consolidating:
1. The 13-item bucket originally surfaced as a CHANGELOG-only fence (CHANGELOG.md:245, MVP-3.5 OOS).
2. The 14 doc-dim findings from the multi-dim review at `agent-teams-review/runs/mint-review-mint-l2-mac-filter-202605271147/raw/documentation-reviewer.md` (2026-05-27).

This backlog is **manual prose work** — explicitly separated from `/mint-dev` slices per user direction. Owner: human.

## ✅ Documentation pass — RESOLVED 2026-06-01

The full doc bucket **B1–B13** was paid down in one prose pass (commit on `main`):

- **B1, B3, B4, B6, B10, B11, B12** — `README.md` full rewrite: dropped MVP-1 framing; 9-axis match-model table; all 5 loader subcommands + `xdpmf-exporter`; exit codes 0–9; env-var table; CMake-options table; `ansible` apt line; `FLEET_DEPLOYMENT.md` install path; Operator/Contributor "Where docs live" split.
- **B2** — `HANDOFF.md` → `docs/history/HANDOFF-mvp1.md` with an ARCHIVED banner (git mv).
- **B5** — `ansible/templates/xdpfilter-config.yaml.j2`: `schema_version` 1→2, `action: {{ rule.action | default('pass') }}`, all 9 axes optionally rendered; playbook var-spec updated.
- **B7** — `FLEET_DEPLOYMENT.md`: chose option (b) — honestly documented that the `xdpmacfilter_trust_model` metric is **NOT implemented / not scheduled** (the alert never fires; audit-log is the only trust-posture signal). Implementing the metric is a code slice, out of scope for the docs pass.
- **B8** — `FLEET_DEPLOYMENT.md`: NEW "Environment variables" section (`XDPMF_TRUST_MODEL`, `XDPMF_LOG_FORMAT`, `XDPMF_BPFFS_ROOT`) + JSON-logging Drop-In recipe.
- **B9** — chose option (a): NEW `mint/README.md` index/reading-order for the design corpus (no file moves — avoids breaking `design.md` cross-refs).
- **B13** — chose option (a): NEW `docs/CONFIG_SCHEMA.md` — full schema_version-2 / 9-axis reference with per-axis grammar + worked example.
- **B14** — meta-finding; this file is the tracking surface. No action (closed pre-pass).

Remaining open in this file: **B16, B17** (test-infra, code-side) and **B15** (gitignore `.pyc`, code-side) — NOT docs; carry to a `/mint-dev` housekeeping cycle. Original B1–B14 entries below are retained for provenance.

## Status legend

- **bucket** = was in the original CHANGELOG:245 13-item bucket
- **new** = surfaced by 2026-05-27 mint-review (not in original bucket)
- Severity tags use mint-review's classification.

## High-priority — first-contact discoverability

### B1 [CRITICAL, bucket] — README.md frozen at MVP-1
**File**: `README.md:1` (title), `:9-18` (no-X paragraph), `:67-71` (Run block), `:82-84` (exit codes), `:121-128` (Where docs live).
**Reality vs README**: every "no daemon / no hot reload / no JSON / no metrics endpoint / no multi-iface / no L3+" claim is false vs shipped 0.10.0 (xdpmf-exporter daemon; ExecReload via apply; XDPMF_LOG_FORMAT=json; /metrics endpoint; systemd template per iface; cidr.cpp). Five subcommands now (attach/detach/apply/bypass/reset-counters), README mentions two.
**Scope**: ~80-LOC rewrite — drop "(MVP-1)" suffix, drop "no X" paragraph, cover all 5 subcommands + xdpmf-exporter --port, document YAML schema, point at Prometheus discovery + journalctl, exit codes 0-9.

### B2 [HIGH, bucket] — HANDOFF.md fully stale
**File**: `HANDOFF.md:1, :18` — instructs reader to "Write `~/.claude/commands/mint.md`. It does NOT exist yet" — 18 cycles obsolete; mint family (/mint-dev, /mint-hld, /mint-review, /mint-briefer) shipped + used daily.
**Action**: delete OR rename `docs/history/HANDOFF-mvp1.md` with ARCHIVED banner.

### B3 [HIGH, bucket] — README Run block omits 3 of 5 subcommands
**File**: `README.md:67-71` vs `src/cli/cli.cpp:82-88` (usage_text) + `:363-377` (dispatch).
**Missing**: `apply`, `bypass`, `reset-counters`, AND the `xdpmf-exporter` binary entirely.
**Action**: reproduce cli.cpp:82-88 USAGE block in README + add parallel block for `xdpmf-exporter --port 9417 --bind 127.0.0.1 --bpffs-root <path>`.

### B4 [HIGH, bucket] — README exit-code list missing 7, 8, 9
**File**: `README.md:82-84` (lists 0-6 only) vs `src/lib/loader.hpp:43-52` + `src/cli/cli.cpp:112-114`.
**Missing**: 7 KernelUnsupported, 8 PathRefused, 9 ConfigError. `XDPMF_TRUST_MODEL=banana → exit 9` operator-footgun not surfaced.
**Action**: 3-line addition.

### B5 [HIGH, bucket] — Ansible Jinja template hardcodes `action: pass`
**File**: `ansible/templates/xdpfilter-config.yaml.j2:9` + var spec at `ansible/xdpmacfilter-deploy.yml:21`.
**Security-flavored**: operator who tries `xdpfilter_rules: [{id: 0, action: drop, mac: ...}]` ships PASS rule silently; the `action` key is swallowed.
**Cross-validation**: also flagged by security-reviewer as OOS-DOC.
**Action**: `action: {{ rule.action | default('pass') }}`; update var spec to include `action?`.

### B6 [HIGH, bucket] — README "Where docs live" table points at stale labels
**File**: `README.md:121-128`.
**Drift**: lists `mint/task-brief.md | Current pass brief (MVP-1.1A refactor)` (actual = MVP-3.4d); `mint/review.md | (MVP-1)`; omits `docs/FLEET_DEPLOYMENT.md` (the only installed operator doc), `CHANGELOG.md`, `architecture-v2.md`.
**Action**: split into Operator docs / Contributor docs sections; strip MVP-1-era labels.

## Medium-priority — operator-doc gaps

### B7 [MEDIUM, bucket] — FLEET_DEPLOYMENT.md describes `xdpmacfilter_trust_model` metric as "not yet shipped"
**File**: `docs/FLEET_DEPLOYMENT.md:99-101, :146` vs `src/exporter/prom_format.cpp:65, 84` (emits `xdpfilter_packets_total` + `xdpfilter_rule_match_total` only; no `xdpmacfilter_trust_model`).
**Operator impact**: documented Prometheus alert `count(count by (trust_model) (xdpmacfilter_trust_model)) > 1` never fires — metric was never implemented.
**Action**: either (a) implement metric (loader writes to sidecar → exporter reads), or (b) rewrite paragraph to acknowledge it's not implemented; drop "once MVP-3.4 lands" framing.

### B8 [MEDIUM, NEW] — `XDPMF_LOG_FORMAT` env var undocumented in any user-facing doc
**Surface**: absent from `README.md` + `docs/FLEET_DEPLOYMENT.md`; surfaced only via ctests + logger.cpp source. CHANGELOG:118 (0.8.0) announces feature but operators don't read CHANGELOG for env vars.
**Operators wanting JSON logs** (Loki/Splunk/ELK pipelines) have no surfaced way to learn `XDPMF_LOG_FORMAT=json` enables it.
**Action**: 5-line "Loader env vars" subsection in `FLEET_DEPLOYMENT.md` covering `XDPMF_TRUST_MODEL`, `XDPMF_LOG_FORMAT={text,json}` (default text), `XDPMF_BPFFS_ROOT`. Mirror exporter's --help env-var block style.

### B9 [MEDIUM, NEW] — No documentation index / reading order
**Surface**: repo has ~30 .md files; README "Where docs live" lists 5 with stale labels (B6); `mint/` has 19 .md files with inconsistent dash patterns (`task-brief-mvp1.md` vs `task-brief-mvp-3.5.5.md` vs `task-brief-mvp3.4.md`) and no index.
**Action**: either (a) `mint/README.md` chronological index OR (b) move closed-cycle briefs to `mint/history/` keeping only `design.md` + current `task-brief.md` + `architecture-v2.md` at top of `mint/`.

## Low-priority

### B10 [LOW, NEW] — README apt install line missing `ansible-playbook`
**File**: `README.md:28-35` vs `tests/CMakeLists.txt:32` (`ANSIBLE_PLAYBOOK`).
**Impact**: `T_ANSIBLE_PLAYBOOK_SYNTAX` SKIP-77s silently; contributors expecting full green get unexplained skip.
**Action**: add `ansible` to apt line + "optional, gates `T_ANSIBLE_PLAYBOOK_SYNTAX`" note.

### B11 [LOW, NEW] — README never mentions `docs/FLEET_DEPLOYMENT.md` install path
**File**: `README.md:86-103` vs `CMakeLists.txt:208-210` (installs to `${PREFIX}/share/doc/xdpmacfilter/`) + `systemd/*.service` `Documentation=file:///usr/share/doc/...` URI.
**Action**: one sentence: "FLEET_DEPLOYMENT.md installed alongside systemd units when `XDPMF_INSTALL_SYSTEMD_UNIT=ON` (default)."

### B12 [LOW, NEW] — CMake options `XDPMF_SANITIZERS` / `XDPMF_INSTALL_SYSTEMD_UNIT` / `XDPMF_ENABLE_BPF_OBJECT_OVERRIDE` undocumented in README
**File**: `CMakeLists.txt:93-102, 197, 219` declares all 3; README:55-63 covers only SANITIZERS partially.
**Action**: CMake options table in README (flag + default + 1-line purpose).

### B13 [LOW, bucket] — `CONFIG_SCHEMA.md` referenced in CHANGELOG:245 backlog but never created
**Surface**: schema lives at `src/lib/config.hpp:1-19` (top of 63-line .hpp); FLEET_DEPLOYMENT.md:139 partial; ansible Jinja template partial; cli.cpp:96-97 says "Schema details — see config.hpp" (three indirect sources, none complete).
**Action**: either create `docs/CONFIG_SCHEMA.md` (config.hpp:1-19 is essentially a draft) OR remove the line from CHANGELOG backlog if not a real deliverable.

### B14 [LOW, NEW] — CHANGELOG backlog tracking issue meta-resolved by this file
**File**: this `docs/BACKLOG.md` IS the tracking surface flagged as missing by mint-review.
**Action**: nothing — this entry exists for completeness; the meta-finding is now closed.

## Out-of-scope from this review (gitignore hygiene, code-side concern)

### B15 [OOS, NEW] — Committed `.pyc` artifact: `tests/lib/__pycache__/read_rule_counters.cpython-311.pyc`
**Action**: pass to next /mint-dev housekeeping cycle; add `tests/lib/__pycache__/` to `.gitignore` + `git rm -r --cached tests/lib/__pycache__`. NOT a doc task.

## Test-infra debt (code-side — surfaced during MVP-4.x cycles, parked here per user direction 2026-05-29)

### B16 [MEDIUM, test-infra] — `T_SANITIZER_BUILD` times out under `-j4` → orphan-pin cascade
**Surface**: full-suite `ctest -j4`. `T_SANITIZER_BUILD` does a whole-project sanitizer rebuild; under -j4 CPU starvation it can exceed its 240s `TIMEOUT`, ctest SIGKILLs it, its cleanup trap never runs → leaves an orphan pin `xdpmf_a_<pid>` under the production bpffs root `/sys/fs/bpf/xdpmacfilter/`, which **cascades** `T_BPFFS_ROOT_SYMLINK` to fail (its safety guard correctly refuses a non-empty root). Both PASS on serial re-run after orphan cleanup. Seen MVP-4.2 (2026-05-28). NOT a product regression (all-additive slices unaffected).
**Action options**: (a) raise `T_SANITIZER_BUILD` TIMEOUT and/or give it a dedicated RESOURCE_LOCK so it doesn't contend; (b) cap suite parallelism; (c) make `T_BPFFS_ROOT_SYMLINK` self-heal stale `xdpmf_a_*` orphans in its precondition before asserting.

### B17 [LOW, test-infra] — `T_EXPORTER_BIND_NON_LOOPBACK_WARN` (#70) hardcodes port 9524, no RESOURCE_LOCK
**Surface**: the test's own case-(a) exporter can leak a listener on `0.0.0.0:9524`; under -j4 the parent mis-reads "died during startup" and sub-cases (b)-(e) hit EADDRINUSE. Passes 1/1 isolated from a clean port. Seen MVP-4.1 (2026-05-28).
**Action**: add an `exporter_port` RESOURCE_LOCK (or per-test ephemeral port) + close the case-(a) cleanup gap.

## Mapping: CHANGELOG:245 5 categories → backlog items above

| CHANGELOG category | Backlog items |
|---|---|
| README rewrite | B1, B3, B4, B6, B10, B11, B12 (7 items consolidated) |
| FLEET_DEPLOYMENT.md sections | B7, B8 (B8 is NEW — env-var subsection) |
| CONFIG_SCHEMA.md | B13 |
| HANDOFF.md move | B2 |
| Ansible Jinja fixes | B5 |
| (NEW from 2026-05-27 mint-review) | B8, B9, B14, B15 (4 items not in original 13-item count) |

## Notes

- Original CHANGELOG:245 quote: *"13-item documentation bucket (README rewrite, FLEET_DEPLOYMENT.md sections, CONFIG_SCHEMA.md, HANDOFF.md move, Ansible Jinja fixes) — separate manual pass per user direction."*
- Effort estimate: ~8-10h of focused manual prose (per `project_session_handoff_2026-05-26.md` memory note).
- Recommend tackling B1 + B3 + B4 + B6 together as a single README rewrite session (~80 LOC; closes 4 items).
- B5 (Ansible) + B2 (HANDOFF) are XS — could land as one-line fixes any cycle.
- B7 (FLEET trust_model metric) has implementation-vs-doc fork — needs decision before action.

## Rule-model maturity audit (/mint-review 2026-05-29 — 6-axis model, src/)

Full report: `/home/user/agent-teams-review/runs/mint-review-src-202605291445/report.md` (5-dim hybrid review; 0 Critical, 4 High; security A−, architecture A−; all High citations re-Read-validated). Items below are the actionable consolidation. None blocks ship.

**Cheap wins (do soon — small effort):**
### B18 — ✅ SHIPPED MVP-4.9 (`9b3e6fc`) — `port_scan` `continue`→`break` (verified: `mac_filter.bpf.c:519`)
### B19 — ✅ SHIPPED MVP-4.9 (`9b3e6fc`) — `build_cpu` RESOURCE_LOCK for the `-j4` build-timeout flake (also resolves B16)
### B21 — ✅ SHIPPED MVP-4.14 (S5) — de-vacuified `T_MAC_NON_IP` (KC-A)
`tests/T_MAC_NON_IP.sh` rewritten under S5's family-blind-mac supersede (§5.54 D-mvp-4.14-MAC-NONIP-SUPERSEDE): the non-IP case now positively asserts `(( d3-d2 != 1 ))` (deny fires) + `(( m3-m2 != 0 ))` with the load-bearing assertion OUTSIDE the `||true` (which now guards only the wait). `T_AND6_ORACLE_AGREEMENT.sh` NOMATCH vectors carry a `saw_negation` flag + per-slot drift-guard (delta∈{0,1}, non-target slot moving → FAIL) — non-vacuous. Closed alongside the gate-widening as planned.

**Structural / before-IPv6:**
### B20 — ✅ SHIPPED MVP-4.8 (`0265bcb`) — `apply_request` table-driven (`populate_all_axes` `loader.cpp:1858` + `inactive_axis_fd` `:1837`). Prerequisite for B28/B31 — satisfied.
### B28 — ✅ SHIPPED MVP-4.10 (`9b3e6fc` cycle, −99 LOC) — templated the 3+3 near-dup fns
`loader.cpp:1503 populate_hash_inner_slot<Key>` (folds former populate_inner/proto/vlan, §5.50 B28-1) + `loader.cpp:1420 aggregate_axis<Key>` (folds former lower_proto/vlan/mac, §5.50 B28-2). Rule-of-three OVERRIDES guard applied. B20 table-driven was the prerequisite (shipped). Survived S4/S5/S6 axis growth unchanged (Key=__u32 instantiations + the v6 axes use their own LPM path).
### B30 [MEDIUM, architecture] decouple internal `slot` from operator `id` (counter-continuity footgun)
Today `id` is triple-coupled: operator-assigned priority AND bit position (`bit = 1ULL<<id`, ~5 callsites incl. `loader.cpp:1256+`) AND `rule_counters[]` index. Consequence: renumbering a rule to re-prioritize, or inserting a rule between two others (a normal day-1 operator op), moves that rule's Prometheus counter series and breaks monotonicity. Fix: operator `id` = pure identity + counter key; loader assigns a dense internal `slot`, `bit = 1ULL<<slot`, with a `slot→id` table so `rule_counters[]` stays keyed on stable `id`. Datapath byte-untouched IFF no site hardcodes `id==bit` (the "bit-position opacity" guarantee — verify the `1ULL<<r.id` callsites first). Also unblocks most-specific-wins (S.3) and N>64 later. Source: hld-workflow v3 synthesis Option 4 + contrarian #5 (`/home/user/agent-teams-review/runs/hld-mint-l2-mac-filter-20260530084033/`). **Plan: schedule as its own slice; do NOT pull-forward unless rule reordering becomes a near-term operator workflow.**
### B31 — ✅ SHIPPED MVP-4.14 (S5, `99eb17e`) — EtherType as a real L2 match axis
Shipped as the 9th axis `BV_AXIS_ETHERTYPE` (`mac_filter.bpf.c:376`): ARRAY_OF_MAPS[2] of HASH inners cloning the proto axis (BITVEC 8→9, kManagedMaps 36→39), hoisted above the family dispatch, composed into all 3 arms incl. a NEW full-symmetric 9-term non-IP `else` arm. `ethertype:arp/0x88b5 drop` works (coarse non-IP steering). The B20 table-driven refactor was the prerequisite as predicted. C3 fast-follow (`9abb02d`) later surfaced it on both observability surfaces (sidecar JSON + rule_info labels). Brief field-list coverage gap closed. Source: `/home/user/agent-teams-review/runs/hld-mint-l2-mac-filter-20260530084033/`.

**Cleanup (cross-validated by ≥2 reviewers; doc/dead-code, Low):**
### B24 — ✅ SHIPPED MVP-4.17 — delete vestigial `classify_match_kind` + `match_kind`
`src/exporter/sidecar_reader.cpp:39-47`,:93,`.hpp:30`. Scans a retired `"cidr"` key the producer no longer emits (→ `has_cidr` permanently false); `match_kind` never consumed (live path = 6 `extract_axis` fields). Delete fn+assignment+member (−12 LOC).
### B25 — ✅ SHIPPED MVP-4.17 — fix config schema_version / mac-rejected stale comments (+9-axis count drift)
`config.hpp:5,14-15,45,60` + `apply_internal.hpp:27` say "schema_version 1 / mac DEFERRED"; `config.cpp:367-384`/:56-60 stack "mac REJECTED" then "RE-ACCEPTED" — but `config.cpp:286-297` requires `==2` + :413 re-accepts mac. `config.hpp:60 =1` dead init. 4 header comments actively mislead. Updated to v2/**9-axis** (the model grew through S4/S5/S6); superseded paragraphs dropped (history→git/RETROSPECTIVES). Shipped scope was broader than the original note: 8 sites incl. the dead init `=1`→`=2`, sidecar.cpp's false "config.cpp rejects mac", and the prom_format.hpp 6→9 doc-mirror.
### B26 [LOW, observability] rename `pass_cidr` stat-label → `pass_rule`
`src/exporter/prom_format.cpp:31` + enum `src/common/mac_filter.h:58` (set `bpf.c:836`). The label now misnames all 6-axis matches (mac/proto/port/vlan funnel to "pass_cidr"). Metric-contract rename (crosses kernel stat enum + dashboards depend) → fold into a slice already bumping the stat enum. Deferred.

**Other Mediums:**
### B22 [MEDIUM, test] sanitize the 6-axis lowering path
`tests/T_SANITIZER_BUILD.sh:84-95` runs only 1 src_cidr rule under ASAN/UBSAN → `close_prefixes`/`populate_{proto,port,vlan,mac}_inner_slot`/`write_wildcard_slots`/per-axis bounds never sanitized. Point a sanitizer test at `config_valid_and6.yaml` + 2-3 vectors (full-6 + wildcard + NOMATCH).
### B23 [CLOSED — documented as known gap] 5.15-verifier load of the PRODUCTION object
**B23-min DONE (MVP-4.20, §5.60):** the misleading "verifies on the 5.15 floor" over-claim in `tests/T_BITVEC_VERIFIER_LOAD.sh:7,159` is reworded to the accurate "prototype object loads+verifies on the dev kernel (uname -r, currently 6.1); NOT a 5.15-floor nor a production-object guarantee", and the honest prototype-vs-production gap-note is flagged in **design §5.60** (+ inline `[CLARIFIED BY §5.60]` on §6.46). The behavioral core (prototype load + rc=0 assertion) is byte-unchanged.
**Remainder = DOCUMENTATION, not a tracked task (PO call 2026-06-01).** The production `mac_filter.bpf.c` (9 axes — dst/src/proto/port/vlan/mac/dst6/src6/ethertype + IPv6 ext-walk + variable IHL-offset L4 read) is **DESIGNED** to load on the 5.15 floor (bounded `#pragma unroll`, no `bpf_loop`, FFS + variable-IHL fallbacks — see `mac_filter.bpf.c:578/600/641/782`) and is **expected to work there — but this has not been empirically verified** (dev kernel is 6.1; the §5.42 feasibility spike also ran on 6.1). Stated plainly: *should work on 5.15, we have not checked.* This is recorded as an honest known-gap, NOT a pending engineering item. If a real 5.15 verifier proof is ever wanted, it would need a 5.15 kernel image in CI (`bpftool prog load` the production `.o`) — but that is not scheduled and not owed.
### B27 [MEDIUM, security] exporter single-threaded HTTP connection-hold DoS
`src/exporter/http.cpp:421`+:465, 5s/conn budget, single sync acceptor → sequential attacker blacks out /metrics+/healthz (CWE-400). Mitigated by the loopback-default bind. Fix: lower per-conn read deadline (~1s) and/or per-source cap.
### B29 — ✅ SHIPPED MVP-4.18 (`194be4f`) — deleted the legacy `allowlist` alias map
Removed the BPF alias map + the bespoke `legacy_alias` loader control-flow (kManagedMaps row + field + 2 skip-guards + the §5.26 special-pin block) + the `XDPMF_MAP_ALLOWLIST_NAME` constant; migrated the 4 canary ctests to assert the live `allowlist_a` pin (T_LOAD_ATTACH gained a negation control proving the legacy pin is GONE at runtime). ABI-promise (bpf.c out-of-tree-harness alias) re-confirmed vestigial — ZERO tree-wide consumer → retired. kManagedMaps 39→38 (guard #10); LIVE datapath verdict-identical; PI-7 loader.hpp ∅; bpftool prog load rc=0 on the prod object; 96/96 ctest. §5.58.

**Deferred-by-design (NOT backlog action — tracked elsewhere):** the IPv4-gate semantic gap (MAC/VLAN match IPv4 only) = `D-mvp-4.7-Q2-GATE-DEFER` → ✅ **RESOLVED in S5 (MVP-4.14)**: the NEW full-symmetric non-IP `else` arm makes mac/vlan family-blind (they now fire on non-IP + IPv6 frames), exactly the L2-universal MAC the PO leaned toward (guard #27/#28). Perf H-2/M1/M2/M3 (proto+vlan HASH→ARRAY, wildcard struct-of-6, LPM hybrid, gate mac_mask) = for the future non-eBPF perf datapath (eBPF = model-validation vehicle), not the current vehicle.

---

## L2/L3 gate ladder + C3 — SHIPPED STATUS (2026-05-31)

The S1→S6 gate ladder + C3 fast-follow are COMPLETE on origin/main. Match model = **9 axes** (dst/src/proto/port/vlan/mac/dst6/src6/ethertype) AND-composed across 3 family arms (IPv4/IPv6/non-IP), IPv6 with full ext-header L4 depth. Shipped: S4 cidr6 (`971f2fd`), S5 EtherType (`99eb17e`, closes B31), S6 ext-walk (`ce59a5e`), C3 sidecar v6/ethertype match-kinds on both observability surfaces (`9abb02d`). VERSION 0.15.0, 96/96 ctest.

---

## Architectural debt + cleanup workstream (2026-06-02/03 — PO: tidiness before mirror/redirect)

Source: user's 5-point datapath review + the 2026-06-01 hybrid review (PERF-M1/ARCH-H1). Full planning context in memory `project_datapath_cleanup_workstream.md`. Sequence: comments-collapse → rename → MEASURE → datapath workstream. Mirror/redirect deferred behind this by PO choice ("чище будет; mirror не убежит").

### B32 [hygiene, AGREED-NEXT] comment-collapse / archaeology pass
`.bpf.c` 33% + `loader.cpp` 31% comment-lines. Pilot counts (cut-candidates): bpf.c ~136 (82 §-stacks + 42 D-mvp narration + 12 net-delta) of 477; loader.cpp ~301 (214+56+31) of 935. KEEP-tripwires: bpf.c 20 (14 PI + 6 guard), loader.cpp 20. Rubric: KEEP WHY + 1 canonical invariant-tripwire (PI-7/guard #N) + security rationale; CUT D-mvp decision-narration (lives in design.md), net-delta archaeology, WHAT-restatement, §-tag stacking. Behavior-preserving → bpf.c byte-identity (xdp 3658), .cpp ctest. Band slice under the byte-identity guard.

### B33 [hygiene] rename `mac_filter`/`xdpmacfilter` → `xdpfilter` (+ repo align mint-filter→xdpfilter)
Blast radius (greps 2026-06-02): A. internal source — 27 files (`mac_filter.bpf.c`/`.h`, prog, idents, includes); B. operator-surface `xdpmacfilter` — CMake binary (23), tests (45), systemd (2), ansible (1), docs (5), bpffs-root `XDPMF_BPFFS_ROOT="/sys/fs/bpf/xdpmacfilter"`; C. **security-coupled** `mac_filter_prog` (28 sites — §5.19 name-check literal + self-tag capture + `T_ATTACH_TAG_MISMATCH`/`T_VERIFIER_REJECT` fixtures); D. env `XDPMF_*` — **KEEP spelling, reinterpret acronym** (M=Match/Multi), zero operator-break. Ladder: (A+C source+prog+security-fixtures) → (B operator-surface+docs) → (repo). **byte-identity nuance**: renaming `mac_filter_prog` changes BTF symbol+self-tag BY DESIGN — instructions stay 3658, but prog name/tag in BTF change (don't false-alarm).

### B34 [hygiene/structure] datapath de-monolith: helpers → module split
#4+#5 = one workstream. (a) extract repeated lookup+null-check + verdict-dispatch idioms (ARCH-H1) into `static __always_inline` helpers (byte-identical); (b) helpers reveal module boundaries → split `mac_filter.bpf.c` + `mac_filter.h`(→`xdpfilter.h`) into `ipv4_match.h`/`ipv6_match.h`/`vlan.h`/`classifier.h`/`maps.h` included into ONE TU (verifier unaffected, byte-identical pure code-movement). #4 BEFORE #5 (split before extract = scattered spaghetti). After B32+B33.

### B35 [perf, MEASURE-FIRST] wildcard+defaults → `ruleset_state` struct (= PERF-M1 promoted)
~30 lookups/pkt IPv4. The collapsible class = VALUES: pack 9 per-axis `wildcard` u64 + `defaults` u32 into one `ruleset_state[active]` struct → 1 lookup (−9). The per-axis OUTER lookups are map-REFERENCES (ARRAY_OF_MAPS double-buffer) → NOT packable → hard ceiling. **MEASURE instructions/cycles per packet first** (BPF_PROG_TEST_RUN, commit `e9bb321`). **Only slice with real regression surface — map-layout change ⇒ verdict-identity test, not byte-identity.** Perf is NOT a fire (eBPF clears SLA#1 w/ 1-2 core headroom) — this is ceiling-lowering.

### B37 [test-hardening, DO BEFORE B34] decorative regression gates on the two surfaces any refactor touches
Source: subtractive-reviewer ("Code Judo") trial, external review 2026-06-03. Full writeup + P1-P6 proposal math: `/home/user/agent-teams-review/runs/SESSION-SUMMARY-20260603-simplifier-trial.md`. **Finding**: the project's regression gates are *decorative* on exactly the surfaces a behavior-preserving refactor mutates —
1. **BPF instruction-stream**: `tests/T_PROD_VERIFIER_LOAD.sh:94-101` **prints** the xlated insn count (baseline 3658) but **asserts only `rc==0`** — the count is informational/NON-fatal by an explicit prior decision (`D-mvp-4.23-H3-PRODOBJ`). A codegen drift that still verifies passes silently. The `xdp 3658 byte-identical` claim we lean on every slice has **no automated gate**.
2. **Operator-facing loader stderr**: `throw_loader`/`classify` emit `"<label>: {strerror}"` lines that are **pinned by NO ctest** — only `T_BUILD` (compile-clean). The text is part of the operator ABI (greppable audit prefix, `FLEET_DEPLOYMENT.md:37`) and can silently change.

**Fix = mint slice**: (a) promote the insn-count check from informational to a **fatal assert** (with an explicit "bump baseline on intentional codegen change" escape hatch — this *consciously reverses* `D-mvp-4.23-H3-PRODOBJ`, not an oversight); (b) add a **golden-stderr ctest** pinning the operator-facing error-string shapes against a checked-in expected. **Payoff**: unblocks safe application of the deferred behavior-preserving folds (`SESSION-SUMMARY` P3/P4 objdump-gated, P6 stderr-gated) AND catches future regressions. **Sequence: BEFORE B34** — B34's `__always_inline` extraction + module split rests entirely on the byte-identity guard these gates would make real. Author via `mint-briefer` → `mint-dev`.
