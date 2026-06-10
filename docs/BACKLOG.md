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

Remaining open in this file: **B16, B17** (test-infra, code-side) and **B15** (gitignore `.pyc`, code-side) — NOT docs; carry to a `/mint-dev` housekeeping cycle. The original B1–B14 detail blocks were **retired 2026-06-07** — the RESOLVED summary above is the durable record; full provenance lives in git history.

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

Source: user's 5-point datapath review + the 2026-06-01 hybrid review (PERF-M1/ARCH-H1). Full planning context in memory `project_datapath_cleanup_workstream.md`. Sequence: comments-collapse → rename → MEASURE → datapath workstream. Mirror/redirect were deferred behind this by PO choice ("чище будет; mirror не убежит"); the cleanup arc has since closed and **redirect shipped** (B42/MVP-4.35, §5.75). Mirror remains deferred (needs TC/TCX).

### B32 — ✅ SHIPPED MVP-4.25 (`1d31f51`, §5.65) — comment-collapse / archaeology pass
−274 comment-lines across `.bpf.c` + `loader.cpp`; KEEP WHY + invariant-tripwires (PI/guard), CUT D-mvp narration + net-delta archaeology + §-tag stacking. Traceability audit: 0 governing-anchor loss. xdp 3658 byte-identical; round-1.

### B33 — ✅ SHIPPED MVP-4.26 (`00e28ea`, §5.66) — rename `mac_filter`/`xdpmacfilter` → `xdpfilter` (+ GitHub repo)
6 git mv + 93 files; `mac_filter_prog`→`xdpfilter_prog` (BTF symbol/self-tag change BY DESIGN, §5.19 name-check + security fixtures consistent). KEPT `XDPMF_*` env (reinterpret MF=Match/Multi), `xdpfilter_*` metrics, `xdpmf-exporter`. VERSION 0.15.0→**0.16.0**; xdp 3658 byte-identical; round-1.

### B34 — ✅ SHIPPED MVP-4.28 + 4.29 — datapath de-monolith (helpers → module split)
B34a/MVP-4.28 (`8c9a110`, §5.68) helper-extraction (4/5 folds byte-identical, macros>helpers, fold #2 dropped→B35); B34b/MVP-4.29 (`fc96a45`, §5.69) module split (`xdpfilter.bpf.c` 1280→581 LOC into `defs.h`/`maps.h`/`classifier.h`, the 5-file sketch refined to 3). xdp 3658 byte-identical (×3 independent each); round-1 each.

### B35 — ✅ SHIPPED MVP-4.30 (`91fe39a`, §5.70) — wildcard+defaults → `ruleset_state` pack (PERF-M1)
25 static per-axis `wildcard` lookups + 1 `defaults` → ONE hoisted `ruleset_state[active]` struct read. **First verdict-identity slice** (map-schema change, NOT byte-identical); spike-gated measure-first confirmed real win **3658→3437 (−221 insns)**; B37 baseline re-based (sanctioned); oracle-agreement held; subsumed B34a fold #2. round-1.

### B37 — ✅ SHIPPED MVP-4.27 (`bb62891`, §5.67) — decorative regression gates made real
(a) `T_PROD_VERIFIER_LOAD.sh` insn-count print→**FATAL** assert == `${XDPMF_PROD_INSN_BASELINE:-3658}` (consciously reversed `D-mvp-4.23-H3-PRODOBJ`); (b) NEW `T_LOADER_STDERR_GOLDEN.sh` + 3 goldens pinning operator-facing error-string shapes. guard #35 + tester teeth-layer (`T_INSN_BASELINE_GATE.sh`/`T_LOADER_STDERR_SHAPE.sh`). This gate is what every byte-identity slice since leans on (and B35's sanctioned re-baseline rides). round-1.

### B42 — ✅ SHIPPED MVP-4.35 (§5.75) — `redirect` verb: XDP-native steer-to-DPI (Option 1, single global tap)
First **steering** verb (filter→selector). New `action: redirect` + top-level `steering: { redirect_to }` block (`schema_version` {2}→{2,3} additive); `bpf_redirect_map` + a single `BPF_MAP_TYPE_DEVMAP` (`redirect_devmap[0]` = resolved tap ifindex, fail-closed at apply, PASS-on-miss). New `STAT_REDIRECT`/`verdict="redirect"`. Classifier branch APPENDED after `ACTION_DROP` ⇒ PASS/DROP **verdict-identity** held (surviving invariant); xdp insn re-baselined 3437→N (one branch + helper, documented per D-mvp-4.30-REBASELINE precedent). No struct widen (`action_entry`/`rule_entry` stay sizeof==4 — no per-rule target). VERSION 0.16.0→**0.17.0**. **Mirror (clone-and-continue) + per-rule targets remain deferred (Option 2+, need TC/TCX).**
**PO ruling 2026-06-10 (scope-gate of an aborted second steering HLD round): mirror CLOSED, not just deferred — the DPI sink is TERMINAL (selected traffic does NOT continue to Gi), so clone-and-continue has no product need; the §architecture-mirror-redirect.md mirror discriminator resolved "No→redirect". Per-rule targets PARKED — single global tap suffices for v1 (re-charge only on a multi-DPI-destination product signal; engineering default then = A3 devmap-membership-as-target per the discharged grounder ledger). Hardware-SPAN presence: unknown, moot while mirror is closed. Steering capability as shipped (B42) = complete to current product need.**

### B46 [LOW, cosmetic / operator-readability] `apply --dry-run` human view: ethertype to canonical 4-digit hex
**Context:** roadmap-① is complete to operator-usability — B43 (§5.76 offline golden) + B44 (§5.77 `apply --dry-run` verb) + B45 (§5.78 human-decoded view, now the DEFAULT; machine golden behind `--format=golden`). In the B45 human view, `format_dryrun_human` renders the EtherType match axis via `0x{:x}` (no leading-zero pad), so ARP's EtherType `0x0806` prints as **`0x806`** — the zero-stripped form is less recognizable to an operator than the canonical 4-digit `0x0806` (textbook EtherType notation). For a feature whose whole point is operator readability ([[feedback_hld_brief_center_user_job]]), the canonical form is friendlier.
**Fix (≈2 lines):** in `src/lib/map_image.cpp` the ethertype axis renderer → `0x{:04x}` (4-digit zero-padded lowercase); update `tests/T_CLI_APPLY_DRYRUN.sh` ethertype grep `ethertype=0x806`→`ethertype=0x0806`; and `mint/design.md` §5.78.4(a) ethertype value-form table back to "4-digit zero-padded" (it was reconciled DOWN to `0x806` at B45 review r1 OOT to match the shipped impl — this item reverses that toward the canonical form). Surfaced to PO at B45 close; **PO ruled "приведение к каноническому выводу" wanted (2026-06-06).** Pure host-side formatting — no live/datapath/PI impact; fold into the next touch of `map_image.cpp`. Catch: confirm no other EtherType render site relies on the non-padded form (grep `ethertype=`).
