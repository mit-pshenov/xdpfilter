# Documentation Backlog

Tracks pending documentation work. Created 2026-05-27 consolidating:
1. The 13-item bucket originally surfaced as a CHANGELOG-only fence (CHANGELOG.md:245, MVP-3.5 OOS).
2. The 14 doc-dim findings from the multi-dim review at `agent-teams-review/runs/mint-review-mint-l2-mac-filter-202605271147/raw/documentation-reviewer.md` (2026-05-27).

This backlog is **manual prose work** — explicitly separated from `/mint-dev` slices per user direction. Owner: human.

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
