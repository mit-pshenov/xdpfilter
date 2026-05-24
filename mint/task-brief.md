# Task brief — MVP-3.4: observability exporter + manual bypass + rules/action_table skeleton (brownfield, defer posture)

## Goal

Per `mint/architecture-v2.md` MVP-3.4 row, under Open Q #13 RESOLUTION (committed 2d4b31a, 2026-05-24): **per-rule counters are DEFERRED to MVP-3.4b** — this slice ships observability surface for what's already on the kernel (global `stats`) + a manual bypass operator primitive + the `rules`+`action_table` BPF map skeleton (B.2 partial), WITHOUT wiring rules into the datapath and WITHOUT extending the inner-allowlist value beyond `__u8 present`.

The slice ships 3 pieces:

1. **`xdpmf-exporter` binary** — long-running Prometheus `/metrics` HTTP server reading the existing global `stats` `BPF_MAP_TYPE_PERCPU_ARRAY[STAT_MAX=4]` (STAT_PASS / STAT_DROP_DENY / STAT_DROP_MALFORMED / STAT_PASS_CIDR). Wires against `xdpmf_internal` static lib (MVP-3.1 prep pays off). Project's first NEW binary since MVP-2.
2. **Manual bypass primitive** — new `xdpmacfilter bypass --iface <X>` CLI subcommand. Audit-logged, `--unsafe` required in non-tty contexts. Mechanism = invoke existing `detach` path with a warning banner; NO new BPF map flag, NO datapath touch.
3. **`rules`+`action_table` BPF skeleton** — declare two new BPF maps (`rules` ARRAY[64], `action_table` ARRAY[N]) + populate from config on apply. **NOT WIRED into datapath.** Datapath stays MVP-3.2 shape (MAC HASH → CIDR LPM_TRIE → PASS/DROP). Loader emits stderr WARN if config has `rules:` section. Forward compatibility for MVP-3.4b wiring.

Estimated budget per `architecture-v2.md` MVP-3.4 row under defer posture: **~1.5 cycles, low-medium risk**. Slimmer than the ship-everything baseline (2-3 cycles, medium risk) because inner-allowlist-value extension + PI-13 adjudication + per-rule counter wiring are all deferred.

## Context: prior work

- **All prior briefs**: archived in `mint/task-brief-mvp{1,1.1*,2-*,3.1,3.2,3.3}.md`.
- **Existing design**: `mint/design.md` — §5.28 (systemd + Ansible + fleet docs) is the immediate ancestor (MVP-3.3 round-2 pass). PI-1..PI-26 must continue to hold; this slice adds PI-27+ for exporter/bypass/skeleton invariants.
- **Architecture document**: `mint/architecture-v2.md` —
  - **MVP-3.4 dependency graph row**: lines 234-243.
  - **MVP-3.4 per-phase scope summary**: line 312 (was 2-3 cycles medium risk; ~1.5 cycles low-medium under defer).
  - **MVP-3.4 risk register**: lines 337-340 — 4 risks: (a) per-rule counter cardinality blow-up [MOOT under defer]; (b) Q13 map type choice [RESOLVED — defer]; (c) exporter version-skew vs loader [active]; (d) manual bypass misused as automatic fail-open [active].
  - **§MVP-3.4 Open Question #13 RESOLUTION** (newly appended section, ~line 421+): defer rationale, 5 composite options laid out, Option 2 standing default if MVP-3.4b re-asks. Architect MUST read this section for the defer posture context.
- **MVP-3.3 review**: `mint/review.md` — round-2 pass + 1 OOT-deferred (T_SYSTEMD_RESTART_ON_FAILURE flake) — addendum in `mint/impl-notes.md`.
- **MVP-3.1/3.2/3.3 deviations**: `mint/impl-notes.md` D-3.1-1..D-3.3-10 stand. Do NOT undo any.
- **`/mint-hld` HLD artifacts (ephemeral, /tmp only — NOT committed)**: `/tmp/mint-hld-mint-l2-mac-filter-202605242116/{architect-HASH,architect-ARRAY,architect-T,synthesis,review}.md` — round outputs, will be wiped on /tmp cleanup. Synthesis content is the committed amendment.

## Workflow rules (brownfield mode)

- **Architect**: read existing `design.md` (focus §5.26 config harness — schema you extend with `rules:` block and `action:` field; §5.27 CIDR — second-axis precedent; §5.28 systemd — exporter unit will mirror this template idiom; §6.5 PI table 1..26; §4.1 exit codes through 9; §5.4/§5.19/§5.22 trust+identity invariants — bypass primitive must NOT silently bypass these) + `architecture-v2.md` MVP-3.4 row + **§MVP-3.4 Open Question #13 RESOLUTION** (just-amended section) + this brief. EDIT `design.md` in place. Append `§5.29 MVP-3.4: observability exporter + manual bypass + rules/action_table skeleton` after §5.28. Add new §6.x TestStrategy entries for the 4-6 new ctests. Update §6.5 Preserved invariants — PI-1..PI-26 continue + add PI-27+ for exporter/bypass/skeleton invariants. Update §7 OOS — move MVP-3.4 components from deferred to shipped; surface MVP-3.4b (per-rule counter + inner-value extension) as the next slice WITH explicit reference to the open Q #3 (PI-13-3.1 adjudication) that gates it.
- **Impl**: NEW files: `src/exporter/main.cpp` (entry), `src/exporter/http.{cpp,hpp}` (embedded minimal HTTP/1.0 server per HG-3.4-3), `src/exporter/prom_format.{cpp,hpp}` (Prometheus text format emitter), `src/exporter/stats_reader.{cpp,hpp}` (PERCPU_ARRAY scan + sum), `src/cli/bypass.{cpp,hpp}` (CLI subcommand). EDIT: `src/bpf/mac_filter.bpf.c` (add `rules` ARRAY + `action_table` ARRAY declarations; datapath UNCHANGED), `src/common/mac_filter.h` (new map name constants + action enum stubs), `src/lib/apply_internal.{cpp,hpp}` (populate rules+action_table from config; emit WARN if rules: block non-empty), `src/lib/config.{cpp,hpp}` (schema accepts `rules:` block with `id/match/action` fields per Q3), `src/lib/yaml_subset.cpp` (parser extension if needed for rules block — likely already handles it), `src/cli/cli.cpp` (register `bypass` subcommand), `CMakeLists.txt` (add xdpmf-exporter target, version 0.5.0 → 0.6.0; install both binaries to /usr/bin under CMAKE_INSTALL_PREFIX), `CHANGELOG.md` (new [0.6.0] entry), NEW `systemd/xdpmf-exporter.service` (single-instance unit per Q5 recommendation N3), NEW `ansible/templates/xdpfilter-config.yaml.j2` (extend with `rules:` block forward-fit if architect picks). `loader.hpp` PUBLIC-API UNCHANGED (PI-7-3.4 strengthening — ZERO diff on src/loader.hpp continues across 4 cycles).
- **Tester**: NEW ctests in `tests/` (4-6). Suggested:
  - `T_EXPORTER_METRICS_FORMAT.sh` — `curl localhost:9417/metrics` + regex Prometheus text format compliance; SKIP-77 if curl absent (shouldn't be on dev VM)
  - `T_EXPORTER_VALUES_MATCH_STATS.sh` — generate known traffic via persistent AF_PACKET socket (MVP-3.1 idiom), query exporter, query bpftool stats, assert sum equal
  - `T_EXPORTER_NO_ATTACHED_IFACE.sh` — exporter starts/serves on system with no attached XDP; `/metrics` returns no `xdpfilter_*` lines (graceful empty)
  - `T_BYPASS_CMD_DETACHES.sh` — `xdpmacfilter bypass --iface veth-test0 --unsafe --reason test` → XDP detached + stderr audit line matches `BYPASS activated.*uid=`
  - `T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE.sh` — bypass under nohup without `--unsafe` → exit 1, stderr message instructs to use --unsafe
  - `T_RULES_SKELETON_NOT_WIRED.sh` — apply config with `rules:` section, generate traffic that would match a rule "if wired", verify datapath behavior IDENTICAL to MVP-3.2 (no rule_id-driven differentiation; counter values match expected MVP-3.2 distribution)
  - New helpers in `tests/lib/common.sh` ONLY IF needed (e.g., `start_exporter_in_background()` + cleanup). DO NOT modify existing 36 tests (PI-6-3.4 = PI-6-3.3 strict superset).
- **Reviewer**: 5-point brownfield framework. Special attention:
  - **(1) PI-1..PI-26 preserved**: inner-allowlist-value PI (whichever # — verify in design.md §6.5) is the load-bearing one to NOT touch this slice. `__u8 present` stays `__u8 present`. This is what defer was about.
  - **(2) `rules`+`action_table` are SKELETON ONLY**: datapath does NOT consult them on the per-packet path. Read `src/bpf/mac_filter.bpf.c` xdp_filter() function and verify byte-equivalent lookup chain to MVP-3.2 modulo new map *declarations*.
  - **(3) Bypass primitive WARNS every invocation and requires `--unsafe` in non-tty**: per risk register row 340 — re-introducing C.5 fail-open via ops-script human error is the named risk.
  - **(4) Exporter is READ-ONLY by design**: no map mutations, no attach/detach calls. Exporter holds RO file descriptors to pinned maps.
  - **(5) PI-7-3.4 ZERO diff on `src/loader.hpp` public API**: the public attach/detach surface must remain byte-equivalent. New binary lives in `src/exporter/`, new CLI subcommand in `src/cli/`; neither leaks into loader.hpp.

## Human-gate decisions (defaults applied — override at architect Phase A if you disagree)

### HG-3.4-1: `rules`+`action_table` = STRUCTURAL-ONLY (not wired in datapath)

**Resolves Open Q #4 from /mint-hld round.** Declare and populate the maps; do NOT touch the datapath function body. Inner-allowlist value STAYS `__u8 present`. Loader emits stderr WARN if config has non-empty `rules:` block: `xdpmacfilter: rules: section parsed (N entries) but per-rule action dispatch deferred to MVP-3.4b — datapath uses MAC/CIDR-only matching this cycle`.

**Rationale**: this is the interpretation that genuinely realizes the defer's PI-13 savings. Wiring would force inner-value extension → defeats defer. Skeleton-only buys forward compatibility (operator can author `rules:` blocks now; MVP-3.4b is a pure wiring slice not a schema+wiring slice).

**Default**: STRUCTURAL-ONLY. Architect picks the precise stub shape of `action_table` value at Q3.

### HG-3.4-2: bypass primitive = CLI subcommand wrapping existing `detach` + audit warning

`xdpmacfilter bypass --iface <X> [--unsafe] [--reason "<text>"]` subcommand. Interactive tty: y/N prompt. Non-tty: require `--unsafe` flag (exit 1 with audit-trail stderr message if missing). Always logs to stderr in audit format: `xdpmacfilter: BYPASS activated on <iface> by uid=<UID> reason=<text|UNSPECIFIED>`. Implementation: calls existing `loader::detach` codepath. NO new BPF map flag, NO datapath touch.

**Rationale**: cleanest path. A new BPF map flag for "bypass mode" would touch the datapath, defeating defer's complexity savings. Detach IS bypass at the BPF level; the CLI subcommand adds the audit/safety layer.

**Default**: detach-alias + audit + `--unsafe` gate. Architect MAY propose alternate Q decision (e.g., bypass via in-map flag) if there's a strong reason.

### HG-3.4-3: exporter HTTP = embedded minimal C++23 HTTP/1.0 server, `/metrics` over TCP

~150-200 LOC plain-socket HTTP/1.0 server. Listens on configurable port (default `9417` — checked against the prometheus_exporter_default_ports registry as of 2026 to avoid collision). NO HTTP routing library, NO third-party dep. Aligns with `cli.cpp:1-3` "zero non-standard deps" project value.

**Rationale**: alternatives evaluated:
- prometheus-cpp: adds dep, violates project value
- node_exporter textfile-collector: requires `node_exporter` on every operator host, file rotation, extra cron — net cost > embedded server cost
- microhttpd / cpp-httplib: smaller deps but still deps

**Default**: embedded minimal server. Architect MAY pick textfile-collector pattern if a strong reason emerges.

## Open mechanism questions (architect decides; document in §5.29)

### Q1: exporter runtime model

- **D1 (long-running daemon)**: starts at boot via systemd, listens on TCP, serves `/metrics` on every Prometheus scrape. State-resident process.
- **D2 (oneshot per scrape)**: invoked per Prometheus scrape (xinetd-style or systemd socket-activated), reads stats, prints, exits.

**Recommendation**: **D1**. Simpler ops, lower per-scrape latency, standard observability pattern. Aligns with single-instance `xdpmf-exporter.service` per Q5 N3.

### Q2: exporter binary install path

- `/usr/bin/xdpmf-exporter` (consistent with `xdpmacfilter`)
- `/usr/libexec/xdpmf/exporter` (libexec convention)

**Recommendation**: **`/usr/bin/xdpmf-exporter`**.

### Q3: `rules` map value shape (for skeleton-only purposes)

For SKELETON-ONLY, we still need to define what an entry looks like for forward compatibility with MVP-3.4b wiring. Proposed:

```c
struct rule_entry {
    __u8 present;      /* 0 = empty slot; 1 = occupied */
    __u8 action_id;    /* index into action_table */
    __u8 _pad[2];
};
struct action_entry {
    __u8 action_type;  /* 0 = PASS, 1 = DROP (MVP-3.4 only); future: MIRROR/RL/TAG */
    __u8 _pad[3];
};
```

**Recommendation**: minimal — only `present + action_id` per rule, `action_type` per action. Forward-fit hooks (named rules, action params) land later. The maps exist; their inner shapes are committed but their use is deferred.

### Q4: stats map exposure — direct read vs cached snapshot

- **E1 (direct read on scrape)**: exporter reads `/sys/fs/bpf/.../<iface>/stats` on every `/metrics` request; PERCPU sum is fast (<1ms typical).
- **E2 (cached snapshot)**: exporter polls every N seconds, `/metrics` returns last snapshot. Bounded staleness.

**Recommendation**: **E1**. PERCPU sum on a 32-CPU box reading 4 u64 slots × 32 = 128 u64 reads is microseconds; no caching layer needed.

### Q5: exporter systemd integration

- **N1 (no systemd this slice)**: ship binary only; operator wires up systemd.
- **N2 (per-iface template unit)**: `xdpmf-exporter@.service` template, one instance per iface.
- **N3 (single-instance unit)**: `xdpmf-exporter.service` listens on one port, scans ALL attached interfaces under `XDPMF_BPFFS_ROOT`, emits per-iface labels.

**Recommendation**: **N3**. Prometheus scrape pattern is one endpoint per node, multi-iface inside via `iface` label. Matches `node_exporter` and similar.

### Q6 (optional): tackle MVP-3.1/3.2/3.3 OOT-deferred housekeeping items?

5+ items still deferred:
- T_SYSTEMD_RESTART_ON_FAILURE flake (MVP-3.3 OOT-1)
- Orphan map pins from T_ATTACH_TAG_MISMATCH (MVP-3.1)
- T_APPLY_ATOMIC_SWAP_NO_DROP stale NOTE (MVP-3.1)
- §6.25 "replacing existing program" grep (MVP-3.1)
- ParsedAttach/Detach/Apply wrapper design-text inaccuracy (MVP-3.1)

**Recommendation**: **DEFER**. This slice already has new-binary territory (first since MVP-2) + 3 distinct piece-types. Housekeeping in a dedicated cycle is cleaner. T_SYSTEMD_RESTART_ON_FAILURE flake may auto-resolve if ctest stress profile changes between slices.

## Scope (3 items + 4-6 tests — anything else is OOS)

### Item 1 — `xdpmf-exporter` binary (per HG-3.4-3, Q1, Q2, Q4, Q5)

**Where**: NEW `src/exporter/{main.cpp, http.{cpp,hpp}, prom_format.{cpp,hpp}, stats_reader.{cpp,hpp}}`, NEW `systemd/xdpmf-exporter.service`.

**Action**:
- main.cpp: parse args (`--port <N>` default 9417, `--bind <addr>` default `127.0.0.1`, `--bpffs-root <path>` default `XDPMF_BPFFS_ROOT`), set signal handlers, start HTTP server.
- http.{cpp,hpp}: minimal HTTP/1.0 server — accept TCP conn, read request line, route `/metrics` (200 OK, Content-Type: text/plain; version=0.0.4) vs `/healthz` (200 OK liveness) vs other (404). Single-threaded acceptor + per-conn synchronous handle. ~150-200 LOC.
- stats_reader.{cpp,hpp}: scan `XDPMF_BPFFS_ROOT/*/stats` for pinned stats maps (one per attached iface), open RO, read PERCPU_ARRAY[STAT_MAX=4] via libbpf, sum across CPUs. Returns vector<{iface_name, stats[4]}>. Wires against `xdpmf_internal` static lib for the map-name constants.
- prom_format.{cpp,hpp}: format Prometheus text output:
  - HELP/TYPE lines for `xdpfilter_packets_total`
  - One sample per (iface, verdict) tuple. Verdicts: `pass`, `drop_deny`, `drop_malformed`, `pass_cidr`
  - Counter semantic (`# TYPE xdpfilter_packets_total counter`)
- systemd/xdpmf-exporter.service: Type=simple ExecStart=/usr/bin/xdpmf-exporter, AmbientCapabilities=CAP_BPF (read-only map access via fd-relative bpffs ops per MVP-2 Sec idiom), Restart=on-failure with same StartLimit pattern as MVP-3.3's xdpmacfilter@.service.

**CMakeLists.txt**: add `xdpmf-exporter` target linking `xdpmf_internal` + libbpf; install both binaries to `${CMAKE_INSTALL_PREFIX}/bin/` (project-relative install, OS-level install is operator's call).

### Item 2 — Manual bypass primitive (per HG-3.4-2)

**Where**: NEW `src/cli/bypass.{cpp,hpp}`, EDIT `src/cli/cli.cpp` (register subcommand), EDIT `src/cli/main.cpp` (dispatch).

**Action**:
- New subcommand parser: `xdpmacfilter bypass --iface <X> [--unsafe] [--reason "<text>"]`.
- TTY check: `isatty(STDIN_FILENO) && isatty(STDERR_FILENO)`. If interactive: prompt `BYPASS will detach XDP filter on <iface>. Continue? [y/N]:` — non-y answer → exit 0 (no-op).
- If non-interactive: require `--unsafe` flag. If absent: exit 1 with `xdpmacfilter: refusing to bypass in non-interactive context without --unsafe flag (audit safety)`.
- Always log to stderr BEFORE detach: `xdpmacfilter: BYPASS activated on <iface> by uid=$(getuid()) reason="<text or UNSPECIFIED>"`.
- Implementation: construct `loader::DetachConfig`, call existing `loader::detach()` path. Exit code: 0 on success, propagate loader::detach errors otherwise.

### Item 3 — `rules` + `action_table` BPF skeleton (per HG-3.4-1, Q3)

**Where**: EDIT `src/bpf/mac_filter.bpf.c`, EDIT `src/common/mac_filter.h`, EDIT `src/lib/apply_internal.cpp`, EDIT `src/lib/config.{cpp,hpp}`.

**Action**:
- `src/common/mac_filter.h`: add map name constants `XDPMF_MAP_RULES_NAME = "rules"`, `XDPMF_MAP_ACTION_TABLE_NAME = "action_table"`; define `struct rule_entry { __u8 present; __u8 action_id; __u8 _pad[2]; };` and `struct action_entry { __u8 action_type; __u8 _pad[3]; };` per Q3 recommendation; enum `xdpmf_action_type { ACTION_PASS = 0, ACTION_DROP = 1, ACTION_MAX = 2 };`
- `src/bpf/mac_filter.bpf.c`: declare two new maps:
  ```c
  struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, XDPMF_ALLOWLIST_MAX); __type(key, __u32); __type(value, struct rule_entry); } rules SEC(".maps");
  struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, ACTION_MAX); __type(key, __u32); __type(value, struct action_entry); } action_table SEC(".maps");
  ```
  **xdp_filter() function body UNCHANGED**. Verify byte-equivalent disassembly to MVP-3.2 (architect MAY ask reviewer for confirmation).
- `src/lib/config.{cpp,hpp}`: schema extension — accept `rules:` block in YAML with per-entry `id: <int>`, `match: { mac: <addr>, src_cidr: <net> }`, `action: { type: pass | drop }`. Validator: id ∈ [0, XDPMF_ALLOWLIST_MAX-1] (re-use §5.26 rule 3); action.type ∈ {pass, drop}.
- `src/lib/apply_internal.cpp`: on apply, populate `rules` and `action_table` maps from config. If `Config.rules` non-empty: emit stderr WARN `xdpmacfilter: rules: section parsed (N entries) but per-rule action dispatch deferred to MVP-3.4b — datapath uses MAC/CIDR-only matching this cycle`.

### Item 4 — Integration tests (per HG-3.4-3 + Items 1-3)

**Where**: NEW tests per architect's Q-decisions. 4-6 suggested (T_EXPORTER_METRICS_FORMAT, T_EXPORTER_VALUES_MATCH_STATS, T_EXPORTER_NO_ATTACHED_IFACE, T_BYPASS_CMD_DETACHES, T_BYPASS_REQUIRES_UNSAFE_NONINTERACTIVE, T_RULES_SKELETON_NOT_WIRED — full descriptions in Workflow rules → Tester section above).

## Out of scope (explicit)

- **Per-rule counter map** (`per_rule_counters` BPF_MAP_TYPE_PERCPU_*) — MVP-3.4b slice (Open Q #13 resolved → defer). DO NOT add this map.
- **Inner-allowlist-value extension** (`__u8 → struct { __u8 present; __u32 rule_id; }`) — MVP-3.4b. PI-13-3.1 adjudication needed before then. DO NOT touch inner-value shape of `allowlist` HASH or `cidr_allowlist` LPM_TRIE.
- **Datapath wiring of `rules` or `action_table`** — explicit fence per HG-3.4-1. xdp_filter() body must remain byte-equivalent to MVP-3.2.
- **Action types beyond {pass, drop}** — MIRROR/RATE_LIMIT/TAG/REDIRECT all MVP-3.8+.
- **JSON structured logs from exporter** — MVP-3.5.
- **sFlow** — MVP-3.6 (conditional).
- **`xdpmf-exporter` HTTPS/TLS** — operator wraps with stunnel/nginx if needed.
- **`xdpmf-exporter` authentication** — Prometheus scrape is unauthenticated by convention.
- **Exporter histograms / summary / labels beyond `{iface, verdict}`** — kept minimal.
- **Bypass via BPF map flag** (versus detach-alias) — explicitly fenced by HG-3.4-2 unless architect overrides with strong reason.
- **Library extraction `libxdpmf.so.0`** — MVP-3.6+ optional.
- **Daemon `xdpmfd`** — MVP-3.6+ optional.
- **L4 ports / VLAN / IPv6 CIDR** — still fenced per MVP-3.2 §7 OOS.
- **Binary rename `xdpmacfilter` → `xdpfilter`** — still MVP-3.12.
- **MVP-3.1/3.2/3.3 OOT-deferred housekeeping items** — per Q6 default DEFER.

## Definition of done

- `§5.29 MVP-3.4: observability exporter + manual bypass + rules/action_table skeleton` amendment in `design.md` documenting Q1-Q6 decisions + HG-3.4-1/2/3 confirmation + cross-reference to `architecture-v2.md` §"§MVP-3.4 Open Question #13 RESOLUTION" for defer rationale.
- New `§6.x TestStrategy` entries for 4-6 new ctests.
- `§6.5 Preserved invariants` extended: PI-1..PI-26 hold + new PI-27+ for exporter/bypass/skeleton. **Inner-allowlist-value PI explicitly preserved** (the load-bearing one this cycle).
- `loader.hpp` PUBLIC-API UNCHANGED (PI-7-3.4 strengthening — ZERO diff continues across 4 cycles).
- `xdpmacfilter --version` reports `xdpmacfilter 0.6.0` (bump from 0.5.0).
- `xdpmf-exporter --version` reports `xdpmf-exporter 0.6.0` (same version-stamp across binaries — shared `version.h`).
- `CHANGELOG.md` entry `[0.6.0] - 2026-05-NN`.
- 4-6 new ctests pass; 36 existing ctests still pass (PI-6-3.4 strict superset, only exporter/bypass/skeleton additions).
- `XDPMF_SANITIZERS=ON` build clean (both binaries).
- `systemd-analyze verify systemd/xdpmf-exporter.service` → exit 0.
- `mint/review.md` round-1 verdict = `pass`.
- One git commit per phase boundary per workflow B.

## Dependencies

- libbpf (existing); no new build deps.
- HTTP libraries: NONE — embedded minimal HTTP/1.0 server in C++23.
- Test-time: `curl` for scraping (likely on dev VM); `bpftool` (existing); persistent AF_PACKET socket idiom (MVP-3.1+).
- No new C++ libraries. No new BPF features. No new kernel-version dependencies.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       [lang/cpp.md, lang/cmake.md, lang/bpf.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []
```
