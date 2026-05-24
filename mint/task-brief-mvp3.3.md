# Task brief — MVP-3.3: systemd + Ansible + fleet docs (brownfield)

## Goal

Make the loader **operator-deployable** by adding systemd integration + an example Ansible playbook + identity-gate-relax `fleet` mode operator docs. Per `mint/architecture-v2.md` MVP-3.3 row: ops/integration slice, low BPF/C++ surface area, mostly unit file + playbook + docs.

The slice ships 4 pieces:

1. **systemd unit template** `xdpmacfilter@.service` — one instance per iface, `Type=oneshot RemainAfterExit=yes`, ExecStart re-runs `xdpmacfilter apply -f /etc/xdpfilter/%i.yaml --iface %i`, ExecReload re-runs the same (idempotent reattach via MVP-3.1's bpf_link__update_program), ExecStop runs `xdpmacfilter detach --iface %i`. `Restart=on-failure` for the apply (oneshot exit-nonzero retry).
2. **Ansible example playbook** at `ansible/xdpmacfilter-deploy.yml` — installs binary + systemd unit + `/etc/xdpfilter/<iface>.yaml` config (Jinja2 template) + handler `notify: reload xdpmacfilter` driving `systemctl reload`. Reference example only — not a full collection/role; operator adapts to fleet specifics.
3. **Fleet-mode operator docs** at `docs/FLEET_DEPLOYMENT.md` — when to set `XDPMF_TRUST_MODEL=fleet`, the audit story (stderr emits `trust_model=<mode>` at attach per MVP-3.1 HG3), recommended Prometheus alert pattern (fleet-wide trust-model distribution divergence — implementation is MVP-3.4 exporter scope; this slice just specifies the alert semantic). README pointer added.
4. **Integration tests** — systemd unit install + daemon-reload + start/reload/stop lifecycle exercised via real `sudo systemctl` on dev VM (user has passwordless root per project context). Ansible playbook gets `ansible-playbook --syntax-check` validation (skipped if ansible not installed). 3-5 ctests.

Estimated budget per `architecture-v2.md` per-phase scope summary: ~1 cycle, low risk. Smallest LOC delta of MVP-3.x to date — mostly text files (unit + YAML playbook + Markdown docs) + a thin ctest shim around systemctl.

## Context: prior work

- **All prior briefs**: archived in `mint/task-brief-mvp{1,1.1*,2-*,3.1,3.2}.md`.
- **Existing design**: `mint/design.md` — §5.26 (config harness) + §5.27 (L3 src-CIDR) are the immediate ancestors. PI-1..PI-18 must continue to hold; this slice adds PI-19+ for systemd/Ansible/docs invariants.
- **Architecture document**: `mint/architecture-v2.md` —
  - **MVP-3.3 dependency graph row**: lines 226-231.
  - **MVP-3.3 per-phase scope summary**: line 311 (1 cycle, low risk).
  - **MVP-3.3 risk register**: lines 335-336 — 2 risks: (a) Ansible idempotency drift across heterogeneous fleet; (b) `XDPMF_TRUST_MODEL` mis-set escapes audit (silent posture change).
  - **Component map** row 6: `xdpfilter@.service` (systemd unit template) — note the name uses `xdpfilter`; this slice ships under `xdpmacfilter@.service` (HG-3.3-1 below) and the rename is deferred to MVP-3.12.
- **MVP-3.2 review**: `mint/review.md` — round-1 pass with 3 inline-merged design-text OOTs; clean baseline.
- **MVP-3.1/3.2 deviations**: `mint/impl-notes.md` D-3.1-1..D-3.1-4 stand; MVP-3.2 had 0 deviations. Do NOT undo any.
- **User permission context**: dev VM has passwordless `sudo` available (per project context). `systemctl daemon-reload`, `systemctl start xdpmacfilter@veth-test0`, etc. can run directly.

## Workflow rules (brownfield mode)

- **Architect**: read existing `design.md` (focus §5.26+§5.27 — your immediate ancestors; §6.5 PI-1..PI-18 — invariants you extend; §4.1 — exit codes through 9; §5.20 attach/detach flow — systemd ExecStart/ExecStop call into this; §5.26 trust_model env var — fleet-mode docs describe this) + `architecture-v2.md` MVP-3.3 rows + this brief. EDIT `design.md` in place. Append `§5.28 MVP-3.3: systemd + Ansible + fleet docs` after §5.27. Add new §6.x TestStrategy entries for the 3-5 new ctests. Update §6.5 Preserved invariants — PI-1..PI-18 continue + add PI-19+ for systemd/Ansible/docs invariants (e.g., "unit file syntax accepted by `systemd-analyze verify`"; "ansible playbook passes --syntax-check"; "fleet-mode docs cite the actual stderr log format from §5.26"). Update §7 OOS — move MVP-3.3 components from deferred to shipped; surface MVP-3.4 (per-rule counters / exporter) as the next-natural slice.
- **Impl**: NEW files: `systemd/xdpmacfilter@.service` (unit template), `ansible/xdpmacfilter-deploy.yml` (example playbook), `ansible/templates/xdpfilter-config.yaml.j2` (config template), `docs/FLEET_DEPLOYMENT.md` (operator docs). EDIT: `README.md` (add pointer to FLEET_DEPLOYMENT.md), `CMakeLists.txt` (version bump 0.4.0 → 0.5.0; install rules if architect picks them — install the unit file to a project-relative path for ctest; system install is OOS), `CHANGELOG.md` (new [0.5.0] entry). loader.hpp/loader.cpp/cli.cpp/apply.cpp/bpf/* probably UNCHANGED — this slice is pure ops integration unless architect surfaces a need (e.g., new `--quiet` flag for cleaner systemd journal output, which would be a Q decision). PI-7-3.2 ZERO diff on loader.hpp continues — strengthen to PI-7-3.3.
- **Tester**: NEW ctests in `tests/` (3-5). Suggested naming: `T_SYSTEMD_UNIT_SYNTAX.sh`, `T_SYSTEMD_LIFECYCLE.sh` (install + start + reload + stop end-to-end against veth fixture), `T_SYSTEMD_RESTART_ON_FAILURE.sh` (force apply exit-nonzero, verify Restart=on-failure kicks in), `T_ANSIBLE_PLAYBOOK_SYNTAX.sh` (SKIP-77 if `ansible-playbook` not in PATH), `T_FLEET_DOCS_SUBSTRING.sh` (regex-check that FLEET_DEPLOYMENT.md cites the actual stderr `trust_model=<mode>` format and not stale prose). New helpers in `tests/lib/common.sh` ONLY IF needed (e.g., `setup_systemd_unit_in_test_path()`); existing helpers UNCHANGED. DO NOT modify existing 31 tests (PI-6-3.3 = PI-6-3.2 strict superset).
- **Reviewer**: 5-point brownfield framework. Special attention:
  - **(1) PI-1..PI-18 preserved**: nothing in MVP-3.3 should touch identity gates, trust_model semantics, atomic apply, or counter behaviour.
  - **(2) systemd ExecStart/ExecReload/ExecStop verify against actual loader CLI**: ExecStart calls `xdpmacfilter apply -f ... --iface %i`; assert this is the ACTUAL exit-0 path (T_APPLY_VALID_CONFIG already verifies that).
  - **(3) Ansible playbook idempotency**: per risk register row 1 — playbook should be idempotent (re-running yields no changes if config unchanged). `ansible-playbook --check` validates dry-run path.
  - **(4) Fleet-mode docs must cite ACTUAL stderr format**: per MVP-3.1 HG3 the format is literally `xdpmacfilter: trust_model=<strict|fleet>`. Docs must match grep-able reality (mitigation for risk register row 2).
  - **(5) No CLI surface change**: PI-7-3.3 ZERO diff on loader.hpp. New `--quiet` or similar must be explicitly negotiated.

## Human-gate decisions (defaults applied — override at architect Phase A if you disagree)

### HG-3.3-1: Unit name = `xdpmacfilter@.service`

Match the current binary name (`xdpmacfilter`). Architecture-v2.md component map calls it `xdpfilter@.service` but explicitly defers the binary rename to MVP-3.12. Shipping `xdpfilter@.service` now would create a rename transition burden NOW instead of in MVP-3.12.

**Default**: `xdpmacfilter@.service`. MVP-3.12 will rename + ship transitional `xdpfilter@.service → xdpmacfilter@.service` alias.

### HG-3.3-2: Ansible scope = single example playbook + handler

Not a full Ansible collection or role. One working example playbook + one Jinja2 template + one handler (`reload xdpmacfilter` → `systemctl reload xdpmacfilter@<iface>`). Operator adapts to fleet specifics (inventory, secrets, multi-iface variations).

**Default**: minimal example only. Production-grade collection is OOS.

### HG-3.3-3: systemd test approach = real `sudo systemctl`

User confirmed passwordless sudo available on dev VM. Tests run real `systemctl daemon-reload`, `systemctl start xdpmacfilter@veth-test0`, etc. Avoid stub-validation-only approach — it doesn't catch unit file semantic bugs.

**Default**: real systemctl. Install unit to a ctest-controlled path (e.g., `/etc/systemd/system/` if architect picks system install for the test, OR `~/.config/systemd/user/` for user-mode). Cleanup in trap.

## Open mechanism questions (architect decides; document in §5.28)

### Q1: systemd unit install path for ctest

- **Option I1 (system path)**: `/etc/systemd/system/xdpmacfilter@.service`. Requires sudo (have it). Standard production path. Risk: stale install if cleanup fails.
- **Option I2 (user path)**: `~/.config/systemd/user/xdpmacfilter@.service` + `--user` systemctl. No sudo for the install. **But**: BPF attach needs CAP_BPF — user systemd can't grant that. ExecStart would need to `sudo xdpmacfilter ...` from within user-mode unit, which is awkward.
- **Option I3 (ctest-local path + DropInDirectory override)**: install to `/tmp/xdpmf-systemd-test-$$/system/` and pass `SYSTEMD_UNIT_PATH=...` to a child systemctl invocation. Most isolated but most complex.

**Recommendation**: **I1** (system path) with aggressive cleanup in test trap (`systemctl stop xdpmacfilter@... ; rm /etc/systemd/system/xdpmacfilter@.service ; systemctl daemon-reload`). Production-realistic and simplest. Single data point of stale install (test trap failure) is easy to spot.

### Q2: ExecReload mechanism

- **Option R1 (re-exec `apply -f`)**: ExecReload re-runs `xdpmacfilter apply -f /etc/xdpfilter/%i.yaml --iface %i`. Idempotent reattach via MVP-3.1's bpf_link__update_program. Same as ExecStart.
- **Option R2 (SIGHUP)**: loader gets a signal handler that re-reads the config file. Currently no SIGHUP handler exists; MVP-3.1 OOS explicitly fenced SIGHUP. Would require new code.
- **Option R3 (no ExecReload, force restart)**: `systemctl reload` falls back to restart. Slower (full detach+reattach, brief drop window) but simpler.

**Recommendation**: **R1**. SIGHUP is explicitly OOS per MVP-3.1; restart-as-reload (R3) breaks the atomic-swap promise that Composite 6 was built for. R1 is the natural answer (ExecReload = ExecStart in this design).

### Q3: Fleet-mode docs depth

- **Option D1 (single MD file)**: `docs/FLEET_DEPLOYMENT.md` ~50-100 lines. README pointer. Covers: when fleet mode, audit story, recommended alert pattern (described semantically — exporter is MVP-3.4 scope).
- **Option D2 (extended)**: D1 + `docs/SECURITY.md` + `docs/AUDIT.md`. Comprehensive docs sprint within this slice.

**Recommendation**: **D1**. D2 is scope creep — this slice's brief explicitly fences exporter / Prometheus implementation to MVP-3.4. Docs grow as features land.

### Q4: Restart=on-failure tuning

systemd defaults: no restart limit. Could runaway-loop if config is permanently broken.

- **Option RT1 (default no limit)**: `Restart=on-failure`. Apply failure (e.g., bad YAML) → systemd loops forever.
- **Option RT2 (rate-limited)**: `Restart=on-failure` + `StartLimitBurst=5 StartLimitIntervalSec=300`. After 5 failures in 5 min, systemd gives up. Operator must reset via `systemctl reset-failed`.
- **Option RT3 (no restart)**: `Restart=no`. Apply failure → unit stays dead. Operator must manually `systemctl start`.

**Recommendation**: **RT2**. Production-sensible — handles transient failures (race condition on boot, brief network blip during config push) but doesn't infinite-loop on permanent failures (bad config syntax).

### Q5: README integration

- **Option N1 (add 1 section)**: README gains a "Production deployment" section pointing to FLEET_DEPLOYMENT.md and the systemd unit. ~10-15 lines.
- **Option N2 (rewrite)**: README restructured to lead with deployment.
- **Option N3 (no README change)**: docs/FLEET_DEPLOYMENT.md discoverable only via file browsing.

**Recommendation**: **N1**. Minimal disturbance; preserves existing README structure.

### Q6 (optional): tackle MVP-3.1/3.2 OOT-deferred housekeeping items?

5 items still deferred from prior cycles (orphan map pins from T_ATTACH_TAG_MISMATCH; stale NOTE comment; cli.hpp ParsedAttach wrapper design-text; §6.25 "replacing existing program" grep; MVP-3.2 had 0 deferred). Architect picks: include if scope budget allows; defer otherwise.

**Recommendation**: **DEFER**. This slice's scope is already 4 piece-types (unit + playbook + docs + tests), and ops integration tests are new territory. Housekeeping in a dedicated cycle is cleaner than mixing.

## Scope (4 items + 3-5 tests — anything else is OOS)

### Item 1 — systemd unit template (per Q1 + Q2 + Q4)

**Where**: NEW `systemd/xdpmacfilter@.service` (template unit file).

**Action**: write the unit template per Q1-Q4 decisions. Key directives: `Type=oneshot RemainAfterExit=yes`, `ExecStart=/usr/bin/xdpmacfilter apply -f /etc/xdpfilter/%i.yaml --iface %i`, `ExecReload=/usr/bin/xdpmacfilter apply -f /etc/xdpfilter/%i.yaml --iface %i` (per R1), `ExecStop=/usr/bin/xdpmacfilter detach --iface %i`, `Restart=on-failure StartLimitBurst=5 StartLimitIntervalSec=300` (per RT2). Capability hardening: `AmbientCapabilities=CAP_BPF CAP_NET_ADMIN`. Document each directive's purpose inline.

CMakeLists.txt: project-local install via `install(FILES ...)` to a configurable prefix (default `${CMAKE_INSTALL_PREFIX}/lib/systemd/system/`). System install is operator's call, not the build.

### Item 2 — Ansible example playbook (per HG-3.3-2)

**Where**: NEW `ansible/xdpmacfilter-deploy.yml` (playbook), `ansible/templates/xdpfilter-config.yaml.j2` (Jinja2 config template).

**Action**: minimal play that:
- Copies `/usr/bin/xdpmacfilter` (assumes binary built externally; operator provides build pipeline).
- Templates `/etc/xdpfilter/{{ iface }}.yaml` from `xdpfilter-config.yaml.j2` with operator-provided MAC list + CIDR list variables.
- Drops `xdpmacfilter@.service` to `/etc/systemd/system/`.
- `systemctl daemon-reload` (handler).
- `systemctl enable --now xdpmacfilter@{{ iface }}.service` (handler).
- On config change: `notify: reload xdpmacfilter` → `systemctl reload xdpmacfilter@{{ iface }}.service` (handler — uses our ExecReload).

Idempotent (mitigation per risk register row 1 — re-running with same vars yields no changes).

### Item 3 — Fleet-mode operator docs (per Q3 + Q5)

**Where**: NEW `docs/FLEET_DEPLOYMENT.md` (~50-100 lines), EDIT `README.md` (add 1 pointer section per N1).

**Action**: docs cover:
- When to use `XDPMF_TRUST_MODEL=fleet` (decision matrix: trusted segment vs operator-managed-only).
- Audit story: stderr emits `xdpmacfilter: trust_model=<mode>` at every attach (cite actual format from §5.26).
- Recommended Prometheus alert semantic: fleet-wide trust_model distribution should be uniform; alert when divergence detected. Note that the alert IMPLEMENTATION requires the MVP-3.4 exporter (forward reference).
- Example systemd Drop-In to set the env var via `Environment=XDPMF_TRUST_MODEL=fleet`.
- Cite §5.4/§5.19/§5.22 invariants that fleet does/doesn't relax (per HG3: ONLY §5.4 relaxes; §5.19+§5.22 hold in both modes).

### Item 4 — Integration tests (per HG-3.3-3)

**Where**: NEW tests in `tests/` per architect's Q-decisions. Suggested 3-5 tests:

- **`T_SYSTEMD_UNIT_SYNTAX.sh`** — `systemd-analyze verify systemd/xdpmacfilter@.service` → exit 0. No fixture needed.
- **`T_SYSTEMD_LIFECYCLE.sh`** — install unit to `/etc/systemd/system/` per I1; create config at `/etc/xdpfilter/veth-test0.yaml`; `systemctl daemon-reload`; `systemctl start xdpmacfilter@veth-test0`; assert XDP attached + pin present; modify config; `systemctl reload xdpmacfilter@veth-test0`; assert active_idx flipped (or at least new ruleset active); `systemctl stop xdpmacfilter@veth-test0`; assert XDP detached. Aggressive trap cleanup.
- **`T_SYSTEMD_RESTART_ON_FAILURE.sh`** (optional) — install malformed config; assert systemd attempts Restart and eventually hits StartLimit per RT2.
- **`T_ANSIBLE_PLAYBOOK_SYNTAX.sh`** — `ansible-playbook --syntax-check ansible/xdpmacfilter-deploy.yml`; SKIP-77 if `ansible-playbook` not in PATH.
- **`T_FLEET_DOCS_SUBSTRING.sh`** — `grep -qE 'trust_model=(strict|fleet)' docs/FLEET_DEPLOYMENT.md` — docs cite actual format. Additional substring checks per architect's decision.

## Out of scope (explicit)

- **Binary rename `xdpmacfilter` → `xdpfilter`** — still MVP-3.12. Unit file is `xdpmacfilter@.service` per HG-3.3-1; rename happens with transitional alias in MVP-3.12.
- **Per-rule counters / `xdpmf-exporter` binary / Prometheus exporter** — MVP-3.4 slice. Fleet docs reference Prometheus alert semantically but do NOT implement.
- **SIGHUP signal handler in loader** — explicitly fenced by Q2 (R1 chosen).
- **Full Ansible role/collection** — minimal example only per HG-3.3-2. Production-grade Ansible is operator's responsibility.
- **Multi-iface unit (single unit managing multiple ifaces)** — unit is template (one instance per iface); multi-iface = multiple instance names.
- **Service hardening beyond AmbientCapabilities** — no `User=`/`Group=` non-root (BPF needs CAP_BPF; running as non-root with capabilities is operator's call); no seccomp filter; no `ProtectSystem=`. Architect MAY add basic hardening directives if low-risk.
- **systemd `Type=notify`** — oneshot+RemainAfterExit per architecture-v2.md. Notify-style is daemon territory (MVP-3.6+ `xdpmfd` optional branch).
- **System install of binary in this slice's CMakeLists.txt** — unit file install is in scope (configurable prefix); binary install untouched (architect's call if it changes).
- **JSON structured logs** — MVP-3.5 slice.
- **sFlow** — MVP-3.6 (conditional).
- **Library extraction (libxdpmf.so.0)** — MVP-3.6+ optional.
- **Daemon (xdpmfd)** — MVP-3.6+ optional.
- **L4 ports / VLAN / IPv6 CIDR** — still fenced per MVP-3.2 §7 OOS.
- **MVP-3.1/3.2 OOT-deferred housekeeping items** — per Q6 default DEFER.

## Definition of done

- `§5.28 MVP-3.3: systemd + Ansible + fleet docs` amendment in `design.md` documenting Q1-Q6 decisions with rationale + HG-3.3-1/2/3 confirmation
- New `§6.x TestStrategy` entries for 3-5 new ctests
- `§6.5 Preserved invariants` extended: PI-1..PI-18 hold + new PI-19+ for systemd/Ansible/docs
- `§7 OOS`: MVP-3.3 components moved from deferred to shipped; MVP-3.4 (per-rule counters / exporter) surfaced as next slice
- `loader.hpp` PUBLIC-API UNCHANGED (PI-7-3.3 strengthening — ZERO diff continues across 3 cycles)
- `xdpmacfilter --version` reports `xdpmacfilter 0.5.0` (bump from 0.4.0)
- `CHANGELOG.md` entry `[0.5.0] - 2026-05-NN`
- 3-5 new ctests pass; 31 existing ctests still pass (PI-6-3.3 strict superset, only systemd lifecycle additions)
- `XDPMF_SANITIZERS=ON` build clean
- `systemd-analyze verify systemd/xdpmacfilter@.service` → exit 0
- `mint/review.md` round-1 verdict = `pass`
- One git commit per phase boundary per workflow B

## Dependencies

New system deps (test-time only, OPTIONAL with SKIP-77 paths):
- `systemd` (`systemctl`, `systemd-analyze`) — present on any modern Linux dev VM; ctests assume availability.
- `ansible-core` (`ansible-playbook`) — OPTIONAL; ctest SKIPs 77 if not in PATH.

No new build dependencies. No new C++ libraries. No new BPF features.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       [lang/cpp.md, lang/cmake.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []
```
