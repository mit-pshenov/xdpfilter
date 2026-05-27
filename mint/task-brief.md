# Task brief — MVP-3.4e: reset-counters path-hardening + sidecar iface-subdir symlink defense (brownfield, security-hardening)

## Goal

Closure of KC-3 kill-chain surfaced by 2026-05-27 `/mint-review` (report at `agent-teams-review/runs/mint-review-mint-l2-mac-filter-202605271147/report.md`). Two coupled architectural regressions of the §5.22 BpffsRootFd invariant:

1. **`reset-counters` path-hardening** — `src/cli/reset_counters.cpp` builds raw absolute paths via `pin_path_for(iface, basename) = XDPMF_BPFFS_ROOT + "/" + iface + "/" + basename` (no validation, no symlink defense, no `O_NOFOLLOW`) and passes them to `bpf_obj_get(path.c_str())`. Operator with CAP_BPF + sudoers can `reset-counters --iface ../../tmp/x` → zero-write any PERCPU pin under `/sys/fs/bpf/`. Unlike `apply_request` + `detach()` paths which call `resolve_ifindex(iface, ...)` + use `BpffsRootFd` + fd-relative `openat`/`mkdirat`/`unlinkat`.

2. **Sidecar iface-subdir symlink defense gap** — `src/lib/sidecar.cpp` `mkdir_p(dir)` + `atomic_write_file` (`::open(O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC)` — no `O_NOFOLLOW`) on `/run/xdpmacfilter/<iface>/rule_index.json`. §5.31 EDIT-1 hardened the SIDECAR_ROOT-level lstat but per-iface subdir creation follows symlinks. Attacker with root + write to `/run/xdpmacfilter/` can pre-create iface as symlink → loader writes attacker-controlled JSON to chosen target.

KC-3 chains the two: clobber sibling BPF subsystem (reset-counters) + write to executable-on-cron-tick location (sidecar). Both individually need root; together = CIS-style hardening regression vs §5.22 invariant. **Single architectural fix**: extend `BpffsRootFd` + `IfaceDirGuard` discipline to BOTH paths.

Narrow scope per user direction 2026-05-27 (bonus items from mint-review — escape_util extraction, BpffsDir delete, exporter bind WARN — deferred to separate slices).

## Context: prior work

- All prior briefs archived in `mint/task-brief-*.md`. Most recent: `task-brief-mvp-3.4d.md` (reset-counters CLI + rule_counters atomic-swap).
- Existing design: `mint/design.md` §5.35 (MVP-3.4d amendment) — D-3.4d-3 copy_rule_counters_forward, D-3.4d-FEAS/FALLBACK pattern, 2 new anti-misdiagnosis guards (#14 + #15).
- §5.22 + §5.31 EDIT-1 are the load-bearing precedents for this slice's hardening pattern.
- /mint-review report KC-3 evidence:
  - security-reviewer H1 + M3 (anchors)
  - Validated by synthesizer with `±5-line` Read at each citation
- Phase A code-grep verification: brief author ran `grep -nE "bpf_obj_get|resolve_ifindex|pin_path_for|BpffsRootFd|O_NOFOLLOW" src/cli/reset_counters.cpp`; `grep -nE "mkdir_p|atomic_write|::open|::lstat|S_ISLNK|O_NOFOLLOW|openat|mkdirat" src/lib/sidecar.cpp`; `grep -nE "BpffsRootFd|IfaceDirGuard|resolve_ifindex" src/lib/loader.cpp`. Confirmed: `BpffsRootFd` is anon-namespace in `loader.cpp` (not exposed via `raii.hpp` — there's a separate dead `BpffsDir` per code-quality H1 which is OOS for this slice).
- PI continuity: PI-7-3.4e-hpp = **11th consecutive ZERO-diff cycle target** on `loader.hpp`; PI-7-3.4e-cpp = **6th consecutive** on `config.hpp`. PI-32-3.4b (sidecar never throws; exporter degrades to `action="unknown"`) PRESERVED — sidecar symlink response is WARN + skip per HG-3.4e-4. New PIs needed: PI-3.4e-1 (reset-counters path-refused via §5.22 invariant), PI-3.4e-2 (sidecar iface-subdir symlink refusal).

## Workflow rules (brownfield)

- **Architect**: read §5.22 (BpffsRootFd hardening invariant — load-bearing precedent), §5.31 EDIT-1 (sidecar SIDECAR_ROOT lstat — symmetric to this slice's per-iface subdir gap), §5.34 + §5.35 (recent context); EDIT `design.md` in place; append §5.36 (architect picks §-number). Apply anti-misdiagnosis guards #5 + #9 + #12 (see footer). HG-3.4e-1 architectural choice (extract vs route-through-internal-helper vs duplicate) is the load-bearing Phase A decision.
- **Impl**: FileList = DIFF. Brownfield discipline. PI-7-3.4e-hpp/cpp ZERO-diff target. [[impl-role-discipline]] holds.
- **Tester**: 2 NEW ctests (T_RESET_COUNTERS_PATH_TRAVERSAL + T_SIDECAR_IFACE_SYMLINK_REFUSAL). Template = T_BPFFS_ROOT_SYMLINK.sh. Brief estimate is upper bound.
- **Reviewer**: 5-point brownfield. Special attention: (a) PI-3.4e-1 + PI-3.4e-2 new contracts cleanly written; (b) PI-32-3.4b sidecar-never-throws PRESERVED (no escalation to fatal); (c) §5.22 invariant restored bilaterally (reset-counters + sidecar).

## Human-gate decisions (defaults applied — architect overrides at Phase A)

### HG-3.4e-1: BpffsRootFd reachability for reset_counters → **route through new `internal::reset_counters_request()` (mirror `internal::apply_request` pattern)**

Preserves §5.22 anon-namespace fence on `BpffsRootFd`/`IfaceDirGuard`/`resolve_ifindex`. Reuses existing infrastructure (no duplication, no new shared-header surface). reset_counters.cpp's CLI-side responsibility shrinks to: parse argv → call `internal::reset_counters_request(iface, optional<rule_id>)` → emit audit-log → return exit code. The hardening lives entirely in loader.cpp where the precedent infrastructure is. Alternatives: extract to shared header (broadens API surface vs §5.22 fence); duplicate minimal version (guard #9 violation at function level — distinct from helper-duplication which is acceptable).

### HG-3.4e-2: sidecar iface subdir symlink defense → **mirror BpffsRootFd pattern**

Open SIDECAR_ROOT with `O_PATH | O_DIRECTORY | O_NOFOLLOW`; use `mkdirat(root_fd, "<iface>", 0755)` + `openat(root_fd, "<iface>/rule_index.json.tmp", O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, 0644)`. Reject `S_ISLNK` on `fstatat(root_fd, "<iface>", AT_SYMLINK_NOFOLLOW)` lstat-equivalent BEFORE write. Mechanical mirror of §5.22's bpffs hardening + §5.31 EDIT-1's existing SIDECAR_ROOT pattern. Architect picks exact shape per existing precedent.

### HG-3.4e-3: exit code for reset-counters path-refused → **exit 8 (PathRefused)**

Mirrors §5.22 — operator gets semantic-meaningful code consistent with loader's `--iface ../` rejection. Alternative exit 1 (generic CliError) is less informative + breaks the precedent that PathRefused = "the input was a symlink/bad-path; refused to operate". `LoaderError::PathRefused` enum value already exists; no new exit code introduced.

### HG-3.4e-4: sidecar iface-subdir symlink response → **WARN + skip (PI-32-3.4b PRESERVED)**

Sidecar-never-throws contract from §5.31 EDIT-1: log a NEW `sidecar.warn.iface_dir_symlink` event via `logger.emit` and skip the write (rule_index.json not refreshed → exporter degrades to `action="unknown"` per existing PI-32-3.4b). Do NOT escalate to fatal apply error. Apply continues + exits 0. Operator alerts go through logger.warn.sidecar.* event series (mirrors §5.31 EDIT-1 event class).

## Open mechanism questions (architect decides; document in §<new>)

### Q1: `dev_valid_name` validation timing in reset-counters
- **A1**: CLI-parse-time (in `parse_reset_counters` in cli.cpp)
- **A2**: `reset_counters_main` entry
- **A3**: `internal::reset_counters_request()` entry (mirrors apply_request)
- **Recommendation: A3** — fail-closed AT the internal-helper entry consistent with apply_request's iface validation. CLI-side argv-parse stays minimal (already does basic non-empty check).

### Q2: re-use `resolve_ifindex` directly vs new `validate_iface_name` helper
- **A1**: call `resolve_ifindex(iface, LoaderError::LoadFailed)` — does ifindex lookup + dev_valid_name in one
- **A2**: split into `validate_iface_name(iface)` + `resolve_ifindex(iface)` for callers that don't need ifindex
- **Recommendation: A1** — minimize new surface; reset_counters doesn't need ifindex separately; the wasted ifindex lookup is microseconds.

### Q3: separate test for sidecar iface-subdir symlink vs fold into existing
- **A1**: NEW T_SIDECAR_IFACE_SYMLINK_REFUSAL.sh standalone (mirrors T_BPFFS_ROOT_SYMLINK precedent)
- **A2**: fold into existing T_BPFFS_ROOT_SYMLINK with new sub-case
- **A3**: fold into T_SIDECAR_JSON_SHAPE
- **Recommendation: A1** — clean separation, mirrors §5.22 precedent's standalone test, RESOURCE_LOCK isolation cleaner.

### Q4: sidecar SIDECAR_ROOT lstat (existing §5.31 EDIT-1) vs new iface-subdir lstat — single helper or two
- **A1**: two helpers (`lstat_sidecar_root` existing + new `lstat_iface_subdir`)
- **A2**: one parameterized helper `lstat_path_safe(path)` covering both
- **Recommendation: A2** — DRY; matches §5.31 EDIT-1 hardening pattern; smaller diff.

## Scope (MVP-3.4e — concrete items)

### Item S-1 — Loader: NEW `internal::reset_counters_request()` helper
**Where**: `src/lib/loader.cpp` (anon-namespace + `xdpmf::internal::` adjacent to `apply_request`) + `src/lib/apply_internal.hpp` (or NEW `src/lib/reset_counters_internal.hpp` — architect picks)

- Signature: `void reset_counters_request(const ResetCountersRequest&)` taking iface + `std::optional<std::uint32_t> rule_id`.
- Body: `resolve_ifindex(req.iface, LoaderError::LoadFailed)` (Q1.A3 + Q2.A1) → `BpffsRootFd root{}` → assert per-iface dir exists + is real dir (reuse `iface_entry_is_real_dir(root, req.iface)`) → `openat(root_fd, "<iface>/rule_counters_a", O_RDWR|O_NOFOLLOW)` → `openat(root_fd, "<iface>/rule_counters_b", O_RDWR|O_NOFOLLOW)` → zero-write per HG-3.4d-1 + D-3.4d-RESET-BOTH semantics.
- Throws `std::system_error{LoaderError::PathRefused}` (HG-3.4e-3) on any O_NOFOLLOW + ELOOP / S_ISLNK path; propagates ENOENT-tolerant ifindex-not-found as `LoaderError::LoadFailed`.

### Item S-2 — Reset_counters CLI: route through new internal helper
**Where**: `src/cli/reset_counters.cpp` (significant rewrite)

- Strip `pin_path_for(iface, basename)` + the direct `bpf_obj_get` calls. CLI-side keeps: argv-parse → audit-log emit BEFORE writes → `internal::reset_counters_request(req)` → exit-code mapping from `std::system_error` catch arm (existing main.cpp pattern).
- `escape_audit_value` stays (guard #9 — function-level duplication intentional per D-3.4d-6; NOT in this slice's scope per Narrow decision).
- The `precondition probe` semantics shift: instead of `bpf_obj_get(rule_counters_a_path)` → `LoaderError::PathRefused (8)` if O_NOFOLLOW fires OR `LoaderError::LoadFailed (2)` on ENOENT (= "iface not attached"). Audit-log refused event extends to cover the new exit-8 case.

### Item S-3 — Sidecar: iface-subdir symlink defense
**Where**: `src/lib/sidecar.cpp` (`mkdir_p` + `atomic_write_file` callers around `write_rule_index`)

- Open SIDECAR_ROOT (`/run/xdpmacfilter`) with `O_PATH | O_DIRECTORY | O_NOFOLLOW` once at the top of `write_rule_index` (RAII via new local class OR scope guard).
- Replace `mkdir_p(dir)` with `mkdirat(root_fd, "<iface>", 0755)` (ENOENT-tolerant — create if missing); on ENOTDIR / EEXIST + `fstatat(root_fd, "<iface>", AT_SYMLINK_NOFOLLOW)` returning S_ISLNK → emit NEW `sidecar.warn.iface_dir_symlink` event (HG-3.4e-4) + return non-fatal.
- Replace `::open(tmp_path.c_str(), O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0644)` with `openat(root_fd, "<iface>/rule_index.json.tmp", O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW|O_CLOEXEC, 0644)`.
- Replace `::rename(tmp_path.c_str(), final_path.c_str())` with `renameat(root_fd, "<iface>/rule_index.json.tmp", root_fd, "<iface>/rule_index.json")`.
- New helper per Q4.A2: `lstat_path_safe(...)` covering both SIDECAR_ROOT (existing) + new iface-subdir check (refactor existing §5.31 EDIT-1 lstat block to call it).

### Item S-4 — Logger: NEW event `sidecar.warn.iface_dir_symlink`
**Where**: `src/common/logger.hpp` (kEventNames extension)

- Add 1 entry → kEventNames 35 → 36.
- Emit-site: `src/lib/sidecar.cpp` per HG-3.4e-4 + Item S-3.
- Fixture lockstep (Phase 2.7a): `tests/fixtures/log_events_v1.txt` 35 → 36 lines.

### Item T-1 — NEW ctest: `T_RESET_COUNTERS_PATH_TRAVERSAL.sh`
**Where**: NEW; entry in `tests/CMakeLists.txt`
**Template**: `tests/T_BPFFS_ROOT_SYMLINK.sh` (verified existing).

- Setup: attach iface normally.
- Sub-case (a): `reset-counters --iface ../foo` → exit 8 (PathRefused) + stderr matches `"path-refused"` or `"refusing to operate"` substring per §5.22 phrasing.
- Sub-case (b): `reset-counters --iface invalid name with spaces` → exit 8 (dev_valid_name reject).
- Negation: `reset-counters --iface <real-iface>` → exit 0 + audit-log emitted (regression-baseline).
- RESOURCE_LOCK: `xdp_fixture` (per guard #12).

### Item T-2 — NEW ctest: `T_SIDECAR_IFACE_SYMLINK_REFUSAL.sh`
**Where**: NEW; entry in `tests/CMakeLists.txt`
**Template**: `T_BPFFS_ROOT_SYMLINK.sh` + adapt for `/run/xdpmacfilter` path.

- Setup: pre-create `/run/xdpmacfilter/<iface>` as symlink to `/tmp/attacker_target`.
- Sub-case (a): `attach --iface <iface>` followed by `apply -f <config>` → apply rc=0 (sidecar warn + skip per PI-32-3.4b); stderr contains `sidecar.warn.iface_dir_symlink` event; `/tmp/attacker_target/rule_index.json` NOT created.
- Sub-case (b) negation: clean `/run/xdpmacfilter/<iface>/` (no symlink) → apply rc=0 + sidecar writes successfully (rule_index.json present).
- RESOURCE_LOCK: `xdp_fixture;sidecar_root` (NEW lock domain since iface subdir is host-global state under `/run`).

### Item E-1 — EDITED fixture: `tests/fixtures/log_events_v1.txt`
**Where**: existing fixture
- Add `sidecar.warn.iface_dir_symlink` entry per S-4. Lockstep with kEventNames 35→36.

## Out of scope (explicit)

Per Narrow scope decision (2026-05-27 inline). Bonus items from mint-review deferred to separate slices:

- **escape_util.{hpp,cpp} extraction** (sec M1 + arch M2 + CQ M2 cross-validated theme B) — defer to MVP-3.4f.
- **Dead BpffsDir + XdpAttachment delete from raii.hpp** (CQ H1, ~75 LOC) — defer to MVP-3.4f or housekeeping mini.
- **Exporter --bind non-loopback WARN** (sec M2) — defer to MVP-3.5b (exporter-adjacent).
- **`.github/workflows/ci.yml` matrix** (testing H1 cascades) — separate infra cycle, not /mint-dev.
- **T_SANITIZER_BUILD ctest-recurse refactor** (testing H2) — depends on CI cycle.
- **TUN/TAP injector for T_DROP_MALFORMED** (testing H3) — depends on CI cycle OR independent test-infra cycle.
- **Compound exporter scrape-path perf** (perf compound, ~88% reduction max-fleet) — separate perf cycle.
- **datapath dispatch helper consolidation** (CQ M1, mac_filter.bpf.c MAC vs CIDR branch) — defer.
- **logger.cpp dup-TU promotion to OBJECT lib** (arch M1) — defer.
- **README rewrite + HANDOFF.md + Ansible Jinja** — doc backlog (docs/BACKLOG.md, manual prose).
- **CO-RE field probes + T_CORE_FIELD_PROBE** (testing M1) — defer.
- **Exit-code 8 vs 1 generalization** — Q3 picked 8; future cycles MAY revisit if new path-class additions surface.

Carry-forward from §5.35 §7 OOS unless noted — unchanged.

## Definition of done

- §5.36 amendment (or architect-named §) in design.md covering: HG-3.4e-1..4 + Q1-Q4 + 2 new PIs.
- PI-1..PI-34 + PI-3.4b-* + PI-3.4d-* preserved; PI-32-3.4b explicitly upheld (sidecar never throws).
- PI-7-3.4e-hpp/cpp: 11th/6th consecutive ZERO-diff.
- ctest baseline 64 → 66 (+2 NEW T-1 + T-2). No EDITED ctests beyond fixture-lockstep (E-1).
- `mint/review.md` round-1 verdict = pass (5-point brownfield).
- One git commit per phase boundary.

## Dependencies

- Build: libbpf 1.x (no new deps).
- Runtime: kernel BPF support (existing).
- Platform: `/run/xdpmacfilter/` tmpfs path (existing); `/sys/fs/bpf/xdpmacfilter/` bpffs (existing).
- No new caps required (sidecar already uses CAP_BPF + write perms; reset-counters re-uses).

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
mode: brownfield
packs:
  architect:  []
  impl:       []
  tester:     []
  reviewer:   []
```

(No packs — established 18-cycle precedent sufficient.)

---

## Pre-brief sanity check (per [[mint-hld-scope-discipline]])

- Slice goal stated in one sentence: ✓ (KC-3 closure via §5.22 hardening pattern bilateral extension).
- Multi-axis check: slight — resolved inline 2026-05-27 to Narrow scope (only KC-3; bonus items deferred). NOT multi-axis enough for /mint-hld.
- Mechanical-answer check: ✓ — §5.22 + §5.31 EDIT-1 precedents are direct templates.
- Brief author overconfidence check: ⚠ — third dogfood of `/mint-briefer`; Phase 2.7b + Phase 1.5 PRESERVE-vs-RESET both N/A this slice; Phase 4.4 operative-semantic discipline applied.
- Phase 1.5 PRESERVE-vs-RESET check: N/A — no stateful-map atomic-swap promotion.

## Notes for architect Phase A code-grep discipline (per architect spec rules)

Brief author already ran Phase 2 greps. Architect re-verifies INDEPENDENTLY + extends:

```bash
# Confirm BpffsRootFd + resolve_ifindex location (anon-namespace in loader.cpp)
grep -nE "class BpffsRootFd|IfaceDirGuard|^.*resolve_ifindex" src/lib/loader.cpp | head -15

# Confirm reset_counters.cpp's current unsafe-path-construction sites
grep -nE "pin_path_for|bpf_obj_get|XDPMF_BPFFS_ROOT" src/cli/reset_counters.cpp | head

# Confirm sidecar.cpp's current per-iface-subdir handling
grep -nE "mkdir_p|atomic_write_file|::open|::rename|::lstat|S_ISLNK" src/lib/sidecar.cpp | head -15

# Confirm T_BPFFS_ROOT_SYMLINK precedent (template for both NEW ctests)
sed -n '1,40p' tests/T_BPFFS_ROOT_SYMLINK.sh

# Verify §5.22 BpffsRootFd hardening invariant — read the design section for the load-bearing precedent
grep -nE "§5.22|BpffsRootFd|O_PATH.*O_DIRECTORY.*O_NOFOLLOW" mint/design.md | head -15

# Verify §5.31 EDIT-1 sidecar SIDECAR_ROOT lstat — symmetric to this slice's per-iface gap
grep -nE "§5\.31 EDIT-1|sidecar.*symlink|SIDECAR_ROOT" mint/design.md | head -15

# kEventNames count consistency
grep -nE "kEventNames|kEventCount|fixtures/log_events_v1.txt" src/common/logger.hpp tests/

# Confirm PI-32-3.4b preserved-contract (sidecar never throws)
grep -nE "PI-32-3.4b|sidecar.*never.*throws|action=.unknown." mint/design.md | head -10
```

### Anti-misdiagnosis guards applicable to this slice (per Phase 3)

- **Guard #5 (Phase A code-grep discipline)** — always applies; architect re-runs above.
- **Guard #9 (helper-location duplication-over-extraction)** — HG-3.4e-1 architectural choice (extract `BpffsRootFd` vs route-through-internal-helper vs duplicate). Default = route-through-internal — preserves §5.22 anon-namespace fence + DRY. Architect picks with evidence.
- **Guard #12 (RESOURCE_LOCK for shared host state)** — T-1 needs `xdp_fixture`; T-2 needs `xdp_fixture;sidecar_root` (NEW lock domain because /run/xdpmacfilter is host-global writable state).
- **Guard #13 (fixture cross-reference)** — Item S-4 NEW logger event → fixture E-1 lockstep update (kEventNames 35→36 + tests/fixtures/log_events_v1.txt +1 line). Pre-listed in scope.

### Cycle-specific anti-misdiagnosis (potentially new guards)

- **Symmetric §5.22 invariant restoration discipline (NEW candidate guard #17)**: when mint-review surfaces a security hardening regression vs an existing invariant (§5.22 here), the brief MUST locate ALL call-sites that opted out of the invariant + close them in one slice (bilateral). One-sided fix is half-measure. Validated this cycle: reset-counters + sidecar both deviate from §5.22; both fixed in same amendment. Future-cycle guard for architect: when applying invariant-restoration, `grep` for the ANTI-PATTERN (e.g., raw `::open` without O_NOFOLLOW, raw `bpf_obj_get(abspath)` without root-fd) ACROSS THE WHOLE src/ tree to confirm bilateral coverage.

### Operative-semantic SHOULD-hint discipline (per /mint-briefer Phase 4.4)

Counts/sizes in verifiable-invariants block are **operative-semantic, not literal-precise**. Impl deviations on small details (exact O_NOFOLLOW placement order, helper file naming `lstat_path_safe` vs `lstat_safe_path`, audit-log refused-event wording tweaks, ctest sub-case ordering) are `inline-merge` per design's resolution rule — NOT `[CONTRACT-DRIFT]` per reviewer.
