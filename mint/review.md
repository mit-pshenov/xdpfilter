# Review — MVP-3.4e KC-3 closure (mint triangulation, brownfield 5-point)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 (66/66 pass + 2 SKIP-77 baseline) | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |
| OOT (does not affect verdict) | 2 | inline-merge × 2 |

## Detailed triangulation

### 1. Spec ↔ Code

- `xdpmf::internal::ResetCountersRequest` struct (§5.36 EDIT-1) → `src/lib/apply_internal.hpp:75-78` ✓
- `[[nodiscard]] bool reset_counters_request(...)` (EDIT-1) → `src/lib/apply_internal.hpp:80` ✓ signature per EDIT-1
- Body flow per EDIT-1: validate_iface_name → BpffsRootFd → iface_entry_is_real_dir (false-branch emit no_pin + return false) → pin construction → bpf_obj_get → zero-write → `src/lib/loader.cpp:2147-2283` ✓. `resolve_ifindex` correctly DROPPED per D-3.4e-EDIT-1-DROP-RESOLVE.
- `validate_iface_name` Q2.A2 (non-empty, ≤15 chars, [A-Za-z0-9._-], reject `.`/`..`, throw PathRefused with `refusing to operate` token) → `src/lib/loader.cpp:456-485` ✓
- D-3.4e-PROBE-PLACEMENT FINAL A.2 (drop CLI-side probe; `reset_counters.refused.no_pin` from helper) → `src/lib/loader.cpp:2170-2185` ✓
- CLI shrinks to argv → audit → helper → return → `src/cli/reset_counters.cpp:75-153` ✓; `pin_path_for|bpf_obj_get` zero hits in CLI TU
- `SidecarRootFd` RAII (O_PATH|O_DIRECTORY|O_NOFOLLOW + state enum + idempotent mkdir-retry + non-throwing) → `src/lib/sidecar.cpp:189-256` ✓
- HG-3.4e-4 per-iface symlink detection: `fstatat(AT_SYMLINK_NOFOLLOW)` + S_ISLNK → emit `sidecar.warn.iface_dir_symlink` + return → `sidecar.cpp:420-461` ✓; fd-relative atomic write via `openat(O_NOFOLLOW)` + `renameat` → `sidecar.cpp:270-323` ✓
- D-3.4e-5 6 existing `sidecar.warn.*` event names PRESERVED → `logger.hpp:106-112` ✓
- Logger catalog 35→36 + fixture lockstep → `logger.hpp:109` + `:132`, `log_events_v1.txt:30` (alphabetical pre-`lstat_failed`) ✓

### 2. Spec ↔ Tests

- T-1 (a) path-traversal → exit 8 + `refusing to operate` + iface token → `T_RESET_COUNTERS_PATH_TRAVERSAL.sh:83-120` ✓
- T-1 (b) whitespace-shape → exit 8 + same → `:126-160` ✓
- T-1 (c) NEGATION real iface → exit 0 + audit-log ERE → `:168-204` ✓
- T-2 (a) per EDIT-2: exit 0 + prose `symlink` + iface + attacker-target absent + attacker-tmp absent → `T_SIDECAR_IFACE_SYMLINK_REFUSAL.sh:192-242` ✓; event-name-token assertion correctly DROPPED per EDIT-2 (cited at test lines 37-44, 198-203).
- T-2 (b) NEGATION clean dir → exit 0 + rule_index.json present + no `symlink` prose → `:248-303` ✓

### 3. Code ↔ Tests

Reviewer's `ctest -j4` → **100% (66/66 pass + 2 legitimate SKIP)**, 529.78 sec. Matches tester's run. No UNEXERCISED-EXPORT.

### 4. Out-of-Scope Drift

All §7 OOS items NOT touched: escape_util not extracted; BpffsDir/XdpAttachment not deleted; exporter --bind WARN absent; apply_internal.hpp not renamed; validate_iface_name not retrofit to apply/detach; sidecar_root lock domain not added; §5.22 Maximum not done; CIS-style sweep not done. ✓

### 5. Behaviour preserved (brownfield §6.5)

| PI | Result |
|---|---|
| PI-7-3.4e-hpp (11th ZERO-diff) | `git diff f2122c7 HEAD -- src/lib/loader.hpp` empty ✓ |
| PI-7-3.4e-cpp (6th ZERO-diff) | empty ✓ |
| PI-32-3.4b PRESERVED | T-2 (a) apply exit 0 + sidecar never throws ✓ |
| §5.22 bilateral restoration | T-1 (a/b) exit 8; T_BPFFS_ROOT_SYMLINK still green ✓ |
| §5.31 EDIT-1 event names preserved | 6 sidecar.warn.* + 1 new = 7 at logger.hpp:106-112 ✓ |
| PI-3.4d-* counter-mgmt + atomic-swap | T_CLI_RESET_COUNTERS{,_RULE_ID,_NO_IFACE} + T_RULE_COUNTER_* all PASS ✓ |
| PI-3.4e-1 NEW | T-1 a/b exit 8 + sibling pins untouched ✓ |
| PI-3.4e-2 NEW | T-2 (a) event emitted + apply exit 0 + attacker absent ✓ |
| PI-6 ctest count regression | 64→66; zero existing-body EDITs; 1 fixture EDIT ✓ |
| PI-10 additive mac_filter.h | zero diff ✓ |

All UNCHANGED-BUT-AFFECTED zero-diff fences confirmed.

Anti-misdiagnosis guards #17 (bilateral invariant restoration) + #18 (host-vs-netns audit) + #19 (logger text-mode convention) all present in §5.36 + EDIT-1/2.

## Test execution

```
100% tests passed, 0 tests failed out of 66
Total Test time (real) = 529.78 sec

Skipped:  5 - T_DROP_MALFORMED, 35 - T_ANSIBLE_PLAYBOOK_SYNTAX
```

Reviewer log: `/tmp/mint-review-tests-1748357XXX.log`.

## Findings

NONE.

## Rework assignments

N/A (verdict = pass).

## Out-of-triangulation findings

### OOT-1: `docs/BACKLOG.md` NEW file committed in impl/test commit
**Location**: `docs/BACKLOG.md:1-109` (commit ccfd8d9)
**Disposition**: `inline-merge`
**Rationale**: Doc-only file (109 LOC); resolution of mint-review doc L4 "no tracking issue exists". No code/test/spec surface; no PI violation. Pre-flagged by team-lead. Architect MAY retroactively register in §5.36 for audit-trail completeness.

### OOT-2: T-1 sub-case (c) runs `reset-counters` via `${NSEXEC}` vs EDIT-1 HOST-context clarification
**Location**: `tests/T_RESET_COUNTERS_PATH_TRAVERSAL.sh:182` vs design.md EDIT-1 clarification
**Disposition**: `inline-merge`
**Rationale**: Behavior contract intact (3/3 sub-cases pass). resolve_ifindex was DROPPED per EDIT-1, so NSEXEC-vs-HOST is now behaviorally moot. Tester's NSEXEC choice internally consistent with setup_veth+attach being NSEXEC. Cosmetic only.

---

**Triangulation summary**: bilateral §5.22 BpffsRootFd invariant restoration successful across reset-counters + sidecar. PI-32-3.4b preserved (sidecar never throws). PI-7-3.4e-hpp 11th + cpp 6th consecutive ZERO-diff (strongest streaks in project history). KC-3 kill-chain fully closed. ZERO test failures across 66/66 in 2 independent runs. 2 OOT both inline-merge.

### Post-review sweep — round 1

Both OOTs disposed as `inline-merge`. Edits ride in Phase 6 final commit.

- **OOT-1** → `design.md` §5.36 EDIT-3: retroactively register `docs/BACKLOG.md` as NEW out-of-cycle file (doc-backlog tracking surface resolution of mint-review doc L4).
- **OOT-2** → `design.md` §5.36 EDIT-1 clarification text amended to acknowledge NSEXEC and HOST contexts as functionally equivalent post-resolve_ifindex-drop (no operator-observable difference once helper drops netns-aware ifindex resolution).

No `defer` or `promote-to-rework`. Verdict stays `pass` round-1.
