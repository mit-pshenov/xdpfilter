# Task brief — MVP-1.1B: §5.4 trust-boundary hardening (refactor mode)

## Goal

Harden the §5.4 idempotent-reload ownership-marker mechanism (the load-bearing trust boundary the hybrid review flagged from 3 dimensions). Three concrete impl changes + one new test, all touching the same ~20-line `loader.cpp:149-169` region plus the `query_attached_prog_id` helper at `loader.cpp:97-107`.

This is the **second refactor pass** on the MVP-1 codebase, following MVP-1.1A. MVP-1.1A validated the workflow for cheap doc/build/test additions; MVP-1.1B validates it for a real architectural change with cross-section ripples in design.md §5.4.

## Context: prior work

- **MVP-1 brief**: `mint/task-brief-mvp1.md` (canonical 0.1.0 brief)
- **MVP-1.1A brief**: `mint/task-brief-mvp1.1a.md` (just-completed quick-wins refactor)
- **Existing design**: `mint/design.md` — already amended with §5.15 + §5.16 (MVP-1 closeout) + §5.17 + §5.18 + §6.8 (MVP-1.1A)
- **MVP-1.1A review**: `mint/review.md` (latest round-1 pass)
- **Hybrid review** (the source of these findings): `mint/hybrid-review.md`

## Workflow rules (refactor mode — same as MVP-1.1A)

- **Architect**: read existing `design.md` + `hybrid-review.md` + this brief. EDIT design.md in place. For §5.4 itself: architect chooses between (a) editing §5.4 in place AND recording the amendment in §5.19, OR (b) writing §5.19 as the new 4-state authoritative version and adding a "superseded by §5.19" line to §5.4. Either is fine — pick what reads cleanest. Append §5.20 if needed for the all-modes query decision. Append new `§6.x` TestStrategy item for the alien-refusal test. NO rewrite from scratch.
- **Impl**: edit existing `src/loader/loader.cpp` (the `query_attached_prog_id` helper + the §5.4 probe + branch logic in `attach()`). If a new helper is needed (e.g. identity verification), add it inside `loader.cpp` — do NOT introduce new source files. The other src/** files stay untouched.
- **Tester**: ADD one new test (`tests/T_ATTACH_ALIEN_REFUSAL.sh`) + register in `tests/CMakeLists.txt`. The 8 existing tests stay untouched.
- **Reviewer**: 4-point triangulation focused on the amendments + new test. Existing-and-unchanged code is out of scope.

## Scope (exactly 4 items — anything else is OOS)

### Item 1 — KC-B fix: query XDP in ALL modes, not SKB-only (HIGH KC-B in hybrid-review.md)

`loader.cpp:97-107` (`query_attached_prog_id`) calls `bpf_xdp_query_id(ifindex, static_cast<int>(kXdpFlags), &prog_id)` where `kXdpFlags == XDP_FLAGS_SKB_MODE`. Native-mode and offload-mode alien XDP programs return `prog_id = 0` → §5.4 logic treats them as "no program" → exit 3 (AttachFailed) instead of exit 4 (AttachRefusedAlien), blinding any audit that greps for exit 4 to detect attempted clobbers.

**Action**: change the query flag argument to `0` (libbpf docs: flags=0 means "any mode"). When `prog_id != 0`, separately determine via `bpf_prog_info` (or via the mode-specific re-query) whether the attached program is in our mode (SKB) or a different mode. Architect specifies HOW; impl follows.

### Item 2 — KC-A fix: identity-verify the pinned object, not directory presence (HIGH KC-A in hybrid-review.md)

`loader.cpp:149-169` decides "ours vs alien" purely by `std::filesystem::exists(pin_dir)`. An attacker with CAP_SYS_ADMIN-on-bpffs can plant the directory and fool the loader into detaching legitimate alien XDP. The mitigation per hybrid-review report H-KC-A: verify pinned object identity.

**Action** (architect chooses the verification mechanism — multiple options listed in hybrid-review.md report HIGH KC-A "Recommended fix"):
- Preferred: fetch `bpf_prog_info` via `bpf_prog_get_info_by_fd` on the attached program, check `info.name` matches a known marker (e.g. `"mac_filter_prog"` from the SEC name) AND/OR the program tag matches the freshly-compiled skeleton's tag.
- Alternative: open the pinned maps and verify their names/types/sizes match the skeleton's expected layout before deciding "ours".
- Minimum (closes most attacks): O_PATH/O_DIRECTORY fd on `pin_dir` before the query, use fd for subsequent ops.

Architect documents the choice in §5.19 (or wherever fits). The directory existence remains a precondition (no pin_dir → can't be ours), but it ceases to be sufficient.

### Item 3 — §5.4 4-state stale-pin recovery (HIGH H1 in hybrid-review.md)

Current §5.4 enumerates 3 states: (a) no-existing-prog/no-pin-dir → fresh attach; (b) ours-prog/pin-dir-present → detach+re-attach; (c) alien-prog/no-pin-dir → refuse exit 4. The 4th state — **no-existing-prog AND pin-dir-PRESENT** (post-SIGKILL between dir-create and xdp-attach, or post-OOM) — falls through to fresh attach, then libbpf `-EEXIST` on the pre-pinned maps → cryptic `LoadFailed` "File exists".

**Action**: in `attach()`, treat `existing_prog_id == 0 && pin_dir_exists` as "stale ours" → run `bpffs_remove_iface()` to clean the orphan dir → continue with fresh attach. Symmetrically, `detach()` should treat `existing_prog_id == 0 && pin_dir_exists` as a no-op recoverable cleanup (remove dir, exit 0) instead of throwing DetachFailed.

Update §5.4 to a 4-state machine. Document the new state's recovery path.

### Item 4 — T_ATTACH_ALIEN_REFUSAL test (MEDIUM in testing dim of hybrid-review.md; design §6.6 OPTIONAL sub-variant)

The alien-refusal exit-code-4 path is currently untested (only logic-tested in MVP-1.1A reviewer's spot check). Add an end-to-end test:

**Setup**: build a tiny xdp-pass.o (or similar minimal foreign XDP program) — architect specifies whether to: (a) include a `tests/fixtures/xdp_pass.bpf.c` in-tree and build it as a CMake test artifact, or (b) use an existing system path if one exists. Option (a) is more portable.

**Trigger**: attach the foreign program to `veth_a` directly via `bpftool net attach xdpgeneric pinned …` or `bpf_xdp_attach()`, then run `xdpmacfilter attach --iface veth_a --allow MAC_GOOD`, capture exit code.

**Assert**: exit 4 (`LoaderError::AttachRefusedAlien`); stderr message contains the foreign prog id from `loader.cpp:157-159`'s exception text; foreign program still attached after our attempt (we didn't clobber).

**Cleanup**: detach the foreign program manually in cleanup.

Add as `§6.9 T_ATTACH_ALIEN_REFUSAL`.

## Out of scope (explicit anti-drift fence)

The following hybrid-review.md findings are explicitly DEFERRED to a later pass (C / MVP-2):

- **PERCPU stats migration** — MVP-2 (explicit per design §5.3)
- **`--mode {generic,native,offload}` CLI flag** — MVP-2 (explicit per design §5.6 + part of KC-B fix's *workaround* alternative, but the CLI flag itself stays out)
- **All MEDIUM / LOW findings** from hybrid-review.md not in the 4 scope items above (string churn, sleep-based sync, host-scope veth, `prog_count` race, `--help`/`--version` test, MAC parser tests, detach failure tests, kernel-version probe, sudo -n, etc.)
- **Architecture M1** (backwards layering `loader.hpp → cli.hpp`) — MVP-2
- **Architecture M2** (raii.hpp `BpffsDir::create()` ghost comment) — could be C-pass with other doc cleanup, NOT this pass
- **Performance MEDIUMs** (string churn, `bpffs_dir_for` reallocs, O(n²) dedup) — MVP-2 polish
- **Documentation MEDIUM** (inject_runt.py docstring drift) — could be C-pass, NOT this pass
- **`pkg_check_modules(libbpf>=1.1)` version qualifier** — could be C-pass, NOT this pass

Do NOT "while you're at it" fix any of these. Tight scope = clean stress test of refactor-mode workflow on a real architectural change.

## Acceptance criteria

1. `mint/design.md` has §5.4 amended either in-place (with the amendment recorded in §5.19) OR §5.19 contains the new 4-state authoritative version with §5.4 marked as superseded. Either is acceptable; the design must clearly enumerate 4 states.
2. `mint/design.md` §5.19 (or §5.20) documents the chosen identity-verification mechanism for KC-A.
3. `mint/design.md` §5.20 (or §5.21) documents the all-modes query decision for KC-B.
4. `mint/design.md` §6.9 T_ATTACH_ALIEN_REFUSAL TestStrategy entry exists.
5. `src/loader/loader.cpp` query_attached_prog_id (or its successor) queries XDP in all modes; the §5.4 probe + branch logic implements the 4-state machine + identity verification.
6. `tests/T_ATTACH_ALIEN_REFUSAL.sh` exists and passes; the foreign-XDP fixture is provided in-tree (architect decides exact form).
7. All 8 pre-existing tests still pass (T_BUILD, T_LOAD_ATTACH, T_PASS_ALLOWED, T_DROP_DENY, T_DROP_MALFORMED [may SKIP], T_IDEMPOTENT_RELOAD, T_NEGATION_CONTROL, T_SANITIZER_BUILD). No regression — proves refactor mode handles real source changes without breaking what worked.
8. Build is clean (zero warnings under `-Werror`) for both default and `-DXDPMF_SANITIZERS=ON` configurations. **Sanitizer build is now particularly meaningful** — the §5.4 logic touches RAII rollback paths, exception throwing, std::format formatting, file I/O — ASAN/UBSAN would catch many classes of memory bugs introduced by these changes.
9. Exit code 4 (`LoaderError::AttachRefusedAlien`) is observed in T_ATTACH_ALIEN_REFUSAL — proves the code path is reachable from a real fixture, not just theoretically present.

## References

- `mint/hybrid-review.md` — the consolidated 5-dim report (KC-A, KC-B, HIGH H1, testing M1 are this pass)
- `mint/design.md` — the existing design (target for amendments; §5.4 is the focus)
- `mint/review.md` — MVP-1.1A round-1 review (just-completed pass; proves refactor mode works for additive changes)
- Raw hybrid-review per-reviewer outputs at `/home/user/agent-teams-review/runs/hybrid-mint-l2-mac-filter-202605222203/` — external to repo, available if architect wants the multi-dim reasoning behind KC-A or KC-B.

## Packs to load

```yaml
packs:
  architect:  []
  impl:       [lang/cpp.md, lang/bpf.md, lang/cmake.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []
```

## Notes for architect

- This is **the second refactor-mode run** and **the first that touches real source code** (loader.cpp, not just CMake/Markdown). Existing design.md is your starting point. Your output is **§5.4 revision + §5.19/§5.20/§6.9 amendments**.
- The three trust-boundary items (KC-A, KC-B, 4-state) are interlinked — they all touch the same `loader.cpp:97-107` + `loader.cpp:149-169` region. Design them as a coherent §5.4 revision, not as 3 independent amendments that conflict with each other. The §5.4 revision IS the unifying story.
- For KC-A identity-verification: pick ONE mechanism and document it (multiple options listed in scope item 2). Don't enumerate all options in §5.19 — that's design indecision. Pick the one that closes the threat at minimal impl cost. The reviewer can re-evaluate the tradeoff if they disagree.
- For KC-B all-modes query: the libbpf API surface here matters — `bpf_xdp_query_id(ifindex, flags, &id)` with `flags=0` queries any mode AND returns the highest-priority attached program. If multiple modes have attachments (rare but possible), the highest mode wins. Architect: document this libbpf behavior in §5.20 so impl doesn't have to rediscover.
- For the 4-state machine: be explicit about which state corresponds to which exit code. The current 3-state matrix maps to exits {0, 3, 4}; the new 4th state (stale-pin recovery) should NOT introduce a new exit code — it's a successful attach (exit 0) that first cleans the orphan dir. Symmetrically, detach in the no-prog-but-pin-dir state should exit 0 (recoverable cleanup), not 5.
- For the test (§6.9): the foreign-XDP fixture is a real engineering decision. If you go with a vendored `tests/fixtures/xdp_pass.bpf.c` (~15 lines: `SEC("xdp") int xdp_pass(struct xdp_md *ctx) { return XDP_PASS; }` + license), CMake needs an `add_bpf_object(xdp_pass …)` invocation in `tests/CMakeLists.txt`. Document the build wiring decision in §6.9.

## Notes for impl

- Source-code edits ARE in scope this pass — but ONLY in `src/loader/loader.cpp` (no other src/ files touched). If you find yourself wanting to change `loader.hpp` (e.g. adding a new public function), SendMessage architect first — that's an API change that needs design coverage.
- Per cpp pack: maintain zero-warning floor + `-Werror`. The new ownership-verification logic must be RAII-clean (no fd leaks if verification fails mid-process; close any new fds via `unique_ptr` with custom deleter or via the existing RAII pattern).
- Per bpf pack idiom + design §5.18: the existing sanitizer build will catch UB in your new logic if you make any. Run it.
- For the foreign-XDP fixture (if architect specifies vendored): you build the `xdp_pass.bpf.o` artifact, tester invokes it.

## Notes for tester

- One new test: `T_ATTACH_ALIEN_REFUSAL` per §6.9. RESOURCE_LOCK xdp_fixture (same lock as the other 6 functional tests). TIMEOUT 60s should suffice (no asan build inside).
- The negative assertion (foreign prog NOT clobbered) is the safety floor — verify via `xdp_prog_id veth_a` before+after our attach attempt; the prog id should remain identical to the foreign one we attached.
- T_NEGATION_CONTROL still serves as the suite-level negation control; no additional negation needed for this single new test.
- All 8 pre-existing tests must remain byte-identical and still pass — non-negotiable.
