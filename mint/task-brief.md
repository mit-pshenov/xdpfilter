# Task brief — MVP-1.1A: hybrid-review quick wins (refactor mode)

## Goal

Apply 3 narrowly-scoped fixes from the hybrid review to the existing MVP-1 codebase. This is **NOT a redesign** — it's an iterative refactor pass. The MVP-1 codebase (`src/`, `tests/`, `CMakeLists.txt`, `cmake/`) exists and works (7/7 ctest entries green); architect produces AMENDMENTS to existing artifacts, impl EDITS existing files, tester ADDS to the existing test suite.

This is **the first refactor-mode run of the mint workflow** — until now mint has only been validated on greenfield. Workflow rules below clarify the refactor framing.

## Context: prior MVP-1 work

- **MVP-1 brief**: `mint/task-brief-mvp1.md` (the original 0.1.0 brief — kept for reference)
- **MVP-1 design**: `mint/design.md` (single source of truth — architect EDITS this, doesn't rewrite)
- **MVP-1 review**: `mint/review.md` (mint-reviewer triangulation, verdict pass)
- **Hybrid review report**: `mint/hybrid-review.md` (5-dim external review — input for THIS pass)
- **Impl notes**: `mint/impl-notes.md` (deviations log; impl appends here as needed)

## Workflow rules (refactor mode — read carefully)

- **Architect**: read `mint/design.md` + `mint/hybrid-review.md` + this brief. Produce AMENDMENT-style output by **editing `mint/design.md` in place**: append new `§5.17` / `§5.18` decision entries (continue the §5.15 / §5.16 amendment pattern), edit the existing `§2 FileList` row(s) that drifted from reality, and append new `§6.x` TestStrategy items for any new tests. **Do NOT rewrite design.md from scratch.** Do NOT regenerate FileList — list only the new files that this pass adds.
- **Impl**: EDIT existing files. The only NEW file in this pass is `README.md` at repo root. Do not rewrite untouched code.
- **Tester**: ADD new tests for the new TestStrategy items. Existing 7 tests stay untouched.
- **Reviewer**: 4-point triangulation over the amendments + new tests. Existing-and-unchanged code is out of scope for this pass.

## Scope (exactly 3 items — anything else is out of scope this pass)

### Item 1 — design.md §2 FileList drift fix (HIGH H4 in hybrid-review.md)

`mint/design.md:28` (raii.hpp row) and `mint/design.md:31` (loader.hpp row) name symbols that don't exist in code:
- design says `BpfObject, BpfMap (non-owning view), XdpAttachment, BpffsDir` → code declares `BpfSkeleton, XdpAttachment, BpffsDir` (no BpfObject, no BpfMap).
- design says loader exports `populate_allowlist()` → code doesn't; it's inline in `loader.cpp:205-213`.

**Action**: edit the §2 FileList rows in place to match reality, AND append `§5.17` decision entry recording the post-publication FileList correction (same pattern as `§5.15` rename amendment).

### Item 2 — README.md + missing dependency declarations (HIGH H5 in hybrid-review.md)

Repo root has no entry-point documentation; `libc++-19-dev` is buried in `mint/impl-notes.md`; `python3`/`scapy`/`jq`/`sudo`/`iproute2` test deps are nowhere user-facing.

**Action**:
1. Create `README.md` (~40-80 lines) at repo root with sections: what / prerequisites + apt-install line / build / run / test / where-docs-live.
2. Edit `mint/task-brief-mvp1.md` (the renamed original brief) Dependencies section to add `libc++-19-dev` — this is the canonical MVP-1 constraint list.

The README is allowed to be informal; the goal is to remove first-contact friction, not to ship polished prose. Mention the kernel ≥ 5.15 floor.

### Item 3 — Sanitizer build option + ctest entry (HIGH H3 in hybrid-review.md)

No ASAN/UBSAN coverage exists; C++ ownership paths (RAII × 3, MAC tokenizer, filesystem::remove_all rollbacks) are uninstrumented.

**Action**:
1. Add CMake option `XDPMF_SANITIZERS=OFF` (default off) in `CMakeLists.txt`. When `ON`, inject `-fsanitize=address,undefined -fno-omit-frame-pointer` to C++ targets only (libbpf is plain C — do not sanitize it; the BPF object is `clang -target bpf` — also out of scope for sanitizers).
2. Add `T_SANITIZER_BUILD` ctest entry that: (a) configures a fresh `/tmp/xdpmf-asan-XXXXXX` build dir with `-DXDPMF_SANITIZERS=ON`, (b) builds it cleanly, (c) runs ONE end-to-end attach+inject-MAC_GOOD+stats-check+detach scenario against the asan-built binary, (d) asserts no AddressSanitizer/UndefinedBehaviorSanitizer report appears in the binary's stderr (`grep -q -E 'AddressSanitizer|UndefinedBehavior' && fail`). Test goes into `tests/` per existing pattern.
3. Append `§5.18` decision entry to design.md recording the sanitizer-build addition + rationale (test-only build target, not shipped).
4. Append `§6.8 T_SANITIZER_BUILD` to design.md TestStrategy section.

## Out of scope (explicit anti-drift fence — anything in hybrid-review.md NOT listed above)

The following findings from `mint/hybrid-review.md` are explicitly DEFERRED to a later pass (B / C / MVP-2):
- §5.4 ownership marker hardening (KC-A identity verification, KC-B all-modes query) — B pass
- §5.4 4-state stale-pin recovery — B pass
- `T_ATTACH_ALIEN_REFUSAL` test — B pass
- PERCPU stats migration — MVP-2 (explicit per design §5.3)
- `--mode {generic,native,offload}` CLI flag — MVP-2 (explicit per design §5.6)
- All MEDIUM and LOW findings (string churn, sleep-based sync, host-scope veth, etc.) — MVP-2 polish
- Architecture M1 (backwards layering loader.hpp → cli.hpp) — MVP-2

Do NOT incidentally fix any of the above "while you're at it". Tight scope = clean stress test of refactor-mode workflow.

## Acceptance criteria

1. `mint/design.md` contains a new `§5.17` amendment entry fixing the §2 FileList drift, with the §2 rows themselves edited.
2. `mint/design.md` contains a new `§5.18` amendment entry recording the sanitizer-build option.
3. `mint/design.md` contains a new `§6.8` TestStrategy entry for `T_SANITIZER_BUILD`.
4. `README.md` exists at repo root, ≥ 30 lines, with at minimum: title line, "What it does" paragraph, "Prerequisites" (apt-install line), "Build" steps, "Test" steps.
5. `mint/task-brief-mvp1.md` Dependencies section includes `libc++-19-dev`.
6. `CMakeLists.txt` has a `XDPMF_SANITIZERS` CMake option (default OFF). When OFF, the existing build is byte-identical to before this pass.
7. `tests/CMakeLists.txt` declares `T_SANITIZER_BUILD` with appropriate timeout.
8. `T_SANITIZER_BUILD` passes when run via `sudo -E ctest --test-dir build --output-on-failure`.
9. All 7 pre-existing tests still pass (no regression — proves refactor mode didn't break anything).
10. Build is clean (zero warnings under `-Werror` floor) for both default and `-DXDPMF_SANITIZERS=ON` build configurations.

## References

- `mint/hybrid-review.md` — the consolidated 5-dimension report (input)
- `mint/design.md` — the existing design (target for amendments)
- `mint/task-brief-mvp1.md` — original MVP-1 brief (target for one-line dep update)
- The raw per-reviewer outputs + archaeology that fed the hybrid report live at `/home/user/agent-teams-review/runs/hybrid-mint-l2-mac-filter-202605222203/` — outside the repo, available if architect wants additional detail on any finding.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
packs:
  architect:  []                                       # designs amendments at abstract level
  impl:       [lang/cpp.md, lang/bpf.md, lang/cmake.md]
  tester:     [test/bpf-xdp.md]
  reviewer:   []                                       # generic framework + LSP
```

## Notes for architect

- This is the **first refactor-mode run** of the mint workflow. Existing design.md is your starting point, not a blank page. Your job is much smaller than MVP-1: edit §2 to match reality, append §5.17 + §5.18 + §6.8 amendments. That's it.
- The hybrid-review.md report is comprehensive — do NOT design fixes for anything outside the 3 scope items above. The "out of scope" fence is explicit precisely because the hybrid report is tempting reading.
- For the sanitizer item: architect decides HOW (CMake option name, exact flag set, whether ASAN+UBSAN combined or separate targets) — document the choice in §5.18.
- For the README item: architect decides structure (which sections, in what order). The brief specifies minimum content; architect can be more thorough. Keep it utilitarian, not marketing prose.
- For §2 FileList drift: edit the rows themselves to current reality, AND record the post-publication correction in §5.17 (the §5.15 / §5.16 pattern). The mint-reviewer's prior triangulation missed this drift; explicitly note in §5.17 that the §2 FileList serves as a contract going forward.

## Notes for impl

- Code changes are SMALL: ~20-30 LOC of CMake for the sanitizer option, ~30-50 LOC of bash for T_SANITIZER_BUILD, ~30-80 LOC of Markdown for README.md, one line in task-brief-mvp1.md.
- No source-code edits to `src/**` for this pass.
- Verify the existing 7 ctest entries still pass after your changes.

## Notes for tester

- Only one new test in this pass: `T_SANITIZER_BUILD`. Use the same `tests/T_BUILD.sh` pattern for "configure-and-build-from-clean-tmp" — but configure with `-DXDPMF_SANITIZERS=ON` instead, then run an end-to-end veth attach+inject+stats scenario against the asan binary, then grep its stderr.
- Negation control NOT required for this single test (the suite-level sanity floor was satisfied in MVP-1; this is an additive pass).
- All existing tests must still pass — that IS your sanity floor for the refactor.
