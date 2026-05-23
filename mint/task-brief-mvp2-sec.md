# Task brief — MVP-2 Sec: §5.19 tag-check + O_PATH bpffs root hardening (refactor mode)

## Goal

Close two remaining attack vectors on the §5.4 / §5.19 trust boundary, both deferred to MVP-2 in design.md §7:

1. **Tag-check identity gate** layered ON TOP of the existing name-check (§5.19 option iii referenced; full spec deferred to MVP-2 per §7 line 1378-1382). Closes the **attacker-recompile** vector: a CAP_BPF attacker who recompiles `src/bpf/mac_filter.bpf.c` with the same `SEC()` name but altered behaviour produces a program whose `bpf_prog_info.name == "mac_filter_prog"` (passes name-check) but whose `bpf_prog_info.tag` (SHA1-of-bytecode) differs from our own freshly-built skeleton's tag.

2. **O_PATH/O_DIRECTORY/O_NOFOLLOW fd hardening** on the bpffs root path (per §5.19 option (iii) + §7 line 1383-1385). Closes the **symlink-vortex** subset of KC-A: an attacker who plants a symlink at `/sys/fs/bpf/xdpmacfilter/` itself or at the per-iface subdir tricks `std::filesystem::{exists,create_directories,remove_all}` into operating on attacker-controlled paths.

This is the **first MVP-2 pass** — first time we touch security beyond MVP-1.1B's name-check baseline. Scope is intentionally narrow: 2 items, both extending §5.19. No CLI surface changes, no .bpf.c changes, no .hpp changes (per §5.19 "All new helpers live in the anonymous namespace of `loader.cpp`. No new symbols cross the `loader.hpp` boundary").

## Context: prior work

- **MVP-1 brief**: `mint/task-brief-mvp1.md`
- **MVP-1.1A brief**: `mint/task-brief-mvp1.1a.md`
- **MVP-1.1B brief**: `mint/task-brief-mvp1.1b.md` — the §5.4 4-state machine + §5.19 name-check baseline
- **MVP-1.1C brief**: `mint/task-brief-mvp1.1c.md` — the polish batch
- **Existing design**: `mint/design.md` — already amended through §5.21 + §6.13. §5.19 is the authoritative spec on identity verification; §7 lines 1378-1385 explicitly defer tag-check and O_PATH to MVP-2 (us).
- **Hybrid review source**: `mint/hybrid-review.md` — sec M1 "Recommended fix" enumerates the three identity mechanisms (name / map-identity / O_PATH); §5.19 ships (i) name-check; this brief ships (iii) O_PATH **plus** the tag-check enhancement architect described in §5.19's "strongest defense" paragraph (lines 576-584).

## Workflow rules (refactor mode — same as MVP-1.1A/B/C)

- **Architect**: read existing `design.md` (especially §5.19 in full + §7 deferral entries) + `hybrid-review.md` sec M1 + this brief. EDIT design.md in place. Append a new amendment block `§5.22 MVP-2 Sec: tag-check + O_PATH hardening` after §5.21. The amendment MUST address the open mechanism questions below (architect chooses, justifies, documents). Append new `§6.x` TestStrategy items for the new tests. NO design rewrites; this extends §5.19, doesn't replace it.
- **Impl**: EDIT `src/loader/loader.cpp` in place — the probe helper, the attach() entry path, and the bpffs-touching helpers (`ensure_bpffs_dir`, `bpffs_remove_iface`, and the inline `std::filesystem::exists(pin_dir)` callsite in `attach()`/`detach()`). All new helpers stay in the anon namespace per §5.19. `loader.hpp` MUST NOT change (no new public symbols). May need a new local RAII wrapper for the bpffs root fd in `loader.cpp` anon namespace.
- **Tester**: ADD new ctest scripts for the new TestStrategy entries (~2 new tests; architect specifies the exact list in §6.x). Tester may need to extend `tests/fixtures/` with a second variant of the alien-XDP fixture that has the same SEC name but altered bytecode (for tag-mismatch test). Existing 13 ctest entries stay green (or legitimately SKIP).
- **Reviewer**: 4-point triangulation focused on §5.22 + new tests + the §5.19 extension correctness. Existing-and-unchanged code is out of scope, with one exception: verify the loader.hpp invariant ("no new public symbols") actually held.

## Open mechanism questions (architect decides; document in §5.22)

These are the substantive design decisions this pass requires. Architect picks one path per question, documents rationale.

### Q1: Self-tag capture timing — early vs. lazy?

The tag-check requires the loader to know "our own" tag at the moment of identity verification (which currently happens inside the probe at the start of `attach()`, before any skeleton load). Two options:

- **Option E (early)**: load the skeleton FIRST (before the probe), capture self-tag via `bpf_prog_get_info_by_fd(skel->progs.mac_filter_prog.prog->fd)`, THEN do the probe. Pro: one skeleton load, one tag, used everywhere. Con: skeleton is loaded even in state-(c) (alien refusal) where we immediately throw → wasted work + brief kernel-resource churn.
- **Option C (compile-time)**: post-build step extracts the tag from `mac_filter.bpf.o` via a tiny libbpf-using extractor, generates `expected_tag.h` with `constexpr std::array<__u8, 8> kExpectedTag = {0x..., ...};`; loader compares probe's tag against this static constant. Pro: no extra runtime work; tag-check is pure constant-time. Con: build pipeline gains a new step + a new generated header; release-build determinism becomes load-bearing.

Architect picks; both are reasonable; (C) is the cleaner architectural answer if the build pipeline can absorb the codegen step. (E) is simpler at runtime cost.

### Q2: O_PATH fd hardening scope — surface area?

Three concentric circles of coverage; architect chooses how far to push:

- **Minimum**: open `/sys/fs/bpf/xdpmacfilter/` with `O_PATH | O_DIRECTORY | O_NOFOLLOW` early; use this fd for the existence check (`faccessat(root_fd, iface, F_OK, AT_SYMLINK_NOFOLLOW)`), per-iface dir creation (`mkdirat(root_fd, iface, 0755)`), and existence check before pin operations. **Does NOT** harden `std::filesystem::remove_all(pin_dir)` (the recursive-removal path) — leave that as-is.
- **Standard**: minimum + harden removal via `openat(root_fd, iface, O_PATH|O_DIRECTORY|O_NOFOLLOW)` + iterate `entries` via `getdents64` (or `std::filesystem::directory_iterator` on an fd-relative path) + `unlinkat` each + `unlinkat(root_fd, iface, AT_REMOVEDIR)`. Closes the per-iface-symlink subset too.
- **Maximum**: standard + also pass the fd-relative path to libbpf for map pinning so that libbpf's `bpf_obj_pin` happens relative to our O_PATH fd. CON: libbpf's `pin_root_path` API is path-string-based; this would require either a libbpf version that supports fd-relative pinning OR re-implementing the pin step manually via `bpf_obj_pin` against `O_PATH`-rooted constructed paths. Likely too invasive for this pass.

Architect picks; **Standard** is the recommended target — covers both attack vectors (root-level symlink + per-iface symlink) without dragging libbpf into scope. **Minimum** is the floor; **Maximum** is OOS for this pass.

### Q3: New exit code for symlink-refused?

If the bpffs root or per-iface entry exists but is a symlink, the loader refuses to operate. Current exit codes (§4.1):

- 4 = `AttachRefusedAlien` (semantically "refusing to clobber someone else's setup")
- 6 = `Permission` (kernel/filesystem permission denial)
- 7 = reserved (was going to be `KernelUnsupported` per MVP-2 Robust slice; that's a different pass)

Options:
- **Reuse 4 (`AttachRefusedAlien`)**: spec'd "alien" extended to mean "anything not in our exact ownership shape", including suspect paths.
- **Reuse 6 (`Permission`)**: symlink refusal is a filesystem-policy decision; fits the permission semantic.
- **New code (`PathRefused`, exit 8)**: distinct, observable, audit-friendly. Costs a new design §4.1 row.

Architect picks; reusing existing codes keeps the surface flat. If picking new code, justify the audit value.

## Scope (exactly 2 items + tests — anything else is OOS)

### Item 1 — Tag-check identity gate (extends §5.19 mechanism (i))

**Where**: `src/loader/loader.cpp` — the `probe_attached_xdp()` helper + the `is_ours` predicate + the `attach()` state-(b) branch.

**Action**:
1. Extend the existing `XdpProbe` struct (§5.19 spec, lines 594-604 of design.md) to add a `std::array<__u8, BPF_TAG_SIZE> tag;` field populated from `bpf_prog_info.tag`. `BPF_TAG_SIZE` is libbpf-defined and currently 8.
2. The `is_ours` predicate becomes: `(mode == SKB) && (name == "mac_filter_prog") && (tag == self_tag)`. The `self_tag` comes from Q1 architect decision (option E or C).
3. State-(c) refusal message MUST now include the probed tag in hex (load-bearing for the new T_ATTACH_TAG_MISMATCH test): `std::format("XDP prog id {} (name '{}', tag {:02x}{:02x}...{:02x}) on {} — refusing to clobber (tag mismatch)", ...)`. Use `std::format` ranges-style join for the 8-byte array; impl picks format spelling.
4. Failure of the tag query (e.g. kernel returned `bpf_prog_info.tag` as zeros, or `bpf_prog_get_info_by_fd` returned EPERM) → fail closed (`is_ours = false`), as already specified for the name-check at §5.19 lines 611-616.

### Item 2 — O_PATH bpffs root fd hardening (extends §5.19 mechanism (iii))

**Where**: `src/loader/loader.cpp` — `ensure_bpffs_dir`, `bpffs_remove_iface`, the inline `std::filesystem::exists(pin_dir)` checks in `attach()` (line 284) and `detach()` (line 390).

**Action** (Standard scope per Q2):
1. Add a local RAII wrapper `BpffsRootFd` in `loader.cpp` anon namespace (NOT in `raii.hpp` — single-callsite per §5.19 RAII pattern) that opens `XDPMF_BPFFS_ROOT` with `O_PATH | O_DIRECTORY | O_NOFOLLOW`, retrying once via `mkdirat(AT_FDCWD, XDPMF_BPFFS_ROOT, 0755) + open` if the initial open returns `ENOENT`. Close fd on destruction. Sole owner.
2. Replace path-based bpffs operations with fd-relative `*at()` syscalls relative to the root fd:
   - `std::filesystem::exists(pin_dir)` → `faccessat(root_fd, iface, F_OK, AT_SYMLINK_NOFOLLOW)`. Symlink → behaves as "not exists" AND records a soft warning to stderr (or: refuses outright with the Q3-chosen exit code; architect decides).
   - `ensure_bpffs_dir(pin_dir)` → `mkdirat(root_fd, iface, 0755)`. Already-exists (`EEXIST`) is OK only if `fstatat(root_fd, iface, &st, AT_SYMLINK_NOFOLLOW)` confirms it's a directory (not symlink).
   - `bpffs_remove_iface(iface)` → open per-iface dir via `openat(root_fd, iface, O_PATH|O_DIRECTORY|O_NOFOLLOW)`, iterate entries, `unlinkat(iface_fd, entry, 0)` each, then `unlinkat(root_fd, iface, AT_REMOVEDIR)`. Wrap iface_fd in scoped fd RAII.
3. The "bpffs root itself is a symlink" case: initial `open(XDPMF_BPFFS_ROOT, O_PATH|O_DIRECTORY|O_NOFOLLOW)` returns ELOOP → fail attach with the Q3-chosen exit code, clear stderr message. Do NOT silently `unlink+mkdir` the root — that's destructive and outside this scope.
4. Existing TOCTOU race window between probe and attach is unchanged (out of scope; would require single-syscall atomic operations not available in libbpf 1.1).

### Tests (tester writes; architect specifies §6.x in design)

#### Test 1 — T_ATTACH_TAG_MISMATCH (closes attacker-recompile vector)

**Fixture**: a second `.bpf.c` source `tests/fixtures/mac_filter_alt.bpf.c` with the SAME `SEC(...)` function name `mac_filter_prog` but a different (no-op `return XDP_PASS` minimum) body. Compile to `.bpf.o` via existing `add_bpf_object` CMake function. The bytecode is intentionally different from `src/bpf/mac_filter.bpf.c` → tag differs.

**Scenario**: attach the fixture via raw `bpftool prog load + bpftool net attach xdp` (same fixture-attach style as `T_ATTACH_ALIEN_REFUSAL`), then invoke `xdpmacfilter attach --iface ${IFACE_A} …`. Assert exit code = `AttachRefusedAlien` (or Q3-chosen code) + stderr contains both the probed tag (in hex) AND the substring `tag mismatch`.

Negation control: same scenario but using the real `mac_filter.bpf.o` (built from `src/bpf/mac_filter.bpf.c`) as the pre-attached fixture — must hit state-(b) (idempotent reload, exit 0). This proves the tag-check accepts our own program identity AND rejects look-alikes — the actual triangulation.

#### Test 2 — T_BPFFS_ROOT_SYMLINK (closes symlink-vortex vector)

**Pre-setup**: as root, `mkdir /tmp/xdpmf-fake-bpffs && ln -sfn /tmp/xdpmf-fake-bpffs /sys/fs/bpf/xdpmacfilter` (if `/sys/fs/bpf/xdpmacfilter` exists from a prior run, `rm -rf` it first; this test deliberately corrupts the bpffs root for the duration of the test).

**Cleanup**: `unlink /sys/fs/bpf/xdpmacfilter; rm -rf /tmp/xdpmf-fake-bpffs`. MUST run in `trap EXIT` because the corruption affects all subsequent tests; `tests/CMakeLists.txt` registers this test with `RESOURCE_LOCK` so it doesn't race the others.

**Scenario**: invoke `xdpmacfilter attach --iface ${IFACE_A} --allow MAC_GOOD`. Assert exit code = Q3-chosen exit (4 / 6 / 8 — architect's pick) + stderr contains a recognizable substring (`ELOOP` / `symlink` / `not a directory` — architect spec's exact word).

Negation control: after cleanup restores the real bpffs root, a fresh attach succeeds. This proves the refusal is symlink-specific, not a permanent break.

Test 2 sub-variant: per-iface symlink. If the architect chooses Q2 Standard (recommended), add a 1-scenario sub-test in the same script: `mkdir /tmp/xdpmf-fake-iface && ln -sfn /tmp/xdpmf-fake-iface /sys/fs/bpf/xdpmacfilter/${IFACE_A}` then attach — must also refuse via Q3-chosen exit. Same cleanup pattern.

## Out of scope (explicit)

- **PERCPU stats migration** — MVP-2 Perf slice
- **`--mode {generic,native,offload}` CLI flag** — MVP-2 Perf slice
- **Kernel-version probe + `LoaderError::KernelUnsupported`** — MVP-2 Robust slice (this pass MUST NOT take exit code 7)
- **`T_VERIFIER_REJECT`** — MVP-2 Robust slice
- **Netns isolation for tests (C3 Path A)** — MVP-2 Polish-2 slice
- **CMake-generation of `PIN_ROOT`** — MVP-2 Polish-2 slice
- **Version-string sync between CHANGELOG.md and `--version`** — MVP-2 Polish-2 slice
- **`inject_runt.py:37` inline comment fix** — MVP-2 Polish-2 slice (advisory from MVP-1.1C review)
- **libbpf-level `pin_root_path` fd-relative pinning (Q2 Maximum)** — too invasive; deferred
- **TOCTOU window between probe and attach** — requires libbpf changes outside our control; deferred
- **`loader.hpp` public API changes** — strict invariant: zero changes to `loader.hpp` symbols in this pass

## Definition of done

- §5.22 amendment block in `mint/design.md` documenting Q1/Q2/Q3 decisions with rationale
- Up to 2 new §6.x TestStrategy entries for T_ATTACH_TAG_MISMATCH + T_BPFFS_ROOT_SYMLINK
- `loader.cpp` extended with tag-check + O_PATH hardening per Q1/Q2 decisions
- `loader.hpp` byte-identical to its current state (verifiable via `git diff`)
- 2 new ctest entries pass on dev host; 13 existing entries still pass (or legitimately SKIP per §6.5)
- `XDPMF_SANITIZERS=ON` build clean (no ASAN/UBSAN regressions from new fd-handling code)
- `mint/review.md` round-1 verdict = `pass`
- One git commit per phase boundary per workflow B

## Dependencies

No new system dependencies. libbpf 1.1+ is already required (B2 in MVP-1.1C). `BPF_TAG_SIZE` and `bpf_prog_info.tag` are stable libbpf API. `mkdirat`/`openat`/`faccessat`/`unlinkat` are POSIX-2008 + Linux. No new C++ libraries.

## Packs to load (orchestrator: inject into spawn prompts)

```yaml
packs:
  architect:  []                                       # security-focused but at abstract level
  impl:       [lang/cpp.md, lang/cmake.md]             # no .bpf.c edits this pass
  tester:     [test/bpf-xdp.md]
  reviewer:   []                                       # generic framework + LSP
```
