# Review — MVP-2 Sec: §5.22 tag-check + O_PATH bpffs root hardening (mint triangulation)

## Verdict
`pass`

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |

## Per-item verification (all green)

### Spec ↔ Code (A1–A9)

- **A1 loader.hpp invariant** — `git diff HEAD~2 -- src/loader/loader.hpp` shows exactly ONE line added: `PathRefused = 8,` at `src/loader/loader.hpp:40`. `git diff HEAD~2 --stat -- src/loader/raii.hpp src/loader/cli.hpp src/loader/cli.cpp src/loader/main.cpp src/bpf/ src/common/` returns empty (all byte-identical). ✅
- **A2 attach() Q1 flow** — skeleton load `loader.cpp:713`, self_tag capture `loader.cpp:714`, probe with self_tag param `loader.cpp:717`, extended `is_ours` predicate `loader.cpp:570-572` (`mode==SKB && name && tag==self_tag`). ✅
- **A3 detach() symmetry per merged §5.22 Q1 detach block (design.md:1004-1046)** — `loader.cpp:817` BpffsRootFd; `loader.cpp:834` `load_skeleton()`; `loader.cpp:835` `capture_self_tag`; `loader.cpp:837` probe with self_tag; state-(c) tag-mismatch → `DetachFailed` (exit 5) at `loader.cpp:868-872`. ✅
- **A4 BpffsRootFd RAII** — `loader.cpp:213-302`. O_PATH|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC at `loader.cpp:224`; retry-once-on-ENOENT at `loader.cpp:227-242`; ELOOP→PathRefused at `loader.cpp:243-249`; ENOTDIR disambig via lstat at `loader.cpp:250-263`. ✅
- **A5 *at() conversion** — `iface_entry_is_real_dir` (faccessat `loader.cpp:310` + fstatat `loader.cpp:320`); `ensure_iface_dir` (mkdirat `loader.cpp:334` + fstatat `loader.cpp:340`); `bpffs_remove_iface` (openat `loader.cpp:368`+`:384`, fdopendir `loader.cpp:396`, readdir+unlinkat `loader.cpp:412-416`, unlinkat AT_REMOVEDIR `loader.cpp:435`). ✅
- **A6 PathRefused fence (Q3 OOS)** — all `throw_loader(LoaderError::PathRefused, …)` callsites are at root open (`loader.cpp:247,257,261`) or per-iface symlink/non-dir helpers (`loader.cpp:192,199`); never used elsewhere. ✅
- **A7 stderr discipline** —
  - tag-mismatch attach message at `loader.cpp:686-689` includes hex tag (via `format_tag_hex`, `loader.cpp:661-666`) + literal "tag mismatch". Detach symmetric message at `loader.cpp:868-872` same shape. ✅
  - root symlink: "bpffs root '…' is a symlink — refusing to operate" at `loader.cpp:248,258` — contains `symlink` + root path. ✅
  - per-iface symlink: "bpffs entry for iface '…' is a symlink — refusing to operate" at `loader.cpp:193` — contains `symlink` + iface name. ✅
- **A8 self-tag failure modes (design.md:1048-1060)** — EPERM/EACCES→Permission via `classify()`; other errno→LoadFailed; all-zero tag→LoadFailed at `loader.cpp:632-656`. Matches spec. ✅
- **A9 Tag stability across loaders (design.md:1062-1091)** — documentary only; no code assertion required. ✅

### Spec ↔ Tests (T1–T6)

- **T1 §6.14 primary** — `T_ATTACH_TAG_MISMATCH.sh:117-190`: pre-attach alt fixture via `ip link xdpgeneric` (`:118`), capture foreign_id (`:121`) + foreign_tag (`:128`), invoke loader (`:139`), assert rc=4 (`:151`), foreign_tag (`:161`), 'tag mismatch' (`:167`), foreign_id (`:173`), foreign-still-attached (`:180`), no-orphan-pin-dir (`:186`). ✅
- **T2 §6.14 loader-twice negation control (reshape)** — `T_ATTACH_TAG_MISMATCH.sh:222-363`: precheck clean (`:233-242`), first attach rc1=0 (`:262`) + our_id_1 (`:266`), second attach rc2=0 (`:297`) + our_id_2 (`:319`) + id-change assertion (`:329-332`), no 'tag mismatch' (`:307`), no 'error:' (`:313`), detach rc=0 + clean post-state (`:348-363`). ✅
- **T3 tag-distinctness preflight** — `T_ATTACH_TAG_MISMATCH.sh:87-107`: bpftool prog load both fixtures, parse `.tag` via jq, compare, abort early if equal. ✅
- **T4 `mac_filter_alt.bpf.c`** — `mac_filter_alt.bpf.c:25-35`: SEC `mac_filter_prog`, body `return XDP_PASS;`, `SEC("license") = "GPL"`, `SEC("xdp")`. ✅
- **T5 §6.15 T_BPFFS_ROOT_SYMLINK** — trap EXIT/INT/TERM/HUP at `T_BPFFS_ROOT_SYMLINK.sh:85`; pre-check refuses non-empty in-use bpffs at `:87-114`; snapshot/restore for empty real root (`ROOT_PREEXISTED` at `:42,109,113`; restore at `:64-66`); primary root-symlink rc=8 + 'symlink' + root path at `:128-188`; per-iface sub-variant rc=8 + 'symlink' + iface token at `:199-256`; negation control real-root rc=0 attach + detach at `:263-335`. ✅
- **T6 `tests/CMakeLists.txt`** — `add_bpf_object(mac_filter_alt …)` at `:30`; T_ATTACH_TAG_MISMATCH `add_test` at `:156-166` (TIMEOUT 60 + RESOURCE_LOCK xdp_fixture + SKIP_RETURN_CODE 77); T_BPFFS_ROOT_SYMLINK `add_test` at `:168-178` (same triple); T_DETACH_NOTHING gains RESOURCE_LOCK xdp_fixture at `:134-139` per §5.22 amendment to §6.13. ✅

### Code ↔ Tests (C1–C4)

- **C1** stderr tokens emitted by impl (`tag mismatch`, hex tag, `symlink`, iface name, root path) all match test grep assertions; all six T_ATTACH_TAG_MISMATCH primary checks pass + all five T_BPFFS_ROOT_SYMLINK primary/sub-variant checks pass.
- **C2** both new tests have working negation controls — loader-twice in T_ATTACH_TAG_MISMATCH (proves identity gate ACCEPTS our own program); clean-real-root in T_BPFFS_ROOT_SYMLINK (proves refusal is symlink-specific).
- **C3** tester's `mint/test-run.log` shows 15/15 pass (1 SKIP for T_DROP_MALFORMED). ✅
- **C4** re-ran `ctest --output-on-failure` against fresh build: same 15/15 pass / 1 SKIP. Log at `/tmp/mint-review-tests-1748022*.log`. ✅

### OOS-Drift (4)

Touched files vs spec'd surface:
- `src/loader/loader.cpp` ✅ (per §5.22)
- `src/loader/loader.hpp` +1 line ✅ (per §5.22 Q3 relaxation)
- `tests/T_ATTACH_TAG_MISMATCH.sh` ✅ new
- `tests/T_BPFFS_ROOT_SYMLINK.sh` ✅ new
- `tests/fixtures/mac_filter_alt.bpf.c` ✅ new
- `tests/CMakeLists.txt` ✅ 1 `add_bpf_object` + 2 `add_test` + 1-line RESOURCE_LOCK amendment to T_DETACH_NOTHING

`git diff HEAD~2 --stat` confirms only these paths were modified. No OOS drift.

Impl deviations from spawn message (judged):
- **`bpf_map__set_pin_path(map, NULL)` workaround** (`loader.cpp:610-616`) — necessary for §5.22 Q1 Option E (early-load WITHOUT auto-pin so state-(c) refusal unwinds cleanly). Inline-documented at `loader.cpp:589-601`. **In scope** — supports the architectural choice.
- **ENOTDIR vs ELOOP dual handling** (`loader.cpp:243-263`) — Debian kernel reality: under `O_PATH|O_NOFOLLOW|O_DIRECTORY`, symlink-at-trailing-component returns ENOTDIR on some kernels (per `man 2 open`). Impl disambiguates via lstat to preserve literal "symlink" stderr token. **In scope** — defensive impl detail; stderr discipline preserved.
- **detach() also early-loads + tag-checks** — explicitly merged into design.md §5.22 Q1 detach() symmetry block at `design.md:1004-1046` during architect's Phase B. **In spec, not drift.**

## Test execution

Last lines of `/tmp/mint-review-tests-*.log`:

```
13/15 Test #13: T_DETACH_NOTHING .................   Passed    0.17 sec
14/15 Test #14: T_ATTACH_TAG_MISMATCH ............   Passed    2.10 sec
15/15 Test #15: T_BPFFS_ROOT_SYMLINK .............   Passed    1.47 sec

100% tests passed, 0 tests failed out of 15

Total Test time (real) =  65.08 sec

The following tests did not run:
	  5 - T_DROP_MALFORMED (Skipped)
```

Matches tester's `mint/test-run.log` exactly (modulo wall-clock).

## Justification

All four triangulation framework points are clean:
1. Spec↔Code: every §5.22 contract item (A1-A9) maps to concrete code at cited file:line; the 1-line `loader.hpp` diff is exactly the Q3-negotiated relaxation and nothing more.
2. Spec↔Tests: every §6.14 + §6.15 test directive has a corresponding assertion at cited file:line; both tests include working negation controls; T_ATTACH_TAG_MISMATCH uses the architect-merged loader-twice reshape per §6.14 Phase B reshape block.
3. Code↔Tests: 15/15 pass (1 expected SKIP) reproduced locally; stderr tokens emitted by impl are exactly what tests grep for.
4. OOS-Drift: only the spec'd surface was touched; the three negotiated impl deviations are either documented inline (pin-path NULL, ENOTDIR/ELOOP) or merged into spec (detach symmetry).

No findings. Verdict: **pass**.
