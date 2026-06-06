# Review — MVP-4.37/B44 `apply --dry-run` (mint triangulation)

## Verdict
`pass` (round 1)

## Triangulation matrix

| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | (negation control PRESENT ×2) |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

OOT: 1 (`inline-merge`, non-verdict-affecting).

## Point-by-point evidence

**1. Spec ↔ Code — all §5.77.3/.4 contracts present & matching**
- `MapWriter` base + `map_*` free-fn wrappers: `map_writer.hpp:39-58`. Signatures match §5.77.4(1).
- **PI-mvp-4.37-FAILCLOSED ✓ (hard gate):** every wrapper's FIRST statement is `if (g_active_writer == nullptr) { no_writer_installed(); }` (`map_writer.cpp:61,67,73,79,85`); `no_writer_installed()` is `[[noreturn]]` → `fputs("xdpfilter: map writer not installed")` + `std::abort()` (`map_writer.cpp:42-46`). No null-deref / no silent no-op / no libbpf fallback on any wrapper.
- `LiveMapWriter` forwards VERBATIM to real libbpf (`live_map_writer.cpp:31-51`). `install_live_map_writer()` at `live_map_writer.cpp:59`, called once at `main.cpp:122` before `std::visit`.
- `kMapCatalog` = EXACTLY 14 entries via `sizeof` (no magic numbers) `map_writer.cpp:100-115` → guard #10 ✓.
- `render_dryrun_image` drives the SAME 3-call sequence (`map_image.cpp:109-113`) under `RecordingScope`; D-mvp-4.37-BRANCH-SITE honored — dry-run branches at `run_apply` (`main.cpp:58-62`) BEFORE `apply_config`/`apply_request`; `ApplyConfig.dry_run` is the only new field (`apply.hpp:31`), `ApplyRequest` untouched.
- `dryrun_image_for_file` shares `load_and_reconcile` with live `apply_config` (`apply.cpp:93-117,129-135`) → invalid-config dry-run errors with identical exit codes 1/9.
- impl-notes 3 MAY-level choices (`set_active_writer`/`active_writer` free-fns; `format_dryrun_image` public name; `load_and_reconcile` extraction) — all within-contract, no silent drift.

**2. Spec ↔ Tests — TestStrategy fully covered + negation controls present**
- #112 `T_DRYRUN_IMAGE_IDENTITY`: drives production `render_dryrun_image(build_corpus())`, byte-compares frozen golden (`dryrun_harness.cpp:338-348`). SMOKE (`:352`) + NEGATION (`:377`) + three-way oracle agreement via production `format_dryrun_image` (`:411`).
- #113 `T_CLI_APPLY_DRYRUN`: exit 0, image header, symbolic `dpi0 RESOLVED-AT-APPLY` devmap, byte-equals golden, ZERO side-effects (`T_CLI_APPLY_DRYRUN.sh:69-127`); **MANDATORY NEGATION** = same args without `--dry-run` → non-zero (`:142`) + **secondary negation** = corrupted-golden comparator proof (`:176`). No CIRCULAR-TEST.

**3. Code ↔ Tests — re-ran independently**
- `/tmp/mint-review-tests-1780751301.log`: #112 + #113 PASS (offline subset, no competing run live).
- No UNEXERCISED-EXPORT: `LiveMapWriter`/`install_live_map_writer` exercised by full-suite live apply (test-run.log #21/#23/#109-111 GREEN); render path by #112/#113.

**4. Out-of-Scope — clean**
- No human-decode/pretty-print/mirror/rate-limit tokens in new code. `--dry-run` wired ONLY into `parse_apply` (`cli.cpp:247`) + `run_apply` — NOT `attach`. No VERSION bump (D-mvp-4.37-NOVER).

**5. Behaviour preserved (brownfield) — all invariants hold**
- **PI-mvp-4.37/4.36-LIVE-IDENTITY ✓:** `git diff c30200d` = ZERO on `loader.cpp`, `apply_internal.hpp`, `materialize.hpp`, `loader.hpp`, `src/bpf/`. `materialize.cpp` diff is body-only `bpf_*`→`map_*` swaps + 1 include, all 4 signatures byte-identical.
- **PI-mvp-4.37-LIBBPF-FREE ✓:** `ldd build/dryrun_harness` → no libbpf; `nm -u` → no undefined `bpf_*`. Harness links neither `PkgConfig::LIBBPF` nor `live_map_writer.cpp` nor `loader.cpp` (tests/CMakeLists.txt:1768-1772).
- **PI-mvp-4.37-SSOT ✓ (guard #9):** sole `# xdpfilter-image v1` producer = `map_image.cpp`; `format_dryrun_image` defined once; harness has NO own image builder.
- golden `dryrun_image.golden` BYTE-UNCHANGED (git diff = 0); `fake_bpf.{cpp,hpp}` deleted; test total +1.
- **#48/#63 are NOT regressions:** `git diff c30200d` = ZERO on both test scripts + `src/exporter/`; env-rooted (host `/sys/fs/bpf/xdpfilter` absent → exporter exit 999/Killed). Pre-existing floor matches prior cycle. No `[REGRESSION]`.

## Test execution (last lines)
```
1/2 Test #112: T_DRYRUN_IMAGE_IDENTITY ..........   Passed    0.01 sec
2/2 Test #113: T_CLI_APPLY_DRYRUN ...............   Passed    0.14 sec
100% tests passed, 0 tests failed out of 2
golden byte-unchanged vs c30200d: 0 diff lines ; fake_bpf.*: deleted
dryrun_harness libbpf-free: ldd CLEAN, nm -u CLEAN
```
(Full-suite live witnesses in tester's mint/test-run.log: 111/113, only #48/#63 env-fails.)

## Out-of-triangulation findings

### [OUT-OF-TRIANGULATION] CLI test script path differs from FileList
**Location**: `tests/T_CLI_APPLY_DRYRUN.sh` (actual) vs `design.md` §5.77.2 FileList row `tests/dryrun/T_CLI_APPLY_DRYRUN.sh`
**Evidence**: Design FileList places the script under `tests/dryrun/`; tester landed it at `tests/` (registered via `${TEST_DIR}/T_CLI_APPLY_DRYRUN.sh`, tests/CMakeLists.txt:1823) — consistent with where the other `T_*.sh` scripts live. The `dryrun_cli.yaml` corpus IS at `tests/dryrun/` as specced. Purely a test-harness file location, not a contract/PI/behavioral surface; test runs green.
**Recommended disposition**: `inline-merge` (amend the design FileList path to match the landed location)
**Rationale**: Tester-owned path with zero load-bearing impact; flagged so the FileList drift is disposed of visibly.

No rework assignments — all 5 framework points pass.

### Post-review sweep — round 1
- OOT "CLI test script path" → `mint/design.md` §5.77.2 FileList edited → corrected the row path `tests/dryrun/T_CLI_APPLY_DRYRUN.sh` → `tests/T_CLI_APPLY_DRYRUN.sh` (matches the landed location + the other `T_*.sh` convention; `dryrun_cli.yaml` stays under `tests/dryrun/`). Rides in the Phase 6 final commit.
