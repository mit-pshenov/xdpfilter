# Consolidated Review — mint-l2-mac-filter (MVP-1 L2 MAC allow-list XDP filter, v0.1.0)

## TL;DR

A small (~870 LOC), well-organised MVP that already passed mint-reviewer triangulation. The hybrid review surfaces **no Criticals**, **5 verified Highs**, and **two compounded findings that elevate to High by cross-dimension synthesis**. Everything serious clusters around three repeated themes: (1) the `stats` map is shared/non-atomic (flagged independently by 3 dimensions — design-sanctioned per §5.3 but real impact at production load); (2) the §5.4 "ownership marker = directory existence" rule is structurally weak (flagged independently by 3 dimensions — TOCTOU, lifecycle gap, untested branch); (3) onboarding/discoverability friction (no README, design §2 FileList drift, undeclared test deps). Nothing here fails MVP-1 acceptance; everything here is MVP-2 fodder with one quick win available (the design §2 FileList drift is a 5-line amendment in the same pattern as §5.15/§5.16).

Headline bullets:
- 5 confirmed High findings (1 arch, 1 perf, 1 testing, 2 documentation); 0 demotions; 1 synthesized High kill-chain (security M1 + M2 + §5.7 = "Spoofed-ours network blackhole DoS" in multi-tenant root contexts).
- The §5.4 ownership marker (directory presence only) is the single most-flagged code region — appears in security (M1 TOCTOU + M2 mode-bypass kill chains), architecture (HIGH stale-pin lifecycle gap), and testing (M alien-refusal untested). Same 20 lines of loader.cpp seen through 3 different lenses.
- `stats` map non-PERCPU + non-atomic increment is correctly design-sanctioned (§5.3) — but 3 reviewers independently flagged its real-world impact. Performance reviewer's quantitative model (~30–70% counter loss at 1 Mpps × 16-CPU, +80–150 cycles/pkt cache bounce) is the most actionable framing.
- Documentation reviewer caught a real cross-doc drift the mint-reviewer missed: design.md §2 FileList names (`BpfObject`/`BpfMap`/`populate_allowlist`) don't exist in code — they were superseded when impl adopted the bpftool-generated skeleton. Fixable as a §5.17 amendment.
- The 7-test ctest harness is genuinely solid (real WILL_FAIL negation control, proper SKIP_RETURN_CODE wiring, trap-based cleanup) — primary testing gaps are sanitizer build (HIGH) and the alien-refusal sub-variant (which design §6.6 marked OPTIONAL).

## Headline numbers

| Reviewer | Total | Critical | High | Medium | Low | Info |
|---|---|---|---|---|---|---|
| security | 7 | 0 | 0 | 2 | 4 | 1 |
| architecture | 9 | 0 | 1 | 3 | 4 | 1 |
| performance | 7 | 0 | 1 | 3 | 3 | 0 |
| testing | 18 | 0 | 1 | 8 | 9 | 0 |
| documentation | 13 | 0 | 2 | 6 | 5 | 0 |
| **Σ raw (with dupes)** | **54** | **0** | **5** | **22** | **25** | **2** |
| **Σ (deduplicated)** | **~42** | **0** | **5 + 1 synth** | **~18** | **~22** | **2** |

(Dedup primarily merges the §5.4 ownership-marker findings across 3 dims and the `stats` non-atomic counter across 3 dims.)

## Validation report

- findings_received: 54 raw across 5 dimensions
- findings_validated: 11 (all 5 Critical/High citations re-Read at cited line; 6 cross-validated Mediums spot-checked)
- findings_unverified: 0
- findings_demoted: 0
- citations_normalized: 2
  - The §5.4 ownership marker is cited at loader.cpp:149-169 (architecture), loader.cpp:154-160 (testing), loader.cpp:149-169 (security M1) — all refer to the same 20-line code region; normalized to **loader.cpp:149-169**.
  - The non-atomic stats counter is cited at mac_filter.bpf.c:39-45 (security), :37-45 (architecture), :29-45 (performance, including the map decl) — normalized to **mac_filter.bpf.c:29-45** (covers both decl and bump_stat).

## Critical findings (after validation)

_None._

## High findings (after validation)

### [HIGH] H1 — Stale pin directory with no attached prog is unrecoverable through the tool
- **Dimension**: architecture | **Location**: `src/loader/loader.cpp:149-169` (attach probe) + `loader.cpp:239-263` (detach) | **cross_validated: partially (touches §5.4 region also flagged by security and testing)**
- **Verified**: Read confirmed both branches require `existing != 0` AND `pin_dir exists` — the 4th state (prog NOT attached + bpffs dir PRESENT, e.g. post-SIGKILL between dir-create and xdp-attach) falls through to fresh-attach, then libbpf trips `-EEXIST` on the pre-pinned maps → `LoadFailed` with cryptic `"File exists"`. Symmetrically detach refuses because `prog_id == 0`. Only recovery: `sudo rm -rf /sys/fs/bpf/xdpmacfilter/<iface>` — undocumented in `--help`/§5.4.
- **Impact**: A single SIGKILL or OOM mid-attach leaves the user stuck without using the tool. Operationally rare but real; undermines the §5.4 promise that "our own prior instance is auto-cleaned".
- **Fix**: Either treat `existing == 0 && pin_dir_exists` as "stale ours" in `attach()` (option a), or let `detach()` clean an orphan dir without erroring (option b). Update §5.4 from a 3-state to a 4-state machine. ~10 LOC + one test extension.

### [HIGH] H2 — `stats` map is shared (non-PERCPU) with non-atomic `*v += 1` — counter loss + cache-line ping-pong under concurrent traffic
- **Dimension**: performance | **Location**: `src/bpf/mac_filter.bpf.c:29-45` | **cross_validated: 3 (perf HIGH, security LOW#3, architecture INFO)** — all three reviewers found this, all three correctly noted §5.3 sanctions it for MVP-1.
- **Verified**: Read confirmed `BPF_MAP_TYPE_ARRAY` (not PERCPU), `__uint(max_entries, STAT_MAX)` (3 u64s in one cache line), `*v += 1` (no `__sync_fetch_and_add`, no `LOCK` prefix).
- **Impact** (perf reviewer's quantitative model): at 1 Mpps × 16-CPU contending `STAT_PASS`, expected counter loss ~30–70%; cache-line bouncing adds ~80–150 cycles/pkt vs PERCPU. Translated to throughput: ~5–15% regression at the bump_stat call. Security reviewer's reframe: counters are **observability-grade, not forensic-grade** — anyone using them as an audit signal will see undercounts. Architecture reviewer notes this is the cross-cutting concurrency contract for the whole MVP.
- **Note on severity dissent**: perf calls this HIGH; security calls it LOW (different impact framing); architecture calls it INFO (design-sanctioned). **My call: HIGH** — the design sanction makes this an MVP-1 trade-off, not an MVP-1 defect, BUT the cross-validation count is 3 and the quantitative impact at any real load is large; this is the single most-important MVP-2 work item even if it's intentionally deferred.
- **Fix**: Switch to `BPF_MAP_TYPE_PERCPU_ARRAY`; sum CPUs in `tests/lib/read_stats.py` (~30 LOC). Eliminates both pathologies at zero hot-path cost (PERCPU lookups are also verifier-inlined). Already on MVP-2 roadmap per design.

### [HIGH] H3 — No ASAN/UBSAN/TSAN build target — userspace memory-safety untested
- **Dimension**: testing | **Location**: `CMakeLists.txt:1-77` | **cross_validated: no**
- **Verified**: Read confirmed only `RelWithDebInfo` build type, only `-Wall -Wextra -Wpedantic -Wconversion -Wshadow -fno-strict-aliasing -Werror` flags; zero `-fsanitize`/`ASAN`/`UBSAN`/`TSAN`/`Sanitizer` mentions anywhere in the tree.
- **Impact**: The C++23 loader has nontrivial ownership (move-only RAII × 3, `std::filesystem::remove_all` on rollback paths, hand-rolled MAC tokenizer with pointer-style indexing). Any UB / use-after-free / leak is invisible to the current ctest suite (which only inspects exit codes + BPF map counters). Lang-pack guidance flagged sanitizer build as a focus area; this is pure omission, not design-fenced.
- **Fix**: Add CMake option `XDPMF_SANITIZERS=ON` injecting `-fsanitize=address,undefined -fno-omit-frame-pointer` to C++ targets only (libbpf is plain C and unaffected). Add a `T_SANITIZER_BUILD` ctest entry re-running existing T_LOAD_ATTACH+T_PASS_ALLOWED scenarios. ~+8s ctest runtime.

### [HIGH] H4 — design.md §2 FileList enumerates RAII class names and a loader API symbol that don't exist in code
- **Dimension**: documentation | **Location**: `mint/design.md:28` (raii row) + `mint/design.md:31` (loader.hpp row) | **cross_validated: no — explicitly missed by mint/review.md triangulation**
- **Verified**: Read confirmed design.md:28 says `BpfObject, BpfMap (non-owning view), XdpAttachment, BpffsDir`, while `raii.hpp:29` declares `BpfSkeleton`, `:74` `XdpAttachment`, `:125` `BpffsDir` — no `BpfObject`, no `BpfMap`. design.md:31 advertises `populate_allowlist()` but `loader.hpp:42,47` exports only `attach`/`detach` — the allow-list is populated inline in `loader.cpp:205-213`.
- **Impact**: A new contributor reading §2 (the authoritative FileList that HANDOFF.md and source comments cross-reference) for orientation will grep-hunt for nonexistent symbols. Same class of drift the §5.15/§5.16 amendments fixed for other items — there's an established pattern.
- **Fix**: Add §5.17 amendment noting (a) `raii.hpp` wrappers are `BpfSkeleton`/`XdpAttachment`/`BpffsDir` (BpfObject/BpfMap were superseded when impl adopted the bpftool skeleton); (b) `populate_allowlist()` is implemented inline in `attach()`, not exposed as a separate API. ~5 lines.

### [HIGH] H5 — No README / install / quickstart — first-contact friction
- **Dimension**: documentation | **Location**: repo root (no `README*`, no `INSTALL*`, no `doc/`; only top-level .md is `HANDOFF.md` which is meta about a sibling repo) | **cross_validated: no** | **Severity dissent**: doc reviewer self-downgraded from Critical to High citing MVP-sanctioned doc minimum. **My call: HIGH** — agreement with the reviewer; the brief explicitly says MVP-stage doc minimum, so this is friction-not-failure.
- **Impact** (top-3 first-contact frustrations per doc reviewer's framework table): "what is this?" / "how do I build it?" / "what do I need installed?" — `libc++-19-dev` is buried in `mint/impl-notes.md:26-35` and isn't in the brief's Dependencies; `python3`/`scapy`/`jq`/`sudo`/`iproute2` are nowhere user-facing.
- **Fix**: ~40-line README at repo root with what/build/run/test/where-docs-live sections. Closes 4 of doc reviewer's 6 Top-N frustrations in one pass.

## Synthesized findings (kill-chain elevations)

### [HIGH-SYNTH] KC-A — Spoofed-ours network blackhole DoS (security M1 + L1 + design §5.7)
- **Severity in single-root threat model**: Medium; **in multi-tenant/container-shared-bpffs/multi-daemon root threat model**: HIGH (security reviewer's call, supported here).
- **Components**: security M1 (TOCTOU on §5.4 marker, `loader.cpp:149-169`) + security L1 (implicit iface-name validation via `if_nametoindex`) + design §5.7 (empty allow-list = drop all).
- **Chain**: attacker with CAP_SYS_ADMIN-on-bpffs plants `/sys/fs/bpf/xdpmacfilter/<victim_iface>/` → admin (or config-mgmt agent) runs `xdpmacfilter attach --iface <victim_iface>` for routine reason → loader sees pin_dir → treats existing XDP as "ours" → `bpf_xdp_detach` of legitimate XDP (e.g. Cilium pod-network filter) → xdpmacfilter attached with empty allow-list (default drop-all) → all RX on victim iface dropped → network blackhole / lateral movement enabled.
- **Fix** (closes whole chain): verify pinned object identity via `bpf_prog_get_info_by_fd` → check `info.name == "mac_filter_prog"` AND tag matches the freshly-built `mac_filter.bpf.o` tag (in the skeleton). Spoofing then requires actually attaching a copy of our program — privilege-flat. Cheaper alternative: verify map names/types/sizes match the skeleton's expected layout before deciding "ours".

### [MEDIUM-SYNTH] KC-B — Mode-mismatch exit-code spoofing (security M2)
- Already worked out in security report; my contribution is just renaming and adopting. `bpf_xdp_query_id(…, XDP_FLAGS_SKB_MODE, …)` only sees SKB-mode programs; native-mode alien XDP causes loader to emit exit 3 (AttachFailed, "generic load problem") instead of exit 4 (AttachRefusedAlien). Audit greps for code 4 are blinded against native-mode alien. Kernel itself still blocks the second attach so data plane stays safe — this is **detection-layer** failure, not data-plane failure.
- **Fix**: query with `flags=0` (or union all three modes); if non-zero result is in a mode ≠ ours, unambiguously alien — exit 4 regardless of pin_dir state. Also tightens KC-A.

## Cross-cutting themes (≥2 reviewers independently — highest confidence)

| Theme | Dimensions flagging | Cross-validated count | Net severity | Disposition |
|---|---|---|---|---|
| `stats` shared/non-atomic | perf HIGH + security LOW + arch INFO | **3** | HIGH (design-sanctioned but cross-validated) | MVP-2: PERCPU |
| §5.4 ownership marker is the load-bearing trust boundary | sec M1+M2 (TOCTOU+mode bypass) + arch HIGH (stale pin lifecycle) + testing M1 (alien-refusal untested) | **3 (different facets)** | HIGH (compound) | Address the marker (identity verification) AND add stale-pin recovery AND add alien-refusal test |
| SKB-mode hardcoded | perf M (throughput) + security M2 (alien detection bypass) | **2** | MEDIUM | Add `--mode {generic,native,offload}` (default generic for compat) |
| Bpffs root path duplicated (C++ macro vs bash literal) | arch LOW + doc MEDIUM + archaeology obs#8 | **3** (2 reviewers + archaeology) | LOW→MEDIUM | Annotate `common.sh:25` as source-of-truth-mirror; CMake-time generation for MVP-2 |
| `--help`/`--version` untested | testing LOW + mint/review.md prior INFO | **2** | LOW | 6-line `T_CLI_HELP_VERSION` |

## Kill chains / compound issues

| ID | Components | Compound severity | Status |
|---|---|---|---|
| KC-A | security M1 (TOCTOU) + L1 (implicit iface validation) + design §5.7 (empty allow = drop all) | HIGH (multi-tenant root) | Synthesized above; closes by identity-verifying the pinned object, not the directory |
| KC-B | security M2 (SKB-only query) | MEDIUM | Synthesized above; closes by querying all XDP modes |
| KC-C | security L2 (create_directories follows symlinks) + M1 (ownership marker) | LOW→MEDIUM in container-escape | Synthesized in security report; closes by openat+O_NOFOLLOW from a root fd |
| KC-D **(NEW)** | arch HIGH (stale pin dir, no recovery via tool) + testing M1 (alien-refusal untested) + the lack of doc on manual recovery (`rm -rf /sys/fs/bpf/xdpmacfilter/<iface>`) | MEDIUM (operational footgun) | First time identified at synthesis layer: the same trust-boundary code region that produces KC-A also produces an operator-stuck state, *and* the recovery procedure is undocumented. Combined fix: 4-state §5.4 + document recovery in `--help` exit-code table + add T_ALIEN_REFUSAL ctest. |

## Unique-per-reviewer findings

### Security — unique catches
- KC-A and KC-B kill-chain synthesis (TOCTOU + SKB-only mode query); no other dimension threat-modelled this combination.
- L4 `LOADER` env var in tests honored without validation, then run under `sudo` — test-time priv-esc channel; not in other reports.
- L2 `create_directories` follows symlinks on intermediate path components.

### Architecture — unique catches
- M1 backwards layering: `loader.hpp` includes `cli.hpp` for `AttachConfig` (verified loader.hpp:17). Pure architectural debt; perf/sec/testing didn't flag because it's not a behavior issue.
- M2 doc-vs-code drift in `raii.hpp:120-124` — comment references a `BpffsDir::create()` method that doesn't exist. Cohesion/header-hygiene class; doc reviewer's tagging was on design.md drift, not header-comment drift.
- L1 `enum mac_filter_stat` underlying type vs `__u32` BPF map key — latent ABI mismatch.
- L4 `detach()` refuses when pin dir is missing even if attached prog is provably ours. Conservative-by-design rule from §5.4 surfaced.

### Performance — unique catches
- M3 `consume_flag_value` string allocation churn (cli.cpp:134-158) — 2-3 heap strings per CLI flag.
- L1 `bpffs_dir_for` rebuilds same string 3×/attach, 2×/detach.
- L3 fixture `sleep 0.5` × 6 tests = ~3s wasted ctest runtime (~11%).
- Quantitative throughput model for stats PERCPU and SKB→native (numeric before/after table).

### Testing — unique catches
- HIGH no sanitizer build (covered above).
- M3 sleep-based synchronization throughout tests — 11 fixed-sleep calls; flake risk on loaded CI.
- M4 host-scope `veth_a`/`veth_b` collision with real interfaces (also touched by archaeology obs#13).
- M5 T_DROP_MALFORMED SKIP path logs but doesn't assert slot-2 readability per design §6.5.
- M6 `prog_count` baseline-vs-final is host-global → racy with concurrent BPF activity / kernel GC.
- M7 no kernel-version compatibility matrix / runtime probe.
- M8 passwordless-sudo assumption — non-`sudo -n` invocation hangs to 60s timeout.

### Documentation — unique catches
- HIGH §2 FileList drift (covered above — missed by mint/review.md).
- M2 `libc++-19-dev` hard requirement buried in impl-notes only.
- M3 `inject_runt.py` docstring contradicts inline comment AND actual bytes (`02:00:00:00:00:99` vs `02:00:00:00:00:00`) — verified.
- M4 HANDOFF.md is meta-narrative about sibling repo, not project entry point.
- M5 `pkg_check_modules(libbpf)` missing `>=1.1` version qualifier (could also be Arch finding).
- L1 `mint/test-run.log` is `.gitignore`d but committed.
- L2 usage_text exit-code legend doesn't explain how to recover from code 4.
- L3 no CHANGELOG.

## Disagreements

| Issue | Reviewer A | Reviewer B | My call | Reason |
|---|---|---|---|---|
| `stats` non-atomic counter | perf HIGH (throughput + correctness at load) | security LOW (observability-grade caveat), architecture INFO (design-sanctioned) | **HIGH** | Cross-validation count of 3 + perf's quantitative model. Design sanction makes this an MVP-1 *trade-off*, not an MVP-1 *defect* — but tagging at HIGH makes it visible in the MVP-2 backlog where it belongs. Both lower opinions are preserved as alternate framings (audit-grade and arch-contract). |
| No README | doc HIGH (self-downgraded from Critical) | — | **HIGH** | Agreement; brief's "MVP-stage doc minimum" justifies keeping at HIGH rather than CRITICAL. |
| §5.4 ownership marker | sec MEDIUM (TOCTOU framing) | arch HIGH (lifecycle framing), testing MEDIUM (coverage) | **HIGH** as compound (KC-D + KC-A) | The same code region is the load-bearing trust boundary AND has a recoverability gap AND is untested. Synthesizing rather than picking one. |
| `parse_allow_token` dedup O(n²) | perf LOW (acceptable at N=64) | — | **LOW** | No dissent; preserved as-is. Worth raising only if MVP-2 raises `XDPMF_ALLOWLIST_MAX`. |
| SKB-mode hardcoded | perf MEDIUM (throughput) | sec MEDIUM (alien-detection bypass) | **MEDIUM** (both lenses preserved) | Two genuinely different impacts of the same line (`loader.cpp:45`). Not really disagreement — complementary findings. |

## Top actionable list (priority order)

| # | Title | Source | Effort | Blocking MVP-1? |
|---|---|---|---|---|
| 1 | Add `§5.17` amendment fixing design.md §2 FileList drift (BpfObject→BpfSkeleton, drop `BpfMap`, note inline `populate_allowlist`) | doc HIGH (unique) | ~5 LOC in design.md | No — cheap win, same pattern as §5.15/§5.16 |
| 2 | Add ~40-line `README.md` (what/build/run/test/where-docs-live) + add `libc++-19-dev` + python3/scapy/jq/sudo/iproute2 to deps | doc HIGH + 3 doc Mediums | ~40 LOC + brief edit | No — first-contact friction, expected MVP-2 work |
| 3 | Add CMake `XDPMF_SANITIZERS=ON` option + `T_SANITIZER_BUILD` ctest entry | testing HIGH (unique) | ~20 LOC CMake + ~15 LOC ctest | No |
| 4 | Fix §5.4 4th state in `attach()`: treat `existing==0 && pin_dir_exists` as "stale ours" → bpffs_remove_iface → fresh attach. Mirror in `detach()`. Update §5.4 to 4-state machine. | arch HIGH (cross-validates with sec M1 + testing M1) | ~10 LOC + 1 test extension + design edit | No — but operational footgun |
| 5 | Strengthen §5.4 ownership marker: verify pinned object identity via `bpf_prog_get_info_by_fd` (name+tag) instead of directory presence. Closes KC-A. | sec M1 synth + KC-A | ~30 LOC | No — but threat-model gap for multi-tenant deployments |
| 6 | Query `bpf_xdp_query_id` with `flags=0` (all modes) instead of `SKB_MODE` only. Closes KC-B. | sec M2 + KC-B | ~5 LOC | No |
| 7 | Switch `stats` map to `BPF_MAP_TYPE_PERCPU_ARRAY`; update `read_stats.py` to sum CPUs | perf HIGH (cross_validated:3) | ~30 LOC | No — explicit MVP-2 |
| 8 | Add `--mode {generic,native,offload}` CLI flag (default generic for compat) | perf M + sec M2 | ~30 LOC in cli.cpp + map in loader.cpp | No |
| 9 | Implement design §6.6 alien-refusal sub-variant (`T_ATTACH_ALIEN_REFUSAL`) | testing M1 + KC-D | ~30 LOC bash + tiny xdp-pass.o builder | No — design marked OPTIONAL |
| 10 | Fix `inject_runt.py` docstring to match actual bytes (`02:00:00:00:00:00`, not `:99`); rewrite "first 6 bytes plus partial 7th" claim to match 13-byte send | doc M3 (verified contradiction) | ~5 LOC docstring | No — but invitation for someone to "fix" the wrong file |
| 11 | Replace `sudo` with `sudo -n` throughout tests + early preflight that exits 77 if passwordless-sudo unavailable | testing M8 | ~10 LOC | No |
| 12 | Replace fixed `sleep 0.3` post-inject with `wait_for_stats_sum` poll helper | testing M3 | ~15 LOC | No |
| 13 | Move `AttachConfig`/`DetachConfig` from `cli.hpp` to `loader.hpp` (fixes backwards layering) | arch M1 | ~10 LOC | No |
| 14 | Add `>=1.1` qualifier to `pkg_check_modules(LIBBPF …)` | doc M5 | 1-token edit | No |
| 15 | Annotate `tests/lib/common.sh:25 PIN_ROOT` as mirror-of `XDPMF_BPFFS_ROOT` (or CMake-generate in MVP-2) | arch L3 + doc M6 + archaeology obs#8 | ~1 comment | No |

Items 1-3 are the highest-value quick wins (≤1 day total). Items 4-9 are MVP-2-scoped trust-boundary and observability work. Items 10-15 are polish.

## Coverage manifest

- **files_reread** (for High citation validation, with full paths):
  - `/home/user/mint-l2-mac-filter/src/loader/loader.cpp` (offsets 40-50, 97-107, 144-173, 235-264)
  - `/home/user/mint-l2-mac-filter/src/bpf/mac_filter.bpf.c` (offset 25-49)
  - `/home/user/mint-l2-mac-filter/CMakeLists.txt` (full, 77 lines)
  - `/home/user/mint-l2-mac-filter/mint/design.md` (offset 23-37 — §2 FileList region)
  - `/home/user/mint-l2-mac-filter/src/loader/raii.hpp` (offsets 25-39, 115-129)
  - `/home/user/mint-l2-mac-filter/src/loader/loader.hpp` (offset 12-22, 37-47)
  - `/home/user/mint-l2-mac-filter/tests/inject/inject_runt.py` (offset 11-45, multi-line evidence widening applied)

- **raw_reviewer_files_consumed**:
  - `/home/user/agent-teams-review/runs/hybrid-mint-l2-mac-filter-202605222203/archaeology.md`
  - `/home/user/agent-teams-review/runs/hybrid-mint-l2-mac-filter-202605222203/raw/security-reviewer.md`
  - `/home/user/agent-teams-review/runs/hybrid-mint-l2-mac-filter-202605222203/raw/architecture-reviewer.md`
  - `/home/user/agent-teams-review/runs/hybrid-mint-l2-mac-filter-202605222203/raw/performance-reviewer.md`
  - `/home/user/agent-teams-review/runs/hybrid-mint-l2-mac-filter-202605222203/raw/testing-reviewer.md`
  - `/home/user/agent-teams-review/runs/hybrid-mint-l2-mac-filter-202605222203/raw/documentation-reviewer.md`

- **citations_validated**: 11 (all 5 High citations + 6 cross-validated Medium spot-checks: security M1 + M2, architecture M2, documentation M3 + M5 + arch M1)
- **citations_unverified**: 0
- **citations_normalized**: 2 (§5.4 region → `loader.cpp:149-169`; stats non-atomic → `mac_filter.bpf.c:29-45`)
- **tool_calls_made**: 14 (1 TaskList, 1 TaskUpdate at start, 10 Reads — 5 upstream files + 5 validation passes that included multi-Read batches, 1 final TaskUpdate after this SendMessage, this SendMessage = 14th)
- **time_spent_minutes**: ~14
- **confidence_in_completeness**: **high** — all 5 reviewer files read end-to-end; every High citation re-Read at cited offset and evidence confirmed; cross-validation count tallied against archaeology themes; 3 kill-chains synthesized (1 promoted to HIGH, 2 maintained at MEDIUM/LOW per security reviewer's original framing) plus 1 new KC-D identified at synthesis layer.
- **validation_method**: "Each High citation re-read from source file with ±5 to ±15-line window via Read(offset, limit); multi-line evidence widening applied for inject_runt.py docstring-vs-code span."
- **residual_uncertainty**:
  - LOW findings are trusted as cited (per spec — only Critical/High require re-Read validation). Spot-checks on a handful of Mediums all confirmed; no demotions needed.
  - Runtime-only behaviors not validated: perf reviewer's PERCPU/SKB throughput numbers come from a quantitative model, not from this team measuring (~80–150 cycles/pkt cache bounce, 5–10 Mpps generic vs 30–80 Mpps native); accepted as plausible.
  - Architecture reviewer's HIGH (-EEXIST behavior on pre-pinned map) wasn't reproduced live in this synthesis; conclusion holds regardless of exact strerror, but the specific error string the user sees is unverified.
  - libbpf version behavior of `bpf_xdp_query_id(…, flags=0, …)` returning all modes is assumed from libbpf docs; if it actually requires a different incantation, sec M2 fix needs adjustment.
  - I noted but did not file a possible additional MEDIUM during validation: `loader.hpp:17 #include "cli.hpp"  // AttachConfig` is the exact backwards-layering edge arch reviewer flagged — verified in-passing; nothing new.

— synthesizer
