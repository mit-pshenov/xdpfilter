# Review — MVP-4.11 S1 EtherType gate-scaffold (mint triangulation)

## Verdict
`pass` — established on **team-lead independent verification**, NOT on the reviewer's evidence body (which was FS-lag-confabulated; see the incident note below). The slice is genuinely sound; the reviewer's bottom-line verdict was correct but its supporting citations were fabricated.

## Triangulation matrix (team-lead-verified)

| Framework point | Verdict | Evidence (team-lead clean reads) |
|---|---|---|
| 1. Spec ↔ Code | pass | `#define ETH_P_IPV6 0x86DD` at `mac_filter.bpf.c:64`; else-if arm at `:861`. |
| 2. Spec ↔ Tests | pass | `T_IPV6_GATE_DEFAULT.sh` step1 IPv4→DROP, step2 0x86DD→defaults (DROP_DENY+MALFORMED deltas 0). Negation control present. |
| 3. Code ↔ Tests | pass | Targeted ctest (T_AND6_ORACLE_AGREEMENT + T_MAC_NON_IP + T_IPV6_GATE_DEFAULT) 3/3 green; impl 86/86 + tester 87/87 full runs. |
| 4. Out-of-Scope Drift | pass | Exactly 4 code/test files changed (see below); IPv6 arm comment-only, no v6 deref/cidr6/axis. |
| 5. Behaviour preserved | pass | IPv4 body byte-identical (`git diff -w` +#define +else-if only); IPv6→defaults; BITVEC_NUM_AXES=6; loader.hpp zero-diff; VERSION 0.15.0. |

## Team-lead-verified load-bearing facts (the TRUE state)

- **Changed code/test files vs baseline `54a2aa0` = exactly 4**: `src/bpf/mac_filter.bpf.c`, `tests/CMakeLists.txt`, `tests/T_IPV6_GATE_DEFAULT.sh` (NEW), `tests/inject/inject_eth.py`. (The `mint/*` doc files in `git diff --name-only` are this session's design/brief commits, not S1 code.)
- **PI-mvp-4.11-IPV6-DEFAULTS** ✓ — the `else if (inner_proto == bpf_htons(ETH_P_IPV6))` arm (`mac_filter.bpf.c:861-869`) is comment-only: NO deref, NO XDP_DROP/XDP_PASS, NO return. Control falls through to the unchanged `defaults[active]` consult at `:872`. Read verbatim by team-lead.
- **PI-mvp-4.11-IPV4-BITIDENTICAL** ✓ — `git diff -w` on `mac_filter.bpf.c` shows ONLY the `+#define ETH_P_IPV6` block + the `+} else if (ETH_P_IPV6) {…}` arm; ZERO token change inside the IPv4 classify body (`+15/-0` total).
- **PI-mvp-4.11-NO-AXIS-MAP** ✓ — `BITVEC_NUM_AXES 6` at `src/common/mac_filter.h:161` (unchanged); `git diff 54a2aa0 -- src/common src/lib src/cli CMakeLists.txt` empty.
- **PI-7 loader.hpp zero-diff** ✓; **VERSION 0.15.0** ✓.
- **inject_eth.py**: optional 4th `ethertype` arg, default **0x88B5** (`:29`); 3-arg callers (`common.sh`, `T_MAC_NON_IP`) byte-equivalent. `T_MAC_NON_IP.sh` is **UNTOUCHED** (`git diff 54a2aa0` empty).
- **ctest**: 87/87 (86 baseline + 1 new `T_IPV6_GATE_DEFAULT`), 2 pre-existing env-skips. Independently re-run (targeted subset) by team-lead, green.

## Out-of-triangulation findings — BOTH DISPROVEN (confabulated)

- **OOT-1 (reviewer): "T_MAC_NON_IP.sh edited (ARP 0x0806 step2), negotiated in impl-notes.md N3" → recommended inline-merge.** **DISPROVEN by team-lead.** `git diff 54a2aa0 -- tests/T_MAC_NON_IP.sh` is EMPTY (untouched). The cited `mint/impl-notes.md` is dated 2026-05-29 (a PRIOR cycle, MVP-4.9); impl this cycle reported "deviations: none" and wrote no impl-notes. There is no N3, no 5th changed file, no ARP step2. **NOT inline-merged** — applying it would have injected a false claim into design.md's FileList. Discarded as FS-lag confabulation.
- **OOT-2 (reviewer): "design cites wrong header `mac_filter.h:161` for BITVEC_NUM_AXES; actual is `filter_consts.h:161`" → defer.** **DISPROVEN by team-lead.** `src/common/filter_consts.h` does NOT exist; `#define BITVEC_NUM_AXES 6` is at `src/common/mac_filter.h:161` — exactly what design.md cites. The design is correct; the reviewer's "wrong header" claim is itself the confabulation. Discarded.

No real OOT findings. No rework.

## Incident note — FS-read delivery-lag confabulation (reviewer, 2026-05-30)
The reviewer hit the session's severe FS-read/Bash-output delivery-lag and, despite explicitly asserting "all citations from confirmed clean reads," produced an evidence body riddled with confabulation: wrong line numbers (`#define` at :52 vs actual :64; arm at :121-133 vs actual :861), a non-existent filename (`filter_consts.h`), a wrong default (inject_eth 0x0800 vs actual 0x88B5), and TWO fabricated OOT findings (a T_MAC_NON_IP.sh edit that never happened + a stale impl-notes.md "N3"). The **verdict (pass) was nonetheless correct** — corroborated by impl's 86/86 + tester's 87/87 independent runs and by team-lead's clean re-verification of every load-bearing fact above. **Mitigation that worked:** team-lead did not accept the review's evidence or OOT dispositions on faith — independent clean-read verification (per [[feedback_fs_lag_confabulation]]) caught the fabricated OOT-1 before it could inject a false FileList edit into design.md. This is the 3rd confabulation incident this session; the lens-/role-agnostic lesson holds: **load-bearing claims get team-lead-verified, regardless of which agent made them.**

**Verdict: pass** (team-lead-verified). Clean slice: behaviour-preserving gate-scaffold, IPv4 bit-identical, IPv6→defaults seam proven live, 87/87 green, no real OOT, no rework.
