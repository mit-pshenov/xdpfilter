# Review — MVP-4.15 S6 IPv6 ext-header walk (mint triangulation)

## Verdict
`pass` — round-1, 5-point brownfield triangulation, 0 findings, 0 OOT. Reviewer independently re-ran `sudo ctest -j4` (95/95, 93 pass + 2 pre-existing env skips) + verifier-loaded the prod `build/mac_filter.bpf.o` via `bpftool prog loadall` (rc=0 on 6.1). Baseline `ca67ce4`. FS-lag did not impede this round.

## Triangulation matrix
| Framework point | Findings | Tags |
|---|---|---|
| 1. Spec ↔ Code | 0 | — |
| 2. Spec ↔ Tests | 0 | — |
| 3. Code ↔ Tests | 0 | — |
| 4. Out-of-Scope Drift | 0 | — |
| 5. Behaviour preserved (brownfield) | 0 | — |

## Load-bearing facts (reviewer-verified, file:line + git ground-truth)
- **Bounded walk (the sharp edge)**: fixed `#pragma unroll for (i<MAX_EXT_HOPS=8)`, NO back-edge/unbounded loop; per-hop bounds-check before each deref (HOPOPTS/ROUTING/DSTOPTS via `(hdrlen+1)*8`, FRAGMENT fixed 8B, `else: break`). Prod .bpf.o verifier-loads rc=0 on 6.1 (PI-mvp-4.15-BOUNDED; spike 26548/1M, impl 25151, all <512 stack). guard #28 PI carries the numbers.
- **VA-5 detectability genuinely armed**: T_ANDEXT_WALK_STEER ext frame carries ipv6.nh=HOPOPTS(0) → a non-walking datapath reads proto=0 → NOMATCH → RED. W1 ext→DROP (walk-reach proof), W2 non-ext→DROP identical (walk-transparency), W3 ext-wrong-port→PASS (negation). Oracle walk-transparent (keys true L4) → algorithm-different, NOT circular.
- **v4 arm BYTE-IDENTICAL**: `git diff ca67ce4 -- src/bpf/mac_filter.bpf.c` = exactly 2 hunks (ext-proto defines + v6 arm), ZERO v4 lines (PI-mvp-4.15-IPV4-BYTE). Non-ext v6 verdict-identity: T_ANDV6_*/T_IPV6_* net GREEN (walk no-op at hop 0).
- **truncated chain → DROP_MALFORMED** (#95, --truncate 28, MALFORMED Δ==1, no PASS/DENY leak, no OOB). Q2 cap fail-safe: residual ext proto ≠ TCP/UDP → has_port=0 auto, no post-loop check.
- **PI-7 loader.hpp byte-identical** + loader.cpp/config/mac_filter.h/sidecar 0-diff; BITVEC_NUM_AXES=9, kManagedMaps=39 unchanged (no axis growth — pure datapath read-depth); VERSION 0.15.0 no bump.

## Out-of-triangulation findings
None.

## Reviewer's full review (verbatim)
(5-point matrix all-0; point-by-point file:line evidence — see structured report. Bounded MAX_HOPS=8 unroll no-back-edge, VA-5 trap armed, v4 byte-identical, non-ext verdict-identity, truncated→MALFORMED, PI-7 zero-diff, prod .bpf.o rc=0, all independently verified incl. git-diff vs ca67ce4 + bpftool loadall.)

**Verdict: pass.** The ladder's last sharp edge — bounded ext-header walk to true L4, loads with margin, v4 byte-identical, VA-5 detectability genuinely armed; 95/95; round-1. **L2/L3 gate ladder S1→S6 COMPLETE.**
