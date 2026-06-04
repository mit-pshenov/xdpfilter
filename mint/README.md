# `mint/` — design corpus index

This directory is the design + process record for `xdpfilter`, produced
by the mint multi-agent dev workflow. It is **contributor documentation**;
operators want `README.md`, `docs/CONFIG_SCHEMA.md`, and
`docs/FLEET_DEPLOYMENT.md` instead.

## Start here

| File | What it is |
|---|---|
| **`design.md`** | **Single source of truth** — data structures, interfaces, decisions (`D-*`), invariants (`PI-*`), test strategy. The authoritative living document; everything else is supporting or historical. |
| `architecture-v2.md` | Architecture overview (the v2 baseline the rule model was built on). |
| `task-brief.md` | The currently-active task brief (latest MVP slice). |
| `impl-notes.md` | Implementation deviation log (e.g. the libc++/`<format>` C++23 dependency). |

## Standing reference docs

| File | What it is |
|---|---|
| `selection-scenarios.md` | The traffic-selection scenarios catalog driving the rule model. |
| `architecture-rule-model.md` | Architecture for the OR→AND rule-model shift. |
| `architecture-l2l3-gate.md` | Architecture for the L2/L3 gate ladder (the family-arm rework). |
| `perf.md` | Performance envelope measurements (Tier-0 BPF_PROG_TEST_RUN data, Tier-1 notes). |
| `review.md` | **Current-slice** mint-review verdict — per-cycle scratch, overwritten each `/mint-dev`. Historical verdicts live in `CHANGELOG.md` + the `design.md` §5.x ledger, not here. |
| `hybrid-review.md` | Frozen MVP-1 hybrid review (cross-lens kill-chain synthesis; cited by `tests/T_ATTACH_ALIEN_REFUSAL.sh` — load-bearing, keep). |

## Design briefs (`design-brief-*.md`)

Inputs to `/mint-hld` design rounds — the question framing for a design
exploration, not the outcome. `design-brief.md` (original), then
`-architecture-v2`, `-l2l3-gate`, `-l2l3-gate-v2`, `-mvp3.4-counters`,
`-s4-cidr6`. The *outcome* of each lands back in `design.md`.

## Task briefs (`task-brief-mvp*.md`)

One brief per `/mint-dev` slice, in roughly chronological order. The
currently-active brief is `task-brief.md` (a plain copy — `/mint-briefer`
archives the prior brief as `task-brief-mvp-<N>.md` before each overwrite);
the rest are historical.

**For the authoritative per-slice record read `CHANGELOG.md` (repo root)** —
it is the better, self-maintaining chronological index of *outcomes*, so this
file no longer hand-maintains a slice timeline. At a phase glance: MVP-1
L2-MAC bootstrap → MVP-2 security/robustness/attach-modes → MVP-3
config/counters/exporter/fleet → MVP-4 the 9-axis rule model + the tidiness
workstream.

> History note: the archived first-session handoff lives at
> `docs/history/HANDOFF-mvp1.md`. The `mint/` agent definitions and packs
> referenced by old briefs live globally under `~/.claude/agents/mint/`.
