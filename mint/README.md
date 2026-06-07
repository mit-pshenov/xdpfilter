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

## Standing reference + design-round inputs

Per-topic design material is discoverable by glob rather than hand-listed
here — the prior enumerations drifted (disk carries more `architecture-*.md`
and `design-brief*.md` files than any list tracked):

- **`architecture-*.md`** — per-topic architecture deep-dives (the `-v2`
  baseline, plus the rule-model / l2l3-gate / loader-datamodel / dryrun /
  mirror-redirect reworks). Each captures the design state for one arc.
- **`design-brief*.md`** — one brief per `/mint-hld` design round: the
  *question framing* for an exploration, **not** the outcome. The outcome of
  each lands back in `design.md`.
- **`selection-scenarios.md`** — the traffic-selection scenarios catalog
  driving the rule model.
- **`perf.md`** — performance-envelope measurements (Tier-0
  `BPF_PROG_TEST_RUN` data, Tier-1 notes).

Two reference docs carry special lifecycle and are **not** interchangeable
glob boilerplate:

- **`review.md`** — current-slice mint-review verdict; **overwritten each
  `/mint-dev`**. Historical verdicts live in `CHANGELOG.md` + the `design.md`
  §5.x ledger, not here.
- **`hybrid-review.md`** — frozen MVP-1 hybrid review; **load-bearing** (cited
  by `tests/T_ATTACH_ALIEN_REFUSAL.sh`) — keep.

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
