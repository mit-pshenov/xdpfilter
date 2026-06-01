# `mint/` — design corpus index

This directory is the design + process record for `xdpmacfilter`, produced
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
| `review.md`, `hybrid-review.md` | mint-review triangulation + early external review reports. |

## Design briefs (`design-brief-*.md`)

Inputs to `/mint-hld` design rounds — the question framing for a design
exploration, not the outcome. `design-brief.md` (original), then
`-architecture-v2`, `-l2l3-gate`, `-l2l3-gate-v2`, `-mvp3.4-counters`,
`-s4-cidr6`. The *outcome* of each lands back in `design.md`.

## Task briefs (`task-brief-mvp*.md`)

One brief per `/mint-dev` slice, in roughly chronological order. The
current one is symlinked/copied as `task-brief.md`; the rest are historical.
Read `CHANGELOG.md` (repo root) for the per-version narrative of what each
slice shipped — it is the better chronological index of *outcomes*.

Rough timeline:

- **MVP-1.x** (`task-brief-mvp1.md`, `-mvp1.1a/b/c`) — L2 MAC allow-list bootstrap.
- **MVP-2.x** (`-mvp2-sec`, `-robust`, `-perf`, `-polish2`) — security, robustness, attach modes.
- **MVP-3.x** (`-mvp3.1` … `-mvp3.5.5`) — config harness, counters, exporter, fleet/Ansible.
- **MVP-4.x** (`-mvp-4.1` … `-mvp-4.21`) — the rule model: OR→AND, the 9 match axes, IPv6, EtherType, slot/id decouple.

> History note: the archived first-session handoff lives at
> `docs/history/HANDOFF-mvp1.md`. The `mint/` agent definitions and packs
> referenced by old briefs live globally under `~/.claude/agents/mint/`.
