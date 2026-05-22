# Session handoff — mint MVP-1

This is the first work session in `/home/user/mint-l2-mac-filter/`. The previous session (`/home/user/agent-teams-review/`) designed the mint multi-agent dev workflow; this session executes it.

## Read these first

1. **`mint/task-brief.md`** — what we're building.
2. **`~/.claude/agents/mint/`** — 4 generic agent definitions:
   - `architect.md` — produces design.md (single-shot + post-publication dialog)
   - `impl.md` — writes code per design
   - `tester.md` — writes tests per design's TestStrategy (two-phase turn)
   - `reviewer.md` — 4-point triangulation, has no Write/Edit (anti-bullshit gate)
3. **`~/.claude/agents/mint/packs/`** — language/testing knowledge:
   - `packs/lang/{cpp,bpf,cmake}.md`, `packs/test/bpf-xdp.md`

## First action this session

Write `~/.claude/commands/mint.md` (slash command orchestrator). It does NOT exist yet — design it against the brief at `mint/task-brief.md`.

Orchestration phases (sequential):

| Phase | Action |
|---|---|
| 0 | Parse args (`.` → current dir). Validate `<dir>/mint/task-brief.md` exists. Parse `Packs to load:` section. Verify cwd has `hasTrustDialogAccepted: true` in `~/.claude.json` (else pre-init). |
| 1 | `TeamCreate`. Spawn `mint-architect` with brief inlined + architect packs (may be empty). Wait for design.md via SendMessage. Show user, await approval. |
| 2 | Spawn `mint-impl` (with impl packs) and `mint-tester` (with tester packs) **in parallel**. Both work from `mint/design.md`. Tester goes idle after Phase A (tests written). |
| 3 | When impl SendMessages "build green / done", orchestrator SendMessages tester "go" → tester Phase B (run tests), reports results. |
| 4 | Spawn `mint-reviewer`. Read design + code + tests. Verdict: `pass` / `needs-rework`. |
| 5 | If `needs-rework`: re-spawn affected agents per review's assignments. Max 3 rounds. |
| 6 | Commit at each phase boundary (workflow B): `git -C <dir> commit -m "mint phase X: <summary>"`. |
| 7 | Shutdown agents, `TeamDelete`, summary to user. |

After writing the slash command, run it: `/mint .`

## Key constraints (lessons from past sessions)

- **`TeamCreate`, `Agent`, `SendMessage`, `TeamDelete` work only in main session** — subagents cannot spawn other agents. The `/mint` slash command IS the main session.
- **Agent Teams + tmux**: each subagent runs in its own tmux pane. Visibility is the feature — you can watch them work.
- **TaskCreate echo**: ~15-25s after a TaskCreate, the runtime auto-broadcasts a task_assignment notification. That's normal, not a duplicate.
- **Architect lifecycle**: stays `in_progress` after publishing design.md. Goes idle. Wakes on peer SendMessage from impl/tester for clarifications. TaskUpdate completed only when team-lead (you) signals "design phase closed".
- **Tester two-phase**: writes tests in Phase A (parallel with impl, no peek at src/), goes idle. Wakes when you SendMessage "go" after impl reports done. Runs tests in Phase B.
- **Reviewer is the anti-bullshit gate**: no Write/Edit by design. Reports findings, doesn't fix. Use 4-point triangulation framework strictly.

## Past sessions

- `/home/user/agent-teams-review/STATUS.md` — full story of hybrid review (5 selfies, ~6 sprints) + mint design discussions. **Do not re-read deeply** — the agents and packs in `~/.claude/agents/mint/` ARE the result. STATUS.md is archeology.
