# QUBIT — Core Prompts & Multi-Agent Workflow

> **This is the canonical home for (A) how the multi-agent workflow works, and (B) every prompt used to
> run it.** If you only open one file to understand or operate the agent system, open this one.
> Part A explains the *mechanism* (reusable — it's about coordination, not the project's subject matter).
> Part B holds the actual prompts you paste into agents.

---

# PART A — How multiple agents work together (the mechanism)

## A1. The problem this solves
No single AI agent has unlimited context or credits, and different agents are good at different things.
So the build is spread across several agents (Claude + Codex + Copilot + Gemini + Antigravity) that may
each be swapped in and out at any time. The challenge: **keep total continuity across switches without
(a) losing in-progress work, or (b) letting any agent corrupt the shared project.** The whole system
below exists to make that safe and seamless.

## A2. The shared brain = a set of Markdown files (agents have no shared memory otherwise)
Every agent starts cold. Its ONLY knowledge of the project is these files, so the files are the source of
truth and keeping them current is mandatory:

| File | Role |
|---|---|
| `PROJECT_PHASE_MEMORY.md` | Live state: constraints (§0), status (§2), next action (§4), and Claude's authoritative CHANGELOG (§5). **Start here.** |
| `CORE_PROMPTS.md` (this file) | The workflow mechanism + all prompts. |
| `AGENT_WORK_SPLIT.md` | Who does what, and the hard boundaries that protect the core. |
| `SUBAGENT_WORK_LOG.md` | Where non-Claude agents log their work (Claude verifies it). |
| `USER_PROMPTS_LOG.md` | Every human instruction, timestamped — the intent history. |
| `docs/BUILD_PLAN.md` + `docs/design/**` | The plan and the binding design (source of truth for WHAT to build). |

## A3. Roles
- **Claude = the ORCHESTRATOR.** It designs, owns the frozen core, integrates, reviews every sub-agent
  change, and has final say (keep / update / remove). Sub-agent work is *provisional* until Claude merges it.
- **Sub-agents (Codex / Copilot / Gemini / Antigravity) = scoped workers.** Each has a lane
  (`AGENT_WORK_SPLIT.md`), works on its own git branch, opens a PR, and never touches the core or the
  design docs or pushes to `main`.

## A4. The handoff loop (the actual workflow)
```
1. Human picks a task + the best agent for it (see AGENT_WORK_SPLIT.md §3 triggers).
2. Human pastes the RIGHT prompt as the agent's FIRST message:
      - fresh start / normal handoff  -> Universal Handoff Prompt      (B1)
      - agent was cut off mid-task     -> Sudden Credit-Out Prompt      (B3)
      - returning to Claude to review  -> Orchestrator Resume Prompt    (B2)
   (optionally follow with a scoped task using the Task Assignment template B4)
3. The agent bootstraps from the files, DECLARES its lane, and works on a branch.
4. The agent LOGS CONTINUOUSLY (see A5) — especially before it might run out of credits.
5. The agent commits to its branch / opens a PR. It does NOT merge to main.
6. Human returns to Claude and pastes the Orchestrator Resume Prompt (B2).
7. Claude reviews: boundaries + quality gate + semantic correctness -> KEEP / UPDATE / REMOVE,
   merges the good work, records the verdict, updates the state files.
8. Repeat.
```

## A5. The safety mechanisms (why nothing gets lost or broken)
1. **Boundaries** (`AGENT_WORK_SPLIT.md §0`): only Claude edits `packages/qubit-core/` (the frozen schema)
   and `docs/design/**`; sub-agents work in their lane, on a branch, PR-only to `main`.
2. **Quality gate before "done":** `uv run ruff check <pkg> && uv run mypy <pkg>/src && uv run pytest <pkg> -q`.
3. **Continuous, pre-cutoff logging:** log after every meaningful step; if you sense you're low on
   credits/context, write partial progress + the exact next step and commit BEFORE stopping. A cut-off
   with no log is the single worst failure — it's the one thing that breaks continuity.
4. **Real timestamps:** `date "+%Y-%m-%d %H:%M:%S %Z"` on every log entry.
5. **Orchestrator review = the merge gate:** sub-agent work only enters `main` after Claude verifies it.

## A6. Which prompt to use when (decision table)
| Situation | Prompt |
|---|---|
| Bringing any agent (incl. a fresh Claude) onto the project normally | **B1 Universal Handoff** |
| Returning to Claude to review + absorb what sub-agents did | **B2 Orchestrator Resume** |
| An agent died mid-task and may have left half-finished / unlogged work | **B3 Sudden Credit-Out Continuation** |
| Giving a sub-agent a specific scoped task (after B1) | **B4 Task Assignment (template)** |

---

# PART B — The prompt library

> Paste the whole fenced block. B1/B3 are pasted as the FIRST message to a switched agent; B2 is for
> Claude; B4 is an optional follow-up that scopes a concrete task.

## B1 — Universal Handoff Prompt (paste FIRST to any agent taking over)

```
You are helping build QUBIT, a production-ready open-source post-quantum cryptography migration
platform. I am the sole human builder; AI agents write most of the code and I review. You have NO prior
context — this project's memory lives in files. Get context from them before doing anything.

STEP 1 — READ THESE FILES IN ORDER (do not skip any):
1. project-phase-memory/PROJECT_PHASE_MEMORY.md   <- START HERE. Constraints (§0), current status (§2),
   next action (§4), and the CHANGELOG (§5, newest first) show exactly where the last agent stopped.
2. project-phase-memory/AGENT_WORK_SPLIT.md        <- which agent does what + the HARD boundaries.
3. project-phase-memory/CORE_PROMPTS.md            <- how the multi-agent workflow works + all prompts.
4. docs/BUILD_PLAN.md                              <- master plan + canonical cross-doc decisions (§4).
5. docs/design/00-architecture-frame.md            <- BINDING: stack, monorepo layout, CryptoAsset schema.
6. The specific docs/design/0X file for the subsystem you'll work on.

STEP 2 — IDENTIFY YOUR LANE:
State which agent you are (Claude / OpenAI Codex / GitHub Copilot / Google Gemini / Google Antigravity).
Find your assigned packages and BOUNDARIES in AGENT_WORK_SPLIT.md §0 + §2. You may ONLY work in your lane.
If you are NOT Claude: never edit packages/qubit-core/ (frozen schema), never edit docs/design/** or the
memory docs, work on your own git branch, and open a PR — never push to main.

HARD RULES (all agents):
- PRODUCTION-READY, not a demo/simulation. Nothing stubbed or faked "for the demo." (The one legitimate
  simulation is the CRQC-arrival risk timeline — see PROJECT_PHASE_MEMORY §0.)
- Solo, continuous build. Ignore the two-person "Student A/B" split + exam-break timeline in the design
  docs (university paperwork only).
- Conform to the BINDING frame (docs/design/00) + BUILD_PLAN §4 canonical decisions. If two docs
  disagree, BUILD_PLAN wins. The CryptoAsset schema in qubit-core is FROZEN (additive only, Claude only).
- Import from qubit_core; never redefine its models. Match doc 05's normative REST registry exactly.
- Quality gate before you call anything done:
  `uv run ruff check <pkg> && uv run mypy <pkg>/src && uv run pytest <pkg> -q`  (all green).
- Windows 11 (i7-14700HX / 16 GB / RTX 4060). Ollama runs natively on the GPU, not in Docker. Use
  `uv run ...` for everything (Python 3.12 is pinned by the workspace).

STEP 3 — DO THE WORK:
- Do the PROJECT_PHASE_MEMORY §4 "Next action", OR the specific task I give you — but first confirm it's
  inside your lane. If it isn't, tell me which agent should do it. If anything is ambiguous, ask ONE
  question, then proceed. Work in small, verifiable increments; run the quality gate after each.

STEP 4 — LOGGING IS MANDATORY AND CONTINUOUS:
- WHERE: Claude -> PROJECT_PHASE_MEMORY.md §5 CHANGELOG. Sub-agent -> SUBAGENT_WORK_LOG.md. Also append the
  task you were given to USER_PROMPTS_LOG.md. Real timestamps: `date "+%Y-%m-%d %H:%M:%S %Z"`.
- Log the moment you start; log after EVERY meaningful step; never have more than one unlogged step.
- If you're running low MID-TASK: write your partial progress + exact next step, commit, THEN stop.
- When finished: update §2 status + §4 "Next action".

Confirm you've read files 1–6, state which agent you are + your lane, the current phase, and the next
concrete action — then start.
```

## B2 — Orchestrator Resume Prompt (paste to CLAUDE when returning after sub-agents worked)

```
You are Claude, the ORCHESTRATOR of QUBIT. Sub-agents (Codex / Copilot / Gemini / Antigravity) may have
done work while I was away. Review it, decide keep / update / remove, then continue building.

1. READ: project-phase-memory/PROJECT_PHASE_MEMORY.md (§0 constraints, §5 changelog),
   SUBAGENT_WORK_LOG.md (what sub-agents say they did), AGENT_WORK_SPLIT.md (the boundaries),
   USER_PROMPTS_LOG.md (what I asked for), docs/BUILD_PLAN.md §4 (canonical decisions).
2. SEE WHAT ACTUALLY CHANGED: `git status`, `git branch -a`, `git log --oneline -15`, and for each
   sub-agent branch `git diff main...<branch> --stat` then read the important diffs.
3. VERIFY every sub-agent change against:
   - BOUNDARIES (AGENT_WORK_SPLIT §0): did it edit packages/qubit-core/ or docs/design/** or push to
     main? If yes -> suspect, scrutinize hard.
   - The FROZEN CryptoAsset schema + BUILD_PLAN §4 canonical decisions + the relevant docs/design/0X.
   - QUALITY GATE: `uv run ruff check <pkg> && uv run mypy <pkg>/src && uv run pytest <pkg> -q`.
   - SEMANTIC CORRECTNESS: does it actually do the right thing? (e.g. do scanner rules resolve to real
     algorithms with the correct quantum verdict? does an endpoint match doc 05's registry exactly?)
4. DECIDE per change — you have final say:
   - KEEP (verified good) -> merge the branch to main.
   - UPDATE (good idea, flawed execution) -> fix it, then merge.
   - REMOVE (breaks the core, deviates from the design, or lowers quality) -> revert/discard and, if the
     task still matters, redo it correctly or re-assign it.
5. Merge good work; fix or discard the rest; commit clearly; push.
6. LOG: write a KEEP/UPDATE/REMOVE verdict (with reason) on each SUBAGENT_WORK_LOG.md entry you reviewed;
   add a PROJECT_PHASE_MEMORY §5 changelog entry; update §2 status + §4 Next action; append this prompt
   to USER_PROMPTS_LOG.md with a timestamp (`date "+%Y-%m-%d %H:%M:%S %Z"`). Then continue the build.

State your review verdict on each sub-agent change before you continue.
```

## B3 — Sudden Credit-Out / Continuation Prompt (paste when an agent was cut off mid-task)

```
The previous agent may have run out of credits/context MID-TASK and stopped without finishing or logging.
Recover before doing anything new:

1. READ the newest entries in project-phase-memory/PROJECT_PHASE_MEMORY.md §5 and SUBAGENT_WORK_LOG.md —
   the last line usually says what was in progress and the intended next step. Also read AGENT_WORK_SPLIT.md
   (your lane) and, if you are Claude, CORE_PROMPTS.md B2 (you are the orchestrator).
2. FIND THE INTERRUPTED WORK: `git status` (uncommitted edits ARE the in-progress work), `git stash list`,
   `git diff`, `git log --oneline -8`. Note the current branch.
3. HEALTH CHECK: `uv run ruff check . ; uv run pytest -q`  (see what's green vs broken right now).
4. JUDGE the in-progress change:
   - Complete AND gate-green -> just finish logging + commit it.
   - Half-done -> complete it following the relevant docs/design/0X + BUILD_PLAN, then gate + commit.
   - Broken or unclear intent -> revert it (`git checkout -- <files>`) and redo cleanly from the design.
   Never build new work on top of an unverified half-finished change.
5. From here on, LOG AFTER EVERY STEP so a cut-off never loses a trail.

State what interrupted work you found and its health, then continue.
```

## B4 — Sub-Agent Task Assignment (template — fill in, paste AFTER B1)

```
Your scoped task: <one-sentence goal>.
Lane: <package/dir you may touch, e.g. packages/qubit-scanner/src/qubit_scanner/catalog/rules/>.
Branch: <agent>/<short-task-name>  (create it; do NOT work on main).
Spec to follow: docs/design/<0X>.md §<sections>  and the existing pattern in <example file>.
Definition of done:
  - <concrete acceptance criteria, e.g. "rules for X/Y/Z, each with positive+negative examples">
  - `uv run ruff check <pkg> && uv run mypy <pkg>/src && uv run pytest <pkg> -q` all green.
Boundaries: do NOT touch packages/qubit-core/, docs/design/**, or other packages. Import from qubit_core.
When done (or if you run low mid-task): log to SUBAGENT_WORK_LOG.md (timestamp, files, gate result, next
step), commit to your branch, open a PR. Do not merge to main — Claude reviews and merges.
```

---

## Maintenance note
When any prompt or the workflow changes, edit it HERE (this is the canonical copy). `PROJECT_PHASE_MEMORY.md`
points to this file for the prompts rather than duplicating them, so there is one source of truth.
