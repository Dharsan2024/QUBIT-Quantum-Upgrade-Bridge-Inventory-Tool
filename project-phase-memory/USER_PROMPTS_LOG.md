# QUBIT — User Prompt Log

> Every instruction the human gives is logged here with a timestamp, so any agent can see the intent
> history even across model switches. **Claude appends each turn**; sub-agents append the prompt they
> were given too. Newest first. Get timestamps from the shell: `date "+%Y-%m-%d %H:%M:%S %Z"`.
> Entries paraphrase the request (they are a decision trail, not a verbatim transcript).

---

### 2026-07-17 06:59:46 +05:30 � OpenAI Codex
Recover interrupted work before doing anything new: read project memory/sub-agent logs/work split, inspect git status/stash/diff/log, run health checks, judge whether the uncommitted change is complete/half-done/broken, log after every step, then continue safely.
### 2026-07-17 06:49:26 +05:30 — GitHub Copilot
Read project memory/design files 1-6 in order, identify Copilot lane, and start the next concrete
work item: DB persistence + `qubit-api` FastAPI service so scans are stored in the registry and
become queryable/trend-able.

### 2026-07-17 23:20 IST — Claude
Use git identity `Dharsan L <dharsanlingadurai24@gmail.com>`. Continue with qubit-risk M1 (heuristic
sensitivity + Monte-Carlo CRQC timeline + Mosca). [/compact issued mid-turn → paused build at clean point,
made memory current for seamless resume; qubit-risk build starts next.]

### 2026-07-17 23:10 IST — Claude
Learn the "caveman" token-compression skill (github.com/JuliusBrussee/caveman) and bake it into ALL
CORE_PROMPTS prompts → terse output, fewer credits, full required output preserved. Codex + Copilot credits
are exhausted → now switching only between Claude and Antigravity (models: Gemini 3.5 Flash L/M/H, Gemini 3.1
Pro L/H, Claude Sonnet 4.6 Thinking, Claude Opus 4.6 Thinking, GPT-OSS 120B). Don't BLOCK agents from work —
assign best-fit but let anyone do anything; orchestrator (main Claude) checks + verifies on return. Git:
don't expose the astradyne email — keep just the name.

### 2026-07-17 22:50 IST — Claude (Orchestrator Resume, prompt B2)
Review what the sub-agents did while away, decide keep/update/remove, then continue.
→ Reviewed `copilot/api-db-persistence`: verdict UPDATE→KEEP, merged to main after fixing a settings/auth
  threading bug. (Earlier this session I had also set out to build the qubit-api persistence seam + a scoped
  sub-agent task; Copilot delivered the API directly, so the review path superseded that.)

### 2026-07-17 06:29 IST — Claude
Create a canonical CORE_PROMPTS.md: (a) a project-agnostic explanation of HOW the multi-agent workflow
works — the structure/mechanism (shared-memory files, logs, branches, orchestrator review), not the
project subject matter; and (b) ALL the project's operating prompts in one file (universal handoff,
orchestrator resume, sudden credit-out continuation, and any others).

### 2026-07-17 ~04:00 IST — Claude
Verify Codex's work and take it back. Build resume/continuation prompts + logging infrastructure:
(1) an ORCHESTRATOR RESUME prompt for Claude to review sub-agent work and decide keep/update/remove;
(2) a separate SUBAGENT_WORK_LOG.md for non-Claude agents to log in;
(3) make agents log BEFORE they run out of credits (proactive logging);
(4) a SUDDEN CREDIT-OUT continuation prompt;
(5) log every user prompt with a timestamp (this file);
(6) add Google Antigravity as a switchable agent;
(7) reaffirm Claude as the main orchestrator overseeing everything.

### 2026-07-16 (evening) IST — Claude → Codex handoff
"Codex did its part" — user ran Codex on the bulk scanner rules task on branch `codex/scanner-rules`.

### 2026-07-16 IST — Claude
Continue building. Confirmed the multi-agent split; asked Claude to proceed with the scanner engine.

### 2026-07-16 IST — Claude
Set up git remote + push to github.com/Dharsan2024/QUBIT-Quantum-Upgrade-Bridge-Inventory-Tool (push
required stuff periodically). Use Neon for the DB backend. Split work across Copilot/Codex/Gemini in a
separate file with boundaries so the core isn't spoiled; notify when to switch models. Reaffirm the
build is production-ready, not a simulation.

### 2026-07-16 IST — Claude
Confirm the universal handoff prompt is what gets pasted into any switched model first, and ensure every
switch logs to the memory md and continues the work.

### 2026-07-16 IST — Claude
Laptop specs given (i7-14700HX / 16 GB / RTX 4060). Everything installed. Ask if anything else is needed
(quantum tooling? git?). Reaffirm production-ready, not just a simulation/demo.

### 2026-07-16 IST — Claude
List all prerequisites needed before building. Create a "project phase memory" file in a separate folder,
updated every time something changes, so agent switches can catch up. Solo build, no breaks.

### 2026-07-16 IST — Claude
Plan and build QUBIT as a full-fledged working product (not a prototype), from the research doc + the
knowledge folder. (Design docs 00–07 + BUILD_PLAN produced and reviewed.)
