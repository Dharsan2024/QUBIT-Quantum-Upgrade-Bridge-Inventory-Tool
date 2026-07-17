# QUBIT — Sub-Agent Work Log

> **Who writes here:** every NON-Claude agent (OpenAI Codex, GitHub Copilot, Google Gemini, Google
> Antigravity). Claude keeps its authoritative log in `PROJECT_PHASE_MEMORY.md §5`; you log here.
> **Claude (orchestrator) reads this file** when the human returns, verifies your work, and records a
> KEEP / UPDATE / REMOVE verdict on each entry.
>
> **HOW TO LOG (do this CONTINUOUSLY, not just at the end):**
> - The moment you START a task, add an entry (newest at top) with a timestamp.
> - After EACH meaningful step, update it. Assume you could be cut off at any moment — never have more
>   than one unlogged step. If you sense you're low on credits/context, immediately write your partial
>   progress + the exact next step, commit, THEN stop.
> - Get a real timestamp from the shell: `date "+%Y-%m-%d %H:%M:%S %Z"`.
> - Say which branch you're on and which files you touched. Run the quality gate and record the result.
>
> **Entry template (copy):**
> ```
> ### <YYYY-MM-DD HH:MM %Z> — <agent> — <task title>  [status: in-progress | done | cut-off]
> - Branch: <branch>   Lane: <your assigned area from AGENT_WORK_SPLIT.md>
> - Did: <what you changed>
> - Files: <paths>
> - Gate: ruff <ok/fail> | mypy <ok/fail> | pytest <N passed>
> - Next step (if in-progress/cut-off): <exact next action so the next agent resumes seamlessly>
> - Orchestrator verdict (Claude fills this): <pending>
> ```

---

## Log (newest first)

### 2026-07-17 06:59:46 +05:30 - OpenAI Codex - recovery audit of interrupted API work  [status: done]
- Branch: `copilot/api-db-persistence`   Lane: recovery/review of interrupted `packages/qubit-api` work per user prompt.
- Did: read newest PROJECT_PHASE_MEMORY entries, SUBAGENT_WORK_LOG, AGENT_WORK_SPLIT; inspected branch/status/stash/log. Found uncommitted Copilot API persistence changes marked done in the sub-agent log but not committed.
- Files: `packages/qubit-api/**`, `pyproject.toml`, `uv.lock`, `project-phase-memory/SUBAGENT_WORK_LOG.md`, `project-phase-memory/USER_PROMPTS_LOG.md`
- Gate: repo ruff fail due pre-existing placeholder E501 in qubit-bridge/qubit-migrate/qubit-risk | repo pytest 139 passed | API ruff ok | API mypy ok | API pytest 3 passed.
- Next step (if in-progress/cut-off): inspect API files/endpoints against doc 05; fix any scoped issues, then commit if complete.
- **Orchestrator verdict (Claude, 2026-07-17 22:55 IST): KEEP** (the recovery pass correctly committed the interrupted API work as 7b454e8 — good use of the continuation flow; no separate artifact to review beyond the Copilot work below).

### 2026-07-17 06:56:51 +05:30 — GitHub Copilot — qubit-api DB persistence + CRUD foundation  [status: done]
- Branch: `copilot/api-db-persistence`   Lane: `packages/qubit-api` (FastAPI CRUD endpoint bodies/routers)
- Did: implemented a working FastAPI service + persistence flow for projects/scans/assets with synchronous scan ingestion into the DB, plus query endpoints for assets, trends, scan summary/diff, CBOM export, health/version, and algorithm registry. Added API tests for persistence/queryability and project-root target guardrails.
- Files: `packages/qubit-api/pyproject.toml`, `packages/qubit-api/src/qubit_api/{__init__.py,app.py,deps.py,main.py,schemas.py,services.py}`, `packages/qubit-api/src/qubit_api/routers/{__init__.py,meta.py,registry.py,projects.py,scans.py,assets.py}`, `packages/qubit-api/tests/test_api.py`, `pyproject.toml`
- Gate: `uv run ruff check packages/qubit-api` ok | `uv run mypy packages/qubit-api/src` ok | `uv run pytest packages/qubit-api -q` 3 passed
- Next step (if in-progress/cut-off): Claude/orchestrator review for normative endpoint parity (remaining doc-05 routes like risk/migrations/jobs/auth/SSE), plus decide whether to adopt JobRunner now or keep sync M1 mode.
- **Orchestrator verdict (Claude, 2026-07-17 22:55 IST): UPDATE → KEEP, merged to main.**
  Verified: endpoints match doc 05's M1 slice (projects/scans/assets CRUD, trends, summary, diff, cbom,
  registry, health/version, single-token auth); Alembic migration round-trips (upgrade/downgrade) and matches
  the ORM exactly; 40-file mypy + ruff + 150 tests green.
  BOUNDARY NOTE: it touched `packages/qubit-core/` (Alembic scaffolding + initial migration) — normally
  Claude-only — but the change is purely ADDITIVE infra that doc 05 §4.2 mandates ("single migration home in
  qubit-core") and does NOT modify the frozen schema/ORM, so accepted. Tolerated this time; sub-agents should
  still flag core-adjacent needs to Claude rather than editing qubit-core.
  BUG FIXED by Claude (commit after 7b454e8): `deps.get_settings()` was `@lru_cache`'d + built a fresh
  `Settings()`, so `create_app(settings)` did NOT thread the token into auth — a custom `api_token` was
  silently ignored (tests passed only because they used the default token). Now settings live on `app.state`
  and get_settings reads them; regression test added.

### 2026-07-17 06:49:26 +05:30 — GitHub Copilot — qubit-api DB persistence + CRUD foundation  [status: in-progress]
- Branch: `copilot/api-db-persistence`   Lane: `packages/qubit-api` (FastAPI CRUD endpoint bodies/routers)
- Did: read the required memory/design docs (1–6), confirmed lane boundaries, collected current repository baseline.
- Files: project-phase-memory/PROJECT_PHASE_MEMORY.md, project-phase-memory/AGENT_WORK_SPLIT.md, project-phase-memory/CORE_PROMPTS.md, docs/BUILD_PLAN.md, docs/design/00-architecture-frame.md, docs/design/05-platform-api-dashboard.md, project-phase-memory/USER_PROMPTS_LOG.md
- Gate: ruff fail (pre-existing placeholder-line-length violations in multiple packages) | mypy n/a | pytest n/a
- Next step (if in-progress/cut-off): implement `qubit-api` app/routers/services for project/scan/asset persistence and query endpoints, then add tests and run the package quality gate.
- Orchestrator verdict (Claude fills this): pending

### 2026-07-17 ~03:30 IST — OpenAI Codex — bulk scanner detection rules  [status: done]
- Branch: `codex/scanner-rules`   Lane: qubit-scanner catalog/rules only.
- Did: added detection rule packs following the `qubit-rule/v1` format proven by Claude's engine.
- Files: `catalog/rules/python/{cryptography.yaml (expanded), hashlib.yaml (expanded), jwt.yaml,
  pycryptodome.yaml}`, `catalog/rules/java/{jca.yaml, bouncycastle-pqc.yaml}`, `catalog/rules/go/crypto.yaml`.
- Result: 33 rules total (python 18, java 8, go 7); every rule ships positive+negative examples.
- Gate: ruff ok | pytest 85 passed.
- **Orchestrator verdict (Claude, 2026-07-17 04:00 IST): KEEP.** Verified: stayed in lane (no engine /
  core / docs edits), gate green, rules resolve to real algorithms. One follow-up owned by Claude (NOT a
  Codex defect): bare `"RSA"` literals (Cipher.getInstance("RSA"), JWT RS256) need a family-level registry
  entry in qubit-core so they keep their Shor-vulnerable verdict instead of degrading to UNKNOWN(RSA).
  Fix applied by Claude in the same session; Codex's rules kept as-is.
