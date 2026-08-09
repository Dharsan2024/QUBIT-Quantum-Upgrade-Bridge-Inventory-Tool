# QUBIT — Weekly Progress Report

**Sprint:** 2026-08-09 → **2026-09-30** (deadline). Goal: a **hardened, self-hostable working product** by
Sep 30 — the research paper is deferred to after the deadline. See
[PROJECT_STATUS_REPORT.md](PROJECT_STATUS_REPORT.md) for the point-in-time snapshot and
[BUILD_PLAN §5](../BUILD_PLAN.md) for the sprint scope.

**How to use this file — WEEKLY CADENCE ONLY (Mondays).** Write exactly **one** dated section per week,
on **Monday**, summarizing the week just finished (newest at the top). This file is a weekly roll-up, NOT
a running log — do **not** append to it after each task. Day-to-day work is logged as usual in
`project-phase-memory/PROJECT_PHASE_MEMORY.md §5` (Claude) / `SUBAGENT_WORK_LOG.md` (sub-agents); the
Monday entry here distills those. Every line **names the agent that did it** — role + tool/model, e.g.
`[Claude orchestrator]` or `[sub-agent — Gemini Pro High]` (logging rule, `AGENT_WORK_SPLIT.md §0` rule 7).
Report what landed, what slipped, and the measured gate result. Timestamps: `date "+%Y-%m-%d %H:%M:%S %Z"`.

**Sprint burndown (update the status each week):**

| # | Deliverable (for Sep 30) | Owner (recommended) | Status |
|---|---|---|---|
| 1 | Real token auth (tokens + scopes, hashed store) | Claude orchestrator | ✅ done (2026-08-09) |
| 2 | E5 migration KB (`params/migration_kb.yaml` + `/meta/migration-kb`) | Claude orchestrator | ⬜ not started |
| 3 | E2 crypto-agility policy (`params/agility_policy.yaml` + resolver + `/meta/agility-policy`) | Claude orchestrator | ⬜ not started |
| 4 | E1 per-asset recommendation (`/assets/{id}/recommendation` + Inventory badge) | Claude orchestrator | ⬜ not started |
| 5 | E3 dependency graph surfaced (`/plans/{id}/graph` + graph tab) | sub-agent | ⬜ not started |
| 6 | E4 governance sign-off + policy gate | sub-agent | ⬜ not started |
| 7 | Packaging + `docker compose up` verified on a clean machine + README quickstart | sub-agent | ⬜ not started |
| 8 | Test hygiene: fix bridge e2e probe; add `xgboost` to eval env; keep cov ≥70% | sub-agent | ✅ done (2026-08-09) |
| 9 | Demo readiness: `qubit demo run --all` rehearsed + backup demo video | Claude + sub-agent | ⬜ not started |

Status legend: ⬜ not started · 🏃 in progress · ✅ done · ⏸ blocked · ✂️ cut to cut-line.

---

## Week 1 — 2026-08-09 → 2026-08-15

**Baseline at start of sprint** (grounded at commit `b4c070c`, measured — not estimated):
- ~12,451 Py LOC (7 packages) + ~2,545 dashboard TS; **271 passed · 1 skipped · 1 failed** on
  `uv run pytest packages -q`; ruff + mypy clean; CI live.
- The 1 fail = `qubit-bridge` e2e probe hitting a `host.docker.internal` timeout under WSL2 docker
  networking (environmental, not a code regression); the 1 skip = `xgboost` not installed in the eval env.
- Docker daemon (v29.6.1) and Ollama (`qwen2.5-coder:7b`) confirmed **up** on 2026-08-09.

**Summary of the week (weekly roll-up — see PROJECT_PHASE_MEMORY §5 for the per-step log):**
- `[Claude orchestrator]` **Re-planned to the end-of-September deadline** (product-first, paper deferred):
  `BUILD_PLAN §5` rewritten into one continuous hardening sprint; Phases 0/1/2 marked complete; paper +
  experiment suites moved to "deferred post-deadline".
- `[Claude orchestrator]` **Generalized the multi-agent rules** (Claude sole orchestrator; all others are
  generic "sub-agents"), strengthened logging to name the agent, and added the branch rule (sub-agents push
  to `sub-workers-push`; only Claude merges to `main`) + the one-identity rule (all commits authored as
  Dharsan L).
- `[Claude orchestrator]` **Folded the literature survey into the design**: new
  `docs/design/08-extended-modules.md` (M1–M12 coverage map + additive designs E1–E5), additive edits to
  docs 03 + 05, BUILD_PLAN module-coverage table; created `docs/project-status/` + this report.
- `[Claude orchestrator]` **Item 1 — real token auth (DB tokens + ro/rw scopes + `qubit serve token` CLI).**
- `[Claude orchestrator]` **Item 8 — test hygiene: eliminated the failure and the skip.** Fixed the
  `qubit-bridge` e2e probe (root cause: `probe_host`/`bench` did `apk add openssl` in `nginx:alpine` on
  every call — ~25 s, over the 10 s timeout, and offline-hostile; now runs openssl in an image that already
  ships the 3.5 CLI, no install) and installed `xgboost` so the regressor test runs.

**Gate (end of week):** ruff clean; mypy clean per-package; **full suite green — 0 failures, 0 skips**
(`289 passed`), Docker + Ollama up. Details in PROJECT_PHASE_MEMORY §5.

**Next week:** item 2 (E5 migration KB) → item 3 (E2 agility policy) → item 4 (E1 recommendation) — the
substrate + read model, Claude's lane. Items 5–7 (E3 graph, E4 governance, packaging) are good parallel
sub-agent hand-offs.

---

<!-- Add Week 2 above this line, keeping newest-first order. Template:

## Week N — YYYY-MM-DD → YYYY-MM-DD
**Done this week:**
- `[<agent — role + tool/model>]` <date> — <what landed> (gate: <result>).
**Slipped / blocked:** <items + why>.
**Gate at end of week:** <ruff/mypy/pytest result + coverage>.
**Next week's focus:** <items>.

-->
