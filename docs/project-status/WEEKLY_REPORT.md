# QUBIT — Weekly Progress Report

**Sprint:** 2026-08-09 → **2026-09-30** (deadline). Goal: a **hardened, self-hostable working product** by
Sep 30 — the research paper is deferred to after the deadline. See
[PROJECT_STATUS_REPORT.md](PROJECT_STATUS_REPORT.md) for the point-in-time snapshot and
[BUILD_PLAN §5](../BUILD_PLAN.md) for the sprint scope.

**How to use this file:** add one dated section per week (newest at the top). Every line of work **names
the agent that did it** — role + tool/model, e.g. `[Claude orchestrator]` or `[sub-agent — Gemini Pro
High]` — per the logging rule in `AGENT_WORK_SPLIT.md §0` rule 7. Keep it honest: report what landed, what
slipped, and the measured gate result. Get timestamps from the shell: `date "+%Y-%m-%d %H:%M:%S %Z"`.

**Sprint burndown (update the status each week):**

| # | Deliverable (for Sep 30) | Owner (recommended) | Status |
|---|---|---|---|
| 1 | Real token auth (tokens + scopes, hashed store) | Claude orchestrator | ⬜ not started |
| 2 | E5 migration KB (`params/migration_kb.yaml` + `/meta/migration-kb`) | Claude orchestrator | ⬜ not started |
| 3 | E2 crypto-agility policy (`params/agility_policy.yaml` + resolver + `/meta/agility-policy`) | Claude orchestrator | ⬜ not started |
| 4 | E1 per-asset recommendation (`/assets/{id}/recommendation` + Inventory badge) | Claude orchestrator | ⬜ not started |
| 5 | E3 dependency graph surfaced (`/plans/{id}/graph` + graph tab) | sub-agent | ⬜ not started |
| 6 | E4 governance sign-off + policy gate | sub-agent | ⬜ not started |
| 7 | Packaging + `docker compose up` verified on a clean machine + README quickstart | sub-agent | ⬜ not started |
| 8 | Test hygiene: mark bridge e2e `integration`; add `xgboost` to eval env; keep cov ≥70% | sub-agent | ⬜ not started |
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

**Done this week:**
- `[Claude orchestrator]` 2026-08-09 — **Re-planned the whole timeline to the new end-of-September
  deadline** (product-first, paper deferred): rewrote `BUILD_PLAN §5` into a single continuous hardening
  sprint, marked Phase 0/1/2 complete, moved the paper + experiment suites to "deferred post-deadline".
- `[Claude orchestrator]` 2026-08-09 — **Generalized the multi-agent rules**: Claude stays the sole
  orchestrator; all non-Claude agents are now referred to generically as "sub-agents" in the rules
  (`CORE_PROMPTS.md`, `AGENT_WORK_SPLIT.md`, `PROJECT_PHASE_MEMORY §0`); the specific tool/model table is
  kept as *reference only*. Strengthened the logging rule so **every log entry names the agent** (role +
  tool/model).
- `[Claude orchestrator]` 2026-08-09 — **Folded the literature survey into the design**: new
  `docs/design/08-extended-modules.md` (M1–M12 coverage map + additive designs E1–E5), additive edits to
  docs 03 + 05, and the BUILD_PLAN module-coverage table. (Earlier this session.)
- `[Claude orchestrator]` 2026-08-09 — **Created this `docs/project-status/` folder**, moved
  `PROJECT_STATUS_REPORT.md` here, and seeded this weekly report.

**Slipped / not yet started:** all nine sprint deliverables above (the week was planning + docs). Auth
(item 1) and the E5→E2→E1 substrate (items 2–4) are next.

**Gate at end of week:** unchanged from baseline (docs-only changes this week — no code touched, so
ruff/mypy/pytest are unaffected).

**Next week's focus:** start item 1 (real token auth) and item 2 (E5 migration KB) — both are Claude's
lane (touch the core contract / security path). Hand item 8 (test hygiene) to a sub-agent in parallel.

---

<!-- Add Week 2 above this line, keeping newest-first order. Template:

## Week N — YYYY-MM-DD → YYYY-MM-DD
**Done this week:**
- `[<agent — role + tool/model>]` <date> — <what landed> (gate: <result>).
**Slipped / blocked:** <items + why>.
**Gate at end of week:** <ruff/mypy/pytest result + coverage>.
**Next week's focus:** <items>.

-->
