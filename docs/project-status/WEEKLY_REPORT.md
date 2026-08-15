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
| 2 | E5 migration KB (`params/migration_kb.yaml` + `/meta/migration-kb`) | sub-agent → Claude review | ✅ done (2026-08-09) |
| 3 | E2 crypto-agility policy (`params/agility_policy.yaml` + resolver + `/meta/agility-policy`) | sub-agent → Claude review | ✅ done (2026-08-09) |
| 4 | E1 per-asset recommendation (`/assets/{id}/recommendation` + Inventory drawer) | sub-agent (API) + Claude (drawer) | ✅ done (2026-08-10 — API + dashboard drawer) |
| 5 | E3 dependency graph surfaced (`/plans/{id}/graph` + graph tab) | sub-agent → Claude review | ✅ done (2026-08-09) |
| 6 | E4 governance sign-off + policy gate | sub-agent → Claude review | ✅ done (2026-08-09) |
| 7 | Packaging + `docker compose up` verified on a clean machine + README quickstart | sub-agent + Claude fix/verify | ✅ done (2026-08-09 — 5 bugs fixed, run live); **re-verified 2026-08-15** against freshly built `--no-cache` images + a true clean-room boot (9 s to authenticated stack). README rewritten 2026-08-15. *Still open: PyPI publication.* |
| 8 | Test hygiene: fix bridge e2e probe; add `xgboost` to eval env; keep cov ≥70% | sub-agent | ✅ **actually** done 2026-08-15. Marked done 2026-08-09, but that fix was **not durable** — `xgboost` was installed into the environment without being declared, so a later `uv sync` dropped it and the regressor test was silently skipping again by 2026-08-15. Now declared in the root `dev` group. Suite: 419 pass / 0 skip; coverage 82%. |
| 9 | Demo readiness: `qubit demo run --all` rehearsed + backup demo video | Claude + sub-agent | 🏃 rehearsed live ✅ (2026-08-09, re-rehearsed 2026-08-15 → `PASS negotiated=X25519MLKEM768`); backup video pending (manual) |
| 10 | External-repo integrations (SCA scanner, Vault connector, CNSA 2.0 + real PQC probe) | Claude orchestrator | ✅ done (2026-08-15) — added mid-sprint from the 8-repo evaluation; traded against the backlog, not against items 1–9 |

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

**Gate (mid-week, 2026-08-09):** ruff clean; mypy clean per-package; **full suite green — 0 failures,
0 skips** (`289 passed`), Docker + Ollama up. Details in PROJECT_PHASE_MEMORY §5.

### Addendum — rest of week 1 (2026-08-10 → 2026-08-15)

- `[Claude — Opus 5]` E1 recommendation surfaced in the dashboard (completes E1 end-to-end); Stitch
  "Quantum Command" HUD design implemented across the desktop app; desktop-app fixes (native folder
  picker, CBOM export, in-app report + HTML export, lazy-loaded Plotly).
- `[Claude — Sonnet 5]` App test pass → **3 genuine production bugs** found + fixed (app-wide pagination
  silently capped at 50 assets; Alembic migrations not applied at startup causing `DELETE /projects` 500s;
  KPI undercount). Dead tracked files removed.
- `[Claude — Sonnet 5 → Opus 5]` **Integrated the 8 external reference repos** the user cloned into
  `git help/` (item 10). Tier 1: JOSE/JWT canonical algorithm grounding + Go/JS/TS JWT rule packs (3
  already-scannable languages that had zero JWT rules) + a `migration_kb.yaml` gap where every JWT-context
  asset silently got no recommendation. Then backlog items **B3** (real raw-ClientHello PQC probe replacing
  a pure mock, + CNSA 2.0 milestone evaluator), **B2** (dependency/SCA manifest scanner — closed a total
  zero-SCA-parsing gap; created `THIRD_PARTY_NOTICES.md`), **B1** (Vault transit/PKI connector + demo-lab
  compose service, verified live: 9 assets, 5 quantum-vulnerable).
- `[Claude — Opus 5]` **Two process failures found in my own work, both corrected:** (a) I had been running
  `ruff check` but never `ruff format`, which is `poe check`'s first step — 4 files were unformatted;
  (b) I reported a Docker build as succeeding because I piped it into `tail`, which masked Docker's real
  exit code — the dashboard build had actually failed on a transient npm registry timeout and the stack
  I "verified" was running 5-day-old images. Both re-done properly.
- `[Claude — Opus 5]` **Real bug caught by rehearsing the demo:** the new SCA scanner credited
  `cryptography==42.0.8` with ML-KEM-768/ML-DSA-65 (which need `>=48`), so a quantum-*vulnerable*
  dependency read as quantum-*ready*. Added version-aware capability gates (`min_version`), deliberately
  conservative: unpinned/lower/unparseable ⇒ not claimed.
- `[Claude — Opus 5]` Docs brought up to date: README rewritten against measured reality;
  PROJECT_STATUS_REPORT re-grounded at `d89eb66`; BUILD_PLAN's stale "auth pending" and "test hygiene
  pending" lines corrected; 3 pre-existing defects promoted from loose observations to tracked items.

**Gate (end of week 1, 2026-08-15):** ruff clean · ruff-format clean · mypy clean (except 2 known
pre-existing `union-attr` errors in `qubit_migrate/graph/order.py`) · **419 passed / 0 failed / 0 skipped** ·
coverage **82%** on the 3 core packages · all 3 Docker integration tests passing · `qubit demo run --all`
completing with `PASS negotiated=X25519MLKEM768` · `docker compose up` clean-room boot in 9 s.

**Slipped / carried into week 2:** PyPI publication (item 7 remainder), structured logging, the backup
demo video (manual), and the 3 known defects in PROJECT_STATUS_REPORT §4.

**Next week's focus:** the 3 known defects (starting with the API's ignored `scanners` list), a minimal
structured-logging story, and PyPI packaging.

---

<!-- Add Week 2 above this line, keeping newest-first order. Template:

## Week N — YYYY-MM-DD → YYYY-MM-DD
**Done this week:**
- `[<agent — role + tool/model>]` <date> — <what landed> (gate: <result>).
**Slipped / blocked:** <items + why>.
**Gate at end of week:** <ruff/mypy/pytest result + coverage>.
**Next week's focus:** <items>.

-->
