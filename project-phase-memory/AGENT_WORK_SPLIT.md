# QUBIT — Multi-Agent Work Split

> **Purpose:** Assign the BEST-FIT work to each agent so Claude (the orchestrator) isn't the bottleneck —
> **without blocking anyone from any work.** Any agent may do any task; everything a sub-agent does is
> *provisional* until the orchestrator (Claude) verifies it on return. Read alongside `PROJECT_PHASE_MEMORY.md`
> and `CORE_PROMPTS.md`.

---

## 0. The rules (assign best-fit, don't block, verify on return)

1. **Assignments are recommendations, not restrictions.** §2 says who is *best* for each area. But if the
   work in front of you needs something outside it — do it. Nobody is blocked from any part of the codebase.
2. **Everything is provisional until the orchestrator verifies it.** When the human returns to Claude, it
   reviews every sub-agent change (KEEP / UPDATE / REMOVE) via the ORCHESTRATOR RESUME prompt
   (`CORE_PROMPTS.md B2`). This verification gate — not prohibitions — is what keeps the project safe.
3a. **All commits are authored as `Dharsan L <dharsanlingadurai24@gmail.com>` — no exceptions.** Regardless
   of which agent (Claude or any sub-agent) makes a commit, it must appear as authored + committed by
   **Dharsan L <dharsanlingadurai24@gmail.com>**. This repo's local git config already pins it; on any fresh
   clone/machine, set it FIRST: `git config user.name "Dharsan L" && git config user.email "dharsanlingadurai24@gmail.com"`.
   Never commit under an agent/tool identity or any other email (and never the old astradyne email — see §0 of
   PROJECT_PHASE_MEMORY). Verify before pushing: `git log -1 --format='%an <%ae>'` must print exactly
   `Dharsan L <dharsanlingadurai24@gmail.com>`; if a wrong-identity commit slipped in, fix it with
   `git commit --amend --reset-author` (or `git rebase --exec 'git commit --amend --reset-author --no-edit'`
   for several) before pushing.

3. **Sub-agents push to `sub-workers-push`, NEVER to `main`.** Any agent MAY commit and **push** its work —
   but sub-agents push only to the shared integration branch **`sub-workers-push`** (branch it from `main`
   if it doesn't exist: `git checkout main && git pull && git checkout -B sub-workers-push`; otherwise
   `git checkout sub-workers-push && git pull` first, then commit + `git push origin sub-workers-push`).
   **Only Claude (the orchestrator) verifies and merges `sub-workers-push` → `main`.** Sub-agents must NOT
   push to, commit to, or merge into `main`. (A GitHub PR from `sub-workers-push` → `main` is ideal but not
   required — Claude reviews the branch either way.) Optionally use a per-task branch off `sub-workers-push`
   (`subagent/<task>`) for isolation, but the branch Claude reviews on return is `sub-workers-push`.
4. **Handle the frozen core with extra care (not a ban).** `packages/qubit-core/` holds the `CryptoAsset`
   schema + registry + DB. You MAY change it, but keep changes ADDITIVE (never alter an existing binding
   field's meaning) and say WHY in your log — the orchestrator scrutinizes core changes hardest, because a
   bad one breaks everything. Prefer to leave deep schema changes to Claude.
5. **Conform to the contracts.** `from qubit_core import ...` (don't redefine its models); match doc 05's
   normative REST registry; follow the relevant `docs/design/0X`. If you must deviate, log the reason.
6. **Pass the quality gate before "done":**
   `uv run ruff check <pkg> && uv run mypy <pkg>/src && uv run pytest <pkg> -q` — all green.
7. **Log continuously, and NAME THE AGENT in every entry.** Sub-agents log in `SUBAGENT_WORK_LOG.md`;
   Claude logs in `PROJECT_PHASE_MEMORY.md §5`. **Every entry must state which agent did the work** — the
   role + the specific tool/model, e.g. `[sub-agent — Gemini 3.1 Pro High]` or `[Claude orchestrator]` —
   so anyone reading the log later knows exactly who did what. Timestamp with `date "+%Y-%m-%d %H:%M:%S %Z"`;
   entry when you START, update after every step; if running low on credits/context, log partial progress +
   the exact next step and commit BEFORE stopping. Append the task you were given to `USER_PROMPTS_LOG.md`
   (also naming the agent).
8. **OUTPUT DISCIPLINE — "caveman" (save credits).** Talk terse: fragments over sentences, no filler,
   preamble, or flattery. Shrink what you *say*, not what you *do*. Code, commands, diffs, file paths,
   config, and log entries stay byte-for-byte exact and COMPLETE — never abbreviate those, and never drop a
   required step (gate, logging, verification) for brevity. (Technique: github.com/JuliusBrussee/caveman.)

**Claude is the main orchestrator** — it oversees everything and has final say (KEEP/UPDATE/REMOVE) on all
sub-agent work when the human returns.

---

## 1. Active agents (roster)

Two roles, and only two matter to the rules:

| Role | Who | Responsibilities |
|---|---|---|
| **Orchestrator + core builder** | **Claude** (this agent) — the **main orchestrator** | System design, security/math-heavy code (qubit-core, qubit-risk), cross-module integration, and the **only** agent that reviews + verifies + merges (final say KEEP/UPDATE/REMOVE). Reserve for work needing the reasoning. |
| **Sub-agent (worker)** | **Any other agent** — referred to generically as a "sub-agent" | Autonomous multi-file implementation, tests, docs, browser/e2e verification. Work is **provisional** until Claude verifies it on return. May be any agentic IDE/CLI running any capable model. |

The rules never depend on which specific sub-agent tool is used. **Always name the agent (role + tool/model)
in your log entries** (rule 7).

**Reference only — sub-agent model picker (not part of the rules).** When a sub-agent tool exposes a model
choice, pick by task difficulty:
| Model tier | Use for |
|---|---|
| Fast/cheap (e.g. Gemini Flash-class) | High-volume boilerplate, detection rules, tests, docs, CRUD, config. Default to this. |
| Strong-reasoning (e.g. Gemini Pro High / Claude Opus/Sonnet-class) | Multi-file features, refactors, trickier logic. |
| Open-model alternative (e.g. GPT-OSS-class) | Second opinion / general implementation. |

Deep `qubit-core` schema + `qubit-risk` math stay with the Claude orchestrator regardless of sub-agent model.
Any sub-agent's past work that is already merged stays merged (audited on return like any other).

---

## 2. Best-fit assignments (recommendations, per rule 1 — not restrictions)

| Area | Best fit | Why |
|---|---|---|
| `qubit-core` (schema, registry, DB, redaction, CBOM) | **Claude** | Frozen contract; a mistake breaks everything. Others may add additive infra (e.g. Alembic) + log why. |
| `qubit-risk` (Monte-Carlo CRQC, Bayes, XGBoost, Mosca) | **Claude** | Statistical correctness + the paper ride on it. A sub-agent may add tests/fixtures from a Claude spec. |
| `qubit-scanner` detection rules (`catalog/rules/*.yaml`) | **Sub-agent** (fast tier) | High-volume, well-specified; the engine + format already exist. |
| `qubit-migrate` template transforms, IaC, rule pack | **Sub-agent** (strong tier) | Self-contained, spec-driven (doc 03). LLM/safety logic reviewed by Claude. |
| `qubit-bridge` probe/verify, compose images, bench | **Sub-agent** | Well-defined I/O, testable vs containers (doc 04); browser/e2e fits here. |
| `qubit-api` remaining routes, JobRunner, SSE, auth scopes | **Sub-agent** (strong tier) | Boilerplate over doc 05's registry. Auth/security-guardrail bits verified by Claude. |
| `qubit-cli` command wiring | **Sub-agent** (fast tier) | Boilerplate plumbing over package APIs. |
| `dashboard/` React/TS pages + browser/e2e | **Sub-agent** | UI + built-in browser verification. Data via REST only. |
| Docs site, README, paper figures, experiment analysis | **Sub-agent** (strong tier, big context) | Long-context + writing. Leave `docs/design/**` (source of truth) to Claude. |
| Cross-package integration, merges to `main`, security review, paper core claims | **Claude** | Whole-system reasoning + final say. |

---

## 3. When to switch (Claude ↔ sub-agent)

**Use Claude (orchestrator) when:** designing/architecting; changing `qubit-core` schema or `qubit-risk`
math; integrating packages; debugging cross-cutting failures; **reviewing/merging sub-agent work**; the paper.

**Hand to a sub-agent when:** a task is well-specified and isolated enough to run autonomously — pick the
sub-agent model by difficulty (fast tier = cheap/bulk; strong tier = complex). Give it a scoped task
(`CORE_PROMPTS.md B4`) after the universal prompt (B1).

**Claude will flag in its replies** when an upcoming task is a good sub-agent hand-off ("well-specified +
isolated → hand to a sub-agent, fast tier").

---

## 4. Branch + verify flow (keeps `main` reviewable)

```
main                          # ONLY Claude (orchestrator) verifies + merges here
 └─ sub-workers-push          # ALL sub-agents push here (shared integration branch off main)
      └─ subagent/<task>      # optional per-task isolation branch off sub-workers-push
```
Sub-agent: `git checkout sub-workers-push && git pull` (branch from `main` if it doesn't exist yet) → build
→ quality gate green → log → commit → **`git push origin sub-workers-push`** → hand back. **Sub-agents
never touch `main`.** Claude (on return): `git checkout main`, review `sub-workers-push` (boundaries + gate
+ semantics) → KEEP/UPDATE/REMOVE → merge the good work into `main`, fix/drop the rest → push `main` →
verify the push reached the remote (A5.8). After a clean merge, `sub-workers-push` can be reset to
`main` (`git checkout sub-workers-push && git reset --hard main && git push --force-with-lease`) so the next
batch starts fresh.

---

## 5. Current recommended assignment (updated as phases progress)

Sprint: **2026-08-09 → 2026-09-30**, product-hardening (paper deferred). See `docs/BUILD_PLAN.md §5` Phase 3.

- **NOW (Claude's lane):** real token auth (tokens+scopes) over doc 05 §6.6; extended-module features
  E5 → E2 → E1 (doc 08) — the KB/agility substrate and recommendation read model touch the core contract,
  so Claude leads.
- **Good sub-agent hand-offs available in parallel:** E3 dependency-graph serializer + dashboard graph tab;
  E4 governance UI strip; packaging/`docker compose` verification on a clean machine; dashboard polish +
  deferred UI; test-hygiene (mark bridge e2e `integration`, add `xgboost` to eval env).
- Claude flags the exact hand-off point in its updates and names the agent in the log.
