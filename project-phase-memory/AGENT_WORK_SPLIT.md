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
3. **Work on a branch; let the orchestrator merge.** Use `antigravity/<task>` (or `<agent>/<task>`), so
   Claude can review before it lands on `main`. A GitHub PR is ideal (that's how the API work landed). If
   you must commit to `main`, that's allowed — but the orchestrator will still audit it on return.
4. **Handle the frozen core with extra care (not a ban).** `packages/qubit-core/` holds the `CryptoAsset`
   schema + registry + DB. You MAY change it, but keep changes ADDITIVE (never alter an existing binding
   field's meaning) and say WHY in your log — the orchestrator scrutinizes core changes hardest, because a
   bad one breaks everything. Prefer to leave deep schema changes to Claude.
5. **Conform to the contracts.** `from qubit_core import ...` (don't redefine its models); match doc 05's
   normative REST registry; follow the relevant `docs/design/0X`. If you must deviate, log the reason.
6. **Pass the quality gate before "done":**
   `uv run ruff check <pkg> && uv run mypy <pkg>/src && uv run pytest <pkg> -q` — all green.
7. **Log continuously in `SUBAGENT_WORK_LOG.md`** (Claude logs in `PROJECT_PHASE_MEMORY.md §5`). Timestamp
   with `date "+%Y-%m-%d %H:%M:%S %Z"`; entry when you START, update after every step; if running low on
   credits/context, log partial progress + the exact next step and commit BEFORE stopping. Append the task
   you were given to `USER_PROMPTS_LOG.md`.
8. **OUTPUT DISCIPLINE — "caveman" (save credits).** Talk terse: fragments over sentences, no filler,
   preamble, or flattery. Shrink what you *say*, not what you *do*. Code, commands, diffs, file paths,
   config, and log entries stay byte-for-byte exact and COMPLETE — never abbreviate those, and never drop a
   required step (gate, logging, verification) for brevity. (Technique: github.com/JuliusBrussee/caveman.)

**Claude is the main orchestrator** — it oversees everything and has final say (KEEP/UPDATE/REMOVE) on all
sub-agent work when the human returns.

---

## 1. Active agents (roster)

| Agent | Role | Strengths | Notes |
|---|---|---|---|
| **Claude** (this agent) | **Orchestrator + core builder** | System design, security/math-heavy code (qubit-core, qubit-risk), cross-module integration, review + merge, the paper. | The only one that verifies/merges. Reserve for work that needs the reasoning. |
| **Google Antigravity** (agent-first IDE) | **Primary sub-agent** | Autonomous multi-file implementation + planning + browser/e2e verification. Runs several models (below) — pick per task. | Provisional work; Claude verifies on return. |

**Antigravity model picker** (models available in your Antigravity):
| Model | Use for |
|---|---|
| Gemini 3.5 Flash (Low/Med/High) | Cheap + fast: high-volume boilerplate, detection rules, tests, docs, CRUD, config. Default to this. |
| Gemini 3.1 Pro (Low/High) | Harder reasoning: multi-file features, refactors, trickier logic. Use **High** for complex. |
| Claude Sonnet 4.6 (Thinking) | Strong general implementation when Flash/Pro struggle. |
| Claude Opus 4.6 (Thinking) | Hardest sub-agent tasks needing top quality (still: deep core/risk work → the main Claude orchestrator). |
| GPT-OSS 120B (Medium) | Open-model alternative / second opinion / general implementation. |

**Currently unavailable:** OpenAI Codex and GitHub Copilot — credits exhausted. (Their past work is merged;
if credits return, treat them like any sub-agent under these rules.)

---

## 2. Best-fit assignments (recommendations, per rule 1 — not restrictions)

| Area | Best fit | Why |
|---|---|---|
| `qubit-core` (schema, registry, DB, redaction, CBOM) | **Claude** | Frozen contract; a mistake breaks everything. Others may add additive infra (e.g. Alembic) + log why. |
| `qubit-risk` (Monte-Carlo CRQC, Bayes, XGBoost, Mosca) | **Claude** | Statistical correctness + the paper ride on it. Antigravity may add tests/fixtures from a Claude spec. |
| `qubit-scanner` detection rules (`catalog/rules/*.yaml`) | **Antigravity** (Gemini Flash) | High-volume, well-specified; the engine + format already exist. |
| `qubit-migrate` template transforms, IaC, rule pack | **Antigravity** (Gemini Pro) | Self-contained, spec-driven (doc 03). LLM/safety logic reviewed by Claude. |
| `qubit-bridge` probe/verify, compose images, bench | **Antigravity** | Well-defined I/O, testable vs containers (doc 04); its browser/e2e fits here. |
| `qubit-api` remaining routes, JobRunner, SSE, auth scopes | **Antigravity** (Gemini Pro) | Boilerplate over doc 05's registry. Auth/security-guardrail bits verified by Claude. |
| `qubit-cli` command wiring | **Antigravity** (Gemini Flash) | Boilerplate plumbing over package APIs. |
| `dashboard/` React/TS pages + browser/e2e | **Antigravity** | UI + its built-in browser verification. Data via REST only. |
| Docs site, README, paper figures, experiment analysis | **Antigravity** (Gemini Pro, big context) | Long-context + writing. Leave `docs/design/**` (source of truth) to Claude. |
| Cross-package integration, merges to `main`, security review, paper core claims | **Claude** | Whole-system reasoning + final say. |

---

## 3. When to switch (Claude ↔ Antigravity)

**Use Claude (orchestrator) when:** designing/architecting; changing `qubit-core` schema or `qubit-risk`
math; integrating packages; debugging cross-cutting failures; **reviewing/merging sub-agent work**; the paper.

**Hand to Antigravity when:** a task is well-specified and isolated enough to run autonomously — pick the
model by difficulty (Gemini Flash = cheap/bulk; Gemini Pro High or Claude Opus 4.6 Thinking = complex).
Give it a scoped task (`CORE_PROMPTS.md B4`) after the universal prompt (B1).

**Claude will flag in its replies** when an upcoming task is a good Antigravity hand-off ("well-specified +
isolated → hand to Antigravity, Gemini Flash").

---

## 4. Branch + verify flow (keeps `main` reviewable)

```
main                          # orchestrator (Claude) verifies + merges here
 └─ antigravity/<task>        # sub-agent works here -> PR or hand back -> Claude reviews -> merge
```
Sub-agent: branch → build → quality gate green → log → PR/hand back. Claude: verify (boundaries + gate +
semantics) → KEEP/UPDATE/REMOVE → merge. Direct commits to `main` are allowed but still audited on return.

---

## 5. Current recommended assignment (updated as phases progress)

- **NOW:** Claude builds `qubit-risk` M1 (heuristic sensitivity + Monte-Carlo CRQC timeline + Mosca) — core
  math, Claude's lane.
- **Good Antigravity hand-offs available in parallel:** remaining `qubit-api` routes + JobRunner/SSE (Gemini
  Pro); config/network scanners + more detection rules (Gemini Flash); dashboard scaffold (Antigravity).
- Claude flags the exact hand-off point in its updates.
