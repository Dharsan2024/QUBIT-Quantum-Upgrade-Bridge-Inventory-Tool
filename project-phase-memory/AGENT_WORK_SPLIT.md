# QUBIT — Multi-Agent Work Split & Boundaries

> **Purpose:** Distribute the build across several AI coding agents so Claude (the most expensive) is
> reserved for high-stakes work and doesn't carry the whole load. This file assigns work by each
> agent's strengths and sets HARD boundaries so no agent spoils the frozen core or overwrites another's
> work. Read this alongside `PROJECT_PHASE_MEMORY.md`.

---

## 0. The golden rules (apply to EVERY non-Claude agent, no exceptions)

1. **Never touch the frozen core.** `packages/qubit-core/` (the `CryptoAsset` schema, algorithm
   registry, DB models, redaction) is Claude-only. If your task seems to need a schema change, STOP and
   ask the human to route it to Claude. Additive schema changes go through Claude, never anyone else.
2. **Never edit the source-of-truth docs.** `docs/design/**`, `docs/BUILD_PLAN.md`, and
   `project-phase-memory/**` are read-only for coding agents. Only Claude or the human updates them.
3. **Stay in your lane.** Work ONLY inside your assigned package (§2), on your OWN git branch
   (`codex/<pkg>`, `copilot/<feature>`, `gemini/<task>`). One package = one agent at a time — never edit
   a package another agent is mid-flight on.
4. **Import the core, don't redefine it.** Always `from qubit_core import ...`. Conform to the frozen
   schema and to doc 05's normative REST registry. Do not invent competing models or endpoints.
5. **Pass the quality gate before you commit:**
   `uv run ruff check <pkg> && uv run mypy <pkg>/src && uv run pytest <pkg> -q` — all green.
6. **PR, never push to `main`.** Open a pull request. Claude or the human reviews and merges. This
   review step is the safety net that keeps the core intact.
7. **Log your work.** When a chunk is done, append a dated entry to `PROJECT_PHASE_MEMORY.md` §5.

Violating rule 1, 2, or 6 can corrupt the project — those are the ones that matter most.

---

## 1. Who is best at what (why the split is shaped this way)

| Agent | Real strengths | Weaknesses to avoid relying on |
|---|---|---|
| **Claude** (this agent) | System design, security-critical logic, math-heavy code, cross-module integration, code review, the research paper. Careful, follows constraints. | Cost — reserve it for work that actually needs the reasoning. |
| **OpenAI Codex** (Codex CLI / cloud agent) | Autonomous, well-specified multi-file features in a sandbox; generates a whole module from a clear spec; runs test loops until green. | Drifts on under-specified/ambiguous tasks; give it acceptance criteria. |
| **GitHub Copilot** (in-IDE, you drive) | Inline autocomplete, boilerplate, CRUD, React components, config, docstrings, filling obvious bodies. | Not autonomous; don't let it auto-accept large multi-file edits unreviewed. |
| **Google Gemini** (Gemini CLI / Code Assist) | Very large context (whole-repo reads), docs, data/experiment analysis, multimodal (diagrams/screenshots). | Can over-refactor across the repo; scope it tightly. |

---

## 2. Package/task assignments

| Area | Primary agent | Why | Boundary |
|---|---|---|---|
| `qubit-core` (schema, registry, DB, redaction) | **Claude ONLY** | Frozen contract; a mistake here breaks everything. | No other agent edits this package. |
| `qubit-risk` (Monte-Carlo CRQC, Bayesian net, XGBoost, Mosca math) | **Claude** | Statistical correctness + the paper's credibility ride on it. | Codex may add *tests/fixtures* here from a Claude-written spec, not the math. |
| `qubit-scanner` — engine + tree-sitter integration | **Claude** (skeleton), then **Codex** (bulk rules) | Engine is integration-heavy; the YAML detection rules are high-volume + well-specified. | Codex writes `catalog/rules/*.yaml` + adapters against Claude's engine; doesn't change the engine. |
| `qubit-migrate` — template transforms, IaC templates, rule pack | **Codex** | Self-contained, spec-driven (doc 03 has exact rules + goldens). | LLM-prompt/safety logic + state machine reviewed by Claude before merge. |
| `qubit-bridge` — probe/verify, compose images, bench harness | **Codex** | Well-defined I/O, testable against containers (doc 04). | Claude reviews the security-adjacent probe parsing. |
| `qubit-api` — FastAPI CRUD endpoint bodies, routers | **Copilot** (you drive) + Claude review | Mostly boilerplate over the normative registry (doc 05). | Endpoints must match doc 05 exactly; JobRunner + auth guardrails = Claude. |
| `qubit-cli` — Typer command wiring | **Copilot** | Boilerplate command plumbing. | Business logic delegates to package APIs, not reimplemented. |
| `dashboard/` — React/TS pages + components | **Copilot** (build) + **Gemini** (layout/UX passes) | UI is boilerplate-heavy; Gemini good for multi-file layout. | Data only via the REST client + fixtures; no direct DB. |
| Docs site, README polish, paper figures/tables, experiment analysis | **Gemini** | Long-context + data analysis + writing. | Does NOT edit `docs/design/**` (source of truth) — only `docs/` user-guide/site + `experiments/`. |
| Test corpora, ground-truth labeling assistance | **Gemini** / **Codex** | High-volume, well-specified. | Labels reviewed by the human (paper artifact). |
| Cross-package integration, merges to `main`, security review, the paper's core claims | **Claude** | Needs whole-system reasoning. | — |

---

## 3. When to switch models (the notify triggers)

**Stay on / go to Claude when:**
- Designing a new subsystem or changing the architecture.
- Anything touching `qubit-core` / the schema, or the `qubit-risk` math.
- Integrating two packages, or debugging a cross-cutting failure.
- Reviewing/merging a PR to `main`, or writing the research paper.

**Hand off to Codex when:** you have a fully-specified, isolated package/feature with acceptance
criteria (e.g. "implement the nginx + sshd config scanner per doc 01 §6.2, tests green") and want it
built autonomously while you spend Claude credits elsewhere.

**Hand off to Copilot when:** you're hand-writing UI/CRUD/CLI boilerplate in VS Code and want inline
completion — cheapest for high-volume typing.

**Hand off to Gemini when:** the task needs huge context (read all seven design docs at once), doc
writing, or analyzing experiment output / building paper figures.

**Claude will proactively tell you** in its replies when an upcoming task is better suited to another
agent — e.g. *"this next piece is well-specified and isolated → good Codex task, save your Claude
credits."* Watch for those notes.

---

## 4. Suggested branch + PR flow (keeps `main` always-green)

```
main                      # always green; only Claude/human merges here
 ├─ claude/qubit-core      # done (Phase 0)
 ├─ codex/scanner-rules    # Codex works here, opens PR -> Claude reviews -> merge
 ├─ copilot/api-crud       # Copilot works here
 └─ gemini/docs-site       # Gemini works here
```

Each agent: branch → build → quality gate green → PR → review → merge. Never commit to `main` directly.

---

## 5. Current recommended assignment (updated as phases progress)

- **NOW (Phase 1 start):** Claude builds the `qubit-scanner` engine skeleton + tree-sitter integration
  + the first Python rules (this is core-adjacent and defines the rule format). **Then** the bulk Python
  + Java + Go detection rules become a **Codex** task, and the dashboard scaffold a **Copilot** task.
- Claude will flag the exact handoff point in its next updates.
