# QUBIT — Project Phase Memory

> **Purpose:** This is the cross-agent handoff log. If you (or a different agent) pick up this
> project later, READ THIS FILE FIRST. It records what's been decided, what's built, what's next,
> and how to resume. Every agent working on QUBIT must append a dated entry to the CHANGELOG
> (newest at top) whenever something meaningful changes.

---

## 0. Project constraints (BINDING — read before doing anything)

- **Solo build.** Dharsan is the ONLY builder. The design docs mention a second student (Akshay) and a
  "Student A / Student B" work split — that is paperwork for the university, NOT a real division of labor.
  Ignore the two-person split when planning work; everything is done by one person + AI agents.
- **No breaks in the build.** Do NOT pace work around the academic calendar / exam breaks that appear in
  `docs/design/06-engineering-plan.md §11`. Building is continuous. That week-by-week table is reference only.
- **Agent-assisted.** The agent writes the bulk of the code; the human orchestrates, reviews, and tests.
  So the "~44 person-week" budget in the design docs is NOT the real constraint — throughput is gated by
  human review/integration time, not by hand-coding hours. Treat effort estimates as relative sizing only.
- **PRODUCTION-READY, not a toy or a demo script.** The deliverable is a production-grade application:
  real scanning of real repos/hosts, real CBOM output, real code patches applied to real files, a real
  hybrid-TLS bridge — with proper error handling, packaging (`pip install`), a test suite, CI, security
  hardening, and docs. Nothing may be faked or stubbed "just for the demo."
  **Important nuance (do not confuse with faking):** the CRQC-arrival *risk timeline* is necessarily a
  statistical Monte-Carlo **simulation** — a quantum computer that breaks RSA does not exist yet, so you
  can only MODEL its arrival from published hardware resource estimates (Webber/Gidney), never measure it.
  That one component is legitimately a simulation and that is the scientifically correct approach.
  EVERYTHING ELSE (discovery, inventory, migration, hybrid bridge) runs against real systems and must be
  production-hardened.
- **Everything offline / local.** Local LLM (Ollama), no cloud APIs, no telemetry, MIT license.
- **QUBIT does NOT run on / need a quantum computer.** It models the quantum THREAT classically. No IBM
  Quantum account, no quantum hardware, no quantum cloud service is required to build or run it. The
  qiskit/cirq/pennylane/qutip skills are only for an OPTIONAL paper illustration (a local-simulator
  Shor/Grover figure, qiskit-aer, no IBM account) — decide in Phase 3, not needed for the product.

---

## 1. Where to read the plan

| File | What it is |
|---|---|
| `docs/BUILD_PLAN.md` | Master plan: the through-line, phased execution, canonical cross-doc decisions |
| `docs/design/00-architecture-frame.md` | BINDING: stack, monorepo layout, shared `CryptoAsset` schema, milestones |
| `docs/design/01`–`06` | Six subsystem designs (discovery, risk, migrate, bridge, platform, engineering) |
| `docs/design/07-ecosystem-factcheck.md` | Web-verified July-2026 PQC ecosystem facts (versions, standards) |
| `knowledge/` + `knowledge/extracted/` | Original source material (PDFs + extracted text of the research plan) |

The design docs were adversarially reviewed and fixed; the cross-document contradictions are resolved by
the canonical decisions in `docs/BUILD_PLAN.md §4`. Trust the BUILD_PLAN when docs disagree.

---

## 2. Current status

**Phase: PRE-BUILD (planning complete, environment PARTIALLY set up, no code written).**

Build machine: Intel i7-14700HX (20c), 16 GB DDR5-5600, **NVIDIA RTX 4060 Laptop (8 GB VRAM)**, Windows 11.
Verdict: well-suited. 7B LLM runs on the GPU (VRAM), keeping it off system RAM. The 16 GB RAM is the only
tight spot when Docker + dashboard + browser + IDE run together — mitigations in §3.

- [x] Requirements + full design planned and reviewed (docs 00–07 + BUILD_PLAN).
- [x] Project constraints captured (solo, continuous, agent-assisted, PRODUCTION-ready).
- [x] Prerequisites list defined (see §3 below).
- [~] Dev environment PARTIAL (verified 2026-07-16):
      - OK on PATH: git 2.55, Python **3.14.0**, uv 0.10.9, Node **24.18**, npm 11.16.
      - **MISSING/not launched:** `docker` and `ollama` not on PATH → Docker Desktop and Ollama must be
        installed AND launched (Docker Desktop adds its CLI to PATH only after first launch + often needs a
        reboot/WSL2 enable; Ollama runs as a background service). Re-verify in a NEW terminal after launching.
      - Python: system has 3.14 but the risk engine pins `<3.14` (pgmpy/torch). NON-ISSUE — uv will download
        and pin **3.12** for the workspace (`uv python pin 3.12`); system Python is irrelevant.
      - Node 24 (not 22 LTS) is fine for Vite 8 + React 18. uv 0.10.9 works; optional bump to ≥0.11.
      - Model not pulled yet: `ollama pull qwen2.5-coder:7b-instruct-q4_K_M` (after Ollama runs).
- [x] Environment verified 2026-07-16: Docker 29.6.1 engine running, Ollama 0.32.0 + qwen2.5-coder:7b
      pulled, RTX 4060 (8188 MiB) detected. (Also present: gemma4:12b — 7B is the default.)
- [x] **Phase 0 DONE:** uv monorepo bootstrapped; `qubit-core` built + **CryptoAsset schema FROZEN**;
      6 sibling packages stubbed; `uv sync` resolves all 7; **quality gate green** (ruff + mypy --strict +
      31 tests). Git repo initialized (branch `main`). NOT yet committed / pushed to GitHub.
- [~] **Phase 1 (M1) IN PROGRESS** — `qubit-scanner` code-scan engine DONE:
      - `qubit-rule/v1` YAML rule format + loader (compiles tree-sitter 0.26 `Query`); bad rules fail loudly.
      - `CodeScanner`: walk → parse → import-gate shortlist → run rules → `Detection`; error-node guard;
        string-literal + single-assignment string-constant folding + int-literal resolver.
      - `normalize()`: Detection → `CryptoAsset` via qubit-core (canonical resolve + quantum verdict +
        **evidence redaction** + fingerprint). Unknown algos kept as `UNKNOWN(...)`, low-confidence.
      - `scan_paths()` public API (complete ScanResult, .gitignore-aware, 2 MB cap, occurrence dedup).
      - First Python rules: hashlib (MD5/SHA-1), cryptography (RSA keygen w/ key_size, EC keygen).
      - 24 scanner tests incl. auto-generated rule-example tests (every rule ships its own fixtures).
      - **Gate GREEN: ruff + mypy + 55 tests total.** tree-sitter 0.26 + language-pack 1.12.5.
      - STILL TODO in M1: bulk detection rules (more Python libs, Java, Go) — **good Codex task now that
        the format is proven**; minimal CBOM 1.7 export; Java grammar rules; `qubit rules lint/test` CLI.
- [ ] Phase 1 (M1) remainder + Phase 2.  ← next
- [ ] Phase 2 (M2 feature-complete + live 4-phase demo).
- [ ] Phase 3 (M3 hardening + paper experiments).

---

## 3. Prerequisites to install BEFORE building (Windows 11)

**Must have before Phase 0** (install commands use `winget`; run in PowerShell):

| # | Tool | Why | Install |
|---|---|---|---|
| 1 | Git | version control | `winget install --id Git.Git -e` |
| 2 | Python 3.12 | primary dev interpreter (frame min; best library support — pgmpy/torch lag on 3.14) | `winget install --id Python.Python.3.12 -e` |
| 3 | uv | monorepo/workspace + lockfile + task runner (the whole build uses uv) | `winget install --id astral-sh.uv -e` |
| 4 | Docker Desktop | OpenSSL-3.5 base image, TLS test matrix, demo-lab, sandboxed patch validation | `winget install --id Docker.DockerDesktop -e` |
| 5 | Node.js 22 LTS | React/TypeScript dashboard toolchain | `winget install --id OpenJS.NodeJS.LTS -e` |
| 6 | Ollama | local LLM runtime for code migration | `winget install --id Ollama.Ollama -e` |
| 7 | VS Code | editor (already installed) | — |

**After installing, pull the LLM model** (one-time, ~4.7 GB): `ollama pull qwen2.5-coder:7b-instruct-q4_K_M`
(no GPU? also pull the small fallback: `ollama pull qwen2.5-coder:1.5b-instruct-q4_K_M`)

**Needed later, can defer:**
- **GitHub account** (free) — repo, Actions CI, GHCR container registry, Pages docs. Needed early in Phase 0 for the repo/CI, but you can build locally first.
- **Wireshark** (`winget install --id WiresharkFoundation.Wireshark -e`) — for the committee demo's packet capture (Phase 2+ / demo day).
- **PyPI account** (free) — only for the `v0.1.0` publish step (Phase 1 release). Reserve the `qubit-*` package names when you get there.
- **HuggingFace account** (free, optional) — only if fine-tuning DistilBERT (Phase 2); the base model downloads without auth.

**Hardware (target machine):**
- RAM: **16 GB minimum** (Ollama 7B needs ~8 GB free alongside Docker + dashboard).
- GPU: **NVIDIA ≥8 GB VRAM strongly recommended** for Ollama (CPU works but a patch takes minutes not seconds). No GPU → use the 1.5B model or template-only migration path.
- Disk: **~50 GB free** (Docker images ~10–15 GB, Ollama models ~5–10 GB, node_modules, venvs, corpora).
- CPU: 4+ cores.

**Recommended, not required:**
- **WSL2** (`wsl --install`) — doc 06 prefers it as the canonical dev env; Docker + Linux tooling behave better. Native Windows works too (the designs were made Windows-aware).
- No paid/cloud services are needed anywhere — the project is deliberately offline/local.

**16 GB RAM management (important on this machine):**
- Run **Ollama natively on Windows** (uses the RTX 4060 VRAM) — the winget install already did this. Do NOT run Ollama inside Docker (that would compete for the 16 GB). The API container points at `http://host.docker.internal:11434` (already the design's plan, doc 05).
- Cap Docker's WSL2 backend so it doesn't starve Windows: create `%USERPROFILE%\.wslconfig` with `[wsl2]` / `memory=8GB` / `processors=12`, then `wsl --shutdown`.
- During heavy runs (LLM patch + Docker + dashboard), keep browser tabs modest. It all fits; just don't run everything maxed at once.

**No quantum hardware/accounts needed** — see §0. Product models the quantum threat classically; qiskit/etc. are optional Phase-3 paper illustration only.

**Baseline knowledge** (you're a cybersecurity student, so mostly covered): Python; Git; Docker basics; TLS/PKI fundamentals; PQC concepts (ML-KEM/ML-DSA, HNDL, Mosca's inequality — all explained in the design docs). React/TS can lean on the agent.

---

## 4. Next action when resuming

**Phase 0, step 1:** bootstrap the uv monorepo per `docs/design/06-engineering-plan.md §3.1` and land
`qubit-core` (the binding `CryptoAsset` Pydantic + SQLAlchemy models, algorithm registry, fingerprint fn),
then **freeze the CryptoAsset schema** — everything downstream depends on it. See `docs/BUILD_PLAN.md §5 Phase 0`.

Do not start until the §3 "must have" tools are installed and `ollama pull` has finished.

---

## 4b. Prompts → see CORE_PROMPTS.md (single source of truth)

All operating prompts live in **`project-phase-memory/CORE_PROMPTS.md`** (Part B), alongside an
explanation of how the multi-agent workflow works (Part A). Use:

- **B1 Universal Handoff** — paste FIRST to any agent taking over (fresh start / model switch).
- **B2 Orchestrator Resume** — paste to Claude when returning to review + absorb sub-agent work.
- **B3 Sudden Credit-Out Continuation** — paste when an agent was cut off mid-task.
- **B4 Task Assignment** — template to scope a concrete task to a sub-agent.

They were moved there to avoid two copies drifting. Edit prompts in CORE_PROMPTS.md only.

---

## 5. CHANGELOG (newest first — every agent appends here)

### 2026-07-17 06:29 IST — CORE_PROMPTS.md added (canonical prompt + workflow reference)
- Created `project-phase-memory/CORE_PROMPTS.md`: **Part A** = how the multi-agent workflow works
  (shared-memory files, roles, the handoff loop, safety mechanisms, which-prompt-when decision table) —
  the reusable mechanism, not project subject matter; **Part B** = all operating prompts (B1 universal
  handoff, B2 orchestrator resume, B3 sudden credit-out continuation, B4 task-assignment template).
- De-duplicated: PROJECT_PHASE_MEMORY §4b/4c/4d now POINT to CORE_PROMPTS (single source of truth for prompts).
- Build state unchanged (no code touched this turn). **Next** still: CBOM 1.7 export + `qubit rules
  lint/test` CLI (Claude), or delegate a scoped task.

### 2026-07-17 — Orchestration: verified + merged Codex rules; agent infra; registry fix
- **Reviewed Codex's `codex/scanner-rules`** (33 rules: py 18 / java 8 / go 7). Verdict **KEEP**: stayed in
  lane (rules only), gate green, rules semantically sound. Logged in SUBAGENT_WORK_LOG.md.
- **Orchestrator-found bug FIXED (qubit-core, Claude's lane):** bare `"RSA"/"EC"/"DSA"` (no key size, e.g.
  `Cipher.getInstance("RSA")`, JWT RS256) previously resolved to None → normalized to UNKNOWN → marked
  quantum-SAFE (wrong for a security tool). Added Shor-vulnerable bare-family fallback in `algorithms.resolve`
  (size still wins: `resolve("RSA",3072)`→RSA-3072). +2 tests. Gate green, 118 tests.
- **Agent infrastructure added** (this turn's user request):
  - PROJECT_PHASE_MEMORY §4c **ORCHESTRATOR RESUME PROMPT** (Claude reviews sub-agent work → keep/update/remove).
  - PROJECT_PHASE_MEMORY §4d **SUDDEN CREDIT-OUT CONTINUATION PROMPT** (recover interrupted work).
  - Strengthened §4b universal prompt STEP 4: continuous logging, log BEFORE running out, route sub-agents
    to their own log, timestamps via `date`.
  - New **SUBAGENT_WORK_LOG.md** (non-Claude agents log here) + **USER_PROMPTS_LOG.md** (every user prompt, timestamped).
  - AGENT_WORK_SPLIT.md: added **Google Antigravity** as a switchable agent; reaffirmed Claude as orchestrator.
- Merged `codex/scanner-rules` → `main`.
- **Next:** minimal CBOM 1.7 export + `qubit rules lint/test` CLI (Claude), or hand more rules/CBOM to a sub-agent.

### 2026-07-16 (Phase 1 start) — qubit-scanner code-scan engine built + tested
- Built the whole code-discovery pipeline (Claude's lane, engine + rule format):
  `catalog/` (qubit-rule/v1 schema + loader compiling tree-sitter 0.26 Query), `code/` (languages,
  resolver, CodeScanner), `normalize.py` (Detection→CryptoAsset via qubit-core), `api.py` (scan_paths).
- First Python rule packs: `rules/python/hashlib.yaml` (MD5, SHA-1), `rules/python/cryptography.yaml`
  (RSA keygen + key_size, EC keygen). Rules are DATA — new rule = new YAML + embedded examples.
- Verified end-to-end: scans real Python → canonical assets (RSA-2048/MD5) with quantum verdicts,
  fingerprints, and **redacted evidence** (planted AWS key was scrubbed). 24 tests; full gate green.
- Deps added to qubit-scanner: tree-sitter 0.26, tree-sitter-language-pack 1.12.5, pyyaml, pathspec.
- **HANDOFF FLAG:** the rule format is proven → the BULK detection rules (Python pycryptodome/ssl/jwt,
  Java JCA/BouncyCastle, Go crypto) are now a well-specified **Codex** task (see AGENT_WORK_SPLIT §2:
  Codex writes catalog/rules/*.yaml against the engine, doesn't touch the engine or qubit-core).
- **Next:** either (a) Claude builds minimal CBOM 1.7 export + `qubit rules lint/test` CLI, or
  (b) hand the bulk rules to Codex while Claude does CBOM. Recommend (b) to save Claude credits.

### 2026-07-16 (Phase 0 shipped to GitHub) — remote push + DB decision + multi-agent split
- GitHub remote: `origin` = https://github.com/Dharsan2024/QUBIT-Quantum-Upgrade-Bridge-Inventory-Tool.git ,
  branch `main`. Push only committed source (the `.gitignore`/`.gitattributes` keep out venvs/models/secrets).
- **Database decision (important):** default stays **offline SQLite** (backs the "no exfiltration" claim).
  Neon/Postgres is wired as an **optional** hosted backend via the `QUBIT_DB_URL` env var (see `.env.example`)
  + the `qubit-core[postgres]` extra (`psycopg`). The DB code already supports it (session.py only applies
  SQLite pragmas to sqlite URLs). NOTE: the URL the user gave is Neon's **Data-API (REST)** endpoint —
  SQLAlchemy needs the **Postgres connection string** instead (`postgresql+psycopg://…neon.tech/neondb?sslmode=require`),
  which must come from the Neon dashboard. NOT hardcoded; NOT the default. Real scanned data in a cloud DB
  leaves the machine — only for a hosted demo, never the offline core.
- Added **`project-phase-memory/AGENT_WORK_SPLIT.md`** — assigns work across Claude / Codex / Copilot /
  Gemini by strength, with hard boundaries (no one but Claude touches qubit-core or the design docs; PR-only
  to main) and model-switch triggers. See that file before delegating.

### 2026-07-16 (Phase 0 complete) — Repo bootstrapped + qubit-core built, schema FROZEN
- Environment verified: Docker 29.6.1, Ollama 0.32.0 + qwen2.5-coder:7b, RTX 4060 8 GB.
- Git repo initialized on branch `main` with identity Dharsan L <astradyne.recruitment@gmail.com>.
- Root repo scaffold: `.gitignore`, `LICENSE` (MIT), `README.md`, root `pyproject.toml` (uv workspace +
  ruff/mypy/pytest/poe config), Python pinned to **3.12** via `.python-version` (uv-managed; system is 3.14).
- **`qubit-core` fully built and production-clean:**
  - `schemas.py` — the **FROZEN binding CryptoAsset** + all enums/nested models (extra="forbid", UTC-aware).
  - `algorithms.py` — canonical algorithm registry (RSA/ECC/AES/SHA/ML-KEM/ML-DSA/hybrid) + alias resolver.
  - `fingerprint.py` — POSIX-normalized cross-platform fingerprint (Windows==Linux, line-drift tolerant).
  - `redaction.py` — evidence redaction (PEM keys / secrets / high-entropy) — the security guarantee.
  - `db/` — SQLAlchemy models (Project/Scan/Asset) + engine with SQLite WAL pragmas.
  - `mapping.py` — CryptoAsset <-> AssetRow flatten/unflatten.
  - 31 tests (schema, registry, fingerprint incl. Windows/Linux convergence, redaction incl. "no PEM
    survives", DB round-trip). **Gate GREEN: ruff + mypy --strict + 31 passed.**
- 6 sibling packages (scanner/risk/migrate/bridge/api/cli) stubbed so `uv sync --all-packages` resolves.
- Added the **UNIVERSAL HANDOFF PROMPT** (§4b) for switching agents.
- **NOT yet committed to git or pushed to GitHub** (username Dharsan2024). Do that next, then start Phase 1.
- **Next:** commit Phase 0; create the GitHub repo `qubit` (public); then Phase 1 M1 — start `qubit-scanner`
  (tree-sitter Python+Java code scanner) + minimal CBOM export, per docs/design/01.

### 2026-07-16 (later) — Machine specs + toolchain verified; production-ready constraint hardened
- Build machine recorded: i7-14700HX / 16 GB / RTX 4060 8 GB / Win 11 → good fit; 16 GB RAM is the tight spot (§3 mitigations).
- Verified toolchain: git/python(3.14)/uv/node(24)/npm present; **docker + ollama NOT on PATH** — must be
  launched (Docker Desktop) / service-started (Ollama), then re-verified in a fresh terminal.
- Added **PRODUCTION-READY** as an explicit binding constraint (§0), with the simulation nuance (only the
  CRQC timeline is a legitimate Monte-Carlo simulation; everything else runs on real systems).
- Clarified **no quantum hardware/accounts needed** (§0); qiskit/etc. optional for a Phase-3 paper figure only.
- Decision: dev venv pins **Python 3.12 via uv** regardless of system 3.14 (pgmpy/torch compat).
- **Blocked-on-user before Phase 0:** launch Docker Desktop + Ollama and confirm on PATH; `ollama pull`
  the 7B model; provide GitHub username + repo name (default `qubit`) + public/private choice.

### 2026-07-16 — Planning complete; constraints + prerequisites captured
- Full design planned, adversarially reviewed, and fixed: `docs/design/00`–`07` + `docs/BUILD_PLAN.md`.
- Recorded project constraints: **solo builder, continuous (no academic-calendar breaks), agent-assisted.**
  → design docs' two-person split and exam-break timeline are now reference-only.
- Defined the prerequisites list (§3). No code written yet, no environment set up yet.
- Installed helper skills to `~/.claude/skills/` (qutip, qiskit, pennylane, cirq) and the
  document-skills + example-skills plugins — general tooling, not project source.
- **Next:** install the §3 tools, then Phase 0 monorepo bootstrap + freeze `qubit-core` schema.

<!-- TEMPLATE for the next entry (copy above this line):
### YYYY-MM-DD — <short title>
- <what changed / what was built / what decision was made>
- <files touched>
- **Next:** <the immediate next action>
-->
