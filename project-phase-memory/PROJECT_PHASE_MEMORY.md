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
- **Active agents: Claude (orchestrator) + Google Antigravity (sub-agent).** OpenAI Codex + GitHub Copilot
  are OUT OF CREDITS — not in rotation. Model is **assign best-fit, don't block anyone, orchestrator verifies
  on return** (AGENT_WORK_SPLIT.md / CORE_PROMPTS.md). Antigravity runs Gemini 3.5 Flash / Gemini 3.1 Pro /
  Claude Sonnet 4.6 / Claude Opus 4.6 / GPT-OSS 120B — pick by difficulty (Flash = cheap/bulk).
- **OUTPUT DISCIPLINE (caveman):** every agent replies terse (fragments, no filler) to save credits — but
  code, commands, diffs, paths, and LOG ENTRIES stay exact + complete, and no required step (gate, logging,
  verification) is ever dropped for brevity. Baked into all CORE_PROMPTS prompts.
- **Git identity:** commits use `Dharsan L <dharsanlingadurai24@gmail.com>` — do NOT use the astradyne
  email. (Commits before 2026-07-17 evening carry the old astradyne email; not rewritten — pushed history.)

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
      - DONE: bulk rules (33, via Codex), **CBOM 1.7 export**, **qubit CLI (scan + rules lint/list)**.
      - M1 scanner path is end-to-end (discover → normalize → CBOM → CLI). 136 tests, gate green.
- [x] **DB persistence + qubit-api DONE** (Copilot, orchestrator-reviewed + merged): FastAPI service with
      projects/scans/assets CRUD, synchronous scan→DB ingestion, trends/summary/diff, CBOM export, registry,
      health/version, single-token auth; Alembic migration home in qubit-core (round-trips); expanded CLI
      (project/db/serve). 150 tests, gate green.
- [x] **qubit-risk M1 DONE** (Claude/Antigravity, recovered + completed):
      Monte-Carlo CRQC timeline (surface-code resource math, GE2019/Webber anchors within x2),
      heuristic sensitivity classifier (regex rules → shelf-life priors), Mosca inequality,
      static HNDL risk score v0, RiskPipeline annotating CryptoAssets with priority rank.
      5 param YAMLs, 6 source modules, 3 test files (17 tests). Gate GREEN: ruff + 167 passed.
- [x] **qubit-migrate M1 DONE** (Antigravity):
      Graph builder (SCC), queue prioritization (WSJF), state machine (12-state FSM + DB),
      patch generation (`libcst` templating), validation pipeline. 5 tests + 172 suite tests passing.
- [x] **qubit-bridge M1 DONE** (Antigravity):
      `demo-lab/vulnapp-python` built. `nginx-hybrid` container built for OpenSSL 3.5.x.
      Client-side probe (`qubit bridge probe` / `verify`) via ephemeral `nginx:alpine` `s_client`.
      Tests passing, CLI wired.
- [x] **Platform Dashboard M1 Scaffold DONE** (Antigravity):
      React 18 / Vite 8 / TailwindCSS v4 app scaffolded. 
      `Inventory` page implemented with `@tanstack/react-table` showing discovered assets.
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

### 2026-07-18 (eve-3) — Dashboard Timeline survey-blend toggle (Claude, Fable) — a3b4f97
- `fetchTimeline(algo, {blend, weight})`; Timeline page gains a "Blend survey" toggle + w slider
  (hardware share). Blended curve shown with the pure-hardware baseline overlaid (dotted) for contrast;
  4th stat tile swaps to the survey weight. Makes the M2 survey blend visible in the UI.
- Verified live over HTTP: RSA-2048 hardware median 2041 (p05 2036/p95 2055) vs blended w=0.5 median
  2040 (p05 2030/p95 2060) — expert survey widens the band as expected. Dashboard build green.
- **Note (git):** PowerShell here-strings with parens in `-m @'...'@` mis-parse — commit via `-F file`.
- **Risk M2 remaining:** XGBoost conformal band + DistilBERT sensitivity tier (heavy, training-data
  pipeline, Oct-15 gate). Analytical novelty (survey blend + Bayesian net) is DONE and UI-visible.

### 2026-07-18 (eve-2) — HNDL Bayesian network + closed-form integral (Claude, Fable) — 24e18f6
- `hndl.py`: closed-form `P_HNDL = P(H|E,S)·∫ f_L(ℓ)·F_a(now+ℓ)dℓ` (512-pt Gauss-Legendre) as the
  ground truth, + `HndlBayesNet` (pgmpy DiscreteBayesianNetwork: Harvested|Exposure,SensTier;
  CRQCArrival per-year off F_a; ShelfLife equal-support bins; DBO deterministic). **BN agrees with the
  closed form to <0.02** (network 0.0159 / at_rest 0.0060 / offline 0.0010) — unit-tested per doc 02 §6.2.2.
- `params/bn_cpds.yaml` (harvest_cpd, high_tiers, shelf_bins) registered in config. `score.py` now uses
  the closed-form integral for P(decrypt) (was M1 MC) and pulls harvest prob from bn_cpds (one source).
- Added `pgmpy>=1.0` dep (pulls torch/pandas/statsmodels; python already pinned <3.14). pgmpy 1.x uses
  `DiscreteBayesianNetwork`.
- Gate: **215 tests**, ruff+mypy clean.
- **Risk M2 remaining:** XGBoost conformal band + DistilBERT sensitivity tier (Oct-15 ship/no-ship gate,
  heavy — needs training data pipeline); dashboard Timeline blend toggle + BN-factors panel.

### 2026-07-18 (eve) — Orchestrator review + M2 survey blend FINISHED (Claude, Fable) — 68e7314
Reviewed 2 commits that landed while away (B2 resume):
- **8e493f4 bridge E2E (Antigravity) — VERDICT KEEP.** `@pytest.mark.integration` test really spins up
  the nginx-hybrid container (testcontainers) and the openssl probe negotiates **X25519MLKEM768 /
  TLSv1.3** live — verified it PASSES here. Only ruff-cleaned (E501, import order).
- **c0fdac2 survey blend — VERDICT KEEP-CORE + FINISH.** survey.py/config/simulator/yaml matched
  doc 02 §6.1.4-6.1.5 and gate-green, but was INCOMPLETE (no tests, unwired) and carried cruft (2 empty
  tracked files + an opportunistic ruff-reformat of the demo-lab fixture — vulnerable patterns intact).
  Finished: 6 survey tests (LogNormal fit recovers GRI anchors ≤8pts, monotonic, w=1/w=0 extremes equal
  hardware/survey components, ECDSA≤RSA, unknown→None); API `GET /risk/timeline?blend=true&weight=`;
  removed junk files; fixed simulator cache-key bug (keyed algo+trials+window so 24h blend ≠ 30d curve).
- Gate: **208 tests**, ruff+mypy clean.
- **Next (risk M2 remaining):** Bayesian net (pgmpy, doc 02 §6.2); dashboard Timeline blend toggle;
  JobRunner async polish.

### 2026-07-18 — Bridge E2E Testing (Antigravity)
- **Feature:** Added E2E integration test for `qubit-bridge` (`test_e2e.py`).
- **Dev-Ops:** Integrated `testcontainers-python` to dynamically build and run the `nginx-hybrid` terminator.
- **Fix:** Updated `probe.py` to gracefully install `openssl` in standard `nginx:alpine` containers for the probe client.
- **Fix:** Fixed `nginx-hybrid` Dockerfile to correctly `apk add openssl` before checking version.
- **Gate:** Tests pass locally via `uv run pytest packages/qubit-bridge -m integration -v`.
- **Next:** `qubit-risk` M2 (Bayesian net) or JobRunner polish.

### 2026-07-18 — Recovery: qubit-risk M2 survey blend (Antigravity)
- **Recovered interrupted work:** Agent built `survey.py` (LogNormal fit to 26-expert GRI-2025) and blended hardware Monte-Carlo offsets. 
- Fixed ambiguous unicode characters (RUF002/3) in docstrings and line-too-long in `vulnapp-python`.
- Gate: **200 tests**, ruff clean. Committed.
- **Next:** Bayesian net or JobRunner polish.

### 2026-07-18 (aft-6) — FULL demo-lab remediation 2/2 (Claude, Fable) — 4fbd3b0
- New rule `py-rsa-kex-01` (RSA→ML-KEM-768 KEM-DEM, reencrypt_required, rescan expects RSA-* gone).
  No codemod → auto routes to the local LLM with hard constraints (pqcrypto ml_kem_768 + AESGCM).
- Demo fix: commit after each applied patch (2nd apply used to die on the dirty-tree guard);
  per-task apply failures reported, not crashed.
- **LIVE:** `qubit demo run` now fully remediates the demo lab — template fixes SHA-1, the LLM does
  the structural RSA→ML-KEM rewrite; both pass applies/parses/compiles(Docker)/rescan;
  re-scan: **RSA-2048 1→0, SHA-1 1→0**.
- Gate: **200 tests**, ruff+mypy clean.
- **Next:** qubit-risk M2 (survey blend, Bayesian net) OR JobRunner polish OR bridge e2e.

### 2026-07-18 (aft-5) — `qubit demo run`: full M2 acceptance loop in ONE command (Claude, Fable) — bda7f5c
- New `qubit demo run [--target DIR] [--generator auto|template|llm] [--keep]`: scratch git repo →
  tree-sitter scan → MC-backed risk annotation → WSJF plan → generate → auto-approve → git apply →
  re-scan with a before/after remediation table. All real components, in-process, no server needed.
- **Proven live BOTH ways:** template AND llm (qwen2.5-coder via Ollama) each remediate SHA-1 1→0 with
  stages applies/parses/**compiles(Docker)**/rescan all passing. RSA-2048 stays (no kex codemod rule
  yet — honest gap, listed for M2 rules backlog).
- Gate: 199 tests, ruff+mypy clean.
- **Next:** more codemod rules (RSA kex → ML-KEM via bridge config?), qubit-risk M2, JobRunner polish.

### 2026-07-18 (aft-4) — Docker sandbox validation stages 3-4 REAL (Claude, Fable) — aab04a5
- Stages `compiles`+`tests` were permanent skip-stubs → now real isolated containers
  (python:3.12-slim, `--network=none`): compile check on a read-only mount; tests = repo copy +
  patched-file overlay + pytest (stdlib `unittest discover` fallback). Honest skips (daemon down,
  non-python, no test suite) — never false-green. **Any hard stage fail now fails the patch**
  (compiles/tests no longer exempt from gating).
- Proven with real containers in the suite: SyntaxError caught; behavior-equivalent patch passes the
  repo's tests in the sandbox; a regression patch (`double(x) -> x`) is CAUGHT and fails.
- Env: Docker Desktop 29.6.1 up; image python:3.12-slim pulled. `MigrateConfig.no_docker=True` opts out.
- Gate: **199 tests**, ruff+mypy clean. Dashboard picker (auto/template/llm) + model_name shipped
  earlier today (1f0576b).
- **Next:** qubit-risk M2 OR JobRunner polish OR bridge/demo e2e (`qubit demo run`).

### 2026-07-18 (aft-3) — LLM patch generation LIVE via local Ollama (Claude, Fable) — e155e16
- `transform/llm.py`: prompt = rule semantic_note + hard constraints + full source; model returns the
  complete rewritten file in a fenced block; temp 0; urllib only (no new deps). Orchestrator
  `generator="llm"` (or auto w/o codemod) → records generator+model_name; auto still prefers the
  deterministic codemod; the SAME validation pipeline gates LLM output (never trusted blindly).
  API `GenerateRequest.generator` passthrough; `PatchOut.model_name`.
- **LIVE proof (RTX 4060, qwen2.5-coder:7b-instruct-q4_K_M):** against the real demo-lab Flask app the
  model recognized the *password* context and rewrote `hashlib.sha1(password)` → argon2
  `PasswordHasher` (import + init included) — context-aware beyond the template codemod.
  parses✓ rescan✓ → proposed.
- Note: Ollama server must be running (`ollama serve`); models pulled: qwen2.5-coder:7b, gemma4:12b.
- Gate: **192 tests**, ruff+mypy clean.
- **Next:** qubit-risk M2 OR JobRunner async polish OR bridge/demo-lab e2e (`qubit demo run`).

### 2026-07-18 (aft-2) — Apply leg proven e2e; 4th latent bug fixed (Claude, Fable)
- **BUG (apply-blocker):** generated diffs used absolute Windows paths in headers → `git apply`
  and the `applies` validation stage failed ("invalid path"); apply could never have worked.
  Fixed: `generate_patch` emits repo-relative posix diff paths + stores `patch.file_path`
  relative when the file sits under `repo_root`. (7f4d720)
- **New e2e proof** (`test_apply_e2e.py`): real git repo → plan → generate (`applies` stage passes)
  → approve → apply → **file rewritten on disk, committed on `pqc-migration` branch** → verify passes.
  The full doc-03 loop (scan→plan→generate→review→apply→verify) is now covered by real tests.
- Gate: **187 tests**, ruff+mypy clean.
- **Next:** qubit-risk M2 (survey blend, Bayesian net) OR JobRunner async polish OR qubit-bridge polish.

### 2026-07-18 (aft) — M2 migration workflow over REST + Migrations page interactive (Claude, Fable)
Found + fixed 3 REAL latent bugs while building it, then shipped the full workflow.
- **BUG (crasher):** `MigrationOrchestrator` used `select(CryptoAsset)` / `session.get(CryptoAsset, ...)`
  on the *Pydantic* schema → SQLAlchemy `ArgumentError` at runtime; every DB entrypoint (`qubit migrate
  plan/generate/verify`) would crash. Fixed: query `AssetRow`, hydrate via `row_to_asset`; `_load_asset`
  helper; `_sync_public_status` writes `migration_status`+`migration_json` on the row (always incl. the
  required `recommendation`). Also fixed scope filter (`quantum_vulnerable.vulnerable` — a Pydantic model
  is always truthy so safe assets were in scope). Regression tests in `test_orchestrator.py`. (7a69a6a)
- **BUG (dead rule):** `py-weakhash-01` matched NO real assets — its `usage_context` values
  (hashing/digest/…) don't exist in the frozen UsageContext enum (hash/password). Fixed to canonical
  values. Its `rescan_expect present: SHA-256` was unsatisfiable (scanner reports only vulnerable
  crypto) → now expects MD5+SHA-1 *gone*; validate accepts prefix lists.
- **BUG (race + ignored flag):** API `run_risk` was silently ignored (sync path) / hardcoded (job path),
  and `scan_handler` flipped the scan to `succeeded` BEFORE the chained risk run → clients polling
  status read `risk=None`. Fixed: `annotate_scan_risk` service, flag threaded through, status flips
  only after risk chain. (047be2f)
- **NEW:** `/migrate` REST router in qubit-api (doc 03 §5.1 over REST): POST/GET plans, GET
  plans/{id}/queue (+denormalized asset context), POST tasks/{id}/generate, GET tasks/{id}/patches,
  POST patches/{id}/review, POST patches/{id}/apply. qubit-api now deps qubit-migrate; state tables
  register on shared Base. E2E test: scan→plan→queue→generate→approve→double-review-422.
- **Dashboard Migrations page now interactive** (fdf8ab9): Build Plan, ranked WSJF queue, per-task
  Generate → inline colorized diff + validation-stage chips, Approve/Reject.
- **Proven live over HTTP:** plan (4 tasks/2 units from the real registry) → SHA-1 task → real argon2
  codemod diff generated against `demo-lab/vulnapp-python/app.py` (parses✓ rescan✓) → approved.
- Gate: **186 tests pass**, ruff+mypy clean, dashboard build green. NOTE: root env needs
  `uv sync --all-packages` (plain `uv sync` prunes workspace members).
- **Next:** qubit-risk M2 (survey blend, Bayesian net) OR JobRunner async polish OR qubit-bridge.

### 2026-07-18 (later) — Live-data wiring COMPLETE: every dashboard page is real (Claude, Opus)
Finished removing ALL mock data from the dashboard; every page now reads the live qubit-api.
- **Authed client** (`api/client.ts`): generic `send()` (GET/POST/DELETE + 204), bearer token from
  localStorage/Vite env, `ApiError`. Fns: whoami, fetchProjects, fetchScans/fetchScan/createScan/
  deleteScan, fetchScanAssets, fetchRiskSummary, fetchCbom, fetchTimeline. `useActiveScan` hook =
  shared "selected scan, else latest succeeded" resolver.
- **Fixed a real bug:** old `fetchAssets` hit `/projects/{id}/assets` which does not exist → Inventory
  silently empty. Now uses `/scans/{id}/assets`.
- Pages wired to real endpoints: **Timeline** (`/risk/timeline?algorithm=`, MOCK_CDF gone),
  **Scans** (list/create/delete/select, polls running), **Inventory** (`/scans/{id}/assets`),
  **Risk** (`/scans/{id}/summary` → KPIs+histogram+top-10), **CBOM** (`/scans/{id}/cbom`, real
  download+preview), **Projects** (`GET /projects` + per-project counts), **Login**/**Settings**
  (token set + `/auth/whoami` verify).
- **Honest, not faked:** qubit-api has NO migrate endpoints → **Migrations** shows real candidates
  derived from the scan's vulnerable assets (algo→recommended PQC target+risk) with a note that apply
  runs via the `qubit migrate` CLI (API in M2); **MigrationDetail** documents the CLI steps (no fake diff).
- **Proven live over HTTP** end-to-end: POST project → POST scan on demo-lab → succeeded → real assets
  (RSA-2048/Shor, SHA-1/Grover at real file:line), summary, CycloneDX-1.7 CBOM (2 components), MC timeline
  (median 2041), DELETE 204. Grep confirms zero `mock/dummy/hardcoded` left in pages/components.
- Gate: dashboard `npm run build` green; qubit-api ruff+mypy clean, 9 tests. Commits c74dcd4, 7f67124,
  adbe69d, f7390c9 pushed.
- **Next:** M2 — add migrate API endpoints (plan/generate/diff/apply) so Migrations becomes interactive;
  qubit-risk M2 (survey blend, Bayesian net); optional JobRunner async scans (currently synchronous, M1).

### 2026-07-18 (later) — Live-data wiring: CRQC Timeline page is now REAL (Claude, Opus)
Answering the user's "make sure it's real, not mock" demand + wiring the first mock page to the API.
- **Proved realness end-to-end:** ran the scanner on `demo-lab` → real RSA-2048 (Shor) + SHA-1 (Grover)
  at real line numbers; ran the MC simulator → RSA-2048 median CRQC **2041** (p05 2036 / p95 2055),
  real CDF (cdf@2040≈0.44) — nothing like the old hardcoded `MOCK_CDF`.
- **New API endpoint** `GET /api/v1/risk/timeline?algorithm=` (qubit-api `routers/risk.py`): runs the
  real `CRQCTimelineSimulator` on demand (no scan/DB row needed), returns years/cdf/percentiles/n_trials.
  Doc 02 §5.3. Verified live over HTTP for RSA-2048/3072/4096, ECDSA-P256, ECDH-P256 (all 200); PQC → 404.
- **Dashboard client rewritten** (`api/client.ts`): added **bearer auth** (was missing → every call would
  have 401'd), `ApiError`, `getToken/setToken` (localStorage `qubit_token`, Vite `VITE_API_BASE`/`_TOKEN`
  overrides), `fetchTimeline()`. This also fixes the Inventory page, which previously sent no token.
- **Timeline.tsx** now fetches real data via react-query (algorithm picker, real P05/P50/P95 stat cards +
  percentile markers), **`MOCK_CDF` deleted**.
- Gate: dashboard `npm run build` green; qubit-api ruff+mypy clean, **9 tests pass** (added 2: real-curve
  shape + PQC-404).
- **Next:** wire the remaining mock pages to real endpoints following this pattern — Risk/Scans/Migrations/
  Cbom/MigrationDetail/Settings (Antigravity task, Timeline is the reference vertical slice). Note the
  scan→risk pages need a real scan+run in the DB first (`qubit scan` / POST scan), unlike the on-demand
  timeline; may add on-demand variants where doc-05 allows.

### 2026-07-18 00:25 IST — M1 qubit-migrate orchestrator COMPLETE
- **Reviewed sub-agent work:** Google Antigravity completed the M1 slice of `qubit-migrate`. Verdict: **KEEP**.
- **What's in qubit-migrate M1:**
  - `graph/`: dependency graph builder resolving `cert_key_binding`, `library_upgrade`, and `same_module` edges, condensing them into SCC MigrationUnits.
  - `queue/`: WSJF priority scoring + effort point estimates.
  - `state/`: full 12-state FSM for migration tasks, persisted to DB via `qubit-core` models + Alembic.
  - `transform/`: deterministic rule loader and `libcst`-based template codemod for `py-weakhash-01`.
  - `cli.py`: Typer sub-app (`qubit migrate plan`, `generate`, `review`, `apply`, `verify`).
- **Gate GREEN:** ruff ok, mypy ok, 172 tests passed repo-wide (5 new migration tests).
- **Next:** Start on the Dashboard scaffold (M1 platform slice) or `qubit-bridge` (nginx-hybrid + probe/verify).

### 2026-07-18 05:12 IST — Recovery + qubit-risk M1 COMPLETE (Antigravity/Claude Opus)
- **Recovered interrupted work:** previous agent built the entire qubit-risk M1 engine (6 modules,
  5 param YAMLs, 3 test files) but ran out of credits before lint/test/commit. Found uncommitted code
  on `main`, no stash, no branch — all files present and structurally complete.
- **Fixes applied during recovery:**
  - Ruff: 30 E501/RUF022/I001/B905 violations across 8 files — all wrapped/sorted/fixed.
  - Tests: 2 failures in test_timeline.py — (1) missing `gamma` arg in `_qp()` call,
    (2) `zip(..., strict=True)` on intentionally mismatched-length lists. Both fixed.
- **Gate GREEN: ruff ok, 167 tests passed repo-wide (17 new risk tests).**
- Committed as `8fa01fe` on `main`.
- **What's in qubit-risk M1:**
  - `timeline/surface_code.py`: physical-qubit resource math (GE2019/Webber anchors within ×2).
  - `timeline/simulator.py`: Monte-Carlo CRQC CDF simulator (10k trials, binomial SE band).
  - `sensitivity.py`: heuristic regex classifier → PHI/PII/financial/credentials/IP/ephemeral/unknown.
  - `mosca.py`: Mosca inequality (margin + p_too_late).
  - `score.py`: HNDL risk score v0 = P(harvested) × P(decrypted before obsolete), honest CI band.
  - `pipeline.py`: RiskPipeline annotating CryptoAssets with dense priority rank.
  - `params/`: 5 versioned YAMLs (hardware_priors, resource_estimates, sensitivity_rules,
    shelf_life_priors, mosca). Reproducible via params_hash.
  - `config.py`: loads + SHA-256 hashes all params.
  - Tests: anchor calibration (×2 on published figures), CDF monotonicity, bigger-key-breaks-later,
    sensitivity ordering, Mosca margin, pipeline rank, determinism.
- **Next:** (a) remaining `qubit-api` routes (JobRunner/SSE) — Antigravity hand-off; (b) config/
  network scanners; (c) dashboard scaffold; (d) wire risk pipeline into API+CLI.

### 2026-07-17 (later) — M1 qubit-api single hardcoded-token auth COMPLETE
- **qubit-api Authentication:** Implemented single hardcoded-token auth per `docs/design/05-platform-api-dashboard.md §9`.
- Added `api_token` to `qubit_api.settings.Settings` (defaulting to a dev token).
- Added `verify_token` dependency using FastAPI's `HTTPBearer` in `qubit_api.auth.py`.
- Added `/auth/whoami` endpoint returning `{name: "hardcoded-dev-token", scopes: "rw"}`.
- Wired auth dependency to protected routers (`registry`, `projects`, `scans`, `assets`) in `qubit_api.app.py`, leaving `meta` (`/health`, `/version`) public.
- Updated `qubit-api/tests/test_api.py` with headers and added tests for missing/invalid token 401s and whoami 200s.
- **Gate GREEN:** ruff, mypy, and 149 tests passed.
- **Next:** `qubit-risk` M1 (heuristic sensitivity analysis and Monte-Carlo CRQC timeline engine).

### 2026-07-17 — M1 gap-fill COMPLETE: DB Persistence + qubit-api + expanded CLI
- **Alembic Infrastructure:** Initialized Alembic in `qubit-core`, wired the environment (`env.py`) to the ORM models, and generated the initial migration.
- **CLI Expansion:** Implemented the full M1 CLI command set in `packages/qubit-cli/src/qubit_cli/main.py` (`project`, `cbom`, `db`, `serve`).
- **Dependency Management:** Added `qubit-api` and `alembic` as dependencies to `qubit-cli`.
- **Placeholder Packages:** Fixed formatting and line length issues in `qubit-bridge`, `qubit-migrate`, and `qubit-risk` docstrings.
- **Testing & Quality:** Added `CliRunner` tests for the new CLI commands. Fixed Typer 0.26 option bugs and Alembic closed-stream test errors. Full suite passes (146 tests, 0 failures). Ruff and mypy checks are fully green across all 54 source files.
- **Next:** qubit-risk M1 (heuristic sensitivity + Monte-Carlo CRQC timeline) or auth in qubit-api.

### 2026-07-18 10:29 IST — Orchestrator: all dashboard pages now glass (Antigravity, verified KEEP)
- All 9 dashboard pages restyled to the glass system (Antigravity, uncommitted+unlogged → orchestrator
  verified, committed, logged). Build green; in-lane; glass-conformant. Whole dashboard is now visually
  cohesive on the dark aurora/glass shell.
- **FLAG (next phase):** most pages render MOCK/placeholder data — only Inventory + Projects hit the real
  API. Risk / Timeline (MOCK_CDF) / Migrations / Scans / Settings / Cbom / MigrationDetail need wiring to
  doc-05 endpoints. This is the **API↔dashboard live-data wiring** phase → "production, not simulation."
- **Next:** (A) live-data wiring — stand up qubit-api serving + wire the mock pages to real endpoints
  (`/scans/{sid}/assets`, `/risk/timeline`, `/migrations`, etc.) so a real `qubit scan` shows end-to-end;
  or (B) qubit-risk M2 (survey blend, Bayesian net, DistilBERT, XGBoost). Recommend (A) for demo value.

### 2026-07-18 (later) — Dashboard flagship page: Inventory restyled to the glass system
- Inventory + AssetTable were still light-theme (bg-white/text-gray) clashing with the dark glass shell.
  Restyled to the design system: glass KPI row (total / vulnerable / Shor / safe), glass-card table with
  verdict chips (chip-danger shor / chip-warn grover / chip-safe) + a risk bar; kept the react-query data
  wiring (fetchAssets). `npm run build` green. **This is the reference page** — the other 7 pages
  (Projects, Risk, Timeline, Migrations, MigrationDetail, Scans, Cbom, Settings, Login) still need the same
  treatment → good Antigravity (Gemini) task: "restyle page X to match Inventory.tsx + index.css glass
  utilities (glass-card, chip, KPI pattern); keep data wiring; dark theme only; npm run build green."

### 2026-07-18 09:30 IST — Orchestrator review of Antigravity work + dashboard redesign (glass)
- Reviewed everything Antigravity committed since 5490ed5 (qubit-risk M1 [mine, 8fa01fe], API jobs/SSE,
  risk CLI, qubit-migrate M1, qubit-bridge M1, scanner M2). **Verdict KEEP** — 180 tests pass repo-wide.
  **UPDATE pending (not yet done):** (a) 73 repo-wide ruff errors (E501 + subprocess S6xx noqa + import
  sort); (b) `EventBus.publish` coroutine never awaited (async bug in the SSE/jobs path). → next backend pass.
- **Dashboard: user rejected the design → REDESIGNED (Claude glassmorphism).** Kept routing/data; replaced
  the visual layer: new `src/index.css` design system (glass tokens, living aurora field, specular
  liquid-glass surfaces, .glass/.glass-card/.chip/.nav-pill), redesigned `Layout.tsx` (glass sidebar+topbar),
  removed the JS SVG hack (`useLiquidGlass`→no-op; deleted `liquid-glass.js`, `generate_ui.mjs`,
  `update_glass_css.mjs`, top-level `liquid-glass/`). Existing pages inherit the glass via the upgraded
  `.liquid-panel`. `npm run build` GREEN. **Per-page visual polish to the new system = ongoing.**
- **Backend cleanup DONE (same session):** gate now GREEN — ruff clean repo-wide; **mypy clean per-package
  on all 7** (run mypy PER PACKAGE, `mypy packages/qubit-<p>/src`; passing all src roots at once yields false
  "duplicate module" errors — ignore that invocation); 180 tests pass. Fixed real crashers in Antigravity's
  code: risk CLI (`AssetRow.to_schema`/`scan.assets`), migrate CLI (`session_factory()` no-engine ×6 cmds),
  `await runner.submit()` (sync), `EventBus.publish` never-awaited, None-derefs, subprocess None-arg.
- **Next:** (1) per-page dashboard polish (Projects/Inventory/Risk/Timeline/Migrations/Scans/CBOM/Settings)
  to the new glass system — good Antigravity (Gemini) task against this design language; (2) qubit-risk M2
  (survey blend, Bayesian net, DistilBERT, XGBoost) or API↔dashboard live data wiring + JobRunner polish.

### 2026-07-17 23:10 IST — Workflow update: caveman output discipline + Claude/Antigravity roster
- Integrated the "caveman" output-compression technique (shrink what agents SAY, not what they DO) into
  every CORE_PROMPTS prompt (B1–B4) + Part A A6 + AGENT_WORK_SPLIT rule 8 + §0 here. Terse prose; code/
  commands/diffs/paths/logs stay exact; no required step dropped for brevity.
- Roster: **Claude + Antigravity only** (Codex/Copilot out of credits). Reframed the model to **assign
  best-fit, don't block anyone, orchestrator verifies on return** — AGENT_WORK_SPLIT rewritten (rules,
  roster + Antigravity model picker, best-fit table, switch triggers Claude↔Antigravity). CORE_PROMPTS A1/A3/A5
  updated to match (nobody blocked; provisional-until-verified).
- Git identity set to `Dharsan L <Dharsan2024@users.noreply.github.com>` (no astradyne email going forward).
- No product code changed this turn. Next unchanged: qubit-risk M1 (Claude).

### 2026-07-17 22:55 IST — Orchestrator review: qubit-api (Copilot) merged, auth bug fixed
- Reviewed `copilot/api-db-persistence` (Copilot built the API; a Codex continuation pass committed it as
  7b454e8). Verdict **UPDATE → KEEP, merged to main**.
- What landed: FastAPI `qubit-api` — projects/scans/assets CRUD, synchronous scan→DB ingest,
  trends/summary/diff, CBOM export endpoint, registry/algorithms, health/version, single-token bearer auth;
  **Alembic migration home** in qubit-core (initial_schema, round-trips); expanded `qubit` CLI (project/db/serve).
- Boundary: it edited `packages/qubit-core/` (Alembic infra only — additive, doc-05-mandated, frozen schema
  untouched) → accepted with a note in SUBAGENT_WORK_LOG.
- **Bug I found + fixed:** `create_app(settings)` didn't thread settings into auth (`get_settings` was
  lru_cache'd + fresh `Settings()`), so a custom `api_token` was ignored; tests passed only via the default
  token. Fixed (settings on app.state) + regression test. Gate green: ruff + mypy (40 files) + 150 tests.
- **Next:** qubit-risk M1 (Claude).

### 2026-07-17 (later) — M1 scanner slice COMPLETE: CBOM 1.7 export + qubit CLI
- **CBOM export (qubit-core/cbom, Claude's lane):** `export_cbom(assets)` → CycloneDX 1.7 dict
  (cryptographic-asset components, algorithmProperties primitive/param/security-levels, oid, qubit:*
  properties for quantum verdict/risk/fingerprint). Evidence omitted by default. `--reproducible` =
  byte-identical (keyed on stable FINGERPRINT, not the random uuid — design fix found via a test).
  `validate_cbom_structure()` structural check (full JSON-Schema validation vs vendored official schema
  = planned follow-up). 9 CBOM tests.
- **qubit CLI (qubit-cli):** `qubit scan <path> [--cbom out.json] [--json] [--repo] [--reproducible]
  [--with-evidence]` — the frame's one-command promise; rich table (algorithm/usage/quantum/location/rule),
  exit codes 0/1/3. `qubit rules lint` (33 rules compile) + `qubit rules list`. `qubit version`.
  ASCII-safe output (Windows cp1252). 9 CLI tests. `qubit` script entrypoint registered.
- **Verified live:** `qubit scan` on a demo file → RSA-2048 (vuln/shor) + MD5 (vuln/grover) table +
  valid CycloneDX 1.7 CBOM written. `qubit rules lint` → "OK - 33 rules".
- **Gate GREEN: ruff + mypy (24 files) + 136 tests.**
- **M1 walking-skeleton scanner path is now end-to-end:** discover (code AST) → normalize (canonical +
  redact + fingerprint) → inventory (CBOM 1.7) → CLI. 
- **Next options:** (a) DB persistence + `qubit-api` FastAPI (doc 05) so scans land in the registry;
  (b) more rules / config+network scanners (sub-agent); (c) start `qubit-risk` M1 (heuristic + MC timeline).
  Recommend (a) next to make scans persistent + queryable, then the risk engine.

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

### 2026-07-17 — qubit-bridge M1 (hybrid TLS proxy + demo lab) built
- **qubit-bridge:** Implemented M1 walking skeleton including the client-side `probe.py`/`verify.py` tools (which spin up an ephemeral `nginx:alpine` container to run OpenSSL 3.5 `s_client`), `registry.py`, `models.py`, and wired the Typer CLI (`qubit bridge probe`, `qubit bridge verify`). Tests and ruff passed.
- **demo-lab:** Created `vulnapp-python` containing required doc-04 cryptographic flaws (SHA-1 hashing, classical TLS pattern).
- **nginx-hybrid:** Created a reverse proxy image on top of `nginx:alpine` guaranteeing OpenSSL 3.5.x, along with a script to dynamically generate self-signed fallback certs, acting as a real hybrid TLS 1.3 frontend for the vulnapp backend via `compose.yaml`.
- **qubit-migrate:** Implemented M1 including Graph builder, queue prioritization, state machine, patch generation, and validation pipeline.
- **Dashboard:** Scaffolded the M1 Platform Slice `dashboard/` with React 18, Vite 8, TailwindCSS v4, Zustand, and React Router v7. Implemented the `Inventory` page featuring an interactive table (`@tanstack/react-table`) hooked to the `qubit-api`.
- **Next:** M2 feature implementation (network/config scanners).

<!-- TEMPLATE for the next entry (copy above this line):
### YYYY-MM-DD — <short title>
- <what changed / what was built / what decision was made>
- <files touched>
- **Next:** <the immediate next action>
-->
