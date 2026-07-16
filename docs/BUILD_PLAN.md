# QUBIT — Master Build Plan

**QUBIT: A Quantum Upgrade Bridge & Inventory Tool for HNDL Risk Modeling and Automated Cryptographic Migration**

Team: Dharsan L (43614012), Akshay Kumar S (43614004) · Guide: Dr. P. Shanmuga Prabha · BE-CSE Cybersecurity, Batch 2023–2027.
Deliverable: a **full working open-source product** (not a prototype) + an Annexure-1/SCOPUS research paper.
Window: Phase 1 Jul–Nov 2026 · Phase 2 Dec 2026–Mar 2027 · Final defence ~Apr 2027.

This file is the executive plan. It sits on top of a set of implementable engineering designs — read them in this order:

| Doc | Scope |
|---|---|
| [00-architecture-frame](design/00-architecture-frame.md) | **Binding** global frame: stack, monorepo layout, shared `CryptoAsset` schema, milestone cadence |
| [01-discovery-inventory](design/01-discovery-inventory.md) | Scanners (code AST, config, network TLS, cert/key) + CBOM export/import |
| [02-risk-engine](design/02-risk-engine.md) | HNDL risk: Monte-Carlo CRQC timeline, Bayesian net, sensitivity classifier, XGBoost, Mosca |
| [03-migration-orchestrator](design/03-migration-orchestrator.md) | Dependency graph, priority queue, local-LLM + template transforms, IaC, state machine |
| [04-hybrid-bridge-demo](design/04-hybrid-bridge-demo.md) | Hybrid PQC TLS terminator, probe/verify, demo-lab, 4-phase committee demo |
| [05-platform-api-dashboard](design/05-platform-api-dashboard.md) | **Normative REST registry**, DB, JobRunner, React dashboard, CLI |
| [06-engineering-plan](design/06-engineering-plan.md) | **Capacity authority**: repo/CI/CD, testing, evaluation, week-by-week timeline, team split |
| [07-ecosystem-factcheck](design/07-ecosystem-factcheck.md) | Web-verified July-2026 PQC ecosystem facts (versions, standards) with sources |

Every design was written, then adversarially reviewed for feasibility + factual correctness (with live web verification), then fixed. The cross-document contradictions that review surfaced are resolved by the canonical decisions in §4 below.

---

## 1. What QUBIT is, in one paragraph

QUBIT discovers every cryptographic asset an organization has (source code via tree-sitter AST parsing, TLS endpoints via handshake enumeration, config files, certificates/keys), inventories them as a **CycloneDX 1.7 Cryptographic Bill of Materials**, quantifies each asset's **Harvest-Now-Decrypt-Later risk** probabilistically (Monte-Carlo simulation of when a cryptographically-relevant quantum computer arrives × how long the data must stay secret, per **Mosca's inequality**), ranks a migration queue, generates **verified** code patches to NIST PQC algorithms (ML-KEM / ML-DSA) using a **local** LLM with deterministic template fallbacks, and stands up a **hybrid classical+PQC TLS bridge** (X25519MLKEM768) so the migration is provable on a packet capture. It is fully offline, MIT-licensed, and ships as a CLI + REST API + React dashboard that `docker compose up` brings to life.

## 2. The through-line the whole project must protect

One narrative must always work end-to-end — it is both the committee demo and the paper's spine:

> **Capture** classical TLS traffic (HNDL adversary) → **Discover** the vulnerable crypto + emit a CBOM → **Quantify** HNDL risk on the dashboard (CRQC timeline + Mosca overlay) → **Remediate** with an LLM-generated, validated patch → **Re-capture** the same service on the same port now negotiating X25519MLKEM768, and re-scan to prove the vulnerable asset is gone.

Everything else is depth behind this line. If time runs short, the cut-lines in each design protect exactly this path.

## 3. Binding technical decisions (from the frame)

- **Language/stack:** Python 3.12+ (Docker image 3.14→3.15 at M2), FastAPI + Pydantic v2, SQLAlchemy 2.x (SQLite default, Postgres optional), React 18 + TypeScript + Plotly.js, Typer CLI, local **Ollama** for the LLM, MIT license.
- **Monorepo (uv workspace):** `packages/qubit-{core,scanner,risk,migrate,bridge,api,cli}`, `dashboard/`, `demo-lab/`, `tools/qubit-eval`, `experiments/`, `docs/`.
- **Modules communicate ONLY through** the shared `qubit-core` models, the database, and the REST API — no private cross-package imports (enforced by an import-linter contract in CI).
- **Interchange:** the DB is the source of truth; the CycloneDX 1.7 CBOM is the exportable compliance artifact.
- **PQC runtime:** native **OpenSSL 3.5** (ships ML-KEM/ML-DSA, negotiates X25519MLKEM768 by default) — *not* oqs-provider, which self-disables under OpenSSL ≥3.5 and is kept only for exotic non-native algorithms. Confirmed in [07-ecosystem-factcheck](design/07-ecosystem-factcheck.md).

## 4. Canonical cross-document decisions (resolve the review's conflicts)

These are binding on all subsystem docs; where an older draft disagreed, this table wins:

1. **REST API ownership.** [05-platform §5.1](design/05-platform-api-dashboard.md) is the **single normative endpoint registry**. Scans are project-scoped (`POST /projects/{pid}/scans`); progress is **SSE, not WebSocket**; bulk ingest is `POST /scans/{sid}/assets/batch` (the bridge `--push` path); CBOM is `GET /scans/{sid}/cbom`. Docs 01/04 consume it and declare no competing endpoints.
2. **Migration persistence ownership.** [03-migration §4.2](design/03-migration-orchestrator.md) owns the migration tables (`MigrationPlan/Unit/Task/PatchProposal/MigrationEvent`) in `qubit-core`. Doc 05 does **not** define a competing `MigrationItem` table; its API read-model is a projection. The binding 4-value `migration.status` is doc 03's `to_public_status()` — the single authority.
3. **Demo-lab contract.** `demo-lab/SPEC.md` (co-owned) fixes the apps: **`vulnapp-python`** and **`vulnapp-java`** (`vulnapp-node` is M3 stretch). Flaws are tagged `# QUBIT-FIXTURE: <rule-id>` and use only rules that exist in the doc-03 pack. **There is no RS256-JWT→PQC-JOSE patch** (no mainstream JOSE library registers an ML-DSA `alg` in 2026); the phase-4 showcase patch is `py-ecdh-kex-01` (ECDH→ML-KEM-768 hybrid) applied via `qubit migrate apply --patch ID --auto-approve`.
4. **Evidence contract.** The scanner guarantees `evidence.snippet` = ±5 lines + `location{file_path,line}`; at M2 it additionally emits `evidence.context.{symbols,imports}` consumed by the migration dependency graph. The risk engine tokenizes identifiers/comments from the snippet itself (no route-to-crypto attribution).
5. **Fingerprints are POSIX-normalized + casefolded** before hashing, everywhere, so a Windows-host CLI scan and a Linux-container scan of the same repo converge (needed for trends, scan-diff, and the phase-4 remediation proof).
6. **Capacity is owned by [06-engineering-plan §9](design/06-engineering-plan.md):** ~44 person-weeks total (≈22 pw/student). Per-subsystem baseline sub-totals and the reconciliation are in that doc's §9.0; the week-by-week plan and the per-student cap are the binding constraints, cut-lines are the release valve.
7. **Python `ssl` groups API** (`SSLContext.set_groups` / `SSLSocket.group`) is a **Python 3.15** feature (verified), not 3.14 — always gated on `hasattr(ssl.SSLSocket, "group")`. The canonical negotiated-group check is a raw-ClientHello / `openssl s_client` parse, never a stdlib dependency.
8. **PQC target libraries in generated patches:** Python → `cryptography>=49` (`mlkem.MLKEM768PrivateKey.generate()`); Java → BouncyCastle `>=1.79` (recommend 1.84). `liboqs-python` is **not** injected into target repos (its first-import C build breaks the offline sandbox and Windows machines).

## 5. Phased execution plan

Person-weeks (pw) below are the *committed* baseline; 1 pw ≈ 35 focused hours. Full week-by-week detail and the two-person split live in [06-engineering-plan §11–12](design/06-engineering-plan.md).

### Phase 0 — Foundation (Weeks 1–2, Jul 2026)
Bootstrap the uv monorepo, CI (`ruff`/`mypy`/`pytest`/coverage/licenses/gitleaks), the `qubit-pqc-base` Docker image (OpenSSL 3.5), branch protection, PyPI name reservation. Land `qubit-core`: the binding `CryptoAsset` Pydantic + SQLAlchemy models, the canonical algorithm registry, and the fingerprint function. **Freeze the `CryptoAsset` schema here** (additive changes only afterward) — everything downstream depends on it. Exit: `uv sync && uv run poe check` green on both laptops and in CI.

### Phase 1 — M1 Walking skeleton (Weeks 3–9 → First Review ~mid-Sep 2026)
The thin end-to-end slice, one command deep:
- **Scanner:** Python + Java code scanning (~40 rules), normalization + dedup + **evidence redaction**, minimal CBOM 1.7 export.
- **Risk:** heuristic sensitivity classifier + Monte-Carlo CRQC timeline v0 (anchor-tested against Webber/Gidney figures) + static risk score + Mosca margin.
- **Migrate:** graph (schema-only edges) + WSJF queue + FSM + one template transform (`py-weakhash-01`) with re-scan validation.
- **Bridge:** `nginx-hybrid` image + probe/verify against it (tested on Windows), `vulnapp-python`.
- **Platform:** core DB + projects/scans/assets CRUD (with scan-target path validation) + CBOM endpoint + Inventory dashboard page + `qubit scan` one-command.
- **Eng:** CI gating, CryptoAPI-Bench + QUBIT-Corpus v1, golden CBOM #1, `v0.1.0` release dry-run.

**M1 acceptance:** `qubit scan demo-lab/vulnapp-python --cbom out.json` → DB rows + schema-valid CBOM; dashboard lists them with filters; a template patch flips one asset to `verified`; the First-Review demo runs from a runbook.

### Phase 2 — M2 Feature-complete baseline (Weeks 10–18 → Second Review ~late Nov 2026)
Every subsystem reaches its committed baseline and the **full 4-phase demo runs live**:
- **Scanner:** + Go, config scanner, active TLS enumeration with PQC group probing, cert/key, PQC-API detection rules, `--no-db`, the `symbols/imports` evidence contract, CBOM import.
- **Risk:** survey-blended timeline, 5-node Bayesian net, DistilBERT sensitivity classifier (**ship/no-ship gate Oct 15**), XGBoost primary path + split-conformal CIs, degradation ladder.
- **Migrate:** Ollama transformer + repair loop + **prompt-injection/path hardening**, docker sandbox validation, 6-rule pack, dependency edges + `encrypt_decrypt_pair`, nginx IaC, review inbox.
- **Bridge:** verify/capture/diff/bench, same-port classical↔hybrid swap, `--canned` mode, `vulnapp-java`.
- **Platform:** JobRunner + SSE + crash recovery, risk + migration workflow endpoints + apply guardrails (`is_relative_to`), never-cut dashboard pages, token auth.
- **Eng:** integration CI (TLS matrix, e2e), LLM contract fixtures, coverage ≥70% gating, scan-authorization guardrails.

**M2 acceptance:** one `qubit demo run --all` (or `--canned`) executes capture → scan/CBOM → risk dashboard → LLM patch reviewed/applied → hybrid re-capture on the same port → re-scan proves remediation; `kill -9` mid-scan recovers cleanly.

### Break (Weeks 19–20) — exams; CI-only.

### Phase 3 — M3 Hardening + paper (Weeks 21–32, Dec 2026–Feb 2027)
Baselines (CryptoGuard, CogniCrypt) in containers; the four experiment suites (**E1** scanner P/R/F1 vs baselines + ablation, **E2** risk calibration, **E3** patch pass@k, **E4** hybrid-handshake overhead via pcap-timestamp + `tc netem`); `v0.9.0` to PyPI + GHCR; docs site; deferred stretch items (Java LLM rules, HAProxy, Apache/Terraform, `/risk/simulate`, dashboard analytics extras) as time allows. **Paper submitted ~W32** to an Annexure-1 venue.

### Phase 4 — Defence (Weeks 33–40, Mar–Apr 2027)
`v1.0.0`, thesis chapters, two rehearsals + a **backup demo video** (demo-failure insurance), viva prep.

## 6. What makes this a product, not a prototype

`pip install qubit-cli` + `docker compose up` both work from a clean clone; CI is green with ≥70% coverage on the three core packages; every scan/risk run records engine versions for reproducibility; the CBOM validates against the official ECMA-424 schema; the whole thing runs offline with a local LLM and no telemetry; and a third party can add a detection rule or a migration rule as pure YAML + fixtures and watch it flow through the pipeline.

## 7. What makes it publishable

The novelty is the **synthesis** no prior work combines (confirmed against the 2026 ecosystem in doc 07): CRQC Monte-Carlo hardware simulation **fused with** programmatic AST discovery into a continuous, calibrated HNDL score; **local-LLM** AST-to-PQC code transformation with a safety-gated verification pipeline (a bad patch can never merge — the honest claim even at a 55% LLM success rate); and automated CycloneDX CBOM output tying it to emerging compliance mandates. The evaluation (E1–E4) measures each claim against real baselines on real benchmarks, with all figures regenerable from `experiments/run_all.py`.

## 8. Top risks and how the plan absorbs them

- **Two people, six subsystems, placement season.** → Front-load M1 into the July–August break; pre-ordered cut-lines (C1–C8 in doc 06 + per-doc cut-lines); the never-cut cores fit the 44 pw budget with ~4 pw slack.
- **LLM patch quality on student hardware.** → Deterministic template transforms guarantee the demo without a GPU; the validation gate makes *safety* the claim; success rate is a finding either way.
- **Subsystem interfaces slipping.** → Fixture-first development (recorded/hand-written scans, canned RiskResult) unblocks the API and dashboard from day 1; the normative REST registry + `demo-lab/SPEC.md` + the frozen `CryptoAsset` schema are the contracts.
- **Demo fails live.** → `--canned` mode + a pre-recorded backup video.

---

*Design docs 00–07 are the implementable detail behind each line above. Start at [00-architecture-frame](design/00-architecture-frame.md), then build Phase 0.*
