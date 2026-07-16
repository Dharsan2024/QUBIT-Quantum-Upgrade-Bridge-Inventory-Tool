# QUBIT — Global Architecture Frame (v1, BINDING for all subsystem designs)

QUBIT (Quantum Upgrade Bridge & Inventory Tool) is an open-source platform that: **discovers** cryptographic assets (code, configs, network, certificates) → **inventories** them as a CycloneDX CBOM → **quantifies** Harvest-Now-Decrypt-Later (HNDL) risk probabilistically → **orchestrates** automated migration to NIST PQC standards → **bridges** the transition with hybrid classical+PQC TLS, verified end-to-end.

Constraints: built by a 2-person final-year team (Jul 2026 → Apr 2027), but must ship as a real installable product — not a prototype: CLI + REST API + dashboard, reproducible demo lab, CI, docs, and experiments supporting a publishable paper.

## Binding stack decisions

| Concern | Decision |
|---|---|
| Core language | Python 3.12+ |
| API | FastAPI + Pydantic v2 |
| DB | SQLite by default, PostgreSQL optional — SQLAlchemy 2.x ORM, Alembic migrations |
| Dashboard | React 18 + TypeScript + Plotly.js (talks only to REST/WebSocket API) |
| CLI | Typer (`qubit` entrypoint) |
| Background jobs | FastAPI background tasks first; upgrade to RQ + Redis only if proven necessary |
| LLM runtime | Ollama, local only (no cloud exfiltration of scanned code) |
| PQC | liboqs + oqs-provider (OpenSSL 3.x), ML-KEM / ML-DSA targets |
| Packaging | Monorepo with uv workspaces; each package pip-installable; `docker compose up` runs full stack |
| License | MIT |
| CI | GitHub Actions: ruff, mypy, pytest (≥70% coverage on core packages), build + docker image |

## Monorepo layout (binding)

```
qubit/
  packages/
    qubit-core/       # shared Pydantic/SQLAlchemy models, Asset schema, config, canonical algorithm registry
    qubit-scanner/    # discovery: code (tree-sitter AST), config, network/TLS, certs & keystores
    qubit-risk/       # HNDL engine: Monte Carlo CRQC timeline, Bayesian net, sensitivity classifier, XGBoost regressor
    qubit-migrate/    # orchestrator: dependency graph, priority queue, LLM code transformer, IaC patch generator
    qubit-bridge/     # hybrid PQC TLS bridge tooling + runtime verification
    qubit-api/        # FastAPI service
    qubit-cli/        # Typer CLI
  dashboard/          # React + TS + Plotly app
  demo-lab/           # deliberately-vulnerable sample apps + docker compose scenario for the 4-phase demo
  docs/
```

Modules communicate ONLY through: qubit-core models, the database, and the REST API. No cross-package private imports.

## Shared CryptoAsset schema (binding, lives in qubit-core)

```
CryptoAsset:
  id: uuid
  source_scanner: code | config | network | cert | key
  location: { host?, service?, repo?, file_path?, line? }
  asset_type: algorithm-use | protocol | certificate | key | library
  algorithm: canonical name (e.g. RSA-2048, ECDSA-P256, X25519, AES-128, SHA-1, ML-KEM-768)
  key_size: int | null
  protocol_detail: { protocol, version, cipher_suites[] } | null
  library: { name, version } | null
  usage_context: tls | kex | signature | encryption-at-rest | token | hash | password | unknown
  sensitivity: pii | phi | financial | ip | credentials | ephemeral | public | unknown   # set by risk engine
  shelf_life_years: float | null                                                        # required secrecy lifetime (Mosca X)
  quantum_vulnerable: { vulnerable: bool, attack: shor | grover | none }
  evidence: source snippet / pcap ref / cert fingerprint
  discovered_at: timestamp
  risk: { score: float 0..1, ci_low, ci_high, mosca_margin_years, priority_rank } | null # set by risk engine
  migration: { status: pending|planned|patched|verified, recommendation, effort_estimate } | null
```

Canonical interchange format: **CycloneDX v1.7 CBOM** (import + export). The DB is the source of truth; CBOM is the compliance artifact.

## Data flow (binding)

scanners → Asset Registry (DB) → risk engine annotates each asset → orchestrator consumes the ranked queue → emits code diffs + IaC patches → hybrid bridge applies/verifies runtime posture → re-scan proves remediation → dashboard/CLI/API read everything; CBOM exportable at every stage.

## Non-negotiable product requirements

1. `qubit scan <path|host>` → assets in DB + CBOM JSON, one command.
2. `docker compose up` brings up API + dashboard + demo lab.
3. Dashboard: inventory browser, risk posture, CRQC timeline distribution curves, migration queue, patch/diff review.
4. End-to-end demo: scan demo-lab app → risk-rank → LLM-generated patch → hybrid TLS (X25519+ML-KEM-768) live → verified by re-scan and packet capture.
5. Fully offline-capable (local LLM, no telemetry).

## Milestone cadence (binding)

- **M1 — walking skeleton** (by First Review, ~Sep 2026): thin end-to-end slice — code scanner (Python+Java) → registry → heuristic risk score → CBOM export → minimal dashboard page.
- **M2 — feature complete** (end of Phase 1, ~Nov 2026): all scanners, full risk engine, LLM transformer on demo lab, hybrid bridge demo.
- **M3 — hardened product + paper experiments** (Jan–Mar 2027): packaging, CI green, benchmark evaluation, paper submission.
- **Final defense** ~Apr 2027.
