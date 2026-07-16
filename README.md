# QUBIT — Quantum Upgrade Bridge & Inventory Tool

**HNDL risk modeling and automated cryptographic migration for the post-quantum era.**

QUBIT discovers cryptographic assets across code, configuration, network TLS, and certificates;
inventories them as a CycloneDX 1.7 Cryptographic Bill of Materials (CBOM); quantifies
**Harvest-Now-Decrypt-Later (HNDL)** risk probabilistically; generates *verified* migrations to
NIST post-quantum algorithms (ML-KEM / ML-DSA) using a **local** LLM; and stands up a hybrid
classical+PQC TLS bridge (X25519MLKEM768) so the migration is provable on a packet capture.

Fully offline. Local LLM. MIT licensed.

> **Status:** early development (Phase 0). See [`docs/BUILD_PLAN.md`](docs/BUILD_PLAN.md) for the roadmap
> and [`project-phase-memory/PROJECT_PHASE_MEMORY.md`](project-phase-memory/PROJECT_PHASE_MEMORY.md) for
> current progress.

## The pipeline

```
Discover ─▶ Inventory (CBOM) ─▶ Quantify HNDL risk ─▶ Migrate (verified) ─▶ Hybrid TLS bridge
 code/TLS/     CycloneDX 1.7       Monte-Carlo CRQC       local LLM + templates    X25519MLKEM768
 config/cert                       + Bayesian + Mosca      + re-scan proof          proven on pcap
```

## Quick start (once the CLI ships)

```bash
pip install qubit-cli
qubit scan .                 # discover crypto assets in the current repo -> CBOM
qubit risk run -p default    # HNDL risk scores + CRQC timeline
qubit plan  -p default       # ranked migration queue
```

Full stack (API + dashboard + demo lab):

```bash
docker compose up
```

## Development

```bash
uv sync --all-packages --group dev
uv run poe check             # ruff + mypy + unit tests
```

Requires: Python 3.12 (managed by uv), Docker, Node 22+, Ollama (`qwen2.5-coder:7b-instruct-q4_K_M`).

## Architecture

Monorepo (uv workspace). Packages communicate only through `qubit-core` models, the database, and the
REST API.

| Package | Role |
|---|---|
| `qubit-core` | Shared `CryptoAsset` schema, algorithm registry, DB, CBOM |
| `qubit-scanner` | Code (tree-sitter AST) / config / network TLS / cert discovery |
| `qubit-risk` | HNDL risk: Monte-Carlo CRQC timeline, Bayesian net, sensitivity, XGBoost, Mosca |
| `qubit-migrate` | Dependency graph, priority queue, LLM + template code transforms, IaC |
| `qubit-bridge` | Hybrid PQC TLS terminator, probe/verify, demo lab |
| `qubit-api` | FastAPI service (normative REST registry) |
| `qubit-cli` | Typer CLI (`qubit`) |

Design detail: [`docs/design/00`–`07`](docs/design/). Frame (binding): [`docs/design/00-architecture-frame.md`](docs/design/00-architecture-frame.md).

## License

MIT — see [LICENSE](LICENSE). Third-party benchmark corpora and baseline tools are run-only and are not
redistributed; see their upstream licenses.
