# 05 — Platform: API, Database, Dashboard, CLI

**Subsystem:** `qubit-api`, `qubit-cli`, `dashboard/` (+ the DB layer that physically lives in `qubit-core`)
**Status:** Design v1 — conforms to `00-architecture-frame.md` (v1, binding)
**Authors:** QUBIT team (Dharsan L, Akshay Kumar S)
**Date:** 2026-07-15

This document is the implementable engineering design for QUBIT's product surface: the REST API, the persistence layer (SQLAlchemy + Alembic), the job orchestration for long-running scans/LLM patch jobs, the React dashboard, the Typer CLI, and API authentication. Everything below assumes the binding frame: Python 3.12+, FastAPI + Pydantic v2, SQLite-default/Postgres-optional via SQLAlchemy 2.x, React 18 + TS + Plotly.js, Typer, local Ollama, MIT license, uv monorepo.

---

## 1. Purpose & requirements

### 1.1 Purpose

The platform subsystem is the **spine** of QUBIT. Scanners (`qubit-scanner`), the risk engine (`qubit-risk`), the migration orchestrator (`qubit-migrate`) and the hybrid bridge (`qubit-bridge`) are libraries; this subsystem is what turns them into a *product*:

- a **database** that is the single source of truth for projects, scans, assets, risk annotations, migration items and jobs — versioned per scan so posture trends are queryable;
- a **REST API** that exposes everything and pushes live progress events;
- a **job runner** so multi-minute scans and LLM patch generation never block a request;
- a **dashboard** where the evaluation-committee demo actually happens (inventory → risk → CRQC timeline → diff review → CBOM);
- a **CLI** (`qubit`) that delivers the frame's non-negotiable "`qubit scan <path|host>` → assets in DB + CBOM JSON, one command".

### 1.2 Functional requirements

| ID | Requirement |
|----|-------------|
| F1 | Multi-project, multi-scan data model: every scan is an immutable snapshot; assets carry a stable cross-scan `fingerprint` so trends and remediation deltas are queryable. |
| F2 | REST API (v1) covering projects, scans, assets (filter/sort/paginate), risk results, CRQC timeline data, migration queue + diff review workflow (generate/approve/reject/apply/verify), CBOM export/import, jobs. |
| F3 | Live progress for scans / risk runs / LLM patch jobs via Server-Sent Events (SSE); REST remains the source of truth on reconnect. |
| F4 | Job orchestration: bounded-concurrency in-process runner with persistent `jobs` table, cancellation, crash recovery on restart. Ollama jobs serialized (1 slot). |
| F5 | Dashboard pages: Projects, Inventory browser, Risk posture, CRQC timeline (Monte Carlo curves + Mosca overlay), Migration queue + side-by-side diff review with approve/reject, CBOM export, Scans & Jobs, Settings/Login. |
| F6 | CLI command tree: `qubit scan / risk / plan / migrate / cbom / project / jobs / db / serve` with rich terminal output and CBOM file export. |
| F7 | Token authentication (bearer), token lifecycle managed via CLI; all mutating endpoints authenticated; safe network defaults (bind 127.0.0.1). |
| F8 | CBOM: export any scan as CycloneDX v1.7 JSON; validate; import an external CBOM as a synthetic scan (M3, cut-line). |
| F9 | `docker compose up` brings up API + dashboard (static build served by the API container) + Ollama + demo-lab. |
| F10 | Fully offline: no telemetry, no cloud calls; dashboard bundles all JS locally. |

### 1.3 Non-functional requirements

| ID | Requirement | Target |
|----|-------------|--------|
| N1 | Inventory browsing latency | < 300 ms for filtered page of 50 assets on a 50k-asset DB (SQLite, indexed) |
| N2 | Asset ingest throughput | ≥ 1,000 assets/s bulk insert (batched `executemany`) |
| N3 | SSE event latency | < 1 s from job progress update to browser |
| N4 | Concurrency | 2 concurrent scans + 1 LLM job without starving the API (worker semaphores) |
| N5 | Portability | Windows + Linux dev machines; CI on ubuntu-latest; SQLite file DB needs zero setup |
| N6 | Test coverage | ≥ 70% on `qubit-api`, `qubit-core.db`, `qubit-cli` (frame CI gate) |
| N7 | Security defaults | localhost bind, hashed tokens, no diff-apply outside registered project roots, CORS allowlist |
| N8 | Reproducibility | every scan/risk run records engine versions + parameters (paper requirement) |

### 1.4 Explicitly out of scope for this subsystem

Scanner logic (doc 01), risk math (doc 02), LLM prompting/diff generation (doc 03), hybrid TLS bridge internals (doc 04). This subsystem only *invokes* their public functions and *stores/serves* their outputs.

---

## 2. Component breakdown

```
qubit-core/                      # (DB parts owned by this design)
  qubit_core/
    schemas.py                   # Pydantic v2: CryptoAsset + nested models (BINDING shared schema)
    db/
      models.py                  # SQLAlchemy 2.x ORM (typed, DeclarativeBase)
      session.py                 # engine factory, session dependency, SQLite pragmas
      fingerprint.py             # stable asset identity hash
      queries.py                 # reusable filtered/aggregate queries (used by API + CLI)
    cbom/
      export.py                  # assets -> CycloneDX 1.7 CBOM JSON
      import_.py                 # CBOM JSON -> synthetic scan (M3)
    registry.py                  # canonical algorithm registry (name, family, qv, pqc replacement)
    alembic/                     # migration env + versions/ (single migration home)

qubit-api/
  qubit_api/
    main.py                      # create_app(), uvicorn entry
    settings.py                  # pydantic-settings config
    auth.py                      # bearer-token dependency, token hashing
    jobs/
      runner.py                  # JobRunner (asyncio + thread pool, semaphores)
      bus.py                     # EventBus (in-proc pub/sub, ring buffer for SSE replay)
      handlers.py                # job kind -> callable (scan, risk, plan, patch, verify, cbom)
    routers/
      projects.py  scans.py  assets.py  risk.py
      migrations.py  cbom.py  jobs.py  meta.py  bridge.py
    services/                    # thin orchestration over qubit_core.db.queries + libraries
      scan_service.py  risk_service.py  migration_service.py  cbom_service.py
    static.py                    # serves dashboard build (prod / docker)

qubit-cli/
  qubit_cli/
    main.py                      # Typer root app, subcommand mounting
    commands/ scan.py risk.py plan.py migrate.py cbom.py project.py jobs.py db.py serve.py
    render.py                    # rich tables/progress helpers
    context.py                   # resolves DB url / project from flags, env, .qubit.toml

dashboard/
  src/
    api/        client.ts  queries.ts  sse.ts  types.ts (generated from OpenAPI)
    stores/     ui.ts (zustand: project, filters, token, theme)
    components/ AssetTable/ DiffReview/ TimelineChart/ RiskCharts/ JobProgress/ KpiTile/ CbomViewer/
    pages/      Projects Inventory Risk Timeline Migrations MigrationDetail Scans Cbom Settings Login
    App.tsx  router.tsx  main.tsx
```

**Responsibilities:**

| Component | Owns | Never does |
|---|---|---|
| `qubit_core.db` | ORM models, migrations, fingerprinting, bulk insert, query helpers | HTTP, business decisions |
| `qubit_core.schemas` | The binding CryptoAsset Pydantic models + enums (shared by scanners, risk, API, CLI) | persistence |
| `qubit_api.routers` | request/response validation, authz, pagination envelope | direct SQL (delegates to services/queries) |
| `qubit_api.jobs` | lifecycle of long-running work, progress events, crash recovery | domain logic (delegates to handlers → package functions) |
| `qubit_api.services` | glue: call `qubit_scanner.scan_paths()`, `qubit_risk.annotate()`, `qubit_migrate.generate_patch()` etc., persist results | reimplementing those packages |
| `qubit_cli` | UX for local, offline operation; talks to the DB via `qubit_core` directly (default) or to a server via REST (`--server`, M3) | duplicating scan/risk logic |
| `dashboard` | read/visualize via REST + SSE only (frame rule) | direct DB access |

Inter-module contract (frame-compliant): dashboard ↔ REST only; CLI ↔ `qubit_core` models + DB (and optionally REST); API ↔ sibling packages via their documented public functions and the shared DB.

---

## 3. Exact tech stack

All licenses permissive; versions verified on PyPI/npm as of **July 2026 except where a cell says "re-verify at lock time"**. Pin with `~=` (Python) / `^` (npm); lock with `uv.lock` / `package-lock.json`.

### 3.1 Python (qubit-core/db, qubit-api, qubit-cli)

| Library | Version (verified) | License | Use |
|---|---|---|---|
| `fastapi` | 0.139.0 (2026-07-01) | MIT | REST API, WebSocket-capable ASGI app |
| `pydantic` | 2.13.4 | MIT | schemas, validation (frame-binding v2) |
| `pydantic-settings` | ≥2.6 | MIT | `QUBIT_*` env config |
| `sqlalchemy` | 2.0.51 (2026-06-15) | MIT | ORM, typed `Mapped[]` models |
| `alembic` | 1.18.5 (2026-06-25) | MIT | schema migrations |
| `uvicorn[standard]` | ≥0.35 | BSD-3 | ASGI server |
| `sse-starlette` | ~=3.4 (3.4.4 confirmed 2026-05-12; re-verify patch at lock time) | BSD-3 | SSE responses (auto disconnect detection, graceful shutdown) |
| `typer` | 0.26.8 (2026-06-26) | MIT | CLI (rich output integrated since 0.12) |
| `rich` | ≥13 | MIT | CLI tables, progress bars (typer dependency) |
| `httpx` | ≥0.28 | BSD-3 | CLI client mode + API tests |
| `cyclonedx-python-lib` | 11.11.0 (2026-06-17; spec 1.7 + `cryptoprimitive` enums since 11.4/11.11) | Apache-2.0 | CBOM model/serialize/validate |
| `psycopg[binary]` | ≥3.2 | LGPL w/ exception → use `psycopg` (BSD-like "LGPL exception"—if licensing review objects, swap to `pg8000` MIT) | optional Postgres driver (M3, cut-line) |
| `pytest`, `pytest-cov` | ≥8 / ≥5 | MIT | tests |

Notes on verified capabilities: FastAPI 0.139 includes SSE field validation fixes and router-internals refactor (routes reflected, not copied) — no impact on our usage. `cyclonedx-python-lib` gained CycloneDX **1.7** support in 11.4.0 and 1.7 crypto-primitive/protocol-property enums in 11.11.0, which is exactly what CBOM export needs.

Deliberately **not** used: Redis/RQ, Celery (frame: background tasks first — see §6.3 for the upgrade seam), async SQLAlchemy (sync sessions + FastAPI threadpool are simpler and sufficient; SQLite is sync anyway).

### 3.2 Frontend (dashboard/)

| Library | Version (verified) | License | Use |
|---|---|---|---|
| `react`, `react-dom` | 18.3.x (frame-binding React 18) | MIT | UI |
| `typescript` | ≥5.6 | Apache-2.0 | types |
| `vite` | 8.1.4 | MIT | build/dev server |
| `plotly.js-dist-min` | 3.7.0 | MIT | charts (min bundle; swap to `plotly.js-cartesian-dist-min` if bundle size hurts) |
| `react-plotly.js` | 4.0.0 (README pins React 18; fine for this React-18 app) | MIT | React wrapper |
| `@tanstack/react-query` | 5.101.2 | MIT | server state, cache, polling fallback |
| `@tanstack/react-table` | 8.21.3 | MIT | headless inventory table |
| `zustand` | 5.0.14 | MIT | UI state (filters, selected project, token) |
| `react-router` | ^7 | MIT | routing |
| `react-diff-viewer-continued` | ^4 (4.2.2 latest on npm ~May 2026; **4.4.0 does not exist** — re-verify at lock time; `splitView` prop) | MIT | side-by-side diff review |
| `tailwindcss` | ^4 | MIT | styling |
| `vitest` + `@testing-library/react` + `msw` | version line matching Vite 8 per Vitest compat table / ≥16 / ^2 | MIT | component tests with mocked API |

OpenAPI → TS types: `openapi-typescript` (^7, MIT) run in CI (`npm run gen:types` hits `/openapi.json` from a spun-up test app) so `types.ts` never drifts from Pydantic.

---

## 4. Data models & schemas

### 4.1 Pydantic (qubit_core/schemas.py) — the binding CryptoAsset, field-exact

```python
from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, Field

class SourceScanner(StrEnum):
    code = "code"; config = "config"; network = "network"; cert = "cert"; key = "key"

class AssetType(StrEnum):
    algorithm_use = "algorithm-use"; protocol = "protocol"
    certificate = "certificate"; key = "key"; library = "library"

class UsageContext(StrEnum):
    tls = "tls"; kex = "kex"; signature = "signature"
    encryption_at_rest = "encryption-at-rest"; token = "token"
    hash = "hash"; password = "password"; unknown = "unknown"

class Sensitivity(StrEnum):
    pii = "pii"; phi = "phi"; financial = "financial"; ip = "ip"
    credentials = "credentials"; ephemeral = "ephemeral"
    public = "public"; unknown = "unknown"

class LocationRef(BaseModel):
    host: str | None = None
    service: str | None = None
    repo: str | None = None
    file_path: str | None = None
    line: int | None = Field(default=None, ge=1)

class ProtocolDetail(BaseModel):
    protocol: str                      # "tls" | "ssh" | ...
    version: str | None = None         # "TLSv1.2"
    cipher_suites: list[str] = []

class LibraryRef(BaseModel):
    name: str
    version: str | None = None

class QuantumVulnerability(BaseModel):
    vulnerable: bool
    attack: Literal["shor", "grover", "none"]

class RiskAnnotation(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    ci_low: float = Field(ge=0.0, le=1.0)
    ci_high: float = Field(ge=0.0, le=1.0)
    mosca_margin_years: float           # t_CRQC(median) - (shelf_life + migration_time); negative == already compromised
    priority_rank: int = Field(ge=1)

class MigrationStatus(StrEnum):
    pending = "pending"; planned = "planned"; patched = "patched"; verified = "verified"

class MigrationAnnotation(BaseModel):
    status: MigrationStatus
    recommendation: str                 # e.g. "RSA-2048 kex -> ML-KEM-768 (hybrid X25519+ML-KEM-768)"
    effort_estimate: float | None = None  # person-days, from qubit-migrate

class CryptoAsset(BaseModel):
    """BINDING shared schema (frame §'Shared CryptoAsset schema')."""
    id: UUID
    source_scanner: SourceScanner
    location: LocationRef
    asset_type: AssetType
    algorithm: str                      # canonical registry name, e.g. "RSA-2048"
    key_size: int | None = None
    protocol_detail: ProtocolDetail | None = None
    library: LibraryRef | None = None
    usage_context: UsageContext = UsageContext.unknown
    sensitivity: Sensitivity | None = None
    shelf_life_years: float | None = None
    quantum_vulnerable: QuantumVulnerability
    evidence: str                       # source snippet / pcap ref / cert fingerprint
    discovered_at: datetime
    risk: RiskAnnotation | None = None
    migration: MigrationAnnotation | None = None

class CryptoAssetOut(CryptoAsset):
    """API read model: adds platform bookkeeping (additive — frame-compatible)."""
    scan_id: UUID
    project_id: UUID
    fingerprint: str                    # 16-hex stable identity, see §6.1
```

API request/response envelopes (in `qubit_api`):

```python
class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int = Field(le=200, default=50)
    offset: int = 0

class ScanCreate(BaseModel):
    targets: list[str]                        # paths, "host:port", pcap files
    scanners: list[SourceScanner] = [SourceScanner.code, SourceScanner.config]
    label: str | None = None
    run_risk: bool = True                     # chain a risk run after scan

class JobOut(BaseModel):
    id: UUID; kind: str
    status: Literal["queued","running","succeeded","failed","cancelled"]
    progress: float; stage: str; message: str
    project_id: UUID | None; ref_id: UUID | None
    created_at: datetime; started_at: datetime | None; finished_at: datetime | None
    error: str | None

class MigrationItemOut(BaseModel):
    id: UUID; asset_id: UUID; scan_id: UUID
    status: Literal["pending","planned","generating","generated",
                    "approved","rejected","applied","verified","failed"]
    order_index: int | None
    recommendation: str; target_algorithm: str | None
    effort_estimate: float | None
    diff: str | None                          # unified diff
    source_file: str | None
    llm_model: str | None; gen_seconds: float | None
    rationale: str | None                     # LLM explanation, shown in review UI
    reviewer_note: str | None; reviewed_at: datetime | None
    applied_at: datetime | None; verified_by_scan_id: UUID | None
```

Note the two status vocabularies: the **asset-level** `migration.status` (frame-binding 4 values, derived) and the **workflow-level** internal FSM state owned by doc 03 (12 states, drives the review UI). The mapping is doc 03's `to_public_status()` — the single authority; `MigrationItemOut.status` above surfaces the internal state for the UI but the binding 4-value projection is doc 03's, not re-derived here.

### 4.2 SQLAlchemy models (qubit_core/db/models.py)

SQLite-first: UUIDs as `CHAR(32)`, JSON columns as `sqlalchemy.JSON` (maps to `JSON`/TEXT; it is **not** JSONB under Postgres — if the optional Postgres path wants JSONB, use `JSON().with_variant(postgresql.JSONB, "postgresql")`, which matters only if that cut-line survives). All timestamps UTC.

```python
class Base(DeclarativeBase): pass

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    root_path: Mapped[str | None]                 # registered repo root; gates diff-apply
    description: Mapped[str | None]
    settings: Mapped[dict] = mapped_column(JSON, default=dict)   # {"allow_apply": false, ...}
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int]                              # per-project monotonic; UNIQUE(project_id, seq)
    label: Mapped[str | None]
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|running|succeeded|failed|cancelled
    targets: Mapped[list] = mapped_column(JSON)
    scanners: Mapped[list] = mapped_column(JSON)  # subset of SourceScanner values
    stats: Mapped[dict] = mapped_column(JSON, default=dict)  # {"assets": 412, "files": 1310, "duration_s": 84.2, per-scanner...}
    engine_versions: Mapped[dict] = mapped_column(JSON, default=dict)  # {"qubit-scanner": "0.3.1", "registry": "2026.07"} (N8)
    error: Mapped[str | None]
    started_at: Mapped[datetime | None]; finished_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    __table_args__ = (UniqueConstraint("project_id", "seq"),)

class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"), index=True)  # denormalized for trend queries
    fingerprint: Mapped[str] = mapped_column(String(16), index=True)   # §6.1
    # --- CryptoAsset fields, flattened where filterable ---
    source_scanner: Mapped[str] = mapped_column(String(8))
    asset_type: Mapped[str] = mapped_column(String(16))
    algorithm: Mapped[str] = mapped_column(String(64), index=True)
    key_size: Mapped[int | None]
    usage_context: Mapped[str] = mapped_column(String(20), default="unknown")
    sensitivity: Mapped[str | None] = mapped_column(String(12))
    shelf_life_years: Mapped[float | None]
    qv_vulnerable: Mapped[bool] = mapped_column(index=True)
    qv_attack: Mapped[str] = mapped_column(String(8))                  # shor|grover|none
    location: Mapped[dict] = mapped_column(JSON)                       # LocationRef
    protocol_detail: Mapped[dict | None] = mapped_column(JSON)
    library: Mapped[dict | None] = mapped_column(JSON)
    evidence: Mapped[str] = mapped_column(Text)
    discovered_at: Mapped[datetime]
    # --- risk annotation (written by risk engine; nullable until a run happens) ---
    risk_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("risk_runs.id"))
    risk_score: Mapped[float | None] = mapped_column(index=True)
    risk_ci_low: Mapped[float | None]; risk_ci_high: Mapped[float | None]
    mosca_margin_years: Mapped[float | None]
    priority_rank: Mapped[int | None]
    # --- analyst overrides (survive re-runs; keyed copy in project settings by fingerprint) ---
    override_sensitivity: Mapped[str | None]
    override_shelf_life_years: Mapped[float | None]
    __table_args__ = (
        Index("ix_assets_proj_fp", "project_id", "fingerprint"),
        Index("ix_assets_scan_algo", "scan_id", "algorithm"),
    )

class RiskRun(Base):
    __tablename__ = "risk_runs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    params: Mapped[dict] = mapped_column(JSON)      # {"n_sims": 20000, "hw_priors": "webber2022-v3", "xgb_model": "sha256:..."}
    timeline: Mapped[list | None] = mapped_column(JSON)  # [{"year": 2030, "cdf": 0.04}, ...] P(CRQC <= year)
    percentiles: Mapped[dict | None] = mapped_column(JSON)  # {"p05": 2031.2, "p50": 2037.8, "p95": 2049.1}
    summary: Mapped[dict | None] = mapped_column(JSON)   # aggregates for the posture page
    started_at: Mapped[datetime | None]; finished_at: Mapped[datetime | None]

# Migration persistence is OWNED BY doc 03 (qubit-migrate): its MigrationPlan /
# MigrationUnit / MigrationTask / PatchProposal / MigrationEvent tables live in
# qubit-core (created via qubit-core's Alembic env). This platform doc does NOT
# define a competing MigrationItem table — the API's MigrationItemOut read model
# (§4.1) is a projection assembled from doc 03's task+patch rows, and the
# asset-level migration.status is doc 03's `to_public_status()` 4-value projection.
# (An earlier draft duplicated these columns here; removed to keep one owner.)

class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    kind: Mapped[str] = mapped_column(String(16))   # scan|risk|plan|patch|verify|cbom_import
    status: Mapped[str] = mapped_column(String(12), default="queued", index=True)
    project_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("projects.id"), index=True)
    ref_id: Mapped[uuid.UUID | None]                # scan_id / migration_item_id / risk_run_id
    progress: Mapped[float] = mapped_column(default=0.0)
    stage: Mapped[str] = mapped_column(String(64), default="")
    message: Mapped[str] = mapped_column(String(256), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict | None] = mapped_column(JSON)
    error: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime | None]; finished_at: Mapped[datetime | None]

class ApiToken(Base):
    __tablename__ = "api_tokens"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)   # sha256 hex of raw token
    scopes: Mapped[str] = mapped_column(String(16), default="rw")      # "ro" | "rw"
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
```

**SQLite pragmas** (set in `session.py` on connect): `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=5000`. These make concurrent reader (API) + writer (job thread) workable.

**Alembic:** single migration home in `qubit_core/alembic/`; `alembic.ini` lives in `qubit-core`; `qubit db upgrade` shells into `alembic.command.upgrade(cfg, "head")`. Autogenerate is allowed but every migration is reviewed; CI runs `upgrade head` + `downgrade base` + `upgrade head` on a temp DB.

### 4.3 CBOM mapping (qubit_core/cbom/export.py)

DB is the source of truth; CBOM is the compliance artifact (frame). Export maps each `Asset` row to a CycloneDX 1.7 `component` of type `cryptographic-asset` using `cyclonedx-python-lib` 11.11:

| CryptoAsset field | CycloneDX 1.7 |
|---|---|
| `asset_type=algorithm-use` | `cryptoProperties.assetType=algorithm`, `algorithmProperties.{primitive, parameterSetIdentifier, executionEnvironment}` |
| `asset_type=protocol` + `protocol_detail` | `assetType=protocol`, `protocolProperties.{type, version, cipherSuites[]}` |
| `asset_type=certificate` | `assetType=certificate`, `certificateProperties` |
| `asset_type=key` + `key_size` | `assetType=related-crypto-material`, `relatedCryptoMaterialProperties.{type=key, size, state}` |
| `algorithm` | registry-canonical name, e.g. `RSA-PKCS1-1.5-SHA-256-2048` pattern where derivable; else plain canonical (`RSA-2048`) + `qubit:algorithm` property |
| `risk.*`, `quantum_vulnerable`, `fingerprint` | `properties[]` namespace `qubit:` (`qubit:risk-score`, `qubit:mosca-margin-years`, `qubit:fingerprint`) |
| `evidence` | `evidence.occurrences[].location` (file:line) |

`metadata.tools` records QUBIT version + scan id; `serialNumber` = `urn:uuid:{scan_id}` so a CBOM is traceable to its scan.

---

## 5. Public interfaces

### 5.1 REST API — endpoint table (prefix `/api/v1`, all JSON)

> **This table is THE normative REST registry for all of QUBIT.** Docs 01–04 consume these endpoints and do not define their own; where an earlier draft of a sibling doc listed a different shape (e.g. `POST /scans` unscoped, WebSocket events, `POST /bridge/probe`), this registry supersedes it. Sibling docs may *request additions* here (tracked in the "requested additions" note below the table).

Auth column: 🔓 = anonymous, 🔑ro = any valid token, 🔑rw = write-scope token.

| Method | Path | Auth | Purpose / notes |
|---|---|---|---|
| GET | `/health` | 🔓 | liveness: `{status, db, version}` |
| GET | `/version` | 🔓 | package versions incl. engine_versions |
| GET | `/registry/algorithms` | 🔑ro | canonical algorithm registry (drives dashboard filter dropdowns) |
| GET | `/auth/whoami` | 🔑ro | token name + scopes |
| GET/POST | `/projects` | 🔑ro / 🔑rw | list / create (`{name, root_path?, description?}`) |
| GET/PATCH/DELETE | `/projects/{pid}` | 🔑ro/🔑rw/🔑rw | detail incl. latest-scan summary; PATCH settings (`allow_apply`); DELETE cascades |
| GET | `/projects/{pid}/trends` | 🔑ro | per-scan time series: `[{scan_id, seq, finished_at, total, vulnerable, median_risk, negative_mosca}]` (F1) |
| POST | `/projects/{pid}/scans` | 🔑rw | body `ScanCreate` → `202 {job, scan}`; job kind=`scan` |
| GET | `/projects/{pid}/scans` | 🔑ro | list, newest first |
| GET/DELETE | `/scans/{sid}` | 🔑ro/🔑rw | detail with stats / delete snapshot |
| GET | `/scans/{sid}/summary` | 🔑ro | aggregates: by algorithm, by usage_context, risk histogram buckets, top-10 risk |
| GET | `/scans/{sid}/diff?against={sid2}` | 🔑ro | fingerprint set diff: `{added[], removed[], persisting[], risk_deltas[]}` — proves remediation in demo phase 4 |
| GET | `/scans/{sid}/assets` | 🔑ro | `Page[CryptoAssetOut]`; filters: `algorithm`, `source_scanner`, `asset_type`, `usage_context`, `sensitivity`, `vulnerable`, `min_risk`, `max_risk`, `q` (substring on file_path/evidence/algorithm), `sort` (`risk_score:desc`, `algorithm:asc`, ...), `limit`, `offset` |
| GET | `/assets/{aid}` | 🔑ro | full `CryptoAssetOut` |
| POST | `/scans/{sid}/assets/batch` | 🔑rw | bulk-ingest externally-produced `CryptoAsset`s into a scan (the `qubit bridge probe --push` path, remote-CLI ingestion, and CBOM import all use this); body `{assets: [CryptoAsset]}` → `{new, updated}` |
| PATCH | `/assets/{aid}` | 🔑rw | analyst override `{sensitivity?, shelf_life_years?}` → sets `override_*`, response includes `risk_stale: true` |
| POST | `/scans/{sid}/risk/run` | 🔑rw | `202 {job, risk_run}`; params `{n_sims?, hw_priors?}`; job kind=`risk` |
| GET | `/risk/runs/{rid}` | 🔑ro | params, status, percentiles |
| GET | `/scans/{sid}/risk/summary` | 🔑ro | posture aggregates for latest risk run |
| GET | `/scans/{sid}/risk/timeline` | 🔑ro | `{timeline:[{year,cdf}], percentiles, samples_histogram:[{year,count}]}` — Plotly-ready |
| POST | `/scans/{sid}/risk/simulate` | 🔑rw | what-if timeline re-run with user MC params (dashboard sliders); never persisted, trials capped — **M3 stretch, first cut-line** (owns doc 02's `SimulateRequest`) |
| GET | `/assets/{aid}/risk/explain` | 🔑ro | feature contributions from qubit-risk (XGBoost SHAP-style) — M3, cut-line |
| POST | `/scans/{sid}/migrations/plan` | 🔑rw | `202 {job}`; runs qubit-migrate planner → creates `MigrationItem`s ordered by dependency-safe `order_index` |
| GET | `/projects/{pid}/migrations` | 🔑ro | `Page[MigrationItemOut]`; filters: `status`, `scan_id`, `min_risk`; default sort `order_index` |
| GET | `/migrations/{mid}` | 🔑ro | full item incl. `diff`, `rationale` |
| POST | `/migrations/{mid}/generate` | 🔑rw | `202 {job}`; kind=`patch`; serialized on LLM slot; regenerate allowed from `generated/rejected/failed` |
| POST | `/migrations/{mid}/approve` | 🔑rw | `generated→approved`; body `{note?}` |
| POST | `/migrations/{mid}/reject` | 🔑rw | `generated→rejected`; body `{note?}` (note is fed back into regeneration prompt by qubit-migrate) |
| POST | `/migrations/{mid}/apply` | 🔑rw | guarded (see §6.5): `approved→applied`; writes patch inside `project.root_path` only; requires header `X-Qubit-Confirm: apply` **and** `project.settings.allow_apply == true` |
| POST | `/migrations/{mid}/verify` | 🔑rw | `202 {job}`; kind=`verify`; re-scans touched files, checks fingerprint gone → `verified` |
| GET | `/scans/{sid}/cbom` | 🔑ro | CycloneDX 1.7 CBOM JSON (`Content-Disposition: attachment; filename=qubit-cbom-{project}-{seq}.json`); `?validate=true` runs schema validation first |
| POST | `/projects/{pid}/cbom/import` | 🔑rw | multipart CBOM file → synthetic scan (M3, cut-line) |
| GET | `/jobs` | 🔑ro | filter `status`, `kind`, `project_id` |
| GET | `/jobs/{jid}` | 🔑ro | `JobOut` — source of truth for progress |
| POST | `/jobs/{jid}/cancel` | 🔑rw | cooperative cancel (§6.3) |
| GET | `/jobs/{jid}/events` | 🔑ro | **SSE** stream of this job's progress events |
| GET | `/events` | 🔑ro | **SSE** firehose: all job/scan/migration state changes (dashboard subscribes once) |
| GET | `/bridge/status?host=&port=` | 🔑ro | qubit-bridge probe result: negotiated TLS groups, is hybrid (`X25519MLKEM768`) active |
| POST | `/bridge/verify` | 🔑rw | `202 {job}`; runs bridge verification against demo-lab, stores evidence |
| POST/GET | `/bridge/measurements` | 🔑rw / 🔑ro | store / read `HandshakeMeasurement` bench rows (qubit-bridge writes; one dashboard chart reads) — **M3** |

**Requested additions consumed by sibling docs:** `POST /scans/{sid}/assets/batch` (bridge `--push`, doc 04); `POST /scans/{sid}/risk/simulate` (doc 02, M3 stretch); `/bridge/measurements` (doc 04, M3). **No `/demo/*` endpoints exist** — the 4-phase demo is orchestrated by the host CLI only; a containerized API driving `docker compose` would require a docker-socket mount (root-equivalent), which we refuse.

SSE event format (`sse-starlette`), consumed by `EventSource` with `Last-Event-ID` replay from an in-memory ring buffer (size 1024; on gap, client refetches via REST):

```
id: 4213
event: job.progress
data: {"job_id":"...","kind":"scan","progress":0.62,"stage":"code:java","message":"demo-lab/vulnapp-python/src (312 files)"}

event: job.finished
data: {"job_id":"...","status":"succeeded","result":{"scan_id":"...","assets":412}}
```

Since token auth is required and `EventSource` cannot set headers, SSE endpoints also accept `?token=` query param — but this leaks the token into access logs, so it is **disabled whenever `QUBIT_ALLOW_REMOTE=1`** (allowed only on the localhost default). The dashboard uses `fetch`-based SSE from `sse.ts` with the `Authorization` header instead, so the query-param path is a localhost-only fallback.

### 5.2 CLI command tree (Typer, entrypoint `qubit`)

```
qubit
├── scan <TARGET...>          # paths, host:port, *.pcap — the frame's one-command promise
│     --project/-p TEXT        (default: "default", auto-created)
│     --type [code|config|network|cert|all]  (repeatable; default code,config)
│     --cbom PATH              (also write CBOM JSON)
│     --no-risk                (skip chained heuristic risk pass)
│     --db TEXT                (default resolves to sqlite:///<user-data-dir>/qubit.db via
│                               platformdirs; `context.py` calls expanduser()/user_data_dir BEFORE
│                               building the URL — SQLAlchemy does NOT expand `~`, so a literal
│                               `sqlite:///~/...` would create a `./~/` directory. env QUBIT_DB_URL)
├── risk
│   ├── run        -p PROJ [--scan SEQ] [--sims 20000]
│   ├── summary    -p PROJ [--scan SEQ]
│   └── timeline   -p PROJ [--json out.json]      # percentiles table / raw curve
├── plan           -p PROJ [--scan SEQ] [--top N]  # build + show migration queue
├── migrate
│   ├── list       -p PROJ [--status ...]
│   ├── generate   MIGRATION_ID | --all-planned    # LLM patch via local Ollama
│   ├── show       MIGRATION_ID                    # rich-rendered diff + rationale
│   ├── approve|reject MIGRATION_ID [--note TEXT]
│   ├── apply      MIGRATION_ID [--yes]            # writes patch; interactive confirm unless --yes
│   └── verify     MIGRATION_ID                    # re-scan touched files
├── cbom
│   ├── export     -p PROJ [--scan SEQ] -o cbom.json [--validate]
│   ├── validate   FILE
│   └── import     FILE -p PROJ                    # M3
├── project  list | create NAME [--root PATH] | delete NAME
├── jobs     list | watch [JOB_ID]                 # live rich progress (SSE in client mode, DB poll in direct)
├── db       upgrade | revision -m MSG | current
├── serve    [--host 127.0.0.1] [--port 8787] [--reload]
│   └── token  create NAME [--scope ro|rw] | list | revoke NAME
└── demo     up | down | reset                     # docker compose wrapper for demo-lab
```

Global flags: `--db`, `--server URL` (client mode, M3), `--json` (machine-readable output for scripting/tests), `-v/-q`.

**Example transcript 1 — the money command:**

```
$ qubit scan ./demo-lab/vulnapp-python -p demo --cbom vulnapp-cbom.json
QUBIT v0.4.0 — scan #3 on project 'demo'
  code    ████████████████████ 100%  1,310 files (py, java)   9.8s
  config  ████████████████████ 100%  14 files (nginx, yaml)   0.4s
Heuristic risk pass... done (412 assets)

  Algorithm     Assets  Vulnerable  Max risk  Worst location
  ─────────────────────────────────────────────────────────────────────
  RSA-2048          31      31 ⚠️     0.91    vulnapp/src/auth/keygen.py:44
  ECDSA-P256        12      12 ⚠️     0.84    vulnapp/src/api/sign.java:102
  AES-128           57      57 (Grover)0.38   vulnapp/src/store/enc.py:17
  SHA-256           88       0        0.05    —
  ...

412 assets → <user-data-dir>/qubit/qubit.db  (scan 7f3a…, project 'demo', #3)
CBOM (CycloneDX 1.7): vulnapp-cbom.json  ✓ schema-valid
Next: qubit risk run -p demo   |   qubit plan -p demo
```

**Example transcript 2 — review loop:**

```
$ qubit plan -p demo --top 3
Priority  Risk   Mosca margin  Asset                              Recommendation
────────────────────────────────────────────────────────────────────────────────
   1      0.91   -3.2 yr ⚠️    RSA-2048 kex @ keygen.py:44        → hybrid X25519+ML-KEM-768
   2      0.84   -1.9 yr ⚠️    ECDSA-P256 sig @ sign.java:102     → ML-DSA-65
   3      0.71   +0.8 yr       RSA-2048 @ legacy/export.py:9      → ML-KEM-768
24 migration items created (order respects dependency graph).

$ qubit migrate generate 1 && qubit migrate show 1
Generating patch via ollama:qwen2.5-coder:7b ... done in 41.2s
--- a/vulnapp-python/src/auth/keygen.py
+++ b/vulnapp-python/src/auth/keygen.py
@@ -41,8 +41,9 @@
-from cryptography.hazmat.primitives.asymmetric import rsa
-key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
+from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
+priv = MLKEM768PrivateKey.generate()          # pyca cryptography>=49 (doc 03 rule py-ecdh-kex-01)
+shared_secret, kem_ct = priv.public_key().encapsulate()
Rationale: RSA-2048 used for session key exchange (HNDL-exposed). ML-KEM-768 is
the NIST FIPS-203 KEM at security category 3 ...

$ qubit migrate approve 1 --note "reviewed, imports OK" && qubit migrate apply 1 --yes
Applied to demo-lab/vulnapp-python/src/auth/keygen.py. Run: qubit migrate verify 1
```

### 5.3 Python API (what other packages / tests call)

```python
# qubit_core.db
def get_engine(url: str) -> Engine
def session_factory(engine: Engine) -> sessionmaker[Session]
def bulk_insert_assets(s: Session, scan_id: UUID, assets: Iterable[CryptoAsset]) -> int
def asset_fingerprint(a: CryptoAsset) -> str                    # §6.1
def query_assets(s: Session, f: AssetFilter) -> tuple[list[Asset], int]
def scan_trends(s: Session, project_id: UUID) -> list[TrendPoint]
def scan_delta(s: Session, sid_a: UUID, sid_b: UUID) -> ScanDelta

# qubit_core.cbom
def export_cbom(s: Session, scan_id: UUID) -> dict              # CycloneDX 1.7 JSON
def validate_cbom(doc: dict) -> list[str]                       # [] if valid

# qubit_api
def create_app(settings: Settings | None = None) -> FastAPI     # used by uvicorn, tests, `qubit serve`

# consumed FROM sibling packages — NORMATIVE signatures matching docs 01–04:
qubit_scanner.scan_paths(paths, *, scanners, catalog=None, llm_assist=False,
                         progress=None) -> ScanResult             # complete result (NOT a stream);
                                                                  # per-asset progress via ScanProgress callback
qubit_scanner.scan_network(targets, *, ports=[443], probe_pqc=True) -> ScanResult   # async
qubit_risk.RiskPipeline(cfg, session_factory).assess(asset_ids=None, seed=42) -> RiskRun  # annotates DB
qubit_risk.classify_sensitivity(asset, cfg, model=None) -> SensitivityResult             # heuristic path, M1
qubit_migrate.MigrationOrchestrator(session, config).build_plan(scope=None) -> MigrationPlan
qubit_migrate.MigrationOrchestrator(...).generate_patch(task_id, generator="auto") -> PatchProposal
qubit_migrate.MigrationOrchestrator(...).apply_patch(patch_id, branch=None) -> AppliedResult
qubit_bridge.probe_host(host, port=443, *, groups=None) -> ProbeResult
```

`scan_paths` returns a complete `ScanResult` (doc 01), so the scan flow (§6.2) inserts assets **after** the scan completes, driving progress from the `ScanProgress` callback — not a streaming generator loop. If a sibling signature still shifts, the **service layer** in `qubit_api/services/` is the only place that changes.

---

## 6. Key algorithms & flows

### 6.1 Asset fingerprint (cross-scan identity — enables trends, deltas, remediation proof)

```python
def asset_fingerprint(a: CryptoAsset) -> str:
    """Stable across scans; tolerant to line drift; 16 hex chars."""
    if a.source_scanner in ("code", "config"):
        # POSIX-normalize + casefold-on-Windows so a Windows-host CLI scan and a
        # Linux-container scan of the SAME repo produce IDENTICAL fingerprints
        # (raw backslash/drive-letter paths would otherwise make trends, /diff, and
        # the phase-4 "fingerprint no longer present" proof silently fail).
        rel = PurePosixPath(a.location.file_path or "").as_posix()
        loc = f"{a.location.repo or ''}:{rel}"
        # line NOT included: lines drift. Disambiguate multiple same-algo uses
        # in one file by an occurrence ordinal computed at insert time.
    elif a.source_scanner == "network":
        loc = f"{a.location.host}:{a.location.service}:{(a.protocol_detail or ProtocolDetail(protocol='?')).protocol}"
    else:  # cert | key
        loc = first_line(a.evidence)          # cert fingerprint / key id is already stable
    raw = f"{a.source_scanner}|{a.asset_type}|{a.algorithm}|{a.usage_context}|{loc}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
```

Occurrence ordinal: during `bulk_insert_assets`, same-`raw` assets within one scan get `raw + f"|{n}"` for n=2,3,… (deterministic file order). Known heuristic limitation → stated in the paper; verified fix path (rename detection) is out of scope.

### 6.2 Scan flow (POST /projects/{pid}/scans)

```
1. Router validates ScanCreate; project must exist.
   PATH SAFETY (§6.5 discipline applies to scan targets too): each filesystem target
   is resolved and required to sit inside project.root_path OR an explicit
   settings.scan_roots allowlist — otherwise 400. Without this, any rw token could
   scan ~/.ssh or the DB file and read the bytes back through evidence snippets,
   especially once QUBIT_ALLOW_REMOTE=1. (The direct-DB CLI path is unrestricted —
   local possession of the DB file is already the trust boundary.)
2. scan_service.create_scan(): allocate seq = max(seq)+1 (SELECT ... FOR project),
   insert Scan(status=queued), insert Job(kind=scan, ref_id=scan.id), commit.
3. JobRunner.submit(job) → returns 202 {job, scan} immediately.
4. Worker thread (anyio.to_thread):
   a. scan.status=running; emit job.started
   b. result = qubit_scanner.scan_paths(targets, scanners=kinds,
                 progress=reporter.on_scan_progress)   # ScanResult (complete, non-streaming, doc 01)
      for batch in chunked(result.assets, 500):
        bulk_insert_assets(session, scan.id, batch)     # one txn per batch
      # network targets: await qubit_scanner.scan_network(...) on the event loop, not to_thread
   c. if payload.run_risk: RiskPipeline(cfg, sf).assess(scan_id=scan.id)   # heuristic path, M1
   d. scan.stats = {...}; scan.status=succeeded; emit job.finished
5. Any exception → scan.status=failed, job.error=repr, emit job.failed. Partial
   assets from committed batches are kept but scan is marked failed (UI badges it).
```

`ProgressReporter.update()` is called from the worker thread; it commits the Job row on its own short-lived session and hands the event to the asyncio loop via `loop.call_soon_threadsafe(bus.publish, evt)` — no cross-thread session sharing.

### 6.3 JobRunner (in-process, frame-compliant "background tasks first")

Plain `BackgroundTasks` gives no status, no bounded concurrency, no cancellation — so we wrap the same in-process idea in a tiny runner (~150 LOC), keeping the **frame's "no Redis until proven necessary"** rule. The interface is deliberately RQ-shaped so swapping the executor later touches one file.

```python
class JobRunner:
    def __init__(self, sf: sessionmaker, bus: EventBus,
                 scan_slots: int = 2, llm_slots: int = 1):
        # one semaphore key PER job kind — must cover every Job.kind value
        # (scan|risk|plan|patch|verify|cbom_import) or submit() KeyErrors
        self._sem = {"scan": Semaphore(scan_slots), "risk": Semaphore(scan_slots),
                     "patch": Semaphore(llm_slots),  # Ollama: strictly serialized
                     "plan": Semaphore(2), "verify": Semaphore(2),
                     "cbom_import": Semaphore(2)}
        self._cancel_flags: dict[UUID, threading.Event] = {}
        self._tasks: set[asyncio.Task] = set()       # keep strong refs — else the
                                                     # event loop may GC an in-flight task

    async def submit(self, job_id: UUID) -> None:
        # create the cancel flag at SUBMIT time so cancel() works while still queued
        self._cancel_flags[job_id] = threading.Event()
        t = asyncio.create_task(self._run(job_id))
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def _run(self, job_id):
        job = load(job_id); handler = HANDLERS[job.kind]     # jobs/handlers.py
        async with self._sem[job.kind]:
            flag = self._cancel_flags[job_id]
            if flag.is_set():                                 # cancelled while queued
                return finish(job_id, "cancelled")
            reporter = ProgressReporter(job_id, self.sf, self.bus, cancel=flag)
            try:
                result = await anyio.to_thread.run_sync(handler, job.payload, reporter)
                finish(job_id, "succeeded", result)
            except JobCancelled:  finish(job_id, "cancelled")
            except Exception as e: finish(job_id, "failed", error=redact(e))
            finally: self._cancel_flags.pop(job_id, None)

    def cancel(self, job_id):
        flag = self._cancel_flags.get(job_id)                 # may be queued or running
        if flag: flag.set()                                   # cooperative: handlers call
        # reporter.checkpoint() between batches, which raises JobCancelled when set.
```

**Crash recovery:** on API startup, `UPDATE jobs SET status='failed', error='interrupted by server restart' WHERE status IN ('queued','running')`; corresponding scans/risk_runs likewise. Scans are idempotent — the user reruns.

**Chained jobs:** `run_risk=True` on a scan enqueues the risk job from the scan handler's success path (not nested), so each job row is independently observable.

### 6.4 Risk run + timeline endpoint

Risk handler calls `qubit_risk.run_full(assets, params, reporter)`; the returned `RiskResult` contains per-asset annotations plus the Monte Carlo CRQC timeline (list of `(year, cdf)` and raw-sample histogram). Handler: UPDATE assets (single txn), insert `RiskRun` with `timeline/percentiles/summary`, honoring `override_*` fields (overrides are passed into the engine as fixed features). `GET /scans/{sid}/risk/timeline` is a pure read of `RiskRun.timeline` — the dashboard never recomputes.

### 6.5 Diff apply guardrails (the only endpoint that writes to user files)

```
preconditions:
  item.status == approved
  project.settings["allow_apply"] is true      (PATCH /projects/{pid} to enable)
  request header X-Qubit-Confirm == "apply"
procedure:
  1. root   = Path(project.root_path).resolve()
     target = (root / item.source_file).resolve()
     # is_relative_to, NOT startswith — startswith("/data/proj") wrongly admits
     # "/data/proj-evil/x"; on Windows also casefold both sides (C:\Proj vs c:\proj).
     assert target.is_relative_to(root)                        # path-traversal guard
  2. snapshot: copy target -> <user-data-dir>/qubit/backups/{item.id}/{basename}.orig
  3. apply with python `patch`-style application via difflib-checked hunks
     (qubit_migrate.apply_diff(target, item.diff) — it owns fuzz logic);
     on context mismatch -> 409 {"error": "diff_conflict", "hunk": n}
  4. item.status=applied, applied_at=now; emit migration.applied
rollback: POST /migrations/{mid}/rollback restores the snapshot (M2 nice-to-have; CLI always available).
```

### 6.6 Auth flow (simple token, safe defaults)

- `qubit serve` on first start with an empty `api_tokens` table: generate `secrets.token_urlsafe(32)`, store `sha256(raw)`, print raw **once** to the terminal ("Initial admin token — store it now").
- Request path: `Authorization: Bearer <raw>` → dependency hashes and looks up `ApiToken` (constant-time compare via indexed hash lookup is fine; hash is non-reversible), checks `revoked_at IS NULL`, enforces scope (`ro` tokens get 403 on mutating routes), updates `last_used_at` (throttled to 1/min).
- Defaults: host `127.0.0.1`; `--host 0.0.0.0` prints a red warning and requires `QUBIT_ALLOW_REMOTE=1`; CORS allowlist = `http://localhost:5173` (Vite dev) + same-origin (prod build served by API at `/`); OpenAPI docs stay on (local tool); request body cap 10 MB (CBOM import); no cookies → no CSRF surface.
- Dashboard: `/login` page stores the token in `localStorage["qubit_token"]`; 401 anywhere → redirect to `/login`.

### 6.7 Dashboard pages (page-by-page spec)

State rules: **all server data via TanStack Query** (`staleTime` 15 s; job-linked queries invalidated by SSE events); **UI-only state via zustand** (selected project, filter objects, token, theme). One global SSE subscription (`/events`) in `App.tsx` dispatches → `queryClient.invalidateQueries` by event type.

1. **Projects** (`/`): card grid — name, last scan time, asset count, vulnerable %, sparkline from `/trends`. "New scan" button → modal (targets, scanner checkboxes) → POST, then navigate to Scans with live progress.
2. **Inventory** (`/p/:pid/inventory`): TanStack Table over `/scans/{latest}/assets`, server-side pagination/sort. Filter bar: algorithm (multi-select from `/registry/algorithms`), scanner type, usage context, sensitivity, vulnerable-only toggle, risk range slider, free-text `q`. Row: algorithm chip (red=Shor, amber=Grover, green=safe), location `file:line`, risk score bar with CI whisker, sensitivity badge. Row click → right-hand drawer: full asset, evidence snippet (monospace), risk explanation, override form (PATCH), "plan migration" shortcut. Scan selector dropdown pins the page to any historical scan (F1).
3. **Risk posture** (`/p/:pid/risk`): KPI tiles (total assets / % quantum-vulnerable / median risk / count with negative Mosca margin); Plotly charts: risk-score histogram (20 bins); treemap by algorithm family sized by count, colored by max risk; stacked bar usage_context × vulnerability; **trend line** across scans (median risk + vulnerable count vs scan date). All read `/risk/summary` + `/trends` — zero client-side math.
4. **CRQC timeline** (`/p/:pid/timeline`): the paper's centerpiece. Top: CDF curve `P(CRQC ≤ year)` 2026–2060 with shaded 5–95% band and P50 marker (from `/risk/timeline`). Bottom: sample histogram (PDF). **Mosca overlay**: select asset(s) in a side list → for each, draw vertical band `[now + migration_time, now + migration_time + shelf_life]`; band intersecting the CDF above threshold renders red with the computed `mosca_margin_years` label. Hover unified tooltip; export-as-PNG via Plotly toolbar (paper figures come from here).
5. **Migration queue** (`/p/:pid/migrations`): status filter chips (pending / planned / generated / approved / applied / verified / rejected / failed) + table sorted by `order_index`: rank, asset, recommendation, effort, status, actions (Generate ▸ shows inline job progress). "Generate all planned" button (queues sequentially — LLM slot serializes anyway).
6. **Migration detail / diff review** (`/m/:mid`): header (asset, risk, recommendation, model, gen time); `react-diff-viewer-continued` with `splitView={true}` (toggle to unified), syntax highlight via its Prism hook; rationale panel; action bar: **Approve / Reject (with note) / Regenerate / Apply / Verify** — buttons enabled per state machine; Apply shows a confirm dialog quoting the guardrails (§6.5) and is hidden unless `allow_apply`. After Verify succeeds, a green "verified by scan #N — fingerprint no longer present" banner links to the scan diff.
7. **CBOM** (`/p/:pid/cbom`): summary (component counts by `assetType`, spec version 1.7 badge, serialNumber); collapsible JSON tree (custom `<details>`-based component, no extra dep); buttons: Download JSON, Validate (shows validator findings), Copy `curl` command.
8. **Scans & Jobs** (`/p/:pid/scans`): scan history table (seq, label, status, assets, duration) with per-scan actions (assets / CBOM / delete / compare→`/scans/{sid}/diff` view showing added/removed/persisting); live jobs panel with progress bars fed by SSE.
9. **Settings** (`/settings`): server URL + token (test button → `/auth/whoami`), theme toggle, danger zone (delete project).

### 6.8 Serving model

Dev: Vite dev server on :5173 proxying `/api` → :8787. Prod/docker: `npm run build` output copied into the API image; FastAPI mounts `StaticFiles(dist, html=True)` at `/` with an SPA fallback — one container, one origin, no CORS in prod. `docker-compose.yml` (repo root):

```yaml
services:
  api:
    build: {context: ., dockerfile: docker/api.Dockerfile}   # multi-stage: node build -> python image
    ports: ["8787:8787"]
    # demo-lab is copied into the WRITABLE qubit-data volume on first start (entrypoint:
    # `cp -rn /demo-lab-seed /data/demo-lab`), because migrate-apply (§6.5) and the
    # verify re-scan MUST write patches into project.root_path — a :ro mount would EROFS
    # the flagship demo. `demo reset` restores from the read-only seed.
    environment:
      - QUBIT_DB_URL=sqlite:////data/qubit.db
      # host-installed GPU Ollama is the Windows dev path (Docker-Desktop Ollama is CPU-only,
      # turning a 41 s patch into minutes and killing the live demo cadence); override to
      # http://host.docker.internal:11434 on dev machines with a GPU.
      - OLLAMA_HOST=http://ollama:11434
    volumes: [qubit-data:/data, ./demo-lab:/demo-lab-seed:ro]
  ollama:
    image: ollama/ollama:0.6.5            # PINNED, not :latest (reproducibility, F10/N8)
    volumes: [ollama-models:/root/.ollama]
    # Linux+NVIDIA demo boxes get GPU; ignored on Docker Desktop (host-Ollama override there)
    deploy:
      resources:
        reservations:
          devices: [{driver: nvidia, count: 1, capabilities: [gpu]}]
  demo-vulnapp:
    build: ./demo-lab/vulnapp-python
    # patched source is picked up via the shared qubit-data mount + app reload; a rebuild
    # step is documented in the demo script for the compile-language app
    volumes: [qubit-data:/data]
    ports: ["8443:8443"]
volumes: {qubit-data: {}, ollama-models: {}}
```

---

## 7. Failure modes & handling

| # | Failure | Detection | Handling |
|---|---|---|---|
| 1 | Ollama down / model not pulled | `httpx.ConnectError` / 404 from Ollama in patch handler | Job fails with actionable error (`"Ollama unreachable at {url} — run: ollama pull qwen2.5-coder:7b"`); migration item → `failed`, regenerate allowed; dashboard shows the message verbatim |
| 2 | Scan target unreadable / missing | scanner raises before first batch | scan → `failed`, 0 assets; error surfaced in scan row + SSE |
| 3 | API crash mid-job | startup recovery scan | jobs/scans in queued/running → `failed('interrupted by server restart')`; idempotent rerun |
| 4 | SQLite `database is locked` | `OperationalError` despite WAL + busy_timeout | batch writes retried ×3 with jittered backoff; reads unaffected (WAL); if chronic → the documented Postgres path |
| 5 | SSE client disconnect / proxy buffering | sse-starlette disconnect detection | server drops subscriber queue; client `sse.ts` reconnects with backoff + `Last-Event-ID`; on ring-buffer gap, refetch `/jobs` (REST is truth — F3) |
| 6 | Diff no longer applies (file changed since generation) | context mismatch in `apply_diff` | 409 `diff_conflict`; UI offers Regenerate (prompt includes current file content) |
| 7 | Path traversal in `source_file` | realpath prefix check (§6.5) | 400, item flagged, incident logged |
| 8 | Token lost | — | `qubit serve token create backup` from the host machine (CLI talks to DB directly; possession of the DB file is the trust boundary) |
| 9 | Huge repo (100k+ files) | progress stalls | scanner streams; API inserts in 500-asset batches; inventory always paginated; per-scan asset cap (default 200k) aborts with clear error |
| 10 | Alembic migration fails on user DB | `qubit db upgrade` error | automatic pre-upgrade file copy `qubit.db.bak-{ts}` (SQLite = file copy); restore instructions printed |
| 11 | Job cancel requested but handler between checkpoints | cooperative flag | `checkpoint()` calls at every batch boundary bound cancel latency to one batch (~seconds); patch jobs also poll flag while streaming LLM tokens |
| 12 | CBOM fails 1.7 schema validation (mapping bug) | `?validate=true` + CI golden test | export returns 500 with validator findings in body; CI blocks merge |
| 13 | Dashboard/API schema drift | `openapi-typescript` in CI | type-gen diff fails the build |
| 14 | Concurrent risk run on same scan | unique partial check (one non-terminal RiskRun per scan) | second POST → 409 with running job id |

---

## 8. Testing strategy

### 8.1 Layers

| Layer | Tooling | What |
|---|---|---|
| DB | pytest + tmp SQLite file (not `:memory:` — WAL differs) | fingerprint stability/ordinals, bulk insert throughput (N2 smoke), trend + delta queries, cascade deletes |
| Migrations | pytest | `upgrade head → downgrade base → upgrade head` on temp DB; model-vs-migration diff via `alembic check` |
| API | `fastapi.testclient.TestClient` (httpx) + `create_app(test_settings)` | every route: happy path + authz (401/403 ro-token) + validation (422) + guardrails (409/400 on apply); SSE via `stream=True` reading N events |
| Jobs | pytest + fake handlers (sleep/step/fail/raise-on-checkpoint) | concurrency caps, cancellation latency, crash-recovery (simulated by direct DB state + startup hook), chained scan→risk |
| CBOM | golden files | export demo fixture scan → compare to `tests/golden/cbom-vulnapp.json` (normalized: sorted keys, serial stripped) → validate with cyclonedx-python-lib against official 1.7 schema |
| CLI | `typer.testing.CliRunner` | each command against a temp DB; `--json` outputs snapshot-tested |
| Dashboard | Vitest + Testing Library + **MSW** (mocks `/api/v1/*` from recorded fixtures) | AssetTable filtering/pagination, DiffReview state machine (button enablement per status), TimelineChart props mapping, login redirect |
| E2E | Playwright (M3, cut-line) | `docker compose up` → scan demo-lab → approve one diff → CBOM download |

### 8.2 How fixtures get built (important — decouples platform dev from scanner dev)

1. **Builder functions**, not factory libs: `qubit_core.testing.make_asset(**overrides)` returns a valid `CryptoAsset` with deterministic defaults (`seed`-able); `make_scan_with_assets(session, n, mix)` populates a DB. Lives in `qubit-core` so every package shares it.
2. **Recorded scans**: `scripts/record_fixtures.py` runs the real scanner on `demo-lab/vulnapp-python` and dumps `tests/fixtures/scan-vulnapp.json` (list of CryptoAsset JSON). Committed; regenerated when scanner or demo-lab changes (CI job flags drift). Until `qubit-scanner` exists (early M1), this file is **hand-written from the schema** — 25 assets covering every enum value, which also serves as the schema's executable documentation.
3. **Risk fixtures**: a canned `RiskResult` JSON (timeline curve = smooth logistic around 2038, percentiles, per-asset scores) so dashboard/timeline work never blocks on the risk engine.
4. **MSW handlers** for the dashboard import the same JSON fixtures (single source of truth across Python and TS tests).

CI (frame-binding): ruff + mypy(strict on qubit-core/api) + pytest ≥70% cov + `npm run typecheck && npm run test` + docker image build.

---

## 9. Milestones (frame cadence) — platform-subsystem effort only

1 person-week (pw) ≈ 35 focused hours. Effort draws from the **portfolio-reconciled ~44 pw team budget owned by 06-engineering-plan** (an earlier draft cited "~80 pw", which double-counted; corrected). Platform total is **~11 pw**, and the M2 slice was cut so it is not 100% of one student's term-time capacity: the custom CBOM JSON-tree viewer, Projects sparklines, the treemap, and the scan-compare UI all move to M3, and ~1 pw is explicitly reserved for cross-doc interface reconciliation.

### M1 — walking skeleton (by First Review, ~Sep 2026) — **4 pw**

| Work | pw |
|---|---|
| qubit-core: schemas.py, ORM, session/pragmas (WAL+busy_timeout), alembic init, POSIX fingerprint, builders + hand-written fixture scan | 1.5 |
| qubit-api: create_app, projects/scans/assets CRUD + filters + scan-target path validation, CBOM export endpoint, synchronous scan execution (no JobRunner yet — in-request with a warning), single hardcoded-token auth | 1.5 |
| qubit-cli: `scan` (+`--no-db`), `project`, `cbom export`, `db upgrade`, `serve` | 0.5 |
| dashboard: Vite+TS scaffold, login, Projects page (no sparklines yet), Inventory page (table + 3 filters), REST client + type-gen | 0.5 |

**Acceptance:** `qubit scan demo-lab/vulnapp-python -p demo --cbom out.json` produces DB rows + schema-valid 1.7 CBOM; dashboard lists those assets with algorithm/vulnerable filters; `pytest` green; demo runs on both teammates' machines.

### M2 — feature complete baseline (end Phase 1, ~Nov 2026) — **6 pw**

| Work | pw |
|---|---|
| Interface reconciliation with docs 01–04 (normative endpoint registry, sibling signatures, MigrationItemOut projection over doc-03 tables) | 1 |
| JobRunner + jobs table + SSE (`/events`, `/jobs/{id}/events`) + cancel + crash recovery; scans/risk/patch as jobs | 2 |
| Risk endpoints (run/summary/timeline) + migration workflow endpoints (plan/generate/approve/reject/apply/verify) + guardrails (`is_relative_to`) | 1.5 |
| Dashboard: Risk posture (histogram only), CRQC timeline + Mosca overlay, Migration queue + diff review, Scans/Jobs live progress, minimal CBOM page (download+validate, no custom tree) | 1 |
| Token lifecycle (`serve token`), scopes, CORS/prod static serving; CLI: `risk`, `plan`, `migrate`, `jobs watch` | 0.5 |

**Acceptance:** full 4-phase committee demo executable end-to-end from dashboard + CLI: scan → risk-ranked inventory → LLM diff reviewed/approved/applied → verify re-scan shows fingerprint removed → CBOM exported; SSE progress visible; kill -9 during scan recovers cleanly on restart. **M2 dashboard scope = exactly the §10 never-cut list, nothing more.**

### M3 — hardened product + paper support (Jan–Mar 2027) — **3 pw + deferred M2 UI**

| Work | pw |
|---|---|
| docker compose full stack (writable demo-lab volume, pinned Ollama, GPU stanza), multi-stage image, README quickstart | 1 |
| Coverage to ≥70%, Playwright smoke, `alembic check` in CI | 0.75 |
| Deferred-from-M2 UI: Projects sparklines, risk treemap, CBOM JSON-tree viewer, Trends + scan-diff pages; timeline PNG export; risk explain endpoint; `/risk/simulate` sliders | 0.75 |
| Perf pass (N1/N2 measured + reported), optional Postgres CI job, CBOM import | 0.5 |

**Acceptance:** `docker compose up` → working product on a clean machine in <10 min (excl. model pull); CI green incl. coverage gate; benchmark numbers (N1/N2/N3) recorded in `docs/benchmarks.md` for the paper.

**Subsystem total: ~13 pw** of the ~44 pw reconciled capacity (06-engineering-plan owns the portfolio table).

---

## 10. Risks, mitigations & cut-lines

### Risks

| Risk | L×I | Mitigation |
|---|---|---|
| Sibling-package interfaces slip (scanner/risk not ready when API needs them) | H×H | Fixture-first development (§8.2): recorded/hand-written scan + canned RiskResult unblock API and dashboard from day 1; service layer isolates signature churn |
| Two-person team drowning in dashboard scope | M×H | Pages ranked by demo value (cut-lines below); headless TanStack Table + Tailwind avoids hand-rolled grid code; no design-system yak-shaving |
| SQLite write contention under concurrent jobs | M×M | WAL + batch txns + retry (§7.4); jobs cap at 2; documented Postgres escape hatch |
| SSE flakiness in demo network | L×H | REST-is-truth + polling fallback in TanStack Query (5 s) — demo degrades gracefully, never blocks |
| `react-plotly.js` maintenance risk (thin wrapper) | L×L | verified 4.0.0 works with React 18 + plotly 3.x; fallback is a 30-line `usePlotly` hook around `plotly.js-dist-min` — no API redesign |
| Diff apply corrupts demo-lab live on stage | L×H | snapshot backup + rollback (§6.5); demo script rehearses `demo reset` |
| Undergrad time estimates optimistic | H×M | cut-lines pre-agreed below; M2 acceptance is the *demo path*, not endpoint completeness |

### Cut-lines (drop in this order under time pressure — the product story survives all of them)

1. **Postgres support** → SQLite only (keep the SQLAlchemy URL indirection).
2. **CBOM import** → export-only (export is the compliance story; import is a nicety).
3. **CLI client mode (`--server`)** → CLI is direct-DB only; dashboard covers remote use.
4. **Risk explain endpoint + UI** → show score + CI only.
5. **Playwright E2E** → scripted manual demo checklist.
6. **Trends chart + scan-diff UI** → keep the *data model + endpoints* (cheap, paper-relevant), drop the pages; CLI `--json` can still produce trend data for paper plots.
7. **Apply/rollback via API+UI** → apply via CLI only; dashboard shows the exact command to run (keeps the guarded write path off the hot list).
8. **Token scopes (`ro`)** → single rw token.

**Never cut** (they *are* the demo and the paper): inventory browser with filters, risk posture page, CRQC timeline with Mosca overlay, diff review with approve/reject, CBOM 1.7 export, live SSE progress, `qubit scan` one-command promise.

### Frame deviations

None of substance. Clarifications within the frame's letter: (a) "FastAPI background tasks first" is implemented as a thin in-process JobRunner (asyncio + threadpool + jobs table) rather than raw `BackgroundTasks`, because status/cancel/recovery are product requirements (F4) — still no Redis/RQ; the executor seam is where RQ would slot in if ever proven necessary. (b) The frame's "WebSocket or SSE" option is resolved to **SSE** (sse-starlette): unidirectional progress needs no client→server channel, `Last-Event-ID` reconnect is free, and it is trivially testable with httpx. (c) `CryptoAssetOut` adds `scan_id/project_id/fingerprint` on top of the binding schema — purely additive; the binding fields are byte-identical. (d) `HandshakeMeasurement` (doc 04) and doc 03's migration tables also live in qubit-core as additive tables. Migration persistence is owned by doc 03, not duplicated here (§4.2).
