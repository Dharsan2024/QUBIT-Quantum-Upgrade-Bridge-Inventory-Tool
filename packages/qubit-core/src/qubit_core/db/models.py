"""SQLAlchemy ORM models — the physical schema behind the CryptoAsset registry.

Filterable ``CryptoAsset`` fields are flattened into columns; the rest ride in JSON. Migration and
risk-run tables are owned by their respective packages (qubit-migrate / qubit-risk) and added
through this same Alembic environment — they are intentionally NOT defined here (single-owner rule,
BUILD_PLAN §4.2).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text, UniqueConstraint, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON, Uuid

from ..schemas import utcnow

#: The tenant every pre-multi-team row belongs to, and the one a bootstrap token authenticates as.
#:
#: A fixed literal rather than a `uuid4()` resolved at runtime, for the same reason
#: `ThreatIntelConfig.id` is pinned to 1: a variable identity for "the default" invites two rows
#: nobody reconciles. It also lets `authenticate()` name the default tenant with no DB query.
DEFAULT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
DEFAULT_TENANT_SLUG = "default"


class Base(DeclarativeBase):
    """Shared declarative base. Every QUBIT table (core, risk, migrate) hangs off this so a single
    Alembic ``target_metadata`` sees them all."""


class Tenant(Base):
    """One team sharing this installation, isolated from the others.

    QUBIT runs on-premise and offline; a tenant is a TEAM boundary inside one deployment, not a
    customer of a hosted service. Every row of project data carries a `tenant_id`, and a token
    authenticates as exactly one tenant, so two teams on the same engine cannot read each other's
    code, findings or migrations.

    A single-team install never sees any of this: it has one tenant (`DEFAULT_TENANT_ID`), created
    automatically, and behaves exactly as it did before tenants existed.
    """

    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


@event.listens_for(Tenant.__table__, "after_create")
def _seed_default_tenant(target, connection, **kw) -> None:  # type: ignore[no-untyped-def]
    """Create the default team's row the moment the table exists.

    Every scoped table's `tenant_id` defaults to `DEFAULT_TENANT_ID` and carries a foreign key, and
    SQLite enforces it (``PRAGMA foreign_keys=ON``, see session.py) — so a schema without this row
    cannot accept a single project. Seeding it here rather than in each caller means the row exists
    on EVERY path that builds a schema: the API's `create_all()` branch, the Alembic migration, the
    CLI's own engine, and any test that calls `Base.metadata.create_all()` directly.
    """
    connection.execute(
        target.insert().values(
            id=DEFAULT_TENANT_ID,
            slug=DEFAULT_TENANT_SLUG,
            name="Default",
            created_at=utcnow(),
        )
    )


class ProjectRow(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), index=True, default=DEFAULT_TENANT_ID
    )
    name: Mapped[str] = mapped_column(String(120))
    slug: Mapped[str] = mapped_column(String(64), index=True)
    root_path: Mapped[str | None] = mapped_column(default=None)  # gates diff-apply + scan targets
    description: Mapped[str | None] = mapped_column(default=None)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    # Per-tenant, not global. Two teams on one engine both wanting a project called "backend" is
    # ordinary; making the second one fail would leak the first team's naming through a 409.
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_project_tenant_name"),
        UniqueConstraint("tenant_id", "slug", name="uq_project_tenant_slug"),
    )


class ScanRow(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # Denormalized off `projects.tenant_id`, exactly as `assets.project_id` is denormalized off
    # `scans.project_id`: it keeps a tenant filter off the join path on the hot read queries.
    # Safe to duplicate because it is write-once — a project never moves between tenants.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), index=True, default=DEFAULT_TENANT_ID
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    seq: Mapped[int]  # per-project monotonic
    label: Mapped[str | None] = mapped_column(default=None)
    status: Mapped[str] = mapped_column(String(16), default="queued")
    targets: Mapped[list] = mapped_column(JSON, default=list)
    scanners: Mapped[list] = mapped_column(JSON, default=list)
    stats: Mapped[dict] = mapped_column(JSON, default=dict)
    engine_versions: Mapped[dict] = mapped_column(JSON, default=dict)  # reproducibility (N8)
    error: Mapped[str | None] = mapped_column(default=None)
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    __table_args__ = (UniqueConstraint("project_id", "seq", name="uq_scans_project_seq"),)


class AssetRow(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), index=True, default=DEFAULT_TENANT_ID
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(16), index=True)

    # --- flattened, filterable CryptoAsset fields ---
    source_scanner: Mapped[str] = mapped_column(String(8))
    asset_type: Mapped[str] = mapped_column(String(16))
    algorithm: Mapped[str] = mapped_column(String(64), index=True)
    key_size: Mapped[int | None] = mapped_column(default=None)
    usage_context: Mapped[str] = mapped_column(String(20), default="unknown")
    sensitivity: Mapped[str] = mapped_column(String(12), default="unknown")
    shelf_life_years: Mapped[float | None] = mapped_column(default=None)
    qv_vulnerable: Mapped[bool] = mapped_column(index=True, default=False)
    qv_attack: Mapped[str] = mapped_column(String(8), default="none")
    confidence: Mapped[str] = mapped_column(String(8), default="high")
    rule_id: Mapped[str | None] = mapped_column(default=None)
    stale: Mapped[bool] = mapped_column(default=False)

    # --- structured remainder (JSON) ---
    location: Mapped[dict] = mapped_column(JSON, default=dict)
    protocol_detail: Mapped[dict | None] = mapped_column(JSON, default=None)
    library: Mapped[dict | None] = mapped_column(JSON, default=None)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    discovered_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow)

    # --- risk annotation (written by qubit-risk) ---
    risk_score: Mapped[float | None] = mapped_column(index=True, default=None)
    risk_ci_low: Mapped[float | None] = mapped_column(default=None)
    risk_ci_high: Mapped[float | None] = mapped_column(default=None)
    mosca_margin_years: Mapped[float | None] = mapped_column(default=None)
    priority_rank: Mapped[int | None] = mapped_column(default=None)

    # --- migration annotation (public projection written by qubit-migrate) ---
    migration_status: Mapped[str | None] = mapped_column(String(10), default=None)
    migration_json: Mapped[dict | None] = mapped_column(JSON, default=None)

    __table_args__ = (
        Index("ix_assets_proj_fp", "project_id", "fingerprint"),
        Index("ix_assets_scan_algo", "scan_id", "algorithm"),
    )


class RiskRun(Base):
    __tablename__ = "risk_runs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(16), default="queued")
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    timeline: Mapped[list | None] = mapped_column(JSON, default=None)
    percentiles: Mapped[dict | None] = mapped_column(JSON, default=None)
    summary: Mapped[dict | None] = mapped_column(JSON, default=None)
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String(16))  # scan|risk|plan|patch|verify|cbom_import
    status: Mapped[str] = mapped_column(String(12), default="queued", index=True)
    # NOT NULL even though `project_id` below is nullable: a job with no project scope is a real
    # state, but a job belonging to no TEAM never was — whoever queued it was authenticated.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), index=True, default=DEFAULT_TENANT_ID
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        # CASCADE so deleting a project (which always has ≥1 Job from its scans) doesn't hit a
        # FOREIGN KEY constraint failure — DELETE /projects/{id} was 500ing without this.
        ForeignKey("projects.id", ondelete="CASCADE"),
        index=True,
        default=None,
    )
    ref_id: Mapped[uuid.UUID | None] = mapped_column(
        default=None
    )  # scan_id / migration_item_id / risk_run_id
    progress: Mapped[float] = mapped_column(default=0.0)
    stage: Mapped[str] = mapped_column(String(64), default="")
    message: Mapped[str] = mapped_column(String(256), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict | None] = mapped_column(JSON, default=None)
    error: Mapped[str | None] = mapped_column(default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(default=None)
    finished_at: Mapped[datetime | None] = mapped_column(default=None)


class ApiToken(Base):
    """Bearer-token identity for the REST API (doc 05 §4.2 / §6.6).

    The raw token is shown to the user exactly once at creation; only its sha256 hex is stored, so a
    DB leak never yields a usable token. ``scopes`` is "ro" (read-only) or "rw" (read-write).
    Additive table — no change to the frozen CryptoAsset schema.

    A token also carries the TEAM it speaks for (`tenant_id`). That is the only thing establishing
    which tenant a request belongs to, so it is what makes multi-team isolation real rather than
    advisory — see :class:`Tenant`.
    """

    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), index=True, default=DEFAULT_TENANT_ID
    )
    name: Mapped[str] = mapped_column(String(64), unique=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # sha256 hex
    scopes: Mapped[str] = mapped_column(String(2), default="rw")  # "ro" | "rw"
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(default=None)
    revoked_at: Mapped[datetime | None] = mapped_column(default=None)


class LearnedPatch(Base):
    """A validated LLM line-fix, kept so the next occurrence costs less than the first.

    Serves two paths, both offline (see ``qubit_migrate.transform.learn``):

    * **Exact reuse** — keyed by ``snippet_key`` = sha256(rule_id + the stripped flagged line), so
      an identical finding in another file, another project or a later scan is answered from here
      instead of a model call. The reused patch still passes the full validation gate before it is
      proposed; only the LLM round-trip is skipped.
    * **Experience grounding** — the highest-``hit_count`` fixes for a rule are replayed into the
      generator prompt, so a *non*-identical finding is still conditioned on work this project has
      already had verified rather than starting cold.

    ``snippet_before``/``snippet_after`` are Text, not String(1024): a flagged line in minified or
    generated code can exceed any bound worth guessing at, and truncating one silently would poison
    both paths above with a fix that no longer reproduces.

    Scoped to a tenant, and that costs something worth stating: a team no longer benefits from
    another team's validated fixes on the same engine. It is still right. These columns hold literal
    source lines from a team's own codebase, so sharing them across teams would leak exactly the
    code the isolation exists to protect — and "another team's line looked like yours" is not a
    reason to hand it over.
    """

    __tablename__ = "learned_patches"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), index=True, default=DEFAULT_TENANT_ID
    )
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    language: Mapped[str] = mapped_column(String(32))
    algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    snippet_key: Mapped[str] = mapped_column(String(64), index=True)
    snippet_before: Mapped[str] = mapped_column(Text)
    snippet_after: Mapped[str] = mapped_column(Text)
    source_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    hit_count: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(nullable=True)

    # Tenant is part of the key: the same rule and line in two teams are two separate lessons.
    __table_args__ = (
        UniqueConstraint("tenant_id", "rule_id", "snippet_key", name="uq_learned_patch_key"),
    )


class LearnedOutcome(Base):
    """What happened the last time this SHAPE of finding was migrated - success or failure.

    `LearnedPatch` remembers a proven line replacement so an identical line can skip the model.
    That is a cache, and it only ever learns the easiest fixes: `record` refuses anything whose
    line count changed, which is precisely the multi-statement rewrite the generator prompt asks
    for. Measured on this project's own store: 59 accepted LLM patches produced 21 entries, so
    roughly two thirds of everything the model got RIGHT taught it nothing, and the harder the fix
    the less likely it was to be kept.

    This table is the other half - the experience base rather than the cache:

    * it records **hunks**, not lines, so a whole-function rewrite is retained;
    * it records **failures** too, so a shape that has defeated the model is known before three
      more attempts are spent on it, and so per-rule reliability can be reported honestly;
    * it records the model's own **reasoning** for a patch that passed validation, which is the
      strongest few-shot content available - a verified explanation of a verified change;
    * it is keyed by a **structural shape**, not an exact string, so `hashlib.md5(payload)` and
      `hashlib.md5(data)` are recognised as the same problem instead of two unrelated ones.

    Nothing here leaves the machine. It is written by the migration orchestrator after the
    validation gate has already ruled, and read only to build a local prompt.

    Tenant-scoped for the same reason as :class:`LearnedPatch`: the stored hunks are real source
    from a team's own codebase, and a prompt grounded on another team's code would be a leak with
    extra steps.
    """

    __tablename__ = "learned_outcomes"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("tenants.id", ondelete="CASCADE"), index=True, default=DEFAULT_TENANT_ID
    )
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    #: The FILE's language, never a rule's `multi`. Validated on write - see
    #: `qubit_migrate.transform.learn.record_outcome`, and the defect that made it necessary:
    #: 17 of 21 rows in the older table carry `multi`, a value the lookup can never ask for, so
    #: they were dead weight for grounding from the moment they were written.
    language: Mapped[str] = mapped_column(String(32), index=True)
    algorithm: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Structural fingerprint of the flagged code - identifiers and literals folded out. Two
    #: findings that differ only in variable names share it.
    shape_key: Mapped[str] = mapped_column(String(64), index=True)
    #: "passed" or "failed", as the validation gate ruled.
    outcome: Mapped[str] = mapped_column(String(16), index=True)
    #: The changed region, not the whole file: enough context to learn from, small enough to put
    #: several of them in a 7B model's prompt without crowding out the file being edited.
    hunk_before: Mapped[str] = mapped_column(Text)
    hunk_after: Mapped[str] = mapped_column(Text, default="")
    #: The model's SECURITY NOTES for a patch that passed. Replayed as grounding.
    reasoning: Mapped[str] = mapped_column(Text, default="")
    #: Why the gate rejected it, for a failure. Replayed as a warning.
    failure_reason: Mapped[str] = mapped_column(Text, default="")
    #: Whether a failure was QUBIT's own gap (it ships no verified target shape for the language,
    #: so the rescan could not be satisfied by any output) rather than the model's ceiling. Stated
    #: by the caller that produced the rejection instead of being guessed from the message text
    #: afterwards. NULL on rows written before this column existed — those still fall back to the
    #: legacy substring match; see `qubit_migrate.transform.learn.was_unwinnable`.
    is_unwinnable: Mapped[bool | None] = mapped_column(nullable=True, default=None)
    source_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: How often this row has been used as grounding. Ranks the strongest evidence first.
    hit_count: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(nullable=True)


class ThreatIntelConfig(Base):
    """The one settings row for optional threat-intelligence checks. Off by default.

    Every other table on this page says "nothing here leaves the machine" truthfully — this is
    the one exception, and it is opt-in for exactly that reason. When `enabled`, QUBIT fetches
    PUBLIC pages from a small, hardcoded allowlist of authoritative sources (see
    `qubit_risk.threat_intel.SOURCES`) to check whether the reference material behind the CRQC
    timeline and Mosca parameters has changed. Nothing about the user's code, scans, or findings
    is ever sent — these are plain GETs against static reference pages.

    Deliberately does NOT auto-apply anything it fetches. Free text from a web page has no
    business overwriting a number that drives migration prioritization without a human reading
    it first — seeing that a source changed, and staging a reviewable diff, is where automation
    stops and a person's judgment has to start. See `ThreatIntelSnapshot.reviewed`.
    """

    __tablename__ = "threat_intel_config"

    #: Singleton row. A settings table with a variable primary key invites two rows nobody
    #: reconciles; fixing it at 1 makes "the config" unambiguous by construction.
    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    enabled: Mapped[bool] = mapped_column(default=False)
    check_interval_hours: Mapped[int] = mapped_column(default=24)
    last_checked_at: Mapped[datetime | None] = mapped_column(default=None)


class ThreatIntelSnapshot(Base):
    """One fetch of one source: its content hash, an excerpt, and whether it changed.

    The excerpt (not the full page) is what a reviewer reads to decide whether the change is
    worth acting on — a stored, growing archive of full HTML per source is not what this is for.
    `reviewed` is the actual gate: `changed_from_previous=True` means "look at this",
    `reviewed=True` means a person did and recorded what they made of it, and only a person can
    set the second one — see `ThreatIntelConfig`'s docstring for why that boundary is deliberate.
    """

    __tablename__ = "threat_intel_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_id: Mapped[str] = mapped_column(String(64), index=True)
    source_url: Mapped[str] = mapped_column(String(512))
    fetched_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    #: None when the fetch itself failed (network error, non-200, timeout) — a fetch failure is
    #: not "unchanged", and conflating them would hide a source going permanently stale.
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    excerpt: Mapped[str] = mapped_column(Text, default="")
    fetch_error: Mapped[str | None] = mapped_column(String(512), nullable=True)
    changed_from_previous: Mapped[bool] = mapped_column(default=False)
    reviewed: Mapped[bool] = mapped_column(default=False)
    reviewed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    reviewer_note: Mapped[str | None] = mapped_column(Text, nullable=True)


class LlmEngine(Base):
    """One attachable generation engine. Any number of them, pooled.

    `LlmProviderConfig` holds exactly two: a primary and a backup. That is a real ceiling on the
    thing QUBIT is trying to be good at. A hosted free tier is rationed per PROJECT -- measured on
    this installation: Groq allows 1,000 requests/day, and two Google keys belonging to the same
    project share one quota while a different model on the same key gets its own. So the way to
    have more capacity is not a better model, it is MORE INDEPENDENT TIERS, and two slots meant a
    third key had nowhere to go.

    Every row is an OpenAI-compatible endpoint plus a key, which is all an engine has ever needed
    to be here: the model is swappable infrastructure and this table is the socket it plugs into.
    The local Ollama engine is deliberately absent -- it is always available, needs no key, and has
    no quota to pool.

    `api_key_encrypted` is `Fernet` ciphertext (`qubit_core.db.secrets_at_rest`), for the same
    reason as `LlmProviderConfig`: generation must present the key outward on every call. The API
    layer must never serialise or decrypt it.
    """

    __tablename__ = "llm_engines"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    #: What an operator calls it. Free text, so two keys for the same model stay tellable apart.
    label: Mapped[str] = mapped_column(String(128))
    base_url: Mapped[str] = mapped_column(String(512))
    model: Mapped[str] = mapped_column(String(128))
    api_key_encrypted: Mapped[bytes] = mapped_column()
    #: Shown instead of the key, so an operator can tell which one this is without it being
    #: readable. Never the key itself.
    api_key_last4: Mapped[str] = mapped_column(String(8), default="")
    #: The provider's EFFECTIVE per-request token allowance -- on a free tier this is a rate limit
    #: far below the model's context window, and using the window instead earns a 413.
    context_tokens: Mapped[int | None] = mapped_column(nullable=True, default=None)
    #: Off without deleting it, so a key can be rested when its quota is spent and brought back
    #: tomorrow without being re-entered.
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class LlmProviderConfig(Base):
    """Which engine `qubit_migrate` calls for patch generation. Off (Ollama) by default.

    Singleton row, `id` fixed at 1 -- same reasoning as `ThreatIntelConfig`: a settings table with
    a variable primary key invites two rows nobody reconciles. No `tenant_id`: this is operator
    infrastructure (which engine this deployment talks to), not team-owned data, exactly like
    `ThreatIntelConfig` is exempt from tenant scoping for the same reason.

    `api_key_encrypted` is `Fernet` ciphertext (see `qubit_core.db.secrets_at_rest`) -- reversible,
    because generation has to present the key outward on every call, unlike `ApiToken.token_hash`
    which only ever needs to verify equality. The API layer must never serialise this column or
    decrypt it for a response; only the orchestrator decrypts it, in memory, for the duration of
    building one outbound request.
    """

    __tablename__ = "llm_provider_config"

    id: Mapped[int] = mapped_column(primary_key=True, default=1)
    #: "ollama" (the always-available local default) or "openai-compatible" (an external endpoint
    #: -- OpenAI, Azure OpenAI, a free hosted tier like Groq/OpenRouter, or a company's own
    #: self-hosted server; all speak the same `{base_url}/chat/completions` shape).
    provider: Mapped[str] = mapped_column(default="ollama")
    base_url: Mapped[str | None] = mapped_column(default=None)
    model: Mapped[str | None] = mapped_column(default=None)
    api_key_encrypted: Mapped[bytes | None] = mapped_column(default=None)
    #: Last 4 characters of the plaintext key, so the UI can show "configured: ...ab12" without
    #: ever asking the backend to decrypt anything just to render a settings page.
    api_key_last4: Mapped[str | None] = mapped_column(default=None)
    #: The selected model's real context window, read from the provider's own `/models` metadata
    #: when the config is saved. NULL means "not known", and the caller falls back to
    #: `MigrateConfig.llm_context_tokens` (sized for the local 7B model).
    #:
    #: This is load-bearing, not decoration. `_llm_detour_reason` routes a finding to guided
    #: remediation when the file cannot fit the window -- so leaving this at the local model's
    #: 8,192 while an external model actually offers 131,072 would keep sending files to advice
    #: that the configured model could comfortably rewrite. The gate has to know which engine it
    #: is really gating.
    context_tokens: Mapped[int | None] = mapped_column(default=None)

    # ── Backup external provider ───────────────────────────────────────────────────────────────
    #: A SECOND OpenAI-compatible endpoint, tried when the primary refuses the request. Free tiers
    #: are capped on tokens per minute and requests per day, and those caps are the practical limit
    #: on how much of a repository QUBIT can migrate in one sitting -- measured, Groq's free tier
    #: allows 8,000 tokens/minute, so a single large file exhausts a whole minute's allowance. A
    #: second key on a different provider multiplies the usable budget without any code path of its
    #: own: it is the same `_openai_compatible_generate` call with different config.
    #:
    #: Ollama remains the last resort below both, so an install with neither key configured behaves
    #: exactly as it always has.
    backup_base_url: Mapped[str | None] = mapped_column(default=None)
    backup_model: Mapped[str | None] = mapped_column(default=None)
    backup_api_key_encrypted: Mapped[bytes | None] = mapped_column(default=None)
    backup_api_key_last4: Mapped[str | None] = mapped_column(default=None)
    backup_context_tokens: Mapped[int | None] = mapped_column(default=None)

    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


__all__ = [
    "DEFAULT_TENANT_ID",
    "DEFAULT_TENANT_SLUG",
    "ApiToken",
    "AssetRow",
    "Base",
    "Job",
    "LearnedOutcome",
    "LearnedPatch",
    "LlmProviderConfig",
    "ProjectRow",
    "RiskRun",
    "ScanRow",
    "Tenant",
    "ThreatIntelConfig",
    "ThreatIntelSnapshot",
]
