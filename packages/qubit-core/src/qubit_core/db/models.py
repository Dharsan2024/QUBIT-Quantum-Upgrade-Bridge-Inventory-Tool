"""SQLAlchemy ORM models — the physical schema behind the CryptoAsset registry.

Filterable ``CryptoAsset`` fields are flattened into columns; the rest ride in JSON. Migration and
risk-run tables are owned by their respective packages (qubit-migrate / qubit-risk) and added
through this same Alembic environment — they are intentionally NOT defined here (single-owner rule,
BUILD_PLAN §4.2).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import JSON, Uuid

from ..schemas import utcnow


class Base(DeclarativeBase):
    """Shared declarative base. Every QUBIT table (core, risk, migrate) hangs off this so a single
    Alembic ``target_metadata`` sees them all."""


class ProjectRow(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    root_path: Mapped[str | None] = mapped_column(default=None)  # gates diff-apply + scan targets
    description: Mapped[str | None] = mapped_column(default=None)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class ScanRow(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
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


__all__ = ["AssetRow", "Base", "ProjectRow", "ScanRow"]
