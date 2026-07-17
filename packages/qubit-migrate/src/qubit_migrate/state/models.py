# qubit-migrate state models — 6 SQLAlchemy tables (doc 03 §4.2)
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from qubit_core.db.models import Base
from qubit_core.schemas import utcnow
from sqlalchemy import JSON, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship


class MigrationPlan(Base):
    __tablename__ = "migration_plans"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="draft")
    # draft | active | completed | abandoned
    stats_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    units: Mapped[list[MigrationUnit]] = relationship(
        back_populates="plan", cascade="all, delete-orphan"
    )
    tasks: Mapped[list[MigrationTask]] = relationship(
        back_populates="plan", cascade="all, delete-orphan"
    )
    edges: Mapped[list[DependencyEdge]] = relationship(
        back_populates="plan", cascade="all, delete-orphan"
    )


class DependencyEdge(Base):
    __tablename__ = "migration_dependency_edges"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    plan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("migration_plans.id", ondelete="CASCADE"), index=True
    )
    src_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE")
    )
    dst_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE")
    )
    # keygen_before_use | shared_certificate | cert_key_binding
    # library_upgrade | tls_endpoint_config | same_module
    edge_type: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[float] = mapped_column(default=1.0)
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    plan: Mapped[MigrationPlan] = relationship(back_populates="edges")


class MigrationUnit(Base):
    __tablename__ = "migration_units"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    plan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("migration_plans.id", ondelete="CASCADE"), index=True
    )
    order_index: Mapped[int] = mapped_column(default=0)
    label: Mapped[str] = mapped_column(String(256), default="")
    member_ids_json: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # list of asset UUIDs (as strings) in this SCC

    plan: Mapped[MigrationPlan] = relationship(back_populates="units")
    tasks: Mapped[list[MigrationTask]] = relationship(
        back_populates="unit", cascade="all, delete-orphan"
    )


class MigrationTask(Base):
    __tablename__ = "migration_tasks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    plan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("migration_plans.id", ondelete="CASCADE"), index=True
    )
    unit_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("migration_units.id", ondelete="CASCADE")
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE")
    )
    # FSM state (internal, projected to migration.status via to_public_status)
    state: Mapped[str] = mapped_column(String(32), default="pending")
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    effort_points: Mapped[int] = mapped_column(default=1)
    effort_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    priority: Mapped[float] = mapped_column(default=0.0)
    rank: Mapped[int] = mapped_column(default=0)
    attempts: Mapped[int] = mapped_column(default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    unit: Mapped[MigrationUnit] = relationship(back_populates="tasks")
    plan: Mapped[MigrationPlan] = relationship(back_populates="tasks")
    patches: Mapped[list[PatchProposal]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    events: Mapped[list[MigrationEvent]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )


class PatchProposal(Base):
    __tablename__ = "migration_patches"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    task_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("migration_tasks.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(16), default="code")  # code | iac
    generator: Mapped[str] = mapped_column(String(16), default="template")  # llm | template
    model_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    file_path: Mapped[str] = mapped_column(Text)
    base_sha256: Mapped[str] = mapped_column(String(64))
    diff_text: Mapped[str] = mapped_column(Text)
    new_files_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    validation_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # proposed | approved | rejected | applied | superseded | failed
    status: Mapped[str] = mapped_column(String(32), default="proposed")
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    applied_branch: Mapped[str | None] = mapped_column(String(128), nullable=True)
    applied_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)

    task: Mapped[MigrationTask] = relationship(back_populates="patches")


class MigrationEvent(Base):
    __tablename__ = "migration_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    task_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("migration_tasks.id", ondelete="CASCADE"), index=True
    )
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str] = mapped_column(String(32))
    # "system" | "cli:<user>" | "api:<user>"
    actor: Mapped[str] = mapped_column(String(64), default="system")
    detail_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    at: Mapped[datetime] = mapped_column(default=utcnow)

    task: Mapped[MigrationTask] = relationship(back_populates="events")


__all__ = [
    "DependencyEdge",
    "MigrationEvent",
    "MigrationPlan",
    "MigrationTask",
    "MigrationUnit",
    "PatchProposal",
]
