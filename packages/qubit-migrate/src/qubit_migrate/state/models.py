# qubit-migrate state models — 6 SQLAlchemy tables (doc 03 §4.2)
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from qubit_core.db.models import DEFAULT_TENANT_ID, Base
from qubit_core.schemas import utcnow
from sqlalchemy import JSON, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship


class MigrationPlan(Base):
    __tablename__ = "migration_plans"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    # NOT NULL, unlike `project_id` below. "Built across every project" was always a real state;
    # "built for no team" never was — the plan was created through an authenticated request.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), index=True, default=DEFAULT_TENANT_ID
    )
    # Which project (and optionally which single scan) this plan was built from.
    #
    # Nullable because plans predating scoping were built across the ENTIRE database — every
    # project, every historical scan — and there is no honest way to retro-assign one of them to a
    # project. NULL means exactly that: "unscoped, built before plans had a scope". The UI shows
    # those as legacy rather than filing them under a project they may not represent.
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True, default=None
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True, default=None
    )
    scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    #: Which regulatory regime this plan was built under, or NULL for none.
    #:
    #: Without it the targets in a plan are unexplainable after the fact. `ML-KEM-1024` and
    #: `X25519MLKEM768` are both defensible and neither is correct on its own: the first satisfies
    #: CNSA 2.0 and violates BSI, the second the reverse. A reviewer looking at a stored plan has
    #: no way to tell a deliberate choice from a mistake unless the plan says which regulator it
    #: was answering.
    #:
    #: NULL means no regime was configured, which is the shipped default and is a distinct claim
    #: from "the default regime was chosen" — writing `nist-civil` for an install that never chose
    #: it would fabricate a decision nobody made.
    regime: Mapped[str | None] = mapped_column(String(32), nullable=True)
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
    src_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    dst_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
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
    unit_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("migration_units.id", ondelete="CASCADE"))
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    # FSM state (internal, projected to migration.status via to_public_status)
    state: Mapped[str] = mapped_column(String(32), default="pending")
    rule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    effort_points: Mapped[int] = mapped_column(default=1)
    effort_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    priority: Mapped[float] = mapped_column(default=0.0)
    rank: Mapped[int] = mapped_column(default=0)
    attempts: Mapped[int] = mapped_column(default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # WHY a task is parked in `deferred`. Both "could not migrate" and "nothing to migrate" land in
    # that state -- the FSM's terminal states all mean "a patch was applied and verified" -- so
    # without this the two are indistinguishable and a plan reports finished work as broken.
    # NULL on tasks that never parked, and on rows written before this column existed.
    # See RESOLUTION_SATISFIED / RESOLUTION_UNRESOLVED in orchestrator.py.
    resolution: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: Model requests and tokens this task has consumed, ACCUMULATED across every
    #: attempt including the ones that produced nothing. `PatchProposal.cost_json`
    #: records what a successful patch cost; this records what the task cost, and the
    #: two differ exactly where it matters -- a finding that burns its repair budget and
    #: fails writes no patch at all, so its spend would otherwise be invisible.
    spend_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    # Migration advice for a finding no patch could be produced for. A queue entry that says
    # "manual change" and nothing else is a dead end: it names an algorithm and a line and leaves
    # the reader to work out what the code does, what it should become, and what breaks on the way.
    advice_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    advice_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    advice_at: Mapped[datetime | None] = mapped_column(nullable=True)

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
    #: How much was actually ESTABLISHED about this patch, on the evidence ladder: -1 nothing,
    #: 0 applies+parses, 1 symbols+compiles, 2 rescan, 3 behaves (metamorphic), 4 the project's
    #: own tests. `status="proposed"` says a gate returned yes; this says which gates ran.
    #:
    #: They are not the same claim, and the gap between them is the finding: of 292 patches on
    #: this installation, 216 were accepted, all 216 were `partial`, 20 had every stage
    #: skipped, and `tests` had never run once. A skipped gate and a vacuous one both award
    #: nothing here, which is what makes the number smaller than `passed` and defensible.
    #:
    #: Nullable: rows written before the ladder existed read as "not assessed", not as zero.
    evidence_level: Mapped[int | None] = mapped_column(nullable=True)
    #: The regime in force when this patch was generated, copied from the plan.
    #:
    #: Denormalised deliberately. A plan's regime can be changed and its patches
    #: regenerated, and a patch that carried only a foreign key would then claim to have
    #: been built under a policy it never saw. The evidence record has to describe the run
    #: that produced it, not the current state of its parent.
    regime: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: What this patch cost the attached model: calls, prompt and completion tokens,
    #: seconds, and which engine answered. Empty for a patch produced without a model at
    #: all -- a deterministic codemod or a replay from the learned-patch cache -- and that
    #: emptiness is the point. QUBIT's claim about an LLM is an efficiency claim, and it
    #: was unmeasurable while nothing recorded the spend: both engines report usage in
    #: their responses and it was read for the answer text and thrown away.
    cost_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    # proposed | approved | rejected | applied | superseded | failed
    status: Mapped[str] = mapped_column(String(32), default="proposed")
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    # Who approved this SPECIFIC patch. `review_patch` already took an `actor` parameter and
    # forwarded it to the audit log (`MigrationEvent.actor`) but never stored it on the patch
    # itself -- so the governance gate's multi-approval policies (PHI/financial data require 2,
    # see `governance_policy.yaml`) had no way to tell one approver from two. `evaluate_gate`
    # counted raw APPROVED ROWS, which one person can produce alone: approve, defer, regenerate,
    # approve again. Recording the approver here is what lets the gate count DISTINCT approvers
    # instead, which is the control the policy exists to provide.
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
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
