"""Migration workflow endpoints (doc 03 §5.1 exposed over REST — M2).

Wraps :class:`qubit_migrate.MigrationOrchestrator`; plan → queue → generate → review → apply.
Importing the state models here also registers the migration tables on the shared ``Base`` so
``create_schema_on_startup`` creates them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from qubit_core.db import AssetRow
from qubit_migrate.orchestrator import MigrationOrchestrator
from qubit_migrate.state import MigrationPlan, MigrationTask, PatchProposal
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..deps import get_session

router = APIRouter(tags=["migrate"])


# ── Schemas ──────────────────────────────────────────────────────────────────


class PlanCreate(BaseModel):
    min_risk: float = Field(0.0, ge=0.0, le=1.0)


class PlanOut(BaseModel):
    id: UUID
    status: str
    stats: dict
    created_at: str


class TaskOut(BaseModel):
    id: UUID
    plan_id: UUID
    asset_id: UUID
    state: str
    rule_id: str | None
    priority: float
    rank: int
    effort_points: int
    last_error: str | None
    # denormalized asset context for the UI
    algorithm: str | None = None
    file_path: str | None = None
    line: int | None = None
    risk_score: float | None = None


class GenerateRequest(BaseModel):
    repo_root: str | None = None
    generator: Literal["auto", "llm", "template"] = "auto"


class PatchOut(BaseModel):
    id: UUID
    task_id: UUID
    generator: str
    model_name: str | None = None
    file_path: str
    diff_text: str
    validation: dict
    status: str
    review_note: str | None
    applied_branch: str | None
    applied_commit: str | None


class ReviewRequest(BaseModel):
    approve: bool
    note: str = ""


class ApplyRequest(BaseModel):
    repo_root: str
    branch: str | None = None


# ── Helpers ──────────────────────────────────────────────────────────────────


def _plan_out(plan: MigrationPlan) -> PlanOut:
    return PlanOut(
        id=plan.id,
        status=plan.status,
        stats=plan.stats_json or {},
        created_at=plan.created_at.isoformat(),
    )


def _task_out(task: MigrationTask, row: AssetRow | None) -> TaskOut:
    loc = (row.location or {}) if row else {}
    return TaskOut(
        id=task.id,
        plan_id=task.plan_id,
        asset_id=task.asset_id,
        state=task.state,
        rule_id=task.rule_id,
        priority=task.priority,
        rank=task.rank,
        effort_points=task.effort_points,
        last_error=task.last_error,
        algorithm=row.algorithm if row else None,
        file_path=loc.get("file_path"),
        line=loc.get("line"),
        risk_score=row.risk_score if row else None,
    )


def _patch_out(patch: PatchProposal) -> PatchOut:
    return PatchOut(
        id=patch.id,
        task_id=patch.task_id,
        generator=patch.generator,
        model_name=patch.model_name,
        file_path=patch.file_path,
        diff_text=patch.diff_text,
        validation=patch.validation_json or {},
        status=patch.status,
        review_note=patch.review_note,
        applied_branch=patch.applied_branch,
        applied_commit=patch.applied_commit,
    )


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("/migrate/plans", response_model=PlanOut, status_code=status.HTTP_201_CREATED)
def create_plan(
    payload: PlanCreate,
    session: Annotated[Session, Depends(get_session)],
) -> PlanOut:
    orch = MigrationOrchestrator(session)
    plan = orch.build_plan(min_risk=payload.min_risk)
    return _plan_out(plan)


@router.get("/migrate/plans", response_model=list[PlanOut])
def list_plans(session: Annotated[Session, Depends(get_session)]) -> list[PlanOut]:
    plans = session.scalars(
        select(MigrationPlan).order_by(MigrationPlan.created_at.desc()).limit(20)
    ).all()
    return [_plan_out(p) for p in plans]


@router.get("/migrate/plans/{plan_id}/queue", response_model=list[TaskOut])
def get_queue(
    plan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> list[TaskOut]:
    if not session.get(MigrationPlan, plan_id):
        raise HTTPException(status_code=404, detail="Plan not found")
    tasks = session.scalars(
        select(MigrationTask).where(MigrationTask.plan_id == plan_id).order_by(MigrationTask.rank)
    ).all()
    return [_task_out(t, session.get(AssetRow, t.asset_id)) for t in tasks]


@router.post("/migrate/tasks/{task_id}/generate", response_model=PatchOut)
def generate_patch(
    task_id: UUID,
    payload: GenerateRequest,
    session: Annotated[Session, Depends(get_session)],
) -> PatchOut:
    orch = MigrationOrchestrator(session)
    try:
        patch = orch.generate_patch(
            task_id,
            generator=payload.generator,
            repo_root=Path(payload.repo_root) if payload.repo_root else None,
        )
    except (ValueError, NotImplementedError) as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return _patch_out(patch)


@router.get("/migrate/tasks/{task_id}/patches", response_model=list[PatchOut])
def list_task_patches(
    task_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> list[PatchOut]:
    patches = session.scalars(
        select(PatchProposal)
        .where(PatchProposal.task_id == task_id)
        .order_by(PatchProposal.created_at.desc())
    ).all()
    return [_patch_out(p) for p in patches]


@router.get("/migrate/plans/{plan_id}/graph")
def get_plan_graph(
    plan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> dict:
    from qubit_core import row_to_asset
    from qubit_core.db import AssetRow, ScanRow
    from qubit_migrate.graph.builder import build_dependency_graph
    from qubit_migrate.graph.export import serialize_graph
    from qubit_migrate.graph.order import migration_order

    plan = session.get(MigrationPlan, plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Plan not found")

    asset_ids = [t.asset_id for t in plan.tasks]
    if not asset_ids:
        return {"nodes": [], "edges": [], "units": []}

    asset_rows = session.scalars(select(AssetRow).where(AssetRow.id.in_(asset_ids))).all()
    assets = [row_to_asset(row) for row in asset_rows]
    id_to_asset = {a.id: a for a in assets}

    g = build_dependency_graph(assets)
    units = migration_order(g, id_to_asset=id_to_asset)

    return serialize_graph(g, units)


@router.get("/migrate/tasks/{task_id}/governance")
def get_task_governance(
    task_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> dict:
    from qubit_migrate.state.models import MigrationTask
    from qubit_migrate.governance import evaluate_gate

    task = session.get(MigrationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return evaluate_gate(task, session)


@router.post("/migrate/patches/{patch_id}/review", response_model=PatchOut)
def review_patch(
    patch_id: UUID,
    payload: ReviewRequest,
    session: Annotated[Session, Depends(get_session)],
) -> PatchOut:
    orch = MigrationOrchestrator(session)
    try:
        patch = orch.review_patch(patch_id, approve=payload.approve, note=payload.note, actor="api")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return _patch_out(patch)


@router.post("/migrate/patches/{patch_id}/apply", response_model=PatchOut)
def apply_patch(
    patch_id: UUID,
    payload: ApplyRequest,
    session: Annotated[Session, Depends(get_session)],
) -> PatchOut:
    repo_root = Path(payload.repo_root)
    if not repo_root.is_dir():
        raise HTTPException(status_code=422, detail=f"repo_root {payload.repo_root} not found")
    orch = MigrationOrchestrator(session)
    try:
        patch = orch.apply_patch(patch_id, repo_root=repo_root, branch=payload.branch, actor="api")
    except Exception as e:  # EditApplyError / ValueError / subprocess errors
        msg = str(e)
        if "Governance gate blocked" in msg:
            raise HTTPException(status_code=409, detail=msg) from e
        raise HTTPException(status_code=422, detail=msg) from e
    return _patch_out(patch)
