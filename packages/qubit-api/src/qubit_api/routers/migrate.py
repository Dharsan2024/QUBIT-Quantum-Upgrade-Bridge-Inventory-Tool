"""Migration workflow endpoints (doc 03 §5.1 exposed over REST — M2).

Wraps :class:`qubit_migrate.MigrationOrchestrator`; plan → queue → generate → review → apply.
Importing the state models here also registers the migration tables on the shared ``Base`` so
``create_schema_on_startup`` creates them.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from qubit_core.db import AssetRow, ProjectRow
from qubit_migrate.orchestrator import MigrationOrchestrator
from qubit_migrate.state import MigrationPlan, MigrationTask, PatchProposal
from qubit_migrate.state.machine import InvalidTransition
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..deps import get_session
from ..schemas import UtcDateTime

router = APIRouter(tags=["migrate"])


# ── Schemas ──────────────────────────────────────────────────────────────────


class PlanCreate(BaseModel):
    min_risk: float = Field(0.0, ge=0.0, le=1.0)
    # Optional so the pre-scoping call shape (`{"min_risk": 0}`) still means what it always meant:
    # a plan across everything. The app always sends a project.
    project_id: UUID | None = None
    scan_id: UUID | None = None


class PlanOut(BaseModel):
    id: UUID
    status: str
    stats: dict
    # `UtcDateTime`, not a hand-rolled `.isoformat()` string. SQLite has no timezone type, so the
    # value comes back naive and `.isoformat()` emitted `2026-08-20T15:51:25.853134` with no
    # offset — which JavaScript parses as LOCAL time. On this UTC+5:30 machine a plan built two
    # seconds ago looked 5.5 hours OLDER than the scan it was built from, so the Migration Hub
    # showed "this plan is outdated, rebuild it" on every freshly built plan. `schemas._ensure_utc`
    # already existed for exactly this failure (it was fixed for scans); this router had simply
    # never adopted it.
    created_at: UtcDateTime
    project_id: UUID | None = None
    scan_id: UUID | None = None
    scope: dict = Field(default_factory=dict)


class TaskOut(BaseModel):
    id: UUID
    plan_id: UUID
    unit_id: UUID
    asset_id: UUID
    state: str
    rule_id: str | None
    #: True when `rule_id` names a rule with a deterministic codemod. Without it the app cannot
    #: know that picking the "template" generator will 422, so it offered the option anyway.
    has_codemod: bool = False
    priority: float
    rank: int
    effort_points: int
    last_error: str | None
    # denormalized asset context for the UI
    algorithm: str | None = None
    key_size: int | None = None
    file_path: str | None = None
    line: int | None = None
    risk_score: float | None = None
    # The remaining asset context the queue table had no way to show. Without these a row read
    # "AES-128 · 0.412" with no way to tell a config finding from a certificate or to know whether
    # the number is a signing key or a hash, which is most of what decides how a task is handled.
    asset_type: str | None = None
    source_scanner: str | None = None
    usage_context: str | None = None
    sensitivity: str | None = None
    mosca_margin_years: float | None = None
    effort_hours_low: float | None = None
    effort_hours_high: float | None = None
    effort_drivers: list[str] = Field(default_factory=list)
    #: Migration advice, when it has been generated. Present on the task so the queue can show
    #: which entries already have guidance without a request per row.
    advice_text: str | None = None
    advice_model: str | None = None


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


def _plan_split(plan: MigrationPlan) -> dict[str, int]:
    """The automatic / LLM-assisted / manual counts for a plan.

    Stored on the plan when it was built. Plans built before the split existed carry only
    `automatable` (a count of tasks with a rule of ANY kind), and rendering those as
    "0 automatic, 0 LLM-assisted" is wrong — measured on the live installation, 2 of 7 plans. The
    counts are derived from the plan's own tasks in that case, so an old plan reads correctly
    without having to be rebuilt.
    """
    stats = plan.stats_json or {}
    if "with_codemod" in stats:
        return {
            "with_codemod": int(stats.get("with_codemod", 0)),
            "with_llm_rule": int(stats.get("with_llm_rule", 0)),
            "manual": int(stats.get("manual", 0)),
        }
    codemod_rules = _codemod_rule_ids()
    with_codemod = sum(1 for t in plan.tasks if t.rule_id in codemod_rules)
    with_rule = sum(1 for t in plan.tasks if t.rule_id)
    return {
        "with_codemod": with_codemod,
        "with_llm_rule": with_rule - with_codemod,
        "manual": len(plan.tasks) - with_rule,
    }


def _plan_out(plan: MigrationPlan) -> PlanOut:
    return PlanOut(
        id=plan.id,
        status=plan.status,
        stats={**(plan.stats_json or {}), **_plan_split(plan)},
        created_at=plan.created_at,
        project_id=plan.project_id,
        scan_id=plan.scan_id,
        scope=plan.scope_json or {},
    )


@lru_cache(maxsize=1)
def _codemod_rule_ids() -> frozenset[str]:
    """Ids of the rules that carry a deterministic codemod.

    Cached because the rule pack is read-only at runtime and this is consulted once per task in a
    queue that can be several hundred rows long.
    """
    from qubit_migrate.transform import load_rules

    return frozenset(r.id for r in load_rules() if r.codemod)


def _task_out(task: MigrationTask, row: AssetRow | None) -> TaskOut:
    loc = (row.location or {}) if row else {}
    effort = task.effort_json or {}
    drivers = effort.get("drivers") or []
    return TaskOut(
        id=task.id,
        plan_id=task.plan_id,
        unit_id=task.unit_id,
        asset_id=task.asset_id,
        state=task.state,
        rule_id=task.rule_id,
        has_codemod=task.rule_id in _codemod_rule_ids(),
        priority=task.priority,
        rank=task.rank,
        effort_points=task.effort_points,
        last_error=task.last_error,
        algorithm=row.algorithm if row else None,
        key_size=row.key_size if row else None,
        file_path=loc.get("file_path"),
        line=loc.get("line"),
        risk_score=row.risk_score if row else None,
        asset_type=row.asset_type if row else None,
        source_scanner=row.source_scanner if row else None,
        usage_context=row.usage_context if row else None,
        sensitivity=row.sensitivity if row else None,
        mosca_margin_years=row.mosca_margin_years if row else None,
        effort_hours_low=effort.get("hours_low"),
        effort_hours_high=effort.get("hours_high"),
        effort_drivers=[str(d) for d in drivers],
        advice_text=task.advice_text,
        advice_model=task.advice_model,
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
    if payload.project_id is not None and not session.get(ProjectRow, payload.project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    orch = MigrationOrchestrator(session)
    plan = orch.build_plan(
        min_risk=payload.min_risk,
        project_id=payload.project_id,
        scan_id=payload.scan_id,
    )
    return _plan_out(plan)


@router.get("/migrate/plans", response_model=list[PlanOut])
def list_plans(
    session: Annotated[Session, Depends(get_session)],
    project_id: UUID | None = None,
    limit: int = Query(50, ge=1, le=200),
) -> list[PlanOut]:
    """Plans, newest first.

    `project_id` filters to one project. Without it every plan is returned, including the
    unscoped ones built before plans carried a project — the caller can tell them apart by
    `project_id` being null rather than having them silently folded into some project's list.
    """
    stmt = select(MigrationPlan).order_by(MigrationPlan.created_at.desc()).limit(limit)
    if project_id is not None:
        stmt = stmt.where(MigrationPlan.project_id == project_id)
    plans = session.scalars(stmt).all()
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
    except InvalidTransition as e:
        # Generating twice for the same task. The task FSM only allows `generate` from `ready`, and
        # a second call arrives with the task already in `proposed` — which is reachable from the
        # app by double-clicking Generate before the queue refetches, and was an uncaught 500 with
        # a stack trace. 409 is the accurate answer: the request conflicts with the task's current
        # state, and the existing patch is the thing to look at.
        raise HTTPException(
            status_code=409,
            detail=(
                f"{e} — this task already has a generated patch. Review or reject it before "
                "generating another."
            ),
        ) from e
    except (ValueError, NotImplementedError) as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return _patch_out(patch)


class AdviseRequest(BaseModel):
    force: bool = False


@router.post("/migrate/tasks/{task_id}/advise", response_model=TaskOut)
def advise_task(
    task_id: UUID,
    payload: AdviseRequest,
    session: Annotated[Session, Depends(get_session)],
) -> TaskOut:
    """Ask the local model how to migrate this finding by hand.

    For the tasks QUBIT cannot patch — a structural protocol change, a language with no codemod, a
    SQL dialect the token swap cannot express — the queue otherwise says "manual change" and stops.
    This is the other half: what the code does, why it is a problem, what to change in THIS file,
    what it breaks, and how to prove it is gone.

    Needs Ollama. Cached on the task; `force` regenerates.
    """
    orch = MigrationOrchestrator(session)
    try:
        task = orch.advise_task(task_id, force=payload.force)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e)) from e
    return _task_out(task, session.get(AssetRow, task.asset_id))


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
    from qubit_core.db import AssetRow
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
    from qubit_migrate.governance import evaluate_gate
    from qubit_migrate.state.models import MigrationTask

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
