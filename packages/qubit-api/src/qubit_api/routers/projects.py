from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from qubit_core.db import AssetRow, ProjectRow, ScanRow
from qubit_migrate.state import MigrationPlan
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..deps import get_session
from ..schemas import (
    ProjectCreate,
    ProjectOut,
    ProjectOverview,
    ProjectPatch,
    ProjectPlanRef,
    ProjectScanRef,
    TrendPoint,
)
from ..services import require_project, scan_trends, slugify

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=list[ProjectOut])
def list_projects(session: Annotated[Session, Depends(get_session)]) -> list[ProjectOut]:
    rows = session.scalars(select(ProjectRow).order_by(ProjectRow.created_at.asc())).all()
    return [ProjectOut.model_validate(row, from_attributes=True) for row in rows]


@router.get("/overview", response_model=list[ProjectOverview])
def projects_overview(
    session: Annotated[Session, Depends(get_session)],
) -> list[ProjectOverview]:
    """Every project with the headline numbers each tab's landing grid needs.

    Declared before ``/{project_id}`` on purpose: that route types its parameter as ``UUID``, so a
    later declaration would make this path 422 rather than fall through to here.

    Four aggregate queries, not one per project — the counts come back grouped, so the cost does
    not grow with the number of projects on screen.
    """
    projects = session.scalars(select(ProjectRow).order_by(ProjectRow.created_at.asc())).all()
    if not projects:
        return []

    # Asset rollups, grouped by project.
    asset_stats = {
        row.project_id: row
        for row in session.execute(
            select(
                AssetRow.project_id.label("project_id"),
                func.count().label("assets"),
                func.sum(case((AssetRow.qv_vulnerable.is_(True), 1), else_=0)).label("vulnerable"),
                func.sum(case((AssetRow.qv_attack == "shor", 1), else_=0)).label("shor"),
                func.sum(case((AssetRow.qv_attack == "grover", 1), else_=0)).label("grover"),
                func.avg(AssetRow.risk_score).label("mean_risk"),
                func.max(AssetRow.risk_score).label("max_risk"),
            ).group_by(AssetRow.project_id)
        ).all()
    }

    # Top vulnerable algorithms per project. Ordered so the first rows for each project are its
    # most common ones; the dict comprehension below keeps the first three it sees.
    top_algorithms: dict[UUID, list[str]] = {}
    for pid, algorithm, _count in session.execute(
        select(AssetRow.project_id, AssetRow.algorithm, func.count().label("n"))
        .where(AssetRow.qv_vulnerable.is_(True))
        .group_by(AssetRow.project_id, AssetRow.algorithm)
        .order_by(AssetRow.project_id, func.count().desc(), AssetRow.algorithm)
    ).all():
        bucket = top_algorithms.setdefault(pid, [])
        if len(bucket) < 3:
            bucket.append(algorithm)

    scan_counts = {
        pid: n
        for pid, n in session.execute(
            select(ScanRow.project_id, func.count()).group_by(ScanRow.project_id)
        ).all()
    }

    # Newest scan per project, and newest plan per project. Both lists are small (one row per
    # scan / per plan, capped by history), so they are walked in Python rather than being turned
    # into a correlated subquery that SQLite would run once per project anyway.
    latest_scan: dict[UUID, ScanRow] = {}
    for scan_row in session.scalars(select(ScanRow).order_by(ScanRow.created_at.desc())).all():
        latest_scan.setdefault(scan_row.project_id, scan_row)

    latest_plan: dict[UUID, MigrationPlan] = {}
    for plan_row in session.scalars(
        select(MigrationPlan)
        .where(MigrationPlan.project_id.is_not(None))
        .order_by(MigrationPlan.created_at.desc())
    ).all():
        if plan_row.project_id is not None:
            latest_plan.setdefault(plan_row.project_id, plan_row)

    out: list[ProjectOverview] = []
    for project in projects:
        stats = asset_stats.get(project.id)
        scan: ScanRow | None = latest_scan.get(project.id)
        plan: MigrationPlan | None = latest_plan.get(project.id)
        plan_ref = None
        if plan is not None:
            # Same derivation as the migrate router: a plan built before the three-way split has
            # only `automatable`, and showing it as "0 automatic" on the grid is wrong.
            from ..routers.migrate import _plan_split

            plan_stats = {**(plan.stats_json or {}), **_plan_split(plan)}
            plan_ref = ProjectPlanRef(
                id=plan.id,
                status=plan.status,
                tasks=int(plan_stats.get("tasks", 0)),
                units=int(plan_stats.get("units", 0)),
                with_codemod=int(plan_stats.get("with_codemod", 0)),
                with_llm_rule=int(plan_stats.get("with_llm_rule", 0)),
                manual=int(plan_stats.get("manual", 0)),
                automatable=int(plan_stats.get("automatable", 0)),
                created_at=plan.created_at,
                scan_id=plan.scan_id,
                # A plan is stale once a scan finished after it was built — its queue describes a
                # snapshot of the project that no longer exists.
                stale=bool(scan is not None and scan.created_at > plan.created_at),
            )
        out.append(
            ProjectOverview(
                id=project.id,
                name=project.name,
                slug=project.slug,
                description=project.description,
                created_at=project.created_at,
                scans=int(scan_counts.get(project.id, 0)),
                latest_scan=(
                    ProjectScanRef(
                        id=scan.id,
                        seq=scan.seq,
                        status=scan.status,
                        targets=scan.targets or [],
                        created_at=scan.created_at,
                        assets=int((scan.stats or {}).get("assets", 0) or 0),
                    )
                    if scan
                    else None
                ),
                assets=int(stats.assets or 0) if stats else 0,
                vulnerable=int(stats.vulnerable or 0) if stats else 0,
                shor=int(stats.shor or 0) if stats else 0,
                grover=int(stats.grover or 0) if stats else 0,
                mean_risk=float(stats.mean_risk) if stats and stats.mean_risk is not None else None,
                max_risk=float(stats.max_risk) if stats and stats.max_risk is not None else None,
                top_algorithms=top_algorithms.get(project.id, []),
                plan=plan_ref,
            )
        )
    return out


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    session: Annotated[Session, Depends(get_session)],
) -> ProjectOut:
    row = ProjectRow(
        name=payload.name,
        slug=slugify(payload.name),
        root_path=payload.root_path,
        description=payload.description,
    )
    session.add(row)
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="project already exists",
        ) from exc
    session.refresh(row)
    return ProjectOut.model_validate(row, from_attributes=True)


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(
    project_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> ProjectOut:
    project = require_project(session, project_id)
    return ProjectOut.model_validate(project, from_attributes=True)


@router.patch("/{project_id}", response_model=ProjectOut)
def patch_project(
    project_id: UUID,
    payload: ProjectPatch,
    session: Annotated[Session, Depends(get_session)],
) -> ProjectOut:
    project = require_project(session, project_id)
    if payload.root_path is not None:
        project.root_path = payload.root_path
    if payload.description is not None:
        project.description = payload.description
    if payload.settings is not None:
        project.settings = payload.settings
    session.add(project)
    session.commit()
    session.refresh(project)
    return ProjectOut.model_validate(project, from_attributes=True)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> None:
    project = require_project(session, project_id)
    session.delete(project)
    session.commit()


@router.get("/{project_id}/trends", response_model=list[TrendPoint])
def get_project_trends(
    project_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> list[TrendPoint]:
    require_project(session, project_id)
    return scan_trends(session, project_id)


@router.get("/{project_id}/scans", response_model=list[dict[str, object]])
def list_project_scans(
    project_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> list[dict[str, object]]:
    require_project(session, project_id)
    scans = session.scalars(
        select(ScanRow).where(ScanRow.project_id == project_id).order_by(ScanRow.seq.desc())
    ).all()
    return [
        {
            "id": str(scan.id),
            "project_id": str(scan.project_id),
            "seq": scan.seq,
            "label": scan.label,
            "status": scan.status,
            "targets": scan.targets,
            "scanners": scan.scanners,
            "stats": scan.stats,
            "error": scan.error,
            "started_at": scan.started_at,
            "finished_at": scan.finished_at,
            "created_at": scan.created_at,
        }
        for scan in scans
    ]
