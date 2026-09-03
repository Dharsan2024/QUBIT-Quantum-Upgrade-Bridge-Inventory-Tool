from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from qubit_core.db import AssetRow, ProjectRow, ScanRow
from qubit_migrate.state import MigrationPlan, MigrationTask
from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..auth import get_current_tenant
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
logger = logging.getLogger(__name__)


@router.get("", response_model=list[ProjectOut])
def list_projects(
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> list[ProjectOut]:
    rows = session.scalars(
        select(ProjectRow)
        .where(ProjectRow.tenant_id == tenant_id)
        .order_by(ProjectRow.created_at.asc())
    ).all()
    return [ProjectOut.model_validate(row, from_attributes=True) for row in rows]


@router.get("/overview", response_model=list[ProjectOverview])
def projects_overview(
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> list[ProjectOverview]:
    """Every project with the headline numbers each tab's landing grid needs.

    Declared before ``/{project_id}`` on purpose: that route types its parameter as ``UUID``, so a
    later declaration would make this path 422 rather than fall through to here.

    Four aggregate queries, not one per project — the counts come back grouped, so the cost does
    not grow with the number of projects on screen.

    Every aggregate is filtered by tenant. Filtering only the project list and letting the rollups
    span the whole table would be the subtle version of the leak: the names would be right and the
    counts would quietly include another team's findings.
    """
    projects = session.scalars(
        select(ProjectRow)
        .where(ProjectRow.tenant_id == tenant_id)
        .order_by(ProjectRow.created_at.asc())
    ).all()
    if not projects:
        return []

    # The project's LATEST scan, per project. Everything below is scoped to it.
    #
    # These rollups counted every asset row the project had ever produced, so each repeat scan of
    # the same codebase added its findings again: three scans of certbot reported "829 vulnerable"
    # — 293 + 268 + 268, the same code counted three times — while the scans themselves showed the
    # number falling 293 → 268 as migrations landed. The headline said the problem was growing and
    # the tool was making it worse, which is the exact opposite of what had happened.
    #
    # A posture is a statement about code as it stands now, and only the newest scan describes that.
    # History is not lost: it is what the scan list and the trend chart are for.
    latest = (
        select(ScanRow.project_id.label("project_id"), func.max(ScanRow.seq).label("seq"))
        .where(ScanRow.tenant_id == tenant_id)
        .group_by(ScanRow.project_id)
        .subquery()
    )
    newest_scan_ids = (
        select(ScanRow.id)
        .join(
            latest,
            (ScanRow.project_id == latest.c.project_id) & (ScanRow.seq == latest.c.seq),
        )
        .where(ScanRow.tenant_id == tenant_id)
        .scalar_subquery()
    )

    # Asset rollups, grouped by project, over that scan alone.
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
            )
            .where(AssetRow.tenant_id == tenant_id, AssetRow.scan_id.in_(newest_scan_ids))
            .group_by(AssetRow.project_id)
        ).all()
    }

    # Top vulnerable algorithms per project. Ordered so the first rows for each project are its
    # most common ones; the dict comprehension below keeps the first three it sees.
    top_algorithms: dict[UUID, list[str]] = {}
    for pid, algorithm, _count in session.execute(
        select(AssetRow.project_id, AssetRow.algorithm, func.count().label("n"))
        .where(
            AssetRow.qv_vulnerable.is_(True),
            AssetRow.tenant_id == tenant_id,
            # Scoped to the newest scan for the same reason as the rollup above: an algorithm this
            # project has already migrated away from must stop being named as one of its top three.
            AssetRow.scan_id.in_(newest_scan_ids),
        )
        .group_by(AssetRow.project_id, AssetRow.algorithm)
        .order_by(AssetRow.project_id, func.count().desc(), AssetRow.algorithm)
    ).all():
        bucket = top_algorithms.setdefault(pid, [])
        if len(bucket) < 3:
            bucket.append(algorithm)

    scan_counts = {
        pid: n
        for pid, n in session.execute(
            select(ScanRow.project_id, func.count())
            .where(ScanRow.tenant_id == tenant_id)
            .group_by(ScanRow.project_id)
        ).all()
    }

    # Newest scan per project, and newest plan per project. Both lists are small (one row per
    # scan / per plan, capped by history), so they are walked in Python rather than being turned
    # into a correlated subquery that SQLite would run once per project anyway.
    latest_scan: dict[UUID, ScanRow] = {}
    for scan_row in session.scalars(
        select(ScanRow).where(ScanRow.tenant_id == tenant_id).order_by(ScanRow.created_at.desc())
    ).all():
        latest_scan.setdefault(scan_row.project_id, scan_row)

    latest_plan: dict[UUID, MigrationPlan] = {}
    for plan_row in session.scalars(
        select(MigrationPlan)
        .where(MigrationPlan.project_id.is_not(None), MigrationPlan.tenant_id == tenant_id)
        .order_by(MigrationPlan.created_at.desc())
    ).all():
        if plan_row.project_id is not None:
            latest_plan.setdefault(plan_row.project_id, plan_row)

    # Where each plan's work has actually got to, grouped in ONE query rather than one per plan.
    # `stats_json` records what the plan was built as and never moves; this is what separates a
    # migration still in flight from one that is finished, which is what the Migration Hub's
    # "ongoing" and "completed" sections are built on. Read from the tasks' own FSM states so the
    # sections can never disagree with the queue they link to.
    #
    # `deferred` is three different outcomes sharing one state, so it is split by `resolution`:
    # a finding parked as `guided` or `satisfied` is RESOLVED and must not read as outstanding
    # work, while `unresolved` is a failed attempt that is retried on the next build and must.
    progress: dict[UUID, dict[str, int]] = {}
    for plan_id, state, resolution, count in session.execute(
        select(
            MigrationTask.plan_id,
            MigrationTask.state,
            MigrationTask.resolution,
            func.count(),
        )
        # Tasks carry no tenant of their own; they inherit it from the plan one hop up.
        .join(MigrationPlan, MigrationPlan.id == MigrationTask.plan_id)
        .where(MigrationPlan.tenant_id == tenant_id)
        .group_by(MigrationTask.plan_id, MigrationTask.state, MigrationTask.resolution)
    ).all():
        moved_counts = progress.setdefault(plan_id, {})
        if state in ("applied", "verifying", "verified"):
            moved_counts["written"] = moved_counts.get("written", 0) + count
            if state == "verified":
                moved_counts["verified"] = moved_counts.get("verified", 0) + count
        elif state in ("proposed", "approved"):
            moved_counts["prepared"] = moved_counts.get("prepared", 0) + count
        elif state == "deferred" and resolution == "guided":
            moved_counts["guided"] = moved_counts.get("guided", 0) + count
        elif state == "deferred" and resolution == "satisfied":
            moved_counts["satisfied"] = moved_counts.get("satisfied", 0) + count
        else:
            # `ready`, `pending`, `generating`, and `deferred/unresolved` — work that still has
            # something left to happen to it.
            moved_counts["outstanding"] = moved_counts.get("outstanding", 0) + count

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
            moved = progress.get(plan.id, {})
            plan_ref = ProjectPlanRef(
                id=plan.id,
                status=plan.status,
                tasks=int(plan_stats.get("tasks", 0)),
                units=int(plan_stats.get("units", 0)),
                with_codemod=int(plan_stats.get("with_codemod", 0)),
                with_llm_rule=int(plan_stats.get("with_llm_rule", 0)),
                manual=int(plan_stats.get("manual", 0)),
                automatable=int(plan_stats.get("automatable", 0)),
                written=moved.get("written", 0),
                verified=moved.get("verified", 0),
                prepared=moved.get("prepared", 0),
                outstanding=moved.get("outstanding", 0),
                guided=moved.get("guided", 0),
                satisfied=moved.get("satisfied", 0),
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


#: Where a cloned repository is put. Beside the database, so a checkout QUBIT made is as easy to
#: find and delete as the data about it, and never inside the user's own directories.
def _workspace_root() -> Path:
    from qubit_core.db import default_db_url

    url = default_db_url()
    if url.startswith("sqlite:///"):
        return Path(url[len("sqlite:///") :]).parent / "workspaces"
    return Path.home() / ".qubit" / "workspaces"


#: A git URL this endpoint is willing to hand to `git clone`.
#:
#: Anchored, and it rejects a leading `-` explicitly: `git clone --upload-pack=...` is argument
#: injection, and a URL is the one field here that reaches a subprocess.
_GIT_URL = re.compile(
    r"^(?:https://|http://|ssh://|git://|git@)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$"
)


def _clone_for_project(git_url: str, slug: str) -> Path:
    """Clone `git_url` into the workspace and return the checkout.

    Shallow. A depth-1 clone still has a HEAD, which is everything QUBIT asks of the repository:
    `applies` runs `git apply --check` against the index, and `_compute_baseline` materialises the
    pristine tree with `git archive HEAD`. Full history costs minutes on a large repository and buys
    nothing either stage uses.

    Cloning is the one place this tool reaches the network, and it does so only for a URL the user
    typed. Nothing is uploaded: the direction is inward.
    """
    if not _GIT_URL.match(git_url):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"not a git URL QUBIT will clone: {git_url!r}",
        )
    dest = _workspace_root() / slug
    if dest.exists():
        # A second scan of the same project must not fail on a directory that is already correct.
        if (dest / ".git").is_dir():
            return dest
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{dest} exists and is not a git checkout; remove it or rename the project",
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(  # noqa: S603
        ["git", "clone", "--depth", "1", "--", git_url, str(dest)],  # noqa: S607
        capture_output=True,
        # `encoding` explicitly: `text=True` alone decodes with the LOCALE codec, cp1252 on
        # Windows, and a branch or path carrying a non-Latin-1 byte then raises inside the reader.
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
    )
    if proc.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"clone failed: {(proc.stderr or '').strip()[:400] or 'git clone error'}",
        )
    logger.info("cloned %s into %s", git_url, dest)
    return dest


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> ProjectOut:
    slug = slugify(payload.name)
    root_path = payload.root_path
    if root_path is None and payload.git_url:
        root_path = str(_clone_for_project(payload.git_url, slug))
    row = ProjectRow(
        tenant_id=tenant_id,
        name=payload.name,
        slug=slug,
        root_path=root_path,
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
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> ProjectOut:
    project = require_project(session, project_id, tenant_id)
    return ProjectOut.model_validate(project, from_attributes=True)


@router.patch("/{project_id}", response_model=ProjectOut)
def patch_project(
    project_id: UUID,
    payload: ProjectPatch,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> ProjectOut:
    project = require_project(session, project_id, tenant_id)
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
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> None:
    project = require_project(session, project_id, tenant_id)
    # See routers/scans.py's identical rationale: a cascading delete with no caller trail was
    # undiagnosable in practice.
    logger.warning(
        "DELETE /projects/%s (%s, tenant=%s) from %s",
        project_id,
        project.name,
        tenant_id,
        request.client.host if request.client else "unknown",
    )
    session.delete(project)
    session.commit()


@router.delete("")
def delete_all_projects(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> dict[str, int]:
    """The main-panel "Reset" -- every project of THIS team, in one call, not just every scan.

    Clearing scans alone (`DELETE /scans`) leaves the project shells behind on purpose, so a
    repeated scan of the same target has somewhere to land. Reset means something stronger: every
    project's `id` -> `CASCADE` on scans, assets, tasks and migration plans already handles the
    rest, the same as deleting one project does -- this is that, over all of them, in one commit.

    Tenant-filtered, and this is the endpoint where that matters most on a shared engine: an
    unscoped "Reset" would wipe every other team's work from a button one team pressed.
    """
    projects = session.scalars(select(ProjectRow).where(ProjectRow.tenant_id == tenant_id)).all()
    logger.warning(
        "DELETE /projects (bulk, %d project(s), tenant=%s) from %s",
        len(projects),
        tenant_id,
        request.client.host if request.client else "unknown",
    )
    for project in projects:
        session.delete(project)
    session.commit()
    return {"deleted": len(projects)}


@router.get("/{project_id}/trends", response_model=list[TrendPoint])
def get_project_trends(
    project_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> list[TrendPoint]:
    require_project(session, project_id, tenant_id)
    return scan_trends(session, project_id)


@router.get("/{project_id}/scans", response_model=list[dict[str, object]])
def list_project_scans(
    project_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> list[dict[str, object]]:
    require_project(session, project_id, tenant_id)
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
