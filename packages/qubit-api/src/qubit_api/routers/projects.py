from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from qubit_core.db import ProjectRow, ScanRow
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..deps import get_session
from ..schemas import ProjectCreate, ProjectOut, ProjectPatch, TrendPoint
from ..services import require_project, scan_trends, slugify

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("", response_model=list[ProjectOut])
def list_projects(session: Annotated[Session, Depends(get_session)]) -> list[ProjectOut]:
    rows = session.scalars(select(ProjectRow).order_by(ProjectRow.created_at.asc())).all()
    return [ProjectOut.model_validate(row, from_attributes=True) for row in rows]


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
