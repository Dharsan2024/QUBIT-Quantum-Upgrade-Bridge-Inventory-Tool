from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from qubit_core.db import ScanRow
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..deps import get_session
from ..schemas import ScanCreate, ScanCreateResponse, ScanOut
from ..services import (
    export_scan_cbom,
    require_project,
    require_scan,
    run_scan,
    scan_diff,
    scan_summary,
)

router = APIRouter(tags=["scans"])


@router.post(
    "/projects/{project_id}/scans",
    response_model=ScanCreateResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_scan(
    project_id: UUID,
    payload: ScanCreate,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
) -> ScanCreateResponse:
    project = require_project(session, project_id)
    scan = run_scan(
        session,
        project=project,
        targets=payload.targets,
        scanners=[scanner.value for scanner in payload.scanners],
        label=payload.label,
        job_runner=getattr(request.app.state, "job_runner", None),
        run_risk=payload.run_risk,
    )
    return ScanCreateResponse(
        scan=ScanOut(
            id=scan.id,
            project_id=scan.project_id,
            seq=scan.seq,
            label=scan.label,
            status=scan.status,
            targets=scan.targets,
            scanners=scan.scanners,
            stats=scan.stats,
            error=scan.error,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            created_at=scan.created_at,
        ),
        warning="Synchronous scan execution is enabled in M1; JobRunner lands in M2.",
    )


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> ScanOut:
    scan = require_scan(session, scan_id)
    return ScanOut(
        id=scan.id,
        project_id=scan.project_id,
        seq=scan.seq,
        label=scan.label,
        status=scan.status,
        targets=scan.targets,
        scanners=scan.scanners,
        stats=scan.stats,
        error=scan.error,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        created_at=scan.created_at,
    )


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> None:
    scan = require_scan(session, scan_id)
    session.delete(scan)
    session.commit()


@router.get("/scans/{scan_id}/summary")
def get_scan_summary(
    scan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, object]:
    require_scan(session, scan_id)
    return scan_summary(session, scan_id)


@router.get("/scans/{scan_id}/diff")
def get_scan_diff(
    scan_id: UUID,
    against: Annotated[UUID, Query(...)],
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, object]:
    require_scan(session, scan_id)
    require_scan(session, against)
    return scan_diff(session, scan_id, against)


@router.get("/scans/{scan_id}/cbom")
def get_scan_cbom(
    scan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, object]:
    require_scan(session, scan_id)
    return export_scan_cbom(session, scan_id)


@router.get("/scans")
def list_scans(session: Annotated[Session, Depends(get_session)]) -> list[ScanOut]:
    scans = session.scalars(select(ScanRow).order_by(ScanRow.created_at.desc())).all()
    return [
        ScanOut(
            id=scan.id,
            project_id=scan.project_id,
            seq=scan.seq,
            label=scan.label,
            status=scan.status,
            targets=scan.targets,
            scanners=scan.scanners,
            stats=scan.stats,
            error=scan.error,
            started_at=scan.started_at,
            finished_at=scan.finished_at,
            created_at=scan.created_at,
        )
        for scan in scans
    ]
