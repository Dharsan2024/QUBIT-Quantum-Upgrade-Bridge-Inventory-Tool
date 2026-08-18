from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from qubit_core.db import ScanRow
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..deps import get_session
from ..schemas import JobRef, ScanCreate, ScanCreateResponse, ScanOut
from ..services import (
    export_scan_cbom,
    require_project,
    require_scan,
    run_scan,
    scan_cnsa2,
    scan_diff,
    scan_pdf,
    scan_sarif,
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
    scan, job_id = run_scan(
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
        job=JobRef(id=job_id, kind="scan") if job_id else None,
        warning=(
            f"Scan dispatched to the job runner as job {job_id}. It runs off the request path, so "
            f"this response reports status 'running' with no assets yet — poll "
            f"GET /api/v1/scans/{scan.id} until status leaves queued/running, then read its assets."
            if job_id
            else "Scan executed inline; this response is already final."
        ),
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


@router.get("/scans/{scan_id}/cnsa2")
def get_scan_cnsa2(
    scan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, object]:
    """CNSA 2.0 migration-milestone posture for this scan's inventory.

    The deterministic, regulatory counterpart to the probabilistic HNDL score: CNSA 2.0 fixes real
    deadlines (2025 → 2035), so this answers "are we on track against the mandate" while the risk
    engine answers "what should we fix first".
    """
    require_scan(session, scan_id)
    return scan_cnsa2(session, scan_id)


@router.get("/scans/{scan_id}/sarif")
def get_scan_sarif(
    scan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    include_safe: Annotated[
        bool, Query(description="Also emit notes for quantum-safe assets.")
    ] = False,
) -> dict[str, object]:
    """SARIF 2.1.0 log — uploadable to GitHub code scanning, readable by VS Code and Azure
    DevOps."""
    require_scan(session, scan_id)
    return scan_sarif(session, scan_id, include_safe=include_safe)


@router.get(
    "/scans/{scan_id}/report.pdf",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}}, "description": "Paginated PDF report."}},
)
def get_scan_pdf(
    scan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """The paginated PDF a compliance submission or leadership review attaches.

    Distinct from the dashboard's browser print: this is the real report `qubit_core.report.pdf`
    composes — verdict first, then the drivers, then the itemized findings.
    """
    require_scan(session, scan_id)
    pdf = scan_pdf(session, scan_id)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            # `inline` so a browser tab can preview it; the dashboard passes a filename when saving.
            "Content-Disposition": f'inline; filename="qubit-report-{scan_id}.pdf"'
        },
    )
