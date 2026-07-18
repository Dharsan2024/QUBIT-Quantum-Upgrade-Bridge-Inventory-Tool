from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from qubit_core.db import Job, RiskRun, ScanRow
from qubit_risk import CRQCTimelineSimulator
from qubit_risk.timeline.survey import BlendedTimeline
from sqlalchemy.orm import Session

from ..deps import get_session
from ..jobs.runner import JobRunner

router = APIRouter(tags=["risk"])


class RiskRunOut(BaseModel):
    id: UUID
    scan_id: UUID
    status: str
    params: dict
    timeline: list | None = None
    percentiles: dict | None = None
    summary: dict | None = None
    started_at: str | None = None
    finished_at: str | None = None

    class Config:
        from_attributes = True


class RiskRunRequest(BaseModel):
    params: dict = {}


@router.post("/scans/{scan_id}/risk/run", status_code=status.HTTP_202_ACCEPTED)
async def run_risk_for_scan(
    scan_id: UUID,
    request: Request,
    payload: RiskRunRequest,
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, str]:
    scan = session.get(ScanRow, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Check for concurrent running risk jobs on this scan
    existing = (
        session.query(RiskRun)
        .filter(RiskRun.scan_id == scan_id, RiskRun.status.in_(["queued", "running"]))
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409, detail=f"Risk run already in progress (run id: {existing.id})"
        )

    job = Job(
        kind="risk",
        project_id=scan.project_id,
        ref_id=scan_id,
        payload={
            "scan_id": str(scan_id),
            "params": payload.params,
        },
    )
    session.add(job)
    session.commit()
    session.refresh(job)

    runner: JobRunner = request.app.state.job_runner
    runner.submit(job.id)  # sync: schedules the async job; do not await

    return {"job_id": str(job.id), "status": "queued"}


@router.get("/risk/runs/{risk_run_id}", response_model=RiskRunOut)
def get_risk_run(
    risk_run_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> RiskRun:
    risk_run = session.get(RiskRun, risk_run_id)
    if not risk_run:
        raise HTTPException(status_code=404, detail="Risk run not found")
    return risk_run


@router.get("/scans/{scan_id}/risk/summary")
def get_risk_summary(
    scan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> dict:
    risk_run = (
        session.query(RiskRun)
        .filter(RiskRun.scan_id == scan_id)
        .order_by(RiskRun.finished_at.desc())
        .first()
    )
    if not risk_run or risk_run.status != "succeeded":
        raise HTTPException(status_code=404, detail="Completed risk run not found for this scan")
    return risk_run.summary or {}


@router.get("/scans/{scan_id}/risk/timeline")
def get_risk_timeline(
    scan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> dict:
    risk_run = (
        session.query(RiskRun)
        .filter(RiskRun.scan_id == scan_id)
        .order_by(RiskRun.finished_at.desc())
        .first()
    )
    if not risk_run or risk_run.status != "succeeded":
        raise HTTPException(status_code=404, detail="Completed risk run not found for this scan")
    return {"timeline": risk_run.timeline or [], "percentiles": risk_run.percentiles or {}}


# On-demand CRQC timeline for a single algorithm — runs the real Monte-Carlo simulator (doc 02 §5.3
# `GET /risk/timeline?algorithm=`). No scan required; used by the dashboard's CRQC Timeline page.
# blend=true additionally fuses the expert-survey CDF (doc 02 §6.1.5); weight overrides w.
_SIM = CRQCTimelineSimulator()
_BLEND = BlendedTimeline()


@router.get("/risk/timeline")
def get_algorithm_timeline(
    algorithm: str = "RSA-2048",
    blend: bool = False,
    weight: float | None = None,
) -> dict:
    curve = _BLEND.blend(algorithm, weight=weight) if blend else _SIM.simulate(algorithm)
    if curve is None:
        raise HTTPException(
            status_code=404,
            detail=f"No CRQC timeline for '{algorithm}' (not Shor-vulnerable / unknown)",
        )
    used_weight = (_BLEND.cfg.survey_weight if weight is None else weight) if blend else None
    return {
        "algorithm": curve.algorithm,
        "blended": blend,
        "survey_weight": used_weight,
        "years": curve.years,
        "cdf": curve.cdf,
        "cdf_stderr": curve.cdf_stderr,
        "median_year": curve.median_year,
        "p05_year": curve.p05_year,
        "p95_year": curve.p95_year,
        "n_trials": curve.n_trials,
    }
