from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from qubit_core.db import Job
from sqlalchemy import select
from sqlalchemy.orm import Session
from sse_starlette.sse import EventSourceResponse

from ..auth import get_current_tenant
from ..deps import get_session
from ..jobs.bus import EventBus
from ..jobs.runner import JobRunner

router = APIRouter(tags=["jobs"])


class JobOut(BaseModel):
    id: UUID
    kind: str
    status: str
    project_id: UUID | None = None
    ref_id: UUID | None = None
    progress: float
    stage: str
    message: str
    payload: dict
    result: dict | None = None
    error: str | None = None
    # These are `datetime` on the ORM model (qubit_core.db.models.Job) and every other router's
    # schema declares them as `datetime` too. Declaring them `str` here made Pydantic v2 response
    # validation fail on a real datetime, so BOTH /jobs and /jobs/{id} returned 500 for any
    # non-empty jobs table. FastAPI serializes datetime to ISO-8601 in JSON, so the wire format is
    # unchanged from what the schema intended.
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


def _require_job(session: Session, job_id: UUID, tenant_id: UUID) -> Job:
    """A job, scoped to the team that queued it. 404 (not 403) when it belongs to another team."""
    job = session.scalar(select(Job).where(Job.id == job_id, Job.tenant_id == tenant_id))
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/jobs", response_model=list[JobOut])
def list_jobs(
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
    project_id: UUID | None = None,
    limit: int = 100,
) -> list[Job]:
    query = session.query(Job).filter(Job.tenant_id == tenant_id)
    if project_id:
        query = query.filter(Job.project_id == project_id)
    return query.order_by(Job.created_at.desc()).limit(limit).all()


@router.get("/jobs/{job_id}", response_model=JobOut)
def get_job(
    job_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> Job:
    return _require_job(session, job_id, tenant_id)


@router.post("/jobs/{job_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
def cancel_job(
    job_id: UUID,
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    tenant_id: Annotated[UUID, Depends(get_current_tenant)],
) -> dict[str, str]:
    job = _require_job(session, job_id, tenant_id)
    if job.status not in ("queued", "running"):
        raise HTTPException(status_code=400, detail=f"Cannot cancel job in status {job.status}")

    runner: JobRunner = request.app.state.job_runner
    runner.cancel(job_id)
    return {"status": "cancel requested"}


async def _sse_generator(bus: EventBus, request: Request, job_id: UUID | None = None):
    last_event_id = request.headers.get("Last-Event-ID")

    # We use a context manager if sse_starlette had one, but it handles GeneratorExit.
    try:
        async for ev in bus.subscribe(last_event_id):
            if await request.is_disconnected():
                break

            # Filter by job_id if requested
            if job_id:
                import json

                try:
                    data = json.loads(ev.data)
                    if data.get("job_id") != str(job_id):
                        continue
                except json.JSONDecodeError:
                    continue

            yield {"id": ev.id, "event": ev.event, "data": ev.data}
    except asyncio.CancelledError:
        pass


@router.get("/events")
async def global_events(request: Request) -> EventSourceResponse:
    bus: EventBus = request.app.state.event_bus
    return EventSourceResponse(_sse_generator(bus, request))


@router.get("/jobs/{job_id}/events")
async def job_events(job_id: UUID, request: Request) -> EventSourceResponse:
    bus: EventBus = request.app.state.event_bus
    return EventSourceResponse(_sse_generator(bus, request, job_id=job_id))
