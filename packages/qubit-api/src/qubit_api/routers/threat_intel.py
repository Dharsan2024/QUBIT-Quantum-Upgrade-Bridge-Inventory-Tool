"""Optional, opt-in checks against a small curated allowlist of PQC reference pages.

See :mod:`qubit_risk.threat_intel` for the offline-stance rationale: off by default, a fixed
allowlist rather than open web access, and no automatic write to the versioned risk-parameter
YAML files — a changed source only ever produces a snapshot for a human to read and mark
reviewed.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from qubit_core.db.models import ThreatIntelConfig, ThreatIntelSnapshot
from qubit_core.schemas import utcnow
from qubit_risk.threat_intel import SOURCES, check_now
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..deps import get_session
from ..schemas import (
    ThreatIntelConfigOut,
    ThreatIntelConfigPatch,
    ThreatIntelReviewRequest,
    ThreatIntelSnapshotOut,
    ThreatIntelSourceOut,
)

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])

_SOURCES_OUT = [
    ThreatIntelSourceOut(id=s.id, url=s.url, label=s.label, note=s.note) for s in SOURCES
]


def _get_or_create_config(session: Session) -> ThreatIntelConfig:
    # Singleton row, id fixed at 1 (see ThreatIntelConfig's docstring) - lazily created so a
    # fresh install doesn't need a data migration just to seed one disabled row.
    config = session.get(ThreatIntelConfig, 1)
    if config is None:
        config = ThreatIntelConfig(id=1, enabled=False, check_interval_hours=24)
        session.add(config)
        session.commit()
        session.refresh(config)
    return config


def _to_config_out(config: ThreatIntelConfig) -> ThreatIntelConfigOut:
    return ThreatIntelConfigOut(
        enabled=config.enabled,
        check_interval_hours=config.check_interval_hours,
        last_checked_at=config.last_checked_at,
        sources=_SOURCES_OUT,
    )


@router.get("/config", response_model=ThreatIntelConfigOut)
def get_config(session: Annotated[Session, Depends(get_session)]) -> ThreatIntelConfigOut:
    return _to_config_out(_get_or_create_config(session))


@router.patch("/config", response_model=ThreatIntelConfigOut)
def patch_config(
    payload: ThreatIntelConfigPatch, session: Annotated[Session, Depends(get_session)]
) -> ThreatIntelConfigOut:
    config = _get_or_create_config(session)
    if payload.enabled is not None:
        config.enabled = payload.enabled
    if payload.check_interval_hours is not None:
        config.check_interval_hours = payload.check_interval_hours
    session.commit()
    session.refresh(config)
    return _to_config_out(config)


@router.post("/check-now", response_model=list[ThreatIntelSnapshotOut])
def run_check_now(
    session: Annotated[Session, Depends(get_session)],
) -> list[ThreatIntelSnapshot]:
    """Fetch every allowlisted source right now, regardless of the configured interval.

    Runs inline rather than as a background Job: two bounded HTTPS GETs against static pages,
    worst case ~15s each on a timeout, not the kind of work that needs progress reporting or
    cancellation. Available whether or not the toggle is enabled - a manual check is an explicit
    user action, distinct from the periodic background check the toggle governs.
    """
    config = _get_or_create_config(session)
    created = check_now(session, config)
    session.commit()
    for snapshot in created:
        session.refresh(snapshot)
    return created


@router.get("/snapshots", response_model=list[ThreatIntelSnapshotOut])
def list_snapshots(
    session: Annotated[Session, Depends(get_session)],
    source_id: str | None = None,
    limit: int = 50,
) -> list[ThreatIntelSnapshot]:
    stmt = (
        select(ThreatIntelSnapshot)
        .order_by(ThreatIntelSnapshot.fetched_at.desc())
        .limit(min(limit, 200))
    )
    if source_id is not None:
        stmt = stmt.where(ThreatIntelSnapshot.source_id == source_id)
    return list(session.scalars(stmt).all())


@router.post("/snapshots/{snapshot_id}/review", response_model=ThreatIntelSnapshotOut)
def review_snapshot(
    snapshot_id: UUID,
    payload: ThreatIntelReviewRequest,
    session: Annotated[Session, Depends(get_session)],
) -> ThreatIntelSnapshot:
    snapshot = session.get(ThreatIntelSnapshot, snapshot_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    snapshot.reviewed = True
    snapshot.reviewed_at = utcnow()
    if payload.note is not None:
        snapshot.reviewer_note = payload.note
    session.commit()
    session.refresh(snapshot)
    return snapshot
