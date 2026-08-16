from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from qubit_core import asset_to_row
from qubit_core.db import AssetRow, ProjectRow, ScanRow
from qubit_core.schemas import utcnow
from sqlalchemy import asc, desc, func, select
from sqlalchemy.orm import Session

from ..deps import get_session
from ..schemas import AssetBatchRequest, AssetBatchResponse, CryptoAssetOut, Page
from ..services import (
    apply_asset_filters,
    next_scan_sequence,
    require_asset,
    require_scan,
    slugify,
    to_asset_out,
)

router = APIRouter(tags=["assets"])

_SORT_FIELDS = {
    "risk_score": AssetRow.risk_score,
    "algorithm": AssetRow.algorithm,
    "discovered_at": AssetRow.discovered_at,
    "source_scanner": AssetRow.source_scanner,
}


@router.get("/scans/{scan_id}/assets", response_model=Page[CryptoAssetOut])
def list_scan_assets(
    scan_id: UUID,
    session: Annotated[Session, Depends(get_session)],
    algorithm: str | None = None,
    source_scanner: str | None = None,
    asset_type: str | None = None,
    usage_context: str | None = None,
    sensitivity: str | None = None,
    vulnerable: bool | None = None,
    min_risk: float | None = None,
    max_risk: float | None = None,
    q: str | None = None,
    sort: Annotated[str, Query()] = "risk_score:desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[CryptoAssetOut]:
    require_scan(session, scan_id)
    stmt = select(AssetRow).where(AssetRow.scan_id == scan_id)
    stmt = apply_asset_filters(
        stmt,
        algorithm=algorithm,
        source_scanner=source_scanner,
        asset_type=asset_type,
        usage_context=usage_context,
        sensitivity=sensitivity,
        vulnerable=vulnerable,
        min_risk=min_risk,
        max_risk=max_risk,
        q=q,
    )
    order_field, _, direction = sort.partition(":")
    field = _SORT_FIELDS.get(order_field, AssetRow.risk_score)
    stmt = stmt.order_by(desc(field) if direction != "asc" else asc(field))
    total_stmt = select(func.count()).select_from(stmt.subquery())
    total = int(session.scalar(total_stmt) or 0)
    rows = session.scalars(stmt.limit(limit).offset(offset)).all()
    return Page[CryptoAssetOut](
        items=[to_asset_out(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/assets/{asset_id}", response_model=CryptoAssetOut)
def get_asset(
    asset_id: UUID,
    session: Annotated[Session, Depends(get_session)],
) -> CryptoAssetOut:
    row = require_asset(session, asset_id)
    return to_asset_out(row)


@router.post(
    "/assets/batch",
    response_model=AssetBatchResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["assets"],
)
def ingest_asset_batch(
    payload: AssetBatchRequest,
    session: Annotated[Session, Depends(get_session)],
) -> AssetBatchResponse:
    """Ingest externally-discovered assets (the hybrid bridge's TLS probe) into the inventory.

    `qubit bridge probe --push` and `qubit demo run --all` have always POSTed here, but the endpoint
    did not exist — so the push returned 404 and the demo reported "Assets not pushed (API
    unreachable)" on every run. The bridge probe is a real discovery source (it is what proves a
    deployment negotiated X25519MLKEM768), and its findings belong in the same inventory and CBOM as
    everything else rather than being printed to a terminal and discarded.

    An `AssetRow` requires a scan and a project, so a batch creates a `succeeded` scan under the
    named project (created on first use) and attaches the assets to it. That keeps bridge findings
    diffable and CBOM-exportable through exactly the same endpoints a filesystem scan uses.
    """
    project = session.scalar(select(ProjectRow).where(ProjectRow.slug == slugify(payload.project)))
    if project is None:
        project = ProjectRow(name=payload.project, slug=slugify(payload.project))
        session.add(project)
        session.flush()

    scan = ScanRow(
        project_id=project.id,
        seq=next_scan_sequence(session, project.id),
        label=payload.label or "bridge probe",
        status="succeeded",
        targets=payload.targets or [],
        # `network` is the frozen SourceScanner value these assets already carry; naming it here
        # keeps the scan row honest about where its contents came from.
        scanners=["network"],
        stats={"assets": len(payload.assets)},
        started_at=utcnow(),
        finished_at=utcnow(),
    )
    session.add(scan)
    session.flush()

    for asset in payload.assets:
        session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
    session.commit()

    return AssetBatchResponse(project_id=project.id, scan_id=scan.id, ingested=len(payload.assets))
