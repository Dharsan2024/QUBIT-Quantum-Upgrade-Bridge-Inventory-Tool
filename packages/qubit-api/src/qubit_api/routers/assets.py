from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from qubit_core.db import AssetRow
from sqlalchemy import asc, desc, func, select
from sqlalchemy.orm import Session

from ..deps import get_session
from ..schemas import CryptoAssetOut, Page
from ..services import apply_asset_filters, require_asset, require_scan, to_asset_out

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
