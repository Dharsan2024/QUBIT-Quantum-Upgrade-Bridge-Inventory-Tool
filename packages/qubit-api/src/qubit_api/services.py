from __future__ import annotations

import re
from pathlib import Path
from statistics import median
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from qubit_core import asset_to_row, row_to_asset
from qubit_core.cbom import export_cbom
from qubit_core.db import AssetRow, ProjectRow, ScanRow
from qubit_core.schemas import utcnow
from qubit_scanner import scan_paths
from sqlalchemy import Select, String, func, select
from sqlalchemy.orm import Session

from .schemas import CryptoAssetOut, TrendPoint


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug or "project"


def require_project(session: Session, project_id: UUID) -> ProjectRow:
    project = session.get(ProjectRow, project_id)
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="project not found")
    return project


def require_scan(session: Session, scan_id: UUID) -> ScanRow:
    scan = session.get(ScanRow, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return scan


def require_asset(session: Session, asset_id: UUID) -> AssetRow:
    asset = session.get(AssetRow, asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset not found")
    return asset


def to_asset_out(row: AssetRow) -> CryptoAssetOut:
    asset = row_to_asset(row)
    payload = asset.model_dump(mode="python")
    payload["project_id"] = row.project_id
    payload["fingerprint"] = row.fingerprint
    return CryptoAssetOut.model_validate(payload)


def next_scan_sequence(session: Session, project_id: UUID) -> int:
    max_seq = session.scalar(select(func.max(ScanRow.seq)).where(ScanRow.project_id == project_id))
    return 1 if max_seq is None else int(max_seq) + 1


def validate_targets(project: ProjectRow, targets: list[str]) -> list[Path]:
    roots: list[Path] = []
    if project.root_path:
        roots.append(Path(project.root_path).resolve())

    resolved_targets: list[Path] = []
    for raw in targets:
        path = Path(raw).expanduser().resolve()
        if not path.exists():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"scan target does not exist: {raw}",
            )
        if roots and not any(path.is_relative_to(root) for root in roots):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"scan target outside project root: {raw}",
            )
        resolved_targets.append(path)
    return resolved_targets


def run_scan(
    session: Session,
    project: ProjectRow,
    targets: list[str],
    scanners: list[str],
    label: str | None,
    job_runner: Any = None,
) -> ScanRow:
    scan = ScanRow(
        project_id=project.id,
        seq=next_scan_sequence(session, project.id),
        label=label,
        status="running",
        targets=targets,
        scanners=scanners,
        stats={},
        started_at=utcnow(),
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    # Synchronous validation so bad targets return early
    resolved_targets = validate_targets(project, targets)

    if job_runner:
        from qubit_core.db import Job

        job = Job(
            kind="scan",
            project_id=project.id,
            ref_id=scan.id,
            payload={
                "project_id": str(project.id),
                "scan_id": str(scan.id),
                "targets": targets,
                "scanners": scanners,
                "run_risk": True,
            },
        )
        session.add(job)
        session.commit()
        session.refresh(job)
        job_runner.submit(job.id)
    else:
        try:
            result = scan_paths(resolved_targets, repo=project.slug)
            rows = [
                asset_to_row(asset, scan_id=scan.id, project_id=project.id)
                for asset in result.assets
            ]
            if rows:
                session.add_all(rows)
            scan.status = "succeeded"
            scan.stats = result.stats.model_dump(mode="json")
            scan.error = None
        except Exception as exc:
            scan.status = "failed"
            scan.error = str(exc)
            scan.stats = {}
        scan.finished_at = utcnow()
        session.add(scan)
        session.commit()
        session.refresh(scan)
    return scan


def scan_trends(session: Session, project_id: UUID) -> list[TrendPoint]:
    scans = session.scalars(
        select(ScanRow).where(ScanRow.project_id == project_id).order_by(ScanRow.seq.asc())
    ).all()
    out: list[TrendPoint] = []
    for scan in scans:
        rows = session.scalars(select(AssetRow).where(AssetRow.scan_id == scan.id)).all()
        risk_scores = [r.risk_score for r in rows if r.risk_score is not None]
        out.append(
            TrendPoint(
                scan_id=scan.id,
                seq=scan.seq,
                finished_at=scan.finished_at,
                total=len(rows),
                vulnerable=sum(1 for r in rows if r.qv_vulnerable),
                median_risk=median(risk_scores) if risk_scores else None,
                negative_mosca=sum(1 for r in rows if (r.mosca_margin_years or 0.0) < 0.0),
            )
        )
    return out


def scan_diff(session: Session, scan_id: UUID, against_scan_id: UUID) -> dict[str, object]:
    a_rows = session.scalars(select(AssetRow).where(AssetRow.scan_id == scan_id)).all()
    b_rows = session.scalars(select(AssetRow).where(AssetRow.scan_id == against_scan_id)).all()
    by_fp_a = {row.fingerprint: row for row in a_rows}
    by_fp_b = {row.fingerprint: row for row in b_rows}
    set_a = set(by_fp_a)
    set_b = set(by_fp_b)
    persisting = sorted(set_a & set_b)
    risk_deltas: list[dict[str, object]] = []
    for fp in persisting:
        cur = by_fp_a[fp].risk_score
        prev = by_fp_b[fp].risk_score
        if cur is None or prev is None or cur == prev:
            continue
        risk_deltas.append({"fingerprint": fp, "from": prev, "to": cur, "delta": cur - prev})
    return {
        "added": sorted(set_a - set_b),
        "removed": sorted(set_b - set_a),
        "persisting": persisting,
        "risk_deltas": sorted(
            risk_deltas,
            key=lambda item: abs(float(str(item["delta"]))),
            reverse=True,
        ),
    }


def scan_summary(session: Session, scan_id: UUID) -> dict[str, object]:
    rows = session.scalars(select(AssetRow).where(AssetRow.scan_id == scan_id)).all()
    by_algorithm: dict[str, dict[str, int]] = {}
    by_usage: dict[str, int] = {}
    for row in rows:
        algo = by_algorithm.setdefault(row.algorithm, {"count": 0, "vulnerable": 0})
        algo["count"] += 1
        if row.qv_vulnerable:
            algo["vulnerable"] += 1
        by_usage[row.usage_context] = by_usage.get(row.usage_context, 0) + 1
    risk_scores = sorted([r.risk_score for r in rows if r.risk_score is not None])
    return {
        "total_assets": len(rows),
        "by_algorithm": by_algorithm,
        "by_usage_context": by_usage,
        "risk_scores": risk_scores,
        "top_10_risk": [
            {"asset_id": str(r.id), "algorithm": r.algorithm, "risk_score": r.risk_score}
            for r in sorted(rows, key=lambda item: item.risk_score or 0.0, reverse=True)[:10]
        ],
    }


def export_scan_cbom(session: Session, scan_id: UUID) -> dict[str, object]:
    rows = session.scalars(select(AssetRow).where(AssetRow.scan_id == scan_id)).all()
    assets = [row_to_asset(row) for row in rows]
    return export_cbom(assets)


def apply_asset_filters(stmt: Select, **filters: object) -> Select:
    if algorithm := filters.get("algorithm"):
        stmt = stmt.where(AssetRow.algorithm == algorithm)
    if source_scanner := filters.get("source_scanner"):
        stmt = stmt.where(AssetRow.source_scanner == source_scanner)
    if asset_type := filters.get("asset_type"):
        stmt = stmt.where(AssetRow.asset_type == asset_type)
    if usage_context := filters.get("usage_context"):
        stmt = stmt.where(AssetRow.usage_context == usage_context)
    if sensitivity := filters.get("sensitivity"):
        stmt = stmt.where(AssetRow.sensitivity == sensitivity)
    vulnerable = filters.get("vulnerable")
    if vulnerable is not None:
        stmt = stmt.where(AssetRow.qv_vulnerable.is_(bool(vulnerable)))
    min_risk = filters.get("min_risk")
    if min_risk is not None:
        stmt = stmt.where(AssetRow.risk_score >= float(str(min_risk)))
    max_risk = filters.get("max_risk")
    if max_risk is not None:
        stmt = stmt.where(AssetRow.risk_score <= float(str(max_risk)))
    if q := filters.get("q"):
        query = f"%{q!s}%"
        stmt = stmt.where(
            AssetRow.algorithm.ilike(query)
            | func.cast(AssetRow.location, String).ilike(query)
            | func.cast(AssetRow.evidence, String).ilike(query)
        )
    return stmt
