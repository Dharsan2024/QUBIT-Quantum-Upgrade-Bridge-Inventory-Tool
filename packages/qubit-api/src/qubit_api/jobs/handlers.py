from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID

from qubit_core import asset_to_row
from qubit_core.db import AssetRow, ProjectRow, ScanRow
from qubit_risk.pipeline import RiskPipeline
from qubit_scanner import scan_paths

from .runner import ProgressReporter

logger = logging.getLogger(__name__)


def _scan_progress_callback(reporter: ProgressReporter) -> Callable[[str, int, int], None]:
    def cb(stage: str, current: int, total: int) -> None:
        progress = current / max(total, 1)
        reporter.update(progress, stage, f"Processing {stage} ({current}/{total})")

    return cb


def scan_handler(payload: dict[str, Any], reporter: ProgressReporter) -> dict[str, Any]:
    project_id = UUID(payload["project_id"])
    scan_id = UUID(payload["scan_id"])
    targets = payload.get("targets", [])
    payload.get("scanners", ["code", "config"])
    run_risk = payload.get("run_risk", True)

    with reporter.sf() as session:
        project = session.get(ProjectRow, project_id)
        scan = session.get(ScanRow, scan_id)
        if not project or not scan:
            raise ValueError("Project or scan not found")

        # Validate targets again (defensive)
        roots: list[Path] = []
        if project.root_path:
            roots.append(Path(project.root_path).resolve())

        resolved_targets: list[Path] = []
        for raw in targets:
            path = Path(raw).expanduser().resolve()
            if not path.exists():
                raise ValueError(f"Scan target does not exist: {raw}")
            if roots and not any(path.is_relative_to(root) for root in roots):
                raise ValueError(f"Scan target outside project root: {raw}")
            resolved_targets.append(path)

    # Note: For M1, we run the scan_paths synchronously (in a thread)
    # The scan_paths doesn't currently accept a callback, so we simulate it or pass it.
    # The design says `progress=reporter.on_scan_progress`, we'll pass it if supported,
    # but currently qubit_scanner might not have it. Let's pass it anyway as `progress`.
    try:
        result = scan_paths(
            resolved_targets, repo=project.slug, progress=_scan_progress_callback(reporter)
        )
    except TypeError:
        # Fallback if qubit_scanner.scan_paths doesn't accept 'progress'
        reporter.update(0.1, "scanning", "Starting scan (progress callback unsupported)")
        result = scan_paths(resolved_targets, repo=project.slug)

    reporter.checkpoint()

    with reporter.sf() as session:
        scan = session.get(ScanRow, scan_id)
        if not scan:
            raise ValueError("Scan deleted during run")

        # In chunks of 500
        chunk: list[AssetRow] = []
        for asset in result.assets:
            chunk.append(asset_to_row(asset, scan_id=scan.id, project_id=project_id))
            if len(chunk) >= 500:
                session.add_all(chunk)
                session.commit()
                reporter.checkpoint()
                chunk.clear()
        if chunk:
            session.add_all(chunk)
            session.commit()

        # Update scan stats
        scan.stats = result.stats.model_dump(mode="json")
        scan.status = "succeeded"
        session.commit()

    # Chain risk run if requested
    if run_risk:
        reporter.update(0.9, "risk", "Chaining risk assessment")
        _run_risk_impl(scan_id, {}, reporter)

    reporter.update(1.0, "done", f"Completed. Found {len(result.assets)} assets.")
    return {"scan_id": str(scan_id), "assets": len(result.assets)}


def risk_handler(payload: dict[str, Any], reporter: ProgressReporter) -> dict[str, Any]:
    scan_id = UUID(payload["scan_id"])
    params = payload.get("params", {})
    return _run_risk_impl(scan_id, params, reporter)


def _run_risk_impl(
    scan_id: UUID, params: dict[str, Any], reporter: ProgressReporter
) -> dict[str, Any]:
    with reporter.sf() as session:
        from qubit_core import row_to_asset
        from qubit_core.db import AssetRow, RiskRun

        # Check if we already have a risk run
        risk_run = session.query(RiskRun).filter(RiskRun.scan_id == scan_id).first()
        if not risk_run:
            risk_run = RiskRun(scan_id=scan_id, status="running", params=params)
            session.add(risk_run)
            session.commit()
            session.refresh(risk_run)

        rows = session.query(AssetRow).filter(AssetRow.scan_id == scan_id).all()
        assets = [row_to_asset(r) for r in rows]

    pipeline = RiskPipeline()  # we could pass custom params here
    reporter.update(0.5, "risk", "Assessing risk via RiskPipeline")
    annotated_assets = pipeline.assess(assets)
    reporter.checkpoint()

    # Update DB
    with reporter.sf() as session:
        for a in annotated_assets:
            if not a.risk:
                continue
            # update AssetRow risk annotations
            row = session.query(AssetRow).filter(AssetRow.id == a.id).first()
            if row:
                row.risk_score = a.risk.score
                row.risk_ci_low = a.risk.ci_low
                row.risk_ci_high = a.risk.ci_high
                row.mosca_margin_years = a.risk.mosca_margin_years
                row.priority_rank = a.risk.priority_rank
                row.priority_rank = a.risk.priority_rank

        # Generate summary
        summary = _generate_risk_summary(annotated_assets)

        # Pull timeline from simulator
        # M1 pipeline uses CRQCTimelineSimulator internally, but we need the curve
        # from it to store in RiskRun.timeline. The pipeline.sim holds the latest
        # simulator used, but timeline is per-algorithm. For the project dashboard,
        # usually RSA-2048 is the proxy. Let's just pull RSA-2048.
        timeline_data = None
        percentiles = None
        curve = pipeline.sim.simulate("RSA-2048")
        if curve:
            timeline_data = [
                {"year": pipeline._now + i, "cdf": curve.cdf[i]} for i in range(len(curve.cdf))
            ]
            percentiles = {"p05": curve.p05_year, "p50": curve.median_year, "p95": curve.p95_year}
        risk_run = session.get(RiskRun, risk_run.id)
        if risk_run:
            risk_run.timeline = timeline_data
            risk_run.percentiles = percentiles
            risk_run.summary = summary
            risk_run.status = "succeeded"
            from qubit_core.schemas import utcnow

            risk_run.finished_at = utcnow()
        session.commit()

    return {"risk_run_id": str(risk_run.id), "assets_annotated": len(annotated_assets)}


def _generate_risk_summary(assets) -> dict[str, Any]:
    total_assets = len(assets)
    vulnerable_assets = [a for a in assets if a.quantum_vulnerable.vulnerable]
    scores = [a.risk.score for a in assets if a.risk and a.risk.score is not None]
    negative_mosca = [
        a
        for a in assets
        if a.risk and a.risk.mosca_margin_years is not None and a.risk.mosca_margin_years < 0
    ]

    import statistics

    median_risk = statistics.median(scores) if scores else 0.0

    return {
        "total_assets": total_assets,
        "vulnerable_count": len(vulnerable_assets),
        "median_risk": median_risk,
        "negative_mosca_count": len(negative_mosca),
    }


HANDLERS = {
    "scan": scan_handler,
    "risk": risk_handler,
}
