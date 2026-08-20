from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import HTTPException, status
from qubit_core import asset_to_row, row_to_asset
from qubit_core.cbom import export_cbom
from qubit_core.db import AssetRow, ProjectRow, ScanRow
from qubit_core.schemas import utcnow
from qubit_scanner import scan_paths
from sqlalchemy import Integer, Select, String, case, cast, func, select
from sqlalchemy.orm import Session

from .schemas import CryptoAssetOut, TrendPoint

logger = logging.getLogger(__name__)


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


def autobuild_migration_plan(session: Session, scan_id: UUID) -> UUID | None:
    """Build the migration plan for a scan that has just finished, and return its id.

    Called at the end of every successful risk-annotated scan. Before this, a plan only existed if
    someone pressed "Build plan", and the plan that button produced was global — so the ordinary
    path of "scan a project, open the Migration Hub" showed either nothing or a queue assembled
    from some unrelated project's assets. Building it here is what makes a project's migration
    appear as a consequence of scanning it.

    Scoped to the *scan*, not the project: nothing dedupes assets across scans, so a project-wide
    plan over a directory scanned three times would carry three copies of every task. One scan is
    one coherent snapshot. A project-wide plan is still reachable on request.

    Returns None when there is nothing to plan (no vulnerable assets), and swallows failures — a
    scan that found real assets must not be reported as failed because planning tripped over.
    """
    from qubit_migrate.orchestrator import MigrationOrchestrator

    scan = session.get(ScanRow, scan_id)
    if scan is None:
        return None
    vulnerable = session.scalar(
        select(func.count())
        .select_from(AssetRow)
        .where(
            AssetRow.scan_id == scan_id,
            AssetRow.qv_vulnerable.is_(True),
            AssetRow.risk_score.is_not(None),
        )
    )
    if not vulnerable:
        return None
    try:
        plan = MigrationOrchestrator(session).build_plan(
            project_id=scan.project_id, scan_id=scan_id
        )
    except Exception:
        logger.exception("Auto-building a migration plan failed for scan %s", scan_id)
        session.rollback()
        return None
    return plan.id


def annotate_scan_risk(session: Session, scan_id: UUID) -> int:
    """Run the qubit-risk pipeline over a scan's assets and persist the annotations.

    Returns the number of assets annotated. Mirrors ``qubit risk assess``.
    """
    from qubit_risk import RiskPipeline, load_config

    rows = session.scalars(select(AssetRow).where(AssetRow.scan_id == scan_id)).all()
    if not rows:
        return 0
    annotated = RiskPipeline(load_config()).assess([row_to_asset(r) for r in rows])
    by_id = {r.id: r for r in rows}
    count = 0
    for asset in annotated:
        row = by_id.get(asset.id)
        if row and asset.risk:
            row.risk_score = asset.risk.score
            row.risk_ci_low = asset.risk.ci_low
            row.risk_ci_high = asset.risk.ci_high
            row.mosca_margin_years = asset.risk.mosca_margin_years
            row.priority_rank = asset.risk.priority_rank
            count += 1
    session.commit()
    return count


def is_git_url(s: str) -> bool:
    """True if the target is a remote git repo URL rather than a local path."""
    s = s.strip()
    return s.startswith(("http://", "https://", "git@", "ssh://", "git://")) or s.endswith(".git")


def validate_targets(
    project: ProjectRow, targets: list[str], scan_roots: list[Path] | None = None
) -> list[Path]:
    """Router pre-check. Git URLs pass through (cloned later in the scan handler); local paths must
    exist, stay inside the project root when one is set, AND stay inside the server's configured
    scan roots when those are set.

    The two confinements are independent and both apply. A project's `root_path` is a per-project
    narrowing chosen by whoever created the project; `scan_roots` is an operator-level boundary from
    `QUBIT_SCAN_ROOTS` that a project cannot widen. Without the latter, a scan target was any path
    the server process could read — fine for the desktop app, wrong for anything shared.
    """
    roots: list[Path] = []
    if project.root_path:
        roots.append(Path(project.root_path).resolve())

    allowlist = scan_roots or []

    resolved_targets: list[Path] = []
    for raw in targets:
        if is_git_url(raw):
            resolved_targets.append(Path(raw))  # placeholder; handler clones it
            continue
        path = Path(raw).expanduser().resolve()
        if not path.exists():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"scan target does not exist: {raw}",
            )
        if allowlist and not any(path.is_relative_to(root) for root in allowlist):
            # Deliberately does not echo the configured roots: a refusal should not double as a
            # directory-disclosure oracle for an unauthenticated-adjacent caller.
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"scan target is outside the paths this server is permitted to scan: {raw}. "
                    "Ask the operator to add it to QUBIT_SCAN_ROOTS."
                ),
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
    run_risk: bool = True,
    scan_roots: list[Path] | None = None,
) -> tuple[ScanRow, UUID | None]:
    """Create a scan row and execute it; return the row and the background job id, if one was used.

    The job id is returned so the route can hand a client the handle to poll. Previously this
    returned the row alone and the response advertised `job: null` unconditionally, leaving an
    asynchronous API with no way to tell a caller what was running.
    """
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

    # Synchronous validation so bad targets return early, before a ScanRow exists.
    #
    # `scan_roots` is passed IN rather than read from a fresh `Settings()`. Constructing one here
    # reads the process environment and silently ignores the instance `create_app(settings)` was
    # given, so a configured allowlist had no effect — the same trap deps.get_settings() documents
    # for the auth token. The route supplies it from app.state.settings.
    resolved_targets = validate_targets(project, targets, scan_roots)

    job_id: UUID | None = None
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
                "run_risk": run_risk,
                # Carried into the job so the handler re-checks rather than trusting the route.
                "scan_roots": [str(r) for r in (scan_roots or [])],
            },
        )
        session.add(job)
        session.commit()
        session.refresh(job)
        job_id = job.id
        job_runner.submit(job.id)
    else:
        try:
            # The requested scanner set was recorded on the scan row and then NOT passed here, so
            # the API's scanner selection was stored and silently ignored — every API scan ran the
            # default set regardless of what the caller asked for.
            result = scan_paths(resolved_targets, repo=project.slug, scanners=set(scanners))
            rows = [
                asset_to_row(asset, scan_id=scan.id, project_id=project.id)
                for asset in result.assets
            ]
            if rows:
                session.add_all(rows)
            scan.status = "succeeded"
            scan.stats = result.stats.model_dump(mode="json")
            scan.error = None
            if rows and run_risk:
                session.commit()  # rows must be visible before the pipeline reads them
                annotate_scan_risk(session, scan.id)
                session.commit()  # ...and annotated before the planner reads them
                autobuild_migration_plan(session, scan.id)
        except Exception as exc:
            scan.status = "failed"
            scan.error = str(exc)
            scan.stats = {}
        scan.finished_at = utcnow()
        session.add(scan)
        session.commit()
        session.refresh(scan)
    return scan, job_id


def _median_risk_by_scan(session: Session, scan_ids: list[UUID]) -> dict[UUID, float | None]:
    """Median risk score per scan, computed entirely in SQL.

    There is no portable median AGGREGATE (SQLite has none; `percentile_cont` is Postgres-only), but
    there is a portable median IDIOM: rank each row within its scan with `ROW_NUMBER()`, count the
    rows in the same partition with `COUNT(*) OVER`, keep only the middle one or two, and average
    them. Window functions are available in SQLite 3.25+ (and every supported Postgres), which is
    the same floor the rest of this schema already assumes.

    This replaces streaming every `(scan_id, risk_score)` pair back to Python — 20,000 rows to
    produce 10 numbers, and the last remaining O(assets) transfer in the trends endpoint. The result
    set is now one row per scan.

    `AVG` of the two central values reproduces `statistics.median` exactly for an even count, and
    the `(count + 1) / 2` / `(count + 2) / 2` integer-division pair collapses to the single middle
    rank for an odd count — so the value is identical to the previous implementation rather than
    merely close.
    """
    if not scan_ids:
        return {}

    ranked = (
        select(
            AssetRow.scan_id.label("scan_id"),
            AssetRow.risk_score.label("risk_score"),
            func.row_number()
            .over(partition_by=AssetRow.scan_id, order_by=AssetRow.risk_score.asc())
            .label("rank"),
            func.count().over(partition_by=AssetRow.scan_id).label("total"),
        )
        .where(AssetRow.scan_id.in_(scan_ids), AssetRow.risk_score.is_not(None))
        .subquery()
    )
    # The middle ranks must be INTEGERS. Without the casts, SQLAlchemy renders `/` as float
    # division, so for an even count of 4 the predicate became `rank IN (2.5, 3.0)`, matched rank 3
    # alone, and returned that single value (0.3) instead of the average of ranks 2 and 3 (0.25).
    # Truncating the division reproduces `statistics.median`: both middle ranks for an even count,
    # and the same rank twice — which `IN` collapses — for an odd one.
    lower_rank = cast((ranked.c.total + 1) / 2, Integer)
    upper_rank = cast((ranked.c.total + 2) / 2, Integer)
    middle = (
        select(ranked.c.scan_id, func.avg(ranked.c.risk_score).label("median_risk"))
        .where(ranked.c.rank.in_((lower_rank, upper_rank)))
        .group_by(ranked.c.scan_id)
    )
    return {scan_id: median_risk for scan_id, median_risk in session.execute(middle).all()}


def scan_trends(session: Session, project_id: UUID) -> list[TrendPoint]:
    """Per-scan totals for a project's trend chart.

    Counting is done by the DATABASE. This used to `select(AssetRow)` for every scan in the project
    and hydrate each row into a full ORM object — including its two JSON columns (`location`,
    `evidence`) — purely to compute four aggregates. On a 10-scan project with 20,000 assets that
    was 20,000 objects built and ~40,000 JSON documents parsed to produce 10 numbers, and it
    measured **470 ms**. The JSON deserialization dominates, so the fix is not an index (scan_id is
    already indexed) but never fetching those columns at all.

    Median has no portable SQL aggregate — SQLite has none and `percentile_cont` is Postgres-only —
    so it stays in Python, but over a two-column projection instead of whole rows.
    """
    scans = session.scalars(
        select(ScanRow).where(ScanRow.project_id == project_id).order_by(ScanRow.seq.asc())
    ).all()
    scan_ids = [s.id for s in scans]
    if not scan_ids:
        return []

    # One grouped query for the three pure counts.
    counts = {
        row.scan_id: row
        for row in session.execute(
            select(
                AssetRow.scan_id,
                func.count().label("total"),
                func.sum(case((AssetRow.qv_vulnerable, 1), else_=0)).label("vulnerable"),
                func.sum(
                    case((func.coalesce(AssetRow.mosca_margin_years, 0.0) < 0.0, 1), else_=0)
                ).label("negative_mosca"),
            )
            .where(AssetRow.scan_id.in_(scan_ids))
            .group_by(AssetRow.scan_id)
        ).all()
    }

    medians = _median_risk_by_scan(session, scan_ids)

    out: list[TrendPoint] = []
    for scan in scans:
        agg = counts.get(scan.id)
        out.append(
            TrendPoint(
                scan_id=scan.id,
                seq=scan.seq,
                finished_at=scan.finished_at,
                total=int(agg.total) if agg else 0,
                vulnerable=int(agg.vulnerable or 0) if agg else 0,
                median_risk=medians.get(scan.id),
                negative_mosca=int(agg.negative_mosca or 0) if agg else 0,
            )
        )
    return out


def scan_diff(session: Session, scan_id: UUID, against_scan_id: UUID) -> dict[str, object]:
    # Only `fingerprint` and `risk_score` are used, so only those are selected. Fetching whole ORM
    # rows meant building two full objects per asset — JSON `location`/`evidence` parsed for each —
    # to compare two strings and two floats.
    def _scores(target: UUID) -> dict[str, float | None]:
        return {
            fingerprint: risk_score
            for fingerprint, risk_score in session.execute(
                select(AssetRow.fingerprint, AssetRow.risk_score).where(AssetRow.scan_id == target)
            ).all()
        }

    by_fp_a = _scores(scan_id)
    by_fp_b = _scores(against_scan_id)
    set_a = set(by_fp_a)
    set_b = set(by_fp_b)
    persisting = sorted(set_a & set_b)
    risk_deltas: list[dict[str, object]] = []
    for fp in persisting:
        cur = by_fp_a[fp]
        prev = by_fp_b[fp]
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
    """Aggregates for one scan, computed in SQL rather than by hydrating every row.

    Same change as `scan_trends`: this fetched all of a scan's assets as ORM objects (JSON columns
    included) to build two histograms, a sorted score list and a top-10. The histograms are a
    GROUP BY, the top-10 is ORDER BY … LIMIT 10, and the score list is one indexed column — so
    none of it needs a full row. The `(scan_id, algorithm)` composite index already exists and now
    gets used for the grouping.
    """
    total = int(
        session.scalar(
            select(func.count()).select_from(AssetRow).where(AssetRow.scan_id == scan_id)
        )
        or 0
    )

    by_algorithm: dict[str, dict[str, int]] = {
        algorithm: {"count": int(count), "vulnerable": int(vulnerable or 0)}
        for algorithm, count, vulnerable in session.execute(
            select(
                AssetRow.algorithm,
                func.count(),
                func.sum(case((AssetRow.qv_vulnerable, 1), else_=0)),
            )
            .where(AssetRow.scan_id == scan_id)
            .group_by(AssetRow.algorithm)
        ).all()
    }

    by_usage: dict[str, int] = {
        usage: int(count)
        for usage, count in session.execute(
            select(AssetRow.usage_context, func.count())
            .where(AssetRow.scan_id == scan_id)
            .group_by(AssetRow.usage_context)
        ).all()
    }

    # Ordered by the database (the risk_score index makes this a scan of the index, not the table).
    risk_scores = list(
        session.scalars(
            select(AssetRow.risk_score)
            .where(AssetRow.scan_id == scan_id, AssetRow.risk_score.is_not(None))
            .order_by(AssetRow.risk_score.asc())
        ).all()
    )

    # `coalesce(..., 0.0)` reproduces the previous Python `r.risk_score or 0.0` ordering exactly:
    # a NULL score sorts as zero rather than being placed by the backend's NULL ordering rules.
    top_10 = [
        {"asset_id": str(asset_id), "algorithm": algorithm, "risk_score": risk_score}
        for asset_id, algorithm, risk_score in session.execute(
            select(AssetRow.id, AssetRow.algorithm, AssetRow.risk_score)
            .where(AssetRow.scan_id == scan_id)
            .order_by(func.coalesce(AssetRow.risk_score, 0.0).desc())
            .limit(10)
        ).all()
    ]

    return {
        "total_assets": total,
        "by_algorithm": by_algorithm,
        "by_usage_context": by_usage,
        "risk_scores": risk_scores,
        "top_10_risk": top_10,
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


# ── Reporting + compliance exports ───────────────────────────────────────────────────────────────
# These three capabilities existed only behind the CLI (`qubit report`) or, for CNSA 2.0, only as a
# Python function with no caller at all. The dashboard's "Save as PDF" was `window.print()` — a
# browser screenshot of the page, not the paginated report `qubit_core.report.pdf` builds. Wiring
# them here is what makes them reachable from the app.


def _scan_assets(session: Session, scan_id: UUID) -> list[Any]:
    """Every asset of a scan, as domain objects. Shared by the CBOM and the report exporters."""
    rows = session.scalars(select(AssetRow).where(AssetRow.scan_id == scan_id)).all()
    return [row_to_asset(row) for row in rows]


def scan_cnsa2(session: Session, scan_id: UUID, *, as_of: object = None) -> dict[str, Any]:
    """Evaluate a scan's inventory against the NSA CNSA 2.0 migration milestones (2025 → 2035).

    Returns a JSON-ready dict rather than the dataclass so the router needs no response model
    duplication. `evaluate_cnsa2` answers only the milestone question — "is the required algorithm
    class present at all" — never the stricter "is everything compliant"; conflating the two is the
    documented bug in the reference implementation this was ported from, so the distinction is kept.
    """
    from datetime import date

    from qubit_risk import load_config
    from qubit_risk.cnsa2 import evaluate_cnsa2

    assets = _scan_assets(session, scan_id)
    report = evaluate_cnsa2(assets, load_config(), as_of=as_of if isinstance(as_of, date) else None)
    return {
        "as_of": report.as_of.isoformat(),
        "overall_score": report.overall_score,
        "current_phase": report.current_phase,
        "next_deadline": report.next_deadline.isoformat() if report.next_deadline else None,
        "days_to_next_deadline": report.days_to_next_deadline,
        "next_action": report.next_action,
        "assets_evaluated": len(assets),
        "milestones": [
            {
                "name": m.name,
                "deadline": m.deadline.isoformat(),
                "is_due": m.is_due,
                "status": m.status,
                "weight": m.weight,
                "score_contribution": m.score_contribution,
                "evidence": m.evidence,
            }
            for m in report.milestones
        ],
    }


def scan_sarif(session: Session, scan_id: UUID, *, include_safe: bool = False) -> dict[str, Any]:
    """SARIF 2.1.0 log for a scan, for upload to code-scanning tooling."""
    from qubit_core import __version__ as core_version
    from qubit_core.report import export_sarif

    return export_sarif(
        _scan_assets(session, scan_id),
        tool_version=core_version,
        include_safe=include_safe,
    )


def scan_pdf(session: Session, scan_id: UUID) -> bytes:
    """Render the paginated PDF report for a scan and return its bytes.

    `build_pdf_report` writes to a path (reportlab's document model is file-oriented), so this goes
    through a temporary file rather than changing that signature for one caller. A report is not a
    hot path, and keeping qubit-core's API stable is worth more than avoiding one temp file.
    """
    import tempfile

    from qubit_core import __version__ as core_version
    from qubit_core.report import build_pdf_report

    scan = require_scan(session, scan_id)
    assets = _scan_assets(session, scan_id)
    if not assets:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="this scan found no cryptographic assets, so there is nothing to report",
        )
    target = ", ".join(scan.targets or []) or "(unknown target)"
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "qubit-report.pdf"
        try:
            build_pdf_report(assets, out, target=target, tool_version=core_version)
        except RuntimeError as exc:
            # reportlab is an optional extra. Say how to fix it instead of returning a 500.
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
            ) from exc
        return out.read_bytes()


# ── Network + Vault scans ────────────────────────────────────────────────────────────────────────
# Both scanners existed and were tested, but were reachable only from the CLI — `scan_network` said
# so in its own docstring ("not yet wired into qubit-api's job runner either; both are CLI-only for
# now"). They are two of the six input sources the architecture claims, so the app was showing four.
# Both reuse the `scan` job kind, so they inherit progress events, cancellation and crash recovery.


def _new_scan_row(
    session: Session,
    project: ProjectRow,
    *,
    targets: list[str],
    scanners: list[str],
    label: str | None,
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
    return scan


def run_network_scan(
    session: Session,
    project: ProjectRow,
    *,
    targets: list[str],
    ports: list[int] | None = None,
    probe_pqc: bool = True,
    authorized: bool = False,
    label: str | None = None,
    job_runner: Any = None,
    run_risk: bool = True,
) -> tuple[ScanRow, UUID | None]:
    """Queue a live TLS/SSH enumeration + hybrid-PQC group probe against `targets`.

    Authorization is deliberately NOT pre-checked here. `scan_network` calls
    `verify_scan_authorization` per target/port, which permits loopback and RFC1918 unconditionally
    and requires an allowlist entry plus `authorized` for anything public — and it writes an audit
    log entry for every attempt, allowed or refused. A second check at this layer could drift out of
    step with that one, and the audit trail would miss the refusals it never saw.
    """
    ports = ports or [443]
    if not targets:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="a network scan needs at least one host",
        )
    scan = _new_scan_row(
        session, project, targets=targets, scanners=["network"], label=label or "network scan"
    )
    if job_runner is None:
        # No runner (test client without lifespan, or a sync caller): run it inline so the endpoint
        # is still honest about the outcome rather than reporting a scan that never happened.
        import asyncio

        from qubit_scanner import scan_network as _scan_network

        try:
            result = asyncio.run(
                _scan_network(targets, ports=ports, probe_pqc=probe_pqc, authorized=authorized)
            )
        except Exception as exc:
            _fail_scan(session, scan, str(exc))
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        _store_assets_inline(session, scan, project, result)
        return scan, None

    from qubit_core.db import Job

    job = Job(
        kind="scan",
        project_id=project.id,
        ref_id=scan.id,
        payload={
            "mode": "network",
            "project_id": str(project.id),
            "scan_id": str(scan.id),
            "targets": targets,
            "ports": ports,
            "probe_pqc": probe_pqc,
            "authorized": authorized,
            "run_risk": run_risk,
        },
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    job_runner.submit(job.id)
    return scan, job.id


def run_vault_scan(
    session: Session,
    project: ProjectRow,
    *,
    addr: str,
    token: str,
    mount_transit: str = "transit",
    mount_pki: str = "pki",
    label: str | None = None,
    job_runner: Any = None,
    run_risk: bool = True,
) -> tuple[ScanRow, UUID | None]:
    """Queue a HashiCorp Vault transit/PKI enumeration.

    The token is handed to the job through the process-local single-use store in `jobs/secrets.py`
    and never written to `Job.payload`, because that column is persisted and would put a live
    credential in the database and in `GET /jobs/{id}`.
    """
    addr = (addr or "").strip()
    if not addr:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="a Vault scan needs the server address (e.g. http://127.0.0.1:8200)",
        )
    if not token:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="a Vault scan needs a token with read access to the transit/pki mounts",
        )
    # The address is recorded as the scan target; the token is not, and must never become one.
    scan = _new_scan_row(
        session, project, targets=[addr], scanners=["key"], label=label or "vault scan"
    )

    if job_runner is None:
        import asyncio

        from qubit_scanner import scan_vault as _scan_vault

        try:
            result = asyncio.run(
                _scan_vault(addr, token, mount_transit=mount_transit, mount_pki=mount_pki)
            )
        except Exception as exc:
            _fail_scan(session, scan, str(exc))
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        _store_assets_inline(session, scan, project, result)
        return scan, None

    from qubit_core.db import Job

    from .jobs import secrets as job_secrets

    job = Job(
        kind="scan",
        project_id=project.id,
        ref_id=scan.id,
        payload={
            "mode": "vault",
            "project_id": str(project.id),
            "scan_id": str(scan.id),
            "addr": addr,
            "mount_transit": mount_transit,
            "mount_pki": mount_pki,
            "run_risk": run_risk,
            # No "token" key, by design.
        },
    )
    session.add(job)
    session.commit()
    session.refresh(job)
    job_secrets.put(job.id, token)
    try:
        job_runner.submit(job.id)
    except Exception:
        job_secrets.discard(job.id)  # never leave a secret behind for a job that will not run
        raise
    return scan, job.id


def _fail_scan(session: Session, scan: ScanRow, error: str) -> None:
    scan.status = "failed"
    scan.error = error
    scan.finished_at = utcnow()
    session.commit()


def _store_assets_inline(session: Session, scan: ScanRow, project: ProjectRow, result: Any) -> None:
    """Persist a synchronously-produced ScanResult and mark the scan succeeded."""
    for asset in result.assets:
        session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
    scan.stats = result.stats.model_dump(mode="json")
    scan.status = "succeeded"
    scan.finished_at = utcnow()
    session.commit()
    session.refresh(scan)
