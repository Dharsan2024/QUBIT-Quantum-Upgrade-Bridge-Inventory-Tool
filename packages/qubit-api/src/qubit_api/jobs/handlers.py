from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import UUID

from qubit_core import asset_to_row
from qubit_core.db import AssetRow, ProjectRow, ScanRow
from qubit_risk.pipeline import RiskPipeline
from qubit_scanner import SCANNER_NAMES, scan_paths

from ..services import is_git_url
from .runner import ProgressReporter

logger = logging.getLogger(__name__)


def _clone_git_target(url: str) -> Path:
    """Shallow-clone a remote repo to a temp dir and return the checkout path.

    Mirrors the CLI's `qubit run` git support so the dashboard/API can scan a repo URL too.
    """
    dest = Path(tempfile.mkdtemp(prefix="qubit-apiclone-")) / "repo"
    proc = subprocess.run(  # noqa: S603
        ["git", "clone", "--depth", "1", url, str(dest)],  # noqa: S607
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode != 0:
        raise ValueError(f"git clone failed for {url}: {proc.stderr.strip() or 'clone error'}")
    return dest


def _scan_progress_callback(reporter: ProgressReporter) -> Callable[[str, int, int], None]:
    def cb(stage: str, current: int, total: int) -> None:
        progress = current / max(total, 1)
        reporter.update(progress, stage, f"Processing {stage} ({current}/{total})")

    return cb


def scan_handler(payload: dict[str, Any], reporter: ProgressReporter) -> dict[str, Any]:
    """Filesystem, network or Vault scan — dispatched on `mode`.

    All three share the `scan` job kind deliberately. They produce the same thing (CryptoAssets
    against a ScanRow) and need the same machinery: progress events, cancellation, concurrency
    slots, and the crash recovery that marks an interrupted scan failed instead of leaving it
    "running" forever. Adding new job kinds would have meant duplicating all of that, and
    forgetting one entry in the runner's semaphore map is a silent hang.
    """
    mode = payload.get("mode", "paths")
    if mode == "network":
        return _network_scan_impl(payload, reporter)
    if mode == "vault":
        return _vault_scan_impl(payload, reporter)

    project_id = UUID(payload["project_id"])
    scan_id = UUID(payload["scan_id"])
    targets = payload.get("targets", [])
    # This line used to fetch the requested scanners and discard the value outright, so the async
    # path ignored the caller's selection exactly as the synchronous one did.
    scanners = set(payload.get("scanners") or SCANNER_NAMES)
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
        clone_dirs: list[Path] = []  # temp git clones to remove after the scan
        for raw in targets:
            if is_git_url(raw):
                reporter.update(0.05, "cloning", f"Cloning {raw}")
                clone = _clone_git_target(raw)
                clone_dirs.append(clone.parent)
                resolved_targets.append(clone)
                continue
            path = Path(raw).expanduser().resolve()
            if not path.exists():
                raise ValueError(f"Scan target does not exist: {raw}")
            if roots and not any(path.is_relative_to(root) for root in roots):
                raise ValueError(f"Scan target outside project root: {raw}")
            resolved_targets.append(path)

    # `scan_paths` runs synchronously here; the job runner is what makes the API asynchronous, by
    # executing this handler off the request path.
    #
    # There used to be an `except TypeError` fallback around this call, guarding against a
    # `scan_paths` that did not accept `progress`. It does accept it (and has for some time), so the
    # fallback was unreachable for its stated purpose while remaining reachable for a genuine
    # TypeError raised *inside* the scan — which it would have swallowed, silently re-running the
    # whole scan without progress reporting and hiding the real bug.
    try:
        result = scan_paths(
            resolved_targets,
            repo=project.slug,
            scanners=scanners,
            progress=_scan_progress_callback(reporter),
        )
    finally:
        for d in clone_dirs:  # always clean up temp git clones, even on scan failure
            shutil.rmtree(d, ignore_errors=True)

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

        # Update scan stats (status flips to succeeded only after the chained risk run,
        # so "succeeded" always means the assets are fully annotated)
        scan.stats = result.stats.model_dump(mode="json")
        session.commit()

    # Chain risk run if requested. A risk failure doesn't invalidate the scan itself.
    if run_risk:
        reporter.update(0.9, "risk", "Chaining risk assessment")
        try:
            _run_risk_impl(scan_id, {}, reporter)
        except Exception:
            logger.exception("Chained risk run failed for scan %s", scan_id)

    with reporter.sf() as session:
        scan = session.get(ScanRow, scan_id)
        if scan:
            scan.status = "succeeded"
            session.commit()

    reporter.update(1.0, "done", f"Completed. Found {len(result.assets)} assets.")
    return {"scan_id": str(scan_id), "assets": len(result.assets)}


def _persist_scan_result(
    result: Any,
    *,
    scan_id: UUID,
    project_id: UUID,
    reporter: ProgressReporter,
    run_risk: bool,
) -> int:
    """Write a ScanResult's assets + stats, optionally chain risk, and flip the scan to succeeded.

    Factored out of `scan_handler` so the network and Vault paths persist through exactly the same
    code. Duplicating it was the alternative, and a second copy that forgot to flip `status` would
    leave a finished scan looking like it was still running.
    """
    with reporter.sf() as session:
        scan = session.get(ScanRow, scan_id)
        if not scan:
            raise ValueError("Scan deleted during run")
        chunk: list[AssetRow] = []
        for asset in result.assets:
            chunk.append(asset_to_row(asset, scan_id=scan_id, project_id=project_id))
            if len(chunk) >= 500:
                session.add_all(chunk)
                session.commit()
                reporter.checkpoint()
                chunk.clear()
        if chunk:
            session.add_all(chunk)
            session.commit()
        scan.stats = result.stats.model_dump(mode="json")
        session.commit()

    if run_risk:
        reporter.update(0.9, "risk", "Chaining risk assessment")
        try:
            _run_risk_impl(scan_id, {}, reporter)
        except Exception:
            logger.exception("Chained risk run failed for scan %s", scan_id)

    with reporter.sf() as session:
        scan = session.get(ScanRow, scan_id)
        if scan:
            scan.status = "succeeded"
            session.commit()
    return len(result.assets)


def _network_scan_impl(payload: dict[str, Any], reporter: ProgressReporter) -> dict[str, Any]:
    """Live TLS/SSH enumeration plus the raw-ClientHello PQC-group probe.

    `scan_network` is async and this handler is sync — which is correct, not a workaround: the job
    runner executes handlers via `anyio.to_thread.run_sync`, so this body owns a fresh worker thread
    with no running event loop, and `asyncio.run` is the right way to drive the coroutine.

    Authorization is enforced inside `scan_network` (`verify_scan_authorization`), not here:
    loopback and RFC1918 targets are always permitted, anything public additionally requires an
    allowlist entry AND the explicit authorized flag. Re-implementing that check at this layer would
    risk the two disagreeing, so this passes the caller's intent through and lets the one
    implementation decide.
    """
    import asyncio

    from qubit_scanner import scan_network
    from qubit_scanner.network.auth import ScanAuthorizationError

    project_id = UUID(payload["project_id"])
    scan_id = UUID(payload["scan_id"])
    targets = [str(t) for t in payload.get("targets", [])]
    ports = [int(p) for p in (payload.get("ports") or [443])]
    probe_pqc = bool(payload.get("probe_pqc", True))
    authorized = bool(payload.get("authorized", False))

    if not targets:
        raise ValueError("a network scan needs at least one host")

    reporter.update(
        0.1,
        "network",
        f"Probing {len(targets)} host(s) on {len(ports)} port(s)"
        + (" including hybrid PQC groups" if probe_pqc else ""),
    )
    try:
        result = asyncio.run(
            scan_network(targets, ports=ports, probe_pqc=probe_pqc, authorized=authorized)
        )
    except ScanAuthorizationError as exc:
        # Surface the refusal verbatim. It already explains which of the two conditions failed, and
        # a scan that quietly returned zero findings for an unauthorized target would be far worse.
        raise ValueError(str(exc)) from exc

    reporter.checkpoint()
    count = _persist_scan_result(
        result,
        scan_id=scan_id,
        project_id=project_id,
        reporter=reporter,
        run_risk=bool(payload.get("run_risk", True)),
    )
    reporter.update(1.0, "done", f"Completed. Found {count} assets across {len(targets)} host(s).")
    return {"scan_id": str(scan_id), "assets": count}


def _vault_scan_impl(payload: dict[str, Any], reporter: ProgressReporter) -> dict[str, Any]:
    """HashiCorp Vault transit-key and PKI-certificate enumeration.

    The token is NOT in the job payload. `Job.payload` is a persisted JSON column, so a token there
    would be written to the database, returned by `GET /jobs/{id}`, and kept in every backup — an
    indefensible outcome for a tool that exists to find stray credentials. It travels through the
    process-local single-use store in `jobs/secrets.py` instead; that module documents what the
    choice costs (no resume across restarts, single-process only).
    """
    import asyncio

    from qubit_scanner import scan_vault

    from . import secrets as job_secrets

    project_id = UUID(payload["project_id"])
    scan_id = UUID(payload["scan_id"])
    addr = str(payload.get("addr") or "").strip()
    # Popped from the process-local store, never read from the payload — see jobs/secrets.py.
    token = job_secrets.take(reporter.job_id) or ""
    if not addr:
        raise ValueError("a Vault scan needs the server address (e.g. http://127.0.0.1:8200)")
    if not token:
        raise ValueError("a Vault scan needs a token with read access to the transit/pki mounts")

    from qubit_scanner.vault.connector import VaultUnreachable, verify_vault_reachable

    async def _run() -> Any:
        # Preflight first. `scan_vault` resolves an unreachable server to an empty result, which is
        # right for a background sweep but wrong here: a user typed this address and is waiting, and
        # "succeeded, 0 assets" for a typo or an expired token reads as "Vault is clean".
        await verify_vault_reachable(addr, token)
        return await scan_vault(
            addr,
            token,
            mount_transit=str(payload.get("mount_transit") or "transit"),
            mount_pki=str(payload.get("mount_pki") or "pki"),
        )

    reporter.update(0.1, "vault", f"Contacting {addr}")
    try:
        result = asyncio.run(_run())
    except VaultUnreachable as exc:
        raise ValueError(str(exc)) from exc
    reporter.checkpoint()
    count = _persist_scan_result(
        result,
        scan_id=scan_id,
        project_id=project_id,
        reporter=reporter,
        run_risk=bool(payload.get("run_risk", True)),
    )
    reporter.update(1.0, "done", f"Completed. Found {count} Vault-managed assets.")
    return {"scan_id": str(scan_id), "assets": count}


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
        rid = risk_run.id
        risk_row = session.get(RiskRun, rid)  # distinct name: `row` above is AssetRow-typed
        if risk_row:
            risk_row.timeline = timeline_data
            risk_row.percentiles = percentiles
            risk_row.summary = summary
            risk_row.status = "succeeded"
            from qubit_core.schemas import utcnow

            risk_row.finished_at = utcnow()
        session.commit()

    return {"risk_run_id": str(rid), "assets_annotated": len(annotated_assets)}


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
