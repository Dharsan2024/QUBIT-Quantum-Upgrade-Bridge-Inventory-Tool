from __future__ import annotations

import concurrent.futures as cf
import contextlib
import logging
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast
from uuid import UUID

from qubit_core import asset_to_row
from qubit_core.db import AssetRow, ProjectRow, ScanRow
from qubit_core.schemas import utcnow
from qubit_risk.pipeline import RiskPipeline
from qubit_scanner import SCANNER_NAMES, scan_paths
from sqlalchemy import func, select

from ..services import autobuild_migration_plan, is_git_url, workspace_root
from .runner import JobCancelled, ProgressReporter

logger = logging.getLogger(__name__)

#: The generators `generate_patch` accepts. Narrowed from the job payload, which is JSON and so
#: arrives as a plain string — an unrecognised value is refused rather than passed through.
GeneratorName = Literal["auto", "llm", "template"]
GENERATORS: frozenset[str] = frozenset(("auto", "llm", "template"))

if TYPE_CHECKING:  # imported lazily at runtime, to keep this module free of a cycle
    from qubit_migrate.orchestrator import MigrationOrchestrator
    from sqlalchemy.orm import Session


def _clone_into_workspace(url: str, slug: str) -> Path:
    """Shallow-clone a remote repo into the PERSISTENT workspace and return the checkout path.

    Mirrors the CLI's `qubit run` git support so the dashboard/API can scan a repo URL too — and
    keeps the result, which the temp-directory version this replaced did not. A scan records a
    `file_path` per asset; if the tree those paths point into is deleted when the scan ends, the
    migration that follows has nothing to patch.

    Re-cloning is skipped when the checkout is already there, so scanning the same project twice
    does not re-download it, and a second scan sees the migrations the first one applied.

    Shallow (`--depth 1`) on purpose: a depth-1 clone still has a HEAD, which is all QUBIT asks of
    the repository — `applies` runs `git apply --check` against the index, and the tests baseline is
    materialised with `git archive HEAD`. Full history costs minutes on a large repository and buys
    neither stage anything.
    """
    dest = workspace_root() / (slug or "repo")
    if (dest / ".git").is_dir():
        logger.info("reusing the existing checkout at %s", dest)
        return dest
    if dest.exists():
        # Something is there that is not a checkout. Refusing beats cloning over it.
        raise ValueError(
            f"{dest} exists and is not a git checkout; remove it or rename the project"
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(  # noqa: S603
        # `--` before the URL: a target beginning with `-` would otherwise be read as a git option
        # (`--upload-pack=...` is argument injection), and a scan target is user input.
        ["git", "clone", "--depth", "1", "--", url, str(dest)],  # noqa: S607
        capture_output=True,
        text=True,
        # `encoding` explicitly: `text=True` alone decodes with the LOCALE codec, which is
        # cp1252 on Windows. A commit message, branch or path carrying any non-Latin-1
        # byte then raises inside the reader THREAD, where the traceback surfaces detached
        # from the call that caused it. Observed exactly that while scanning a corpus.
        encoding="utf-8",
        errors="replace",
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
        # The checkout a URL target was cloned into, if any. NOT a temp directory: see the clone
        # call below for why keeping it is the difference between a scan and a migration.
        cloned_checkout: Path | None = None
        # Re-enforce the operator's scan-root allowlist here rather than trusting that the route
        # already did. The job runs off the request path and its payload is persisted, so a handler
        # that assumed the check had happened would be one edited row away from scanning anything.
        allowed_roots = [Path(r).resolve() for r in (payload.get("scan_roots") or [])]
        for raw in targets:
            if is_git_url(raw):
                reporter.update(0.05, "cloning", f"Cloning {raw}")
                # Cloned into the PERSISTENT workspace, and deliberately not deleted afterwards.
                #
                # This used to clone into a temp directory and `shutil.rmtree` it in a `finally` as
                # soon as the scan finished. The scan itself was fine -- but every asset it
                # recorded carried a `file_path` inside that deleted directory, so the migration
                # that follows had nothing to patch and no repository to derive a root from. The
                # inventory half of "paste a GitHub URL" worked and the migrate half could not,
                # which is the whole workflow for a repository that is not on this machine.
                clone = _clone_into_workspace(raw, project.slug)
                cloned_checkout = clone
                resolved_targets.append(clone)
                continue
            path = Path(raw).expanduser().resolve()
            if not path.exists():
                raise ValueError(f"Scan target does not exist: {raw}")
            if allowed_roots and not any(path.is_relative_to(root) for root in allowed_roots):
                raise ValueError(f"Scan target is outside the paths this server may scan: {raw}")
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
    # No cleanup step: the clone IS the tree the assets point into and the tree the migration will
    # patch. `workspace_root()` keeps it somewhere the user can find and delete.
    result = scan_paths(
        resolved_targets,
        repo=project.slug,
        scanners=scanners,
        progress=_scan_progress_callback(reporter),
    )

    # Point the project at the checkout, so `_plan_repo_root` can find it.
    #
    # Without this the migration has no repository root even though the files are on disk:
    # `_plan_repo_root` reads the project's `root_path` (through the scan when the plan carries no
    # project of its own), and a project created by pasting a URL into the Scans box never had one
    # set. `applies` then reports "no git repo to check against", the tests baseline cannot be
    # materialised, and no patch can be written back.
    if cloned_checkout is not None:
        with reporter.sf() as session:
            project_row = session.get(ProjectRow, project_id)
            if project_row is not None and not project_row.root_path:
                project_row.root_path = str(cloned_checkout)
                session.commit()
                logger.info(
                    "project %s root_path set to the clone at %s", project_id, cloned_checkout
                )

    reporter.checkpoint()

    with reporter.sf() as session:
        scan = session.get(ScanRow, scan_id)
        if not scan:
            raise ValueError("Scan deleted during run")

        # In chunks of 500
        chunk: list[AssetRow] = []
        for asset in result.assets:
            chunk.append(
                asset_to_row(
                    asset, scan_id=scan.id, project_id=project_id, tenant_id=scan.tenant_id
                )
            )
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
        _chain_migration_plan(scan_id, reporter)

    with reporter.sf() as session:
        scan = session.get(ScanRow, scan_id)
        if scan:
            scan.status = "succeeded"
            # A scan row is the user-facing lifecycle record; the job row's terminal timestamp
            # is not a substitute for it.  The synchronous path records this, but these async
            # handlers used to leave successful scans at `finished_at = NULL`, so completed runs
            # rendered with no completion time and trends could not place them reliably.
            scan.finished_at = utcnow()
            session.commit()

    reporter.update(1.0, "done", f"Completed. Found {len(result.assets)} assets.")
    return {"scan_id": str(scan_id), "assets": len(result.assets)}


def _chain_migration_plan(scan_id: UUID, reporter: ProgressReporter) -> None:
    """Build this scan's migration plan, so the project has one the moment the scan lands.

    Runs after risk because the planner only considers risk-scored assets; running it before would
    silently produce an empty plan. Failures are logged, never raised — the scan's assets are real
    whether or not a plan could be assembled from them.
    """
    reporter.update(0.95, "plan", "Building migration plan")
    try:
        with reporter.sf() as session:
            autobuild_migration_plan(session, scan_id)
    except Exception:
        logger.exception("Auto-building a migration plan failed for scan %s", scan_id)


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
            chunk.append(
                asset_to_row(
                    asset, scan_id=scan_id, project_id=project_id, tenant_id=scan.tenant_id
                )
            )
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
        _chain_migration_plan(scan_id, reporter)

    with reporter.sf() as session:
        scan = session.get(ScanRow, scan_id)
        if scan:
            scan.status = "succeeded"
            # Keep the shared network/Vault completion path consistent with filesystem scans.
            # `Job.finished_at` measures the worker; `ScanRow.finished_at` is the timestamp every
            # scan API and dashboard view exposes.
            scan.finished_at = utcnow()
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


def _plan_repo_root(session, plan) -> Path | None:
    """Where this plan's code actually lives, so a patch can be written back to it.

    A task's `file_path` is absolute, but `git apply` needs a root to resolve the diff's relative
    headers against, and `generate_patch` only writes relative headers when it is GIVEN one. The
    project's `root_path` is the declared answer; a scan's first target is the observed one, and is
    what the dashboard's scans actually set, so it is the fallback rather than the other way round.
    """
    scan = session.get(ScanRow, plan.scan_id) if plan.scan_id else None

    # A plan reaches its project either directly or THROUGH the scan it was built from, and the
    # second spelling is the one the dashboard produces: "Build plan" posts a `scan_id` and no
    # `project_id`, so `plan.project_id` is null and this used to fall straight through to the scan
    # target. That target is whatever directory was scanned -- routinely a subtree like `src/main`
    # or `lib` -- and using it as the repository root silently costs two rungs of the evidence
    # ladder: `applies` reports "no git repo to check against" and `tests` reports "no test suite
    # detected in repo", both of them true of the subtree and false of the project.
    #
    # Measured through the desktop app on the Ruby twin: every applied patch came back
    # `evidence_level: -1` with `applies` and `tests` skipped, against a repository that has both a
    # git history and a suite. `MigrationOrchestrator._project_root_of` already makes this hop; it
    # was only this function that did not.
    project_id = plan.project_id or (scan.project_id if scan else None)
    project = session.get(ProjectRow, project_id) if project_id else None
    if project and project.root_path and Path(project.root_path).is_dir():
        return Path(project.root_path)
    for target in (scan.targets if scan else []) or []:
        candidate = Path(str(target))
        if candidate.is_dir():
            return candidate
    return None


class _GateRejected(Exception):
    """A patch was generated and a validation stage turned it down.

    Its own type because it is the one outcome that used to be indistinguishable from a crash: the
    check was `raise ValueError("the validation gate rejected this patch")`, caught two lines later
    by the same `except Exception` that catches a dead transport, a poisoned Session and a model
    that gave up. Those are opposite results. A rejection means every part of QUBIT worked -- a
    patch exists, the gate read it and said no -- and a `tests` stage catching a bad rewrite is the
    single most valuable thing the tool does. Measured on medivault-emr: 7 of the 18 findings
    reported as failed were rejections, 5 of them by `tests`.

    Carries the stage that objected so the failure list says WHICH gate, not just that one did.
    """

    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(f"the {stage} gate rejected this patch: {detail}" if detail else stage)
        self.stage = stage
        self.detail = detail


def _rejecting_stage(patch: Any) -> tuple[str, str]:
    """Which validation stage failed, from the patch's own stored report.

    Read back out of `validation_json` rather than passed down, because the orchestrator has
    already committed the patch by the time the caller sees `status != "proposed"` -- the record is
    the only thing in hand, and it is also exactly what the operator sees in the UI, so the two
    cannot disagree about which gate said no.
    """
    stages = (patch.validation_json or {}).get("stages") or {}
    for name, stage in stages.items():
        if isinstance(stage, dict) and stage.get("status") == "fail":
            return str(name), str(stage.get("detail") or "")[:300]
    return "validation", ""


@dataclass
class _Tally:
    """What a bulk run produced, accumulated across workers.

    Six mutually exclusive outcomes, and they are not interchangeable. In order of how good the
    news is:

    * `generated` -- a patch exists and passed the gate. Finished work.
    * `refused` -- QUBIT decided no edit is correct here, and that decision is the product. Covers
      an algorithm a remote party owns (a Gravatar URL keyed by MD5, a webhook `sha1=` field, an
      established KDF) and `AlreadySatisfied`, where an earlier patch already made the file right.
    * `needs_guidance` -- no patch was available, so a written procedure was produced instead: no
      rule matches, the target primitive is not installable here, the file will not fit the model.
    * `rejected` -- a patch WAS produced and a validation stage turned it down. The gate working.
    * `failed` -- nothing usable was produced at all: the model exhausted its attempts, the
      transport died, something crashed. The only bucket that means QUBIT fell short.

    `covered`, `applied` and `from_cache` are sub-counts of the bucket above them (`covered` of
    `refused`, the other two of `generated`), kept under their original names because the dashboard
    reads them; they are NOT summed with the buckets.

    The split is the whole point. A medivault-emr run reported "0 ready, 5 guided, 18 failed" for
    24 findings whose real breakdown was 6 refused on ownership grounds, 1 already satisfied, 7
    rejected by a gate (5 by `tests`, 2 by `symbols`), 2 genuinely failed and 1 applied. Collapsing
    a correct refusal, a gate doing its job and a model giving up into one word is how a tool that
    was mostly right reported itself as mostly broken.
    """

    generated: int = 0
    applied: int = 0
    covered: int = 0
    from_cache: int = 0
    needs_guidance: int = 0
    refused: int = 0
    rejected: int = 0
    failed: int = 0
    failures: list[dict[str, str]] = field(default_factory=list)
    done: int = 0

    def merge(self, other: _Tally) -> None:
        self.generated += other.generated
        self.applied += other.applied
        self.covered += other.covered
        self.from_cache += other.from_cache
        self.needs_guidance += other.needs_guidance
        self.refused += other.refused
        self.rejected += other.rejected
        self.failed += other.failed
        self.failures.extend(other.failures)
        self.done += other.done


def _prepare_one(
    session: Session,
    orch: MigrationOrchestrator,
    task: Any,
    *,
    generator: GeneratorName,
    repo_root: Path | None,
    should_apply: bool,
) -> _Tally:
    """Prepare one finding, and never raise.

    A bulk run's contract is that one bad finding does not end it, so every outcome is turned into
    a count here rather than an exception the caller has to sort out. Split out of the loop so it
    can be called from several workers at once without the counting logic existing twice.
    """
    from qubit_migrate.orchestrator import (
        RESOLUTION_SATISFIED,
        AlreadySatisfied,
        GuidedRemediation,
    )

    tally = _Tally(done=1)

    # A finding with no rule is not written off here.
    #
    # This used to short-circuit straight to guidance: no rule in the YAML pack, therefore no patch
    # to attempt. `generate_patch` now derives one from QUBIT's own knowledge base for the families
    # that HAVE a post-quantum answer, and declines for the ones that do not -- raising
    # `GuidedRemediation`, which is counted below exactly as this branch used to count it. Deciding
    # it here meant the synthesiser was never consulted on the findings it was built for.
    def park_for_retry(exc: Exception) -> None:
        """Leave a finding that produced no usable patch somewhere a later run can pick it up.

        Shared by the rejected and failed branches because both owe the same follow-up: the plan is
        written, but the finding is NOT claimed as resolved, so a better engine on a later run has
        to be able to try again.
        """
        try:
            orch.resolve_guided(task.id, force=True, claim_resolved=False)
        except Exception as resolve_exc:
            # This used to be `contextlib.suppress(Exception)`. `resolve_guided` already retries
            # transient SQLite lock contention on its own write (`retry_write_on_lock`), so a
            # SECOND exception here is not the ordinary case that guard exists for -- and silently
            # swallowing it left the task in whatever state `generate_patch` set before it failed
            # (often `generating`), with no resolution and no error recorded anywhere.
            #
            # The job still returns `tally` normally, so the outer worker sees a clean "done=1,
            # failed=1" and the run completes with a status of "succeeded" — the task is orphaned
            # in a non-terminal state and nothing about the job's own report says so. Measured:
            # a paymesh-gateway run finished at progress 1.0 with two tasks still sitting in
            # `generating`/`ready`, silently dropped from a migration the UI reported as done.
            #
            # Logged rather than re-raised: raising here would turn a resolution-bookkeeping
            # failure into a whole worker dying, which is a worse outcome for the other tasks still
            # queued behind it. The next `POST .../run` on this plan recovers a task left in
            # `generating`/`verifying` back onto the retry queue (see the interrupted-run recovery
            # at the top of `migrate_handler`), so the finding is not lost — only delayed, and now
            # visibly so instead of invisibly so.
            logger.error(
                "task %s: generation failed (%s) AND resolve_guided also failed (%s) -- "
                "this task is left in a non-terminal state; the next run on this plan will "
                "recover it",
                task.id,
                exc,
                resolve_exc,
            )

    def record(exc: Exception, bucket: str) -> None:
        tally.failures.append(
            {
                "task_id": str(task.id),
                "rule_id": task.rule_id or "",
                # Which of the three unhappy outcomes this was. Kept in the same list under the
                # same key so the abandoned-task sweep at the end of `_prepare_in_parallel` (which
                # de-duplicates against `failures`) still sees every finding that was accounted
                # for, and so a consumer reading `failures` for its detail strings is unaffected.
                "bucket": bucket,
                "detail": f"{type(exc).__name__}: {exc}".replace(chr(10), " ")[:300],
            }
        )

    try:
        patch = orch.generate_patch(task.id, generator=generator, repo_root=repo_root)
        if patch.status != "proposed":
            # NOT a generic ValueError. Raised as its own type so the `except Exception` below --
            # which exists for dead transports and poisoned Sessions -- stops counting a gate that
            # correctly caught a bad patch as QUBIT failing to produce one.
            raise _GateRejected(*_rejecting_stage(patch))
        tally.generated += 1
        if patch.model_name and patch.model_name.startswith("cache:"):
            # Answered from the learned-patch store (transform/learn.py) rather than by a fresh
            # model call -- an identical finding was already fixed and validated earlier.
            tally.from_cache += 1
        # Approval is withheld on a generate-only run. Approving a patch nobody has read, and then
        # not writing it, would strip the queue of the Approve/Reject buttons that are the entire
        # point of generating ahead of applying.
        if should_apply:
            orch.review_patch(patch.id, approve=True, note="bulk migration", actor="api")
            if repo_root is not None:
                orch.apply_patch(patch.id, repo_root=repo_root, actor="api")
                tally.applied += 1
    except GuidedRemediation as verdict:
        # A verdict, not an error, on both branches -- but two different verdicts, and reporting
        # them as one is what this split exists to stop.
        #
        # `refusal` means a patch was available and writing it would have been WRONG: the algorithm
        # is fixed by a party outside this repository. `refused` is therefore a success column;
        # eleven patches on `pyload` passed every gate while breaking authentication against three
        # services, and this check is what stops that. Everything else here means no patch was on
        # offer at all, so a written procedure is the output -- which is what `guided` has always
        # meant, and stays meaning.
        #
        # Both branches MUST leave the task's own row parked (state -> `deferred`, a resolution,
        # `advice_text` written) before returning. `GuidedRemediation`'s docstring says the guidance
        # is "already persisted... by the time this is raised" -- true of `generate_patch`'s real
        # callers, but the raise is the only contract this handler can rely on, and a task this
        # branch leaves at `ready` is a task the post-pool abandoned-task sweep below will find,
        # since it queries fresh from the database rather than from this in-memory tally. Measured
        # via `test_parallel_preparation.py`: without this, every refused/guided finding in a bulk
        # run was independently RE-counted as `failed` by that sweep, on top of being counted
        # correctly here -- both numbers in the same response, and the wrong one was the one
        # `result["failed"]` reported.
        #
        # GUARDED on `task.resolution is None`, not called unconditionally. `generate_patch`'s real
        # raise sites do NOT all mean the same thing despite sharing `refusal=False`: "no rule
        # matches" and "the rule says guided" are permanently resolved (`claim_resolved=True`), but
        # a size/routing DETOUR is explicitly retryable (`claim_resolved=False`) -- the comment at
        # its own raise site names both load-bearing retry queries that depend on that distinction
        # surviving. Calling `resolve_guided(..., claim_resolved=True)` unconditionally here
        # overwrote that nuance the instant a detour was hit, silently making every detoured
        # finding permanently unretryable again -- the same class of bug `park_for_retry` exists to
        # prevent, reintroduced one layer up. `task.resolution` already reflects whatever
        # `generate_patch` persisted, in the SAME session, before it raised -- `None` here means
        # nothing did (the shape every bulk-run test that mocks `generate_patch` directly produces,
        # since the mock skips the real method's own persistence entirely), which is exactly when
        # this handler owes the task a resolution of its own.
        if verdict.refusal:
            tally.refused += 1
            # UNCONDITIONAL, unlike the branch below. Every real raise site for `refusal=True`
            # already persists SOME resolution before raising (via the generic `resolve_guided`,
            # which predates `resolve_refused` and is still what those sites call) -- but never
            # the ownership-specific wording `resolve_refused` writes, so calling it again is
            # always a correction, never a loss of nuance the way it would be below.
            orch.resolve_refused(task.id, verdict.guidance)
        else:
            tally.needs_guidance += 1
            # GUARDED, unlike the branch above. Here the real raise sites disagree on purpose: "no
            # rule matches" and "the rule says guided" are permanent (`claim_resolved=True`), but a
            # size/routing DETOUR is explicitly retryable (`claim_resolved=False` -- see that raise
            # site's own comment naming the two retry queries this keeps working). Calling
            # `resolve_guided(..., claim_resolved=True)` unconditionally overwrote the detour
            # case's nuance the instant one was hit. `task.resolution` already reflects whatever
            # `generate_patch` persisted, in the SAME session, before it raised; `None` means
            # nothing did, which is the shape a bulk-run test that mocks `generate_patch` directly
            # produces (the mock skips the real method's own persistence entirely) -- exactly when
            # this handler owes the task a resolution of its own.
            if task.resolution is None:
                orch.resolve_guided(task.id, force=True, claim_resolved=True)
    except AlreadySatisfied as satisfied:
        # The outcome the rule exists to reach is already true -- an earlier patch rewrote the
        # whole file, or the dependency pin already meets the PQC floor. Finished work, not a
        # failure. Matched on the EXCEPTION TYPE, never on words in the message: the string test
        # this replaced recognised two of the four satisfied paths and counted 19 findings of
        # finished work as failures.
        #
        # Counted in `refused` too, and for the same reason the contract branch above is: QUBIT
        # looked at this finding and concluded that no edit is the right answer. `covered` is the
        # narrower sub-count and keeps its exact previous meaning, because the dashboard reads it.
        tally.refused += 1
        tally.covered += 1
        session.rollback()
        # Parked with the SAME resolution `test_task_resolution.py` already pins for this exact
        # exception outside the bulk path -- see the note on the `GuidedRemediation` branch above
        # for why an unparked task here is not merely incomplete bookkeeping.
        orch._fail_task(
            task, str(satisfied) or "already remediated", resolution=RESOLUTION_SATISFIED
        )
    except _GateRejected as rejection:
        # The gate did its job. A patch exists, a stage read it and said no -- `tests` catching a
        # rewrite that breaks the suite is the strongest evidence this tool produces, and counting
        # it as a failure of the tool inverts what it means.
        tally.rejected += 1
        record(rejection, "rejected")
        session.rollback()
        # Parked exactly as a failure is: a rejected patch leaves the finding unresolved, and it is
        # retried on the next run against whatever the engine pool has learned since.
        park_for_retry(rejection)
    except Exception as exc:  # one bad finding must not end the run
        tally.failed += 1
        record(exc, "failed")
        session.rollback()
        # A failed generation is still a finding that needs handling. Without this the queue row
        # carried a rejection reason and nothing else -- the same dead end as "manual change",
        # reached by a different route.
        park_for_retry(exc)
    return tally


def _file_groups(session: Session, tasks: list[Any]) -> list[list[Any]]:
    """Tasks grouped by the file they edit, each group in rank order.

    The group, not the task, is the unit of parallel work, and that is a correctness requirement
    rather than a tidying choice. Two findings in one file must be prepared in sequence: each patch
    is written against the file as it stood, and the second one's `AlreadySatisfied` /
    `already migrated by an earlier patch to this file` outcomes only make sense once the first has
    been decided. Run them at the same time and both are generated against the original, both look
    valid, and the second silently reverts the first when it is written.

    Different files share nothing, so groups are independent.
    """
    from qubit_core.db import AssetRow

    by_file: dict[str, list[Any]] = {}
    for task in tasks:
        asset = session.get(AssetRow, task.asset_id)
        location = (asset.location if asset else None) or {}
        # Findings with no file path are grouped under one key rather than spread across workers:
        # without a path there is no way to prove two of them do not touch the same thing.
        key = str(location.get("file_path") or "")
        by_file.setdefault(key, []).append(task)
    return list(by_file.values())


def _advise_unpatched(reporter: ProgressReporter, plan_id: UUID, pins: list[str]) -> int:
    """Give every finding that ends a run WITHOUT a patch a model's reading of its own file.

    A finding that ends `deferred` with resolution `RESOLUTION_GUIDED` carries the deterministic
    plan and nothing else -- that plan is deliberately model-free, and for a finding with no
    patch on offer it is the ONLY output, so this is what an engineer actually works from.

    Meanwhile the pool that just generated the patches is idle. Measured on `medivault-emr`: 24
    findings, 17 of them ending with `qubit-guided` advice and not one model call spent on reading
    any of their files, on an install with nine configured engines.

    INCLUSION on `resolution == RESOLUTION_GUIDED` specifically, not "any deferred task with a
    qubit-guided advice_model" -- the two look almost the same and are not. `RESOLUTION_REFUSED`
    also sets that `advice_model`, and a refused finding's advice text is not a placeholder
    waiting on a model's read -- it is the complete, correct, final answer (an ownership reason
    `resolve_refused` already wrote); force-regenerating it replaces that reason with a generic
    algorithm-migration plan, exactly what the refusal exists to refuse. `RESOLUTION_UNRESOLVED`
    is the more damaging case: that finding was CORRECTLY parked as retryable by `park_for_retry`,
    and `advise_task` -- built for a task that is ALREADY guided -- unconditionally sets
    `resolution = RESOLUTION_GUIDED` on the path this pass exercises (its model-unavailable
    fallback, `_store_plan_only`). Selecting on advice_model alone caught retryable failures too
    and silently converted them into permanently-guided ones, undoing `park_for_retry`'s own
    resolution the moment this pass ran over one -- measured: a Go finding whose LLM call failed
    correctly parked `unresolved`, then read `guided` by the time this pass finished with it, and
    a later run's retry query never saw it again.

    `advice_model == "qubit-guided"` is ALSO required, alongside the resolution check, not
    dropped in its favour. `resolve_guided` sets that value; a subsequent model read that
    actually succeeds sets `advice_model` to the ENGINE's own name instead (`_store_advice`), so
    "qubit-guided" specifically means "only the deterministic plan, no model has read this file
    yet". Without it a genuinely guided task -- permanently `deferred`/`RESOLUTION_GUIDED` by
    design, every subsequent bulk run -- was re-selected and force-regenerated on EVERY run
    forever, burning a model call and rewriting `advice_text` each time even after a model had
    already answered it once.

    Best-effort by construction. The deterministic plan is already stored on the task before this
    runs, so a failure here costs detail and never the answer -- which is why every exception is
    logged and swallowed rather than failing the job.
    """
    from qubit_migrate.orchestrator import RESOLUTION_GUIDED, MigrationOrchestrator
    from qubit_migrate.state import MigrationTask

    with reporter.sf() as session:
        pending: list[UUID] = [
            row.id
            for row in session.scalars(
                select(MigrationTask)
                .where(MigrationTask.plan_id == plan_id)
                .where(MigrationTask.state == "deferred")
                .where(MigrationTask.resolution == RESOLUTION_GUIDED)
                .where(MigrationTask.advice_model == "qubit-guided")
                .order_by(MigrationTask.rank)
            ).all()
        ]
    if not pending:
        return 0

    queue: list[UUID] = list(pending)
    lock = threading.Lock()
    logger.info("plan %s: reading %d unpatched finding(s) with the pool", plan_id, len(pending))

    def worker(pin: str) -> int:
        written = 0
        with reporter.sf() as session:
            orch = MigrationOrchestrator(session, pinned_engine=pin)
            while True:
                with lock:
                    if not queue:
                        return written
                    task_id = queue.pop(0)
                try:
                    orch.advise_task(task_id, force=True)
                except Exception as exc:  # see the docstring: this costs detail, never the answer
                    logger.info("advice for task %s unavailable (%s)", task_id, exc)
                else:
                    written += 1

    written = 0
    # One worker per pinned engine, exactly as generation runs, so the reading is spread over the
    # pool instead of queueing behind whichever engine is cheapest.
    workers = pins or [""]
    with cf.ThreadPoolExecutor(max_workers=len(workers)) as pool:
        for future in cf.as_completed([pool.submit(worker, pin) for pin in workers]):
            with contextlib.suppress(Exception):
                written += future.result()
    return written


def _prepare_in_parallel(
    reporter: ProgressReporter,
    plan_id: UUID,
    groups: list[list[Any]],
    pins: list[str],
    *,
    generator: GeneratorName,
    repo_root: Path | None,
    should_apply: bool,
    total: int,
    verb: str,
) -> _Tally:
    """Work the groups across the whole engine pool at once.

    One worker per engine, each pinned to its own, because the alternative measured badly: the
    router runs one cost policy, so every worker independently reaches the same conclusion and
    piles onto the same cheapest engine -- more rate-limit pressure, no more throughput. With pins,
    six configured engines do six findings at a time and the local GPU is one of them instead of
    sitting at 0% waiting for every hosted engine to fail first.

    Each worker owns its own `Session`. SQLite allows one WRITER at a time, which is fine here
    because the expensive part of a finding is a model call holding no transaction; the writes are
    short and `busy_timeout` plus `retry_write_on_lock` absorb the overlap.
    """
    from qubit_migrate.orchestrator import MigrationOrchestrator
    from qubit_migrate.state import MigrationTask

    tally = _Tally()
    lock = threading.Lock()
    queue: list[list[Any]] = list(groups)

    def worker(pin: str) -> _Tally:
        mine = _Tally()
        with reporter.sf() as session:
            orch = MigrationOrchestrator(session, pinned_engine=pin)
            while True:
                with lock:
                    if not queue:
                        return mine
                    group = queue.pop(0)
                for task_id in [t.id for t in group]:
                    reporter.checkpoint()
                    try:
                        task = session.get(MigrationTask, task_id)
                        if task is None or task.state != "ready":
                            continue
                        got = _prepare_one(
                            session,
                            orch,
                            task,
                            generator=generator,
                            repo_root=repo_root,
                            should_apply=should_apply,
                        )
                    except JobCancelled:
                        raise
                    except Exception as exc:
                        # A Session that failed a flush stays failed until it is rolled back, and
                        # every later use of it raises `PendingRollbackError` -- including the
                        # `session.get` above, which sits outside `_prepare_one`'s own handling.
                        #
                        # Measured, and this is what it cost: parallel workers made SQLite write
                        # contention real, one lost the race on a `learned_outcomes` hit-count bump
                        # ("database is locked"), that poisoned its Session, the next task's `get`
                        # raised, the exception left the worker, and a job that had already prepared
                        # 133 of 143 findings was reported as FAILED at 93%. The work was done and
                        # the run was thrown away over a bookkeeping write.
                        with contextlib.suppress(Exception):
                            session.rollback()
                        got = _Tally(
                            done=1,
                            failed=1,
                            failures=[
                                {
                                    "task_id": str(task_id),
                                    "rule_id": "",
                                    "bucket": "failed",
                                    "detail": f"{type(exc).__name__}: {exc}".replace(chr(10), " ")[
                                        :300
                                    ],
                                }
                            ],
                        )
                        logger.warning("worker on %s: task %s failed (%s)", pin, task_id, exc)
                    with lock:
                        mine.merge(got)
                        tally.merge(got)
                        snapshot = _Tally()
                        snapshot.merge(tally)
                    # Every outcome named by what it actually is. The line this replaced said
                    # "N ready, N guided, N failed", so a correct refusal, a gate rejecting a bad
                    # patch and a model giving up were one number: medivault-emr read "0 ready,
                    # 5 guided, 18 failed" for a run whose 18 were 6 ownership refusals, 1 already
                    # satisfied, 7 gate rejections and 2 real failures. These numbers go into a
                    # paper; the old ones understated the tool by an order of magnitude.
                    #
                    # Zero buckets are dropped rather than printed as "0 x", so a healthy run reads
                    # "18 ready" instead of dragging four zeroes across the status bar.
                    done = (
                        ", ".join(
                            f"{count} {label}"
                            for count, label in (
                                (snapshot.generated, "ready"),
                                (snapshot.needs_guidance, "guided"),
                                (snapshot.refused, "refused"),
                                (snapshot.rejected, "rejected"),
                                (snapshot.failed, "failed"),
                            )
                            if count
                        )
                        or "0 ready"
                    )
                    # Reported as COMPLETED out of total, not as an index. With several findings in
                    # flight there is no single "current" one, and a counter that went 4, 2, 5 as
                    # workers reported would be worse than no counter at all.
                    reporter.update(
                        snapshot.done / max(total, 1),
                        "migrate",
                        f"{verb} {snapshot.done}/{total} ({done}) on {len(pins)} engines",
                    )

    with cf.ThreadPoolExecutor(max_workers=len(pins)) as pool:
        futures = [pool.submit(worker, pin) for pin in pins]
        died: list[BaseException] = []
        for future in cf.as_completed(futures):
            try:
                future.result()
            except JobCancelled:
                # Cancellation is the operator's decision and must reach the caller: swallowing it
                # would leave a run going after the job was told to stop.
                raise
            except Exception as exc:
                logger.exception("a preparation worker died")
                died.append(exc)
        # One worker dying is not a failed run. The others carried the rest of the queue, and the
        # findings they prepared are real -- reporting the whole job as failed threw away 133
        # prepared findings over one bookkeeping write that lost a lock. It is a failed run only if
        # NOTHING survived to do the work.
        if died and len(died) == len(futures):
            raise died[0]

    # A worker that dies mid-run does not merely lose ITS OWN place in the queue -- it can be
    # holding a GROUP it already popped (`queue.pop(0)`, above) and never returns. That group's
    # tasks are still `ready` in the database, nothing else will pick them up this run, and
    # nothing in `tally` accounts for them: they were never reached, so no per-task except block
    # ever ran for them.
    #
    # Measured live: a paymesh-gateway migration job finished with status "succeeded" at
    # progress 1.0 while one task sat at plain `ready` -- never even reached `generating` -- with
    # no error naming it anywhere. The job's own report said done; a whole finding had been
    # silently dropped.
    #
    # `ready` needs no special recovery mechanism the way `generating`/`verifying` do (see the
    # sweep at the top of `migrate_handler`): it is exactly the state the very next `/run` call's
    # own task-selection query already looks for, so the finding is not lost. What was missing was
    # this job's own honesty about what it actually finished.
    #
    # Checked UNCONDITIONALLY, not only when `died` is non-empty. A dead worker caught via
    # `future.result()` is the mechanism observed and reproduced, but the check itself is a cheap
    # read query -- there is no reason to trust that it is the only way a popped group could go
    # unprocessed, and the cost of checking regardless is negligible next to what it catches.
    with reporter.sf() as session:
        from qubit_migrate.state import MigrationTask

        # `generating` as well as `ready`. The pool has EXITED by this line -- every worker has
        # returned and `shutdown(wait=True)` has completed -- so no task can legitimately still be
        # mid-generation. One that is was left there by a worker that stopped without finishing it.
        #
        # Measured: the engine process itself went away during a MediVault run, and seven tasks
        # (one per busy worker) stayed `generating` for good, while the job's last written status
        # was "succeeded" at progress 1.0.
        still_ready = list(
            session.scalars(
                select(MigrationTask)
                .where(MigrationTask.plan_id == plan_id)
                .where(MigrationTask.state.in_(("ready", "generating")))
            ).all()
        )
    # Excludes anything the tally already accounts for. A task can legitimately still be `ready`
    # after being COUNTED as failed: `_prepare_one`'s own exception handler tries to park it via
    # `resolve_guided`, and if that write ALSO fails (see its own try/except, above), the task is
    # left wherever `generate_patch` set it -- which can be its original `ready` -- while the
    # failure was still tallied correctly at the point it happened. Counting it again here would
    # double the reported failures for the same finding.
    already_tallied = {f["task_id"] for f in tally.failures}
    abandoned = [t for t in still_ready if str(t.id) not in already_tallied]
    if abandoned:
        logger.error(
            "plan %s: %d task(s) abandoned mid-run when %d of %d worker(s) died -- still "
            "'ready', not attempted this run, not reflected in this job's tally: %s",
            plan_id,
            len(abandoned),
            len(died),
            len(futures),
            [str(t.id) for t in abandoned],
        )
        tally.failed += len(abandoned)
        tally.failures.extend(
            {
                "task_id": str(t.id),
                "rule_id": t.rule_id or "",
                # Genuinely `failed`: nothing was produced for this finding and nothing decided
                # about it. It was never reached at all.
                "bucket": "failed",
                "detail": "abandoned: a worker died while this task's group was already "
                "popped from the queue, before it could be reached",
            }
            for t in abandoned
        )

    # The pool is idle from here. Spend it on the findings that got no patch -- see
    # `_advise_unpatched`. Never allowed to fail the run: the tally is already complete and
    # correct, and advice is an addition to it, not part of it.
    try:
        advised = _advise_unpatched(reporter, plan_id, pins)
    except Exception as exc:  # an addition to a finished run, never its verdict
        logger.info("plan %s: the advice pass did not run (%s)", plan_id, exc)
    else:
        if advised:
            logger.info("plan %s: %d unpatched finding(s) read by a model", plan_id, advised)
    return tally


def _write_prepared_patches(
    session: Any,
    orch: Any,
    plan_id: UUID,
    repo_root: Path | None,
    reporter: ProgressReporter,
) -> dict[str, Any]:
    """Write already-generated patches into the original files. The "Initiate migration" half.

    Nothing is decided here and no model runs: every patch in this set has already been through
    the validation gate, and the operator has had the diff in front of them. All that is left is
    the irreversible part, which is why it is its own act.

    A patch still `proposed` is approved on the way past — pressing "Initiate migration" IS the
    approval for anything the operator did not reject by hand. One already `approved` (by the row's
    own Approve button) is written as it stands.
    """
    from qubit_migrate.state import MigrationTask, PatchProposal

    if repo_root is None:
        # Not a failure of any individual patch: there is nowhere to write. Raising makes the job
        # fail loudly with the reason, rather than reporting "0 applied" and leaving the operator
        # to guess whether every patch was rejected.
        raise ValueError(
            "No repository root could be derived from this plan, so there is nowhere to write "
            "the changes. Set the project's root path and try again."
        )

    prepared = list(
        session.scalars(
            select(PatchProposal)
            .join(MigrationTask, PatchProposal.task_id == MigrationTask.id)
            .where(MigrationTask.plan_id == plan_id)
            .where(PatchProposal.status.in_(("proposed", "approved")))
            .order_by(MigrationTask.rank)
        ).all()
    )
    # Findings that were never generated for. Reported rather than quietly generated: "write the
    # changes" is not a licence to spend ten minutes of model time the operator did not ask for.
    no_patch = int(
        session.scalar(
            select(func.count())
            .select_from(MigrationTask)
            .where(MigrationTask.plan_id == plan_id)
            .where(MigrationTask.state == "ready")
        )
        or 0
    )

    total = len(prepared)
    applied = failed = 0
    failures: list[dict[str, str]] = []

    for index, patch in enumerate(prepared, start=1):
        task = session.get(MigrationTask, patch.task_id)
        reporter.update(
            index / max(total, 1),
            "apply",
            f"Writing {index}/{total}: {patch.file_path}",
        )
        try:
            if patch.status == "proposed":
                orch.review_patch(patch.id, approve=True, note="initiate migration", actor="api")
            orch.apply_patch(patch.id, repo_root=repo_root, actor="api")
            applied += 1
        except Exception as exc:  # one unwritable patch must not abandon the rest
            failed += 1
            failures.append(
                {
                    "task_id": str(patch.task_id),
                    "rule_id": (task.rule_id if task else None) or "",
                    "detail": f"{type(exc).__name__}: {exc}".replace(chr(10), " ")[:300],
                }
            )
            session.rollback()

    return {
        "plan_id": str(plan_id),
        "mode": "apply",
        "total": total,
        "generated": 0,
        "applied": applied,
        "covered": 0,
        "from_cache": 0,
        "needs_guidance": 0,
        # Always present, always zero on this half: nothing is decided here and no gate runs, so
        # neither outcome is reachable. Emitted anyway so a caller never has to tell "this run had
        # no refusals" apart from "this run predates the field".
        "refused": 0,
        "rejected": 0,
        "no_patch": no_patch,
        "failed": failed,
        "repo_root": str(repo_root),
        "applied_to_disk": True,
        "failures": failures[:25],
    }


def migrate_handler(payload: dict[str, Any], reporter: ProgressReporter) -> dict[str, Any]:
    """Run a whole plan. Two independent halves, selected by `generate` and `apply`.

    The two halves are what the app's two buttons do, and they are deliberately separate:

    * **`generate` only** — "Build plan". Write a patch for every ready finding, run each through
      the full validation gate, and leave it PROPOSED. Nothing on disk changes, so the operator
      gets the whole set of diffs to read before anything is committed to.
    * **`apply` only** — "Initiate migration". Take the patches that are already prepared and
      write them into the original files. No model runs; there is nothing left to decide.
    * **both** — the original single-shot behaviour, still the default, and what the CLI and the
      API's own callers get when they say nothing.

    Splitting them is the difference between a tool that asks for trust and one that earns it: the
    long, expensive, uncertain half now finishes before the operator is asked to approve anything,
    and the irreversible half is a separate, deliberate act on diffs they have seen.

    Doing it per task from the browser meant one HTTP request per finding, each holding a
    connection open for as long as the local model took, and no way to see how far along it was —
    so it runs as a job, like a scan, and reports progress the same way.

    Every stage stays the one the single-task path already uses (`generate_patch` runs the full
    validation gate, `review_patch` records the approval, `apply_patch` does the git-safety checks),
    so a bulk run cannot apply anything a careful operator could not have applied one at a time.
    A task that fails is recorded and the run continues: one unmigratable finding in a plan of
    twenty is not a reason to abandon the other nineteen.
    """
    from qubit_migrate.orchestrator import (
        RESOLUTION_UNRESOLVED,
        MigrationOrchestrator,
    )
    from qubit_migrate.state import MigrationPlan, MigrationTask
    from qubit_migrate.state.machine import InvalidTransition

    plan_id = UUID(payload["plan_id"])
    should_apply = bool(payload.get("apply", True))
    should_generate = bool(payload.get("generate", True))
    requested = str(payload.get("generator", "auto"))
    if requested not in GENERATORS:
        raise ValueError(f"unknown generator {requested!r}; expected one of {sorted(GENERATORS)}")
    generator = cast("GeneratorName", requested)

    with reporter.sf() as session:
        plan = session.get(MigrationPlan, plan_id)
        if not plan:
            raise ValueError(f"Plan {plan_id} not found")
        repo_root = _plan_repo_root(session, plan)
        orch = MigrationOrchestrator(session)

        if not should_generate:
            return _write_prepared_patches(session, orch, plan_id, repo_root, reporter)

        # ── Recover work an INTERRUPTED run left mid-flight ──────────────────────────────────
        #
        # `generating` and `verifying` mean "a run was here and did not come back". They are in
        # neither selection below — not `ready`, not `deferred` — so a task left in one is invisible
        # to every subsequent run and is stranded for good. The plan then never settles: a UI
        # polling for completion waits forever on a task nothing will ever pick up.
        #
        # Observed on a campaign run: `plan 9843201d still has 2 tasks running after 5400s`, an
        # hour and a half spent waiting on a task no code path could advance. The engine being
        # restarted mid-run is what produced it, and a crash or a closed laptop does the same thing
        # to a real user.
        #
        # Recovered through `defer` rather than by writing the state directly, so the FSM stays the
        # only thing that moves a task and the transition is recorded like any other.
        interrupted = list(
            session.scalars(
                select(MigrationTask)
                .where(MigrationTask.plan_id == plan_id)
                .where(MigrationTask.state.in_(("generating", "verifying")))
            ).all()
        )
        for task in interrupted:
            with contextlib.suppress(InvalidTransition):
                orch._fail_task(task, "a previous run was interrupted before this finished")
        if interrupted:
            session.commit()
            logger.info("recovered %d task(s) left mid-flight by an earlier run", len(interrupted))

        # Ready work, PLUS anything a previous run failed on or whose proposed diff a reviewer
        # rejected.  A rejection is feedback on a patch, not a terminal verdict on the finding.
        #
        # The engine learns between runs - a rewrite validated on one file grounds the next
        # attempt at the same shape, and a rejection is retained so it is not repeated blind. None
        # of that reached the findings that most needed it, because a failed task parks in
        # `deferred` and only `ready` was ever selected. Measured on this corpus: 9 findings sat
        # at `deferred/unresolved` across three subsequent runs, each of which had a better engine
        # than the one that failed them, and not one was tried again.
        #
        # `satisfied` and `guided` are deliberately NOT resumed. Both are resolved outcomes - one
        # is finished work, the other a written remediation - and re-running them would undo the
        # distinction the resolution field exists to make.
        retryable = list(
            session.scalars(
                select(MigrationTask)
                .where(MigrationTask.plan_id == plan_id)
                .where(MigrationTask.state == "deferred")
                .where(MigrationTask.resolution == RESOLUTION_UNRESOLVED)
                .order_by(MigrationTask.rank)
            ).all()
        )
        for task in retryable:
            with contextlib.suppress(InvalidTransition):
                orch.resume_task(task.id)
        reviewer_rejected = list(
            session.scalars(
                select(MigrationTask)
                .where(MigrationTask.plan_id == plan_id)
                .where(MigrationTask.state == "rejected")
                .order_by(MigrationTask.rank)
            ).all()
        )
        for task in reviewer_rejected:
            with contextlib.suppress(InvalidTransition):
                orch.resume_task(task.id)
        if retryable or reviewer_rejected:
            session.commit()

        tasks = list(
            session.scalars(
                select(MigrationTask)
                .where(MigrationTask.plan_id == plan_id)
                .where(MigrationTask.state == "ready")
                .order_by(MigrationTask.rank)
            ).all()
        )

        total = len(tasks)
        # A run that is only preparing must never say it is writing: that is the one sentence here
        # an operator would act on wrongly.
        verb = "Migrating" if should_apply else "Preparing"
        groups = _file_groups(session, tasks)
        # As many workers as there are engines, capped by the work available. One engine means the
        # old sequential behaviour exactly, which is what an install with only local Ollama gets.
        pins = orch.engine_names()[: max(1, min(len(groups), len(orch.engine_names())))]
        reporter.update(
            0.0,
            "migrate",
            f"{verb} {total} findings across {len(pins)} engine(s)",
        )

    # Outside the outer session: each worker opens its own, and holding a second one here for the
    # duration would be one more writer contending for the same SQLite file for no reason.
    tally = _prepare_in_parallel(
        reporter,
        plan_id,
        groups,
        pins,
        generator=generator,
        repo_root=repo_root,
        should_apply=should_apply,
        total=total,
        verb=verb,
    )
    generated = tally.generated
    applied = tally.applied
    covered = tally.covered
    from_cache = tally.from_cache
    needs_guidance = tally.needs_guidance
    refused = tally.refused
    rejected = tally.rejected
    failed = tally.failed
    failures = tally.failures

    return {
        "plan_id": str(plan_id),
        "mode": "full" if should_apply else "generate",
        "total": total,
        "generated": generated,
        "applied": applied,
        "covered": covered,
        "from_cache": from_cache,
        "needs_guidance": needs_guidance,
        # `refused` and `rejected` were both inside `failed` until this split, and every key here
        # keeps the name it had so the dashboard and the API's other callers are unaffected --
        # `covered` still counts exactly the `AlreadySatisfied` findings (a sub-count of `refused`),
        # `needs_guidance` still counts the findings that got a procedure instead of a patch.
        # What changed is that `failed` now means only what it says.
        #
        # `generated + refused + needs_guidance + rejected + failed == total` is the invariant;
        # `applied`, `from_cache` and `covered` are sub-counts and are not part of that sum.
        "refused": refused,
        "rejected": rejected,
        "failed": failed,
        # Absent a repo root nothing was written, and a caller that only sees `applied: 0` cannot
        # tell that apart from every patch failing.
        "repo_root": str(repo_root) if repo_root else None,
        "applied_to_disk": should_apply and repo_root is not None,
        "failures": failures[:25],
    }


HANDLERS = {
    "scan": scan_handler,
    "risk": risk_handler,
    "migrate": migrate_handler,
}
