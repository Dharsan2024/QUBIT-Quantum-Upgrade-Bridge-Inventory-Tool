from __future__ import annotations

import concurrent.futures as cf
import contextlib
import logging
import shutil
import subprocess
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast
from uuid import UUID

from qubit_core import asset_to_row
from qubit_core.db import AssetRow, ProjectRow, ScanRow
from qubit_risk.pipeline import RiskPipeline
from qubit_scanner import SCANNER_NAMES, scan_paths
from sqlalchemy import func, select

from ..services import autobuild_migration_plan, is_git_url
from .runner import JobCancelled, ProgressReporter

logger = logging.getLogger(__name__)

#: The generators `generate_patch` accepts. Narrowed from the job payload, which is JSON and so
#: arrives as a plain string — an unrecognised value is refused rather than passed through.
GeneratorName = Literal["auto", "llm", "template"]
GENERATORS: frozenset[str] = frozenset(("auto", "llm", "template"))

if TYPE_CHECKING:  # imported lazily at runtime, to keep this module free of a cycle
    from qubit_migrate.orchestrator import MigrationOrchestrator
    from sqlalchemy.orm import Session


def _clone_git_target(url: str) -> Path:
    """Shallow-clone a remote repo to a temp dir and return the checkout path.

    Mirrors the CLI's `qubit run` git support so the dashboard/API can scan a repo URL too.
    """
    dest = Path(tempfile.mkdtemp(prefix="qubit-apiclone-")) / "repo"
    proc = subprocess.run(  # noqa: S603
        ["git", "clone", "--depth", "1", url, str(dest)],  # noqa: S607
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
        clone_dirs: list[Path] = []  # temp git clones to remove after the scan
        # Re-enforce the operator's scan-root allowlist here rather than trusting that the route
        # already did. The job runs off the request path and its payload is persisted, so a handler
        # that assumed the check had happened would be one edited row away from scanning anything.
        allowed_roots = [Path(r).resolve() for r in (payload.get("scan_roots") or [])]
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


@dataclass
class _Tally:
    """What a bulk run produced, accumulated across workers.

    Every finding lands in exactly one bucket, and the buckets are not interchangeable: `covered`
    is finished work, `needs_guidance` is a written procedure, and only `failed` means QUBIT could
    not do what it set out to. Collapsing them is how a healthy run came to read as a broken one.
    """

    generated: int = 0
    applied: int = 0
    covered: int = 0
    from_cache: int = 0
    needs_guidance: int = 0
    failed: int = 0
    failures: list[dict[str, str]] = field(default_factory=list)
    done: int = 0

    def merge(self, other: _Tally) -> None:
        self.generated += other.generated
        self.applied += other.applied
        self.covered += other.covered
        self.from_cache += other.from_cache
        self.needs_guidance += other.needs_guidance
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
    from qubit_migrate.orchestrator import AlreadySatisfied, GuidedRemediation

    tally = _Tally(done=1)
    # A finding with no rule is not written off here.
    #
    # This used to short-circuit straight to guidance: no rule in the YAML pack, therefore no patch
    # to attempt. `generate_patch` now derives one from QUBIT's own knowledge base for the families
    # that HAVE a post-quantum answer, and declines for the ones that do not -- raising
    # `GuidedRemediation`, which is counted below exactly as this branch used to count it. Deciding
    # it here meant the synthesiser was never consulted on the findings it was built for.
    try:
        patch = orch.generate_patch(task.id, generator=generator, repo_root=repo_root)
        if patch.status != "proposed":
            raise ValueError("the validation gate rejected this patch")
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
    except GuidedRemediation:
        # A verdict, not an error: the rule says no edit QUBIT can make is the right answer here,
        # and `generate_patch` has already stored the plan that says what is.
        tally.needs_guidance += 1
    except AlreadySatisfied:
        # The outcome the rule exists to reach is already true -- an earlier patch rewrote the
        # whole file, or the dependency pin already meets the PQC floor. Finished work, not a
        # failure. Matched on the EXCEPTION TYPE, never on words in the message: the string test
        # this replaced recognised two of the four satisfied paths and counted 19 findings of
        # finished work as failures.
        tally.covered += 1
        session.rollback()
    except Exception as exc:  # one bad finding must not end the run
        tally.failed += 1
        tally.failures.append(
            {
                "task_id": str(task.id),
                "rule_id": task.rule_id or "",
                "detail": f"{type(exc).__name__}: {exc}".replace(chr(10), " ")[:300],
            }
        )
        session.rollback()
        # A failed generation is still a finding that needs handling. Without this the queue row
        # carried a rejection reason and nothing else -- the same dead end as "manual change",
        # reached by a different route.
        with contextlib.suppress(Exception):
            # The plan is written, but the finding is NOT claimed as resolved: a better engine on
            # a later run has to be able to pick it back up.
            orch.resolve_guided(task.id, force=True, claim_resolved=False)
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
                    done = f"{snapshot.generated} ready"
                    if snapshot.needs_guidance:
                        done += f", {snapshot.needs_guidance} guided"
                    if snapshot.failed:
                        done += f", {snapshot.failed} failed"
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

        # Ready work, PLUS anything a previous run failed on.
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
        if retryable:
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
