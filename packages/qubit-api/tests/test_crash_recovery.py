"""JobRunner crash recovery (BUILD_PLAN M2 acceptance: 'kill -9 mid-scan recovers cleanly').

A hard kill leaves jobs/scans/risk-runs stuck in queued|running. On restart the recovery sweep must
mark them failed with a clear message so nothing is left silently 'running'.
"""

from __future__ import annotations

from pathlib import Path

from qubit_api.settings import Settings
from qubit_core.db import Base, Job, ProjectRow, RiskRun, ScanRow, get_engine, session_factory


def _sf(tmp_path: Path):
    engine = get_engine(f"sqlite:///{(tmp_path / 'q.db').as_posix()}")
    Base.metadata.create_all(engine)
    return session_factory(engine)


def _seed_orphans(sf) -> None:
    """Simulate state left behind by a kill -9 mid-scan."""
    with sf() as s:
        proj = ProjectRow(name="p", slug="p")
        s.add(proj)
        s.flush()
        scan = ScanRow(project_id=proj.id, seq=1, status="running", targets=["x"])
        s.add(scan)
        s.flush()
        s.add(Job(kind="scan", status="running", project_id=proj.id, ref_id=scan.id, payload={}))
        s.add(Job(kind="risk", status="queued", payload={}))
        s.add(RiskRun(scan_id=scan.id, status="running", params={}))
        s.commit()


def test_recover_orphaned_marks_everything_failed(tmp_path: Path) -> None:
    import asyncio

    from qubit_api.jobs.bus import EventBus
    from qubit_api.jobs.runner import JobRunner

    sf = _sf(tmp_path)
    _seed_orphans(sf)

    async def _run() -> dict:
        # a fresh JobRunner == a restarted process
        return JobRunner(sf, EventBus()).recover_orphaned()

    counts = asyncio.run(_run())
    assert counts == {"jobs": 2, "scans": 1, "risk_runs": 1, "tasks": 0}

    with sf() as s:
        assert all(j.status == "failed" for j in s.query(Job).all())
        assert all("interrupted" in (j.error or "") for j in s.query(Job).all())
        scan = s.query(ScanRow).one()
        assert scan.status == "failed" and "interrupted" in (scan.error or "")
        assert s.query(RiskRun).one().status == "failed"


def test_recover_orphaned_unwedges_a_task_killed_mid_generation(tmp_path: Path) -> None:
    """The gap the job/scan/risk-run recovery above does not touch.

    A task killed mid-LLM-call is left at `generating` — neither `ready` (so a fresh "Build plan"
    never selects it) nor `deferred`/`unresolved` (so `resume_task` and the bulk retry query never
    select it either). Found reading the FSM and the retry queries directly while investigating
    what first looked like a stalled migrate job; that specific job turned out to have finished
    normally (a UTC-vs-local timestamp misread on my part), but the gap in the recovery sweep is
    real independent of that, and this is what closes it: on restart, `generating` is parked
    `deferred`/`unresolved` exactly as a real failure is, which makes it retryable again.
    """
    import asyncio

    from qubit_api.jobs.bus import EventBus
    from qubit_api.jobs.runner import JobRunner
    from qubit_core.mapping import asset_to_row
    from qubit_core.schemas import (
        AssetType,
        CryptoAsset,
        Location,
        QuantumAttack,
        QuantumVulnerability,
        RiskAnnotation,
        SourceScanner,
        UsageContext,
        utcnow,
    )
    from qubit_migrate.orchestrator import MigrationOrchestrator
    from qubit_migrate.state import MigrationTask

    sf = _sf(tmp_path)
    with sf() as s:
        project = ProjectRow(name="p", slug="p")
        s.add(project)
        s.flush()
        scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
        s.add(scan)
        s.flush()
        asset = CryptoAsset(
            algorithm="RSA-2048",
            usage_context=UsageContext.kex,
            source_scanner=SourceScanner.code,
            asset_type=AssetType.algorithm_use,
            location=Location(file_path="app.go", line=3),
            quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
            discovered_at=utcnow(),
            risk=RiskAnnotation(
                score=0.6, ci_low=0.5, ci_high=0.7, mosca_margin_years=-2.0, priority_rank=1
            ),
        )
        s.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
        s.commit()
        orch = MigrationOrchestrator(s)
        plan = orch.build_plan()
        task = orch.get_queue(plan.id)[0]
        # Simulate the kill: a real crash stops the process mid-`generate_patch`, after the
        # `ready -> generating` transition committed but before anything moved it further.
        orch._transition(task, "generate")
        s.commit()
        task_id = task.id

    async def _run() -> dict:
        return JobRunner(sf, EventBus()).recover_orphaned()

    counts = asyncio.run(_run())
    assert counts["tasks"] == 1, counts

    with sf() as s:
        recovered = s.get(MigrationTask, task_id)
        assert recovered.state == "deferred"
        assert recovered.resolution == "unresolved"
        assert "interrupted" in (recovered.last_error or "")

        orch = MigrationOrchestrator(s)
        resumed = orch.resume_task(task_id)
        assert resumed.state == "ready", "the whole point: it must be retryable again"


def test_recover_orphaned_does_not_touch_a_task_already_settled(tmp_path: Path) -> None:
    """The sweep must be selective — a `ready` or `proposed` task is not evidence of a crash."""
    import asyncio

    from qubit_api.jobs.bus import EventBus
    from qubit_api.jobs.runner import JobRunner
    from qubit_core.mapping import asset_to_row
    from qubit_core.schemas import (
        AssetType,
        CryptoAsset,
        Location,
        QuantumAttack,
        QuantumVulnerability,
        RiskAnnotation,
        SourceScanner,
        UsageContext,
        utcnow,
    )
    from qubit_migrate.orchestrator import MigrationOrchestrator
    from qubit_migrate.state import MigrationTask

    sf = _sf(tmp_path)
    with sf() as s:
        project = ProjectRow(name="p", slug="p")
        s.add(project)
        s.flush()
        scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
        s.add(scan)
        s.flush()
        asset = CryptoAsset(
            algorithm="MD5",
            usage_context=UsageContext.hash,
            source_scanner=SourceScanner.code,
            asset_type=AssetType.algorithm_use,
            location=Location(file_path="app.py", line=2),
            quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
            discovered_at=utcnow(),
            risk=RiskAnnotation(
                score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=1
            ),
        )
        s.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
        s.commit()
        orch = MigrationOrchestrator(s)
        plan = orch.build_plan()
        task_id = orch.get_queue(plan.id)[0].id

    async def _run() -> dict:
        return JobRunner(sf, EventBus()).recover_orphaned()

    counts = asyncio.run(_run())
    assert counts["tasks"] == 0, "a task that was never mid-transition must not be touched"

    with sf() as s:
        assert s.get(MigrationTask, task_id).state == "ready"


def test_recover_is_noop_when_nothing_orphaned(tmp_path: Path) -> None:
    import asyncio

    sf = _sf(tmp_path)
    with sf() as s:  # a cleanly-finished job must not be touched
        s.add(Job(kind="scan", status="succeeded", payload={}))
        s.commit()

    counts = asyncio.run(_run_recover(sf))
    assert counts == {"jobs": 0, "scans": 0, "risk_runs": 0, "tasks": 0}
    with sf() as s:
        assert s.query(Job).one().status == "succeeded"


async def _run_recover(sf) -> dict:
    from qubit_api.jobs.bus import EventBus
    from qubit_api.jobs.runner import JobRunner

    return JobRunner(sf, EventBus()).recover_orphaned()


def test_lifespan_startup_recovers(tmp_path: Path) -> None:
    """The app's startup (lifespan) must run recovery — a running scan becomes failed on boot."""
    from fastapi.testclient import TestClient
    from qubit_api.app import create_app

    settings = Settings(
        db_url=f"sqlite:///{(tmp_path / 'q.db').as_posix()}", create_schema_on_startup=True
    )
    # create schema + seed an orphaned running scan BEFORE the app boots
    engine = get_engine(settings.db_url)
    Base.metadata.create_all(engine)
    sf = session_factory(engine)
    with sf() as s:
        proj = ProjectRow(name="p", slug="p")
        s.add(proj)
        s.flush()
        s.add(ScanRow(project_id=proj.id, seq=1, status="running", targets=["x"]))
        s.add(Job(kind="scan", status="running", payload={}))
        s.commit()

    with TestClient(create_app(settings)):  # entering the context triggers lifespan startup
        pass

    with sf() as s:
        assert s.query(ScanRow).one().status == "failed"
        assert s.query(Job).one().status == "failed"
