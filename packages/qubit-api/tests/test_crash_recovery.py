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
    assert counts == {"jobs": 2, "scans": 1, "risk_runs": 1}

    with sf() as s:
        assert all(j.status == "failed" for j in s.query(Job).all())
        assert all("interrupted" in (j.error or "") for j in s.query(Job).all())
        scan = s.query(ScanRow).one()
        assert scan.status == "failed" and "interrupted" in (scan.error or "")
        assert s.query(RiskRun).one().status == "failed"


def test_recover_is_noop_when_nothing_orphaned(tmp_path: Path) -> None:
    import asyncio


    sf = _sf(tmp_path)
    with sf() as s:  # a cleanly-finished job must not be touched
        s.add(Job(kind="scan", status="succeeded", payload={}))
        s.commit()

    counts = asyncio.run(_run_recover(sf))
    assert counts == {"jobs": 0, "scans": 0, "risk_runs": 0}
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
