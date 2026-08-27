"""`ProgressReporter.update()` runs on a worker thread (`anyio.to_thread.run_sync`) while the event
loop it publishes onto lives on a different thread. The `is_closed()` guard and the
`run_coroutine_threadsafe` call are not atomic, so the loop can close in the gap between them —
observed as a "coroutine 'EventBus.publish' was never awaited" `RuntimeWarning` surfacing on a
LATER, unrelated test once GC finally collected the orphaned coroutine. This pins the fix's actual
contract: if scheduling fails, `update()` retires the coroutine itself via `coro.close()` rather
than leaving it for GC to warn about.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

from qubit_api.jobs.bus import EventBus
from qubit_api.jobs.runner import ProgressReporter
from qubit_core.db import Base, Job, ProjectRow, ScanRow, get_engine, session_factory


def _sf(tmp_path: Path):
    engine = get_engine(f"sqlite:///{(tmp_path / 'q.db').as_posix()}")
    Base.metadata.create_all(engine)
    return session_factory(engine)


def _seed_job(sf) -> object:
    with sf() as s:
        proj = ProjectRow(name="p", slug="p")
        s.add(proj)
        s.flush()
        scan = ScanRow(project_id=proj.id, seq=1, status="running", targets=["x"])
        s.add(scan)
        s.flush()
        job = Job(kind="scan", status="running", project_id=proj.id, ref_id=scan.id, payload={})
        s.add(job)
        s.commit()
        s.refresh(job)
        return job.id


def test_update_closes_the_coroutine_when_scheduling_races_a_closing_loop(
    tmp_path: Path, monkeypatch
) -> None:
    sf = _sf(tmp_path)
    job_id = _seed_job(sf)
    bus = EventBus()

    async def _make_reporter() -> ProgressReporter:
        return ProgressReporter(job_id, sf, bus, threading.Event())

    reporter = asyncio.run(_make_reporter())

    # Spy on EventBus.publish so the test can inspect the exact coroutine object `update()`
    # creates, without changing what it does — `real_publish` is still called and its coroutine
    # still returned, only captured on the way out.
    created: list = []
    real_publish = EventBus.publish

    def spy_publish(self, *a, **kw):
        coro = real_publish(self, *a, **kw)
        created.append(coro)
        return coro

    monkeypatch.setattr(EventBus, "publish", spy_publish)

    # `is_closed()` reports healthy (mirrors the real race: the loop is still open when `update()`
    # checks it) but `run_coroutine_threadsafe` itself fails, exactly as it does when the loop
    # closes in the gap between that check and this call — reproduced deterministically instead of
    # via a flaky real thread race.
    monkeypatch.setattr(reporter.loop, "is_closed", lambda: False)

    def _raise_closed(coro, loop):
        raise RuntimeError("Event loop is closed")

    monkeypatch.setattr(asyncio, "run_coroutine_threadsafe", _raise_closed)

    reporter.update(0.5, "scan", "halfway")  # must not raise

    assert len(created) == 1
    # A closed coroutine's frame is released — this is what stops the "was never awaited" warning
    # at GC time, deterministically, rather than depending on when/whether GC runs.
    assert created[0].cr_frame is None

    with sf() as s:
        job = s.get(Job, job_id)
        assert job.progress == 0.5
        assert job.message == "halfway"
