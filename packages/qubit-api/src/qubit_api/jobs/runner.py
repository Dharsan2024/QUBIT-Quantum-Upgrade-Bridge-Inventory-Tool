from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any
from uuid import UUID

import anyio
from qubit_core.db import Job, RiskRun, ScanRow
from qubit_core.db.session import retry_write_on_lock
from qubit_core.schemas import utcnow
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from .bus import EventBus

logger = logging.getLogger(__name__)


class JobCancelled(Exception):
    """Raised when a job is cooperatively cancelled via checkpoints."""


class ProgressReporter:
    def __init__(
        self, job_id: UUID, sf: sessionmaker[Session], bus: EventBus, cancel: threading.Event
    ):
        self.job_id = job_id
        self.sf = sf
        self.bus = bus
        self.cancel = cancel
        self.loop = asyncio.get_running_loop()

    def checkpoint(self) -> None:
        if self.cancel.is_set():
            raise JobCancelled()

    def update(self, progress: float, stage: str, message: str) -> None:
        self.checkpoint()

        # Update DB using a short-lived session
        with self.sf() as session:
            # Progress is telemetry. The complete load/update/commit is the retry unit: retrying
            # a no-op and committing outside it only caught a lock after the update was dropped.
            def persist_progress() -> Job | None:
                job = session.get(Job, self.job_id)
                if job is None:
                    return None
                job.progress = progress
                job.stage = stage
                job.message = message
                session.commit()
                return job

            try:
                job = retry_write_on_lock(session, persist_progress, attempts=3)
            except OperationalError:
                session.rollback()
                logger.warning(
                    "job %s: progress update skipped, database busy (%s)",
                    self.job_id,
                    message[:80],
                )
                return

            if job is not None and not self.loop.is_closed():
                # `update()` runs on a worker thread (anyio.to_thread.run_sync), while `self.loop`
                # closes on the EVENT LOOP thread — the `is_closed()` check below and the
                # `run_coroutine_threadsafe` call are not atomic, so the loop can close in the gap
                # between them (observed as a "coroutine 'EventBus.publish' was never awaited"
                # RuntimeWarning surfacing on a LATER, unrelated test, once GC finally collected
                # the orphaned coroutine `run_coroutine_threadsafe` never got to schedule).
                # `run_coroutine_threadsafe` owns the coro once scheduling succeeds; on the race,
                # `coro.close()` retires it deterministically instead of leaving it to GC.
                coro = self.bus.publish(
                    "job.progress",
                    {
                        "job_id": str(self.job_id),
                        "kind": job.kind,
                        "progress": progress,
                        "stage": stage,
                        "message": message,
                    },
                )
                try:
                    asyncio.run_coroutine_threadsafe(coro, self.loop)
                except RuntimeError:
                    coro.close()


class JobRunner:
    def __init__(
        self, sf: sessionmaker[Session], bus: EventBus, scan_slots: int = 2, llm_slots: int = 1
    ):
        self.sf = sf
        self.bus = bus
        self.loop = asyncio.get_running_loop()
        self._sem = {
            "scan": asyncio.Semaphore(scan_slots),
            "risk": asyncio.Semaphore(scan_slots),
            "patch": asyncio.Semaphore(llm_slots),
            "plan": asyncio.Semaphore(2),
            # One bulk migration at a time: every task in a run writes to the same working tree, and
            # two runs interleaving `git apply` on one checkout is how a half-applied patch happens.
            "migrate": asyncio.Semaphore(1),
            "verify": asyncio.Semaphore(2),
            "cbom_import": asyncio.Semaphore(2),
        }
        self._cancel_flags: dict[UUID, threading.Event] = {}
        self._tasks: set[asyncio.Task[Any]] = set()

    def recover_orphaned(self) -> dict[str, int]:
        """Recover jobs left mid-flight by a crash / kill -9 (M2 acceptance: 'recovers cleanly').

        A hard kill leaves jobs (and their scans / risk runs) stuck in queued/running forever. On
        startup we mark every such record failed with a clear message, so state is consistent and
        the work can simply be re-run — nothing is left silently 'running'. Returns per-kind counts.
        """
        # `dict` keys are invariant and SQLAlchemy's `Query.update` accepts columns as well as
        # names, so a `dict[str, ...]` is narrower than the parameter type however it is
        # spelled. The values are column names here and nothing else.
        interrupted: dict[Any, Any] = {
            "status": "failed",
            "error": "interrupted by server restart",
        }
        active = ["queued", "running"]
        with self.sf() as session:
            jobs = (
                session.query(Job)
                .filter(Job.status.in_(active))
                .update(interrupted, synchronize_session=False)
            )
            scans = (
                session.query(ScanRow)
                .filter(ScanRow.status.in_(active))
                .update(interrupted, synchronize_session=False)
            )
            risk_runs = (
                session.query(RiskRun)
                .filter(RiskRun.status.in_(active))
                .update({"status": "failed"}, synchronize_session=False)  # RiskRun has no error col
            )
            tasks = self._recover_orphaned_tasks(session)
            session.commit()
        counts = {
            "jobs": int(jobs),
            "scans": int(scans),
            "risk_runs": int(risk_runs),
            "tasks": tasks,
        }
        if any(counts.values()):
            logger.warning("Recovered orphaned records after restart: %s", counts)
        return counts

    @staticmethod
    def _recover_orphaned_tasks(session: Session) -> int:
        """Recover `MigrationTask` rows a crashed job left mid-transition.

        The job/scan/risk-run recovery above only touches the RECORD OF THE JOB. Nothing recovered
        the WORK a migrate job was doing when it died -- a task killed mid-generation stays at
        `generating` forever, and that state is neither `ready` (so a fresh "Build plan" run
        never selects it) nor `deferred/unresolved` (so `resume_task` and the bulk retry query
        never select it either). It is invisible to every path that would otherwise pick it back
        up: a genuine dead end, reached by a crash rather than a bug in the migration itself.

        A `generating` task orphaned by a crash is invisible to every retry path there is:
        `resume_task` and the bulk retry query both select ONLY `deferred`/`unresolved`, and a
        fresh "Build plan" run selects ONLY `ready`. `generating` is neither, so a task killed
        mid-LLM-call stays there until someone reads the database directly and notices -- which
        is how this was found, investigating what first looked like a stalled migrate job (it
        turned out not to be one: a UTC-vs-local timestamp misread on my part made a genuine
        513-second run look like it had been hung for five hours). The gap this closes is real
        regardless of that; `test_llm_hard_timeout.py` covers the other real gap surfaced by the
        same investigation -- `urlopen(timeout=...)` bounding each socket read, not a whole call.

        `generating` and `verifying` are the two states a task can be orphaned in -- see the FSM
        in `state/machine.py`. `generating` only has a `defer` event, so it is parked exactly as a
        real failure is (`_fail_task`'s own shape): `deferred`/`unresolved`, immediately retryable.
        `verifying` has no `defer` event at all, because a patch has already reached disk by then;
        the honest move is `verify_fail` (`apply_failed`), which itself allows `revert` or `defer`
        later -- claiming a verify that never ran actually passed would be worse than not knowing.
        """
        from qubit_migrate.orchestrator import RESOLUTION_UNRESOLVED
        from qubit_migrate.state import MigrationTask, write_event
        from qubit_migrate.state.machine import transition

        recovered = 0
        for from_state, event in (("generating", "defer"), ("verifying", "verify_fail")):
            for task in session.scalars(
                select(MigrationTask).where(MigrationTask.state == from_state)
            ).all():
                task.state = transition(from_state, event)
                task.last_error = "interrupted by server restart"
                if from_state == "generating":
                    task.resolution = RESOLUTION_UNRESOLVED
                write_event(
                    session,
                    task,
                    from_state=from_state,
                    to_state=task.state,
                    actor="system",
                    detail={"reason": "interrupted by server restart"},
                )
                recovered += 1
        return recovered

    def _mark_running(self, job_id: UUID) -> None:
        """Record that the work has actually started, and when.

        Best-effort for the same reason progress is: the status of a job must never be able to kill
        the job. A lost write here costs a wrong label on one row; raising would cost the run.
        """
        try:
            with self.sf() as session:
                job = session.get(Job, job_id)
                if job and job.status == "queued":
                    job.status = "running"
                    job.started_at = utcnow()
                    session.commit()
        except OperationalError:
            logger.warning("job %s: could not mark running, database busy", job_id)

    def _finish(
        self,
        job_id: UUID,
        status: str,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        with self.sf() as session:
            job = session.get(Job, job_id)
            if not job:
                return
            job.status = status
            # Paired with `started_at`, this is the only record of how long a run took. Without it
            # "how long does a migration of this repository take" is answerable only by watching
            # one, which is not an answer a paper can carry.
            job.finished_at = utcnow()
            if result is not None:
                job.result = result
            if error is not None:
                job.error = error

            # Propagate a terminal failure to the record the job was working on.
            #
            # Without this, a job that fails or is cancelled updates only the Job row and leaves its
            # ScanRow at status "running" forever: the scan appears to be in progress, `GET /scans`
            # keeps listing it as active, and `recover_orphaned` only cleans it up on the NEXT
            # restart. Surfaced by a network scan refused by the authorization gate — the job
            # correctly failed with the refusal reason while the scan still read "running" with no
            # error, which is precisely the state a user cannot act on. Applies to every scan mode,
            # including the filesystem one this predates.
            if status in ("failed", "cancelled") and job.ref_id is not None:
                if job.kind == "scan":
                    scan = session.get(ScanRow, job.ref_id)
                    # Never overwrite a scan that already reached a terminal state of its own.
                    if scan and scan.status in ("queued", "running"):
                        scan.status = "failed" if status == "failed" else "cancelled"
                        scan.error = error or f"job {status}"
                        scan.finished_at = utcnow()
                elif job.kind == "risk":
                    risk_run = session.get(RiskRun, job.ref_id)
                    if risk_run and risk_run.status in ("queued", "running"):
                        risk_run.status = "failed"  # RiskRun has no error column
                        risk_run.finished_at = utcnow()
            session.commit()

            # Emit finished event (threadsafe schedule; coro is owned, never GC'd un-awaited)
            if not self.loop.is_closed():
                asyncio.run_coroutine_threadsafe(
                    self.bus.publish(
                        "job.finished",
                        {"job_id": str(job_id), "status": status, "result": result, "error": error},
                    ),
                    self.loop,
                )

    def submit(self, job_id: UUID) -> None:
        self._cancel_flags[job_id] = threading.Event()
        self.loop.call_soon_threadsafe(self._create_task, job_id)

    def _create_task(self, job_id: UUID) -> None:
        t = asyncio.create_task(self._run(job_id))
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def _run(self, job_id: UUID) -> None:
        # Avoid circular imports by importing handlers locally
        from .handlers import HANDLERS

        with self.sf() as session:
            job = session.get(Job, job_id)
            if not job:
                logger.error("Job %s not found in DB.", job_id)
                self._cancel_flags.pop(job_id, None)
                return
            kind = job.kind
            payload = job.payload

        handler = HANDLERS.get(kind)
        if not handler:
            self._finish(job_id, "failed", error=f"Unknown job kind: {kind}")
            self._cancel_flags.pop(job_id, None)
            return

        async with self._sem[kind]:
            flag = self._cancel_flags[job_id]
            if flag.is_set():
                self._finish(job_id, "cancelled")
                self._cancel_flags.pop(job_id, None)
                return

            reporter = ProgressReporter(job_id, self.sf, self.bus, cancel=flag)
            # The job is only RUNNING once it holds its kind's slot. Nothing set this before, so
            # every job read `queued` for its whole life however long it worked, and the two states
            # an operator most needs to tell apart looked identical: a migration grinding through
            # three hundred findings, and one waiting behind it for a semaphore that allows one
            # migrate job at a time. Both said "queued", both sat at whatever progress they had.
            # That is the shape of the "it's stuck" report — three clicks, three jobs, one of them
            # working and two of them genuinely waiting, and no way to see which.
            self._mark_running(job_id)

            try:
                # Run the handler in a worker thread
                result = await anyio.to_thread.run_sync(handler, payload, reporter)
                self._finish(job_id, "succeeded", result)
            except JobCancelled:
                self._finish(job_id, "cancelled")
            except Exception as e:
                logger.exception("Job %s failed", job_id)
                self._finish(job_id, "failed", error=str(e))
            finally:
                self._cancel_flags.pop(job_id, None)

    def cancel(self, job_id: UUID) -> None:
        flag = self._cancel_flags.get(job_id)
        if flag:
            flag.set()
