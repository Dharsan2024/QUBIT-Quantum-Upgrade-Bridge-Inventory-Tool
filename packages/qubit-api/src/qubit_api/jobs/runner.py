from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any
from uuid import UUID

import anyio
from qubit_core.db import Job
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
            job = session.get(Job, self.job_id)
            if job:
                job.progress = progress
                job.stage = stage
                job.message = message
                session.commit()

                # run_coroutine_threadsafe owns the coro (never GC'd un-awaited); skip if the loop
                # is gone (test teardown) so no orphan coro is created.
                if not self.loop.is_closed():
                    asyncio.run_coroutine_threadsafe(
                        self.bus.publish(
                            "job.progress",
                            {
                                "job_id": str(self.job_id),
                                "kind": job.kind,
                                "progress": progress,
                                "stage": stage,
                                "message": message,
                            },
                        ),
                        self.loop,
                    )


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
            "verify": asyncio.Semaphore(2),
            "cbom_import": asyncio.Semaphore(2),
        }
        self._cancel_flags: dict[UUID, threading.Event] = {}
        self._tasks: set[asyncio.Task[Any]] = set()

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
            if result is not None:
                job.result = result
            if error is not None:
                job.error = error
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
