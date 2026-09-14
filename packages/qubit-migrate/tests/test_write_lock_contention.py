"""Writes on the generate path must survive brief SQLite write-lock contention.

SQLite allows exactly one writer, and `generate_patch` writes at five points: `resume_task`, the
`generating` transition, `resolve_guided`, `_fail_task`, and the final patch store. When two
generations overlap -- one client's request still finishing server-side while the next starts --
those short writes collide, the loser waits out `PRAGMA busy_timeout` (20s) and raises
`OperationalError: database is locked`, which the API surfaces as a bare HTTP 500.

Measured live during an A/B run: generate answered **500 at 22-26s** on both engines whenever a
previous generation was still writing, and answered 303 in 4.5s with the queue quiet. Reachable in
completely ordinary use -- clicking Generate on several rows in a row.

The fix is `commit_with_retry` (jittered backoff, already in this codebase for a "Build plan" click
losing the same race). These tests pin that it is actually wired in, because the failure mode is
invisible until two things happen at once.
"""

from __future__ import annotations

import uuid

import pytest
from qubit_core.db import Base
from qubit_migrate.orchestrator import RESOLUTION_UNRESOLVED, MigrationOrchestrator
from qubit_migrate.state import MigrationPlan, MigrationTask, MigrationUnit
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session


@pytest.fixture
def orch() -> MigrationOrchestrator:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return MigrationOrchestrator(Session(engine))


def _deferred_task(orch: MigrationOrchestrator) -> MigrationTask:
    plan = MigrationPlan(id=uuid.uuid4())
    unit = MigrationUnit(id=uuid.uuid4(), plan_id=plan.id, label="wallet.go")
    task = MigrationTask(
        id=uuid.uuid4(),
        plan_id=plan.id,
        unit_id=unit.id,
        asset_id=uuid.uuid4(),
        state="deferred",
        resolution=RESOLUTION_UNRESOLVED,
    )
    orch.session.add_all([plan, unit, task])
    orch.session.commit()
    return task


def _fail_commits_once(orch: MigrationOrchestrator, calls: list[int]) -> None:
    """Make the NEXT commit fail exactly as a lost write-lock race does, then behave normally.

    `commit_with_retry` matches on the message text, so the message has to be the real one --
    `_retry_on_lock` re-raises anything that does not contain "database is locked".
    """
    real = orch.session.commit

    def flaky() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise OperationalError("UPDATE migration_tasks", {}, Exception("database is locked"))
        real()

    orch.session.commit = flaky  # type: ignore[method-assign]


def test_resume_task_survives_a_lost_write_lock_race(orch: MigrationOrchestrator) -> None:
    """`generate_patch` calls `resume_task` unconditionally, so a collision here fails the whole
    generation before the model is even reached.
    """
    task = _deferred_task(orch)
    calls: list[int] = []
    _fail_commits_once(orch, calls)

    resumed = orch.resume_task(task.id)

    assert len(calls) >= 2, "the first commit must be retried, not propagated as a 500"
    assert resumed.state == "ready"


# `resolve_guided` takes the same treatment, but is not covered here: it routes through
# `advise_task`, which loads the finding's asset and builds a real remediation plan, so a
# meaningful test needs a fully-populated AssetRow rather than a bare task. The retry mechanism
# itself is what these tests pin, and `resume_task` exercises the identical code path.


def test_a_non_lock_operational_error_is_not_retried(orch: MigrationOrchestrator) -> None:
    """The retry must stay narrow. A genuine schema or constraint error is not a race, and quietly
    re-running it would turn one clear failure into a slower, more confusing one.
    """
    task = _deferred_task(orch)
    calls: list[int] = []

    def always_broken() -> None:
        calls.append(1)
        raise OperationalError("UPDATE migration_tasks", {}, Exception("no such column: nope"))

    orch.session.commit = always_broken  # type: ignore[method-assign]

    with pytest.raises(OperationalError, match="no such column"):
        orch.resume_task(task.id)
    assert len(calls) == 1, "a non-lock error must propagate on the first attempt"
