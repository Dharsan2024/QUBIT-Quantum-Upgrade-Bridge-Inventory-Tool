"""A task stranded in `generating` must be reclaimable without restarting the server.

The FSM has no `generate` event from `generating`, so a generation whose caller went away leaves
the row answering "No transition 'generate' from state 'generating'" to every later click --
permanently, because `resume_task` and the bulk retry query both select only `deferred`, and a
fresh plan build selects only `ready`.

`JobRunner._recover_orphaned_tasks` already repairs this, but only on server RESTART. That does
nothing for the case people actually hit: navigating away mid-generation, coming back, and finding
a dead row. These tests pin the on-demand repair, and the boundary that stops it reclaiming a
generation that is genuinely still running.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from qubit_core.db import Base
from qubit_migrate.orchestrator import RESOLUTION_UNRESOLVED, MigrationOrchestrator
from qubit_migrate.state import MigrationEvent, MigrationPlan, MigrationTask, MigrationUnit
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


@pytest.fixture
def orch() -> MigrationOrchestrator:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return MigrationOrchestrator(Session(engine))


def _generating_task(orch: MigrationOrchestrator, *, age_seconds: float) -> MigrationTask:
    """A task sitting at `generating`, whose `generating` event is ``age_seconds`` old."""
    plan = MigrationPlan(id=uuid.uuid4())
    unit = MigrationUnit(id=uuid.uuid4(), plan_id=plan.id, label="wallet.go")
    task = MigrationTask(
        id=uuid.uuid4(),
        plan_id=plan.id,
        unit_id=unit.id,
        asset_id=uuid.uuid4(),
        state="generating",
    )
    orch.session.add_all([plan, unit, task])
    orch.session.flush()
    orch.session.add(
        MigrationEvent(
            task_id=task.id,
            from_state="ready",
            to_state="generating",
            actor="api",
            at=datetime.now(UTC) - timedelta(seconds=age_seconds),
        )
    )
    orch.session.commit()
    return task


def test_a_long_stranded_generating_task_is_reclaimed_on_retry(
    orch: MigrationOrchestrator,
) -> None:
    """The user-visible fix: clicking Generate again on a dead row makes it retryable."""
    # Well past the bound (llm_timeout 180s x 16 = 48 min).
    task = _generating_task(orch, age_seconds=60 * 60 * 3)

    resumed = orch.resume_task(task.id)

    assert resumed.state == "ready", "a stranded task must return to the queue, not stay dead"
    assert resumed.resolution is None
    assert "interrupted" in (resumed.last_error or "").lower()


def test_a_generation_still_in_flight_is_never_reclaimed(orch: MigrationOrchestrator) -> None:
    """The safety direction that matters more than the fix.

    Reclaiming a task whose generation is genuinely still running would let two generations write
    to the same row. Waiting is the cheaper failure, so anything inside the bound stays put.
    """
    task = _generating_task(orch, age_seconds=30)

    resumed = orch.resume_task(task.id)

    assert resumed.state == "generating", "an in-flight generation must not be reclaimed"


def test_a_generating_task_with_no_recorded_event_is_left_alone(
    orch: MigrationOrchestrator,
) -> None:
    """No timestamp means no evidence, and refusing to reclaim is always the safe direction."""
    plan = MigrationPlan(id=uuid.uuid4())
    unit = MigrationUnit(id=uuid.uuid4(), plan_id=plan.id, label="a.go")
    task = MigrationTask(
        id=uuid.uuid4(),
        plan_id=plan.id,
        unit_id=unit.id,
        asset_id=uuid.uuid4(),
        state="generating",
    )
    orch.session.add_all([plan, unit, task])
    orch.session.commit()

    assert orch.resume_task(task.id).state == "generating"


def test_the_bound_scales_with_the_configured_timeout(orch: MigrationOrchestrator) -> None:
    """The bound is derived from `llm_timeout`, not a hardcoded number of minutes -- an install
    that raises the timeout for a slower machine must not start reclaiming live generations.
    """
    orch.config.llm_timeout = 600.0  # 600 x 16 = 160 minutes
    task = _generating_task(orch, age_seconds=60 * 60)  # 1 hour: stranded at 180s, live at 600s

    assert orch.resume_task(task.id).state == "generating"

    orch.config.llm_timeout = 60.0  # 60 x 16 = 16 minutes, so the same task is now stranded
    assert orch.resume_task(task.id).state == "ready"


def test_an_ordinary_deferred_task_still_resumes(orch: MigrationOrchestrator) -> None:
    """Regression guard: the existing `deferred`/`unresolved` path must be untouched."""
    plan = MigrationPlan(id=uuid.uuid4())
    unit = MigrationUnit(id=uuid.uuid4(), plan_id=plan.id, label="b.go")
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

    assert orch.resume_task(task.id).state == "ready"
