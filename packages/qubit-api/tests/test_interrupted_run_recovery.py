"""A run that was interrupted must not strand its work forever.

`generating` and `verifying` mean "a run was here and did not come back". The bulk handler selected
`ready` tasks and `deferred/unresolved` ones, and a task left mid-flight is in neither — so no
subsequent run could ever pick it up. The plan then never settles, and a UI polling for completion
waits on a task nothing will advance.

Observed on a real campaign run:

    plan 9843201d still has 2 tasks running after 5400s

Ninety minutes spent waiting on work no code path could reach. An engine restart produced it here;
a crash, a closed laptop or a killed container does the same thing to a user.

Recovery goes through the state machine (`defer`, then the existing resume) rather than writing the
state column, so the FSM stays the only thing that moves a task and the transition is recorded like
any other.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from qubit_core import CryptoAsset
from qubit_core.db import AssetRow, Base, ProjectRow, ScanRow
from qubit_core.mapping import asset_to_row
from qubit_core.schemas import (
    AssetType,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.orchestrator import RESOLUTION_UNRESOLVED, MigrationOrchestrator
from qubit_migrate.state import MigrationPlan, MigrationTask, MigrationUnit
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session


@pytest.fixture
def session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def _plan_with_task(session: Session, state: str) -> tuple[MigrationPlan, MigrationTask]:
    project = ProjectRow(name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    plan = MigrationPlan(project_id=project.id, scan_id=scan.id)
    session.add(plan)
    session.flush()
    unit = MigrationUnit(plan_id=plan.id, label="app/exports.py")
    session.add(unit)
    session.flush()

    asset = CryptoAsset(
        id=uuid.uuid4(),
        algorithm="AES",
        usage_context=UsageContext.encryption_at_rest,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path="app/exports.py", line=79),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=datetime.now(UTC),
        risk=RiskAnnotation(
            score=0.5, ci_low=0.5, ci_high=0.5, mosca_margin_years=5.0, priority_rank=1
        ),
    )
    row: AssetRow = asset_to_row(asset, project_id=project.id, scan_id=scan.id)
    session.add(row)
    session.flush()
    task = MigrationTask(
        plan_id=plan.id, unit_id=unit.id, asset_id=row.id, state=state,
        rule_id="py-weakcipher-01",
    )
    session.add(task)
    session.commit()
    return plan, task


def _recover(session: Session, plan_id) -> int:
    """The recovery step the handler performs, in isolation.

    Mirrors `migrate_handler` so the test is about the SELECTION — which states count as
    interrupted — rather than about assembling a whole job run.
    """
    import contextlib

    from qubit_migrate.state.machine import InvalidTransition

    orch = MigrationOrchestrator(session)
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
    session.commit()
    return len(interrupted)


class TestMidFlightStatesAreRecovered:
    @pytest.mark.parametrize("state", ["generating", "verifying"])
    def test_a_task_left_mid_flight_is_returned_to_the_queue(
        self, session: Session, state: str
    ) -> None:
        plan, task = _plan_with_task(session, state)

        assert _recover(session, plan.id) == 1

        session.refresh(task)
        assert task.state == "deferred"
        assert task.resolution == RESOLUTION_UNRESOLVED, (
            "it must be resumable: `satisfied` or `guided` would park it again permanently"
        )

    @pytest.mark.parametrize("state", ["applied", "deferred", "ready"])
    def test_a_task_that_is_not_mid_flight_is_left_alone(
        self, session: Session, state: str
    ) -> None:
        """Recovery must not touch settled work.

        `applied` is a finished migration and `deferred` may be a written remediation; moving
        either would undo the distinction the resolution field exists to draw.
        """
        plan, task = _plan_with_task(session, state)

        assert _recover(session, plan.id) == 0

        session.refresh(task)
        assert task.state == state

    def test_recovery_leaves_the_task_where_the_retry_selection_will_find_it(
        self, session: Session
    ) -> None:
        """The point of the whole fix: recovered work has to be picked up, not merely re-labelled.

        The handler resumes `deferred` + `unresolved` immediately after recovering, so this asserts
        the recovered task satisfies exactly that query.
        """
        plan, task = _plan_with_task(session, "generating")
        _recover(session, plan.id)

        retryable = session.scalars(
            select(MigrationTask)
            .where(MigrationTask.plan_id == plan.id)
            .where(MigrationTask.state == "deferred")
            .where(MigrationTask.resolution == RESOLUTION_UNRESOLVED)
        ).all()
        assert [t.id for t in retryable] == [task.id]

    def test_a_plan_of_only_interrupted_tasks_fully_settles(self, session: Session) -> None:
        """The failure this reproduces: nothing advances, so the plan never reaches a terminal
        state and any caller waiting for completion waits forever."""
        plan, first = _plan_with_task(session, "generating")
        second = MigrationTask(
            plan_id=plan.id, unit_id=first.unit_id, asset_id=first.asset_id,
            state="verifying", rule_id="py-weakcipher-01",
        )
        session.add(second)
        session.commit()

        assert _recover(session, plan.id) == 2

        states = {t.state for t in session.scalars(
            select(MigrationTask).where(MigrationTask.plan_id == plan.id)
        ).all()}
        assert states == {"deferred"}, states
