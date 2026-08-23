""" "Nothing left to migrate" is not "could not migrate", and the plan has to say which.

Both outcomes park a task in `deferred`. They have to: the FSM's terminal states all mean "a patch
was applied and verified", and no patch exists in either case. But they are opposite facts about the
codebase, and sharing one state meant a plan reported finished work as broken.

Measured on the polyglot corpus, 6 of 18 apparent failures were of the second kind -- a third of
the reported failure rate. On a real repository it is worse: a plan over 266 tasks from one scan of
go-jose has many findings sharing a file, and the first patch routinely satisfies the rest.

These tests pin the classification at the four sites that produce it, because the failure mode is
silent: the tasks still park, the plan still completes, and the only symptom is a number that sends
someone to fix code that is already correct.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from qubit_core import CryptoAsset
from qubit_core.db import Base, ProjectRow, ScanRow
from qubit_core.schemas import (
    AssetType,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.orchestrator import (
    RESOLUTION_SATISFIED,
    RESOLUTION_UNRESOLVED,
    MigrationOrchestrator,
)
from qubit_migrate.state import MigrationPlan, MigrationTask, MigrationUnit
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def _session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def _task(session: Session) -> MigrationTask:
    project = ProjectRow(name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()

    from qubit_core.db import AssetRow
    from qubit_core.mapping import asset_to_row

    asset = CryptoAsset(
        id=uuid.uuid4(),
        algorithm="RSA-2048",
        usage_context=UsageContext.kex,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path="src/app.py", line=10),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        discovered_at=datetime.now(UTC),
        risk=RiskAnnotation(
            score=0.9, ci_low=0.9, ci_high=0.9, mosca_margin_years=-3.0, priority_rank=1
        ),
    )
    row: AssetRow = asset_to_row(asset, project_id=project.id, scan_id=scan.id)
    session.add(row)
    session.flush()

    plan = MigrationPlan(project_id=project.id, scan_id=scan.id)
    session.add(plan)
    session.flush()
    unit = MigrationUnit(plan_id=plan.id, label="src/app.py")
    session.add(unit)
    session.flush()
    # `ready`, not `pending`: `defer` is only legal once prerequisites are done, which is exactly
    # where the orchestrator parks tasks in real runs.
    task = MigrationTask(plan_id=plan.id, unit_id=unit.id, asset_id=row.id, state="ready")
    session.add(task)
    session.commit()
    return task


class TestResolutionIsRecorded:
    def test_a_task_nothing_could_be_done_for_is_unresolved(self) -> None:
        session = _session()
        task = _task(session)
        orchestrator = MigrationOrchestrator(session)

        orchestrator._fail_task(task, "no rule matched")
        session.commit()

        assert task.state == "deferred"
        assert task.resolution == RESOLUTION_UNRESOLVED
        assert task.last_error == "no rule matched"

    def test_an_already_handled_task_is_satisfied(self) -> None:
        session = _session()
        task = _task(session)
        orchestrator = MigrationOrchestrator(session)

        orchestrator._fail_task(
            task,
            "already remediated by an earlier task in this plan",
            resolution=RESOLUTION_SATISFIED,
        )
        session.commit()

        # Same FSM state as a genuine failure -- that is the point, and why the field is needed.
        assert task.state == "deferred"
        assert task.resolution == RESOLUTION_SATISFIED

    def test_unresolved_is_the_default(self) -> None:
        """A caller that says nothing must not accidentally claim the work is finished.

        The four satisfied sites are named explicitly; anything else is a failure until someone
        shows otherwise, because the direction of a wrong default matters. Reporting real breakage
        as "already compliant" hides work; the reverse merely adds noise.
        """
        session = _session()
        task = _task(session)
        MigrationOrchestrator(session)._fail_task(task, "something went wrong")
        session.commit()
        assert task.resolution == RESOLUTION_UNRESOLVED

    def test_a_second_failure_keeps_the_newest_resolution(self) -> None:
        """Parking is idempotent -- one file with two findings hits this in ordinary use.

        The second call must be able to CORRECT the first: a task deferred as unresolved and then
        found to have been satisfied by an earlier patch is satisfied, and the stale verdict would
        keep it in the failure column.
        """
        session = _session()
        task = _task(session)
        orchestrator = MigrationOrchestrator(session)

        orchestrator._fail_task(task, "first attempt failed")
        orchestrator._fail_task(
            task, "already remediated by an earlier task", resolution=RESOLUTION_SATISFIED
        )
        session.commit()

        assert task.state == "deferred"
        assert task.resolution == RESOLUTION_SATISFIED
        assert task.last_error == "already remediated by an earlier task"

    def test_a_task_that_never_parked_has_no_resolution(self) -> None:
        """NULL means "not parked", which is also what every pre-migration row says."""
        session = _session()
        task = _task(session)
        assert task.resolution is None


class TestTheFailureSurvivesTheRequest:
    """The bug that made every field above invisible in the running app.

    Nothing on the failure path committed. `_transition` mutates and writes an event, the API turns
    the raised ValueError into a 422, and `get_session` closes the session in a `finally` with no
    commit -- so the deferral, `last_error` and `resolution` were discarded when the request ended.

    Observed against the running desktop app: a task whose asset matched no rule returned 422 and
    came back from the queue still `ready`, `last_error` null, ready to fail identically forever.
    The unit tests above passed throughout, because they call `session.commit()` themselves.
    """

    def test_parking_is_committed_without_the_caller_committing(self) -> None:
        session = _session()
        task = _task(session)
        task_id = task.id

        # Deliberately no session.commit() here -- that is the whole point.
        MigrationOrchestrator(session)._fail_task(task, "no rule matched")

        # A rollback stands in for the request ending: anything uncommitted is gone.
        session.rollback()
        session.expire_all()

        reloaded = session.get(MigrationTask, task_id)
        assert reloaded is not None
        assert reloaded.state == "deferred", "the deferral did not survive the request"
        assert reloaded.last_error == "no rule matched"
        assert reloaded.resolution == RESOLUTION_UNRESOLVED

    def test_a_satisfied_parking_also_survives(self) -> None:
        session = _session()
        task = _task(session)
        task_id = task.id

        MigrationOrchestrator(session)._fail_task(
            task, "already remediated by an earlier task", resolution=RESOLUTION_SATISFIED
        )
        session.rollback()
        session.expire_all()

        reloaded = session.get(MigrationTask, task_id)
        assert reloaded is not None
        assert reloaded.resolution == RESOLUTION_SATISFIED
