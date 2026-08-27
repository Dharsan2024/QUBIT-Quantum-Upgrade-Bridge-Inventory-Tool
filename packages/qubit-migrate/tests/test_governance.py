from uuid import uuid4

import pytest
from qubit_core.db import AssetRow, ProjectRow, ScanRow
from qubit_migrate.governance import check_governance, evaluate_gate
from qubit_migrate.state.models import (
    Base,
    MigrationPlan,
    MigrationTask,
    MigrationUnit,
    PatchProposal,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def _session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def _approved_patch(
    task_id, file_path: str, sha: str, *, approved_by: str | None = "reviewer"
) -> PatchProposal:
    return PatchProposal(
        id=uuid4(),
        task_id=task_id,
        status="approved",
        base_sha256=sha,
        file_path=file_path,
        diff_text="",
        validation_json={},
        approved_by=approved_by,
    )


def _setup_task(session: Session, sensitivity: str) -> MigrationTask:
    project = ProjectRow(id=uuid4(), name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(id=uuid4(), project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    asset = AssetRow(
        id=uuid4(),
        project_id=project.id,
        scan_id=scan.id,
        fingerprint="abc",
        source_scanner="code",
        asset_type="key",
        algorithm="RSA",
        sensitivity=sensitivity,
    )
    session.add(asset)
    plan = MigrationPlan(id=uuid4())
    session.add(plan)
    session.flush()
    unit = MigrationUnit(id=uuid4(), plan_id=plan.id)
    session.add(unit)
    session.flush()
    task = MigrationTask(
        id=uuid4(), plan_id=plan.id, unit_id=unit.id, asset_id=asset.id, state="pending"
    )
    session.add(task)
    session.commit()
    return task


def test_evaluate_gate_default_blocked():
    session = _session()
    task = _setup_task(session, "public")

    gate = evaluate_gate(task, session)
    assert gate["status"] == "blocked"
    assert gate["required"] == 1
    assert gate["current"] == 0

    with pytest.raises(ValueError, match="Governance gate blocked"):
        check_governance(task.id, session)


def test_evaluate_gate_default_passed():
    session = _session()
    task = _setup_task(session, "public")

    # Add an approved patch
    session.add(_approved_patch(task.id, "foo.py", "abc"))
    session.commit()

    gate = evaluate_gate(task, session)
    assert gate["status"] == "passed"
    assert gate["required"] == 1
    assert gate["current"] == 1

    # Should not raise
    check_governance(task.id, session)


def test_evaluate_gate_phi_blocked():
    session = _session()
    task = _setup_task(session, "phi")

    # Add one approved patch, but 2 are required for phi
    session.add(_approved_patch(task.id, "foo.py", "abc"))
    session.commit()

    gate = evaluate_gate(task, session)
    assert gate["status"] == "blocked"
    assert gate["required"] == 2
    assert gate["current"] == 1

    with pytest.raises(ValueError, match="Governance gate blocked"):
        check_governance(task.id, session)


def test_evaluate_gate_phi_passed():
    """2 required, satisfied by two DISTINCT approvers — the control the gate exists to provide."""
    session = _session()
    task = _setup_task(session, "phi")

    session.add(_approved_patch(task.id, "foo.py", "abc", approved_by="alice"))
    session.add(_approved_patch(task.id, "bar.py", "def", approved_by="bob"))
    session.commit()

    gate = evaluate_gate(task, session)
    assert gate["status"] == "passed"
    assert gate["required"] == 2
    assert gate["current"] == 2

    # Should not raise
    check_governance(task.id, session)


def test_evaluate_gate_phi_blocked_when_the_same_approver_approves_twice():
    """The loophole this whole mechanism exists to close.

    `review_patch` took an `actor` parameter and forwarded it only to the audit log, never to the
    patch itself — so `evaluate_gate` counted ROWS, and one person could satisfy a 2-approval gate
    alone: approve, defer, regenerate, approve again. Two "approved" `PatchProposal` rows, one
    real approver. This is the exact shape of that, reproduced directly rather than through the
    orchestrator: two patches, same `approved_by`, on a gate that requires two DISTINCT approvers.
    """
    session = _session()
    task = _setup_task(session, "phi")

    session.add(_approved_patch(task.id, "foo.py", "abc", approved_by="alice"))
    session.add(_approved_patch(task.id, "foo.py", "abc2", approved_by="alice"))
    session.commit()

    gate = evaluate_gate(task, session)
    assert gate["status"] == "blocked", (
        "one approver's second approval must not count as a second person's sign-off"
    )
    assert gate["required"] == 2
    assert gate["current"] == 1, "two rows from the same approver must count as ONE approver"

    with pytest.raises(ValueError, match="Governance gate blocked"):
        check_governance(task.id, session)


def test_evaluate_gate_ignores_approvals_with_no_recorded_approver():
    """`approved_by=None` (a row from before this column existed) must not count as a real
    approver of its own — an unknown approver is not evidence of a second distinct one, and
    counting it would make the fix a no-op for exactly the rows it exists to stop trusting.
    """
    session = _session()
    task = _setup_task(session, "phi")

    session.add(_approved_patch(task.id, "foo.py", "abc", approved_by="alice"))
    session.add(_approved_patch(task.id, "bar.py", "def", approved_by=None))
    session.commit()

    gate = evaluate_gate(task, session)
    assert gate["current"] == 1
    assert gate["status"] == "blocked"


def test_review_patch_records_the_real_approver_and_the_gate_sees_it():
    """The full pipeline, through the actual call a reviewer's click makes.

    `review_patch(patch_id, approve=True, actor=...)` is where an approval enters the system.
    Before this fix `actor` reached only the audit log (`MigrationEvent`); this proves it now
    lands on the patch itself, and that `evaluate_gate` reading it produces the right verdict at
    each step of a genuine multi-approver flow rather than just against hand-built rows.

    Between attempts the task is put back at `proposed` directly rather than driven through
    `defer` -> `resume` -> `generate` -> `validation_passed`. That real cycle is what produces a
    second `PatchProposal` for one task (see `governance.py`'s docstring), and the FSM's own
    correctness for it is covered elsewhere (`test_task_resolution.py`); this test's subject is
    governance counting, and re-deriving the whole cycle here would obscure that.
    """
    from qubit_migrate.orchestrator import MigrationOrchestrator

    session = _session()
    task = _setup_task(session, "phi")
    task.state = "proposed"
    session.commit()

    orch = MigrationOrchestrator(session)
    patch_one = PatchProposal(
        id=uuid4(),
        task_id=task.id,
        status="proposed",
        base_sha256="abc",
        file_path="foo.py",
        diff_text="",
        validation_json={},
    )
    session.add(patch_one)
    session.commit()

    reviewed = orch.review_patch(patch_one.id, approve=True, actor="alice")
    assert reviewed.approved_by == "alice"
    assert evaluate_gate(task, session)["status"] == "blocked", "one of two required so far"

    # A real second attempt for this task reaches `proposed` again via defer -> resume ->
    # generate -> validation_passed; reset directly here since that cycle is not this test's
    # subject (see docstring).
    task.state = "proposed"
    patch_two = PatchProposal(
        id=uuid4(),
        task_id=task.id,
        status="proposed",
        base_sha256="def",
        file_path="bar.py",
        diff_text="",
        validation_json={},
    )
    session.add(patch_two)
    session.commit()

    # The SAME actor approving a second patch for this task must not clear the gate alone.
    reviewed_two = orch.review_patch(patch_two.id, approve=True, actor="alice")
    assert reviewed_two.approved_by == "alice"
    assert evaluate_gate(task, session)["status"] == "blocked", (
        "the same actor approving twice must not satisfy a two-DISTINCT-approver gate"
    )

    task.state = "proposed"
    patch_three = PatchProposal(
        id=uuid4(),
        task_id=task.id,
        status="proposed",
        base_sha256="ghi",
        file_path="baz.py",
        diff_text="",
        validation_json={},
    )
    session.add(patch_three)
    session.commit()

    orch.review_patch(patch_three.id, approve=True, actor="bob")
    gate = evaluate_gate(task, session)
    assert gate["current"] == 2, "alice + bob = two distinct approvers"
    assert gate["status"] == "passed"
