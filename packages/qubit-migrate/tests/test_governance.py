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


def _approved_patch(task_id, file_path: str, sha: str) -> PatchProposal:
    return PatchProposal(
        id=uuid4(),
        task_id=task_id,
        status="approved",
        base_sha256=sha,
        file_path=file_path,
        diff_text="",
        validation_json={},
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
    session = _session()
    task = _setup_task(session, "phi")

    session.add(_approved_patch(task.id, "foo.py", "abc"))
    session.add(_approved_patch(task.id, "bar.py", "def"))
    session.commit()

    gate = evaluate_gate(task, session)
    assert gate["status"] == "passed"
    assert gate["required"] == 2
    assert gate["current"] == 2

    # Should not raise
    check_governance(task.id, session)
