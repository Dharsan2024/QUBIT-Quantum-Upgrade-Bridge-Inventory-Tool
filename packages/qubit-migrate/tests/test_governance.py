import pytest
from uuid import uuid4
from qubit_migrate.governance import evaluate_gate, check_governance
from qubit_migrate.state.models import MigrationTask, PatchProposal, Base, MigrationPlan, MigrationUnit
from qubit_core.db import AssetRow, ProjectRow, ScanRow
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

def _session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)

def _setup_task(session: Session, sensitivity: str) -> MigrationTask:
    project = ProjectRow(id=uuid4(), name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(id=uuid4(), project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    asset = AssetRow(id=uuid4(), project_id=project.id, scan_id=scan.id, fingerprint="abc", source_scanner="code", asset_type="key", algorithm="RSA", sensitivity=sensitivity)
    session.add(asset)
    plan = MigrationPlan(id=uuid4())
    session.add(plan)
    session.flush()
    unit = MigrationUnit(id=uuid4(), plan_id=plan.id)
    session.add(unit)
    session.flush()
    task = MigrationTask(id=uuid4(), plan_id=plan.id, unit_id=unit.id, asset_id=asset.id, state="pending")
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
    patch = PatchProposal(id=uuid4(), task_id=task.id, status="approved", base_sha256="abc", file_path="foo.py", diff_text="", validation_json={})
    session.add(patch)
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
    patch = PatchProposal(id=uuid4(), task_id=task.id, status="approved", base_sha256="abc", file_path="foo.py", diff_text="", validation_json={})
    session.add(patch)
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
    
    patch1 = PatchProposal(id=uuid4(), task_id=task.id, status="approved", base_sha256="abc", file_path="foo.py", diff_text="", validation_json={})
    patch2 = PatchProposal(id=uuid4(), task_id=task.id, status="approved", base_sha256="def", file_path="bar.py", diff_text="", validation_json={})
    session.add(patch1)
    session.add(patch2)
    session.commit()

    gate = evaluate_gate(task, session)
    assert gate["status"] == "passed"
    assert gate["required"] == 2
    assert gate["current"] == 2

    # Should not raise
    check_governance(task.id, session)
