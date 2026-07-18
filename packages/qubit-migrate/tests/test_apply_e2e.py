"""End-to-end apply proof (doc 03 §6.4): generate -> approve -> apply to a real git repo.

The applied file must actually change on disk, be committed on the requested branch,
and verify_task must then pass.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from qubit_core.db import Base, ProjectRow, ScanRow
from qubit_core.mapping import asset_to_row
from qubit_core.schemas import (
    AssetType,
    CryptoAsset,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_migrate.orchestrator import MigrationOrchestrator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

VULN_SOURCE = "import hashlib\ndigest = hashlib.md5(data)\n"


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args], cwd=str(repo), capture_output=True, text=True, check=True
    )


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(VULN_SOURCE, encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")
    return repo


def _seed(session: Session, repo: Path) -> None:
    project = ProjectRow(name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    asset = CryptoAsset(
        algorithm="MD5",
        usage_context=UsageContext.hash,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=str(repo / "app.py"), line=2),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=utcnow(),
        risk=RiskAnnotation(
            score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=1
        ),
    )
    session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
    session.commit()


def test_generate_approve_apply_verify(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    _seed(session, repo)

    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    assert plan.status == "active"
    task = orch.get_queue(plan.id)[0]
    assert task.rule_id == "py-weakhash-01"

    patch = orch.generate_patch(task.id, repo_root=repo)
    assert patch.status == "proposed", patch.validation_json

    orch.review_patch(patch.id, approve=True, note="e2e")

    applied = orch.apply_patch(patch.id, repo_root=repo, branch="pqc-migration")
    assert applied.status == "applied"
    assert applied.applied_branch == "pqc-migration"
    assert applied.applied_commit

    # The file on disk really changed
    new_source = (repo / "app.py").read_text(encoding="utf-8")
    assert "md5" not in new_source
    assert "sha256" in new_source or "argon2" in new_source

    # ... and was committed on the branch
    head_msg = _git(repo, "log", "-1", "--format=%s").stdout
    assert "QUBIT: migrate" in head_msg

    # verify closes the loop
    report = orch.verify_task(task.id)
    assert report is not None and report.passed
