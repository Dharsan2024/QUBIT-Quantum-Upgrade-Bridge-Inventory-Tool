"""`repo_root` must actually govern where a patch is read from and written to.

`Path.__truediv__` is a documented no-op when the right operand is already absolute:
`repo_root / file_path` silently returns `file_path` unchanged, discarding `repo_root` entirely.
`asset.location.file_path` is always absolute -- the scanner records real filesystem paths -- so
this line never re-anchored anything; it only looked correct because `repo_root` and the asset's
own path had, until now, always agreed (both derived from the same scan).

They stop agreeing the moment a project's `root_path` changes without a fresh scan to refresh its
assets' paths -- reachable today via `PATCH /projects/{id}`, even with no dashboard control wired
to it yet. Traced fully, the old behaviour was worse than a no-op: `diff_path`'s `.relative_to()`
raised and was swallowed, so it fell back to the STALE absolute path; `apply_patch` re-anchored the
same no-op way; the read AND the write both silently happened at the OLD location, with `repo_root`
bypassed end to end and nothing to say so.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
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
    return subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True, check=True)


def _make_repo(root: Path) -> Path:
    repo = root / "repo"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text(VULN_SOURCE, encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")
    return repo


def _seed(session: Session, file_path: Path) -> None:
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
        location=Location(file_path=str(file_path), line=2),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=utcnow(),
        risk=RiskAnnotation(
            score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=1
        ),
    )
    session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
    session.commit()


def test_a_repo_root_that_does_not_contain_the_asset_raises_instead_of_silently_relocating(
    tmp_path: Path,
) -> None:
    """The exact scenario: the asset's path is where the ORIGINAL scan found it; `repo_root`
    points somewhere else entirely, as it would after `root_path` changed without a rescan.
    """
    original_repo = _make_repo(tmp_path / "original")
    unrelated_dir = tmp_path / "somewhere_else"
    unrelated_dir.mkdir()

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    _seed(session, original_repo / "app.py")

    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    task = orch.get_queue(plan.id)[0]

    with pytest.raises(ValueError, match="is not inside"):
        orch.generate_patch(task.id, repo_root=unrelated_dir)

    # Nothing was written anywhere -- neither the stale original location nor the wrong root.
    assert "md5" in (original_repo / "app.py").read_text(encoding="utf-8")
    assert list(unrelated_dir.iterdir()) == [], "the mismatched root must not have been touched"


def test_a_repo_root_that_is_a_parent_of_a_moved_copy_still_works(tmp_path: Path) -> None:
    """The check must not be so strict that a genuinely correct root_root is rejected.

    Not a real-world path (an asset's location always matches its OWN scan), but confirms the
    fix is a targeted containment check, not an accidental full-path equality requirement.
    """
    repo = _make_repo(tmp_path)

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    _seed(session, repo / "app.py")

    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    task = orch.get_queue(plan.id)[0]

    patch = orch.generate_patch(task.id, repo_root=repo)

    assert patch.status == "proposed", patch.validation_json
    assert patch.file_path == "app.py", "a matching root must still produce a repo-relative path"
