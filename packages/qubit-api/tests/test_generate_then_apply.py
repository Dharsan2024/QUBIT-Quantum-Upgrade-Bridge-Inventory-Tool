"""The two halves of a bulk migration: prepare the changes, then write them.

"Build plan" generates a patch for every vulnerable finding and stops. "Initiate migration" writes
those prepared patches into the original files. They are separate acts on purpose — the slow,
uncertain half finishes before anyone is asked to approve anything, and the irreversible half runs
only on diffs that have been sitting in the queue to be read.

What is pinned here is that neither half quietly does the other's job: generating must not touch
the working tree, and writing must not spend model time on findings nobody generated for.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from qubit_api.jobs.handlers import migrate_handler
from qubit_core.db import Base, ProjectRow, ScanRow, session_factory
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
from qubit_migrate.state import MigrationTask, PatchProposal
from sqlalchemy import create_engine, select

VULN_SOURCE = "import hashlib\ndigest = hashlib.md5(data)\n"
FILES = ("alpha.py", "beta.py")


def _reporter(sf: Any) -> MagicMock:
    r = MagicMock()
    r.sf = sf
    r.update = MagicMock()
    r.checkpoint = MagicMock()
    return r


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), capture_output=True, check=True)


@pytest.fixture
def plan(tmp_path: Path) -> tuple[Any, Path, Any]:
    """A two-finding plan over a real git repo, with the project's root path set."""
    repo = tmp_path / "repo"
    repo.mkdir()
    for name in FILES:
        (repo / name).write_text(VULN_SOURCE, encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")

    engine = create_engine(f"sqlite:///{(tmp_path / 't.db').as_posix()}")
    Base.metadata.create_all(engine)
    sf = session_factory(engine)
    with sf() as s:
        project = ProjectRow(name="t", slug="t", root_path=str(repo))
        s.add(project)
        s.flush()
        scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
        s.add(scan)
        s.flush()
        for rank, name in enumerate(FILES, start=1):
            asset = CryptoAsset(
                algorithm="MD5",
                usage_context=UsageContext.hash,
                source_scanner=SourceScanner.code,
                asset_type=AssetType.algorithm_use,
                location=Location(file_path=str(repo / name), line=2),
                quantum_vulnerable=QuantumVulnerability(
                    vulnerable=True, attack=QuantumAttack.grover
                ),
                discovered_at=utcnow(),
                risk=RiskAnnotation(
                    score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=rank
                ),
            )
            s.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
        s.commit()
        # Scoped to the project, so `_plan_repo_root` can find the root path a write needs.
        built = MigrationOrchestrator(s).build_plan(project_id=project.id, scan_id=scan.id)
        assert len(MigrationOrchestrator(s).get_queue(built.id)) == 2
        plan_id = built.id
    return plan_id, repo, sf


def _still_vulnerable(repo: Path) -> list[str]:
    return [n for n in FILES if "md5" in (repo / n).read_text(encoding="utf-8")]


def test_generating_prepares_every_patch_and_writes_nothing(plan: tuple[Any, Path, Any]) -> None:
    """The "Build plan" half. Two diffs ready to read, two files untouched."""
    plan_id, repo, sf = plan

    result = migrate_handler(
        {"plan_id": str(plan_id), "generate": True, "apply": False}, _reporter(sf)
    )

    assert result["mode"] == "generate", result
    assert result["generated"] == 2, result
    assert result["applied"] == 0, result
    assert result["failed"] == 0, result
    assert sorted(_still_vulnerable(repo)) == sorted(FILES), (
        "preparing changes must not modify the working tree"
    )

    # Left PROPOSED, not approved: the queue's Approve/Reject buttons only exist in that state, and
    # they are the reason for generating ahead of applying at all.
    with sf() as s:
        statuses = list(
            s.scalars(
                select(PatchProposal.status)
                .join(MigrationTask, PatchProposal.task_id == MigrationTask.id)
                .where(MigrationTask.plan_id == plan_id)
            ).all()
        )
    assert statuses == ["proposed", "proposed"], statuses


def test_writing_applies_what_was_prepared_without_regenerating(
    plan: tuple[Any, Path, Any],
) -> None:
    """The "Initiate migration" half, run over the output of the first."""
    plan_id, repo, sf = plan
    migrate_handler({"plan_id": str(plan_id), "generate": True, "apply": False}, _reporter(sf))

    result = migrate_handler(
        {"plan_id": str(plan_id), "generate": False, "apply": True}, _reporter(sf)
    )

    assert result["mode"] == "apply", result
    assert result["applied"] == 2, result
    assert result["generated"] == 0, "writing must not call a generator"
    assert result["failed"] == 0, result
    assert result["no_patch"] == 0, result
    assert _still_vulnerable(repo) == [], "both files should have been migrated on disk"


def test_writing_reports_findings_nobody_prepared_instead_of_generating_them(
    plan: tuple[Any, Path, Any],
) -> None:
    """A finding with no patch is named, not silently generated.

    "Write the changes" is not a licence to spend model time the operator did not ask for. The
    honest answer is to write what exists and say how much was left — the app turns `no_patch`
    into a prompt to build the plan again.
    """
    plan_id, repo, sf = plan
    with sf() as s:
        first = MigrationOrchestrator(s).get_queue(plan_id)[0]
        patch = MigrationOrchestrator(s).generate_patch(first.id, repo_root=repo)
        assert patch.status == "proposed", patch.validation_json

    result = migrate_handler(
        {"plan_id": str(plan_id), "generate": False, "apply": True}, _reporter(sf)
    )

    assert result["applied"] == 1, result
    assert result["no_patch"] == 1, result
    assert len(_still_vulnerable(repo)) == 1, "only the prepared finding should have been written"


def test_asking_for_both_halves_at_once_is_unchanged(plan: tuple[Any, Path, Any]) -> None:
    """The default is still the single-shot run every existing caller relies on."""
    plan_id, repo, sf = plan

    result = migrate_handler({"plan_id": str(plan_id)}, _reporter(sf))

    assert result["mode"] == "full", result
    assert result["generated"] == 2, result
    assert result["applied"] == 2, result
    assert _still_vulnerable(repo) == []
