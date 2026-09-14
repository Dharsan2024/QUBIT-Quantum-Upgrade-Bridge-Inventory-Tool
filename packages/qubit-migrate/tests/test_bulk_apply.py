"""Applying several patches from one plan into a real git repository.

The dirty-tree guard in `apply_patch` protects a migration from being written on top of edits QUBIT
has not seen. Taken literally it also refused QUBIT's OWN edits: the first patch lands, the tree is
now dirty by QUBIT's hand, and every later patch in the same run is refused with "commit or stash
changes before applying".

That made the app's "Initiate migration" — which writes a whole plan's worth of prepared patches —
impossible against any real repository. It went unnoticed because the demo corpus is not a git
repository, where both git guards are inert.
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
FILES = ("alpha.py", "beta.py", "gamma.py")


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True, check=True)


def _repo_with_three_findings(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    for name in FILES:
        (repo / name).write_text(VULN_SOURCE, encoding="utf-8")
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
    for rank, name in enumerate(FILES, start=1):
        asset = CryptoAsset(
            algorithm="MD5",
            usage_context=UsageContext.hash,
            source_scanner=SourceScanner.code,
            asset_type=AssetType.algorithm_use,
            location=Location(file_path=str(repo / name), line=2),
            quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
            discovered_at=utcnow(),
            risk=RiskAnnotation(
                score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=rank
            ),
        )
        session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
    session.commit()


@pytest.fixture
def session_and_repo(tmp_path: Path) -> tuple[Session, Path]:
    repo = _repo_with_three_findings(tmp_path)
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    _seed(session, repo)
    return session, repo


def test_every_patch_in_a_plan_can_be_written_to_one_git_repo(
    session_and_repo: tuple[Session, Path],
) -> None:
    """Three findings, three files, one plan — all three must reach disk.

    Before the guard learned to recognise QUBIT's own writes this stopped after the first file:
    two of the three failed with "Dirty git tree", and the operator was told to stash the very
    change QUBIT had just made.
    """
    session, repo = session_and_repo
    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    tasks = orch.get_queue(plan.id)
    assert len(tasks) == 3, "the fixture must produce one task per file"

    # Prepare everything FIRST, writing nothing — the "Build plan" half.
    patches = []
    for task in tasks:
        patch = orch.generate_patch(task.id, repo_root=repo)
        assert patch.status == "proposed", patch.validation_json
        patches.append(patch)
    assert all("md5" in (repo / name).read_text(encoding="utf-8") for name in FILES), (
        "generating must not touch the working tree"
    )

    # Then write them — the "Initiate migration" half.
    for patch in patches:
        orch.review_patch(patch.id, approve=True)
        assert orch.apply_patch(patch.id, repo_root=repo).status == "applied"

    for name in FILES:
        body = (repo / name).read_text(encoding="utf-8")
        assert "md5" not in body, f"{name} was not migrated: {body}"
        assert "sha256" in body.lower(), f"{name} lost its hash entirely: {body}"


def test_an_edit_to_the_file_being_written_still_stops_the_write(
    session_and_repo: tuple[Session, Path],
) -> None:
    """The protection that matters: nobody's work is overwritten by a patch that never saw it.

    A patch is written against the file as it stood when the model read it. If that file changes
    afterwards — the operator edits it, another tool rewrites it, an earlier patch in the same run
    lands on it — the diff describes a file that no longer exists, and applying it would either
    fail confusingly or silently discard the newer content.

    Two guards cover this, and the message matters as much as the refusal. The porcelain check gets
    there first and NAMES the file, which is what the operator needs — the old wide guard said only
    "Dirty git tree" over a repository full of files and left them to guess which one it meant.
    """
    session, repo = session_and_repo
    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    tasks = orch.get_queue(plan.id)

    first = orch.generate_patch(tasks[0].id, repo_root=repo)
    second = orch.generate_patch(tasks[1].id, repo_root=repo)
    orch.review_patch(first.id, approve=True)
    orch.review_patch(second.id, approve=True)
    orch.apply_patch(first.id, repo_root=repo)

    # Somebody else edits the very file the second patch is about to write.
    target = repo / second.file_path
    target.write_text(target.read_text(encoding="utf-8") + "# edited by hand\n", encoding="utf-8")

    with pytest.raises(ValueError, match="uncommitted edits QUBIT did not make"):
        orch.apply_patch(second.id, repo_root=repo)
    assert "edited by hand" in target.read_text(encoding="utf-8"), "the hand edit was clobbered"


def test_a_committed_change_to_the_target_supersedes_the_patch(
    session_and_repo: tuple[Session, Path],
) -> None:
    """The backstop the porcelain check cannot provide: a change that leaves the tree CLEAN.

    Commit an edit to the file between generating a patch and writing it, and nothing about the
    working tree looks wrong — git reports it clean, so a porcelain guard sees nothing to object
    to. The patch is still stale: it was written against content that is no longer there.

    Caught on the file's sha256, recorded at generation time, and the patch is marked `superseded`
    rather than failed — the finding is real, the diff is simply out of date, and the task goes back
    to the queue so the next run regenerates it against the file as it now stands.
    """
    session, repo = session_and_repo
    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    tasks = orch.get_queue(plan.id)

    patch = orch.generate_patch(tasks[0].id, repo_root=repo)
    orch.review_patch(patch.id, approve=True)

    target = repo / patch.file_path
    target.write_text(
        target.read_text(encoding="utf-8") + "# committed elsewhere\n", encoding="utf-8"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "someone else's change")

    with pytest.raises(ValueError, match="changed since generation"):
        orch.apply_patch(patch.id, repo_root=repo)
    assert patch.status == "superseded"


def test_unrelated_work_in_progress_does_not_refuse_a_migration(
    session_and_repo: tuple[Session, Path],
) -> None:
    """A dirty file no patch will touch is not this migration's business. Deliberate, and measured.

    The guard used to refuse on ANY uncommitted change under the repository root, which made QUBIT
    unusable against a repository in its normal state: one unrelated edit refused every patch in
    the run with "Dirty git tree", naming no file and giving no reason the operator could act on.
    Measured on this installation — one patch written, twenty refused, all twenty for edits in
    files no patch would have touched.

    Nothing is given up. The file each patch WRITES is protected by its recorded hash (the test
    above), and a file a patch CREATES that already exists dirty is still refused here, because
    `git apply` would overwrite content the hash guard never saw.
    """
    session, repo = session_and_repo
    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    tasks = orch.get_queue(plan.id)

    patch = orch.generate_patch(tasks[0].id, repo_root=repo)
    orch.review_patch(patch.id, approve=True)

    (repo / "notes.txt").write_text("half-written note\n", encoding="utf-8")
    # Derived from the PATCH, not assumed to be `FILES[2]`. Indexing a fixed file made this test
    # depend on the queue landing a particular task first, so it failed whenever the ranking put
    # that same file at the head — which is what the old random tie-break produced. The property
    # under test is "a file this patch will not touch", so the test now says that outright instead
    # of hoping for it. See `test_queue_determinism.py`.
    untouched = next(f for f in FILES if f != Path(patch.file_path).name)
    other = repo / untouched
    other.write_text(other.read_text(encoding="utf-8") + "# my own edit\n", encoding="utf-8")

    assert orch.apply_patch(patch.id, repo_root=repo).status == "applied"
    assert "my own edit" in other.read_text(encoding="utf-8"), "the operator's edit was clobbered"


def test_a_committed_qubit_write_is_not_dirt_either(
    session_and_repo: tuple[Session, Path],
) -> None:
    """Committing between patches is the tidy workflow and must keep working."""
    session, repo = session_and_repo
    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    tasks = orch.get_queue(plan.id)

    first = orch.generate_patch(tasks[0].id, repo_root=repo)
    second = orch.generate_patch(tasks[1].id, repo_root=repo)
    orch.review_patch(first.id, approve=True)
    orch.review_patch(second.id, approve=True)
    orch.apply_patch(first.id, repo_root=repo)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "qubit: migrate alpha")

    assert orch.apply_patch(second.id, repo_root=repo).status == "applied"
