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
    return subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True, check=True)


def _make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
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


def test_generate_approve_apply_verify_when_the_file_is_crlf(tmp_path: Path) -> None:
    """OpenSSL's `apps/passwd.c` is CRLF as OpenSSL itself committed it (confirmed via
    ``git show HEAD:apps/passwd.c``, independent of any local checkout config) — this is not a
    Windows/autocrlf artifact, so a repo whose tracked file is genuinely CRLF must patch cleanly
    on any platform. Before the fix, `old_new_to_diff` always built an LF diff (every reader in
    this codebase normalizes on read), which `git apply --check` correctly rejected against the
    real CRLF bytes — the patch's status became "failed" and the task parked, unwritable, forever.
    """
    repo = tmp_path / "repo_crlf"
    repo.mkdir(parents=True)
    (repo / "app.py").write_text(VULN_SOURCE.replace("\n", "\r\n"), encoding="utf-8", newline="")
    _git(repo, "init")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    # Isolated from checkout conversion on purpose: the CRLF here is the file's OWN committed
    # content, exactly like OpenSSL's, not something a local `core.autocrlf=true` introduced.
    _git(repo, "config", "core.autocrlf", "false")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "init")

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    _seed(session, repo)

    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    task = orch.get_queue(plan.id)[0]
    assert task.rule_id == "py-weakhash-01"

    patch = orch.generate_patch(task.id, repo_root=repo)
    assert patch.status == "proposed", patch.validation_json
    assert "\r\n" in patch.diff_text  # the diff matches the file's real on-disk bytes

    orch.review_patch(patch.id, approve=True, note="crlf e2e")
    applied = orch.apply_patch(patch.id, repo_root=repo, branch="pqc-migration")
    assert applied.status == "applied"

    new_bytes = (repo / "app.py").read_bytes()
    assert b"\r\n" in new_bytes  # still CRLF — the fix doesn't rewrite the file's convention
    assert b"md5" not in new_bytes.lower()


def _seed_named(session: Session, repo: Path, name: str):
    """A second project whose vulnerable file has the SAME repo-relative path as the first."""
    project = ProjectRow(name=name, slug=name)
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
    return project.id


def test_migrating_one_project_does_not_block_another_with_the_same_relative_path(
    tmp_path: Path,
) -> None:
    """`app.py` is `app.py` in every checkout that has one.

    The "an earlier patch already rewrote this file" guard matched on the repo-RELATIVE path with
    no plan scoping, so applying a patch to one project's `app.py` made every other project's
    `app.py` unmigratable — it reported "already migrated by an earlier py-weakhash-01 patch" and
    refused. Measured on two independent clones of `requests`: the second project could not
    migrate a single one of its weak-hash findings.
    """
    first = _make_repo(tmp_path / "one")
    second = _make_repo(tmp_path / "two")
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)

    _seed(session, first)
    orch = MigrationOrchestrator(session)
    plan_one = orch.build_plan()
    task_one = orch.get_queue(plan_one.id)[0]
    patch_one = orch.generate_patch(task_one.id, repo_root=first)
    orch.review_patch(patch_one.id, approve=True)
    assert orch.apply_patch(patch_one.id, repo_root=first).status == "applied"

    # A DIFFERENT project, its own plan, its own checkout — same relative filename.
    second_project = _seed_named(session, second, "second")
    plan_two = orch.build_plan(project_id=second_project)
    task_two = orch.get_queue(plan_two.id)[0]

    patch_two = orch.generate_patch(task_two.id, repo_root=second)
    assert patch_two.status == "proposed", patch_two.validation_json
    orch.review_patch(patch_two.id, approve=True)
    assert orch.apply_patch(patch_two.id, repo_root=second).status == "applied"
    assert "md5" not in (second / "app.py").read_text(encoding="utf-8")


def test_apply_ignores_dirty_state_outside_repo_root(tmp_path: Path) -> None:
    """A dirty file OUTSIDE `repo_root` must not block applying a patch INSIDE it.

    `git status --porcelain` reports the whole repository it is run in, not the directory it is run
    from. So whenever `repo_root` is a SUBDIRECTORY of a larger working tree — any scan target that
    is not its own repo: a copied folder, an extracted archive, a subproject — unrelated edits
    elsewhere in that outer tree were reported as this migration's own dirty state and every apply
    was refused.

    Measured: migrating a plain copy of the 21-app demo corpus that happened to sit inside this
    monorepo's working tree failed 246 of 250 real findings with "Dirty git tree", entirely because
    of edits in the monorepo that `repo_root` had nothing to do with. The fix is the `-- .`
    pathspec; this test is what keeps it.
    """
    outer = tmp_path / "outer"
    (outer / "sub").mkdir(parents=True)
    _git(outer, "init")
    _git(outer, "config", "user.email", "test@example.com")
    _git(outer, "config", "user.name", "Test")

    repo_root = outer / "sub"
    (repo_root / "app.py").write_text(VULN_SOURCE, encoding="utf-8")
    (outer / "unrelated.txt").write_text("committed\n", encoding="utf-8")
    _git(outer, "add", ".")
    _git(outer, "commit", "-m", "init")

    # Dirty the OUTER tree only. `repo_root` itself stays clean.
    (outer / "unrelated.txt").write_text("edited after the commit\n", encoding="utf-8")

    # Precondition: unscoped status sees the outer edit, scoped status does not. If this ever
    # stops holding, the guard is no longer testing what it claims to.
    assert _git(repo_root, "status", "--porcelain").stdout.strip(), "expected outer tree dirty"
    assert not _git(repo_root, "status", "--porcelain", "--", ".").stdout.strip()

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    _seed(session, repo_root)

    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    task = orch.get_queue(plan.id)[0]
    patch = orch.generate_patch(task.id, repo_root=repo_root)
    assert patch.status == "proposed", patch.validation_json
    orch.review_patch(patch.id, approve=True)

    applied = orch.apply_patch(patch.id, repo_root=repo_root)
    assert applied.status == "applied"
    assert "md5" not in (repo_root / "app.py").read_text(encoding="utf-8")
