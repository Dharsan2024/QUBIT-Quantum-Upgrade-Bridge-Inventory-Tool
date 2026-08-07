"""M2 acceptance: the full software remediation loop, CI-proven without Docker/network/LLM.

Mirrors `qubit demo run`: real scanner -> real risk pipeline (all analytic tiers) -> real migration
orchestrator (template codemod) -> git apply -> RE-SCAN proves the vulnerable finding is gone.
This is the BUILD_PLAN M2 acceptance criterion for the software path, guarded so it can't regress.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from qubit_core.db import Base, ProjectRow, ScanRow
from qubit_core.mapping import asset_to_row
from qubit_risk import RiskPipeline, load_config
from qubit_scanner import scan_paths
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

# A deliberately vulnerable password hash (SHA-1) — the py-weakhash-01 rule remediates it to argon2.
_VULN_SOURCE = (
    "import hashlib\n"
    "def store_password(user, pw):\n"
    "    # QUBIT-FIXTURE: weak password hash\n"
    "    return hashlib.sha1(pw.encode()).hexdigest()\n"
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), capture_output=True, check=True)


def _vuln_algorithms(assets) -> set[str]:
    return {a.algorithm for a in assets if a.quantum_vulnerable.vulnerable}


def test_m2_acceptance_scan_risk_migrate_rescan(tmp_path: Path) -> None:
    from qubit_migrate.orchestrator import MigrationOrchestrator

    # --- repo with a real weak-crypto finding ---
    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "auth.py").write_text(_VULN_SOURCE, encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "baseline")

    # --- 1. SCAN: real finding present ---
    before = scan_paths([repo], repo="acc")
    assert "SHA-1" in _vuln_algorithms(before.assets), before.assets

    # --- 2. RISK: analytic tiers annotate (heuristic sensitivity, closed-form HNDL, Mosca) ---
    cfg = load_config()
    annotated = RiskPipeline(cfg).assess(before.assets)
    scored = [a for a in annotated if a.risk]
    assert scored, "risk pipeline produced no annotations"
    assert all(0.0 <= a.risk.score <= 1.0 for a in scored)

    # --- persist to the registry so the migrate orchestrator can read the assets ---
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    project = ProjectRow(name="acc", slug="acc")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    for a in annotated:
        session.add(asset_to_row(a, scan_id=scan.id, project_id=project.id))
    session.commit()

    # --- 3. MIGRATE: plan -> generate (template codemod) -> approve -> apply to the git repo ---
    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()
    assert plan.status == "active"
    task = next(t for t in orch.get_queue(plan.id) if t.rule_id == "py-weakhash-01")

    patch = orch.generate_patch(task.id, generator="template", repo_root=repo)
    assert patch.status == "proposed", patch.validation_json
    orch.review_patch(patch.id, approve=True, note="acceptance")
    applied = orch.apply_patch(patch.id, repo_root=repo)
    assert applied.status == "applied"

    # the file on disk really changed (no more sha1)
    assert "sha1" not in (repo / "auth.py").read_text(encoding="utf-8").lower()

    # --- 4. RE-SCAN proves remediation: SHA-1 is gone ---
    after = scan_paths([repo], repo="acc")
    assert "SHA-1" not in _vuln_algorithms(after.assets), after.assets
    assert len(_vuln_algorithms(after.assets)) < len(_vuln_algorithms(before.assets))
