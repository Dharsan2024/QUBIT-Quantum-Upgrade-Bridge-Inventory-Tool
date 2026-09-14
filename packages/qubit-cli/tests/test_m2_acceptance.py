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

# A weak hash the pipeline SHOULD migrate: a cache key, where nothing outside this file depends on
# which algorithm produced it.
#
# This fixture was `hashlib.sha1(pw.encode())` inside `store_password`, and this test asserted the
# pipeline rewrote it. The protocol-contract guard now refuses that, correctly — a stored password
# hash cannot be re-algorithmed in one line, because verification re-derives with whatever the code
# says now and every existing password stops matching. That failure was measured on `pyload`
# (`qubit-v2/08-evaluation/RESULTS-B0-arm.md`).
#
# So the end-to-end path is exercised on a finding that genuinely is the repository's to change, and
# the refusal is asserted separately. Splitting them keeps this test honest about which behaviour it
# is proving.
_VULN_SOURCE = (
    "import hashlib\n"
    "def cache_key(url):\n"
    "    # QUBIT-FIXTURE: weak hash used as a cache key\n"
    "    return hashlib.sha1(url.encode()).hexdigest()\n"
)

#: The other contract: a stored password hash must be ADVISED ON, never silently re-algorithmed.
_CONTRACT_SOURCE = (
    "import hashlib\n"
    "def store_password(user, pw):\n"
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
    (repo / "cache.py").write_text(_VULN_SOURCE, encoding="utf-8")
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
    assert "sha1" not in (repo / "cache.py").read_text(encoding="utf-8").lower()

    # --- 4. RE-SCAN proves remediation: SHA-1 is gone ---
    after = scan_paths([repo], repo="acc")
    assert "SHA-1" not in _vuln_algorithms(after.assets), after.assets
    assert len(_vuln_algorithms(after.assets)) < len(_vuln_algorithms(before.assets))


def test_a_stored_password_hash_is_advised_on_rather_than_rewritten(tmp_path: Path) -> None:
    """The other half of the contract, and the reason the fixture above changed.

    `hashlib.sha1(pw)` inside `store_password` is a real finding — SHA-1 is a real weakness and the
    operator must be told. What the pipeline must NOT do is swap the algorithm, because verification
    re-derives with whatever the code says now and every stored password stops matching. Measured on
    `pyload`, where seven such patches passed `applies`, `parses`, `symbols`, `compiles` and
    `rescan` and broke authentication against five services.

    So the assertion is not "nothing happens" — it is "advice happens, and a patch does not".
    """
    from qubit_migrate.orchestrator import GuidedRemediation, MigrationOrchestrator

    repo = tmp_path / "app"
    repo.mkdir()
    (repo / "accounts.py").write_text(_CONTRACT_SOURCE, encoding="utf-8")
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "baseline")

    found = scan_paths([repo], repo="contract")
    assert "SHA-1" in _vuln_algorithms(found.assets), found.assets
    annotated = RiskPipeline(load_config()).assess(found.assets)

    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        project = ProjectRow(name="contract", slug="contract")
        session.add(project)
        session.flush()
        scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
        session.add(scan)
        session.flush()
        for a in annotated:
            session.add(asset_to_row(a, scan_id=scan.id, project_id=project.id))
        session.commit()

        orch = MigrationOrchestrator(session)
        plan = orch.build_plan()
        tasks = orch.get_queue(plan.id, limit=10)
        assert tasks, "the weak hash must still be FOUND — refusing to patch is not refusing to see"

        refused = 0
        for task in tasks:
            try:
                orch.generate_patch(task.id, generator="template", repo_root=repo)
            except GuidedRemediation:
                refused += 1
        assert refused == len(tasks), "a stored password hash must not be silently re-algorithmed"

        session.refresh(tasks[0])
        advice = (tasks[0].advice_text or "").lower()
        assert advice, "a refusal with no advice is worse than a wrong patch"
        assert "negotiate" in advice or "accept the risk" in advice

    # And the source is untouched.
    assert "sha1" in (repo / "accounts.py").read_text(encoding="utf-8").lower()
