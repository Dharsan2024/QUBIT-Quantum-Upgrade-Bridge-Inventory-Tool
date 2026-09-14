"""How a bulk migration reports its own outcome.

The counts in the completion banner are the only summary most operators will read, so a category
that is wrong there is worse than a bug in a rarely-used path: it changes what people believe the
tool did. This pins the distinction that was measurably wrong — a finding with no rule is not a
failed migration.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from qubit_api.jobs.handlers import migrate_handler
from qubit_core.db import Base, ProjectRow, ScanRow, session_factory
from qubit_core.mapping import asset_to_row
from qubit_core.schemas import (
    AssetType,
    CryptoAsset,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_migrate.orchestrator import MigrationOrchestrator
from sqlalchemy import create_engine, select


def _reporter(sf):
    r = MagicMock()
    r.sf = sf
    r.update = MagicMock()
    r.checkpoint = MagicMock()
    return r


def _asset(
    path: str,
    algorithm: str,
    usage: UsageContext,
    *,
    line: int = 2,
    snippet: str = "",
) -> CryptoAsset:
    return CryptoAsset(
        algorithm=algorithm,
        usage_context=usage,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=path, line=line),
        # The +/-2 line window the scanner records. Empty for most findings here; the ownership
        # test needs it because that is the evidence `external_contract` reads.
        evidence=Evidence(snippet=snippet),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        discovered_at=utcnow(),
        risk=RiskAnnotation(
            score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=1
        ),
    )


def test_a_finding_with_no_rule_is_guided_not_failed(tmp_path: Path) -> None:
    """A no-rule finding must be counted as needing guidance, never as a failed migration.

    Measured on the 21-app demo corpus before this fix: the run reported "94 could not be
    migrated", of which 75 were findings that never had a rule to attempt. Each of those already
    offers a guidance button in the queue, so the app was describing its own designed behaviour as
    94 failures — understating the result and alarming the operator. They are also skipped rather
    than sent to `generate_patch` purely to raise.
    """
    db = tmp_path / "t.db"
    engine = create_engine(f"sqlite:///{db.as_posix()}")
    Base.metadata.create_all(engine)
    sf = session_factory(engine)

    with sf() as s:
        project = ProjectRow(name="t", slug="t")
        s.add(project)
        s.flush()
        scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
        s.add(scan)
        s.flush()
        # `.txt` matches no migration rule in the catalog, so this task gets rule_id = None.
        src = tmp_path / "notes.txt"
        src.write_text("rsa stuff\n", encoding="utf-8")
        s.add(
            asset_to_row(
                _asset(str(src), "RSA", UsageContext.kex),
                scan_id=scan.id,
                project_id=project.id,
            )
        )
        s.commit()

        orch = MigrationOrchestrator(s)
        plan = orch.build_plan()
        queue = orch.get_queue(plan.id)
        assert queue and queue[0].rule_id is None, "fixture must produce a rule-less task"
        plan_id = plan.id

    result = migrate_handler({"plan_id": str(plan_id), "apply": False}, _reporter(sf))

    assert result["needs_guidance"] == 1, result
    assert result["failed"] == 0, "a finding with no rule is not a failed migration"
    assert result["generated"] == 0


def test_a_reviewer_rejected_patch_is_regenerated_on_the_next_plan_run(tmp_path: Path) -> None:
    """Plan-level retries must agree with the task-row Regenerate action.

    The state machine has always allowed ``rejected -> ready``.  The API preflight was taught to
    dispatch that work, but the worker still selected only ready/deferred tasks, turning a 202 job
    into a successful no-op.  Exercise the real handler so the selection and transition cannot
    drift apart again.
    """
    db = tmp_path / "t.db"
    engine = create_engine(f"sqlite:///{db.as_posix()}")
    Base.metadata.create_all(engine)
    sf = session_factory(engine)
    src = tmp_path / "app.py"
    src.write_text("import hashlib\ndigest = hashlib.md5(data)\n", encoding="utf-8")

    with sf() as s:
        project = ProjectRow(name="t", slug="t", root_path=str(tmp_path))
        s.add(project)
        s.flush()
        scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
        s.add(scan)
        s.flush()
        s.add(
            asset_to_row(
                _asset(str(src), "MD5", UsageContext.hash, line=2),
                scan_id=scan.id,
                project_id=project.id,
            )
        )
        s.commit()
        orch = MigrationOrchestrator(s)
        plan = orch.build_plan()
        task = orch.get_queue(plan.id)[0]
        task.state = "rejected"
        s.commit()
        plan_id = plan.id

    result = migrate_handler(
        {"plan_id": str(plan_id), "apply": False, "generator": "template"}, _reporter(sf)
    )

    assert result["total"] == 1, result
    assert result["generated"] == 1, result
    assert result["failed"] == 0, result


#: An MD5 whose digest is the KEY a remote service looks an avatar up by. Gravatar's URL scheme is
#: `/avatar/<md5 of the lowercased email>`; migrating the hash produces a patch that applies,
#: parses, resolves its symbols, compiles, and rescans clean — while every avatar on the site
#: silently 404s. The gates provably cannot catch it, because `rescan` passes precisely BECAUSE the
#: algorithm changed.
GRAVATAR_PY = (
    "import hashlib\n"
    "\n"
    "\n"
    "def avatar_url(email: str) -> str:\n"
    "    digest = hashlib.md5(email.strip().lower().encode()).hexdigest()\n"
    '    return f"https://www.gravatar.com/avatar/{digest}?d=identicon"\n'
)


def test_an_algorithm_a_remote_party_owns_is_refused_not_failed(tmp_path: Path) -> None:
    """A refusal is a decision QUBIT made, and the run must report it as one.

    Measured on medivault-emr: a run of 24 findings reported "0 ready, 5 guided, 18 failed". Six of
    those 18 were refusals on exactly these grounds — a Gravatar URL keyed by MD5, a webhook field
    the remote names `sha1=`, an already-established KDF — and one more was a file an earlier patch
    had already fixed. The tool had been right about all seven and said so nowhere.

    End to end through `external_contract` rather than by raising the exception directly, because
    the thing that can silently break is the wiring between the two: the contract check reaching a
    verdict and the tally still filing it under the wrong heading is the exact bug this pins.
    """
    db = tmp_path / "t.db"
    engine = create_engine(f"sqlite:///{db.as_posix()}")
    Base.metadata.create_all(engine)
    sf = session_factory(engine)

    src = tmp_path / "avatars.py"
    src.write_text(GRAVATAR_PY, encoding="utf-8")

    with sf() as s:
        project = ProjectRow(name="t", slug="t", root_path=str(tmp_path))
        s.add(project)
        s.flush()
        scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
        s.add(scan)
        s.flush()
        s.add(
            asset_to_row(
                _asset(
                    str(src),
                    "MD5",
                    UsageContext.hash,
                    line=5,
                    snippet="\n".join(GRAVATAR_PY.splitlines()[2:6]),
                ),
                scan_id=scan.id,
                project_id=project.id,
            )
        )
        s.commit()
        plan_id = MigrationOrchestrator(s).build_plan().id

    result = migrate_handler({"plan_id": str(plan_id), "apply": False}, _reporter(sf))

    assert result["refused"] == 1, result
    assert result["failed"] == 0, "declining to break a remote party's format is not a failure"
    assert result["rejected"] == 0, result
    assert result["needs_guidance"] == 0, (
        "a contract refusal is a verdict about the finding, not an absence of any patch to offer"
    )

    with sf() as s:
        from qubit_migrate.state import MigrationTask

        task = next(iter(s.scalars(select(MigrationTask)).all()))
        assert "fixed by a party outside this repository" in (task.advice_text or ""), (
            "the operator must be told WHY no edit was made, not just that none was"
        )


def test_plan_out_carries_the_regime() -> None:
    """A plan's targets are unexplainable without the regime that chose them.

    `ML-KEM-1024` and `X25519MLKEM768` are each required by one regulator and rejected by another,
    so a reviewer reading a stored plan cannot tell a deliberate choice from a mistake unless the
    response says which one it was answering.
    """
    import uuid

    from qubit_api.routers.migrate import _plan_out
    from qubit_core import utcnow
    from qubit_migrate.state.models import MigrationPlan

    plan = MigrationPlan(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        status="active",
        created_at=utcnow(),
        regime="cnsa-2.0",
    )
    assert _plan_out(plan).regime == "cnsa-2.0"


def test_plan_out_reports_no_regime_as_none_not_as_the_default() -> None:
    """NULL means "none configured", which is a different claim from "the default was chosen".

    Substituting the default regime's name here would attribute a decision to an operator who
    never made it — and would make every unconfigured install look CNSA- or NIST-governed.
    """
    import uuid

    from qubit_api.routers.migrate import _plan_out
    from qubit_core import utcnow
    from qubit_migrate.state.models import MigrationPlan

    plan = MigrationPlan(
        id=uuid.uuid4(), tenant_id=uuid.uuid4(), status="active", created_at=utcnow()
    )
    assert _plan_out(plan).regime is None


class TestTheInjectedApiBaseIsNotBlockedByOurOwnCsp:
    """The API injects one inline script and must not then refuse it.

    Measured in the running desktop app before this fix: `window.__QUBIT_API_BASE__` was `null`
    because `script-src 'self'` blocked the very script that sets it, and every cold start logged
    three CSP errors. The client worked only by falling back to a default that happened to be
    right — a mechanism documented as "a reliable signal that the API shares this origin" that had
    never once functioned.
    """

    def test_the_csp_hash_matches_the_script_actually_injected(self) -> None:
        """Derived from the same bytes, so the two cannot drift. A hardcoded hash would silently
        stop matching the first time the script changed, restoring the bug in a subtler form."""
        import base64
        import hashlib

        from qubit_api.app import API_BASE_SCRIPT, API_BASE_SCRIPT_HASH

        expected = base64.b64encode(hashlib.sha256(API_BASE_SCRIPT).digest()).decode()
        assert API_BASE_SCRIPT_HASH == f"sha256-{expected}"

    def test_the_policy_permits_that_script_and_not_inline_generally(self) -> None:
        """A HASH, not `'unsafe-inline'`: an injection elsewhere in the page must still be
        refused."""
        from fastapi.testclient import TestClient
        from qubit_api.app import API_BASE_SCRIPT_HASH, create_app

        with TestClient(create_app()) as client:
            csp = client.get("/api/v1/health").headers["content-security-policy"]
        assert API_BASE_SCRIPT_HASH in csp
        assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
