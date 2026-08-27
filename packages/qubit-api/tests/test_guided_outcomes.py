"""A bulk migration has three outcomes, not two.

`migrated`, `could not be migrated` — and, missing until now, `handled by a guided path`. The
third is the one that decides whether the app reads as a tool that fixes things or a tool that
shrugs: a certificate finding, a Dart manifest and a shell provisioning script all have concrete
remediations, and all three used to arrive in the banner as failures.
"""

from __future__ import annotations

from pathlib import Path
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
from qubit_migrate.orchestrator import (
    RESOLUTION_GUIDED,
    GuidedRemediation,
    MigrationOrchestrator,
)
from sqlalchemy import create_engine


def _reporter(sf):
    reporter = MagicMock()
    reporter.sf = sf
    reporter.update = MagicMock()
    reporter.checkpoint = MagicMock()
    return reporter


def _asset(path: str, algorithm: str, usage: UsageContext, scanner: SourceScanner) -> CryptoAsset:
    return CryptoAsset(
        algorithm=algorithm,
        usage_context=usage,
        source_scanner=scanner,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=path, line=2),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        discovered_at=utcnow(),
        risk=RiskAnnotation(
            score=0.6, ci_low=0.5, ci_high=0.7, mosca_margin_years=-2.0, priority_rank=1
        ),
    )


@pytest.fixture
def project(tmp_path: Path):
    """A plan over one finding, with the file on disk so nothing is blocked on reading it."""

    def _build(filename: str, contents: str, algorithm: str, usage: UsageContext, scanner):
        db = tmp_path / f"{filename}.db"
        engine = create_engine(f"sqlite:///{db.as_posix()}")
        Base.metadata.create_all(engine)
        sf = session_factory(engine)
        src = tmp_path / filename
        src.write_text(contents, encoding="utf-8")
        with sf() as session:
            row_project = ProjectRow(name="t", slug=filename)
            session.add(row_project)
            session.flush()
            scan = ScanRow(project_id=row_project.id, seq=1, status="succeeded")
            session.add(scan)
            session.flush()
            session.add(
                asset_to_row(
                    _asset(str(src), algorithm, usage, scanner),
                    scan_id=scan.id,
                    project_id=row_project.id,
                )
            )
            session.commit()
            orch = MigrationOrchestrator(session)
            plan = orch.build_plan()
            queue = orch.get_queue(plan.id)
            return sf, plan.id, queue[0].id if queue else None

    return _build


CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"


def test_a_certificate_resolves_to_guidance_and_never_reaches_the_model(project) -> None:
    """`generate_patch` must decide this BEFORE calling anything.

    A code model handed a `.pem` produces a confidently corrupted certificate, and three attempts
    at it cost minutes to arrive at a patch that could never be right.
    """
    sf, _plan_id, task_id = project(
        "edge.pem", CERT_PEM, "RSA-2048", UsageContext.signature, SourceScanner.cert
    )
    assert task_id is not None
    with sf() as session:
        orch = MigrationOrchestrator(session)
        with pytest.raises(GuidedRemediation) as excinfo:
            orch.generate_patch(task_id)
        assert "openssl genpkey -algorithm ML-DSA-65" in excinfo.value.guidance

        from qubit_migrate.state import MigrationTask

        task = session.get(MigrationTask, task_id)
        assert task is not None
        assert task.resolution == RESOLUTION_GUIDED
        assert task.advice_model == "qubit-guided"
        assert "Steps" in (task.advice_text or "")


def test_guidance_is_produced_with_no_model_available(project, monkeypatch) -> None:
    """The property that makes this a fix rather than a rearrangement.

    `advise_task` raised `could not generate advice` when Ollama was down, so the app's answer to
    "what do I do about this?" depended on a side-car the user may not be running.
    """
    from qubit_migrate.transform import llm

    def refuse(*args: object, **kwargs: object) -> str:
        raise llm.OllamaError("connection refused")

    monkeypatch.setattr(llm, "_ollama_generate", refuse)

    sf, _plan_id, task_id = project(
        "pubspec.yaml",
        "name: app\ndependencies:\n  pointycastle: ^3.9.0\n",
        "RSA",
        UsageContext.kex,
        SourceScanner.config,
    )
    assert task_id is not None
    with sf() as session:
        task = MigrationOrchestrator(session).resolve_guided(task_id)
        assert task.advice_text
        assert "unverified" in task.advice_text.lower()
        assert "Option 1" in task.advice_text


def test_the_banner_counts_guided_separately_from_failed(project) -> None:
    sf, plan_id, _ = project(
        "edge.pem", CERT_PEM, "RSA-2048", UsageContext.signature, SourceScanner.cert
    )
    result = migrate_handler({"plan_id": str(plan_id), "apply": False}, _reporter(sf))
    assert result["needs_guidance"] == 1, result
    assert result["failed"] == 0, "a guided remediation is a result, not a failure"
    assert result["generated"] == 0


def test_a_rule_less_finding_is_given_a_plan_rather_than_skipped(project) -> None:
    """Skipping was only half the fix.

    Counting a no-rule finding as guidance stopped the banner lying about it. It did not put
    anything in the guidance panel — that still waited on the user to click, and on Ollama to be
    running when they did.
    """
    sf, plan_id, task_id = project(
        "notes.txt", "rsa stuff\n", "RSA", UsageContext.kex, SourceScanner.code
    )
    assert task_id is not None
    with sf() as session:
        from qubit_migrate.state import MigrationTask

        assert session.get(MigrationTask, task_id).rule_id is None

    result = migrate_handler({"plan_id": str(plan_id), "apply": False}, _reporter(sf))
    assert result["needs_guidance"] == 1
    assert result["failed"] == 0

    with sf() as session:
        from qubit_migrate.state import MigrationTask

        task = session.get(MigrationTask, task_id)
        assert task is not None and task.advice_text, (
            "a bulk run must leave every guided finding with its plan already written"
        )
        assert "Steps" in task.advice_text


def test_finished_work_is_never_reported_as_a_failure(project, monkeypatch) -> None:
    """The outcome a codemod reaches when there is nothing left to change is SUCCESS.

    Measured on the demo corpus mid-run: 19 findings parked as `unresolved` whose recorded reason
    was "nothing left for weakhash_to_sha256 to change", "no bump needed - this dependency already
    pins a version that provides PQC primitives", or "already remediated by an earlier task". Every
    one of them was finished work.

    Two defects produced that, and both are pinned here. The orchestrator parked the task as
    `satisfied` and then raised, and the generic `except Exception` around the codemod branch
    re-parked it with the DEFAULT resolution. The handler then classified the outcome by searching
    the message for two specific phrases, which the other two wordings do not contain.
    """
    from qubit_migrate.orchestrator import RESOLUTION_SATISFIED
    from qubit_migrate.state import MigrationTask
    from qubit_migrate.transform import codemods

    # A manifest that already declares the provider: `add_pqc_dependency` correctly reports no
    # change, which is the success condition for dep-pqc-03.
    sf, plan_id, task_id = project(
        "Package.swift",
        "// swift-tools-version:5.9\nimport PackageDescription\n\nlet package = Package(\n"
        '    name: "App",\n    dependencies: [\n'
        '        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.1"),\n'
        "    ]\n)\n",
        "ECDSA-P256",
        UsageContext.signature,
        SourceScanner.config,
    )
    assert task_id is not None
    assert codemods is not None  # imported for the failure message, not patched

    result = migrate_handler({"plan_id": str(plan_id), "apply": False}, _reporter(sf))
    assert result["failed"] == 0, (
        f"a manifest that already declares the provider is finished work: {result}"
    )
    assert result["covered"] == 1, result

    with sf() as session:
        task = session.get(MigrationTask, task_id)
        assert task is not None
        assert task.resolution == RESOLUTION_SATISFIED, (
            "the generic exception handler overwrote the resolution the codemod branch set"
        )
        assert "Codemod error" not in (task.last_error or ""), (
            "finished work must not be renamed an error on its way out"
        )


def test_a_failed_generation_still_leaves_a_plan_behind(project, monkeypatch) -> None:
    """The last route to a dead end, closed.

    A rejected rewrite left the queue row carrying a rejection reason and nothing else - which is
    "manual change" reached a different way. `code-kex-01` is why it matters rather than being a
    nicety: replacing RSA key transport with a KEM changes the shape of the protocol, and across
    two measured runs and eleven languages the local 7B model solved 0 of them. That is a ceiling
    on the model, not a reason to hand the user a stack trace.
    """
    from qubit_migrate.state import MigrationTask
    from qubit_migrate.transform import llm

    def refuse(*args: object, **kwargs: object) -> str:
        raise llm.OllamaError("the model returned the file unchanged")

    monkeypatch.setattr(llm, "_ollama_generate", refuse)
    monkeypatch.setattr(llm, "installed_models", lambda *a, **k: [])

    sf, plan_id, task_id = project(
        "seal.go",
        'package main\n\nimport "crypto/rsa"\n\nfunc seal(k *rsa.PublicKey) {}\n',
        "RSA-2048",
        UsageContext.kex,
        SourceScanner.code,
    )
    assert task_id is not None

    result = migrate_handler({"plan_id": str(plan_id), "apply": False}, _reporter(sf))
    assert result["failed"] == 1, result

    with sf() as session:
        task = session.get(MigrationTask, task_id)
        assert task is not None
        assert task.advice_text, "a failed generation must still leave a remediation path"
        assert "What the automated attempt could not do" in task.advice_text, (
            "the plan must open with the reason the automation stopped"
        )
        assert "Steps" in task.advice_text


def test_the_learning_endpoint_reports_both_stores(project, tmp_path: Path) -> None:
    """A system that claims to improve with use has to be able to show it.

    The two stores are counted separately on purpose: the line cache answers an identical line
    without a model call, and the experience base grounds a fresh call on structurally similar
    work. Reporting one number for both would hide which is doing the work.
    """
    from fastapi.testclient import TestClient
    from qubit_api.app import create_app
    from qubit_api.deps import get_session
    from qubit_api.settings import Settings
    from qubit_migrate.transform import learn

    sf, _plan_id, _task_id = project(
        "notes.txt", "rsa stuff\n", "RSA", UsageContext.kex, SourceScanner.code
    )
    with sf() as session:
        shape = learn.shape_key("code-ecb-01", "python", "c = AES.new(key, AES.MODE_ECB)")
        learn.record_outcome(
            session,
            rule_id="code-ecb-01",
            language="python",
            algorithm="AES",
            shape=shape,
            passed=True,
            hunk_before="c = AES.new(key, AES.MODE_ECB)",
            hunk_after="c = AES.new(key, AES.MODE_GCM, nonce=n)",
            reasoning="- Fresh nonce per message.",
        )
        learn.record_outcome(
            session,
            rule_id="code-kex-01",
            language="rust",
            algorithm="RSA",
            shape="s2",
            passed=False,
            hunk_before="Rsa::generate(1024)",
            failure_reason="the file came back unchanged",
        )
        session.commit()

    # The app is pointed at the SAME file the fixture wrote to, so the endpoint reads the rows
    # just recorded. Its startup runs a job-recovery statement, which needs the schema present.
    settings = Settings(
        db_url=f"sqlite:///{(tmp_path / 'notes.txt.db').as_posix()}",
        create_schema_on_startup=True,
    )
    app = create_app(settings)
    app.dependency_overrides[get_session] = lambda: sf().__enter__()
    with TestClient(app, headers={"Authorization": f"Bearer {settings.api_token}"}) as client:
        response = client.get("/api/v1/migrate/learning")
        body = response.json()
        assert response.status_code == 200, body

    assert body["proven_rewrites"] == 1
    assert body["retained_failures"] == 1, (
        "a rejection is evidence too - it was retained by nothing before this"
    )
    rules = {(r["rule_id"], r["language"]): r for r in body["by_rule"]}
    assert rules[("code-ecb-01", "python")]["proven"] == 1
    assert rules[("code-kex-01", "rust")]["warnings"] == 1


def test_a_run_retries_what_an_earlier_run_failed(project, monkeypatch) -> None:
    """The engine learns between runs; the findings that needed it most never saw the benefit.

    A failed task parks in `deferred` and every bulk run selected only `ready`, so 9 findings on
    this corpus sat unresolved across three subsequent runs - each with a better engine than the
    one that failed them - and not one was tried again.
    """
    from qubit_migrate.orchestrator import RESOLUTION_UNRESOLVED
    from qubit_migrate.state import MigrationTask
    from qubit_migrate.transform import llm

    attempts = {"n": 0}

    def sometimes(*args: object, **kwargs: object) -> str:
        attempts["n"] += 1
        raise llm.OllamaError("the model returned the file unchanged")

    monkeypatch.setattr(llm, "_ollama_generate", sometimes)
    monkeypatch.setattr(llm, "installed_models", lambda *a, **k: [])

    sf, plan_id, task_id = project(
        "seal.go",
        'package main\n\nimport "crypto/rsa"\n\nfunc seal(k *rsa.PublicKey) {}\n',
        "RSA-2048",
        UsageContext.kex,
        SourceScanner.code,
    )
    assert task_id is not None

    first = migrate_handler({"plan_id": str(plan_id), "apply": False}, _reporter(sf))
    assert first["failed"] == 1
    with sf() as session:
        assert session.get(MigrationTask, task_id).resolution == RESOLUTION_UNRESOLVED
    after_first = attempts["n"]
    assert after_first > 0

    # A second run over the SAME plan must pick the failure back up rather than reporting an
    # empty queue.
    second = migrate_handler({"plan_id": str(plan_id), "apply": False}, _reporter(sf))
    assert second["total"] == 1, "the previously-failed finding was not retried"
    assert attempts["n"] > after_first, "it was selected but never actually attempted"


def test_a_guided_or_satisfied_finding_is_not_dragged_back(project) -> None:
    """Both are resolved outcomes. Re-running them would undo the distinction, and would
    overwrite a remediation plan the user may already be following."""
    from qubit_migrate.state import MigrationTask

    sf, plan_id, task_id = project(
        "edge.pem", CERT_PEM, "RSA-2048", UsageContext.signature, SourceScanner.cert
    )
    assert task_id is not None
    first = migrate_handler({"plan_id": str(plan_id), "apply": False}, _reporter(sf))
    assert first["needs_guidance"] == 1
    with sf() as session:
        plan_text = session.get(MigrationTask, task_id).advice_text

    second = migrate_handler({"plan_id": str(plan_id), "apply": False}, _reporter(sf))
    assert second["total"] == 0, "a guided finding is resolved and must stay parked"
    with sf() as session:
        assert session.get(MigrationTask, task_id).advice_text == plan_text
