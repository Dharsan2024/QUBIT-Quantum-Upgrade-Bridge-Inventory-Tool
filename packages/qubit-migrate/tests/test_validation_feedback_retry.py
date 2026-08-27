"""The validator's verdict must reach the model, and every rejection must be remembered.

Two gaps this pins, both measured as real losses of accepted patches:

1. `generate_llm_source` runs its own repair loop, but the only verdict it can see is the rescan.
   `applies`, `parses`, `symbols`, `compiles` and `tests` all run in `generate_patch` AFTER it has
   returned, so a rewrite rejected for something as answerable as "uses mldsa65.PublicKey but the
   patch does not import it" was discarded without the model ever being told — while a merely
   truncated answer got three tries. One extra attempt carrying the real stage detail is the
   cheapest source of accepted patches available.

2. That rejection was never recorded. `record_outcome` was only reachable from the generation
   exception handler, so a patch that generated cleanly and then failed `compiles` left no trace,
   and the next attempt at structurally identical code repeated the mistake from scratch.

Both are capped deliberately: exactly ONE extra outer attempt, because the inner loop is already
three and an uncapped product turns one finding into nine model calls.
"""

from __future__ import annotations

from qubit_core.db import Base, ProjectRow, ScanRow
from qubit_core.db.models import LearnedOutcome
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
from qubit_migrate.config import MigrateConfig
from qubit_migrate.orchestrator import MigrationOrchestrator
from qubit_migrate.state import MigrationTask
from qubit_migrate.transform.validate import StageResult, ValidationReport
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

REWRITTEN = "import hashlib\ndigest = hashlib.sha256(data)\n"
REPAIRED = "import hashlib\ndigest = hashlib.sha256(data)  # repaired\n"


def _seeded_orchestrator(tmp_path) -> tuple[MigrationOrchestrator, MigrationTask]:
    """One ready task, with the plan-first and self-review passes off.

    Both are on by default and each costs an extra `_ollama_generate` call, so leaving them on
    makes a call count read "3" for a single generation and tells you nothing about whether the
    retry fired. These tests are about the outer validation-feedback loop specifically.
    """
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    project = ProjectRow(name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    src = tmp_path / "app.py"
    src.write_text("import hashlib\ndigest = hashlib.md5(data)\n", encoding="utf-8")
    asset = CryptoAsset(
        algorithm="MD5",
        usage_context=UsageContext.hash,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path=str(src), line=2),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=utcnow(),
        risk=RiskAnnotation(
            score=0.5, ci_low=0.4, ci_high=0.6, mosca_margin_years=-1.0, priority_rank=1
        ),
    )
    session.add(asset_to_row(asset, scan_id=scan.id, project_id=project.id))
    session.commit()
    orch = MigrationOrchestrator(
        session, MigrateConfig(llm_plan_first=False, llm_self_review=False)
    )
    plan = orch.build_plan()
    task = orch.get_queue(plan.id)[0]
    return orch, task


_SYMBOLS_DETAIL = (
    "uses mldsa65.PublicKey but the patch does not import it — if you replace an algorithm "
    "you must add its import"
)


def _failing(stage: str = "symbols", detail: str = _SYMBOLS_DETAIL) -> ValidationReport:
    return ValidationReport(stages={stage: StageResult("fail", detail)}, passed=False)


def _passing() -> ValidationReport:
    return ValidationReport(stages={"symbols": StageResult("pass", "")}, passed=True)


class TestTheValidatorsVerdictReachesTheModel:
    def test_the_failing_stage_detail_is_fed_into_a_second_attempt(
        self, tmp_path, monkeypatch
    ) -> None:
        prompts: list[str] = []

        def fake_generate(prompt, *, model, base_url="x", timeout=0, **_):
            prompts.append(prompt)
            return "```python\n" + REWRITTEN + "```"

        monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", fake_generate)
        monkeypatch.setattr("qubit_migrate.orchestrator.validate_patch", lambda *a, **k: _failing())

        orch, task = _seeded_orchestrator(tmp_path)
        orch.generate_patch(task.id, generator="llm")

        # The retry happened at all...
        assert len(prompts) >= 2, (
            "no second attempt was made after the validator rejected the patch"
        )
        # ...and it carried the validator's OWN words, not a generic "try again".
        retry_prompt = prompts[-1]
        assert "REJECTED" in retry_prompt
        assert "symbols failed" in retry_prompt
        assert "mldsa65.PublicKey" in retry_prompt

    def test_a_patch_the_retry_fixes_is_accepted(self, tmp_path, monkeypatch) -> None:
        """The whole point: a finding that used to fail now yields a proposed patch."""
        answers = iter(["```python\n" + REWRITTEN + "```", "```python\n" + REPAIRED + "```"])
        monkeypatch.setattr(
            "qubit_migrate.transform.llm._ollama_generate",
            lambda prompt, *, model, base_url="x", timeout=0, **_: next(answers),
        )

        reports = iter([_failing(), _passing()])
        monkeypatch.setattr(
            "qubit_migrate.orchestrator.validate_patch", lambda *a, **k: next(reports)
        )

        orch, task = _seeded_orchestrator(tmp_path)
        patch = orch.generate_patch(task.id, generator="llm")

        assert patch.status == "proposed"
        assert "repaired" in patch.diff_text
        orch.session.refresh(task)
        # The gate passed, so the task advanced out of the failure states entirely.
        assert task.state == "proposed"
        assert task.resolution != "unresolved"

    def test_a_patch_that_passes_first_time_never_retries(self, tmp_path, monkeypatch) -> None:
        """No extra model call on the happy path — the retry must not cost every finding a round."""
        calls: list[str] = []

        def fake_generate(prompt, *, model, base_url="x", timeout=0, **_):
            calls.append(prompt)
            return "```python\n" + REWRITTEN + "```"

        monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", fake_generate)
        monkeypatch.setattr("qubit_migrate.orchestrator.validate_patch", lambda *a, **k: _passing())

        orch, task = _seeded_orchestrator(tmp_path)
        patch = orch.generate_patch(task.id, generator="llm")

        assert patch.status == "proposed"
        assert len(calls) == 1

    def test_the_retry_is_capped_at_one_extra_attempt(self, tmp_path, monkeypatch) -> None:
        """A permanently-failing validator must not loop. Inner loop (3) + one outer retry (3)."""
        calls: list[str] = []

        def fake_generate(prompt, *, model, base_url="x", timeout=0, **_):
            calls.append(prompt)
            return "```python\n" + REWRITTEN + "```"

        monkeypatch.setattr("qubit_migrate.transform.llm._ollama_generate", fake_generate)
        monkeypatch.setattr("qubit_migrate.orchestrator.validate_patch", lambda *a, **k: _failing())

        orch, task = _seeded_orchestrator(tmp_path)
        patch = orch.generate_patch(task.id, generator="llm")

        assert patch.status == "failed"
        # The inner repair loop accepts this candidate on its first try (its rescan verifier is
        # satisfied), so each outer attempt costs exactly one call: 1 + 1, never a runaway.
        assert len(calls) == 2, f"retry is not bounded: {len(calls)} model calls for one finding"

    def test_a_still_failing_retry_leaves_the_task_exactly_as_before(
        self, tmp_path, monkeypatch
    ) -> None:
        """The pre-existing contract survives: deferred/unresolved with the real stage detail."""
        monkeypatch.setattr(
            "qubit_migrate.transform.llm._ollama_generate",
            lambda prompt, *, model, base_url="x", timeout=0, **_: (
                "```python\n" + REWRITTEN + "```"
            ),
        )
        monkeypatch.setattr(
            "qubit_migrate.orchestrator.validate_patch",
            lambda *a, **k: _failing("applies", "patch does not apply: context lines moved"),
        )

        orch, task = _seeded_orchestrator(tmp_path)
        patch = orch.generate_patch(task.id, generator="llm")

        assert patch.status == "failed"
        orch.session.refresh(task)
        assert task.state == "deferred"
        assert task.resolution == "unresolved"
        assert task.last_error is not None
        assert "applies failed" in task.last_error
        assert "context lines moved" in task.last_error


class TestEveryRejectionIsRemembered:
    def test_a_validation_failure_is_recorded_to_the_experience_base(
        self, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.setattr(
            "qubit_migrate.transform.llm._ollama_generate",
            lambda prompt, *, model, base_url="x", timeout=0, **_: (
                "```python\n" + REWRITTEN + "```"
            ),
        )
        monkeypatch.setattr("qubit_migrate.orchestrator.validate_patch", lambda *a, **k: _failing())

        orch, task = _seeded_orchestrator(tmp_path)
        orch.generate_patch(task.id, generator="llm")

        rows = orch.session.scalars(
            select(LearnedOutcome).where(LearnedOutcome.outcome == "failed")
        ).all()
        assert rows, "a validation failure left no trace in the experience base"
        row = rows[0]
        assert "symbols failed" in row.failure_reason
        assert "mldsa65.PublicKey" in row.failure_reason
        # The validator judged the rewrite on its merits, so this counts against the model rather
        # than being written off as a QUBIT gap.
        assert row.is_unwinnable is False

    def test_a_recorded_validation_failure_counts_toward_reliability(
        self, tmp_path, monkeypatch
    ) -> None:
        """The reliability gate must SEE these failures — that is the point of recording them."""
        from qubit_migrate.transform import learn

        monkeypatch.setattr(
            "qubit_migrate.transform.llm._ollama_generate",
            lambda prompt, *, model, base_url="x", timeout=0, **_: (
                "```python\n" + REWRITTEN + "```"
            ),
        )
        monkeypatch.setattr("qubit_migrate.orchestrator.validate_patch", lambda *a, **k: _failing())

        orch, task = _seeded_orchestrator(tmp_path)
        rule_id = task.rule_id
        assert rule_id is not None
        orch.generate_patch(task.id, generator="llm")

        passed, failed = learn.reliability(orch.session, rule_id=rule_id, language="python")
        assert passed == 0
        assert failed >= 1
