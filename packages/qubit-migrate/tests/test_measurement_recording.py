"""Every terminal path writes exactly one measurement row.

The property the whole dataset rests on. A finding that consumed four repair attempts and was then
routed to a human took real time; if that row is missing, `Y` is biased downward — the direction
that flatters the tool, and therefore the direction to be most careful about.

Exercised through the real orchestrator against a real database. A test that called
`_record_measurement` directly would prove the recorder works and say nothing about whether the
paths that matter ever reach it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import pytest
from qubit_core.db import Base
from qubit_migrate.orchestrator import AlreadySatisfied, GuidedRemediation, MigrationOrchestrator
from qubit_migrate.state.measurement import MigrationMeasurement
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session


@pytest.fixture
def session() -> Session:
    """An in-memory database with the full schema, as the e2e tests build one."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def _rows(session: Session) -> list[MigrationMeasurement]:
    return list(session.execute(select(MigrationMeasurement)).scalars())


class TestOneRowPerAttempt:
    """Driven by faking the inner call, so every branch of the wrapper is reached deterministically.

    The wrapper is the unit under test: `_generate_patch` is a several-hundred-line method whose
    own behaviour is covered elsewhere, and steering a real run into each of five terminal states
    would be slow and flaky without testing anything more.
    """

    @staticmethod
    def _orch(session, monkeypatch, behaviour):
        orch = MigrationOrchestrator(session)
        monkeypatch.setattr(
            MigrationOrchestrator, "_generate_patch", lambda self, *a, **k: behaviour()
        )
        return orch

    def test_already_satisfied_is_recorded_as_its_own_path(
        self, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A verdict, not a failure — and it still consumed scanner time."""

        def raise_satisfied():
            raise AlreadySatisfied("already migrated by an earlier patch")

        orch = self._orch(session, monkeypatch, raise_satisfied)
        with pytest.raises(AlreadySatisfied):
            orch.generate_patch(uuid.uuid4())

        (row,) = _rows(session)
        assert row.path == "satisfied"
        assert row.outcome == "satisfied"
        assert row.total_s >= 0

    def test_guided_remediation_is_recorded_as_needing_a_human(
        self, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Scoring this as a failure understates the tool; as an acceptance, overstates it."""

        def raise_guided():
            raise GuidedRemediation(uuid.uuid4(), "rotate the key by hand")

        orch = self._orch(session, monkeypatch, raise_guided)
        with pytest.raises(GuidedRemediation):
            orch.generate_patch(uuid.uuid4())

        (row,) = _rows(session)
        assert row.path == "guided"
        assert row.human_needed is True

    def test_an_unexpected_failure_is_still_recorded(
        self, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The row that is easiest to lose and most important to keep."""

        def boom():
            raise RuntimeError("engine unreachable")

        orch = self._orch(session, monkeypatch, boom)
        with pytest.raises(RuntimeError):
            orch.generate_patch(uuid.uuid4())

        (row,) = _rows(session)
        assert row.outcome == "failed"

    def test_recording_never_swallows_the_original_exception(
        self, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An instrumentation defect must not masquerade as a tool defect.

        If the recorder raises, the caller must still see the migration's own error — not the
        measurement's.
        """

        def boom():
            raise RuntimeError("the real problem")

        orch = self._orch(session, monkeypatch, boom)
        monkeypatch.setattr(
            MigrationOrchestrator,
            "_record_measurement",
            lambda *a, **k: (_ for _ in ()).throw(ValueError("recorder is broken")),
        )
        with pytest.raises(RuntimeError, match="the real problem"):
            orch.generate_patch(uuid.uuid4())

    def test_a_broken_recorder_does_not_lose_a_good_patch(
        self, session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The mirror case: a measurement failure must not discard a correct patch.

        The patch has already been generated, validated and committed by the time the recorder
        runs. Losing it to an instrumentation error would be the most expensive possible way for
        this feature to fail.
        """

        class _Patch:
            generator = "template"
            status = "proposed"
            model_name = None
            diff_text = ""
            evidence_level = 2
            file_path = "k.py"

            def __init__(self) -> None:
                self.validation_json: dict = {}

        sentinel = _Patch()
        orch = self._orch(session, monkeypatch, lambda: sentinel)
        monkeypatch.setattr(
            MigrationOrchestrator,
            "_record_measurement",
            lambda *a, **k: (_ for _ in ()).throw(ValueError("recorder is broken")),
        )
        assert orch.generate_patch(uuid.uuid4()) is sentinel


class TestTheRecorderIsResilient:
    def test_a_missing_task_does_not_raise(self, session) -> None:
        """The recorder is handed a task id that may already be gone. It must still write what it
        knows rather than losing the row — or, worse, breaking the caller."""
        orch = MigrationOrchestrator(session)
        orch._record_measurement(
            uuid.uuid4(), "codemod", "accepted", queued_at=datetime.now(UTC), started=0.0
        )
        assert len(_rows(session)) == 1


@dataclass
class _FakeRow:
    """The two attributes the covariate helpers read off an `AssetRow`."""

    location: dict[str, str]


class TestTheCovariates:
    """The fields a reader needs to interpret a migration time, and the ways they go silently
    blank."""

    def test_language_is_derived_from_the_path(self) -> None:
        """`AssetRow` has no `language` column.

        Reading one with `getattr(asset, "language", "")` returned "" for every row — worse than
        an error, because the column looked measured while being uniformly blank, and any
        per-language breakdown would have shown a single empty bucket.
        """
        from qubit_migrate.orchestrator import _language_of_row

        assert _language_of_row(_FakeRow({"file_path": "pkg/crypto.py"})) == "python"
        assert _language_of_row(None) == ""

    def test_an_unknown_suffix_yields_empty_rather_than_a_guess(self) -> None:
        from qubit_migrate.orchestrator import _language_of_row

        assert _language_of_row(_FakeRow({"file_path": "notes.qqq"})) == ""

    def test_file_size_is_measured_from_the_repo(self, tmp_path) -> None:
        from qubit_migrate.orchestrator import _file_size

        (tmp_path / "k.py").write_text("a\nb\nc\n", encoding="utf-8", newline="\n")

        row = _FakeRow({"file_path": "k.py"})
        assert _file_size(row, tmp_path) == {"file_bytes": 6, "file_lines": 4}

    def test_a_missing_file_yields_zeros_rather_than_raising(self, tmp_path) -> None:
        """The recorder runs after the migration; a path can legitimately be gone by then."""
        from qubit_migrate.orchestrator import _file_size

        row = _FakeRow({"file_path": "vanished.py"})
        assert _file_size(row, tmp_path) == {"file_bytes": 0, "file_lines": 0}
        assert _file_size(row, None) == {"file_bytes": 0, "file_lines": 0}


class TestDiffLineCounting:
    def test_file_headers_are_not_counted_as_changes(self) -> None:
        """`+++`/`---` are headers, not content.

        Counting them adds two phantom changed lines to every patch, which matters most on the
        one-line substitutions that dominate the codemod path.
        """
        from qubit_migrate.orchestrator import _diff_lines

        diff = "--- a/k.py\n+++ b/k.py\n@@ -1 +1 @@\n-import hashlib\n+import hashlib  # sha256\n"
        assert _diff_lines(diff) == (2, 0)

    def test_blank_only_changes_are_counted_as_noise(self) -> None:
        """A real failure mode: 12 of 18 patches in one run were majority whitespace, and a
        "changed lines" count that includes them overstates how much work the tool did."""
        from qubit_migrate.orchestrator import _diff_lines

        diff = "--- a/k.py\n+++ b/k.py\n@@ -1,2 +1,3 @@\n-x = 1\n+x = 2\n+\n+   \n"
        assert _diff_lines(diff) == (4, 2)

    def test_an_empty_diff_is_zero_not_an_error(self) -> None:
        from qubit_migrate.orchestrator import _diff_lines

        assert _diff_lines("") == (0, 0)
        assert _diff_lines(None) == (0, 0)


class TestTheRecorderWritesTheCovariates:
    """Not just that the helpers work — that the recorder CALLS them.

    Testing the helpers alone left both wirings unverified: reverting the recorder to read a
    non-existent `language` column, or to omit the size fields entirely, left every helper test
    green while the exported dataset lost two columns.
    """

    @staticmethod
    def _seeded(session: Session, tmp_path: Path) -> uuid.UUID:
        """One asset and one task, enough for the recorder to populate a full row."""
        from qubit_core.db import AssetRow
        from qubit_migrate.state import MigrationPlan, MigrationTask, MigrationUnit

        (tmp_path / "pkg").mkdir(parents=True, exist_ok=True)
        (tmp_path / "pkg" / "crypto.py").write_text(
            "import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8", newline="\n"
        )

        tenant = uuid.uuid4()
        asset = AssetRow(
            id=uuid.uuid4(),
            tenant_id=tenant,
            scan_id=uuid.uuid4(),
            project_id=uuid.uuid4(),
            fingerprint="abc123",
            source_scanner="code",
            asset_type="algorithm_use",
            algorithm="MD5",
            usage_context="hash",
            location={"file_path": "pkg/crypto.py", "line": 2},
        )
        plan = MigrationPlan(id=uuid.uuid4(), tenant_id=tenant, status="active")
        unit = MigrationUnit(id=uuid.uuid4(), plan_id=plan.id, label="pkg/crypto.py")
        task = MigrationTask(
            id=uuid.uuid4(),
            plan_id=plan.id,
            unit_id=unit.id,
            asset_id=asset.id,
            rule_id="py-weakhash-01",
        )
        session.add_all([asset, plan, unit, task])
        session.commit()
        return task.id

    def test_language_and_size_reach_the_row(self, session, tmp_path) -> None:
        task_id = self._seeded(session, tmp_path)
        orch = MigrationOrchestrator(session)
        orch._record_measurement(
            task_id,
            "codemod",
            "accepted",
            queued_at=datetime.now(UTC),
            started=0.0,
            repo_root=tmp_path,
        )
        (row,) = _rows(session)
        assert row.language == "python", "the language column would be blank for every row"
        assert row.file_bytes == 33, row.file_bytes
        assert row.file_lines == 3
        assert row.algorithm == "MD5"
        assert row.usage_context == "hash"
        assert row.rule_id == "py-weakhash-01"
        assert row.synthesised is False

    def test_a_synthesised_rule_is_marked_as_one(self, session, tmp_path) -> None:
        """A different experimental condition; pooling the two hides which one the tool is good
        at."""
        from qubit_migrate.state import MigrationTask

        task_id = self._seeded(session, tmp_path)
        task = session.get(MigrationTask, task_id)
        assert task is not None
        task.rule_id = "synth-md5-hash-python"
        session.commit()

        MigrationOrchestrator(session)._record_measurement(
            task_id, "model", "accepted", queued_at=datetime.now(UTC), started=0.0
        )
        assert _rows(session)[0].synthesised is True
