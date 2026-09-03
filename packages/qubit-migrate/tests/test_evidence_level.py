"""The evidence ladder, and the vacuous-expectation flag that keeps it honest.

`passed: bool` collapsed six different states into one word. Measured on the live database, all
216 accepted patches were flagged `partial`, 20 were accepted with every stage skipped, and the
`tests` stage had never once run — 0 of 292. Every one of those is `passed=True`.

These tests pin the two properties that make the replacement worth having: a gate that did not run
awards nothing, and a gate that could not have failed awards nothing either.
"""

from __future__ import annotations

import pytest
from qubit_migrate.transform.validate import (
    NO_EVIDENCE,
    STAGE_NAMES,
    StageResult,
    ValidationReport,
    evidence_level,
)


def _stages(**statuses: str) -> dict[str, StageResult]:
    """Stages by name; anything unnamed is `skipped`, as a real report has it."""
    return {name: StageResult(statuses.get(name, "skipped")) for name in STAGE_NAMES}


ALL_PASS = dict.fromkeys(STAGE_NAMES, "pass")


class TestTheLadderClimbs:
    def test_nothing_run_is_not_level_zero(self) -> None:
        """Level 0 is a claim — the diff applied and the result parses. No stages is no claim."""
        assert evidence_level(_stages()) == NO_EVIDENCE

    @pytest.mark.parametrize(
        ("through", "expected"),
        [
            (("applies", "parses"), 0),
            (("applies", "parses", "symbols", "compiles"), 1),
            (("applies", "parses", "symbols", "compiles", "rescan"), 2),
            (("applies", "parses", "symbols", "compiles", "rescan", "behaves"), 3),
        ],
    )
    def test_each_rung_needs_every_gate_below_it(
        self, through: tuple[str, ...], expected: int
    ) -> None:
        assert evidence_level(_stages(**dict.fromkeys(through, "pass"))) == expected

    def test_the_top_rung_is_reachable(self) -> None:
        assert evidence_level(_stages(**ALL_PASS)) == 4


class TestSkippedIsNotPassed:
    """The single assumption that produced every number this project has had to retract."""

    def test_a_skipped_gate_caps_the_level(self) -> None:
        stages = _stages(**ALL_PASS)
        stages["compiles"] = StageResult("skipped", "no_docker configured")
        # applies+parses stand. Everything above `compiles` is unestablished, however green.
        assert evidence_level(stages) == 0

    def test_a_skipped_behaves_caps_below_three_even_though_tests_passed(self) -> None:
        """The exact shape of an inflated number: a stronger gate passing over a hole."""
        stages = _stages(**ALL_PASS)
        stages["behaves"] = StageResult("skipped", "no probed API shape for 'AES-256-GCM'")
        assert evidence_level(stages) == 2

    def test_a_failing_gate_caps_the_level_too(self) -> None:
        stages = _stages(**ALL_PASS)
        stages["behaves"] = StageResult("fail", "sig-wrong-key: accepted input it must reject")
        assert evidence_level(stages) == 2


class TestVacuousExpectations:
    """A pass that could not have been a fail is worth exactly what a skip is worth."""

    def test_a_vacuous_rescan_does_not_award_its_rung(self) -> None:
        stages = _stages(**ALL_PASS)
        stages["rescan"] = StageResult("pass", "rescan ok", vacuous=True)
        assert evidence_level(stages) == 1

    def test_a_vacuous_rescan_blocks_the_rungs_above_it(self) -> None:
        """`behaves` passing does not paper over the hole underneath it."""
        stages = _stages(**ALL_PASS)
        stages["rescan"] = StageResult("pass", "rescan ok", vacuous=True)
        assert evidence_level(stages) < 3

    def test_the_flag_is_serialized_only_when_set(self) -> None:
        """Presence is the query. Records written before the flag existed must not read as
        "measured, and not vacuous"."""
        assert "vacuous" not in StageResult("pass").as_dict()
        assert StageResult("pass", vacuous=True).as_dict()["vacuous"] is True


class TestTheReportExposesIt:
    def test_the_report_reports_its_level(self) -> None:
        report = ValidationReport(stages=_stages(**ALL_PASS), passed=True, partial=False)
        assert report.evidence_level == 4
        assert report.as_dict()["evidence_level"] == 4

    def test_passed_true_can_still_mean_no_evidence(self) -> None:
        """The whole indictment in one assertion: this is 20 real rows of the live database."""
        report = ValidationReport(stages=_stages(), passed=True, partial=True)
        assert report.passed is True
        assert report.evidence_level == NO_EVIDENCE

    def test_the_level_cannot_disagree_with_the_stages(self) -> None:
        """Derived, not stored — so no caller can write one without the other."""
        report = ValidationReport(stages=_stages(**ALL_PASS))
        assert report.evidence_level == 4
        report.stages["parses"] = StageResult("fail", "SyntaxError")
        assert report.evidence_level == NO_EVIDENCE


class TestItIsQueryable:
    """The column exists so the distribution is a GROUP BY, not a scan of 292 JSON blobs."""

    def test_the_column_round_trips(self, tmp_path: object) -> None:
        import uuid

        from qubit_migrate.state.models import PatchProposal

        patch = PatchProposal(
            id=uuid.uuid4(),
            task_id=uuid.uuid4(),
            file_path="k.py",
            base_sha256="0" * 64,
            diff_text="",
            evidence_level=3,
        )
        assert patch.evidence_level == 3

    def test_it_defaults_to_unassessed_not_to_zero(self) -> None:
        """Rows written before the ladder existed must not read as "assessed at rung 0"."""
        import uuid

        from qubit_migrate.state.models import PatchProposal

        patch = PatchProposal(
            id=uuid.uuid4(),
            task_id=uuid.uuid4(),
            file_path="k.py",
            base_sha256="0" * 64,
            diff_text="",
        )
        assert patch.evidence_level is None
