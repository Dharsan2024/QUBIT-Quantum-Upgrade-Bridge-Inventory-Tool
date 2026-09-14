"""The evidence ladder, and the vacuous-expectation flag that keeps it honest.

`passed: bool` collapsed six different states into one word. Measured on the live database, all
216 accepted patches were flagged `partial`, 20 were accepted with every stage skipped, and the
`tests` stage had never once run — 0 of 292. Every one of those is `passed=True`.

These tests pin the two properties that make the replacement worth having: a gate that did not run
awards nothing, and a gate that could not have failed awards nothing either.
"""

from __future__ import annotations

import pytest
from qubit_migrate.transform import validate as validate_mod
from qubit_migrate.transform.validate import (
    NO_EVIDENCE,
    STAGE_NAMES,
    StageResult,
    ValidationReport,
    _stage_compiles,
    evidence_basis,
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


#: Every language whose toolchain refuses to judge one file with no project — see
#: `_NO_SINGLE_FILE_COMPILE`. Listed here rather than imported so that widening the production set
#: has to be a deliberate edit in two places.
INAPPLICABLE_COMPILE_LANGUAGES = [
    "go",
    "java",
    "rust",
    "csharp",
    "kotlin",
    "scala",
    "swift",
    "dart",
    "typescript",
    "tsx",
]

GO_SOURCE = 'package main\n\nimport "crypto/ecdsa"\n\nfunc main() { _ = ecdsa.PublicKey{} }\n'


class TestInapplicableIsNotTheSameAsSkipped:
    """A gate that CANNOT run and a gate that DID NOT run are different claims.

    Measured on the sentinel-idp (Go) run before this split existed:

        symbols  {'pass': 2, 'fail': 5}    compiles {'skipped': 7}
        rescan   {'pass': 7}               behaves  {'skipped': 7}
        tests    {'pass': 2, 'fail': 5}    evidence_levels {'0': 7}

    Two patches passed `symbols`, `rescan` AND the project's own test suite — the strongest
    evidence this tool produces — and both were recorded at rung 0, because rung 1 requires
    `compiles` and `go build` will not judge a single file with no module. The cap was an artifact
    of the ladder, not a statement about the patches.
    """

    @pytest.mark.parametrize("language", INAPPLICABLE_COMPILE_LANGUAGES)
    def test_compiles_says_so_structurally(self, language: str) -> None:
        """The flag is what the ladder reads — never the wording of the detail string.

        Reaches no daemon: `_stage_compiles` answers the language question before it consults
        Docker, which is exactly why this claim is a property of the language.
        """
        result = _stage_compiles(GO_SOURCE, language)
        assert result.status == "skipped"
        assert result.not_applicable is True

    def test_a_go_patch_with_symbols_rescan_and_tests_is_not_capped_at_zero(self) -> None:
        """The defect, in one assertion. Rung 1's remaining gate ran and passed."""
        stages = _stages(applies="pass", parses="pass", symbols="pass", rescan="pass", tests="pass")
        stages["compiles"] = _stage_compiles(GO_SOURCE, "go")
        assert evidence_level(stages) == 2

    def test_java_reaches_the_same_rung_for_the_same_reason(self) -> None:
        stages = _stages(applies="pass", parses="pass", symbols="pass", rescan="pass", tests="pass")
        stages["compiles"] = _stage_compiles("class A {}", "java")
        assert evidence_level(stages) == 2

    def test_a_failing_symbols_still_caps_at_zero(self) -> None:
        """The relaxation is not a free pass: rung 1 now rests entirely on `symbols` for Go, so a
        Go patch that deletes an import while keeping its callers stays exactly where it was."""
        stages = _stages(applies="pass", parses="pass", rescan="pass", tests="pass")
        stages["symbols"] = StageResult("fail", "uses ecdsa but the patch does not import it")
        stages["compiles"] = _stage_compiles(GO_SOURCE, "go")
        assert evidence_level(stages) == 0

    def test_behaves_still_caps_go_at_two(self) -> None:
        """The conservative half of the decision, pinned.

        `behaves` skips for Go with "no metamorphic harness has been probed for go" — a gap in
        THIS TOOL that someone could close, not a property of the language. So it stays a plain
        skip, and a Go patch cannot claim rung 3 or 4 however green `tests` comes back: nothing
        exercised the cryptography it installed.
        """
        stages = _stages(**ALL_PASS)
        stages["compiles"] = _stage_compiles(GO_SOURCE, "go")
        stages["behaves"] = StageResult("skipped", "no metamorphic harness has been probed for go")
        assert evidence_level(stages) == 2

    def test_an_unknown_language_is_not_inapplicable(self) -> None:
        """ "We do not know whether this could be checked" may not relax the ladder — only "it
        provably cannot be" may. A typo in a rule must not buy a rung."""
        result = _stage_compiles("...", "brainfuck")
        assert result.status == "skipped"
        assert result.not_applicable is False
        stages = _stages(**ALL_PASS)
        stages["compiles"] = result
        assert evidence_level(stages) == 0

    @pytest.mark.parametrize("language", ["c", "cpp", "powershell", "sql"])
    def test_the_undecided_languages_keep_capping(self, language: str) -> None:
        """Deliberately left out of the set. A single-file `gcc -fsyntax-only` is arguable; nobody
        has measured it, so these keep the behaviour they had."""
        assert _stage_compiles("int main(void){return 0;}", language).not_applicable is False

    def test_a_rung_with_no_applicable_gate_left_is_refused(self) -> None:
        """`all([])` is True, and that is the one way this change could have inflated a number.

        If every gate of a rung were ever marked inapplicable, nothing could have run and nothing
        was established — the ladder must stop, not award it.
        """
        stages = _stages(**ALL_PASS)
        stages["symbols"] = StageResult("skipped", "hypothetical", not_applicable=True)
        stages["compiles"] = StageResult("skipped", "hypothetical", not_applicable=True)
        assert evidence_level(stages) == 0

    def test_the_flag_is_serialized_only_when_set(self) -> None:
        """Presence is the query, exactly as for `vacuous`: records written before this flag
        existed must not read as "we checked, and the gate was applicable"."""
        assert "not_applicable" not in StageResult("skipped").as_dict()
        assert StageResult("skipped", not_applicable=True).as_dict()["not_applicable"] is True


class TestDockerUnavailableStillCaps:
    """The regression that matters most. An absent daemon establishes nothing, as it always did."""

    def test_docker_unavailable_is_not_inapplicable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Same status, opposite meaning. Python HAS a single-file compile check; the machine just
        could not run it."""
        monkeypatch.setattr(validate_mod, "_docker_available", lambda: False)
        result = _stage_compiles("x = 1\n", "python")
        assert result.status == "skipped"
        assert result.detail == "docker unavailable"
        assert result.not_applicable is False

    def test_docker_unavailable_still_caps_the_level_at_zero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(validate_mod, "_docker_available", lambda: False)
        stages = _stages(**ALL_PASS)
        stages["compiles"] = _stage_compiles("x = 1\n", "python")
        assert evidence_level(stages) == 0

    def test_an_unpulled_image_still_caps_the_level_at_zero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The second "did not run" branch: QUBIT is offline by mandate and never pulls, so a
        missing image is a fact about this machine, not about Python."""
        monkeypatch.setattr(validate_mod, "_docker_available", lambda: True)
        monkeypatch.setattr(validate_mod, "_image_present", lambda image: False)
        result = _stage_compiles("x = 1\n", "python")
        assert result.status == "skipped"
        assert result.not_applicable is False
        stages = _stages(**ALL_PASS)
        stages["compiles"] = result
        assert evidence_level(stages) == 0

    def test_no_docker_configured_still_caps_a_python_patch(self) -> None:
        """`validate_patch`'s own short-circuit. `compiles` exists for Python, so switching Docker
        off means it did not run."""
        stages = _stages(**ALL_PASS)
        stages["compiles"] = StageResult("skipped", "no_docker configured")
        assert evidence_level(stages) == 0


class TestPythonIsUnchanged:
    """The languages with a real compile check must climb exactly the ladder they climbed before."""

    @pytest.mark.parametrize(
        ("through", "expected"),
        [
            (("applies", "parses"), 0),
            (("applies", "parses", "symbols", "compiles"), 1),
            (("applies", "parses", "symbols", "compiles", "rescan"), 2),
            (("applies", "parses", "symbols", "compiles", "rescan", "behaves"), 3),
        ],
    )
    def test_each_rung_still_needs_every_gate_below_it(
        self, through: tuple[str, ...], expected: int
    ) -> None:
        assert evidence_level(_stages(**dict.fromkeys(through, "pass"))) == expected

    def test_a_full_python_ladder_is_not_reduced(self) -> None:
        stages = _stages(**ALL_PASS)
        assert evidence_level(stages) == 4
        assert evidence_basis(stages)["reduced"] is False
        assert evidence_basis(stages)["not_applicable"] == []

    def test_a_vacuous_rescan_still_awards_nothing_under_an_inapplicable_compile(self) -> None:
        """The two flags are independent, and `vacuous` is not weakened by `not_applicable`: an
        APPLICABLE gate that passed without being able to fail is still worth what a skip is."""
        stages = _stages(**ALL_PASS)
        stages["compiles"] = _stage_compiles(GO_SOURCE, "go")
        stages["rescan"] = StageResult("pass", "rescan ok", vacuous=True)
        assert evidence_level(stages) == 1


class TestTheBasisIsRecorded:
    """A level is no longer self-describing, so the record has to say how it was reached."""

    def test_a_reader_can_tell_a_reduced_rung_from_a_full_one(self) -> None:
        """The requirement in one assertion: two identical numbers, two different claims."""
        full = _stages(**ALL_PASS)
        reduced = _stages(**ALL_PASS)
        reduced["compiles"] = _stage_compiles(GO_SOURCE, "go")
        # Same rung reached by both (`behaves` is hypothetical for Go — see the ladder tests).
        assert evidence_level(full) == evidence_level(reduced) == 4
        assert evidence_basis(full)["reduced"] is False
        assert evidence_basis(reduced)["reduced"] is True
        assert evidence_basis(reduced)["not_applicable"] == ["compiles"]
        assert "compiles" in evidence_basis(full)["established_by"]
        assert "compiles" not in evidence_basis(reduced)["established_by"]

    def test_the_basis_only_describes_rungs_actually_reached(self) -> None:
        """A gate above the level established nothing and is not part of the basis for it."""
        stages = _stages(applies="pass", parses="pass")
        basis = evidence_basis(stages)
        assert basis["level"] == 0
        assert basis["established_by"] == ["applies", "parses"]
        assert basis["not_applicable"] == []

    def test_no_evidence_has_an_empty_basis(self) -> None:
        basis = evidence_basis(_stages())
        assert basis["level"] == NO_EVIDENCE
        assert basis["established_by"] == []
        assert basis["reduced"] is False

    def test_the_report_stores_the_basis_beside_the_level(self) -> None:
        stages = _stages(applies="pass", parses="pass", symbols="pass", rescan="pass")
        stages["compiles"] = _stage_compiles(GO_SOURCE, "go")
        payload = ValidationReport(stages=stages, passed=True, partial=True).as_dict()
        assert payload["evidence_level"] == 2
        assert payload["evidence_basis"]["not_applicable"] == ["compiles"]
        # The per-stage record carries it too, so the basis can be re-derived from the stages.
        assert payload["stages"]["compiles"]["not_applicable"] is True
        assert payload["stages"]["compiles"]["status"] == "skipped"


class TestValidatePatchAgrees:
    """The flag must not depend on how the run was configured."""

    def test_no_docker_does_not_make_go_compilable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Whether `go build` can judge one file is a fact about Go, not about a Docker flag.
        Answering it in only one of the two branches would make the same patch record two
        different evidence levels in two runs of the same tool."""
        monkeypatch.setattr(
            validate_mod, "_stage_rescan", lambda *a, **k: StageResult("pass", "rescan ok")
        )
        report = validate_mod.validate_patch(
            diff_text="--- a/main.go\n+++ b/main.go\n",
            patched_source=GO_SOURCE,
            original_source=GO_SOURCE,
            language="go",
            target_rel_path="main.go",
            no_docker=True,
        )
        assert report.stages["compiles"].not_applicable is True
        # `behaves` and `tests` CAN run for Go, so under `no_docker` they genuinely did not.
        assert report.stages["behaves"].not_applicable is False
        assert report.stages["tests"].not_applicable is False

    def test_no_docker_leaves_python_compiles_a_plain_skip(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            validate_mod, "_stage_rescan", lambda *a, **k: StageResult("pass", "rescan ok")
        )
        report = validate_mod.validate_patch(
            diff_text="--- a/k.py\n+++ b/k.py\n",
            patched_source="import os\n\nprint(os.name)\n",
            original_source="import os\n\nprint(os.name)\n",
            language="python",
            target_rel_path="k.py",
            no_docker=True,
        )
        assert report.stages["compiles"].not_applicable is False
        assert report.stages["compiles"].detail == "no_docker configured"
