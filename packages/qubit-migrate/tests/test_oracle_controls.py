"""Admission controls: the check that the oracle can fail before its passes are believed.

These tests are deliberately paranoid about the ways a control suite can look green while
establishing nothing, because that is the failure mode the module exists to prevent and it is
invisible from the outside.
"""

from __future__ import annotations

from typing import Any

import pytest
from qubit_migrate.oracles.controls import (
    CONTROLLED_FAMILIES,
    CONTROLS,
    Control,
    ControlReport,
    evaluate,
    run_controls,
)


def _verdict(status: str, **outcomes: str) -> dict[str, Any]:
    """A harness verdict with `outcomes` mapping relation id -> outcome."""
    return {
        "status": status,
        "reason": "",
        "relations": [{"id": k, "kind": "negative", "outcome": v} for k, v in outcomes.items()],
    }


_POSITIVE = Control(
    id="probe-positive",
    family="probe",
    usage_context="signature",
    target="ML-DSA-65",
    source="",
    expect="fail",
    caught_by=frozenset({"sig-wrong-key"}),
    survives=frozenset({"sig-roundtrip"}),
)
_NEGATIVE = Control(
    id="probe-negative",
    family="probe",
    usage_context="signature",
    target="ML-DSA-65",
    source="",
    expect="pass",
)


class TestSkippedIsNeverAControl:
    """An oracle that did not run has established nothing, in either direction."""

    def test_a_skipped_negative_control_is_a_failure(self) -> None:
        assert not evaluate(_NEGATIVE, _verdict("skipped")).ok

    def test_a_skipped_positive_control_is_a_failure(self) -> None:
        """Not "it failed, good" — it did not run, which is not the same claim."""
        assert not evaluate(_POSITIVE, _verdict("skipped")).ok


class TestAPositiveControlMustFailForTheRightReason:
    """The subtle half. Any failure satisfies a naive check, including a totally broken oracle."""

    def test_failing_on_the_expected_relation_is_accepted(self) -> None:
        outcome = evaluate(
            _POSITIVE, _verdict("fail", **{"sig-wrong-key": "fail", "sig-roundtrip": "pass"})
        )
        assert outcome.ok, outcome.detail

    def test_failing_on_some_other_relation_is_rejected(self) -> None:
        """An oracle that rejects everything also produces `status: fail`.

        Without this check it would be certified as working, and every subsequent `behaves: fail`
        would be attributed to the patch rather than to the instrument.
        """
        outcome = evaluate(
            _POSITIVE, _verdict("fail", **{"sig-truncated": "fail", "sig-roundtrip": "pass"})
        )
        assert not outcome.ok
        assert "not on the relations that are supposed to catch this" in outcome.detail

    def test_a_defect_visible_to_the_weaker_relations_is_rejected(self) -> None:
        """The fixture must demonstrate that the NEGATIVES are load-bearing.

        If the round trip also catches it, this control no longer supports the claim it exists to
        support — a plain smoke test would have sufficed, and the whole contribution rests on the
        cases where it does not.
        """
        outcome = evaluate(
            _POSITIVE, _verdict("fail", **{"sig-wrong-key": "fail", "sig-roundtrip": "fail"})
        )
        assert not outcome.ok
        assert "no longer demonstrates" in outcome.detail

    def test_a_positive_control_that_passes_is_rejected(self) -> None:
        """The headline failure: the oracle saw a known-broken patch and said yes."""
        outcome = evaluate(_POSITIVE, _verdict("pass", **{"sig-roundtrip": "pass"}))
        assert not outcome.ok
        assert "expected fail, observed pass" in outcome.detail


class TestTrustworthiness:
    def test_both_controls_are_required(self) -> None:
        report = ControlReport([evaluate(_NEGATIVE, _verdict("pass"))])
        assert not report.trustworthy("probe"), "one control is not a control suite"

    def test_a_family_with_no_controls_is_never_trustworthy(self) -> None:
        """Absence is not a licence. This is the `skipped == pass` error in another costume."""
        assert not ControlReport().trustworthy("signature")

    def test_both_passing_licenses_the_family(self) -> None:
        report = ControlReport(
            [
                evaluate(_NEGATIVE, _verdict("pass")),
                evaluate(
                    _POSITIVE,
                    _verdict("fail", **{"sig-wrong-key": "fail", "sig-roundtrip": "pass"}),
                ),
            ]
        )
        assert report.trustworthy("probe")
        assert report.families == frozenset({"probe"})

    def test_one_bad_control_revokes_the_family(self) -> None:
        report = ControlReport(
            [evaluate(_NEGATIVE, _verdict("fail")), evaluate(_POSITIVE, _verdict("fail"))]
        )
        assert not report.trustworthy("probe")


class TestRunner:
    def test_a_runner_that_raises_is_a_failed_control(self) -> None:
        """Not an error that propagates and aborts the run — a control that did not establish."""

        def boom(*_: object) -> dict[str, Any]:
            raise RuntimeError("no docker")

        report = run_controls(boom)
        assert report.outcomes
        assert not any(o.ok for o in report.outcomes)
        assert report.families == frozenset()

    def test_an_oracle_that_says_yes_to_everything_licenses_nothing(self) -> None:
        """The exact scenario the module exists for: if the container's library shadows the
        patched module, every relation exercises a correct implementation and passes."""
        report = run_controls(lambda *_: _verdict("pass", **{"sig-roundtrip": "pass"}))
        assert report.families == frozenset()

    def test_families_can_be_narrowed(self) -> None:
        report = run_controls(lambda *_: _verdict("skipped"), families=frozenset({"hash"}))
        assert {o.control.family for o in report.outcomes} == {"hash"}


class TestTheFixturesThemselves:
    @pytest.mark.parametrize("family", sorted(CONTROLLED_FAMILIES))
    def test_every_family_has_both_directions(self, family: str) -> None:
        expectations = {c.expect for c in CONTROLS if c.family == family}
        assert expectations == {"pass", "fail"}, family

    @pytest.mark.parametrize(
        "control", [c for c in CONTROLS if c.expect == "fail"], ids=lambda c: c.id
    )
    def test_every_positive_control_names_what_must_catch_it(self, control: Control) -> None:
        """Without `caught_by` the control is satisfied by any failure at all."""
        assert control.caught_by, control.id

    @pytest.mark.parametrize(
        "control", [c for c in CONTROLS if c.expect == "fail"], ids=lambda c: c.id
    )
    def test_every_positive_control_names_what_must_miss_it(self, control: Control) -> None:
        """`survives` is what makes the fixture evidence for the contribution rather than for a
        smoke test: the defect must be invisible to the weaker relations."""
        assert control.survives, control.id
        assert not (control.caught_by & control.survives), control.id

    def test_the_report_is_serializable(self) -> None:
        report = run_controls(lambda *_: _verdict("skipped"))
        payload = report.as_dict()
        assert len(payload["controls"]) == len(CONTROLS)
        assert payload["trustworthy_families"] == []


class TestTheGateInTheStage:
    """`behaves` must refuse to award evidence for a family the controls have not licensed.

    Exercised against the real stage rather than the report object, because the property that
    matters is what `validate_patch` records — a `ControlReport` that knows a family is untrusted
    is useless if the stage never asks it.
    """

    @staticmethod
    def _rule() -> object:
        from qubit_migrate.transform.rules import MigrationRule

        return MigrationRule(
            id="probe",
            language="python",
            title="ECDSA -> ML-DSA",
            matches={"algorithm": ["ECDSA"]},
            target={"algorithm": "ML-DSA-65"},
            codemod=None,
            prompt_constraints=[],
            remediation="auto",
            rescan_expect=None,
        )

    _CORRECT = (
        "from cryptography.hazmat.primitives.asymmetric import mldsa\n\n\n"
        "def k():\n    return mldsa.MLDSA65PrivateKey.generate()\n"
    )

    def test_an_unlicensed_family_is_skipped_not_passed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A correct patch, an oracle that would pass it, and no licence. Must skip.

        This is the whole module in one assertion: the verdict is not the question, the
        trustworthiness of the instrument that produced it is.
        """
        from qubit_migrate.transform import validate as validate_module

        monkeypatch.setattr(validate_module, "_verified_families", frozenset())
        monkeypatch.setattr(validate_module, "_docker_available", lambda: True)
        monkeypatch.setattr(validate_module, "_image_present", lambda _image: True)

        result = validate_module._stage_behaves(
            self._CORRECT, self._rule(), "python", "signature", "pure"
        )
        assert result.status == "skipped", result.detail
        assert "admission controls have not licensed" in result.detail

    def test_a_licensed_family_produces_a_verdict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The control for the control: with the licence present, the same patch is judged.

        Without this the test above would also pass if the stage were broken in some other way,
        and would be measuring nothing.
        """
        from qubit_migrate.transform import validate as validate_module

        monkeypatch.setattr(validate_module, "_verified_families", frozenset({"signature"}))
        monkeypatch.setattr(validate_module, "_docker_available", lambda: True)
        monkeypatch.setattr(validate_module, "_image_present", lambda _image: True)
        monkeypatch.setattr(
            validate_module,
            "_run_oracle",
            lambda *_: _verdict("pass", **{"sig-roundtrip": "pass"}),
        )

        result = validate_module._stage_behaves(
            self._CORRECT, self._rule(), "python", "signature", "pure"
        )
        assert result.status == "pass", result.detail
