"""The statistics, checked against closed-form values rather than against themselves.

Every test here that asserts a number derives it independently — from the binomial mass function,
or from a construction whose answer is known by inspection. A statistics test that computes the
expected value with the code under test is a tautology, and a tautology in a significance test is
worse than no test at all.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

import pytest
from qubit_migrate.report.analysis import (
    BOOTSTRAP_DRAWS,
    COMPARISONS,
    bootstrap_rate,
    denominator_ladder,
    exact_mcnemar,
    holm,
    verified_accept,
    widest,
)


@dataclass
class Row:
    """A measurement row, only the fields the analysis reads."""

    path: str = "model"
    outcome: str = "accepted"
    vacuous: bool = False
    covered: bool = True
    file: str = "a.py"
    rule_id: str = "r1"
    stage_outcomes: dict[str, Any] = field(default_factory=lambda: {"tests": "pass"})


class TestVerifiedAccept:
    """The primary endpoint. Each condition excludes a specific past inflation."""

    def test_all_four_conditions_met(self) -> None:
        assert verified_accept(Row())

    def test_a_vacuous_expectation_disqualifies(self) -> None:
        """A criterion the asset could not fail is not evidence, however green."""
        assert not verified_accept(Row(vacuous=True))

    def test_skipped_tests_disqualify(self) -> None:
        """`tests` was skipped for 292 of 292 patches on this installation. Counting a skip as a
        pass is the assumption behind every retracted figure."""
        assert not verified_accept(Row(stage_outcomes={"tests": "skipped"}))
        assert not verified_accept(Row(stage_outcomes={}))

    def test_an_uncovered_line_disqualifies(self) -> None:
        """A finding on a line the suite never executes cannot be falsified by that suite."""
        assert not verified_accept(Row(covered=False))

    def test_a_rejected_patch_disqualifies(self) -> None:
        assert not verified_accept(Row(outcome="rejected"))


class TestDenominatorLadder:
    def test_each_stage_is_counted_separately(self) -> None:
        """Collapsing them is how the previous harness went wrong: `AlreadySatisfied` and
        `GuidedRemediation` were both recorded as errors, so two verdicts became failures."""
        rows = (
            [Row(path="no-rule", outcome="")] * 5
            + [Row(vacuous=True, outcome="accepted")] * 3
            + [Row(path="guided", outcome="guided")] * 4
            + [Row()] * 10
        )
        ladder = denominator_ladder(rows)
        assert ladder.total == 22
        assert ladder.no_rule == 5
        assert ladder.vacuous == 3
        assert ladder.guided == 4
        assert ladder.attempted == 13, "codemod + model only"
        assert ladder.accepted == 13
        assert ladder.verified == 10, "the vacuous three are accepted but not verified"

    def test_the_published_rows_subtract_in_order(self) -> None:
        rows = [Row(path="no-rule", outcome="")] * 2 + [Row()] * 8
        published = {name: n for name, n, _ in denominator_ladder(rows).as_rows()}
        assert published["total findings"] == 10
        assert published["minus no-rule"] == 8

    def test_verified_never_exceeds_accepted(self) -> None:
        """A structural invariant: verification is a subset of acceptance."""
        rows = [Row(covered=False)] * 4 + [Row()] * 6
        ladder = denominator_ladder(rows)
        assert ladder.verified <= ladder.accepted


class TestExactMcNemar:
    """Checked against the binomial mass function computed independently."""

    @pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 12])
    def test_a_one_sided_split_matches_the_closed_form(self, n: int) -> None:
        """With all discordant pairs favouring one arm, p = 2 * (1/2)^n."""
        result = exact_mcnemar([(False, True)] * n)
        assert result.p_value == pytest.approx(min(1.0, 2 * (0.5**n)))

    def test_a_mixed_split_matches_the_binomial_tail(self) -> None:
        """p = 2 * sum_{i<=k} C(n,i) / 2^n, computed here from `math.comb` directly."""
        a_only, b_only = 3, 9
        paired = [(True, False)] * a_only + [(False, True)] * b_only
        n, k = a_only + b_only, min(a_only, b_only)
        expected = min(1.0, 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2**n)
        assert exact_mcnemar(paired).p_value == pytest.approx(expected)

    def test_no_discordant_pairs_is_not_evidence_of_no_difference(self) -> None:
        """It is no evidence either way, and must not read as a confident null."""
        result = exact_mcnemar([(True, True)] * 40 + [(False, False)] * 40)
        assert result.discordant == 0
        assert result.p_value == 1.0

    def test_an_even_split_is_maximally_unsurprising(self) -> None:
        result = exact_mcnemar([(True, False)] * 6 + [(False, True)] * 6)
        assert result.p_value == pytest.approx(1.0)

    def test_concordant_pairs_do_not_affect_the_p_value(self) -> None:
        """McNemar conditions on the discordant pairs. Adding agreements changes the risk
        difference's denominator but not the test."""
        bare = exact_mcnemar([(True, False)] * 2 + [(False, True)] * 8)
        padded = exact_mcnemar([(True, False)] * 2 + [(False, True)] * 8 + [(True, True)] * 100)
        assert bare.p_value == pytest.approx(padded.p_value)
        assert bare.risk_difference != pytest.approx(padded.risk_difference)

    def test_the_risk_difference_has_the_sign_of_the_better_arm(self) -> None:
        assert exact_mcnemar([(True, False)] * 5).risk_difference > 0
        assert exact_mcnemar([(False, True)] * 5).risk_difference < 0

    def test_an_empty_comparison_does_not_divide_by_zero(self) -> None:
        result = exact_mcnemar([])
        assert result.p_value == 1.0
        assert result.risk_difference == 0.0


class TestHolm:
    def test_the_smallest_p_takes_the_full_correction(self) -> None:
        """Holm's first step is Bonferroni; only later steps relax."""
        assert holm({"a": 0.01, "b": 0.04, "c": 0.03})["a"] == pytest.approx(0.03)

    def test_adjusted_values_are_monotone(self) -> None:
        """Without enforcing it, a later comparison can be reported as more significant than an
        earlier one it cannot beat."""
        adjusted = holm({"a": 0.01, "b": 0.04, "c": 0.03})
        ordered = sorted(adjusted.items(), key=lambda kv: kv[1])
        assert [v for _, v in ordered] == sorted(v for _, v in ordered)
        assert adjusted["b"] >= adjusted["c"] >= adjusted["a"]

    def test_it_is_never_weaker_than_bonferroni_on_the_smallest(self) -> None:
        raw = {"a": 0.02, "b": 0.5, "c": 0.9}
        assert holm(raw)["a"] == pytest.approx(min(1.0, 3 * 0.02))

    def test_it_is_more_powerful_than_bonferroni_on_the_rest(self) -> None:
        """The reason for choosing Holm: same family-wise error rate, uniformly more power."""
        raw = {"a": 0.02, "b": 0.03, "c": 0.04}
        adjusted = holm(raw)
        assert adjusted["c"] < min(1.0, 3 * raw["c"])

    def test_values_are_capped_at_one(self) -> None:
        assert all(v <= 1.0 for v in holm({"a": 0.9, "b": 0.8, "c": 0.7}).values())

    def test_an_empty_family_is_empty(self) -> None:
        assert holm({}) == {}


class TestClusterBootstrap:
    """Clusters are files, not findings."""

    def test_it_resamples_clusters_not_rows(self) -> None:
        """The property that makes the interval honest.

        Twenty findings in ONE file carry the information of one file. Resampling rows would give
        a tight interval; resampling clusters must give a wide one, because a single draw can miss
        that file entirely.
        """
        rows = [Row(file="a.py", outcome="accepted") for _ in range(20)]
        rows += [Row(file="b.py", outcome="rejected") for _ in range(20)]
        ci = bootstrap_rate(
            rows,
            lambda r: r.outcome == "accepted",
            cluster_by=lambda r: r.file,
            cluster_name="file",
            draws=2000,
        )
        assert ci is not None
        assert ci.point == pytest.approx(0.5)
        # Two clusters, opposite outcomes: a resample can draw both of one, so the interval must
        # reach the extremes. A row-level bootstrap would report roughly 0.34-0.66.
        assert ci.low == pytest.approx(0.0)
        assert ci.high == pytest.approx(1.0)

    def test_a_single_cluster_returns_nothing(self) -> None:
        """An interval from one cluster describes that cluster's internal variation — exactly the
        correlation being corrected for. Reporting it is worse than reporting nothing."""
        rows = [Row(file="only.py") for _ in range(50)]
        assert (
            bootstrap_rate(rows, lambda r: True, cluster_by=lambda r: r.file, cluster_name="file")
            is None
        )

    def test_it_is_reproducible(self) -> None:
        rows = [Row(file=f"f{i}.py", outcome="accepted" if i % 3 else "rejected") for i in range(9)]
        kw = {"cluster_by": lambda r: r.file, "cluster_name": "file", "draws": 500}
        a = bootstrap_rate(rows, lambda r: r.outcome == "accepted", **kw)  # type: ignore[arg-type]
        b = bootstrap_rate(rows, lambda r: r.outcome == "accepted", **kw)  # type: ignore[arg-type]
        assert a == b

    def test_the_interval_brackets_the_point_estimate(self) -> None:
        rows = [
            Row(file=f"f{i}.py", outcome="accepted" if i < 7 else "rejected") for i in range(10)
        ]
        ci = bootstrap_rate(
            rows,
            lambda r: r.outcome == "accepted",
            cluster_by=lambda r: r.file,
            cluster_name="file",
            draws=2000,
        )
        assert ci is not None
        assert ci.low <= ci.point <= ci.high

    def test_the_wider_clustering_is_the_one_reported(self) -> None:
        """Pre-registered: file- and rule-clustered intervals are both computed and the WIDER is
        reported. Choosing per result would be choosing the answer."""
        rows = [Row(file=f"f{i}.py", rule_id="r1" if i < 5 else "r2") for i in range(10)]
        by_file = bootstrap_rate(
            rows,
            lambda r: r.file < "f5",
            cluster_by=lambda r: r.file,
            cluster_name="file",
            draws=1000,
        )
        by_rule = bootstrap_rate(
            rows,
            lambda r: r.file < "f5",
            cluster_by=lambda r: r.rule_id,
            cluster_name="rule",
            draws=1000,
        )
        chosen = widest(by_file, by_rule)
        assert chosen is not None
        assert chosen.width >= max(by_file.width, by_rule.width)  # type: ignore[union-attr]

    def test_widest_ignores_absent_clusterings(self) -> None:
        rows = [Row(file=f"f{i}.py") for i in range(4)]
        only = bootstrap_rate(
            rows, lambda r: True, cluster_by=lambda r: r.file, cluster_name="file", draws=200
        )
        assert widest(only, None) is only
        assert widest(None, None) is None


class TestThePreRegistration:
    def test_exactly_three_comparisons(self) -> None:
        """Named before any result was read. A fourth added later needs its own
        pre-registration."""
        assert len(COMPARISONS) == 3

    def test_the_ordering_check_is_not_among_them(self) -> None:
        """`B1-fwd vs B1-rev` bounds an ordering artefact; it is not a hypothesis and must not
        consume family-wise error budget."""
        assert ("B1-fwd", "B1-rev") not in COMPARISONS
        assert ("B1-rev", "B1-fwd") not in COMPARISONS

    def test_the_draw_count_is_fixed_in_the_module(self) -> None:
        """Not a parameter with a default that can be tuned until an interval looks good."""
        assert BOOTSTRAP_DRAWS == 10_000
