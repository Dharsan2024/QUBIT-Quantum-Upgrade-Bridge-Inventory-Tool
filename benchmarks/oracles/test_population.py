"""The estimator's own claims, pinned against populations whose true size is known.

A population estimator is exactly the kind of code that cannot be checked by reading it. It returns
a plausible number for any input, and on real corpora there is nothing to compare that number
against -- which is the whole reason it exists. So it is checked here against simulations where the
true N is chosen in advance, including the case that matters: detectors that are NOT independent.

The uncomfortable test is `test_heterogeneity_defeats_every_estimator`. It fails if someone later
"improves" this module into claiming accuracy it does not have.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from population import (
    agreement_matrix,
    capture_histories,
    chapman_estimate,
    loglinear_estimate,
    stratified_proportion,
    wilson_interval,
)

TRUE_N = 1000


def _simulate(
    probabilities: list[float], *, seed: int, hard_fraction: float = 0.0, hard_factor: float = 0.12
) -> dict[str, set[tuple[str, str]]]:
    """Capture `TRUE_N` sites with per-detector probabilities.

    With `hard_fraction > 0` that share of the population becomes hard for EVERY detector at once,
    which is heterogeneity plus positive correlation -- the real-world regime.
    """
    random.seed(seed)
    sites: dict[str, set[tuple[str, str]]] = {f"d{i}": set() for i in range(len(probabilities))}
    boundary = int(TRUE_N * hard_fraction)
    for index in range(TRUE_N):
        hard = index < boundary
        for detector, probability in enumerate(probabilities):
            effective = probability * hard_factor if hard else probability
            if random.random() < effective:  # noqa: S311 — a simulation, not a keystream
                sites[f"d{detector}"].add((str(index), "X"))
    return sites


class TestChapman:
    def test_matches_the_closed_form_on_a_textbook_case(self) -> None:
        """n1=n2=100, m=50 implies a population of about 200."""
        estimate = chapman_estimate(100, 100, 50)
        assert estimate.total.point == pytest.approx(199.0, abs=0.5)

    def test_recovers_a_known_population_when_detectors_are_independent(self) -> None:
        sites = _simulate([0.6, 0.5], seed=7)
        n1, n2 = len(sites["d0"]), len(sites["d1"])
        estimate = chapman_estimate(n1, n2, len(sites["d0"] & sites["d1"]))
        assert estimate.total.low <= TRUE_N <= estimate.total.high, (
            f"95% interval {estimate.total} excludes the true N={TRUE_N}"
        )

    def test_is_defined_when_the_detectors_share_nothing(self) -> None:
        """Plain Lincoln-Petersen divides by zero here. A hard corpus produces exactly this."""
        estimate = chapman_estimate(10, 10, 0)
        assert estimate.total.point > 0
        assert any("no findings" in c or "share no findings" in c for c in estimate.caveats)

    def test_never_reports_fewer_sites_than_were_actually_seen(self) -> None:
        """A near-total overlap can push Chapman below the union, which is impossible."""
        estimate = chapman_estimate(100, 100, 100)
        assert estimate.total.point >= estimate.observed
        assert estimate.missed_by_all >= 0

    def test_rejects_an_overlap_larger_than_a_detector_found(self) -> None:
        with pytest.raises(ValueError, match="exceeds"):
            chapman_estimate(10, 5, 8)


class TestLogLinear:
    def test_recovers_a_known_population_from_three_independent_detectors(self) -> None:
        sites = _simulate([0.6, 0.5, 0.4], seed=7)
        estimate = loglinear_estimate(capture_histories(sites))
        assert estimate.total.low <= TRUE_N <= estimate.total.high, (
            f"95% interval {estimate.total} excludes the true N={TRUE_N}"
        )

    def test_two_detectors_are_refused(self) -> None:
        """With k=2 the correlation is not identifiable -- it can only be assumed away."""
        sites = _simulate([0.6, 0.5], seed=7)
        with pytest.raises(ValueError, match=">= 3 detectors"):
            loglinear_estimate(capture_histories(sites))

    def test_a_saturated_model_is_refused_rather_than_fitted(self) -> None:
        """Three pairwise interactions on three detectors uses up every observable cell."""
        sites = _simulate([0.6, 0.5, 0.4], seed=7)
        with pytest.raises(ValueError, match="parameters"):
            loglinear_estimate(capture_histories(sites), interactions=[(0, 1), (0, 2), (1, 2)])

    def test_the_independence_model_says_so_in_its_caveats(self) -> None:
        sites = _simulate([0.6, 0.5, 0.4], seed=7)
        estimate = loglinear_estimate(capture_histories(sites))
        assert any("independence" in c for c in estimate.caveats)


class TestTheLimitsAreReal:
    """The results this module is NOT allowed to quietly start overclaiming."""

    def test_heterogeneity_defeats_every_estimator(self) -> None:
        """Half the population hard for everyone: all estimators land far below the truth.

        This is the honest headline. Capture-recapture here establishes a FLOOR on what was missed,
        not an estimate of it, and the README and docstring both say so. If a future change makes
        this test fail by producing an accurate estimate, that is a real result and this test should
        be rewritten -- but it must not fail because someone stopped simulating the hard case.
        """
        sites = _simulate([0.85, 0.80, 0.75], seed=11, hard_fraction=0.5)
        table = capture_histories(sites)

        n1, n2 = len(sites["d0"]), len(sites["d1"])
        two_source = chapman_estimate(n1, n2, len(sites["d0"] & sites["d1"]))
        independence = loglinear_estimate(table)
        correlated = loglinear_estimate(table, interactions=[(0, 1), (0, 2)])

        for label, estimate in [
            ("chapman", two_source),
            ("independence", independence),
            ("correlated", correlated),
        ]:
            assert estimate.total.point < TRUE_N * 0.8, (
                f"{label} reported {estimate.total.point:.0f} against a true {TRUE_N}: if the "
                "estimator really became this accurate under heterogeneity, update the docs"
            )

        # Modelling the correlation moves the estimate the right way, even though it cannot close
        # the gap. That direction is the only thing the extra terms are claimed to buy.
        assert correlated.total.point > independence.total.point > two_source.total.point

    def test_a_two_source_estimate_carries_its_bias_direction(self) -> None:
        estimate = chapman_estimate(619, 529, 332)
        assert any("UPPER bound" in c for c in estimate.caveats)
        assert any("floor" in c for c in estimate.caveats)


class TestWilson:
    def test_never_leaves_the_unit_interval(self) -> None:
        """The reason this is not the normal approximation: 4/4 must not have a negative bound."""
        for successes, trials in [(4, 4), (0, 4), (1, 3), (0, 1), (97, 100)]:
            interval = wilson_interval(successes, trials)
            assert 0.0 <= interval.low <= interval.point <= interval.high <= 1.0

    def test_a_perfect_score_on_four_trials_is_not_certainty(self) -> None:
        interval = wilson_interval(4, 4)
        assert interval.point == 1.0
        assert interval.low < 0.6, "4/4 should not imply better than 60% with any confidence"

    def test_empty_evidence_is_not_an_error(self) -> None:
        assert wilson_interval(0, 0).point == 0.0


class TestStratifiedProportion:
    def test_weights_strata_by_population_not_by_sample_size(self) -> None:
        """The error this exists to prevent.

        A tiny stratum sampled exhaustively and a huge one sampled lightly must not contribute
        equally. Here 90% of the population is 100% true and 10% is 0% true, so the answer is 0.9 --
        even though the samples are the same size and a raw pooled ratio would say 0.5.
        """
        result = stratified_proportion([(900, 50, 50), (100, 50, 0)])
        assert result.point == pytest.approx(0.9, abs=1e-9)

    def test_an_exhaustively_sampled_stratum_contributes_no_variance(self) -> None:
        """Finite-population correction: sample everything and there is nothing left to guess."""
        result = stratified_proportion([(50, 50, 25)])
        assert result.low == pytest.approx(result.high, abs=1e-9)

    def test_empty_input_is_not_an_error(self) -> None:
        assert stratified_proportion([]).point == 0.0


class TestAgreement:
    def test_identical_detectors_agree_completely(self) -> None:
        sites = {"a": {("f.go", "RSA")}, "b": {("f.go", "RSA")}}
        assert agreement_matrix(sites)[("a", "b")] == 1.0

    def test_disjoint_detectors_agree_not_at_all(self) -> None:
        sites = {"a": {("f.go", "RSA")}, "b": {("g.go", "AES")}}
        assert agreement_matrix(sites)[("a", "b")] == 0.0
