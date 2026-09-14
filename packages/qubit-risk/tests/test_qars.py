"""QARS — the published model, and the two calibration constraints it must satisfy.

This is adopted prior work (Electronics 2025, 14, 3338), so the tests are written against the
paper's own equations and its own stated constraints rather than against whatever the code happens
to do. Where a test asserts a number, that number comes from the publication.
"""

from __future__ import annotations

import pytest
from qubit_core import (
    AssetType,
    CryptoAsset,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    Sensitivity,
    SourceScanner,
    UsageContext,
    utcnow,
)
from qubit_risk.pipeline import RiskPipeline
from qubit_risk.qars import (
    DEFAULT_ALPHA,
    GROVER_ALPHA_T,
    SECTOR_WEIGHTS,
    SENSITIVITY_GRADE,
    QarsInputs,
    f_expos,
    f_sens,
    f_time,
    score,
    weights_for,
)

#: The paper's stage-2 calibration constraint: `X > 10` years with `Z = 8` should yield
#: `QARS > 0.70`.
_CALIBRATION = QarsInputs(
    shelf_life_years=11,
    migration_years=1,
    crqc_years=8,
    sensitivity="critical",
    harvestability=1.0,
)


class TestTheEquations:
    def test_weights_sum_to_one_for_every_published_sector(self) -> None:
        """Eq. (2) requires it. A profile that does not sum to 1 silently rescales the whole
        score, so every asset in that sector becomes incomparable with every other."""
        for sector, weights in SECTOR_WEIGHTS.items():
            assert sum(weights) == pytest.approx(1.0), sector
            assert all(w >= 0 for w in weights), sector

    def test_mosca_threshold_maps_to_the_neutral_midpoint(self) -> None:
        """Eq. (4). `r = 1` IS Mosca's binary condition `X + Y = Z`, and the logistic must put it
        at exactly 0.5 — that correspondence is why the logistic was chosen over `min(1, r)`."""
        assert f_time(1.0) == pytest.approx(0.5)

    def test_the_timeline_function_is_monotonic(self) -> None:
        """A later CRQC horizon can never raise urgency."""
        values = [f_time(r) for r in (0.25, 0.5, 1.0, 1.5, 2.0, 4.0)]
        assert values == sorted(values)

    def test_an_extreme_ratio_does_not_overflow(self) -> None:
        """A thirty-year shelf life against a one-year horizon is realistic input, and
        `math.exp` overflows near ±710."""
        assert f_time(1e6) == pytest.approx(1.0)
        assert f_time(-1e6) == pytest.approx(0.0)

    def test_the_sensitivity_grades_are_the_published_ones(self) -> None:
        """Eq. (5): `g(Low) = 0.25 … g(Critical) = 1.0`."""
        assert SENSITIVITY_GRADE == {
            "low": 0.25,
            "moderate": 0.50,
            "high": 0.75,
            "critical": 1.00,
        }

    def test_an_unknown_sensitivity_is_moderate_not_harmless(self) -> None:
        """Scoring an unclassified asset as zero-risk is the failure that makes a risk register
        useless: the assets nobody has classified are the ones nobody has looked at."""
        assert f_sens("not-a-label") == 0.50
        assert f_sens("") == 0.50
        assert f_sens("CRITICAL") == 1.00, "the label must be case-insensitive"

    def test_exposure_is_the_product(self) -> None:
        """Eqs. (6)-(8): `E = v * q`."""
        assert f_expos(1.0, 0.8) == pytest.approx(0.8)
        assert f_expos(0.0, 1.0) == 0.0

    def test_exposure_is_clamped(self) -> None:
        """A harvestability of 1.4 from a mis-scaled input must not push the score above 1."""
        assert f_expos(1.0, 1.4) == pytest.approx(1.0)
        assert f_expos(-1.0, 1.0) == 0.0


class TestTheCalibrationConstraints:
    """The two acceptance criteria the build plan names."""

    def test_the_papers_own_constraint_is_met(self) -> None:
        """`X > 10` with `Z = 8` and `D = Critical` must clear 0.70. Measured: 0.9603."""
        assert score(_CALIBRATION).qars > 0.70

    def test_a_grover_asset_ranks_below_a_shor_asset_at_equal_inputs(self) -> None:
        """Electronics 15(12):2546.

        Grover is a QUADRATIC speedup; Shor collapses RSA outright. Without attenuation AES-256
        inflates urgency it does not deserve and competes with RSA-2048 for the operator's
        attention — the whole point of a ranked register is that it does not.
        """
        common = {
            "shelf_life_years": 10,
            "migration_years": 1,
            "crqc_years": 8,
            "sensitivity": "critical",
            "harvestability": 1.0,
        }
        shor = score(QarsInputs(**common))
        grover = score(QarsInputs(**common, symmetric=True))
        assert grover.qars < shor.qars
        assert grover.attenuated is True
        assert shor.attenuated is False

    def test_attenuation_never_zeroes_a_symmetric_asset(self) -> None:
        """The residual risk is real — side channels, key-management failure, cross-layer
        compromise — so a symmetric asset stays on the register rather than dropping off it."""
        grover = score(
            QarsInputs(
                shelf_life_years=10,
                migration_years=1,
                crqc_years=8,
                sensitivity="critical",
                harvestability=1.0,
                symmetric=True,
            )
        )
        assert grover.qars > 0.0

    def test_the_timeline_attenuation_is_the_published_sixth(self) -> None:
        """The LITERAL one sixth, not `GROVER_ALPHA_T` compared against itself.

        Asserting `attenuated == plain * GROVER_ALPHA_T` is a tautology: changing the constant
        changes both sides, so the test passes for any value including 1.0, which is no
        attenuation at all. The published coefficient is the thing under test, so it is written
        out.
        """
        assert GROVER_ALPHA_T == pytest.approx(1 / 6)
        common = {
            "shelf_life_years": 10,
            "migration_years": 1,
            "crqc_years": 8,
            "sensitivity": "critical",
            "harvestability": 1.0,
        }
        plain = score(QarsInputs(**common))
        attenuated = score(QarsInputs(**common, symmetric=True))
        assert attenuated.timeline == pytest.approx(plain.timeline / 6.0)


class TestVisibilityFallsAfterMigration:
    """The one QARS input QUBIT can watch change, which the original model cannot."""

    def test_a_migrated_asset_has_zero_exposure(self) -> None:
        """The authors state the consequence explicitly: `v = 0` gives `E = 0` regardless of how
        exposed the asset is."""
        before = QarsInputs(
            shelf_life_years=10,
            migration_years=1,
            crqc_years=8,
            sensitivity="critical",
            harvestability=1.0,
        )
        after = QarsInputs(**{**before.__dict__, "visibility": 0.0})
        assert score(before).exposure == pytest.approx(1.0)
        assert score(after).exposure == 0.0
        assert score(after).qars < score(before).qars


class TestReproducibility:
    """A score without its weights is not reproducible."""

    def test_the_components_and_weights_travel_with_the_number(self) -> None:
        payload = score(_CALIBRATION, sector="finance", regime="anssi").as_dict()
        assert set(payload["components"]) == {"timeline", "sensitivity", "exposure"}
        assert payload["weights"] == {"w_T": 0.4, "w_S": 0.4, "w_E": 0.2}
        assert payload["sector"] == "finance"
        assert payload["alpha"] == DEFAULT_ALPHA
        assert payload["regime"] == "anssi"

    def test_the_model_is_attributed_in_the_stored_record(self) -> None:
        """Adopted prior work. The citation must be impossible to lose in transit."""
        assert "Electronics 2025, 14, 3338" in score(_CALIBRATION).as_dict()["model"]

    def test_the_same_asset_scores_differently_under_different_sectors(self) -> None:
        """Which is exactly why a bare stored figure cannot be told from a mis-scored one."""
        scores = {s: score(_CALIBRATION, sector=s).qars for s in SECTOR_WEIGHTS}
        assert len(set(round(v, 4) for v in scores.values())) > 1, scores

    def test_an_unknown_sector_falls_back_to_baseline_thirds(self) -> None:
        """Silently picking a sector would embed a judgement about the operator's business into a
        number they are meant to read as neutral."""
        assert weights_for("not-a-sector") == SECTOR_WEIGHTS["baseline"]
        assert weights_for("") == SECTOR_WEIGHTS["baseline"]


class TestDegenerateInputs:
    def test_a_zero_crqc_horizon_does_not_divide_by_zero(self) -> None:
        """A real input: an operator who believes a CRQC exists today enters 0."""
        result = score(
            QarsInputs(
                shelf_life_years=5,
                migration_years=1,
                crqc_years=0,
                sensitivity="high",
                harvestability=0.5,
            )
        )
        assert result.ratio == float("inf")
        assert result.timeline == pytest.approx(1.0)
        assert result.too_late is True
        assert any("already passed" in n for n in result.notes)

    def test_the_score_stays_within_the_unit_interval(self) -> None:
        for shelf in (0, 1, 10, 100):
            for crqc in (1, 8, 50):
                result = score(
                    QarsInputs(
                        shelf_life_years=shelf,
                        migration_years=1,
                        crqc_years=crqc,
                        sensitivity="critical",
                        harvestability=1.0,
                    )
                )
                assert 0.0 <= result.qars <= 1.0, (shelf, crqc, result.qars)


class TestWhatIsDeliberatelyAbsent:
    def test_no_quantum_amplitude_estimation(self) -> None:
        """QAE for tail risk belongs to a quantum-finance credit-risk model that shares the
        acronym, not to QARS. It was in an early draft of this project's own writing and had to be
        retracted; asserting its absence keeps it retracted."""
        import qubit_risk.qars as module

        source = module.__doc__ or ""
        names = [n.lower() for n in dir(module)]
        assert not any("amplitude" in n for n in names)
        assert "Quantum Amplitude Estimation" in source, (
            "the exclusion should be documented, not merely absent"
        )


class TestThroughTheRiskPipeline:
    """QARS on real assets, scored by the pipeline that already computes its inputs.

    Exercised here rather than only at the function level because the wiring is where the value
    is: `Z` must come from the same horizon the Mosca margin uses, and `v` must come from the
    scanner's verdict rather than from a stored flag, or exposure never changes.
    """

    @staticmethod
    def _asset(algorithm: str, attack: QuantumAttack, vulnerable: bool = True) -> CryptoAsset:
        return CryptoAsset(
            algorithm=algorithm,
            usage_context=UsageContext.kex,
            source_scanner=SourceScanner.code,
            asset_type=AssetType.algorithm_use,
            location=Location(file_path="pkg/net.py", line=3),
            quantum_vulnerable=QuantumVulnerability(vulnerable=vulnerable, attack=attack),
            sensitivity=Sensitivity.credentials,
            evidence=Evidence(),
            discovered_at=utcnow(),
        )

    def test_every_assessed_asset_carries_a_qars_score(self) -> None:
        pipeline = RiskPipeline()
        (asset,) = pipeline.assess([self._asset("RSA-2048", QuantumAttack.shor)])
        assert asset.risk is not None
        assert asset.risk.qars is not None
        assert 0.0 <= asset.risk.qars["qars"] <= 1.0

    def test_the_stored_record_is_reproducible(self) -> None:
        """Components, weights, sector and the citation all travel with the number."""
        pipeline = RiskPipeline()
        (asset,) = pipeline.assess([self._asset("RSA-2048", QuantumAttack.shor)])
        assert asset.risk is not None and asset.risk.qars is not None
        payload = asset.risk.qars
        assert set(payload["components"]) == {"timeline", "sensitivity", "exposure"}
        assert set(payload["weights"]) == {"w_T", "w_S", "w_E"}
        assert payload["sector"] == "baseline"
        assert "Electronics 2025, 14, 3338" in payload["model"]

    def test_z_agrees_with_the_mosca_margin(self) -> None:
        """Two numbers on one dashboard that disagreed about when the CRQC arrives would be worse
        than either alone, so `Z` is recovered from the margin rather than re-derived."""
        pipeline = RiskPipeline()
        (asset,) = pipeline.assess([self._asset("RSA-2048", QuantumAttack.shor)])
        assert asset.risk is not None and asset.risk.qars is not None
        # margin = Z - (X + Y) and r = (X + Y) / Z, so a positive margin means r < 1 and vice
        # versa. The two must never disagree about which side of Mosca's line the asset is on.
        assert (asset.risk.mosca_margin_years < 0) == asset.risk.qars["too_late"]

    def test_a_grover_asset_is_attenuated_by_the_pipeline(self) -> None:
        pipeline = RiskPipeline()
        (asset,) = pipeline.assess([self._asset("MD5", QuantumAttack.grover)])
        assert asset.risk is not None and asset.risk.qars is not None
        assert asset.risk.qars["grover_attenuated"] is True

    def test_a_shor_asset_is_not_attenuated(self) -> None:
        """The control: without it the test above would pass if everything were attenuated."""
        pipeline = RiskPipeline()
        (asset,) = pipeline.assess([self._asset("RSA-2048", QuantumAttack.shor)])
        assert asset.risk is not None and asset.risk.qars is not None
        assert asset.risk.qars["grover_attenuated"] is False

    def test_exposure_falls_once_the_asset_is_no_longer_shor_breakable(self) -> None:
        """4.3 — `v(a)` recomputed from the scanner's verdict, so exposure becomes OBSERVABLE.

        This is the one QARS input the original model cannot watch change: it assumes `v` is known.
        QUBIT rescans the patched source, and a successful migration turns a Shor-breakable finding
        into one that is not, which drives `E` to zero and the score down.
        """
        pipeline = RiskPipeline()
        before, after = pipeline.assess(
            [
                self._asset("RSA-2048", QuantumAttack.shor),
                # What the same call site looks like after a successful migration: the scanner no
                # longer reports a Shor-breakable primitive there.
                self._asset("ML-KEM-768", QuantumAttack.none, vulnerable=False),
            ]
        )
        assert before.risk is not None and before.risk.qars is not None
        assert after.risk is not None and after.risk.qars is not None
        assert before.risk.qars["components"]["exposure"] > 0.0
        assert after.risk.qars["components"]["exposure"] == 0.0
        assert after.risk.qars["qars"] < before.risk.qars["qars"]

    def test_a_grover_asset_ranks_below_a_shor_asset_in_a_real_assessment(self) -> None:
        """The measured claim, through the pipeline rather than through hand-built inputs."""
        pipeline = RiskPipeline()
        shor, grover = pipeline.assess(
            [
                self._asset("RSA-2048", QuantumAttack.shor),
                self._asset("AES-256", QuantumAttack.grover),
            ]
        )
        assert shor.risk is not None and shor.risk.qars is not None
        assert grover.risk is not None and grover.risk.qars is not None
        assert grover.risk.qars["qars"] < shor.risk.qars["qars"]
