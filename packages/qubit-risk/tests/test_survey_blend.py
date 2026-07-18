"""Expert-survey CDF fit + hardware blend (doc 02 §6.1.4-6.1.5)."""

from __future__ import annotations

from qubit_risk.config import load_config
from qubit_risk.timeline.survey import BlendedTimeline, fit_survey_cdf


def test_survey_fit_recovers_anchor_midpoints() -> None:
    cfg = load_config()
    fit = fit_survey_cdf(cfg.expert_survey)
    # the fitted LogNormal should reproduce each anchor midpoint within a few points
    for a in cfg.expert_survey["anchors"]:
        mid = (a["p_low"] + a["p_high"]) / 2.0
        got = fit.cdf_at_year(fit.reference_year + a["years"])
        assert abs(got - mid) < 0.08, f"{a['years']}y: fit {got:.3f} vs anchor {mid:.3f}"


def test_survey_cdf_is_monotonic() -> None:
    fit = fit_survey_cdf(load_config().expert_survey)
    vals = [fit.cdf_at_year(fit.reference_year + y) for y in range(1, 40)]
    assert vals == sorted(vals)
    assert 0.0 <= vals[0] and vals[-1] <= 1.0


def test_blend_returns_valid_cdf() -> None:
    curve = BlendedTimeline().blend("RSA-2048")
    assert curve is not None
    assert curve.cdf == sorted(curve.cdf)  # monotonic
    assert 0.0 <= curve.cdf[0] and curve.cdf[-1] <= 1.0
    assert curve.p05_year and curve.median_year and curve.p95_year
    assert curve.p05_year <= curve.median_year <= curve.p95_year


def test_blend_weight_extremes_match_components() -> None:
    bt = BlendedTimeline()
    # w=1 -> pure hardware curve; w=0 -> pure survey curve (at the reference algo, delta=0)
    hw_only = bt.blend("RSA-2048", weight=1.0)
    survey_only = bt.blend("RSA-2048", weight=0.0)
    assert hw_only is not None and survey_only is not None

    hw = bt.sim.simulate("RSA-2048", window_days=1.0)
    assert hw is not None
    # pure-hardware blend equals the raw hardware curve
    assert hw_only.cdf == [round4(x) for x in hw.cdf] or _close(hw_only.cdf, hw.cdf)
    # pure-survey blend matches the fitted survey CDF at the reference algorithm (delta≈0)
    fit = bt.fit
    for year, p in zip(survey_only.years, survey_only.cdf, strict=True):
        assert abs(p - fit.cdf_at_year(year)) < 1e-6


def test_blend_algorithm_offset_orders_ecdsa_before_rsa() -> None:
    """ECDSA-P256 (cheaper to break) should not land later than RSA-2048 after blending."""
    bt = BlendedTimeline()
    rsa = bt.blend("RSA-2048")
    ecdsa = bt.blend("ECDSA-P256")
    if ecdsa is None:  # registry may not carry it; skip rather than fail
        return
    assert rsa is not None
    assert (ecdsa.median_year or 9999) <= (rsa.median_year or 9999) + 1


def test_blend_unknown_algorithm_returns_none() -> None:
    assert BlendedTimeline().blend("ML-KEM-768") is None


def round4(x: float) -> float:
    return round(x, 4)


def _close(a: list[float], b: list[float]) -> bool:
    return all(abs(x - y) < 1e-9 for x, y in zip(a, b, strict=True))
