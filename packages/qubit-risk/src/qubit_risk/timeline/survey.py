"""Expert-survey CDF fit + hardware blend (doc 02 §6.1.4-6.1.5).

The absolute CRQC calibration comes from the 26-expert GRI-2025 aggregate; the *relative*
difficulty between algorithms comes from the physics-based hardware Monte-Carlo. We fit a
LogNormal F_survey(t) to the survey anchor midpoints, then blend:

    F_a(T) = w · F_hw_a@24h(T) + (1-w) · F_survey(T - ref_year - Δ(a))

where Δ(a) is the physics-derived offset q25(F_hw_a) - q25(F_hw_RSA2048), both computed at a
matched 24h attack window (the survey asks about RSA-2048-in-24h).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.optimize import curve_fit

from ..config import RiskConfig, load_config
from .simulator import CRQCTimelineSimulator, TimelineCurve

# The survey references RSA-2048 broken in 24h, so every hardware curve used in the blend
# is computed at this window (doc 02 §6.1.4) — NOT the 30-day standalone risk-scenario window.
_SURVEY_WINDOW_DAYS = 1.0


def _lognormal_cdf(t: np.ndarray, mu: float, sigma: float) -> np.ndarray:
    """LogNormal CDF F(t) = Φ((ln t - μ)/sigma) for t > 0, 0 otherwise."""
    t = np.asarray(t, dtype=np.float64)
    out = np.zeros_like(t)
    pos = t > 0
    from scipy.stats import norm

    out[pos] = norm.cdf((np.log(t[pos]) - mu) / sigma)
    return out


@dataclass(frozen=True)
class SurveyFit:
    mu: float
    sigma: float
    reference_year: int
    anchor_years: list[int]
    anchor_p: list[float]

    def cdf_at_year(self, year: float) -> float:
        """F_survey evaluated at a calendar year (t = year - reference_year)."""
        return float(_lognormal_cdf(np.array([year - self.reference_year]), self.mu, self.sigma)[0])


def fit_survey_cdf(expert_survey: dict) -> SurveyFit:
    """Least-squares LogNormal fit to the survey anchor midpoints (doc 02 §6.1.4)."""
    anchors = expert_survey["anchors"]
    years = np.array([a["years"] for a in anchors], dtype=np.float64)
    mids = np.array([(a["p_low"] + a["p_high"]) / 2.0 for a in anchors], dtype=np.float64)

    # fit F(years) = Φ((ln years - μ)/sigma); seed from a plausible ~15y median, sigma≈0.5
    (mu, sigma), _ = curve_fit(
        lambda t, mu, sigma: _lognormal_cdf(t, mu, sigma),
        years,
        mids,
        p0=[np.log(15.0), 0.5],
        maxfev=10000,
    )
    return SurveyFit(
        mu=float(mu),
        sigma=float(abs(sigma)),
        reference_year=int(expert_survey["reference_year"]),
        anchor_years=[int(y) for y in years],
        anchor_p=[float(p) for p in mids],
    )


class BlendedTimeline:
    """Blends the hardware Monte-Carlo CDF with the expert-survey CDF (doc 02 §6.1.5)."""

    def __init__(self, config: RiskConfig | None = None) -> None:
        self.cfg = config or load_config()
        self.sim = CRQCTimelineSimulator(self.cfg)
        self.fit = fit_survey_cdf(self.cfg.expert_survey)
        self._ref_alg = self.cfg.expert_survey.get("reference_algorithm", "RSA-2048")

    def _q25(self, curve: TimelineCurve) -> float:
        """First calendar year with F ≥ 0.25 (guaranteed for blended algos, doc 02 §6.1.5)."""
        for year, p in zip(curve.years, curve.cdf, strict=True):
            if p >= 0.25:
                return float(year)
        return float(curve.years[-1])  # beyond_horizon fallback

    def blend(self, algorithm: str, *, weight: float | None = None) -> TimelineCurve | None:
        """Return the blended CDF for a Shor-vulnerable algorithm, or None if unknown."""
        w = self.cfg.survey_weight if weight is None else weight
        hw = self.sim.simulate(algorithm, window_days=_SURVEY_WINDOW_DAYS)
        if hw is None:
            return None

        ref = self.sim.simulate(self._ref_alg, window_days=_SURVEY_WINDOW_DAYS)
        # algorithm offset Δ(a): how much earlier/later than the survey's RSA-2048 reference
        delta = self._q25(hw) - self._q25(ref) if ref is not None else 0.0

        years = hw.years
        blended = []
        for year, f_hw in zip(years, hw.cdf, strict=True):
            f_survey = self.fit.cdf_at_year(year - delta)
            blended.append(w * f_hw + (1.0 - w) * f_survey)

        # keep the hardware SE band (survey fit adds systematic, not sampling, uncertainty)
        return TimelineCurve(
            algorithm=algorithm,
            years=years,
            cdf=[float(x) for x in blended],
            cdf_stderr=hw.cdf_stderr,
            median_year=_first_year_at(years, blended, 0.5),
            p05_year=_first_year_at(years, blended, 0.05),
            p95_year=_first_year_at(years, blended, 0.95),
            n_trials=hw.n_trials,
            params_hash=self.cfg.params_hash,
        )


def _first_year_at(years: list[int], cdf: list[float], q: float) -> float | None:
    for year, p in zip(years, cdf, strict=True):
        if p >= q:
            return float(year)
    return None


__all__ = ["BlendedTimeline", "SurveyFit", "fit_survey_cdf"]
