"""Mosca inequality (doc 02 6.5): is data safe long enough?

margin = Z - (X + Y):  Z = years until CRQC (timeline percentile),
X = data shelf-life (P90), Y = migration effort. Negative margin =>
data is decryptable before it stops mattering (too late).
p_too_late = F_a(now + X + Y) = P(CRQC arrives before migration).
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import RiskConfig
from .timeline import TimelineCurve


@dataclass(frozen=True)
class MoscaResult:
    margin_years: float
    p_too_late: float
    z_year: float | None  # CRQC arrival year at the chosen percentile
    x_years: float  # shelf-life P90
    y_years: float  # migration effort


def _cdf_at(curve: TimelineCurve, year: float) -> float:
    if year <= curve.years[0]:
        return curve.cdf[0]
    if year >= curve.years[-1]:
        return curve.cdf[-1]
    lo = int(year) - curve.years[0]
    frac = year - int(year)
    return curve.cdf[lo] * (1 - frac) + curve.cdf[lo + 1] * frac


def migration_years(cfg: RiskConfig, usage_context: str, override: float | None = None) -> float:
    m = cfg.mosca
    defaults = m["default_migration_years"]
    base = override if override is not None else defaults.get(
        usage_context, 0.5,
    )
    return float(base) + float(m["org_overhead_years"])


def mosca(
    curve: TimelineCurve,
    *,
    shelf_p90: float,
    y_years: float,
    now_year: int,
    z_percentile: float | None = None,
) -> MoscaResult:
    zp = z_percentile if z_percentile is not None else 0.5
    z_year = _percentile_year(curve, zp)
    z_margin = (z_year - now_year) if z_year is not None else float(curve.years[-1] - now_year)
    margin = z_margin - (shelf_p90 + y_years)
    p_too_late = _cdf_at(curve, now_year + shelf_p90 + y_years)
    return MoscaResult(
        margin_years=round(margin, 2),
        p_too_late=round(p_too_late, 4),
        z_year=z_year,
        x_years=shelf_p90,
        y_years=y_years,
    )


def _percentile_year(curve: TimelineCurve, q: float) -> float | None:
    for year, f in zip(curve.years, curve.cdf, strict=True):
        if f >= q:
            return float(year)
    return None


__all__ = ["MoscaResult", "migration_years", "mosca"]
