"""Monte-Carlo CRQC timeline simulator (doc 02 6.1).

Samples plausible quantum-hardware trajectories, finds the first
year each trajectory can break a given algorithm within the attack
window, and reports the empirical CDF F_a(T) = P(broken by year T)
with a binomial standard-error band. M1 is hardware-only (no
expert-survey blend yet — that's M2).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy import stats

from ..config import RiskConfig, load_config
from . import surface_code as sc


@dataclass(frozen=True)
class TimelineCurve:
    algorithm: str
    years: list[int]
    cdf: list[float]  # F_a(T) = P(CRQC breaks a by year T)
    cdf_stderr: list[float]
    median_year: float | None  # None if F(horizon) < 0.5
    p05_year: float | None
    p95_year: float | None
    n_trials: int
    params_hash: str


def _sample(dist: dict, size: int, rng: np.random.Generator) -> np.ndarray:
    kind = dist["dist"]
    if kind == "lognormal":
        return rng.lognormal(dist["mu_ln"], dist["sigma_ln"], size)
    if kind == "loguniform":
        return np.exp(rng.uniform(np.log(dist["low"]), np.log(dist["high"]), size))
    if kind == "uniform":
        return rng.uniform(dist["low"], dist["high"], size)
    if kind == "truncnorm":
        a = (dist["low"] - dist["mu"]) / dist["sigma"]
        b = (dist["high"] - dist["mu"]) / dist["sigma"]
        return stats.truncnorm.rvs(
            a, b, loc=dist["mu"], scale=dist["sigma"], size=size, random_state=rng
        )
    raise ValueError(f"unknown distribution: {kind}")


class CRQCTimelineSimulator:
    def __init__(self, config: RiskConfig | None = None) -> None:
        self.cfg = config or load_config()
        self._cache: dict[tuple[str, int, float], TimelineCurve] = {}

    def simulate(
        self, algorithm: str, *, n_trials: int | None = None, window_days: float | None = None
    ) -> TimelineCurve | None:
        """Return CDF for a Shor-vulnerable algo, or None if absent."""
        # cache key includes trials + window: a 24h-window blend call must never
        # collide with the 30-day standalone risk curve for the same algorithm
        key = (
            algorithm,
            n_trials or self.cfg.n_trials,
            float(window_days or self.cfg.hardware_priors["attack_window_days"]),
        )
        if key in self._cache:
            return self._cache[key]
        res = self.cfg.resource_for(algorithm)
        if res is None or res.get("attack") != "shor":
            return None

        hp = self.cfg.hardware_priors
        sc_p = hp["surface_code"]
        n = n_trials or self.cfg.n_trials
        rng = np.random.default_rng(self.cfg.seed)
        t0 = hp["reference_year"]
        horizon = hp["horizon_year"]
        window_s = (window_days or hp["attack_window_days"]) * 86400.0

        # per-trial hardware draws
        q0 = _sample(hp["physical_qubits_now"], n, rng)
        g = _sample(hp["qubit_growth_rate"], n, rng)
        p0 = _sample(hp["error_rate_now"], n, rng)
        r = _sample(hp["error_improvement_rate"], n, rng)
        eta = _sample(hp["architecture_efficiency"], n, rng)
        t_cycle = _sample(sc_p["t_cycle_us"], n, rng) * 1e-6
        t_react = _sample(sc_p["t_reaction_us"], n, rng) * 1e-6
        gamma = _sample(sc_p["factory_overhead"], n, rng)
        # PyYAML parses "1.3e9" (no sign in exponent) as a str, so coerce bounds to float.
        n_lo = float(res["N_tof"]["low"])
        n_hi = float(res["N_tof"]["high"])
        n_tof = np.exp(rng.uniform(np.log(n_lo), np.log(n_hi), n))
        q_logical = int(res["Q_L"])

        break_year = np.full(n, np.inf)
        years = list(range(t0, horizon + 1))
        for year in years:
            dt = year - t0
            q_avail = q0 * np.exp(g * dt)
            p_t = np.maximum(1e-5, p0 * np.exp(-r * dt))
            q_needed = sc.required_physical_qubits(
                q_logical,
                n_tof,
                p_t,
                window_s=window_s,
                t_cycle_s=t_cycle,
                t_reaction_s=t_react,
                eta=eta,
                gamma=gamma,
                A=sc_p["A"],
                p_threshold=sc_p["p_threshold"],
                eps_fail=sc_p["eps_fail"],
                routing_overhead=sc_p["routing_overhead"],
                parallel_cap=sc_p["parallel_cap"],
            )
            newly = (q_avail >= q_needed) & np.isinf(break_year)
            break_year = np.where(newly, float(year), break_year)

        years_arr = np.array(years, dtype=np.float64)
        broken_by = (break_year[:, None] <= years_arr[None, :]).mean(axis=0)
        se = np.sqrt(np.clip(broken_by * (1.0 - broken_by), 0.0, None) / n)

        curve = TimelineCurve(
            algorithm=algorithm,
            years=years,
            cdf=[float(x) for x in broken_by],
            cdf_stderr=[float(x) for x in se],
            median_year=self._pct_year(break_year, 0.5, horizon),
            p05_year=self._pct_year(break_year, 0.05, horizon),
            p95_year=self._pct_year(break_year, 0.95, horizon),
            n_trials=n,
            params_hash=self.cfg.params_hash,
        )
        self._cache[key] = curve
        return curve

    @staticmethod
    def _pct_year(break_year: np.ndarray, q: float, horizon: int) -> float | None:
        finite = break_year[np.isfinite(break_year)]
        # fraction of ALL trials (including never-break) below q determines definedness
        if len(finite) / len(break_year) < q:
            return None
        return float(np.quantile(finite, q / (len(finite) / len(break_year))))


__all__ = ["CRQCTimelineSimulator", "TimelineCurve"]
