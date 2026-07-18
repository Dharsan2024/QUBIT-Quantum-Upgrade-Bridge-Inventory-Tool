"""HNDL probability: closed-form integral + pgmpy Bayesian network (doc 02 §6.2).

    P_HNDL = P(H=1 | E, S) * integral_0^inf  f_L(ell) * F_a(t_now + ell)  d(ell)

The closed form (512-point Gauss-Legendre over the shelf-life LogNormal) is the ground truth;
the Bayesian network (pgmpy) is the explainable factorization that must agree with it to <0.02.
The BN exists so the dashboard/paper can show the factor decomposition and so users can override
any CPD — not because it is more accurate.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from scipy import stats

from .config import RiskConfig
from .timeline import TimelineCurve

_GL_POINTS = 512


def _shelf_dist(shelf_spec: dict) -> stats.rv_continuous:
    """Return the frozen shelf-life distribution for a sensitivity class."""
    if "fixed" in shelf_spec:
        # near-degenerate LogNormal so the integral machinery still applies
        return stats.lognorm(s=1e-6, scale=float(shelf_spec["fixed"]))
    return stats.lognorm(s=float(shelf_spec["sigma_ln"]), scale=float(np.exp(shelf_spec["mu_ln"])))


def _f_a_at(curve: TimelineCurve, years: np.ndarray) -> np.ndarray:
    """F_a interpolated at calendar years (flat-extrapolated past the horizon)."""
    xs = np.array(curve.years, dtype=float)
    ys = np.array(curve.cdf, dtype=float)
    return np.interp(years, xs, ys, left=ys[0], right=ys[-1])


def p_decrypt_integral(curve: TimelineCurve, shelf_spec: dict, now_year: int) -> float:
    """Integral of f_L(ell)*F_a(now+ell) d(ell) via Gauss-Legendre (doc 02 6.2.2)."""
    dist = _shelf_dist(shelf_spec)
    lo = float(dist.ppf(0.001))
    hi = float(dist.ppf(0.999))
    if hi <= lo:  # degenerate (fixed) shelf life
        return float(_f_a_at(curve, np.array([now_year + lo]))[0])
    nodes, weights = np.polynomial.legendre.leggauss(_GL_POINTS)
    ell = 0.5 * (hi - lo) * nodes + 0.5 * (hi + lo)  # map [-1,1] -> [lo,hi]
    jac = 0.5 * (hi - lo)
    integrand = dist.pdf(ell) * _f_a_at(curve, now_year + ell)
    return float(np.sum(weights * integrand) * jac)


def harvest_prob(cfg: RiskConfig, exposure: str, sensitivity: str) -> float:
    cpd = cfg.bn_cpds["harvest_cpd"]
    tier = "high" if sensitivity in set(cfg.bn_cpds["high_tiers"]) else "low"
    return float(cpd.get(exposure, cpd["at_rest"])[tier])


def p_hndl_closed_form(
    cfg: RiskConfig,
    curve: TimelineCurve,
    exposure: str,
    sensitivity: str,
    shelf_spec: dict,
    now_year: int,
) -> float:
    h = harvest_prob(cfg, exposure, sensitivity)
    return h * p_decrypt_integral(curve, shelf_spec, now_year)


@dataclass
class BnFactors:
    """Factor decomposition for RiskExplanation.bn_factors (doc 02 §6.2.3)."""

    harvest_prob: float
    p_decrypt: float
    p_hndl: float
    exposure: str
    tier: str
    extra: dict = field(default_factory=dict)


class HndlBayesNet:
    """pgmpy discretization of the closed form (doc 02 §6.2.1/6.2.3).

    Nodes: Harvested | (Exposure, SensTier); CRQCArrival (per-year bins off F_a);
    ShelfLife (equal-support LogNormal bins); DecryptedBeforeObsolete | (Harvested,
    CRQCArrival, ShelfLife) — deterministic yes iff Harvested ∧ crqc_year ≤ now + shelf_years.
    """

    def __init__(self, cfg: RiskConfig) -> None:
        self.cfg = cfg
        self._n_shelf = int(cfg.bn_cpds.get("shelf_bins", 24))

    def _shelf_bins(self, shelf_spec: dict) -> tuple[np.ndarray, np.ndarray]:
        """Equal-probability shelf-life bins: (masses, midpoints_years)."""
        dist = _shelf_dist(shelf_spec)
        edges_p = np.linspace(0.0, 1.0, self._n_shelf + 1)
        edges = dist.ppf(edges_p)
        edges[0] = float(dist.ppf(1e-6))
        edges[-1] = float(dist.ppf(1 - 1e-6))
        masses = np.full(self._n_shelf, 1.0 / self._n_shelf)
        mids = 0.5 * (edges[:-1] + edges[1:])
        return masses, mids

    def _crqc_bins(self, curve: TimelineCurve) -> tuple[np.ndarray, np.ndarray]:
        """Per-year CRQC arrival mass + a 'never' bin (doc 02 §6.2.1)."""
        years = np.array(curve.years, dtype=float)
        cdf = np.array(curve.cdf, dtype=float)
        mass = np.diff(cdf, prepend=0.0)  # P(arrival in year i)
        never = max(0.0, 1.0 - cdf[-1])
        mids = np.append(years, 1e9)  # sentinel 'never' bin never satisfies the deadline
        mass = np.append(mass, never)
        s = mass.sum()
        if s > 0:
            mass = mass / s
        return mass, mids

    def p_hndl(
        self,
        curve: TimelineCurve,
        exposure: str,
        sensitivity: str,
        shelf_spec: dict,
        now_year: int,
    ) -> tuple[float, BnFactors]:
        from pgmpy.factors.discrete import TabularCPD
        from pgmpy.inference import VariableElimination
        from pgmpy.models import DiscreteBayesianNetwork

        h = harvest_prob(self.cfg, exposure, sensitivity)
        tier = "high" if sensitivity in set(self.cfg.bn_cpds["high_tiers"]) else "low"

        crqc_mass, crqc_mid = self._crqc_bins(curve)
        shelf_mass, shelf_mid = self._shelf_bins(shelf_spec)
        n_c, n_s = len(crqc_mass), len(shelf_mass)

        model = DiscreteBayesianNetwork(
            [
                ("Harvested", "DBO"),
                ("CRQCArrival", "DBO"),
                ("ShelfLife", "DBO"),
            ]
        )
        cpd_h = TabularCPD("Harvested", 2, [[1 - h], [h]])  # 0=no, 1=yes
        cpd_c = TabularCPD("CRQCArrival", n_c, crqc_mass.reshape(-1, 1))
        cpd_s = TabularCPD("ShelfLife", n_s, shelf_mass.reshape(-1, 1))

        # DBO deterministic: yes iff Harvested=yes AND crqc_year <= now + shelf_years.
        # Evidence order (pgmpy): Harvested (2), CRQCArrival (n_c), ShelfLife (n_s).
        deadline_ok = crqc_mid[:, None] <= (now_year + shelf_mid)[None, :]  # (n_c, n_s)
        # Flatten to the pgmpy evidence order (Harvested, CRQCArrival, ShelfLife); DBO=yes only
        # when harvested AND the deadline holds.
        harvested_yes = np.array([0.0, 1.0])  # per Harvested state
        yes_row = (harvested_yes[:, None, None] * deadline_ok[None, :, :]).reshape(-1)
        cpd_dbo = TabularCPD(
            "DBO",
            2,
            np.vstack([1 - yes_row, yes_row]),
            evidence=["Harvested", "CRQCArrival", "ShelfLife"],
            evidence_card=[2, n_c, n_s],
        )
        model.add_cpds(cpd_h, cpd_c, cpd_s, cpd_dbo)
        model.check_model()

        q = VariableElimination(model).query(["DBO"], show_progress=False)
        p = float(q.values[1])
        p_dec = p / h if h > 0 else 0.0
        return p, BnFactors(
            harvest_prob=h,
            p_decrypt=p_dec,
            p_hndl=p,
            exposure=exposure,
            tier=tier,
            extra={"crqc_bins": int(n_c), "shelf_bins": int(n_s)},
        )


def hndl_bayes_net(cfg: RiskConfig) -> HndlBayesNet:
    return HndlBayesNet(cfg)


__all__ = [
    "BnFactors",
    "HndlBayesNet",
    "harvest_prob",
    "hndl_bayes_net",
    "p_decrypt_integral",
    "p_hndl_closed_form",
]
