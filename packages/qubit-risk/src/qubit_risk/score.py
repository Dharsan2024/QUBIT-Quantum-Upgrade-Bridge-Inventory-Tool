"""HNDL risk score v0 (doc 02 M1: static, honest, explainable).

score = P(harvested) x P(decrypted before obsolete), in [0,1].
- P(harvested): expert-elicited table over (exposure, sensitivity).
- P(decrypted before obsolete): MC over shelf-life prior of
  F_a(now + L) — closed-form HNDL (doc 02 6.2.2), sampled.
Non-vulnerable (PQC) => 0. Grover-tier => small fixed marginal.
XGBoost + Bayesian net are M2; CI here is a simple honest band.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from qubit_core import CryptoAsset, QuantumAttack, SourceScanner

from .config import RiskConfig
from .sensitivity import SensitivityResult
from .timeline import TimelineCurve

# P(harvested | exposure, sensitivity tier) — expert-elicited (doc 02 bn_cpds.harvest_cpd).
_HARVEST = {
    ("network", "high"): 0.80,
    ("network", "low"): 0.40,
    ("at_rest", "high"): 0.30,
    ("at_rest", "low"): 0.10,
    ("offline", "high"): 0.05,
    ("offline", "low"): 0.02,
}
_HIGH_TIER = {"phi", "pii", "financial", "ip", "credentials"}
_GROVER_MARGINAL = 0.15  # fixed small score for AES-128/3DES-class (halved symmetric strength)


@dataclass(frozen=True)
class ScoreResult:
    score: float
    ci_low: float
    ci_high: float
    harvest_prob: float
    p_decrypt: float


def exposure_of(asset: CryptoAsset) -> str:
    is_net = asset.source_scanner == SourceScanner.network or asset.usage_context.value in (
        "tls",
        "kex",
    )
    if is_net:
        return "network"
    is_offline = (
        asset.source_scanner in (SourceScanner.cert, SourceScanner.key)
        and asset.protocol_detail is None
    )
    if is_offline:
        return "offline"
    return "at_rest"


def _p_decrypt(
    curve: TimelineCurve,
    sens: SensitivityResult,
    cfg: RiskConfig,
    now_year: int,
) -> float:
    """MC over the shelf-life prior: mean_L F_a(now + L)."""
    spec = cfg.shelf_life_priors["classes"].get(sens.sensitivity, {})
    rng = np.random.default_rng(cfg.seed)
    if "fixed" in spec:
        samples = np.full(256, float(spec["fixed"]))
    else:
        samples = rng.lognormal(float(spec["mu_ln"]), float(spec["sigma_ln"]), 256)
    years = np.array(curve.years, dtype=float)
    cdf = np.array(curve.cdf, dtype=float)
    target = now_year + samples
    f = np.interp(target, years, cdf)
    return float(f.mean())


def score_asset(
    asset: CryptoAsset,
    sens: SensitivityResult,
    curve: TimelineCurve | None,
    cfg: RiskConfig,
    now_year: int,
) -> ScoreResult:
    qv = asset.quantum_vulnerable
    if not qv.vulnerable:
        return ScoreResult(0.0, 0.0, 0.0, 0.0, 0.0)
    if qv.attack == QuantumAttack.grover or curve is None:
        # symmetric/Grover-tier or no Shor curve available: small marginal, wide band
        s = _GROVER_MARGINAL
        return ScoreResult(s, 0.0, min(1.0, s + 0.15), 0.0, 0.0)

    tier = "high" if sens.sensitivity in _HIGH_TIER else "low"
    harvest = _HARVEST.get((exposure_of(asset), tier), 0.1)
    p_dec = _p_decrypt(curve, sens, cfg, now_year)
    score = harvest * p_dec
    # Honest fixed CI band for M1 (the calibrated conformal interval is M2's XGBoost job).
    band = 0.12
    return ScoreResult(
        score=round(score, 4),
        ci_low=round(max(0.0, score - band), 4),
        ci_high=round(min(1.0, score + band), 4),
        harvest_prob=harvest,
        p_decrypt=round(p_dec, 4),
    )


__all__ = ["ScoreResult", "exposure_of", "score_asset"]
