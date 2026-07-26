"""RiskRegressor inference: score + conformal CI + TreeSHAP (doc 02 §6.4.4/6.4.6).

Graceful degradation (NFR2): if the model artifacts are absent, the caller uses the BN/closed-form
probability directly with a wide CI, so the pipeline never hard-fails when the regressor is missing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .features import FEATURE_NAMES


@dataclass
class RiskPrediction:
    score: float
    ci_low: float
    ci_high: float
    shap_top: list[tuple[str, float]]  # (feature, contribution), top-8 by |value|
    score_source: str = "xgb"


class RiskRegressor:
    def __init__(self, booster, q_hat: float) -> None:
        self._booster = booster
        self._q_hat = q_hat

    @classmethod
    def load(cls, path: Path) -> RiskRegressor:
        import xgboost as xgb

        conf = json.loads((path / "conformal.json").read_text(encoding="utf-8"))
        booster = xgb.Booster()
        booster.load_model(str(path / "risk-xgb.ubj"))
        return cls(booster, float(conf["q_hat"]))

    @staticmethod
    def available(path: Path) -> bool:
        return (path / "risk-xgb.ubj").exists() and (path / "conformal.json").exists()

    def predict(self, features: list[float]) -> RiskPrediction:
        import numpy as np
        import xgboost as xgb

        dmat = xgb.DMatrix(np.array([features], dtype=np.float32), feature_names=FEATURE_NAMES)
        score = float(self._booster.predict(dmat)[0])
        score = min(1.0, max(0.0, score))
        lo = max(0.0, score - self._q_hat)
        hi = min(1.0, score + self._q_hat)
        # built-in TreeSHAP (no extra dep): last column is the bias term, drop it
        contribs = self._booster.predict(dmat, pred_contribs=True)[0][:-1]
        order = sorted(range(len(contribs)), key=lambda i: abs(contribs[i]), reverse=True)[:8]
        shap_top = [(FEATURE_NAMES[i], round(float(contribs[i]), 4)) for i in order]
        return RiskPrediction(
            score=round(score, 4), ci_low=round(lo, 4), ci_high=round(hi, 4), shap_top=shap_top
        )


__all__ = ["RiskPrediction", "RiskRegressor"]
