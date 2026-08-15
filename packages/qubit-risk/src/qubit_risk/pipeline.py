"""RiskPipeline — annotate CryptoAssets with sensitivity,
shelf-life, risk score + CI, Mosca margin, and priority rank
(doc 02 6.6). M1: in-memory over a list of assets; DB write is a
thin follow-up. Heuristic-only (no BERT/XGBoost yet).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from pathlib import Path

from qubit_core import CryptoAsset, RiskAnnotation, Sensitivity

from .config import RiskConfig, load_config
from .mosca import migration_years, mosca
from .score import score_asset
from .sensitivity import classify_sensitivity
from .timeline import CRQCTimelineSimulator

logger = logging.getLogger(__name__)


class RiskPipeline:
    def __init__(self, config: RiskConfig | None = None) -> None:
        self.cfg = config or load_config()
        self.sim = CRQCTimelineSimulator(self.cfg)
        self._now = int(self.cfg.hardware_priors["reference_year"])
        # Optional XGBoost regressor tier (doc 02 §6.4). Enabled only when QUBIT_RISK_XGB_DIR points
        # at a trained model dir; otherwise the pipeline uses the heuristic/closed-form score
        # (graceful degradation, NFR2). Loaded once here so per-asset scoring stays fast.
        self._regressor = None
        xgb_dir = os.getenv("QUBIT_RISK_XGB_DIR")
        if xgb_dir:
            from .regressor.predict import RiskRegressor

            if RiskRegressor.available(Path(xgb_dir)):
                try:
                    self._regressor = RiskRegressor.load(Path(xgb_dir))
                except Exception:
                    logger.exception("XGBoost regressor load failed; falling back to closed-form")

    def assess(self, assets: Sequence[CryptoAsset]) -> list[CryptoAsset]:
        """Annotate assets in-place. Mutates sensitivity/risk."""
        for asset in assets:
            sens = classify_sensitivity(asset, self.cfg)
            asset.sensitivity = Sensitivity(sens.sensitivity)
            asset.shelf_life_years = sens.shelf_life_years

            is_vuln = asset.quantum_vulnerable.vulnerable
            curve = self.sim.simulate(asset.algorithm) if is_vuln else None
            sr = score_asset(asset, sens, curve, self.cfg, self._now)

            # XGBoost tier: distilled score + conformal CI when a model is loaded (doc 02 §6.4).
            score, ci_low, ci_high = sr.score, sr.ci_low, sr.ci_high
            if self._regressor is not None and is_vuln:
                try:
                    from .regressor.asset_features import build_asset_features

                    feats = build_asset_features(asset, sens, curve, self.cfg, self._now)
                    pred = self._regressor.predict(feats)
                    score, ci_low, ci_high = pred.score, pred.ci_low, pred.ci_high
                except Exception:
                    logger.exception("regressor.predict failed; using closed-form score")

            y = migration_years(self.cfg, asset.usage_context.value)
            if curve is not None:
                mr = mosca(
                    curve,
                    shelf_p90=sens.shelf_life_p90,
                    y_years=y,
                    now_year=self._now,
                    z_percentile=self.cfg.mosca["z_percentile"],
                )
                margin = mr.margin_years
            else:
                # No CRQC curve for this asset: Grover-tier symmetric/hash (doc 02 section 6.1.6),
                # an already-quantum-safe algorithm, or an unresolved UNKNOWN(...). Doc 02 F8
                # sanctions falling back to Z = horizon - now, but Z is the *arrival-time input*:
                # the margin is still Z - (X + Y). This previously assigned Z straight to the
                # margin, so every non-modelled asset reported an identical horizon distance
                # (e.g. +74.00y at horizon 2100) and the shelf-life and migration effort this
                # pipeline had just computed were silently discarded - two MD5 assets, one holding
                # PHI with a 31-year secrecy need and one ephemeral, got the same margin.
                z_margin = float(self.cfg.hardware_priors["horizon_year"] - self._now)
                margin = round(z_margin - (sens.shelf_life_p90 + y), 2)

            asset.risk = RiskAnnotation(
                score=score,
                ci_low=ci_low,
                ci_high=ci_high,
                mosca_margin_years=margin,
                priority_rank=1,  # rank filled after sorting
            )

        # dense priority rank: highest score first, tie-break most-negative Mosca margin
        ranked = sorted(
            [a for a in assets if a.risk is not None],
            key=lambda a: (-a.risk.score, a.risk.mosca_margin_years),  # type: ignore[union-attr]
        )
        rank = 0
        prev: tuple[float, float] | None = None
        for a in ranked:
            key = (a.risk.score, a.risk.mosca_margin_years)  # type: ignore[union-attr]
            if key != prev:
                rank += 1
                prev = key
            a.risk = a.risk.model_copy(update={"priority_rank": rank})  # type: ignore[union-attr]
        return list(assets)


__all__ = ["RiskPipeline"]
