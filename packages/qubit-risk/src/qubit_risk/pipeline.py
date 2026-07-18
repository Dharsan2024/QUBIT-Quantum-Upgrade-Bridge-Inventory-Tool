"""RiskPipeline — annotate CryptoAssets with sensitivity,
shelf-life, risk score + CI, Mosca margin, and priority rank
(doc 02 6.6). M1: in-memory over a list of assets; DB write is a
thin follow-up. Heuristic-only (no BERT/XGBoost yet).
"""

from __future__ import annotations

from collections.abc import Sequence

from qubit_core import CryptoAsset, RiskAnnotation, Sensitivity

from .config import RiskConfig, load_config
from .mosca import migration_years, mosca
from .score import score_asset
from .sensitivity import classify_sensitivity
from .timeline import CRQCTimelineSimulator


class RiskPipeline:
    def __init__(self, config: RiskConfig | None = None) -> None:
        self.cfg = config or load_config()
        self.sim = CRQCTimelineSimulator(self.cfg)
        self._now = int(self.cfg.hardware_priors["reference_year"])

    def assess(self, assets: Sequence[CryptoAsset]) -> list[CryptoAsset]:
        """Annotate assets in-place. Mutates sensitivity/risk."""
        for asset in assets:
            sens = classify_sensitivity(asset, self.cfg)
            asset.sensitivity = Sensitivity(sens.sensitivity)
            asset.shelf_life_years = sens.shelf_life_years

            is_vuln = asset.quantum_vulnerable.vulnerable
            curve = self.sim.simulate(asset.algorithm) if is_vuln else None
            sr = score_asset(asset, sens, curve, self.cfg, self._now)

            if curve is not None:
                y = migration_years(self.cfg, asset.usage_context.value)
                mr = mosca(
                    curve,
                    shelf_p90=sens.shelf_life_p90,
                    y_years=y,
                    now_year=self._now,
                    z_percentile=self.cfg.mosca["z_percentile"],
                )
                margin = mr.margin_years
            else:
                margin = float(self.cfg.hardware_priors["horizon_year"] - self._now)

            asset.risk = RiskAnnotation(
                score=sr.score,
                ci_low=sr.ci_low,
                ci_high=sr.ci_high,
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
