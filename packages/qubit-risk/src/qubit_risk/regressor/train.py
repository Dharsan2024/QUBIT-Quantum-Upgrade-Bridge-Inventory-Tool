"""Train the XGBoost risk regressor + split-conformal calibration (doc 02 6.4.4).

Primary path only: plain median regressor (reg:squarederror) + split conformal (alpha=0.10) giving a
finite-sample marginal coverage guarantee P(y in CI) >= 1-alpha under exchangeability. Writes the
booster (UBJSON), conformal.json (q_hat), and metrics.json (empirical test coverage + width).
xgboost/sklearn are imported lazily (optional `ml` extra).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from ..config import RiskConfig, load_config
from .features import FEATURE_NAMES
from .labels import generate_training_table

_ALPHA = 0.10  # 90% intervals


@dataclass
class RegressorConfig:
    out_dir: Path
    n_assets: int = 6000
    k_draws: int = 48
    seed: int = 42
    n_estimators: int = 600
    max_depth: int = 6
    learning_rate: float = 0.05
    n_jobs: int | None = None  # label-gen worker cap (RAM-bound); None -> auto


def _require() -> None:
    try:
        import sklearn  # noqa: F401
        import xgboost  # noqa: F401
    except ImportError as e:  # pragma: no cover
        msg = "Regressor needs the 'ml' extra: `uv sync --extra ml` (xgboost+sklearn)."
        raise RuntimeError(msg) from e


def _stratified_split(fams: list[str], seed: int) -> tuple[list[int], list[int], list[int]]:
    """70/15/15 train/calibration/test, stratified by algorithm family."""
    rng = np.random.default_rng(seed)
    by_fam: dict[str, list[int]] = {}
    for i, f in enumerate(fams):
        by_fam.setdefault(f, []).append(i)
    tr, cal, te = [], [], []
    for idxs in by_fam.values():
        idxs = list(idxs)
        rng.shuffle(idxs)
        n = len(idxs)
        a, b = int(0.70 * n), int(0.85 * n)
        tr += idxs[:a]
        cal += idxs[a:b]
        te += idxs[b:]
    return tr, cal, te


def train(cfg: RegressorConfig, risk_cfg: RiskConfig | None = None) -> dict:  # pragma: no cover
    """Train + calibrate + evaluate; write model artifacts; return a metrics dict."""
    _require()
    import xgboost as xgb

    risk_cfg = risk_cfg or load_config()
    table = generate_training_table(
        n_assets=cfg.n_assets, k_draws=cfg.k_draws, seed=cfg.seed, cfg=risk_cfg, n_jobs=cfg.n_jobs
    )
    X = np.array(table.X, dtype=np.float32)
    y = np.array(table.y, dtype=np.float32)
    tr, cal, te = _stratified_split(table.families, cfg.seed)

    booster = xgb.XGBRegressor(
        objective="reg:squarederror",
        tree_method="hist",
        n_estimators=cfg.n_estimators,
        max_depth=cfg.max_depth,
        learning_rate=cfg.learning_rate,
        min_child_weight=10,
        subsample=0.9,
        random_state=cfg.seed,
        n_jobs=os.cpu_count() or 4,  # use all cores for tree construction
    )
    booster.fit(X[tr], y[tr])

    # split-conformal q̂ on the calibration fold
    resid = np.abs(y[cal] - booster.predict(X[cal]))
    n = len(resid)
    level = np.ceil((n + 1) * (1 - _ALPHA)) / n
    q_hat = float(np.quantile(resid, min(level, 1.0), method="higher"))

    # empirical coverage + width on the held-out test fold
    y_hat_te = booster.predict(X[te])
    lo = np.clip(y_hat_te - q_hat, 0, 1)
    hi = np.clip(y_hat_te + q_hat, 0, 1)
    covered = float(np.mean((y[te] >= lo) & (y[te] <= hi)))
    mae = float(np.mean(np.abs(y[te] - y_hat_te)))

    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(cfg.out_dir / "risk-xgb.ubj"))
    (cfg.out_dir / "conformal.json").write_text(
        json.dumps({"q_hat": q_hat, "alpha": _ALPHA, "feature_names": FEATURE_NAMES}, indent=2),
        encoding="utf-8",
    )
    metrics = {
        "n_assets": cfg.n_assets,
        "k_draws": cfg.k_draws,
        "n_train": len(tr),
        "n_cal": len(cal),
        "n_test": len(te),
        "q_hat": round(q_hat, 4),
        "target_coverage": 1 - _ALPHA,
        "empirical_test_coverage": round(covered, 4),
        "mean_interval_width": round(float(np.mean(hi - lo)), 4),
        "test_mae": round(mae, 4),
    }
    (cfg.out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


__all__ = ["RegressorConfig", "train"]
