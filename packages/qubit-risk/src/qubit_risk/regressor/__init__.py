"""XGBoost risk regressor + split-conformal CI (doc 02 §6.4).

A distillation/fusion layer over the MC+BN closed-form pipeline: a millisecond scorer that
reproduces P_HNDL smoothly across the feature space, fuses features the BN doesn't model, and
carries conformal prediction intervals. Trained on the pipeline's OWN analytic output under
parameter uncertainty (no external data). xgboost is imported lazily (optional `ml` extra).
"""

from .features import FEATURE_NAMES, N_FEATURES, build_features

__all__ = ["FEATURE_NAMES", "N_FEATURES", "build_features"]
