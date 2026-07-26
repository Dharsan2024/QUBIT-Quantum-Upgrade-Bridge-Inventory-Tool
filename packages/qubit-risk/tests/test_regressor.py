"""XGBoost risk regressor + split-conformal CI (doc 02 §6.4)."""

from __future__ import annotations

import pytest
from qubit_risk.regressor import FEATURE_NAMES, N_FEATURES, build_features
from qubit_risk.regressor.features import FeatureInputs, family_of
from qubit_risk.regressor.predict import RiskRegressor

xgboost = pytest.importorskip("xgboost")


def _fi(**kw) -> FeatureInputs:
    base = dict(
        algorithm_family="RSA",
        key_size=2048,
        attack="shor",
        p_crqc_2030=0.1,
        p_crqc_2035=0.3,
        p_crqc_2040=0.5,
        break_year_median=2041.0,
        sens_probs=[0.5, 0.1, 0.1, 0.1, 0.1, 0.05, 0.05],
        shelf_life_mean=30.0,
        shelf_life_p90=45.0,
        exposure="network",
        usage_context="kex",
        bn_p_hndl=0.6,
        harvest_prob=0.8,
    )
    base.update(kw)
    return FeatureInputs(**base)


def test_feature_vector_is_34_dims_and_named() -> None:
    vec = build_features(_fi())
    assert len(vec) == N_FEATURES == 34
    assert len(FEATURE_NAMES) == 34
    # RSA one-hot set, others zero
    assert vec[FEATURE_NAMES.index("alg_family_RSA")] == 1.0
    assert vec[FEATURE_NAMES.index("alg_family_ECDSA")] == 0.0
    assert vec[FEATURE_NAMES.index("attack_ord")] == 2.0  # shor


def test_missing_values_use_sentinel() -> None:
    vec = build_features(_fi(key_size=None, sens_probs=[], bn_p_hndl=None))
    assert vec[FEATURE_NAMES.index("log2_key_size")] == -1.0
    assert vec[FEATURE_NAMES.index("sens_phi")] == -1.0
    assert vec[FEATURE_NAMES.index("bn_p_hndl")] == -1.0


def test_family_of() -> None:
    assert family_of("RSA-2048") == "RSA"
    assert family_of("ECDSA-P256") == "ECDSA"
    assert family_of("ML-KEM-768") == "OTHER"


def test_regressor_available_false_on_empty(tmp_path) -> None:
    assert RiskRegressor.available(tmp_path) is False


def test_train_conformal_coverage_and_predict(tmp_path) -> None:
    """End-to-end small train: split-conformal must hit ~90% coverage on the test fold."""
    from qubit_risk.regressor.train import RegressorConfig, train

    m = train(RegressorConfig(out_dir=tmp_path, n_assets=1200, k_draws=8, n_estimators=120, seed=1))
    # split conformal guarantees >=1-alpha coverage under exchangeability; small-N slack allowed
    assert m["empirical_test_coverage"] >= 0.85, m
    assert 0.0 <= m["mean_interval_width"] <= 2.0

    assert RiskRegressor.available(tmp_path)
    reg = RiskRegressor.load(tmp_path)
    pred = reg.predict(build_features(_fi()))
    assert 0.0 <= pred.ci_low <= pred.score <= pred.ci_high <= 1.0
    assert len(pred.shap_top) == 8
    assert pred.score_source == "xgb"
