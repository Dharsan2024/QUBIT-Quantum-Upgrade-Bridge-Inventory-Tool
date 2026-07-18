"""HNDL closed-form integral + pgmpy Bayesian network (doc 02 §6.2).

Key contract: the BN discretization agrees with the closed-form integral to <0.02 absolute.
"""

from __future__ import annotations

import pytest
from qubit_risk.config import load_config
from qubit_risk.hndl import (
    harvest_prob,
    hndl_bayes_net,
    p_decrypt_integral,
    p_hndl_closed_form,
)
from qubit_risk.timeline.simulator import CRQCTimelineSimulator


@pytest.fixture(scope="module")
def cfg():
    return load_config()


@pytest.fixture(scope="module")
def curve(cfg):
    return CRQCTimelineSimulator(cfg).simulate("RSA-2048")


def test_harvest_prob_tiers(cfg):
    # high tier (phi) vs low tier (unknown) on the network exposure
    assert harvest_prob(cfg, "network", "phi") == 0.80
    assert harvest_prob(cfg, "network", "unknown") == 0.40
    assert harvest_prob(cfg, "offline", "phi") == 0.05


def test_p_decrypt_integral_in_unit_interval(cfg, curve):
    spec = cfg.shelf_life_priors["classes"]["phi"]
    p = p_decrypt_integral(curve, spec, cfg.hardware_priors["reference_year"])
    assert 0.0 <= p <= 1.0


def test_longer_shelf_life_raises_p_decrypt(cfg, curve):
    now = cfg.hardware_priors["reference_year"]
    classes = cfg.shelf_life_priors["classes"]
    p_phi = p_decrypt_integral(curve, classes["phi"], now)  # ~30y median
    # a short-lived class must have <= decrypt probability than a long-lived one
    short = min(
        (c for c in classes.values() if "mu_ln" in c),
        key=lambda c: c["mu_ln"],
    )
    p_short = p_decrypt_integral(curve, short, now)
    assert p_short <= p_phi + 1e-9


@pytest.mark.parametrize("exposure", ["network", "at_rest", "offline"])
def test_bn_agrees_with_closed_form(cfg, curve, exposure):
    """The Bayesian network must agree with the closed-form integral to <0.02 (doc 02 §6.2.2)."""
    now = cfg.hardware_priors["reference_year"]
    spec = cfg.shelf_life_priors["classes"]["phi"]
    cf = p_hndl_closed_form(cfg, curve, exposure, "phi", spec, now)
    bn, factors = hndl_bayes_net(cfg).p_hndl(curve, exposure, "phi", spec, now)
    assert abs(cf - bn) < 0.02, f"{exposure}: closed={cf:.4f} bn={bn:.4f}"
    assert factors.exposure == exposure
    assert 0.0 <= bn <= 1.0


def test_bn_factor_decomposition(cfg, curve):
    now = cfg.hardware_priors["reference_year"]
    spec = cfg.shelf_life_priors["classes"]["phi"]
    _p, factors = hndl_bayes_net(cfg).p_hndl(curve, "network", "phi", spec, now)
    # p_hndl ~= harvest_prob * p_decrypt
    assert abs(factors.p_hndl - factors.harvest_prob * factors.p_decrypt) < 1e-6
    assert factors.tier == "high"
