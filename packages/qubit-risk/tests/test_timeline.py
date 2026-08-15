from __future__ import annotations

import pytest
from qubit_risk import CRQCTimelineSimulator, load_config
from qubit_risk.timeline import required_physical_qubits

CFG = load_config()
SCP = CFG.hardware_priors["surface_code"]


def _qp(q_logical: int, n_tof: float, p: float, window_h: float, eta: float, gamma: float) -> float:
    return float(
        required_physical_qubits(
            q_logical,
            n_tof,
            p,
            window_s=window_h * 3600.0,
            t_cycle_s=1e-6,
            t_reaction_s=1e-5,
            eta=eta,
            gamma=gamma,
            A=SCP["A"],
            p_threshold=SCP["p_threshold"],
            eps_fail=SCP["eps_fail"],
            routing_overhead=SCP["routing_overhead"],
            parallel_cap=SCP["parallel_cap"],
        )
    )


# --- anchor calibration (the scientific-credibility gate) ---
# k=1 (reaction-limited) anchors must reproduce published figures within x2.
@pytest.mark.parametrize(
    "q_logical,n_tof,window_h,expect",
    [
        (6200, 2.7e9, 8, 2.0e7),  # GE2019 RSA-2048 ~20M physical qubits @ ~8h
        (2400, 1.3e9, 24, 1.3e7),  # Webber+ 2022 ECC-256 ~13M @ 24h
    ],
)
def test_anchor_within_2x(q_logical: int, n_tof: float, window_h: float, expect: float) -> None:
    got = _qp(q_logical, n_tof, 1e-3, window_h, eta=1.0, gamma=0.35)
    assert 0.5 <= got / expect <= 2.0, f"{got:.3e} vs {expect:.3e} (ratio {got / expect:.2f})"


def test_shorter_window_needs_more_qubits() -> None:
    # 1h (aggressively parallelized) must need >= the 24h footprint (direction only at M1).
    assert _qp(2400, 1.3e9, 1e-3, 1, 1.0, 0.35) >= _qp(2400, 1.3e9, 1e-3, 24, 1.0, 0.35)


# --- CDF properties ---
def test_cdf_bounds_and_monotonic() -> None:
    c = CRQCTimelineSimulator(CFG).simulate("RSA-2048", n_trials=2000)
    assert c is not None
    assert all(0.0 <= f <= 1.0 for f in c.cdf)
    assert all(b >= a for a, b in zip(c.cdf, c.cdf[1:], strict=False))  # non-decreasing


def test_bigger_key_breaks_later() -> None:
    sim = CRQCTimelineSimulator(CFG)
    r2 = sim.simulate("RSA-2048", n_trials=2500)
    r4 = sim.simulate("RSA-4096", n_trials=2500)
    ecc = sim.simulate("ECDSA-P256", n_trials=2500)
    i = r2.years.index(2045)  # type: ignore[union-attr]
    # physics ordering: bigger/harder breaks later => lower CDF at a fixed year
    assert r4.cdf[i] <= r2.cdf[i] <= ecc.cdf[i]  # type: ignore[union-attr]


def test_non_shor_algorithm_has_no_curve() -> None:
    sim = CRQCTimelineSimulator(CFG)
    assert sim.simulate("AES-256") is None  # not in the shor resource table
    assert sim.simulate("ML-KEM-768") is None


def test_deterministic_same_seed() -> None:
    a = CRQCTimelineSimulator(CFG).simulate("RSA-2048", n_trials=1500)
    b = CRQCTimelineSimulator(CFG).simulate("RSA-2048", n_trials=1500)
    assert a.cdf == b.cdf  # type: ignore[union-attr]


def test_every_shor_vulnerable_algorithm_is_modellable() -> None:
    """Guard against a whole class of silent risk under-statement: if the canonical registry gains a
    Shor-vulnerable algorithm with no matching entry in `resource_estimates.yaml`, the simulator
    returns no CDF for it and its risk score quietly collapses to the non-modellable fallback — i.e.
    a breakable algorithm reads as unbreakable. This caught RS256/RS384/RS512/PS256/PS384/PS512 and
    ECDSA-P521 when the JOSE identifiers were added to the registry.
    """
    from qubit_core.algorithms import ALGORITHMS
    from qubit_core.schemas import QuantumAttack

    missing = [
        a.canonical
        for a in ALGORITHMS
        if a.attack is QuantumAttack.shor
        and ((res := CFG.resource_for(a.canonical)) is None or res.get("attack") != "shor")
    ]
    assert not missing, (
        f"Shor-vulnerable algorithms with no usable resource estimate: {missing}. "
        "Add an entry (or an `alias:` to the closest anchor) in resource_estimates.yaml, "
        "otherwise their CRQC timeline is empty and their risk is under-stated."
    )


def test_jose_rsa_aliases_share_the_rsa2048_curve() -> None:
    """RS256/PS256 carry no key size in a JOSE header, so they anchor on RSA-2048 (weakest common
    size ⇒ earliest break ⇒ most conservative risk). Their curves must therefore be identical."""
    sim = CRQCTimelineSimulator(CFG)
    base = sim.simulate("RSA-2048", n_trials=1500)
    for alg in ("RS256", "PS512"):
        curve = sim.simulate(alg, n_trials=1500)
        assert curve is not None, f"{alg} must be modellable"
        assert curve.cdf == base.cdf, f"{alg} should share the RSA-2048 curve"  # type: ignore[union-attr]
