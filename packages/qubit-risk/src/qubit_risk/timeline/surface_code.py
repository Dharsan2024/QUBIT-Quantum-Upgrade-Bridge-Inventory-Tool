"""Surface-code resource math (doc 02 6.1.1), as pure functions over scalars or numpy arrays.

Given an algorithm's logical-qubit count Q_L and Toffoli count N_tof, and a hardware point
(gate error p, cycle/reaction times), compute the physical-qubit footprint needed to run the attack
inside a time window.

M1 fidelity: first-order model reproducing *reaction-limited*
(k=1) published anchors (GE2019 RSA-2048 ~20M @8h; Webber ECC-256
~13M @24h) within x2. The aggressively time-optimized 1h Webber
figure (317M) needs magic-state-factory / space-time modelling,
deferred to M2; M1 only asserts the correct DIRECTION.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

Array = NDArray[np.float64]

_MAX_DISTANCE = 55  # odd code distances searched: 3,5,...,55


def logical_error_rate(d: Array | int, p: Array | float, *, A: float, p_threshold: float) -> Array:
    """p_L(d) = A * (p / p_th)^((d+1)/2) — per-logical-qubit error per code cycle."""
    d_arr = np.asarray(d, dtype=np.float64)
    p_arr = np.asarray(p, dtype=np.float64)
    return A * (p_arr / p_threshold) ** ((d_arr + 1.0) / 2.0)


def min_distance(
    q_logical: int,
    n_toffoli: Array | float,
    p: Array | float,
    *,
    A: float,
    p_threshold: float,
    eps_fail: float,
) -> Array:
    """Smallest odd code distance d such that the whole run fails with prob <= eps_fail:
    Q_L * N_tof * d * p_L(d) <= eps_fail. Vectorized over n_toffoli / p. Returns float array of d.
    """
    n_arr = np.asarray(n_toffoli, dtype=np.float64)
    p_arr = np.asarray(p, dtype=np.float64)
    shape = np.broadcast(n_arr, p_arr).shape
    chosen = np.full(shape, np.nan, dtype=np.float64)
    for d in range(3, _MAX_DISTANCE + 1, 2):
        p_l = logical_error_rate(d, p_arr, A=A, p_threshold=p_threshold)
        ok = (q_logical * n_arr * d * p_l) <= eps_fail
        newly = ok & np.isnan(chosen)
        chosen = np.where(newly, float(d), chosen)
    # anything still unresolved gets the max distance (best effort)
    return np.where(np.isnan(chosen), float(_MAX_DISTANCE), chosen)


def required_physical_qubits(
    q_logical: int,
    n_toffoli: Array | float,
    p: Array | float,
    *,
    window_s: float,
    t_cycle_s: Array | float,
    t_reaction_s: Array | float,
    eta: Array | float,
    gamma: Array | float,
    A: float,
    p_threshold: float,
    eps_fail: float,
    routing_overhead: float,
    parallel_cap: int,
) -> Array:
    """Physical qubits to break the algorithm within ``window_s``.

    Footprint = eta * (1+gamma) * routing * Q_L * d^2 * k, where k is the space-time parallelization
    factor needed to compress the serial run into the window (reaction-limited). k=1 is the natural
    (Webber/GE2019 anchor) regime.
    """
    d = min_distance(
        q_logical, n_toffoli, p, A=A, p_threshold=p_threshold, eps_fail=eps_fail
    )
    n_arr = np.asarray(n_toffoli, dtype=np.float64)
    tc = np.asarray(t_cycle_s, dtype=np.float64)
    tr = np.asarray(t_reaction_s, dtype=np.float64)
    # Reaction-limited wall time at k=1 (Webber): the reaction
    # term dominates; the raw code-cycle term is a lower bound.
    # (Not N_tof*d*t_cycle — that over-inflates the depth and
    # wrongly forces k>1 on the published k=1 anchors.)
    serial_s = np.maximum(n_arr * tc, n_arr * tr)
    k = np.clip(np.ceil(serial_s / window_s), 1.0, float(parallel_cap))
    footprint = (
        np.asarray(eta, dtype=np.float64)
        * (1.0 + np.asarray(gamma, dtype=np.float64))
        * routing_overhead
        * q_logical
        * d**2
        * k
    )
    return footprint


__all__ = ["Array", "logical_error_rate", "min_distance", "required_physical_qubits"]
