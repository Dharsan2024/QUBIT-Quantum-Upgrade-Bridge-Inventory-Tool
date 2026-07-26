"""Teacher-label synthesis for the risk regressor (doc 02 §6.4.3).

No external data: each synthetic asset's target is the MEDIAN of the closed-form P_HNDL (§6.2.2)
over K draws of parameter uncertainty — a fresh hardware-MC curve from a per-algorithm ensemble
(re-seeded simulations), harvest-CPD jitter (±0.1 truncated), and a shelf-life draw. Extra features
(tls<1.3, cert_expired, deprecated_lib) shift the label via reviewed rules.

Parallelized across all CPU cores: the re-seeded MC ensembles and the per-asset generation are both
embarrassingly parallel, so label synthesis fans out over a process pool (Windows-spawn safe).
Defaults (n=6000, k=48) are a tractable subset of the spec's N=50k/K=200; both are CLI-configurable.
"""

from __future__ import annotations

import math
import os
import random
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, replace

import numpy as np

from ..config import RiskConfig, load_config
from ..hndl import harvest_prob, p_decrypt_integral
from ..timeline.simulator import CRQCTimelineSimulator, TimelineCurve
from .features import SENS_CLASSES, FeatureInputs, build_features, family_of

# Rough inventory frequencies (demo-lab + published CBOM stats), Shor + grover + safe mix.
_ALG_FREQ = {
    "RSA-2048": 0.28,
    "RSA-3072": 0.06,
    "RSA-4096": 0.05,
    "ECDSA-P256": 0.14,
    "ECDH-P256": 0.10,
    "AES-256": 0.12,
    "AES-128": 0.05,
    "SHA-256": 0.06,
    "3DES": 0.03,
    "MD5": 0.03,
    "SHA-1": 0.08,
}
_GROVER_MARGINAL = 0.15
_EXPOSURES = ["network", "at_rest", "offline"]
_USAGES = ["tls", "kex", "signature", "encryption-at-rest", "token", "hash", "password"]

# Per-worker globals set by the pool initializer (avoids re-pickling ensembles per task).
_G: dict = {}


@dataclass
class TrainingTable:
    X: list[list[float]]
    y: list[float]
    families: list[str]  # for stratified split


def _reseed(cfg: RiskConfig, seed: int) -> RiskConfig:
    hp = dict(cfg.hardware_priors)
    hp["seed"] = seed
    return replace(cfg, hardware_priors=hp)


# ── parallel ensemble build ────────────────────────────────────────────────────
def _sim_task(task: tuple[str, int, RiskConfig]) -> tuple[str, TimelineCurve | None]:
    algo, s, cfg = task
    sim = CRQCTimelineSimulator(_reseed(cfg, 1000 + s))
    return algo, sim.simulate(algo)


def _build_ensembles(
    algos: list[str], n_curves: int, cfg: RiskConfig, n_jobs: int
) -> dict[str, list[TimelineCurve]]:
    tasks = [(a, s, cfg) for a in algos for s in range(n_curves)]
    out: dict[str, list[TimelineCurve]] = {a: [] for a in algos}
    with ProcessPoolExecutor(max_workers=n_jobs) as ex:
        for algo, curve in ex.map(_sim_task, tasks, chunksize=4):
            if curve is not None:
                out[algo].append(curve)
    return out


# ── per-asset generation (runs in workers) ──────────────────────────────────────
def _gen_assets(
    ensembles: dict[str, list[TimelineCurve]],
    cfg: RiskConfig,
    count: int,
    k_draws: int,
    seed: int,
) -> tuple[list[list[float]], list[float], list[str]]:
    rng = np.random.default_rng(seed)
    pyrng = random.Random(seed)
    now = cfg.hardware_priors["reference_year"]
    classes = cfg.shelf_life_priors["classes"]
    algos = list(_ALG_FREQ)
    probs = np.array([_ALG_FREQ[a] for a in algos], dtype=float)
    probs /= probs.sum()

    X: list[list[float]] = []
    y: list[float] = []
    fams: list[str] = []

    for _ in range(count):
        algo = algos[int(rng.choice(len(algos), p=probs))]
        res = cfg.resource_for(algo)
        attack = (res or {}).get("attack", "none")
        if algo in cfg.resource_estimates.get("grover_tier", {}):
            attack = "grover"
        ens = ensembles[algo]

        sens_probs = [float(x) for x in rng.dirichlet(np.ones(len(SENS_CLASSES)) * 0.4)]
        dom = SENS_CLASSES[int(np.argmax(sens_probs))]
        shelf_spec = classes.get(dom, {})

        exposure = pyrng.choices(_EXPOSURES, weights=[0.5, 0.35, 0.15])[0]
        usage = pyrng.choice(_USAGES)
        tls_lt = pyrng.random() < 0.25
        cert_exp = pyrng.random() < 0.15
        dep_lib = pyrng.random() < 0.20
        base_harvest = harvest_prob(cfg, exposure, dom)

        draws = []
        for _k in range(k_draws):
            hv = float(np.clip(rng.normal(base_harvest, 0.1), 0.0, 1.0))
            if tls_lt:
                hv = min(1.0, hv * 1.15)
            if ens:
                curve = ens[pyrng.randrange(len(ens))]
                p = hv * p_decrypt_integral(curve, shelf_spec, now)
            elif attack == "grover":
                p = _GROVER_MARGINAL * float(np.clip(rng.normal(1.0, 0.1), 0, 2))
            else:
                p = 0.0
            draws.append(min(1.0, p))
        y_med = float(np.median(draws))

        p30: float | None
        p35: float | None
        p40: float | None
        bym: float | None
        sl_mean: float | None
        sl_p90: float | None
        if ens:
            mean_cdf = np.mean([c.cdf for c in ens], axis=0)
            years = ens[0].years
            p30, p35, p40 = (float(np.interp(yr, years, mean_cdf)) for yr in (2030, 2035, 2040))
            bym = next((float(yr) for yr, p in zip(years, mean_cdf, strict=True) if p >= 0.5), None)
            bn_nom = base_harvest * p_decrypt_integral(ens[0], shelf_spec, now)
        else:
            p30 = p35 = p40 = bym = None
            bn_nom = None

        if "fixed" in shelf_spec:
            sl_mean = sl_p90 = float(shelf_spec["fixed"])
        elif "mu_ln" in shelf_spec:
            mu, sg = float(shelf_spec["mu_ln"]), float(shelf_spec["sigma_ln"])
            sl_mean = math.exp(mu + sg * sg / 2)
            sl_p90 = math.exp(mu + sg * 1.2815515594)
        else:
            sl_mean = sl_p90 = None

        fi = FeatureInputs(
            algorithm_family=family_of(algo),
            key_size=(res or {}).get("key_size"),
            attack=attack,
            p_crqc_2030=p30,
            p_crqc_2035=p35,
            p_crqc_2040=p40,
            break_year_median=bym,
            sens_probs=sens_probs,
            shelf_life_mean=sl_mean,
            shelf_life_p90=sl_p90,
            exposure=exposure,
            usage_context=usage,
            tls_lt_1_3=tls_lt,
            cert_expired=cert_exp,
            deprecated_lib=dep_lib,
            bn_p_hndl=bn_nom,
            harvest_prob=base_harvest,
        )
        X.append(build_features(fi))
        y.append(y_med)
        fams.append(family_of(algo))
    return X, y, fams


def _init_worker(ensembles: dict, cfg: RiskConfig) -> None:
    _G["ens"] = ensembles
    _G["cfg"] = cfg


def _chunk_task(task: tuple[int, int, int]) -> tuple[list, list, list]:
    count, k_draws, seed = task
    return _gen_assets(_G["ens"], _G["cfg"], count, k_draws, seed)


def generate_training_table(
    *,
    n_assets: int = 6000,
    k_draws: int = 48,
    seed: int = 42,
    cfg: RiskConfig | None = None,
    n_jobs: int | None = None,
) -> TrainingTable:
    cfg = cfg or load_config()
    # Cap workers: each carries the numpy/scipy/qubit stack (~300 MB), so on a 16 GB box the
    # binding constraint is RAM, not cores. 12 is a safe, still-massively-parallel default.
    n_jobs = n_jobs or min(12, os.cpu_count() or 4)
    algos = list(_ALG_FREQ)
    n_curves = min(k_draws, 24)

    ensembles = _build_ensembles(algos, n_curves, cfg, n_jobs)

    # split assets into n_jobs deterministic chunks (seed per chunk keeps it reproducible)
    base, extra = divmod(n_assets, n_jobs)
    chunks = [
        (base + (1 if i < extra else 0), k_draws, seed + 1 + i)
        for i in range(n_jobs)
        if base + (1 if i < extra else 0) > 0
    ]
    X: list[list[float]] = []
    y: list[float] = []
    families: list[str] = []
    with ProcessPoolExecutor(
        max_workers=n_jobs, initializer=_init_worker, initargs=(ensembles, cfg)
    ) as ex:
        for xc, yc, fc in ex.map(_chunk_task, chunks):
            X.extend(xc)
            y.extend(yc)
            families.extend(fc)
    return TrainingTable(X=X, y=y, families=families)


__all__ = ["TrainingTable", "generate_training_table"]
