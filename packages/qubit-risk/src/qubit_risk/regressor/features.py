"""34-dim feature vector for the risk regressor (doc 02 §6.4.2).

Breakdown (10+1+1+3+1+7+2+3+1+3+2 = 34):
  alg_family one-hot (10) · log2(key_size) · attack{none,grover,shor}->{0,1,2}
  p_crqc_2030 · p_crqc_2035 · p_crqc_2040 · break_year_median
  sens_probs (7) · shelf_life_mean · shelf_life_p90
  exposure one-hot (3) · usage_context ordinal
  tls_lt_1_3 · cert_expired · deprecated_lib
  bn_p_hndl · harvest_prob

Missing values use the explicit sentinel -1 (XGBoost handles natively; never a silent zero).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

_MISSING = -1.0

# 10 algorithm families (index order is the golden contract for the model file).
ALG_FAMILIES = ["RSA", "ECDSA", "ECDH", "DSA", "DH", "AES", "3DES", "SHA", "MD5", "OTHER"]
# 7 sensitivity classes (matches qubit_risk.ml.vocab.CLASSES order).
SENS_CLASSES = ["phi", "financial", "pii", "credentials", "ip", "ephemeral", "public"]
EXPOSURES = ["network", "at_rest", "offline"]
ATTACK_ORD = {"none": 0, "grover": 1, "shor": 2}
# usage_context ordinal by rough long-term-secrecy weight (higher = more persistent secrecy need)
USAGE_ORD = {
    "unknown": 0,
    "hash": 1,
    "token": 2,
    "password": 3,
    "tls": 4,
    "kex": 5,
    "signature": 6,
    "encryption-at-rest": 7,
}

FEATURE_NAMES: list[str] = (
    [f"alg_family_{f}" for f in ALG_FAMILIES]
    + ["log2_key_size", "attack_ord"]
    + ["p_crqc_2030", "p_crqc_2035", "p_crqc_2040", "break_year_median"]
    + [f"sens_{c}" for c in SENS_CLASSES]
    + ["shelf_life_mean", "shelf_life_p90"]
    + [f"exposure_{e}" for e in EXPOSURES]
    + ["usage_ord"]
    + ["tls_lt_1_3", "cert_expired", "deprecated_lib"]
    + ["bn_p_hndl", "harvest_prob"]
)
N_FEATURES = len(FEATURE_NAMES)
assert N_FEATURES == 34, N_FEATURES  # spec contract


@dataclass
class FeatureInputs:
    """Structured inputs the feature builder needs (all already computed upstream)."""

    algorithm_family: str
    key_size: int | None
    attack: str  # none | grover | shor
    p_crqc_2030: float | None
    p_crqc_2035: float | None
    p_crqc_2040: float | None
    break_year_median: float | None
    sens_probs: list[float]  # len 7, sums ~1; -1-filled if unknown
    shelf_life_mean: float | None
    shelf_life_p90: float | None
    exposure: str  # network | at_rest | offline
    usage_context: str
    tls_lt_1_3: bool = False
    cert_expired: bool = False
    deprecated_lib: bool = False
    bn_p_hndl: float | None = None
    harvest_prob: float | None = None
    extra: dict = field(default_factory=dict)


def _num(x: float | None) -> float:
    return _MISSING if x is None else float(x)


def build_features(fi: FeatureInputs) -> list[float]:
    """Deterministic 34-dim vector (order == FEATURE_NAMES)."""
    fam = [1.0 if fi.algorithm_family == f else 0.0 for f in ALG_FAMILIES]
    log2_ks = math.log2(fi.key_size) if fi.key_size and fi.key_size > 0 else _MISSING
    attack = float(ATTACK_ORD.get(fi.attack, 0))
    curve = [
        _num(fi.p_crqc_2030),
        _num(fi.p_crqc_2035),
        _num(fi.p_crqc_2040),
        _num(fi.break_year_median),
    ]
    sens = (
        [float(p) for p in fi.sens_probs]
        if fi.sens_probs and len(fi.sens_probs) == 7
        else [_MISSING] * 7
    )
    shelf = [_num(fi.shelf_life_mean), _num(fi.shelf_life_p90)]
    exposure = [1.0 if fi.exposure == e else 0.0 for e in EXPOSURES]
    usage = float(USAGE_ORD.get(fi.usage_context, 0))
    flags = [float(fi.tls_lt_1_3), float(fi.cert_expired), float(fi.deprecated_lib)]
    tail = [_num(fi.bn_p_hndl), _num(fi.harvest_prob)]
    vec = [*fam, log2_ks, attack, *curve, *sens, *shelf, *exposure, usage, *flags, *tail]
    assert len(vec) == N_FEATURES, len(vec)
    return vec


def family_of(algorithm: str) -> str:
    """Map a canonical algorithm to one of ALG_FAMILIES."""
    a = algorithm.upper()
    for fam in ALG_FAMILIES[:-1]:
        if a.startswith(fam):
            return fam
    if a.startswith(("ML-KEM", "ML-DSA", "KYBER", "DILITHIUM")):
        return "OTHER"
    return "OTHER"


__all__ = [
    "ALG_FAMILIES",
    "EXPOSURES",
    "FEATURE_NAMES",
    "N_FEATURES",
    "SENS_CLASSES",
    "FeatureInputs",
    "build_features",
    "family_of",
]
