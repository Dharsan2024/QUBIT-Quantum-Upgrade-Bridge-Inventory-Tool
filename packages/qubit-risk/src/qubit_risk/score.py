"""HNDL risk score v0 (doc 02 M1: static, honest, explainable).

score = P(harvested) x P(decrypted before obsolete), in [0,1].
- P(harvested): expert-elicited table over (exposure, sensitivity).
- P(decrypted before obsolete): MC over shelf-life prior of
  F_a(now + L) — closed-form HNDL (doc 02 6.2.2), sampled.
Non-vulnerable (PQC) => 0. Grover-tier => small fixed marginal.
XGBoost + Bayesian net are M2; CI here is a simple honest band.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from qubit_core import CryptoAsset, QuantumAttack, SourceScanner

from .config import RiskConfig
from .hndl import harvest_prob, p_decrypt_integral
from .sensitivity import SensitivityResult
from .timeline import TimelineCurve

_GROVER_MARGINAL = 0.15  # fixed small score for AES-128/3DES-class (halved symmetric strength)

#: Directory names that mean "this file is not the running system".
_TEST_DIR_SEGMENTS = frozenset(
    {
        "test",
        "tests",
        "spec",
        "specs",
        "__tests__",
        "testing",
        "fixtures",
        "fixture",
        "testdata",
        "test_data",
        "mocks",
        "__mocks__",
        "examples",
        "example",
        "demo",
        "demos",
        "samples",
        "benchmarks",
    }
)

#: Filename shapes that mean the same thing, for repositories that keep tests beside the code
#: they exercise (Go's `foo_test.go`, JS's `foo.spec.ts`, pytest's `test_foo.py`).
_TEST_FILE_PATTERNS = (
    re.compile(r"^test_.+", re.IGNORECASE),
    re.compile(r".+_test\.[^.]+$", re.IGNORECASE),
    re.compile(r".+\.test\.[^.]+$", re.IGNORECASE),
    re.compile(r".+\.spec\.[^.]+$", re.IGNORECASE),
    re.compile(r"^conftest\.py$", re.IGNORECASE),
)


@dataclass(frozen=True)
class ScoreResult:
    score: float
    ci_low: float
    ci_high: float
    harvest_prob: float
    p_decrypt: float


def looks_like_test_path(file_path: str | None) -> bool:
    """True when a finding's file is test/fixture/example code rather than the running system.

    Whole path SEGMENTS are matched, never substrings: ``contest/``, ``latest/`` and ``protests/``
    all contain "test" and none of them is a test directory. Getting that wrong would silently
    discount real production findings, which is a far worse failure than the one this fixes.
    """
    if not file_path:
        return False
    parts = PurePosixPath(file_path.replace("\\", "/")).parts
    if not parts:
        return False
    if any(segment.lower() in _TEST_DIR_SEGMENTS for segment in parts[:-1]):
        return True
    name = parts[-1]
    return any(pattern.match(name) for pattern in _TEST_FILE_PATTERNS)


def exposure_of(asset: CryptoAsset) -> str:
    # A key in a test fixture is not reachable by an adversary harvesting live traffic, so it
    # belongs in the lowest exposure tier no matter which algorithm it names. Measured as the
    # single largest source of this pass's false positives: it previously scored a throwaway
    # RSA key in `tests/fixtures/` exactly like one terminating production TLS.
    if looks_like_test_path(asset.location.file_path):
        return "offline"

    is_net = asset.source_scanner == SourceScanner.network or asset.usage_context.value in (
        "tls",
        "kex",
    )
    if is_net:
        return "network"
    is_offline = (
        asset.source_scanner in (SourceScanner.cert, SourceScanner.key)
        and asset.protocol_detail is None
    )
    if is_offline:
        return "offline"
    return "at_rest"


def _p_decrypt(
    curve: TimelineCurve,
    sens: SensitivityResult,
    cfg: RiskConfig,
    now_year: int,
) -> float:
    """Closed-form integral f_L(ell)*F_a(now+ell) (doc 02 6.2.2), replacing the M1 MC estimate."""
    spec = cfg.shelf_life_priors["classes"].get(sens.sensitivity, {})
    return p_decrypt_integral(curve, spec, now_year)


def score_asset(
    asset: CryptoAsset,
    sens: SensitivityResult,
    curve: TimelineCurve | None,
    cfg: RiskConfig,
    now_year: int,
) -> ScoreResult:
    qv = asset.quantum_vulnerable
    if not qv.vulnerable:
        return ScoreResult(0.0, 0.0, 0.0, 0.0, 0.0)
    if qv.attack == QuantumAttack.grover or curve is None:
        # symmetric/Grover-tier or no Shor curve available: small marginal, wide band
        s = _GROVER_MARGINAL
        return ScoreResult(s, 0.0, min(1.0, s + 0.15), 0.0, 0.0)

    harvest = harvest_prob(cfg, exposure_of(asset), sens.sensitivity)
    p_dec = _p_decrypt(curve, sens, cfg, now_year)
    score = harvest * p_dec
    # Honest fixed CI band for M1 (the calibrated conformal interval is M2's XGBoost job).
    band = 0.12
    return ScoreResult(
        score=round(score, 4),
        ci_low=round(max(0.0, score - band), 4),
        ci_high=round(min(1.0, score + band), 4),
        harvest_prob=harvest,
        p_decrypt=round(p_dec, 4),
    )


__all__ = ["ScoreResult", "exposure_of", "looks_like_test_path", "score_asset"]
