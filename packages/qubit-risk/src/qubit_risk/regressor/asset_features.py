"""Assemble the 34-dim regressor feature vector from live pipeline state (doc 02 §6.4.2).

Kept separate from features.py so the pure feature contract has no risk-internal imports.
"""

from __future__ import annotations

from qubit_core import CryptoAsset

from ..config import RiskConfig
from ..hndl import harvest_prob, p_decrypt_integral
from ..score import exposure_of
from ..sensitivity import SensitivityResult
from ..timeline import TimelineCurve
from .features import SENS_CLASSES, FeatureInputs, build_features, family_of


def _sens_probs(sens: SensitivityResult) -> list[float]:
    """Soft 7-vector: mass on the classified class, small uniform elsewhere."""
    if sens.sensitivity not in SENS_CLASSES:
        return [-1.0] * 7  # unknown -> sentinel (broad prior)
    hi, lo = 0.7, 0.3 / (len(SENS_CLASSES) - 1)
    return [hi if c == sens.sensitivity else lo for c in SENS_CLASSES]


def _deprecated_lib(asset: CryptoAsset) -> bool:
    return asset.algorithm.upper().startswith(("MD5", "SHA-1", "3DES", "DES", "RC4"))


def build_asset_features(
    asset: CryptoAsset,
    sens: SensitivityResult,
    curve: TimelineCurve | None,
    cfg: RiskConfig,
    now_year: int,
) -> list[float]:
    qv = asset.quantum_vulnerable
    exposure = exposure_of(asset)
    shelf_spec = cfg.shelf_life_priors["classes"].get(sens.sensitivity, {})

    p30: float | None
    p35: float | None
    p40: float | None
    bym: float | None
    bn: float | None
    if curve is not None:
        years, cdf = curve.years, curve.cdf

        def _at(yr: int) -> float:
            for y, p in zip(years, cdf, strict=True):
                if y >= yr:
                    return float(p)
            return float(cdf[-1])

        p30, p35, p40 = _at(2030), _at(2035), _at(2040)
        bym = curve.median_year
        bn = harvest_prob(cfg, exposure, sens.sensitivity) * p_decrypt_integral(
            curve, shelf_spec, now_year
        )
    else:
        p30 = p35 = p40 = bym = None
        bn = None

    fi = FeatureInputs(
        algorithm_family=family_of(asset.algorithm),
        key_size=asset.key_size,
        attack=qv.attack.value,
        p_crqc_2030=p30,
        p_crqc_2035=p35,
        p_crqc_2040=p40,
        break_year_median=bym,
        sens_probs=_sens_probs(sens),
        shelf_life_mean=sens.shelf_life_years,
        shelf_life_p90=sens.shelf_life_p90,
        exposure=exposure,
        usage_context=asset.usage_context.value,
        tls_lt_1_3=bool(asset.protocol_detail and (asset.protocol_detail.version or "") < "1.3"),
        cert_expired=False,
        deprecated_lib=_deprecated_lib(asset),
        bn_p_hndl=bn,
        harvest_prob=harvest_prob(cfg, exposure, sens.sensitivity),
    )
    return build_features(fi)


__all__ = ["build_asset_features"]
