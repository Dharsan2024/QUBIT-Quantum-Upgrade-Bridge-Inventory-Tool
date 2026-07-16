from __future__ import annotations

import pytest
from pydantic import ValidationError
from qubit_core import (
    AssetType,
    CryptoAsset,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)


def _asset(**over: object) -> CryptoAsset:
    base = dict(
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="RSA-2048",
        usage_context=UsageContext.kex,
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
    )
    base.update(over)
    return CryptoAsset(**base)  # type: ignore[arg-type]


def test_minimal_asset_defaults() -> None:
    a = _asset()
    assert a.sensitivity.value == "unknown"
    assert a.risk is None and a.migration is None
    assert a.confidence.value == "high"
    assert a.discovered_at.tzinfo is not None  # UTC-aware


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        CryptoAsset(
            source_scanner=SourceScanner.code,
            asset_type=AssetType.algorithm_use,
            algorithm="RSA-2048",
            quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
            not_a_real_field=1,  # type: ignore[call-arg]
        )


def test_risk_bounds_enforced() -> None:
    from qubit_core import RiskAnnotation

    with pytest.raises(ValidationError):
        RiskAnnotation(score=1.5, ci_low=0.0, ci_high=1.0, mosca_margin_years=-1.0, priority_rank=1)


def test_roundtrip_json() -> None:
    a = _asset(location=Location(repo="demo", file_path="src/x.py", line=3))
    restored = CryptoAsset.model_validate_json(a.model_dump_json())
    assert restored == a
