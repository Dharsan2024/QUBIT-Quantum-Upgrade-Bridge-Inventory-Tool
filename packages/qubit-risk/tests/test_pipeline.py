from __future__ import annotations

from qubit_core import CryptoAsset
from qubit_core.schemas import (
    AssetType,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)
from qubit_risk import RiskPipeline


def _vuln_rsa(snippet: str, usage: UsageContext = UsageContext.kex) -> CryptoAsset:
    return CryptoAsset(
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="RSA-2048",
        usage_context=usage,
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        location=Location(file_path="a.py", line=1),
        evidence=Evidence(snippet=snippet),
    )


def _safe_mlkem() -> CryptoAsset:
    return CryptoAsset(
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="ML-KEM-768",
        usage_context=UsageContext.kex,
        quantum_vulnerable=QuantumVulnerability(vulnerable=False, attack=QuantumAttack.none),
    )


def test_pipeline_annotates_all_fields() -> None:
    assets = [_vuln_rsa("password store"), _safe_mlkem()]
    RiskPipeline().assess(assets)
    for a in assets:
        assert a.risk is not None
        assert 0.0 <= a.risk.score <= 1.0
        assert a.risk.ci_low <= a.risk.score <= a.risk.ci_high
        assert a.sensitivity is not None


def test_vulnerable_scores_above_safe() -> None:
    # long-lived PHI: harvested today, still secret past CRQC => real HNDL risk (> 0).
    # (A short-lived credentials asset would correctly score ~0 — that's the engine being right.)
    vuln = _vuln_rsa("patient diagnosis medical_record")
    safe = _safe_mlkem()
    RiskPipeline().assess([vuln, safe])
    assert vuln.risk.score > 0.0  # type: ignore[union-attr]
    assert safe.risk.score == 0.0  # type: ignore[union-attr]
    assert (
        vuln.risk.priority_rank  # type: ignore[union-attr]
        < safe.risk.priority_rank  # type: ignore[union-attr]
    )  # higher risk ranks first


def test_high_sensitivity_outranks_low() -> None:
    phi = _vuln_rsa("patient medical_record", usage=UsageContext.kex)
    eph = _vuln_rsa("session_token cache_key", usage=UsageContext.kex)
    RiskPipeline().assess([eph, phi])
    assert phi.risk.score >= eph.risk.score  # type: ignore[union-attr]


def test_deterministic_scores() -> None:
    a1 = _vuln_rsa("password")
    a2 = _vuln_rsa("password")
    RiskPipeline().assess([a1])
    RiskPipeline().assess([a2])
    assert a1.risk.score == a2.risk.score  # type: ignore[union-attr]
