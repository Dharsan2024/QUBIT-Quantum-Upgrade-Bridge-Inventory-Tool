from __future__ import annotations

import json

from qubit_core import CryptoAsset, export_cbom, validate_cbom_structure
from qubit_core.schemas import (
    AssetType,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    SourceScanner,
    UsageContext,
)


def _rsa() -> CryptoAsset:
    return CryptoAsset(
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="RSA-2048",
        key_size=2048,
        usage_context=UsageContext.kex,
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        location=Location(repo="demo", file_path="src/keygen.py", line=44),
        evidence=Evidence(snippet="rsa.generate_private_key(key_size=2048)"),
        fingerprint="abcdef0123456789",
        rule_id="PY-CRYPTOGRAPHY-RSA-KEYGEN",
    )


def _mlkem() -> CryptoAsset:
    return CryptoAsset(
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="ML-KEM-768",
        usage_context=UsageContext.kex,
        quantum_vulnerable=QuantumVulnerability(vulnerable=False, attack=QuantumAttack.none),
        fingerprint="1111222233334444",
    )


def test_cbom_top_level_shape() -> None:
    doc = export_cbom([_rsa()])
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.7"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["tools"]["components"][0]["name"] == "qubit"
    assert len(doc["components"]) == 1


def test_cbom_validates_structurally() -> None:
    doc = export_cbom([_rsa(), _mlkem()])
    assert validate_cbom_structure(doc) == []


def test_algorithm_component_mapping() -> None:
    comp = export_cbom([_rsa()])["components"][0]
    assert comp["type"] == "cryptographic-asset"
    assert comp["name"] == "RSA-2048"
    assert comp["bom-ref"].startswith("urn:qubit:asset:")
    cp = comp["cryptoProperties"]
    assert cp["assetType"] == "algorithm"
    assert cp["algorithmProperties"]["primitive"] == "pke"  # RSA key transport
    assert cp["algorithmProperties"]["parameterSetIdentifier"] == "2048"
    assert cp["algorithmProperties"]["classicalSecurityLevel"] == 112
    assert cp["oid"] == "1.2.840.113549.1.1.1"


def test_quantum_verdict_in_properties() -> None:
    comp = export_cbom([_rsa()])["components"][0]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["qubit:quantum-vulnerable"] == "true"
    assert props["qubit:quantum-attack"] == "shor"
    assert props["qubit:fingerprint"] == "abcdef0123456789"


def test_pqc_component_is_safe() -> None:
    comp = export_cbom([_mlkem()])["components"][0]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["qubit:quantum-vulnerable"] == "false"
    assert comp["cryptoProperties"]["algorithmProperties"]["primitive"] == "kem"
    assert comp["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3


def test_risk_props_included_when_present() -> None:
    a = _rsa()
    a.risk = RiskAnnotation(
        score=0.91, ci_low=0.8, ci_high=0.98, mosca_margin_years=-3.2, priority_rank=1
    )
    comp = export_cbom([a])["components"][0]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["qubit:risk-score"] == "0.9100"
    assert props["qubit:mosca-margin-years"] == "-3.20"


def test_evidence_omitted_by_default_included_on_request() -> None:
    assert "evidence" not in export_cbom([_rsa()])["components"][0]
    with_ev = export_cbom([_rsa()], include_evidence=True)["components"][0]
    assert with_ev["evidence"]["occurrences"][0]["location"] == "src/keygen.py"
    assert with_ev["evidence"]["occurrences"][0]["line"] == 44


def test_reproducible_is_byte_identical() -> None:
    a = export_cbom([_rsa(), _mlkem()], reproducible=True)
    b = export_cbom([_mlkem(), _rsa()], reproducible=True)  # different input order
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_components_sorted_by_bomref() -> None:
    doc = export_cbom([_mlkem(), _rsa()])
    refs = [c["bom-ref"] for c in doc["components"]]
    assert refs == sorted(refs)
