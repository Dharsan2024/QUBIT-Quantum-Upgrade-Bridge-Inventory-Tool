from __future__ import annotations

from qubit_core import CryptoAsset, fingerprint
from qubit_core.schemas import (
    AssetType,
    Location,
    ProtocolDetail,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)


def _code_asset(file_path: str) -> CryptoAsset:
    return CryptoAsset(
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="RSA-2048",
        usage_context=UsageContext.kex,
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        location=Location(repo="demo", file_path=file_path, line=42),
    )


def test_fingerprint_is_16_hex() -> None:
    fp = fingerprint(_code_asset("src/auth/keygen.py"))
    assert len(fp) == 16
    int(fp, 16)  # valid hex


def test_windows_and_posix_paths_converge() -> None:
    # THE cross-platform guarantee: same repo scanned on Windows vs in a Linux container
    # must yield identical fingerprints.
    win = fingerprint(_code_asset("src\\auth\\keygen.py"))
    posix = fingerprint(_code_asset("src/auth/keygen.py"))
    assert win == posix


def test_case_insensitive_paths_converge() -> None:
    assert fingerprint(_code_asset("SRC/Auth/Keygen.py")) == fingerprint(
        _code_asset("src/auth/keygen.py")
    )


def test_line_number_does_not_affect_fingerprint() -> None:
    a = _code_asset("src/x.py")
    b = _code_asset("src/x.py")
    b.location.line = 999
    assert fingerprint(a) == fingerprint(b)


def test_occurrence_disambiguates() -> None:
    a = _code_asset("src/x.py")
    assert fingerprint(a, occurrence=1) != fingerprint(a, occurrence=2)


def test_network_endpoint_algorithm_split() -> None:
    def net(algo: str, vulnerable: bool) -> CryptoAsset:
        return CryptoAsset(
            source_scanner=SourceScanner.network,
            asset_type=AssetType.algorithm_use,
            algorithm=algo,
            usage_context=UsageContext.kex,
            quantum_vulnerable=QuantumVulnerability(
                vulnerable=vulnerable,
                attack=QuantumAttack.shor if vulnerable else QuantumAttack.none,
            ),
            location=Location(host="demo.local", service="tcp/8443"),
            protocol_detail=ProtocolDetail(protocol="tls", version="TLSv1.3"),
        )

    # one endpoint offering both a classical and a hybrid group => two distinct assets
    assert fingerprint(net("X25519", True)) != fingerprint(net("X25519MLKEM768", False))
