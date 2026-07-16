from __future__ import annotations

import uuid
from pathlib import Path

from qubit_core import CryptoAsset, asset_to_row, row_to_asset
from qubit_core.db import Base, ProjectRow, ScanRow, get_engine, session_factory
from qubit_core.schemas import (
    AssetType,
    Evidence,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    Sensitivity,
    SourceScanner,
    UsageContext,
    utcnow,
)


def _engine(tmp_path: Path):
    # a real file DB (not :memory:) so WAL pragmas are exercised like production
    eng = get_engine(f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    Base.metadata.create_all(eng)
    return eng


def test_pragmas_applied(tmp_path: Path) -> None:
    eng = _engine(tmp_path)
    with eng.connect() as conn:
        from sqlalchemy import text

        assert conn.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
        assert conn.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        _ = text  # keep import used


def test_asset_roundtrip_through_db(tmp_path: Path) -> None:
    eng = _engine(tmp_path)
    sf = session_factory(eng)
    pid, sid = uuid.uuid4(), uuid.uuid4()

    asset = CryptoAsset(
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="RSA-2048",
        key_size=2048,
        usage_context=UsageContext.kex,
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        location=Location(repo="demo", file_path="src/keygen.py", line=44),
        evidence=Evidence(snippet="key = rsa.generate_private_key(key_size=2048)"),
        sensitivity=Sensitivity.credentials,
        shelf_life_years=10.0,
        risk=RiskAnnotation(
            score=0.91, ci_low=0.8, ci_high=0.98, mosca_margin_years=-3.2, priority_rank=1
        ),
    )

    with sf() as s:
        # parents committed before assets are ingested — mirrors real scan flow
        s.add(ProjectRow(id=pid, name="demo", slug="demo"))
        s.add(ScanRow(id=sid, project_id=pid, seq=1))
        s.commit()
        s.add(asset_to_row(asset, scan_id=sid, project_id=pid))
        s.commit()

    with sf() as s:
        from qubit_core.db import AssetRow

        row = s.query(AssetRow).one()
        assert row.fingerprint and len(row.fingerprint) == 16
        assert row.qv_vulnerable is True and row.qv_attack == "shor"
        assert row.risk_score == 0.91

        restored = row_to_asset(row)
        assert restored.algorithm == "RSA-2048"
        assert restored.risk is not None and restored.risk.priority_rank == 1
        assert restored.sensitivity is Sensitivity.credentials
        assert restored.location.file_path == "src/keygen.py"


def test_last_seen_default() -> None:
    pid, sid = uuid.uuid4(), uuid.uuid4()
    asset = CryptoAsset(
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        algorithm="SHA-1",
        usage_context=UsageContext.hash,
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.grover),
        discovered_at=utcnow(),
    )
    row = asset_to_row(asset, scan_id=sid, project_id=pid)
    assert row.last_seen_at == asset.discovered_at
