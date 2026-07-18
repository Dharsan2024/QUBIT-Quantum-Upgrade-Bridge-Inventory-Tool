"""Regression tests for MigrationOrchestrator's DB path (doc 03 §5.2).

The orchestrator must read assets via the ORM ``AssetRow`` (hydrated with ``row_to_asset``);
selecting the Pydantic ``CryptoAsset`` directly crashes SQLAlchemy at runtime.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from qubit_core import CryptoAsset
from qubit_core.db import AssetRow, Base, ProjectRow, ScanRow
from qubit_core.mapping import asset_to_row
from qubit_core.schemas import (
    AssetType,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    SourceScanner,
    UsageContext,
)
from qubit_migrate.orchestrator import MigrationOrchestrator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def _session() -> Session:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return Session(engine)


def _seed_scan(session: Session) -> tuple[uuid.UUID, uuid.UUID]:
    project = ProjectRow(name="t", slug="t")
    session.add(project)
    session.flush()
    scan = ScanRow(project_id=project.id, seq=1, status="succeeded")
    session.add(scan)
    session.flush()
    return project.id, scan.id


def _vuln_asset(algo: str, score: float) -> CryptoAsset:
    return CryptoAsset(
        id=uuid.uuid4(),
        algorithm=algo,
        usage_context=UsageContext.kex,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path="src/app.py", line=10),
        quantum_vulnerable=QuantumVulnerability(vulnerable=True, attack=QuantumAttack.shor),
        discovered_at=datetime.now(UTC),
        risk=RiskAnnotation(
            score=score, ci_low=score, ci_high=score, mosca_margin_years=-3.0, priority_rank=1
        ),
    )


def test_build_plan_reads_asset_rows() -> None:
    """build_plan must work against real AssetRow rows (regression: select(CryptoAsset) crash)."""
    session = _session()
    project_id, scan_id = _seed_scan(session)
    for i, algo in enumerate(("RSA-2048", "ECDSA-P256")):
        session.add(
            asset_to_row(_vuln_asset(algo, 0.5 + i * 0.1), scan_id=scan_id, project_id=project_id)
        )
    session.commit()

    orch = MigrationOrchestrator(session)
    plan = orch.build_plan()

    assert plan.status == "active"
    assert plan.stats_json["tasks"] == 2
    queue = orch.get_queue(plan.id)
    assert len(queue) == 2
    assert all(t.state == "ready" for t in queue)
    # public status synced back onto the row
    row = session.get(AssetRow, queue[0].asset_id)
    assert row is not None
    assert row.migration_status is not None


def test_build_plan_min_risk_filters() -> None:
    session = _session()
    project_id, scan_id = _seed_scan(session)
    session.add(
        asset_to_row(_vuln_asset("RSA-2048", 0.2), scan_id=scan_id, project_id=project_id)
    )
    session.commit()

    plan = MigrationOrchestrator(session).build_plan(min_risk=0.9)
    assert plan.status == "completed"  # nothing in scope


def test_build_plan_skips_safe_assets() -> None:
    """quantum_vulnerable.vulnerable must gate scope (a truthy Pydantic model must not)."""
    session = _session()
    project_id, scan_id = _seed_scan(session)
    safe = _vuln_asset("AES-256", 0.4)
    safe.quantum_vulnerable = QuantumVulnerability(vulnerable=False, attack=QuantumAttack.none)
    session.add(asset_to_row(safe, scan_id=scan_id, project_id=project_id))
    session.commit()

    plan = MigrationOrchestrator(session).build_plan()
    assert plan.status == "completed"
