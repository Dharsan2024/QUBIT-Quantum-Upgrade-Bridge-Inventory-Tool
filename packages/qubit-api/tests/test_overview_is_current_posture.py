"""A project's headline numbers describe the code as it stands, not its whole history.

The rollup counted every asset row a project had ever produced, so scanning the same codebase again
added its findings again. Measured on certbot: three scans reported "829 vulnerable" — 293 + 268 +
268, the same code counted three times — while the scans themselves showed the number FALLING from
293 to 268 as migrations landed.

That is the worst direction for an error to point. The screen that summarises a project told its
operator the problem was growing, at the exact moment the tool was shrinking it — and it grew a
little more with every scan they ran to check.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from qubit_api.routers.projects import projects_overview
from qubit_core.db import Base, ProjectRow, ScanRow
from qubit_core.db.models import DEFAULT_TENANT_ID
from qubit_core.mapping import asset_to_row
from qubit_core.schemas import (
    AssetType,
    CryptoAsset,
    Location,
    QuantumAttack,
    QuantumVulnerability,
    SourceScanner,
    UsageContext,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


def _asset(algorithm: str, vulnerable: bool) -> CryptoAsset:
    return CryptoAsset(
        id=uuid.uuid4(),
        algorithm=algorithm,
        usage_context=UsageContext.signature,
        source_scanner=SourceScanner.code,
        asset_type=AssetType.algorithm_use,
        location=Location(file_path="a.py", line=1),
        quantum_vulnerable=QuantumVulnerability(
            vulnerable=vulnerable,
            attack=QuantumAttack.shor if vulnerable else QuantumAttack.none,
        ),
        discovered_at=datetime.now(UTC),
    )


@pytest.fixture
def two_scans() -> Session:
    """One project, scanned twice: three vulnerable findings, then one after a migration."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = Session(engine)
    project = ProjectRow(name="p", slug="p", tenant_id=DEFAULT_TENANT_ID)
    session.add(project)
    session.flush()

    for seq, algorithms in (
        (1, [("ECDSA-P256", True), ("ECDSA-P256", True), ("RSA-2048", True)]),
        # The migration landed: two became ML-DSA, which is a NEW asset rather than a removed one.
        (2, [("ML-DSA-65", False), ("ML-DSA-65", False), ("RSA-2048", True)]),
    ):
        scan = ScanRow(
            project_id=project.id, seq=seq, status="succeeded", tenant_id=DEFAULT_TENANT_ID
        )
        session.add(scan)
        session.flush()
        for algorithm, vulnerable in algorithms:
            session.add(
                asset_to_row(_asset(algorithm, vulnerable), scan_id=scan.id, project_id=project.id)
            )
    session.commit()
    return session


def test_the_headline_counts_the_latest_scan_only(two_scans: Session) -> None:
    """Not the sum. Three vulnerable then one is a project with ONE vulnerable finding left."""
    (row,) = projects_overview(two_scans, DEFAULT_TENANT_ID)

    assert row.vulnerable == 1, (
        f"expected the newest scan's count; {row.vulnerable} looks like a sum across scans"
    )
    assert row.assets == 3, "and its asset total, not every asset row ever recorded"


def test_scanning_again_without_changing_anything_changes_nothing(two_scans: Session) -> None:
    """The property that makes the number trustworthy.

    Re-scanning is how an operator CHECKS their posture, so a posture that gets worse merely for
    having been checked is worse than no number at all — it punishes the person for looking.
    """
    project = two_scans.query(ProjectRow).one()
    before = projects_overview(two_scans, DEFAULT_TENANT_ID)[0].vulnerable

    scan = ScanRow(project_id=project.id, seq=3, status="succeeded", tenant_id=DEFAULT_TENANT_ID)
    two_scans.add(scan)
    two_scans.flush()
    for algorithm, vulnerable in (("ML-DSA-65", False), ("ML-DSA-65", False), ("RSA-2048", True)):
        two_scans.add(
            asset_to_row(_asset(algorithm, vulnerable), scan_id=scan.id, project_id=project.id)
        )
    two_scans.commit()

    assert projects_overview(two_scans, DEFAULT_TENANT_ID)[0].vulnerable == before


def test_a_migrated_algorithm_stops_being_listed_as_a_top_offender(two_scans: Session) -> None:
    """`top_algorithms` is read the same way and was wrong the same way: an algorithm the project
    had already migrated away from stayed in its top three forever, because the rows from the scan
    that found it were still being counted."""
    (row,) = projects_overview(two_scans, DEFAULT_TENANT_ID)

    assert "ECDSA-P256" not in row.top_algorithms, row.top_algorithms
    assert row.top_algorithms == ["RSA-2048"]
