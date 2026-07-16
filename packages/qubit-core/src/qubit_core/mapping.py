"""Convert between the Pydantic ``CryptoAsset`` (the wire/domain model) and the ORM ``AssetRow``
(the physical row). Keeping this in one place means the flatten/unflatten logic is tested once.
"""

from __future__ import annotations

import uuid

from .db.models import AssetRow
from .fingerprint import fingerprint as compute_fingerprint
from .schemas import (
    AssetType,
    Confidence,
    CryptoAsset,
    Evidence,
    LibraryRef,
    Location,
    ProtocolDetail,
    Sensitivity,
    SourceScanner,
    UsageContext,
)


def asset_to_row(
    asset: CryptoAsset,
    *,
    scan_id: uuid.UUID,
    project_id: uuid.UUID,
    occurrence: int = 1,
) -> AssetRow:
    """Flatten a domain ``CryptoAsset`` into an ``AssetRow`` ready for insert."""
    fp = asset.fingerprint or compute_fingerprint(asset, occurrence=occurrence)
    return AssetRow(
        id=asset.id,
        scan_id=scan_id,
        project_id=project_id,
        fingerprint=fp,
        source_scanner=asset.source_scanner.value,
        asset_type=asset.asset_type.value,
        algorithm=asset.algorithm,
        key_size=asset.key_size,
        usage_context=asset.usage_context.value,
        sensitivity=asset.sensitivity.value,
        shelf_life_years=asset.shelf_life_years,
        qv_vulnerable=asset.quantum_vulnerable.vulnerable,
        qv_attack=asset.quantum_vulnerable.attack.value,
        confidence=asset.confidence.value,
        rule_id=asset.rule_id,
        stale=asset.stale,
        location=asset.location.model_dump(),
        protocol_detail=asset.protocol_detail.model_dump() if asset.protocol_detail else None,
        library=asset.library.model_dump() if asset.library else None,
        evidence=asset.evidence.model_dump(),
        discovered_at=asset.discovered_at,
        last_seen_at=asset.last_seen_at or asset.discovered_at,
        risk_score=asset.risk.score if asset.risk else None,
        risk_ci_low=asset.risk.ci_low if asset.risk else None,
        risk_ci_high=asset.risk.ci_high if asset.risk else None,
        mosca_margin_years=asset.risk.mosca_margin_years if asset.risk else None,
        priority_rank=asset.risk.priority_rank if asset.risk else None,
        migration_status=asset.migration.status.value if asset.migration else None,
        migration_json=asset.migration.model_dump() if asset.migration else None,
    )


def row_to_asset(row: AssetRow) -> CryptoAsset:
    """Reconstruct a domain ``CryptoAsset`` from a persisted row."""
    from .schemas import MigrationAnnotation, QuantumAttack, QuantumVulnerability, RiskAnnotation

    risk = None
    if row.risk_score is not None:
        risk = RiskAnnotation(
            score=row.risk_score,
            ci_low=row.risk_ci_low if row.risk_ci_low is not None else row.risk_score,
            ci_high=row.risk_ci_high if row.risk_ci_high is not None else row.risk_score,
            mosca_margin_years=row.mosca_margin_years
            if row.mosca_margin_years is not None
            else 0.0,
            priority_rank=row.priority_rank if row.priority_rank is not None else 1,
        )
    migration = (
        MigrationAnnotation.model_validate(row.migration_json) if row.migration_json else None
    )
    return CryptoAsset(
        id=row.id,
        source_scanner=SourceScanner(row.source_scanner),
        location=Location.model_validate(row.location or {}),
        asset_type=AssetType(row.asset_type),
        algorithm=row.algorithm,
        key_size=row.key_size,
        protocol_detail=ProtocolDetail.model_validate(row.protocol_detail)
        if row.protocol_detail
        else None,
        library=LibraryRef.model_validate(row.library) if row.library else None,
        usage_context=UsageContext(row.usage_context),
        quantum_vulnerable=QuantumVulnerability(
            vulnerable=row.qv_vulnerable, attack=QuantumAttack(row.qv_attack)
        ),
        evidence=Evidence.model_validate(row.evidence or {}),
        discovered_at=row.discovered_at,
        sensitivity=Sensitivity(row.sensitivity),
        shelf_life_years=row.shelf_life_years,
        risk=risk,
        migration=migration,
        fingerprint=row.fingerprint,
        last_seen_at=row.last_seen_at,
        stale=row.stale,
        scan_id=row.scan_id,
        rule_id=row.rule_id,
        confidence=Confidence(row.confidence),
    )


__all__ = ["asset_to_row", "row_to_asset"]
