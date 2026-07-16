"""qubit-core — the shared foundation for QUBIT.

Public surface: the binding ``CryptoAsset`` schema and its enums/nested models, the canonical
algorithm registry (``algorithms``), deterministic ``fingerprint``, evidence ``redaction``, the
``db`` layer, and Pydantic<->ORM ``mapping`` helpers.
"""

from __future__ import annotations

from . import algorithms, redaction
from .fingerprint import fingerprint
from .mapping import asset_to_row, row_to_asset
from .schemas import (
    AssetType,
    Confidence,
    CryptoAsset,
    EffortEstimate,
    Evidence,
    EvidenceContext,
    LibraryRef,
    Location,
    MigrationAnnotation,
    MigrationStatus,
    ProtocolDetail,
    QuantumAttack,
    QuantumVulnerability,
    RiskAnnotation,
    Sensitivity,
    SourceScanner,
    UsageContext,
    utcnow,
)

__version__ = "0.1.0"

__all__ = [
    "AssetType",
    "Confidence",
    "CryptoAsset",
    "EffortEstimate",
    "Evidence",
    "EvidenceContext",
    "LibraryRef",
    "Location",
    "MigrationAnnotation",
    "MigrationStatus",
    "ProtocolDetail",
    "QuantumAttack",
    "QuantumVulnerability",
    "RiskAnnotation",
    "Sensitivity",
    "SourceScanner",
    "UsageContext",
    "__version__",
    "algorithms",
    "asset_to_row",
    "fingerprint",
    "redaction",
    "row_to_asset",
    "utcnow",
]
