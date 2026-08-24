"""Scanner-internal models. ``Detection`` is a raw finding before normalization into a
``qubit_core.CryptoAsset``; ``ScanResult`` is what the public API returns.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from qubit_core import CryptoAsset, Location


class Detection(BaseModel):
    """A raw finding straight from a rule match, before canonicalization/redaction."""

    scanner: str = "code"
    rule_id: str
    raw_algorithm: str  # exactly as seen: "des", "MD5", "RSA"
    key_size: int | None = None
    usage_context: str = "unknown"
    asset_type: str = "algorithm-use"
    location: Location
    library_name: str | None = None
    evidence_snippet: str = ""
    # Enclosing AST context (M2, doc 01 §4.3): {"symbols": {"defined": [...], "used": [...]},
    # "imports": [...], "extra": {"enclosing_function": ..., "enclosing_class": ...}}
    evidence_context: dict = Field(default_factory=dict)
    confidence: str = "high"


class ScanError(BaseModel):
    file: str
    reason: str


class ScanStats(BaseModel):
    files_scanned: int = 0
    files_skipped: int = 0
    parse_failures: int = 0
    detections: int = 0
    assets: int = 0
    #: How many of `assets` are quantum-vulnerable. This is the number a migration actually moves,
    #: and it was not recorded at all — so the only figure the UI could show after a migration was
    #: `assets`, the CBOM total, which a *successful* migration leaves almost unchanged by design:
    #: replacing MD5 with SHA-256 removes one asset and adds one back. Measured on the 21-app demo
    #: corpus, a run that resolved 89 of 250 vulnerable findings moved `assets` from 325 to 322,
    #: so the app reported a real 36% reduction in exposure as "3 fewer assets" and the migration
    #: looked broken when it was working.
    vulnerable: int = 0
    duration_s: float = 0.0


class ScanResult(BaseModel):
    """Complete result of a scan (non-streaming, per doc 01 §5.2)."""

    assets: list[CryptoAsset] = Field(default_factory=list)
    errors: list[ScanError] = Field(default_factory=list)
    stats: ScanStats = Field(default_factory=ScanStats)


__all__ = ["Detection", "ScanError", "ScanResult", "ScanStats"]
