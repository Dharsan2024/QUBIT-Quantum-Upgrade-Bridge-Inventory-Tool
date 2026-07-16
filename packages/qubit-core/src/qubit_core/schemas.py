"""The binding ``CryptoAsset`` schema and its nested models.

This module is the contract every QUBIT package speaks. It conforms exactly to
``docs/design/00-architecture-frame.md`` (the binding frame). Fields are **frozen**: additions
must be optional/additive and never change the meaning of an existing binding field.

Producers (scanners, bridge) create ``CryptoAsset`` values; the risk engine fills ``sensitivity``,
``shelf_life_years`` and ``risk``; the migration orchestrator fills ``migration``. The database is
the source of truth; the CycloneDX 1.7 CBOM is the exportable artifact.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    """Timezone-aware UTC now (all QUBIT timestamps are UTC)."""
    return datetime.now(UTC)


# --------------------------------------------------------------------------------------
# Enums (binding vocabularies)
# --------------------------------------------------------------------------------------


class SourceScanner(StrEnum):
    code = "code"
    config = "config"
    network = "network"
    cert = "cert"
    key = "key"


class AssetType(StrEnum):
    algorithm_use = "algorithm-use"
    protocol = "protocol"
    certificate = "certificate"
    key = "key"
    library = "library"


class UsageContext(StrEnum):
    tls = "tls"
    kex = "kex"
    signature = "signature"
    encryption_at_rest = "encryption-at-rest"
    token = "token"  # noqa: S105 — enum value, not a secret
    hash = "hash"
    password = "password"  # noqa: S105 — enum value, not a secret
    unknown = "unknown"


class Sensitivity(StrEnum):
    pii = "pii"
    phi = "phi"
    financial = "financial"
    ip = "ip"
    credentials = "credentials"
    ephemeral = "ephemeral"
    public = "public"
    unknown = "unknown"


class QuantumAttack(StrEnum):
    shor = "shor"
    grover = "grover"
    none = "none"


class MigrationStatus(StrEnum):
    """Binding 4-value asset-level status. The migration orchestrator projects its richer
    internal FSM onto these via a single tested function (``to_public_status``)."""

    pending = "pending"
    planned = "planned"
    patched = "patched"
    verified = "verified"


class Confidence(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"


# --------------------------------------------------------------------------------------
# Nested models
# --------------------------------------------------------------------------------------


class Location(BaseModel):
    """Where an asset was found. All fields optional; scanners fill what applies."""

    host: str | None = None
    service: str | None = None
    repo: str | None = None
    file_path: str | None = None
    line: int | None = Field(default=None, ge=1)


class ProtocolDetail(BaseModel):
    """Network-protocol facts (TLS/SSH/...). ``group``/``group_codepoint`` are additive fields
    written by the network scanner and bridge (declared additive deviation, doc 04)."""

    protocol: str  # "tls" | "ssh" | "ipsec" | "smtp" | "other"
    version: str | None = None  # "TLSv1.2", "TLSv1.3"
    cipher_suites: list[str] = Field(default_factory=list)  # IANA names
    group: str | None = None  # negotiated key-exchange group, e.g. "X25519MLKEM768"
    group_codepoint: int | None = None  # IANA codepoint, e.g. 0x11EC
    extensions: dict[str, object] = Field(default_factory=dict)  # sig_algs, alpn — evidence-grade


class LibraryRef(BaseModel):
    name: str
    version: str | None = None


class QuantumVulnerability(BaseModel):
    """Whether a cryptographically-relevant quantum computer threatens this asset.

    ``shor`` breaks public-key crypto (RSA/ECC/DH) outright; ``grover`` only halves symmetric
    security (a tiered concern, not a break); ``none`` == quantum-safe (PQC/large symmetric).
    """

    vulnerable: bool
    attack: QuantumAttack


class EvidenceContext(BaseModel):
    """Structured context derived from the finding. ``symbols``/``imports`` are populated by the
    code scanner at M2 and consumed by the migration dependency graph (doc 03)."""

    symbols: dict[str, list[str]] = Field(default_factory=dict)  # {"defined": [...], "used": [...]}
    imports: list[str] = Field(default_factory=list)
    extra: dict[str, object] = Field(default_factory=dict)


class Evidence(BaseModel):
    """Proof of a finding, post-redaction. ``snippet`` is ±5 lines for code, or a pcap/cert
    reference string otherwise. Private-key bytes and secrets are NEVER stored here
    (see ``qubit_core.redaction``)."""

    snippet: str = ""
    snippet_sha256: str | None = None
    context: EvidenceContext = Field(default_factory=EvidenceContext)


class RiskAnnotation(BaseModel):
    """Written by qubit-risk. ``score`` is the calibrated P(decrypted before obsolete)."""

    score: float = Field(ge=0.0, le=1.0)
    ci_low: float = Field(ge=0.0, le=1.0)
    ci_high: float = Field(ge=0.0, le=1.0)
    mosca_margin_years: float  # Z - (X + Y); negative => already too late
    priority_rank: int = Field(ge=1)


class EffortEstimate(BaseModel):
    """Migration effort. Structured to carry the orchestrator's WSJF inputs."""

    points: int  # Fibonacci story points
    hours_low: float
    hours_high: float
    drivers: list[str] = Field(default_factory=list)  # human-readable, e.g. "no test suite (+2)"


class MigrationAnnotation(BaseModel):
    """Written by qubit-migrate. ``status`` is the binding 4-value projection."""

    status: MigrationStatus
    recommendation: str
    effort_estimate: EffortEstimate | None = None


# --------------------------------------------------------------------------------------
# The binding CryptoAsset
# --------------------------------------------------------------------------------------


class CryptoAsset(BaseModel):
    """A single cryptographic asset — the unit of currency across all of QUBIT.

    BINDING schema (frame section "Shared CryptoAsset schema"). Producers set everything except
    ``sensitivity`` / ``shelf_life_years`` (risk engine) and ``risk`` / ``migration``
    (risk + migration engines). Additive provenance fields (``fingerprint`` … ``confidence``)
    are optional and never alter binding-field semantics.
    """

    model_config = ConfigDict(extra="forbid")

    # --- identity ---
    id: UUID = Field(default_factory=uuid4)

    # --- what & where (producer-set) ---
    source_scanner: SourceScanner
    location: Location = Field(default_factory=Location)
    asset_type: AssetType
    algorithm: str  # canonical registry name, e.g. "RSA-2048", "ML-KEM-768"
    key_size: int | None = None
    protocol_detail: ProtocolDetail | None = None
    library: LibraryRef | None = None
    usage_context: UsageContext = UsageContext.unknown
    quantum_vulnerable: QuantumVulnerability
    evidence: Evidence = Field(default_factory=Evidence)
    discovered_at: datetime = Field(default_factory=utcnow)

    # --- risk-engine-set (null until a risk run happens) ---
    sensitivity: Sensitivity = Sensitivity.unknown
    shelf_life_years: float | None = None
    risk: RiskAnnotation | None = None

    # --- migration-engine-set ---
    migration: MigrationAnnotation | None = None

    # --- additive provenance (doc 01 §4.1; optional, never in the binding minimum) ---
    fingerprint: str | None = None  # set by qubit_core.fingerprint at ingest
    last_seen_at: datetime | None = None
    stale: bool = False  # set when a rescan no longer observes this asset
    scan_id: UUID | None = None
    rule_id: str | None = None
    confidence: Confidence = Confidence.high


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
    "utcnow",
]
