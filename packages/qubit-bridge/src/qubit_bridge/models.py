"""Pydantic models for qubit-bridge."""

from datetime import datetime

from pydantic import BaseModel


class ProbeResult(BaseModel):
    """Result of a TLS handshake probe against a target host."""
    host: str
    port: int
    reachable: bool
    tls_version: str | None = None
    negotiated_group: str | None = None
    group_codepoint: int | None = None
    hybrid_pqc: bool = False
    cipher_suite: str | None = None
    peer_signature_type: str | None = None
    cert_public_key_algorithm: str | None = None
    cert_public_key_bits: int | None = None
    cert_signature_algorithm: str | None = None
    cert_fingerprint_sha256: str | None = None
    cert_not_after: datetime | None = None
    offered_groups: list[str] = []
    error: str | None = None
    raw_output: str = ""
    probed_at: datetime
