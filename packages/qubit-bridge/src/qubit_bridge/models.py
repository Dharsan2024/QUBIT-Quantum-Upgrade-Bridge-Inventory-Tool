"""Pydantic models for qubit-bridge."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel

BridgeEngine = Literal["nginx", "haproxy"]


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


class HandshakeMeasurement(BaseModel):
    """Result of benchmarking a TLS handshake."""
    id: UUID
    run_id: UUID
    target_host: str
    target_port: int
    group: str
    hybrid_pqc: bool
    n_samples: int
    handshake_ms_mean: float
    handshake_ms_p50: float
    handshake_ms_p95: float
    handshake_ms_stdev: float
    client_hello_bytes: int | None = None
    server_hello_bytes: int | None = None
    client_key_share_bytes: int | None = None
    server_key_share_bytes: int | None = None
    tls_version: str
    cipher_suite: str
    openssl_version: str
    captured_at: datetime


class BridgeProfile(BaseModel):
    """Configuration for bringing up a hybrid bridge container."""
    engine: BridgeEngine = "nginx"
    listen_port: int = 8443
    upstream: str
    groups: str = "X25519MLKEM768:X25519:secp256r1"
    cert_path: str = "/etc/certs/server.crt"
    key_path: str = "/etc/certs/server.key"
    server_name: str = "demo.local"
