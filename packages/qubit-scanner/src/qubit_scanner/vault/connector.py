"""HashiCorp Vault transit/PKI connector (backlog item B1): an opt-in scanner source that polls
a running Vault server's HTTP API for managed keys and issued certificates, converting them into
``Detection``s. Original QUBIT code — Vault itself is BUSL-1.1 (not permissively open source), so
nothing here is copied from its source; only its publicly-documented HTTP API response shapes are
used (verified against the local reference clone, see docs/design/07-ecosystem-factcheck.md §11 /
THIRD_PARTY_NOTICES.md, but not code from it).

Vault's ``LIST`` verb: the API accepts either the non-standard HTTP ``LIST`` method or a plain
``GET`` with ``?list=true`` — this connector uses the latter for compatibility with httpx (and
every other standard HTTP client/proxy). A mount with zero entries returns ``404``, not an empty
list — Vault's own documented behavior, handled explicitly below rather than treated as an error.
"""

from __future__ import annotations

import httpx
from qubit_core import Location

from qubit_scanner.certs.scanner import CertScanner
from qubit_scanner.models import Detection

_DEFAULT_TIMEOUT = 5.0

# Vault transit key `type` -> (canonical-ish algorithm name, usage_context).
# `usage_context=None` means "infer from supports_signing/supports_encryption" (see _usage_context).
_KEY_TYPE_MAP: dict[str, tuple[str, str | None]] = {
    "aes128-gcm96": ("AES-128", "encryption-at-rest"),
    "aes256-gcm96": ("AES-256", "encryption-at-rest"),
    "aes128-cbc": ("AES-128", "encryption-at-rest"),
    "aes256-cbc": ("AES-256", "encryption-at-rest"),
    "chacha20-poly1305": ("ChaCha20-Poly1305", "encryption-at-rest"),
    "ecdsa-p256": ("ECDSA-P256", "signature"),
    "ecdsa-p384": ("ECDSA-P384", "signature"),
    "ecdsa-p521": ("ECDSA-P521", "signature"),
    "ed25519": ("Ed25519", "signature"),
    "rsa-2048": ("RSA-2048", None),
    "rsa-3072": ("RSA-3072", None),
    "rsa-4096": ("RSA-4096", None),
    "hmac": ("HMAC", "unknown"),  # Vault doesn't expose which hash size from `type` alone
    "aes128-cmac": ("AES-128", "unknown"),
    "aes192-cmac": ("AES-192", "unknown"),
    "aes256-cmac": ("AES-256", "unknown"),
}

# PQC key types (doc 07-ecosystem-factcheck §11): parameter_set carries the security level.
_ML_DSA_PARAMETER_SETS = {"44": "ML-DSA-44", "65": "ML-DSA-65", "87": "ML-DSA-87"}


def _usage_context(vault_type: str, key_data: dict) -> str:
    mapped = _KEY_TYPE_MAP.get(vault_type)
    if mapped and mapped[1] is not None:
        return mapped[1]
    # RSA and anything else ambiguous: infer from the capability flags Vault reports.
    if key_data.get("supports_signing") and not key_data.get("supports_encryption"):
        return "signature"
    if key_data.get("supports_encryption"):
        return "kex"
    return "unknown"


def _algorithm_for(vault_type: str, key_data: dict) -> str | None:
    if vault_type in _KEY_TYPE_MAP:
        return _KEY_TYPE_MAP[vault_type][0]
    if vault_type == "ml-dsa":
        param_set = str(key_data.get("parameter_set", ""))
        return _ML_DSA_PARAMETER_SETS.get(param_set, "ML-DSA")
    if vault_type == "slh-dsa":
        return "SLH-DSA"
    if vault_type == "hybrid":
        # Vault's hybrid transit keys pair a PQC signature alg with a classical EC curve; surface
        # the PQC half (the migration-relevant one) when Vault names it, else a generic marker.
        pqc_side = key_data.get("hybrid_key_type_pqc")
        return str(pqc_side) if pqc_side else "hybrid"
    return vault_type or None


async def _vault_get(client: httpx.AsyncClient, path: str, **params: str) -> dict | None:
    try:
        resp = await client.get(path, params=params or None)
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError):
        return None
    if resp.status_code == 404:
        return None
    try:
        resp.raise_for_status()
        return resp.json().get("data")
    except (httpx.HTTPStatusError, ValueError):
        return None


async def _scan_transit(client: httpx.AsyncClient, mount: str, addr: str) -> list[Detection]:
    listing = await _vault_get(client, f"/v1/{mount}/keys", list="true")
    if not listing:
        return []

    detections: list[Detection] = []
    for name in listing.get("keys", []):
        key_data = await _vault_get(client, f"/v1/{mount}/keys/{name}")
        if key_data is None:
            continue
        vault_type = str(key_data.get("type", ""))
        algorithm = _algorithm_for(vault_type, key_data)
        if not algorithm:
            continue
        detections.append(
            Detection(
                scanner="key",
                rule_id="VAULT-TRANSIT-KEY-001",
                raw_algorithm=algorithm,
                asset_type="key",
                usage_context=_usage_context(vault_type, key_data),
                location=Location(host=addr, service=f"{mount}/keys/{name}"),
                library_name="hashicorp-vault-transit",
                evidence_snippet=f"transit key '{name}' type={vault_type}",
                confidence="high",
            )
        )
    return detections


async def _scan_pki(client: httpx.AsyncClient, mount: str, addr: str) -> list[Detection]:
    listing = await _vault_get(client, f"/v1/{mount}/certs", list="true")
    if not listing:
        return []

    cert_scanner = CertScanner()
    detections: list[Detection] = []
    for serial in listing.get("keys", []):
        cert_data = await _vault_get(client, f"/v1/{mount}/cert/{serial}")
        if cert_data is None:
            continue
        pem = cert_data.get("certificate")
        if not pem:
            continue
        loc = Location(host=addr, service=f"{mount}/cert/{serial}")
        detections.extend(cert_scanner.parse_bytes(pem.encode("utf-8"), loc))
    return detections


async def scan_vault(
    addr: str,
    token: str,
    *,
    mount_transit: str = "transit",
    mount_pki: str = "pki",
    timeout: float = _DEFAULT_TIMEOUT,
    transport: httpx.AsyncBaseTransport | None = None,
) -> list[Detection]:
    """Poll a running Vault server's ``transit`` and ``pki`` secrets engines for managed
    keys/certs. Opt-in: requires an explicit ``addr``/``token`` — never runs as part of a default
    filesystem or network scan. Vault being unreachable or the mounts not existing both resolve
    to an empty result, not an exception — an expected, non-fatal state for an opt-in source.

    ``transport`` is injectable (httpx's standard mock-transport testing pattern) so tests can
    exercise this against crafted responses without a live Vault server."""
    headers = {"X-Vault-Token": token}
    try:
        # verify=False: dev-mode/self-signed Vault instances (the common case for this opt-in,
        # infra-scanning source) don't have a CA-trusted cert; same tradeoff TlsEnumerator makes
        # via ssl.CERT_NONE for the same reason.
        async with httpx.AsyncClient(
            base_url=addr,
            headers=headers,
            timeout=timeout,
            verify=False,  # noqa: S501
            transport=transport,
        ) as client:
            transit = await _scan_transit(client, mount_transit, addr)
            pki = await _scan_pki(client, mount_pki, addr)
            return transit + pki
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError, OSError):
        return []


class VaultUnreachable(RuntimeError):
    """Vault could not be contacted, or rejected the supplied token."""


async def verify_vault_reachable(
    addr: str,
    token: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """Raise ``VaultUnreachable`` unless ``addr`` answers and ``token`` is accepted.

    ``scan_vault`` deliberately resolves an unreachable server to an empty result — correct for an
    opt-in source that may simply not be deployed. But a *user-initiated* scan is a different
    situation: someone typed an address and a token and is waiting for an answer, and reporting
    "succeeded, 0 assets" for a typo'd address or an expired token reads as "Vault is clean" —
    the worst possible way to be wrong about a credential store.

    So callers that have an interactive user preflight with this, and callers that are sweeping
    optional infrastructure keep using ``scan_vault`` alone. The distinction that matters is
    unreachable-versus-empty, and only this function can tell them apart.
    """
    try:
        async with httpx.AsyncClient(
            base_url=addr,
            headers={"X-Vault-Token": token},
            timeout=timeout,
            verify=False,  # noqa: S501 — same dev-mode/self-signed rationale as scan_vault
            transport=transport,
        ) as client:
            # `sys/health` needs no token, so it separates "server is not there" from
            # "token is bad".
            try:
                health = await client.get("/v1/sys/health")
            except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError, OSError) as exc:
                raise VaultUnreachable(
                    f"could not reach a Vault server at {addr} ({type(exc).__name__}). "
                    "Check the address and that the server is running."
                ) from exc
            # Vault answers sys/health with 200 (unsealed+active), 429 (standby), 472/473
            # (DR/perf standby) or 501/503 (uninitialized/sealed) — all of these prove a Vault
            # is there. Anything else means the address points at something that is not Vault.
            if health.status_code not in (200, 429, 472, 473, 501, 503):
                raise VaultUnreachable(
                    f"{addr} answered HTTP {health.status_code} for /v1/sys/health — "
                    "this does not look like a Vault server."
                )
            if health.status_code in (501, 503):
                raise VaultUnreachable(
                    f"Vault at {addr} is not ready (HTTP {health.status_code}: sealed or "
                    "uninitialized). Unseal it before scanning."
                )

            lookup = await client.get("/v1/auth/token/lookup-self")
            if lookup.status_code in (401, 403):
                raise VaultUnreachable(
                    f"Vault at {addr} rejected the supplied token (HTTP {lookup.status_code}). "
                    "It may be expired, revoked, or lack read access."
                )
    except VaultUnreachable:
        raise
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPError, OSError) as exc:
        raise VaultUnreachable(
            f"could not reach a Vault server at {addr} ({type(exc).__name__})."
        ) from exc


__all__ = ["VaultUnreachable", "scan_vault", "verify_vault_reachable"]
