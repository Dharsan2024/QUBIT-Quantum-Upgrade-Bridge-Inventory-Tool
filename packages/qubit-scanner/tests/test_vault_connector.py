"""Tests for the Vault transit/PKI connector (backlog item B1).

Unit tests use httpx's standard mock-transport pattern (crafted JSON responses shaped exactly
like Vault's real HTTP API, verified against the local reference clone — see
docs/design/07-ecosystem-factcheck.md §11 / THIRD_PARTY_NOTICES.md — but no code from it) so they
run without a live Vault server. One integration test spins up the real ``hashicorp/vault`` dev-mode
image, seeds real transit keys and a PKI cert through the actual HTTP API, and proves the
connector's parsing is correct against a genuine server, not just internally self-consistent.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time

import httpx
import pytest
from qubit_scanner.vault.connector import scan_vault

_ROOT_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIICtDCCAZygAwIBAgIUBNFjKkcs6Pby/Teems1swY1gyTkwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJZGVtby1yb290MB4XDTI2MDEwMTAwMDAwMFoXDTM2MDEw
MTAwMDAwMFowFDESMBAGA1UEAwwJZGVtby1yb290MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA38w2t4KeAsMJPIJoVvvGFXEyjxyi1/5+yWAFaEQB0OMc
ip4qvyPNjYJEwFGOizpnermfhpc3xt1l88y5b1L+mlv0Snr1GuMGXGY3nHmk7vax
FWkDWy8LA4PsE9dhEb3NgqnPkuKo175QtXMaIACU7YD/577/w0Q5y9F8ODGEXkPk
bUbOhylf2OPffktC4oeJwWubrYMBTFbvSAac5PknAzTePef6aeP7FPA3Hu07gki8
d0Tt8wNXqLDSqD276pTs20L06SQEMWS0eL1j5eXi+ORNLSVzno9ebBq966r2q/u/
qmT4z7d3AOT6vzjwLdi3Z3YM1OYto+/6OxRBz5zLywIDAQABMA0GCSqGSIb3DQEB
CwUAA4IBAQAyVWId5LhPvymgo9buyPaQMoVI1Gcx08kISiEzbqDaoUUVmKofpvBr
jpz7hUvdRrynls6+I0vq03ydr90EKPq8OywocIN/F0iqghv9CXBJf6gT1Kdgpnu6
tG9mzZe48ewmUw2cb79oTA3OMARJ7x/IPLbk51tSUb1y08zT7BjppQENr7rBr/MS
skeybYwt+KzV4/90DI9CXLv1O6G4BxThevSlyNErAyJIJSaZaHrh8RaiycaBzvQx
00Eye3CPnoeubBQcTUGZeA2zc+EsCQDvW5HAYSOmdA7b9JGwzEeYnYCL4bbkknUS
8Fh9zNO8ZVMagbmflxr7VWE8CFc6VpMx
-----END CERTIFICATE-----"""


def _route(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    query = dict(request.url.params)

    if path == "/v1/transit/keys" and query.get("list") == "true":
        return httpx.Response(200, json={"data": {"keys": ["rsa-key", "aes-key", "ed-key"]}})

    if path == "/v1/transit/keys/rsa-key":
        return httpx.Response(
            200,
            json={
                "data": {
                    "name": "rsa-key",
                    "type": "rsa-2048",
                    "supports_signing": True,
                    "supports_encryption": True,
                }
            },
        )
    if path == "/v1/transit/keys/aes-key":
        return httpx.Response(
            200,
            json={
                "data": {
                    "name": "aes-key",
                    "type": "aes256-gcm96",
                    "supports_signing": False,
                    "supports_encryption": True,
                }
            },
        )
    if path == "/v1/transit/keys/ed-key":
        return httpx.Response(
            200,
            json={
                "data": {
                    "name": "ed-key",
                    "type": "ed25519",
                    "supports_signing": True,
                    "supports_encryption": False,
                }
            },
        )

    if path == "/v1/pki/certs" and query.get("list") == "true":
        return httpx.Response(200, json={"data": {"keys": ["aa:bb:cc"]}})
    if path == "/v1/pki/cert/aa:bb:cc":
        return httpx.Response(200, json={"data": {"certificate": _ROOT_CERT_PEM}})

    return httpx.Response(404, json={"errors": []})


def _run(coro):
    return asyncio.run(coro)


def test_full_scan_maps_transit_types_correctly() -> None:
    transport = httpx.MockTransport(_route)
    dets = _run(scan_vault("http://vault.local", "tok", transport=transport))

    by_algo = {d.raw_algorithm: d for d in dets if d.scanner == "key"}
    assert by_algo["RSA-2048"].usage_context == "kex"  # supports_encryption -> kex
    assert by_algo["AES-256"].usage_context == "encryption-at-rest"
    assert by_algo["Ed25519"].usage_context == "signature"
    assert all(d.location.host == "http://vault.local" for d in dets)
    assert all(d.library_name == "hashicorp-vault-transit" for d in by_algo.values())


def test_empty_transit_mount_returns_no_key_detections() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "transit/keys" in request.url.path:
            return httpx.Response(404)  # Vault's real behavior: empty mount -> 404, not []
        return _route(request)

    transport = httpx.MockTransport(handler)
    dets = _run(scan_vault("http://vault.local", "tok", transport=transport))
    assert not any(d.scanner == "key" for d in dets)


def test_bad_token_returns_empty_not_exception() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"errors": ["permission denied"]})

    transport = httpx.MockTransport(handler)
    dets = _run(scan_vault("http://vault.local", "wrong-token", transport=transport))
    assert dets == []


def test_ml_dsa_key_maps_by_parameter_set() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if (
            request.url.path == "/v1/transit/keys"
            and dict(request.url.params).get("list") == "true"
        ):
            return httpx.Response(200, json={"data": {"keys": ["pqc-sig-key"]}})
        if request.url.path == "/v1/transit/keys/pqc-sig-key":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "name": "pqc-sig-key",
                        "type": "ml-dsa",
                        "parameter_set": "65",
                        "supports_signing": True,
                        "supports_encryption": False,
                    }
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    dets = _run(scan_vault("http://vault.local", "tok", transport=transport))
    key_dets = [d for d in dets if d.scanner == "key"]
    assert len(key_dets) == 1
    assert key_dets[0].raw_algorithm == "ML-DSA-65"
    assert key_dets[0].usage_context == "signature"


def test_slh_dsa_and_hybrid_key_types() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if (
            request.url.path == "/v1/transit/keys"
            and dict(request.url.params).get("list") == "true"
        ):
            return httpx.Response(200, json={"data": {"keys": ["slh-key", "hybrid-key"]}})
        if request.url.path == "/v1/transit/keys/slh-key":
            return httpx.Response(
                200,
                json={"data": {"name": "slh-key", "type": "slh-dsa", "supports_signing": True}},
            )
        if request.url.path == "/v1/transit/keys/hybrid-key":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "name": "hybrid-key",
                        "type": "hybrid",
                        "hybrid_key_type_pqc": "ML-DSA-65",
                        "supports_signing": True,
                    }
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    dets = _run(scan_vault("http://vault.local", "tok", transport=transport))
    algos = {d.raw_algorithm for d in dets if d.scanner == "key"}
    assert algos == {"SLH-DSA", "ML-DSA-65"}


def test_unmapped_key_type_still_reported_honestly() -> None:
    """A Vault key type this connector doesn't have a specific mapping for still produces a
    finding (raw_algorithm = the Vault type string itself) rather than being silently dropped —
    it'll resolve to UNKNOWN(...) downstream, same "nothing silently dropped" contract as the
    rest of the scanner."""

    def handler(request: httpx.Request) -> httpx.Response:
        if (
            request.url.path == "/v1/transit/keys"
            and dict(request.url.params).get("list") == "true"
        ):
            return httpx.Response(200, json={"data": {"keys": ["managed"]}})
        if request.url.path == "/v1/transit/keys/managed":
            return httpx.Response(200, json={"data": {"name": "managed", "type": "managed_key"}})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    dets = _run(scan_vault("http://vault.local", "tok", transport=transport))
    assert [d.raw_algorithm for d in dets if d.scanner == "key"] == ["managed_key"]


def test_pki_cert_reuses_cert_scanner_parsing() -> None:
    transport = httpx.MockTransport(_route)
    dets = _run(scan_vault("http://vault.local", "tok", transport=transport))
    cert_dets = [d for d in dets if d.scanner == "cert"]
    assert any(d.rule_id == "CERT-PUBKEY-001" for d in cert_dets)
    assert any(d.rule_id == "CERT-SIGALGO-001" for d in cert_dets)


def test_connection_error_returns_empty() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    transport = httpx.MockTransport(handler)
    dets = _run(scan_vault("http://vault.local", "tok", transport=transport))
    assert dets == []


# ---------------------------------------------------------------------------
# Integration: the real hashicorp/vault dev-mode image
# ---------------------------------------------------------------------------


def _docker_up() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=10).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


pytest.importorskip("testcontainers")
if not _docker_up():
    pytest.skip("docker daemon unavailable", allow_module_level=True)

from testcontainers.core.container import DockerContainer  # noqa: E402


@pytest.mark.integration
def test_scan_vault_against_real_dev_server() -> None:
    root_token = "qubit-integration-test-token"
    container = (
        DockerContainer("hashicorp/vault:latest")
        .with_env("VAULT_DEV_ROOT_TOKEN_ID", root_token)
        .with_env("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
        .with_exposed_ports(8200)
    )
    with container as vault:
        time.sleep(3)
        host = vault.get_container_host_ip()
        port = vault.get_exposed_port(8200)
        addr = f"http://{host}:{port}"
        headers = {"X-Vault-Token": root_token, "Content-Type": "application/json"}

        with httpx.Client(base_url=addr, headers=headers, timeout=10.0) as setup:
            assert setup.post(
                "/v1/sys/mounts/transit", content=json.dumps({"type": "transit"})
            ).status_code in (200, 204)
            assert setup.post(
                "/v1/sys/mounts/pki", content=json.dumps({"type": "pki"})
            ).status_code in (200, 204)
            assert setup.post(
                "/v1/transit/keys/int-rsa", content=json.dumps({"type": "rsa-2048"})
            ).status_code in (200, 204)
            assert setup.post(
                "/v1/transit/keys/int-ecdsa", content=json.dumps({"type": "ecdsa-p256"})
            ).status_code in (200, 204)
            assert setup.post(
                "/v1/pki/root/generate/internal",
                content=json.dumps({"common_name": "qubit-it-root", "ttl": "87600h"}),
            ).status_code in (200, 204)

        dets = asyncio.run(scan_vault(addr, root_token))
        key_algos = {d.raw_algorithm for d in dets if d.scanner == "key"}
        cert_rule_ids = {d.rule_id for d in dets if d.scanner == "cert"}

        assert {"RSA-2048", "ECDSA-P256"} <= key_algos
        assert "CERT-PUBKEY-001" in cert_rule_ids
