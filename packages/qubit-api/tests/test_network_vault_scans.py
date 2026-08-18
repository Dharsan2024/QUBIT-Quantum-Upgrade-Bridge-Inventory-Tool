"""Network and Vault scans through the API, plus the job→scan failure propagation they surfaced.

`scan_network` and `scan_vault` were both real and tested but CLI-only — `scan_network`'s own
docstring said "not yet wired into qubit-api's job runner either; both are CLI-only for now". They
are two of the six discovery inputs the architecture claims, so the app offered four.

The tests that need live infrastructure (a TLS server, a Vault) are marked `integration`. The ones
here need neither: they cover the authorization contract, the secret-handling contract, and the
failure propagation, all of which are exactly where a wiring mistake would be invisible.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings
from qubit_core.db import Job, ScanRow, get_engine, session_factory
from sqlalchemy import select


def _client(tmp_path: Path) -> TestClient:
    settings = Settings(
        db_url=f"sqlite:///{(tmp_path / 'netvault.db').as_posix()}",
        create_schema_on_startup=True,
    )
    client = TestClient(
        create_app(settings), headers={"Authorization": f"Bearer {settings.api_token}"}
    )
    client.qubit_db_url = settings.db_url  # type: ignore[attr-defined]
    return client


def _project(client: TestClient) -> str:
    return client.post("/api/v1/projects", json={"name": "netvault"}).json()["id"]


def _await_scan(client: TestClient, scan_id: str, timeout: float = 60.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        scan = client.get(f"/api/v1/scans/{scan_id}").json()
        if scan["status"] not in ("queued", "running"):
            return scan
        time.sleep(0.2)
    raise TimeoutError(f"scan {scan_id} never reached a terminal state")


# ── The authorization contract ───────────────────────────────────────────────────────────────────


def test_public_target_without_authorization_fails_the_scan_loudly(tmp_path: Path) -> None:
    """A refused target must FAIL the scan, not leave it running forever.

    This is what exposed the propagation bug fixed alongside it: the job correctly failed with the
    refusal reason while its ScanRow stayed at status "running" with a null error — so the UI showed
    a spinner that would never resolve, and `recover_orphaned` would only clean it up on the next
    restart. The refusal itself comes from `verify_scan_authorization`, which permits loopback and
    RFC1918 unconditionally and requires an allowlist entry plus `authorized` for anything else.
    """
    with _client(tmp_path) as client:
        project_id = _project(client)
        resp = client.post(
            f"/api/v1/projects/{project_id}/scans/network",
            json={"targets": ["example.com"], "ports": [443]},
        )
        assert resp.status_code == 202, resp.text
        scan = _await_scan(client, resp.json()["scan"]["id"])

        assert scan["status"] == "failed"
        assert scan["error"], "a failed scan with no error message is not actionable"
        assert "refused" in scan["error"].lower()
        assert scan["finished_at"] is not None


def test_loopback_target_is_permitted_without_the_authorized_flag(tmp_path: Path) -> None:
    """Loopback needs no authorization, so the scan must not be refused.

    It may still fail for a lack of anything listening — that is a connection outcome, not an
    authorization one — so this asserts only that the refusal path was not taken.
    """
    with _client(tmp_path) as client:
        project_id = _project(client)
        resp = client.post(
            f"/api/v1/projects/{project_id}/scans/network",
            # Port 9 (discard) is almost certainly closed — the point is that neither
            # outcome is a refusal.
            json={"targets": ["127.0.0.1"], "ports": [9]},
        )
        scan = _await_scan(client, resp.json()["scan"]["id"])
        assert "refused" not in (scan["error"] or "").lower()


def test_network_scan_requires_at_least_one_target(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        project_id = _project(client)
        resp = client.post(
            f"/api/v1/projects/{project_id}/scans/network", json={"targets": [], "ports": [443]}
        )
        assert resp.status_code == 422


# ── The secret-handling contract ─────────────────────────────────────────────────────────────────


def test_vault_token_is_never_persisted_anywhere(tmp_path: Path) -> None:
    """The single most important property of the Vault path.

    `Job.payload` is a persisted JSON column. A token there would be written to the database,
    returned by `GET /jobs/{id}`, and kept in every backup — indefensible for a tool whose
    purpose is finding credentials people left lying around. It travels through the
    process-local single-use store in `jobs/secrets.py` instead. This asserts against the raw
    DB rows, not just the API responses, because a response filter would be the easy way to
    look correct while still storing the secret.
    """
    secret = "s.THIS-MUST-NEVER-BE-STORED"  # a fixture, not a real credential
    with _client(tmp_path) as client:
        project_id = _project(client)
        resp = client.post(
            f"/api/v1/projects/{project_id}/scans/vault",
            json={"addr": "http://127.0.0.1:9", "token": secret},
        )
        assert resp.status_code == 202, resp.text
        body = resp.json()

        # Not in the creation response.
        assert secret not in resp.text
        # Not recorded as a scan target (the address is; the token must not be).
        assert body["scan"]["targets"] == ["http://127.0.0.1:9"]

        job_id = body["job"]["id"]
        assert secret not in client.get(f"/api/v1/jobs/{job_id}").text

        _await_scan(client, body["scan"]["id"])

        # And not in the database, which is the assertion that actually matters.
        engine = get_engine(client.qubit_db_url)  # type: ignore[attr-defined]
        with session_factory(engine)() as session:
            for job in session.scalars(select(Job)).all():
                assert "token" not in (job.payload or {})
                assert secret not in str(job.payload)
                assert secret not in str(job.result or "")
                assert secret not in str(job.error or "")
            for scan in session.scalars(select(ScanRow)).all():
                assert secret not in str(scan.targets)
                assert secret not in str(scan.error or "")


def test_unreachable_vault_fails_rather_than_reporting_an_empty_inventory(tmp_path: Path) -> None:
    """`scan_vault` alone returns [] for an unreachable server; a user-initiated scan must not.

    Zero assets and "succeeded" is indistinguishable from a Vault that genuinely holds nothing, so a
    typo'd address or an expired token would read as "Vault is clean" — the worst way to be wrong
    about a credential store. The API preflights reachability (`verify_vault_reachable`) first.
    """
    with _client(tmp_path) as client:
        project_id = _project(client)
        resp = client.post(
            f"/api/v1/projects/{project_id}/scans/vault",
            json={"addr": "http://127.0.0.1:9", "token": "irrelevant"},
        )
        scan = _await_scan(client, resp.json()["scan"]["id"])
        assert scan["status"] == "failed"
        assert "could not reach" in (scan["error"] or "").lower()


@pytest.mark.parametrize(
    ("payload", "missing"),
    [
        ({"addr": "", "token": "t"}, "address"),
        ({"addr": "http://127.0.0.1:8200", "token": ""}, "token"),
    ],
)
def test_vault_scan_validates_its_inputs(tmp_path: Path, payload: dict, missing: str) -> None:
    with _client(tmp_path) as client:
        project_id = _project(client)
        resp = client.post(f"/api/v1/projects/{project_id}/scans/vault", json=payload)
        assert resp.status_code == 422
        assert missing in resp.text.lower()


# ── Live infrastructure ──────────────────────────────────────────────────────────────────────────


@pytest.mark.integration
def test_network_scan_finds_the_hybrid_pqc_group_on_a_real_server(tmp_path: Path) -> None:
    """Requires the demo TLS server:
    `docker run -d --rm -p 8443:8443 qubit-nginx-hybrid:latest`.

    Asserts the thing that cannot be faked: `X25519MLKEM768` read off a real handshake. Note the
    container listens on 8443 *inside* the container — mapping host 8443 to container 443 produces a
    TCP-accepting port with no TLS behind it and a scan that finds nothing.
    """
    import socket

    try:
        socket.create_connection(("127.0.0.1", 8443), timeout=2).close()
    except OSError:
        pytest.skip("no TLS server on 127.0.0.1:8443 (see docstring for the docker command)")

    with _client(tmp_path) as client:
        project_id = _project(client)
        resp = client.post(
            f"/api/v1/projects/{project_id}/scans/network",
            json={"targets": ["127.0.0.1"], "ports": [8443], "probe_pqc": True},
        )
        scan = _await_scan(client, resp.json()["scan"]["id"])
        assert scan["status"] == "succeeded", scan.get("error")

        assets = client.get(f"/api/v1/scans/{scan['id']}/assets?limit=100").json()["items"]
        algorithms = {a["algorithm"] for a in assets}
        assert "X25519MLKEM768" in algorithms, f"got {algorithms}"
        assert all(a["source_scanner"] == "network" for a in assets)


@pytest.mark.integration
def test_vault_scan_finds_transit_keys_and_pki_certs_on_a_real_server(tmp_path: Path) -> None:
    """Requires the seeded demo Vault:
    `docker compose -f demo-lab/compose.vault.yml up -d`.
    """
    import urllib.error
    import urllib.request

    addr = "http://127.0.0.1:8200"
    try:
        urllib.request.urlopen(f"{addr}/v1/sys/health", timeout=2)  # local health probe
    except (urllib.error.URLError, OSError):
        pytest.skip("no Vault on 127.0.0.1:8200 (see docstring for the compose command)")

    with _client(tmp_path) as client:
        project_id = _project(client)
        resp = client.post(
            f"/api/v1/projects/{project_id}/scans/vault",
            json={"addr": addr, "token": "qubit-demo-root-token"},
        )
        scan = _await_scan(client, resp.json()["scan"]["id"])
        assert scan["status"] == "succeeded", scan.get("error")

        assets = client.get(f"/api/v1/scans/{scan['id']}/assets?limit=100").json()["items"]
        scanners = {a["source_scanner"] for a in assets}
        assert "key" in scanners, "transit keys were not discovered"
        assert "cert" in scanners, "PKI certificates were not discovered"

        # No UNKNOWN(...) may survive. The seeded certificates are signed with
        # sha256WithRSAEncryption, which resolved to nothing until the registry learned the X.509
        # signature-algorithm spellings — and an unresolved name is rated NOT vulnerable, so every
        # certificate signature was reported quantum-safe.
        unknown = [a["algorithm"] for a in assets if a["algorithm"].startswith("UNKNOWN(")]
        assert unknown == [], f"unresolved algorithms are silently rated safe: {unknown}"
