"""Operational hardening: scan-target confinement and mutating-request rate limiting.

Both close gaps that were real in a *shared* deployment while being deliberately inert in the
desktop one, which is why each is opt-in by configuration rather than on by default:

* A scan target was any path the server process could read. For `qubit serve` on your own machine
  that is the entire point; for an API anyone else can reach it means `POST /projects/{id}/scans`
  with `/etc` or `C:\\Users` inventories it.
* There was no rate limit at all, so one caller could queue unbounded filesystem walks, LLM
  invocations, or outbound network probes.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings


def _client(tmp_path: Path, **overrides: object) -> TestClient:
    settings = Settings(
        db_url=f"sqlite:///{(tmp_path / 'hardening.db').as_posix()}",
        create_schema_on_startup=True,
        **overrides,  # type: ignore[arg-type]
    )
    return TestClient(
        create_app(settings), headers={"Authorization": f"Bearer {settings.api_token}"}
    )


def _project(client: TestClient) -> str:
    return client.post("/api/v1/projects", json={"name": "hardening"}).json()["id"]


# ── Scan-target confinement ─────────────────────────────────────────────────────────────────────


def test_scan_target_outside_the_configured_roots_is_refused(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    (allowed / "src").mkdir(parents=True)
    (allowed / "src" / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    forbidden = tmp_path / "forbidden"
    forbidden.mkdir()
    (forbidden / "secret.py").write_text("KEY = 'nope'\n")

    with _client(tmp_path, scan_roots=str(allowed)) as client:
        project_id = _project(client)

        # Inside the allowlist: accepted.
        ok = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(allowed / "src")], "run_risk": False},
        )
        assert ok.status_code == 202, ok.text

        # Outside it: refused with 403, and the refusal must not name the configured roots — a
        # refusal that echoes them doubles as a directory-disclosure oracle.
        refused = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(forbidden)], "run_risk": False},
        )
        assert refused.status_code == 403, refused.text
        assert str(allowed) not in refused.text


def test_multiple_scan_roots_are_all_honoured(tmp_path: Path) -> None:
    first = tmp_path / "repo-a"
    second = tmp_path / "repo-b"
    for d in (first, second):
        d.mkdir()
        (d / "m.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")
    outside = tmp_path / "repo-c"
    outside.mkdir()
    (outside / "m.py").write_text("x = 1\n")

    roots = os.pathsep.join([str(first), str(second)])
    with _client(tmp_path, scan_roots=roots) as client:
        project_id = _project(client)
        for allowed in (first, second):
            resp = client.post(
                f"/api/v1/projects/{project_id}/scans",
                json={"targets": [str(allowed)], "run_risk": False},
            )
            assert resp.status_code == 202, f"{allowed} should be permitted: {resp.text}"
        blocked = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(outside)], "run_risk": False},
        )
        assert blocked.status_code == 403


def test_traversal_out_of_a_configured_root_is_refused(tmp_path: Path) -> None:
    """`allowed/../forbidden` must not slip past — the check resolves before comparing."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    forbidden = tmp_path / "forbidden"
    forbidden.mkdir()
    (forbidden / "m.py").write_text("x = 1\n")

    with _client(tmp_path, scan_roots=str(allowed)) as client:
        project_id = _project(client)
        sneaky = str(allowed / ".." / "forbidden")
        resp = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [sneaky], "run_risk": False},
        )
        assert resp.status_code == 403, resp.text


def test_no_confinement_when_scan_roots_is_unset(tmp_path: Path) -> None:
    """The desktop default must stay unconfined — scanning any local path is the point there."""
    anywhere = tmp_path / "anywhere"
    anywhere.mkdir()
    (anywhere / "m.py").write_text("import hashlib\nhashlib.md5(b'x')\n")

    with _client(tmp_path) as client:  # scan_roots defaults to ""
        project_id = _project(client)
        resp = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(anywhere)], "run_risk": False},
        )
        assert resp.status_code == 202, resp.text


# ── Rate limiting ───────────────────────────────────────────────────────────────────────────────


def test_mutating_requests_are_rate_limited(tmp_path: Path) -> None:
    with _client(tmp_path, rate_limit_per_minute=3) as client:
        codes = [
            client.post("/api/v1/projects", json={"name": f"p{i}"}).status_code for i in range(6)
        ]
        assert 429 in codes, f"expected a 429 within 6 writes at a limit of 3: {codes}"
        # The limit is a threshold, not a coincidence: the first three must have gone through.
        assert codes[:3] == [201, 201, 201], codes

        limited = client.post("/api/v1/projects", json={"name": "over"})
        assert limited.status_code == 429
        assert "Retry-After" in limited.headers
        assert int(limited.headers["Retry-After"]) >= 1


def test_reads_are_never_rate_limited(tmp_path: Path) -> None:
    """The dashboard polls `GET /scans` while a scan runs; throttling that would break the app."""
    with _client(tmp_path, rate_limit_per_minute=2) as client:
        codes = {client.get("/api/v1/scans").status_code for _ in range(25)}
        assert codes == {200}, codes


def test_rate_limit_can_be_disabled(tmp_path: Path) -> None:
    """0 disables it — right for the desktop app, whose only client is the operator's own window."""
    with _client(tmp_path, rate_limit_per_minute=0) as client:
        codes = [
            client.post("/api/v1/projects", json={"name": f"q{i}"}).status_code for i in range(12)
        ]
        assert 429 not in codes, codes
