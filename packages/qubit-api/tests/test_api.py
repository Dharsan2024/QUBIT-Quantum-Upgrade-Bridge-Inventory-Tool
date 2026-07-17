from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings


def _make_client(tmp_path: Path) -> TestClient:
    db_path = tmp_path / "qubit-api.db"
    settings = Settings(
        db_url=f"sqlite:///{db_path.as_posix()}",
        create_schema_on_startup=True,
    )
    return TestClient(
        create_app(settings),
        headers={"Authorization": f"Bearer {settings.api_token}"},
    )


def _write_repo(repo: Path, *, include_md5: bool = True, include_rsa: bool = True) -> None:
    parts = ["import hashlib", "from cryptography.hazmat.primitives.asymmetric import rsa"]
    if include_md5:
        parts.append("digest = hashlib.md5(data)")
    if include_rsa:
        parts.append("key = rsa.generate_private_key(public_exponent=65537, key_size=2048)")
    (repo / "app.py").write_text("\n".join(parts) + "\n", encoding="utf-8")


def test_project_crud_and_scan_asset_flow(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)
    with _make_client(tmp_path) as client:
        create_resp = client.post(
            "/api/v1/projects",
            json={"name": "Demo", "root_path": str(repo)},
        )
        assert create_resp.status_code == 201
        project_id = create_resp.json()["id"]

        scan_resp = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(repo)]},
        )
        assert scan_resp.status_code == 202
        scan_payload = scan_resp.json()
        assert scan_payload["scan"]["status"] == "succeeded"
        scan_id = scan_payload["scan"]["id"]

        assets_resp = client.get(f"/api/v1/scans/{scan_id}/assets")
        assert assets_resp.status_code == 200
        body = assets_resp.json()
        assert body["total"] == 2
        assert {item["algorithm"] for item in body["items"]} == {"MD5", "RSA-2048"}

        summary_resp = client.get(f"/api/v1/scans/{scan_id}/summary")
        assert summary_resp.status_code == 200
        assert summary_resp.json()["total_assets"] == 2

        cbom_resp = client.get(f"/api/v1/scans/{scan_id}/cbom")
        assert cbom_resp.status_code == 200
        assert cbom_resp.json()["specVersion"] == "1.7"


def test_trends_and_scan_diff(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    with _make_client(tmp_path) as client:
        project = client.post(
            "/api/v1/projects",
            json={"name": "Trend Project", "root_path": str(repo)},
        ).json()
        project_id = project["id"]

        _write_repo(repo, include_md5=True, include_rsa=False)
        scan_1 = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(repo)]},
        ).json()["scan"]["id"]

        _write_repo(repo, include_md5=True, include_rsa=True)
        scan_2 = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(repo)]},
        ).json()["scan"]["id"]

        trends = client.get(f"/api/v1/projects/{project_id}/trends")
        assert trends.status_code == 200
        trend_items = trends.json()
        assert len(trend_items) == 2
        assert trend_items[0]["total"] == 1
        assert trend_items[1]["total"] == 2

        diff_resp = client.get(f"/api/v1/scans/{scan_2}/diff", params={"against": scan_1})
        assert diff_resp.status_code == 200
        diff = diff_resp.json()
        assert len(diff["added"]) == 1
        assert len(diff["removed"]) == 0
        assert len(diff["persisting"]) == 1


def test_scan_rejects_target_outside_project_root(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    _write_repo(outside)
    with _make_client(tmp_path) as client:
        project_id = client.post(
            "/api/v1/projects",
            json={"name": "Demo", "root_path": str(repo)},
        ).json()["id"]
        response = client.post(
            f"/api/v1/projects/{project_id}/scans",
            json={"targets": [str(outside)]},
        )
        assert response.status_code == 202
        payload = response.json()
        assert payload["scan"]["status"] == "failed"
        assert "outside project root" in payload["scan"]["error"]


def test_auth_missing_token(tmp_path: Path) -> None:
    db_path = tmp_path / "qubit-api.db"
    settings = Settings(db_url=f"sqlite:///{db_path.as_posix()}", create_schema_on_startup=True)
    # No headers injected
    client = TestClient(create_app(settings))
    response = client.get("/api/v1/projects")
    assert response.status_code == 401


def test_auth_invalid_token(tmp_path: Path) -> None:
    db_path = tmp_path / "qubit-api.db"
    settings = Settings(db_url=f"sqlite:///{db_path.as_posix()}", create_schema_on_startup=True)
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer bad-token"})
    response = client.get("/api/v1/projects")
    assert response.status_code == 401


def test_auth_whoami(tmp_path: Path) -> None:
    with _make_client(tmp_path) as client:
        response = client.get("/api/v1/auth/whoami")
        assert response.status_code == 200
        assert response.json()["scopes"] == "rw"


def test_custom_api_token_is_honored(tmp_path: Path) -> None:
    # regression: create_app(settings) must thread the token into auth (not a fresh Settings()).
    settings = Settings(
        db_url=f"sqlite:///{(tmp_path / 'q.db').as_posix()}",
        api_token="a-custom-token",
        create_schema_on_startup=True,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        assert client.get("/api/v1/projects").status_code == 401  # no token
        ok = client.get("/api/v1/projects", headers={"Authorization": "Bearer a-custom-token"})
        assert ok.status_code == 200
        wrong = client.get("/api/v1/projects", headers={"Authorization": "Bearer default-token"})
        assert wrong.status_code == 401
