"""Serving the dashboard SPA from the API process (`qubit serve` / desktop mode).

When `QUBIT_DASHBOARD_DIST` points at a built dashboard, the API mounts `/assets` and a catch-all
route so client-side routes survive a refresh. That catch-all is deliberately UNAUTHENTICATED — it
has to serve the login shell to a caller who has no token yet — which makes it the one route where a
path-handling mistake is directly exploitable. It had no tests before this file.

The traversal case below is a real fix, not a hypothetical: `full_path` arrives URL-DECODED, and
while the HTTP layer normalizes a literal `/../`, it does not normalize a percent-encoded one. A
probe against a live app confirmed `GET /%2e%2e%2fSECRET.txt` returned 200 with the file's contents,
so the shipping desktop configuration would read out any file the process could reach.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings

SECRET = "TOP-SECRET-MUST-NOT-BE-SERVED"


@pytest.fixture
def served(tmp_path: Path) -> tuple[TestClient, Path]:
    """A built-dashboard layout with a sensitive file sitting OUTSIDE the dist directory.

    `tmp_path` stands in for a real machine: `dist/` is the public bundle, and the secret is a
    sibling — the same relationship `dashboard/dist` has with the rest of a user's filesystem.
    """
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>QUBIT SPA</html>")
    (dist / "favicon.ico").write_text("icon-bytes")
    (dist / "assets" / "app-abc123.js").write_text("console.log('bundle')")
    (tmp_path / "SECRET.txt").write_text(SECRET)

    settings = Settings(
        db_url=f"sqlite:///{(tmp_path / 'spa.db').as_posix()}",
        dashboard_dist=str(dist),
        create_schema_on_startup=True,
    )
    return TestClient(create_app(settings)), tmp_path


# --- the security property ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/../SECRET.txt",  # literal — normalized by the HTTP layer, was already safe
        "/%2e%2e%2fSECRET.txt",  # fully percent-encoded `../` — this one leaked
        "/%2e%2e/SECRET.txt",  # encoded dots, literal slash — leaked
        "/..%2fSECRET.txt",  # literal dots, encoded slash — leaked
        "/%2e%2e%2f%2e%2e%2fSECRET.txt",  # two levels up
        "/assets/%2e%2e%2f%2e%2e%2fSECRET.txt",  # escaping from a legitimate prefix
    ],
)
def test_traversal_never_serves_a_file_outside_dist(
    served: tuple[TestClient, Path], path: str
) -> None:
    client, _ = served
    response = client.get(path)
    # The one property that matters: the file's contents never come back.
    assert SECRET not in response.text, f"{path} leaked a file from outside dist"
    # Two safe shapes, depending on which route claimed the URL. Anything under `/assets` belongs
    # to the StaticFiles mount, which rejects an escaping path itself (404); everything else
    # reaches the catch-all and falls through to the SPA shell — indistinguishable from a real
    # client-side route, which is what a refresh on /inventory needs.
    if path.startswith("/assets/"):
        assert response.status_code == 404
    else:
        assert response.status_code == 200
        assert response.text == "<html>QUBIT SPA</html>"


def test_absolute_path_is_not_served(served: tuple[TestClient, Path]) -> None:
    """A path param that looks absolute must not escape either.

    Worth its own case because `Path("/etc/passwd").is_absolute()` is False on Windows, so an
    implementation that tried to reject absolute paths instead of confining resolved ones would pass
    on CI's Linux runner and fail on the platform QUBIT actually ships as a desktop app.
    """
    client, tmp_path = served
    for path in (f"/{(tmp_path / 'SECRET.txt').as_posix()}", "//SECRET.txt"):
        assert SECRET not in client.get(path).text


# --- the behavior the route exists for ---------------------------------------------------------


def test_real_files_inside_dist_are_still_served(served: tuple[TestClient, Path]) -> None:
    """The hardening must not break the hosting it protects."""
    client, _ = served
    assert client.get("/favicon.ico").text == "icon-bytes"
    assert client.get("/assets/app-abc123.js").text == "console.log('bundle')"


def test_client_side_routes_fall_back_to_the_shell(served: tuple[TestClient, Path]) -> None:
    """A refresh on /inventory must return the SPA, not a 404."""
    client, _ = served
    for route in ("/", "/inventory", "/migration/queue"):
        response = client.get(route)
        assert response.status_code == 200
        assert response.text == "<html>QUBIT SPA</html>"


def test_the_api_is_not_shadowed_by_the_catch_all(served: tuple[TestClient, Path]) -> None:
    """`/api/*` must still reach the routers — the catch-all is mounted last for this reason."""
    client, _ = served
    unauthenticated = client.get("/api/v1/projects")
    # 401/403 proves the guarded router handled it; a 200 SPA shell would mean the catch-all won.
    assert unauthenticated.status_code in (401, 403)
    assert "QUBIT SPA" not in unauthenticated.text


def test_no_spa_mount_when_dist_is_absent(tmp_path: Path) -> None:
    """A configured-but-missing dist must not register the catch-all at all."""
    settings = Settings(
        db_url=f"sqlite:///{(tmp_path / 'none.db').as_posix()}",
        dashboard_dist=str(tmp_path / "does-not-exist"),
        create_schema_on_startup=True,
    )
    assert TestClient(create_app(settings)).get("/inventory").status_code == 404
