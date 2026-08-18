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
    (dist / "index.html").write_text("<html><head></head><body>QUBIT SPA</body></html>")
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
        assert "QUBIT SPA" in response.text


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
        assert "QUBIT SPA" in response.text


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


# --- the runtime API base ------------------------------------------------------------------------


def test_served_shell_carries_a_runtime_api_base(served: tuple[TestClient, Path]) -> None:
    """The page the API serves must tell the front-end where the API is.

    Otherwise the base is fixed at BUILD time and hardcodes a port. `qubit-desktop.bat` passes
    `VITE_API_BASE=/api/v1`, but only when it actually has to build, so a `dist/` produced by any
    other command keeps its compiled-in `http://127.0.0.1:8787` — and 8787 is not always bindable:
    Windows reserves port blocks for Hyper-V/WSL, and on the development machine
    `netsh int ipv4 show excludedportrange protocol=tcp` listed 8695-8794, so uvicorn failed with
    WinError 10013 and the launcher had to move to another port. A build-time base then points at
    nothing. The injected value is relative, which makes it port-agnostic.
    """
    client, _ = served
    body = client.get("/").text
    assert 'window.__QUBIT_API_BASE__="/api/v1"' in body
    # Injected inside <head>, ahead of the bundle, so the client reads it during module init.
    assert body.index("__QUBIT_API_BASE__") < body.index("QUBIT SPA")


def test_runtime_api_base_is_injected_on_client_side_routes_too(
    served: tuple[TestClient, Path],
) -> None:
    """A deep link is the same shell and needs the same base — a refresh on /inventory must work."""
    client, _ = served
    assert 'window.__QUBIT_API_BASE__="/api/v1"' in client.get("/inventory").text


def test_static_assets_are_not_rewritten(served: tuple[TestClient, Path]) -> None:
    """Only the HTML shell is touched; the JS bundle must be served byte-for-byte.

    Worth pinning because injecting into anything other than the shell would corrupt the bundle,
    and a corrupted bundle fails at parse time with a message that points nowhere near this code.
    """
    client, _ = served
    assert client.get("/assets/app-abc123.js").text == "console.log('bundle')"
    assert client.get("/favicon.ico").text == "icon-bytes"
