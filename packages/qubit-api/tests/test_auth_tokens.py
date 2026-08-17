"""DB-backed API token auth + scopes (doc 05 §6.6).

Covers: the dev-token bootstrap fallback (empty table), minting real tokens, ro vs rw scope
enforcement by HTTP method, revocation, and that the dev token stops working once a token exists.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings
from qubit_core.db import Base as CoreBase
from qubit_core.db import create_token, get_engine, session_factory


def _settings(tmp_path: Path) -> Settings:
    db_path = tmp_path / "qubit-auth.db"
    return Settings(
        db_url=f"sqlite:///{db_path.as_posix()}",
        create_schema_on_startup=True,
    )


def _mint(settings: Settings, name: str, scope: str) -> str:
    """Mint a token directly in the DB and return its raw value."""
    engine = get_engine(settings.db_url)
    CoreBase.metadata.create_all(engine)
    with session_factory(engine)() as session:
        return create_token(session, name, scopes=scope).raw


def test_bootstrap_dev_token_when_table_empty(tmp_path: Path) -> None:
    """With no DB tokens, the dev token authenticates as rw (backward-compatible)."""
    settings = _settings(tmp_path)
    client = TestClient(
        create_app(settings), headers={"Authorization": f"Bearer {settings.api_token}"}
    )
    r = client.get("/api/v1/auth/whoami")
    assert r.status_code == 200
    assert r.json() == {"name": "bootstrap-dev-token", "scopes": "rw"}


def test_bootstrap_disabled_once_real_token_exists(tmp_path: Path) -> None:
    """After a real token is minted, the dev token no longer works (401)."""
    settings = _settings(tmp_path)
    _mint(settings, "ci", "rw")
    app = create_app(settings)
    dev = TestClient(app, headers={"Authorization": f"Bearer {settings.api_token}"})
    assert dev.get("/api/v1/projects").status_code == 401


def test_configuring_a_token_disables_the_published_dev_defaults(tmp_path: Path) -> None:
    """Setting QUBIT_API_TOKEN must make it the ONLY bootstrap credential.

    This is the production configuration the README and docker-compose document: a real token in the
    environment, no DB token minted yet. The bootstrap block used to accept `settings.api_token`
    *and* both hardcoded defaults unconditionally, so `dev_token` — a value published in this repo —
    still authenticated as `rw` against a deployment with a strong secret configured. Probing a live
    app confirmed it returned 200. Anyone who had read the repo held a write-scope credential.
    """
    db_path = tmp_path / "configured.db"
    strong = "a-very-strong-random-production-token"  # a test fixture, not a real credential
    settings = Settings(
        db_url=f"sqlite:///{db_path.as_posix()}",
        api_token=strong,
        create_schema_on_startup=True,
    )
    app = create_app(settings)

    # The configured token works...
    ok = TestClient(app, headers={"Authorization": f"Bearer {strong}"})
    assert ok.get("/api/v1/projects").status_code == 200

    # ...and every published default is rejected, including the one this repo's own settings.py and
    # docker-compose.yml use as their default.
    for leaked in ("dev_token", "qubit-dev-token-do-not-use-in-prod"):
        client = TestClient(app, headers={"Authorization": f"Bearer {leaked}"})
        assert client.get("/api/v1/projects").status_code == 401, (
            f"published default {leaked!r} still authenticates against a configured deployment"
        )


def test_unconfigured_install_still_accepts_the_bundled_defaults(tmp_path: Path) -> None:
    """The desktop-resilience behavior is preserved where it was actually needed.

    A fresh install that has configured nothing keeps accepting either bundled default, so a
    dashboard bundle built with the other one does not present as "Failed to fetch" (a 401 that
    looks like a dead API). This is the half of the old behavior worth keeping — it only applies
    while the deployment carries a default token anyway, so it leaks no secret that wasn't public.
    """
    settings = _settings(tmp_path)  # api_token is the settings.py default => unconfigured
    app = create_app(settings)
    for bundled in ("dev_token", "qubit-dev-token-do-not-use-in-prod"):
        client = TestClient(app, headers={"Authorization": f"Bearer {bundled}"})
        assert client.get("/api/v1/projects").status_code == 200
    # A value that is neither the configured token nor a bundled default is still rejected.
    bad = TestClient(app, headers={"Authorization": "Bearer not-a-real-token"})
    assert bad.get("/api/v1/projects").status_code == 401


def test_rw_token_can_read_and_write(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    raw = _mint(settings, "writer", "rw")
    client = TestClient(create_app(settings), headers={"Authorization": f"Bearer {raw}"})

    assert client.get("/api/v1/auth/whoami").json() == {"name": "writer", "scopes": "rw"}
    assert client.get("/api/v1/projects").status_code == 200
    created = client.post("/api/v1/projects", json={"name": "p1"})
    assert created.status_code == 201, created.text


def test_ro_token_can_read_but_not_write(tmp_path: Path) -> None:
    """A read-only token reads fine but any mutating verb returns 403."""
    settings = _settings(tmp_path)
    ro = _mint(settings, "reader", "ro")
    client = TestClient(create_app(settings), headers={"Authorization": f"Bearer {ro}"})

    assert client.get("/api/v1/auth/whoami").json()["scopes"] == "ro"
    assert client.get("/api/v1/projects").status_code == 200  # read OK

    forbidden = client.post("/api/v1/projects", json={"name": "nope"})
    assert forbidden.status_code == 403, forbidden.text
    assert "read-write" in forbidden.json()["detail"]


def test_revoked_token_is_rejected(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    raw = _mint(settings, "temp", "rw")
    client = TestClient(create_app(settings), headers={"Authorization": f"Bearer {raw}"})
    assert client.get("/api/v1/projects").status_code == 200

    # Revoke it, then a fresh client with the same token must be rejected.
    from qubit_core.db import revoke_token

    engine = get_engine(settings.db_url)
    with session_factory(engine)() as session:
        assert revoke_token(session, "temp") is True

    assert client.get("/api/v1/projects").status_code == 401


def test_unknown_token_rejected_when_tokens_exist(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _mint(settings, "real", "rw")
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer totally-made-up"})
    assert client.get("/api/v1/projects").status_code == 401
