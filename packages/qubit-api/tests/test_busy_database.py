"""A busy SQLite write lock must answer 503, never a bare 500.

SQLite allows exactly one writer. A migration generating in the background holds the write lock in
bursts, so ANY concurrent write can lose the race and exhaust `PRAGMA busy_timeout` (20s). Measured
live: a queue of overlapping generations produced `500 Internal Server Error` rows across the
Migration Hub, which read as the model failing when the database was simply busy.

The hot paths retry, but a retry budget can be spent. This pins the app-wide backstop -- and
equally that a NON-lock `OperationalError` is still a real error, because dressing a schema fault
up as transient would send someone retrying a request that can never succeed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings
from sqlalchemy.exc import OperationalError


def _make_client(tmp_path: Path) -> TestClient:
    db_path = tmp_path / "qubit-api.db"
    settings = Settings(db_url=f"sqlite:///{db_path.as_posix()}", create_schema_on_startup=True)
    return TestClient(
        create_app(settings),
        headers={"Authorization": f"Bearer {settings.api_token}"},
        raise_server_exceptions=False,
    )


def test_a_locked_database_answers_503_with_retry_after(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def locked(*_a: object, **_k: object) -> None:
        raise OperationalError("SELECT 1", {}, Exception("database is locked"))

    with _make_client(tmp_path) as client:
        monkeypatch.setattr("qubit_api.routers.projects.list_projects", locked, raising=False)
        # Any endpoint will do; the handler is registered app-wide, not per-router.
        monkeypatch.setattr(
            "qubit_api.routers.llm_provider._get_or_create_config", locked, raising=False
        )
        resp = client.get("/api/v1/llm-provider/config")

    assert resp.status_code == 503, f"expected 503, got {resp.status_code}: {resp.text[:200]}"
    assert resp.headers.get("Retry-After") == "5"
    detail = resp.json()["detail"].lower()
    assert "busy" in detail
    assert "nothing was changed" in detail


def test_a_real_operational_error_is_not_disguised_as_transient(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A schema fault is a bug, not a busy database. Answering 503 would tell the user to retry
    something that can never succeed.
    """

    def broken(*_a: object, **_k: object) -> None:
        raise OperationalError("SELECT nope", {}, Exception("no such column: nope"))

    with _make_client(tmp_path) as client:
        monkeypatch.setattr(
            "qubit_api.routers.llm_provider._get_or_create_config", broken, raising=False
        )
        resp = client.get("/api/v1/llm-provider/config")

    assert resp.status_code != 503, "a non-lock error must not be reported as transient"
