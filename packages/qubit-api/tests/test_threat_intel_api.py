"""The threat-intel API surface: config get/patch, manual check-now, snapshot history + review.

`check_now` genuinely reaches the network (see qubit_risk.threat_intel), so every test here
monkeypatches `qubit_risk.threat_intel.fetch_source` rather than depending on NIST being up -
that live path is exercised separately, by hand, not in the suite that runs on every commit.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings
from qubit_risk.threat_intel import SOURCES, FetchResult


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


def _stub_fetch(monkeypatch: pytest.MonkeyPatch, hashes: dict[str, str | None]) -> None:
    """Replaces the real network call with one canned hash per source id, keyed by SOURCES[i].id."""

    def _fake(source, *, timeout: float = 15) -> FetchResult:
        h = hashes.get(source.id)
        return FetchResult(
            source=source,
            fetched_at=datetime.now(UTC),
            content_hash=h,
            excerpt="stub excerpt" if h else "",
            error=None if h else "stub failure",
        )

    monkeypatch.setattr("qubit_risk.threat_intel.fetch_source", _fake)


def test_config_defaults_to_disabled_and_lists_the_fixed_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _make_client(tmp_path) as client:
        resp = client.get("/api/v1/threat-intel/config")
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is False
        assert body["check_interval_hours"] == 24
        assert body["last_checked_at"] is None
        assert {s["id"] for s in body["sources"]} == {s.id for s in SOURCES}


def test_patch_config_flips_the_toggle_and_interval(tmp_path: Path) -> None:
    with _make_client(tmp_path) as client:
        resp = client.patch(
            "/api/v1/threat-intel/config",
            json={"enabled": True, "check_interval_hours": 6},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["enabled"] is True
        assert body["check_interval_hours"] == 6

        # Persisted, not just echoed back.
        again = client.get("/api/v1/threat-intel/config").json()
        assert again["enabled"] is True
        assert again["check_interval_hours"] == 6


def test_patch_config_rejects_an_absurd_interval(tmp_path: Path) -> None:
    with _make_client(tmp_path) as client:
        resp = client.patch("/api/v1/threat-intel/config", json={"check_interval_hours": 0})
        assert resp.status_code == 422


def test_check_now_records_one_snapshot_per_source_and_updates_last_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_fetch(monkeypatch, {s.id: "hash-1" for s in SOURCES})
    with _make_client(tmp_path) as client:
        resp = client.post("/api/v1/threat-intel/check-now")
        assert resp.status_code == 200
        rows = resp.json()
        assert len(rows) == len(SOURCES)
        assert all(r["content_hash"] == "hash-1" for r in rows)
        # A first-ever fetch has no baseline - never reported as a change.
        assert all(r["changed_from_previous"] is False for r in rows)

        config = client.get("/api/v1/threat-intel/config").json()
        assert config["last_checked_at"] is not None


def test_check_now_works_even_when_the_toggle_is_disabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Manual "check now" is an explicit user action, independent of the background-poll toggle.
    _stub_fetch(monkeypatch, {s.id: "hash-1" for s in SOURCES})
    with _make_client(tmp_path) as client:
        assert client.get("/api/v1/threat-intel/config").json()["enabled"] is False
        resp = client.post("/api/v1/threat-intel/check-now")
        assert resp.status_code == 200
        assert len(resp.json()) == len(SOURCES)


def test_a_second_check_with_a_different_hash_is_flagged_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _make_client(tmp_path) as client:
        _stub_fetch(monkeypatch, {s.id: "hash-1" for s in SOURCES})
        client.post("/api/v1/threat-intel/check-now")

        _stub_fetch(monkeypatch, {s.id: "hash-2" for s in SOURCES})
        resp = client.post("/api/v1/threat-intel/check-now")
        assert all(r["changed_from_previous"] is True for r in resp.json())


def test_snapshots_endpoint_lists_newest_first_and_filters_by_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _make_client(tmp_path) as client:
        _stub_fetch(monkeypatch, {s.id: "hash-1" for s in SOURCES})
        client.post("/api/v1/threat-intel/check-now")
        _stub_fetch(monkeypatch, {s.id: "hash-2" for s in SOURCES})
        client.post("/api/v1/threat-intel/check-now")

        all_rows = client.get("/api/v1/threat-intel/snapshots").json()
        assert len(all_rows) == 2 * len(SOURCES)

        one_source = SOURCES[0].id
        filtered = client.get(f"/api/v1/threat-intel/snapshots?source_id={one_source}").json()
        assert len(filtered) == 2
        assert all(r["source_id"] == one_source for r in filtered)
        # Newest first.
        assert filtered[0]["content_hash"] == "hash-2"


def test_reviewing_a_snapshot_records_who_and_a_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_fetch(monkeypatch, {s.id: "hash-1" for s in SOURCES})
    with _make_client(tmp_path) as client:
        client.post("/api/v1/threat-intel/check-now")
        snapshot_id = client.get("/api/v1/threat-intel/snapshots").json()[0]["id"]

        resp = client.post(
            f"/api/v1/threat-intel/snapshots/{snapshot_id}/review",
            json={"note": "matches what we already cite"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["reviewed"] is True
        assert body["reviewed_at"] is not None
        assert body["reviewer_note"] == "matches what we already cite"


def test_reviewing_an_unknown_snapshot_is_a_404(tmp_path: Path) -> None:
    with _make_client(tmp_path) as client:
        resp = client.post(
            "/api/v1/threat-intel/snapshots/00000000-0000-0000-0000-000000000000/review",
            json={},
        )
        assert resp.status_code == 404


def test_a_fetch_failure_is_recorded_with_no_hash_and_never_flagged_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub_fetch(monkeypatch, {s.id: None for s in SOURCES})
    with _make_client(tmp_path) as client:
        rows = client.post("/api/v1/threat-intel/check-now").json()
        assert all(r["content_hash"] is None for r in rows)
        assert all(r["fetch_error"] == "stub failure" for r in rows)
        assert all(r["changed_from_previous"] is False for r in rows)
