"""Project scoping: the overview rollup, and migration plans belonging to a project.

These pin the behaviour behind a specific reported failure: *after a scan, the migration for the
project isn't showing up*. Three separate causes sat behind it, and each gets a test here.

1. ``MigrationOrchestrator.build_plan`` had no scope at all — it selected every vulnerable,
   risk-scored asset in the database, across every project and every historical scan. On the
   development machine that meant one 18-task plan assembled from eight unrelated projects.
2. ``MigrationPlan`` had nowhere to record what it was built from (``scope_json`` was ``{}`` on all
   24 plans in the real database), so ``GET /migrate/plans`` could not be filtered and the app took
   whichever plan was newest — belonging to whatever had been scanned last.
3. Nothing built a plan when a scan finished, so a freshly scanned project had none of its own even
   once scoping worked.

The fourth piece is ``GET /projects/overview``: the app needs per-project counts to draw a
project-wise landing on every tab, and computing them by fetching every asset into the browser is
what the merged view was doing instead.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings

# Two small source trees with genuinely different cryptography, so a plan built for one can be shown
# not to contain the other's assets.
PROJECT_A_SOURCE = """
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa


def fingerprint(payload: bytes) -> str:
    return hashlib.md5(payload).hexdigest()


def issue_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
"""

PROJECT_B_SOURCE = """
import hashlib


def marker(payload: bytes) -> str:
    return hashlib.sha1(payload).hexdigest()
"""


@pytest.fixture
def client(tmp_path: Path) -> Any:
    settings = Settings(
        db_url=f"sqlite:///{(tmp_path / 'scoping.db').as_posix()}",
        create_schema_on_startup=True,
    )
    with TestClient(
        create_app(settings), headers={"Authorization": f"Bearer {settings.api_token}"}
    ) as c:
        yield c


def _await_scan(client: TestClient, scan_id: str) -> None:
    """Wait for a scan to leave queued/running.

    The app under test has a job runner, so a scan is dispatched off the request path and the POST
    response reports "running" with no assets yet. The plan is built at the *end* of that job, so a
    test that asserted on plans immediately after the POST would be racing the thing it is testing.
    """
    for _ in range(300):
        status = client.get(f"/api/v1/scans/{scan_id}").json()["status"]
        if status not in ("queued", "running"):
            assert status == "succeeded", f"seed scan failed: {status}"
            return
        time.sleep(0.1)
    raise TimeoutError(f"scan {scan_id} did not finish")


def _scan(client: TestClient, name: str, target: Path) -> tuple[str, str]:
    """Create a project, scan `target` into it, and return (project_id, scan_id)."""
    project_id = client.post("/api/v1/projects", json={"name": name}).json()["id"]
    response = client.post(
        f"/api/v1/projects/{project_id}/scans",
        json={"targets": [str(target)], "run_risk": True},
    )
    assert response.status_code in (200, 202), response.text
    scan_id = response.json()["scan"]["id"]
    _await_scan(client, scan_id)
    return project_id, scan_id


@pytest.fixture
def two_projects(client: TestClient, tmp_path: Path) -> dict[str, Any]:
    a_dir = tmp_path / "alpha"
    a_dir.mkdir()
    (a_dir / "billing.py").write_text(PROJECT_A_SOURCE, encoding="utf-8")
    b_dir = tmp_path / "beta"
    b_dir.mkdir()
    (b_dir / "marker.py").write_text(PROJECT_B_SOURCE, encoding="utf-8")

    a_project, a_scan = _scan(client, "alpha", a_dir)
    b_project, b_scan = _scan(client, "beta", b_dir)
    return {
        "a_project": a_project,
        "a_scan": a_scan,
        "b_project": b_project,
        "b_scan": b_scan,
    }


# ── GET /projects/overview ───────────────────────────────────────────────────


def test_overview_reports_each_project_separately(
    client: TestClient, two_projects: dict[str, Any]
) -> None:
    rows = client.get("/api/v1/projects/overview").json()
    by_name = {row["name"]: row for row in rows}
    assert set(by_name) == {"alpha", "beta"}

    alpha, beta = by_name["alpha"], by_name["beta"]
    # The whole point: neither project's counts include the other's assets.
    assert alpha["assets"] > 0 and beta["assets"] > 0
    assert alpha["scans"] == 1 and beta["scans"] == 1
    assert alpha["vulnerable"] > 0
    # alpha has RSA (Shor) and MD5 (Grover); beta has only SHA-1 (Grover).
    assert alpha["shor"] >= 1, alpha
    assert beta["shor"] == 0, beta
    assert "SHA-1" in beta["top_algorithms"], beta["top_algorithms"]
    assert "SHA-1" not in alpha["top_algorithms"], alpha["top_algorithms"]

    for row in (alpha, beta):
        assert row["latest_scan"] is not None
        assert row["latest_scan"]["status"] == "succeeded"
        # Risk ran inline, so a mean exists. `None` here would mean the tab shows "—" for a
        # project that really was scored.
        assert row["mean_risk"] is not None
        assert 0.0 <= row["mean_risk"] <= 1.0


def test_overview_is_empty_before_anything_is_scanned(client: TestClient) -> None:
    assert client.get("/api/v1/projects/overview").json() == []


def test_overview_route_is_not_shadowed_by_the_project_id_route(client: TestClient) -> None:
    """`/projects/{project_id}` types its parameter as a UUID, so declaration order decides
    whether `/projects/overview` resolves or 422s on 'overview' not being a UUID."""
    assert client.get("/api/v1/projects/overview").status_code == 200


def test_overview_counts_a_project_with_no_assets_as_zero_not_missing(
    client: TestClient, tmp_path: Path
) -> None:
    """An empty project must still appear. Dropping it would hide a scan that found nothing —
    which is exactly the case worth seeing, because it may mean the scan was misconfigured."""
    empty = tmp_path / "nothing"
    empty.mkdir()
    (empty / "notes.txt").write_text("no cryptography here", encoding="utf-8")
    _scan(client, "empty-project", empty)

    row = next(
        r for r in client.get("/api/v1/projects/overview").json() if r["name"] == "empty-project"
    )
    assert row["assets"] == 0
    assert row["vulnerable"] == 0
    assert row["mean_risk"] is None  # not 0.0 — "unscored" and "scored zero" are different
    assert row["top_algorithms"] == []
    assert row["plan"] is None


# ── Plans belong to a project ────────────────────────────────────────────────


def test_a_scan_builds_a_plan_for_its_own_project(
    client: TestClient, two_projects: dict[str, Any]
) -> None:
    """The reported bug, directly: after a scan, that project has a migration plan."""
    rows = client.get("/api/v1/projects/overview").json()
    alpha = next(r for r in rows if r["name"] == "alpha")

    assert alpha["plan"] is not None, "scanning a project with vulnerable assets built no plan"
    assert alpha["plan"]["tasks"] > 0
    assert alpha["plan"]["scan_id"] == two_projects["a_scan"], (
        "the plan should be scoped to the scan that produced it, not to the whole project"
    )
    assert alpha["plan"]["stale"] is False


def test_plan_contains_only_its_own_project_assets(
    client: TestClient, two_projects: dict[str, Any]
) -> None:
    a_plans = client.get(
        "/api/v1/migrate/plans", params={"project_id": two_projects["a_project"]}
    ).json()
    b_plans = client.get(
        "/api/v1/migrate/plans", params={"project_id": two_projects["b_project"]}
    ).json()
    assert len(a_plans) == 1 and len(b_plans) == 1
    assert a_plans[0]["project_id"] == two_projects["a_project"]
    assert b_plans[0]["project_id"] == two_projects["b_project"]

    a_queue = client.get(f"/api/v1/migrate/plans/{a_plans[0]['id']}/queue").json()
    b_queue = client.get(f"/api/v1/migrate/plans/{b_plans[0]['id']}/queue").json()

    a_files = {t["file_path"] for t in a_queue}
    b_files = {t["file_path"] for t in b_queue}
    assert a_files and b_files
    assert not (a_files & b_files), "a project's queue contains another project's files"
    assert all("billing.py" in f for f in a_files), a_files
    assert all("marker.py" in f for f in b_files), b_files

    # alpha's RSA-1024 must not appear anywhere in beta's queue.
    assert any(t["algorithm"] == "RSA-1024" for t in a_queue), a_queue
    assert not any(t["algorithm"] == "RSA-1024" for t in b_queue), b_queue


def test_unfiltered_plan_listing_still_returns_every_plan(
    client: TestClient, two_projects: dict[str, Any]
) -> None:
    """Without `project_id` the listing is global — the app relies on the filter, not on the
    endpoint having silently become project-only."""
    all_plans = client.get("/api/v1/migrate/plans").json()
    assert len(all_plans) >= 2
    assert {p["project_id"] for p in all_plans} >= {
        two_projects["a_project"],
        two_projects["b_project"],
    }


def test_a_plan_built_without_a_project_is_reported_as_unscoped(
    client: TestClient, two_projects: dict[str, Any]
) -> None:
    """Plans predating scoping genuinely spanned everything. `project_id: null` says so, and the
    project filter must exclude them rather than attributing them to a project they were not
    built from."""
    created = client.post("/api/v1/migrate/plans", json={"min_risk": 0}).json()
    assert created["project_id"] is None
    assert created["scan_id"] is None

    filtered = client.get(
        "/api/v1/migrate/plans", params={"project_id": two_projects["a_project"]}
    ).json()
    assert created["id"] not in {p["id"] for p in filtered}

    # A global plan spans both projects, which is what makes it useless per-project.
    queue = client.get(f"/api/v1/migrate/plans/{created['id']}/queue").json()
    files = {t["file_path"] for t in queue}
    assert any("billing.py" in f for f in files) and any("marker.py" in f for f in files), files


def test_building_a_plan_for_an_unknown_project_is_404_not_an_empty_plan(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/v1/migrate/plans",
        json={"min_risk": 0, "project_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert response.status_code == 404, response.text


def test_rescanning_marks_the_existing_plan_stale(
    client: TestClient, two_projects: dict[str, Any], tmp_path: Path
) -> None:
    """A plan describes the snapshot it was built from. Once a newer scan lands, showing its queue
    as current is a lie, so the overview flags it — and the second scan builds its own plan."""
    project_id = two_projects["a_project"]
    before = next(
        r for r in client.get("/api/v1/projects/overview").json() if r["id"] == project_id
    )
    first_plan_id = before["plan"]["id"]

    response = client.post(
        f"/api/v1/projects/{project_id}/scans",
        json={"targets": [str(tmp_path / "alpha")], "run_risk": True},
    )
    assert response.status_code in (200, 202), response.text
    _await_scan(client, response.json()["scan"]["id"])

    after = next(r for r in client.get("/api/v1/projects/overview").json() if r["id"] == project_id)
    # The new scan built its own plan, so the newest plan is a different one and is NOT stale.
    assert after["plan"]["id"] != first_plan_id
    assert after["plan"]["stale"] is False
    assert after["scans"] == 2

    plans = client.get("/api/v1/migrate/plans", params={"project_id": project_id}).json()
    assert len(plans) == 2


def test_deleting_a_project_removes_its_plans(
    client: TestClient, two_projects: dict[str, Any]
) -> None:
    """The new `project_id` column carries ON DELETE CASCADE. Without it, deleting a project would
    leave its plans behind pointing at a project that no longer exists."""
    project_id = two_projects["a_project"]
    assert client.get("/api/v1/migrate/plans", params={"project_id": project_id}).json()

    assert client.delete(f"/api/v1/projects/{project_id}").status_code == 204
    assert client.get("/api/v1/migrate/plans", params={"project_id": project_id}).json() == []
    # The other project is untouched.
    assert client.get(
        "/api/v1/migrate/plans", params={"project_id": two_projects["b_project"]}
    ).json()


def test_plan_stats_describe_the_work_not_just_its_size(
    client: TestClient, two_projects: dict[str, Any]
) -> None:
    """The hub leads with these, so they have to be real. `automatable` is the one that changes how
    the work is planned: a task with no codemod rule has to be changed by hand."""
    plans = client.get(
        "/api/v1/migrate/plans", params={"project_id": two_projects["a_project"]}
    ).json()
    stats = plans[0]["stats"]
    assert stats["tasks"] > 0
    assert stats["units"] > 0
    assert 0 <= stats["automatable"] <= stats["tasks"]
    assert stats["effort_points"] > 0
    assert 0 < stats["effort_hours_low"] <= stats["effort_hours_high"]
    assert sum(stats["by_algorithm"].values()) == stats["tasks"]

    queue = client.get(f"/api/v1/migrate/plans/{plans[0]['id']}/queue").json()
    assert sum(1 for t in queue if t["rule_id"]) == stats["automatable"]


def test_queue_carries_the_asset_context_the_ui_shows(
    client: TestClient, two_projects: dict[str, Any]
) -> None:
    """A queue row read "AES-128 · 0.412" with no way to tell a config finding from a certificate,
    or a signing key from a hash — which is most of what decides how a task is handled."""
    plans = client.get(
        "/api/v1/migrate/plans", params={"project_id": two_projects["a_project"]}
    ).json()
    queue = client.get(f"/api/v1/migrate/plans/{plans[0]['id']}/queue").json()
    assert queue

    for task in queue:
        assert task["unit_id"], "no execution unit, so the queue cannot be grouped by wave"
        assert task["source_scanner"] == "code"
        assert task["asset_type"]
        assert task["file_path"]
        assert task["effort_hours_low"] is not None
        assert task["effort_hours_high"] is not None
        assert task["effort_hours_low"] <= task["effort_hours_high"]
        assert isinstance(task["effort_drivers"], list)


def test_plan_timestamps_carry_a_timezone(client: TestClient, two_projects: dict[str, Any]) -> None:
    """A plan's ``created_at`` must be unambiguous.

    It was serialized with a bare ``.isoformat()`` on a value SQLite hands back naive, producing
    ``2026-08-20T15:51:25.853134`` — which JavaScript parses as LOCAL time. On a UTC+5:30 machine
    that made a plan built two seconds ago read as 5.5 hours older than the scan it was built from,
    so the Migration Hub displayed "this plan is outdated, rebuild it" over every current plan.
    Caught by screenshotting the shipped app, not by any assertion on the JSON.

    `schemas._ensure_utc` exists for precisely this and is already applied to scans; this pins that
    plans use it too, and that the two are therefore comparable.
    """
    from datetime import datetime

    plans = client.get(
        "/api/v1/migrate/plans", params={"project_id": two_projects["a_project"]}
    ).json()
    raw = plans[0]["created_at"]
    parsed = datetime.fromisoformat(raw)
    assert parsed.tzinfo is not None, f"plan created_at has no timezone: {raw!r}"

    scan = client.get(f"/api/v1/scans/{two_projects['a_scan']}").json()
    scan_created = datetime.fromisoformat(scan["created_at"])
    assert scan_created.tzinfo is not None, scan["created_at"]

    # The plan is built at the END of the scan, so it is never older than the scan that produced
    # it. Comparing them at all requires both to be tz-aware — mixing one of each raises.
    assert parsed >= scan_created, (
        "the plan looks older than the scan it was built from, which is what makes the hub call "
        "every fresh plan outdated"
    )
