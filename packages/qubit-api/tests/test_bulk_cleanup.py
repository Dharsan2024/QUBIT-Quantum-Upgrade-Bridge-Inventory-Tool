"""Removing previous work — and, more importantly, what removing it must NOT take with it.

The app offers three rungs, weakest first, because "clear it" almost never means "clear all of it":

* `DELETE /migrate/plans` — throw away the migration, keep the findings it was derived from.
  This one did not exist. `DELETE /scans` threw away the findings too, so "start the migration
  over" cost a rescan of the whole corpus, which on a real repository is minutes of work to undo a
  decision that takes one click to remake.
* `DELETE /scans` — throw away the findings, keep the project shells.
* `DELETE /projects` — throw away everything.

The assertions that matter most here are the ones about what SURVIVES. `learned_patches` and
`learned_outcomes` hold what this installation has worked out about migrating this code: validated
fixes it can replay without a model call, and the per-engine pass/fail record that routes work away
from an engine measured as unable to do it. They carry a `tenant_id` and nothing else — no scan id,
no project id — so no cascade reaches them, and none should. Clearing data means "run it again",
never "forget what you learned". That property is currently true by construction, which is exactly
the kind of thing that breaks silently the day someone adds a convenient `project_id` column.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings
from qubit_migrate.transform import learn
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session


def _make_client(tmp_path: Path) -> tuple[TestClient, str]:
    db_path = tmp_path / "qubit-api.db"
    settings = Settings(
        db_url=f"sqlite:///{db_path.as_posix()}",
        create_schema_on_startup=True,
    )
    client = TestClient(
        create_app(settings),
        headers={"Authorization": f"Bearer {settings.api_token}"},
    )
    return client, settings.db_url


def _seed_repo(repo: Path) -> None:
    repo.mkdir(exist_ok=True)
    (repo / "app.py").write_text(
        "import hashlib\ndigest = hashlib.md5(data)\n",
        encoding="utf-8",
    )


def _scan_and_plan(client: TestClient, repo: Path) -> tuple[str, str, str]:
    """A project with a real scan and a real migration plan built from it."""
    import time

    project_id = client.post(
        "/api/v1/projects", json={"name": "Demo", "root_path": str(repo)}
    ).json()["id"]
    scan_id = client.post(
        f"/api/v1/projects/{project_id}/scans", json={"targets": [str(repo)]}
    ).json()["scan"]["id"]
    for _ in range(150):
        if client.get(f"/api/v1/scans/{scan_id}").json()["status"] not in ("queued", "running"):
            break
        time.sleep(0.1)
    plan = client.post("/api/v1/migrate/plans", json={"min_risk": 0.0, "project_id": project_id})
    assert plan.status_code == 201, plan.text
    return project_id, scan_id, plan.json()["id"]


def _remember_something(db_url: str) -> None:
    """Put a validated fix and a recorded outcome in the experience base."""
    with Session(create_engine(db_url)) as session:
        learn.record(
            session,
            rule_id="py-weakhash-01",
            language="python",
            algorithm="MD5",
            orig="import hashlib\ndigest = hashlib.md5(data)\n",
            new="import hashlib\ndigest = hashlib.sha256(data)\n",
            line=2,
            model_name="test-engine",
        )
        learn.record_outcome(
            session,
            rule_id="py-weakhash-01",
            language="python",
            algorithm="MD5",
            shape="shape-1",
            passed=True,
            hunk_before="digest = hashlib.md5(data)",
            hunk_after="digest = hashlib.sha256(data)",
            model_name="test-engine",
        )
        session.commit()


def _learning_counts(db_url: str) -> tuple[int, int]:
    from qubit_core.db.models import LearnedOutcome, LearnedPatch

    with Session(create_engine(db_url)) as session:
        return (
            session.scalar(select(func.count()).select_from(LearnedPatch)) or 0,
            session.scalar(select(func.count()).select_from(LearnedOutcome)) or 0,
        )


def test_clearing_migrations_keeps_the_scan_it_was_built_from(tmp_path: Path) -> None:
    """The rung that did not exist. Rebuilding a plan is one click; rescanning a corpus is not."""
    repo = tmp_path / "repo"
    _seed_repo(repo)
    client, _ = _make_client(tmp_path)
    with client:
        project_id, scan_id, _plan_id = _scan_and_plan(client, repo)
        assert client.get("/api/v1/migrate/plans").json(), "baseline: a plan exists"
        assets_before = client.get(f"/api/v1/scans/{scan_id}/assets").json()["total"]
        assert assets_before > 0, "baseline: the scan found something"

        resp = client.request("DELETE", "/api/v1/migrate/plans")

        assert resp.status_code == 200, resp.text
        assert resp.json()["deleted"] >= 1
        assert client.get("/api/v1/migrate/plans").json() == []
        # The whole point: the findings are still here, so a new plan can be built at once.
        assert client.get(f"/api/v1/scans/{scan_id}/assets").json()["total"] == assets_before
        assert len(client.get("/api/v1/scans").json()) == 1
        rebuilt = client.post(
            "/api/v1/migrate/plans", json={"min_risk": 0.0, "project_id": project_id}
        )
        assert rebuilt.status_code == 201, "a plan must be rebuildable with no rescan"


def test_clearing_scans_keeps_the_project_shell(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _seed_repo(repo)
    client, _ = _make_client(tmp_path)
    with client:
        _scan_and_plan(client, repo)

        resp = client.request("DELETE", "/api/v1/scans")

        assert resp.status_code == 200, resp.text
        assert client.get("/api/v1/scans").json() == []
        assert len(client.get("/api/v1/projects").json()) == 1, (
            "the project shell stays so a repeat scan has somewhere to land"
        )


def test_resetting_projects_clears_everything_below_them(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _seed_repo(repo)
    client, _ = _make_client(tmp_path)
    with client:
        _scan_and_plan(client, repo)

        resp = client.request("DELETE", "/api/v1/projects")

        assert resp.status_code == 200, resp.text
        assert client.get("/api/v1/projects").json() == []
        assert client.get("/api/v1/scans").json() == []
        assert client.get("/api/v1/migrate/plans").json() == []


def test_no_rung_of_the_ladder_forgets_what_qubit_has_learned(tmp_path: Path) -> None:
    """The assertion this file exists for.

    `learned_patches` and `learned_outcomes` are what make the next run cheaper and better: a
    validated fix replayed without a model call, and the per-engine record that routes a finding
    away from an engine already measured as unable to do it. Both cost real model time to produce.

    Nothing here should reach them, and today nothing does — they carry only a `tenant_id`. This
    pins that, because the day someone denormalises a `project_id` onto either table for a
    convenient query, a "Clear scans" click would silently start wiping the experience base and
    the only symptom would be that QUBIT quietly got worse at its job.
    """
    repo = tmp_path / "repo"
    _seed_repo(repo)
    client, db_url = _make_client(tmp_path)
    with client:
        _scan_and_plan(client, repo)
        _remember_something(db_url)
        before = _learning_counts(db_url)
        assert before == (1, 1), f"baseline: something was learned, got {before}"

        for endpoint in ("/api/v1/migrate/plans", "/api/v1/scans", "/api/v1/projects"):
            assert client.request("DELETE", endpoint).status_code == 200
            assert _learning_counts(db_url) == before, (
                f"DELETE {endpoint} destroyed the experience base"
            )

        # And the data really is gone — otherwise the assertion above proves nothing.
        assert client.get("/api/v1/projects").json() == []
        assert client.get("/api/v1/scans").json() == []
        assert client.get("/api/v1/migrate/plans").json() == []
