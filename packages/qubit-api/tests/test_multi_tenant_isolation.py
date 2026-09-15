"""Two teams on one engine must not be able to reach each other's data.

QUBIT is self-hosted and offline, so a "tenant" here is a TEAM sharing one deployment, not a
customer of a hosted service. The isolation still has to be real rather than advisory: the token
names the team, and every scoped query filters on it.

The assertions that matter most are the negative ones, and they check for **404, never 403**. A 403
would confirm the id exists, which tells team B that team A has a project by that id — from outside
a tenant, another tenant's data must be indistinguishable from data that was never there.

A single-team install is the same code path with one tenant, which is why the rest of the suite
needed no changes: the bootstrap token authenticates as the default tenant, exactly as before.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings
from qubit_core.db import create_token, session_factory
from qubit_core.db.models import (
    DEFAULT_TENANT_ID,
    AssetRow,
    Job,
    LearnedOutcome,
    LearnedPatch,
    ProjectRow,
    ScanRow,
    Tenant,
)
from qubit_migrate.state import MigrationPlan, MigrationTask, MigrationUnit, PatchProposal
from sqlalchemy import create_engine


@pytest.fixture
def app_and_tokens(tmp_path: Path):
    """One engine, two teams, one rw token each.

    Team A is the DEFAULT tenant, because that is what an existing single-team install becomes when
    it grows a second team — the realistic upgrade path, not a synthetic pair.
    """
    db_path = tmp_path / "qubit-tenants.db"
    settings = Settings(db_url=f"sqlite:///{db_path.as_posix()}", create_schema_on_startup=True)
    app = create_app(settings)

    engine = create_engine(settings.db_url)
    factory = session_factory(engine)
    with factory() as session:
        team_b = Tenant(id=uuid.uuid4(), slug="team-b", name="Team B")
        session.add(team_b)
        session.commit()
        token_a = create_token(session, "team-a-token", "rw", DEFAULT_TENANT_ID).raw
        token_b = create_token(session, "team-b-token", "rw", team_b.id).raw

    return app, token_a, token_b


def _client(app, token: str) -> TestClient:
    return TestClient(app, headers={"Authorization": f"Bearer {token}"})


class TestProjectsAreInvisibleAcrossTeams:
    def test_a_project_created_by_one_team_is_not_listed_by_the_other(self, app_and_tokens) -> None:
        app, token_a, token_b = app_and_tokens
        with _client(app, token_a) as a, _client(app, token_b) as b:
            created = a.post("/api/v1/projects", json={"name": "Team A secret work"})
            assert created.status_code == 201

            assert [p["name"] for p in a.get("/api/v1/projects").json()] == ["Team A secret work"]
            assert b.get("/api/v1/projects").json() == []

    def test_fetching_another_teams_project_by_id_is_404_not_403(self, app_and_tokens) -> None:
        app, token_a, token_b = app_and_tokens
        with _client(app, token_a) as a, _client(app, token_b) as b:
            project_id = a.post("/api/v1/projects", json={"name": "A"}).json()["id"]

            resp = b.get(f"/api/v1/projects/{project_id}")
            # 404, not 403: a 403 would confirm the id is real.
            assert resp.status_code == 404

    def test_another_team_cannot_modify_or_delete_it(self, app_and_tokens) -> None:
        app, token_a, token_b = app_and_tokens
        with _client(app, token_a) as a, _client(app, token_b) as b:
            project_id = a.post("/api/v1/projects", json={"name": "A"}).json()["id"]

            assert (
                b.patch(
                    f"/api/v1/projects/{project_id}", json={"description": "hijacked"}
                ).status_code
                == 404
            )
            assert b.delete(f"/api/v1/projects/{project_id}").status_code == 404
            # Still there, still untouched.
            assert a.get(f"/api/v1/projects/{project_id}").json()["description"] is None

    def test_the_overview_rollup_does_not_count_another_teams_projects(
        self, app_and_tokens
    ) -> None:
        app, token_a, token_b = app_and_tokens
        with _client(app, token_a) as a, _client(app, token_b) as b:
            a.post("/api/v1/projects", json={"name": "A one"})
            a.post("/api/v1/projects", json={"name": "A two"})
            b.post("/api/v1/projects", json={"name": "B one"})

            assert len(a.get("/api/v1/projects/overview").json()) == 2
            assert len(b.get("/api/v1/projects/overview").json()) == 1


class TestTheDestructiveEndpointsAreScoped:
    def test_reset_all_projects_only_clears_the_callers_own(self, app_and_tokens) -> None:
        """The endpoint where an unscoped query would be worst: one team's Reset button must not
        wipe every other team's work off the shared engine."""
        app, token_a, token_b = app_and_tokens
        with _client(app, token_a) as a, _client(app, token_b) as b:
            a.post("/api/v1/projects", json={"name": "A one"})
            b.post("/api/v1/projects", json={"name": "B one"})

            deleted = a.delete("/api/v1/projects").json()
            assert deleted == {"deleted": 1}
            assert a.get("/api/v1/projects").json() == []
            assert [p["name"] for p in b.get("/api/v1/projects").json()] == ["B one"]

    def test_clear_all_scans_only_clears_the_callers_own(self, app_and_tokens) -> None:
        app, token_a, token_b = app_and_tokens
        with _client(app, token_a) as a, _client(app, token_b) as b:
            b.post("/api/v1/projects", json={"name": "B one"})
            # Team A has no scans at all; the call must still not touch team B's project.
            a.delete("/api/v1/scans")
            assert [p["name"] for p in b.get("/api/v1/projects").json()] == ["B one"]


class TestNamesAreUniquePerTeamNotGlobally:
    def test_two_teams_may_both_have_a_project_called_backend(self, app_and_tokens) -> None:
        """Previously a global UNIQUE, so the second team got a 409 — which also leaked the fact
        that someone else had taken the name."""
        app, token_a, token_b = app_and_tokens
        with _client(app, token_a) as a, _client(app, token_b) as b:
            assert a.post("/api/v1/projects", json={"name": "backend"}).status_code == 201
            assert b.post("/api/v1/projects", json={"name": "backend"}).status_code == 201

    def test_the_same_team_still_cannot_reuse_a_name(self, app_and_tokens) -> None:
        app, token_a, _ = app_and_tokens
        with _client(app, token_a) as a:
            assert a.post("/api/v1/projects", json={"name": "backend"}).status_code == 201
            assert a.post("/api/v1/projects", json={"name": "backend"}).status_code == 409


class TestWhoamiReportsTheTeam:
    def test_each_token_reports_its_own_team(self, app_and_tokens) -> None:
        app, token_a, token_b = app_and_tokens
        with _client(app, token_a) as a, _client(app, token_b) as b:
            assert a.get("/api/v1/auth/whoami").json()["tenant"] == "Default"
            assert b.get("/api/v1/auth/whoami").json()["tenant"] == "Team B"


class TestTheBootstrapTokenClosesOnceTeamsExist:
    def test_the_published_default_token_stops_working_once_a_real_token_is_minted(
        self, app_and_tokens
    ) -> None:
        """No window where a credential published in this repository works alongside team tokens.

        `has_any_tokens` is global across every tenant, and onboarding a team requires minting it a
        token — so the first mint permanently closes the bootstrap path for everyone.
        """
        app, _, _ = app_and_tokens
        with _client(app, "qubit-dev-token-do-not-use-in-prod") as bootstrap:
            assert bootstrap.get("/api/v1/projects").status_code == 401


class TestASingleTeamInstallIsUnchanged:
    def test_the_bootstrap_token_works_and_lands_on_the_default_tenant(
        self, tmp_path: Path
    ) -> None:
        """The path every existing install takes: no tokens minted, one implicit team."""
        db_path = tmp_path / "single.db"
        settings = Settings(db_url=f"sqlite:///{db_path.as_posix()}", create_schema_on_startup=True)
        with TestClient(
            create_app(settings), headers={"Authorization": f"Bearer {settings.api_token}"}
        ) as client:
            assert client.post("/api/v1/projects", json={"name": "demo"}).status_code == 201
            assert [p["name"] for p in client.get("/api/v1/projects").json()] == ["demo"]

            who = client.get("/api/v1/auth/whoami").json()
            assert who["tenant_id"] == str(DEFAULT_TENANT_ID)


def _seed_migration(app, tenant_id):
    with app.state.session_factory() as session:
        project = ProjectRow(tenant_id=tenant_id, name=str(uuid.uuid4()), slug=str(uuid.uuid4()))
        session.add(project)
        session.flush()
        scan = ScanRow(tenant_id=tenant_id, project_id=project.id, seq=1, status="succeeded")
        session.add(scan)
        session.flush()
        asset = AssetRow(
            tenant_id=tenant_id,
            project_id=project.id,
            scan_id=scan.id,
            fingerprint=uuid.uuid4().hex[:16],
            source_scanner="code",
            asset_type="primitive",
            algorithm="RSA",
            qv_vulnerable=True,
        )
        plan = MigrationPlan(tenant_id=tenant_id, project_id=project.id, scan_id=scan.id)
        session.add_all([asset, plan])
        session.flush()
        unit = MigrationUnit(plan_id=plan.id)
        session.add(unit)
        session.flush()
        task = MigrationTask(plan_id=plan.id, unit_id=unit.id, asset_id=asset.id, state="ready")
        session.add(task)
        session.flush()
        patch = PatchProposal(
            task_id=task.id,
            file_path="secret.py",
            base_sha256="0" * 64,
            diff_text="private source change",
        )
        job = Job(tenant_id=tenant_id, project_id=project.id, kind="migrate", ref_id=plan.id)
        session.add_all([patch, job])
        session.commit()
        return {
            name: str(row.id)
            for name, row in dict(
                project=project, scan=scan, plan=plan, task=task, patch=patch, job=job
            ).items()
        }


def test_migration_identifiers_are_checked_before_side_effects(app_and_tokens, monkeypatch):
    app, token_a, token_b = app_and_tokens
    with _client(app, token_a) as a, _client(app, token_b) as b:
        ids = _seed_migration(app, DEFAULT_TENANT_ID)
        from qubit_migrate.orchestrator import MigrationOrchestrator

        def forbidden_call(*args, **kwargs):
            pytest.fail("Foreign task reached the orchestrator")

        for method in ("generate_patch", "advise_task", "review_patch", "apply_patch"):
            monkeypatch.setattr(MigrationOrchestrator, method, forbidden_call)
        for task_id in (ids["task"], str(uuid.uuid4())):
            assert b.get(f"/api/v1/migrate/tasks/{task_id}/patches").status_code == 404
            for operation in ("generate", "advise"):
                assert (
                    b.post(f"/api/v1/migrate/tasks/{task_id}/{operation}", json={}).status_code
                    == 404
                )
        for patch_id in (ids["patch"], str(uuid.uuid4())):
            assert (
                b.post(
                    f"/api/v1/migrate/patches/{patch_id}/review", json={"approve": True}
                ).status_code
                == 404
            )
            assert (
                b.post(
                    f"/api/v1/migrate/patches/{patch_id}/apply", json={"repo_root": "nonexistent"}
                ).status_code
                == 404
            )
        assert a.get(f"/api/v1/migrate/tasks/{ids['task']}/patches").status_code == 200
        assert b.get(f"/api/v1/jobs/{ids['job']}/events").status_code == 404
        assert b.get(f"/api/v1/jobs/{uuid.uuid4()}/events").status_code == 404


def test_plan_scan_scope_is_validated_even_before_duplicate_reuse(app_and_tokens):
    app, token_a, token_b = app_and_tokens
    with _client(app, token_a) as a, _client(app, token_b) as b:
        ids = _seed_migration(app, DEFAULT_TENANT_ID)
        assert b.post("/api/v1/migrate/plans", json={"scan_id": ids["scan"]}).status_code == 404
        other = a.post("/api/v1/projects", json={"name": "other"}).json()["id"]
        assert (
            a.post(
                "/api/v1/migrate/plans", json={"scan_id": ids["scan"], "project_id": other}
            ).status_code
            == 422
        )
        response = a.post(
            "/api/v1/migrate/plans", json={"scan_id": ids["scan"], "project_id": ids["project"]}
        )
        assert response.status_code == 201
        assert response.json()["id"] == ids["plan"]


def test_learning_counts_do_not_include_another_team(app_and_tokens):
    app, token_a, token_b = app_and_tokens
    with _client(app, token_a) as a, _client(app, token_b) as b:
        tenant_b = uuid.UUID(b.get("/api/v1/auth/whoami").json()["tenant_id"])
        with app.state.session_factory() as session:
            for tenant, rule, hits in (
                (DEFAULT_TENANT_ID, "private-a", 7),
                (tenant_b, "private-b", 2),
            ):
                session.add(
                    LearnedPatch(
                        tenant_id=tenant,
                        rule_id=rule,
                        language="python",
                        snippet_key=rule,
                        snippet_before="before",
                        snippet_after="after",
                        hit_count=hits,
                    )
                )
                session.add(
                    LearnedOutcome(
                        tenant_id=tenant,
                        rule_id=rule,
                        language="python",
                        shape_key=rule,
                        outcome="passed",
                        hunk_before="before",
                        hunk_after="after",
                    )
                )
            session.commit()
        for client, own_rule, foreign_rule, hits in (
            (a, "private-a", "private-b", 7),
            (b, "private-b", "private-a", 2),
        ):
            response = client.get("/api/v1/migrate/learning")
            assert response.status_code == 200
            assert response.json()["cached_lines"] == 1
            assert response.json()["cache_hits"] == hits
            assert own_rule in response.text and foreign_rule not in response.text


def test_nondefault_migration_job_stays_with_its_tenant(app_and_tokens, monkeypatch):
    app, token_a, token_b = app_and_tokens
    with _client(app, token_a) as a, _client(app, token_b) as b:
        tenant_b = uuid.UUID(b.get("/api/v1/auth/whoami").json()["tenant_id"])
        ids = _seed_migration(app, tenant_b)
        submitted = []
        monkeypatch.setattr(app.state.job_runner, "submit", submitted.append)
        response = b.post(f"/api/v1/migrate/plans/{ids['plan']}/run", json={"generate": True})
        assert response.status_code == 202, response.text
        job_id = response.json()["job"]["id"]
        assert submitted == [uuid.UUID(job_id)]
        assert b.get(f"/api/v1/jobs/{job_id}").status_code == 200
        assert a.get(f"/api/v1/jobs/{job_id}").status_code == 404


@pytest.mark.parametrize(
    "path",
    ["llm-provider/config", "llm-provider/engines", "llm-provider/budget", "threat-intel/config"],
)
def test_shared_provider_and_installation_state_is_operator_only(app_and_tokens, path):
    app, token_a, token_b = app_and_tokens
    with _client(app, token_a) as a, _client(app, token_b) as b:
        assert b.get(f"/api/v1/{path}").status_code == 403
        assert a.get(f"/api/v1/{path}").status_code == 200


def test_sse_replay_filters_foreign_and_unowned_events(app_and_tokens):
    import asyncio
    from types import SimpleNamespace

    from qubit_api.jobs.bus import SSEEvent
    from qubit_api.routers.jobs import _sse_generator

    app, _, _ = app_and_tokens
    ids = _seed_migration(app, DEFAULT_TENANT_ID)
    with app.state.session_factory() as session:
        team_b = session.query(Tenant).filter(Tenant.slug == "team-b").one().id
    other = _seed_migration(app, team_b)

    class Bus:
        async def subscribe(self, last_event_id):
            assert last_event_id == "0"
            for index, job in enumerate((other["job"], str(uuid.uuid4()), ids["job"])):
                yield SSEEvent(
                    id=str(index), event="job.progress", data='{"job_id": "' + job + '"}'
                )
            yield SSEEvent(id="4", event="bad", data="[]")

    async def connected():
        return False

    request = SimpleNamespace(app=app, headers={"Last-Event-ID": "0"}, is_disconnected=connected)

    async def collect():
        return [event async for event in _sse_generator(Bus(), request, DEFAULT_TENANT_ID)]

    assert [event["id"] for event in asyncio.run(collect())] == ["2"]
