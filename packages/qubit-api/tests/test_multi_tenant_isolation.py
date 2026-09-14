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
from qubit_core.db.models import DEFAULT_TENANT_ID, Tenant
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
