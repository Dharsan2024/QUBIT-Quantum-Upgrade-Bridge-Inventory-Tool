"""Creating a project from a git URL, which is how the twins are reached at demo time.

The CLI could always start from a URL; the desktop app could not. `POST /projects` accepted a local
`root_path` only, so a repository that was not already checked out had to be cloned by hand before
the app could see it. That matters concretely here: the digital twins live in a teammate's GitHub
account, not on the machine running the demo.

Cloning is the one place QUBIT reaches the network, and only for a URL a person typed. The direction
is inward — nothing is uploaded — but the URL is also the one field on this endpoint that reaches a
subprocess, so the validation is tested as carefully as the happy path.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from qubit_api.app import create_app
from qubit_api.settings import Settings


@pytest.fixture
def client(tmp_path: Path) -> Any:
    settings = Settings(
        db_url=f"sqlite:///{(tmp_path / 'giturl.db').as_posix()}",
        create_schema_on_startup=True,
    )
    with TestClient(
        create_app(settings), headers={"Authorization": f"Bearer {settings.api_token}"}
    ) as c:
        yield c


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


@pytest.fixture
def origin(tmp_path: Path) -> Path:
    """A real git repository to clone, so the test exercises `git clone` rather than a mock."""
    repo = tmp_path / "origin"
    (repo / "lib").mkdir(parents=True)
    (repo / "lib" / "crypto.rb").write_text(
        'require "digest"\ndef d(x) = Digest::MD5.hexdigest(x)\n', encoding="utf-8"
    )
    _git("init", "-q", "-b", "main", cwd=repo)
    _git("config", "user.email", "t@example.com", cwd=repo)
    _git("config", "user.name", "T", cwd=repo)
    _git("add", "-A", cwd=repo)
    _git("commit", "-q", "-m", "initial", cwd=repo)
    return repo


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """Redirect the clone destination, so a test never writes into the real app data directory."""
    root = tmp_path / "workspaces"
    monkeypatch.setattr("qubit_api.routers.projects._workspace_root", lambda: root, raising=True)
    return root


class TestCloningOnCreate:
    def test_a_local_clone_is_accepted_and_root_path_points_at_it(
        self, client, origin: Path, workspace: Path, monkeypatch
    ) -> None:
        """`git clone` accepts a plain path, which is what makes this testable offline.

        The URL pattern refuses `file://` on purpose, so the test relaxes the pattern rather than
        the endpoint: what is under test is the clone-and-wire-up, not the regex, which has its
        own test below.
        """
        import re

        monkeypatch.setattr(
            "qubit_api.routers.projects._GIT_URL", re.compile(r"^.+$"), raising=True
        )
        response = client.post(
            "/api/v1/projects", json={"name": "twin-local", "git_url": str(origin)}
        )
        assert response.status_code == 201, response.text
        root = Path(response.json()["root_path"])
        assert root.is_dir(), "the project points at a directory that does not exist"
        assert (root / "lib" / "crypto.rb").is_file(), "the repository contents are missing"
        assert (root / ".git").exists(), (
            "no git metadata: `applies` and the tests baseline both need a HEAD to work from"
        )

    def test_an_explicit_root_path_is_never_replaced_by_a_clone(
        self, client, origin: Path, workspace: Path, tmp_path: Path
    ) -> None:
        """A local checkout the user named must win. Silently cloning over it would migrate the
        wrong tree, and the user would have no way to tell from the UI."""
        local = tmp_path / "already-here"
        local.mkdir()
        response = client.post(
            "/api/v1/projects",
            json={
                "name": "twin-both",
                "root_path": str(local),
                "git_url": "https://github.com/example/other.git",
            },
        )
        assert response.status_code == 201, response.text
        assert Path(response.json()["root_path"]) == local
        assert not workspace.exists(), "cloned even though a root_path was given"

    def test_creating_the_same_project_twice_reuses_the_checkout(
        self, client, origin: Path, workspace: Path, monkeypatch
    ) -> None:
        import re

        monkeypatch.setattr(
            "qubit_api.routers.projects._GIT_URL", re.compile(r"^.+$"), raising=True
        )
        first = client.post("/api/v1/projects", json={"name": "twin-twice", "git_url": str(origin)})
        assert first.status_code == 201, first.text
        # Same slug, so the same destination: it must be reused rather than failing on "exists".
        from qubit_api.routers.projects import _clone_for_project

        again = _clone_for_project(str(origin), "twin-twice")
        assert again == workspace / "twin-twice"

    def test_a_clone_that_fails_reports_git_s_own_error(
        self, client, workspace: Path, monkeypatch
    ) -> None:
        """A failure must name the cause. An early version of the CLI's clone just hung."""
        import re

        monkeypatch.setattr(
            "qubit_api.routers.projects._GIT_URL", re.compile(r"^.+$"), raising=True
        )
        response = client.post(
            "/api/v1/projects",
            json={"name": "twin-missing", "git_url": "/nonexistent/repo/path"},
        )
        assert response.status_code == 422
        assert "clone failed" in response.json()["detail"]
        assert not (workspace / "twin-missing").exists(), "a failed clone left a partial checkout"


class TestTheUrlPatternIsTheSubprocessBoundary:
    @pytest.mark.parametrize(
        "url",
        [
            "https://github.com/user/twin.git",
            "http://internal.example/repo.git",
            "git@github.com:user/twin.git",
            "ssh://git@host:2222/team/twin.git",
            "git://host/x.git",
        ],
    )
    def test_real_forms_are_accepted(self, url: str) -> None:
        from qubit_api.routers.projects import _GIT_URL

        assert _GIT_URL.match(url), url

    @pytest.mark.parametrize(
        "url",
        [
            "--upload-pack=/bin/sh",  # argument injection: the reason this pattern is anchored
            "-u",
            "; rm -rf /",
            "file:///etc/passwd",  # not a remote; would expose local files as a "project"
            "ext::sh -c whoami",  # git's own transport escape hatch
            "",
        ],
    )
    def test_dangerous_forms_are_refused(self, url: str) -> None:
        from qubit_api.routers.projects import _GIT_URL

        assert not _GIT_URL.match(url), url

    def test_the_endpoint_refuses_them_too(self, client, workspace: Path) -> None:
        response = client.post(
            "/api/v1/projects",
            json={"name": "twin-evil", "git_url": "--upload-pack=/bin/sh"},
        )
        assert response.status_code == 422
        assert "not a git URL" in response.json()["detail"]
