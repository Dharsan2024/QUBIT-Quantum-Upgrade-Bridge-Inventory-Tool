"""Which sandbox image validates a patch, and what counts as having a test suite.

Both questions gate the only stage that can say a migration PRESERVED BEHAVIOUR. Getting either
wrong does not produce a wrong answer -- it produces no answer, reported as `skipped`, which reads
as a property of the repository rather than of QUBIT. Measured on this installation before these
fixes: 84 patches, 84 `tests` skips, not one behaviour verdict in the database. After them, on
tornado, `tests` adjudicated 5 of 5.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from qubit_core.db.models import Base
from qubit_migrate.config import MigrateConfig
from qubit_migrate.orchestrator import MigrationOrchestrator
from qubit_migrate.transform.validate import _has_test_suite
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


@pytest.fixture
def orch() -> MigrationOrchestrator:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return MigrationOrchestrator(Session(engine))


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    MigrationOrchestrator._IMAGE_CACHE.clear()


def _git_repo(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    (root / "f.py").write_text("x = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
        cwd=root,
        check=True,
    )


class TestSandboxImage:
    def test_the_configured_default_is_read_from_the_model_not_the_class(
        self, orch: MigrationOrchestrator
    ) -> None:
        """The regression that took generation down for every task.

        `MigrateConfig` is a pydantic model, so its default lives in `model_fields` -- reading
        `MigrateConfig.test_sandbox_image` as a class attribute raises `AttributeError`, and because
        this runs on the validation path it surfaced as HTTP 500 on every single generate.
        """
        assert orch._sandbox_image_for(None) == MigrateConfig().test_sandbox_image

    def test_a_repository_with_a_matching_image_gets_it(
        self, orch: MigrationOrchestrator, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The images `build_sandbox_image.py` produces sat unused on disk because nothing derived
        their tag. The builder names them `qubit-eval/<owner>-<repo>:<commit12>`, and the corpus
        checkout for that repository is the directory `<owner>__<repo>` -- the same two names, one
        separator apart."""
        repo = tmp_path / "tornadoweb__tornado"
        _git_repo(repo)
        head = (
            subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, check=True)
            .stdout.decode()
            .strip()[:12]
        )
        asked: list[str] = []
        real_run = subprocess.run

        def fake_run(argv, **kwargs):
            if argv[:3] == ["docker", "image", "inspect"]:
                asked.append(argv[3])
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            return real_run(argv, **kwargs)

        monkeypatch.setattr("subprocess.run", fake_run)

        assert orch._sandbox_image_for(repo) == f"qubit-eval/tornadoweb-tornado:{head}"
        assert asked == [f"qubit-eval/tornadoweb-tornado:{head}"]

    def test_a_repository_with_no_matching_image_keeps_the_default(
        self, orch: MigrationOrchestrator, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "nobody__nothing"
        _git_repo(repo)
        real_run = subprocess.run

        def fake_run(argv, **kwargs):
            if argv[:3] == ["docker", "image", "inspect"]:
                return subprocess.CompletedProcess(argv, 1, b"", b"No such image")
            return real_run(argv, **kwargs)

        monkeypatch.setattr("subprocess.run", fake_run)

        assert orch._sandbox_image_for(repo) == MigrateConfig().test_sandbox_image

    def test_an_explicitly_configured_image_is_never_substituted(
        self, tmp_path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An operator who set an image meant it. Silently swapping in another would make the
        sandbox unauditable -- the published `pip freeze` would describe a different container from
        the one that produced the verdict."""
        engine = create_engine("sqlite://")
        Base.metadata.create_all(engine)
        orch = MigrationOrchestrator(
            Session(engine), MigrateConfig(test_sandbox_image="my/own:image")
        )
        repo = tmp_path / "tornadoweb__tornado"
        _git_repo(repo)
        real_run = subprocess.run

        def explode(argv, **kwargs):
            if argv[:3] == ["docker", "image", "inspect"]:
                raise AssertionError("docker must not be consulted for a configured image")
            return real_run(argv, **kwargs)

        monkeypatch.setattr("subprocess.run", explode)

        assert orch._sandbox_image_for(repo) == "my/own:image"

    def test_a_directory_that_is_not_a_git_checkout_falls_back(
        self, orch: MigrationOrchestrator, tmp_path
    ) -> None:
        """No commit means no tag to derive, and a missing repository must never raise on a path
        whose only job is to pick a nicer image."""
        plain = tmp_path / "plain"
        plain.mkdir()

        assert orch._sandbox_image_for(plain) == MigrateConfig().test_sandbox_image


class TestSuiteDetection:
    def test_a_root_level_tests_directory_counts(self, tmp_path) -> None:
        (tmp_path / "tests").mkdir()
        assert _has_test_suite(tmp_path) is True

    def test_tests_nested_beside_the_code_count(self, tmp_path) -> None:
        """Django and Ansible both keep tests inside each app rather than at the root. Looking only
        at the root refused wagtail and ansible -- 16 of 84 patches on this installation -- with
        "no test suite detected in repo", against repositories that unambiguously have one."""
        (tmp_path / "wagtail" / "images" / "tests").mkdir(parents=True)
        assert _has_test_suite(tmp_path) is True

    def test_a_tox_runner_counts(self, tmp_path) -> None:
        (tmp_path / "tox.ini").write_text("[testenv]\ncommands = pytest {posargs}\n")
        assert _has_test_suite(tmp_path) is True

    def test_a_bare_conftest_counts(self, tmp_path) -> None:
        (tmp_path / "conftest.py").write_text("")
        assert _has_test_suite(tmp_path) is True

    def test_vendored_trees_do_not_count(self, tmp_path) -> None:
        """`node_modules` and `.tox` carry other people's suites. Counting them would send a
        container after a repository that has no tests of its own."""
        (tmp_path / "node_modules" / "pkg" / "tests").mkdir(parents=True)
        (tmp_path / ".tox" / "py312" / "tests").mkdir(parents=True)
        assert _has_test_suite(tmp_path) is False

    def test_a_repository_with_nothing_is_still_refused(self, tmp_path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "README.md").write_text("hi")
        assert _has_test_suite(tmp_path) is False
