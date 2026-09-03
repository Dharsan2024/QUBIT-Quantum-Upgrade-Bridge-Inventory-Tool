"""A plan built from a scan must resolve the PROJECT's root, not the scanned subtree.

The dashboard's "Build plan" posts a `scan_id` and no `project_id`, so `plan.project_id` is null on
every plan the app itself creates. `_plan_repo_root` used to read only that field and fall through
to the scan's first target, which is routinely a subtree — `src/main` for a Maven project, `lib` for
a gem, `internal` for a Go module.

Handing a subtree to the validator as the repository root costs two rungs of the evidence ladder
without saying so: `applies` reports "no git repo to check against" and `tests` reports "no test
suite detected in repo", both true of the subtree and false of the project. Measured through the
desktop app on the Ruby twin, every applied patch came back `evidence_level: -1` against a
repository that has both a git history and a suite.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from qubit_api.jobs.handlers import _plan_repo_root


class _Row:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Session:
    """Just enough Session to answer the two `get` calls the function makes."""

    def __init__(self, rows: dict):
        self._rows = rows

    def get(self, model, pk):
        return self._rows.get((model.__name__, pk))


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "lib" / "inkwell").mkdir(parents=True)
    (tmp_path / "test").mkdir()
    (tmp_path / ".git").mkdir()
    return tmp_path


def _session(project_root, plan_project_id, scan_project_id, targets):
    from qubit_api.jobs.handlers import ProjectRow, ScanRow

    project_id, scan_id = uuid4(), uuid4()
    rows = {
        ("ScanRow", scan_id): _Row(
            project_id=scan_project_id and project_id, targets=targets
        ),
    }
    if project_root is not None:
        rows[("ProjectRow", project_id)] = _Row(root_path=str(project_root))
    plan = _Row(project_id=plan_project_id and project_id, scan_id=scan_id)
    assert ProjectRow.__name__ == "ProjectRow" and ScanRow.__name__ == "ScanRow"
    return _Session(rows), plan


def test_plan_without_project_id_still_finds_the_project_root(tree: Path):
    """The case the dashboard actually produces."""
    session, plan = _session(tree, plan_project_id=False, scan_project_id=True,
                             targets=[str(tree / "lib")])
    assert _plan_repo_root(session, plan) == tree


def test_plan_with_its_own_project_id_is_unchanged(tree: Path):
    session, plan = _session(tree, plan_project_id=True, scan_project_id=True,
                             targets=[str(tree / "lib")])
    assert _plan_repo_root(session, plan) == tree


def test_scan_target_is_still_the_fallback_when_there_is_no_project(tree: Path):
    """A scan with no project behind it has nothing better to offer, and the target is right."""
    session, plan = _session(None, plan_project_id=False, scan_project_id=False,
                             targets=[str(tree / "lib")])
    assert _plan_repo_root(session, plan) == tree / "lib"


def test_a_project_root_that_no_longer_exists_falls_back(tree: Path, tmp_path: Path):
    """A stale `root_path` must not beat a target that is really there."""
    session, plan = _session(tmp_path / "gone", plan_project_id=False, scan_project_id=True,
                             targets=[str(tree / "lib")])
    assert _plan_repo_root(session, plan) == tree / "lib"


def test_no_scan_and_no_project_gives_none():
    session, plan = _session(None, plan_project_id=False, scan_project_id=False, targets=[])
    assert _plan_repo_root(session, plan) is None
