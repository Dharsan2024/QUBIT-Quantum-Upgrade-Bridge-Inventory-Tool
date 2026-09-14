"""Where the repo root comes from when the caller does not name one.

Two validation stages are gated on it: `applies` needs a root to run `git apply` from, and `tests`
needs one to mount into the sandbox. The dashboard has nowhere to type a path, so every patch
generated through the app arrived at the validator with `repo_root=None` and skipped both -- while
`projects.root_path` held a correct, existing directory the whole time.

Measured on this installation before the fix: of 84 patches, **58 skipped both stages** with "no
repo_root/relative target for test run". After it, `applies` adjudicates and `tests` reports its
real blocker (the sandbox image carries none of the project's dependencies) instead of a plumbing
excuse -- which is the difference between a gap you can see and one you cannot.
"""

from __future__ import annotations

import uuid

import pytest
from qubit_core.db.models import Base, ProjectRow, ScanRow
from qubit_migrate.orchestrator import MigrationOrchestrator
from qubit_migrate.state.models import MigrationPlan, MigrationTask, MigrationUnit
from sqlalchemy import create_engine
from sqlalchemy.orm import Session


@pytest.fixture
def orch() -> MigrationOrchestrator:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return MigrationOrchestrator(Session(engine))


def _task(orch: MigrationOrchestrator, plan: MigrationPlan) -> MigrationTask:
    """A task hangs off a UNIT, not the plan directly, and `unit_id` is NOT NULL."""
    unit = MigrationUnit(id=uuid.uuid4(), plan_id=plan.id)
    orch.session.add(unit)
    orch.session.commit()
    task = MigrationTask(
        id=uuid.uuid4(),
        plan_id=plan.id,
        unit_id=unit.id,
        asset_id=uuid.uuid4(),
        state="ready",
    )
    orch.session.add(task)
    orch.session.commit()
    return task


def _project(orch: MigrationOrchestrator, root: str | None) -> ProjectRow:
    project = ProjectRow(id=uuid.uuid4(), name="p", slug="p", root_path=root)
    orch.session.add(project)
    orch.session.commit()
    return project


def test_a_plan_that_names_its_project_finds_the_root(
    orch: MigrationOrchestrator, tmp_path
) -> None:
    project = _project(orch, str(tmp_path))
    plan = MigrationPlan(id=uuid.uuid4(), project_id=project.id)
    orch.session.add(plan)
    orch.session.commit()

    assert orch._project_root_of(_task(orch, plan)) == tmp_path


def test_a_plan_that_only_names_a_scan_still_finds_the_root(
    orch: MigrationOrchestrator, tmp_path
) -> None:
    """Both spellings occur: a plan built from a scan carries `scan_id` and no `project_id`, which
    is exactly how the corpus plans on this installation were created."""
    project = _project(orch, str(tmp_path))
    scan = ScanRow(id=uuid.uuid4(), project_id=project.id, seq=1)
    orch.session.add(scan)
    orch.session.commit()
    plan = MigrationPlan(id=uuid.uuid4(), scan_id=scan.id)
    orch.session.add(plan)
    orch.session.commit()

    assert orch._project_root_of(_task(orch, plan)) == tmp_path


def test_a_root_that_no_longer_exists_is_ignored(orch: MigrationOrchestrator, tmp_path) -> None:
    """A checkout that has moved must degrade to an unvalidated patch, not a failed one.

    Handing `git apply` and the sandbox mount a directory that is not there turns a clean `skipped`
    into a stage FAILURE, which blames the patch for the operator having moved a folder.
    """
    project = _project(orch, str(tmp_path / "gone"))
    plan = MigrationPlan(id=uuid.uuid4(), project_id=project.id)
    orch.session.add(plan)
    orch.session.commit()

    assert orch._project_root_of(_task(orch, plan)) is None


@pytest.mark.parametrize("root", [None, ""])
def test_a_project_with_no_recorded_root_returns_none(
    orch: MigrationOrchestrator, root: str | None
) -> None:
    project = _project(orch, root)
    plan = MigrationPlan(id=uuid.uuid4(), project_id=project.id)
    orch.session.add(plan)
    orch.session.commit()

    assert orch._project_root_of(_task(orch, plan)) is None


def test_an_orphaned_task_does_not_raise(orch: MigrationOrchestrator) -> None:
    """This runs on a path that had no root at all a moment ago, so every failure mode has to leave
    the caller exactly where it would have been -- never raise."""
    plan = MigrationPlan(id=uuid.uuid4())
    orch.session.add(plan)
    orch.session.commit()

    assert orch._project_root_of(_task(orch, plan)) is None


def test_generate_patch_consults_the_project_root_when_none_was_supplied(
    orch: MigrationOrchestrator, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The helper working is not the fix; `generate_patch` USING it is.

    Without this, removing the fallback call leaves every test above green while the app goes
    straight back to skipping `applies` and `tests` on every patch. The generation itself is
    expected to fail here -- the task points at an asset that does not exist -- and that is
    deliberate: the lookup happens before the asset is loaded, so the cheap failure is enough to
    prove the consultation without standing up a whole repository and rule catalogue.
    """
    project = _project(orch, str(tmp_path))
    plan = MigrationPlan(id=uuid.uuid4(), project_id=project.id)
    orch.session.add(plan)
    orch.session.commit()
    task = _task(orch, plan)

    consulted: list[uuid.UUID] = []
    real = orch._project_root_of

    def spy(t):
        consulted.append(t.id)
        return real(t)

    monkeypatch.setattr(orch, "_project_root_of", spy)

    with pytest.raises(ValueError, match="Asset"):
        orch.generate_patch(task.id)

    assert consulted == [task.id], "a caller that named no root must be given the project's"


def test_a_supplied_repo_root_is_not_second_guessed(
    orch: MigrationOrchestrator, tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The CLI and the evidence scripts pass a root explicitly, and it must win outright --
    silently substituting the project's would send `git apply` somewhere the caller did not ask
    for."""
    project = _project(orch, str(tmp_path / "project-root"))
    plan = MigrationPlan(id=uuid.uuid4(), project_id=project.id)
    orch.session.add(plan)
    orch.session.commit()
    task = _task(orch, plan)

    def must_not_run(t):
        raise AssertionError("the project root was consulted despite one being supplied")

    monkeypatch.setattr(orch, "_project_root_of", must_not_run)

    with pytest.raises(ValueError, match="Asset"):
        orch.generate_patch(task.id, repo_root=tmp_path)
