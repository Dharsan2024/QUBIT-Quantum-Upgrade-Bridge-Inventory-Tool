"""The `tests` stage: the only thing in the pipeline that can say a migration preserved behaviour.

Every other stage is syntactic. `rescan` says the scanner stopped seeing RSA and started seeing
ML-KEM — equally true of a rewrite that reuses a nonce, drops an auth tag, or breaks every caller.
Measured on this installation before these changes: **292 patches, 292 `tests` skips**, 0 patches
with every stage run, and 216 of 216 accepted patches flagged `partial`.

The cause was not a bug in the check, it was the sandbox: a bare `python:3.12-slim` with no network
carries no pytest and none of the target repo's dependencies, so the suite died on its own imports,
the stage re-ran the untouched tree, that was red too, and it honestly declined to judge. These
tests pin the three changes that turn it into an oracle:

* the image is configurable, and is **guarded** so the stage can never silently pull one;
* the verdict is a per-test set difference — a patch fails when something that PASSED before it
  stops passing — so the handful of tests a real repo cannot run offline no longer discard the
  evidence from the other several thousand;
* the baseline is computed once per (image, repo), not once per patch.

Docker is never invoked here. `_docker_run` is replaced by a fake that decides outcomes from the
content of the tree it is handed, which is exactly what a real suite does, only faster.
"""

from __future__ import annotations

import json

import pytest
from qubit_migrate.config import MigrateConfig
from qubit_migrate.transform import validate

_MODULE = "pkg/mod.py"
_CLEAN = "def value():\n    return 1\n"
_BREAKS_B = "def value():\n    return 999\n"


@pytest.fixture(autouse=True)
def _sandbox(monkeypatch):
    """Docker is present and the image is pulled; the suite itself is faked per-test."""
    monkeypatch.setattr(validate, "_docker_available", lambda: True)
    monkeypatch.setattr(validate, "_image_present", lambda image: True)
    validate._BASELINE_CACHE.clear()
    yield
    validate._BASELINE_CACHE.clear()


@pytest.fixture
def repo(tmp_path):
    """A repository with a real test suite, as `_has_test_suite` recognises one."""
    root = tmp_path / "repo"
    (root / "pkg").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "pkg" / "mod.py").write_text(_CLEAN, encoding="utf-8")
    (root / "tests" / "test_mod.py").write_text("# suite\n", encoding="utf-8")
    return root


def _fake_runner(calls: list[str], *, always_red: str | None = None):
    """A suite that reads the tree it was given and reports per-test outcomes.

    `test_a` always passes. `test_b` passes only while `pkg/mod.py` is unmodified. `always_red`
    names a node id that fails no matter what — the permanently-broken test that a real offline
    sandbox always has, and that used to make the whole stage `skipped`.
    """

    def run(work, image, shell_cmd, timeout_s):
        source = (work / _MODULE).read_text(encoding="utf-8")
        calls.append(source)
        outcomes = {
            "tests/test_mod.py::test_a": "passed",
            "tests/test_mod.py::test_b": "passed" if source == _CLEAN else "failed",
        }
        if always_red:
            outcomes[always_red] = "failed"
        (work / validate._REPORT_NAME).write_text(
            json.dumps({"tests": [{"nodeid": n, "outcome": o} for n, o in outcomes.items()]}),
            encoding="utf-8",
        )
        code = 0 if all(o == "passed" for o in outcomes.values()) else 1
        return code, "fake suite output"

    return run


# ── the offline mandate ───────────────────────────────────────────────────────────────────────


def test_a_missing_image_is_declined_not_pulled(repo, monkeypatch) -> None:
    """`_stage_compiles` has always guarded this; `_stage_tests` did not, so `docker run` could
    fetch an image — from a tool whose stated promise is that your code never leaves the machine."""
    monkeypatch.setattr(validate, "_image_present", lambda image: False)
    monkeypatch.setattr(
        validate, "_docker_run", lambda *a, **k: pytest.fail("must not run without the image")
    )

    result = validate._stage_tests(_CLEAN, repo, _MODULE, image="qubit-eval/absent:1")

    assert result.status == "skipped"
    assert "not pulled" in result.detail
    assert "qubit-eval/absent:1" in result.detail


# ── the verdict is a per-test difference ──────────────────────────────────────────────────────


def test_a_patch_that_breaks_a_passing_test_fails_and_names_it(repo, monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(validate, "_docker_run", _fake_runner(calls))

    result = validate._stage_tests(_BREAKS_B, repo, _MODULE, original_source=_CLEAN)

    assert result.status == "fail"
    assert "tests/test_mod.py::test_b" in result.detail
    assert "passed before this patch" in result.detail


def test_a_patch_that_breaks_nothing_passes(repo, monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(validate, "_docker_run", _fake_runner(calls))

    result = validate._stage_tests(_CLEAN, repo, _MODULE, original_source=_CLEAN)

    assert result.status == "pass"
    assert "still pass" in result.detail


def test_a_test_that_was_already_red_is_not_blamed_on_the_patch(repo, monkeypatch) -> None:
    """The change that matters most on a real repository.

    A suite in an offline sandbox almost always has a few tests that cannot run — they need DNS, a
    database, a clock. Under the old exit-code comparison ONE of those made the entire stage
    `skipped`, discarding the evidence from every other test. A set difference simply ignores them:
    they did not pass before the patch, so they cannot have been broken by it.
    """
    calls: list[str] = []
    monkeypatch.setattr(
        validate, "_docker_run", _fake_runner(calls, always_red="tests/test_net.py::test_dns")
    )

    result = validate._stage_tests(_CLEAN, repo, _MODULE, original_source=_CLEAN)

    assert result.status == "pass", result.detail
    assert "test_dns" not in result.detail


def test_a_suite_with_nothing_passing_declines_to_judge(repo, monkeypatch) -> None:
    """Zero passing tests is not a green light — it is no evidence at all."""

    def run(work, image, shell_cmd, timeout_s):
        (work / validate._REPORT_NAME).write_text(
            json.dumps({"tests": [{"nodeid": "t::a", "outcome": "failed"}]}), encoding="utf-8"
        )
        return 1, "all red"

    monkeypatch.setattr(validate, "_docker_run", run)

    result = validate._stage_tests(_CLEAN, repo, _MODULE, original_source=_CLEAN)

    assert result.status == "skipped"
    assert "cannot say anything" in result.detail


# ── the baseline is computed once, not once per patch ─────────────────────────────────────────


def test_the_baseline_is_cached_across_patches(repo, monkeypatch) -> None:
    """It is byte-identical for every patch in a run. Re-deriving it per patch doubled the most
    expensive operation in the pipeline to re-learn the same fact — at 150 findings across 5
    experiment arms, 750 suite runs of pure waste."""
    calls: list[str] = []
    monkeypatch.setattr(validate, "_docker_run", _fake_runner(calls))

    validate._stage_tests(_CLEAN, repo, _MODULE, original_source=_CLEAN)
    validate._stage_tests(_CLEAN, repo, _MODULE, original_source=_CLEAN)

    # One baseline + one run per patch. Without the cache this is four.
    assert len(calls) == 3, calls
    assert len(validate._BASELINE_CACHE) == 1


# ── a timeout is not automatically the patch's fault ──────────────────────────────────────────


def test_a_suite_too_slow_even_untouched_says_nothing_about_the_patch(repo, monkeypatch) -> None:
    """A timeout used to be scored `fail`, which called a slow-but-green suite a broken patch."""
    import subprocess

    def always_times_out(work, image, shell_cmd, timeout_s):
        raise subprocess.TimeoutExpired(cmd="docker", timeout=timeout_s)

    monkeypatch.setattr(validate, "_docker_run", always_times_out)

    result = validate._stage_tests(_CLEAN, repo, _MODULE, original_source=_CLEAN, timeout_s=5.0)

    assert result.status == "skipped"
    assert "neither did the untouched tree" in result.detail


# ── configuration reaches the stage ───────────────────────────────────────────────────────────


def test_the_configured_image_and_command_reach_the_stage(repo, monkeypatch) -> None:
    seen: dict = {}

    def capture(*args, **kwargs):
        seen.update(kwargs)
        return validate.StageResult("skipped", "captured")

    monkeypatch.setattr(validate, "_stage_tests", capture)

    validate.validate_patch(
        diff_text="",
        patched_source=_CLEAN,
        repo_root=repo,
        language="python",
        target_rel_path=_MODULE,
        test_sandbox_image="qubit-eval/scrapy:abc123",
        test_command="python -m pytest tests -q",
        test_timeout_s=900.0,
    )

    assert seen["image"] == "qubit-eval/scrapy:abc123"
    assert seen["command"] == "python -m pytest tests -q"
    assert seen["timeout_s"] == 900.0


def test_the_defaults_keep_todays_behaviour() -> None:
    """An unconfigured install must be honest about being unable to judge rather than wrong about
    it: a bare interpreter and bare pytest, with no repository-specific assumptions baked in.

    The timeout is the one default that has moved, and it moved on measurement. At 300s wagtail's
    Django suite (~320s per run on this machine) timed out on BOTH the baseline and the patched
    run, so a repository whose oracle controls pass produced no verdict at all -- purely because the
    clock was set too tight. The ceiling is reached only when a suite is already useless, and the
    container is killed by name at the limit either way.
    """
    config = MigrateConfig()

    assert config.test_sandbox_image == validate._SANDBOX_IMAGE == "python:3.12-slim"
    assert config.test_command == "python -m pytest -q --continue-on-collection-errors"
    assert config.test_timeout_s == 900.0
