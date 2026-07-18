"""Docker sandbox validation stages 3-4 (doc 03 §6.5). Real-container tests are
skipped automatically when the Docker daemon is not available so the suite stays portable.
"""

from __future__ import annotations

import pytest
from qubit_migrate.transform.validate import (
    _docker_available,
    _stage_compiles,
    _stage_tests,
    validate_patch,
)

needs_docker = pytest.mark.skipif(not _docker_available(), reason="docker daemon unavailable")


@needs_docker
def test_compiles_stage_passes_for_valid_python() -> None:
    r = _stage_compiles("import hashlib\ndigest = hashlib.sha256(b'x')\n")
    assert r.status == "pass", r.detail


@needs_docker
def test_compiles_stage_fails_for_broken_python() -> None:
    r = _stage_compiles("def broken(:\n    pass\n")
    assert r.status == "fail"
    assert "SyntaxError" in r.detail


def test_compiles_stage_skips_non_python() -> None:
    assert _stage_compiles("class A {}", language="java").status == "skipped"


def test_tests_stage_skips_without_repo() -> None:
    r = _stage_tests("x = 1\n", repo_root=None, target_rel_path=None)
    assert r.status == "skipped"


@needs_docker
def test_tests_stage_runs_unittest_suite(tmp_path) -> None:
    # repo with a unittest-style suite exercising the patched module
    (tmp_path / "mymod.py").write_text("def double(x):\n    return x * 2\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_mymod.py").write_text(
        "import sys, unittest\n"
        "sys.path.insert(0, '/work')\n"
        "from mymod import double\n\n"
        "class T(unittest.TestCase):\n"
        "    def test_double(self):\n"
        "        self.assertEqual(double(3), 6)\n",
        encoding="utf-8",
    )
    patched = "def double(x):\n    return x + x\n"  # behavior-equivalent patch
    r = _stage_tests(patched, repo_root=tmp_path, target_rel_path="mymod.py")
    assert r.status == "pass", r.detail


@needs_docker
def test_tests_stage_fails_on_regression(tmp_path) -> None:
    (tmp_path / "mymod.py").write_text("def double(x):\n    return x * 2\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_mymod.py").write_text(
        "import sys, unittest\n"
        "sys.path.insert(0, '/work')\n"
        "from mymod import double\n\n"
        "class T(unittest.TestCase):\n"
        "    def test_double(self):\n"
        "        self.assertEqual(double(3), 6)\n",
        encoding="utf-8",
    )
    broken = "def double(x):\n    return x\n"  # regression the sandbox must catch
    r = _stage_tests(broken, repo_root=tmp_path, target_rel_path="mymod.py")
    assert r.status == "fail"


def test_no_docker_config_skips_sandbox() -> None:
    report = validate_patch(
        diff_text="--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n",
        patched_source="x = 1\n",
        no_docker=True,
    )
    assert report.stages["compiles"].status == "skipped"
    assert report.stages["tests"].status == "skipped"
