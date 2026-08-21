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


# ── The compile stage beyond Python ──────────────────────────────────────────
#
# It reported `skipped: compile sandbox is python-only` for every other language, so the strongest
# check available — the language's OWN parser, which knows that version's grammar — never ran on a
# patch in any of the eighteen other languages QUBIT can migrate.
#
# Only languages whose toolchain can check a single file with no project, no manifest and no network
# are here. Rust, Swift, Kotlin, Scala, C# and Dart need a resolved dependency graph before they can
# say anything about one file.

_MULTI_LANG_CASES = [
    ("php", "<?php\nfunction f($x) { return hash('sha256', $x); }\n", "<?php\nfunction f( { }\n"),
    (
        "ruby",
        "require 'digest'\ndef f(x) = Digest::SHA256.hexdigest(x)\n",
        "def f(x\n",
    ),
    (
        "javascript",
        "const c = require('crypto');\nc.createHash('sha256');\n",
        "function ( {\n",
    ),
    ("bash", '#!/usr/bin/env bash\nsha256sum "$1"\n', "if [ -z ; then\n"),
]


@needs_docker
@pytest.mark.parametrize(
    ("language", "good", "bad"), _MULTI_LANG_CASES, ids=[c[0] for c in _MULTI_LANG_CASES]
)
def test_compile_stage_runs_the_real_toolchain_per_language(
    language: str, good: str, bad: str
) -> None:
    """Both directions, because a stage that cannot fail is not a check.

    Skips — rather than fails — when the image is not pulled: QUBIT is offline by mandate and never
    downloads one itself, so a machine that has not pulled it legitimately cannot run this.
    """
    from qubit_migrate.transform.validate import _COMPILE_SANDBOX, _image_present

    image = _COMPILE_SANDBOX[language][0]
    if not _image_present(image):
        pytest.skip(f"sandbox image {image} not pulled — run: docker pull {image}")

    ok = _stage_compiles(good, language)
    assert ok.status == "pass", f"valid {language} rejected: {ok.detail}"

    broken = _stage_compiles(bad, language)
    assert broken.status == "fail", f"broken {language} accepted: {broken.detail}"
    assert broken.detail.strip(), "a failure with no toolchain output is not actionable"


@needs_docker
def test_compile_stage_never_pulls_an_image() -> None:
    """The offline mandate, enforced.

    `docker run` fetches a missing image silently. From a tool whose stated promise is that your
    code never leaves the machine, that is a network call nobody asked for — so the stage checks the
    image is present first and skips with the exact `docker pull` command when it is not.
    """
    from qubit_migrate.transform.validate import _stage_compiles

    result = _stage_compiles("x = 1\n", "python")
    assert result.status in ("pass", "skipped")

    # A language mapped to an image that cannot exist must skip, not attempt a pull.
    from qubit_migrate.transform import validate as validate_module

    original = dict(validate_module._COMPILE_SANDBOX)
    try:
        validate_module._COMPILE_SANDBOX["python"] = (
            "qubit-nonexistent-image:does-not-exist",
            "patched.py",
            ["python", "-c", "1"],
        )
        skipped = _stage_compiles("x = 1\n", "python")
    finally:
        validate_module._COMPILE_SANDBOX.clear()
        validate_module._COMPILE_SANDBOX.update(original)

    assert skipped.status == "skipped"
    assert "docker pull" in skipped.detail


@needs_docker
def test_languages_without_a_single_file_check_skip_with_a_reason() -> None:
    """A language that genuinely needs a project says so, rather than reporting a python-only
    message that is about the sandbox rather than about the language."""
    for language in ("rust", "swift", "kotlin", "csharp", "dart", "scala"):
        result = _stage_compiles("fn main() {}\n", language)
        assert result.status == "skipped"
        assert "project" in result.detail, result.detail
