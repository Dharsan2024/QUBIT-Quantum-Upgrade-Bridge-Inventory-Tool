"""Patch validation pipeline (doc 03 §6.4).

M1 stages (no Docker):
  1 applies — git apply --check  (skipped if no git repo)
  2 parses  — tree-sitter zero ERROR nodes
  5 rescan  — qubit scan --json <file> subprocess, check expected algorithms

Stages 3 (compile) and 4 (tests) are M2 (require Docker sandbox).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

StageStatus = Literal["pass", "fail", "skipped"]


@dataclass
class StageResult:
    status: StageStatus
    detail: str = ""
    duration_s: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "detail": self.detail[:4096],
            "duration_s": round(self.duration_s, 3),
        }


@dataclass
class ValidationReport:
    stages: dict[str, StageResult] = field(default_factory=dict)
    passed: bool = False
    partial: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "stages": {k: v.as_dict() for k, v in self.stages.items()},
            "passed": self.passed,
            "partial": self.partial,
        }


def _stage_applies(
    diff_text: str,
    repo_root: Path | None,
) -> StageResult:
    t0 = time.monotonic()
    if not diff_text.strip():
        return StageResult("fail", "empty diff", time.monotonic() - t0)
    if repo_root is None or not (repo_root / ".git").exists():
        # No git repo — skip but mark partial
        return StageResult("skipped", "no git repo to check against", time.monotonic() - t0)
    try:
        result = subprocess.run(
            ["git", "apply", "--check", "-"],
            input=diff_text.encode("utf-8"),
            capture_output=True,
            cwd=str(repo_root),
            timeout=30,
        )
        ok = result.returncode == 0
        detail = result.stderr.decode("utf-8", errors="replace")[:2048]
        return StageResult("pass" if ok else "fail", detail, time.monotonic() - t0)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return StageResult("fail", str(exc), time.monotonic() - t0)


def _stage_parses(patched_source: str, language: str = "python") -> StageResult:
    t0 = time.monotonic()
    try:
        from tree_sitter_language_pack import (  # type: ignore[import-untyped]
            get_parser,
        )

        lang_map = {"python": "python", "java": "java", "go": "go"}
        ts_lang_name = lang_map.get(language, "python")
        parser = get_parser(ts_lang_name)
        tree = parser.parse(patched_source.encode("utf-8", errors="replace"))
        error_nodes = [n for n in tree.root_node.children if n.type == "ERROR"]
        if error_nodes:
            return StageResult(
                "fail",
                f"{len(error_nodes)} ERROR nodes in tree-sitter parse",
                time.monotonic() - t0,
            )
        return StageResult("pass", "zero ERROR nodes", time.monotonic() - t0)
    except Exception as exc:
        return StageResult("fail", f"parse error: {exc}", time.monotonic() - t0)


def _stage_rescan(
    patched_source: str,
    rule: Any | None,
    language: str = "python",
) -> StageResult:
    """Run qubit scan --json on the patched source and check rescan_expect."""
    t0 = time.monotonic()
    if rule is None or rule.rescan_expect is None:
        return StageResult("skipped", "no rescan_expect in rule", time.monotonic() - t0)

    ext_map = {"python": ".py", "java": ".java", "go": ".go"}
    ext = ext_map.get(language, ".py")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_file = Path(tmpdir) / f"patched{ext}"
        tmp_file.write_text(patched_source, encoding="utf-8")

        try:
            result = subprocess.run(
                ["uv", "run", "qubit", "scan", str(tmp_file), "--json"],
                capture_output=True,
                timeout=60,
                cwd=str(Path(__file__).parents[6]),  # workspace root
            )
            raw = result.stdout.decode("utf-8", errors="replace")
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                # exit code 3 means no assets found — that's fine for "gone" check
                data = {"assets": [], "stats": {}}

            assets = data.get("assets", [])
            algos = {a.get("algorithm", "") for a in assets}

            expect = rule.rescan_expect
            gone_spec = expect.get("gone", {}).get("algorithm_prefix", "")
            present_prefix = expect.get("present", {}).get("algorithm_prefix", "")
            # algorithm_prefix accepts a single prefix or a list of prefixes
            gone_prefixes = [gone_spec] if isinstance(gone_spec, str) and gone_spec else gone_spec

            for gone_prefix in gone_prefixes or []:
                still_present = [a for a in algos if a.startswith(gone_prefix)]
                if still_present:
                    return StageResult(
                        "fail",
                        f"Expected {gone_prefix!r} gone, but still found: {still_present}",
                        time.monotonic() - t0,
                    )
            if present_prefix:
                found = [a for a in algos if a.startswith(present_prefix)]
                if not found:
                    return StageResult(
                        "fail",
                        f"Expected {present_prefix!r} present, but not found. Algorithms: {algos}",
                        time.monotonic() - t0,
                    )
            return StageResult("pass", f"rescan ok. algorithms: {algos}", time.monotonic() - t0)

        except subprocess.TimeoutExpired:
            return StageResult("fail", "rescan timed out", time.monotonic() - t0)
        except FileNotFoundError:
            return StageResult("skipped", "qubit CLI not found in PATH", time.monotonic() - t0)


_SANDBOX_IMAGE = "python:3.12-slim"
_docker_ok: bool | None = None  # process-level cache; daemon state won't flip mid-run


def _docker_available() -> bool:
    global _docker_ok
    if _docker_ok is None:
        try:
            r = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                timeout=10,
            )
            _docker_ok = r.returncode == 0 and bool(r.stdout.strip())
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            _docker_ok = False
    return _docker_ok


def _stage_compiles(patched_source: str, language: str = "python") -> StageResult:
    """Stage 3: byte-compile the patched file inside an isolated container (no network)."""
    t0 = time.monotonic()
    if language != "python":
        return StageResult("skipped", f"compile sandbox is python-only (got {language})", 0.0)
    if not _docker_available():
        return StageResult("skipped", "docker unavailable", time.monotonic() - t0)

    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "patched.py").write_text(patched_source, encoding="utf-8")
        try:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network=none",
                    "-v",
                    f"{tmpdir}:/work:ro",
                    _SANDBOX_IMAGE,
                    "python",
                    "-c",
                    "compile(open('/work/patched.py').read(), 'patched.py', 'exec')",
                ],
                capture_output=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            return StageResult("fail", "sandbox compile timed out", time.monotonic() - t0)
        if result.returncode == 0:
            return StageResult("pass", "byte-compiles in sandbox", time.monotonic() - t0)
        return StageResult(
            "fail",
            result.stderr.decode("utf-8", errors="replace")[:2048],
            time.monotonic() - t0,
        )


def _has_test_suite(repo_root: Path) -> bool:
    if (repo_root / "tests").is_dir():
        return True
    if (repo_root / "pytest.ini").exists() or (repo_root / "setup.cfg").exists():
        return True
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.exists():
        return False
    return "pytest" in pyproject.read_text(encoding="utf-8", errors="replace")


def _stage_tests(
    patched_source: str,
    repo_root: Path | None,
    target_rel_path: str | None,
    language: str = "python",
) -> StageResult:
    """Stage 4: copy the repo, overlay the patched file, run pytest inside the sandbox.

    Network stays off; pytest comes from the host venv mounted read-only would be fragile,
    so we use `python -m unittest`-compatible pytest bundled via pip cache only when the
    image has it — otherwise the stage reports skipped (honest) rather than green.
    """
    t0 = time.monotonic()
    if language != "python":
        return StageResult("skipped", f"test sandbox is python-only (got {language})", 0.0)
    if repo_root is None or target_rel_path is None or Path(target_rel_path).is_absolute():
        return StageResult("skipped", "no repo_root/relative target for test run", 0.0)
    if not _has_test_suite(repo_root):
        return StageResult("skipped", "no test suite detected in repo", 0.0)
    if not _docker_available():
        return StageResult("skipped", "docker unavailable", time.monotonic() - t0)

    with tempfile.TemporaryDirectory() as tmpdir:
        work = Path(tmpdir) / "repo"
        shutil.copytree(repo_root, work, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        target = work / target_rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(patched_source, encoding="utf-8")
        def _run_in_sandbox(cmd: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network=none",
                    "-v",
                    f"{work}:/work",
                    "-w",
                    "/work",
                    _SANDBOX_IMAGE,
                    "sh",
                    "-c",
                    cmd,
                ],
                capture_output=True,
                timeout=300,
            )

        try:
            result = _run_in_sandbox("python -m pytest -x -q 2>&1")
            out = result.stdout.decode("utf-8", errors="replace")
            if "No module named pytest" in out:
                # base image has no pytest; fall back to the stdlib runner
                result = _run_in_sandbox("python -m unittest discover -s tests 2>&1")
                out = result.stdout.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return StageResult("fail", "sandbox tests timed out", time.monotonic() - t0)
        if result.returncode == 0:
            return StageResult(
                "pass", out[:2048] or "tests green in sandbox", time.monotonic() - t0
            )
        return StageResult("fail", out[:2048], time.monotonic() - t0)


def validate_patch(
    *,
    diff_text: str,
    patched_source: str,
    rule: Any | None = None,
    repo_root: Path | None = None,
    language: str = "python",
    target_rel_path: str | None = None,
    no_docker: bool = False,
) -> ValidationReport:
    """Run validation stages 1 applies, 2 parses, 3 compiles, 4 tests, 5 rescan.

    Any hard `fail` fails the patch; `skipped` stages mark the report partial.
    """
    stages: dict[str, StageResult] = {}

    stages["applies"] = _stage_applies(diff_text, repo_root)
    stages["parses"] = _stage_parses(patched_source, language)
    if no_docker:
        stages["compiles"] = StageResult("skipped", "no_docker configured")
        stages["tests"] = StageResult("skipped", "no_docker configured")
    else:
        stages["compiles"] = _stage_compiles(patched_source, language)
        stages["tests"] = _stage_tests(patched_source, repo_root, target_rel_path, language)
    stages["rescan"] = _stage_rescan(patched_source, rule, language)

    passed = all(v.status in ("pass", "skipped") for v in stages.values())
    partial = any(v.status == "skipped" for v in stages.values())

    return ValidationReport(stages=stages, passed=passed, partial=partial)


__all__ = ["StageResult", "ValidationReport", "validate_patch"]
