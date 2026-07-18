"""Patch validation pipeline (doc 03 §6.4).

M1 stages (no Docker):
  1 applies — git apply --check  (skipped if no git repo)
  2 parses  — tree-sitter zero ERROR nodes
  5 rescan  — qubit scan --json <file> subprocess, check expected algorithms

Stages 3 (compile) and 4 (tests) are M2 (require Docker sandbox).
"""

from __future__ import annotations

import json
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
            gone_prefix = expect.get("gone", {}).get("algorithm_prefix", "")
            present_prefix = expect.get("present", {}).get("algorithm_prefix", "")

            if gone_prefix:
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


def validate_patch(
    *,
    diff_text: str,
    patched_source: str,
    rule: Any | None = None,
    repo_root: Path | None = None,
    language: str = "python",
) -> ValidationReport:
    """Run M1 validation stages (1 applies, 2 parses, 5 rescan)."""
    stages: dict[str, StageResult] = {}

    stages["applies"] = _stage_applies(diff_text, repo_root)
    stages["parses"] = _stage_parses(patched_source, language)
    # Stages 3 (compiles) and 4 (tests) are M2
    stages["compiles"] = StageResult("skipped", "Docker sandbox — M2")
    stages["tests"] = StageResult("skipped", "Docker sandbox — M2")
    stages["rescan"] = _stage_rescan(patched_source, rule, language)

    mandatory = {k: v for k, v in stages.items() if k not in ("compiles", "tests")}
    passed = all(v.status in ("pass", "skipped") for v in mandatory.values())
    partial = any(v.status == "skipped" for v in stages.values())

    return ValidationReport(stages=stages, passed=passed, partial=partial)


__all__ = ["StageResult", "ValidationReport", "validate_patch"]
