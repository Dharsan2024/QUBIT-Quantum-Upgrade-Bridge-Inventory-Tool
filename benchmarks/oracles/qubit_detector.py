"""QUBIT as one detector among several — deliberately given no special status.

This adapter exists so the comparison harness cannot tell which tool is under test. The population
estimator in `population.py` takes a mapping of detector name to site set; if QUBIT were passed in
through a different type or a different code path, every future change to the comparison would carry
a quiet temptation to treat "QUBIT found it" as ground truth. It is not ground truth. It is the
thing being measured.

The scan goes through the public CLI rather than by importing `qubit_scanner`, for the same reason
the migration side calls the scanner over a CLI boundary: it is the entry point a user actually
runs, so a benchmark that used a private API could report recall for code paths no user reaches.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from base import Finding

REPO_ROOT = Path(__file__).resolve().parents[2]


class QubitDetector:
    """Runs `qubit scan --json` over a tree."""

    name = "qubit"
    provenance = "this repository, working tree"

    def __init__(self, timeout: int = 3600) -> None:
        self.timeout = timeout

    def available(self) -> tuple[bool, str]:
        return True, "ok"

    def scan(self, root: Path) -> list[Finding]:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "qubit_cli.main", "scan", str(root), "--json"],
            capture_output=True,
            timeout=self.timeout,
            cwd=str(REPO_ROOT),
            check=False,
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        start = stdout.find("{")
        if start == -1:
            return []
        try:
            payload = json.loads(stdout[start:])
        except json.JSONDecodeError:
            return []

        resolved_root = root.resolve()
        findings: list[Finding] = []
        for asset in payload.get("assets", []):
            location = asset.get("location") or {}
            file_path = location.get("file_path")
            line = location.get("line")
            algorithm = asset.get("algorithm")
            if not file_path or not line or not algorithm:
                continue
            try:
                rel = Path(file_path).resolve().relative_to(resolved_root).as_posix()
            except ValueError:
                rel = Path(file_path).as_posix()
            findings.append(
                Finding(
                    detector=self.name,
                    path=rel,
                    line=int(line),
                    algorithm=str(algorithm),
                    rule_id=str(asset.get("rule_id") or ""),
                )
            )
        return findings


__all__ = ["QubitDetector"]
