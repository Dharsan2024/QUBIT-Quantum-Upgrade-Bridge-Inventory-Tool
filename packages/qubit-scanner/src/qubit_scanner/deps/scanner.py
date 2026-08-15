"""Dependency/SCA manifest scanner: declares a manifest file's crypto-relevant dependencies as
``library``-typed findings. Deliberately manifest-level, not call-site-level — a package appearing
in ``requirements.txt`` means it's *available*, not necessarily *used*; ``confidence="medium"``
reflects that (cryptodeps' analogous CONFIRMED/REACHABLE/AVAILABLE distinction, doc 01 §4.4's
JWT rule packs' AST-level detections, are the higher-confidence call-site-confirmed complement).

Packages absent from the curated database are silently skipped — most manifest entries are not
crypto-relevant (a JSON parser, a web framework), and forcing a placeholder finding for every one
of them would be noise, not signal (unlike a specific line of *detected* crypto usage, where
doc 01's "nothing silently dropped" contract applies).
"""

from __future__ import annotations

from pathlib import Path

from qubit_core import Location

from qubit_scanner.models import Detection

from . import database
from .manifest import (
    Dependency,
    parse_go_mod,
    parse_package_json,
    parse_pom_xml,
    parse_pyproject_toml,
    parse_requirements_txt,
)

_PARSERS = {
    "go.mod": parse_go_mod,
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "pom.xml": parse_pom_xml,
}

_RULE_ID = {
    "go": "DEP-GO-001",
    "npm": "DEP-NPM-001",
    "pypi": "DEP-PYPI-001",
    "maven": "DEP-MAVEN-001",
}


class ManifestParser:
    """Scans a single dependency-manifest file for crypto-relevant declared dependencies."""

    def parse(self, file_path: Path) -> list[Detection]:
        parse_fn = _PARSERS.get(file_path.name)
        if parse_fn is None:
            return []

        try:
            content = file_path.read_text(encoding="utf-8")
        except OSError:
            return []

        try:
            deps = parse_fn(content)
        except Exception:  # a malformed manifest never aborts the scan
            return []

        detections: list[Detection] = []
        for dep in deps:
            detections.extend(self._detections_for(dep, file_path))
        return detections

    def _detections_for(self, dep: Dependency, file_path: Path) -> list[Detection]:
        algorithms = database.lookup(dep.ecosystem, dep.name)
        if not algorithms:
            return []

        loc = Location(file_path=str(file_path))
        version_note = f" {dep.version}" if dep.version else ""
        return [
            Detection(
                scanner="config",
                rule_id=_RULE_ID[dep.ecosystem],
                raw_algorithm=entry["algorithm"],
                asset_type="library",
                usage_context=entry["usage_context"],
                location=loc,
                library_name=dep.name,
                evidence_snippet=f"{dep.name}{version_note} ({dep.ecosystem} manifest dependency)",
                confidence="medium",
            )
            for entry in algorithms
        ]


__all__ = ["ManifestParser"]
