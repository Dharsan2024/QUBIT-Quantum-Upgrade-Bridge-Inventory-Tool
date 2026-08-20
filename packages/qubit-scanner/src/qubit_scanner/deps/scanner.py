"""Dependency/SCA manifest scanner: declares a manifest file's crypto-relevant dependencies as
``library``-typed findings. Deliberately manifest-level, not call-site-level — a package appearing
in ``requirements.txt`` means it's *available*, not necessarily *used*; ``confidence="medium"``
reflects that (cryptodeps' analogous CONFIRMED/REACHABLE/AVAILABLE distinction, doc 01 §4.4's
JWT rule packs' AST-level detections, are the higher-confidence call-site-confirmed complement).

Packages absent from the curated database are silently skipped — most manifest entries are not
crypto-relevant (a JSON parser, a web framework), and forcing a placeholder finding for every one
of them would be noise, not signal (unlike a specific line of *detected* crypto usage, where
doc 01's "nothing silently dropped" contract applies).

Version-gated algorithms (``min_version`` in the curated map) are reported only when the manifest
version *proves* the capability exists — see :func:`_satisfies_min_version`.
"""

from __future__ import annotations

import re
from pathlib import Path

from packaging.version import InvalidVersion, Version
from qubit_core import Location

from qubit_scanner.models import Detection

from . import database
from .manifest import (
    Dependency,
    parse_build_gradle,
    parse_build_sbt,
    parse_cargo_toml,
    parse_composer_json,
    parse_csproj,
    parse_gemfile,
    parse_go_mod,
    parse_package_json,
    parse_package_swift,
    parse_pom_xml,
    parse_pubspec_yaml,
    parse_pyproject_toml,
    parse_requirements_txt,
)

_PARSERS = {
    "go.mod": parse_go_mod,
    "package.json": parse_package_json,
    "requirements.txt": parse_requirements_txt,
    "pyproject.toml": parse_pyproject_toml,
    "pom.xml": parse_pom_xml,
    "cargo.toml": parse_cargo_toml,
    "composer.json": parse_composer_json,
    "gemfile": parse_gemfile,
    "build.gradle": parse_build_gradle,
    "build.gradle.kts": parse_build_gradle,
    "build.sbt": parse_build_sbt,
    "pubspec.yaml": parse_pubspec_yaml,
    "package.swift": parse_package_swift,
    "directory.packages.props": parse_csproj,
}

# Manifests identified by suffix rather than exact name: a .NET project file is named after its
# project (`PaymentGateway.csproj`), so there is no fixed filename to match.
_SUFFIX_PARSERS = {
    ".csproj": parse_csproj,
    ".vbproj": parse_csproj,
    ".fsproj": parse_csproj,
    ".gemspec": parse_gemfile,
}

_RULE_ID = {
    "go": "DEP-GO-001",
    "npm": "DEP-NPM-001",
    "pypi": "DEP-PYPI-001",
    "maven": "DEP-MAVEN-001",
    "cargo": "DEP-CARGO-001",
    "packagist": "DEP-PACKAGIST-001",
    "rubygems": "DEP-RUBYGEMS-001",
    "nuget": "DEP-NUGET-001",
    "pub": "DEP-PUB-001",
    "swiftpm": "DEP-SWIFTPM-001",
}

# Leading numeric-ish version core, after stripping specifier operators and a Go "v" prefix.
# ">=41.0" -> "41.0"; "==42.0.8" -> "42.0.8"; "v5.2.1" -> "5.2.1"; "1.79" -> "1.79".
_VERSION_CORE_RE = re.compile(r"(\d+(?:\.\d+)*)")


def _satisfies_min_version(dep_version: str | None, min_version: str) -> bool:
    """True only when ``dep_version`` PROVES the dependency is at least ``min_version``.

    Conservative by design: an absent, unparseable, or open-ended-below version returns False. A
    range like ``>=41.0`` is judged on its floor (41.0), because that is the weakest version the
    manifest actually permits — claiming a capability the resolved install might not have would
    make a vulnerable dependency look quantum-ready.
    """
    if not dep_version:
        return False
    m = _VERSION_CORE_RE.search(dep_version)
    if m is None:
        return False
    try:
        return Version(m.group(1)) >= Version(min_version)
    except InvalidVersion:
        return False


class ManifestParser:
    """Scans a single dependency-manifest file for crypto-relevant declared dependencies."""

    def parse(self, file_path: Path) -> list[Detection]:
        # Case-insensitive: the real files are `Gemfile`, `Cargo.toml`, `Package.swift`, and a
        # case-sensitive lookup against lowercase keys would have matched none of them.
        parse_fn = _PARSERS.get(file_path.name.lower()) or _SUFFIX_PARSERS.get(
            file_path.suffix.lower()
        )
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
            # A version-gated capability is claimed only when the manifest proves it exists.
            if "min_version" not in entry
            or _satisfies_min_version(dep.version, entry["min_version"])
        ]


__all__ = ["ManifestParser"]
