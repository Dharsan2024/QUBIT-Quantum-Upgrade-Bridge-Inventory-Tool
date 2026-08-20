"""Per-ecosystem dependency-manifest parsers. Pure functions: text/bytes in, ``Dependency`` list
out — no filesystem access here (``deps/scanner.py`` owns reading the file), so these are easy to
unit-test with inline fixtures.

Approach mirrors csnp/cryptodeps's `internal/manifest/*.go` (Apache-2.0) — see
docs/design/07-ecosystem-factcheck.md §11 — reimplemented natively against QUBIT's own
``Dependency`` shape, stdlib-only (``json``/``tomllib``/``xml.etree``), no new dependencies.
"""

from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass

_VERSION_SPEC_RE = re.compile(r"[=<>!~]")
_NPM_RANGE_PREFIX_RE = re.compile(r"^[\^~>=<\s]+")


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str | None
    # Package-registry identity, which is NOT the same as the language: a Kotlin project and a
    # Java project both resolve from Maven, and a Scala one does too via sbt.
    ecosystem: str  # go | npm | pypi | maven | cargo | packagist | rubygems | nuget | pub | swiftpm


def parse_go_mod(content: str) -> list[Dependency]:
    deps: list[Dependency] = []
    in_require_block = False
    for raw_line in content.splitlines():
        line = raw_line.split("//", 1)[0].strip()  # drop "// indirect" etc.
        if not line:
            continue
        if line.startswith("require") and line.endswith("("):
            in_require_block = True
            continue
        if in_require_block and line == ")":
            in_require_block = False
            continue

        if in_require_block:
            parts = line.split()
        elif line.startswith("require "):
            parts = line[len("require ") :].split()
        else:
            continue

        if len(parts) >= 2:
            deps.append(Dependency(name=parts[0], version=parts[1], ecosystem="go"))
    return deps


def parse_package_json(content: str) -> list[Dependency]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []

    deps: list[Dependency] = []
    seen: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        for name, version_range in sorted(block.items()):
            if name in seen:
                continue
            seen.add(name)
            version = _NPM_RANGE_PREFIX_RE.sub("", str(version_range)).strip() or None
            deps.append(Dependency(name=name, version=version, ecosystem="npm"))
    return deps


def parse_requirements_txt(content: str) -> list[Dependency]:
    deps: list[Dependency] = []
    for raw_line in content.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith(("-r ", "-e ", "--", "-c ")):
            continue
        line = line.split(";", 1)[0].strip()  # drop environment markers
        m = _VERSION_SPEC_RE.search(line)
        name = (line[: m.start()] if m else line).strip()
        version = line[m.start() :].strip() if m else None
        name = name.split("[", 1)[0].strip()  # drop extras: "requests[security]"
        if name:
            deps.append(Dependency(name=name.lower(), version=version, ecosystem="pypi"))
    return deps


def parse_pyproject_toml(content: str) -> list[Dependency]:
    """PEP 621 ``[project.dependencies]`` only (a list of requirement strings) — Poetry's
    ``[tool.poetry.dependencies]`` table has a different shape and isn't handled here."""
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return []

    raw_deps = data.get("project", {}).get("dependencies", [])
    deps: list[Dependency] = []
    for entry in raw_deps:
        if not isinstance(entry, str):
            continue
        line = entry.split(";", 1)[0].strip()
        m = _VERSION_SPEC_RE.search(line)
        name = (line[: m.start()] if m else line).strip()
        version = line[m.start() :].strip() if m else None
        name = name.split("[", 1)[0].strip()
        if name:
            deps.append(Dependency(name=name.lower(), version=version, ecosystem="pypi"))
    return deps


def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse_pom_xml(content: str) -> list[Dependency]:
    try:
        root = ET.fromstring(content)  # noqa: S314 - manifest files, not untrusted network input
    except ET.ParseError:
        return []

    deps: list[Dependency] = []
    for dep_el in root.iter():
        if _strip_ns(dep_el.tag) != "dependency":
            continue
        fields: dict[str, str] = {}
        for child in dep_el:
            fields[_strip_ns(child.tag)] = (child.text or "").strip()
        group_id = fields.get("groupId")
        artifact_id = fields.get("artifactId")
        if not group_id or not artifact_id:
            continue
        name = f"{group_id}:{artifact_id}"
        deps.append(Dependency(name=name, version=fields.get("version") or None, ecosystem="maven"))
    return deps


__all__ = [
    "Dependency",
    "parse_go_mod",
    "parse_package_json",
    "parse_pom_xml",
    "parse_pyproject_toml",
    "parse_requirements_txt",
]


# ── Ecosystems added alongside the Rust/PHP/Ruby/.NET/Dart/Swift rule packs ──────────────────────
#
# A manifest finding says a crypto library is AVAILABLE, not that it is used — the scanner records
# them at `confidence="medium"` for exactly that reason. They still matter: a `Gemfile` pinning an
# old `jwt` gem is evidence for a service whose Ruby the code scanner may never reach, and a
# `.csproj` referencing BouncyCastle is the only trace of crypto in a project that wraps it.


def parse_cargo_toml(content: str) -> list[Dependency]:
    """Rust `Cargo.toml` — `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`."""
    try:
        data = tomllib.loads(content)
    except tomllib.TOMLDecodeError:
        return []
    deps: list[Dependency] = []
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in (data.get(table) or {}).items():
            # A dependency is either `name = "1.2"` or `name = { version = "1.2", ... }`.
            version = spec if isinstance(spec, str) else (spec or {}).get("version")
            deps.append(
                Dependency(
                    name=name.lower(),
                    version=version if isinstance(version, str) else None,
                    ecosystem="cargo",
                )
            )
    return deps


def parse_composer_json(content: str) -> list[Dependency]:
    """PHP `composer.json` — `require` and `require-dev`."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    deps: list[Dependency] = []
    for section in ("require", "require-dev"):
        for name, version in (data.get(section) or {}).items():
            # `php` and `ext-*` are the runtime and its extensions, not packages. `ext-openssl` is
            # genuinely interesting, so it is kept; the bare `php` constraint is not a dependency.
            if name == "php":
                continue
            deps.append(
                Dependency(
                    name=name.lower(),
                    version=_NPM_RANGE_PREFIX_RE.sub("", str(version)) or None,
                    ecosystem="packagist",
                )
            )
    return deps


_GEMFILE_GEM_RE = re.compile(
    r"""^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""", re.MULTILINE
)


def parse_gemfile(content: str) -> list[Dependency]:
    """Ruby `Gemfile` / `*.gemspec` — `gem "name", "~> 1.2"`.

    Line-oriented rather than evaluated: a Gemfile is executable Ruby, and running it to find out
    what it declares is not something a scanner should ever do.
    """
    deps: list[Dependency] = []
    for name, version in _GEMFILE_GEM_RE.findall(content):
        deps.append(
            Dependency(
                name=name.lower(),
                version=_NPM_RANGE_PREFIX_RE.sub("", version) or None if version else None,
                ecosystem="rubygems",
            )
        )
    return deps


def parse_csproj(content: str) -> list[Dependency]:
    """.NET `*.csproj` / `Directory.Packages.props` — `<PackageReference Include= Version=/>`."""
    try:
        # Project files are local build inputs, not untrusted network data.
        root = ET.fromstring(content)  # noqa: S314
    except ET.ParseError:
        return []
    deps: list[Dependency] = []
    for node in root.iter():
        if not node.tag.endswith("PackageReference"):
            continue
        name = node.get("Include") or node.get("Update")
        if not name:
            continue
        version = node.get("Version")
        if version is None:
            # NuGet also allows `<Version>` as a child element.
            for child in node:
                if child.tag.endswith("Version"):
                    version = (child.text or "").strip() or None
        deps.append(Dependency(name=name.lower(), version=version, ecosystem="nuget"))
    return deps


_GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)"""
    r"""[\s(]+['"]([^'"\s:]+):([^'"\s:]+)(?::([^'"\s]+))?['"]""",
)


def parse_build_gradle(content: str) -> list[Dependency]:
    """Kotlin/Java `build.gradle` and `build.gradle.kts` — Maven coordinates in a Groovy/Kotlin DSL.

    Reported as `maven`, because that is the registry the coordinate resolves from; Gradle is the
    build tool, not the ecosystem.
    """
    deps: list[Dependency] = []
    for group, artifact, version in _GRADLE_DEP_RE.findall(content):
        deps.append(
            Dependency(name=f"{group}:{artifact}", version=version or None, ecosystem="maven")
        )
    return deps


_SBT_DEP_RE = re.compile(
    r"""['"]([^'"\s]+)['"]\s*%%?\s*['"]([^'"\s]+)['"]\s*%\s*['"]([^'"\s]+)['"]"""
)


def parse_build_sbt(content: str) -> list[Dependency]:
    """Scala `build.sbt` — `"org.bouncycastle" % "bcprov-jdk18on" % "1.78"`."""
    deps: list[Dependency] = []
    for group, artifact, version in _SBT_DEP_RE.findall(content):
        deps.append(
            Dependency(name=f"{group}:{artifact}", version=version or None, ecosystem="maven")
        )
    return deps


_PUBSPEC_DEP_RE = re.compile(r"^  ([A-Za-z0-9_]+):\s*(?:\^?([0-9][^\s#]*))?\s*$", re.MULTILINE)


def parse_pubspec_yaml(content: str) -> list[Dependency]:
    """Dart/Flutter `pubspec.yaml` — two-space-indented entries under `dependencies:`.

    Parsed structurally by indentation rather than with a YAML loader, to stay consistent with the
    other parsers here (stdlib only, no dependency on the scanner's YAML stack) and because a
    pubspec's dependency entries are a flat, well-known shape.
    """
    deps: list[Dependency] = []
    in_deps = False
    for raw_line in content.splitlines():
        stripped = raw_line.strip()
        if not raw_line.startswith(" ") and stripped.endswith(":"):
            in_deps = stripped[:-1] in ("dependencies", "dev_dependencies")
            continue
        if not in_deps:
            continue
        match = _PUBSPEC_DEP_RE.match(raw_line)
        if match:
            deps.append(
                Dependency(name=match.group(1).lower(), version=match.group(2), ecosystem="pub")
            )
    return deps


_SWIFTPM_DEP_RE = re.compile(
    r"""\.package\s*\(\s*url:\s*['"]([^'"]+)['"]\s*,\s*[^)]*?["']?([0-9][0-9.]*)"""
)


def parse_package_swift(content: str) -> list[Dependency]:
    """Swift `Package.swift` — `.package(url: "https://github.com/apple/swift-crypto", ...)`.

    The package NAME is the last path component of the repository URL, which is how SwiftPM itself
    identifies a package by default.
    """
    deps: list[Dependency] = []
    for url, version in _SWIFTPM_DEP_RE.findall(content):
        name = url.rstrip("/").rsplit("/", 1)[-1]
        if name.endswith(".git"):
            name = name[: -len(".git")]
        deps.append(Dependency(name=name.lower(), version=version or None, ecosystem="swiftpm"))
    return deps
