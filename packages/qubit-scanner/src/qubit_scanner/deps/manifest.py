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
    ecosystem: str  # "go" | "npm" | "pypi" | "maven"


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
