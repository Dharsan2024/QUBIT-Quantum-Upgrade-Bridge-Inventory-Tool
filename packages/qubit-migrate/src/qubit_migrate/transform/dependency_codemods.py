"""Manifest edits that make post-quantum primitives available to a project.

Split out of `codemods.py` because it grew past the point where the cipher swaps and the manifest
edits belonged in one file, and because every function here answers the same question in a
different syntax: *given this project's manifest, what is the smallest edit that lets it import
ML-KEM or ML-DSA?*

The package names and version floors are NOT written here. They come from
`params/remediation_playbook.yaml` through `playbook.load_playbook()`, which is also what the
guided paths quote. A floor stated twice is a floor that will disagree with itself - this project
has already paid for that once, when a Maven artifact spelled `org.bouncycastle:bcprov-jdk18on` in
the rule and `bcprov-jdk18on` in the version table made `dep-pqc-01` unreachable for every Maven
project on the corpus.

Every function is idempotent: if the dependency is already declared, it reports "no change" rather
than adding a second copy. That is what lets the orchestrator use a codemod probe to detect
"another task already remediated this file".
"""

from __future__ import annotations

import re

from ..playbook import Provider, load_playbook

# --- helpers ----------------------------------------------------------------------------------


def _already_declared(source: str, package: str) -> bool:
    """True when the manifest already names this package, in any of its spellings.

    Maven's `groupId:artifactId` is written as two XML elements, so the joined form never appears
    in a pom; the artifact id is what to look for. npm and Packagist use the full string.
    """
    artifact = package.rsplit(":", 1)[-1]
    return artifact in source


# --- Maven / Gradle / sbt ----------------------------------------------------------------------

_POM_DEPENDENCIES_RE = re.compile(r"([ \t]*)<dependencies>[ \t]*\r?\n")
_GRADLE_DEPENDENCIES_RE = re.compile(r"^([ \t]*)dependencies[ \t]*\{[ \t]*$", re.M)


def add_maven_dependency(source: str, provider: Provider) -> tuple[str, bool]:
    """Insert a `<dependency>` block as the first child of `<dependencies>`."""
    if _already_declared(source, provider.package):
        return source, False
    match = _POM_DEPENDENCIES_RE.search(source)
    if match is None:
        return source, False
    group_id, _, artifact_id = provider.package.rpartition(":")
    if not group_id:
        return source, False
    inner = match.group(1) + "  "
    block = (
        f"{inner}<!-- QUBIT: FIPS 203/204 provider -->\n"
        f"{inner}<dependency>\n"
        f"{inner}  <groupId>{group_id}</groupId>\n"
        f"{inner}  <artifactId>{artifact_id}</artifactId>\n"
        f"{inner}  <version>{provider.constraint}</version>\n"
        f"{inner}</dependency>\n"
    )
    return source[: match.end()] + block + source[match.end() :], True


def add_gradle_dependency(source: str, provider: Provider) -> tuple[str, bool]:
    """Insert an `implementation` line as the first entry of a Gradle `dependencies { }` block.

    Written in the parenthesised form, which is valid in both the Groovy and Kotlin DSLs, so one
    branch covers `build.gradle` and `build.gradle.kts`.
    """
    if _already_declared(source, provider.package):
        return source, False
    match = _GRADLE_DEPENDENCIES_RE.search(source)
    if match is None:
        return source, False
    inner = match.group(1) + "    "
    coordinate = f"{provider.package}:{provider.constraint}"
    line = f'\n{inner}implementation("{coordinate}")  // QUBIT: FIPS 203/204 provider'
    return source[: match.end()] + line + source[match.end() :], True


def add_sbt_dependency(source: str, provider: Provider) -> tuple[str, bool]:
    """Append an sbt `libraryDependencies +=` line.

    Appended rather than inserted into an existing sequence: sbt settings are order-independent
    and `+=` composes with whatever is already there, so appending cannot break an existing build
    the way rewriting a `Seq(...)` literal could.
    """
    if _already_declared(source, provider.package):
        return source, False
    group_id, _, artifact_id = provider.package.rpartition(":")
    if not group_id:
        return source, False
    line = (
        f'libraryDependencies += "{group_id}" % "{artifact_id}" % "{provider.constraint}"'
        "  // QUBIT: FIPS 203/204 provider\n"
    )
    body = source if source.endswith("\n") else source + "\n"
    return body + "\n" + line, True


# --- NuGet -------------------------------------------------------------------------------------

_CSPROJ_ITEMGROUP_RE = re.compile(r"([ \t]*)<ItemGroup>[ \t]*\r?\n")
_CSPROJ_PROJECT_RE = re.compile(r"(<Project\b[^>]*>[ \t]*\r?\n)")


def add_nuget_dependency(source: str, provider: Provider) -> tuple[str, bool]:
    """Insert a `<PackageReference>`, reusing an existing `<ItemGroup>` when there is one."""
    if _already_declared(source, provider.package):
        return source, False
    reference = f'<PackageReference Include="{provider.package}" Version="{provider.constraint}" />'
    match = _CSPROJ_ITEMGROUP_RE.search(source)
    if match is not None:
        inner = match.group(1) + "  "
        return source[: match.end()] + f"{inner}{reference}\n" + source[match.end() :], True
    # No ItemGroup at all - open one directly under <Project>.
    project = _CSPROJ_PROJECT_RE.search(source)
    if project is None:
        return source, False
    block = f"\n  <ItemGroup>\n    {reference}\n  </ItemGroup>\n"
    return source[: project.end()] + block + source[project.end() :], True


# --- SwiftPM -----------------------------------------------------------------------------------

_SWIFT_DEPENDENCIES_RE = re.compile(r"([ \t]*)dependencies:[ \t]*\[", re.M)


def add_swift_dependency(source: str, provider: Provider) -> tuple[str, bool]:
    """Insert a `.package(url:from:)` entry into Package.swift's top-level `dependencies:` array.

    Only the FIRST `dependencies:` array is touched. A `Package.swift` has one at package level
    and another inside each target, and the target-level list names products, not URLs - inserting
    a `.package(url:)` there produces a manifest that does not compile.
    """
    if _already_declared(source, "swift-crypto"):
        return source, False
    match = _SWIFT_DEPENDENCIES_RE.search(source)
    if match is None:
        return source, False
    inner = match.group(1) + "    "
    entry = (
        f"\n{inner}// QUBIT: FIPS 203/204 provider (MLKEM, MLDSA, XWing)\n"
        f'{inner}.package(url: "{provider.package}", {provider.constraint}),'
    )
    return source[: match.end()] + entry + source[match.end() :], True


# --- Python ------------------------------------------------------------------------------------

_PIP_NAME_RE = re.compile(r"^\s*(?P<name>[A-Za-z0-9._-]+)", re.M)
_PYPROJECT_DEPS_RE = re.compile(r"(^[ \t]*dependencies[ \t]*=[ \t]*\[)", re.M)


def add_pip_dependency(source: str, provider: Provider) -> tuple[str, bool]:
    """Append `cryptography>=<floor>` to a requirements.txt that does not declare it.

    A requirements file that already pins it is the `bump_crypto_dependency` codemod's job, not
    this one - raising an existing pin and adding a missing package are different edits, and
    conflating them produced duplicate lines.
    """
    for match in _PIP_NAME_RE.finditer(source):
        if match.group("name").lower().replace("_", "-") == provider.package.lower():
            return source, False
    body = source if source.endswith("\n") or not source else source + "\n"
    line = f"{provider.package}{provider.constraint}  # QUBIT: version providing PQC primitives\n"
    return body + line, True


def add_pyproject_dependency(source: str, provider: Provider) -> tuple[str, bool]:
    """Insert the requirement into pyproject.toml's `dependencies = [ ... ]` array.

    A separate branch from requirements.txt because appending a bare `cryptography>=48.0.0` line
    to a TOML file is not a dependency declaration - it is a syntax error.
    """
    if re.search(rf"""["']{re.escape(provider.package)}["'>=~]""", source):
        return source, False
    match = _PYPROJECT_DEPS_RE.search(source)
    if match is None:
        return source, False
    indent_match = re.match(r"\r?\n([ \t]+)", source[match.end() :])
    indent = indent_match.group(1) if indent_match else "    "
    requirement = f"{provider.package}{provider.constraint}"
    entry = f'\n{indent}"{requirement}",  # QUBIT: provides PQC primitives'
    return source[: match.end()] + entry + source[match.end() :], True


# --- dispatch ----------------------------------------------------------------------------------

#: Manifest basename (lowercased, glob-able) -> the function that edits it.
_EDITORS = (
    ("pom.xml", add_maven_dependency),
    ("build.gradle", add_gradle_dependency),
    ("build.gradle.kts", add_gradle_dependency),
    ("build.sbt", add_sbt_dependency),
    ("*.csproj", add_nuget_dependency),
    ("*.fsproj", add_nuget_dependency),
    ("*.vbproj", add_nuget_dependency),
    ("package.swift", add_swift_dependency),
    ("requirements.txt", add_pip_dependency),
    ("pyproject.toml", add_pyproject_dependency),
)


def add_dependency_for_manifest(source: str, filename: str) -> tuple[str, bool]:
    """Add the playbook's provider to ``filename``, or report no change.

    Returns ``(source, False)`` for a manifest this module does not handle, for one whose
    ecosystem has no verified provider, and for one that already declares it. All three are
    "nothing to do", which is the answer the orchestrator needs to tell a satisfied task from a
    failed one.
    """
    from fnmatch import fnmatch

    name = filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
    provider = load_playbook().provider_for_manifest(name)
    if provider is None:
        return source, False
    for pattern, editor in _EDITORS:
        if fnmatch(name, pattern):
            return editor(source, provider)
    return source, False


__all__ = [
    "add_dependency_for_manifest",
    "add_gradle_dependency",
    "add_maven_dependency",
    "add_nuget_dependency",
    "add_pip_dependency",
    "add_pyproject_dependency",
    "add_sbt_dependency",
    "add_swift_dependency",
]
