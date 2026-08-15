"""Tests for the dependency/SCA manifest scanner (backlog item B2, doc 01 grounding: 07 §11).

Each fixture mixes crypto-relevant packages (from the curated database) with ordinary,
non-crypto ones — the ordinary ones must produce zero detections (silently skipped, not flagged
as UNKNOWN), matching the module's documented design decision.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from qubit_scanner.deps import database
from qubit_scanner.deps.manifest import (
    parse_go_mod,
    parse_package_json,
    parse_pom_xml,
    parse_pyproject_toml,
    parse_requirements_txt,
)
from qubit_scanner.deps.scanner import ManifestParser

# ---------------------------------------------------------------------------
# Manifest fixtures (realistic shape, mixing crypto and non-crypto packages)
# ---------------------------------------------------------------------------

_GO_MOD = """\
module example.com/demo

go 1.22

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/spf13/cobra v1.8.0 // indirect
)
"""

_PACKAGE_JSON = """\
{
  "name": "demo",
  "version": "1.0.0",
  "dependencies": {
    "jsonwebtoken": "^9.0.0",
    "express": "^4.18.0"
  },
  "devDependencies": {
    "jest": "^29.0.0"
  }
}
"""

_REQUIREMENTS_TXT = """\
cryptography==41.0.0
PyJWT==2.8.0
requests==2.31.0
# a comment line
-r other-requirements.txt
"""

_PYPROJECT_TOML = """\
[project]
name = "demo"
dependencies = [
    "cryptography>=41.0",
    "click>=8.0",
]
"""

_POM_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>demo</artifactId>
    <version>1.0.0</version>
    <dependencies>
        <dependency>
            <groupId>org.bouncycastle</groupId>
            <artifactId>bcprov-jdk18on</artifactId>
            <version>1.79</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>6.1.0</version>
        </dependency>
    </dependencies>
</project>
"""


# ---------------------------------------------------------------------------
# database.lookup
# ---------------------------------------------------------------------------


def test_lookup_known_package_returns_algorithms() -> None:
    algos = database.lookup("pypi", "cryptography")
    assert algos is not None
    names = {a["algorithm"] for a in algos}
    assert "RSA" in names
    assert "ML-KEM-768" in names


def test_lookup_is_case_insensitive() -> None:
    assert database.lookup("pypi", "Cryptography") is not None


def test_lookup_unknown_package_returns_none() -> None:
    assert database.lookup("pypi", "totally-unrelated-package") is None


# ---------------------------------------------------------------------------
# ManifestParser.parse — one test per ecosystem, real manifest shapes
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_go_mod_detects_golang_jwt_only(tmp_path: Path) -> None:
    f = _write(tmp_path, "go.mod", _GO_MOD)
    dets = ManifestParser().parse(f)
    lib_names = {d.library_name for d in dets}
    assert lib_names == {"github.com/golang-jwt/jwt/v5"}
    algos = {d.raw_algorithm for d in dets}
    assert algos == {"RS256", "ES256", "HS256"}
    assert all(d.asset_type == "library" for d in dets)
    assert all(d.scanner == "config" for d in dets)


def test_package_json_detects_jsonwebtoken_not_express(tmp_path: Path) -> None:
    f = _write(tmp_path, "package.json", _PACKAGE_JSON)
    dets = ManifestParser().parse(f)
    lib_names = {d.library_name for d in dets}
    assert lib_names == {"jsonwebtoken"}
    assert "express" not in lib_names
    assert "jest" not in lib_names


def test_requirements_txt_detects_crypto_and_pyjwt_not_requests(tmp_path: Path) -> None:
    f = _write(tmp_path, "requirements.txt", _REQUIREMENTS_TXT)
    dets = ManifestParser().parse(f)
    lib_names = {d.library_name for d in dets}
    assert lib_names == {"cryptography", "pyjwt"}
    assert "requests" not in lib_names


def test_pyproject_toml_detects_cryptography_not_click(tmp_path: Path) -> None:
    f = _write(tmp_path, "pyproject.toml", _PYPROJECT_TOML)
    dets = ManifestParser().parse(f)
    lib_names = {d.library_name for d in dets}
    assert lib_names == {"cryptography"}


def test_pom_xml_detects_bouncycastle_not_spring(tmp_path: Path) -> None:
    f = _write(tmp_path, "pom.xml", _POM_XML)
    dets = ManifestParser().parse(f)
    lib_names = {d.library_name for d in dets}
    assert lib_names == {"org.bouncycastle:bcprov-jdk18on"}
    algos = {d.raw_algorithm for d in dets}
    assert "ML-KEM-768" in algos  # BC >=1.79 ships ML-KEM natively


def test_unrecognized_filename_returns_empty(tmp_path: Path) -> None:
    f = _write(tmp_path, "Cargo.toml", "[package]\nname = \"demo\"\n")
    assert ManifestParser().parse(f) == []


def test_malformed_manifest_does_not_crash(tmp_path: Path) -> None:
    f = _write(tmp_path, "package.json", "{not valid json")
    assert ManifestParser().parse(f) == []


def test_malformed_pom_does_not_crash(tmp_path: Path) -> None:
    f = _write(tmp_path, "pom.xml", "<not><valid</xml")
    assert ManifestParser().parse(f) == []


# ---------------------------------------------------------------------------
# End-to-end through scan_paths (dependency scanner wired in, opt-in-by-default)
# ---------------------------------------------------------------------------


def test_scan_paths_includes_dependency_findings(tmp_path: Path) -> None:
    from qubit_scanner.api import scan_paths

    _write(tmp_path, "go.mod", _GO_MOD)
    result = scan_paths([tmp_path])
    algos = {a.algorithm for a in result.assets if a.library and a.library.name}
    assert "RS256" in algos


def test_scan_paths_can_disable_dependency_scanner(tmp_path: Path) -> None:
    from qubit_scanner.api import scan_paths

    _write(tmp_path, "go.mod", _GO_MOD)
    result = scan_paths([tmp_path], scanners={"code"})
    assert result.assets == []


# ---------------------------------------------------------------------------
# Parser edge cases
# ---------------------------------------------------------------------------


def test_go_mod_single_line_require() -> None:
    deps = parse_go_mod("module x\n\ngo 1.22\n\nrequire github.com/pkg/errors v0.9.1\n")
    assert len(deps) == 1
    assert deps[0].name == "github.com/pkg/errors"
    assert deps[0].version == "v0.9.1"


def test_package_json_strips_semver_range_prefix() -> None:
    deps = parse_package_json('{"dependencies": {"foo": "^1.2.3"}}')
    assert deps[0].version == "1.2.3"


def test_requirements_txt_handles_extras_and_markers() -> None:
    deps = parse_requirements_txt('pyjwt[crypto]>=2.8; python_version >= "3.8"\n')
    assert deps[0].name == "pyjwt"


def test_pyproject_toml_ignores_poetry_table() -> None:
    content = """
[tool.poetry.dependencies]
python = "^3.12"
cryptography = "^41.0"
"""
    # PEP 621 [project.dependencies] only — Poetry's table has a different shape and is skipped.
    assert parse_pyproject_toml(content) == []


@pytest.mark.parametrize("bad", ["", "not xml at all", "<a><b></a></b>"])
def test_pom_xml_parser_never_raises(bad: str) -> None:
    assert parse_pom_xml(bad) == []
