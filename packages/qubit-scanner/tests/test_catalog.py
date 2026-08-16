from __future__ import annotations

from pathlib import Path

import pytest
from qubit_scanner import RuleCatalog
from qubit_scanner.catalog import RuleLoadError


def test_builtin_catalog_loads_and_compiles() -> None:
    cat = RuleCatalog.load()
    assert len(cat) >= 4
    assert "python" in cat.languages()
    ids = {c.rule.id for c in cat.all_rules()}
    assert {"PY-HASHLIB-MD5", "PY-HASHLIB-SHA1", "PY-CRYPTOGRAPHY-RSA-KEYGEN"} <= ids


def test_every_rule_defines_algorithm_extractor() -> None:
    for c in RuleCatalog.load().all_rules():
        assert "algorithm" in c.rule.extract, c.rule.id


def test_bad_query_fails_loudly(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "schema: qubit-rule/v1\n"
        "language: python\n"
        "library: {name: x, detect_imports: [x]}\n"
        "rules:\n"
        "  - id: BAD\n"
        "    match: {query: '(this is not a valid query'}\n"
        "    extract: {algorithm: {literal: X}}\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError):
        RuleCatalog.load([tmp_path])


def test_missing_algorithm_extractor_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "schema: qubit-rule/v1\n"
        "language: python\n"
        "library: {name: x, detect_imports: [x]}\n"
        "rules:\n"
        "  - id: NOALGO\n"
        "    match: {query: '(identifier) @i'}\n"
        "    extract: {key_size: {literal: '2048'}}\n",
        encoding="utf-8",
    )
    with pytest.raises(RuleLoadError):
        RuleCatalog.load([tmp_path])


def test_catalog_load_is_cached() -> None:
    """The rule pack is static per install, but loading it parses 29 YAML files and
    compiles ~152 tree-sitter queries — profiled at 0.8s of a 2.17s scan (37%). It is paid far more
    often than once per run: `scan_paths()` loads it whenever no catalog is passed, `qubit run`
    scans twice, and the validator's rescan stage pays it again per patch. Pure waste uncached."""
    RuleCatalog.load.cache_clear()  # type: ignore[attr-defined]
    first = RuleCatalog.load()
    second = RuleCatalog.load()
    assert len(first) == len(second) > 0
    # Same compiled rule objects, not merely equal counts — proof the work was not redone.
    assert first.all_rules()[0] is second.all_rules()[0]


def test_catalog_cache_is_keyed_by_directory(tmp_path: Path) -> None:
    """A temporary pack must not be served from (or poison) the built-in pack's cache entry."""
    (tmp_path / "solo.yaml").write_text(
        "schema: qubit-rule/v1\n"
        "language: python\n"
        "library: {name: x, detect_imports: []}\n"
        "rules:\n"
        "  - id: SOLO\n"
        "    match: {query: '(identifier) @i'}\n"
        "    extract: {algorithm: {literal: MD5}}\n",
        encoding="utf-8",
    )
    assert len(RuleCatalog.load([tmp_path])) == 1
    assert len(RuleCatalog.load()) > 1


def test_catalog_cache_can_be_cleared() -> None:
    """Tests that rewrite a rule directory in place depend on this escape hatch existing."""
    RuleCatalog.load.cache_clear()  # type: ignore[attr-defined]
    assert len(RuleCatalog.load()) > 0
